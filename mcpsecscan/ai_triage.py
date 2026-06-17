"""AI-powered triage layer for mcpsecscan findings.

Sends scan findings to any OpenAI-compatible endpoint and returns
per-finding risk assessments and an overall natural-language report.

Supports:
  - OpenAI (https://api.openai.com/v1)
  - Azure OpenAI
  - Local models via Ollama (http://localhost:11434/v1)
  - Any other OpenAI-compatible API (LM Studio, vLLM, Together, etc.)

Usage:
    from mcpsecscan.ai_triage import triage

    report = triage(
        scan_result,
        api_url="https://api.openai.com/v1",
        api_key="sk-...",
        model="gpt-4o-mini",
    )
    print(report.summary)
    for item in report.items:
        print(item.finding_id, item.verdict, item.explanation)
"""

from __future__ import annotations

import json
import textwrap
from dataclasses import dataclass, field
from typing import Any

# ── dependency guard ─────────────────────────────────────────────────────────

try:
    import httpx  # type: ignore
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False


def is_available() -> bool:
    """Return True if the httpx dependency is installed."""
    return _HTTPX_AVAILABLE


# ── data models ──────────────────────────────────────────────────────────────

@dataclass
class TriageItem:
    """AI assessment for one finding."""
    finding_id: str
    verdict: str          # "confirmed" | "likely_fp" | "needs_review"
    confidence: str       # "high" | "medium" | "low"
    explanation: str      # natural language, 1-3 sentences
    attack_scenario: str  # how an attacker would exploit this (if confirmed)
    fix_suggestion: str   # concrete code-level fix hint


@dataclass
class TriageReport:
    """Full AI triage report for a scan result."""
    model: str
    items: list[TriageItem] = field(default_factory=list)
    summary: str = ""           # overall risk summary paragraph
    risk_level: str = ""        # "critical" | "high" | "medium" | "low" | "safe"
    raw_response: str = ""      # full LLM response text (for debugging)
    error: str = ""             # non-empty if triage failed


# ── prompt construction ───────────────────────────────────────────────────────

_SYSTEM_PROMPT = textwrap.dedent("""\
    You are a senior application security engineer specializing in MCP (Model Context Protocol) server security.
    You will receive a JSON list of static analysis findings from mcpsecscan, a static security scanner.
    Your job is to:
    1. Assess each finding: is it a real threat (confirmed), a false positive (likely_fp), or ambiguous (needs_review)?
    2. For confirmed findings, describe a concrete attack scenario (1-2 sentences).
    3. Suggest a specific code fix (not generic advice — reference the actual finding evidence).
    4. Write a brief overall risk summary.

    Respond ONLY with a valid JSON object matching this exact schema:
    {
      "risk_level": "<critical|high|medium|low|safe>",
      "summary": "<1-3 sentence overall risk assessment>",
      "items": [
        {
          "finding_id": "<MCPX-Lx-xxx>",
          "verdict": "<confirmed|likely_fp|needs_review>",
          "confidence": "<high|medium|low>",
          "explanation": "<1-3 sentences>",
          "attack_scenario": "<how attacker exploits this, or empty string if likely_fp>",
          "fix_suggestion": "<concrete fix referencing the evidence>"
        }
      ]
    }

    Rules:
    - Do NOT wrap the JSON in markdown code fences.
    - Keep explanations concise (under 100 words each).
    - If a finding has shlex.quote or parameterized queries in the evidence, it is likely_fp.
    - Focus on HIGH and CRITICAL findings first in the summary.
""")

_SYSTEM_PROMPT_DEEP = textwrap.dedent("""\
    You are a senior application security engineer specializing in MCP (Model Context Protocol) server security.
    You will receive:
    1. Static analysis findings (may be empty if the static layer had no findings)
    2. Structural tool digests — metadata about each @mcp.tool() function extracted via AST.
       These digests contain NO source code, only: description, parameters, data sources/sinks,
       callback registrations, and control flow type.

    Your job is to:
    A. Triage each static finding as before (confirmed / likely_fp / needs_review).
    B. Using the tool digests, detect blind spots that static analysis cannot find:
       - Semantic data leaks: a tool reads sensitive data (os.environ, credentials file) and
         returns it in the tool response — even without a dangerous network/file-write call.
       - Hidden async behavior: a callback registered by the tool performs operations
         (network POST, file write) not mentioned in the tool's description.
       - Combination risk: two or more tools together enable multi-step attacks
         (read file → POST to external URL) even if each tool is individually legitimate.

    Respond ONLY with a valid JSON object:
    {
      "risk_level": "<critical|high|medium|low|safe>",
      "summary": "<2-4 sentence overall risk assessment including blind-spot findings>",
      "items": [
        {
          "finding_id": "<MCPX-Lx-xxx or AI-BS-001/002/003 for blind-spot findings>",
          "verdict": "<confirmed|likely_fp|needs_review>",
          "confidence": "<high|medium|low>",
          "explanation": "<1-3 sentences>",
          "attack_scenario": "<concrete exploitation path, or empty string>",
          "fix_suggestion": "<concrete fix>"
        }
      ]
    }

    Blind-spot finding IDs to use:
    - AI-BS-001: Semantic data leak (env/credentials → return value, no dangerous sink)
    - AI-BS-002: Hidden async/callback behavior not disclosed in description
    - AI-BS-003: Tool combination exfiltration channel (confirmed lethal trifecta)

    Rules:
    - Do NOT wrap the JSON in markdown code fences.
    - Only emit AI-BS-* findings when you are reasonably confident (medium+ confidence).
    - For AI-BS-001: confirm only if the tool reads sensitive env vars OR credential files
      AND the return value goes back to the agent context.
    - For AI-BS-002: confirm only if callback_operations contains network/file-write ops
      that are NOT mentioned in the tool description.
    - For AI-BS-003: confirm only if the combination creates a DIRECT exfiltration path
      (not just theoretical — the agent must be able to compose them in one session).
""")


def _build_user_prompt(scan_dict: dict[str, Any], tool_digests: list | None = None) -> str:
    """Build the user message from a scan result dict.

    In deep mode, tool_digests (list of ToolDigest.to_prompt_dict()) are appended
    so the AI can reason about blind spots beyond static findings.
    """
    findings = scan_dict.get("findings", [])
    target = scan_dict.get("target", "unknown")

    # Keep only fields the model needs — strip noise, never send full source paths
    slim_findings = []
    for f in findings:
        slim_findings.append({
            "id": f.get("id"),
            "title": f.get("title"),
            "severity": f.get("severity"),
            "layer": f.get("layer"),
            "file": f.get("file"),
            "line": f.get("line"),
            "evidence": f.get("evidence"),
            "description": f.get("description"),
            "tool_name": f.get("tool_name"),
        })

    payload: dict[str, Any] = {
        "target": target,
        "total_findings": len(slim_findings),
        "findings": slim_findings,
    }

    if tool_digests:
        payload["tool_digests"] = tool_digests
        payload["note"] = (
            "Tool digests contain structural metadata (no source code). "
            "Use them to detect semantic blind spots not covered by static findings."
        )

    return (
        f"Please triage the following mcpsecscan findings for target: {target}\n\n"
        + json.dumps(payload, indent=2, ensure_ascii=False)
    )


# ── OpenAI-compatible API call ────────────────────────────────────────────────

def _call_openai_compat(
    api_url: str,
    api_key: str,
    model: str,
    system: str,
    user: str,
    timeout: int = 60,
) -> str:
    """Call an OpenAI-compatible /v1/chat/completions endpoint.

    Returns the assistant message content as a string.
    Raises RuntimeError on failure.
    """
    if not _HTTPX_AVAILABLE:
        raise RuntimeError(
            "httpx is required for AI triage. "
            "Install with: pip install mcpsecscan[ai]"
        )

    # Normalise base URL — strip trailing slash, ensure /v1/chat/completions
    base = api_url.rstrip("/")
    if not base.endswith("/v1"):
        # Allow passing just https://api.openai.com without /v1
        if not base.endswith("/chat/completions"):
            endpoint = base + "/v1/chat/completions" if "/v1" not in base else base + "/chat/completions"
        else:
            endpoint = base
    else:
        endpoint = base + "/chat/completions"

    headers: dict[str, str] = {
        "Content-Type": "application/json",
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": 0.1,   # deterministic for security analysis
        "response_format": {"type": "json_object"},
    }

    try:
        resp = httpx.post(
            endpoint,
            headers=headers,
            json=body,
            timeout=timeout,
        )
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise RuntimeError(
            f"AI API returned HTTP {e.response.status_code}: {e.response.text[:300]}"
        ) from e
    except httpx.RequestError as e:
        raise RuntimeError(f"AI API request failed: {e}") from e

    data = resp.json()
    try:
        return data["choices"][0]["message"]["content"]
    except (KeyError, IndexError) as e:
        raise RuntimeError(f"Unexpected API response shape: {data}") from e


# ── parse LLM response ────────────────────────────────────────────────────────

def _parse_response(raw: str, model: str) -> TriageReport:
    """Parse the LLM JSON response into a TriageReport."""
    report = TriageReport(model=model, raw_response=raw)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        report.error = f"Failed to parse AI response as JSON: {e}\nRaw: {raw[:500]}"
        return report

    report.risk_level = data.get("risk_level", "unknown")
    report.summary = data.get("summary", "")

    for item_data in data.get("items", []):
        report.items.append(TriageItem(
            finding_id=item_data.get("finding_id", ""),
            verdict=item_data.get("verdict", "needs_review"),
            confidence=item_data.get("confidence", "low"),
            explanation=item_data.get("explanation", ""),
            attack_scenario=item_data.get("attack_scenario", ""),
            fix_suggestion=item_data.get("fix_suggestion", ""),
        ))

    return report


# ── public API ────────────────────────────────────────────────────────────────

def triage(
    scan_result,                     # ScanResult instance or dict
    api_url: str = "https://api.openai.com/v1",
    api_key: str = "",
    model: str = "gpt-4o-mini",
    timeout: int = 60,
    mode: str = "basic",             # "basic" | "deep"
    py_files: list | None = None,    # required for mode="deep"
) -> TriageReport:
    """Run AI triage on a scan result.

    Args:
        scan_result: A ScanResult object or a plain dict from ScanResult.to_dict().
        api_url:     Base URL for OpenAI-compatible API.
        api_key:     API key (Bearer token). Empty string for local models.
        model:       Model name, e.g. "gpt-4o-mini", "llama3", "deepseek-coder".
        timeout:     HTTP timeout in seconds.
        mode:        "basic" — triage existing findings only (no source code sent).
                     "deep"  — also extract AST-based tool digests for blind-spot
                               detection (env leaks, async callbacks, combo risk).
                               Still sends NO source code — only structural metadata.
        py_files:    List of Path objects to scan for tool digests (deep mode only).

    Returns:
        TriageReport with per-finding verdicts and overall summary.
        In deep mode, may include AI-BS-* blind-spot findings.
    """
    # Normalise input
    if hasattr(scan_result, "to_dict"):
        scan_dict = scan_result.to_dict()
    else:
        scan_dict = scan_result

    # Build tool digests for deep mode
    tool_digests = None
    system_prompt = _SYSTEM_PROMPT
    if mode == "deep" and py_files:
        from mcpsecscan.ai_deep_analysis import collect_server_digests
        digests = collect_server_digests(py_files)
        if digests:
            tool_digests = [d.to_prompt_dict() for d in digests]
            system_prompt = _SYSTEM_PROMPT_DEEP

    # Short-circuit: nothing to triage (basic mode only — deep always runs)
    if mode == "basic" and not scan_dict.get("findings"):
        return TriageReport(
            model=model,
            risk_level="safe",
            summary="No findings to triage.",
        )

    user_prompt = _build_user_prompt(scan_dict, tool_digests=tool_digests)

    try:
        raw = _call_openai_compat(
            api_url=api_url,
            api_key=api_key,
            model=model,
            system=system_prompt,
            user=user_prompt,
            timeout=timeout,
        )
    except RuntimeError as e:
        return TriageReport(model=model, error=str(e))

    return _parse_response(raw, model)
