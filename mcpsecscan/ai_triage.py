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


def _build_user_prompt(scan_dict: dict[str, Any]) -> str:
    """Build the user message from a scan result dict."""
    findings = scan_dict.get("findings", [])
    target = scan_dict.get("target", "unknown")

    # Keep only fields the model needs — strip noise
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

    payload = {
        "target": target,
        "total_findings": len(slim_findings),
        "findings": slim_findings,
    }
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
) -> TriageReport:
    """Run AI triage on a scan result.

    Args:
        scan_result: A ScanResult object or a plain dict from ScanResult.to_dict().
        api_url:     Base URL for OpenAI-compatible API.
                     Examples:
                       "https://api.openai.com/v1"          (OpenAI)
                       "http://localhost:11434/v1"           (Ollama)
                       "https://xxx.openai.azure.com/..."   (Azure OpenAI)
        api_key:     API key (Bearer token). Empty string for local models.
        model:       Model name, e.g. "gpt-4o-mini", "llama3", "deepseek-coder".
        timeout:     HTTP timeout in seconds.

    Returns:
        TriageReport with per-finding verdicts and overall summary.
    """
    # Normalise input
    if hasattr(scan_result, "to_dict"):
        scan_dict = scan_result.to_dict()
    else:
        scan_dict = scan_result

    # Short-circuit: nothing to triage
    if not scan_dict.get("findings"):
        return TriageReport(
            model=model,
            risk_level="safe",
            summary="No findings to triage.",
        )

    user_prompt = _build_user_prompt(scan_dict)

    try:
        raw = _call_openai_compat(
            api_url=api_url,
            api_key=api_key,
            model=model,
            system=_SYSTEM_PROMPT,
            user=user_prompt,
            timeout=timeout,
        )
    except RuntimeError as e:
        return TriageReport(model=model, error=str(e))

    return _parse_response(raw, model)
