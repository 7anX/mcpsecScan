"""L3: Taint analysis via Semgrep — tracks user input to dangerous sinks.

This is mcpx's core differentiator. It detects vulnerabilities that pattern
matching cannot find: cases where user-controlled parameters flow to dangerous
operations (SSRF, path traversal, command injection, deserialization, dynamic
imports) without proper validation.

Requires: semgrep CLI installed (`pip install semgrep` or `pip install mcpx[taint]`)
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from mcpsec_scan.engine.models import (
    Finding, Severity, Confidence, CIAImpact, SecurityProperty
)

# Where our rules live (relative to this file)
RULES_DIR = Path(__file__).parent.parent / "rules"

# Map Semgrep severity to mcpx severity
_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


def _semgrep_available() -> bool:
    """Check if semgrep CLI is installed."""
    return shutil.which("semgrep") is not None


def _run_semgrep(target: Path) -> Optional[dict]:
    """Run semgrep with our MCP rules on the target.

    Runs each rule file individually to avoid one broken rule killing the scan.
    """
    if not RULES_DIR.exists():
        return None

    rule_files = list(RULES_DIR.glob("**/*.yaml"))
    if not rule_files:
        return None

    all_results: list[dict] = []
    import os as _os
    env = dict(_os.environ)
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"

    for rule_file in rule_files:
        cmd = [
            "semgrep",
            "scan",
            "--config", str(rule_file),
            "--json",
            "--quiet",
            "--no-git-ignore",
            "--timeout", "30",
            str(target),
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                encoding="utf-8",
                errors="replace",
                env=env,
            )
            if result.stdout:
                data = json.loads(result.stdout)
                all_results.extend(data.get("results", []))
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
            continue

    return {"results": all_results}

    return None


def _parse_semgrep_results(data: dict) -> list[Finding]:
    """Convert Semgrep JSON output to mcpx Findings."""
    findings: list[Finding] = []

    for result in data.get("results", []):
        # Extract metadata
        meta = result.get("extra", {}).get("metadata", {})
        rule_id = result.get("check_id", "unknown")
        message = result.get("extra", {}).get("message", "")
        severity_str = result.get("extra", {}).get("severity", "WARNING")
        filepath = result.get("path", "")
        start_line = result.get("start", {}).get("line", 0)
        end_line = result.get("end", {}).get("line", 0)

        # Get the matched code snippet
        lines_text = result.get("extra", {}).get("lines", "")

        # Map metadata
        mcpx_id = meta.get("mcpx_id", f"MCPX-L3-{rule_id[-3:]}")
        owasp = meta.get("owasp_mcp", "")
        cia_raw = meta.get("cia_impact", [])
        cia = []
        for c in cia_raw:
            if c == "C":
                cia.append(CIAImpact.CONFIDENTIALITY)
            elif c == "I":
                cia.append(CIAImpact.INTEGRITY)
            elif c == "A":
                cia.append(CIAImpact.AVAILABILITY)

        confidence_str = meta.get("confidence", "HIGH")
        confidence = Confidence.HIGH
        if confidence_str == "MEDIUM":
            confidence = Confidence.MEDIUM
        elif confidence_str in ("LOW", "NEEDS_REVIEW"):
            confidence = Confidence.NEEDS_REVIEW

        findings.append(Finding(
            id=mcpx_id,
            title=message[:200] if message else f"Taint finding: {rule_id}",
            severity=_SEVERITY_MAP.get(severity_str, Severity.MEDIUM),
            layer="L3",
            file=filepath,
            line=start_line,
            evidence=lines_text.strip()[:200] if lines_text else "",
            description=f"Semgrep rule: {rule_id}",
            owasp_mcp=owasp,
            cia_impact=cia,
            security_property=SecurityProperty.DATA_ISOLATION,
            confidence=confidence,
        ))

    return findings


def _post_filter(findings: list[Finding], target: Path) -> list[Finding]:
    """Post-process L3 findings to reduce false positives.

    Checks source code context to identify common safe patterns:
    - shlex.quote() before subprocess → sanitized command injection
    - Hardcoded URL host with user input only in query params → not SSRF
    - re.escape() before re.compile → sanitized ReDoS
    """
    if not findings:
        return findings

    # Read all source files referenced in findings
    source_cache: dict[str, list[str]] = {}
    for f in findings:
        if f.file and f.file not in source_cache:
            try:
                source_cache[f.file] = Path(f.file).read_text(
                    encoding="utf-8", errors="replace"
                ).split("\n")
            except OSError:
                source_cache[f.file] = []

    filtered = []
    for finding in findings:
        lines = source_cache.get(finding.file, [])
        if not lines:
            filtered.append(finding)
            continue

        # Get context: 10 lines before the finding
        start = max(0, finding.line - 10)
        end = min(len(lines), finding.line + 3)
        context = "\n".join(lines[start:end])

        skip = False

        # Filter 1: shlex.quote before subprocess → sanitized
        if "command" in finding.description.lower() or "L3-003" in finding.id:
            if "shlex.quote" in context or "shlex.split" in context:
                skip = True

        # Filter 2: Hardcoded URL host with f-string query param → not SSRF
        if "ssrf" in finding.title.lower() or "L3-001" in finding.id:
            # Check if the URL string has a hardcoded host
            import re
            # Pattern: f"https://specific-domain.com/...{user_input}..."
            hardcoded_url = re.search(
                r'f["\']https?://[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}/',
                context,
            )
            if hardcoded_url:
                # User input is only in path/query, not controlling the host
                finding.confidence = Confidence.NEEDS_REVIEW
                finding.severity = Severity.LOW
                finding.title += " (host hardcoded — likely query param injection, not SSRF)"

        # Filter 3: re.escape before re.compile → sanitized ReDoS
        if "regex" in finding.title.lower() or "L3-008" in finding.id:
            if "re.escape" in context:
                skip = True

        if not skip:
            filtered.append(finding)

    return filtered


def run_l3(target: Path) -> list[Finding]:
    """Run L3 taint analysis on the target path.

    Args:
        target: Path to a file or directory to scan.

    Returns:
        List of findings. Empty if semgrep is not installed (with a note).
    """
    if not _semgrep_available():
        return []

    data = _run_semgrep(target)
    if data is None:
        return []

    findings = _parse_semgrep_results(data)
    return _post_filter(findings, target)


def is_available() -> bool:
    """Check if L3 (Semgrep) is available."""
    return _semgrep_available()
