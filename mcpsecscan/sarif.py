"""SARIF 2.1.0 output formatter for mcpsecscan findings.

SARIF (Static Analysis Results Interchange Format) is supported by:
- GitHub Code Scanning (upload-sarif action)
- GitLab SAST
- Azure DevOps
- VS Code SARIF Viewer extension

Usage:
    result = scan_target("./my-server")
    sarif = to_sarif(result)
    print(json.dumps(sarif, indent=2))
"""

from __future__ import annotations

from mcpsecscan.engine.models import ScanResult
from mcpsecscan import __version__

# OWASP MCP Top 10 → CWE mapping (best-effort approximation)
_OWASP_TO_CWE: dict[str, str] = {
    "MCP01": "CWE-74",   # Injection
    "MCP02": "CWE-285",  # Improper Authorization
    "MCP03": "CWE-200",  # Information Exposure
    "MCP04": "CWE-798",  # Hardcoded Credentials
    "MCP05": "CWE-502",  # Deserialization
    "MCP06": "CWE-601",  # Open Redirect / SSRF
    "MCP07": "CWE-22",   # Path Traversal
    "MCP08": "CWE-89",   # SQL Injection
    "MCP09": "CWE-441",  # Unintended Proxy / Confused Deputy
    "MCP10": "CWE-693",  # Protection Mechanism Failure
}

_SEVERITY_TO_SARIF = {
    "critical": "error",
    "high":     "error",
    "medium":   "warning",
    "low":      "note",
    "info":     "note",
}


def to_sarif(result: ScanResult) -> dict:
    """Convert a ScanResult to a SARIF 2.1.0 document."""

    # Build rule index from findings
    rules_seen: dict[str, dict] = {}
    for f in result.findings:
        if f.id not in rules_seen:
            cwe = _OWASP_TO_CWE.get(f.owasp_mcp, "CWE-0")
            rules_seen[f.id] = {
                "id": f.id,
                "name": _rule_name(f.id),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description or f.title},
                "helpUri": f"https://github.com/7anX/mcpsecScan/blob/master/README.md#{f.id.lower()}",
                "properties": {
                    "tags": [f.layer, f.owasp_mcp] if f.owasp_mcp else [f.layer],
                    "precision": "high" if f.confidence.value == "high" else "medium",
                    "problem.severity": _SEVERITY_TO_SARIF.get(f.severity.value, "warning"),
                    "security-severity": _sarif_security_score(f.severity.value),
                },
                "defaultConfiguration": {
                    "level": _SEVERITY_TO_SARIF.get(f.severity.value, "warning"),
                },
                "relationships": [
                    {
                        "target": {
                            "id": cwe,
                            "guid": None,
                            "toolComponent": {"name": "CWE", "guid": None},
                        },
                        "kinds": ["relevant"],
                    }
                ] if cwe != "CWE-0" else [],
            }

    rules_list = list(rules_seen.values())
    rule_index = {rid: i for i, rid in enumerate(rules_seen)}

    # Build results
    sarif_results = []
    for f in result.findings:
        loc = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": _normalize_uri(f.file),
                    "uriBaseId": "%SRCROOT%",
                },
                "region": {
                    "startLine": max(1, f.line) if f.line else 1,
                },
            },
        }
        if f.tool_name:
            loc["logicalLocations"] = [{"name": f.tool_name, "kind": "function"}]

        message_text = f.title
        if f.evidence:
            message_text += f"\n\nEvidence: {f.evidence}"
        if f.remediation:
            message_text += f"\n\nRemediation: {f.remediation}"

        sarif_results.append({
            "ruleId": f.id,
            "ruleIndex": rule_index.get(f.id, 0),
            "level": _SEVERITY_TO_SARIF.get(f.severity.value, "warning"),
            "message": {"text": message_text},
            "locations": [loc],
            "properties": {
                "confidence": f.confidence.value,
                "owasp_mcp": f.owasp_mcp,
                "cia_impact": [c.value for c in f.cia_impact],
            },
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Documents/CommitteeSpecifications/2.1.0/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcpsecscan",
                        "version": __version__,
                        "informationUri": "https://github.com/7anX/mcpsecScan",
                        "rules": rules_list,
                    }
                },
                "results": sarif_results,
                "artifacts": [
                    {"location": {"uri": _normalize_uri(result.target), "uriBaseId": "%SRCROOT%"}}
                ],
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "toolExecutionNotifications": [
                            {"message": {"text": e}, "level": "note"}
                            for e in result.errors
                        ],
                    }
                ],
            }
        ],
    }


def _rule_name(rule_id: str) -> str:
    """Convert MCPX-L1-001 → McpxL1001 (UpperCamelCase for SARIF)."""
    return rule_id.replace("-", "").title()


def _normalize_uri(path: str) -> str:
    """Normalize a file path to a relative URI for SARIF."""
    import os
    # Convert backslashes to forward slashes
    uri = path.replace("\\", "/")
    # Make relative if possible
    try:
        cwd = os.getcwd().replace("\\", "/")
        if uri.startswith(cwd):
            uri = uri[len(cwd):].lstrip("/")
    except Exception:
        pass
    return uri


def _sarif_security_score(severity: str) -> str:
    """Map severity to SARIF security-severity score (0-10)."""
    return {
        "critical": "9.8",
        "high":     "7.5",
        "medium":   "5.0",
        "low":      "3.0",
        "info":     "1.0",
    }.get(severity, "5.0")
