"""L2-Combo: Project-level tool capability combination risk detection.

Single MCP tools may look innocent in isolation. This layer detects when
a server exposes multiple tools whose combined capabilities form a dangerous
pipeline — even if each individual tool is perfectly legitimate.

Classic example ("lethal trifecta"):
    read_file(path) + send_http(url, data)
    → Agent can read ~/.ssh/id_rsa then POST it to evil.com

This is a project-level (multi-file) check, run AFTER all per-file layers.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from mcpsecscan.engine.models import (
    Finding, Severity, Confidence, CIAImpact, SecurityProperty,
)

# ── Capability taxonomy ────────────────────────────────────────────────────────

# Each capability is a set of (regex patterns on call names OR import names)
# that indicate the tool exercises that capability.

# Call patterns that indicate file-read capability
_CAP_FILE_READ = re.compile(
    r'\b(?:open\s*\(|read_text|read_bytes|Path.*\.read|'
    r'os\.listdir|glob\.|os\.walk|os\.scandir|shutil\.copy)\b',
    re.I,
)
# Call patterns that indicate file-write capability
_CAP_FILE_WRITE = re.compile(
    r'\b(?:open\s*\([^)]*["\']w|write_text|write_bytes|'
    r'os\.makedirs|shutil\.rmtree|os\.remove|os\.unlink)\b',
    re.I,
)
# Call patterns that indicate outbound network capability
_CAP_NETWORK_OUT = re.compile(
    r'\b(?:requests\.|httpx\.|urllib\.request\.|aiohttp\.|'
    r'socket\.(?:connect|getaddrinfo|gethostbyname)|fetch\(|axios\.)\b',
    re.I,
)
# Call patterns that indicate env/credential reading
_CAP_ENV_READ = re.compile(
    r'\b(?:os\.environ|os\.getenv|dotenv|configparser|'
    r'open\s*\([^)]*(?:\.env|credentials|\.aws|\.ssh|id_rsa))\b',
    re.I,
)
# Call patterns that indicate command execution
_CAP_EXEC = re.compile(
    r'\b(?:subprocess\.|os\.system|os\.popen|'
    r'asyncio\.create_subprocess|exec\s*\(|eval\s*\()\b',
    re.I,
)


def _get_tool_body_source(func_node: ast.FunctionDef, source_lines: list[str]) -> str:
    """Extract the raw source text of a function body."""
    start = func_node.lineno - 1
    end = getattr(func_node, "end_lineno", func_node.lineno)
    return "\n".join(source_lines[start:end])


def _extract_capabilities(file_path: Path) -> list[dict]:
    """Return list of {tool_name, capabilities: set[str]} for all @mcp.tool() in file."""
    results = []
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return results

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return results

    source_lines = source.split("\n")

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        is_tool = any("tool" in ast.dump(d).lower() for d in node.decorator_list)
        if not is_tool:
            continue

        body = _get_tool_body_source(node, source_lines)
        caps: set[str] = set()
        if _CAP_FILE_READ.search(body):
            caps.add("file_read")
        if _CAP_FILE_WRITE.search(body):
            caps.add("file_write")
        if _CAP_NETWORK_OUT.search(body):
            caps.add("network_out")
        if _CAP_ENV_READ.search(body):
            caps.add("env_read")
        if _CAP_EXEC.search(body):
            caps.add("exec")

        if caps:
            results.append({
                "tool_name": node.name,
                "file": str(file_path),
                "line": node.lineno,
                "caps": caps,
            })

    return results


# ── Dangerous combination rules ────────────────────────────────────────────────
# Format: (required_caps_set, finding_id, title, severity, evidence_template)

_COMBO_RULES: list[tuple[set[str], str, str, Severity, str]] = [
    (
        {"file_read", "network_out"},
        "MCPX-L2C-001",
        "Dangerous tool combination: file read + outbound network = data exfiltration channel",
        Severity.HIGH,
        "Tool '{readers}' can read local files; tool '{senders}' can send data outbound. "
        "An AI agent can compose these to exfiltrate ~/.ssh/id_rsa, ~/.aws/credentials, etc.",
    ),
    (
        {"env_read", "network_out"},
        "MCPX-L2C-002",
        "Dangerous tool combination: env/credential read + outbound network = credential exfiltration",
        Severity.HIGH,
        "Tool '{readers}' reads environment variables or credentials; tool '{senders}' sends data outbound. "
        "Combined, they can exfiltrate API keys and secrets.",
    ),
    (
        {"file_write", "exec"},
        "MCPX-L2C-003",
        "Dangerous tool combination: file write + command execution = persistent backdoor",
        Severity.CRITICAL,
        "Tool '{writers}' can write arbitrary files; tool '{execers}' can execute commands. "
        "Combined, they can drop and execute malicious scripts for persistence.",
    ),
    (
        {"file_read", "exec"},
        "MCPX-L2C-004",
        "Dangerous tool combination: file read + command execution = local privilege escalation",
        Severity.HIGH,
        "Tool '{readers}' can read local files (e.g. scripts, configs); tool '{execers}' can execute commands. "
        "Combined, they enable reading then executing sensitive scripts.",
    ),
]

# Known-legitimate server patterns that produce false positives.
# If ALL tool names match one of these patterns, suppress the combo finding.
_SAFE_SERVER_PATTERNS = [
    # Standard filesystem + HTTP proxy MCP servers (e.g. mcp-filesystem + fetch)
    re.compile(r'^(read_file|write_file|list_directory|create_directory|move_file|search_files|get_file_info)$'),
]


def run_l2_combo(py_files: list[Path]) -> list[Finding]:
    """Run project-level combination risk analysis across all Python files.

    Args:
        py_files: All Python files in the scan target (already collected by scanner).

    Returns:
        Findings for dangerous tool capability combinations.
    """
    findings: list[Finding] = []

    # Collect capabilities from all files
    all_tools: list[dict] = []
    for f in py_files:
        all_tools.extend(_extract_capabilities(f))

    if len(all_tools) < 2:
        return findings  # need at least 2 tools for combination risk

    # Build capability → tools mapping
    cap_tools: dict[str, list[dict]] = {}
    for t in all_tools:
        for cap in t["caps"]:
            cap_tools.setdefault(cap, []).append(t)

    # Evaluate each combo rule
    for required_caps, fid, title, severity, evidence_tmpl in _COMBO_RULES:
        # All required capabilities must be present
        if not all(c in cap_tools for c in required_caps):
            continue

        # Collect tool names per capability role
        cap_role_tools: dict[str, list[str]] = {
            c: [t["tool_name"] for t in cap_tools[c]]
            for c in required_caps
        }

        # Check if any single tool exercises ALL required capabilities
        # (already reported by per-tool L4 checks — skip to avoid duplicate)
        all_tool_names_with_all = [
            t["tool_name"] for t in all_tools
            if required_caps.issubset(t["caps"])
        ]
        if all_tool_names_with_all:
            continue  # single-tool combo — L4 handles it

        # Format evidence with role labels
        fmt_args: dict[str, str] = {}
        cap_list = sorted(required_caps)
        for i, cap in enumerate(cap_list):
            role_labels = {
                "file_read": "readers", "file_write": "writers",
                "network_out": "senders", "env_read": "readers",
                "exec": "execers",
            }
            key = role_labels.get(cap, cap)
            fmt_args[key] = ", ".join(cap_role_tools[cap])

        # Build a representative file + line (use the first tool's location)
        first_tool = cap_tools[list(required_caps)[0]][0]
        evidence = evidence_tmpl.format(**fmt_args)

        # Collect all involved files for evidence
        involved_files = sorted({
            t["file"] for cap in required_caps for t in cap_tools[cap]
        })
        involved_tools = sorted({
            t["tool_name"] for cap in required_caps for t in cap_tools[cap]
        })

        findings.append(Finding(
            id=fid,
            title=title,
            severity=severity,
            layer="L2-Combo",
            file=first_tool["file"],
            line=0,
            evidence=(
                f"Tools involved: {', '.join(involved_tools)}\n"
                f"Files: {', '.join(involved_files)}\n"
                f"{evidence}"
            ),
            description=(
                "Individual tools may be legitimate, but their combination enables "
                "multi-step attacks when composed by an AI agent. "
                "This is the 'lethal trifecta' attack pattern documented in MCP threat research."
            ),
            remediation=(
                "1. Audit whether all these capabilities are necessary in a single server. "
                "2. If file read + network are both needed, add explicit user-consent prompts. "
                "3. Restrict network calls to a hardcoded allowlist of trusted endpoints. "
                "4. Consider splitting into separate servers with different trust levels."
            ),
            owasp_mcp="MCP05",
            cia_impact=[CIAImpact.CONFIDENTIALITY, CIAImpact.INTEGRITY],
            security_property=SecurityProperty.DATA_ISOLATION,
            confidence=Confidence.NEEDS_REVIEW,
        ))

    return findings
