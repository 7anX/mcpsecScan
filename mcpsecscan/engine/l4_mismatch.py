"""L4: Description-code mismatch detection — compares what a tool's docstring
claims it does vs. what the code actually does.

This is mcpx's unique differentiator. No other MCP scanner performs this check.

Detection logic:
1. Extract "claimed capabilities" from tool description keywords
2. Analyze actual code operations via AST
3. Flag contradictions (e.g., "read-only" description + file write in code)
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Optional

from mcpsecscan.engine.models import (
    Finding, Severity, Confidence, CIAImpact, SecurityProperty
)

# ─── Claimed capability categories ──────────────────────────────────────────

# Keywords in descriptions that imply specific behavioral constraints
CLAIM_READ_ONLY = re.compile(
    r'\b(?:read[- ]only|only\s+reads?|never\s+(?:modif|writ|chang|delet)|'
    r'does\s+not\s+(?:modify|write|change|delete|create)|'
    r'no\s+(?:side[- ]effects?|modifications?))\b',
    re.I,
)

CLAIM_PURE_COMPUTE = re.compile(
    r'\b(?:calculate|compute|convert|transform|format|parse|validate)\b',
    re.I,
)

CLAIM_NO_NETWORK = re.compile(
    r'\b(?:offline|local[- ]only|no\s+(?:network|internet|external)|'
    r'does\s+not\s+(?:connect|send|upload|download))\b',
    re.I,
)

CLAIM_SAFE = re.compile(
    r'\b(?:safe|secure|sandboxed|isolated|harmless|innocent)\b',
    re.I,
)

# Descriptions that explicitly state the tool runs commands/network — NOT a mismatch
DESC_ACKNOWLEDGES_COMMANDS = re.compile(
    r'\b(?:execut|run[s ]|invoke[s ]|call[s ])\b.*\b(?:command|shell|script|process|program|tool|linter|pylint|black|flake)\b',
    re.I,
)
DESC_ACKNOWLEDGES_NETWORK = re.compile(
    r'\b(?:fetch|request|call|connect|query)\b.*\b(?:api|http|server|endpoint|service|url)\b',
    re.I,
)

# ─── Actual code operation detection (AST-based) ────────────────────────────

# Dangerous call patterns that we check in the function body
FILE_WRITE_MODES = {"w", "a", "x", "wb", "ab", "xb", "w+", "a+"}
FILE_WRITE_METHODS = {
    "write", "writelines", "write_text", "write_bytes",
    "mkdir", "makedirs", "rename", "replace", "remove", "unlink", "rmdir",
}

NETWORK_CALLS = {
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "requests.head", "requests.patch", "requests.request",
    "httpx.get", "httpx.post", "httpx.put",
    "urllib.request.urlopen", "urllib.request.Request",
    "aiohttp.ClientSession",
    "socket.connect", "socket.create_connection",
}

COMMAND_EXEC_CALLS = {
    "subprocess.run", "subprocess.call", "subprocess.Popen",
    "subprocess.check_output", "subprocess.check_call",
    "os.system", "os.popen", "os.exec", "os.execvp",
}

DANGEROUS_CALLS = {
    "eval", "exec", "compile",
    "pickle.load", "pickle.loads",
    "yaml.load", "marshal.load", "marshal.loads",
}


def _get_call_name(node: ast.Call) -> str:
    """Extract the full dotted name of a function call."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    elif isinstance(node.func, ast.Attribute):
        parts = []
        current = node.func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    return ""


def _check_open_write_mode(node: ast.Call) -> bool:
    """Check if an open() call uses a write mode."""
    # open(path, 'w') or open(path, mode='w')
    if len(node.args) >= 2:
        mode_arg = node.args[1]
        if isinstance(mode_arg, ast.Constant) and isinstance(mode_arg.value, str):
            return any(m in mode_arg.value for m in ("w", "a", "x"))
    for kw in node.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
            if isinstance(kw.value.value, str):
                return any(m in kw.value.value for m in ("w", "a", "x"))
    return False


def _analyze_function_operations(func_node: ast.FunctionDef) -> dict[str, list[int]]:
    """Analyze what operations a function actually performs.

    Returns dict with categories and line numbers where they occur.
    """
    ops: dict[str, list[int]] = {
        "file_write": [],
        "file_read": [],
        "network": [],
        "command_exec": [],
        "dangerous": [],
    }

    for node in ast.walk(func_node):
        if not isinstance(node, ast.Call):
            continue

        call_name = _get_call_name(node)
        lineno = getattr(node, "lineno", 0)

        # File write
        if call_name == "open" and _check_open_write_mode(node):
            ops["file_write"].append(lineno)
        elif call_name in ("write", "writelines") or call_name.endswith((".write", ".writelines")):
            ops["file_write"].append(lineno)
        elif any(call_name.endswith(m) for m in (".write_text", ".write_bytes", ".mkdir", ".makedirs")):
            ops["file_write"].append(lineno)
        elif call_name in ("os.remove", "os.unlink", "os.rmdir", "os.rename", "os.replace"):
            ops["file_write"].append(lineno)
        elif call_name in ("shutil.rmtree", "shutil.copy", "shutil.move"):
            ops["file_write"].append(lineno)
        elif call_name == "os.chmod" or call_name == "os.makedirs":
            ops["file_write"].append(lineno)

        # File read (for context, not mismatch)
        elif call_name == "open" and not _check_open_write_mode(node):
            ops["file_read"].append(lineno)

        # Network
        elif any(call_name.startswith(prefix) for prefix in ("requests.", "httpx.", "urllib.", "aiohttp.")):
            ops["network"].append(lineno)
        elif call_name in ("socket.connect", "socket.create_connection"):
            ops["network"].append(lineno)

        # Command execution
        elif any(call_name.startswith(prefix) for prefix in ("subprocess.", "os.system", "os.popen")):
            ops["command_exec"].append(lineno)

        # Dangerous
        elif call_name in ("eval", "exec", "compile"):
            ops["dangerous"].append(lineno)
        elif call_name in ("pickle.load", "pickle.loads", "yaml.load", "marshal.load"):
            ops["dangerous"].append(lineno)

    return ops


def _extract_mcp_tools(tree: ast.AST) -> list[dict]:
    """Extract MCP tool functions with their docstrings."""
    tools = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            dec_str = ast.dump(dec)
            if "tool" in dec_str.lower():
                docstring = ast.get_docstring(node) or ""
                tools.append({
                    "name": node.name,
                    "docstring": docstring,
                    "node": node,
                    "lineno": node.lineno,
                })
                break
    return tools


def run_l4(file_path: Path) -> list[Finding]:
    """Run L4 description-code mismatch analysis on a single file."""
    findings: list[Finding] = []
    file_str = str(file_path)

    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return findings

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return findings

    tools = _extract_mcp_tools(tree)

    for tool in tools:
        docstring = tool["docstring"]
        if not docstring:
            continue

        # Analyze actual operations
        ops = _analyze_function_operations(tool["node"])

        # ─── Check mismatches ───

        # Claim: read-only → Actual: file writes
        if CLAIM_READ_ONLY.search(docstring) and ops["file_write"]:
            findings.append(Finding(
                id="MCPX-L4-001",
                title=f"Description-code mismatch: '{tool['name']}' claims read-only but writes files",
                severity=Severity.CRITICAL,
                layer="L4",
                file=file_str,
                line=ops["file_write"][0],
                evidence=(
                    f"Description says: \"{CLAIM_READ_ONLY.search(docstring).group()}\"\n"
                    f"But code writes at line(s): {ops['file_write']}"
                ),
                owasp_mcp="MCP01",
                cia_impact=[CIAImpact.INTEGRITY],
                security_property=SecurityProperty.TASK_ALIGNMENT,
                tool_name=tool["name"],
            ))

        # Claim: pure compute/format → Actual: network calls
        # Skip if description explicitly acknowledges network/API usage
        if (CLAIM_PURE_COMPUTE.search(docstring) and ops["network"]
                and not DESC_ACKNOWLEDGES_NETWORK.search(docstring)):
            findings.append(Finding(
                id="MCPX-L4-002",
                title=f"Description-code mismatch: '{tool['name']}' claims computation but makes network requests",
                severity=Severity.HIGH,
                layer="L4",
                file=file_str,
                line=ops["network"][0],
                evidence=(
                    f"Description says: \"{CLAIM_PURE_COMPUTE.search(docstring).group()}\"\n"
                    f"But code makes network calls at line(s): {ops['network']}"
                ),
                owasp_mcp="MCP09",
                cia_impact=[CIAImpact.CONFIDENTIALITY],
                security_property=SecurityProperty.TASK_ALIGNMENT,
                tool_name=tool["name"],
            ))

        # Claim: pure compute/format → Actual: command execution
        # Skip if description explicitly acknowledges running commands
        if (CLAIM_PURE_COMPUTE.search(docstring) and ops["command_exec"]
                and not DESC_ACKNOWLEDGES_COMMANDS.search(docstring)):
            findings.append(Finding(
                id="MCPX-L4-003",
                title=f"Description-code mismatch: '{tool['name']}' claims computation but executes system commands",
                severity=Severity.CRITICAL,
                layer="L4",
                file=file_str,
                line=ops["command_exec"][0],
                evidence=(
                    f"Description says: \"{CLAIM_PURE_COMPUTE.search(docstring).group()}\"\n"
                    f"But code executes commands at line(s): {ops['command_exec']}"
                ),
                owasp_mcp="MCP09",
                cia_impact=[CIAImpact.INTEGRITY, CIAImpact.CONFIDENTIALITY],
                security_property=SecurityProperty.TASK_ALIGNMENT,
                tool_name=tool["name"],
            ))

        # Claim: no network/local only → Actual: network calls
        if CLAIM_NO_NETWORK.search(docstring) and ops["network"]:
            findings.append(Finding(
                id="MCPX-L4-004",
                title=f"Description-code mismatch: '{tool['name']}' claims no network but makes external requests",
                severity=Severity.CRITICAL,
                layer="L4",
                file=file_str,
                line=ops["network"][0],
                evidence=(
                    f"Description says: \"{CLAIM_NO_NETWORK.search(docstring).group()}\"\n"
                    f"But code makes network calls at line(s): {ops['network']}"
                ),
                owasp_mcp="MCP09",
                cia_impact=[CIAImpact.CONFIDENTIALITY],
                security_property=SecurityProperty.DATA_ISOLATION,
                tool_name=tool["name"],
            ))

        # Claim: read-only → Actual: command execution
        if CLAIM_READ_ONLY.search(docstring) and ops["command_exec"]:
            findings.append(Finding(
                id="MCPX-L4-005",
                title=f"Description-code mismatch: '{tool['name']}' claims read-only but executes commands",
                severity=Severity.CRITICAL,
                layer="L4",
                file=file_str,
                line=ops["command_exec"][0],
                evidence=(
                    f"Description says: \"{CLAIM_READ_ONLY.search(docstring).group()}\"\n"
                    f"But code executes commands at line(s): {ops['command_exec']}"
                ),
                owasp_mcp="MCP09",
                cia_impact=[CIAImpact.INTEGRITY, CIAImpact.CONFIDENTIALITY],
                security_property=SecurityProperty.TASK_ALIGNMENT,
                tool_name=tool["name"],
            ))

        # Claim: safe/harmless → Actual: dangerous calls
        if CLAIM_SAFE.search(docstring) and (ops["dangerous"] or ops["command_exec"]):
            danger_lines = ops["dangerous"] + ops["command_exec"]
            findings.append(Finding(
                id="MCPX-L4-006",
                title=f"Description-code mismatch: '{tool['name']}' claims safe/harmless but uses dangerous operations",
                severity=Severity.HIGH,
                layer="L4",
                file=file_str,
                line=danger_lines[0],
                evidence=(
                    f"Description says: \"{CLAIM_SAFE.search(docstring).group()}\"\n"
                    f"But code has dangerous calls at line(s): {danger_lines}"
                ),
                owasp_mcp="MCP01",
                cia_impact=[CIAImpact.INTEGRITY],
                security_property=SecurityProperty.TASK_ALIGNMENT,
                tool_name=tool["name"],
            ))

    return findings
