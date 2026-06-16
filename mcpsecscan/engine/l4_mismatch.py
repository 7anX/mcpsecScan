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
    # asyncio subprocess variants (mcp-shell-server pattern)
    "asyncio.create_subprocess_shell",
    "asyncio.create_subprocess_exec",
    "create_subprocess_shell",
    "create_subprocess_exec",
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


def _iter_direct_calls(func_node: ast.FunctionDef):
    """Iterate over Call nodes in func_node's body WITHOUT descending into
    nested function/class definitions.

    ast.walk() recurses into nested defs, which causes false positives when
    a tool defines a helper function inside itself (e.g. mcp-alchemy's
    execute_query defines save_full_results inside its body). Those inner
    operations are not directly triggered by the tool's execution path.
    """
    for child in ast.iter_child_nodes(func_node):
        # Don't recurse into nested function/class defs
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        yield from _iter_calls_shallow(child)


def _iter_calls_shallow(node: ast.AST):
    """Yield all Call nodes in subtree, not crossing into nested func/class defs."""
    if isinstance(node, ast.Call):
        yield node
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        yield from _iter_calls_shallow(child)


def _analyze_function_operations(func_node: ast.FunctionDef) -> dict[str, list[int]]:
    """Analyze what operations a function directly performs.

    Deliberately does NOT descend into nested function/class definitions to
    avoid false positives from helper functions defined inside the tool body.

    Returns dict with categories and line numbers where they occur.
    """
    ops: dict[str, list[int]] = {
        "file_write": [],
        "file_read": [],
        "network": [],
        "command_exec": [],
        "dangerous": [],
        "sql_exec": [],      # direct SQL execution (new)
    }

    for node in _iter_direct_calls(func_node):
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

        # Command execution — subprocess, os.system, asyncio subprocess
        elif any(call_name.startswith(prefix) for prefix in (
            "subprocess.", "os.system", "os.popen",
            "asyncio.create_subprocess", "create_subprocess",
        )):
            ops["command_exec"].append(lineno)
        # paramiko exec_command (SSH remote execution)
        elif call_name.endswith(".exec_command"):
            ops["command_exec"].append(lineno)

        # SQL execution — conn/cursor.execute / .executemany with non-trivial first arg
        elif call_name.endswith((".execute", ".executemany", ".exec", ".run_sync")):
            # Only flag if first argument is not a plain string literal
            # (parameterized queries with a literal template are acceptable;
            # f-strings or variable references are suspicious)
            if node.args:
                first_arg = node.args[0]
                # JoinedStr = f-string, Name = variable, BinOp = concatenation
                if isinstance(first_arg, (ast.JoinedStr, ast.Name, ast.BinOp)):
                    ops["sql_exec"].append(lineno)
                elif isinstance(first_arg, ast.Constant):
                    pass  # hardcoded SQL template — safe (params in second arg)

        # Dangerous
        elif call_name in ("eval", "exec", "compile"):
            ops["dangerous"].append(lineno)
        elif call_name in ("pickle.load", "pickle.loads", "yaml.load", "marshal.load"):
            ops["dangerous"].append(lineno)

    return ops


def _get_decorator_description(dec: ast.expr) -> str:
    """Extract the 'description' keyword argument from a @mcp.tool(description=...)
    decorator call, if present. Returns empty string if not found."""
    if not isinstance(dec, ast.Call):
        return ""
    for kw in dec.keywords:
        if kw.arg == "description":
            # Could be a string literal or a function call that returns a string.
            # We only handle string literals here; call results are opaque.
            if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                return kw.value.value
    return ""


def _extract_mcp_tools(tree: ast.AST) -> list[dict]:
    """Extract MCP tool functions with their docstrings (or decorator descriptions)."""
    tools = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            dec_str = ast.dump(dec)
            if "tool" in dec_str.lower():
                # Prefer docstring; fall back to description= kwarg in decorator
                docstring = ast.get_docstring(node) or _get_decorator_description(dec)
                # If the decorator description is a dynamic call (e.g.
                # description=execute_query_description()), it won't be
                # extractable statically — but that still counts as "has description",
                # so we mark it as "<dynamic description>" to avoid L4-007 false positives.
                if not docstring and isinstance(dec, ast.Call):
                    for kw in dec.keywords:
                        if kw.arg == "description" and isinstance(kw.value, ast.Call):
                            docstring = "<dynamic description>"
                            break
                # Extract parameter names for cross-function call detection
                params = [arg.arg for arg in node.args.args if arg.arg not in ("self", "ctx")]
                tools.append({
                    "name": node.name,
                    "docstring": docstring,
                    "node": node,
                    "lineno": node.lineno,
                    "params": params,
                })
                break
    return tools


# Patterns that suggest a called function does dangerous things
_DANGEROUS_CALLEE_NAMES = re.compile(
    r'(?:exec(?:ute)?_?(?:command|cmd|shell|query|script|process)|'
    r'run_?(?:command|cmd|shell|script|process)|'
    r'spawn_?(?:process|shell)|'
    r'shell_?(?:exec|run|cmd))',
    re.I,
)
# Parameter names that typically carry user-controlled shell input
_DANGEROUS_PARAM_NAMES = re.compile(
    r'\b(?:command|cmd|shell_cmd|script|query|sql|code)\b',
    re.I,
)


def _check_dangerous_delegate(tool_node: ast.FunctionDef, tool_params: list[str]) -> list[int]:
    """Detect calls to functions that sound like command/query execution
    where a tool parameter is passed as an argument.

    This catches the sshmcp pattern:
        def vault_exec(command: str) -> ...:
            execute_command(..., command=command, ...)  # <-- tool param flows to exec sink

    Returns list of line numbers where delegation was detected.
    """
    hits = []
    for node in ast.walk(tool_node):
        if not isinstance(node, ast.Call):
            continue
        # Get the called function name
        if isinstance(node.func, ast.Name):
            callee = node.func.id
        elif isinstance(node.func, ast.Attribute):
            callee = node.func.attr
        else:
            continue
        if not _DANGEROUS_CALLEE_NAMES.search(callee):
            continue
        # Check if any tool param is passed as argument
        all_arg_names = set()
        for kw in node.keywords:
            if kw.arg:
                all_arg_names.add(kw.arg)
            if isinstance(kw.value, ast.Name):
                all_arg_names.add(kw.value.id)
        for arg in node.args:
            if isinstance(arg, ast.Name):
                all_arg_names.add(arg.id)
        if any(p in all_arg_names for p in tool_params):
            hits.append(getattr(node, "lineno", 0))
    return hits


def _merge_callee_ops(
    tool_node: ast.FunctionDef,
    file_func_ops: dict[str, dict[str, list[int]]],
    ops: dict[str, list[int]],
) -> None:
    """Merge ops from directly-called local functions into the tool's ops dict (depth=2).

    Catches the mcp-shell-server pattern:
        call_tool() → self.shell_executor.execute(command) → asyncio.create_subprocess_shell

    We look at all Call nodes in the tool body. If the callee is a local function
    whose name appears in file_func_ops, we merge its ops into the tool's ops,
    adjusting line numbers to point to the call site.
    """
    for node in _iter_direct_calls(tool_node):
        if not isinstance(node, ast.Call):
            continue
        callee = ""
        if isinstance(node.func, ast.Name):
            callee = node.func.id
        elif isinstance(node.func, ast.Attribute):
            callee = node.func.attr  # method name only

        callee_ops = file_func_ops.get(callee)
        if not callee_ops:
            continue
        call_lineno = getattr(node, "lineno", 0)
        for op_category, lines in callee_ops.items():
            if lines and op_category in ops:
                # Use the call-site line number so the finding points to the delegation
                ops[op_category] = ops[op_category] or [call_lineno]


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

    # Build a file-level function operation index for depth-2 call resolution.
    # Maps function_name → ops dict so that when a tool calls another local function
    # we can look up what that function actually does.
    file_func_ops: dict[str, dict[str, list[int]]] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            file_func_ops[node.name] = _analyze_function_operations(node)

    for tool in tools:
        docstring = tool["docstring"]

        # Analyze actual operations (needed for both docstring and no-docstring paths)
        # Merge direct ops with ops from called local functions (depth=2)
        ops = _analyze_function_operations(tool["node"])
        _merge_callee_ops(tool["node"], file_func_ops, ops)

        # ─── Check 0: No docstring but performs dangerous operations ───
        # A tool with no description that executes commands / writes files / makes
        # network calls is suspicious — the AI agent has no way to know what it does.
        if not docstring:
            dangerous_ops = ops["command_exec"] + ops["file_write"] + ops["network"] + ops["dangerous"]
            if dangerous_ops:
                op_labels = []
                if ops["command_exec"]: op_labels.append(f"command_exec@{ops['command_exec']}")
                if ops["file_write"]: op_labels.append(f"file_write@{ops['file_write']}")
                if ops["network"]: op_labels.append(f"network@{ops['network']}")
                if ops["dangerous"]: op_labels.append(f"dangerous@{ops['dangerous']}")
                findings.append(Finding(
                    id="MCPX-L4-007",
                    title=f"Tool '{tool['name']}' has no description but performs dangerous operations",
                    severity=Severity.HIGH,
                    layer="L4",
                    file=file_str,
                    line=dangerous_ops[0],
                    evidence=(
                        f"No docstring — AI agent cannot know this tool's behavior. "
                        f"Operations: {', '.join(op_labels)}"
                    ),
                    owasp_mcp="MCP01",
                    cia_impact=[CIAImpact.INTEGRITY, CIAImpact.CONFIDENTIALITY],
                    security_property=SecurityProperty.TASK_ALIGNMENT,
                    tool_name=tool["name"],
                    confidence=Confidence.HIGH,
                ))
            continue  # no docstring — skip the mismatch checks below

        # ─── Check 0b: Dangerous delegation — tool param forwarded to exec-sounding function ───
        # Catches: vault_exec(command) → execute_command(..., command=command)
        # This detects cross-function command injection without needing full taint analysis.
        delegate_lines = _check_dangerous_delegate(tool["node"], tool.get("params", []))
        if delegate_lines:
            findings.append(Finding(
                id="MCPX-L4-008",
                title=f"Tool '{tool['name']}' passes user parameter to dangerous delegated function",
                severity=Severity.HIGH,
                layer="L4",
                file=file_str,
                line=delegate_lines[0],
                evidence=(
                    f"Tool params {tool.get('params', [])} forwarded to execution-sounding callee "
                    f"at line(s): {delegate_lines}. "
                    f"Static analysis cannot confirm safety — verify manual sanitization."
                ),
                owasp_mcp="MCP09",
                cia_impact=[CIAImpact.INTEGRITY, CIAImpact.CONFIDENTIALITY, CIAImpact.AVAILABILITY],
                security_property=SecurityProperty.DATA_ISOLATION,
                tool_name=tool["name"],
                confidence=Confidence.MEDIUM,
            ))

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

        # ─── Check: tool accepts raw SQL string AND executes it with dynamic argument ───
        # Catches: def query(sql: str) → conn.execute(sql, ...) where sql is a Name/variable
        # This is the mcp-toolkit sqlite_explorer pattern: tool accepts sql param directly.
        if ops["sql_exec"]:
            # Check if any tool param name suggests it's raw SQL input
            sql_params = [p for p in tool.get("params", [])
                          if re.search(r'\b(?:sql|query|statement|stmt)\b', p, re.I)]
            if sql_params:
                findings.append(Finding(
                    id="MCPX-L4-009",
                    title=f"Tool '{tool['name']}' accepts raw SQL parameter and executes it directly",
                    severity=Severity.HIGH,
                    layer="L4",
                    file=file_str,
                    line=ops["sql_exec"][0],
                    evidence=(
                        f"Parameter(s) {sql_params} flow to DB execute() with "
                        f"dynamic SQL at line(s): {ops['sql_exec']}. "
                        f"Verify L3 taint analysis for SQL injection risk."
                    ),
                    owasp_mcp="MCP09",
                    cia_impact=[CIAImpact.CONFIDENTIALITY, CIAImpact.INTEGRITY],
                    security_property=SecurityProperty.DATA_ISOLATION,
                    tool_name=tool["name"],
                    confidence=Confidence.MEDIUM,
                ))

    return findings
