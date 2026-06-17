"""AI Deep Analysis: structured tool digest for AI blind-spot coverage.

Static analysis can't detect:
  1. Semantic data leaks (os.environ → return value, no dangerous API call)
  2. Async callback misbehavior (mirror/exfil hidden in _on_complete)
  3. Combination risk confirmation (two innocent tools that an agent can chain)

This module extracts a ToolDigest — a structured, code-free summary of what
a tool does — and sends it to the AI for blind-spot analysis.

Security boundary guarantee:
  - NO source code lines are sent.
  - NO string literal values (secrets, hardcoded URLs) are sent.
  - Only structural metadata: API names accessed, data flow direction,
    callback registrations, parameter names, and docstrings (which are
    already public in the MCP protocol).
"""

from __future__ import annotations

import ast
import re
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ── ToolDigest data model ─────────────────────────────────────────────────────

@dataclass
class ToolDigest:
    """Structural summary of an @mcp.tool() function.

    Contains only metadata — no source code, no string literal contents.
    Safe to send to external AI APIs.
    """
    tool_name: str
    file: str
    line: int

    # What the tool advertises
    description: str                     # docstring (already public via MCP protocol)
    params: list[str]                    # ["path: str", "mode: str = 'r'"]
    return_annotation: str               # "str" | "dict" | ""

    # Data sources (what sensitive data the tool reads)
    data_sources: list[str] = field(default_factory=list)
    # Examples: "os.environ (full dict)", "os.getenv('API_KEY')",
    #           "open(path, 'r')", "pathlib.read_text()"

    # Data sinks (where data goes)
    data_sinks: list[str] = field(default_factory=list)
    # Examples: "return value", "requests.post(url)", "logging.debug()",
    #           "socket.getaddrinfo(host)"

    # Async/callback behavior
    async_callbacks: list[str] = field(default_factory=list)
    # Names of functions registered as callbacks / awaited tasks
    callback_operations: list[str] = field(default_factory=list)
    # What those callbacks do (API names only, not code)

    # Control flow hint
    control_flow: str = "linear"         # "linear" | "async_callback" | "threaded"

    # Internal calls (to non-tool functions in the same file)
    internal_calls: list[str] = field(default_factory=list)

    def to_prompt_dict(self) -> dict:
        """Compact representation for AI prompt. Omits empty fields."""
        d: dict = {
            "tool": self.tool_name,
            "description": self.description or "(no description)",
            "params": self.params,
        }
        if self.data_sources:
            d["data_sources"] = self.data_sources
        if self.data_sinks:
            d["data_sinks"] = self.data_sinks
        if self.async_callbacks:
            d["async_callbacks"] = self.async_callbacks
            d["callback_operations"] = self.callback_operations
        if self.control_flow != "linear":
            d["control_flow"] = self.control_flow
        if self.internal_calls:
            d["internal_calls"] = self.internal_calls
        return d


# ── AST analysis helpers ──────────────────────────────────────────────────────

# Patterns that indicate reading env/credentials
_ENV_CALL = re.compile(r'^(?:os\.environ|os\.getenv|os\.environ\.get)$', re.I)

# Patterns that indicate reading files
_FILE_READ = re.compile(r'^(?:open|read_text|read_bytes|Path\.read_text|pathlib\.read_text)$', re.I)

# Patterns that indicate outbound network
_NET_SINK = re.compile(
    r'^(?:requests\.\w+|httpx\.\w+|urllib\.request\.\w+|'
    r'aiohttp\.\w+|session\.\w+|socket\.(?:getaddrinfo|gethostbyname|connect))$',
    re.I,
)

# Patterns that indicate logging sinks
_LOG_SINK = re.compile(r'^(?:logging\.\w+|logger\.\w+|log\.\w+|print)$', re.I)

# Async callback registration patterns
_CALLBACK_REGISTER = re.compile(
    r'^(?:add_done_callback|ensure_future|create_task|asyncio\.gather|'
    r'loop\.run_until_complete|asyncio\.create_task)$',
    re.I,
)


def _call_name(node: ast.Call) -> str:
    """Get dotted call name like 'os.environ.get' or 'requests.post'."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    elif isinstance(node.func, ast.Attribute):
        parts = []
        cur = node.func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""


def _attr_access(node: ast.Attribute) -> str:
    """Get 'os.environ' or 'os.environ.items' style access."""
    if isinstance(node.value, ast.Name):
        return f"{node.value.id}.{node.attr}"
    return ""


def _extract_func_ops(func_node: ast.FunctionDef, all_func_names: set[str]) -> dict:
    """Extract structural operations from a function body."""
    data_sources: list[str] = []
    data_sinks: list[str] = []
    callbacks: list[str] = []
    internal_calls: list[str] = []

    for node in ast.walk(func_node):
        # Attribute accesses: os.environ (not a call, just a read)
        if isinstance(node, ast.Attribute):
            attr = _attr_access(node)
            if attr in ("os.environ", "os.environ.items", "os.environ.copy"):
                src = "os.environ (full dict)"
                if src not in data_sources:
                    data_sources.append(src)

        # Call nodes
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        if not name:
            continue

        # Data sources
        if _ENV_CALL.match(name):
            # Distinguish single-key vs full-dict access
            if name == "os.environ" or (name == "os.getenv" and not node.args):
                src = "os.environ (full dict)"
            else:
                # Try to get the key name if it's a string literal
                key = ""
                if node.args and isinstance(node.args[0], ast.Constant):
                    key = f"['{node.args[0].value}']"
                src = f"os.getenv{key}" if "getenv" in name else f"os.environ{key}"
            if src not in data_sources:
                data_sources.append(src)

        elif _FILE_READ.match(name):
            src = f"{name}(path)"
            if src not in data_sources:
                data_sources.append(src)

        # Data sinks
        if _NET_SINK.match(name):
            sink = f"{name}(url/host)"
            if sink not in data_sinks:
                data_sinks.append(sink)

        elif _LOG_SINK.match(name):
            sink = f"{name}(message)"
            if sink not in data_sinks:
                data_sinks.append(sink)

        # Return-value sink (handled separately below)

        # Async callbacks
        if _CALLBACK_REGISTER.match(name):
            # Try to get the callback target name
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id in all_func_names:
                    # create_task(func_ref)
                    callbacks.append(arg.id)
                elif isinstance(arg, ast.Name):
                    callbacks.append(f"<func:{arg.id}>")
                elif isinstance(arg, ast.Call):
                    # create_task(func_call(...)) — extract the callee name
                    if isinstance(arg.func, ast.Name) and arg.func.id in all_func_names:
                        callbacks.append(arg.func.id)
                    elif isinstance(arg.func, ast.Name):
                        callbacks.append(f"<call:{arg.func.id}>")

        # Internal calls to other functions in the file
        if isinstance(node.func, ast.Name) and node.func.id in all_func_names:
            if node.func.id != func_node.name:
                if node.func.id not in internal_calls:
                    internal_calls.append(node.func.id)

    # Check if function has a return statement (non-None)
    for node in ast.walk(func_node):
        if isinstance(node, ast.Return) and node.value is not None:
            if "return value" not in data_sinks:
                data_sinks.append("return value (to AI agent context)")
            break

    return {
        "data_sources": data_sources,
        "data_sinks": data_sinks,
        "async_callbacks": callbacks,
        "internal_calls": internal_calls,
    }


def _get_callback_ops(
    callback_name: str,
    all_func_nodes: dict[str, ast.FunctionDef],
    all_func_names: set[str],
) -> list[str]:
    """Get the data sinks of a callback function (what it actually does)."""
    func = all_func_nodes.get(callback_name)
    if not func:
        return []
    ops = _extract_func_ops(func, all_func_names)
    return ops["data_sinks"] + ops["data_sources"]


def _param_repr(arg: ast.arg) -> str:
    """Format a parameter as 'name: type' or just 'name'."""
    if arg.annotation:
        ann = ast.unparse(arg.annotation) if hasattr(ast, "unparse") else ""
        return f"{arg.arg}: {ann}" if ann else arg.arg
    return arg.arg


# ── Main extractor ────────────────────────────────────────────────────────────

def extract_tool_digests(file_path: Path) -> list[ToolDigest]:
    """Extract ToolDigest for every @mcp.tool() in a Python file."""
    digests: list[ToolDigest] = []
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source)
    except (OSError, SyntaxError):
        return digests

    # Build file-level function index
    all_func_nodes: dict[str, ast.FunctionDef] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            all_func_nodes[node.name] = node
    all_func_names = set(all_func_nodes.keys())

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        is_tool = any("tool" in ast.dump(d).lower() for d in node.decorator_list)
        if not is_tool:
            continue

        # Description
        description = ast.get_docstring(node) or ""

        # Parameters (exclude self, ctx)
        params = [
            _param_repr(a)
            for a in node.args.args
            if a.arg not in ("self", "ctx")
        ]

        # Return type annotation
        ret_ann = ""
        if node.returns:
            ret_ann = ast.unparse(node.returns) if hasattr(ast, "unparse") else ""

        # Ops
        ops = _extract_func_ops(node, all_func_names)

        # Control flow
        is_async = isinstance(node, ast.AsyncFunctionDef)
        has_callbacks = bool(ops["async_callbacks"])
        has_threads = any("Thread" in str(n) for n in ast.walk(node))
        if has_callbacks or is_async:
            control_flow = "async_callback"
        elif has_threads:
            control_flow = "threaded"
        else:
            control_flow = "linear"

        # Resolve callback operations
        cb_ops: list[str] = []
        for cb_name in ops["async_callbacks"]:
            cb_ops.extend(_get_callback_ops(cb_name, all_func_nodes, all_func_names))
        # Also check functions called by the tool that might register callbacks
        for internal_name in ops["internal_calls"]:
            internal_node = all_func_nodes.get(internal_name)
            if internal_node:
                internal_ops = _extract_func_ops(internal_node, all_func_names)
                for cb_name in internal_ops["async_callbacks"]:
                    cb_ops.extend(_get_callback_ops(cb_name, all_func_nodes, all_func_names))
                    if cb_name not in ops["async_callbacks"]:
                        ops["async_callbacks"].append(cb_name)

        digests.append(ToolDigest(
            tool_name=node.name,
            file=str(file_path),
            line=node.lineno,
            description=description,
            params=params,
            return_annotation=ret_ann,
            data_sources=ops["data_sources"],
            data_sinks=ops["data_sinks"],
            async_callbacks=ops["async_callbacks"],
            callback_operations=list(set(cb_ops)),
            control_flow=control_flow,
            internal_calls=ops["internal_calls"],
        ))

    return digests


# ── Multi-file digest collection ──────────────────────────────────────────────

def collect_server_digests(py_files: list[Path]) -> list[ToolDigest]:
    """Collect ToolDigests from all Python files in the scan target."""
    all_digests: list[ToolDigest] = []
    for f in py_files:
        all_digests.extend(extract_tool_digests(f))
    return all_digests
