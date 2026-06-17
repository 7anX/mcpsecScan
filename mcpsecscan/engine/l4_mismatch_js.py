"""L4 for JS/TS: Description-code mismatch detection for JavaScript/TypeScript MCP servers.

JS/TS MCP servers use different registration patterns than Python:

Pattern A — Low-level SDK (most common in malicious samples):
    server.setRequestHandler("tools/list", async (req) => {
        return { tools: [{ name: "fetch_page", description: "...", ... }] }
    })
    server.setRequestHandler("tools/call", async (req) => {
        if (name === "fetch_page") { /* handler body */ }
    })

Pattern B — High-level McpServer SDK (modern):
    server.tool("name", "description", zodSchema, async (args) => { ... })

Pattern C — ListToolsRequestSchema / CallToolRequestSchema:
    server.setRequestHandler(ListToolsRequestSchema, async () => [...])
    server.setRequestHandler(CallToolRequestSchema, async (req) => { ... })

We use regex-based analysis (not a full JS AST parser) because:
1. Installing a JS parser (acorn, tree-sitter) adds a heavy dependency
2. The patterns are regular enough for regex to work well in practice
3. Keeps the tool fully offline and fast (<5s)
"""

from __future__ import annotations

import re
from pathlib import Path

from mcpsecscan.engine.models import (
    Finding, Severity, Confidence, CIAImpact, SecurityProperty
)

# ── Tool registration extraction ─────────────────────────────────────────────

# Pattern A: tools/list handler — extract tool name + description
# Matches objects that have BOTH name AND description (tool definitions inside tools array).
# Uses a tighter anchor: requires inputSchema or type nearby to reduce false positives
# on server-level name fields like { name: "server-name", version: "1.0" }.
_TOOL_DEF_RE = re.compile(
    r'name\s*:\s*["\'](?P<name>[^"\']{1,64})["\']'
    r'(?:(?!version\s*:).){0,300}?'   # must NOT be followed by version: (server config)
    r'description\s*:\s*["\'](?P<desc>[^"\']{1,500})["\']',
    re.S,
)

# Negative filter: skip matches that look like server/transport config
_SERVER_CONFIG_RE = re.compile(
    r'(?:version\s*:\s*["\'][^"\']+["\']|capabilities\s*:)',
    re.I,
)

# Pattern B: server.tool("name", "description", ...) — high-level SDK
_SERVER_TOOL_RE = re.compile(
    r'\.tool\s*\(\s*["\'](?P<name>[^"\']+)["\']\s*,\s*["\'](?P<desc>[^"\']{0,500})["\']',
    re.S,
)

# Pattern B variant: server.tool("name", { description: "..." }, ...)
_SERVER_TOOL_OBJ_RE = re.compile(
    r'\.tool\s*\(\s*["\'](?P<name>[^"\']+)["\']\s*,\s*\{[^}]*?description\s*:\s*["\'](?P<desc>[^"\']{0,500})["\']',
    re.S,
)

# Extract handler bodies for a given tool name from tools/call handler
# Looks for:  if (name === "foo") { ... }  or  case "foo": { ... }
def _extract_handler_body(source: str, tool_name: str) -> str:
    """Extract the JS code block that handles a specific tool name."""
    escaped = re.escape(tool_name)
    # if (name === "foo") { ... } or if (name == "foo") { ... }
    pattern = re.compile(
        r'(?:if\s*\(\s*name\s*===?\s*["\']' + escaped + r'["\']|'
        r'case\s+["\']' + escaped + r'["\']:)',
        re.S,
    )
    m = pattern.search(source)
    if not m:
        return ""
    # Extract the block — find matching braces
    start = m.end()
    # Skip to the opening brace
    brace_pos = source.find("{", start)
    if brace_pos == -1:
        # case statement without braces — grab until next case/default/}
        end = re.search(r'\b(?:case|default)\b|^\s*\}', source[start:], re.M)
        return source[start: start + end.start()] if end else source[start: start + 500]
    # Balance braces
    depth = 0
    pos = brace_pos
    while pos < len(source):
        ch = source[pos]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return source[brace_pos: pos + 1]
        pos += 1
    return source[brace_pos: brace_pos + 2000]


def _extract_tool_handler_body_pattern_b(source: str, tool_name: str) -> str:
    """For Pattern B: server.tool("name", ..., handler) — extract the last arrow function."""
    escaped = re.escape(tool_name)
    pattern = re.compile(
        r'\.tool\s*\(\s*["\']' + escaped + r'["\'].*?(?:async\s*)?\(?(?:\w+)?\)?\s*=>\s*\{',
        re.S,
    )
    m = pattern.search(source)
    if not m:
        return ""
    start = source.rfind("{", 0, m.end())
    if start == -1:
        return ""
    depth = 0
    pos = start
    while pos < len(source):
        ch = source[pos]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return source[start: pos + 1]
        pos += 1
    return source[start: start + 2000]


# ── Dangerous operation detection (regex on JS/TS code) ──────────────────────

# File write operations
_JS_FILE_WRITE = re.compile(
    r'\b(?:'
    r'fs\.(?:write(?:File)?Sync?|append(?:File)?Sync?|mkdir(?:Sync)?|rename(?:Sync)?|'
    r'unlink(?:Sync)?|rmdir(?:Sync)?|rm(?:Sync)?|chmod(?:Sync)?|copyFile(?:Sync)?)|'
    r'fsp?\.write(?:File)?|'
    r'createWriteStream|'
    r'\.write\s*\(|\.end\s*\(|'  # writable stream
    r'Deno\.writeFile|Deno\.writeTextFile'
    r')\b',
    re.I,
)

# Network operations
_JS_NETWORK = re.compile(
    r'(?:'
    r'\bfetch\s*\(|'
    r'\baxios\.|'
    r'\b(?:http|https)\.(?:get|post|request|put|delete)\s*\(|'
    r'\b(?:got|superagent|needle|node-fetch)\.|'
    r'\bXMLHttpRequest\b|'
    r'\bnew\s+WebSocket\s*\(|'
    r'\bnet\.(?:connect|createConnection)\s*\(|'
    r'\bDeno\.connect\b'
    r')',
    re.I,
)

# Command execution
_JS_CMD_EXEC = re.compile(
    r'\b(?:'
    r'(?:child_process\.)?\s*(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\(|'
    r'shelljs\.|'
    r'shell\.exec\s*\(|'
    r'Deno\.run\s*\(|Deno\.Command\s*\(|'
    r'execa\s*\('
    r')\b',
    re.I,
)

# Dangerous eval-like operations
_JS_DANGEROUS = re.compile(
    r'\b(?:'
    r'eval\s*\(|'
    r'new\s+Function\s*\(|'
    r'vm\.(?:runInNewContext|runInThisContext|Script)\s*\(|'
    r'require\s*\(\s*(?:user|input|args|param)|'  # dynamic require
    r'import\s*\(\s*(?!["\'`])'  # dynamic import with variable
    r')\b',
    re.I,
)

# SQL execution patterns
_JS_SQL_EXEC = re.compile(
    r'(?:'
    r'\.(?:query|execute|run|prepare|exec)\s*\(\s*(?:`[^`]*\$\{|["\'][^"\']*\$|[a-zA-Z_]\w*\s*[,)])|'
    r'db\.(?:prepare|query)\s*\(`[^`]*\$\{'
    r')',
    re.I,
)


def _analyze_js_body(body: str) -> dict[str, list[int]]:
    """Detect dangerous operations in a JS/TS handler body.

    Returns dict of op_category → list of approximate line offsets.
    Line numbers are approximate (counted from start of body).
    """
    ops: dict[str, list[int]] = {
        "file_write": [],
        "network": [],
        "command_exec": [],
        "dangerous": [],
        "sql_exec": [],
    }
    if not body:
        return ops

    lines = body.split("\n")
    for i, line in enumerate(lines, 1):
        # Skip comment lines
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        if _JS_FILE_WRITE.search(line):
            ops["file_write"].append(i)
        if _JS_NETWORK.search(line):
            ops["network"].append(i)
        if _JS_CMD_EXEC.search(line):
            ops["command_exec"].append(i)
        if _JS_DANGEROUS.search(line):
            ops["dangerous"].append(i)
        if _JS_SQL_EXEC.search(line):
            ops["sql_exec"].append(i)
    return ops


# ── Claim detection (same keywords as Python L4) ─────────────────────────────

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
DESC_ACKNOWLEDGES_NETWORK = re.compile(
    r'\b(?:fetch|request|call|connect|query)\b.*\b(?:api|http|server|endpoint|service|url)\b',
    re.I,
)
DESC_ACKNOWLEDGES_COMMANDS = re.compile(
    r'\b(?:execut|run[s ]|invoke[s ]|call[s ])\b.*\b(?:command|shell|script|process|program)\b',
    re.I,
)

# ── Reverse detection keyword sets ───────────────────────────────────────────
DESC_DISCLOSES_WRITE = re.compile(
    r'\b(?:writ|modif|creat|delet|updat|append|remov|chang|sav|stor|overwrite|generat)\w*\b',
    re.I,
)
DESC_DISCLOSES_NETWORK = re.compile(
    r'\b(?:fetch|request|call|connect|send|upload|download|post|get|http|api|url|endpoint|network|internet|external|remote)\w*\b',
    re.I,
)
DESC_DISCLOSES_COMMAND = re.compile(
    r'\b(?:execut|run|invoke|call|spawn|launch|command|shell|subprocess|process|script|bash|sh|cmd|terminal)\w*\b',
    re.I,
)


# ── Tool extraction from source ───────────────────────────────────────────────

def _extract_tools_from_js(source: str) -> list[dict]:
    """Extract tool name + description + handler body from JS/TS source."""
    tools = []
    seen_names: set[str] = set()

    def _add(name: str, desc: str, body: str) -> None:
        if name in seen_names:
            return
        seen_names.add(name)
        tools.append({"name": name, "description": desc, "body": body})

    # Pattern A: tools/list + tools/call handlers
    for m in _TOOL_DEF_RE.finditer(source):
        name = m.group("name")
        desc = m.group("desc")
        # Skip server/transport config objects (contain version: or capabilities: nearby)
        context = source[max(0, m.start() - 20): m.end() + 120]
        if _SERVER_CONFIG_RE.search(context):
            continue
        body = _extract_handler_body(source, name)
        _add(name, desc, body)

    # Pattern B: server.tool("name", "description", ...)
    for m in _SERVER_TOOL_RE.finditer(source):
        name = m.group("name")
        desc = m.group("desc")
        body = _extract_tool_handler_body_pattern_b(source, name)
        _add(name, desc, body)

    # Pattern B variant: server.tool("name", { description: "..." }, ...)
    for m in _SERVER_TOOL_OBJ_RE.finditer(source):
        name = m.group("name")
        desc = m.group("desc")
        if name not in seen_names:
            body = _extract_tool_handler_body_pattern_b(source, name)
            _add(name, desc, body)

    return tools


# ── Public entry point ────────────────────────────────────────────────────────

def run_l4_js(file_path: Path) -> list[Finding]:
    """Run L4 description-code mismatch analysis on a JS/TS file."""
    findings: list[Finding] = []
    file_str = str(file_path)

    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return findings

    tools = _extract_tools_from_js(source)

    for tool in tools:
        name = tool["name"]
        desc = tool["description"]
        body = tool["body"]

        if not desc:
            # No description — check if handler body has dangerous ops
            if body:
                ops = _analyze_js_body(body)
                dangerous = ops["command_exec"] + ops["file_write"] + ops["network"] + ops["dangerous"]
                if dangerous:
                    findings.append(Finding(
                        id="MCPX-L4-007",
                        title=f"JS tool '{name}' has no description but performs dangerous operations",
                        severity=Severity.HIGH,
                        layer="L4",
                        file=file_str,
                        line=0,
                        evidence=(
                            f"No description found. "
                            f"Handler performs: "
                            + ", ".join(k for k, v in ops.items() if v)
                        ),
                        owasp_mcp="MCP01",
                        cia_impact=[CIAImpact.INTEGRITY, CIAImpact.CONFIDENTIALITY],
                        security_property=SecurityProperty.TASK_ALIGNMENT,
                        tool_name=name,
                        confidence=Confidence.MEDIUM,
                    ))
            continue

        if not body:
            # Have description but couldn't extract body — skip mismatch checks
            continue

        ops = _analyze_js_body(body)

        # Claim: read-only → file writes
        if CLAIM_READ_ONLY.search(desc) and ops["file_write"]:
            findings.append(Finding(
                id="MCPX-L4-001",
                title=f"JS tool '{name}' claims read-only but writes files",
                severity=Severity.CRITICAL,
                layer="L4",
                file=file_str,
                line=0,
                evidence=(
                    f"Description: \"{CLAIM_READ_ONLY.search(desc).group()}\"\n"
                    f"Handler calls fs.write*/appendFile/unlink at relative lines: {ops['file_write']}"
                ),
                owasp_mcp="MCP01",
                cia_impact=[CIAImpact.INTEGRITY],
                security_property=SecurityProperty.TASK_ALIGNMENT,
                tool_name=name,
            ))

        # Claim: pure compute → network calls
        if (CLAIM_PURE_COMPUTE.search(desc) and ops["network"]
                and not DESC_ACKNOWLEDGES_NETWORK.search(desc)):
            findings.append(Finding(
                id="MCPX-L4-002",
                title=f"JS tool '{name}' claims computation but makes network requests",
                severity=Severity.HIGH,
                layer="L4",
                file=file_str,
                line=0,
                evidence=(
                    f"Description: \"{CLAIM_PURE_COMPUTE.search(desc).group()}\"\n"
                    f"Handler calls fetch/axios/http at relative lines: {ops['network']}"
                ),
                owasp_mcp="MCP09",
                cia_impact=[CIAImpact.CONFIDENTIALITY],
                security_property=SecurityProperty.TASK_ALIGNMENT,
                tool_name=name,
            ))

        # Claim: pure compute → command execution
        if (CLAIM_PURE_COMPUTE.search(desc) and ops["command_exec"]
                and not DESC_ACKNOWLEDGES_COMMANDS.search(desc)):
            findings.append(Finding(
                id="MCPX-L4-003",
                title=f"JS tool '{name}' claims computation but executes system commands",
                severity=Severity.CRITICAL,
                layer="L4",
                file=file_str,
                line=0,
                evidence=(
                    f"Description: \"{CLAIM_PURE_COMPUTE.search(desc).group()}\"\n"
                    f"Handler calls exec/spawn/shell at relative lines: {ops['command_exec']}"
                ),
                owasp_mcp="MCP09",
                cia_impact=[CIAImpact.INTEGRITY, CIAImpact.CONFIDENTIALITY],
                security_property=SecurityProperty.TASK_ALIGNMENT,
                tool_name=name,
            ))

        # Claim: no network → network calls
        if CLAIM_NO_NETWORK.search(desc) and ops["network"]:
            findings.append(Finding(
                id="MCPX-L4-004",
                title=f"JS tool '{name}' claims no network but makes external requests",
                severity=Severity.CRITICAL,
                layer="L4",
                file=file_str,
                line=0,
                evidence=(
                    f"Description: \"{CLAIM_NO_NETWORK.search(desc).group()}\"\n"
                    f"Handler calls fetch/http at relative lines: {ops['network']}"
                ),
                owasp_mcp="MCP09",
                cia_impact=[CIAImpact.CONFIDENTIALITY],
                security_property=SecurityProperty.DATA_ISOLATION,
                tool_name=name,
            ))

        # Claim: read-only → command execution
        if CLAIM_READ_ONLY.search(desc) and ops["command_exec"]:
            findings.append(Finding(
                id="MCPX-L4-005",
                title=f"JS tool '{name}' claims read-only but executes commands",
                severity=Severity.CRITICAL,
                layer="L4",
                file=file_str,
                line=0,
                evidence=(
                    f"Description: \"{CLAIM_READ_ONLY.search(desc).group()}\"\n"
                    f"Handler calls exec/spawn at relative lines: {ops['command_exec']}"
                ),
                owasp_mcp="MCP09",
                cia_impact=[CIAImpact.INTEGRITY, CIAImpact.CONFIDENTIALITY],
                security_property=SecurityProperty.TASK_ALIGNMENT,
                tool_name=name,
            ))

        # Claim: safe/harmless → dangerous/command ops
        if CLAIM_SAFE.search(desc) and (ops["dangerous"] or ops["command_exec"]):
            danger_lines = ops["dangerous"] + ops["command_exec"]
            findings.append(Finding(
                id="MCPX-L4-006",
                title=f"JS tool '{name}' claims safe/harmless but uses dangerous operations",
                severity=Severity.HIGH,
                layer="L4",
                file=file_str,
                line=0,
                evidence=(
                    f"Description: \"{CLAIM_SAFE.search(desc).group()}\"\n"
                    f"Handler uses eval/exec/spawn at relative lines: {danger_lines}"
                ),
                owasp_mcp="MCP01",
                cia_impact=[CIAImpact.INTEGRITY],
                security_property=SecurityProperty.TASK_ALIGNMENT,
                tool_name=name,
            ))

        # Raw SQL with template literals
        if ops["sql_exec"]:
            findings.append(Finding(
                id="MCPX-L4-009",
                title=f"JS tool '{name}' executes dynamic SQL (template literal injection risk)",
                severity=Severity.HIGH,
                layer="L4",
                file=file_str,
                line=0,
                evidence=(
                    f"Handler uses db.query/execute with template literals at "
                    f"relative lines: {ops['sql_exec']}. "
                    f"Use parameterized queries instead."
                ),
                owasp_mcp="MCP09",
                cia_impact=[CIAImpact.CONFIDENTIALITY, CIAImpact.INTEGRITY],
                security_property=SecurityProperty.DATA_ISOLATION,
                tool_name=name,
                confidence=Confidence.MEDIUM,
            ))

        # ── Reverse detection: dangerous op present but description never discloses it ──
        # Catches neutral descriptions like "helper tool", "process data", "assistant"

        if (ops["file_write"]
                and not DESC_DISCLOSES_WRITE.search(desc)
                and not CLAIM_READ_ONLY.search(desc)):
            findings.append(Finding(
                id="MCPX-L4-010",
                title=f"JS tool '{name}' writes files but description never mentions it",
                severity=Severity.HIGH,
                layer="L4",
                file=file_str,
                line=0,
                evidence=(
                    f"Description contains no write-related keywords, "
                    f"but handler writes files at relative lines: {ops['file_write']}"
                ),
                owasp_mcp="MCP01",
                cia_impact=[CIAImpact.INTEGRITY],
                security_property=SecurityProperty.TASK_ALIGNMENT,
                tool_name=name,
                confidence=Confidence.MEDIUM,
            ))

        if (ops["network"]
                and not DESC_DISCLOSES_NETWORK.search(desc)
                and not DESC_ACKNOWLEDGES_NETWORK.search(desc)):
            findings.append(Finding(
                id="MCPX-L4-011",
                title=f"JS tool '{name}' makes network requests but description never mentions it",
                severity=Severity.HIGH,
                layer="L4",
                file=file_str,
                line=0,
                evidence=(
                    f"Description contains no network-related keywords, "
                    f"but handler makes requests at relative lines: {ops['network']}"
                ),
                owasp_mcp="MCP09",
                cia_impact=[CIAImpact.CONFIDENTIALITY],
                security_property=SecurityProperty.DATA_ISOLATION,
                tool_name=name,
                confidence=Confidence.MEDIUM,
            ))

        if (ops["command_exec"]
                and not DESC_DISCLOSES_COMMAND.search(desc)
                and not DESC_ACKNOWLEDGES_COMMANDS.search(desc)):
            findings.append(Finding(
                id="MCPX-L4-012",
                title=f"JS tool '{name}' executes system commands but description never mentions it",
                severity=Severity.CRITICAL,
                layer="L4",
                file=file_str,
                line=0,
                evidence=(
                    f"Description contains no command-related keywords, "
                    f"but handler spawns processes at relative lines: {ops['command_exec']}"
                ),
                owasp_mcp="MCP09",
                cia_impact=[CIAImpact.INTEGRITY, CIAImpact.CONFIDENTIALITY],
                security_property=SecurityProperty.TASK_ALIGNMENT,
                tool_name=name,
                confidence=Confidence.MEDIUM,
            ))

    return findings
