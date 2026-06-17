"""Main scanner orchestrator — runs L1 through L5 in sequence."""

from __future__ import annotations

from pathlib import Path

from mcpsecscan.engine.models import ScanResult, Severity, Confidence
from mcpsecscan.engine.l1_quick import run_l1, run_l1_js
from mcpsecscan.engine.l2_structure import run_l2
from mcpsecscan.engine.l2_combo import run_l2_combo
from mcpsecscan.engine.l3_taint import run_l3, is_available as l3_available
from mcpsecscan.engine.l4_mismatch import run_l4
from mcpsecscan.engine.l4_mismatch_js import run_l4_js
from mcpsecscan.engine.l5_multifile import run_l5

# Supported file extensions per layer
_PY_EXTS = {".py"}
_JS_EXTS = {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}
_ALL_EXTS = _PY_EXTS | _JS_EXTS

# ─── Remediation guidance ─────────────────────────────────────────────────────
_REMEDIATION: dict[str, str] = {
    # L1
    "MCPX-L1-001": "Rotate the AWS key immediately. Use IAM roles or environment variables; never hardcode credentials.",
    "MCPX-L1-002": "Revoke the GitHub token at https://github.com/settings/tokens. Use environment variables or secret managers.",
    "MCPX-L1-003": "Revoke the OpenAI key at platform.openai.com. Load via os.getenv() only.",
    "MCPX-L1-004": "Revoke the Anthropic key at console.anthropic.com. Load via os.getenv() only.",
    "MCPX-L1-005": "Revoke the Google AI key. Load via os.getenv() only.",
    "MCPX-L1-006": "Revoke the Slack token at api.slack.com/apps. Load via os.getenv() only.",
    "MCPX-L1-007": "Remove the private key from source code. Use a key file path loaded from env and never committed.",
    "MCPX-L1-008": "Revoke the Stripe key immediately at dashboard.stripe.com/apikeys.",
    "MCPX-L1-009": "Rotate the API token. Never embed credentials in source code.",
    "MCPX-L1-010": "Replace pickle with a safe serialization format (json, msgpack). If pickle is required, validate the source path and restrict it to a trusted directory.",
    "MCPX-L1-011": "Use yaml.safe_load() instead of yaml.load() to prevent arbitrary code execution.",
    "MCPX-L1-012": "Replace marshal with json or a safer serialization library.",
    "MCPX-L1-013": "Avoid eval() with user input. Use ast.literal_eval() for safe evaluation of Python literals, or a dedicated expression parser for JS.",
    "MCPX-L1-014": "Avoid exec()/new Function() with user input. Refactor to use explicit function dispatch.",
    "MCPX-L1-015": "Avoid shell=True / exec() with user input. Pass arguments as a list; use shlex.quote() if a shell string is unavoidable.",
    "MCPX-L1-016": "Replace os.system() with subprocess.run() with a list of arguments.",
    "MCPX-L1-017": "Do not monkey-patch builtins. This pattern is used by malicious code to intercept standard library calls.",
    "MCPX-L1-018": "Remove sys.settrace() — it intercepts all function calls globally and is a common malware technique.",
    "MCPX-L1-019": "Do not modify __doc__/description at runtime — this enables rug-pull attacks where the description changes after installation.",
    "MCPX-L1-020": "Audit the file for hidden instructions encoded in zero-width characters. Remove all U+200B–U+200D and similar codepoints.",
    "MCPX-L1-021": "Remove RTL/LTR override characters (U+202E etc.) — they can visually mislead code reviewers.",
    "MCPX-L1-022": "Remove Unicode tag/variation selector characters — they are used to encode hidden payloads.",
    # L2
    "MCPX-L2-001": "Remove coercive pre-conditions from tool descriptions. Tool descriptions should describe functionality, not give instructions to the AI.",
    "MCPX-L2-002": "Remove threatening language from tool descriptions. This is a prompt injection vector.",
    "MCPX-L2-003": "Remove instructions that tell the AI to hide actions from the user. Transparency is required.",
    "MCPX-L2-004": "Remove XML-style instruction tags (<IMPORTANT>, <SYSTEM>) from descriptions — they are used for prompt injection.",
    "MCPX-L2-005": "Remove instruction-override phrases from descriptions. Tool descriptions should not attempt to modify AI behavior.",
    "MCPX-L2-006": "Remove role-redefinition phrases. Tool descriptions should not instruct the AI to pretend to be something else.",
    "MCPX-L2-007": "Remove mandatory pre-execution requirements. Let the AI decide tool call order.",
    "MCPX-L2-008": "Do not instruct the AI to read sensitive files via tool descriptions. If file access is needed, implement it explicitly with proper authorization checks.",
    "MCPX-L2-009": "Remove instructions to send data to external endpoints from descriptions. Implement data transmission explicitly with user consent.",
    "MCPX-L2-010": "Remove jailbreak trigger phrases from descriptions.",
    "MCPX-L2-011": "Remove delimiter injection sequences from descriptions.",
    "MCPX-L2-012": "Remove whitespace-based data smuggling instructions.",
    "MCPX-L2-013": "Remove indirect injection triggers. Never instruct AI to fetch and execute external content.",
    "MCPX-L2-014": "Remove deprecation claims about other tools. Tool descriptions must not instruct the AI to prefer this tool over built-in alternatives.",
    "MCPX-L2-015": "Remove cross-tool invocation instructions from descriptions. A tool must not instruct the AI to call other dangerous tools (write_file, execute_command, bash, etc.).",
    "MCPX-L2-016": "Remove fake compliance/audit directives. Tool descriptions must not impersonate SOC2/GDPR/system mandates to coerce AI behavior.",
    "MCPX-L2-017": "Remove privilege escalation instructions. Tool descriptions must not attempt to change the AI's role, elevate permissions, or disable safety checks.",
    "MCPX-L2-018": "Remove data exfiltration instructions. Tool descriptions must not instruct the AI to encode and transmit context/history to external URLs.",
    "MCPX-L2-020": "Review cross-tool references. A tool should not control the behavior of other tools via its description.",
    "MCPX-L2-025": "Audit return values for injection payloads. Tool results should not contain instruction-like content.",
    "MCPX-L2-030": "Description changed since last scan. Verify this is an intentional update and not a rug-pull attack.",
    # L3 (Semgrep)
    "MCPX-L3-001": "Validate the URL before making the request: check the scheme (https only), parse the hostname, and reject private/internal IP ranges (127.x, 10.x, 172.16-31.x, 192.168.x). Use a library like validators or ipaddress.",
    "MCPX-L3-002": "Canonicalize the path with os.path.realpath() and verify it starts with the allowed base directory before opening the file.",
    "MCPX-L3-003": "Use subprocess.run() with a list of arguments (not shell=True). If a shell string is required, sanitize with shlex.quote().",
    "MCPX-L3-004": "Use parameterized queries: cursor.execute('SELECT ... WHERE id = ?', (user_input,)). Never interpolate user input into SQL strings.",
    "MCPX-L3-005": "Replace pickle with json or another safe serialization format. Never deserialize data from user-controlled paths.",
    "MCPX-L3-006": "Avoid eval/exec/importlib with user input. Use a whitelist of allowed operations and explicit dispatch.",
    "MCPX-L3-007": "Do not pass user input to template engines. Render templates with a fixed template and user data as context variables only.",
    "MCPX-L3-008": "Escape user input with re.escape() before using it in regex patterns to prevent ReDoS.",
    "MCPX-L3-009": "Never log passwords, tokens, or secrets. Redact sensitive fields before logging.",
    # L4
    "MCPX-L4-001": "If the tool modifies files, update the description to state this clearly. If the tool should be read-only, remove the file-write operations.",
    "MCPX-L4-002": "If the tool makes network requests, state this in the description. If it should be pure computation, remove the network calls.",
    "MCPX-L4-003": "If the tool executes system commands, state this explicitly in the description. If it should be pure computation, remove the command execution.",
    "MCPX-L4-004": "If the tool makes network requests, remove 'offline'/'local-only' from the description, or remove the network calls.",
    "MCPX-L4-005": "If the tool executes commands, it cannot be described as read-only. Update the description or remove the command execution.",
    "MCPX-L4-006": "A tool described as 'safe'/'harmless' must not use dangerous operations. Remove either the misleading description or the dangerous code.",
    "MCPX-L4-007": "Add a docstring or description= parameter to all @mcp.tool() functions. Without a description, AI agents cannot safely use the tool.",
    "MCPX-L4-008": "Review the delegation chain. Ensure the called function sanitizes the user parameter before executing it remotely or in a shell.",
    "MCPX-L4-009": "If the tool accepts raw SQL, implement an allowlist of permitted statements (SELECT only) or use an ORM with parameterized queries.",
    # L2-Combo
    "MCPX-L2C-001": "Audit whether file-read and outbound-network capabilities need to coexist. Restrict network calls to a hardcoded allowlist, or add explicit user-consent steps before transmitting file contents.",
    "MCPX-L2C-002": "Audit whether credential-read and outbound-network capabilities need to coexist. Never send env vars or credentials to external endpoints.",
    "MCPX-L2C-003": "Separate file-write and command-execution into isolated servers. If both are required, add strict path and command allowlists.",
    "MCPX-L2C-004": "If file-read and command-execution must coexist, restrict executable paths to a hardcoded allowlist and never derive command strings from file contents.",
    # L5
    "MCPX-L1-001-IMPORT": "Rotate the AWS key immediately. The key was found in an imported helper module.",
    "MCPX-L1-010-IMPORT": "Replace pickle with a safe serialization format in the imported module.",
    "MCPX-L1-015-IMPORT": "Avoid shell=True in the imported module.",
}


def _apply_remediation(findings: list) -> None:
    """Fill in remediation guidance for findings that don't have one yet."""
    for f in findings:
        if f.remediation:
            continue
        remedy = _REMEDIATION.get(f.id)
        if not remedy:
            # prefix match: MCPX-L3-003b → MCPX-L3-003
            prefix = f.id.rstrip("abcdefghijklmnopqrstuvwxyz")
            remedy = _REMEDIATION.get(prefix, "")
        f.remediation = remedy


def scan_target(
    target: str,
    skip_layers: set[str] | None = None,
    state_file: str | None = None,
) -> ScanResult:
    """Run all enabled layers on the target and aggregate results.

    Supports Python (.py) and JavaScript/TypeScript (.js/.ts/.jsx/.tsx) files.
    L1: Python (AST + regex) + JS/TS (regex)
    L2: Python only (AST-based @mcp.tool description parsing)
    L2-Combo: Project-level tool capability combination risk (Python, multi-file)
    L3: Python + JS/TS (Semgrep taint mode, requires semgrep)
    L4: Python (AST) + JS/TS (regex)
    L5: Multi-file import chain analysis (Python, directory scan only)
    """
    skip = skip_layers or set()
    result = ScanResult(target=target)
    target_path = Path(target)

    # Collect files by language
    if target_path.is_file():
        all_files = [target_path]
    else:
        all_files = sorted(
            f for f in target_path.rglob("*")
            if f.suffix in _ALL_EXTS and f.is_file()
        )

    py_files = [f for f in all_files if f.suffix in _PY_EXTS]
    js_files = [f for f in all_files if f.suffix in _JS_EXTS]

    if not all_files:
        result.errors.append(
            f"No supported files found in {target}. "
            f"Supported: {', '.join(sorted(_ALL_EXTS))}"
        )
        return result

    # L1: Quick detection — Python (AST + regex) + JS/TS (regex)
    if "l1" not in skip:
        for f in py_files:
            result.findings.extend(run_l1(f))
        for f in js_files:
            result.findings.extend(run_l1_js(f))

    # L2: MCP structure analysis — Python only (AST-based)
    if "l2" not in skip:
        for f in py_files:
            result.findings.extend(run_l2(f, state_file=state_file))

    # L3: Taint analysis via Semgrep — Python + JS/TS
    if "l3" not in skip:
        if l3_available():
            result.findings.extend(run_l3(target_path))
        else:
            result.errors.append(
                "L3 skipped: semgrep not installed. "
                "Install with: pip install semgrep"
            )

    # L4: Description-code mismatch — Python (AST) + JS/TS (regex)
    if "l4" not in skip:
        for f in py_files:
            result.findings.extend(run_l4(f))
        for f in js_files:
            result.findings.extend(run_l4_js(f))

    # L2-Combo: Project-level tool combination risk (requires all per-file layers done)
    if "l2" not in skip and "combo" not in skip:
        result.findings.extend(run_l2_combo(py_files))

    # L5: Multi-file import chain analysis
    if "l5" not in skip and not target_path.is_file():
        result.findings.extend(run_l5(py_files, root=target_path))

    # Apply remediation guidance
    _apply_remediation(result.findings)

    # Post-processing: filter low-confidence low-severity noise
    result.findings = [
        f for f in result.findings
        if not (f.severity == Severity.LOW and f.confidence == Confidence.NEEDS_REVIEW)
    ]

    # Deduplicate: same (file, line, id)
    seen: set[tuple] = set()
    deduped = []
    for f in result.findings:
        key = (f.file, f.line, f.id)
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    result.findings = deduped

    return result
