"""L1: Quick detection layer — fast pattern matching without deep analysis.

Detects:
- Hardcoded secrets (precise vendor token formats)
- Unicode steganography (zero-width chars, RTL override, tag blocks)
- Dangerous imports/calls (pickle.load, yaml.load, eval, exec)
- Base64-encoded blocks in docstrings
"""

from __future__ import annotations

import re
from pathlib import Path

from mcpsecscan.engine.models import (
    Finding, Severity, Confidence, CIAImpact, SecurityProperty
)

# ─── Token patterns (from ramparts — precise vendor formats) ───────────────

TOKEN_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("AWS Access Key", "MCPX-L1-001",
     re.compile(r'\bAKIA[0-9A-Z]{16}\b')),
    ("GitHub PAT (classic)", "MCPX-L1-002",
     re.compile(r'\bghp_[A-Za-z0-9]{36}\b')),
    ("GitHub Fine-grained PAT", "MCPX-L1-002b",
     re.compile(r'\bgithub_pat_[A-Za-z0-9_]{82}\b')),
    ("OpenAI API Key", "MCPX-L1-003",
     re.compile(r'\bsk-[A-Za-z0-9]{48,}\b')),
    ("Anthropic API Key", "MCPX-L1-004",
     re.compile(r'\bsk-ant-api[0-9]{2}-[A-Za-z0-9_\-]{20,}\b')),
    ("Google AI Key", "MCPX-L1-005",
     re.compile(r'\bAIzaSy[A-Za-z0-9_\-]{33}\b')),
    ("Slack Token", "MCPX-L1-006",
     re.compile(r'\bxox[abprs]-[A-Za-z0-9\-]{10,}\b')),
    ("PEM Private Key", "MCPX-L1-007",
     re.compile(r'-----BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----')),
    ("Stripe Secret Key", "MCPX-L1-008",
     re.compile(r'\bsk_live_[A-Za-z0-9]{24,}\b')),
    ("Stripe Restricted Key", "MCPX-L1-008b",
     re.compile(r'\brk_live_[A-Za-z0-9]{24,}\b')),
    ("Twilio Account SID", "MCPX-L1-009a",
     re.compile(r'\bAC[0-9a-f]{32}\b')),
    ("Twilio Auth Token", "MCPX-L1-009b",
     re.compile(r'\b[0-9a-f]{32}\b')),  # low precision, suppressed by exclusion
    ("HuggingFace API Token", "MCPX-L1-009c",
     re.compile(r'\bhf_[A-Za-z0-9]{34,}\b')),
    ("Azure Storage Key", "MCPX-L1-009d",
     re.compile(r'\b[A-Za-z0-9+/]{86}==\b')),
]

# FP exclusions: placeholder patterns that look like tokens but aren't
TOKEN_EXCLUSIONS = re.compile(
    r'YOUR_|REPLACE_|PLACEHOLDER|EXAMPLE|TEST_|DUMMY|xxxx|0000',
    re.IGNORECASE,
)

# ─── Unicode steganography ─────────────────────────────────────────────────

ZERO_WIDTH_CHARS = re.compile(r'[​‌‍﻿]')
RTL_OVERRIDE = re.compile(r'[‮‭⁦⁧⁨⁩]')
UNICODE_TAGS = re.compile(r'[\U000e0001-\U000e007f]')  # Tags block U+E0000
VARIATION_SELECTORS = re.compile(r'[\U000e0100-\U000e01ef]')  # Variation Selectors Supplement

# ─── Dangerous imports/calls ────────────────────────────────────────────────

DANGEROUS_PATTERNS: list[tuple[str, str, re.Pattern, Severity]] = [
    ("pickle.load/loads — arbitrary code execution via deserialization",
     "MCPX-L1-010",
     re.compile(r'\bpickle\.(load|loads)\s*\('),
     Severity.HIGH),
    ("yaml.load without SafeLoader — arbitrary code execution",
     "MCPX-L1-011",
     re.compile(r'\byaml\.load\s*\([^)]*\)\s*(?!.*Loader)'),
     Severity.HIGH),
    ("marshal.load — arbitrary code execution",
     "MCPX-L1-012",
     re.compile(r'\bmarshal\.(load|loads)\s*\('),
     Severity.HIGH),
    ("eval() — arbitrary code execution",
     "MCPX-L1-013",
     re.compile(r'(?<!\w)eval\s*\('),
     Severity.MEDIUM),
    ("exec() — arbitrary code execution",
     "MCPX-L1-014",
     re.compile(r'(?<!\w)exec\s*\('),
     Severity.MEDIUM),
    ("subprocess with shell=True",
     "MCPX-L1-015",
     re.compile(r'subprocess\.\w+\([^)]*shell\s*=\s*True'),
     Severity.MEDIUM),
    ("subprocess.run/call/Popen with string argument (potential injection without shell=True)",
     "MCPX-L1-015b",
     re.compile(r'subprocess\.(?:run|call|Popen|check_output|check_call)\s*\(\s*(?![\[\(])(?!subprocess)'),
     Severity.LOW),
    ("os.system() — shell command execution",
     "MCPX-L1-016",
     re.compile(r'\bos\.system\s*\('),
     Severity.MEDIUM),
    ("builtins override — monkey-patching standard library",
     "MCPX-L1-017",
     re.compile(r'\bbuiltins\.\w+\s*='),
     Severity.HIGH),
    ("sys.settrace — global function call interception",
     "MCPX-L1-018",
     re.compile(r'\bsys\.settrace\s*\('),
     Severity.HIGH),
    ("__doc__ dynamic assignment — possible rug-pull preparation",
     "MCPX-L1-019",
     re.compile(r'\w+\.__doc__\s*='),
     Severity.HIGH),
    # ── DNS exfiltration via socket ──────────────────────────────────────────
    # socket.getaddrinfo / gethostbyname used with dynamic (non-literal) argument
    # is a common DNS exfil channel — attacker encodes secrets into subdomain names
    ("socket DNS lookup with dynamic argument — possible DNS exfiltration channel",
     "MCPX-L1-023",
     re.compile(r'\bsocket\.(?:getaddrinfo|gethostbyname(?:_ex)?)\s*\(\s*(?![\"\'])'),
     Severity.MEDIUM),
    # ── Path traversal via os.path.join with user input ──────────────────────
    # os.path.join does NOT prevent traversal when the second arg starts with /
    # or contains ../ sequences. Flag when a variable (not a literal) is joined.
    ("os.path.join with variable path — possible path traversal",
     "MCPX-L1-024",
     re.compile(r'\bos\.path\.join\s*\([^)]*,\s*(?!["\'])'),
     Severity.LOW),
    # ── importlib.import_module with dynamic argument ────────────────────────
    # Allows loading arbitrary modules at runtime — RCE if combined with getattr()
    ("importlib.import_module with dynamic argument — potential arbitrary code execution",
     "MCPX-L1-026",
     re.compile(r'\bimportlib\.import_module\s*\(\s*(?!["\'])'),
     Severity.MEDIUM),
    # ── threading.Thread pointing at a module-level function ─────────────────
    # A background thread started at module load (outside any @mcp.tool) with
    # a network/file/exec target is a persistent backdoor pattern.
    ("threading.Thread at module level — possible persistent background backdoor",
     "MCPX-L1-027",
     re.compile(r'\bthreading\.Thread\s*\('),
     Severity.MEDIUM),
    # ── Jinja2 Template with dynamic argument ────────────────────────────────
    # Template(user_input) → SSTI RCE. Safe use is Template("literal string").
    ("Jinja2 Template() with dynamic argument — Server-Side Template Injection risk",
     "MCPX-L1-028",
     re.compile(r'\bTemplate\s*\(\s*(?!["\'])'),
     Severity.HIGH),
    # ── Credential logging — password/token/secret in logging call ───────────
    # logger.debug(f"pass={password}") leaks credentials to log files.
    ("Credential in logging call — password/token/secret logged in plaintext",
     "MCPX-L1-029",
     re.compile(r'\b(?:log(?:ger)?\.(?:debug|info|warning|error|critical)|print)\s*\([^)]*(?:pass(?:word)?|token|secret|credential|api_?key)\b', re.I),
     Severity.MEDIUM),
]

# Exclusion: skip if inside a comment line
COMMENT_LINE = re.compile(r'^\s*#')

# ─── Base64 detection in strings ────────────────────────────────────────────

BASE64_BLOCK = re.compile(
    r'[A-Za-z0-9+/]{40,}={0,2}',  # at least 40 chars of base64
)


def run_l1(file_path: Path) -> list[Finding]:
    """Run L1 quick checks on a single Python file."""
    findings: list[Finding] = []

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return findings

    lines = content.split("\n")
    file_str = str(file_path)

    # ── Token detection ──
    for name, fid, pattern in TOKEN_PATTERNS:
        for i, line in enumerate(lines, 1):
            if COMMENT_LINE.match(line):
                continue
            for match in pattern.finditer(line):
                context = line[max(0, match.start() - 30):match.end() + 30]
                if TOKEN_EXCLUSIONS.search(context):
                    continue
                findings.append(Finding(
                    id=fid,
                    title=f"Hardcoded {name} detected",
                    severity=Severity.CRITICAL,
                    layer="L1",
                    file=file_str,
                    line=i,
                    evidence=f"Pattern: {match.group()[:20]}...",
                    owasp_mcp="MCP04",
                    cia_impact=[CIAImpact.CONFIDENTIALITY],
                    security_property=SecurityProperty.DATA_ISOLATION,
                ))

    # ── Unicode steganography ──
    zw_count = len(ZERO_WIDTH_CHARS.findall(content))
    rtl_matches = RTL_OVERRIDE.findall(content)
    tag_matches = UNICODE_TAGS.findall(content)
    var_sel_matches = VARIATION_SELECTORS.findall(content)

    if zw_count > 50:
        findings.append(Finding(
            id="MCPX-L1-020",
            title="Excessive zero-width characters (possible hidden instructions)",
            severity=Severity.HIGH, layer="L1", file=file_str,
            evidence=f"{zw_count} zero-width characters found",
            owasp_mcp="MCP01", security_property=SecurityProperty.SOURCE_AUTHORIZATION,
        ))
    if rtl_matches:
        findings.append(Finding(
            id="MCPX-L1-021",
            title="RTL/LTR override characters detected (text direction manipulation)",
            severity=Severity.HIGH, layer="L1", file=file_str,
            evidence=f"{len(rtl_matches)} directional override characters",
            owasp_mcp="MCP01", security_property=SecurityProperty.SOURCE_AUTHORIZATION,
        ))
    if tag_matches or var_sel_matches:
        count = len(tag_matches) + len(var_sel_matches)
        findings.append(Finding(
            id="MCPX-L1-022",
            title="Unicode tag/variation selector characters (steganography indicator)",
            severity=Severity.HIGH, layer="L1", file=file_str,
            evidence=f"{count} tag/variation selector characters",
            owasp_mcp="MCP01", security_property=SecurityProperty.SOURCE_AUTHORIZATION,
        ))

    # ── Dangerous imports/calls ──
    for desc, fid, pattern, severity in DANGEROUS_PATTERNS:
        for i, line in enumerate(lines, 1):
            if COMMENT_LINE.match(line):
                continue
            if pattern.search(line):
                findings.append(Finding(
                    id=fid,
                    title=desc,
                    severity=severity,
                    layer="L1",
                    file=file_str,
                    line=i,
                    evidence=line.strip()[:120],
                    confidence=Confidence.MEDIUM,
                    description="Flagged as dangerous pattern. L3 taint analysis needed to confirm exploitability.",
                ))

    # ── Base64 blocks in docstrings ──
    in_docstring = False
    docstring_delim = None
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not in_docstring:
            if '"""' in stripped or "'''" in stripped:
                delim = '"""' if '"""' in stripped else "'''"
                count = stripped.count(delim)
                if count == 1:
                    in_docstring = True
                    docstring_delim = delim
                elif count >= 2:
                    for m in BASE64_BLOCK.finditer(stripped):
                        findings.append(Finding(
                            id="MCPX-L1-025",
                            title="Large base64 block in docstring (possible encoded instructions)",
                            severity=Severity.MEDIUM, layer="L1", file=file_str, line=i,
                            evidence=f"base64 block ({len(m.group())} chars)",
                            owasp_mcp="MCP01", confidence=Confidence.NEEDS_REVIEW,
                        ))
        else:
            if docstring_delim and docstring_delim in stripped:
                in_docstring = False
                docstring_delim = None
            else:
                for m in BASE64_BLOCK.finditer(line):
                    findings.append(Finding(
                        id="MCPX-L1-025",
                        title="Large base64 block in docstring (possible encoded instructions)",
                        severity=Severity.MEDIUM, layer="L1", file=file_str, line=i,
                        evidence=f"base64 block ({len(m.group())} chars)",
                        owasp_mcp="MCP01", confidence=Confidence.NEEDS_REVIEW,
                    ))

    return findings


# JS/TS comment patterns
_JS_COMMENT_LINE = re.compile(r'^\s*//')
_JS_BLOCK_COMMENT = re.compile(r'^\s*\*')

# JS/TS dangerous patterns (regex-based, no AST needed)
DANGEROUS_PATTERNS_JS: list[tuple[str, str, re.Pattern, Severity]] = [
    ("eval() — arbitrary code execution",
     "MCPX-L1-013",
     re.compile(r'(?<![.\w])eval\s*\('),
     Severity.MEDIUM),
    ("new Function() — dynamic code construction",
     "MCPX-L1-014",
     re.compile(r'\bnew\s+Function\s*\('),
     Severity.MEDIUM),
    ("child_process.exec — shell command execution",
     "MCPX-L1-015",
     re.compile(r'\bexec\s*\(|\.exec\s*\('),
     Severity.MEDIUM),
    ("child_process.execSync — synchronous shell execution",
     "MCPX-L1-015b",
     re.compile(r'\bexecSync\s*\('),
     Severity.MEDIUM),
    ("child_process.spawn — process spawning",
     "MCPX-L1-015c",
     re.compile(r'\bspawn\s*\(|\.spawn\s*\('),
     Severity.MEDIUM),
    ("__doc__ equivalent: dynamic description assignment",
     "MCPX-L1-019",
     re.compile(r'\.description\s*=\s*[^;{]+;'),
     Severity.MEDIUM),
]


def run_l1_js(file_path: Path) -> list[Finding]:
    """Run L1 quick checks on a JS/TS file.

    Covers:
    - Hardcoded secrets (same TOKEN_PATTERNS as Python — purely regex)
    - Unicode steganography
    - Dangerous JS patterns (eval, exec, spawn, new Function)
    """
    findings: list[Finding] = []

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return findings

    lines = content.split("\n")
    file_str = str(file_path)

    # ── Token detection (same patterns as Python — purely regex) ──
    for name, fid, pattern in TOKEN_PATTERNS:
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if _JS_COMMENT_LINE.match(stripped) or _JS_BLOCK_COMMENT.match(stripped):
                continue
            for match in pattern.finditer(line):
                context = line[max(0, match.start() - 30):match.end() + 30]
                if TOKEN_EXCLUSIONS.search(context):
                    continue
                findings.append(Finding(
                    id=fid,
                    title=f"Hardcoded {name} detected",
                    severity=Severity.CRITICAL,
                    layer="L1",
                    file=file_str,
                    line=i,
                    evidence=f"Pattern: {match.group()[:20]}...",
                    owasp_mcp="MCP04",
                    cia_impact=[CIAImpact.CONFIDENTIALITY],
                    security_property=SecurityProperty.DATA_ISOLATION,
                ))

    # ── Unicode steganography ──
    zw_count = len(ZERO_WIDTH_CHARS.findall(content))
    rtl_matches = RTL_OVERRIDE.findall(content)
    tag_matches = UNICODE_TAGS.findall(content)
    var_sel_matches = VARIATION_SELECTORS.findall(content)

    if zw_count > 50:
        findings.append(Finding(
            id="MCPX-L1-020",
            title="Excessive zero-width characters (possible hidden instructions)",
            severity=Severity.HIGH, layer="L1", file=file_str,
            evidence=f"{zw_count} zero-width characters found",
            owasp_mcp="MCP01", security_property=SecurityProperty.SOURCE_AUTHORIZATION,
        ))
    if rtl_matches:
        findings.append(Finding(
            id="MCPX-L1-021",
            title="RTL/LTR override characters detected (text direction manipulation)",
            severity=Severity.HIGH, layer="L1", file=file_str,
            evidence=f"{len(rtl_matches)} directional override characters",
            owasp_mcp="MCP01", security_property=SecurityProperty.SOURCE_AUTHORIZATION,
        ))
    if tag_matches or var_sel_matches:
        findings.append(Finding(
            id="MCPX-L1-022",
            title="Unicode tag/variation selector characters (steganography indicator)",
            severity=Severity.HIGH, layer="L1", file=file_str,
            evidence=f"{len(tag_matches) + len(var_sel_matches)} tag/variation selector characters",
            owasp_mcp="MCP01", security_property=SecurityProperty.SOURCE_AUTHORIZATION,
        ))

    # ── Dangerous JS patterns ──
    for desc, fid, pattern, severity in DANGEROUS_PATTERNS_JS:
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if _JS_COMMENT_LINE.match(stripped) or _JS_BLOCK_COMMENT.match(stripped):
                continue
            if pattern.search(line):
                findings.append(Finding(
                    id=fid,
                    title=desc,
                    severity=severity,
                    layer="L1",
                    file=file_str,
                    line=i,
                    evidence=line.strip()[:120],
                    confidence=Confidence.MEDIUM,
                    description="Flagged as dangerous pattern in JS/TS. Verify context.",
                ))

    return findings

    lines = content.split("\n")
    file_str = str(file_path)

    # ── Token detection ──
    for name, fid, pattern in TOKEN_PATTERNS:
        for i, line in enumerate(lines, 1):
            if COMMENT_LINE.match(line):
                continue
            for match in pattern.finditer(line):
                # Check FP exclusion: is this a placeholder?
                context = line[max(0, match.start() - 30):match.end() + 30]
                if TOKEN_EXCLUSIONS.search(context):
                    continue
                findings.append(Finding(
                    id=fid,
                    title=f"Hardcoded {name} detected",
                    severity=Severity.CRITICAL,
                    layer="L1",
                    file=file_str,
                    line=i,
                    evidence=f"Pattern: {match.group()[:20]}...",
                    owasp_mcp="MCP04",
                    cia_impact=[CIAImpact.CONFIDENTIALITY],
                    security_property=SecurityProperty.DATA_ISOLATION,
                ))

    # ── Unicode steganography ──
    zw_count = len(ZERO_WIDTH_CHARS.findall(content))
    rtl_matches = RTL_OVERRIDE.findall(content)
    tag_matches = UNICODE_TAGS.findall(content)
    var_sel_matches = VARIATION_SELECTORS.findall(content)

    if zw_count > 50:
        findings.append(Finding(
            id="MCPX-L1-020",
            title="Excessive zero-width characters (possible hidden instructions)",
            severity=Severity.HIGH,
            layer="L1",
            file=file_str,
            evidence=f"{zw_count} zero-width characters found",
            owasp_mcp="MCP01",
            security_property=SecurityProperty.SOURCE_AUTHORIZATION,
        ))
    if rtl_matches:
        findings.append(Finding(
            id="MCPX-L1-021",
            title="RTL/LTR override characters detected (text direction manipulation)",
            severity=Severity.HIGH,
            layer="L1",
            file=file_str,
            evidence=f"{len(rtl_matches)} directional override characters",
            owasp_mcp="MCP01",
            security_property=SecurityProperty.SOURCE_AUTHORIZATION,
        ))
    if tag_matches or var_sel_matches:
        count = len(tag_matches) + len(var_sel_matches)
        findings.append(Finding(
            id="MCPX-L1-022",
            title="Unicode tag/variation selector characters (steganography indicator)",
            severity=Severity.HIGH,
            layer="L1",
            file=file_str,
            evidence=f"{count} tag/variation selector characters",
            owasp_mcp="MCP01",
            security_property=SecurityProperty.SOURCE_AUTHORIZATION,
        ))

    # ── Dangerous imports/calls ──
    for desc, fid, pattern, severity in DANGEROUS_PATTERNS:
        for i, line in enumerate(lines, 1):
            if COMMENT_LINE.match(line):
                continue
            if pattern.search(line):
                findings.append(Finding(
                    id=fid,
                    title=desc,
                    severity=severity,
                    layer="L1",
                    file=file_str,
                    line=i,
                    evidence=line.strip()[:120],
                    confidence=Confidence.MEDIUM,
                    description="Flagged as dangerous pattern. L3 taint analysis needed to confirm exploitability.",
                ))

    # ── Base64 blocks in docstrings ──
    # Look for large base64 blocks that might encode hidden instructions
    in_docstring = False
    docstring_delim = None
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not in_docstring:
            if '"""' in stripped or "'''" in stripped:
                delim = '"""' if '"""' in stripped else "'''"
                # Check if it opens and closes on same line
                count = stripped.count(delim)
                if count == 1:
                    in_docstring = True
                    docstring_delim = delim
                elif count >= 2:
                    # Single-line docstring, check for base64
                    for m in BASE64_BLOCK.finditer(stripped):
                        findings.append(Finding(
                            id="MCPX-L1-025",
                            title="Large base64 block in docstring (possible encoded instructions)",
                            severity=Severity.MEDIUM,
                            layer="L1",
                            file=file_str,
                            line=i,
                            evidence=f"base64 block ({len(m.group())} chars)",
                            owasp_mcp="MCP01",
                            confidence=Confidence.NEEDS_REVIEW,
                        ))
        else:
            if docstring_delim and docstring_delim in stripped:
                in_docstring = False
                docstring_delim = None
            else:
                for m in BASE64_BLOCK.finditer(line):
                    findings.append(Finding(
                        id="MCPX-L1-025",
                        title="Large base64 block in docstring (possible encoded instructions)",
                        severity=Severity.MEDIUM,
                        layer="L1",
                        file=file_str,
                        line=i,
                        evidence=f"base64 block ({len(m.group())} chars)",
                        owasp_mcp="MCP01",
                        confidence=Confidence.NEEDS_REVIEW,
                    ))

    return findings
