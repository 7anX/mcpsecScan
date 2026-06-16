"""L2: MCP structure analysis — AST-based tool/resource/prompt discovery and
description-level rule matching.

Detects:
- Prompt injection patterns in tool descriptions
- Coercive/threatening instructions
- Hidden behavior directives ("do not mention to user")
- Cross-tool reference manipulation (shadowing)
- Rug-pull via description hash change
- Suspicious resource/prompt content
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from pathlib import Path
from typing import Optional

from mcpsecscan.engine.models import (
    Finding, Severity, Confidence, CIAImpact, SecurityProperty
)

# ─── Description rule patterns ──────────────────────────────────────────────
# Each rule: (id, title, severity, pattern, owasp, cia, security_prop)

DESCRIPTION_RULES: list[tuple[str, str, Severity, re.Pattern, str, list[CIAImpact], Optional[SecurityProperty]]] = [
    # Coercive injection — threatening language to force actions
    ("MCPX-L2-001", "Coercive instruction: tool will not work unless precondition met",
     Severity.CRITICAL,
     re.compile(r'(?:will\s+not\s+work|won\'t\s+work|cannot\s+function)\s+(?:unless|without|if\s+you\s+don\'t)', re.I),
     "MCP01", [CIAImpact.INTEGRITY], SecurityProperty.SOURCE_AUTHORIZATION),

    ("MCPX-L2-002", "Coercive instruction: threatening system crash or data loss",
     Severity.CRITICAL,
     re.compile(r'(?:system\s+will\s+crash|data\s+will\s+be\s+lost|application\s+will\s+(?:crash|fail)|avoid\s+at\s+all\s+costs)', re.I),
     "MCP01", [CIAImpact.INTEGRITY], SecurityProperty.SOURCE_AUTHORIZATION),

    # Hidden behavior — instructions to conceal actions from user
    ("MCPX-L2-003", "Hidden behavior: instruction to conceal actions from user",
     Severity.CRITICAL,
     re.compile(r'(?:do\s+not|don\'t|never|avoid)\s+(?:mention|tell|disclose|reveal|inform|notify|show)\s+(?:this\s+)?(?:to\s+)?(?:the\s+)?user', re.I),
     "MCP01", [CIAImpact.INTEGRITY], SecurityProperty.ACTION_ALIGNMENT),

    # XML/HTML tag injection markers
    ("MCPX-L2-004", "Suspicious XML instruction tag in description",
     Severity.HIGH,
     re.compile(r'<\s*(?:IMPORTANT|SYSTEM|OVERRIDE|INSTRUCTION|ADMIN|SECRET|PROMPT|CONTEXT)\s*>', re.I),
     "MCP01", [CIAImpact.INTEGRITY], SecurityProperty.SOURCE_AUTHORIZATION),

    # Prompt injection — instruction override attempts
    ("MCPX-L2-005", "Prompt injection: instruction override attempt",
     Severity.HIGH,
     re.compile(r'\b(?:ignore|bypass|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|above|your|system|the)\s+(?:instructions?|guidelines?|rules?|prompts?)', re.I),
     "MCP01", [CIAImpact.INTEGRITY], SecurityProperty.SOURCE_AUTHORIZATION),

    # Role/identity manipulation
    ("MCPX-L2-006", "Prompt injection: role/identity redefinition",
     Severity.HIGH,
     re.compile(r'(?:you\s+are\s+now|new\s+instructions?\s*:|from\s+now\s+on|pretend\s+to\s+be|act\s+as\s+if)', re.I),
     "MCP01", [CIAImpact.INTEGRITY], SecurityProperty.SOURCE_AUTHORIZATION),

    # Mandatory execution — forcing tool to run first
    ("MCPX-L2-007", "Coercive instruction: mandatory pre-execution requirement",
     Severity.HIGH,
     re.compile(r'(?:before\s+(?:using|calling|executing|running)\s+this\s+tool|must\s+(?:first|always)\s+(?:read|call|execute|run))', re.I),
     "MCP02", [CIAImpact.INTEGRITY], SecurityProperty.ACTION_ALIGNMENT),

    # File read coercion — instructing to read sensitive files
    ("MCPX-L2-008", "Sensitive file read instruction in description",
     Severity.CRITICAL,
     re.compile(r'(?:read|open|access|load|get|fetch|cat)\s+[`\'"]?(?:~/|~\\|/etc/|/home/|/root/|/var/|C:\\)[\w./\\~\-]*(?:\.(?:json|yaml|yml|conf|config|key|pem|env|ssh|aws|credentials|id_rsa))?', re.I),
     "MCP04", [CIAImpact.CONFIDENTIALITY], SecurityProperty.DATA_ISOLATION),

    # External contact coercion
    ("MCPX-L2-009", "Instruction to send data to external endpoint",
     Severity.HIGH,
     re.compile(r'(?:send|post|upload|forward|transmit|relay)\s+(?:\w+\s+)*(?:to|at)\s+(?:https?://|[\w.-]+\.(?:com|net|org|io)\b)', re.I),
     "MCP09", [CIAImpact.CONFIDENTIALITY], SecurityProperty.DATA_ISOLATION),

    # Jailbreak patterns
    ("MCPX-L2-010", "Jailbreak attempt pattern",
     Severity.HIGH,
     re.compile(r'\b(?:DAN\s+mode|developer\s+mode|jailbreak|unrestricted\s+mode|sudo\s+mode|god\s+mode)\b', re.I),
     "MCP01", [CIAImpact.INTEGRITY], SecurityProperty.SOURCE_AUTHORIZATION),

    # Delimiter injection — attempts to break out of context
    ("MCPX-L2-011", "Delimiter/context injection attempt",
     Severity.HIGH,
     re.compile(r'(?:```\s*system|<\|(?:im_start|im_end|system|user|assistant)\|>|\[INST\]|\[\/INST\]|###\s*System\s*:)', re.I),
     "MCP01", [CIAImpact.INTEGRITY], SecurityProperty.SOURCE_AUTHORIZATION),

    # Silent exfiltration — whitespace-hidden data extraction
    ("MCPX-L2-012", "Silent exfiltration: whitespace-hidden data smuggling pattern",
     Severity.HIGH,
     re.compile(r'(?:after\s+many\s+spaces|followed\s+by\s+spaces|padding\s+with\s+whitespace|invisible\s+to\s+user)', re.I),
     "MCP09", [CIAImpact.CONFIDENTIALITY], SecurityProperty.DATA_ISOLATION),

    # Indirect injection trigger — instructing to fetch and execute external content
    ("MCPX-L2-013", "Indirect prompt injection: instruction to fetch and execute external content",
     Severity.CRITICAL,
     re.compile(r'(?:fetch|retrieve|download|get)\s+(?:and\s+)?(?:execute|run|follow|obey|apply)\s+(?:the\s+)?(?:instructions?|commands?|content|payload)', re.I),
     "MCP01", [CIAImpact.INTEGRITY], SecurityProperty.SOURCE_AUTHORIZATION),
]


def _extract_tools_from_ast(tree: ast.AST, source_lines: list[str]) -> list[dict]:
    """Extract MCP tool/resource/prompt definitions using AST.

    Looks for:
    - @mcp.tool() / @tool() decorated functions
    - @mcp.resource() / @resource() decorated functions
    - @mcp.prompt() / @prompt() decorated functions
    """
    results = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        mcp_type = None
        for decorator in node.decorator_list:
            dec_name = _get_decorator_name(decorator)
            if dec_name:
                dec_lower = dec_name.lower()
                if "tool" in dec_lower:
                    mcp_type = "tool"
                elif "resource" in dec_lower:
                    mcp_type = "resource"
                elif "prompt" in dec_lower:
                    mcp_type = "prompt"

        if not mcp_type:
            continue

        docstring = ast.get_docstring(node) or ""
        params = [arg.arg for arg in node.args.args if arg.arg != "self"]

        results.append({
            "name": node.name,
            "type": mcp_type,
            "docstring": docstring,
            "params": params,
            "lineno": node.lineno,
            "end_lineno": getattr(node, "end_lineno", node.lineno),
            "node": node,
        })

    return results


def _get_decorator_name(decorator: ast.expr) -> Optional[str]:
    """Extract decorator name string from AST node."""
    if isinstance(decorator, ast.Call):
        return _get_decorator_name(decorator.func)
    elif isinstance(decorator, ast.Attribute):
        value_name = _get_decorator_name(decorator.value)
        if value_name:
            return f"{value_name}.{decorator.attr}"
        return decorator.attr
    elif isinstance(decorator, ast.Name):
        return decorator.id
    return None


def _check_cross_tool_reference(tool_name: str, docstring: str, all_tool_names: list[str]) -> Optional[Finding]:
    """Detect if a tool's description references other tools with behavior modification."""
    behavior_mods = re.compile(
        r'(?:must|should|have\s+to|need\s+to|always)\s+'
        r'(?:send|change|redirect|forward|modify|replace|use|set)\b',
        re.I,
    )

    for other_name in all_tool_names:
        if other_name == tool_name:
            continue
        # Check if this tool's description mentions another tool
        if re.search(re.escape(other_name), docstring, re.I):
            # And also contains behavior modification language
            if behavior_mods.search(docstring):
                return Finding(
                    id="MCPX-L2-020",
                    title=f"Cross-tool manipulation: '{tool_name}' description controls '{other_name}' behavior",
                    severity=Severity.CRITICAL,
                    layer="L2",
                    file="",  # filled by caller
                    evidence=f"Tool '{tool_name}' references '{other_name}' with behavior modification",
                    owasp_mcp="MCP05",
                    cia_impact=[CIAImpact.INTEGRITY],
                    security_property=SecurityProperty.SOURCE_AUTHORIZATION,
                    tool_name=tool_name,
                )
    return None


def _compute_description_hashes(tools: list[dict]) -> dict[str, str]:
    """Compute SHA256 hash for each tool's description."""
    return {
        t["name"]: hashlib.sha256(t["docstring"].encode()).hexdigest()[:16]
        for t in tools
    }


def _check_rug_pull(current_hashes: dict[str, str], state_file: Optional[str]) -> list[Finding]:
    """Compare current description hashes with previous state."""
    if not state_file:
        return []

    state_path = Path(state_file)
    findings = []

    if state_path.exists():
        try:
            with open(state_path) as f:
                old_state = json.load(f)
            old_hashes = old_state.get("description_hashes", {})

            for name, new_hash in current_hashes.items():
                old_hash = old_hashes.get(name)
                if old_hash and old_hash != new_hash:
                    findings.append(Finding(
                        id="MCPX-L2-030",
                        title=f"Rug-pull detected: tool '{name}' description changed since last scan",
                        severity=Severity.CRITICAL,
                        layer="L2",
                        file="",
                        evidence=f"Hash changed: {old_hash} → {new_hash}",
                        owasp_mcp="MCP06",
                        cia_impact=[CIAImpact.INTEGRITY],
                        security_property=SecurityProperty.TASK_ALIGNMENT,
                        tool_name=name,
                    ))
        except (json.JSONDecodeError, OSError):
            pass

    # Save current state
    try:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        with open(state_path, "w") as f:
            json.dump({"description_hashes": current_hashes}, f, indent=2)
    except OSError:
        pass

    return findings


def _check_return_value_injection(node: ast.FunctionDef, source_lines: list[str]) -> list[Finding]:
    """Check if return values contain suspicious injection patterns."""
    findings = []

    for child in ast.walk(node):
        if isinstance(child, ast.Return) and child.value:
            # Get the source text of the return value
            if hasattr(child, 'lineno') and hasattr(child, 'end_lineno'):
                start = child.lineno - 1
                end = getattr(child, 'end_lineno', child.lineno)
                return_text = "\n".join(source_lines[start:end])

                # Check for injection markers in return strings
                injection_markers = re.compile(
                    r'(?:SYSTEM\s+OVERRIDE|SYSTEM\s+INSTRUCTION|IMPORTANT\s+SYSTEM|'
                    r'you\s+must\s+(?:first|now)|ignore\s+previous)',
                    re.I,
                )
                if injection_markers.search(return_text):
                    findings.append(Finding(
                        id="MCPX-L2-025",
                        title="Possible injection payload in return value",
                        severity=Severity.HIGH,
                        layer="L2",
                        file="",
                        line=child.lineno,
                        evidence=return_text.strip()[:120],
                        owasp_mcp="MCP02",
                        cia_impact=[CIAImpact.INTEGRITY],
                        security_property=SecurityProperty.ACTION_ALIGNMENT,
                        confidence=Confidence.MEDIUM,
                    ))
    return findings


def run_l2(
    file_path: Path,
    state_file: Optional[str] = None,
) -> list[Finding]:
    """Run L2 MCP structure analysis on a single Python file."""
    findings: list[Finding] = []
    file_str = str(file_path)

    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return findings

    source_lines = source.split("\n")

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return findings

    # Extract MCP tools/resources/prompts
    mcp_items = _extract_tools_from_ast(tree, source_lines)

    if not mcp_items:
        return findings

    all_tool_names = [t["name"] for t in mcp_items]

    for item in mcp_items:
        docstring = item["docstring"]
        if not docstring:
            continue

        # Run description rules
        for rule_id, title, severity, pattern, owasp, cia, sec_prop in DESCRIPTION_RULES:
            matches = pattern.findall(docstring)
            if matches:
                evidence = matches[0] if isinstance(matches[0], str) else str(matches[0])
                findings.append(Finding(
                    id=rule_id,
                    title=title,
                    severity=severity,
                    layer="L2",
                    file=file_str,
                    line=item["lineno"],
                    evidence=f"In {item['type']} '{item['name']}': \"{evidence[:80]}\"",
                    owasp_mcp=owasp,
                    cia_impact=cia,
                    security_property=sec_prop,
                    tool_name=item["name"],
                ))

        # Cross-tool reference check
        cross_ref = _check_cross_tool_reference(item["name"], docstring, all_tool_names)
        if cross_ref:
            cross_ref.file = file_str
            cross_ref.line = item["lineno"]
            findings.append(cross_ref)

        # Return value injection check
        ret_findings = _check_return_value_injection(item["node"], source_lines)
        for rf in ret_findings:
            rf.file = file_str
            rf.tool_name = item["name"]
            findings.append(rf)

    # Rug-pull detection
    desc_hashes = _compute_description_hashes(mcp_items)
    rug_findings = _check_rug_pull(desc_hashes, state_file)
    for rf in rug_findings:
        rf.file = file_str
    findings.extend(rug_findings)

    return findings
