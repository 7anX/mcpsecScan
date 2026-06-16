"""Main scanner orchestrator — runs L1 through L4 in sequence."""

from __future__ import annotations

from pathlib import Path

from mcpsecscan.engine.models import ScanResult, Severity, Confidence
from mcpsecscan.engine.l1_quick import run_l1
from mcpsecscan.engine.l2_structure import run_l2
from mcpsecscan.engine.l3_taint import run_l3, is_available as l3_available
from mcpsecscan.engine.l4_mismatch import run_l4

# Supported file extensions per layer
_PY_EXTS = {".py"}
_JS_EXTS = {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}
_ALL_EXTS = _PY_EXTS | _JS_EXTS


def scan_target(
    target: str,
    skip_layers: set[str] | None = None,
    state_file: str | None = None,
) -> ScanResult:
    """Run all enabled layers on the target and aggregate results.

    Supports Python (.py) and JavaScript/TypeScript (.js/.ts/.jsx/.tsx) files.
    L1/L2/L4 work on Python files; L3 (Semgrep) works on both Python and JS/TS.
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

    # L1: Quick detection — Python only (AST + regex)
    if "l1" not in skip:
        for f in py_files:
            findings = run_l1(f)
            result.findings.extend(findings)

    # L2: MCP structure analysis — Python only (AST-based)
    if "l2" not in skip:
        for f in py_files:
            findings = run_l2(f, state_file=state_file)
            result.findings.extend(findings)

    # L3: Taint analysis via Semgrep — Python + JS/TS
    if "l3" not in skip:
        if l3_available():
            # Semgrep scans all supported languages in one pass
            findings = run_l3(target_path)
            result.findings.extend(findings)
        else:
            result.errors.append(
                "L3 skipped: semgrep not installed. "
                "Install with: pip install semgrep"
            )

    # L4: Description-code mismatch — Python only (AST-based)
    if "l4" not in skip:
        for f in py_files:
            findings = run_l4(f)
            result.findings.extend(findings)

    # Post-processing: filter out low-confidence low-severity noise
    result.findings = [
        f for f in result.findings
        if not (f.severity == Severity.LOW and f.confidence == Confidence.NEEDS_REVIEW)
    ]

    # Deduplicate findings with same (file, line, id)
    seen = set()
    deduped = []
    for f in result.findings:
        key = (f.file, f.line, f.id)
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    result.findings = deduped

    # Add language stats to help user understand coverage
    if js_files and "l1" not in skip:
        result.errors.append(
            f"Note: {len(js_files)} JS/TS file(s) found. "
            f"L1/L2/L4 only analyze Python; L3 (Semgrep) covers JS/TS."
        )

    return result
