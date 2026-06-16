"""Entry point: CLI + Web server."""

from __future__ import annotations

import json
import sys


def _print_triage_report(report, findings: list) -> None:
    """Pretty-print AI triage report to stderr (keeps stdout clean for JSON)."""
    import sys

    # Build a lookup from finding_id → triage item
    triage_map = {item.finding_id: item for item in report.items}

    RESET = "\033[0m"
    BOLD  = "\033[1m"
    RED   = "\033[31m"
    YEL   = "\033[33m"
    GRN   = "\033[32m"
    CYN   = "\033[36m"
    DIM   = "\033[2m"

    verdict_color = {
        "confirmed":    RED,
        "likely_fp":    GRN,
        "needs_review": YEL,
    }
    risk_color = {
        "critical": RED,
        "high":     RED,
        "medium":   YEL,
        "low":      GRN,
        "safe":     GRN,
    }

    sep = "─" * 72
    print(f"\n{BOLD}{'═' * 72}{RESET}", file=sys.stderr)
    print(f"{BOLD}  🤖  AI Triage Report  (model: {report.model}){RESET}", file=sys.stderr)
    print(f"{BOLD}{'═' * 72}{RESET}", file=sys.stderr)

    if report.error:
        print(f"\n{RED}AI triage failed:{RESET} {report.error}\n", file=sys.stderr)
        return

    # Overall risk
    rc = risk_color.get(report.risk_level, RESET)
    print(f"\n{BOLD}Overall risk:{RESET} {rc}{report.risk_level.upper()}{RESET}", file=sys.stderr)
    print(f"\n{report.summary}\n", file=sys.stderr)

    if not report.items:
        print(f"{DIM}No per-finding items returned.{RESET}", file=sys.stderr)
        return

    print(sep, file=sys.stderr)

    for item in report.items:
        vc = verdict_color.get(item.verdict, RESET)
        # Try to find matching finding for context
        matching = next((f for f in findings if f.get("id") == item.finding_id), None)
        loc = ""
        if matching:
            loc = f"  {DIM}{matching.get('file','')}:{matching.get('line','')}{RESET}"

        print(
            f"\n{BOLD}{item.finding_id}{RESET}{loc}\n"
            f"  Verdict:  {vc}{item.verdict}{RESET}  "
            f"{DIM}(confidence: {item.confidence}){RESET}",
            file=sys.stderr,
        )
        print(f"  {item.explanation}", file=sys.stderr)
        if item.attack_scenario:
            print(f"  {YEL}Attack:{RESET} {item.attack_scenario}", file=sys.stderr)
        if item.fix_suggestion:
            print(f"  {CYN}Fix:{RESET} {item.fix_suggestion}", file=sys.stderr)

    print(f"\n{sep}", file=sys.stderr)


def cli():
    """mcpsecscan CLI entry point."""
    args = sys.argv[1:]

    # ── scan subcommand ───────────────────────────────────────────────────────
    if args and args[0] == "scan":
        from mcpsecscan.engine.scanner import scan_target

        # positional: target path
        target = "."
        remaining = args[1:]
        positional = [a for a in remaining if not a.startswith("--")]
        if positional:
            target = positional[0]

        # flags
        skip: set[str] = set()
        if "--skip-l3" in args:
            skip.add("l3")

        # AI triage flags
        ai_explain  = "--ai-explain" in args
        ai_url      = _flag_value(args, "--ai-url",   "https://api.openai.com/v1")
        ai_key      = _flag_value(args, "--ai-key",   "")
        ai_model    = _flag_value(args, "--ai-model", "gpt-4o-mini")
        ai_timeout  = int(_flag_value(args, "--ai-timeout", "60"))

        # output format
        fmt = _flag_value(args, "--format", "json")

        result = scan_target(target, skip_layers=skip)
        result_dict = result.to_dict()

        # ── AI triage ─────────────────────────────────────────────────────
        triage_report = None
        if ai_explain:
            from mcpsecscan.ai_triage import triage, is_available
            if not is_available():
                print(
                    "ERROR: --ai-explain requires httpx. "
                    "Install with: pip install mcpsecscan[ai]",
                    file=sys.stderr,
                )
                sys.exit(2)
            print(
                f"Running AI triage (model={ai_model}, url={ai_url}) ...",
                file=sys.stderr,
            )
            triage_report = triage(
                result,
                api_url=ai_url,
                api_key=ai_key,
                model=ai_model,
                timeout=ai_timeout,
            )
            # Merge triage data into result dict for JSON output
            result_dict["ai_triage"] = {
                "model": triage_report.model,
                "risk_level": triage_report.risk_level,
                "summary": triage_report.summary,
                "error": triage_report.error,
                "items": [
                    {
                        "finding_id":     item.finding_id,
                        "verdict":        item.verdict,
                        "confidence":     item.confidence,
                        "explanation":    item.explanation,
                        "attack_scenario": item.attack_scenario,
                        "fix_suggestion": item.fix_suggestion,
                    }
                    for item in triage_report.items
                ],
            }

        # ── output ────────────────────────────────────────────────────────
        if fmt == "sarif":
            from mcpsecscan.sarif import to_sarif
            print(json.dumps(to_sarif(result), indent=2, ensure_ascii=False))
        else:
            print(json.dumps(result_dict, indent=2, ensure_ascii=False))

        # Pretty-print triage report to stderr (separate from JSON stdout)
        if triage_report is not None:
            _print_triage_report(triage_report, result_dict.get("findings", []))

        # CI exit code
        if any(f.severity.value in ("critical", "high") for f in result.findings):
            sys.exit(1)

    # ── web subcommand (default) ──────────────────────────────────────────────
    else:
        import uvicorn

        port = 8000
        if "--port" in args:
            idx = args.index("--port")
            port = int(args[idx + 1])

        print(f"Starting mcpsecscan Web UI at http://localhost:{port}")
        print("Open your browser to start scanning.")
        uvicorn.run("mcpsecscan.api:app", host="0.0.0.0", port=port, reload=False)


# ── helpers ───────────────────────────────────────────────────────────────────

def _flag_value(args: list[str], flag: str, default: str) -> str:
    """Return the value after `flag` in args, or `default`."""
    if flag in args:
        idx = args.index(flag)
        if idx + 1 < len(args):
            return args[idx + 1]
    return default


if __name__ == "__main__":
    cli()
