"""Entry point: CLI + Web server."""

import sys
import uvicorn


def cli():
    """mcpsec-scan CLI entry point."""
    args = sys.argv[1:]

    # 极简 CLI: 默认启动 web, 加 scan 则直接扫描
    if args and args[0] == "scan":
        # CLI 模式: mcpsec-scan scan ./target
        from mcpsec_scan.engine.scanner import scan_target
        import json

        target = args[1] if len(args) > 1 else "."
        skip = set()
        if "--skip-l3" in args:
            skip.add("l3")

        result = scan_target(target, skip_layers=skip)
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))

        if any(f.severity.value in ("critical", "high") for f in result.findings):
            sys.exit(1)
    else:
        # Web 模式: mcpsec-scan [--port 8000]
        port = 8000
        if "--port" in args:
            idx = args.index("--port")
            port = int(args[idx + 1])

        print(f"Starting mcpsec-scan Web UI at http://localhost:{port}")
        print(f"Open your browser to start scanning.")
        uvicorn.run("mcpsec_scan.api:app", host="0.0.0.0", port=port, reload=False)


if __name__ == "__main__":
    cli()
