"""FastAPI application — REST API + static file serving."""

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional

from mcpsecscan import __version__
from mcpsecscan.engine.scanner import scan_target

app = FastAPI(title="mcpsecscan", version=__version__)

STATIC_DIR = Path(__file__).parent / "static"


# ── API Models ────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str
    skip: list[str] = []


class AITriageRequest(BaseModel):
    findings: list[dict]
    target: str = ""
    api_url: str = "https://api.openai.com/v1"
    api_key: str = ""
    model: str = "gpt-4o-mini"


class ScanResponse(BaseModel):
    target: str
    total_findings: int
    scan_time_ms: int
    summary: dict
    findings: list[dict]
    errors: list[str]


# ── API Routes ────────────────────────────────────────────────────────────────

@app.post("/api/scan", response_model=ScanResponse)
async def api_scan(req: ScanRequest):
    """Run static security scan."""
    import time

    target_path = Path(req.target)
    if not target_path.exists():
        return JSONResponse(
            status_code=400,
            content={"error": f"Path not found: {req.target}"}
        )

    start = time.time()
    result = scan_target(req.target, skip_layers=set(req.skip))
    result.scan_time_ms = int((time.time() - start) * 1000)

    return ScanResponse(
        target=result.target,
        total_findings=len(result.findings),
        scan_time_ms=result.scan_time_ms,
        summary=result.summary,
        findings=[f.to_dict() for f in result.findings],
        errors=result.errors,
    )


@app.post("/api/ai-triage")
async def api_ai_triage(req: AITriageRequest):
    """Run AI triage on scan findings via any OpenAI-compatible API."""
    from mcpsecscan.ai_triage import triage, is_available
    from mcpsecscan.engine.models import ScanResult, Finding, Severity, Confidence

    if not is_available():
        return JSONResponse(
            status_code=503,
            content={"error": "httpx not installed. Run: pip install mcpsecscan[ai]"}
        )

    if not req.findings:
        return {"risk_level": "safe", "summary": "No findings to triage.", "items": [], "error": ""}

    # Reconstruct a minimal ScanResult from the dict findings
    scan_dict = {"target": req.target, "findings": req.findings}

    report = triage(
        scan_dict,
        api_url=req.api_url,
        api_key=req.api_key,
        model=req.model,
    )

    return {
        "model": report.model,
        "risk_level": report.risk_level,
        "summary": report.summary,
        "error": report.error,
        "items": [
            {
                "finding_id": item.finding_id,
                "verdict": item.verdict,
                "confidence": item.confidence,
                "explanation": item.explanation,
                "attack_scenario": item.attack_scenario,
                "fix_suggestion": item.fix_suggestion,
            }
            for item in report.items
        ],
    }


@app.get("/api/info")
async def api_info():
    """Return scanner info."""
    from mcpsecscan.engine.l3_taint import is_available as l3_ok, RULES_DIR
    from mcpsecscan.ai_triage import is_available as ai_ok

    rule_count = len(list(RULES_DIR.rglob("*.yaml"))) if RULES_DIR.exists() else 0

    return {
        "version": __version__,
        "layers": {
            "l1": {"name": "Quick Detection", "available": True},
            "l2": {"name": "MCP Structure", "available": True},
            "l3": {"name": "Taint Analysis", "available": l3_ok()},
            "l4": {"name": "Desc-Code Mismatch", "available": True},
        },
        "rules_count": rule_count,
        "ai_available": ai_ok(),
    }


# ── Static Files ──────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index():
    html_path = STATIC_DIR / "index.html"
    return HTMLResponse(html_path.read_text(encoding="utf-8"))

