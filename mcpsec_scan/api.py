"""FastAPI application — REST API + static file serving."""

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from mcpsec_scan import __version__
from mcpsec_scan.engine.scanner import scan_target

app = FastAPI(title="mcpsec-scan", version=__version__)

STATIC_DIR = Path(__file__).parent / "static"


# ─── API Models ─────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str  # 文件或目录路径
    skip: list[str] = []  # 要跳过的层: ["l3"]


class FindingResponse(BaseModel):
    id: str
    title: str
    severity: str
    layer: str
    file: str
    line: int
    evidence: str
    owasp_mcp: str
    cia_impact: list[str]
    confidence: str
    tool_name: str


class ScanResponse(BaseModel):
    target: str
    total_findings: int
    scan_time_ms: int
    summary: dict
    findings: list[dict]
    errors: list[str]


# ─── API Routes ─────────────────────────────────────────────────────────────

@app.post("/api/scan", response_model=ScanResponse)
async def api_scan(req: ScanRequest):
    """执行静态安全扫描。"""
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


@app.get("/api/info")
async def api_info():
    """返回扫描器信息。"""
    from mcpsec_scan.engine.l3_taint import is_available as l3_ok, RULES_DIR

    rule_count = len(list(RULES_DIR.rglob("*.yaml"))) if RULES_DIR.exists() else 0

    return {
        "version": __version__,
        "layers": {
            "l1": {"name": "Quick Detection", "available": True},
            "l2": {"name": "MCP Structure", "available": True},
            "l3": {"name": "Taint Analysis", "available": l3_ok()},
            "l4": {"name": "Description-Code Mismatch", "available": True},
        },
        "rules_count": rule_count,
    }


# ─── Static Files (Web UI) ──────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index():
    """Serve the Web UI."""
    html_path = STATIC_DIR / "index.html"
    return HTMLResponse(html_path.read_text(encoding="utf-8"))
