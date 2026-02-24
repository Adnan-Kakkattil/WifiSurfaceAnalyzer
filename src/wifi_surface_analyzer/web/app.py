from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .. import __version__
from ..analyze import analyze_packets
from ..capture import read_pcap
from ..io import load_report, save_report
from ..risk import score_access_point, summarize_risk


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _project_root() -> Path:
    # Prefer current working directory so running from repo root "just works".
    return Path(os.environ.get("WSA_BASE_DIR", Path.cwd())).resolve()


def _reports_dir() -> Path:
    return Path(os.environ.get("WSA_REPORTS_DIR", _project_root() / "reports" / "webui")).resolve()


def _allowed_capture(name: str) -> bool:
    n = (name or "").lower()
    return n.endswith(".pcap") or n.endswith(".pcapng")


def _templates_dir() -> Path:
    return (Path(__file__).resolve().parent / "templates").resolve()


def _static_dir() -> Path:
    return (Path(__file__).resolve().parent / "static").resolve()


app = FastAPI(title="Wi-Fi Attack Surface Analyzer", version=__version__)
templates = Jinja2Templates(directory=str(_templates_dir()))

if _static_dir().exists():
    app.mount("/static", StaticFiles(directory=str(_static_dir())), name="static")


def _list_reports() -> List[Tuple[str, Path]]:
    root = _reports_dir() / "reports"
    if not root.exists():
        return []
    items: List[Tuple[str, Path]] = []
    for p in root.glob("*.json"):
        items.append((p.stem, p))
    items.sort(key=lambda t: t[1].stat().st_mtime, reverse=True)
    return items


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    reports = _list_reports()
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "tool_version": __version__,
            "reports": [{"id": rid, "path": str(p)} for rid, p in reports],
        },
    )


@app.post("/scan/pcap")
async def scan_pcap(request: Request, capture: UploadFile = File(...), format: str = Form("both")):
    if not capture.filename or not _allowed_capture(capture.filename):
        raise HTTPException(status_code=400, detail="Please upload a .pcap or .pcapng file.")

    report_id = uuid.uuid4().hex[:12]
    base = _reports_dir()
    uploads = base / "uploads"
    reports = base / "reports"
    uploads.mkdir(parents=True, exist_ok=True)
    reports.mkdir(parents=True, exist_ok=True)

    suffix = Path(capture.filename).suffix.lower() or ".pcapng"
    capture_path = uploads / f"{report_id}{suffix}"
    with capture_path.open("wb") as f:
        while True:
            chunk = await capture.read(1024 * 1024)
            if not chunk:
                break
            f.write(chunk)

    packets = read_pcap(capture_path)
    aps_map = analyze_packets(packets)
    aps = list(aps_map.values())
    for ap in aps:
        score_access_point(ap)

    summary = summarize_risk(aps)
    meta: Dict[str, Any] = {
        "tool": "wifi-surface-analyzer",
        "version": __version__,
        "generated_at": _utc_now_iso(),
        "source": f"webui:pcap:{capture.filename}",
        "report_id": report_id,
    }

    report_path = reports / f"{report_id}.json"
    save_report(path=report_path, meta=meta, aps=aps, summary=summary)

    if format == "json":
        return FileResponse(path=str(report_path), media_type="application/json", filename=f"{report_id}.json")

    return RedirectResponse(url=f"/reports/{report_id}", status_code=303)


@app.get("/reports/{report_id}", response_class=HTMLResponse)
def view_report(request: Request, report_id: str):
    report_path = _reports_dir() / "reports" / f"{report_id}.json"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not found.")

    data = load_report(report_path)
    aps = data["access_points"]
    for ap in aps:
        if ap.risk_score is None:
            score_access_point(ap)

    summary = data.get("summary") or summarize_risk(aps)
    aps_sorted = sorted(aps, key=lambda a: (a.risk_score or -1, a.beacon_count), reverse=True)

    return templates.TemplateResponse(
        "report.html",
        {
            "request": request,
            "tool_version": __version__,
            "report_id": report_id,
            "meta": data.get("meta", {}),
            "summary": summary,
            "access_points": aps_sorted,
        },
    )


@app.get("/reports/{report_id}.json")
def download_report_json(report_id: str):
    report_path = _reports_dir() / "reports" / f"{report_id}.json"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not found.")
    return FileResponse(path=str(report_path), media_type="application/json", filename=f"{report_id}.json")

