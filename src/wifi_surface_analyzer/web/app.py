from __future__ import annotations

import csv
import io
import os
import platform
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .. import __version__
from ..analyze import analyze_packets
from ..capture import read_pcap, sniff_live
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

def _is_live_supported() -> bool:
    return platform.system().lower() != "windows"


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
            "live_supported": _is_live_supported(),
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

@app.post("/scan/live")
def scan_live(iface: str = Form(...), seconds: int = Form(30), format: str = Form("both")):
    report_id = uuid.uuid4().hex[:12]
    base = _reports_dir()
    reports = base / "reports"
    reports.mkdir(parents=True, exist_ok=True)

    try:
        packets = sniff_live(iface=iface, seconds=int(seconds))
        aps_map = analyze_packets(packets)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    aps = list(aps_map.values())
    for ap in aps:
        score_access_point(ap)

    summary = summarize_risk(aps)
    meta: Dict[str, Any] = {
        "tool": "wifi-surface-analyzer",
        "version": __version__,
        "generated_at": _utc_now_iso(),
        "source": f"webui:live:{iface}:{seconds}s",
        "report_id": report_id,
        "note": "Live capture requires Linux monitor mode + privileges.",
    }

    report_path = reports / f"{report_id}.json"
    save_report(path=report_path, meta=meta, aps=aps, summary=summary)

    if format == "json":
        return FileResponse(path=str(report_path), media_type="application/json", filename=f"{report_id}.json")

    return RedirectResponse(url=f"/reports/{report_id}", status_code=303)


def _get_query_str(request: Request, key: str, default: str = "") -> str:
    v = request.query_params.get(key, default)
    return str(v) if v is not None else default


def _get_query_int(request: Request, key: str, default: int | None = None) -> int | None:
    raw = request.query_params.get(key, None)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except Exception:
        return default


def _apply_filters(*, aps, q: str, min_risk: int | None, level: str, encryption: str, band: str):
    qn = (q or "").strip().lower()
    lvl = (level or "").strip().upper()
    enc = (encryption or "").strip().upper()
    bd = (band or "").strip().lower()

    out = []
    for ap in aps:
        if qn:
            hay = f"{ap.ssid or ''} {ap.bssid or ''}".lower()
            if qn not in hay:
                continue
        if min_risk is not None:
            if (ap.risk_score or 0) < min_risk:
                continue
        if lvl:
            if (ap.risk_level or "").upper() != lvl:
                continue
        if enc:
            if (ap.encryption or "").upper() != enc:
                continue
        if bd:
            if bd not in (ap.band or "").lower():
                continue
        out.append(ap)
    return out


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

    summary_all = data.get("summary") or summarize_risk(aps)
    q = _get_query_str(request, "q", "")
    min_risk = _get_query_int(request, "min_risk", None)
    level = _get_query_str(request, "level", "")
    encryption = _get_query_str(request, "encryption", "")
    band = _get_query_str(request, "band", "")

    aps_filtered = _apply_filters(aps=aps, q=q, min_risk=min_risk, level=level, encryption=encryption, band=band)
    aps_sorted = sorted(aps_filtered, key=lambda a: (a.risk_score or -1, a.beacon_count), reverse=True)
    summary_filtered = summarize_risk(aps_sorted)

    return templates.TemplateResponse(
        "report.html",
        {
            "request": request,
            "tool_version": __version__,
            "report_id": report_id,
            "meta": data.get("meta", {}),
            "summary": summary_all,
            "summary_filtered": summary_filtered,
            "filters": {"q": q, "min_risk": min_risk if min_risk is not None else "", "level": level, "encryption": encryption, "band": band},
            "access_points": aps_sorted,
        },
    )


@app.get("/reports/{report_id}.json")
def download_report_json(report_id: str):
    report_path = _reports_dir() / "reports" / f"{report_id}.json"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not found.")
    return FileResponse(path=str(report_path), media_type="application/json", filename=f"{report_id}.json")


@app.get("/reports/{report_id}.csv")
def download_report_csv(request: Request, report_id: str):
    report_path = _reports_dir() / "reports" / f"{report_id}.json"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not found.")

    data = load_report(report_path)
    aps = data["access_points"]
    for ap in aps:
        if ap.risk_score is None:
            score_access_point(ap)

    q = _get_query_str(request, "q", "")
    min_risk = _get_query_int(request, "min_risk", None)
    level = _get_query_str(request, "level", "")
    encryption = _get_query_str(request, "encryption", "")
    band = _get_query_str(request, "band", "")

    aps_filtered = _apply_filters(aps=aps, q=q, min_risk=min_risk, level=level, encryption=encryption, band=band)
    aps_sorted = sorted(aps_filtered, key=lambda a: (a.risk_score or -1, a.beacon_count), reverse=True)

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(
        [
            "risk_score",
            "risk_level",
            "bssid",
            "ssid",
            "ssid_hidden",
            "encryption",
            "channel",
            "band",
            "rssi_dbm",
            "beacon_count",
            "first_seen",
            "last_seen",
        ]
    )
    for ap in aps_sorted:
        w.writerow(
            [
                ap.risk_score,
                ap.risk_level,
                ap.bssid,
                ap.ssid,
                ap.ssid_hidden,
                ap.encryption,
                ap.channel,
                ap.band,
                ap.rssi_dbm,
                ap.beacon_count,
                ap.first_seen,
                ap.last_seen,
            ]
        )

    payload = buf.getvalue().encode("utf-8")
    filename = f"{report_id}.csv"
    return StreamingResponse(
        iter([payload]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )

