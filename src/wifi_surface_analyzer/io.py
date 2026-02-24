from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import AccessPointObservation


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def save_report(*, path: str | Path, meta: Dict[str, Any], aps: List[AccessPointObservation], summary: Dict[str, Any]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "meta": meta,
        "access_points": [ap.to_json() for ap in aps],
        "summary": summary,
    }
    p.write_text(json.dumps(payload, indent=2, sort_keys=False), encoding="utf-8")


def load_report(path: str | Path) -> Dict[str, Any]:
    p = Path(path)
    data = json.loads(p.read_text(encoding="utf-8"))
    aps = [AccessPointObservation.from_json(d) for d in data.get("access_points", [])]
    return {"meta": data.get("meta", {}), "access_points": aps, "summary": data.get("summary", {})}

