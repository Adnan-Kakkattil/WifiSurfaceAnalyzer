from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Iterable, List

from rich.console import Console
from rich.table import Table
from rich.text import Text

from .models import AccessPointObservation


def _fmt_ts(ts: float) -> str:
    try:
        return datetime.fromtimestamp(ts).isoformat(timespec="seconds")
    except Exception:
        return str(ts)


def print_console_report(*, aps: List[AccessPointObservation], meta: Dict[str, Any], summary: Dict[str, Any]) -> None:
    console = Console()
    console.print(Text("Wi-Fi Attack Surface Analyzer", style="bold"))

    if meta:
        src = meta.get("source", "")
        gen = meta.get("generated_at", "")
        console.print(f"[bold]Source:[/bold] {src}")
        console.print(f"[bold]Generated:[/bold] {gen}")

    counts = (summary or {}).get("counts", {})
    if counts:
        console.print(
            f"[bold]Totals:[/bold] {summary.get('total', len(aps))}  "
            f"CRITICAL={counts.get('CRITICAL', 0)}  HIGH={counts.get('HIGH', 0)}  "
            f"MEDIUM={counts.get('MEDIUM', 0)}  LOW={counts.get('LOW', 0)}"
        )

    table = Table(title="Access Points (sorted by risk)", show_lines=False)
    table.add_column("Risk", justify="right", no_wrap=True)
    table.add_column("Level", no_wrap=True)
    table.add_column("BSSID", no_wrap=True)
    table.add_column("SSID", overflow="fold")
    table.add_column("Enc", no_wrap=True)
    table.add_column("Chan", justify="right", no_wrap=True)
    table.add_column("Band", no_wrap=True)
    table.add_column("RSSI", justify="right", no_wrap=True)
    table.add_column("Beacons", justify="right", no_wrap=True)
    table.add_column("Last seen", no_wrap=True)

    def level_style(level: str | None) -> str:
        return {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "green",
        }.get((level or "").upper(), "white")

    aps_sorted = sorted(aps, key=lambda a: (a.risk_score or -1, a.beacon_count), reverse=True)
    for ap in aps_sorted:
        rssi = "" if ap.rssi_dbm is None else f"{ap.rssi_dbm:.0f} dBm"
        ssid = ap.ssid if ap.ssid else ("<hidden>" if ap.ssid_hidden else "<unknown>")
        table.add_row(
            str(ap.risk_score if ap.risk_score is not None else ""),
            Text(str(ap.risk_level or ""), style=level_style(ap.risk_level)),
            ap.bssid,
            ssid,
            ap.encryption,
            "" if ap.channel is None else str(ap.channel),
            ap.band,
            rssi,
            str(ap.beacon_count),
            _fmt_ts(ap.last_seen),
        )

    console.print(table)

