from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List

from . import __version__
from .analyze import analyze_packets
from .capture import read_pcap, sniff_live
from .io import load_report, save_report, utc_now_iso
from .risk import score_access_point, summarize_risk
from .reporting import print_console_report


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="wsa", description="Wi-Fi Attack Surface Analyzer (passive recon + feasibility risk scoring)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="Scan from PCAP or live capture")
    scan_sub = scan.add_subparsers(dest="scan_cmd", required=True)

    pcap = scan_sub.add_parser("pcap", help="Analyze a PCAP/PCAPNG capture")
    pcap.add_argument("path", help="Path to .pcap/.pcapng file")
    pcap.add_argument("--out", default=None, help="Write JSON report to this path (recommended: reports/scan.json)")
    pcap.add_argument("--format", choices=["rich", "json", "both"], default="rich", help="Output format")

    live = scan_sub.add_parser("live", help="Live sniff (Linux monitor mode)")
    live.add_argument("--iface", required=True, help="Monitor-mode interface (e.g. wlan0mon)")
    live.add_argument("--seconds", type=int, default=30, help="Capture duration seconds (default: 30)")
    live.add_argument("--out", default=None, help="Write JSON report to this path (recommended: reports/scan.json)")
    live.add_argument("--format", choices=["rich", "json", "both"], default="rich", help="Output format")

    rep = sub.add_parser("report", help="Render a Rich report from a saved JSON")
    rep.add_argument("path", help="Path to previously generated JSON report")

    return p


def _run_analysis(*, packets, source: str, out: str | None, fmt: str) -> int:
    aps_map = analyze_packets(packets)
    aps = list(aps_map.values())
    for ap in aps:
        score_access_point(ap)

    summary = summarize_risk(aps)
    meta = {"tool": "wifi-surface-analyzer", "version": __version__, "generated_at": utc_now_iso(), "source": source}

    if fmt in {"json", "both"}:
        if not out:
            out = str(Path("reports") / "scan.json")
        save_report(path=out, meta=meta, aps=aps, summary=summary)
        if fmt == "json":
            return 0

    if fmt in {"rich", "both"}:
        print_console_report(aps=aps, meta=meta, summary=summary)

    return 0


def main(argv: List[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.cmd == "scan" and args.scan_cmd == "pcap":
        packets = read_pcap(args.path)
        return _run_analysis(packets=packets, source=f"pcap:{args.path}", out=args.out, fmt=args.format)

    if args.cmd == "scan" and args.scan_cmd == "live":
        packets = sniff_live(iface=args.iface, seconds=args.seconds)
        return _run_analysis(packets=packets, source=f"live:{args.iface}:{args.seconds}s", out=args.out, fmt=args.format)

    if args.cmd == "report":
        data = load_report(args.path)
        aps = data["access_points"]
        # If JSON was produced by earlier version without scores, score now.
        for ap in aps:
            if ap.risk_score is None:
                score_access_point(ap)
        summary = data.get("summary") or summarize_risk(aps)
        print_console_report(aps=aps, meta=data.get("meta", {}), summary=summary)
        return 0

    raise RuntimeError("unreachable")


if __name__ == "__main__":
    raise SystemExit(main())

