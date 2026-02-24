from __future__ import annotations

import platform
from pathlib import Path
from typing import Iterable, Iterator


def read_pcap(path: str | Path) -> Iterable:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(str(p))
    try:
        from scapy.all import rdpcap
    except Exception as e:  # pragma: no cover
        raise RuntimeError("Scapy is required to read PCAP/PCAPNG files.") from e
    return rdpcap(str(p))


def sniff_live(*, iface: str, seconds: int) -> Iterator:
    sysname = platform.system().lower()
    if sysname == "windows":
        raise RuntimeError("Live 802.11 monitor-mode capture is not supported on Windows in this tool. Use PCAP analysis instead.")
    if not iface:
        raise ValueError("iface is required")
    if seconds <= 0:
        raise ValueError("seconds must be > 0")

    try:
        from scapy.all import sniff
    except Exception as e:  # pragma: no cover
        raise RuntimeError("Scapy is required for live capture.") from e

    # Scapy returns a PacketList; iterating yields packets.
    pkts = sniff(iface=iface, timeout=int(seconds), store=True)
    for p in pkts:
        yield p

