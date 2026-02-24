from __future__ import annotations

from collections import defaultdict
from typing import Dict, Iterable, Iterator, Optional, Tuple

from .models import AccessPointObservation


def _safe_decode_ssid(raw: bytes) -> str:
    if not raw:
        return ""
    try:
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return repr(raw)


def _iter_dot11_elts(pkt) -> Iterator:
    try:
        from scapy.layers.dot11 import Dot11Elt
    except Exception:
        return iter(())

    elt = pkt.getlayer(Dot11Elt)
    seen = 0
    while elt is not None and seen < 64:
        yield elt
        seen += 1
        elt = elt.payload.getlayer(Dot11Elt)


def _extract_ssid_channel_crypto(pkt) -> Tuple[str, bool, Optional[int], str, Dict[str, object]]:
    ssid = ""
    ssid_hidden = False
    channel: Optional[int] = None
    has_rsn = False
    has_wpa = False
    rsn_raw: bytes | None = None

    wpa_oui = b"\x00P\xf2\x01"

    for elt in _iter_dot11_elts(pkt):
        try:
            eid = int(getattr(elt, "ID", -1))
            info: bytes = getattr(elt, "info", b"") or b""
        except Exception:
            continue

        if eid == 0:  # SSID
            ssid = _safe_decode_ssid(info)
            ssid_hidden = len(info) == 0
        elif eid == 3 and info:
            channel = int(info[0])
        elif eid == 48:  # RSN
            has_rsn = True
            rsn_raw = bytes(info)
        elif eid == 221 and info.startswith(wpa_oui):
            has_wpa = True

    privacy = False
    try:
        from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp

        # Dot11Beacon / Dot11ProbeResp have .cap with a "privacy" flag.
        layer = pkt.getlayer(Dot11Beacon) or pkt.getlayer(Dot11ProbeResp)
        if layer is not None:
            cap = getattr(layer, "cap", None) or getattr(layer, "capability", None)
            if cap is not None:
                privacy = bool(getattr(cap, "privacy", False))
    except Exception:
        privacy = False

    enc = _classify_encryption(privacy=privacy, has_rsn=has_rsn, has_wpa=has_wpa, rsn_raw=rsn_raw)
    extra: Dict[str, object] = {"privacy": privacy, "has_rsn": has_rsn, "has_wpa": has_wpa}
    return ssid, ssid_hidden, channel, enc, extra


def _classify_encryption(*, privacy: bool, has_rsn: bool, has_wpa: bool, rsn_raw: bytes | None) -> str:
    if not privacy and not has_rsn and not has_wpa:
        return "OPEN"
    if not privacy and (has_rsn or has_wpa):
        return "OPEN"

    if has_rsn:
        akms = _parse_rsn_akm_types(rsn_raw or b"")
        has_psk = 2 in akms
        has_8021x = 1 in akms
        has_sae = 8 in akms

        if has_sae and has_psk:
            return "WPA2/WPA3-TRANSITION"
        if has_sae:
            return "WPA3-SAE"
        if has_8021x:
            return "WPA2-ENTERPRISE"
        if has_psk:
            return "WPA2-PSK"
        return "RSN"

    if has_wpa:
        return "WPA"
    return "WEP"


def _parse_rsn_akm_types(rsn: bytes) -> set[int]:
    """
    Minimal RSN IE parser to extract AKM suite types.
    RSN layout (bytes):
      - 2: version
      - 4: group cipher suite
      - 2: pairwise cipher count (n)
      - 4*n: pairwise cipher suites
      - 2: akm suite count (m)
      - 4*m: akm suites (OUI(3) + type(1))
    """
    if len(rsn) < 2 + 4 + 2:
        return set()
    i = 0
    i += 2  # version
    i += 4  # group cipher
    if i + 2 > len(rsn):
        return set()
    pairwise_count = int.from_bytes(rsn[i : i + 2], "little")
    i += 2
    i += 4 * pairwise_count
    if i + 2 > len(rsn):
        return set()
    akm_count = int.from_bytes(rsn[i : i + 2], "little")
    i += 2
    akms: set[int] = set()
    for _ in range(max(0, min(akm_count, 16))):
        if i + 4 > len(rsn):
            break
        suite = rsn[i : i + 4]
        akms.add(int(suite[3]))
        i += 4
    return akms


def _extract_rssi(pkt) -> Optional[float]:
    try:
        from scapy.layers.dot11 import RadioTap
    except Exception:
        return None
    try:
        rt = pkt.getlayer(RadioTap)
        if rt is None:
            return None
        # Scapy commonly exposes this attribute when present.
        v = getattr(rt, "dBm_AntSignal", None)
        if v is None:
            return None
        return float(v)
    except Exception:
        return None


def _channel_to_band(channel: Optional[int]) -> str:
    if channel is None:
        return "Unknown"
    if 1 <= channel <= 14:
        return "2.4GHz"
    if 32 <= channel <= 177:
        return "5GHz"
    # 6GHz channels overlap numerically with 2.4/5 depending on region; keep generic.
    return "Unknown"


def analyze_packets(packets: Iterable) -> Dict[str, AccessPointObservation]:
    """
    Builds per-BSSID observations from beacons and probe responses.
    """
    try:
        from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeResp
    except Exception as e:  # pragma: no cover
        raise RuntimeError("Scapy with 802.11 support is required to analyze captures.") from e

    aps: Dict[str, AccessPointObservation] = {}
    seen_types = defaultdict(int)

    for pkt in packets:
        try:
            if not pkt.haslayer(Dot11):
                continue
            if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
                continue
        except Exception:
            continue

        ts = float(getattr(pkt, "time", 0.0) or 0.0)
        dot11 = pkt.getlayer(Dot11)
        bssid = getattr(dot11, "addr2", None) or getattr(dot11, "addr3", None) or "unknown"
        bssid = str(bssid).lower()

        ssid, ssid_hidden, channel, encryption, extra = _extract_ssid_channel_crypto(pkt)
        rssi = _extract_rssi(pkt)
        band = _channel_to_band(channel)

        if bssid not in aps:
            aps[bssid] = AccessPointObservation(
                bssid=bssid,
                ssid=ssid,
                ssid_hidden=ssid_hidden,
                channel=channel,
                band=band,
                encryption=encryption,
                rssi_dbm=rssi,
                first_seen=ts,
                last_seen=ts,
                beacon_count=0,
                extra={},
            )

        ap = aps[bssid]
        ap.touch(ts, rssi_dbm=rssi)

        # Prefer non-empty SSIDs if we saw a hidden one first.
        if ap.ssid_hidden and ssid and not ssid_hidden:
            ap.ssid = ssid
            ap.ssid_hidden = False

        if ap.channel is None and channel is not None:
            ap.channel = channel
            ap.band = band

        # Prefer "better" encryption signals as more data arrives.
        if ap.encryption in {"UNKNOWN", "OPEN"} and encryption not in {"UNKNOWN"}:
            ap.encryption = encryption

        if pkt.haslayer(Dot11Beacon):
            ap.beacon_count += 1
            seen_types["beacon"] += 1
        else:
            seen_types["probe_resp"] += 1

        ap.extra.update(extra)

    return aps

