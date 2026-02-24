from __future__ import annotations

from typing import Any, Dict, Tuple

from .models import AccessPointObservation


def _leakage_points(rssi_dbm: float | None) -> Tuple[int, str]:
    if rssi_dbm is None:
        return 5, "unknown (no RSSI in capture)"
    if rssi_dbm >= -40:
        return 20, "very strong signal leakage (>= -40 dBm)"
    if rssi_dbm >= -60:
        return 15, "strong signal leakage (-60..-40 dBm)"
    if rssi_dbm >= -75:
        return 8, "moderate signal leakage (-75..-60 dBm)"
    return 2, "weak signal leakage (<= -75 dBm)"


def _encryption_points(enc: str) -> Tuple[int, str]:
    e = (enc or "").upper()
    if e == "OPEN":
        return 45, "unencrypted network (OPEN)"
    if e == "WEP":
        return 55, "legacy WEP (practically broken)"
    if e == "WPA":
        return 30, "legacy WPA (TKIP often present)"
    if e in {"WPA2-PSK", "WPA2/WPA3-TRANSITION"}:
        return 20 if e == "WPA2-PSK" else 15, e
    if e == "WPA2-ENTERPRISE":
        return 10, "WPA2-Enterprise (depends on EAP config)"
    if e == "WPA3-SAE":
        return 5, "WPA3-Personal (SAE)"
    if e == "RSN":
        return 18, "RSN present (WPA2/3-like), details unknown"
    return 25, f"unknown encryption: {enc}"


def _discoverability_points(ssid_hidden: bool) -> Tuple[int, str]:
    if ssid_hidden:
        return 3, "hidden SSID (still discoverable, slightly less visible)"
    return 10, "broadcast SSID (highly discoverable)"


def _channel_points(channel: int | None, band: str) -> Tuple[int, str]:
    if channel is None:
        return 2, "unknown channel"
    b = (band or "").lower()
    if "2.4" in b:
        return 6, f"2.4 GHz channel {channel} (common/long-range band)"
    if "5" in b:
        return 4, f"5 GHz channel {channel}"
    if "6" in b:
        return 3, f"6 GHz channel {channel}"
    return 4, f"channel {channel}"


def score_access_point(ap: AccessPointObservation) -> AccessPointObservation:
    enc_pts, enc_reason = _encryption_points(ap.encryption)
    disc_pts, disc_reason = _discoverability_points(ap.ssid_hidden)
    leak_pts, leak_reason = _leakage_points(ap.rssi_dbm)
    ch_pts, ch_reason = _channel_points(ap.channel, ap.band)

    score = enc_pts + disc_pts + leak_pts + ch_pts
    score = max(0, min(100, int(round(score))))

    if score >= 75:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 25:
        level = "MEDIUM"
    else:
        level = "LOW"

    ap.risk_score = score
    ap.risk_level = level
    ap.risk_factors = {
        "encryption": {"points": enc_pts, "reason": enc_reason},
        "discoverability": {"points": disc_pts, "reason": disc_reason},
        "signal_leakage": {"points": leak_pts, "reason": leak_reason},
        "channel_band": {"points": ch_pts, "reason": ch_reason},
    }
    return ap


def summarize_risk(aps: list[AccessPointObservation]) -> Dict[str, Any]:
    by_level: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    top = sorted([ap for ap in aps if ap.risk_score is not None], key=lambda a: a.risk_score or 0, reverse=True)[
        :10
    ]
    for ap in aps:
        if ap.risk_level in by_level:
            by_level[ap.risk_level] += 1

    return {
        "counts": by_level,
        "top10": [{"bssid": ap.bssid, "ssid": ap.ssid, "risk_score": ap.risk_score, "risk_level": ap.risk_level} for ap in top],
        "total": len(aps),
    }

