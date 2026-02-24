from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


Encryption = str


@dataclass
class AccessPointObservation:
    bssid: str
    ssid: str
    ssid_hidden: bool
    channel: Optional[int]
    band: str
    encryption: Encryption
    rssi_dbm: Optional[float]
    first_seen: float
    last_seen: float
    beacon_count: int = 0
    extra: Dict[str, Any] = field(default_factory=dict)

    risk_score: Optional[int] = None
    risk_level: Optional[str] = None
    risk_factors: Dict[str, Any] = field(default_factory=dict)

    def touch(self, ts: float, rssi_dbm: Optional[float] = None) -> None:
        self.last_seen = max(self.last_seen, ts)
        if rssi_dbm is not None:
            self.rssi_dbm = rssi_dbm

    def to_json(self) -> Dict[str, Any]:
        return {
            "bssid": self.bssid,
            "ssid": self.ssid,
            "ssid_hidden": self.ssid_hidden,
            "channel": self.channel,
            "band": self.band,
            "encryption": self.encryption,
            "rssi_dbm": self.rssi_dbm,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "beacon_count": self.beacon_count,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "risk_factors": self.risk_factors,
            "extra": self.extra,
        }

    @staticmethod
    def from_json(d: Dict[str, Any]) -> "AccessPointObservation":
        ap = AccessPointObservation(
            bssid=d["bssid"],
            ssid=d.get("ssid", ""),
            ssid_hidden=bool(d.get("ssid_hidden", False)),
            channel=d.get("channel"),
            band=d.get("band", "Unknown"),
            encryption=d.get("encryption", "UNKNOWN"),
            rssi_dbm=d.get("rssi_dbm"),
            first_seen=float(d.get("first_seen", 0.0)),
            last_seen=float(d.get("last_seen", 0.0)),
            beacon_count=int(d.get("beacon_count", 0)),
            extra=dict(d.get("extra", {})),
        )
        ap.risk_score = d.get("risk_score")
        ap.risk_level = d.get("risk_level")
        ap.risk_factors = dict(d.get("risk_factors", {}))
        return ap

