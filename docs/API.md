# API Reference

This document describes the CLI, Web API, and Python module interfaces.

---

## 1. CLI (wsa)

### Invocation

```bash
wsa [--version] <command> [options]
python -m wifi_surface_analyzer [--version] <command> [options]
```

### Commands

#### scan pcap

Analyze a PCAP or PCAPNG file.

```bash
wsa scan pcap <path> [--out PATH] [--format {rich|json|both}]
```

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `path` | Yes | — | Path to .pcap or .pcapng file |
| `--out` | No | `reports/scan.json` | Output JSON path |
| `--format` | No | `rich` | Output: `rich`, `json`, or `both` |

#### scan live

Live capture from a monitor-mode interface (Linux only).

```bash
wsa scan live --iface <interface> [--seconds N] [--out PATH] [--format {rich|json|both}]
```

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `--iface` | Yes | — | Monitor-mode interface (e.g. wlan0mon) |
| `--seconds` | No | 30 | Capture duration in seconds |
| `--out` | No | `reports/scan.json` | Output JSON path |
| `--format` | No | `rich` | Output format |

#### report

Render a Rich report from a previously saved JSON file.

```bash
wsa report <path>
```

| Argument | Required | Description |
|----------|----------|-------------|
| `path` | Yes | Path to JSON report file |

---

## 2. Web API (wsa-web)

### Start Server

```bash
wsa-web [--host HOST] [--port PORT]
```

Default: `127.0.0.1:8000`

### Routes

#### GET /

Index page: upload form, live capture form (if supported), list of recent reports.

#### POST /scan/pcap

Upload a PCAP/PCAPNG file for analysis.

**Form fields:**
- `capture` (file, required): .pcap or .pcapng file
- `format` (string, optional): `both` (default) or `json`

**Response:**
- If `format=both`: 303 redirect to `/reports/{id}`
- If `format=json`: File download of JSON report

#### POST /scan/live

Live capture (Linux only; returns 400 on Windows).

**Form fields:**
- `iface` (string, required): Monitor-mode interface
- `seconds` (int, optional): Duration, default 30
- `format` (string, optional): `both` or `json`

**Response:** Same as `/scan/pcap`

#### GET /reports/{report_id}

HTML report page with filters.

**Query parameters (filters):**
- `q`: Search SSID/BSSID
- `min_risk`: Minimum risk score (integer)
- `level`: CRITICAL, HIGH, MEDIUM, LOW
- `encryption`: Filter by encryption type
- `band`: 2.4GHz, 5GHz, etc.

#### GET /reports/{report_id}.json

Download full JSON report.

#### GET /reports/{report_id}.csv

Download CSV export. Respects same query filters as HTML report.

**CSV columns:** risk_score, risk_level, bssid, ssid, ssid_hidden, encryption, channel, band, rssi_dbm, beacon_count, first_seen, last_seen

---

## 3. Python Module API

### capture

```python
from wifi_surface_analyzer.capture import read_pcap, sniff_live

# Read from file
packets = read_pcap("path/to/capture.pcapng")

# Live capture (Linux)
packets = sniff_live(iface="wlan0mon", seconds=30)
```

| Function | Parameters | Returns |
|----------|------------|---------|
| `read_pcap(path)` | `path: str | Path` | Iterable of Scapy packets |
| `sniff_live(iface, seconds)` | `iface: str`, `seconds: int` | Iterator of Scapy packets |

### analyze

```python
from wifi_surface_analyzer.analyze import analyze_packets

aps_map = analyze_packets(packets)
# aps_map: Dict[str, AccessPointObservation]
```

| Function | Parameters | Returns |
|----------|------------|---------|
| `analyze_packets(packets)` | `packets: Iterable` | `Dict[str, AccessPointObservation]` |

### risk

```python
from wifi_surface_analyzer.risk import score_access_point, summarize_risk

for ap in aps:
    score_access_point(ap)

summary = summarize_risk(aps)
# summary: {counts, top10, total}
```

| Function | Parameters | Returns |
|----------|------------|---------|
| `score_access_point(ap)` | `ap: AccessPointObservation` | Same AP (mutated) |
| `summarize_risk(aps)` | `aps: list[AccessPointObservation]` | `Dict[str, Any]` |

### io

```python
from wifi_surface_analyzer.io import save_report, load_report, utc_now_iso

save_report(path="reports/scan.json", meta=meta, aps=aps, summary=summary)
data = load_report("reports/scan.json")
# data: {meta, access_points, summary}
```

| Function | Parameters | Returns |
|----------|------------|---------|
| `save_report(path, meta, aps, summary)` | — | None |
| `load_report(path)` | `path: str | Path` | `Dict[str, Any]` |
| `utc_now_iso()` | — | `str` (ISO timestamp) |

### reporting

```python
from wifi_surface_analyzer.reporting import print_console_report

print_console_report(aps=aps, meta=meta, summary=summary)
```

| Function | Parameters | Returns |
|----------|------------|---------|
| `print_console_report(aps, meta, summary)` | — | None |

### models

```python
from wifi_surface_analyzer.models import AccessPointObservation

ap = AccessPointObservation(
    bssid="aa:bb:cc:dd:ee:ff",
    ssid="MyNetwork",
    ssid_hidden=False,
    channel=6,
    band="2.4GHz",
    encryption="WPA2-PSK",
    rssi_dbm=-65.0,
    first_seen=0.0,
    last_seen=0.0,
    beacon_count=10,
)
ap.to_json()
AccessPointObservation.from_json(d)
```

| Class/Field | Description |
|-------------|-------------|
| `AccessPointObservation` | Dataclass for AP observation |
| `bssid`, `ssid`, `ssid_hidden` | Identity |
| `channel`, `band`, `rssi_dbm` | RF / signal |
| `encryption` | Encryption type string |
| `first_seen`, `last_seen`, `beacon_count` | Activity |
| `risk_score`, `risk_level`, `risk_factors` | Risk (populated by risk.py) |
