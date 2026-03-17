# Architecture

This document describes the system architecture, module design, and data flow of the Wi-Fi Attack Surface Analyzer.

---

## 1. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Wi-Fi Attack Surface Analyzer                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌───────────┐ │
│   │   Capture    │───▶│   Analyze    │───▶│  Risk Score  │───▶│  Output   │ │
│   │ capture.py   │    │ analyze.py   │    │   risk.py    │    │ reporting │ │
│   │              │    │              │    │              │    │ io.py     │ │
│   │ read_pcap()  │    │ analyze_     │    │ score_      │    │ web/      │ │
│   │ sniff_live() │    │ packets()    │    │ access_     │    │           │ │
│   └──────────────┘    └──────────────┘    │ point()     │    └───────────┘ │
│          │                    │           │ summarize_   │         │       │
│          │                    │           │ risk()       │         │       │
│          ▼                    ▼           └──────────────┘         ▼       │
│   ┌──────────────┐    ┌──────────────┐                      ┌───────────┐  │
│   │ Scapy        │    │ AccessPoint  │                      │ Terminal  │  │
│   │ rdpcap/      │    │ Observation  │                      │ JSON      │  │
│   │ sniff        │    │ (models.py)  │                      │ Web HTML  │  │
│   └──────────────┘    └──────────────┘                      │ CSV       │  │
│                                                             └───────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Module Responsibilities

| Module | File | Responsibility |
|--------|------|----------------|
| **CLI** | `cli.py` | Argument parsing, subcommand dispatch, orchestration |
| **Capture** | `capture.py` | Read PCAP/PCAPNG or sniff live 802.11 packets |
| **Analyze** | `analyze.py` | Parse Dot11Beacon/Dot11ProbeResp, extract SSID/BSSID/channel/encryption/RSSI |
| **Models** | `models.py` | `AccessPointObservation` dataclass, JSON serialization |
| **Risk** | `risk.py` | Per-AP risk scoring, summarize_risk() |
| **I/O** | `io.py` | save_report(), load_report() |
| **Reporting** | `reporting.py` | Rich console table output |
| **Web** | `web/app.py`, `web/run.py` | FastAPI app, routes, templates |

---

## 3. Data Flow (Detailed)

### 3.1 Capture → Packets

**Input:** File path (PCAP) or interface + duration (live)

**Process:**
- `read_pcap(path)` → Scapy `rdpcap()` → yields packets
- `sniff_live(iface, seconds)` → Scapy `sniff()` → yields packets

**Output:** Iterable of Scapy packets (802.11 frames)

**Platform:** Live capture requires Linux + monitor mode; Windows supports PCAP only.

---

### 3.2 Analyze → AccessPointObservation

**Input:** Iterable of Scapy packets

**Process:**
1. Filter: `Dot11` + (`Dot11Beacon` or `Dot11ProbeResp`)
2. Extract BSSID from `addr2` or `addr3`
3. Parse 802.11 information elements:
   - SSID (EID 0), channel (EID 3), RSN (EID 48), WPA (EID 221)
4. Classify encryption: OPEN, WEP, WPA, WPA2-PSK, WPA2-ENTERPRISE, WPA3-SAE, etc.
5. Extract RSSI from RadioTap if present
6. Derive band from channel (2.4GHz, 5GHz)
7. Aggregate per BSSID: merge observations, update SSID/channel/encryption as better data arrives

**Output:** `Dict[str, AccessPointObservation]` keyed by BSSID

---

### 3.3 Risk Score → Scored APs

**Input:** List of `AccessPointObservation`

**Process (per AP):**
1. **Encryption points** (0–55): OPEN=45, WEP=55, WPA=30, WPA2-PSK=20, WPA3-SAE=5, etc.
2. **Discoverability** (3–10): hidden=3, broadcast=10
3. **Signal leakage** (2–20): based on RSSI (stronger = higher risk)
4. **Channel/band** (2–6): 2.4GHz=6, 5GHz=4, unknown=2
5. Sum → clamp 0–100
6. Label: CRITICAL (≥75), HIGH (≥50), MEDIUM (≥25), LOW (<25)

**Output:** Same APs with `risk_score`, `risk_level`, `risk_factors` populated

---

### 3.4 Output

| Output | Module | Format |
|--------|--------|--------|
| Terminal | `reporting.py` | Rich table, summary counts |
| JSON | `io.py` | `{meta, access_points, summary}` |
| Web HTML | `web/app.py` | Jinja2 templates, filters |
| CSV | `web/app.py` | Filtered export |

---

## 4. Execution Paths

### CLI – PCAP Scan

```
main() → scan pcap
  → read_pcap(path)
  → analyze_packets(packets)
  → score_access_point(ap) for each ap
  → summarize_risk(aps)
  → save_report() [if json/both]
  → print_console_report() [if rich/both]
```

### CLI – Report from JSON

```
main() → report
  → load_report(path)
  → score_access_point(ap) if risk_score is None
  → print_console_report()
```

### Web – PCAP Upload

```
POST /scan/pcap
  → Save upload to uploads/{id}.pcapng
  → read_pcap()
  → analyze_packets()
  → score_access_point() for each
  → save_report() to reports/{id}.json
  → Redirect to /reports/{id}
```

### Web – View Report

```
GET /reports/{id}
  → load_report()
  → Apply query filters (q, min_risk, level, encryption, band)
  → Render report.html with filtered APs
```

---

## 5. Dependencies

| Package | Purpose |
|---------|---------|
| scapy | 802.11 packet parsing, PCAP read, live sniff |
| rich | Terminal tables and formatting |
| fastapi | Web framework |
| uvicorn | ASGI server |
| jinja2 | HTML templates |
| python-multipart | File upload handling |

---

## 6. Extensibility Points

- **CTI feeds:** Map Wi-Fi weaknesses to TTPs and prevalence
- **ML models:** Learn environment-specific leakage patterns
- **SOAR/SIEM:** Push JSON to pipelines, correlate with inventory
