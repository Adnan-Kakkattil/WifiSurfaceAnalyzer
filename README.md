# Wi-Fi Attack Surface Analyzer

Research-oriented **Wi-Fi attack surface analyzer** that performs **passive reconnaissance** (PCAP-first) and produces a **context-aware, attacker-centric risk prioritization** of discovered access points.

---

## What It Does

- **Passive recon** from 802.11 management frames (beacons / probe responses)
  - SSID visibility (broadcast vs hidden)
  - BSSID, channel, band
  - Encryption posture: Open / WEP / WPA / WPA2 / WPA3 (best-effort classification)
  - Optional signal strength (RSSI) when present in capture metadata
- **Risk scoring** focused on attack feasibility (0–100 scale)
- **Outputs**
  - Human-friendly terminal report (Rich)
  - Structured **JSON** for automation
  - **Web UI** with filters, JSON/CSV export

---

## Data Flow Diagrams (DFD)

### Level 0 – Context Diagram

Shows the system boundary and external entities interacting with the analyzer.

```mermaid
flowchart LR
    subgraph External["External Entities"]
        User([User])
        PCAP[(PCAP/PCAPNG File)]
        Live[(Live Interface)]
    end

    subgraph System["Wi-Fi Attack Surface Analyzer"]
        WSA[("0.0\nWSA System")]
    end

    subgraph Outputs["Outputs"]
        Report[(Terminal Report)]
        JSON[(JSON Report)]
        Web[(Web Report)]
        CSV[(CSV Export)]
    end

    User -->|"Upload / Command"| WSA
    PCAP -->|"802.11 Packets"| WSA
    Live -->|"Live Capture"| WSA
    WSA -->|"Risk Report"| Report
    WSA -->|"Structured Data"| JSON
    WSA -->|"HTML + Filters"| Web
    WSA -->|"Filtered Export"| CSV
```

**Data flows:**
- **Input:** User commands, PCAP file path, live interface + duration
- **Output:** Terminal report, JSON file, Web HTML report, CSV export

---

### Level 1 – Main Process Decomposition

Decomposes the system into four main processes.

```mermaid
flowchart TB
    subgraph External["External"]
        User([User])
        PCAP[(PCAP File)]
        Live[(Live Interface)]
    end

    subgraph System["Wi-Fi Attack Surface Analyzer"]
        P1["1.0\nCapture\nread_pcap / sniff_live"]
        P2["2.0\nAnalyze\nanalyze_packets"]
        P3["3.0\nRisk Score\nscore_access_point"]
        P4["4.0\nOutput\nreporting / io / web"]
    end

    subgraph DataStores["Data Stores"]
        D1[(D1: Packets)]
        D2[(D2: AP Observations)]
        D3[(D3: Scored APs)]
    end

    subgraph Outputs["Outputs"]
        Report[(Terminal)]
        JSON[(JSON)]
        Web[(Web/CSV)]
    end

    User --> P1
    PCAP -->|"file path"| P1
    Live -->|"iface, seconds"| P1
    P1 -->|"802.11 packets"| D1
    D1 --> P2
    P2 -->|"AccessPointObservation"| D2
    D2 --> P3
    P3 -->|"risk_score, risk_level"| D3
    D3 --> P4
    P4 --> Report
    P4 --> JSON
    P4 --> Web
```

**Processes:**
| ID | Process | Module | Description |
|----|---------|--------|-------------|
| 1.0 | Capture | `capture.py` | Read PCAP or sniff live 802.11 traffic |
| 2.0 | Analyze | `analyze.py` | Parse beacons/probe responses, build per-BSSID observations |
| 3.0 | Risk Score | `risk.py` | Compute feasibility-based risk score per AP |
| 4.0 | Output | `reporting.py`, `io.py`, `web/` | Terminal, JSON, Web UI, CSV |

---

### Level 2 – Detailed Sub-Processes

#### Process 2.0 – Analyze (Expanded)

```mermaid
flowchart TB
    subgraph P2["Process 2.0: Analyze"]
        P2A["2.1\nFilter Frames\nDot11Beacon / Dot11ProbeResp"]
        P2B["2.2\nExtract Identity\nBSSID, SSID, hidden"]
        P2C["2.3\nExtract RF\nchannel, band, RSSI"]
        P2D["2.4\nClassify Encryption\nRSN/WPA parsing"]
        P2E["2.5\nAggregate\nper-BSSID merge"]
    end

    D1[(Packets)] --> P2A
    P2A --> P2B
    P2B --> P2C
    P2C --> P2D
    P2D --> P2E
    P2E --> D2[(AP Observations)]
```

#### Process 3.0 – Risk Score (Expanded)

```mermaid
flowchart TB
    subgraph P3["Process 3.0: Risk Score"]
        P3A["3.1\nEncryption Points\nOpen/WEP/WPA/WPA2/WPA3"]
        P3B["3.2\nDiscoverability\nbroadcast vs hidden SSID"]
        P3C["3.3\nSignal Leakage\nRSSI-based scoring"]
        P3D["3.4\nChannel/Band\n2.4/5/6 GHz"]
        P3E["3.5\nAggregate & Label\n0-100, CRITICAL/HIGH/MED/LOW"]
    end

    D2[(AP Observations)] --> P3A
    P3A --> P3B
    P3B --> P3C
    P3C --> P3D
    P3D --> P3E
    P3E --> D3[(Scored APs)]
```

#### Process 4.0 – Output (Expanded)

```mermaid
flowchart TB
    subgraph P4["Process 4.0: Output"]
        P4A["4.1\nSummarize\ncounts, top10"]
        P4B["4.2\nRich Terminal\nprint_console_report"]
        P4C["4.3\nJSON Save\nsave_report"]
        P4D["4.4\nWeb Render\nJinja2 templates"]
        P4E["4.5\nCSV Export\nfiltered download"]
    end

    D3[(Scored APs)] --> P4A
    P4A --> P4B
    P4A --> P4C
    P4A --> P4D
    P4A --> P4E
```

---

## Quick Start

### Install

```bash
python -m venv .venv
.venv\Scripts\activate   # Windows
# source .venv/bin/activate  # Linux/macOS
pip install -r requirements.txt
pip install -e .
```

### Analyze a PCAP/PCAPNG

```bash
python -m wifi_surface_analyzer scan pcap "path\to\capture.pcapng" --out reports\scan.json --format both
```

### Report from saved JSON

```bash
python -m wifi_surface_analyzer report reports\scan.json
```

### Live capture (Linux monitor mode)

```bash
sudo python -m wifi_surface_analyzer scan live --iface wlan0mon --seconds 30 --out reports\scan.json --format both
```

### Web UI

```bash
wsa-web --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000` in your browser and upload a `.pcap` / `.pcapng`.

---

## Project Layout

| Path | Purpose |
|------|---------|
| `src/wifi_surface_analyzer/cli.py` | CLI entrypoints (`scan`, `report`) |
| `src/wifi_surface_analyzer/capture.py` | PCAP read + live sniff |
| `src/wifi_surface_analyzer/analyze.py` | 802.11 frame parsing + aggregation |
| `src/wifi_surface_analyzer/risk.py` | Feasibility-oriented scoring |
| `src/wifi_surface_analyzer/reporting.py` | Rich tables / summaries |
| `src/wifi_surface_analyzer/io.py` | JSON save/load |
| `src/wifi_surface_analyzer/models.py` | `AccessPointObservation` dataclass |
| `src/wifi_surface_analyzer/web/` | FastAPI Web UI |

---

## Documentation

- [**Full Project Documentation**](docs/README.md) – Architecture, API, data model, risk model
- [**Data Flow Diagrams (DFD)**](docs/DFD.md) – 3-level DFD (context, level 1, level 2)
- [**Project Details**](docs/PROJECT_DETAILS.md) – Data model, risk model, JSON shape
- [**Abstract**](Abstract.md) – Research abstract

---

## Ethics / Legal

Use only on networks you own or have explicit permission to assess. Passive capture can still be regulated by policy and law in your jurisdiction.

---

## References

- [Scapy](https://scapy.readthedocs.io/) – 802.11 / Dot11 layers
- [Rich](https://rich.readthedocs.io/) – Terminal output
- [802.11 / RSN (WPA2/WPA3) information elements](https://mrncciew.com/2014/10/08/802-11-mgmt-beacon-frame/)
- [Radiotap](https://www.radiotap.org/) – RSSI metadata in captures
