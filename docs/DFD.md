# Data Flow Diagrams (DFD)

This document provides the 3-level Data Flow Diagrams for the Wi-Fi Attack Surface Analyzer.

---

## Level 0 – Context Diagram

Shows the system boundary and external entities.

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

**External entities:**
- **User:** Initiates scans, uploads files, views reports
- **PCAP File:** Pre-captured 802.11 traffic
- **Live Interface:** Monitor-mode wireless interface (Linux)

**Outputs:**
- Terminal report (Rich)
- JSON report file
- Web HTML report
- CSV export (filtered)

---

## Level 1 – Main Process Decomposition

Four main processes and data stores.

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

| Process | Module | Input | Output |
|---------|--------|-------|--------|
| 1.0 Capture | capture.py | Path / iface+seconds | 802.11 packets |
| 2.0 Analyze | analyze.py | Packets | AccessPointObservation per BSSID |
| 3.0 Risk Score | risk.py | AP observations | Scored APs with risk_score, risk_level |
| 4.0 Output | reporting, io, web | Scored APs + summary | Terminal, JSON, Web, CSV |

---

## Level 2 – Detailed Sub-Processes

### Process 2.0 – Analyze (Expanded)

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

| Sub-process | Description |
|-------------|-------------|
| 2.1 Filter Frames | Keep only Dot11Beacon and Dot11ProbeResp |
| 2.2 Extract Identity | BSSID (addr2/addr3), SSID (EID 0), ssid_hidden |
| 2.3 Extract RF | Channel (EID 3), band from channel, RSSI from RadioTap |
| 2.4 Classify Encryption | Parse RSN/WPA IEs, map to OPEN/WEP/WPA/WPA2/WPA3 |
| 2.5 Aggregate | Merge per BSSID, update as better data arrives |

### Process 3.0 – Risk Score (Expanded)

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

| Sub-process | Description |
|-------------|-------------|
| 3.1 Encryption | OPEN=45, WEP=55, WPA=30, WPA2-PSK=20, WPA3-SAE=5, etc. |
| 3.2 Discoverability | Hidden=3, broadcast=10 |
| 3.3 Signal Leakage | Strong RSSI = higher points (2–20) |
| 3.4 Channel/Band | 2.4GHz=6, 5GHz=4, unknown=2 |
| 3.5 Aggregate | Sum, clamp 0–100, assign level |

### Process 4.0 – Output (Expanded)

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

| Sub-process | Description |
|-------------|-------------|
| 4.1 Summarize | Count by level, top 10 by risk |
| 4.2 Rich Terminal | Rich table, summary counts |
| 4.3 JSON Save | Write meta, access_points, summary |
| 4.4 Web Render | Jinja2 report.html with filters |
| 4.5 CSV Export | Filtered CSV download |
