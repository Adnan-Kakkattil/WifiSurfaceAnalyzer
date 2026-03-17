# Wi-Fi Attack Surface Analyzer – Full Documentation

This folder contains the complete project documentation for the Wi-Fi Attack Surface Analyzer (WSA).

---

## Documentation Index

| Document | Description |
|----------|-------------|
| [**ARCHITECTURE.md**](ARCHITECTURE.md) | System architecture, module design, data flow |
| [**PROJECT_DETAILS.md**](PROJECT_DETAILS.md) | Data model, risk model, JSON output shape |
| [**API.md**](API.md) | CLI commands, Web API routes, Python module API |
| [**INSTALLATION.md**](INSTALLATION.md) | Installation, dependencies, platform notes |
| [**USER_GUIDE.md**](USER_GUIDE.md) | Usage guide for CLI and Web UI |
| [**DFD.md**](DFD.md) | 3-level Data Flow Diagrams (context, level 1, level 2) |

---

## Quick Reference

### Entry Points

| Entry | Command | Purpose |
|-------|---------|---------|
| CLI | `wsa` or `python -m wifi_surface_analyzer` | Command-line interface |
| Web | `wsa-web --host 127.0.0.1 --port 8000` | Web UI server |

### CLI Subcommands

| Command | Description |
|---------|-------------|
| `wsa scan pcap <path>` | Analyze PCAP/PCAPNG file |
| `wsa scan live --iface wlan0mon --seconds 30` | Live capture (Linux only) |
| `wsa report <path>` | Render report from saved JSON |

### Web Routes

| Route | Method | Purpose |
|-------|--------|---------|
| `/` | GET | Index: upload form, recent reports |
| `/scan/pcap` | POST | Upload PCAP → analyze → report |
| `/scan/live` | POST | Live capture → analyze → report |
| `/reports/{id}` | GET | HTML report with filters |
| `/reports/{id}.json` | GET | JSON download |
| `/reports/{id}.csv` | GET | CSV download (filtered) |

---

## Project Overview

WSA is a research-oriented tool that:

1. **Captures** 802.11 management traffic (PCAP or live)
2. **Analyzes** beacons and probe responses to extract AP attributes
3. **Scores** each AP by attack feasibility (0–100)
4. **Outputs** terminal report, JSON, Web UI, CSV

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full data flow and module design.
