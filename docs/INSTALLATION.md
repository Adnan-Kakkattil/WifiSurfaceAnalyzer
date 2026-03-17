# Installation

This document describes how to install and configure the Wi-Fi Attack Surface Analyzer.

---

## Requirements

- **Python:** 3.10 or higher
- **OS:** Windows, Linux, macOS (PCAP analysis); Linux only for live capture
- **Live capture:** Linux wireless drivers with monitor mode support, root privileges

---

## Install Steps

### 1. Clone or Download

```bash
cd /path/to/WifiSurfaceAnalyzer
```

### 2. Create Virtual Environment

```bash
python -m venv .venv
```

### 3. Activate Virtual Environment

**Windows (PowerShell):**
```powershell
.venv\Scripts\activate
```

**Windows (CMD):**
```cmd
.venv\Scripts\activate.bat
```

**Linux / macOS:**
```bash
source .venv/bin/activate
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
pip install -e .
```

The `-e` flag installs the package in editable mode so changes to source are reflected immediately.

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| scapy | ≥2.5.0 | 802.11 packet parsing, PCAP, live sniff |
| rich | ≥13.7.0 | Terminal output |
| fastapi | ≥0.110.0 | Web framework |
| uvicorn | ≥0.27.0 | ASGI server |
| jinja2 | ≥3.1.3 | HTML templates |
| python-multipart | ≥0.0.9 | File upload |

---

## Verify Installation

```bash
wsa --version
wsa-web --help
```

---

## Live Capture Setup (Linux)

For live 802.11 capture, you need:

1. **Monitor mode interface**

   ```bash
   sudo airmon-ng start wlan0
   # Creates wlan0mon
   ```

2. **Root privileges** for sniffing

   ```bash
   sudo wsa scan live --iface wlan0mon --seconds 30
   ```

3. **Compatible wireless driver** (e.g. Atheros, Ralink, Intel with monitor support)

---

## Environment Variables (Optional)

| Variable | Purpose |
|----------|---------|
| `WSA_BASE_DIR` | Project root for Web UI (default: current working directory) |
| `WSA_REPORTS_DIR` | Base directory for Web UI reports/uploads (default: `{cwd}/reports/webui`) |

---

## Troubleshooting

### Scapy import error

Ensure Scapy is installed with 802.11 support:

```bash
pip install scapy>=2.5.0
```

### Live capture not supported on Windows

Use PCAP analysis instead. Capture with Wireshark or another tool, then:

```bash
wsa scan pcap capture.pcapng --out reports/scan.json
```

### Permission denied for live capture

Run with `sudo` on Linux.
