## Wi-Fi Attack Surface Analyzer

Research-oriented **Wi-Fi attack surface analyzer** that performs **passive reconnaissance** (PCAP-first) and produces a **context-aware, attacker-centric risk prioritization** of discovered access points.

### What it does

- **Passive recon** from 802.11 management frames (beacons / probe responses)
  - SSID visibility (broadcast vs hidden)
  - BSSID, channel
  - Encryption posture: Open / WEP / WPA / WPA2 / WPA3 (best-effort classification)
  - Optional signal strength (RSSI) when present in capture metadata
- **Risk scoring** focused on attack feasibility (not just static severity)
- **Outputs**
  - Human-friendly terminal report using Rich
  - Structured **JSON** for automation / future integrations

### Quick start (Windows / any OS for PCAP analysis)

Install:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

Analyze a PCAP/PCAPNG:

```bash
python -m wifi_surface_analyzer scan pcap "path\to\capture.pcapng" --out reports\scan.json --format both
```

Show a report from a previous JSON:

```bash
python -m wifi_surface_analyzer report reports\scan.json
```

### Live capture (Linux monitor mode)

Live capture requires:

- Linux wireless drivers that support **monitor mode**
- Root/admin privileges for sniffing

Example:

```bash
sudo python -m wifi_surface_analyzer scan live --iface wlan0mon --seconds 30 --out reports\scan.json --format both
```

### Web UI

Start the local Web UI:

```bash
wsa-web --host 127.0.0.1 --port 8000
```

Then open `http://127.0.0.1:8000` in your browser and upload a `.pcap` / `.pcapng`.

### Project layout

- `src/wifi_surface_analyzer/cli.py`: CLI entrypoints (`scan`, `report`)
- `src/wifi_surface_analyzer/analyze.py`: 802.11 frame parsing + aggregation
- `src/wifi_surface_analyzer/risk.py`: feasibility-oriented scoring + labels
- `src/wifi_surface_analyzer/reporting.py`: Rich tables / summaries
- `src/wifi_surface_analyzer/io.py`: JSON save/load
- `src/wifi_surface_analyzer/web/`: FastAPI Web UI (upload + report pages)

### Ethics / legal

Use only on networks you own or have explicit permission to assess. Passive capture can still be regulated by policy and law in your jurisdiction.

### References (online docs / articles)

- **Scapy**
  - Docs: `https://scapy.readthedocs.io/`
  - 802.11 / Dot11 layers: `https://scapy.readthedocs.io/en/latest/api/scapy.layers.dot11.html`
- **Rich**
  - Docs: `https://rich.readthedocs.io/`
- **802.11 / RSN (WPA2/WPA3) information elements**
  - RSN element overview (practical parsing references): `https://mrncciew.com/2014/10/08/802-11-mgmt-beacon-frame/`
  - Wi-Fi Alliance WPA3 overview: `https://www.wi-fi.org/discover-wi-fi/security`
- **Radiotap (RSSI metadata in captures)**
  - Spec landing page: `https://www.radiotap.org/`

