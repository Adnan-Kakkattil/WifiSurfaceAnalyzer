# User Guide

This guide explains how to use the Wi-Fi Attack Surface Analyzer via CLI and Web UI.

---

## 1. CLI Usage

### Analyze a PCAP File

```bash
wsa scan pcap capture.pcapng --out reports/scan.json --format both
```

- **`--format rich`**: Terminal report only
- **`--format json`**: JSON file only (no terminal output)
- **`--format both`**: Both terminal and JSON

### View a Saved Report

```bash
wsa report reports/scan.json
```

### Live Capture (Linux)

```bash
sudo wsa scan live --iface wlan0mon --seconds 60 --out reports/live.json --format both
```

---

## 2. Web UI Usage

### Start the Server

```bash
wsa-web --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000` in your browser.

### Upload PCAP

1. Click **Choose File** and select a .pcap or .pcapng file
2. Click **Upload & Analyze**
3. You are redirected to the report page

### Live Capture (Linux Only)

1. Enter the monitor-mode interface (e.g. `wlan0mon`)
2. Set capture duration (seconds)
3. Click **Start Live Capture**

On Windows, the live capture form is disabled.

### Report Page

- **Filters:** Search by SSID/BSSID, min risk, level, encryption, band
- **Export JSON:** Download full report
- **Export CSV:** Download filtered results (respects active filters)

---

## 3. Understanding the Output

### Risk Levels

| Level | Score Range | Meaning |
|-------|-------------|---------|
| CRITICAL | 75–100 | Very high attack feasibility |
| HIGH | 50–74 | High attack feasibility |
| MEDIUM | 25–49 | Moderate attack feasibility |
| LOW | 0–24 | Lower attack feasibility |

### Risk Factors

Each AP has a `risk_factors` breakdown:

- **encryption:** Open/WEP/WPA etc. (highest weight)
- **discoverability:** Broadcast vs hidden SSID
- **signal_leakage:** RSSI-based (stronger = more leakage)
- **channel_band:** 2.4GHz vs 5GHz (2.4GHz often longer range)

### JSON Report Structure

```json
{
  "meta": {
    "tool": "wifi-surface-analyzer",
    "version": "0.1.0",
    "generated_at": "2025-03-17T12:00:00Z",
    "source": "pcap:capture.pcapng"
  },
  "access_points": [
    {
      "bssid": "aa:bb:cc:dd:ee:ff",
      "ssid": "MyNetwork",
      "ssid_hidden": false,
      "channel": 6,
      "band": "2.4GHz",
      "encryption": "WPA2-PSK",
      "rssi_dbm": -65.0,
      "risk_score": 42,
      "risk_level": "MEDIUM",
      "risk_factors": { ... }
    }
  ],
  "summary": {
    "counts": { "CRITICAL": 0, "HIGH": 2, "MEDIUM": 5, "LOW": 3 },
    "top10": [ ... ],
    "total": 10
  }
}
```

---

## 4. Typical Workflows

### One-off PCAP Analysis

```bash
wsa scan pcap my_capture.pcapng --format both
```

### Batch Analysis

```bash
for f in captures/*.pcapng; do
  wsa scan pcap "$f" --out "reports/$(basename "$f" .pcapng).json" --format json
done
```

### Web UI with Filters

1. Upload PCAP
2. On report page, set `min_risk=50` to see HIGH/CRITICAL only
3. Export CSV for filtered list

---

## 5. Ethics and Legal

- Use only on networks you **own** or have **explicit permission** to assess
- Passive capture may be regulated by policy and law in your jurisdiction
- Do not use for unauthorized access or surveillance
