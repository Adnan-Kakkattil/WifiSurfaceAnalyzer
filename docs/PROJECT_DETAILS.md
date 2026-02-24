## Project details (from `Abstract.md`)

### Goal

Provide a unified, attacker-centric view of **Wi‑Fi exposure** by:

- passively discovering access points from 802.11 management traffic
- extracting attributes relevant to reconnaissance and initial access
- prioritizing findings using a **feasibility-oriented risk model**
- producing both **human-readable** and **machine-readable** outputs

### Data collected (current implementation)

From beacon / probe-response frames the analyzer extracts:

- **Identity**: BSSID, SSID (and whether hidden)
- **RF / discoverability**: channel + derived band, optional RSSI (if present in capture metadata)
- **Encryption posture** (best-effort):
  - `OPEN`, `WEP`, `WPA`, `WPA2-PSK`, `WPA2-ENTERPRISE`, `WPA3-SAE`, `WPA2/WPA3-TRANSITION`, `RSN`

### Risk model (current implementation)

The score is a bounded sum (0–100) that emphasizes **attack feasibility**:

- **Encryption**: highest weight (Open/WEP highest risk, WPA3-SAE lowest)
- **Discoverability**: broadcast SSIDs get higher recon feasibility than hidden SSIDs
- **Signal leakage**: strong RSSI implies likely off‑prem discoverability (when RSSI is available)
- **Band/channel**: small adjustment (2.4 GHz is typically longer-range)

The output includes:

- numeric score `risk_score`
- label `risk_level`: `LOW` / `MEDIUM` / `HIGH` / `CRITICAL`
- per-factor breakdown `risk_factors`

### JSON output shape

The JSON report contains:

- `meta`: tool/version/time/source
- `access_points`: list of observations (one per BSSID)
- `summary`: counts and a top‑10 list by risk

### Extensibility points (intended next steps)

- **CTI feeds**: map common Wi‑Fi weaknesses to real-world actor TTPs and prevalence
- **ML models**: learn environment-specific leakage / exposure patterns from labeled captures
- **SOAR/SIEM integration**: push JSON outputs to pipelines and correlate with inventory

