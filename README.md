# Network Intrusion Detection System (NIDS)

A lightweight, rule-based Network Intrusion Detection System built in Python
using `scapy`. Built to satisfy **Task 4: Network Intrusion Detection System**:

1. Captures live network traffic (packet sniffer).
2. Applies configurable rules to detect suspicious/malicious activity:
   - Port scans (many distinct ports touched by one source in a short window)
   - SYN floods
   - ICMP (ping) floods
   - Blacklisted IP traffic
   - Access to known-suspicious ports
3. Monitors traffic continuously in real time.
4. Responds to detected intrusions (logs + simulated/real IP block via `iptables`).
5. Visualizes detected attacks with a matplotlib dashboard.

## Project structure

```
nids-project/
├── sniffer.py            # Main entry point / packet capture
├── detector.py            # Rule engine (detection logic)
├── alert.py                # Alert logging (console, file, JSON)
├── response.py            # Automated response (block offending IPs)
├── visualize_alerts.py     # Optional dashboard (matplotlib)
├── config.py                # Thresholds, blacklist, settings
├── requirements.txt
└── README.md
```

## Setup

```bash
git clone <your-repo-url>
cd nids-project
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

> **Windows users:** scapy needs [Npcap](https://npcap.com/) installed
> (install with "WinPcap API-compatible mode" checked) for live capture.

## Usage

### 1. Try it instantly — no admin rights needed
Runs synthetic attack traffic through the detector so you can see it work
immediately, without root/NIC access:
```bash
python3 sniffer.py --demo
```

### 2. Live capture (requires admin/root — it's reading real packets)
```bash
sudo python3 sniffer.py
```
Press `Ctrl+C` to stop. Alerts are printed to the console and written to
`alerts.log` / `alerts.json`.

### 3. Analyze a saved capture file (.pcap)
```bash
python3 sniffer.py --pcap sample.pcap
```

### 4. Visualize detected attacks
After running the sniffer (demo, live, or pcap mode), generate a dashboard:
```bash
python3 visualize_alerts.py
```
This produces `alerts_dashboard.png` with:
- a bar chart of alerts by type
- a line chart of alerts over time

## Configuration

All thresholds live in `config.py`:
- `PORT_SCAN_THRESHOLD` / `PORT_SCAN_WINDOW`
- `SYN_FLOOD_THRESHOLD` / `SYN_FLOOD_WINDOW`
- `ICMP_FLOOD_THRESHOLD` / `ICMP_FLOOD_WINDOW`
- `BLACKLISTED_IPS`
- `SUSPICIOUS_PORTS`
- `AUTO_BLOCK_ENABLED`

## Response mechanism

By default, `response.py` only **simulates** blocking (logs the action) so it's
safe to run anywhere. To perform a real `iptables` block on Linux, set
`REAL_BLOCK = True` in `response.py` and run with `sudo`. Only enable real
blocking on systems/networks you own or are authorized to manage.

## Notes on using Snort/Suricata instead

If your assignment specifically requires Snort or Suricata rather than a
custom Python sniffer, this project's `config.py` thresholds map directly to
Snort/Suricata rule syntax, e.g. a port-scan style rule in Suricata:

```
alert tcp any any -> any any (msg:"Possible port scan"; flags:S; threshold:type threshold, track by_src, count 15, seconds 10; sid:1000001;)
```

You can mention in your report that you implemented the same detection logic
both as custom Python code and as equivalent Suricata rules, if the task asks
for the "Snort or Suricata" tools explicitly.

## Disclaimer

This project is for educational use in a controlled/lab environment or on
networks you own or are authorized to monitor. Do not deploy against networks
without permission.
