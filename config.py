"""
config.py
Central configuration for the Network Intrusion Detection System.
Tune these values to change detection sensitivity.
"""

# Network interface to sniff on.
# Leave as None to let scapy pick the default interface.
INTERFACE = None

# --- Port Scan Detection ---
# If a single source IP touches this many DISTINCT destination ports
# within PORT_SCAN_WINDOW seconds, flag it as a port scan.
PORT_SCAN_THRESHOLD = 15
PORT_SCAN_WINDOW = 10  # seconds

# --- SYN Flood Detection ---
# If a single source IP sends this many SYN packets (without completed
# handshake) within SYN_FLOOD_WINDOW seconds, flag it as a SYN flood.
SYN_FLOOD_THRESHOLD = 100
SYN_FLOOD_WINDOW = 5  # seconds

# --- ICMP Flood (ping flood) Detection ---
ICMP_FLOOD_THRESHOLD = 50
ICMP_FLOOD_WINDOW = 5  # seconds

# --- Blacklisted IPs ---
# Any traffic from/to these IPs is immediately flagged.
BLACKLISTED_IPS = {
    "0.0.0.0",  # replace with real known-bad IPs as needed
}

# --- Known malicious ports (commonly abused / backdoor ports) ---
SUSPICIOUS_PORTS = {31337, 4444, 1337, 6666, 6667}

# --- Logging ---
LOG_FILE = "alerts.log"
ALERT_JSON_FILE = "alerts.json"

# --- Response ---
# If True, the system will call the auto-block hook in response.py
# (by default this only logs a simulated block — see response.py)
AUTO_BLOCK_ENABLED = True
