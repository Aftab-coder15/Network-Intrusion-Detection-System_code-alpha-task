"""
detector.py
Rule engine that inspects packets and decides whether they represent
suspicious / malicious activity (Task 4, steps 2-3).
"""

import time
from collections import defaultdict, deque

import config
from alert import raise_alert
from response import block_ip


class IntrusionDetector:
    def __init__(self):
        # src_ip -> deque[(timestamp, dst_port)] for port-scan detection
        self._port_touches = defaultdict(deque)
        # src_ip -> deque[timestamp] for SYN flood detection
        self._syn_times = defaultdict(deque)
        # src_ip -> deque[timestamp] for ICMP flood detection
        self._icmp_times = defaultdict(deque)

        self.stats = defaultdict(int)  # running counters, e.g. alerts by type

    # ---------- helpers ----------
    @staticmethod
    def _trim(dq: deque, window: float, now: float):
        while dq and now - dq[0][0] > window:
            dq.popleft()

    # ---------- rule checks ----------
    def check_blacklist(self, src_ip, dst_ip):
        if src_ip in config.BLACKLISTED_IPS or dst_ip in config.BLACKLISTED_IPS:
            self._fire("Blacklisted IP Traffic", src_ip, f"dst={dst_ip}")

    def check_suspicious_port(self, src_ip, dst_port):
        if dst_port in config.SUSPICIOUS_PORTS:
            self._fire("Suspicious Port Access", src_ip,
                        f"dst_port={dst_port}", severity="MEDIUM")

    def check_port_scan(self, src_ip, dst_port):
        now = time.time()
        dq = self._port_touches[src_ip]
        dq.append((now, dst_port))
        # trim old entries outside the time window
        while dq and now - dq[0][0] > config.PORT_SCAN_WINDOW:
            dq.popleft()

        distinct_ports = {p for _, p in dq}
        if len(distinct_ports) >= config.PORT_SCAN_THRESHOLD:
            self._fire("Port Scan", src_ip,
                        f"{len(distinct_ports)} distinct ports in "
                        f"{config.PORT_SCAN_WINDOW}s")
            dq.clear()  # avoid repeated re-firing on same burst

    def check_syn_flood(self, src_ip, is_syn):
        if not is_syn:
            return
        now = time.time()
        dq = self._syn_times[src_ip]
        dq.append((now, None))
        while dq and now - dq[0][0] > config.SYN_FLOOD_WINDOW:
            dq.popleft()

        if len(dq) >= config.SYN_FLOOD_THRESHOLD:
            self._fire("SYN Flood", src_ip,
                        f"{len(dq)} SYN packets in {config.SYN_FLOOD_WINDOW}s")
            dq.clear()

    def check_icmp_flood(self, src_ip):
        now = time.time()
        dq = self._icmp_times[src_ip]
        dq.append((now, None))
        while dq and now - dq[0][0] > config.ICMP_FLOOD_WINDOW:
            dq.popleft()

        if len(dq) >= config.ICMP_FLOOD_THRESHOLD:
            self._fire("ICMP Flood (Ping Flood)", src_ip,
                        f"{len(dq)} ICMP echo requests in "
                        f"{config.ICMP_FLOOD_WINDOW}s")
            dq.clear()

    # ---------- internal ----------
    def _fire(self, alert_type, src_ip, details, severity="HIGH"):
        raise_alert(alert_type, src_ip, details, severity)
        self.stats[alert_type] += 1
        if config.AUTO_BLOCK_ENABLED and severity == "HIGH":
            block_ip(src_ip, reason=alert_type)
