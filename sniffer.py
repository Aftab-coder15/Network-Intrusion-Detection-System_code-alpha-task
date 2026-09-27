"""
sniffer.py
Main entry point for the Network Intrusion Detection System.

Captures live traffic (or reads a .pcap file for offline testing),
runs each packet through the rule engine, and continuously monitors
for suspicious activity (Task 4, steps 1 and 3).

Usage:
    sudo python3 sniffer.py                # live capture
    python3 sniffer.py --pcap sample.pcap  # offline test on a capture file
    python3 sniffer.py --demo              # generate synthetic traffic, no admin needed
"""

import argparse

from scapy.all import sniff, rdpcap, IP, TCP, ICMP

import config
from detector import IntrusionDetector
from alert import logger

detector = IntrusionDetector()


def process_packet(pkt):
    if IP not in pkt:
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst

    detector.check_blacklist(src_ip, dst_ip)

    if TCP in pkt:
        dst_port = pkt[TCP].dport
        flags = pkt[TCP].flags
        is_syn = flags == "S"  # SYN set, ACK not set -> connection attempt

        detector.check_suspicious_port(src_ip, dst_port)
        detector.check_port_scan(src_ip, dst_port)
        detector.check_syn_flood(src_ip, is_syn)

    elif ICMP in pkt:
        if int(pkt[ICMP].type) == 8:  # echo-request
            detector.check_icmp_flood(src_ip)


def run_live_capture():
    logger.info(f"Starting live capture on interface: "
                f"{config.INTERFACE or 'default'}")
    logger.info("Press Ctrl+C to stop.")
    sniff(iface=config.INTERFACE, prn=process_packet, store=False)


def run_pcap(path):
    logger.info(f"Reading packets from {path} ...")
    packets = rdpcap(path)
    for pkt in packets:
        process_packet(pkt)
    _print_summary()


def run_demo():
    """
    Generates synthetic packets in-process (no NIC access / root needed)
    so the detection logic can be demonstrated and unit-tested anywhere,
    e.g. in CI or on a machine without packet-capture permissions.
    """
    from scapy.all import Ether
    logger.info("Running synthetic demo traffic through the detector...")

    attacker = "10.0.0.99"
    victim = "10.0.0.5"

    # Simulate a port scan: many distinct ports from the same source
    for port in range(2000, 2000 + config.PORT_SCAN_THRESHOLD + 2):
        pkt = IP(src=attacker, dst=victim) / TCP(dport=port, flags="S")
        process_packet(pkt)

    # Simulate a SYN flood
    for _ in range(config.SYN_FLOOD_THRESHOLD + 5):
        pkt = IP(src=attacker, dst=victim) / TCP(dport=80, flags="S")
        process_packet(pkt)

    # Simulate an ICMP flood
    for _ in range(config.ICMP_FLOOD_THRESHOLD + 5):
        pkt = IP(src=attacker, dst=victim) / ICMP(type=8)
        process_packet(pkt)

    _print_summary()


def _print_summary():
    logger.info("---- Detection summary ----")
    if not detector.stats:
        logger.info("No intrusions detected.")
    for alert_type, count in detector.stats.items():
        logger.info(f"{alert_type}: {count} time(s)")


def main():
    parser = argparse.ArgumentParser(description="Simple Network Intrusion Detection System")
    parser.add_argument("--pcap", help="Path to a .pcap file to analyze offline")
    parser.add_argument("--demo", action="store_true",
                         help="Run against synthetic traffic (no root/NIC needed)")
    args = parser.parse_args()

    if args.demo:
        run_demo()
    elif args.pcap:
        run_pcap(args.pcap)
    else:
        run_live_capture()


if __name__ == "__main__":
    main()
