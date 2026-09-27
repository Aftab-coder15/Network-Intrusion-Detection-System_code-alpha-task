"""
response.py
Implements response mechanisms for detected intrusions (Task 4, step 4).

By default this performs a SAFE, SIMULATED block (it only logs the action).
To perform a real block on Linux using iptables, set REAL_BLOCK = True below
and run the script with sufficient privileges. Use real blocking only on
systems/networks you own or are authorized to manage.
"""

import subprocess
import platform

from alert import logger

REAL_BLOCK = False  # flip to True to actually block IPs via iptables (Linux only)

_blocked_ips = set()


def block_ip(ip: str, reason: str = ""):
    """
    Respond to a detected intrusion by blocking the offending IP.
    Simulated by default; can be switched to a real iptables block on Linux.
    """
    if ip in _blocked_ips:
        return  # already handled

    _blocked_ips.add(ip)

    if not REAL_BLOCK:
        logger.warning(f"[RESPONSE] Simulated block of {ip} ({reason})")
        return

    if platform.system() != "Linux":
        logger.warning(f"[RESPONSE] Real blocking only supported on Linux. "
                        f"Would have blocked {ip} ({reason})")
        return

    try:
        subprocess.run(
            ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            check=True,
        )
        logger.warning(f"[RESPONSE] Blocked {ip} via iptables ({reason})")
    except Exception as e:
        logger.error(f"[RESPONSE] Failed to block {ip}: {e}")


def unblock_all():
    """Utility to clear all simulated/real blocks (for testing)."""
    for ip in list(_blocked_ips):
        if REAL_BLOCK and platform.system() == "Linux":
            subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
    _blocked_ips.clear()
