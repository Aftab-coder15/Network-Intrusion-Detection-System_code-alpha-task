"""
alert.py
Handles formatting, logging, and dispatching of intrusion alerts.
"""

import json
import logging
from datetime import datetime

import config

# Configure a dedicated logger that writes both to console and to file.
logger = logging.getLogger("NIDS")
logger.setLevel(logging.INFO)

_formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")

_file_handler = logging.FileHandler(config.LOG_FILE)
_file_handler.setFormatter(_formatter)

_console_handler = logging.StreamHandler()
_console_handler.setFormatter(_formatter)

if not logger.handlers:
    logger.addHandler(_file_handler)
    logger.addHandler(_console_handler)


def raise_alert(alert_type: str, src_ip: str, details: str, severity: str = "HIGH"):
    """
    Record an intrusion alert: log it, print it, and append it as
    structured JSON so it can be visualized later.
    """
    timestamp = datetime.utcnow().isoformat() + "Z"

    message = f"[{severity}] {alert_type} detected from {src_ip} -> {details}"
    if severity == "HIGH":
        logger.warning(message)
    else:
        logger.info(message)

    record = {
        "timestamp": timestamp,
        "type": alert_type,
        "src_ip": src_ip,
        "details": details,
        "severity": severity,
    }
    _append_json(record)
    return record


def _append_json(record: dict):
    """Append a single alert record to the JSON alert store (one JSON object per line)."""
    with open(config.ALERT_JSON_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")
