"""
visualize_alerts.py
Optional visualization dashboard (Task 4, step 5).
Reads alerts.json (produced by alert.py) and renders charts summarizing
detected attacks: counts by type, and alerts over time.

Usage:
    python3 visualize_alerts.py
"""

import json
from collections import Counter
from datetime import datetime

import matplotlib.pyplot as plt

import config


def load_alerts(path=config.ALERT_JSON_FILE):
    alerts = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    alerts.append(json.loads(line))
    except FileNotFoundError:
        print(f"No alert file found at {path}. Run sniffer.py first "
              f"(try `python3 sniffer.py --demo`).")
    return alerts


def plot_dashboard(alerts):
    if not alerts:
        print("No alerts to visualize.")
        return

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    # --- Chart 1: alerts by type ---
    type_counts = Counter(a["type"] for a in alerts)
    axes[0].bar(type_counts.keys(), type_counts.values(), color="crimson")
    axes[0].set_title("Alerts by Type")
    axes[0].set_ylabel("Count")
    axes[0].tick_params(axis="x", rotation=30)

    # --- Chart 2: alerts over time (binned by minute) ---
    timestamps = [datetime.fromisoformat(a["timestamp"].replace("Z", "")) for a in alerts]
    minute_bins = Counter(ts.strftime("%H:%M") for ts in timestamps)
    sorted_bins = sorted(minute_bins.items())
    axes[1].plot([b[0] for b in sorted_bins], [b[1] for b in sorted_bins],
                 marker="o", color="darkblue")
    axes[1].set_title("Alerts Over Time")
    axes[1].set_ylabel("Alert Count")
    axes[1].tick_params(axis="x", rotation=45)

    plt.tight_layout()
    out_path = "alerts_dashboard.png"
    plt.savefig(out_path)
    print(f"Dashboard saved to {out_path}")
    plt.show()


if __name__ == "__main__":
    plot_dashboard(load_alerts())
