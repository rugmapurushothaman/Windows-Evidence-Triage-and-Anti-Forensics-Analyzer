"""
event_logs.py

Windows Evidence Triage & Anti-Forensics Analyzer

Event Log Collector

Author: Rugma Purushothaman
"""

import subprocess


def collect_security_events():

    events = []

    command = [
        "wevtutil",
        "qe",
        "Security",
        "/c:50",
        "/rd:true",
        "/f:text"
    ]

    try:

        output = subprocess.check_output(
            command,
            text=True,
            errors="ignore"
        )

        events.append(output)

    except Exception as error:

        events.append(f"Error reading Security log: {error}")

    return events
