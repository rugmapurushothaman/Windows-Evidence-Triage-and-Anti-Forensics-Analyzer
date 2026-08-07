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
            universal_newlines=True,
            stderr=subprocess.STDOUT
        )

        events.append(output)

    except subprocess.CalledProcessError as error:

        events.append(error.output)

    except Exception as error:

        events.append(str(error))

    return events
