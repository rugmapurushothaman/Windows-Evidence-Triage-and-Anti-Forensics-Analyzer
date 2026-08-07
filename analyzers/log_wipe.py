"""
log_wipe.py

Analyze Security Event Logs for important forensic events.
"""


def analyze_security_events(event_text):

    findings = []

    event_map = {
        "1102": {
            "name": "Security Log Cleared",
            "severity": "HIGH"
        },
        "4624": {
            "name": "Successful Logon",
            "severity": "INFO"
        },
        "4625": {
            "name": "Failed Logon",
            "severity": "MEDIUM"
        },
        "4720": {
            "name": "User Account Created",
            "severity": "HIGH"
        },
        "5379": {
            "name": "Credential Manager Access",
            "severity": "LOW"
        }
    }

    for event_id, details in event_map.items():

        if f"Event ID: {event_id}" in event_text:

            findings.append({
                "event_id": event_id,
                "name": details["name"],
                "severity": details["severity"]
            })

    return findings
