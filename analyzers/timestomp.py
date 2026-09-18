"""
timestomp.py

Windows Evidence Triage & Anti-Forensics Analyzer

Timestamp Anomaly Analyzer

Author: Rugma Purushothaman

Purpose:
--------
Identify files with potentially unusual filesystem timestamps.

Important:
-----------
A timestamp anomaly is an indicator for further investigation.
It is NOT by itself proof of timestomping or malicious activity.
"""

from datetime import datetime


def parse_time(value):

    if isinstance(value, datetime):
        return value

    try:
        return datetime.strptime(
            value,
            "%Y-%m-%d %H:%M:%S"
        )

    except (TypeError, ValueError):

        return None


def analyze_timestamps(files):

    findings = []

    for file_info in files:

        created = parse_time(
            file_info.get("created_time")
        )

        modified = parse_time(
            file_info.get("modified_time")
        )

        accessed = parse_time(
            file_info.get("accessed_time")
        )

        if created is None or modified is None:

            continue

        file_findings = []

        # --------------------------------------------------
        # Check 1: Modified before Created
        # --------------------------------------------------

        if modified < created:

            file_findings.append(
                "Modified time is earlier than Created time"
            )

        # --------------------------------------------------
        # Check 2: Accessed significantly before Created
        # --------------------------------------------------

        if accessed is not None:

            if accessed < created:

                file_findings.append(
                    "Accessed time is earlier than Created time"
                )

        # --------------------------------------------------
        # Only return files with findings
        # --------------------------------------------------

        if len(file_findings) > 0:

            findings.append({

                "name": file_info.get("name"),

                "path": file_info.get("path"),

                "created": file_info.get(
                    "created_time"
                ),

                "modified": file_info.get(
                    "modified_time"
                ),

                "accessed": file_info.get(
                    "accessed_time"
                ),

                "findings": file_findings

            })

    return findings
