"""
timestomp.py

Timestamp Analyzer

Detects possible timestamp manipulation.
"""

from datetime import datetime


def analyze_timestamps(files):

    suspicious_files = []

    for file in files:

        try:

            created = datetime.strptime(
                file["created_time"],
                "%Y-%m-%d %H:%M:%S"
            )

            modified = datetime.strptime(
                file["modified_time"],
                "%Y-%m-%d %H:%M:%S"
            )

            accessed = datetime.strptime(
                file["accessed_time"],
                "%Y-%m-%d %H:%M:%S"
            )

            findings = []

            # Modified earlier than created
            if modified < created:
                findings.append(
                    "Modified time is earlier than Created time"
                )

            # Accessed earlier than created
            if accessed < created:
                findings.append(
                    "Accessed time is earlier than Created time"
                )

            # Future timestamps
            now = datetime.now()

            if created > now:
                findings.append("Created time is in the future")

            if modified > now:
                findings.append("Modified time is in the future")

            if accessed > now:
                findings.append("Accessed time is in the future")

            if findings:

                suspicious_files.append({

                    "name": file["name"],

                    "path": file["path"],

                    "created": file["created_time"],

                    "modified": file["modified_time"],

                    "accessed": file["accessed_time"],

                    "findings": findings

                })

        except Exception:

            continue

    return suspicious_files
