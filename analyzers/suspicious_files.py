# analyzers/suspicious_files.py

import os

from utils.constants import SUSPICIOUS_EXTENSIONS
from utils.constants import SUSPICIOUS_DIRECTORIES
from utils.helpers import get_file_extension
from utils.helpers import safe_get
from utils.logger import get_logger


logger = get_logger("suspicious_files")


def analyze_file(file_info):
    """
    Analyze one file dictionary.

    Expected structure:

    {
        "name": "...",
        "path": "...",
        "extension": "...",
        "size_bytes": 123,
        "created_time": "...",
        "modified_time": "...",
        "accessed_time": "...",
        "is_hidden": False
    }
    """

    findings = []

    if not isinstance(file_info, dict):
        return findings

    path = safe_get(file_info, "path", "")
    name = safe_get(file_info, "name", "")

    if not path:
        return findings

    extension = safe_get(
        file_info,
        "extension",
        get_file_extension(path)
    )

    extension = extension.lower()

    # Suspicious extension
    if extension in SUSPICIOUS_EXTENSIONS:

        findings.append({
            "type": "SUSPICIOUS_EXTENSION",
            "severity": "MEDIUM",
            "file": path,
            "description":
                "Executable or script file found during triage."
        })

    # Hidden file
    if safe_get(file_info, "is_hidden", False):

        findings.append({
            "type": "HIDDEN_FILE",
            "severity": "MEDIUM",
            "file": path,
            "description":
                "File has the Windows hidden attribute."
        })

    # Suspicious directory
    normalized_path = path.lower()

    for directory in SUSPICIOUS_DIRECTORIES:

        if directory.lower() in normalized_path:

            findings.append({
                "type": "SUSPICIOUS_LOCATION",
                "severity": "MEDIUM",
                "file": path,
                "description":
                    "File located in a directory commonly requiring "
                    "additional investigation."
            })

            break

    # Double extension
    if name.count(".") >= 2:

        findings.append({
            "type": "DOUBLE_EXTENSION",
            "severity": "HIGH",
            "file": path,
            "description":
                "File contains multiple extensions and should be reviewed."
        })

    # Timestamp anomaly
    created = safe_get(file_info, "created_time")
    modified = safe_get(file_info, "modified_time")

    if created and modified:

        try:
            if modified < created:

                findings.append({
                    "type": "TIMESTAMP_ANOMALY",
                    "severity": "HIGH",
                    "file": path,
                    "description":
                        "Modified timestamp appears earlier than "
                        "created timestamp."
                })

        except Exception:
            pass

    return findings


def analyze_files(file_list):
    """
    Analyze a list of collected files.
    """

    all_findings = []

    if not file_list:
        return all_findings

    for file_info in file_list:

        try:
            findings = analyze_file(file_info)
            all_findings.extend(findings)

        except Exception as error:

            logger.error(
                "Error analyzing file: %s",
                error
            )

    return all_findings
