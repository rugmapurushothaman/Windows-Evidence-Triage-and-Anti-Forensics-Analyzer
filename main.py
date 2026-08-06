"""
main.py

Windows Evidence Triage & Anti-Forensics Analyzer

Author: Rugma Purushothaman
"""

import os

from collectors.filesystem import collect_files
from analyzers.timestomp import analyze_timestamps


def print_banner():

    print("=" * 70)
    print("Windows Evidence Triage & Anti-Forensics Analyzer")
    print("=" * 70)


def get_evidence_path():

    while True:

        path = input("\nEnter Evidence Folder: ").strip()

        if os.path.exists(path):
            return path

        print("Invalid path. Try again.")


def main():

    print_banner()

    evidence_path = get_evidence_path()

    print("\nCollecting Evidence...\n")

    result = collect_files(evidence_path)

    print("=" * 70)
    print("Collection Summary")
    print("=" * 70)

    print("Folders :", result["folder_count"])
    print("Files   :", result["file_count"])

    print("\nRunning Timestamp Analysis...\n")

    suspicious = analyze_timestamps(result["files"])

    if len(suspicious) == 0:

        print("No timestamp anomalies detected.")

    else:

        print("=" * 70)
        print("Possible Timestamp Manipulation")
        print("=" * 70)

        for item in suspicious:

            print("\n----------------------------------------")

            print("File :", item["name"])

            print("Path :", item["path"])

            print("Created :", item["created"])

            print("Modified :", item["modified"])

            print("Accessed :", item["accessed"])

            print("\nFindings:")

            for finding in item["findings"]:
                print(" -", finding)

    print("\nAnalysis Completed.")


if __name__ == "__main__":
    main()
