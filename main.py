"""
main.py

Windows Evidence Triage & Anti-Forensics Analyzer

Author: Rugma Purushothaman
Version: 0.1.0
"""

import os
from collectors.filesystem import collect_files


def print_banner():
    print("=" * 70)
    print("     Windows Evidence Triage & Anti-Forensics Analyzer")
    print("=" * 70)


def get_evidence_path():
    while True:
        path = input("\nEnter the evidence folder path: ").strip()

        if os.path.exists(path):
            return path

        print("\n[ERROR] Invalid folder path. Please try again.")


def main():

    print_banner()

    evidence_path = get_evidence_path()

    print("\nEvidence Selected")
    print("-" * 70)
    print(evidence_path)

    print("\nStarting Evidence Collection...\n")

    # Collect metadata
    result = collect_files(evidence_path)

    print("=" * 70)
    print("Evidence Collection Summary")
    print("=" * 70)

    print(f"Folders Found : {result['folder_count']}")
    print(f"Files Found   : {result['file_count']}")

    print("\nDEBUG INFORMATION")
    print("=" * 70)

    print("Type of result        :", type(result))
    print("Type of result['files']:", type(result["files"]))

    if len(result["files"]) > 0:

        print("Type of first item    :", type(result["files"][0]))

        print("\nFirst item:")
        print(result["files"][0])

    else:

        print("No files collected.")

    print("\nEvidence Collection Completed Successfully.")


if __name__ == "__main__":
    main()
