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

    # Collect file system metadata
    result = collect_files(evidence_path)

    print("=" * 70)
    print("Evidence Collection Summary")
    print("=" * 70)

    print(f"Folders Found : {result['folder_count']}")
    print(f"Files Found   : {result['file_count']}")

    print("\nShowing First 5 Files Collected\n")

    for file in result["files"][:5]:

        print("-" * 70)
        print(f"Name        : {file['name']}")
        print(f"Path        : {file['path']}")
        print(f"Extension   : {file['extension']}")
        print(f"Size        : {file['size_bytes']} bytes")
        print(f"Created     : {file['created_time']}")
        print(f"Modified    : {file['modified_time']}")
        print(f"Accessed    : {file['accessed_time']}")
        print(f"Hidden      : {file['is_hidden']}")

    print("\nEvidence Collection Completed Successfully.")


if __name__ == "__main__":
    main()
