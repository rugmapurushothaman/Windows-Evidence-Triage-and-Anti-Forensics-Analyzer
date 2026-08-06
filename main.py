"""
main.py

Windows Evidence Triage & Anti-Forensics Analyzer
Author: Rugma Purushothaman
Version: 0.1.0
"""

import os


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
    print("----------------------------")
    print(evidence_path)

    print("\nStarting Evidence Collection...")


if __name__ == "__main__":
    main()
