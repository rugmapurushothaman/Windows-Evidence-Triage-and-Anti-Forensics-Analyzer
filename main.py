"""
main.py

Windows Evidence Triage & Anti-Forensics Analyzer

Author: Rugma Purushothaman
Version: 0.4.0
"""

import os

from collectors.filesystem import collect_files
from collectors.registry import collect_installed_programs
from collectors.usb import collect_usb_devices
from collectors.event_logs import collect_security_events
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

    print("\nCollecting File System Evidence...\n")

    result = collect_files(evidence_path)

    print("=" * 70)
    print("Collection Summary")
    print("=" * 70)

    print("Folders :", result["folder_count"])
    print("Files   :", result["file_count"])

    # ======================================================
    # Timestamp Analysis
    # ======================================================

    print("\nRunning Timestamp Analysis...\n")

    suspicious = analyze_timestamps(result["files"])

    if len(suspicious) == 0:

        print("No timestamp anomalies detected.")

    else:

        print("=" * 70)
        print("Possible Timestamp Anomalies")
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

    print("\nTimestamp Analysis Completed.")

    # ======================================================
    # Registry Collection
    # ======================================================

    print("\n")
    print("=" * 70)
    print("Registry Evidence Collection")
    print("=" * 70)

    programs = collect_installed_programs()

    print(f"\nInstalled Programs Found : {len(programs)}\n")

    if len(programs) == 0:

        print("No installed programs detected.")

    else:

        for program in programs[:20]:
            print(program)

        if len(programs) > 20:
            print("\n...more programs omitted...")

    # ======================================================
    # USB Device Collection
    # ======================================================

    print("\n")
    print("=" * 70)
    print("USB Device Analysis")
    print("=" * 70)

    usb_devices = collect_usb_devices()

    print(f"\nUSB Devices Found : {len(usb_devices)}\n")

    if len(usb_devices) == 0:

        print("No USB storage devices found.")

    else:

        for device in usb_devices:

            print("----------------------------------------")
            print("Device Name   :", device["device_name"])
            print("Serial Number :", device["serial_number"])

    # ======================================================
    # Event Log Collection
    # ======================================================

    print("\n")
    print("=" * 70)
    print("Security Event Log Collection")
    print("=" * 70)

    events = collect_security_events()

    if len(events) == 0:

        print("No Security Events Collected.")

    else:

        print(events[0][:2000])

    # ======================================================

    print("\nInvestigation Completed Successfully.")


if __name__ == "__main__":
    main()
