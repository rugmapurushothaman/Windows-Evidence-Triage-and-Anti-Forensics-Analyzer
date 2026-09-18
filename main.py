"""
main.py

Windows Evidence Triage & Anti-Forensics Analyzer

Author: Rugma Purushothaman
Version: 0.5.0
"""

import os

from collectors.filesystem import collect_files
from collectors.registry import collect_installed_programs
from collectors.usb import collect_usb_devices
from collectors.event_logs import collect_security_events

from analyzers.timestomp import analyze_timestamps
from analyzers.ads import analyze_ads


# ==========================================================
# Banner
# ==========================================================

def print_banner():

    print("=" * 70)
    print("Windows Evidence Triage & Anti-Forensics Analyzer")
    print("=" * 70)
    print("Author : Rugma Purushothaman")
    print("Version: 0.5.0")
    print("=" * 70)


# ==========================================================
# Evidence Path
# ==========================================================

def get_evidence_path():

    while True:

        path = input("\nEnter Evidence Folder: ").strip()

        if os.path.exists(path):

            return path

        print("\nInvalid path. Try again.")


# ==========================================================
# Main Investigation
# ==========================================================

def main():

    print_banner()

    # ------------------------------------------------------
    # Evidence Location
    # ------------------------------------------------------

    evidence_path = get_evidence_path()

    print("\nEvidence Folder:")
    print(evidence_path)

    # ======================================================
    # File System Evidence Collection
    # ======================================================

    print("\n")
    print("=" * 70)
    print("File System Evidence Collection")
    print("=" * 70)

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

    print("\n")
    print("=" * 70)
    print("Timestamp Analysis")
    print("=" * 70)

    print("\nRunning Timestamp Analysis...\n")

    suspicious = analyze_timestamps(result["files"])

    if len(suspicious) == 0:

        print("No timestamp anomalies detected.")

    else:

        print("=" * 70)
        print("Possible Timestamp Anomalies")
        print("=" * 70)

        print("\nTotal Anomalies :", len(suspicious))

        for item in suspicious:

            print("\n----------------------------------------")

            print("File     :", item["name"])
            print("Path     :", item["path"])
            print("Created  :", item["created"])
            print("Modified :", item["modified"])
            print("Accessed :", item["accessed"])

            print("\nFindings:")

            for finding in item["findings"]:

                print(" -", finding)

    print("\nTimestamp Analysis Completed.")

    # ======================================================
    # Registry Evidence Collection
    # ======================================================

    print("\n")
    print("=" * 70)
    print("Registry Evidence Collection")
    print("=" * 70)

    print("\nCollecting Installed Program Information...\n")

    programs = collect_installed_programs()

    print("Installed Programs Found :", len(programs))

    if len(programs) == 0:

        print("\nNo installed programs detected.")

    else:

        print("\nFirst 20 Installed Programs:\n")

        for program in programs[:20]:

            print(" -", program)

        if len(programs) > 20:

            print("\n...more programs omitted...")

    # ======================================================
    # USB Device Collection
    # ======================================================

    print("\n")
    print("=" * 70)
    print("USB Device Analysis")
    print("=" * 70)

    print("\nCollecting USB Storage Device Information...\n")

    usb_devices = collect_usb_devices()

    print("USB Devices Found :", len(usb_devices))

    if len(usb_devices) == 0:

        print("\nNo USB storage devices found.")

    else:

        for device in usb_devices:

            print("\n----------------------------------------")

            print("Device Name   :", device["device_name"])
            print("Serial Number :", device["serial_number"])

    # ======================================================
    # Security Event Log Collection
    # ======================================================

    print("\n")
    print("=" * 70)
    print("Security Event Log Collection")
    print("=" * 70)

    print("\nCollecting Security Event Logs...\n")

    events = collect_security_events()

    if len(events) == 0:

        print("No Security Events Collected.")

    else:

        print("Security Event Log collected successfully.")

        print("\nFirst portion of collected Security Events:\n")

        print(events[0][:2000])

    # ======================================================
    # Alternate Data Stream Analysis
    # ======================================================

    print("\n")
    print("=" * 70)
    print("Alternate Data Stream Analysis")
    print("=" * 70)

    print("\nScanning files for NTFS Alternate Data Streams...\n")

    ads_findings = analyze_ads(result["files"])

    print("ADS Findings :", len(ads_findings))

    if len(ads_findings) == 0:

        print("\nNo Alternate Data Streams detected.")

    else:

        for item in ads_findings:

            print("\n----------------------------------------")

            print("File :", item["name"])
            print("Path :", item["path"])

            print("\nStreams:")

            for stream in item["streams"]:

                print(" - Stream :", stream["stream_name"])
                print("   Size   :", stream["size_bytes"], "bytes")

    # ======================================================
    # Investigation Summary
    # ======================================================

    print("\n")
    print("=" * 70)
    print("Investigation Summary")
    print("=" * 70)

    print("\nEvidence Path :", evidence_path)

    print("Folders       :", result["folder_count"])
    print("Files         :", result["file_count"])

    print("Timestamp Anomalies :", len(suspicious))

    print("Installed Programs  :", len(programs))

    print("USB Devices         :", len(usb_devices))

    print("ADS Findings        :", len(ads_findings))

    print("\n")
    print("=" * 70)
    print("Investigation Completed Successfully.")
    print("=" * 70)


# ==========================================================
# Program Entry Point
# ==========================================================

if __name__ == "__main__":

    main()
