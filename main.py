"""
main.py

Windows Evidence Triage & Anti-Forensics Analyzer

Author: Rugma Purushothaman
Version: 0.6.0
"""

import os

from collectors.filesystem import collect_files
from collectors.registry import collect_installed_programs
from collectors.usb import collect_usb_devices
from collectors.event_logs import collect_security_events
from collectors.browser import collect_browser_artifacts
from collectors.prefetch import collect_prefetch
from collectors.recycle_bin import collect_recycle_bin

from analyzers.timestomp import analyze_timestamps
from analyzers.ads import analyze_ads
from analyzers.suspicious_files import analyze_files
from analyzers.browser_cleanup import analyze_all_browsers

from correlation.timeline import create_timeline
from correlation.timeline import print_timeline

from correlation.risk_engine import correlate_findings
from correlation.risk_engine import print_risk_summary

from utils.logger import get_logger


logger = get_logger("main")


# ==========================================================
# Banner
# ==========================================================

def print_banner():

    print("=" * 70)
    print("Windows Evidence Triage & Anti-Forensics Analyzer")
    print("=" * 70)
    print("Author : Rugma Purushothaman")
    print("Version: 0.6.0")
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
    # FILE SYSTEM COLLECTION
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
    # TIMESTAMP ANALYSIS
    # ======================================================

    print("\n")
    print("=" * 70)
    print("Timestamp Analysis")
    print("=" * 70)

    print("\nRunning Timestamp Analysis...\n")

    suspicious = analyze_timestamps(
        result["files"]
    )

    if len(suspicious) == 0:

        print("No timestamp anomalies detected.")

    else:

        print("=" * 70)
        print("Possible Timestamp Anomalies")
        print("=" * 70)

        print("\nTotal Anomalies :", len(suspicious))

        # Avoid printing thousands of results
        # to the terminal.

        display_limit = 20

        for item in suspicious[:display_limit]:

            print("\n----------------------------------------")

            print("File     :", item["name"])
            print("Path     :", item["path"])
            print("Created  :", item["created"])
            print("Modified :", item["modified"])
            print("Accessed :", item["accessed"])

            print("\nFindings:")

            for finding in item["findings"]:

                print(" -", finding)

        if len(suspicious) > display_limit:

            print("\n...more timestamp anomalies omitted...")

    print("\nTimestamp Analysis Completed.")

    # ======================================================
    # SUSPICIOUS FILE ANALYSIS
    # ======================================================

    print("\n")
    print("=" * 70)
    print("Suspicious File Analysis")
    print("=" * 70)

    print("\nAnalyzing collected files...\n")

    suspicious_files = analyze_files(
        result["files"]
    )

    print(
        "Suspicious File Findings :",
        len(suspicious_files)
    )

    if len(suspicious_files) == 0:

        print("\nNo suspicious file indicators detected.")

    else:

        for item in suspicious_files[:20]:

            print("\n----------------------------------------")

            print("Type       :", item["type"])
            print("Severity   :", item["severity"])
            print("File       :", item.get("file", ""))
            print("Description:", item["description"])

        if len(suspicious_files) > 20:

            print("\n...more suspicious file findings omitted...")

    # ======================================================
    # REGISTRY COLLECTION
    # ======================================================

    print("\n")
    print("=" * 70)
    print("Registry Evidence Collection")
    print("=" * 70)

    print("\nCollecting Installed Program Information...\n")

    programs = collect_installed_programs()

    print(
        "Installed Programs Found :",
        len(programs)
    )

    if len(programs) == 0:

        print("\nNo installed programs detected.")

    else:

        print("\nFirst 20 Installed Programs:\n")

        for program in programs[:20]:

            print(" -", program)

        if len(programs) > 20:

            print("\n...more programs omitted...")

    # ======================================================
    # USB COLLECTION
    # ======================================================

    print("\n")
    print("=" * 70)
    print("USB Device Analysis")
    print("=" * 70)

    print("\nCollecting USB Storage Device Information...\n")

    usb_devices = collect_usb_devices()

    print(
        "USB Devices Found :",
        len(usb_devices)
    )

    if len(usb_devices) == 0:

        print("\nNo USB storage devices found.")

    else:

        for device in usb_devices:

            print("\n----------------------------------------")

            print(
                "Device Name   :",
                device["device_name"]
            )

            print(
                "Serial Number :",
                device["serial_number"]
            )

    # ======================================================
    # SECURITY EVENT LOG COLLECTION
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

        print(
            "Security Event Log collected successfully."
        )

        print(
            "\nFirst portion of collected Security Events:\n"
        )

        print(events[0][:2000])

    # ======================================================
    # ADS ANALYSIS
    # ======================================================

    print("\n")
    print("=" * 70)
    print("Alternate Data Stream Analysis")
    print("=" * 70)

    print(
        "\nScanning files for NTFS Alternate Data Streams...\n"
    )

    ads_findings = analyze_ads(
        result["files"]
    )

    print(
        "ADS Findings :",
        len(ads_findings)
    )

    if len(ads_findings) == 0:

        print(
            "\nNo Alternate Data Streams detected."
        )

    else:

        for item in ads_findings[:20]:

            print("\n----------------------------------------")

            print(
                "File :",
                item["name"]
            )

            print(
                "Path :",
                item["path"]
            )

            print("\nStreams:")

            for stream in item["streams"]:

                print(
                    " - Stream :",
                    stream["stream_name"]
                )

                print(
                    "   Size   :",
                    stream["size_bytes"],
                    "bytes"
                )

        if len(ads_findings) > 20:

            print(
                "\n...more ADS findings omitted..."
            )

    # ======================================================
    # BROWSER COLLECTION
    # ======================================================

    print("\n")
    print("=" * 70)
    print("Browser Artifact Collection")
    print("=" * 70)

    print("\nCollecting browser artifacts...\n")

    browser_results = collect_browser_artifacts()

    print(
        "Browser Sources Checked :",
        len(browser_results)
    )

    for browser in browser_results:

        print("\n----------------------------------------")

        print(
            "Browser       :",
            browser.get("browser", "Unknown")
        )

        print(
            "History Exists:",
            browser.get("history_exists", False)
        )

        print(
            "History Count :",
            browser.get("history_count", 0)
        )

        print(
            "Downloads     :",
            browser.get("download_count", 0)
        )

    # ======================================================
    # BROWSER CLEANUP ANALYSIS
    # ======================================================

    print("\n")
    print("=" * 70)
    print("Browser Cleanup Analysis")
    print("=" * 70)

    browser_findings = analyze_all_browsers(
        browser_results
    )

    print(
        "\nBrowser Cleanup Findings :",
        len(browser_findings)
    )

    for finding in browser_findings:

        print("\n----------------------------------------")

        print(
            "Browser     :",
            finding.get("browser", "Unknown")
        )

        print(
            "Type        :",
            finding.get("type", "UNKNOWN")
        )

        print(
            "Severity    :",
            finding.get("severity", "UNKNOWN")
        )

        print(
            "Description :",
            finding.get("description", "")
        )

    # ======================================================
    # PREFETCH COLLECTION
    # ======================================================

    print("\n")
    print("=" * 70)
    print("Windows Prefetch Collection")
    print("=" * 70)

    print("\nCollecting Prefetch artifacts...\n")

    prefetch_results = collect_prefetch()

    print(
        "Prefetch Files Found :",
        len(prefetch_results)
    )

    for item in prefetch_results[:20]:

        print(
            " -",
            item.get("name", "")
        )

    if len(prefetch_results) > 20:

        print("\n...more Prefetch files omitted...")

    # ======================================================
    # RECYCLE BIN COLLECTION
    # ======================================================

    print("\n")
    print("=" * 70)
    print("Recycle Bin Collection")
    print("=" * 70)

    print("\nCollecting Recycle Bin artifacts...\n")

    recycle_results = collect_recycle_bin()

    print(
        "Recycle Bin Items Found :",
        len(recycle_results)
    )

    for item in recycle_results[:20]:

        print(
            " -",
            item.get("name", "")
        )

    if len(recycle_results) > 20:

        print(
            "\n...more Recycle Bin items omitted..."
        )

    # ======================================================
    # CORRELATION - PREPARE FINDINGS
    # ======================================================

    print("\n")
    print("=" * 70)
    print("Evidence Correlation")
    print("=" * 70)

    print("\nCorrelating forensic findings...\n")

    all_findings = []

    # ------------------------------------------------------
    # Suspicious file findings
    # ------------------------------------------------------

    all_findings.extend(
        suspicious_files
    )

    # ------------------------------------------------------
    # Browser findings
    # ------------------------------------------------------

    all_findings.extend(
        browser_findings
    )

    # ------------------------------------------------------
    # Timestamp findings
    # ------------------------------------------------------

    for item in suspicious:

        all_findings.append({
            "type": "TIMESTAMP_ANOMALY",
            "severity": "HIGH",
            "file": item.get(
                "path",
                ""
            ),
            "description":
                "Possible timestamp anomaly detected."
        })

    # ------------------------------------------------------
    # ADS findings
    # ------------------------------------------------------

    for item in ads_findings:

        all_findings.append({
            "type": "ALTERNATE_DATA_STREAM",
            "severity": "MEDIUM",
            "file": item.get(
                "path",
                ""
            ),
            "description":
                "NTFS Alternate Data Stream detected."
        })

    # ------------------------------------------------------
    # Security event findings
    # ------------------------------------------------------

    if len(events) > 0:

        all_findings.append({
            "type": "SECURITY_EVENTS_COLLECTED",
            "severity": "LOW",
            "description":
                "Security event log data was successfully collected."
        })

    # ======================================================
    # RISK ENGINE
    # ======================================================

    risk_result = correlate_findings(
        all_findings
    )

    print_risk_summary(
        risk_result
    )

    # ======================================================
    # TIMELINE
    # ======================================================

    timeline_events = []

    # Add suspicious files
    for item in suspicious_files:

        timeline_events.append({
            "type": item.get(
                "type",
                "SUSPICIOUS_FILE"
            ),
            "description": item.get(
                "description",
                ""
            ),
            "path": item.get(
                "file",
                ""
            ),
            "severity": item.get(
                "severity",
                "UNKNOWN"
            ),
            "source": "File System"
        })

    # Add timestamp anomalies
    for item in suspicious:

        timeline_events.append({
            "type": "TIMESTAMP_ANOMALY",
            "description":
                "Possible timestamp anomaly",
            "path": item.get(
                "path",
                ""
            ),
            "severity": "HIGH",
            "source": "Timestamp Analyzer"
        })

    # Add ADS
    for item in ads_findings:

        timeline_events.append({
            "type": "ALTERNATE_DATA_STREAM",
            "description":
                "NTFS Alternate Data Stream detected",
            "path": item.get(
                "path",
                ""
            ),
            "severity": "MEDIUM",
            "source": "ADS Analyzer"
        })

    # Create timeline
    timeline = create_timeline(
        timeline_events
    )

    print_timeline(
        timeline
    )

    # ======================================================
    # FINAL INVESTIGATION SUMMARY
    # ======================================================

    print("\n")
    print("=" * 70)
    print("Investigation Summary")
    print("=" * 70)

    print("\nEvidence Path :", evidence_path)

    print(
        "Folders       :",
        result["folder_count"]
    )

    print(
        "Files         :",
        result["file_count"]
    )

    print(
        "Timestamp Anomalies :",
        len(suspicious)
    )

    print(
        "Installed Programs  :",
        len(programs)
    )

    print(
        "USB Devices         :",
        len(usb_devices)
    )

    print(
        "ADS Findings        :",
        len(ads_findings)
    )

    print(
        "Browser Findings    :",
        len(browser_findings)
    )

    print(
        "Prefetch Files      :",
        len(prefetch_results)
    )

    print(
        "Recycle Bin Items   :",
        len(recycle_results)
    )

    print(
        "Total Correlated Findings :",
        len(all_findings)
    )

    print(
        "Risk Level          :",
        risk_result["risk"]
    )

    print(
        "Risk Score          :",
        risk_result["score"]
    )

    print("\n")
    print("=" * 70)
    print(
        "Investigation Completed Successfully."
    )
    print("=" * 70)


# ==========================================================
# Program Entry Point
# ==========================================================

if __name__ == "__main__":

    main()
