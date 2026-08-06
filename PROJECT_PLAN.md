# Windows Evidence Triage & Anti-Forensics Analyzer

## Project Overview

The Windows Evidence Triage & Anti-Forensics Analyzer is a Python-based Digital Forensics and Incident Response (DFIR) toolkit designed to automate the collection, analysis, and correlation of Windows forensic artifacts.

The toolkit assists investigators by rapidly identifying suspicious activities, highlighting potential anti-forensic behavior, generating investigation timelines, and producing structured reports to support digital forensic investigations.

---

# Problem Statement

Modern digital forensic investigations often involve analyzing thousands of files and multiple Windows artifacts manually. While forensic acquisition tools such as FTK Imager preserve and preview digital evidence, investigators must still examine numerous artifacts to identify suspicious activity.

This project aims to reduce manual effort by automatically collecting forensic artifacts, correlating evidence from multiple sources, and highlighting activities that may indicate anti-forensic techniques.

---

# Objectives

- Automate Windows evidence triage.
- Collect forensic artifacts from multiple Windows sources.
- Detect suspicious and potential anti-forensic activities.
- Correlate evidence into an investigation timeline.
- Calculate an overall investigation risk score.
- Generate investigator-ready reports.

---

# Target Users

- Digital Forensic Investigators
- DFIR Analysts
- SOC Analysts
- Incident Response Teams
- Cyber Crime Investigation Units
- Students learning Digital Forensics

---

# Workflow

Investigator Selects Evidence

↓

Evidence Collection

↓

Artifact Analysis

↓

Evidence Correlation

↓

Risk Assessment

↓

Investigation Report

---

# Project Architecture

```
               Investigator
                    │
                    ▼
        Select Evidence Folder
                    │
                    ▼
      +----------------------------+
      | Evidence Collection        |
      +----------------------------+
                    │
      ┌─────────────┼─────────────┐
      ▼             ▼             ▼
 Event Logs    Registry      File System
      ▼             ▼             ▼
 Browser      USB History    Prefetch
                    │
                    ▼
      +----------------------------+
      | Artifact Analysis          |
      +----------------------------+
                    │
                    ▼
      +----------------------------+
      | Correlation Engine         |
      +----------------------------+
                    │
                    ▼
      +----------------------------+
      | Risk Assessment            |
      +----------------------------+
                    │
                    ▼
      +----------------------------+
      | Investigation Report       |
      +----------------------------+
```

---

# Evidence Sources

The toolkit will collect forensic artifacts from:

- Windows Event Logs
- Windows Registry
- File System Metadata
- Alternate Data Streams (ADS)
- USB Device History
- Windows Prefetch
- Browser Artifacts
- Recycle Bin
- Recent Files
- User Profiles

---

# Analysis Modules

The toolkit will analyze evidence for:

- Hidden Files
- Timestamp Anomalies
- Alternate Data Streams
- Event Log Clearing
- Suspicious Executables
- Browser Cleanup Indicators
- File Deletion Activity
- USB Device Usage
- Registry Persistence (Future Version)

---

# Correlation Engine

Instead of reporting artifacts individually, the toolkit correlates events from multiple sources to build an investigation timeline.

Example:

14:10 USB Connected

↓

14:12 PowerShell Executed

↓

14:15 Security Log Cleared

↓

14:16 Browser History Deleted

↓

14:17 Recycle Bin Emptied

---

# Risk Assessment

Each suspicious finding contributes to an overall investigation risk score.

Risk Levels

- Low
- Medium
- High
- Critical

---

# Report Output

The toolkit will generate:

- Executive Summary
- Investigation Timeline
- Suspicious Findings
- Risk Assessment
- Recommendations

---


# Technologies

- Python
- Windows Forensics
- DFIR
- Event Log Analysis
- Registry Analysis
- HTML Reporting
- Git & GitHub

---

# Future Enhancements

- Support for forensic image analysis (E01/RAW via mounted evidence)
- Timeline visualization
- YARA integration
- Sigma rule mapping
- Automatic MITRE ATT&CK technique mapping
- JSON and PDF report export
- Multi-case evidence comparison

---

# License

This project is intended for educational, research, and digital forensic investigation purposes.
