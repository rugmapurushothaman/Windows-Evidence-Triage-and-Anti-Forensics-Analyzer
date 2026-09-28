"""
main.py

Windows Evidence Triage & Anti-Forensics Analyzer

Author: Rugma Purushothaman

Purpose:
    Graphical interface for Windows forensic triage.

    This file controls the existing forensic collectors and analyzers.
    The existing collector/analyzer files are preserved and will be
    corrected individually later.
"""

import os
import threading
import traceback
import tkinter as tk

from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox


# ==========================================================
# EXISTING FORENSIC MODULES
# ==========================================================

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

from utils.logger import get_logger


logger = get_logger("main")


# ==========================================================
# APPLICATION
# ==========================================================

class ForensicApplication(object):

    def __init__(self, root):

        self.root = root

        self.root.title(
            "Windows Evidence Triage & Anti-Forensics Analyzer"
        )

        self.root.geometry("1350x800")

        self.root.minsize(1100, 650)

        # --------------------------------------------------
        # Investigation data
        # --------------------------------------------------

        self.evidence_path = ""

        self.filesystem_result = {}
        self.timestamp_findings = []
        self.suspicious_files = []
        self.programs = []
        self.usb_devices = []
        self.events = []
        self.ads_findings = []
        self.browser_results = []
        self.browser_findings = []
        self.prefetch_results = []
        self.recycle_results = []

        self.all_findings = []
        self.timeline = []

        self.investigation_running = False

        # --------------------------------------------------
        # Build interface
        # --------------------------------------------------

        self.create_interface()


    # ======================================================
    # INTERFACE
    # ======================================================

    def create_interface(self):

        # --------------------------------------------------
        # Header
        # --------------------------------------------------

        header = tk.Frame(
            self.root,
            bg="#202020",
            height=80
        )

        header.pack(
            fill="x"
        )

        title = tk.Label(
            header,
            text="WINDOWS EVIDENCE TRIAGE & ANTI-FORENSICS ANALYZER",
            bg="#202020",
            fg="white",
            font=("Segoe UI", 18, "bold")
        )

        title.pack(
            pady=(15, 2)
        )

        subtitle = tk.Label(
            header,
            text="Digital Evidence Collection • Triage • Analysis • Reporting",
            bg="#202020",
            fg="#cccccc",
            font=("Segoe UI", 10)
        )

        subtitle.pack()


        # --------------------------------------------------
        # Evidence selection
        # --------------------------------------------------

        evidence_frame = tk.Frame(
            self.root,
            padx=15,
            pady=12
        )

        evidence_frame.pack(
            fill="x"
        )


        tk.Label(
            evidence_frame,
            text="Evidence Folder:",
            font=("Segoe UI", 10, "bold")
        ).pack(
            side="left"
        )


        self.path_entry = tk.Entry(
            evidence_frame,
            font=("Segoe UI", 10)
        )

        self.path_entry.pack(
            side="left",
            fill="x",
            expand=True,
            padx=10
        )


        browse_button = tk.Button(
            evidence_frame,
            text="Browse",
            width=12,
            command=self.browse_folder
        )

        browse_button.pack(
            side="left",
            padx=5
        )


        self.start_button = tk.Button(
            evidence_frame,
            text="START INVESTIGATION",
            width=22,
            command=self.start_investigation,
            bg="#303030",
            fg="white",
            font=("Segoe UI", 10, "bold")
        )

        self.start_button.pack(
            side="left",
            padx=5
        )


        # --------------------------------------------------
        # Progress
        # --------------------------------------------------

        progress_frame = tk.Frame(
            self.root,
            padx=15
        )

        progress_frame.pack(
            fill="x"
        )


        self.status_label = tk.Label(
            progress_frame,
            text="Ready",
            anchor="w",
            font=("Segoe UI", 9)
        )

        self.status_label.pack(
            fill="x"
        )


        self.progress = ttk.Progressbar(
            progress_frame,
            mode="indeterminate"
        )

        self.progress.pack(
            fill="x",
            pady=(3, 10)
        )


        # --------------------------------------------------
        # Main notebook
        # --------------------------------------------------

        notebook_frame = tk.Frame(
            self.root,
            padx=15
        )

        notebook_frame.pack(
            fill="both",
            expand=True
        )


        self.notebook = ttk.Notebook(
            notebook_frame
        )

        self.notebook.pack(
            fill="both",
            expand=True
        )


        # --------------------------------------------------
        # Create tabs
        # --------------------------------------------------

        self.dashboard_tab = self.create_tab(
            "Dashboard"
        )

        self.files_tab = self.create_tab(
            "File System"
        )

        self.timestamp_tab = self.create_tab(
            "Timestamps"
        )

        self.suspicious_tab = self.create_tab(
            "Suspicious Files"
        )

        self.registry_tab = self.create_tab(
            "Registry"
        )

        self.usb_tab = self.create_tab(
            "USB"
        )

        self.events_tab = self.create_tab(
            "Event Logs"
        )

        self.ads_tab = self.create_tab(
            "ADS"
        )

        self.browser_tab = self.create_tab(
            "Browser"
        )

        self.prefetch_tab = self.create_tab(
            "Prefetch"
        )

        self.recycle_tab = self.create_tab(
            "Recycle Bin"
        )

        self.timeline_tab = self.create_tab(
            "Timeline"
        )

        self.correlation_tab = self.create_tab(
            "Correlation"
        )

        self.reports_tab = self.create_tab(
            "Reports"
        )


        # --------------------------------------------------
        # Dashboard
        # --------------------------------------------------

        self.create_dashboard()


    # ======================================================
    # CREATE TAB
    # ======================================================

    def create_tab(self, name):

        frame = tk.Frame(
            self.notebook
        )

        self.notebook.add(
            frame,
            text=name
        )

        return frame


    # ======================================================
    # DASHBOARD
    # ======================================================

    def create_dashboard(self):

        title = tk.Label(
            self.dashboard_tab,
            text="INVESTIGATION DASHBOARD",
            font=("Segoe UI", 16, "bold")
        )

        title.pack(
            pady=20
        )


        self.dashboard_path = tk.Label(
            self.dashboard_tab,
            text="Evidence Source: Not selected",
            font=("Segoe UI", 10)
        )

        self.dashboard_path.pack(
            pady=5
        )


        cards_frame = tk.Frame(
            self.dashboard_tab
        )

        cards_frame.pack(
            fill="x",
            padx=30,
            pady=25
        )


        self.dashboard_values = {}


        categories = [
            ("Files", "files"),
            ("Folders", "folders"),
            ("Timestamp Findings", "timestamps"),
            ("Suspicious Files", "suspicious"),
            ("Installed Programs", "programs"),
            ("USB Devices", "usb"),
            ("Event Logs", "events"),
            ("ADS Findings", "ads"),
            ("Browser Findings", "browser"),
            ("Prefetch Files", "prefetch"),
            ("Recycle Bin Items", "recycle"),
            ("Correlated Findings", "correlation")
        ]


        for index, item in enumerate(categories):

            label = item[0]
            key = item[1]

            row = index // 4
            column = index % 4


            card = tk.Frame(
                cards_frame,
                relief="groove",
                borderwidth=1,
                padx=20,
                pady=15
            )

            card.grid(
                row=row,
                column=column,
                padx=8,
                pady=8,
                sticky="nsew"
            )


            cards_frame.grid_columnconfigure(
                column,
                weight=1
            )


            name_label = tk.Label(
                card,
                text=label,
                font=("Segoe UI", 9)
            )

            name_label.pack()


            value_label = tk.Label(
                card,
                text="0",
                font=("Segoe UI", 20, "bold")
            )

            value_label.pack(
                pady=(5, 0)
            )


            self.dashboard_values[key] = value_label


        self.dashboard_status = tk.Label(
            self.dashboard_tab,
            text="No investigation has been started.",
            font=("Segoe UI", 11)
        )

        self.dashboard_status.pack(
            pady=30
        )


    # ======================================================
    # BROWSE FOLDER
    # ======================================================

    def browse_folder(self):

        folder = filedialog.askdirectory(
            title="Select Evidence Folder"
        )

        if folder:

            self.path_entry.delete(
                0,
                tk.END
            )

            self.path_entry.insert(
                0,
                folder
            )


    # ======================================================
    # START INVESTIGATION
    # ======================================================

    def start_investigation(self):

        if self.investigation_running:

            return


        path = self.path_entry.get().strip()


        if not path:

            messagebox.showwarning(
                "Evidence Folder",
                "Please select an evidence folder."
            )

            return


        if not os.path.exists(path):

            messagebox.showerror(
                "Invalid Evidence Folder",
                "The selected folder does not exist."
            )

            return


        self.evidence_path = os.path.abspath(
            path
        )


        # --------------------------------------------------
        # Clear previous data
        # --------------------------------------------------

        self.clear_data()

        self.investigation_running = True

        self.start_button.config(
            state="disabled"
        )

        self.progress.start(
            10
        )


        self.status_label.config(
            text="Investigation started..."
        )


        self.dashboard_status.config(
            text="Investigation in progress..."
        )


        # --------------------------------------------------
        # Run investigation in background
        # --------------------------------------------------

        worker = threading.Thread(
            target=self.run_investigation
        )

        worker.daemon = True

        worker.start()


    # ======================================================
    # RUN INVESTIGATION
    # ======================================================

    def run_investigation(self):

        try:

            # ==================================================
            # FILE SYSTEM
            # ==================================================

            self.update_status(
                "Collecting file system evidence..."
            )

            self.filesystem_result = collect_files(
                self.evidence_path
            )


            # ==================================================
            # TIMESTAMP ANALYSIS
            # ==================================================

            self.update_status(
                "Analyzing timestamps..."
            )

            self.timestamp_findings = analyze_timestamps(
                self.filesystem_result.get(
                    "files",
                    []
                )
            )


            # ==================================================
            # SUSPICIOUS FILES
            # ==================================================

            self.update_status(
                "Analyzing suspicious files..."
            )

            self.suspicious_files = analyze_files(
                self.filesystem_result.get(
                    "files",
                    []
                )
            )


            # ==================================================
            # REGISTRY
            # ==================================================

            self.update_status(
                "Collecting installed programs..."
            )

            self.programs = collect_installed_programs()


            # ==================================================
            # USB
            # ==================================================

            self.update_status(
                "Collecting USB devices..."
            )

            self.usb_devices = collect_usb_devices()


            # ==================================================
            # EVENT LOGS
            # ==================================================

            self.update_status(
                "Collecting Security event logs..."
            )

            self.events = collect_security_events()


            # ==================================================
            # ADS
            # ==================================================

            self.update_status(
                "Analyzing Alternate Data Streams..."
            )

            self.ads_findings = analyze_ads(
                self.filesystem_result.get(
                    "files",
                    []
                )
            )


            # ==================================================
            # BROWSER
            # ==================================================

            self.update_status(
                "Collecting browser artifacts..."
            )

            self.browser_results = collect_browser_artifacts()


            self.browser_findings = analyze_all_browsers(
                self.browser_results
            )


            # ==================================================
            # PREFETCH
            # ==================================================

            self.update_status(
                "Collecting Prefetch artifacts..."
            )

            self.prefetch_results = collect_prefetch()


            # ==================================================
            # RECYCLE BIN
            # ==================================================

            self.update_status(
                "Collecting Recycle Bin artifacts..."
            )

            self.recycle_results = collect_recycle_bin()


            # ==================================================
            # BUILD FINDINGS
            # ==================================================

            self.update_status(
                "Building investigation findings..."
            )

            self.build_findings()


            # ==================================================
            # TIMELINE
            # ==================================================

            self.update_status(
                "Building forensic timeline..."
            )

            self.build_timeline()


            # ==================================================
            # UPDATE GUI
            # ==================================================

            self.root.after(
                0,
                self.display_results
            )


        except Exception as error:

            logger.exception(
                "Investigation failed."
            )

            self.root.after(
                0,
                lambda: self.investigation_error(
                    error
                )
            )


    # ======================================================
    # BUILD FINDINGS
    # ======================================================

    def build_findings(self):

        self.all_findings = []


        # --------------------------------------------------
        # Suspicious files
        # --------------------------------------------------

        for item in self.suspicious_files:

            finding = dict(item)

            finding["category"] = (
                "Suspicious Files"
            )

            self.all_findings.append(
                finding
            )


        # --------------------------------------------------
        # Browser
        # --------------------------------------------------

        for item in self.browser_findings:

            finding = dict(item)

            finding["category"] = (
                "Browser"
            )

            self.all_findings.append(
                finding
            )


        # --------------------------------------------------
        # Timestamp
        # --------------------------------------------------

        for item in self.timestamp_findings:

            finding = {
                "category":
                    "Timestamps",

                "type":
                    "TIMESTAMP_ANOMALY",

                "severity":
                    "REVIEW",

                "file":
                    item.get(
                        "path",
                        ""
                    ),

                "description":
                    "Possible timestamp inconsistency detected."
            }

            self.all_findings.append(
                finding
            )


        # --------------------------------------------------
        # ADS
        # --------------------------------------------------

        for item in self.ads_findings:

            finding = {
                "category":
                    "ADS",

                "type":
                    "ALTERNATE_DATA_STREAM",

                "severity":
                    "REVIEW",

                "file":
                    item.get(
                        "path",
                        ""
                    ),

                "description":
                    "NTFS Alternate Data Stream detected."
            }

            self.all_findings.append(
                finding
            )


    # ======================================================
    # BUILD TIMELINE
    # ======================================================

    def build_timeline(self):

        timeline_events = []


        # --------------------------------------------------
        # Suspicious files
        # --------------------------------------------------

        for item in self.suspicious_files:

            timeline_events.append({

                "type":
                    item.get(
                        "type",
                        "SUSPICIOUS_FILE"
                    ),

                "description":
                    item.get(
                        "description",
                        ""
                    ),

                "path":
                    item.get(
                        "file",
                        ""
                    ),

                "severity":
                    item.get(
                        "severity",
                        "UNKNOWN"
                    ),

                "source":
                    "File System"

            })


        # --------------------------------------------------
        # Timestamp findings
        # --------------------------------------------------

        for item in self.timestamp_findings:

            timeline_events.append({

                "type":
                    "TIMESTAMP_ANOMALY",

                "description":
                    "Possible timestamp inconsistency",

                "path":
                    item.get(
                        "path",
                        ""
                    ),

                "severity":
                    "REVIEW",

                "source":
                    "Timestamp Analyzer",

                "timestamp":
                    item.get(
                        "modified",
                        ""
                    )

            })


        # --------------------------------------------------
        # ADS
        # --------------------------------------------------

        for item in self.ads_findings:

            timeline_events.append({

                "type":
                    "ALTERNATE_DATA_STREAM",

                "description":
                    "NTFS Alternate Data Stream detected",

                "path":
                    item.get(
                        "path",
                        ""
                    ),

                "severity":
                    "REVIEW",

                "source":
                    "ADS Analyzer"

            })


        self.timeline = create_timeline(
            timeline_events
        )


    # ======================================================
    # DISPLAY RESULTS
    # ======================================================

    def display_results(self):

        self.progress.stop()

        self.investigation_running = False

        self.start_button.config(
            state="normal"
        )


        self.status_label.config(
            text="Investigation completed successfully."
        )


        self.dashboard_status.config(
            text="Investigation completed successfully."
        )


        self.dashboard_path.config(
            text="Evidence Source: " +
            self.evidence_path
        )


        # --------------------------------------------------
        # Dashboard counts
        # --------------------------------------------------

        self.dashboard_values[
            "files"
        ].config(
            text=str(
                self.filesystem_result.get(
                    "file_count",
                    0
                )
            )
        )


        self.dashboard_values[
            "folders"
        ].config(
            text=str(
                self.filesystem_result.get(
                    "folder_count",
                    0
                )
            )
        )


        self.dashboard_values[
            "timestamps"
        ].config(
            text=str(
                len(
                    self.timestamp_findings
                )
            )
        )


        self.dashboard_values[
            "suspicious"
        ].config(
            text=str(
                len(
                    self.suspicious_files
                )
            )
        )


        self.dashboard_values[
            "programs"
        ].config(
            text=str(
                len(
                    self.programs
                )
            )
        )


        self.dashboard_values[
            "usb"
        ].config(
            text=str(
                len(
                    self.usb_devices
                )
            )
        )


        self.dashboard_values[
            "events"
        ].config(
            text=str(
                len(
                    self.events
                )
            )
        )


        self.dashboard_values[
            "ads"
        ].config(
            text=str(
                len(
                    self.ads_findings
                )
            )
        )


        self.dashboard_values[
            "browser"
        ].config(
            text=str(
                len(
                    self.browser_findings
                )
            )
        )


        self.dashboard_values[
            "prefetch"
        ].config(
            text=str(
                len(
                    self.prefetch_results
                )
            )
        )


        self.dashboard_values[
            "recycle"
        ].config(
            text=str(
                len(
                    self.recycle_results
                )
            )
        )


        self.dashboard_values[
            "correlation"
        ].config(
            text=str(
                len(
                    self.all_findings
                )
            )
        )


        # --------------------------------------------------
        # Display category data
        # --------------------------------------------------

        self.display_filesystem()

        self.display_timestamps()

        self.display_suspicious_files()

        self.display_registry()

        self.display_usb()

        self.display_events()

        self.display_ads()

        self.display_browser()

        self.display_prefetch()

        self.display_recycle()

        self.display_timeline()

        self.display_correlation()

        self.display_reports()


    # ======================================================
    # GENERIC TABLE
    # ======================================================

    def clear_frame(self, frame):

        for widget in frame.winfo_children():

            widget.destroy()


    def create_table(
        self,
        frame,
        columns
    ):

        self.clear_frame(
            frame
        )


        container = tk.Frame(
            frame
        )

        container.pack(
            fill="both",
            expand=True
        )


        tree = ttk.Treeview(
            container,
            columns=columns,
            show="headings"
        )


        vertical = ttk.Scrollbar(
            container,
            orient="vertical",
            command=tree.yview
        )


        horizontal = ttk.Scrollbar(
            container,
            orient="horizontal",
            command=tree.xview
        )


        tree.configure(
            yscrollcommand=vertical.set,
            xscrollcommand=horizontal.set
        )


        vertical.pack(
            side="right",
            fill="y"
        )


        horizontal.pack(
            side="bottom",
            fill="x"
        )


        tree.pack(
            side="left",
            fill="both",
            expand=True
        )


        for column in columns:

            tree.heading(
                column,
                text=column
            )

            tree.column(
                column,
                width=180,
                anchor="w"
            )


        return tree


    # ======================================================
    # FILE SYSTEM
    # ======================================================

    def display_filesystem(self):

        tree = self.create_table(
            self.files_tab,
            (
                "Name",
                "Path",
                "Extension",
                "Size",
                "Created",
                "Modified",
                "Accessed",
                "Hidden"
            )
        )


        files = self.filesystem_result.get(
            "files",
            []
        )


        for item in files:

            tree.insert(
                "",
                "end",
                values=(
                    item.get("name", ""),
                    item.get("path", ""),
                    item.get("extension", ""),
                    item.get("size_bytes", ""),
                    item.get("created_time", ""),
                    item.get("modified_time", ""),
                    item.get("accessed_time", ""),
                    item.get("is_hidden", "")
                )
            )


    # ======================================================
    # TIMESTAMPS
    # ======================================================

    def display_timestamps(self):

        tree = self.create_table(
            self.timestamp_tab,
            (
                "File",
                "Path",
                "Created",
                "Modified",
                "Accessed",
                "Findings"
            )
        )


        for item in self.timestamp_findings:

            findings = "; ".join(
                [
                    str(x)
                    for x in item.get(
                        "findings",
                        []
                    )
                ]
            )


            tree.insert(
                "",
                "end",
                values=(
                    item.get("name", ""),
                    item.get("path", ""),
                    item.get("created", ""),
                    item.get("modified", ""),
                    item.get("accessed", ""),
                    findings
                )
            )


    # ======================================================
    # SUSPICIOUS FILES
    # ======================================================

    def display_suspicious_files(self):

        tree = self.create_table(
            self.suspicious_tab,
            (
                "Type",
                "Severity",
                "File",
                "Description"
            )
        )


        for item in self.suspicious_files:

            tree.insert(
                "",
                "end",
                values=(
                    item.get("type", ""),
                    item.get("severity", ""),
                    item.get("file", ""),
                    item.get("description", "")
                )
            )


    # ======================================================
    # REGISTRY
    # ======================================================

    def display_registry(self):

        tree = self.create_table(
            self.registry_tab,
            (
                "Installed Program",
            )
        )


        for program in self.programs:

            tree.insert(
                "",
                "end",
                values=(
                    str(program),
                )
            )


    # ======================================================
    # USB
    # ======================================================

    def display_usb(self):

        tree = self.create_table(
            self.usb_tab,
            (
                "Device Name",
                "Serial Number"
            )
        )


        for device in self.usb_devices:

            tree.insert(
                "",
                "end",
                values=(
                    device.get(
                        "device_name",
                        ""
                    ),
                    device.get(
                        "serial_number",
                        ""
                    )
                )
            )


    # ======================================================
    # EVENTS
    # ======================================================

    def display_events(self):

        tree = self.create_table(
            self.events_tab,
            (
                "Security Event Data",
            )
        )


        for event in self.events:

            tree.insert(
                "",
                "end",
                values=(
                    str(event),
                )
            )


    # ======================================================
    # ADS
    # ======================================================

    def display_ads(self):

        tree = self.create_table(
            self.ads_tab,
            (
                "File",
                "Path",
                "Stream",
                "Size"
            )
        )


        for item in self.ads_findings:

            streams = item.get(
                "streams",
                []
            )


            for stream in streams:

                tree.insert(
                    "",
                    "end",
                    values=(
                        item.get(
                            "name",
                            ""
                        ),
                        item.get(
                            "path",
                            ""
                        ),
                        stream.get(
                            "stream_name",
                            ""
                        ),
                        stream.get(
                            "size_bytes",
                            ""
                        )
                    )
                )


    # ======================================================
    # BROWSER
    # ======================================================

    def display_browser(self):

        tree = self.create_table(
            self.browser_tab,
            (
                "Browser",
                "History Exists",
                "History Count",
                "Downloads"
            )
        )


        for item in self.browser_results:

            tree.insert(
                "",
                "end",
                values=(
                    item.get(
                        "browser",
                        ""
                    ),
                    item.get(
                        "history_exists",
                        False
                    ),
                    item.get(
                        "history_count",
                        0
                    ),
                    item.get(
                        "download_count",
                        0
                    )
                )
            )


    # ======================================================
    # PREFETCH
    # ======================================================

    def display_prefetch(self):

        tree = self.create_table(
            self.prefetch_tab,
            (
                "Name",
                "Path",
                "Size",
                "Created",
                "Modified"
            )
        )


        for item in self.prefetch_results:

            tree.insert(
                "",
                "end",
                values=(
                    item.get(
                        "name",
                        ""
                    ),
                    item.get(
                        "path",
                        ""
                    ),
                    item.get(
                        "size",
                        item.get(
                            "size_bytes",
                            ""
                        )
                    ),
                    item.get(
                        "created",
                        item.get(
                            "created_time",
                            ""
                        )
                    ),
                    item.get(
                        "modified",
                        item.get(
                            "modified_time",
                            ""
                        )
                    )
                )
            )


    # ======================================================
    # RECYCLE BIN
    # ======================================================

    def display_recycle(self):

        tree = self.create_table(
            self.recycle_tab,
            (
                "Name",
                "Path",
                "Size",
                "Created",
                "Modified"
            )
        )


        for item in self.recycle_results:

            tree.insert(
                "",
                "end",
                values=(
                    item.get(
                        "name",
                        ""
                    ),
                    item.get(
                        "path",
                        ""
                    ),
                    item.get(
                        "size",
                        item.get(
                            "size_bytes",
                            ""
                        )
                    ),
                    item.get(
                        "created",
                        item.get(
                            "created_time",
                            ""
                        )
                    ),
                    item.get(
                        "modified",
                        item.get(
                            "modified_time",
                            ""
                        )
                    )
                )
            )


    # ======================================================
    # TIMELINE
    # ======================================================

    def display_timeline(self):

        tree = self.create_table(
            self.timeline_tab,
            (
                "Timestamp",
                "Type",
                "Description",
                "Path",
                "Severity",
                "Source"
            )
        )


        for item in self.timeline:

            tree.insert(
                "",
                "end",
                values=(
                    item.get(
                        "timestamp",
                        "UNKNOWN TIME"
                    ),
                    item.get(
                        "type",
                        ""
                    ),
                    item.get(
                        "description",
                        ""
                    ),
                    item.get(
                        "path",
                        ""
                    ),
                    item.get(
                        "severity",
                        ""
                    ),
                    item.get(
                        "source",
                        ""
                    )
                )
            )


    # ======================================================
    # CORRELATION
    # ======================================================

    def display_correlation(self):

        tree = self.create_table(
            self.correlation_tab,
            (
                "Category",
                "Type",
                "Severity",
                "File",
                "Description"
            )
        )


        for item in self.all_findings:

            tree.insert(
                "",
                "end",
                values=(
                    item.get(
                        "category",
                        ""
                    ),
                    item.get(
                        "type",
                        ""
                    ),
                    item.get(
                        "severity",
                        ""
                    ),
                    item.get(
                        "file",
                        ""
                    ),
                    item.get(
                        "description",
                        ""
                    )
                )
            )


    # ======================================================
    # REPORTS
    # ======================================================

    def display_reports(self):

        self.clear_frame(
            self.reports_tab
        )


        title = tk.Label(
            self.reports_tab,
            text="REPORT GENERATION",
            font=("Segoe UI", 16, "bold")
        )

        title.pack(
            pady=30
        )


        info = tk.Label(
            self.reports_tab,
            text=(
                "Report generation will use the collected "
                "investigation data shown in the categories."
            ),
            font=("Segoe UI", 10)
        )

        info.pack(
            pady=10
        )


        button_frame = tk.Frame(
            self.reports_tab
        )

        button_frame.pack(
            pady=30
        )


        pdf_button = tk.Button(
            button_frame,
            text="GENERATE PDF REPORT",
            width=25,
            height=2,
            state="disabled"
        )

        pdf_button.grid(
            row=0,
            column=0,
            padx=10
        )


        excel_button = tk.Button(
            button_frame,
            text="EXPORT TO EXCEL",
            width=25,
            height=2,
            state="disabled"
        )

        excel_button.grid(
            row=0,
            column=1,
            padx=10
        )


        csv_button = tk.Button(
            button_frame,
            text="EXPORT TO CSV",
            width=25,
            height=2,
            state="disabled"
        )

        csv_button.grid(
            row=0,
            column=2,
            padx=10
        )


        note = tk.Label(
            self.reports_tab,
            text=(
                "PDF / Excel / CSV export will be connected "
                "after the investigation data structure is corrected."
            ),
            font=("Segoe UI", 9)
        )

        note.pack(
            pady=20
        )


    # ======================================================
    # STATUS UPDATE
    # ======================================================

    def update_status(self, message):

        self.root.after(
            0,
            lambda: self.status_label.config(
                text=message
            )
        )


    # ======================================================
    # ERROR
    # ======================================================

    def investigation_error(
        self,
        error
    ):

        self.progress.stop()

        self.investigation_running = False

        self.start_button.config(
            state="normal"
        )


        self.status_label.config(
            text="Investigation failed."
        )


        self.dashboard_status.config(
            text="Investigation failed."
        )


        messagebox.showerror(
            "Investigation Error",
            "The investigation could not be completed.\n\n"
            + str(error)
            + "\n\n"
            + "Check forensic_tool.log for details."
        )


    # ======================================================
    # CLEAR DATA
    # ======================================================

    def clear_data(self):

        self.filesystem_result = {}

        self.timestamp_findings = []

        self.suspicious_files = []

        self.programs = []

        self.usb_devices = []

        self.events = []

        self.ads_findings = []

        self.browser_results = []

        self.browser_findings = []

        self.prefetch_results = []

        self.recycle_results = []

        self.all_findings = []

        self.timeline = []


# ==========================================================
# APPLICATION ENTRY POINT
# ==========================================================

def main():

    root = tk.Tk()

    application = ForensicApplication(
        root
    )

    root.mainloop()


# ==========================================================
# START
# ==========================================================

if __name__ == "__main__":

    main()
