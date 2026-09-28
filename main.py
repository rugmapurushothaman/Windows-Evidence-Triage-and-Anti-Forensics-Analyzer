import os
import threading
import traceback
import tkinter as tk

from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox

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


class ForensicApplication:

    def __init__(self, root):

        self.root = root

        self.root.title(
            "Windows Evidence Triage & Anti-Forensics Analyzer"
        )

        self.root.geometry("1350x800")

        self.root.minsize(1100, 650)

        # ============================================================
        # DATA VARIABLES
        # ============================================================

        self.evidence_path = ""

        self.filesystem_result = {}

        self.timestamp_findings = []

        self.suspicious_files = []

        self.programs = []

        self.usb_devices = []

        self.events = []

        self.ads_findings = []

        self.browser_results = {}

        self.browser_findings = []

        self.prefetch_results = []

        self.recycle_results = []

        self.all_findings = []

        self.timeline = []

        self.investigation_running = False

        # ============================================================
        # BUILD GUI
        # ============================================================

        self.build_gui()

    # ================================================================
    # GUI
    # ================================================================

    def build_gui(self):

        # ------------------------------------------------------------
        # TOP FRAME
        # ------------------------------------------------------------

        top_frame = ttk.Frame(self.root)

        top_frame.pack(
            fill="x",
            padx=10,
            pady=10
        )

        ttk.Label(
            top_frame,
            text="Evidence Folder:"
        ).pack(
            side="left"
        )

        self.evidence_entry = ttk.Entry(
            top_frame,
            width=80
        )

        self.evidence_entry.pack(
            side="left",
            padx=5
        )

        browse_button = ttk.Button(
            top_frame,
            text="Browse",
            command=self.browse_evidence
        )

        browse_button.pack(
            side="left",
            padx=5
        )

        self.start_button = ttk.Button(
            top_frame,
            text="START INVESTIGATION",
            command=self.start_investigation
        )

        self.start_button.pack(
            side="left",
            padx=10
        )

        # ------------------------------------------------------------
        # STATUS
        # ------------------------------------------------------------

        status_frame = ttk.Frame(self.root)

        status_frame.pack(
            fill="x",
            padx=10,
            pady=5
        )

        self.status_label = ttk.Label(
            status_frame,
            text="Ready"
        )

        self.status_label.pack(
            side="left"
        )

        self.progress = ttk.Progressbar(
            status_frame,
            mode="indeterminate"
        )

        self.progress.pack(
            side="right",
            fill="x",
            expand=True,
            padx=10
        )

        # ------------------------------------------------------------
        # NOTEBOOK
        # ------------------------------------------------------------

        self.notebook = ttk.Notebook(
            self.root
        )

        self.notebook.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=10
        )

        # ============================================================
        # TABS
        # ============================================================

        self.dashboard_tab = ttk.Frame(
            self.notebook
        )

        self.filesystem_tab = ttk.Frame(
            self.notebook
        )

        self.timestamps_tab = ttk.Frame(
            self.notebook
        )

        self.suspicious_tab = ttk.Frame(
            self.notebook
        )

        self.registry_tab = ttk.Frame(
            self.notebook
        )

        self.usb_tab = ttk.Frame(
            self.notebook
        )

        self.events_tab = ttk.Frame(
            self.notebook
        )

        self.ads_tab = ttk.Frame(
            self.notebook
        )

        self.browser_tab = ttk.Frame(
            self.notebook
        )

        self.prefetch_tab = ttk.Frame(
            self.notebook
        )

        self.recycle_tab = ttk.Frame(
            self.notebook
        )

        self.timeline_tab = ttk.Frame(
            self.notebook
        )

        self.correlation_tab = ttk.Frame(
            self.notebook
        )

        self.reports_tab = ttk.Frame(
            self.notebook
        )

        # ------------------------------------------------------------
        # ADD TABS
        # ------------------------------------------------------------

        self.notebook.add(
            self.dashboard_tab,
            text="Dashboard"
        )

        self.notebook.add(
            self.filesystem_tab,
            text="File System"
        )

        self.notebook.add(
            self.timestamps_tab,
            text="Timestamps"
        )

        self.notebook.add(
            self.suspicious_tab,
            text="Suspicious Files"
        )

        self.notebook.add(
            self.registry_tab,
            text="Registry"
        )

        self.notebook.add(
            self.usb_tab,
            text="USB"
        )

        self.notebook.add(
            self.events_tab,
            text="Event Logs"
        )

        self.notebook.add(
            self.ads_tab,
            text="ADS"
        )

        self.notebook.add(
            self.browser_tab,
            text="Browser"
        )

        self.notebook.add(
            self.prefetch_tab,
            text="Prefetch"
        )

        self.notebook.add(
            self.recycle_tab,
            text="Recycle Bin"
        )

        self.notebook.add(
            self.timeline_tab,
            text="Timeline"
        )

        self.notebook.add(
            self.correlation_tab,
            text="Correlation"
        )

        self.notebook.add(
            self.reports_tab,
            text="Reports"
        )

        # ------------------------------------------------------------
        # DASHBOARD
        # ------------------------------------------------------------

        self.dashboard_text = tk.Text(
            self.dashboard_tab,
            wrap="word"
        )

        self.dashboard_text.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=10
        )

        # ------------------------------------------------------------
        # INITIAL REPORT BUTTONS
        # ------------------------------------------------------------

        self.build_reports_tab()

    # ================================================================
    # BROWSE
    # ================================================================

    def browse_evidence(self):

        path = filedialog.askdirectory(
            title="Select Evidence Folder"
        )

        if path:

            self.evidence_path = path

            self.evidence_entry.delete(
                0,
                tk.END
            )

            self.evidence_entry.insert(
                0,
                path
            )

            self.status_label.config(
                text="Evidence folder selected: " + path
            )

    # ================================================================
    # START INVESTIGATION
    # ================================================================

    def start_investigation(self):

        if self.investigation_running:

            return

        path = self.evidence_entry.get().strip()

        if not path:

            messagebox.showwarning(
                "Evidence Folder",
                "Please select an evidence folder."
            )

            return

        if not os.path.exists(path):

            messagebox.showerror(
                "Invalid Evidence Folder",
                "The selected evidence folder does not exist."
            )

            return

        self.evidence_path = path

        self.investigation_running = True

        self.start_button.config(
            state="disabled"
        )

        self.progress.start(10)

        self.status_label.config(
            text="Investigation running..."
        )

        self.clear_data()

        thread = threading.Thread(
            target=self.run_investigation
        )

        thread.daemon = True

        thread.start()

    # ================================================================
    # RUN INVESTIGATION
    # ================================================================

    def run_investigation(self):

        try:

            # --------------------------------------------------------
            # FILE SYSTEM
            # --------------------------------------------------------

            self.update_status(
                "Collecting file system evidence..."
            )

            self.filesystem_result = collect_files(
                self.evidence_path
            )

            files = self.filesystem_result.get(
                "files",
                []
            )

            # --------------------------------------------------------
            # TIMESTAMPS
            # --------------------------------------------------------

            self.update_status(
                "Analyzing timestamps..."
            )

            self.timestamp_findings = analyze_timestamps(
                files
            )

            # --------------------------------------------------------
            # SUSPICIOUS FILES
            # --------------------------------------------------------

            self.update_status(
                "Analyzing suspicious files..."
            )

            self.suspicious_files = analyze_files(
                files
            )

            # --------------------------------------------------------
            # REGISTRY
            # --------------------------------------------------------

            self.update_status(
                "Collecting installed programs..."
            )

            self.programs = collect_installed_programs()

            # --------------------------------------------------------
            # USB
            # --------------------------------------------------------

            self.update_status(
                "Collecting USB device evidence..."
            )

            self.usb_devices = collect_usb_devices()

            # --------------------------------------------------------
            # EVENT LOGS
            # --------------------------------------------------------

            self.update_status(
                "Collecting Windows security events..."
            )

            self.events = collect_security_events()

            # --------------------------------------------------------
            # ADS
            # --------------------------------------------------------

            self.update_status(
                "Analyzing Alternate Data Streams..."
            )

            self.ads_findings = analyze_ads(
                files
            )

            # --------------------------------------------------------
            # BROWSER
            # --------------------------------------------------------

            self.update_status(
                "Analyzing browser artifacts..."
            )

            try:

                self.browser_results = collect_browser_artifacts(
                    self.evidence_path
                )

            except TypeError:

                # Compatibility with an older browser collector
                self.browser_results = collect_browser_artifacts()

            try:

                self.browser_findings = analyze_all_browsers(
                    self.browser_results
                )

            except Exception:

                logger.exception(
                    "Browser cleanup analysis failed"
                )

                self.browser_findings = []

            # --------------------------------------------------------
            # PREFETCH
            # --------------------------------------------------------

            self.update_status(
                "Collecting Prefetch artifacts..."
            )

            self.prefetch_results = collect_prefetch()

            # --------------------------------------------------------
            # RECYCLE BIN
            # --------------------------------------------------------

            self.update_status(
                "Collecting Recycle Bin artifacts..."
            )

            self.recycle_results = collect_recycle_bin()

            # --------------------------------------------------------
            # BUILD FINDINGS
            # --------------------------------------------------------

            self.update_status(
                "Building investigation findings..."
            )

            self.build_findings()

            # --------------------------------------------------------
            # BUILD TIMELINE
            # --------------------------------------------------------

            self.update_status(
                "Building forensic timeline..."
            )

            self.build_timeline()

            # --------------------------------------------------------
            # DISPLAY
            # --------------------------------------------------------

            self.root.after(
                0,
                self.display_results
            )

        except Exception as error:

            logger.exception(
                "Investigation failed"
            )

            self.root.after(
                0,
                lambda: self.investigation_error(
                    error
                )
            )

    # ================================================================
    # STATUS
    # ================================================================

    def update_status(self, text):

        self.root.after(
            0,
            lambda: self.status_label.config(
                text=text
            )
        )

    # ================================================================
    # BUILD FINDINGS
    # ================================================================

    def build_findings(self):

        self.all_findings = []

        # ------------------------------------------------------------
        # TIMESTAMP FINDINGS
        # ------------------------------------------------------------

        if self.timestamp_findings:

            for item in self.timestamp_findings:

                self.all_findings.append(
                    {
                        "category": "Timestamp",
                        "finding": item
                    }
                )

        # ------------------------------------------------------------
        # SUSPICIOUS FILES
        # ------------------------------------------------------------

        if self.suspicious_files:

            for item in self.suspicious_files:

                self.all_findings.append(
                    {
                        "category": "Suspicious File",
                        "finding": item
                    }
                )

        # ------------------------------------------------------------
        # ADS
        # ------------------------------------------------------------

        if self.ads_findings:

            for item in self.ads_findings:

                self.all_findings.append(
                    {
                        "category": "ADS",
                        "finding": item
                    }
                )

        # ------------------------------------------------------------
        # BROWSER
        # ------------------------------------------------------------

        if self.browser_findings:

            for item in self.browser_findings:

                self.all_findings.append(
                    {
                        "category": "Browser",
                        "finding": item
                    }
                )

        # ------------------------------------------------------------
        # EVENTS
        # ------------------------------------------------------------

        if self.events:

            for item in self.events:

                self.all_findings.append(
                    {
                        "category": "Event Log",
                        "finding": item
                    }
                )

    # ================================================================
    # BUILD TIMELINE
    # ================================================================

    def build_timeline(self):

        try:

            events = []

            # --------------------------------------------------------
            # EVENT LOGS
            # --------------------------------------------------------

            for event in self.events:

                if isinstance(event, dict):

                    item = dict(event)

                    item["source"] = "Windows Event Log"

                    events.append(item)

            # --------------------------------------------------------
            # USB
            # --------------------------------------------------------

            for device in self.usb_devices:

                if not isinstance(device, dict):

                    continue

                observations = device.get(
                    "observations",
                    []
                )

                for observation in observations:

                    if not isinstance(observation, dict):

                        continue

                    item = dict(observation)

                    item["source"] = "USB / SetupAPI"

                    item["device_name"] = device.get(
                        "device_name",
                        ""
                    )

                    events.append(item)

            # --------------------------------------------------------
            # CREATE TIMELINE
            # --------------------------------------------------------

            self.timeline = create_timeline(
                events
            )

        except Exception:

            logger.exception(
                "Timeline creation failed"
            )

            self.timeline = []

    # ================================================================
    # DISPLAY RESULTS
    # ================================================================

    def display_results(self):

        self.display_dashboard()

        self.display_filesystem()

        self.display_timestamps()

        self.display_suspicious_files()

        self.display_registry()

        self.display_usb()

        self.display_events()

        self.display_ads()

        self.display_browser()

        self.display_prefetch()

        self.display_recycle_bin()

        self.display_timeline()

        self.display_correlation()

        self.progress.stop()

        self.start_button.config(
            state="normal"
        )

        self.investigation_running = False

        self.status_label.config(
            text="Investigation completed successfully."
        )

    # ================================================================
    # DASHBOARD
    # ================================================================

    def display_dashboard(self):

        self.dashboard_text.delete(
            "1.0",
            tk.END
        )

        folders = self.filesystem_result.get(
            "folders",
            0
        )

        files = self.filesystem_result.get(
            "files",
            []
        )

        text = ""

        text += "=" * 70
        text += "\n"
        text += "WINDOWS EVIDENCE TRIAGE & ANTI-FORENSICS ANALYZER\n"
        text += "=" * 70
        text += "\n\n"

        text += "Evidence Path : {}\n".format(
            self.evidence_path
        )

        text += "Folders       : {}\n".format(
            folders
        )

        text += "Files         : {}\n".format(
            len(files)
        )

        text += "Timestamp Findings : {}\n".format(
            len(self.timestamp_findings)
        )

        text += "Suspicious Files   : {}\n".format(
            len(self.suspicious_files)
        )

        text += "Installed Programs : {}\n".format(
            len(self.programs)
        )

        text += "USB Devices        : {}\n".format(
            len(self.usb_devices)
        )

        text += "Event Logs         : {}\n".format(
            len(self.events)
        )

        text += "ADS Findings       : {}\n".format(
            len(self.ads_findings)
        )

        text += "Browser Findings   : {}\n".format(
            len(self.browser_findings)
        )

        text += "Prefetch Records   : {}\n".format(
            len(self.prefetch_results)
            if isinstance(
                self.prefetch_results,
                list
            )
            else 0
        )

        text += "Recycle Bin Records: {}\n".format(
            len(self.recycle_results)
            if isinstance(
                self.recycle_results,
                list
            )
            else 0
        )

        text += "\n"
        text += "=" * 70
        text += "\n"

        self.dashboard_text.insert(
            tk.END,
            text
        )

    # ================================================================
    # TREEVIEW HELPER
    # ================================================================

    def create_treeview(
        self,
        parent,
        columns,
        headings=None
    ):

        frame = ttk.Frame(
            parent
        )

        frame.pack(
            fill="both",
            expand=True
        )

        tree = ttk.Treeview(
            frame,
            columns=columns,
            show="headings"
        )

        if headings is None:

            headings = columns

        for column in columns:

            tree.heading(
                column,
                text=headings[
                    columns.index(column)
                ]
            )

            tree.column(
                column,
                width=150,
                anchor="w"
            )

        vertical = ttk.Scrollbar(
            frame,
            orient="vertical",
            command=tree.yview
        )

        horizontal = ttk.Scrollbar(
            frame,
            orient="horizontal",
            command=tree.xview
        )

        tree.configure(
            yscrollcommand=vertical.set,
            xscrollcommand=horizontal.set
        )

        tree.grid(
            row=0,
            column=0,
            sticky="nsew"
        )

        vertical.grid(
            row=0,
            column=1,
            sticky="ns"
        )

        horizontal.grid(
            row=1,
            column=0,
            sticky="ew"
        )

        frame.rowconfigure(
            0,
            weight=1
        )

        frame.columnconfigure(
            0,
            weight=1
        )

        return tree

    # ================================================================
    # FILE SYSTEM
    # ================================================================

    def display_filesystem(self):

        for widget in self.filesystem_tab.winfo_children():

            widget.destroy()

        files = self.filesystem_result.get(
            "files",
            []
        )

        columns = (
            "name",
            "path",
            "extension",
            "size",
            "created",
            "modified",
            "accessed",
            "hidden"
        )

        tree = self.create_treeview(
            self.filesystem_tab,
            columns
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

    # ================================================================
    # TIMESTAMPS
    # ================================================================

    def display_timestamps(self):

        for widget in self.timestamps_tab.winfo_children():

            widget.destroy()

        columns = (
            "path",
            "created",
            "modified",
            "accessed",
            "reason"
        )

        tree = self.create_treeview(
            self.timestamps_tab,
            columns
        )

        for item in self.timestamp_findings:

            if isinstance(item, dict):

                tree.insert(
                    "",
                    "end",
                    values=(
                        item.get(
                            "path",
                            item.get("name", "")
                        ),
                        item.get(
                            "created_time",
                            ""
                        ),
                        item.get(
                            "modified_time",
                            ""
                        ),
                        item.get(
                            "accessed_time",
                            ""
                        ),
                        item.get(
                            "reason",
                            item.get(
                                "description",
                                ""
                            )
                        )
                    )
                )

    # ================================================================
    # SUSPICIOUS FILES
    # ================================================================

    def display_suspicious_files(self):

        for widget in self.suspicious_tab.winfo_children():

            widget.destroy()

        columns = (
            "path",
            "risk",
            "reason"
        )

        tree = self.create_treeview(
            self.suspicious_tab,
            columns
        )

        for item in self.suspicious_files:

            if isinstance(item, dict):

                tree.insert(
                    "",
                    "end",
                    values=(
                        item.get(
                            "path",
                            item.get("name", "")
                        ),
                        item.get(
                            "risk",
                            ""
                        ),
                        item.get(
                            "reason",
                            item.get(
                                "description",
                                ""
                            )
                        )
                    )
                )

    # ================================================================
    # REGISTRY
    # ================================================================

    def display_registry(self):

        for widget in self.registry_tab.winfo_children():

            widget.destroy()

        columns = (
            "name",
            "version",
            "publisher",
            "install_date"
        )

        tree = self.create_treeview(
            self.registry_tab,
            columns
        )

        for item in self.programs:

            if isinstance(item, dict):

                tree.insert(
                    "",
                    "end",
                    values=(
                        item.get(
                            "name",
                            ""
                        ),
                        item.get(
                            "version",
                            ""
                        ),
                        item.get(
                            "publisher",
                            ""
                        ),
                        item.get(
                            "install_date",
                            ""
                        )
                    )
                )

            else:

                tree.insert(
                    "",
                    "end",
                    values=(
                        str(item),
                        "",
                        "",
                        ""
                    )
                )

    # ================================================================
    # USB
    # ================================================================

    def display_usb(self):

        for widget in self.usb_tab.winfo_children():

            widget.destroy()

        # ------------------------------------------------------------
        # TITLE
        # ------------------------------------------------------------

        title = ttk.Label(
            self.usb_tab,
            text="USB Device Evidence"
        )

        title.pack(
            anchor="w",
            padx=10,
            pady=5
        )

        # ------------------------------------------------------------
        # MAIN USB TREE
        # ------------------------------------------------------------

        main_frame = ttk.Frame(
            self.usb_tab
        )

        main_frame.pack(
            fill="both",
            expand=True,
            padx=5,
            pady=5
        )

        columns = (
            "device",
            "manufacturer",
            "serial",
            "first_observed",
            "last_observed",
            "observation_count",
            "source"
        )

        tree = ttk.Treeview(
            main_frame,
            columns=columns,
            show="headings",
            height=12
        )

        headings = {
            "device": "Device",
            "manufacturer": "Manufacturer",
            "serial": "Serial Number",
            "first_observed": "First Observed",
            "last_observed": "Last Observed",
            "observation_count": "Observation Count",
            "source": "Evidence Source"
        }

        widths = {
            "device": 220,
            "manufacturer": 150,
            "serial": 180,
            "first_observed": 180,
            "last_observed": 180,
            "observation_count": 130,
            "source": 180
        }

        for column in columns:

            tree.heading(
                column,
                text=headings[column]
            )

            tree.column(
                column,
                width=widths[column],
                anchor="w"
            )

        scrollbar = ttk.Scrollbar(
            main_frame,
            orient="vertical",
            command=tree.yview
        )

        tree.configure(
            yscrollcommand=scrollbar.set
        )

        tree.pack(
            side="left",
            fill="both",
            expand=True
        )

        scrollbar.pack(
            side="right",
            fill="y"
        )

        # ------------------------------------------------------------
        # INSERT DEVICES
        # ------------------------------------------------------------

        for index, device in enumerate(
            self.usb_devices
        ):

            if not isinstance(
                device,
                dict
            ):

                continue

            observations = device.get(
                "observations",
                []
            )

            tree.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    device.get(
                        "device_name",
                        ""
                    ),
                    device.get(
                        "manufacturer",
                        ""
                    ),
                    device.get(
                        "serial_number",
                        ""
                    ),
                    device.get(
                        "first_observed",
                        ""
                    ),
                    device.get(
                        "last_observed",
                        ""
                    ),
                    device.get(
                        "connection_count",
                        len(observations)
                    ),
                    device.get(
                        "evidence_source",
                        ""
                    )
                )
            )

        # ------------------------------------------------------------
        # OBSERVATION DETAILS
        # ------------------------------------------------------------

        detail_label = ttk.Label(
            self.usb_tab,
            text=(
                "Observation History "
                "(installation/observation evidence; "
                "not guaranteed exact physical insertion count)"
            )
        )

        detail_label.pack(
            anchor="w",
            padx=10,
            pady=(5, 2)
        )

        detail_frame = ttk.Frame(
            self.usb_tab
        )

        detail_frame.pack(
            fill="both",
            expand=True,
            padx=5,
            pady=5
        )

        detail_columns = (
            "timestamp",
            "event",
            "source",
            "detail"
        )

        detail_tree = ttk.Treeview(
            detail_frame,
            columns=detail_columns,
            show="headings"
        )

        detail_headings = {
            "timestamp": "Timestamp",
            "event": "Event",
            "source": "Source",
            "detail": "Detail"
        }

        for column in detail_columns:

            detail_tree.heading(
                column,
                text=detail_headings[column]
            )

            detail_tree.column(
                column,
                width=200,
                anchor="w"
            )

        detail_scroll = ttk.Scrollbar(
            detail_frame,
            orient="vertical",
            command=detail_tree.yview
        )

        detail_tree.configure(
            yscrollcommand=detail_scroll.set
        )

        detail_tree.pack(
            side="left",
            fill="both",
            expand=True
        )

        detail_scroll.pack(
            side="right",
            fill="y"
        )

        # ------------------------------------------------------------
        # SELECT DEVICE
        # ------------------------------------------------------------

        def show_usb_observations(event):

            selection = tree.selection()

            detail_tree.delete(
                *detail_tree.get_children()
            )

            if not selection:

                return

            selected_id = selection[0]

            try:

                index = int(
                    selected_id
                )

            except ValueError:

                return

            if index >= len(
                self.usb_devices
            ):

                return

            device = self.usb_devices[
                index
            ]

            observations = device.get(
                "observations",
                []
            )

            for observation in observations:

                if not isinstance(
                    observation,
                    dict
                ):

                    continue

                detail_tree.insert(
                    "",
                    "end",
                    values=(
                        observation.get(
                            "timestamp",
                            ""
                        ),
                        observation.get(
                            "event",
                            ""
                        ),
                        observation.get(
                            "source",
                            ""
                        ),
                        observation.get(
                            "detail",
                            ""
                        )
                    )
                )

        tree.bind(
            "<<TreeviewSelect>>",
            show_usb_observations
        )

    # ================================================================
    # EVENT LOGS
    # ================================================================

    def display_events(self):

        for widget in self.events_tab.winfo_children():

            widget.destroy()

        columns = (
            "time",
            "event_id",
            "level",
            "message"
        )

        tree = self.create_treeview(
            self.events_tab,
            columns
        )

        for item in self.events:

            if isinstance(item, dict):

                tree.insert(
                    "",
                    "end",
                    values=(
                        item.get(
                            "timestamp",
                            item.get(
                                "time",
                                ""
                            )
                        ),
                        item.get(
                            "event_id",
                            item.get(
                                "id",
                                ""
                            )
                        ),
                        item.get(
                            "level",
                            ""
                        ),
                        item.get(
                            "message",
                            item.get(
                                "description",
                                ""
                            )
                        )
                    )
                )

    # ================================================================
    # ADS
    # ================================================================

    def display_ads(self):

        for widget in self.ads_tab.winfo_children():

            widget.destroy()

        columns = (
            "path",
            "stream",
            "size"
        )

        tree = self.create_treeview(
            self.ads_tab,
            columns
        )

        for item in self.ads_findings:

            if isinstance(item, dict):

                tree.insert(
                    "",
                    "end",
                    values=(
                        item.get(
                            "path",
                            ""
                        ),
                        item.get(
                            "stream",
                            item.get(
                                "name",
                                ""
                            )
                        ),
                        item.get(
                            "size",
                            item.get(
                                "size_bytes",
                                ""
                            )
                        )
                    )
                )

    # ================================================================
    # BROWSER
    # ================================================================

    def display_browser(self):

        for widget in self.browser_tab.winfo_children():

            widget.destroy()

        # ------------------------------------------------------------
        # INNER NOTEBOOK
        # ------------------------------------------------------------

        browser_notebook = ttk.Notebook(
            self.browser_tab
        )

        browser_notebook.pack(
            fill="both",
            expand=True,
            padx=5,
            pady=5
        )

        history_tab = ttk.Frame(
            browser_notebook
        )

        search_tab = ttk.Frame(
            browser_notebook
        )

        downloads_tab = ttk.Frame(
            browser_notebook
        )

        deleted_tab = ttk.Frame(
            browser_notebook
        )

        cleanup_tab = ttk.Frame(
            browser_notebook
        )

        browser_notebook.add(
            history_tab,
            text="History"
        )

        browser_notebook.add(
            search_tab,
            text="Search Activity"
        )

        browser_notebook.add(
            downloads_tab,
            text="Downloads"
        )

        browser_notebook.add(
            deleted_tab,
            text="Deleted / Recoverable"
        )

        browser_notebook.add(
            cleanup_tab,
            text="Cleanup Indicators"
        )

        # ------------------------------------------------------------
        # GET DATA
        # ------------------------------------------------------------

        results = self.browser_results

        if not isinstance(
            results,
            dict
        ):

            results = {}

        history_records = results.get(
            "history_records",
            []
        )

        search_records = results.get(
            "search_records",
            []
        )

        download_records = results.get(
            "download_records",
            []
        )

        deleted_records = results.get(
            "deleted_records",
            []
        )

        cleanup_records = results.get(
            "cleanup_indicators",
            []
        )

        # ------------------------------------------------------------
        # HISTORY
        # ------------------------------------------------------------

        history_columns = (
            "datetime",
            "browser",
            "url",
            "title",
            "visit_count",
            "source"
        )

        history_tree = self.create_treeview(
            history_tab,
            history_columns
        )

        for item in history_records:

            if not isinstance(
                item,
                dict
            ):

                continue

            history_tree.insert(
                "",
                "end",
                values=(
                    item.get(
                        "datetime",
                        item.get(
                            "visit_time",
                            ""
                        )
                    ),
                    item.get(
                        "browser",
                        ""
                    ),
                    item.get(
                        "url",
                        ""
                    ),
                    item.get(
                        "title",
                        ""
                    ),
                    item.get(
                        "visit_count",
                        ""
                    ),
                    item.get(
                        "source",
                        ""
                    )
                )
            )

        # ------------------------------------------------------------
        # SEARCH ACTIVITY
        # ------------------------------------------------------------

        search_columns = (
            "datetime",
            "browser",
            "engine",
            "query",
            "url",
            "source"
        )

        search_tree = self.create_treeview(
            search_tab,
            search_columns
        )

        for item in search_records:

            if not isinstance(
                item,
                dict
            ):

                continue

            search_tree.insert(
                "",
                "end",
                values=(
                    item.get(
                        "datetime",
                        item.get(
                            "visit_time",
                            ""
                        )
                    ),
                    item.get(
                        "browser",
                        ""
                    ),
                    item.get(
                        "search_engine",
                        item.get(
                            "engine",
                            ""
                        )
                    ),
                    item.get(
                        "search_query",
                        item.get(
                            "query",
                            ""
                        )
                    ),
                    item.get(
                        "url",
                        ""
                    ),
                    item.get(
                        "source",
                        ""
                    )
                )
            )

        # ------------------------------------------------------------
        # DOWNLOADS
        # ------------------------------------------------------------

        download_columns = (
            "browser",
            "file",
            "download_time",
            "url",
            "local_path",
            "source"
        )

        download_tree = self.create_treeview(
            downloads_tab,
            download_columns
        )

        for item in download_records:

            if not isinstance(
                item,
                dict
            ):

                continue

            download_tree.insert(
                "",
                "end",
                values=(
                    item.get(
                        "browser",
                        ""
                    ),
                    item.get(
                        "file_name",
                        item.get(
                            "file",
                            ""
                        )
                    ),
                    item.get(
                        "download_time",
                        item.get(
                            "datetime",
                            ""
                        )
                    ),
                    item.get(
                        "url",
                        ""
                    ),
                    item.get(
                        "local_path",
                        item.get(
                            "path",
                            ""
                        )
                    ),
                    item.get(
                        "source",
                        ""
                    )
                )
            )

        # ------------------------------------------------------------
        # DELETED / RECOVERABLE
        # ------------------------------------------------------------

        deleted_columns = (
            "browser",
            "status",
            "source",
            "description"
        )

        deleted_tree = self.create_treeview(
            deleted_tab,
            deleted_columns
        )

        for item in deleted_records:

            if not isinstance(
                item,
                dict
            ):

                continue

            deleted_tree.insert(
                "",
                "end",
                values=(
                    item.get(
                        "browser",
                        ""
                    ),
                    item.get(
                        "status",
                        "Recovery Indicator"
                    ),
                    item.get(
                        "source",
                        ""
                    ),
                    item.get(
                        "description",
                        ""
                    )
                )
            )

        # ------------------------------------------------------------
        # CLEANUP INDICATORS
        # ------------------------------------------------------------

        cleanup_columns = (
            "type",
            "description"
        )

        cleanup_tree = self.create_treeview(
            cleanup_tab,
            cleanup_columns
        )

        for item in cleanup_records:

            if not isinstance(
                item,
                dict
            ):

                continue

            cleanup_tree.insert(
                "",
                "end",
                values=(
                    item.get(
                        "type",
                        ""
                    ),
                    item.get(
                        "description",
                        ""
                    )
                )
            )

    # ================================================================
    # PREFETCH
    # ================================================================

    def display_prefetch(self):

        for widget in self.prefetch_tab.winfo_children():

            widget.destroy()

        columns = (
            "file",
            "path",
            "run_count",
            "last_run"
        )

        tree = self.create_treeview(
            self.prefetch_tab,
            columns
        )

        for item in self.prefetch_results:

            if isinstance(item, dict):

                tree.insert(
                    "",
                    "end",
                    values=(
                        item.get(
                            "file_name",
                            item.get(
                                "name",
                                ""
                            )
                        ),
                        item.get(
                            "path",
                            ""
                        ),
                        item.get(
                            "run_count",
                            ""
                        ),
                        item.get(
                            "last_run",
                            ""
                        )
                    )
                )

    # ================================================================
    # RECYCLE BIN
    # ================================================================

    def display_recycle_bin(self):

        for widget in self.recycle_tab.winfo_children():

            widget.destroy()

        columns = (
            "name",
            "original_path",
            "deleted_time",
            "size"
        )

        tree = self.create_treeview(
            self.recycle_tab,
            columns
        )

        for item in self.recycle_results:

            if isinstance(item, dict):

                tree.insert(
                    "",
                    "end",
                    values=(
                        item.get(
                            "name",
                            ""
                        ),
                        item.get(
                            "original_path",
                            ""
                        ),
                        item.get(
                            "deleted_time",
                            ""
                        ),
                        item.get(
                            "size",
                            item.get(
                                "size_bytes",
                                ""
                            )
                        )
                    )
                )

    # ================================================================
    # TIMELINE
    # ================================================================

    def display_timeline(self):

        for widget in self.timeline_tab.winfo_children():

            widget.destroy()

        columns = (
            "timestamp",
            "source",
            "event",
            "description"
        )

        tree = self.create_treeview(
            self.timeline_tab,
            columns
        )

        for item in self.timeline:

            if isinstance(item, dict):

                tree.insert(
                    "",
                    "end",
                    values=(
                        item.get(
                            "timestamp",
                            ""
                        ),
                        item.get(
                            "source",
                            ""
                        ),
                        item.get(
                            "event",
                            ""
                        ),
                        item.get(
                            "description",
                            item.get(
                                "detail",
                                ""
                            )
                        )
                    )
                )

    # ================================================================
    # CORRELATION
    # ================================================================

    def display_correlation(self):

        for widget in self.correlation_tab.winfo_children():

            widget.destroy()

        text = tk.Text(
            self.correlation_tab,
            wrap="word"
        )

        text.pack(
            fill="both",
            expand=True
        )

        text.insert(
            tk.END,
            "Correlated Findings\n"
        )

        text.insert(
            tk.END,
            "=" * 60
        )

        text.insert(
            tk.END,
            "\n\n"
        )

        if not self.all_findings:

            text.insert(
                tk.END,
                "No correlated findings available."
            )

            return

        for index, finding in enumerate(
            self.all_findings,
            start=1
        ):

            text.insert(
                tk.END,
                "{}. {}\n".format(
                    index,
                    finding.get(
                        "category",
                        ""
                    )
                )
            )

            text.insert(
                tk.END,
                "   {}\n\n".format(
                    finding.get(
                        "finding",
                        ""
                    )
                )
            )

    # ================================================================
    # REPORTS TAB
    # ================================================================

    def build_reports_tab(self):

        for widget in self.reports_tab.winfo_children():

            widget.destroy()

        title = ttk.Label(
            self.reports_tab,
            text="Forensic Reports"
        )

        title.pack(
            pady=20
        )

        info = ttk.Label(
            self.reports_tab,
            text=(
                "PDF, Excel and CSV report generation "
                "will be connected here."
            )
        )

        info.pack(
            pady=10
        )

        self.pdf_button = ttk.Button(
            self.reports_tab,
            text="Generate PDF Report",
            state="disabled"
        )

        self.pdf_button.pack(
            pady=5
        )

        self.excel_button = ttk.Button(
            self.reports_tab,
            text="Export Excel",
            state="disabled"
        )

        self.excel_button.pack(
            pady=5
        )

        self.csv_button = ttk.Button(
            self.reports_tab,
            text="Export CSV",
            state="disabled"
        )

        self.csv_button.pack(
            pady=5
        )

    # ================================================================
    # CLEAR DATA
    # ================================================================

    def clear_data(self):

        self.filesystem_result = {}

        self.timestamp_findings = []

        self.suspicious_files = []

        self.programs = []

        self.usb_devices = []

        self.events = []

        self.ads_findings = []

        self.browser_results = {}

        self.browser_findings = []

        self.prefetch_results = []

        self.recycle_results = []

        self.all_findings = []

        self.timeline = []

        self.dashboard_text.delete(
            "1.0",
            tk.END
        )

        for tab in [
            self.filesystem_tab,
            self.timestamps_tab,
            self.suspicious_tab,
            self.registry_tab,
            self.usb_tab,
            self.events_tab,
            self.ads_tab,
            self.browser_tab,
            self.prefetch_tab,
            self.recycle_tab,
            self.timeline_tab,
            self.correlation_tab
        ]:

            for widget in tab.winfo_children():

                widget.destroy()

    # ================================================================
    # INVESTIGATION ERROR
    # ================================================================

    def investigation_error(
        self,
        error
    ):

        self.progress.stop()

        self.start_button.config(
            state="normal"
        )

        self.investigation_running = False

        self.status_label.config(
            text="Investigation failed."
        )

        messagebox.showerror(
            "Investigation Error",
            "The investigation failed.\n\n{}".format(
                error
            )
        )

        print(
            traceback.format_exc()
        )


# ====================================================================
# MAIN
# ====================================================================

if __name__ == "__main__":

    root = tk.Tk()

    app = ForensicApplication(
        root
    )

    root.mainloop()
