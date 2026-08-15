"""Tkinter desktop interface.

Six tabs following the order the work is actually done in: identify the case,
attach the evidence, connect the camera, set the analysis parameters, read the
result, and build the bundle to hand over.

Long operations run on worker threads and post results back to the Tk thread
through a queue, so the window never freezes mid-analysis.
"""

from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
import traceback
import webbrowser
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .. import __version__, __tool_name__
from ..config import AppConfig
from ..correlate import run_analysis
from ..csvout import write_correlation_csv, write_events_csv, write_incidents_csv
from ..hashing import Provenance, record_file
from ..report import write_manifest, write_report
from ..stats import VERDICT_FOUND, VERDICT_INSUFFICIENT
from ..timeutil import DEFAULT_TZ
from .liveview import LiveView
from .widgets import FileList, LabeledEntry, LogPane, PALETTE, ScrollFrame, make_table

COMMON_ZONES = [
    "America/New_York", "America/Chicago", "America/Denver", "America/Phoenix",
    "America/Los_Angeles", "America/Anchorage", "Pacific/Honolulu", "UTC",
    "Europe/London", "Europe/Berlin", "Australia/Sydney",
]


class App(ttk.Frame):
    def __init__(self, master: tk.Tk, config: AppConfig | None = None):
        super().__init__(master, padding=0)
        self.master = master
        self.config_model = config or AppConfig()
        self.analysis = None
        self.recorder = None
        self.camera_password = tk.StringVar(
            value=os.environ.get("DEAUTH_CORRELATOR_CAMPASS", ""))
        self.events_queue: queue.Queue = queue.Queue()
        self._timeline_image = None

        master.title(f"{__tool_name__} {__version__} - wireless disruption correlator")
        master.geometry("1120x820")
        master.minsize(940, 660)

        self.pack(fill="both", expand=True)
        self._build_header()

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=(0, 6))

        self._build_case_tab()
        self._build_evidence_tab()
        self._build_camera_tab()
        self._build_analyze_tab()
        self._build_results_tab()
        self._build_bundle_tab()

        self._build_statusbar()
        self._apply_config_to_widgets()
        self.after(120, self._drain_queue)
        # A single read of the releases API, a moment after the window is
        # up so it never delays the program starting. Turned off by the box
        # on the Case tab, after which nothing but the camera is contacted.
        if self.config_model.check_for_updates:
            self.after(1500, lambda: self._check_updates(quiet=True))
        master.protocol("WM_DELETE_WINDOW", self._on_close)

    # -- chrome ----------------------------------------------------------

    def _build_header(self) -> None:
        header = ttk.Frame(self, padding=(12, 10, 12, 6))
        header.pack(fill="x")
        ttk.Label(header, text="deauth-correlator",
                  font=("Segoe UI", 15, "bold")).pack(side="left")
        ttk.Label(header,
                  text="  read-only forensic analysis - never transmits, never attacks",
                  foreground=PALETTE["muted"]).pack(side="left", padx=(6, 0))

        self.verdict_var = tk.StringVar(value="No analysis run yet.")
        self.verdict_label = ttk.Label(self, textvariable=self.verdict_var,
                                       font=("Segoe UI", 10, "bold"),
                                       foreground=PALETTE["muted"],
                                       wraplength=1080, justify="left",
                                       padding=(12, 0, 12, 8))
        self.verdict_label.pack(fill="x")

    def _build_statusbar(self) -> None:
        bar = ttk.Frame(self, relief="groove", padding=(10, 4))
        bar.pack(fill="x", side="bottom")
        self.status_var = tk.StringVar(value="Ready.")
        ttk.Label(bar, textvariable=self.status_var).pack(side="left")
        self.progress = ttk.Progressbar(bar, mode="indeterminate", length=160)
        self.progress.pack(side="right")

    # -- tab 1: case -----------------------------------------------------

    def _build_case_tab(self) -> None:
        scroll = ScrollFrame(self.notebook)
        self.notebook.add(scroll, text="1. Case")
        body = ttk.Frame(scroll.body, padding=16)
        body.pack(fill="both", expand=True)

        ttk.Label(body, text="Case identification",
                  font=("Segoe UI", 12, "bold")).pack(anchor="w")
        ttk.Label(body, foreground=PALETTE["muted"], wraplength=820, justify="left",
                  text="These details are printed on the report header and recorded in "
                       "the manifest. Fill them in before producing anything you intend "
                       "to hand to someone else.").pack(anchor="w", pady=(2, 12))

        self.case_number = LabeledEntry(body, "Case number", 36)
        self.case_number.pack(anchor="w", pady=3)
        self.operator = LabeledEntry(body, "Prepared by", 36)
        self.operator.pack(anchor="w", pady=3)
        self.agency = LabeledEntry(body, "Agency / organization", 36)
        self.agency.pack(anchor="w", pady=3)

        ttk.Label(body, text="Case notes", anchor="w").pack(anchor="w", pady=(12, 2))
        self.case_notes = tk.Text(body, height=5, width=90, wrap="word")
        self.case_notes.pack(anchor="w", fill="x")

        ttk.Separator(body).pack(fill="x", pady=16)
        ttk.Label(body, text="Timezone", font=("Segoe UI", 12, "bold")).pack(anchor="w")
        ttk.Label(body, foreground=PALETTE["muted"], wraplength=820, justify="left",
                  text="Every local time shown in the outputs uses this zone. The UTC "
                       "offset written in each source file is preserved separately and "
                       "reported, so nothing is lost by converting.").pack(
            anchor="w", pady=(2, 8))

        row = ttk.Frame(body)
        row.pack(anchor="w")
        ttk.Label(row, text="Timezone", width=22, anchor="w").grid(row=0, column=0)
        self.tz_var = tk.StringVar(value=DEFAULT_TZ)
        ttk.Combobox(row, textvariable=self.tz_var, values=COMMON_ZONES,
                     width=34).grid(row=0, column=1, sticky="w")

        self.log_year = LabeledEntry(
            body, "Syslog year (optional)", 12,
            hint="For logs whose lines carry no year. Inferred from the file date "
                 "if blank.")
        self.log_year.pack(anchor="w", pady=(8, 3))
        self.clock_offset = LabeledEntry(
            body, "Camera clock offset (s)", 12, value="0",
            hint="Added to every camera timestamp. Measure it on the Camera tab.")
        self.clock_offset.pack(anchor="w", pady=3)

        ttk.Separator(body).pack(fill="x", pady=16)
        ttk.Label(body, text="Updates", font=("Segoe UI", 12, "bold")).pack(anchor="w")
        ttk.Label(body, foreground=PALETTE["muted"], wraplength=820, justify="left",
                  text="The program checks for a newer release when it starts. That is "
                       "one read of the GitHub releases API and sends nothing about "
                       "you or this machine. Installing is always a separate step: the "
                       "version that produced a report is recorded in it, so the "
                       "program never replaces itself behind your back."
                  ).pack(anchor="w", pady=(2, 8))

        self.update_status = tk.StringVar(value="Not checked yet.")
        ttk.Label(body, textvariable=self.update_status,
                  wraplength=820, justify="left").pack(anchor="w", pady=(0, 6))

        update_row = ttk.Frame(body)
        update_row.pack(anchor="w")
        ttk.Button(update_row, text="Check now",
                   command=self._check_updates).pack(side="left")
        self.update_install_btn = ttk.Button(
            update_row, text="Download and stage update",
            command=self._install_update, state="disabled")
        self.update_install_btn.pack(side="left", padx=(8, 0))
        ttk.Button(update_row, text="What does it contact?",
                   command=self._show_update_endpoints).pack(side="left", padx=(8, 0))

        self.auto_update_check = tk.BooleanVar(value=True)
        ttk.Checkbutton(body, text="Check for updates when the program starts",
                        variable=self.auto_update_check).pack(anchor="w", pady=(6, 0))

        ttk.Separator(body).pack(fill="x", pady=16)
        buttons = ttk.Frame(body)
        buttons.pack(anchor="w")
        ttk.Button(buttons, text="Save case file…",
                   command=self._save_case).pack(side="left")
        ttk.Button(buttons, text="Open case file…",
                   command=self._open_case).pack(side="left", padx=(8, 0))
        ttk.Label(body, foreground=PALETTE["muted"], wraplength=820, justify="left",
                  text="A case file stores the inputs and every analysis parameter so "
                       "the same run can be reproduced later. Camera passwords are "
                       "never written to it.").pack(anchor="w", pady=(8, 0))

    # -- tab 2: evidence -------------------------------------------------

    def _build_evidence_tab(self) -> None:
        scroll = ScrollFrame(self.notebook)
        self.notebook.add(scroll, text="2. Evidence")
        body = ttk.Frame(scroll.body, padding=16)
        body.pack(fill="both", expand=True)

        self.opnsense_list = FileList(
            body, "OPNsense DHCP / system logs",
            "dnsmasq, Kea or ISC dhcpd logs, and hostapd or kernel wireless events. "
            "Repeated re-association by the same client becomes a client-drop event.",
            on_change=self._refresh_evidence_summary,
            filetypes=[("Log files", "*.log *.txt *.syslog"), ("All files", "*.*")])
        self.opnsense_list.pack(fill="x", pady=(0, 6))

        self.capture_list = FileList(
            body, "802.11 monitor-mode evidence",
            "The .cap/.pcap/.pcapng from 'airodump-ng --write' is the primary source - "
            "reason codes exist only in the frames themselves. Kismet .kismet "
            "databases, airodump CSVs and nzyme/tshark CSVs are also accepted.",
            on_change=self._refresh_evidence_summary,
            filetypes=[("Captures and logs",
                        "*.cap *.pcap *.pcapng *.kismet *.csv"),
                       ("All files", "*.*")])
        self.capture_list.pack(fill="x", pady=(0, 6))

        self.camera_list = FileList(
            body, "Camera events",
            "A CSV of timestamp,plate,make,model,notes - or a folder of recorded clips, "
            "whose start times are read from the filenames.",
            on_change=self._refresh_evidence_summary, allow_dirs=True,
            filetypes=[("CSV files", "*.csv *.tsv *.txt"), ("All files", "*.*")])
        self.camera_list.pack(fill="x", pady=(0, 6))

        ttk.Separator(body).pack(fill="x", pady=10)
        self._build_fetch_block(body)

        ttk.Separator(body).pack(fill="x", pady=10)
        ttk.Label(body, text="Detected formats and file hashes",
                  font=("Segoe UI", 11, "bold")).pack(anchor="w")
        ttk.Label(body, foreground=PALETTE["muted"], wraplength=820, justify="left",
                  text="Each file is hashed as soon as it is attached, so the "
                       "chain of custody starts before any analysis runs.").pack(
            anchor="w", pady=(2, 6))

        frame, self.evidence_tree = make_table(body, [
            ("File", 260), ("Role", 110), ("Detected format", 200),
            ("Size", 90), ("SHA-256", 300)], height=8)
        frame.pack(fill="both", expand=True)
        ttk.Button(body, text="Re-check attached files",
                   command=self._refresh_evidence_summary).pack(anchor="w", pady=8)


    # -- pulling the logs off the firewall -------------------------------

    def _build_fetch_block(self, body) -> None:
        """Fetch the OPNsense logs instead of exporting them by hand.

        The window is taken from the camera events attached above, so the
        ordinary way to use this is: attach the camera events, press Fetch. The
        logs are the part the firewall already has; the camera events are the
        part only the operator can produce.
        """
        ttk.Label(body, text="Pull the logs off the firewall",
                  font=("Segoe UI", 11, "bold")).pack(anchor="w")
        ttk.Label(body, foreground=PALETTE["muted"], wraplength=820,
                  justify="left",
                  text="Reads the DHCP and system logs straight from OPNsense for "
                       "the period your camera events cover, and attaches them "
                       "above. This only ever reads - the one API action that "
                       "would delete a log cannot be reached from here. The API "
                       "secret is held for this session only and is never written "
                       "to the case file.").pack(anchor="w", pady=(2, 6))

        grid = ttk.Frame(body)
        grid.pack(fill="x")
        left = ttk.Frame(grid)
        left.pack(side="left", anchor="n")
        right = ttk.Frame(grid)
        right.pack(side="left", anchor="n", padx=(24, 0))

        self.fw_host = LabeledEntry(left, "Firewall address", 30,
                                    value=self.config_model.firewall_host)
        self.fw_host.pack(anchor="w", pady=3)
        self.fw_key = LabeledEntry(left, "API key", 30,
                                   value=self.config_model.firewall_key)
        self.fw_key.pack(anchor="w", pady=3)
        self.fw_secret = LabeledEntry(right, "API secret", 30, show="*")
        self.fw_secret.pack(anchor="w", pady=3)
        self.fw_margin = LabeledEntry(
            right, "Baseline margin (hours)", 30,
            value=f"{self.config_model.firewall_margin_h:g}")
        self.fw_margin.pack(anchor="w", pady=3)

        tls = ttk.Frame(body)
        tls.pack(fill="x", pady=(6, 0))
        self.fw_tls_mode = tk.StringVar(value=self.config_model.firewall_tls_mode)
        ttk.Label(tls, text="Certificate:", width=22, anchor="w").pack(side="left")
        for label, value in (("verify normally", "verify"),
                             ("pin it", "pin"),
                             ("do not check", "insecure")):
            ttk.Radiobutton(tls, text=label, value=value,
                            variable=self.fw_tls_mode,
                            command=self._fetch_tls_changed).pack(side="left",
                                                                  padx=(0, 12))
        self.fw_fingerprint = LabeledEntry(
            body, "Pinned SHA-256", 64,
            value=self.config_model.firewall_fingerprint)
        self.fw_fingerprint.pack(anchor="w", pady=3)

        row = ttk.Frame(body)
        row.pack(anchor="w", pady=(8, 0))
        self.fw_fetch_btn = ttk.Button(row, text="Fetch logs for my camera events",
                                       command=self._fetch_logs)
        self.fw_fetch_btn.pack(side="left")
        ttk.Button(row, text="Test connection",
                   command=self._fetch_probe).pack(side="left", padx=(8, 0))
        ttk.Button(row, text="Read fingerprint",
                   command=self._fetch_fingerprint).pack(side="left", padx=(8, 0))

        self.fw_status = tk.StringVar(value="Not connected.")
        ttk.Label(body, textvariable=self.fw_status, foreground=PALETTE["muted"],
                  wraplength=820, justify="left").pack(anchor="w", pady=(6, 0))
        self.fetch_log = LogPane(body, height=7)
        self.fetch_log.pack(fill="x", pady=(6, 0))
        self._fetch_tls_changed()

    def _fetch_tls_changed(self) -> None:
        pinning = self.fw_tls_mode.get() == "pin"
        self.fw_fingerprint.entry.configure(
            state="normal" if pinning else "disabled")

    def _firewall_config(self):
        from ..firewall import FirewallConfig

        mode = self.fw_tls_mode.get()
        return FirewallConfig(
            host=self.fw_host.get().strip(),
            key=self.fw_key.get().strip(),
            secret=self.fw_secret.get(),
            verify=False if mode == "insecure" else True,
            fingerprint=(self.fw_fingerprint.get().strip()
                         if mode == "pin" else ""))

    def _fetch_fingerprint(self) -> None:
        from ..firewall.opnsense_api import FirewallError, certificate_fingerprint

        host = self.fw_host.get().strip()
        if not host:
            messagebox.showinfo("Firewall address",
                                "Enter the firewall's address first.")
            return
        self.fw_status.set("Reading the certificate \u2026")

        def work():
            try:
                self._post("fetch_fingerprint", certificate_fingerprint(host))
            except FirewallError as exc:
                self._post("fetch_failed", exc)

        threading.Thread(target=work, name="fw-fingerprint", daemon=True).start()

    def _fetch_probe(self) -> None:
        from ..firewall import FirewallError
        from ..firewall.fetch import _product_name
        from ..firewall.opnsense_api import OpnsenseClient

        config = self._firewall_config()
        if not config.is_configured():
            messagebox.showinfo(
                "Firewall details",
                "Enter the address, the API key and the API secret.\n\n"
                "Create a key under System > Access > Users > (your user) > "
                "API keys. It downloads as a text file holding both halves.")
            return
        self.fw_status.set("Connecting \u2026")

        def work():
            try:
                with OpnsenseClient(config) as client:
                    identity = client.identify()
                self._post("fetch_probed",
                           f"{_product_name(identity)} at {config.host}. The API "
                           f"key was accepted. Certificate: "
                           f"{config.tls_description()}")
            except FirewallError as exc:
                self._post("fetch_failed", exc)

        threading.Thread(target=work, name="fw-probe", daemon=True).start()

    def _fetch_logs(self) -> None:
        from ..firewall import FirewallError, fetch_logs, window_from_events

        config = self._firewall_config()
        if not config.is_configured():
            messagebox.showinfo(
                "Firewall details",
                "Enter the address, the API key and the API secret first.")
            return

        app_config = self._collect_config()
        if not app_config.camera_events:
            messagebox.showinfo(
                "Camera events first",
                "Attach the camera events above before fetching.\n\n"
                "They decide which stretch of log matters: the tool pulls the "
                "period they cover plus a margin either side, so the analysis "
                "has a quiet period to compare against.")
            return
        if config.verify is False and not config.fingerprint:
            if not messagebox.askokcancel(
                    "Certificate will not be checked",
                    "With 'do not check' selected, this connection does not "
                    "establish which machine answered.\n\n"
                    "Every log fetched this way is marked UNVERIFIED inside the "
                    "file, and the analysis repeats that in its warnings. "
                    "Continue?"):
                return
        try:
            margin = float(self.fw_margin.get() or 2.0)
        except ValueError:
            messagebox.showerror("Baseline margin",
                                 "The baseline margin must be a number of hours.")
            return

        self.fw_fetch_btn.configure(state="disabled")
        self.fw_status.set("Working out the window \u2026")
        self.fetch_log.clear()
        self._busy("Fetching logs from the firewall \u2026")
        outdir = str(Path(app_config.outdir or "output") / "fetched-logs")

        def work():
            try:
                times = self._camera_event_times(app_config)
                since, until = window_from_events(times, margin)
                self._post("fetch_progress",
                           f"Window {since:%Y-%m-%d %H:%M} to "
                           f"{until:%Y-%m-%d %H:%M} UTC")
                result = fetch_logs(
                    config, since, until, outdir,
                    progress=lambda m: self._post("fetch_progress", m))
                self._post("fetch_done", result)
            except Exception as exc:                       # noqa: BLE001
                self._post("fetch_failed", exc)

        threading.Thread(target=work, name="fw-fetch", daemon=True).start()

    def _camera_event_times(self, app_config):
        """Timestamps of every attached camera event, for the fetch window.

        Read through the same parsers and the same time context the analysis
        would use, so the window is expressed in the same terms as the answer.
        """
        from ..parsers import ParseContext, parse_path
        from ..timeutil import TimeContext

        time_ctx = TimeContext(app_config.timezone, app_config.log_year,
                               app_config.assume_offset or None)
        times = []
        for raw in app_config.camera_events:
            path = Path(raw).expanduser()
            if not path.exists():
                continue
            ctx = ParseContext(
                time=time_ctx,
                clock_offset_s=app_config.camera_clock_offset_s,
                options={"clip_time_from": app_config.clip_time_from})
            rows, _parser = parse_path(path, ctx, "camera-events", None)
            times.extend(row["ts_utc"] for row in rows
                         if row.get("ts_utc") is not None)
        return times

    # -- tab 3: camera ---------------------------------------------------

    def _build_camera_tab(self) -> None:
        scroll = ScrollFrame(self.notebook)
        self.notebook.add(scroll, text="3. Camera")
        body = ttk.Frame(scroll.body, padding=16)
        body.pack(fill="both", expand=True)

        ttk.Label(body, text="TP-Link Tapo C100 (and other ONVIF cameras)",
                  font=("Segoe UI", 12, "bold")).pack(anchor="w")
        ttk.Label(body, foreground=PALETTE["muted"], wraplength=840, justify="left",
                  text="Use the Camera Account created in the Tapo app under Device "
                       "Settings > Advanced Settings > Camera Account. That is not the "
                       "TP-Link cloud login and the cloud login will not work here. "
                       "The password is held in memory for this session only - it is "
                       "never written to the case file, the report or the bundle."
                  ).pack(anchor="w", pady=(2, 12))

        grid = ttk.Frame(body)
        grid.pack(anchor="w")
        self.cam_host = LabeledEntry(grid, "Camera IP address", 22,
                                     hint="e.g. 192.168.1.50")
        self.cam_host.pack(anchor="w", pady=3)
        self.cam_user = LabeledEntry(grid, "Camera account username", 22)
        self.cam_user.pack(anchor="w", pady=3)

        row = ttk.Frame(grid)
        row.pack(anchor="w", pady=3)
        ttk.Label(row, text="Camera account password", width=22,
                  anchor="w").grid(row=0, column=0, sticky="w")
        self.cam_pass_entry = ttk.Entry(row, textvariable=self.camera_password,
                                        width=22, show="•")
        self.cam_pass_entry.grid(row=0, column=1, sticky="w")
        self.show_pass = tk.BooleanVar(value=False)
        ttk.Checkbutton(row, text="show", variable=self.show_pass,
                        command=self._toggle_password).grid(row=0, column=2,
                                                            padx=(8, 0))

        ports = ttk.Frame(grid)
        ports.pack(anchor="w", pady=3)
        ttk.Label(ports, text="ONVIF / RTSP ports", width=22,
                  anchor="w").grid(row=0, column=0, sticky="w")
        self.cam_onvif_port = tk.StringVar(value="2020")
        self.cam_rtsp_port = tk.StringVar(value="554")
        ttk.Entry(ports, textvariable=self.cam_onvif_port, width=8).grid(row=0, column=1)
        ttk.Entry(ports, textvariable=self.cam_rtsp_port, width=8).grid(row=0, column=2,
                                                                        padx=(6, 0))
        self.cam_stream = tk.StringVar(value="hd")
        ttk.Combobox(ports, textvariable=self.cam_stream, values=["hd", "sd"],
                     width=6, state="readonly").grid(row=0, column=3, padx=(10, 0))

        buttons = ttk.Frame(body)
        buttons.pack(anchor="w", pady=(12, 6))
        ttk.Button(buttons, text="Test connection and clock",
                   command=self._camera_probe).pack(side="left")
        ttk.Button(buttons, text="Save snapshot",
                   command=self._camera_snapshot).pack(side="left", padx=(8, 0))
        ttk.Button(buttons, text="Setup help",
                   command=self._camera_help).pack(side="left", padx=(8, 0))

        ttk.Separator(body).pack(fill="x", pady=12)
        ttk.Label(body, text="Record motion events while you capture",
                  font=("Segoe UI", 11, "bold")).pack(anchor="w")
        ttk.Label(body, foreground=PALETTE["muted"], wraplength=840, justify="left",
                  text="Run this at the same time as airodump-ng. Each motion event is "
                       "appended to a camera-event CSV with a snapshot attached, so "
                       "both sides of the evidence cover exactly the same period - "
                       "which is what the statistics need.").pack(anchor="w",
                                                                  pady=(2, 8))

        watch = ttk.Frame(body)
        watch.pack(anchor="w", fill="x")
        self.watch_csv = LabeledEntry(watch, "Write events to", 46,
                                      value=str(Path.cwd() / "camera_events.csv"))
        self.watch_csv.pack(anchor="w", pady=3)
        self.watch_exhibits = LabeledEntry(watch, "Snapshot folder", 46,
                                           value=str(Path.cwd() / "exhibits"))
        self.watch_exhibits.pack(anchor="w", pady=3)
        self.watch_gap = LabeledEntry(watch, "Ignore repeats within (s)", 8, value="5")
        self.watch_gap.pack(anchor="w", pady=3)

        self.watch_snapshots = tk.BooleanVar(value=True)
        ttk.Checkbutton(body, text="Save a still image for each motion event",
                        variable=self.watch_snapshots).pack(anchor="w", pady=(4, 8))

        watch_buttons = ttk.Frame(body)
        watch_buttons.pack(anchor="w")
        self.watch_start_btn = ttk.Button(watch_buttons, text="Start recording",
                                          command=self._start_watch)
        self.watch_start_btn.pack(side="left")
        self.watch_stop_btn = ttk.Button(watch_buttons, text="Stop",
                                         command=self._stop_watch, state="disabled")
        self.watch_stop_btn.pack(side="left", padx=(8, 0))
        ttk.Button(watch_buttons, text="Attach this CSV as evidence",
                   command=self._attach_watch_csv).pack(side="left", padx=(8, 0))

        ttk.Separator(body).pack(fill="x", pady=12)
        ttk.Label(body, text="Live view",
                  font=("Segoe UI", 11, "bold")).pack(anchor="w")
        ttk.Label(body, foreground=PALETTE["muted"], wraplength=840, justify="left",
                  text="Watch the camera while you set it up, so you can confirm it is "
                       "pointed where you think it is and that the picture is usable "
                       "before you rely on it for evidence. This reads the RTSP stream "
                       "and nothing else; it records nothing unless you save a frame."
                  ).pack(anchor="w", pady=(2, 8))

        # The widget reads the camera settings when Start is pressed rather than
        # at construction, so editing the address or credentials above and
        # pressing Start again picks up the change without rebuilding the tab.
        self.live_view = LiveView(
            body,
            config=self._camera_config,
            exhibits_dir=lambda: self.watch_exhibits.get() or "exhibits",
            tz_name=self.tz_var.get(),
            on_saved=lambda path: self._post("camera_snapshot", path))
        self.live_view.pack(fill="both", expand=True, pady=(0, 8))

        self.camera_log = LogPane(body, height=10)
        self.camera_log.pack(fill="both", expand=True, pady=(10, 0))
        self.camera_log.write(
            "Not connected. Enter the camera address and the camera-account "
            "credentials, then press 'Test connection and clock'.", "muted")

    # -- tab 4: analyze --------------------------------------------------

    def _build_analyze_tab(self) -> None:
        scroll = ScrollFrame(self.notebook)
        self.notebook.add(scroll, text="4. Analyze")
        body = ttk.Frame(scroll.body, padding=16)
        body.pack(fill="both", expand=True)

        ttk.Label(body, text="Correlation parameters",
                  font=("Segoe UI", 12, "bold")).pack(anchor="w")
        ttk.Label(body, foreground=PALETTE["muted"], wraplength=840, justify="left",
                  text="The defaults are the ones documented in the report's "
                       "methodology section. Change them only with a reason you are "
                       "willing to state - every value used is printed in the "
                       "report.").pack(anchor="w", pady=(2, 12))

        grid = ttk.Frame(body)
        grid.pack(anchor="w")
        self.window_s = LabeledEntry(grid, "Coincidence window ±(s)", 10, value="30",
                                     hint="How close counts as simultaneous.")
        self.window_s.pack(anchor="w", pady=3)
        self.alpha = LabeledEntry(grid, "Significance threshold", 10, value="0.01",
                                  hint="p below this is called significant.")
        self.alpha.pack(anchor="w", pady=3)
        self.trials = LabeledEntry(grid, "Permutation trials", 10, value="10000")
        self.trials.pack(anchor="w", pady=3)
        self.reassoc_window = LabeledEntry(
            grid, "Re-association window (s)", 10, value="120",
            hint="A repeat DHCP handshake this soon is a client drop.")
        self.reassoc_window.pack(anchor="w", pady=3)
        self.handshake_window = LabeledEntry(
            grid, "Handshake grouping (s)", 10, value="10",
            hint="Lease messages this close are one join.")
        self.handshake_window.pack(anchor="w", pady=3)
        self.incident_gap = LabeledEntry(
            grid, "Incident grouping (s)", 10, value="10",
            hint="Disruptions this close are one incident.")
        self.incident_gap.pack(anchor="w", pady=3)
        self.camera_dedupe = LabeledEntry(
            grid, "Camera de-duplication (s)", 10, value="2",
            hint="One pass in two camera sources is counted once. 0 disables.")
        self.camera_dedupe.pack(anchor="w", pady=3)
        self.flood_threshold = LabeledEntry(grid, "Flood threshold (frames)", 10,
                                            value="5")
        self.flood_threshold.pack(anchor="w", pady=3)
        self.flood_window = LabeledEntry(grid, "Flood window (s)", 10, value="10")
        self.flood_window.pack(anchor="w", pady=3)

        self.do_sensitivity = tk.BooleanVar(value=True)
        ttk.Checkbutton(body, text="Include the multi-window sensitivity table "
                                   "(recommended - shows the result is not an artifact "
                                   "of the chosen window)",
                        variable=self.do_sensitivity).pack(anchor="w", pady=(8, 4))

        ttk.Separator(body).pack(fill="x", pady=12)
        out = ttk.Frame(body)
        out.pack(anchor="w", fill="x")
        self.outdir = LabeledEntry(out, "Output folder", 52,
                                   value=str(Path.cwd() / "output"))
        self.outdir.pack(side="left", anchor="w")
        ttk.Button(out, text="Browse…", command=self._pick_outdir).pack(side="left",
                                                                        padx=(8, 0))

        run = ttk.Frame(body)
        run.pack(anchor="w", pady=12)
        self.run_button = ttk.Button(run, text="Run analysis",
                                     command=self._run_analysis)
        self.run_button.pack(side="left")
        ttk.Button(run, text="Open output folder",
                   command=lambda: _open_path(self.outdir.get())).pack(side="left",
                                                                       padx=(8, 0))

        self.analyze_log = LogPane(body, height=18)
        self.analyze_log.pack(fill="both", expand=True)

    # -- tab 5: results --------------------------------------------------

    def _build_results_tab(self) -> None:
        outer = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(outer, text="5. Results")

        self.results_banner = tk.Text(outer, height=7, wrap="word",
                                      state="disabled", relief="flat",
                                      background=PALETTE["panel"],
                                      font=("Segoe UI", 10))
        self.results_banner.pack(fill="x", pady=(0, 8))

        panes = ttk.Notebook(outer)
        panes.pack(fill="both", expand=True)

        table_tab = ttk.Frame(panes, padding=6)
        panes.add(table_tab, text="Camera events")
        frame, self.results_tree = make_table(table_tab, [
            ("#", 40), ("Camera event", 160), ("Plate", 80), ("Coincidence", 90),
            ("Nearest disruption", 150), ("Delta", 120), ("Source MAC", 150),
            ("Reason", 260)], height=18)
        frame.pack(fill="both", expand=True)

        stats_tab = ttk.Frame(panes, padding=6)
        panes.add(stats_tab, text="Statistics")
        frame, self.stats_tree = make_table(stats_tab, [
            ("Measure", 320), ("Value", 260), ("Meaning", 520)], height=18)
        frame.pack(fill="both", expand=True)

        flood_tab = ttk.Frame(panes, padding=6)
        panes.add(flood_tab, text="Deauth sources")
        frame, self.flood_tree = make_table(flood_tab, [
            ("Source MAC", 170), ("Frames", 80), ("Share", 80),
            ("Note", 620)], height=18)
        frame.pack(fill="both", expand=True)

        timeline_tab = ttk.Frame(panes, padding=6)
        panes.add(timeline_tab, text="Timeline")
        self.timeline_label = ttk.Label(
            timeline_tab, text="Run an analysis to render the timeline.",
            foreground=PALETTE["muted"])
        self.timeline_label.pack(pady=20)
        ttk.Button(timeline_tab, text="Open timeline.png in the image viewer",
                   command=self._open_timeline).pack()

        buttons = ttk.Frame(outer)
        buttons.pack(anchor="w", pady=(8, 0))
        ttk.Button(buttons, text="Open report.md",
                   command=lambda: _open_path(
                       Path(self.outdir.get()) / "report.md")).pack(side="left")
        ttk.Button(buttons, text="Open correlation.csv",
                   command=lambda: _open_path(
                       Path(self.outdir.get()) / "correlation.csv")).pack(
            side="left", padx=(8, 0))

    # -- tab 6: evidence builder -----------------------------------------

    def _build_bundle_tab(self) -> None:
        scroll = ScrollFrame(self.notebook)
        self.notebook.add(scroll, text="6. Evidence builder")
        body = ttk.Frame(scroll.body, padding=16)
        body.pack(fill="both", expand=True)

        ttk.Label(body, text="Build a handover bundle",
                  font=("Segoe UI", 12, "bold")).pack(anchor="w")
        ttk.Label(body, foreground=PALETTE["muted"], wraplength=840, justify="left",
                  text="Produces a numbered folder holding the report, the tables, the "
                       "figure, hash-verified copies of every source file, your "
                       "exhibits, and a manifest tying them together. Each copy is "
                       "re-hashed after writing; a copy that does not match its "
                       "original is reported rather than quietly included.").pack(
            anchor="w", pady=(2, 12))

        row = ttk.Frame(body)
        row.pack(anchor="w", fill="x")
        self.bundle_dir = LabeledEntry(row, "Bundle folder", 52)
        self.bundle_dir.pack(side="left")
        ttk.Button(row, text="Browse…", command=self._pick_bundle_dir).pack(
            side="left", padx=(8, 0))

        self.bundle_copy_inputs = tk.BooleanVar(value=True)
        self.bundle_zip = tk.BooleanVar(value=True)
        ttk.Checkbutton(body, text="Include hash-verified copies of the source files",
                        variable=self.bundle_copy_inputs).pack(anchor="w", pady=(10, 2))
        ttk.Checkbutton(body, text="Also produce a .zip archive and hash it",
                        variable=self.bundle_zip).pack(anchor="w", pady=2)

        ttk.Separator(body).pack(fill="x", pady=12)
        self.exhibit_list = FileList(
            body, "Exhibits to attach",
            "Camera stills, photographs, screenshots, or any other file you want "
            "carried in the bundle. Snapshots saved on the Camera tab can be added "
            "here.", filetypes=[("All files", "*.*")], height=5)
        self.exhibit_list.pack(fill="x")

        buttons = ttk.Frame(body)
        buttons.pack(anchor="w", pady=(6, 8))
        self.bundle_button = ttk.Button(buttons, text="Build evidence bundle",
                                        command=self._build_bundle)
        self.bundle_button.pack(side="left")
        ttk.Button(buttons, text="Open bundle folder",
                   command=lambda: _open_path(self.bundle_dir.get())).pack(
            side="left", padx=(8, 0))

        self.bundle_log = LogPane(body, height=16)
        self.bundle_log.pack(fill="both", expand=True)

    # -- actions ---------------------------------------------------------

    def _toggle_password(self) -> None:
        self.cam_pass_entry.configure(show="" if self.show_pass.get() else "•")

    def _pick_outdir(self) -> None:
        path = filedialog.askdirectory()
        if path:
            self.outdir.set(path)

    def _pick_bundle_dir(self) -> None:
        path = filedialog.askdirectory()
        if path:
            self.bundle_dir.set(path)

    def _attach_watch_csv(self) -> None:
        path = self.watch_csv.get()
        if not path or not Path(path).exists():
            messagebox.showinfo("Nothing to attach",
                                "Start the recorder first, or pick an existing CSV.")
            return
        self.camera_list.set_paths(self.camera_list.paths() + [path])
        self.notebook.select(1)

    def _refresh_evidence_summary(self) -> None:
        from ..parsers import detect

        self.evidence_tree.delete(*self.evidence_tree.get_children())
        roles = [("opnsense-log", self.opnsense_list.paths()),
                 ("wifi-capture", self.capture_list.paths()),
                 ("camera-events", self.camera_list.paths())]
        for role, paths in roles:
            for raw in paths:
                path = Path(raw)
                if not path.exists():
                    self.evidence_tree.insert("", "end", values=(
                        path.name, role, "FILE NOT FOUND", "-", "-"))
                    continue
                parser, score = detect(path, None)
                label = (f"{parser.name} ({score:.2f})" if parser
                         else "not recognized")
                if path.is_dir():
                    files = [p for p in path.rglob("*") if p.is_file()]
                    size = f"{len(files)} files"
                    digest = "(directory)"
                else:
                    try:
                        record = record_file(path, role)
                        size = f"{record.size_bytes:,} B"
                        digest = record.sha256
                    except OSError as exc:
                        size, digest = "-", f"unreadable: {exc}"
                self.evidence_tree.insert("", "end",
                                          values=(path.name, role, label, size, digest))

    def _camera_probe(self) -> None:
        from ..camera import CameraConfig, probe

        config = self._camera_config()
        if not config.host:
            messagebox.showinfo("Camera address needed",
                                "Enter the camera's IP address first.")
            return
        self.camera_log.clear()
        self.camera_log.write(f"Probing {config.host}:{config.onvif_port} …", "muted")
        self._busy("Probing the camera…")

        def work():
            try:
                result = probe(config)
                self._post("camera_probe", result)
            except Exception as exc:
                self._post("error", ("Camera probe failed", exc))

        threading.Thread(target=work, daemon=True).start()

    def _camera_snapshot(self) -> None:
        from ..camera import snapshot

        config = self._camera_config()
        if not config.host:
            messagebox.showinfo("Camera address needed",
                                "Enter the camera's IP address first.")
            return
        target = Path(self.watch_exhibits.get() or "exhibits") / (
            f"snapshot_{datetime.now():%Y%m%d_%H%M%S}.jpg")
        self._busy("Grabbing a frame…")

        def work():
            try:
                written = snapshot(config, target)
                self._post("camera_snapshot", written)
            except Exception as exc:
                self._post("error", ("Snapshot failed", exc))

        threading.Thread(target=work, daemon=True).start()

    def _camera_help(self) -> None:
        from ..camera import credentials_help
        window = tk.Toplevel(self.master)
        window.title("Camera setup")
        window.geometry("640x420")
        text = tk.Text(window, wrap="word", padx=12, pady=12, font=("Consolas", 9))
        text.pack(fill="both", expand=True)
        text.insert("1.0", credentials_help())
        text.configure(state="disabled")

    def _start_watch(self) -> None:
        from ..camera import MotionRecorder

        config = self._camera_config()
        if not (config.host and config.username):
            messagebox.showinfo(
                "Credentials needed",
                "Motion events need the camera address and the camera-account "
                "username and password.")
            return
        try:
            gap = float(self.watch_gap.get() or 5)
        except ValueError:
            gap = 5.0

        self.recorder = MotionRecorder(
            config, self.watch_csv.get(),
            exhibits_dir=(self.watch_exhibits.get()
                          if self.watch_snapshots.get() else None),
            tz_name=self.tz_var.get(), min_gap_s=gap,
            save_snapshots=self.watch_snapshots.get(),
            on_event=lambda when, note, shot: self._post(
                "motion", f"{when:%Y-%m-%d %H:%M:%S}  {note}"),
            on_status=lambda status: self._post("recorder_status", status))
        self.recorder.start()
        self.watch_start_btn.configure(state="disabled")
        self.watch_stop_btn.configure(state="normal")
        self.camera_log.write(f"Recording to {self.watch_csv.get()}", "ok")
        self.status_var.set("Recording camera motion events…")

    def _stop_watch(self) -> None:
        if self.recorder:
            self.recorder.stop()
            self.camera_log.write(
                f"Stopped. {self.recorder.status.events_written} event(s) written, "
                f"{self.recorder.status.snapshots_saved} snapshot(s) saved.", "ok")
        self.watch_start_btn.configure(state="normal")
        self.watch_stop_btn.configure(state="disabled")
        self.status_var.set("Ready.")

    def _run_analysis(self) -> None:
        from ..cli import load_evidence

        config = self._collect_config()
        problems = config.validate()
        blocking = [p for p in problems
                    if "No input files" in p or "nothing to correlate" in p
                    or "must be" in p]
        if blocking:
            messagebox.showerror("Cannot run", "\n\n".join(blocking))
            return

        self.analyze_log.clear()
        for problem in problems:
            self.analyze_log.write(f"note: {problem}", "muted")
        self.analyze_log.write("Reading evidence…")
        self.run_button.configure(state="disabled")
        self._busy("Analyzing…")

        def work():
            try:
                events, records, warnings = load_evidence(
                    config, None, log=lambda m: self._post("log", m))
                if events.empty:
                    self._post("analysis_failed",
                               "No events were parsed from any input file.")
                    return
                provenance = Provenance.collect(
                    operator=config.operator, case_number=config.case_number,
                    agency=config.agency, tz_name=config.timezone,
                    notes=config.case_notes,
                    argv=["deauth-correlator", "(graphical interface)"])
                analysis = run_analysis(events, config.analysis_dict(),
                                        inputs=records, warnings=warnings,
                                        provenance=provenance)
                outdir = Path(config.outdir)
                outdir.mkdir(parents=True, exist_ok=True)
                written = [
                    write_correlation_csv(analysis.matches, outdir / "correlation.csv"),
                    write_events_csv(analysis.events, outdir / "events.csv"),
                    write_incidents_csv(analysis.incidents, outdir / "incidents.csv"),
                    write_report(analysis, outdir / "report.md"),
                ]
                try:
                    from ..plot import write_timeline
                    written.append(write_timeline(analysis, outdir / "timeline.png"))
                except Exception as exc:
                    self._post("log", f"  ! timeline could not be rendered: {exc}")
                write_manifest(analysis, outdir / "MANIFEST.json",
                               outputs=[record_file(p, "output") for p in written
                                        if p.exists()])
                self._post("analysis_done", analysis)
            except Exception as exc:
                self._post("error", ("Analysis failed", exc))
                self._post("analysis_failed", str(exc))

        threading.Thread(target=work, daemon=True).start()

    def _build_bundle(self) -> None:
        from ..evidence import build_bundle

        if self.analysis is None:
            messagebox.showinfo("Run the analysis first",
                                "The bundle is built from a completed analysis.")
            return
        target = self.bundle_dir.get()
        if not target:
            target = str(Path(self.outdir.get()) /
                         f"evidence_{_slug(self.case_number.get())}")
            self.bundle_dir.set(target)

        self.bundle_log.clear()
        self.bundle_button.configure(state="disabled")
        self._busy("Building the bundle…")
        exhibits = self.exhibit_list.paths()
        copy_inputs = self.bundle_copy_inputs.get()
        make_zip = self.bundle_zip.get()
        analysis = self.analysis

        def work():
            try:
                result = build_bundle(analysis, target, copy_inputs=copy_inputs,
                                      exhibits=exhibits, make_zip=make_zip,
                                      progress=lambda m: self._post("bundle_log", m))
                self._post("bundle_done", result)
            except Exception as exc:
                self._post("error", ("Bundle failed", exc))
                self._post("bundle_failed", str(exc))

        threading.Thread(target=work, daemon=True).start()

    # -- updates ---------------------------------------------------------

    def _check_updates(self, quiet: bool = False) -> None:
        """Ask GitHub whether a newer release exists. Never installs anything."""
        self.update_status.set("Checking…")

        def work():
            try:
                from .. import update as updater
                release = updater.check_for_update(__version__)
                self._post("update_result", release)
            except Exception as exc:
                self._post("update_failed", (exc, quiet))

        threading.Thread(target=work, name="update-check", daemon=True).start()

    def _install_update(self) -> None:
        """Download, verify and stage the release, then say how to finish.

        The swap is never performed by this process. On Windows a running
        executable cannot be replaced, and on any platform replacing the files
        under a live analysis is a good way to produce a report nobody can
        account for.
        """
        release = getattr(self, "_pending_release", None)
        if release is None:
            messagebox.showinfo("Nothing to install", "No newer release is known. "
                                                      "Press Check now first.")
            return
        if self.analysis is None and self.recorder is None:
            pass
        if self.recorder is not None and self.recorder.status.running:
            messagebox.showwarning(
                "Recording in progress",
                "Stop the camera recorder before updating.")
            return

        if not messagebox.askokcancel(
                f"Install {release.version}?",
                "This downloads the release, checks it against the SHA-256 "
                "published with it, unpacks it beside the current install and "
                "verifies the result.\n\n"
                "Nothing is replaced until you finish the update from a command "
                "prompt, and the current install is kept so it can be rolled "
                "back."):
            return

        self.update_install_btn.configure(state="disabled")
        self.update_status.set("Downloading…")
        self._busy("Downloading the update…")

        def work():
            import tempfile
            try:
                from .. import update as updater
                place = updater.installation()
                if not place.is_standalone():
                    self._post("update_staged_text",
                               "This is not a standalone build. Update it with:\n    "
                               + updater.pip_upgrade_command())
                    return
                def reporter(label: str, unit: str):
                    # progress is called with (done, total), and verify_tree
                    # calls it once per file - throttle, or the queue fills
                    # with a line per file in the build.
                    last = [0.0]

                    def report(done: int, total: int) -> None:
                        now = time.monotonic()
                        if not (total and done >= total) and now - last[0] < 0.2:
                            return
                        last[0] = now
                        self._post("update_progress",
                                   f"{label} "
                                   f"{updater.format_progress(done, total, unit)}")

                    return report

                with tempfile.TemporaryDirectory(
                        prefix="deauth-correlator-update-") as tmp:
                    archive = updater.download_and_verify(
                        release, Path(tmp),
                        progress=reporter("Downloading", "bytes"))
                    staged = updater.stage_update(
                        release, archive, place.root,
                        progress=reporter("Verifying", "files"))
                self._post("update_staged_text",
                           updater.completion_instructions(staged))
            except Exception as exc:
                self._post("update_failed", (exc, False))

        threading.Thread(target=work, name="update-install", daemon=True).start()

    def _show_update_endpoints(self) -> None:
        from .. import update as updater

        window = tk.Toplevel(self.master)
        window.title("What an update check contacts")
        window.geometry("700x420")
        text = tk.Text(window, wrap="word", padx=12, pady=12, font=("Consolas", 9))
        text.pack(fill="both", expand=True)
        lines = ["An update check or download contacts these hosts and no others.",
                 ""]
        for host, why in updater.UPDATE_ENDPOINTS:
            lines.append(host)
            lines.append(f"    {why}")
            lines.append("")
        lines.append(f"User-Agent sent: {updater.USER_AGENT}")
        lines.append("")
        lines.append("Nothing about this machine is transmitted beyond that, and "
                     "nothing is uploaded. Turn the check off with the box on the "
                     "Case tab and the program contacts nothing but your camera.")
        text.insert("1.0", "\n".join(lines))
        text.configure(state="disabled")

    # -- thread plumbing -------------------------------------------------

    def _post(self, kind: str, payload) -> None:
        self.events_queue.put((kind, payload))

    def _drain_queue(self) -> None:
        try:
            while True:
                kind, payload = self.events_queue.get_nowait()
                self._handle(kind, payload)
        except queue.Empty:
            pass
        self.after(120, self._drain_queue)

    def _handle(self, kind: str, payload) -> None:
        if kind == "log":
            self.analyze_log.write(str(payload))
        elif kind == "bundle_log":
            self.bundle_log.write(f". {payload}")
        elif kind == "motion":
            self.camera_log.write(str(payload), "ok")
        elif kind == "recorder_status":
            if payload.last_error:
                self.camera_log.write(payload.last_error, "error")
            self.status_var.set(
                f"Recording: {payload.events_written} event(s), "
                f"{payload.snapshots_saved} snapshot(s).")
        elif kind == "camera_probe":
            self._idle()
            for line in payload.summary_lines():
                self.camera_log.write(line, "ok" if payload.reachable else "error")
            if payload.clock_offset_s is not None:
                self.clock_offset.set(f"{-payload.clock_offset_s:.3f}")
                self.camera_log.write(
                    "The camera clock offset has been filled in on the Case tab, so "
                    "camera event times will be corrected automatically.", "muted")
        elif kind == "camera_snapshot":
            self._idle()
            self.camera_log.write(f"Saved {payload}", "ok")
            self.exhibit_list.set_paths(self.exhibit_list.paths() + [str(payload)])
        elif kind == "analysis_done":
            self._idle()
            self.run_button.configure(state="normal")
            self.analysis = payload
            self._show_results(payload)
        elif kind == "analysis_failed":
            self._idle()
            self.run_button.configure(state="normal")
            self.analyze_log.write(f"FAILED: {payload}", "error")
        elif kind == "bundle_done":
            self._idle()
            self.bundle_button.configure(state="normal")
            self.bundle_log.write(payload.summary(),
                                  "error" if payload.problems else "ok")
        elif kind == "bundle_failed":
            self._idle()
            self.bundle_button.configure(state="normal")
            self.bundle_log.write(f"FAILED: {payload}", "error")
        elif kind == "update_result":
            release = payload
            self._pending_release = release
            if release is None:
                self.update_status.set(f"{__version__} is the latest release.")
                self.update_install_btn.configure(state="disabled")
            else:
                self.update_status.set(release.summary())
                self.update_install_btn.configure(state="normal")
                self.status_var.set(f"Update available: {release.version} "
                                    f"(Case tab)")
        elif kind == "update_progress":
            self.update_status.set(str(payload))
        elif kind == "update_staged_text":
            self._idle()
            self.update_install_btn.configure(state="normal")
            self.update_status.set("Update staged and verified.")
            messagebox.showinfo("Update ready to finish", str(payload))
        elif kind == "fetch_fingerprint":
            self.fw_fingerprint.set(payload)
            self.fw_tls_mode.set("pin")
            self._fetch_tls_changed()
            self.fw_status.set(
                "Pinned. Check that value against the firewall's own web "
                "interface under System > Trust > Certificates - whoever answers "
                "gets to state their own fingerprint, so reading it proves "
                "nothing on its own.")
            self.fetch_log.write(f"Certificate fingerprint: {payload}", "muted")
        elif kind == "fetch_probed":
            self.fw_status.set(payload)
            self.fetch_log.write(payload, "ok")
        elif kind == "fetch_progress":
            self.fw_status.set(payload)
            self.fetch_log.write(payload, "muted")
        elif kind == "fetch_done":
            self._idle()
            self.fw_fetch_btn.configure(state="normal")
            self.fw_status.set(payload.summary())
            self.fetch_log.write(payload.summary(),
                                 "ok" if payload.written else "muted")
            for note in payload.skipped:
                self.fetch_log.write(f"skipped: {note}", "muted")
            if payload.written:
                existing = self.opnsense_list.paths()
                fresh = [str(p) for p in payload.written
                         if str(p) not in existing]
                self.opnsense_list.set_paths(existing + fresh)
                self._refresh_evidence_summary()
        elif kind == "fetch_failed":
            self._idle()
            self.fw_fetch_btn.configure(state="normal")
            self.fw_status.set(str(payload))
            self.fetch_log.write(f"{payload}", "error")
        elif kind == "update_failed":
            self._idle()
            exc, quiet = payload
            self.update_install_btn.configure(state="normal")
            self.update_status.set(f"Update check failed: {exc}")
            if not quiet:
                messagebox.showerror("Update", f"{exc}")
        elif kind == "error":
            self._idle()
            title, exc = payload
            messagebox.showerror(title, f"{exc.__class__.__name__}: {exc}")
            self.analyze_log.write(traceback.format_exc(), "error")

    def _busy(self, message: str) -> None:
        self.status_var.set(message)
        self.progress.start(12)

    def _idle(self) -> None:
        self.progress.stop()
        self.status_var.set("Ready.")

    # -- results rendering -----------------------------------------------

    def _show_results(self, analysis) -> None:
        s = analysis.stats
        colour = {VERDICT_FOUND: PALETTE["found"],
                  VERDICT_INSUFFICIENT: PALETTE["insufficient"]}.get(
            analysis.verdict.label, PALETTE["not_found"])
        self.verdict_var.set(analysis.one_line_verdict())
        self.verdict_label.configure(foreground=colour)

        self.results_banner.configure(state="normal")
        self.results_banner.delete("1.0", "end")
        text = [analysis.verdict.label, "", analysis.verdict.headline, ""]
        if analysis.verdict.reasons and analysis.verdict.label != VERDICT_FOUND:
            text.append("Why: " + "; ".join(analysis.verdict.reasons))
        text.append(
            f"Analysis period {analysis.obs_start_local:%Y-%m-%d %H:%M} to "
            f"{analysis.obs_end_local:%Y-%m-%d %H:%M} "
            f"({analysis.observation_hours:.2f} h, {analysis.config['timezone']}).")
        for note in analysis.period_notes:
            text.append(f"! {note}")
        self.results_banner.insert("1.0", "\n".join(text))
        self.results_banner.configure(state="disabled")

        self.results_tree.delete(*self.results_tree.get_children())
        for i, row in enumerate(analysis.matches.itertuples(index=False), start=1):
            self.results_tree.insert("", "end", tags=("hit",) if row.coincidence
                                     else ("odd",) if i % 2 else (),
                                     values=(
                i, _fmt(row.event_local), _text(row.plate),
                "YES" if row.coincidence else "no",
                _text(row.nearest_kind), row.delta_plain,
                _text(row.attacker_mac), _text(row.reason)))

        self.stats_tree.delete(*self.stats_tree.get_children())
        for measure, value, meaning in _stats_rows(analysis):
            self.stats_tree.insert("", "end", values=(measure, value, meaning))

        self.flood_tree.delete(*self.flood_tree.get_children())
        floods = analysis.floods
        total = max(floods.total_frames, 1)
        for mac, count in sorted(floods.by_source.items(), key=lambda kv: -kv[1]):
            self.flood_tree.insert("", "end", values=(
                mac, count, f"{count / total * 100:.1f}%",
                "Source address of these frames. Management-frame addresses are not "
                "authenticated and can be forged."))
        if not floods.by_source:
            self.flood_tree.insert("", "end", values=(
                "-", 0, "-", "No deauthentication frames were present. Supply a "
                          "monitor-mode capture to obtain frame-level evidence."))

        self._load_timeline(Path(self.outdir.get()) / "timeline.png")
        self.notebook.select(4)

    def _load_timeline(self, path: Path) -> None:
        if not path.exists():
            self.timeline_label.configure(text="timeline.png was not produced.",
                                          image="")
            return
        try:
            image = tk.PhotoImage(file=str(path))
            factor = max(1, int(image.width() / 1000) + 1)
            self._timeline_image = image.subsample(factor, factor)
            self.timeline_label.configure(image=self._timeline_image, text="")
        except tk.TclError:
            self.timeline_label.configure(
                text=f"Rendered to {path}\n(Tk cannot preview this PNG; use the "
                     f"button below to open it.)", image="")

    def _open_timeline(self) -> None:
        _open_path(Path(self.outdir.get()) / "timeline.png")

    # -- config marshalling ----------------------------------------------

    def _camera_config(self):
        from ..camera import CameraConfig
        return CameraConfig(
            host=self.cam_host.get(),
            username=self.cam_user.get(),
            password=self.camera_password.get(),
            onvif_port=_int(self.cam_onvif_port.get(), 2020),
            rtsp_port=_int(self.cam_rtsp_port.get(), 554),
            stream=self.cam_stream.get())

    def _collect_config(self) -> AppConfig:
        config = AppConfig(
            case_number=self.case_number.get(),
            operator=self.operator.get(),
            agency=self.agency.get(),
            case_notes=self.case_notes.get("1.0", "end").strip(),
            opnsense_logs=self.opnsense_list.paths(),
            wifi_captures=self.capture_list.paths(),
            camera_events=self.camera_list.paths(),
            timezone=self.tz_var.get() or DEFAULT_TZ,
            log_year=_int(self.log_year.get(), None),
            camera_clock_offset_s=_float(self.clock_offset.get(), 0.0),
            window_s=_float(self.window_s.get(), 30.0),
            alpha=_float(self.alpha.get(), 0.01),
            trials=_int(self.trials.get(), 10000),
            sensitivity=self.do_sensitivity.get(),
            handshake_window_s=_float(self.handshake_window.get(), 10.0),
            reassoc_window_s=_float(self.reassoc_window.get(), 120.0),
            incident_gap_s=_float(self.incident_gap.get(), 10.0),
            camera_dedupe_s=_float(self.camera_dedupe.get(), 2.0),
            flood_window_s=_float(self.flood_window.get(), 10.0),
            flood_threshold=_int(self.flood_threshold.get(), 5),
            outdir=self.outdir.get() or "output",
            check_for_updates=self.auto_update_check.get(),
            camera_host=self.cam_host.get(),
            camera_user=self.cam_user.get(),
            camera_onvif_port=_int(self.cam_onvif_port.get(), 2020),
            camera_rtsp_port=_int(self.cam_rtsp_port.get(), 554),
            camera_stream=self.cam_stream.get(),
        )
        self.config_model = config
        return config

    def _apply_config_to_widgets(self) -> None:
        c = self.config_model
        self.case_number.set(c.case_number)
        self.operator.set(c.operator)
        self.agency.set(c.agency)
        self.case_notes.delete("1.0", "end")
        self.case_notes.insert("1.0", c.case_notes)
        self.opnsense_list.set_paths(c.opnsense_logs)
        self.capture_list.set_paths(c.wifi_captures)
        self.camera_list.set_paths(c.camera_events)
        self.tz_var.set(c.timezone)
        self.log_year.set(c.log_year if c.log_year else "")
        self.clock_offset.set(c.camera_clock_offset_s)
        self.window_s.set(c.window_s)
        self.alpha.set(c.alpha)
        self.trials.set(c.trials)
        self.do_sensitivity.set(c.sensitivity)
        self.auto_update_check.set(c.check_for_updates)
        self.handshake_window.set(c.handshake_window_s)
        self.reassoc_window.set(c.reassoc_window_s)
        self.incident_gap.set(c.incident_gap_s)
        self.camera_dedupe.set(c.camera_dedupe_s)
        self.flood_window.set(c.flood_window_s)
        self.flood_threshold.set(c.flood_threshold)
        if c.outdir:
            self.outdir.set(str(Path(c.outdir).resolve()))
        self.cam_host.set(c.camera_host)
        self.cam_user.set(c.camera_user)
        self.cam_onvif_port.set(str(c.camera_onvif_port))
        self.cam_rtsp_port.set(str(c.camera_rtsp_port))
        self.cam_stream.set(c.camera_stream)
        self._refresh_evidence_summary()

    def _save_case(self) -> None:
        path = filedialog.asksaveasfilename(
            defaultextension=".json", filetypes=[("Case file", "*.json")],
            initialfile=f"{_slug(self.case_number.get())}.json")
        if not path:
            return
        self._collect_config().save(path)
        self.status_var.set(f"Case saved to {path}")

    def _open_case(self) -> None:
        path = filedialog.askopenfilename(filetypes=[("Case file", "*.json")])
        if not path:
            return
        try:
            self.config_model = AppConfig.load(path)
        except Exception as exc:
            messagebox.showerror("Could not open case file", str(exc))
            return
        self._apply_config_to_widgets()
        self.status_var.set(f"Case loaded from {path}")

    def _on_close(self) -> None:
        # Stop the live view first. It holds a worker thread and an open RTSP
        # connection, and a frame callback arriving after the widgets are gone
        # raises "invalid command name" out of the Tk event loop.
        view = getattr(self, "live_view", None)
        if view is not None and view.is_streaming():
            view.stop()

        if self.recorder and self.recorder.status.running:
            if not messagebox.askokcancel(
                    "Recording in progress",
                    "The camera motion recorder is still running. Stop it and quit?"):
                return
            self.recorder.stop()
        self.master.destroy()


def _stats_rows(analysis) -> list[tuple[str, str, str]]:
    s = analysis.stats
    rows = [
        ("Camera passes analyzed", f"{s.n_camera}", "Events inside the overlapping "
                                                    "period covered by both sources."),
        ("Coincidences", f"{s.n_coincident} within ±{s.window_s:g} s",
         "Camera passes with a wireless disruption close enough in time."),
        ("Observed coincidence rate", f"{s.coincidence_rate * 100:.1f}%", ""),
        ("Baseline coincidence rate", f"{s.baseline_rate * 100:.1f}%",
         "What a randomly-timed pass would hit by chance."),
        ("Expected by chance", f"{s.expected_by_chance:.2f} passes", ""),
        ("Binomial p", _p(s.binom_p), "Chance of this many hits if unrelated."),
        ("Permutation p", _p(s.perm_p),
         f"Empirical, from {s.perm_trials:,} circular shifts of the camera sequence."),
        ("Fisher's exact p", _p(s.fisher_p),
         f"On a 2x2 table of {2 * s.window_s:g}-second bins."),
        ("Fisher odds ratio", _num(s.fisher_odds_ratio), ""),
        ("Chi-square (Yates)", f"{_num(s.chi2)} (p = {_p(s.chi2_p)})", ""),
        ("Disruption rate in windows", f"{s.rate_in_per_min:.4f} /min",
         f"{s.incidents_in_window} incidents over {s.exposed_minutes:.1f} min."),
        ("Disruption rate elsewhere", f"{s.rate_out_per_min:.4f} /min",
         f"{s.incidents_outside} incidents over {s.unexposed_minutes:.1f} min."),
        ("Rate ratio",
         ("not applicable - no disruptions in either period"
          if s.rate_ratio != s.rate_ratio else
          f"{s.rate_ratio:.2f}x"
          + (" (zero-cell corrected)" if s.rate_ratio_corrected else "")),
         "How much more often disruptions happened during camera windows."),
        ("Deauth frames recovered", f"{analysis.floods.total_frames}",
         f"{analysis.floods.broadcast_frames} addressed to broadcast."),
        ("Floods detected", f"{len(analysis.floods.floods)}",
         f"Bursts of {analysis.floods.threshold}+ frames in "
         f"{analysis.floods.window_s:g} s."),
        ("Numerical backend", s.backend, ""),
    ]
    for entry in analysis.sensitivity:
        rows.append((f"Sensitivity ±{entry.window_s:g} s",
                     f"{entry.n_coincident}/{entry.n_camera}, "
                     f"ratio {entry.rate_ratio:.2f}x, weakest p = {_p(entry.worst_p)}",
                     "Same analysis at a different window width."))
    return rows


def _open_path(path) -> None:
    path = Path(path)
    if not path.exists():
        messagebox.showinfo("Not found", f"{path} does not exist yet.")
        return
    try:
        if sys.platform.startswith("win"):
            os.startfile(str(path))
        elif sys.platform == "darwin":
            subprocess.run(["open", str(path)], check=False)
        else:
            subprocess.run(["xdg-open", str(path)], check=False)
    except Exception:
        webbrowser.open(path.as_uri())


def _text(value) -> str:
    """Display-safe string; pandas 3.x hands back a truthy NaN for blanks."""
    from ..events import text
    return text(value)


def _fmt(value) -> str:
    try:
        import pandas as pd
        return pd.Timestamp(value).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(value)


def _p(value) -> str:
    if value is None or value != value:
        return "n/a"
    return f"{value:.2e}" if value < 1e-4 else f"{value:.4f}"


def _num(value) -> str:
    if value is None or value != value:
        return "n/a"
    if value == float("inf"):
        return "infinite"
    return f"{value:.3f}"


def _int(text, default):
    try:
        return int(str(text).strip())
    except (TypeError, ValueError):
        return default


def _float(text, default):
    try:
        return float(str(text).strip())
    except (TypeError, ValueError):
        return default


def _slug(text: str) -> str:
    cleaned = "".join(c if c.isalnum() or c in "-_" else "_" for c in (text or "").strip())
    return cleaned or "case"


def launch(config: AppConfig | None = None) -> int:
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        print(f"error: no graphical display available ({exc}).", file=sys.stderr)
        return 2

    try:
        style = ttk.Style(root)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        elif "clam" in style.theme_names():
            style.theme_use("clam")
    except tk.TclError:
        pass

    App(root, config)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(launch())
