"""Analysis configuration, shared by the CLI and the GUI.

The GUI saves and reloads these as a case file so an analysis can be repeated
months later with the same parameters. Camera credentials are deliberately not
part of the saved structure.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path

from .stats import DEFAULT_ALPHA, DEFAULT_TRIALS, DEFAULT_WINDOW_S
from .timeutil import DEFAULT_TZ


@dataclass
class AppConfig:
    # Case identification
    case_number: str = ""
    operator: str = ""
    agency: str = ""
    case_notes: str = ""

    # Inputs
    opnsense_logs: list = field(default_factory=list)
    wifi_captures: list = field(default_factory=list)
    camera_events: list = field(default_factory=list)

    # Time handling
    timezone: str = DEFAULT_TZ
    log_year: int | None = None
    assume_offset: str = ""
    camera_clock_offset_s: float = 0.0
    clip_time_from: str = "auto"          # auto | filename | mtime

    # Correlation
    window_s: float = DEFAULT_WINDOW_S
    alpha: float = DEFAULT_ALPHA
    trials: int = DEFAULT_TRIALS
    sensitivity: bool = True

    # Event derivation
    handshake_window_s: float = 10.0
    reassoc_window_s: float = 120.0
    incident_gap_s: float = 10.0
    camera_dedupe_s: float = 2.0

    # Flood detection
    flood_window_s: float = 10.0
    flood_threshold: int = 5

    # Output
    outdir: str = "output"
    evidence_bundle: bool = False
    zip_bundle: bool = False

    # Camera (credentials are never persisted)
    camera_host: str = ""
    camera_user: str = ""
    camera_onvif_port: int = 2020
    camera_rtsp_port: int = 554
    camera_stream: str = "hd"

    def analysis_dict(self) -> dict:
        """The subset the analysis and report actually read."""
        return {
            "timezone": self.timezone,
            "window_s": self.window_s,
            "alpha": self.alpha,
            "trials": self.trials,
            "sensitivity": self.sensitivity,
            "handshake_window_s": self.handshake_window_s,
            "reassoc_window_s": self.reassoc_window_s,
            "incident_gap_s": self.incident_gap_s,
            "camera_dedupe_s": self.camera_dedupe_s,
            "flood_window_s": self.flood_window_s,
            "flood_threshold": self.flood_threshold,
            "camera_clock_offset_s": self.camera_clock_offset_s,
            "clip_time_from": self.clip_time_from,
            "log_year": self.log_year,
        }

    def save(self, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = asdict(self)
        data.pop("camera_password", None)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return path

    @classmethod
    def load(cls, path: str | Path) -> "AppConfig":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})

    def validate(self) -> list[str]:
        problems = []
        if self.window_s <= 0:
            problems.append("The coincidence window must be greater than zero.")
        if not 0 < self.alpha < 1:
            problems.append("The significance threshold must be between 0 and 1.")
        if self.trials < 100:
            problems.append("At least 100 permutation trials are needed for a "
                            "meaningful empirical p-value.")
        if self.flood_threshold < 2:
            problems.append("The flood threshold must be at least 2 frames.")
        if self.reassoc_window_s <= self.handshake_window_s:
            problems.append("The re-association window must be longer than the "
                            "handshake window, or every ordinary DHCP join would be "
                            "counted as a drop.")
        if not (self.opnsense_logs or self.wifi_captures or self.camera_events):
            problems.append("No input files were selected.")
        elif not self.camera_events:
            problems.append("No camera events were supplied, so there is nothing to "
                            "correlate the wireless evidence against.")
        elif not (self.opnsense_logs or self.wifi_captures):
            problems.append("No wireless evidence was supplied, so there is nothing to "
                            "correlate the camera events against.")
        return problems
