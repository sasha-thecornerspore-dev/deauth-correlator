"""Deauthentication flood detection.

A flood is a burst of deauth/disassoc frames arriving faster than any healthy
network produces them. An access point legitimately deauthenticates a client
now and then - on roaming, on idle timeout, on a failed key exchange - but it
does not emit ten frames in ten seconds, and it does not repeatedly address the
broadcast MAC.

Bursts are found with a sliding window over frame arrival times: any point
where ``threshold`` or more frames fall inside ``window_s`` starts a burst,
which then extends until the rate falls back below the threshold.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict

import numpy as np
import pandas as pd

from .events import TOOL_SIGNATURE_REASONS, BROADCAST, epoch_seconds, reason_text

DEFAULT_FLOOD_WINDOW_S = 10.0
DEFAULT_FLOOD_THRESHOLD = 5


@dataclass
class Flood:
    start_local: object
    end_local: object
    duration_s: float
    n_frames: int
    peak_rate_per_s: float
    src_macs: dict = field(default_factory=dict)
    target_macs: dict = field(default_factory=dict)
    reason_codes: dict = field(default_factory=dict)
    broadcast_frames: int = 0

    @property
    def top_source(self) -> str:
        if not self.src_macs:
            return ""
        return max(self.src_macs.items(), key=lambda kv: kv[1])[0]

    def to_dict(self) -> dict:
        data = asdict(self)
        data["start_local"] = str(self.start_local)
        data["end_local"] = str(self.end_local)
        data["top_source"] = self.top_source
        return data


@dataclass
class FloodReport:
    floods: list = field(default_factory=list)
    by_source: dict = field(default_factory=dict)      # src mac -> frame count
    by_reason: dict = field(default_factory=dict)      # reason code -> frame count
    total_frames: int = 0
    broadcast_frames: int = 0
    window_s: float = DEFAULT_FLOOD_WINDOW_S
    threshold: int = DEFAULT_FLOOD_THRESHOLD

    @property
    def tool_signature_frames(self) -> int:
        return sum(n for code, n in self.by_reason.items()
                   if code in TOOL_SIGNATURE_REASONS)

    def to_dict(self) -> dict:
        return {
            "floods": [f.to_dict() for f in self.floods],
            "by_source": self.by_source,
            "by_reason": {str(k): v for k, v in self.by_reason.items()},
            "total_frames": self.total_frames,
            "broadcast_frames": self.broadcast_frames,
            "tool_signature_frames": self.tool_signature_frames,
            "window_s": self.window_s,
            "threshold": self.threshold,
        }


def detect_floods(df: pd.DataFrame, window_s: float = DEFAULT_FLOOD_WINDOW_S,
                  threshold: int = DEFAULT_FLOOD_THRESHOLD) -> FloodReport:
    """Find deauth bursts and tally the source MACs behind them."""
    frames = df[df["kind"].isin(["deauth", "disassoc"])].sort_values("ts_utc")
    report = FloodReport(window_s=window_s, threshold=threshold)
    if frames.empty:
        return report

    report.total_frames = len(frames)
    report.by_source = _counts(frames["src_mac"])
    report.by_reason = {int(k): v for k, v in
                        frames["reason_code"].dropna().astype(int)
                        .value_counts().to_dict().items()}
    report.broadcast_frames = int((frames["dst_mac"] == BROADCAST).sum())

    times = epoch_seconds(frames["ts_utc"])
    # For each frame, how many frames fall in the window ending at it.
    left = np.searchsorted(times, times - window_s, side="left")
    counts = np.arange(len(times)) - left + 1
    hot = counts >= threshold
    if not hot.any():
        return report

    # Expand each hot point back over the frames it counted.
    in_burst = np.zeros(len(times), dtype=bool)
    for i in np.flatnonzero(hot):
        in_burst[left[i]:i + 1] = True

    # Group the flagged frames into bursts. Index adjacency alone is not enough:
    # when every frame in the capture belongs to some burst, consecutive indices
    # span the quiet gaps between separate attacks and would collapse them into
    # one enormous flood. A gap longer than the detection window ends a burst.
    segments: list[tuple[int, int]] = []
    start: int | None = None
    for i in range(len(times)):
        if not in_burst[i]:
            if start is not None:
                segments.append((start, i))
                start = None
            continue
        if start is None:
            start = i
        elif times[i] - times[i - 1] > window_s:
            segments.append((start, i))
            start = i
    if start is not None:
        segments.append((start, len(times)))

    for start, end in segments:
        chunk = frames.iloc[start:end]
        if len(chunk) < threshold:
            continue
        chunk_times = times[start:end]
        duration = float(chunk_times[-1] - chunk_times[0])
        peak = float(counts[start:end].max()) / window_s
        report.floods.append(Flood(
            start_local=chunk["ts_local"].iloc[0],
            end_local=chunk["ts_local"].iloc[-1],
            duration_s=duration,
            n_frames=len(chunk),
            peak_rate_per_s=peak,
            src_macs=_counts(chunk["src_mac"]),
            target_macs=_counts(chunk["dst_mac"]),
            reason_codes={int(k): v for k, v in
                          chunk["reason_code"].dropna().astype(int)
                          .value_counts().to_dict().items()},
            broadcast_frames=int((chunk["dst_mac"] == BROADCAST).sum()),
        ))
    return report


def describe_reason_profile(report: FloodReport) -> str:
    """Plain-English note on what the reason codes suggest, if anything."""
    if not report.by_reason:
        return ""
    signature = report.tool_signature_frames
    if not signature:
        return ("None of the deauthentication frames used reason code 1 or 7, the "
                "codes that off-the-shelf deauthentication tools emit by default.")
    share = signature / max(report.total_frames, 1) * 100
    codes = sorted(c for c in report.by_reason if c in TOOL_SIGNATURE_REASONS)
    listed = " or ".join(f"{c} ({reason_text(c)})" for c in codes)
    plural = "codes" if len(codes) > 1 else "code"
    return (f"{signature} of {report.total_frames} deauthentication frames "
            f"({share:.0f}%) carried reason {plural} {listed}. Those are the default "
            f"codes emitted by common deauthentication tools; an access point "
            f"disconnecting a client for ordinary reasons normally reports codes "
            f"such as 3, 4 or 8.")


def _counts(series: pd.Series) -> dict:
    cleaned = series.dropna()
    cleaned = cleaned[cleaned.astype(bool)]
    if cleaned.empty:
        return {}
    return {str(k): int(v) for k, v in cleaned.value_counts().items()}
