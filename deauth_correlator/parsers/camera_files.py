"""Clip-filename parser: a directory of NVR recordings becomes camera events.

How each timestamp was derived matters evidentially, so every row records the
named pattern that matched (``notes``) rather than silently producing a time.
When no pattern matches, the file's modification time is used only if
``--clip-time-from`` allows it, and the row says so plainly.

Recognized layouts cover Tapo/TP-Link, Hikvision, Dahua, Reolink, Amcrest,
UniFi Protect, Blue Iris, and bare ISO or epoch names.
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from pathlib import Path

from .base import Parser, ParseContext
from ..events import make_event
from ..timeutil import finalize, parse_compact

VIDEO_EXTENSIONS = {".mp4", ".mkv", ".avi", ".mov", ".dav", ".264", ".h264",
                    ".ts", ".flv", ".asf", ".jpg", ".jpeg", ".png"}

# Ordered most-specific first; the first match wins and is named in the output.
PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("UniFi Protect",
     re.compile(r"(?P<y>20\d{2})-(?P<mon>\d{2})-(?P<day>\d{2})_"
                r"(?P<h>\d{2})\.(?P<m>\d{2})\.(?P<s>\d{2})"),
     "date_underscore_dotted_time"),
    ("ISO 8601",
     re.compile(r"(?P<y>20\d{2})-(?P<mon>\d{2})-(?P<day>\d{2})[T_]"
                r"(?P<h>\d{2})[-:](?P<m>\d{2})[-:](?P<s>\d{2})"),
     "iso_datetime"),
    ("Dahua / Amcrest",
     re.compile(r"(?:ch\d+[_-])?(?:main|sub)?[_-]?"
                r"(?P<y>20\d{2})(?P<mon>\d{2})(?P<day>\d{2})"
                r"(?P<h>\d{2})(?P<m>\d{2})(?P<s>\d{2})", re.I),
     "compact_datetime_no_separator"),
    ("Hikvision export",
     re.compile(r"_(?P<y>20\d{2})(?P<mon>\d{2})(?P<day>\d{2})"
                r"(?P<h>\d{2})(?P<m>\d{2})(?P<s>\d{2})\d{0,3}"),
     "underscore_compact_datetime"),
    ("Tapo / Reolink / Blue Iris",
     re.compile(r"(?P<y>20\d{2})(?P<mon>\d{2})(?P<day>\d{2})[_-]"
                r"(?P<h>\d{2})(?P<m>\d{2})(?P<s>\d{2})"),
     "date_underscore_time"),
]

EPOCH_RE = re.compile(r"^(?P<epoch>1[0-9]{9})(?:\d{3})?$")


class CameraFilenameParser(Parser):
    id = "camera_clips"
    name = "camera clip filenames"
    describes = ("Directory of recorded clips. Each clip's start time is read from its "
                 "filename using a named NVR naming pattern, and one camera event is "
                 "produced per clip.")
    extensions = tuple(VIDEO_EXTENSIONS)

    def sniff(self, path: Path) -> float:
        if path.is_dir():
            clips = [p for p in _iter_clips(path)]
            if not clips:
                return 0.0
            dated = sum(1 for p in clips[:50] if _timestamp_from_name(p.name)[0])
            return 0.95 if dated else 0.5
        if path.suffix.lower() in VIDEO_EXTENSIONS:
            return 0.9 if _timestamp_from_name(path.name)[0] else 0.4
        return 0.0

    def parse(self, path: Path, ctx: ParseContext) -> list[dict]:
        mode = ctx.options.get("clip_time_from", "auto")
        clips = list(_iter_clips(path)) if path.is_dir() else [path]
        clips.sort(key=lambda p: p.name)

        offset_s = ctx.clock_offset_s
        rows: list[dict] = []
        by_pattern: dict[str, int] = {}
        from_mtime = 0

        for clip in clips:
            dt, pattern_name = _timestamp_from_name(clip.name)
            derivation = f"filename pattern: {pattern_name}" if dt else ""

            if dt is None or mode == "mtime":
                if mode == "filename":
                    ctx.warn(f"{clip.name}: no timestamp in filename and "
                             f"--clip-time-from=filename was set; clip skipped.")
                    continue
                dt = datetime.fromtimestamp(os.path.getmtime(clip), tz=timezone.utc)
                derivation = ("file modification time (NOT the recorded time - the "
                              "filename carried no timestamp)")
                pattern_name = "mtime"
                from_mtime += 1

            by_pattern[pattern_name] = by_pattern.get(pattern_name, 0) + 1
            utc, local, observed = finalize(dt, ctx.time)
            if offset_s:
                utc = utc + _seconds(offset_s)
                local = local + _seconds(offset_s)
            rows.append(make_event(
                ts_utc=utc, ts_local=local, utc_offset=observed,
                kind="camera",
                notes=f"clip {clip.name}; time from {derivation}",
                source_file=str(clip), source_kind=self.id,
                source_ref=clip.name,
                raw=clip.name,
            ))

        if by_pattern:
            summary = ", ".join(f"{n}x {p}" for p, n in sorted(by_pattern.items()))
            ctx.warn(f"{path.name}: clip timestamps derived as - {summary}")
        if from_mtime:
            ctx.warn(f"{path.name}: {from_mtime} clip(s) fell back to file modification "
                     f"time. That is when the file was last written, not necessarily "
                     f"when the event was recorded; treat those rows with caution.")
        if offset_s:
            ctx.warn(f"{path.name}: camera clock offset of {offset_s:+.3f} s applied.")
        return rows


def _iter_clips(directory: Path):
    for entry in sorted(directory.rglob("*")):
        if entry.is_file() and entry.suffix.lower() in VIDEO_EXTENSIONS:
            yield entry


def _timestamp_from_name(name: str) -> tuple[datetime | None, str]:
    stem = Path(name).stem
    m = EPOCH_RE.match(stem)
    if m:
        return datetime.fromtimestamp(int(m["epoch"]), tz=timezone.utc), "unix epoch"

    for label, pattern, _slug in PATTERNS:
        m = pattern.search(name)
        if not m:
            continue
        try:
            return datetime(int(m["y"]), int(m["mon"]), int(m["day"]),
                            int(m["h"]), int(m["m"]), int(m["s"])), label
        except ValueError:
            continue

    got = parse_compact(name)
    if got is not None:
        return got[0], "generic embedded datetime"
    return None, ""


def _seconds(value: float):
    import pandas as pd
    return pd.Timedelta(seconds=value)
