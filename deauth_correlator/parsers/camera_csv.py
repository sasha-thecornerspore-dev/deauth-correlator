"""Camera event CSV parser.

The documented layout is ``timestamp,plate,make,model,notes``. Real files from
an NVR export or a hand-kept log rarely match exactly, so the header is matched
by synonym and a header-less file whose first column parses as a timestamp is
accepted as well.
"""

from __future__ import annotations

import csv
from pathlib import Path

from .base import Parser, ParseContext
from ..events import make_event
from ..timeutil import finalize, parse_any

SYNONYMS = {
    "timestamp": ["timestamp", "time", "datetime", "date_time", "event_time", "ts",
                  "date", "start", "start_time", "recorded", "captured"],
    "plate": ["plate", "license", "license_plate", "tag", "reg", "registration",
              "plate_number"],
    "make": ["make", "manufacturer", "vehicle_make", "brand"],
    "model": ["model", "vehicle_model", "type", "vehicle_type"],
    "notes": ["notes", "note", "comment", "comments", "description", "detail",
              "details", "remarks", "observation"],
    "clip": ["clip", "file", "filename", "video", "path", "recording", "clip_path"],
}


class CameraCsvParser(Parser):
    id = "camera_csv"
    name = "camera event CSV"
    describes = ("Log of vehicle passes recorded by the security camera, one row per "
                 "pass, with the observation time and any plate/make/model noted.")
    extensions = (".csv", ".tsv", ".txt")

    def sniff(self, path: Path) -> float:
        text = self.head_text(path, 4096)
        if not text:
            return 0.0
        lines = text.splitlines()
        if not lines:
            return 0.0
        header = [h.strip().strip('"').lower() for h in lines[0].split(",")]
        mapping = _map_columns(header)
        if "timestamp" in mapping and {"plate", "make", "model"} & set(mapping):
            return 0.95
        if "timestamp" in mapping and "notes" in mapping and len(header) <= 6:
            return 0.7
        return 0.0

    def parse(self, path: Path, ctx: ParseContext) -> list[dict]:
        delimiter = "\t" if path.suffix.lower() == ".tsv" else ","
        with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as fh:
            records = list(csv.reader(fh, delimiter=delimiter))
        if not records:
            return []

        header = [h.strip().strip('"') for h in records[0]]
        mapping = _map_columns([h.lower() for h in header])
        start = 1
        if "timestamp" not in mapping:
            # Maybe there is no header row and column 0 is the timestamp.
            if parse_any(records[0][0] if records[0] else "", ctx.time) is not None:
                mapping = {"timestamp": 0, "plate": 1, "make": 2, "model": 3, "notes": 4}
                start = 0
                ctx.warn(f"{path.name}: no header row detected; columns assumed to be "
                         f"timestamp, plate, make, model, notes in that order.")
            else:
                ctx.warn(f"{path.name}: no timestamp column found; file skipped.")
                return []

        offset_s = ctx.clock_offset_s
        rows: list[dict] = []
        skipped = 0
        for row_no, record in enumerate(records[start:], start=start + 1):
            if not any(f.strip() for f in record):
                continue
            get = lambda field: (record[mapping[field]].strip()
                                 if field in mapping and mapping[field] < len(record)
                                 else "")
            dt = parse_any(get("timestamp"), ctx.time)
            if dt is None:
                skipped += 1
                continue
            utc, local, observed = finalize(dt, ctx.time)
            if offset_s:
                utc = utc + _seconds(offset_s)
                local = local + _seconds(offset_s)
            clip = get("clip")
            note = get("notes")
            if clip:
                note = f"{note} [clip: {clip}]".strip()
            rows.append(make_event(
                ts_utc=utc, ts_local=local, utc_offset=observed,
                kind="camera",
                plate=get("plate"), make=get("make"), model=get("model"),
                notes=note,
                source_file=str(path), source_kind=self.id,
                source_ref=f"row {row_no}",
                raw=delimiter.join(record)[:400],
            ))

        if skipped:
            ctx.warn(f"{path.name}: {skipped} row(s) had an unreadable timestamp.")
        if offset_s:
            ctx.warn(f"{path.name}: camera clock offset of {offset_s:+.3f} s applied to "
                     f"every event time.")
        return rows


def _seconds(value: float):
    import pandas as pd
    return pd.Timedelta(seconds=value)


def _map_columns(header_lower: list[str]) -> dict[str, int]:
    mapping: dict[str, int] = {}
    for field, names in SYNONYMS.items():
        for idx, column in enumerate(header_lower):
            cleaned = column.strip().strip('"').replace(" ", "_")
            if cleaned in names:
                mapping[field] = idx
                break
    return mapping
