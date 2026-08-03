"""airodump-ng CSV parser.

``airodump-ng --write prefix`` emits ``prefix-01.csv`` containing two tables:
access points, then a blank line, then associated stations. The CSV records
first/last seen times and packet counts - it does **not** contain individual
management frames, so deauthentication reason codes cannot come from here.
Point ``--wifi-capture`` at the ``.cap`` alongside it for that.

What this file does give is corroborating context: which stations were present,
which BSSID each was associated with, and the moment each was last heard from.
A station whose "Last time seen" is followed by a fresh probe burst is
consistent with a forced disconnect, so those last-seen instants are emitted as
low-weight context rather than as disruptions in their own right.
"""

from __future__ import annotations

import csv
from pathlib import Path

from .base import Parser, ParseContext
from ..events import make_event, norm_mac
from ..timeutil import finalize, parse_any

AP_HEADER_HINT = "BSSID, First time seen"
STATION_HEADER_HINT = "Station MAC"


class AirodumpCsvParser(Parser):
    id = "airodump_csv"
    name = "airodump-ng CSV"
    describes = ("Access-point and station tables written by airodump-ng. Provides "
                 "which clients were present and when each was last heard, as context "
                 "for the frame-level evidence in the companion capture file.")
    extensions = (".csv",)

    def sniff(self, path: Path) -> float:
        text = self.head_text(path, 4096)
        if not text:
            return 0.0
        if "BSSID" in text and "First time seen" in text and "ESSID" in text:
            return 0.95
        if "Station MAC" in text and "Power" in text:
            return 0.9
        return 0.0

    def parse(self, path: Path, ctx: ParseContext) -> list[dict]:
        with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
            lines = fh.read().splitlines()

        section = None
        ap_names: dict[str, str] = {}
        rows: list[dict] = []

        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("BSSID,"):
                section = "ap"
                continue
            if stripped.startswith("Station MAC,"):
                section = "station"
                continue
            if section is None:
                continue

            fields = next(csv.reader([line]), [])
            fields = [f.strip() for f in fields]
            if len(fields) < 6:
                continue

            if section == "ap":
                bssid = norm_mac(fields[0])
                if bssid and len(fields) >= 14:
                    ap_names[bssid] = fields[13]
                continue

            station = norm_mac(fields[0])
            if not station:
                continue
            last_seen = parse_any(fields[2], ctx.time) if len(fields) > 2 else None
            if last_seen is None:
                continue
            bssid = norm_mac(fields[5]) if len(fields) > 5 else ""
            power = _int_or_none(fields[3]) if len(fields) > 3 else None
            packets = _int_or_none(fields[4]) if len(fields) > 4 else None

            utc, local, offset = finalize(last_seen, ctx.time)
            rows.append(make_event(
                ts_utc=utc, ts_local=local, utc_offset=offset,
                kind="context", category="context",
                client_mac=station, src_mac=station, bssid=bssid,
                signal=power,
                notes=(f"airodump last seen; {packets or 0} frames"
                       + (f"; BSSID {ap_names.get(bssid, '')}".rstrip() if bssid else "")),
                source_file=str(path), source_kind=self.id,
                source_ref=f"line {lineno}", raw=line,
            ))

        if not rows:
            ctx.warn(f"{path.name}: no station rows recognized in the airodump CSV.")
        else:
            ctx.warn(f"{path.name}: airodump CSV parsed for station context only. "
                     f"Deauthentication frames and reason codes come from the "
                     f"companion .cap file - pass it with --wifi-capture.")
        return rows


def _int_or_none(text: str):
    try:
        return int(text)
    except (TypeError, ValueError):
        return None
