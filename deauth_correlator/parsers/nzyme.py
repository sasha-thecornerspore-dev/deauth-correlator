"""nzyme CSV parser, and the general-purpose 802.11 CSV fallback.

nzyme's export column names differ between versions, and analysts often hand a
CSV exported from Wireshark or ``tshark -T fields`` instead. Rather than
hard-coding one layout, this parser maps columns by synonym: it looks for a
timestamp column, a transmitter, a receiver, a BSSID, a frame-type/subtype and
a reason code, accepting any of the names each of those goes by.

The mapping that was actually used is recorded in the row notes and surfaced in
the report, so a reader can see how each column was interpreted.
"""

from __future__ import annotations

import csv
from pathlib import Path

from .base import Parser, ParseContext
from ..events import make_event, norm_mac, reason_text, is_group_addressed, BROADCAST
from ..timeutil import finalize, parse_any

SYNONYMS = {
    "timestamp": ["timestamp", "time", "ts", "datetime", "date_time", "created_at",
                  "first_seen", "seen_at", "frame.time_epoch", "frame.time", "_ws.col.time"],
    "src_mac": ["transmitter", "transmitter_address", "source", "source_mac", "src",
                "src_mac", "sender", "station", "addr2", "wlan.ta", "wlan.sa",
                "transmitter_mac"],
    "dst_mac": ["destination", "destination_address", "dest", "dst", "dst_mac",
                "receiver", "receiver_address", "target", "addr1", "wlan.da", "wlan.ra",
                "destination_mac"],
    "bssid": ["bssid", "ap", "ap_mac", "addr3", "wlan.bssid", "access_point"],
    "subtype": ["subtype", "frame_subtype", "type", "frame_type", "wlan.fc.type_subtype",
                "frametype", "kind", "event", "event_type", "alert_type"],
    "reason_code": ["reason", "reason_code", "wlan.fixed.reason_code",
                    "wlan_mgt.fixed.reason_code", "reasoncode"],
    "channel": ["channel", "chan", "wlan_radio.channel", "frequency"],
    "signal": ["signal", "rssi", "signal_strength", "wlan_radio.signal_dbm", "power",
               "signal_dbm"],
    "ssid": ["ssid", "essid", "network", "wlan.ssid"],
}

DEAUTH_TOKENS = ("deauth", "0x000c", "0x0c", "12", "deauthentication")
DISASSOC_TOKENS = ("disassoc", "0x000a", "0x0a", "10", "disassociation")


class NzymeCsvParser(Parser):
    id = "nzyme_csv"
    name = "nzyme / generic 802.11 frame CSV"
    describes = ("Tabular export of 802.11 management frames (nzyme, tshark, or any "
                 "CSV with transmitter, receiver, subtype and reason-code columns). "
                 "Columns are matched by name against a synonym table.")
    extensions = (".csv",)

    def sniff(self, path: Path) -> float:
        text = self.head_text(path, 4096)
        if not text:
            return 0.0
        first = text.splitlines()[0] if text.splitlines() else ""
        header = [h.strip().lower() for h in first.split(",")]
        if not header:
            return 0.0
        mapping = _map_columns(header)
        if "timestamp" not in mapping:
            return 0.0
        low = text.lower()
        has_frame_evidence = ("subtype" in mapping or "reason_code" in mapping
                              or "deauth" in low)
        if not has_frame_evidence:
            return 0.0
        score = 0.55
        if "nzyme" in low:
            score = 0.95
        if "reason_code" in mapping and ("src_mac" in mapping or "dst_mac" in mapping):
            score = max(score, 0.8)
        return score

    def parse(self, path: Path, ctx: ParseContext) -> list[dict]:
        with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as fh:
            reader = csv.reader(fh)
            try:
                header = next(reader)
            except StopIteration:
                return []
            header = [h.strip() for h in header]
            mapping = _map_columns([h.lower() for h in header])
            overrides = ctx.options.get("nzyme_columns") or {}
            for field, column in overrides.items():
                if column in header:
                    mapping[field] = header.index(column)

            if "timestamp" not in mapping:
                ctx.warn(f"{path.name}: no timestamp column found; file skipped. "
                         f"Header was: {', '.join(header[:12])}")
                return []

            described = ", ".join(f"{k}={header[v]}" for k, v in sorted(mapping.items()))
            ctx.warn(f"{path.name}: column mapping used - {described}")

            rows: list[dict] = []
            skipped = 0
            for row_no, record in enumerate(reader, start=2):
                if not any(f.strip() for f in record):
                    continue
                get = lambda field: (record[mapping[field]].strip()
                                     if field in mapping and mapping[field] < len(record)
                                     else "")
                dt = parse_any(get("timestamp"), ctx.time)
                if dt is None:
                    skipped += 1
                    continue
                kind = _classify(get("subtype"), get("reason_code"))
                if kind is None:
                    continue
                target = norm_mac(get("dst_mac"))
                reason = _int_or_none(get("reason_code"))
                utc, local, offset = finalize(dt, ctx.time)
                rows.append(make_event(
                    ts_utc=utc, ts_local=local, utc_offset=offset,
                    kind=kind,
                    src_mac=norm_mac(get("src_mac")),
                    dst_mac=target,
                    bssid=norm_mac(get("bssid")),
                    client_mac="" if is_group_addressed(target) else target,
                    reason_code=reason,
                    reason_text=reason_text(reason),
                    channel=_int_or_none(get("channel")),
                    signal=_int_or_none(get("signal")),
                    notes=("broadcast deauth - disconnects every client on the BSS"
                           if target == BROADCAST else (get("ssid") or "")),
                    source_file=str(path), source_kind=self.id,
                    source_ref=f"row {row_no}",
                    raw=",".join(record)[:400],
                ))

            if skipped:
                ctx.warn(f"{path.name}: {skipped} row(s) had an unreadable timestamp.")
            return rows


def _map_columns(header_lower: list[str]) -> dict[str, int]:
    mapping: dict[str, int] = {}
    for field, names in SYNONYMS.items():
        for idx, column in enumerate(header_lower):
            cleaned = column.strip().strip('"').replace(" ", "_")
            if cleaned in names:
                mapping[field] = idx
                break
    return mapping


def _classify(subtype: str, reason: str) -> str | None:
    """Decide whether a row is a deauth, a disassoc, or not of interest."""
    token = (subtype or "").strip().lower()
    if any(t in token for t in DEAUTH_TOKENS):
        return "deauth"
    if any(t in token for t in DISASSOC_TOKENS):
        return "disassoc"
    if not token and reason.strip():
        # A reason code with no subtype column: the export is deauth-only.
        return "deauth"
    return None


def _int_or_none(text: str):
    text = (text or "").strip()
    if not text:
        return None
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(float(text))
    except ValueError:
        return None
