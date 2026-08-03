"""Kismet ``.kismet`` SQLite log parser.

Two evidence paths, both used when available:

* ``alerts``  - Kismet's own DEAUTHFLOOD / BCASTDISCON / DISASSOCTRAFFIC findings
* ``packets`` - raw frames, decoded the same way as a pcap so reason codes and
  transmitter addresses come from the frame itself rather than from Kismet's
  interpretation of it

The schema has changed across Kismet releases, so column presence is checked
with ``PRAGMA table_info`` rather than assumed.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .base import Parser, ParseContext, ParseError
from .dot11 import WIFI_DLTS, decode_packet
from ..events import make_event, norm_mac, reason_text, is_group_addressed, BROADCAST
from ..timeutil import finalize

DISRUPTION_ALERTS = {
    "DEAUTHFLOOD": "Kismet detected a flood of deauthentication frames",
    "BCASTDISCON": "Kismet detected a broadcast disconnect (deauth/disassoc to all clients)",
    "DISASSOCTRAFFIC": "Kismet detected disassociation traffic",
    "DEAUTHCODEINVALID": "Deauthentication frame carrying an invalid reason code",
    "NULLPROBERESP": "Malformed probe response consistent with an attack tool",
    "CHANCHANGE": "Access point changed channel unexpectedly",
}


class KismetParser(Parser):
    id = "kismet"
    name = "Kismet SQLite log"
    describes = ("Kismet capture database. Deauthentication and disassociation frames "
                 "are decoded from the stored raw packets, and Kismet's own "
                 "deauth-flood alerts are carried through as findings.")
    extensions = (".kismet", ".kismet.log", ".sqlite", ".db")

    def sniff(self, path: Path) -> float:
        if not self.head_bytes(path, 16).startswith(b"SQLite format 3"):
            return 0.0
        try:
            with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as con:
                names = {r[0] for r in con.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'")}
        except sqlite3.Error:
            return 0.0
        if {"devices", "packets"} & names and ("KISMET" in names or "alerts" in names):
            return 1.0
        if {"packets", "alerts"} <= names:
            return 0.8
        return 0.0

    def parse(self, path: Path, ctx: ParseContext) -> list[dict]:
        try:
            con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        except sqlite3.Error as exc:
            raise ParseError(f"{path.name}: cannot open Kismet database: {exc}") from exc

        rows: list[dict] = []
        try:
            tables = {r[0] for r in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            if "packets" in tables:
                rows.extend(self._from_packets(con, path, ctx, tables))
            if "alerts" in tables:
                rows.extend(self._from_alerts(con, path, ctx))
        finally:
            con.close()

        if not rows:
            ctx.warn(f"{path.name}: Kismet database contained no deauthentication "
                     f"frames or disruption alerts.")
        return rows

    def _from_packets(self, con, path: Path, ctx: ParseContext, tables) -> list[dict]:
        cols = {r[1] for r in con.execute("PRAGMA table_info(packets)")}
        if "packet" not in cols:
            ctx.warn(f"{path.name}: Kismet 'packets' table stores no raw frames "
                     f"(logging was set to metadata only); reason codes unavailable.")
            return []

        select = ["ts_sec", "packet"]
        for optional in ("ts_usec", "dlt", "sourcemac", "destmac", "signal", "frequency"):
            if optional in cols:
                select.append(optional)
        query = f"SELECT {', '.join(select)} FROM packets"
        if "dlt" in cols:
            query += f" WHERE dlt IN ({','.join(str(d) for d in sorted(WIFI_DLTS))})"

        rows: list[dict] = []
        for pkt_no, record in enumerate(con.execute(query), start=1):
            values = dict(zip(select, record))
            blob = values.get("packet")
            if not blob:
                continue
            dlt = values.get("dlt", 127)
            frame = decode_packet(bytes(blob), int(dlt))
            if frame is None or frame.kind not in ("deauth", "disassoc"):
                continue
            epoch = float(values["ts_sec"]) + float(values.get("ts_usec") or 0) / 1e6
            dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
            utc, local, offset = finalize(dt, ctx.time)
            target = frame.dst_mac
            rows.append(make_event(
                ts_utc=utc, ts_local=local, utc_offset=offset,
                kind=frame.kind,
                src_mac=frame.src_mac, dst_mac=target, bssid=frame.bssid,
                client_mac="" if is_group_addressed(target) else target,
                reason_code=frame.reason_code,
                reason_text=reason_text(frame.reason_code),
                signal=values.get("signal") if values.get("signal") else frame.signal_dbm,
                channel=frame.channel,
                notes=("broadcast deauth - disconnects every client on the BSS"
                       if target == BROADCAST else ""),
                source_file=str(path), source_kind=self.id,
                source_ref=f"packets row {pkt_no}",
                raw=f"{frame.kind} src={frame.src_mac} dst={target} "
                    f"bssid={frame.bssid} reason={frame.reason_code}",
            ))
        return rows

    def _from_alerts(self, con, path: Path, ctx: ParseContext) -> list[dict]:
        cols = {r[1] for r in con.execute("PRAGMA table_info(alerts)")}
        select = [c for c in ("ts_sec", "ts_usec", "devmac", "header", "json")
                  if c in cols]
        if "ts_sec" not in select:
            return []

        rows: list[dict] = []
        for row_no, record in enumerate(
                con.execute(f"SELECT {', '.join(select)} FROM alerts"), start=1):
            values = dict(zip(select, record))
            header = (values.get("header") or "").upper()
            if header not in DISRUPTION_ALERTS:
                continue
            epoch = float(values["ts_sec"]) + float(values.get("ts_usec") or 0) / 1e6
            dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
            utc, local, offset = finalize(dt, ctx.time)
            detail, source = _alert_detail(values.get("json"))
            rows.append(make_event(
                ts_utc=utc, ts_local=local, utc_offset=offset,
                kind="alert",
                src_mac=source or norm_mac(values.get("devmac") or ""),
                bssid=norm_mac(values.get("devmac") or ""),
                notes=f"{header}: {DISRUPTION_ALERTS[header]}"
                      + (f" - {detail}" if detail else ""),
                source_file=str(path), source_kind=self.id,
                source_ref=f"alerts row {row_no}",
                raw=header,
            ))
        return rows


def _alert_detail(payload) -> tuple[str, str]:
    """Pull the human text and any transmitter MAC out of a Kismet alert record."""
    if not payload:
        return "", ""
    try:
        data = json.loads(payload if isinstance(payload, str) else payload.decode())
    except (ValueError, AttributeError, UnicodeDecodeError):
        return "", ""
    text = str(data.get("kismet.alert.text", "") or "")[:300]
    source = norm_mac(data.get("kismet.alert.source_mac", "") or "")
    if source == "00:00:00:00:00:00":
        source = ""
    return text, source
