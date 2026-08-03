"""OPNsense DHCP and system log parser.

Handles the four shapes an OPNsense box actually emits:

* ``dnsmasq-dhcp`` - the default DHCP server on current OPNsense
* ``kea-dhcp4``    - the newer server offered from 24.x
* ``dhcpd``        - the legacy ISC server
* ``hostapd`` / ``wpa_supplicant`` / kernel link-state - wireless disconnects

Both syslog framings are accepted: RFC3164 (``Jul 14 21:03:11 host proc[pid]:``)
and RFC5424 (``<134>1 2026-07-14T21:03:11-04:00 host proc pid - -``), which is
what OPNsense sends to a remote syslog collector.

Lease traffic is emitted as ``context`` events; :mod:`deauth_correlator.drops`
turns rapid re-association into ``client_drop`` disruption events afterwards.
Explicit disconnect lines become ``link_reset`` disruptions immediately.
"""

from __future__ import annotations

import re
from pathlib import Path

from .base import Parser, ParseContext
from ..events import make_event, norm_mac, MAC_IN_TEXT_RE
from ..timeutil import finalize, parse_isoish, parse_rfc3164, rewind_year_if_future

# <134>1 2026-07-14T21:03:11-04:00 OPNsense.localdomain dnsmasq-dhcp 12345 - [meta ...] msg
RFC5424_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?(?:1\s+)?"
    r"(?P<ts>\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+(?P<proc>\S+)\s+(?P<pid>\S+)\s+(?P<msgid>\S+)\s+"
    r"(?:\[(?P<sd>[^\]]*)\]|-)\s*(?P<msg>.*)$"
)

# Jul 14 21:03:11 OPNsense dnsmasq-dhcp[12345]: msg
RFC3164_LINE_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?"
    r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w./-]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)

# Kea writes its own timestamped lines when logging to a file rather than syslog.
KEA_FILE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)\s+"
    r"(?P<level>[A-Z]+)\s+\[(?P<logger>[^\]]+)\]\s+(?P<msg>.*)$"
)

DNSMASQ_RE = re.compile(
    r"DHCP(?P<op>DISCOVER|REQUEST|ACK|NAK|OFFER|RELEASE|INFORM|DECLINE)"
    r"(?:\((?P<iface>[^)]+)\))?\s+"
    r"(?P<rest>.*)$"
)

ISC_RE = re.compile(
    r"DHCP(?P<op>DISCOVER|REQUEST|ACK|NAK|OFFER|RELEASE|INFORM|DECLINE)\b(?P<rest>.*)$"
)

KEA_HWADDR_RE = re.compile(r"hwtype=\d+\s+(?P<mac>(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})")
KEA_EVENT_RE = re.compile(r"\b(?P<event>DHCP4_LEASE_ALLOC|DHCP4_LEASE_RENEW|"
                          r"DHCP4_LEASE_ADVERT|DHCP4_INIT_REBOOT|DHCP6_LEASE_ALLOC|"
                          r"DHCP4_PACKET_RECEIVED|DHCP4_RELEASE)\b")
KEA_PKT_TYPE_RE = re.compile(r"packet type (?P<type>DHCP\w+)")

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

LEASE_OPS = {"DISCOVER", "REQUEST", "ACK", "OFFER", "INFORM"}
RELEASE_OPS = {"RELEASE", "DECLINE", "NAK"}

# Lines that are themselves evidence of a client losing its link.
DISCONNECT_PATTERNS = [
    (re.compile(r"IEEE 802\.11:\s*disassociated", re.I), "disassociated"),
    (re.compile(r"IEEE 802\.11:\s*deauthenticated due to (?P<why>[^(]+)", re.I),
     "deauthenticated"),
    (re.compile(r"\bdeauthenticated\b", re.I), "deauthenticated"),
    (re.compile(r"\bdisassociated\b", re.I), "disassociated"),
    (re.compile(r"CTRL-EVENT-DISCONNECTED", re.I), "wpa_supplicant disconnect"),
    (re.compile(r"AP-STA-DISCONNECTED", re.I), "hostapd station disconnect"),
    (re.compile(r"link state changed to DOWN", re.I), "interface link down"),
    (re.compile(r"\bassociation failed\b", re.I), "association failure"),
]

ASSOC_PATTERNS = [
    re.compile(r"AP-STA-CONNECTED", re.I),
    re.compile(r"IEEE 802\.11:\s*associated", re.I),
    re.compile(r"CTRL-EVENT-CONNECTED", re.I),
]

REASON_IN_TEXT_RE = re.compile(r"reason[ =:]+(?P<code>\d{1,2})", re.I)

DHCP_PROCS = ("dnsmasq", "dhcpd", "kea", "dhcrelay", "dhclient")
WIFI_PROCS = ("hostapd", "wpa_supplicant", "kernel", "wlan")


class OpnsenseParser(Parser):
    id = "opnsense"
    name = "OPNsense DHCP / system log"
    describes = ("DHCP lease activity (dnsmasq, Kea or ISC dhcpd) and wireless "
                 "link-state events from the firewall. Repeated re-association by "
                 "the same client within a short interval is treated as a client drop.")
    extensions = (".log", ".txt", ".syslog", "")

    def sniff(self, path: Path) -> float:
        text = self.head_text(path, 16384)
        if not text:
            return 0.0
        score = 0.0
        low = text.lower()
        if "dnsmasq-dhcp" in low or "dnsmasq" in low:
            score = max(score, 0.9)
        if "dhcpd" in low and "DHCP" in text:
            score = max(score, 0.85)
        if "kea-dhcp" in low or "DHCP4_LEASE" in text:
            score = max(score, 0.9)
        if "hostapd" in low or "wpa_supplicant" in low:
            score = max(score, 0.8)
        if "opnsense" in low:
            score = max(score, 0.75)
        if score == 0.0 and (RFC3164_LINE_RE.match(text.splitlines()[0] if text.splitlines() else "")
                             or RFC5424_RE.match(text.splitlines()[0] if text.splitlines() else "")):
            score = 0.4  # generic syslog; usable but not confidently ours
        return score

    def parse(self, path: Path, ctx: ParseContext) -> list[dict]:
        year_hint = self.year_hint_for(path, ctx)
        file_mtime_local = _file_mtime_local(path, ctx)
        rows: list[dict] = []
        unparsed = 0

        for lineno, line in self.iter_lines(path):
            parsed = _split_syslog(line, ctx, year_hint, file_mtime_local)
            if parsed is None:
                unparsed += 1
                continue
            dt, proc, msg = parsed
            utc, local, offset = finalize(dt, ctx.time)
            common = dict(
                ts_utc=utc, ts_local=local, utc_offset=offset,
                source_file=str(path), source_kind=self.id,
                source_ref=f"line {lineno}", raw=line,
            )
            row = (_wireless_event(proc, msg, common)
                   or _dhcp_event(proc, msg, common))
            if row is not None:
                rows.append(row)

        if unparsed:
            ctx.warn(f"{path.name}: {unparsed} line(s) had no recognizable syslog "
                     f"timestamp and were skipped.")
        return rows


def _file_mtime_local(path: Path, ctx: ParseContext):
    from datetime import datetime
    import os
    return datetime.fromtimestamp(os.path.getmtime(path), tz=ctx.time.tz)


def _split_syslog(line: str, ctx: ParseContext, year_hint: int, file_mtime):
    """Return (datetime, process, message) for any accepted syslog framing."""
    m = RFC5424_RE.match(line)
    if m:
        dt = parse_isoish(m["ts"])
        if dt is not None:
            return dt, m["proc"], m["msg"]

    m = RFC3164_LINE_RE.match(line)
    if m:
        dt = parse_rfc3164(m["ts"], ctx.time, year_hint)
        if dt is not None:
            aware = ctx.time.localize_naive(dt)
            aware = rewind_year_if_future(aware, file_mtime)
            return aware, m["proc"], m["msg"]

    m = KEA_FILE_RE.match(line)
    if m:
        dt = parse_isoish(m["ts"])
        if dt is not None:
            return dt, m["logger"].split(".")[0], m["msg"]

    return None


def _wireless_event(proc: str, msg: str, common: dict) -> dict | None:
    """hostapd / wpa_supplicant / kernel lines that mean a client lost its link."""
    proc_low = (proc or "").lower()
    if not any(p in proc_low for p in WIFI_PROCS):
        # hostapd output is sometimes relayed under another tag; fall back to
        # matching the message body only when it is unmistakably 802.11.
        if "IEEE 802.11" not in msg and "AP-STA-" not in msg:
            return None

    mac = _first_mac(msg)
    for pattern, label in DISCONNECT_PATTERNS:
        m = pattern.search(msg)
        if not m:
            continue
        reason = REASON_IN_TEXT_RE.search(msg)
        return make_event(
            kind="link_reset",
            client_mac=mac,
            dst_mac=mac,
            reason_code=int(reason["code"]) if reason else None,
            notes=f"{proc}: {label}",
            **common,
        )

    for pattern in ASSOC_PATTERNS:
        if pattern.search(msg):
            return make_event(kind="assoc", client_mac=mac,
                              notes=f"{proc}: associated", **common)
    return None


def _dhcp_event(proc: str, msg: str, common: dict) -> dict | None:
    proc_low = (proc or "").lower()
    if not any(p in proc_low for p in DHCP_PROCS) and "DHCP" not in msg:
        return None

    if "kea" in proc_low or "DHCP4_" in msg or "DHCP6_" in msg:
        return _kea_event(msg, common)

    m = DNSMASQ_RE.search(msg) or ISC_RE.search(msg)
    if not m:
        return None
    op = m["op"].upper()
    rest = m.group("rest") or ""
    mac = _first_mac(rest) or _first_mac(msg)
    ip_match = IPV4_RE.search(rest)
    if not mac:
        return None

    kind = "assoc" if op in LEASE_OPS else "context"
    return make_event(
        kind=kind, category="context",
        client_mac=mac,
        notes=f"DHCP{op}" + (f" {ip_match.group(0)}" if ip_match else ""),
        **common,
    )


def _kea_event(msg: str, common: dict) -> dict | None:
    m = KEA_HWADDR_RE.search(msg)
    mac = norm_mac(m["mac"]) if m else _first_mac(msg)
    if not mac:
        return None
    ev = KEA_EVENT_RE.search(msg)
    pkt = KEA_PKT_TYPE_RE.search(msg)
    label = ev["event"] if ev else (pkt["type"] if pkt else "KEA_LEASE")
    if label in ("DHCP4_RELEASE",):
        return make_event(kind="context", category="context", client_mac=mac,
                          notes=label, **common)
    return make_event(kind="assoc", category="context", client_mac=mac,
                      notes=label, **common)


def _first_mac(text: str) -> str:
    m = MAC_IN_TEXT_RE.search(text or "")
    return norm_mac(m.group(0)) if m else ""
