"""Deciding what to pull off the firewall, and writing it down as evidence.

The point of this module is that you should not have to go and find the logs.
You attach the camera events - which are the part only you can produce - and
this works out which stretch of firewall log could possibly bear on them, pulls
exactly that, and writes it where the rest of the pipeline expects to find it.

Two things it is careful about.

**The window is derived, not guessed.** It comes from the camera events
themselves: the span they cover, widened by a baseline margin on each side. The
margin is not decoration. Every statistic in this tool compares the disruption
rate inside the event windows against the rate outside them, so a log that
covers only the events has no outside and the comparison has nothing to stand
on. Pulling the span alone would quietly produce the most flattering possible
answer.

**What is written down is what the firewall said.** The rows are saved
verbatim, inside an envelope recording where they came from, when, over what
kind of connection, and exactly which request produced them. Nothing is
reformatted into something that looks like a log file the firewall never wrote;
:mod:`deauth_correlator.parsers.opnsense_api` reads the saved rows directly.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .. import __tool_name__, __version__
from .opnsense_api import FirewallConfig, FirewallUnavailable, OpnsenseClient

#: How much log to pull on each side of the camera events, by default.
DEFAULT_BASELINE_MARGIN_H = 2.0

#: Never pull more than this, however wide the events are spread. A month of
#: DHCP logging is already an unwieldy exhibit.
MAX_WINDOW_DAYS = 31


@dataclass(frozen=True)
class LogSource:
    """One log on the firewall, named the way OPNsense names it."""

    module: str
    scope: str
    label: str
    why: str
    #: False for logs that are useful when present but whose absence is normal.
    expected: bool = False

    @property
    def key(self) -> str:
        return f"{self.module}/{self.scope}"

    def filename(self, since: datetime, until: datetime) -> str:
        stamp = f"{since:%Y%m%dT%H%M%SZ}_{until:%Y%m%dT%H%M%SZ}"
        return f"opnsense_{self.module}_{self.scope}_{stamp}.json"


#: The logs worth asking for, in the order they matter. OPNsense names a log by
#: a module and a scope, which is what the two path components of
#: /api/diagnostics/log/{module}/{scope} are; the service pages in the web
#: interface use exactly the same pair, so "Services: Kea DHCP: Log File" at
#: /ui/diagnostics/log/core/kea is module "core", scope "kea".
#:
#: Which DHCP server is in use varies by installation and only one of them will
#: normally answer, so all three are offered and the ones that are not there
#: are skipped rather than reported as failures.
LOG_SOURCES: tuple[LogSource, ...] = (
    LogSource("core", "kea", "Kea DHCP",
              "lease activity from the Kea DHCP server, which is the default on "
              "current OPNsense"),
    LogSource("core", "dnsmasq", "dnsmasq DHCP",
              "lease activity where dnsmasq is serving DHCP"),
    LogSource("core", "dhcpd", "ISC dhcpd",
              "lease activity from the older ISC DHCP server"),
    LogSource("core", "system", "System log",
              "wireless link-state messages - hostapd, wpa_supplicant and the "
              "kernel - which is where a disconnection is recorded when it does "
              "not show up as a DHCP event",
              expected=True),
)


@dataclass
class FetchResult:
    """What one fetch produced, for the log pane and for the report."""

    written: list[Path] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    rows_by_source: dict = field(default_factory=dict)
    since: datetime | None = None
    until: datetime | None = None
    truncated: list[str] = field(default_factory=list)

    @property
    def total_rows(self) -> int:
        return sum(self.rows_by_source.values())

    def summary(self) -> str:
        if not self.written:
            return ("Nothing was written. The firewall has none of the logs this "
                    "looks for, or the window contained no entries.")
        files = ", ".join(p.name for p in self.written)
        span = ""
        if self.since and self.until:
            span = (f" covering {self.since:%Y-%m-%d %H:%M} to "
                    f"{self.until:%Y-%m-%d %H:%M} UTC")
        note = ""
        if self.truncated:
            note = (f" Note: {', '.join(self.truncated)} hit the page limit, so "
                    f"the oldest part of the window is missing from it.")
        return (f"{self.total_rows:,} log rows{span}, written as {files}.{note}")


def window_from_events(times, margin_hours: float = DEFAULT_BASELINE_MARGIN_H
                       ) -> tuple[datetime, datetime]:
    """The stretch of log worth pulling for a set of camera-event times.

    ``times`` is any iterable of timezone-aware datetimes. The result is the
    span they cover widened by ``margin_hours`` on each side, so the analysis
    has periods with no camera event in them to compare against.
    """
    stamps = sorted(t for t in times if t is not None)
    if not stamps:
        raise ValueError(
            "there are no camera events to take a time window from. Attach the "
            "camera events first - they are what says which stretch of log "
            "matters - or give an explicit --since and --until.")
    margin = timedelta(hours=max(margin_hours, 0.0))
    since = stamps[0].astimezone(timezone.utc) - margin
    until = stamps[-1].astimezone(timezone.utc) + margin
    if until - since > timedelta(days=MAX_WINDOW_DAYS):
        raise ValueError(
            f"the camera events span {(until - since).days} days, past the "
            f"{MAX_WINDOW_DAYS} this will pull in one go. Narrow the camera "
            f"events, or pass --since and --until for the part you want.")
    return since, until


def discover_sources(client: OpnsenseClient,
                     sources: tuple[LogSource, ...] = LOG_SOURCES
                     ) -> list[LogSource]:
    """Which of the candidate logs this particular firewall actually has."""
    return [source for source in sources
            if client.log_exists(source.module, source.scope)]


def fetch_logs(config: FirewallConfig, since: datetime, until: datetime,
               outdir: str | Path, sources: tuple[LogSource, ...] = LOG_SOURCES,
               progress=None) -> FetchResult:
    """Pull each available log for the window and write it into ``outdir``.

    Returns a :class:`FetchResult`. Files are written only for logs that had at
    least one row in the window; a log that exists but was quiet leaves nothing
    behind, and is reported as skipped rather than as an empty exhibit.
    """
    def say(message: str) -> None:
        if progress is not None:
            progress(message)

    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    result = FetchResult(since=since, until=until)

    with OpnsenseClient(config) as client:
        try:
            identity = client.identify()
        except FirewallUnavailable:
            identity = {}
        product = _product_name(identity)
        say(f"Connected to {config.host} ({product}).")

        for source in sources:
            say(f"Looking for {source.label} ({source.key}) …")
            try:
                rows, truncated = _collect(client, source, since, until, say)
            except FirewallUnavailable as exc:
                result.skipped.append(f"{source.label}: {exc}")
                say(f"  not available: {exc}")
                continue

            if not rows:
                result.skipped.append(
                    f"{source.label}: present, but no entries in the window")
                say("  present, but nothing in the window.")
                continue

            path = outdir / source.filename(since, until)
            _write(path, source, rows, config, product, since, until, truncated)
            result.written.append(path)
            result.rows_by_source[source.key] = len(rows)
            if truncated:
                result.truncated.append(source.label)
            say(f"  {len(rows):,} rows -> {path.name}")

    return result


def _collect(client: OpnsenseClient, source: LogSource, since: datetime,
             until: datetime, say) -> tuple[list[dict], bool]:
    """Page through one log until the window is covered.

    OPNsense returns newest first, so paging walks backwards in time and can
    stop as soon as a page is entirely older than the window.
    """
    from .opnsense_api import MAX_PAGES, PAGE_ROWS

    collected: list[dict] = []
    truncated = False
    for page in range(1, MAX_PAGES + 1):
        payload = client.log_page(source.module, source.scope, page)
        rows = payload.get("rows")
        if not isinstance(rows, list) or not rows:
            break

        older_than_window = 0
        for row in rows:
            when = row_time(row)
            if when is None:
                # Keep it. A row whose timestamp this does not understand is
                # still evidence, and dropping it silently would be worse than
                # carrying a few rows outside the window.
                collected.append(row)
                continue
            if when > until:
                continue
            if when < since:
                older_than_window += 1
                continue
            collected.append(row)

        if older_than_window:
            break
        if len(rows) < PAGE_ROWS:
            break
        if page % 20 == 0:
            say(f"  … {len(collected):,} rows so far")
    else:
        truncated = True

    collected.reverse()          # oldest first, the way a log file reads
    return collected, truncated


#: Field names OPNsense has used for the timestamp and the message. Checked in
#: order; the shape differs between releases and between log back-ends.
TIME_FIELDS = ("timestamp", "@timestamp", "time", "date")
MESSAGE_FIELDS = ("line", "message", "msg", "text")
PROCESS_FIELDS = ("process_name", "process", "program", "app_name", "processName")


def row_time(row: dict) -> datetime | None:
    """The timestamp of one API row, as an aware datetime, or None."""
    if not isinstance(row, dict):
        return None
    for name in TIME_FIELDS:
        raw = row.get(name)
        if not raw:
            continue
        parsed = _parse_stamp(str(raw))
        if parsed is not None:
            return parsed
    return None


def row_message(row: dict) -> str:
    for name in MESSAGE_FIELDS:
        value = row.get(name)
        if isinstance(value, str) and value:
            return value
    return ""


def row_process(row: dict) -> str:
    for name in PROCESS_FIELDS:
        value = row.get(name)
        if isinstance(value, str) and value:
            return value
    return ""


def _parse_stamp(text: str) -> datetime | None:
    text = text.strip()
    if not text:
        return None
    try:                                   # epoch seconds, as some rows carry
        if text.replace(".", "", 1).isdigit() and len(text.split(".")[0]) >= 9:
            return datetime.fromtimestamp(float(text), tz=timezone.utc)
    except (ValueError, OSError, OverflowError):
        pass
    candidate = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        # OPNsense reports local time for the firewall. Without an offset the
        # only honest reading is UTC, and the analysis records the assumption.
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _product_name(identity: dict) -> str:
    data = identity.get("data") if isinstance(identity, dict) else None
    for holder in (data, identity):
        if not isinstance(holder, dict):
            continue
        versions = holder.get("versions")
        if isinstance(versions, list) and versions:
            return str(versions[0])
        for key in ("product_version", "product", "version"):
            if holder.get(key):
                return str(holder[key])
    return "OPNsense, version not reported"


def _write(path: Path, source: LogSource, rows: list[dict],
           config: FirewallConfig, product: str, since: datetime,
           until: datetime, truncated: bool) -> None:
    """Write the rows verbatim inside a provenance envelope."""
    envelope = {
        "deauth_correlator_fetch": 1,
        "fetched_utc": datetime.now(tz=timezone.utc).isoformat(
            timespec="seconds"),
        "tool": f"{__tool_name__} {__version__}",
        "firewall": {
            "host": config.host,
            "port": config.port,
            "product": product,
            "tls": config.tls_description(),
        },
        "request": {
            "endpoint": f"/api/diagnostics/log/{source.module}/{source.scope}",
            "module": source.module,
            "scope": source.scope,
            "label": source.label,
            "window_start_utc": since.isoformat(timespec="seconds"),
            "window_end_utc": until.isoformat(timespec="seconds"),
        },
        "row_count": len(rows),
        "complete": not truncated,
        "note": ("Rows are exactly as the firewall returned them. The window "
                 "was applied by this tool, using each row's own timestamp."
                 + ("" if not truncated else
                    " INCOMPLETE: the page limit was reached, so entries older "
                    "than the last row below were not retrieved.")),
        "rows": rows,
    }
    path.write_text(json.dumps(envelope, indent=1, ensure_ascii=False),
                    encoding="utf-8")
