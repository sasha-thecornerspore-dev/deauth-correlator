"""Timezone normalization.

Every timestamp in the pipeline is stored twice: as tz-aware UTC (``ts_utc``,
what the maths uses) and as tz-aware local time in the case timezone
(``ts_local``, what humans read). The UTC offset actually observed in the
source is preserved separately as a string so the report can show that a log
line said ``-04:00`` rather than implying the analyst assumed it.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

DEFAULT_TZ = "America/New_York"

_MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

# "Jul 14 21:03:11" / "Jul  4 09:00:00" - RFC3164, no year.
RFC3164_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})(?:\.(?P<frac>\d+))?"
)

# "2026-07-14T21:03:11.123-04:00" / "2026-07-14 21:03:11,123" / with Z.
ISOISH_RE = re.compile(
    r"^(?P<y>\d{4})-(?P<mon>\d{2})-(?P<day>\d{2})[T ]"
    r"(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})"
    r"(?:[.,](?P<frac>\d{1,9}))?"
    r"(?P<off>Z|[+-]\d{2}:?\d{2})?"
)

# "20260714210311" / "20260714_210311" / "2026-07-14_21-03-11"
COMPACT_RE = re.compile(
    r"(?P<y>20\d{2})[-_]?(?P<mon>0[1-9]|1[0-2])[-_]?(?P<day>0[1-9]|[12]\d|3[01])"
    r"[-_T]?(?P<h>[01]\d|2[0-3])[-_:]?(?P<m>[0-5]\d)[-_:]?(?P<s>[0-5]\d)"
    r"(?:[.,]?(?P<frac>\d{1,3}))?"
)


class TimeContext:
    """Holds the case timezone and the fallback year for year-less log lines."""

    def __init__(self, tz_name: str = DEFAULT_TZ, default_year: int | None = None,
                 assume_offset: str | None = None):
        try:
            self.tz = ZoneInfo(tz_name)
        except ZoneInfoNotFoundError as exc:  # pragma: no cover - env-specific
            raise SystemExit(
                f"Unknown timezone {tz_name!r}. Install 'tzdata' or pick an IANA name "
                f"such as America/New_York."
            ) from exc
        self.tz_name = tz_name
        self.default_year = default_year or datetime.now(tz=self.tz).year
        self.assume_offset = parse_offset(assume_offset) if assume_offset else None
        # Set by parsers when they infer a year for a year-less file, so the
        # report can disclose the inference.
        self.year_inferences: list[str] = []

    def localize_naive(self, naive: datetime) -> datetime:
        """Attach a timezone to a naive timestamp read from a log."""
        if self.assume_offset is not None:
            return naive.replace(tzinfo=timezone(self.assume_offset))
        return naive.replace(tzinfo=self.tz)

    def to_local(self, dt: datetime) -> datetime:
        return dt.astimezone(self.tz)

    def note_year_inference(self, message: str) -> None:
        if message not in self.year_inferences:
            self.year_inferences.append(message)


def parse_offset(text: str) -> timedelta:
    """Parse ``-04:00`` / ``+0530`` / ``Z`` into a timedelta."""
    text = text.strip()
    if text in ("Z", "z", "UTC", "utc"):
        return timedelta(0)
    m = re.fullmatch(r"(?P<sign>[+-])(?P<h>\d{2}):?(?P<m>\d{2})", text)
    if not m:
        raise ValueError(f"cannot parse UTC offset {text!r}")
    delta = timedelta(hours=int(m["h"]), minutes=int(m["m"]))
    return -delta if m["sign"] == "-" else delta


def offset_str(dt: datetime) -> str:
    """Render a tz-aware datetime's UTC offset as ``-04:00``."""
    off = dt.utcoffset()
    if off is None:
        return ""
    total = int(off.total_seconds())
    sign = "-" if total < 0 else "+"
    total = abs(total)
    return f"{sign}{total // 3600:02d}:{(total % 3600) // 60:02d}"


def parse_isoish(text: str) -> datetime | None:
    """Parse an ISO-8601-like timestamp, returning naive or aware as written."""
    m = ISOISH_RE.match(text.strip())
    if not m:
        return None
    micro = _frac_to_micro(m["frac"])
    dt = datetime(int(m["y"]), int(m["mon"]), int(m["day"]),
                  int(m["h"]), int(m["m"]), int(m["s"]), micro)
    if m["off"]:
        dt = dt.replace(tzinfo=timezone(parse_offset(m["off"])))
    return dt


def parse_rfc3164(text: str, ctx: TimeContext, year_hint: int | None = None) -> datetime | None:
    """Parse a year-less syslog timestamp using ``year_hint`` (or the context year)."""
    m = RFC3164_RE.match(text)
    if not m:
        return None
    year = year_hint or ctx.default_year
    try:
        return datetime(year, _MONTHS[m["mon"].lower()], int(m["day"]),
                        int(m["h"]), int(m["m"]), int(m["s"]), _frac_to_micro(m["frac"]))
    except ValueError:
        return None


def parse_compact(text: str) -> tuple[datetime, str] | None:
    """Find an embedded ``YYYYMMDDhhmmss``-style stamp. Returns (dt, matched_text)."""
    m = COMPACT_RE.search(text)
    if not m:
        return None
    try:
        dt = datetime(int(m["y"]), int(m["mon"]), int(m["day"]),
                      int(m["h"]), int(m["m"]), int(m["s"]), _frac_to_micro(m["frac"]))
    except ValueError:
        return None
    return dt, m.group(0)


def parse_any(text: str, ctx: TimeContext, year_hint: int | None = None) -> datetime | None:
    """Best-effort parse of a timestamp in any supported shape."""
    text = str(text).strip()
    if not text:
        return None
    dt = parse_isoish(text)
    if dt is not None:
        return dt
    dt = parse_rfc3164(text, ctx, year_hint)
    if dt is not None:
        return dt
    # Bare epoch seconds or milliseconds.
    if re.fullmatch(r"\d{9,13}(\.\d+)?", text):
        val = float(text)
        if val > 1e11:  # milliseconds
            val /= 1000.0
        return datetime.fromtimestamp(val, tz=timezone.utc)
    got = parse_compact(text)
    if got is not None:
        return got[0]
    # US-style "07/14/2026 09:03:11 PM" as a last resort.
    for fmt in ("%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %H:%M:%S",
                "%d/%m/%Y %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def finalize(dt: datetime, ctx: TimeContext) -> tuple[datetime, datetime, str]:
    """Normalize one parsed timestamp.

    Returns ``(utc, local, observed_offset)``. ``observed_offset`` is the offset
    that was literally present in the source, or the case-timezone offset that
    was applied to a naive timestamp.
    """
    if dt.tzinfo is None:
        dt = ctx.localize_naive(dt)
    observed = offset_str(dt)
    return dt.astimezone(timezone.utc), dt.astimezone(ctx.tz), observed


def infer_year_for_file(mtime_epoch: float, ctx: TimeContext) -> int:
    """Year to assume for a year-less log, based on the file's modification time."""
    return datetime.fromtimestamp(mtime_epoch, tz=ctx.tz).year


def rewind_year_if_future(dt: datetime, reference: datetime) -> datetime:
    """Handle a December log read in January: pull the stamp back a year.

    A year-less syslog line dated 31 Dec, read from a file last written on
    2 Jan, belongs to the previous year. Only applied when the naive
    interpretation lands more than a day in the future relative to the file.
    """
    if dt > reference + timedelta(days=1):
        try:
            return dt.replace(year=dt.year - 1)
        except ValueError:  # 29 Feb
            return dt.replace(year=dt.year - 1, day=28)
    return dt


def _frac_to_micro(frac: str | None) -> int:
    if not frac:
        return 0
    return int(round(float("0." + frac) * 1_000_000))


def humanize_delta(seconds: float) -> str:
    """``-4.2`` -> ``4.2 s before``; used in the plain-English report."""
    if seconds != seconds:  # NaN
        return "n/a"
    mag = abs(seconds)
    if mag < 1:
        text = f"{mag * 1000:.0f} ms"
    elif mag < 90:
        text = f"{mag:.1f} s"
    elif mag < 5400:
        text = f"{mag / 60:.1f} min"
    else:
        text = f"{mag / 3600:.2f} h"
    if seconds < 0:
        return f"{text} before"
    if seconds > 0:
        return f"{text} after"
    return "simultaneous"
