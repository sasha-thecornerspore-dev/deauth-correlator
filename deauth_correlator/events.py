"""The one event schema every parser emits and every analysis stage consumes.

Parsers return plain dicts; :func:`to_frame` turns a list of them into a
normalized pandas DataFrame with a fixed column set and dtypes. Nothing
downstream needs to know which log format a row came from.
"""

from __future__ import annotations

import re
import pandas as pd

EVENT_COLUMNS = [
    "ts_utc",        # tz-aware UTC - all arithmetic uses this
    "ts_local",      # tz-aware, case timezone - all display uses this
    "utc_offset",    # offset observed in the source, e.g. "-04:00"
    "kind",          # deauth | disassoc | client_drop | link_reset | camera | assoc | alert
    "category",      # camera | disruption | context
    "subtype",       # protocol operation, e.g. DISCOVER / REQUEST / ACK / RENEW
    "src_mac",       # transmitter (the deauth sender - the "attacker" address)
    "dst_mac",       # receiver (the targeted client, or ff:ff:ff:ff:ff:ff)
    "bssid",
    "client_mac",    # the affected client, whichever field it came from
    "reason_code",
    "reason_text",
    "channel",
    "signal",
    "plate",
    "make",
    "model",
    "notes",
    "source_file",
    "source_kind",   # parser id
    "source_ref",    # line number / row number / packet number
    "raw",
]

# Categories
CAMERA = "camera"
DISRUPTION = "disruption"
CONTEXT = "context"

DISRUPTION_KINDS = {"deauth", "disassoc", "client_drop", "link_reset", "alert"}

BROADCAST = "ff:ff:ff:ff:ff:ff"

# IEEE 802.11 reason codes (802.11-2020 Table 9-49). Codes 1 and 7 are the
# classic signature of an off-the-shelf deauth tool (aireplay-ng, mdk4,
# esp8266 deauthers) rather than a genuine AP-initiated disconnect.
REASON_CODES = {
    0: "Reserved",
    1: "Unspecified reason",
    2: "Previous authentication no longer valid",
    3: "Deauthenticated because sending STA is leaving BSS",
    4: "Disassociated due to inactivity",
    5: "Disassociated because AP is unable to handle all associated STAs",
    6: "Class 2 frame received from nonauthenticated STA",
    7: "Class 3 frame received from nonassociated STA",
    8: "Disassociated because sending STA is leaving BSS",
    9: "STA requesting association is not authenticated with responding STA",
    10: "Disassociated because of unacceptable power capability",
    11: "Disassociated because of unacceptable supported channels",
    12: "Disassociated due to BSS transition management",
    13: "Invalid element",
    14: "MIC failure",
    15: "4-Way Handshake timeout",
    16: "Group Key Handshake timeout",
    17: "Element in 4-Way Handshake different from (Re)Association Request",
    18: "Invalid group cipher",
    19: "Invalid pairwise cipher",
    20: "Invalid AKMP",
    21: "Unsupported RSNE version",
    22: "Invalid RSNE capabilities",
    23: "IEEE 802.1X authentication failed",
    24: "Cipher suite rejected because of security policy",
    25: "TDLS teardown - unreachable peer",
    26: "TDLS teardown - unspecified reason",
    32: "Disassociated for unspecified QoS-related reason",
    33: "Disassociated because AP lacks bandwidth for this QoS STA",
    34: "Disassociated because of excessive unacknowledged frames",
    35: "Disassociated because STA is transmitting outside the limits of its TXOPs",
    36: "Requested from peer STA as the STA is leaving the BSS",
    37: "Requested from peer STA as it does not want to use this mechanism",
    38: "Requested from peer STA as the STA received frames using the mechanism",
    39: "Requested from peer STA due to timeout",
    45: "Peer STA does not support the requested cipher suite",
    46: "Disassociated - authorized access limit reached",
    47: "Disassociated - external service requirements",
}

# Reason codes that off-the-shelf deauthers emit by default.
TOOL_SIGNATURE_REASONS = {1, 7}


def reason_text(code) -> str:
    if code is None or (isinstance(code, float) and code != code):
        return ""
    try:
        code = int(code)
    except (TypeError, ValueError):
        return ""
    return REASON_CODES.get(code, f"Reserved/unknown reason code {code}")


_MAC_RE = re.compile(r"^([0-9a-fA-F]{2})[:\-.]?"
                     r"([0-9a-fA-F]{2})[:\-.]?"
                     r"([0-9a-fA-F]{2})[:\-.]?"
                     r"([0-9a-fA-F]{2})[:\-.]?"
                     r"([0-9a-fA-F]{2})[:\-.]?"
                     r"([0-9a-fA-F]{2})$")

MAC_IN_TEXT_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")


def norm_mac(value) -> str:
    """Normalize any MAC spelling to lowercase colon form. Returns '' if invalid."""
    if value is None:
        return ""
    text = str(value).strip()
    if not text or text.lower() in ("nan", "none", "(not associated)"):
        return ""
    m = _MAC_RE.match(text.replace(" ", ""))
    if not m:
        return ""
    return ":".join(g.lower() for g in m.groups())


def mac_from_bytes(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def is_broadcast(mac: str) -> bool:
    return norm_mac(mac) == BROADCAST


def is_group_addressed(mac: str) -> bool:
    """True for broadcast and multicast destinations (I/G bit set)."""
    mac = norm_mac(mac)
    if not mac:
        return False
    return bool(int(mac.split(":")[0], 16) & 0x01)


def make_event(**kwargs) -> dict:
    """Build one event row, filling unset columns with sensible blanks."""
    row = {col: None for col in EVENT_COLUMNS}
    row.update({k: v for k, v in kwargs.items() if k in EVENT_COLUMNS})
    if row["kind"] and not row["category"]:
        row["category"] = (
            CAMERA if row["kind"] == CAMERA
            else DISRUPTION if row["kind"] in DISRUPTION_KINDS
            else CONTEXT
        )
    for mac_col in ("src_mac", "dst_mac", "bssid", "client_mac"):
        if row[mac_col]:
            row[mac_col] = norm_mac(row[mac_col])
    if row["reason_code"] is not None and not row["reason_text"]:
        row["reason_text"] = reason_text(row["reason_code"])
    return row


def to_frame(rows: list[dict]) -> pd.DataFrame:
    """Normalize a list of event dicts into the canonical DataFrame."""
    if not rows:
        df = pd.DataFrame({c: pd.Series(dtype="object") for c in EVENT_COLUMNS})
        df["ts_utc"] = pd.Series(dtype="datetime64[ns, UTC]")
        df["ts_local"] = pd.Series(dtype="object")
        df["reason_code"] = pd.Series(dtype="Float64")
        return df

    df = pd.DataFrame(rows)
    for col in EVENT_COLUMNS:
        if col not in df.columns:
            df[col] = None
    df = df[EVENT_COLUMNS]
    df["ts_utc"] = pd.to_datetime(df["ts_utc"], utc=True)
    df["reason_code"] = pd.to_numeric(df["reason_code"], errors="coerce").astype("Float64")
    df = df.sort_values("ts_utc", kind="stable").reset_index(drop=True)
    return df


def text(value) -> str:
    """A display-safe string for a possibly-missing field.

    Never use ``value or ""`` on a column read back from a DataFrame. Under
    pandas 3.x a column mixing strings and blanks gets ``str`` dtype with
    ``NaN`` for the blanks, and ``NaN`` is truthy - so ``or ""`` returns the
    NaN and the report prints a MAC address of ``nan``.
    """
    if value is None:
        return ""
    if isinstance(value, float) and value != value:
        return ""
    result = str(value).strip()
    return "" if result.lower() in ("nan", "none", "<na>", "nat") else result


_EPOCH = pd.Timestamp("1970-01-01", tz="UTC")


def epoch_seconds(series) -> "np.ndarray":
    """Convert a tz-aware timestamp Series to float epoch seconds.

    Computed as an explicit difference from the epoch rather than through
    ``astype("int64")``: the integer view depends on the Series' datetime
    resolution, which pandas defaults to microseconds in 3.x and nanoseconds
    before that, so casting silently rescales times by 1000.
    """
    import numpy as np
    if series is None or len(series) == 0:
        return np.array([], dtype=float)
    values = pd.to_datetime(series, utc=True)
    return (values - _EPOCH).dt.total_seconds().to_numpy(dtype=float)


def disruptions(df: pd.DataFrame) -> pd.DataFrame:
    return df[df["category"] == DISRUPTION]


def cameras(df: pd.DataFrame) -> pd.DataFrame:
    return df[df["category"] == CAMERA]


def deauth_frames(df: pd.DataFrame) -> pd.DataFrame:
    return df[df["kind"].isin(["deauth", "disassoc"])]


def summarize_kinds(df: pd.DataFrame) -> dict:
    if df.empty:
        return {}
    return df["kind"].value_counts().to_dict()
