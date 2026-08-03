"""correlation.csv - one row per camera event.

Written with explicit local *and* UTC columns. A reader should never have to
guess which timezone a column is in, and an opposing expert should be able to
recompute every delta from the two absolute times alone.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

COLUMNS = [
    ("event_local", "camera_event_local"),
    ("event_utc", "camera_event_utc"),
    ("utc_offset", "camera_event_utc_offset"),
    ("plate", "plate"),
    ("make", "make"),
    ("model", "model"),
    ("coincidence", "coincidence"),
    ("delta_s", "delta_seconds"),
    ("delta_plain", "delta_plain_english"),
    ("nearest_kind", "nearest_disruption_type"),
    ("nearest_local", "nearest_disruption_local"),
    ("attacker_mac", "deauth_source_mac"),
    ("reason_code", "reason_code"),
    ("reason", "reason_meaning"),
    ("client_mac", "affected_client_mac"),
    ("nearest_deauth_local", "nearest_deauth_frame_local"),
    ("deauth_delta_s", "deauth_delta_seconds"),
    ("nearest_drop_local", "nearest_client_drop_local"),
    ("drop_delta_s", "client_drop_delta_seconds"),
    ("events_in_window", "disruption_events_in_window"),
    ("in_analysis_period", "within_analysis_period"),
    ("camera_source", "camera_source_file"),
    ("camera_ref", "camera_source_reference"),
    ("notes", "notes"),
]


def write_correlation_csv(matches: pd.DataFrame, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    out = pd.DataFrame()
    for source, target in COLUMNS:
        out[target] = matches[source] if source in matches.columns else None

    for col in ("camera_event_local", "camera_event_utc", "nearest_disruption_local",
                "nearest_deauth_frame_local", "nearest_client_drop_local"):
        out[col] = out[col].map(_fmt_time)

    out["coincidence"] = out["coincidence"].map(
        lambda v: "YES" if bool(v) else "no")
    out["within_analysis_period"] = out["within_analysis_period"].map(
        lambda v: "yes" if bool(v) else "NO - outside overlapping period")

    out.to_csv(path, index=False, encoding="utf-8")
    return path


def write_events_csv(events: pd.DataFrame, path: str | Path) -> Path:
    """The full normalized event list, for anyone who wants to recheck the work."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    out = events.copy()
    for col in ("ts_utc", "ts_local"):
        out[col] = out[col].map(_fmt_time)
    out.to_csv(path, index=False, encoding="utf-8")
    return path


def write_incidents_csv(incidents: pd.DataFrame, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    out = incidents.copy()
    for col in ("ts_utc", "ts_local", "end_utc"):
        if col in out.columns:
            out[col] = out[col].map(_fmt_time)
    out.to_csv(path, index=False, encoding="utf-8")
    return path


def _fmt_time(value) -> str:
    if value is None or value != value:
        return ""
    try:
        return pd.Timestamp(value).isoformat(timespec="milliseconds")
    except (ValueError, TypeError):
        return str(value)
