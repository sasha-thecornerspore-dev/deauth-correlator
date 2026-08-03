"""Deriving client-drop events from DHCP lease activity.

A DHCP log does not say "this client was knocked off the network". It says a
client asked for an address. The inference chain is:

1. A normal join produces a burst of lease traffic - DISCOVER, OFFER, REQUEST,
   ACK - inside a second or two. Those are collapsed into one *association
   episode* so a single ordinary join is never counted as four events.
2. A client that already holds a valid lease does not re-run that handshake.
   When the same MAC starts a second episode within ``reassoc_window`` of the
   previous one, something interrupted it. That second episode is a client drop.

The first episode seen for a MAC is never a drop - there is nothing to say it
was preceded by a disconnection.
"""

from __future__ import annotations

import pandas as pd

from .events import make_event

DEFAULT_HANDSHAKE_WINDOW = 10.0
DEFAULT_REASSOC_WINDOW = 120.0


def derive_client_drops(df: pd.DataFrame,
                        handshake_window_s: float = DEFAULT_HANDSHAKE_WINDOW,
                        reassoc_window_s: float = DEFAULT_REASSOC_WINDOW) -> list[dict]:
    """Return new ``client_drop`` event rows derived from lease/assoc context rows."""
    if df.empty:
        return []

    lease = df[(df["kind"] == "assoc") & df["client_mac"].astype(bool)]
    if lease.empty:
        return []

    drops: list[dict] = []
    for mac, group in lease.groupby("client_mac", sort=False):
        group = group.sort_values("ts_utc")
        episodes = _episodes(group, handshake_window_s)
        for previous, current in zip(episodes, episodes[1:]):
            gap = (current["ts_utc"] - previous["ts_utc"]).total_seconds()
            if gap > reassoc_window_s:
                continue
            drops.append(make_event(
                ts_utc=current["ts_utc"],
                ts_local=current["ts_local"],
                utc_offset=current["utc_offset"],
                kind="client_drop",
                client_mac=mac,
                dst_mac=mac,
                notes=(f"re-association {gap:.1f} s after the previous one "
                       f"({current['episode_events']} lease message(s)); a client "
                       f"holding a valid lease does not normally repeat the DHCP "
                       f"handshake this soon"),
                source_file=current["source_file"],
                source_kind=f"{current['source_kind']}+derived",
                source_ref=current["source_ref"],
                raw=current["raw"],
            ))
    return drops


def _episodes(group: pd.DataFrame, handshake_window_s: float) -> list[dict]:
    """Collapse a MAC's lease messages into association episodes."""
    episodes: list[dict] = []
    current: dict | None = None
    last_ts = None

    for row in group.itertuples(index=False):
        if current is None or (row.ts_utc - last_ts).total_seconds() > handshake_window_s:
            if current is not None:
                episodes.append(current)
            current = {
                "ts_utc": row.ts_utc,
                "ts_local": row.ts_local,
                "utc_offset": row.utc_offset,
                "source_file": row.source_file,
                "source_kind": row.source_kind,
                "source_ref": row.source_ref,
                "raw": row.raw,
                "episode_events": 1,
            }
        else:
            current["episode_events"] += 1
        last_ts = row.ts_utc

    if current is not None:
        episodes.append(current)
    return episodes


def cluster_incidents(df: pd.DataFrame, gap_s: float = 10.0) -> pd.DataFrame:
    """Collapse disruption events into distinct physical incidents.

    A 200-frame deauth flood is one attack, not 200 pieces of evidence, and a
    hostapd disconnect line plus the DHCP re-association it caused are one
    outage seen twice. Statistics run on incidents; the full event list is
    still kept for the timeline and the report, so corroboration stays visible.

    Returns one row per incident with the incident's start time, the number and
    kinds of events it contains, and the source MACs involved.
    """
    disruption = df[df["category"] == "disruption"].sort_values("ts_utc")
    if disruption.empty:
        return pd.DataFrame(columns=[
            "ts_utc", "ts_local", "end_utc", "n_events", "kinds", "src_macs",
            "client_macs", "reason_codes", "sources", "has_deauth"])

    times = disruption["ts_utc"].tolist()
    boundaries = [0]
    for i in range(1, len(times)):
        if (times[i] - times[i - 1]).total_seconds() > gap_s:
            boundaries.append(i)
    boundaries.append(len(times))

    records = []
    for start, end in zip(boundaries, boundaries[1:]):
        chunk = disruption.iloc[start:end]
        kinds = sorted(set(chunk["kind"].dropna()))
        records.append({
            "ts_utc": chunk["ts_utc"].iloc[0],
            "ts_local": chunk["ts_local"].iloc[0],
            "end_utc": chunk["ts_utc"].iloc[-1],
            "n_events": len(chunk),
            "kinds": ", ".join(kinds),
            "src_macs": ", ".join(sorted({m for m in chunk["src_mac"].dropna() if m})),
            "client_macs": ", ".join(sorted({m for m in chunk["client_mac"].dropna() if m})),
            "reason_codes": ", ".join(
                str(int(c)) for c in sorted(set(chunk["reason_code"].dropna()))),
            "sources": ", ".join(sorted(set(chunk["source_kind"].dropna()))),
            "has_deauth": bool(chunk["kind"].isin(["deauth", "disassoc"]).any()),
        })

    return pd.DataFrame(records)
