"""Deriving client-drop events from DHCP lease activity.

A DHCP log never says "this client was knocked off the network". It says a
client asked for an address, and most of the time that is entirely routine.
Turning routine traffic into disconnection evidence is the worst thing this
module could do, so the rule is narrow:

    A client drop is a **DISCOVER** from a client that held a confirmed lease
    moments earlier.

That is the only pattern that means lost state. A client with a working lease
renews it with REQUEST/ACK; it does not go back to the beginning. Everything
else that superficially looks like "repeated DHCP activity" is excluded by
name, because each of these occurs constantly on healthy networks:

* **Retransmission backoff.** RFC 2131 has a client retry DISCOVER at roughly
  4, 8, 16 and 32-second intervals when the server does not answer. Those gaps
  are wider than any plausible handshake window, so grouping messages by
  proximity in time turned one client that simply could not reach the server
  into several "disconnections". Retries with no ACK between them are one
  unfinished attempt.
* **Lease renewal.** At T1 the client sends REQUEST and gets ACK, forever, with
  no DISCOVER. Nothing was lost, so it can never be a drop.
* **DHCPINFORM.** A statically-addressed host asking for option data. Not a
  lease acquisition at all.
* **An already-logged disconnection.** When hostapd recorded the disconnect
  directly, the DHCP re-acquisition that follows is its consequence. Counting
  both would make one outage look like two.

The first activity seen for a MAC is never a drop: there is no evidence it held
anything to lose.
"""

from __future__ import annotations

import pandas as pd

from .events import make_event

DEFAULT_HANDSHAKE_WINDOW = 10.0
DEFAULT_REASSOC_WINDOW = 120.0
DEFAULT_RECONNECT_WINDOW = 120.0


def derive_client_drops(df: pd.DataFrame,
                        handshake_window_s: float = DEFAULT_HANDSHAKE_WINDOW,
                        reassoc_window_s: float = DEFAULT_REASSOC_WINDOW,
                        reconnect_window_s: float = DEFAULT_RECONNECT_WINDOW
                        ) -> list[dict]:
    """Return new ``client_drop`` event rows derived from lease/assoc context rows.

    ``handshake_window_s`` is accepted for interface stability but is no longer
    used: grouping messages by proximity in time is what let retransmission
    backoff masquerade as repeated disconnections. The operation each message
    carries is now what decides, which does not depend on timing at all.
    """
    if df.empty:
        return []

    has_mac = df["client_mac"].map(lambda v: bool(str(v or "").strip()))
    lease = df[(df["kind"] == "assoc") & has_mac]
    if lease.empty:
        return []

    resets = _link_reset_times(df)
    drops: list[dict] = []
    for mac, group in lease.groupby("client_mac", sort=False):
        drops.extend(_drops_for_client(
            mac, group.sort_values("ts_utc"), resets.get(mac, []),
            reassoc_window_s, reconnect_window_s))
    return drops


def _drops_for_client(mac: str, group: pd.DataFrame, resets: list,
                      reassoc_window_s: float,
                      reconnect_window_s: float) -> list[dict]:
    """Walk one client's lease traffic and pick out genuine re-acquisitions.

    The state machine encodes what actually distinguishes a disconnection from
    routine traffic:

    * A **DISCOVER** means the client is starting acquisition from nothing. Only
      that can indicate lost lease state.
    * Repeated DISCOVERs with no ACK between them are RFC 2131 retransmission
      backoff - one client trying and failing, not one disconnection per retry.
      The backoff intervals (4, 8, 16, 32 s) exceed any sane handshake window,
      so counting each retry separately manufactured drops out of a client that
      simply could not reach the server.
    * A **renewal** is REQUEST/ACK with no DISCOVER. A client renewing at T1 has
      never lost anything, so it can never be a drop.
    * An **ACK** confirms the client holds a working lease, and is what a later
      DISCOVER is judged against.
    """
    confirming = _confirming_ops(group)
    drops: list[dict] = []

    last_confirmed = None
    attempt_open = False

    for row in group.itertuples(index=False):
        op = str(getattr(row, "subtype", "") or "").upper()

        if op in ("INFORM", "RELEASE", "DECLINE", "NAK"):
            continue

        if op in confirming:
            last_confirmed = row.ts_utc
            attempt_open = False
            continue

        if op != "DISCOVER":
            continue  # OFFER, or a REQUEST that is part of a renewal

        if attempt_open:
            continue  # retransmission of an acquisition already under way
        attempt_open = True

        if last_confirmed is None:
            continue  # no evidence this client ever held a lease to lose
        gap = (row.ts_utc - last_confirmed).total_seconds()
        if gap > reassoc_window_s or gap < 0:
            continue

        if _preceded_by_reset(row.ts_utc, resets, reconnect_window_s):
            # An explicit disconnection was already logged for this client. The
            # re-acquisition is its consequence, and counting both would make
            # one outage look like two.
            continue

        drops.append(make_event(
            ts_utc=row.ts_utc,
            ts_local=row.ts_local,
            utc_offset=row.utc_offset,
            kind="client_drop",
            subtype="DISCOVER",
            client_mac=mac,
            dst_mac=mac,
            notes=(f"restarted DHCP acquisition {gap:.1f} s after holding a "
                   f"confirmed lease; a client that still has a valid lease "
                   f"renews it rather than starting again from DISCOVER"),
            source_file=row.source_file,
            source_kind=f"{row.source_kind}+derived",
            source_ref=row.source_ref,
            raw=row.raw,
        ))
    return drops


def _confirming_ops(group: pd.DataFrame) -> set:
    """Which operations count as proof the client held a working lease.

    ACK is the right answer. Some servers and log levels never record one, and
    on those a renewing REQUEST is the best available evidence, so it is
    accepted only when the client has no ACK anywhere in the data.
    """
    seen = {str(s or "").upper() for s in group.get("subtype", [])}
    return {"ACK"} if "ACK" in seen else {"ACK", "REQUEST"}


def _link_reset_times(df: pd.DataFrame) -> dict:
    resets: dict[str, list] = {}
    explicit = df[df["kind"] == "link_reset"]
    for row in explicit.itertuples(index=False):
        mac = str(row.client_mac or "").strip()
        if mac:
            resets.setdefault(mac, []).append(row.ts_utc)
    for times in resets.values():
        times.sort()
    return resets


def _preceded_by_reset(when, resets: list, window_s: float) -> bool:
    for reset in resets:
        delta = (when - reset).total_seconds()
        if 0 <= delta <= window_s:
            return True
    return False


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
