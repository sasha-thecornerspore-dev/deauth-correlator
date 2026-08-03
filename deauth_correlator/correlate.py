"""The analysis pipeline: events in, findings out.

:func:`run_analysis` is the single entry point used by both the CLI and the
GUI. It takes already-parsed events plus a configuration and returns an
:class:`Analysis` holding everything the writers need - the per-camera-event
match table, the statistics, the flood report and the provenance records.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from . import events as ev
from . import stats as st
from .drops import cluster_incidents, derive_client_drops
from .floods import FloodReport, detect_floods
from .hashing import FileRecord, Provenance
from .timeutil import humanize_delta


@dataclass
class Analysis:
    events: pd.DataFrame                 # every parsed event, all sources
    incidents: pd.DataFrame              # clustered disruption incidents
    matches: pd.DataFrame                # one row per camera event
    stats: st.WindowStats
    verdict: st.Verdict
    sensitivity: list = field(default_factory=list)
    lag_scan: st.LagScan = field(default_factory=st.LagScan)
    floods: FloodReport = field(default_factory=FloodReport)
    inputs: list = field(default_factory=list)          # list[FileRecord]
    warnings: list = field(default_factory=list)
    period_notes: list = field(default_factory=list)
    obs_start: float = 0.0
    obs_end: float = 0.0
    config: dict = field(default_factory=dict)
    provenance: Provenance = field(default_factory=Provenance)

    @property
    def obs_start_local(self):
        return _to_local(self.obs_start, self.config.get("timezone", "UTC"))

    @property
    def obs_end_local(self):
        return _to_local(self.obs_end, self.config.get("timezone", "UTC"))

    @property
    def observation_hours(self) -> float:
        return max(self.obs_end - self.obs_start, 0.0) / 3600.0

    def one_line_verdict(self) -> str:
        return f"{self.verdict.label}: {self.verdict.headline}"


def run_analysis(events: pd.DataFrame, config: dict,
                 inputs: list[FileRecord] | None = None,
                 warnings: list[str] | None = None,
                 provenance: Provenance | None = None) -> Analysis:
    window_s = float(config.get("window_s", st.DEFAULT_WINDOW_S))
    alpha = float(config.get("alpha", st.DEFAULT_ALPHA))
    trials = int(config.get("trials", st.DEFAULT_TRIALS))
    incident_gap = float(config.get("incident_gap_s", 10.0))
    warnings = list(warnings or [])

    # 1. Derive client drops from lease activity, then re-sort.
    drops = derive_client_drops(
        events,
        handshake_window_s=float(config.get("handshake_window_s", 10.0)),
        reassoc_window_s=float(config.get("reassoc_window_s", 120.0)),
        reconnect_window_s=float(config.get("reconnect_window_s", 120.0)),
    )
    if drops:
        events = ev.to_frame(events.to_dict("records") + drops)

    # 2. Merge camera events that describe the same pass recorded twice.
    events, dedupe_notes = dedupe_camera_events(
        events, window_s=float(config.get("camera_dedupe_s", 2.0)))
    warnings.extend(dedupe_notes)

    # 3. Collapse disruptions into physical incidents for the statistics.
    incidents = cluster_incidents(events, gap_s=incident_gap)

    camera = ev.cameras(events).sort_values("ts_utc")
    camera_times = _epoch(camera["ts_utc"])
    incident_times = _epoch(incidents["ts_utc"]) if not incidents.empty else np.array([])

    # 3. Establish the period over which both streams are in force.
    obs_start, obs_end, period_notes = st.observation_period(
        camera_times, incident_times, pad_s=window_s)

    in_period = _mask_between(camera_times, obs_start, obs_end)
    inc_in_period = _mask_between(incident_times, obs_start, obs_end)
    camera_used = camera_times[in_period]
    incidents_used = incident_times[inc_in_period]

    # 4. Statistics.
    analysis_stats = st.analyze(camera_used, incidents_used, obs_start, obs_end,
                                window_s, trials=trials)
    verdict = st.decide(analysis_stats, alpha=alpha, n_incidents=len(incidents_used))

    sens = []
    if config.get("sensitivity", True) and len(camera_used) and len(incidents_used):
        sens = st.sensitivity(camera_used, incidents_used, obs_start, obs_end,
                              window_s, trials=min(trials, 2000))

    # Would the two streams line up at some other offset? A clock an hour out
    # turns a real correlation into a confident "none found". This runs on the
    # unrestricted times: the analysis period is itself derived from the two
    # streams as recorded, so restricting to it would move the shifted events
    # out of range and hide the very thing being looked for.
    lag_scan = st.scan_for_lag(camera_times, incident_times, window_s)

    # 5. Per-camera-event match table.
    matches = build_matches(camera, events, incidents, window_s, obs_start, obs_end)

    # 6. Flood detection over the raw frames.
    flood_report = detect_floods(
        events,
        window_s=float(config.get("flood_window_s", 10.0)),
        threshold=int(config.get("flood_threshold", 5)),
    )

    return Analysis(
        events=events,
        incidents=incidents,
        matches=matches,
        stats=analysis_stats,
        verdict=verdict,
        sensitivity=sens,
        lag_scan=lag_scan,
        floods=flood_report,
        inputs=list(inputs or []),
        warnings=warnings,
        period_notes=period_notes,
        obs_start=obs_start,
        obs_end=obs_end,
        config=dict(config),
        provenance=provenance or Provenance.collect(),
    )


def dedupe_camera_events(events: pd.DataFrame, window_s: float = 2.0):
    """Collapse the same vehicle pass recorded by two different sources.

    Pointing the tool at both a camera-event CSV and the folder of clips those
    events came from is the natural thing to do, and it lists every pass twice.
    Left alone that inflates the number of camera events and the number of
    coincidences together, which pushes the statistics in the direction of
    finding a correlation - the one direction an evidential tool must never
    drift in.

    Merging is deliberately narrow, because deleting a real vehicle pass is as
    damaging as counting one twice:

    * Rows are merged only across *different* source files. A source listing two
      entries close together is describing two passes it saw, and is left alone.
    * At most one row per source joins a merged set, so a CSV that legitimately
      records two passes 1 s apart keeps both.
    * Merging is anchored, never chained. Four passes 1.9 s apart are four
      passes, not one five-second event - a rule of "every gap is under the
      window" would swallow the lot.

    The row carrying the most identifying detail survives, so a plate recorded
    in a CSV is not discarded in favour of a bare clip filename.
    """
    notes: list[str] = []
    if events.empty or window_s <= 0:
        return events, notes

    camera = events[events["category"] == ev.CAMERA]
    if len(camera) < 2:
        return events, notes

    camera = camera.sort_values("ts_utc")
    times = _epoch(camera["ts_utc"])
    indices = camera.index.to_list()
    sources = [str(camera.loc[i, "source_file"]) for i in indices]

    consumed: set = set()
    drop: set = set()
    merged_sets = 0

    for position, index in enumerate(indices):
        if index in consumed:
            continue
        members = [position]
        claimed = {sources[position]}
        for other in range(position + 1, len(indices)):
            if times[other] - times[position] > window_s:
                break
            if indices[other] in consumed or sources[other] in claimed:
                continue
            claimed.add(sources[other])
            members.append(other)
        if len(members) < 2:
            continue

        keeper = max(members, key=lambda pos: _detail_score(camera.loc[indices[pos]]))
        for pos in members:
            consumed.add(indices[pos])
            if pos != keeper:
                drop.add(indices[pos])
        merged_sets += 1

    if not drop:
        return events, notes

    notes.append(
        f"{len(drop)} camera event(s) were removed as duplicates: {merged_sets} "
        f"vehicle pass(es) appeared in more than one camera source within "
        f"{window_s:g} s. Counting the same pass twice would inflate both the "
        f"number of passes and the number of coincidences. Only rows from "
        f"different source files were merged, at most one per source, and the "
        f"entry carrying the most detail was kept in each case.")
    return events.drop(index=drop).reset_index(drop=True), notes


def _detail_score(row) -> int:
    """How much identifying detail a camera row carries, for choosing a survivor."""
    return sum(1 for field in ("plate", "make", "model", "notes")
               if ev.text(row.get(field)))


def build_matches(camera: pd.DataFrame, all_events: pd.DataFrame,
                  incidents: pd.DataFrame, window_s: float,
                  obs_start: float, obs_end: float) -> pd.DataFrame:
    """One row per camera event: what happened on the network closest to it."""
    if camera.empty:
        return pd.DataFrame(columns=[
            "event_local", "event_utc", "utc_offset", "plate", "make", "model",
            "coincidence", "nearest_kind", "nearest_local", "delta_s", "delta_plain",
            "attacker_mac", "reason_code", "reason", "client_mac",
            "nearest_deauth_local", "deauth_delta_s", "nearest_drop_local",
            "drop_delta_s", "events_in_window", "in_analysis_period",
            "camera_source", "camera_ref", "notes"])

    camera_times = _epoch(camera["ts_utc"])
    deauths = ev.deauth_frames(all_events).sort_values("ts_utc")
    drops = all_events[all_events["kind"].isin(["client_drop", "link_reset"])] \
        .sort_values("ts_utc")

    inc_times = _epoch(incidents["ts_utc"]) if not incidents.empty else np.array([])
    deauth_times = _epoch(deauths["ts_utc"])
    drop_times = _epoch(drops["ts_utc"])

    inc_delta = st.nearest_delta(camera_times, inc_times)
    deauth_delta = st.nearest_delta(camera_times, deauth_times)
    drop_delta = st.nearest_delta(camera_times, drop_times)

    rows = []
    for i, cam in enumerate(camera.itertuples(index=False)):
        d_inc = inc_delta[i] if i < len(inc_delta) else float("nan")
        d_deauth = deauth_delta[i] if i < len(deauth_delta) else float("nan")
        d_drop = drop_delta[i] if i < len(drop_delta) else float("nan")

        coincident = bool(abs(d_inc) <= window_s) if d_inc == d_inc else False
        nearest_inc = _row_at(incidents, camera_times[i], inc_times)
        nearest_deauth = _row_at(deauths, camera_times[i], deauth_times)
        nearest_drop = _row_at(drops, camera_times[i], drop_times)

        window_events = _events_in_window(all_events, camera_times[i], window_s)
        attacker = ""
        reason = None
        if nearest_deauth is not None and abs(d_deauth) <= window_s:
            attacker = ev.text(nearest_deauth["src_mac"])
            reason = nearest_deauth["reason_code"]
        elif nearest_inc is not None and coincident:
            attacker = ev.text(nearest_inc.get("src_macs"))

        rows.append({
            "event_local": cam.ts_local,
            "event_utc": cam.ts_utc,
            "utc_offset": cam.utc_offset,
            "plate": ev.text(cam.plate),
            "make": ev.text(cam.make),
            "model": ev.text(cam.model),
            "coincidence": coincident,
            "nearest_kind": (ev.text(nearest_inc.get("kinds")) if nearest_inc is not None
                             else ""),
            "nearest_local": (nearest_inc.get("ts_local") if nearest_inc is not None
                              else None),
            "delta_s": round(float(d_inc), 3) if d_inc == d_inc else None,
            "delta_plain": humanize_delta(d_inc),
            "attacker_mac": attacker,
            "reason_code": (int(reason) if reason is not None and reason == reason
                            else None),
            "reason": ev.reason_text(reason),
            "client_mac": (ev.text(nearest_inc.get("client_macs"))
                           if nearest_inc is not None else ""),
            "nearest_deauth_local": (nearest_deauth["ts_local"]
                                     if nearest_deauth is not None else None),
            "deauth_delta_s": (round(float(d_deauth), 3) if d_deauth == d_deauth
                               else None),
            "nearest_drop_local": (nearest_drop["ts_local"]
                                   if nearest_drop is not None else None),
            "drop_delta_s": round(float(d_drop), 3) if d_drop == d_drop else None,
            "events_in_window": window_events,
            "in_analysis_period": bool(obs_start <= camera_times[i] <= obs_end),
            "camera_source": cam.source_file,
            "camera_ref": cam.source_ref,
            "notes": ev.text(cam.notes),
        })

    return pd.DataFrame(rows)


def _events_in_window(all_events: pd.DataFrame, centre: float, window_s: float) -> int:
    disruption = all_events[all_events["category"] == "disruption"]
    if disruption.empty:
        return 0
    times = _epoch(disruption["ts_utc"])
    return int(((times >= centre - window_s) & (times <= centre + window_s)).sum())


def _row_at(frame: pd.DataFrame, target: float, times: np.ndarray):
    """The row of ``frame`` whose time is nearest ``target``, as a dict."""
    if frame.empty or len(times) == 0:
        return None
    idx = int(np.argmin(np.abs(times - target)))
    return frame.iloc[idx].to_dict()


def _epoch(series: pd.Series) -> np.ndarray:
    return ev.epoch_seconds(series)


def _mask_between(times: np.ndarray, lo: float, hi: float) -> np.ndarray:
    if len(times) == 0:
        return np.array([], dtype=bool)
    return (times >= lo) & (times <= hi)


def _to_local(epoch: float, tz_name: str):
    try:
        return pd.Timestamp(epoch, unit="s", tz="UTC").tz_convert(tz_name)
    except Exception:
        return pd.Timestamp(epoch, unit="s", tz="UTC")
