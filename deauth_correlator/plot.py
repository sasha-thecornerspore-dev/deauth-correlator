"""timeline.png - camera passes, client drops and deauth frames on one axis.

The point of the figure is that a juror can see the alignment without reading
a statistic. Camera events are drawn as vertical bands (the +/-window itself, so
"within 30 seconds" is a visible width rather than an assertion), and the
network events are plotted in lanes above and below.
"""

from __future__ import annotations

from pathlib import Path

import matplotlib
matplotlib.use("Agg")

import matplotlib.dates as mdates
import matplotlib.pyplot as plt
import pandas as pd
from matplotlib.lines import Line2D
from matplotlib.patches import Patch

from . import events as ev

LANES = [
    ("deauth", 3.0, "#c0392b", "o", "Deauthentication frame"),
    ("disassoc", 2.6, "#e67e22", "o", "Disassociation frame"),
    ("alert", 2.2, "#8e44ad", "^", "IDS deauth alert"),
    ("link_reset", 1.6, "#2980b9", "s", "Wireless link reset"),
    ("client_drop", 1.2, "#16a085", "D", "Client drop (DHCP re-association)"),
]
CAMERA_LANE = 0.4
BAND_COLOR = "#f39c12"
COINCIDENT_COLOR = "#c0392b"


def write_timeline(analysis, path: str | Path, title: str | None = None,
                   max_points: int = 20000) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    events = analysis.events
    matches = analysis.matches
    window_s = float(analysis.config.get("window_s", 30.0))
    tz = analysis.config.get("timezone", "UTC")

    fig, (ax, ax_rate) = plt.subplots(
        2, 1, figsize=(16, 9.0), height_ratios=[3, 1], sharex=True,
        gridspec_kw={"hspace": 0.12})

    _draw_camera_bands(ax, matches, window_s, tz)
    plotted_any = _draw_event_lanes(ax, events, max_points, tz)
    _draw_camera_markers(ax, matches, tz)
    _draw_analysis_period(ax, analysis, tz)

    ax.set_ylim(0, 3.6)
    ax.set_yticks([CAMERA_LANE] + [y for _, y, _, _, _ in LANES])
    ax.set_yticklabels(["Camera pass"] + [label for _, _, _, _, label in LANES],
                       fontsize=9)
    ax.grid(axis="x", alpha=0.25, linestyle=":")
    ax.set_axisbelow(True)

    heading = title or _default_title(analysis)
    ax.set_title(heading, fontsize=13, fontweight="bold", loc="left", pad=14)
    ax.text(0.0, 1.005, analysis.one_line_verdict(), transform=ax.transAxes,
            fontsize=9.5, va="bottom",
            color=COINCIDENT_COLOR if analysis.verdict.found else "#555555")

    _draw_rate_panel(ax_rate, analysis, tz)

    handles = [Patch(facecolor=BAND_COLOR, alpha=0.30,
                     label=f"Camera event window (±{window_s:g} s)")]
    handles.append(Line2D([], [], color=COINCIDENT_COLOR, marker="v", linestyle="",
                          markersize=9, label="Camera pass WITH a coincident disruption"))
    handles.append(Line2D([], [], color="#7f8c8d", marker="v", linestyle="",
                          markersize=7, label="Camera pass with no coincident disruption"))
    for kind, _y, color, marker, label in LANES:
        if kind in plotted_any:
            handles.append(Line2D([], [], color=color, marker=marker, linestyle="",
                                  markersize=6, label=label))

    _format_time_axis(ax_rate)
    ax_rate.set_xlabel(f"Time ({tz})", fontsize=10)

    # Fixed margins rather than tight_layout: the long lane labels need a wide
    # left gutter, and tight_layout cannot account for the figure legend below.
    fig.subplots_adjust(left=0.17, right=0.985, top=0.905, bottom=0.10, hspace=0.12)
    # A figure-level legend anchored just below the canvas. An axes-level legend
    # overlaps the rate panel once it wraps, and placing it inside the figure
    # collides with the x-axis label; bbox_inches="tight" grows the saved image
    # to include whatever sits below the axes.
    fig.legend(handles=handles, loc="upper center", ncol=3, fontsize=8.5,
               frameon=False, bbox_to_anchor=(0.5, 0.02))
    fig.savefig(path, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    return path


def _local_naive(values, tz):
    """Local wall-clock times with the zone stripped off.

    Matplotlib renders tz-aware timestamps in ``rcParams['timezone']``, which is
    UTC by default, so plotting aware values silently shifts the axis away from
    the case timezone. Converting to the case zone and then dropping tzinfo
    makes the axis show exactly the local times printed everywhere else.
    """
    series = pd.to_datetime(pd.Series(list(values)), utc=True)
    return series.dt.tz_convert(tz).dt.tz_localize(None)


def _local_naive_one(value, tz):
    return pd.Timestamp(value).tz_convert(tz).tz_localize(None)


def _draw_camera_bands(ax, matches: pd.DataFrame, window_s: float, tz) -> None:
    if matches.empty:
        return
    half = pd.Timedelta(seconds=window_s)
    times = _local_naive(matches["event_local"], tz)
    for t, coincident in zip(times, matches["coincidence"]):
        ax.axvspan(t - half, t + half, color=BAND_COLOR,
                   alpha=0.32 if coincident else 0.13, linewidth=0, zorder=0)


def _draw_event_lanes(ax, events: pd.DataFrame, max_points: int, tz) -> set:
    plotted = set()
    for kind, y, color, marker, _label in LANES:
        subset = events[events["kind"] == kind]
        if subset.empty:
            continue
        if len(subset) > max_points:
            subset = subset.sample(max_points, random_state=0).sort_values("ts_utc")
        times = _local_naive(subset["ts_utc"], tz)
        ax.plot(times, [y] * len(times), linestyle="", marker=marker,
                markersize=5, color=color, alpha=0.75, zorder=3)
        plotted.add(kind)
    return plotted


def _draw_camera_markers(ax, matches: pd.DataFrame, tz) -> None:
    if matches.empty:
        return
    for coincident, color, size in ((True, COINCIDENT_COLOR, 11),
                                    (False, "#7f8c8d", 8)):
        subset = matches[matches["coincidence"] == coincident]
        if subset.empty:
            continue
        times = _local_naive(subset["event_local"], tz)
        ax.plot(times, [CAMERA_LANE] * len(times), linestyle="", marker="v",
                markersize=size, color=color, zorder=4,
                markeredgecolor="white", markeredgewidth=0.6)


def _draw_analysis_period(ax, analysis, tz) -> None:
    if analysis.obs_end <= analysis.obs_start:
        return
    for epoch, label in ((analysis.obs_start, "analysis period start"),
                         (analysis.obs_end, "analysis period end")):
        t = _local_naive_one(pd.Timestamp(epoch, unit="s", tz="UTC"), tz)
        ax.axvline(t, color="#34495e", linestyle="--", linewidth=1.0, alpha=0.7,
                   zorder=1)
        ax.annotate(label, xy=(t, 3.5), fontsize=7, color="#34495e",
                    rotation=90, va="top", ha="right", alpha=0.8)


def _draw_rate_panel(ax, analysis, tz) -> None:
    """Disruption incidents per minute, so a burst is visible as a spike."""
    incidents = analysis.incidents
    ax.set_ylabel("disruptions\nper 5 min", fontsize=8)
    ax.grid(alpha=0.25, linestyle=":")
    if incidents.empty:
        ax.text(0.5, 0.5, "no wireless-disruption incidents found",
                transform=ax.transAxes, ha="center", va="center",
                fontsize=9, color="#7f8c8d")
        ax.set_yticks([])
        return

    times = _local_naive(incidents["ts_utc"], tz)
    series = pd.Series(1, index=pd.DatetimeIndex(times)).resample("5min").sum()
    if len(series) > 1:
        ax.fill_between(series.index, series.to_numpy(), step="mid",
                        color="#c0392b", alpha=0.45)
        ax.step(series.index, series.to_numpy(), where="mid",
                color="#c0392b", linewidth=1.0)
    else:
        ax.bar(series.index, series.to_numpy(), color="#c0392b", alpha=0.6)
    ax.set_ylim(bottom=0)


def _format_time_axis(ax) -> None:
    locator = mdates.AutoDateLocator(minticks=4, maxticks=12)
    ax.xaxis.set_major_locator(locator)
    ax.xaxis.set_major_formatter(mdates.ConciseDateFormatter(locator))
    for label in ax.get_xticklabels():
        label.set_fontsize(9)


def _default_title(analysis) -> str:
    case = analysis.provenance.case_number
    prefix = f"Case {case} - " if case else ""
    return (f"{prefix}Camera passes against wireless-disruption events "
            f"({analysis.config.get('timezone', 'UTC')})")
