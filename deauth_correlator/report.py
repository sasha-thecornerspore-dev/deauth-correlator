"""report.md - the document that gets attached to a police report or filing.

Written for a reader with no wireless-networking background. Every technical
term is explained the first time it appears, every number is stated with what
it would have been by chance, and the limitations section says plainly what the
analysis cannot show. An expert report that overclaims is worse than no report,
so the "What this does not prove" section is not optional.
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from . import __version__, __tool_name__
from . import events as ev
from .floods import describe_reason_profile
from .stats import VERDICT_FOUND, VERDICT_INSUFFICIENT
from .timeutil import humanize_delta


def write_report(analysis, path: str | Path, timeline_name: str = "timeline.png",
                 csv_name: str = "correlation.csv") -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(build_report(analysis, timeline_name, csv_name), encoding="utf-8")
    return path


def build_report(analysis, timeline_name: str = "timeline.png",
                 csv_name: str = "correlation.csv") -> str:
    parts = [
        _header(analysis),
        _summary(analysis),
        _findings(analysis),
        _statistics(analysis),
        _sensitivity(analysis),
        _floods(analysis),
        _event_table(analysis),
        _figure(analysis, timeline_name, csv_name),
        _methodology(analysis),
        _custody(analysis),
        _limitations(analysis),
        _glossary(),
    ]
    return "\n\n".join(p for p in parts if p).rstrip() + "\n"


def _header(a) -> str:
    p = a.provenance
    lines = ["# Wireless disruption / vehicle pass correlation analysis", ""]
    rows = [
        ("Case number", p.case_number or "(not supplied)"),
        ("Prepared by", p.operator or "(not supplied)"),
        ("Agency / organization", p.agency or "(not supplied)"),
        ("Report generated", f"{p.generated_utc} UTC"),
        ("Analysis timezone", f"{a.config.get('timezone')} "
                              f"(all local times below are in this zone)"),
        ("Tool", f"{__tool_name__} {__version__}"),
    ]
    lines.append("| Field | Value |")
    lines.append("| --- | --- |")
    lines.extend(f"| {k} | {v} |" for k, v in rows)
    if p.notes:
        lines += ["", f"**Case notes:** {p.notes}"]
    return "\n".join(lines)


def _summary(a) -> str:
    s = a.stats
    banner = {
        VERDICT_FOUND: "**FINDING: A STATISTICALLY SIGNIFICANT CORRELATION WAS FOUND.**",
        VERDICT_INSUFFICIENT: "**FINDING: THE EVIDENCE IS INSUFFICIENT TO TEST FOR A "
                              "CORRELATION.**",
    }.get(a.verdict.label,
          "**FINDING: NO STATISTICALLY SIGNIFICANT CORRELATION WAS ESTABLISHED.**")

    lines = ["## 1. Summary", "", banner, "", a.verdict.headline, ""]

    if a.verdict.label != VERDICT_INSUFFICIENT:
        lines += [
            f"In plain terms: {s.n_coincident} of the {s.n_camera} vehicle passes "
            f"recorded by the camera happened within {s.window_s:g} seconds of a "
            f"disruption to the wireless network. If the vehicle passes and the "
            f"network disruptions were unrelated, the expected number of such "
            f"near-simultaneous pairings would be about "
            f"{s.expected_by_chance:.1f}, not {s.n_coincident}.",
            "",
            f"Baseline coincidence rate = {s.baseline_rate * 100:.1f}%. "
            f"Observed coincidence rate = {s.coincidence_rate * 100:.1f}%.",
        ]

    if a.verdict.reasons and a.verdict.label != VERDICT_FOUND:
        lines += ["", "Why the finding is not stronger:", ""]
        lines += [f"- {reason}" for reason in a.verdict.reasons]

    return "\n".join(lines)


def _findings(a) -> str:
    lines = ["## 2. What the evidence shows", ""]
    counts = ev.summarize_kinds(a.events)
    total_disruption = int((a.events["category"] == "disruption").sum())

    lines.append(
        f"The evidence covers {a.observation_hours:.1f} hours from "
        f"{_fmt(a.obs_start_local)} to {_fmt(a.obs_end_local)} "
        f"({a.config.get('timezone')}). Within that period the tool identified "
        f"{total_disruption} individual wireless-disruption events, which group into "
        f"{len(a.incidents)} distinct incidents, alongside "
        f"{int((a.events['category'] == 'camera').sum())} camera events.")
    lines.append("")

    if counts:
        lines += ["| Event type | Count | What it means |", "| --- | ---: | --- |"]
        for kind, n in sorted(counts.items(), key=lambda kv: -kv[1]):
            lines.append(f"| {kind} | {n} | {_kind_meaning(kind)} |")
        lines.append("")

    lines.append(
        "Multiple events caused by the same physical disruption - for example a burst "
        "of deauthentication frames plus the DHCP re-association that followed it - are "
        f"grouped into one incident when they fall within "
        f"{a.config.get('incident_gap_s', 10):g} seconds of each other. The statistics "
        "count incidents, not raw events, so a single flood is not counted hundreds of "
        "times.")

    coincident = a.matches[a.matches["coincidence"]] if not a.matches.empty else a.matches
    if not coincident.empty:
        deltas = coincident["delta_s"].dropna()
        if len(deltas):
            lines += [
                "",
                f"Among the {len(coincident)} coincident passes the disruption occurred "
                f"a median of {humanize_delta(float(deltas.median()))} the camera event "
                f"(range {humanize_delta(float(deltas.min()))} to "
                f"{humanize_delta(float(deltas.max()))}). A consistent sign and a tight "
                "spread indicate a repeatable relationship rather than chance overlap.",
            ]
    return "\n".join(lines)


def _statistics(a) -> str:
    s = a.stats
    lines = ["## 3. Statistical analysis", ""]
    lines.append(
        f"Four independent tests were run on the same data. They are reported together "
        f"because any single test can be argued with; agreement between methods that "
        f"rest on different assumptions is what makes the result durable. All use a "
        f"coincidence window of ±{s.window_s:g} seconds and were computed with the "
        f"{s.backend} numerical backend.")
    lines.append("")

    lines += [
        "### 3.1 Coincidence count",
        "",
        f"**{s.n_coincident} of {s.n_camera} camera passes coincided with a "
        f"wireless-disruption event within ±{s.window_s:g} s; baseline coincidence "
        f"rate = {s.baseline_rate * 100:.1f}%.**",
        "",
        f"That is an observed coincidence rate of {s.coincidence_rate * 100:.1f}%.",
        "",
        f"The baseline is the share of the whole observation period that lies within "
        f"{s.window_s:g} seconds of some disruption. A vehicle passing at a random "
        f"moment would fall inside that share {s.baseline_rate * 100:.1f}% of the time. "
        f"The observed rate is {_lift_text(s.lift)} the baseline.",
        "",
        "### 3.2 Binomial test against the chance baseline",
        "",
        f"Treating each camera pass as an independent draw with probability "
        f"{s.baseline_rate:.4f} of coinciding by chance, the probability of seeing "
        f"{s.n_coincident} or more coincidences out of {s.n_camera} is "
        f"**p = {_p(s.binom_p)}**.",
        "",
        "### 3.3 Circular-shift permutation test",
        "",
        f"The entire sequence of camera events was slid forward by a random amount and "
        f"wrapped around the observation period, {s.perm_trials:,} times, and the "
        f"coincidences recounted each time. This preserves the real spacing of the "
        f"vehicle passes and the real clustering of the disruptions, so it does not "
        f"rely on the independence assumption the binomial test makes. Shifts close "
        f"to zero are excluded, because a shift of almost nothing simply reproduces "
        f"the real alignment and would put the observed arrangement into its own "
        f"comparison set. Randomly positioned sequences produced an average of "
        f"{s.perm_mean:.2f} coincidences against the {s.n_coincident} actually "
        f"observed: **p = {_p(s.perm_p)}**.",
        "",
        "### 3.4 Fisher's exact test and chi-square",
        "",
        f"The observation period was divided into {sum(sum(r) for r in s.table):,} "
        f"non-overlapping bins of {2 * s.window_s:g} seconds each and every bin "
        f"classified two ways:",
        "",
        "| | disruption in bin | no disruption in bin |",
        "| --- | ---: | ---: |",
        f"| **camera event in bin** | {s.table[0][0]} | {s.table[0][1]} |",
        f"| **no camera event in bin** | {s.table[1][0]} | {s.table[1][1]} |",
        "",
        f"Fisher's exact test (one-sided): odds ratio "
        f"{_num(s.fisher_odds_ratio)}, **p = {_p(s.fisher_p)}**. "
        f"Chi-square with Yates' continuity correction: "
        f"chi2 = {_num(s.chi2)}, p = {_p(s.chi2_p)}.",
        "",
        "### 3.5 Disruption rate inside and outside the camera windows",
        "",
        f"| Period | Duration | Incidents | Rate |",
        f"| --- | ---: | ---: | ---: |",
        f"| Within ±{s.window_s:g} s of a camera pass | {s.exposed_minutes:.1f} min | "
        f"{s.incidents_in_window} | {s.rate_in_per_min:.4f} /min |",
        f"| All other time | {s.unexposed_minutes:.1f} min | {s.incidents_outside} | "
        f"{s.rate_out_per_min:.4f} /min |",
        "",
        f"**Rate ratio: {s.rate_ratio:.2f}x** - wireless disruptions were "
        f"{s.rate_ratio:.2f} times more frequent during the camera windows than at "
        f"other times.",
    ]
    if s.rate_ratio_corrected:
        lines += [
            "",
            "There were no disruptions at all outside the camera windows, which makes "
            "the plain ratio undefined. The figure above uses the Haldane-Anscombe "
            "correction (half an event added to each cell), which is the conventional "
            "conservative treatment of a zero cell.",
        ]
    return "\n".join(lines)


def _sensitivity(a) -> str:
    if not a.sensitivity:
        return ""
    lines = [
        "## 4. Window sensitivity",
        "",
        "The ±30-second default is a judgement call, so the same analysis was repeated "
        "at other window widths. A real relationship shows up across a range of "
        "windows; a result that appears at exactly one width and nowhere else is a "
        "sign of chance or of a window chosen to fit.",
        "",
        "| Window | Coincidences | Baseline | Rate ratio | Binomial p | Permutation p | Fisher p |",
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for s in a.sensitivity:
        marker = " **(primary)**" if s.window_s == a.stats.window_s else ""
        lines.append(
            f"| ±{s.window_s:g} s{marker} | {s.n_coincident}/{s.n_camera} | "
            f"{s.baseline_rate * 100:.1f}% | {s.rate_ratio:.2f}x | {_p(s.binom_p)} | "
            f"{_p(s.perm_p)} | {_p(s.fisher_p)} |")
    return "\n".join(lines)


def _floods(a) -> str:
    f = a.floods
    lines = ["## 5. Deauthentication frames and floods", ""]
    if f.total_frames == 0:
        lines.append(
            "No deauthentication or disassociation frames were present in the evidence. "
            "This means either that none occurred, or - more commonly - that no "
            "monitor-mode capture was supplied. Without a capture the analysis rests on "
            "DHCP re-association as an indirect indicator, which shows that clients "
            "dropped but not what made them drop. See the README for how to record a "
            "capture with airodump-ng.")
        return "\n".join(lines)

    lines.append(
        f"{f.total_frames} deauthentication/disassociation frames were recovered from "
        f"the capture evidence. {f.broadcast_frames} of them were addressed to the "
        f"broadcast address ff:ff:ff:ff:ff:ff, which disconnects every client on the "
        f"network at once rather than a single device.")
    lines.append("")

    profile = describe_reason_profile(f)
    if profile:
        lines += [profile, ""]

    if f.by_source:
        lines += [
            "### 5.1 Source addresses",
            "",
            "The source address of a management frame is not authenticated and can be "
            "set to any value by the transmitting device. These addresses identify the "
            "frames as a group; they are not by themselves proof of which physical "
            "device sent them.",
            "",
            "| Source MAC | Frames |",
            "| --- | ---: |",
        ]
        for mac, n in sorted(f.by_source.items(), key=lambda kv: -kv[1])[:25]:
            lines.append(f"| `{mac}` | {n} |")
        lines.append("")

    if f.by_reason:
        lines += ["### 5.2 Reason codes", "", "| Code | Meaning | Frames |",
                  "| ---: | --- | ---: |"]
        for code, n in sorted(f.by_reason.items(), key=lambda kv: -kv[1]):
            lines.append(f"| {code} | {ev.reason_text(code)} | {n} |")
        lines.append("")

    if f.floods:
        lines += [
            "### 5.3 Detected floods",
            "",
            f"A flood is recorded wherever {f.threshold} or more frames arrived within "
            f"{f.window_s:g} seconds.",
            "",
            "| Start | Duration | Frames | Peak rate | Principal source | Broadcast frames |",
            "| --- | ---: | ---: | ---: | --- | ---: |",
        ]
        for flood in f.floods[:40]:
            lines.append(
                f"| {_fmt(flood.start_local)} | {flood.duration_s:.1f} s | "
                f"{flood.n_frames} | {flood.peak_rate_per_s:.1f} /s | "
                f"`{flood.top_source or 'n/a'}` | {flood.broadcast_frames} |")
        if len(f.floods) > 40:
            lines.append(f"\n({len(f.floods) - 40} further floods omitted; the complete "
                         f"list is in the exported event CSV.)")
    else:
        lines.append(
            f"No burst reached the flood threshold of {f.threshold} frames in "
            f"{f.window_s:g} seconds.")
    return "\n".join(lines)


def _event_table(a) -> str:
    if a.matches.empty:
        return ""
    lines = [
        "## 6. Camera events, one by one",
        "",
        "Every camera event is listed with the closest wireless disruption to it. The "
        f"full table, including source-file references for each row, is in "
        f"`correlation.csv`.",
        "",
        "| # | Camera event (local) | Plate | Coincidence | Nearest disruption | Delta | Deauth source MAC | Reason |",
        "| ---: | --- | --- | :---: | --- | --- | --- | --- |",
    ]
    for i, row in enumerate(a.matches.itertuples(index=False), start=1):
        flag = "**YES**" if row.coincidence else "no"
        if not row.in_analysis_period:
            flag += " (outside period)"
        source = f"`{row.attacker_mac}`" if row.attacker_mac else "-"
        lines.append(
            f"| {i} | {_fmt(row.event_local)} | {row.plate or '-'} | {flag} "
            f"| {row.nearest_kind or '-'} | {row.delta_plain} | {source} "
            f"| {row.reason or '-'} |")
    return "\n".join(lines)


def _figure(a, timeline_name: str, csv_name: str) -> str:
    return "\n".join([
        "## 7. Timeline",
        "",
        f"![Timeline of camera events against wireless disruptions]({timeline_name})",
        "",
        f"Each amber band is one camera event with its ±{a.stats.window_s:g}-second "
        f"window drawn to scale. Red triangles mark passes that coincided with a "
        f"disruption; grey triangles mark those that did not. The lower panel shows "
        f"disruption incidents per five minutes.",
        "",
        f"Machine-readable output accompanying this report: `{csv_name}` "
        f"(one row per camera event), `events.csv` (every parsed event), "
        f"`incidents.csv` (grouped disruptions), `MANIFEST.json` (hashes).",
    ])


def _methodology(a) -> str:
    cfg = a.config
    lines = [
        "## 8. Methodology",
        "",
        "### 8.1 What the tool did",
        "",
        "1. Each input file was hashed with SHA-256 before anything was read from it "
        "(section 9).",
        "2. A format-specific parser converted each file into a common event list. "
        "Timestamps were normalized to UTC for computation and to the case timezone "
        f"({cfg.get('timezone')}) for display; the UTC offset written in each source "
        "was preserved and is carried in the exported CSVs.",
        "3. DHCP lease traffic was collapsed into association episodes "
        f"(messages within {cfg.get('handshake_window_s', 10):g} seconds of one another "
        "are one episode, because a normal join produces several messages in quick "
        "succession). A second episode from the same client within "
        f"{cfg.get('reassoc_window_s', 120):g} seconds of the previous one was recorded "
        "as a client drop, on the basis that a client holding a valid lease does not "
        "repeat the handshake that soon.",
        "4. Deauthentication and disassociation frames were decoded directly from the "
        "capture, including the IEEE 802.11 reason code carried in each frame body.",
        f"5. Disruption events within {cfg.get('incident_gap_s', 10):g} seconds of each "
        "other were grouped into single incidents.",
        "6. Each camera event was matched against the nearest incident, and the four "
        "tests in section 3 were computed.",
        "",
        "### 8.2 Analysis period",
        "",
        f"Statistics were computed over {_fmt(a.obs_start_local)} to "
        f"{_fmt(a.obs_end_local)} ({a.observation_hours:.2f} hours), which is the "
        "period covered by both the camera log and the wireless evidence. Restricting "
        "to the overlap matters: computing a background rate over a week of camera "
        "footage when the packet capture only ran for two hours would understate the "
        "background and overstate the finding.",
    ]
    if a.period_notes:
        lines += [""] + [f"- {note}" for note in a.period_notes]

    lines += [
        "",
        "### 8.3 Parameters used",
        "",
        "| Parameter | Value | Effect |",
        "| --- | --- | --- |",
        f"| Coincidence window | ±{cfg.get('window_s')} s | how close in time an event "
        "must be to count as coincident |",
        f"| Significance threshold | {cfg.get('alpha')} | p-value below which the "
        "correlation is called significant |",
        f"| Permutation trials | {cfg.get('trials'):,} | resolution of the empirical "
        "p-value |",
        f"| Re-association window | {cfg.get('reassoc_window_s', 120)} s | how soon a "
        "repeat DHCP handshake counts as a drop |",
        f"| Handshake window | {cfg.get('handshake_window_s', 10)} s | how lease "
        "messages are grouped into one join |",
        f"| Incident grouping | {cfg.get('incident_gap_s', 10)} s | how disruption "
        "events are grouped into incidents |",
        f"| Flood threshold | {cfg.get('flood_threshold', 5)} frames / "
        f"{cfg.get('flood_window_s', 10)} s | when a burst is called a flood |",
        f"| Camera clock offset applied | {cfg.get('camera_clock_offset_s', 0):+g} s | "
        "correction for camera clock error |",
    ]

    lines += ["", "### 8.4 Data sources and parsers", ""]
    if a.inputs:
        lines += ["| File | Role | Parser | Events |", "| --- | --- | --- | ---: |"]
        for rec in a.inputs:
            lines.append(f"| `{rec.name}` | {rec.role} | {rec.parser or 'n/a'} | "
                         f"{rec.rows} |")
    else:
        lines.append("No input files were recorded.")

    if a.provenance.libraries:
        lines += ["", "### 8.5 Software environment", "",
                  "| Component | Version |", "| --- | --- |",
                  f"| {__tool_name__} | {__version__} |",
                  f"| Python | {a.provenance.python} |"]
        for lib, version in sorted(a.provenance.libraries.items()):
            lines.append(f"| {lib} | {version} |")
        lines += [f"| Platform | {a.provenance.platform} |",
                  f"| Analysis host | {a.provenance.host} |"]
        lines += ["", f"Command line: `{a.provenance.command_line}`"]

    if a.warnings:
        lines += ["", "### 8.6 Parser notes and warnings", "",
                  "Recorded verbatim so that anything the tool had to assume is "
                  "visible rather than buried:", ""]
        lines += [f"- {w}" for w in a.warnings]

    return "\n".join(lines)


def _custody(a) -> str:
    lines = [
        "## 9. Chain of custody",
        "",
        "Each file was hashed with SHA-256 as it was read. A copy of a file that "
        "produces the same hash is bit-for-bit identical to the one analysed here; any "
        "alteration, however small, produces a completely different hash.",
        "",
        "| File | Role | Size | Last modified (UTC) | SHA-256 |",
        "| --- | --- | ---: | --- | --- |",
    ]
    if not a.inputs:
        return "\n".join(lines[:2] + ["No input files were recorded."])
    for rec in a.inputs:
        lines.append(f"| `{rec.name}` | {rec.role} | {rec.size_bytes:,} B | "
                     f"{rec.modified_utc} | `{rec.sha256}` |")
    lines += ["", "Full paths as read:", ""]
    lines += [f"- `{rec.path}`" for rec in a.inputs]
    return "\n".join(lines)


def _limitations(a) -> str:
    lines = [
        "## 10. What this analysis does not prove",
        "",
        "- **Correlation is not identification.** Even a very strong statistical "
        "association shows that network disruptions happened when a vehicle passed. It "
        "does not establish who was in the vehicle or who operated any transmitting "
        "equipment.",
        "- **MAC addresses in management frames are not authenticated.** The source "
        "address of a deauthentication frame is chosen by whatever device sent it and "
        "can be set to any value, including the address of an innocent device. A source "
        "MAC is a label for a group of frames, not an identification of hardware.",
        "- **Clock accuracy bounds the resolution.** The analysis is only as precise as "
        "the clocks that produced the timestamps. Camera and router clocks drift, and a "
        "camera whose clock is wrong by a minute will destroy a 30-second correlation "
        "or manufacture a false one. Where the camera was reachable its clock offset "
        "was measured and is stated in section 8.3.",
        "- **Other causes produce the same signature.** Wireless interference, a "
        "failing access point, a client device with a defective radio, channel changes, "
        "microwave ovens and cordless phones can all cause clients to drop. What "
        "distinguishes a deliberate attack is the presence of deauthentication frames "
        "with tool-default reason codes, and particularly broadcast-addressed ones.",
        "- **Absence of capture evidence is not absence of an attack.** If no "
        "monitor-mode capture was running, deauthentication frames would not have been "
        "recorded no matter how many were transmitted.",
    ]
    if a.stats.n_camera and a.stats.n_camera < 10:
        lines.append(
            f"- **The sample is small.** With only {a.stats.n_camera} camera events, "
            "the statistics are sensitive to a single event being added or removed. "
            "Collecting more observations would materially strengthen or weaken this "
            "finding.")
    if a.floods.total_frames == 0:
        lines.append(
            "- **No frame-level evidence was available in this run.** The conclusions "
            "rest on client-drop inference from DHCP logs alone.")
    return "\n".join(lines)


def _glossary() -> str:
    terms = [
        ("Deauthentication frame",
         "A short management message defined by the Wi-Fi standard that tells a device "
         "it is being disconnected. On networks without Protected Management Frames "
         "(802.11w) it is unauthenticated, so any nearby transmitter can send one and "
         "the receiving device will act on it."),
        ("Disassociation frame",
         "Similar to a deauthentication frame; it ends the association but leaves the "
         "device authenticated. Its practical effect on the user is the same."),
        ("Reason code",
         "A number inside a deauthentication frame stating why the disconnection "
         "happened. Codes 1 and 7 are the values that common attack tools send by "
         "default; a genuine access point usually sends 3, 4 or 8."),
        ("BSSID",
         "The MAC address of the access point's radio - in effect, the identifier of "
         "the specific wireless network being used."),
        ("Broadcast address (ff:ff:ff:ff:ff:ff)",
         "A destination meaning 'every device'. A deauthentication frame sent here "
         "disconnects the entire network at once."),
        ("DHCP",
         "The protocol a device uses to obtain an IP address when it joins a network. "
         "A device that already has a valid address does not normally repeat the "
         "request, so a repeat is evidence that its connection was interrupted."),
        ("Monitor mode",
         "A mode in which a wireless adapter records all traffic in the air rather than "
         "only traffic addressed to it. It is required to capture the management frames "
         "described above."),
        ("p-value",
         "The probability of seeing a result at least this extreme if there were no "
         "real relationship. Smaller means less easily explained by chance. A common "
         "threshold is 0.05; this report uses a stricter one."),
        ("Rate ratio",
         "How many times more often disruptions occurred during the camera windows than "
         "outside them. A ratio of 1 means no difference."),
    ]
    lines = ["## 11. Glossary", ""]
    for term, definition in terms:
        lines.append(f"**{term}.** {definition}")
        lines.append("")
    return "\n".join(lines).rstrip()


def write_manifest(analysis, path: str | Path, outputs: list | None = None) -> Path:
    """MANIFEST.json plus a plain-text twin, covering inputs and outputs."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "tool": f"{__tool_name__} {__version__}",
        "provenance": analysis.provenance.to_dict(),
        "verdict": {
            "label": analysis.verdict.label,
            "headline": analysis.verdict.headline,
            "reasons": analysis.verdict.reasons,
        },
        "statistics": analysis.stats.to_dict(),
        "sensitivity": [s.to_dict() for s in analysis.sensitivity],
        "floods": analysis.floods.to_dict(),
        "analysis_period": {
            "start_utc": str(pd.Timestamp(analysis.obs_start, unit="s", tz="UTC")),
            "end_utc": str(pd.Timestamp(analysis.obs_end, unit="s", tz="UTC")),
            "hours": analysis.observation_hours,
            "notes": analysis.period_notes,
        },
        "configuration": analysis.config,
        "inputs": [rec.__dict__ for rec in analysis.inputs],
        "outputs": [rec.__dict__ for rec in (outputs or [])],
        "warnings": analysis.warnings,
    }
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")

    text_path = path.with_suffix(".txt")
    text_path.write_text(_manifest_text(analysis, outputs or []), encoding="utf-8")
    return path


def _manifest_text(a, outputs: list) -> str:
    lines = [
        f"{__tool_name__} {__version__} - evidence manifest",
        "=" * 60,
        f"Case:      {a.provenance.case_number or '(not supplied)'}",
        f"Operator:  {a.provenance.operator or '(not supplied)'}",
        f"Generated: {a.provenance.generated_utc} UTC",
        f"Timezone:  {a.config.get('timezone')}",
        f"Verdict:   {a.verdict.label}",
        f"           {a.verdict.headline}",
        "",
        "INPUT FILES",
        "-" * 60,
    ]
    for rec in a.inputs:
        lines += [f"{rec.name}",
                  f"  role     {rec.role}",
                  f"  parser   {rec.parser}",
                  f"  events   {rec.rows}",
                  f"  size     {rec.size_bytes:,} bytes",
                  f"  modified {rec.modified_utc} UTC",
                  f"  sha256   {rec.sha256}",
                  f"  path     {rec.path}",
                  ""]
    if outputs:
        lines += ["OUTPUT FILES", "-" * 60]
        for rec in outputs:
            lines += [f"{rec.name}",
                      f"  size     {rec.size_bytes:,} bytes",
                      f"  sha256   {rec.sha256}",
                      ""]
    return "\n".join(lines)


def _kind_meaning(kind: str) -> str:
    return {
        "deauth": "A frame instructing a device to disconnect from the network",
        "disassoc": "A frame ending a device's association with the access point",
        "client_drop": "A device re-ran the DHCP handshake unexpectedly soon, "
                       "indicating its connection was interrupted",
        "link_reset": "The access point or client logged a disconnection directly",
        "alert": "An intrusion-detection system flagged deauthentication activity",
        "camera": "A vehicle pass recorded by the security camera",
        "assoc": "A device joined or renewed its address (context, not a disruption)",
        "context": "Supporting information, not counted as a disruption",
    }.get(kind, "")


def _fmt(value) -> str:
    if value is None or value != value:
        return "-"
    try:
        return pd.Timestamp(value).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return str(value)


def _p(value) -> str:
    if value is None or value != value:
        return "n/a"
    if value < 1e-4:
        return f"{value:.2e}"
    return f"{value:.4f}"


def _num(value) -> str:
    if value is None or value != value:
        return "n/a"
    if value == float("inf"):
        return "infinite (no counter-examples)"
    return f"{value:.3f}"


def _lift_text(lift: float) -> str:
    if lift != lift:
        return "not comparable to"
    if lift == float("inf"):
        return "infinitely above"
    return f"{lift:.1f} times"
