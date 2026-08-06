"""``--self-test``: synthetic fixtures, then the whole pipeline over them.

Two scenarios are generated from the same generator with different seeds:

* **positive** - deauth bursts planted a few seconds after each camera event.
  The tool must return CORRELATION FOUND.
* **negative** - camera events and disruptions drawn independently over the
  same period at the same rates. The tool must *not* claim a correlation.

The negative case matters more than the positive one. A correlator that always
finds a correlation is worthless as evidence, so the test fails if random data
produces a finding.

Fixtures are written for every parser in the registry, so the test also covers
format detection, timestamp normalization and reason-code extraction.
"""

from __future__ import annotations

import csv
import json
import os
import sqlite3
import struct
import sys
import tempfile
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from . import __version__, __tool_name__
from .config import AppConfig
from .correlate import run_analysis
from .events import BROADCAST, norm_mac
from .parsers.dot11 import DLT_IEEE802_11_RADIOTAP, build_deauth_frame
from .stats import VERDICT_FOUND

TZ = "America/New_York"
BASE = datetime(2026, 7, 14, 18, 0, 0, tzinfo=ZoneInfo(TZ))

ATTACKER_MAC = "de:ad:be:ef:00:01"
AP_BSSID = "a4:2b:b0:11:22:33"
CLIENTS = ["3c:22:fb:aa:bb:01", "3c:22:fb:aa:bb:02", "f0:18:98:cc:dd:03"]


class Check:
    def __init__(self, verbose: bool = True):
        self.passed = 0
        self.failed = 0
        self.verbose = verbose
        self.failures: list[str] = []

    def that(self, condition: bool, description: str, detail: str = "") -> bool:
        if condition:
            self.passed += 1
            if self.verbose:
                print(f"  PASS  {description}")
        else:
            self.failed += 1
            self.failures.append(f"{description}{' - ' + detail if detail else ''}")
            print(f"  FAIL  {description}"
                  + (f"\n          {detail}" if detail else ""))
        return condition

    def equal(self, actual, expected, description: str) -> bool:
        return self.that(actual == expected, description,
                         f"expected {expected!r}, got {actual!r}")

    def at_least(self, actual, minimum, description: str) -> bool:
        return self.that(actual >= minimum, description,
                         f"expected at least {minimum}, got {actual}")


def run_self_test(keep: str | None = None, verbose: bool = True) -> int:
    print(f"{__tool_name__} {__version__} - self-test\n")
    check = Check(verbose)

    if keep:
        root = Path(keep)
        root.mkdir(parents=True, exist_ok=True)
        cleanup = None
    else:
        tmp = tempfile.TemporaryDirectory(prefix="deauth-correlator-selftest-")
        root = Path(tmp.name)
        cleanup = tmp

    def section(number: int, title: str, body) -> None:
        """Run one section, recording a crash as a failure rather than aborting.

        A section that raises should not cost the results of the ones after it -
        when something is broken you want the whole picture, not the first
        traceback.
        """
        print(f"{'' if number == 1 else chr(10)}[{number}/10] {title}")
        try:
            body()
        except Exception as exc:
            check.that(False, f"section '{title}' ran to completion",
                       f"{exc.__class__.__name__}: {exc}")
            traceback.print_exc()

    try:
        print(f"Fixtures: {root}\n")

        state: dict = {}
        section(1, "Time handling", lambda: _test_time(check))
        section(2, "Frame decoding and reason codes", lambda: _test_frames(check))

        def parsers() -> None:
            state["positive"] = _write_scenario(root / "positive", correlated=True,
                                                seed=1)
            state["negative"] = _write_scenario(root / "negative", correlated=False,
                                                seed=99)
            _test_parsers(check, state["positive"])

        section(3, "Parsers over synthetic fixtures", parsers)

        def positive() -> None:
            state["pos_analysis"] = _analyze(state["positive"])
            _test_positive(check, state["pos_analysis"])

        section(4, "Positive scenario - a planted correlation must be found", positive)
        section(5, "Negative scenario - random data must NOT produce a finding",
                lambda: _test_negative(check, _analyze(state["negative"])))
        section(6, "Outputs and chain of custody",
                lambda: _test_outputs(check, state["pos_analysis"],
                                      root / "positive_output"))
        section(7, "The two statistics backends agree", lambda: _test_backends(check))
        section(8, "Degenerate inputs are handled honestly",
                lambda: _test_edge_cases(check, root / "edge"))
        section(9, "Routine network traffic is not mistaken for evidence",
                lambda: _test_no_fabrication(check))
        section(10, "The read-only and chain-of-custody guarantees hold",
                lambda: _test_guarantees(check, root / "guarantees"))

    finally:
        if cleanup is not None:
            try:
                cleanup.cleanup()
            except OSError:
                pass

    total = check.passed + check.failed
    print(f"\n{'=' * 60}")
    if check.failed:
        print(f"SELF-TEST FAILED: {check.failed} of {total} checks failed.")
        for failure in check.failures:
            print(f"  - {failure}")
        return 1
    print(f"SELF-TEST PASSED: all {total} checks passed.")
    if keep:
        print(f"Fixtures kept in {root}")
    return 0


# -- unit-level checks -----------------------------------------------------

def _test_time(check: Check) -> None:
    from .timeutil import TimeContext, finalize, humanize_delta, parse_any

    ctx = TimeContext(TZ, default_year=2026)

    dt = parse_any("2026-07-14T21:03:11.500-04:00", ctx)
    utc, local, offset = finalize(dt, ctx)
    check.equal(offset, "-04:00", "an explicit UTC offset in the source is preserved")
    check.equal(utc.hour, 1, "an offset timestamp converts to the right UTC hour")
    check.equal(local.hour, 21, "and back to the right local hour")

    dt = parse_any("Jul 14 21:03:11", ctx)
    utc, local, offset = finalize(dt, ctx)
    check.equal(local.strftime("%Y-%m-%d %H:%M:%S"), "2026-07-14 21:03:11",
                "a year-less syslog timestamp uses the year hint")
    check.equal(offset, "-04:00", "and picks up the zone's summer offset")

    winter = finalize(parse_any("Jan 14 21:03:11", ctx), ctx)
    check.equal(winter[2], "-05:00", "a January timestamp gets the winter offset")

    check.that(parse_any("1752541391", ctx) is not None,
               "a bare epoch timestamp parses")
    check.that("before" in humanize_delta(-4.2) and "after" in humanize_delta(4.2),
               "delta direction is worded, not signed")

    # Daylight-saving edges. A wall-clock time with no offset is not always one
    # instant, and a silently-resolved hour would be a sixty-second error inside
    # a thirty-second analysis, so both cases must be counted and disclosed.
    fallback = TimeContext(TZ, 2026)
    for stamp in ("Nov  1 01:30:00", "Nov  1 01:45:00"):
        finalize(parse_any(stamp, fallback), fallback)
    check.equal((fallback.dst_ambiguous, fallback.dst_nonexistent), (2, 0),
                "timestamps in the repeated daylight-saving hour are flagged ambiguous")

    gap = TimeContext(TZ, 2026)
    finalize(parse_any("Mar  8 02:30:00", gap), gap)
    check.equal((gap.dst_ambiguous, gap.dst_nonexistent), (0, 1),
                "a timestamp in the skipped daylight-saving hour is flagged as "
                "nonexistent, not as ambiguous")

    southern = TimeContext("Australia/Sydney", 2026)
    finalize(parse_any("Oct  4 02:30:00", southern), southern)
    check.equal(southern.dst_nonexistent, 1,
                "the same detection works for a southern-hemisphere transition")

    ordinary = TimeContext(TZ, 2026)
    for stamp in ("Jul 14 21:03:11", "Jan  5 06:00:00"):
        finalize(parse_any(stamp, ordinary), ordinary)
    check.equal(ordinary.dst_warnings(), [],
                "ordinary timestamps raise no daylight-saving warning")

    explicit = TimeContext(TZ, 2026)
    finalize(parse_any("2026-11-01T01:30:00-04:00", explicit), explicit)
    check.equal(explicit.dst_warnings(), [],
                "a timestamp carrying its own UTC offset is never ambiguous")


def _test_frames(check: Check) -> None:
    from .parsers.dot11 import decode_packet

    raw = build_deauth_frame(_mac_bytes(ATTACKER_MAC), _mac_bytes(BROADCAST),
                             _mac_bytes(AP_BSSID), reason=7)
    frame = decode_packet(_radiotap(-42, 2437) + raw, DLT_IEEE802_11_RADIOTAP)
    check.that(frame is not None, "a radiotap-wrapped deauth frame decodes")
    if frame:
        check.equal(frame.kind, "deauth", "the frame is identified as a deauth")
        check.equal(frame.reason_code, 7, "reason code 7 is read from the frame body")
        check.equal(frame.src_mac, ATTACKER_MAC, "the transmitter address is read")
        check.equal(frame.dst_mac, BROADCAST, "the broadcast target is read")
        check.equal(frame.bssid, AP_BSSID, "the BSSID is read")
        check.equal(frame.signal_dbm, -42, "the radiotap signal field is read")
        check.equal(frame.channel, 6, "the radiotap channel is derived from frequency")

    disassoc = build_deauth_frame(_mac_bytes(ATTACKER_MAC), _mac_bytes(CLIENTS[0]),
                                  _mac_bytes(AP_BSSID), reason=1, disassoc=True)
    frame = decode_packet(disassoc, 105)
    check.that(frame is not None and frame.kind == "disassoc",
               "a bare 802.11 disassociation frame decodes")
    check.that(frame is not None and frame.reason_code == 1,
               "reason code 1 is read from a disassociation frame")


def _test_parsers(check: Check, scenario: dict) -> None:
    from .parsers import ParseContext, detect, parse_path
    from .timeutil import TimeContext

    expectations = [
        ("dnsmasq.log", "opnsense-log", "opnsense"),
        ("kea-dhcp4.log", "opnsense-log", "opnsense"),
        ("isc-dhcpd.log", "opnsense-log", "opnsense"),
        ("hostapd.log", "opnsense-log", "opnsense"),
        ("capture-01.cap", "wifi-capture", "pcap80211"),
        ("capture.pcapng", "wifi-capture", "pcap80211"),
        ("kismet.kismet", "wifi-capture", "kismet"),
        ("airodump-01.csv", "wifi-capture", "airodump_csv"),
        ("nzyme-deauth.csv", "wifi-capture", "nzyme_csv"),
        ("camera_events.csv", "camera-events", "camera_csv"),
        ("clips", "camera-events", "camera_clips"),
    ]

    for name, role, expected_id in expectations:
        path = scenario["dir"] / name
        if not path.exists():
            check.that(False, f"fixture {name} exists")
            continue
        ctx = ParseContext(time=TimeContext(TZ, 2026), options={"clip_time_from": "auto"})
        parser, score = detect(path, None)
        rows, used = parse_path(path, ctx, role)
        check.equal(used.id, expected_id, f"{name} is parsed by {expected_id}")
        check.at_least(len(rows), 1, f"{name} yields at least one event")

    # Reason codes must survive the pcap path end to end.
    ctx = ParseContext(time=TimeContext(TZ, 2026))
    rows, _ = parse_path(scenario["dir"] / "capture-01.cap", ctx, "wifi-capture")
    codes = {r["reason_code"] for r in rows}
    check.that(codes <= {1, 7} and codes, "pcap deauth frames carry reason codes 1/7",
               f"got {sorted(c for c in codes if c is not None)}")
    check.that(any(r["dst_mac"] == BROADCAST for r in rows),
               "broadcast deauth frames are recognized in the capture")

    # Kismet alerts must come through alongside decoded frames.
    ctx = ParseContext(time=TimeContext(TZ, 2026))
    rows, _ = parse_path(scenario["dir"] / "kismet.kismet", ctx, "wifi-capture")
    check.that(any(r["kind"] == "alert" for r in rows),
               "Kismet DEAUTHFLOOD alerts are extracted")
    check.that(any(r["kind"] == "deauth" for r in rows),
               "Kismet stored packets are decoded into deauth events")

    # Clip filenames must record how the time was derived.
    ctx = ParseContext(time=TimeContext(TZ, 2026), options={"clip_time_from": "auto"})
    rows, _ = parse_path(scenario["dir"] / "clips", ctx, "camera-events")
    check.that(all("time from" in (r["notes"] or "") for r in rows),
               "every clip row states how its timestamp was derived")


def _test_positive(check: Check, analysis) -> None:
    s = analysis.stats
    check.equal(analysis.verdict.label, VERDICT_FOUND,
                "a planted correlation is reported as found")
    check.at_least(s.n_coincident, 8, "most planted camera events are matched")
    check.that(s.worst_p < 0.01,
               "every significance test clears the threshold, not just the best one",
               f"weakest p = {s.worst_p:.4g} from {s.weakest_test}")
    check.that(s.rate_ratio >= 2.0, "the rate ratio exceeds 2x",
               f"got {s.rate_ratio:.2f}")
    check.at_least(len(analysis.floods.floods), 1, "the planted floods are detected")
    check.that(ATTACKER_MAC in analysis.floods.by_source,
               "the planted attacker MAC is listed as a flood source",
               f"sources: {list(analysis.floods.by_source)}")
    check.at_least(int((analysis.events["kind"] == "client_drop").sum()), 1,
                   "client drops are derived from the DHCP re-associations")
    check.that(analysis.observation_hours > 0,
               "the analysis period has a positive duration")

    drops = analysis.events[analysis.events["kind"] == "client_drop"]
    check.that(all("restarted DHCP acquisition" in (n or "") for n in drops["notes"]),
               "each derived drop explains why it was derived")


def _test_negative(check: Check, analysis) -> None:
    check.that(analysis.verdict.label != VERDICT_FOUND,
               "independent random data does NOT produce a correlation finding",
               f"verdict was {analysis.verdict.label}: {analysis.verdict.headline}")
    check.that(analysis.stats.worst_p > 0.001,
               "random data does not produce an extreme p-value",
               f"weakest p = {analysis.stats.worst_p:.4g}")
    check.that(analysis.stats.n_camera > 0,
               "the negative scenario still parsed its camera events")


def _bundle_layout() -> dict:
    from .evidence import LAYOUT
    return LAYOUT


def _test_outputs(check: Check, analysis, outdir: Path) -> None:
    from .csvout import write_correlation_csv, write_events_csv
    from .evidence import build_bundle
    from .hashing import sha256_file
    from .report import build_report, write_manifest

    outdir.mkdir(parents=True, exist_ok=True)

    csv_path = write_correlation_csv(analysis.matches, outdir / "correlation.csv")
    check.that(csv_path.exists(), "correlation.csv is written")
    header = csv_path.read_text(encoding="utf-8").splitlines()[0]
    for column in ("camera_event_local", "camera_event_utc", "delta_seconds",
                   "coincidence", "deauth_source_mac", "reason_code"):
        check.that(column in header, f"correlation.csv has a {column} column")

    write_events_csv(analysis.events, outdir / "events.csv")

    report = build_report(analysis)
    (outdir / "report.md").write_text(report, encoding="utf-8")
    for phrase in ("camera passes coincided", "Chain of custody", "does not prove",
                   "Glossary", "Methodology", "SHA-256"):
        check.that(phrase.lower() in report.lower(),
                   f"report.md contains the {phrase!r} section")
    check.that(all(rec.sha256 in report for rec in analysis.inputs),
               "every input hash appears in the report")

    try:
        from .plot import write_timeline
        png = write_timeline(analysis, outdir / "timeline.png")
        check.that(png.exists() and png.stat().st_size > 5000,
                   "timeline.png is rendered and non-trivial")
    except Exception as exc:
        check.that(False, "timeline.png is rendered", str(exc))

    manifest = write_manifest(analysis, outdir / "MANIFEST.json")
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    check.that(payload["verdict"]["label"] == analysis.verdict.label,
               "MANIFEST.json records the verdict")
    check.that(len(payload["inputs"]) == len(analysis.inputs),
               "MANIFEST.json records every input file")

    # Hashing must be deterministic - the same bytes always hash the same.
    first = sha256_file(csv_path)
    check.equal(sha256_file(csv_path), first, "file hashing is deterministic")

    # The manifest must be valid JSON to every parser, not just Python's.
    # json.dumps writes bare NaN and Infinity by default, and Fisher's odds
    # ratio is infinite on exactly the shape of a strong positive finding.
    def _reject(token):
        raise ValueError(f"non-JSON literal {token!r}")

    try:
        json.loads(manifest.read_text(encoding="utf-8"), parse_constant=_reject)
        strict_ok, detail = True, ""
    except ValueError as exc:
        strict_ok, detail = False, str(exc)
    check.that(strict_ok,
               "MANIFEST.json is valid JSON by the strict grammar, not only to Python",
               detail)

    bundle = build_bundle(analysis, outdir / "bundle", copy_inputs=True, make_zip=True)

    # Rebuilding into the same directory must replace the previous bundle, not
    # accumulate a second set of evidence copies beside it.
    before = sorted(p.name for p in (bundle.root / "06_source_files").iterdir())
    rebuilt = build_bundle(analysis, outdir / "bundle", copy_inputs=True)
    after = sorted(p.name for p in (rebuilt.root / "06_source_files").iterdir())
    check.equal(after, before,
                "rebuilding a bundle replaces the previous one rather than "
                "accumulating duplicate evidence copies")
    custody = (rebuilt.root / "chain_of_custody.log").read_text(encoding="utf-8")
    check.equal(custody.count("Bundle started"), 1,
                "and the chain-of-custody log describes only the current build")

    cover = (rebuilt.root / "00_READ_ME_FIRST.txt").read_text(encoding="utf-8")
    present = {p.name for p in rebuilt.root.iterdir()}
    missing = [name for name in _bundle_layout().values()
               if name in present and name not in cover]
    check.that(not missing,
               "the bundle cover sheet lists every file the bundle actually contains",
               f"present but absent from the inventory: {missing}")
    phantom = [name for name in _bundle_layout().values()
               if name not in present and name in cover]
    check.that(not phantom,
               "and describes no file that is not there",
               f"described but missing: {phantom}")
    check.that((bundle.root / "01_report.md").exists(), "the bundle contains the report")
    check.that((bundle.root / "00_MANIFEST.json").exists(),
               "the bundle contains the manifest")
    check.that((bundle.root / "06_source_files").exists(),
               "the bundle contains copies of the source files")
    check.that((bundle.root / "chain_of_custody.log").exists(),
               "the bundle contains a chain-of-custody log")
    check.that(bundle.zip_path is not None and bundle.zip_path.exists(),
               "the bundle archive is created")
    check.that(len(bundle.zip_sha256) == 64, "the archive is hashed")
    check.that(not bundle.problems, "the bundle reports no problems",
               "; ".join(bundle.problems))


def _test_backends(check: Check) -> None:
    """The pure-Python tests must reproduce SciPy exactly.

    The report names whichever backend was used, so the two must not be able to
    disagree - a number that changes depending on whether an optional package
    happens to be installed is indefensible in a report.
    """
    from . import stats as st

    if not st.HAVE_SCIPY:
        check.that(True, "SciPy is not installed; the pure-Python backend is in use "
                         "and there is nothing to compare against")
        return

    import random
    random.seed(4242)
    tables = [(12, 3, 5, 180), (5, 0, 2, 60), (3, 9, 40, 300), (20, 1, 3, 500),
              (2, 2, 2, 2), (7, 7, 7, 77), (1, 1, 1, 1), (0, 5, 5, 50),
              (4, 4, 5, 5), (9, 1, 1, 9), (6, 2, 3, 90)]
    tables += [(random.randint(0, 30), random.randint(0, 30),
                random.randint(0, 60), random.randint(1, 400)) for _ in range(30)]
    binomials = [(12, 12, 0.10), (5, 5, 0.21), (3, 20, 0.4), (0, 10, 0.5),
                 (10, 10, 0.9), (1, 50, 0.02), (25, 100, 0.2)]

    def collect():
        values = []
        for a, b, c, d in tables:
            values.append(st._fisher_exact_greater(a, b, c, d)[1])
            chi, p = st._chi_square(a, b, c, d)
            values.extend([chi, p])
        values.extend(st._binom_sf(k, n, p) for k, n, p in binomials)
        return values

    with_scipy = collect()
    st.HAVE_SCIPY = False
    try:
        pure = collect()
    finally:
        st.HAVE_SCIPY = True

    worst = 0.0
    worst_at = -1
    for i, (u, v) in enumerate(zip(with_scipy, pure)):
        if u != u and v != v:
            continue
        rel = abs(u - v) / max(abs(u), abs(v), 1e-300)
        if rel > worst:
            worst, worst_at = rel, i

    check.that(worst < 1e-9,
               f"Fisher, chi-square and binomial agree between backends across "
               f"{len(tables)} tables",
               f"largest relative difference {worst:.3e} at value {worst_at}")


def _test_edge_cases(check: Check, directory: Path) -> None:
    """Degenerate inputs must produce a stated limitation, not a crash or a claim."""
    import numpy as np
    import pandas as pd

    from . import stats as st
    from .correlate import run_analysis
    from .events import to_frame
    from .timeutil import TimeContext

    base_config = AppConfig(timezone=TZ, trials=500).analysis_dict()

    def event(when: datetime, kind: str) -> dict:
        from .events import make_event
        from .timeutil import finalize
        utc, local, offset = finalize(when, TimeContext(TZ, 2026))
        return make_event(ts_utc=utc, ts_local=local, utc_offset=offset, kind=kind,
                          source_file="synthetic", source_kind="selftest",
                          source_ref="edge", raw="")

    # No camera events at all.
    only_deauth = to_frame([event(BASE + timedelta(seconds=i * 60), "deauth")
                            for i in range(5)])
    result = run_analysis(only_deauth, base_config)
    check.equal(result.verdict.label, st.VERDICT_INSUFFICIENT,
                "wireless evidence with no camera events reports insufficient data")

    # Camera events with no disruptions whatsoever.
    only_camera = to_frame([event(BASE + timedelta(seconds=i * 300), "camera")
                            for i in range(6)])
    result = run_analysis(only_camera, base_config)
    check.equal(result.verdict.label, st.VERDICT_INSUFFICIENT,
                "camera events with no disruptions reports insufficient data")
    check.that("nothing to correlate" in result.verdict.headline,
               "and says why in plain language")

    # Two streams that never overlap in time.
    disjoint = to_frame(
        [event(BASE + timedelta(seconds=i * 60), "camera") for i in range(6)]
        + [event(BASE + timedelta(days=30, seconds=i * 60), "deauth")
           for i in range(6)])
    result = run_analysis(disjoint, base_config)
    check.that(any("do not overlap" in note for note in result.period_notes),
               "non-overlapping evidence periods are reported, not silently analysed",
               f"notes were {result.period_notes}")
    check.that(result.verdict.label != VERDICT_FOUND,
               "and no correlation is claimed from them")

    # A single camera event: too few to test.
    single = to_frame([event(BASE, "camera"), event(BASE + timedelta(seconds=3),
                                                    "deauth")])
    result = run_analysis(single, base_config)
    check.equal(result.verdict.label, st.VERDICT_INSUFFICIENT,
                "one camera event is reported as too few to test")

    # An empty event set must not raise.
    try:
        result = run_analysis(to_frame([]), base_config)
        check.that(result.verdict.label == st.VERDICT_INSUFFICIENT,
                   "an empty event set produces a verdict rather than an exception")
    except Exception as exc:
        check.that(False, "an empty event set produces a verdict rather than an "
                          "exception", f"{exc.__class__.__name__}: {exc}")

    # The report must always carry the same eleven sections. Section numbers are
    # cross-referenced from the text and from the bundle cover sheet, so a
    # report that skips a number because a section had nothing in it would
    # invite the question of what was removed.
    import re

    from .report import build_report

    scenarios = {
        "there are no camera events": [
            event(BASE + timedelta(seconds=i * 60), "deauth") for i in range(5)],
        "there are no disruptions": [
            event(BASE + timedelta(seconds=i * 300), "camera") for i in range(6)],
        "there are no events at all": [],
        "the sensitivity table is disabled": (
            [event(BASE + timedelta(seconds=i * 300), "camera") for i in range(6)]
            + [event(BASE + timedelta(seconds=i * 300 + 4), "deauth")
               for i in range(6)]),
    }
    for label, rows in scenarios.items():
        config = AppConfig(
            timezone=TZ, trials=400,
            sensitivity=(label != "the sensitivity table is disabled")).analysis_dict()
        report = build_report(run_analysis(to_frame(rows), config))
        numbers = [int(n) for n in re.findall(r"^## (\d+)\. ", report, re.M)]
        check.equal(numbers, list(range(1, 12)),
                    f"the report keeps all eleven sections when {label}")

    # The same vehicle pass listed by two camera sources must be counted once.
    # Double-counting raises the number of passes and the number of coincidences
    # together, which pushes the p-value towards significance - the one
    # direction this tool must never drift in.
    def camera_from(source: str, seconds: float, plate: str = "") -> dict:
        row = event(BASE + timedelta(seconds=seconds), "camera")
        row["source_file"] = source
        row["plate"] = plate
        return row

    duplicated = [camera_from("passes.csv", i * 300, plate=f"PLATE{i}")
                  for i in range(6)]
    duplicated += [camera_from("clips/", i * 300 + 0.4) for i in range(6)]
    duplicated += [event(BASE + timedelta(seconds=i * 300 + 4), "deauth")
                   for i in range(6)]

    config = AppConfig(timezone=TZ, trials=500).analysis_dict()
    merged = run_analysis(to_frame(duplicated), config)
    check.equal(merged.stats.n_camera, 6,
                "a pass listed in both a camera CSV and a clip folder is counted once")
    check.that(any("duplicates" in w for w in merged.warnings),
               "and the de-duplication is disclosed in the report warnings")
    kept = merged.events[merged.events["category"] == "camera"]
    check.that(all(str(p or "").startswith("PLATE") for p in kept["plate"]),
               "the surviving row is the one carrying the plate, not the bare clip")

    config_off = AppConfig(timezone=TZ, trials=500,
                           camera_dedupe_s=0.0).analysis_dict()
    unmerged = run_analysis(to_frame(duplicated), config_off)
    check.equal(unmerged.stats.n_camera, 12,
                "--camera-dedupe 0 leaves both copies in place")

    same_file = [camera_from("passes.csv", 0.0), camera_from("passes.csv", 0.5)]
    same_file += [event(BASE + timedelta(seconds=4), "deauth")]
    result = run_analysis(to_frame(same_file), config)
    check.equal(result.stats.n_camera, 2,
                "two entries close together within one source are left alone - they "
                "are the operator's own data, not a duplicate import")

    # A whole-hour timezone error turns a real correlation into a confident
    # "none found". The tool must notice and say to check the clocks, without
    # crying wolf on data that genuinely has no relationship.
    # Irregular spacing matters here: a evenly-spaced sequence shifted by a
    # multiple of its own period re-aligns with itself, which would make the
    # test pass for the wrong reason.
    truth = [100, 640, 1310, 2050, 2600, 3320, 4100, 4780, 5300, 6010,
             6900, 7450, 8100, 8760, 9400, 10050]
    disruptions = [event(BASE + timedelta(seconds=t), "deauth") for t in truth]
    aligned = ([event(BASE + timedelta(seconds=t), "camera") for t in truth[:10]]
               + disruptions)
    shifted = ([event(BASE + timedelta(seconds=t + 3600), "camera")
                for t in truth[:10]] + disruptions)

    result = run_analysis(to_frame(shifted), config)
    check.that(result.lag_scan.suspicious,
               "an hour of clock skew is detected and flagged")
    check.that(abs(abs(result.lag_scan.best_lag_s) - 3600) < 60,
               "and the offset it reports is about an hour",
               f"reported {result.lag_scan.best_lag_s:.0f} s")
    check.that("one hour" in result.lag_scan.explanation(),
               "and the wording names a timezone mismatch as the likely cause")
    from .report import build_report as _build
    check.that("diagnostic, not a finding" in _build(result),
               "the report says the shifted alignment is a diagnostic, not a result")

    result = run_analysis(to_frame(aligned), config)
    check.that(not result.lag_scan.suspicious,
               "correctly aligned evidence raises no clock warning")

    import numpy as np
    rng = np.random.default_rng(3)
    unrelated = ([event(BASE + timedelta(seconds=float(t)), "camera")
                  for t in rng.uniform(0, 14400, size=12)]
                 + [event(BASE + timedelta(seconds=float(t)), "deauth")
                    for t in rng.uniform(0, 14400, size=14)])
    result = run_analysis(to_frame(unrelated), config)
    check.that(not result.lag_scan.suspicious,
               "genuinely unrelated data does not produce a spurious clock warning")

    # A missing input path is reported and skipped, not fatal.
    from .cli import load_evidence
    directory.mkdir(parents=True, exist_ok=True)
    config = AppConfig(camera_events=[str(directory / "does-not-exist.csv")],
                       timezone=TZ)
    events, records, warnings = load_evidence(config, None, log=lambda *a, **k: None)
    check.that(events.empty and any("not found" in w for w in warnings),
               "a missing input file is reported as a warning rather than crashing")

    # A file whose contents match no parser.
    junk = directory / "junk.bin"
    junk.write_bytes(b"\x00\x01\x02not a log or a capture\xff" * 20)
    config = AppConfig(wifi_captures=[str(junk)], timezone=TZ)
    events, records, warnings = load_evidence(config, None, log=lambda *a, **k: None)
    check.that(any("no parser recognized" in w for w in warnings),
               "an unrecognized file is reported with the formats that were accepted")

    # An empty CSV with only a header.
    empty_csv = directory / "empty_camera.csv"
    empty_csv.write_text("timestamp,plate,make,model,notes\n", encoding="utf-8")
    config = AppConfig(camera_events=[str(empty_csv)], timezone=TZ)
    events, records, warnings = load_evidence(config, None, log=lambda *a, **k: None)
    check.that(events.empty, "a header-only CSV yields no events without crashing")


def _test_no_fabrication(check: Check) -> None:
    """Regressions for the ways this tool could invent or overstate evidence.

    Every case here was a real defect. Each one either manufactured disruption
    events out of ordinary network traffic, deleted genuine camera events, or
    let a finding be declared on weaker grounds than the report claimed. They
    are the failures that matter most, because their output looks entirely
    plausible.
    """
    import numpy as np

    from . import stats as st
    from .correlate import dedupe_camera_events
    from .drops import derive_client_drops
    from .events import make_event, norm_mac, text, to_frame
    from .parsers.dot11 import decode_packet
    from .timeutil import TimeContext, finalize

    ctx = TimeContext(TZ, 2026)
    mac = CLIENTS[0]

    def lease(seconds: float, subtype: str, kind: str = "assoc") -> dict:
        utc, local, offset = finalize(BASE + timedelta(seconds=seconds), ctx)
        return make_event(ts_utc=utc, ts_local=local, utc_offset=offset, kind=kind,
                          subtype=subtype, client_mac=mac, source_file="dhcp.log",
                          source_kind="opnsense", source_ref="1", raw="")

    # -- routine DHCP traffic must never become disruption evidence ----------
    scenarios = {
        "DHCP retransmission backoff is one failed attempt, not five drops": (
            [lease(-500, "ACK")] + [lease(t, "DISCOVER") for t in (0, 4, 12, 28, 60)],
            0),
        "routine T1 lease renewals are not drops": (
            [lease(t, "REQUEST") for t in (0, 90, 180, 270)]
            + [lease(t + 1, "ACK") for t in (0, 90, 180, 270)], 0),
        "repeated DHCPINFORM from a static host is not a drop": (
            [lease(-500, "ACK")] + [lease(t, "INFORM") for t in (0, 30, 60)], 0),
        "a client that never held a lease cannot have dropped": (
            [lease(t, "DISCOVER") for t in (0, 4, 12, 28)], 0),
        "an already-logged disconnection is not counted twice": (
            [lease(0, "ACK"), lease(10, "", "link_reset"),
             lease(30, "DISCOVER"), lease(32, "ACK")], 0),
        "a genuine re-acquisition after a confirmed lease IS a drop": (
            [lease(0, "ACK"), lease(20, "DISCOVER"), lease(22, "ACK")], 1),
    }
    for description, (rows, expected) in scenarios.items():
        found = len(derive_client_drops(to_frame(rows)))
        check.equal(found, expected, description)

    # -- de-duplication must not delete genuine passes -----------------------
    def camera(seconds: float, source: str, plate: str = "") -> dict:
        utc, local, offset = finalize(BASE + timedelta(seconds=seconds), ctx)
        return make_event(ts_utc=utc, ts_local=local, utc_offset=offset, kind="camera",
                          plate=plate, source_file=source, source_kind="camera_csv",
                          source_ref="r", raw="")

    kept, _ = dedupe_camera_events(
        to_frame([camera(0, "passes.csv", "ABC123"),
                  camera(1, "passes.csv", "XYZ789"),
                  camera(0, "clips/")]), 2.0)
    plates = sorted(p for p in kept["plate"] if text(p))
    check.equal(plates, ["ABC123", "XYZ789"],
                "two distinct passes in one file survive a duplicate from another "
                "source")

    chained = [camera(t, "passes.csv", f"P{i}")
               for i, t in enumerate((0, 1.9, 3.8, 5.7))]
    kept, _ = dedupe_camera_events(to_frame(chained), 2.0)
    check.equal(int((kept["category"] == "camera").sum()), 4,
                "four passes 1.9 s apart are four passes, not one merged event")

    kept, _ = dedupe_camera_events(
        to_frame([camera(0, "passes.csv", "ABC123"), camera(0.4, "clips/")]), 2.0)
    check.equal(int((kept["category"] == "camera").sum()), 1,
                "a real cross-source duplicate is still merged")

    # -- the verdict must rest on the weakest test, not the best -------------
    stats = st.analyze(np.array([100.0, 500.0, 900.0, 1300.0]),
                       np.array([104.0, 505.0, 903.0, 1305.0]),
                       0.0, 2000.0, 30.0, trials=500)
    check.that(stats.worst_p >= stats.best_p,
               "worst_p is never smaller than best_p")

    forced = st.WindowStats(
        window_s=30, n_camera=40, n_coincident=14, coincidence_rate=0.35,
        baseline_rate=0.181, expected_by_chance=7.25, lift=1.9,
        binom_p=0.00832, perm_p=0.111, fisher_p=0.265,
        perm_trials=1000, perm_mean=7.0, fisher_odds_ratio=1.7,
        chi2=1.2, chi2_p=0.27, table=[[14, 26], [30, 200]], rate_ratio=3.0)
    verdict = st.decide(forced, alpha=0.01, n_incidents=300)
    check.that(verdict.label != VERDICT_FOUND,
               "one test clearing alpha while the others do not is NOT a finding",
               f"binom={forced.binom_p} perm={forced.perm_p} "
               f"fisher={forced.fisher_p} -> {verdict.label}")
    check.that(forced.tests_straddle(0.01),
               "and the disagreement across the threshold is flagged")

    # -- frame decoding must not invent a reason code ------------------------
    import struct as _struct

    def mac_bytes(value: str) -> bytes:
        return bytes(int(part, 16) for part in norm_mac(value).split(":"))

    protected = bytearray(build_deauth_frame(
        mac_bytes(ATTACKER_MAC), mac_bytes(BROADCAST), mac_bytes(AP_BSSID), reason=7))
    control = _struct.unpack_from("<H", protected, 0)[0] | 0x4000
    _struct.pack_into("<H", protected, 0, control)
    frame = decode_packet(bytes(protected), 105)
    check.that(frame is not None and frame.reason_code is None and frame.protected,
               "an 802.11w protected frame yields no reason code rather than "
               "ciphertext read as one")

    # -- radiotap FHSS is byte-aligned; getting it wrong drops the signal ----
    present = (1 << 0) | (1 << 1) | (1 << 4) | (1 << 5)
    fields = (_struct.pack("<Q", 12345) + _struct.pack("<B", 0)
              + _struct.pack("<BB", 1, 2) + _struct.pack("<b", -55))
    header = _struct.pack("<BBHI", 0, 0, 8 + len(fields), present) + fields
    frame = decode_packet(
        header + build_deauth_frame(mac_bytes(ATTACKER_MAC), mac_bytes(BROADCAST),
                                    mac_bytes(AP_BSSID), reason=7),
        DLT_IEEE802_11_RADIOTAP)
    check.that(frame is not None and frame.signal_dbm == -55,
               "the radiotap signal survives a header containing an FHSS field",
               f"got {frame.signal_dbm if frame else 'no frame'}")

    # -- no p-value is ever reported as exactly zero -------------------------
    check.that(st._binom_sf(5, 5, 0.0) > 0.0,
               "a p-value is never reported as exactly zero")

    # -- missing values never render as the string 'nan' ---------------------
    check.equal(text(float("nan")), "", "a missing value renders as blank, not 'nan'")
    check.equal(text(None), "", "None renders as blank")
    check.equal(text("aa:bb:cc:dd:ee:ff"), "aa:bb:cc:dd:ee:ff",
                "a real value is left alone")

    mixed = to_frame([camera(0, "a.csv", "ABC123"), camera(300, "a.csv")])
    from .correlate import build_matches
    from .drops import cluster_incidents
    matches = build_matches(mixed[mixed["category"] == "camera"], mixed,
                            cluster_incidents(mixed), 30.0, 0.0, 1e12)
    check.that(all(str(v) != "nan" for v in matches["plate"]),
               "a blank plate in a mixed column does not become the text 'nan'",
               f"got {list(matches['plate'])}")


def _test_camera_guarantees(check: Check, directory: Path, recorder_module,
                            OnvifClient, OnvifError, MotionRecorder,
                            CameraConfig) -> None:
    """The camera half of the guarantees.

    Split out and called conditionally because it needs ``requests``, which is
    an optional dependency. Importing it at module scope made ``--self-test``
    fail outright on a base install that had never asked for camera support.
    """
    client = OnvifClient("192.0.2.1", username="u", password="p")
    check.that(client.session.trust_env is False,
               "the ONVIF session ignores proxy environment variables, so the "
               "credential header cannot be routed to a proxy")

    sent: dict = {}

    class _Reply:
        status_code = 200
        content = b"<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope'/>"
        headers: dict = {}

    def _capture(url, **kwargs):
        sent.update(kwargs)
        sent["url"] = url
        return _Reply()

    client.session.post = _capture
    client.call(client.device_url, "<tds:GetSystemDateAndTime/>", authenticated=False)
    check.equal(sent.get("allow_redirects"), False,
                "every ONVIF request is sent with redirects disabled")

    class _Redirect:
        status_code = 307
        content = b""
        headers = {"Location": "http://elsewhere.example/onvif"}

    client.session.post = lambda url, **kwargs: _Redirect()
    try:
        client.call(client.device_url, "<tds:GetSystemDateAndTime/>",
                    authenticated=False)
        check.that(False, "a redirect reply is refused rather than followed")
    except OnvifError as exc:
        check.that("redirect" in str(exc).lower(),
                   "a redirect reply is refused rather than followed")

    # -- the recorder must not touch the camera once stop has been asked for -
    config = CameraConfig(host="192.0.2.1", username="u", password="p")
    recorder = MotionRecorder(config, directory / "camera_events.csv",
                              save_snapshots=False)

    created: list = []

    class _CountingClient:
        def __init__(self, *args, **kwargs):
            created.append(1)

        def create_pull_point(self, *args, **kwargs):
            return "http://192.0.2.1:2020/sub"

    original = recorder_module.OnvifClient
    recorder_module.OnvifClient = _CountingClient
    try:
        recorder._stop.set()
        result = recorder._resubscribe()
        check.that(result is False and not created,
                   "no subscription is created once a stop has been requested",
                   f"returned {result!r} after {len(created)} client(s)")
    finally:
        recorder_module.OnvifClient = original

    check.that(recorder_module.MAX_RESUBSCRIBE_ATTEMPTS >= 1
               and 0 < recorder_module.RESUBSCRIBE_BACKOFF_S
               <= recorder_module.MAX_RESUBSCRIBE_BACKOFF_S,
               "re-subscription gives up after a bounded number of attempts")



def _test_guarantees(check: Check, directory: Path) -> None:
    """Regressions for the promises SAFETY.md makes to an auditing reader.

    Each of these was found by an independent review of the published 1.0.0, and
    each was a case where the documentation described behaviour the code did not
    have. A claim in a document that invites verification has to stay true.

    Everything here tests behaviour rather than source text. An earlier version
    read the source with ``inspect.getsource``, which works from a checkout and
    raises ``OSError`` inside a frozen build - so the checks that mattered most
    were exactly the ones that could not run in the artefact people download.

    The camera checks need ``requests``, which is an optional dependency. They
    are skipped rather than failed when it is absent, because the base install
    genuinely does not have it and the README says so. Importing it at module
    scope broke ``--self-test`` outright for anyone who installed without the
    camera extra.
    """
    import struct as _struct

    from . import cli as cli_module
    from .parsers.dot11 import decode_packet

    directory.mkdir(parents=True, exist_ok=True)

    try:
        from .camera import recorder as recorder_module
        from .camera.onvif_min import OnvifClient, OnvifError
        from .camera.recorder import MotionRecorder
        from .camera.tapo import CameraConfig
        camera_available = True
    except ImportError as exc:
        camera_available = False
        check.that(True, f"camera checks skipped - the optional camera support is "
                         f"not installed ({exc.name})")

    # -- the ONVIF client must talk to the camera and to nothing else --------
    if camera_available:
        _test_camera_guarantees(check, directory, recorder_module, OnvifClient,
                                OnvifError, MotionRecorder, CameraConfig)

    # -- an input file is hashed before anything reads it -------------------
    order: list = []
    sample = directory / "order.csv"
    sample.write_text("timestamp,plate,make,model,notes\n"
                      "2026-07-14T18:00:00-04:00,ABC123,,,pass\n",
                      encoding="utf-8")

    real_sha = cli_module.sha256_file
    real_parse = cli_module.parse_path

    def _sha(path):
        order.append("hash")
        return real_sha(path)

    def _parse(*args, **kwargs):
        order.append("parse")
        return real_parse(*args, **kwargs)

    cli_module.sha256_file = _sha
    cli_module.parse_path = _parse
    try:
        cli_module.load_evidence(
            AppConfig(camera_events=[str(sample)], timezone=TZ),
            None, log=lambda *a, **k: None)
    finally:
        cli_module.sha256_file = real_sha
        cli_module.parse_path = real_parse

    check.equal(order[:2], ["hash", "parse"],
                "an input file is hashed before it is parsed, as the report claims")

    # -- a protected frame must not have ciphertext read as a reason code ---
    def mac_bytes(value: str) -> bytes:
        return bytes(int(part, 16) for part in norm_mac(value).split(":"))

    protected = bytearray(build_deauth_frame(
        mac_bytes(ATTACKER_MAC), mac_bytes(BROADCAST), mac_bytes(AP_BSSID), reason=7))
    _struct.pack_into("<H", protected, 0,
                      _struct.unpack_from("<H", protected, 0)[0] | 0x4000)
    frame = decode_packet(bytes(protected), 105)
    check.that(frame is not None and frame.reason_code is None and frame.protected,
               "a protected management frame yields no reason code")

    # -- a build whose graphical interface is dead must be detectable --------
    flags = {opt for action in cli_module.build_parser()._actions
             for opt in action.option_strings}
    check.that("--check-runtime" in flags,
               "--check-runtime exists so a build with a dead GUI can be detected")
    check.equal(cli_module._check_runtime(), 0,
                "--check-runtime reports this environment as complete")


# -- fixture generation ----------------------------------------------------

def _analyze(scenario: dict):
    from .cli import load_evidence

    config = AppConfig(
        case_number="SELFTEST-001",
        operator="self-test",
        agency="deauth-correlator",
        opnsense_logs=[str(scenario["dir"] / n) for n in
                       ("dnsmasq.log", "kea-dhcp4.log", "isc-dhcpd.log", "hostapd.log")],
        wifi_captures=[str(scenario["dir"] / n) for n in
                       ("capture-01.cap", "capture.pcapng", "kismet.kismet",
                        "airodump-01.csv", "nzyme-deauth.csv")],
        camera_events=[str(scenario["dir"] / "camera_events.csv")],
        timezone=TZ,
        log_year=2026,
        trials=2000,
        outdir=str(scenario["dir"] / "out"),
    )
    events, records, warnings = load_evidence(config, None, log=lambda *a, **k: None)
    from .hashing import Provenance
    provenance = Provenance.collect(operator="self-test", case_number="SELFTEST-001",
                                    tz_name=TZ)
    return run_analysis(events, config.analysis_dict(), inputs=records,
                        warnings=warnings, provenance=provenance)


def _write_scenario(directory: Path, correlated: bool, seed: int) -> dict:
    """Generate a complete, self-consistent set of fixtures."""
    import numpy as np

    directory.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(seed)
    duration_s = 4 * 3600

    # 12 camera events spread over the period.
    camera_offsets = np.sort(rng.uniform(120, duration_s - 120, size=12))

    if correlated:
        # A deauth burst 2-8 s after each pass, plus a little background.
        attack_offsets = camera_offsets + rng.uniform(2, 8, size=len(camera_offsets))
        background = rng.uniform(0, duration_s, size=4)
        attack_offsets = np.sort(np.concatenate([attack_offsets, background]))
    else:
        # Same number of disruptions, placed independently.
        attack_offsets = np.sort(rng.uniform(0, duration_s, size=16))

    camera_times = [BASE + timedelta(seconds=float(s)) for s in camera_offsets]
    attack_times = [BASE + timedelta(seconds=float(s)) for s in attack_offsets]

    _write_camera_csv(directory / "camera_events.csv", camera_times, rng)
    _write_clips(directory / "clips", camera_times[:6])
    _write_dnsmasq(directory / "dnsmasq.log", attack_times, rng)
    _write_kea(directory / "kea-dhcp4.log", attack_times[:6], rng)
    _write_isc(directory / "isc-dhcpd.log", attack_times[:4], rng)
    _write_hostapd(directory / "hostapd.log", attack_times, rng)
    _write_pcap(directory / "capture-01.cap", attack_times, rng)
    _write_pcapng(directory / "capture.pcapng", attack_times[:3], rng)
    _write_kismet(directory / "kismet.kismet", attack_times, rng)
    _write_airodump(directory / "airodump-01.csv", camera_times, rng)
    _write_nzyme(directory / "nzyme-deauth.csv", attack_times[:8], rng)

    return {"dir": directory, "camera_times": camera_times,
            "attack_times": attack_times}


def _write_camera_csv(path: Path, times, rng) -> None:
    plates = ["7XK2291", "8BQ4417", "", "3MRT508"]
    makes = [("Ford", "F-150"), ("Honda", "Civic"), ("", ""), ("Toyota", "Tacoma")]
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["timestamp", "plate", "make", "model", "notes"])
        for i, when in enumerate(times):
            plate = plates[i % len(plates)]
            make, model = makes[i % len(makes)]
            writer.writerow([when.isoformat(timespec="seconds"), plate, make, model,
                             f"vehicle pass {i + 1}, westbound"])


def _write_clips(directory: Path, times) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    patterns = [
        lambda t: f"{t:%Y%m%d_%H%M%S}.mp4",                       # Tapo
        lambda t: f"Reolink_{t:%Y%m%d}_{t:%H%M%S}.mp4",
        lambda t: f"192.168.1.64_01_{t:%Y%m%d%H%M%S}000.mp4",     # Hikvision
        lambda t: f"NVR_ch1_main_{t:%Y%m%d%H%M%S}.dav",           # Dahua
        lambda t: f"{t:%Y-%m-%d}_{t:%H.%M.%S}_cam1.mp4",          # UniFi
        lambda t: f"{t:%Y-%m-%dT%H-%M-%S}.mp4",                   # ISO
    ]
    for i, when in enumerate(times):
        name = patterns[i % len(patterns)](when)
        (directory / name).write_bytes(b"\x00" * 512)


def _write_dnsmasq(path: Path, attack_times, rng) -> None:
    """Each disruption is followed by repeated DHCP handshakes from a client.

    This mirrors what a sustained deauthentication burst actually produces: the
    client re-associates, is knocked off again, and re-associates once more. The
    second handshake falls inside the re-association window, which is what the
    drop detector keys on. A healthy lease well before the disruption is also
    written, and must *not* be flagged.
    """
    lines = []
    for i, when in enumerate(attack_times):
        client = CLIENTS[i % len(CLIENTS)]
        ip = f"192.168.1.{50 + (i % len(CLIENTS))}"
        episodes = (
            (-900.0, "healthy lease, long before the disruption"),
            (2.0, "first re-association after the disruption"),
            (37.0, "knocked off again during the same burst"),
        )
        for base_delay, _why in episodes:
            for op, step in (("DISCOVER", 0.0), ("OFFER", 0.3),
                             ("REQUEST", 0.6), ("ACK", 0.8)):
                lines.append(_dnsmasq_line(
                    when + timedelta(seconds=base_delay + step), op, ip, client))

    lines.sort()
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _dnsmasq_line(when: datetime, op: str, ip: str, mac: str) -> str:
    return (f"<134>1 {when.isoformat(timespec='milliseconds')} OPNsense.localdomain "
            f"dnsmasq-dhcp 41231 - [meta sequenceId=\"1\"] "
            f"DHCP{op}(igb1) {ip} {mac}")


def _write_kea(path: Path, attack_times, rng) -> None:
    lines = []
    for i, when in enumerate(attack_times):
        client = CLIENTS[i % len(CLIENTS)]
        for label, delay in (("DHCP4_LEASE_ALLOC", -240.0),
                             ("DHCP4_PACKET_RECEIVED", 1.2),
                             ("DHCP4_LEASE_ALLOC", 2.0)):
            stamp = (when + timedelta(seconds=delay)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            lines.append(
                f"{stamp} INFO  [kea-dhcp4.leases/8801.140234] {label} "
                f"[hwtype=1 {client}], cid=[01:{client}], tid=0x{1000 + i:x}: "
                f"lease 192.168.1.{60 + i % 3} has been allocated for 7200 seconds")
    lines.sort()
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_isc(path: Path, attack_times, rng) -> None:
    lines = []
    for i, when in enumerate(attack_times):
        client = CLIENTS[i % len(CLIENTS)]
        for op, delay in ((f"DISCOVER from {client} via igb1", -180.0),
                          (f"ACK on 192.168.1.7{i} to {client} via igb1", -179.5),
                          (f"DISCOVER from {client} via igb1", 1.9),
                          (f"REQUEST for 192.168.1.7{i} from {client} via igb1", 2.4)):
            stamp = (when + timedelta(seconds=delay)).strftime("%b %e %H:%M:%S")
            lines.append(f"{stamp} OPNsense dhcpd: DHCP{op}")
    lines.sort()
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_hostapd(path: Path, attack_times, rng) -> None:
    lines = []
    for i, when in enumerate(attack_times):
        client = CLIENTS[i % len(CLIENTS)]
        stamp = when.strftime("%b %e %H:%M:%S")
        lines.append(f"{stamp} OPNsense hostapd: wlan0: STA {client} IEEE 802.11: "
                     f"disassociated")
        later = (when + timedelta(seconds=3)).strftime("%b %e %H:%M:%S")
        lines.append(f"{later} OPNsense hostapd: wlan0: STA {client} IEEE 802.11: "
                     f"associated")
    lines.sort()
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_pcap(path: Path, attack_times, rng) -> None:
    """A real libpcap file with radiotap-wrapped deauth bursts."""
    packets = []
    for i, when in enumerate(attack_times):
        n_frames = int(rng.integers(8, 20))
        broadcast = i % 3 != 2
        for k in range(n_frames):
            epoch = when.timestamp() + k * 0.09
            target = BROADCAST if broadcast else CLIENTS[i % len(CLIENTS)]
            reason = 7 if broadcast else 1
            frame = build_deauth_frame(_mac_bytes(ATTACKER_MAC), _mac_bytes(target),
                                       _mac_bytes(AP_BSSID), reason=reason,
                                       disassoc=(k % 7 == 6))
            packets.append((epoch, _radiotap(int(rng.integers(-70, -35)), 2437) + frame))

    packets.sort(key=lambda p: p[0])
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535,
                             DLT_IEEE802_11_RADIOTAP))
        for epoch, data in packets:
            seconds = int(epoch)
            micro = int(round((epoch - seconds) * 1_000_000))
            if micro >= 1_000_000:
                seconds += 1
                micro -= 1_000_000
            fh.write(struct.pack("<IIII", seconds, micro, len(data), len(data)))
            fh.write(data)


def _write_pcapng(path: Path, attack_times, rng) -> None:
    """The same evidence in pcapng form, to exercise that reader."""
    blocks = bytearray()

    # Section Header Block
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    blocks += _ng_block(0x0A0D0D0A, shb_body)

    # Interface Description Block: radiotap, microsecond resolution
    idb_body = struct.pack("<HHI", DLT_IEEE802_11_RADIOTAP, 0, 65535)
    idb_body += struct.pack("<HH", 9, 1) + bytes([6, 0, 0, 0])  # if_tsresol = 1e-6
    idb_body += struct.pack("<HH", 0, 0)
    blocks += _ng_block(0x00000001, idb_body)

    for i, when in enumerate(attack_times):
        for k in range(6):
            epoch_us = int((when.timestamp() + k * 0.11) * 1_000_000)
            frame = build_deauth_frame(_mac_bytes(ATTACKER_MAC), _mac_bytes(BROADCAST),
                                       _mac_bytes(AP_BSSID), reason=7)
            data = _radiotap(-50, 2437) + frame
            epb = struct.pack("<IIIII", 0, epoch_us >> 32, epoch_us & 0xFFFFFFFF,
                              len(data), len(data))
            epb += data + b"\x00" * ((-len(data)) % 4)
            blocks += _ng_block(0x00000006, epb)

    path.write_bytes(bytes(blocks))


def _ng_block(block_type: int, body: bytes) -> bytes:
    total = len(body) + 12
    return (struct.pack("<II", block_type, total) + body
            + struct.pack("<I", total))


def _write_kismet(path: Path, attack_times, rng) -> None:
    if path.exists():
        path.unlink()
    con = sqlite3.connect(path)
    try:
        con.execute("CREATE TABLE KISMET (kismet_version TEXT, db_version INT, "
                    "db_module TEXT)")
        con.execute("INSERT INTO KISMET VALUES ('2023-07-R1', 8, 'kismetlog')")
        con.execute("CREATE TABLE devices (first_time INT, last_time INT, devkey TEXT, "
                    "phyname TEXT, devmac TEXT, device BLOB)")
        con.execute("CREATE TABLE packets (ts_sec INT, ts_usec INT, phyname TEXT, "
                    "sourcemac TEXT, destmac TEXT, transmitmac TEXT, frequency REAL, "
                    "devkey TEXT, lat REAL, lon REAL, packet_len INT, signal INT, "
                    "datasource TEXT, dlt INT, packet BLOB, error INT, tags TEXT, "
                    "datarate REAL, hash INT, packetid INT)")
        con.execute("CREATE TABLE alerts (ts_sec INT, ts_usec INT, phyname TEXT, "
                    "devmac TEXT, lat REAL, lon REAL, header TEXT, json BLOB)")

        for i, when in enumerate(attack_times):
            for k in range(5):
                epoch = when.timestamp() + k * 0.12
                frame = build_deauth_frame(_mac_bytes(ATTACKER_MAC),
                                           _mac_bytes(BROADCAST),
                                           _mac_bytes(AP_BSSID), reason=7)
                data = _radiotap(-48, 2437) + frame
                con.execute(
                    "INSERT INTO packets VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (int(epoch), int((epoch % 1) * 1e6), "IEEE802.11", ATTACKER_MAC,
                     BROADCAST, ATTACKER_MAC, 2437.0, "", 0, 0, len(data), -48,
                     "wlan0mon", DLT_IEEE802_11_RADIOTAP, data, 0, "", 1.0, 0, i * 10 + k))

            payload = json.dumps({
                "kismet.alert.text": f"Deauthenticate/Disassociate flood on {AP_BSSID}",
                "kismet.alert.source_mac": ATTACKER_MAC,
                "kismet.alert.dest_mac": BROADCAST,
            })
            con.execute("INSERT INTO alerts VALUES (?,?,?,?,?,?,?,?)",
                        (int(when.timestamp()), 0, "IEEE802.11", AP_BSSID, 0, 0,
                         "DEAUTHFLOOD", payload))
        con.commit()
    finally:
        con.close()


def _write_airodump(path: Path, camera_times, rng) -> None:
    first = (camera_times[0] - timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "",
        "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, "
        "Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key",
        f"{AP_BSSID.upper()}, {first}, "
        f"{camera_times[-1].strftime('%Y-%m-%d %H:%M:%S')}, 6, 130, WPA2, CCMP, PSK, "
        f"-38, 4211, 0, 0.0.0.0, 9, HomeNet-5, ",
        "",
        "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, "
        "Probed ESSIDs",
    ]
    for i, when in enumerate(camera_times):
        client = CLIENTS[i % len(CLIENTS)]
        lines.append(
            f"{client.upper()}, {first}, {when.strftime('%Y-%m-%d %H:%M:%S')}, "
            f"-{45 + i % 20}, {200 + i * 13}, {AP_BSSID.upper()}, HomeNet-5")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_nzyme(path: Path, attack_times, rng) -> None:
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["timestamp", "subtype", "transmitter", "destination",
                         "bssid", "reason_code", "channel", "signal_strength", "ssid"])
        for i, when in enumerate(attack_times):
            for k in range(3):
                stamp = (when + timedelta(seconds=k * 0.2)).isoformat(
                    timespec="milliseconds")
                writer.writerow([stamp, "deauthentication", ATTACKER_MAC, BROADCAST,
                                 AP_BSSID, 7, 6, -47, "HomeNet-5"])


def _radiotap(signal_dbm: int, freq_mhz: int) -> bytes:
    """A radiotap header carrying flags, rate, channel and signal."""
    present = (1 << 1) | (1 << 2) | (1 << 3) | (1 << 5)
    fields = struct.pack("<BB", 0x00, 0x02)                    # flags, rate
    fields += struct.pack("<HH", freq_mhz, 0x00A0)             # channel freq + flags
    fields += struct.pack("<b", signal_dbm)                    # dBm antenna signal
    length = 8 + len(fields)
    return struct.pack("<BBHI", 0, 0, length, present) + fields


def _mac_bytes(mac: str) -> bytes:
    return bytes(int(part, 16) for part in norm_mac(mac).split(":"))


if __name__ == "__main__":
    sys.exit(run_self_test())
