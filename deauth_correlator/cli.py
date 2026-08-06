"""Command-line interface.

    deauth-correlator --opnsense-log dhcp.log --wifi-capture cap-01.cap \
                      --camera-events passes.csv --outdir case-2026-0714

    deauth-correlator --gui
    deauth-correlator --self-test
    deauth-correlator camera probe --camera-host 192.168.1.50 --camera-user forensics
    deauth-correlator camera watch --camera-host 192.168.1.50 --camera-user forensics \
                      --out camera_events.csv
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__, __tool_name__
from .config import AppConfig
from .correlate import run_analysis
from .csvout import write_correlation_csv, write_events_csv, write_incidents_csv
from .events import to_frame
from .hashing import Provenance, record_file, sha256_file
from .parsers import ParseContext, ParseError, describe_registry, parse_path
from .report import write_manifest, write_report
from .stats import DEFAULT_ALPHA, DEFAULT_TRIALS, DEFAULT_WINDOW_S
from .timeutil import DEFAULT_TZ, TimeContext

BANNER = f"{__tool_name__} {__version__} - read-only wireless disruption correlator"

EPILOG = """\
This tool only reads. It never transmits 802.11 frames, never injects, and never
attacks. Camera access is read-only against a camera you own.

Typical workflow:
  1. Export the OPNsense DHCP log (see README section "Exporting OPNsense logs").
  2. Capture 802.11 with a monitor-mode adapter:
       sudo airodump-ng --write case0714 --output-format pcap,csv wlan0mon
  3. Build the camera event list, either by hand as a CSV or with:
       deauth-correlator camera watch --camera-host <ip> --camera-user <account>
  4. Run the analysis, then build the evidence bundle with --evidence-bundle.
"""


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    if argv and argv[0] == "camera":
        return _camera_command(argv[1:])

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_parsers:
        return _list_parsers()
    if args.check_runtime:
        return _check_runtime()
    if args.self_test:
        from .selftest import run_self_test
        return run_self_test(keep=args.self_test_dir, verbose=not args.quiet)
    if args.gui:
        from .gui.app import launch
        return launch(_config_from_args(args))

    config = _config_from_args(args)
    problems = config.validate()
    fatal = [p for p in problems if "No input files" in p
             or "nothing to correlate" in p
             or "must be" in p]
    if fatal:
        for problem in fatal:
            print(f"error: {problem}", file=sys.stderr)
        print("\nRun with --help for usage, or --gui for the graphical interface.",
              file=sys.stderr)
        return 2

    return run_cli_analysis(config, args, verbose=not args.quiet)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="deauth-correlator",
        description=BANNER,
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter)

    inputs = parser.add_argument_group("evidence inputs (any subset)")
    inputs.add_argument("--opnsense-log", action="append", default=[], metavar="PATH",
                        help="OPNsense DHCP/system log (dnsmasq, Kea or ISC dhcpd). "
                             "Repeatable.")
    inputs.add_argument("--wifi-capture", action="append", default=[], metavar="PATH",
                        help="802.11 monitor-mode evidence: a .cap/.pcap/.pcapng from "
                             "airodump-ng, a Kismet .kismet database, an airodump CSV, "
                             "or an nzyme/tshark frame CSV. Repeatable.")
    inputs.add_argument("--camera-events", action="append", default=[], metavar="PATH",
                        help="Camera events: a CSV of timestamp,plate,make,model,notes "
                             "or a directory of clip files. Repeatable.")
    inputs.add_argument("--parser", default=None, metavar="ID",
                        help="Force a parser for every input instead of detecting it. "
                             "See --list-parsers.")
    inputs.add_argument("--list-parsers", action="store_true",
                        help="List the available parsers and exit.")

    timing = parser.add_argument_group("time handling")
    timing.add_argument("--tz", default=DEFAULT_TZ, metavar="ZONE",
                        help=f"IANA timezone for all displayed times "
                             f"(default: {DEFAULT_TZ}).")
    timing.add_argument("--log-year", type=int, default=None, metavar="YEAR",
                        help="Year to assume for syslog lines that carry no year. "
                             "Inferred from the file's modification time otherwise.")
    timing.add_argument("--assume-offset", default="", metavar="OFF",
                        help="UTC offset to attach to timestamps that have none, e.g. "
                             "-04:00. Defaults to the --tz rules for that date.")
    timing.add_argument("--camera-clock-offset", type=float, default=0.0,
                        metavar="SECONDS",
                        help="Seconds to add to every camera timestamp to correct a "
                             "known camera clock error. Measure it with "
                             "'camera probe'.")
    timing.add_argument("--clip-time-from", choices=("auto", "filename", "mtime"),
                        default="auto",
                        help="Where clip timestamps come from (default: auto - "
                             "filename when recognizable, otherwise file mtime).")

    correlation = parser.add_argument_group("correlation")
    correlation.add_argument("--window", type=float, default=DEFAULT_WINDOW_S,
                             metavar="SECONDS",
                             help=f"Coincidence window, plus and minus "
                                  f"(default: {DEFAULT_WINDOW_S:g}).")
    correlation.add_argument("--alpha", type=float, default=DEFAULT_ALPHA,
                             help=f"Significance threshold (default: {DEFAULT_ALPHA}).")
    correlation.add_argument("--trials", type=int, default=DEFAULT_TRIALS,
                             help=f"Permutation trials (default: {DEFAULT_TRIALS}).")
    correlation.add_argument("--no-sensitivity", action="store_true",
                             help="Skip the multi-window sensitivity table.")
    correlation.add_argument("--reassoc-window", type=float, default=120.0,
                             metavar="SECONDS",
                             help="A repeat DHCP handshake within this long of the "
                                  "previous one is a client drop (default: 120).")
    correlation.add_argument("--handshake-window", type=float, default=10.0,
                             metavar="SECONDS",
                             help="Lease messages within this long of each other are "
                                  "one association episode (default: 10).")
    correlation.add_argument("--incident-gap", type=float, default=10.0,
                             metavar="SECONDS",
                             help="Disruption events within this long of each other "
                                  "count as one incident (default: 10).")
    correlation.add_argument("--camera-dedupe", type=float, default=2.0,
                             metavar="SECONDS",
                             help="Camera events this close together from different "
                                  "sources are treated as one pass recorded twice "
                                  "(default: 2). Use 0 to disable.")
    correlation.add_argument("--flood-window", type=float, default=10.0,
                             metavar="SECONDS", help="Flood detection window "
                                                     "(default: 10).")
    correlation.add_argument("--flood-threshold", type=int, default=5, metavar="N",
                             help="Frames within the flood window that constitute a "
                                  "flood (default: 5).")

    case = parser.add_argument_group("case identification")
    case.add_argument("--case", default="", metavar="NUMBER", help="Case number.")
    case.add_argument("--operator", default="", metavar="NAME",
                      help="Name of the person running the analysis.")
    case.add_argument("--agency", default="", metavar="NAME",
                      help="Agency or organization.")
    case.add_argument("--case-notes", default="", metavar="TEXT",
                      help="Free-text note carried into the report header.")

    output = parser.add_argument_group("output")
    output.add_argument("--outdir", default="output", metavar="DIR",
                        help="Directory for correlation.csv, report.md and "
                             "timeline.png (default: output).")
    output.add_argument("--evidence-bundle", nargs="?", const="", default=None,
                        metavar="DIR",
                        help="Also build a numbered evidence bundle with verified "
                             "copies of the inputs. Optionally give a directory.")
    output.add_argument("--zip", dest="zip_bundle", action="store_true",
                        help="Zip the evidence bundle and hash the archive.")
    output.add_argument("--no-plot", action="store_true",
                        help="Skip timeline.png.")
    output.add_argument("-q", "--quiet", action="store_true",
                        help="Print only the one-line verdict.")

    other = parser.add_argument_group("other modes")
    other.add_argument("--gui", action="store_true",
                       help="Launch the graphical interface.")
    other.add_argument("--self-test", action="store_true",
                       help="Generate synthetic fixtures, run the whole pipeline over "
                            "them and check the results.")
    other.add_argument("--check-runtime", action="store_true",
                       help="Report which optional subsystems can be imported (the "
                            "graphical interface, the SciPy statistics backend, the "
                            "camera support). Needs no display. In a standalone build "
                            "this exits non-zero when something that ships in the "
                            "bundle cannot be loaded.")
    other.add_argument("--self-test-dir", default=None, metavar="DIR",
                       help="Keep the self-test fixtures in this directory.")
    other.add_argument("--version", action="version",
                       version=f"{__tool_name__} {__version__}")
    return parser


def _config_from_args(args) -> AppConfig:
    return AppConfig(
        case_number=args.case,
        operator=args.operator,
        agency=args.agency,
        case_notes=args.case_notes,
        opnsense_logs=list(args.opnsense_log),
        wifi_captures=list(args.wifi_capture),
        camera_events=list(args.camera_events),
        timezone=args.tz,
        log_year=args.log_year,
        assume_offset=args.assume_offset,
        camera_clock_offset_s=args.camera_clock_offset,
        clip_time_from=args.clip_time_from,
        window_s=args.window,
        alpha=args.alpha,
        trials=args.trials,
        sensitivity=not args.no_sensitivity,
        handshake_window_s=args.handshake_window,
        reassoc_window_s=args.reassoc_window,
        incident_gap_s=args.incident_gap,
        camera_dedupe_s=args.camera_dedupe,
        flood_window_s=args.flood_window,
        flood_threshold=args.flood_threshold,
        outdir=args.outdir,
        evidence_bundle=args.evidence_bundle is not None,
        zip_bundle=args.zip_bundle,
    )


def load_evidence(config: AppConfig, forced_parser: str | None = None,
                  log=print) -> tuple:
    """Parse every configured input into one event frame plus custody records."""
    time_ctx = TimeContext(config.timezone, config.log_year,
                           config.assume_offset or None)
    rows: list[dict] = []
    records = []
    warnings: list[str] = []

    roles = [
        ("opnsense-log", config.opnsense_logs, 0.0),
        ("wifi-capture", config.wifi_captures, 0.0),
        ("camera-events", config.camera_events, config.camera_clock_offset_s),
    ]

    for role, paths, clock_offset in roles:
        for raw_path in paths:
            path = Path(raw_path).expanduser()
            if not path.exists():
                warnings.append(f"{path}: not found; skipped.")
                log(f"  ! {path}: not found")
                continue

            # Hash before a single byte is parsed. SAFETY.md, the report and the
            # evidence bundle's cover sheet all tell the reader the hash was
            # taken before the file was read, and the point of that sentence is
            # that the hash bounds exactly what was analysed. Sniffing the
            # format and then parsing opens the file twice, so the digest has to
            # be taken ahead of both.
            digest = None
            if path.is_file():
                try:
                    digest = sha256_file(path)
                except OSError as exc:
                    warnings.append(f"{path.name}: could not be read - {exc}")
                    log(f"  ! {path.name}: could not be read - {exc}")
                    continue

            ctx = ParseContext(
                time=time_ctx,
                year_hint=config.log_year,
                clock_offset_s=clock_offset,
                options={"clip_time_from": config.clip_time_from},
            )
            try:
                parsed, parser = parse_path(path, ctx, role, forced_parser)
            except ParseError as exc:
                warnings.append(str(exc))
                log(f"  ! {exc}")
                continue
            except Exception as exc:
                warnings.append(f"{path.name}: parser failed - "
                                f"{exc.__class__.__name__}: {exc}")
                log(f"  ! {path.name}: parser failed - {exc}")
                continue

            rows.extend(parsed)
            warnings.extend(ctx.warnings)
            if path.is_dir():
                record = _directory_record(path, role, parser.id, len(parsed))
            else:
                record = record_file(path, role=role, parser=parser.id,
                                     rows=len(parsed), sha256=digest)
            records.append(record)
            log(f"  + {path.name}: {len(parsed)} event(s) via {parser.name}")

    warnings.extend(time_ctx.year_inferences)
    warnings.extend(time_ctx.dst_warnings())
    return to_frame(rows), records, warnings


def run_cli_analysis(config: AppConfig, args, verbose: bool = True) -> int:
    log = print if verbose else (lambda *a, **k: None)

    log(BANNER)
    log("\nReading evidence:")
    events, records, warnings = load_evidence(config, args.parser, log)

    if events.empty:
        print("error: no events were parsed from any input file.", file=sys.stderr)
        for warning in warnings:
            print(f"  {warning}", file=sys.stderr)
        return 2

    provenance = Provenance.collect(
        operator=config.operator, case_number=config.case_number,
        agency=config.agency, tz_name=config.timezone, notes=config.case_notes)

    log("\nAnalyzing...")
    analysis = run_analysis(events, config.analysis_dict(), inputs=records,
                            warnings=warnings, provenance=provenance)

    outdir = Path(config.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    written = []
    written.append(write_correlation_csv(analysis.matches, outdir / "correlation.csv"))
    written.append(write_events_csv(analysis.events, outdir / "events.csv"))
    written.append(write_incidents_csv(analysis.incidents, outdir / "incidents.csv"))
    written.append(write_report(analysis, outdir / "report.md"))

    if not args.no_plot:
        try:
            from .plot import write_timeline
            written.append(write_timeline(analysis, outdir / "timeline.png"))
        except Exception as exc:
            print(f"warning: timeline could not be rendered: {exc}", file=sys.stderr)

    output_records = [record_file(p, role="output") for p in written if p.exists()]
    write_manifest(analysis, outdir / "MANIFEST.json", outputs=output_records)

    if verbose:
        _print_summary(analysis, outdir, written)

    if config.evidence_bundle:
        from .evidence import build_bundle
        bundle_root = (Path(args.evidence_bundle) if args.evidence_bundle
                       else outdir / f"evidence_{_slug(config.case_number)}")
        log(f"\nBuilding evidence bundle in {bundle_root} ...")
        result = build_bundle(analysis, bundle_root, copy_inputs=True,
                              make_zip=config.zip_bundle,
                              progress=(lambda m: log(f"  . {m}")) if verbose else None)
        log(result.summary())

    print()
    print(analysis.one_line_verdict())
    return 0 if analysis.verdict.found else 1


def _print_summary(analysis, outdir: Path, written: list) -> None:
    s = analysis.stats
    print(f"\nAnalysis period: {analysis.obs_start_local:%Y-%m-%d %H:%M:%S} to "
          f"{analysis.obs_end_local:%Y-%m-%d %H:%M:%S} "
          f"({analysis.observation_hours:.2f} h, {analysis.config['timezone']})")
    print(f"Camera events:   {s.n_camera}")
    print(f"Disruptions:     {int((analysis.events['category'] == 'disruption').sum())} "
          f"events in {len(analysis.incidents)} incidents")
    if analysis.floods.total_frames:
        print(f"Deauth frames:   {analysis.floods.total_frames} "
              f"({analysis.floods.broadcast_frames} broadcast) in "
              f"{len(analysis.floods.floods)} flood(s)")
        top = sorted(analysis.floods.by_source.items(), key=lambda kv: -kv[1])[:3]
        for mac, count in top:
            print(f"                 {mac}: {count} frames")
    print(f"\nCoincidences:    {s.n_coincident}/{s.n_camera} within "
          f"+/-{s.window_s:g}s  (baseline {s.baseline_rate * 100:.1f}%, "
          f"expected {s.expected_by_chance:.1f})")
    print("Rate ratio:      "
          + ("not applicable (no disruptions in either period)"
             if s.rate_ratio != s.rate_ratio else f"{s.rate_ratio:.2f}x"))
    print(f"p-values:        binomial {s.binom_p:.4g} | permutation {s.perm_p:.4g} | "
          f"Fisher {s.fisher_p:.4g}")

    if analysis.period_notes:
        print("\nNotes on the analysis period:")
        for note in analysis.period_notes:
            print(f"  ! {note}")

    if analysis.lag_scan.suspicious:
        print("\n*** CHECK THE CLOCKS ***")
        for line in _wrap(analysis.lag_scan.explanation(), 78):
            print(f"  {line}")
        print("  This is a diagnostic, not a finding. Correct the clock, re-export,")
        print("  and re-run; do not report a correlation at a shifted offset.")

    print("\nWritten:")
    for path in written:
        print(f"  {path}")
    print(f"  {outdir / 'MANIFEST.json'}")


def _camera_command(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="deauth-correlator camera",
        description="Read-only camera operations (TP-Link Tapo C100 and other ONVIF "
                    "cameras).",
        epilog="The password is read from DEAUTH_CORRELATOR_CAMPASS if set, so it "
               "need not appear in shell history.")
    parser.add_argument("action", choices=("probe", "snapshot", "watch", "help"),
                        help="probe: reachability and clock check. snapshot: save one "
                             "frame. watch: record motion events to a CSV. help: how "
                             "to set up the camera account.")
    parser.add_argument("--camera-host", default="", metavar="IP")
    parser.add_argument("--camera-user", default="", metavar="NAME",
                        help="The Tapo Camera Account username, not the cloud login.")
    parser.add_argument("--camera-pass", default=None, metavar="SECRET",
                        help="Prefer the DEAUTH_CORRELATOR_CAMPASS environment "
                             "variable to avoid shell history.")
    parser.add_argument("--onvif-port", type=int, default=2020)
    parser.add_argument("--rtsp-port", type=int, default=554)
    parser.add_argument("--stream", choices=("hd", "sd"), default="hd")
    parser.add_argument("--out", default="camera_events.csv", metavar="PATH",
                        help="watch: CSV to append motion events to.")
    parser.add_argument("--exhibits", default="exhibits", metavar="DIR",
                        help="watch: directory for snapshot exhibits.")
    parser.add_argument("--no-snapshots", action="store_true",
                        help="watch: do not save a still for each event.")
    parser.add_argument("--min-gap", type=float, default=5.0, metavar="SECONDS",
                        help="watch: ignore repeat motion within this long (default: 5).")
    parser.add_argument("--tz", default=DEFAULT_TZ)
    parser.add_argument("--duration", type=float, default=0.0, metavar="SECONDS",
                        help="watch: stop after this long (default: until Ctrl-C).")
    args = parser.parse_args(argv)

    from .camera import CameraConfig, MotionRecorder, credentials_help, probe, snapshot

    if args.action == "help":
        print(credentials_help())
        return 0

    if not args.camera_host:
        print("error: --camera-host is required.", file=sys.stderr)
        return 2

    password = (args.camera_pass
                if args.camera_pass is not None
                else os.environ.get("DEAUTH_CORRELATOR_CAMPASS", ""))
    config = CameraConfig(host=args.camera_host, username=args.camera_user,
                          password=password, onvif_port=args.onvif_port,
                          rtsp_port=args.rtsp_port, stream=args.stream)

    if args.action == "probe":
        result = probe(config)
        for line in result.summary_lines():
            print(line)
        if result.stream_uri:
            print(f"Stream URI reported by the camera: {result.stream_uri}")
        print(f"RTSP URL to use: {config.rtsp_url(redact=True)}")
        return 0 if result.reachable else 1

    if args.action == "snapshot":
        from datetime import datetime
        target = Path(args.exhibits) / (
            f"snapshot_{datetime.now():%Y%m%d_%H%M%S}.jpg")
        try:
            written = snapshot(config, target)
        except Exception as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(f"Saved {written}")
        return 0

    # watch
    import time
    recorder = MotionRecorder(
        config, args.out,
        exhibits_dir=None if args.no_snapshots else args.exhibits,
        tz_name=args.tz, min_gap_s=args.min_gap,
        save_snapshots=not args.no_snapshots,
        on_event=lambda when, note, shot: print(f"  {when:%Y-%m-%d %H:%M:%S}  {note}"))
    print(f"Recording motion events from {args.camera_host} to {args.out}")
    print("Press Ctrl-C to stop.\n")
    recorder.start()
    started = time.monotonic()
    try:
        while recorder.status.running:
            time.sleep(0.5)
            if args.duration and time.monotonic() - started >= args.duration:
                break
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        recorder.stop()

    print(f"\n{recorder.status.events_written} event(s) written to {args.out}")
    if recorder.status.snapshots_saved:
        print(f"{recorder.status.snapshots_saved} snapshot(s) in {args.exhibits}")
    if recorder.status.last_error:
        print(f"Last error: {recorder.status.last_error}", file=sys.stderr)
        return 1
    return 0


def _check_runtime() -> int:
    """Report which optional subsystems can actually be loaded.

    A standalone build can pass ``--version`` and the whole self-test while its
    graphical interface is dead, because neither touches Tkinter. PyInstaller
    failing to collect the Tk libraries is a common and completely silent
    packaging failure, and the frozen GUI executable cannot be used to detect it
    without a display. This performs the imports directly, needs no display, and
    is what packaging/build.py runs to gate a release.
    """
    frozen = bool(getattr(sys, "frozen", False))

    subsystems = [
        ("graphical interface", "tkinter",
         "the --gui option and the packaged GUI executable"),
        ("SciPy statistics backend", "scipy",
         "optional; without it the exact pure-Python tests are used instead"),
        ("camera ONVIF support", "requests",
         "the camera probe and the motion recorder"),
        ("camera snapshots", "cv2",
         "grabbing a still frame over RTSP"),
        ("timezone database", "tzdata",
         "on Windows, where the system has none"),
    ]
    # In a frozen build these were bundled deliberately, so a failure to import
    # one means the build is broken rather than that the user chose not to
    # install it. Outside a frozen build they are genuinely optional.
    required_when_frozen = {"tkinter"}

    print(f"{BANNER}\n")
    print(f"Running {'from a standalone build' if frozen else 'from a Python install'}"
          f" on {sys.platform}, Python {sys.version.split()[0]}\n")

    broken = []
    for label, module, purpose in subsystems:
        try:
            __import__(module)
            status = "available"
        except Exception as exc:
            status = f"UNAVAILABLE ({exc.__class__.__name__})"
            if frozen and module in required_when_frozen:
                broken.append((label, module, exc))
        print(f"  {label:26s} {status}")
        print(f"  {'':26s} {purpose}")

    if broken:
        print("\nThis build is incomplete. The following ship inside the bundle and "
              "should always import:")
        for label, module, exc in broken:
            print(f"  - {label} ({module}): {exc}")
        return 1

    print("\nEverything expected in this build loaded.")
    return 0


def _list_parsers() -> int:
    print(BANNER)
    print("\nAvailable parsers:\n")
    for entry in describe_registry():
        print(f"  {entry['id']:<16} {entry['name']}")
        if entry["extensions"]:
            print(f"  {'':<16} extensions: {entry['extensions']}")
        print(f"  {'':<16} {entry['describes']}")
        print()
    print("Force one with --parser <id>. Detection is automatic otherwise.")
    return 0


def _directory_record(path: Path, role: str, parser_id: str, rows: int):
    """Custody record for a directory input: hash the listing, not the tree."""
    from .hashing import FileRecord, sha256_bytes
    from datetime import datetime, timezone as tz

    entries = sorted(p for p in path.rglob("*") if p.is_file())
    listing = "\n".join(f"{p.relative_to(path).as_posix()}\t{p.stat().st_size}"
                        for p in entries)
    return FileRecord(
        path=str(path.resolve()),
        role=role,
        sha256=sha256_bytes(listing.encode("utf-8")),
        size_bytes=sum(p.stat().st_size for p in entries),
        modified_utc=datetime.fromtimestamp(path.stat().st_mtime, tz=tz.utc)
        .isoformat(timespec="seconds"),
        parser=parser_id,
        rows=rows,
        note=f"directory of {len(entries)} file(s); the hash covers the file listing "
             f"and sizes, not the contents of each clip",
    )


def _wrap(text: str, width: int) -> list[str]:
    import textwrap
    return textwrap.wrap(text, width) or [""]


def _slug(text: str) -> str:
    cleaned = "".join(c if c.isalnum() or c in "-_" else "_" for c in text.strip())
    return cleaned or "case"


if __name__ == "__main__":
    sys.exit(main())
