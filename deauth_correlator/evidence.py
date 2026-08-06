"""Evidence bundle builder.

Produces a numbered folder that can be handed to a detective or attached to a
filing whole. Everything needed to check the work is inside it: the report, the
machine-readable tables, the figure, verified copies of the original inputs, and
a manifest tying them together by hash.

Copies are hash-verified after writing. A copy whose hash does not match the
original is reported rather than silently included - a bundle that quietly
contains a corrupted exhibit is worse than one that fails loudly.
"""

from __future__ import annotations

import shutil
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from . import __version__, __tool_name__
from .csvout import write_correlation_csv, write_events_csv, write_incidents_csv
from .hashing import CustodyLog, FileRecord, record_file, verify_copy
from .plot import write_timeline
from .report import write_manifest, write_report

LAYOUT = {
    "report": "01_report.md",
    "correlation": "02_correlation.csv",
    "timeline": "03_timeline.png",
    "events": "04_all_events.csv",
    "incidents": "05_disruption_incidents.csv",
    "inputs": "06_source_files",
    "exhibits": "07_exhibits",
    "manifest": "00_MANIFEST.json",
    "manifest_text": "00_MANIFEST.txt",
    "custody": "chain_of_custody.log",
    "readme": "00_READ_ME_FIRST.txt",
}


@dataclass
class BundleResult:
    root: Path
    files: list = field(default_factory=list)         # list[FileRecord]
    zip_path: Path | None = None
    zip_sha256: str = ""
    problems: list = field(default_factory=list)
    custody: CustodyLog | None = None

    def summary(self) -> str:
        lines = [f"Evidence bundle: {self.root}",
                 f"{len(self.files)} file(s) written."]
        if self.zip_path:
            lines.append(f"Archive: {self.zip_path}")
            lines.append(f"Archive SHA-256: {self.zip_sha256}")
        if self.problems:
            lines.append("Problems:")
            lines.extend(f"  - {p}" for p in self.problems)
        return "\n".join(lines)


def build_bundle(analysis, root: str | Path, copy_inputs: bool = True,
                 exhibits: list | None = None, make_zip: bool = False,
                 progress=None) -> BundleResult:
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)

    # A bundle is a snapshot of one analysis, so a rebuild has to start from
    # nothing. Left alone, a second run into the same directory kept the first
    # run's copies alongside the new ones under _2 names and appended its
    # custody log to the old one - a handover folder holding evidence from a
    # superseded analysis, with no way to tell which copy belonged to which.
    problems = _clear_previous_bundle(root)
    custody = CustodyLog(root / LAYOUT["custody"])
    result = BundleResult(root=root, custody=custody)
    result.problems.extend(problems)

    def step(message: str) -> None:
        custody.add("bundle", message)
        if progress:
            progress(message)

    step(f"Bundle started by {__tool_name__} {__version__}")
    case = analysis.provenance.case_number or "(no case number)"
    step(f"Case {case}; operator {analysis.provenance.operator or '(not supplied)'}")

    # Core outputs.
    step("Writing report.md")
    write_report(analysis, root / LAYOUT["report"],
                 timeline_name=LAYOUT["timeline"], csv_name=LAYOUT["correlation"])

    step("Writing correlation.csv")
    write_correlation_csv(analysis.matches, root / LAYOUT["correlation"])

    step("Writing the full event and incident tables")
    write_events_csv(analysis.events, root / LAYOUT["events"])
    write_incidents_csv(analysis.incidents, root / LAYOUT["incidents"])

    step("Rendering timeline.png")
    try:
        write_timeline(analysis, root / LAYOUT["timeline"])
    except Exception as exc:
        result.problems.append(f"timeline could not be rendered: {exc}")
        step(f"Timeline failed: {exc}")

    # Verified copies of the sources.
    if copy_inputs and analysis.inputs:
        inputs_dir = root / LAYOUT["inputs"]
        inputs_dir.mkdir(exist_ok=True)
        for record in analysis.inputs:
            source = Path(record.path)
            if not source.exists():
                result.problems.append(
                    f"source file no longer present, not copied: {record.path}")
                step(f"MISSING source: {record.path}")
                continue
            target = _unique(inputs_dir / source.name)
            try:
                if source.is_dir():
                    shutil.copytree(source, target, dirs_exist_ok=True)
                    step(f"Copied directory {source.name}")
                    continue
                shutil.copy2(source, target)
            except OSError as exc:
                result.problems.append(f"could not copy {source.name}: {exc}")
                step(f"Copy failed for {source.name}: {exc}")
                continue
            if verify_copy(record, target):
                step(f"Copied and hash-verified {source.name} "
                     f"(sha256 {record.sha256[:16]}...)")
            else:
                result.problems.append(
                    f"copy of {source.name} does not match the original hash - "
                    f"it was left in place but must not be relied on")
                step(f"HASH MISMATCH after copying {source.name}")

    # Exhibits (camera snapshots and anything the operator attached).
    if exhibits:
        exhibits_dir = root / LAYOUT["exhibits"]
        exhibits_dir.mkdir(exist_ok=True)
        for item in exhibits:
            source = Path(item)
            if not source.exists():
                result.problems.append(f"exhibit not found: {item}")
                continue
            target = _unique(exhibits_dir / source.name)
            try:
                shutil.copy2(source, target)
                step(f"Attached exhibit {source.name} "
                     f"(sha256 {record_file(target, 'exhibit').sha256[:16]}...)")
            except OSError as exc:
                result.problems.append(f"could not attach {source.name}: {exc}")

    # Hash everything written, then the manifest last so it can list them.
    written = _collect_records(root, exclude={LAYOUT["manifest"], LAYOUT["custody"]})
    step("Writing MANIFEST.json")
    write_manifest(analysis, root / LAYOUT["manifest"], outputs=written)
    (root / LAYOUT["readme"]).write_text(_read_me(analysis, result), encoding="utf-8")

    result.files = _collect_records(root)

    if make_zip:
        step("Creating the archive")
        result.zip_path, result.zip_sha256 = _zip_bundle(root)
        step(f"Archive sha256 {result.zip_sha256}")

    step("Bundle complete")
    return result


def _clear_previous_bundle(root: Path) -> list[str]:
    """Remove a previous bundle from ``root`` so a rebuild starts clean.

    Only the files and directories this module creates are removed, and only
    when the directory actually looks like one of our bundles. A directory
    holding anything else is left completely alone and reported instead - the
    operator may have pointed at the wrong path, and deleting their files
    because of a typo would be far worse than refusing.
    """
    known = {LAYOUT[key] for key in LAYOUT}
    existing = [p for p in root.iterdir()] if root.is_dir() else []
    if not existing:
        return []

    ours = {p.name for p in existing} & known
    if not ours:
        return [f"the bundle directory {root} already contains files this tool did not "
                f"write, so nothing was removed. Point --evidence-bundle at an empty "
                f"directory, or move the existing contents aside."]

    foreign = [p.name for p in existing if p.name not in known]
    for path in existing:
        if path.name not in known:
            continue
        try:
            shutil.rmtree(path) if path.is_dir() else path.unlink()
        except OSError as exc:
            return [f"could not remove the previous bundle at {root}: {exc}"]

    notes = [f"a previous bundle in {root} was replaced; its files were removed so the "
             f"copies and the chain-of-custody log describe this run only."]
    if foreign:
        notes.append(f"left in place because this tool did not write them: "
                     f"{', '.join(sorted(foreign))}")
    return notes


def _collect_records(root: Path, exclude: set | None = None) -> list[FileRecord]:
    exclude = exclude or set()
    records = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if relative in exclude or path.suffix == ".zip":
            continue
        records.append(record_file(path, role=f"bundle output ({relative})"))
    return records


def _zip_bundle(root: Path) -> tuple[Path, str]:
    from .hashing import sha256_file
    archive = root.parent / f"{root.name}.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(root.rglob("*")):
            if path.is_file():
                zf.write(path, path.relative_to(root.parent).as_posix())
    return archive, sha256_file(archive)


def _unique(path: Path) -> Path:
    """Never silently overwrite an exhibit that is already in the bundle."""
    if not path.exists():
        return path
    stem, suffix = path.stem, path.suffix
    for n in range(2, 1000):
        candidate = path.with_name(f"{stem}_{n}{suffix}")
        if not candidate.exists():
            return candidate
    return path


def _read_me(analysis, result: BundleResult) -> str:
    a = analysis
    lines = [
        f"{__tool_name__} {__version__} - evidence bundle",
        "=" * 66,
        "",
        f"Case:      {a.provenance.case_number or '(not supplied)'}",
        f"Prepared:  {a.provenance.generated_utc} UTC",
        f"Operator:  {a.provenance.operator or '(not supplied)'}",
        f"Timezone:  {a.config.get('timezone')} (all local times in this bundle)",
        "",
        "FINDING",
        "-" * 66,
        a.verdict.label,
        a.verdict.headline,
        "",
        "WHAT IS IN THIS FOLDER",
        "-" * 66,
        f"{LAYOUT['readme']:<28} this file",
        f"{LAYOUT['manifest']:<28} SHA-256 hashes and full parameters, machine-readable",
        f"{LAYOUT['manifest_text']:<28} the same hashes as plain text, for reading without tools",
        f"{LAYOUT['report']:<28} the written findings - start here",
        f"{LAYOUT['correlation']:<28} one row per camera event",
        f"{LAYOUT['timeline']:<28} the timeline figure",
        f"{LAYOUT['events']:<28} every event parsed from every source",
        f"{LAYOUT['incidents']:<28} disruptions grouped into incidents",
        f"{LAYOUT['inputs']:<28} unmodified copies of the source files",
    ]
    # Only describe the exhibits folder when there is one; a cover sheet that
    # lists a folder the reader cannot find undermines the rest of it.
    if (result.root / LAYOUT["exhibits"]).exists():
        lines.append(f"{LAYOUT['exhibits']:<28} camera snapshots and attached exhibits")
    lines += [
        f"{LAYOUT['custody']:<28} timestamped log of how this bundle was built",
        "",
        "HOW TO VERIFY THE SOURCE FILES ARE UNALTERED",
        "-" * 66,
        f"Each file in {LAYOUT['inputs']} was hashed before it was read and again",
        "after it was copied here. To check a copy yourself:",
        "",
        "  Windows:  certutil -hashfile <file> SHA256",
        "  macOS:    shasum -a 256 <file>",
        "  Linux:    sha256sum <file>",
        "",
        f"Compare the result against the value for that file in {LAYOUT['manifest']}",
        "or in section 9 of the report. Any difference at all means the file is not",
        "the one that was analysed.",
        "",
    ]
    if result.problems:
        lines += ["PROBLEMS RECORDED WHILE BUILDING THIS BUNDLE", "-" * 66]
        lines += [f"- {p}" for p in result.problems]
        lines.append("")
    lines += [
        "SCOPE OF THIS ANALYSIS",
        "-" * 66,
        "This tool reads logs and capture files. It does not transmit on any wireless",
        "network and cannot disconnect any device. Section 10 of the report sets out",
        "what the analysis does and does not establish; read it before relying on the",
        "finding above.",
        "",
    ]
    return "\n".join(lines)
