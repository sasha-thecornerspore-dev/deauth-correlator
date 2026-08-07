"""Build the standalone application and prove that the result works.

    python packaging/build.py

It runs PyInstaller over packaging/deauth-correlator.spec, then runs the
executable it just produced and checks two things: that ``--version`` reports
the version this source tree declares, and that ``--self-test`` passes. The
self-test is the useful one. It generates synthetic evidence for every
supported input format, runs the whole pipeline over it twice, renders
timeline.png and writes a report, so it exercises pandas, numpy, matplotlib,
zoneinfo and sqlite3 inside the frozen program. A build that is missing a data
file or a compiled extension fails it.

The checks run with the working directory set to an empty temporary folder, so
a binary that has quietly kept a dependency on the source tree is caught here
rather than on someone else's machine.

Exit codes, following the same convention the tool itself uses:

    0   the build succeeded and the executable passed every check
    1   the build produced an executable that does not work
    2   the build could not be run at all

PyInstaller does not cross-compile. This script produces artefacts for the
operating system it is run on and no other; see packaging/README.md.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SPEC_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SPEC_DIR.parent
SPEC_FILE = SPEC_DIR / "deauth-correlator.spec"

DIST_NAME = "deauth-correlator"
CLI_NAME = "deauth-correlator"
GUI_NAME = "deauth-correlator-gui"
APP_NAME = "deauth-correlator.app"

# Documents worth having next to the executables. A recipient who is handed the
# folder should be able to read what the tool does without a network.
DOCS = ["README.md", "SAFETY.md", "LICENSE", "LICENSE.txt", "NOTICE"]

SELF_TEST_TIMEOUT_S = 900
VERSION_TIMEOUT_S = 120


class BuildError(RuntimeError):
    """Something went wrong that makes the build unusable."""


class SetupError(RuntimeError):
    """The build could not be started."""


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def say(message: str = "") -> None:
    print(message, flush=True)


def rule(title: str) -> None:
    say()
    say(title)
    say("-" * len(title))


def exe_suffix() -> str:
    return ".exe" if os.name == "nt" else ""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def directory_size(path: Path) -> int:
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file())


def human(size: int) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{value:,.1f} {unit}" if unit != "B" else f"{int(value):,} B"
        value /= 1024
    return f"{value:,.1f} GiB"


def source_version() -> str:
    """Read the declared version without importing the dependencies."""
    sys.path.insert(0, str(PROJECT_ROOT))
    try:
        from deauth_correlator import __version__
    except Exception as exc:  # pragma: no cover - a broken checkout
        raise SetupError(
            f"cannot import deauth_correlator from {PROJECT_ROOT}: {exc}") from exc
    return __version__


def run(command: list[str], *, cwd: Path, timeout: int) -> subprocess.CompletedProcess:
    """Run a command, capture everything it says, never raise on exit status."""
    return subprocess.run(
        command, cwd=str(cwd), timeout=timeout,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, errors="replace", check=False)


def show_output(result: subprocess.CompletedProcess, tail: int = 40) -> None:
    lines = (result.stdout or "").splitlines()
    if len(lines) > tail:
        say(f"    ... {len(lines) - tail} earlier line(s) omitted")
        lines = lines[-tail:]
    for line in lines:
        say(f"    {line}")


# --------------------------------------------------------------------------
# Build
# --------------------------------------------------------------------------

def check_prerequisites() -> None:
    if sys.version_info < (3, 10):
        raise SetupError(
            f"deauth-correlator requires Python 3.10 or newer; this is "
            f"{platform.python_version()}.")
    if not SPEC_FILE.is_file():
        raise SetupError(f"spec file not found: {SPEC_FILE}")
    try:
        import PyInstaller  # noqa: F401
    except ImportError as exc:
        raise SetupError(
            "PyInstaller is not installed in this interpreter. Install it with\n"
            f"    {sys.executable} -m pip install pyinstaller") from exc


def run_pyinstaller(dist: Path, work: Path, clean: bool) -> None:
    command = [sys.executable, "-m", "PyInstaller", "--noconfirm",
               "--distpath", str(dist), "--workpath", str(work)]
    if clean:
        command.append("--clean")
    command.append(str(SPEC_FILE))

    rule("Running PyInstaller")
    say(" ".join(command))
    say()
    # Not captured: PyInstaller's progress is long and worth watching, and if it
    # fails the reason is in that output.
    result = subprocess.run(command, cwd=str(PROJECT_ROOT), check=False)
    if result.returncode != 0:
        raise BuildError(f"PyInstaller exited {result.returncode}.")


def locate_artefacts(dist: Path) -> tuple[Path, Path, Path, Path | None]:
    """Return (output directory, CLI executable, GUI executable, .app or None)."""
    outdir = dist / DIST_NAME
    if not outdir.is_dir():
        raise BuildError(f"PyInstaller reported success but {outdir} does not exist.")

    cli = outdir / (CLI_NAME + exe_suffix())
    gui = outdir / (GUI_NAME + exe_suffix())
    for path in (cli, gui):
        if not path.is_file():
            raise BuildError(f"expected executable is missing: {path}")
        if path.stat().st_size == 0:
            raise BuildError(f"executable is empty: {path}")

    app = dist / APP_NAME
    return outdir, cli, gui, (app if app.is_dir() else None)


CONTENTS_MANIFEST = "CONTENTS.sha256"
VERIFY_WINDOWS = "verify-install.ps1"
VERIFY_UNIX = "verify-install.sh"

VERIFY_PS1 = r"""# Verify a deauth-correlator installation is complete and unmodified.
#
# Run this if the program fails to start, and in particular if it reports
#   Tk data directory "...\_internal\_tk_data" not found
# which means the archive did not extract completely. That failure happens
# inside PyInstaller's startup hook, before any of the program's own code runs,
# so the program cannot diagnose it for you - hence this script, which does not
# depend on the program working at all.
#
#   powershell -ExecutionPolicy Bypass -File verify-install.ps1
#
# Exit codes: 0 intact, 1 files missing or altered, 2 the manifest is absent.

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$manifest = Join-Path $root "CONTENTS.sha256"

if (-not (Test-Path $manifest)) {
    Write-Host "CONTENTS.sha256 is missing, so this installation cannot be checked."
    Write-Host "Re-extract the archive you downloaded."
    exit 2
}

$missing = 0; $changed = 0; $checked = 0
foreach ($line in Get-Content $manifest) {
    if ($line -match '^\s*(#|$)') { continue }
    $expected, $relative = $line -split '\s+', 2
    $path = Join-Path $root $relative.Trim()
    $checked++
    if (-not (Test-Path -LiteralPath $path)) {
        Write-Host "MISSING  $relative"; $missing++; continue
    }
    $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $expected.ToLower()) { Write-Host "CHANGED  $relative"; $changed++ }
}

Write-Host ""
Write-Host "$checked file(s) checked, $missing missing, $changed altered."
if ($missing -or $changed) {
    Write-Host ""
    Write-Host "This installation is not intact. Delete the folder and extract the"
    Write-Host "archive again - prefer 7-Zip or 'Expand-Archive' over dragging files"
    Write-Host "out of Explorer's zip viewer, which can stop part way without saying so."
    exit 1
}
Write-Host "This installation matches the archive it was built from."
exit 0
"""

VERIFY_SH = r"""#!/bin/sh
# Verify a deauth-correlator installation is complete and unmodified.
#
# Run this if the program fails to start. A missing Tk data directory aborts
# inside PyInstaller's startup hook, before any of the program's own code runs,
# so the program cannot diagnose it for you - hence this script, which does not
# depend on the program working at all.
#
#   sh verify-install.sh
#
# Exit codes: 0 intact, 1 files missing or altered, 2 the manifest is absent.

root=$(cd "$(dirname "$0")" && pwd)
manifest="$root/CONTENTS.sha256"

if [ ! -f "$manifest" ]; then
    echo "CONTENTS.sha256 is missing, so this installation cannot be checked."
    echo "Re-extract the archive you downloaded."
    exit 2
fi

if command -v shasum >/dev/null 2>&1; then
    check="shasum -a 256 -c --quiet"
elif command -v sha256sum >/dev/null 2>&1; then
    check="sha256sum -c --quiet"
else
    echo "Neither shasum nor sha256sum is available; cannot verify."
    exit 2
fi

cd "$root" || exit 2
if $check "$manifest"; then
    echo "This installation matches the archive it was built from."
    exit 0
fi

echo ""
echo "This installation is not intact. Delete the folder and extract the archive"
echo "again. On macOS, use 'tar -xzf' rather than double-clicking, which can"
echo "mishandle the symlinks inside an application bundle."
exit 1
"""


def write_contents_manifest(outdir: Path) -> int:
    """Hash every file in the finished build so an install can be checked later.

    A build that leaves CI intact can still arrive damaged: an archive that
    stopped extracting part way is indistinguishable from a broken build to
    someone looking at a PyInstaller traceback, and the traceback for a missing
    Tk data directory is raised by a startup hook that runs before any of this
    program's code. Nothing inside the frozen application can report on it, so
    the manifest and the two scripts beside it deliberately do not depend on the
    application running.
    """
    entries = []
    for path in sorted(p for p in outdir.rglob("*") if p.is_file()):
        relative = path.relative_to(outdir).as_posix()
        if relative in (CONTENTS_MANIFEST, VERIFY_WINDOWS, VERIFY_UNIX):
            continue
        entries.append(f"{sha256_file(path)}  {relative}")

    header = [
        "# deauth-correlator installation manifest.",
        "# Every file this build produced, with its SHA-256.",
        "# Check an installation against it with verify-install.ps1 (Windows)",
        "# or verify-install.sh (macOS and Linux).",
    ]
    (outdir / CONTENTS_MANIFEST).write_text(
        "\n".join(header + entries) + "\n", encoding="utf-8")

    (outdir / VERIFY_WINDOWS).write_text(VERIFY_PS1, encoding="utf-8")
    unix = outdir / VERIFY_UNIX
    unix.write_text(VERIFY_SH, encoding="utf-8", newline="\n")
    try:
        unix.chmod(unix.stat().st_mode | 0o111)
    except OSError:
        pass
    return len(entries)


def copy_documents(outdir: Path, app: Path | None) -> list[str]:
    """Put the documentation next to the executables. Returns what was copied."""
    copied = []
    targets = [outdir]
    if app is not None:
        resources = app / "Contents" / "Resources"
        if resources.is_dir():
            targets.append(resources)
    for name in DOCS:
        source = PROJECT_ROOT / name
        if not source.is_file():
            continue
        for target in targets:
            shutil.copy2(source, target / name)
        copied.append(name)
    return copied


# --------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------

def verify_cli(cli: Path, expected_version: str) -> None:
    """Run the frozen executable and fail loudly if it does not behave."""
    with tempfile.TemporaryDirectory(prefix="deauth-correlator-verify-") as sandbox:
        cwd = Path(sandbox)

        say(f"  {cli.name} --version")
        result = run([str(cli), "--version"], cwd=cwd, timeout=VERSION_TIMEOUT_S)
        if result.returncode != 0:
            show_output(result)
            raise BuildError(
                f"'{cli.name} --version' exited {result.returncode}; the executable "
                f"does not start.")
        reported = (result.stdout or "").strip()
        expected = f"deauth-correlator {expected_version}"
        if reported != expected:
            show_output(result)
            raise BuildError(
                f"'{cli.name} --version' printed {reported!r}, expected {expected!r}.")
        say(f"    {reported}")

        say(f"  {cli.name} --self-test")
        result = run([str(cli), "--self-test", "-q"], cwd=cwd,
                     timeout=SELF_TEST_TIMEOUT_S)
        summary = next((line for line in (result.stdout or "").splitlines()
                        if line.startswith("SELF-TEST")), "")
        if result.returncode != 0 or "SELF-TEST PASSED" not in (result.stdout or ""):
            show_output(result, tail=60)
            raise BuildError(
                f"'{cli.name} --self-test' exited {result.returncode}. The build is "
                f"broken: something the analysis needs did not make it into the "
                f"bundle.")
        say(f"    {summary}")

        # Neither check above touches Tkinter, so a bundle whose GUI is dead -
        # the classic PyInstaller Tk-collection failure - passes both of them
        # and ships. The frozen GUI executable cannot be used to detect that
        # without a display, so the CLI performs the imports instead.
        say(f"  {cli.name} --check-runtime")
        result = run([str(cli), "--check-runtime"], cwd=cwd,
                     timeout=VERSION_TIMEOUT_S)
        if result.returncode != 0:
            show_output(result, tail=40)
            raise BuildError(
                f"'{cli.name} --check-runtime' exited {result.returncode}. Something "
                f"that ships inside the bundle cannot be imported - most often the Tk "
                f"libraries, which leaves {cli.name} working and the graphical "
                f"interface dead.")
        for line in (result.stdout or "").splitlines():
            if "available" in line or "UNAVAILABLE" in line:
                say(f"    {line.strip()}")


def verify_app_bundle(app: Path) -> None:
    """Check the .app is structurally what Finder and codesign expect."""
    import plistlib

    plist_path = app / "Contents" / "Info.plist"
    if not plist_path.is_file():
        raise BuildError(f"{app.name} has no Contents/Info.plist.")
    with open(plist_path, "rb") as handle:
        info = plistlib.load(handle)

    executable = info.get("CFBundleExecutable", "")
    if executable != GUI_NAME:
        raise BuildError(
            f"{app.name} declares CFBundleExecutable={executable!r}; the windowed "
            f"executable {GUI_NAME!r} should be the one Finder launches.")
    if not (app / "Contents" / "MacOS" / executable).is_file():
        raise BuildError(f"{app.name} declares {executable!r} but does not contain it.")
    if info.get("LSBackgroundOnly"):
        raise BuildError(
            f"{app.name} is marked LSBackgroundOnly, so its window would never "
            f"appear. The collection was built from a console executable.")
    identifier = info.get("CFBundleIdentifier", "")
    if not identifier:
        raise BuildError(f"{app.name} has no CFBundleIdentifier.")
    say(f"    CFBundleIdentifier {identifier}")
    say(f"    CFBundleExecutable {executable}")
    say(f"    CFBundleShortVersionString "
        f"{info.get('CFBundleShortVersionString', '(none)')}")


# --------------------------------------------------------------------------
# Archive
# --------------------------------------------------------------------------

def make_archive(dist: Path, outdir: Path, app: Path | None, version: str) -> Path:
    """Produce one file to publish, so there is one hash to publish with it."""
    tag = f"{platform.system().lower()}-{platform.machine().lower()}"
    if app is not None:
        target = dist / f"{DIST_NAME}-{version}-{tag}-app.zip"
        if target.exists():
            target.unlink()
        # ditto, not shutil: an .app contains symlinks and executable bits, and
        # a zip written without them produces a bundle macOS refuses to launch.
        result = run(["ditto", "-c", "-k", "--sequesterRsrc", "--keepParent",
                      str(app), str(target)], cwd=dist, timeout=1800)
        if result.returncode != 0:
            show_output(result)
            raise BuildError("ditto failed to archive the .app bundle.")
        return target

    base = dist / f"{DIST_NAME}-{version}-{tag}"
    return Path(shutil.make_archive(str(base), "zip",
                                    root_dir=str(outdir.parent),
                                    base_dir=outdir.name))


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def build(args) -> int:
    check_prerequisites()
    version = source_version()

    dist = Path(args.distpath).resolve()
    work = Path(args.workpath).resolve()

    rule("deauth-correlator standalone build")
    say(f"Version        {version}")
    say(f"Platform       {platform.system()} {platform.release()} "
        f"({platform.machine()})")
    say(f"Python         {platform.python_version()} at {sys.executable}")
    say(f"Project root   {PROJECT_ROOT}")
    say(f"Output         {dist}")
    say()
    say("PyInstaller does not cross-compile. This run produces artefacts for "
        f"{platform.system()} only;")
    say("artefacts for another operating system have to be built on that "
        "operating system.")

    run_pyinstaller(dist, work, clean=not args.no_clean)
    outdir, cli, gui, app = locate_artefacts(dist)

    rule("Verifying the executable")
    verify_cli(cli, version)
    if app is not None:
        say(f"  {app.name}")
        verify_app_bundle(app)
    say(f"  {gui.name}")
    say("    present and non-empty. It is not launched here: it opens a window "
        "and needs")
    say("    a display, so check it by hand once per platform.")

    copied = copy_documents(outdir, app)
    manifest_count = write_contents_manifest(outdir)
    # On macOS the archive carries the .app alone, so the collection's
    # manifest would never reach anyone. The bundle needs its own.
    if app is not None:
        manifest_count += write_contents_manifest(app)

    rule("Artefacts")
    say(f"{outdir}{os.sep}")
    say(f"    total {human(directory_size(outdir))}")
    for path in (cli, gui):
        say(f"  {path}")
        say(f"    {human(path.stat().st_size)}")
        say(f"    sha256  {sha256_file(path)}")
    if app is not None:
        say(f"  {app}")
        say(f"    total {human(directory_size(app))}")
        say("    A bundle is a directory, so it has no single hash of its own. "
            "Use --archive")
        say("    to produce one file, which does.")
    if copied:
        say(f"  copied alongside the executables: {', '.join(copied)}")
    say(f"  {CONTENTS_MANIFEST}: {manifest_count} file(s) hashed, with "
        f"{VERIFY_WINDOWS} and {VERIFY_UNIX} beside it")

    if args.archive:
        archive = make_archive(dist, outdir, app, version)
        say()
        say(f"  {archive}")
        say(f"    {human(archive.stat().st_size)}")
        say(f"    sha256  {sha256_file(archive)}")

    rule("Result")
    say("Build succeeded and the executable passed every check.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="build.py",
        description="Build deauth-correlator as a standalone application and "
                    "verify the result.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exit codes: 0 built and verified, 1 the build is broken, "
               "2 the build could not be run.")
    parser.add_argument("--distpath", default=str(PROJECT_ROOT / "dist"),
                        metavar="DIR",
                        help="Where the finished application is written "
                             "(default: <project>/dist).")
    parser.add_argument("--workpath", default=str(PROJECT_ROOT / "build"),
                        metavar="DIR",
                        help="Scratch directory for the build "
                             "(default: <project>/build).")
    parser.add_argument("--no-clean", action="store_true",
                        help="Keep PyInstaller's caches. Faster on a rebuild, and "
                             "the usual cause of a stale file surviving into the "
                             "output.")
    parser.add_argument("--archive", action="store_true",
                        help="Also produce a single zip of the result and print "
                             "its SHA-256.")
    args = parser.parse_args(argv)

    try:
        return build(args)
    except SetupError as exc:
        say()
        say(f"error: {exc}")
        return 2
    except BuildError as exc:
        say()
        say(f"BUILD FAILED: {exc}")
        return 1
    except subprocess.TimeoutExpired as exc:
        say()
        say(f"BUILD FAILED: {exc.cmd[0]} did not finish within {exc.timeout:.0f} s.")
        return 1
    except KeyboardInterrupt:
        say()
        say("interrupted.")
        return 2


if __name__ == "__main__":
    sys.exit(main())
