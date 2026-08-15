"""Check what the standalone builds actually redistribute, and whether NOTICE says so.

This exists because of a real miss. opencv-python is Apache-2.0, and it carries
FFmpeg (LGPL-2.1) *inside its own wheel*. PyInstaller collected the resulting
30 MB opencv_videoio_ffmpeg500_64.dll into every release archive, and NOTICE --
pure Apache boilerplate at the time -- said nothing about it. Four public
releases went out that way. No manifest-reading tool would have caught it:
pip-licenses, FOSSA and friends all report opencv-python as Apache-2.0, which is
true, and none of them look inside the wheel. The only place the truth exists is
the built tree.

The check has four layers, and the third is the reason it exists:

    L1  name denylist       - distributions that must never be installed
    L2  SPDX denylist       - copyleft/non-commercial families, from installed
                              metadata, minus PyInstaller (its GPL-2.0 bootloader
                              exception exists to permit exactly this use)
    L3  artifact walk       - binary filenames in dist/, classified DENY (must
                              not ship at all) or NOTICE (may ship, must be
                              documented)
    L4  notice cross-check  - every L3 notice hit must be named in NOTICE. This
                              fails on the DOCUMENT, not on the dependency:
                              shipping an LGPL library is allowed, shipping it
                              silently is not.

Usage:

    python tools/license_gate.py                    # L1 + L2 only
    python tools/license_gate.py --artifact dist    # + L3 + L4

Exit status is 0 when clean and 1 on any violation, so it can be dropped into a
workflow between the build step and the publish step.
"""

from __future__ import annotations

import argparse
import re
import sys
from importlib import metadata
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Distributions that must never appear in an environment we freeze from.
NAME_DENY = (
    "pymupdf", "pymupdfb", "fitz",
    "stirling-pdf", "mcp-server-stirling-pdf",
    "ghostscript",
)

# Licence families that cannot ship inside a distributed archive.
SPDX_DENY = re.compile(
    r"\b(AGPL|SSPL|CC-BY-NC|BUSL|Commons-Clause|OSL-3|EUPL|GPL-2\.0|GPL-3\.0"
    r"|GPLv2|GPLv3)\b",
    re.IGNORECASE,
)

# Exempt from L2 only, each for a stated reason. PyInstaller's bootloader is
# GPL-2.0-or-later WITH an exception written to allow shipping frozen programs
# under any licence; gating on it would fail every build for nothing.
SPDX_EXEMPT = {"pyinstaller", "pyinstaller-hooks-contrib"}

# L3. Matched case-insensitively against a binary's stem at a word boundary, so
# "opencv_videoio_ffmpeg500_64" matches on "_ffmpeg" and "ffmpeg.dll" matches at
# the start.
ARTIFACT_RULES = (
    ("Ghostscript", "AGPL-3.0", "deny",
     re.compile(r"(^|[_-])(gswin|gsdll|libgs|ghostscript)", re.IGNORECASE)),
    ("MuPDF", "AGPL-3.0", "deny",
     re.compile(r"(^|[_-])(mupdf|fitz)", re.IGNORECASE)),
    ("FFmpeg", "LGPL-2.1-or-later", "notice",
     re.compile(r"(^|[_-])(ffmpeg|avcodec|avformat|avutil|avfilter|avdevice"
                r"|swscale|swresample)", re.IGNORECASE)),
    ("libvpx", "BSD-3-Clause", "notice",
     re.compile(r"(^|[_-])vpx", re.IGNORECASE)),
    ("Tesseract", "Apache-2.0", "notice",
     re.compile(r"(^|[_-])(tesseract|leptonica)", re.IGNORECASE)),
)

BINARY_SUFFIXES = {".dll", ".so", ".dylib", ".exe", ".pyd", ".a", ".lib"}


def _licence_of(md) -> str:
    """A licence *expression* for a distribution, never its licence prose.

    Core-metadata "License" is free text, and several projects paste an entire
    licence agreement into it -- matplotlib ships some 20 KB there, including
    the text of the other licences it bundles. Scanning that for "GPL" flags
    every licence that merely mentions the GPL, which on this project's own
    dependencies was three false positives and no true ones. So: prefer
    License-Expression, accept a short single-line License as an expression,
    and otherwise fall back to the classifiers, which are structured.
    """
    expression = (md.get("License-Expression") or "").strip()
    if not expression:
        raw = (md.get("License") or "").strip()
        if raw and len(raw) <= 100 and "\n" not in raw:
            expression = raw
    classifiers = [c for c in (md.get_all("Classifier") or [])
                   if c.startswith("License ::")]
    return " ".join([expression, *classifiers]).strip()


def _installed_distributions() -> list[tuple[str, str, str]]:
    """(name, version, licence expression) for everything importable here."""
    out: list[tuple[str, str, str]] = []
    for dist in metadata.distributions():
        md = dist.metadata
        name = (md["Name"] or "").strip()
        if not name:
            continue
        out.append((name, md["Version"] or "", _licence_of(md)))
    return out


def _binaries(root: Path):
    for path in root.rglob("*"):
        if path.is_file() and path.suffix.lower() in BINARY_SUFFIXES:
            yield path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--artifact", metavar="DIR",
                        help="built tree to walk (enables layers 3 and 4)")
    parser.add_argument("--notice", metavar="FILE", default="NOTICE",
                        help="notice file that must document what ships")
    args = parser.parse_args(argv)

    problems: list[str] = []
    notes: list[str] = []

    # Which environment is being judged matters as much as the verdict: this
    # machine's global interpreter carries a hand-installed AGPL PyMuPDF that
    # the clean .buildenv does not, and packaging/build.py freezes from
    # whichever interpreter invokes it.
    notes.append(f"[env] {sys.executable}")

    # L1 + L2
    for name, version, licence_text in _installed_distributions():
        bare = name.lower()
        if any(bare == d or d in bare for d in NAME_DENY):
            problems.append(f"[name] {name} {version} is on the denylist")
        if SPDX_DENY.search(licence_text) and bare not in SPDX_EXEMPT:
            shown = licence_text.strip()
            if len(shown) > 120:
                shown = shown[:117] + "..."
            problems.append(f"[spdx] {name} {version} is {shown}")

    # L3 + L4
    if args.artifact:
        root = (PROJECT_ROOT / args.artifact).resolve()
        if not root.is_dir():
            problems.append(f"[artifact] {args.artifact} does not exist - nothing was checked")
        else:
            notice_path = (PROJECT_ROOT / args.notice).resolve()
            notice = notice_path.read_text(encoding="utf-8") if notice_path.is_file() else ""
            if not notice:
                problems.append(f"[docs] notice file not found: {args.notice}")

            found: dict[str, list[Path]] = {}
            rules = {name: (licence, action) for name, licence, action, _ in ARTIFACT_RULES}
            for path in _binaries(root):
                for name, _licence, _action, pattern in ARTIFACT_RULES:
                    if pattern.search(path.stem):
                        found.setdefault(name, []).append(path)

            for name, paths in sorted(found.items()):
                licence, action = rules[name]
                where = ", ".join(
                    f"{p.relative_to(PROJECT_ROOT)} ({p.stat().st_size / 1048576:.1f} MB)"
                    for p in paths)
                if action == "deny":
                    problems.append(f"[artifact] {name} ({licence}) must not ship: {where}")
                elif not re.search(rf"\b{re.escape(name)}\b", notice, re.IGNORECASE):
                    problems.append(
                        f"[docs] {name} ({licence}) is redistributed but absent from "
                        f"{args.notice}: {where}")
                else:
                    notes.append(f"[artifact] {name} ({licence}) present and documented: {where}")
            if not found:
                notes.append("[artifact] no copyleft-family binaries found in the build")
    else:
        notes.append("[artifact] no --artifact given; layers 3 and 4 skipped")

    for line in notes:
        print(f"  - {line}")
    if problems:
        print(f"\nlicence gate FAILED ({len(problems)}):", file=sys.stderr)
        for line in problems:
            print(f"  X {line}", file=sys.stderr)
        print(file=sys.stderr)
        return 1
    print("licence gate OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
