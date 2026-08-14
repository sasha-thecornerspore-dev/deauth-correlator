"""Finding out whether a newer release exists, and installing one on request.

Checking and installing are deliberately two different acts, and this module
never performs the second one on its own. Every report and every MANIFEST.json
this tool writes records the version that produced it, and an analysis that ran
against files a background task quietly replaced halfway through cannot answer
the question a court will ask about it. Checking is a read of a public release
index. Installing rewrites the program on disk, and that only happens when
somebody asks for it.

What is verified, and against what
----------------------------------
Two independent digests have to match before anything is put in place.

* The published release carries ``SHA256SUMS.txt`` beside the archives. The
  downloaded archive is hashed and compared against the line for its own file
  name. A mismatch deletes the download and raises.
* Every standalone build contains ``CONTENTS.sha256``, written by
  ``packaging/build.py``, listing the SHA-256 of every file the build produced.
  After extraction the whole tree is checked against it, including a check for
  files that are present but not listed.

Neither of these makes the download trustworthy on its own: both the archive and
the checksum file arrive over the same connection, so an attacker who controls
that connection controls both. TLS is what rules that out, which is why this
module talks only to the hosts in :data:`UPDATE_ENDPOINTS`, only over HTTPS,
refuses to follow a redirect to any other host, and ignores proxy settings from
the environment. What the hashes do rule out is a truncated download, a corrupt
archive, a mirror serving the wrong file, and an installation tree that lost
files on the way out of the zip. That last one is not hypothetical: it is the
reason ``packaging/build.py`` ships ``verify-install.ps1`` and
``verify-install.sh`` beside every build, because a half-extracted archive
fails inside PyInstaller's startup hook where the program cannot report on it.

Why the swap is never performed by the running program
------------------------------------------------------
A running program cannot safely replace its own installation directory.

On Windows the operating system refuses outright: a directory cannot be renamed
while an executable image inside it is loaded. On macOS and Linux the rename
succeeds, which is worse rather than better. This is a one-directory PyInstaller
build, and PyInstaller resolves the contents of ``_internal`` by path at the
moment they are first needed. Tkinter, the matplotlib backends, the SciPy
extensions and OpenCV are all imported lazily, so a swap performed during a
session hands the already-running interpreter shared libraries belonging to a
different build. The failure would land in the middle of somebody's analysis.

So the conclusion is the honest one: in-place self-replacement cannot be made
safe, on any of the three platforms, and this module does not attempt it. What
it does instead is everything up to the last step. It downloads, verifies,
extracts beside the existing installation, verifies the extracted tree, and
then stops and hands over one command. :func:`stage_update` writes that command
out as ``complete-update.cmd`` or ``complete-update.sh`` in the staging folder,
and :func:`completion_instructions` returns the text to show the operator. The
script itself contacts nothing and does exactly two renames:

    <install>        ->  <install>.previous-<old version>
    <staged build>   ->  <install>

Both are ordinary renames inside one directory, so both are atomic, and the
replaced installation stays on disk under its ``.previous`` name. If the second
rename fails the script puts the first one back; if that also fails it says so
and names the directory the installation is now sitting in.
:func:`complete_update` is the same two renames in Python, for a caller that is
demonstrably not running out of the directory being replaced - a source
checkout driving the update of a standalone install, or a test.

The finishing step is a shell script rather than a Python one because a
standalone build has nothing to run Python with. It ships no interpreter
executable, and PyInstaller keeps only bytecode: ``get_source`` on its importer
returns None when the ``.py`` is not on disk, so a helper module could not even
be written out to be run. ``cmd.exe`` and ``/bin/sh`` are the only interpreters
that are certain to be there once this program has exited.

Installed with pip
------------------
A pip installation is never touched. ``sys.frozen`` tells the two apart;
:func:`check_for_update` works the same either way, and :func:`stage_update`
refuses with the pip command to run instead. Replacing files under a package
manager's feet leaves it with a lie in its metadata.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import stat
import sys
import zipfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from urllib.parse import urljoin, urlsplit

from . import __tool_name__, __version__

# --------------------------------------------------------------------------
# Where this module is allowed to go
# --------------------------------------------------------------------------

REPOSITORY = "sasha-thecornerspore-dev/deauth-correlator"
RELEASES_API_URL = f"https://api.github.com/repos/{REPOSITORY}/releases/latest"
RELEASES_PAGE_URL = f"https://github.com/{REPOSITORY}/releases"

# Every host this module can open a connection to, with the reason. SAFETY.md
# cites this list, so it is written to be read rather than to be short, and it
# is enforced rather than merely documented: _check_url below rejects any URL
# whose host is not in it, including one arrived at through a redirect. If
# GitHub renames its asset CDN this updater stops working and says which host
# it refused, which is the right way round for a tool whose network behaviour
# is meant to be checkable.
#
# One caveat belongs here rather than in a footnote. The list is exact only
# because the session sets trust_env = False: a stock requests session honours
# HTTP_PROXY and HTTPS_PROXY, and on a machine configured with a proxy every
# request below would go to the proxy instead of to the host named here. On a
# machine that genuinely needs a proxy to reach the internet the check reports
# a network error, and the release page has to be opened by hand.
UPDATE_ENDPOINTS: tuple[tuple[str, str], ...] = (
    ("api.github.com",
     "One HTTPS GET of RELEASES_API_URL per check. Unauthenticated: no token, "
     "no credentials, no cookies, nothing about this machine beyond the "
     "User-Agent below and the TLS connection itself."),
    ("github.com",
     "The published release assets - the platform archive and SHA256SUMS.txt - "
     "requested only when a download is asked for. These URLs answer with a "
     "redirect rather than with the bytes."),
    ("objects.githubusercontent.com",
     "Where github.com redirects a release-asset download. The archive bytes "
     "arrive from here."),
    ("release-assets.githubusercontent.com",
     "The newer name for the same redirect target. Both are in use, so both "
     "have to be allowed."),
)

ALLOWED_HOSTS = frozenset(host for host, _ in UPDATE_ENDPOINTS)

# Identifies the tool and points at the source, which is what GitHub asks
# unauthenticated API callers to send.
USER_AGENT = f"{__tool_name__}/{__version__} (+https://github.com/{REPOSITORY})"

# --------------------------------------------------------------------------
# Names and limits
# --------------------------------------------------------------------------

DIST_NAME = "deauth-correlator"
PIP_NAME = "deauth-correlator"
CHECKSUMS_NAME = "SHA256SUMS.txt"

# Written into every standalone build by packaging/build.py. Their names are
# repeated here rather than imported because packaging/ is not part of the
# installed package.
CONTENTS_MANIFEST = "CONTENTS.sha256"
VERIFY_WINDOWS = "verify-install.ps1"
VERIFY_UNIX = "verify-install.sh"

COMPLETE_WINDOWS = "complete-update.cmd"
COMPLETE_UNIX = "complete-update.sh"
UPDATE_NOTES = "UPDATE.txt"

# A check once a day is enough to be useful and few enough requests to stay well
# inside GitHub's unauthenticated rate limit even on a shared address.
CHECK_INTERVAL_HOURS = 24.0

CHUNK = 1024 * 1024
MAX_REDIRECTS = 5
MAX_METADATA_BYTES = 4 * 1024 * 1024        # the release JSON and SHA256SUMS.txt
MAX_ARCHIVE_BYTES = 1536 * 1024 * 1024      # a build is around 400 MiB
MAX_EXTRACTED_BYTES = 4096 * 1024 * 1024

ProgressFn = Callable[[int, int], None]
"""Called as ``progress(done, total)``. ``total`` is 0 when it is not known.

The unit is bytes during a download and files during a verification pass; each
function that takes one says which. Exceptions raised by the callback are not
swallowed, so a caller that aborts by raising gets a clean abort - partial
files are removed by the ``finally`` blocks that own them.
"""


# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------

class UpdateError(RuntimeError):
    """Base class, so a caller can catch everything from this module at once."""


class UpdateUnavailable(UpdateError):
    """The question could not be answered: network, HTTP, or a bad reply.

    Nothing has been changed on disk when this is raised.
    """


class UpdateVerificationError(UpdateError):
    """A digest did not match. Raised loudly and never recovered from.

    Nothing is installed after this. The downloaded file, if any, is deleted,
    because the one thing that must not happen is for it to be picked up and
    used later by something that assumes it was checked.
    """


class UpdateStagingError(UpdateError):
    """The download could not be unpacked into a usable installation tree."""


class UpdateNotSupported(UpdateError):
    """This installation cannot be replaced by this module.

    Raised for a pip installation, for a source checkout, and for a standalone
    build whose directory does not look like one that ``packaging/build.py``
    produced. The message says what to do instead.
    """


# --------------------------------------------------------------------------
# Versions
# --------------------------------------------------------------------------

# The stage alternatives are longest-first: Python's alternation takes the first
# branch that matches, so "a" listed before "alpha" would reduce "1.0.4alpha2" to
# stage "a" and lose the 2.
_VERSION_RE = re.compile(
    r"^\s*[vV]?(?P<release>\d+(?:\.\d+)*)"
    r"(?:[-_.]?(?P<stage>alpha|beta|preview|pre|rc|a|b|c)[-_.]?(?P<serial>\d*))?")

_STAGE_ORDER = {"a": 0, "alpha": 0, "b": 1, "beta": 1,
                "c": 2, "rc": 2, "pre": 2, "preview": 2}


def normalise_version(text: str) -> str:
    """Return the version out of a tag such as ``v1.0.3``, or "" if there is none."""
    match = _VERSION_RE.match(str(text or ""))
    if not match:
        return ""
    version = match.group("release")
    if match.group("stage"):
        version += match.group("stage") + (match.group("serial") or "")
    return version


def version_key(text: str) -> tuple:
    """A sort key for a version string. Compare these, never the strings.

    "1.0.10" is newer than "1.0.9", and string comparison says the opposite,
    which is the entire reason this exists. The release numbers are compared as
    numbers, padded to four components so that "1.0" and "1.0.0" come out equal,
    and a pre-release sorts before the final release of the same number so that
    1.0.4rc1 does not look newer than 1.0.4.
    """
    match = _VERSION_RE.match(str(text or ""))
    if not match:
        # An unreadable version sorts below everything, so it can never win a
        # comparison and offer an update that should not be offered.
        return ((-1,), 0, (0, 0))
    numbers = tuple(int(part) for part in match.group("release").split("."))
    numbers += (0,) * max(0, 4 - len(numbers))
    stage = (match.group("stage") or "").lower()
    if not stage:
        return (numbers, 1, (0, 0))
    serial = int(match.group("serial") or 0)
    return (numbers, 0, (_STAGE_ORDER.get(stage, 2), serial))


def is_newer(candidate: str, current: str) -> bool:
    """True when ``candidate`` is a strictly later version than ``current``."""
    return version_key(candidate) > version_key(current)


def due_for_check(last_checked_utc: str | None,
                  interval_hours: float = CHECK_INTERVAL_HOURS,
                  now: datetime | None = None) -> bool:
    """Whether enough time has passed since the last check.

    ``last_checked_utc`` is an ISO 8601 timestamp, typically the one the caller
    stored after the previous check. Anything unparseable is treated as never
    having checked, because guessing is worse than one extra request.
    """
    if not last_checked_utc:
        return True
    try:
        last = datetime.fromisoformat(str(last_checked_utc).replace("Z", "+00:00"))
    except ValueError:
        return True
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    reference = now or datetime.now(tz=timezone.utc)
    return reference - last >= timedelta(hours=interval_hours)


# --------------------------------------------------------------------------
# What is installed here
# --------------------------------------------------------------------------

@dataclass
class Installation:
    """How this copy of the tool was installed, and where it lives."""

    kind: str                       # "standalone" or "package"
    version: str
    root: Path | None = None        # the directory a standalone build occupies
    manifest: Path | None = None    # its CONTENTS.sha256, when it has one
    executable: Path | None = None

    @property
    def is_standalone(self) -> bool:
        return self.kind == "standalone"

    def describe(self) -> str:
        if not self.is_standalone:
            return (f"{__tool_name__} {self.version}, installed as a Python package "
                    f"({sys.executable})")
        where = str(self.root) if self.root else "an unknown directory"
        return f"{__tool_name__} {self.version}, standalone build in {where}"


def installation() -> Installation:
    """Describe the running installation.

    ``sys.frozen`` is what PyInstaller sets, and it is the only reliable way to
    tell a standalone build from an ordinary import of the package.
    """
    if not getattr(sys, "frozen", False):
        return Installation(kind="package", version=__version__)

    executable = Path(sys.executable).resolve()
    root = executable.parent
    # On macOS the collected directory is wrapped in a bundle and the executable
    # sits three levels down. The bundle is the unit that gets replaced, and it
    # is where build.py writes the bundle's own CONTENTS.sha256.
    if (root.name == "MacOS" and root.parent.name == "Contents"
            and root.parent.parent.suffix == ".app"):
        root = root.parent.parent

    manifest = root / CONTENTS_MANIFEST
    return Installation(kind="standalone", version=__version__, root=root,
                        manifest=manifest if manifest.is_file() else None,
                        executable=executable)


def running_from(root: Path) -> bool:
    """Whether this process is executing out of ``root``.

    Used to refuse a swap that would pull the directory out from under the
    interpreter performing it.
    """
    root = Path(root).resolve()
    for candidate in (Path(sys.executable), Path(__file__)):
        try:
            if Path(candidate).resolve().is_relative_to(root):
                return True
        except (OSError, ValueError):
            continue
    return False


def pip_upgrade_command() -> str:
    """The exact command that upgrades a pip installation of this tool."""
    return f'"{sys.executable}" -m pip install --upgrade {PIP_NAME}'


# --------------------------------------------------------------------------
# Releases
# --------------------------------------------------------------------------

@dataclass
class Release:
    """One published release, and the archive that belongs to this platform.

    ``sha256`` is empty until :func:`download_and_verify` has read
    ``SHA256SUMS.txt``; the check does not fetch it, so that a routine daily
    check is a single request. Everything else is filled in from the release
    index.

    ``asset_name`` is empty when the release exists but carries no build for
    this operating system and architecture. That is worth reporting rather than
    hiding: the new version is real, there is just nothing here to install.
    """

    version: str
    tag: str = ""
    published_utc: str = ""
    notes_url: str = RELEASES_PAGE_URL
    asset_name: str = ""
    asset_url: str = ""
    asset_size: int = 0
    sha256: str = ""
    checksums_url: str = ""
    notes: str = ""

    @property
    def has_asset(self) -> bool:
        return bool(self.asset_name and self.asset_url)

    def summary(self) -> str:
        parts = [f"{__tool_name__} {self.version} is available"]
        if self.published_utc:
            parts.append(f"published {self.published_utc[:10]}")
        if self.has_asset:
            parts.append(f"{self.asset_name} ({_human(self.asset_size)})")
        return ", ".join(parts) + "."


def platform_tags(system: str | None = None, machine: str | None = None) -> tuple[str, ...]:
    """The archive name fragments that identify this platform, most exact first.

    ``packaging/build.py`` names archives with ``platform.system().lower()`` and
    ``platform.machine().lower()``, so those are what has to be matched. The
    aliases exist because the same processor is called amd64 on Windows and
    x86_64 on Linux, and arm64 on macOS and aarch64 on Linux, and a release may
    have been built on either.
    """
    system = (system or platform.system()).lower()
    machine = (machine or platform.machine()).lower()
    aliases = {
        "amd64": ("amd64", "x86_64", "x64"),
        "x86_64": ("x86_64", "amd64", "x64"),
        "x64": ("x64", "amd64", "x86_64"),
        "arm64": ("arm64", "aarch64"),
        "aarch64": ("aarch64", "arm64"),
    }
    return tuple(f"{system}-{name}" for name in aliases.get(machine, (machine,)))


def select_asset(assets: list, version: str, system: str | None = None,
                 machine: str | None = None) -> dict | None:
    """Pick the release asset built for this platform, or None if there is none.

    The macOS archive is the ``.app`` bundle and its name ends ``-app.zip``. On
    every other platform that suffix marks an archive that must not be offered,
    so it is excluded rather than merely not preferred.
    """
    system = (system or platform.system()).lower()
    app_suffix = system == "darwin"
    tags = platform_tags(system, machine)
    by_name = {str(asset.get("name") or ""): asset for asset in assets
               if isinstance(asset, dict)}

    for tag in tags:
        exact = f"{DIST_NAME}-{version}-{tag}{'-app.zip' if app_suffix else '.zip'}"
        if exact in by_name:
            return by_name[exact]

    # A release whose file names do not carry the version exactly as the tag
    # does. Still required to name this platform and this kind of archive.
    for tag in tags:
        for name, asset in by_name.items():
            lowered = name.lower()
            if not lowered.startswith(f"{DIST_NAME}-") or tag not in lowered:
                continue
            if app_suffix and lowered.endswith("-app.zip"):
                return asset
            if not app_suffix and lowered.endswith(".zip") \
                    and not lowered.endswith("-app.zip"):
                return asset
    return None


def check_for_update(current_version: str = __version__, timeout: float = 10.0,
                     system: str | None = None,
                     machine: str | None = None) -> Release | None:
    """Ask GitHub for the latest release. Return None when nothing is newer.

    One unauthenticated HTTPS GET of :data:`RELEASES_API_URL`. No token is sent
    and none is accepted; the endpoint is public. Drafts and pre-releases are
    not offered - ``/releases/latest`` excludes them by definition, and the
    flags are checked again here in case that ever stops being true.

    Raises :class:`UpdateUnavailable` when the answer could not be obtained, with
    a message written to be shown to an operator rather than logged.
    """
    data = _fetch_json(RELEASES_API_URL, timeout=timeout)

    if data.get("draft") or data.get("prerelease"):
        return None

    tag = str(data.get("tag_name") or data.get("name") or "")
    version = normalise_version(tag)
    if not version:
        raise UpdateUnavailable(
            f"the latest release is tagged {tag!r}, which does not contain a "
            f"version this can compare against {current_version}. Check "
            f"{RELEASES_PAGE_URL} by hand.")

    if not is_newer(version, current_version):
        return None

    assets = data.get("assets") if isinstance(data.get("assets"), list) else []
    release = Release(
        version=version,
        tag=tag,
        published_utc=str(data.get("published_at") or ""),
        notes_url=str(data.get("html_url") or RELEASES_PAGE_URL),
        notes=str(data.get("body") or "")[:20000],
        checksums_url=_asset_url(assets, CHECKSUMS_NAME)
        or f"https://github.com/{REPOSITORY}/releases/download/{tag}/{CHECKSUMS_NAME}",
    )

    asset = select_asset(assets, version, system=system, machine=machine)
    if asset is not None:
        release.asset_name = str(asset.get("name") or "")
        release.asset_url = str(asset.get("browser_download_url") or "")
        try:
            release.asset_size = int(asset.get("size") or 0)
        except (TypeError, ValueError):
            release.asset_size = 0
    return release


def _asset_url(assets: list, name: str) -> str:
    for asset in assets:
        if isinstance(asset, dict) and str(asset.get("name") or "") == name:
            return str(asset.get("browser_download_url") or "")
    return ""


# --------------------------------------------------------------------------
# Downloading
# --------------------------------------------------------------------------

def download_and_verify(release: Release, destination: str | os.PathLike,
                        progress: ProgressFn | None = None,
                        timeout: float = 30.0) -> Path:
    """Download the release archive and check it against the published digest.

    ``destination`` may be a directory, in which case the archive keeps the name
    it has on the release page, or the exact path to write. ``progress`` is
    called with bytes received and the total expected.

    ``SHA256SUMS.txt`` is fetched first, so the digest is known before the bytes
    arrive rather than being taken from whatever came with them. The archive is
    written to a ``.part`` file, hashed as it is written, and only renamed into
    place once the digest matches. A mismatch deletes the partial file and
    raises :class:`UpdateVerificationError`; nothing that failed this check is
    ever left somewhere it could be picked up later.

    On success ``release.sha256`` is filled in with the digest that was checked,
    so a caller can record it, and the path to the archive is returned.
    """
    if not release.has_asset:
        raise UpdateNotSupported(
            f"release {release.version} does not include a build for "
            f"{platform.system()} {platform.machine()}. The source is at "
            f"{release.notes_url}.")

    expected = _expected_digest(release, timeout=timeout)

    destination = Path(destination)
    if destination.is_dir():
        target = destination / release.asset_name
    else:
        target = destination
    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_name(target.name + ".part")

    digest = hashlib.sha256()
    received = 0
    try:
        with _fetch(release.asset_url, timeout=timeout) as response:
            total = release.asset_size or _content_length(response)
            with open(partial, "wb") as handle:
                for block in response.iter_content(CHUNK):
                    if not block:
                        continue
                    received += len(block)
                    if received > MAX_ARCHIVE_BYTES:
                        raise UpdateUnavailable(
                            f"the download from {release.asset_url} passed "
                            f"{_human(MAX_ARCHIVE_BYTES)} and was stopped. That is "
                            f"far larger than any build of this tool.")
                    digest.update(block)
                    handle.write(block)
                    if progress is not None:
                        progress(received, total)

        actual = digest.hexdigest()
        if actual != expected:
            raise UpdateVerificationError(
                f"the downloaded file does not match the digest published with the "
                f"release, so it will not be installed.\n"
                f"  file      {release.asset_name}\n"
                f"  expected  {expected}\n"
                f"  received  {actual}\n"
                f"Either the download was damaged, in which case trying again "
                f"usually fixes it, or the file served is not the file that was "
                f"published. Nothing has been changed on this machine.")
        if release.asset_size and received != release.asset_size:
            raise UpdateVerificationError(
                f"the release index says {release.asset_name} is "
                f"{release.asset_size} bytes and {received} arrived, yet the "
                f"digest matched. Treat the release metadata as unreliable and "
                f"download it by hand from {release.notes_url}.")

        os.replace(partial, target)
    finally:
        # A partial file that survived a failure is worse than no file: it looks
        # like a download that can be resumed or installed, and it is neither.
        if partial.exists():
            try:
                partial.unlink()
            except OSError:
                pass

    release.sha256 = expected
    return target


def _expected_digest(release: Release, timeout: float) -> str:
    """Read the digest for this archive out of the release's SHA256SUMS.txt."""
    text = _fetch_text(release.checksums_url, timeout=timeout)
    digests = parse_sha256sums(text)
    digest = digests.get(release.asset_name)
    if not digest:
        listed = ", ".join(sorted(digests)) or "nothing"
        raise UpdateVerificationError(
            f"{CHECKSUMS_NAME} for release {release.version} does not list "
            f"{release.asset_name}. It lists {listed}. Without a published digest "
            f"the download cannot be checked, so it will not be made.")
    return digest


def parse_sha256sums(text: str) -> dict[str, str]:
    """Parse ``sha256sum`` output into ``{file name: digest}``.

    The format is a 64-character hex digest, whitespace, then the file name,
    optionally prefixed with ``*`` for a binary read. Only the base name is
    kept, because the archives sit at the top level of the release and a path
    in the file would be meaningless here.
    """
    digests: dict[str, str] = {}
    for line in str(text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        digest, name = parts[0].lower(), parts[1].strip().lstrip("*").strip()
        if len(digest) != 64 or not all(c in "0123456789abcdef" for c in digest):
            continue
        digests[PurePosixPath(name.replace("\\", "/")).name] = digest
    return digests


# --------------------------------------------------------------------------
# Staging
# --------------------------------------------------------------------------

@dataclass
class StagedUpdate:
    """A verified new installation sitting beside the current one, not yet live.

    Nothing in the current installation has been touched at this point, and
    deleting :attr:`container` abandons the update completely.
    """

    version: str
    previous_version: str
    install_root: Path
    container: Path
    tree: Path
    previous: Path
    archive: Path | None = None
    scripts: list = field(default_factory=list)
    notes_file: Path | None = None

    def completion_command(self) -> str:
        """The exact command that finishes the update, to be shown to a person.

        This is what somebody types at a prompt, and the quoting is what a
        prompt needs. A caller starting the script itself should pass
        ``script_path`` below as a single argument to the process it starts
        rather than pasting this string through a shell: on Windows,
        ``cmd /c "<quoted path>"`` strips the outer quotes again and then trips
        over a space or an ``&`` in the path, whereas CreateProcess runs a .cmd
        given as one argument without any of that.
        """
        if os.name == "nt":
            return f'"{self.container / COMPLETE_WINDOWS}"'
        return f"sh {shlex.quote(str(self.container / COMPLETE_UNIX))}"

    @property
    def script_path(self) -> Path | None:
        """The completion script itself, or None if none could be written."""
        return self.scripts[0] if self.scripts else None

    def manual_commands(self) -> list[str]:
        """The two renames the script performs, for doing it without the script."""
        if os.name == "nt":
            return [f'move "{self.install_root}" "{self.previous}"',
                    f'move "{self.tree}" "{self.install_root}"']
        return [f"mv {shlex.quote(str(self.install_root))} "
                f"{shlex.quote(str(self.previous))}",
                f"mv {shlex.quote(str(self.tree))} "
                f"{shlex.quote(str(self.install_root))}"]


def stage_update(release: Release, archive: str | os.PathLike,
                 install_root: str | os.PathLike | None = None,
                 progress: ProgressFn | None = None) -> StagedUpdate:
    """Unpack a verified archive beside the installation and verify the result.

    Everything that can be checked is checked before this returns and nothing
    that is in use is touched. In order: the archive is re-hashed against
    ``release.sha256`` if that is known, extracted into a new sibling directory
    of the installation, the extracted tree is located and checked against the
    ``CONTENTS.sha256`` inside it, and the structure is checked for the
    executables it is supposed to contain.

    ``progress`` is called with files verified and files expected during the
    manifest check, which is the slow part.

    The returned :class:`StagedUpdate` describes where everything is and what
    command finishes the job. Nothing is swapped here - see the module docstring
    for why that is somebody else's process's problem.
    """
    current = installation()
    if not current.is_standalone:
        raise UpdateNotSupported(
            f"this is a Python package installation, not a standalone build, so "
            f"its files belong to pip and are not replaced from here. Upgrade it "
            f"with:\n    {pip_upgrade_command()}")

    root = Path(install_root).resolve() if install_root else current.root
    if root is None:
        raise UpdateNotSupported(
            "the directory this build was installed into could not be determined.")
    if not (root / CONTENTS_MANIFEST).is_file():
        raise UpdateNotSupported(
            f"{root} does not contain {CONTENTS_MANIFEST}, so it does not look "
            f"like an installation this tool produced. Refusing to replace a "
            f"directory it cannot identify. Download the new version from "
            f"{release.notes_url} and extract it yourself.")

    archive = Path(archive).resolve()
    if not archive.is_file():
        raise UpdateStagingError(f"the downloaded archive is not there: {archive}")
    if release.sha256:
        actual = sha256_file(archive)
        if actual != release.sha256:
            raise UpdateVerificationError(
                f"{archive.name} no longer matches the digest it was downloaded "
                f"with.\n  expected  {release.sha256}\n  found     {actual}\n"
                f"It has been changed since. Delete it and download it again.")

    container = root.parent / f"{root.name}.update-{release.version}"
    try:
        if container.exists():
            # Named after this exact version, so it is a previous attempt at this
            # same update and there is nothing in it worth keeping.
            shutil.rmtree(container)
        container.mkdir(parents=True)
    except OSError as exc:
        raise UpdateStagingError(
            f"could not create {container}: {exc}. The new version has to be "
            f"unpacked next to the old one so that putting it in place is a "
            f"rename rather than a copy across volumes. If the installation is "
            f"somewhere only an administrator can write, move it somewhere you "
            f"own, or extract the archive yourself.") from exc

    extract_dir = container / "extract"
    try:
        _extract_zip(archive, extract_dir)
        found = _locate_tree(extract_dir)
        tree = container / "new"
        os.replace(found, tree)
        shutil.rmtree(extract_dir, ignore_errors=True)
        verify_tree(tree, progress=progress)
        _check_structure(tree)
    except Exception:
        shutil.rmtree(container, ignore_errors=True)
        raise

    staged = StagedUpdate(
        version=release.version,
        previous_version=current.version,
        install_root=root,
        container=container,
        tree=tree,
        previous=_unique_sibling(root, f"previous-{current.version}"),
        archive=archive,
    )
    _write_completion_scripts(staged)
    return staged


def verify_tree(tree: str | os.PathLike, progress: ProgressFn | None = None) -> None:
    """Check an extracted installation against the CONTENTS.sha256 inside it.

    Three things are wrong and all three are looked for: a file listed in the
    manifest that is absent, a file whose contents differ, and a file present in
    the tree that the manifest does not list. The third matters as much as the
    other two - an archive that carries something the build did not produce is
    not the build that was published, whatever its own manifest says about the
    parts it does list.

    ``progress`` is called with files checked and files listed.
    """
    tree = Path(tree)
    manifest = tree / CONTENTS_MANIFEST
    if not manifest.is_file():
        raise UpdateVerificationError(
            f"the extracted build has no {CONTENTS_MANIFEST}, so there is nothing "
            f"to check it against. Every build this project publishes has one.")

    expected: dict[str, str] = {}
    for line in manifest.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2 and len(parts[0]) == 64:
            expected[parts[1].strip()] = parts[0].lower()

    if not expected:
        raise UpdateVerificationError(
            f"{CONTENTS_MANIFEST} in the extracted build lists no files.")

    problems: list[str] = []
    done = 0
    for relative, digest in sorted(expected.items()):
        path = tree / relative
        if not path.is_file():
            problems.append(f"missing    {relative}")
        elif sha256_file(path) != digest:
            problems.append(f"altered    {relative}")
        done += 1
        if progress is not None:
            progress(done, len(expected))

    # build.py leaves the manifest and the two verifiers out of the manifest,
    # so they are the only files allowed to be present without being listed.
    known = set(expected) | {CONTENTS_MANIFEST, VERIFY_WINDOWS, VERIFY_UNIX}
    for path in tree.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(tree).as_posix()
        if relative not in known:
            problems.append(f"unexpected {relative}")

    if problems:
        shown = "\n  ".join(problems[:20])
        more = (f"\n  ... and {len(problems) - 20} more"
                if len(problems) > 20 else "")
        raise UpdateVerificationError(
            f"the extracted build does not match its own {CONTENTS_MANIFEST} and "
            f"will not be installed:\n  {shown}{more}\n"
            f"{len(expected)} file(s) were listed. Delete the update folder and "
            f"download it again.")


def _check_structure(tree: Path) -> None:
    """Confirm the extracted tree contains the executables it should.

    The manifest check proves the tree is the tree that was published. This
    proves the tree that was published is an installation of this program and
    not, say, the source archive GitHub attaches to every release.
    """
    if tree.suffix == ".app" or (tree / "Contents" / "MacOS").is_dir():
        wanted = [Path("Contents") / "MacOS" / f"{DIST_NAME}-gui"]
    elif os.name == "nt":
        wanted = [Path(f"{DIST_NAME}.exe"), Path(f"{DIST_NAME}-gui.exe")]
    else:
        wanted = [Path(DIST_NAME), Path(f"{DIST_NAME}-gui")]

    missing = [str(name) for name in wanted if not (tree / name).is_file()]
    if missing:
        raise UpdateStagingError(
            f"the extracted build does not contain {', '.join(missing)}, so it is "
            f"not an installation of this program for this platform. Nothing has "
            f"been changed.")


def _locate_tree(extract_dir: Path) -> Path:
    """Find the installation directory inside what was extracted.

    A Windows or Linux archive holds one ``deauth-correlator/`` directory; the
    macOS archive holds ``deauth-correlator.app``. Rather than assuming either,
    the directory that contains a CONTENTS.sha256 is the one that counts.
    """
    if (extract_dir / CONTENTS_MANIFEST).is_file():
        return extract_dir
    candidates = [child for child in sorted(extract_dir.iterdir())
                  if child.is_dir() and (child / CONTENTS_MANIFEST).is_file()]
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        raise UpdateStagingError(
            f"no {CONTENTS_MANIFEST} was found in the archive, at its top level or "
            f"one directory down. This is not an archive this tool published.")
    raise UpdateStagingError(
        f"the archive contains {len(candidates)} installation directories "
        f"({', '.join(c.name for c in candidates)}) and there is no way to tell "
        f"which one is meant.")


def _unique_sibling(root: Path, label: str) -> Path:
    """A directory name beside ``root`` that nothing occupies yet."""
    candidate = root.parent / f"{root.name}.{label}"
    if not candidate.exists():
        return candidate
    stamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return root.parent / f"{root.name}.{label}-{stamp}"


# --------------------------------------------------------------------------
# Extraction
# --------------------------------------------------------------------------

def _extract_zip(archive: Path, into: Path) -> None:
    """Extract a zip, refusing anything that would write outside ``into``.

    ``ZipFile.extractall`` is not used, for two reasons that pull in opposite
    directions. It does not restore the executable bit or symbolic links, which
    matters on macOS and Linux where a build extracted without them will not run
    and an .app bundle will not even open. And a zip is free to name a member
    ``../../anything``, which extractall in current Python does neutralise but
    silently - here an archive that tries it is a reason to stop, not something
    to quietly work around.
    """
    into.mkdir(parents=True, exist_ok=True)
    try:
        handle = zipfile.ZipFile(archive)
    except (zipfile.BadZipFile, OSError) as exc:
        raise UpdateStagingError(
            f"{archive.name} is not a readable zip archive: {exc}") from exc

    with handle as zf:
        members = zf.infolist()
        total = 0
        for info in members:
            if _ignored_member(info.filename):
                continue
            _safe_parts(info.filename, archive.name)
            total += info.file_size
        if total > MAX_EXTRACTED_BYTES:
            raise UpdateStagingError(
                f"{archive.name} expands to {_human(total)}, past the "
                f"{_human(MAX_EXTRACTED_BYTES)} this will unpack. Extract it "
                f"yourself if that is genuinely what the release contains.")

        into_real = into.resolve()
        for info in members:
            if _ignored_member(info.filename):
                continue
            parts = _safe_parts(info.filename, archive.name)
            target = _contained(into.joinpath(*parts), into_real,
                                info.filename, archive.name)
            mode = info.external_attr >> 16
            try:
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)

                if stat.S_ISLNK(mode):
                    _write_symlink(zf, info, target, into_real, archive.name)
                    continue
                with zf.open(info) as source, open(target, "wb") as sink:
                    shutil.copyfileobj(source, sink, CHUNK)
            except OSError as exc:
                raise UpdateStagingError(
                    f"{archive.name} contains a member that could not be written "
                    f"({info.filename!r}): {exc}. Nothing has been installed.") from exc
            # Permission bits are only meaningful when the archive was written on
            # a system that has them, and only the execute bit actually matters.
            if os.name != "nt" and mode & 0o777:
                try:
                    os.chmod(target, mode & 0o777)
                except OSError:
                    pass


def _ignored_member(name: str) -> bool:
    """Metadata macOS puts in an archive that is not part of the build.

    ``ditto`` sequesters resource forks into ``__MACOSX``. They are not in
    CONTENTS.sha256, so extracting them would make the tree fail its own
    manifest check for no reason.
    """
    return name.startswith("__MACOSX/") or PurePosixPath(name).name == ".DS_Store"


def _safe_parts(name: str, archive_name: str) -> tuple[str, ...]:
    """Split a zip member name, rejecting anything that escapes the tree."""
    # A backslash is the form a traversal aimed at Windows takes. Current
    # CPython rewrites it to a forward slash while reading the central
    # directory, so this may well never fire - which is exactly why it is here
    # rather than assumed: nothing below should depend on that normalisation
    # still happening in the Python this ends up running on.
    if "\\" in name:
        raise UpdateStagingError(
            f"{archive_name} contains a member with a backslash in its name "
            f"({name!r}). Zip names use forward slashes; this one is malformed.")
    parts = tuple(part for part in PurePosixPath(name).parts if part not in ("", "."))
    if not parts:
        raise UpdateStagingError(f"{archive_name} contains a member with no name.")
    # Every component is checked for a drive letter, not just the first. This is
    # not pedantry: pathlib treats any component carrying a drive as a fresh
    # anchor, so joinpath("a", "b", "Z:", "evil") is Z:evil - the whole staging
    # path is discarded and the write lands on another volume. Checking only the
    # start of the member name leaves that wide open.
    drive_part = next((p for p in parts if PureWindowsPath(p).drive), None)
    if (name.startswith("/") or drive_part is not None or ".." in parts):
        raise UpdateStagingError(
            f"{archive_name} contains a member that would be written outside the "
            f"directory it is extracted into ({name!r}). Nothing has been "
            f"extracted. This is not an archive to install.")
    return parts


def _contained(target: Path, into_real: Path, name: str, archive_name: str) -> Path:
    """Return ``target`` having checked where it *really* lands.

    ``_safe_parts`` reads the member name; this reads the filesystem. The two
    catch different things, and the second is the one that matters once an
    archive contains symbolic links: a link written by an earlier member can
    make a later member's nominal path and its real path disagree, so a name
    that looks entirely innocent resolves somewhere else. ``resolve()`` is
    non-strict, so the part of the path that exists is resolved through any
    links and the part that does not yet exist is kept as written - which is
    exactly the question being asked, and it is asked before anything is
    created.
    """
    real = Path(target).resolve()
    if real != into_real and not real.is_relative_to(into_real):
        raise UpdateStagingError(
            f"{archive_name} contains a member that resolves outside the "
            f"directory it is extracted into ({name!r} -> {real}). This can only "
            f"happen through a symbolic link the archive itself created. Nothing "
            f"has been installed.")
    return target


def _write_symlink(zf: zipfile.ZipFile, info: zipfile.ZipInfo, target: Path,
                   into_real: Path, archive_name: str) -> None:
    """Recreate a symbolic link, having checked it points inside the tree.

    An .app bundle is full of these - every framework has Versions/Current - and
    a bundle whose links were extracted as ordinary files containing the link
    text will not launch.
    """
    destination = zf.read(info).decode("utf-8", errors="replace")
    if not destination:
        raise UpdateStagingError(
            f"{archive_name} contains an empty symbolic link at {info.filename!r}.")
    # The link text is resolved against where the link's directory *really* is,
    # not against the path the member happens to spell. Those two diverge as
    # soon as an earlier member of the same archive is a link that shortens the
    # path, and resolving against the nominal parent then mis-measures how far
    # up "../.." reaches - which is enough to call a link that leaves the tree
    # an inside one. An absolute destination escapes by definition.
    real_parent = Path(target.parent).resolve()
    resolved = Path(os.path.normpath(os.path.join(str(real_parent), destination)))
    if (os.path.isabs(destination)
            or not real_parent.is_relative_to(into_real)
            or not resolved.is_relative_to(into_real)):
        raise UpdateStagingError(
            f"{archive_name} contains a symbolic link pointing outside the "
            f"extracted tree ({info.filename!r} -> {destination!r}). Nothing has "
            f"been installed.")
    try:
        os.symlink(destination, target)
    except OSError as exc:
        raise UpdateStagingError(
            f"could not recreate the symbolic link {info.filename!r} that the "
            f"archive contains: {exc}. On Windows this needs Developer Mode or "
            f"an elevated prompt; on macOS and Linux it should not happen.") from exc


# --------------------------------------------------------------------------
# Completing the update
# --------------------------------------------------------------------------

def complete_update(staged: StagedUpdate, reverify: bool = True) -> Path:
    """Perform the swap, from a process that is not the one being replaced.

    This refuses to run when the calling process is executing out of the
    directory it would move, which is the case that cannot be made safe and the
    reason the generated scripts exist. Use
    :meth:`StagedUpdate.completion_command` there.

    The two renames happen in the order that keeps a working installation on
    disk at every moment. If the second fails the first is undone. If undoing it
    also fails the error names the directory the installation is now in, because
    at that point the only thing that helps is knowing where the files are.

    Returns the installation path, which now holds the new version.
    """
    if running_from(staged.install_root):
        raise UpdateNotSupported(
            f"this process is running out of {staged.install_root}, which is the "
            f"directory being replaced, so it cannot perform the swap. Quit the "
            f"program and run:\n    {staged.completion_command()}")
    if not staged.tree.is_dir():
        raise UpdateStagingError(
            f"the staged build is not at {staged.tree}. Stage the update again.")
    if staged.previous.exists():
        raise UpdateStagingError(
            f"{staged.previous} already exists, and that is where the installation "
            f"being replaced has to go. Move or delete it first.")

    if reverify:
        verify_tree(staged.tree)

    try:
        os.replace(staged.install_root, staged.previous)
    except OSError as exc:
        raise UpdateStagingError(
            f"could not move {staged.install_root} aside: {exc}. Nothing has been "
            f"changed.") from exc

    try:
        os.replace(staged.tree, staged.install_root)
    except OSError as exc:
        try:
            os.replace(staged.previous, staged.install_root)
        except OSError as rollback_exc:
            raise UpdateStagingError(
                f"the new build could not be installed ({exc}) and the previous "
                f"installation could not be put back ({rollback_exc}). It is "
                f"intact and it is at:\n    {staged.previous}\nRename that "
                f"directory back to:\n    {staged.install_root}") from exc
        raise UpdateStagingError(
            f"the new build could not be moved into place: {exc}. The previous "
            f"installation has been put back and nothing was changed.") from exc

    return staged.install_root


def roll_back(install_root: str | os.PathLike,
              previous: str | os.PathLike) -> Path | None:
    """Put a kept ``.previous`` installation back where it came from.

    Returns where the installation that was displaced ended up, or None if there
    was nothing at the installation path to displace.
    """
    install_root = Path(install_root)
    previous = Path(previous)
    if not (previous / CONTENTS_MANIFEST).is_file():
        raise UpdateStagingError(
            f"{previous} does not contain {CONTENTS_MANIFEST}, so it is not a "
            f"kept installation and will not be restored over a working one.")
    if running_from(install_root):
        raise UpdateNotSupported(
            f"this process is running out of {install_root}, so it cannot replace "
            f"it. Quit the program first.")

    displaced: Path | None = None
    if install_root.exists():
        displaced = _unique_sibling(install_root, "rolled-back")
        os.replace(install_root, displaced)
    try:
        os.replace(previous, install_root)
    except OSError:
        if displaced is not None:
            os.replace(displaced, install_root)
        raise
    return displaced


def discard_staged_update(staged: StagedUpdate) -> None:
    """Delete a staged update. The installation is untouched either way."""
    shutil.rmtree(staged.container, ignore_errors=True)


def completion_instructions(staged: StagedUpdate) -> str:
    """What to tell the operator once an update is staged and verified."""
    lines = [
        f"{__tool_name__} {staged.version} has been downloaded and checked.",
        "",
        "Both digests matched: the archive against the SHA256SUMS.txt published",
        f"with the release, and every file in it against the "
        f"{CONTENTS_MANIFEST} inside it.",
        "",
        "It is not installed yet. A running program cannot replace its own",
        "files, so the last step happens after this program has closed.",
        "",
    ]
    if staged.script_path is not None:
        lines += [
            "Close the program, then run:",
            "",
            f"    {staged.completion_command()}",
            "",
            "That script uses no network. It renames the current installation to",
            f"    {staged.previous}",
            "and the new build into its place. If anything goes wrong it puts the",
            "old one back.",
            "",
            "To do it without the script, run these two instead:",
        ]
    else:
        lines += [
            "Close the program, then run these two commands. The first moves the",
            "installation aside, keeping it; the second puts the new build in its",
            "place. If the second fails, undo the first to get back to where you",
            "started.",
            "",
        ]
    lines += [f"    {command}" for command in staged.manual_commands()]
    lines += [
        "",
        "To abandon the update, delete:",
        f"    {staged.container}",
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------
# The scripts that finish the job
# --------------------------------------------------------------------------
#
# These are written from templates for the same reason packaging/build.py writes
# verify-install.ps1 and verify-install.sh from templates: they have to work when
# the program they belong to is not running, and in a standalone build there is
# no Python interpreter and no source on disk to run one from. A shell script is
# the only thing guaranteed to be there.
#
# Substitution is a plain textual replacement of @@TOKEN@@ rather than str.format
# or a percent template, because both scripts are full of $, % and {} that mean
# something to the shell and nothing to Python.

COMPLETE_UPDATE_CMD = r"""@echo off
rem Finish an update of deauth-correlator to @@VERSION@@.
rem
rem The download has already happened and both digests have already been
rem checked: the archive against the SHA256SUMS.txt published with the release,
rem and every extracted file against the CONTENTS.sha256 that ships inside it.
rem This script uses no network. It does two renames and nothing else:
rem
rem     the current installation  ->  the .previous- name below
rem     the new build             ->  the installation path
rem
rem It is a separate script because Windows will not rename a directory while an
rem executable inside it is loaded, so the program being replaced cannot do
rem this itself. Run it after closing deauth-correlator, or start it and then
rem close the program: the first rename is retried for about a minute.
rem
rem Exit codes:
rem   0  the new version is installed
rem   1  nothing was changed
rem   2  the swap failed and so did the rollback - read the message

setlocal enabledelayedexpansion
set "INSTALL=@@INSTALL@@"
set "STAGED=@@STAGED@@"
set "PREVIOUS=@@PREVIOUS@@"
set "CONTAINER=@@CONTAINER@@"

if not exist "!STAGED!\@@MANIFEST@@" (
    echo The new build is not where this script expects it:
    echo   !STAGED!
    echo Nothing has been changed.
    exit /b 1
)
if not exist "!INSTALL!\@@MANIFEST@@" (
    echo This does not look like a deauth-correlator installation:
    echo   !INSTALL!
    echo Nothing has been changed.
    exit /b 1
)
if exist "!PREVIOUS!" (
    echo Something is already saved at:
    echo   !PREVIOUS!
    echo That is where the installation being replaced has to go. Move or delete
    echo it and run this again. Nothing has been changed.
    exit /b 1
)

echo Re-checking the new build against its own manifest...
powershell -NoProfile -ExecutionPolicy Bypass -File "!STAGED!\@@VERIFY_WINDOWS@@"
if errorlevel 9009 (
    echo   PowerShell is not available, so this check was skipped. The same check
    echo   passed when the update was downloaded.
) else if errorlevel 1 (
    echo The new build no longer matches its manifest, so it will not be
    echo installed. Delete the update folder and download the update again.
    echo Nothing has been changed.
    exit /b 1
)

echo Moving the current installation aside...
for /L %%i in (1,1,30) do (
    move "!INSTALL!" "!PREVIOUS!" >nul 2>&1
    if not errorlevel 1 goto :moved
    ping -n 3 127.0.0.1 >nul
)
echo Could not move:
echo   !INSTALL!
echo Windows will not rename a folder while a program inside it is running.
echo Close deauth-correlator - the window, and any command prompt running it -
echo and start this script again. Nothing has been changed.
exit /b 1

:moved
echo Installing the new version...
move "!STAGED!" "!INSTALL!" >nul 2>&1
if errorlevel 1 (
    echo The new build could not be moved into place. Putting the previous
    echo installation back...
    move "!PREVIOUS!" "!INSTALL!" >nul 2>&1
    if errorlevel 1 (
        echo THE ROLLBACK ALSO FAILED. Your installation is intact, but it is
        echo now at:
        echo   !PREVIOUS!
        echo Rename that folder back to:
        echo   !INSTALL!
        exit /b 2
    )
    echo The previous installation is back in place. Nothing was updated.
    exit /b 1
)

echo.
echo deauth-correlator @@VERSION@@ is installed at:
echo   !INSTALL!
echo The version it replaced is kept at:
echo   !PREVIOUS!
echo To go back, delete the new folder and rename that one back.
echo Once you are satisfied, this folder can be deleted:
echo   !CONTAINER!
exit /b 0
"""

COMPLETE_UPDATE_SH = r"""#!/bin/sh
# Finish an update of deauth-correlator to @@VERSION@@.
#
# The download has already happened and both digests have already been checked:
# the archive against the SHA256SUMS.txt published with the release, and every
# extracted file against the CONTENTS.sha256 that ships inside it. This script
# uses no network. It does two renames and nothing else:
#
#     the current installation  ->  the .previous- name below
#     the new build             ->  the installation path
#
# It is a separate script because the program being replaced must not be
# running. Renaming the directory would succeed on this platform, and that is
# the problem rather than the solution: a one-directory PyInstaller build loads
# most of what it needs out of that directory on demand, so a running program
# would start loading pieces of a different build.
#
#   sh complete-update.sh        wait for the program to exit, then swap
#   sh complete-update.sh now    swap immediately, without waiting
#
# Exit codes: 0 installed, 1 nothing changed, 2 the swap failed and so did the
# rollback.

set -u

INSTALL=@@INSTALL@@
STAGED=@@STAGED@@
PREVIOUS=@@PREVIOUS@@
CONTAINER=@@CONTAINER@@
VERSION=@@VERSION_Q@@
WAIT_PID=@@PID@@

if [ "${1:-}" != "now" ] && [ "$WAIT_PID" -gt 0 ]; then
    waited=0
    while kill -0 "$WAIT_PID" 2>/dev/null; do
        if [ "$waited" -ge 120 ]; then
            echo "deauth-correlator (pid $WAIT_PID) is still running after two"
            echo "minutes. Quit it and run this again. If it is not running, the"
            echo "process id has been reused by something else, in which case run:"
            echo "  sh \"$0\" now"
            echo "Nothing has been changed."
            exit 1
        fi
        sleep 2
        waited=$((waited + 2))
    done
fi

if [ ! -f "$STAGED/@@MANIFEST@@" ]; then
    echo "The new build is not where this script expects it:"
    echo "  $STAGED"
    echo "Nothing has been changed."
    exit 1
fi
if [ ! -f "$INSTALL/@@MANIFEST@@" ]; then
    echo "This does not look like a deauth-correlator installation:"
    echo "  $INSTALL"
    echo "Nothing has been changed."
    exit 1
fi
if [ -e "$PREVIOUS" ]; then
    echo "Something is already saved at:"
    echo "  $PREVIOUS"
    echo "That is where the installation being replaced has to go. Move or delete"
    echo "it and run this again. Nothing has been changed."
    exit 1
fi

echo "Re-checking the new build against its own manifest..."
if [ ! -f "$STAGED/@@VERIFY_UNIX@@" ] || ! command -v sh >/dev/null 2>&1; then
    # Not being able to run the checker is a different thing from the checker
    # saying no, and only the second is a reason to stop. This same check
    # already passed when the update was downloaded.
    echo "The manifest check could not be re-run here, so it was skipped."
elif ! sh "$STAGED/@@VERIFY_UNIX@@"; then
    echo "The new build no longer matches its manifest, so it will not be"
    echo "installed. Delete the update folder and download the update again."
    echo "Nothing has been changed."
    exit 1
fi

echo "Moving the current installation aside..."
if ! mv "$INSTALL" "$PREVIOUS"; then
    echo "Could not move $INSTALL. Nothing has been changed."
    exit 1
fi

echo "Installing the new version..."
if ! mv "$STAGED" "$INSTALL"; then
    echo "The new build could not be moved into place. Putting the previous"
    echo "installation back..."
    if ! mv "$PREVIOUS" "$INSTALL"; then
        echo "THE ROLLBACK ALSO FAILED. Your installation is intact, but it is"
        echo "now at:"
        echo "  $PREVIOUS"
        echo "Rename it back to:"
        echo "  $INSTALL"
        exit 2
    fi
    echo "The previous installation is back in place. Nothing was updated."
    exit 1
fi

echo ""
echo "deauth-correlator $VERSION is installed at:"
echo "  $INSTALL"
echo "The version it replaced is kept at:"
echo "  $PREVIOUS"
echo "To go back, delete the new folder and rename that one back."
echo "Once you are satisfied, this folder can be deleted:"
echo "  $CONTAINER"
exit 0
"""

# cmd.exe expands %VAR% while it parses a line and eats ! when delayed expansion
# is on, and there is no equivalent of shlex.quote to escape either. A path
# containing one of these cannot be put into a batch file correctly, so the
# batch file is not written at all and UPDATE.txt says why. Parentheses, which
# are the character that actually turns up in Windows paths, are handled: every
# expansion inside a block uses !VAR! precisely so that "Program Files (x86)"
# does not close the block early.
_CMD_UNSAFE = ('"', "%", "!", "\r", "\n")


def _write_completion_scripts(staged: StagedUpdate) -> None:
    """Write the finishing script for this platform, and the notes beside it."""
    substitutions = {
        "@@VERSION@@": staged.version,
        "@@MANIFEST@@": CONTENTS_MANIFEST,
        "@@VERIFY_WINDOWS@@": VERIFY_WINDOWS,
        "@@VERIFY_UNIX@@": VERIFY_UNIX,
    }
    notes: list[str] = []

    if os.name == "nt":
        paths = (str(staged.install_root), str(staged.tree), str(staged.previous),
                 str(staged.container))
        offending = [c for c in _CMD_UNSAFE if any(c in p for p in paths)]
        if offending:
            notes.append(
                f"(No {COMPLETE_WINDOWS} was written for this update: one of the "
                f"paths involved contains {' '.join(repr(c) for c in offending)}, "
                f"which cmd.exe cannot be given literally, and a batch file that "
                f"is subtly wrong about which directory it is moving is worse "
                f"than no batch file. The two commands above are the whole of "
                f"what it would have done.)")
        else:
            script = COMPLETE_UPDATE_CMD
            for token, value in {**substitutions,
                                 "@@INSTALL@@": str(staged.install_root),
                                 "@@STAGED@@": str(staged.tree),
                                 "@@PREVIOUS@@": str(staged.previous),
                                 "@@CONTAINER@@": str(staged.container)}.items():
                script = script.replace(token, value)
            path = staged.container / COMPLETE_WINDOWS
            # CRLF: cmd.exe mis-parses labels and goto in a file with bare
            # newlines, and this file depends on both.
            path.write_text(script, encoding="utf-8", newline="\r\n")
            staged.scripts.append(path)
    else:
        script = COMPLETE_UPDATE_SH
        # The process that must exit before the swap is this one, when this one
        # is the installation being replaced. A caller running from anywhere
        # else has nothing to wait for.
        pid = os.getpid() if running_from(staged.install_root) else 0
        for token, value in {**substitutions,
                             "@@INSTALL@@": shlex.quote(str(staged.install_root)),
                             "@@STAGED@@": shlex.quote(str(staged.tree)),
                             "@@PREVIOUS@@": shlex.quote(str(staged.previous)),
                             "@@CONTAINER@@": shlex.quote(str(staged.container)),
                             "@@VERSION_Q@@": shlex.quote(staged.version),
                             "@@PID@@": str(pid)}.items():
            script = script.replace(token, value)
        path = staged.container / COMPLETE_UNIX
        path.write_text(script, encoding="utf-8", newline="\n")
        try:
            path.chmod(path.stat().st_mode | 0o111)
        except OSError:
            pass
        staged.scripts.append(path)

    text = completion_instructions(staged)
    if notes:
        text += "\n\n" + "\n".join(notes)
    notes_file = staged.container / UPDATE_NOTES
    notes_file.write_text(text + "\n", encoding="utf-8")
    staged.notes_file = notes_file


# --------------------------------------------------------------------------
# Network
# --------------------------------------------------------------------------

def _requests():
    """Import requests when it is actually needed, not at module import.

    requests is an optional dependency, and this module is imported by code that
    has to work without it. In a standalone build it is always present.
    """
    try:
        import requests
    except ImportError as exc:
        raise UpdateUnavailable(
            f"checking for updates needs the 'requests' package, which is not "
            f"installed in this Python. Install it with 'pip install requests', "
            f"or look at {RELEASES_PAGE_URL} by hand.") from exc
    return requests


def _check_url(url: str) -> None:
    """Refuse any URL outside UPDATE_ENDPOINTS, including one reached by redirect."""
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise UpdateUnavailable(
            f"refusing to fetch {url}: this module only uses HTTPS.")
    host = (parts.hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        raise UpdateUnavailable(
            f"refusing to contact {host or 'an unnamed host'}. This module only "
            f"talks to {', '.join(sorted(ALLOWED_HOSTS))}, and it will not follow "
            f"a redirect anywhere else. If GitHub has changed where it serves "
            f"releases from, download the new version by hand from "
            f"{RELEASES_PAGE_URL}.")
    # urlsplit defers parsing the port until it is read, and raises ValueError
    # for one that is not a number or is out of range. That would escape this
    # module as a bare traceback, past every caller's "except UpdateError".
    try:
        port = parts.port
    except ValueError:
        raise UpdateUnavailable(
            f"refusing to fetch {url}: it does not name a valid port.") from None
    if port not in (None, 443):
        raise UpdateUnavailable(
            f"refusing to fetch {url}: it names port {port} rather than 443.")


@contextmanager
def _fetch(url: str, timeout: float) -> Iterator:
    """GET a URL, following redirects by hand so every hop can be checked.

    requests follows redirects itself, which would mean the host allow-list only
    applied to the first request. Redirects are switched off and walked here
    instead, so a redirect to an unlisted host stops the download rather than
    silently completing it from somewhere else. Release-asset URLs on github.com
    always redirect, so this path is the normal one, not an edge case.
    """
    requests = _requests()
    session = requests.Session()
    # As in camera/onvif_min.py: a stock session honours HTTP_PROXY and
    # HTTPS_PROXY, and UPDATE_ENDPOINTS would then be a list of hosts this
    # module intends to reach rather than hosts it actually connects to.
    session.trust_env = False
    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github+json, application/octet-stream;q=0.9, */*;q=0.8",
        "X-GitHub-Api-Version": "2022-11-28",
    })

    response = None
    try:
        current = url
        for _hop in range(MAX_REDIRECTS + 1):
            _check_url(current)
            try:
                response = session.get(current, timeout=timeout, stream=True,
                                       allow_redirects=False)
            except requests.RequestException as exc:
                raise UpdateUnavailable(_network_message(current, exc)) from exc
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("Location", "")
                response.close()
                response = None
                if not location:
                    raise UpdateUnavailable(
                        f"{current} answered with a redirect that names no "
                        f"destination.")
                current = urljoin(current, location)
                continue
            break
        else:
            raise UpdateUnavailable(
                f"{url} redirected more than {MAX_REDIRECTS} times without "
                f"arriving anywhere.")

        _raise_for_status(response, current)
        yield response
    finally:
        if response is not None:
            response.close()
        session.close()


def _raise_for_status(response, url: str) -> None:
    status = response.status_code
    if status == 200:
        return
    if status == 404:
        raise UpdateUnavailable(
            f"{url} does not exist (HTTP 404). Either no release has been "
            f"published yet or the project has moved. {RELEASES_PAGE_URL} is the "
            f"place to look.")
    if status in (403, 429):
        remaining = response.headers.get("x-ratelimit-remaining")
        if remaining == "0":
            raise UpdateUnavailable(
                "GitHub is rate-limiting this address (HTTP "
                f"{status}). Unauthenticated callers get 60 requests an hour, "
                "shared by everything behind the same address. Try again later, "
                f"or look at {RELEASES_PAGE_URL}.")
        raise UpdateUnavailable(
            f"GitHub refused the request for {url} (HTTP {status}).")
    if 500 <= status < 600:
        raise UpdateUnavailable(
            f"GitHub returned HTTP {status} for {url}. That is a fault at their "
            f"end; nothing here needs fixing and trying later usually works.")
    raise UpdateUnavailable(f"{url} returned HTTP {status}.")


def _read_capped(response, limit: int, what: str) -> bytes:
    chunks: list[bytes] = []
    total = 0
    for block in response.iter_content(64 * 1024):
        total += len(block)
        if total > limit:
            raise UpdateUnavailable(
                f"{what} is larger than {_human(limit)}, which it has no reason to "
                f"be. It has not been read.")
        chunks.append(block)
    return b"".join(chunks)


def _fetch_text(url: str, timeout: float) -> str:
    with _fetch(url, timeout=timeout) as response:
        raw = _read_capped(response, MAX_METADATA_BYTES, url)
    return raw.decode("utf-8", errors="replace")


def _fetch_json(url: str, timeout: float) -> dict:
    text = _fetch_text(url, timeout=timeout)
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise UpdateUnavailable(
            f"{url} did not return readable JSON. If this machine is behind a "
            f"captive portal or a filtering proxy, that is usually what answered "
            f"instead of GitHub.") from exc
    if not isinstance(data, dict):
        raise UpdateUnavailable(f"{url} returned {type(data).__name__}, not a "
                                f"release description.")
    return data


def _network_message(url: str, exc: Exception) -> str:
    """A short, actionable message instead of a wrapped urllib3 repr."""
    requests = _requests()
    host = urlsplit(url).hostname or url
    if isinstance(exc, requests.exceptions.SSLError):
        return (f"the TLS connection to {host} could not be verified. On a network "
                f"that inspects HTTPS traffic this is expected; check for updates "
                f"from somewhere else, or look at {RELEASES_PAGE_URL}.")
    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return f"{host} did not answer in time. There may be no internet connection."
    if isinstance(exc, requests.exceptions.ReadTimeout):
        return f"{host} accepted the connection but stopped sending data."
    if isinstance(exc, requests.exceptions.ProxyError):
        return (f"a proxy refused the connection to {host}. This module does not "
                f"use the proxy settings in the environment, deliberately - see "
                f"UPDATE_ENDPOINTS in update.py.")
    if isinstance(exc, requests.exceptions.ConnectionError):
        return (f"could not reach {host}. There may be no internet connection, or "
                f"a firewall may be blocking it. Nothing else about this tool "
                f"needs the internet.")
    return f"could not reach {host} ({exc.__class__.__name__})."


def _content_length(response) -> int:
    try:
        return int(response.headers.get("Content-Length") or 0)
    except (TypeError, ValueError):
        return 0


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def sha256_file(path: str | os.PathLike) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            block = handle.read(CHUNK)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _human(size: int) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{int(value)} B" if unit == "B" else f"{value:,.1f} {unit}"
        value /= 1024
    return f"{value:,.1f} GiB"
