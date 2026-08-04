"""Chain-of-custody records for input and output files.

Every file the tool reads or writes is hashed with SHA-256 and described with
size, modification time and the role it played. The resulting records go into
report.md and MANIFEST.json so a reader can verify that the copy in the
evidence bundle is bit-identical to what was analyzed.
"""

from __future__ import annotations

import hashlib
import os
import platform
import socket
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, __tool_name__

CHUNK = 1024 * 1024


@dataclass
class FileRecord:
    path: str
    role: str
    sha256: str
    size_bytes: int
    modified_utc: str
    parser: str = ""
    rows: int = 0
    note: str = ""

    @property
    def name(self) -> str:
        return Path(self.path).name

    def short(self) -> str:
        return f"{self.sha256[:16]}…"


def sha256_file(path: str | os.PathLike) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(CHUNK)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def record_file(path: str | os.PathLike, role: str, parser: str = "",
                rows: int = 0, note: str = "",
                sha256: str | None = None) -> FileRecord:
    """Describe one file for the chain of custody.

    ``sha256`` accepts a digest taken earlier. Callers that must hash before
    reading - which is what the report and the evidence bundle tell the reader
    happened - pass the value they already computed rather than making this
    function read the file a second time.
    """
    p = Path(path)
    st = p.stat()
    return FileRecord(
        path=str(p.resolve()),
        role=role,
        sha256=sha256 if sha256 is not None else sha256_file(p),
        size_bytes=st.st_size,
        modified_utc=datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
        .isoformat(timespec="seconds"),
        parser=parser,
        rows=rows,
        note=note,
    )


def verify_copy(source: FileRecord, copied_path: str | os.PathLike) -> bool:
    """Confirm a file copied into an evidence bundle still hashes the same."""
    return sha256_file(copied_path) == source.sha256


@dataclass
class Provenance:
    """Everything about the analysis environment that a court may ask about."""

    tool: str = f"{__tool_name__} {__version__}"
    generated_utc: str = ""
    host: str = ""
    platform: str = ""
    python: str = ""
    libraries: dict = field(default_factory=dict)
    command_line: str = ""
    operator: str = ""
    case_number: str = ""
    agency: str = ""
    timezone: str = ""
    notes: str = ""

    @classmethod
    def collect(cls, operator: str = "", case_number: str = "", agency: str = "",
                tz_name: str = "", notes: str = "", argv: list[str] | None = None) -> "Provenance":
        return cls(
            generated_utc=datetime.now(tz=timezone.utc).isoformat(timespec="seconds"),
            host=socket.gethostname(),
            platform=f"{platform.system()} {platform.release()} ({platform.machine()})",
            python=sys.version.split()[0],
            libraries=_library_versions(),
            command_line=" ".join(argv if argv is not None else sys.argv),
            operator=operator,
            case_number=case_number,
            agency=agency,
            timezone=tz_name,
            notes=notes,
        )

    def to_dict(self) -> dict:
        return asdict(self)


def _library_versions() -> dict:
    versions: dict[str, str] = {}
    for mod in ("pandas", "numpy", "matplotlib", "scipy"):
        try:
            versions[mod] = __import__(mod).__version__
        except Exception:
            versions[mod] = "not installed"
    try:
        import tzdata
        versions["tzdata"] = getattr(tzdata, "IANA_VERSION", "installed")
    except Exception:
        versions["tzdata"] = "system"
    return versions


class CustodyLog:
    """Append-only action log written alongside an evidence bundle."""

    def __init__(self, path: str | os.PathLike | None = None):
        self.path = Path(path) if path else None
        self.entries: list[str] = []

    def add(self, action: str, detail: str = "") -> None:
        stamp = datetime.now(tz=timezone.utc).isoformat(timespec="seconds")
        line = f"{stamp}\t{action}" + (f"\t{detail}" if detail else "")
        self.entries.append(line)
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    def text(self) -> str:
        return "\n".join(self.entries)
