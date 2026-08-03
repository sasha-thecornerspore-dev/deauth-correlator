"""Parser interface.

A parser is one file implementing :class:`Parser`. ``sniff`` looks at a path
(and, if useful, its first bytes) and returns a confidence in 0..1 that this
parser handles the file. ``parse`` returns event dicts in the schema from
:mod:`deauth_correlator.events`.

Adding a format means adding one module and one line in ``parsers/__init__.py``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from ..timeutil import TimeContext


@dataclass
class ParseContext:
    """Everything a parser may need beyond the file itself."""

    time: TimeContext
    year_hint: int | None = None
    clock_offset_s: float = 0.0
    options: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def warn(self, message: str) -> None:
        if message not in self.warnings:
            self.warnings.append(message)


class ParseError(Exception):
    """Raised when a file matched a parser but could not be read."""


class Parser:
    #: stable identifier recorded in every row's ``source_kind``
    id: str = "base"
    #: human-readable name for the report
    name: str = "base parser"
    #: what this parser contributes, shown in the methodology section
    describes: str = ""
    #: file extensions this parser commonly handles (lowercase, with dot)
    extensions: tuple[str, ...] = ()

    def sniff(self, path: Path) -> float:
        """Return 0..1 confidence that this parser handles ``path``."""
        return 0.0

    def parse(self, path: Path, ctx: ParseContext) -> list[dict]:
        raise NotImplementedError

    # -- helpers shared by concrete parsers ------------------------------

    @staticmethod
    def head_text(path: Path, limit: int = 8192) -> str:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read(limit)
        except OSError:
            return ""

    @staticmethod
    def head_bytes(path: Path, limit: int = 64) -> bytes:
        try:
            with open(path, "rb") as fh:
                return fh.read(limit)
        except OSError:
            return b""

    @staticmethod
    def iter_lines(path: Path):
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.rstrip("\r\n")
                if line.strip():
                    yield lineno, line

    def year_hint_for(self, path: Path, ctx: ParseContext) -> int:
        """Year to assume for year-less timestamps in this file."""
        if ctx.year_hint:
            return ctx.year_hint
        from ..timeutil import infer_year_for_file
        year = infer_year_for_file(os.path.getmtime(path), ctx.time)
        ctx.time.note_year_inference(
            f"{path.name}: syslog lines carry no year; assumed {year} from the file's "
            f"last-modified time. Override with --log-year."
        )
        return year
