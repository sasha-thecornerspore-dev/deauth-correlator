"""Parser registry and format auto-detection.

To add a format: write a module with a :class:`~.base.Parser` subclass and add
it to ``REGISTRY`` below. Nothing else changes - detection, the CLI, the GUI
and the methodology section of the report all read from this list.
"""

from __future__ import annotations

from pathlib import Path

from .base import Parser, ParseContext, ParseError
from .airodump import AirodumpCsvParser
from .camera_csv import CameraCsvParser
from .camera_files import CameraFilenameParser
from .kismet import KismetParser
from .nzyme import NzymeCsvParser
from .opnsense import OpnsenseParser
from .pcap import PcapParser

REGISTRY: list[Parser] = [
    PcapParser(),
    KismetParser(),
    OpnsenseParser(),
    CameraCsvParser(),
    AirodumpCsvParser(),
    NzymeCsvParser(),
    CameraFilenameParser(),
]

BY_ID = {p.id: p for p in REGISTRY}

#: Which parsers each CLI input flag is allowed to select.
ROLE_PARSERS = {
    "opnsense-log": ["opnsense"],
    "wifi-capture": ["pcap80211", "kismet", "airodump_csv", "nzyme_csv"],
    "camera-events": ["camera_csv", "camera_clips"],
}


def detect(path: Path, allowed: list[str] | None = None) -> tuple[Parser | None, float]:
    """Pick the best parser for ``path``, optionally restricted to ``allowed`` ids."""
    candidates = [p for p in REGISTRY if allowed is None or p.id in allowed]
    best: Parser | None = None
    best_score = 0.0
    for parser in candidates:
        try:
            score = parser.sniff(path)
        except Exception:
            score = 0.0
        if score > best_score:
            best, best_score = parser, score
    return best, best_score


def parse_path(path: Path, ctx: ParseContext, role: str,
               forced_id: str | None = None) -> tuple[list[dict], Parser]:
    """Detect (or force) a parser for one input and run it."""
    allowed = ROLE_PARSERS.get(role)
    if forced_id:
        parser = BY_ID.get(forced_id)
        if parser is None:
            raise ParseError(f"unknown parser id {forced_id!r}; "
                             f"available: {', '.join(sorted(BY_ID))}")
        score = 1.0
    else:
        parser, score = detect(path, allowed)

    if parser is None:
        raise ParseError(
            f"{path.name}: no parser recognized this file for --{role}. "
            f"Formats accepted here: "
            f"{', '.join(BY_ID[i].name for i in (allowed or BY_ID))}. "
            f"Force one with --parser <id>."
        )
    if score < 0.5:
        ctx.warn(f"{path.name}: format matched {parser.name} only weakly "
                 f"(confidence {score:.2f}); check the parsed row count below.")
    return parser.parse(path, ctx), parser


def describe_registry() -> list[dict]:
    return [{"id": p.id, "name": p.name, "describes": p.describes,
             "extensions": ", ".join(e for e in p.extensions if e)}
            for p in REGISTRY]


__all__ = ["Parser", "ParseContext", "ParseError", "REGISTRY", "BY_ID",
           "ROLE_PARSERS", "detect", "parse_path", "describe_registry"]
