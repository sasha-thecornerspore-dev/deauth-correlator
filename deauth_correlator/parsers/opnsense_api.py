"""Logs pulled off the firewall by ``deauth-correlator fetch``.

The file this reads is a JSON envelope written by
:mod:`deauth_correlator.firewall.fetch`: provenance at the top, and under
``rows`` the log entries exactly as the OPNsense API returned them.

The point of a separate parser is that the saved evidence stays in the form the
firewall produced it. Rewriting API rows into syslog lines so the ordinary
OPNsense parser could read them would mean hashing, and swearing to, a file the
firewall never wrote. So the envelope is preserved and unpacked here.

What is *not* duplicated is the meaning of a log line. Which messages count as
a client drop, which count as a wireless disconnection, and how a Kea lease
message is read are all decided in :mod:`deauth_correlator.parsers.opnsense`,
and this module calls into it. There is one definition of a client drop in this
package and both entry points use it.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..timeutil import finalize
from .base import ParseContext, ParseError, Parser
from .opnsense import _dhcp_event, _wireless_event

#: The marker written at the top of every fetched file.
ENVELOPE_KEY = "deauth_correlator_fetch"


class OpnsenseApiParser(Parser):
    id = "opnsense_api"
    name = "OPNsense log pulled from the firewall API"
    describes = ("The same DHCP and wireless events as the OPNsense log parser, "
                 "read from entries retrieved directly from the firewall rather "
                 "than from a file exported by hand. The retrieval is recorded "
                 "in the file: which firewall, when, over what kind of "
                 "connection, and for what time window.")
    extensions = (".json",)

    def sniff(self, path: Path) -> float:
        if path.suffix.lower() != ".json":
            return 0.0
        head = self.head_text(path, 4096)
        if ENVELOPE_KEY in head:
            return 0.98
        return 0.0

    def parse(self, path: Path, ctx: ParseContext) -> list[dict]:
        from ..firewall.fetch import row_message, row_process, row_time

        try:
            envelope = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ParseError(f"{path.name} could not be read as JSON: {exc}") from exc
        if not isinstance(envelope, dict) or ENVELOPE_KEY not in envelope:
            raise ParseError(
                f"{path.name} is JSON but not a log fetched by this tool: it has "
                f"no {ENVELOPE_KEY!r} marker.")

        rows = envelope.get("rows")
        if not isinstance(rows, list):
            raise ParseError(f"{path.name} has no 'rows' list.")

        self._warn_about_provenance(envelope, path, ctx)

        request = envelope.get("request") or {}
        label = request.get("label") or request.get("scope") or "firewall log"
        out: list[dict] = []
        undated = 0

        for index, row in enumerate(rows, start=1):
            if not isinstance(row, dict):
                continue
            when = row_time(row)
            if when is None:
                undated += 1
                continue
            message = row_message(row)
            if not message:
                continue
            process = row_process(row)
            if not process:
                # Some back-ends fold the process name into the message.
                process, message = _split_leading_process(message)

            utc, local, offset = finalize(when, ctx.time)
            common = dict(
                ts_utc=utc, ts_local=local, utc_offset=offset,
                source_file=str(path), source_kind=self.id,
                source_ref=f"{label} row {index}",
                raw=f"{process}: {message}" if process else message,
            )
            event = (_wireless_event(process, message, common)
                     or _dhcp_event(process, message, common))
            if event is not None:
                out.append(event)

        if undated:
            ctx.warn(f"{path.name}: {undated} row(s) carried no timestamp this "
                     f"understands and were skipped.")
        return out

    @staticmethod
    def _warn_about_provenance(envelope: dict, path: Path,
                               ctx: ParseContext) -> None:
        """Surface anything about the retrieval that weakens the evidence."""
        if envelope.get("complete") is False:
            ctx.warn(f"{path.name}: the fetch hit its page limit, so entries "
                     f"older than the earliest row in the file were never "
                     f"retrieved. Treat the start of this window as incomplete.")
        tls = str((envelope.get("firewall") or {}).get("tls", ""))
        if tls.startswith("UNVERIFIED"):
            ctx.warn(f"{path.name}: this log was pulled over a connection whose "
                     f"certificate was not checked, so the file records where "
                     f"the entries were said to come from rather than "
                     f"establishing it. Note that if the provenance of this "
                     f"exhibit is challenged.")


def _split_leading_process(message: str) -> tuple[str, str]:
    """``"kea-dhcp4[123]: DHCP4_LEASE_ALLOC ..."`` -> ``("kea-dhcp4", "DHCP4...")``."""
    head, sep, tail = message.partition(":")
    if not sep or len(head) > 64 or " " in head.strip():
        return "", message
    name = head.strip()
    bracket = name.find("[")
    if bracket > 0:
        name = name[:bracket]
    return name, tail.strip()
