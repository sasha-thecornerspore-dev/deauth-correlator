# Contributing

This tool produces output that gets handed to detectives, attorneys and courts. That
constrains what a good contribution looks like more than it constrains most projects, so
this document starts with the constraint rather than with the setup instructions.

## Contents

1. [The rule that governs everything else](#the-rule-that-governs-everything-else)
2. [Development environment](#development-environment)
3. [Running the self-test](#running-the-self-test)
4. [Section 9, and when you have to add to it](#section-9-and-when-you-have-to-add-to-it)
5. [Adding a log-format parser](#adding-a-log-format-parser)
6. [Code style](#code-style)
7. [Submitting a change](#submitting-a-change)

---

## The rule that governs everything else

**No change may make the tool more likely to declare a correlation.**

The two directions of error are not symmetric here. If the tool misses a real
correlation, the operator collects more evidence, checks the clocks and runs it again;
the cost is time. If the tool declares a correlation that is not there, the output is a
report with a case number on it, a p-value, a hash-verified evidence bundle and a
plausible-looking timeline, and there is no stage after that where anyone catches the
mistake. The whole apparatus of provenance and formatting that makes the report useful
is the same apparatus that makes a wrong finding hard to challenge.

So the asymmetry is deliberate and it has to be preserved. Three areas of the code decide
whether a finding appears, and a change to any of them is treated as evidential rather
than routine:

| Area | Files | Why it decides the outcome |
| --- | --- | --- |
| Statistics | `stats.py` | computes the p-values, the rate ratio and the verdict itself |
| Drop derivation | `drops.py` | turns DHCP traffic into "disruption" events, which are one half of every coincidence |
| De-duplication | `correlate.py` (`dedupe_camera_events`), `drops.py` (`cluster_incidents`) | decides how many camera passes and how many incidents exist, which is the denominator and the numerator |

Concretely, the following are all failures, and each one has already happened at least
once during development:

- Making `derive_client_drops` recognise a new pattern as a drop when that pattern also
  occurs on healthy networks. DHCP retransmission backoff produced five "drops" from one
  client that simply could not reach the server. Read the module docstring in `drops.py`
  before touching it; it lists what is excluded and why each exclusion is necessary.
- Letting `dedupe_camera_events` merge more aggressively. Merging chains of nearby events
  collapsed four genuine passes 1.9 s apart into one, and merging within a single source
  discarded passes that source really saw. Under-merging inflates the number of passes
  *and* the number of coincidences together, which pushes the p-value towards
  significance; over-merging deletes evidence. Both are wrong, and the code is narrow on
  purpose.
- Deciding the verdict on `best_p` instead of `worst_p`. Taking the smallest of several
  p-values is the same error as running tests until one agrees, and it inflates the
  false-positive rate well past `--alpha`. `decide()` in `stats.py` uses `worst_p`, and
  the report tells the reader that the tests agree — that claim is only honest if every
  test had to clear the threshold.
- Relaxing any of the three verdict conditions in `decide()`: at least
  `MIN_COINCIDENCES_FOR_VERDICT` (3) coincidences, `worst_p < alpha`, and a rate ratio of
  at least `MIN_RATE_RATIO_FOR_VERDICT` (2.0). All three must hold. If you have a reason
  to change one, say what it is in the pull request and expect it to be the whole
  discussion.

Changes in the opposite direction — making the tool harder to satisfy, catching another
class of ordinary traffic that was being counted as a disruption, stating a limitation
the report was leaving implicit — need much less justification. They are the normal
direction of travel for this project.

Everything else in the codebase (parsers, output formatting, the GUI, the camera code,
performance) is ordinary software and is reviewed as such.

---

## Development environment

Python 3.10 or newer. The `X | None` type syntax used throughout works on 3.10 because
every module begins with `from __future__ import annotations`.

```bash
git clone <your fork>
cd deauth-correlator
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[all]"
```

`pandas`, `numpy` and `matplotlib` are required. `tzdata` is required on Windows, which
ships no IANA timezone database of its own. Three things are optional:

- **scipy** supplies the reference implementations of the significance tests. Without it
  the tool falls back to exact pure-Python versions. They are not approximations — section
  7 of the self-test checks that the two backends agree — so scipy is a convenience, not a
  requirement, and any change to `stats.py` has to keep both paths working.
- **requests** and **opencv-python** are needed only by `deauth_correlator/camera/`.
- **Tkinter** backs the GUI. It is in the standard library but is packaged separately on
  some Linux distributions (`sudo apt install python3-tk` on Debian and Ubuntu). Without
  it everything except `--gui` still works.

Work against an editable install rather than running from the source directory, so that
the console entry points (`deauth-correlator`, `deauth-correlator-gui`) are exercised by
the same code you are editing. `python -m deauth_correlator` works either way.

There is no separate test suite and no test runner to configure. `--self-test` is the
test suite.

---

## Running the self-test

```bash
python -m deauth_correlator --self-test
```

It writes synthetic fixtures for every parser in the registry into a temporary directory,
runs the entire pipeline over them twice, checks 146 assertions, and prints
`SELF-TEST PASSED: all 150 checks passed.` The process exits 0 on success and 1 on
failure. Run it before you open a pull request and paste the final line into the
description.

To keep the generated fixtures and inspect them:

```bash
python -m deauth_correlator --self-test --self-test-dir ./fixtures
```

`-q` suppresses the per-check `PASS` lines and prints only the section headers and the
result. Failures are always printed, and are listed again at the end.

The ten sections, and what each one exists to catch:

| Section | Title | Catches |
| --- | --- | --- |
| 1 | Time handling | timezone normalization, year inference for year-less syslog, DST edges |
| 2 | Frame decoding and reason codes | radiotap parsing, 802.11 header decoding, reason-code extraction |
| 3 | Parsers over synthetic fixtures | format detection and parsing for all seven parsers |
| 4 | Positive scenario | a planted correlation must be reported as `CORRELATION FOUND` |
| 5 | Negative scenario | independent random data must **not** produce a finding |
| 6 | Outputs and chain of custody | every output file, SHA-256 records, manifest contents |
| 7 | The two statistics backends agree | scipy and the pure-Python fallback give the same numbers |
| 8 | Degenerate inputs are handled honestly | no camera events, no disruptions, non-overlapping periods, empty input |
| 9 | Routine network traffic is not mistaken for evidence | the anti-fabrication regressions |
| 10 | The read-only and chain-of-custody guarantees hold | the promises SAFETY.md makes: no proxy or redirect can receive the camera credential header, the recorder stops when told to, files are hashed before they are parsed, and a build with a dead GUI is detectable |

A section that raises is recorded as one failed check and the remaining sections still
run. That is deliberate: when something is broken you want the whole picture, not the
first traceback.

Sections 4 and 5 are a pair, and 5 is the more important of the two. A correlator that
always finds a correlation is worthless as evidence, so the negative scenario draws camera
events and disruptions independently over the same period at the same rates and fails the
build if a finding comes out. If you find yourself weakening section 5 to make a change
pass, the change is the problem.

---

## Section 9, and when you have to add to it

Section 9 is titled "Routine network traffic is not mistaken for evidence" and lives in
`_test_no_fabrication` in `selftest.py`. It is not a general correctness suite. Every
case in it was a real defect that either manufactured disruption events out of ordinary
network traffic, deleted genuine camera events, or let a finding be declared on weaker
grounds than the report claimed. They are the failures that matter most precisely because
their output looks entirely plausible — nothing crashes, no warning appears, and the
report reads exactly like a correct one.

What is in there now, grouped by the defect class each group guards:

- **Routine DHCP traffic must never become disruption evidence.** Six scenarios run
  through `derive_client_drops` and assert an exact drop count: retransmission backoff
  yields 0, T1 lease renewals yield 0, repeated `DHCPINFORM` from a static host yields 0,
  a client that never held a lease yields 0, a disconnection already logged by hostapd is
  not counted a second time, and — the control case — a genuine re-acquisition after a
  confirmed lease does yield exactly 1. The control matters as much as the exclusions; a
  derivation that returns 0 for everything would pass the first five and be useless.
- **De-duplication must not delete genuine passes.** Two distinct passes in one file
  survive a duplicate arriving from another source; four passes 1.9 s apart stay four
  passes rather than chaining into one; and a real cross-source duplicate is still
  merged.
- **The verdict must rest on the weakest test, not the best.** `worst_p >= best_p` always,
  and a hand-constructed `WindowStats` where the binomial test clears alpha while the
  permutation and Fisher tests do not must produce a label other than `CORRELATION FOUND`,
  with the disagreement flagged by `tests_straddle`.
- **Decoding must not invent values.** An 802.11w protected management frame yields no
  reason code rather than ciphertext read as one, and a radiotap header containing an
  FHSS field still yields the correct signal level rather than a misaligned read.
- **Nothing is reported more precisely than it is known.** A p-value is never rendered as
  exactly zero, and a missing value renders as blank rather than as the string `nan` — a
  `nan` in a plate column of `correlation.csv` is a fabricated identifier as far as a
  reader is concerned.

**If your change touches statistics, drop derivation or de-duplication, add a check to
section 9.** Not to section 4, not to section 8 — section 9, because that is the section
a reviewer reads when they want to know what the tool refuses to claim.

Write the check so that it fails against the code as it stood before your change. If you
cannot construct an input that distinguishes the old behaviour from the new, then either
the change has no effect on findings, in which case say so in the pull request, or you
have not yet found the case where it matters.

Follow the shape of what is there:

```python
check.equal(len(derive_client_drops(to_frame(rows))), 0,
            "routine T1 lease renewals are not drops")
```

The description is a complete assertion in plain English, phrased as the property that
must hold rather than as the name of a function. `check.equal` and `check.at_least`
report the actual and expected values automatically; `check.that` takes an optional
`detail` string, and you should supply one whenever the failure would otherwise be a bare
`False`. Prefer an exact count over a bound: `at_least(1, ...)` would have passed for
every one of the six DHCP defects above.

---

## Adding a log-format parser

A parser is one module in `deauth_correlator/parsers/` plus one line in
`parsers/__init__.py`. Detection, the CLI, `--list-parsers`, the GUI evidence tab and the
methodology section of the report all read from the registry, so nothing else has to
change.

### 1. Write the module

Subclass `Parser` from `parsers/base.py` and implement two methods.

```python
"""nzyme CSV parser.

<Explain what the format is, where it comes from, and anything about it that
would otherwise look like a bug in this module.>
"""

from __future__ import annotations

from pathlib import Path

from .base import Parser, ParseContext
from ..events import make_event
from ..timeutil import finalize, parse_any


class MyFormatParser(Parser):
    id = "my_format"                     # stable; recorded in every row's source_kind
    name = "my format"                   # shown by --list-parsers and in the report
    describes = ("One sentence on what this parser contributes to the analysis, "
                 "printed in the report's methodology section.")
    extensions = (".log",)               # lowercase, with the dot

    def sniff(self, path: Path) -> float:
        ...

    def parse(self, path: Path, ctx: ParseContext) -> list[dict]:
        ...
```

`sniff(path)` returns a confidence between 0 and 1. `detect()` runs it over every parser
allowed for that input flag and takes the highest score; ties go to whichever appears
first in `REGISTRY`. A score below 0.5 still parses but emits a warning that reaches the
report, so the operator sees that the format matched only weakly.

Be honest in `sniff`. Return `0.0` when you are not sure rather than a small positive
number: a parser that is confidently wrong beats one that is correctly hesitant, and the
failure mode is silent — the file parses into a small number of misinterpreted events
rather than raising. `Parser.head_text`, `Parser.head_bytes` and `Parser.iter_lines`
handle the file-opening and encoding details; use them rather than opening the file
yourself. An exception raised from `sniff` is caught and treated as a score of 0.

`parse(path, ctx)` returns a list of plain dicts built with `make_event()` from
`events.py`. That function fills in the full `EVENT_COLUMNS` schema, so pass only the
fields you actually have. Points worth getting right:

- Convert timestamps with `parse_any(text, ctx.time)` and then `finalize(dt, ctx.time)`,
  which returns `(utc, local, observed_offset)`. Do not construct UTC times yourself; the
  timezone, the assumed offset and the year inference all live in `ctx.time`.
- For year-less timestamps call `self.year_hint_for(path, ctx)`. It honours `--log-year`
  when given, infers the year from the file's modification time otherwise, and records the
  inference so it appears in the report rather than being made silently.
- Apply `ctx.clock_offset_s` if your format is a camera source. It carries
  `--camera-clock-offset`.
- Set `source_file`, `source_kind=self.id` and `source_ref` (line number, row number or
  packet number) on every row. `source_ref` is what lets a reader go from a line in
  `correlation.csv` back to the line in the original file, which is the point of the
  whole custody chain.
- Keep a truncated `raw` string. `report.py` and `events.csv` quote it.
- Report anything you skipped with `ctx.warn(...)`. Warnings are carried into the report;
  rows that vanish without a warning are the thing to avoid. Do not `print`.
- Raise `ParseError` only when the file matched your parser but could not be read. A file
  that is not yours should have scored 0 in `sniff`.
- Set `kind` to one of the values listed at the top of `events.py`
  (`deauth`, `disassoc`, `client_drop`, `link_reset`, `camera`, `assoc`, `alert`).
  `make_event` derives `category` from it, and `category` is what decides whether a row is
  a camera pass, a disruption, or context that informs the analysis without being counted
  as either. Emitting `assoc` context rows and letting `drops.py` decide what is a drop is
  correct; emitting `client_drop` directly from a parser puts a finding-affecting decision
  in the wrong module.

### 2. Register it

In `parsers/__init__.py`, import the class and add an instance to `REGISTRY`:

```python
from .my_format import MyFormatParser

REGISTRY: list[Parser] = [
    ...
    MyFormatParser(),
]
```

Then add the id to `ROLE_PARSERS` under whichever CLI flag should be able to select it —
`opnsense-log`, `wifi-capture` or `camera-events`. A parser missing from `ROLE_PARSERS` is
never reached by auto-detection and can only be selected with `--parser <id>`.

### 3. Add a fixture and a check

In `selftest.py`, write a `_write_myformat(path, times, rng)` generator alongside the
existing ones, call it from `_write_scenario`, and add a
`("myformat.log", "<role>", "my_format")` row to the `expectations` list in
`_test_parsers`. That gets you detection and a non-empty parse for free. If the format
carries anything the analysis depends on — reason codes, alert records, a note about how a
timestamp was derived — assert it explicitly the way the pcap, Kismet and clip fixtures
do.

The fixture generator must produce a file a real producer would produce, not the minimum
your parser accepts. The point of the fixtures is to catch the case where the parser and
the test agree with each other and both disagree with reality.

### 4. Update the format table

Add a row to the input-formats table in `README.md`. `--list-parsers` picks up `name`,
`describes` and `extensions` on its own.

---

## Code style

There is no formatter or linter configured. Match the file you are editing; the
conventions below are all observable in the existing source.

**Module docstrings explain the reasoning, not the contents.** This is the strongest
convention in the codebase and the most important one to keep. `drops.py` spends thirty
lines on why four superficially similar DHCP patterns are excluded, `stats.py` explains
why four tests are reported instead of one, and `dedupe_camera_events` records which
merging rules were tried and rejected. Write down the alternative you did not take and
why; a reviewer six months from now, or an opposing expert, needs the reasoning far more
than a restatement of the code.

**Layout.**

- `from __future__ import annotations` is the first import in every module.
- Imports in three blocks separated by blank lines: standard library, third party
  (`numpy`, `pandas`), then package-relative.
- Heavy or optional imports are deferred into the function that needs them —
  `matplotlib`, the GUI, `selftest`, the camera package and `evidence` are all imported at
  the point of use in `cli.py`. This keeps `--help` and `--list-parsers` fast and keeps the
  optional dependencies genuinely optional. `scipy` is the exception: it is imported in a
  `try` at module scope in `stats.py`, which sets `HAVE_SCIPY` for the fallback to test.
- Public functions first, `_`-prefixed helpers below them in the same module.
- Lines fit in 88 columns. The handful that do not are all string literals.
- Source is ASCII, except for a few characters in strings shown to the user. Docstrings
  and comments write `+/-` rather than `±` and `->` rather than an arrow.

**Types and structure.**

- Type hints on public signatures. `X | None`, `list[dict]`, `str | Path`.
- Dataclasses for anything with more than two fields that crosses a module boundary:
  `WindowStats`, `Verdict`, `Analysis`, `FileRecord`, `ParseContext`, `AppConfig`. Not
  tuples, and not free-form dicts.
- Thresholds and defaults are named module-level constants — `DEFAULT_WINDOW_S`,
  `MIN_COINCIDENCES_FOR_VERDICT`, `DEFAULT_FLOOD_THRESHOLD`. A number that affects a
  finding must never appear only at its call site, because the report prints these and a
  reader has to be able to find the one definition.

**Behaviour.**

- Library modules do not print. Output goes through a `log` callable the caller supplies,
  or is returned as a string, or is appended to `warnings` / `period_notes` so it reaches
  the report. `cli.py`, `gui/` and `selftest.py` are the only modules that call `print`.
- No bare `except:`. `except Exception` is used where one bad input file must not take
  down a run, and the failure is always reported to the user rather than swallowed.
- Anything the tool assumed, inferred or discarded is stated in the output. Year inference,
  DST ambiguity, weak format matches, dropped duplicate camera events, a non-overlapping
  analysis period, skipped rows: all of them reach `report.md`. A silent assumption in a
  forensic tool is a defect regardless of whether the assumption was right.
- The report always carries the same eleven numbered sections, even when a section has
  nothing to say. Section 8 of the self-test enforces this. Section numbers are
  cross-referenced from the text and from the bundle cover sheet, and a report that skipped
  a number would invite the question of what had been removed.

**Prose in output.** The report, the CLI and the GUI are read by people who are not
network engineers. Complete sentences, no jargon that is not defined in the report's
glossary, and no adjective where a number would do.

---

## Submitting a change

Before opening a pull request:

1. `python -m deauth_correlator --self-test` passes, all 150 checks (more, if you added
   any). Paste the final line into the description.
2. If you touched `stats.py`, `drops.py` or the de-duplication code, section 9 has a new
   check that fails without your change. Say in the description which check it is.
3. If you touched anything in `stats.py`, confirm it works both with and without scipy
   installed. `pip uninstall scipy` and run the self-test again; section 7 compares the
   backends but only exercises the path that is present.
4. If you added a parser, `--list-parsers` shows it and the README format table has a row
   for it.
5. Nothing in `SAFETY.md` has become untrue. If your change adds a `socket`, `subprocess`
   or network call, the table in that document has to grow a row, and the pull request has
   to explain why the call is necessary and why it is read-only. The four greps in
   SAFETY.md are meant to return only the sixteen lines its table accounts for; a line
   the table does not explain needs an entry.
6. No evidence, real captures or case material in the diff. `.gitignore` covers `*.cap`,
   `*.pcap`, `*.pcapng`, `*.kismet`, `output/`, `evidence_*/` and `exhibits/`, but check
   anyway.

In the pull request, state what the change does to the likelihood of a `CORRELATION FOUND`
verdict. "No effect" is a complete answer and is the expected one for most changes. If the
answer is "it makes findings more likely", lead with the justification.

Bugs and false findings are reported through the issue templates in
`.github/ISSUE_TEMPLATE/`. A finding you believe is wrong goes in the false-finding
template rather than the bug template — that class of report is handled as
security-critical, for the reasons set out in `SECURITY.md`.

This project is licensed under Apache-2.0. Contributions are accepted under the same
licence.
