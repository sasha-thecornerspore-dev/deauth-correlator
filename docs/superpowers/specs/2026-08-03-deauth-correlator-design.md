# deauth-correlator — Design

Date: 2026-08-03
Status: Approved for implementation (single-pass build, autonomous session)

## Purpose

Given (a) wireless-disruption evidence from a home/small-office network and (b) a log of
vehicle passes captured by a security camera, determine and quantify whether the two are
correlated, and emit output a non-technical reader (police detective, prosecutor, judge)
can follow.

The tool is **read-only forensics**. It parses logs and capture files and reads from the
user's own camera. It never transmits 802.11 frames, never injects, never scans, never
attacks. There is no code path that opens a raw socket.

## Scope decisions

### Statistics: four independent tests, not one

A single p-value from one window is easy to attack on cross-examination ("you picked the
window that worked"). The tool therefore reports:

1. **Coincidence count** — `N of M camera passes coincided with a wireless-disruption
   event within ±Xs`. The headline number.
2. **Binomial test against a chance baseline** — the fraction of the observation period
   covered by the union of ±X-second windows around disruption events is `p0`, the
   probability that a randomly-timed vehicle pass lands next to a disruption by chance.
   `binomtest(N, M, p0, alternative="greater")`.
3. **Monte-Carlo permutation test** — re-draw all M camera times uniformly across the
   observation period 10,000 times; the empirical fraction of trials reaching `N` or more
   coincidences. Robust to disruption events being clustered rather than independent.
4. **Fisher's exact + chi-square on a 2×2 table** — the observation period is cut into
   disjoint bins of width `2X`; each bin is classified by whether it contains a camera
   event and whether it contains a disruption event. Gives an odds ratio.

Plus a **rate ratio**: disruptions per minute inside camera windows vs. outside, and a
**window sensitivity table** (±10/15/30/60/120 s) so the reader can see the result is not
an artifact of the chosen window.

Verdict rule (all must hold for "CORRELATION FOUND"): `N >= 3`, the strongest p-value is
below `--alpha` (default 0.01), and the rate ratio is at least 2.0. Otherwise the verdict
is `NOT ESTABLISHED` with the reason stated, or `INSUFFICIENT DATA` when there are fewer
than 3 camera events or no disruption events at all.

### Deauth frames come from the capture, not the CSV

`airodump-ng`'s `-01.csv` contains the AP and station tables — it does **not** contain
individual management frames, so reason codes cannot come from it. The primary evidence
path is therefore a pure-Python 802.11 reader over the `.cap`/`.pcap`/`.pcapng` that
`airodump-ng --write` produces alongside the CSV. `--wifi-capture` accepts either and
auto-detects. The airodump CSV is still parsed, for the association/last-seen context it
does carry.

### Client drops

A "client drop" is derived, not logged directly. Two sources:

- **Re-association**: a DHCP DISCOVER/REQUEST/renew from a MAC that already had a lease
  event within `--reassoc-window` (default 120 s). The first lease event in a session is
  not a drop; each subsequent early re-request is.
- **Explicit link/state resets**: hostapd `disassociated`/`deauthenticated`, wpa_supplicant
  state changes, kernel `link state changed to DOWN`.

### Camera clock skew is measured, not assumed

Consumer cameras drift. When the camera is reachable, the tool reads ONVIF
`GetSystemDateAndTime` (an unauthenticated read per the ONVIF spec), computes the offset
against the analysis host, records it in the report, and can apply it with
`--camera-clock-offset`. An uncorrected skew silently destroys a ±30 s correlation, so it
is surfaced rather than hidden.

## Architecture

```
deauth_correlator/
  cli.py         argparse + orchestration          gui/app.py      Tkinter 6-tab GUI
  config.py      AppConfig dataclass               camera/onvif_min.py  raw-SOAP ONVIF (read-only)
  timeutil.py    tz normalization                  camera/tapo.py       Tapo C100 profile
  hashing.py     SHA-256 chain of custody          camera/recorder.py   motion-event -> CSV
  events.py      canonical event schema            parsers/opnsense.py  dnsmasq/Kea/ISC/hostapd
  drops.py       re-association -> client drop     parsers/pcap.py      pcap/pcapng reader
  correlate.py   windowing + nearest match         parsers/dot11.py     802.11 frame decode
  stats.py       the four tests                    parsers/airodump.py  airodump CSV
  floods.py      burst detection                   parsers/kismet.py    Kismet SQLite
  report.py      report.md                         parsers/nzyme.py     nzyme / generic CSV
  csvout.py      correlation.csv                   parsers/camera_csv.py
  plot.py        timeline.png                      parsers/camera_files.py  NVR filenames
  evidence.py    evidence bundle + manifest        selftest.py     synthetic fixtures
```

Every parser is a subclass of `parsers.base.Parser` with `sniff(path) -> confidence` and
`parse(path, ctx) -> list[dict]`. `parsers/__init__.py` holds the registry; a new format is
one file plus one registry line.

All parsers emit rows in one flat schema (`events.EVENT_COLUMNS`) carrying `ts_utc`,
`ts_local`, the original `utc_offset`, `kind`, `category`, MAC fields, reason code,
`source_file`, `source_ref` (line/row/packet number) and the `raw` source text. Everything
downstream sees only that schema.

## Outputs

- `correlation.csv` — one row per camera event: local + UTC time, nearest disruption of
  each type, delta seconds, coincidence flag, attacker MAC, reason code, plate/make/model.
- `report.md` — verdict, plain-English findings, all four statistics, flood table, window
  sensitivity, and a methodology section listing data sources with SHA-256, tool and
  library versions, timezone, clock-skew handling, and stated limitations.
- `timeline.png` — camera events, client drops and deauth frames on one shared time axis
  with coincidence windows shaded.
- `MANIFEST.json` / `MANIFEST.txt` — chain of custody for inputs and outputs.
- One-line verdict on stdout.

The evidence builder (GUI and `--evidence-bundle`) assembles a numbered folder with copies
of the inputs (hashes re-verified after copy), the reports, exhibit snapshots, and an
append-only `chain_of_custody.log`, then optionally zips it and hashes the zip.

## Testing

`--self-test` writes synthetic fixtures for every parser to a temp directory and runs the
whole pipeline twice: once over data with a planted 4-second-lag correlation (must return
CORRELATION FOUND) and once over independently-random data (must return NOT ESTABLISHED).
It also asserts per-parser row counts, reason-code extraction, timezone round-tripping,
and hash determinism. Exit code 0 only if every check passes.

## Non-goals

Live packet capture, frame injection, deauthing anything, cracking, device
fingerprinting beyond MAC, plate OCR, and any network write other than the ONVIF
subscription the user explicitly starts against their own camera.
