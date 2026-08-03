# Changelog

All notable changes to this project are recorded in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Because the
output of this tool is used as evidence, any change to how a verdict is reached will be
listed explicitly, with the direction of its effect stated.

## [1.0.0] - 2026-08-03

First release.

### Added

**Correlation analysis.** Reads wireless disruption events and security-camera events
from files on disk, normalizes them into one event schema, and measures whether the two
line up more often than chance accounts for. Any subset of the three input types is
accepted, and each input flag is repeatable; at least one camera source and one wireless
source are needed before a correlation is computable.

**Seven input parsers,** detected automatically and listable with `--list-parsers`. Each
can be forced with `--parser <id>`:

| Parser id | Accepts |
| --- | --- |
| `opnsense` | dnsmasq-dhcp, Kea DHCP4, ISC dhcpd, hostapd, wpa_supplicant and kernel link events, in RFC 3164 or RFC 5424 syslog framing |
| `pcap80211` | `.cap` / `.pcap` / `.pcapng` captures from airodump-ng, tcpdump or Wireshark, with radiotap and 802.11 header decoding |
| `kismet` | Kismet `.kismet` SQLite databases, decoding stored frames and carrying through DEAUTHFLOOD and BCASTDISCON alerts |
| `airodump_csv` | airodump-ng `-01.csv` station and access-point tables |
| `nzyme_csv` | nzyme CSV exports, `tshark -T fields` output, and generic CSVs carrying transmitter, receiver, subtype and reason-code columns |
| `camera_csv` | CSV of `timestamp,plate,make,model,notes`, with column names matched by synonym |
| `camera_clips` | folders of NVR clips — Tapo, Hikvision, Dahua, Reolink, Amcrest, UniFi Protect, Blue Iris, and ISO or epoch filenames |

Adding a format is one module implementing `sniff()` and `parse()` plus one line in the
registry; detection, the CLI, the GUI and the report's methodology section all read from
that list.

**Client-drop derivation from DHCP activity.** A drop is recognized only as a DISCOVER
from a client that held a confirmed lease moments earlier, which is the sole pattern that
means lost state. Retransmission backoff, T1 lease renewal, `DHCPINFORM` from a
statically-addressed host, the first activity seen for a MAC, and a re-acquisition that
follows a disconnection hostapd already logged are each excluded by name, because all of
them occur constantly on healthy networks.

**Incident grouping.** Disruption events within `--incident-gap` seconds of one another
are treated as one incident, so a 200-frame flood counts once rather than 200 times, and
a hostapd disconnect plus the DHCP re-association it caused count as one outage rather
than two.

**Camera-event de-duplication.** The same vehicle pass recorded by two sources — a camera
CSV and the folder of clips those events came from — is collapsed into one. Merging
happens only across different source files, admits at most one row per source, and is
anchored rather than chained, so four passes 1.9 s apart remain four passes. The row
carrying the most identifying detail survives.

**Four independent statistical tests,** reported together rather than singly, so that the
result does not rest on one window and one method:

1. Coincidence count — N of M camera passes with a disruption within ±X seconds.
2. Exact binomial test against the fraction of the observation period covered by the
   union of ±X-second windows around the disruptions.
3. Circular-shift permutation test, 10,000 trials by default, which preserves the real
   spacing of the camera events and the real clustering of the disruptions. Shifts near
   zero are excluded so the observed arrangement does not enter its own comparison set.
4. Fisher's exact test and chi-square on a 2×2 table of disjoint 2X-second bins.

Each test is implemented against SciPy when it is installed and against an exact
pure-Python fallback when it is not, so the numbers can be reproduced without the optional
dependency.

**Rate ratio and window sensitivity.** Disruptions per minute inside camera windows versus
outside, plus a table re-running the analysis at ±10, 15, 30, 60 and 120 seconds so a
reader can see whether the result holds across window widths.

**A verdict requiring three conditions at once.** `CORRELATION FOUND` is declared only
when there are at least 3 coincidences, *every* p-value falls below `--alpha` (default
0.01), and the rate ratio is at least 2. The decision is made on the weakest p-value,
never the best, because taking the smallest of several tests is the same error as running
tests until one agrees. Otherwise the result is `CORRELATION NOT ESTABLISHED` with the
failing condition named, or `INSUFFICIENT DATA`. Disagreement between the tests about
which side of the threshold they fall on is flagged separately.

**Analysis period narrowed to the overlap of the evidence streams,** with anything
discarded reported. Computing a background rate over a week of camera clips when the
capture ran for two hours would understate the background and inflate the finding.

**Clock-offset diagnostic.** After every run the tool asks whether the two streams would
line up at some constant offset and prints a `*** CHECK THE CLOCKS ***` block when they
would, naming the offset and pointing out when it is close to a whole hour. It is stated
as a diagnostic, never as a result.

**Deauthentication flood detection.** Sliding-window burst detection over frame arrival
times, with per-source and per-target frame counts, broadcast-frame counts, and
identification of reason codes 1 and 7, which off-the-shelf deauthers emit by default.

**Timezone and timestamp handling.** All arithmetic in UTC and all display in the case
timezone (`--tz`, default `America/New_York`). Year-less syslog timestamps get a year
inferred from the file's modification time, including the December-to-January rollover,
and the inference is stated in the report. The two genuinely ambiguous daylight-saving
cases — the repeated hour in autumn and the missing hour in spring — are reported rather
than resolved silently. `--log-year`, `--assume-offset` and `--camera-clock-offset`
override the inferences.

**Outputs** written to `--outdir`:

- `report.md` — eleven numbered sections: summary, what the evidence shows, statistics,
  window sensitivity, deauthentication frames and floods, camera events one by one,
  timeline, methodology, chain of custody, what the analysis does not prove, and a
  glossary. The section numbering is fixed; a section with nothing to say says so rather
  than being omitted.
- `correlation.csv` — one row per camera event with local and UTC time, the nearest
  disruption of each type, delta seconds, coincidence flag, source MAC and reason code.
- `events.csv` — every event parsed from every source, normalized.
- `incidents.csv` — disruptions grouped into incidents.
- `timeline.png` — camera passes, client drops and deauth frames on one axis with each
  coincidence window drawn to scale.
- `MANIFEST.json` and `MANIFEST.txt` — the verdict, all statistics, the sensitivity table,
  the clock-offset scan, the flood report, the analysis period, the complete parameter
  set, and a SHA-256 record for every input and output file.

**Evidence bundle** (`--evidence-bundle`, optionally `--zip`). A numbered folder holding
the report, the tables, the figure, hash-verified copies of the source files, an exhibits
folder, a `chain_of_custody.log`, and a `00_READ_ME_FIRST.txt` that explains to a
non-technical reader how to verify the hashes without this tool. Copies are re-hashed
after writing and compared against the originals; a mismatch is reported in the bundle
rather than quietly included.

**Chain of custody.** Every input file is hashed with SHA-256 before it is read, and the
hash, size, modification time, parser used and row count appear in the report and the
manifest. Directory inputs are recorded with a hash covering the file listing and sizes,
with that limitation stated in the record itself. No input file is modified, moved or
deleted.

**A mandatory "What this analysis does not prove" section** in every report, stating that
correlation is not identification, that MAC addresses in management frames are
unauthenticated and forgeable, that clock accuracy bounds the resolution, that
interference and hardware faults produce the same signature as an attack, and that the
absence of capture evidence is not the absence of an attack. Small sample sizes are
flagged explicitly.

**Graphical interface** (`--gui`), six tabs in the order the work happens: Case,
Evidence, Camera, Analyze, Results, Evidence builder. Files are hashed and their format
detected the moment they are attached, so the custody chain starts before any analysis.
Case files save and reload every analysis parameter so a run can be reproduced months
later; camera credentials are deliberately excluded from the saved structure.

**Camera integration** for the TP-Link Tapo C100 and other ONVIF-conformant cameras, via
`deauth-correlator camera {probe|snapshot|watch|help}`. ONVIF on port 2020 and RTSP on
port 554 by default, authenticated with the Tapo Camera Account rather than the cloud
login. `probe` reports reachability, device information, stream profiles and — the reason
it exists — the camera's clock error against the analysis host, which a ±30 s analysis
cannot tolerate being wrong about. `watch` records motion events into a camera-event CSV
and saves a still for each one as an exhibit. Passwords are read from
`DEAUTH_CORRELATOR_CAMPASS` so they need not appear in shell history, are held in memory
for the session only, and RTSP URLs are recorded in redacted form.

**`--self-test`,** which generates synthetic fixtures for every parser in the registry,
runs the entire pipeline over them twice — once with a planted correlation and once with
camera events and disruptions drawn independently — and verifies 132 checks across nine
sections. The negative scenario matters more than the positive one: a correlator that
always finds a correlation is worthless as evidence, so random data producing a finding
fails the test. Section 9 holds regression checks for every way the tool has been found to
invent or overstate a finding.

**Exit codes:** `0` correlation found, `1` correlation not established, `2` could not run.

**Read-only by construction.** No 802.11 frame is ever transmitted, nothing is injected,
no adapter is placed into monitor mode, and no raw socket is opened. `SAFETY.md` states
the guarantee and gives the greps that let a reader verify it against the source rather
than take it on trust.

### Requirements

Python 3.10 or newer. `pandas`, `numpy` and `matplotlib` are required, plus `tzdata` on
Windows. `scipy` is optional and supplies reference implementations of the significance
tests. `requests` and `opencv-python` are needed only for the camera features. Tkinter,
from the standard library, backs the GUI.

### License

Apache-2.0.
