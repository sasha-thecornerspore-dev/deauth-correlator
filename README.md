# deauth-correlator

Detects and quantifies whether wireless client disruptions on your network line up
with vehicle passes recorded by a security camera, and writes the result in a form a
detective, prosecutor or judge can read.

**This tool only reads.** It parses log files and capture files and, when you ask it to,
reads from a camera you own. It never transmits an 802.11 frame, never injects, never
scans, never deauthenticates anything. There is no code path that opens a raw socket.
See [SAFETY.md](SAFETY.md).

```
CORRELATION FOUND: 12 of 12 camera passes (100%) coincided with a wireless disruption
within +/-30 s; 1.2 would be expected by chance (p = 1.47e-12, 13.8x the background rate).
```

---

## Contents

1. [Install](#install)
2. [Quick start](#quick-start)
3. [The graphical interface](#the-graphical-interface)
4. [Setting up a monitor-mode adapter and running airodump-ng](#a-setting-up-a-monitor-mode-adapter-and-running-airodump-ng)
5. [Exporting OPNsense logs](#b-exporting-opnsense-logs)
6. [TP-Link Tapo C100 setup](#c-tp-link-tapo-c100-setup)
7. [Input formats](#input-formats)
8. [Outputs](#outputs)
9. [How the statistics work](#how-the-statistics-work)
10. [Command reference](#command-reference)
11. [Getting the evidence right](#getting-the-evidence-right)
12. [Troubleshooting](#troubleshooting)

---

## Install

Python 3.10 or newer.

```bash
pip install -e ".[all]"
```

That puts `deauth-correlator` and `deauth-correlator-gui` on your path. If the shell
cannot find them afterwards, pip installed them into a user scripts directory that is
not on `PATH` — find it with `python -c "import sysconfig; print(sysconfig.get_path('scripts', 'nt_user' if __import__('os').name=='nt' else 'posix_user'))"`,
or skip the problem entirely and run the module directly:

```bash
python -m deauth_correlator --help
```

Every example below works with either form.

`pandas`, `numpy` and `matplotlib` are required. `scipy` is optional — it supplies the
reference implementations of the significance tests, and without it the tool falls back
to exact pure-Python versions that produce the same numbers. `requests` and
`opencv-python` are needed only for the camera features.

Verify the installation:

```bash
python -m deauth_correlator --self-test
```

That generates synthetic evidence for every supported format, runs the whole pipeline
over it twice — once with a planted correlation, once with independent random data —
and checks that the first is found and the second is not. All 82 checks should pass.

---

## Quick start

```bash
python -m deauth_correlator \
  --opnsense-log dhcp.log \
  --wifi-capture case0714-01.cap \
  --camera-events passes.csv \
  --case "2026-CF-00417" --operator "J. Schatz" \
  --outdir case0714 --evidence-bundle --zip
```

Any subset of the three input types works, and each flag can be repeated. You need at
least one camera source and at least one wireless source for a correlation to be
computable.

---

## The graphical interface

```bash
python -m deauth_correlator --gui
```

Six tabs, in the order the work actually happens:

| Tab | What it does |
| --- | --- |
| **1. Case** | Case number, operator, agency, timezone, camera clock offset. Save and reload a case file so a run can be reproduced later. |
| **2. Evidence** | Attach logs, captures and camera events. Each file is hashed and its format detected the moment you add it, so the chain of custody starts before any analysis. |
| **3. Camera** | Connect to the Tapo C100, measure its clock error, save snapshots, and record live motion events straight into a camera-event CSV. |
| **4. Analyze** | Every analysis parameter, with the reason each one matters, and the run button. |
| **5. Results** | Verdict banner, per-event table, all the statistics, deauth sources, and the timeline. |
| **6. Evidence builder** | Assembles the handover bundle: report, tables, figure, hash-verified copies of the sources, your exhibits, manifest, and a zip. |

Camera passwords live in memory for the session only. They are never written to the case
file, the report or the bundle.

---

## (a) Setting up a monitor-mode adapter and running airodump-ng

**This is the single most valuable piece of evidence you can collect.** Deauthentication
frames — and in particular the reason code inside each one — exist only in the radio
traffic. A DHCP log can show that a device dropped; only a capture can show what pushed
it off.

### Hardware

You need an adapter whose chipset supports monitor mode. Reliable choices:

| Chipset | Common adapters | Notes |
| --- | --- | --- |
| Atheros AR9271 | Alfa AWUS036NHA, TP-Link TL-WN722N **v1 only** | 2.4 GHz only; excellent driver support, works out of the box on Linux |
| Realtek RTL8812AU | Alfa AWUS036ACH | 2.4/5 GHz; needs the `rtl8812au` DKMS driver |
| MediaTek MT7612U | Alfa AWUS036ACM | 2.4/5 GHz; in-kernel driver, currently the easiest dual-band option |

TL-WN722N **v2 and v3 are a different chipset and do not do monitor mode reliably** —
check the version sticker, this catches people out constantly.

The adapter must be on the same band and channel as the network being attacked. If your
network runs on 5 GHz, a 2.4 GHz-only adapter records nothing.

### Software

Linux is strongly preferred; a Raspberry Pi left running is ideal for a multi-day watch.
Windows and macOS monitor-mode support is poor.

```bash
sudo apt install aircrack-ng          # Debian / Ubuntu / Raspberry Pi OS
```

### Put the adapter into monitor mode

```bash
# 1. See the interface name and identify processes that will interfere
iw dev
sudo airmon-ng check

# 2. Stop NetworkManager and wpa_supplicant from retuning the card mid-capture
sudo airmon-ng check kill

# 3. Enter monitor mode - this usually renames wlan1 to wlan1mon
sudo airmon-ng start wlan1

# 4. Confirm
iw dev wlan1mon info      # should report "type monitor"
```

If `airmon-ng` is unavailable, do it manually:

```bash
sudo ip link set wlan1 down
sudo iw wlan1 set monitor control
sudo ip link set wlan1 up
sudo iw wlan1 set channel 6
```

### Find your own network's channel and BSSID

```bash
sudo airodump-ng wlan1mon
```

Let it sweep for a minute, note the **BSSID** and **CH** of your access point, then stop
with Ctrl-C.

### Record

Lock to your channel and your BSSID. Channel hopping is the most common reason a capture
misses the attack — while the card is listening on channel 11, a flood on channel 6 is
simply not recorded.

```bash
sudo airodump-ng \
  --bssid AA:BB:CC:DD:EE:FF \
  --channel 6 \
  --write case0714 \
  --output-format pcap,csv \
  wlan1mon
```

This writes:

| File | Contents | Use it for |
| --- | --- | --- |
| `case0714-01.cap` | every frame, including deauthentication frames and reason codes | **`--wifi-capture` — the primary evidence** |
| `case0714-01.csv` | access-point and station tables | `--wifi-capture` — corroborating context |
| `case0714-01.kismet.netxml` | network list | not used |

Pass both to the tool; it detects which is which.

Leave it running for as long as you can. A few hours of quiet baseline is not wasted
time — it is what establishes the background rate, and without a background the
statistics have nothing to compare against.

**Watch the disk.** A busy network fills gigabytes per day. To keep only management
frames, filter as you go:

```bash
sudo dumpcap -i wlan1mon -f "type mgt" -b filesize:102400 -w case0714.pcapng
```

Or trim an existing capture afterwards:

```bash
tshark -r case0714-01.cap -Y "wlan.fc.type_subtype in {10 12}" -w deauths-only.pcap
```

### Verify you actually captured management frames

Before relying on a capture, confirm it contains what you think:

```bash
tshark -r case0714-01.cap -Y "wlan.fc.type_subtype == 12" \
       -T fields -e frame.time -e wlan.ta -e wlan.da -e wlan.fixed.reason_code
```

Or just run the tool — if the adapter was not really in monitor mode, it says so
explicitly rather than reporting zero deauths as though none occurred.

### Legality

Capturing traffic on your own network is fine. Capturing on networks you do not own or
have permission to monitor is not, in most jurisdictions. Lock the capture to your own
BSSID — it keeps the evidence focused and keeps you clear of other people's traffic.

---

## (b) Exporting OPNsense logs

Two routes. Remote syslog is better for an ongoing investigation because it gets the
logs off the firewall continuously, so a reboot or log rotation cannot destroy them.

### Route 1 — remote syslog (recommended)

**On OPNsense:** System → Settings → Logging / Targets → **+**

| Field | Value |
| --- | --- |
| Transport | UDP(4) or TCP(4) |
| Applications | `dhcpd`, `dnsmasq`, `kea-dhcp4`, `hostapd` — or leave empty for everything |
| Levels | leave empty (all) |
| Hostname | IP of the machine collecting the logs |
| Port | 514 |
| rfc5424 | **tick this** — it puts a full date and UTC offset on every line, which removes all guesswork about what year and zone a timestamp belongs to |

**On the collector**, with rsyslog:

```
# /etc/rsyslog.d/10-opnsense.conf
module(load="imudp")
input(type="imudp" port="514")
:fromhost-ip, isequal, "192.168.1.1"  /var/log/opnsense/dhcp.log
& stop
```

```bash
sudo mkdir -p /var/log/opnsense && sudo systemctl restart rsyslog
```

Then `--opnsense-log /var/log/opnsense/dhcp.log`.

Anything that receives syslog works — `journald`, `syslog-ng`, or for a quick collector
on any machine:

```bash
sudo python3 -c "
import socket, datetime
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('0.0.0.0', 514))
with open('opnsense.log', 'a', buffering=1) as fh:
    while True:
        data, _ = s.recvfrom(65535)
        fh.write(data.decode('utf-8', 'replace').rstrip() + '\n')
"
```

### Route 2 — download from the firewall

**Web interface.** System → Log Files → General (or Services → *your DHCP server* → Log
File) → the download button. Save as `.log` and pass it with `--opnsense-log`.

**API.** Create an API key under System → Access → Users → *your user* → API keys, then:

```bash
curl -k -u "$KEY:$SECRET" \
  "https://192.168.1.1/api/diagnostics/log/core/system/?limit=100000" \
  -o opnsense-system.json

curl -k -u "$KEY:$SECRET" \
  "https://192.168.1.1/api/dnsmasq/service/log/?limit=100000" \
  -o dnsmasq.json
```

The API returns JSON. Flatten it to plain syslog lines:

```bash
python -c "
import json, sys
rows = json.load(open('opnsense-system.json'))
rows = rows.get('rows', rows) if isinstance(rows, dict) else rows
for r in rows:
    print(f\"{r.get('timestamp','')} {r.get('hostname','opnsense')} \"
          f\"{r.get('process_name','')}: {r.get('line', r.get('message',''))}\")
" > opnsense-system.log
```

**SSH.** Fastest when you have shell access:

```bash
ssh root@192.168.1.1 'clog /var/log/dhcpd/latest.log' > dhcp.log
ssh root@192.168.1.1 'clog /var/log/system/latest.log' > system.log
```

OPNsense stores logs in the circular `clog` format; `clog` prints them as text. Newer
versions write plain files under `/var/log/<service>/` that you can `scp` directly.

### Which logs to collect

| Log | Why |
| --- | --- |
| `dnsmasq` / `kea-dhcp4` / `dhcpd` | lease activity — the basis for client-drop detection |
| `hostapd` | direct 802.11 disassociation and deauthentication records, if OPNsense runs your access point |
| `system` | interface link-state changes |

If your access point is a separate device (a Ubiquiti AP, a mesh node, an ISP router),
its own logs are more useful than the firewall's for wireless events. OPNsense only sees
DHCP unless it is also the AP.

### A note on year-less timestamps

Classic syslog lines look like `Jul 14 21:03:11` with no year. The tool infers the year
from the log file's modification date, handles the December-to-January rollover, and
**states the inference in the report** so nobody has to wonder. Override it with
`--log-year 2026`, or avoid the problem entirely by ticking rfc5424 above.

---

## (c) TP-Link Tapo C100 setup

The C100 speaks ONVIF on port **2020** and RTSP on port **554**, both gated by a
**Camera Account** that is separate from your TP-Link cloud login. The cloud login will
not work.

1. Open the Tapo app and select the camera.
2. **Device Settings → Advanced Settings → Camera Account.**
3. Create a username and password there.
4. Give the camera a static DHCP lease in OPNsense so its address does not move.

Check it:

```bash
export DEAUTH_CORRELATOR_CAMPASS='your-camera-account-password'
python -m deauth_correlator camera probe \
  --camera-host 192.168.1.50 --camera-user forensics
```

```
Device: TP-LINK Tapo C100 (firmware 1.3.9)
Camera clock is 43.71 s ahead of this computer (large enough to matter for a
  +/-30 s analysis). Pass --camera-clock-offset -43.710 to correct camera event times.
RTSP port open
Stream profile 'profile_1': 1920x1080 H264
```

**Take the clock line seriously.** A camera running 44 seconds fast will shift every
recorded event by 44 seconds and destroy a 30-second correlation — or manufacture a
false one. The GUI fills the correction in automatically after a probe; on the command
line pass the offset it prints.

### Record motion events while you capture

Run this next to `airodump-ng` so both sides of the evidence cover the same period:

```bash
python -m deauth_correlator camera watch \
  --camera-host 192.168.1.50 --camera-user forensics \
  --out camera_events.csv --exhibits exhibits/
```

Each motion event appends a row to `camera_events.csv` and saves a still into
`exhibits/`, so a coincident pass arrives with a picture attached. Ctrl-C to stop.

Other commands: `camera snapshot` saves one frame, `camera help` prints the setup notes.

**What this does on the camera:** reads the clock, reads the device information and
stream profiles, opens the RTSP stream to grab frames, and creates one standard ONVIF
event subscription that the camera expires by itself and the tool removes on exit.
Nothing is configured, changed or deleted.

---

## Input formats

Formats are detected automatically; `--parser <id>` forces one, and `--list-parsers`
lists them.

| Flag | Accepts | Parser id |
| --- | --- | --- |
| `--opnsense-log` | dnsmasq-dhcp, Kea DHCP4, ISC dhcpd, hostapd, wpa_supplicant, kernel link events, in RFC3164 or RFC5424 syslog framing | `opnsense` |
| `--wifi-capture` | `.cap` / `.pcap` / `.pcapng` from airodump-ng, tcpdump or Wireshark | `pcap80211` |
| `--wifi-capture` | Kismet `.kismet` SQLite database — decodes stored frames and carries through DEAUTHFLOOD / BCASTDISCON alerts | `kismet` |
| `--wifi-capture` | airodump-ng `-01.csv` — station and AP tables | `airodump_csv` |
| `--wifi-capture` | nzyme CSV export, `tshark -T fields` CSV, or any CSV with transmitter / receiver / subtype / reason-code columns | `nzyme_csv` |
| `--camera-events` | CSV of `timestamp,plate,make,model,notes` | `camera_csv` |
| `--camera-events` | a folder of clips — Tapo, Hikvision, Dahua, Reolink, Amcrest, UniFi Protect, Blue Iris, ISO or epoch filenames | `camera_clips` |

Column names in the CSV parsers are matched by synonym, so `time`/`datetime`/`ts` all
work for the timestamp, and the mapping actually used is printed in the report.

**Adding a format** is one file in `deauth_correlator/parsers/` implementing `sniff()`
and `parse()`, plus one line in `parsers/__init__.py`. Everything else — detection, the
CLI, the GUI, the methodology section — picks it up automatically.

---

## Outputs

Written to `--outdir`:

| File | Contents |
| --- | --- |
| `report.md` | the findings in plain English, all four statistics, the flood table, the methodology, SHA-256 of every input, the limitations, and a glossary |
| `correlation.csv` | one row per camera event: local and UTC time, nearest disruption of each type, delta seconds, coincidence flag, source MAC, reason code |
| `timeline.png` | camera passes, client drops and deauth frames on one axis, with each coincidence window drawn to scale |
| `events.csv` | every event parsed from every source, normalized |
| `incidents.csv` | disruptions grouped into physical incidents |
| `MANIFEST.json` / `.txt` | hashes and the complete parameter set |

`--evidence-bundle` additionally builds a numbered folder holding all of the above plus
hash-verified copies of the source files, an exhibits folder, a `chain_of_custody.log`,
and a `00_READ_ME_FIRST.txt` explaining to a non-technical reader how to verify the
hashes themselves. `--zip` archives it and hashes the archive.

Exit codes: `0` correlation found, `1` not established, `2` could not run.

---

## How the statistics work

The tool reports **four independent tests**, not one, because a single p-value from a
single window invites the obvious question: how many windows did you try first?

1. **Coincidence count.** N of M camera passes had a disruption within ±X seconds. The
   headline number.
2. **Binomial test.** The union of ±X-second windows around the disruptions covers some
   fraction of the observation period. That fraction is the chance a randomly-timed pass
   lands next to a disruption. The exact binomial tail gives the probability of N or more
   hits.
3. **Circular-shift permutation test.** The whole camera-event sequence is slid by a
   random offset, wrapping around the period, 10,000 times, and the coincidences
   recounted. This preserves the real spacing of the passes and the real clustering of
   the disruptions. Shifts near zero are excluded — they simply reproduce the real
   alignment and would put the observed arrangement into its own comparison set.
4. **Fisher's exact test and chi-square** on a 2×2 table of disjoint 2X-second bins
   classified by whether each contained a camera event and whether it contained a
   disruption.

Plus a **rate ratio** (disruptions per minute inside camera windows versus outside) and
a **window sensitivity table** at ±10/15/30/60/120 s, so a reader can see the result
holds across window widths rather than at one convenient value.

**A correlation is only declared when all three of these hold:** at least 3
coincidences, the strongest p-value below `--alpha` (default 0.01), and a rate ratio of
at least 2. Otherwise the verdict is `CORRELATION NOT ESTABLISHED` with the failing
condition stated, or `INSUFFICIENT DATA`.

Two further things the tool does that matter more than they sound:

- **The analysis period is the overlap of the two evidence streams.** Computing a
  background rate over a week of camera clips when the capture only ran for two hours
  would understate the background and inflate the finding. Anything discarded is
  reported.
- **Disruptions are grouped into incidents.** A 200-frame flood is one attack, and a
  hostapd disconnect plus the DHCP re-association it caused are one outage seen twice.
  Counting raw events would multiply the same disruption into hundreds of data points.

---

## Command reference

```
deauth-correlator [inputs] [options]
deauth-correlator --gui
deauth-correlator --self-test
deauth-correlator --list-parsers
deauth-correlator camera {probe|snapshot|watch|help} [options]
```

| Option | Default | Meaning |
| --- | --- | --- |
| `--window SECONDS` | 30 | coincidence window, plus and minus |
| `--alpha` | 0.01 | significance threshold |
| `--trials` | 10000 | permutation trials |
| `--tz ZONE` | America/New_York | timezone for every displayed time |
| `--log-year YEAR` | inferred | year for year-less syslog lines |
| `--assume-offset OFF` | from `--tz` | UTC offset for timestamps that carry none |
| `--camera-clock-offset S` | 0 | seconds added to every camera timestamp |
| `--clip-time-from` | auto | `auto`, `filename` or `mtime` |
| `--reassoc-window SECONDS` | 120 | a repeat DHCP handshake this soon is a client drop |
| `--handshake-window SECONDS` | 10 | lease messages this close are one join |
| `--incident-gap SECONDS` | 10 | disruptions this close are one incident |
| `--camera-dedupe SECONDS` | 2 | camera events this close from *different* sources are one pass recorded twice; `0` disables |
| `--flood-threshold N` | 5 | frames within the flood window that make a flood |
| `--flood-window SECONDS` | 10 | flood detection window |
| `--no-sensitivity` | off | skip the multi-window table |
| `--case`, `--operator`, `--agency`, `--case-notes` | — | printed in the report header |
| `--outdir DIR` | output | where the results go |
| `--evidence-bundle [DIR]` | off | build the handover bundle |
| `--zip` | off | archive the bundle and hash it |
| `--parser ID` | auto | force a parser |
| `-q, --quiet` | off | print only the verdict |

---

## Getting the evidence right

The analysis can only be as good as what goes into it. In rough order of how often each
one ruins a case:

- **Check the clocks first.** Run `camera probe` and compare the firewall's clock too
  (`ssh root@192.168.1.1 date -u`). Enable NTP everywhere. A camera 44 seconds fast makes
  a real ±30 s correlation invisible.
- **Lock the capture to your channel.** A channel-hopping adapter misses most of a flood.
- **Capture the quiet periods.** Hours where nothing happens are what establish the
  background rate. A capture that only runs when you suspect something is happening
  cannot produce a defensible baseline — and it looks like cherry-picking.
- **Collect more than a handful of events.** Ten camera passes is thin; fifty is
  convincing. The report says so when the sample is small.
- **Never edit an evidence file.** Not to fix a typo, not to trim a range. Hash it, keep
  the original, and let the tool do the filtering. The bundle's whole value is that the
  copies match the originals bit for bit.
- **Record the camera and the wireless side over the same period.** `camera watch` next
  to `airodump-ng` is the simplest way to guarantee it.

---

## Troubleshooting

**"no parser recognized this file"** — run `--list-parsers` and force one with
`--parser <id>`. If the file is a capture, check the magic bytes: `xxd file.cap | head -1`
should start `d4c3b2a1`, `a1b2c3d4` or `0a0d0d0a`.

**Zero deauth frames from a capture that should have them** — the adapter was probably
not in monitor mode. The tool says so explicitly when the capture contains packets whose
link type is not 802.11. Confirm with `iw dev wlan1mon info`.

**Timestamps are off by exactly one hour** — a daylight-saving boundary. Use `--tz` with
the correct IANA zone rather than a fixed offset; the zone knows when the transition
happened, a fixed offset does not.

The tool detects the two genuinely ambiguous cases and reports them in the methodology
section rather than resolving them silently. On the night the clocks go back, every
wall-clock reading in the repeated hour happens twice — a year-less `Nov 1 01:30:00`
could be either of two instants an hour apart, and the earlier is assumed. On the night
they go forward, an hour of readings never happens at all, which usually means the
logging device had the wrong timezone. Both are one-hour errors hiding inside a
thirty-second analysis. Ticking **rfc5424** on the OPNsense syslog target removes the
ambiguity entirely by putting a real UTC offset on every line.

**Timestamps are off by a whole year** — a year-less syslog file whose modification date
misled the inference. Pass `--log-year`.

**Camera returns HTTP 401** — you are using the TP-Link cloud login. Create a Camera
Account in the Tapo app (section (c) above).

**Camera reachable but ONVIF silent** — some firmware versions need ONVIF switched on in
the app, and a few models use port 8000 or 80 instead of 2020. Try
`--onvif-port 8000`. RTSP snapshots keep working either way.

**`CORRELATION NOT ESTABLISHED` when you are certain something is happening** — read the
"Why the finding is not stronger" list in section 1 of the report. The usual causes are
clock skew, too few camera events, or a capture that only covers the incidents and so
has no background to compare against.

---

## Project layout

```
deauth_correlator/
  cli.py        argparse and orchestration      parsers/
  config.py     AppConfig                         base.py         parser interface
  timeutil.py   timezone normalization            opnsense.py     dnsmasq / Kea / ISC / hostapd
  hashing.py    SHA-256 chain of custody          pcap.py         pcap and pcapng reader
  events.py     the one event schema              dot11.py        802.11 frame decoding
  drops.py      re-association -> client drop     kismet.py       Kismet SQLite
  correlate.py  the analysis pipeline             airodump.py     airodump-ng CSV
  stats.py      the four tests                    nzyme.py        nzyme / generic frame CSV
  floods.py     burst detection                   camera_csv.py   camera event CSV
  report.py     report.md                         camera_files.py NVR clip filenames
  csvout.py     correlation.csv                 camera/
  plot.py       timeline.png                      onvif_min.py    dependency-free ONVIF
  evidence.py   the handover bundle               tapo.py         Tapo C100 profile
  selftest.py   fixtures and checks               recorder.py     motion events -> CSV
                                                gui/app.py        the six-tab interface
```

## License

MIT. See [SAFETY.md](SAFETY.md) for the scope of what this tool does and does not do.
