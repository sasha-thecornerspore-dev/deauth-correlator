# End-to-end walkthrough

This document takes you from a machine with nothing installed to a sealed evidence
bundle you could hand to a detective. It is a narrative: work through the stages in
order, because each one depends on the one before it. [README.md](../README.md) is the
reference for individual flags and file formats; this is the story of how they fit
together.

Nothing here transmits anything. The tool reads log files, capture files and — when you
ask it to — a camera you own. See [SAFETY.md](../SAFETY.md) for the scope of that claim
and how to verify it against the source.

**What you will have at the end:** a `report.md` written in plain English with four
independent statistical tests, a `correlation.csv` listing every camera event beside the
nearest network disruption, a timeline figure, and a numbered folder containing
hash-verified copies of every source file, so that anyone who receives it can prove the
evidence they are holding is the evidence that was analysed.

**Rough timings.** Stage 1 takes ten minutes. Stage 2 takes another ten and is the most
useful ten minutes in this document, because it shows you a known-good result before
your own evidence is at stake. Stage 3 is days or weeks of collection. Stages 4 to 6 take
an afternoon once the evidence exists.

## Contents

1. [Install the tool and prove it works](#stage-1--install-the-tool-and-prove-it-works)
2. [A dry run on synthetic data, before you touch real evidence](#stage-2--a-dry-run-on-synthetic-data-before-you-touch-real-evidence)
3. [The collection plan](#stage-3--the-collection-plan)
4. [Check the clocks before you collect anything](#stage-4--check-the-clocks-before-you-collect-anything)
5. [Run the real analysis and read the report](#stage-5--run-the-real-analysis-and-read-the-report)
6. [Build the evidence bundle and verify it](#stage-6--build-the-evidence-bundle-and-verify-it)
7. [When the verdict is CORRELATION NOT ESTABLISHED](#stage-7--when-the-verdict-is-correlation-not-established)
8. [What not to do](#stage-8--what-not-to-do)

---

## Stage 1 — Install the tool and prove it works

You need Python 3.10 or newer. Check what you have:

```bash
python --version
```

From the root of the repository:

```bash
pip install -e ".[all]"
```

`pandas`, `numpy`, `matplotlib` and — on Windows — `tzdata` are required and install
automatically. The `[all]` extra adds two optional groups on top of those:

- **scipy** supplies the reference implementations of Fisher's exact test, the
  chi-square test and the binomial tail. Without it the tool falls back to exact
  pure-Python versions that produce the same numbers; section 7 of the self-test
  compares the two backends across 41 contingency tables and fails if they disagree.
  Installing scipy is a speed and familiarity choice, not a correctness one.
- **requests** and **opencv-python** are needed only for the camera features
  (`camera probe`, `camera snapshot`, `camera watch`, and the Camera tab in the
  interface). If you are going to build the camera event list by hand from an NVR, you
  do not need them.

Installing puts `deauth-correlator` and `deauth-correlator-gui` on your path. If your
shell cannot find them afterwards, pip put them in a user scripts directory that is not
on `PATH`. Rather than fight that, run the module directly:

```bash
python -m deauth_correlator --help
```

Every command in this document works in either form. The `python -m` form is used
throughout because it works everywhere.

### Prove the installation is sound

```bash
python -m deauth_correlator --self-test
```

This is not a smoke test. It generates a complete synthetic case in a temporary
directory — a DHCP log, a Kea log, an ISC dhcpd log, a hostapd log, a pcap, a pcapng, a
Kismet database, an airodump CSV, an nzyme CSV, a camera event CSV and a folder of NVR
clip files — and runs the entire pipeline over it twice. The run ends like this:

```
============================================================
SELF-TEST PASSED: all 132 checks passed.
```

It exits 0 when everything passes and 1 when anything fails, so it can go in a script.
The 132 checks are grouped into nine sections, and it is worth knowing what each one is
defending:

| Section | What it proves |
| --- | --- |
| 1. Time handling | UTC offsets in the source survive; year-less syslog lines take the year hint; the ambiguous hour when clocks go back and the non-existent hour when they go forward are both detected and labelled correctly, in both hemispheres |
| 2. Frame decoding and reason codes | A radiotap-wrapped deauthentication frame decodes to the right transmitter, target, BSSID, reason code, signal and channel; a bare disassociation frame does too |
| 3. Parsers over synthetic fixtures | Every parser in the registry is detected automatically from a file it has never seen and produces events; reason codes 1 and 7 come out of the pcap; Kismet's own DEAUTHFLOOD alerts are carried through; every clip row states how its timestamp was derived |
| 4. Positive scenario | A planted correlation is found, *every* significance test clears the threshold rather than just the best one, and the rate ratio exceeds 2 |
| 5. Negative scenario | Camera events and disruptions drawn independently at the same rates over the same period do **not** produce a finding |
| 6. Outputs and chain of custody | The report, the CSVs, the manifest and the evidence bundle are all written, the copied source files re-hash to the original values, and the archive is hashed |
| 7. Statistics backends | scipy and the pure-Python fallback agree on Fisher, chi-square and the binomial across 41 tables |
| 8. Degenerate inputs | No camera events, no disruptions, one camera event, an empty event set, non-overlapping evidence periods, an hour of clock skew, a missing file, an unrecognised file and a header-only CSV each produce an honest answer instead of a crash or a silent result |
| 9. No fabrication | DHCP retransmission backoff, routine lease renewals, repeated DHCPINFORM from a static host and an already-logged disconnection are not counted as client drops; a protected (802.11w) frame yields no reason code rather than ciphertext read as one; a p-value is never printed as exactly zero |

Section 5 matters more than section 4. A correlator that always finds a correlation is
worthless as evidence, and the value of the whole exercise rests on the tool being
capable of saying no. If you ever need to defend the output, section 5 and section 9 are
the ones to point at.

---

## Stage 2 — A dry run on synthetic data, before you touch real evidence

Do this before you collect anything. It costs ten minutes and it means that the first
time you see the tool's output, you are looking at a case whose answer is already known.
When you later run it on your own evidence, you will be comparing against something.

### Keep the fixtures the self-test generates

The self-test normally builds its fixtures in a temporary directory and deletes them.
`--self-test-dir` keeps them instead. Both flags are needed — `--self-test-dir` on its
own does nothing:

```bash
python -m deauth_correlator --self-test --self-test-dir ./fixtures
```

The header now tells you where they went, and the last line confirms they stayed:

```
deauth-correlator 1.0.0 - self-test

Fixtures: /home/you/fixtures
...
SELF-TEST PASSED: all 132 checks passed.
Fixtures kept in /home/you/fixtures
```

Four directories are left behind:

| Directory | Contents |
| --- | --- |
| `positive/` | a four-hour case in which a burst of deauthentication frames was planted 2 to 8 seconds after each of twelve camera events, plus four unrelated background disruptions |
| `negative/` | the same generator with a different seed and no planted relationship: twelve camera events and sixteen disruptions placed independently over the same period |
| `edge/` | the degenerate inputs used by section 8 |
| `positive_output/` | the report, CSVs, manifest and evidence bundle the self-test built from `positive/` while checking section 6 |

`positive/` contains one file per supported format:

```
airodump-01.csv   camera_events.csv   capture-01.cap   capture.pcapng
clips/            dnsmasq.log         hostapd.log      isc-dhcpd.log
kea-dhcp4.log     kismet.kismet       nzyme-deauth.csv
```

The scenario is set in July 2026 in `America/New_York`. `dnsmasq.log` is RFC5424 with a
full date and offset on every line; `hostapd.log` and `isc-dhcpd.log` are classic
RFC3164 with no year at all (`Jul 14 18:08:34 OPNsense hostapd: ...`). That is why the
commands below pass `--log-year 2026`: without it the tool infers the year from each
file's modification time, which is the day you ran the self-test, and in any year other
than 2026 those two files would land twelve months away from everything else. This is
exactly the trap real syslog exports set, which is why the fixtures reproduce it.

### Run the case that should come out positive

```bash
python -m deauth_correlator \
  --opnsense-log fixtures/positive/dnsmasq.log \
  --opnsense-log fixtures/positive/hostapd.log \
  --wifi-capture fixtures/positive/capture-01.cap \
  --wifi-capture fixtures/positive/kismet.kismet \
  --camera-events fixtures/positive/camera_events.csv \
  --tz America/New_York --log-year 2026 \
  --case "DRY-RUN" --operator "your name" \
  --outdir dryrun
```

```
deauth-correlator 1.0.0 - read-only wireless disruption correlator

Reading evidence:
  + dnsmasq.log: 192 event(s) via OPNsense DHCP / system log
  + hostapd.log: 32 event(s) via OPNsense DHCP / system log
  + capture-01.cap: 197 event(s) via 802.11 capture (pcap/pcapng)
  + kismet.kismet: 96 event(s) via Kismet SQLite log
  + camera_events.csv: 12 event(s) via camera event CSV

Analyzing...

Analysis period: 2026-07-14 18:08:04 to 2026-07-14 21:46:48 (3.65 h, America/New_York)
Camera events:   12
Disruptions:     309 events in 16 incidents
Deauth frames:   277 (208 broadcast) in 16 flood(s)
                 de:ad:be:ef:00:01: 277 frames

Coincidences:    12/12 within +/-30s  (baseline 6.5%, expected 0.8)
Rate ratio:      72.97x
p-values:        binomial 5.525e-15 | permutation 9.999e-05 | Fisher 1.492e-14

Written:
  dryrun/correlation.csv
  dryrun/events.csv
  dryrun/incidents.csv
  dryrun/report.md
  dryrun/timeline.png
  dryrun/MANIFEST.json

CORRELATION FOUND: 12 of 12 camera passes (100%) coincided with a wireless disruption
within +/-30 s; 0.8 would be expected by chance (every test p <= 0.0001, 73.0x the
background rate).
```

### Every number in that block, explained

**`Analysis period ... (3.65 h)`.** Not the span of the camera log and not the span of
the capture, but the overlap of the two. The camera CSV and the capture each start and
end at slightly different moments; statistics are computed only where both were in
force. This matters more than it looks: a background rate computed over a week of camera
footage when the capture ran for two hours would understate the background and inflate
the finding. Anything discarded by this rule is printed under "Notes on the analysis
period" and repeated in section 8.2 of the report.

**`Disruptions: 309 events in 16 incidents`.** 309 is the raw count — every
deauthentication frame, every disassociation, every hostapd link reset, every DHCP
re-association that looked like a client drop. 16 is the number of physical events those
represent, after grouping anything within `--incident-gap` (default 10 s) into one
incident. A 200-frame flood is one attack, and a hostapd disconnect plus the DHCP
handshake it caused are one outage seen twice. **The statistics count the 16, not the
309.** Counting raw events would multiply a single disruption into hundreds of data
points and make any result look overwhelming.

**`Coincidences: 12/12 within +/-30s`.** Twelve of the twelve camera events had an
incident within thirty seconds either side.

**`(baseline 6.5%, expected 0.8)`.** Take the union of the ±30-second windows drawn
around all 16 incidents and measure what fraction of the 3.65-hour period it covers:
6.5%. That is the probability that a vehicle passing at a randomly chosen moment lands
next to a disruption by accident. Multiply by 12 passes and you get 0.8 — the number of
coincidences you would expect from unrelated streams. Observed 12, expected 0.8.

**`Rate ratio: 72.97x`.** Disruption incidents per minute inside the camera windows
divided by incidents per minute everywhere else. This is the test that is hardest to
fake and easiest to explain to a non-statistician: the network fell over 73 times more
often while a vehicle was passing than at any other time.

**`p-values: binomial ... | permutation ... | Fisher ...`.** Three tests resting on
three different sets of assumptions. The binomial treats each pass as an independent
draw against the 6.5% baseline. The permutation test slides the entire camera sequence
by a random offset 10,000 times and recounts, which preserves the real spacing of the
passes and the real clustering of the disruptions and so does not need the independence
assumption at all. Fisher's exact test works on a 2×2 table of disjoint 60-second bins.
The permutation value of `9.999e-05` is the floor for 10,000 trials — no shifted
arrangement out of ten thousand beat the real one — not a coincidence of rounding.

**`(every test p <= 0.0001 ...)`** in the verdict line. The headline is decided on the
**weakest** of the three p-values, never the best. Here that is the permutation test at
1.0e-04. Reporting the smallest of several p-values is the same error as running tests
until one agrees, and it inflates the false-positive rate several times over. The report
says which test was the weakest, by name, in section 3.

**The verdict itself.** `CORRELATION FOUND` requires all three of these at once:

1. at least **3** coincidences,
2. **every** p-value below `--alpha` (default 0.01), not just the most favourable one,
3. a rate ratio of at least **2**.

If any one fails, the verdict is `CORRELATION NOT ESTABLISHED` and the report lists the
condition that failed. If there are fewer than three camera events in the analysis
period, or no disruptions at all, the verdict is `INSUFFICIENT DATA`.

### Now run the case that should come out negative

Same command, same flags, `negative/` instead of `positive/`:

```bash
python -m deauth_correlator \
  --opnsense-log fixtures/negative/dnsmasq.log \
  --opnsense-log fixtures/negative/hostapd.log \
  --wifi-capture fixtures/negative/capture-01.cap \
  --wifi-capture fixtures/negative/kismet.kismet \
  --camera-events fixtures/negative/camera_events.csv \
  --tz America/New_York --log-year 2026 \
  --case "DRY-RUN-NEG" --outdir dryrun-neg
```

```
Analysis period: 2026-07-14 18:59:31 to 2026-07-14 21:45:11 (2.76 h, America/New_York)
Camera events:   11
Disruptions:     332 events in 16 incidents
Deauth frames:   300 (234 broadcast) in 16 flood(s)
                 de:ad:be:ef:00:01: 300 frames

Coincidences:    0/11 within +/-30s  (baseline 9.1%, expected 1.0)
Rate ratio:      0.00x
p-values:        binomial 1 | permutation 1 | Fisher 1

Notes on the analysis period:
  ! 0.8 h of wireless evidence falls outside the period covered by the camera log and
    was excluded from the statistics.

CORRELATION NOT ESTABLISHED: 0 of 11 camera passes coincided with a wireless
disruption within +/-30 s, which is not distinguishable from chance (1.0 expected).
```

Two things to notice. The disruption evidence here is *more* aggressive than in the
positive case — 300 deauthentication frames, 234 of them broadcast, from the same source
MAC, in 16 floods — and the tool still reports nothing, because none of it lines up with
a camera event. Volume of attack evidence is not correlation. And "Camera events: 11",
not 12: one camera event fell outside the overlap of the two streams and was excluded,
which is stated rather than quietly dropped.

Open both `report.md` files side by side. Ten minutes reading a report you already know
the answer to is worth more than an hour reading one you do not.

### Exit codes

```bash
echo $?          # bash / zsh
$LASTEXITCODE    # PowerShell
```

| Code | Meaning |
| --- | --- |
| 0 | correlation found |
| 1 | correlation not established (this includes `INSUFFICIENT DATA`) |
| 2 | the analysis could not be run at all — no inputs, only one side of the evidence, an invalid parameter, or nothing parsed from any file |

Exit 1 is a result. Exit 2 is a problem with the command or the files.

### Before moving on

Delete `dryrun/`, `dryrun-neg/` and `fixtures/`, or at least keep them well away from
your case directory. They are synthetic data generated by a random number generator, the
MAC `de:ad:be:ef:00:01` is not a real device, and nothing from them should ever appear in
a bundle that leaves your hands.

---

## Stage 3 — The collection plan

Everything from here depends on evidence that does not exist yet. The analysis can only
be as good as what goes into it, and the two most common ways a case fails are decided
before a single command is run: the clocks were wrong, or the capture only ran when
someone was already suspicious.

You need three things, and the third is the one people forget.

### 1. Wireless evidence

The primary evidence is a monitor-mode capture, because the deauthentication frames and
their reason codes exist only in the radio traffic. A DHCP log can show that a device
dropped; only a capture can show what pushed it off. README section (a) covers the
adapter choice and the `airodump-ng` invocation in detail. Two points bear repeating
because they ruin captures constantly:

- **Lock the capture to your own channel and BSSID.** A channel-hopping adapter is
  listening on channel 11 while the flood happens on channel 6, and records nothing.
  Locking also keeps the capture off other people's traffic, which is where the legal
  exposure is.
- **Match the band.** A 2.4 GHz-only adapter records nothing at all from a 5 GHz
  network.

The firewall's DHCP log is a valuable second stream, and worth collecting even if you
have a capture. It is derived from a completely different mechanism, it comes from a
device you can testify about, and it survives when the capture adapter dies overnight.
README section (b) covers exporting it; the rfc5424 option on the OPNsense syslog target
is worth ticking, because it writes a full date and UTC offset on every line and removes
an entire category of ambiguity from stage 4.

### 2. Camera evidence

Either a CSV of passes, one row per pass:

```csv
timestamp,plate,make,model,notes
2026-07-14T18:08:30-04:00,7XK2291,Ford,F-150,"vehicle pass 1, westbound"
2026-07-14T18:36:01-04:00,8BQ4417,Honda,Civic,"vehicle pass 2, westbound"
```

or a directory of clips whose filenames carry their start time (Tapo, Hikvision, Dahua,
Reolink, Amcrest, UniFi Protect, Blue Iris, ISO or epoch naming are all recognised), or
both. `camera watch` writes exactly the CSV format above and saves a still for each
event into an exhibits folder, so a coincident pass arrives with a picture attached.

Timestamps that carry their own UTC offset (`-04:00` above) are unambiguous and should
be preferred over bare local times wherever the source can produce them.

### 3. Quiet time — the part people skip

This is what makes the statistics work, and it is not optional.

The baseline in the output block above — 6.5% — is the fraction of the observation
period that lies within ±30 s of some disruption. It is computed from your data, not
assumed, and it is the yardstick everything else is measured against. Sixteen isolated
incidents each cover 60 seconds of a ±30-second window, so:

- Over a **four-hour** capture (14,400 s), 960 s of coverage is a baseline of about
  **6.7%**. Twelve of twelve coincidences against that baseline is overwhelming.
- Over **forty minutes** of capture (2,400 s) that you started only when you suspected
  trouble, the same 16 incidents cover the same 960 s — but now that is **40%** of the
  period. Twelve of twelve is far less remarkable, and the rate ratio has almost no
  "outside" time left to compare against.
- Widen to ±120 s in that forty-minute capture and the windows cover 3,840 s of a
  2,400-second period. The baseline reaches **100%**, the test has no power at all, and
  the sensitivity table in section 4 of the report will show the result evaporating as
  the window grows. That table exists precisely so a reader can see this.

So: **hours where nothing happens are not wasted capture.** They are the denominator. A
capture that only runs when you suspect something cannot produce a defensible baseline,
and on the stand it looks exactly like what it is — a sample chosen after the fact to
contain the events you wanted.

Run continuously. A Raspberry Pi left in a corner is the standard answer. If disk is the
constraint, filter as you capture rather than shortening the window:

```bash
sudo dumpcap -i wlan1mon -f "type mgt" -b filesize:102400 -w case0714.pcapng
```

### How much is enough

Ten camera passes is thin. Fifty is convincing. Below three the tool refuses to test at
all and returns `INSUFFICIENT DATA`, because three coincidences is the minimum the
verdict requires. The report flags a small sample explicitly rather than letting a
striking p-value from four events speak for itself.

Run the camera side and the wireless side over the same period. `camera watch` running
next to `airodump-ng` is the simplest way to guarantee it, and the overlap rule in stage
2 is what happens when you do not.

### Keep a collection log

Write down, contemporaneously and by hand: which adapter, which channel, which BSSID,
when you started and stopped each capture, when you touched anything, and what the
clocks read. None of this is generated by the tool, all of it will be asked about, and
none of it can be reconstructed afterwards.

---

## Stage 4 — Check the clocks before you collect anything

An hour of clock skew silently destroys a real result or manufactures a false one. This
is the single most common way the analysis goes wrong in practice, which is why the tool
has a dedicated diagnostic for it — but the diagnostic is a safety net, not a substitute
for getting it right at collection time.

### Why it is fatal rather than merely annoying

The default coincidence window is ±30 seconds. A camera running 44 seconds fast shifts
every recorded pass 44 seconds away from the disruption it actually accompanied, and
every one of them falls outside the window. The tool reports 0 of 12 with complete
confidence. There is nothing in the numbers to suggest anything is wrong; the p-values
are 1, the rate ratio is 0, and the finding is a clean, wrong negative.

The reverse is worse. If a clock error happens to shift passes *onto* unrelated
disruptions, you get a strong finding from nothing.

### Measure the camera

Set the password in the environment so it does not land in shell history:

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

The clock line grades itself in three bands:

| Measured error | Wording | What to do |
| --- | --- | --- |
| up to 2 s | *well within tolerance* | nothing |
| 2 to 120 s | *large enough to matter for a ±30 s analysis* | fix the clock, and pass the offset for evidence already collected |
| over 120 s | *SEVERE - fix the camera clock* | fix it before collecting anything further |

`--camera-clock-offset` is **added to every camera timestamp**, so the value the probe
prints is the negative of the measured error. A camera 43.71 s ahead needs
`--camera-clock-offset -43.710` to pull its events back to true time. The correction is
recorded in section 8.3 of the report, so a reader can see it was applied and by how
much. The interface fills this in automatically after a probe.

Correcting after the fact is a fallback for evidence you already have. Fixing the
camera's clock and re-collecting is better, because a measured offset only holds at the
moment it was measured and cheap camera clocks drift.

The C100 speaks ONVIF on port 2020 and RTSP on 554, both gated by a **Camera Account**
created in the Tapo app under Device Settings → Advanced Settings → Camera Account. The
TP-Link cloud login will not work and produces HTTP 401. `camera help` prints the setup
steps.

### Measure the firewall

```bash
ssh root@192.168.1.1 date -u
date -u
```

Compare them. Then turn NTP on everywhere — the firewall, the camera, the capture
machine, the analysis machine — and confirm it is actually synchronising rather than
merely configured.

### The CHECK THE CLOCKS diagnostic

After every run the tool asks a question the statistics do not: *would these two streams
line up if one of them were shifted by a constant amount?* It takes the offsets that
would actually align some pair of events, tries each one, and reports the best. Here is
a real run of the positive fixtures with an hour of skew introduced:

```
*** CHECK THE CLOCKS ***
  The camera events line up with the wireless disruptions if the camera times
  are treated as 3620 s earlier than recorded (12 of 12 would coincide, against
  0 as the data stands). This is almost exactly one hour, which nearly always
  means a timezone or daylight-saving mismatch between the camera and the
  network logs rather than a real delay.
  This is a diagnostic, not a finding. Correct the clock, re-export,
  and re-run; do not report a correlation at a shifted offset.
```

The same text appears as a block quote at the top of section 1 of the report, so it
cannot be missed by someone who only reads the summary.

Reading it:

- **3620 s, not 3600.** The offset is chosen from differences that actually occur in the
  data, and in this scenario each burst began a few seconds after its pass. Expect a
  number near a round one rather than exactly on it. The wording keys off the magnitude:
  within 90 s of an hour it names a timezone or daylight-saving mismatch, within 60 s of
  half an hour it names a half-hour zone, near any whole number of hours it names a
  timezone mismatch, and otherwise it tells you to check the camera with `camera probe`
  and the firewall with `date -u`.
- **"12 of 12 would coincide, against 0 as the data stands"** — but the verdict line
  above it said 0 of 8. The lag scan considers every camera event; the headline counts
  only those inside the overlap of the two streams, and the skew had pushed four of them
  outside it. The disagreement is itself a symptom.
- **The block only appears when it means something.** It requires at least three camera
  events, an offset of at least a second, and a shifted alignment that beats the real one
  by at least three coincidences, covers at least 60% of the camera events, and is at
  least double what the data shows as recorded. Genuinely unrelated data does not trigger
  it — that is one of the checks in section 8 of the self-test.

**What to do about it:** find the wrong clock, fix it, re-export the logs, and run again.
The second run is the one to rely on. Do not report the correlation at the shifted
offset — see stage 8.

---

## Stage 5 — Run the real analysis and read the report

### The command

```bash
python -m deauth_correlator \
  --opnsense-log /var/log/opnsense/dhcp.log \
  --opnsense-log /var/log/opnsense/hostapd.log \
  --wifi-capture case0714-01.cap \
  --wifi-capture case0714-01.csv \
  --camera-events camera_events.csv \
  --camera-events clips/ \
  --camera-clock-offset -43.710 \
  --tz America/New_York \
  --case "2026-CF-00417" \
  --operator "J. Schatz" \
  --agency "Example County Sheriff's Office" \
  --outdir case0714
```

Each input flag can be repeated and formats are detected automatically, so you can hand
it everything you have without sorting it first. Points worth understanding rather than
copying:

- **`--tz`** governs every displayed time and, more importantly, supplies the rules for
  timestamps that carry no UTC offset of their own. Use an IANA zone name, never a fixed
  offset: the zone knows when daylight saving changed, a fixed offset does not, and that
  is where the one-hour errors come from.
- **`--log-year`** is only needed for year-less syslog files whose modification date
  would mislead the inference — a log exported in January covering December, for
  instance. The tool infers the year otherwise, handles the December-to-January rollover,
  and **states the inference in section 8.6 of the report** so nobody has to wonder.
- **`--camera-clock-offset`** carries the correction measured in stage 4.
- **`--case`, `--operator`, `--agency`** go in the report header and the bundle cover
  sheet. Fill them in on any run whose output might leave your machine.
- Leave `--window`, `--alpha`, `--trials`, `--incident-gap` and the rest at their
  defaults unless you have a reason you are prepared to state. Every parameter is printed
  in section 8.3 of the report, and a non-default value invites the question of what you
  tried first. If you do need to change one, change it once, before you look at the
  result.

If the command exits 2, nothing was analysed. The two usual causes are giving only one
side of the evidence — the tool needs at least one camera source *and* at least one
wireless source — and giving files nothing could parse. See stage 7.

### Reading report.md, section by section

The report always has the same eleven sections in the same order, even when a section has
nothing to show, in which case it says so. A report that jumps from 3 to 5 invites the
question of what was removed.

**Header.** Case number, operator, agency, generation time in UTC, the analysis timezone,
and the tool version. The timezone line states explicitly that every local time below is
in that zone.

**1. Summary.** The finding in one bold line, then the same thing in a sentence a
non-technical reader can follow, then the baseline and observed coincidence rates. When
the verdict is not `CORRELATION FOUND`, a list headed "Why the finding is not stronger"
names each condition that failed. If the clock diagnostic fired, it is quoted here.
*This is the section a prosecutor reads first and may be the only one they read closely.*

**2. What the evidence shows.** The observation period, the raw event counts broken out
by type with a plain-English gloss on each, the explanation of incident grouping, and —
when there were coincidences — the median and range of the delay between camera event
and disruption. That last sentence is more useful in argument than it looks: a consistent
sign and a tight spread ("a median of 4.0 s after the camera event, range 3.0 s after to
8.0 s after") describe a repeatable mechanism, while deltas scattered either side of zero
describe overlap.

**3. Statistical analysis.** The four tests, each with its assumptions stated in words
before its number. Section 3 opens by naming the weakest of the three p-values and the
test it came from, because that is the figure the verdict rests on. If the tests disagree
about the answer — some clearing `--alpha` and others not — the report says so here and
explains the usual cause, which is several camera rows describing a single vehicle pass
breaking the binomial test's independence assumption. Sections 3.1 to 3.5 are the
coincidence count, the binomial, the permutation test, Fisher and chi-square with the 2×2
table printed in full, and the rate ratio with the durations and incident counts it was
computed from. *An opposing expert will start here, and everything they need to recompute
the numbers is on the page.*

**4. Window sensitivity.** The same analysis at ±10, ±15, ±30, ±60 and ±120 seconds, with
the primary window marked. The last column is the weakest test at each width. A real
relationship shows up across a range of widths; a result that appears at exactly one
width and nowhere else is a sign of chance, or of a window chosen to fit. *This is the
answer to "how many windows did you try?" and it is worth reading before anyone asks.*

**5. Deauthentication frames and floods.** How many frames were recovered, how many were
addressed to the broadcast address (which disconnects every client at once rather than
one device), and what proportion carried reason codes 1 or 7 — the defaults emitted by
common deauthentication tools, where an access point disconnecting a client for ordinary
reasons normally reports 3, 4 or 8. Then a table of source addresses, a table of reason
codes, and a table of detected floods with start time, duration, frame count, peak rate,
principal source and broadcast count. The source-address table is preceded by a warning
that management-frame source addresses are unauthenticated and can be set to any value.
*This section is what distinguishes a deliberate attack from a failing access point.*

**6. Camera events, one by one.** Every camera event with its plate, whether it
coincided, the nearest disruption, the delta in plain English, the deauthentication
source MAC and the reason code. `correlation.csv` carries the same rows with source-file
references for each. *This is the section a detective will read, line by line, against
the video.*

**7. Timeline.** The figure, with a caption explaining the encoding: amber bands are
camera events with their windows drawn to scale, red triangles mark passes that
coincided, grey triangles those that did not, and the lower panel shows disruption
incidents per five minutes.

**8. Methodology.** 8.1 is a numbered account of what the tool did, in order, including
how DHCP traffic was collapsed into association episodes and what made a repeat handshake
count as a client drop. 8.2 states the analysis period and why it is the overlap. 8.3 is
every parameter with its value and its effect — including the camera clock offset
applied. 8.4 lists each input file, its role, the parser used and how many events it
produced. 8.5 records the software environment down to library versions, the analysis
host, and the exact command line. 8.6 appears when there were warnings and reproduces
them verbatim, including year inferences and daylight-saving ambiguities. *8.3 and 8.5
are what make the run reproducible; 8.6 is where anything the tool had to assume is
visible rather than buried.*

**9. Chain of custody.** Every input file with its size, modification time and SHA-256,
plus the full paths as read. *See stage 6.*

**10. What this analysis does not prove.** Mandatory and non-negotiable: correlation is
not identification; MAC addresses in management frames are forgeable; clock accuracy
bounds the resolution; interference, a failing access point and a defective client radio
produce the same signature as an attack; and the absence of capture evidence is not the
absence of an attack. *Read this before you describe the finding to anyone. If you would
not say these sentences out loud, do not hand over the report.*

**11. Glossary.** Deauthentication frame, disassociation frame, reason code, BSSID,
broadcast address, DHCP, monitor mode, p-value, rate ratio — each in two or three
sentences aimed at a reader with no networking background.

### The other outputs

| File | What it is for |
| --- | --- |
| `correlation.csv` | one row per camera event, with local *and* UTC times and the UTC offset in separate columns, so every delta can be recomputed from absolute times alone; includes the source file and row or packet reference for each camera event |
| `events.csv` | every event parsed from every source, normalized, with the original raw log line or frame summary preserved in the last column |
| `incidents.csv` | the disruption incidents the statistics actually counted, with the kinds, source MACs, client MACs and reason codes that went into each |
| `timeline.png` | the figure from section 7 |
| `MANIFEST.json` | machine-readable: verdict, every statistic, the sensitivity table, the clock-offset scan, flood details, the analysis period, the full configuration, input and output hashes, and the warnings |
| `MANIFEST.txt` | the same in plain text, for anyone without a JSON viewer |

`events.csv` is the one to keep when someone asks you to show your working. Every row
carries the file it came from and the line or packet number, so any claim in the report
can be traced back to a byte in a source file.

---

## Stage 6 — Build the evidence bundle and verify it

Add `--evidence-bundle --zip` to the command from stage 5. Nothing else changes; the
analysis is identical.

```bash
python -m deauth_correlator \
  --opnsense-log /var/log/opnsense/dhcp.log \
  --wifi-capture case0714-01.cap \
  --camera-events camera_events.csv \
  --camera-clock-offset -43.710 \
  --tz America/New_York \
  --case "2026-CF-00417" --operator "J. Schatz" \
  --agency "Example County Sheriff's Office" \
  --outdir case0714 \
  --evidence-bundle --zip
```

```
Building evidence bundle in case0714/evidence_2026-CF-00417 ...
  . Bundle started by deauth-correlator 1.0.0
  . Case 2026-CF-00417; operator J. Schatz
  . Writing report.md
  . Writing correlation.csv
  . Writing the full event and incident tables
  . Rendering timeline.png
  . Copied and hash-verified dhcp.log (sha256 fc4abc0cc8fc636e...)
  . Copied and hash-verified case0714-01.cap (sha256 dd5ebb6de51ed420...)
  . Copied and hash-verified camera_events.csv (sha256 c636efec46d7a64c...)
  . Writing MANIFEST.json
  . Creating the archive
  . Archive sha256 45fa6590ada2c6fdf679556552af1ed3152b04560c0f79033bd86dd28bf1649a
  . Bundle complete
Evidence bundle: case0714/evidence_2026-CF-00417
13 file(s) written.
Archive: case0714/evidence_2026-CF-00417.zip
Archive SHA-256: 45fa6590ada2c6fdf679556552af1ed3152b04560c0f79033bd86dd28bf1649a
```

Give `--evidence-bundle` a directory if you want to choose the location; with no argument
it uses `<outdir>/evidence_<case number>`.

"Copied and hash-verified" means the file was hashed before it was read, copied, and
hashed again in its new location, and the two values matched. A mismatch is reported in
the bundle's cover sheet and in the build log rather than passed over.

### What is in the bundle

```
00_READ_ME_FIRST.txt          plain text, aimed at a non-technical reader
00_MANIFEST.json              hashes and the complete parameter set
00_MANIFEST.txt               the same in plain text
01_report.md                  the findings
02_correlation.csv            one row per camera event
03_timeline.png               the figure
04_all_events.csv             every parsed event
05_disruption_incidents.csv   the incidents the statistics counted
06_source_files/              unmodified, hash-verified copies of the inputs
chain_of_custody.log          timestamped log of how the bundle was built
```

The numbering is deliberate: the folder reads in order in any file browser, and
`00_READ_ME_FIRST.txt` sorts first. That file states the case number, the finding, what
each file is, how to verify the hashes, and a scope note pointing at section 10 of the
report.

If you recorded stills with `camera watch --exhibits exhibits/` during collection, attach
them through the Evidence builder tab in the interface, which copies and hashes each one
into an `07_exhibits` folder in the bundle. The command line does not attach exhibits; it
builds the layout above and nothing else. A coincident pass with a picture attached is
worth more than a row in a table, so it is worth the extra step.

### Verify a hash yourself

Do this once on your own bundle before you hand it over, so that you have done it and can
say so. The recipient should do the same.

```powershell
# Windows (PowerShell or cmd)
certutil -hashfile 06_source_files\case0714-01.cap SHA256
```

```bash
# macOS
shasum -a 256 06_source_files/case0714-01.cap

# Linux
sha256sum 06_source_files/case0714-01.cap
```

Compare the result with the value for that file in `00_MANIFEST.json` or in section 9 of
the report; both carry the full hash. `chain_of_custody.log` records the first sixteen
characters against a timestamp, which is enough to confirm which file a log line refers
to but is not the value to compare against.

Do the same for the archive itself against the `Archive SHA-256` printed at the end of
the run. If the archive hashes correctly, everything inside it is intact and you do not
need to check the files individually.

A matching hash means the file is bit-for-bit identical to the one that was analysed.
Any difference at all — a single byte, a line ending changed by a text editor, a file
opened and re-saved — produces a completely different value. That is the entire point:
the bundle's worth rests on the copies matching the originals exactly.

### What to hand over

The zip, its SHA-256 written down separately from the zip, and your contemporaneous
collection log from stage 3. Send the hash by a different route than the archive; a hash
travelling inside the thing it certifies proves nothing.

---

## Stage 7 — When the verdict is CORRELATION NOT ESTABLISHED

This is a real answer and sometimes it is the right one. But before accepting it, work
down this list in order. The tool has already done most of the diagnosis for you; the
information is in the output if you know where to look.

### Step 1 — Is there a `*** CHECK THE CLOCKS ***` block?

Look at the console output and at the top of section 1 of the report. If the block is
there, stop. Nothing else in the report is trustworthy until the clocks are reconciled.
Go back to stage 4, find the wrong clock, fix it, re-export, and re-run. Do not proceed
by applying the offset the diagnostic printed and calling the result a finding — see
stage 8.

### Step 2 — Read "Why the finding is not stronger" in section 1

The report names every condition that failed, in these words:

```
Why the finding is not stronger:

- only 0 of 11 camera events coincided (at least 3 coincidences are required)
- the binomial test gave p = 1, which does not clear the threshold of 0.01. Every
  test has to clear it, not just the most favourable one
- disruptions were only 0.00x more frequent during camera windows than outside them
  (at least 2x is required)
```

Which line appears tells you where to go next.

**"only N of M camera events coincided".** Either there is genuinely nothing there, or
the two streams are misaligned in a way the lag scan did not catch — a drift rather than
a constant offset, for instance, which a cheap camera clock will produce over days. Check
the sign and spread of the deltas in `correlation.csv`: if every camera event has a
disruption a consistent 90 seconds away, that is not chance, it is a clock.

**"the *X* test gave p = ..., which does not clear the threshold".** Note which test.
If the binomial fails while the permutation test passes, the most likely cause is that
several camera rows describe one vehicle pass — a clip folder and a camera CSV covering
the same events, or an NVR writing several short clips per pass. The binomial assumes
each row is an independent draw and that assumption is broken. `--camera-dedupe` (default
2 s) merges events that close together **from different sources**; deliberately, it does
not merge events that close together within a single source, because those are your own
data rather than a duplicate import. Raise it if your sources overlap at wider spacing.
The report discloses any de-duplication in the warnings.

**"disruptions were only Nx more frequent during camera windows".** The background rate
is too high relative to what happens during passes. Usually this means the network is
genuinely unstable for other reasons, or the disruption count is dominated by something
that is not an attack. Look at the event-type table in section 2: if `client_drop`
outnumbers `deauth` heavily, you may be measuring a flaky access point.

**"the tests disagree about the answer".** One test's assumptions are not being met. Take
the weakest figure as the honest one and find out why they disagree before reporting
anything.

### Step 3 — Is the verdict `INSUFFICIENT DATA` rather than `NOT ESTABLISHED`?

Two causes, both stated in the headline:

- **Fewer than three camera events in the analysis period.** Note *in the analysis
  period* — you may have supplied thirty and had twenty-seven fall outside the overlap.
  Check the next step.
- **No wireless disruption events at all.** If you have a capture that should contain
  deauthentication frames, go to step 5.

### Step 4 — Check "Notes on the analysis period"

```
Notes on the analysis period:
  ! 0.8 h of wireless evidence falls outside the period covered by the camera log and
    was excluded from the statistics.
```

Some exclusion is normal — the two streams never start and stop at the same instant. A
large exclusion means the two sides of your evidence barely overlap, and the effective
sample is much smaller than the file sizes suggest. If most of one stream is being
discarded, you have a collection problem, not an analysis problem: go back and capture
both sides over the same window.

If the exclusion is total, the report says the periods do not overlap at all and claims
nothing. That is usually a timezone error rather than a scheduling one — check whether
one source is being read in the wrong zone before assuming the recordings really missed
each other.

### Step 5 — Did the capture actually record management frames?

If section 5 of the report shows zero deauthentication frames from a capture that should
have them, the adapter was probably not in monitor mode. The tool detects this case
explicitly rather than reporting zero as though none had occurred:

```
capture-01.cap: contains 84213 packets but none use an 802.11 link type. The adapter
was probably not in monitor mode when this was captured, so no management frames were
recorded.
```

That message appears in the console warnings and in section 8.6 of the report. Confirm
with `iw dev wlan1mon info`, which should report `type monitor`, and check the capture
directly:

```bash
tshark -r case0714-01.cap -Y "wlan.fc.type_subtype == 12" \
       -T fields -e frame.time -e wlan.ta -e wlan.da -e wlan.fixed.reason_code
```

A capture in monitor mode on the wrong channel is the other half of this problem, and it
looks identical from the file: management frames exist, but not the ones you wanted.

### Step 6 — Did every file parse?

Warnings appear as `!` lines in the console and again in section 8.6:

- **"no parser recognized this file"** — run `--list-parsers` and force one with
  `--parser <id>`. For a capture, check the magic bytes: `xxd file.cap | head -1` should
  begin `d4c3b2a1`, `a1b2c3d4` or `0a0d0d0a`.
- **"not found; skipped"** — a path typo. The run continues without that file, so check
  that "Reading evidence" lists everything you passed.
- **A file that parsed but yielded zero events** — the format was recognised but nothing
  in it was relevant. A DHCP log with no lease activity, or an airodump CSV with no
  station rows.

Compare the file list in section 8.4 of the report against what you intended to supply.

### Step 7 — Are the timestamps in the right year and the right hour?

Section 8.6 records every year inference and every daylight-saving ambiguity verbatim. If
times are off by exactly one hour, use `--tz` with the correct IANA zone rather than a
fixed offset. If they are off by a whole year, a year-less syslog file's modification date
misled the inference — pass `--log-year`.

Two cases are genuinely ambiguous and the tool reports them rather than resolving them
silently. On the night the clocks go back, every wall-clock reading in the repeated hour
happens twice, and a year-less `Nov 1 01:30:00` could be either of two instants an hour
apart; the earlier is assumed and the assumption is stated. On the night they go forward,
an hour of readings never happens at all, which usually means the logging device had the
wrong timezone configured. Both are one-hour errors hiding inside a thirty-second
analysis.

### Step 8 — Accept the answer

If the clocks are right, the streams overlap, the capture is real, every file parsed, and
the sample is adequate — then the honest conclusion is that the correlation is not
established, and that is what the report says. Hand it over as it stands. A negative
result from a properly conducted analysis is evidence too, and it is worth considerably
more than a positive one obtained by adjusting parameters until the answer changed.

---

## Stage 8 — What not to do

**Do not edit an evidence file.** Not to fix a typo in a note column, not to trim a range
you think is irrelevant, not to convert line endings, not to open it in a spreadsheet and
save. Any of those changes the hash, and the hash is the only thing making the copies in
your bundle worth anything. Hash it, keep the original untouched, and let the tool do the
filtering — every parameter it filtered with is printed in section 8.3.

**Do not report a correlation found at a shifted lag.** If the only way the two streams
line up is by moving one of them, you have found a clock error, not an attack. The tool
says this in three places for a reason. A lag with no independent explanation is exactly
the kind of finding that collapses under cross-examination, and it will take the rest of
your case with it. Fix the clock, re-collect or re-export, and run again.

**Do not transmit anything.** This tool has no capability to send an 802.11 frame and
that is deliberate. Transmitting deauthentication frames is unlawful in most
jurisdictions regardless of whose network it is — in the United States the FCC has issued
substantial fines for Wi-Fi blocking under 47 U.S.C. § 333. Do not test your setup by
attacking your own network to see whether the tool notices. If you are building a case
about someone doing this, do not hand them the argument that you did it too.

**Do not capture on networks you do not own.** Lock the capture to your own BSSID. It
keeps the evidence focused and it keeps you clear of other people's traffic.

**Do not tune parameters until the answer changes.** Change a default once, before you
look at the result, for a reason you can state. Every value ends up in section 8.3, and a
non-default window invites the question of what you tried first. The sensitivity table
exists so you never need to move `--window` to show the result is stable.

**Do not overstate the finding.** Section 10 of the report is not boilerplate to skip
past. A strong correlation shows that network disruptions happened when a vehicle passed.
It does not establish who was in the vehicle, who operated any equipment, or that a
device was present at all — the source MAC in a management frame is chosen by whatever
sent it and can be any value, including an innocent device's. Say "the disruptions
coincided with the passes to a degree that is not explicable by chance". Do not say "the
vehicle was jamming the network". The first is what the analysis supports and it is
strong enough on its own.

**Do not delete the intermediate outputs.** `events.csv` and `incidents.csv` are how you
answer "show me where that number came from" months later, when you no longer remember.
They cost nothing to keep.

---

## Where to go next

- [README.md](../README.md) — every flag, every input format, monitor-mode adapter
  selection, OPNsense log export, Tapo C100 setup, and how the statistics work.
- [SAFETY.md](../SAFETY.md) — exactly what the tool does on a network, with the greps to
  verify it against the source yourself.
- `python -m deauth_correlator --gui` — the same pipeline in six tabs, in the order the
  work happens: Case, Evidence, Camera, Analyze, Results, Evidence builder. It hashes
  each file the moment you attach it, so the chain of custody starts before any analysis,
  and it can save and reload a case file so a run can be reproduced later. Camera
  passwords live in memory for the session only and are never written to the case file.
  The interface needs Tkinter, which ships with most Python installations but is a
  separate package on some Linux distributions (`sudo apt install python3-tk`).
- `python -m deauth_correlator --list-parsers` — what each parser accepts and what it
  extracts, when automatic detection needs overriding with `--parser`.
