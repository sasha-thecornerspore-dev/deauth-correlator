# Changelog

All notable changes to this project are recorded in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Because the
output of this tool is used as evidence, any change to how a verdict is reached will be
listed explicitly, with the direction of its effect stated.

## [1.2.0] - 2026-08-15

You should not have to go and find the logs. Attach the camera events, press one button,
and the firewall's own DHCP and system logs for that period are pulled, hashed and
attached for you.

### Added

- **`deauth-correlator fetch`** reads the DHCP and system logs straight off an OPNsense
  firewall, for the period your camera events cover. There is a matching block on the
  Evidence tab of the graphical interface: fill in the address and API key, press
  **Fetch logs for my camera events**, and the results are attached to the analysis
  where you would otherwise have dropped an exported file.

  ```bash
  export DEAUTH_CORRELATOR_OPNSENSE_SECRET='...'
  deauth-correlator fetch --firewall-host 192.168.1.1 --firewall-key KEY \
                          --camera-events passes.csv
  ```

  Create the API key under System > Access > Users > (your user) > API keys; it
  downloads as a text file holding both halves. `fetch probe` checks the connection,
  `fetch sources` lists which logs your firewall actually has, and `fetch fingerprint`
  prints the certificate so it can be pinned.

- **The time window is derived, not guessed.** It comes from the camera events
  themselves — the span they cover, widened by a baseline margin (2 hours by default).
  The margin is not decoration: every statistic in this tool compares the disruption
  rate inside the event windows against the rate outside them, so a log covering only
  the events has no outside and would produce the most flattering possible answer. A
  request with no camera events, or spanning more than a month, is refused rather than
  guessed at.

- **The fetch cannot write to the firewall, by construction.** OPNsense exposes its logs
  through one controller with four actions, and one of them — `clear` — empties the log
  it is pointed at. Rather than avoid it, every request URL is matched against a pattern
  that cannot express it, checked before the request and again on every redirect hop,
  with the module and scope components separately restricted so neither can smuggle in a
  `/` or a `..`. [SAFETY.md](SAFETY.md#reading-logs-off-the-firewall) sets out the whole
  arrangement. The self-test tries to empty both logs, reboot the box, upgrade its
  firmware, add a firewall rule, restart a service and delete a DHCP lease, and requires
  every one to be refused.

- **Which machine answered is recorded, not assumed.** An OPNsense box normally presents
  a self-signed certificate, so you can trust its CA (`--firewall-ca`), pin the
  certificate (`--firewall-fingerprint`, checked on every connection), or skip the check
  (`--firewall-insecure`). Whichever you choose is written into every fetched file, and
  a log fetched with no check carries `UNVERIFIED` in those words — with the analysis
  repeating the point in its warnings, because the file then records where the entries
  were *said* to come from rather than establishing it.

- **A parser for fetched logs** (`opnsense_api`). The rows are saved exactly as the
  firewall returned them, inside an envelope recording the firewall, the endpoint, the
  time window and the kind of connection. Nothing is reformatted into a log file the
  firewall never wrote — hashing and swearing to a file you synthesised would defeat the
  point of hashing it. What a log line *means* is not duplicated: which messages count
  as a client drop is still decided in one place, and both parsers call into it. The
  self-test asserts that a fetched log and the same lines exported by hand produce
  identical events.

- **Thirty-five new self-test checks** covering all of the above. `--self-test` now runs
  230 checks, or 223 without the optional dependencies.

### Changed

- The API secret is held for the session only. It is never written to the case file, and
  there is no field for it in the case file format at all — the same treatment the
  camera password gets. `DEAUTH_CORRELATOR_OPNSENSE_SECRET` keeps it out of shell
  history.
- `--check-runtime` now notes that `requests` also covers reading logs off the firewall.
- [SAFETY.md](SAFETY.md) gains a "Reading logs off the firewall" section and three new
  rows in its audit table. The grep counts it quotes are updated: thirty-three lines
  across the four greps, describing twelve distinct things.

## [1.1.1] - 2026-08-14

A fix for 1.1.0, released the same day. `update install` did not work at all.

### Fixed

- **`deauth-correlator update install` failed partway through the download** with
  `TypeError: <lambda>() takes 1 positional argument but 2 were given`, in both the
  command line and the graphical interface. The progress callback is documented and
  implemented as `progress(done, total)` — two numbers — and both callers passed a
  one-argument function expecting a message string. Nothing was ever installed or
  damaged: the failure happens while the archive is being fetched, before anything is
  unpacked or replaced, and the partial download is removed by the `finally` block that
  owns it. But the feature could not be used.

  This was invisible to every check that existed. The download is the only caller of that
  callback with a real total, and it only runs against a live release, so the first thing
  to exercise it was an end-to-end run against the published 1.1.0.

  `format_progress(done, total, unit)` now renders the line, so callers no longer decide
  the wording, and five self-test checks cover the contract offline — including one that
  calls `verify_tree` with a strict two-argument callback and asserts it is invoked with
  two integers. `--self-test` now runs 195 checks, or 188 without the optional
  dependencies.

**If you are on 1.1.0, update by hand** — download the archive from the releases page as
you did before. 1.1.0 cannot install 1.1.1 for you, because installing is the part that
is broken. From 1.1.1 onwards `update install` works.

## [1.1.0] - 2026-08-14

Two features that were asked for directly: the program can tell you when a newer release
exists, and it can show you the camera on the screen. Both are read-only, and both were
reviewed adversarially before release — that review found nine defects, listed at the
bottom of this entry, and all nine are fixed here.

### Added

- **Update checking.** `deauth-correlator update check` reports whether a newer release
  exists; the Case tab does the same automatically when the program starts, and shows
  the result in the Updates block. This is the first thing in the program that contacts
  anything other than your camera, so it is documented in full in
  [SAFETY.md](SAFETY.md#checking-for-updates) and can be switched off completely by
  clearing "Check for updates when the program starts", or by setting
  `check_for_updates` to `false` in the case file.

  The check is a single unauthenticated HTTPS GET of GitHub's public releases API. No
  token, no cookie, no identifier, nothing about you or this machine beyond the
  User-Agent. Nothing is uploaded. The complete list of hosts it can reach is a constant
  in the source and can be printed without running an analysis:

  ```
  deauth-correlator update endpoints
  ```

  That list is enforced rather than merely documented: redirects are switched off and
  walked by hand so every hop is checked against it, and the session sets
  `trust_env = False` so a proxy in the environment cannot redirect the request.

- **Installing an update, only when you say so.** `deauth-correlator update install`
  downloads the release, checks it against the SHA-256 published with it, unpacks it
  beside the current installation and verifies the unpacked tree against the
  `CONTENTS.sha256` inside it — all before anything is replaced. The previous
  installation is kept, so a bad update can be rolled back, and the final swap is
  performed by a separate command rather than by the process being replaced.

  It never installs by itself, and that is deliberate. Every report and every
  `MANIFEST.json` records the version that produced it; software that replaces itself
  between an analysis and the question "which version produced this?" makes that
  question unanswerable.

- **Live camera view.** The Camera tab can now show the RTSP stream, with a "Save this
  frame" button that writes a timestamped JPEG into the exhibits folder using the same
  naming as the motion recorder. It needs `opencv-python` and Pillow; without them the
  tab says so and stays inert rather than failing at the click.

- **Thirty new self-test checks**, covering exactly the refusals the two new modules are
  responsible for: the host allow-list, six kinds of archive member that would escape the
  extraction directory, symbolic links that point out of the tree, and credential
  redaction. `--self-test` now runs 190 checks, or 183 without the optional dependencies.

### Fixed

Nine defects found by an adversarial review of the two new modules, each reproduced
before it was fixed and covered by a self-test check afterwards where the fix is
checkable offline.

- **An archive could write outside the directory it was extracted into.** The extractor
  rejected a Windows drive letter only at the very start of a member name, so
  `_internal/Z:/planted.dll` passed. `pathlib` treats any component carrying a drive as a
  fresh anchor, which discards the whole staging path — the file landed on `Z:\` instead,
  and because it never appeared in the extracted tree, the tree still matched its own
  manifest and the update was reported as verified. Every component is now checked, and
  every member is checked against where it *really* resolves before anything is created.

- **A symbolic link could escape the tree by going through another link in the same
  archive.** The containment check resolved the link text against the path the member
  spelled rather than against the directory it actually landed in, and those two diverge
  as soon as an earlier member is a link that shortens the path. Resolution is now done
  against the real parent. This affected macOS most, since the `.app` archive is the only
  one that contains links at all.

- **Two failure paths raised exceptions that were not `UpdateError`**, so a caller
  catching the module's own base class got a traceback instead of a message: a malformed
  port in a redirect target, and a member that could not be written.

- **The live view could save one camera's frame as another camera's exhibit.** Starting a
  new session did not clear the previous frame, so if you retyped the address for a
  second camera and that camera failed to answer, the first camera's picture stayed on
  the canvas with "Save this frame" still armed — and the saved exhibit carried the new
  camera's name. Starting a session now drops the previous frame. Stopping still keeps
  it, which is the case where it is genuinely still yours to save.

- **Stopping the live view under-reported that it was still running.** When the decoder
  did not return within the timeout, the thread handle was dropped anyway, so
  `is_streaming()` said False while an RTSP session was still open. Start's
  "pressing it twice is harmless" guard then never fired, and each Stop/Start cycle
  stacked another connection on a camera that serves only two or three. The handle is now
  kept, Start is disabled until the decoder reports in, and the status says so.

- **Redacting the password mangled the message it was protecting.** It replaced the
  password as a substring, twice over the same text, so a password of `pass` rewrote the
  `pass` inside the `<password>` placeholder it had just inserted and produced
  `<<<password>word>word>`; a password of `554` rewrote the port, and one of `camera`
  edited the prose. It also hid only the password, leaving the camera account's username
  on screen in clear text. The whole userinfo of any RTSP URL is now rewritten in one
  pass, which cannot cascade, cannot corrupt the rest of the sentence, and hides both
  credentials.

- **A frozen stream could report "Live." indefinitely.** The watchdog measured time since
  the last failed frame grab, which a stream whose grabs keep succeeding while its
  decodes fail never sets. It now measures time since the last frame actually displayed,
  which covers all three ways a stream can go quiet.

- **A missing dependency stopped being reported after the first Stop.** Stopping
  re-enabled the Start button unconditionally and overwrote the install instructions with
  "Stopped.", leaving a machine without OpenCV showing a live-looking button and no
  explanation of why it would not work.

Two more found while checking the update path against what the release workflow actually
publishes, rather than against what the code assumed it published:

- **`update install` could not have worked on macOS or Linux.** It looked for a `.zip`,
  but those platforms are published as `.tar.gz` — deliberately, because a zip written by
  Python restores neither the executable bit nor the symbolic links inside an `.app`
  bundle. Tar archives are now accepted and are held to exactly the same rules as a zip,
  plus two that only a tar can break: hard links and device nodes are refused, and so is
  a member marked setuid or setgid.

- **macOS would not have been recognised even once the archive kind was right.** The
  platform tag was derived from `platform.system()`, which returns `darwin`, while the
  published archive is labelled `macos-arm64` — that label comes from the release
  workflow's build matrix, not from Python. Both names are now matched.

### Changed

- `--check-runtime` now also reports whether live view rendering and update checking are
  available, and treats `PIL.ImageTk` as required in a standalone build.
- [SAFETY.md](SAFETY.md) no longer claims the camera is the only thing this program ever
  contacts, because as of this release that is not true. The claim has been replaced with
  a section that names the fifth destination, says exactly what is sent, and says how to
  switch it off.

## [1.0.3] - 2026-08-07

A distribution fix, prompted by a real report: the standalone Windows build failed to
start with

```
Failed to execute script 'pyi_rth__tkinter' due to unhandled exception:
Tk data directory "...\_internal\_tk_data" not found.
```

The published archives were not at fault — all three contain that directory, 93 entries
of it — and the installation turned out to have extracted incompletely. But the message
points at PyInstaller rather than at the cause, and nothing in the program could say so.

### Added

- **`CONTENTS.sha256`, `verify-install.ps1` and `verify-install.sh` now ship inside every
  standalone archive.** They list every file with its SHA-256 and check an installation
  against it, naming whatever is missing or altered and exiting non-zero.

  They deliberately do not depend on the program working. A missing Tk data directory
  aborts inside PyInstaller's startup hook, which runs *before any of this project's
  code*, so `--version`, `--self-test` and `--check-runtime` all die with the identical
  traceback. No self-diagnostic inside the frozen application can reach that failure, and
  `--check-runtime` — added in 1.0.1 precisely to catch a dead graphical interface — is
  no help here.

  On macOS the manifest is written into the `.app` as well as beside it, since the
  archive carries the bundle alone.

### Documentation

- A troubleshooting entry maps that traceback to its actual cause and to the fix:
  re-extract with a real archiver rather than Explorer's built-in zip viewer, which can
  stop part way without reporting it.
- The install instructions now say what the archive contains on macOS (one `.app`, with
  the command-line tool inside it) and recommend verifying the extraction once.
- Recorded that `deauth-correlator --version` doubles as an integrity check: because the
  same startup hook runs first, a version that prints at all proves the Tk data survived.

### Note

Nothing in the analysis changed. Reports produced by 1.0.1 or 1.0.2 need no revisiting.

## [1.0.2] - 2026-08-05

A packaging fix. Nothing here changes how a verdict is reached, and no analysis result
differs from 1.0.1.

### Fixed

- **`--self-test` could not run on a base install.** The guarantees section added in
  1.0.1 imported `MotionRecorder` at module scope, which pulls in
  `deauth_correlator.camera` and therefore `requests`. On an install without the optional
  extras — the install the README describes as not needing `requests` — the self-test
  failed at import before running a single check, so the tool's whole verification story
  was unavailable to exactly the users least likely to have a workaround. The standalone
  builds bundle `requests` and were unaffected; the wheel and sdist were not.

  The camera checks now live in their own function, called only when the import succeeds,
  and their absence is reported as a skip rather than passed over silently. A base install
  runs 143 checks and names what was skipped; a full install runs 150.

  This was found by CI and could not have been found locally: every environment on the
  development machine had `requests` installed.

- **`MANIFEST.json` was not valid JSON.** `json.dumps` writes bare `NaN` and `Infinity`
  tokens, which Python reads back but no other parser accepts. Both occur in ordinary use:
  Fisher's odds ratio is infinite whenever every camera window contains a disruption —
  the shape of a strong positive finding — and the permutation statistics are NaN when
  there are no disruptions at all. So the file the bundle's cover sheet calls
  machine-readable, and tells the recipient to open, was rejected by every parser except
  the one that wrote it. Non-finite values now serialise as `null`, the replaced fields
  are named in a `_non_finite_fields` key, and `allow_nan=False` turns any future escape
  into a failed build rather than an unparseable evidence file.
- **A rate ratio was asserted when there were no disruptions at all.** The zero-cell
  correction was applied even when both cells were zero, so the report printed
  "wireless disruptions were 17.13 times more frequent during the camera windows"
  directly beneath a table showing zero incidents in both periods. With nothing in either
  period there is no ratio, and the report, the console and the interface now say so.
- **Rebuilding a bundle into the same directory accumulated the previous one.** A second
  run left both sets of hash-verified source copies side by side under `_2` names and
  appended its chain-of-custody log to the old one, producing a handover folder holding
  evidence from a superseded analysis. A rebuild now replaces the previous bundle, and
  refuses — without deleting anything — if the directory holds files this tool did not
  write.
- The bundle cover sheet's inventory omitted `00_MANIFEST.txt`, which every bundle
  contains.

### Changed

- CI now tests Python 3.10, the floor `requires-python` has always declared and the one
  version never previously exercised. It passes on Linux, macOS and Windows.
- A second independent review checked every factual claim in the documentation against
  the code and walked the whole user journey. It found no blockers. Its confirmed
  findings are the corrections above and the documentation fixes below.

### Documentation

- The README's flagship example showed a verdict line the tool cannot produce — a single
  `p = 1.47e-12` rather than the `every test p <= …` form — which is precisely the
  most-favourable-p presentation 1.0.1 removed and `VALIDATION.md` explains at length.
- `SAFETY.md` said its four greps returned "the following, and nothing else" while the
  fourth returned around forty lines, most of them XML namespace URLs and fixture
  strings. The grep is now narrow enough to match only call sites, and the count is
  stated: sixteen lines describing seven distinct things.
- The `[1.0.0]` changelog entry had been rewritten to a later check count. A shipped
  release's record should not be edited; restored to 132.
- `CONTRIBUTING.md` cited three greps and four hits, told contributors to `cd CamLink`
  (the repository is `deauth-correlator`), and described nine self-test sections.
- The walkthrough's section table omitted the tenth section, said four fixture
  directories where there are five, and reported a bundle file count of 13 where it is 12.
- Version literals in expected-output blocks are now `<version>` rather than a number
  that goes stale every release.
- The README described adding a parser as one registry line; `ROLE_PARSERS` is a second,
  separate entry, without which a new parser is never reached by detection.
- `--no-plot` and `--check-runtime` were missing from the README command reference, and
  `--check-runtime` from the packaging guide's hand-verification list even though the
  release gate runs it.
- `SECURITY.md` still counted six camera read operations; 1.0.1 removed one.

## [1.0.1] - 2026-08-03

An independent review of the published 1.0.0 found thirteen defects. None changes how a
verdict is reached, so no analysis result differs between 1.0.0 and 1.0.1. Three of them
weaken the read-only guarantee and four were statements in the documentation that the
code did not honour — the latter matter here because `SAFETY.md` invites the reader to
verify its claims, and a claim that does not survive checking is worse than no claim.

### Security

- **The ONVIF client honoured `HTTP_PROXY` from the environment.** `requests.Session`
  trusts the environment by default, so on a machine with a proxy configured every ONVIF
  request — including the WS-Security header carrying the camera username and the
  password digest, nonce and timestamp — went to the proxy host rather than the camera,
  and the proxy's reply was accepted as the camera's. Demonstrated against an unroutable
  camera address that nevertheless returned a device description. The session now sets
  `trust_env = False`.
- **ONVIF requests followed redirects.** A device answering with a 307 caused the whole
  SOAP body, credential header included, to be re-sent to whatever host the reply named.
  Requests now use `allow_redirects=False` and a 3xx is reported as an error.
- **The motion recorder could hammer a camera and outlive its own stop.** A faulting
  event service produced unbounded `CreatePullPointSubscription` calls — measured at over
  thirty a second — with no backoff and no cap, and a subscription could be created after
  `stop()` had returned and reported not-running. Both failure paths that re-subscribe
  now check for a stop request first, back off exponentially, and give up after six
  consecutive failures.

### Fixed

- Input files are now hashed **before** they are parsed. `SAFETY.md`, the report and the
  evidence bundle's cover sheet all stated that the hash was taken before the file was
  read; in fact the file was sniffed and parsed first and hashed afterwards. The claim is
  the point of the sentence, so the code was changed to match rather than the sentence.
- `packaging/build.py` could not detect a build whose graphical interface was dead.
  Both of its checks ran only the console executable and neither touched Tkinter, so a
  bundle missing the Tk libraries passed and shipped. A new `--check-runtime` option
  imports each bundled subsystem without needing a display, and the build gate runs it.
- The macOS release archive contained two complete copies of the application — the
  collection directory and the `.app` built from it — roughly doubling the download. The
  release workflow now packs the `.app` alone.
- `build-system.requires` declared `setuptools>=68`, which cannot build this package:
  the PEP 639 `license`/`license-files` metadata needs 77 or newer, and any build in the
  declared-supported range failed outright. Corrected to `>=77`.
- `pyproject.toml` declared a `py.typed` marker that does not exist in the tree, so the
  wheel shipped no typing marker. The declaration was removed rather than the marker
  added, since the package is annotated but not type-checked in CI.

### Documentation

- `SAFETY.md` claimed three greps enumerated every network-adjacent call. They did not:
  they missed the ONVIF client entirely, because it is built on `requests` rather than on
  sockets directly, and they missed `webbrowser.open` and `os.startfile`. A fourth grep
  has been added, the table now lists every hit, and the omission is described rather
  than quietly corrected. `SECURITY.md` no longer says "three".
- `packaging/README.md` stated that no CI workflow was checked into the repository. Both
  `test.yml` and `release.yml` were, and `release.yml` produced the shipped artefacts.
- Removed `get_snapshot_uri` and `get_capabilities`, which had no callers anywhere;
  `SAFETY.md` listed `GetSnapshotUri` as an operation the tool performs.
- Corrected a stale line-number citation, the self-test count in the root README (which
  said 82 where every other document said the true figure), and the bundled time-zone database size
  in the packaging size table (0.5 MiB, not 2 MiB).

### Added

- `--check-runtime` reports which optional subsystems can be imported. Useful on its own
  for diagnosing an installation, and it is what gates a standalone release.
- A tenth self-test section asserting the read-only and chain-of-custody guarantees, so
  each of the defects above fails the suite if it returns. 150 checks in total.

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
