# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | Yes |
| anything earlier | There is nothing earlier. 1.0.0 is the first release. |

Fixes are issued against the 1.0.x line. When a later minor or major line exists this
table will say how long 1.0.x continues to receive them; until then, 1.0.x is the only
line and it is supported.

## Reporting a vulnerability

Report privately through GitHub's private security advisories: go to the repository's
**Security** tab, choose **Advisories**, and click **Report a vulnerability**. That opens
a draft advisory visible only to you and the maintainers, where the report can be
discussed and a fix prepared before anything is public.

**Do not open a public issue for a security report**, and do not describe the problem in
a pull request, a discussion thread, or a comment on an unrelated issue. Use the private
advisory. If GitHub advisories are unavailable to you for some reason, say so in a public
issue containing no detail beyond "I would like to report a security issue privately" and
a maintainer will open a channel.

Include, as far as you can:

- the version (`deauth-correlator --version`) and the Python version;
- whether scipy was installed, since the statistics have two backends;
- what the tool did, and what it should have done instead;
- the smallest input that reproduces it — a synthetic file you constructed is far more
  useful than a real one, and see the note on evidence below;
- the exact command line or the GUI parameters used.

**Do not attach case material.** Captures, DHCP logs, camera exports and evidence bundles
contain MAC addresses, lease histories, plate numbers, timestamps and the layout of
someone's network, and a private advisory is not the right custody for any of it. Describe
the shape of the input instead — how many events, over what period, in what format — and
build a synthetic reproduction. If a defect genuinely cannot be reproduced without real
data, say so in the advisory and a maintainer will arrange something; do not upload it
first and ask afterwards.

### What to expect

An acknowledgement within a few days, and an assessment — whether it is a vulnerability,
what class it falls into, and what the fix looks like — within two weeks. If a report
turns out not to be a security issue it is moved to a public issue with your agreement and
handled as an ordinary bug. Credit is given in the advisory and the changelog unless you
ask otherwise.

## The most serious class of bug is not a crash

In most projects the severity ranking runs from remote code execution down through
denial of service to information disclosure, and a wrong answer is a correctness bug
rather than a security one. That ranking does not fit this tool.

**The highest-severity class of defect in `deauth-correlator` is anything that causes the
tool to overstate, invent or fail to qualify a finding.** Reports in that class are
treated as security-critical and handled through this policy, not through the ordinary
issue tracker.

The reason is what the output is for. `report.md`, `correlation.csv` and the evidence
bundle are built to be handed to a detective, attached to a filing, or put in front of a
judge. They carry a case number, an operator's name, SHA-256 hashes of every input, a
p-value and a timeline drawn to scale. All of that exists so that a correct finding
survives scrutiny — and all of it works exactly as well for an incorrect one. A crash is
loud and stops the process. A fabricated coincidence is silent, looks entirely plausible,
and may be relied on by someone with no way to check it. Between the two, the silent
failure is the one that does real harm, so it gets the higher severity.

Defects in this class include:

- **Fabricated disruption events.** Ordinary network traffic turned into evidence of a
  disconnection — DHCP retransmission backoff, lease renewal, `DHCPINFORM` from a static
  host, or a re-association counted separately from the disconnect that caused it. The
  reasoning behind the current exclusions is in the module docstring of
  `deauth_correlator/drops.py`.
- **Miscounted camera events.** De-duplication merging genuine separate passes, or failing
  to merge one pass recorded by two sources. Both change the statistics, and the second
  moves them towards significance.
- **A verdict resting on weaker grounds than the report claims.** Anything that lets
  `CORRELATION FOUND` be declared without all three conditions holding: at least three
  coincidences, *every* p-value below `--alpha`, and a rate ratio of at least 2. The
  verdict is decided on the weakest test, never the best; a path that reaches a finding
  through `best_p` is a vulnerability, not a preference.
- **Invented values in output.** A reason code read out of an encrypted 802.11w frame, a
  p-value rendered as exactly zero, a missing plate rendered as the string `nan`, a
  timestamp presented with more confidence than the source supports.
- **Silent assumptions.** The tool infers the year for year-less syslog lines, resolves
  ambiguous times across a daylight-saving boundary, narrows the analysis period to the
  overlap of the evidence streams, and applies a camera clock offset. Every one of those
  is stated in the report. An assumption that stops being reported is a defect in this
  class even if the assumption is correct, because the reader has lost the ability to
  challenge it.
- **Chain-of-custody failures.** A hash that does not cover what it appears to cover, an
  evidence bundle whose copies differ from the originals without the mismatch being
  reported, a manifest that omits a parameter that affected the result.

Reports here do not need a working exploit or an attacker. "Under these inputs, the tool
reports something the evidence does not support" is the complete claim. If you are unsure
whether what you are seeing belongs in this class, file it as a false finding using
`.github/ISSUE_TEMPLATE/false_finding.md` and it will be reclassified if it belongs
elsewhere.

Ordinary severity applies to everything else: crashes on malformed input, parser failures,
GUI faults, dependency issues. Those are real bugs and worth reporting, but a crash tells
the operator that something went wrong, which is the property the class above lacks.

## The read-only guarantee

The tool reads. It never transmits an 802.11 frame, never injects, never scans, never
deauthenticates anything, and never places an adapter into monitor mode. There is no code
path that opens a raw socket. Camera access is read-only and only against a camera you
configure it to reach.

That claim is meant to be checkable rather than taken on trust. `SAFETY.md` states it in
full and gives four greps covering every network-adjacent and process-spawning call in
the package, together with a table naming each hit they return and explaining what it is.
If you run them and get a hit the table does not list, or if any entry in that table does
not match what the code actually does, that is a security report and it goes through the
private advisory process above.

That has already happened once. An earlier revision listed only three greps and claimed
they were exhaustive; they missed the ONVIF client entirely, because it is built on
`requests` rather than on sockets directly. The fourth grep exists because of that.

`SAFETY.md` also documents what the camera integration does on the device: six read
operations, one standard ONVIF pull-point subscription that the camera expires on its own
and the recorder removes when it stops, and nothing else. No camera setting is read for
modification, changed or deleted. A code path that configures, changes or deletes anything
on a camera contradicts the guarantee and should be reported.

Related properties covered by that document and worth reporting if broken:

- No input file is modified, moved or deleted. All writing happens under the output
  directory the operator specified.
- Camera passwords exist in memory for the session only. They are never written to the
  case file, the report, the manifest or the evidence bundle, and RTSP URLs are recorded
  in redacted form. A credential reaching disk or output is a vulnerability.
- No network destination other than the camera the operator names is ever contacted, and
  nothing is uploaded anywhere.

## Scope

In scope: the `deauth_correlator` package, the CLI, the GUI, the camera integration, the
parsers, the evidence bundle, and the accuracy and honesty of everything the tool writes.

Out of scope: vulnerabilities in `pandas`, `numpy`, `matplotlib`, `scipy`, `requests` or
`opencv-python` themselves — report those upstream, though tell us if this project's use
of them is what makes the problem reachable. Also out of scope: the security of the camera
firmware, the OPNsense installation, or the network being investigated. The tool reads
what those produce; it does not secure them.

The tool provides no capability to transmit deauthentication frames, and requests to add
one will be declined. Transmitting them is unlawful in most jurisdictions regardless of
whose network it is; in the United States the FCC has issued substantial fines for Wi-Fi
blocking under 47 U.S.C. § 333.
