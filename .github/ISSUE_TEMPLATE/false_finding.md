---
name: Incorrect or overstated finding
about: The tool reported something the evidence does not support, or stated it more strongly than it should have
title: ''
labels: false-finding, priority
assignees: ''

---

<!--
This is the most serious class of defect in this project. The output of this tool gets
handed to detectives, attached to filings and put in front of judges, and a wrong finding
arrives with a case number, hashes, a p-value and a timeline drawn to scale - everything
that makes a correct finding survive scrutiny works just as well for an incorrect one.
Reports here are triaged as security-critical. See SECURITY.md.

You do not need to know the cause. "Under these inputs, the tool reported something the
evidence does not support" is the complete claim.

BEFORE YOU POST - two things.

1. If describing the problem requires quoting real case material, use a private security
   advisory instead: the repository's Security tab, then Advisories, then "Report a
   vulnerability". This issue is public.

2. Do not attach captures, DHCP logs, camera exports, evidence bundles or MANIFEST files
   that came from a real case. They contain MAC addresses, lease histories, plate numbers
   and the layout of someone's network. Fill in the characteristics below instead, and
   redact the manifest excerpt.
-->

## What the tool reported

<!-- The verdict line as printed, with case details removed. -->

```
CORRELATION FOUND: ...
```

## Why you believe it is wrong

<!-- What do you know about the evidence that the tool does not? For example: the passes
     and the disruptions come from unrelated causes you can account for; the same vehicle
     is being counted several times; the DHCP activity is routine; the two clocks were
     never synchronized; a scheduled job produces the disruptions on its own. -->

## Which part is overstated

<!-- Tick everything that applies. -->

- [ ] Disruption events were counted that are ordinary network traffic
- [ ] Camera passes were counted more than once, or genuine passes were removed
- [ ] The verdict does not follow from the numbers printed beside it
- [ ] A value appears in the output that is not in the source (reason code, plate, timestamp, p-value)
- [ ] An assumption was applied without being stated in the report
- [ ] A hash, manifest entry or bundle copy does not cover what it appears to cover
- [ ] Something else, described above

## Parameters

<!-- Copy from the "configuration" block of MANIFEST.json or the methodology section of
     report.md. Every one of these can move a finding. -->

| Parameter | Value |
| --- | --- |
| `--window` | |
| `--alpha` | |
| `--trials` | |
| `--tz` | |
| `--camera-clock-offset` | |
| `--log-year` / `--assume-offset` | |
| `--reassoc-window` | |
| `--incident-gap` | |
| `--camera-dedupe` | |
| `--flood-window` / `--flood-threshold` | |
| Non-default anything else | |

## Statistics as reported

| Figure | Value |
| --- | --- |
| Camera events (M) | |
| Coincidences (N) | |
| Baseline rate | |
| Expected by chance | |
| Binomial p | |
| Permutation p | |
| Fisher p | |
| Rate ratio | |
| Incidents | |
| Observation period (hours) | |

<!-- If the sensitivity table is in the report, paste it. A finding that appears at one
     window width and vanishes at the others is diagnostic in itself. -->

## Input characteristics

<!-- Describe the shape of the evidence, not its contents. -->

| | |
| --- | --- |
| Camera source | <!-- camera CSV / clip folder / both --> |
| Camera events, before and after de-duplication | |
| Wireless sources | <!-- pcap, pcapng, Kismet, airodump CSV, nzyme CSV, dnsmasq, Kea, ISC dhcpd, hostapd --> |
| Capture duration, and whether it covers quiet periods | |
| Disruption events by kind | <!-- deauth / disassoc / client_drop / link_reset / alert --> |
| Distinct clients involved | |
| Distinct source MACs in the deauth frames | |
| Reason codes present | |
| Were the camera and firewall clocks verified against NTP | |
| Did the run print `*** CHECK THE CLOCKS ***` | |

## Manifest excerpt

<!-- OPTIONAL but the single most useful thing you can provide. MANIFEST.json holds the
     verdict, every statistic, the sensitivity table, the clock-offset scan and the full
     parameter set in one place.

     REDACT BEFORE PASTING: remove the "provenance" block (operator, case number, agency,
     hostname), and in "inputs" and "outputs" remove the "path" fields. The hashes, sizes,
     parser ids and row counts are fine to keep and are worth keeping. -->

```json
```

## A reproduction, if you can build one

<!-- Synthetic inputs that show the same behaviour are the fastest route to a fix and
     carry no case material. `--self-test --self-test-dir ./fixtures` writes a complete
     set of realistic fixtures for every format, which is usually the easiest starting
     point to modify. -->

## Environment

| | |
| --- | --- |
| `deauth-correlator --version` | |
| Python version | |
| Operating system | |
| scipy installed | <!-- yes / no --> |
| `--self-test -q` final line | |

## Anything else

<!-- Warnings the run printed, notes on the analysis period, the "Why the finding is not
     stronger" list from section 1, or the report's methodology section if it explains
     something that turned out to be wrong. -->
