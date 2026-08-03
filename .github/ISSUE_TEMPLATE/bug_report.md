---
name: Bug report
about: Something crashed, failed to parse, or behaved differently from the documentation
title: ''
labels: bug
assignees: ''

---

<!--
If the tool produced a FINDING you believe is wrong - a correlation reported that the
evidence does not support, an event count that looks invented, a verdict that does not
match the numbers - stop and use the "Incorrect or overstated finding" template instead.
That class is handled as security-critical and is triaged differently.

Do not attach captures, DHCP logs, camera exports or evidence bundles. They contain MAC
addresses, lease histories, plate numbers and the layout of someone's network, and this
issue is public. Describe the input instead, or build a synthetic file that reproduces
the problem.
-->

## What happened

<!-- One or two sentences. If there is a traceback, paste it in full below. -->

```
```

## What you expected instead

<!-- Quote the README, SAFETY.md or --help text if the behaviour contradicts them. -->

## Command or steps to reproduce

<!-- The exact command line, with any file paths and case details replaced. For the GUI,
     name the tab and the parameters you set. -->

```
python -m deauth_correlator ...
```

## Input

| | |
| --- | --- |
| Input type | <!-- --opnsense-log / --wifi-capture / --camera-events --> |
| Format | <!-- dnsmasq, Kea, ISC dhcpd, hostapd, pcap, pcapng, Kismet, airodump CSV, nzyme CSV, camera CSV, clip folder --> |
| Parser used | <!-- from the "+ file: N event(s) via ..." line, or "detection failed" --> |
| Approximate size | <!-- lines, packets or rows --> |
| Produced by | <!-- airodump-ng 1.7, OPNsense 25.1, Kismet 2023-07, Reolink NVR, hand-written... --> |

<!-- If you can reproduce it with a synthetic file, attach that file. A file you
     constructed is far more useful than a real one and carries no case material. -->

## Environment

| | |
| --- | --- |
| `deauth-correlator --version` | |
| Python version | |
| Operating system | |
| Installed with | <!-- pip install -e ".[all]" / pip install -e "." / other --> |
| scipy installed | <!-- yes / no - the statistics have two backends --> |

## Self-test result

<!-- Paste the last line of: python -m deauth_correlator --self-test -q
     A failure there usually explains the problem and tells us where to look. -->

```
```

## Anything else

<!-- Warnings the run printed, notes from the report's methodology section, whether it
     is intermittent, anything you already ruled out. -->
