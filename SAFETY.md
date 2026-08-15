# Scope and safety

`deauth-correlator` is a defensive forensic tool. This document states exactly what it
does on a network, so that anyone reviewing it — an opposing expert, a court, or you in
six months — can check the claim against the code rather than taking it on trust.

## What the tool does not do

It does not transmit 802.11 frames. It does not inject. It does not deauthenticate,
disassociate, jam, or interfere with any device. It does not scan for networks, crack
keys, capture handshakes for offline attack, or place any adapter into monitor mode.

There is no code path that opens a raw socket, a packet socket, or an `AF_PACKET`
socket. The package does not import `scapy`, and does not shell out to `aireplay-ng`,
`mdk4`, `hostapd`, or any other transmitting tool. `airodump-ng` is described in the
README as something *you* run; the tool never invokes it.

To confirm this yourself:

```bash
grep -rnE "AF_PACKET|SOCK_RAW|scapy|aireplay|mdk[34]|sendp\(|\.inject" deauth_correlator/
grep -rn "socket" deauth_correlator/
grep -rnE "subprocess|os\.system|popen|os\.exec" deauth_correlator/
grep -rnE "webbrowser\.|os\.startfile|requests\.(Session|get|post|put|RequestException|exceptions)|urllib\.request" deauth_correlator/
```

Note the fourth grep. The first three do **not** catch the ONVIF client, the firewall
log reader or the update check, which between them are where all of this program's real
network traffic originates: all three are built on `requests` rather than on sockets
directly, so `grep socket` misses them entirely. Nor do they catch
`webbrowser.open` or `os.startfile`. An earlier version of this document listed only the
first three and claimed they enumerated everything, which was wrong. If you are auditing
this, run all four.

Together they return thirty-three lines and nothing else: 1, 11, 3 and 18
respectively. Those describe the twelve distinct things in the table below — most appear more than once,
as an `import` line, a call site, and the exception types named when the call fails. One
`socket` hit is the word inside a docstring. Each is listed so a hit does not have to be
chased down.

The fourth grep is deliberately narrow, matching call sites rather than the bare words.
A looser pattern such as `"webbrowser|startfile|requests\.|urllib|http"` also matches the
XML namespace URLs at the top of `onvif_min.py`, the RTSP URL template in `tapo.py` and
the self-test's fixture strings — around forty lines, none of which touch the network.

| Hit | Location | What it is |
| --- | --- | --- |
| `aireplay-ng, mdk4` | `events.py:48` | a comment explaining why reason codes 1 and 7 are notable |
| `socket.create_connection` | `camera/tapo.py::_port_open` | a TCP connect to the camera's RTSP port to check it is open, closed immediately |
| `socket.gethostname` | `hashing.py::Provenance.collect` | reads this machine's name for the report header; no network traffic |
| `subprocess.run(["open"/"xdg-open", path])` | `gui/app.py::_open_path` | asks the desktop to open an output file the tool just wrote, when you click "Open report.md". macOS and Linux only |
| `os.startfile(path)` | `gui/app.py::_open_path` | the same thing on Windows |
| `webbrowser.open(path.as_uri())` | `gui/app.py::_open_path` | last-resort fallback for the same action, handed a `file://` URI pointing inside your own output directory. It is reached only if the two calls above raise |
| `requests.Session()`, `session.post(...)` | `camera/onvif_min.py` | the ONVIF client. Every request goes to the camera address you entered and nowhere else — see the two settings below that make that true |
| `socket.create_connection` | `gui/liveview.py::_reach_rtsp` | a TCP connect to the camera's RTSP port before opening the live view, so an unreachable camera reports that rather than hanging inside OpenCV. Closed immediately |
| `requests.Session()`, `session.get(...)` | `update.py` | the update check and download; the section "Checking for updates" below sets out exactly what it reaches and how to switch it off |
| `requests.Session()`, `session.request(...)` | `firewall/opnsense_api.py` | reading DHCP and system logs from your own OPNsense firewall, when you ask it to. The section "Reading logs off the firewall" below sets out what it can and cannot reach |
| `socket.create_connection` | `firewall/opnsense_api.py::certificate_fingerprint` | a TCP connect to the firewall to read the certificate it presents, so you can pin it. Closed immediately, and it sends no credentials |
| `ssl.SSLContext`, `wrap_socket` | `firewall/opnsense_api.py` | the TLS handshake for that same fingerprint read |

Two properties of that session are worth checking by eye, because without them the
"nowhere else" claim above would be false:

- `self.session.trust_env = False`. A stock `requests` session honours `HTTP_PROXY` from
  the environment, which on a machine with a proxy configured would send every ONVIF
  request — including the WS-Security header carrying your camera username and password
  digest — to the proxy instead of the camera.
- `allow_redirects=False` on every call. A device answering with a redirect would
  otherwise cause that same header to be re-sent to whatever host the reply names.

`build_deauth_frame` in `parsers/dot11.py` constructs deauthentication frame *bytes*. It
exists so the self-test can generate realistic capture files, and it is called only from
`selftest.py`. It returns a `bytes` object; nothing in the package writes bytes to a
network interface.

## What the tool reads

**Files on disk.** Log files, capture files, SQLite databases, CSVs and clip filenames
that you pass on the command line or attach in the interface. Opened read-only. The
Kismet reader opens its database with SQLite's `mode=ro` URI flag. Each file is hashed
with SHA-256 before it is parsed, so the digest in the report bounds exactly the bytes
that were analysed.

**Your camera, when you ask it to.** The camera features are inactive unless you supply
a host address and credentials. When active they perform:

| Operation | Kind | Notes |
| --- | --- | --- |
| `GetSystemDateAndTime` | read | unauthenticated per the ONVIF specification; used to measure clock error |
| `GetDeviceInformation` | read | model, firmware, serial for the report |
| `GetProfiles`, `GetStreamUri` | read | stream discovery |
| RTSP connect and frame grab | read | one frame kept as a JPEG exhibit |
| `CreatePullPointSubscription`, `PullMessages`, `Renew` | event subscription | the one operation that creates remote state |
| `Unsubscribe` | cleanup | removes it |

The pull-point subscription is the standard ONVIF mechanism for receiving motion
notifications. It is created only when you start the motion recorder, it carries an
expiry that the camera enforces on its own, and the recorder removes it explicitly when
stopped or when the window closes. No camera setting is read for modification, changed,
or deleted.

**Your own OPNsense firewall, when you ask it to.** Read-only, and only the log
endpoints — see "Reading logs off the firewall" below.

Apart from those and the update check, no other network destination is ever contacted.
Nothing is uploaded anywhere, ever, by any part of this program.

## Checking for updates

Until version 1.1.0 this document said that the camera was the only thing the program
ever contacted. That is no longer true, and rather than quietly soften the sentence it is
worth stating plainly what changed.

The program asks GitHub whether a newer release exists. By default it does this once when
it starts. It is a single HTTPS GET of a public API, unauthenticated — no token, no
cookies, no identifier — and it sends nothing about you or this machine beyond the
User-Agent and the TLS connection itself. Nothing is uploaded. The complete list of hosts
it can reach is a constant in the source, `UPDATE_ENDPOINTS` in `update.py`, and you can
print it without running an analysis:

```bash
deauth-correlator update endpoints
```

| Host | When | What for |
| --- | --- | --- |
| `api.github.com` | each check | the latest release's version number and notes |
| `github.com` | only when you ask to download | the release asset URLs, which answer with a redirect |
| `objects.githubusercontent.com` | only when you ask to download | where those redirects lead; the archive bytes |
| `release-assets.githubusercontent.com` | only when you ask to download | the newer name for the same redirect target |

That list is enforced, not merely documented. `_check_url` rejects any URL outside it, and
because a release-asset download always redirects, redirects are switched off and walked
by hand so **every hop** is checked — a redirect to an unlisted host stops the download
instead of quietly completing it from somewhere else. The session also sets
`trust_env = False`, so `HTTP_PROXY` cannot route the request somewhere the list does not
name.

**To turn it off entirely,** clear the "Check for updates when the program starts" box on
the Case tab, or set `check_for_updates` to `false` in the case file. With it off the
program contacts nothing but your camera, and the update code never runs.

### Why it never installs by itself

Checking is a read. Installing is not, and it does not happen implicitly.

Every report and every `MANIFEST.json` records the version that produced it. Software
that replaces itself between an analysis and the question "which version produced this?"
makes that question unanswerable, and replacing files underneath a running analysis is
worse. So an update is only ever installed when you say so, and even then:

- the archive is checked against the SHA-256 published with the release before anything
  is unpacked;
- the unpacked tree is checked against the `CONTENTS.sha256` inside it before anything is
  replaced;
- the previous install is kept alongside the new one, so a bad update can be rolled back;
- the swap is never performed by the process being replaced.

A verification failure at any of those points aborts and leaves the existing installation
untouched.


## Reading logs off the firewall

`deauth-correlator fetch` pulls the DHCP and system logs from your own OPNsense box
so you do not have to export them by hand. It is inactive unless you supply an address
and an API key.

### What it can reach

OPNsense exposes its logs through one controller, at
`/api/diagnostics/log/{module}/{scope}`. That controller has four actions, and one of
them — `clear` — **empties the log file it is pointed at**. For a tool whose entire
purpose is preserving evidence, that is the most destructive call on the box.

So this is not a general OPNsense client that declines to use the dangerous parts. Every
request URL is matched against one regular expression, `READ_ONLY_PATH` in
`firewall/opnsense_api.py`, which cannot express `clear`:

```
/api/diagnostics/log/{module}/{scope}          read a log
/api/diagnostics/log/{module}/{scope}/export   read a log as CSV
/api/core/system/status                        the version, for the provenance record
/api/core/firmware/status
```

Anything else raises `FirewallRefused` before a request is issued. The check runs on the
initial URL **and on every redirect hop**, and the `{module}` and `{scope}` components
are separately restricted to letters, digits, dot, dash and underscore, so neither can
carry a `/` or a `..` that would change which endpoint is reached. The self-test asserts
all of this: it tries to empty both logs, reboot the box, upgrade its firmware, add a
firewall rule, restart a service and delete a DHCP lease, and requires every one to be
refused.

Only GET and POST are ever issued, and POST only because OPNsense models the log query
itself as a paginated POST search. Nothing is created by it.

### Where the credentials can go

The API key and secret are credentials to your firewall, so they are treated the way the
camera password is:

- `session.trust_env = False`, so a proxy named in the environment cannot receive them.
- `allow_redirects=False` on every call, with each hop checked, so the firewall — or
  something answering in its place — cannot bounce them to another host.
- HTTPS only. A plain-HTTP URL is refused rather than downgraded.
- The secret is held in memory for the session. It is not written to the case file, the
  report, the manifest or the evidence bundle, and there is no field for it in the case
  file format at all. Set it in the environment to keep it out of shell history:

  ```bash
  export DEAUTH_CORRELATOR_OPNSENSE_SECRET='...'
  ```

### Which machine answered

An OPNsense box normally presents a self-signed certificate, so there are three honest
options and the one you chose is written into every file fetched:

| Option | Recorded as |
| --- | --- |
| `--firewall-ca FILE` | verified against that CA bundle |
| `--firewall-fingerprint SHA256:…` | pinned certificate, checked on every connection |
| `--firewall-insecure` | **UNVERIFIED**, in those words |

The third is available because sometimes it is what you have, but it is not quiet about
it. A log fetched that way carries `UNVERIFIED` in its provenance, and any analysis that
reads it repeats the point in its warnings: the file records where the entries were
*said* to come from rather than establishing it. That matters if the provenance of the
exhibit is ever challenged, which is the whole reason the distinction is recorded rather
than assumed.

`deauth-correlator fetch fingerprint` prints what the firewall presents so you can pin
it. It proves nothing on its own — whoever answers gets to state their own fingerprint —
so check the value against the firewall's own web interface under System > Trust >
Certificates before trusting it. The tool says so when it prints it.

### What ends up on disk

Each log is written as JSON: the rows exactly as the firewall returned them, inside an
envelope recording which firewall, which endpoint, when, over what kind of connection,
and for what time window. Nothing is reformatted into a log file the firewall never
wrote — hashing and swearing to a file you synthesised would defeat the point of hashing
it. The window itself is derived from your camera events and widened by a baseline
margin, because a log covering only the events has no quiet period to compare against
and would produce the most flattering possible answer.


## Credentials

Camera passwords are held in memory for the duration of the session. They are not
written to the case file, the report, the manifest, or the evidence bundle. Where an
RTSP URL appears in output it is recorded in redacted form
(`rtsp://<user>:<password>@host:554/stream1`).

To keep the password out of shell history, set it in the environment:

```bash
export DEAUTH_CORRELATOR_CAMPASS='...'
```

## Evidence integrity

Every input file is hashed with SHA-256 before it is read, and the hash appears in
`report.md`, `MANIFEST.json` and `MANIFEST.txt`. Files copied into an evidence bundle are
re-hashed after copying and compared against the original; a mismatch is reported in the
bundle's `00_READ_ME_FIRST.txt` and in the build log rather than being passed over.

No input file is ever modified, moved, or deleted. All writing happens under the output
directory you specify.

## Honest reporting

The report contains a mandatory section headed "What this analysis does not prove". It
states that correlation is not identification, that MAC addresses in management frames
are unauthenticated and forgeable, that clock accuracy bounds the resolution, that
interference and hardware faults produce the same signature as an attack, and that the
absence of capture evidence is not the absence of an attack. It also flags small sample
sizes explicitly.

A verdict of `CORRELATION FOUND` requires three independent conditions to hold at once,
and every parameter used is printed alongside the result. When the tool cannot support a
finding it says `CORRELATION NOT ESTABLISHED` and lists which condition failed.

## Lawful use

Capturing traffic on a network you own or administer is generally lawful. Capturing on
networks you do not own or have written permission to monitor generally is not. Lock
captures to your own BSSID.

Transmitting deauthentication frames is a separate matter and is unlawful in most
jurisdictions regardless of whose network it is — in the United States the FCC has
issued substantial fines for Wi-Fi blocking under 47 U.S.C. § 333. This tool provides no
capability to do it, and if you are building a case about someone else doing it, do not
undermine that case by doing it yourself.

## Reporting a problem

If you find a code path that contradicts anything above, treat it as a defect and open
an issue. The claims in this document are meant to be verifiable, not aspirational.
