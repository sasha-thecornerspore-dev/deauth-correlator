# Building deauth-correlator as a standalone application

This directory turns the Python package into an application that runs on a
machine with no Python installed. The intended recipients are the people who
have to look at the evidence rather than produce it: an investigator, a
supervisor, opposing counsel checking a hash. They should be able to unzip a
folder, run the program, and reproduce the report.

Nothing here changes what the tool does. It still only reads. It still never
transmits an 802.11 frame. See [SAFETY.md](../SAFETY.md).

---

## PyInstaller does not cross-compile

**A macOS application cannot be built on Windows, and a Windows executable
cannot be built on macOS.** This is not a limitation of the spec file in this
directory and no option changes it. PyInstaller works by taking the interpreter,
the compiled extension modules and the platform bootloader that are present on
the machine doing the build and packing them into an executable for *that*
operating system and *that* processor architecture. There is nothing in the
build to translate a Windows `.pyd` into a macOS `.so`.

So:

| You want                     | You must build on                                    |
| ---------------------------- | ---------------------------------------------------- |
| `deauth-correlator.exe`      | Windows                                              |
| `deauth-correlator.app`      | macOS                                                |
| An Apple-silicon `.app`      | an Apple-silicon Mac (or an Intel Mac cross-targeting arm64 with a universal2 Python) |
| A Linux executable           | Linux, and preferably the oldest glibc you intend to support |

`packaging/build.py` states which platform it is running on before it starts,
and produces artefacts for that platform only. If you need both, build twice on
two machines, or let CI do it.

That is what `.github/workflows/release.yml` in this repository does. On a `v*`
tag it runs a three-way matrix - `ubuntu-latest`, `windows-latest` and
`macos-latest` - each job running `python packaging/build.py` (without
`--archive`; the workflow packs the result itself so it can apply the macOS
rules described below), then attaches the three archives, the sdist, the wheel
and a `SHA256SUMS.txt` to the GitHub Release. `.github/workflows/test.yml`
separately runs the self-test across all three platforms on every push.

---

## What you need

* Python 3.10 or newer, the same interpreter you want frozen into the result.
* The runtime dependencies: `pandas`, `numpy`, `matplotlib`, and `tzdata` on
  Windows.
* PyInstaller.

```bash
python -m pip install -r requirements.txt
python -m pip install pyinstaller
```

`requirements.txt` also lists `scipy`, `requests` and `opencv-python`. They are
optional, and **whether they are installed when you build decides what the
finished application can do**, because whatever is not present at build time
cannot be added afterwards:

* **scipy** supplies the reference implementations of the significance tests.
  Without it the tool falls back to exact pure-Python versions that produce the
  same numbers, and the report says so — it prints the numerical backend it
  used. Building without scipy therefore produces a smaller application whose
  reports read `pure-python` where the reference build reads `scipy`. Either is
  defensible; be deliberate about which one you hand over.
* **requests** and **opencv-python** are needed for the camera features (the
  `camera` subcommand and the Camera tab). A build made without them is a
  working correlator that cannot talk to a camera. opencv is by far the largest
  single dependency, so leaving it out removes about a third of the size of the
  result.

### Build in a clean virtual environment

This is not a style preference. PyInstaller decides what to bundle by following
import statements — including imports inside functions and inside `try` blocks
that never execute — outwards from the entry script. Every optional backend that
one of the dependencies knows how to use is followed if the package providing it
happens to be installed in the same environment, and then everything *that*
package imports is followed too. A day-to-day environment shared with other work
therefore produces a build that is enormous, slow to analyse, and full of code
this program never calls.

The symptom is unmistakable in the PyInstaller log: hooks are processed for
packages that have nothing to do with wireless forensics. If you see lines like
`Processing standard module hook 'hook-tensorflow.py'`, stop, and build in an
environment created for the purpose.

```
python -m venv .buildenv
.buildenv\Scripts\activate         (Windows)
source .buildenv/bin/activate      (macOS and Linux)
python -m pip install -r requirements.txt pyinstaller
python packaging/build.py
```

The build that produced the sizes quoted below was made this way, in an
environment holding nothing but those packages and what they depend on.

The spec excludes the more common offenders — alternative GUI toolkits,
notebook backends, test suites, and pandas' optional spreadsheet, HTML,
database and remote-storage readers — but that list cannot anticipate
everything that might be installed alongside. A clean environment can.

---

## Building

From the project root:

```bash
python packaging/build.py
```

That runs PyInstaller over `packaging/deauth-correlator.spec`, then runs the
executable it just produced and checks it. Add `--archive` to also get a single
zip file and its SHA-256, which is what you would publish.

| Option        | Effect                                                                                |
| ------------- | ------------------------------------------------------------------------------------- |
| `--distpath`  | Where the finished application goes. Default `<project>/dist`.                          |
| `--workpath`  | Scratch directory. Default `<project>/build`.                                           |
| `--no-clean`  | Keep PyInstaller's caches. Faster on a rebuild, and the usual reason a stale file survives into the output. |
| `--archive`   | Also produce one zip of the result and print its SHA-256. On macOS it archives the `.app` with `ditto`; elsewhere it archives the output directory. |

Exit codes: `0` built and verified, `1` the build produced something that does
not work, `2` the build could not be started at all. A build that produces a
broken executable exits non-zero, so it can be used as a CI gate without
interpreting the log.

To drive PyInstaller yourself instead:

```bash
pyinstaller --noconfirm --distpath dist --workpath build \
    packaging/deauth-correlator.spec
```

You then get no verification, which is the part worth keeping.

---

## What you get

```
dist/
  deauth-correlator/
    deauth-correlator[.exe]        console program
    deauth-correlator-gui[.exe]    windowed program
    README.md  SAFETY.md           copied in by build.py, along with
    LICENSE  NOTICE                whichever of these the project has
    _internal/                     interpreter, libraries, time zone database
  deauth-correlator.app/           macOS only
```

Both executables sit in one directory and share a single copy of the
interpreter, the compiled extensions and the data files, so the second one adds
only its own bootloader and its own compiled entry script.

A full build on Windows with Python 3.14 and every optional dependency
installed comes to about 308 MiB unpacked and 141 MiB zipped, of which each
executable is 17.5 MiB and the rest is `_internal`. Where that goes:

| Component                | Size    |
| ------------------------ | ------- |
| OpenCV                   | 112 MiB |
| SciPy, with its libraries | 68 MiB |
| NumPy, with its libraries | 28 MiB |
| matplotlib               | 15 MiB  |
| pandas                   | 14 MiB  |
| Pillow                   | 11 MiB  |
| Tcl/Tk                   | 6 MiB   |
| Time zone database       | 0.5 MiB |

Leaving out `opencv-python` therefore removes about a third of the total, and
leaving out `scipy` as well removes about a further fifth. Both are legitimate
choices with the consequences described above.

The console program takes the flags documented in the main
[README](../README.md): `--opnsense-log`, `--wifi-capture`, `--camera-events`,
`--outdir`, `--evidence-bundle`, `--self-test`, and the rest. `--gui` works from
it too, so `deauth-correlator --gui` and `deauth-correlator-gui` open the same
window; the separate windowed executable exists so that double-clicking it does
not leave a console window behind.

### Why one directory rather than one file

The build is deliberately one-directory. A one-file executable unpacks itself
into a temporary directory on every start, which with pandas, numpy and
matplotlib inside costs several seconds each time and leaves the extracted copy
behind if the program is killed. It also cannot be signed or notarised
meaningfully, because the signing tools inspect what they can see and everything
of interest is inside an opaque archive. A one-directory build starts
immediately and can be signed file by file.

If you want one file anyway, the spec explains the change: pass the analysis
binaries and data to `EXE` instead of setting `exclude_binaries=True`, and drop
the `COLLECT` call. Do not do it for the macOS bundle — an `.app` is a directory
by definition.

### Verifying by hand

The build script already does the first three of these; they are worth knowing
because they are also how you check an application someone hands you.

```bash
./deauth-correlator --version         # deauth-correlator <version>
./deauth-correlator --self-test       # SELF-TEST PASSED: all 146 checks passed.
./deauth-correlator --check-runtime   # every bundled subsystem must load
./deauth-correlator --list-parsers
```

`--check-runtime` is the one that catches a dead graphical interface. Neither
`--version` nor `--self-test` touches Tkinter, so a bundle missing the Tk
libraries passes both and ships with a GUI that will not open. It needs no
display, and in a standalone build it exits non-zero when something that ships
inside the bundle cannot be imported.

The self-test is the real check. It generates synthetic evidence for every
supported input format, runs the whole pipeline over it twice — once with a
planted correlation, once with independent random data — renders `timeline.png`
and writes a report. It therefore exercises pandas, numpy, matplotlib's Agg
backend, `zoneinfo`, and `sqlite3` inside the frozen program, which is most of
what a bad build breaks. `build.py` runs it from an empty temporary directory,
so an executable that has quietly kept a dependency on the source tree fails
there rather than on someone else's machine.

The windowed executable is not launched by the build script, because it opens a
window and needs a display. Start it once by hand on each platform you ship.

---

## macOS: Gatekeeper will block the unsigned application

The `.app` this spec produces is unsigned and un-notarised. macOS will refuse to
open it. What the user sees depends on the version, but it amounts to
*"deauth-correlator.app" cannot be opened because Apple cannot check it for
malicious software*, sometimes with **Move to Trash** as the prominent button.

This is expected, and it is not evidence that anything is wrong with the build.
Gatekeeper is reporting the absence of an Apple-issued signature, which is a
statement about who paid Apple, not about what the program does.

There are three ways past it, in increasing order of how much you should prefer
them.

**1. Right-click and Open, once.** In Finder, right-click (or Control-click) the
application and choose **Open**, then confirm in the dialog that appears. This
records a per-application exception, so subsequent launches are normal. Opening
it the ordinary way — double-clicking — does not offer that choice, which is why
this is the one instruction people miss. On recent macOS versions the equivalent
route is **System Settings → Privacy & Security**, where an **Open Anyway**
button appears after the first blocked attempt.

**2. Remove the quarantine attribute.** Files that arrive by download, AirDrop
or from a disk image are tagged with `com.apple.quarantine`, and that tag is
what Gatekeeper consults. Clearing it makes the application launch normally:

```bash
xattr -d com.apple.quarantine /Applications/deauth-correlator.app
```

If the tag is on files inside the bundle as well, clear it recursively:

```bash
xattr -dr com.apple.quarantine /Applications/deauth-correlator.app
```

`xattr -l` on the bundle shows whether the attribute is there before and after.
Understand what this does: you are telling macOS that you have decided to trust
this copy. Do it only for a copy whose SHA-256 you have checked against the one
published with the build.

**3. Sign and notarise it properly.** This is the only option that produces an
application other people can open without being talked through a workaround, and
it requires a paid Apple Developer account — there is no free path. In outline:
get a Developer ID Application certificate, sign the bundle with a hardened
runtime, submit it to Apple's notary service, wait for the ticket, and staple
the ticket to the bundle so it validates without a network connection.

```bash
codesign --deep --force --options runtime --timestamp \
    --sign "Developer ID Application: Your Name (TEAMID)" \
    dist/deauth-correlator.app

ditto -c -k --keepParent dist/deauth-correlator.app deauth-correlator.zip
xcrun notarytool submit deauth-correlator.zip \
    --apple-id you@example.com --team-id TEAMID --wait

xcrun stapler staple dist/deauth-correlator.app
spctl --assess --verbose=4 dist/deauth-correlator.app
```

Before signing, change `BUNDLE_IDENTIFIER` in the spec from its placeholder to a
reverse-DNS identifier under a domain you control. Apple ties the identifier to
the certificate, and an identifier you do not own cannot be notarised.

Two notes specific to this build. Archive the bundle with `ditto`, not with a
zip tool: an `.app` contains symbolic links and executable permission bits, and
an archive that discards them produces a bundle macOS refuses to launch.
`build.py --archive` already uses `ditto` when it finds a bundle. And sign after
building rather than during: the spec leaves `codesign_identity` unset, so
PyInstaller ad-hoc signs the collected binaries, which is a valid starting point
for a real signature but is not one itself.

The command-line program inside the bundle stays usable directly:

```bash
/Applications/deauth-correlator.app/Contents/MacOS/deauth-correlator --self-test
```

---

## Windows

The executables are unsigned. SmartScreen shows *Windows protected your PC* on
first run; **More info → Run anyway** starts it. An Authenticode certificate
from a commercial CA removes this, and SmartScreen's reputation system means a
new certificate still warns until the binary has been downloaded enough times.

UPX compression is disabled in the spec on purpose. Packed executables are a
common antivirus heuristic, they cannot be signed after packing, and the space
saved is small next to numpy and OpenCV. A forensic tool that a reviewer's
endpoint protection quarantines is not usable as evidence.

If antivirus software quarantines the build anyway — PyInstaller output is
occasionally misidentified, since the bootloader pattern is shared with things
that are genuinely malicious — the answer is to submit it to the vendor as a
false positive, and in the meantime hand over the source and let the recipient
run `pip install -e .` instead.

Windows has no system time zone database, so the `tzdata` package must be
installed when you build. The spec collects it and the self-test would fail
without it, since every fixture is stamped in `America/New_York`.

---

## Files in this directory

| File                     | What it is                                                                 |
| ------------------------ | -------------------------------------------------------------------------- |
| `deauth-correlator.spec` | The PyInstaller build description: both executables, the hidden imports, the exclusions, and the macOS bundle. |
| `entry_cli.py`           | The script frozen into the console executable. Calls `deauth_correlator.cli:main`. |
| `entry_gui.py`           | The script frozen into the windowed executable. Calls `deauth_correlator.gui.app:launch`, and gives the process usable `stdout`/`stderr` and a visible traceback, neither of which exists when there is no console. |
| `build.py`               | Runs PyInstaller, verifies the result, prints paths and SHA-256 digests.    |
| `icon.ico`, `icon.icns`  | Not present. Add either and the spec picks it up; without them PyInstaller's default icon is used. |
