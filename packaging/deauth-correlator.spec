# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller build description for deauth-correlator.

It produces one output directory containing two executables that share a single
copy of the interpreter, the compiled extensions and the data files:

    deauth-correlator       console program - the CLI in deauth_correlator/cli.py
    deauth-correlator-gui   windowed program - the Tk interface in
                            deauth_correlator/gui/app.py

Build it through packaging/build.py, which runs PyInstaller and then checks that
the executable it produced actually works:

    python packaging/build.py

or run PyInstaller directly if you want to pass your own options:

    pyinstaller --noconfirm --distpath dist --workpath build \
        packaging/deauth-correlator.spec

On macOS this spec additionally wraps the collected directory in a .app bundle
so the interface can be started from Finder. That step is skipped on every other
platform, and it cannot be performed on any other platform: PyInstaller does not
cross-compile. A macOS bundle has to be built on macOS.

One-directory, not one-file
---------------------------
The build is one-directory. A one-file build unpacks itself into a temporary
directory on every start, which costs several seconds with pandas, numpy and
matplotlib inside, leaves the extracted copy behind if the program is killed,
and produces an executable that code-signing and notarisation tools cannot
inspect. A one-directory build starts immediately and can be signed file by
file. To build one-file anyway, pass a_cli.binaries and a_cli.datas to EXE
instead of setting exclude_binaries=True, and delete the COLLECT call - but do
not do that for the macOS bundle, because an .app is a directory by definition.

Note for linters: Analysis, PYZ, EXE, COLLECT, BUNDLE and SPECPATH are injected
into this file's namespace by PyInstaller and are undefined when it is read as
ordinary Python.
"""

import importlib.util
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

# --------------------------------------------------------------------------
# Locations
# --------------------------------------------------------------------------

SPEC_DIR = Path(SPECPATH).resolve()          # noqa: F821 - injected by PyInstaller
PROJECT_ROOT = SPEC_DIR.parent

# The package has to be importable while the spec runs, both here and in the
# isolated sub-processes PyInstaller starts for collect_submodules (it passes
# the parent's sys.path to them). This makes the build work from a plain clone,
# with no pip install of any kind.
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# deauth_correlator/__init__.py defines two constants and imports nothing, so
# reading the version this way pulls in none of the heavy dependencies.
from deauth_correlator import __version__  # noqa: E402

CLI_NAME = "deauth-correlator"
GUI_NAME = "deauth-correlator-gui"
DIST_NAME = "deauth-correlator"
APP_NAME = "deauth-correlator.app"

# Replace this with a reverse-DNS identifier under a domain you control before
# signing or notarising the bundle. Apple ties the identifier to the signing
# certificate, and an identifier you do not own cannot be notarised.
BUNDLE_IDENTIFIER = "org.deauth-correlator.app"


def _optional_file(path: Path):
    """Return the path as a string when the file exists, otherwise None."""
    return str(path) if path.is_file() else None


# Icons are optional. Drop packaging/icon.ico or packaging/icon.icns in place
# and they are picked up; without them PyInstaller uses its own default icon.
ICON_WINDOWS = _optional_file(SPEC_DIR / "icon.ico")
ICON_MACOS = _optional_file(SPEC_DIR / "icon.icns")

if sys.platform == "win32":
    EXE_ICON = ICON_WINDOWS
elif sys.platform == "darwin":
    EXE_ICON = ICON_MACOS
else:
    EXE_ICON = None


# --------------------------------------------------------------------------
# What has to be pulled in that the dependency scan would otherwise miss
# --------------------------------------------------------------------------

def _installed(module_name: str) -> bool:
    """True when the module can be located in the environment doing the build."""
    try:
        return importlib.util.find_spec(module_name) is not None
    except (ImportError, ValueError):
        return False


# Submodule names that pull in a development-time dependency rather than
# anything the program uses. scipy.special ships modules that compare its
# functions against arbitrary-precision references, which drags in mpmath and
# sympy - tens of megabytes to support code that only scipy's own test suite
# calls.
_UNWANTED_SUBMODULES = (
    "test", "tests", "testing",
    "_testutils", "_mptestutils", "_test_internal", "_precompute",
)


def _wanted_submodule(module_name: str) -> bool:
    """Filter for collect_submodules: drop test and development-only modules."""
    return not any(part in _UNWANTED_SUBMODULES
                   for part in module_name.split("."))


hiddenimports = []
datas = []

# The parser registry in deauth_correlator/parsers/__init__.py instantiates
# every parser at import time, so all of them are reachable by a static scan
# today. Collecting the package wholesale keeps the build correct if a parser is
# ever registered by name instead, and costs nothing - these are the program's
# own modules.
hiddenimports += collect_submodules("deauth_correlator")

hiddenimports += [
    # Tkinter. PyInstaller's own hook collects the Tcl and Tk libraries and
    # their script directories; these are the Python-side submodules the GUI
    # reaches through "from tkinter import ...".
    "tkinter",
    "tkinter.ttk",
    "tkinter.filedialog",
    "tkinter.messagebox",
    "tkinter.font",
    # deauth_correlator/plot.py calls matplotlib.use("Agg") before importing
    # pyplot. Naming the backend module here means the build does not depend on
    # the matplotlib hook's bytecode scan finding that call.
    "matplotlib.backends.backend_agg",
    # deauth_correlator/parsers/kismet.py reads a Kismet SQLite database, and
    # the self-test writes one.
    "sqlite3",
    # Every displayed time is converted through zoneinfo.
    "zoneinfo",
]

if _installed("tzdata"):
    # Windows ships no IANA time zone database, so zoneinfo cannot resolve
    # "America/New_York" unless the tzdata wheel travels with the build. zoneinfo
    # loads a zone by importing its region as a package and reading a data file
    # out of it, which is why both the submodules and the data files are needed.
    # This is the same work PyInstaller's bundled tzdata hook does; doing it here
    # as well is harmless (the file lists are de-duplicated) and keeps the build
    # from depending on which version of pyinstaller-hooks-contrib is installed.
    hiddenimports += collect_submodules("tzdata")
    datas += collect_data_files("tzdata")

if _installed("scipy"):
    # deauth_correlator/stats.py imports scipy.stats when it is present and
    # falls back to exact pure-Python implementations when it is not. Whether
    # scipy is installed in the build environment therefore decides which
    # backend the frozen program reports, and the report prints that name. Parts
    # of scipy.stats and scipy.special are loaded by name at call time rather
    # than imported at the top of a module, so the submodule lists are collected
    # explicitly, minus the test and precomputation machinery.
    hiddenimports += collect_submodules("scipy.stats", filter=_wanted_submodule)
    hiddenimports += collect_submodules("scipy.special", filter=_wanted_submodule)

# The camera features are optional and are imported inside the functions that
# use them, so a build made without these installed is still a working
# correlator - it simply cannot talk to a camera. Listing them explicitly means
# that when they are installed they are definitely collected.
for optional in ("requests", "cv2"):
    if _installed(optional):
        hiddenimports.append(optional)


# --------------------------------------------------------------------------
# What to keep out
# --------------------------------------------------------------------------

EXCLUDES = [
    # Alternative GUI toolkits. matplotlib binds to whichever of these is
    # importable in the build environment, so a stray PySide6 in the same
    # virtual environment would otherwise add a whole Qt installation to the
    # output. This program draws its figure with the headless Agg backend and
    # puts its window on screen with Tkinter, and needs none of these.
    "PyQt5", "PyQt6", "PySide2", "PySide6", "shiboken2", "shiboken6",
    "wx", "gi", "pygtk", "gtk",
    # Browser and notebook backends, and the web server one of them needs.
    "matplotlib.backends.backend_webagg",
    "matplotlib.backends.backend_webagg_core",
    "matplotlib.backends.backend_nbagg",
    "tornado",
    "IPython", "ipykernel", "jupyter", "jupyter_core", "notebook", "nbformat",
    # Test suites that ship inside the dependencies. They are large and none of
    # them is ever executed by this program.
    "pytest", "_pytest", "nose",
    "matplotlib.tests", "matplotlib.testing",
    "numpy.tests", "pandas.tests",
    "scipy.stats.tests", "scipy.special.tests",
    # pandas' optional file-format backends. pandas imports these inside the
    # readers and writers that need them, so PyInstaller finds them and collects
    # them whenever they happen to be installed. This program reads CSV, syslog,
    # pcap and SQLite and writes CSV, Markdown and PNG; it opens no spreadsheet,
    # no HTML, no HDF5, no remote object store, and never touches the clipboard.
    # Excluding them costs nothing and removes a large amount of unrelated code
    # from evidence-producing software. pyarrow is deliberately absent from this
    # list: it is an optional extra that a clean build environment will not have,
    # but where it is installed pandas may use it to hold string columns, and
    # cutting out something the data itself passes through is not a risk worth
    # taking in a tool whose output is meant to be reproducible.
    "openpyxl", "xlrd", "xlsxwriter", "odf", "pyxlsb", "tables",
    "lxml", "bs4", "html5lib",
    "sqlalchemy", "psycopg2", "pymysql",
    "fsspec", "s3fs", "gcsfs", "adlfs", "botocore", "boto3",
    "numexpr", "bottleneck", "zstandard",
    "win32com", "win32clipboard",
]
# "setuptools", "pip" and "wheel" are deliberately not excluded. PyInstaller
# aliases the packages setuptools vendors, and excluding one of them makes the
# dependency graph inconsistent and aborts the build.

HOOKS_CONFIG = {
    # Collect the Agg backend and nothing else. Left to itself the matplotlib
    # hook selects whichever GUI backend happens to be importable, which is both
    # unnecessary and large. Agg writes the PNG directly to disk, which is all
    # deauth_correlator/plot.py asks of it.
    "matplotlib": {"backends": ["Agg"]},
}


def make_analysis(entry_script):
    """One dependency analysis, shared settings, for one entry script."""
    return Analysis(                          # noqa: F821 - injected
        [str(entry_script)],
        pathex=[str(PROJECT_ROOT)],
        binaries=[],
        datas=list(datas),
        hiddenimports=list(hiddenimports),
        hookspath=[],
        hooksconfig=HOOKS_CONFIG,
        excludes=list(EXCLUDES),
        runtime_hooks=[],
        noarchive=False,
    )


analysis_cli = make_analysis(SPEC_DIR / "entry_cli.py")
analysis_gui = make_analysis(SPEC_DIR / "entry_gui.py")

pyz_cli = PYZ(analysis_cli.pure)              # noqa: F821 - injected
pyz_gui = PYZ(analysis_gui.pure)              # noqa: F821 - injected

# UPX compression is disabled deliberately. Compressed executables are a common
# heuristic trigger for antivirus products, they cannot be code-signed after
# packing, and the space saved is small next to the numerical libraries. A
# forensic tool that a reviewer's endpoint protection quarantines is of no use.
UPX = False

exe_cli = EXE(                                # noqa: F821 - injected
    pyz_cli,
    analysis_cli.scripts,
    [],
    exclude_binaries=True,
    name=CLI_NAME,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=UPX,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=EXE_ICON,
    contents_directory="_internal",
)

exe_gui = EXE(                                # noqa: F821 - injected
    pyz_gui,
    analysis_gui.scripts,
    [],
    exclude_binaries=True,
    name=GUI_NAME,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=UPX,
    console=False,
    # Leave PyInstaller's own crash dialog enabled. packaging/entry_gui.py
    # catches what it can and shows a traceback itself; this covers failures
    # that happen before that handler is in place.
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=EXE_ICON,
    contents_directory="_internal",
)

# Both executables go into one directory and share one copy of everything else.
# The two analyses overlap almost completely, and COLLECT de-duplicates by
# destination path, so the second executable adds only its own bootloader and
# its own compiled entry script.
#
# The GUI executable is listed LAST on purpose. COLLECT loops over its EXE
# arguments assigning `self.console = arg.console` each time, so the last one
# assigned is the one that survives - not the first. BUNDLE then reads that
# setting, and a collection marked as a console program produces an .app with
# LSBackgroundOnly set, which never opens a window and never appears in the
# Dock. Listing the console executable first and the windowed one second is
# therefore what makes the macOS bundle usable.
#
# Do not reorder these without re-reading COLLECT.__init__ and BUNDLE.__init__
# in the PyInstaller version in use. packaging/build.py checks the resulting
# Info.plist and fails the build if this is wrong, which is how the original
# ordering was caught.
collected = COLLECT(                          # noqa: F821 - injected
    exe_cli,
    exe_gui,
    analysis_gui.binaries,
    analysis_gui.datas,
    analysis_cli.binaries,
    analysis_cli.datas,
    strip=False,
    upx=UPX,
    upx_exclude=[],
    name=DIST_NAME,
)

# --------------------------------------------------------------------------
# macOS application bundle
# --------------------------------------------------------------------------
# BUNDLE is a no-op off macOS, but the guard is kept explicit so that reading
# this file makes the platform restriction obvious. PyInstaller cannot
# cross-compile: running this spec on Windows or Linux produces Windows or Linux
# executables and no .app, whatever is written here.
#
# BUNDLE takes the name of its main executable from the first EXECUTABLE entry
# in its table of contents, so exe_gui is passed before the collection: that
# puts the windowed executable at the head of the TOC and makes it the one macOS
# launches. The console flag is a separate matter and follows the last argument,
# which is the collection - see the note above COLLECT. Both executables end up
# in Contents/MacOS, and the command-line one stays usable at
#     deauth-correlator.app/Contents/MacOS/deauth-correlator
if sys.platform == "darwin":
    app = BUNDLE(                             # noqa: F821 - injected
        exe_gui,
        collected,
        name=APP_NAME,
        icon=ICON_MACOS,
        bundle_identifier=BUNDLE_IDENTIFIER,
        version=__version__,
        info_plist={
            "CFBundleName": DIST_NAME,
            "CFBundleDisplayName": DIST_NAME,
            "CFBundleShortVersionString": __version__,
            "CFBundleVersion": __version__,
            "NSHighResolutionCapable": True,
            # The program reads files the user chooses in a file dialog and
            # talks to a camera on the local network. It declares no document
            # types and registers no URL schemes.
            "LSApplicationCategoryType": "public.app-category.utilities",
            "NSHumanReadableCopyright":
                "Licensed under the Apache License, Version 2.0.",
        },
    )
