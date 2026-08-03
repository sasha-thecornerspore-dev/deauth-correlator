"""Windowed entry point for the frozen build.

This is the script behind the ``deauth-correlator-gui`` executable and behind
the macOS ``.app`` bundle. It calls :func:`deauth_correlator.gui.app.launch`,
which returns 0 when the window closes normally and 2 when Tk cannot open a
display.

Two things have to be handled here that do not arise when the same code is run
from a terminal.

First, a windowed executable has no console. CPython then leaves ``sys.stdout``
and ``sys.stderr`` set to ``None``, and any ``print()`` reached at runtime
raises ``AttributeError: 'NoneType' object has no attribute 'write'``. The GUI
does print - ``launch()`` reports a missing display on stderr, and imported
libraries emit warnings - so the streams are replaced with sinks that accept
writes and discard them.

Second, an exception escaping ``launch()`` in a windowed process has nowhere to
go: the window never appears and there is no terminal showing a traceback. The
handler below puts the traceback in a dialog box so the user has something to
report.
"""

from __future__ import annotations

import multiprocessing
import sys
import traceback

TITLE = "deauth-correlator"


class _NullStream:
    """Stands in for a standard stream that does not exist.

    Only the parts of the file protocol that ``print()`` and the logging and
    warnings machinery actually reach are implemented.
    """

    encoding = "utf-8"
    errors = "replace"

    def write(self, text: str) -> int:
        return len(text)

    def writelines(self, lines) -> None:
        for _ in lines:
            pass

    def flush(self) -> None:
        pass

    def isatty(self) -> bool:
        return False

    def readable(self) -> bool:
        return False

    def writable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def fileno(self) -> int:
        raise OSError("this build has no console, so there is no file descriptor")

    def close(self) -> None:
        pass


def _ensure_streams() -> None:
    if sys.stdout is None:
        sys.stdout = _NullStream()
    if sys.stderr is None:
        sys.stderr = _NullStream()


def _report_crash(text: str) -> None:
    """Show a traceback that would otherwise be lost, then give up quietly."""
    print(text, file=sys.stderr)
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            f"{TITLE} could not start",
            "The graphical interface stopped with an unhandled error.\n\n"
            + text[-2000:])
        root.destroy()
    except Exception:
        # If Tk is the thing that is broken there is no way to show a dialog.
        pass


def main() -> int:
    _ensure_streams()
    from deauth_correlator.gui.app import launch

    return launch()


if __name__ == "__main__":
    # See the comment in entry_cli.py: a frozen executable must not restart
    # itself from the top when a child process is spawned.
    multiprocessing.freeze_support()
    _ensure_streams()
    try:
        code = main()
    except SystemExit:
        raise
    except BaseException:
        _report_crash(traceback.format_exc())
        code = 2
    sys.exit(code)
