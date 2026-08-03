"""Console entry point for the frozen build.

PyInstaller freezes a *script*, not a console-script entry point, so the
``deauth-correlator = deauth_correlator.cli:main`` declaration in
``pyproject.toml`` is invisible to it. This file is the script the spec points
at, and it does the same thing ``deauth_correlator/__main__.py`` does: hand
``argv`` to :func:`deauth_correlator.cli.main` and return its exit code.

Exit codes are the tool's own, unchanged:

    0   a correlation was found
    1   a correlation was not established
    2   the analysis could not be run
"""

from __future__ import annotations

import multiprocessing
import sys


def main() -> int:
    # Imported inside the function so that an ImportError in the package shows
    # up as a normal traceback from a running program rather than as a failure
    # during interpreter start-up, which is harder to read.
    from deauth_correlator.cli import main as cli_main

    return cli_main()


if __name__ == "__main__":
    # A frozen executable re-runs its own entry script in any child process
    # that multiprocessing spawns. Without this call the child would start the
    # program again from the top instead of running the worker function, which
    # on Windows produces an endless chain of processes. Nothing in
    # deauth_correlator uses multiprocessing today, but numerical libraries
    # sometimes do, and the call costs nothing when no child is being started.
    multiprocessing.freeze_support()
    sys.exit(main())
