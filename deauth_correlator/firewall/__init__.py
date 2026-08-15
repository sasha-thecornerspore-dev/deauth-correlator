"""Reading logs from an OPNsense firewall, so they do not have to be fished out by hand.

This package only ever reads. The OPNsense log API is one controller with four
actions, and one of them - ``clear`` - deletes the log it is pointed at. That is
the single most destructive thing that could be done to the evidence in a case
like this, so the client here does not merely avoid calling it: the request path
is checked against a pattern that cannot express it, and the check runs on the
initial URL and on every redirect hop.

See :mod:`deauth_correlator.firewall.opnsense_api` for the client and
:mod:`deauth_correlator.firewall.fetch` for choosing what to pull.
"""

from .opnsense_api import (                                        # noqa: F401
    FirewallConfig,
    FirewallError,
    FirewallAuthError,
    FirewallUnavailable,
    FirewallRefused,
    OpnsenseClient,
    READ_ONLY_PATH,
)
from .fetch import (                                               # noqa: F401
    LOG_SOURCES,
    LogSource,
    FetchResult,
    fetch_logs,
    window_from_events,
    discover_sources,
)
