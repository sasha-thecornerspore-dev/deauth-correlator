"""deauth-correlator - read-only forensic correlation of wireless disruption
events with external (camera) events.

This package never transmits 802.11 frames, never injects, and never scans.
It reads log files, capture files, and - only when explicitly asked - the
user's own camera over ONVIF/RTSP.
"""

__version__ = "1.0.0"
__tool_name__ = "deauth-correlator"

TOOL_ID = f"{__tool_name__} {__version__}"
