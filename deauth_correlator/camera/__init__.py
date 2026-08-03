"""Camera integration - read-only.

Supports the TP-Link Tapo C100 (and any ONVIF-conformant camera) for three
things: measuring the camera's clock error against the analysis host, pulling
still frames as exhibits, and recording motion events into the camera-event CSV
the analysis consumes.
"""

from .onvif_min import MotionEvent, OnvifClient, OnvifError, is_motion_topic
from .recorder import MotionRecorder, RecorderStatus
from .tapo import CameraConfig, ProbeResult, credentials_help, probe, snapshot

__all__ = ["CameraConfig", "ProbeResult", "MotionEvent", "MotionRecorder",
           "RecorderStatus", "OnvifClient", "OnvifError", "probe", "snapshot",
           "credentials_help", "is_motion_topic"]
