"""TP-Link Tapo C100 support.

The C100 exposes ONVIF on port 2020 and RTSP on 554, both gated by the
**Camera Account** that is created in the Tapo mobile app under
Device Settings -> Advanced Settings -> Camera Account. That account is
separate from the TP-Link cloud login, and only it will work here.

Streams:
    rtsp://<user>:<pass>@<ip>:554/stream1   1080p
    rtsp://<user>:<pass>@<ip>:554/stream2   360p

Everything in this module reads. Snapshots are pulled by connecting to the
camera's own RTSP stream and keeping one frame.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from .onvif_min import DeviceInfo, OnvifClient, OnvifError

DEFAULT_ONVIF_PORT = 2020
DEFAULT_RTSP_PORT = 554
STREAM_PATHS = {"hd": "stream1", "sd": "stream2"}


@dataclass
class CameraConfig:
    host: str = ""
    username: str = ""
    password: str = ""
    onvif_port: int = DEFAULT_ONVIF_PORT
    rtsp_port: int = DEFAULT_RTSP_PORT
    stream: str = "hd"
    label: str = "Tapo C100"

    def rtsp_url(self, redact: bool = False) -> str:
        path = STREAM_PATHS.get(self.stream, "stream1")
        if redact:
            return f"rtsp://<user>:<password>@{self.host}:{self.rtsp_port}/{path}"
        user = quote(self.username, safe="")
        secret = quote(self.password, safe="")
        return f"rtsp://{user}:{secret}@{self.host}:{self.rtsp_port}/{path}"


@dataclass
class ProbeResult:
    reachable: bool = False
    onvif_ok: bool = False
    rtsp_port_open: bool = False
    device: DeviceInfo = field(default_factory=DeviceInfo)
    profiles: list = field(default_factory=list)
    clock_offset_s: float | None = None
    camera_time_utc: datetime | None = None
    host_time_utc: datetime | None = None
    stream_uri: str = ""
    messages: list = field(default_factory=list)
    error: str = ""

    def summary_lines(self) -> list[str]:
        lines = []
        if not self.reachable:
            lines.append(f"Camera not reachable: {self.error}")
            return lines
        lines.append(f"Device: {self.device.summary()}")
        if self.device.serial:
            lines.append(f"Serial: {self.device.serial}")
        if self.clock_offset_s is not None:
            lines.append(self.clock_note())
        lines.append(f"RTSP port {'open' if self.rtsp_port_open else 'CLOSED'}")
        for profile in self.profiles:
            lines.append(f"Stream profile '{profile['name']}': "
                         f"{profile.get('width')}x{profile.get('height')} "
                         f"{profile.get('encoding')}")
        lines.extend(self.messages)
        return lines

    def clock_note(self) -> str:
        if self.clock_offset_s is None:
            return "Camera clock offset: not measured."
        offset = self.clock_offset_s
        verdict = ("well within tolerance" if abs(offset) <= 2
                   else "large enough to matter for a +/-30 s analysis"
                   if abs(offset) <= 120 else "SEVERE - fix the camera clock")
        direction = "ahead of" if offset >= 0 else "behind"
        return (f"Camera clock is {abs(offset):.2f} s {direction} this computer "
                f"({verdict}). Pass --camera-clock-offset {-offset:.3f} to correct "
                f"camera event times.")


def probe(config: CameraConfig, timeout: float = 6.0) -> ProbeResult:
    """Read-only reachability and clock check against the camera."""
    result = ProbeResult()
    result.rtsp_port_open = _port_open(config.host, config.rtsp_port, timeout=2.0)
    client = OnvifClient(config.host, config.onvif_port, config.username,
                         config.password, timeout=timeout)

    try:
        result.host_time_utc = datetime.now(tz=timezone.utc)
        result.clock_offset_s = client.measure_clock_offset()
        result.camera_time_utc = client.get_system_date_and_time()
        result.reachable = True
        result.onvif_ok = True
    except OnvifError as exc:
        result.error = str(exc)
        if result.rtsp_port_open:
            result.reachable = True
            result.messages.append(
                "ONVIF did not answer, but the RTSP port is open. Snapshots will still "
                "work; motion-event recording will not. Check that ONVIF is enabled and "
                f"that port {config.onvif_port} is correct for this model.")
        return result

    if not config.username:
        result.messages.append(
            "No camera-account credentials were supplied, so only the unauthenticated "
            "clock read was performed.")
        return result

    try:
        result.device = client.get_device_information()
    except OnvifError as exc:
        result.messages.append(f"Device information unavailable: {exc}")

    try:
        result.profiles = client.get_profiles()
        if result.profiles:
            result.stream_uri = client.get_stream_uri(result.profiles[0]["token"])
    except OnvifError as exc:
        result.messages.append(f"Media profiles unavailable: {exc}")

    return result


def snapshot(config: CameraConfig, destination: str | Path,
             timeout_s: float = 12.0) -> Path:
    """Grab one frame from the camera's RTSP stream and write it as a JPEG."""
    try:
        import cv2
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise RuntimeError(
            "Snapshots need OpenCV. Install it with: pip install opencv-python"
        ) from exc

    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)

    capture = cv2.VideoCapture(config.rtsp_url(), cv2.CAP_FFMPEG)
    try:
        if not capture.isOpened():
            raise RuntimeError(
                f"could not open the RTSP stream at "
                f"{config.rtsp_url(redact=True)}. Check the camera-account "
                f"credentials and that RTSP is reachable from this machine.")
        # The first frames off an H.264 stream are often incomplete; take a few.
        frame = None
        for _ in range(8):
            ok, candidate = capture.read()
            if ok and candidate is not None:
                frame = candidate
        if frame is None:
            raise RuntimeError("the RTSP stream opened but produced no frames")
        if not cv2.imwrite(str(destination), frame):
            raise RuntimeError(f"could not write the snapshot to {destination}")
    finally:
        capture.release()
    return destination


def _port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    if not host:
        return False
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def credentials_help() -> str:
    return (
        "Tapo C100 camera account\n"
        "------------------------\n"
        "1. Open the Tapo app and select the camera.\n"
        "2. Device Settings -> Advanced Settings -> Camera Account.\n"
        "3. Create a username and password there (this is NOT your TP-Link login).\n"
        "4. Note the camera's IP address from your router's DHCP list, and give it a\n"
        "   static lease so it does not move.\n"
        "5. ONVIF is on port 2020 and RTSP on 554 for this model.\n"
        "\n"
        "The password is held in memory for the session only. It is never written to\n"
        "the case file, the report, or the evidence bundle - the RTSP URL is recorded\n"
        "in redacted form. You can also supply it in the DEAUTH_CORRELATOR_CAMPASS\n"
        "environment variable to keep it out of shell history."
    )
