"""A minimal, read-only ONVIF client built on requests and the standard library.

Written rather than pulled from a dependency for two reasons: the tool must
stay auditable by anyone reviewing what it does on the network, and the
operations needed here are a small, fixed set of reads.

Every operation in this module is a read or a standard event subscription
against a camera the operator owns and has entered credentials for. Nothing
changes camera configuration, and nothing is sent anywhere else.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import requests

NS = {
    "s": "http://www.w3.org/2003/05/soap-envelope",
    "tds": "http://www.onvif.org/ver10/device/wsdl",
    "trt": "http://www.onvif.org/ver10/media/wsdl",
    "tev": "http://www.onvif.org/ver10/events/wsdl",
    "tt": "http://www.onvif.org/ver10/schema",
    "wsa": "http://www.w3.org/2005/08/addressing",
    "wsnt": "http://docs.oasis-open.org/wsn/b-2",
    "tptz": "http://www.onvif.org/ver20/ptz/wsdl",
}

ENVELOPE = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
    'xmlns:tds="http://www.onvif.org/ver10/device/wsdl" '
    'xmlns:trt="http://www.onvif.org/ver10/media/wsdl" '
    'xmlns:tev="http://www.onvif.org/ver10/events/wsdl" '
    'xmlns:tt="http://www.onvif.org/ver10/schema" '
    'xmlns:wsa="http://www.w3.org/2005/08/addressing" '
    'xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2">'
    "{header}<s:Body>{body}</s:Body></s:Envelope>"
)

WSSE = (
    '<s:Header><Security s:mustUnderstand="1" '
    'xmlns="http://docs.oasis-open.org/wss/2004/01/'
    'oasis-200401-wss-wssecurity-secext-1.0.xsd">'
    "<UsernameToken><Username>{user}</Username>"
    '<Password Type="http://docs.oasis-open.org/wss/2004/01/'
    'oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{digest}</Password>'
    '<Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/'
    'oasis-200401-wss-soap-message-security-1.0#Base64Binary">{nonce}</Nonce>'
    '<Created xmlns="http://docs.oasis-open.org/wss/2004/01/'
    'oasis-200401-wss-wssecurity-utility-1.0.xsd">{created}</Created>'
    "</UsernameToken></Security></s:Header>"
)

MOTION_TOPICS = (
    "RuleEngine/CellMotionDetector/Motion",
    "VideoSource/MotionAlarm",
    "RuleEngine/MotionRegionDetector/Motion",
    "VideoAnalytics/MotionDetection",
    "RuleEngine/TamperDetector/Tamper",
    "RuleEngine/LineDetector/Crossed",
    "RuleEngine/FieldDetector/ObjectsInside",
)


class OnvifError(RuntimeError):
    pass


@dataclass
class MotionEvent:
    utc: datetime
    topic: str
    active: bool
    source: str = ""
    raw: str = ""


@dataclass
class DeviceInfo:
    manufacturer: str = ""
    model: str = ""
    firmware: str = ""
    serial: str = ""
    hardware: str = ""

    def summary(self) -> str:
        bits = [b for b in (self.manufacturer, self.model) if b]
        text = " ".join(bits) or "unknown camera"
        if self.firmware:
            text += f" (firmware {self.firmware})"
        return text


class OnvifClient:
    """Read-only ONVIF client.

    ``timeout`` is deliberately short: a camera that is not answering should
    surface as an error in the GUI, not hang the analysis.
    """

    def __init__(self, host: str, port: int = 2020, username: str = "",
                 password: str = "", timeout: float = 8.0):
        self.host = host
        self.port = int(port)
        self.username = username
        self.password = password
        self.timeout = timeout
        self.session = requests.Session()
        self._clock_offset: float | None = None

    # -- endpoints -------------------------------------------------------

    @property
    def device_url(self) -> str:
        return f"http://{self.host}:{self.port}/onvif/device_service"

    @property
    def media_url(self) -> str:
        return f"http://{self.host}:{self.port}/onvif/media_service"

    @property
    def events_url(self) -> str:
        return f"http://{self.host}:{self.port}/onvif/event_service"

    # -- transport -------------------------------------------------------

    def call(self, url: str, body: str, authenticated: bool = True) -> ET.Element:
        header = self._security_header() if authenticated and self.username else ""
        payload = ENVELOPE.format(header=header, body=body)
        try:
            response = self.session.post(
                url, data=payload.encode("utf-8"),
                headers={"Content-Type": 'application/soap+xml; charset=utf-8'},
                timeout=self.timeout)
        except requests.RequestException as exc:
            raise OnvifError(_connection_message(self.host, self.port, exc)) from exc

        if response.status_code == 401:
            raise OnvifError(
                "the camera rejected the credentials (HTTP 401). On a Tapo camera the "
                "ONVIF username and password are the Camera Account set in the Tapo "
                "app under Device Settings > Advanced Settings > Camera Account - not "
                "the TP-Link cloud login.")

        try:
            root = ET.fromstring(response.content)
        except ET.ParseError as exc:
            raise OnvifError(f"the camera returned a response that is not valid XML "
                             f"(HTTP {response.status_code})") from exc

        fault = root.find(".//s:Fault", NS)
        if fault is not None:
            raise OnvifError(f"the camera returned a SOAP fault: {_fault_text(fault)}")
        if response.status_code >= 400:
            raise OnvifError(f"the camera returned HTTP {response.status_code}")
        return root

    def _security_header(self) -> str:
        nonce = os.urandom(16)
        created = (datetime.now(tz=timezone.utc)
                   .strftime("%Y-%m-%dT%H:%M:%S.") + f"{datetime.now().microsecond:06d}Z")
        digest = base64.b64encode(
            hashlib.sha1(nonce + created.encode() + self.password.encode()).digest()
        ).decode()
        return WSSE.format(user=_xml_escape(self.username), digest=digest,
                           nonce=base64.b64encode(nonce).decode(), created=created)

    # -- reads -----------------------------------------------------------

    def get_system_date_and_time(self) -> datetime:
        """The camera's own clock. Unauthenticated per the ONVIF specification."""
        root = self.call(self.device_url, "<tds:GetSystemDateAndTime/>",
                         authenticated=False)
        utc = root.find(".//tt:UTCDateTime", NS)
        if utc is None:
            local = root.find(".//tt:LocalDateTime", NS)
            if local is None:
                raise OnvifError("the camera did not report its clock")
            utc = local
        date = utc.find("tt:Date", NS)
        time_el = utc.find("tt:Time", NS)
        if date is None or time_el is None:
            raise OnvifError("the camera's clock reply was incomplete")
        return datetime(
            int(date.findtext("tt:Year", "1970", NS)),
            int(date.findtext("tt:Month", "1", NS)),
            int(date.findtext("tt:Day", "1", NS)),
            int(time_el.findtext("tt:Hour", "0", NS)),
            int(time_el.findtext("tt:Minute", "0", NS)),
            int(time_el.findtext("tt:Second", "0", NS)),
            tzinfo=timezone.utc)

    def measure_clock_offset(self) -> float:
        """Seconds the camera clock is ahead of this machine's clock.

        A camera running a minute fast will shift every recorded event by a
        minute, which silently destroys a 30-second correlation. Measuring the
        offset makes that visible, and it can be corrected with
        ``--camera-clock-offset``.
        """
        before = datetime.now(tz=timezone.utc)
        camera_time = self.get_system_date_and_time()
        after = datetime.now(tz=timezone.utc)
        midpoint = before + (after - before) / 2
        self._clock_offset = (camera_time - midpoint).total_seconds()
        return self._clock_offset

    def get_device_information(self) -> DeviceInfo:
        root = self.call(self.device_url, "<tds:GetDeviceInformation/>")
        return DeviceInfo(
            manufacturer=root.findtext(".//tds:Manufacturer", "", NS),
            model=root.findtext(".//tds:Model", "", NS),
            firmware=root.findtext(".//tds:FirmwareVersion", "", NS),
            serial=root.findtext(".//tds:SerialNumber", "", NS),
            hardware=root.findtext(".//tds:HardwareId", "", NS),
        )

    def get_capabilities(self) -> dict:
        root = self.call(self.device_url,
                         "<tds:GetCapabilities><tds:Category>All</tds:Category>"
                         "</tds:GetCapabilities>")
        found: dict[str, str] = {}
        for element in root.iter():
            tag = element.tag.rsplit("}", 1)[-1]
            if tag == "XAddr" and element.text:
                parent = _parent_tag(root, element)
                found[parent or tag] = element.text
        return found

    def get_profiles(self) -> list[dict]:
        root = self.call(self.media_url, "<trt:GetProfiles/>")
        profiles = []
        for profile in root.findall(".//trt:Profiles", NS):
            profiles.append({
                "token": profile.get("token", ""),
                "name": profile.findtext("tt:Name", "", NS),
                "encoding": profile.findtext(
                    ".//tt:VideoEncoderConfiguration/tt:Encoding", "", NS),
                "width": profile.findtext(
                    ".//tt:VideoEncoderConfiguration/tt:Resolution/tt:Width", "", NS),
                "height": profile.findtext(
                    ".//tt:VideoEncoderConfiguration/tt:Resolution/tt:Height", "", NS),
            })
        return profiles

    def get_stream_uri(self, profile_token: str) -> str:
        body = (
            "<trt:GetStreamUri><trt:StreamSetup>"
            "<tt:Stream>RTP-Unicast</tt:Stream>"
            "<tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport>"
            "</trt:StreamSetup>"
            f"<trt:ProfileToken>{_xml_escape(profile_token)}</trt:ProfileToken>"
            "</trt:GetStreamUri>")
        root = self.call(self.media_url, body)
        return root.findtext(".//tt:Uri", "", NS)

    def get_snapshot_uri(self, profile_token: str) -> str:
        body = ("<trt:GetSnapshotUri>"
                f"<trt:ProfileToken>{_xml_escape(profile_token)}</trt:ProfileToken>"
                "</trt:GetSnapshotUri>")
        try:
            root = self.call(self.media_url, body)
        except OnvifError:
            return ""
        return root.findtext(".//tt:Uri", "", NS)

    # -- events ----------------------------------------------------------

    def create_pull_point(self, initial_timeout: str = "PT60S") -> str:
        """Start an event subscription and return its address.

        This is the only operation in the package that creates state on a
        remote device. It is a standard ONVIF monitoring subscription against
        the operator's own camera, it expires on its own, and
        :meth:`unsubscribe` removes it.
        """
        body = ("<tev:CreatePullPointSubscription>"
                f"<tev:InitialTerminationTime>{initial_timeout}"
                "</tev:InitialTerminationTime>"
                "</tev:CreatePullPointSubscription>")
        root = self.call(self.events_url, body)
        address = root.findtext(".//wsa:Address", "", NS)
        if not address:
            raise OnvifError("the camera did not return an event subscription address")
        return _rewrite_host(address, self.host, self.port)

    def pull_messages(self, subscription_url: str, timeout: str = "PT20S",
                      limit: int = 50) -> list[MotionEvent]:
        body = (f"<tev:PullMessages><tev:Timeout>{timeout}</tev:Timeout>"
                f"<tev:MessageLimit>{limit}</tev:MessageLimit></tev:PullMessages>")
        root = self.call(subscription_url, body)
        return _parse_notifications(root)

    def renew(self, subscription_url: str, duration: str = "PT60S") -> None:
        body = (f'<Renew xmlns="http://docs.oasis-open.org/wsn/b-2">'
                f"<TerminationTime>{duration}</TerminationTime></Renew>")
        self.call(subscription_url, body)

    def unsubscribe(self, subscription_url: str) -> None:
        try:
            self.call(subscription_url,
                      '<Unsubscribe xmlns="http://docs.oasis-open.org/wsn/b-2"/>')
        except OnvifError:
            pass  # the subscription expires by itself; nothing is left behind


def _connection_message(host: str, port: int, exc: Exception) -> str:
    """A short, actionable message instead of a wrapped urllib3 repr."""
    where = f"{host}:{port}"
    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return (f"no response from {where}. The address may be wrong, the camera may "
                f"be off, or a firewall rule may be blocking it.")
    if isinstance(exc, requests.exceptions.ReadTimeout):
        return (f"{where} accepted the connection but did not reply in time. If this "
                f"happens while pulling events it is usually harmless.")
    if isinstance(exc, requests.exceptions.ConnectionError):
        return (f"{where} refused the connection. ONVIF is probably disabled or on a "
                f"different port - Tapo cameras use 2020, some other models use 80 "
                f"or 8000.")
    if isinstance(exc, requests.exceptions.TooManyRedirects):
        return f"{where} redirected repeatedly; this does not look like an ONVIF service."
    return f"could not reach {where} ({exc.__class__.__name__})."


def _parse_notifications(root: ET.Element) -> list[MotionEvent]:
    events: list[MotionEvent] = []
    for message in root.iter():
        if message.tag.rsplit("}", 1)[-1] != "NotificationMessage":
            continue
        topic = ""
        for child in message:
            if child.tag.rsplit("}", 1)[-1] == "Topic":
                topic = "".join(child.itertext()).strip()
        if not topic:
            continue

        utc = None
        active = True
        source = ""
        for element in message.iter():
            tag = element.tag.rsplit("}", 1)[-1]
            if tag == "Message" and element.get("UtcTime"):
                utc = _parse_utc(element.get("UtcTime"))
            elif tag == "SimpleItem":
                name = (element.get("Name") or "").lower()
                value = (element.get("Value") or "")
                if name in ("state", "ismotion", "motion", "isinside", "logicalstate"):
                    active = value.strip().lower() in ("true", "1", "active")
                elif name in ("source", "videosourceconfigurationtoken",
                              "videosourcetoken", "rule"):
                    source = value

        events.append(MotionEvent(
            utc=utc or datetime.now(tz=timezone.utc),
            topic=_short_topic(topic),
            active=active,
            source=source,
            raw=topic,
        ))
    return events


def is_motion_topic(topic: str) -> bool:
    short = _short_topic(topic)
    return any(short.endswith(t) or t in short for t in MOTION_TOPICS)


def _short_topic(topic: str) -> str:
    return re.sub(r"\b\w+:", "", topic).strip()


def _parse_utc(text: str) -> datetime | None:
    if not text:
        return None
    try:
        cleaned = text.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(cleaned)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _rewrite_host(address: str, host: str, port: int) -> str:
    """Cameras often report a subscription address on 0.0.0.0 or an internal name."""
    return re.sub(r"^https?://[^/]+", f"http://{host}:{port}", address)


def _fault_text(fault: ET.Element) -> str:
    text = " ".join(t.strip() for t in fault.itertext() if t.strip())
    return text[:300] or "unspecified fault"


def _parent_tag(root: ET.Element, target: ET.Element) -> str:
    for parent in root.iter():
        for child in parent:
            if child is target:
                return parent.tag.rsplit("}", 1)[-1]
    return ""


def _xml_escape(text: str) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def iso_duration(seconds: int) -> str:
    delta = timedelta(seconds=max(int(seconds), 1))
    return f"PT{int(delta.total_seconds())}S"
