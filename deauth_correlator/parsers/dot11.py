"""Minimal IEEE 802.11 management-frame decoding.

Only what is needed to identify deauthentication and disassociation frames and
pull their addresses and reason code. Pure parsing of bytes already on disk -
nothing here touches a network interface.

Frame layout for a management frame:

    frame control (2) | duration (2) | addr1 (6) | addr2 (6) | addr3 (6)
    | seq ctl (2) | body...

For deauth (subtype 12) and disassoc (subtype 10) the body starts with a
2-byte little-endian reason code. addr1 is the receiver (the targeted client
or broadcast), addr2 the transmitter (the address the frames claim to come
from), addr3 the BSSID.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from ..events import mac_from_bytes

TYPE_MGMT = 0
SUBTYPE_ASSOC_REQ = 0
SUBTYPE_ASSOC_RESP = 1
SUBTYPE_REASSOC_REQ = 2
SUBTYPE_PROBE_REQ = 4
SUBTYPE_BEACON = 8
SUBTYPE_DISASSOC = 10
SUBTYPE_AUTH = 11
SUBTYPE_DEAUTH = 12

# Link types seen in captures produced by airodump-ng / tcpdump / Wireshark.
DLT_IEEE802_11 = 105
DLT_PRISM_HEADER = 119
DLT_IEEE802_11_RADIOTAP = 127
DLT_IEEE802_11_AVS = 163
DLT_PPI = 192

WIFI_DLTS = {DLT_IEEE802_11, DLT_PRISM_HEADER, DLT_IEEE802_11_RADIOTAP,
             DLT_IEEE802_11_AVS, DLT_PPI}


@dataclass
class Dot11Frame:
    subtype: int
    ftype: int
    dst_mac: str
    src_mac: str
    bssid: str
    reason_code: int | None
    signal_dbm: int | None = None
    channel: int | None = None

    @property
    def kind(self) -> str | None:
        if self.ftype != TYPE_MGMT:
            return None
        if self.subtype == SUBTYPE_DEAUTH:
            return "deauth"
        if self.subtype == SUBTYPE_DISASSOC:
            return "disassoc"
        if self.subtype in (SUBTYPE_ASSOC_REQ, SUBTYPE_REASSOC_REQ):
            return "assoc"
        return None


def strip_link_header(data: bytes, dlt: int) -> tuple[bytes, int | None, int | None]:
    """Remove the capture-layer header, returning (802.11 bytes, signal, channel)."""
    if dlt == DLT_IEEE802_11:
        return data, None, None
    if dlt == DLT_IEEE802_11_RADIOTAP:
        return _strip_radiotap(data)
    if dlt == DLT_PPI:
        if len(data) < 8:
            return b"", None, None
        ppi_len = struct.unpack_from("<H", data, 2)[0]
        return data[ppi_len:], None, None
    if dlt == DLT_PRISM_HEADER:
        # Prism headers are a fixed 144 bytes in every capture that uses them.
        return data[144:], None, None
    if dlt == DLT_IEEE802_11_AVS:
        if len(data) < 8:
            return b"", None, None
        avs_len = struct.unpack_from(">I", data, 4)[0]
        return data[avs_len:], None, None
    return b"", None, None


def _strip_radiotap(data: bytes) -> tuple[bytes, int | None, int | None]:
    """Skip the radiotap header, opportunistically reading signal and channel."""
    if len(data) < 8:
        return b"", None, None
    version, _pad, length = struct.unpack_from("<BBH", data, 0)
    if version != 0 or length < 8 or length > len(data):
        return b"", None, None

    signal, channel = None, None
    try:
        signal, channel = _radiotap_fields(data, length)
    except (struct.error, IndexError):
        pass
    return data[length:], signal, channel


# Radiotap field sizes and alignments, in bit order. Only the fields up to
# dBm antenna signal (bit 5) are needed, so the table stops being consulted
# once that bit is passed.
_RT_FIELDS = [
    (8, 8),   # 0 TSFT
    (1, 1),   # 1 Flags
    (1, 1),   # 2 Rate
    (4, 2),   # 3 Channel (freq u16 + flags u16)
    (2, 2),   # 4 FHSS
    (1, 1),   # 5 dBm antenna signal
]


def _radiotap_fields(data: bytes, header_len: int) -> tuple[int | None, int | None]:
    # Skip the whole present-bitmap chain; only the first word describes the
    # standard fields this reader cares about.
    offset = 4
    first_present = None
    while True:
        word = struct.unpack_from("<I", data, offset)[0]
        if first_present is None:
            first_present = word
        offset += 4
        if not (word & (1 << 31)) or offset + 4 > header_len:
            break
    present = first_present

    signal = None
    channel = None
    for bit, (size, align) in enumerate(_RT_FIELDS):
        if not (present & (1 << bit)):
            continue
        offset += (-offset) % align
        if offset + size > header_len:
            break
        if bit == 3:
            freq = struct.unpack_from("<H", data, offset)[0]
            channel = _freq_to_channel(freq)
        elif bit == 5:
            signal = struct.unpack_from("<b", data, offset)[0]
        offset += size
    return signal, channel


def _freq_to_channel(freq: int) -> int | None:
    if 2412 <= freq <= 2484:
        return 14 if freq == 2484 else (freq - 2407) // 5
    if 5000 <= freq <= 5900:
        return (freq - 5000) // 5
    if 5955 <= freq <= 7115:
        return (freq - 5955) // 5 + 1
    return None


def parse_dot11(data: bytes, signal: int | None = None,
                channel: int | None = None) -> Dot11Frame | None:
    """Decode an 802.11 frame's header. Returns None if it is not a usable frame."""
    if len(data) < 24:
        return None
    fc = struct.unpack_from("<H", data, 0)[0]
    ftype = (fc >> 2) & 0x03
    subtype = (fc >> 4) & 0x0F
    if ftype != TYPE_MGMT:
        return None

    dst = mac_from_bytes(data[4:10])
    src = mac_from_bytes(data[10:16])
    bssid = mac_from_bytes(data[16:22])

    reason = None
    if subtype in (SUBTYPE_DEAUTH, SUBTYPE_DISASSOC) and len(data) >= 26:
        reason = struct.unpack_from("<H", data, 24)[0]

    return Dot11Frame(subtype=subtype, ftype=ftype, dst_mac=dst, src_mac=src,
                      bssid=bssid, reason_code=reason, signal_dbm=signal,
                      channel=channel)


def decode_packet(data: bytes, dlt: int) -> Dot11Frame | None:
    """Full path: strip the capture header, then decode the management frame."""
    body, signal, channel = strip_link_header(data, dlt)
    if not body:
        return None
    return parse_dot11(body, signal, channel)


def build_deauth_frame(src: bytes, dst: bytes, bssid: bytes, reason: int,
                       disassoc: bool = False) -> bytes:
    """Build a deauth/disassoc frame **for synthetic test fixtures only**.

    The self-test needs realistic capture files. This function returns bytes;
    nothing in this package ever writes bytes to a network interface.
    """
    subtype = SUBTYPE_DISASSOC if disassoc else SUBTYPE_DEAUTH
    fc = (subtype << 4) | (TYPE_MGMT << 2)
    return (struct.pack("<HH", fc, 0) + dst + src + bssid
            + struct.pack("<H", 0) + struct.pack("<H", reason))
