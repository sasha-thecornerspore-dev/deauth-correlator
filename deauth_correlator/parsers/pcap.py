"""Reader for the .cap/.pcap/.pcapng files that ``airodump-ng --write`` produces.

This is the primary evidence source. Deauthentication and disassociation
frames - and in particular their reason codes - exist only in the capture;
airodump's CSV carries the AP/station tables, not individual frames.

Both classic libpcap and pcapng are supported, with no third-party
dependency. The reader is strictly sequential and read-only.
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone
from pathlib import Path

from .base import Parser, ParseContext, ParseError
from .dot11 import WIFI_DLTS, decode_packet
from ..events import make_event, reason_text, is_group_addressed, BROADCAST
from ..timeutil import finalize

PCAP_MAGIC_LE = 0xA1B2C3D4          # microsecond resolution, little-endian
PCAP_MAGIC_BE = 0xD4C3B2A1
PCAP_MAGIC_NS_LE = 0xA1B23C4D       # nanosecond resolution
PCAP_MAGIC_NS_BE = 0x4D3CB2A1
PCAPNG_MAGIC = 0x0A0D0D0A

MAX_SNAPLEN = 262144


class PcapParser(Parser):
    id = "pcap80211"
    name = "802.11 capture (pcap/pcapng)"
    describes = ("Raw 802.11 management frames captured in monitor mode. "
                 "Deauthentication and disassociation frames are extracted with "
                 "their transmitter address, target address, BSSID and IEEE reason code.")
    extensions = (".cap", ".pcap", ".pcapng", ".dump")

    def sniff(self, path: Path) -> float:
        head = self.head_bytes(path, 4)
        if len(head) < 4:
            return 0.0
        magic_le = struct.unpack("<I", head)[0]
        magic_be = struct.unpack(">I", head)[0]
        if magic_le in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE, PCAPNG_MAGIC):
            return 1.0
        if magic_be in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
            return 1.0
        if magic_le in (PCAP_MAGIC_BE, PCAP_MAGIC_NS_BE):
            return 1.0
        return 0.0

    def parse(self, path: Path, ctx: ParseContext) -> list[dict]:
        rows: list[dict] = []
        non_wifi = 0

        # The packet readers are generators over an open handle, so the whole
        # loop has to stay inside the file context.
        with open(path, "rb") as fh:
            head = fh.read(4)
            fh.seek(0)
            if len(head) < 4:
                raise ParseError(f"{path.name}: file is too short to be a capture")
            reader = (_read_pcapng if struct.unpack("<I", head)[0] == PCAPNG_MAGIC
                      else _read_pcap)

            for pkt_no, epoch, dlt, data in reader(fh, path, ctx):
                if dlt not in WIFI_DLTS:
                    non_wifi += 1
                    continue
                frame = decode_packet(data, dlt)
                if frame is None or frame.kind not in ("deauth", "disassoc"):
                    continue
                dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
                utc, local, offset = finalize(dt, ctx.time)
                target = frame.dst_mac
                rows.append(make_event(
                    ts_utc=utc, ts_local=local, utc_offset=offset,
                    kind=frame.kind,
                    src_mac=frame.src_mac,
                    dst_mac=target,
                    bssid=frame.bssid,
                    client_mac="" if is_group_addressed(target) else target,
                    reason_code=frame.reason_code,
                    reason_text=reason_text(frame.reason_code),
                    channel=frame.channel,
                    signal=frame.signal_dbm,
                    source_file=str(path),
                    source_kind=self.id,
                    source_ref=f"packet {pkt_no}",
                    notes=("broadcast deauth - disconnects every client on the BSS"
                           if target == BROADCAST else ""),
                    raw=f"{frame.kind} src={frame.src_mac} dst={target} "
                        f"bssid={frame.bssid} reason={frame.reason_code}",
                ))

        if non_wifi and not rows:
            ctx.warn(
                f"{path.name}: contains {non_wifi} packets but none use an 802.11 link "
                f"type. The adapter was probably not in monitor mode when this was "
                f"captured, so no management frames were recorded."
            )
        return rows


def _read_pcap(fh, path: Path, ctx: ParseContext):
    """Yield (packet_number, epoch_seconds, dlt, bytes) from a classic pcap."""
    header = fh.read(24)
    if len(header) < 24:
        raise ParseError(f"{path.name}: truncated pcap header")
    magic = struct.unpack("<I", header[:4])[0]
    if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
        endian = "<"
        nanos = magic == PCAP_MAGIC_NS_LE
    else:
        magic_be = struct.unpack(">I", header[:4])[0]
        if magic_be not in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
            raise ParseError(f"{path.name}: not a recognized pcap file")
        endian = ">"
        nanos = magic_be == PCAP_MAGIC_NS_LE

    # magic, version major/minor, thiszone, sigfigs, snaplen, network(dlt)
    dlt = struct.unpack(endian + "IHHiIII", header)[6]

    divisor = 1e9 if nanos else 1e6
    pkt_no = 0
    while True:
        rec = fh.read(16)
        if len(rec) < 16:
            break
        ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(endian + "IIII", rec)
        if incl_len > MAX_SNAPLEN:
            ctx.warn(f"{path.name}: implausible packet length {incl_len}; stopping read")
            break
        data = fh.read(incl_len)
        if len(data) < incl_len:
            ctx.warn(f"{path.name}: capture ends mid-packet (file truncated by the "
                     f"capture tool being interrupted); {pkt_no} packets read")
            break
        pkt_no += 1
        yield pkt_no, ts_sec + ts_frac / divisor, dlt, data


def _read_pcapng(fh, path: Path, ctx: ParseContext):
    """Yield (packet_number, epoch_seconds, dlt, bytes) from a pcapng file."""
    endian = "<"
    interfaces: list[tuple[int, int]] = []  # (dlt, timestamp resolution divisor)
    pkt_no = 0

    while True:
        head = fh.read(8)
        if len(head) < 8:
            break
        block_type = struct.unpack(endian + "I", head[:4])[0]
        block_len = struct.unpack(endian + "I", head[4:8])[0]

        if block_type == PCAPNG_MAGIC:
            # Section Header Block: the byte-order magic tells us the endianness.
            body = fh.read(4)
            if len(body) < 4:
                break
            if struct.unpack("<I", body)[0] != 0x1A2B3C4D:
                endian = ">"
                block_len = struct.unpack(endian + "I", head[4:8])[0]
            # 8 bytes of header plus the 4-byte magic are already consumed; the
            # remainder includes the trailing block-length field.
            rest = block_len - 12
            if rest < 0:
                break
            fh.read(rest)
            interfaces = []
            continue

        if block_len < 12 or block_len > 100 * 1024 * 1024:
            ctx.warn(f"{path.name}: implausible pcapng block length; stopping read")
            break
        body = fh.read(block_len - 12)
        if len(body) < block_len - 12:
            ctx.warn(f"{path.name}: pcapng file ends mid-block")
            break
        fh.read(4)  # trailing block length

        if block_type == 0x00000001:  # Interface Description Block
            link_type = struct.unpack_from(endian + "H", body, 0)[0]
            divisor = _if_tsresol(body[8:], endian)
            interfaces.append((link_type, divisor))

        elif block_type == 0x00000006:  # Enhanced Packet Block
            if len(body) < 20:
                continue
            iface_id, ts_hi, ts_lo, cap_len, _orig = struct.unpack_from(
                endian + "IIIII", body, 0)
            if iface_id >= len(interfaces):
                continue
            dlt, divisor = interfaces[iface_id]
            ts = ((ts_hi << 32) | ts_lo) / divisor
            data = body[20:20 + cap_len]
            pkt_no += 1
            yield pkt_no, ts, dlt, data

        elif block_type == 0x00000003:  # Simple Packet Block (no timestamp)
            ctx.warn(f"{path.name}: contains Simple Packet Blocks, which carry no "
                     f"timestamp; those packets were skipped")


def _if_tsresol(options: bytes, endian: str) -> float:
    """Read the if_tsresol option (code 9); default is microseconds."""
    offset = 0
    while offset + 4 <= len(options):
        code, length = struct.unpack_from(endian + "HH", options, offset)
        offset += 4
        if code == 0:  # opt_endofopt
            break
        value = options[offset:offset + length]
        offset += length + ((-length) % 4)
        if code == 9 and value:
            raw = value[0]
            if raw & 0x80:
                return float(2 ** (raw & 0x7F))
            return float(10 ** raw)
    return 1e6
