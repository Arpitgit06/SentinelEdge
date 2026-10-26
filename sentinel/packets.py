"""Packet model and a dependency-light IPv4/IPv6, TCP, UDP, ICMP, DNS parser.

The live enforcement path parses packets with pure `struct` decoding so the
engine runs at usable speed without heavy deps. Scapy is used for crafting and
lab traffic, never required for the hot path.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from typing import List, Optional

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17

# ---- TCP flags ----
FIN, SYN, RST, PSH, ACK, URG, ECE, CWR = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80


@dataclass
class TcpInfo:
    sport: int
    dport: int
    seq: int
    ack_seq: int
    data_offset: int          # bytes
    flags: int
    window: int
    checksum: Optional[int] = None
    payload: bytes = b""

    # properties
    @property
    def fin(self): return bool(self.flags & FIN)
    @property
    def syn(self): return bool(self.flags & SYN)
    @property
    def rst(self): return bool(self.flags & RST)
    @property
    def psh(self): return bool(self.flags & PSH)
    @property
    def ack(self): return bool(self.flags & ACK)
    @property
    def urg(self): return bool(self.flags & URG)
    @property
    def ece(self): return bool(self.flags & ECE)
    @property
    def cwr(self): return bool(self.flags & CWR)
    @property
    def flag_names(self) -> str:
        names = ["F", "S", "R", "P", "A", "U", "E", "C"]
        out = []
        for idx, flag in enumerate((FIN, SYN, RST, PSH, ACK, URG, ECE, CWR)):
            if self.flags & flag:
                out.append(names[idx])
        return "".join(out) or "-"


@dataclass
class UdpInfo:
    sport: int
    dport: int
    length: int               # UDP length field (8 + payload)
    checksum: Optional[int] = None
    payload: bytes = b""


@dataclass
class IcmpInfo:
    type: int
    code: int
    payload: bytes = b""


@dataclass
class DnsInfo:
    """Minimal DNS decode: the queried names of the first question record(s)."""
    queries: List[str] = field(default_factory=list)
    is_response: bool = False
    # NOTE: only query names are extracted (sufficient for domain reputation).


@dataclass
class PacketMeta:
    """A fully-decoded-enough packet for the pipeline stages.

    `raw` is the IP payload (IPv4/IPv6 frame stripped where available).
    """
    ts: float                  # epoch seconds (pcap ts for replay, monotonic ok)
    raw: bytes = b""
    src: str = ""
    dst: str = ""
    proto: int = 0             # IANA number (6/17/1)
    direction: str = "in"      # 'in' | 'out' | 'unk' — inbound decisions default
    ip_version: int = 4
    ihl: int = 20              # IPv4 header length
    total_len: int = 0
    frag_offset: int = 0       # in 8-byte units
    more_frag: bool = False
    is_fragment_beyond_first: bool = False
    ttl: int = 0
    tcp: Optional[TcpInfo] = None
    udp: Optional[UdpInfo] = None
    icmp: Optional[IcmpInfo] = None
    dns: Optional[DnsInfo] = None
    truncated: bool = False
    # --- flow context (filled by flow table before ML stage) ---
    _flow_row_cache: Optional[dict] = field(default=None, repr=False, compare=False)

    # -- derived helpers ------------------------------------------------------
    @property
    def proto_name(self) -> str:
        return {PROTO_TCP: "tcp", PROTO_UDP: "udp", PROTO_ICMP: "icmp"}.get(
            self.proto, "other")

    @property
    def sport(self) -> Optional[int]:
        return self.tcp.sport if self.tcp else (self.udp.sport if self.udp else None)

    @property
    def dport(self) -> Optional[int]:
        return self.tcp.dport if self.tcp else (self.udp.dport if self.udp else None)

    @property
    def payload_len(self) -> int:
        if self.tcp is not None:
            return len(self.tcp.payload)
        if self.udp is not None:
            return max(0, self.udp.length - 8) if getattr(self.udp, "length", 0) else len(
                self.udp.payload)
        return len(self.raw)

    def flow_key(self) -> tuple:
        return (self.proto, self.src, self.sport, self.dst, self.dport)

    def is_loopback(self) -> bool:
        import ipaddress
        for ip in (self.src, self.dst):
            try:
                if ipaddress.ip_address(ip).is_loopback:
                    return True
            except ValueError:
                pass
        return False

    def is_dns(self) -> bool:
        if self.udp and self.udp.sport == 53:
            return True
        if self.udp and self.udp.dport == 53 and not self.is_response_dgram():
            return True
        if self.tcp and self.tcp.dport == 53:
            return True
        return False

    def is_response_dgram(self) -> bool:
        return self.dns is not None and self.dns.is_response

    def is_dhcp(self) -> bool:
        return (self.udp is not None
                and {self.udp.sport, self.udp.dport} & {67, 68}
                and (self.udp.sport in (67, 68) or self.udp.dport in (67, 68)))


def _ip_str(fout: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", fout))


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def parse_dns_query(payload: bytes) -> Optional[DnsInfo]:
    """Decode DNS header + question names (handles label compression pointers)."""
    if len(payload) < 12:
        return None
    try:
        flags = struct.unpack("!H", payload[2:4])[0]
        qd = struct.unpack("!H", payload[4:6])[0]
    except struct.error:
        return None
    is_resp = bool(flags & 0x8000)
    queries: List[str] = []
    pos = 12
    for _ in range(min(qd, 4)):          # cap work
        name = _read_dns_name(payload, pos)
        if not name:
            break
        queries.append(name)
        # skip skip type(2) class(2)
        end = _dns_name_end(payload, pos)
        if not end or end + 4 > len(payload):
            break
        pos = end + 4
    if not queries and qd:
        return None
    return DnsInfo(queries=queries, is_response=is_resp)


def _read_dns_name(payload: bytes, pos: int, depth: int = 0) -> Optional[str]:
    labels = []
    while pos < len(payload):
        length = payload[pos]
        if length == 0:
            break
        if length & 0xC0 == 0xC0:        # compression pointer
            ptr = struct.unpack("!H", payload[pos:pos + 2])[0] & 0x3FFF
            inner = _read_dns_name(payload, ptr, depth + 1)
            if inner and depth < 3:
                labels.append(inner)
            else:
                labels.append("...")
            break
        labels.append(payload[pos + 1:pos + 1 + length].decode("idna", errors="replace"))
        pos += 1 + length
        if len(labels) > 20:
            break
    return ".".join(labels) if labels else None


def _dns_name_end(payload: bytes, pos: int, hops: int = 0) -> Optional[int]:
    while pos < len(payload):
        length = payload[pos]
        if length == 0:
            return pos + 1
        if length & 0xC0 == 0xC0:
            return pos + 2
        pos += 1 + length
        hops += 1
        if hops > 64:
            return None
    return None


def parse_l4(proto: int, payload: bytes) -> tuple:
    """Decode TCP/UDP/ICMP transport payloads -> (tcp, udp, icmp)."""
    tcp = udp = icmp = None
    if proto == PROTO_TCP and len(payload) >= 20:
        sport, dport, seq, ack_seq = struct.unpack("!HHII", payload[:12])
        off_flags, window = struct.unpack("!HH", payload[12:16])
        data_offset = (off_flags >> 12) * 4
        flags = off_flags & 0x01FF
        checksum = struct.unpack("!H", payload[16:18])[0]
        if data_offset < 20 or data_offset > len(payload):
            data_offset = 20             # malformed; protocol stage will flag
        tcp = TcpInfo(sport=sport, dport=dport, seq=seq, ack_seq=ack_seq,
                      data_offset=data_offset, flags=flags, window=window,
                      checksum=checksum, payload=payload[data_offset:])
    elif proto == PROTO_UDP and len(payload) >= 8:
        sport, dport, length, checksum = struct.unpack("!HHHH", payload[:8])
        udp = UdpInfo(sport=sport, dport=dport, length=length, checksum=checksum,
                      payload=payload[8:])
    elif proto == PROTO_ICMP and len(payload) >= 4:
        typ, code = struct.unpack("!BB", payload[:2])
        icmp = IcmpInfo(type=typ, code=code, payload=payload[8:])  # skip csum for echo data
    return tcp, udp, icmp


def parse_ip(buf: bytes, ts: float = 0.0, direction: str = "in") -> Optional[PacketMeta]:
    """Parse an IPv4/IPv6 packet body -> PacketMeta, or None if not conceptually IP."""
    if buf and (buf[0] >> 4) == 6:
        return _parse_ipv6(buf, ts, direction)
    if not buf or (buf[0] >> 4) != 4:
        return None
    ihl_words = buf[0] & 0xF
    ihl = ihl_words * 4
    if ihl < 20 or len(buf) < ihl:
        # Still classify as malformed IP so protocol stage can reason about it
        pkt = PacketMeta(ts=ts, raw=buf, direction=direction, truncated=True)
        pkt.ihl = ihl
        return pkt
    tos, total_len, _id, frag_off_flags, ttl, proto_num = struct.unpack(
        "!BHHHBB", buf[1:10])
    frag_off = frag_off_flags & 0x1FFF
    more_frag = bool(frag_off_flags & 0x2000) or frag_off > 0
    src, dst = _ip_str(struct.unpack("!I", buf[12:16])[0]), _ip_str(
        struct.unpack("!I", buf[16:20])[0])
    pkt = PacketMeta(ts=ts, raw=buf, src=src, dst=dst, proto=proto_num,
                     direction=direction, ip_version=4, ihl=ihl,
                     total_len=total_len, frag_offset=frag_off,
                     more_frag=more_frag, ttl=ttl)
    pkt.is_fragment_beyond_first = frag_off > 0
    l4 = buf[ihl:]
    pkt.tcp, pkt.udp, pkt.icmp = parse_l4(proto_num, l4)
    if pkt.udp and (pkt.udp.dport == 53 or pkt.udp.sport == 53) and pkt.udp.length >= 12:
        pkt.dns = parse_dns_query(pkt.udp.payload)
    return pkt


def _parse_ipv6(buf: bytes, ts: float, direction: str) -> Optional[PacketMeta]:
    """Basic IPv6 (no extension-header chains): fixed 40-byte header."""
    if len(buf) < 40:
        pkt = PacketMeta(ts=ts, raw=buf, direction=direction, truncated=True,
                         ip_version=6)
        return pkt
    _vtf, _pl, nxt, _hl, src_b, dst_b = struct.unpack(
        "!IHBB16s16s", buf[:40])
    src = socket.inet_ntop(socket.AF_INET6, src_b)
    dst = socket.inet_ntop(socket.AF_INET6, dst_b)
    pkt = PacketMeta(ts=ts, raw=buf, src=src, dst=dst, proto=nxt,
                     direction=direction, ip_version=6, ihl=40,
                     total_len=40 + _pl, ttl=_hl)
    l4 = buf[40:]
    pkt.tcp, pkt.udp, pkt.icmp = parse_l4(nxt, l4)
    if pkt.udp and (pkt.udp.dport == 53 or pkt.udp.sport == 53):
        pkt.dns = parse_dns_query(pkt.udp.payload)
    return pkt
