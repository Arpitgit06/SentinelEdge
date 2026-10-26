"""Passive OS fingerprint hint (p0f-style heuristic, approximate by design).

Reads TTL + TCP window + DF hints from an inbound packet: no packets are sent,
no packets are touched. Result is clearly labelled an estimate:
    ttl 255 -> 'agent like network appliance or BSD'
    ttl 128 -> 'agent looks like a Windows host'
    ttl 64  -> 'agent looks like a Linux/BSD/macOS host'
tiny windows, SYN data etc. refine slightly. Result goes into the alert as an
"OS hint", never a claim.
"""

from __future__ import annotations

from typing import Optional

from sentinel.packets import PacketMeta


def os_hint(pkt: PacketMeta) -> Optional[str]:
    if pkt.ttl <= 0:
        return None
    base = None
    if pkt.ttl >= 255:
        base = "network appliance or BSD-class host"
    elif pkt.ttl >= 128:
        base = "Windows host"
    elif pkt.ttl >= 64:
        base = "Linux/BSD/macOS-class host"
    elif pkt.ttl >= 32:
        base = "older appliance or long host path"
    else:
        base = "unusual TTL"
    suffix = []
    if pkt.tcp is not None:
        if pkt.tcp.flags & 0x02 and pkt.tcp.window in (1024, 8192, 16384):
            suffix.append("scanner-like TCP window")
        if pkt.tcp.syn and len(pkt.tcp.payload) == 0 and pkt.tcp.window >= 8192:
            suffix.append("typical OS stack handshake")
    label = f"likely {base}"
    if suffix:
        label += " (" + ", ".join(suffix[:2]) + ")"
    return label
