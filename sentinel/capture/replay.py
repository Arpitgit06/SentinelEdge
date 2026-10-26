"""Offline replay: evaluate saved pcaps through the engine (no enforcement).

This is the core of the red-team replay harness: every packet in the capture
goes through the full pipeline, verdicts keep their original packet
timestamps, and the caller (harness.replay) compares verdicts with labels.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


@dataclass
class ReplayVerdict:
    ts: float                      # packet timestamp from the pcap
    action: str                    # allow | block | quarantine
    reason: str
    stage: str
    src: str
    dst: str
    dport: Optional[int]


def replay_pcap(pcap_path: Path, engine: Any,
                packet_filter: Optional[Callable[[bytes], bool]] = None
                ) -> List[ReplayVerdict]:
    """Feed every IP packet of a pcap through the engine synchronously."""
    from scapy.all import rdpcap
    from scapy.compat import raw as scapy_raw
    from sentinel.packets import parse_ip

    packets = rdpcap(str(pcap_path))
    out: List[ReplayVerdict] = []
    for scapy_pkt in packets:
        try:
            frame = bytes(scapy_raw(scapy_pkt))
        except Exception:                           # noqa: BLE001
            continue
        start = _ip_offset(frame)
        buf = frame[start:]
        ts = float(getattr(scapy_pkt, "time", time.time()))
        if packet_filter and not packet_filter(buf):
            continue
        meta = parse_ip(buf, ts=ts, direction="in")
        if meta is None:
            continue
        meta.raw = buf
        verdict = engine.inspect(meta)
        out.append(ReplayVerdict(
            ts=ts, action=verdict.action, reason=verdict.reason,
            stage=verdict.stage, src=meta.src, dst=meta.dst,
            dport=meta.dport))
    return out


def _ip_offset(buf: bytes) -> int:
    """Strip an ethernet frame header if present, else start at IP."""
    if len(buf) >= 14 and buf[12:14] == b"\x08\x00":
        return 14
    if len(buf) >= 14 and buf[12:14] == b"\x86\xdd":
        return 14
    if len(buf) >= 18 and buf[16:18] == b"\x86\xdd":
        return 18
    return 0
