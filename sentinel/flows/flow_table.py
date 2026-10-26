"""Runtime flow table: per-5-tuple state with incremental cumulative counters.

Single source of truth for the ML feature contract: `features.py` reads rows
from this table, so training-time extraction (`tools/pcap_to_flows.py`) and
runtime inference both observe byte-identical feature columns — the core
defence against train/serve skew.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Deque, Dict, Optional, Tuple

from ..packets import PacketMeta, FIN, SYN, RST, PSH, ACK, URG

# TTLs for housekeeping
DEFAULT_FLOW_TTL_S = 4 * 60
SOURCE_TTL_S = 45 * 60


class FlowRow:
    """Incremental per-flow counters (fast path: O(1) per packet)."""

    __slots__ = (
        "proto", "src", "sport", "dst", "dport",
        "t_first", "t_last", "fwd_pkts", "bwd_pkts",
        "fwd_bytes", "bwd_bytes", "fwd_hdr_bytes", "bwd_hdr_bytes",
        "fwd_sizes", "bwd_sizes",
        "fwd_iats", "bwd_iats", "all_iats",
        "flags_seen", "fwd_syn", "fwd_fin", "fwd_rst", "fwd_psh", "fwd_ack",
        "fwd_urg", "bwd_syn", "bwd_fin", "bwd_rst", "bwd_psh", "bwd_ack",
        "bwd_urg", "init_win_fwd", "init_win_bwd",
        "fwd_last_ts", "bwd_last_ts", "_owner_key",
    )

    def __init__(self, pkt: PacketMeta):
        self.proto = pkt.proto_name
        self.src, self.sport = pkt.src, pkt.sport
        self.dst, self.dport = pkt.dst, pkt.dport
        self.t_first = pkt.ts
        self.t_last = pkt.ts
        self.fwd_pkts = self.bwd_pkts = 0
        self.fwd_bytes = self.bwd_bytes = 0
        self.fwd_hdr_bytes = self.bwd_hdr_bytes = 0
        self.fwd_sizes: Deque[int] = deque(maxlen=64)
        self.bwd_sizes: Deque[int] = deque(maxlen=64)
        self.fwd_iats: Deque[float] = deque(maxlen=64)
        self.bwd_iats: Deque[float] = deque(maxlen=64)
        self.all_iats: Deque[float] = deque(maxlen=128)
        self.flags_seen = set()
        self.fwd_last_ts: Optional[float] = None
        self.bwd_last_ts: Optional[float] = None
        self.init_win_fwd: Optional[int] = None
        self.init_win_bwd: Optional[int] = None
        # direction 'fwd' = src->dst as first observed (the initiating side).
        self._owner_key = pkt.flow_key()
        for name in ("fwd_syn", "fwd_fin", "fwd_rst", "fwd_psh", "fwd_ack",
                     "fwd_urg", "bwd_syn", "bwd_fin", "bwd_rst", "bwd_psh",
                     "bwd_ack", "bwd_urg"):
            setattr(self, name, 0)

    def is_owner(self, pkt: PacketMeta) -> bool:
        return pkt.flow_key() == self._owner_key

    def update(self, pkt: PacketMeta) -> None:
        """Absorb a packet: `fwd` = first-seen direction, `bwd` = the other."""
        # NOTE: capture direction is 'in' for most lab/attack traffic; the
        # initiating socket (owner key) is 'fwd'.
        from_direction_fwd = (pkt.src == self.src and pkt.sport == self.sport
                              and pkt.dst == self.dst and pkt.dport == self.dport)
        delta_ts = max(0.0, pkt.ts - self.t_last)
        self.flags_seen.update({pkt.proto_name})
        pkt_finalize_forward = from_direction_fwd
        if pkt_finalize_forward:
            if self.t_first != pkt.ts:
                self.fwd_iats.append(delta_ts)
            self.all_iats.append(delta_ts)
            if pkt.tcp is not None and self.init_win_fwd is None and pkt.tcp.syn:
                self.init_win_fwd = pkt.tcp.window
            for flag, counter in ((SYN, "fwd_syn"), (FIN, "fwd_fin"),
                                  (RST, "fwd_rst"), (PSH, "fwd_psh"),
                                  (ACK, "fwd_ack"), (URG, "fwd_urg")):
                if pkt.tcp is not None and pkt.tcp.flags & flag:
                    setattr(self, counter, getattr(self, counter) + 1)
            self.fwd_pkts += 1
            self.fwd_bytes += pkt.payload_len
            self.fwd_hdr_bytes += (pkt.tcp.data_offset
                                   if pkt.tcp else 8)
            self.fwd_sizes.append(pkt.payload_len)
            self.fwd_last_ts = pkt.ts
        else:
            if self.t_first != pkt.ts:
                self.bwd_iats.append(delta_ts)
            self.all_iats.append(delta_ts)
            if pkt.tcp is not None and self.init_win_bwd is None and pkt.tcp.syn:
                self.init_win_bwd = pkt.tcp.window
            for flag, counter in ((SYN, "bwd_syn"), (FIN, "bwd_fin"),
                                  (RST, "bwd_rst"), (PSH, "bwd_psh"),
                                  (ACK, "bwd_ack"), (URG, "bwd_urg")):
                if pkt.tcp is not None and pkt.tcp.flags & flag:
                    setattr(self, counter, getattr(self, counter) + 1)
            self.bwd_pkts += 1
            self.bwd_bytes += pkt.payload_len
            self.bwd_hdr_bytes += pkt.tcp.data_offset if pkt.tcp else 8
            self.bwd_sizes.append(pkt.payload_len)
            self.bwd_last_ts = pkt.ts
        self.t_last = pkt.ts


class SourceState:
    """Per-source state for behaviour detectors (scan fan-out, rates)."""

    def __init__(self):
        self.new_syn_ports_events: Deque[Tuple[float, Tuple[str, int]]] = deque()
        self.udp_dst_ports: Deque[Tuple[float, Tuple[str, int]]] = deque()
        self.conn_attempts: Deque[Tuple[float, Tuple[str, int]]] = deque()
        self.last_seen = time.monotonic()


class FlowTable:
    """Thread-safe table: (proto,sip,sport,dip,dport) -> FlowRow."""

    def __init__(self, flow_ttl_s: float = DEFAULT_FLOW_TTL_S,
                 source_ttl_s: float = SOURCE_TTL_S):
        self.flows: Dict[tuple, FlowRow] = {}
        self.sources: Dict[str, SourceState] = {}
        self.flow_ttl_s = flow_ttl_s
        self.source_ttl_s = source_ttl_s
        self._lock = threading.RLock()

    # -- packet absorption -----------------------------------------------------
    def update(self, pkt: PacketMeta, *_args) -> FlowRow:
        """Record a packet; returns (flow_row, source_state, is_new_flow)."""
        with self._lock:
            fwd_key = pkt.flow_key()
            rev_key = (pkt.proto, pkt.dst, pkt.dport, pkt.src, pkt.sport)
            row = self.flows.get(fwd_key)
            is_new = row is None
            if is_new:
                # Check if the reverse direction already has a flow
                row = self.flows.get(rev_key)
                if row is not None:
                    # This is a response packet for an existing flow;
                    # route it as backward traffic.
                    is_new = False
                    row.update(pkt)
                else:
                    row = FlowRow(pkt)
                    self.flows[fwd_key] = row
                    # Count the first packet immediately (was previously
                    # skipped, leaving all 1-packet flows with 0 counts).
                    row.update(pkt)
            else:
                row.update(pkt)
            src = self.sources.get(pkt.src)
            if src is None:
                src = self.sources[pkt.src] = SourceState()
            # new SYN -> record a distinct port fan-out event (scan detector);
            # the same port repeated (SYN retrans / flood) is excluded here: the
            # flood detector counts SYNs separately.
            if pkt.tcp is not None and pkt.tcp.syn and is_new:
                src.new_syn_ports_events.append((pkt.ts, (pkt.proto_name, pkt.dport)))
                if len(src.new_syn_ports_events) > 4096:
                    src.new_syn_ports_events.popleft()
            elif pkt.udp is not None and is_new:
                src.udp_dst_ports.append((pkt.ts, (pkt.proto_name, pkt.dport)))
                if len(src.udp_dst_ports) > 4096:
                    src.udp_dst_ports.popleft()
            src.last_seen = time.monotonic()
            return row

    def source(self, src: str) -> SourceState:
        with self._lock:
            return self.sources.setdefault(src, SourceState())

    # -- housekeeping -----------------------------------------------------------
    def prune(self, now_monotonic: Optional[float] = None) -> None:
        with self._lock:
            now = now_monotonic or time.monotonic()
            stale = [k for k, row in self.flows.items()
                     if now - row.t_last > self.flow_ttl_s]
            for k in stale:
                self.flows.pop(k, None)
            dead = [s for s, state in self.sources.items()
                    if now - state.last_seen > self.source_ttl_s]
            for s in dead:
                self.sources.pop(s, None)

    def __len__(self) -> int:
        with self._lock:
            return len(self.flows)
