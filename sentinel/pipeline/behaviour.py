"""Behaviour stage: port-scan detection, floods, rate limiting, brute force.

Order in the pipeline: 40. Stateful, windowed detectors over the shared flow
table's per-source fan-out data:

  * Port scan: >= N distinct *new-connection* destination ports within a
    window from one source (catches nmap SYN/UDP scans AND low-and-slow
    variants because the window keeps recent history).
  * SYN flood: >= R SYNs/s towards one service.
  * ICMP flood: >= R ICMP/s (and syn-flood-like repeated attempts for TCP).
  * Brute force: >= N connection attempts to SSH/FTP/RDP-class ports within
    the bruteforce window (hydra, repeated ssh logins).
  * Connection-rate limit: generic per-source attempts/s cap.
"""

from __future__ import annotations

import time
from collections import deque
from typing import Deque, List, Optional, Tuple

from .base import Stage, StageResult, VERDICT_BLOCK, VERDICT_ALERT
from ..packets import PacketMeta, PROTO_TCP, PROTO_UDP, PROTO_ICMP, SYN, ACK


def _prune(deq: Deque[Tuple[float, object]], window_s: float, now_ts: float
           ) -> List[Tuple[float, object]]:
    """Filter to the window WITHOUT mutating (several detectors share rings
    with different window sizes; a mutating prune would corrupt other views).
    """
    cutoff = now_ts - window_s
    return [entry for entry in deq if entry[0] >= cutoff]


def _prune_floats(deq: Deque[float], window_s: float, now_ts: float
                  ) -> Deque[float]:
    """Drop scalar timestamps older than window (single-owner rings)."""
    cutoff = now_ts - window_s
    while deq and deq[0] < cutoff:
        deq.popleft()
    return deq


class BehaviourStage(Stage):
    name = "behaviour"
    order = 40

    def __init__(self, config):
        super().__init__(config)
        cfg = config
        self.scan_window = cfg.scan_window_s
        self.scan_ports = cfg.scan_distinct_ports
        self.flood_window = cfg.flood_window_s
        self.syn_flood_rate = cfg.syn_flood_rate
        self.icmp_flood_rate = cfg.icmp_flood_rate
        self.bruteforce_window = cfg.bruteforce_window_s
        self.bruteforce_attempts = cfg.bruteforce_attempts
        self.bruteforce_ports = set(cfg.bruteforce_ports)
        self.conn_rate_limit = cfg.conn_rate_limit
        # per-source SYN-describing ring for flood counting
        self._syn_ring: dict = {}
        self._icmp_ring: dict = {}
        self._conn_ring: dict = {}
        self._ring_cap = 4096                    # per-dict source cap

    def _sweep_ring_dict(self, d: dict, now_ts: float) -> None:
        """Evict stale per-source keys so source-rotation floods cannot
        grow these dicts without bound (keys pruned here are those whose
        ring emptied for the active window or stayed idle)."""
        if len(d) <= self._ring_cap:
            return
        cutoff = now_ts - max(self.flood_window, self.bruteforce_window) \
            * 2.0
        for key in list(d):
            ring = d[key]
            if not ring or ring[-1] < cutoff:
                del d[key]

    def inspect(self, pkt: PacketMeta, ctx) -> Optional[StageResult]:
        ft = ctx.flow_table
        if ft is None:
            return None
        source = ft.source(pkt.src)
        now_ts = pkt.ts

        # ---- connections / floods bookkeeping --------------------------------
        if (pkt.proto == PROTO_TCP and pkt.tcp is not None
                and pkt.tcp.syn and not pkt.tcp.ack):
            ring = self._syn_ring.setdefault(pkt.src, deque())
            if len(self._syn_ring) > self._ring_cap:
                self._sweep_ring_dict(self._syn_ring, now_ts)
        elif pkt.proto == PROTO_ICMP:
            ring = self._icmp_ring.setdefault(pkt.src, deque())
            if len(self._icmp_ring) > self._ring_cap:
                self._sweep_ring_dict(self._icmp_ring, now_ts)
        else:
            ring = None

        if ring is not None:
            ring.append(now_ts)
            _prune_floats(ring, self.flood_window, now_ts)
            if ring and len(ring) >= 15:
                span = max(1e-6, now_ts - ring[0])
                if span >= 0.25:
                    rate = len(ring) / span
                    if pkt.proto == PROTO_TCP and rate > self.syn_flood_rate:
                        return self._fire(
                            "SYN flood from {src} ({rate:.0f} SYNs/s towards "
                            "{dst}:{port})", pkt, rate,
                            {"rate_syn_per_s": round(rate, 1)})
                    if pkt.proto == PROTO_ICMP and rate > self.icmp_flood_rate:
                        return self._fire(
                            "ICMP flood from {src} ({rate:.0f} packets/s)",
                            pkt, rate, {"rate_icmp_per_s": round(rate, 1)})

        # ---- connection-rate limit (any proto) ---------------------------------
        if (pkt.dport is not None and pkt.tcp is not None
                and pkt.tcp.syn and not pkt.tcp.ack):
            conn_ring = self._conn_ring.setdefault(pkt.src, deque())
            conn_ring.append(now_ts)
            if len(self._conn_ring) > self._ring_cap:
                self._sweep_ring_dict(self._conn_ring, now_ts)
            _prune_floats(conn_ring, self.flood_window, now_ts)
            if len(conn_ring) >= 3:                  # need volume for a real rate
                span = max(1e-6, now_ts - conn_ring[0])
                rate = len(conn_ring) / span
                if rate > self.conn_rate_limit:
                    return self._fire(
                        "Connection-rate limit exceeded from {src} "
                        "({rate:.0f} new connections/s)", pkt, rate,
                        {"conn_rate_per_s": round(rate, 1)})

        # ---- overall port scan fan-out -------------------------------------------
        distinct = set()
        for ts, (_proto, port) in _prune(source.new_syn_ports_events,
                                         self.scan_window, now_ts):
            distinct.add(port)
        for ts, (_proto, port) in _prune(source.udp_dst_ports,
                                         self.scan_window, now_ts):
            distinct.add(port)
        if len(distinct) >= self.scan_ports:
            ev_src = source.new_syn_ports_events or source.udp_dst_ports
            first_ts = ev_src[0][0] if ev_src else now_ts
            window_s = max(1e-6, now_ts - first_ts)
            return self._fire(
                "Port scan detected: {ports} distinct ports probed in "
                "{window:.1f}s", pkt, len(distinct),
                {"distinct_ports": sorted(distinct)[:32],
                 "distinct_ports_count": len(distinct),
                 "window_s": round(window_s, 2)})

        # ---- brute-force accumulation to login services ----------------------------
        if (pkt.proto == PROTO_TCP and pkt.tcp is not None
                and pkt.tcp.syn and not pkt.tcp.ack
                and pkt.dport in self.bruteforce_ports):
            matched = [(ts, port) for ts, (_proto, port)
                       in _prune(source.new_syn_ports_events,
                                 self.bruteforce_window, now_ts)]
            same_service = [t for t in matched if t[1] == pkt.dport]
            if len(same_service) >= self.bruteforce_attempts:
                return self._fire(
                    "Brute-force pattern: {attempts} repeated connection "
                    "attempts to port {port} (login service) within "
                    "{window:.1f}s", pkt, len(same_service),
                    {"attempts": len(same_service), "port": pkt.dport,
                     "window_s": self.bruteforce_window},
                    severity="bruteforce")
        return None

    # -- shared results -------------------------------------------------------
    def _fire(self, template: str, pkt: PacketMeta, score: float,
              evidence: Optional[dict] = None, severity: str = "scan"
              ) -> StageResult:
        reason = template.format(src=pkt.src, dst=pkt.dst, port=pkt.dport,
                                 rate=score,
                                 ports=(evidence or {}).get(
                                     "distinct_ports_count",
                                     (evidence or {}).get("attempts", 0)) or 0,
                                 window=float((evidence or {}).get("window_s", 0.0)),
                                 attempts=(evidence or {}).get("attempts", 0))
        return StageResult(stage=self.name, verdict=VERDICT_BLOCK,
                           reason=reason,
                           evidence={"detector": severity,
                                     **(evidence or {})},
                           score=min(1.0, score / 100.0))
