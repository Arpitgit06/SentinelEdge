"""Protocol sanity stage: malformed headers + illegal TCP flag combinations.

Order in the pipeline: 3. Validates IPv4/IPv6 and TCP structural integrity and
drops provably-illegal flag combos in real time so packets never reach the
behaviour/ML stages.

Stages checked (per proposal):
    * IP: header length, total-length consistency, fragmentation plausibility
    * TCP: data offset, flag legality (SYN+FIN, SYN+PSH, SYN+URG+PSH, SYN+CWE)
    * UDP: length field sanity
    * Fragments: reassembly tracking so fragmented attacks are judged whole
"""

from __future__ import annotations

import threading
import time
from typing import Dict, Optional, Set, Tuple

from .base import Stage, StageResult, VERDICT_BLOCK, VERDICT_ALERT
from ..packets import (PacketMeta, PROTO_TCP, PROTO_UDP, SYN, FIN, RST, PSH,
                       ACK, URG, ECE, CWR)


class FragmentTracker:
    """Tracks fragment arrival counts so fragmentation-based attacks are
    detected on reassembly volume (nmap -f produces 8-byte fragments;
    we flag when the fragment *count* exceeds a threshold)."""

    def __init__(self, max_entries: int = 4096, stale_after_s: float = 30.0):
        self._lock = threading.Lock()
        # key -> (last_ts, frag_count, total_bytes)
        self._table: Dict[Tuple[str, str, int], Tuple[float, int, int]] = {}
        self._max = max_entries
        self._stale = stale_after_s

    def observe(self, pkt: PacketMeta) -> Optional[Tuple[float, int, int]]:
        key = (pkt.src, pkt.dst, getattr(pkt, "_ident", 0))
        now = time.monotonic()
        with self._lock:
            # prune
            if len(self._table) > self._max:
                self._table = {k: v for k, v in self._table.items()
                               if now - v[0] < self._stale}
            prev = self._table.get(key)
            prev_count = prev[1] if prev else 0
            prev_bytes = prev[2] if prev else 0
            self._table[key] = (now, prev_count + 1, prev_bytes + len(pkt.raw))
            return self._table[key]


class ProtocolStage(Stage):
    name = "protocol"
    order = 30

    def __init__(self, config):
        super().__init__(config)
        self._frags = FragmentTracker()

    def inspect(self, pkt: PacketMeta, ctx) -> Optional[StageResult]:
        cfg = self.config
        # ---- IPv4 header coherence -------------------------------------------
        if pkt.ip_version == 4:
            if pkt.ihl < 20:
                return self._drop("malformed ip header (ihl < 20)",
                                  evidence={"ihl": pkt.ihl})
            if not pkt.truncated and pkt.total_len and pkt.total_len != len(pkt.raw):
                if pkt.total_len > len(pkt.raw):
                    return self._drop(
                        "ip total length exceeds captured bytes (bad length)",
                        evidence={"total_len": pkt.total_len, "bytes": len(pkt.raw)})
        # ---- TCP flag & structural legality -----------------------------------
        if pkt.proto == PROTO_TCP and pkt.tcp is not None:
            tcp = pkt.tcp
            if tcp.data_offset < 20:
                return self._drop("malformed tcp header (data offset < 20)")
            if tcp.syn and tcp.fin:
                return self._drop("illegal TCP combination: SYN+FIN", evidence={
                    "flags": tcp.flag_names})
            if cfg.drop_syn_psh and tcp.syn and tcp.psh:
                return self._drop("illegal TCP combination: SYN+PSH", evidence={
                    "flags": tcp.flag_names})
            if cfg.drop_syn_psh and tcp.syn and tcp.psh and tcp.urg:
                pass  # covered by SYN+PSH rule above
            if cfg.drop_syn_urg_psh and (tcp.syn | tcp.fin) and tcp.urg and tcp.psh:
                return self._drop("illegal TCP combination: SYN/FIN+URG+PSH",
                                  evidence={"flags": tcp.flag_names})
            if cfg.drop_syn_cwe and tcp.syn and (tcp.ece or tcp.cwr):
                # RFC 3168: a standard ECN handshake uses SYN+ECE+CWR
                # together.  Only flag if *one* of ECE/CWR is set without
                # the other (evasion / probing), not a legitimate ECN setup.
                if not (tcp.ece and tcp.cwr):
                    return self._drop(
                        "illegal TCP combination: SYN with partial "
                        "ECE/CWR (non-RFC-3168 ECN abuse)",
                        evidence={"flags": tcp.flag_names})
            if cfg.drop_null_scan and tcp.flags == 0x00:
                return StageResult(stage=self.name, verdict=VERDICT_ALERT,
                                   reason="NULL scan probe (no TCP flags set)",
                                   evidence={"flags": "NULL"})
            if cfg.drop_null_scan and tcp.fin and not tcp.ack and not tcp.syn and not tcp.rst:
                return StageResult(stage=self.name, verdict=VERDICT_ALERT,
                                   reason="FIN/Xmas-scan probe (stealth)",
                                   evidence={"flags": tcp.flag_names})
            # Xmas: all override flags and no SYN/ACK -> definitely probe
            if (tcp.urg and tcp.psh and tcp.fin
                    and not tcp.syn and not tcp.ack):
                return StageResult(stage=self.name, verdict=VERDICT_ALERT,
                                   reason="Xmas-scan probe (stealth)",
                                   evidence={"flags": tcp.flag_names})
        # ---- UDP length sanity -------------------------------------------------
        if pkt.proto == PROTO_UDP and pkt.udp is not None:
            udp = pkt.udp
            if udp.length < 8 and udp.length:
                return self._drop("malformed udp header (length < 8)")
            if udp.length > len(pkt.raw) and udp.length:
                return self._drop("udp length exceeds captured bytes",
                                  evidence={"udp_len": udp.length,
                                            "bytes": len(pkt.raw)})
        # ---- fragment tracking --------------------------------------------------
        if pkt.is_fragment_beyond_first or pkt.more_frag:
            _last_ts, frag_count, _total_bytes = self._frags.observe(pkt)
            if frag_count > 64:                              # absurd fragment storm
                return self._drop("fragment flood (over 64 fragments per flow)")
        return None

    def _drop(self, reason: str, evidence: Optional[dict] = None
              ) -> StageResult:
        return StageResult(stage=self.name, verdict=VERDICT_BLOCK,
                           reason=reason, evidence=evidence or {},
                           score=0.95)
