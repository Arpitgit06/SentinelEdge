"""Pipeline orchestrator + decision engine.

Runs the ordered stages over each packet, fuses verdicts into
allow / block / quarantine, enforces the safety contract and hands finished
decisions to consumers (SQLite log, OS notification, dashboard, slow lane).

Safety contract (enforced FIRST, before any detection):
    1. Loopback, DHCP, DNS traffic -> allow immediately.
    2. Allow-once entries (owner's explicit override) -> allow until expired.
    3. Fail-open: any exception inside a stage forwards the packet (unless an
       explicit verdict already existed).
The optional language model is never involved in decisions - it only explains
evidence produced by these stages afterwards (sentinel.explainer.slow_lane).
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Deque, Dict, List, Optional

from ..packets import PacketMeta
from ..flows.flow_table import FlowTable
from .base import Stage, StageResult, VERDICT_BLOCK, VERDICT_ALERT
from .reputation import ReputationStage
from .signatures import SignatureStage
from .protocol import ProtocolStage
from .behaviour import BehaviourStage
from . import flow_ml as _ml


# ---------------------------------------------------------------------------
# Verdict dataclass
# ---------------------------------------------------------------------------

@dataclass
class Verdict:
    action: str                   # 'allow' | 'block' | 'quarantine'
    reason: str = ""
    stage: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    score: float = 0.0
    packet: Optional[PacketMeta] = None
    fail_open: bool = False
    duration_ms: float = 0.0
    ts: float = 0.0
    # EventLog rowid once recorded (used by dashboard allow-once callbacks)
    event_id: Optional[int] = None
    # filled by enrichment in background worker
    intel: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = {
            "action": self.action, "reason": self.reason, "stage": self.stage,
            "evidence": self.evidence, "score": self.score,
            "ts": self.ts, "fail_open": self.fail_open,
            "duration_ms": round(self.duration_ms, 3), "event_id": self.event_id,
        }
        if self.packet is not None:
            d.update({"src": self.packet.src, "dst": self.packet.dst,
                      "src_port": self.packet.sport, "dst_port": self.packet.dport,
                      "proto": self.packet.proto_name})
        if self.intel:
            d["intel"] = self.intel
        return d


# ---------------------------------------------------------------------------
# Decision engine
# ---------------------------------------------------------------------------

class AllowOnceTable:
    """Owner overrides: drop-loop 'allow once' entries with optional TTL."""

    def __init__(self):
        self._lock = threading.Lock()
        self._entries: Dict[str, float] = {}   # ip -> expiry (0 = permanent)

    def grant(self, ip: str, ttl_seconds: float = 300.0) -> float:
        exp = 0.0 if (ttl_seconds is None or ttl_seconds <= 0) else \
            time.time() + float(ttl_seconds)
        with self._lock:
            self._entries[ip] = exp
        return exp

    def revoke(self, ip: str) -> bool:
        with self._lock:
            return self._entries.pop(ip, None) is not None

    def is_allowed(self, ip: str) -> bool:
        with self._lock:
            exp = self._entries.get(ip)
            if exp is None:
                return False
            if exp and time.time() >= exp:
                del self._entries[ip]
                return False
            return True


class DecisionEngine:
    """Owns stage execution, explicit and heuristic decision fusion."""

    STAGE_CLASSES = (ReputationStage, SignatureStage, ProtocolStage,
                     BehaviourStage, _ml.FlowMLStage)

    def __init__(self, config, flow_table: Optional[FlowTable] = None,
                 stages: Optional[List[Stage]] = None,
                 ml_model: Any = None):
        self.config = config
        self.flow_table = flow_table or FlowTable()
        self.stages = stages if stages is not None else self._build_stages(
            self.flow_table, ml_model)
        self._anomaly_model = None
        self.allow_once = AllowOnceTable()
        # runtime blocklist additions (honeypot decpts, feedback learning)
        self.runtime_block_ips = set()
        self._lock = threading.Lock()
        self._pkt_count = 0                      # drives flow-table housekeeping
        self._prune_every = 2048
        self.stats = {"seen": 0, "allowed": 0, "blocked": 0,
                      "quarantined": 0, "errors_fail_open": 0,
                      "safety_allowed": 0}
        self._recent = deque(maxlen=8192)  # recent verdicts ring for the UI
        self._subscribers: List[Callable[[Verdict], None]] = []

    # -- construction --------------------------------------------------------
    def _build_stages(self, flow_table: FlowTable, ml_model) -> List[Stage]:
        stages: List[Stage] = []
        cfg = self.config
        rep_store = getattr(self, "_rep_store", None)
        if getattr(cfg.reputation, "enabled", True):
            stages.append(ReputationStage(cfg.reputation, store=rep_store))
        if getattr(cfg.signatures, "enabled", True):
            stages.append(SignatureStage(cfg.signatures))
        if getattr(cfg.protocol, "enabled", True):
            stages.append(ProtocolStage(cfg.protocol))
        if getattr(cfg.behaviour, "enabled", True):
            stages.append(BehaviourStage(cfg.behaviour))
        if getattr(cfg.ml, "enabled", True) and ml_model is not None:
            stages.append(_ml.FlowMLStage(cfg.ml, model=ml_model))
        return stages

    def set_reputation_store(self, store) -> None:
        self._rep_store = store
        for stage in self.stages:
            if isinstance(stage, ReputationStage):
                stage.store = store
        if not any(isinstance(s, ReputationStage) for s in self.stages):
            self.stages.insert(0, ReputationStage(self.config.reputation,
                                                  store=store))
            self.stages.sort(key=lambda s: s.order)

    def set_ml_model(self, model) -> None:
        """Hot-swap the ML flow model without re-creating the engine.

        Preserves allow_once entries, runtime blocklists, and subscribers.
        """
        existing = [i for i, s in enumerate(self.stages)
                    if isinstance(s, _ml.FlowMLStage)]
        if model is None:
            for i in reversed(existing):
                del self.stages[i]
            return
        if existing:
            for i in existing:
                self.stages[i].model = model
        else:
            self.stages.append(_ml.FlowMLStage(self.config.ml, model=model))
            self.stages.sort(key=lambda s: s.order)

    def set_anomaly_model(self, model) -> None:
        """Attach (or detach) the novelty autoencoder as pipeline stage 5."""
        self._anomaly_model = model
        from .anomaly import AnomalyStage
        existing = [i for i, s in enumerate(self.stages)
                    if isinstance(s, AnomalyStage)]
        if model is None or not getattr(self.config.anomaly, "enabled", True):
            for i in reversed(existing):
                del self.stages[i]
            self._anomaly_model = None
            return
        if existing:
            for i in existing:
                self.stages[i].model = model
        else:
            self.stages.append(AnomalyStage(self.config, model=model))
            self.stages.sort(key=lambda s: s.order)

    # -- subscription (UI live stream, alerts) ---------------------------------
    def subscribe(self, callback: Callable[[Verdict], None]) -> None:
        self._subscribers.append(callback)

    def _notify(self, verdict: Verdict) -> None:
        for cb in list(self._subscribers):
            try:
                cb(verdict)
            except Exception:                          # noqa: BLE001
                pass

    # -- pipeline -------------------------------------------------------------
    @staticmethod
    def safety_allow(pkt: PacketMeta, config) -> Optional[str]:
        """Contract: loopback, DHCP, DNS always allowed. Returns reason or None."""
        s = config.safety
        if pkt.is_loopback() and s.always_allow_loopback:
            return "loopback traffic"
        if pkt.is_dhcp() and s.always_allow_dhcp:
            return "DHCP traffic"
        if pkt.is_dns() and s.always_allow_dns:
            return "DNS traffic"
        return None

    def inspect(self, pkt: PacketMeta) -> Verdict:
        t0 = time.perf_counter()
        verdict = self._inspect_inner(pkt, t0)
        verdict.duration_ms = (time.perf_counter() - t0) * 1000.0
        verdict.ts = pkt.ts if pkt.ts else time.time()
        verdict.packet = pkt
        self.stats["seen"] += 1
        self.stats[{"allow": "allowed", "block": "blocked",
                    "quarantine": "quarantined"}[verdict.action]] += 1
        self._recent.append(verdict)
        self._notify(verdict)
        return verdict

    def _inspect_inner(self, pkt: PacketMeta, t0: float) -> Verdict:
        # ---- safety contract first (never bypassed) ----------------------------
        allow_reason = self.safety_allow(pkt, self.config)
        if allow_reason:
            self.stats["safety_allowed"] += 1
            return Verdict(action="allow", reason=f"always-allowed: {allow_reason}",
                           stage="safety")
        src = pkt.src
        # ---- owner's allow-once overrides -------------------------------------
        if src and self.allow_once.is_allowed(src):
            return Verdict(action="allow", reason="owner override (allow once)",
                           stage="allow_once")
        with self._lock:
            if src and src in self.runtime_block_ips:
                return Verdict(action="block",
                               reason="source previously caught on decoy port",
                               stage="honeypot", score=1.0)
        # ---- flow table absorb (shared with behaviour + ML stages) ------------
        ctx_flow_table = self.flow_table
        try:
            ctx_flow_table.update(pkt)
        except Exception:                                # noqa: BLE001
            pass
        # periodic housekeeping: without this the per-flow rows (and their
        # deques) accumulate for the whole session let-us-run lifetime
        self._pkt_count += 1
        if self._pkt_count % self._prune_every == 0:
            try:
                ctx_flow_table.prune()
            except Exception:                            # noqa: BLE001
                pass

        from .base import InspectionContext
        ctx = InspectionContext(flow_table=ctx_flow_table, config=self.config)

        stage_verdicts: List[StageResult] = []
        blocked: Optional[StageResult] = None
        alerted: Optional[StageResult] = None
        errors = 0

        for stage in self.stages:
            try:
                result = stage.inspect(pkt, ctx)
            except Exception:                            # noqa: BLE001 — fail-open
                errors += 1
                continue
            if result is None:
                continue
            stage_verdicts.append(result)
            if result.verdict == VERDICT_BLOCK and blocked is None:
                blocked = result
            elif result.verdict == VERDICT_ALERT and alerted is None:
                alerted = result

        if errors:
            self.stats["errors_fail_open"] += errors

        # ---- fusion ----------------------------------------------------------
        if blocked is not None:
            return Verdict(action="block", reason=blocked.reason,
                           stage=blocked.stage, evidence=blocked.evidence,
                           score=blocked.score,
                           fail_open=bool(errors) and self.config.safety.fail_open)
        if alerted is not None:
            return Verdict(action="quarantine", reason=alerted.reason,
                           stage=alerted.stage, evidence=alerted.evidence,
                           score=alerted.score)
        if errors and self.config.safety.fail_open:
            return Verdict(action="allow",
                           reason=f"stage errors -> fail-open ({errors} stage(s))",
                           stage="fail_open_evidence", fail_open=True,
                           evidence={"stage_errors": errors})
        return Verdict(action="allow", reason="no detector fired", stage="decision")

    # -- runtime blocklist helpers (honeypot / feedback) ------------------------

    def block_source(self, ip: str) -> None:
        with self._lock:
            self.runtime_block_ips.add(ip)

    # -- health -----------------------------------------------------------------
    def stats_snapshot(self) -> dict:
        with self._lock:
            return dict(self.stats)
