"""Signature stage: Aho-Corasick multi-pattern matching + rule engine.

Order in the pipeline: 2 (after reputation). Scans transport payloads for
compiled literal patterns; each match's owning rule decides drop/alert, bound
by protocol and destination port so ordinary traffic on other services is
never inspected unnecessarily.

NOTE: we do not need PyYAML in the hot path—the rules file is compiled once
at engine start (sentinel.rules.loader).
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Iterable

from .base import Stage, StageResult, VERDICT_BLOCK, VERDICT_ALERT, InspectionContext
from ..packets import PacketMeta, PROTO_TCP, PROTO_UDP, PROTO_ICMP
from sentinel.rules.loader import PayloadRule, CompiledRules, load_compiled

import os

_PROTO_NUM = {"tcp": PROTO_TCP, "udp": PROTO_UDP, "icmp": PROTO_ICMP}


def _payload_of(pkt: PacketMeta, proto: str) -> Optional[bytes]:
    if proto == "tcp":
        return pkt.tcp.payload if pkt.tcp else None
    if proto == "udp":
        return pkt.udp.payload if pkt.udp else None
    if proto == "icmp":
        return pkt.icmp.payload if pkt.icmp else None
    return None


def _port_of(pkt: PacketMeta, proto: str) -> Optional[int]:
    if proto == "tcp":
        return pkt.tcp.dport if pkt.tcp else None
    if proto == "udp":
        return pkt.udp.dport if pkt.udp else None
    return None


class SignatureStage(Stage):
    name = "signatures"
    order = 20

    def __init__(self, config, rules_path: Optional[Path] = None):
        super().__init__(config)
        path = rules_path or getattr(config, "rules_file", None)
        self.rules, self.compiled = load_compiled(path or Path(
            __file__).resolve().parent.parent / "rules" / "default_rules.yaml")
        self.automaton = self.compiled.automaton

    # -- inspection ------------------------------------------------------------
    def inspect(self, pkt: PacketMeta, ctx) -> Optional[StageResult]:
        if self.automaton is None and not self.compiled.fallback_re:
            return None
        for proto_filter in ("tcp", "udp", "icmp", "any"):
            pass
        matches = self._scan(pkt)
        if not matches:
            return None
        best = self._rank(matches)
        return best

    # -- internals ---------------------------------------------------------
    def _scan(self, pkt: PacketMeta):
        """Collect (payload_rule, needle) matches valid for this packet."""
        out: list = []
        automaton = self.automaton
        proto = pkt.proto_name
        payload = _payload_of(pkt, proto)
        if payload:
            # latin-1 keeps a 1:1 byte<->codepoint mapping, safe for binary
            text = payload.decode("latin-1", errors="replace")
            target_port = _port_of(pkt, proto)
            lower = text.lower()

            def _protocol_ok(rule: PayloadRule) -> bool:
                if rule.proto not in (proto, "any"):
                    return False
                if not rule.any_port:
                    if target_port is None or target_port not in rule.dst_ports:
                        return False
                return True

            # pass 1: case-insensitive needles against the lowered text
            if automaton is not None:
                for _, (needle, _meta) in automaton.iter(lower):
                    for rule in _meta:
                        if rule.case_sensitive:        # needs original case
                            continue
                        if not _protocol_ok(rule):
                            continue
                        if needle in lower:
                            out.append((rule, needle))
                # pass 2: case-sensitive needles against the original text
                for _, (needle, _meta) in automaton.iter(text):
                    for rule in _meta:
                        if not rule.case_sensitive:
                            continue
                        if not _protocol_ok(rule):
                            continue
                        if needle in text:
                            out.append((rule, needle))
            else:
                for pattern, rules in self.compiled.fallback_re:
                    for rule in rules:
                        if not _protocol_ok(rule):
                            continue
                        hay = text if rule.case_sensitive else text.lower()
                        if pattern.search(hay):
                            out.append((rule, str(pattern.pattern)[:32]))
        return out

    def _rank(self, matches):
        """Drop-wins ordering, then by severity."""
        severity_rank = {"high": 3, "medium": 2, "low": 1}
        matches = sorted(matches,
                         key=lambda m: (0 if m[0].action == "drop" else 1,
                                        -severity_rank.get(m[0].severity, 0)))
        rule, needle = matches[0]
        verdict = VERDICT_BLOCK if rule.action == "drop" else VERDICT_ALERT
        return StageResult(
            stage=self.name,
            verdict=verdict,
            reason=rule.msg or f"signature match {rule.rule_id}",
            evidence={
                "rule_id": rule.rule_id,
                "matched": needle.replace("\x00", "")[:64],
                "severity": rule.severity,
                "proto": rule.proto,
            },
            score={"high": 0.9, "medium": 0.7, "low": 0.4}.get(rule.severity, 0.5),
        )
