"""Reputation stage — Stage 1 in the pipeline.

Pure microseconds per packet: one Bloom lookup (fast negative always decisive),
then exact / CIDR confirmation, plus a blocklist check over DNS query names.

The owner's own (trusted) subnets are exempt: bogon feeds list RFC1918, and a
LAN-facing firewall must never reputation-block its owner.
"""

from __future__ import annotations

import ipaddress
from typing import List, Optional, Tuple

from .base import Stage, StageResult, VERDICT_BLOCK
from ..packets import PacketMeta


def _subnet_converter(subnets: List[str]):
    nets = []
    for s in subnets or ():
        try:
            nets.append(ipaddress.ip_network(s, strict=False))
        except ValueError:
            pass
    return nets


class ReputationStage(Stage):
    name = "reputation"
    order = 10

    def __init__(self, config, store=None):
        super().__init__(config)
        self.store = store
        self._trusted = _subnet_converter(getattr(config, "trusted_subnets",
                                                  []))

    def _trusted_src(self, ip: str) -> bool:
        if not self._trusted:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._trusted)

    def inspect(self, pkt: PacketMeta, ctx) -> Optional[StageResult]:
        if self.store is None:
            return None
        # 0. owner's own subnets skip reputation entirely
        if self._trusted_src(pkt.src):
            return None
        # 1. source IP against the known-bad lists
        bad, source_label = self.store.contains_ip(pkt.src)
        if bad:
            return StageResult(
                stage=self.name, verdict=VERDICT_BLOCK,
                reason=f"Source IP is {source_label}",
                evidence={"src": pkt.src, "list": source_label},
                score=1.0)
        # 2. DNS reputation: any queried name on the domain blocklist?
        if pkt.dns is not None and pkt.dns.queries:
            for qname in pkt.dns.queries:
                bad_dom, dom_label = self.store.contains_domain(qname)
                if bad_dom:
                    return StageResult(
                        stage=self.name, verdict=VERDICT_BLOCK,
                        reason=f"DNS query to {dom_label} domain",
                        evidence={"qname": qname, "list": dom_label},
                        score=1.0)
        return None
