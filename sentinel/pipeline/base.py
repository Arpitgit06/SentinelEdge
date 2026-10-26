"""Pipeline stage contracts.

Stage: inspect() receives every inbound packet plus a context (flow table,
config, shared state) and returns None ("no hard verdict, continue") or a
StageResult. Verdicts:
    * block      -> decision engine drops the packet
    * alert      -> packet passes but the owner is alerted (e.g. NULL scan)
Any exception inside a stage is caught by the engine and results in
fail-open behaviour (packet forwarded).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:                      # avoid import cycles
    from sentinel.packets import PacketMeta
    from sentinel.flows.flow_table import FlowTable

VERDICT_BLOCK = "block"
VERDICT_ALERT = "alert"


@dataclass
class StageResult:
    stage: str
    verdict: str                        # 'block' | 'alert'
    reason: str                         # short, machine-readable
    evidence: Dict[str, Any] = field(default_factory=dict)
    score: float = 0.0                  # confidence 0..1 where applicable


@dataclass
class InspectionContext:
    """Everything a stage may need beyond the packet itself."""
    flow_table: Optional["FlowTable"] = None
    config: Any = None
    shared: Dict[str, Any] = field(default_factory=dict)   # runtime state (honeypot hits, allowlist...)


class Stage(ABC):
    """One detection stage in the ordered pipeline."""

    name: str = "stage"
    order: int = 0                      # lower runs earlier

    def __init__(self, config: Any):
        self.config = config

    @abstractmethod
    def inspect(self, pkt: "PacketMeta", ctx: InspectionContext
                ) -> Optional[StageResult]:
        ...
