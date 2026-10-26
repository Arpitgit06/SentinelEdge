"""Enforcement driver interface + shared definitions."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Callable


class EnforcementDriver(ABC):
    """A driver produces inbound packets and applies verdicts.

    Contract:
      * start(can_view: Callable[[PacketMeta], Verdict]) — called by runner.
      * allow = reinject the packet; block = never reinject (WinDivert contract).
      * Drivers must never crash the pipeline: any fault is fail-open, packets
        are forwarded.
    """

    name: str = "driver"

    @abstractmethod
    def start(self) -> None:
        ...

    @abstractmethod
    def stop(self) -> None:
        ...

    @abstractmethod
    def is_active(self) -> bool:
        ...
