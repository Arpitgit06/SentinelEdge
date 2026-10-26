"""Passive capture driver (Scapy / Npcap sniffing) — logged verdicts only.

Used for lab runs without admin where WinDivert isn't wanted, and by the
red-team replay harness. Blocking is simulated: the driver never drops real
traffic, it just records what the decision engine *would* do.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, Optional

from .base import EnforcementDriver

log = logging.getLogger(__name__)


class PassiveDriver(EnforcementDriver):
    name = "passive"

    def __init__(self, config, engine_view: Callable[[Any], Any],
                 iface: Optional[str] = None,
                 bpf: str = "tcp or udp or icmp"):
        self.config = config
        self.engine_view = engine_view
        self.iface = iface
        self.bpf = bpf
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._exception: Optional[BaseException] = None

    def start(self) -> None:
        from scapy.all import sniff  # local import keeps startup light

        def _worker() -> None:
            try:
                sniff(iface=self.iface, filter=self.bpf,
                      prn=self._on_packet, stop_filter=lambda _x:
                      self._stop.is_set())
            except (KeyboardInterrupt, SystemExit):
                pass
            except Exception as exc:                # noqa: BLE001
                self._exception = exc
                log.exception("passive capture failed: %s", exc)

        self._thread = threading.Thread(target=_worker,
                                        name="sentinel-passive", daemon=True)
        self._thread.start()

    def _on_packet(self, scapy_pkt: Any) -> None:
        from sentinel.packets import parse_ip
        try:
            from scapy.compat import raw as scapy_raw
            buf = bytes(scapy_raw(scapy_pkt))
        except Exception:                           # noqa: BLE001
            return
        # scapy gives full frames (L2); parse_ip wants the IP body
        start = self._ip_offset(buf)
        meta = parse_ip(buf[start:], ts=time.time(), direction="in")
        if meta is not None:
            meta.raw = buf[start:]
            self.engine_view(meta)

    @staticmethod
    def _ip_offset(buf: bytes) -> int:
        """Strip the ethernet heuristically: look for 0x4x / 0x6x IPvx start."""
        if len(buf) >= 14 and buf[12:14] == b"\x08\x00":
            return 14
        if len(buf) >= 18 and buf[16:18] == b"\x86\xdd":
            return 18
        if len(buf) >= 14 and buf[12:14] == b"\x86\xdd":
            return 14
        return 0

    def stop(self) -> None:
        self._stop.set()

    def is_active(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def error(self) -> Optional[BaseException]:
        return self._exception
