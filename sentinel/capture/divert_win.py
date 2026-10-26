"""Windows enforcement via WinDivert (pydivert).

   * Filter pre-excludes loopback / DHCP / DNS traffic (config.capture).
   * For every captured inbound packet the engine decides: reinject = allow,
     skip reinject = block. WinDivert blocks simply by not re-injecting.
   * Fail-open: an engine exception triggers reinject; a stalled loop is
     detected by the watchdog and the handle closes — WinDivert then
     re-injects everything it held, so the owner is never locked out.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, Optional

from .base import EnforcementDriver

log = logging.getLogger(__name__)


class WinDivertDriver(EnforcementDriver):
    name = "win-divert"

    def __init__(self, config, engine_view: Callable[[Any], Any]):
        """engine_view: fn(PacketMeta) -> Verdict  (engine.inspect)."""
        self.config = config
        self.engine_view = engine_view
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._handle: Any = None
        self.last_packet_tick = time.monotonic()
        self.last_resp_tick = time.monotonic()   # recv answered (or timed out)
        self.watchdog = None
        self.packets_seen = 0
        self._exception: Optional[BaseException] = None

    # -- lifecycle -------------------------------------------------------------
    def start(self) -> None:
        import pydivert  # deferred so the rest of the app runs without it

        filt = self._driver_filter()
        log.info("WinDivert starting with filter: %s", filt)
        self._handle = pydivert.WinDivert(filt)
        self._handle.open()
        if not getattr(self._handle, "is_open", True):
            raise RuntimeError("WinDivert handle did not open")
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="sentinel-divert-loop", daemon=True)
        self._thread.start()
        self.watchdog = threading.Thread(
            target=self._watchdog, name="sentinel-watchdog", daemon=True)
        self.watchdog.start()

    def _driver_filter(self) -> str:
        """Capture filter (WinDivert 1.x syntax: no unary NOT)."""
        base = self.config.capture.windivert_filter
        if self.config.capture.bypass_dns_dhcp_in_filter:
            # Expressed with `!=` only: WinDivert 1.x rejects `!(...)`.
            # Leading `tcp or udp or icmp` admits every TCP/ICMP packet
            # regardless of how udp.* fields evaluate on them, so UDP
            # port 53/67 flows are the only thing filtered out.
            base = ("inbound and (tcp or udp or icmp) and "
                    "(udp.SrcPort != 53 and udp.SrcPort != 67 and "
                    "udp.DstPort != 53 and udp.DstPort != 67)")
        return base

    def _loop(self) -> None:
        """Main loop: recv -> parse -> engine verdict -> reinject or drop.

        recv uses a 1 s timeout so an idle network cannot starve the watchdog
        signal: every answered recv (packet OR TimeoutError) proves the loop
        is responsive; only a genuinely wedged native wait stays silent.
        """
        from sentinel.packets import parse_ip
        from sentinel.pipeline.engine import Verdict

        handle = self._handle
        try:
            while not self._stop.is_set():
                try:
                    pkt = handle.recv(timeout=1.0)
                except TimeoutError:               # idle, loop is responsive
                    self.last_resp_tick = time.monotonic()
                    continue
                self.last_packet_tick = time.monotonic()
                self.last_resp_tick = self.last_packet_tick
                try:
                    meta = self._to_meta(pkt, parse_ip)
                    if meta is None:                   # not IP: nothing to judge
                        try:
                            handle.reinject(pkt)
                        except Exception:              # noqa: BLE001
                            pass
                        continue
                    verdict: Verdict = self.engine_view(meta)
                except Exception:                       # noqa: BLE001 — fail-open
                    log.exception("engine error on packet -> fail-open reinject")
                    try:
                        handle.reinject(pkt)
                    except Exception:                   # noqa: BLE001
                        pass
                    continue
                if verdict.action == "allow":
                    try:
                        handle.reinject(pkt)
                    except Exception:                   # noqa: BLE001
                        log.exception("reinject failed")
                # blocks never re-injected; quarantines (alerts) also pass
                elif verdict.action == "quarantine":
                    try:
                        handle.reinject(pkt)
                    except Exception:                   # noqa: BLE001
                        log.exception("reinject failed (quarantine)")
        except (KeyboardInterrupt, SystemExit):
            pass
        except Exception as exc:                        # noqa: BLE001
            self._exception = exc
            log.exception("WinDivert loop crashed: %s", exc)

    def _to_meta(self, pkt: Any, parse_ip) -> Optional[Any]:
        direction = "in"
        try:
            # pydivert direction: 0 outbound, 1 inbound, +2 loopback flag
            direction = "in" if (int(getattr(pkt, "direction", 1) or 0) & 1) \
                else "out"
        except (TypeError, ValueError):
            direction = "in"
        buf = pkt.raw
        try:
            meta = parse_ip(buf, ts=time.time(), direction=direction)
        except Exception:                               # noqa: BLE001
            meta = None
        if meta is not None:
            meta.raw = buf
        return meta

    def _watchdog(self) -> None:
        """Fail-open on a wedged capture loop.

        Liveness = packets arriving OR recv answering its 1 s timeout. A
        quiet network keeps last_resp_tick fresh, so only a genuinely
        stuck recv() (neither packet nor timeout for the full window)
        triggers the fail-open handle close.
        """
        timeout = float(self.config.safety.watchdog_timeout_s)
        while not self._stop.wait(timeout=1.0):
            alive = self._thread is not None and self._thread.is_alive()
            last_liveness = max(self.last_packet_tick, self.last_resp_tick)
            if alive and time.monotonic() - last_liveness > timeout:
                # loop is alive but wedged inside recv(): close handle so the
                # OS re-injects remaining packets (fail-open), then stop.
                log.error("watchdog: capture loop unresponsive %.1fs -> "
                          "fail-open", time.monotonic() - last_liveness)
                try:
                    self._handle.close()
                except Exception:                       # noqa: BLE001
                    pass
                return

    def stop(self) -> None:
        self._stop.set()
        try:
            if self._handle:
                self._handle.close()                    # auto-reinjects pending
        except Exception:                               # noqa: BLE001
            pass

    def is_active(self) -> bool:
        return (self._thread is not None and self._thread.is_alive()
                and not self._stop.is_set())

    @property
    def error(self) -> Optional[BaseException]:
        return self._exception
