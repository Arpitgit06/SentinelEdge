"""Per-process attribution (stretch goal).

Best-effort map of local sockets -> owning process via psutil. In inbound-only
mode this identifies the local service a hostile packet was addressed to
(e.g. "your text editor tried to listen on 0.0.0.0:55555"). The full
'must-never-talk' outbound policy needs an outbound capture mode — see
config.attribution and docs/architecture.md.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, Optional, Tuple


class ProcessMap:
    """Refreshes every `interval` seconds: {(laddr, port)} -> (pid, name)."""

    def __init__(self, interval_s: float = 5.0):
        self.interval_s = interval_s
        self._lock = threading.Lock()
        self._map: Dict[Tuple[str, int], Dict[str, Any]] = {}
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        def worker() -> None:
            self.refresh()
            while not self._stop.wait(self.interval_s):
                try:
                    self.refresh()
                except Exception:               # noqa: BLE001
                    pass
        self._thread = threading.Thread(target=worker, name="sentinel-procmap",
                                        daemon=True)
        self._thread.start()

    def refresh(self) -> None:
        try:
            import psutil
        except ImportError:
            return
        fresh: Dict[Tuple[str, int], Dict[str, Any]] = {}
        try:
            for conn in psutil.net_connections(kind="tcp"):
                laddr = (conn.laddr.ip, conn.laddr.port) if conn.laddr else None
                if not laddr:
                    continue
                pid = conn.pid
                name = None
                if pid:
                    try:
                        proc = psutil.Process(pid)
                        name = proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                fresh[laddr] = {"pid": pid, "name": name}
        except Exception:                       # noqa: BLE001 — restricted OS perms
            pass
        # UDP pass (listen sockets matter for decoys too)
        try:
            for conn in psutil.net_connections(kind="udp"):
                laddr = (conn.laddr.ip, conn.laddr.port) if conn.laddr else None
                if not laddr:
                    continue
                pid = conn.pid
                name = None
                if pid:
                    try:
                        name = psutil.Process(pid).name()
                    except Exception:           # noqa: BLE001
                        pass
                fresh.setdefault(laddr, {"pid": pid, "name": name})
        except Exception:                       # noqa: BLE001
            pass
        with self._lock:
            self._map = fresh

    def owning_process(self, ip: str, port: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._map.get((ip, int(port)))

    def stop(self) -> None:
        self._stop.set()


def describe_owner(owner: Optional[Dict[str, Any]]) -> str:
    if not owner:
        return "unknown owner"
    name = owner.get("name")
    pid = owner.get("pid")
    if name and pid:
        return f"{name} (pid {pid})"
    if name:
        return str(name)
    return f"pid {pid}" if pid is not None else "unknown owner"
