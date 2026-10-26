"""Honeypot decoy service (stretch goal from the proposal).

Listens on otherwise-unused ports with a plausible banner. Any connection is
unsolicited by definition: recorded, alerted and blocked by the engine. Never
deploy it on ports that serve real traffic — the default port list is safe.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from collections import deque
from typing import Any, Callable, Dict, Optional

log = logging.getLogger(__name__)

# Small, honest decoy banner per port class
_BANNERS: Dict[int, bytes] = {
    21: b"220 sentinel-decoy FTP service ready\r\n",
    22: b"SSH-2.0-OpenSSH_8.4p1 sentinel-decoy\r\n",
    23: b"Welcome to sentinel-decoy. Login: ",
    25: b"220 sentinel-decoy SMTP Simple Mail Transfer Service Ready\r\n",
    8081: b"HTTP/1.0 200 OK\r\nServer: sentinel-decoy\r\n\r\n<body>decoy</>",
    8888: b"HTTP/1.0 200 OK\r\nServer: sentinel-decoy\r\n\r\n<body>decoy</>",
}


class DecoyService:
    """Threaded multi-port TCP decoy listener."""

    def __init__(self, config, on_touch: Callable[[str, int, dict], None]):
        self.config = config
        self.on_touch = on_touch
        self._stop = threading.Event()
        self._listeners: list = []
        self._threads: list = []
        # Resource caps: a hostile client must not be able to exhaust the
        # process with connection floods against the decoy ports.
        self._conn_cap = threading.BoundedSemaphore(
            int(getattr(config, "max_concurrent_handlers", 64)))
        # touch log is bounded (attackers cannot grow it without bound)
        self.touches = deque(maxlen=int(getattr(config, "max_touches_kept",
                                                512)))

    def start(self) -> None:
        bind_host = getattr(self.config, "bind_host", "0.0.0.0")
        for port in self.config.ports:
            thread = threading.Thread(target=self._serve, args=(bind_host, port),
                                      name=f"sentinel-decoy-{port}",
                                      daemon=True)
            thread.start()
            self._threads.append(thread)
        log.info("decoy ports listening: %s", list(self.config.ports))

    def _serve(self, host: str, port: int) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind((host, port))
            srv.listen(8)
            srv.settimeout(0.5)
        except OSError as exc:
            log.warning("decoy port %d unavailable (%s)", port, exc)
            return
        self._listeners.append(srv)
        while not self._stop.is_set():
            try:
                conn, (src_ip, src_port) = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._handle_bounded,
                args=(conn, src_ip, src_port, port),
                name=f"sentinel-decoy-h{port}", daemon=True).start()

    def _handle_bounded(self, conn: socket.socket, src_ip: str, src_port: int,
                        port: int) -> None:
        """Concurrent-handler cap so connection floods cannot exhaust the
        process; overflow connections are dropped immediately."""
        try:
            if not self._conn_cap.acquire(timeout=2.0):
                try:
                    conn.close()
                except OSError:
                    pass
                return                                  # drop under load
            self._handle(conn, src_ip, src_port, port)
        finally:
            try:
                self._conn_cap.release()
            except ValueError:
                pass

    def _handle(self, conn: socket.socket, src_ip: str, src_port: int,
                port: int) -> None:
        details: Dict[str, Any] = {"src_port": src_port}
        try:
            conn.settimeout(3.0)
            try:
                peek = conn.recv(256, socket.MSG_PEEK)
                if peek:
                    details["client_banner"] = peek[:120].decode(
                        "utf-8", errors="replace")
            except (socket.timeout, OSError):
                pass
            banner = _BANNERS.get(port)
            if banner:
                try:
                    conn.sendall(banner)
                except OSError:
                    pass
            self.touches.append({"src": src_ip, "port": port, **details})
            self.on_touch(src_ip, port, details)         # engine: block source
        except Exception:                                # noqa: BLE001
            log.exception("decoy handler error")
        finally:
            try:
                conn.close()
            except OSError:
                pass
            # linger on the capped handler slot: hostile clients experience a
            # 'service hung' moment AND floods can't recycle slots immediately
            time.sleep(0.4)

    def stop(self) -> None:
        self._stop.set()
        for srv in list(self._listeners):
            try:
                srv.close()
            except OSError:
                pass
