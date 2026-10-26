"""OS notifications with an 'Allow once' button.

Fallback chain (first available wins):
  1. windows-toasts (native Win10/11 toast with an Allow-once button)
  2. plyer (cross-platform notification, no button)
  3. console log (never silently loses the alert)

The Allow-once button calls the `on_allow_once(ip=None)` callback which the
engine wires to `DecisionEngine.allow_once.grant(...)`.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional

log = logging.getLogger(__name__)

_BACKENDS = tuple()


def _detect_backends() -> tuple:
    global _BACKENDS
    if _BACKENDS:
        return _BACKENDS
    backends = []
    try:
        import windows_toasts  # noqa: F401
        backends.append("windows_toasts")
    except Exception:                            # noqa: BLE001
        pass
    try:
        import plyer  # noqa: F401
        backends.append("plyer")
    except Exception:                            # noqa: BLE001
        pass
    backends.append("console")
    _BACKENDS = tuple(backends)
    return _BACKENDS


class Notifier:
    """Send `title/body` to the OS with optional Allow-once callback."""

    def __init__(self, app_id: str = "Sentinel Edge",
                 on_allow_once: Optional[Callable[[str], None]] = None):
        self.app_id = app_id
        self.on_allow_once = on_allow_once
        self.backends = _detect_backends()
        self._cached_toaster: Any = None

    # -- public -------------------------------------------------------------
    def notify(self, title: str, body: str, source_ip: Optional[str] = None,
               allow_once_enabled: bool = False) -> bool:
        """Returns True if any backend accepted the notification."""
        for backend in self.backends:
            try:
                if backend == "windows_toasts" and self._toast(
                        title, body, source_ip, allow_once_enabled):
                    return True
                if backend == "plyer" and self._plyer(title, body):
                    return True
            except Exception:                        # noqa: BLE001
                log.exception("notification backend %s failed", backend)
        # always console mirror if all GUI backends fail
        log.warning("[alert] %s | %s", title, body)
        return False

    # -- backends ---------------------------------------------------------
    def _toast(self, title: str, body: str, source_ip: Optional[str] = None,
               allow_once_enabled: bool = False) -> bool:
        """windows-toasts path; returns False on any failure so next try runs."""
        try:
            from windows_toasts import (Toast, WindowsToaster)
        except Exception:                            # noqa: BLE001
            return False

        def _allow_once(args, _ip: Optional[str] = source_ip):   # type: ignore[no-untyped-def]
            if _ip:
                (self.on_allow_once or (lambda ip=None: None))(_ip)

        try:
            toast = Toast()
            toast.text_fields = [title, body]
            if allow_once_enabled:
                try:
                    from windows_toasts import ToastButton
                    toast.AddButton(ToastButton(
                        content="Allow once",
                        arguments="allow-once",
                        on_activated=_allow_once))
                except Exception:                    # noqa: BLE001 — no button; text only
                    toast.text_fields = [f"{title} (press Y in console to allow)",
                                        body]
            try:
                toast.launch = ("Sentinel Edge", "")   # click target optional
            except Exception:                        # noqa: BLE001
                pass
            toaster = self._cached_toaster
            if toaster is None:
                toaster = self._cached_toaster = WindowsToaster(self.app_id)
            toaster.display_toast(toast)
            return True
        except Exception:                            # noqa: BLE001
            return False

    def _plyer(self, title: str, body: str) -> bool:
        try:
            from plyer import notification
            notification.notify(title=title[:63], message=body[:255],
                                app_name=self.app_id, timeout=8)
            return True
        except Exception:                            # noqa: BLE001
            return False

    # -- optional console interaction for lab runs -----------------------------
    def allow_once_console_prompt(self, source_ip: Optional[str]) -> None:
        """Interactive fallback: 'Y' allows once (lab/demo only)."""
        try:
            answer = input(f"Allow one more attempt from {source_ip}? [yN] ")
            if answer.strip().lower().startswith("y") and source_ip:
                (self.on_allow_once or (lambda ip=None: None))(source_ip)
        except (EOFError, KeyboardInterrupt):
            pass
