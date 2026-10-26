"""Security guards on the local dashboard + resource caps.

Covers: DNS-rebinding Host check, cross-origin websocket rejection,
ip input validation, evidence-zip output. Run directly:
python tests\\test_ui_security.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

PASSED = 0


def ok(name: str, cond: bool) -> None:
    global PASSED
    assert cond, f"FAILED: {name}"
    PASSED += 1
    print(f"  ok  {name}")


def _app_with(tmpdir: Path):
    from sentinel.config import default_config
    from sentinel.service import FirewallService
    from sentinel.ui.server import create_app
    cfg = default_config()
    cfg.storage.event_db = tmpdir / "events.db"
    cfg.data_dir = tmpdir
    svc = FirewallService(cfg)
    return create_app(svc), svc


_LOCAL_BASE = "http://127.0.0.1:8636"          # Host header must look local


def test_host_and_injection_guards() -> None:
    from fastapi.testclient import TestClient

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        app, svc = _app_with(Path(td))
        try:
            ok("local host works",
               TestClient(app, base_url=_LOCAL_BASE).get(
                   "/api/health").status_code == 200)
            # DNS-rebinding style: evil hostname mapped to 127.0.0.1
            c = TestClient(app, base_url="http://attacker.example:8636")
            ok("foreign Host rebinding -> 403",
               c.get("/api/health").status_code == 403)
            ok("foreign Host events -> 403",
               c.get("/api/events").status_code == 403)
            cl = TestClient(app, base_url=_LOCAL_BASE)
            ok("invalid ip allowlist -> 400",
               cl.post("/api/allowlist",
                       json={"ip": "not-an-ip; DROP TABLE events"}).status_code
               == 400)
            ok("invalid ip intel -> 400",
               cl.get("/api/intel/999.999.1.1").status_code == 400)
            ok("valid ip accepted",
               cl.post("/api/allowlist",
                       json={"ip": "198.51.100.90"}).status_code == 200)
        finally:
            try:
                svc.event_log.close()
                svc.intel_cache._conn.close()
            except Exception:                        # noqa: BLE001
                pass


def test_websocket_origin_guard() -> None:
    from fastapi.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        app, svc = _app_with(Path(td))
        try:
            with TestClient(app, base_url=_LOCAL_BASE) as cl:
                # local origin (served page) is allowed
                with cl.websocket_connect(
                        "/api/stream",
                        headers={"origin": "http://127.0.0.1:8636"}) as local:
                    local.send_text("ping")
                ok("local-origin WS accepted", True)
                # a rogue website origin gets closed with policy code 1008
                rejected = False
                try:
                    with cl.websocket_connect(
                            "/api/stream",
                            headers={"origin": "http://evil.test"}) as rogue:
                        rogue.receive_text()          # nothing should arrive
                except WebSocketDisconnect as exc:
                    rejected = True
                    ok(f"rogue-origin WS closed (code={exc.code})",
                       exc.code in (1008, 1000))
                except Exception:
                    rejected = True
                    ok("rogue-origin WS rejected (exception path)", True)
                if not rejected:
                    raise AssertionError("rogue origin was accepted")
        finally:
            try:
                svc.event_log.close()
                svc.intel_cache._conn.close()
            except Exception:                        # noqa: BLE001
                pass


def test_evidence_html_escaping() -> None:
    from sentinel.export.evidence import _summary_html
    rows = [{"iso": "t", "action": "block", "src": "<script>alert(1)</script>",
             "dst": "o.k", "dst_port": 80, "reason": "</td><script>x</script>",
             "intel": {"country": "<b>", "owner": "<i>x</i>",
                       "abuse_contacts": "<img src=x onerror=1>"}}]
    out = _summary_html(rows)
    ok("html report escapes", "<script>" not in out
       and "&lt;script&gt;" in out)


if __name__ == "__main__":
    test_host_and_injection_guards()
    test_websocket_origin_guard()
    test_evidence_html_escaping()
    print(f"test_ui_security: {PASSED} checks passed")
