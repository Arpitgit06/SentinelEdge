"""Local dashboard (FastAPI) — loopback only.

Endpoints:
    GET  /                     dashboard page
    GET  /api/events           JSON history (filters: action/src/dst/stage/q)
    GET  /api/events/{id}      single event with evidence + intel
    POST /api/events/{id}/allow-once   grant owner override (TTL)
    POST /api/allowlist        permanent allowlist (ip)
    GET  /api/stats            engine counters
    GET  /api/health           liveness + driver status
    GET  /api/intel/{ip}       enrichment lookup on demand
    WS   /api/stream           live verdict stream
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import (FastAPI, HTTPException, Request, WebSocket,
                     WebSocketDisconnect)
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

log = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).resolve().parent / "static"

# The dashboard listens on 127.0.0.1 only; these guards stop *browser-based*
# attacks against the local port (CSWSH / DNS-rebinding / drive-by CSRF):
_LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")


def _local_host(host: str) -> bool:
    return (host or "").split(":")[0].lower() in _LOCAL_HOSTS


def _valid_ip(value: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def _ws_origin_ok(ws) -> bool:
    """Websocket handshake happens without CORS preflight — a rogue page
    could otherwise stream this machine's alert feed. Local origins only;
    clients that send no Origin header are native/non-browser and allowed."""
    from urllib.parse import urlsplit
    origin = (ws.headers.get("origin") or "").strip()
    if not origin:
        return True
    if origin.lower() == "null":                     # sandboxed document
        return False
    try:
        host = (urlsplit(origin).hostname or "").lower()
    except ValueError:
        return False
    return host in _LOCAL_HOSTS


class AllowOnceBody(BaseModel):
    ttl_seconds: float = 300.0


class AllowlistBody(BaseModel):
    ip: str


def create_app(service: Any) -> FastAPI:
    app = FastAPI(title="Sentinel Edge dashboard", docs_url=None, redoc_url=None)

    # -- browser-hardening: DNS-rebinding / cross-site access guard -----------
    @app.middleware("http")
    async def _same_host_only(request: Request, call_next):    # noqa: ANN201
        # Browsers always send a Host header; rebinding attacks resolve an
        # attacker hostname to 127.0.0.1 and would read JSON responses.
        host = request.headers.get("host") or ""
        if host and not _local_host(host):
            return JSONResponse({"ok": False, "detail": "untrusted host"},
                                status_code=403)
        return await call_next(request)

    state: Dict[str, Any] = {
        "clients": set(),
        "queue_updater": None,
    }
    loop: Optional[asyncio.AbstractEventLoop] = None

    # -- async bridge from the engine thread ---------------------------------
    def broadcast(event: dict) -> None:
        nonlocal loop
        if loop is None or not state["clients"]:
            return
        fut = asyncio.run_coroutine_threadsafe(_push(event), loop)
        try:
            fut.result(timeout=1.0)
        except Exception:                            # noqa: BLE001
            pass

    async def _push(event: dict) -> None:
        dead = []
        payload = json.dumps(event, default=str)
        for ws in list(state["clients"]):
            try:
                await ws.send_text(payload)
            except Exception:                        # noqa: BLE001
                dead.append(ws)
        for ws in dead:
            state["clients"].discard(ws)

    service.ui_broadcast = broadcast

    # -- startup: record the loop for thread-safe pushes -----------------------
    @app.on_event("startup")
    async def _startup() -> None:
        nonlocal loop
        loop = asyncio.get_running_loop()

    # -- static frontend -------------------------------------------------------
    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)),
                  name="static")
    if (STATIC_DIR / "index.html").exists():
        app.get("/")(  # type: ignore[func-assigns]
            lambda: FileResponse(str(STATIC_DIR / "index.html")))

    # -- APIs -------------------------------------------------------------------
    @app.get("/api/events")
    def events(limit: int = 50, action: Optional[str] = None,
               src: Optional[str] = None, dst: Optional[str] = None,
               stage: Optional[str] = None, q: Optional[str] = None
               ) -> List[dict]:
        rows = service.event_log.query(limit=limit, action=action, src=src,
                                       dst=dst, stage=stage, search=q)
        return rows

    @app.get("/api/events/{event_id}")
    def event_detail(event_id: int) -> dict:
        row = service.event_log.get(event_id)
        if row is None:
            raise HTTPException(404, "event not found")
        # decode json fields for the frontend
        for col in ("evidence", "intel", "meta"):
            try:
                row[col] = json.loads(row.get(col) or "{}")
            except json.JSONDecodeError:
                row[col] = {}
        return row

    @app.post("/api/events/{event_id}/allow-once")
    def allow_once(event_id: int, body: AllowOnceBody) -> dict:
        row = service.event_log.get(event_id)
        if row is None:
            raise HTTPException(404, "event not found")
        ip = row.get("src")
        if not ip:
            raise HTTPException(400, "event has no source ip")
        ttl = max(1.0, min(float(body.ttl_seconds), 86400.0 * 100000))
        service._allow_once(ip, ttl_seconds=ttl,
                            event_id=event_id)      # single audit row
        return {"ok": True, "ip": ip, "ttl_seconds": ttl}

    @app.post("/api/allowlist")
    def allowlist(body: AllowlistBody) -> dict:
        if not _valid_ip(body.ip):
            raise HTTPException(400, "invalid ip address")
        service._allow_once(body.ip, ttl_seconds=86400 * 100000)
        return {"ok": True, "ip": body.ip}

    @app.get("/api/export")
    def export(event_id: Optional[int] = None, action: Optional[str] = None,
               q: Optional[str] = None, src: Optional[str] = None,
               limit: int = 50):
        """Evidence zip (stretch goal): one event, or the filtered history."""
        if event_id:
            ids = [event_id]
        else:
            rows = service.event_log.query(limit=limit, action=action or
                                           "block", src=src, search=q)
            ids = [r["id"] for r in rows]
        from sentinel.export.evidence import export_events
        path = export_events(service.event_log, ids,
                             Path(service.config.storage.evidence_dir))
        if path is None:
            raise HTTPException(404, "nothing to export")
        return FileResponse(str(path), media_type="application/zip",
                            filename=path.name)

    @app.get("/api/feedback")
    def feedback() -> dict:
        try:
            counts = service.feedback.counts()
        except Exception:                           # noqa: BLE001
            counts = {}
        return {"enabled": service.config.feedback.enabled,
                "counts": counts}

    @app.post("/api/feedback/retrain")
    def feedback_retrain() -> dict:
        """Opt-in on-device retraining (config.feedback.enabled)."""
        started = service.retrain_from_feedback()
        return {"ok": started,
                "enabled": service.config.feedback.enabled}

    @app.get("/api/stats")
    def stats() -> dict:
        snap = service.snapshot_for_ui()
        snap["db_stats"] = service.event_log.stats()
        snap["keys_active"] = {}
        try:
            from sentinel.intel.reputation_api import key_status
            snap["keys_active"] = key_status()
        except Exception:                        # noqa: BLE001
            pass
        return snap

    @app.get("/api/health")
    def health() -> dict:
        driver = service.driver
        return {"ok": True,
                "driver": getattr(driver, "name", None) if driver else None,
                "driver_active": bool(driver and driver.is_active()),
                "enforcement_active": service.enforcement_active,
                "enforcement_error": str(service.enforcement_error) if
                service.enforcement_error else None}

    @app.get("/api/intel/{ip}")
    def intel(ip: str, refresh: bool = False) -> dict:
        if not _valid_ip(ip):
            raise HTTPException(400, "invalid ip address")
        key = f"ip:{ip}"
        if refresh:
            service.intel_cache.delete(key)
        from sentinel.intel.enrich import gather_intel_sync
        return gather_intel_sync(ip, service.intel_cache,
                                 service.config.intel)

    # -- websocket live stream --------------------------------------------------
    @app.websocket("/api/stream")
    async def stream(ws: WebSocket) -> None:
        # WS handshakes skip CORS — reject foreign origins (see module header)
        if not _ws_origin_ok(ws):
            await ws.accept()
            await ws.close(code=1008, reason="cross-origin rejected")
            return
        await ws.accept()
        state["clients"].add(ws)
        try:
            while True:
                await ws.receive_text()          # keepalive pings from ui
        except WebSocketDisconnect:
            state["clients"].discard(ws)
        except Exception:                        # noqa: BLE001
            state["clients"].discard(ws)

    return app


def run_dashboard(service: Any, host: Optional[str] = None,
                  port: Optional[int] = None) -> None:
    """Blocking dashboard-only mode (engine events come from a running service)."""
    import uvicorn
    app = create_app(service)
    uvicorn.run(app, host=host or service.config.dashboard.host,
                port=port or service.config.dashboard.port, log_level="warning")
