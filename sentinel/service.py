"""Service runner: the composition root of the live firewall.

Wires: decision engine + event log + plain-language toasts (Allow once) +
async intel enrichment + dashboard bridge + optional honeypot + optional
slow-lane explainer. Both `main.py` and tests use this class.
"""

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .config import Config, default_config
from .pipeline.engine import DecisionEngine, Verdict
from .reputation_store import ReputationStore
from .storage.event_log import EventLog
from .alerts.templates import build_alert_text, short_title
from .alerts.toast import Notifier
from .intel.cache import IntelCache
from .intel.enrich import enrich_async
from .intel.p0f_fingerprint import os_hint

log = logging.getLogger(__name__)


class FirewallService:
    """One process = engine + IO. All modules optional-degraded."""

    def __init__(self, config: Optional[Config] = None,
                 driver_factory: Optional[Callable[[Any], Any]] = None):
        self.config = config or default_config()
        self.event_log = EventLog(self.config.storage.event_db)
        self.intel_cache = IntelCache(
            self.config.data_dir / "logs" / "intel_cache.db",
            ttl_hours=self.config.intel.ttl_hours_cache)
        self.engine = DecisionEngine(self.config)
        self.engine.subscribe(self._on_verdict)
        self.notifier = Notifier(
            app_id=self.config.alert.app_id,
            on_allow_once=self._allow_once)
        self.reputation_store: Optional[ReputationStore] = None
        self.ml_model: Any = None
        self.anomaly_model: Optional[Any] = None
        # feedback store: always records owner clicks; retraining is
        # threshold-guarded and opt-in (config.feedback.enabled)
        from .feedback.loop import FeedbackStore
        self.feedback = FeedbackStore(self.config.feedback.feedback_db,
                                      self.config.feedback)
        self.driver: Any = None
        self.enforcement_error: Optional[BaseException] = None
        self._driver_factory = driver_factory
        self.honeypot: Optional[Any] = None
        self.started_at = time.time()
        # UI broadcaster: dashboard module fills this when it starts
        self.ui_broadcast: Optional[Callable[[dict], None]] = None

    # -- optional subsystems -------------------------------------------------
    def load_reputation(self, store_path: Optional[Path] = None) -> None:
        path = store_path or (self.config.reputation.blocklist_dir /
                              "reputation.bin")
        if Path(path).exists():
            self.reputation_store = ReputationStore.load(path)
            log.info("reputation store loaded: %s", self.reputation_store.stats)
        else:
            log.warning("reputation store missing at %s (run "
                        "tools/update_blocklists.py)", path)
            self.reputation_store = ReputationStore(
                bloom_m=self.config.reputation.bloom_m,
                bloom_k=self.config.reputation.bloom_k)
        self.engine.set_reputation_store(self.reputation_store)

    def load_model(self) -> None:
        path = self.config.ml.model_path
        if not Path(path).exists():
            path = self.config.ml.fallback_model_path
        if Path(path).exists():
            from .pipeline.flow_ml import FlowModel
            try:
                self.ml_model = FlowModel(path)
                self.engine.set_ml_model(self.ml_model)
                log.info("ML model loaded from %s (backend=%s)", path,
                         self.ml_model.backend)
            except Exception:                       # noqa: BLE001
                log.exception("failed to load ML model %s", path)
        else:
            log.info("no ML model found (see sentinel/ml/train.py)")
        self.load_anomaly()

    def load_anomaly(self) -> None:
        """Attach the novelty autoencoder (stretch goal) when present."""
        path = Path(self.config.anomaly.model_path)
        if not (self.config.anomaly.enabled and path.exists()):
            return
        try:
            from .ml.autoencoder import Autoencoder
            self.anomaly_model = Autoencoder.load(path)
            self.engine.set_anomaly_model(self.anomaly_model)
            log.info("anomaly autoencoder loaded from %s "
                     "(baseline threshold %.6g, p%s)",
                     path, self.anomaly_model.threshold,
                     self.anomaly_model.threshold_percentile)
        except Exception:                       # noqa: BLE001
            log.exception("failed to load anomaly model %s", path)

    def start_honeypot(self) -> None:
        if not self.config.honeypot.enabled:
            return
        from .honeypot.decoy import DecoyService
        self.honeypot = DecoyService(self.config.honeypot,
                                     on_touch=self._on_honeypot_touch)
        self.honeypot.start()

    # -- lifecycle ------------------------------------------------------------
    def start(self, driver: Optional[Any] = None) -> None:
        if driver is None and self._driver_factory:
            driver = self._driver_factory(self)
        if driver is None:
            driver = self._default_driver()
        self.driver = driver
        try:
            driver.start()
        except Exception as exc:                    # noqa: BLE001 — fail-open
            # First, do no harm: if enforcement can't start (missing admin,
            # driver blocked...), traffic keeps flowing unimpeded.
            self.enforcement_error = exc
            log.critical("enforcement driver failed to start: %r", exc)
            log.critical(
                "FAIL-OPEN: observe-only mode — no packets will be blocked. "
                "Run as Administrator to enable blocking mode.")
        self.start_honeypot()
        log.info("firewall running (%s, enforcement=%s)",
                 getattr(driver, "name", driver), self.enforcement_active)

    @property
    def enforcement_active(self) -> bool:
        try:
            return bool(self.driver and self.driver.is_active())
        except Exception:                           # noqa: BLE001
            return False

    def _default_driver(self):
        cfg = self.config
        if cfg.capture.driver == "passive":
            from .capture.passive import PassiveDriver
            return PassiveDriver(cfg, self.engine.inspect)
        from .capture.divert_win import WinDivertDriver
        return WinDivertDriver(cfg, self.engine.inspect)

    def stop(self) -> None:
        try:
            if self.driver:
                self.driver.stop()
        except Exception:                           # noqa: BLE001
            pass
        if self.honeypot:
            self.honeypot.stop()
        # Close SQLite connections to avoid WinError 32 file locks
        for store_name in ('event_log', 'intel_cache', 'feedback'):
            store = getattr(self, store_name, None)
            if store is not None:
                conn = getattr(store, '_conn', None)
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:               # noqa: BLE001
                        pass

    # -- allow once -------------------------------------------------------------
    def _allow_once(self, ip: Optional[str], ttl_seconds: float = 300.0,
                    event_id: Optional[int] = None) -> None:
        if not ip:
            return
        self.engine.allow_once.grant(ip, ttl_seconds)
        self.event_log.record_user_action(event_id, "allow_once", ip,
                                          ttl_seconds)
        try:                                        # feedback learning input
            permanent = ttl_seconds >= 86400 * 365
            self.feedback.record(f"ip:{ip}",
                                 "allowlist" if permanent else "allow_once",
                                 {"ttl_seconds": ttl_seconds})
        except Exception:                           # noqa: BLE001
            pass
        log.info("allow-once granted to %s for %.0fs", ip, ttl_seconds)

    def retrain_from_feedback(self) -> bool:
        """Opt-in stretch goal: retrain the flow model on-device."""
        if not self.config.feedback.enabled:
            log.info("feedback retraining disabled (config.feedback.enabled)")
            return False
        csv_paths = list(self.config.ml.flow_csvs or [])
        if not csv_paths:
            log.info("no flow CSVs configured for feedback retraining")
            return False
        return self.feedback.maybe_retrain(csv_paths,
                                           self.config.ml.model_path)

    # -- verdict consumption (log, toast, UI) ------------------------------
    def _on_verdict(self, verdict: Verdict) -> None:
        """Runs synchronously in the packet path — keep it light."""
        if verdict.ts == 0:
            verdict.ts = time.time()
        # 1. record to sqlite (always), with immediate plain-language text
        intel_stub: dict = {}
        if verdict.packet is not None:
            hint = os_hint(verdict.packet)
            if hint:
                intel_stub["os_hint"] = hint
        plain = build_alert_text(verdict, intel=intel_stub)
        record_id = self.event_log.record(
            verdict, plain_text=plain,
            intel=intel_stub) \
            if verdict.action in ("block", "quarantine") else None
        verdict.event_id = record_id
        # 2. background enrichment (refines owner/country/abuse info)
        if (verdict.action in ("block", "quarantine")
                and verdict.packet is not None and self.config.intel.enabled):
            src = verdict.packet.src

            def _with_intel(intel: dict, _v: Verdict = verdict) -> None:
                merged = {**intel_stub, **intel}
                self.event_log.update_intel(_v.event_id or 0, merged)
                refined = build_alert_text(_v, intel=merged)
                self.event_log.update_plain(_v.event_id or 0, refined)
                if self.ui_broadcast:
                    self.ui_broadcast({**_v.to_dict(), "plain": refined,
                                       "intel": merged})
            if src:
                enrich_async(src, self.intel_cache, self.config.intel,
                             on_done=_with_intel)
        if self.ui_broadcast:
            self.ui_broadcast({**verdict.to_dict(),
                               "plain": plain, "intel": intel_stub})
        # 3. OS notification with Allow once
        if (self.config.alert.enabled
                and verdict.action in self.config.alert.toasts_for):
            threading.Thread(
                target=self.notifier.notify,
                args=(short_title(verdict), plain),
                kwargs={"source_ip": verdict.packet.src if verdict.packet
                        else None,
                        "allow_once_enabled": True},
                name="sentinel-toast", daemon=True).start()

    def _on_honeypot_touch(self, src_ip: str, port: int, details: dict) -> None:
        """Any touch on a decoy port is hostile by definition -> block."""
        from .packets import PacketMeta
        verdict = Verdict(
            action="block", stage="honeypot", score=1.0,
            reason=f"connection to decoy service port {port}",
            evidence={"decoy_port": port, **details},
            packet=PacketMeta(ts=time.time(), src=src_ip, dst="self",
                              proto=6, direction="in"),
            ts=time.time())
        self.engine.block_source(src_ip)
        self._on_verdict(verdict)   # runs log + toast + UI consumers directly

    def snapshot_for_ui(self) -> dict:
        return {
            "uptime_s": round(time.time() - self.started_at, 1),
            "engine_stats": self.engine.stats_snapshot(),
            "stages": [s.name for s in self.engine.stages],
            "driver": getattr(self.driver, "name", None),
        }
