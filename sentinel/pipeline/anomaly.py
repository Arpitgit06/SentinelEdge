"""Stage 5 — anomaly autoencoder novelty detection (stretch goal).

Flags flows whose reconstruction error exceeds the benign baseline
calibrated at `config.anomaly.threshold_percentile`. Alert-only by
default (`config.anomaly.alert_only`): novelty is soft evidence and
never auto-blocks, so this stage cannot cause a lock-out.
"""

from __future__ import annotations

import time
from typing import Any, Optional

from .base import Stage, StageResult, VERDICT_ALERT, VERDICT_BLOCK
from ..packets import PacketMeta

FEATURES_PARITY_NOTE = (
    "shares the single FEATURES contract in sentinel/flows/features.py "
    "with the ML stage and the training extractor")


class AnomalyStage(Stage):
    name = "anomaly"
    order = 55                                  # right after flow_ml (50)

    def __init__(self, config, model: Optional[Any] = None):
        super().__init__(config)
        self.model = model
        # cadence knobs are shared with the ML flow stage
        self.infer_every_n = max(1, int(getattr(config.ml,
                                                "infer_every_n_packets", 4)))
        self.min_packets = max(1, int(getattr(config.ml,
                                              "min_packets_to_infer", 6)))
        self.alert_only = bool(getattr(config.anomaly, "alert_only", True))
        self.block_factor = float(getattr(config.anomaly, "block_factor", 8.0))
        self.last_latency_ms: Optional[float] = None

    def inspect(self, pkt: PacketMeta, ctx) -> Optional[StageResult]:
        if self.model is None or ctx.flow_table is None:
            return None
        if self.model.threshold is None:
            return None
        row = ctx.flow_table.flows.get(pkt.flow_key())
        if row is None:
            return None
        total_pkts = row.fwd_pkts + row.bwd_pkts
        if total_pkts < self.min_packets or total_pkts % self.infer_every_n:
            return None
        t0 = time.perf_counter()
        from sentinel.flows.features import (features_vector,
                                             flow_row_to_feature_dict,
                                             source_context)
        context = source_context(ctx.flow_table, pkt.src, pkt.ts)
        fdict = flow_row_to_feature_dict(row, ctx=context)
        try:
            err = float(self.model.reconstruction_error(
                [features_vector(fdict)])[0])
        except Exception:                       # noqa: BLE001 — fail-open
            return None
        self.last_latency_ms = (time.perf_counter() - t0) * 1000.0
        threshold = float(self.model.threshold)
        uplift = err / max(threshold, 1e-12)
        return self._verdict(err, threshold, uplift)

    def _verdict(self, err: float, threshold: float,
                 uplift: float) -> Optional[StageResult]:
        if err <= threshold:
            return None
        base = "This flow looks unlike anything this machine normally does"
        evidence = {"recon_error": round(err, 6),
                    "baseline_threshold": round(threshold, 6),
                    "uplift": round(uplift, 2),
                    "backend": "numpy-autoencoder"}
        if self.alert_only:
            return StageResult(
                stage=self.name, verdict=VERDICT_ALERT,
                reason=f"{base} (reconstruction error {err:.6g} vs "
                       f"learned baseline {threshold:.6g})",
                evidence=evidence,
                score=min(1.0, uplift))
        if err >= threshold * self.block_factor:
            return StageResult(
                stage=self.name, verdict=VERDICT_BLOCK,
                reason=f"{base} — strongly off-baseline "
                       f"(reconstruction error {err:.6g}, "
                       f"{uplift:.0f}x learned baseline)",
                evidence=evidence,
                score=min(1.0, uplift))
        return StageResult(
            stage=self.name, verdict=VERDICT_ALERT,
            reason=f"{base} (reconstruction error {err:.6g} vs "
                   f"learned baseline {threshold:.6g})",
            evidence=evidence,
            score=min(1.0, uplift))
