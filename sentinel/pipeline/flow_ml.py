"""Flow-ML stage — Stage 4 in the pipeline (Random Forest / LightGBM).

Inference stays well under a millisecond at flow granularity:
  * Stage runs when a flow has absorbed `infer_every_n_packets` packets.
  * Features come from the same flow table the behaviour stage uses (parity
    contract: sentinel/flows/features.py::FEATURES is the single definition).
  * Verdicts:
      score >= block_threshold      -> block
      score >= quarantine_threshold -> quarantine (alert, flow kept open)
      otherwise                     -> pass (score attached to flow evidence)
"""

from __future__ import annotations

import os
import statistics
import time
from pathlib import Path
from typing import Any, Optional, Tuple

from .base import Stage, StageResult, VERDICT_ALERT, VERDICT_BLOCK
from ..packets import PacketMeta
from ..flows.features import FEATURES, features_vector, flow_row_to_feature_dict

VERDICT_QUARANTINE = "quarantine"

FEATURE_COUNT_EXPECTED = len(FEATURES)


class FlowModel:
    """Small wrapper: joblib (sklearn/lightgbm) or ONNX runtime if present."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.bundle: dict = {}
        self.backend: str = ""
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            raise FileNotFoundError(f"model not found: {self.path}")
        ext = self.path.suffix.lower()
        if ext == ".onnx":
            import onnxruntime as ort          # optional dep
            opts = ort.SessionOptions()
            session = ort.InferenceSession(str(self.path), opts,
                                                  providers=["CPUExecutionProvider"])
            self.session = session
            self.input_name = session.get_inputs()[0].name
            self.backend = "onnx"
        else:
            import joblib
            self.bundle = joblib.load(self.path)
            # bundle format: {"model": estimator, "features": [...], "meta":{}}
            self.model = self.bundle["model"]
            self.feature_names = self.bundle.get("features", FEATURES)
            self.backend = "joblib"
            # Fast path: the raw lgb.Booster avoids the sklearn wrapper's
            # per-call validation overhead (~2 ms -> ~0.1 ms per 1-row call).
            self._booster = getattr(self.model, "booster_", None)

    def predict_proba_malicious(self, feature_dict) -> float:                # type: ignore[no-untyped-def]
        if self.backend == "onnx":
            import numpy as np
            x = np.array([features_vector(feature_dict)], dtype=np.float32)
            pred = self.session.run(None, {self.input_name: x})[0]
            # handle single-class / proba variants
            arr = pred[0]
            return float(arr[1]) if getattr(arr, "__len__", None) and len(arr) > 1 \
                else float(arr)
        model = self.model
        if getattr(self, "_booster", None) is not None:
            import numpy as np
            if self.feature_names == FEATURES:
                x = np.array([features_vector(feature_dict)],
                             dtype=np.float32)
            else:                                    # legacy column order
                x = np.array([[float(feature_dict.get(n, 0.0))
                               for n in self.feature_names]],
                             dtype=np.float32)
            # num_threads=1: single-row calls are dominated by OpenMP
            # thread-pool sync; one worker is fastest and cheapest.
            return float(self._booster.predict(x, num_threads=1)[0])
        x = [features_vector(feature_dict)]
        if x and len(self.feature_names) != FEATURE_COUNT_EXPECTED:
            # model trained with feature union mismatch -> re-order columns
            x = [[float(feature_dict.get(n, 0.0)) for n in self.feature_names]]
        proba = getattr(model, "predict_proba", None)
        if proba is not None:                        # sklearn & lgb sklearn-like
            return float(model.predict_proba(x)[0][1])
        # lgb native Booster: expects float ndarray
        arr = model.predict(x if not hasattr(model, "predict_proba") else x[0])
        return float(arr[0])

    @property
    def meta(self) -> dict:
        return self.bundle.get("meta", {}) if self.backend == "joblib" else {}


class FlowMLStage(Stage):
    name = "flow_ml"
    order = 50

    def __init__(self, config, model: Optional[FlowModel] = None):
        super().__init__(config)
        self.model = model
        self.infer_every_n = max(1, int(getattr(config, "infer_every_n_packets", 4)))
        self.min_packets = max(1, int(getattr(config, "min_packets_to_infer", 6)))
        self.block_threshold = float(getattr(config, "block_threshold", 0.9))
        self.quarantine_threshold = float(getattr(config,
                                                  "quarantine_threshold", 0.6))
        self.last_latency_ms: Optional[float] = None

    def inspect(self, pkt: PacketMeta, ctx) -> Optional[StageResult]:
        if self.model is None or ctx.flow_table is None:
            return None
        row = ctx.flow_table.flows.get(pkt.flow_key())
        if row is None:
            return None
        total_pkts = row.fwd_pkts + row.bwd_pkts
        if total_pkts < self.min_packets or total_pkts % self.infer_every_n:
            return None
        t0 = time.perf_counter()
        from sentinel.flows.features import source_context
        context = source_context(ctx.flow_table, pkt.src, pkt.ts)
        fdict = flow_row_to_feature_dict(row, ctx=context)
        try:
            score = self.model.predict_proba_malicious(fdict)
        except Exception as exc:                     # noqa: BLE001 — fail-open
            return None
        self.last_latency_ms = (time.perf_counter() - t0) * 1000.0
        if score >= self.block_threshold:
            return StageResult(
                stage=self.name, verdict=VERDICT_BLOCK,
                reason="Flow features match malicious pattern "
                       f"(ML score {score:.2f})",
                evidence={"ml_score": round(score, 4),
                          "backend": self.model.backend},
                score=score)
        if score >= self.quarantine_threshold:
            return StageResult(
                stage=self.name, verdict=VERDICT_ALERT,
                reason="Suspicious flow parked for review "
                       f"(ML score {score:.2f})",
                evidence={"ml_score": round(score, 4),
                          "backend": self.model.backend},
                score=score)
        return None
