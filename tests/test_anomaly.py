"""Anomaly autoencoder + AnomalyStage tests (stretch goal).

Run directly:  python tests\\test_anomaly.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.ml.autoencoder import Autoencoder           # noqa: E402
from sentinel.flows.features import FEATURES              # noqa: E402

PASSED = 0


def ok(name: str, cond: bool) -> None:
    global PASSED
    assert cond, f"FAILED: {name}"
    PASSED += 1
    print(f"  ok  {name}")


_MANIFOLD = np.array(
    [3.0, 10.0, 8.0, 18.0, 2500.0, 1000.0, 3500.0, 40.0, 40.0, 40.0,
     2.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.01,
     0.02, 0.2, 0.01, 0.0, 0.0, 0.0, 0.0, 0.01, 0.005, 0.2, 0.01,
     1.0, 0.5, 0.0, 1.0, 0.1, 1.0, 0.0, 8.0, 0.0, 40.0, 1.0,
     0.0, 3.0, 5.0, 0.0], dtype=np.float64)


_LATENT_SEED = 5
_LAT = np.random.default_rng(_LATENT_SEED)
_LAT_MAP = _LAT.normal(0.0, np.sqrt(1.0 / 8.0), size=(8, len(_MANIFOLD)))


def _benign_matrix(n: int, seed: int = 3, noise: float = 0.05) -> np.ndarray:
    """Off an 8-dof manifold: features are correlated like real benign
    traffic (independent jitters would be 48-dof — not representable by
    an 8-dim bottleneck, i.e. unlearnable by construction)."""
    rng = np.random.default_rng(seed)
    latent = rng.uniform(-1.0, 1.0, size=(n, len(_LAT_MAP)))
    return _MANIFOLD * (1.0 + 0.15 * (latent @ _LAT_MAP))


def _anomalous_row(seed: int = 9) -> np.ndarray:
    rng = np.random.default_rng(seed)
    row = _benign_matrix(1)[0].copy()
    # push a fistful of features way outside the learned envelope
    row[0] = 1200.0                                  # flow_duration
    row[4] = 200000.0                                # fwd_payload_bytes
    row[44] = 900.0                                  # ctx_src_conns
    row[6] = 400000.0                                # total_bytes
    return row


def test_autoencoder_basics() -> None:
    X = _benign_matrix(160)
    hold = _benign_matrix(30, seed=44)
    weird = _anomalous_row()
    ae = Autoencoder(dims=(len(FEATURES), 24, 8, 24, len(FEATURES)))
    ae.fit(X, epochs=250, batch=32, lr=3e-3)
    thr = ae.calibrate_threshold(X, percentile=97.0, margin=3.0)
    ok("threshold calibrated", thr > 0.0 and ae.threshold == thr)
    errs = ae.reconstruction_error(hold)
    frac_below = float((errs <= thr).mean())
    ok(f"benign holdout stays below threshold (frac={frac_below:.2f}>=0.9)",
       frac_below >= 0.9)
    weird_err = float(ae.reconstruction_error(weird)[0])
    ok(f"off-manifold row flags (err {weird_err:.4f} > thr {thr:.4f})",
       weird_err > thr)
    ok("is_anomalous true for weird row", ae.is_anomalous(weird))
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "ae.npz"
        ae.save(p)
        ae2 = Autoencoder.load(p)
        e1 = ae.reconstruction_error(weird)
        e2 = ae2.reconstruction_error(weird)
        ok("save/load roundtrip identical",
           float(e1[0]) == float(e2[0]) and ae2.threshold == ae.threshold)


def test_stage_wiring() -> None:
    from sentinel.config import default_config
    from sentinel.pipeline.engine import DecisionEngine
    from sentinel.pipeline.anomaly import AnomalyStage

    cfg = default_config()
    eng = DecisionEngine(cfg)
    n_before = len(eng.stages)
    X = _benign_matrix(120)
    ae = AutoengineStub(X)
    eng.set_anomaly_model(ae)
    stages = [type(s).__name__ for s in eng.stages]
    ok("AnomalyStage attached once",
       stages.count("AnomalyStage") == 1 and len(eng.stages) == n_before + 1)
    order_idx = stages.index("AnomalyStage")
    ml_idx = stages.index("FlowMLStage") if "FlowMLStage" in stages else -1
    ok("stage ordering after flow_ml", order_idx > ml_idx)
    eng.set_anomaly_model(None)
    ok("detach removes stage",
       all(type(s).__name__ != "AnomalyStage" for s in eng.stages))
    # fail-safe: config flag disables attach
    cfg2 = default_config()
    cfg2.anomaly.enabled = False
    eng2 = DecisionEngine(cfg2)
    nb = len(eng2.stages)
    eng2.set_anomaly_model(AutoengineStub(X))
    ok("disabled config keeps stage out", len(eng2.stages) == nb)


class AutoengineStub:
    """Minimal stand-in for Autoencoder with a huge threshold (no alerts)."""

    def __init__(self, X):
        self.threshold = float(np.abs(X).max() * 9 + 1)
        self.threshold_percentile = 97.0
        self.meta = {}


if __name__ == "__main__":
    test_autoencoder_basics()
    test_stage_wiring()
    print(f"test_anomaly: {PASSED} checks passed")
