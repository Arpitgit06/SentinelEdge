"""Dense autoencoder that learns the machine's normal traffic (stretch goal).

Pure NumPy — no torch dependency, trains locally in seconds on the benign
flows produced by `tools/pcap_to_flows.py` or the feedback store input.

Contract notes
--------------
* Input space == the ML feature contract (`sentinel/flows/features.py`),
  so one feature definition powers every learning stage.
* Unsupervised: trained on benign rows only (label == 0). Reconstruction
  error above a calibrated benign-error percentile marks novelty.
* The downstream stage (sentinel/pipeline/anomaly.py) is alert-only by
  default — novelty is a soft signal and never auto-blocks, keeping the
  proposal's fail-open / first-do-no-harm stance.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import List, Optional, Sequence

import numpy as np


class Autoencoder:
    """Tanh dense autoencoder with z-score input scaling and Adam updates."""

    def __init__(self, dims: Sequence[int] = (48, 32, 12, 32, 48),
                 seed: int = 13):
        if len(dims) < 2 or dims[0] != dims[-1]:
            raise ValueError("autoencoder dims must be symmetric: (d, ..., d)")
        self.dims: List[int] = [int(d) for d in dims]
        rng = np.random.default_rng(seed)
        self.weights = [
            rng.normal(0.0, np.sqrt(2.0 / (a + b)), size=(a, b))
            for a, b in zip(self.dims[:-1], self.dims[1:])
        ]
        self.biases = [np.zeros(self.dims[i + 1])
                       for i in range(len(self.dims) - 1)]
        self.mu: Optional[np.ndarray] = None
        self.sigma: Optional[np.ndarray] = None
        self.threshold: Optional[float] = None
        self.meta: dict = {}

    # -- inference -----------------------------------------------------------
    def _standardize(self, X: np.ndarray) -> np.ndarray:
        if self.mu is None:
            return np.asarray(X, dtype=np.float64)
        # clip z-scores: heavy-tailed counters otherwise let a single
        # benign outlier dominate the loss (and the threshold calibration)
        return np.clip((X - self.mu) / self.sigma, -8.0, 8.0)

    def _forward(self, X: np.ndarray):
        """Tanh hidden layers; linear output (standardized z can exceed 1)."""
        zs, acts = [], [X]
        A = X
        n = len(self.weights)
        for i, (W, b) in enumerate(zip(self.weights, self.biases)):
            Z = A @ W + b
            zs.append(Z)
            A = Z if i == n - 1 else np.tanh(Z)
            acts.append(A)
        return zs, acts

    def reconstruction_error(self, X) -> np.ndarray:
        """Mean squared reconstruction error per row (standardized space)."""
        X = np.atleast_2d(np.asarray(X, dtype=np.float64))
        Xn = self._standardize(X)
        _, acts = self._forward(Xn)
        return np.mean((acts[-1] - Xn) ** 2, axis=1)

    def is_anomalous(self, x) -> bool:
        if self.threshold is None:
            raise RuntimeError("threshold not calibrated (call "
                               "calibrate_threshold after fit)")
        return bool(self.reconstruction_error(x)[0] > self.threshold)

    # -- training ------------------------------------------------------------
    def fit(self, X, epochs: int = 500, batch: int = 64, lr: float = 5e-3,
            seed: int = 7, noise_std: float = 0.05,
            weight_decay: float = 1e-5) -> List[float]:
        """Denoising-AE training: jitter standardized inputs, target clean.

        `noise_std` (z-space) forces a smooth identity mapping so the
        threshold generalizes to unseen benign rows instead of
        memorizing the training rows; `weight_decay` regresses the same.
        """
        X = np.atleast_2d(np.asarray(X, dtype=np.float64))
        self.mu = X.mean(axis=0)
        self.sigma = X.std(axis=0)
        self.sigma[self.sigma < 1e-9] = 1.0
        Xn = self._standardize(X)
        n, rng = Xn.shape[0], np.random.default_rng(seed)

        mW = [np.zeros_like(W) for W in self.weights]
        vW = [np.zeros_like(W) for W in self.weights]
        mb = [np.zeros_like(b) for b in self.biases]
        vb = [np.zeros_like(b) for b in self.biases]
        b1, b2, eps, t = 0.9, 0.999, 1e-8, 0
        n_layers = len(self.weights)
        history: List[float] = []

        for _ in range(epochs):
            order = rng.permutation(n)
            for s in range(0, n, batch):
                xb = Xn[order[s:s + batch]]
                xb_noisy = xb + rng.normal(0.0, noise_std, xb.shape)
                _, acts = self._forward(xb_noisy)
                # backward: MSE; linear output -> plain gradient there,
                # tanh derivative only when chaining through hidden layers
                delta = 2.0 * (acts[-1] - xb) / len(xb)
                gW = [None] * n_layers
                gb = [None] * n_layers
                for l in range(n_layers - 1, -1, -1):
                    gW[l] = acts[l].T @ delta
                    gb[l] = delta.sum(axis=0)
                    if l > 0:
                        delta = (delta @ self.weights[l].T) * \
                            (1.0 - acts[l] ** 2)
                t += 1
                for l in range(n_layers):
                    mW[l] = b1 * mW[l] + (1 - b1) * gW[l]
                    vW[l] = b2 * vW[l] + (1 - b2) * gW[l] ** 2
                    mb[l] = b1 * mb[l] + (1 - b1) * gb[l]
                    vb[l] = b2 * vb[l] + (1 - b2) * gb[l] ** 2
                    self.weights[l] -= lr * ((mW[l] / (1 - b1 ** t)) /
                                             (np.sqrt(vW[l] / (1 - b2 ** t))
                                              + eps)
                                             + weight_decay * self.weights[l])
                    self.biases[l] -= lr * (mb[l] / (1 - b1 ** t)) / \
                        (np.sqrt(vb[l] / (1 - b2 ** t)) + eps)
            history.append(float(self.reconstruction_error(X).mean()))
        return history

    def calibrate_threshold(self, X, percentile: float = 97.0,
                            margin: float = 1.0) -> float:
        """threshold = margin * percentile of training reconstruction errors.

        The margin buys headroom for benign rows unseen during training
        (novel ethereal attacks still err 10-100x above this line).
        """
        errs = self.reconstruction_error(X)
        self.threshold = float(np.percentile(errs, percentile)) * margin
        self.meta["threshold_percentile"] = percentile
        self.meta["threshold_margin"] = margin
        self.meta["train_err_mean"] = float(errs.mean())
        self.meta["train_err_max"] = float(errs.max())
        return self.threshold

    # -- persistence ------------------------------------------------------------
    def save(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        arrays: dict = {"dims": np.array(self.dims, dtype=np.int64),
                        "meta": np.array(json.dumps(self.meta))}
        if self.mu is not None:
            arrays["mu"] = self.mu
            arrays["sigma"] = self.sigma
        if self.threshold is not None:
            arrays["threshold"] = np.array([self.threshold])
        for i, (W, b) in enumerate(zip(self.weights, self.biases)):
            arrays[f"W{i}"] = W
            arrays[f"b{i}"] = b
        np.savez(path, **arrays)

    @classmethod
    def load(cls, path: Path) -> "Autoencoder":
        path = Path(path)
        with np.load(path, allow_pickle=False) as z:
            model = cls(dims=tuple(int(d) for d in z["dims"]))
            for i in range(len(model.weights)):
                model.weights[i] = z[f"W{i}"]
                model.biases[i] = z[f"b{i}"]
            if "mu" in z:
                model.mu = z["mu"]
                model.sigma = z["sigma"]
            if "threshold" in z:
                model.threshold = float(z["threshold"][0])
            model.meta = json.loads(str(z["meta"]))
        return model

    @property
    def threshold_percentile(self) -> float:
        return float(self.meta.get("threshold_percentile", 97.0))


def train_from_csv(csv_paths: Sequence[str], epochs: int = 500,
                   percentile: Optional[float] = None,
                   out_path: Optional[Path] = None,
                   dims: Sequence[int] = (48, 32, 12, 32, 48),
                   noise_std: float = 0.05, margin: float = 3.0,
                   cic: bool = False) -> Autoencoder:
    """Fit + calibrate the baseline AE from `tools/pcap_to_flows.py` CSVs
    (or raw CIC-IDS CSVs with cic=True).

    Benign rows are those with label == 0 / benign-ish text; all other
    activity is excluded from the baseline.
    """
    import pandas as pd
    from ..flows.features import FEATURES
    if cic:
        from .datasets import normalize_cic_columns

    frames = []
    total_benign = 0
    for p in csv_paths:
        df = pd.read_csv(p, encoding="latin-1" if cic else None,
                         low_memory=False)
        if cic:
            df.columns = [str(c).strip() for c in df.columns]
            df = normalize_cic_columns(df)
        if "label" in df.columns:
            lab = df["label"].astype(str).str.strip().str.lower()
            num = pd.to_numeric(df["label"], errors="coerce")
            keep = lab.isin({"0", "0.0", "benign", "normal", "legit"}) | \
                (num.fillna(-1.0) == 0)
            df = df[keep]
        total_benign += len(df)
        frames.append(df)
    if total_benign == 0:
        raise RuntimeError("no benign rows found in the given CSV files")

    per_frame = []
    for f in frames:
        cols = []
        for col in FEATURES:
            if col in f.columns:
                vals = pd.to_numeric(f[col], errors="coerce").to_numpy(
                    dtype=float)
            else:
                vals = np.zeros(len(f))
            cols.append(vals)
        per_frame.append(np.stack(cols, axis=1))
    X = np.vstack(per_frame)
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    model = Autoencoder(dims=dims)
    t0 = time.time()
    history = model.fit(X, epochs=epochs, noise_std=noise_std)
    model.calibrate_threshold(X, percentile=percentile or 97.0,
                              margin=margin)
    train_s = round(time.time() - t0, 2)
    model.meta.update({
        "kind": "flow-autoencoder",
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "train_s": train_s,
        "n_rows": int(X.shape[0]),
        "n_features": int(X.shape[1]),
        "dims": [int(d) for d in model.dims],
        "n_features_input": len(FEATURES),
    })
    if out_path is not None:
        model.save(out_path)
    print(f"autoencoder trained: {X.shape[0]} benign rows -> "
          f"final MSE {history[-1]:.6f}, threshold(p{model.threshold_percentile:g}) "
          f"{model.threshold:.6f} in {train_s}s")
    return model
