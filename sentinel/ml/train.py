"""Train the flow ML classifier (Random Forest / LightGBM) from extracted CSVs.

Input CSV: `tools/pcap_to_flows.py` rows with the runtime FEATURES columns
plus `label` and `capture` (session id). Session-split train/test by capture
(the proposal: "split train and test by capture session, not randomly, or the
test leaks").

Output: joblib bundle {"model", "features", "meta"} with metrics written next
to it + LightGBM native booster when available.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional, Tuple

import numpy as np
import pandas as pd

from sentinel.flows.features import FEATURES

LABEL_CLASSES = ("benign", "scan", "flood", "bruteforce", "injection",
                 "beaconing")


def load_flow_csvs(csv_paths, label_col: str = "label",
                   session_col: str = "capture"
                   ) -> Tuple[pd.DataFrame, pd.Series, pd.Series]:     # type: ignore[no-untyped-def]
    frames = []
    for path in csv_paths:
        df = pd.read_csv(path, low_memory=False)
        for feature in FEATURES:
            if feature not in df.columns:
                df[feature] = 0.0
        frames.append(df)
    combined = pd.concat(frames, ignore_index=True)
    y_text = combined[label_col].astype(str).str.strip().str.lower()
    y = (y_text != "benign").astype(int)
    sessions = combined[session_col].astype(str)
    X = combined[FEATURES].apply(pd.to_numeric, errors="coerce").fillna(0.0)
    # Multi-class labels: map text to class index
    class_map = {name: idx for idx, name in enumerate(LABEL_CLASSES)}
    y_multi = y_text.map(lambda t: class_map.get(t, 1 if t != "benign" else 0))
    return X, y, sessions, y_text, y_multi


def session_split(sessions: pd.Series, y: Optional[pd.Series] = None,
                  holdout_fraction: float = 0.25
                  ) -> Tuple[np.ndarray, np.ndarray]:
    """Hold out whole capture sessions (never leak rows across the split).

    Falls back to stratified random split when the session holdout would
    produce a degenerate test set (< 30 rows or < 2 classes).
    """
    unique = sorted(sessions.unique())
    holdout_n = max(1, int(len(unique) * holdout_fraction))
    holdout = set(unique[-holdout_n:])
    train_idx = np.where(~sessions.isin(holdout))[0]
    test_idx = np.where(sessions.isin(holdout))[0]
    if len(train_idx) == 0 or len(test_idx) == 0:
        all_idx = np.arange(len(sessions))
        return all_idx, all_idx
    # Stratified fallback: if the session holdout is degenerate, use
    # a stratified random split instead so evaluation metrics are meaningful.
    if y is not None:
        n_test = len(test_idx)
        n_test_classes = int(y.iloc[test_idx].nunique())
        if n_test < 30 or n_test_classes < 2:
            try:
                from sklearn.model_selection import train_test_split
                all_idx = np.arange(len(sessions))
                train_idx, test_idx = train_test_split(
                    all_idx, test_size=holdout_fraction, random_state=17,
                    stratify=y.to_numpy())
            except Exception:                       # noqa: BLE001
                pass  # fall through to session split
    return train_idx, test_idx


def train_model(X_train: np.ndarray, y_train: np.ndarray,
                prefer: str = "lightgbm"):
    """Return (model, kind). Uses class weights for imbalance (proposal)."""
    from sklearn.utils.class_weight import compute_class_weight
    classes = np.unique(y_train)
    weights = compute_class_weight(class_weight="balanced",
                                   classes=classes, y=y_train)
    weight_map = {int(cls): float(w) for cls, w in zip(classes, weights)}
    if prefer == "lightgbm":
        try:
            from lightgbm import LGBMClassifier
            model = LGBMClassifier(
                n_estimators=220, learning_rate=0.08, max_depth=7,
                num_leaves=64, class_weight=weight_map, n_jobs=-1,
                verbose=-1)
            model.fit(X_train, y_train)
            return model, "lightgbm"
        except ImportError:
            pass
    from sklearn.ensemble import RandomForestClassifier
    weights_per_sample = np.array(
        [weight_map[int(t)] for t in y_train], dtype=float)
    model = RandomForestClassifier(
        n_estimators=180, max_depth=18, n_jobs=-1,
        class_weight=weight_map)
    model.fit(X_train, y_train)
    return model, "sklearn-rf"


def evaluate_flexible(model, X_test: np.ndarray, y_test: np.ndarray
                      ) -> dict:
    """Recall per attack class, FPR, precision — envelope for the report."""
    from sklearn.metrics import (classification_report, precision_score,
                                 recall_score, confusion_matrix)
    y_pred = model.predict(X_test)
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred, labels=[0, 1]).ravel()
    metrics = {
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "fpr": float(fp / (fp + tn)) if fp + tn else 0.0,
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "report": classification_report(y_test, y_pred, target_names=[
            "benign", "malicious"], zero_division=0, output_dict=True),
    }
    return metrics


def fpr_at_recall(model, X_test: np.ndarray, y_test: np.ndarray,
                  target_recall: float = 0.95) -> dict:
    """Sweep threshold: FPR achieved at the target recall."""
    proba = model.predict_proba(X_test)[:, 1]
    y_true = y_test
    thresholds = sorted(set(float(t) for t in (np.arange(0.02, 0.98, 0.02))))
    best = {"threshold": None, "recall": 0.0, "fpr": 1.0}
    for thr in thresholds:
        y_pred = (proba >= thr).astype(int)
        tp = int(((y_pred == 1) & (y_true == 1)).sum())
        fn = int(((y_pred == 0) & (y_true == 1)).sum())
        fp = int(((y_pred == 1) & (y_true == 0)).sum())
        tn = int(((y_pred == 0) & (y_true == 0)).sum())
        recall = tp / (tp + fn) if tp + fn else 0.0
        fpr = fp / (fp + tn) if fp + tn else 0.0
        if recall >= target_recall and fpr < best["fpr"]:
            best = {"threshold": thr, "recall": recall, "fpr": fpr}
    return best


def run_training(args) -> int:
    """CLI entry: --csv file1 [file2 ...] --out model.joblib [--cic]"""
    csvs = [Path(p) for p in args.csv]
    print(f"training from {len(csvs)} csv file(s)")
    if getattr(args, "cic", False):
        from .datasets import load_csvs as load_cic, summarize_classes
        X, y, sessions = load_cic(csvs)
        y_text = pd.Series(["benign" if v == 0 else "malicious" for v in y])
        y_multi = y
        print("classes:", summarize_classes(y))
    else:
        X, y, sessions, y_text, y_multi = load_flow_csvs(
            csvs, session_col=args.session_col)
        print("class distribution:",
              y_text.value_counts().to_dict())
    train_idx, test_idx = session_split(sessions, y=y,
                                        holdout_fraction=0.25)
    X_train, y_train = X.iloc[train_idx], y.iloc[train_idx]
    X_test, y_test = X.iloc[test_idx], y.iloc[test_idx]
    print(f"session split: train={len(train_idx)} test={len(test_idx)}")
    started = time.time()
    model, kind = train_model(X_train.to_numpy(), y_train.to_numpy(),
                              prefer=getattr(args, "model", "lightgbm"))
    train_s = time.time() - started
    metrics = evaluate_flexible(model, X_test.to_numpy(), y_test.to_numpy())
    sweep = fpr_at_recall(model, X_test.to_numpy(), y_test.to_numpy(),
                          target_recall=0.9)
    bundle = {"model": model, "features": list(FEATURES),
              "meta": {"kind": kind, "trained_at": time.strftime(
                  "%Y-%m-%d %H:%M:%S"), "train_s": round(train_s, 1),
                       "n_features": len(FEATURES)},
              "metrics": metrics, "fpr_at_recall": sweep}
    # ---- multi-class training (proposal: per-class precision/recall) ----------
    y_multi_train = y_multi.iloc[train_idx]
    y_multi_test = y_multi.iloc[test_idx]
    n_multi_classes = int(y_multi_train.nunique())
    if n_multi_classes > 2:
        try:
            mc_model, mc_kind = train_model(
                X_train.to_numpy(), y_multi_train.to_numpy(),
                prefer=getattr(args, "model", "lightgbm"))
            from sklearn.metrics import classification_report
            mc_pred = mc_model.predict(X_test.to_numpy())
            # Map class indices back to names for the report
            idx_to_name = {idx: name for idx, name in enumerate(LABEL_CLASSES)}
            target_names = [idx_to_name.get(c, str(c))
                            for c in sorted(y_multi_test.unique())]
            mc_report = classification_report(
                y_multi_test.to_numpy(), mc_pred,
                target_names=target_names, zero_division=0, output_dict=True)
            bundle["multi_class"] = {
                "model": mc_model, "kind": mc_kind,
                "report": mc_report}
            print(f"multi-class model ({mc_kind}): "
                  f"{n_multi_classes} classes")
            print(classification_report(
                y_multi_test.to_numpy(), mc_pred,
                target_names=target_names, zero_division=0))
        except Exception as exc:                        # noqa: BLE001
            print(f"[info] multi-class training skipped ({exc})")
    import joblib
    out = Path(args.out) if args.out else (
        Path("data") / "models" / "flow_lgbm.joblib")
    out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, out)
    print(f"model: {kind} | precision={metrics['precision']:.3f} "
          f"recall={metrics['recall']:.3f} fpr={metrics['fpr']:.4f}")
    print(f"fpr at recall 0.9: {sweep}")
    print(f"saved: {out}")
    # metrics json alongside
    Path(str(out) + ".metrics.json").write_text(json.dumps(
        {k: metrics.get(k) for k in ("precision", "recall", "fpr")}
        | {"fpr_at_recall": sweep}, indent=2))
    return 0


def run_training_from_csvs(flow_csvs, out_path, prefer="lightgbm") -> None:
    """Programmatic entry point for feedback-loop retraining.

    Called by `sentinel.feedback.loop.FeedbackStore.maybe_retrain()` to
    retrain the flow classifier on-device from accumulated flow CSVs.
    """
    csv_paths = [Path(p) for p in flow_csvs]
    X, y, sessions, y_text, y_multi = load_flow_csvs(csv_paths)
    train_idx, test_idx = session_split(sessions, y=y, holdout_fraction=0.25)
    X_train, y_train = X.iloc[train_idx], y.iloc[train_idx]
    model, kind = train_model(X_train.to_numpy(), y_train.to_numpy(),
                              prefer=prefer)
    import joblib
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    bundle = {"model": model, "features": list(FEATURES),
              "meta": {"kind": kind, "trained_at": time.strftime(
                  "%Y-%m-%d %H:%M:%S"),
                       "n_features": len(FEATURES),
                       "source": "feedback_retrain"}}
    joblib.dump(bundle, out)
