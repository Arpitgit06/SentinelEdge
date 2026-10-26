"""Export a trained sklearn/LightGBM model to ONNX (production path).

Requires the optional converters:
    pip install skl2onnx onnxmltools onnxruntime

If unavailable, explains the joblib alternative (the runtime supports both).
"""

from __future__ import annotations

from pathlib import Path


def export_joblib_bundle(bundle_path: Path, out_path: Path) -> bool:
    """Convert {"model", "features"} -> .onnx; quantization left to ONNX tooling."""
    try:
        import joblib
        import json
        from sklearn.ensemble import RandomForestClassifier
        from lightgbm import LGBMClassifier
    except ImportError as exc:
        print(f"onnx export deps missing: {exc}\n"
              "pip install skl2onnx onnxmltools onnxruntime")
        return False
    bundle = joblib.load(bundle_path)
    model = bundle["model"]
    n_features = len(bundle.get("features", []))
    try:
        from skl2onnx.common.data_types import FloatTensorType
        from skl2onnx import convert_sklearn
        if isinstance(model, LGBMClassifier):
            from onnxmltools.convert.lightgbm import convert_lightgbm
            onx = convert_lightgbm(
                model, initial_types=[("input", FloatTensorType(
                    [None, n_features]))])
        else:
            onx = convert_sklearn(
                model, initial_types=[("input", FloatTensorType(
                    [None, n_features]))])
    except Exception as exc:                    # noqa: BLE001
        print(f"conversion failed: {exc}")
        return False
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(onx.SerializeToString())
    print(f"exported {out_path} ({out_path.stat().st_size / 1024:.1f} KB)")
    return True


if __name__ == "__main__":
    import sys
    bundle = Path(sys.argv[1] if len(sys.argv) > 1 else
                  "data/models/flow_lgbm.joblib")
    out = Path(sys.argv[2] if len(sys.argv) > 2 else
               "data/models/flow_lgbm.onnx")
    ok = export_joblib_bundle(bundle, out)
    sys.exit(0 if ok else 1)
