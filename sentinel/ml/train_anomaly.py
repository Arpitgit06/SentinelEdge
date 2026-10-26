"""Train the traffic-baseline autoencoder (stretch goal).

Usage:
    python -m sentinel.ml.train_anomaly --csv data/flows.csv
    python -m sentinel.ml.train_anomaly --csv a.csv b.csv --percentile 97

Fits the NumPy autoencoder on benign rows only (label == 0) and saves an
npz bundle with calibrated threshold to data/models/flow_ae.npz. The
engine picks it up automatically on next start (config.anomaly.enabled).
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import List, Optional

from ..config import default_config
from .autoencoder import train_from_csv


def main(argv: Optional[List[str]] = None) -> int:
    cfg = default_config()
    p = argparse.ArgumentParser(
        description="train the traffic-baseline anomaly autoencoder")
    p.add_argument("--csv", nargs="+",
                   default=[str(cfg.data_dir / "flows.csv")],
                   help="flow CSV file(s) from tools/pcap_to_flows.py")
    p.add_argument("--epochs", type=int, default=500)
    p.add_argument("--percentile", type=float,
                   default=cfg.anomaly.threshold_percentile,
                   help="benign-error percentile for the alert threshold")
    p.add_argument("--dims", type=int, nargs="+",
                   default=list((48, 32, 12, 32, 48)))
    p.add_argument("--margin", type=float, default=3.0,
                   help="threshold headroom multiplier over the benign "
                        "error percentile (for unseen-benign tolerance)")
    p.add_argument("--cic", action="store_true",
                   help="csvs are CIC-IDS2017/2018 files (header aliases "
                        "map onto the FEATURES contract)")
    p.add_argument("--out", type=Path, default=cfg.anomaly.model_path)
    args = p.parse_args(argv)
    model = train_from_csv(args.csv, epochs=args.epochs,
                           percentile=args.percentile, out_path=args.out,
                           dims=tuple(args.dims), margin=args.margin,
                           cic=args.cic)
    print(f"saved: {args.out} (threshold={model.threshold:.6f})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
