"""Dataset loaders: CIC-IDS2017/2018 CSVs mapped onto the runtime feature list.

Public datasets ship CICFlowMeter column names; we map the subset we can
compute at runtime onto `sentinel.flows.features.FEATURES`. Unavailable
columns become 0.0 (documented, class-weighted training absorbs it).

Recommended primary path, though, is `tools/pcap_to_flows.py` over pcaps
(lab + public dataset captures) — that pipeline uses the runtime FlowTable
so feature drift is impossible. Public CSV support here is a convenience.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Tuple

import pandas as pd

from sentinel.flows.features import FEATURES

# CICFlowMeter column -> our runtime feature name (same stats, alias names)
CIC_ALIAS = {
    "Flow Duration": "flow_duration",
    " Total Fwd Packets": "fwd_pkt_count",
    "Total Fwd Packets": "fwd_pkt_count",
    " Total Backward Packets": "bwd_pkt_count",
    "Total Backward Packets": "bwd_pkt_count",
    " Total Length of Fwd Packets": "fwd_payload_bytes",
    "Total Length of Fwd Packets": "fwd_payload_bytes",
    " Total Length of Bwd Packets": "bwd_payload_bytes",
    "Total Length of Bwd Packets": "bwd_payload_bytes",
    " Flow Bytes/s": "bytes_per_second",
    "Flow Bytes/s": "bytes_per_second",
    " Flow Packets/s": "packets_per_second",
    "Flow Packets/s": "packets_per_second",
    " Flow IAT Mean": "flow_iat_mean",
    " Flow IAT Std": "flow_iat_std",
    " Flow IAT Max": "flow_iat_max",
    " Flow IAT Min": "flow_iat_min",
    " Fwd IAT Total": "fwd_iat_mean",
    "Fwd IAT Mean": "fwd_iat_mean",
    " Fwd IAT Mean": "fwd_iat_mean",
    " Fwd IAT Std": "fwd_iat_std",
    " Fwd IAT Max": "fwd_iat_max",
    " Fwd IAT Min": "fwd_iat_min",
    " Bwd IAT Total": "bwd_iat_mean",
    " Bwd IAT Mean": "bwd_iat_mean",
    " Bwd IAT Std": "bwd_iat_std",
    " Bwd IAT Max": "bwd_iat_max",
    " Bwd IAT Min": "bwd_iat_min",
    " SYN Flag Count": "syn_count",
    "SYN Flag Count": "syn_count",
    " FIN Flag Count": "fin_count",
    "FIN Flag Count": "fin_count",
    " RST Flag Count": "rst_count",
    "RST Flag Count": "rst_count",
    " PSH Flag Count": "psh_count",
    "PSH Flag Count": "psh_count",
    " ACK Flag Count": "ack_count",
    "ACK Flag Count": "ack_count",
    " URG Flag Count": "urg_count",
    "URG Flag Count": "urg_count",
    " Init_Win_bytes_forward": "init_win_bytes_fwd",
    "Init_Win_bytes_forward": "init_win_bytes_fwd",
    " Init_Win_bytes_backward": "init_win_bytes_bwd",
    "Init_Win_bytes_backward": "init_win_bytes_bwd",
    " act_data_pkt_fwd": None,  # (informational, not in runtime vector)
    " Label": "label",
    "Label": "label",
}

LABEL_MAP = {
    "benign": "benign", "webattacks": "injection",
    "bruteforce": "bruteforce", "ddos": "flood", "dos": "flood",
    "hearbeat": "beaconing", "infiltration": "injection",
    "portscan": "scan", "bot": "beaconing",
}


def normalize_cic_columns(df: "pd.DataFrame") -> "pd.DataFrame":
    """Strip/alias-map CICFlowMeter headers onto the FEATURES contract.

    Shared by the supervised trainer (CIC-IDS2017/2018) and the autoencoder
    baseline so both see identical, normalized column names.
    """
    alias = {k.strip().lower(): v for k, v in CIC_ALIAS.items() if v}
    rename = {}
    for c in df.columns:
        target = alias.get(str(c).strip().lower())
        if target:
            rename[c] = target
    df = df.rename(columns=rename)
    if "label" in df.columns:
        df["label"] = df["label"].astype(str).str.strip().str.lower().map(
            lambda s: LABEL_MAP.get(s, s))
    return df


def load_csvs(csv_paths: List[Path], session_col: str = "source_file"
              ) -> Tuple[pd.DataFrame, pd.Series, pd.Series]:
    """Load CIC CSVs -> (X: pd.DataFrame[order=FEATURES-with-mapped-names],
    y: pd.Series[0/1 or class text], sessions: pd.Series)."""
    frames = []
    for path in csv_paths:
        df = pd.read_csv(path, encoding="latin-1", low_memory=False)
        df.columns = [c.strip() for c in df.columns]
        df = normalize_cic_columns(df)
        label_col = df.pop("label")
        df["label"] = label_col.values
        df["capture"] = str(path.stem)                # session split key
        frames.append(df)
    combined = pd.concat(frames, ignore_index=True)
    y_text = combined["label"]
    y = (y_text != "benign").astype(int)
    sessions = combined["capture"]
    X = combined.drop(columns=["label", "capture"])
    # align to runtime FEATURES: add missing as zeros, x in order
    for feature in FEATURES:
        if feature not in X.columns:
            X[feature] = 0.0
    X = X[FEATURES].apply(pd.to_numeric, errors="coerce").fillna(0.0)
    return X, y, sessions


def summarize_classes(y: pd.Series, y_text: Optional[pd.Series] = None) -> str:
    from collections import Counter
    if y_text is not None:
        counts = Counter(map(str, y_text))
    else:
        counts = Counter(map(int, y))
    return ", ".join(f"{k}:{v}" for k, v in sorted(counts.items()))
