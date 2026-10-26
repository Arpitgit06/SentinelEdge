"""The feature contract: one ordered list, one extractor, zero drift.

`FEATURES` defines the exact column order used for BOTH:
  * training (`tools/pcap_to_flows.py` -> CSV, `sentinel/ml/train.py`)
  * runtime inference (`sentinel.pipeline.flow_ml` reads the same row dict)

Add or edit features here and everything stays in sync.
"""

from __future__ import annotations

import math
import statistics
from typing import Dict, Optional, Sequence

from .flow_table import FlowRow

# Canonical, ordered feature list (lightgbm/sklearn both consume these names).
FEATURES = [
    "flow_duration",
    "fwd_pkt_count", "bwd_pkt_count", "total_pkt_count",
    "fwd_payload_bytes", "bwd_payload_bytes", "total_bytes",
    "fwd_pkt_size_min", "fwd_pkt_size_max", "fwd_pkt_size_mean",
    "fwd_pkt_size_std", "bwd_pkt_size_min", "bwd_pkt_size_max",
    "bwd_pkt_size_mean", "bwd_pkt_size_std",
    "bytes_per_second", "packets_per_second",
    "fwd_iat_mean", "fwd_iat_max", "fwd_iat_min", "fwd_iat_std",
    "bwd_iat_mean", "bwd_iat_max", "bwd_iat_min", "bwd_iat_std",
    "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
    "syn_count", "fin_count", "rst_count", "psh_count", "ack_count",
    "urg_count", "fwd_psh_flags", "fwd_urg_flags",
    "fwd_header_len", "bwd_header_len",
    "init_win_bytes_fwd", "init_win_bytes_bwd",
    "fwd_seg_size_avg", "bwd_seg_size_avg",
    "active_mean", "idle_mean",
    # per-source context (fan-out signatures: the only place scan/flood/
    # bruteforce behaviour shows up as *numbers* per flow)
    "ctx_src_distinct_ports", "ctx_src_conns", "ctx_src_synth_ratio",
]

# context window matched to the behaviour detector's scan window
CTX_WINDOW_S = 30.0


def _std(values: Optional[Sequence[float]]) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return 0.0
    try:
        return statistics.pstdev(values)
    except statistics.StatisticsError:
        return 0.0


def flow_row_to_feature_dict(row: FlowRow, ctx: Optional[Dict[str, float]]
                             = None) -> Dict[str, float]:
    """Extract feature dict from a FlowRow (order-exact to FEATURES).

    `ctx` carries per-source context computed by callers (flow table source
    state); missing keys become 0.0 of the three ctx features.
    """
    duration = max(0.0, row.t_last - row.t_first)
    fwd_sizes = list(row.fwd_sizes)
    bwd_sizes = list(row.bwd_sizes)
    fwd_iats = list(row.fwd_iats)
    bwd_iats = list(row.bwd_iats)
    all_iats = list(row.all_iats)
    total_pkts = row.fwd_pkts + row.bwd_pkts
    total_bytes = row.fwd_bytes + row.bwd_bytes
    # idle/active means: idle = gaps > 1 s inside the flow, active = the rest
    idle_gaps = [g for g in all_iats if g > 1.0]
    active_gaps = [g for g in all_iats if 0.0 <= g <= 1.0]
    out = {
        "flow_duration": duration,
        "fwd_pkt_count": float(row.fwd_pkts),
        "bwd_pkt_count": float(row.bwd_pkts),
        "total_pkt_count": float(total_pkts),
        "fwd_payload_bytes": float(row.fwd_bytes),
        "bwd_payload_bytes": float(row.bwd_bytes),
        "total_bytes": float(total_bytes),
        "fwd_pkt_size_min": float(min(fwd_sizes)) if fwd_sizes else 0.0,
        "fwd_pkt_size_max": float(max(fwd_sizes)) if fwd_sizes else 0.0,
        "fwd_pkt_size_mean": (statistics.fmean(fwd_sizes) if fwd_sizes else 0.0),
        "fwd_pkt_size_std": _std(fwd_sizes),
        "bwd_pkt_size_min": float(min(bwd_sizes)) if bwd_sizes else 0.0,
        "bwd_pkt_size_max": float(max(bwd_sizes)) if bwd_sizes else 0.0,
        "bwd_pkt_size_mean": (statistics.fmean(bwd_sizes) if bwd_sizes else 0.0),
        "bwd_pkt_size_std": _std(bwd_sizes),
        "bytes_per_second": total_bytes / duration if duration > 0 else float(total_bytes),
        "packets_per_second": total_pkts / duration if duration > 0 else float(total_pkts),
        "fwd_iat_mean": statistics.fmean(fwd_iats) if fwd_iats else 0.0,
        "fwd_iat_max": max(fwd_iats) if fwd_iats else 0.0,
        "fwd_iat_min": min(fwd_iats) if fwd_iats else 0.0,
        "fwd_iat_std": _std(fwd_iats),
        "bwd_iat_mean": statistics.fmean(bwd_iats) if bwd_iats else 0.0,
        "bwd_iat_max": max(bwd_iats) if bwd_iats else 0.0,
        "bwd_iat_min": min(bwd_iats) if bwd_iats else 0.0,
        "bwd_iat_std": _std(bwd_iats),
        "flow_iat_mean": statistics.fmean(all_iats) if all_iats else 0.0,
        "flow_iat_std": _std(all_iats),
        "flow_iat_max": max(all_iats) if all_iats else 0.0,
        "flow_iat_min": min(all_iats) if all_iats else 0.0,
        "syn_count": float(row.fwd_syn + row.bwd_syn),
        "fin_count": float(row.fwd_fin + row.bwd_fin),
        "rst_count": float(row.fwd_rst + row.bwd_rst),
        "psh_count": float(row.fwd_psh + row.bwd_psh),
        "ack_count": float(row.fwd_ack + row.bwd_ack),
        "urg_count": float(row.fwd_urg + row.bwd_urg),
        "fwd_psh_flags": float(row.fwd_psh),
        "fwd_urg_flags": float(row.fwd_urg),
        "fwd_header_len": float(row.fwd_hdr_bytes),
        "bwd_header_len": float(row.bwd_hdr_bytes),
        "init_win_bytes_fwd": float(row.init_win_fwd or 0),
        "init_win_bytes_bwd": float(row.init_win_bwd or 0),
        "fwd_seg_size_avg": row.fwd_bytes / row.fwd_pkts if row.fwd_pkts else 0.0,
        "bwd_seg_size_avg": row.bwd_bytes / row.bwd_pkts if row.bwd_pkts else 0.0,
        "active_mean": statistics.fmean(active_gaps) if active_gaps else 0.0,
        "idle_mean": statistics.fmean(idle_gaps) if idle_gaps else 0.0,
    }
    # per-source context appended last (order fixed by FEATURES)
    ctx = ctx or {}
    out["ctx_src_distinct_ports"] = float(ctx.get("distinct_ports", 0.0))
    out["ctx_src_conns"] = float(ctx.get("conns", 0.0))
    total = out["total_pkt_count"]
    out["ctx_src_synth_ratio"] = (
        out["syn_count"] / total if total else 0.0)
    return out


def source_context(flow_table, src: str, ts: float) -> Dict[str, float]:
    """Per-source fan-out context for one moment in time (runtime + training).

    Mirrors the behaviour detector's windows so the ML stage reads the exact
    numbers the rule engine sees.
    """
    try:
        source = flow_table.source(src)
    except Exception:                                 # noqa: BLE001
        return {"distinct_ports": 0.0, "conns": 0.0}
    cutoff = ts - CTX_WINDOW_S
    ports = {port for t, (_proto, port) in source.new_syn_ports_events
             if t >= cutoff and t <= ts}
    ports |= {port for t, (_proto, port) in source.udp_dst_ports
              if t >= cutoff and t <= ts}
    conns = sum(1 for t, _meta in source.new_syn_ports_events
                if t >= cutoff and t <= ts)
    return {"distinct_ports": float(len(ports)), "conns": float(conns)}


def features_vector(feature_dict: Dict[str, float]) -> list:
    """Ordered vector in exactly FEATURES order (for model.predict)."""
    return [float(feature_dict.get(name, 0.0)) for name in FEATURES]
