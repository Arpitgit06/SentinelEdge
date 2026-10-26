"""Convert pcaps to flow-feature CSVs using the RUNTIME FlowTable.

This is the feature-parity pipeline: pcap -> our flow table (the same code
that feeds runtime inference) -> labeled CSV -> training. Public CIC CSVs are
the supplement, not the primary path (see datasets.py).

    python tools/pcap_to_flows.py attack.pcap --label scan --capture labA
    python tools/pcap_to_flows.py benign/*.pcap --label benign --out all.csv
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from sentinel.flows.features import FEATURES, flow_row_to_feature_dict  # noqa: E402
from sentinel.flows.flow_table import FlowTable                         # noqa: E402
from sentinel.packets import parse_ip                                   # noqa: E402


def pcap_to_flow_rows(pcap_path: Path, table: FlowTable) -> List[dict]:
    from scapy.all import rdpcap
    from scapy.compat import raw as scapy_raw
    packets = rdpcap(str(pcap_path))
    for pkt in packets:
        try:
            frame = bytes(scapy_raw(pkt))
        except Exception:                            # noqa: BLE001
            continue
        start = _ip_offset(frame)
        buf = frame[start:]
        ts = float(getattr(pkt, "time", 0.0))
        meta = parse_ip(buf, ts=ts, direction="in")
        if meta is None:
            continue
        meta.raw = buf
        table.update(meta)
    # one row per completed flow, with per-source context at the flow's
    # last-packet timestamp (same counters the runtime ML stage reads)
    from sentinel.flows.features import source_context
    rows = []
    for key, flow in table.flows.items():
        ctx = source_context(table, flow.src, flow.t_last)
        features = flow_row_to_feature_dict(flow, ctx=ctx)
        features.update({
            "src": flow.src, "dst": flow.dst, "dport": flow.dport,
            "proto": flow.proto,
        })
        rows.append(features)
    return rows


def _guess_outbound(buf: bytes, ts: float):
    """For outbound-only captures both directions have same src=host; keep
    symmetric parse by treating as inbound (works: initiating side is fwd)."""
    return None


def _ip_offset(buf: bytes) -> int:
    if len(buf) >= 14 and buf[12:14] == b"\x08\x00":
        return 14
    if len(buf) >= 14 and buf[12:14] == b"\x86\xdd":
        return 14
    if len(buf) >= 18 and buf[16:18] == b"\x86\xdd":
        return 18
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcaps", nargs="+")
    parser.add_argument("--label", default="unknown",
                        help="label for all pcaps (benign|scan|flood|...) "
                        "or 'auto' to infer from pcap filenames")
    parser.add_argument("--capture", default=None,
                        help="session id (default: shared for all args)")
    parser.add_argument("--out", default="data/flows/flows.csv")
    args = parser.parse_args()
    import pandas as pd
    rows = []
    for i, pcap_arg in enumerate(args.pcaps):
        path = Path(pcap_arg)
        if not path.exists():
            print(f"[skip] missing {path}")
            continue
        label = args.label
        if label.lower() == "auto":
            stem = path.stem.lower()
            label = "unknown"
            for candidate, mapped in (
                    ("benign", "benign"), ("port_scan", "scan"),
                    ("slow_scan", "scan"), ("syn_flood", "flood"),
                    ("brute_force", "bruteforce"),
                    ("web_injection", "injection"),
                    ("malformed", "malformed")):
                if candidate in stem:
                    label = mapped
                    break
        capture_id = args.capture or path.stem
        table = FlowTable()
        flow_rows = pcap_to_flow_rows(path, table)
        for row in flow_rows:
            row["label"] = label
            row["capture"] = capture_id
        rows.extend(flow_rows)
        print(f"[ok] {path.name}: {len(flow_rows)} flows (label={label})")
    if not rows:
        print("no flows extracted")
        return 1
    df = pd.DataFrame(rows)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    # ordered columns: FEATURES, then metadata
    cols = FEATURES + ["src", "dst", "dport", "proto", "label", "capture"]
    df = df[cols]
    df.to_csv(out, index=False)
    print(f"saved {len(df)} rows -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
