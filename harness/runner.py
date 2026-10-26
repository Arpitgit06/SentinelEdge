"""Red-team replay harness.

Per the proposal, "a project feature": a Python driver generates each lab
scenario (or shells out to nmap/hping3/hydra when a lab VM provides them),
captures it as a labelled pcap, replays it through the firewall engine and
compares verdicts with labels -> recall, false positives, time to block.

Scenario set (from the proposal):
    port_scan, slow_scan, syn_flood, brute_force, web_injection,
    malformed_packets, benign_browsing
Runs in three modes:
    --mode build     generate synthetic scenario pcaps (scapy, no tooling)
    --mode replay    replay pcaps through the engine -> verdict report
    --mode lab       [Kali VM] drive real tools (nmap/hping3/hydra) — see docs
"""

from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from sentinel.capture.replay import replay_pcap, ReplayVerdict  # noqa: E402
from sentinel.config import default_config, ensure_dirs          # noqa: E402
from sentinel.pipeline.engine import DecisionEngine              # noqa: E402

DEFENDER_IP = "192.168.1.50"
# Lab source IPs chosen OUT of reputation lists (bogons/TEST-NET are listed):
# attacker must trip detectors, benign must legitimately pass reputation.
ATTACKER_IP = "209.85.145.1"      # clean public edge range for scenarios
ATTACKER2_IP = "209.85.145.66"    # second attacker for brute force
BENIGN_IP = "151.101.1.140"       # verified not in the loaded lists


# ---------------------------------------------------------------------------
# Synthetic pcap builder (mode=build): no external tools required
# ---------------------------------------------------------------------------
def build_pcap(path_out: Path, packets: List[Any]) -> None:
    from scapy.all import wrpcap
    wrpcap(str(path_out), packets)


def syn_packet(src, dst, sport, dport, ts, flags="S", seq=1000, ack=0,
               window=1024):
    from scapy.all import IP, TCP, Ether
    p = (Ether() / IP(src=src, dst=dst) /
         TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack,
             window=window))
    p.time = ts
    return p


def udp_packet(src, dst, sport, dport, payload, ts):
    from scapy.all import IP, UDP, Ether
    p = (Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) /
         bytes(payload))
    p.time = ts
    return p


def icmp_packet(src, dst, ts):
    from scapy.all import IP, ICMP, Ether
    p = Ether() / IP(src=src, dst=dst) / ICMP()
    p.time = ts
    return p


def http_packet(src, dst, sport: int, dport: int, payload: bytes, ts,
                flags="PA", seq=10, ack=20):
    from scapy.all import IP, TCP, Ether
    p = (Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport,
                                              flags=flags, seq=seq,
                                              ack=ack) / payload)
    p.time = ts
    return p


def tcp_composite(src, dst, sport, dport, ts, flags, payload=b""):
    from scapy.all import IP, TCP, Ether
    p = (Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport,
                                              flags=flags, seq=1000, ack=0,
                                              window=8192) / payload)
    p.time = ts
    return p


def scenario_port_scan(seconds: float = 4.0, ports: int = 60) -> List[Any]:
    out = []
    t = 0.0
    step = seconds / ports
    for i in range(ports):
        out.append(syn_packet(ATTACKER_IP, DEFENDER_IP, 51000 + i, 30000 + i,
                              t))
        t += step
    return out


def scenario_slow_scan(ports: int = 26, pct_s: float = 1.2) -> List[Any]:
    """Low-and-slow: 1.2 s/port -> beats the 30 s window button, still 25+ port."""
    out: List[Any] = []
    t = 0.0
    for i in range(ports):
        out.append(syn_packet(ATTACKER_IP, DEFENDER_IP, 52000 + i, 31000 + i,
                              t))
        t += pct_s
    return out


def scenario_syn_flood(rate_pps: int = 500, seconds: float = 1.0
                       ) -> List[Any]:
    n = int(rate_pps * seconds)
    step = seconds / max(1, n)
    return [syn_packet(ATTACKER_IP, DEFENDER_IP, 40000 + i, 80, i * step,
                       flags="S", window=1024) for i in range(n)]


def scenario_brute_force(attempts: int = 46, interval: float = 1.0
                         ) -> List[Any]:
    return [syn_packet(ATTACKER2_IP, DEFENDER_IP, 50000 + i, 22, i *
                       interval, flags="S") for i in range(attempts)]


def scenario_web_injection(sentences: List[str] = None) -> List[Any]:
    payloads: List[Tuple[str, str]] = sentences or [
        ("SELECT * FROM users UNION SELECT cardnumber FROM payments", "443"),
        ("GET /admin.php?path=../../etc/shadow HTTP/1.1", "80"),
        ("; cat /etc/passwd && echo done", "80"),
        ("sqlmap/1.5-test#stable", "80"),
    ]
    out = []
    t = 0.4
    for idx, (payload, port) in enumerate(payloads):
        out.append(http_packet(ATTACKER_IP, DEFENDER_IP, 55000 + idx,
                               int(port), payload.encode(), t))
        t += 0.2
    return out


def scenario_malformed() -> List[Any]:
    from scapy.all import IP, TCP, Ether
    t = 0.4
    out = []
    for flags in ("SF", "SP", "PC"):
        p = (Ether() / IP(src=ATTACKER_IP, dst=DEFENDER_IP) /
             TCP(sport=56000, dport=22, flags=flags, seq=10))
        out.append(p)
        t += 0.2
    return out


def scenario_benign(nav_seconds: float = 6.0) -> List[Any]:
    """Realistic-ish browsing: HTTPS handshakes, small HTTP conversations."""
    rng = random.Random(42)
    sites = [8, 22, 30, 40, 52]
    out: List[Any] = []
    t = 0.0
    for i in range(160):                       # 6 s of packets
        src = BENIGN_IP
        sport = rng.randint(49152, 60000)
        dport = 443 if i % 3 else 80
        if i % 4 == 0:                          # new connection (SYN)
            out.append(syn_packet(src, DEFENDER_IP, sport, dport, t))
        elif i % 4 == 1:
            out.append(syn_packet(DEFENDER_IP, src,
                                  dport if False else sport, dport if False else
                                  0, t, flags="SA") if False else
                       http_packet(DEFENDER_IP, src, dport, sport,
                                   b"HTTP/1.1 200 OK\r\n", t))
        elif i % 4 == 2:
            out.append(http_packet(src, DEFENDER_IP, sport, dport,
                                   b"GET / HTTP/1.1\r\nHost: i\r\n", t))
        else:
            out.append(http_packet(src, DEFENDER_IP, sport, dport,
                                   b"data" * rng.randint(8, 40), t))
        t += nav_seconds / 160
    return out


SCENARIOS = {
    "port_scan": (scenario_port_scan, "scan"),
    "slow_scan": (scenario_slow_scan, "scan"),
    "syn_flood": (scenario_syn_flood, "flood"),
    "brute_force": (scenario_brute_force, "bruteforce"),
    "web_injection": (scenario_web_injection, "injection"),
    "malformed_packets": (scenario_malformed, "malformed"),
    "benign_browsing": (scenario_benign, "benign"),
}


def mode_build(out_dir: Path, scenarios: List[str]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for name in scenarios:
        if name == "all":
            names = list(SCENARIOS)
        else:
            names = [name]
        for target in names:
            if target not in SCENARIOS:
                print(f"[skip] unknown scenario {target}")
                continue
            builder, label = SCENARIOS[target]
            packets = builder()
            path = out_dir / f"{target}.pcap"
            build_pcap(path, packets)
            print(f"[build] {target}: {len(packets)} packets -> "
                  f"{path} (label={label})")


# ---------------------------------------------------------------------------
# Replay mode: engine verdicts vs labels
# ---------------------------------------------------------------------------
def expected_for(label: str) -> str:
    return {"benign": "allow"}.get(label, "block")


def mode_replay(pcap_dir: Path, engine_factory, report_path: Optional[Path]
                ) -> dict:
    rows = []
    for pcap_path in sorted(pcap_dir.glob("*.pcap")):
        stem_head = pcap_path.stem.split("_")[0]
        label = {
            "port": "scan", "slow": "scan", "syn": "flood",
            "brute": "bruteforce", "web": "injection",
            "malformed": "malformed", "benign": "benign",
        }.get(stem_head, "unknown")
        expected = expected_for(label)
        engine = engine_factory()                  # fresh state per lab run
        verdicts = replay_pcap(pcap_path, engine)
        # time-to-block: pcap ts delta from first attack packet to first block
        first_ts = verdicts[0].ts if verdicts else 0.0
        first_block_ts = next((v.ts for v in verdicts
                               if v.action == "block"), None)
        blocked = sum(1 for v in verdicts if v.action == "block")
        benign_flagged = (label == "benign" and blocked)
        detected = (expected == "block" and blocked > 0)
        t_rules = [v for v in verdicts if v.stage == "behaviour"]
        rows.append({
            "pcap": pcap_path.name, "label": label, "expected": expected,
            "packets": len(verdicts), "blocked": blocked,
            "detected": detected,
            "false_positive": benign_flagged,
            "time_to_block_s": (first_block_ts - first_ts
                                if first_block_ts is not None else None),
            "first_block_reason": next((v.reason for v in verdicts
                                        if v.action == "block"), ""),
        })
    correct = sum(1 for r in rows if r["detected"] or
                  (r["label"] == "benign" and not r["blocked"]))
    fp_count = sum(1 for r in rows if r["false_positive"])
    ttb = [r["time_to_block_s"] for r in rows
           if r["time_to_block_s"] is not None]
    report = {
        "scenarios": rows,
        "detection_rate": correct / len(rows) if rows else 0.0,
        "false_positive_scenarios": fp_count,
        "median_time_to_block_s": (round(statistics.median(ttb), 3)
                                   if ttb else None),
    }
    print(json.dumps(report, indent=2))
    if report_path:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2))
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["build", "replay", "lab"],
                        default="replay")
    parser.add_argument("--scenarios", default="all",
                        help="comma list or 'all' (build mode)")
    parser.add_argument("--pcap-dir", default="data/harness/pcaps")
    parser.add_argument("--report", default="data/harness/reports/report.json")
    args = parser.parse_args()
    cfg = default_config()
    ensure_dirs(cfg)
    if args.mode == "build":
        names = args.scenarios.split(",")
        mode_build(Path(args.pcap_dir), names)
        return 0
    if args.mode == "replay":
        rep_path = Path("data/blocklists/reputation.bin")

        def engine_factory():
            from sentinel.pipeline.engine import DecisionEngine as E
            e = E(cfg)
            if rep_path.exists():
                from sentinel.reputation_store import ReputationStore
                e.set_reputation_store(ReputationStore.load(rep_path))
            return e

        created = engine_factory()          # warm the store (files loaded)
        report = mode_replay(Path(args.pcap_dir), engine_factory,
                             Path(args.report))
        return 0 if (report["detection_rate"] >= 1.0 and
                     report["false_positive_scenarios"] == 0) else 1
    print("lab mode: see docs/lab-setup.md for Kali VM scenario commands")
    return 0


if __name__ == "__main__":
    sys.exit(main())
