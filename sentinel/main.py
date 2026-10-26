"""Sentinel Edge CLI.

Commands:
    firewall     run the live enforcement engine (admin required on Windows)
    dashboard    launch the local web dashboard only
    serve        run firewall + dashboard + optional honeypot together
    simulate     feed synthetic attack traffic into the engine (no driver;
                 validates the whole chain without admin/lab setup)
    replay       evaluate a pcap through the engine and print verdict stats
    update-blocklists  fetch public IP/domain blocklists, rebuild bloom store
    train        train the flow classifier from the data csv (see sentinel.ml)

Examples:
    python -m sentinel.main serve
    python -m sentinel.main simulate --scenario scan
    python -m sentinel.main replay data/harness/pcaps/scan.pcap
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import List, Optional

from .config import default_config, ensure_dirs


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")


def _build_and_start_service(cfg, with_dashboard: bool, with_honeypot: bool,
                             driver=None):
    from .service import FirewallService
    svc = FirewallService(cfg)
    svc.load_reputation()
    svc.load_model()
    if with_dashboard:
        import threading
        import uvicorn
        from .ui.server import create_app
        app = create_app(svc)

        def _serve_dashboard() -> None:
            uvicorn.run(app, host=cfg.dashboard.host,
                        port=cfg.dashboard.port, log_level="warning")

        threading.Thread(target=_serve_dashboard, name="sentinel-dashboard",
                         daemon=True).start()
        logging.getLogger(__name__).info(
            "dashboard on http://%s:%s", cfg.dashboard.host, cfg.dashboard.port)
    if with_honeypot:
        cfg.honeypot.enabled = True
    svc.start(driver=driver)
    return svc


def cmd_firewall(args: argparse.Namespace) -> int:
    cfg = default_config()
    ensure_dirs(cfg)
    _build_and_start_service(cfg, with_dashboard=False, with_honeypot=False)
    service_banner(cfg)
    keep_alive()
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    cfg = default_config()
    ensure_dirs(cfg)
    cfg.honeypot.enabled = True
    _build_and_start_service(cfg, with_dashboard=True, with_honeypot=True)
    service_banner(cfg)
    keep_alive()
    return 0


def cmd_dashboard(args: argparse.Namespace) -> int:
    cfg = default_config()
    ensure_dirs(cfg)
    from .service import FirewallService
    svc = FirewallService(cfg)
    svc.load_reputation()
    svc.load_model()
    from .ui.server import run_dashboard
    run_dashboard(svc, host=cfg.dashboard.host, port=cfg.dashboard.port)
    return 0


def cmd_simulate(args: argparse.Namespace) -> int:
    """Synthetic traffic through the FULL engine +99% pipeline (no driver)."""
    from .service import FirewallService
    from .packets import parse_ip
    import struct
    import time as _time
    cfg = default_config()
    ensure_dirs(cfg)
    cfg.intel.enabled = False                    # offline-friendly demo
    svc = FirewallService(cfg)
    svc.load_reputation()
    scenario = args.scenario
    now_base = _time.time() + 100
    local = bytes([192, 168, 1, 50])

    def tcp(sport, dport, flags, payload=b""):
        return struct.pack("!HHIIHHHH", sport, dport, 0, 0,
                           (5 << 12) | flags, 1024, 0, 0) + payload

    def syn_packet(src, sport, dport, i, ts):
        return parse_ip(struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, 40, i, 0x4000, 64, 6, 0, src, local)
            + tcp(sport, dport, 0x02), ts=ts)

    if scenario == "scan":
        print("[simulate] 25-port SYN scan from 198.51.100.9 ...")
        for i in range(25):
            p = parse_ip(struct.pack(
                "!BBHHHBBH4s4s", 0x45, 0, 40, i, 0x4000, 64, 6, 0,
                bytes([198, 51, 100, 9]), local)
                + tcp(51000 + i, 33000 + i, 0x02), ts=now_base + i * 0.5)
            v = svc.engine.inspect(p)
            print(f"  port probe #{i+1:>2} -> {v.action}"
                  + (f"  ({v.reason})" if v.action != "allow" else ""))
    elif scenario == "flood":
        print("[simulate] SYN flood towards 192.168.1.50:80 ...")
        for i in range(200):
            p = parse_ip(struct.pack(
                "!BBHHHBBH4s4s", 0x45, 0, 40, i, 0x4000, 64, 6, 0,
                bytes([198, 51, 100, 9]), local)
                + tcp(40000 + i, 80, 0x02), ts=now_base + i * 0.003)
            v = svc.engine.inspect(p)
            if v.action == "block":
                print(f"  flood blocked after {i+1} SYNs -> ({v.reason})")
                break
        else:
            print("  flood NOT blocked")
    elif scenario == "signatures":
        print("[simulate] path traversal exploit attempt ...")
        payload = b"GET /?file=../../etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n"
        p = parse_ip(struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp(55431, 80, 0x18, payload)),
            1234, 0x4000, 64, 6, 0, bytes([198, 51, 100, 9]), local)
            + tcp(55431, 80, 0x18, payload), ts=now_base)
        v = svc.engine.inspect(p)
        print(f"  -> {v.action} ({v.reason}; stage={v.stage})")
    elif scenario == "badflags":
        print("[simulate] SYN+FIN illegal combination ...")
        p = parse_ip(struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, 40, 0, 0x4000, 64, 6, 0,
            bytes([198, 51, 100, 9]), local) + tcp(55431, 22, 0x03),
            ts=now_base)
        v = svc.engine.inspect(p)
        print(f"  -> {v.action} ({v.reason}; stage={v.stage})")
    elif scenario == "bruteforce":
        print("[simulate] brute-force to SSH ...")
        for i in range(45):
            p = parse_ip(struct.pack(
                "!BBHHHBBH4s4s", 0x45, 0, 40, 9000 + i, 0x4000, 64, 6, 0,
                bytes([198, 51, 100, 66]), local)
                + tcp(50000 + i, 22, 0x02), ts=now_base + i)
            v = svc.engine.inspect(p)
            if v.action == "block":
                print(f"  brute force blocked after {i+1} attempts "
                      f"-> ({v.reason})")
                break
        else:
            print("  brute force NOT detected")
    else:
        print(f"unknown scenario {scenario} (scan|flood|signatures|badflags|"
              f"bruteforce)")
        return 2
    stats = svc.engine.stats_snapshot()
    print("engine stats:", stats)
    print("events written to:", cfg.storage.event_db)
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    cfg = default_config()
    cfg.intel.enabled = False               # offline replay: no enrichment
    ensure_dirs(cfg)
    from .service import FirewallService
    from .capture.replay import replay_pcap
    svc = FirewallService(cfg)
    svc.load_reputation()
    svc.load_model()
    svc.intel_enabled = False
    path = Path(args.pcap)
    if not path.exists():
        print(f"pcap not found: {path}")
        return 2
    verdicts = replay_pcap(path, svc.engine)
    blocked = [v for v in verdicts if v.action == "block"]
    print(f"packets: {len(verdicts)} | blocked: {len(blocked)} | "
          f"quarantined: {sum(1 for v in verdicts if v.action == 'quarantine')}")
    for v in blocked[:10]:
        print(f"  {v.ts:.2f} block {v.src} -> {v.dst}:{v.dport} "
              f"[{v.stage}] {v.reason[:60]}")
    return 0


def cmd_update_blocklists(args: argparse.Namespace) -> int:
    from tools.update_blocklists import main as updater
    return updater(args.sources, args.output)


def cmd_train(args: argparse.Namespace) -> int:
    from sentinel.ml.train import run_training
    return run_training(args)


def service_banner(cfg) -> None:
    print("=" * 64)
    print("Sentinel Edge — Local Adaptive Firewall is running")
    print(f"  safety   : loopback/DHCP/DNS always allowed; fail-open ON")
    print(f"  event log: {cfg.storage.event_db}")
    print(f"  dashboard: http://{cfg.dashboard.host}:{cfg.dashboard.port}")
    print("  stop     : Ctrl+C (WinDivert auto-reinjects queued packets)")
    print("=" * 64)


def keep_alive() -> None:
    try:
        while True:
            import time
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\nSentinel Edge stopped.")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel",
                                     description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--verbose", "-v", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("firewall", help="run enforcement engine only")
    sub.add_parser("dashboard", help="run local web dashboard only")
    sub.add_parser("serve", help="firewall + dashboard + honeypot")

    p_sim = sub.add_parser("simulate", help="synthetic attack through engine")
    p_sim.add_argument("--scenario", default="scan",
                       choices=["scan", "flood", "signatures", "badflags",
                                "bruteforce"])

    p_rep = sub.add_parser("replay", help="replay a pcap through the engine")
    p_rep.add_argument("pcap")

    p_upd = sub.add_parser("update-blocklists",
                           help="refresh known-bad lists + bloom filter")
    p_upd.add_argument("--sources", nargs="*", default=None)
    p_upd.add_argument("--output", default=None)

    p_tr = sub.add_parser("train", help="train flow ML classifier")
    p_tr.add_argument("--csv", required=True, nargs="+",
                      help="extracted flow csv path(s) — or raw CIC CSVs "
                           "with --cic")
    p_tr.add_argument("--out", default=None, help="model output path")
    p_tr.add_argument("--session-col", default="capture")
    p_tr.add_argument("--cic", action="store_true",
                      help="csvs are CIC-IDS2017/2018 flow CSVs "
                           "(header aliases map onto the FEATURES contract)")
    p_tr.add_argument("--model", default="lightgbm",
                      choices=("lightgbm", "random_forest"))

    args = parser.parse_args(argv)
    _setup_logging(args.verbose)
    commands = {
        "firewall": cmd_firewall, "dashboard": cmd_dashboard, "serve": cmd_serve,
        "simulate": cmd_simulate, "replay": cmd_replay,
        "update-blocklists": cmd_update_blocklists, "train": cmd_train,
    }
    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
