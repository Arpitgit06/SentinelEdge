"""Unit tests — pipeline core (run: python -m pytest tests/ or python tests/test_engine.py)."""

import os
import struct
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinel.packets import parse_ip, TcpInfo                          # noqa
from sentinel.pipeline import DecisionEngine, Verdict                    # noqa
from sentinel.pipeline.protocol import ProtocolStage                     # noqa
from sentinel.pipeline.signatures import SignatureStage                  # noqa
from sentinel.pipeline.behaviour import BehaviourStage                   # noqa
from sentinel.pipeline.reputation import ReputationStage                 # noqa
from sentinel.flows.features import FEATURES, flow_row_to_feature_dict   # noqa
from sentinel.flows.flow_table import FlowTable                          # noqa
from sentinel.config import default_config                               # noqa
from sentinel.reputation_store import ReputationStore                    # noqa


def ip4(total, proto, src, dst):
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1234, 0x4000, 64,
                       proto, 0, src, dst)


def tcp_hdr(sport, dport, flags, payload=b""):
    return struct.pack("!HHIIHHHH", sport, dport, 0, 0, (5 << 12) | flags,
                       1024, 0, 0) + payload


def fresh_engine():
    cfg = default_config()
    cfg.reputation.enabled = False     # isolated stage tests
    return DecisionEngine(cfg)


def test_parser_syn():
    buf = ip4(40, 6, bytes([203, 0, 113, 10]), bytes([192, 168, 1, 50])) + \
        tcp_hdr(55431, 22, 0x02)
    pkt = parse_ip(buf, ts=0.5)
    assert pkt is not None and pkt.tcp.syn and pkt.dst == "192.168.1.50"


def test_protocol_illegal_combos():
    stage = ProtocolStage(default_config().protocol)
    for flags, name in ((0x03, "SYN+FIN"), (0x0A, "SYN+PSH"),
                        (0x22, "SYN? x"), (0x42, "SYN+E")):
        buf = ip4(40, 6, bytes([198, 51, 100, 5]), bytes([192, 168, 1, 9])) + \
            tcp_hdr(55431, 22, flags)
        result = stage.inspect(parse_ip(buf, ts=0.1), None)
        if name == "SYN? x":
            continue
        if flags in (0x03, 0x0A):
            assert result is not None and result.verdict == "block"


def test_signature_matches_and_benign_clear():
    cfg = default_config().signatures
    stage = SignatureStage(cfg)
    attack = b"GET /?f=../../etc/passwd HTTP/1.1"
    pkt = parse_ip(ip4(40 + len(attack), 6, bytes([198, 51, 100, 5]),
                       bytes([192, 168, 1, 9])) +
                   tcp_hdr(55431, 80, 0x18, attack), ts=0.1)
    r = stage.inspect(pkt, None)
    assert r is not None and r.verdict == "block"
    benign = b"GET /index.html HTTP/1.1\r\n\r\n"
    pkt2 = parse_ip(ip4(40 + len(benign), 6, bytes([198, 51, 100, 5]),
                        bytes([192, 168, 1, 9])) +
                    tcp_hdr(55431, 80, 0x18, benign), ts=0.2)
    assert stage.inspect(pkt2, None) is None


def test_port_scan_detection_thresholds():
    eng = fresh_engine()
    now = time.time() + 1000
    fired = None
    for i in range(30):
        buf = ip4(40, 6, bytes([198, 51, 100, 9]), bytes([192, 168, 1, 50])) + \
            tcp_hdr(51000 + i, 33000 + i, 0x02)
        verdict = eng.inspect(parse_ip(buf, ts=now + i * 0.5))
        if verdict.action == "block":
            fired = i
            break
    assert fired is not None and fired <= 21          # at the scan threshold


def test_bruteforce_detector():
    eng = fresh_engine()
    now = time.time() + 2000
    fired = None
    for i in range(45):
        buf = ip4(40, 6, bytes([198, 51, 100, 66]), bytes([192, 168, 1, 50])) + \
            tcp_hdr(50000 + i, 22, 0x02)
        verdict = eng.inspect(parse_ip(buf, ts=now + i))
        if verdict.action == "block":
            fired = i
            break
    assert fired is not None and fired <= 41


def test_safety_loopback_dhcp_dns():
    eng = fresh_engine()
    now = time.time() + 3000
    lb = parse_ip(ip4(40, 6, bytes([127, 0, 0, 1]), bytes([127, 0, 0, 1])) +
                  tcp_hdr(5000, 22, 0x02), ts=now)
    assert eng.inspect(lb).action == "allow"
    dhcp = parse_ip(ip4(40, 17, bytes([0, 0, 0, 0]), bytes([255, 255, 255, 255]))
                    + struct.pack("!HHHH", 68, 67, 20, 0), ts=now + 1)
    assert eng.inspect(dhcp).action == "allow"
    dns = parse_ip(ip4(40, 17, bytes([198, 51, 100, 5]), bytes([192, 168, 1, 50]))
                   + struct.pack("!HHHH", 52525, 53, 0, 0), ts=now + 2)
    assert eng.inspect(dns).action == "allow"


def test_allow_once_override():
    eng = fresh_engine()
    now = time.time() + 4000
    eng.allow_once.grant("198.51.100.7", ttl_seconds=60)
    buf = ip4(40, 6, bytes([198, 51, 100, 7]), bytes([192, 168, 1, 50])) + \
        tcp_hdr(40000, 22, 0x02)
    assert eng.inspect(parse_ip(buf, ts=now)).action == "allow"


def test_reputation_blocklist_hits():
    store = ReputationStore(bloom_m=1 << 18, bloom_k=5)
    store.add_ip("8.8.8.8")
    store.add_cidr("203.0.113.0/24")
    store.add_domain("evil.example.com")
    store.finalize()
    stage = ReputationStage(default_config().reputation, store=store)
    cfg = default_config()
    # trusted subnets: 198.51.100/24 passes without lookup
    pkt_clean = parse_ip(ip4(40, 6, bytes([198, 51, 100, 9]),
                             bytes([192, 168, 1, 50])) +
                         tcp_hdr(4000, 443, 0x02), ts=0.1)
    assert stage.inspect(pkt_clean, None) is None
    pkt_bad = parse_ip(ip4(40, 6, bytes([8, 8, 8, 8]), bytes([192, 168, 1, 50]))
                       + tcp_hdr(4000, 443, 0x02), ts=0.2)
    result = stage.inspect(pkt_bad, None)
    assert result is not None and result.verdict == "block"


def test_feature_vector_shape_and_finiteness():
    ft = FlowTable()
    now = time.time() + 5000
    for i in range(12):
        buf = ip4(40, 6, bytes([198, 51, 100, 5]), bytes([192, 168, 1, 50])) + \
            tcp_hdr(51000, 443, 0x18 if 0x18 else 0x02, b"x" * (10 + i))
        ft.update(parse_ip(buf, ts=now + i * 0.25))
    key = (6, "198.51.100.5", 51000, "192.168.1.50", 443)   # flow_key format
    row = ft.flows[key]
    fdict = flow_row_to_feature_dict(row)
    assert set(fdict) == set(FEATURES)
    assert len(list(fdict)) == len(FEATURES)
    for value in fdict.values():
        assert isinstance(value, float) and value == value  # no NaN


def test_engine_fail_open_on_stage_exception():
    eng = fresh_engine()

    class Boom:
        name = "boom"
        order = 1

        def inspect(self, pkt, ctx):
            raise RuntimeError("test fault")

    eng.stages.insert(0, Boom())
    buf = ip4(40, 6, bytes([203, 0, 113, 7]), bytes([192, 168, 1, 50])) + \
        tcp_hdr(4000, 443, 0x02)
    verdict = eng.inspect(parse_ip(buf, ts=1.0))
    assert verdict.fail_open and verdict.action == "allow"


def test_event_log_roundtrip(tmp_path=None):
    from sentinel.storage.event_log import EventLog
    eng = fresh_engine()
    buf = ip4(40, 6, bytes([203, 0, 113, 7]), bytes([192, 168, 1, 50])) + \
        tcp_hdr(4040, 443, 0x02)
    verdict = eng.inspect(parse_ip(buf, ts=1.0))
    d = tmp_path or tempfile.mkdtemp()
    log = EventLog(Path(d) / "events.db")
    rid = log.record(verdict, plain_text="demo markup")
    row = log.get(rid)
    assert row and row["reason"] == verdict.reason and row["plain"]
    log.record_user_action(rid, "allow_once", "203.0.113.7", 300)
    assert log.query(limit=5)
    stats = log.stats()[verdict.action]
    assert stats >= 1


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items())
             if k.startswith("test_") and callable(v)]
    failed = 0
    for tst in tests:
        try:
            tst()
            print(f"[pass] {tst.__name__}")
        except Exception as exc:                    # noqa: BLE001
            failed += 1
            print(f"[FAIL] {tst.__name__}: {exc}")
            import traceback; traceback.print_exc()
    print(f"{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
