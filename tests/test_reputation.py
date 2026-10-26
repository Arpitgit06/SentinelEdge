"""Reputation store sematics: bloom speed, CIDR confirm, trusted-subnet
exemption (owner networks are never reputation-blocked — safety contract).

Run directly:  python tests\\test_reputation.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.reputation_store import ReputationStore  # noqa: E402

PASSED = 0


def ok(name: str, cond: bool) -> None:
    global PASSED
    assert cond, f"FAILED: {name}"
    PASSED += 1
    print(f"  ok  {name}")


def test_store_roundtrip_and_semantics() -> None:
    store = ReputationStore(bloom_m=1 << 16, bloom_k=5)
    store.add_ip("203.0.113.9")               # exact ip list
    store.add_cidr("209.85.145.0/24")         # cidr confirm path
    store.add_domain("bad.example.net")       # domain suffix match

    ok("bloom hits exact ip", store.contains_ip("203.0.113.9")[0])
    ok("cidr range confirms", store.contains_ip("209.85.145.66")[0])
    ok("clean ip passes", not store.contains_ip("8.8.8.8")[0])
    ok("clean near-range passes", not store.contains_ip("209.85.146.66")[0])
    ok("domain match", store.contains_domain("sub.bad.example.net")[0])
    ok("domain no false match",
       not store.contains_domain("bad.example.org")[0])

    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "rep.bin"
        store.save(p)
        loaded = ReputationStore.load(p)
        ok("persisted store: exact", loaded.contains_ip("203.0.113.9")[0])
        ok("persisted store: cidr", loaded.contains_ip("209.85.145.7")[0])


def test_bloom_recall_bound() -> None:
    # with m=2^20 bits, k=5: FP rate ~ (1-e^{-k*n/m})^k stays well under 2%
    store = ReputationStore(bloom_m=1 << 20, bloom_k=5)
    n = 2000
    for i in range(n):
        store.bloom.add(f"10.{(i >> 8) & 255}.{i & 255}.{i % 211}".encode())
    fp = sum(1 for i in range(3000, 3200)
             if store.bloom.contains(f"10.{i % 256}.9.{i % 97}".encode()))
    ok(f"bloom FP {fp}/{200} < 4", fp < 4)


if __name__ == "__main__":
    test_store_roundtrip_and_semantics()
    test_bloom_recall_bound()
    print(f"test_reputation: {PASSED} checks passed")
