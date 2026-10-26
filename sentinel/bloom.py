"""Bloom filter with FNV-1a + MD5 double hashing: microseconds per lookup.

Used by the reputation stage as a fast negative check: if the bloom says "not
present" the item is definite-non-member, so the packet proceeds immediately.
A bloom hit is then confirmed against the backing exact/CIDR sets, so false
positives never block legitimate traffic.
"""

from __future__ import annotations

import hashlib
import json
import math
import struct
from typing import Iterable, Tuple


def _fnv1a(data: bytes) -> int:
    h = 0x811C9DC5
    for b in data:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


class BloomFilter:
    """Fixed-size bit array bloom filter, serialisable to JSON/bitarray bytes."""

    __slots__ = ("m", "k", "bits", "n_items")

    def __init__(self, m: int = 1 << 24, k: int = 7, bits: bytearray = None):
        if bits is None:
            bits = bytearray((m + 7) // 8)
        self.m = m
        self.k = k
        self.bits = bits
        self.n_items = 0

    # -- core -------------------------------------------------------------
    def _positions(self, item: bytes) -> Tuple[int, ...]:
        h1 = _fnv1a(item)
        h2_raw = hashlib.md5(item).digest()
        h2 = struct.unpack("!I", h2_raw[:4])[0] | 1   # odd so step never zero
        return tuple((h1 + i * h2) % self.m for i in range(self.k))

    def add(self, item: bytes) -> None:
        for pos in self._positions(item):
            self.bits[pos >> 3] |= 1 << (pos & 7)
        self.n_items += 1

    def contains(self, item: bytes) -> bool:
        bits, m, k = self.bits, self.m, self.k
        h1 = _fnv1a(item)
        h2_raw = hashlib.md5(item).digest()
        h2 = struct.unpack("!I", h2_raw[:4])[0] | 1
        i = 0
        while i < k:
            pos = (h1 + i * h2) % m
            if not bits[pos >> 3] & (1 << (pos & 7)):
                return False
            i += 1
        return True

    # -- housekeeping -------------------------------------------------------
    def expected_false_positive_rate(self) -> float:
        if self.n_items == 0:
            return 0.0
        ratio = math.exp(-(self.k * self.n_items) / self.m)
        return math.pow(1 - ratio, self.k)

    def to_file(self, path) -> None:                     # type: ignore[no-untyped-def]
        """Serialize: header line (json) + raw bitarray."""
        header = json.dumps({"m": self.m, "k": self.k, "n": self.n_items})
        with open(path, "wb") as fh:
            fh.write(header.encode() + b"\n")
            fh.write(bytes(self.bits))

    @classmethod
    def from_file(cls, path):                            # type: ignore[no-untyped-def]
        with open(path, "rb") as fh:
            header = fh.readline()
            meta = json.loads(header.decode())
            bits = bytearray(fh.read())
        if len(bits) < (meta["m"] + 7) // 8:
            bits.extend(bytearray((meta["m"] + 7) // 8 - len(bits)))
        bf = cls(m=meta["m"], k=meta["k"], bits=bits)
        bf.n_items = meta.get("n", 0)
        return bf

    # -- bulk build ----------------------------------------------------------
    @classmethod
    def build(cls, items: Iterable[bytes], m: int, k: int) -> "BloomFilter":
        bf = cls(m=m, k=k)
        for item in items:
            bf.add(item)
        return bf


def optimal_params(expected_items: int, fp_rate: float = 1e-4
                   ) -> Tuple[int, int]:
    """Compute m bits and k hashes for desired FP rate (for autosizing)."""
    m = int(math.ceil(-expected_items * math.log(fp_rate) / (math.log(2) ** 2)))
    k = max(1, int(round((m / max(expected_items, 1)) * math.log(2))))
    return m, k
