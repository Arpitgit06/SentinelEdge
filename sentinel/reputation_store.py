"""Reputation store: Bloom-filter-accelerated known-bad IP and domain lookups.

Contents:
  * exact IPs (and /24 bloom keys expanded from CIDR for the fast path)
  * CIDR ranges checked via sorted bisect (log-time, exact)
  * domains (FQDNs), checked for a DNS query name and its suffixes

`contains_ip(ip)` never produces false blocks: a bloom hit is always confirmed
against the exact backing set / CIDR list before a block verdict.
"""

from __future__ import annotations

import ipaddress
import struct
import bisect
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from sentinel.bloom import BloomFilter


def ip_to_int(ip: str) -> int:
    return struct.unpack("!I", ipaddress.ip_address(ip).packed)[0]


def ipv4_of(value: str) -> Optional[str]:
    try:
        addr = ipaddress.ip_address(value.strip())
        return None if addr.version != 4 else str(addr)
    except ValueError:
        return None


def cidr_of(line: str) -> Optional[ipaddress._BaseNetwork]:
    try:
        net = ipaddress.ip_network(line.strip(), strict=False)
        return net if net.version == 4 else None
    except ValueError:
        return None


class ReputationStore:
    """Backed by: exact_ip set, sorted CIDR list, domain set, bloom over all."""

    def __init__(self, bloom_m: int = 1 << 24, bloom_k: int = 7):
        self.bloom = BloomFilter(m=bloom_m, k=bloom_k)
        self.exact_ips: Set[int] = set()
        self.cidr_starts: List[int] = []
        self.cidr_ends: List[int] = []
        self.domains: Set[str] = set()
        self.stats: Dict[str, int] = {"exact_ips": 0, "cidr_ranges": 0, "domains": 0}

    # -- builders -----------------------------------------------------------
    def add_ip(self, ip: str) -> None:
        v = ipv4_of(ip)
        if v:
            self.exact_ips.add(ip_to_int(v))
            self.bloom.add(v.encode())

    def add_cidr(self, cidr: str) -> None:
        net = cidr_of(cidr)
        if net is None:
            return
        start = ip_to_int(str(net.network_address))
        end = ip_to_int(str(net.broadcast_address))
        self.cidr_starts.append(start)
        self.cidr_ends.append(end)
        # bloom /24 prefilter keys so a random hit can short-circuit (bisect decides)
        for prefix24 in self._prefix24s(net):
            self.bloom.add(prefix24.encode())

    @staticmethod
    def _prefix24s(net: ipaddress._BaseNetwork) -> List[str]:
        """Bloom keys "<a.b.c>.*" for every /24 subnet inside a CIDR (capped)."""
        if net.prefixlen < 24:
            return []                      # huge nets: keep bisect, no full warm
        keys = []
        base = ip_to_int(str(net.network_address))
        top = ip_to_int(str(net.broadcast_address))
        n_subnets = (top - base) // 256 + 1
        step = 256
        i = 0
        while i < n_subnets and i < 65536:        # hard cap of bloom pre-warm
            sub_net = ipaddress.ip_network(
                str(ipaddress.ip_address(base + i * step)) + "/24", strict=False)
            keys.append(str(sub_net.network_address).rsplit(".", 1)[0] + ".*")
            i += 1
        return keys

    def add_domain(self, domain: str) -> None:
        d = domain.strip().lower().strip(".")
        if d:
            self.domains.add(d)
            self.bloom.add(d.encode())

    def finalize(self) -> None:
        """Sort CIDR list for bisect lookups (call after bulk add)."""
        pairs = sorted(zip(self.cidr_starts, self.cidr_ends))
        self.cidr_starts = [p[0] for p in pairs]
        self.cidr_ends = [p[1] for p in pairs]
        self.stats = {"exact_ips": len(self.exact_ips),
                      "cidr_ranges": len(self.cidr_starts),
                      "domains": len(self.domains)}

    # -- lookups -------------------------------------------------------------
    def contains_ip(self, ip: str) -> Tuple[bool, str]:
        """-> (is_known_bad, evidence_source).

        Bloom is a pure accelerator here, never a gate: exact-IP membership is
        confirmed via the backing set, and CIDR membership via sorted bisect
        (log-time, still microseconds) so large networks can never miss.
        """
        v = ipv4_of(ip)
        if not v:
            return False, ""
        ival = ip_to_int(v)
        if self.bloom.contains(v.encode()) and ival in self.exact_ips:
            return True, "exact-IP blocklist"
        if ival in self.exact_ips:                      # belt + braces
            return True, "exact-IP blocklist"
        if self.cidr_starts:
            idx = bisect.bisect_right(self.cidr_starts, ival) - 1
            if idx >= 0 and self.cidr_ends[idx] >= ival:
                return True, "CIDR blocklist"
        return False, ""

    def contains_domain(self, domain: str) -> Tuple[bool, str]:
        """Check a DNS qname against known-bad domains (full + all suffixes)."""
        d = (domain or "").strip().lower().strip(".")
        if not d:
            return False, ""
        parts = d.split(".")
        # full name plus every suffix with >= 2 labels
        for i in range(0, max(1, len(parts) - 1)):
            candidate = ".".join(parts[i:])
            if self.bloom.contains(candidate.encode()) and candidate in self.domains:
                return True, "domain blocklist"
        return False, ""

    # -- persistence -----------------------------------------------------------
    def save(self, path: Path) -> None:
        """Save full state (bloom bits + backing sets) as a single gz binary."""
        import gzip
        import json
        payload = {
            "stats": self.stats,
            "bloom_m": self.bloom.m,
            "bloom_k": self.bloom.k,
            "exact_ips": sorted(self.exact_ips),
            "cidr": [[s, e] for s, e in zip(self.cidr_starts, self.cidr_ends)],
            "domains": sorted(self.domains),
        }
        with gzip.open(path, "wb") as fh:
            fh.write(json.dumps(payload).encode() + b"\n")
            fh.write(b"---BLOOM---\n")
            fh.write(bytes(self.bloom.bits))

    @classmethod
    def load(cls, path: Path) -> "ReputationStore":
        import gzip
        import json
        store = cls()
        with gzip.open(path, "rb") as fh:
            blob = fh.read()
        head, _, bits = blob.partition(b"\n---BLOOM---\n")
        meta = json.loads(head.decode())
        store.exact_ips = set(meta.get("exact_ips", []))
        store.cidr_starts = [x[0] for x in meta.get("cidr", [])]
        store.cidr_ends = [x[1] for x in meta.get("cidr", [])]
        store.domains = set(meta.get("domains", []))
        m = int(meta.get("bloom_m", 1 << 24))
        k = int(meta.get("bloom_k", 7))
        if bits:
            store.bloom = BloomFilter(m=m, k=k, bits=bytearray(bits))
        store.stats = meta.get("stats", {"exact_ips": 0, "cidr_ranges": 0, "domains": 0})
        return store
