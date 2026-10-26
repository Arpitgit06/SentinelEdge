"""Fetch public blocklists and rebuild the Bloom-filter reputation store.

Default sources (free, plain text / netset):
    * FireHOL level1           — aggregated high-confidence bad IPs
    * Spamhaus DROP/EDROP      — hijacked netblocks
    * DShield block.txt        — most-recently offending networks
    * URLhaus text             — malware-hosting domains

Usage:
    python tools/update_blocklists.py            # defaults, ~24 h cadence
    python tools/update_blocklists.py --output data/blocklists/reputation.bin
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
import time
import urllib.request
from pathlib import Path
from typing import List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from sentinel.reputation_store import ReputationStore  # noqa: E402
from sentinel.bloom import optimal_params              # noqa: E402

DEFAULT_SOURCES = [
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "https://www.spamhaus.org/drop/drop.txt",
    "https://www.spamhaus.org/drop/edrop.txt",
    "https://www.dshield.org/block.txt",
    "https://raw.githubusercontent.com/curbengh/urlhaus-filter/master/urlhaus-filter-domains.txt",
]

SAMPLE_TEXTS = {
    # offline fallback so first-run demos work without connectivity
    "seed": [
        "203.0.113.0/24",              # TEST-NET-3 (lab-safe list seed)
        "198.51.100.0/24",             # TEST-NET-2
        "192.0.2.66",                  # example known-bad IP
        "malware.blockads.example.com",
        "c2.trafficdispatcher.example.com",
    ]
}


def _fetch(url: str, timeout_s: float = 15.0) -> str:
    req = urllib.request.Request(url, headers={
        "User-Agent": "SentinelEdge/0.1 (blocklist updater; local use)"})
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        text = resp.read().decode("utf-8", errors="replace")
    return text


def parse_netset(text: str) -> List[str]:
    """FireHOL netsets: comments start with '#', entries are IPs or CIDR."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        ipaddress.ip_network(line, strict=False)      # validation
        out.append(line)
    return out


def parse_drop(text: str) -> List[str]:
    """Spamhaus DROP: '1.2.3.0/24 ; SBL123456' style."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(";") or line.startswith("#"):
            continue
        net = line.split()[0]
        ipaddress.ip_network(net, strict=False)
        out.append(net)
    return out


def parse_dshield(text: str) -> List[str]:
    """DShield block.txt: 'start\tstop\tnetwork\tname' (skip header rows)."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            start = ipaddress.ip_address(parts[0])
            end = ipaddress.ip_address(parts[1])
        except ValueError:
            continue
        if int(end) >= int(start):
            range_size = int(end) - int(start) + 1
            if range_size & (range_size - 1) == 0:      # power-of-two range
                host_bits = (range_size - 1).bit_length()
                prefix = 32 - host_bits
                try:
                    out.append(str(ipaddress.ip_network(
                        f"{start}/{prefix}", strict=False)))
                    continue
                except ValueError:
                    pass
            out.append(str(start))
    return out


def parse_urlhaus(text: str) -> List[str]:
    """URLhaus abuse.ch downloads: plain list of malware domains/urls."""
    domains = []
    for line in text.splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        if "://" in entry:                        # url -> extract host
            entry = entry.split("://", 1)[1].split("/")[0]
        if ":" in entry.split("/")[0]:
            entry = entry.split(":")[0]
        if entry and "." in entry and " " not in entry:
            domains.append(entry)
    return domains


def build_store(sources: List[str], output_path: Path, timeout_s: float
                ) -> ReputationStore:
    store = ReputationStore()
    for url in sources:
        try:
            text = _fetch(url, timeout_s)
        except Exception as exc:                  # noqa: BLE001
            print(f"  [skip] {url}: {exc}")
            continue
        if "netset" in url:
            entries = parse_netset(text)
            for e in entries:
                store.add_cidr(e) if "/" in e else store.add_ip(e)
            print(f"  [ok]   {url}: {len(entries)} IPs/CIDRs")
        elif "drop" in url:
            entries = parse_drop(text)
            for e in entries:
                store.add_cidr(e)
            print(f"  [ok]   {url}: {len(entries)} CIDRs")
        elif "dshield" in url:
            entries = parse_dshield(text)
            for e in entries:
                store.add_cidr(e) if "/" in e else store.add_ip(e)
            print(f"  [ok]   {url}: {len(entries)} ranges")
        elif "urlhaus" in url:
            entries = parse_urlhaus(text)
            for d in entries:
                store.add_domain(d)
            print(f"  [ok]   {url}: {len(entries)} domains")
        else:
            # unknown feed: try permissive parse
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith(";"):
                    continue
                first = line.split()[0]
                if "/" in first:
                    store.add_cidr(first)
                elif "." in first:
                    try:
                        ipaddress.ip_address(first)
                        store.add_ip(first)
                    except ValueError:
                        store.add_domain(first)
    # Lab-safe offline seed when nothing was fetched (keeps demo/test working)
    if len(store.exact_ips) + len(store.cidr_starts) + len(store.domains) < 3:
        for line in SAMPLE_TEXTS["seed"]:
            if "/" in line:
                store.add_cidr(line)
            else:
                try:
                    ipaddress.ip_address(line)
                    store.add_ip(line)
                except ValueError:
                    store.add_domain(line)
    store.finalize()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    store.save(output_path)
    print(f"saved: {output_path}\nstats: {store.stats}")
    return store


def main(sources: List[str] = None, output: str = None) -> int:
    s_list = sources or DEFAULT_SOURCES
    out = Path(output) if output else (
        PROJECT_ROOT / "data" / "blocklists" / "reputation.bin")
    print("updating blocklists ...")
    started = time.time()
    store = build_store(s_list, out, timeout_s=15.0)
    print(f"done in {time.time() - started:.1f}s")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", nargs="*", default=None)
    parser.add_argument("--output", default=None)
    args = parser.parse_args()
    sys.exit(main(args.sources, args.output))
