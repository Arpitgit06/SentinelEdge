"""Enrichment facade: one async call that fills WHOIS/RDAP + GeoIP + OS hint
+ secret reputation APIs (only the free sources run when no keys provided).

Called for blocked/quarantined events only (off the packet path); results are
merged back into the event row and pushed to any live subscribers.
"""

from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Optional

from .cache import IntelCache
from .whois_rdap import rdap_lookup, reverse_dns
from .geoip import geo_lookup
from .reputation_api import (abuseipdb_check, greynoise_check,
                             virustotal_check, otx_check, key_status)

_EXECUTOR: Optional[ThreadPoolExecutor] = None
_INFLIGHT: set = set()                       # ips being enriched right now
_INFLIGHT_LOCK = threading.Lock()
_MAX_INFLIGHT = 32                           # slow lane overloads -> drop


def _executor() -> ThreadPoolExecutor:
    global _EXECUTOR
    if _EXECUTOR is None:
        _EXECUTOR = ThreadPoolExecutor(
            max_workers=2, thread_name_prefix="sentinel-intel")
    return _EXECUTOR


def enrich_async(ip: str, cache: IntelCache, cfg,
                 on_done: Optional[Any] = None) -> Optional[Any]:
    """Fetch intel on the bounded background pool; call on_done(intel).

    Bounds are deliberate: a flood of blocked packets must not spawn a
    thread-per-verdict (it used to); duplicate IPs enqueue once and
    overloaded slow lanes are dropped silently (enrichment is best-effort).
    """
    ip = (ip or "").strip()
    if not ip:
        return None
    with _INFLIGHT_LOCK:
        if ip in _INFLIGHT or len(_INFLIGHT) >= _MAX_INFLIGHT:
            return None
        _INFLIGHT.add(ip)

    def _run() -> None:
        try:
            result = gather_intel_sync(ip, cache, cfg)
            if on_done:
                on_done(result)
        except Exception:                            # noqa: BLE001
            pass
        finally:
            with _INFLIGHT_LOCK:
                _INFLIGHT.discard(ip)

    try:
        return _executor().submit(_run)
    except Exception:                                # noqa: BLE001
        with _INFLIGHT_LOCK:
            _INFLIGHT.discard(ip)
        return None


def gather_intel_sync(ip: str, cache: IntelCache, cfg) -> Dict[str, Any]:
    """Blocking enrichment (exercised by tools/dashboard/enrich_async)."""
    key = f"ip:{ip}"
    hit = cache.get(key)
    if hit is not None:
        return hit
    out: Dict[str, Any] = {"ip": ip}
    # 1. registry facts (owner, country, abuse contact, ASN)
    rdap = rdap_lookup(ip, timeout_s=cfg.rdap_timeout_s)
    out.update(rdap if rdap else {})
    # 2. reverse dns (never a connection to the source)
    rdns = reverse_dns(ip, timeout_s=cfg.dns_reverse_timeout_s)
    if rdns:
        out["rdns"] = rdns
    # 3. geo
    geo = geo_lookup(ip, mmdb=cfg.geoip_mmdb, allow_web=cfg.allow_web_geo_fill,
                     timeout_s=cfg.web_geo_timeout_s)
    if geo and (out.get("country") in ("", None, "unknown")):
        out["country"] = geo.get("country") or out.get("country") or ""
    if geo.get("city"):
        out["city"] = geo["city"]
    if geo.get("isp") and not out.get("owner"):
        out["owner"] = geo["isp"]
    # 4. optional secret keys
    keys = key_status()
    if keys.get("abuseipdb"):
        out.update(abuseipdb_check(ip, os.environ["ABUSEIPDB_API_KEY"]))
    if keys.get("greynoise"):
        out.update(greynoise_check(ip, os.environ["GREYNOISE_API_KEY"]))
    if keys.get("virustotal"):
        out.update(virustotal_check(ip, os.environ["VIRUSTOTAL_API_KEY"]))
    if keys.get("otx"):
        out.update(otx_check(ip, os.environ["OTX_API_KEY"]))
    # normalise a few fields for templates
    if out.get("abuse_reports") is not None:
        out["reputation_reports"] = out["abuse_reports"]
    out["keys_active"] = keys
    cache.put(key, out)
    return out
