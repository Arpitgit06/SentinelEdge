"""RDAP/WHOIS + reverse DNS enrichment (no traffic sent to the source).

Combined from (in preference order):
  * ipwhois RDAP (auth network, ASN, country, abuse contacts) — installed
    optionally, falls back to plain rdap.org HTTP if the lib is missing.
  * reverse DNS: resolution only, never a connection to the sender.
All results cached; lookups run off-path (background thread on block events).
"""

from __future__ import annotations

import socket
from typing import Any, Dict, Optional


def reverse_dns(ip: str, timeout_s: float = 3.0) -> Optional[str]:
    try:
        import concurrent.futures as futmod
        with futmod.ThreadPoolExecutor(max_workers=1) as pool:
            result = pool.submit(socket.gethostbyaddr, ip)
            return result.result(timeout=timeout_s)[0]
    except Exception:                                # noqa: BLE001 — offline etc.
        return None


def _rdap_fallback(ip: str, timeout_s: float) -> Optional[Dict[str, Any]]:
    """Direct rdap.org request without ipwhois (stdlib urllib)."""
    import json as _json
    import urllib.request
    try:
        with urllib.request.urlopen(
                f"https://rdap.org/ip/{ip}", timeout=timeout_s) as resp:
            data = _json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception:                                # noqa: BLE001 — offline
        return None
    names, emails, countries = [], set(), []
    for ent in data.get("entities", []):
        vcard = ent.get("vcardArray")
        if vcard and len(vcard) > 1:
            for item in vcard[1]:
                if item and item[0] == "fn" and len(item) > 3:
                    names.append(str(item[3]))
                if item and item[0] == "email" and len(item) > 3:
                    emails.add(str(item[3]))
        roles = ent.get("roles", [])
        if any(r and r.lower() == "abuse" for r in roles):
            countries.append(str(ent.get("contact", {}).get("country", "")))
    return {
        "rdap_name": data.get("name") or "",
        "rdap_type": data.get("type") or "",
        "country": data.get("country") or (countries[0] if countries else ""),
        "owner": data.get("name") or (names[0] if names else ""),
        "abuse_contacts": sorted(emails)[:4],
        "source": "rdap.org",
    }


def rdap_lookup(ip: str, timeout_s: float = 6.0) -> Dict[str, Any]:
    """Rich registry info: owner (org name), country, abuse contact, ASN."""
    out: Dict[str, Any] = {}
    try:
        from ipwhois import IPWhois
        result = IPWhois(ip).lookup_rdap(depth=1, timeout=timeout_s,
                                         inc_countries=True)
        objects = result.get("objects") or {}
        abuse = []
        asn_desc = result.get("asn_description") or ""
        for cand in objects.values():
            contact = cand.get("contact") or {}
            emails = contact.get("email") or []
            if cand.get("roles") and any(
                    str(r).lower() == "abuse" for r in cand["roles"]):
                for e in emails if isinstance(emails, list) else [emails]:
                    if e and e not in abuse:
                        abuse.append(str(e))
        out.update({
            "owner": result.get("network", {}).get("name") or asn_desc,
            "rdap_name": result.get("network", {}).get("name") or "",
            "country": result.get("country") or "",
            "asn": result.get("asn"),
            "asn_desc": asn_desc,
            "abuse_contacts": abuse[:4],
            "source": "ipwhois",
        })
    except Exception:                                # noqa: BLE001 — lib/offline
        fb = _rdap_fallback(ip, timeout_s)
        if fb:
            out.update(fb)
        else:
            out = {"source": "unavailable", "owner": "unknown",
                   "country": "unknown"}
    if not out.get("asn_desc") and out.get("owner"):
        out.setdefault("asn_desc", out["owner"])
    return out
