"""Optional key-backed reputation APIs (AbuseIPDB, VirusTotal, GreyNoise, OTX).

Activated automatically when the matching env var is present:
    ABUSEIPDB_API_KEY   https://www.abuseipdb.com/ (free tier, 1k/day)
    VIRUSTOTAL_API_KEY  https://www.virustotal.com/  (free tier, 4/min)
    GREYNOISE_API_KEY   https://viz.greynoise.io/    (community; free signup)
    OTX_API_KEY         https://otx.alienvault.com/  (free signup)

Every result is cached by the caller (intel.cache) with WEEKLY TTL since these
APIs are rate-limited and slow — enrichment is never on the packet path.
"""

from __future__ import annotations

import os
from typing import Any, Dict

_TIMEOUT = 6.0


def abuseipdb_check(ip: str, api_key: str) -> Dict[str, Any]:
    """Confidence of abuse score, number of reports, categories."""
    import json as _json
    import urllib.request
    url = ("https://api.abuseipdb.com/api/v2/check?"
           f"ipAddress={ip}&maxAgeInDays=30")
    req = urllib.request.Request(url)
    req.add_header("Key", api_key)
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = _json.loads(resp.read()).get("data", {})
        return {
            "abuseipdb_score": data.get("abuseConfidenceScore"),
            "abuse_reports": data.get("totalReports"),
            "was_reported": data.get("isReported"),
            "categories": data.get("usageType"),
            "source": "AbuseIPDB",
        }
    except Exception:                                # noqa: BLE001 — network/offline
        return {"source": "AbuseIPDB", "error": "lookup failed"}


def greynoise_check(ip: str, api_key: str) -> Dict[str, Any]:
    """GreyNoise: does a real internet scanner 'own' this IP; common tags."""
    import json as _json
    import urllib.request
    req = urllib.request.Request(
        f"https://api.greynoise.io/v3/community/{ip}",
        headers={"key": api_key, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = _json.loads(resp.read())
        tags = [t.get("name") for t in (data.get("tags") or [])][:8]
        return {
            "greynoise_seen": data.get("noise"),
            "greynoise_classification": data.get("classification"),
            "greynoise_tags": tags,
            "source": "GreyNoise",
        }
    except Exception:                                # noqa: BLE001
        return {"source": "GreyNoise", "error": "lookup failed"}


def virustotal_check(ip: str, api_key: str) -> Dict[str, Any]:
    """File + domain reputation count for an IP (community API v3)."""
    import json as _json
    import urllib.request
    req = urllib.request.Request(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": api_key, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = _json.loads(resp.read()).get("data", {})
            stats = (data.get("attributes", {}).get("last_analysis_stats")
                     or {})
        malicious = stats.get("malicious", 0)
        return {"vt_malicious_engines": malicious,
                "source": "VirusTotal"}
    except Exception:                                # noqa: BLE001
        return {"source": "VirusTotal", "error": "lookup failed"}


def otx_check(ip: str, api_key: str) -> Dict[str, Any]:
    """AlienVault OTX indicator reputation (pulses, general info)."""
    import json as _json
    import urllib.request
    req = urllib.request.Request(
        f"https://otx.alienvault.com/api/v1/indicators/ipv4/{ip}/general",
        headers={"X-OTX-API-KEY": api_key, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = _json.loads(resp.read())
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        tags = (data.get("pulse_info", {}).get("pulses") or [{}])
        first = tags[0] if isinstance(tags, list) else {}
        return {"otx_pulse_count": pulse_count,
                "otx_tags": (first.get("tags") or [])[:6],
                "source": "AlienVault OTX"}
    except Exception:                                # noqa: BLE001
        return {"source": "AlienVault OTX", "error": "lookup failed"}


def key_status() -> dict:
    """Which optional API keys are present (dashboard shows this)."""
    return {
        "abuseipdb": bool(os.environ.get("ABUSEIPDB_API_KEY")),
        "virustotal": bool(os.environ.get("VIRUSTOTAL_API_KEY")),
        "greynoise": bool(os.environ.get("GREYNOISE_API_KEY")),
        "otx": bool(os.environ.get("OTX_API_KEY")),
    }
