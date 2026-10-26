"""GeoIP: offline MaxMind GeoLite2 first; optional web fallback (ip-api)."""

from __future__ import annotations

from pathlib import Path
from typing import Optional


def geo_lookup(ip: str, mmdb: Optional[Path] = None,
               allow_web: bool = True, timeout_s: float = 4.0) -> dict:
    """Return {'country': .., 'city': .., 'source': ..} with graceful empty."""
    out = {"country": "", "city": "", "source": "unavailable"}
    if mmdb and Path(mmdb).exists():
        try:
            import geoip2.database
            with geoip2.database.Reader(str(mmdb)) as reader:
                resp = reader.country(ip)
                out["country"] = resp.country.name or ""
                out["source"] = "GeoLite2 (offline)"
                return out
        except Exception:                            # noqa: BLE001
            pass
    if allow_web:
        try:
            import urllib.request, json as _json
            url = f"http://ip-api.com/json/{ip}?fields=country,city,isp"
            with urllib.request.urlopen(url, timeout=timeout_s) as resp:
                data = _json.loads(resp.read().decode("utf-8", errors="replace"))
            out["country"] = data.get("country") or ""
            out["city"] = data.get("city") or ""
            if data.get("isp"):
                out["isp"] = data["isp"]
            out["source"] = "ip-api.com"
            return out
        except Exception:                            # noqa: BLE001 — offline
            pass
    return out
