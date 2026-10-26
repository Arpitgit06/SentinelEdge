"""Evidence export bundles (stretch goal).

Given event ids, produce an abuse-report-ready zip: event JSON with evidence,
intel summaries, packet hashes, and a manifest. Everything stays local; the
zip is for the owner to send externally (abuse contact / CERT), matching the
proposal's "defensive response only: block, rate-limit, log and report".
"""

from __future__ import annotations

import hashlib
import json
import time
import zipfile
from pathlib import Path
from typing import Iterable, Optional


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def export_events(event_log, event_ids: Iterable[int], out_dir: Path,
                  include_packet_hex: bool = True) -> Optional[Path]:
    rows = []
    ids = list(event_ids)
    if not ids:
        return None
    for eid in ids:
        row = event_log.get(eid)
        if row is None:
            continue
        events = {
            "id": row["id"], "ts": row["ts"], "iso": row["iso"],
            "action": row["action"], "stage": row["stage"],
            "src": row["src"], "dst": row["dst"],
            "src_port": row["src_port"], "dst_port": row["dst_port"],
            "proto": row["proto"], "reason": row["reason"],
            "plain": row["plain"], "score": row["score"],
            "packet_hash": row["packet_hash"],
            "packet_len": row["packet_len"],
            "evidence": json.loads(row["evidence"] or "{}"),
            "intel": json.loads(row["intel"] or "{}"),
        }
        if include_packet_hex and row.get("meta"):
            try:
                blob = json.loads(row["meta"] or "{}")
                if "packet_hex" in blob:
                    events["packet_hex"] = blob["packet_hex"]
            except json.JSONDecodeError:
                pass
        rows.append(events)
    if not rows:
        return None
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    zip_path = out_dir / f"sentinel-evidence-{stamp}.zip"
    manifest = {
        "bundle": "Sentinel Edge evidence export",
        "created": time.strftime("%Y-%m-%d %H:%M:%S"),
        "event_count": len(rows),
        "bundle_sha256": None,
        "events": rows,
    }
    blob = json.dumps(manifest, indent=2, default=str).encode()
    manifest["bundle_sha256"] = _hash_bytes(blob)
    blob = json.dumps(manifest, indent=2, default=str).encode()
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", blob)
        zf.writestr("report.html", _summary_html(rows))
    return zip_path


def _summary_html(rows: list) -> str:
    import html
    trs = []
    for r in rows:
        intel = r.get("intel") or {}
        esc = lambda v: html.escape(str(v if v is not None else ""))  # noqa: E731
        trs.append(
            f"<tr><td>{esc(r.get('iso'))}</td><td>{esc(r.get('action'))}</td>"
            f"<td>{esc(r.get('src'))}</td><td>{esc(r.get('dst'))}:"
            f"{esc(r.get('dst_port'))}</td>"
            f"<td>{esc(r.get('reason'))}</td>"
            f"<td>{esc(intel.get('country', ''))} "
            f"{esc(intel.get('owner', ''))}</td>"
            f"<td>{esc(intel.get('abuse_contacts', ''))}"
            f"</td></tr>")
    return ("<html><body><h3>Sentinel Edge evidence report</h3>"
            "<table border=1><tr><th>time</th><th>action</th><th>src</th>"
            "<th>dst</th><th>reason</th><th>source country/org</th>"
            "<th>abuse contact</th></tr>" + "".join(trs) +
            "</table></body></html>")
