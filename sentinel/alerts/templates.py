"""Plain-language alert templates.

The proposal is explicit: alert text such as "150 ports probed in 3 seconds
from one address" comes from templates filled with the detector's own
evidence. This module is self-contained (stdlib only) and used by:
  * OS notifications (allow-once toasts)
  * the local dashboard
  * the optional slow-lane model, which gets this text as its input
"""

from __future__ import annotations

from typing import Any, Dict, Optional

_ACTION_TEXT = {
    "block": "Blocked",
    "quarantine": "Suspicious traffic flagged (not blocked yet)",
    "allow": "Allowed",
}

_STAGE_DEVICE = {
    "reputation": "known-bad source reputation",
    "signatures": "payload signature match",
    "protocol": "protocol-sanity check",
    "behaviour": "connection-behaviour detector",
    "flow_ml": "ML flow classifier",
    "allow_once": "your Allow-once choice",
    "decision": "the decision engine",
}


def _describe_source(intel: Optional[Dict[str, Any]]) -> str:
    """Friendly ownership line, e.g. proposal's hosting-provider example."""
    if not intel:
        return ""
    bits = []
    org = intel.get("owner") or intel.get("rdap_name")
    country = intel.get("country")
    asorg = intel.get("asn_desc")
    reported = intel.get("abuse_reports") or intel.get("reputation_reports")
    if org:
        bits.append(str(org))
    elif asorg:
        bits.append(f"network {asorg}")
    if country:
        bits.append(f"in {country}")
    base = " Source: " + " ".join(bits) if bits else ""
    if reported:
        try:
            n = int(reported)
            base += f" ({n} abuse reports of this kind this week)"
        except (TypeError, ValueError):
            pass
    return base


def _evidence_line(evidence: Dict[str, Any]) -> str:
    """Compact human-evidence phrase from the detector's own data."""
    out = []
    if evidence.get("distinct_ports_count"):
        ports = evidence.get("distinct_ports_count")
        window = evidence.get("window_s")
        out.append(f"{ports} ports probed"
                   + (f" in {window} seconds" if window else ""))
    elif evidence.get("rate_syn_per_s"):
        out.append(f"{evidence['rate_syn_per_s']} half-open connections per second")
    elif evidence.get("rate_icmp_per_s"):
        out.append(f"{evidence['rate_icmp_per_s']} ping packets per second")
    elif evidence.get("conn_rate_per_s"):
        out.append(f"{evidence['conn_rate_per_s']} new connections per second")
    if evidence.get("attempts"):
        out.append(f"{evidence['attempts']} repeated login attempts"
                   + (f" to port {evidence['port']}" if evidence.get("port") else ""))
    if evidence.get("rule_id"):
        out.append(f"pattern '{evidence['rule_id']}'")
    if evidence.get("matched"):
        match = str(evidence["matched"])
        if len(match) > 48:
            match = match[:45] + "..."
        out.append(f"matched content: {match}")
    if evidence.get("list"):
        out.append(f"listed on {evidence['list']}")
    if evidence.get("qname"):
        out.append(f"lookup of '{evidence['qname']}'")
    if evidence.get("ml_score"):
        out.append(f"model score {evidence['ml_score']}")
    if not out:
        for key in ("flags",):
            if evidence.get(key):
                out.append(f"bad header flags {evidence[key]}")
    return ", ".join(out)


def build_alert_text(verdict, intel: Optional[Dict[str, Any]] = None) -> str:
    """The full plain-language alert shown to the owner."""
    action = _ACTION_TEXT.get(verdict.action, verdict.action.title())
    reason = verdict.reason or "unexplained activity"
    where = ""
    src_ip = "unknown source"
    src_port = ""
    if verdict.packet is not None:
        src_ip = verdict.packet.src
        src_port = f":{verdict.packet.sport}" if verdict.packet.sport else ""
        dst = verdict.packet.dst
        dport = verdict.packet.dport
        service = {80: "web", 443: "HTTPS", 22: "SSH", 3389: "RDP",
                   21: "FTP", 445: "SMB", 53: "DNS", 25: "SMTP"}.get(dport)
        if dst:
            where = (f" traffic to {dst}"
                     + (f" ({service})" if service else
                        (f" port {dport}" if dport else "")))
    body = (f"{action} from {src_ip}{src_port}{where}. "
            f"Reason ({verdict.stage}): {reason}. Evidence: "
            f"{_evidence_line(verdict.evidence) or 'n/a'}.")
    body += _describe_source(intel)
    return body


def short_title(verdict) -> str:
    """One-line title used in the OS notification."""
    action = {"block": "Blocked", "quarantine": "Suspicious traffic"
              }.get(verdict.action, verdict.action)
    if verdict.packet is None:
        return f"Sentinel Edge: {action}"
    reason_short = verdict.reason.split("(")[0].strip(" .")
    if len(reason_short) > 60:
        reason_short = reason_short[:57] + "..."
    return f"Sentinel Edge: {action} - {reason_short}"
