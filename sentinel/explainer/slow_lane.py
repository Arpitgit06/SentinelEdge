"""Slow-lane explainer (stretch goal) — the proposal's optional LLM.

Runs OFF the packet path: given a finished event's evidence bundle, produce a
more natural explanation. Order of preference:
  1. evidence-based template text (always available, already plain language)
  2. local small LM via an OpenAI-compatible endpoint (Ollama / LM Studio)
  3. local ONNX MobileBERT/DistilBERT-class model if one is provisioned

Never called on the packet path: only the dashboard and post-hoc triage use
this. The detector decision cites the stage reason; the explainer only adds
narrative.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

from sentinel.alerts.templates import build_alert_text


def explain_with_local_lm(prompt: str, base_url: str, model: str,
                          timeout_s: float = 8.0) -> Optional[str]:
    """Ollama-style local endpoint; returns None on any failure."""
    try:
        import urllib.request
        body = json.dumps({
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.2, "num_predict": 160},
        }).encode()
        req = urllib.request.Request(
            f"{base_url.rstrip('/')}/api/generate", data=body,
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        return data.get("response") or None
    except Exception:                               # noqa: BLE001 — off-path optionality
        return None


def explain_event(verdict_or_event: Any,
                  slowlane_cfg: Any = None,
                  intel: Optional[Dict[str, Any]] = None) -> str:
    """Return the finished, human explanation for an event.

    Template first (the proposal: alert text from templates filled with the
    detector's own evidence); local LM only optionally enriches afterward.
    """
    base = build_alert_text(verdict_or_event, intel=intel)
    if slowlane_cfg is None or not getattr(slowlane_cfg, "enabled", False):
        return base
    url = getattr(slowlane_cfg, "local_model_url", None)
    if not url:
        return base
    prompt = (
        "Rewrite this firewall alert for a non-technical user. Be warm, "
        "specific, and under 80 words. Do not invent facts.\n\n" +
        base + "\n\nEvidence JSON: " +
        json.dumps(getattr(verdict_or_event, "evidence", {}), default=str))
    refined = explain_with_local_lm(prompt, url, getattr(
        slowlane_cfg, "model_name", "tinyllama"),
        timeout_s=getattr(slowlane_cfg, "timeout_s", 8.0))
    return refined or base
