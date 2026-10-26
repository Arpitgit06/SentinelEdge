"""Local feedback learning (stretch goal).

Records the owner's Allow-once / blocklist / allowlist clicks (already in the
event log's user_actions table) and, when enough labelled feedback exists,
retrains the flow classifier on-device — nothing is uploaded.

The retraining uses the exported flow CSVs (tools/pcap_to_flows.py) plus the
feedback store. It stays deliberately disabled (config.feedback.enabled)
until the owner opts in.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

from ..config import FeedbackConfig


class FeedbackStore:
    """Tiny sqlite: (ts, target, action, pre_verdict_stage)."""

    def __init__(self, db_path: Path, config: Optional[FeedbackConfig] = None):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS feedback ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " ts REAL NOT NULL, target TEXT NOT NULL, action TEXT NOT NULL,"
            " context TEXT)")
        self._conn.commit()
        self.config = config

    def record(self, target: str, action: str, context: Optional[dict]
               ) -> None:
        self._conn.execute(
            "INSERT INTO feedback (ts, target, action, context) VALUES (?,?,?,?)",
            (time.time(), target, action,
             json.dumps(context or {}, default=str)))
        self._conn.commit()

    def counts(self) -> Dict[str, int]:
        rows = self._conn.execute(
            "SELECT action, COUNT(*) FROM feedback GROUP BY action").fetchall()
        return {a: c for a, c in rows}

    def maybe_retrain(self, flow_csvs: list, model_out: Path) -> bool:
        """Retrain when enough feedback exists (threshold-guarded)."""
        counts = self.counts()
        total = sum(counts.values())
        min_events = (self.config.min_events_retrain if self.config else 100)
        if total < min_events:
            return False
        from ..ml.train import run_training_from_csvs
        try:
            run_training_from_csvs(flow_csvs, model_out,
                                   prefer="lightgbm")
            self.record("model", "retrain_done",
                        {"events": total, "model": str(model_out)})
            return True
        except Exception:                           # noqa: BLE001
            return False
