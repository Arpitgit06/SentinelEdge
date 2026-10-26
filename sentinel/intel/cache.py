"""Intel cache: TTL cache so every enrichment result is computed once per IP."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional


class IntelCache:
    """SQLite-backed TTL cache for enrichment lookups."""

    def __init__(self, db_path: Path, ttl_hours: float = 12.0):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.execute("CREATE TABLE IF NOT EXISTS intel_cache ("
                           " key TEXT PRIMARY KEY,"
                           " value TEXT NOT NULL,"
                           " stored REAL NOT NULL,"
                           " expires REAL NOT NULL)")
        self._conn.commit()
        self.ttl_s = max(0.05, float(ttl_hours) * 3600.0)

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        cur = time.time()
        with self._lock:
            row = self._conn.execute(
                "SELECT value, expires FROM intel_cache WHERE key = ?",
                (key,)).fetchone()
        if row is None:
            return None
        if row[1] < cur:
            with self._lock:
                self._conn.execute("DELETE FROM intel_cache WHERE key = ?", (key,))
                self._conn.commit()
            return None
        try:
            return json.loads(row[0])
        except json.JSONDecodeError:
            return None

    def put(self, key: str, value: Dict[str, Any]) -> None:
        now = time.time()
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO intel_cache (key, value, stored, expires)"
                " VALUES (?,?,?,?)",
                (key, json.dumps(value, default=str), now, now + self.ttl_s))
            self._conn.commit()

    def delete(self, key: str) -> None:
        """Locked delete (dashboard refresh path)."""
        with self._lock:
            self._conn.execute("DELETE FROM intel_cache WHERE key = ?", (key,))
            self._conn.commit()

    def prune(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM intel_cache WHERE expires < ?",
                               (time.time(),))
            self._conn.commit()
