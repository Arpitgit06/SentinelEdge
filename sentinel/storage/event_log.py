"""SQLite event log: searchable history with evidence per block.

Schema keeps every proposal-relevant field: verdict, stage, reason, the
plain-language alert text, structured evidence, intel summary, packet hash and
hex. Rowids are what the dashboard Allow-once button references.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           REAL NOT NULL,
    iso          TEXT NOT NULL,
    action       TEXT NOT NULL,          -- allow | block | quarantine
    stage        TEXT NOT NULL,
    src          TEXT, dst TEXT,
    src_port     INTEGER, dst_port INTEGER,
    proto        TEXT,
    reason       TEXT,
    plain        TEXT,                   -- plain-language alert text
    score        REAL,
    evidence     TEXT,                   -- json
    intel        TEXT,                   -- json (WHOIS/GeoIP/reputation)
    fail_open    INTEGER DEFAULT 0,
    packet_hash  TEXT,
    packet_len   INTEGER,
    meta         TEXT                    -- json free-form (user actions etc.)
);
CREATE INDEX IF NOT EXISTS idx_events_ts    ON events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_action ON events(action, ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_src   ON events(src);
CREATE INDEX IF NOT EXISTS idx_events_stage ON events(stage);
CREATE TABLE IF NOT EXISTS user_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL, event_id INTEGER,
    action TEXT NOT NULL,           -- allow_once | allowlist | blocklist
    target TEXT NOT NULL,
    ttl_seconds REAL
);
"""


def iso(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def packet_hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class EventLog:
    """Thread-safe wrapper over the events database."""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._conn:
            self._conn.executescript(_SCHEMA)

    # -- writing ------------------------------------------------------------
    def record(self, verdict, plain_text: str = "",
               intel: Optional[dict] = None, meta: Optional[dict] = None
               ) -> int:
        """Insert a verdict (engine Verdict) -> returns rowid."""
        pkt = verdict.packet
        raw = pkt.raw if pkt is not None else b""
        evidence = json.dumps(verdict.evidence, default=str)
        intel_json = json.dumps(intel or {}, default=str)
        meta_json = json.dumps(meta or {}, default=str)
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO events (ts, iso, action, stage, src, dst, src_port,"
                " dst_port, proto, reason, plain, score, evidence, intel,"
                " fail_open, packet_hash, packet_len, meta)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (verdict.ts, iso(verdict.ts), verdict.action, verdict.stage,
                 pkt.src if pkt else "", pkt.dst if pkt else "",
                 pkt.sport if pkt else None, pkt.dport if pkt else None,
                 pkt.proto_name if pkt else "other",
                 verdict.reason, plain_text, verdict.score, evidence,
                 intel_json, 1 if verdict.fail_open else 0,
                 packet_hash(raw) if raw else "", len(raw), meta_json))
            self._conn.commit()
            return int(cur.lastrowid)

    def record_user_action(self, event_id: Optional[int], action: str,
                           target: str, ttl_seconds: Optional[float] = None
                           ) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO user_actions (ts, event_id, action, target,"
                " ttl_seconds) VALUES (?,?,?,?,?)",
                (time.time(), event_id, action, target, ttl_seconds))
            self._conn.commit()

    # -- reading ------------------------------------------------------------
    def query(self, limit: int = 50, action: Optional[str] = None,
              src: Optional[str] = None, dst: Optional[str] = None,
              stage: Optional[str] = None, search: Optional[str] = None,
              order: str = "DESC") -> List[Dict[str, Any]]:
        sql = "SELECT * FROM events"
        clauses, params = [], []
        if action:
            clauses.append(action_placeholder(action, "action", params))
        if src:
            clauses.append("src LIKE ?"); params.append(f"%{src}%")
        if dst:
            clauses.append("dst LIKE ?"); params.append(f"%{dst}%")
        if stage:
            clauses.append("stage = ?"); params.append(stage)
        if search:
            clauses.append("(reason LIKE ? OR plain LIKE ? OR evidence LIKE ?)")
            params.extend([f"%{search}%"] * 3)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += f" ORDER BY ts {order if order in ('ASC', 'DESC') else 'DESC'}"
        sql += " LIMIT ?"
        params.append(max(1, min(int(limit), 500)))
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
            return [dict(r) for r in rows]

    def get(self, event_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM events WHERE id = ?", (int(event_id),)).fetchone()
            return dict(row) if row else None

    def update_intel(self, event_id: int, intel: dict) -> None:
        with self._lock:
            self._conn.execute("UPDATE events SET intel = ? WHERE id = ?",
                               (json.dumps(intel, default=str), int(event_id)))
            self._conn.commit()

    def update_plain(self, event_id: int, plain: str) -> None:
        with self._lock:
            self._conn.execute("UPDATE events SET plain = ? WHERE id = ?",
                               (plain, int(event_id)))
            self._conn.commit()

    def stats(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        with self._lock:
            for action in ("allow", "block", "quarantine"):
                row = self._conn.execute(
                    "SELECT COUNT(*) c FROM events WHERE action = ?",
                    (action,)).fetchone()
                out[action] = int(row["c"])
            row = self._conn.execute(
                "SELECT COUNT(*) c FROM events WHERE ts >= ?",
                (time.time() - 3600,)).fetchone()
            out["last_hour"] = int(row["c"])
        return out

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def action_placeholder(action: str, column: str, params: list) -> str:
    vals = [a.strip() for a in str(action).split(",") if a.strip()]
    if len(vals) == 1:
        params.append(vals[0]); return f"{column} = ?"
    params.extend(vals)
    return f"{column} IN ({','.join('?' * len(vals))})"
