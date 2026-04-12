"""
WardenStrike - Episodic Memory
Persists what worked against which targets so the autopilot learns across engagements.

Inspired by PentAGI's tri-layer memory:
  - Episodic  : technique → target_type → outcome (stored in SQLite)
  - Working   : current engagement state (in-memory dict, passed around)
  - Semantic  : system prompts / payloads (static knowledge base files)

The episodic store lets the agent say:
  "Last time I saw a Node.js app with an open /graphql endpoint, introspection
   was enabled AND the depth-bomb triggered a 502 — try that first."
"""

import json
import sqlite3
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any

from wardenstrike.utils.logger import get_logger

log = get_logger("memory")

_DB_DEFAULT = "./data/memory.db"


class EpisodicMemory:
    """
    SQLite-backed episodic memory for the autopilot agent.

    Each memory record captures:
      - action      : what was tried (e.g. "graphql_introspection")
      - target_hint : technology / service fingerprint (e.g. "node,express,graphql")
      - outcome     : success | partial | failure
      - finding     : what was found (vuln type + severity) if success
      - notes       : free-text detail for the planner
    """

    def __init__(self, db_path: str = _DB_DEFAULT):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS episodes (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    action      TEXT NOT NULL,
                    target_hint TEXT NOT NULL,
                    outcome     TEXT NOT NULL CHECK(outcome IN ('success','partial','failure')),
                    finding     TEXT,
                    notes       TEXT,
                    engagement  TEXT,
                    created_at  TEXT DEFAULT (datetime('now'))
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ep_action ON episodes(action)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ep_target ON episodes(target_hint)")
            conn.commit()

    # ── Write ─────────────────────────────────────────────────────────────────

    def record(self, action: str, target_hint: str, outcome: str,
               finding: str = "", notes: str = "", engagement: str = ""):
        """Record the outcome of an autopilot action."""
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO episodes (action, target_hint, outcome, finding, notes, engagement) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (action, target_hint.lower(), outcome, finding, notes, engagement),
            )
            conn.commit()
        log.debug(f"[memory] recorded: {action} / {target_hint} → {outcome}")

    # ── Read ──────────────────────────────────────────────────────────────────

    def recall(self, target_hint: str, action: str | None = None,
               limit: int = 10) -> list[dict]:
        """
        Retrieve relevant past episodes for a given target fingerprint.
        Fuzzy match: any word in target_hint that appears in stored target_hint.
        """
        keywords = [w.strip() for w in target_hint.lower().split(",") if w.strip()]
        if not keywords:
            return []

        # Build a WHERE clause matching any keyword
        conditions = " OR ".join(["target_hint LIKE ?" for _ in keywords])
        params: list[Any] = [f"%{k}%" for k in keywords]

        if action:
            conditions = f"({conditions}) AND action = ?"
            params.append(action)

        with self._conn() as conn:
            rows = conn.execute(
                f"SELECT * FROM episodes WHERE {conditions} ORDER BY created_at DESC LIMIT ?",
                params + [limit],
            ).fetchall()
        return [dict(r) for r in rows]

    def success_rate(self, action: str, target_hint: str) -> float:
        """Return 0.0–1.0 success rate for an action against similar targets."""
        keywords = [w.strip() for w in target_hint.lower().split(",") if w.strip()]
        if not keywords:
            return 0.5  # unknown → neutral

        conditions = " OR ".join(["target_hint LIKE ?" for _ in keywords])
        params = [f"%{k}%" for k in keywords]

        with self._conn() as conn:
            total = conn.execute(
                f"SELECT COUNT(*) FROM episodes WHERE action = ? AND ({conditions})",
                [action] + params,
            ).fetchone()[0]
            success = conn.execute(
                f"SELECT COUNT(*) FROM episodes WHERE action = ? AND outcome = 'success' AND ({conditions})",
                [action] + params,
            ).fetchone()[0]

        if total == 0:
            return 0.5  # no data → neutral
        return success / total

    def suggest_actions(self, target_hint: str, available_actions: list[str]) -> list[dict]:
        """
        Rank available_actions by historical success rate against similar targets.
        Returns list of {action, success_rate, past_episodes} sorted best-first.
        """
        ranked = []
        for action in available_actions:
            rate = self.success_rate(action, target_hint)
            episodes = self.recall(target_hint, action=action, limit=3)
            ranked.append({
                "action": action,
                "success_rate": rate,
                "past_episodes": episodes,
            })
        ranked.sort(key=lambda x: x["success_rate"], reverse=True)
        return ranked

    def summary(self) -> dict:
        """Return aggregate statistics for the memory store."""
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM episodes").fetchone()[0]
            by_outcome = {
                row["outcome"]: row["cnt"]
                for row in conn.execute(
                    "SELECT outcome, COUNT(*) as cnt FROM episodes GROUP BY outcome"
                ).fetchall()
            }
            top_actions = [
                dict(r) for r in conn.execute(
                    "SELECT action, COUNT(*) as cnt FROM episodes GROUP BY action ORDER BY cnt DESC LIMIT 10"
                ).fetchall()
            ]
        return {"total": total, "by_outcome": by_outcome, "top_actions": top_actions}
