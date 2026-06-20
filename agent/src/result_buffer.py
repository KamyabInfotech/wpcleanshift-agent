"""Local SQLite buffer for scan results when the API is unreachable.

When the CleanShift agent completes a scan but cannot reach the central
API, results are stored in a local SQLite database and retried on the
next scan or via `cleanshift buffer flush`.

Buffer lifecycle:
    1. scan completes → agent tries POST /api/scan-results
    2. if API unreachable → store in buffer.db
    3. next scan (or manual flush) → retry pending results
    4. after 7 days or 5 failed retries → mark as abandoned
    5. daily cleanup removes sent/abandoned entries
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger("cleanshift.buffer")

_DEFAULT_BUFFER_PATH = Path("/opt/cleanshift/buffer.db")
_MAX_BUFFER_AGE_DAYS = 7
_MAX_RETRIES = 5


class ResultBuffer:
    """Thread-safe local buffer for scan results."""

    def __init__(self, db_path: Path = _DEFAULT_BUFFER_PATH) -> None:
        self.db_path = db_path
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            # Fall back to user-writable path
            self.db_path = Path.home() / ".cleanshift" / "buffer.db"
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Create the buffer table if it doesn't exist."""
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS buffered_results (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_json   TEXT    NOT NULL,
                    created_at  REAL    NOT NULL,
                    retry_count INTEGER DEFAULT 0,
                    status      TEXT    DEFAULT 'pending',
                    last_error  TEXT    DEFAULT ''
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_status
                ON buffered_results (status)
            """)

    def store(self, scan_result_dict: dict) -> int:
        """Store a scan result for later submission. Returns the buffer row ID."""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.execute(
                "INSERT INTO buffered_results (scan_json, created_at) VALUES (?, ?)",
                (json.dumps(scan_result_dict, default=str), time.time()),
            )
            row_id = cursor.lastrowid or 0
            logger.info("Buffered scan result (id=%d) for later submission", row_id)
            return row_id

    def get_pending(self, limit: int = 10) -> list[tuple[int, dict]]:
        """Return up to `limit` pending results as (id, dict) tuples."""
        with sqlite3.connect(str(self.db_path)) as conn:
            rows = conn.execute(
                "SELECT id, scan_json FROM buffered_results "
                "WHERE status = ? ORDER BY created_at LIMIT ?",
                ("pending", limit),
            ).fetchall()
            return [(row[0], json.loads(row[1])) for row in rows]

    def mark_sent(self, result_id: int) -> None:
        """Mark a buffered result as successfully sent."""
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                "UPDATE buffered_results SET status = ? WHERE id = ?",
                ("sent", result_id),
            )

    def mark_failed(self, result_id: int, error: str = "") -> None:
        """Increment retry count; abandon after MAX_RETRIES."""
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                "UPDATE buffered_results SET "
                "retry_count = retry_count + 1, "
                "last_error = ?, "
                "status = CASE WHEN retry_count >= ? THEN 'abandoned' ELSE 'pending' END "
                "WHERE id = ?",
                (error, _MAX_RETRIES, result_id),
            )

    def cleanup_old(self) -> int:
        """Remove sent, abandoned, and expired entries. Returns count removed."""
        cutoff = time.time() - (_MAX_BUFFER_AGE_DAYS * 86400)
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.execute(
                "DELETE FROM buffered_results WHERE created_at < ? OR status IN (?, ?)",
                (cutoff, "sent", "abandoned"),
            )
            return cursor.rowcount

    def pending_count(self) -> int:
        """Return the number of pending (unsent) results."""
        with sqlite3.connect(str(self.db_path)) as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM buffered_results WHERE status = ?",
                ("pending",),
            ).fetchone()
            return row[0] if row else 0

    def all_stats(self) -> dict[str, int]:
        """Return counts by status."""
        with sqlite3.connect(str(self.db_path)) as conn:
            rows = conn.execute(
                "SELECT status, COUNT(*) FROM buffered_results GROUP BY status"
            ).fetchall()
            return {row[0]: row[1] for row in rows}
