"""
pattern_stats.py
────────────────
Per-pattern detection telemetry for Guardian AI's heuristic tier.

Records how often each regex pattern fires and how often the user later
adds the matched file to the ignore list. Together these yield an
empirical "false positive rate" per pattern that Settings → Guardian
Advanced surfaces back to the user — so they can decide which patterns
are noisy enough to disable.

Pure file-local SQLite. No network. Auto-creates on first detection.

Database: intelligence/pattern_stats.sqlite
"""
from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

_DB_PATH = Path(__file__).resolve().parents[3] / "intelligence" / "pattern_stats.sqlite"
_lock    = threading.Lock()


def _schema() -> str:
    return """
    CREATE TABLE IF NOT EXISTS pattern_stats (
        pattern        TEXT PRIMARY KEY,
        detections     INTEGER DEFAULT 0,
        ignored        INTEGER DEFAULT 0,
        last_detected  TEXT
    );
    """


def _connect() -> sqlite3.Connection:
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(_DB_PATH), timeout=3)
    con.executescript(_schema())
    return con


def record_detection(pattern: str) -> None:
    """Increment the detection counter for the given pattern label."""
    if not pattern:
        return
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        with _lock:
            con = _connect()
            try:
                con.execute(
                    "INSERT INTO pattern_stats(pattern, detections, ignored, last_detected) "
                    "VALUES (?, 1, 0, ?) "
                    "ON CONFLICT(pattern) DO UPDATE SET "
                    "  detections = detections + 1, "
                    "  last_detected = excluded.last_detected",
                    (pattern, now),
                )
                con.commit()
            finally:
                con.close()
    except Exception:
        pass


def record_ignore(pattern: str) -> None:
    """Increment the ignore counter when a user adds a matched file to ignore_list."""
    if not pattern:
        return
    try:
        with _lock:
            con = _connect()
            try:
                con.execute(
                    "INSERT INTO pattern_stats(pattern, detections, ignored) "
                    "VALUES (?, 0, 1) "
                    "ON CONFLICT(pattern) DO UPDATE SET ignored = ignored + 1",
                    (pattern,),
                )
                con.commit()
            finally:
                con.close()
    except Exception:
        pass


def get_stats() -> list[dict]:
    """Return one dict per pattern, ordered by detection count descending."""
    rows: list[dict] = []
    try:
        with _lock:
            con = _connect()
            try:
                cur = con.execute(
                    "SELECT pattern, detections, ignored, last_detected "
                    "FROM pattern_stats ORDER BY detections DESC"
                )
                for r in cur.fetchall():
                    det, ign = int(r[1] or 0), int(r[2] or 0)
                    rows.append({
                        "pattern":       r[0],
                        "detections":    det,
                        "ignored":       ign,
                        "fp_rate":       (ign / det) if det > 0 else 0.0,
                        "last_detected": r[3] or "",
                    })
            finally:
                con.close()
    except Exception:
        pass
    return rows


def fp_rate(pattern: str) -> float:
    """Return ignored/detections ratio for one pattern, or 0.0 if unknown."""
    try:
        with _lock:
            con = _connect()
            try:
                row = con.execute(
                    "SELECT detections, ignored FROM pattern_stats WHERE pattern = ?",
                    (pattern,),
                ).fetchone()
                if not row:
                    return 0.0
                d, i = int(row[0] or 0), int(row[1] or 0)
                return (i / d) if d > 0 else 0.0
            finally:
                con.close()
    except Exception:
        return 0.0


def reset() -> None:
    """Wipe all stats (for testing or user-requested clear)."""
    try:
        with _lock:
            con = _connect()
            try:
                con.execute("DELETE FROM pattern_stats")
                con.commit()
            finally:
                con.close()
    except Exception:
        pass
