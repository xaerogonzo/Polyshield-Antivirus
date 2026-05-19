"""
ignore_list.py
──────────────
Persistent local whitelist of file hashes flagged as false positives.

A small SQLite-backed module that the Guardian AI scanner consults before
applying its detection tiers. When a file's MD5 (or SHA-256) is in this list,
the scanner short-circuits and treats the file as clean.

The user can add entries from:
  • The Threat Actions detail pane: "Ignore…" button on any flagged file
  • Bulk "Ignore Selected" footer action

Each entry carries an optional `note` (user-supplied reason for ignoring) and
`original_reason` (the engine's verdict at the time of ignoring). This makes
auditing the list months later possible — you can see *why* you added it and
which engine pattern produced the noise.

Database: intelligence/ignore_list.sqlite
"""
from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

_DB_PATH = Path(__file__).resolve().parents[3] / "intelligence" / "ignore_list.sqlite"
_lock    = threading.Lock()

# In-process cache to avoid hitting SQLite on every scan_file() call.
# Refreshed on add()/remove(); also on first access.
_cache: set[str] | None = None


def _schema() -> str:
    return """
    CREATE TABLE IF NOT EXISTS ignored_hashes (
        hash             TEXT PRIMARY KEY,
        hash_type        TEXT NOT NULL,
        filename         TEXT,
        added_utc        TEXT NOT NULL,
        note             TEXT,
        original_reason  TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_added ON ignored_hashes(added_utc DESC);
    """


def _connect() -> sqlite3.Connection:
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(_DB_PATH), timeout=3)
    con.executescript(_schema())
    return con


def _refresh_cache() -> None:
    """Reload the hash set from disk into the in-memory cache."""
    global _cache
    try:
        con = _connect()
        try:
            _cache = {row[0] for row in con.execute("SELECT hash FROM ignored_hashes")}
        finally:
            con.close()
    except Exception:
        _cache = set()


def contains(hash_value: str) -> bool:
    """
    True if the given hash (MD5 or SHA-256, lower-case) is in the ignore list.

    Reads from an in-process cache for O(1) lookups during scans. The cache is
    populated on first call and refreshed by add()/remove().
    """
    if not hash_value:
        return False
    global _cache
    with _lock:
        if _cache is None:
            _refresh_cache()
        return hash_value.lower() in _cache


def add(
    hash_value: str,
    hash_type: str = "md5",
    filename: str = "",
    note: str = "",
    original_reason: str = "",
) -> bool:
    """
    Insert a hash into the ignore list. Returns True on success.

    If the hash already exists, the existing row is left untouched (no overwrite).
    Use remove() then add() if you want to update notes.

    v1.10: if ``original_reason`` begins with "Suspicious pattern: <label>" the
    matched pattern label is forwarded to pattern_stats.record_ignore() so the
    Settings UI can show empirical false-positive rates per pattern.
    """
    if not hash_value:
        return False
    h = hash_value.lower()
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        con = _connect()
        try:
            con.execute(
                "INSERT OR IGNORE INTO ignored_hashes "
                "(hash, hash_type, filename, added_utc, note, original_reason) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (h, hash_type, filename, now, note, original_reason),
            )
            con.commit()
        finally:
            con.close()
    except Exception:
        return False
    with _lock:
        if _cache is not None:
            _cache.add(h)
        else:
            _refresh_cache()

    # v1.10: pattern-stats telemetry when the original reason references a pattern.
    try:
        _SUSP_PREFIX = "Suspicious pattern: "
        if original_reason and original_reason.startswith(_SUSP_PREFIX):
            label = original_reason[len(_SUSP_PREFIX):].strip()
            if label:
                from ui.core import pattern_stats as _ps
                _ps.record_ignore(label)
    except Exception:
        pass

    return True


def remove(hash_value: str) -> bool:
    """Delete a single hash from the list. Returns True if a row was deleted."""
    if not hash_value:
        return False
    h = hash_value.lower()
    deleted = False
    try:
        con = _connect()
        try:
            cur = con.execute("DELETE FROM ignored_hashes WHERE hash = ?", (h,))
            deleted = cur.rowcount > 0
            con.commit()
        finally:
            con.close()
    except Exception:
        return False
    with _lock:
        if _cache is not None:
            _cache.discard(h)
    return deleted


def clear_all() -> int:
    """Remove every entry. Returns the count of rows deleted."""
    n = 0
    try:
        con = _connect()
        try:
            cur = con.execute("DELETE FROM ignored_hashes")
            n = cur.rowcount or 0
            con.commit()
        finally:
            con.close()
    except Exception:
        return 0
    with _lock:
        if _cache is not None:
            _cache.clear()
    return n


def list_all() -> list[dict]:
    """
    Return every entry ordered by most-recent first.

    Each dict: {hash, hash_type, filename, added_utc, note, original_reason}
    """
    rows: list[dict] = []
    try:
        con = _connect()
        try:
            cur = con.execute(
                "SELECT hash, hash_type, filename, added_utc, note, original_reason "
                "FROM ignored_hashes ORDER BY added_utc DESC"
            )
            for r in cur.fetchall():
                rows.append({
                    "hash":            r[0],
                    "hash_type":       r[1],
                    "filename":        r[2] or "",
                    "added_utc":       r[3],
                    "note":            r[4] or "",
                    "original_reason": r[5] or "",
                })
        finally:
            con.close()
    except Exception:
        pass
    return rows


def count() -> int:
    """Total entries in the ignore list."""
    try:
        con = _connect()
        try:
            row = con.execute("SELECT COUNT(*) FROM ignored_hashes").fetchone()
            return int(row[0]) if row else 0
        finally:
            con.close()
    except Exception:
        return 0
