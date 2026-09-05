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
from ui.core import paths

_DB_PATH = paths.intelligence_dir() / "ignore_list.sqlite"
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


class ServiceRequired(RuntimeError):
    """An ignore-list write needs the service, and the service is not reachable.

    Deliberately loud, and deliberately not a silent ``return False``.  In a
    distribution ``intelligence/`` is owned by the service (Users:Read), because
    the ignore list is detection-*suppression* state: anything that can write it
    can whitelist its own hash for every scan on the machine, including the
    service's.  So the unelevated GUI asks the service to write it.

    If that request cannot be made, the write did not happen.  Reporting it as a
    plain failure would be indistinguishable from "the hash was already there",
    and the user would believe a file had been whitelisted when it had not.
    """


def _writes_are_service_owned() -> bool:
    """True when this process must ask the service to write intelligence/.

    A source checkout owns its own project root, so the developer path is
    unchanged.  A distribution's intelligence/ is service-owned -- see
    docs/ARCHITECTURE.md, "The privilege boundary".
    """
    return paths.is_distribution()


def _ask_service(cmd: str, **kwargs) -> bool:
    """Send one ignore-list write to the service. Raises ServiceRequired."""
    from ui.core import service_client            # local: keeps import cost off scans

    try:
        reply = service_client.send_command(cmd, **kwargs)
    except Exception as exc:                       # socket refused, token unreadable
        raise ServiceRequired(
            f"PolyShield service is not reachable ({exc})") from exc
    if not reply or not reply.get("ok"):
        raise ServiceRequired(
            (reply or {}).get("error") or "PolyShield service rejected the request")

    # This process's Guardian cache still holds the pre-write set. The service
    # refreshed its own; ours has to be dropped or the next scan in THIS process
    # keeps using the stale answer.
    _invalidate_cache()
    return True


def _invalidate_cache() -> None:
    global _cache
    with _lock:
        _cache = None


def add(
    hash_value: str,
    hash_type: str = "md5",
    filename: str = "",
    note: str = "",
    original_reason: str = "",
) -> bool:
    """Insert a hash into the ignore list. Returns True on success.

    Routes through the service when intelligence/ is service-owned; writes
    directly in a source checkout.  Raises ServiceRequired if the write needed
    the service and could not reach it.
    """
    if not hash_value:
        return False
    if _writes_are_service_owned():
        return _ask_service(
            "IGNORE_HASH", md5=hash_value.lower(), hash_type=hash_type,
            filename=filename, note=note, original_reason=original_reason)
    return add_local(hash_value, hash_type, filename, note, original_reason)


def remove(hash_value: str) -> bool:
    """Delete a single hash. Returns True if a row was deleted."""
    if not hash_value:
        return False
    if _writes_are_service_owned():
        return _ask_service("UNIGNORE_HASH", md5=hash_value.lower())
    return remove_local(hash_value)


def clear_all() -> int:
    """Remove every entry. Returns the count of rows deleted."""
    if _writes_are_service_owned():
        _ask_service("CLEAR_IGNORED")
        # The service owns the count; it is not worth a second round trip.
        return 0
    return clear_all_local()


def add_local(
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


def remove_local(hash_value: str) -> bool:
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


def clear_all_local() -> int:
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
