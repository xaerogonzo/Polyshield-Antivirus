"""
intel_db.py
───────────
Read-only query layer for intelligence/threat_db.sqlite.

Extracted from update_intelligence.py to break the circular import between
guardian_engine (read consumer) and update_intelligence (write producer).

Uses threading.local() to maintain one persistent SQLite connection per thread,
avoiding per-file open/close overhead during scans (up to 3,000 files → 3,000
disk I/O handshakes without caching).
"""
import sqlite3
import threading
from pathlib import Path
from ui.core import paths

_DB_PATH      = paths.intelligence_dir() / "threat_db.sqlite"
_thread_local = threading.local()


def _get_conn() -> sqlite3.Connection | None:
    """Return a cached per-thread read-only connection, creating it if needed.

    Guards against a 'closed connection' trap: if a caller somewhere in the
    call-tree explicitly closes the connection, the next call here will detect
    the broken state and open a fresh one.
    """
    if not _DB_PATH.exists():
        return None
    conn = getattr(_thread_local, "conn", None)
    if conn is not None:
        # Liveness check — connection may have been closed by a caller that
        # still had a reference to the same object.
        try:
            conn.execute("SELECT 1")
        except (sqlite3.ProgrammingError, sqlite3.OperationalError):
            conn = None
    if conn is None:
        try:
            conn = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
            # Reader-side backstop for the moment a writer is mid-commit.  The
            # journal mode itself is set once by the writer (WAL — see
            # update_intelligence._open_db), so readers inherit it.
            conn.execute("PRAGMA busy_timeout=5000")
            _thread_local.conn = conn
        except Exception:
            return None
    return conn


# ── Public read helpers ───────────────────────────────────────────────────────

def get_stats() -> dict:
    """Return statistics about the intelligence database."""
    if not _DB_PATH.exists():
        return {"malicious": 0, "safe": 0, "last_update": "Never", "db_exists": False}
    try:
        con = _get_conn()
        if con is None:
            return {"malicious": 0, "safe": 0, "last_update": "Error", "db_exists": False}
        mal   = con.execute("SELECT COUNT(*) FROM malicious").fetchone()[0]
        safe  = con.execute("SELECT COUNT(*) FROM safe").fetchone()[0]
        row   = con.execute("SELECT value FROM meta WHERE key='last_mb_update'").fetchone()
        last  = row[0][:19].replace("T", " ") if row else "Never"
        return {"malicious": mal, "safe": safe, "last_update": last, "db_exists": True}
    except Exception:
        return {"malicious": 0, "safe": 0, "last_update": "Error", "db_exists": True}


def lookup_hash(md5: str) -> dict | None:
    """
    Look up an MD5 in the malicious table.
    Returns dict with {family, detection_count, trust_score} or None if not found.
    Fast path: None means clean (not in malicious DB).
    """
    if not _DB_PATH.exists():
        return None
    try:
        con = _get_conn()
        if con is None:
            return None
        row = con.execute(
            "SELECT malware_family, detection_count, trust_score "
            "FROM malicious WHERE hash=?", (md5.lower(),)
        ).fetchone()
        if row:
            return {"family": row[0], "detection_count": row[1], "trust_score": row[2]}
    except Exception:
        pass
    return None


def is_known_safe(md5: str) -> bool:
    """Return True if the MD5 is in the NSRL known-safe table."""
    if not _DB_PATH.exists():
        return False
    try:
        con = _get_conn()
        if con is None:
            return False
        row = con.execute("SELECT 1 FROM safe WHERE hash=?", (md5.lower(),)).fetchone()
        return row is not None
    except Exception:
        return False
