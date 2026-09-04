"""
update_intelligence.py
──────────────────────
Intelligence Gatherer for the Guardian AI scanner.

Downloads known-bad hash feeds from public threat intel sources and
stores them in:
  • intelligence/threat_db.sqlite   (canonical source; guardian_engine and
                                     process_monitor load directly from here)
  • guardianai/data/known_bad.txt   (legacy — no longer written automatically;
                                     use --sync flag for manual export)

Sources
───────
  MalwareBazaar (abuse.ch)  — vetted malware MD5/SHA256, daily updated
    Full list (large):   https://bazaar.abuse.ch/export/txt/md5/full/
    Recent 24 h (fast):  https://bazaar.abuse.ch/export/txt/md5/recent/

  NSRL (NIST) — known-SAFE hashes  [manual import, too large to auto-download]
    Download from: https://www.nist.gov/itl/ssd/software-quality-group/nsrl-download
    Then run:  python update_intelligence.py --nsrl <path/to/NSRLFile.txt>

Usage
─────
  # Fetch recent 24h malware hashes (fast, ~500KB)
  python tools/update_intelligence.py

  # Fetch full MalwareBazaar hash list (slow, hundreds of MB)
  python tools/update_intelligence.py --full

  # Import NSRL known-safe list (one-time, very large)
  python tools/update_intelligence.py --nsrl "C:/path/NSRLFile.txt"

  # Print DB statistics only
  python tools/update_intelligence.py --stats

Can also be called programmatically:
  from tools.update_intelligence import run_update
  run_update(on_progress=print, mode="recent")
"""
from __future__ import annotations

import argparse
import io
import ipaddress
import logging
import os
import sqlite3
import sys
import time
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

# ── Paths ─────────────────────────────────────────────────────────────────────

_LOG = logging.getLogger(__name__)

# Running this file directly (python src/tools/update_intelligence.py) puts
# src/tools/ on sys.path but not src/, so the ui.core re-export shim further
# down would raise ModuleNotFoundError before main() ever runs.  Bootstrap the
# path here instead — a no-op when imported as tools.update_intelligence from a
# host process that already configured sys.path.
#
# This is one of only three places still allowed to derive a root from
# __file__: the bootstrap cannot import the module that centralises path
# resolution until sys.path can find it.  Everything below goes through it.
_ROOT = Path(__file__).resolve().parents[2]
if __package__ in (None, ""):
    for _p in (_ROOT / "src", _ROOT):
        if str(_p) not in sys.path:
            sys.path.insert(0, str(_p))

from ui.core import paths                    # noqa: E402  (after bootstrap)

_DB_PATH      = paths.intelligence_dir() / "threat_db.sqlite"
_KNOWN_BAD    = paths.guardian_dir() / "data" / "known_bad.txt"
_BLOOM_PATH   = paths.intelligence_dir() / "nsrl_bloom.bin"

_MB_RECENT_URL    = "https://bazaar.abuse.ch/export/txt/md5/recent/"
_MB_FULL_URL      = "https://bazaar.abuse.ch/export/txt/md5/full/"
# Feodo Tracker: Botnet C2 IOC feed — all C2 IPs seen in the past 30 days.
# This is the broader IOC CSV (not the "recommended" active-only subset).
# The aggressive/all-time list exists but has high FP from IP recycling.
_FEODO_IOC_URL    = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
# ThreatFox: IP:port IOC feed — covers the past 6 months of detections.
# No broader time window exists in their CSV export API.
_THREATFOX_URL    = "https://threatfox.abuse.ch/export/csv/ip-port/recent/"

# ── DB schema ─────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS malicious (
    hash            TEXT PRIMARY KEY,
    hash_type       TEXT    NOT NULL DEFAULT 'md5',
    malware_family  TEXT    NOT NULL DEFAULT '',
    detection_count INTEGER NOT NULL DEFAULT 0,
    trust_score     INTEGER NOT NULL DEFAULT 0,
    source          TEXT    NOT NULL DEFAULT 'malwarebazaar',
    first_seen      TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS safe (
    hash        TEXT PRIMARY KEY,
    hash_type   TEXT NOT NULL DEFAULT 'md5',
    source      TEXT NOT NULL DEFAULT 'nsrl',
    product     TEXT NOT NULL DEFAULT '',
    added_at    TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS ip_blocklist (
    ip        TEXT PRIMARY KEY,
    tags      TEXT    NOT NULL DEFAULT '',
    port      INTEGER NOT NULL DEFAULT 0,
    malware   TEXT    NOT NULL DEFAULT '',
    added_ts  TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


def _utcnow() -> datetime:
    """Naive UTC — the single time frame for every freshness stamp here.

    Mirrors intel_updater._utcnow().  The two modules write and read the same
    `meta` rows, so they have to agree on the frame: naive UTC, so a stored
    stamp subtracts cleanly from a later reading of it.  datetime.utcnow() is
    deprecated from 3.12 and was emitting warnings from four call sites.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _valid_ip(value: str) -> str:
    """Return the normalised IP, or "" if `value` is not one.

    Both C2 feeds are IP feeds, so anything that will not parse is not a
    record — it is a CSV header row, a stray comment, or a truncated line.
    Letting those through put the literal string "dst_ip" in the blocklist,
    where network_monitor would compare live connections against it forever.
    """
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return ""


def _open_db_readonly() -> sqlite3.Connection | None:
    """Open the intelligence DB for reading without creating or converting it.

    _open_db() runs the schema script and sets WAL, which is wrong for a pure
    status read on a machine that has never run an update.
    """
    try:
        if not _DB_PATH.exists():
            return None
        con = sqlite3.connect(str(_DB_PATH), timeout=3)
        con.execute("PRAGMA busy_timeout=5000")
        return con
    except Exception:
        return None


def _open_db() -> sqlite3.Connection:
    """Open the intelligence DB for writing, in WAL mode.

    WAL is set here (the writer side) because journal_mode is a persistent
    property of the database file — one write connection converts it once and
    every later reader inherits it.

    Why it matters, measured rather than assumed: under the old rollback
    journal a COMMIT needs an EXCLUSIVE lock, so a *reader* holding an open
    read transaction blocks the writer — an update commit fails with "database
    is locked" once busy_timeout expires.  That is precisely the v1.12
    scenario: the service updating in the background while the UI holds one of
    intel_db's long-lived per-thread connections.  Under WAL the same commit
    lands in about a millisecond.  (The reverse direction was never the
    problem: a write transaction only holds RESERVED, which readers may
    cross.)

    busy_timeout is a backstop for a genuine write/write race, not the
    mechanism — the single-writer lock is what prevents concurrent writers.
    """
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(_DB_PATH))
    try:
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA busy_timeout=5000")
    except sqlite3.Error as exc:
        # Non-fatal: a filesystem that cannot support WAL (network share) keeps
        # the previous journal mode and simply serialises as it did before.
        _LOG.warning("Could not set WAL journal mode: %s", exc)
    con.executescript(_SCHEMA)
    con.commit()
    return con


# ── MalwareBazaar import ──────────────────────────────────────────────────────

def fetch_malwarebazaar(
    mode: str = "recent",
    on_progress: Callable[[str], None] | None = None,
    notify: bool = True,
) -> dict:
    """
    Download MalwareBazaar hash list and insert into the SQLite malicious table.

    v1.8+: hashes are loaded directly from SQLite by guardian_engine and
    process_monitor; known_bad.txt is no longer written automatically.

    mode:   "recent" (24h, fast) | "full" (all, slow ~100MB+ download)
    notify: fire the "hashes" post-update hooks after a successful commit.
            Direct callers (Update Center button, CLI) want this.  The batch
            updater passes notify=False and fires ONE notification phase for
            the union of domains it changed, after every feed has committed.

    Returns stats dict: {added, skipped, total_db}, or {error, http_status} if
    the feed could not be downloaded or did not parse to any usable hash.

    Nothing local is touched until the response has parsed to at least one
    valid MD5: download -> validate -> import -> commit -> freshness.  A feed
    that returns an error page, an empty archive, or garbage must leave the
    existing intelligence exactly as it was, and must not stamp last_mb_update.
    """
    log = on_progress or (lambda _: None)
    url = _MB_FULL_URL if mode == "full" else _MB_RECENT_URL

    log(f"Fetching MalwareBazaar {mode} list…  {url}")

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "PolyShield-Intelligence/1.0"}
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw_bytes = resp.read()
    except Exception as exc:
        # getattr for the status: urllib raises HTTPError (which carries .code)
        # for 4xx/5xx and URLError (which does not) for transport failures.  The
        # updater needs the distinction — a 401/403 means "stop retrying on a
        # schedule", a timeout means "back off and try again".
        log(f"[ERROR] Download failed: {exc}")
        return {"error": str(exc), "http_status": int(getattr(exc, "code", 0) or 0)}

    log(f"Downloaded {len(raw_bytes):,} bytes.  Parsing…")

    # The full list is a ZIP; recent list is plain text.  Every failure here is
    # a bad *download*, so it returns like one — this function's contract is a
    # dict, and intel_updater._run_malwarebazaar reads res["error"] first.  An
    # empty archive used to raise IndexError straight through that adapter.
    if raw_bytes[:2] == b"PK":
        try:
            with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
                names = zf.namelist()
                if not names:
                    log("[ERROR] Downloaded archive is empty.")
                    return {"error": "downloaded archive is empty", "http_status": 0}
                text = zf.read(names[0]).decode("utf-8", errors="ignore")
        except Exception as exc:
            # Broad on purpose, and consistent with download_yara_community: the
            # contract of this function is a dict, and zipfile raises several
            # unrelated types for a bad archive (BadZipFile for corruption,
            # RuntimeError for an encrypted member, EOFError for a truncated
            # stream).  Enumerating them invites the next one to escape.
            log(f"[ERROR] Downloaded archive could not be read: {exc}")
            return {"error": f"unreadable archive: {exc}", "http_status": 0}
    else:
        text = raw_bytes.decode("utf-8", errors="ignore")

    hashes: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Normalise
        h = line.lower()
        if len(h) == 32 and all(c in "0123456789abcdef" for c in h):
            hashes.append(h)

    if not hashes:
        # Deliberately an error rather than {"added": 0, "total_db": 0}.  That
        # shape claimed the database held nothing, which is a lie about a table
        # that may hold millions, and it was the value the Update Center logged
        # back to the user.  Reporting the *real* total would be worse still:
        # _run_malwarebazaar would then read (added=0, total>0) as UNCHANGED and
        # advance freshness on a feed that returned nothing.
        log("[WARNING] No valid MD5 hashes found in downloaded file.")
        return {"error": "feed returned no valid MD5 hashes", "http_status": 0}

    log(f"Found {len(hashes):,} valid MD5 hashes.  Writing to DB…")

    con = _open_db()
    now = _utcnow().isoformat()
    added = 0
    for h in hashes:
        cur = con.execute(
            "INSERT OR IGNORE INTO malicious (hash, hash_type, source, first_seen) "
            "VALUES (?, 'md5', 'malwarebazaar', ?)",
            (h, now),
        )
        added += cur.rowcount
    con.execute("INSERT OR REPLACE INTO meta VALUES ('last_mb_update', ?)", (now,))
    con.commit()
    skipped = len(hashes) - added

    total_db = con.execute("SELECT COUNT(*) FROM malicious").fetchone()[0]
    con.close()

    log(f"Done.  Added {added:,} new  |  {skipped:,} already known  |  "
        f"DB total: {total_db:,}")

    # Committed — only now may in-memory consumers be told to refresh.
    if notify:
        _fire_post_update_hooks(("hashes",))

    return {"added": added, "skipped": skipped, "total_db": total_db}


# ── NSRL import ───────────────────────────────────────────────────────────────

def import_nsrl(
    nsrl_path: str,
    on_progress: Callable[[str], None] | None = None,
    notify: bool = True,
) -> dict:
    """
    Import NIST NSRL known-safe hash file into the safe table.

    nsrl_path: path to NSRLFile.txt (from NSRL RDS ISO or download).
    Format per line:  "SHA-1","MD5","CRC32","FileName","FileSize",...
    """
    log = on_progress or (lambda _: None)
    p = Path(nsrl_path)
    if not p.exists():
        log(f"[ERROR] NSRL file not found: {nsrl_path}")
        return {"error": "file not found"}

    log(f"Importing NSRL from {p.name} — this may take several minutes…")
    con = _open_db()
    try:
        # Mark the bloom stale before the first row lands.  Under the atomic
        # publish in _rebuild_nsrl_bloom the old filter now survives a crash --
        # but the `safe` table commits every 500 K rows, so a crash still
        # leaves a filter that no longer describes the table.  Stale is exactly
        # what that is, and a reader seeing stale=1 falls back to SQLite.
        con.execute("INSERT OR REPLACE INTO meta VALUES ('nsrl_bloom_stale', '1')")
        con.commit()

        now = _utcnow().isoformat()
        added = 0
        rows = 0

        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            for raw_line in f:
                rows += 1
                if rows == 1 and raw_line.startswith('"SHA-1"'):
                    continue  # header row
                parts = raw_line.strip().split(",")
                if len(parts) < 2:
                    continue
                md5 = parts[1].strip().strip('"').lower()
                if len(md5) != 32:
                    continue
                product = parts[3].strip().strip('"') if len(parts) > 3 else ""
                cur = con.execute(
                    "INSERT OR IGNORE INTO safe (hash, source, product, added_at) "
                    "VALUES (?, 'nsrl', ?, ?)",
                    (md5, product, now),
                )
                added += cur.rowcount
                if rows % 500_000 == 0:
                    con.commit()
                    log(f"  Processed {rows:,} rows, {added:,} new safe hashes…")

        # Commit the table BEFORE building the filter over it, so the filter can
        # never be published describing rows that are not durable yet.
        con.commit()
        total = con.execute("SELECT COUNT(*) FROM safe").fetchone()[0]
        log(f"NSRL import complete.  Added {added:,}  |  Safe DB total: {total:,}")

        # Rebuild the bloom filter now that the import is complete
        def _bloom_progress(pct: int) -> None:
            log(f"  Building NSRL bloom filter… {pct}%")

        _rebuild_nsrl_bloom(con, progress_cb=_bloom_progress)
    finally:
        # An unreadable file or a failed rebuild must not also leak the write
        # connection — it holds the WAL lock the service needs.
        con.close()

    # Committed — the safe table feeds the same hash-domain consumers.
    if notify:
        _fire_post_update_hooks(("hashes",))

    return {"added": added, "total": total}


# ── NSRL Bloom filter ────────────────────────────────────────────────────────

def _rebuild_nsrl_bloom(
    con: sqlite3.Connection,
    progress_cb: Callable[[int], None] | None = None,
) -> None:
    """
    Build a Bloom filter from the `safe` table and save it to intelligence/nsrl_bloom.bin.

    Why: the NSRL safe table can hold ~72 million hashes.  Loading those into a
    Python `set` at startup would consume 4–6 GB of RAM.  A ScalableBloomFilter at
    0.1 % false-positive rate for 72 M entries takes ~150–200 MB on disk and ~same
    in RAM — completely workable.

    False positives (bloom says "maybe safe" but SQLite says "not found") are
    confirmed via a single SQLite query, so the actual false-positive rate seen by
    the scanner is effectively zero — only performance is affected, not correctness.

    Uses fetchmany(10_000) to batch SQLite reads — reduces Python/C boundary
    crossings ~7 000× compared with single-row iteration.

    Emits progress_cb(pct: int) periodically (every 500 K rows) if provided.

    Publication is atomic, and ordered.  The filter is built beside its
    destination, flushed and fsynced, then moved into place with os.replace;
    only after that move lands is nsrl_bloom_stale cleared.  The previous form
    opened the live nsrl_bloom.bin "wb" -- truncating a valid ~150-200 MB
    filter before tofile() had written a byte -- so a crash during the write
    destroyed the old one and left nothing usable in its place.

    The two failure states this rules out:

        SQLite=NEW / bloom=OLD / stale=0    bloom advertised for data it lacks
        SQLite=OLD / bloom=NEW / stale=0    bloom advertised ahead of the table

    Caller ordering matters and is part of this contract: import_nsrl commits
    the `safe` rows *before* calling here, and stale=0 is written last, so a
    reader either sees stale=1 (and falls back to SQLite, per
    guardian_engine._load_nsrl_bloom) or sees a filter that matches a committed
    table.  On any failure stale stays 1 and the previous filter is untouched:
    an out-of-date bloom is safe -- it can only omit entries, never invent
    them, and a miss falls through to the SQLite truth.
    """
    try:
        from pybloom_live import ScalableBloomFilter
    except ImportError:
        # pybloom-live not installed — skip silently; guardian_engine falls back
        # to per-file SQLite queries
        return

    total_row = con.execute("SELECT COUNT(*) FROM safe").fetchone()
    total = total_row[0] if total_row else 0
    if total == 0:
        # No NSRL data yet — nothing to build
        return

    # initial_capacity: prime slightly above current total so the first internal
    # filter doesn't overflow immediately and trigger a cascade of growing filters.
    bloom = ScalableBloomFilter(
        initial_capacity=max(total + 1_000_000, 80_000_000),
        error_rate=0.001,   # 0.1 % false-positive rate
    )

    cursor = con.execute("SELECT hash FROM safe")
    done = 0
    while True:
        batch = cursor.fetchmany(10_000)
        if not batch:
            break
        for (h,) in batch:
            bloom.add(h.lower())
        done += len(batch)
        if progress_cb and total:
            # Emit every 500 K rows to avoid flooding the UI progress bar
            if done % 500_000 < 10_000:
                progress_cb(int(done * 100 / total))

    _BLOOM_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Sibling temp file, not tempfile.mkstemp: os.replace carries the ACL along
    # with the file, and a hardened scratch DACL would become a live filter only
    # the publishing account can read -- which _load_nsrl_bloom reports as
    # simply "no bloom".  A plain create here inherits the intelligence dir ACL.
    tmp = _BLOOM_PATH.with_name(f"{_BLOOM_PATH.name}.{os.getpid()}.tmp")
    try:
        with open(tmp, "wb") as f:
            bloom.tofile(f)
            f.flush()
            os.fsync(f.fileno())    # the write must be on disk before the swap

        # Validate before publishing.  A full fromfile() round-trip is not done
        # deliberately: it would allocate a second ~150-200 MB filter while the
        # first is still live, to re-prove what tofile() returning plus fsync
        # already establishes.  The reader is the second line of defence and
        # already quarantines a filter it cannot parse.
        if tmp.stat().st_size == 0:
            raise OSError("bloom filter serialised to an empty file")

        os.replace(str(tmp), str(_BLOOM_PATH))   # atomic; previous stays valid until now
    finally:
        # A failed build leaves the previous nsrl_bloom.bin in place and
        # nsrl_bloom_stale at 1, which is the safe direction: consumers fall
        # back to SQLite rather than trusting a filter that may be partial.
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass

    # Published — and only now is the filter allowed to claim it is current.
    con.execute("INSERT OR REPLACE INTO meta VALUES ('nsrl_bloom_stale', '0')")
    con.commit()

    if progress_cb:
        progress_cb(100)


# ── Sync known_bad.txt ────────────────────────────────────────────────────────

def _sync_known_bad_txt(on_progress: Callable[[str], None] | None = None):
    """
    Write all malicious MD5s from SQLite into known_bad.txt.

    DEPRECATED (v1.8): guardian_engine and process_monitor now load directly from
    SQLite. This function is no longer called automatically after MalwareBazaar
    imports. It is kept for manual export/debug use only.
    """
    log = on_progress or (lambda _: None)
    if not _DB_PATH.exists():
        return
    con = _open_db()
    hashes = [row[0] for row in con.execute("SELECT hash FROM malicious WHERE hash_type='md5'")]
    con.close()

    _KNOWN_BAD.parent.mkdir(parents=True, exist_ok=True)
    header = (
        "# PolyShield Intelligence DB — auto-generated, do not edit manually.\n"
        f"# Generated: {_utcnow().isoformat()}  |  Entries: {len(hashes):,}\n"
    )
    with open(_KNOWN_BAD, "w", encoding="utf-8") as f:
        f.write(header)
        for h in hashes:
            f.write(h + "\n")

    log(f"Synced {len(hashes):,} hashes to {_KNOWN_BAD.name}")


# ── Stats ─────────────────────────────────────────────────────────────────────

# ── Read-only helpers — re-exported from the dedicated read layer ─────────────
# These names are kept here for backward compatibility.  All callers
# (update_view.py, any script importing directly from tools.update_intelligence)
# continue to work without modification.
#
# TODO (tech debt): migrate callers to import directly from ui.core.intel_db
# and remove these shims once all call sites are updated.
from ui.core.intel_db import (   # noqa: F401 — re-exported for backward compat
    get_stats,
    lookup_hash,
    is_known_safe,
)


# ── Meta table helpers ────────────────────────────────────────────────────────

def get_meta(key: str, default: str = "") -> str:
    """Read one value from the meta table.  Never creates or converts the DB."""
    con = _open_db_readonly()
    if con is None:
        return default
    try:
        row = con.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row[0] if row and row[0] is not None else default
    except Exception:
        return default
    finally:
        con.close()


def set_meta(key: str, value: str) -> None:
    """Write one value to the meta table."""
    con = _open_db()
    try:
        con.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (key, value))
        con.commit()
    finally:
        con.close()


# ── Post-update hook registry ─────────────────────────────────────────────────
# Registered callbacks are invoked after an intelligence write completes, scoped
# to the *domain* of intelligence that changed:
#
#   "hashes" — malicious / safe hash tables  (MalwareBazaar, NSRL)
#   "ips"    — ip_blocklist table            (Feodo Tracker, ThreatFox)
#   "rules"  — on-disk YARA rule sets
#
# A hook means "local intelligence in domain D may have changed; refresh your
# in-memory copy" — NOT "the feed update succeeded".  The scoping matters: a
# YARA archive changing must not force Guardian to rebuild its MD5 set.
#
# guardian_engine registers reload_signatures() here so it can refresh its
# in-RAM hash set without this module importing guardian_engine (which would
# re-create the circular dependency we just broke).

_KNOWN_DOMAINS = ("hashes", "ips", "rules")

_post_update_hooks: list[tuple[Callable[[], None], frozenset]] = []


def register_post_update_hook(fn, domains=("hashes",)) -> None:
    """Register a zero-argument callable, invoked when *domains* change.

    Re-registering the same callable updates its domain set in place rather
    than queueing a second call, so repeated (idempotent) registration from
    both an eager start-up path and a lazy first-use path is safe.
    """
    doms = frozenset(domains)
    unknown = doms - set(_KNOWN_DOMAINS)
    if unknown:
        raise ValueError("unknown post-update domain(s): %s" % sorted(unknown))
    for i, (existing, _) in enumerate(_post_update_hooks):
        if existing == fn:
            _post_update_hooks[i] = (fn, doms)
            return
    _post_update_hooks.append((fn, doms))


def _fire_post_update_hooks(domains=("hashes",)) -> None:
    """Invoke every hook whose domains intersect *domains*.

    Each hook is isolated — one failing reload can never suppress the others.
    Failures are logged rather than swallowed silently.
    """
    doms = frozenset(domains)
    if not doms:
        return
    for fn, hook_doms in list(_post_update_hooks):
        if not (hook_doms & doms):
            continue
        try:
            fn()
        except Exception as exc:
            _LOG.warning(
                "post-update hook %s failed: %s",
                getattr(fn, "__qualname__", repr(fn)), exc,
            )


# ── Clear / reset helpers ─────────────────────────────────────────────────────

def clear_malicious_db(
    on_progress: Callable[[str], None] | None = None,
    notify: bool = True,
) -> dict:
    """
    Delete all rows from the malicious table and wipe known_bad.txt.
    Leaves the safe (NSRL) table untouched.
    Returns {deleted, ok}.

    Removal is an intelligence change, so it fires the "hashes" post-update
    hooks exactly as an import does.  Without that, the database said empty
    while every already-running consumer kept the hashes it loaded at start-up:
    guardian_engine went on reporting "Known Signature", and process_monitor --
    which does not merely report -- went on terminating process trees and
    quarantining executables on hashes the user had just deleted.  Nothing in
    the UI could distinguish that from the clear having failed.

    The hooks fire even when zero rows were deleted.  The contract of a
    function called "clear" is that consumers end up reflecting an empty
    database, not that DELETE happened to match something: a monitor holding a
    stale RAM set is exactly the case where the table is already empty and the
    consumer is not, and a row-count guard would skip precisely that repair.
    Pass notify=False to suppress it (the batch updater's convention).
    """
    log = on_progress or (lambda _: None)
    try:
        con = _open_db()
        count = con.execute("SELECT COUNT(*) FROM malicious").fetchone()[0]
        con.execute("DELETE FROM malicious")
        con.execute("DELETE FROM meta WHERE key='last_mb_update'")
        con.commit()
        con.close()
        log(f"Removed {count:,} malicious hashes from DB.")
    except Exception as exc:
        log(f"[ERROR] DB clear failed: {exc}")
        return {"deleted": 0, "ok": False, "error": str(exc)}

    # known_bad.txt is the pre-v1.8 load path and nothing reads it any more
    # (guardian_engine and process_monitor both SELECT from SQLite).  Kept
    # truthful rather than relied upon: the hook fired below is what actually
    # clears the RAM sets.
    try:
        if _KNOWN_BAD.exists():
            _KNOWN_BAD.write_text(
                "# PolyShield Intelligence DB — cleared.\n", encoding="utf-8")
            log(f"Cleared {_KNOWN_BAD.name}.")
    except Exception as exc:
        log(f"[WARNING] Could not clear known_bad.txt: {exc}")

    # Committed — only now may in-memory consumers be told to refresh.
    if notify:
        _fire_post_update_hooks(("hashes",))

    return {"deleted": count, "ok": True}


# ── Feodo Tracker C2 IP blocklist ────────────────────────────────────────────

def _parse_feodo(raw: str) -> list[tuple[str, str, int, str]]:
    """
    Parse Feodo Tracker CSV.
    Format: first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware
    Returns list of (ip, tags, port, malware).

    Rows whose dst_ip is not an IP are dropped rather than trusted.  The export
    carries a bare column-header row that is *not* '#'-commented, so the old
    truthiness check ("if ip") admitted the literal string "dst_ip" into the
    blocklist, where network_monitor compared every live connection against it.
    """
    records: list[tuple[str, str, int, str]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        if len(parts) < 4:
            continue
        ip      = _valid_ip(parts[1])
        port    = int(parts[2].strip()) if parts[2].strip().isdigit() else 0
        status  = parts[3].strip()
        malware = parts[5].strip() if len(parts) > 5 else ""
        if ip:
            records.append((ip, status, port, malware))
    return records


def _split_ioc_endpoint(ioc_value: str) -> tuple[str, int]:
    """Split a ThreatFox ioc_value into (ip, port).

    Three shapes reach this, and only the first two carry a port:

        1.2.3.4:443          IPv4 with port      -> one colon
        [2001:db8::1]:443    IPv6 with port      -> bracketed, per RFC 3986
        2001:db8::1          bare IPv6, no port  -> many colons, no brackets

    The previous rsplit(":", 1) treated the third case as the second and cut
    the address at its last colon, so a bare IPv6 IOC was stored as the
    meaningless prefix "2001:db8:" -- despite a docstring claiming IPv6 was
    handled.  Returns ("", 0) for anything that is not an address.
    """
    value = ioc_value.strip()
    if not value:
        return "", 0

    if value.startswith("["):
        host, _, rest = value.partition("]")
        ip = _valid_ip(host[1:])
        port_str = rest.lstrip(":")
        return ip, int(port_str) if port_str.isdigit() else 0

    # Exactly one colon can only be host:port -- an IPv6 address always has
    # at least two.  Anything else is an address in its own right.
    if value.count(":") == 1:
        host, _, port_str = value.partition(":")
        return _valid_ip(host), int(port_str) if port_str.isdigit() else 0

    return _valid_ip(value), 0


def _parse_threatfox(raw: str) -> list[tuple[str, str, int, str]]:
    """
    Parse ThreatFox ip-port CSV.
    Format: "id","ioc_type","ioc_value","malware","confidence_level"
    ioc_value is "ip:port" or "ip" (IPv4 and IPv6).
    Returns list of (ip, tags, port, malware).
    """
    records: list[tuple[str, str, int, str]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith('"id"'):
            continue
        # Strip outer quotes from each field
        parts = [p.strip().strip('"') for p in line.split('","')]
        if len(parts) < 4:
            continue
        ioc_value = parts[2] if len(parts) > 2 else ""
        malware   = parts[3] if len(parts) > 3 else ""
        confidence = parts[4].strip('"') if len(parts) > 4 else ""
        tags      = f"threatfox:{confidence}%"
        ip, port  = _split_ioc_endpoint(ioc_value)
        if ip:
            records.append((ip, tags, port, malware))
    return records


def import_c2_blocklist(
    on_progress: Callable[[str], None] | None = None,
    notify: bool = True,
) -> dict:
    """
    Download C2 IP blocklist from two sources and merge into ip_blocklist table.

    Sources (both free, regenerated every 5 min, from abuse.ch):
      • Feodo Tracker — 30-day Botnet C2 IOC CSV (Emotet, Dridex, QakBot…)
        ipblocklist.csv: all C2s seen in the past 30 days (broader than the
        "recommended" active-only subset; no aggressive/all-time list used
        due to high false positives from IP recycling)
      • ThreatFox — IP:port IOC feed, past 6 months; no finer time window
        exists in their CSV export API

    The two feeds complement each other — Feodo can go near-empty during
    takedown operations; ThreatFox bridges that gap.  Results are merged,
    deduplicated, and upserted in a single DB transaction.

    Returns: {added, updated, total_db, feodo_count, threatfox_count, error?}
    """
    log = on_progress or (lambda _: None)

    all_records: list[tuple[str, str, int, str]] = []
    feodo_count = threatfox_count = 0

    # ── Feodo Tracker (30-day IOC CSV) ───────────────────────────────────────
    log(f"Fetching Feodo Tracker…  {_FEODO_IOC_URL}")
    try:
        req = urllib.request.Request(
            _FEODO_IOC_URL,
            headers={"User-Agent": "PolyShield-Intelligence/1.0"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
        feodo_records = _parse_feodo(raw)
        feodo_count   = len(feodo_records)
        all_records.extend(feodo_records)
        log(f"  Feodo: {feodo_count:,} IPs" +
            (" (empty — may be post-takedown)" if feodo_count == 0 else ""))
    except Exception as exc:
        log(f"  [WARN] Feodo download failed: {exc} — continuing with ThreatFox only")

    # ── ThreatFox ────────────────────────────────────────────────────────────
    log(f"Fetching ThreatFox…  {_THREATFOX_URL}")
    try:
        req = urllib.request.Request(
            _THREATFOX_URL,
            headers={"User-Agent": "PolyShield-Intelligence/1.0"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
        tf_records     = _parse_threatfox(raw)
        threatfox_count = len(tf_records)
        all_records.extend(tf_records)
        log(f"  ThreatFox: {threatfox_count:,} IPs")
    except Exception as exc:
        log(f"  [WARN] ThreatFox download failed: {exc}")

    if not all_records:
        # No usable record from either feed: return an error rather than
        # {"total_db": 0}, which described an untouched blocklist table as
        # empty.  The blocklist itself is deliberately left alone — a failed
        # fetch must not cost the user the C2 intelligence they already have.
        log("[WARNING] Both feeds returned no records — check network or try again later.")
        return {"error": "both C2 feeds returned no usable records",
                "added": 0, "updated": 0,
                "feodo_count": 0, "threatfox_count": 0}

    # Deduplicate — keep last entry per IP (ThreatFox overwrites Feodo for same IP)
    deduped: dict[str, tuple[str, str, int, str]] = {}
    for ip, tags, port, malware in all_records:
        deduped[ip] = (ip, tags, port, malware)

    log(f"Merged {len(all_records):,} total → {len(deduped):,} unique IPs.  Writing to DB…")

    con   = _open_db()
    now   = _utcnow().isoformat()
    added = updated = 0

    for ip, tags, port, malware in deduped.values():
        existing = con.execute(
            "SELECT ip FROM ip_blocklist WHERE ip=?", (ip,)
        ).fetchone()
        if existing:
            con.execute(
                "UPDATE ip_blocklist SET tags=?, port=?, malware=?, added_ts=? WHERE ip=?",
                (tags, port, malware, now, ip),
            )
            updated += 1
        else:
            con.execute(
                "INSERT INTO ip_blocklist (ip, tags, port, malware, added_ts) "
                "VALUES (?, ?, ?, ?, ?)",
                (ip, tags, port, malware, now),
            )
            added += 1

    con.execute(
        "INSERT OR REPLACE INTO meta VALUES ('last_c2_update', ?)", (now,)
    )
    con.commit()
    total_db = con.execute("SELECT COUNT(*) FROM ip_blocklist").fetchone()[0]
    con.close()

    log(f"Done.  Added {added:,} new  |  {updated:,} refreshed  |  "
        f"Blocklist total: {total_db:,} IPs  "
        f"(Feodo: {feodo_count:,}, ThreatFox: {threatfox_count:,})")

    # Committed — only now may in-memory consumers be told to refresh.
    if notify:
        _fire_post_update_hooks(("ips",))

    return {
        "added":          added,
        "updated":        updated,
        "total_db":       total_db,
        "feodo_count":    feodo_count,
        "threatfox_count": threatfox_count,
    }


def get_c2_blocklist_stats() -> dict:
    """Return stats for the ip_blocklist table."""
    if not _DB_PATH.exists():
        return {"total": 0, "last_update": "Never", "db_exists": False}
    try:
        con = _open_db()
        total = con.execute("SELECT COUNT(*) FROM ip_blocklist").fetchone()[0]
        row   = con.execute(
            "SELECT value FROM meta WHERE key='last_c2_update'"
        ).fetchone()
        last  = row[0][:19].replace("T", " ") if row else "Never"
        con.close()
        return {"total": total, "last_update": last, "db_exists": True}
    except Exception:
        return {"total": 0, "last_update": "Error", "db_exists": True}


# ── YARA community rules (YARA Forge) ─────────────────────────────────────────
#
# Publishing model — the "complete-or-previous" invariant
# ───────────────────────────────────────────────────────
# yara_engine._compile() re-reads the rule directory on EVERY scan, so a scan
# that starts while an archive is being extracted would compile a half-written
# ruleset.  The previous in-view implementation made this worse: it deleted the
# live *.yar files first and then extracted one file at a time, leaving a window
# where the ruleset was empty.
#
# Instead, each download is published as an immutable generation directory:
#
#   rules/community/
#       .active                     <- text file naming the live generation
#       yara-forge-v1.2.3/*.yar     <- generations, never mutated in place
#
# The switch is a single os.replace() of the .active pointer file, which is
# atomic on Windows (MoveFileEx REPLACE_EXISTING).  A scan therefore sees either
# the whole previous generation or the whole new one.  Directory renames are
# only used for staging -> generation, where the target does not exist yet, so
# they never hit Windows' "cannot replace an existing directory" behaviour.
#
# Old generations are removed best-effort AFTER the flip; a scan still reading
# one keeps working, and a leftover directory is inert because nothing points
# at it.

_YARA_DIR         = paths.rules_dir() / "community"
_YARA_ACTIVE_FILE = _YARA_DIR / ".active"
_YARA_RELEASE_URL = "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest"
_YARA_UA          = "PolyShield-Intelligence/1.0"


def get_active_yara_generation() -> Path | None:
    """Resolve the live generation directory, or None if there is no pointer.

    Callers must fall back to the legacy flat layout (loose *.yar directly in
    rules/community/) when this returns None — installs that predate the
    generation layout still have their rules there.
    """
    try:
        if not _YARA_ACTIVE_FILE.is_file():
            return None
        name = _YARA_ACTIVE_FILE.read_text(encoding="utf-8").strip()
        if not name:
            return None
        gen = _YARA_DIR / name
        return gen if gen.is_dir() else None
    except Exception:
        return None


def get_yara_info() -> dict:
    """Return {version, last_update, rule_count} for the installed rule set."""
    info = {"version": "", "last_update": "", "rule_count": 0}
    try:
        if _DB_PATH.exists():
            con = _open_db_readonly()
            if con is not None:
                for key, field in (("yara_version", "version"),
                                   ("yara_last_update", "last_update")):
                    row = con.execute(
                        "SELECT value FROM meta WHERE key=?", (key,)
                    ).fetchone()
                    if row and row[0]:
                        info[field] = row[0]
                con.close()
    except Exception:
        pass

    gen = get_active_yara_generation()
    if gen is not None:
        info["rule_count"] = len(list(gen.glob("*.yar"))) + len(list(gen.glob("*.yara")))
        if not info["version"]:
            info["version"] = gen.name
    elif _YARA_DIR.is_dir():
        # Legacy flat layout
        info["rule_count"] = len(list(_YARA_DIR.glob("*.yar"))) + \
                             len(list(_YARA_DIR.glob("*.yara")))
        legacy_ver = _YARA_DIR / ".version"
        if not info["version"] and legacy_ver.is_file():
            try:
                info["version"] = legacy_ver.read_text(encoding="utf-8").strip()
            except Exception:
                pass
    return info


def _dacl_is_protected(path: Path):
    """True if `path`'s DACL blocks inheritance, False if it inherits, None if unknown.

    A protected DACL is the signature of the bug this guard exists for: a
    directory created by tempfile.mkdtemp() carries an explicit
    SYSTEM/Administrators/OWNER RIGHTS ACL and inherits nothing, so publishing
    it hands the machine a rule set only the publishing account can read.
    """
    try:
        import win32security
    except Exception:
        return None                      # not Windows, or pywin32 absent
    try:
        SE_DACL_PROTECTED = 0x1000
        sd = win32security.GetFileSecurity(
            str(path), win32security.DACL_SECURITY_INFORMATION)
        control, _revision = sd.GetSecurityDescriptorControl()
        return bool(control & SE_DACL_PROTECTED)
    except Exception:
        return None


def _make_staging_dir(parent: Path) -> Path:
    """Create a staging directory that INHERITS the parent's ACL.

    Deliberately not tempfile.mkdtemp(): that hardens the directory it creates
    (measured here: zero inherited ACEs vs nine from os.mkdir), which is right
    for a scratch file and wrong for one that gets promoted to shared
    application data.
    """
    import os as _os
    for attempt in range(100):
        candidate = parent / f".staging-{_os.getpid()}-{int(time.time())}-{attempt}"
        try:
            _os.mkdir(candidate)         # inherits parent ACEs on Windows
            return candidate
        except FileExistsError:
            continue
    raise RuntimeError("could not create a staging directory")


def _safe_generation_name(tag: str) -> str:
    """Turn a release tag into a directory name safe on Windows."""
    cleaned = "".join(c if (c.isalnum() or c in "._-") else "-" for c in tag).strip("-.")
    return ("yara-forge-" + cleaned)[:80] or "yara-forge-unknown"


def _fetch_yara_release(timeout: int, log) -> tuple[dict, str, dict | None]:
    """Query the YARA Forge releases API and validate the tag.

    Returns (release, tag, None), or (_, _, error-fields) which the caller
    merges into its result.  Nothing live is touched here, so a bad query
    leaves the installed rule set exactly as it was.
    """
    import json as _json
    import urllib.error as _urlerr

    log(f"Querying YARA Forge releases…  {_YARA_RELEASE_URL}")
    try:
        req = urllib.request.Request(_YARA_RELEASE_URL, headers={"User-Agent": _YARA_UA})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            release = _json.loads(resp.read().decode("utf-8"))
    except _urlerr.HTTPError as exc:
        err = f"HTTP {exc.code} from GitHub"
        log(f"[ERROR] {err}")
        return {}, "", {"error": err, "http_status": int(exc.code)}
    except Exception as exc:
        log(f"[ERROR] Release query failed: {exc}")
        return {}, "", {"error": str(exc)}

    tag = str(release.get("tag_name") or "").strip()
    if not tag:
        return {}, "", {"error": "release has no tag_name"}
    return release, tag, None


def _select_yara_zip_asset(release: dict) -> dict | None:
    """Pick the core rule ZIP from a release, else any ZIP, else None."""
    assets = release.get("assets") or []
    asset = next((a for a in assets
                  if str(a.get("name", "")).lower().endswith(".zip")
                  and "core" in str(a.get("name", "")).lower()), None)
    if asset is None:
        asset = next((a for a in assets
                      if str(a.get("name", "")).lower().endswith(".zip")), None)
    return asset


def _stamp_yara_freshness(tag: str) -> None:
    """Record what was installed and when.

    WHAT was installed and WHEN we installed it are different facts, so
    they are stored separately.
    """
    now = _utcnow().isoformat()
    con = _open_db()
    con.execute("INSERT OR REPLACE INTO meta VALUES ('yara_version', ?)", (tag,))
    con.execute("INSERT OR REPLACE INTO meta VALUES ('yara_last_update', ?)", (now,))
    con.commit()
    con.close()

    # Legacy .version file — still read by older UI code paths.
    try:
        (_YARA_DIR / ".version").write_text(tag, encoding="utf-8")
    except Exception:
        pass


def _sweep_old_generations(gen_dir) -> None:
    """Best-effort cleanup AFTER the flip.

    A scan still reading an old generation keeps working; anything we
    cannot delete is inert.
    """
    import shutil as _shutil

    for child in _YARA_DIR.iterdir():
        try:
            if child.is_dir() and child != gen_dir:
                if child.name.startswith("yara-forge-") or child.name.startswith(".staging-"):
                    _shutil.rmtree(child, ignore_errors=True)
            elif child.is_file() and child.suffix.lower() in (".yar", ".yara"):
                # Legacy flat layout — inert now that .active resolves.
                child.unlink(missing_ok=True)
        except Exception:
            pass


def download_yara_community(
    on_progress: Callable[[str], None] | None = None,
    notify: bool = True,
    force: bool = False,
    timeout: int = 60,
) -> dict:
    """Download the latest YARA Forge core rule set and publish it atomically.

    Returns {status, version, previous_version, extracted, error, http_status}
    with status one of:
      "updated"   — a new generation was published
      "unchanged" — the installed version already matches the latest release
      "failed"    — nothing was touched; the previous rule set is still live
    """
    import json as _json
    import os as _os
    import shutil as _shutil
    import tempfile as _tempfile      # zip download only — never for staging
    import urllib.error as _urlerr

    log = on_progress or (lambda _: None)
    result = {"status": "failed", "version": "", "previous_version": "",
              "extracted": 0, "error": "", "http_status": 0}

    current = get_yara_info().get("version", "")
    result["previous_version"] = current

    # 1. Latest release metadata
    release, tag, err = _fetch_yara_release(timeout, log)
    if err:
        result.update(err)
        return result
    result["version"] = tag

    gen_name = _safe_generation_name(tag)
    gen_dir  = _YARA_DIR / gen_name

    # 2. Already current?  (An existing generation dir is the real evidence —
    #    a metadata row without its files would be a lie.)
    if not force and current == tag and gen_dir.is_dir():
        log(f"Already up to date ({tag}).")
        result["status"] = "unchanged"
        result["extracted"] = len(list(gen_dir.glob("*.yar")))
        return result

    # 3. Pick the core ZIP asset
    asset = _select_yara_zip_asset(release)
    if asset is None:
        result["error"] = "no ZIP asset in release"
        log(f"[ERROR] {result['error']}")
        return result

    # 4. Download to a temp file
    tmp_zip = None
    staging = None
    try:
        log(f"  Downloading {asset.get('name')}…")
        req = urllib.request.Request(str(asset["browser_download_url"]),
                                     headers={"User-Agent": _YARA_UA})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = resp.read()
        with _tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as fh:
            tmp_zip = Path(fh.name)
            fh.write(payload)
        log(f"  Downloaded {len(payload):,} bytes.")

        # 5. Validate the archive BEFORE anything live is touched
        if not zipfile.is_zipfile(tmp_zip):
            result["error"] = "downloaded file is not a ZIP archive"
            log(f"[ERROR] {result['error']}")
            return result

        _YARA_DIR.mkdir(parents=True, exist_ok=True)
        staging = _make_staging_dir(_YARA_DIR)

        extracted = 0
        with zipfile.ZipFile(tmp_zip) as zf:
            bad = zf.testzip()          # CRC check — catches truncated downloads
            if bad is not None:
                result["error"] = f"corrupt archive member: {bad}"
                log(f"[ERROR] {result['error']}")
                return result
            for name in zf.namelist():
                low = name.lower()
                if not (low.endswith(".yar") or low.endswith(".yara")):
                    continue
                # Flatten, and never trust an archive path (zip-slip guard)
                target = staging / Path(name).name
                if target.parent.resolve() != staging.resolve():
                    continue
                target.write_bytes(zf.read(name))
                extracted += 1

        # 6. Validate the extracted tree
        if extracted == 0:
            result["error"] = "archive contained no .yar/.yara files"
            log(f"[ERROR] {result['error']}")
            return result
        result["extracted"] = extracted

        # 6b. Refuse to publish a directory nobody else can read.  os.replace
        #     carries the ACL along with the directory, so a protected DACL here
        #     becomes a live rule set only the publishing account can open —
        #     which yara_engine reports as simply "no rules", with no error.
        if _dacl_is_protected(staging) is True:
            result["error"] = ("staging directory does not inherit the rules "
                               "directory ACL; refusing to publish an unreadable "
                               "rule set")
            log(f"[ERROR] {result['error']}")
            return result

        # 7. Publish: staging -> generation (target must not exist), then flip
        #    the pointer with an atomic single-file replace.
        if gen_dir.exists():
            _shutil.rmtree(gen_dir, ignore_errors=True)
        _os.replace(str(staging), str(gen_dir))
        # Ownership transfer: the staging directory is now gen_dir, and this
        # variable is how the finally below knows not to clean it up.  It is
        # belt-and-braces rather than load-bearing -- os.replace renames, so
        # the staging path is already gone and the finally's rmtree is
        # ignore_errors -- but clear it here, the moment the replace succeeds
        # rather than once the whole publish does, so the variable never
        # outlives the thing it names.
        staging = None

        # Sanity: the move must have landed the files.  Cheap, and it catches a
        # publish that produced an empty generation for any reason.
        published = list(gen_dir.glob("*.yar")) + list(gen_dir.glob("*.yara"))
        if not published:
            result["error"] = "published generation is empty after publish"
            log(f"[ERROR] {result['error']}")
            _shutil.rmtree(gen_dir, ignore_errors=True)
            return result

        ptr_tmp = _YARA_DIR / f".active.{_os.getpid()}.tmp"
        ptr_tmp.write_text(gen_name, encoding="utf-8")
        _os.replace(str(ptr_tmp), str(_YARA_ACTIVE_FILE))
        log(f"  Published {extracted} rule file(s) as {gen_name}.")

        # 8. Freshness metadata
        _stamp_yara_freshness(tag)

        # 9. Best-effort cleanup
        _sweep_old_generations(gen_dir)

        result["status"] = "updated"
        log(f"Done.  YARA rules updated to {tag}.")

        if notify:
            _fire_post_update_hooks(("rules",))

        return result

    except Exception as exc:
        result["error"] = str(exc)
        log(f"[ERROR] YARA update failed: {exc}")
        return result
    finally:
        if tmp_zip is not None:
            try:
                tmp_zip.unlink(missing_ok=True)
            except Exception:
                pass
        if staging is not None:
            _shutil.rmtree(staging, ignore_errors=True)


# ── run_update (callable from guardian_view) ──────────────────────────────────

def run_update(
    on_progress: Callable[[str], None] | None = None,
    mode: str = "recent",
) -> dict:
    """
    Main entry point for the 'Update Signatures' button.
    Returns stats dict.
    """
    return fetch_malwarebazaar(mode=mode, on_progress=on_progress)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="PolyShield Intelligence Gatherer — update threat hash database")
    parser.add_argument("--full",  action="store_true",
                        help="Download full MalwareBazaar list (slow, ~100MB+)")
    parser.add_argument("--nsrl",  metavar="FILE",
                        help="Path to NSRLFile.txt for known-safe import")
    parser.add_argument("--stats", action="store_true",
                        help="Print database statistics and exit")
    parser.add_argument("--sync",  action="store_true",
                        help="Re-sync known_bad.txt from existing SQLite DB")
    parser.add_argument("--clear", action="store_true",
                        help="Delete all malicious hashes from DB (keeps NSRL safe table)")
    args = parser.parse_args()

    def log(msg: str):
        print(msg, flush=True)

    if args.stats:
        s = get_stats()
        print(f"\nIntelligence DB: {_DB_PATH}")
        print(f"  Malicious hashes : {s['malicious']:,}")
        print(f"  Known-safe (NSRL): {s['safe']:,}")
        print(f"  Last updated     : {s['last_update']}\n")
        return

    if args.sync:
        _sync_known_bad_txt(on_progress=log)
        return

    if args.clear:
        clear_malicious_db(on_progress=log)
        return

    if args.nsrl:
        import_nsrl(args.nsrl, on_progress=log)

    mode = "full" if args.full else "recent"
    # The importers fire their own domain-scoped post-update hooks on success.
    # Using the callback registry avoids importing ui.core.guardian_engine from
    # a tools module, which was the root cause of the circular import.
    fetch_malwarebazaar(mode=mode, on_progress=log)


if __name__ == "__main__":
    # sys.path is bootstrapped at the top of this module (see _BLOOM_PATH block)
    main()
