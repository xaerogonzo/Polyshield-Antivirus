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
import sqlite3
import sys
import urllib.request
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Callable

# ── Paths ─────────────────────────────────────────────────────────────────────

_ROOT         = Path(__file__).resolve().parents[2]
_DB_PATH      = _ROOT / "intelligence" / "threat_db.sqlite"
_KNOWN_BAD    = _ROOT / "guardianai" / "data" / "known_bad.txt"
_BLOOM_PATH   = _ROOT / "intelligence" / "nsrl_bloom.bin"

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


def _open_db() -> sqlite3.Connection:
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(_DB_PATH))
    con.executescript(_SCHEMA)
    con.commit()
    return con


# ── MalwareBazaar import ──────────────────────────────────────────────────────

def fetch_malwarebazaar(
    mode: str = "recent",
    on_progress: Callable[[str], None] | None = None,
) -> dict:
    """
    Download MalwareBazaar hash list and insert into the SQLite malicious table.

    v1.8+: hashes are loaded directly from SQLite by guardian_engine and
    process_monitor; known_bad.txt is no longer written automatically.

    mode: "recent" (24h, fast) | "full" (all, slow ~100MB+ download)
    Returns stats dict: {added, skipped, total_db}
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
        log(f"[ERROR] Download failed: {exc}")
        return {"error": str(exc)}

    log(f"Downloaded {len(raw_bytes):,} bytes.  Parsing…")

    # The full list is a ZIP; recent list is plain text
    if raw_bytes[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
            name = zf.namelist()[0]
            text = zf.read(name).decode("utf-8", errors="ignore")
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
        log("[WARNING] No valid MD5 hashes found in downloaded file.")
        return {"added": 0, "skipped": 0, "total_db": 0}

    log(f"Found {len(hashes):,} valid MD5 hashes.  Writing to DB…")

    con = _open_db()
    now = datetime.utcnow().isoformat()
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
    return {"added": added, "skipped": skipped, "total_db": total_db}


# ── NSRL import ───────────────────────────────────────────────────────────────

def import_nsrl(
    nsrl_path: str,
    on_progress: Callable[[str], None] | None = None,
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
    # Mark bloom stale immediately — if we crash mid-import the old .bin is invalid
    con.execute("INSERT OR REPLACE INTO meta VALUES ('nsrl_bloom_stale', '1')")
    con.commit()

    now = datetime.utcnow().isoformat()
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

    con.commit()
    total = con.execute("SELECT COUNT(*) FROM safe").fetchone()[0]
    log(f"NSRL import complete.  Added {added:,}  |  Safe DB total: {total:,}")

    # Rebuild the bloom filter now that the import is complete
    def _bloom_progress(pct: int) -> None:
        log(f"  Building NSRL bloom filter… {pct}%")

    _rebuild_nsrl_bloom(con, progress_cb=_bloom_progress)
    con.close()
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
    with open(_BLOOM_PATH, "wb") as f:
        bloom.tofile(f)

    # Mark bloom as up-to-date
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
        f"# Generated: {datetime.utcnow().isoformat()}  |  Entries: {len(hashes):,}\n"
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


# ── Post-update hook registry ─────────────────────────────────────────────────
# Registered callbacks are invoked after every intelligence DB write completes.
# guardian_engine registers reload_signatures() here at first-scan time so it
# can refresh its in-RAM hash set without this module importing guardian_engine
# (which would re-create the circular dependency we just broke).

_post_update_hooks: list = []


def register_post_update_hook(fn) -> None:
    """Register a zero-argument callable to invoke after every DB update."""
    if fn not in _post_update_hooks:
        _post_update_hooks.append(fn)


def _fire_post_update_hooks() -> None:
    for fn in list(_post_update_hooks):
        try:
            fn()
        except Exception:
            pass


# ── Clear / reset helpers ─────────────────────────────────────────────────────

def clear_malicious_db(
    on_progress: Callable[[str], None] | None = None,
) -> dict:
    """
    Delete all rows from the malicious table and wipe known_bad.txt.
    Leaves the safe (NSRL) table untouched.
    Returns {deleted, ok}.
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

    # Wipe known_bad.txt so guardian_engine RAM set is cleared too
    try:
        if _KNOWN_BAD.exists():
            _KNOWN_BAD.write_text(
                "# PolyShield Intelligence DB — cleared.\n", encoding="utf-8")
            log(f"Cleared {_KNOWN_BAD.name}.")
    except Exception as exc:
        log(f"[WARNING] Could not clear known_bad.txt: {exc}")

    return {"deleted": count, "ok": True}


# ── Feodo Tracker C2 IP blocklist ────────────────────────────────────────────

def _parse_feodo(raw: str) -> list[tuple[str, str, int, str]]:
    """
    Parse Feodo Tracker CSV.
    Format: first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware
    Returns list of (ip, tags, port, malware).
    """
    records: list[tuple[str, str, int, str]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        if len(parts) < 4:
            continue
        ip      = parts[1].strip()
        port    = int(parts[2].strip()) if parts[2].strip().isdigit() else 0
        status  = parts[3].strip()
        malware = parts[5].strip() if len(parts) > 5 else ""
        if ip:
            records.append((ip, status, port, malware))
    return records


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
        # ioc_value is "ip:port" — split on last colon to handle IPv6 too
        if ":" in ioc_value:
            rsplit    = ioc_value.rsplit(":", 1)
            ip        = rsplit[0]
            port_str  = rsplit[1]
            port      = int(port_str) if port_str.isdigit() else 0
        else:
            ip   = ioc_value
            port = 0
        if ip:
            records.append((ip, tags, port, malware))
    return records


def import_c2_blocklist(
    on_progress: Callable[[str], None] | None = None,
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
        log("[WARNING] Both feeds returned no records — check network or try again later.")
        return {"added": 0, "updated": 0, "total_db": 0,
                "feodo_count": 0, "threatfox_count": 0}

    # Deduplicate — keep last entry per IP (ThreatFox overwrites Feodo for same IP)
    deduped: dict[str, tuple[str, str, int, str]] = {}
    for ip, tags, port, malware in all_records:
        deduped[ip] = (ip, tags, port, malware)

    log(f"Merged {len(all_records):,} total → {len(deduped):,} unique IPs.  Writing to DB…")

    con   = _open_db()
    now   = datetime.utcnow().isoformat()
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
    fetch_malwarebazaar(mode=mode, on_progress=log)

    # Fire registered post-update hooks (e.g. guardian_engine.reload_signatures).
    # Using the callback registry avoids importing ui.core.guardian_engine from
    # a tools module, which was the root cause of the circular import.
    _fire_post_update_hooks()


if __name__ == "__main__":
    # Allow running from project root without installing package
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    main()
