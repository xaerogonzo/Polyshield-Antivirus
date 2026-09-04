"""
intel_updater.py
────────────────
Scheduled refresh of the threat-intelligence feeds, and the freshness state the
UI reports.

Design invariants (see the v1.12 plan — these matter more than the shapes here)
──────────────────────────────────────────────────────────────────────────────
  • ONE writer at a time, across processes and restarts.  Readers are fine and
    expected — the UI queries the DB constantly.  What must never happen is two
    processes importing feeds concurrently.
  • ONE execution path.  The scheduler thread, the Settings "Run now" button and
    the service's RUN_INTEL_UPDATE command all enter run_updates().  There is no
    second, subtly different code path.
  • ONE notification phase per batch, fired after every feed has committed and
    AFTER the write lock is released — reloading a large hash set must not hold
    the update mutex.
  • PER-FEED status.  "Auto-update completed" is a lie when MalwareBazaar
    succeeded and ThreatFox returned 403.
  • A feed's freshness timestamp means "local data was refreshed or positively
    confirmed current" — never "we tried".  Failures never advance it.

Feeds
─────
Only the small, headless-safe feeds are automated:

    malwarebazaar → recent MD5 list      → domain "hashes"
    c2            → Feodo + ThreatFox    → domain "ips"
    yara          → YARA Forge core zip  → domain "rules"

NSRL, ClamAV freshclam, K2 signatures and Speakeasy stay manual by design —
multi-GB local imports, privileged filesystem locations, or package installs.
"""
from __future__ import annotations

import json
import logging
import os
import socket
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Callable
from ui.core import paths

log = logging.getLogger(__name__)


def _utcnow() -> datetime:
    """Naive UTC — the single time frame for all freshness arithmetic.

    The importers stamp their meta rows with UTC, so ages must be measured
    against UTC too; mixing in local time makes every stamp look hours stale
    (east of UTC) or hours in the future (west of it).  Naive rather than
    aware so it subtracts cleanly from the timestamps already stored.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)

_LOCK_PATH = paths.intelligence_dir() / ".update.lock"

# Only consulted when process liveness cannot be established at all.  It must
# never override positive evidence that the owner is alive — an import can
# legitimately run longer than any timeout worth picking.
_LOCK_MAX_AGE_SECS = 6 * 3600

_SLEEP_SLICE_SECS   = 5      # keeps stop() responsive
_CHECK_INTERVAL_SECS = 1800  # how often the thread asks "is anything due?"

# Status vocabulary for a single feed.
UPDATED   = "updated"      # local data actually changed
UNCHANGED = "unchanged"    # positively confirmed already current
SKIPPED   = "skipped"      # not due, or not enabled
FAILED    = "failed"       # attempted and failed
BACKOFF   = "backoff"      # not attempted — still inside a failure backoff window

# Freshness states reported by get_staleness().
NEVER         = "never"
FRESH         = "fresh"
AGING         = "aging"
STALE         = "stale"
ERROR         = "error"
AUTH_REQUIRED = "auth_required"


# ── Feed registry ─────────────────────────────────────────────────────────────

class _Feed:
    __slots__ = ("name", "label", "domain", "meta_key", "runner", "stamp_fallback")

    def __init__(self, name, label, domain, meta_key, runner, stamp_fallback=None):
        self.name = name
        self.label = label
        self.domain = domain
        self.meta_key = meta_key
        self.runner = runner
        # Optional: recover an approximate install time for data that predates
        # the metadata (see _legacy_yara_stamp).
        self.stamp_fallback = stamp_fallback


def _legacy_yara_stamp():
    """Best-effort install time for rules installed before v1.12.

    Installs predating the generation layout have rules and a .version file but
    no yara_last_update row.  Their mtime is weak evidence — but reporting
    "never installed" for a populated rule set would be worse, because that is
    the state the UI turns into "Intelligence update required".
    """
    from ui.core import yara_engine

    candidates = []
    try:
        legacy_ver = yara_engine._COMMUNITY_DIR / ".version"
        if legacy_ver.is_file():
            candidates.append(legacy_ver.stat().st_mtime)
        active = yara_engine.active_community_dir()
        if active is not None:
            for f in active.glob("*.yar"):
                candidates.append(f.stat().st_mtime)
                break
    except Exception:
        return None
    if not candidates:
        return None
    # st_mtime is an epoch value — convert in UTC to match the meta-row frame.
    return datetime.fromtimestamp(max(candidates), tz=timezone.utc).replace(tzinfo=None)


def _run_malwarebazaar(on_progress) -> dict:
    from tools.update_intelligence import fetch_malwarebazaar

    # Only ever "recent" on a schedule.  The full list is hundreds of MB and a
    # fresh install must never trigger it unprompted.
    res = fetch_malwarebazaar(mode="recent", on_progress=on_progress, notify=False)
    if res.get("error"):
        return {"status": FAILED, "error": res["error"],
                "http_status": int(res.get("http_status") or 0)}
    added = int(res.get("added") or 0)
    total = int(res.get("total_db") or 0)
    if total == 0 and added == 0:
        # The feed parsed to nothing — treat as a failure rather than silently
        # advancing freshness on an empty result.
        return {"status": FAILED, "error": "feed returned no usable hashes"}
    return {"status": UPDATED if added else UNCHANGED, "added": added, "total": total}


def _run_c2(on_progress) -> dict:
    from tools.update_intelligence import import_c2_blocklist

    res = import_c2_blocklist(on_progress=on_progress, notify=False)
    total = int(res.get("total_db") or 0)
    added = int(res.get("added") or 0)
    updated = int(res.get("updated") or 0)
    if total == 0 and added == 0 and updated == 0:
        return {"status": FAILED,
                "error": res.get("error") or "both C2 feeds returned no records",
                "http_status": int(res.get("http_status") or 0)}
    return {"status": UPDATED if (added or updated) else UNCHANGED,
            "added": added, "total": total}


def _run_yara(on_progress) -> dict:
    from tools.update_intelligence import download_yara_community

    res = download_yara_community(on_progress=on_progress, notify=False)
    status = res.get("status")
    if status == "updated":
        return {"status": UPDATED, "added": int(res.get("extracted") or 0),
                "version": res.get("version", "")}
    if status == "unchanged":
        return {"status": UNCHANGED, "version": res.get("version", "")}
    return {"status": FAILED, "error": res.get("error") or "unknown error",
            "http_status": int(res.get("http_status") or 0)}


_FEEDS: dict[str, _Feed] = {
    "malwarebazaar": _Feed("malwarebazaar", "MalwareBazaar hashes", "hashes",
                           "last_mb_update", _run_malwarebazaar),
    "c2":            _Feed("c2", "C2 IP blocklist", "ips",
                           "last_c2_update", _run_c2),
    "yara":          _Feed("yara", "YARA community rules", "rules",
                           "yara_last_update", _run_yara,
                           stamp_fallback=_legacy_yara_stamp),
}

FEED_NAMES = tuple(_FEEDS)


# ── Cross-process write lock ──────────────────────────────────────────────────

class _LockBusy(Exception):
    """Another process owns the intelligence write lock."""


def _owner_alive(rec: dict):
    """True = owner alive, False = demonstrably dead, None = cannot establish.

    The create_time comparison is what makes a recycled PID detectable: the OS
    may hand pid 4242 to something else after the original updater died, and
    treating that stranger as the lock owner would deadlock updates until the
    machine rebooted.
    """
    pid = rec.get("pid")
    if not isinstance(pid, int) or pid <= 0:
        return False
    if rec.get("host") and rec.get("host") != socket.gethostname():
        return None                      # another machine — cannot know
    try:
        import psutil
    except ImportError:
        return None
    try:
        proc = psutil.Process(pid)
        created = proc.create_time()
    except psutil.NoSuchProcess:
        return False
    except Exception:
        return None                      # AccessDenied etc. — be conservative
    want = rec.get("create_time")
    if isinstance(want, (int, float)) and want > 0 and abs(created - want) > 1.0:
        return False                     # PID was recycled
    return True


def _read_lock_record() -> dict | None:
    try:
        return json.loads(_LOCK_PATH.read_text(encoding="utf-8"))
    except Exception:
        return None


def _lock_payload(owner: str) -> str:
    created = 0.0
    try:
        import psutil
        created = psutil.Process(os.getpid()).create_time()
    except Exception:
        pass
    return json.dumps({
        "pid": os.getpid(),
        "create_time": created,
        "host": socket.gethostname(),
        "owner": owner,
        "started": _utcnow().isoformat(timespec="seconds"),
    })


def _try_create_lock(owner: str) -> bool:
    _LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(str(_LOCK_PATH), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        return False
    try:
        os.write(fd, _lock_payload(owner).encode("utf-8"))
    finally:
        os.close(fd)
    return True


def _acquire_file_lock(owner: str) -> None:
    """Take the cross-process lock, or raise _LockBusy.

    The lock is NEVER stolen on age alone.  Resolution order:
        acquired                              -> proceed
        owner demonstrably alive              -> busy
        owner demonstrably dead               -> remove, retry once
        ownership cannot be established       -> busy (conservative),
                                                 unless the record is older than
                                                 _LOCK_MAX_AGE_SECS, which is
                                                 the crash-recovery backstop
    """
    if _try_create_lock(owner):
        return

    rec = _read_lock_record()
    if rec is None:
        # Unreadable or half-written record.  Only reclaim if it is clearly old.
        try:
            age = time.time() - _LOCK_PATH.stat().st_mtime
        except OSError:
            raise _LockBusy("lock file present but unreadable")
        if age <= _LOCK_MAX_AGE_SECS:
            raise _LockBusy("lock file present but unreadable")
        log.warning("Reclaiming unreadable update lock after %.0f h", age / 3600)
    else:
        alive = _owner_alive(rec)
        if alive is True:
            raise _LockBusy(f"update already running (pid {rec.get('pid')}, "
                            f"{rec.get('owner', 'unknown')})")
        if alive is None:
            try:
                age = time.time() - _LOCK_PATH.stat().st_mtime
            except OSError:
                age = 0.0
            if age <= _LOCK_MAX_AGE_SECS:
                raise _LockBusy("cannot establish lock owner — assuming it is alive")
            log.warning("Lock owner pid %s unverifiable and stale for %.0f h — "
                        "reclaiming", rec.get("pid"), age / 3600)

    try:
        _LOCK_PATH.unlink(missing_ok=True)
    except OSError as exc:
        raise _LockBusy(f"could not clear dead lock: {exc}")

    if not _try_create_lock(owner):
        raise _LockBusy("lost the race to reclaim the lock")


def _release_file_lock() -> None:
    """Drop the lock, but only if this process still owns it."""
    rec = _read_lock_record()
    if rec is not None and rec.get("pid") not in (os.getpid(), None):
        log.warning("Not releasing update lock owned by pid %s", rec.get("pid"))
        return
    try:
        _LOCK_PATH.unlink(missing_ok=True)
    except OSError as exc:
        log.warning("Could not remove update lock: %s", exc)


_local_lock = threading.Lock()


# ── Backoff state ─────────────────────────────────────────────────────────────
#
# Persisted in the meta table rather than held in memory, so a service restart
# does not reset the counter and let a failing feed be hammered again.

_BACKOFF_STEPS_SECS = (3600, 7200, 14400)     # 1 h, 2 h, 4 h, then the cadence


def _backoff_key(feed: str) -> str:
    return f"feed_backoff_{feed}"


def _read_backoff(feed: str) -> dict:
    from tools.update_intelligence import get_meta
    raw = get_meta(_backoff_key(feed), "")
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except Exception:
        return {}


def _write_backoff(feed: str, state: dict | None) -> None:
    from tools.update_intelligence import set_meta
    set_meta(_backoff_key(feed), json.dumps(state) if state else "")


def _record_failure(feed: str, error: str, http_status: int, interval_hours: float) -> dict:
    prev = _read_backoff(feed)
    fails = int(prev.get("fail_count") or 0) + 1

    # An authentication wall is not a transient error: retrying it on a tight
    # schedule will never succeed and only burns the feed's rate limit.
    auth = http_status in (401, 403)
    if auth:
        delay = max(interval_hours * 3600, _BACKOFF_STEPS_SECS[-1])
    else:
        idx = min(fails - 1, len(_BACKOFF_STEPS_SECS) - 1)
        delay = min(_BACKOFF_STEPS_SECS[idx], interval_hours * 3600) \
            if interval_hours else _BACKOFF_STEPS_SECS[idx]
        delay = max(delay, _BACKOFF_STEPS_SECS[0])

    state = {
        "fail_count":  fails,
        "next_retry":  (_utcnow() + timedelta(seconds=delay)).isoformat(timespec="seconds"),
        "last_error":  (error or "")[:200],
        "http_status": int(http_status or 0),
        "last_status": AUTH_REQUIRED if auth else FAILED,
    }
    _write_backoff(feed, state)
    return state


def _clear_failure(feed: str) -> None:
    if _read_backoff(feed):
        _write_backoff(feed, None)


# ── Freshness ─────────────────────────────────────────────────────────────────

def _parse_iso(value: str):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.strip().replace(" ", "T")[:26])
    except Exception:
        return None


def _thresholds() -> tuple[float, float, float]:
    from ui.core import settings as cfg
    interval = float(cfg.get("intel_update_interval_hours") or 12)
    aging    = float(cfg.get("intel_aging_days") or 3)
    stale    = float(cfg.get("intel_stale_days") or 7)
    if stale < aging:                     # nonsensical config — keep the ordering
        stale = aging
    return interval, aging, stale


def get_staleness(now: datetime | None = None) -> dict:
    """Per-feed freshness, for the Dashboard, Update Center and service status.

    States are explicit rather than derived from a bare age number:
      never | fresh | aging | stale | error | auth_required

    A brand-new install reports "never", not "0 hours old", and a timestamp in
    the future (clock skew, or a VM snapshot restore) is clamped instead of
    reading as perpetually fresh.
    """
    from ui.core import settings as cfg
    from tools.update_intelligence import get_meta

    now = now or _utcnow()
    interval_h, aging_d, stale_d = _thresholds()
    enabled = set(cfg.get("intel_auto_feeds") or [])

    out: dict[str, dict] = {}
    for name, feed in _FEEDS.items():
        stamp = _parse_iso(get_meta(feed.meta_key, ""))
        estimated = False
        if stamp is None and feed.stamp_fallback is not None:
            try:
                stamp = feed.stamp_fallback()
                estimated = stamp is not None
            except Exception:
                stamp = None
        back  = _read_backoff(name)
        entry = {
            "label":       feed.label,
            "domain":      feed.domain,
            "enabled":     name in enabled,
            "last_update": stamp.isoformat(sep=" ", timespec="seconds") if stamp else "",
            "estimated":   estimated,
            "age_hours":   None,
            "state":       NEVER,
            "due":         False,
            "clock_skew":  False,
            "fail_count":  int(back.get("fail_count") or 0),
            "last_error":  back.get("last_error", ""),
            "next_retry":  back.get("next_retry", ""),
        }

        if back.get("last_status") == AUTH_REQUIRED:
            entry["state"] = AUTH_REQUIRED
        elif stamp is None:
            entry["state"] = NEVER
        else:
            age_h = (now - stamp).total_seconds() / 3600.0
            if age_h < 0:
                entry["clock_skew"] = True
                age_h = 0.0
            entry["age_hours"] = round(age_h, 2)
            if age_h >= stale_d * 24:
                entry["state"] = STALE
            elif age_h >= aging_d * 24:
                entry["state"] = AGING
            else:
                entry["state"] = FRESH

        # Due = old enough, enabled, and past any backoff window.
        if entry["enabled"]:
            old_enough = stamp is None or (now - stamp).total_seconds() >= interval_h * 3600
            retry_at = _parse_iso(back.get("next_retry", ""))
            entry["due"] = bool(old_enough and (retry_at is None or now >= retry_at))

        out[name] = entry
    return out


def is_anything_due(now: datetime | None = None) -> bool:
    return any(e["due"] for e in get_staleness(now).values())


# ── Posture ───────────────────────────────────────────────────────────────────

# Security-posture states.  These drive the Dashboard headline, so the two
# failure states are deliberately distinct: "update required" means we have no
# usable data for a feed, "unavailable" means we cannot read the store at all.
POSTURE_CURRENT     = "current"
POSTURE_STALE       = "stale"
POSTURE_UPDATE_REQ  = "update_required"
POSTURE_UNAVAILABLE = "unavailable"

_POSTURE_HEADLINE = {
    POSTURE_CURRENT:     "Protected — intelligence current",
    POSTURE_STALE:       "Protected — intelligence stale",
    POSTURE_UPDATE_REQ:  "Intelligence update required",
    POSTURE_UNAVAILABLE: "Intelligence unavailable",
}

_POSTURE_LEVEL = {
    POSTURE_CURRENT:     "ok",
    POSTURE_STALE:       "warn",
    POSTURE_UPDATE_REQ:  "warn",
    POSTURE_UNAVAILABLE: "error",
}


def get_usability() -> dict:
    """Per-feed evidence that the data can actually be USED, not just that it
    was downloaded.

    This exists because freshness metadata answers the wrong question.  A YARA
    generation published with a non-inheriting ACL reads as `fresh` while
    yara_engine reports zero rules and silently stops contributing to scans.

    `readable` means "the store could be read", which is NOT the same as "the
    store has something in it".  A database that does not exist yet is readable
    and empty — a fresh install — and belongs in get_posture()'s
    `update_required` branch, not its `unavailable` one.
    """
    out: dict[str, dict] = {}

    try:
        from ui.core.intel_db import get_stats
        stats = get_stats()
        # "Error" is the only unreadable signal.  get_stats() reports an absent
        # database as db_exists=False / last_update="Never", and one it could
        # not open as last_update="Error".  Requiring db_exists here collapsed
        # those two, so a fresh install — nothing downloaded yet — took
        # get_posture()'s "the intelligence database could not be read" branch
        # rather than its "never updated" one, directly beneath a Getting
        # Started card telling the user to populate it.
        readable = stats.get("last_update") != "Error"
        count = int(stats.get("malicious") or 0)
        out["malwarebazaar"] = {"usable": readable and count > 0, "count": count,
                                "unit": "hashes", "readable": readable}
    except Exception as exc:
        out["malwarebazaar"] = {"usable": False, "count": 0, "unit": "hashes",
                                "readable": False, "error": str(exc)}

    try:
        from tools.update_intelligence import get_c2_blocklist_stats
        stats = get_c2_blocklist_stats()
        readable = stats.get("last_update") != "Error"   # see malwarebazaar above
        count = int(stats.get("total") or 0)
        out["c2"] = {"usable": readable and count > 0, "count": count,
                     "unit": "IPs", "readable": readable}
    except Exception as exc:
        out["c2"] = {"usable": False, "count": 0, "unit": "IPs",
                     "readable": False, "error": str(exc)}

    try:
        from ui.core import yara_engine
        count = int(yara_engine.get_rule_count() or 0)
        out["yara"] = {"usable": count > 0, "count": count,
                       "unit": "rule files", "readable": True}
    except Exception as exc:
        out["yara"] = {"usable": False, "count": 0, "unit": "rule files",
                       "readable": False, "error": str(exc)}

    return out


def get_posture(now: datetime | None = None) -> dict:
    """Combine freshness and usability into one honest headline.

    | state           | condition                                              |
    |-----------------|--------------------------------------------------------|
    | current         | every enabled feed usable and within its thresholds    |
    | stale           | data exists and is usable, but a feed is past `stale`  |
    | update_required | an enabled feed has never populated, or has no usable  |
    |                 | data despite what its metadata claims                  |
    | unavailable     | the intelligence store itself cannot be read           |

    Stale intelligence degrades the headline but never claims zero protection —
    the hash tiers keep working on what is already there.
    """
    feeds = get_staleness(now)
    usable = get_usability()
    enabled = [n for n, e in feeds.items() if e.get("enabled")]
    if not enabled:
        enabled = list(feeds)

    # Store unreadable → nothing else is meaningful.
    hash_state = usable.get("malwarebazaar", {})
    if not hash_state.get("readable", False):
        state = POSTURE_UNAVAILABLE
        detail = "The intelligence database could not be read."
        return _posture_result(state, detail, feeds, usable, enabled)

    unusable = [n for n in enabled
                if not usable.get(n, {}).get("usable", False)
                or feeds[n]["state"] == NEVER]
    if unusable:
        names = ", ".join(feeds[n]["label"] for n in unusable)
        # Distinguish "never downloaded" from "downloaded but unusable" — the
        # second is the ACL-style failure and needs different words.
        never = [n for n in unusable if feeds[n]["state"] == NEVER]
        if len(never) == len(unusable):
            detail = f"Never updated: {names}"
        else:
            broken = [feeds[n]["label"] for n in unusable if n not in never]
            detail = ("Reported current but unusable: " + ", ".join(broken)
                      + (f"; never updated: {', '.join(feeds[n]['label'] for n in never)}"
                         if never else ""))
        return _posture_result(POSTURE_UPDATE_REQ, detail, feeds, usable, enabled)

    stale = [n for n in enabled if feeds[n]["state"] in (STALE, AUTH_REQUIRED)]
    if stale:
        names = ", ".join(feeds[n]["label"] for n in stale)
        auth = [n for n in stale if feeds[n]["state"] == AUTH_REQUIRED]
        detail = (f"Feed authentication required: {names}" if auth
                  else f"Out of date: {names}")
        return _posture_result(POSTURE_STALE, detail, feeds, usable, enabled)

    aging = [n for n in enabled if feeds[n]["state"] == AGING]
    detail = ("Ageing: " + ", ".join(feeds[n]["label"] for n in aging)
              if aging else "All feeds up to date.")
    return _posture_result(POSTURE_CURRENT, detail, feeds, usable, enabled)


def _posture_result(state, detail, feeds, usable, enabled) -> dict:
    return {
        "state":    state,
        "headline": _POSTURE_HEADLINE[state],
        "level":    _POSTURE_LEVEL[state],
        "detail":   detail,
        "feeds":    feeds,
        "usable":   usable,
        "enabled":  enabled,
    }


# ── The one execution path ────────────────────────────────────────────────────

def _service_owns_updates() -> bool:
    try:
        from ui.core import service_client as svc
        return bool(svc.is_service_running())
    except Exception:
        return False


def _run_one_feed(name: str, feed, info: dict, force: bool,
                  interval_h: int, log_fn) -> dict:
    """Run a single feed and return its outcome dict.

    Decides skip / backoff / run for one feed, and records success or failure
    against its backoff state.  Returns the outcome rather than writing it, so
    the caller stays the only place that knows about the batch: the lock it
    holds, the domains that changed, and the roll-up.

    Never raises -- a feed that blows up becomes a FAILED outcome, because one
    bad feed must not take the rest of the batch with it.
    """
    if not force:
        if not info.get("enabled", False):
            return {"status": SKIPPED, "reason": "feed disabled"}
        if not info.get("due", False):
            back = _read_backoff(name)
            if back.get("next_retry"):
                return {
                    "status": BACKOFF,
                    "reason": f"retry after {back['next_retry']}",
                    "last_error": back.get("last_error", ""),
                    "fail_count": int(back.get("fail_count") or 0),
                }
            return {"status": SKIPPED, "reason": "not due yet"}

    log_fn(f"── {feed.label} ──")
    try:
        outcome = feed.runner(log_fn)
    except Exception as exc:          # a feed must never kill the batch
        log.exception("Feed %s raised", name)
        outcome = {"status": FAILED, "error": str(exc)}

    status = outcome.get("status", FAILED)
    if status == FAILED:
        back = _record_failure(name, outcome.get("error", ""),
                               int(outcome.get("http_status") or 0),
                               interval_h)
        outcome["next_retry"] = back["next_retry"]
        outcome["fail_count"] = back["fail_count"]
        if back["last_status"] == AUTH_REQUIRED:
            outcome["status"] = FAILED
            outcome["auth_required"] = True
    else:
        _clear_failure(name)

    return outcome


def run_updates(
    feeds: list[str] | None = None,
    force: bool = False,
    on_progress: Callable[[str], None] | None = None,
    owner: str = "ui",
    notify: bool = True,
) -> dict:
    """Refresh the selected feeds.  The single entry point for every caller.

    owner:  "service" | "ui" | "cli" — recorded in the lock file, and used for
            the ownership rule: a UI-side run aborts if the service is running,
            because the service is the designated writer whenever it exists.

    Returns {status, feeds: {name: {...}}, started, finished, error}
    where status is one of updated / unchanged / partial / failed / skipped /
    already_running.
    """
    log_fn = on_progress or (lambda _: None)
    started = _utcnow()
    result = {"status": SKIPPED, "feeds": {}, "error": "",
              "started": started.isoformat(timespec="seconds"), "finished": ""}

    names = list(feeds) if feeds else None
    if names is None:
        from ui.core import settings as cfg
        names = list(cfg.get("intel_auto_feeds") or FEED_NAMES)
    names = [n for n in names if n in _FEEDS]
    if not names:
        result["error"] = "no known feeds selected"
        result["finished"] = _utcnow().isoformat(timespec="seconds")
        return result

    if not _local_lock.acquire(blocking=False):
        result["status"] = "already_running"
        result["error"] = "an update is already running in this process"
        result["finished"] = _utcnow().isoformat(timespec="seconds")
        return result

    changed_domains: set[str] = set()
    try:
        # Ownership re-check INSIDE the updater, immediately before any network
        # or database write.  A caller that checked at start-up cannot close the
        # race — the service may have started in between.
        if owner != "service" and _service_owns_updates():
            result["status"] = SKIPPED
            result["error"] = "the PolyShield service owns intelligence updates"
            log_fn("Service is running — it owns intelligence updates.")
            result["finished"] = _utcnow().isoformat(timespec="seconds")
            return result

        # In a distribution the service owns updates even when it is NOT
        # running.  intelligence/ is service-owned on disk (Users:Read), so a
        # UI-side run would not be merely redundant -- it would fail inside
        # each importer with a permission error, and those surface in the
        # Update Center looking like network failures. Say the real thing once.
        if owner != "service" and paths.is_distribution():
            result["status"] = FAILED
            result["error"] = ("the PolyShield service is required to update "
                               "intelligence, and it is not running")
            log_fn("The PolyShield service is not running - it is the only "
                   "writer for intelligence data in an installed build.")
            result["finished"] = _utcnow().isoformat(timespec="seconds")
            return result

        try:
            _acquire_file_lock(owner)
        except _LockBusy as exc:
            result["status"] = "already_running"
            result["error"] = str(exc)
            log_fn(f"Skipped — {exc}")
            result["finished"] = _utcnow().isoformat(timespec="seconds")
            return result

        try:
            interval_h, _, _ = _thresholds()
            state = get_staleness()
            for name in names:
                feed = _FEEDS[name]
                outcome = _run_one_feed(name, feed, state.get(name, {}),
                                        force, interval_h, log_fn)
                # Accumulated here rather than in the helper: the notification
                # phase below fires once for the union, not once per feed.
                if outcome.get("status") == UPDATED:
                    changed_domains.add(feed.domain)
                result["feeds"][name] = outcome
        finally:
            # Released BEFORE the notification phase: reloading a large hash set
            # must never happen while holding the update mutex.
            _release_file_lock()

        statuses = {v.get("status") for v in result["feeds"].values()}
        if statuses <= {SKIPPED, BACKOFF}:
            result["status"] = SKIPPED
        elif FAILED in statuses and (UPDATED in statuses or UNCHANGED in statuses):
            result["status"] = "partial"
        elif FAILED in statuses:
            result["status"] = FAILED
        elif UPDATED in statuses:
            result["status"] = UPDATED
        else:
            result["status"] = UNCHANGED

        if result["status"] not in (SKIPPED, "already_running"):
            try:
                from ui.core import settings as cfg
                cfg.set_value("intel_last_auto_run", started.isoformat(timespec="seconds"))
            except Exception as exc:
                # Logged, not swallowed: a silent failure here would leave the
                # UI reporting "never run" after every successful update.
                log.warning("Could not record intel_last_auto_run: %s", exc)

        # ONE notification phase, for the union of domains that actually changed.
        if notify and changed_domains:
            try:
                from tools.update_intelligence import _fire_post_update_hooks
                _fire_post_update_hooks(tuple(sorted(changed_domains)))
                log_fn(f"Refreshed in-memory consumers: {', '.join(sorted(changed_domains))}")
            except Exception as exc:
                log.warning("Post-update notification failed: %s", exc)

        result["finished"] = _utcnow().isoformat(timespec="seconds")
        return result
    finally:
        _local_lock.release()


def request_update(feeds: list[str] | None = None, force: bool = True,
                   on_progress=None) -> dict:
    """Route an update request to whoever owns intelligence writes.

    Every UI surface calls this, never run_updates() directly — otherwise the
    Dashboard button and the Settings button could disagree about who writes.
    """
    try:
        from ui.core import service_client as svc
        if svc.is_service_running():
            resp = svc.send_command("RUN_INTEL_UPDATE",
                                    feeds=list(feeds) if feeds else None,
                                    force=bool(force))
            if resp and resp.get("ok"):
                return {"status": resp.get("status", "started"),
                        "feeds": resp.get("feeds", {}),
                        "via": "service", "error": resp.get("error", "")}
            # Service running but the command is unknown (older build) — fall
            # through to a local run.  The cross-process lock keeps that safe.
            log.info("Service did not accept RUN_INTEL_UPDATE; running locally.")
    except Exception as exc:
        log.debug("Service routing unavailable: %s", exc)

    out = run_updates(feeds=feeds, force=force, on_progress=on_progress, owner="ui")
    out["via"] = "local"
    return out


def build_update_event(result: dict) -> dict:
    """The wire shape for an intel_update event.

    Shared by the scheduler thread and the service's on-demand handler so a
    scheduled run and a "Run now" run are indistinguishable to the UI — they are
    the same operation and should not read as two different features.
    """
    feeds = result.get("feeds", {}) or {}
    return {
        "event":   "intel_update",
        "status":  result.get("status", ""),
        "summary": ", ".join(f"{name}: {info.get('status')}"
                             for name, info in feeds.items()),
        "feeds":   feeds,
        "error":   result.get("error", ""),
        "time":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# ── Scheduler thread ──────────────────────────────────────────────────────────

class IntelUpdaterThread:
    """Background scheduler: wakes periodically and refreshes what is due.

    Modelled on NetworkMonitorThread.  The loop sleeps in short slices so stop()
    is responsive; the HTTP calls inside a feed carry their own bounded timeouts
    so a stop during a download cannot delay service shutdown indefinitely.
    """

    def __init__(self, push_event: Callable[[dict], None] | None = None,
                 check_interval: int = _CHECK_INTERVAL_SECS,
                 owner: str = "service"):
        self._push = push_event
        self._check_interval = max(60, int(check_interval))
        self._owner = owner
        self._stop_evt = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_result: dict = {}

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self) -> bool:
        if self.is_running():
            return True
        from ui.core import settings as cfg
        if not cfg.get("intel_auto_update"):
            log.info("Intelligence auto-update disabled by settings.")
            return False
        self._stop_evt.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="IntelUpdater")
        self._thread.start()
        return True

    def stop(self) -> None:
        self._stop_evt.set()
        t = self._thread
        if t is not None and t.is_alive():
            t.join(timeout=10)
        self._thread = None

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def last_result(self) -> dict:
        return dict(self._last_result)

    # ── Internals ─────────────────────────────────────────────────────────────

    def _sleep(self, seconds: float) -> bool:
        """Sleep in slices.  Returns False if asked to stop."""
        remaining = seconds
        while remaining > 0:
            if self._stop_evt.wait(min(_SLEEP_SLICE_SECS, remaining)):
                return False
            remaining -= _SLEEP_SLICE_SECS
        return True

    def _loop(self) -> None:
        log.info("Intelligence updater started (check every %d s).", self._check_interval)
        # Small settle delay so a service start does not immediately hit the
        # network while the watcher and monitors are still coming up.
        if not self._sleep(60):
            return
        while not self._stop_evt.is_set():
            try:
                from ui.core import settings as cfg
                if cfg.get("intel_auto_update") and is_anything_due():
                    result = run_updates(force=False, owner=self._owner,
                                         on_progress=lambda m: log.info("  %s", m))
                    self._last_result = result
                    self._emit(result)
            except Exception as exc:
                log.warning("Intelligence updater cycle failed: %s", exc)
            if not self._sleep(self._check_interval):
                break
        log.info("Intelligence updater stopped.")

    def _emit(self, result: dict) -> None:
        if self._push is None or result.get("status") in (SKIPPED, "already_running"):
            return
        try:
            self._push(build_update_event(result))
        except Exception as exc:
            log.debug("Could not push intel_update event: %s", exc)
