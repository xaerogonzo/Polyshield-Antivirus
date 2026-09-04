"""
Phase B tests — the updater core.

Covers the invariants that matter more than the code shape: one writer, one
execution path, per-feed status, no freshness advance on failure, persistent
backoff, a single notification phase, and a YARA publish that a scan can never
catch half-finished.

No test touches the network: feed runners are swapped for fakes, and the YARA
downloader is driven through a stubbed urlopen.
"""
from __future__ import annotations

import io
import json
import os
import sqlite3
import zipfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from conftest import add_malicious
from ui.core.intel_updater import _utcnow

# All freshness arithmetic runs in naive UTC (see intel_updater._utcnow).
# Using datetime.now() in these tests would pass on a UTC machine and fail
# everywhere else - exactly the bug they exist to catch.


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def updater(intel_db, hooks, settings_sandbox, tmp_path, monkeypatch):
    """intel_updater wired to the temp DB, a temp lock path, and no service."""
    from ui.core import intel_updater as iu

    monkeypatch.setattr(iu, "_LOCK_PATH", tmp_path / ".update.lock")
    monkeypatch.setattr(iu, "_service_owns_updates", lambda: False)
    return iu


def _fake_runner(status, **extra):
    def run(on_progress):
        on_progress("fake feed ran")
        return {"status": status, **extra}
    return run


def _set_runner(iu, name, runner):
    iu._FEEDS[name].runner = runner


@pytest.fixture(autouse=True)
def _restore_runners():
    """Feed runners are module-level state — put the real ones back."""
    from ui.core import intel_updater as iu
    original = {n: f.runner for n, f in iu._FEEDS.items()}
    yield
    for n, r in original.items():
        iu._FEEDS[n].runner = r


def _stamp(iu, feed_name, when: datetime):
    from tools.update_intelligence import set_meta
    set_meta(iu._FEEDS[feed_name].meta_key, when.isoformat())


# ── Cross-process lock ────────────────────────────────────────────────────────

def test_lock_is_not_stolen_from_a_live_owner(updater, monkeypatch):
    """An import may legitimately outrun any timeout — age alone must never
    hand the lock to a second writer."""
    iu = updater
    assert iu._try_create_lock("service") is True

    # Pretend the record is ancient but its owner is demonstrably alive.
    monkeypatch.setattr(iu, "_LOCK_MAX_AGE_SECS", 0)
    monkeypatch.setattr(iu, "_owner_alive", lambda rec: True)

    with pytest.raises(iu._LockBusy):
        iu._acquire_file_lock("ui")


def test_lock_reclaimed_from_a_dead_owner(updater, monkeypatch):
    iu = updater
    assert iu._try_create_lock("service") is True
    monkeypatch.setattr(iu, "_owner_alive", lambda rec: False)

    iu._acquire_file_lock("ui")          # must not raise
    rec = iu._read_lock_record()
    assert rec["pid"] == os.getpid()
    assert rec["owner"] == "ui"


def test_recycled_pid_is_not_treated_as_the_owner(updater, monkeypatch):
    """Same PID, different process start time — the OS reused the number."""
    iu = updater
    iu._LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    iu._LOCK_PATH.write_text(json.dumps({
        "pid": os.getpid(),
        "create_time": 1.0,              # nothing has started at epoch+1s
        "host": iu.socket.gethostname(),
        "owner": "service",
    }), encoding="utf-8")

    assert iu._owner_alive(iu._read_lock_record()) is False
    iu._acquire_file_lock("ui")          # reclaimed
    assert iu._read_lock_record()["owner"] == "ui"


def test_unverifiable_owner_is_treated_as_busy(updater, monkeypatch):
    """If we cannot establish ownership we refuse to write — the conservative
    choice, because the alternative risks two writers."""
    iu = updater
    assert iu._try_create_lock("service") is True
    monkeypatch.setattr(iu, "_owner_alive", lambda rec: None)

    with pytest.raises(iu._LockBusy):
        iu._acquire_file_lock("ui")


def test_unverifiable_owner_reclaimed_only_after_max_age(updater, monkeypatch):
    iu = updater
    assert iu._try_create_lock("service") is True
    monkeypatch.setattr(iu, "_owner_alive", lambda rec: None)
    monkeypatch.setattr(iu, "_LOCK_MAX_AGE_SECS", -1)   # everything is "old"

    iu._acquire_file_lock("ui")
    assert iu._read_lock_record()["owner"] == "ui"


def test_run_updates_reports_already_running_when_locked(updater, monkeypatch):
    iu = updater
    assert iu._try_create_lock("service") is True
    monkeypatch.setattr(iu, "_owner_alive", lambda rec: True)

    out = iu.run_updates(feeds=["malwarebazaar"], force=True)
    assert out["status"] == "already_running"
    assert out["feeds"] == {}


def test_lock_is_released_after_a_run(updater):
    iu = updater
    _set_runner(iu, "malwarebazaar", _fake_runner(iu.UPDATED, added=3, total=3))
    iu.run_updates(feeds=["malwarebazaar"], force=True)
    assert not iu._LOCK_PATH.exists()


# ── Ownership routing ─────────────────────────────────────────────────────────

def test_ui_run_defers_to_a_running_service(updater, monkeypatch):
    """The re-check lives inside the updater: a caller that probed at start-up
    cannot close the race, because the service may start in between."""
    iu = updater
    monkeypatch.setattr(iu, "_service_owns_updates", lambda: True)
    _set_runner(iu, "malwarebazaar", _fake_runner(iu.UPDATED))

    out = iu.run_updates(feeds=["malwarebazaar"], force=True, owner="ui")
    assert out["status"] == iu.SKIPPED
    assert "service" in out["error"]
    assert out["feeds"] == {}


def test_service_run_is_not_blocked_by_itself(updater, monkeypatch):
    iu = updater
    monkeypatch.setattr(iu, "_service_owns_updates", lambda: True)
    _set_runner(iu, "malwarebazaar", _fake_runner(iu.UPDATED, added=1, total=1))

    out = iu.run_updates(feeds=["malwarebazaar"], force=True, owner="service")
    assert out["status"] == iu.UPDATED


# ── Per-feed status ───────────────────────────────────────────────────────────

def test_partial_failure_is_reported_per_feed(updater):
    iu = updater
    _set_runner(iu, "malwarebazaar", _fake_runner(iu.UPDATED, added=12, total=99))
    _set_runner(iu, "c2", _fake_runner(iu.FAILED, error="HTTP 403", http_status=403))

    out = iu.run_updates(feeds=["malwarebazaar", "c2"], force=True)

    assert out["status"] == "partial"
    assert out["feeds"]["malwarebazaar"]["status"] == iu.UPDATED
    assert out["feeds"]["c2"]["status"] == iu.FAILED
    assert out["feeds"]["c2"]["auth_required"] is True


def test_all_feeds_failing_is_failed_overall(updater):
    iu = updater
    _set_runner(iu, "malwarebazaar", _fake_runner(iu.FAILED, error="timeout"))
    _set_runner(iu, "c2", _fake_runner(iu.FAILED, error="timeout"))

    out = iu.run_updates(feeds=["malwarebazaar", "c2"], force=True)
    assert out["status"] == iu.FAILED


def test_unchanged_feeds_are_not_reported_as_updated(updater):
    iu = updater
    _set_runner(iu, "yara", _fake_runner(iu.UNCHANGED, version="v1"))
    out = iu.run_updates(feeds=["yara"], force=True)
    assert out["status"] == iu.UNCHANGED


def test_a_raising_feed_does_not_kill_the_batch(updater):
    iu = updater

    def explode(on_progress):
        raise RuntimeError("feed blew up")

    _set_runner(iu, "malwarebazaar", explode)
    _set_runner(iu, "c2", _fake_runner(iu.UPDATED, added=1, total=1))

    out = iu.run_updates(feeds=["malwarebazaar", "c2"], force=True)
    assert out["feeds"]["malwarebazaar"]["status"] == iu.FAILED
    assert "blew up" in out["feeds"]["malwarebazaar"]["error"]
    assert out["feeds"]["c2"]["status"] == iu.UPDATED


# ── Freshness must not advance on failure ─────────────────────────────────────

def test_failure_does_not_advance_freshness(updater):
    iu = updater
    from tools.update_intelligence import get_meta

    before = _utcnow() - timedelta(days=30)
    _stamp(iu, "malwarebazaar", before)
    _set_runner(iu, "malwarebazaar", _fake_runner(iu.FAILED, error="timeout"))

    iu.run_updates(feeds=["malwarebazaar"], force=True)

    assert get_meta("last_mb_update").startswith(before.isoformat()[:16])


# ── Backoff ───────────────────────────────────────────────────────────────────

def test_backoff_is_persisted_and_survives_a_restart(updater):
    """State lives in the meta table, not in memory — otherwise a service
    restart would reset the counter and hammer a failing feed again."""
    iu = updater
    _set_runner(iu, "c2", _fake_runner(iu.FAILED, error="timeout"))

    iu.run_updates(feeds=["c2"], force=True)
    first = iu._read_backoff("c2")
    assert first["fail_count"] == 1
    assert first["next_retry"]

    iu.run_updates(feeds=["c2"], force=True)
    assert iu._read_backoff("c2")["fail_count"] == 2      # read back from SQLite


def test_success_clears_backoff(updater):
    iu = updater
    _set_runner(iu, "c2", _fake_runner(iu.FAILED, error="timeout"))
    iu.run_updates(feeds=["c2"], force=True)
    assert iu._read_backoff("c2")

    _set_runner(iu, "c2", _fake_runner(iu.UPDATED, added=5, total=5))
    iu.run_updates(feeds=["c2"], force=True)
    assert iu._read_backoff("c2") == {}


def test_auth_failure_backs_off_further_than_a_timeout(updater):
    iu = updater
    _set_runner(iu, "c2", _fake_runner(iu.FAILED, error="forbidden", http_status=403))
    iu.run_updates(feeds=["c2"], force=True)
    auth_retry = datetime.fromisoformat(iu._read_backoff("c2")["next_retry"])

    iu._write_backoff("malwarebazaar", None)
    _set_runner(iu, "malwarebazaar", _fake_runner(iu.FAILED, error="timeout"))
    iu.run_updates(feeds=["malwarebazaar"], force=True)
    timeout_retry = datetime.fromisoformat(iu._read_backoff("malwarebazaar")["next_retry"])

    assert auth_retry > timeout_retry
    assert iu._read_backoff("c2")["last_status"] == iu.AUTH_REQUIRED


def test_feed_in_backoff_is_not_attempted(updater):
    iu = updater
    iu._write_backoff("c2", {
        "fail_count": 2,
        "next_retry": (_utcnow() + timedelta(hours=2)).isoformat(timespec="seconds"),
        "last_error": "timeout",
        "last_status": iu.FAILED,
    })
    _stamp(iu, "c2", _utcnow() - timedelta(days=30))

    calls = []

    def spy(on_progress):
        calls.append(1)
        return {"status": iu.UPDATED}

    _set_runner(iu, "c2", spy)

    out = iu.run_updates(feeds=["c2"], force=False)
    assert out["feeds"]["c2"]["status"] == iu.BACKOFF
    assert calls == [], "a feed inside its backoff window must not be contacted"


# ── Notification phase ────────────────────────────────────────────────────────

def test_one_notification_phase_for_the_union_of_changed_domains(updater, hooks):
    iu = updater
    fired: list[tuple] = []

    hooks.register_post_update_hook(lambda: fired.append(("hashes",)), domains=("hashes",))
    hooks.register_post_update_hook(lambda: fired.append(("ips",)), domains=("ips",))
    hooks.register_post_update_hook(lambda: fired.append(("rules",)), domains=("rules",))

    _set_runner(iu, "malwarebazaar", _fake_runner(iu.UPDATED, added=1, total=1))
    _set_runner(iu, "c2", _fake_runner(iu.UPDATED, added=1, total=1))
    _set_runner(iu, "yara", _fake_runner(iu.UNCHANGED))       # rules did NOT change

    iu.run_updates(feeds=["malwarebazaar", "c2", "yara"], force=True)

    assert sorted(fired) == [("hashes",), ("ips",)]
    assert ("rules",) not in fired, "an unchanged feed must not notify its domain"


def test_no_notification_when_nothing_changed(updater, hooks):
    iu = updater
    fired = []
    hooks.register_post_update_hook(lambda: fired.append(1), domains=("hashes",))
    _set_runner(iu, "malwarebazaar", _fake_runner(iu.UNCHANGED))

    iu.run_updates(feeds=["malwarebazaar"], force=True)
    assert fired == []


def test_notification_fires_after_the_lock_is_released(updater, hooks):
    """A consumer reload can be expensive; it must never run under the update
    mutex, or a long rebuild would block the next run for its whole duration."""
    iu = updater
    observed: list[bool] = []

    hooks.register_post_update_hook(
        lambda: observed.append(iu._LOCK_PATH.exists()), domains=("hashes",))
    _set_runner(iu, "malwarebazaar", _fake_runner(iu.UPDATED, added=1, total=1))

    iu.run_updates(feeds=["malwarebazaar"], force=True)
    assert observed == [False]


# ── Staleness ─────────────────────────────────────────────────────────────────

def test_never_updated_reports_never_not_zero_hours(updater):
    iu = updater
    state = iu.get_staleness()["malwarebazaar"]
    assert state["state"] == iu.NEVER
    assert state["age_hours"] is None


@pytest.mark.parametrize("age_days,expected", [
    (0.5, "fresh"),
    (4, "aging"),
    (30, "stale"),
])
def test_freshness_thresholds(updater, age_days, expected):
    iu = updater
    _stamp(iu, "malwarebazaar", _utcnow() - timedelta(days=age_days))
    assert iu.get_staleness()["malwarebazaar"]["state"] == expected


def test_future_timestamp_is_clamped_not_perpetually_fresh(updater):
    """A restored VM snapshot or a clock change must not read as negative age."""
    iu = updater
    _stamp(iu, "malwarebazaar", _utcnow() + timedelta(days=5))
    state = iu.get_staleness()["malwarebazaar"]
    assert state["clock_skew"] is True
    assert state["age_hours"] == 0.0
    assert state["state"] == iu.FRESH


def test_thresholds_come_from_settings(updater, settings_sandbox):
    iu = updater
    _stamp(iu, "malwarebazaar", _utcnow() - timedelta(days=4))
    assert iu.get_staleness()["malwarebazaar"]["state"] == iu.AGING

    settings_sandbox["intel_aging_days"] = 10
    settings_sandbox["intel_stale_days"] = 20
    assert iu.get_staleness()["malwarebazaar"]["state"] == iu.FRESH


def test_disabled_feed_is_never_due(updater, settings_sandbox):
    iu = updater
    settings_sandbox["intel_auto_feeds"] = ["c2"]
    _stamp(iu, "malwarebazaar", _utcnow() - timedelta(days=30))

    state = iu.get_staleness()["malwarebazaar"]
    assert state["enabled"] is False
    assert state["due"] is False


def test_recent_update_is_not_due(updater):
    iu = updater
    for name in ("malwarebazaar", "c2", "yara"):
        _stamp(iu, name, _utcnow() - timedelta(minutes=5))
    assert iu.is_anything_due() is False


# ── YARA publish atomicity ────────────────────────────────────────────────────

def _yara_zip(names=("core.yar",), body=b"rule Test { condition: false }") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for n in names:
            zf.writestr(n, body)
    return buf.getvalue()


class _FakeResponse:
    def __init__(self, payload: bytes):
        self._payload = payload

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def yara_sandbox(intel_db, hooks, tmp_path, monkeypatch):
    """update_intelligence's YARA paths redirected into tmp."""
    from tools import update_intelligence as upd

    ydir = tmp_path / "rules" / "community"
    ydir.mkdir(parents=True)
    monkeypatch.setattr(upd, "_YARA_DIR", ydir)
    monkeypatch.setattr(upd, "_YARA_ACTIVE_FILE", ydir / ".active")
    return upd, ydir


def _stub_github(monkeypatch, upd, tag="v9.9.9", zip_bytes=None, release=None):
    payload = release if release is not None else {
        "tag_name": tag,
        "assets": [{"name": "yara-forge-rules-core.zip",
                    "browser_download_url": "https://example.invalid/core.zip"}],
    }
    calls = {"n": 0}

    def fake_urlopen(req, timeout=None):
        calls["n"] += 1
        if calls["n"] == 1:
            return _FakeResponse(json.dumps(payload).encode())
        return _FakeResponse(zip_bytes if zip_bytes is not None else _yara_zip())

    monkeypatch.setattr(upd.urllib.request, "urlopen", fake_urlopen)
    return calls


def test_yara_publish_flips_pointer_to_a_complete_generation(yara_sandbox, monkeypatch):
    upd, ydir = yara_sandbox
    _stub_github(monkeypatch, upd, tag="v2026.1")

    res = upd.download_yara_community(notify=False)

    assert res["status"] == "updated"
    assert res["extracted"] == 1
    gen = upd.get_active_yara_generation()
    assert gen is not None and gen.is_dir()
    assert [p.name for p in gen.glob("*.yar")] == ["core.yar"]
    assert upd.get_meta("yara_version") == "v2026.1"
    assert upd.get_meta("yara_last_update")


def test_corrupt_archive_leaves_the_previous_rules_live(yara_sandbox, monkeypatch):
    """The invariant: a scan sees the whole previous ruleset or the whole new
    one — never a half-extracted tree, and never an empty directory."""
    upd, ydir = yara_sandbox

    _stub_github(monkeypatch, upd, tag="v1")
    assert upd.download_yara_community(notify=False)["status"] == "updated"
    good_gen = upd.get_active_yara_generation()
    good_files = sorted(p.name for p in good_gen.glob("*.yar"))

    # Now serve garbage for the next release.
    _stub_github(monkeypatch, upd, tag="v2", zip_bytes=b"this is not a zip file")
    res = upd.download_yara_community(notify=False)

    assert res["status"] == "failed"
    assert upd.get_active_yara_generation() == good_gen
    assert sorted(p.name for p in good_gen.glob("*.yar")) == good_files
    assert upd.get_meta("yara_version") == "v1", "failed update must not claim a version"


def test_archive_without_rules_is_rejected(yara_sandbox, monkeypatch):
    upd, ydir = yara_sandbox
    empty = io.BytesIO()
    with zipfile.ZipFile(empty, "w") as zf:
        zf.writestr("README.md", "no rules here")

    _stub_github(monkeypatch, upd, tag="v3", zip_bytes=empty.getvalue())
    res = upd.download_yara_community(notify=False)

    assert res["status"] == "failed"
    assert "no .yar" in res["error"]
    assert upd.get_active_yara_generation() is None


def test_unchanged_when_version_already_installed(yara_sandbox, monkeypatch):
    upd, ydir = yara_sandbox
    _stub_github(monkeypatch, upd, tag="v5")
    assert upd.download_yara_community(notify=False)["status"] == "updated"

    _stub_github(monkeypatch, upd, tag="v5")
    res = upd.download_yara_community(notify=False)
    assert res["status"] == "unchanged"


def test_no_staging_directories_survive(yara_sandbox, monkeypatch):
    upd, ydir = yara_sandbox
    _stub_github(monkeypatch, upd, tag="v6")
    upd.download_yara_community(notify=False)
    assert [d.name for d in ydir.iterdir() if d.name.startswith(".staging-")] == []


def test_github_http_error_is_surfaced_with_status(yara_sandbox, monkeypatch):
    import urllib.error

    upd, ydir = yara_sandbox

    def boom(req, timeout=None):
        raise urllib.error.HTTPError("u", 403, "Forbidden", None, None)

    monkeypatch.setattr(upd.urllib.request, "urlopen", boom)
    res = upd.download_yara_community(notify=False)

    assert res["status"] == "failed"
    assert res["http_status"] == 403


def test_published_generation_inherits_the_parent_acl(yara_sandbox, monkeypatch):
    """Regression: the Phase C live test published a generation created by
    tempfile.mkdtemp(), whose DACL is protected (0 inherited ACEs).  Under
    LocalService that produced a rule set only LocalService could read, and
    yara_engine reported it as simply "no rules" with no error anywhere."""
    upd, ydir = yara_sandbox
    _stub_github(monkeypatch, upd, tag="v7")

    assert upd.download_yara_community(notify=False)["status"] == "updated"

    gen = upd.get_active_yara_generation()
    protected = upd._dacl_is_protected(gen)
    if protected is None:
        pytest.skip("DACL inspection unavailable (non-Windows or no pywin32)")
    assert protected is False, "published rules must inherit the rules-dir ACL"


def test_staging_dir_inherits_the_parent_acl(yara_sandbox):
    """The staging directory must inherit. This is the whole fix, so it never
    skips for environmental reasons — only if DACLs cannot be read at all."""
    upd, ydir = yara_sandbox
    if upd._dacl_is_protected(ydir) is None:
        pytest.skip("DACL inspection unavailable")

    staged = upd._make_staging_dir(ydir)
    assert upd._dacl_is_protected(staged) is False, \
        "staged rules must inherit the rules-dir ACL or nobody else can read them"


def test_mkdtemp_hardening_is_why_os_mkdir_is_used(yara_sandbox):
    """Documents the contrast that motivated _make_staging_dir.

    Deliberately separate from the guarantee above, and deliberately allowed to
    skip: mkdtemp's hardening is CPython- and platform-dependent. Measured on
    Windows — protected on 3.13, inheriting on 3.11 — so asserting it would pin
    someone else's behaviour and fail across half the supported range. When the
    contrast is absent there is nothing to show, and the real guarantee is
    tested separately rather than riding along in this test's result.
    """
    import tempfile

    upd, ydir = yara_sandbox
    if upd._dacl_is_protected(ydir) is None:
        pytest.skip("DACL inspection unavailable")

    hardened = Path(tempfile.mkdtemp(prefix=".mkdtemp-", dir=str(ydir)))
    if upd._dacl_is_protected(hardened) is not True:
        pytest.skip("tempfile.mkdtemp inherits on this Python — no contrast to "
                    "draw here; the staging guarantee is covered separately")
    assert upd._dacl_is_protected(hardened) is True


def test_unreadable_staging_is_never_published(yara_sandbox, monkeypatch):
    """A protected staging DACL must abort the publish with the previous
    generation left live — never a silent unreadable rule set."""
    upd, ydir = yara_sandbox

    _stub_github(monkeypatch, upd, tag="v1")
    assert upd.download_yara_community(notify=False)["status"] == "updated"
    good_gen = upd.get_active_yara_generation()

    monkeypatch.setattr(upd, "_dacl_is_protected",
                        lambda path: True if ".staging-" in str(path) else False)
    _stub_github(monkeypatch, upd, tag="v2")
    res = upd.download_yara_community(notify=False)

    assert res["status"] == "failed"
    assert "unreadable" in res["error"]
    assert upd.get_active_yara_generation() == good_gen
    assert upd.get_meta("yara_version") == "v1"
    assert [d.name for d in ydir.iterdir() if d.name.startswith(".staging-")] == []


def test_empty_publish_is_caught_and_rolled_back(yara_sandbox, monkeypatch):
    """Belt-and-braces: if the move ever lands nothing, do not flip the pointer."""
    upd, ydir = yara_sandbox
    _stub_github(monkeypatch, upd, tag="v1")
    assert upd.download_yara_community(notify=False)["status"] == "updated"
    good_gen = upd.get_active_yara_generation()

    real_replace = upd_os_replace = __import__("os").replace

    def replace_then_empty(src, dst):
        real_replace(src, dst)
        for f in Path(dst).glob("*.yar"):
            f.unlink()

    monkeypatch.setattr(__import__("os"), "replace", replace_then_empty)
    _stub_github(monkeypatch, upd, tag="v2")
    res = upd.download_yara_community(notify=False)

    assert res["status"] == "failed"
    assert "empty" in res["error"]
    assert upd.get_active_yara_generation() == good_gen


# ── Posture ───────────────────────────────────────────────────────────────────

def _usable(mb=1000, c2=10, yara=1):
    return {
        "malwarebazaar": {"usable": mb > 0, "count": mb, "unit": "hashes", "readable": True},
        "c2":            {"usable": c2 > 0, "count": c2, "unit": "IPs", "readable": True},
        "yara":          {"usable": yara > 0, "count": yara, "unit": "rule files", "readable": True},
    }


def test_posture_current_when_everything_fresh_and_usable(updater, monkeypatch):
    iu = updater
    for name in ("malwarebazaar", "c2", "yara"):
        _stamp(iu, name, _utcnow() - timedelta(hours=2))
    monkeypatch.setattr(iu, "get_usability", lambda: _usable())

    p = iu.get_posture()
    assert p["state"] == iu.POSTURE_CURRENT
    assert p["headline"] == "Protected — intelligence current"
    assert p["level"] == "ok"


def test_posture_stale_still_claims_protection(updater, monkeypatch):
    """Stale intelligence degrades the headline; it must not imply zero
    protection, because the hash tiers keep working on what is already there."""
    iu = updater
    _stamp(iu, "malwarebazaar", _utcnow() - timedelta(days=30))
    _stamp(iu, "c2", _utcnow() - timedelta(hours=1))
    _stamp(iu, "yara", _utcnow() - timedelta(hours=1))
    monkeypatch.setattr(iu, "get_usability", lambda: _usable())

    p = iu.get_posture()
    assert p["state"] == iu.POSTURE_STALE
    assert p["headline"].startswith("Protected")
    assert "MalwareBazaar" in p["detail"]


def test_posture_update_required_when_a_feed_never_populated(updater, monkeypatch):
    iu = updater
    _stamp(iu, "c2", _utcnow() - timedelta(hours=1))
    _stamp(iu, "yara", _utcnow() - timedelta(hours=1))
    monkeypatch.setattr(iu, "get_usability", lambda: _usable())

    p = iu.get_posture()          # malwarebazaar has no stamp at all
    assert p["state"] == iu.POSTURE_UPDATE_REQ
    assert "Never updated" in p["detail"]


def test_posture_catches_fresh_but_unusable_data(updater, monkeypatch):
    """The Phase C failure exactly: YARA reported fresh while the published
    generation was unreadable and the engine had zero rules.  Freshness alone
    would have shown a reassuring 'intelligence current'."""
    iu = updater
    for name in ("malwarebazaar", "c2", "yara"):
        _stamp(iu, name, _utcnow() - timedelta(hours=1))
    monkeypatch.setattr(iu, "get_usability", lambda: _usable(yara=0))

    p = iu.get_posture()
    assert p["state"] == iu.POSTURE_UPDATE_REQ
    assert "unusable" in p["detail"].lower()
    assert "YARA" in p["detail"]
    assert p["feeds"]["yara"]["state"] == "fresh", \
        "the feed is genuinely fresh — posture must catch this, not staleness"


def test_posture_unavailable_when_the_store_cannot_be_read(updater, monkeypatch):
    iu = updater
    broken = _usable()
    broken["malwarebazaar"] = {"usable": False, "count": 0, "unit": "hashes",
                               "readable": False}
    monkeypatch.setattr(iu, "get_usability", lambda: broken)

    p = iu.get_posture()
    assert p["state"] == iu.POSTURE_UNAVAILABLE
    assert p["level"] == "error"


def test_posture_reports_auth_required_as_stale_not_current(updater, monkeypatch):
    iu = updater
    for name in ("malwarebazaar", "c2", "yara"):
        _stamp(iu, name, _utcnow() - timedelta(hours=1))
    iu._write_backoff("c2", {
        "fail_count": 3,
        "next_retry": (_utcnow() + timedelta(hours=12)).isoformat(timespec="seconds"),
        "last_error": "HTTP 403",
        "last_status": iu.AUTH_REQUIRED,
    })
    monkeypatch.setattr(iu, "get_usability", lambda: _usable())

    p = iu.get_posture()
    assert p["state"] == iu.POSTURE_STALE
    assert "authentication" in p["detail"].lower()


def test_get_usability_reads_real_counts(updater, intel_db):
    iu = updater
    from conftest import add_malicious
    add_malicious(intel_db, "a" * 32)

    u = iu.get_usability()
    assert u["malwarebazaar"]["count"] == 1
    assert u["malwarebazaar"]["usable"] is True
    assert u["c2"]["usable"] is False       # temp DB has no blocklist rows


# ── A fresh install is not a broken one ───────────────────────────────────────
#
# Every posture test above stubs get_usability() with a hand-built dict, and
# that is the seam this bug lived in: get_posture() handled `readable: False`
# exactly as documented, while get_usability() was deciding it wrongly for a
# database that did not exist yet.  A first launch showed the red "The
# intelligence database could not be read" — corruption/permissions wording —
# directly beneath a Getting Started card telling the user to populate it.
# These drive the real function.

@pytest.fixture
def fresh_install(updater, intel_db, tmp_path, monkeypatch):
    """A first launch: nothing has ever been downloaded.

    Deleting the fixture's database is most of the setup — every consumer is
    already pointed at that path.  The rest is YARA, whose state comes from the
    rules directory rather than from the DB: on a developer checkout with
    rules/community/ populated, a "fresh install" would still report rules and
    the test would turn on machine state instead of on the code.

    The engine directories are patched inline rather than by requesting
    conftest's `yara_sandbox`, because this module defines a *different*
    fixture under that name — the downloader one, returning (upd, ydir) — which
    shadows it and leaves ui.core.yara_engine pointed at the real checkout.
    """
    from ui.core import yara_engine as ye

    community = tmp_path / "fresh_community"
    monkeypatch.setattr(ye, "_USER_DIR", tmp_path / "fresh_user_rules")
    monkeypatch.setattr(ye, "_COMMUNITY_DIR", community)
    monkeypatch.setattr(ye, "_ACTIVE_PTR", community / ".active")

    intel_db.unlink()
    return updater


def test_a_fresh_install_is_empty_rather_than_unreadable(fresh_install):
    u = fresh_install.get_usability()

    assert u["malwarebazaar"]["readable"] is True, \
        "a database that was never created is empty, not unreadable"
    assert u["malwarebazaar"]["usable"] is False
    assert u["c2"]["readable"] is True
    assert u["c2"]["usable"] is False
    # YARA already expressed this in terms of rule count and is deliberately
    # left alone; asserted here so a later "tidy-up" cannot quietly change it.
    assert u["yara"]["readable"] is True
    assert u["yara"]["usable"] is False


def test_a_fresh_install_says_never_updated_in_words(fresh_install):
    """The state alone was never the defect — the sentence the user reads is.

    "could not be read" describes corruption or a permissions failure, and it
    was appearing on machines where nothing had gone wrong at all.
    """
    p = fresh_install.get_posture()

    assert p["state"] == fresh_install.POSTURE_UPDATE_REQ
    assert "Never updated" in p["detail"]
    assert "could not be read" not in p["detail"]


def test_a_created_but_empty_database_is_also_never_updated(updater):
    """The other first-launch shape: the file exists, no feed has ever run."""
    p = updater.get_posture()

    assert p["state"] == updater.POSTURE_UPDATE_REQ
    assert "Never updated" in p["detail"]


def test_a_database_that_cannot_be_opened_is_still_unavailable(updater, monkeypatch):
    """The distinction has to hold in both directions.

    A database whose file exists but will not open — the ACL failure the
    privilege boundary makes possible — is the case `unavailable` is FOR, and
    narrowing the fresh-install path must not have cost us it.
    """
    from ui.core import intel_db as db
    monkeypatch.setattr(db, "_get_conn", lambda: None)

    u = updater.get_usability()
    assert u["malwarebazaar"]["readable"] is False

    p = updater.get_posture()
    assert p["state"] == updater.POSTURE_UNAVAILABLE
    assert p["level"] == "error"
    assert "could not be read" in p["detail"]


# ── Phase E: remaining failure matrix ─────────────────────────────────────────

def test_rate_limit_backs_off_as_transient_not_auth(updater):
    """429 means "slow down", not "you need credentials" — it must not be
    parked on the long auth-wall backoff."""
    iu = updater
    _set_runner(iu, "c2", _fake_runner(iu.FAILED, error="Too Many Requests",
                                       http_status=429))
    iu.run_updates(feeds=["c2"], force=True)
    rate = iu._read_backoff("c2")

    iu._write_backoff("malwarebazaar", None)
    _set_runner(iu, "malwarebazaar", _fake_runner(iu.FAILED, error="Forbidden",
                                                  http_status=403))
    iu.run_updates(feeds=["malwarebazaar"], force=True)
    auth = iu._read_backoff("malwarebazaar")

    assert rate["last_status"] == iu.FAILED
    assert auth["last_status"] == iu.AUTH_REQUIRED
    assert datetime.fromisoformat(rate["next_retry"]) < \
           datetime.fromisoformat(auth["next_retry"])


def test_extraction_failure_midway_leaves_previous_rules_live(yara_sandbox, monkeypatch):
    """A crash partway through unpacking must not surface a partial rule set."""
    upd, ydir = yara_sandbox

    _stub_github(monkeypatch, upd, tag="v1", zip_bytes=_yara_zip(
        names=("a.yar", "b.yar", "c.yar")))
    assert upd.download_yara_community(notify=False)["status"] == "updated"
    good_gen = upd.get_active_yara_generation()
    good_files = sorted(p.name for p in good_gen.glob("*.yar"))
    assert len(good_files) == 3

    # Blow up after the first member is written on the next run.
    real_read = zipfile.ZipFile.read
    state = {"n": 0}

    def flaky_read(self, name, *a, **kw):
        state["n"] += 1
        if state["n"] > 1:
            raise OSError("disk went away mid-extraction")
        return real_read(self, name, *a, **kw)

    monkeypatch.setattr(zipfile.ZipFile, "read", flaky_read)
    _stub_github(monkeypatch, upd, tag="v2", zip_bytes=_yara_zip(
        names=("a.yar", "b.yar", "c.yar")))
    res = upd.download_yara_community(notify=False)

    assert res["status"] == "failed"
    assert upd.get_active_yara_generation() == good_gen
    assert sorted(p.name for p in good_gen.glob("*.yar")) == good_files
    assert [d.name for d in ydir.iterdir() if d.name.startswith(".staging-")] == []


def test_ui_fallback_stands_down_if_the_service_starts_mid_flight(updater, monkeypatch):
    """The race the ownership re-check exists for: the caller probed while the
    service was down, but it came up before the first write."""
    iu = updater
    calls = []

    # Service is down at the caller's probe, up by the time run_updates checks.
    monkeypatch.setattr(iu, "_service_owns_updates", lambda: True)
    _set_runner(iu, "malwarebazaar",
                lambda on_progress: calls.append(1) or {"status": iu.UPDATED})

    out = iu.run_updates(feeds=["malwarebazaar"], force=True, owner="ui")

    assert out["status"] == iu.SKIPPED
    assert calls == [], "no feed may be contacted once the service owns updates"
    assert not iu._LOCK_PATH.exists(), "and no lock should be left behind"


# ── Phase E: scheduler thread ─────────────────────────────────────────────────

def test_scheduler_runs_when_due_and_stops_cleanly(updater, monkeypatch, settings_sandbox):
    """Soak in miniature: the loop must fire, then stop promptly without
    leaking a thread."""
    import threading as _th

    iu = updater
    fired = _th.Event()

    def runner(on_progress):
        fired.set()
        return {"status": iu.UPDATED, "added": 1, "total": 1}

    _set_runner(iu, "malwarebazaar", runner)
    settings_sandbox["intel_auto_feeds"] = ["malwarebazaar"]

    monkeypatch.setattr(iu, "_SLEEP_SLICE_SECS", 0.05)
    pushed = []
    thread = iu.IntelUpdaterThread(push_event=pushed.append, check_interval=60,
                                   owner="service")
    # The loop's 60 s settle delay is a real behaviour; shorten it for the test.
    monkeypatch.setattr(thread, "_sleep", lambda secs: not thread._stop_evt.wait(0.05))

    before = _th.active_count()
    assert thread.start() is True
    assert fired.wait(timeout=5), "scheduler never ran a due feed"

    thread.stop()
    assert thread.is_running() is False
    for _ in range(50):
        if _th.active_count() <= before:
            break
        time.sleep(0.05)
    assert _th.active_count() <= before, "updater thread leaked"
    assert pushed and pushed[0]["event"] == "intel_update"


def test_scheduler_declines_to_start_when_disabled(updater, settings_sandbox):
    iu = updater
    settings_sandbox["intel_auto_update"] = False
    thread = iu.IntelUpdaterThread()
    assert thread.start() is False
    assert thread.is_running() is False


def test_scheduler_skips_when_nothing_is_due(updater, monkeypatch, settings_sandbox):
    iu = updater
    for name in ("malwarebazaar", "c2", "yara"):
        _stamp(iu, name, _utcnow() - timedelta(minutes=1))
    calls = []
    _set_runner(iu, "malwarebazaar",
                lambda on_progress: calls.append(1) or {"status": iu.UPDATED})

    assert iu.is_anything_due() is False
    out = iu.run_updates(force=False)
    assert out["status"] == iu.SKIPPED
    assert calls == []
