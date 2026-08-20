"""
Phase A regression tests — new intelligence must reach the *already running*
in-memory consumers, without reconstructing them.

Each live-reload test asserts through the same public detection path production
uses (`scan_file()`, `_check_process()`, `is_known_bad_ip()`) rather than poking
at `virus_db` / `_known_bad` / the IP cache directly.  Inspecting internal state
would let these pass while the real decision path still returned "clean".
"""
from __future__ import annotations

import hashlib

import pytest

from conftest import add_c2_ip, add_malicious


def _md5(path) -> str:
    return hashlib.md5(path.read_bytes()).hexdigest()


# ── ProcessMonitor ────────────────────────────────────────────────────────────

def test_process_monitor_blind_until_hook_fires(intel_db, hooks, tmp_path):
    """The fresh-install blind spot: the WMI thread opens its SQLite connection
    once at start-up and only if the DB already exists, so on a new install it
    stays None for the thread's whole life.  With an empty RAM set that monitor
    detects nothing at all — a reload is the only thing that can fix it without
    restarting the service."""
    from ui.core import process_monitor as pm
    from ui.core.intel_hooks import register_intel_consumers

    sample = tmp_path / "payload.exe"
    sample.write_bytes(b"MZ not-really-an-executable body for polyshield tests\n")
    md5 = _md5(sample)

    alerts: list[tuple] = []
    monitor = pm.ProcessMonitor(
        alert_callback=lambda *a: alerts.append(a),
        known_bad=set(),          # started before any intelligence existed
    )

    def check():
        monitor._check_process(
            pid=4242, name="payload.exe", exe_path=str(sample), con=None,
        )

    check()
    assert alerts == []

    add_malicious(intel_db, md5, family="Emotet")
    check()
    assert alerts == [], "no SQLite fallback and a stale RAM set — must still miss"

    register_intel_consumers(force=True)
    hooks._fire_post_update_hooks(("hashes",))

    check()
    assert len(alerts) == 1, "same monitor instance must see the new hash"
    pid, name, exe_path, reason, level = alerts[0]
    assert pid == 4242
    assert "malicious" in reason.lower()


def test_reload_all_known_bad_skips_collected_monitors(intel_db, tmp_path):
    """The weak registry must not resurrect or reload dropped monitors."""
    import gc

    from ui.core import process_monitor as pm

    monitor = pm.ProcessMonitor(alert_callback=lambda *a: None, known_bad=set())
    assert pm.reload_all_known_bad() >= 1

    del monitor
    gc.collect()
    assert pm.reload_all_known_bad() == 0


# ── Guardian ──────────────────────────────────────────────────────────────────

def test_guardian_ram_tier_refreshed_in_place(intel_db, hooks, tmp_path, monkeypatch):
    """Guardian's tier-3 SQLite fallback masks a stale RAM set, so this test
    disables it: with `lookup_hash` returning None, only a refreshed tier-2 RAM
    set can produce a detection.  The scanner instance must never be rebuilt."""
    from ui.core import guardian_engine as ge
    from ui.core import ignore_list
    from ui.core import intel_db as intel_db_mod
    from ui.core.intel_hooks import register_intel_consumers

    monkeypatch.setattr(intel_db_mod, "lookup_hash", lambda md5: None)
    monkeypatch.setattr(intel_db_mod, "is_known_safe", lambda md5: False)
    monkeypatch.setattr(ignore_list, "contains", lambda md5: False)
    monkeypatch.setattr(ge, "_DATA_DIR", tmp_path / "no-such-data-dir")
    monkeypatch.setattr(ge, "_scanner", None)

    scanner = ge._get_scanner()          # the instance scan_async() would use

    sample = tmp_path / "sample.txt"
    sample.write_bytes(b"ordinary benign file contents, nothing to see here\n")
    md5 = _md5(sample)

    assert scanner.scan_file(str(sample))[0] is False

    add_malicious(intel_db, md5)
    assert scanner.scan_file(str(sample))[0] is False, "RAM set is still stale"

    register_intel_consumers(force=True)
    hooks._fire_post_update_hooks(("hashes",))

    assert ge._get_scanner() is scanner, "scanner must be reloaded, not replaced"
    infected, reason, tier, _ctx = scanner.scan_file(str(sample))
    assert infected is True
    assert tier == "hash"


# ── Network monitor ───────────────────────────────────────────────────────────

def test_c2_import_invalidates_ip_cache(intel_db, hooks):
    """is_known_bad_ip() memoises negative verdicts with no fallback, so a
    freshly imported C2 address stays unflagged until the cache is cleared."""
    from ui.core import network_monitor as nm
    from ui.core.intel_hooks import register_intel_consumers

    nm.clear_ip_cache()
    ip = "203.0.113.77"          # TEST-NET-3, never private

    assert nm.is_known_bad_ip(ip)[0] is False      # caches the "clean" verdict

    add_c2_ip(intel_db, ip, tags="botnet_cc")
    assert nm.is_known_bad_ip(ip)[0] is False, "served from the stale cache"

    register_intel_consumers(force=True)
    hooks._fire_post_update_hooks(("ips",))

    flagged, tags = nm.is_known_bad_ip(ip)
    assert flagged is True
    assert tags == "botnet_cc"


def test_clear_ip_cache_resets_poll_counter(intel_db):
    from ui.core import network_monitor as nm

    nm._poll_count = 17
    nm.clear_ip_cache()
    assert nm._poll_count == 0


# ── Hook registry semantics ───────────────────────────────────────────────────

def test_hooks_are_domain_scoped(hooks):
    """A YARA archive changing must not force a Guardian MD5 rebuild."""
    fired: list[str] = []
    hooks.register_post_update_hook(lambda: fired.append("hashes"), domains=("hashes",))
    hooks.register_post_update_hook(lambda: fired.append("ips"), domains=("ips",))
    hooks.register_post_update_hook(lambda: fired.append("rules"), domains=("rules",))

    hooks._fire_post_update_hooks(("hashes",))
    assert fired == ["hashes"]

    hooks._fire_post_update_hooks(("ips", "rules"))
    assert fired == ["hashes", "ips", "rules"]


def test_failing_hook_does_not_suppress_the_others(hooks):
    fired: list[str] = []

    def boom():
        raise RuntimeError("reload exploded")

    hooks.register_post_update_hook(boom, domains=("hashes",))
    hooks.register_post_update_hook(lambda: fired.append("survivor"), domains=("hashes",))

    hooks._fire_post_update_hooks(("hashes",))
    assert fired == ["survivor"]


def test_registration_is_idempotent(hooks):
    fired: list[int] = []

    def hook():
        fired.append(1)

    hooks.register_post_update_hook(hook, domains=("hashes",))
    hooks.register_post_update_hook(hook, domains=("hashes",))
    hooks._fire_post_update_hooks(("hashes",))
    assert fired == [1], "re-registering must not queue a second call"


def test_reregistering_replaces_the_domain_set(hooks):
    fired: list[str] = []

    def hook():
        fired.append("x")

    hooks.register_post_update_hook(hook, domains=("hashes",))
    hooks.register_post_update_hook(hook, domains=("ips",))

    hooks._fire_post_update_hooks(("hashes",))
    assert fired == []

    hooks._fire_post_update_hooks(("ips",))
    assert fired == ["x"]


def test_unknown_domain_is_rejected(hooks):
    with pytest.raises(ValueError):
        hooks.register_post_update_hook(lambda: None, domains=("not-a-domain",))


def test_empty_domain_set_fires_nothing(hooks):
    fired: list[str] = []
    hooks.register_post_update_hook(lambda: fired.append("x"), domains=("hashes",))
    hooks._fire_post_update_hooks(())
    assert fired == []
