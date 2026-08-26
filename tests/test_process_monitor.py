"""
WMI process-creation monitor.

This is the component that kills things. When the UI is closed the service
runs it autonomously and, per `process_monitor_ui_closed_action`, terminates
the process tree and quarantines the executable without asking anyone. A wrong
verdict here is not a row in a list -- it is a process that is already dead.

So the tests drive `_check_process()`, the real decision path, rather than
inspecting `_known_bad`. Internal state can look perfectly correct while the
production path still returns "clean"; that distinction is the whole point of
the rule in docs/TESTING.md.

WMI itself is never touched. `_watch_loop` needs COM, a live subscription and
a real Windows event source; `_check_process` is the part that decides, and it
takes its inputs as arguments.
"""
from __future__ import annotations

import sqlite3
import threading
import time

import pytest

from ui.core import process_monitor as pm

from conftest import add_malicious, make_sample_file


@pytest.fixture
def monitor():
    """A monitor with no WMI thread and a recording alert callback."""
    alerts: list[tuple] = []
    mon = pm.ProcessMonitor(alert_callback=lambda *a: alerts.append(a),
                            known_bad=set())
    mon.alerts = alerts          # type: ignore[attr-defined]
    return mon


def _conn(db):
    return sqlite3.connect(str(db))


# ── The verdict ladder ────────────────────────────────────────────────────────

def test_a_hash_in_the_ram_set_is_a_threat(monitor, tmp_path):
    exe, md5 = make_sample_file(tmp_path, b"malicious payload", "bad.exe")
    monitor._known_bad = {md5}

    monitor._check_process(pid=1234, name="bad.exe", exe_path=str(exe), con=None)

    assert len(monitor.alerts) == 1
    pid, name, path, reason, level = monitor.alerts[0]
    assert pid == 1234 and "MalwareBazaar" in reason and level == "warning"


def test_sqlite_catches_what_the_ram_set_missed(monitor, intel_db, tmp_path):
    """The RAM set is skipped entirely above _KNOWN_BAD_RAM_LIMIT, so the
    per-lookup SQLite path is the only coverage for large databases."""
    exe, md5 = make_sample_file(tmp_path, b"another payload", "bad.exe")
    add_malicious(intel_db, md5, family="Emotet")

    with _conn(intel_db) as con:
        monitor._check_process(pid=1, name="bad.exe", exe_path=str(exe), con=con)

    assert len(monitor.alerts) == 1
    assert "Emotet" in monitor.alerts[0][3]


def test_an_unknown_hash_is_left_alone(monitor, intel_db, tmp_path):
    exe, _ = make_sample_file(tmp_path, b"perfectly ordinary", "ok.exe")

    with _conn(intel_db) as con:
        monitor._check_process(pid=1, name="ok.exe", exe_path=str(exe), con=con)

    assert monitor.alerts == []


def test_a_process_with_no_executable_path_is_skipped(monitor):
    monitor._check_process(pid=1, name="?", exe_path="", con=None)

    assert monitor.alerts == []


def test_an_alert_callback_that_raises_does_not_stop_the_monitor(intel_db, tmp_path):
    """alert_callback is supplied by the UI or the service and runs on the WMI
    thread. One bad callback must not end monitoring for the session."""
    exe, md5 = make_sample_file(tmp_path, b"payload", "bad.exe")

    def angry(*a):
        raise RuntimeError("the view was destroyed")

    mon = pm.ProcessMonitor(alert_callback=angry, known_bad={md5})

    mon._check_process(pid=1, name="bad.exe", exe_path=str(exe), con=None)  # no raise


# ── The kill-suppression ordering ─────────────────────────────────────────────

def test_allow_hash_suppresses_the_kill_and_reload_changes_the_verdict(
        monitor, intel_db, tmp_path):
    """The sequence that matters for the component that terminates processes,
    asserted end to end through _check_process() rather than by reading
    _known_bad.

    1. a known-bad process is detected and the alert path fires
    2. the user restores it from quarantine -> allow_hash() suppresses the
       re-kill when they relaunch it
    3. reload_known_bad() after an intelligence update changes what the
       production decision path actually decides
    """
    exe, md5 = make_sample_file(tmp_path, b"restored by the user", "tool.exe")

    # 1. detected
    monitor._known_bad = {md5}
    monitor._check_process(pid=1, name="tool.exe", exe_path=str(exe), con=None)
    assert len(monitor.alerts) == 1, "the threat was not detected to begin with"

    # 2. user restores it; relaunching must not be killed again
    monitor.allow_hash(md5)
    monitor._check_process(pid=2, name="tool.exe", exe_path=str(exe), con=None)
    assert len(monitor.alerts) == 1, "allow-listed hash was flagged again"

    # 3. a fresh monitor picks the hash up from the DB after an update
    add_malicious(intel_db, md5, family="Emotet")
    fresh = pm.ProcessMonitor(alert_callback=lambda *a: monitor.alerts.append(a),
                              known_bad=set())
    fresh._check_process(pid=3, name="tool.exe", exe_path=str(exe), con=None)
    assert len(monitor.alerts) == 1, "the hash was known before the reload"

    fresh.reload_known_bad()
    fresh._check_process(pid=4, name="tool.exe", exe_path=str(exe), con=None)
    assert len(monitor.alerts) == 2, (
        "reload_known_bad() did not change the production decision path")


def test_the_allow_list_is_case_insensitive(monitor, tmp_path):
    exe, md5 = make_sample_file(tmp_path, b"payload", "tool.exe")
    monitor._known_bad = {md5}

    monitor.allow_hash(md5.upper())
    monitor._check_process(pid=1, name="tool.exe", exe_path=str(exe), con=None)

    assert monitor.alerts == []


# ── _fast_hash guards ─────────────────────────────────────────────────────────

def test_hashing_skips_files_over_the_size_cap(monkeypatch, tmp_path):
    """A 4 GB Steam update should not be read through MD5 on every launch."""
    big = tmp_path / "huge.exe"
    big.write_bytes(b"MZ")

    class BigStat:
        st_size = 101 * 1024 * 1024

    monkeypatch.setattr(pm.Path, "stat", lambda self: BigStat())

    assert pm.ProcessMonitor._fast_hash(str(big)) is None


def test_hashing_skips_protected_processes(monkeypatch, tmp_path):
    """lsass.exe, MsMpEng.exe and other PPL processes deny read access. They
    are skipped silently -- see the Known Limitations note in ARCHITECTURE.md."""
    exe = tmp_path / "lsass.exe"
    exe.write_bytes(b"MZ")

    def denied(*a, **kw):
        raise PermissionError("protected process")

    monkeypatch.setattr("builtins.open", denied)

    assert pm.ProcessMonitor._fast_hash(str(exe)) is None


def test_hashing_skips_a_file_that_vanished(tmp_path):
    """Self-deleting installer temps are gone by the time WMI reports them."""
    assert pm.ProcessMonitor._fast_hash(str(tmp_path / "never_existed.exe")) is None


def test_hashing_a_real_file_matches_its_md5(tmp_path):
    exe, md5 = make_sample_file(tmp_path, b"content to hash", "app.exe")

    assert pm.ProcessMonitor._fast_hash(str(exe)) == md5


# ── Known-bad loading ─────────────────────────────────────────────────────────

def test_the_ram_set_loads_from_sqlite(intel_db):
    add_malicious(intel_db, "d41d8cd98f00b204e9800998ecf8427f")

    assert "d41d8cd98f00b204e9800998ecf8427f" in pm._load_known_bad()


def test_an_oversized_table_is_left_out_of_ram(intel_db, monkeypatch):
    """Above the cap the set is deliberately empty and _check_process() falls
    through to its per-lookup SQLite path. Detection coverage is unchanged;
    only the memory profile is."""
    add_malicious(intel_db, "d41d8cd98f00b204e9800998ecf8427f")
    monkeypatch.setattr(pm, "_KNOWN_BAD_RAM_LIMIT", 0)

    assert pm._load_known_bad() == set()


def test_reload_all_refreshes_every_live_monitor(intel_db, tmp_path):
    """The "hashes" post-update hook is a module-level function rather than a
    bound method precisely so it does not pin whichever monitor happened to
    exist at start-up."""
    exe, md5 = make_sample_file(tmp_path, b"payload", "bad.exe")
    alerts: list = []
    monitors = [pm.ProcessMonitor(alert_callback=lambda *a: alerts.append(a),
                                  known_bad=set())
                for _ in range(3)]

    add_malicious(intel_db, md5)
    assert pm.reload_all_known_bad() >= 3

    for i, mon in enumerate(monitors):
        mon._check_process(pid=i, name="bad.exe", exe_path=str(exe), con=None)

    assert len(alerts) == 3, "a live monitor was not refreshed"


def test_reload_all_survives_a_monitor_that_raises(intel_db):
    class Broken(pm.ProcessMonitor):
        def reload_known_bad(self):
            raise RuntimeError("db locked")

    Broken(alert_callback=lambda *a: None, known_bad=set())
    good = pm.ProcessMonitor(alert_callback=lambda *a: None, known_bad=set())

    assert pm.reload_all_known_bad() >= 1        # the good one still refreshed
    assert good is not None


# ── stop() must not lie ───────────────────────────────────────────────────────

def test_stop_keeps_the_handle_when_the_thread_will_not_die(monkeypatch):
    """The invariant: if stop() returns while the watch thread is still alive,
    is_running() must not report False.

    Before v1.13 stop() cleared _thread after a timed-out join regardless of
    outcome, so a hung GetObject("winmgmts:") left a monitor that still fired
    alert_callback -- and could still kill processes -- while the UI showed it
    as stopped.
    """
    monkeypatch.setattr(pm, "_STOP_JOIN_TIMEOUT_S", 0.1)

    hang = threading.Event()
    mon = pm.ProcessMonitor(alert_callback=lambda *a: None, known_bad=set())
    monkeypatch.setattr(mon, "_watch_loop", lambda: hang.wait(30))

    mon.start()
    assert mon.is_running() is True

    try:
        mon.stop()
        assert mon.is_running() is True, (
            "stop() reported the monitor stopped while its thread was alive")
    finally:
        hang.set()
        mon._thread.join(timeout=5)


def test_stop_releases_the_handle_once_the_thread_actually_dies(monkeypatch):
    monkeypatch.setattr(pm, "_STOP_JOIN_TIMEOUT_S", 2)

    mon = pm.ProcessMonitor(alert_callback=lambda *a: None, known_bad=set())
    monkeypatch.setattr(mon, "_watch_loop", lambda: mon._stop_evt.wait(10))

    mon.start()
    mon.stop()

    assert mon.is_running() is False
    assert mon._thread is None


def test_start_is_idempotent(monkeypatch):
    mon = pm.ProcessMonitor(alert_callback=lambda *a: None, known_bad=set())
    monkeypatch.setattr(mon, "_watch_loop", lambda: mon._stop_evt.wait(10))

    mon.start()
    first = mon._thread
    mon.start()

    try:
        assert mon._thread is first, "a second thread was started"
    finally:
        mon.stop()


def test_stop_on_a_monitor_that_never_started_is_harmless():
    pm.ProcessMonitor(alert_callback=lambda *a: None, known_bad=set()).stop()


def test_the_poll_interval_is_clamped():
    """WMI WITHIN N is the detection latency knob; a 0 or a 600 from a stale
    settings file should not reach the query string."""
    assert pm.ProcessMonitor(lambda *a: None, set(), poll_interval=0)._poll_interval == 1
    assert pm.ProcessMonitor(lambda *a: None, set(), poll_interval=99)._poll_interval == 10
