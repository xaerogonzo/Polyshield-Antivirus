"""
Shared pytest fixtures for the PolyShield test suite.

Everything here is hermetic: no test may touch the real
`intelligence/threat_db.sqlite` (it is ~146 MB and holds the user's live
intelligence), and no test may leave a post-update hook registered behind it.
"""
from __future__ import annotations

import gc
import importlib
import sqlite3
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for _p in (ROOT, ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))


# ── Intelligence DB ───────────────────────────────────────────────────────────

# Every consumer resolves its own _DB_PATH at import time from parents[3], so
# each one has to be redirected individually.
_DB_PATH_CONSUMERS = (
    "ui.core.intel_db",
    "ui.core.guardian_engine",
    "ui.core.process_monitor",
    "ui.core.network_monitor",
)


@pytest.fixture
def intel_db(tmp_path, monkeypatch) -> Path:
    """A temp threat_db.sqlite with every consumer's _DB_PATH pointed at it."""
    from tools import update_intelligence as upd

    db = tmp_path / "threat_db.sqlite"
    con = sqlite3.connect(str(db))
    con.executescript(upd._SCHEMA)
    con.commit()
    con.close()

    monkeypatch.setattr(upd, "_DB_PATH", db)
    for name in _DB_PATH_CONSUMERS:
        monkeypatch.setattr(importlib.import_module(name), "_DB_PATH", db)

    # intel_db memoises a connection per thread — hand it a fresh thread-local
    # so the next call reopens against the temp file.
    intel_db_mod = importlib.import_module("ui.core.intel_db")
    monkeypatch.setattr(intel_db_mod, "_thread_local", threading.local())

    return db


@pytest.fixture
def hooks(monkeypatch):
    """The update_intelligence module with an empty hook registry.

    Also resets the per-process "already registered" latches so a test can call
    register_intel_consumers() and actually see it register.
    """
    from tools import update_intelligence as upd
    from ui.core import guardian_engine, intel_hooks

    monkeypatch.setattr(upd, "_post_update_hooks", [])
    monkeypatch.setattr(intel_hooks, "_registered", False)
    monkeypatch.setattr(guardian_engine, "_post_update_hook_registered", False)
    return upd


@pytest.fixture
def settings_sandbox(monkeypatch):
    """In-memory settings — never writes the user's real ui_settings.json.

    Note the setter is set_value(), not set(); patching the wrong name here
    would let a test silently write to the real config file.
    """
    from ui.core import settings as cfg

    sandbox = dict(cfg._DEFAULTS)
    monkeypatch.setattr(cfg, "_cache", sandbox)

    def _set(k, v):
        sandbox[k] = v
        return cfg.SAVE_OK      # match the real contract; None would be a lie

    monkeypatch.setattr(cfg, "set_value", _set)
    return sandbox


@pytest.fixture
def settings_file(tmp_path, monkeypatch):
    """A real on-disk settings file, for the persistence tests.

    settings_sandbox above replaces set_value() outright, which is what most
    tests want. These tests are about set_value() itself -- the locked
    read-merge-replace, corruption recovery, the failure contract -- so they
    need the real functions pointed at a temp file instead.

    The lock sidecar is redirected too. Leaving it at the real path would let a
    test contend with a running PolyShield for the user's actual settings lock.
    """
    from ui.core import settings as cfg

    sfile = tmp_path / "config" / "ui_settings.json"
    sfile.parent.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(cfg, "_SETTINGS_FILE", sfile)
    monkeypatch.setattr(cfg, "_LOCK_FILE", sfile.with_name(sfile.name + ".lock"))
    monkeypatch.setattr(cfg, "_cache", None)
    return sfile


# ── Row helpers ───────────────────────────────────────────────────────────────

def add_malicious(db: Path, md5: str, family: str = "TestFamily") -> None:
    con = sqlite3.connect(str(db))
    con.execute(
        "INSERT OR REPLACE INTO malicious "
        "(hash, hash_type, malware_family, detection_count, source, first_seen) "
        "VALUES (?, 'md5', ?, 7, 'test', '2026-01-01T00:00:00')",
        (md5.lower(), family),
    )
    con.commit()
    con.close()


def add_c2_ip(db: Path, ip: str, tags: str = "test-c2") -> None:
    con = sqlite3.connect(str(db))
    con.execute(
        "INSERT OR REPLACE INTO ip_blocklist (ip, tags, port, malware, added_ts) "
        "VALUES (?, ?, 443, 'TestBot', '2026-01-01T00:00:00')",
        (ip, tags),
    )
    con.commit()
    con.close()


# ── Process-global state ──────────────────────────────────────────────────────

# A suite can leave every production *file* untouched and still be non-hermetic
# through Python globals.  The detection path keeps more than the DB paths:
# a scanner singleton, a hook registry, and a lazily-populated hash cache.
#
# The leak that makes this autouse rather than opt-in: scan_async()'s worker
# calls register_intel_hooks() as a fallback, so *any* test touching the async
# Guardian path registers reload_signatures into the real hook registry. A
# later test that never asked for the `hooks` fixture then inherits a live
# callback pointing at an earlier test's scanner.
#
# Restore, not clear: test_intel_hooks.py registers hooks on purpose, and
# blanket-clearing would break it.

@pytest.fixture(autouse=True)
def _restore_global_state():
    """Snapshot and restore every module global the detection path mutates."""
    from tools import update_intelligence as upd
    from ui.core import (guardian_engine, ignore_list, intel_hooks,
                         network_monitor, settings, watcher)

    saved_hooks = list(upd._post_update_hooks)
    saved_registered = intel_hooks._registered
    saved_ge_registered = guardian_engine._post_update_hook_registered
    saved_scanner = guardian_engine._scanner
    saved_cache = ignore_list._cache
    saved_settings_cache = settings._cache
    saved_net_ip = dict(network_monitor._ip_check_cache)
    saved_net_pid = dict(network_monitor._pid_proc_cache)
    saved_poll = network_monitor._poll_count
    saved_watch_cbs = list(watcher._on_detection_callbacks)
    saved_watch_log = list(watcher._event_log)

    yield

    # Slice-assign so anything holding a reference to the same list object
    # sees the restoration too.
    upd._post_update_hooks[:] = saved_hooks
    intel_hooks._registered = saved_registered
    guardian_engine._post_update_hook_registered = saved_ge_registered
    guardian_engine._scanner = saved_scanner
    ignore_list._cache = saved_cache
    settings._cache = saved_settings_cache
    network_monitor._ip_check_cache.clear()
    network_monitor._ip_check_cache.update(saved_net_ip)
    network_monitor._pid_proc_cache.clear()
    network_monitor._pid_proc_cache.update(saved_net_pid)
    network_monitor._poll_count = saved_poll
    watcher._on_detection_callbacks[:] = saved_watch_cbs
    watcher._event_log[:] = saved_watch_log


# ── Detection-path sandboxes ──────────────────────────────────────────────────

@pytest.fixture
def guardian_sandbox(tmp_path, monkeypatch):
    """Point _EnhancedScanner's construction-time reads at empty temp paths.

    _load_sigs() walks _DATA_DIR and falls back to _KNOWN_BAD_TXT;
    _load_nsrl_bloom() reads _BLOOM_PATH.  None of those are covered by the
    intel_db fixture, so without this a developer with guardianai/ cloned gets
    a different virus_db than CI does — the test outcome would depend on
    machine state rather than on the code.
    """
    from ui.core import guardian_engine as ge

    empty = tmp_path / "no_guardian_data"
    monkeypatch.setattr(ge, "_DATA_DIR", empty)
    monkeypatch.setattr(ge, "_KNOWN_BAD_TXT", empty / "known_bad.txt")
    monkeypatch.setattr(ge, "_BLOOM_PATH", empty / "nsrl_bloom.bin")
    return empty


@pytest.fixture
def ignore_db(tmp_path, monkeypatch, pattern_db):
    """Temp ignore_list.sqlite, with the in-process cache invalidated.

    _cache is a module global populated lazily on first contains(); without the
    reset, test order decides the verdict.

    Depends on pattern_db deliberately. add() forwards a "Suspicious pattern:"
    reason to pattern_stats.record_ignore(), so whether an ignore test touches
    telemetry depends on a *string argument* rather than on anything visible in
    the fixture list. Chaining them here means a test cannot leak into the real
    stats DB by passing the wrong reason -- which is exactly how this leaked
    the first time.
    """
    from ui.core import ignore_list

    db = tmp_path / "ignore_list.sqlite"
    monkeypatch.setattr(ignore_list, "_DB_PATH", db)
    monkeypatch.setattr(ignore_list, "_cache", None)
    return db


@pytest.fixture
def pattern_db(tmp_path, monkeypatch):
    """Temp pattern_stats.sqlite.

    That is the whole job — pattern_stats holds no cache, only _lock and
    _DB_PATH, so there is nothing else to reset.
    """
    from ui.core import pattern_stats

    db = tmp_path / "pattern_stats.sqlite"
    monkeypatch.setattr(pattern_stats, "_DB_PATH", db)
    return db


@pytest.fixture
def quarantine_sandbox(tmp_path, monkeypatch):
    """Redirect the quarantine folder.

    quarantine.py mkdirs QUARANTINE_DIR at *import* time, so the real folder
    exists regardless; this fixture's job is to guarantee nothing ever writes
    into it.
    """
    from ui.core import quarantine

    qdir = tmp_path / "quarantine"
    qdir.mkdir()
    monkeypatch.setattr(quarantine, "QUARANTINE_DIR", qdir)
    return qdir


@pytest.fixture
def net_sandbox(monkeypatch):
    """Empty the network monitor's module-level caches for one test.

    Both are process-global and both decide verdicts: _ip_check_cache memoises
    "this address is clean" with no expiry, and _pid_proc_cache decides which
    process a connection is attributed to. A test that inherits either one is
    reading a previous test's conclusions.

    test_intel_hooks.py already calls is_known_bad_ip(), so the IP cache was
    being populated with nothing resetting it before v1.13.
    """
    from ui.core import network_monitor as nm

    monkeypatch.setattr(nm, "_ip_check_cache", {})
    monkeypatch.setattr(nm, "_pid_proc_cache", {})
    monkeypatch.setattr(nm, "_poll_count", 0)
    return nm


@pytest.fixture
def watcher_sandbox(monkeypatch, settings_sandbox):
    """Empty the watcher's module-level state for one test.

    All three are process-global: the event log accumulates every file the
    watcher has ever seen, the callback list decides who gets notified, and a
    leftover _observer would make is_running() report a previous test's
    Observer.

    Depends on settings_sandbox deliberately, the same way ignore_db depends on
    pattern_db. start() and stop() both call cfg.set_value("watcher_enabled"),
    so whether a watcher test writes the user's real config depends on a code
    path rather than on anything visible in its fixture list -- which is
    precisely how it leaked the first time, leaving a config/ui_settings.json.lock
    behind in the working tree.
    """
    from ui.core import watcher as wtch

    monkeypatch.setattr(wtch, "_event_log", [])
    monkeypatch.setattr(wtch, "_on_detection_callbacks", [])
    monkeypatch.setattr(wtch, "_observer", None)
    return wtch


class _InlineThread:
    """A threading.Thread stand-in that runs its target on .start()."""

    def __init__(self, target=None, args=(), kwargs=None, daemon=None, **_):
        self._target = target
        self._args = args
        self._kwargs = kwargs or {}

    def start(self):
        if self._target is not None:
            self._target(*self._args, **self._kwargs)

    def join(self, timeout=None):
        pass

    def is_alive(self):
        return False


class _InlineThreading:
    """The threading module with Thread swapped for the inline runner.

    __getattr__ only fires for names not found on the instance, so Thread
    resolves to _InlineThread and Event/Lock/local fall through to the real
    module untouched. Patching threading.Thread directly would mutate the
    stdlib module for the whole process.
    """

    Thread = _InlineThread

    def __getattr__(self, name):
        return getattr(threading, name)


@pytest.fixture
def run_engines_inline(monkeypatch):
    """Make an engine's scan_async() complete before it returns.

    Every engine ends scan_async() with threading.Thread(target=_run,
    daemon=True).start(). A test that lets that thread run really is racing its
    own assertions, and the usual fixes -- sleep, poll, an Event with a timeout
    -- buy flakiness on a loaded CI runner in exchange for nothing. Running the
    worker on the calling thread makes the assertions ordinary.

    Scoped per engine module rather than globally, so a test that genuinely
    wants concurrency (the pause/resume ones) can simply not ask for it.
    """
    def _install(*modules):
        for module in modules:
            monkeypatch.setattr(module, "threading", _InlineThreading())

    return _install


@pytest.fixture
def yara_sandbox(tmp_path, monkeypatch):
    """Point the YARA engine's three import-time path constants at temp dirs.

    _USER_DIR, _COMMUNITY_DIR and _ACTIVE_PTR are resolved from parents[3] when
    the module is imported, so they cannot be configured -- only patched. A
    developer with rules/community/ populated would otherwise compile a
    different ruleset than CI does, and the test outcome would depend on
    machine state rather than on the code.

    Returns (user_dir, community_dir); neither is created, because "the
    directory does not exist" is one of the states under test.
    """
    from ui.core import yara_engine as ye

    user = tmp_path / "user_rules"
    community = tmp_path / "community"
    monkeypatch.setattr(ye, "_USER_DIR", user)
    monkeypatch.setattr(ye, "_COMMUNITY_DIR", community)
    monkeypatch.setattr(ye, "_ACTIVE_PTR", community / ".active")
    return user, community


@pytest.fixture(scope="session", autouse=True)
def _assert_session_leaves_no_trace():
    """Fail the run if the suite ends holding state it did not start with.

    The per-test fixtures above restore state; this asserts they actually did.
    Without it a restoration bug is invisible -- every test passes, and the
    damage only shows up as an unrelated failure somewhere down the line, or
    in the next process to import these modules.

    Deliberately about *process* state. A suite can leave every production file
    untouched and still be thoroughly non-hermetic through Python globals.
    """
    from tools import update_intelligence as upd
    from ui.core import (guardian_engine, ignore_list, intel_hooks,
                         network_monitor, process_monitor, watcher)

    before = {
        "hooks": list(upd._post_update_hooks),
        "intel_registered": intel_hooks._registered,
        "ge_registered": guardian_engine._post_update_hook_registered,
        "scanner": guardian_engine._scanner,
        "ignore_cache": ignore_list._cache,
        "net_ip": dict(network_monitor._ip_check_cache),
        "net_pid": dict(network_monitor._pid_proc_cache),
        "watch_cbs": list(watcher._on_detection_callbacks),
        "live_monitors": len(process_monitor._live_monitors),
    }

    yield

    assert list(upd._post_update_hooks) == before["hooks"], (
        "a post-update hook outlived the test that registered it")
    assert intel_hooks._registered == before["intel_registered"]
    assert guardian_engine._post_update_hook_registered == before["ge_registered"]
    assert guardian_engine._scanner is before["scanner"], (
        "a test left its scanner installed as the production singleton")
    assert ignore_list._cache == before["ignore_cache"], (
        "the ignore-list cache survived the test that populated it")
    # settings._cache is deliberately NOT asserted here. It is a lazily
    # populated read cache: it starts as None because nothing has read a
    # setting yet, not because it is "clean", and any test calling cfg.get()
    # legitimately fills it. The per-test _restore_global_state snapshot is
    # what stops one test's mutation reaching another -- that is the half with
    # teeth. Asserting a meaningless baseline here only produces a false alarm.
    assert network_monitor._ip_check_cache == before["net_ip"], (
        "an IP verdict outlived the test that cached it")
    assert network_monitor._pid_proc_cache == before["net_pid"], (
        "a PID attribution outlived the test that cached it")
    assert watcher._on_detection_callbacks == before["watch_cbs"], (
        "a watcher detection callback outlived the test that registered it")

    # _live_monitors is a WeakSet, so a monitor a test merely constructed is
    # collected on its own. One that is still reachable is a real leak:
    # reload_all_known_bad() would walk into it from a later test. gc first so
    # this measures reachability rather than collection timing.
    gc.collect()
    assert len(process_monitor._live_monitors) == before["live_monitors"], (
        "a ProcessMonitor is still reachable after the test that built it")

    stragglers = [t.name for t in threading.enumerate()
                  if t is not threading.main_thread() and not t.daemon]
    assert not stragglers, f"non-daemon threads outlived the suite: {stragglers}"


# ── Headless Tk ───────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def tk_root():
    """One Tk root for the whole session.

    Deliberately session-scoped: creating and destroying a CTk root per test
    tears down Tcl's library state, and the *next* root then fails with
    'invalid command name "tcl_findLibrary"'. That surfaced once as an
    intermittent skip — a test quietly protecting nothing.

    Lives here rather than in one test module because only one such root can
    exist per session; every GUI test file shares this one.

    ScanView registers a drop target during _build(), and the tkdnd Tcl
    package is loaded by the root rather than by the tkinterdnd2 import — so
    without the _require() call below the view raises TclError before it is
    built. TkinterDnD.Tk is exactly tkinter.Tk plus that call, and the DnD
    methods are already mixed into every widget at import, so loading the
    package here buys the capability without swapping the root class (which
    would cost CustomTkinter's themed background).
    """
    ctk = pytest.importorskip("customtkinter")
    import tkinter

    try:
        root = ctk.CTk()
    except tkinter.TclError as exc:                      # no display
        pytest.skip(f"Tk unavailable: {exc}")
    root.withdraw()

    try:
        from tkinterdnd2 import TkinterDnD
        TkinterDnD._require(root)
    except Exception:
        pass    # drag-and-drop unavailable; ScanView degrades in _build()

    import ui.theme as theme
    from ui.core import settings as cfg
    theme.init(cfg)
    theme.init_colors(cfg)

    yield root

    try:
        root.destroy()
    except Exception:
        pass


def make_sample_file(tmp_path, content: bytes, name: str = "sample.txt"):
    """Write a file and return (path, md5). A plain helper, like add_malicious."""
    import hashlib

    path = tmp_path / name
    path.write_bytes(content)
    return path, hashlib.md5(content).hexdigest()
