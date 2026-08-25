"""
Shared pytest fixtures for the PolyShield test suite.

Everything here is hermetic: no test may touch the real
`intelligence/threat_db.sqlite` (it is ~146 MB and holds the user's live
intelligence), and no test may leave a post-update hook registered behind it.
"""
from __future__ import annotations

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
    monkeypatch.setattr(cfg, "set_value", lambda k, v: sandbox.__setitem__(k, v))
    return sandbox


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
    from ui.core import guardian_engine, ignore_list, intel_hooks

    saved_hooks = list(upd._post_update_hooks)
    saved_registered = intel_hooks._registered
    saved_ge_registered = guardian_engine._post_update_hook_registered
    saved_scanner = guardian_engine._scanner
    saved_cache = ignore_list._cache

    yield

    # Slice-assign so anything holding a reference to the same list object
    # sees the restoration too.
    upd._post_update_hooks[:] = saved_hooks
    intel_hooks._registered = saved_registered
    guardian_engine._post_update_hook_registered = saved_ge_registered
    guardian_engine._scanner = saved_scanner
    ignore_list._cache = saved_cache


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
    from ui.core import guardian_engine, ignore_list, intel_hooks

    before = {
        "hooks": list(upd._post_update_hooks),
        "intel_registered": intel_hooks._registered,
        "ge_registered": guardian_engine._post_update_hook_registered,
        "scanner": guardian_engine._scanner,
        "ignore_cache": ignore_list._cache,
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

    The root class mirrors app.py's own choice: App subclasses TkinterDnD.Tk
    when tkinterdnd2 imports, and plain CTk otherwise. That is not a detail —
    ScanView registers a drop target during _build(), and the tkdnd Tcl
    extension is loaded by the root, not by the import. On a plain CTk root the
    whole view fails to construct, so testing there would mean testing a
    configuration that never ships.
    """
    ctk = pytest.importorskip("customtkinter")
    import tkinter

    try:
        from tkinterdnd2 import TkinterDnD
        root_cls = TkinterDnD.Tk
    except ImportError:
        root_cls = ctk.CTk

    try:
        root = root_cls()
    except tkinter.TclError as exc:                      # no display
        pytest.skip(f"Tk unavailable: {exc}")
    root.withdraw()

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
