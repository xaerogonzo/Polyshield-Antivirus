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
