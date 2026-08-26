"""
Settings persistence.

This file is here because config/ui_settings.json is written by two processes
-- the UI and the Windows Service -- and until v1.13 it was written with a
bare write_text() of a stale whole-file snapshot. Three separate failures came
out of that: a torn write silently reset every preference to defaults, a
service-side write discarded whatever the UI had changed since it last loaded,
and a failed write was reported as a success.

The user-visible version of those bugs is "why did PolyShield forget my
VirusTotal key", which is exactly the kind of thing that should be caught by a
test rather than by the person it happened to.

The concurrency tests below prove the *mechanism* (locked read-merge-replace).
Proving it across a real process boundary needs two processes; that is the
end-to-end step in the plan, not something a unit test can stand in for.
"""
from __future__ import annotations

import json
import os
import pathlib
import threading

import pytest

from ui.core import settings as cfg


def _write_raw(path, text: str) -> None:
    """Write the settings file behind the module's back.

    Stands in for the other process having written between our read and our
    write -- which is the whole scenario set_value() has to survive.
    """
    path.write_text(text, encoding="utf-8")


# ── Reading ───────────────────────────────────────────────────────────────────

def test_absent_file_yields_defaults_and_no_corrupt_artifact(settings_file):
    """A fresh install is not a corruption event."""
    assert cfg.get("display_theme_preset") == "classic"
    assert not list(settings_file.parent.glob("*.corrupt"))


def test_saved_values_override_defaults(settings_file):
    _write_raw(settings_file, json.dumps({"display_theme_preset": "void"}))

    assert cfg.get("display_theme_preset") == "void"
    assert cfg.get("display_bg_blur") == cfg._DEFAULTS["display_bg_blur"]


def test_get_falls_back_to_defaults_for_an_unknown_key(settings_file):
    assert cfg.get("no_such_setting_exists") is None


# ── Writing ───────────────────────────────────────────────────────────────────

def test_set_value_round_trips_to_disk(settings_file):
    assert cfg.set_value("vt_api_key", "abc123") == cfg.SAVE_OK

    on_disk = json.loads(settings_file.read_text(encoding="utf-8"))
    assert on_disk["vt_api_key"] == "abc123"
    assert cfg.get("vt_api_key") == "abc123"


def test_a_concurrent_writers_key_survives(settings_file):
    """The regression that motivated the whole rewrite.

    Before v1.13 set_value() wrote its stale in-memory snapshot of the *entire*
    file, so a write here discarded everything the other process had changed
    since this one last called load(). The assert below failed.
    """
    cfg.set_value("display_theme_preset", "void")

    # The service writes vt_api_key while this process is unaware of it.
    other = json.loads(settings_file.read_text(encoding="utf-8"))
    other["vt_api_key"] = "written-by-the-service"
    _write_raw(settings_file, json.dumps(other))

    cfg.set_value("display_bg_blur", 7)

    final = json.loads(settings_file.read_text(encoding="utf-8"))
    assert final["vt_api_key"] == "written-by-the-service", (
        "the other process's key was clobbered by a whole-file write")
    assert final["display_bg_blur"] == 7
    assert final["display_theme_preset"] == "void"


def test_threaded_writers_do_not_lose_each_others_keys(settings_file):
    """Exercises the locks for real rather than simulating the interleaving.

    Two threads writing distinct keys is the in-process half of the contract;
    _write_lock plus the file lock have to serialise the read-merge-replace or
    one key goes missing.
    """
    start = threading.Barrier(2)

    def writer(key, count):
        start.wait()
        for i in range(count):
            cfg.set_value(key, i)

    threads = [threading.Thread(target=writer, args=("display_bg_blur", 20)),
               threading.Thread(target=writer, args=("display_bg_opacity", 20))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    final = json.loads(settings_file.read_text(encoding="utf-8"))
    assert final["display_bg_blur"] == 19
    assert final["display_bg_opacity"] == 19


# ── Failure contract ──────────────────────────────────────────────────────────

def test_a_failed_write_reports_failure_and_changes_nothing(settings_file, monkeypatch):
    """A durable write that did not land must not look like one that did.

    The old save() set _cache before writing and swallowed the exception, so
    memory reported a value as persisted that was never written.
    """
    cfg.set_value("vt_api_key", "original")
    before = settings_file.read_bytes()

    def boom(*a, **kw):
        raise OSError("disk full")

    monkeypatch.setattr(cfg.os, "replace", boom)

    assert cfg.set_value("vt_api_key", "never-lands") == cfg.SAVE_FAILED
    assert settings_file.read_bytes() == before, "the original file was damaged"
    assert cfg.get("vt_api_key") == "original", (
        "_cache reported a value the disk never received")


def test_a_failed_write_leaves_no_temp_file_behind(settings_file, monkeypatch):
    monkeypatch.setattr(cfg.os, "replace",
                        lambda *a, **kw: (_ for _ in ()).throw(OSError("nope")))

    cfg.set_value("vt_api_key", "x")

    assert not list(settings_file.parent.glob(".ui_settings-*.tmp"))


def test_the_temp_file_name_is_unique_per_write(settings_file, monkeypatch):
    """A fixed ui_settings.json.tmp is a name two processes collide on."""
    seen = []
    real = cfg.tempfile.mkstemp

    def spy(*a, **kw):
        fd, path = real(*a, **kw)
        seen.append(os.path.basename(path))
        return fd, path

    monkeypatch.setattr(cfg.tempfile, "mkstemp", spy)

    cfg.set_value("display_bg_blur", 1)
    cfg.set_value("display_bg_blur", 2)

    assert len(seen) == 2 and seen[0] != seen[1]


# ── Lock timeout ──────────────────────────────────────────────────────────────

def test_lock_timeout_degrades_and_never_claims_a_durable_merge(settings_file,
                                                                monkeypatch):
    """The bounded wait is a deliberate escape hatch, and it must be visible.

    A settings write may not block a UI toggle forever, so on timeout it falls
    back to a single best-effort write -- which is explicitly outside the
    lost-update guarantee. The point of this test is that such a write reports
    SAVE_DEGRADED and never SAVE_OK.
    """
    msvcrt = pytest.importorskip("msvcrt")
    monkeypatch.setattr(cfg, "_LOCK_TIMEOUT_S", 0.05)

    cfg._LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    holder = os.open(str(cfg._LOCK_FILE), os.O_CREAT | os.O_RDWR)
    try:
        os.lseek(holder, 0, os.SEEK_SET)
        msvcrt.locking(holder, msvcrt.LK_NBLCK, 1)
    except OSError:
        os.close(holder)
        pytest.skip("byte-range locks do not conflict in-process here")

    try:
        result = cfg.set_value("vt_api_key", "written-while-locked")
    finally:
        os.lseek(holder, 0, os.SEEK_SET)
        msvcrt.locking(holder, msvcrt.LK_UNLCK, 1)
        os.close(holder)

    assert result == cfg.SAVE_DEGRADED
    # Still best-effort, so the value does land -- it just carries no
    # cross-process guarantee.
    assert cfg.get("vt_api_key") == "written-while-locked"


def test_the_lock_is_held_on_a_sidecar_not_on_the_settings_file(settings_file):
    """Locking ui_settings.json itself would break the atomic replace.

    Windows refuses os.replace() over a file with an open handle, so the lock
    has to live somewhere the replace never touches.
    """
    cfg.set_value("vt_api_key", "x")

    assert cfg._LOCK_FILE != settings_file
    assert cfg._LOCK_FILE.name.endswith(".lock")


# ── Corruption recovery ───────────────────────────────────────────────────────

def test_malformed_file_is_preserved_and_defaults_returned(settings_file):
    _write_raw(settings_file, "{ this is not json")

    assert cfg.get("display_theme_preset") == "classic"

    artifacts = list(settings_file.parent.glob("*.corrupt"))
    assert len(artifacts) == 1
    assert artifacts[0].read_text(encoding="utf-8") == "{ this is not json"


def test_a_json_document_that_is_not_an_object_is_treated_as_corrupt(settings_file):
    """Valid JSON is not the same as valid settings. A bare list would make
    every later .get() raise AttributeError deep inside a view."""
    _write_raw(settings_file, "[1, 2, 3]")

    assert cfg.get("display_theme_preset") == "classic"
    assert list(settings_file.parent.glob("*.corrupt"))


def test_a_second_corruption_does_not_destroy_the_first_artifact(settings_file):
    """The previous diagnostic is evidence; a later failure must not erase it."""
    _write_raw(settings_file, "first corruption")
    cfg.load()

    _write_raw(settings_file, "second corruption")
    cfg.load()

    artifacts = sorted(p.read_text(encoding="utf-8")
                       for p in settings_file.parent.glob("*.corrupt"))
    assert artifacts == ["first corruption", "second corruption"]


def test_preservation_failure_leaves_the_original_untouched(settings_file,
                                                            monkeypatch):
    """Recovery bookkeeping never outranks the user's last remaining copy.

    _preserve_corrupt copies rather than moves precisely so that this failure
    mode cannot destroy the original. If it ever becomes a rename, this fails.
    """
    _write_raw(settings_file, "{ corrupt but precious")

    real_write_bytes = pathlib.Path.write_bytes

    def refuse(self, data):
        if self.name.endswith(".corrupt"):
            raise OSError("cannot write the diagnostic copy")
        return real_write_bytes(self, data)

    monkeypatch.setattr(pathlib.Path, "write_bytes", refuse)

    assert cfg.get("display_theme_preset") == "classic"
    assert settings_file.read_text(encoding="utf-8") == "{ corrupt but precious"


def test_set_value_on_a_malformed_file_recovers_and_persists(settings_file):
    """The read half of the locked merge hits corruption too.

    Preserve aside, fall back to _DEFAULTS as the merge base, apply the key,
    replace the malformed file -- and leave a normal settings file behind.
    """
    _write_raw(settings_file, "}}} not json")

    assert cfg.set_value("vt_api_key", "set-after-corruption") == cfg.SAVE_OK

    recovered = json.loads(settings_file.read_text(encoding="utf-8"))
    assert recovered["vt_api_key"] == "set-after-corruption"
    assert list(settings_file.parent.glob("*.corrupt"))
    # The merge base was defaults, not the unreadable file.
    assert cfg.get("display_theme_preset") == "classic"
