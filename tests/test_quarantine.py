"""
Quarantine — moving a suspected threat out of harm's way, and back.

Everything here is destructive by nature: the file is moved, not copied, and
the only record of where it came from is a JSON sidecar. Two properties matter
more than the rest, and both are asserted below:

  * restoring must never destroy something already at the destination
  * the recorded origin must not depend on what the working directory happened
    to be at the moment of capture

A quarantine that loses the user's file is worse than one that refuses to act.
"""
from __future__ import annotations

import json

from ui.core import quarantine as q


def _quarantine_one(tmp_path, name="threat.exe", body=b"malicious"):
    src = tmp_path / name
    src.write_bytes(body)
    return src, q.add_file(str(src), threat_name="Test.Threat")


# ── Capture ───────────────────────────────────────────────────────────────────

def test_add_file_moves_the_source_and_writes_a_sidecar(quarantine_sandbox, tmp_path):
    src, dest = _quarantine_one(tmp_path)

    assert not src.exists()
    assert dest.exists()
    assert dest.read_bytes() == b"malicious"

    meta = json.loads(q._meta_path(dest).read_text(encoding="utf-8"))
    assert meta["threat_name"] == "Test.Threat"
    assert meta["quarantine_date"]


def test_colliding_names_do_not_overwrite_each_other(quarantine_sandbox, tmp_path):
    """Two different files can share a basename. Quarantining the second must
    not silently replace the first."""
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "dup.exe").write_bytes(b"first")
    (tmp_path / "b" / "dup.exe").write_bytes(b"second")

    first = q.add_file(str(tmp_path / "a" / "dup.exe"))
    second = q.add_file(str(tmp_path / "b" / "dup.exe"))

    assert first != second
    assert first.read_bytes() == b"first"
    assert second.read_bytes() == b"second"


def test_the_recorded_origin_is_absolute(quarantine_sandbox, tmp_path, monkeypatch):
    """A relative path resolved months later, against whatever CWD the process
    happens to have, is not a restore target — it is a guess."""
    workdir = tmp_path / "work"
    workdir.mkdir()
    (workdir / "threat.exe").write_bytes(b"malicious")
    monkeypatch.chdir(workdir)

    dest = q.add_file("threat.exe")

    meta = json.loads(q._meta_path(dest).read_text(encoding="utf-8"))
    recorded = meta["original_path"]
    from pathlib import Path
    assert Path(recorded).is_absolute()
    assert Path(recorded) == workdir / "threat.exe"


# ── Listing ───────────────────────────────────────────────────────────────────

def test_list_reports_the_entry_without_its_sidecar(quarantine_sandbox, tmp_path):
    src, dest = _quarantine_one(tmp_path)

    entries = q.list_quarantined()
    assert len(entries) == 1
    assert entries[0]["filename"] == dest.name
    assert entries[0]["threat_name"] == "Test.Threat"
    assert entries[0]["original_path"] == str(src)


def test_list_skips_dotfiles(quarantine_sandbox, tmp_path):
    _quarantine_one(tmp_path)
    (quarantine_sandbox / ".gitkeep").write_text("")

    assert [e["filename"] for e in q.list_quarantined()] == ["threat.exe"]


def test_an_entry_without_a_sidecar_is_still_listed(quarantine_sandbox, tmp_path):
    """A crash between the move and the sidecar write must not make the file
    invisible — an unrestorable entry the user can see and delete beats a file
    silently occupying the quarantine folder."""
    _, dest = _quarantine_one(tmp_path)
    q._meta_path(dest).unlink()

    entries = q.list_quarantined()
    assert len(entries) == 1
    assert entries[0]["original_path"] == "Unknown"


# ── Restore ───────────────────────────────────────────────────────────────────

def test_restore_returns_the_file_to_its_origin(quarantine_sandbox, tmp_path):
    src, dest = _quarantine_one(tmp_path)
    entry = q.list_quarantined()[0]

    assert q.restore(entry) is True
    assert src.exists()
    assert src.read_bytes() == b"malicious"
    assert not dest.exists()
    assert not q._meta_path(dest).exists()


def test_restore_refuses_when_the_origin_is_unknown(quarantine_sandbox, tmp_path):
    _, dest = _quarantine_one(tmp_path)
    q._meta_path(dest).unlink()

    assert q.restore(q.list_quarantined()[0]) is False
    assert dest.exists()


def test_restore_refuses_rather_than_overwriting_the_destination(quarantine_sandbox, tmp_path):
    """The user re-created (or re-downloaded) something at the original path
    while the threat sat in quarantine. Restoring must not eat it."""
    src, dest = _quarantine_one(tmp_path)
    src.write_bytes(b"a different file the user cares about")

    entry = q.list_quarantined()[0]
    assert q.restore(entry) is False

    assert src.read_bytes() == b"a different file the user cares about"
    assert dest.exists(), "a refused restore must leave the quarantined file intact"
    assert q._meta_path(dest).exists(), "a refused restore must leave the sidecar intact"


def test_restore_recreates_a_missing_parent_directory(quarantine_sandbox, tmp_path):
    nested = tmp_path / "deep" / "nested"
    nested.mkdir(parents=True)
    (nested / "threat.exe").write_bytes(b"malicious")
    q.add_file(str(nested / "threat.exe"))

    import shutil
    shutil.rmtree(tmp_path / "deep")

    assert q.restore(q.list_quarantined()[0]) is True
    assert (nested / "threat.exe").exists()


# ── Delete ────────────────────────────────────────────────────────────────────

def test_delete_removes_the_file_and_its_sidecar(quarantine_sandbox, tmp_path):
    _, dest = _quarantine_one(tmp_path)

    assert q.delete(q.list_quarantined()[0]) is True
    assert not dest.exists()
    assert not q._meta_path(dest).exists()
    assert q.list_quarantined() == []


# ── The view-facing wrapper ───────────────────────────────────────────────────
#
# Every quarantine action in the Threat Actions panel calls move_to_quarantine()
# and unpacks (ok, msg). The function was documented in CLAUDE.md and used from
# three call sites but never actually existed, so each of those actions raised
# AttributeError: the per-threat button did nothing, Quarantine All hung on
# "Quarantining…", and bulk quarantine silently reported 0/N. These tests pin
# the contract those callers rely on.

def test_move_to_quarantine_reports_success_and_a_message(quarantine_sandbox, tmp_path):
    src = tmp_path / "threat.exe"
    src.write_bytes(b"malicious")

    ok, msg = q.move_to_quarantine(str(src), threat_name="Test.Threat")

    assert ok is True
    assert "threat.exe" in msg
    assert not src.exists()
    assert q.list_quarantined()[0]["threat_name"] == "Test.Threat"


def test_move_to_quarantine_reports_a_missing_file_instead_of_raising(quarantine_sandbox, tmp_path):
    """A threat found by a scan can be gone by the time the user clicks
    Quarantine. An exception here reaches a Tk command handler and vanishes."""
    ok, msg = q.move_to_quarantine(str(tmp_path / "already_gone.exe"))

    assert ok is False
    assert "already_gone.exe" in msg


def test_move_to_quarantine_returns_a_two_tuple_every_caller_can_unpack(quarantine_sandbox, tmp_path):
    """_on_quarantine_all_done does `for ok, msg in results` — the shape is
    load-bearing on both the success and the failure path."""
    src = tmp_path / "threat.exe"
    src.write_bytes(b"malicious")

    for result in (q.move_to_quarantine(str(src)),
                   q.move_to_quarantine(str(tmp_path / "missing.exe"))):
        ok, msg = result
        assert isinstance(ok, bool)
        assert isinstance(msg, str) and msg
