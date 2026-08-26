"""
Scan target resolution.

resolve() decides what a Smart/Quick/Full scan actually reads off the disk, so
a mistake here is either a scan that misses where malware lives or one that
spends an hour in a pip cache. It carried the second-highest risk score in
src/ui/core and had no tests at all.

Everything is driven through the environment and stubbed collaborators:
get_running_process_paths() shells out to PowerShell and startup_scanner reads
the registry, neither of which belongs in a unit test -- and both of which
would make the outcome depend on the developer's machine rather than the code.
"""
from __future__ import annotations

import pytest

from ui.core import scan_presets as sp


@pytest.fixture
def no_collaborators(monkeypatch):
    """Silence the two expensive, machine-dependent inputs."""
    monkeypatch.setattr(sp, "get_running_process_paths", lambda: [])
    monkeypatch.setattr(sp.ss, "enumerate_startup_items", lambda: [])
    monkeypatch.setattr(sp.ss, "get_scannable_paths", lambda items: [])


# ── Dispatch ──────────────────────────────────────────────────────────────────

def test_custom_returns_no_paths_and_a_prompt():
    paths, desc = sp.resolve("Custom")

    assert paths == []
    assert "Drop files" in desc


def test_an_unknown_preset_falls_back_to_custom():
    """resolve() is fed a string from a dropdown; a typo or a stale saved
    preset must not raise into the scan thread."""
    assert sp.resolve("NotAPreset") == sp.resolve("Custom")


def test_full_scans_the_user_profile():
    paths, desc = sp.resolve("Full")

    assert len(paths) == 1
    assert "Full Scan" in desc


# ── Path resolution ───────────────────────────────────────────────────────────

def test_downloads_resolves_when_the_folder_exists(tmp_path, monkeypatch):
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    monkeypatch.setenv("USERPROFILE", str(tmp_path))

    paths, desc = sp.resolve("Downloads")

    assert paths == [str(downloads)]
    assert "Downloads Scan" in desc


def test_downloads_reports_absence_rather_than_returning_a_bad_path(tmp_path,
                                                                   monkeypatch):
    monkeypatch.setenv("USERPROFILE", str(tmp_path))     # no Downloads inside

    paths, desc = sp.resolve("Downloads")

    assert paths == []
    assert "not found" in desc


def test_temp_keeps_only_directories_that_exist(tmp_path, monkeypatch):
    real = tmp_path / "temp_real"
    real.mkdir()
    monkeypatch.setenv("TEMP", str(real))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "does_not_exist"))

    paths, _ = sp.resolve("Temp")

    assert str(real) in paths
    assert all(p for p in paths), "a non-existent directory reached the scan list"


def test_quick_combines_startup_items_with_temp_folders(tmp_path, monkeypatch):
    startup_exe = tmp_path / "autorun.exe"
    startup_exe.write_bytes(b"MZ")
    temp = tmp_path / "temp"
    temp.mkdir()

    monkeypatch.setattr(sp.ss, "enumerate_startup_items", lambda: [{"x": 1}])
    monkeypatch.setattr(sp.ss, "get_scannable_paths", lambda items: [str(startup_exe)])
    monkeypatch.setenv("TEMP", str(temp))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "nope"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "nope"))

    paths, desc = sp.resolve("Quick")

    assert str(startup_exe) in paths
    assert str(temp) in paths
    assert "Quick Scan" in desc


def test_smart_includes_running_processes_and_startup_items(tmp_path, monkeypatch):
    running = tmp_path / "running.exe"
    running.write_bytes(b"MZ")
    startup = tmp_path / "startup.exe"
    startup.write_bytes(b"MZ")

    monkeypatch.setattr(sp, "get_running_process_paths", lambda: [str(running)])
    monkeypatch.setattr(sp.ss, "enumerate_startup_items", lambda: [{"x": 1}])
    monkeypatch.setattr(sp.ss, "get_scannable_paths", lambda items: [str(startup)])
    for var in ("TEMP", "LOCALAPPDATA", "USERPROFILE", "APPDATA"):
        monkeypatch.setenv(var, str(tmp_path / "nope"))

    paths, desc = sp.resolve("Smart")

    assert str(running) in paths
    assert str(startup) in paths
    assert "Smart Scan" in desc


# ── Helpers ───────────────────────────────────────────────────────────────────

def test_dedup_is_case_insensitive_but_keeps_the_first_spelling():
    """Windows paths differ only in case all the time. Scanning the same tree
    twice is the visible cost; the first spelling is kept so the log shows what
    the caller actually asked for."""
    out = sp._dedup([r"C:\Users\Bob", r"c:\users\bob", r"C:\Other"])

    assert out == [r"C:\Users\Bob", r"C:\Other"]


def test_expand_dirs_drops_paths_that_are_not_directories(tmp_path, monkeypatch):
    real = tmp_path / "real"
    real.mkdir()
    a_file = tmp_path / "a_file.txt"
    a_file.write_text("x")
    monkeypatch.setenv("REALDIR", str(real))

    out = sp._expand_dirs([r"%REALDIR%", str(a_file), str(tmp_path / "ghost")])

    assert out == [str(real)], "a file or a missing path was treated as a directory"


def test_running_process_paths_returns_empty_when_powershell_fails(monkeypatch):
    """Enumeration is a best-effort input to Smart scan. If PowerShell is
    blocked by policy the scan should shrink, not raise."""
    def boom(*a, **kw):
        raise OSError("powershell unavailable")

    monkeypatch.setattr(sp.subprocess, "run", boom)

    assert sp.get_running_process_paths() == []


def test_running_process_paths_ignores_lines_that_are_not_files(tmp_path,
                                                                monkeypatch):
    real = tmp_path / "real.exe"
    real.write_bytes(b"MZ")

    class Result:
        returncode = 0
        stdout = f"{real}\n{tmp_path / 'gone.exe'}\n\n"

    monkeypatch.setattr(sp.subprocess, "run", lambda *a, **kw: Result())

    assert sp.get_running_process_paths() == [str(real)]
