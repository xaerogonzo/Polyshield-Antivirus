"""
The privilege boundary between the unelevated GUI and the LocalService service.

The invariant, and it is narrower than "the GUI cannot write anything":

    An unprivileged process cannot modify authoritative intelligence that the
    privileged service trusts when making detection decisions.

Split on REACH, not on sensitivity:

  intelligence/  is detection INPUT  -> service-owned, GUI writes via IPC.
                 None of those writes needs to read a user file, so routing
                 them costs nothing.

  quarantine/    is remediation OUTPUT -> stays directly GUI-writable.
                 Quarantine must read and move files inside the interactive
                 user profile, and LocalService cannot reach those without a
                 manual per-folder grant (docs/WINDOWS_SERVICE.md, "Service
                 can't access watched folder"). Routing it would break the core
                 action of the product in order to protect data that is not a
                 detection input.

The ACL half -- that an ordinary user can read but not write intelligence/ --
cannot be asserted from pytest: it is a property of the installed directory,
not of the code. tools/sandbox_verify.ps1 checks it on a real install (4c.5).
What is asserted here is the half the code owns: that the GUI routes the write,
that it fails loudly rather than silently when it cannot, and that quarantine
never became a detection input.
"""
import pathlib

import pytest

from ui.core import ignore_list
from ui.core import paths

SRC = pathlib.Path(__file__).resolve().parents[1] / "src"

_SQL_INJECTION = "'; DROP TABLE ignored_hashes; --"


@pytest.fixture
def distribution(monkeypatch):
    """Make this process look like a shipped build."""
    monkeypatch.setattr(paths, "_FROZEN_OVERRIDE", True)


@pytest.fixture
def source_checkout(monkeypatch):
    monkeypatch.setattr(paths, "_FROZEN_OVERRIDE", False)


# == The GUI writes intelligence only through the service =====================

def test_a_distribution_routes_an_ignore_write_to_the_service(
        distribution, ignore_db, monkeypatch):
    sent = {}

    def _fake_send(cmd, **kwargs):
        sent["cmd"] = cmd
        sent.update(kwargs)
        return {"ok": True}

    import ui.core.service_client as sc
    monkeypatch.setattr(sc, "send_command", _fake_send)

    assert ignore_list.add("a" * 32, "md5", "evil.exe", "note", "reason") is True
    assert sent["cmd"] == "IGNORE_HASH"
    assert sent["md5"] == "a" * 32
    assert not ignore_db.exists(), "a distribution GUI must not write intelligence/"


def test_a_source_checkout_still_writes_directly(source_checkout, ignore_db):
    """The developer path is unchanged: a checkout owns its own project root."""
    assert ignore_list.add("b" * 32) is True
    assert ignore_list.contains("b" * 32)


def test_an_unreachable_service_raises_rather_than_returning_false(
        distribution, ignore_db, monkeypatch):
    """The failure that must never be silent.

    Returning False here is indistinguishable from "that hash was already in
    the list", and the user would believe a file had been whitelisted when
    nothing at all had been written.
    """
    def _refused(*a, **k):
        raise OSError("connection refused")

    import ui.core.service_client as sc
    monkeypatch.setattr(sc, "send_command", _refused)

    with pytest.raises(ignore_list.ServiceRequired):
        ignore_list.add("c" * 32)


def test_a_service_refusal_is_also_raised(distribution, ignore_db, monkeypatch):
    import ui.core.service_client as sc
    monkeypatch.setattr(sc, "send_command",
                        lambda *a, **k: {"ok": False, "error": "unauthorized"})

    with pytest.raises(ignore_list.ServiceRequired, match="unauthorized"):
        ignore_list.add("d" * 32)


def test_a_routed_write_drops_this_process_stale_cache(
        distribution, ignore_db, monkeypatch):
    """The service wrote the row; the in-process Guardian cache predates it.

    Without the invalidation the next scan in THIS process keeps answering from
    the pre-write set, so a file the user just ignored is flagged again.
    """
    monkeypatch.setattr(ignore_list, "_cache", {"stale"})
    import ui.core.service_client as sc
    monkeypatch.setattr(sc, "send_command", lambda *a, **k: {"ok": True})

    ignore_list.add("e" * 32)

    assert ignore_list._cache is None


def test_reads_are_never_routed(distribution, ignore_db, monkeypatch):
    """Users:Read is enough to read; only writes need the service."""
    def _boom(*a, **k):
        raise AssertionError("a read must not contact the service")

    import ui.core.service_client as sc
    monkeypatch.setattr(sc, "send_command", _boom)

    assert ignore_list.contains("f" * 32) is False
    assert ignore_list.count() == 0
    assert ignore_list.list_all() == []


# == The service validates what it is asked to write ==========================

def test_the_service_rejects_anything_that_is_not_a_hash():
    """The IPC token is readable by every local user by design, so this handler
    is reachable by any process running as the user. Constraining the input is
    what keeps that reach to one whitelist entry rather than arbitrary content
    written into a service-owned database.
    """
    import polyshield_service

    for bad in ("", "xyz", "g" * 32, "a" * 31, "a" * 33, _SQL_INJECTION,
                "../../etc/passwd", "A" * 32):
        assert polyshield_service._is_hex_hash(bad) is False, bad


def test_the_service_accepts_md5_and_sha256():
    import polyshield_service

    assert polyshield_service._is_hex_hash("a" * 32) is True
    assert polyshield_service._is_hex_hash("0123456789abcdef" * 4) is True


# == Quarantine stays reachable without the service ===========================

def test_quarantine_works_with_no_service_running(
        distribution, quarantine_sandbox, tmp_path, monkeypatch):
    """The whole reason quarantine is NOT routed.

    A file in a normal user-owned directory must be quarantinable by the GUI
    alone. Any contact with the service here would be the regression this split
    exists to avoid.
    """
    def _boom(*a, **k):
        raise AssertionError("quarantine must not require the service")

    import ui.core.service_client as sc
    monkeypatch.setattr(sc, "send_command", _boom)

    victim = tmp_path / "downloads" / "evil.exe"
    victim.parent.mkdir(parents=True)
    victim.write_bytes(b"MZ payload")

    from ui.core import quarantine

    ok, msg = quarantine.move_to_quarantine(str(victim))

    assert ok, msg
    assert not victim.exists(), "the original should have been moved"


# == Quarantine is not a detection input ======================================

# Only these may name the quarantine directory at all. Everything else in the
# detection path must be unable to consult it, so that tampering with the
# quarantine contents cannot change a verdict.
_MAY_TOUCH_QUARANTINE = {
    "ui/core/quarantine.py": "the module that owns it",
    "ui/core/paths.py":      "the module that resolves it",
    "ui/core/scanner.py":    "k2 --move destination, write-only",
}


def test_no_detection_module_can_read_the_quarantine_directory():
    """Quarantine is remediation OUTPUT, never detection INPUT.

    That is what allows quarantine/ to stay user-writable: a process able to
    tamper with it still cannot influence what the service decides is
    malicious. If a detection path ever starts reading quarantine, the
    reasoning breaks -- and this test is what says so.
    """
    offenders = []
    for path in sorted(SRC.rglob("*.py")):
        rel = path.relative_to(SRC).as_posix()
        if rel in _MAY_TOUCH_QUARANTINE:
            continue
        text = path.read_text(encoding="utf-8")
        if "quarantine_dir()" in text or "QUARANTINE_DIR" in text:
            offenders.append(rel)

    assert offenders == [], (
        "these read the quarantine directory; quarantine must not become a "
        f"detection input, or it can no longer be user-writable: {offenders}")


# == Intelligence updates need the service in a distribution ==================

def test_a_distribution_ui_update_reports_instead_of_failing_per_feed(
        distribution, monkeypatch):
    """The service is the designated writer even when it is not running.

    intelligence/ is service-owned on disk, so a UI-side run would fail inside
    each importer with a permission error. Those surface in the Update Center
    looking like network failures, which sends the user to check their
    connection over a problem that has nothing to do with it.
    """
    from ui.core import intel_updater as iu

    def _no_service():
        return False

    monkeypatch.setattr(iu, "_service_owns_updates", _no_service)

    out = iu.run_updates(feeds=["malwarebazaar"], force=True, owner="ui")

    assert out["status"] == iu.FAILED
    assert "service is required" in out["error"]


def test_a_source_checkout_update_still_runs_locally(
        source_checkout, monkeypatch, intel_db):
    """The developer path is unchanged: a checkout owns its own project root."""
    from ui.core import intel_updater as iu

    monkeypatch.setattr(iu, "_service_owns_updates", lambda: False)
    monkeypatch.setattr(
        iu, "_run_malwarebazaar",
        lambda force, log_fn: {"status": iu.UNCHANGED, "added": 0, "total": 0,
                               "error": "", "http_status": 0})

    out = iu.run_updates(feeds=["malwarebazaar"], force=True, owner="ui")

    assert out["status"] != iu.FAILED, out["error"]


def test_the_service_itself_is_never_blocked(distribution, monkeypatch, intel_db):
    """The gate is for unprivileged callers. The service IS the writer."""
    from ui.core import intel_updater as iu

    monkeypatch.setattr(iu, "_service_owns_updates", lambda: False)
    monkeypatch.setattr(
        iu, "_run_malwarebazaar",
        lambda force, log_fn: {"status": iu.UNCHANGED, "added": 0, "total": 0,
                               "error": "", "http_status": 0})

    out = iu.run_updates(feeds=["malwarebazaar"], force=True, owner="service")

    assert "service is required" not in out.get("error", "")


# == k2 does not get to prune PolyShield rules ================================

def test_k2_is_never_pointed_at_polyshields_rules_directory(monkeypatch):
    """k2 --update deletes every file its manifest does not list.

    It finds the directory to prune through %SYSTEM_RULES_BASE%, and
    config/.env pointed that at PolyShield own rules/ -- which also holds the
    YARA Forge generations published by download_yara_community(). So every
    Update Center -> K2 Engine Signatures click deleted rules/community/,
    the .active pointer included, and yara_engine then reported "no rules"
    with nothing to explain it.

    Measured twice on a live tree before the cause was found. The first
    diagnosis blamed the working directory, which was wrong: k2 never consults
    cwd for this.
    """
    from ui.core import scanner

    seen = {}

    class _FakeProc:
        stdout = []
        returncode = 0

        def wait(self, *a, **k):
            return 0

        def poll(self):
            return 0

    def _fake_popen(cmd, **kwargs):
        seen["env"] = kwargs.get("env")
        return _FakeProc()

    monkeypatch.setattr(scanner.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(scanner, "_stream_process", lambda *a, **k: None)

    scanner.run_update(lambda line: None, lambda rc: None)
    import time
    for _ in range(200):                     # run_update spawns a thread
        if "env" in seen:
            break
        time.sleep(0.01)

    env = seen.get("env")
    assert env, "k2 must be given an explicit environment"
    assert "SYSTEM_RULES_BASE" in env, (
        "without this k2 falls back to config/.env, which names PolyShield rules/")

    pruned = pathlib.Path(env["SYSTEM_RULES_BASE"]).resolve()
    polyshield_rules = paths.rules_dir().resolve()

    assert pruned != polyshield_rules
    assert polyshield_rules not in pruned.parents, (
        "k2 would prune a parent of PolyShield rules/ and take community/ with it")
    # The generation directory yara_engine actually reads must be outside it.
    assert (polyshield_rules / "community").resolve() != pruned


def test_the_env_template_does_not_point_k2_at_polyshield_rules():
    """install.bat generates config/.env from this template, so a wrong value
    here reappears on every new machine."""
    template = (pathlib.Path(__file__).resolve().parents[1]
                / "config" / ".env.template").read_text(encoding="utf-8")

    line = next(l for l in template.splitlines()
                if l.startswith("SYSTEM_RULES_BASE="))
    value = line.split("=", 1)[1].strip()

    assert not value.endswith("{PROJECT_ROOT}" + chr(92) + "rules"), (
        "k2 prunes SYSTEM_RULES_BASE; pointing it at PolyShield rules/ deletes "
        "the published YARA community generation on every signature update")


# == The build gate can tell a loaded K2 from a gutted one ====================

def _k2_probe(monkeypatch, stdout: str, available: bool = True):
    import sys as _sys
    root = pathlib.Path(__file__).resolve().parents[1]
    if str(root) not in _sys.path:
        _sys.path.insert(0, str(root))
    from tools import engine_probe
    from ui.core import scanner

    monkeypatch.setattr(scanner, "is_available", lambda: available)
    monkeypatch.setattr(scanner, "_k2_env", lambda: {})

    class _R:
        pass

    r = _R()
    r.stdout = stdout
    # The probe reports what k2 actually printed when the count falls short: a
    # bare number cannot distinguish "ran and listed nothing" from "did not run".
    r.stderr = ""
    r.returncode = 0
    monkeypatch.setattr(engine_probe.subprocess, "run", lambda *a, **k: r)
    return engine_probe.check_k2()


def test_a_k2_whose_plugins_loaded_reports_detected(monkeypatch):
    listing = "\n".join(
        f"Trojan.Test.{i}   [kicomav.plugins.pdf]" for i in range(500))

    out = _k2_probe(monkeypatch, listing)

    assert out["available"] is True
    assert out["detected"] is True


def test_a_k2_whose_plugins_silently_failed_reports_undetected(monkeypatch):
    """The failure the build gate exists for.

    K2 loads its plugins with SourceFileLoader and swallows every per-plugin
    failure, so a build that lost them still starts, still exits zero and still
    reports a clean scan -- indistinguishable, from outside, from a machine
    with nothing wrong.
    """
    out = _k2_probe(monkeypatch, "no plugins here\n")

    assert out["available"] is True
    assert out["detected"] is False, (
        "a K2 with no loaded plugins must not pass the build gate")
    assert "did not survive" in out["detail"]


def test_an_absent_k2_reports_absent_rather_than_clean(monkeypatch):
    out = _k2_probe(monkeypatch, "", available=False)

    assert out["available"] is False
    assert out["detected"] is None


# == k2 signature count: the number that reveals a crippled install ===========

def _count_with(monkeypatch, stdout, raises=False):
    from ui.core import scanner
    import subprocess as sp

    class _R:
        pass

    def _run(*a, **k):
        if raises:
            raise OSError("k2 could not be started")
        r = _R()
        r.stdout = stdout
        r.stderr = ""
        r.returncode = 0
        return r

    monkeypatch.setattr(scanner, "_k2_env", lambda: {})
    monkeypatch.setattr(sp, "run", _run)
    return scanner.get_signature_count()


def test_a_seeded_k2_reports_its_full_signature_count(monkeypatch):
    listing = "\n".join(f"Trojan.X.{i}  [kicomav.plugins.pdf]" for i in range(1263))

    assert _count_with(monkeypatch, listing) == 1263


def test_an_unseeded_k2_reports_only_its_built_in_signatures(monkeypatch):
    """The failure this number exists to expose.

    k2 answers an unreachable update source with "[No updates available]" and
    exit 0, leaving the rule archives absent. It then scans with the ~23
    signatures compiled into its plugin modules -- under 2% of its detection --
    and nothing else in the product reports that as wrong.
    """
    listing = "\n".join(f"Trojan.X.{i}  [kicomav.plugins.rtf]" for i in range(23))

    n = _count_with(monkeypatch, listing)

    assert n == 23
    assert n < 100, "the Update Center renders anything under 100 as built-in only"


def test_a_k2_that_cannot_run_is_reported_as_unavailable_not_as_zero_signatures(
        monkeypatch):
    """0 means "could not ask", which the UI shows as unavailable. That is a
    different statement from "ran and found few", and they have different fixes.
    """
    assert _count_with(monkeypatch, "", raises=True) == 0
