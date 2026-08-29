"""
Removing the machine-level state PolyShield creates.

Three things outlive the process: the Windows service, the Explorer verb and
the scheduled task. An uninstaller must remove exactly those, and a *failed*
install must be able to get back to the state of one that never ran --
docs/ARCHITECTURE.md records that a run which registers the service and then
fails elsewhere leaves the registration behind, and that repeated attempts
accumulate dirty state.

The properties that matter, and none of them are obvious:

  * absent is success, because a rollback runs after an unknown amount of the
    install has happened
  * every step is attempted even when an earlier one fails, because they are
    independent and a rollback that stops early leaves more behind
  * user data is never touched
"""
import subprocess

import pytest

from ui.core import integration


@pytest.fixture(autouse=True)
def _never_touch_the_real_hive(monkeypatch):
    """shell_ext talks to winreg directly, not through subprocess.

    Learned the hard way: a test here stubbed subprocess, assumed that covered
    every step, and unregister_context_menu went straight to the live HKCU and
    deleted the user real Explorer verb. Autouse so a future test cannot
    reintroduce that by forgetting.
    """
    from ui.core import shell_ext

    class _FakeWinreg:
        HKEY_CURRENT_USER = "HKCU"
        REG_SZ = 1

        def __init__(self):
            self.tree = {}

        def CreateKey(self, hive, sub):
            self.tree.setdefault((hive, sub), {})
            return _Key(self, hive, sub)

        def OpenKey(self, hive, sub, *a, **k):
            if (hive, sub) not in self.tree:
                raise FileNotFoundError(2, "not found")
            return _Key(self, hive, sub)

        def SetValueEx(self, key, name, _r, _t, data):
            self.tree[(key.hive, key.sub)][name] = data

        def DeleteKey(self, hive, sub):
            if (hive, sub) not in self.tree:
                raise FileNotFoundError(2, "not found")
            del self.tree[(hive, sub)]

    class _Key:
        def __init__(self, reg, hive, sub):
            self.reg, self.hive, self.sub = reg, hive, sub

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    fake = _FakeWinreg()
    monkeypatch.setattr(shell_ext, "winreg", fake)
    return fake


@pytest.fixture
def sc_calls(monkeypatch):
    """Record `sc` invocations and script their exit codes."""
    calls = []
    scripted = {}
    # `sc query` output, scriptable per test. Defaults to STOPPED because
    # unregister_service polls query until the stop it just asked for has
    # actually taken effect -- sc stop returns before the service has stopped.
    # A fixture that answered with nothing made every test wait out the full
    # timeout.
    query_text = {"text": "STATE : 1 STOPPED"}

    class _R:
        def __init__(self, code, stdout=""):
            self.returncode = code
            self.stdout = stdout
            self.stderr = ""

    def _fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        verb = cmd[1]
        return _R(scripted.get(verb, 0),
                  query_text["text"] if verb == "query" else "")

    monkeypatch.setattr(subprocess, "run", _fake_run)
    return calls, scripted, query_text


@pytest.fixture
def no_side_effects(monkeypatch):
    """The two non-service steps, stubbed to succeed."""
    monkeypatch.setattr(integration, "unregister_context_menu",
                        lambda: (True, "menu removed"))
    monkeypatch.setattr(integration, "unregister_scheduled_task",
                        lambda: (True, "task removed"))


# == Absent is success ========================================================

def test_a_service_that_was_never_registered_is_not_a_failure(sc_calls):
    """1060 is "the specified service does not exist".

    A rollback runs after an unknown amount of the install has happened, so
    "it was not there" is the expected case at least as often as not.
    """
    calls, scripted, _q = sc_calls
    scripted["delete"] = 1060
    scripted["stop"] = 1060

    ok, detail = integration.unregister_service()

    assert ok
    assert "not registered" in detail


def test_a_service_that_was_not_running_is_still_deleted(sc_calls):
    """1062 is "the service has not been started" -- deleting it is the point."""
    calls, scripted, _q = sc_calls
    scripted["stop"] = 1062
    scripted["delete"] = 0

    ok, detail = integration.unregister_service()

    assert ok
    assert ["sc", "delete", integration.SERVICE_NAME] in calls


def test_the_service_is_stopped_before_it_is_deleted(sc_calls):
    """Deleting a running service only marks it for deletion; it lingers until
    the last handle closes, and the next install then fails with "marked for
    deletion", which reads as a corrupt system rather than a reboot away."""
    calls, _, _q = sc_calls

    integration.unregister_service()

    verbs = [c[1] for c in calls if c[0] == "sc"]
    assert verbs.index("stop") < verbs.index("delete")


def test_a_real_delete_failure_is_reported(sc_calls):
    calls, scripted, _q = sc_calls
    scripted["delete"] = 5           # access denied

    ok, detail = integration.unregister_service()

    assert not ok
    assert "could not delete" in detail


def test_sc_being_unavailable_is_reported_not_raised(monkeypatch):
    def _boom(*a, **k):
        raise FileNotFoundError("sc not found")

    monkeypatch.setattr(subprocess, "run", _boom)

    ok, detail = integration.unregister_service()

    assert not ok
    assert "sc not found" in detail


# == Every step runs ==========================================================

def test_a_failing_step_does_not_stop_the_others(monkeypatch, sc_calls):
    """They are independent. A rollback that stops at the first problem leaves
    more behind than one that keeps going."""
    _, scripted, _q = sc_calls
    scripted["delete"] = 5           # the service step fails

    seen = []
    monkeypatch.setattr(integration, "unregister_context_menu",
                        lambda: (seen.append("menu"), (True, "menu removed"))[1])
    monkeypatch.setattr(integration, "unregister_scheduled_task",
                        lambda: (seen.append("task"), (True, "task removed"))[1])

    report = integration.unregister_all()

    assert seen == ["menu", "task"], "later steps must still run"
    assert report["ok"] is False
    assert report["steps"]["service"]["ok"] is False
    assert report["steps"]["context menu"]["ok"] is True


def test_a_step_that_raises_is_contained(monkeypatch, sc_calls, no_side_effects):
    def _raise():
        raise OSError("hive is locked")

    monkeypatch.setattr(integration, "unregister_context_menu", _raise)

    report = integration.unregister_all()

    assert report["ok"] is False
    assert "hive is locked" in report["steps"]["context menu"]["detail"]
    assert report["steps"]["scheduled task"]["ok"] is True


def test_a_clean_machine_reports_success(sc_calls, no_side_effects):
    _, scripted, _q = sc_calls
    scripted["delete"] = 1060
    scripted["stop"] = 1060

    report = integration.unregister_all()

    assert report["ok"] is True
    assert set(report["steps"]) == {"service", "context menu", "scheduled task"}


def test_unregister_all_is_idempotent(sc_calls, no_side_effects):
    """Running it twice must be the same as running it once: an installer
    rollback may fire after a partial uninstall."""
    _, scripted, _q = sc_calls
    scripted["delete"] = 1060
    scripted["stop"] = 1060

    first = integration.unregister_all()
    second = integration.unregister_all()

    assert first["ok"] is True and second["ok"] is True


# == Nothing here touches user data ===========================================

def test_teardown_never_names_a_user_data_directory():
    """Quarantine may hold the only copy of a file somebody wants back, so an
    uninstall removes program state and leaves data alone unless asked."""
    import pathlib

    src = (pathlib.Path(integration.__file__)).read_text(encoding="utf-8")

    for forbidden in ("app_root", "quarantine_dir", "intelligence_dir",
                      "logs_dir", "rmtree", "unlink"):
        assert forbidden not in src.split('"""')[-1], (
            f"teardown must not reach for {forbidden}")


def test_the_missing_task_case_does_not_call_delete(monkeypatch):
    """schtasks exits non-zero for a task that does not exist, and its failure
    text is localised -- so absence is settled by asking, not by parsing."""
    from ui.core import scheduler

    called = []
    monkeypatch.setattr(scheduler, "get_task_info", lambda: {"exists": False})
    monkeypatch.setattr(scheduler, "delete_task",
                        lambda: (called.append(1), (True, ""))[1])

    ok, detail = integration.unregister_scheduled_task()

    assert ok and not called
    assert "no scheduled task" in detail


def test_the_delete_waits_for_the_stop_to_take_effect(sc_calls, monkeypatch):
    """sc stop RETURNS BEFORE THE SERVICE HAS STOPPED.

    It sends the control code and reports the transition, so deleting straight
    afterwards deletes a service that is still running -- which Windows records
    as "marked for deletion" rather than performing. The service stays present
    until its last handle closes, and the next install fails with a message
    that reads like a corrupt system.

    Measured in the sandbox: uninstall reported success and the service was
    still RUNNING afterwards.
    """
    calls, scripted, query_text = sc_calls
    query_text["text"] = "STATE : 3 STOP_PENDING"

    # Flip to STOPPED after a couple of polls, the way a real service does.
    polls = {"n": 0}
    real_sc = integration._sc

    def _counting_sc(*args):
        if args and args[0] == "query":
            polls["n"] += 1
            if polls["n"] >= 3:
                query_text["text"] = "STATE : 1 STOPPED"
        return real_sc(*args)

    monkeypatch.setattr(integration, "_sc", _counting_sc)
    monkeypatch.setattr(integration, "_STOP_TIMEOUT_S", 5)

    ok, detail = integration.unregister_service()

    assert ok, detail
    verbs = [c[1] for c in calls if c[0] == "sc"]
    assert "query" in verbs, "must confirm the stop before deleting"
    assert verbs.index("query") < verbs.index("delete")


def test_a_service_that_will_not_stop_is_still_deleted(sc_calls, monkeypatch):
    """Marked for deletion beats left registered and running."""
    calls, scripted, query_text = sc_calls
    query_text["text"] = "STATE : 3 STOP_PENDING"        # never stops
    monkeypatch.setattr(integration, "_STOP_TIMEOUT_S", 1)

    ok, detail = integration.unregister_service()

    assert ok, detail
    assert ["sc", "delete", integration.SERVICE_NAME] in calls


# == Windowless processes need an explicit stdin ==============================

def test_sc_is_never_given_an_inherited_stdin(monkeypatch):
    """The bug that made an uninstall report success while nothing happened.

    An uninstaller runs the exe with runhidden, so the process has no console
    and its standard handles are invalid. capture_output covers stdout and
    stderr; stdin stays inherited, and sc.exe then fails with
    "[WinError 6] The handle is invalid" before doing any work.

    Observed in the sandbox: the service step reported exactly that error while
    the context-menu step -- which uses winreg directly and spawns nothing --
    succeeded.
    """
    seen = {}

    class _R:
        returncode = 0
        stdout = "STOPPED"
        stderr = ""

    def _fake_run(cmd, **kwargs):
        seen.update(kwargs)
        return _R()

    monkeypatch.setattr(subprocess, "run", _fake_run)

    integration._sc("query", "AnyService")

    assert seen.get("stdin") is subprocess.DEVNULL, (
        "sc must not inherit stdin; a windowless caller has no valid handle")


def test_schtasks_is_never_given_an_inherited_stdin(monkeypatch):
    """Same failure, and it is why an uninstall skipped the scheduled task:
    get_task_info() reported no task for one that existed."""
    from ui.core import scheduler

    seen = {}

    class _R:
        returncode = 1
        stdout = ""
        stderr = ""

    monkeypatch.setattr(subprocess, "run",
                        lambda cmd, **kw: (seen.update(kw), _R())[1])

    scheduler.get_task_info()

    assert seen.get("stdin") is subprocess.DEVNULL
