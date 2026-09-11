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


#: Every module `unregister_all` reaches HKCU through.  A step added to
#: `_STEPS` without its module added here would run against the developer's
#: live hive in every test in this file -- see _never_touch_the_real_hive.
_HKCU_MODULES = ("ui.core.shell_ext", "ui.core.autostart", "ui.core.dev_install")


@pytest.fixture(autouse=True)
def _never_touch_the_real_hive(monkeypatch):
    """The HKCU-touching modules talk to winreg directly, not through subprocess.

    Learned the hard way: a test here stubbed subprocess, assumed that covered
    every step, and unregister_context_menu went straight to the live HKCU and
    deleted the user real Explorer verb. Autouse so a future test cannot
    reintroduce that by forgetting.

    Every module in _HKCU_MODULES shares ONE fake hive, because they share one
    real one: a test that registers through one and tears down through another
    has to see the same tree, and giving each its own would let a teardown
    "succeed" against a hive nothing was ever written to.
    """
    import importlib

    class _FakeWinreg:
        HKEY_CURRENT_USER = "HKCU"
        REG_SZ = 1
        REG_DWORD = 4
        REG_BINARY = 3

        def __init__(self):
            self.tree = {}

        def CreateKey(self, hive, sub):
            self.tree.setdefault((hive, sub), {})
            return _Key(self, hive, sub)

        def OpenKey(self, hive, sub, *a, **k):
            if (hive, sub) not in self.tree:
                raise FileNotFoundError(2, "not found")
            return _Key(self, hive, sub)

        def SetValueEx(self, key, name, _r, typ, data):
            self.tree[(key.hive, key.sub)][name] = (data, typ)

        def QueryValueEx(self, key, name):
            try:
                return self.tree[(key.hive, key.sub)][name]
            except KeyError:
                raise FileNotFoundError(2, "not found") from None

        def DeleteValue(self, key, name):
            try:
                del self.tree[(key.hive, key.sub)][name]
            except KeyError:
                raise FileNotFoundError(2, "not found") from None

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
    for name in _HKCU_MODULES:
        try:
            mod = importlib.import_module(name)
        except ImportError:
            continue        # not written yet; the guard below is what enforces it
        monkeypatch.setattr(mod, "winreg", fake, raising=False)
    return fake


def test_every_hkcu_teardown_step_is_covered_by_the_fake_hive():
    """The guard on the guard.

    _STEPS growing an HKCU step whose module is not in _HKCU_MODULES would not
    fail loudly -- it would quietly run against the developer's live registry in
    every test in this file. So the list is asserted, not trusted.
    """
    import importlib
    import inspect

    for _label, attr in integration._STEPS:
        src = inspect.getsource(getattr(integration, attr))
        for line in src.splitlines():
            line = line.strip()
            if not line.startswith("from ui.core import "):
                continue
            mod_name = "ui.core." + line.split("import ", 1)[1].split()[0]
            try:
                mod = importlib.import_module(mod_name)
            except ImportError:
                continue
            if hasattr(mod, "winreg"):
                assert mod_name in _HKCU_MODULES, (
                    f"{attr} reaches HKCU through {mod_name}, which "
                    "_never_touch_the_real_hive does not stub")


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
    """Every non-service step, stubbed to succeed.

    Derived from _STEPS rather than listed, so a new step is stubbed the moment
    it is added instead of quietly executing for real in tests that only meant
    to exercise the service branch.
    """
    for _label, attr in integration._STEPS:
        if attr == "unregister_service":
            continue
        monkeypatch.setattr(integration, attr,
                            lambda a=attr: (True, f"{a} stubbed"))


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
    # A literal set, not `set(integration._STEPS)`. Deriving it would make this
    # assertion agree with whatever the code says, including a step silently
    # dropped -- and the report shape is what an uninstaller and a rollback both
    # read to decide whether they are finished.
    assert set(report["steps"]) == {
        "service", "context menu", "startup entry", "scheduled task",
        "uninstall entry"}


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


# ══ Rollback and retry ═══════════════════════════════════════════════════════
#
# Idempotence alone is not the property that matters. The one that does is:
#
#     a failed installation never leaves a half-installed machine.
#
# So these inject a failure at each step of a registration in turn, run the same
# unregister_all() the installer's rollback runs, and assert the machine ends up
# where it started -- then that a retry converges on the same result as a clean
# first run.

_REGISTER_ATTRS = [attr for _label, attr, _default in integration._REGISTER_STEPS]


@pytest.fixture
def fake_machine(monkeypatch):
    """A machine whose five integrations are just a set of names.

    Real enough for what is being asserted -- which is ordering, convergence and
    the absence of leftovers, not registry mechanics. Those are pinned against
    the fake hive in test_integration_edges.py.
    """
    state: set[str] = set()

    def register(name):
        def _do():
            state.add(name)
            return True, f"{name} registered"
        return _do

    def unregister(name):
        def _do():
            if name not in state:
                return True, f"no {name} was registered"
            state.discard(name)
            return True, f"{name} removed"
        return _do

    pairs = {
        "register_context_menu":   ("context menu", "unregister_context_menu"),
        "register_startup_entry":  ("startup entry", "unregister_startup_entry"),
        "register_arp_entry":      ("uninstall entry", "unregister_arp_entry"),
    }
    for reg_attr, (name, unreg_attr) in pairs.items():
        monkeypatch.setattr(integration, reg_attr, register(name))
        monkeypatch.setattr(integration, unreg_attr, unregister(name))

    # The two steps with no registration counterpart in register_all().
    monkeypatch.setattr(integration, "unregister_service",
                        lambda: (True, "service removed"))
    monkeypatch.setattr(integration, "unregister_scheduled_task",
                        unregister("scheduled task"))
    return state


def test_a_clean_registration_leaves_exactly_what_was_asked_for(fake_machine):
    report = integration.register_all(startup=True)
    assert report["ok"] is True
    assert fake_machine == {"context menu", "startup entry", "uninstall entry"}


@pytest.mark.parametrize("failing", _REGISTER_ATTRS)
def test_a_failed_registration_rolls_back_to_a_clean_machine(
        fake_machine, monkeypatch, failing):
    """Whichever step breaks, the rollback converges on the same empty machine.

    Parametrised over the step rather than written once, because the interesting
    cases are the LATER failures: those are the ones with earlier registrations
    already on disk to leave behind.
    """
    monkeypatch.setattr(integration, failing,
                        lambda: (False, "injected failure"))

    report = integration.register_all(startup=True)
    assert report["ok"] is False

    integration.unregister_all()
    assert fake_machine == set(), (
        f"a failure at {failing} left {sorted(fake_machine)} behind")


@pytest.mark.parametrize("failing", _REGISTER_ATTRS)
def test_a_retry_after_a_rollback_matches_a_first_time_success(
        fake_machine, monkeypatch, failing):
    # A transient failure -- a locked hive, a denied write -- rather than
    # monkeypatch.undo(), which would also unwind the fake machine this test is
    # measuring and leave the retry writing to the real one.
    working = getattr(integration, failing)
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        return (False, "injected failure") if calls["n"] == 1 else working()

    monkeypatch.setattr(integration, failing, flaky)
    integration.register_all(startup=True)
    integration.unregister_all()

    report = integration.register_all(startup=True)      # the fault has cleared
    assert report["ok"] is True
    assert fake_machine == {"context menu", "startup entry", "uninstall entry"}


def test_a_step_that_raises_during_registration_is_contained(fake_machine, monkeypatch):
    def boom():
        raise OSError(5, "Access is denied")

    monkeypatch.setattr(integration, "register_context_menu", boom)
    report = integration.register_all(startup=True)
    assert report["ok"] is False
    assert "raised" in report["steps"]["context menu"]["detail"]
    # The later steps still ran: they are independent, and stopping at the first
    # problem leaves more behind than carrying on does.
    assert "uninstall entry" in fake_machine


# ── The idempotence matrix ───────────────────────────────────────────────────


@pytest.mark.parametrize("preexisting", [
    set(),
    {"context menu"},
    {"startup entry"},
    {"uninstall entry"},
    {"scheduled task"},
    {"context menu", "uninstall entry"},
    {"context menu", "startup entry", "uninstall entry", "scheduled task"},
])
def test_uninstall_converges_from_any_partial_state(fake_machine, preexisting):
    """Whatever a previous partial run left, one uninstall finishes the job and
    a second one is still a success.

    A failed uninstall the user cannot simply re-run is a failed uninstall they
    have to fix with regedit.
    """
    fake_machine.update(preexisting)

    first = integration.unregister_all()
    assert first["ok"] is True
    assert fake_machine == set()

    second = integration.unregister_all()
    assert second["ok"] is True
    assert set(second["steps"]) == set(first["steps"])


def test_the_uninstall_entry_is_removed_last(fake_machine):
    """It advertises this uninstall.

    If an earlier step fails, the entry has to still be in Settings > Apps for
    the user to retry from -- so removing it first would strand a
    half-uninstalled product with no visible way to finish.
    """
    order = [name for name, _attr in integration._STEPS]
    assert order[-1] == "uninstall entry"
    assert order[0] == "service", "the elevation-needing step still goes first"
