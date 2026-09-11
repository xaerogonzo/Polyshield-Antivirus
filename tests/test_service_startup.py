r"""How PolyShield registers its service, and why it kept registering it wrong.

`polyshield_service.PolyShieldService._svc_start_type_` is
`win32service.SERVICE_AUTO_START` and has been since the service was written.
It never took effect.  pywin32 does not read that attribute -- measured in the
installed copy at `win32/lib/win32serviceutil.py`:

    :203  def InstallService(..., startType=None, ...)
    :221      if startType is None:
    :222          startType = win32service.SERVICE_DEMAND_START
    :852      InstallService(..., startType=startup, ...)

`startup` is filled only from an explicit `--startup` option.  So every
`polyshield_service.py install` produced a DEMAND_START service, and two of the
three call sites quietly compensated afterwards with `sc config ... start= auto`
while the third -- the in-app Install button -- did not.  A machine running this
project reported START_TYPE 3 with WIN32_EXIT_CODE 1077: registered, and never
once started.

`_with_startup_flag` is the fix, at the single point all three callers funnel
through.  It is pure, so this file can prove the argv shaping without going
anywhere near the SCM.
"""
from __future__ import annotations

import pathlib

import pytest


def _svc():
    # Imported inside the test, not at module scope: the module pulls in
    # servicemanager and opens no handles, but the existing service tests
    # (test_privilege_boundary, test_service_intel) all do it this way and a
    # collection-time import of a Windows service module is the shape that has
    # broken this project's Linux CI before.
    import polyshield_service

    return polyshield_service


# ── Finding the verb ──────────────────────────────────────────────────────────
#
# The verb is not simply argv[1].  getopt consumes options first, and a long
# option may carry its value inline or in the following token, so
# `--username bob install` has its verb in third place.


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["svc.py", "install"],                                 1),
        (["svc.py", "--startup", "auto", "install"],            3),
        (["svc.py", "--startup=auto", "install"],               2),
        (["svc.py", "--username", "bob", "--password", "x",
          "install"],                                           5),
        (["svc.py", "--interactive", "debug"],                  2),
        (["svc.py", "--", "install"],                           2),
        (["svc.py"],                                            None),
        (["svc.py", "--startup", "auto"],                       None),
    ],
)
def test_the_verb_is_found_the_way_getopt_would(argv, expected):
    assert _svc()._find_verb_index(argv) == expected


# ── Injection ─────────────────────────────────────────────────────────────────


def test_install_is_given_startup_auto():
    """The bug, in one assertion."""
    out = _svc()._with_startup_flag(["svc.py", "install"])
    assert out == ["svc.py", "--startup", "auto", "install"]


def test_the_flag_goes_before_the_verb():
    """getopt stops at the first non-option.

    `install --startup auto` parses as the verb `install` with a leftover
    positional, and the option is never seen -- which would reintroduce the bug
    while looking like the fix.
    """
    out = _svc()._with_startup_flag(["svc.py", "install"])
    assert out.index("--startup") < out.index("install")


def test_update_is_also_a_registering_verb():
    out = _svc()._with_startup_flag(["svc.py", "update"])
    assert out == ["svc.py", "--startup", "auto", "update"]


@pytest.mark.parametrize("verb", ["remove", "start", "stop", "restart", "debug"])
def test_a_non_registering_verb_is_left_alone(verb):
    """pywin32 does not consult startType for these, so touching argv would only
    risk turning a working command into a usage error."""
    argv = ["svc.py", verb]
    assert _svc()._with_startup_flag(argv) == argv


@pytest.mark.parametrize(
    "argv",
    [
        ["svc.py", "--startup", "auto", "install"],
        ["svc.py", "--startup", "manual", "install"],
        ["svc.py", "--startup=delayed", "install"],
        # A spelling pywin32 rejects. `sc config` says "delayed-auto"; pywin32
        # says "delayed". Left alone deliberately: rejected loudly by pywin32 is
        # better than silently rewritten here into something the caller did not
        # ask for.
        ["svc.py", "--startup", "delayed-auto", "install"],
    ],
)
def test_an_explicit_startup_is_never_overridden(argv):
    assert _svc()._with_startup_flag(argv) == argv


def test_no_verb_at_all_is_left_alone():
    assert _svc()._with_startup_flag(["svc.py"]) == ["svc.py"]
    assert _svc()._with_startup_flag(["svc.py", "--interactive"]) == \
        ["svc.py", "--interactive"]


def test_delayed_uses_the_pywin32_spelling():
    """Not "delayed-auto" -- that is the `sc config` spelling and pywin32's
    option map does not contain it."""
    out = _svc()._with_startup_flag(["svc.py", "install"], delayed=True)
    assert out == ["svc.py", "--startup", "delayed", "install"]


def test_the_start_type_attribute_is_what_gets_read():
    """`_svc_start_type_` is load-bearing again, through this function."""
    import win32service

    ps = _svc()
    out = ps._with_startup_flag(
        ["svc.py", "install"], start_type=win32service.SERVICE_DEMAND_START)
    assert out == ["svc.py", "--startup", "manual", "install"]

    out = ps._with_startup_flag(
        ["svc.py", "install"], start_type=win32service.SERVICE_DISABLED)
    assert out == ["svc.py", "--startup", "disabled", "install"]


def test_an_unmapped_start_type_injects_nothing():
    """Better a DEMAND_START service the user can see and fix than an argv built
    from a guess."""
    argv = ["svc.py", "install"]
    assert _svc()._with_startup_flag(argv, start_type=0xDEAD) == argv


def test_options_before_the_verb_survive():
    out = _svc()._with_startup_flag(
        ["svc.py", "--username", "bob", "--password", "hunter2", "install"])
    assert out == ["svc.py", "--username", "bob", "--password", "hunter2",
                   "--startup", "auto", "install"]


def test_the_input_argv_is_not_mutated():
    argv = ["svc.py", "install"]
    _svc()._with_startup_flag(argv)
    assert argv == ["svc.py", "install"]


# ── The class still declares what we inject ───────────────────────────────────


def test_the_service_still_asks_for_auto_start():
    """If someone changes `_svc_start_type_` they are now changing behaviour,
    not documentation. This test is here to make that true rather than to
    restate the assignment."""
    import win32service

    assert _svc().PolyShieldService._svc_start_type_ == \
        win32service.SERVICE_AUTO_START
    assert _svc()._STARTUP_FLAG_BY_TYPE[win32service.SERVICE_AUTO_START] == "auto"


# ══ Configuring the service once it exists ═══════════════════════════════════
#
# `--startup auto` covers a fresh registration.  `sc config` covers the upgrade
# path, where an existing DEMAND_START registration survives a reinstall.  The
# failure actions cover the case nobody was covering: a service that dies once
# and stays dead is a protection product that is off without saying so.


def _it():
    from ui.core import integration

    return integration


def test_the_startup_commands_are_config_then_failure():
    cmds = _it().service_startup_commands()
    assert [c[0] for c in cmds] == ["config", "failure"]


def test_sc_wants_its_arguments_as_separate_tokens():
    r"""`reset=` and its value are two argv entries, not one.

    `sc` parses ``reset=`` as a keyword and the next token as its value; writing
    ``reset=86400`` is what it does NOT accept.  Easy to "tidy up" into a bug
    that only shows on a real machine.
    """
    config, failure = _it().service_startup_commands()
    assert config[-2:] == ["start=", "auto"]
    assert "reset=" in failure and failure[failure.index("reset=") + 1] == "86400"
    assert "actions=" in failure
    assert failure[failure.index("actions=") + 1].count("restart/") == 3


def test_delayed_uses_the_sc_spelling_not_the_pywin32_one():
    """`sc config` says ``delayed-auto``; pywin32's ``--startup`` says
    ``delayed``.  Each half of the system must speak its own dialect."""
    config = _it().service_startup_commands(delayed=True)[0]
    assert config[-2:] == ["start=", "delayed-auto"]


def test_configuring_an_absent_service_is_a_failure(monkeypatch):
    """The one function in integration.py where "it was not there" is NOT
    success.

    Every teardown step treats absence as success, because a rollback runs after
    an unknown amount of an install.  This runs immediately after a registration
    the caller believes succeeded, so absence means the registration did not
    happen -- and reporting "ok" would hide exactly the failure it exists to
    catch.
    """
    it = _it()
    monkeypatch.setattr(it, "_sc", lambda *a: (it._SC_SERVICE_ABSENT, ""))
    ok, msg = it.configure_service_startup()
    assert ok is False
    assert "not installed" in msg


def test_a_failing_sc_step_stops_and_names_itself(monkeypatch):
    it = _it()
    seen = []

    def fake_sc(*args):
        seen.append(args[0])
        return (0, "") if args[0] == "config" else (5, "Access is denied.")

    monkeypatch.setattr(it, "_sc", fake_sc)
    ok, msg = it.configure_service_startup()
    assert ok is False and "failure" in msg
    assert seen == ["config", "failure"]


def test_all_steps_succeeding_reports_the_mode(monkeypatch):
    it = _it()
    monkeypatch.setattr(it, "_sc", lambda *a: (0, ""))
    assert it.configure_service_startup() == (
        True, "start= auto, restart-on-failure configured")
    ok, msg = it.configure_service_startup(delayed=True)
    assert ok and "delayed-auto" in msg


# ══ The drift guard ══════════════════════════════════════════════════════════
#
# Three places configure this service and they are written in three languages:
# a batch file, a PowerShell script, and now Python.  Leaving all three in place
# is only defensible if something notices when they stop agreeing.

_ROOT = pathlib.Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("rel", [
    "scripts/service/setup_service.bat",
    "installer/register_service.ps1",
])
def test_the_shell_installers_still_agree_with_the_python_policy(rel):
    it = _it()
    text = (_ROOT / rel).read_text(encoding="utf-8", errors="replace")
    config, failure = it.service_startup_commands()

    assert "start= auto" in text, f"{rel} no longer sets start= auto"
    assert f"reset= {failure[failure.index('reset=') + 1]}" in text, \
        f"{rel} has a different failure-reset window"
    assert failure[failure.index("actions=") + 1] in text, \
        f"{rel} has a different recovery action list"


# ══ service_state: two facts, never one ══════════════════════════════════════


def test_state_reports_start_type_and_state_separately():
    """`auto` + stopped is not "Automatic" and is not "healthy".  Collapsing
    them is how a registered-and-never-started service reads as fine."""
    state = _it().service_state()
    assert set(state) == {"present", "start_type", "state", "exit_code"}


def test_an_unregistered_service_reads_as_absent_on_both_axes(monkeypatch):
    import winreg

    it = _it()

    def boom(*a, **k):
        raise FileNotFoundError(2, "nope")

    monkeypatch.setattr(winreg, "OpenKey", boom)
    state = it.service_state()
    assert state == {"present": False, "start_type": "absent",
                     "state": "absent", "exit_code": 0}


def test_an_unreadable_start_type_degrades_to_unknown(monkeypatch):
    """A status line that lies is worse than one that admits it does not know."""
    import contextlib
    import winreg

    it = _it()

    @contextlib.contextmanager
    def fake_open(*a, **k):
        yield object()

    monkeypatch.setattr(winreg, "OpenKey", fake_open)
    monkeypatch.setattr(winreg, "QueryValueEx",
                        lambda *a: (_ for _ in ()).throw(OSError("denied")))
    monkeypatch.setattr(
        "win32serviceutil.QueryServiceStatus",
        lambda *a: (_ for _ in ()).throw(RuntimeError("no")))
    state = it.service_state()
    assert state["present"] is True
    assert state["start_type"] == "unknown"
    assert state["state"] == "unknown"


def test_never_started_has_its_own_code():
    assert _it().SERVICE_NEVER_STARTED == 1077


# ══ The elevated helper ══════════════════════════════════════════════════════
#
# Moving the helper out of the read-only install directory must not trade it for
# a user-writable file that a privileged process then executes.


def _sv():
    import ui.views.service_view as service_view

    return service_view


def test_the_elevated_script_is_never_written_to_disk(tmp_path, monkeypatch):
    r"""The whole reason this stopped being a `.bat`.

    Between writing an executable file and elevating, any process running as the
    user can replace its contents -- and the user's own account is exactly the
    boundary elevation exists to cross.  A random filename does not close a
    window whose path is handed to the elevating call.
    """
    sv = _sv()
    captured = {}

    def fake_run(argv, **kw):
        captured["argv"] = argv
        # Everything the helper created must be data. If any of it is something
        # Windows would execute, the fix did not work.
        for path in tmp_path.rglob("*"):
            assert path.suffix.lower() not in {".bat", ".cmd", ".ps1", ".vbs",
                                               ".exe", ".psm1"}, path
        raise RuntimeError("stop here; the launch itself is not under test")

    monkeypatch.setattr(sv.tempfile, "mkdtemp",
                        lambda **kw: str(tmp_path / "helper"))
    (tmp_path / "helper").mkdir()
    monkeypatch.setattr(sv.subprocess, "run", fake_run)

    out = {}
    sv._run_elevated([sv._step("x", ["sc.exe", "query", "X"])],
                     done_cb=lambda ok, detail: out.update(ok=ok, detail=detail))

    assert out["ok"] is False                      # the launch was sabotaged
    joined = " ".join(captured["argv"])
    assert "-EncodedCommand" in joined
    assert "RunAs" in joined


def test_the_script_is_recoverable_from_the_encoded_command():
    """Round-trip, so the encoding cannot silently produce a script Windows
    would run as something other than what was written."""
    import base64

    sv = _sv()
    script = sv._build_elevated_script(
        [sv._step("x", ["sc.exe", "query", "PolyShieldService"])],
        pathlib.Path("C:/tmp/r.json"))
    b64 = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    assert base64.b64decode(b64).decode("utf-16-le") == script


def test_a_later_step_cannot_run_after_an_earlier_one_failed():
    sv = _sv()
    script = sv._build_elevated_script(
        [sv._step("first", ["a.exe"]), sv._step("second", ["b.exe"])],
        pathlib.Path("C:/tmp/r.json"))
    # Both calls are guarded on $failed, so the second is unreachable once the
    # first has set it. Without this, an install that succeeded and a config
    # that failed would still be followed by a start, and the UI would report
    # the last command's result as the sequence's.
    assert script.count("if (-not $failed) {") == 2


def test_a_command_that_never_runs_is_not_a_success():
    r"""If the executable cannot be found, PowerShell raises into the error
    stream and never touches $LASTEXITCODE.  Seeding it with 0 -- the obvious
    thing to write -- reports a command that never ran as a step that passed."""
    sv = _sv()
    script = sv._build_elevated_script(
        [sv._step("x", ["a.exe"])], pathlib.Path("C:/tmp/r.json"))
    assert "$global:LASTEXITCODE = -1" in script
    assert "$LASTEXITCODE = 0" not in script


def test_the_generated_script_never_invokes_bare_sc():
    r"""In PowerShell `sc` is an ALIAS FOR Set-Content.

    `& 'sc' 'config' 'PolyShieldService' 'start=' 'auto'` therefore resolves to
    a cmdlet, not to the service controller -- silently, with a plausible exit
    code.  installer/register_service.ps1 writes `& sc.exe` for this reason.
    """
    sv = _sv()
    assert sv._SC_EXE == "sc.exe"
    script = sv._build_elevated_script(
        [sv._step("x", [sv._SC_EXE, "query", "X"])],
        pathlib.Path("C:/tmp/r.json"))
    assert "& 'sc.exe'" in script
    assert "& 'sc'" not in script


def test_single_quotes_in_a_path_cannot_break_out_of_the_literal():
    sv = _sv()
    assert sv._ps_lit("C:/it's here/x.exe") == "'C:/it''s here/x.exe'"


def test_the_install_button_no_longer_names_sys_executable():
    r"""`sys.executable` happens to be right when the GUI runs it and names a
    file that DOES NOT EXIST in a Nuitka build -- the trap paths.py exists to
    remove, sitting in the one code path that registers a Windows service."""
    src = (_ROOT / "src" / "ui" / "views" / "service_view.py").read_text(
        encoding="utf-8")
    assert "sys.executable" not in src
