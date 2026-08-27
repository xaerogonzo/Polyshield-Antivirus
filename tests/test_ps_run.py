"""
The PowerShell runner's contract — asserted against every copy of it.

`_run_ps` exists in this shape for a reason that cost a debugging session:
`subprocess.run(capture_output=True)` can block forever when a WMI child
process keeps the stdout pipe handle open after `proc.kill()`, which is how the
Defender and Windows Security views used to hang the whole app. The current
Popen + drain-after-kill form is the fix, and nothing pinned it.

It was written against the two duplicated copies first, and every assertion
below passed against both before either was touched. That is what made the
extraction into `ui.core.ps_run` safe to do at all: the same suite, unchanged,
now runs against the shared implementation and against both wrappers that reach
it, so "the refactor preserved behaviour" is a checked claim rather than an
assurance.

Nothing here executes PowerShell — the `subprocess` reference is swapped for a
shim, so the tests are identical on a developer's machine and on a runner.
"""
from __future__ import annotations

import subprocess
import types

import pytest

from ui.core import defender, ps_run, win_security


def _shared(command, timeout=20):
    """The shared runner, reached under the wrappers' calling convention."""
    return ps_run.run_ps(command, timeout)


# Every entry point that reaches the runner. The two wrappers are listed
# alongside the shared implementation on purpose: this suite was written
# against the two duplicated copies *before* they were merged, and re-run
# unchanged afterwards. Testing only ps_run would prove the implementation is
# right without proving either caller still reaches it the same way.
_OWNERS = [
    pytest.param(defender, id="defender"),
    pytest.param(win_security, id="win_security"),
    pytest.param(types.SimpleNamespace(_run_ps=_shared), id="shared"),
]


class _FakePopen:
    """Records what the runner did to it, and fails on cue.

    `effects` is consumed one entry per communicate() call: a tuple is
    returned, an exception is raised. That is enough to model the ordinary
    path, a timeout, and a timeout whose drain also times out.
    """

    def __init__(self, effects, returncode=0):
        self._effects = list(effects)
        self.returncode = returncode
        self.kill_calls = 0
        self.communicate_timeouts: list = []

    def communicate(self, timeout=None):
        self.communicate_timeouts.append(timeout)
        effect = self._effects.pop(0)
        if isinstance(effect, BaseException):
            raise effect
        return effect

    def kill(self):
        self.kill_calls += 1


class _FakeSubprocess:
    """The subprocess module with Popen swapped for a factory.

    __getattr__ falls through to the real module so CREATE_NO_WINDOW, PIPE,
    DEVNULL and TimeoutExpired keep their real values -- the runner catches
    subprocess.TimeoutExpired by identity, so a stand-in class would not be
    caught at all and the test would prove nothing.
    """

    def __init__(self, proc=None, popen_raises=None):
        self._proc = proc
        self._popen_raises = popen_raises
        self.popen_calls: list[tuple] = []

    def Popen(self, argv, **kwargs):
        self.popen_calls.append((argv, kwargs))
        if self._popen_raises is not None:
            raise self._popen_raises
        return self._proc

    def __getattr__(self, name):
        return getattr(subprocess, name)


def _install(monkeypatch, module, **kwargs):
    """Install the fake subprocess wherever the Popen actually happens.

    Before the extraction that was each module's own namespace; afterwards it
    is ps_run's. Patching both keeps every test below identical across that
    change, which is precisely what makes this suite usable as the proof that
    the extraction preserved behaviour.
    """
    shim = _FakeSubprocess(**kwargs)
    monkeypatch.setattr(ps_run, "subprocess", shim, raising=False)
    monkeypatch.setattr(module, "subprocess", shim, raising=False)
    return shim


# -- The ordinary paths -------------------------------------------------------

@pytest.mark.parametrize("module", _OWNERS)
def test_a_clean_run_returns_its_output(monkeypatch, module):
    _install(monkeypatch, module, proc=_FakePopen([("  hello  ", None)]))

    assert module._run_ps("Get-Thing") == (True, "hello")


@pytest.mark.parametrize("module", _OWNERS)
def test_a_non_zero_exit_is_a_failure_that_still_carries_its_output(
        monkeypatch, module):
    """The output is not discarded on failure -- callers log it."""
    _install(monkeypatch, module,
             proc=_FakePopen([("partial output", None)], returncode=1))

    assert module._run_ps("Get-Thing") == (False, "partial output")


@pytest.mark.parametrize("module", _OWNERS)
def test_empty_output_is_not_confused_with_failure(monkeypatch, module):
    _install(monkeypatch, module, proc=_FakePopen([("", None)]))

    assert module._run_ps("Get-Thing") == (True, "")


@pytest.mark.parametrize("module", _OWNERS)
def test_output_is_stripped_of_surrounding_whitespace(monkeypatch, module):
    _install(monkeypatch, module, proc=_FakePopen([("\r\n  value \r\n", None)]))

    assert module._run_ps("Get-Thing")[1] == "value"


@pytest.mark.parametrize("module", _OWNERS)
def test_non_ascii_output_survives_intact(monkeypatch, module):
    """Pinned as it stands: text=True with no explicit encoding.

    Decoding therefore uses the platform default rather than UTF-8. Whatever
    the runner is handed as str is returned as str; a *decode failure* happens
    inside communicate() and is covered by the exception case below. Changing
    the encoding would be a behaviour change, not a test concern.
    """
    _install(monkeypatch, module, proc=_FakePopen([("Ünïcödé — ok", None)]))

    assert module._run_ps("Get-Thing") == (True, "Ünïcödé — ok")


# -- stderr is discarded, deliberately ---------------------------------------

@pytest.mark.parametrize("module", _OWNERS)
def test_stderr_is_discarded_rather_than_captured(monkeypatch, module):
    """Pinned, because it explains an otherwise puzzling caller experience.

    stderr goes to DEVNULL, so a command that fails with a message on stderr
    and nothing on stdout reaches the caller as (False, "") -- a bare failure
    with no explanation. Capturing stderr would be an improvement and is also a
    behaviour change; this records the contract as it is.
    """
    shim = _install(monkeypatch, module,
                    proc=_FakePopen([("", None)], returncode=1))

    assert module._run_ps("Write-Error boom") == (False, "")
    assert shim.popen_calls[0][1]["stderr"] is subprocess.DEVNULL


@pytest.mark.parametrize("module", _OWNERS)
def test_stdin_is_closed_so_a_prompt_cannot_wedge_the_runner(monkeypatch, module):
    shim = _install(monkeypatch, module, proc=_FakePopen([("", None)]))

    module._run_ps("Get-Thing")

    assert shim.popen_calls[0][1]["stdin"] is subprocess.DEVNULL


@pytest.mark.parametrize("module", _OWNERS)
def test_no_console_window_is_created(monkeypatch, module):
    """The project-wide rule: every subprocess suppresses the console flash."""
    shim = _install(monkeypatch, module, proc=_FakePopen([("", None)]))

    module._run_ps("Get-Thing")

    flags = shim.popen_calls[0][1]["creationflags"]
    assert flags & subprocess.CREATE_NO_WINDOW


@pytest.mark.parametrize("module", _OWNERS)
def test_powershell_is_invoked_without_a_profile_or_a_prompt(monkeypatch, module):
    """A user profile or an execution-policy prompt would hang a headless run."""
    shim = _install(monkeypatch, module, proc=_FakePopen([("", None)]))

    module._run_ps("Get-Thing")

    argv = shim.popen_calls[0][0]
    assert argv[0] == "powershell"
    for flag in ("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass"):
        assert flag in argv
    assert argv[-2:] == ["-Command", "Get-Thing"]


# -- Failure to start ---------------------------------------------------------

@pytest.mark.parametrize("module", _OWNERS)
def test_a_process_that_will_not_start_is_reported_not_raised(monkeypatch, module):
    """Callers treat this as data; an exception here would kill a view thread."""
    _install(monkeypatch, module, popen_raises=FileNotFoundError("no powershell"))

    ok, output = module._run_ps("Get-Thing")

    assert ok is False
    assert "no powershell" in output


# -- The timeout path, which is the whole reason for this shape ---------------

@pytest.mark.parametrize("module", _OWNERS)
def test_a_timeout_kills_the_process_and_reports_it(monkeypatch, module):
    proc = _FakePopen([subprocess.TimeoutExpired("powershell", 20), ("", None)])
    _install(monkeypatch, module, proc=proc)

    ok, output = module._run_ps("Start-Sleep 60", timeout=20)

    assert ok is False
    assert output.endswith("timed out after 20s")
    assert proc.kill_calls == 1, "a timed-out process must be killed"


@pytest.mark.parametrize("module", _OWNERS)
def test_the_drain_after_kill_is_bounded(monkeypatch, module):
    """An unbounded second communicate() would be the original hang again."""
    proc = _FakePopen([subprocess.TimeoutExpired("powershell", 20), ("", None)])
    _install(monkeypatch, module, proc=proc)

    module._run_ps("Start-Sleep 60", timeout=20)

    assert proc.communicate_timeouts == [20, 3], (
        "the drain after kill must have its own short bound")


@pytest.mark.parametrize("module", _OWNERS)
def test_a_child_still_holding_the_pipe_does_not_hang_the_caller(
        monkeypatch, module):
    """The v1.5 regression, stated directly.

    A WMI child can keep the stdout handle open after the parent is killed, so
    even the drain times out. The caller must still get an answer -- reaching
    the assertion at all is the property under test.
    """
    proc = _FakePopen([
        subprocess.TimeoutExpired("powershell", 20),   # the run itself
        subprocess.TimeoutExpired("powershell", 3),    # and the drain
    ])
    _install(monkeypatch, module, proc=proc)

    ok, output = module._run_ps("Get-WmiObject Win32_Thing", timeout=20)

    assert ok is False
    assert output.endswith("timed out after 20s")
    assert proc.kill_calls == 1


@pytest.mark.parametrize("module", _OWNERS)
def test_the_default_timeout_is_twenty_seconds(monkeypatch, module):
    proc = _FakePopen([subprocess.TimeoutExpired("powershell", 20), ("", None)])
    _install(monkeypatch, module, proc=proc)

    _ok, output = module._run_ps("Get-Thing")

    assert output.endswith("timed out after 20s")


@pytest.mark.parametrize("module", _OWNERS)
def test_a_decode_failure_is_reported_rather_than_raised(monkeypatch, module):
    """text=True decodes inside communicate(), so this is where it surfaces."""
    _install(monkeypatch, module, proc=_FakePopen([
        UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")]))

    ok, output = module._run_ps("Get-Thing")

    assert ok is False
    assert output != ""
