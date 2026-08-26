"""
Scan control: ScanController's state machine, and the pause/resume helper the
subprocess engines share.

The defect this file was written for: run_scan() returns a controller
immediately but pre-counts files before Popen -- minutes on a Full scan of the
home directory. For that entire window _proc was None, so pause() and cancel()
returned early and threw the user's intent away. _run() never consulted
_cancelled either, so k2.exe was launched *after* the user pressed Stop.

Two guarantees are NOT the same and the tests keep them apart:

  * Cancel before the launch decision  -> k2 is never spawned. Real guarantee.
  * Cancel racing Popen()              -> the process may be created; _attach()
                                          must kill it immediately. There is no
                                          way to prevent the spawn without
                                          CREATE_SUSPENDED, so no test here
                                          claims otherwise.

Likewise a pending pause is applied *at attach*: the process is created and
then suspended, not created suspended.

Nothing here touches ntdll. _os_suspend/_os_resume are module-level seams and
the fake process only needs .pid and .kill(), which is the same shape as the
stand-in controller in test_scan_pipeline.py.
"""
from __future__ import annotations

import threading
import time

import pytest

from ui.core import proc_pause, scanner


class FakeProc:
    """The surface ScanController actually uses."""

    def __init__(self, pid: int = 4242):
        self.pid = pid
        self.killed = False
        self._returncode = None

    def kill(self):
        self.killed = True
        self._returncode = -9

    def poll(self):
        return self._returncode


@pytest.fixture
def suspend_calls(monkeypatch):
    """Record NtSuspendProcess/NtResumeProcess intent without issuing it."""
    calls: list[tuple[str, int]] = []
    monkeypatch.setattr(scanner, "_os_suspend", lambda pid: calls.append(("suspend", pid)))
    monkeypatch.setattr(scanner, "_os_resume", lambda pid: calls.append(("resume", pid)))
    return calls


# ── Attached state machine ────────────────────────────────────────────────────

def test_pause_then_resume_suspends_and_resumes(suspend_calls):
    ctrl = scanner.ScanController()
    ctrl._attach(FakeProc())

    ctrl.pause()
    assert ctrl.paused and suspend_calls == [("suspend", 4242)]

    ctrl.resume()
    assert not ctrl.paused and suspend_calls[-1] == ("resume", 4242)


def test_pausing_twice_suspends_once(suspend_calls):
    ctrl = scanner.ScanController()
    ctrl._attach(FakeProc())

    ctrl.pause()
    ctrl.pause()

    assert suspend_calls.count(("suspend", 4242)) == 1


def test_resume_without_a_pause_does_nothing(suspend_calls):
    ctrl = scanner.ScanController()
    ctrl._attach(FakeProc())

    ctrl.resume()

    assert suspend_calls == []


def test_toggle_alternates(suspend_calls):
    ctrl = scanner.ScanController()
    ctrl._attach(FakeProc())

    ctrl.toggle_pause()
    assert ctrl.paused
    ctrl.toggle_pause()
    assert not ctrl.paused

    assert [c[0] for c in suspend_calls] == ["suspend", "resume"]


def test_cancel_resumes_before_killing(suspend_calls):
    """Order is load-bearing on Windows: TerminateProcess is ignored by a
    suspended process, so a paused scan that is cancelled without a resume
    first would never actually die."""
    ctrl = scanner.ScanController()
    proc = FakeProc()
    ctrl._attach(proc)
    ctrl.pause()

    ctrl.cancel()

    assert [c[0] for c in suspend_calls] == ["suspend", "resume"]
    assert proc.killed and ctrl.cancelled and not ctrl.paused


def test_pause_after_cancel_is_ignored(suspend_calls):
    ctrl = scanner.ScanController()
    ctrl._attach(FakeProc())
    ctrl.cancel()
    suspend_calls.clear()

    ctrl.pause()

    assert suspend_calls == [] and not ctrl.paused


# ── Intent recorded before the process exists ─────────────────────────────────

def test_pause_before_attach_is_applied_on_arrival(suspend_calls):
    """The pre-count window. Before v1.13 this pause was silently dropped and
    k2 ran unpaused while the UI showed a PAUSED badge."""
    ctrl = scanner.ScanController()

    ctrl.pause()
    assert ctrl.paused, "intent must be recorded even with no process yet"
    assert suspend_calls == [], "nothing to suspend yet"

    assert ctrl._attach(FakeProc()) is True
    assert suspend_calls == [("suspend", 4242)]


def test_resume_before_attach_clears_the_pending_pause(suspend_calls):
    ctrl = scanner.ScanController()
    ctrl.pause()
    ctrl.resume()

    ctrl._attach(FakeProc())

    assert not ctrl.paused
    assert suspend_calls == [], "a withdrawn pause must not be applied at attach"


def test_cancel_before_attach_kills_on_arrival(suspend_calls):
    ctrl = scanner.ScanController()
    ctrl.cancel()

    proc = FakeProc()
    assert ctrl._attach(proc) is False, "_run() must be told not to proceed"
    assert proc.killed


def test_cancel_outranks_a_pending_pause(suspend_calls):
    """Both recorded before the process exists. Suspending a process we are
    about to kill would leave it alive and unkillable."""
    ctrl = scanner.ScanController()
    ctrl.pause()
    ctrl.cancel()

    proc = FakeProc()
    assert ctrl._attach(proc) is False
    assert proc.killed
    assert not ctrl.paused
    assert ("suspend", 4242) not in suspend_calls


# ── run_scan launch guards ────────────────────────────────────────────────────

@pytest.fixture
def gated_precount(monkeypatch):
    """Hold _run() inside the pre-count so the test can act mid-window.

    Deterministic by construction -- no sleeps, no hoping to win a race.
    """
    gate = threading.Event()
    monkeypatch.setattr(scanner, "count_files",
                        lambda paths: (gate.wait(5), 0)[1])
    return gate


def test_cancel_during_the_precount_never_launches_k2(gated_precount, monkeypatch):
    """Case 1: cancellation lands before the launch decision. This one is a
    real guarantee and is worth asserting as an absolute."""
    spawned = []
    monkeypatch.setattr(scanner.subprocess, "Popen",
                        lambda *a, **kw: spawned.append(a) or FakeProc())

    done = threading.Event()
    result = {}

    def on_done(rc, rp):
        result["rc"] = rc
        done.set()

    ctrl = scanner.run_scan(["C:\\nowhere"], "report_only",
                            lambda line: None, lambda *a: None, on_done)

    ctrl.cancel()                 # user presses Stop during "Counting files..."
    gated_precount.set()

    assert done.wait(5), "done_callback never fired"
    assert spawned == [], "k2.exe was launched after the scan was cancelled"
    assert result["rc"] == -1


def test_cancel_racing_popen_kills_the_process_it_created(gated_precount,
                                                          monkeypatch):
    """Case 2: the cancel lands between the check and the call.

    Deliberately NOT asserting that no process is created -- a check before
    Popen cannot prevent that interleaving. What must hold is that the process
    is killed on attach and the scan does not proceed.
    """
    holder: dict = {}
    created: list[FakeProc] = []

    def racing_popen(*a, **kw):
        holder["ctrl"].cancel()   # lands after _run()'s cancelled check
        proc = FakeProc()
        created.append(proc)
        return proc

    monkeypatch.setattr(scanner.subprocess, "Popen", racing_popen)

    done = threading.Event()
    result = {}

    def on_done(rc, rp):
        result["rc"] = rc
        done.set()

    ctrl = scanner.run_scan(["C:\\nowhere"], "report_only",
                            lambda line: None, lambda *a: None, on_done)
    holder["ctrl"] = ctrl
    gated_precount.set()

    assert done.wait(5), "done_callback never fired"
    assert len(created) == 1, "this test is only meaningful if Popen did run"
    assert created[0].killed, "the racing process was left running"
    assert result["rc"] == -1


# ── proc_pause.watch_pause_event ──────────────────────────────────────────────

@pytest.fixture
def pid_calls(monkeypatch):
    calls: list[tuple[str, int]] = []
    monkeypatch.setattr(proc_pause, "suspend_pid",
                        lambda pid: calls.append(("suspend", pid)) or True)
    monkeypatch.setattr(proc_pause, "resume_pid",
                        lambda pid: calls.append(("resume", pid)) or True)
    return calls


def _wait_for(predicate, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


def test_watch_pause_event_tracks_the_event(pid_calls):
    proc = FakeProc(pid=99)
    event = threading.Event()
    event.set()                                  # set == running

    proc_pause.watch_pause_event(proc, event, poll_interval=0.01)

    event.clear()                                # paused
    assert _wait_for(lambda: ("suspend", 99) in pid_calls)

    event.set()                                  # resumed
    assert _wait_for(lambda: ("resume", 99) in pid_calls)

    proc.kill()                                  # ends the watch loop
    assert _wait_for(lambda: proc.poll() is not None)


def test_watch_pause_event_always_resumes_on_exit(pid_calls):
    """A process that dies while suspended must still be resumed, or the
    cleanup path cannot terminate it."""
    proc = FakeProc(pid=7)
    event = threading.Event()
    event.set()

    proc_pause.watch_pause_event(proc, event, poll_interval=0.01)

    event.clear()
    assert _wait_for(lambda: ("suspend", 7) in pid_calls)

    proc._returncode = 0                         # process exits while suspended

    assert _wait_for(lambda: ("resume", 7) in pid_calls), (
        "the watcher exited leaving the process suspended")


def test_watch_pause_event_is_a_no_op_without_an_event(pid_calls):
    before = threading.active_count()

    proc_pause.watch_pause_event(FakeProc(), None)
    proc_pause.watch_pause_event(None, threading.Event())

    assert pid_calls == []
    assert threading.active_count() == before, "spawned a thread with nothing to watch"
