"""
Cross-engine process pause/resume helper.

`suspend_pid` and `resume_pid` moved to ``polybedrock.proc_control`` (PolyScour's
Game Mode is the second consumer ADR 0003 was waiting for). They are re-exported
here rather than the whole module being aliased, because `watch_pause_event`
**stayed**: it is this application's scan-pause convention, its only caller is
`clamav_engine`, and moving it would have been the speculative shared API the
extraction gate exists to refuse.

The re-export is by name on purpose. `test_scan_control.py` does::

    monkeypatch.setattr(proc_pause, "suspend_pid", fake)

and expects `_watch` below to call the fake. `_watch` resolves `suspend_pid`
from this module's globals at call time, so patching the name here is what it
reads — which is exactly what a `from ... import` binding gives. An aliased
module (the `ps_run` pattern) would also work, but only by moving
`watch_pause_event` out with it.

For Python-loop engines (Guardian AI, YARA), pause is implemented in the
engine's per-file loop via `pause_event.wait()` — no PID involvement needed.

Convention for pause_event:
    pause_event.is_set()  → engine running (default state after Event())
    pause_event.clear()   → engine paused (loops/subprocess will block)
    pause_event.set()     → engine resumed
"""

import subprocess
import threading
import time

from polybedrock.proc_control import resume_pid, suspend_pid  # noqa: F401


def watch_pause_event(
    proc: subprocess.Popen,
    pause_event: threading.Event,
    poll_interval: float = 0.1,
) -> None:
    """
    Spawn a daemon thread that suspends/resumes *proc* in sync with *pause_event*.

    The thread polls the event every *poll_interval* seconds; when the event
    state changes, it issues NtSuspendProcess or NtResumeProcess on proc.pid.
    Exits cleanly once proc.poll() is not None (i.e. the subprocess has
    terminated) and always re-resumes the process on exit, so a cancelled-while-
    paused proc can still receive TerminateProcess.

    Safe to call even if pause_event is None — does nothing in that case.
    """
    if pause_event is None or proc is None:
        return

    def _watch():
        suspended = False
        try:
            while proc.poll() is None:
                want_paused = not pause_event.is_set()
                if want_paused and not suspended:
                    suspend_pid(proc.pid)
                    suspended = True
                elif not want_paused and suspended:
                    resume_pid(proc.pid)
                    suspended = False
                time.sleep(poll_interval)
        finally:
            # Always resume on exit so TerminateProcess / cleanup can proceed
            if suspended:
                resume_pid(proc.pid)

    threading.Thread(target=_watch, daemon=True).start()
