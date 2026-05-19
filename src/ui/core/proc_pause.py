"""
Cross-engine process pause/resume helper.

Uses Windows NtSuspendProcess / NtResumeProcess via ctypes — the same mechanism
ScanController uses for k2.exe, exposed here so other subprocess engines
(ClamAV, future engines) can share the implementation.

For Python-loop engines (Guardian AI, YARA), pause is implemented in the
engine's per-file loop via `pause_event.wait()` — no PID involvement needed.

Convention for pause_event:
    pause_event.is_set()  → engine running (default state after Event())
    pause_event.clear()   → engine paused (loops/subprocess will block)
    pause_event.set()     → engine resumed
"""

import ctypes
import subprocess
import threading
import time

_PROCESS_SUSPEND_RESUME = 0x0800


def suspend_pid(pid: int) -> bool:
    """Suspend a process by PID via NtSuspendProcess. Returns True on success."""
    try:
        handle = ctypes.windll.kernel32.OpenProcess(
            _PROCESS_SUSPEND_RESUME, False, pid)
        if not handle:
            return False
        try:
            return ctypes.windll.ntdll.NtSuspendProcess(handle) == 0
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    except Exception:
        return False


def resume_pid(pid: int) -> bool:
    """Resume a process by PID via NtResumeProcess. Returns True on success."""
    try:
        handle = ctypes.windll.kernel32.OpenProcess(
            _PROCESS_SUSPEND_RESUME, False, pid)
        if not handle:
            return False
        try:
            return ctypes.windll.ntdll.NtResumeProcess(handle) == 0
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    except Exception:
        return False


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
