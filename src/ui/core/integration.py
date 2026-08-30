r"""
integration.py — the machine-level state PolyShield creates outside its own files.

Three things outlive the process and survive a reboot:

    Windows service     PolyShieldService, registered with the SCM
    Explorer verb       HKCU\Software\Classes\*\shell\PolyShield
    Scheduled task      PolyShield_ScheduledScan

Installing creates them, uninstalling must remove exactly them, and a *failed*
install has to be able to get back to the state of one that never ran. That
last case is why this module exists rather than the steps living inside the
installer script: docs/ARCHITECTURE.md records that a run which registers the
service and then fails elsewhere leaves the registration behind, and that
repeated attempts accumulate dirty service and context-menu state.

Every operation is **idempotent**. "It was not there" is success, because a
rollback runs after an unknown amount of the install has happened, and an
uninstaller that fails because something was already absent is an uninstaller
people learn to skip.

Nothing here removes user data. The threat database, quarantine, logs and
settings live under paths.app_root() and outlive an uninstall unless the user
asks otherwise -- quarantine in particular may hold the only copy of a file
somebody wants back.

Requires elevation for the service step. The other two do not: the Explorer
verb is per-user in HKCU, and schtasks deletes a task the same account created.
"""
from __future__ import annotations

import subprocess
import time

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

SERVICE_NAME = "PolyShieldService"

#: `sc` exit codes that mean "already in the state we wanted".
_SC_SERVICE_ABSENT = 1060      # the specified service does not exist
_SC_NOT_STARTED = 1062         # the service has not been started

#: How long to wait for a stop to actually take effect before deleting anyway.
#: Deleting is still attempted on timeout: a service that will not stop is
#: better marked for deletion than left registered and running.
_STOP_TIMEOUT_S = 30


def _sc(*args: str) -> tuple[int, str]:
    try:
        r = subprocess.run(["sc", *args], capture_output=True, text=True,
                           timeout=30, creationflags=_NO_WINDOW,
                           # DEVNULL, not inherited. An uninstaller runs this
                           # exe with runhidden, so the process has NO CONSOLE
                           # and its standard handles are invalid -- sc.exe then
                           # fails with "[WinError 6] The handle is invalid"
                           # before doing anything. capture_output covers stdout
                           # and stderr; stdin is the one left inherited.
                           #
                           # Measured: an uninstall reported the service removed
                           # while it was still RUNNING, and the report said
                           # WinError 6.
                           stdin=subprocess.DEVNULL)
        return r.returncode, (r.stdout + r.stderr).strip()
    except Exception as exc:                      # sc missing, timeout, denied
        return -1, str(exc)


def unregister_service() -> tuple[bool, str]:
    """Stop and delete the Windows service. Absent is success.

    Stopped first because deleting a running service only marks it for deletion
    -- it lingers until the last handle closes, and a reinstall then fails with
    "the specified service has been marked for deletion", which reads as a
    corrupt system rather than as a step that needs a reboot.
    """
    code, out = _sc("stop", SERVICE_NAME)
    if code not in (0, _SC_SERVICE_ABSENT, _SC_NOT_STARTED):
        # Not fatal: a service that will not stop can still be deleted, and
        # reporting the delete result is more useful than stopping here.
        pass

    # `sc stop` RETURNS BEFORE THE SERVICE HAS STOPPED. It sends the control
    # code and reports the transition, so deleting immediately after it deletes
    # a service that is still running -- which Windows records as "marked for
    # deletion" rather than performing, leaving the service present until its
    # last handle closes. Measured in the sandbox: uninstall reported success
    # and the service was still RUNNING afterwards.
    deadline = time.monotonic() + _STOP_TIMEOUT_S
    while time.monotonic() < deadline:
        code, out = _sc("query", SERVICE_NAME)
        if code == _SC_SERVICE_ABSENT or "STOPPED" in out:
            break
        time.sleep(0.5)

    code, out = _sc("delete", SERVICE_NAME)
    if code == 0:
        return True, f"{SERVICE_NAME} removed"
    if code == _SC_SERVICE_ABSENT:
        return True, f"{SERVICE_NAME} was not registered"
    return False, f"could not delete {SERVICE_NAME}: {out or code}"


def unregister_context_menu() -> tuple[bool, str]:
    """Remove the Explorer verb. Already-absent is success."""
    from ui.core import shell_ext

    return shell_ext.unregister()


def unregister_scheduled_task() -> tuple[bool, str]:
    """Remove the scheduled scan. Already-absent is success.

    schtasks exits non-zero for a task that does not exist, which is the normal
    case for anyone who never opened the Scheduler view -- so absence is
    resolved by asking first rather than by parsing the failure text, which is
    localised.
    """
    from ui.core import scheduler

    if not scheduler.get_task_info().get("exists"):
        return True, "no scheduled task was registered"
    ok, out = scheduler.delete_task()
    return (True, "scheduled task removed") if ok else (False, out)


#: Ordered: the service first, because it is the one holding handles and the
#: one that needs elevation. If the caller is not elevated it fails there and
#: the other two still run, which is the useful outcome for a partial rollback.
#:
#: Names, not function objects. Binding the functions here would capture them
#: at import, so a caller -- or a test -- that substitutes one would be ignored
#: while appearing to succeed, and the substitution would silently run the real
#: thing against the real machine.
_STEPS = (
    ("service", "unregister_service"),
    ("context menu", "unregister_context_menu"),
    ("scheduled task", "unregister_scheduled_task"),
)


def unregister_all(log=None) -> dict:
    """Remove every machine-level integration. Returns a per-step report.

    Every step is attempted even when an earlier one fails: they are
    independent, and a rollback that stops at the first problem leaves more
    behind than one that keeps going. The caller decides what a partial result
    means -- an uninstaller reports it, an installer rollback retries.
    """
    report = {"ok": True, "steps": {}}
    for name, attr in _STEPS:
        try:
            ok, detail = globals()[attr]()
        except Exception as exc:                  # a step must not abort the rest
            ok, detail = False, f"raised: {exc!r}"
        report["steps"][name] = {"ok": ok, "detail": detail}
        report["ok"] = report["ok"] and ok
        if log:
            log(f"[{'OK  ' if ok else 'FAIL'}] {name}: {detail}")
    return report
