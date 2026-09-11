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


# ── Registration side: how the service is configured once it exists ──────────
#
# `sc`, not pywin32, for these two.  pywin32 registers the service but has no
# convenient expression for failure actions -- ChangeServiceConfig2 with
# SERVICE_CONFIG_FAILURE_ACTIONS wants a hand-built struct and SC_MANAGER write
# access -- and `installer/register_service.ps1` already shells out to the same
# two commands.  Two implementations of one policy is the drift this module
# exists to prevent, so there is one, here, returned as data.

#: Recovery policy.  Kept beside the start type because they answer the same
#: question -- "is this service actually going to be running tomorrow?".
_FAILURE_RESET_S = "86400"
_FAILURE_ACTIONS = "restart/60000/restart/60000/restart/60000"


def service_startup_commands(delayed: bool = False) -> list[list[str]]:
    r"""The `sc` commands that make the service start at boot and stay started.

    Returned as data rather than run, because three callers need it in three
    shapes: `configure_service_startup` runs it here, `ServiceView` renders it
    into an elevated shell, and `tests/test_service_startup.py` compares it
    against the literals still hard-coded in `scripts/service/setup_service.bat`
    and `installer/register_service.ps1`.

    `start= auto` is belt to `polyshield_service._with_startup_flag`'s braces:
    the flag covers a fresh registration, this covers an upgrade over an older
    one, where the existing start type survives the reinstall.

    The failure actions are the half `register_service.ps1:119` had and the
    developer script did not.  Its comment is the reason, and it is right: a
    service that dies once and stays dead is a protection product that is off
    without saying so.

    Note the spelling.  `sc config` wants ``delayed-auto``; pywin32's
    ``--startup`` wants ``delayed``.  They are not interchangeable.
    """
    return [
        ["config", SERVICE_NAME, "start=", "delayed-auto" if delayed else "auto"],
        ["failure", SERVICE_NAME, "reset=", _FAILURE_RESET_S,
         "actions=", _FAILURE_ACTIONS],
    ]


def configure_service_startup(delayed: bool = False) -> tuple[bool, str]:
    """Apply :func:`service_startup_commands`. Needs elevation.

    **An absent service is a failure here, not a no-op.**  Every other function
    in this module treats "it was not there" as success, because they are
    teardown and a rollback runs after an unknown amount of an install.  This
    one is the opposite: its only caller runs it immediately after a
    registration it believes succeeded, so absence means the registration did
    not happen and saying "ok" would hide it.  Use :func:`service_state` to
    *ask* whether the service is there.
    """
    for args in service_startup_commands(delayed):
        code, out = _sc(*args)
        if code == _SC_SERVICE_ABSENT:
            return False, f"{SERVICE_NAME} is not installed"
        if code != 0:
            return False, f"sc {args[0]} failed: {out or code}"
    return True, ("start= delayed-auto, restart-on-failure configured" if delayed
                  else "start= auto, restart-on-failure configured")


#: `Start` under HKLM\SYSTEM\CurrentControlSet\Services\<name>.  Read from the
#: registry rather than parsed out of `sc qc` because sc's field labels and value
#: names are localised -- the same reason `unregister_scheduled_task` refuses to
#: read schtasks' failure text.  These numbers are not.
_START_TYPE_NAMES = {0: "boot", 1: "system", 2: "auto", 3: "manual", 4: "disabled"}

#: win32service.SERVICE_* current-state codes, likewise numeric.
_STATE_NAMES = {
    1: "stopped", 2: "start_pending", 3: "stop_pending", 4: "running",
    5: "continue_pending", 6: "pause_pending", 7: "paused",
}

#: ERROR_SERVICE_NEVER_STARTED.  Its own diagnosis: the service is registered,
#: the SCM has simply never been asked to launch it since boot -- which is what
#: a DEMAND_START registration looks like from the outside.
SERVICE_NEVER_STARTED = 1077


def service_state() -> dict:
    r"""What the SCM actually holds for this service.

    Start type and current state are **two separate facts** and are never
    collapsed here.  `auto` + `stopped` is not "Automatic" and is not "healthy";
    it is a service that is meant to run and is not running, which is a
    different problem from one registered `manual`.  Callers render both.

    Returns::

        {"present": bool,
         "start_type": "auto"|"delayed-auto"|"manual"|"disabled"|"boot"|
                       "system"|"absent"|"unknown",
         "state": "running"|"stopped"|...|"absent"|"unknown",
         "exit_code": int}

    Never raises.  Every unreadable answer degrades to "unknown" rather than to
    a confident wrong one -- a status line that lies is worse than one that
    admits it does not know.
    """
    info = {"present": False, "start_type": "absent", "state": "absent",
            "exit_code": 0}

    import winreg

    key_path = rf"SYSTEM\CurrentControlSet\Services\{SERVICE_NAME}"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            info["present"] = True
            try:
                start = winreg.QueryValueEx(key, "Start")[0]
                info["start_type"] = _START_TYPE_NAMES.get(start, "unknown")
            except OSError:
                info["start_type"] = "unknown"
            if info["start_type"] == "auto":
                try:
                    if winreg.QueryValueEx(key, "DelayedAutostart")[0]:
                        info["start_type"] = "delayed-auto"
                except OSError:
                    pass            # absent means not delayed, which is the default
    except OSError:
        return info                 # not registered: both fields stay "absent"

    try:
        import win32serviceutil

        status = win32serviceutil.QueryServiceStatus(SERVICE_NAME)
        info["state"] = _STATE_NAMES.get(status[1], "unknown")
        info["exit_code"] = int(status[3])
    except Exception:
        info["state"] = "unknown"
    return info


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


def unregister_startup_entry() -> tuple[bool, str]:
    """Remove the per-user login entry. Already-absent is success."""
    from ui.core import autostart

    return autostart.unregister()


def unregister_arp_entry() -> tuple[bool, str]:
    """Remove the Add/Remove Programs entry. Already-absent is success."""
    from ui.core import dev_install

    return dev_install.unregister()


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
#: The uninstall entry is LAST, and that is not alphabetical.  It is the thing
#: that advertises this uninstall: if an earlier step fails, the entry has to
#: still be in Settings > Apps for the user to retry from.  Removing it first
#: would strand a half-uninstalled product with no visible way to finish.
_STEPS = (
    ("service", "unregister_service"),
    ("context menu", "unregister_context_menu"),
    ("startup entry", "unregister_startup_entry"),
    ("scheduled task", "unregister_scheduled_task"),
    ("uninstall entry", "unregister_arp_entry"),
)


def register_context_menu() -> tuple[bool, str]:
    """Add the Explorer verb. Per-user; no elevation."""
    from ui.core import shell_ext

    return shell_ext.register()


def register_startup_entry() -> tuple[bool, str]:
    """Add the per-user login entry. Per-user; no elevation."""
    from ui.core import autostart

    return autostart.register()


def register_arp_entry() -> tuple[bool, str]:
    """List PolyShield in Settings > Apps. Per-user; no elevation."""
    from ui.core import dev_install

    return dev_install.register()


#: Registration steps, and whether each is on by default.
#:
#: The startup entry is the odd one out and the tuple says so structurally
#: rather than in a comment: ``register_all()`` with no argument does not create
#: it.  PolyShield writing a Run value into somebody's registry because they ran
#: an installer that mentioned "integration" is precisely the behaviour this
#: feature is not allowed to have, and the way that rule gets broken is a future
#: caller reading ``register_all`` as "register everything".
_REGISTER_STEPS = (
    ("context menu", "register_context_menu", True),
    ("startup entry", "register_startup_entry", False),
    ("uninstall entry", "register_arp_entry", True),
)


def register_all(startup: bool = False, log=None) -> dict:
    """Create the machine-level integrations. Mirror of :func:`unregister_all`.

    ``startup`` must be passed explicitly to get a login entry.  There is no way
    to opt in by omission, and the setup flow passes the answer the user
    actually gave rather than a default of its own.

    The **service is deliberately not here.**  It needs elevation and has its own
    script; folding it in would make this whole call require administrator
    rights for the sake of two registry writes that do not.
    """
    report = {"ok": True, "steps": {}}
    for name, attr, on_by_default in _REGISTER_STEPS:
        if attr == "register_startup_entry" and not startup:
            report["steps"][name] = {"ok": True, "detail": "not requested"}
            if log:
                log(f"[SKIP] {name}: not requested")
            continue
        if not on_by_default and not startup:
            continue
        try:
            ok, detail = globals()[attr]()
        except Exception as exc:
            ok, detail = False, f"raised: {exc!r}"
        report["steps"][name] = {"ok": ok, "detail": detail}
        report["ok"] = report["ok"] and ok
        if log:
            log(f"[{'OK  ' if ok else 'FAIL'}] {name}: {detail}")
    return report


def unregister_all(log=None, skip_service: bool = False) -> dict:
    """Remove every machine-level integration. Returns a per-step report.

    Every step is attempted even when an earlier one fails: they are
    independent, and a rollback that stops at the first problem leaves more
    behind than one that keeps going. The caller decides what a partial result
    means -- an uninstaller reports it, an installer rollback retries.

    ``skip_service`` is for a rollback that never got as far as the service.
    Without it, install_dev.bat's failure path asks to delete PolyShieldService
    whether or not that run created it -- so a failure in an earlier step would
    take out a working, pre-existing registration as its idea of "undoing" an
    install that never touched it. It only ever failed harmlessly because that
    script is unelevated; from an elevated shell it would have succeeded.
    """
    report = {"ok": True, "steps": {}}
    for name, attr in _STEPS:
        if skip_service and attr == "unregister_service":
            continue
        try:
            ok, detail = globals()[attr]()
        except Exception as exc:                  # a step must not abort the rest
            ok, detail = False, f"raised: {exc!r}"
        report["steps"][name] = {"ok": ok, "detail": detail}
        report["ok"] = report["ok"] and ok
        if log:
            log(f"[{'OK  ' if ok else 'FAIL'}] {name}: {detail}")
    return report
