import subprocess
from ui.core import paths

_NO_WINDOW = subprocess.CREATE_NO_WINDOW

_TASK_NAME = "PolyShield_ScheduledScan"


def _run(args: list[str]) -> tuple[bool, str]:
    try:
        r = subprocess.run(
            args, capture_output=True, text=True,
            timeout=15, creationflags=_NO_WINDOW,
            # See integration._sc: with no console, an inherited stdin handle
            # makes schtasks fail with WinError 6 before it runs. That made
            # get_task_info() report "no task" for a task that existed, and the
            # uninstaller then skipped deleting it.
            stdin=subprocess.DEVNULL,
        )
        return r.returncode == 0, (r.stdout + r.stderr).strip()
    except Exception as exc:
        return False, str(exc)


def create_task(scan_path: str, frequency: str, start_time: str) -> tuple[bool, str]:
    """
    Create (or replace) the PolyShield scheduled task.
    frequency : 'DAILY' | 'WEEKLY'
    start_time: 'HH:MM'
    """
    # Build the command the task will run.  Routed through paths so a frozen
    # build cannot silently register a task pointing at a virtualenv
    # interpreter and a .py file that the distribution does not contain --
    # a task that would fail at 02:00 months later, with nobody watching.
    try:
        argv = paths.script_launch_argv("scheduled_scan.py", scan_path)
    except paths.StagedRuntimeMissing as exc:
        # A distribution with no staged runtime cannot run a scheduled scan.
        # Returned rather than raised: the only caller runs this on a worker
        # thread with no handler (scheduler_view._create), so an exception
        # would kill that thread and leave the button disabled on "Saving..."
        # with the feedback label still reading "Creating task..." -- the
        # frozen-panel failure this codebase has now hit three times.
        return False, str(exc)
    run_cmd = " ".join(f'"{a}"' for a in argv)

    args = [
        "schtasks", "/create",
        "/tn", _TASK_NAME,
        "/tr", run_cmd,
        "/sc", frequency,
        "/st", start_time,
        "/f",           # force overwrite if exists
        "/rl", "HIGHEST",
    ]
    return _run(args)


def delete_task() -> tuple[bool, str]:
    return _run(["schtasks", "/delete", "/tn", _TASK_NAME, "/f"])


def get_task_info() -> dict:
    """Return task details or {'exists': False} if not found."""
    ok, output = _run([
        "schtasks", "/query", "/tn", _TASK_NAME, "/fo", "CSV", "/nh"
    ])
    if not ok:
        return {"exists": False}

    try:
        # CSV columns: TaskName, Next Run Time, Status
        parts = [p.strip('"') for p in output.split('","')]
        if len(parts) >= 3:
            return {
                "exists": True,
                "name": _TASK_NAME,
                "next_run": parts[1],
                "status": parts[2],
            }
    except Exception:
        pass
    return {"exists": True, "name": _TASK_NAME, "next_run": "—", "status": "—"}


def run_now() -> tuple[bool, str]:
    """Trigger the scheduled task immediately."""
    return _run(["schtasks", "/run", "/tn", _TASK_NAME])
