import subprocess
import json
from pathlib import Path
from datetime import datetime
from ui.core import paths

_NO_WINDOW = subprocess.CREATE_NO_WINDOW

_TASK_NAME = "PolyShield_ScheduledScan"


def _run(args: list[str]) -> tuple[bool, str]:
    try:
        r = subprocess.run(
            args, capture_output=True, text=True,
            timeout=15, creationflags=_NO_WINDOW,
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
    argv = paths.script_launch_argv("scheduled_scan.py", scan_path)
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
