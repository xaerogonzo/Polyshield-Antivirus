"""
sandbox_engine.py
─────────────────
Wrapper around Sandboxie-Plus for isolated file execution (Sandbox Test).

Supports both installation types:
  - System-wide install: SbieSvc Windows service is registered (robust, recommended)
  - Portable build:      SbieCtrl.ini sits next to Start.exe

Usage:
  1. Install Sandboxie-Plus from https://github.com/sandboxie-plus/Sandboxie/releases
     (system-wide installer recommended; portable also works)
  2. Set the path to Start.exe in Settings → Behavioral Analysis
  3. Click "Run in Sandbox" in the Behavioral Analysis view

All file-system changes made by the sandboxed process are trapped inside
Sandboxie's isolation volume.  Use "Wipe Sandbox" to discard them.
"""
from __future__ import annotations

import subprocess
import threading
from pathlib import Path
from typing import Callable

from ui.core import settings as cfg

_SANDBOX_NAME = "KicomHunter"


# ── Availability ─────────────────────────────────────────────────────────────

def _is_service_installed() -> bool:
    """True if the SbieSvc Windows service is registered (system-wide install)."""
    try:
        result = subprocess.run(
            ["sc", "query", "SbieSvc"],
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        return result.returncode == 0
    except Exception:
        return False


def is_available() -> bool:
    """
    True if Start.exe exists AND either:
    - SbieSvc service is registered (system-wide install), OR
    - SbieCtrl.ini is next to Start.exe (portable build).
    """
    start_path = cfg.get("sandboxie_path")
    if not start_path:
        return False
    start = Path(start_path)
    if not start.exists():
        return False
    if (start.parent / "SbieCtrl.ini").exists():
        return True   # portable build
    return _is_service_installed()   # system-wide install


def get_status() -> str:
    """Return a human-readable status string."""
    start_path = cfg.get("sandboxie_path")
    if not start_path:
        return "not configured"
    start = Path(start_path)
    if not start.exists():
        return "Start.exe not found"
    if (start.parent / "SbieCtrl.ini").exists():
        return "ready"   # portable
    if _is_service_installed():
        return "ready"   # system-wide
    return "service not running (SbieSvc not found)"


# ── Core operations ───────────────────────────────────────────────────────────

def detonate(
    path: str,
    on_started: Callable[[], None] | None = None,
    on_finished: Callable[[int], None] | None = None,
) -> None:
    """
    Launch a file inside the KicomHunter sandbox in a daemon thread.

    Parameters
    ----------
    path        : Absolute path to the file to detonate
    on_started  : Optional callback fired immediately before the process starts
    on_finished : Optional callback(returncode) fired when the process exits

    Note: Sandboxie shows the target app's own window — CREATE_NO_WINDOW
    is intentionally NOT set here.  The wiper subprocess below uses it
    because it is purely a management command with no meaningful output.
    """
    def _run():
        start_exe = cfg.get("sandboxie_path")
        if not start_exe or not Path(start_exe).exists():
            if on_finished:
                on_finished(-1)
            return

        if on_started:
            on_started()

        try:
            proc = subprocess.Popen(
                [start_exe, f"/box:{_SANDBOX_NAME}", "/elevate", "/wait", path]
            )
            rc = proc.wait()
        except Exception:
            rc = -1

        if on_finished:
            on_finished(rc)

    threading.Thread(target=_run, daemon=True).start()


def wipe_sandbox(
    on_done: Callable[[bool], None] | None = None,
) -> None:
    """
    Delete all content inside the KicomHunter sandbox in a daemon thread.
    Calls on_done(success: bool) when finished.
    """
    def _run():
        start_exe = cfg.get("sandboxie_path")
        if not start_exe or not Path(start_exe).exists():
            if on_done:
                on_done(False)
            return
        try:
            result = subprocess.run(
                [start_exe, f"/box:{_SANDBOX_NAME}", "/delete"],
                creationflags=subprocess.CREATE_NO_WINDOW,
                timeout=30,
            )
            success = result.returncode == 0
        except Exception:
            success = False
        if on_done:
            on_done(success)

    threading.Thread(target=_run, daemon=True).start()
