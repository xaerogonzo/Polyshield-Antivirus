"""
ClamAV engine for PolyShield.

Uses clamscan.exe as a subprocess — no daemon required.
Install ClamAV from https://www.clamav.net/downloads then configure
the install directory in Settings → ClamAV.

All paths are scanned in a single clamscan invocation via --file-list so
the virus database loads only once per scan (not once per file).
"""

import subprocess
import tempfile
import threading
from pathlib import Path

from ui.core import settings as cfg
from ui.core import proc_pause

_COMMON_PATHS = [
    r"C:\Program Files\ClamAV",
    r"C:\Program Files (x86)\ClamAV",
]
_MAX_FILE_MB  = 50     # skip files larger than this
_SCAN_TIMEOUT = 10     # per-process wait() after stdout closes


def _find_exe(name: str) -> Path | None:
    configured = cfg.get("clamav_path") or ""
    candidates = [configured] if configured else []
    candidates += _COMMON_PATHS
    for p in candidates:
        exe = Path(p) / name
        if exe.is_file():
            return exe
    return None


def is_available() -> bool:
    """True if clamscan.exe is reachable at the configured or default path."""
    return _find_exe("clamscan.exe") is not None


def get_version() -> str:
    """Return the first line of `clamscan --version`, or '' on failure."""
    exe = _find_exe("clamscan.exe")
    if not exe:
        return ""
    try:
        r = subprocess.run(
            [str(exe), "--version"],
            capture_output=True, text=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW)
        lines = r.stdout.strip().splitlines()
        return lines[0] if lines else ""
    except Exception:
        return ""


def scan_async(
    paths: list[str],
    on_result,          # fn(file_path: str, infected: bool, reason: str)
    on_done,            # fn(infected_count: int)
    on_progress=None,   # fn(done: int, total: int, current_file: str) | None
    cancel_event=None,  # threading.Event | None
    pause_event=None,   # threading.Event | None — cleared while paused
) -> None:
    """
    Scan all paths in a single clamscan.exe invocation (DB loads once).
    Matches guardian_engine.scan_async() / yara_engine.scan_async() signature.
    """
    def _run():
        exe = _find_exe("clamscan.exe")
        if exe is None:
            on_done(0)
            return

        # Build the eligible file list, recursively expanding any directories.
        # clamscan --file-list treats every entry as a literal file path and does
        # NOT descend into directories on its own — so we must expand them here,
        # exactly as K2 does via rglob in scanner.py.
        eligible: list[str] = []
        for p in paths:
            pp = Path(p)
            try:
                if pp.is_dir():
                    for f in pp.rglob("*"):
                        try:
                            if f.is_file() and f.stat().st_size / 1_048_576 <= _MAX_FILE_MB:
                                eligible.append(str(f))
                        except (PermissionError, OSError):
                            pass
                elif pp.is_file():
                    if pp.stat().st_size / 1_048_576 <= _MAX_FILE_MB:
                        eligible.append(p)
                    else:
                        on_result(p, False, "")
            except Exception:
                on_result(p, False, "")

        # Set total AFTER expansion so progress reporting reflects the real count
        total = len(eligible)

        if not eligible:
            on_done(0)
            return

        # If already cancelled before the subprocess even starts, skip
        if cancel_event and cancel_event.is_set():
            on_done(0)
            return

        tmpfile = None
        count = 0
        done = 0
        proc = None

        try:
            with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".txt", delete=False,
                    encoding="utf-8") as tf:
                tmpfile = tf.name
                tf.write("\n".join(eligible) + "\n")

            proc = subprocess.Popen(
                [str(exe), "--no-summary", f"--file-list={tmpfile}"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, encoding="utf-8", errors="replace",
                creationflags=subprocess.CREATE_NO_WINDOW)

            # Wire up pause/resume — daemon thread suspends clamscan.exe via
            # NtSuspendProcess whenever pause_event is cleared.
            proc_pause.watch_pause_event(proc, pause_event)

            for raw in proc.stdout:
                # Check for cancellation mid-scan; terminate the subprocess
                if cancel_event and cancel_event.is_set():
                    # Must resume first on Windows — a suspended process
                    # ignores TerminateProcess. The watch thread also clears
                    # itself in its finally, but be explicit here.
                    if pause_event is not None:
                        pause_event.set()
                    proc_pause.resume_pid(proc.pid)
                    try:
                        proc.terminate()
                    except Exception:
                        pass
                    break

                line = raw.rstrip("\n")
                if not line:
                    continue
                # Output format: "<path>: OK"  or  "<path>: Threat.Name FOUND"
                sep = line.rfind(": ")
                if sep == -1:
                    continue
                fpath   = line[:sep]
                verdict = line[sep + 2:]

                done += 1
                if on_progress:
                    on_progress(done, total, fpath)

                if verdict == "OK":
                    on_result(fpath, False, "")
                elif verdict.endswith(" FOUND"):
                    threat = verdict[: -len(" FOUND")]
                    on_result(fpath, True, f"ClamAV: {threat}")
                    count += 1
                # other lines (ERROR, skipped, etc.) are silently ignored

            try:
                proc.wait(timeout=_SCAN_TIMEOUT)
            except Exception:
                pass
        except Exception:
            pass
        finally:
            if tmpfile:
                try:
                    Path(tmpfile).unlink()
                except Exception:
                    pass

        on_done(count)

    threading.Thread(target=_run, daemon=True).start()
