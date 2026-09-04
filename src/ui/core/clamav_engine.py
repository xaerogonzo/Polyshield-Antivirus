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


def _expand_eligible(paths: list[str], on_result) -> list[str]:
    """Expand the requested paths into the list of files clamscan will be given.

    clamscan --file-list treats every entry as a literal file path and does
    NOT descend into directories on its own — so we must expand them here,
    exactly as K2 does via rglob in scanner.py.

    Anything skipped (too large, unreadable) is reported clean through
    ``on_result`` as it is dropped, so the caller's per-file accounting stays
    complete.
    """
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
    return eligible


def _classify_exit(rc: int | None, cancelled: bool) -> str | None:
    """Turn a clamscan return code into a failure message, or None.

    None means *no failure under the existing exit-code semantics* — not that
    the scan is known to have completed. rc is None when proc.wait() itself
    raised (still running, or unwaitable), which has never been treated as a
    verdict; a cancelled scan is not a failure either, because the user asked
    for it.

    clamscan: 0 = nothing found, 1 = threats found, anything else is the
    scanner reporting that the scan itself failed. Treating 2 as "no threats"
    is how a broken virus database becomes an all-clear.
    """
    if not cancelled and rc not in (0, 1, None):
        return f"clamscan exited with code {rc}"
    return None


def scan_async(
    paths: list[str],
    on_result,          # fn(file_path: str, infected: bool, reason: str)
    on_done,            # fn(infected_count: int)
    on_progress=None,   # fn(done: int, total: int, current_file: str) | None
    cancel_event=None,  # threading.Event | None
    pause_event=None,   # threading.Event | None — cleared while paused
    on_error=None,      # fn(message: str) | None — called at most once, before on_done
) -> None:
    """
    Scan all paths in a single clamscan.exe invocation (DB loads once).
    Matches guardian_engine.scan_async() / yara_engine.scan_async() signature.

    on_error is additive: every pre-existing call site omits it and behaves
    exactly as it did before. It fires at most once, and always *before*
    on_done, because on_done releases the watcher's completion barrier — an
    error delivered afterwards would arrive to find "clean" already published.

    A subprocess engine has more ways to fail than a Python-loop one, and all
    of them used to end at on_done(count) with nothing to distinguish them
    from a scan that ran to completion: a missing clamscan.exe, a Popen that
    would not start, a non-zero exit, and a pipe that died half way through a
    scan whose partial results had already been reported.
    """
    def _run():
        failures: list[str] = []

        def _finish(count: int):
            if failures and on_error:
                on_error("; ".join(failures))
            on_done(count)

        exe = _find_exe("clamscan.exe")
        if exe is None:
            failures.append(
                "clamscan.exe not found — set the ClamAV path in Settings")
            _finish(0)
            return

        eligible = _expand_eligible(paths, on_result)

        # Set total AFTER expansion so progress reporting reflects the real count
        total = len(eligible)

        if not eligible:
            _finish(0)
            return

        # If already cancelled before the subprocess even starts, skip.
        # Cancellation is not a failure: the user asked for it, and it must not
        # reach on_error.
        if cancel_event and cancel_event.is_set():
            _finish(0)
            return

        tmpfile = None
        count = 0
        done = 0
        proc = None
        cancelled = False

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
                    cancelled = True
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
                rc = proc.wait(timeout=_SCAN_TIMEOUT)
            except Exception:
                rc = None      # still running or unwaitable; not a verdict

            failure = _classify_exit(rc, cancelled)
            if failure:
                failures.append(failure)
        except Exception as exc:
            # Reached when the stdout pipe dies mid-scan. Whatever was reported
            # before that point is real and stays reported — but the caller has
            # to be told the scan stopped early, or a partial count reads as a
            # complete one.
            failures.append(str(exc))
        finally:
            if tmpfile:
                try:
                    Path(tmpfile).unlink()
                except Exception:
                    pass

        _finish(count)

    threading.Thread(target=_run, daemon=True).start()
