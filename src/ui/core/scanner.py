import subprocess
import threading
import json
import re
import os
import shutil
import ctypes
from datetime import datetime
from pathlib import Path
from ui.core import paths
from ui.core import paths as pathsmod   # run_scan shadows `paths` with its argument

# k2 lives in the development virtualenv and is optional (v1.6.1+);
# is_available() below reports its absence rather than assuming it.
#: Kept for callers that only need the path (diagnostics). The COMMAND
#: comes from paths.k2_argv(): a relocated console stub points at an
#: interpreter that is not there and fails with no output at all.
K2_EXE = str(paths.k2_exe())
LOGS_DIR = paths.logs_dir()
QUARANTINE_DIR = paths.quarantine_dir()


def is_available() -> bool:
    """True if the bundled k2.exe is present. K2 is optional in v1.6.1+."""
    # In a distribution k2 runs as a module through the staged runtime,
    # so the interpreter is what has to exist.
    if paths.is_distribution():
        return paths.runtime_python().exists()
    return Path(K2_EXE).exists()

# parents=True because on the first run of a distribution the data root
# itself does not exist yet; a checkout always had one. Without it this
# raises WinError 3 at import and takes the whole app down before the
# first window is drawn.
LOGS_DIR.mkdir(parents=True, exist_ok=True)
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)


def _short_path(path: Path | str) -> str:
    """
    Return the 8.3 short-name form of a path so k2.exe receives a space-free
    argument.  k2 does not handle spaces inside --report= / --infp= values
    even when subprocess passes them as a single quoted token.

    For a file that doesn't exist yet (e.g. the report output), convert the
    *parent directory* (which must already exist) and append the filename.
    Falls back to the original path string if the API call fails (e.g. 8.3
    names disabled on the volume).
    """
    p = Path(path)
    buf = ctypes.create_unicode_buffer(1024)
    target = p if p.exists() else p.parent
    if ctypes.windll.kernel32.GetShortPathNameW(str(target), buf, 1024) and buf.value:
        short = Path(buf.value)
        return str(short if p.exists() else short / p.name)
    return str(path)

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")
# Matches a Windows absolute path anywhere in a line
_FILE_PATH_RE = re.compile(r'([A-Za-z]:[\\\/][^\t\[\]\(\)\n\r]{2,}?)(?:\s|$|\[|\()')


def _strip_ansi(text: str) -> str:
    return _ANSI_ESCAPE.sub("", text)


# ── Scan controller (pause / cancel) ─────────────────────────────────────────

_PROCESS_SUSPEND_RESUME = 0x0800  # Windows access right for NtSuspendProcess


class ScanController:
    """
    Returned by run_scan().  Lets the caller pause, resume, or cancel the
    running k2.exe process without killing the background thread.

    Thread-safety note: pause()/resume()/cancel() are safe to call from any
    thread (e.g. the main UI thread via button clicks).
    """

    def __init__(self):
        self._proc: subprocess.Popen | None = None
        self._paused   = False
        self._cancelled = False
        self._lock = threading.Lock()

    def _attach(self, proc: subprocess.Popen) -> bool:
        """Adopt the k2 process, applying intent recorded before it existed.

        run_scan() pre-counts files before Popen — minutes on a Full scan — so
        pause() and cancel() are routinely called while _proc is still None.
        They record intent rather than dropping it; this is where it lands, and
        it must happen under the same lock so a cancel() racing Popen() cannot
        slip between the two.

        Returns False when the scan was already cancelled, in which case the
        process has been killed and the caller must not proceed.
        """
        with self._lock:
            self._proc = proc
            if self._cancelled:
                # Cancel outranks a pending pause: never leave a suspended
                # process alive, and never suspend one we are about to kill.
                self._paused = False
                try:
                    proc.kill()
                except Exception:
                    pass
                return False
            if self._paused:
                _os_suspend(proc.pid)
            return True

    @property
    def paused(self) -> bool:
        return self._paused

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    def pause(self):
        with self._lock:
            if self._paused or self._cancelled:
                return
            self._paused = True
            if self._proc is not None:
                _os_suspend(self._proc.pid)
            # else: intent recorded — _attach() applies it on arrival.

    def resume(self):
        with self._lock:
            if not self._paused:
                return
            self._paused = False
            if self._proc is not None:
                _os_resume(self._proc.pid)

    def toggle_pause(self):
        (self.resume if self._paused else self.pause)()

    def cancel(self):
        with self._lock:
            self._cancelled = True
            if self._proc is None:
                self._paused = False    # nothing to resume; drop the intent
                return
            # Must resume first on Windows — a suspended process ignores TerminateProcess
            if self._paused:
                _os_resume(self._proc.pid)
                self._paused = False
            try:
                self._proc.kill()
            except Exception:
                pass


def _os_suspend(pid: int):
    try:
        handle = ctypes.windll.kernel32.OpenProcess(
            _PROCESS_SUSPEND_RESUME, False, pid)
        if handle:
            ctypes.windll.ntdll.NtSuspendProcess(handle)
            ctypes.windll.kernel32.CloseHandle(handle)
    except Exception:
        pass


def _os_resume(pid: int):
    try:
        handle = ctypes.windll.kernel32.OpenProcess(
            _PROCESS_SUSPEND_RESUME, False, pid)
        if handle:
            ctypes.windll.ntdll.NtResumeProcess(handle)
            ctypes.windll.kernel32.CloseHandle(handle)
    except Exception:
        pass


def _k2_env() -> dict:
    """The environment every k2 invocation gets.

    `k2 --update` prunes its rules directory against a downloaded manifest,
    deleting every file the manifest does not list. It finds that directory
    through %SYSTEM_RULES_BASE%, and config/.env pointed it at PolyShield's own
    rules/ -- so an update deleted rules/community/, the published YARA
    generation the .active pointer names, and yara_engine then reported "no
    rules" with nothing to explain it.

    Set here rather than by rewriting .env: kicomav loads that file with
    load_dotenv(override=False), so a value already in the environment wins.
    That repairs existing installations without touching a generated file, and
    works in a distribution that has no .env at all. See paths.k2_rules_dir().
    """
    k2_rules = paths.k2_rules_dir()
    k2_rules.mkdir(parents=True, exist_ok=True)
    return {
        **os.environ,
        "SYSTEM_RULES_BASE": str(k2_rules),
        # k2 reads user rules from here; it does not prune them, and sharing
        # them with yara_engine is deliberate.
        "USER_RULES_BASE": str(paths.rules_dir() / "user_rules"),
    }


def count_files(paths: list[str]) -> int:
    """Count total scannable files across all given paths."""
    total = 0
    for p in paths:
        path = Path(p)
        try:
            if path.is_file():
                total += 1
            elif path.is_dir():
                for item in path.rglob("*"):
                    try:
                        if item.is_file():
                            total += 1
                    except PermissionError:
                        pass
        except PermissionError:
            pass
    return total


def _stream_process(proc, line_callback, progress_callback, total: int, done_callback):
    """
    Stream k2.exe output, calling progress_callback for each file line.

    `total` is a Python pre-count estimate — k2 may scan more files (e.g. archives,
    files accessible to k2 but not rglob).  To prevent the bar hitting 100% before
    k2 finishes, we extend the effective total dynamically: whenever files_done is
    within 5% of the estimate we add a 10% buffer, keeping the bar below 100% until
    _on_done snaps it there.
    """
    files_done = 0
    effective_total = total  # grows if k2 finds more files than we pre-counted
    for raw in proc.stdout:
        line = _strip_ansi(raw.rstrip("\n\r"))
        if not line:
            continue
        line_callback(line)
        if progress_callback:
            m = _FILE_PATH_RE.search(line)
            if m:
                files_done += 1
                # Keep effective_total ahead of files_done so the bar never
                # reaches 100% on its own.  Buffer = 10% of original estimate
                # (min 50 files) so the bar still moves meaningfully.
                buffer = max(total // 10, 50) if total > 0 else 50
                if files_done >= effective_total - buffer // 2:
                    effective_total = files_done + buffer
                progress_callback(files_done, effective_total, m.group(1).rstrip())
    proc.wait()
    done_callback(proc.returncode)


def run_scan(
    paths: list[str],
    threat_action: str,
    line_callback,
    progress_callback,
    done_callback,
) -> "ScanController":
    """
    Start a scan in a background thread.  Returns a ScanController immediately.

    threat_action : "quarantine" | "delete" | "report_only"
    line_callback(line: str)
    progress_callback(done: int, total: int, current_file: str)  — may be None
    done_callback(returncode: int, report_path: str | None)
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = str(LOGS_DIR / f"scan_{timestamp}.json")
    controller = ScanController()

    # --report=json tells k2 to emit a JSON block to stdout after the scan summary.
    # We capture those lines and write them to report_path ourselves so the path
    # (which may contain spaces) never needs to be passed as a k2 argument.
    # Absolute, because k2 is about to be given a working directory of its own
    # (see _k2_cwd): a relative target typed into the Scan view would otherwise
    # start resolving against k2's home instead of the user's.
    paths = [str(Path(p).resolve()) for p in paths]
    cmd = pathsmod.k2_argv(*paths, "--no-color", "-I", "--report=json")
    if threat_action == "quarantine":
        cmd += ["--move", f"--infp={_short_path(QUARANTINE_DIR)}"]
    elif threat_action == "delete":
        cmd += ["-l"]

    def _run():
        # Pre-count files so the progress bar has a denominator
        total = 0
        if progress_callback:
            line_callback("[INFO] Counting files…")
            total = count_files(paths)
            line_callback(f"[INFO] {total} file(s) to scan")
            progress_callback(0, total, "")

        # The pre-count above runs for minutes on a Full scan, and Stop is a
        # button the user can press throughout it.  Without this check k2.exe
        # was launched *after* the scan had been cancelled.
        if controller.cancelled:
            line_callback("[INFO] Scan cancelled before it started.")
            done_callback(-1, None)
            return

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=subprocess.CREATE_NO_WINDOW,
                env=_k2_env(),
            )
            # A cancel() racing this Popen() cannot be prevented by the check
            # above — it lands between the check and the call.  _attach() is the
            # backstop: it kills the process it just adopted and reports False.
            if not controller._attach(proc):
                line_callback("[INFO] Scan cancelled.")
                done_callback(-1, None)
                return

            # k2 emits a JSON block to stdout AFTER the human-readable summary
            # when --report=json is passed.  Accumulate those lines separately so
            # we can write them to report_path; pass everything else to line_callback.
            json_lines: list[str] = []
            in_json = False
            files_done = 0
            effective_total = total

            for raw in proc.stdout:
                line = _strip_ansi(raw.rstrip("\n\r"))
                if not line:
                    continue

                # JSON block starts with the opening brace
                if not in_json and line.strip().startswith("{"):
                    in_json = True

                if in_json:
                    json_lines.append(line)
                    continue

                # Normal scan output — forward to the UI
                line_callback(line)
                if progress_callback:
                    m = _FILE_PATH_RE.search(line)
                    if m:
                        files_done += 1
                        buffer = max(total // 10, 50) if total > 0 else 50
                        if files_done >= effective_total - buffer // 2:
                            effective_total = files_done + buffer
                        progress_callback(files_done, effective_total, m.group(1).rstrip())

            proc.wait()

            # Persist the captured JSON report
            rp = None
            if json_lines:
                try:
                    json_text = "\n".join(json_lines)
                    json.loads(json_text)          # validate before writing
                    Path(report_path).write_text(json_text, encoding="utf-8")
                    rp = report_path
                except Exception:
                    pass

            if not controller.cancelled and threat_action == "quarantine":
                _write_quarantine_meta(paths, timestamp)
            done_callback(proc.returncode, rp)

        except Exception as exc:
            line_callback(f"[ERROR] Failed to start scanner: {exc}")
            done_callback(-1, None)

    threading.Thread(target=_run, daemon=True).start()
    return controller


def run_update(line_callback, done_callback):
    """Run a k2 signature update in a background thread.

    In a distribution this is routed through the service. k2 keeps whitelist.txt
    and its YARA archives under paths.k2_rules_dir(), and the watcher runs k2 on
    every new file (watcher._ENGINE_ORDER) -- so that tree is detection input the
    service trusts, and an unprivileged process able to rewrite the whitelist
    could suppress detections for the whole machine. It is therefore service-
    owned (Users:Read) and this process cannot write it.
    """
    if paths.is_distribution():
        from ui.core import service_client as svc

        try:
            reply = svc.send_command("RUN_K2_UPDATE")
        except Exception as exc:
            reply = None
            line_callback(f"[ERROR] PolyShield service is required to update K2 "
                          f"signatures, and it is not reachable ({exc}).")
        else:
            if reply and reply.get("ok"):
                line_callback("[INFO] Update started by the PolyShield service.")
                done_callback(0)
                return
            line_callback("[ERROR] PolyShield service is required to update K2 "
                          "signatures: " + ((reply or {}).get("error")
                                            or "it is not running"))
        done_callback(-1)
        return

    cmd = pathsmod.k2_argv("--update", "--no-color")

    def _run():
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=subprocess.CREATE_NO_WINDOW,
                env=_k2_env(),
            )
            _stream_process(proc, line_callback, None, 0, done_callback)
        except Exception as exc:
            line_callback(f"[ERROR] Failed to start updater: {exc}")
            done_callback(-1)

    threading.Thread(target=_run, daemon=True).start()


def parse_report(report_path: str) -> dict:
    """Parse a JSON report produced by k2 and return a summary dict."""
    try:
        with open(report_path, encoding="utf-8") as f:
            data = json.load(f)
        # k2 puts totals at top level; older manual reports may nest under "summary"
        summary = data.get("summary", data)
        # k2 reports elapsed as total_scan_time_ms (int); fall back to elapsed/scan_time strings
        elapsed_ms = summary.get("total_scan_time_ms")
        if elapsed_ms is not None:
            elapsed = f"{elapsed_ms / 1000:.2f}s"
        else:
            elapsed = summary.get("elapsed", summary.get("scan_time", ""))
        return {
            "total":    summary.get("total_files",    summary.get("total",    0)),
            "infected": summary.get("infected_files", summary.get("infected", 0)),
            "clean":    summary.get("clean_files",    summary.get("clean",    0)),
            "elapsed":  elapsed,
            "raw":      data,
        }
    except Exception:
        return {"total": 0, "infected": 0, "clean": 0, "elapsed": "", "raw": {}}


def get_infected_paths(report_path: str) -> list[str]:
    """
    Extract file paths flagged as infected or suspect from a JSON scan report.
    Returns a list of absolute path strings.
    """
    try:
        with open(report_path, encoding="utf-8") as f:
            data = json.load(f)
        files = data.get("files", data.get("results", []))
        if not isinstance(files, list):
            return []
        infected = []
        for entry in files:
            status = str(entry.get("status", entry.get("result", ""))).lower()
            if "infected" in status or "suspect" in status:
                # k2 uses "filepath"; older/manual reports may use "path" or "file"
                path = entry.get("filepath", entry.get("path", entry.get("file", "")))
                if path:
                    infected.append(path)
        return infected
    except Exception:
        return []


def get_signature_count() -> int:
    """How many virus names k2 can actually name, via `k2 --vlist`.

    Counting the lines of update.cfg says how many FILES were downloaded, which
    is 3 whether or not they contain anything. This asks the engine.

    It matters because k2 carries only ~23 signatures in its plugin modules and
    the other ~1240 arrive in rule archives it downloads -- and `k2 --update`
    reports SUCCESS when it cannot reach its source, leaving a scanner at under
    2% of its detection with nothing anywhere saying so. Measured on a clean
    install: "[No updates available]", exit 0, an empty rules directory.

    Returns 0 when k2 cannot run at all.
    """
    try:
        r = subprocess.run(
            pathsmod.k2_argv("--vlist", "--no-color"),
            capture_output=True, text=True, timeout=60,
            creationflags=subprocess.CREATE_NO_WINDOW,
            stdin=subprocess.DEVNULL, env=_k2_env(),
        )
        return sum(1 for ln in (r.stdout or "").splitlines()
                   if "[kicomav.plugins." in ln)
    except Exception:
        # 0 means "k2 could not be asked", which the caller renders as
        # "unavailable" rather than as a signature count. Distinct from a small
        # count, which means k2 ran and has only its built-in signatures.
        return 0


def get_update_cfg_info() -> dict:
    """Read k2 own update.cfg and return version metadata."""
    cfg_path = paths.k2_rules_dir() / "update.cfg"
    result = {"version": "Unknown", "last_updated": "Unknown", "raw": ""}
    if not cfg_path.exists():
        return result
    try:
        text = cfg_path.read_text(encoding="utf-8")
        result["raw"] = text
        stat = cfg_path.stat()
        result["last_updated"] = datetime.fromtimestamp(stat.st_mtime).strftime(
            "%Y-%m-%d %H:%M"
        )
    except Exception:
        pass
    return result


def _write_quarantine_meta(scanned_paths: list[str], timestamp: str):
    meta_dir = QUARANTINE_DIR / f".meta_{timestamp}"
    meta_dir.mkdir(parents=True, exist_ok=True)
    meta = {
        "scan_timestamp": timestamp,
        "original_paths": scanned_paths,
        "quarantine_date": datetime.now().isoformat(),
    }
    with open(meta_dir / "scan_meta.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
