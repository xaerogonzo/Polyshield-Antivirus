"""
PolyShield — WMI-based process creation monitor.

Subscribes to Win32_Process __InstanceCreationEvent (configurable poll
interval). For each new process:
  1. Compute full-file MD5 (skip if > 100 MB or unreadable)
  2. Check session allow-list (files the user has restored from quarantine)
  3. Check known_bad RAM set (MalwareBazaar MD5s loaded from SQLite; v1.8+)
  4. Check SQLite malicious table in threat_db.sqlite (fallback / large-DB path)
  5. Call alert_callback if a threat is found

KNOWN LIMITATION
----------------
WMI __InstanceCreationEvent (WITHIN N seconds) is NOT a kernel-level
interceptor — it cannot block process execution. Detection latency is
≤ poll_interval seconds after launch. True blocking requires a kernel
minifilter driver (out of scope for v1.7). Processes that escalate to
SYSTEM / Protected Process Light before the detection window closes are
invisible to this monitor. See docs/ARCHITECTURE.md — Known Limitations.

THREAD SAFETY
-------------
ProcessMonitor is safe to call from any thread:
  • start() / stop() / reload_known_bad() serialise state changes on _lock;
    allow_hash() relies on set.add() being atomic under the GIL
  • The WMI loop runs in its own daemon thread
  • alert_callback is invoked from the WMI thread — callers must marshal
    UI updates back to the main thread (use widget.after(0, ...) in CTk views)

COM REQUIREMENT
---------------
WMI is COM-based. pythoncom.CoInitialize() is called inside the WMI
thread, not on the caller's thread. Do NOT call CoInitialize() on the
main thread for this object.
"""

import hashlib
import logging
import threading
import weakref
from pathlib import Path

log = logging.getLogger(__name__)

_ROOT           = Path(__file__).resolve().parents[3]
_DB_PATH        = _ROOT / "intelligence" / "threat_db.sqlite"
_KNOWN_BAD_PATH = _ROOT / "guardianai" / "data" / "known_bad.txt"  # legacy fallback only

# If the malicious table exceeds this count, skip RAM loading entirely.
# _check_process() already has a per-lookup SQLite fallback that covers all hashes.
_KNOWN_BAD_RAM_LIMIT = 500_000

# How long stop() waits for the watch thread. A constant rather than a literal
# so a test can shrink it -- the failure this guards against takes the whole
# timeout to reproduce.
_STOP_JOIN_TIMEOUT_S = 5

# Every live ProcessMonitor in this process.  Weak, so a monitor that has been
# stopped and dropped (the Processes view recreates one on every toggle) never
# keeps a dead instance alive or gets reloaded pointlessly.
_live_monitors: "weakref.WeakSet" = weakref.WeakSet()


def reload_all_known_bad() -> int:
    """Reload the known-bad set of every live ProcessMonitor in this process.

    This is the callable to register as the "hashes" post-update hook — one
    stable module-level function, rather than a bound method of whichever
    monitor instance happened to exist at start-up.  Returns the number of
    monitors refreshed.
    """
    done = 0
    for mon in list(_live_monitors):
        try:
            mon.reload_known_bad()
            done += 1
        except Exception as exc:
            log.warning("ProcessMonitor reload failed: %s", exc)
    return done


def _load_known_bad() -> set:
    """
    Load MalwareBazaar MD5s from SQLite into a RAM set for fast per-process checks.

    v1.8+: loads directly from threat_db.sqlite (the canonical source) instead of
    the now-deprecated known_bad.txt flat file.

    If the malicious table has more than _KNOWN_BAD_RAM_LIMIT entries the RAM set
    is intentionally left empty — _check_process() already queries SQLite for every
    process that misses the RAM set, so coverage is not affected.
    """
    try:
        if _DB_PATH.exists():
            import sqlite3 as _sqlite3
            _con = _sqlite3.connect(str(_DB_PATH), timeout=3)
            _count = _con.execute(
                "SELECT COUNT(*) FROM malicious WHERE hash_type='md5'"
            ).fetchone()[0]
            if _count <= _KNOWN_BAD_RAM_LIMIT:
                result = {
                    _h.lower()
                    for (_h,) in _con.execute(
                        "SELECT hash FROM malicious WHERE hash_type='md5'"
                    )
                    if _h
                }
                _con.close()
                return result
            _con.close()
            return set()   # too large — rely on per-lookup SQLite in _check_process()
    except Exception:
        pass
    # Legacy fallback: known_bad.txt (only used if SQLite DB doesn't exist yet)
    try:
        if _KNOWN_BAD_PATH.exists():
            return {
                line.strip().lower()
                for line in _KNOWN_BAD_PATH.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.startswith("#")
            }
    except Exception:
        pass
    return set()


class ProcessMonitor:
    """
    WMI process creation monitor.

    Parameters
    ----------
    alert_callback : callable
        Signature: (pid: int, name: str, exe_path: str,
                    reason: str, alert_level: str) -> None
        Called on the WMI thread — must be thread-safe.
        alert_level is "warning" or "critical".
    known_bad : set[str] | None
        Pre-loaded MalwareBazaar MD5 set.  If None, loaded from disk.
    poll_interval : int
        WMI WITHIN N seconds (clamped to 1–10).
    """

    def __init__(self, alert_callback, known_bad=None, poll_interval: int = 1):
        self._alert_cb      = alert_callback
        self._known_bad     = known_bad if known_bad is not None else _load_known_bad()
        self._poll_interval = max(1, min(int(poll_interval), 10))
        self._stop_evt      = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock          = threading.Lock()
        self._session_allowlist: set[str] = set()
        _live_monitors.add(self)

    # ── Public API ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the WMI monitor thread.  No-op if already running."""
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop_evt.clear()
            self._thread = threading.Thread(
                target=self._watch_loop,
                daemon=True,
                name="PolyShield-ProcessMonitor",
            )
            self._thread.start()
        log.info("ProcessMonitor started (poll_interval=%ds).", self._poll_interval)

    def stop(self) -> None:
        """Signal the monitor thread to stop and wait for it to actually die.

        The handle is dropped only on a successful join.  Clearing it after a
        timed-out join made is_running() report False while the thread was
        still alive and still able to fire alert_callback -- and for the one
        component that kills processes, "I turned it off" must not be able to
        lie.  A hung GetObject("winmgmts:") is the way that happens.
        """
        self._stop_evt.set()
        thread = self._thread
        if thread is None:
            return

        thread.join(timeout=_STOP_JOIN_TIMEOUT_S)
        if thread.is_alive():
            log.error(
                "ProcessMonitor: watch thread did not stop within %ss; keeping "
                "the handle so is_running() keeps telling the truth.",
                _STOP_JOIN_TIMEOUT_S)
            return

        self._thread = None
        log.info("ProcessMonitor stopped.")

    def is_running(self) -> bool:
        """Return True if the WMI thread is alive."""
        return bool(self._thread and self._thread.is_alive())

    def allow_hash(self, md5: str) -> None:
        """
        Add an MD5 to the session allow-list.

        Call after the user restores a file from quarantine.  Prevents the
        monitor from immediately re-killing the process if the user relaunches
        the restored file during this session.
        """
        self._session_allowlist.add(md5.lower())

    def reload_known_bad(self) -> None:
        """Reload MalwareBazaar MD5s from SQLite (called after an intelligence update).

        The new set is built OUTSIDE the lock — it can hold hundreds of
        thousands of hashes and rebuilding it under _lock would stall
        start()/stop() for the duration.  Only the rebind is serialised, which
        is what readers of self._known_bad actually depend on.
        """
        fresh = _load_known_bad()
        with self._lock:
            self._known_bad = fresh

    # ── Internal ───────────────────────────────────────────────────────────────

    def _watch_loop(self) -> None:
        """
        WMI subscription loop — runs in its own thread.

        COM is initialized per-thread (required for WMI / win32com).
        A single persistent SQLite connection is kept open for the thread
        lifetime to avoid the overhead of reconnecting per process event.

        The WMI subscription is wrapped in a restart loop so that if the
        WMI service drops the connection (service restart, timeout) the
        monitor automatically re-subscribes after a 5 s back-off rather
        than silently dying while is_running() still returns True.
        """
        try:
            import pythoncom
            import win32com.client
            import pywintypes
        except ImportError as e:
            log.error("ProcessMonitor: pywin32 not available — %s", e)
            return

        import sqlite3

        pythoncom.CoInitialize()
        con: sqlite3.Connection | None = None
        try:
            if _DB_PATH.exists():
                try:
                    con = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
                except Exception as e:
                    log.warning("ProcessMonitor: cannot open threat DB — %s", e)

            query = (
                f"SELECT * FROM __InstanceCreationEvent WITHIN {self._poll_interval} "
                "WHERE TargetInstance ISA 'Win32_Process'"
            )

            # Outer restart loop — re-subscribes if WMI drops the connection.
            while not self._stop_evt.is_set():
                try:
                    wmi     = win32com.client.GetObject("winmgmts:")
                    watcher = wmi.ExecNotificationQuery(query)
                    log.info("ProcessMonitor: WMI subscription active.")

                    while not self._stop_evt.is_set():
                        try:
                            event = watcher.NextEvent(1000)   # 1 s timeout; raises on no event
                            proc  = event.TargetInstance
                            self._check_process(
                                pid=int(proc.ProcessId or 0),
                                name=proc.Name or "",
                                exe_path=proc.ExecutablePath or "",
                                con=con,
                            )
                        except pywintypes.com_error:
                            pass   # normal timeout — not an error
                        except Exception as e:
                            log.warning("ProcessMonitor: WMI event error — %s", e)

                except Exception as e:
                    if self._stop_evt.is_set():
                        break
                    log.warning(
                        "ProcessMonitor: WMI subscription dropped — restarting in 5 s: %s", e
                    )
                    self._stop_evt.wait(5)

        except Exception as e:
            log.error("ProcessMonitor: fatal error in watch loop — %s", e)
        finally:
            if con is not None:
                try:
                    con.close()
                except Exception:
                    pass
            try:
                pythoncom.CoUninitialize()
            except Exception:
                pass

    def _check_process(
        self,
        pid: int,
        name: str,
        exe_path: str,
        con,           # sqlite3.Connection | None
    ) -> None:
        """Check a newly-created process against threat databases."""
        if not exe_path:
            return

        md5 = self._fast_hash(exe_path)
        if md5 is None:
            return   # unreadable, PPL, or >100 MB — skip

        if md5 in self._session_allowlist:
            return   # user explicitly restored this file — respect the choice

        reason: str | None = None

        # 1. RAM set (O(1))
        if md5 in self._known_bad:
            reason = "known malicious hash (MalwareBazaar)"
        elif con is not None:
            # 2. SQLite (one query per suspicious hit only)
            try:
                row = con.execute(
                    "SELECT malware_family FROM malicious WHERE hash=?", (md5,)
                ).fetchone()
                if row:
                    family = row[0] or "unknown family"
                    reason = f"known malicious hash — {family}"
            except Exception as e:
                log.debug("ProcessMonitor: DB lookup error — %s", e)

        if reason:
            log.warning(
                "ProcessMonitor: THREAT PID=%d name=%s reason=%s",
                pid, name, reason,
            )
            try:
                self._alert_cb(pid, name, exe_path, reason, "warning")
            except Exception as e:
                log.error("ProcessMonitor: alert_callback raised — %s", e)

    @staticmethod
    def _fast_hash(path: str) -> str | None:
        """
        Compute the full-file MD5 of an executable.

        Skips files > 100 MB (most malware is ≤ 20 MB; large files are
        typically game installers or Steam updates).  Binary-padding attacks
        that push a malicious binary over 100 MB are logged at DEBUG level.

        Returns None if the file should be skipped (too large, unreadable,
        or a Protected Process Light that denies read access).
        """
        try:
            p    = Path(path)
            size = p.stat().st_size
            if size > 100 * 1024 * 1024:
                log.debug(
                    "ProcessMonitor: skipping large file (%d MB): %s",
                    size // (1024 * 1024), path,
                )
                return None
            h = hashlib.md5()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except (PermissionError, OSError):
            # Protected Process Light (lsass.exe, MsMpEng.exe, DRM services),
            # or file already deleted (self-deleting installer temp)
            return None
        except Exception as e:
            log.debug("ProcessMonitor: hash error for %s — %s", path, e)
            return None
