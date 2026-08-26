import threading
import time
from pathlib import Path
from datetime import datetime

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from ui.core import settings as cfg

# Module-level singleton
_observer: Observer | None = None
_event_log: list[dict] = []  # shared log of detected events
_lock = threading.Lock()
_on_detection_callbacks: list = []


class _Handler(FileSystemEventHandler):
    def __init__(self, scan_callback):
        self._scan_cb = scan_callback

    def on_created(self, event):
        if event.is_directory:
            return
        path = event.src_path
        entry = {
            "path": path,
            "filename": Path(path).name,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status": "pending",
        }
        with _lock:
            _event_log.append(entry)

        # Brief settle delay so the file is fully written before scanning
        time.sleep(1)
        if self._scan_cb:
            # Detection callbacks are deliberately NOT fired here. They mean
            # "scan complete" (see scan_new_file), and scan_new_file returns
            # before k2 has even started -- firing them here handed every
            # observer an entry still reading "pending".
            self._scan_cb(path, entry)
        else:
            # Nothing will scan this file, so there is no completion to wait
            # for. Observers still deserve to hear that it appeared.
            entry["status"] = "clean"
            _notify_detection(entry)


def start(scan_callback=None) -> bool:
    """
    Start watching all configured folders.
    scan_callback(path, entry) is called for each new file.
    Returns True if started successfully.
    """
    global _observer
    folders = cfg.get("watcher_folders") or []
    if not folders:
        return False

    stop()  # stop any existing observer

    observer = Observer()
    handler = _Handler(scan_callback)
    valid = 0
    for folder in folders:
        if Path(folder).is_dir():
            observer.schedule(handler, folder, recursive=False)
            valid += 1

    if valid == 0:
        return False

    observer.daemon = True
    observer.start()
    _observer = observer
    cfg.set_value("watcher_enabled", True)
    return True


def stop():
    global _observer
    if _observer and _observer.is_alive():
        _observer.stop()
        _observer.join(timeout=3)
    _observer = None
    cfg.set_value("watcher_enabled", False)


def is_running() -> bool:
    return _observer is not None and _observer.is_alive()


def get_log() -> list[dict]:
    with _lock:
        return list(_event_log)


def clear_log():
    with _lock:
        _event_log.clear()


def add_detection_callback(cb):
    """Register a callback(entry) called whenever a new file is detected."""
    with _lock:
        _on_detection_callbacks.append(cb)


def remove_detection_callback(cb):
    with _lock:
        try:
            _on_detection_callbacks.remove(cb)
        except ValueError:
            pass

# ── Engine verdicts and the completion barrier ────────────────────────────────

# Precedence for the derived status string. Fixed so the status a consumer
# reads does not depend on which engine happened to finish first.
_SECONDARY_ORDER = ("guardian", "yara", "clamav")
_ENGINE_ORDER = ("k2",) + _SECONDARY_ORDER
_ENGINE_RANK  = {name: i for i, name in enumerate(_ENGINE_ORDER)}
_ENGINE_LABELS = {
    "k2":       "K2",
    "guardian": "Guardian",
    "yara":     "YARA",
    "clamav":   "ClamAV",
}


class _CompletionBarrier:
    """Fires its callback once, after every launched engine has reported.

    Constructed with the number of engines actually launched -- an engine that
    is enabled but unavailable was never launched and must not hold the barrier
    open. Engines that report twice are counted once: a duplicate on_done must
    not produce a duplicate observer notification.
    """

    def __init__(self, expected: int, on_complete):
        self._remaining   = expected
        self._on_complete = on_complete
        self._reported: set[str] = set()
        self._fired       = False
        self._lock        = threading.Lock()

    def arrive(self, engine: str) -> None:
        with self._lock:
            if engine in self._reported:
                return                      # duplicate on_done from one engine
            self._reported.add(engine)
            self._remaining -= 1
            if self._remaining > 0 or self._fired:
                return
            self._fired = True
        self._on_complete()                 # outside the lock

    def fire_if_empty(self) -> None:
        """Complete immediately when nothing was launched (the k2-only path)."""
        with self._lock:
            if self._remaining > 0 or self._fired:
                return
            self._fired = True
        self._on_complete()


def _derive_status(entry: dict) -> str:
    """Reduce entry["verdicts"] to the legacy status string.

    The verdict list is the source of truth; this exists because three
    consumers still read entry["status"] -- service_view, watcher_view and the
    service's own event stream. They colour on `"threat" in status` and
    `status == "clean"` and print anything else verbatim, so "incomplete (...)"
    renders amber with no UI change.

    An engine that errored must never read as clean: "clean" is the only string
    that earns the green all-clear, so it is reserved for runs where every
    launched engine actually completed and found nothing.
    """
    verdicts  = entry.get("verdicts") or []
    by_engine = {v["engine"]: v for v in verdicts}

    k2 = by_engine.get("k2")
    if k2 is not None and k2["infected"]:
        return "threat found"

    for name in _SECONDARY_ORDER:
        v = by_engine.get(name)
        if v is not None and v["infected"]:
            return f"suspicious ({_ENGINE_LABELS[name]})"

    errored = [v["engine"] for v in verdicts if v.get("status") == "error"]
    if errored:
        first = min(errored, key=lambda e: _ENGINE_RANK.get(e, len(_ENGINE_ORDER)))
        return f"incomplete ({_ENGINE_LABELS.get(first, first)} error)"

    return "clean"


def _notify_detection(entry: dict) -> None:
    """Invoke the registered detection callbacks with a completed entry.

    The snapshot is taken under _lock so a concurrent add/remove has defined
    semantics; the callbacks themselves run outside it, because they are
    supplied by the UI and the service and must not be able to deadlock the
    watcher by touching it.
    """
    with _lock:
        callbacks = list(_on_detection_callbacks)
    for cb in callbacks:
        try:
            cb(entry)
        except Exception:
            pass


def scan_new_file(path: str, entry: dict, notify_cb=None, on_complete=None):
    """
    Scan a newly-detected file with k2 and any enabled secondary engines.

    Every launched engine's verdict is appended to entry["verdicts"] as
    {engine, infected, reason, status}; entry["status"] is the derived summary.
    Both are complete before any observer is notified.

    Lifecycle
    ---------
        k2 completes
          -> k2's verdict is recorded
          -> secondary engines launched (barrier sized BEFORE any launch)
          -> each launched engine reports exactly once
          -> barrier fires once
          -> detection callbacks and on_complete see the finished entry

    Two things this replaces. Engine results used to gate on each other --
    YARA and ClamAV only recorded anything when the status was still "clean",
    which Guardian overwrote unconditionally, so a Guardian hit silently
    discarded YARA's finding *and* its tray alert. And every consumer read the
    entry before any engine had finished: run_scan() returns immediately, so
    observers saw "pending" and the service persisted "pending" into
    service_events.json for essentially every detection.

    notify_cb(filename, message) fires tray balloons -- once per engine that
    finds something, never gated on another engine's result.
    on_complete(entry) is the completion signal for callers that own the entry
    rather than observing it (the Windows Service).

    Safe to import from both the UI and the Windows Service (no CTk deps).
    """
    from ui.core import scanner as sc
    from ui.core import guardian_engine as ge

    filename = Path(path).name
    action   = "quarantine" if cfg.get("watcher_auto_quarantine") else "report_only"
    entry.setdefault("verdicts", [])

    def _record(engine: str, infected: bool, reason: str = "", status: str = "ok"):
        with _lock:
            entry["verdicts"].append({
                "engine":   engine,
                "infected": bool(infected),
                "reason":   reason,
                "status":   status,
            })

    def _has_verdict(engine: str) -> bool:
        with _lock:
            return any(v["engine"] == engine for v in entry["verdicts"])

    def _finish():
        entry["status"] = _derive_status(entry)
        _notify_detection(entry)
        if on_complete:
            try:
                on_complete(entry)
            except Exception:
                pass

    def _make_launch(name: str, module, **kwargs):
        label = _ENGINE_LABELS[name]

        def _launch(barrier):
            def _on_result(_fp, infected, reason):
                if infected:
                    _record(name, True, reason)
                    if notify_cb:
                        notify_cb(filename, f"{label}: {reason[:50]}")

            def _on_done(_count):
                if not _has_verdict(name):
                    _record(name, False)
                barrier.arrive(name)

            module.scan_async([path], _on_result, _on_done, **kwargs)

        return _launch

    def _plan_secondary():
        """Which engines will actually run. Enabled but unavailable is not
        launched, so it must not be counted."""
        planned = []
        if cfg.get("watcher_guardian_scan") and ge.is_available():
            # v1.10: real-time scanning runs Guardian signatures only by
            # default. Pattern false positives at watcher cadence cascade --
            # every new file in Downloads/Desktop/USB mounts trips them.
            planned.append(("guardian", _make_launch(
                "guardian", ge,
                use_patterns_override=bool(cfg.get("watcher_guardian_patterns")))))
        if cfg.get("watcher_yara_scan"):
            from ui.core import yara_engine as ye
            if ye.is_available():
                planned.append(("yara", _make_launch("yara", ye)))
        if cfg.get("watcher_clamav_scan"):
            from ui.core import clamav_engine as ce
            if ce.is_available():
                planned.append(("clamav", _make_launch("clamav", ce)))
        return planned

    def _k2_done(rc, _report_path):
        # k2's verdict is recorded before the barrier is evaluated. Otherwise
        # the zero-secondary path fires an entry that does not yet contain the
        # one result it definitely has.
        if rc == -1:
            _record("k2", False, "k2 did not run", status="error")
        else:
            infected = rc != 0
            _record("k2", infected,
                    "Malware detected by PolyShield" if infected else "")
            if infected and notify_cb:
                notify_cb(filename, "Malware detected by PolyShield")

        planned = _plan_secondary()
        barrier = _CompletionBarrier(len(planned), _finish)
        for name, launch in planned:
            try:
                launch(barrier)
            except Exception as exc:
                # A launch that raised will never call on_done, and a barrier
                # that never fires means the detection is never recorded at all
                # -- worse than the bug being fixed here.
                _record(name, False, f"failed to start: {exc}", status="error")
                barrier.arrive(name)
        barrier.fire_if_empty()

    sc.run_scan([path], action, lambda _: None, None, _k2_done)
