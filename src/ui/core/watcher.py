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
            self._scan_cb(path, entry)

        for cb in list(_on_detection_callbacks):
            try:
                cb(entry)
            except Exception:
                pass


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


def scan_new_file(path: str, entry: dict, notify_cb=None):
    """
    Scan a newly-detected file with k2 and optionally Guardian AI.
    Updates entry["status"] in-place.
    notify_cb(filename, message) fires tray balloon alerts if provided.
    Safe to import from both the UI and the Windows Service (no CTk deps).
    """
    from ui.core import scanner as sc
    from ui.core import guardian_engine as ge

    filename = Path(path).name
    action = "quarantine" if cfg.get("watcher_auto_quarantine") else "report_only"

    def _k2_done(rc, report_path):
        entry["status"] = "threat found" if rc != 0 else "clean"
        if rc != 0 and notify_cb:
            notify_cb(filename, "Malware detected by PolyShield")
        if cfg.get("watcher_guardian_scan") and ge.is_available():
            def _g(fp, infected, reason):
                if infected and rc == 0:
                    entry["status"] = "suspicious (Guardian)"
                    if notify_cb:
                        notify_cb(filename, f"Guardian: {reason[:50]}")
            # v1.10: real-time scanning runs Guardian signatures only by default.
            # Pattern false positives at watcher cadence cascade quickly (every
            # new file in Downloads/Desktop/USB mounts triggers them). The user
            # opts into watcher_guardian_patterns explicitly when they want it.
            use_patterns = bool(cfg.get("watcher_guardian_patterns"))
            ge.scan_async([path], _g, lambda _: None,
                          use_patterns_override=use_patterns)
        if cfg.get("watcher_yara_scan"):
            from ui.core import yara_engine as ye
            if ye.is_available():
                def _y(fp, infected, reason):
                    if infected and entry.get("status") == "clean":
                        entry["status"] = "suspicious (YARA)"
                        if notify_cb:
                            notify_cb(filename, f"YARA: {reason[:50]}")
                ye.scan_async([path], _y, lambda _: None)
        if cfg.get("watcher_clamav_scan"):
            from ui.core import clamav_engine as ce
            if ce.is_available():
                def _c(fp, infected, reason):
                    if infected and entry.get("status") == "clean":
                        entry["status"] = "suspicious (ClamAV)"
                        if notify_cb:
                            notify_cb(filename, f"ClamAV: {reason[:50]}")
                ce.scan_async([path], _c, lambda _: None)

    sc.run_scan([path], action, lambda _: None, None, _k2_done)
