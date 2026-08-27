"""
PolyShield — user settings persistence.

Two processes write this file: the UI, and the Windows Service (via the
SET_CONFIG IPC command and via watcher.start()/stop()).  That is the whole
reason this module is more than json.dump().

Concurrency contract
--------------------
`set_value()` is the persistence primitive.  One call performs, under an
OS-owned cross-process lock:

    re-read the file  ->  merge the one changed key  ->  atomic replace

Re-reading inside the lock is what makes concurrent writers preserve each
other's keys.  Atomic replacement alone does NOT: it protects the *file* from
a torn write, not the read-merge-replace *transaction*.  Without the lock,
this interleaving silently loses a=2:

    A: read {a:1,b:1}                B: read {a:1,b:1}
    A: write {a:2,b:1}               B: write {a:1,b:2}

The lock is a byte-range lock (msvcrt.locking) held on a *sidecar* file,
`ui_settings.json.lock`.  Two properties matter and neither is incidental:

  * It is owned by the OS handle, so a crashed process releases it
    automatically.  A PID-in-a-lockfile convention would leave settings
    permanently "locked" after one crash.
  * It is on a sidecar rather than on ui_settings.json itself, because
    Windows refuses os.replace() over a file that has an open handle —
    locking the target would break the atomic replace it exists to protect.

`intel_updater._acquire_file_lock()` is deliberately NOT reused: it is built
for hour-scale operations and reclaims on age, which is the wrong semantics
for a millisecond write.

Return values (never exceptions — see below)
--------------------------------------------
    SAVE_OK        durable merge completed under the lock
    SAVE_DEGRADED  lock timed out; a single best-effort write was made.  This
                   write is explicitly OUTSIDE the lost-update guarantee.
    SAVE_FAILED    nothing was persisted; _cache is left unchanged

Cost
----
set_value() is not free: a lock acquisition, a read, a merge, and an atomic
replace with an fsync is roughly 3 ms. That is fine for a button or a switch
and wrong for a continuous input -- do not call it from a slider `command=`
handler on every tick. display_view's sliders coalesce through
_schedule_persist() and flush on release; anything similar should do the same.
The fsync is deliberate: os.replace() keeps a reader from ever seeing a torn
file, but without the flush a crash can leave the new name pointing at
unwritten blocks, which is the corruption this module exists to prevent.

set_value() returns a status rather than raising.  All 73 call sites are bare
calls inside Tk event handlers — including slider `command=` callbacks that
fire on every drag tick — so an exception would propagate into Tk's dispatcher
per tick.  Callers that ignore the return value behave exactly as before;
callers that care can check it.  Every non-OK outcome is logged.
"""
import json
import logging
import os
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path
from ui.core import paths

try:                                    # Windows-only; the product is too.
    import msvcrt
except ImportError:                     # pragma: no cover - non-Windows
    msvcrt = None

log = logging.getLogger(__name__)

_SETTINGS_FILE = paths.config_dir() / "ui_settings.json"
_LOCK_FILE     = paths.config_dir() / "ui_settings.json.lock"

SAVE_OK       = "ok"
SAVE_DEGRADED = "degraded"
SAVE_FAILED   = "failed"

# Bounded so a settings write can never block a UI toggle indefinitely.
_LOCK_TIMEOUT_S = 2.0
_LOCK_RETRY_S   = 0.02

# Serialises writers inside THIS process; the file lock handles the other one.
_write_lock = threading.Lock()

_DEFAULTS: dict = {
    # Scan panel
    "show_progress_bar": True,
    "show_current_file": True,
    "show_eta": True,
    "verbose_log": True,
    # VirusTotal
    "vt_api_key": "",
    # Folder watcher
    "watcher_enabled": False,
    "watcher_folders": [],
    "watcher_auto_quarantine": False,
    # VirusTotal post-scan verify
    "vt_verify_after_scan": False,
    # Scheduler
    "scheduler_path": "",
    "scheduler_frequency": "DAILY",
    "scheduler_time": "02:00",
    # Guardian AI
    "guardian_dual_scan":    False,
    "guardian_use_nsrl":     True,   # NSRL allow-list SQLite check per file
    "guardian_use_patterns": True,   # Heuristic regex pattern matching
    "guardian_min_scan_bytes": 10,   # v1.9: skip files smaller than N bytes (null-MD5 guard)
    # v1.10: sensitivity profile system + per-pattern overrides
    # Profile values: "conservative" | "balanced" | "power"
    #   conservative — patterns 1-5 only, all pattern matches severity = "suspicious"
    #   balanced     — all 7 patterns, all pattern matches severity = "suspicious"
    #   power        — all 7 patterns, severity = "confirmed" (no downgrade); for researchers
    "guardian_sensitivity_profile": "conservative",
    # Per-pattern toggles (override the profile). Empty dict = use profile defaults.
    # Pattern keys match the labels in guardian_engine._PATTERNS.
    "guardian_pattern_toggles": {},
    # Suspicious-tier display mode in the Threat Actions panel:
    #   "hidden"      — only shown via the "Suspicious" filter chip (default)
    #   "collapsible" — separate "Heuristic Findings" sub-section, collapsed
    #   "inline"      — same list, colored CONFIRMED / SUSPICIOUS badges
    "guardian_suspicious_display": "hidden",
    # Mid-scan circuit breaker: disable pattern tier after N hits in a single scan.
    # 0 = disabled (no breaker). Default 200 catches "hallucination state" without
    # interfering with legitimate large-scale heuristic detections.
    "guardian_circuit_breaker_threshold": 200,
    # Auto-ignore prompt: after a scan, if user added 3+ ignores from the same
    # pattern, prompt to disable it. Setting to True suppresses the prompt.
    "guardian_autoignore_prompt_dismissed": False,
    # Real-time scanning (watcher) should run Guardian signatures only — patterns
    # off by default at real-time speed where false positives cascade.
    "watcher_guardian_patterns": False,
    # VirusTotal smart upload
    "vt_smart_upload_level": "off",  # "off" | "pattern" | "dual"
    # Behavioral analysis
    "sandboxie_path": "",            # Full path to Sandboxie-Plus portable Start.exe
    # System tray & window behavior
    "minimize_to_tray": True,        # Minimize to tray on close instead of quitting
    # Real-time shield enhancements
    "watcher_guardian_scan": False,  # Run Guardian AI second opinion on watcher detections
    "watcher_yara_scan": False,      # Run YARA rules on watcher detections
    # YARA rules engine
    "yara_scan": False,              # Enable YARA rules in manual scan view by default
    # ClamAV signatures engine
    "clamav_path": "",               # Install dir containing clamscan.exe (auto-detected if blank)
    "clamav_scan": False,            # Enable ClamAV in manual scan view by default
    "watcher_clamav_scan": False,    # Run ClamAV on real-time watcher detections
    # Launch behaviour
    "launch_as_admin": False,        # Rewrite launch_ui.vbs to use RunAs (takes effect next launch)
    "context_menu_enabled": False,   # Windows Explorer right-click "Scan with PolyShield"
    # Windows Service IPC
    "service_port": 52614,
    # Scan pipeline engine toggles
    "pipeline_k2":        True,   # K2 engine (True = existing default behaviour)
    "pipeline_defender":  False,  # Windows Defender as an inline pipeline step
    "pipeline_speakeasy": False,  # Speakeasy emulation on flagged PE files
    # Execution order for pipeline engines (Speakeasy always last, not in this list).
    # K2 is now a peer engine — fully reorderable / removable, no longer "primary".
    "pipeline_order": ["k2", "defender", "guardian", "yara", "clamav"],
    # User-defined scan path presets: [{"name": str, "paths": [str, ...]}, ...]
    # Max 20 presets enforced on save.
    "scan_path_presets": [],
    # User-defined pipeline profiles: [{"name": str, "order": [str,...], "enabled": [str,...]}]
    # Max 10 profiles enforced on save.
    "pipeline_profiles": [],
    # First-launch onboarding card (v1.9)
    "getting_started_dismissed": False,  # True once user dismisses or completes all steps
    # WMI Process Monitor (v1.7)
    # Auto-kill detected threat processes from the UI process (better permissions than LocalService)
    "process_monitor_auto_terminate": False,
    # Show clean process events in the Process view log (default off — threats only)
    "process_monitor_show_clean": False,
    # WMI WITHIN N seconds poll interval (1–10); lower = faster detection, more CPU
    "process_monitor_poll_interval": 1,
    # Action when service detects a threat and the UI is closed:
    #   "kill_and_quarantine" — kill process tree then quarantine the .exe (default)
    #   "kill_only"           — terminate only; user reviews in Quarantine on next UI open
    "process_monitor_ui_closed_action": "kill_and_quarantine",
    # ── Display & Appearance (v1.11) ──────────────────────────────────────────
    # Built-in palette preset key: "classic" | "forest" | "void" | "midnight" | "stealth"
    "display_theme_preset":       "classic",
    # Per-component hex overrides — empty string means "use the preset value".
    "display_accent_color":       "",     # section headings, active nav highlight
    # Background image compositing
    "display_bg_image":           "",     # absolute path to image file; "" = none
    "display_bg_opacity":         0.15,   # float 0.0–1.0; how much image shows through
    "display_bg_blur":            0,      # int 0–20; GaussianBlur radius before composite
    # Font size tiers (int, points). Changing these updates all sharing CTkFont objects live.
    "display_font_content_size":  13,     # reading text: Help, descriptions, detail pane
    "display_font_log_size":      12,     # output text: scan log, event feeds, network rows
    "display_log_monospace":      True,   # use Consolas for log/output text
    # Widget scale — requires restart to apply
    "display_widget_scale":       1.0,    # float; passed to ctk.set_widget_scaling()

    # ── Threat intelligence auto-update (v1.12) ───────────────────────────────
    "intel_auto_update":          True,   # master switch for the scheduler
    # Cadence: how often the scheduler considers a feed due for a refresh.
    "intel_update_interval_hours": 12,
    # Freshness thresholds are SEPARATE from cadence — they drive UI warnings,
    # not scheduling.  aging = amber, stale = red.
    "intel_aging_days":           3,
    "intel_stale_days":           7,
    # Which feeds the scheduler is allowed to touch.  NSRL, ClamAV, K2 and
    # Speakeasy stay manual by design (huge local imports, privileged paths,
    # or package installs) — see docs/USAGE.md.
    "intel_auto_feeds":           ["malwarebazaar", "c2", "yara"],
    # Fallback for installs with no Windows Service: update once at launch.
    "intel_update_on_launch":     True,
    "intel_last_auto_run":        "",     # ISO timestamp of the last scheduler run
}

_cache: dict | None = None


# ── Cross-process lock ────────────────────────────────────────────────────────

class _FileLock:
    """OS-owned byte-range lock on the sidecar file.

    Used as a context manager; `acquired` says whether the lock was actually
    taken or the bounded wait expired.  A timeout is not an error — the caller
    degrades to a best-effort write and reports SAVE_DEGRADED.
    """

    def __init__(self, timeout: float = _LOCK_TIMEOUT_S):
        self._timeout = timeout
        self._fd: int | None = None
        self.acquired = False

    def __enter__(self) -> "_FileLock":
        if msvcrt is None:                       # pragma: no cover
            self.acquired = True                 # in-process lock is all we have
            return self
        try:
            _LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
            self._fd = os.open(str(_LOCK_FILE), os.O_CREAT | os.O_RDWR)
        except OSError as exc:
            log.warning("settings: cannot open lock file (%s); "
                        "proceeding without cross-process exclusion", exc)
            return self

        deadline = time.monotonic() + self._timeout
        while True:
            try:
                os.lseek(self._fd, 0, os.SEEK_SET)
                msvcrt.locking(self._fd, msvcrt.LK_NBLCK, 1)
                self.acquired = True
                return self
            except OSError:
                if time.monotonic() >= deadline:
                    log.warning(
                        "settings: lock busy for %.1fs; falling back to a "
                        "best-effort write (outside the lost-update guarantee)",
                        self._timeout)
                    return self
                time.sleep(_LOCK_RETRY_S)

    def __exit__(self, *exc_info) -> None:
        if self._fd is None:
            return
        try:
            if self.acquired and msvcrt is not None:
                os.lseek(self._fd, 0, os.SEEK_SET)
                msvcrt.locking(self._fd, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass                                 # handle close releases it anyway
        finally:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None


# ── Corruption handling ───────────────────────────────────────────────────────

def _preserve_corrupt(raw: bytes) -> None:
    """Copy unparseable settings aside for diagnosis.

    Deliberately a COPY, never a move: if this fails, the user's original file
    is still the original file.  It is their last remaining copy and outranks
    successful recovery bookkeeping — nothing here may delete or truncate it.
    """
    target = _SETTINGS_FILE.with_name(_SETTINGS_FILE.name + ".corrupt")
    if target.exists():
        # Never clobber a previous diagnostic artifact.
        stamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
        target = _SETTINGS_FILE.with_name(f"{_SETTINGS_FILE.name}.{stamp}.corrupt")
    try:
        target.write_bytes(raw)
        log.error("settings: %s was unreadable; preserved as %s and "
                  "falling back to defaults", _SETTINGS_FILE.name, target.name)
    except OSError as exc:
        log.error("settings: %s was unreadable and could not be preserved "
                  "(%s); the original is left untouched",
                  _SETTINGS_FILE.name, exc)


def _read_disk() -> dict:
    """Return the on-disk settings as a dict.

    Absent file -> {} with no .corrupt artifact.  Malformed file -> preserved
    aside, then {} so _DEFAULTS becomes the merge base.  This is the read half
    of set_value()'s locked transaction as well as load()'s, so both paths get
    identical recovery behaviour.
    """
    try:
        raw = _SETTINGS_FILE.read_bytes()
    except FileNotFoundError:
        return {}
    except OSError as exc:
        log.error("settings: cannot read %s (%s); using defaults",
                  _SETTINGS_FILE, exc)
        return {}

    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        _preserve_corrupt(raw)
        return {}

    if not isinstance(data, dict):
        _preserve_corrupt(raw)
        return {}
    return data


# ── Atomic write ──────────────────────────────────────────────────────────────

def _atomic_write(data: dict) -> bool:
    """Write `data` via a unique temp file + os.replace.  True if it landed.

    The temp name must be unique: a fixed ui_settings.json.tmp is a file two
    processes collide on.  On any failure the original file is left intact and
    the temp file is removed.
    """
    fd = tmp = None
    try:
        _SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(_SETTINGS_FILE.parent),
                                   prefix=".ui_settings-", suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fd = None                            # fdopen owns it now
            json.dump(data, fh, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, str(_SETTINGS_FILE))
        return True
    except Exception as exc:
        log.error("settings: durable write failed (%s); %s is unchanged",
                  exc, _SETTINGS_FILE.name)
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if tmp and os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
        return False


# ── Public API ────────────────────────────────────────────────────────────────

def load() -> dict:
    """(Re)read settings from disk into the process cache."""
    global _cache
    _cache = {**_DEFAULTS, **_read_disk()}
    return _cache


def get(key: str):
    if _cache is None:
        load()
    return _cache.get(key, _DEFAULTS.get(key))


def set_value(key: str, value) -> str:
    """Persist one key.  Returns SAVE_OK / SAVE_DEGRADED / SAVE_FAILED.

    The whole read-merge-write runs inside both locks so a concurrent writer
    in either this process or the service cannot lose the other's key.  On
    failure `_cache` is deliberately left alone: it must never report a value
    as persisted when the durable write did not land.
    """
    global _cache
    if _cache is None:
        load()

    with _write_lock:
        with _FileLock() as lock:
            merged = _read_disk()
            merged[key] = value
            written = _atomic_write(merged)

        if not written:
            return SAVE_FAILED

        _cache = {**_DEFAULTS, **merged}
        return SAVE_OK if lock.acquired else SAVE_DEGRADED


def save(updated: dict) -> str:
    """Deprecated whole-file write.  Prefer set_value().

    Kept as cheap insurance against a late-bound caller; the v1.13 audit found
    none.  Unlike set_value() this does NOT merge — it replaces the file
    wholesale, reintroducing exactly the lost-update problem set_value() exists
    to avoid.
    """
    global _cache
    with _write_lock:
        with _FileLock() as lock:
            written = _atomic_write(updated)
        if not written:
            return SAVE_FAILED
        _cache = {**_DEFAULTS, **updated}
        return SAVE_OK if lock.acquired else SAVE_DEGRADED
