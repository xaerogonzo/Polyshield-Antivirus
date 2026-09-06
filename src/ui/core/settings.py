r"""PolyShield's user settings.

The atomic-write and cross-process locking implementation moved to
``polybedrock.settings`` (PolyBedrock Stage 1); PolyScour needs the same guarantees
for its own settings file and should not carry a second copy of a design that
took a corrupted-file incident to get right. **This module *is* that module** --
see ``ps_run.py`` for why the alias is a module replacement rather than a
re-export.

What stays here is what is PolyShield's rather than generic: the settings file's
location, and ``_DEFAULTS``. The defaults name VirusTotal keys, Guardian AI
sensitivity profiles and watcher folders, none of which mean anything to another
consumer -- so ``configure()`` takes them rather than the shared module owning
them. ``conftest.py`` and ``test_settings.py`` read ``cfg._DEFAULTS``; after the
alias that name resolves to the dict installed below.
"""
import sys

from ui.core import paths
from polybedrock import settings as _impl

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


_impl.configure(paths.config_dir() / "ui_settings.json", _DEFAULTS)

sys.modules[__name__] = _impl
