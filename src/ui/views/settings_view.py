import threading
from datetime import datetime

import customtkinter as ctk
from ui.core import settings as cfg
from ui.core import ignore_list as ignore
import ui.theme as theme

_SCAN_OPTIONS = [
    (
        "minimize_to_tray",
        "Minimize to system tray on close",
        "When enabled, clicking X hides the window and keeps PolyShield running in the "
        "notification area (system tray). Right-click the tray icon to restore or quit.\n"
        "When disabled, clicking X exits the app completely.",
    ),
    (
        "show_progress_bar",
        "Show progress bar",
        "Display a progress bar with percentage while scanning.",
    ),
    (
        "show_current_file",
        "Show current file being scanned",
        "Display the name of the file currently being processed beneath the progress bar.\n"
        "Turn off to reduce visual noise on large scans.",
    ),
    (
        "show_eta",
        "Show estimated time remaining (ETA)",
        "Calculate and display how long the scan has left based on current speed.",
    ),
    (
        "verbose_log",
        "Verbose log — show all scanned files",
        "When on: every file appears in the live log.\n"
        "When off: only threats and warnings are shown, keeping the log clean for large scans.",
    ),
    (
        "vt_verify_after_scan",
        "Auto-verify detected threats on VirusTotal",
        "After a scan, automatically check any detected threats against VirusTotal.\n"
        "Requires an API key. Rate-limited to 4 requests/min (free tier).",
    ),
]


class SettingsView(ctk.CTkScrollableFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self._switches: dict[str, ctk.CTkSwitch] = {}
        self._vt_key_entry: ctk.CTkEntry | None = None
        self._build()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(self, text="Settings",
                     font=ctk.CTkFont(size=22, weight="bold")).grid(
            row=0, column=0, sticky="w", padx=24, pady=(20, 4))

        # ── Scan Panel options ──
        self._section("Scan Panel", row=1)
        for i, (key, label, desc) in enumerate(_SCAN_OPTIONS):
            self._option_row(key, label, desc, row=i + 2)

        n = len(_SCAN_OPTIONS)

        # ── VirusTotal ──
        self._divider(row=n + 2)
        self._section("VirusTotal", row=n + 3)

        vt_card = ctk.CTkFrame(self, corner_radius=10, fg_color=theme.color("card"))
        vt_card.grid(row=n + 4, column=0, sticky="ew", padx=24, pady=4)
        vt_card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(vt_card, text="API Key",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     anchor="w").grid(row=0, column=0, padx=16, pady=(14, 4), sticky="w")

        ctk.CTkLabel(vt_card,
                     text="Free tier: 4 requests/min, 500/day. Get yours at virustotal.com.",
                     font=ctk.CTkFont(size=11), text_color=theme.color("subtext"),
                     anchor="w").grid(row=1, column=0, columnspan=3,
                                      sticky="w", padx=16, pady=(0, 6))

        key_row = ctk.CTkFrame(vt_card, fg_color="transparent")
        key_row.grid(row=2, column=0, columnspan=3, sticky="ew", padx=16, pady=(0, 14))
        key_row.grid_columnconfigure(0, weight=1)

        self._vt_key_entry = ctk.CTkEntry(
            key_row, placeholder_text="Paste your VirusTotal API key here",
            show="•", font=ctk.CTkFont(family="Consolas", size=12))
        self._vt_key_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        saved_key = cfg.get("vt_api_key") or ""
        if saved_key:
            self._vt_key_entry.insert(0, saved_key)

        ctk.CTkButton(key_row, text="Save Key", width=100,
                      fg_color=theme.color("accent"), hover_color=theme.color("accent_hover"),
                      command=self._save_vt_key).grid(row=0, column=1)

        self._vt_feedback = ctk.CTkLabel(
            vt_card, text="", font=ctk.CTkFont(size=11))
        self._vt_feedback.grid(row=3, column=0, columnspan=3,
                                sticky="w", padx=16, pady=(0, 4))

        # show/hide toggle for key entry
        self._show_key_var = ctk.StringVar(value="0")
        ctk.CTkCheckBox(key_row, text="Show", variable=self._show_key_var,
                        onvalue="1", offvalue="0",
                        width=60, font=ctk.CTkFont(size=11),
                        command=self._toggle_show_key).grid(row=0, column=2, padx=(8, 0))

        self._vt_test_btn = ctk.CTkButton(
            key_row, text="Test Key", width=90,
            fg_color="#2a3a5a", hover_color="#344a78",
            font=ctk.CTkFont(size=11),
            command=self._test_vt_key)
        self._vt_test_btn.grid(row=0, column=3, padx=(8, 0))

        # Smart upload level selector
        ctk.CTkFrame(vt_card, height=1, fg_color=theme.color("divider")).grid(
            row=4, column=0, columnspan=3, sticky="ew", padx=16, pady=(4, 8))

        ctk.CTkLabel(vt_card, text="Smart upload — auto-check detections after scan",
                     font=ctk.CTkFont(size=12, weight="bold"), anchor="w").grid(
            row=5, column=0, columnspan=3, sticky="w", padx=16, pady=(0, 2))

        ctk.CTkLabel(vt_card,
                     text="Controls which flagged files are automatically checked against "
                          "VirusTotal after a dual-scan.\n"
                          "Only hash lookups — your files are never uploaded.",
                     font=ctk.CTkFont(size=11), text_color=theme.color("subtext"),
                     anchor="w", wraplength=560).grid(
            row=6, column=0, columnspan=3, sticky="w", padx=16, pady=(0, 6))

        level_row = ctk.CTkFrame(vt_card, fg_color="transparent")
        level_row.grid(row=7, column=0, columnspan=3, sticky="ew", padx=16, pady=(0, 14))

        _LEVELS = [
            ("Off",                          "off"),
            ("Pattern matches & unknowns",   "pattern"),
            ("Both engines only",            "dual"),
        ]
        current_level = cfg.get("vt_smart_upload_level") or "off"
        self._vt_level_var = ctk.StringVar(value=current_level)

        for i, (label, val) in enumerate(_LEVELS):
            rb = ctk.CTkRadioButton(
                level_row, text=label, value=val, variable=self._vt_level_var,
                font=ctk.CTkFont(size=12),
                command=lambda v=val: cfg.set_value("vt_smart_upload_level", v))
            rb.grid(row=0, column=i, padx=(0 if i == 0 else 16, 0))

        # ── Guardian AI ──
        self._divider(row=n + 5)
        self._section("Guardian AI", row=n + 6)

        from ui.core import guardian_engine as ge
        guardian_available = ge.is_available()

        guardian_card = ctk.CTkFrame(self, corner_radius=10, fg_color=theme.color("card"))
        guardian_card.grid(row=n + 7, column=0, sticky="ew", padx=24, pady=4)
        guardian_card.grid_columnconfigure(0, weight=1)

        badge_text  = "● Installed" if guardian_available else "● Not installed"
        badge_color = "#50fa7b" if guardian_available else "#ffb86c"
        badge_row = ctk.CTkFrame(guardian_card, fg_color="transparent")
        badge_row.grid(row=0, column=0, sticky="ew", padx=16, pady=(12, 4))
        badge_row.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(badge_row, text="Guardian AI Engine",
                     font=ctk.CTkFont(size=13, weight="bold"), anchor="w").grid(
            row=0, column=0, sticky="w")
        ctk.CTkLabel(badge_row, text=badge_text,
                     font=ctk.CTkFont(size=11), text_color=badge_color).grid(
            row=0, column=1, padx=(8, 0))

        if not guardian_available:
            ctk.CTkLabel(guardian_card,
                         text="Run setup_guardian.bat to clone the repo and create guardian_env/.",
                         font=ctk.CTkFont(size=11), text_color=theme.color("subtext"),
                         anchor="w").grid(row=1, column=0, sticky="w",
                                          padx=16, pady=(0, 12))
        else:
            stats = ge.get_db_stats()
            stat_text = (f"{stats['known_bad']:,} known-bad signatures  •  "
                         f"Last updated: {stats['last_updated']}")
            ctk.CTkLabel(guardian_card, text=stat_text,
                         font=ctk.CTkFont(size=11), text_color=theme.color("subtext"),
                         anchor="w").grid(row=1, column=0, sticky="w",
                                          padx=16, pady=(0, 6))

            # Dual-scan toggle
            from ui.core import settings as _cfg
            dual_key = "guardian_dual_scan"
            dual_switch = ctk.CTkSwitch(guardian_card, text="", width=46,
                                        command=lambda: _cfg.set_value(
                                            dual_key, bool(dual_switch.get())))
            dual_switch.grid(row=2, column=0, padx=(0, 16), pady=(4, 2), sticky="e")
            if _cfg.get(dual_key):
                dual_switch.select()
            else:
                dual_switch.deselect()
            self._switches[dual_key] = dual_switch
            ctk.CTkLabel(guardian_card,
                         text="Enable dual-scan (second opinion) in Scan view by default",
                         font=ctk.CTkFont(size=12), anchor="w").grid(
                row=2, column=0, sticky="w", padx=16, pady=(4, 2))
            ctk.CTkLabel(guardian_card,
                         text="After each PolyShield scan, also run Guardian AI's scanner on the same paths.",
                         font=ctk.CTkFont(size=11), text_color=theme.color("subtext"),
                         anchor="w").grid(row=3, column=0, sticky="w",
                                          padx=16, pady=(0, 8))

            # Thin divider between dual-scan toggle and the tier toggles
            ctk.CTkFrame(guardian_card, height=1, fg_color=theme.color("divider")).grid(
                row=4, column=0, sticky="ew", padx=16, pady=(0, 8))

            ctk.CTkLabel(guardian_card,
                         text="Guardian AI scan tiers",
                         font=ctk.CTkFont(size=11, weight="bold"),
                         text_color=theme.color("accent"), anchor="w").grid(
                row=5, column=0, sticky="w", padx=16, pady=(0, 4))

            # NSRL allow-list toggle
            nsrl_key = "guardian_use_nsrl"
            nsrl_switch = ctk.CTkSwitch(guardian_card, text="", width=46,
                                        command=lambda: _cfg.set_value(
                                            nsrl_key, bool(nsrl_switch.get())))
            nsrl_switch.grid(row=6, column=0, padx=(0, 16), pady=(2, 2), sticky="e")
            if _cfg.get(nsrl_key):
                nsrl_switch.select()
            else:
                nsrl_switch.deselect()
            self._switches[nsrl_key] = nsrl_switch
            ctk.CTkLabel(guardian_card,
                         text="NSRL allow-list check  (skip known-safe system files)",
                         font=ctk.CTkFont(size=12), anchor="w").grid(
                row=6, column=0, sticky="w", padx=16, pady=(2, 2))
            ctk.CTkLabel(guardian_card,
                         text="SQLite lookup per file against NIST known-safe hashes. "
                              "Disable if NSRL not imported or to skip ~1–5 ms per file.",
                         font=ctk.CTkFont(size=11), text_color=theme.color("subtext"),
                         anchor="w", wraplength=560).grid(
                row=7, column=0, sticky="w", padx=16, pady=(0, 6))

            # Heuristic patterns toggle
            pat_key = "guardian_use_patterns"
            pat_switch = ctk.CTkSwitch(guardian_card, text="", width=46,
                                       command=lambda: _cfg.set_value(
                                           pat_key, bool(pat_switch.get())))
            pat_switch.grid(row=8, column=0, padx=(0, 16), pady=(2, 2), sticky="e")
            if _cfg.get(pat_key):
                pat_switch.select()
            else:
                pat_switch.deselect()
            self._switches[pat_key] = pat_switch
            ctk.CTkLabel(guardian_card,
                         text="Heuristic pattern matching  (regex-based detection)",
                         font=ctk.CTkFont(size=12), anchor="w").grid(
                row=8, column=0, sticky="w", padx=16, pady=(2, 2))
            ctk.CTkLabel(guardian_card,
                         text="7 regex patterns: AutoRun, WScript dropper, encoded PowerShell, "
                              "MSHTA, Mimikatz, ransomware notes, Bitcoin demands. "
                              "Disable for pure hash-based detection with no regex overhead.",
                         font=ctk.CTkFont(size=11), text_color=theme.color("subtext"),
                         anchor="w", wraplength=560).grid(
                row=9, column=0, sticky="w", padx=16, pady=(0, 12))

            # Minimum scan size (v1.9 — null-MD5 false-positive guard)
            min_size_row = ctk.CTkFrame(guardian_card, fg_color="transparent")
            min_size_row.grid(row=10, column=0, sticky="ew", padx=16, pady=(2, 4))
            min_size_row.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(min_size_row,
                         text="Minimum scan size (bytes)",
                         font=ctk.CTkFont(size=12), anchor="w").grid(
                row=0, column=0, sticky="w")
            min_var = ctk.StringVar(value=str(_cfg.get("guardian_min_scan_bytes") or 10))
            min_entry = ctk.CTkEntry(min_size_row, textvariable=min_var,
                                      width=80, height=28)
            min_entry.grid(row=0, column=1, padx=(8, 0))

            def _save_min(*_):
                try:
                    val = max(0, min(int(min_var.get().strip() or "0"), 65536))
                except ValueError:
                    val = 10
                _cfg.set_value("guardian_min_scan_bytes", val)
            min_var.trace_add("write", _save_min)

            ctk.CTkLabel(guardian_card,
                         text="Files smaller than this are skipped before MD5 lookup. Default 10 "
                              "prevents the null-MD5 false positive (every 0-byte file appearing as "
                              "a 'Known Signature'). Increase if you're getting noise on tiny "
                              "lockfiles or placeholder files. 0 disables the guard.",
                         font=ctk.CTkFont(size=11), text_color=theme.color("subtext"),
                         anchor="w", wraplength=560).grid(
                row=11, column=0, sticky="w", padx=16, pady=(0, 12))

            # Ignored hashes manager (v1.9)
            ignored_row = ctk.CTkFrame(guardian_card, fg_color="transparent")
            ignored_row.grid(row=12, column=0, sticky="ew", padx=16, pady=(2, 4))
            ignored_row.grid_columnconfigure(0, weight=1)
            self._ignored_count_lbl = ctk.CTkLabel(
                ignored_row,
                text=f"Ignored hashes: {ignore.count()} entries",
                font=ctk.CTkFont(size=12), anchor="w")
            self._ignored_count_lbl.grid(row=0, column=0, sticky="w")
            ctk.CTkButton(
                ignored_row, text="Manage…", width=100, height=28,
                fg_color=theme.color("input_hover"), hover_color="#4a4a5a",
                font=ctk.CTkFont(size=12),
                command=self._open_ignored_manager).grid(row=0, column=1, padx=(8, 0))

            ctk.CTkLabel(guardian_card,
                         text="Files you've explicitly marked as false positives. Their MD5 "
                              "hashes short-circuit Guardian's detection on every future scan.",
                         font=ctk.CTkFont(size=11), text_color=theme.color("subtext"),
                         anchor="w", wraplength=560).grid(
                row=13, column=0, sticky="w", padx=16, pady=(0, 12))

            # ── v1.10: Sensitivity profile + Advanced popup ──
            self._build_guardian_sensitivity_section(guardian_card, start_row=14)

        # ── YARA Rules ──
        self._divider(row=n + 8)
        self._section("YARA Rules", row=n + 9)

        from ui.core import yara_engine as ye
        yara_available = ye.is_available()

        yara_card = ctk.CTkFrame(self, corner_radius=10, fg_color=theme.color("card"))
        yara_card.grid(row=n + 10, column=0, sticky="ew", padx=24, pady=4)
        yara_card.grid_columnconfigure(0, weight=1)

        yara_badge_row = ctk.CTkFrame(yara_card, fg_color="transparent")
        yara_badge_row.grid(row=0, column=0, sticky="ew", padx=16, pady=(12, 4))
        yara_badge_row.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(yara_badge_row, text="YARA Rules Engine",
                     font=ctk.CTkFont(size=13, weight="bold"), anchor="w").grid(
            row=0, column=0, sticky="w")
        yara_badge_text  = f"● {ye.get_rule_count()} rule file(s) loaded" if yara_available else "● No .yar files found"
        yara_badge_color = "#50fa7b" if yara_available else "#ffb86c"
        ctk.CTkLabel(yara_badge_row, text=yara_badge_text,
                     font=ctk.CTkFont(size=11), text_color=yara_badge_color).grid(
            row=0, column=1, padx=(8, 0))

        ctk.CTkLabel(yara_card,
                     text="Drop .yar files into rules/user_rules/ to extend detection.\n"
                          "All rule files are compiled automatically at scan time.",
                     font=ctk.CTkFont(size=11), text_color=theme.color("subtext"),
                     anchor="w", wraplength=560).grid(
            row=1, column=0, sticky="w", padx=16, pady=(0, 6))

        yara_btn_row = ctk.CTkFrame(yara_card, fg_color="transparent")
        yara_btn_row.grid(row=2, column=0, sticky="w", padx=16, pady=(0, 8))
        ctk.CTkButton(yara_btn_row, text="Open rules folder", width=140, height=28,
                      fg_color=theme.color("input_hover"), hover_color="#4a4a5a",
                      font=ctk.CTkFont(size=12),
                      command=self._open_yara_rules_folder).pack(side="left")

        ctk.CTkFrame(yara_card, height=1, fg_color=theme.color("divider")).grid(
            row=3, column=0, sticky="ew", padx=16, pady=(0, 8))

        # Enable YARA in scan view by default
        yara_key = "yara_scan"
        self._yara_scan_switch = ctk.CTkSwitch(
            yara_card, text="", width=46,
            state="normal" if yara_available else "disabled",
            command=lambda: cfg.set_value(yara_key, bool(self._yara_scan_switch.get())))
        self._yara_scan_switch.grid(row=4, column=0, padx=(0, 16), pady=(4, 2), sticky="e")
        if cfg.get(yara_key) and yara_available:
            self._yara_scan_switch.select()
        ctk.CTkLabel(yara_card,
                     text="Enable YARA scan in Scan view by default",
                     font=ctk.CTkFont(size=12), anchor="w").grid(
            row=4, column=0, sticky="w", padx=16, pady=(4, 2))

        # Enable YARA on watcher detections
        yara_w_key = "watcher_yara_scan"
        self._yara_watcher_switch = ctk.CTkSwitch(
            yara_card, text="", width=46,
            state="normal" if yara_available else "disabled",
            command=lambda: cfg.set_value(yara_w_key, bool(self._yara_watcher_switch.get())))
        self._yara_watcher_switch.grid(row=5, column=0, padx=(0, 16), pady=(2, 2), sticky="e")
        if cfg.get(yara_w_key) and yara_available:
            self._yara_watcher_switch.select()
        ctk.CTkLabel(yara_card,
                     text="Run YARA rules on real-time watcher detections",
                     font=ctk.CTkFont(size=12), anchor="w").grid(
            row=5, column=0, sticky="w", padx=16, pady=(2, 12))

        if not yara_available:
            ctk.CTkLabel(yara_card,
                         text="Add at least one .yar file to rules/user_rules/ to enable.",
                         font=ctk.CTkFont(size=11), text_color=theme.color("subtext"),
                         anchor="w").grid(row=6, column=0, sticky="w", padx=16, pady=(0, 12))

        # ── ClamAV ──
        self._divider(row=n + 11)
        self._section("ClamAV", row=n + 12)

        from ui.core import clamav_engine as ce
        clamav_available = ce.is_available()

        clam_card = ctk.CTkFrame(self, corner_radius=10, fg_color=theme.color("card"))
        clam_card.grid(row=n + 13, column=0, sticky="ew", padx=24, pady=4)
        clam_card.grid_columnconfigure(0, weight=1)

        clam_badge_row = ctk.CTkFrame(clam_card, fg_color="transparent")
        clam_badge_row.grid(row=0, column=0, sticky="ew", padx=16, pady=(12, 4))
        clam_badge_row.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(clam_badge_row, text="ClamAV Engine",
                     font=ctk.CTkFont(size=13, weight="bold"), anchor="w").grid(
            row=0, column=0, sticky="w")
        clam_badge_text  = "● " + ce.get_version() if clamav_available else "● Not found"
        clam_badge_color = "#50fa7b" if clamav_available else "#ffb86c"
        ctk.CTkLabel(clam_badge_row, text=clam_badge_text,
                     font=ctk.CTkFont(size=11), text_color=clam_badge_color).grid(
            row=0, column=1, padx=(8, 0))

        ctk.CTkLabel(clam_card,
                     text="Open-source signature engine with millions of community-maintained rules.\n"
                          "Download the Windows installer from clamav.net, then set the install path below.",
                     font=ctk.CTkFont(size=11), text_color=theme.color("subtext"),
                     anchor="w", wraplength=560).grid(
            row=1, column=0, sticky="w", padx=16, pady=(0, 6))

        clam_path_row = ctk.CTkFrame(clam_card, fg_color="transparent")
        clam_path_row.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 8))
        clam_path_row.grid_columnconfigure(0, weight=1)

        self._clam_path_entry = ctk.CTkEntry(
            clam_path_row,
            placeholder_text=r"C:\Program Files\ClamAV  (leave blank to auto-detect)",
            font=ctk.CTkFont(family="Consolas", size=11))
        self._clam_path_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        saved_clam = cfg.get("clamav_path") or ""
        if saved_clam:
            self._clam_path_entry.insert(0, saved_clam)

        ctk.CTkButton(clam_path_row, text="Browse", width=80,
                      fg_color=theme.color("input_hover"), hover_color="#4a4a5a",
                      command=self._browse_clamav).grid(row=0, column=1, padx=(0, 8))

        ctk.CTkButton(clam_path_row, text="Save", width=70,
                      fg_color=theme.color("accent"), hover_color=theme.color("accent_hover"),
                      command=self._save_clamav_path).grid(row=0, column=2)

        self._clam_feedback = ctk.CTkLabel(clam_card, text="",
                                            font=ctk.CTkFont(size=11))
        self._clam_feedback.grid(row=3, column=0, sticky="w", padx=16, pady=(0, 6))

        ctk.CTkFrame(clam_card, height=1, fg_color=theme.color("divider")).grid(
            row=4, column=0, sticky="ew", padx=16, pady=(0, 8))

        # Enable ClamAV in scan view by default
        clam_key = "clamav_scan"
        self._clam_scan_switch = ctk.CTkSwitch(
            clam_card, text="", width=46,
            state="normal" if clamav_available else "disabled",
            command=lambda: cfg.set_value(clam_key, bool(self._clam_scan_switch.get())))
        self._clam_scan_switch.grid(row=5, column=0, padx=(0, 16), pady=(4, 2), sticky="e")
        if cfg.get(clam_key) and clamav_available:
            self._clam_scan_switch.select()
        ctk.CTkLabel(clam_card,
                     text="Enable ClamAV scan in Scan view by default",
                     font=ctk.CTkFont(size=12), anchor="w").grid(
            row=5, column=0, sticky="w", padx=16, pady=(4, 2))

        # Enable ClamAV on watcher detections
        clam_w_key = "watcher_clamav_scan"
        self._clam_watcher_switch = ctk.CTkSwitch(
            clam_card, text="", width=46,
            state="normal" if clamav_available else "disabled",
            command=lambda: cfg.set_value(clam_w_key, bool(self._clam_watcher_switch.get())))
        self._clam_watcher_switch.grid(row=6, column=0, padx=(0, 16), pady=(2, 2), sticky="e")
        if cfg.get(clam_w_key) and clamav_available:
            self._clam_watcher_switch.select()
        ctk.CTkLabel(clam_card,
                     text="Run ClamAV on real-time watcher detections",
                     font=ctk.CTkFont(size=12), anchor="w").grid(
            row=6, column=0, sticky="w", padx=16, pady=(2, 12))

        if not clamav_available:
            ctk.CTkLabel(clam_card,
                         text="Install ClamAV and set the path above, or leave blank for auto-detection.",
                         font=ctk.CTkFont(size=11), text_color=theme.color("subtext"),
                         anchor="w").grid(row=7, column=0, sticky="w", padx=16, pady=(0, 12))

        # ── Behavioral Analysis ──
        self._divider(row=n + 14)
        self._section("Behavioral Analysis", row=n + 15)

        behavioral_card = ctk.CTkFrame(self, corner_radius=10, fg_color=theme.color("card"))
        behavioral_card.grid(row=n + 16, column=0, sticky="ew", padx=24, pady=4)
        behavioral_card.grid_columnconfigure(0, weight=1)

        from ui.core import emulate_engine as ee
        from ui.core import sandbox_engine as se

        # Speakeasy status
        sp_row = ctk.CTkFrame(behavioral_card, fg_color="transparent")
        sp_row.grid(row=0, column=0, sticky="ew", padx=16, pady=(12, 2))
        sp_row.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(sp_row, text="Speakeasy Emulator",
                     font=ctk.CTkFont(size=12, weight="bold"), anchor="w").grid(
            row=0, column=0, sticky="w")
        sp_ok = ee.is_available()
        ctk.CTkLabel(sp_row,
                     text="● Installed" if sp_ok else "● Not installed",
                     font=ctk.CTkFont(size=11),
                     text_color="#50fa7b" if sp_ok else "#ffb86c").grid(
            row=0, column=1, padx=(8, 0))

        if not sp_ok:
            ctk.CTkLabel(behavioral_card,
                         text="Run: kicomav_env\\Scripts\\pip.exe install speakeasy-emulator",
                         font=ctk.CTkFont(family="Consolas", size=10),
                         text_color=theme.color("subtext"), anchor="w").grid(
                row=1, column=0, sticky="w", padx=16, pady=(0, 8))
        else:
            ctk.CTkLabel(behavioral_card,
                         text="PE emulation ready — traces API calls, network, registry without execution.",
                         font=ctk.CTkFont(size=11), text_color=theme.color("subtext"), anchor="w").grid(
                row=1, column=0, sticky="w", padx=16, pady=(0, 8))

        # Divider
        ctk.CTkFrame(behavioral_card, height=1, fg_color=theme.color("divider")).grid(
            row=2, column=0, sticky="ew", padx=16, pady=(0, 8))

        # Sandboxie-Plus path
        sb_row = ctk.CTkFrame(behavioral_card, fg_color="transparent")
        sb_row.grid(row=3, column=0, sticky="ew", padx=16, pady=(0, 4))
        sb_row.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(sb_row, text="Sandboxie-Plus",
                     font=ctk.CTkFont(size=12, weight="bold"), anchor="w").grid(
            row=0, column=0, sticky="w")
        sb_status = se.get_status()
        sb_ok = sb_status == "ready"
        ctk.CTkLabel(sb_row,
                     text="● Ready" if sb_ok else f"● {sb_status.capitalize()}",
                     font=ctk.CTkFont(size=11),
                     text_color="#50fa7b" if sb_ok else "#ffb86c").grid(
            row=0, column=1, padx=(8, 0))

        ctk.CTkLabel(behavioral_card,
                     text="Install Sandboxie-Plus from github.com/sandboxie-plus/Sandboxie\n"
                          "and point the path below to Start.exe  (system-wide or portable install both supported).",
                     font=ctk.CTkFont(size=11), text_color=theme.color("subtext"),
                     anchor="w", wraplength=560).grid(
            row=4, column=0, sticky="w", padx=16, pady=(0, 6))

        path_row = ctk.CTkFrame(behavioral_card, fg_color="transparent")
        path_row.grid(row=5, column=0, sticky="ew", padx=16, pady=(0, 14))
        path_row.grid_columnconfigure(0, weight=1)

        self._sb_path_entry = ctk.CTkEntry(
            path_row, placeholder_text="C:\\path\\to\\sandboxie-plus\\Start.exe",
            font=ctk.CTkFont(family="Consolas", size=11))
        self._sb_path_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        saved_sb = cfg.get("sandboxie_path") or ""
        if saved_sb:
            self._sb_path_entry.insert(0, saved_sb)

        ctk.CTkButton(path_row, text="Browse", width=80,
                      fg_color=theme.color("input_hover"), hover_color="#4a4a5a",
                      command=self._browse_sandboxie).grid(row=0, column=1, padx=(0, 8))

        ctk.CTkButton(path_row, text="Save", width=70,
                      fg_color=theme.color("accent"), hover_color=theme.color("accent_hover"),
                      command=self._save_sandboxie_path).grid(row=0, column=2)

        self._sb_feedback = ctk.CTkLabel(behavioral_card, text="",
                                          font=ctk.CTkFont(size=11))
        self._sb_feedback.grid(row=6, column=0, sticky="w", padx=16, pady=(0, 10))

        # ── Launch ──
        self._divider(row=n + 17)
        self._section("Launch", row=n + 18)

        launch_card = ctk.CTkFrame(self, corner_radius=10, fg_color=theme.color("card"))
        launch_card.grid(row=n + 19, column=0, sticky="ew", padx=24, pady=4)
        launch_card.grid_columnconfigure(0, weight=1)

        self._admin_switch = ctk.CTkSwitch(launch_card, text="", width=46,
                                            command=self._toggle_launch_as_admin)
        self._admin_switch.grid(row=0, column=1, rowspan=2, padx=(8, 16), pady=14, sticky="e")
        if cfg.get("launch_as_admin"):
            self._admin_switch.select()
        else:
            self._admin_switch.deselect()

        ctk.CTkLabel(launch_card, text="Always launch as Administrator",
                     font=ctk.CTkFont(size=13, weight="bold"), anchor="w").grid(
            row=0, column=0, sticky="w", padx=16, pady=(12, 2))
        ctk.CTkLabel(launch_card,
                     text="Rewrites launch_ui.vbs to use RunAs elevation on every launch.\n"
                          "Required for full Device Security data (Secure Boot, TPM, VBS).\n"
                          "Default: off — use 'Run as Administrator' in Win Security as needed.\n"
                          "Takes effect on the next launch.",
                     font=ctk.CTkFont(size=11), text_color=theme.color("subtext"),
                     anchor="w", justify="left", wraplength=560).grid(
            row=1, column=0, sticky="w", padx=16, pady=(0, 12))

        self._admin_feedback = ctk.CTkLabel(launch_card, text="",
                                             font=ctk.CTkFont(size=11))
        self._admin_feedback.grid(row=2, column=0, columnspan=2, sticky="w",
                                   padx=16, pady=(0, 8))

        # Context menu card
        ctx_card = ctk.CTkFrame(self, corner_radius=10, fg_color=theme.color("card"))
        ctx_card.grid(row=n + 20, column=0, sticky="ew", padx=24, pady=(4, 4))
        ctx_card.grid_columnconfigure(0, weight=1)

        self._ctx_switch = ctk.CTkSwitch(ctx_card, text="", width=46,
                                          command=self._toggle_context_menu)
        self._ctx_switch.grid(row=0, column=1, rowspan=2, padx=(8, 16), pady=14, sticky="e")

        from ui.core import shell_ext as _sx
        if _sx.is_registered():
            self._ctx_switch.select()
        else:
            self._ctx_switch.deselect()

        ctk.CTkLabel(ctx_card, text="Windows Explorer context menu",
                     font=ctk.CTkFont(size=13, weight="bold"), anchor="w").grid(
            row=0, column=0, sticky="w", padx=16, pady=(12, 2))
        ctk.CTkLabel(ctx_card,
                     text="Adds 'Scan with PolyShield' to the right-click menu for files, "
                          "folders, and drives.\nNo administrator rights required.",
                     font=ctk.CTkFont(size=11), text_color=theme.color("subtext"),
                     anchor="w", justify="left", wraplength=560).grid(
            row=1, column=0, sticky="w", padx=16, pady=(0, 4))

        self._ctx_status_lbl = ctk.CTkLabel(
            ctx_card, text="Registered" if _sx.is_registered() else "Not registered",
            font=ctk.CTkFont(size=11),
            text_color="#50fa7b" if _sx.is_registered() else "#888888")
        self._ctx_status_lbl.grid(row=2, column=0, sticky="w", padx=16, pady=(0, 10))

        # ── Threat Intelligence Updates ──
        self._divider(row=n + 21)
        self._section("Threat Intelligence Updates", row=n + 22)
        self._build_intel_update_section(row=n + 23)

        # ── About ──
        self._divider(row=n + 24)
        self._section("About", row=n + 25)
        about = ctk.CTkFrame(self, corner_radius=10, fg_color=theme.color("card"))
        about.grid(row=n + 26, column=0, sticky="ew", padx=24, pady=(4, 20))
        about.grid_columnconfigure(0, weight=1)
        for i, text in enumerate([
            "PolyShield Security Suite",
            "Built by Alexander L Corthell  •  k2 engine by Kei Choi",
            "Settings saved to config/ui_settings.json",
        ]):
            ctk.CTkLabel(about, text=text, font=ctk.CTkFont(size=12),
                         text_color=theme.color("dim"), anchor="w").grid(
                row=i, column=0, sticky="w", padx=16,
                pady=(10 if i == 0 else 2, 10 if i == 2 else 2))

    # ── Threat Intelligence Updates ───────────────────────────────────────────

    _INTEL_FEED_LABELS = {
        "malwarebazaar": ("MalwareBazaar hashes",
                          "Recent malware MD5s from abuse.ch (the 'recent' list only)"),
        "c2":            ("C2 IP blocklist",
                          "Feodo Tracker + ThreatFox command-and-control addresses"),
        "yara":          ("YARA community rules",
                          "YARA Forge core rule package from GitHub releases"),
    }

    _INTEL_INTERVALS = ["6", "12", "24", "48"]

    def _build_intel_update_section(self, row: int):
        card = ctk.CTkFrame(self, corner_radius=10, fg_color=theme.color("card"))
        card.grid(row=row, column=0, sticky="ew", padx=24, pady=4)
        card.grid_columnconfigure(0, weight=1)

        # Master switch
        top = ctk.CTkFrame(card, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 2))
        top.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(top, text="Update intelligence automatically", anchor="w",
                     font=ctk.CTkFont(size=13, weight="bold")).grid(
            row=0, column=0, sticky="w")
        self._intel_auto_switch = ctk.CTkSwitch(
            top, text="", width=46,
            command=lambda: self._toggle_intel_auto())
        self._intel_auto_switch.grid(row=0, column=1, sticky="e")
        if cfg.get("intel_auto_update"):
            self._intel_auto_switch.select()
        else:
            self._intel_auto_switch.deselect()

        ctk.CTkLabel(card,
                     text=("The Windows Service refreshes feeds on a schedule when it is "
                           "running; otherwise PolyShield checks once at launch. "
                           "NSRL, ClamAV, K2 and Speakeasy stay manual."),
                     font=ctk.CTkFont(size=11), text_color=theme.color("subtext"),
                     anchor="w", justify="left", wraplength=580).grid(
            row=1, column=0, sticky="w", padx=16, pady=(0, 8))

        # Cadence + thresholds
        knobs = ctk.CTkFrame(card, fg_color="transparent")
        knobs.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 8))

        ctk.CTkLabel(knobs, text="Check every", font=ctk.CTkFont(size=12)).grid(
            row=0, column=0, sticky="w")
        self._intel_interval = ctk.CTkOptionMenu(
            knobs, values=self._INTEL_INTERVALS, width=70,
            command=self._save_intel_interval)
        self._intel_interval.set(str(int(cfg.get("intel_update_interval_hours") or 12)))
        self._intel_interval.grid(row=0, column=1, padx=(8, 4))
        ctk.CTkLabel(knobs, text="hours", font=ctk.CTkFont(size=12),
                     text_color=theme.color("subtext")).grid(row=0, column=2, padx=(0, 20))

        # Warning thresholds are a separate concept from cadence: how often we
        # CHECK is not the same question as when the UI should start worrying.
        ctk.CTkLabel(knobs, text="Warn after", font=ctk.CTkFont(size=12)).grid(
            row=0, column=3, sticky="w")
        self._intel_aging = ctk.CTkEntry(knobs, width=44,
                                         font=ctk.CTkFont(size=12))
        self._intel_aging.insert(0, str(int(cfg.get("intel_aging_days") or 3)))
        self._intel_aging.grid(row=0, column=4, padx=(8, 4))
        ctk.CTkLabel(knobs, text="days,  stale after", font=ctk.CTkFont(size=12),
                     text_color=theme.color("subtext")).grid(row=0, column=5)
        self._intel_stale = ctk.CTkEntry(knobs, width=44,
                                         font=ctk.CTkFont(size=12))
        self._intel_stale.insert(0, str(int(cfg.get("intel_stale_days") or 7)))
        self._intel_stale.grid(row=0, column=6, padx=(8, 4))
        ctk.CTkLabel(knobs, text="days", font=ctk.CTkFont(size=12),
                     text_color=theme.color("subtext")).grid(row=0, column=7, padx=(0, 8))
        ctk.CTkButton(knobs, text="Save", width=60, height=26,
                      font=ctk.CTkFont(size=11),
                      fg_color=theme.color("input_bg"),
                      hover_color=theme.color("input_hover"),
                      command=self._save_intel_thresholds).grid(row=0, column=8)

        # Per-feed toggles + live status
        self._intel_feed_vars = {}
        self._intel_feed_status = {}
        enabled = set(cfg.get("intel_auto_feeds") or [])

        feeds_frame = ctk.CTkFrame(card, fg_color="transparent")
        feeds_frame.grid(row=3, column=0, sticky="ew", padx=16, pady=(0, 6))
        feeds_frame.grid_columnconfigure(1, weight=1)

        for i, (key, (label, desc)) in enumerate(self._INTEL_FEED_LABELS.items()):
            var = ctk.StringVar(value="1" if key in enabled else "0")
            self._intel_feed_vars[key] = var
            ctk.CTkCheckBox(feeds_frame, text="", width=24, variable=var,
                            onvalue="1", offvalue="0",
                            command=self._save_intel_feeds).grid(
                row=i * 2, column=0, sticky="w", pady=(4, 0))
            ctk.CTkLabel(feeds_frame, text=label, anchor="w",
                         font=ctk.CTkFont(size=12, weight="bold")).grid(
                row=i * 2, column=1, sticky="w", pady=(4, 0))
            status = ctk.CTkLabel(feeds_frame, text="—", anchor="e",
                                  font=ctk.CTkFont(size=11),
                                  text_color=theme.color("subtext"))
            status.grid(row=i * 2, column=2, sticky="e", padx=(8, 0))
            self._intel_feed_status[key] = status
            ctk.CTkLabel(feeds_frame, text=desc, anchor="w",
                         font=ctk.CTkFont(size=11),
                         text_color=theme.color("subtext")).grid(
                row=i * 2 + 1, column=1, columnspan=2, sticky="w", pady=(0, 2))

        # Run now + last run
        foot = ctk.CTkFrame(card, fg_color="transparent")
        foot.grid(row=4, column=0, sticky="ew", padx=16, pady=(2, 14))
        foot.grid_columnconfigure(1, weight=1)

        self._intel_run_btn = ctk.CTkButton(
            foot, text="Run now", width=110, height=30,
            fg_color=theme.color("accent"), hover_color=theme.color("accent_hover"),
            command=self._run_intel_now)
        self._intel_run_btn.grid(row=0, column=0, sticky="w")

        self._intel_last_lbl = ctk.CTkLabel(
            foot, text="", anchor="w", font=ctk.CTkFont(size=11),
            text_color=theme.color("subtext"))
        self._intel_last_lbl.grid(row=0, column=1, sticky="w", padx=(12, 0))

        # SettingsView has no status callback — the house convention is a
        # per-section feedback label (see _vt_feedback / _clam_feedback).
        self._intel_feedback = ctk.CTkLabel(
            card, text="", anchor="w", font=ctk.CTkFont(size=11),
            wraplength=580, justify="left")
        self._intel_feedback.grid(row=5, column=0, sticky="w", padx=16, pady=(0, 12))

        self._refresh_intel_settings_status()

    def _intel_say(self, msg: str, colour: str = "") -> None:
        try:
            self._intel_feedback.configure(
                text=msg, text_color=colour or theme.color("subtext"))
        except Exception:
            pass

    def _refresh_intel_settings_status(self):
        """Repaint the per-feed status labels from current freshness."""
        try:
            from ui.core import intel_updater as iu
            state = iu.get_staleness()
        except Exception:
            return
        colours = {"fresh": "#50fa7b", "aging": "#ffb86c", "stale": "#ff5555",
                   "never": "#ff5555", "auth_required": "#ffb86c"}
        for key, lbl in getattr(self, "_intel_feed_status", {}).items():
            info = state.get(key, {})
            st = info.get("state", "")
            age = info.get("age_hours")
            when = ("never" if age is None
                    else ("just now" if age < 1
                          else (f"{int(age)}h ago" if age < 48 else f"{int(age / 24)}d ago")))
            text = f"{st}  ·  {when}"
            if info.get("last_error"):
                text += f"  ·  {info['last_error'][:34]}"
            try:
                lbl.configure(text=text, text_color=colours.get(st, theme.color("subtext")))
            except Exception:
                pass
        last = cfg.get("intel_last_auto_run") or ""
        if hasattr(self, "_intel_last_lbl"):
            try:
                self._intel_last_lbl.configure(
                    text=f"Last run: {last.replace('T', ' ')} UTC" if last else "Never run")
            except Exception:
                pass

    def _toggle_intel_auto(self):
        cfg.set_value("intel_auto_update", bool(self._intel_auto_switch.get()))
        on = bool(self._intel_auto_switch.get())
        self._intel_say(
            f"Automatic updates {'enabled' if on else 'disabled'}"
            + (" — restart the service for it to take effect" if on else ""),
            "#50fa7b" if on else "#ffb86c")

    def _save_intel_interval(self, value: str):
        try:
            cfg.set_value("intel_update_interval_hours", int(value))
            self._intel_say(f"Checking every {value} hours.", "#50fa7b")
        except ValueError:
            pass

    def _save_intel_thresholds(self):
        try:
            aging = int(self._intel_aging.get().strip())
            stale = int(self._intel_stale.get().strip())
        except ValueError:
            self._intel_say("Thresholds must be whole numbers of days.", "#ff5555")
            return
        if aging < 1 or stale < 1:
            self._intel_say("Thresholds must be at least 1 day.", "#ff5555")
            return
        if stale < aging:
            # Silently reordering would hide a mistake; say what is wrong.
            self._intel_say("'Stale after' must be at least as many days as "
                            "'warn after'.", "#ff5555")
            return
        cfg.set_value("intel_aging_days", aging)
        cfg.set_value("intel_stale_days", stale)
        self._intel_say(f"Saved — warn after {aging}d, stale after {stale}d.", "#50fa7b")
        self._refresh_intel_settings_status()

    def _save_intel_feeds(self):
        feeds = [k for k, v in self._intel_feed_vars.items() if v.get() == "1"]
        cfg.set_value("intel_auto_feeds", feeds)
        self._intel_say("Auto-updated feeds: " + (", ".join(feeds) if feeds else "none"),
                        "#50fa7b" if feeds else "#ffb86c")

    def _run_intel_now(self):
        self._intel_run_btn.configure(state="disabled", text="Running…")
        self._intel_say("Updating threat intelligence…")

        def _work():
            try:
                from ui.core import intel_updater as iu
                result = iu.request_update(force=True)
            except Exception as exc:
                result = {"status": "failed", "error": str(exc), "feeds": {}}
            if self.winfo_exists():
                self.after(0, self._on_intel_now_done, result)

        threading.Thread(target=_work, daemon=True).start()

    def _on_intel_now_done(self, result: dict):
        self._intel_run_btn.configure(state="normal", text="Run now")
        feeds = result.get("feeds") or {}
        if result.get("via") == "service" or result.get("status") == "started":
            self._intel_say("Update started by the PolyShield service…", "#8be9fd")
            self.after(4000, self._refresh_intel_settings_status)
            return
        # Report per feed — an overall "done" hides a feed that returned 403.
        parts = [f"{n}: {i.get('status')}" for n, i in feeds.items()]
        summary = "; ".join(parts) if parts else result.get("error", "nothing to do")
        failed = [n for n, i in feeds.items() if i.get("status") == "failed"]
        self._intel_say(summary, "#ff5555" if failed else "#50fa7b")
        self._refresh_intel_settings_status()

    def _section(self, title: str, row: int):
        ctk.CTkLabel(self, text=title,
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=theme.color("accent")).grid(
            row=row, column=0, sticky="w", padx=24, pady=(12, 4))

    def _divider(self, row: int):
        ctk.CTkFrame(self, height=1, fg_color=theme.color("divider")).grid(
            row=row, column=0, sticky="ew", padx=24, pady=(16, 0))

    def _option_row(self, key: str, label: str, desc: str, row: int):
        card = ctk.CTkFrame(self, corner_radius=10, fg_color=theme.color("card"))
        card.grid(row=row, column=0, sticky="ew", padx=24, pady=4)
        card.grid_columnconfigure(0, weight=1)

        switch = ctk.CTkSwitch(card, text="", width=46,
                               command=lambda k=key: self._toggle(k))
        switch.grid(row=0, column=1, rowspan=2, padx=(8, 16), pady=14, sticky="e")
        if cfg.get(key):
            switch.select()
        else:
            switch.deselect()
        self._switches[key] = switch

        ctk.CTkLabel(card, text=label, anchor="w",
                     font=ctk.CTkFont(size=13, weight="bold")).grid(
            row=0, column=0, sticky="w", padx=16, pady=(12, 2))
        ctk.CTkLabel(card, text=desc, anchor="w", justify="left",
                     font=ctk.CTkFont(size=11), text_color=theme.color("subtext"),
                     wraplength=580).grid(
            row=1, column=0, sticky="w", padx=16, pady=(0, 12))

    def _browse_clamav(self):
        import tkinter.filedialog as fd
        path = fd.askdirectory(title="Select ClamAV install folder (containing clamscan.exe)")
        if path:
            self._clam_path_entry.delete(0, "end")
            self._clam_path_entry.insert(0, path)
            self._save_clamav_path()

    def _save_clamav_path(self):
        from ui.core import clamav_engine as ce
        path = self._clam_path_entry.get().strip()
        cfg.set_value("clamav_path", path)
        if ce.is_available():
            ver = ce.get_version()
            self._clam_feedback.configure(
                text=f"ClamAV found: {ver}", text_color="#50fa7b")
        else:
            self._clam_feedback.configure(
                text="clamscan.exe not found at that path.", text_color="#ff5555")

    def _open_yara_rules_folder(self):
        import subprocess
        from pathlib import Path
        rules_dir = Path(__file__).resolve().parents[3] / "rules" / "user_rules"
        rules_dir.mkdir(parents=True, exist_ok=True)
        subprocess.Popen(["explorer", str(rules_dir)],
                         creationflags=subprocess.CREATE_NO_WINDOW)

    # ── Ignored Hashes management (v1.9) ──────────────────────────────────────

    def _open_ignored_manager(self):
        """Modal dialog listing every entry in the local ignore list."""
        dlg = ctk.CTkToplevel(self)
        dlg.title("Ignored Hashes")
        dlg.geometry("720x460")
        dlg.configure(fg_color=theme.color("card2"))
        dlg.transient(self.winfo_toplevel())
        dlg.attributes("-topmost", True)

        dlg.grid_columnconfigure(0, weight=1)
        dlg.grid_rowconfigure(1, weight=1)

        # Header
        hdr = ctk.CTkFrame(dlg, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=20, pady=(16, 8))
        hdr.grid_columnconfigure(0, weight=1)
        title = ctk.CTkLabel(hdr, text="Ignored Hashes",
                             font=ctk.CTkFont(size=15, weight="bold"),
                             text_color=theme.color("text"))
        title.grid(row=0, column=0, sticky="w")
        count_lbl = ctk.CTkLabel(
            hdr, text="", font=ctk.CTkFont(size=11), text_color=theme.color("subtext"))
        count_lbl.grid(row=0, column=1)

        # Scrollable list
        list_frame = ctk.CTkScrollableFrame(dlg, fg_color=theme.color("card"),
                                             corner_radius=6)
        list_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=4)
        list_frame.grid_columnconfigure(0, weight=1)

        # Footer
        footer = ctk.CTkFrame(dlg, fg_color="transparent")
        footer.grid(row=2, column=0, sticky="ew", padx=20, pady=(8, 16))
        footer.grid_columnconfigure(0, weight=1)
        ctk.CTkButton(footer, text="Clear All", width=100, height=30,
                      fg_color="#5a1a1a", hover_color="#7a2020",
                      font=ctk.CTkFont(size=11),
                      command=lambda: self._ignored_clear_all(
                          list_frame, count_lbl)).grid(
            row=0, column=0, sticky="w")
        ctk.CTkButton(footer, text="Close", width=80, height=30,
                      fg_color=theme.color("input_hover"), hover_color="#4a4a5a",
                      command=dlg.destroy).grid(row=0, column=1, sticky="e")

        self._ignored_render_list(list_frame, count_lbl)

    def _ignored_render_list(self, parent: ctk.CTkFrame, count_lbl: ctk.CTkLabel):
        for w in parent.winfo_children():
            w.destroy()
        rows = ignore.list_all()
        count_lbl.configure(text=f"{len(rows)} entries")
        try:
            self._ignored_count_lbl.configure(
                text=f"Ignored hashes: {len(rows)} entries")
        except Exception:
            pass

        if not rows:
            ctk.CTkLabel(parent, text="(no ignored hashes yet)",
                         font=ctk.CTkFont(size=11), text_color=theme.color("dim")).grid(
                row=0, column=0, pady=40)
            return

        # Column headers
        head = ctk.CTkFrame(parent, fg_color="transparent")
        head.grid(row=0, column=0, sticky="ew", pady=(0, 4))
        head.grid_columnconfigure(0, weight=2)
        head.grid_columnconfigure(1, weight=3)
        head.grid_columnconfigure(2, weight=2)
        for col, label in enumerate(("File", "Note / Reason", "Added")):
            ctk.CTkLabel(head, text=label, font=ctk.CTkFont(size=10, weight="bold"),
                         text_color=theme.color("subtext"), anchor="w").grid(
                row=0, column=col, sticky="w", padx=(6, 0))

        for i, entry in enumerate(rows):
            bg = "#1e1e2e" if i % 2 == 0 else "#1a1a26"
            row_f = ctk.CTkFrame(parent, fg_color=bg, corner_radius=4)
            row_f.grid(row=i + 1, column=0, sticky="ew", pady=1)
            row_f.grid_columnconfigure(0, weight=2)
            row_f.grid_columnconfigure(1, weight=3)
            row_f.grid_columnconfigure(2, weight=2)

            fn = entry.get("filename") or "(unknown)"
            ctk.CTkLabel(row_f, text=fn, font=ctk.CTkFont(size=11),
                         text_color=theme.color("text"), anchor="w", wraplength=180).grid(
                row=0, column=0, sticky="w", padx=8, pady=4)

            note = entry.get("note") or entry.get("original_reason") or ""
            ctk.CTkLabel(row_f, text=note[:70],
                         font=ctk.CTkFont(size=10), text_color=theme.color("subtext"),
                         anchor="w", wraplength=240).grid(
                row=0, column=1, sticky="w", padx=8, pady=4)

            added = entry.get("added_utc", "")
            try:
                added_disp = datetime.fromisoformat(added).strftime("%Y-%m-%d %H:%M")
            except Exception:
                added_disp = added
            ctk.CTkLabel(row_f, text=added_disp, font=ctk.CTkFont(size=10),
                         text_color=theme.color("subtext"), anchor="w").grid(
                row=0, column=2, sticky="w", padx=8, pady=4)

            h = entry["hash"]
            ctk.CTkButton(
                row_f, text="Remove", width=70, height=22,
                fg_color="#3a1a1a", hover_color="#5a2a2a",
                font=ctk.CTkFont(size=10),
                command=lambda hh=h: self._ignored_remove_one(
                    hh, parent, count_lbl)).grid(row=0, column=3, padx=(0, 8))

    def _ignored_remove_one(self, hash_value: str, parent, count_lbl):
        ignore.remove(hash_value)
        self._ignored_render_list(parent, count_lbl)

    def _ignored_clear_all(self, parent, count_lbl):
        ignore.clear_all()
        self._ignored_render_list(parent, count_lbl)

    # ── Reusable collapsible / modal helpers (v1.10) ──────────────────────────

    def _collapsible_section(self, parent, title: str, badge: str = "",
                              start_expanded: bool = False) -> ctk.CTkFrame:
        """Header row with a chevron that expands/collapses a body frame.

        Use:
            body = self._collapsible_section(card, "Advanced", badge="2 items")
            # add rows into body — they will be shown/hidden when the chevron is clicked
        Returns the body frame.
        """
        outer = ctk.CTkFrame(parent, fg_color="transparent")
        outer.grid_columnconfigure(0, weight=1)
        # The outer .grid()-placement is left to the caller (so it can pick the row).

        header = ctk.CTkFrame(outer, fg_color="#1c1c2a", corner_radius=4)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(0, weight=1)

        body = ctk.CTkFrame(outer, fg_color="transparent")
        body.grid(row=1, column=0, sticky="ew", padx=8, pady=(2, 2))
        body.grid_columnconfigure(0, weight=1)
        if not start_expanded:
            body.grid_remove()

        state = {"expanded": start_expanded}
        lbl_text = ctk.StringVar()

        def _refresh():
            chev = "▾" if state["expanded"] else "▸"
            extra = f"   [{badge}]" if badge else ""
            lbl_text.set(f"  {chev}  {title}{extra}")

        _refresh()
        title_lbl = ctk.CTkLabel(
            header, textvariable=lbl_text, anchor="w",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=theme.color("text"))
        title_lbl.grid(row=0, column=0, sticky="w", padx=10, pady=6)

        def _toggle(_=None):
            state["expanded"] = not state["expanded"]
            if state["expanded"]:
                body.grid()
            else:
                body.grid_remove()
            _refresh()

        for w in (header, title_lbl):
            w.bind("<Button-1>", _toggle)

        # Attach the outer to its parent's grid implicitly via a wrapper helper
        body._outer_frame = outer  # so caller can .grid() the outer
        return body

    def _modal_settings_dialog(self, title: str, build_fn, width: int = 640,
                                height: int = 540) -> "ctk.CTkToplevel":
        """Open a sized CTkToplevel and call build_fn(container) to populate it.

        The dialog has a 'Close' button at the bottom that destroys the window.
        Returns the dialog instance for further customization.
        """
        dlg = ctk.CTkToplevel(self)
        dlg.title(title)
        dlg.geometry(f"{width}x{height}")
        dlg.configure(fg_color=theme.color("card2"))
        dlg.transient(self.winfo_toplevel())
        dlg.attributes("-topmost", True)

        dlg.grid_columnconfigure(0, weight=1)
        dlg.grid_rowconfigure(0, weight=1)

        container = ctk.CTkScrollableFrame(dlg, fg_color="transparent")
        container.grid(row=0, column=0, sticky="nsew", padx=12, pady=(12, 4))
        container.grid_columnconfigure(0, weight=1)

        try:
            build_fn(container)
        except Exception as exc:
            ctk.CTkLabel(container,
                         text=f"Error building dialog: {exc}",
                         text_color="#ff5555").grid(row=0, column=0, pady=20)

        # Bottom footer with a Close button
        footer = ctk.CTkFrame(dlg, fg_color="transparent")
        footer.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 12))
        footer.grid_columnconfigure(0, weight=1)
        ctk.CTkButton(footer, text="Close", width=100, height=30,
                      fg_color=theme.color("input_hover"), hover_color="#4a4a5a",
                      command=dlg.destroy).grid(row=0, column=1, sticky="e")

        return dlg

    # ── Guardian Sensitivity & Advanced (v1.10) ───────────────────────────────

    _PROFILE_DESCRIPTIONS = {
        "conservative": (
            "Conservative: pattern matches downgraded to 'Suspicious' tier; "
            "the two noisiest patterns (Ransomware note, Ransomware payment "
            "demand) are OFF by default. Best signal-to-noise for daily use."),
        "balanced": (
            "Balanced: all 7 patterns enabled, but matches are still presented "
            "as 'Suspicious' (review-only). Catches more, requires more triage."),
        "power": (
            "Power user: all 7 patterns enabled, matches treated as 'Confirmed' "
            "(no severity downgrade). Closest to the pre-v1.10 behavior. Use "
            "only if you're actively researching false positives."),
    }

    _PATTERN_LABELS = (
        "AutoRun exploit (AUTORUN.INF)",
        "Script dropper (WScript.Shell.Run)",
        "Encoded PowerShell payload",
        "MSHTA remote payload",
        "Mimikatz credential dump",
        "Ransomware note (files encrypted)",
        "Ransomware payment demand",
    )

    def _build_guardian_sensitivity_section(self, parent, start_row: int):
        """v1.10 — Sensitivity profile dropdown + 'Advanced…' button inside the
        Guardian card. Keeps the controls together with the rest of Guardian's
        settings while not requiring a full restructure of the existing rows."""
        from ui.core import settings as _cfg
        sect = ctk.CTkFrame(parent, fg_color="#15151f", corner_radius=6)
        sect.grid(row=start_row, column=0, sticky="ew", padx=12, pady=(4, 12))
        sect.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(sect, text="Sensitivity profile  (v1.10)",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color=theme.color("accent"), anchor="w").grid(
            row=0, column=0, sticky="w", padx=12, pady=(10, 4))

        # Dropdown row
        dropdown_row = ctk.CTkFrame(sect, fg_color="transparent")
        dropdown_row.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 4))
        dropdown_row.grid_columnconfigure(2, weight=1)

        profile_var = ctk.StringVar(
            value=(_cfg.get("guardian_sensitivity_profile") or "conservative"))

        desc_lbl = ctk.CTkLabel(
            sect, text=self._PROFILE_DESCRIPTIONS.get(profile_var.get(), ""),
            font=ctk.CTkFont(size=11), text_color=theme.color("subtext"),
            anchor="w", wraplength=520, justify="left")
        desc_lbl.grid(row=2, column=0, sticky="w", padx=12, pady=(0, 8))

        def _on_profile_change(value):
            _cfg.set_value("guardian_sensitivity_profile", value)
            # Clear all per-pattern overrides so the new profile's defaults take effect
            _cfg.set_value("guardian_pattern_toggles", {})
            desc_lbl.configure(text=self._PROFILE_DESCRIPTIONS.get(value, ""))
            if value == "power":
                # Show a one-time confirmation warning since this removes the
                # severity downgrade on pattern matches.
                self._show_power_profile_warning()

        ctk.CTkLabel(dropdown_row, text="Profile:",
                     font=ctk.CTkFont(size=12)).grid(row=0, column=0, padx=(0, 8))
        ctk.CTkOptionMenu(
            dropdown_row, values=["conservative", "balanced", "power"],
            variable=profile_var, command=_on_profile_change,
            width=160, height=28,
            fg_color=theme.color("divider"), button_color=theme.color("input_hover"),
            button_hover_color="#4a4a5a").grid(
            row=0, column=1, padx=(0, 8))

        adv_btn = ctk.CTkButton(
            dropdown_row, text="Advanced Guardian Settings…", width=210, height=28,
            fg_color=theme.color("input_hover"), hover_color="#4a4a5a",
            font=ctk.CTkFont(size=11),
            command=self._open_guardian_advanced)
        adv_btn.grid(row=0, column=2, sticky="e")

        # "Reset Guardian to defaults" button + feedback label
        reset_row = ctk.CTkFrame(sect, fg_color="transparent")
        reset_row.grid(row=3, column=0, sticky="ew", padx=12, pady=(0, 10))
        reset_row.grid_columnconfigure(1, weight=1)
        self._guardian_reset_lbl = ctk.CTkLabel(
            reset_row, text="", font=ctk.CTkFont(size=10), text_color="#50fa7b")
        self._guardian_reset_lbl.grid(row=0, column=1, sticky="w", padx=(8, 0))
        ctk.CTkButton(
            reset_row, text="Reset Guardian to defaults", width=190, height=26,
            fg_color="#2a2a1a", hover_color="#3a3a2a",
            font=ctk.CTkFont(size=11), text_color="#ffb86c",
            command=lambda: self._reset_guardian_to_defaults(
                profile_var, desc_lbl)).grid(
            row=0, column=0, sticky="w")

    def _show_power_profile_warning(self):
        """One-time warning when user switches to the Power profile."""
        dlg = ctk.CTkToplevel(self)
        dlg.title("Power profile activated")
        dlg.geometry("440x220")
        dlg.resizable(False, False)
        dlg.configure(fg_color=theme.color("card2"))
        dlg.transient(self.winfo_toplevel())
        dlg.attributes("-topmost", True)
        ctk.CTkLabel(dlg, text="⚠  Power profile active",
                     font=ctk.CTkFont(size=14, weight="bold"),
                     text_color="#ffb86c").pack(anchor="w", padx=20, pady=(18, 4))
        ctk.CTkLabel(
            dlg, text=("Pattern-match detections will now be treated as "
                       "'Confirmed' (red) instead of 'Suspicious' (amber). "
                       "This restores the pre-v1.10 behavior and may produce "
                       "high noise on legitimate text files / security docs."),
            font=ctk.CTkFont(size=11), text_color=theme.color("text"),
            wraplength=400, anchor="w", justify="left").pack(
            anchor="w", padx=20, pady=(0, 12))
        ctk.CTkButton(
            dlg, text="OK, got it", width=100, height=30,
            fg_color=theme.color("input_hover"), hover_color="#4a4a5a",
            command=dlg.destroy).pack(anchor="e", padx=20, pady=(0, 16))

    # Default values for all Guardian-specific settings (mirrors settings.py)
    _GUARDIAN_DEFAULTS = {
        "guardian_dual_scan":                    False,
        "guardian_use_nsrl":                     True,
        "guardian_use_patterns":                 True,
        "guardian_min_scan_bytes":               10,
        "guardian_sensitivity_profile":          "conservative",
        "guardian_pattern_toggles":              {},
        "guardian_suspicious_display":           "hidden",
        "guardian_circuit_breaker_threshold":    200,
        "guardian_autoignore_prompt_dismissed":  False,
        "watcher_guardian_patterns":             False,
    }

    def _reset_guardian_to_defaults(self, profile_var=None, desc_lbl=None):
        """Restore every Guardian setting to its factory default and refresh UI."""
        from ui.core import settings as _cfg
        for key, val in self._GUARDIAN_DEFAULTS.items():
            _cfg.set_value(key, val)
        # Sync the profile dropdown and description if they're on screen
        if profile_var is not None:
            profile_var.set("conservative")
        if desc_lbl is not None:
            desc_lbl.configure(
                text=self._PROFILE_DESCRIPTIONS.get("conservative", ""))
        # Sync scan-tier switches that live in the guardian_card
        for key in ("guardian_dual_scan", "guardian_use_nsrl", "guardian_use_patterns"):
            if key in self._switches:
                sw = self._switches[key]
                if self._GUARDIAN_DEFAULTS.get(key):
                    sw.select()
                else:
                    sw.deselect()
        # Feedback
        try:
            self._guardian_reset_lbl.configure(text="✓ Guardian settings reset to defaults")
            self.after(3000, lambda: self._guardian_reset_lbl.configure(text=""))
        except Exception:
            pass

    def _open_guardian_advanced(self):
        """Modal popup with the deep Guardian configuration: pattern toggles,
        statistics, suspicious display mode, circuit breaker threshold, watcher
        pattern toggle, auto-ignore prompt toggle."""
        self._modal_settings_dialog(
            "Advanced Guardian Settings",
            self._build_guardian_advanced_body, width=720, height=660)

    def _build_guardian_advanced_body(self, parent):
        from ui.core import settings as _cfg
        from ui.core import pattern_stats as _ps

        # ── Per-pattern toggles header row (title + reset button) ──
        toggle_hdr = ctk.CTkFrame(parent, fg_color="transparent")
        toggle_hdr.grid(row=0, column=0, sticky="ew", padx=4, pady=(6, 2))
        toggle_hdr.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(toggle_hdr, text="Per-pattern toggles",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=theme.color("accent"), anchor="w").grid(
            row=0, column=0, sticky="w")

        adv_reset_lbl = ctk.CTkLabel(
            toggle_hdr, text="", font=ctk.CTkFont(size=10), text_color="#50fa7b")
        adv_reset_lbl.grid(row=0, column=1, padx=(8, 8), sticky="e")

        # Reset to profile defaults button — lives next to the title
        reset_patterns_btn = ctk.CTkButton(
            toggle_hdr, text="Reset to profile defaults", width=180, height=26,
            fg_color="#2a2a1a", hover_color="#3a3a2a",
            font=ctk.CTkFont(size=11), text_color="#ffb86c")
        reset_patterns_btn.grid(row=0, column=2, sticky="e")

        ctk.CTkLabel(
            parent,
            text=("Disable individual heuristic patterns. Statistics show how "
                  "often each pattern fired vs. how often you added the matched "
                  "file to the ignore list — a 100% FP rate means every detection "
                  "was a false positive."),
            font=ctk.CTkFont(size=10), text_color=theme.color("subtext"),
            anchor="w", wraplength=660, justify="left").grid(
            row=1, column=0, sticky="w", padx=4, pady=(0, 8))

        # Container for the 7 pattern rows — can be rebuilt on reset
        patterns_frame = ctk.CTkFrame(parent, fg_color="transparent")
        patterns_frame.grid(row=2, column=0, sticky="ew")
        patterns_frame.grid_columnconfigure(0, weight=1)

        _CONSERVATIVE_OFF = {"Ransomware note (files encrypted)",
                              "Ransomware payment demand"}

        def _build_pattern_rows():
            """Populate (or repopulate) the pattern toggle rows inside patterns_frame."""
            for w in patterns_frame.winfo_children():
                w.destroy()
            stats_by_label = {r["pattern"]: r for r in _ps.get_stats()}
            toggles = dict(_cfg.get("guardian_pattern_toggles") or {})
            profile  = (_cfg.get("guardian_sensitivity_profile") or "conservative").lower()

            for i, label in enumerate(self._PATTERN_LABELS):
                row_f = ctk.CTkFrame(patterns_frame, fg_color="#1a1a26", corner_radius=4)
                row_f.grid(row=i, column=0, sticky="ew", padx=4, pady=2)
                row_f.grid_columnconfigure(1, weight=1)

                # Effective initial state: explicit override OR profile default
                if label in toggles:
                    initial = bool(toggles[label])
                else:
                    initial = not (profile == "conservative" and label in _CONSERVATIVE_OFF)

                sw_var = ctk.BooleanVar(value=initial)
                def _make_cb(lbl=label, var=sw_var):
                    def _cb():
                        t = dict(_cfg.get("guardian_pattern_toggles") or {})
                        t[lbl] = bool(var.get())
                        _cfg.set_value("guardian_pattern_toggles", t)
                    return _cb
                ctk.CTkSwitch(row_f, text="", width=46,
                              variable=sw_var, command=_make_cb()).grid(
                    row=0, column=0, padx=10, pady=8)

                stats = stats_by_label.get(label, {})
                det = stats.get("detections", 0)
                ign = stats.get("ignored", 0)
                fp  = stats.get("fp_rate", 0.0)
                stat_str = (
                    f"{det:,} detections, {ign:,} ignored "
                    f"({fp * 100:.0f}% FP rate)" if det else "no detections yet")
                ctk.CTkLabel(row_f, text=label,
                             font=ctk.CTkFont(size=12, weight="bold"),
                             text_color=theme.color("text"), anchor="w").grid(
                    row=0, column=1, sticky="w", padx=(0, 8), pady=(8, 0))
                ctk.CTkLabel(row_f, text=stat_str,
                             font=ctk.CTkFont(size=10),
                             text_color=("#ff8888" if fp > 0.5 else "#888888"),
                             anchor="w").grid(
                    row=1, column=1, sticky="w", padx=(0, 8), pady=(0, 8))

        def _reset_to_profile_defaults():
            _cfg.set_value("guardian_pattern_toggles", {})
            _build_pattern_rows()
            adv_reset_lbl.configure(text="✓ Reset to profile defaults")
            patterns_frame.after(
                3000, lambda: adv_reset_lbl.configure(text="")
                if adv_reset_lbl.winfo_exists() else None)

        reset_patterns_btn.configure(command=_reset_to_profile_defaults)
        _build_pattern_rows()

        next_row = 3

        # ── Suspicious display mode ──
        ctk.CTkLabel(parent, text="Suspicious tier display",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=theme.color("accent"), anchor="w").grid(
            row=next_row, column=0, sticky="w", padx=4, pady=(14, 4))
        next_row += 1
        ctk.CTkLabel(
            parent,
            text=("How heuristic-only ('Suspicious') findings appear in the "
                  "Scan view's Threat Actions panel:"),
            font=ctk.CTkFont(size=10), text_color=theme.color("subtext"), anchor="w",
            wraplength=660).grid(row=next_row, column=0, sticky="w", padx=4, pady=(0, 6))
        next_row += 1

        sd_var = ctk.StringVar(value=(_cfg.get("guardian_suspicious_display") or "hidden"))
        for key, label, desc in [
            ("hidden",
             "Hidden by default",
             "Only shown via the 'Suspicious (N)' filter chip. Cleanest default."),
            ("collapsible",
             "Collapsible sub-section",
             "Confirmed at top, then a 'Heuristic Findings ▸/▾' header below."),
            ("inline",
             "Inline with CONFIRMED / SUSPICIOUS badge",
             "All rows in one list; each row carries a colored severity badge."),
        ]:
            rb_f = ctk.CTkFrame(parent, fg_color="transparent")
            rb_f.grid(row=next_row, column=0, sticky="ew", padx=4, pady=1)
            rb_f.grid_columnconfigure(1, weight=1)
            ctk.CTkRadioButton(
                rb_f, text="", variable=sd_var, value=key,
                command=lambda v=key: _cfg.set_value("guardian_suspicious_display", v),
                width=22).grid(row=0, column=0, padx=(8, 6), pady=(4, 0))
            ctk.CTkLabel(rb_f, text=label,
                         font=ctk.CTkFont(size=12, weight="bold"),
                         anchor="w").grid(row=0, column=1, sticky="w")
            ctk.CTkLabel(rb_f, text=desc,
                         font=ctk.CTkFont(size=10), text_color=theme.color("subtext"),
                         anchor="w", wraplength=560).grid(
                row=1, column=1, sticky="w", padx=(0, 0), pady=(0, 4))
            next_row += 1

        # ── Circuit breaker threshold ──
        ctk.CTkLabel(parent, text="Circuit breaker threshold",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=theme.color("accent"), anchor="w").grid(
            row=next_row, column=0, sticky="w", padx=4, pady=(14, 4))
        next_row += 1
        ctk.CTkLabel(
            parent,
            text=("If Guardian's pattern tier produces more than this many "
                  "matches in one scan, it auto-disables for the remainder "
                  "(hash tiers keep running). 0 = disabled."),
            font=ctk.CTkFont(size=10), text_color=theme.color("subtext"), anchor="w",
            wraplength=660).grid(row=next_row, column=0, sticky="w", padx=4, pady=(0, 4))
        next_row += 1

        cb_row = ctk.CTkFrame(parent, fg_color="transparent")
        cb_row.grid(row=next_row, column=0, sticky="w", padx=4, pady=(0, 8))
        cb_var = ctk.StringVar(
            value=str(_cfg.get("guardian_circuit_breaker_threshold") or 0))
        ctk.CTkOptionMenu(
            cb_row, values=["0", "50", "100", "200", "500", "1000"],
            variable=cb_var,
            command=lambda v: _cfg.set_value(
                "guardian_circuit_breaker_threshold", int(v)),
            width=140, height=28,
            fg_color=theme.color("divider"), button_color=theme.color("input_hover")).grid(
            row=0, column=0, sticky="w")
        next_row += 1

        # ── Watcher pattern tier toggle ──
        ctk.CTkLabel(parent, text="Real-time (watcher) pattern tier",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=theme.color("accent"), anchor="w").grid(
            row=next_row, column=0, sticky="w", padx=4, pady=(14, 4))
        next_row += 1
        wp_row = ctk.CTkFrame(parent, fg_color="transparent")
        wp_row.grid(row=next_row, column=0, sticky="ew", padx=4, pady=(0, 4))
        wp_row.grid_columnconfigure(1, weight=1)
        wp_var = ctk.BooleanVar(value=bool(_cfg.get("watcher_guardian_patterns")))
        ctk.CTkSwitch(
            wp_row, text="", variable=wp_var, width=46,
            command=lambda: _cfg.set_value(
                "watcher_guardian_patterns", bool(wp_var.get()))).grid(
            row=0, column=0, padx=(8, 6), pady=4)
        ctk.CTkLabel(wp_row,
                     text="Run heuristic patterns at real-time scanner speed",
                     font=ctk.CTkFont(size=12), anchor="w").grid(
            row=0, column=1, sticky="w")
        next_row += 1
        ctk.CTkLabel(
            parent,
            text=("OFF by default: pattern false positives at watcher cadence "
                  "(every new file in Downloads/Desktop/USB) cascade quickly. "
                  "Hash-based detection still runs. Turn on only if you're "
                  "actively testing heuristic coverage."),
            font=ctk.CTkFont(size=10), text_color=theme.color("subtext"), anchor="w",
            wraplength=660).grid(row=next_row, column=0, sticky="w", padx=4, pady=(0, 8))
        next_row += 1

        # ── Auto-ignore prompt ──
        ap_row = ctk.CTkFrame(parent, fg_color="transparent")
        ap_row.grid(row=next_row, column=0, sticky="ew", padx=4, pady=(8, 4))
        ap_row.grid_columnconfigure(1, weight=1)
        ap_var = ctk.BooleanVar(
            value=(not bool(_cfg.get("guardian_autoignore_prompt_dismissed"))))
        ctk.CTkSwitch(
            ap_row, text="", variable=ap_var, width=46,
            command=lambda: _cfg.set_value(
                "guardian_autoignore_prompt_dismissed",
                not bool(ap_var.get()))).grid(
            row=0, column=0, padx=(8, 6), pady=4)
        ctk.CTkLabel(ap_row,
                     text="Prompt to disable a pattern after 3+ ignores in one scan",
                     font=ctk.CTkFont(size=12), anchor="w").grid(
            row=0, column=1, sticky="w")

    def _toggle(self, key: str):
        cfg.set_value(key, bool(self._switches[key].get()))

    def _toggle_launch_as_admin(self):
        from pathlib import Path
        enabled = bool(self._admin_switch.get())
        cfg.set_value("launch_as_admin", enabled)
        self._rewrite_launch_vbs(enabled)

    def _rewrite_launch_vbs(self, as_admin: bool):
        from pathlib import Path
        vbs_path = Path(__file__).resolve().parents[3] / "launch_ui.vbs"
        if as_admin:
            content = (
                'Dim base\n'
                'base = Left(WScript.ScriptFullName, InStrRev(WScript.ScriptFullName, "\\"))\n'
                '\n'
                'Dim pythonw : pythonw = base & "kicomav_env\\Scripts\\pythonw.exe"\n'
                'Dim script  : script  = base & "src\\ui\\app.py"\n'
                '\n'
                'CreateObject("WScript.Shell").ShellExecute pythonw, '
                '"""" & script & """", "", "runas", 1\n'
            )
        else:
            content = (
                'Dim base\n'
                'base = Left(WScript.ScriptFullName, InStrRev(WScript.ScriptFullName, "\\"))\n'
                '\n'
                'Dim pythonw : pythonw = base & "kicomav_env\\Scripts\\pythonw.exe"\n'
                'Dim script  : script  = base & "src\\ui\\app.py"\n'
                '\n'
                'CreateObject("WScript.Shell").Run """" & pythonw & """ """ & script & """", 0, False\n'
            )
        try:
            vbs_path.write_text(content, encoding="utf-8")
            state = "enabled" if as_admin else "disabled"
            self._admin_feedback.configure(
                text=f"Admin launch {state} — takes effect on next launch.",
                text_color="#50fa7b" if as_admin else "#888888")
        except Exception as exc:
            self._admin_feedback.configure(
                text=f"Could not write launch_ui.vbs: {exc}",
                text_color="#ff5555")

    def _toggle_context_menu(self):
        from ui.core import shell_ext as sx
        enabled = bool(self._ctx_switch.get())
        if enabled:
            ok, msg = sx.register()
        else:
            ok, msg = sx.unregister()
        cfg.set_value("context_menu_enabled", enabled)
        registered = sx.is_registered()
        self._ctx_status_lbl.configure(
            text="Registered" if registered else "Not registered",
            text_color="#50fa7b" if registered else "#888888")
        if not ok:
            self._ctx_status_lbl.configure(text=f"Error: {msg}", text_color="#ff5555")

    def _save_vt_key(self):
        key = self._vt_key_entry.get().strip()
        cfg.set_value("vt_api_key", key)
        if key:
            self._vt_feedback.configure(
                text="API key saved.", text_color="#50fa7b")
        else:
            self._vt_feedback.configure(
                text="Key cleared.", text_color=theme.color("subtext"))

    def _test_vt_key(self):
        """
        Validate the current API key with a single benign VT lookup.

        Uses the EICAR MD5 (44d88612fea8a8f36de82e1278abb02f) — always present
        in the VT database, never changes, costs one of the 4 req/min free quota.
        Runs in a background thread so the UI stays responsive.
        """
        key = self._vt_key_entry.get().strip()
        if not key:
            self._vt_feedback.configure(
                text="No key to test — enter or paste a key first.",
                text_color=theme.color("subtext"))
            return
        self._vt_test_btn.configure(state="disabled", text="Testing…")
        self._vt_feedback.configure(text="Contacting VirusTotal…", text_color=theme.color("subtext"))

        def _run():
            import urllib.request, urllib.error
            url = ("https://www.virustotal.com/api/v3/files/"
                   "44d88612fea8a8f36de82e1278abb02f")
            req = urllib.request.Request(url, headers={"x-apikey": key})
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    resp.read()
                text, color = "✓ Key valid", "#50fa7b"
            except urllib.error.HTTPError as exc:
                if exc.code in (401, 403):
                    text, color = "✗ Invalid key (unauthorized)", "#ff5555"
                else:
                    text, color = f"HTTP {exc.code}", "#ffb86c"
            except Exception as exc:
                text, color = str(exc)[:60], "#ffb86c"
            if self.winfo_exists():
                self.after(0, lambda t=text, c=color: self._on_vt_test_done(t, c))

        threading.Thread(target=_run, daemon=True).start()

    def _on_vt_test_done(self, text: str, color: str) -> None:
        self._vt_feedback.configure(text=text, text_color=color)
        try:
            self._vt_test_btn.configure(state="normal", text="Test Key")
        except Exception:
            pass

    def _toggle_show_key(self):
        show = self._show_key_var.get() == "1"
        self._vt_key_entry.configure(show="" if show else "•")

    def _browse_sandboxie(self):
        import tkinter.filedialog as fd
        path = fd.askopenfilename(
            title="Select Sandboxie-Plus Start.exe",
            filetypes=[("Sandboxie Start", "Start.exe"), ("Executable", "*.exe")])
        if path:
            self._sb_path_entry.delete(0, "end")
            self._sb_path_entry.insert(0, path)
            self._save_sandboxie_path()

    def _save_sandboxie_path(self):
        from ui.core import sandbox_engine as se
        path = self._sb_path_entry.get().strip()
        cfg.set_value("sandboxie_path", path)
        status = se.get_status()
        if status == "ready":
            self._sb_feedback.configure(
                text="Sandboxie-Plus ready.", text_color="#50fa7b")
        else:
            self._sb_feedback.configure(
                text=f"Status: {status}", text_color="#ffb86c")
