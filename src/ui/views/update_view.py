"""
update_view.py — Unified Update Center
────────────────────────────────────────
Five independent update sections:

  1. K2 Engine Signatures  – k2.exe virus definitions via sc.run_update()
  2. Guardian AI Engine    – git pull on the guardianai/ clone
  3. Local Intelligence DB – MalwareBazaar threat data (recent 24 h or full MD5 list)
                           + optional NSRL known-safe import
  4. Speakeasy Emulator    – pip install --upgrade speakeasy-emulator in kicomav_env
  5. Sandboxie-Plus        – check latest GitHub release, open browser to download

A shared log at the bottom records output from whichever updates run.
An "Update All" button at the top triggers sections 1–4 in sequence
(Sandboxie is excluded — portable download must be done manually).
"""
import subprocess
import threading
from pathlib import Path
from tkinter import filedialog

import customtkinter as ctk

from ui.core import scanner as sc
from ui.core import guardian_engine as ge
import ui.theme as theme
from ui.core import paths

#: Below this, k2 is running on the signatures compiled into its plugin
#: modules alone -- the downloaded rule archives are missing.
_K2_BASELINE_ONLY = 100

_TAG_OK        = "ok"
_TAG_ERR       = "err"
_TAG_INFO      = "info"
_TAG_K2        = "k2"
_TAG_GUARDIAN  = "guardian"
_TAG_INTEL     = "intel"
_TAG_SPEAKEASY = "speakeasy"
_TAG_SANDBOXIE = "sandboxie"
_TAG_C2        = "c2"
_TAG_YARA      = "yara"
_TAG_CLAMAV    = "clamav"

_NO_WINDOW = subprocess.CREATE_NO_WINDOW

# Project root (three levels above this file's directory: src/ui/views/file.py)


class UpdateView(ctk.CTkScrollableFrame):
    def __init__(self, master, status_callback, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self._status_cb = status_callback
        # Per-section updating flags
        self._upd_k2     = False
        self._upd_guardian  = False
        self._upd_intel     = False
        self._upd_speakeasy = False
        self._upd_c2        = False
        self._upd_yara      = False
        self._upd_all       = False
        self._build()
        self._refresh_all_info()

    # ── Build ──────────────────────────────────────────────────────────────────

    def _build(self):
        self.grid_columnconfigure(0, weight=1)

        # ── Page title + Update All button ──
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=24, pady=(20, 6))
        header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(header, text="Update Center",
                     font=ctk.CTkFont(size=22, weight="bold")).grid(
            row=0, column=0, sticky="w")

        self._update_all_btn = ctk.CTkButton(
            header, text="⟳  Update All", width=140,
            fg_color=theme.color("accent"), hover_color=theme.color("accent_hover"),
            font=ctk.CTkFont(size=13),
            command=self._run_update_all)
        self._update_all_btn.grid(row=0, column=1, padx=(0, 0))

        # Auto-update status — so the manual buttons below read as a supplement
        # to the schedule rather than the only way to stay current.
        self._auto_status_lbl = ctk.CTkLabel(
            header, text="", anchor="w", font=ctk.CTkFont(size=11),
            text_color=theme.color("subtext"))
        self._auto_status_lbl.grid(row=1, column=0, columnspan=2, sticky="w",
                                   pady=(2, 0))
        self._refresh_auto_status()

        # ── Section 1: K2 Engine Signatures ──
        self._build_k2_section(row=1)

        # ── Section 2: Guardian AI Engine ──
        self._build_guardian_section(row=2)

        # ── Section 3: Local Intelligence Database ──
        self._build_intel_section(row=3)

        # ── Section 4: Speakeasy Emulator ──
        self._build_speakeasy_section(row=4)

        # ── Section 5: Sandboxie-Plus ──
        self._build_sandboxie_section(row=5)

        # ── Section 6: C2 IP Blocklist ──
        self._build_c2_section(row=6)

        # ── Section 7: YARA Community Rules ──
        self._build_yara_section(row=7)

        # ── Section 8: ClamAV Engine ──
        self._build_clamav_section(row=8)

        # ── Divider before log ──
        ctk.CTkFrame(self, height=1, fg_color=theme.color("divider")).grid(
            row=9, column=0, sticky="ew", padx=24, pady=(4, 0))

        # ── Shared log ──
        log_label = ctk.CTkLabel(self, text="Update Log",
                                  font=ctk.CTkFont(size=12, weight="bold"),
                                  text_color=theme.color("dim"))
        log_label.grid(row=9, column=0, sticky="w", padx=28, pady=(6, 2))

        self._log = ctk.CTkTextbox(
            self, font=ctk.CTkFont(family="Consolas", size=11),
            wrap="word", state="disabled", height=220)
        self._log.grid(row=10, column=0, sticky="ew", padx=24, pady=(0, 16))

        self._log.tag_config(_TAG_OK,        foreground="#50fa7b")
        self._log.tag_config(_TAG_ERR,       foreground="#ff5555")
        self._log.tag_config(_TAG_INFO,      foreground=theme.color("text"))
        self._log.tag_config(_TAG_K2,         foreground="#8be9fd")
        self._log.tag_config(_TAG_GUARDIAN,  foreground="#bd93f9")
        self._log.tag_config(_TAG_INTEL,     foreground="#f1fa8c")
        self._log.tag_config(_TAG_SPEAKEASY, foreground="#50fa7b")
        self._log.tag_config(_TAG_SANDBOXIE, foreground="#ffb86c")
        self._log.tag_config(_TAG_C2,        foreground="#ff79c6")
        self._log.tag_config(_TAG_YARA,      foreground="#bd93f9")
        self._log.tag_config(_TAG_CLAMAV,    foreground="#8be9fd")

    # ── Section builders ───────────────────────────────────────────────────────

    def _build_k2_section(self, row: int):
        """K2 engine signature definitions card."""
        card = ctk.CTkFrame(self, corner_radius=10, fg_color=theme.color("card"))
        card.grid(row=row, column=0, sticky="ew", padx=24, pady=(0, 8))
        card.grid_columnconfigure(1, weight=1)

        # Left badge-title
        ctk.CTkLabel(card, text="K2 Engine Signatures",
                     font=ctk.CTkFont(size=14, weight="bold"),
                     text_color="#8be9fd").grid(
            row=0, column=0, columnspan=2, sticky="w", padx=16, pady=(12, 4))

        # Info row
        info_row = ctk.CTkFrame(card, fg_color="transparent")
        info_row.grid(row=1, column=0, columnspan=2, sticky="ew", padx=16, pady=(0, 4))
        info_row.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(info_row, text="Last updated:",
                     font=ctk.CTkFont(size=12), text_color=theme.color("subtext")).grid(
            row=0, column=0, sticky="w")
        self._k2_date = ctk.CTkLabel(info_row, text="—",
                                         font=ctk.CTkFont(size=12))
        self._k2_date.grid(row=0, column=1, sticky="w", padx=8)

        ctk.CTkLabel(info_row, text="Signature files:",
                     font=ctk.CTkFont(size=12), text_color=theme.color("subtext")).grid(
            row=1, column=0, sticky="w")
        self._k2_files = ctk.CTkLabel(info_row, text="—",
                                          font=ctk.CTkFont(size=12))
        self._k2_files.grid(row=1, column=1, sticky="w", padx=8)

        # The count the engine reports, not the number of files downloaded.
        # k2 carries ~23 signatures in its plugins and the other ~1240 arrive in
        # archives -- and it reports success when it cannot fetch them, so an
        # install can end up at under 2% detection with nothing saying so.
        ctk.CTkLabel(info_row, text="Signatures:",
                     font=ctk.CTkFont(size=12), text_color=theme.color("subtext")).grid(
            row=2, column=0, sticky="w")
        self._k2_sigs = ctk.CTkLabel(info_row, text="checking…",
                                     font=ctk.CTkFont(size=12))
        self._k2_sigs.grid(row=2, column=1, sticky="w", padx=8)

        # Buttons + status badge
        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.grid(row=2, column=0, columnspan=2, sticky="ew",
                     padx=16, pady=(4, 12))
        btn_row.grid_columnconfigure(1, weight=1)

        self._k2_btn = ctk.CTkButton(
            btn_row, text="Update Now", width=130,
            fg_color=theme.color("accent"), hover_color=theme.color("accent_hover"),
            font=ctk.CTkFont(size=12),
            command=self._run_k2_update)
        self._k2_btn.grid(row=0, column=0, padx=(0, 12))

        self._k2_badge = ctk.CTkLabel(
            btn_row, text="", width=200,
            corner_radius=6, fg_color="#2a2a2a",
            font=ctk.CTkFont(size=11))
        self._k2_badge.grid(row=0, column=1, sticky="w")

    def _build_guardian_section(self, row: int):
        """Guardian AI engine / git pull card."""
        guardian_dir = paths.guardian_dir()
        is_present = guardian_dir.is_dir()

        card = ctk.CTkFrame(self, corner_radius=10, fg_color=theme.color("card"))
        card.grid(row=row, column=0, sticky="ew", padx=24, pady=(0, 8))
        card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(card, text="Guardian AI Engine",
                     font=ctk.CTkFont(size=14, weight="bold"),
                     text_color="#bd93f9").grid(
            row=0, column=0, columnspan=2, sticky="w", padx=16, pady=(12, 4))

        # Status / description
        if is_present:
            desc = "Updates the guardianai/ clone via git pull (scanner code + pattern rules)."
        else:
            desc = "Guardian AI is not installed. Run setup_guardian.bat first."

        ctk.CTkLabel(card, text=desc, anchor="w",
                     font=ctk.CTkFont(size=11), text_color=theme.color("subtext")).grid(
            row=1, column=0, columnspan=2, sticky="w", padx=16, pady=(0, 4))

        # Show current commit hash if repo exists
        self._guardian_commit_lbl = ctk.CTkLabel(
            card, text="", anchor="w",
            font=ctk.CTkFont(size=11), text_color=theme.color("subtext"))
        self._guardian_commit_lbl.grid(row=2, column=0, columnspan=2,
                                        sticky="w", padx=16, pady=(0, 4))

        # Buttons row
        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.grid(row=3, column=0, columnspan=2, sticky="ew",
                     padx=16, pady=(4, 12))
        btn_row.grid_columnconfigure(1, weight=1)

        self._guardian_btn = ctk.CTkButton(
            btn_row, text="Pull Latest", width=130,
            fg_color="#4a2a7a" if is_present else "#3a3a3a",
            hover_color="#6a3aaa" if is_present else "#3a3a3a",
            state="normal" if is_present else "disabled",
            font=ctk.CTkFont(size=12),
            command=self._run_guardian_update)
        self._guardian_btn.grid(row=0, column=0, padx=(0, 12))

        self._guardian_badge = ctk.CTkLabel(
            btn_row, text="—" if not is_present else "",
            width=200, corner_radius=6, fg_color="#2a2a2a",
            font=ctk.CTkFont(size=11),
            text_color=theme.color("subtext"))
        self._guardian_badge.grid(row=0, column=1, sticky="w")

    def _build_intel_section(self, row: int):
        """Local Intelligence Database (MalwareBazaar + NSRL) card."""
        card = ctk.CTkFrame(self, corner_radius=10, fg_color=theme.color("card"))
        card.grid(row=row, column=0, sticky="ew", padx=24, pady=(0, 8))
        card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(card, text="Local Intelligence Database",
                     font=ctk.CTkFont(size=14, weight="bold"),
                     text_color="#f1fa8c").grid(
            row=0, column=0, columnspan=3, sticky="w", padx=16, pady=(12, 4))

        # DB stats row
        stats_row = ctk.CTkFrame(card, fg_color="transparent")
        stats_row.grid(row=1, column=0, columnspan=3, sticky="ew",
                       padx=16, pady=(0, 4))
        stats_row.grid_columnconfigure(0, weight=1)

        self._intel_malicious_lbl = ctk.CTkLabel(
            stats_row, text="🛡  Known-bad hashes: —",
            anchor="w", font=ctk.CTkFont(size=11), text_color=theme.color("subtext"))
        self._intel_malicious_lbl.grid(row=0, column=0, sticky="w")

        self._intel_safe_lbl = ctk.CTkLabel(
            stats_row, text="✅  Known-safe (NSRL): —",
            anchor="w", font=ctk.CTkFont(size=11), text_color=theme.color("subtext"))
        self._intel_safe_lbl.grid(row=1, column=0, sticky="w")

        self._intel_date_lbl = ctk.CTkLabel(
            stats_row, text="🕒  Last updated: —",
            anchor="w", font=ctk.CTkFont(size=11), text_color=theme.color("subtext"))
        self._intel_date_lbl.grid(row=2, column=0, sticky="w", pady=(0, 4))

        # Buttons row
        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.grid(row=2, column=0, columnspan=3, sticky="ew",
                     padx=16, pady=(4, 4))

        self._intel_recent_btn = ctk.CTkButton(
            btn_row, text="↓  MalwareBazaar Recent (24 h)", width=250,
            fg_color="#3a3a1a", hover_color="#5a5a2a",
            font=ctk.CTkFont(size=12),
            command=self._run_intel_recent)
        self._intel_recent_btn.grid(row=0, column=0, padx=(0, 8))

        self._intel_full_btn = ctk.CTkButton(
            btn_row, text="↓  Full MD5 List", width=140,
            fg_color="#2a2a2a", hover_color=theme.color("divider"),
            font=ctk.CTkFont(size=12),
            command=self._run_intel_full)
        self._intel_full_btn.grid(row=0, column=1, padx=(0, 8))

        self._intel_nsrl_btn = ctk.CTkButton(
            btn_row, text="Import NSRL…", width=120,
            fg_color="#2a2a2a", hover_color=theme.color("divider"),
            font=ctk.CTkFont(size=11),
            command=self._run_nsrl_import)
        self._intel_nsrl_btn.grid(row=0, column=2, padx=(0, 8))

        self._intel_clear_btn = ctk.CTkButton(
            btn_row, text="🗑  Clear DB", width=110,
            fg_color="#4a1a1a", hover_color="#6a2a2a",
            font=ctk.CTkFont(size=11),
            command=self._confirm_clear_db)
        self._intel_clear_btn.grid(row=0, column=3)

        # Status badge (below buttons)
        self._intel_badge = ctk.CTkLabel(
            card, text="", anchor="w",
            font=ctk.CTkFont(size=11), text_color=theme.color("subtext"))
        self._intel_badge.grid(row=3, column=0, columnspan=3,
                                sticky="w", padx=16, pady=(2, 10))

    def _build_speakeasy_section(self, row: int):
        """Speakeasy PE emulator — pip upgrade card."""
        card = ctk.CTkFrame(self, corner_radius=10, fg_color=theme.color("card"))
        card.grid(row=row, column=0, sticky="ew", padx=24, pady=(0, 8))
        card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(card, text="Speakeasy Emulator",
                     font=ctk.CTkFont(size=14, weight="bold"),
                     text_color="#50fa7b").grid(
            row=0, column=0, columnspan=2, sticky="w", padx=16, pady=(12, 4))

        info_row = ctk.CTkFrame(card, fg_color="transparent")
        info_row.grid(row=1, column=0, columnspan=2, sticky="ew", padx=16, pady=(0, 4))
        info_row.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(info_row, text="Installed:",
                     font=ctk.CTkFont(size=12), text_color=theme.color("subtext")).grid(
            row=0, column=0, sticky="w")
        self._speakeasy_version_lbl = ctk.CTkLabel(info_row, text="checking…",
                                                    font=ctk.CTkFont(size=12))
        self._speakeasy_version_lbl.grid(row=0, column=1, sticky="w", padx=8)

        ctk.CTkLabel(info_row, text="Latest (PyPI):",
                     font=ctk.CTkFont(size=12), text_color=theme.color("subtext")).grid(
            row=1, column=0, sticky="w")
        self._speakeasy_latest_lbl = ctk.CTkLabel(info_row, text="—",
                                                   font=ctk.CTkFont(size=12))
        self._speakeasy_latest_lbl.grid(row=1, column=1, sticky="w", padx=8)

        ctk.CTkLabel(card,
                     text="Updates speakeasy-emulator in kicomav_env (the project's portable venv).",
                     font=ctk.CTkFont(size=11), text_color=theme.color("subtext"), anchor="w").grid(
            row=2, column=0, columnspan=2, sticky="w", padx=16, pady=(0, 4))

        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.grid(row=3, column=0, columnspan=2, sticky="ew",
                     padx=16, pady=(4, 12))
        btn_row.grid_columnconfigure(2, weight=1)

        self._speakeasy_btn = ctk.CTkButton(
            btn_row, text="Update Now", width=130,
            fg_color="#1a4a1a", hover_color="#2a6a2a",
            font=ctk.CTkFont(size=12),
            command=self._run_speakeasy_update)
        self._speakeasy_btn.grid(row=0, column=0, padx=(0, 8))

        _sp_pypi_btn = ctk.CTkButton(
            btn_row, text="Check PyPI", width=110,
            fg_color="#2a2a2a", hover_color=theme.color("divider"),
            font=ctk.CTkFont(size=12),
            command=self._check_speakeasy_latest)
        _sp_pypi_btn.grid(row=0, column=1, padx=(0, 12))

        self._speakeasy_badge = ctk.CTkLabel(
            btn_row, text="", width=200,
            corner_radius=6, fg_color="#2a2a2a",
            font=ctk.CTkFont(size=11))
        self._speakeasy_badge.grid(row=0, column=2, sticky="w")

    def _build_sandboxie_section(self, row: int):
        """Sandboxie-Plus — version check + GitHub release link card."""
        card = ctk.CTkFrame(self, corner_radius=10, fg_color=theme.color("card"))
        card.grid(row=row, column=0, sticky="ew", padx=24, pady=(0, 8))
        card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(card, text="Sandboxie-Plus",
                     font=ctk.CTkFont(size=14, weight="bold"),
                     text_color="#ffb86c").grid(
            row=0, column=0, columnspan=2, sticky="w", padx=16, pady=(12, 4))

        info_row = ctk.CTkFrame(card, fg_color="transparent")
        info_row.grid(row=1, column=0, columnspan=2, sticky="ew", padx=16, pady=(0, 4))
        info_row.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(info_row, text="Installed:",
                     font=ctk.CTkFont(size=12), text_color=theme.color("subtext")).grid(
            row=0, column=0, sticky="w")
        self._sandboxie_version_lbl = ctk.CTkLabel(info_row, text="checking…",
                                                    font=ctk.CTkFont(size=12))
        self._sandboxie_version_lbl.grid(row=0, column=1, sticky="w", padx=8)

        ctk.CTkLabel(info_row, text="Latest (GitHub):",
                     font=ctk.CTkFont(size=12), text_color=theme.color("subtext")).grid(
            row=1, column=0, sticky="w")
        self._sandboxie_latest_lbl = ctk.CTkLabel(info_row, text="—",
                                                   font=ctk.CTkFont(size=12))
        self._sandboxie_latest_lbl.grid(row=1, column=1, sticky="w", padx=8)

        ctk.CTkLabel(card,
                     text="Sandboxie-Plus must be updated manually (portable build).\n"
                          "'Check Latest' queries GitHub, then opens the release page for download.",
                     font=ctk.CTkFont(size=11), text_color=theme.color("subtext"),
                     anchor="w", justify="left").grid(
            row=2, column=0, columnspan=2, sticky="w", padx=16, pady=(0, 4))

        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.grid(row=3, column=0, columnspan=2, sticky="ew",
                     padx=16, pady=(4, 12))
        btn_row.grid_columnconfigure(2, weight=1)

        self._sandboxie_check_btn = ctk.CTkButton(
            btn_row, text="Check Latest", width=130,
            fg_color="#3a2a1a", hover_color="#5a4a2a",
            font=ctk.CTkFont(size=12),
            command=self._check_sandboxie_latest)
        self._sandboxie_check_btn.grid(row=0, column=0, padx=(0, 8))

        _sb_gh_btn = ctk.CTkButton(
            btn_row, text="↗  GitHub Releases", width=150,
            fg_color="#2a2a2a", hover_color=theme.color("divider"),
            font=ctk.CTkFont(size=12),
            command=lambda: __import__("webbrowser").open(
                "https://github.com/sandboxie-plus/Sandboxie/releases"))
        _sb_gh_btn.grid(row=0, column=1, padx=(0, 12))

        self._sandboxie_badge = ctk.CTkLabel(
            btn_row, text="", width=200,
            corner_radius=6, fg_color="#2a2a2a",
            font=ctk.CTkFont(size=11))
        self._sandboxie_badge.grid(row=0, column=2, sticky="w")

    def _build_c2_section(self, row: int):
        """Feodo Tracker C2 IP Blocklist card."""
        card = ctk.CTkFrame(self, corner_radius=10, fg_color=theme.color("card"))
        card.grid(row=row, column=0, sticky="ew", padx=24, pady=(0, 8))
        card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(card, text="C2 IP Blocklist  —  Feodo Tracker",
                     font=ctk.CTkFont(size=14, weight="bold"),
                     text_color="#ff79c6").grid(
            row=0, column=0, columnspan=2, sticky="w", padx=16, pady=(12, 4))

        ctk.CTkLabel(
            card,
            text="Feodo Tracker 30-day IOC feed + ThreatFox 6-month IP feed (abuse.ch).\n"
                 "Used by the Network Monitor to flag outbound C2 connections in real time.\n"
                 "Low counts are normal during Feodo takedown gaps — ThreatFox covers the shortfall.",
            font=ctk.CTkFont(size=11), text_color=theme.color("subtext"), anchor="w", justify="left",
        ).grid(row=1, column=0, columnspan=2, sticky="w", padx=16, pady=(0, 4))

        # Stats row
        stats_row = ctk.CTkFrame(card, fg_color="transparent")
        stats_row.grid(row=2, column=0, columnspan=2, sticky="ew", padx=16, pady=(0, 4))
        stats_row.grid_columnconfigure(0, weight=1)

        self._c2_count_lbl = ctk.CTkLabel(
            stats_row, text="🌐  Blocked IPs: —",
            anchor="w", font=ctk.CTkFont(size=11), text_color=theme.color("subtext"))
        self._c2_count_lbl.grid(row=0, column=0, sticky="w")

        self._c2_date_lbl = ctk.CTkLabel(
            stats_row, text="🕒  Last updated: —",
            anchor="w", font=ctk.CTkFont(size=11), text_color=theme.color("subtext"))
        self._c2_date_lbl.grid(row=1, column=0, sticky="w")

        # Buttons row
        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.grid(row=3, column=0, columnspan=2, sticky="ew",
                     padx=16, pady=(4, 12))
        btn_row.grid_columnconfigure(1, weight=1)

        self._c2_btn = ctk.CTkButton(
            btn_row, text="↓  Update C2 Blocklist", width=190,
            fg_color="#3a1a3a", hover_color="#5a2a5a",
            font=ctk.CTkFont(size=12),
            command=self._run_c2_update)
        self._c2_btn.grid(row=0, column=0, padx=(0, 8))

        self._c2_badge = ctk.CTkLabel(
            btn_row, text="", width=200,
            corner_radius=6, fg_color="#2a2a2a",
            font=ctk.CTkFont(size=11))
        self._c2_badge.grid(row=0, column=1, sticky="w")

    def _build_yara_section(self, row: int):
        """YARA Forge community rules — download + auto-extract card."""
        card = ctk.CTkFrame(self, corner_radius=10, fg_color=theme.color("card"))
        card.grid(row=row, column=0, sticky="ew", padx=24, pady=(0, 8))
        card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(card, text="YARA Community Rules",
                     font=ctk.CTkFont(size=14, weight="bold"),
                     text_color="#bd93f9").grid(
            row=0, column=0, columnspan=2, sticky="w", padx=16, pady=(12, 4))

        info_row = ctk.CTkFrame(card, fg_color="transparent")
        info_row.grid(row=1, column=0, columnspan=2, sticky="ew", padx=16, pady=(0, 4))
        info_row.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(info_row, text="Installed:",
                     font=ctk.CTkFont(size=12), text_color=theme.color("subtext")).grid(
            row=0, column=0, sticky="w")
        self._yara_version_lbl = ctk.CTkLabel(info_row, text="checking…",
                                               font=ctk.CTkFont(size=12))
        self._yara_version_lbl.grid(row=0, column=1, sticky="w", padx=8)

        ctk.CTkLabel(info_row, text="Latest (GitHub):",
                     font=ctk.CTkFont(size=12), text_color=theme.color("subtext")).grid(
            row=1, column=0, sticky="w")
        self._yara_latest_lbl = ctk.CTkLabel(info_row, text="—",
                                              font=ctk.CTkFont(size=12))
        self._yara_latest_lbl.grid(row=1, column=1, sticky="w", padx=8)

        ctk.CTkLabel(card,
                     text="YARA Forge weekly rule set — community-maintained detections.\n"
                          "Rules saved to rules/community/ and loaded automatically alongside custom rules.",
                     font=ctk.CTkFont(size=11), text_color=theme.color("subtext"),
                     anchor="w", justify="left").grid(
            row=2, column=0, columnspan=2, sticky="w", padx=16, pady=(0, 4))

        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.grid(row=3, column=0, columnspan=2, sticky="ew",
                     padx=16, pady=(4, 12))
        btn_row.grid_columnconfigure(2, weight=1)

        self._yara_dl_btn = ctk.CTkButton(
            btn_row, text="↓  Download Latest", width=150,
            fg_color="#2a1a4a", hover_color="#4a2a7a",
            font=ctk.CTkFont(size=12),
            command=self._run_yara_update)
        self._yara_dl_btn.grid(row=0, column=0, padx=(0, 8))

        _ya_gh_btn = ctk.CTkButton(
            btn_row, text="↗  GitHub Releases", width=150,
            fg_color="#2a2a2a", hover_color=theme.color("divider"),
            font=ctk.CTkFont(size=12),
            command=lambda: __import__("webbrowser").open(
                "https://github.com/YARAHQ/yara-forge/releases"))
        _ya_gh_btn.grid(row=0, column=1, padx=(0, 12))

        self._yara_badge = ctk.CTkLabel(
            btn_row, text="", width=200,
            corner_radius=6, fg_color="#2a2a2a",
            font=ctk.CTkFont(size=11))
        self._yara_badge.grid(row=0, column=2, sticky="w")

    def _build_clamav_section(self, row: int):
        """ClamAV Engine — version check + download page link card."""
        card = ctk.CTkFrame(self, corner_radius=10, fg_color=theme.color("card"))
        card.grid(row=row, column=0, sticky="ew", padx=24, pady=(0, 8))
        card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(card, text="ClamAV Engine",
                     font=ctk.CTkFont(size=14, weight="bold"),
                     text_color="#8be9fd").grid(
            row=0, column=0, columnspan=2, sticky="w", padx=16, pady=(12, 4))

        info_row = ctk.CTkFrame(card, fg_color="transparent")
        info_row.grid(row=1, column=0, columnspan=2, sticky="ew", padx=16, pady=(0, 4))
        info_row.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(info_row, text="Installed:",
                     font=ctk.CTkFont(size=12), text_color=theme.color("subtext")).grid(
            row=0, column=0, sticky="w")
        self._clamav_version_lbl = ctk.CTkLabel(info_row, text="checking…",
                                                 font=ctk.CTkFont(size=12))
        self._clamav_version_lbl.grid(row=0, column=1, sticky="w", padx=8)

        ctk.CTkLabel(info_row, text="Latest (GitHub):",
                     font=ctk.CTkFont(size=12), text_color=theme.color("subtext")).grid(
            row=1, column=0, sticky="w")
        self._clamav_latest_lbl = ctk.CTkLabel(info_row, text="—",
                                                font=ctk.CTkFont(size=12))
        self._clamav_latest_lbl.grid(row=1, column=1, sticky="w", padx=8)

        ctk.CTkLabel(card,
                     text="Open-source signature engine by Cisco Talos. Download the Windows MSI\n"
                          "installer from clamav.net, then configure the path in Settings → ClamAV.",
                     font=ctk.CTkFont(size=11), text_color=theme.color("subtext"),
                     anchor="w", justify="left").grid(
            row=2, column=0, columnspan=2, sticky="w", padx=16, pady=(0, 4))

        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.grid(row=3, column=0, columnspan=2, sticky="ew",
                     padx=16, pady=(4, 12))
        btn_row.grid_columnconfigure(2, weight=1)

        self._clamav_check_btn = ctk.CTkButton(
            btn_row, text="Check Latest", width=130,
            fg_color="#1a2a3a", hover_color="#2a3a5a",
            font=ctk.CTkFont(size=12),
            command=self._check_clamav_latest)
        self._clamav_check_btn.grid(row=0, column=0, padx=(0, 8))

        _cl_dl_btn = ctk.CTkButton(
            btn_row, text="↗  Download Page", width=150,
            fg_color="#2a2a2a", hover_color=theme.color("divider"),
            font=ctk.CTkFont(size=12),
            command=lambda: __import__("webbrowser").open(
                "https://www.clamav.net/downloads"))
        _cl_dl_btn.grid(row=0, column=1, padx=(0, 12))

        self._clamav_badge = ctk.CTkLabel(
            btn_row, text="", width=200,
            corner_radius=6, fg_color="#2a2a2a",
            font=ctk.CTkFont(size=11))
        self._clamav_badge.grid(row=0, column=2, sticky="w")

    # ── Info refresh ───────────────────────────────────────────────────────────

    def _refresh_all_info(self):
        self._refresh_k2_info()
        self._refresh_guardian_info()
        self._refresh_intel_info()
        self._refresh_speakeasy_info()
        self._refresh_sandboxie_info()
        self._refresh_c2_info()
        self._refresh_yara_info()
        self._refresh_clamav_info()

    @staticmethod
    def _age_suffix(state: str, age_hours) -> tuple[str, str]:
        """Return (suffix, colour) describing how old a feed's data is."""
        colours = {"fresh": "#50fa7b", "aging": "#ffb86c", "stale": "#ff5555",
                   "never": "#ff5555", "auth_required": "#ffb86c"}
        if age_hours is None:
            return ("  —  never updated" if state == "never" else ""), \
                   colours.get(state, "")
        if age_hours < 1:
            age = "just now"
        elif age_hours < 48:
            age = f"{int(age_hours)}h ago"
        else:
            age = f"{int(age_hours / 24)}d ago"
        return f"  ({age})", colours.get(state, "")

    def _feed_state(self, feed: str) -> dict:
        try:
            from ui.core import intel_updater as iu
            return iu.get_staleness().get(feed, {})
        except Exception:
            return {}

    def _apply_age(self, lbl, feed: str, base_text: str) -> None:
        """Append the freshness age (and colour) to a 'Last updated' label."""
        info = self._feed_state(feed)
        suffix, colour = self._age_suffix(info.get("state", ""), info.get("age_hours"))
        try:
            lbl.configure(text=base_text + suffix,
                          text_color=colour or theme.color("subtext"))
        except Exception:
            pass

    def _refresh_auto_status(self) -> None:
        try:
            from ui.core import service_client as svc
            from ui.core import settings as _cfg      # this module has no cfg alias
            enabled = bool(_cfg.get("intel_auto_update"))
            hours = int(_cfg.get("intel_update_interval_hours") or 12)
            last = _cfg.get("intel_last_auto_run") or ""
            feeds = _cfg.get("intel_auto_feeds") or []
            if not enabled:
                text = "Automatic updates: OFF — these feeds only refresh when you click."
                colour = "#ffb86c"
            else:
                if svc.is_service_running():
                    when = f"every {hours}h via the PolyShield service"
                else:
                    when = ("at launch only — start the service for scheduled "
                            "refreshes")
                text = (f"Automatic updates: {when}  ·  "
                        f"{', '.join(feeds) if feeds else 'no feeds selected'}")
                if last:
                    text += f"  ·  last run {last.replace('T', ' ')} UTC"
                colour = theme.color("subtext") if feeds else "#ffb86c"
            self._auto_status_lbl.configure(text=text, text_color=colour)
        except Exception as exc:
            # Never blank: a silent failure here reads as "no schedule exists".
            try:
                self._auto_status_lbl.configure(
                    text=f"Automatic updates: status unavailable ({exc})",
                    text_color="#ffb86c")
            except Exception:
                pass

    def _refresh_c2_info(self):
        try:
            paths.bootstrap_sys_path()
            from tools.update_intelligence import get_c2_blocklist_stats
            stats = get_c2_blocklist_stats()
            count   = stats.get("total", 0)
            updated = stats.get("last_update", "Never")
            self._c2_count_lbl.configure(
                text=f"🌐  Blocked IPs: {count:,}" if count else
                     "🌐  Blocked IPs: none yet — click Update to import")
            self._apply_age(self._c2_date_lbl, "c2", f"🕒  Last updated: {updated}")
        except Exception:
            pass

    def _refresh_yara_info(self):
        """Installed version, age and readable rule count; query GitHub for latest.

        Reads the intelligence metadata rather than rules/community/.version.
        The version file records WHAT is installed but not WHEN, and it stays
        put even when the rules beside it cannot be read — so on its own it can
        report a healthy-looking version over a rule set the engine cannot load.
        get_yara_info() carries the install timestamp and the count of rules
        actually visible, which is the pair worth showing.
        """
        try:
            from tools.update_intelligence import get_yara_info
            info = get_yara_info()
        except Exception:
            info = {"version": "", "last_update": "", "rule_count": 0}

        version = info.get("version") or "Not installed"
        count = int(info.get("rule_count") or 0)

        def _apply():
            if version == "Not installed":
                self._yara_version_lbl.configure(text=version, text_color="#888888")
                return
            if count:
                base = f"{version}   ·   {count} rule file{'' if count == 1 else 's'}"
            else:
                base = f"{version}   ·   no readable rules"
            self._apply_age(self._yara_version_lbl, "yara", base)
            if not count:
                # Published, dated, and still unusable. This is the state a
                # freshness-only reading calls healthy.
                self._yara_version_lbl.configure(text_color="#ff5555")

        if self.winfo_exists():
            self.after(0, _apply)

        def _fetch_latest():
            import urllib.request, json as _json
            try:
                url = "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest"
                req = urllib.request.Request(url, headers={"User-Agent": "PolyShield/1.5"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = _json.loads(resp.read().decode("utf-8"))
                tag = data.get("tag_name", "unknown")
            except Exception:
                tag = "—"
            if self.winfo_exists():
                self.after(0, lambda v=tag: self._yara_latest_lbl.configure(
                    text=v, text_color=theme.color("text") if v != "—" else "#888888"))

        threading.Thread(target=_fetch_latest, daemon=True).start()

    def _refresh_clamav_info(self):
        """Read installed ClamAV version (background)."""
        def _run():
            try:
                from ui.core import clamav_engine as ce
                installed = ce.get_version() or "Not installed"
            except Exception:
                installed = "Not installed"
            if self.winfo_exists():
                self.after(0, lambda v=installed: self._clamav_version_lbl.configure(
                    text=v, text_color=theme.color("text") if v != "Not installed" else "#888888"))
        threading.Thread(target=_run, daemon=True).start()

    def _refresh_k2_info(self):
        try:
            info = sc.get_update_cfg_info()
            self._k2_date.configure(text=info["last_updated"])
            lines = [l for l in info["raw"].splitlines() if l.strip()]
            self._k2_files.configure(text=str(len(lines)))
        except Exception:
            pass

        # Off the UI thread: --vlist starts k2 and enumerates every plugin.
        def _count():
            n = sc.get_signature_count()
            if not self.winfo_exists():
                return
            if n == 0:
                text, colour = "unavailable", "#ff5555"
            elif n < _K2_BASELINE_ONLY:
                text = f"{n:,} — built-in only; run Update Now to download the rest"
                colour = "#ffb86c"
            else:
                text, colour = f"{n:,}", theme.color("text")
            self.after(0, lambda t=text, c=colour:
                       self._k2_sigs.configure(text=t, text_color=c))

        threading.Thread(target=_count, daemon=True).start()

    def _refresh_guardian_info(self):
        guardian_dir = paths.guardian_dir()
        if not guardian_dir.is_dir():
            return
        try:
            r = subprocess.run(
                ["git", "-C", str(guardian_dir), "log", "--oneline", "-1"],
                capture_output=True, text=True, timeout=5,
                creationflags=_NO_WINDOW)
            commit = r.stdout.strip() if r.returncode == 0 else "—"
        except Exception:
            commit = "—"
        if hasattr(self, "_guardian_commit_lbl"):
            self._guardian_commit_lbl.configure(
                text=f"  Current: {commit}" if commit != "—" else "")

    def _refresh_intel_info(self):
        try:
            stats = ge.get_db_stats()
            malicious = stats.get("known_bad", 0)
            safe      = stats.get("known_safe", 0)
            updated   = stats.get("last_updated", "Never")

            self._intel_malicious_lbl.configure(
                text=f"🛡  Known-bad hashes: {malicious:,}" if malicious else
                     "🛡  Known-bad hashes: none yet — fetch MalwareBazaar data")
            self._intel_safe_lbl.configure(
                text=f"✅  Known-safe (NSRL): {safe:,}" if safe else
                     "✅  Known-safe (NSRL): none yet — import NSRL CSV to enable allow-listing")
            self._apply_age(self._intel_date_lbl, "malwarebazaar",
                            f"🕒  Last updated: {updated}")
        except Exception:
            pass

    # Development-environment sections
    #
    # Two of the five update sections drive the *development* environment:
    # Speakeasy is pip-installed into kicomav_env, and Guardian AI is a git
    # clone. A distribution has neither, so paths.venv_pip() and
    # paths.guardian_dir() name directories that are simply not there.
    #
    # They did report -- Popen raised and the handler logged str(exc) -- but
    # what reached the log was "[WinError 2] The system cannot find the file
    # specified", which reads as a broken installation rather than as a section
    # that does not apply to this one.

    _NOT_IN_BUILD = ("not available in an installed build: it updates the "
                     "development environment, which a distribution does not ship")

    def _dev_only_unavailable(self, section: str, tag: str) -> bool:
        """True (and logged) when `section` cannot run in this installation."""
        if not paths.is_distribution():
            return False
        self._log_section_header(section, tag)
        self._log_append(f"  [SKIP] {section} is {self._NOT_IN_BUILD}.\n", _TAG_ERR)
        self._status_cb(f"{section}: not available in an installed build")
        return True

    def _refresh_speakeasy_info(self):
        """Read installed speakeasy-emulator version via pip show (background)."""
        if paths.is_distribution():
            # pip show interrogates the development virtualenv. Reporting "not
            # installed" from a build states something about the product that
            # this check cannot actually determine.
            self._speakeasy_version_lbl.configure(text="n/a in an installed build")
            return

        def _run():
            pip = str(paths.venv_pip())
            try:
                r = subprocess.run(
                    [pip, "show", "speakeasy-emulator"],
                    capture_output=True, text=True, timeout=15,
                    creationflags=_NO_WINDOW)
                version = "not installed"
                for line in r.stdout.splitlines():
                    if line.startswith("Version:"):
                        version = line.split(":", 1)[1].strip()
                        break
            except Exception:
                version = "not installed"
            if self.winfo_exists():
                self.after(0, lambda v=version: self._speakeasy_version_lbl.configure(text=v))
        threading.Thread(target=_run, daemon=True).start()

    def _refresh_sandboxie_info(self):
        """Read installed Sandboxie-Plus version from Start.exe file properties (background)."""
        def _run():
            from ui.core import settings as cfg
            start_path = cfg.get("sandboxie_path") or ""
            if not start_path or not Path(start_path).exists():
                if self.winfo_exists():
                    self.after(0, lambda: self._sandboxie_version_lbl.configure(
                        text="not configured", text_color=theme.color("subtext")))
                return
            try:
                r = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     f"(Get-Item '{start_path}').VersionInfo.FileVersion"],
                    capture_output=True, text=True, timeout=10,
                    creationflags=_NO_WINDOW)
                version = r.stdout.strip() or "unknown"
            except Exception:
                version = "unknown"
            if self.winfo_exists():
                self.after(0, lambda v=version: self._sandboxie_version_lbl.configure(
                    text=v, text_color=theme.color("text")))
        threading.Thread(target=_run, daemon=True).start()

    # ── K2 engine signatures update ────────────────────────────────────────────

    def _run_k2_update(self):
        if self._upd_k2 or self._upd_all:
            return
        self._upd_k2 = True
        self._set_k2_busy(True)
        self._log_section_header("K2 Engine Signatures", _TAG_K2)
        self._status_cb("Updating K2 engine signatures…")
        sc.run_update(self._on_k2_line, self._on_k2_done)

    def _on_k2_line(self, line: str):
        self.after(0, self._log_append, f"  {line}", _TAG_K2)

    def _on_k2_done(self, returncode: int):
        def _upd():
            self._upd_k2 = False
            self._set_k2_busy(False)
            if returncode == 0:
                self._k2_badge.configure(text="  ✓ Up to date  ",
                                             text_color="#50fa7b")
                self._log_append("  [DONE] Signatures updated successfully.\n", _TAG_OK)
                self._status_cb("K2 engine signatures updated")
            else:
                self._k2_badge.configure(text=f"  ✗ Failed (code {returncode})  ",
                                             text_color="#ff5555")
                self._log_append(f"  [ERROR] Finished with code {returncode}.\n", _TAG_ERR)
                self._status_cb("K2 engine update failed")
            self._refresh_k2_info()
            if self._upd_all:
                self._run_guardian_update()
        self.after(0, _upd)

    def _set_k2_busy(self, busy: bool):
        if busy:
            self._k2_btn.configure(state="disabled", text="Updating…")
            self._k2_badge.configure(text="  Updating…  ", text_color="#ffb86c")
        else:
            self._k2_btn.configure(state="normal", text="Update Now")

    # ── Guardian AI update ─────────────────────────────────────────────────────

    def _run_guardian_update(self):
        if self._upd_guardian:
            return
        guardian_dir = paths.guardian_dir()
        if not guardian_dir.is_dir():
            remedy = (self._NOT_IN_BUILD if paths.is_distribution()
                      else "run scripts\\components\\setup_guardian.bat first")
            self._log_append(f"  [SKIP] Guardian AI is {remedy}.\n", _TAG_ERR)
            if self._upd_all:
                self._run_intel_recent()
            return

        self._upd_guardian = True
        self._set_guardian_busy(True)
        self._log_section_header("Guardian AI Engine", _TAG_GUARDIAN)
        self._status_cb("Updating Guardian AI engine…")

        def _pull():
            try:
                r = subprocess.run(
                    ["git", "-C", str(guardian_dir), "pull", "--ff-only"],
                    capture_output=True, text=True, timeout=60,
                    creationflags=_NO_WINDOW)
                output = (r.stdout + r.stderr).strip()
                ok = r.returncode == 0
            except Exception as exc:
                output = str(exc)
                ok = False

            if self.winfo_exists():
                self.after(0, self._on_guardian_done, ok, output)

        threading.Thread(target=_pull, daemon=True).start()

    def _on_guardian_done(self, ok: bool, output: str):
        self._upd_guardian = False
        self._set_guardian_busy(False)
        for line in output.splitlines():
            self._log_append(f"  {line}", _TAG_GUARDIAN)
        if ok:
            self._guardian_badge.configure(text="  ✓ Up to date  ",
                                            text_color="#50fa7b")
            self._log_append("  [DONE] Guardian AI engine updated.\n", _TAG_OK)
            self._status_cb("Guardian AI engine updated")
        else:
            self._guardian_badge.configure(text="  ✗ Pull failed  ",
                                            text_color="#ff5555")
            self._log_append("  [ERROR] git pull failed — check network/repo.\n", _TAG_ERR)
            self._status_cb("Guardian AI update failed")
        self._refresh_guardian_info()
        if self._upd_all:
            self._run_intel_recent()

    def _set_guardian_busy(self, busy: bool):
        if busy:
            self._guardian_btn.configure(state="disabled", text="Pulling…")
            self._guardian_badge.configure(text="  Pulling…  ", text_color="#ffb86c")
        else:
            guardian_dir = paths.guardian_dir()
            ok = guardian_dir.is_dir()
            self._guardian_btn.configure(
                state="normal" if ok else "disabled",
                text="Pull Latest")

    # ── Local Intelligence update ──────────────────────────────────────────────

    def _run_intel_recent(self):
        self._run_intel("recent")

    def _run_intel_full(self):
        self._run_intel("full")

    def _run_intel(self, mode: str):
        if self._upd_intel:
            return
        self._upd_intel = True
        self._set_intel_busy(True, mode)
        self._log_section_header(
            f"Local Intelligence DB — {'Recent 24 h' if mode == 'recent' else 'Full MD5 List'}",
            _TAG_INTEL)
        self._status_cb("Fetching MalwareBazaar intelligence…")

        def _run():
            try:
                import sys
                paths.bootstrap_sys_path()
                from tools.update_intelligence import run_update

                def _on_progress(msg: str):
                    if self.winfo_exists():
                        self.after(0, self._log_append, f"  {msg}", _TAG_INTEL)
                        # Lambda, not a positional dict: CTk's configure() is
                        # (require_redraw=False, **kwargs), so a dict passed
                        # positionally binds to require_redraw and the badge
                        # silently never changes.  See CLAUDE.md.
                        self.after(0, lambda m=msg: self._intel_badge.configure(
                            text=m[:90], text_color="#ffb86c"))

                result = run_update(on_progress=_on_progress, mode=mode)

                from ui.core.guardian_engine import reload_signatures
                reload_signatures()

                if self.winfo_exists():
                    self.after(0, self._on_intel_done, result)
            except Exception as exc:
                if self.winfo_exists():
                    self.after(0, self._on_intel_done, {"error": str(exc)})

        threading.Thread(target=_run, daemon=True).start()

    def _on_intel_done(self, result: dict):
        self._upd_intel = False
        self._set_intel_busy(False)
        if "error" in result:
            self._intel_badge.configure(
                text=f"  ✗ {result['error'][:80]}  ", text_color="#ff5555")
            self._log_append(f"  [ERROR] {result['error']}\n", _TAG_ERR)
            self._status_cb("Intelligence DB update failed")
        else:
            added = result.get("added", 0)
            total = result.get("total_db", 0)
            summary = f"✓ Added {added:,}  |  DB total: {total:,} hashes  |  Signatures reloaded"
            self._intel_badge.configure(text=f"  {summary}  ", text_color="#50fa7b")
            self._log_append(f"  [DONE] {summary}\n", _TAG_OK)
            self._status_cb("Intelligence DB updated")
        self._refresh_intel_info()
        if self._upd_all:
            self._run_speakeasy_update()

    def _run_nsrl_import(self):
        """Let the user pick a NSRL CSV/TSV file and import it."""
        if self._upd_intel:
            return
        path = filedialog.askopenfilename(
            title="Select NSRL hash file (NSRLFile.txt / CSV)",
            filetypes=[("Text / CSV", "*.txt *.csv"), ("All files", "*.*")])
        if not path:
            return

        self._upd_intel = True
        self._set_intel_busy(True, "nsrl")
        self._log_section_header("Local Intelligence DB — NSRL Import", _TAG_INTEL)
        self._status_cb("Importing NSRL…")

        def _run():
            try:
                import sys
                paths.bootstrap_sys_path()
                from tools.update_intelligence import import_nsrl

                def _on_progress(msg: str):
                    if self.winfo_exists():
                        self.after(0, self._log_append, f"  {msg}", _TAG_INTEL)
                        self.after(0, lambda m=msg: self._intel_badge.configure(
                            text=m[:90], text_color="#ffb86c"))

                result = import_nsrl(path, on_progress=_on_progress)
                if self.winfo_exists():
                    self.after(0, self._on_intel_done, result if isinstance(result, dict) else {})
            except Exception as exc:
                if self.winfo_exists():
                    self.after(0, self._on_intel_done, {"error": str(exc)})

        threading.Thread(target=_run, daemon=True).start()

    def _confirm_clear_db(self):
        """Show a modal confirmation before wiping the malicious hash table."""
        if self._upd_intel:
            return
        # Read current count for the dialog message
        try:
            paths.bootstrap_sys_path()
            from tools.update_intelligence import get_stats
            count = get_stats().get("malicious", 0)
        except Exception:
            count = 0

        dlg = ctk.CTkToplevel(self)
        dlg.title("Clear Intelligence DB")
        dlg.geometry("460x200")
        dlg.resizable(False, False)
        dlg.grab_set()
        dlg.focus_force()
        dlg.configure(fg_color=theme.color("card2"))

        # Center over parent window
        self.update_idletasks()
        px = self.winfo_rootx() + self.winfo_width()  // 2 - 230
        py = self.winfo_rooty() + self.winfo_height() // 2 - 100
        dlg.geometry(f"+{px}+{py}")

        ctk.CTkLabel(
            dlg,
            text="Clear Malicious Hash Database?",
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color="#ff5555",
        ).pack(pady=(20, 6))

        body = (
            f"This will permanently delete {count:,} known-bad hash"
            f"{'es' if count != 1 else ''} from the local DB\n"
            "and clear known_bad.txt.  The NSRL safe table is not affected.\n\n"
            "After clearing you can fetch just the recent 24 h list for a clean start."
        )
        ctk.CTkLabel(dlg, text=body, font=ctk.CTkFont(size=12),
                     text_color=theme.color("text"), justify="center").pack(pady=(0, 16))

        btn_row = ctk.CTkFrame(dlg, fg_color="transparent")
        btn_row.pack()

        ctk.CTkButton(
            btn_row, text="Cancel", width=110,
            fg_color=theme.color("divider"), hover_color=theme.color("input_hover"),
            command=dlg.destroy,
        ).grid(row=0, column=0, padx=(0, 12))

        ctk.CTkButton(
            btn_row, text="🗑  Clear DB", width=130,
            fg_color="#7a1a1a", hover_color="#aa2a2a",
            command=lambda: (dlg.destroy(), self._run_clear_db()),
        ).grid(row=0, column=1)

    def _run_clear_db(self):
        if self._upd_intel:
            return
        self._upd_intel = True
        self._set_intel_busy(True, "clear")
        self._log_section_header("Local Intelligence DB — Clear", _TAG_INTEL)
        self._status_cb("Clearing intelligence database…")

        def _run():
            try:
                import sys
                paths.bootstrap_sys_path()
                from tools.update_intelligence import clear_malicious_db

                def _on_progress(msg: str):
                    if self.winfo_exists():
                        self.after(0, self._log_append, f"  {msg}", _TAG_INTEL)

                result = clear_malicious_db(on_progress=_on_progress)

                from ui.core.guardian_engine import reload_signatures
                reload_signatures()

                if self.winfo_exists():
                    self.after(0, self._on_clear_done, result)
            except Exception as exc:
                if self.winfo_exists():
                    self.after(0, self._on_clear_done, {"ok": False, "error": str(exc)})

        threading.Thread(target=_run, daemon=True).start()

    def _on_clear_done(self, result: dict):
        self._upd_intel = False
        self._set_intel_busy(False)
        if result.get("ok"):
            deleted = result.get("deleted", 0)
            msg = f"✓ Cleared {deleted:,} hashes — DB is empty. Fetch Recent 24h to repopulate."
            self._intel_badge.configure(text=f"  {msg}  ", text_color="#ffb86c")
            self._log_append(f"  [DONE] {msg}\n", _TAG_OK)
            self._status_cb("Intelligence DB cleared")
        else:
            err = result.get("error", "unknown error")
            self._intel_badge.configure(text=f"  ✗ Clear failed: {err[:60]}  ",
                                         text_color="#ff5555")
            self._log_append(f"  [ERROR] {err}\n", _TAG_ERR)
            self._status_cb("Intelligence DB clear failed")
        self._refresh_intel_info()

    def _set_intel_busy(self, busy: bool, mode: str = ""):
        if busy:
            label = ("Fetching recent…"  if mode == "recent" else
                     "Fetching full list…" if mode == "full"   else
                     "Importing NSRL…"   if mode == "nsrl"    else
                     "Clearing DB…")
            self._intel_recent_btn.configure(state="disabled")
            self._intel_full_btn.configure(state="disabled")
            self._intel_nsrl_btn.configure(state="disabled")
            self._intel_clear_btn.configure(state="disabled")
            self._intel_badge.configure(text=f"  {label}  ", text_color="#ffb86c")
        else:
            self._intel_recent_btn.configure(state="normal")
            self._intel_full_btn.configure(state="normal")
            self._intel_nsrl_btn.configure(state="normal")
            self._intel_clear_btn.configure(state="normal")

    # ── C2 Blocklist update ────────────────────────────────────────────────────

    def _run_c2_update(self):
        if self._upd_c2:
            return
        self._upd_c2 = True
        self._c2_btn.configure(state="disabled", text="Fetching…")
        self._c2_badge.configure(text="  Fetching…  ", text_color="#ffb86c")
        self._log_section_header("C2 IP Blocklist — Feodo Tracker", _TAG_C2)
        self._status_cb("Fetching C2 IP blocklist…")

        def _run():
            try:
                import sys
                paths.bootstrap_sys_path()
                from tools.update_intelligence import import_c2_blocklist

                def _on_progress(msg: str):
                    if self.winfo_exists():
                        self.after(0, self._log_append, f"  {msg}", _TAG_C2)

                result = import_c2_blocklist(on_progress=_on_progress)
                if self.winfo_exists():
                    self.after(0, self._on_c2_done, result)
            except Exception as exc:
                if self.winfo_exists():
                    self.after(0, self._on_c2_done, {"error": str(exc)})

        threading.Thread(target=_run, daemon=True).start()

    def _on_c2_done(self, result: dict):
        self._upd_c2 = False
        self._c2_btn.configure(state="normal", text="↓  Update C2 Blocklist")
        if "error" in result:
            self._c2_badge.configure(
                text=f"  ✗ {result['error'][:70]}  ", text_color="#ff5555")
            self._log_append(f"  [ERROR] {result['error']}\n", _TAG_ERR)
            self._status_cb("C2 blocklist update failed")
        else:
            added   = result.get("added", 0)
            updated = result.get("updated", 0)
            total   = result.get("total_db", 0)
            summary = f"✓ +{added:,} new, {updated:,} refreshed  |  Total: {total:,} IPs"
            self._c2_badge.configure(text=f"  {summary}  ", text_color="#50fa7b")
            self._log_append(f"  [DONE] {summary}\n", _TAG_OK)
            self._status_cb(f"C2 blocklist updated — {total:,} IPs")
        self._refresh_c2_info()
        if self._upd_all:
            self._run_yara_update()

    # ── Speakeasy update ───────────────────────────────────────────────────────

    def _check_speakeasy_latest(self):
        """Query PyPI for the latest speakeasy-emulator version (background)."""
        self._speakeasy_latest_lbl.configure(text="querying PyPI…", text_color=theme.color("subtext"))

        def _run():
            try:
                import urllib.request, json as _json
                url = "https://pypi.org/pypi/speakeasy-emulator/json"
                req = urllib.request.Request(url, headers={"User-Agent": "PolyShield/1.1"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = _json.loads(resp.read().decode("utf-8"))
                latest = data["info"]["version"]
            except Exception as exc:
                latest = f"error: {str(exc)[:40]}"
            if self.winfo_exists():
                self.after(0, lambda v=latest: self._speakeasy_latest_lbl.configure(
                    text=v, text_color=theme.color("text") if not v.startswith("error") else "#ff5555"))

        threading.Thread(target=_run, daemon=True).start()

    def _run_speakeasy_update(self):
        if self._upd_speakeasy:
            return
        if self._dev_only_unavailable("Speakeasy Emulator", _TAG_SPEAKEASY):
            return

        self._upd_speakeasy = True
        self._set_speakeasy_busy(True)
        self._log_section_header("Speakeasy Emulator", _TAG_SPEAKEASY)
        self._status_cb("Updating Speakeasy emulator…")

        pip = str(paths.venv_pip())

        def _run():
            try:
                proc = subprocess.Popen(
                    [pip, "install", "--upgrade", "speakeasy-emulator"],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, encoding="utf-8", errors="replace",
                    creationflags=_NO_WINDOW)
                lines = []
                for raw in proc.stdout:
                    line = raw.rstrip()
                    lines.append(line)
                    if self.winfo_exists():
                        self.after(0, self._log_append, f"  {line}", _TAG_SPEAKEASY)
                proc.wait()
                ok = proc.returncode == 0
                output = "\n".join(lines)
            except Exception as exc:
                ok = False
                output = str(exc)

            if self.winfo_exists():
                self.after(0, self._on_speakeasy_done, ok, output)

        threading.Thread(target=_run, daemon=True).start()

    def _on_speakeasy_done(self, ok: bool, output: str):
        self._upd_speakeasy = False
        self._set_speakeasy_busy(False)
        if ok:
            # Extract new version from pip output ("Successfully installed speakeasy-emulator-X.Y.Z")
            version = "—"
            for line in output.splitlines():
                if "successfully installed" in line.lower() and "speakeasy" in line.lower():
                    parts = line.split()
                    for p in parts:
                        if p.lower().startswith("speakeasy-emulator-"):
                            version = p.split("-")[-1]
                            break
            self._speakeasy_badge.configure(
                text=f"  ✓ Updated{' to ' + version if version != '—' else ''}  ",
                text_color="#50fa7b")
            self._log_append(f"  [DONE] Speakeasy emulator updated.\n", _TAG_OK)
            self._status_cb("Speakeasy emulator updated")
        else:
            self._speakeasy_badge.configure(text="  ✗ Update failed  ", text_color="#ff5555")
            self._log_append("  [ERROR] pip upgrade failed — check log above.\n", _TAG_ERR)
            self._status_cb("Speakeasy update failed")
        self._refresh_speakeasy_info()
        if self._upd_all:
            self._run_c2_update()

    def _set_speakeasy_busy(self, busy: bool):
        if busy:
            self._speakeasy_btn.configure(state="disabled", text="Updating…")
            self._speakeasy_badge.configure(text="  Updating…  ", text_color="#ffb86c")
        else:
            self._speakeasy_btn.configure(state="normal", text="Update Now")

    # ── Sandboxie-Plus version check ───────────────────────────────────────────

    def _check_sandboxie_latest(self):
        """Query GitHub API for the latest Sandboxie-Plus release (background)."""
        self._sandboxie_check_btn.configure(state="disabled", text="Checking…")
        self._sandboxie_latest_lbl.configure(text="querying GitHub…", text_color=theme.color("subtext"))
        self._log_section_header("Sandboxie-Plus", _TAG_SANDBOXIE)

        def _run():
            import webbrowser
            try:
                import urllib.request, json as _json
                url = "https://api.github.com/repos/sandboxie-plus/Sandboxie/releases/latest"
                req = urllib.request.Request(
                    url, headers={"User-Agent": "PolyShield/1.1",
                                  "Accept": "application/vnd.github+json"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = _json.loads(resp.read().decode("utf-8"))
                tag = data.get("tag_name", "unknown")
                name = data.get("name", tag)
                published = data.get("published_at", "")[:10]
                release_url = data.get("html_url", "")
                ok = True
            except Exception as exc:
                tag = name = f"error: {str(exc)[:50]}"
                published = release_url = ""
                ok = False

            def _upd():
                self._sandboxie_check_btn.configure(state="normal", text="Check Latest")
                self._sandboxie_latest_lbl.configure(
                    text=f"{tag} ({published})" if published else tag,
                    text_color=theme.color("text") if ok else "#ff5555")
                if ok:
                    self._sandboxie_badge.configure(
                        text=f"  Latest: {name}  ", text_color="#ffb86c")
                    self._log_append(
                        f"  Latest release: {name}  ({published})\n"
                        f"  Download at: {release_url}", _TAG_SANDBOXIE)
                    self._log_append(
                        "  [NOTE] Manual download required — extract portable build to "
                        "your Sandboxie folder and replace existing files.\n", _TAG_INFO)
                    if release_url:
                        webbrowser.open(release_url)
                else:
                    self._sandboxie_badge.configure(
                        text=f"  ✗ Check failed  ", text_color="#ff5555")
                    self._log_append(f"  [ERROR] {tag}\n", _TAG_ERR)
                self._status_cb(f"Sandboxie latest: {tag}")

            if self.winfo_exists():
                self.after(0, _upd)

        threading.Thread(target=_run, daemon=True).start()

    # ── YARA Community Rules download ──────────────────────────────────────────

    def _run_yara_update(self):
        if self._upd_yara:
            return
        self._upd_yara = True
        self._yara_dl_btn.configure(state="disabled", text="Downloading…")
        self._yara_badge.configure(text="  Downloading…  ", text_color="#ffb86c")
        self._log_section_header("YARA Community Rules", _TAG_YARA)
        self._status_cb("Downloading YARA community rules…")

        import urllib.request as _urlreq
        import zipfile as _zipfile
        import json as _json
        import tempfile as _tempfile

        def _run():
            community_dir = paths.rules_dir() / "community"
            tmp_path = None
            try:
                # 1. Query GitHub releases API
                url = "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest"
                req = _urlreq.Request(url, headers={"User-Agent": "PolyShield/1.5"})
                with _urlreq.urlopen(req, timeout=15) as resp:
                    release = _json.loads(resp.read().decode("utf-8"))
                tag = release["tag_name"]

                # 2. Check if already up to date
                ver_file = community_dir / ".version"
                if ver_file.exists() and ver_file.read_text(encoding="utf-8").strip() == tag:
                    if self.winfo_exists():
                        self.after(0, lambda t=tag: self._on_yara_done(
                            True, f"Already up to date ({t})"))
                    return

                # 3. Find core ZIP asset
                assets = release.get("assets", [])
                zip_asset = next(
                    (a for a in assets
                     if a["name"].lower().endswith(".zip") and "core" in a["name"].lower()),
                    next((a for a in assets if a["name"].lower().endswith(".zip")), None)
                )
                if not zip_asset:
                    if self.winfo_exists():
                        self.after(0, lambda: self._on_yara_done(
                            False, "No ZIP asset found in release"))
                    return

                asset_name = zip_asset["name"]
                asset_url  = zip_asset["browser_download_url"]
                if self.winfo_exists():
                    self.after(0, self._log_append,
                               f"  Downloading {asset_name}…", _TAG_YARA)

                # 4. Download to temp file
                with _tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
                    tmp_path = tmp.name
                _urlreq.urlretrieve(asset_url, tmp_path)

                # 5. Extract .yar / .yara files to rules/community/ (flattened)
                community_dir.mkdir(parents=True, exist_ok=True)
                for old in community_dir.rglob("*.yar"):
                    old.unlink(missing_ok=True)
                for old in community_dir.rglob("*.yara"):
                    old.unlink(missing_ok=True)

                extracted = 0
                with _zipfile.ZipFile(tmp_path) as zf:
                    for name in zf.namelist():
                        if name.endswith(".yar") or name.endswith(".yara"):
                            target = community_dir / Path(name).name
                            target.write_bytes(zf.read(name))
                            extracted += 1

                # 6. Write version file
                ver_file.write_text(tag, encoding="utf-8")
                Path(tmp_path).unlink(missing_ok=True)

                if self.winfo_exists():
                    self.after(0, self._log_append,
                               f"  Extracted {extracted} rule file(s).", _TAG_YARA)
                    self.after(0, lambda t=tag: self._on_yara_done(
                        True, f"Updated to {t}"))

            except Exception as exc:
                if tmp_path:
                    try:
                        Path(tmp_path).unlink(missing_ok=True)
                    except Exception:
                        pass
                if self.winfo_exists():
                    self.after(0, lambda e=str(exc): self._on_yara_done(False, e[:80]))

        threading.Thread(target=_run, daemon=True).start()

    def _on_yara_done(self, ok: bool, msg: str):
        self._upd_yara = False
        self._yara_dl_btn.configure(state="normal", text="↓  Download Latest")
        if ok:
            self._yara_badge.configure(text=f"  ✓ {msg}  ", text_color="#50fa7b")
            self._log_append(f"  [DONE] {msg}\n", _TAG_OK)
            self._status_cb(f"YARA rules: {msg}")
        else:
            self._yara_badge.configure(text=f"  ✗ {msg[:60]}  ", text_color="#ff5555")
            self._log_append(f"  [ERROR] {msg}\n", _TAG_ERR)
            self._status_cb("YARA community rules update failed")
        self._refresh_yara_info()
        if self._upd_all:
            # End of "Update All" chain
            self._upd_all = False
            self._update_all_btn.configure(state="normal", text="⟳  Update All")
            self._log_append(
                "═══ Update All complete ═══\n", _TAG_INFO)

    # ── ClamAV version check ───────────────────────────────────────────────────

    def _check_clamav_latest(self):
        """Query GitHub API for the latest ClamAV release (background)."""
        self._clamav_check_btn.configure(state="disabled", text="Checking…")
        self._clamav_latest_lbl.configure(text="querying GitHub…", text_color=theme.color("subtext"))
        self._log_section_header("ClamAV Engine", _TAG_CLAMAV)

        def _run():
            import urllib.request as _urlreq, json as _json
            try:
                url = "https://api.github.com/repos/Cisco-Talos/clamav/releases/latest"
                req = _urlreq.Request(
                    url, headers={"User-Agent": "PolyShield/1.5",
                                  "Accept": "application/vnd.github+json"})
                with _urlreq.urlopen(req, timeout=10) as resp:
                    data = _json.loads(resp.read().decode("utf-8"))
                tag = data.get("tag_name", "unknown")
                published = data.get("published_at", "")[:10]
                ok = True
            except Exception as exc:
                tag = f"error: {str(exc)[:50]}"
                published = ""
                ok = False

            def _upd():
                self._clamav_check_btn.configure(state="normal", text="Check Latest")
                self._clamav_latest_lbl.configure(
                    text=f"{tag} ({published})" if published else tag,
                    text_color=theme.color("text") if ok else "#ff5555")
                if ok:
                    self._clamav_badge.configure(
                        text=f"  Latest: {tag}  ", text_color="#50fa7b")
                    self._log_append(
                        f"  Latest release: {tag}  ({published})\n"
                        "  Download the Windows MSI from clamav.net/downloads,\n"
                        "  then configure the install path in Settings → ClamAV.\n",
                        _TAG_CLAMAV)
                else:
                    self._clamav_badge.configure(
                        text="  ✗ Check failed  ", text_color="#ff5555")
                    self._log_append(f"  [ERROR] {tag}\n", _TAG_ERR)
                self._status_cb(f"ClamAV latest: {tag}")

            if self.winfo_exists():
                self.after(0, _upd)

        threading.Thread(target=_run, daemon=True).start()

    # ── Update All ─────────────────────────────────────────────────────────────

    def _run_update_all(self):
        if (self._upd_k2 or self._upd_guardian or self._upd_intel
                or self._upd_speakeasy or self._upd_c2 or self._upd_yara):
            return
        self._upd_all = True
        self._update_all_btn.configure(state="disabled", text="Updating…")
        self._log_clear()
        self._log_append(
            "═══ Update All — K2 Signatures → Guardian AI → Intelligence DB → Speakeasy → C2 Blocklist → YARA ═══\n"
            "    (Sandboxie-Plus and ClamAV require manual download — use their buttons separately)\n",
            _TAG_INFO)
        # Chain: kicom → guardian → intel → speakeasy → c2 → yara  (each on_done triggers the next)
        self._run_k2_update()

    # ── on_show hook (called by app.py on navigation) ─────────────────────────

    def on_show(self):
        """Refresh all info cards when the user navigates to this view."""
        self._refresh_all_info()
        self._refresh_auto_status()

    # ── Log helpers ────────────────────────────────────────────────────────────

    def _log_section_header(self, title: str, tag: str):
        self._log_append(f"── {title} ──", tag)

    def _log_append(self, line: str, tag: str = _TAG_INFO):
        self._log.configure(state="normal")
        self._log.insert("end", line + "\n", tag)
        self._log.see("end")
        self._log.configure(state="disabled")

    def _log_clear(self):
        self._log.configure(state="normal")
        self._log.delete("1.0", "end")
        self._log.configure(state="disabled")
