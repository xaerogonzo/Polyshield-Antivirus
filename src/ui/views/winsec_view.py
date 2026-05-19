"""
winsec_view.py
──────────────
"Windows Security" sidebar panel.

Supplements (not mirrors) every Windows Security Center category:
  • Security Score     — composite 0-100 with transparent breakdown
  • Firewall & Network — profile states + unusual outbound connections
  • Device Security    — Secure Boot, TPM, VBS/Credential Guard
  • Account Protection — local account audit + lockout policy
  • App & Browser      — SmartScreen, CFA, ASR rules by category
  • System Health      — uptime, pending reboot, recent patches
"""
from __future__ import annotations

import subprocess
import sys
import threading
from pathlib import Path

import customtkinter as ctk

from ui.core import defender as dfn
from ui.core import win_security as ws

_NO_WINDOW = subprocess.CREATE_NO_WINDOW

# ── Colour palette (matches app theme) ───────────────────────────────────────
_GREEN  = "#50fa7b"
_RED    = "#ff5555"
_AMBER  = "#ffb86c"
_BLUE   = "#5294e2"
_DIM    = "#555577"
_CARD   = "#1a1a2e"
_CARD2  = "#1e1e2e"


class WinSecView(ctk.CTkScrollableFrame):
    def __init__(self, master, status_callback, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self._status_cb = status_callback
        self._score_data: dict = {}
        self._section_open: dict[str, bool] = {
            "firewall": False,
            "device":   False,
            "accounts": False,
            "app":      False,
            "health":   False,
        }
        self._section_loading: dict[str, bool] = {}
        # Pre-fetch cache: key → detail dict once background load completes.
        # None means "not yet fetched"; absent key means "fetch not started".
        self._prefetch_cache: dict[str, dict] = {}
        self._build()

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self):
        self.grid_columnconfigure(0, weight=1)

        # Header
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=24, pady=(20, 8))
        hdr.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(hdr, text="Windows Security",
                     font=ctk.CTkFont(size=22, weight="bold")).grid(
            row=0, column=0, sticky="w")

        self._refresh_btn = ctk.CTkButton(
            hdr, text="Refresh", width=100,
            fg_color="#3a3a3a", hover_color="#4a4a4a",
            command=self.on_show,
        )
        self._refresh_btn.grid(row=0, column=1)

        self._admin_btn = ctk.CTkButton(
            hdr, text="Run as Administrator", width=170, height=28,
            fg_color="#3a1a1a", hover_color="#5a2a2a",
            font=ctk.CTkFont(size=11),
            command=self._relaunch_as_admin,
        )
        self._admin_btn.grid(row=0, column=2, padx=(8, 0))
        self._admin_btn.grid_remove()  # hidden until on_show determines elevation

        self._admin_badge = ctk.CTkLabel(
            hdr, text="", font=ctk.CTkFont(size=11))
        self._admin_badge.grid(row=1, column=0, columnspan=3, sticky="w", pady=(2, 0))

        # ── Score card ────────────────────────────────────────────────────────
        self._score_card = ctk.CTkFrame(self, corner_radius=10, fg_color=_CARD)
        self._score_card.grid(row=1, column=0, sticky="ew", padx=24, pady=(0, 8))
        self._score_card.grid_columnconfigure(0, weight=1)

        score_top = ctk.CTkFrame(self._score_card, fg_color="transparent")
        score_top.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 4))
        score_top.grid_columnconfigure(0, weight=1)

        self._score_lbl = ctk.CTkLabel(
            score_top, text="Security Score: —",
            font=ctk.CTkFont(size=16, weight="bold"))
        self._score_lbl.grid(row=0, column=0, sticky="w")

        self._score_detail_btn = ctk.CTkButton(
            score_top, text="Details ▼", width=90,
            fg_color="transparent", hover_color="#2a2a3a",
            font=ctk.CTkFont(size=11), text_color=_DIM,
            command=self._toggle_score_details,
        )
        self._score_detail_btn.grid(row=0, column=1)

        self._score_bar = ctk.CTkProgressBar(self._score_card, height=10)
        self._score_bar.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 6))
        self._score_bar.set(0)

        self._score_issue_lbl = ctk.CTkLabel(
            self._score_card, text="",
            font=ctk.CTkFont(size=11), text_color=_AMBER, anchor="w")
        self._score_issue_lbl.grid(row=2, column=0, sticky="w", padx=16, pady=(0, 10))

        # Score breakdown (collapsed by default)
        self._score_details_frame = ctk.CTkFrame(
            self._score_card, fg_color="#12121e", corner_radius=6)
        self._score_details_frame.grid_columnconfigure(0, weight=1)
        self._score_details_visible = False

        # ── Collapsible sections ───────────────────────────────────────────────
        section_row = 2
        self._sections: dict[str, dict] = {}

        for key, title, open_cmd in [
            ("firewall", "Firewall & Network",    "wf.msc"),
            ("device",   "Device Security",       "windowsdefender://devicesecurity"),
            ("accounts", "Account Protection",    "lusrmgr.msc"),
            ("app",      "App & Browser Control", "windowsdefender://appbrowser"),
            ("health",   "System Health",         "ms-settings:windowsupdate"),
        ]:
            frame, summary_lbl, detail_frame = self._make_section(
                row=section_row, key=key, title=title, open_cmd=open_cmd)
            self._sections[key] = {
                "frame": frame,
                "summary": summary_lbl,
                "detail": detail_frame,
            }
            section_row += 1

    def _make_section(self, row: int, key: str, title: str, open_cmd: str | None = None):
        outer = ctk.CTkFrame(self, corner_radius=10, fg_color=_CARD)
        outer.grid(row=row, column=0, sticky="ew", padx=24, pady=(0, 6))
        outer.grid_columnconfigure(0, weight=1)

        # Header row (clickable)
        hdr = ctk.CTkFrame(outer, fg_color="transparent", cursor="hand2")
        hdr.grid(row=0, column=0, sticky="ew", padx=14, pady=10)
        hdr.grid_columnconfigure(0, weight=1)
        hdr.bind("<Button-1>", lambda e, k=key: self._toggle_section(k))

        title_lbl = ctk.CTkLabel(
            hdr, text=title, font=ctk.CTkFont(size=13, weight="bold"),
            text_color=_BLUE, anchor="w", cursor="hand2")
        title_lbl.grid(row=0, column=0, sticky="w")
        title_lbl.bind("<Button-1>", lambda e, k=key: self._toggle_section(k))

        summary_lbl = ctk.CTkLabel(
            hdr, text="Loading…", font=ctk.CTkFont(size=11),
            text_color=_DIM, anchor="e", cursor="hand2")
        summary_lbl.grid(row=0, column=1, padx=(8, 0))
        summary_lbl.bind("<Button-1>", lambda e, k=key: self._toggle_section(k))

        if open_cmd:
            ctk.CTkButton(
                hdr, text="Open →", width=68, height=24,
                fg_color="transparent", hover_color="#2a2a3a",
                font=ctk.CTkFont(size=10), text_color=_BLUE,
                border_width=1, border_color="#2a2a4a",
                command=lambda cmd=open_cmd: self._open_settings(cmd),
            ).grid(row=0, column=2, padx=(8, 0))

        chevron = ctk.CTkLabel(
            hdr, text="▶", font=ctk.CTkFont(size=10),
            text_color=_DIM, cursor="hand2")
        chevron.grid(row=0, column=3, padx=(8, 0))
        chevron.bind("<Button-1>", lambda e, k=key: self._toggle_section(k))

        # Store chevron reference
        outer._chevron = chevron  # type: ignore[attr-defined]

        # Detail area (hidden initially)
        detail = ctk.CTkFrame(outer, fg_color="#12121e", corner_radius=6)
        detail.grid_columnconfigure(0, weight=1)
        # Not gridded until expanded

        return outer, summary_lbl, detail

    # ── Public API ────────────────────────────────────────────────────────────

    def on_show(self):
        """Called each time the view becomes visible. Fetches lightweight data."""
        self._refresh_btn.configure(state="disabled", text="Loading…")
        self._status_cb("Gathering Windows Security data…")

        # Reset pre-fetch cache so Refresh always pulls fresh data
        self._prefetch_cache.clear()
        # Reset section_loading so sections are re-fetchable after a Refresh
        self._section_loading.clear()

        elevated = ws._is_elevated()
        if elevated:
            self._admin_badge.configure(
                text="Running as Administrator — all data available",
                text_color=_GREEN)
            self._admin_btn.grid_remove()
        else:
            self._admin_badge.configure(
                text="Standard user — Device Security fields require admin for full data",
                text_color=_AMBER)
            self._admin_btn.grid()

        def _load():
            defender_status = dfn.get_status()
            ws.fetch_overview_async(defender_status, lambda d: self.after(0, self._apply_overview, d))

        threading.Thread(target=_load, daemon=True).start()

        # Pre-fetch all section details in parallel so they appear instantly on expand
        for _key in self._sections:
            self._prefetch_section(_key)

    def _apply_overview(self, data: dict):
        self._score_data = data
        self._refresh_btn.configure(state="normal", text="Refresh")

        # Score card
        score_info = data.get("score", {})
        score = score_info.get("score", 0)
        label = score_info.get("label", "Unknown")
        top_issue = score_info.get("top_issue", "")

        color = _GREEN if score >= 75 else (_AMBER if score >= 55 else _RED)
        self._score_lbl.configure(
            text=f"Security Score: {score}/100  —  {label}",
            text_color=color)
        self._score_bar.set(score / 100)
        self._score_bar.configure(progress_color=color)
        self._score_issue_lbl.configure(
            text=f"⚠  {top_issue}" if top_issue else "No critical issues detected",
            text_color=_AMBER if top_issue else _GREEN)

        # Firewall summary
        fw = data.get("firewall", {})
        fw_ok = all(v.get("enabled") is True for v in fw.values() if v)
        all_on = sum(1 for v in fw.values() if v.get("enabled") is True)
        self._sections["firewall"]["summary"].configure(
            text=f"{all_on}/3 profiles ON",
            text_color=_GREEN if fw_ok else _AMBER)

        # App control summary
        ac = data.get("app_control", {})
        parts = []
        parts.append("SmartScreen ON" if ac.get("smartscreen_on") else "SmartScreen OFF")
        if ac.get("cfa_enabled"):
            parts.append("CFA ON")
        elif ac.get("cfa_audit"):
            parts.append("CFA Audit")
        else:
            parts.append("CFA OFF")
        asr = ac.get("asr_active_count", 0)
        parts.append(f"{asr} ASR rules")
        app_ok = ac.get("smartscreen_on") and ac.get("cfa_enabled") and asr > 0
        self._sections["app"]["summary"].configure(
            text=" · ".join(parts),
            text_color=_GREEN if app_ok else _AMBER)

        # Health summary
        health = data.get("health", {})
        if health.get("pending_reboot"):
            self._sections["health"]["summary"].configure(
                text="Restart pending", text_color=_AMBER)
        else:
            self._sections["health"]["summary"].configure(
                text="OK", text_color=_GREEN)

        # Update score breakdown if visible
        if self._score_details_visible:
            self._populate_score_breakdown(score_info)

        self._status_cb("Windows Security overview loaded")

    # ── Score breakdown toggle ────────────────────────────────────────────────

    def _toggle_score_details(self):
        self._score_details_visible = not self._score_details_visible
        if self._score_details_visible:
            self._score_detail_btn.configure(text="Details ▲")
            self._score_details_frame.grid(
                row=3, column=0, sticky="ew", padx=16, pady=(0, 12))
            self._populate_score_breakdown(self._score_data.get("score", {}))
        else:
            self._score_detail_btn.configure(text="Details ▼")
            self._score_details_frame.grid_remove()

    def _populate_score_breakdown(self, score_info: dict):
        for w in self._score_details_frame.winfo_children():
            w.destroy()

        breakdown = score_info.get("breakdown", {})
        for i, (cat, info) in enumerate(breakdown.items()):
            cat_score = info.get("score", 0)
            cat_max   = info.get("max", 0)
            issues    = info.get("issues", [])

            bg = "#1a1a2e" if i % 2 == 0 else "#1e1e2e"
            row_f = ctk.CTkFrame(self._score_details_frame, fg_color=bg)
            row_f.grid(row=i, column=0, sticky="ew")
            row_f.grid_columnconfigure(1, weight=1)

            icon = "✓" if cat_score == cat_max else ("⚠" if cat_score > 0 else "✗")
            color = _GREEN if cat_score == cat_max else (_AMBER if cat_score > 0 else _RED)

            ctk.CTkLabel(row_f, text=icon, text_color=color,
                         font=ctk.CTkFont(size=13)).grid(
                row=0, column=0, padx=(10, 6), pady=6)
            ctk.CTkLabel(row_f, text=cat, font=ctk.CTkFont(size=12),
                         anchor="w").grid(row=0, column=1, sticky="w", pady=6)
            ctk.CTkLabel(row_f, text=f"{cat_score}/{cat_max}",
                         font=ctk.CTkFont(size=12), text_color=color).grid(
                row=0, column=2, padx=10)

            if issues:
                for j, iss in enumerate(issues):
                    ctk.CTkLabel(row_f, text=f"  — {iss}",
                                 font=ctk.CTkFont(size=10), text_color=_DIM,
                                 anchor="w").grid(
                        row=j + 1, column=0, columnspan=3, sticky="w",
                        padx=(30, 8), pady=(0, 2 if j < len(issues) - 1 else 6))

    # ── Section pre-fetch ─────────────────────────────────────────────────────

    def _prefetch_section(self, key: str):
        """Start a silent background fetch of section detail data.

        Result is stored in _prefetch_cache[key].  If the section is
        already open and waiting for this data, _populate_section is called
        immediately on completion.  Also updates summary labels for sections
        (device, accounts) whose summaries are not populated by the overview.
        """
        detail_key = "firewall_rules" if key == "firewall" else key

        def _done(data: dict):
            if not self.winfo_exists():
                return
            self._prefetch_cache[key] = data
            # If the section was opened while the pre-fetch was in flight,
            # deliver the data now instead of waiting for a second fetch.
            if self._section_open.get(key) and self._section_loading.get(key):
                self.after(0, self._populate_section, key, data)
            # Update summary labels for sections not covered by _apply_overview
            if key == "device":
                self.after(0, self._apply_device_summary, data)
            elif key == "accounts":
                self.after(0, self._apply_accounts_summary, data)

        ws.fetch_detail_async(detail_key, _done)

    def _apply_device_summary(self, data: dict):
        """Populate Device Security summary label from pre-fetched detail data."""
        parts = []
        sb = data.get("secure_boot")
        if sb is True:
            parts.append("Secure Boot ON")
        elif sb is False:
            parts.append("Secure Boot OFF")
        tpm = data.get("tpm_present")
        if tpm is True:
            parts.append("TPM present")
        elif tpm is False:
            parts.append("No TPM")
        if not parts:
            parts.append("Limited data")
        all_ok = sb is True and tpm is True
        color = _GREEN if all_ok else (_AMBER if sb is None or tpm is None else _RED)
        self._sections["device"]["summary"].configure(
            text=" · ".join(parts), text_color=color)

    def _apply_accounts_summary(self, data: dict):
        """Populate Account Protection summary label from pre-fetched detail data."""
        # fetch_detail_async("accounts") returns {"accounts": get_local_accounts(),
        #                                          "policy": get_account_policy()}
        acc_data = data.get("accounts", {})
        policy   = data.get("policy", {})
        if not acc_data.get("available"):
            self._sections["accounts"]["summary"].configure(
                text="Unavailable", text_color=_AMBER)
            return
        admin_count = acc_data.get("admin_count", 0)
        active = sum(1 for a in acc_data.get("accounts", []) if a.get("enabled"))
        lockout = policy.get("lockout_threshold", 0)
        lockout_txt = f"Lockout: {lockout}" if lockout else "Lockout: disabled"
        color = _GREEN if admin_count <= 1 and lockout else (_AMBER if admin_count <= 2 else _RED)
        self._sections["accounts"]["summary"].configure(
            text=f"{active} active · {admin_count} admin · {lockout_txt}",
            text_color=color)

    # ── Section toggle (lazy load) ────────────────────────────────────────────

    def _toggle_section(self, key: str):
        self._section_open[key] = not self._section_open.get(key, False)
        sec = self._sections[key]
        outer = sec["frame"]
        detail = sec["detail"]
        chevron = outer._chevron  # type: ignore[attr-defined]

        if self._section_open[key]:
            chevron.configure(text="▼")
            detail.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 10))
            if not self._section_loading.get(key):
                self._load_section_detail(key)
        else:
            chevron.configure(text="▶")
            detail.grid_remove()

    def _load_section_detail(self, key: str):
        self._section_loading[key] = True
        detail = self._sections[key]["detail"]

        # Cache hit: pre-fetch already completed — populate immediately, no spinner
        if key in self._prefetch_cache:
            self._populate_section(key, self._prefetch_cache[key])
            return

        # Cache miss: pre-fetch is still in flight (on_show always starts it first).
        # Show a spinner and wait; _prefetch_section's _done callback will call
        # _populate_section when it completes because _section_loading[key] is True.
        for w in detail.winfo_children():
            w.destroy()
        ctk.CTkLabel(detail, text="Loading…", text_color=_DIM,
                     font=ctk.CTkFont(size=11)).grid(row=0, column=0, pady=12)

    def _populate_section(self, key: str, data: dict):
        self._section_loading[key] = False
        detail = self._sections[key]["detail"]
        for w in detail.winfo_children():
            w.destroy()

        if key == "firewall":
            self._build_firewall_detail(detail, data)
        elif key == "device":
            self._build_device_detail(detail, data)
        elif key == "accounts":
            self._build_accounts_detail(detail, data)
        elif key == "app":
            self._build_app_detail(detail, data)
        elif key == "health":
            self._build_health_detail(detail, data)

    # ── Firewall detail ───────────────────────────────────────────────────────

    def _build_firewall_detail(self, parent, rules_data: dict):
        parent.grid_columnconfigure(0, weight=1)
        row = 0

        fw = self._score_data.get("firewall", {})
        for profile, state in fw.items():
            enabled = state.get("enabled")
            color = _GREEN if enabled else (_RED if enabled is False else _AMBER)
            status = "ON" if enabled else ("OFF" if enabled is False else "Unknown")
            self._detail_row(parent, row, f"{profile} Profile: {status}",
                             f"Inbound: {state.get('default_inbound','?')}  "
                             f"Outbound: {state.get('default_outbound','?')}", color)
            row += 1

        if rules_data.get("available"):
            self._divider(parent, row); row += 1
            ctk.CTkLabel(parent, text=f"Total rules: {rules_data.get('total', '?')}  "
                                      f"· Inbound allow: {rules_data.get('inbound_allow', '?')}  "
                                      f"· Outbound allow: {rules_data.get('outbound_allow', '?')}  "
                                      f"· Disabled: {rules_data.get('disabled', '?')}",
                         font=ctk.CTkFont(size=11), text_color=_DIM, anchor="w").grid(
                row=row, column=0, sticky="w", padx=14, pady=(4, 4)); row += 1

        self._divider(parent, row); row += 1

        # Network connections sub-section
        net_btn = ctk.CTkButton(
            parent, text="Show Active Connections", height=28,
            fg_color="#1f3355", hover_color="#144e7a",
            font=ctk.CTkFont(size=11),
            command=lambda: self._load_connections(parent, row))
        net_btn.grid(row=row, column=0, sticky="w", padx=14, pady=(4, 10))

    def _load_connections(self, parent, start_row: int):
        # Remove old button, show spinner
        for w in list(parent.grid_slaves(row=start_row)):
            w.destroy()
        ctk.CTkLabel(parent, text="Checking connections…",
                     text_color=_DIM, font=ctk.CTkFont(size=11)).grid(
            row=start_row, column=0, sticky="w", padx=14, pady=4)

        def _done(data: dict):
            if not self.winfo_exists():
                return
            self.after(0, self._show_connections, parent, start_row, data)

        ws.fetch_detail_async("network", _done)

    def _show_connections(self, parent, start_row: int, data: dict):
        for w in list(parent.grid_slaves(row=start_row)):
            w.destroy()

        parent.grid_columnconfigure(0, weight=1)
        row = start_row

        if not data.get("available"):
            ctk.CTkLabel(parent, text="Could not retrieve connections",
                         text_color=_AMBER, font=ctk.CTkFont(size=11)).grid(
                row=row, column=0, sticky="w", padx=14, pady=6)
            return

        flagged = data.get("flagged", 0)
        total = data.get("total", 0)
        summary_color = _RED if flagged else _GREEN
        ctk.CTkLabel(parent,
                     text=f"{total} established connections  · {flagged} unsigned process(es)",
                     font=ctk.CTkFont(size=11), text_color=summary_color, anchor="w").grid(
            row=row, column=0, sticky="w", padx=14, pady=(4, 6)); row += 1

        for conn in data.get("connections", []):
            if not conn.get("flagged") and conn.get("is_local"):
                continue  # only show interesting connections
            proc = conn.get("process_name", "unknown")
            remote = f"{conn.get('remote_addr')}:{conn.get('remote_port')}"
            color = _AMBER if conn.get("flagged") else _DIM
            ctk.CTkLabel(parent,
                         text=f"  {proc}  →  {remote}",
                         font=ctk.CTkFont(family="Consolas", size=10),
                         text_color=color, anchor="w").grid(
                row=row, column=0, sticky="w", padx=20, pady=1); row += 1

    # ── Device Security detail ────────────────────────────────────────────────

    def _build_device_detail(self, parent, data: dict):
        parent.grid_columnconfigure(0, weight=1)
        row = 0

        def _feature(label, val, needs_elev_key=None):
            nonlocal row
            if val is True:
                self._detail_row(parent, row, label, "Enabled", _GREEN)
            elif val is False:
                self._detail_row(parent, row, label, "Disabled", _RED)
            elif data.get(needs_elev_key):
                self._detail_row(parent, row, label,
                                 "Unknown (requires administrator)", _AMBER)
            else:
                self._detail_row(parent, row, label, "Unknown", _DIM)
            row += 1

        _feature("Secure Boot",              data.get("secure_boot"),      "secure_boot_needs_elevation")
        _feature("TPM Present",              data.get("tpm_present"),      "tpm_needs_elevation")

        if data.get("tpm_present") and data.get("tpm_version"):
            ctk.CTkLabel(parent, text=f"  TPM version: {data['tpm_version']}",
                         font=ctk.CTkFont(size=10), text_color=_DIM, anchor="w").grid(
                row=row, column=0, sticky="w", padx=22, pady=(0, 2)); row += 1

        _feature("Virtualization-Based Security", data.get("vbs_enabled"), "vbs_needs_elevation")
        _feature("Credential Guard",          data.get("credential_guard"), "vbs_needs_elevation")
        _feature("HVCI (Memory Integrity)",   data.get("hvci"),             "vbs_needs_elevation")

        if not data.get("elevated"):
            self._divider(parent, row); row += 1
            ctk.CTkLabel(parent,
                         text="Use 'Run as Administrator' in the header above for full data.",
                         font=ctk.CTkFont(size=10), text_color=_DIM, anchor="w").grid(
                row=row, column=0, sticky="w", padx=14, pady=(4, 10))

    # ── Account detail ────────────────────────────────────────────────────────

    def _build_accounts_detail(self, parent, data: dict):
        parent.grid_columnconfigure(0, weight=1)
        row = 0

        acc_data = data.get("accounts", {})
        policy   = data.get("policy", {})

        if not acc_data.get("available"):
            ctk.CTkLabel(parent, text="Account data unavailable",
                         text_color=_AMBER, font=ctk.CTkFont(size=11)).grid(
                row=row, column=0, padx=14, pady=10)
            return

        for acc in acc_data.get("accounts", []):
            if not acc.get("enabled"):
                continue
            risk = acc.get("risk", [])
            color = _RED if risk else (_AMBER if acc.get("is_admin") else _DIM)
            admin_tag = " [Administrator]" if acc.get("is_admin") else ""
            detail = f"Last logon: {acc.get('last_logon', '?')}"
            if risk:
                detail += "  ⚠ " + "  ·  ".join(risk)
            self._detail_row(parent, row, acc["name"] + admin_tag, detail, color)
            row += 1

        if policy.get("available"):
            self._divider(parent, row); row += 1
            threshold = policy.get("lockout_threshold", 0)
            thresh_color = _GREEN if 0 < threshold <= 10 else (_RED if threshold == 0 else _AMBER)
            if threshold == 0:
                thresh_text = "NOT configured — brute-force risk"
            else:
                thresh_text = f"After {threshold} failed attempt(s)"
            self._detail_row(parent, row, "Account Lockout", thresh_text, thresh_color); row += 1

            dur = policy.get("lockout_duration_min", 0)
            self._detail_row(parent, row, "Lockout Duration",
                             f"{dur} minutes" if dur else "Not set", _DIM); row += 1

        ctk.CTkLabel(parent, text="", height=4).grid(row=row, column=0)

    # ── App & Browser detail ──────────────────────────────────────────────────

    def _build_app_detail(self, parent, _ignored):
        parent.grid_columnconfigure(0, weight=1)
        row = 0

        ac = self._score_data.get("app_control", {})

        # SmartScreen
        ss_on = ac.get("smartscreen_on", True)
        ss_src = ac.get("smartscreen_source", "")
        self._detail_row(
            parent, row, "SmartScreen",
            ("Enabled" + (f" (via {ss_src})" if ss_src else "")) if ss_on else "Disabled — reputation-based protection off",
            _GREEN if ss_on else _RED)
        row += 1

        if not ss_on:
            btn = ctk.CTkButton(
                parent, text="Enable SmartScreen (Windows Settings)", height=26,
                fg_color="#1f3355", hover_color="#144e7a", font=ctk.CTkFont(size=10),
                command=lambda: self._open_settings("ms-settings:windowsdefender"))
            btn.grid(row=row, column=0, sticky="w", padx=22, pady=(0, 6)); row += 1

        # CFA
        cfa = ac.get("cfa_enabled", False)
        cfa_audit = ac.get("cfa_audit", False)
        if cfa:
            cfa_text = "Enabled — Documents and Desktop are protected"
            cfa_color = _GREEN
        elif cfa_audit:
            cfa_text = "Audit mode — detects but does not block"
            cfa_color = _AMBER
        else:
            cfa_text = "Disabled — folders unprotected from ransomware"
            cfa_color = _RED
        self._detail_row(parent, row, "Controlled Folder Access", cfa_text, cfa_color); row += 1

        if not cfa:
            btn = ctk.CTkButton(
                parent, text="Enable via PowerShell (requires admin)", height=26,
                fg_color="#1f3355", hover_color="#144e7a", font=ctk.CTkFont(size=10),
                command=self._enable_cfa)
            btn.grid(row=row, column=0, sticky="w", padx=22, pady=(0, 6)); row += 1

        # ASR rules by category
        self._divider(parent, row); row += 1
        asr_total = ac.get("asr_active_count", 0)
        ctk.CTkLabel(
            parent,
            text=f"Attack Surface Reduction — {asr_total} active rule(s)",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=_BLUE if asr_total else _AMBER,
            anchor="w").grid(row=row, column=0, sticky="w", padx=14, pady=(6, 4)); row += 1

        categories = ac.get("asr_categories", {})
        if categories:
            for cat_name, rules in categories.items():
                active = sum(1 for r in rules if r.get("enabled"))
                color = _GREEN if active == len(rules) else (_AMBER if active else _DIM)
                ctk.CTkLabel(
                    parent,
                    text=f"  {cat_name}: {active}/{len(rules)} active",
                    font=ctk.CTkFont(size=11),
                    text_color=color, anchor="w").grid(
                    row=row, column=0, sticky="w", padx=22, pady=1); row += 1
        else:
            ctk.CTkLabel(parent, text="  No ASR rules configured",
                         font=ctk.CTkFont(size=11), text_color=_AMBER, anchor="w").grid(
                row=row, column=0, sticky="w", padx=22, pady=4); row += 1

        ctk.CTkLabel(parent, text="", height=4).grid(row=row, column=0)

    # ── System Health detail ──────────────────────────────────────────────────

    def _build_health_detail(self, parent, data: dict):
        parent.grid_columnconfigure(0, weight=1)
        row = 0

        uptime = data.get("uptime_days")
        if uptime is None:
            self._detail_row(parent, row, "System Uptime", "Unknown", _DIM)
        elif uptime > 30:
            self._detail_row(parent, row, "System Uptime",
                             f"{uptime} days — reboot recommended to apply patches", _AMBER)
        else:
            self._detail_row(parent, row, "System Uptime", f"{uptime} days", _GREEN)
        row += 1

        reboot = data.get("pending_reboot", False)
        self._detail_row(parent, row, "Pending Restart",
                         "Yes — security updates waiting" if reboot else "No",
                         _AMBER if reboot else _GREEN); row += 1

        driver_errors = data.get("driver_errors", 0)
        self._detail_row(parent, row, "Driver Issues",
                         f"{driver_errors} device(s) in error state" if driver_errors else "All OK",
                         _AMBER if driver_errors else _GREEN); row += 1

        patches = data.get("recent_patches", [])
        if patches:
            self._divider(parent, row); row += 1
            ctk.CTkLabel(parent, text="Recent patches:",
                         font=ctk.CTkFont(size=11, weight="bold"),
                         text_color=_DIM, anchor="w").grid(
                row=row, column=0, sticky="w", padx=14, pady=(4, 2)); row += 1
            for p in patches:
                ctk.CTkLabel(parent,
                             text=f"  {p.get('kb', '?')}  —  {p.get('installed_on', '?')}",
                             font=ctk.CTkFont(family="Consolas", size=10),
                             text_color=_DIM, anchor="w").grid(
                    row=row, column=0, sticky="w", padx=22, pady=1); row += 1

        ctk.CTkLabel(parent, text="", height=4).grid(row=row, column=0)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _detail_row(self, parent, row: int, label: str, value: str, color: str):
        f = ctk.CTkFrame(parent, fg_color="transparent")
        f.grid(row=row, column=0, sticky="ew", padx=14, pady=2)
        f.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(f, text=label, font=ctk.CTkFont(size=12),
                     text_color="#aaaaaa", anchor="w", width=180).grid(
            row=0, column=0, sticky="w")
        ctk.CTkLabel(f, text=value, font=ctk.CTkFont(size=12),
                     text_color=color, anchor="w").grid(row=0, column=1, sticky="w")

    def _divider(self, parent, row: int):
        ctk.CTkFrame(parent, height=1, fg_color="#2a2a3a").grid(
            row=row, column=0, sticky="ew", padx=10, pady=4)

    def _open_settings(self, uri: str):
        try:
            subprocess.Popen(
                ["start", "", uri],
                shell=True, creationflags=_NO_WINDOW)
        except Exception:
            pass

    def _enable_cfa(self):
        """Attempt to enable Controlled Folder Access via elevated PowerShell."""
        try:
            subprocess.Popen(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                 "-Command",
                 "Start-Process powershell -Verb RunAs -ArgumentList "
                 "'-NoProfile -ExecutionPolicy Bypass -Command "
                 "\"Set-MpPreference -EnableControlledFolderAccess Enabled; "
                 "Write-Host Done; Start-Sleep 2\"'"],
                creationflags=_NO_WINDOW,
            )
            self._status_cb("Enabled Controlled Folder Access (refresh to verify)")
        except Exception as exc:
            self._status_cb(f"CFA enable failed: {exc}")

    def _relaunch_as_admin(self):
        """Re-launch the UI script with elevated privileges."""
        try:
            script = str(Path(__file__).resolve().parents[3] / "src" / "ui" / "app.py")
            import ctypes
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, f'"{script}"', None, 1)
        except Exception as exc:
            self._status_cb(f"Could not relaunch as admin: {exc}")
