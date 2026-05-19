"""
threat_actions_mixin.py
───────────────────────
The Threat Actions master-detail subsystem of the Scan view.

This module hosts roughly 40 methods that were previously crammed into
`ScanView` itself (lines 1736–3131 of scan_view.py).  Extracting them as
a mixin keeps every `self.*` reference working unchanged — the mixin
relies on instance state created in `ScanView.__init__`:

  • Engine result maps:
      _k2_infected_paths, _g_infected, _g_tier, _g_context,
      _yara_infected, _clamav_infected, _defender_infected,
      _speakeasy_infected, _threat_severity, _disputes

  • Panel state:
      _threat_actions_frame, _threat_master_frame, _threat_detail_frame,
      _threat_bulk_frame, _threat_pagination_frame, _threat_dispute_banner,
      _threat_circuit_banner, _threat_page, _threat_page_size,
      _threat_filter_text, _threat_filter_reason, _threat_checked,
      _threat_selected_path, _threat_resolved, _threat_resolution,
      _row_registry, _hash_cache, _circuit_state, _circuit_banner_dismissed,
      _heuristic_collapsed, _scan_session_ignored, _bulk_cancel_event,
      _bulk_progress_lbl, _bulk_progress_bar

  • Helpers:
      _status_cb, _nav_cb, _log_append, _send_to_virustotal,
      _open_behavioral, _compute_hashes_async (this file owns it).
"""
import hashlib
import os
import subprocess
import threading
from pathlib import Path
from tkinter import messagebox
import customtkinter as ctk

from ui.core import settings as cfg
from ui.core import ignore_list as ignore

# Log tag constants — mirrored from scan_view.py.  Kept in sync intentionally:
# importing them from scan_view would create a circular import (scan_view
# imports this module to inherit the mixin).
_TAG_CLEAN     = "clean"
_TAG_WARN      = "warn"
_TAG_INFO      = "info"
_TAG_GUARDIAN  = "guardian"


def _human_size(n: int) -> str:
    """Human-readable byte count (1.5 KB, 3.2 MB, etc.)."""
    if n < 1024:
        return f"{n} B"
    units = ["KB", "MB", "GB", "TB"]
    val = float(n) / 1024.0
    for u in units:
        if val < 1024 or u == units[-1]:
            return f"{val:.1f} {u}"
        val /= 1024.0
    return f"{n} B"


class _ThreatActionsMixin:
    """Master-detail Threat Actions panel + bulk actions + hash computation.

    This is a *mixin* — it must be combined with `ctk.CTkFrame` (i.e. the
    `ScanView` class).  It assumes the host class created all the instance
    attributes documented at the top of this module in its `__init__`.
    """

    # ── Dispute detection ────────────────────────────────────────────────────

    def _check_disputes(self):
        """
        Compute K2-vs-Guardian disputes and store them in self._disputes.
        v1.9: no longer opens a popup — disputes are surfaced inline in the
        Threat Actions panel (banner + Dispute Mode in the detail pane).
        """
        self._disputes = []
        if not self._k2_infected_paths and not self._g_infected:
            return

        try:
            from ui.core.dispute import find_disputes
            self._disputes = find_disputes(self._k2_infected_paths, self._g_infected)
        except Exception:
            self._disputes = []
            return

        if self._disputes:
            self._log_append(
                f"\n[DISPUTE] {len(self._disputes)} file(s) where engines disagree — "
                f"select a disputed row in Threat Actions to resolve.",
                _TAG_GUARDIAN)
        # Refresh the threat panel so the dispute banner and chip-counter update.
        self._build_threat_actions()

    # ── Threat Actions (master-detail) ────────────────────────────────────────

    def _get_all_infected_paths(self) -> list[str]:
        """Dedupe across every engine, preserving insertion order."""
        seen: set[str] = set()
        out: list[str] = []
        for p in (self._k2_infected_paths
                  + list(self._g_infected.keys())
                  + list(self._yara_infected.keys())
                  + list(self._clamav_infected.keys())
                  + list(self._defender_infected.keys())
                  + list(self._speakeasy_infected.keys())):
            if p not in seen:
                seen.add(p)
                out.append(p)
        return out

    def _get_engine_verdicts(self, path: str) -> list[tuple[str, bool, str]]:
        """
        Return [(engine_name, flagged: bool, reason: str), ...] for every
        engine that ran. Engines that did not run for this path produce no row.
        """
        out: list[tuple[str, bool, str]] = []
        # K2
        if path in self._k2_infected_paths:
            out.append(("K2", True, "Detected by k2 signature engine"))
        # Guardian
        if path in self._g_infected:
            out.append(("Guardian", True, self._g_infected[path]))
        # YARA
        if path in self._yara_infected:
            out.append(("YARA", True, self._yara_infected[path]))
        # ClamAV
        if path in self._clamav_infected:
            out.append(("ClamAV", True, self._clamav_infected[path]))
        # Defender
        if path in self._defender_infected:
            out.append(("Defender", True, self._defender_infected[path]))
        # Speakeasy
        if path in self._speakeasy_infected:
            out.append(("Speakeasy", True, self._speakeasy_infected[path]))
        return out

    def _is_disputed(self, path: str) -> bool:
        key = path.lower()
        for d in self._disputes:
            if d["path"].lower() == key:
                return True
        return False

    def _dispute_for_path(self, path: str) -> dict | None:
        key = path.lower()
        for d in self._disputes:
            if d["path"].lower() == key:
                return d
        return None

    def _reason_bucket(self, path: str) -> str:
        """Classify the path for the reason filter chips."""
        if path in self._threat_resolved:
            return "resolved"
        if self._is_disputed(path):
            return "dispute"
        # v1.10: Guardian-tier-aware classification first
        g_tier = self._g_tier.get(path, "")
        if g_tier == "pattern":
            return "heuristic"
        if g_tier == "hash":
            return "known"
        # Pull primary reason for non-Guardian engines
        reason = (self._g_infected.get(path)
                  or self._yara_infected.get(path)
                  or self._clamav_infected.get(path)
                  or self._defender_infected.get(path)
                  or self._speakeasy_infected.get(path)
                  or "")
        rlow = reason.lower()
        if ("known signature" in rlow or "malwarebazaar" in rlow
                or "[" in reason or "engines]" in rlow
                or path in self._k2_infected_paths):
            return "known"
        if rlow.startswith("suspicious pattern") or "yara" in rlow or "rule" in rlow:
            return "heuristic"
        return "known"   # default bucket

    def _severity_for(self, path: str) -> str:
        """Return 'confirmed' or 'suspicious' for a path. v1.10 tier-aware."""
        sev = self._threat_severity.get(path)
        if sev:
            return sev
        # Fallback inference: Guardian pattern hits = suspicious; everything else = confirmed
        if self._g_tier.get(path) == "pattern":
            return "suspicious"
        return "confirmed"

    def _get_filtered_paths(self) -> list[str]:
        """Apply text + reason filter + suspicious-display-mode against the full infected-paths list.

        Suspicious display modes (setting: guardian_suspicious_display):
          'hidden'       — Suspicious paths excluded from non-Suspicious views
          'collapsible'  — Suspicious paths placed at the END (after Confirmed)
                           and visually grouped under a 'Heuristic Findings' header
          'inline'       — Suspicious paths interleaved naturally
        """
        all_paths = self._get_all_infected_paths()
        text = self._threat_filter_text.strip().lower()
        chip = self._threat_filter_reason
        display_mode = (cfg.get("guardian_suspicious_display") or "hidden").lower()

        # By default the "resolved" set is HIDDEN; only the explicit Resolved chip shows them.
        out: list[str] = []
        for p in all_paths:
            if chip != "resolved" and p in self._threat_resolved:
                continue
            if text and text not in p.lower():
                continue
            # v1.10 suspicious display mode (when no override chip selected)
            if chip not in ("suspicious", "resolved"):
                if display_mode == "hidden" and self._severity_for(p) == "suspicious":
                    continue
            if chip == "all":
                pass
            elif chip == "known":
                if self._reason_bucket(p) != "known":
                    continue
            elif chip == "heuristic":
                if self._reason_bucket(p) != "heuristic":
                    continue
            elif chip == "dispute":
                if not self._is_disputed(p):
                    continue
            elif chip == "resolved":
                if p not in self._threat_resolved:
                    continue
            elif chip == "suspicious":
                if self._severity_for(p) != "suspicious":
                    continue
            out.append(p)

        # Collapsible mode: place suspicious entries at the END so they group
        # cleanly under a single "Heuristic Findings" header in the master pane.
        if display_mode == "collapsible" and chip not in ("suspicious", "heuristic"):
            confirmed = [p for p in out if self._severity_for(p) == "confirmed"]
            suspicious = [p for p in out if self._severity_for(p) == "suspicious"]
            out = confirmed + suspicious

        return out

    def _build_threat_actions(self):
        """v1.9 — master-detail Threat Actions panel."""
        frame = self._threat_actions_frame
        for w in frame.winfo_children():
            w.destroy()

        all_paths = self._get_all_infected_paths()
        if not all_paths:
            frame.grid_remove()
            self._threat_selected_path = None
            return

        frame.grid()
        frame.grid_columnconfigure(0, weight=55)
        frame.grid_columnconfigure(1, weight=45)

        # ── Row 0: header + dispute banner + Quarantine-All ──
        self._build_threat_header(frame, all_paths)

        # ── Row 1: pagination + search + chips ──
        self._build_threat_pagination(frame)

        # ── Row 2: master (col 0) and detail (col 1) panes ──
        self._threat_master_frame = ctk.CTkScrollableFrame(
            frame, height=420, fg_color="#12121e", corner_radius=6)
        self._threat_master_frame.grid(
            row=2, column=0, sticky="nsew", padx=(14, 4), pady=(0, 6))
        self._threat_master_frame.grid_columnconfigure(0, weight=1)

        self._threat_detail_frame = ctk.CTkScrollableFrame(
            frame, height=420, fg_color="#12121e", corner_radius=6)
        self._threat_detail_frame.grid(
            row=2, column=1, sticky="nsew", padx=(4, 14), pady=(0, 6))
        self._threat_detail_frame.grid_columnconfigure(0, weight=1)

        # ── Row 3: bulk-action footer ──
        self._threat_bulk_frame = ctk.CTkFrame(frame, fg_color="#0e0e1a", corner_radius=6)
        self._threat_bulk_frame.grid(
            row=3, column=0, columnspan=2, sticky="ew",
            padx=14, pady=(0, 10))
        self._threat_bulk_frame.grid_columnconfigure(0, weight=1)

        # Keyboard nav binds (focus required)
        self._threat_master_frame.bind("<Up>",     lambda e: self._on_kbd_move(-1))
        self._threat_master_frame.bind("<Down>",   lambda e: self._on_kbd_move(+1))
        self._threat_master_frame.bind("<space>",  lambda e: self._on_kbd_toggle_check())
        self._threat_master_frame.bind("<Return>", lambda e: self._on_kbd_quarantine())

        # Initial population
        self._render_threat_master()
        self._render_threat_detail()
        self._render_bulk_footer()

    def _build_threat_header(self, frame: ctk.CTkFrame, all_paths: list[str]):
        """Header row: title + dispute banner + Quarantine-All."""
        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.grid(row=0, column=0, columnspan=2, sticky="ew",
                    padx=14, pady=(10, 4))
        header.grid_columnconfigure(0, weight=1)

        n = len(all_paths)
        title = ctk.CTkLabel(
            header, text=f"Threat Actions  ({n} file{'s' if n != 1 else ''})",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#ff5555", anchor="w")
        title.grid(row=0, column=0, sticky="w")

        # Dispute banner (only shown if disputes exist)
        if self._disputes:
            resolved_n = sum(1 for d in self._disputes
                             if d["path"] in self._threat_resolved)
            remaining = len(self._disputes) - resolved_n
            banner_text = (
                f"⚠  {len(self._disputes)} dispute(s) — "
                f"{resolved_n} resolved, {remaining} remaining")
            banner = ctk.CTkLabel(
                header, text=banner_text,
                font=ctk.CTkFont(size=11),
                text_color="#ffb86c", anchor="w")
            banner.grid(row=1, column=0, sticky="w", pady=(2, 0))
            self._threat_dispute_banner = banner

        # v1.10: Circuit breaker banner — prominent red, pinned above the panel.
        # Built into the header row so it sits before pagination/list.
        if (self._circuit_state.get("tripped")
                and not self._circuit_banner_dismissed):
            self._render_circuit_banner(header, row=2)

        _qall_btn = ctk.CTkButton(
            header, text=f"Quarantine All ({n})", width=130, height=26,
            fg_color="#5a1a1a", hover_color="#7a2020",
            font=ctk.CTkFont(size=11))
        _qall_btn.configure(
            command=lambda b=_qall_btn, ps=all_paths:
                self._quarantine_all_threats(ps, b))
        _qall_btn.grid(row=0, column=1, rowspan=2, sticky="e", padx=(8, 0))

    def _render_circuit_banner(self, parent: ctk.CTkFrame | None = None,
                                row: int = 0):
        """Show the prominent red banner indicating the circuit breaker tripped.

        Gemini-mandated: 'The user needs to know that the engine stopped
        looking so they don't assume the rest of the drive is clean.'
        """
        if parent is None:
            # Re-rendering pass: caller is from _on_done for Guardian — rebuild
            # the whole threat actions panel so the banner appears in the header.
            self._build_threat_actions()
            return

        state = self._circuit_state or {}
        hit_count = state.get("hit_count", 0)
        threshold = state.get("threshold", 0)

        banner = ctk.CTkFrame(parent, fg_color="#5a1a1a", corner_radius=6,
                               border_width=1, border_color="#a02020")
        banner.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(8, 4))
        banner.grid_columnconfigure(0, weight=1)
        self._threat_circuit_banner = banner

        text = (
            f"🛑  Guardian heuristic engine entered safety mode\n"
            f"{hit_count} pattern matches exceeded threshold ({threshold}) mid-scan — "
            f"pattern tier disabled for remainder. "
            f"Hash detections (tiers 1–3) ran normally. "
            f"Review pattern settings or consider Conservative profile.")
        ctk.CTkLabel(
            banner, text=text, font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#ffe0e0", anchor="w", justify="left",
            wraplength=720).grid(row=0, column=0, sticky="w", padx=14, pady=(10, 6))

        btn_row = ctk.CTkFrame(banner, fg_color="transparent")
        btn_row.grid(row=1, column=0, sticky="w", padx=12, pady=(0, 10))

        def _open_settings():
            if self._nav_cb:
                self._nav_cb("settings")
        def _dismiss():
            self._circuit_banner_dismissed = True
            self._build_threat_actions()

        ctk.CTkButton(btn_row, text="Open Guardian Settings", width=170, height=26,
                      fg_color="#7a2020", hover_color="#a03030",
                      font=ctk.CTkFont(size=11),
                      command=_open_settings).grid(row=0, column=0, padx=(0, 8))
        ctk.CTkButton(btn_row, text="Dismiss", width=80, height=26,
                      fg_color="#3a1a1a", hover_color="#5a2a2a",
                      font=ctk.CTkFont(size=11),
                      command=_dismiss).grid(row=0, column=1)

    def _build_threat_pagination(self, frame: ctk.CTkFrame):
        """Pagination row + search entry + reason filter chips."""
        pag = ctk.CTkFrame(frame, fg_color="transparent")
        pag.grid(row=1, column=0, columnspan=2, sticky="ew",
                 padx=14, pady=(0, 6))
        pag.grid_columnconfigure(2, weight=1)
        self._threat_pagination_frame = pag

        # Page indicator + nav buttons
        filtered = self._get_filtered_paths()
        total = len(filtered)
        total_pages = max(1, (total + self._threat_page_size - 1)
                          // self._threat_page_size)
        self._threat_page = min(self._threat_page, total_pages - 1)
        page_lbl = ctk.CTkLabel(
            pag, text=f"Page {self._threat_page + 1} of {total_pages}",
            font=ctk.CTkFont(size=11), text_color="#cdd6f4")
        page_lbl.grid(row=0, column=0, sticky="w")

        prev_btn = ctk.CTkButton(
            pag, text="◀ Prev", width=64, height=24,
            fg_color="#2a2a4a", hover_color="#3a3a5a",
            font=ctk.CTkFont(size=11),
            state=("normal" if self._threat_page > 0 else "disabled"),
            command=lambda: self._on_page_change(-1))
        prev_btn.grid(row=0, column=1, padx=(8, 0))

        next_btn = ctk.CTkButton(
            pag, text="Next ▶", width=64, height=24,
            fg_color="#2a2a4a", hover_color="#3a3a5a",
            font=ctk.CTkFont(size=11),
            state=("normal" if self._threat_page < total_pages - 1
                   else "disabled"),
            command=lambda: self._on_page_change(+1))
        next_btn.grid(row=0, column=2, padx=(4, 0), sticky="w")

        # Search entry
        search_lbl = ctk.CTkLabel(
            pag, text="Search:", font=ctk.CTkFont(size=11),
            text_color="#888888")
        search_lbl.grid(row=0, column=3, padx=(12, 4))
        search_var = ctk.StringVar(value=self._threat_filter_text)
        search_entry = ctk.CTkEntry(
            pag, textvariable=search_var, width=180, height=24,
            font=ctk.CTkFont(size=11))
        search_entry.grid(row=0, column=4, padx=(0, 8))
        search_var.trace_add("write",
                             lambda *_: self._on_search_change(search_var.get()))

        # Reason chips (v1.10: added Suspicious)
        chips_frame = ctk.CTkFrame(pag, fg_color="transparent")
        chips_frame.grid(row=1, column=0, columnspan=5, sticky="w", pady=(4, 0))
        # Count suspicious entries to surface visibility when chip is "hidden" mode
        all_paths = self._get_all_infected_paths()
        susp_count = sum(1 for p in all_paths if self._severity_for(p) == "suspicious"
                         and p not in self._threat_resolved)
        chip_defs = [
            ("all",        "All"),
            ("known",      "Known Signature"),
            ("heuristic",  "Heuristic / Pattern"),
            ("suspicious", f"Suspicious ({susp_count})" if susp_count else "Suspicious"),
            ("dispute",    "Dispute"),
            ("resolved",   "Resolved"),
        ]
        for idx, (key, label) in enumerate(chip_defs):
            active = (self._threat_filter_reason == key)
            chip = ctk.CTkButton(
                chips_frame, text=label, width=120, height=22,
                fg_color=("#3a3a6a" if active else "#1e1e2e"),
                hover_color=("#4a4a8a" if active else "#2a2a3a"),
                border_width=(1 if not active else 0),
                border_color="#3a3a4a",
                font=ctk.CTkFont(size=10),
                command=lambda k=key: self._on_chip_change(k))
            chip.grid(row=0, column=idx, padx=(0, 6))

    # ── Master pane rendering ────────────────────────────────────────────────

    def _render_threat_master(self):
        """Render the visible page of the master list."""
        master = self._threat_master_frame
        if master is None:
            return
        for w in master.winfo_children():
            w.destroy()
        self._row_registry.clear()

        filtered = self._get_filtered_paths()
        start = self._threat_page * self._threat_page_size
        end   = min(start + self._threat_page_size, len(filtered))
        page_paths = filtered[start:end]

        if not page_paths:
            ctk.CTkLabel(
                master, text="(no threats match current filter)",
                font=ctk.CTkFont(size=11), text_color="#555577").grid(
                row=0, column=0, pady=20)
            return

        # Master header: select-all checkbox + count
        hdr = ctk.CTkFrame(master, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", pady=(2, 4), padx=4)
        hdr.grid_columnconfigure(1, weight=1)

        all_on_page_checked = all(p in self._threat_checked for p in page_paths)
        sel_var = ctk.BooleanVar(value=all_on_page_checked)
        sel_chk = ctk.CTkCheckBox(
            hdr, text="", variable=sel_var, width=22, height=22,
            command=lambda: self._on_select_all_page(sel_var.get(), page_paths))
        sel_chk.grid(row=0, column=0, padx=(2, 0))

        ctk.CTkLabel(
            hdr, text=f"Select all on page ({len(page_paths)})  •  "
                     f"In filter: {len(filtered)}",
            font=ctk.CTkFont(size=10), text_color="#888888",
            anchor="w").grid(row=0, column=1, sticky="w", padx=(4, 0))

        sel_all_filter_btn = ctk.CTkButton(
            hdr, text=f"Select all in filter ({len(filtered)})",
            width=170, height=22,
            fg_color="#2a2a4a", hover_color="#3a3a5a",
            font=ctk.CTkFont(size=10),
            command=lambda: self._on_select_all_filter(filtered))
        sel_all_filter_btn.grid(row=0, column=2, padx=(0, 4))

        clear_btn = ctk.CTkButton(
            hdr, text="Clear", width=60, height=22,
            fg_color="#2a2a4a", hover_color="#3a3a5a",
            font=ctk.CTkFont(size=10),
            command=self._on_clear_selection)
        clear_btn.grid(row=0, column=3, padx=(0, 2))

        # Rows
        display_mode = (cfg.get("guardian_suspicious_display") or "hidden").lower()
        # In collapsible mode the filtered list is already sorted Confirmed-then-Suspicious;
        # inject a "Heuristic Findings ▸/▾" header between the two groups (if both present).
        row_idx = 0
        heuristic_header_inserted = False
        for i, path in enumerate(page_paths):
            is_susp = self._severity_for(path) == "suspicious"
            if (display_mode == "collapsible" and is_susp
                    and not heuristic_header_inserted
                    and self._threat_filter_reason not in ("suspicious", "heuristic")):
                heuristic_header_inserted = True
                row_idx += 1
                self._build_heuristic_header(master, row_idx, page_paths[i:])
                if self._heuristic_collapsed:
                    break   # Don't render suspicious rows when collapsed
            row_idx += 1
            self._build_master_row(master, path, row_idx)

    def _build_heuristic_header(self, parent: ctk.CTkFrame, row_idx: int,
                                 suspicious_paths: list[str]):
        """Build the 'Heuristic Findings (N) ▸/▾' separator row for collapsible mode."""
        n = sum(1 for p in suspicious_paths
                if self._severity_for(p) == "suspicious")
        chevron = "▸" if self._heuristic_collapsed else "▾"
        hdr = ctk.CTkFrame(parent, fg_color="#1c1c1f", corner_radius=4)
        hdr.grid(row=row_idx, column=0, sticky="ew", pady=(6, 1))
        hdr.grid_columnconfigure(0, weight=1)

        def _toggle(_=None):
            self._heuristic_collapsed = not self._heuristic_collapsed
            self._render_threat_master()

        lbl = ctk.CTkLabel(
            hdr, text=f"  {chevron}  Heuristic Findings  ({n} suspicious — review-only)",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#ffb86c", anchor="w")
        lbl.grid(row=0, column=0, sticky="w", padx=8, pady=6)
        for w in (hdr, lbl):
            w.bind("<Button-1>", _toggle)

    def _build_master_row(self, parent: ctk.CTkFrame, path: str, row_idx: int):
        """Build one row in the master pane. v1.10: tier-aware visual styling."""
        is_selected = (path == self._threat_selected_path)
        is_resolved = path in self._threat_resolved
        severity    = self._severity_for(path)
        is_suspicious = (severity == "suspicious")

        # Suspicious rows use a dimmer background and lighter weight so the user
        # can tune them out at a glance. Selection still wins.
        if is_selected:
            bg = "#2a2a4a"
        elif is_suspicious:
            bg = "#171720" if row_idx % 2 == 0 else "#15151c"
        else:
            bg = "#1e1e2e" if row_idx % 2 == 0 else "#1a1a26"

        row_f = ctk.CTkFrame(parent, fg_color=bg, corner_radius=4)
        row_f.grid(row=row_idx, column=0, sticky="ew", pady=1)
        row_f.grid_columnconfigure(3, weight=1)
        self._row_registry[path] = row_f

        # Checkbox
        check_var = ctk.BooleanVar(value=(path in self._threat_checked))
        chk = ctk.CTkCheckBox(
            row_f, text="", variable=check_var, width=22, height=22,
            command=lambda p=path, v=check_var: self._on_row_check_toggle(p, v))
        chk.grid(row=0, column=0, rowspan=2, padx=(8, 4), pady=4)

        # Severity badge (v1.10): icon + optional inline label
        display_mode = (cfg.get("guardian_suspicious_display") or "hidden").lower()
        if is_resolved:
            sev_icon, sev_color = "✓", "#50fa7b"
        elif self._is_disputed(path):
            sev_icon, sev_color = "⚠", "#ffb86c"
        elif is_suspicious:
            sev_icon, sev_color = "⚠", "#ffb86c"   # amber, dimmer
        else:
            sev_icon, sev_color = "●", "#ff5555"   # confirmed red

        ctk.CTkLabel(row_f, text=sev_icon, font=ctk.CTkFont(size=14),
                     text_color=sev_color, width=18).grid(
            row=0, column=1, rowspan=2, padx=(0, 2))

        # Inline mode shows a CONFIRMED / SUSPICIOUS text badge as well
        if display_mode == "inline":
            badge_text = ("SUSPICIOUS" if is_suspicious
                          else ("RESOLVED" if is_resolved else "CONFIRMED"))
            badge_color = ("#ffb86c" if is_suspicious
                           else ("#50fa7b" if is_resolved else "#ff5555"))
            ctk.CTkLabel(row_f, text=badge_text,
                         font=ctk.CTkFont(size=9, weight="bold"),
                         text_color=badge_color, width=80).grid(
                row=0, column=2, rowspan=2, padx=(0, 4))

        # Filename + directory
        name = Path(path).name
        dir_part = str(Path(path).parent)
        if len(dir_part) > 70:
            dir_part = "…" + dir_part[-69:]

        # Color & weight differ by severity (dimmer + lighter weight for suspicious)
        if is_resolved:
            filename_color = "#888888"
            filename_weight = "normal"
        elif is_suspicious:
            filename_color = "#cdb990"    # dim amber-tinted off-white
            filename_weight = "normal"    # not bold — lower visual weight
        else:
            filename_color = "#ff8888"
            filename_weight = "bold"

        name_lbl = ctk.CTkLabel(
            row_f, text=name, anchor="w",
            text_color=filename_color,
            font=ctk.CTkFont(size=12, weight=filename_weight))
        name_lbl.grid(row=0, column=3, sticky="w", padx=(0, 4), pady=(4, 0))
        dir_lbl = ctk.CTkLabel(
            row_f, text=dir_part, anchor="w",
            text_color="#666688",
            font=ctk.CTkFont(size=10))
        dir_lbl.grid(row=1, column=3, sticky="w", padx=(0, 4), pady=(0, 4))

        # Click anywhere on the row (except checkbox) selects it
        for w in (row_f, name_lbl, dir_lbl):
            w.bind("<Button-1>",
                   lambda e, p=path: self._on_row_click(p))

    # ── Detail pane rendering ────────────────────────────────────────────────

    def _render_threat_detail(self):
        """Render the right-side detail pane for the currently selected path."""
        detail = self._threat_detail_frame
        if detail is None:
            return
        for w in detail.winfo_children():
            w.destroy()

        path = self._threat_selected_path
        if not path:
            ctk.CTkLabel(
                detail,
                text="Select a file on the left to see its details.",
                font=ctk.CTkFont(size=11),
                text_color="#555577", anchor="center").grid(
                row=0, column=0, pady=40, padx=20)
            return

        row = 0

        # Filename header
        ctk.CTkLabel(
            detail, text=Path(path).name, anchor="w",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#cdd6f4", wraplength=480).grid(
            row=row, column=0, sticky="w", padx=10, pady=(8, 0))
        row += 1

        # Full path
        ctk.CTkLabel(
            detail, text=path, anchor="w",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color="#888888", wraplength=480).grid(
            row=row, column=0, sticky="w", padx=10, pady=(0, 6))
        row += 1

        # File size + hashes
        info_frame = ctk.CTkFrame(detail, fg_color="#1e1e2e", corner_radius=6)
        info_frame.grid(row=row, column=0, sticky="ew", padx=10, pady=4)
        info_frame.grid_columnconfigure(1, weight=1)
        row += 1

        # Size (instant)
        try:
            size_bytes = Path(path).stat().st_size
            size_str = f"{size_bytes:,} bytes ({_human_size(size_bytes)})"
        except Exception:
            size_str = "—"
        ctk.CTkLabel(info_frame, text="Size:", font=ctk.CTkFont(size=10),
                     text_color="#666688").grid(
            row=0, column=0, sticky="w", padx=10, pady=(6, 2))
        ctk.CTkLabel(info_frame, text=size_str, font=ctk.CTkFont(size=10),
                     text_color="#cdd6f4").grid(
            row=0, column=1, sticky="w", pady=(6, 2))

        # MD5 / SHA-256 (lazy)
        cached = self._hash_cache.get(path, {})
        md5_str    = cached.get("md5", "computing…")
        sha256_str = cached.get("sha256", "computing…")
        ctk.CTkLabel(info_frame, text="MD5:", font=ctk.CTkFont(size=10),
                     text_color="#666688").grid(
            row=1, column=0, sticky="w", padx=10, pady=2)
        md5_lbl = ctk.CTkLabel(info_frame, text=md5_str,
                               font=ctk.CTkFont(family="Consolas", size=10),
                               text_color="#cdd6f4")
        md5_lbl.grid(row=1, column=1, sticky="w", pady=2)
        ctk.CTkLabel(info_frame, text="SHA-256:", font=ctk.CTkFont(size=10),
                     text_color="#666688").grid(
            row=2, column=0, sticky="w", padx=10, pady=(2, 6))
        sha_lbl = ctk.CTkLabel(info_frame, text=sha256_str,
                               font=ctk.CTkFont(family="Consolas", size=10),
                               text_color="#cdd6f4", wraplength=320)
        sha_lbl.grid(row=2, column=1, sticky="w", pady=(2, 6))
        if "md5" not in cached:
            self._compute_hashes_async(path, md5_lbl, sha_lbl)

        # v1.10: Consensus badge (above engine verdicts)
        verdicts = self._get_engine_verdicts(path)
        n_engines = len(verdicts)
        g_tier = self._g_tier.get(path, "")
        if n_engines >= 3:
            badge_text  = f"🛡  Confirmed by {n_engines} engines — high confidence"
            badge_color = "#ff5555"
        elif n_engines == 2:
            badge_text  = f"●  Confirmed by 2 engines"
            badge_color = "#ff8c42"
        elif n_engines == 1 and g_tier == "pattern":
            # The most important case: lone Guardian heuristic with no hash backing
            badge_text  = ("⚠  Single-engine heuristic — likely false positive "
                           "(hash engines say clean)")
            badge_color = "#ffb86c"
        else:
            badge_text  = "⚠  Single-engine signature match — review carefully"
            badge_color = "#ffb86c"
        badge_frame = ctk.CTkFrame(detail,
                                    fg_color=("#3a2a1a" if n_engines < 2 else "#2a1a1a"),
                                    corner_radius=6)
        badge_frame.grid(row=row, column=0, sticky="ew", padx=10, pady=(8, 4))
        ctk.CTkLabel(
            badge_frame, text=badge_text,
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=badge_color, anchor="w", wraplength=440).pack(
            anchor="w", padx=10, pady=6)
        row += 1

        # Engine verdicts
        ctk.CTkLabel(detail, text="Engine verdicts:", font=ctk.CTkFont(size=11, weight="bold"),
                     text_color="#5294e2", anchor="w").grid(
            row=row, column=0, sticky="w", padx=10, pady=(8, 2))
        row += 1
        if not verdicts:
            ctk.CTkLabel(detail, text="(no engine flagged this file)",
                         font=ctk.CTkFont(size=10), text_color="#666688",
                         anchor="w").grid(
                row=row, column=0, sticky="w", padx=14, pady=2)
            row += 1
        for engine, flagged, reason in verdicts:
            sym = "✗" if flagged else "✓"
            col = "#ff5555" if flagged else "#50fa7b"
            line = f"{sym}  {engine}  —  {reason[:80]}"
            ctk.CTkLabel(detail, text=line, font=ctk.CTkFont(size=10),
                         text_color=col, anchor="w", wraplength=480).grid(
                row=row, column=0, sticky="w", padx=14, pady=1)
            row += 1

        # v1.10: "Why was this flagged?" Match Context block
        match_ctx = self._g_context.get(path, "")
        if match_ctx:
            ctx_frame = ctk.CTkFrame(detail, fg_color="#1c1814",
                                      corner_radius=6,
                                      border_width=1, border_color="#5a4a2a")
            ctx_frame.grid(row=row, column=0, sticky="ew", padx=10, pady=(8, 4))
            ctx_frame.grid_columnconfigure(0, weight=1)
            row += 1

            ctk.CTkLabel(
                ctx_frame, text="Why was this flagged?",
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color="#ffb86c", anchor="w").grid(
                row=0, column=0, sticky="w", padx=12, pady=(8, 0))

            # Extract the pattern label from the Guardian reason for display.
            g_reason = self._g_infected.get(path, "")
            _SUSP_PREFIX = "Suspicious pattern: "
            pat_label = (g_reason[len(_SUSP_PREFIX):]
                         if g_reason.startswith(_SUSP_PREFIX) else g_reason)
            ctk.CTkLabel(
                ctx_frame, text=f"Pattern: {pat_label}",
                font=ctk.CTkFont(size=10),
                text_color="#cdd6f4", anchor="w").grid(
                row=1, column=0, sticky="w", padx=12, pady=(2, 4))

            snippet_box = ctk.CTkTextbox(
                ctx_frame, height=60, wrap="word",
                font=ctk.CTkFont(family="Consolas", size=10),
                fg_color="#0e0e1a")
            snippet_box.grid(row=2, column=0, sticky="ew", padx=12, pady=(0, 10))
            snippet_box.insert("0.0", match_ctx)
            snippet_box.configure(state="disabled")

        # Content preview (lazy: skip large or binary)
        preview = cached.get("preview")
        if preview is None and "md5" in cached:   # only after hash done
            preview = cached.get("preview", "")
        if preview:
            ctk.CTkLabel(detail, text="Preview (first 200 bytes):",
                         font=ctk.CTkFont(size=11, weight="bold"),
                         text_color="#5294e2", anchor="w").grid(
                row=row, column=0, sticky="w", padx=10, pady=(8, 2))
            row += 1
            preview_box = ctk.CTkTextbox(detail, height=80, wrap="word",
                                          font=ctk.CTkFont(family="Consolas", size=10),
                                          fg_color="#0e0e1a")
            preview_box.grid(row=row, column=0, sticky="ew", padx=10, pady=(0, 4))
            preview_box.insert("0.0", preview)
            preview_box.configure(state="disabled")
            row += 1

        # Action buttons
        actions = ctk.CTkFrame(detail, fg_color="transparent")
        actions.grid(row=row, column=0, sticky="ew", padx=10, pady=(8, 4))
        row += 1

        ctk.CTkButton(actions, text="Quarantine", width=86, height=26,
                      fg_color="#5a1a1a", hover_color="#7a2020",
                      font=ctk.CTkFont(size=11),
                      command=lambda: self._action_quarantine(path)
                      ).grid(row=0, column=0, padx=(0, 4))
        ctk.CTkButton(actions, text="Open", width=58, height=26,
                      fg_color="#2a4a2a", hover_color="#3a6a3a",
                      font=ctk.CTkFont(size=11),
                      command=lambda: self._open_in_explorer(path)
                      ).grid(row=0, column=1, padx=4)
        ctk.CTkButton(actions, text="Ignore…", width=72, height=26,
                      fg_color="#4a4a1a", hover_color="#6a6a2a",
                      font=ctk.CTkFont(size=11),
                      command=lambda: self._action_ignore([path])
                      ).grid(row=0, column=2, padx=4)
        ctk.CTkButton(actions, text="VirusTotal", width=84, height=26,
                      fg_color="#1a3a5a", hover_color="#1f4a7a",
                      font=ctk.CTkFont(size=11),
                      command=lambda: self._send_to_virustotal(path)
                      ).grid(row=0, column=3, padx=4)
        if self._nav_cb:
            ctk.CTkButton(actions, text="Analyze", width=76, height=26,
                          fg_color="#2a1a5a", hover_color="#3a2070",
                          font=ctk.CTkFont(size=11),
                          command=lambda: self._open_behavioral("behavioral", path)
                          ).grid(row=0, column=4, padx=4)

        # Dispute Mode panel (only for disputed files)
        dispute = self._dispute_for_path(path)
        if dispute:
            self._build_dispute_mode_panel(detail, row, path, dispute)
            row += 1

    def _build_dispute_mode_panel(self, parent: ctk.CTkFrame, grid_row: int,
                                   path: str, dispute: dict):
        """Inline Dispute Mode block (replaces the old DisputePopup)."""
        is_resolved = path in self._threat_resolved
        title = "Dispute Mode" + ("  •  Resolved" if is_resolved else "")
        panel = ctk.CTkFrame(parent, fg_color="#251818", corner_radius=8,
                              border_width=1, border_color="#5a2a2a")
        panel.grid(row=grid_row, column=0, sticky="ew", padx=10, pady=(6, 8))
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(panel, text=f"⚠  {title}",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color="#ffb86c", anchor="w").grid(
            row=0, column=0, columnspan=2, sticky="w", padx=10, pady=(8, 2))

        # k2 verdict
        k2_col = "#ff5555" if dispute["k2_verdict"] == "Infected" else "#50fa7b"
        kf = ctk.CTkFrame(panel, fg_color="#1a1a2e", corner_radius=6)
        kf.grid(row=1, column=0, sticky="ew", padx=(10, 4), pady=4)
        ctk.CTkLabel(kf, text="k2 Engine", font=ctk.CTkFont(size=10, weight="bold"),
                     text_color="#5294e2").pack(anchor="w", padx=10, pady=(6, 0))
        ctk.CTkLabel(kf, text=dispute["k2_verdict"],
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=k2_col).pack(anchor="w", padx=10, pady=(0, 6))

        # Guardian verdict
        gcol = "#ff5555" if dispute["guardian_verdict"] == "Infected" else "#50fa7b"
        gf = ctk.CTkFrame(panel, fg_color="#1a1a2e", corner_radius=6)
        gf.grid(row=1, column=1, sticky="ew", padx=(4, 10), pady=4)
        ctk.CTkLabel(gf, text="Guardian AI", font=ctk.CTkFont(size=10, weight="bold"),
                     text_color="#f1fa8c").pack(anchor="w", padx=10, pady=(6, 0))
        ctk.CTkLabel(gf, text=dispute["guardian_verdict"],
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=gcol).pack(anchor="w", padx=10)
        reason = dispute.get("guardian_reason", "")[:90]
        if reason:
            ctk.CTkLabel(gf, text=reason, font=ctk.CTkFont(size=9),
                         text_color="#888888", wraplength=200,
                         anchor="w", justify="left").pack(anchor="w", padx=10, pady=(0, 6))

        # Resolve buttons (only if not resolved)
        if not is_resolved:
            res = ctk.CTkFrame(panel, fg_color="transparent")
            res.grid(row=2, column=0, columnspan=2, sticky="ew",
                     padx=10, pady=(4, 8))
            ctk.CTkButton(res, text="✓  Trust K2", width=110, height=26,
                          fg_color="#1a3a1a", hover_color="#2a5a2a",
                          font=ctk.CTkFont(size=11),
                          command=lambda: self._resolve_dispute(path, "trust_k2")
                          ).grid(row=0, column=0, padx=(0, 6))
            ctk.CTkButton(res, text="⚠  Trust Guardian", width=140, height=26,
                          fg_color="#5a1a1a", hover_color="#7a2020",
                          font=ctk.CTkFont(size=11),
                          command=lambda: self._resolve_dispute(path, "trust_guardian")
                          ).grid(row=0, column=1)

    # ── Bulk action footer ───────────────────────────────────────────────────

    def _render_bulk_footer(self):
        """Render the footer bulk-action row OR the progress bar (during ops)."""
        bf = self._threat_bulk_frame
        if bf is None:
            return
        for w in bf.winfo_children():
            w.destroy()

        n_selected = len(self._threat_checked)
        ctk.CTkLabel(
            bf, text=f"Bulk actions  ({n_selected} selected)",
            font=ctk.CTkFont(size=11), text_color="#888888",
            anchor="w").grid(row=0, column=0, sticky="w", padx=12, pady=6)

        state = "normal" if n_selected > 0 else "disabled"

        btn_q = ctk.CTkButton(
            bf, text="Quarantine Selected", width=160, height=26,
            fg_color="#5a1a1a", hover_color="#7a2020",
            font=ctk.CTkFont(size=11), state=state,
            command=lambda: self._bulk_action("quarantine"))
        btn_q.grid(row=0, column=1, padx=4, pady=6)

        btn_i = ctk.CTkButton(
            bf, text="Ignore Selected", width=130, height=26,
            fg_color="#4a4a1a", hover_color="#6a6a2a",
            font=ctk.CTkFont(size=11), state=state,
            command=lambda: self._bulk_action("ignore"))
        btn_i.grid(row=0, column=2, padx=4, pady=6)

        btn_d = ctk.CTkButton(
            bf, text="Delete Selected", width=130, height=26,
            fg_color="#3a1a1a", hover_color="#5a2a2a",
            font=ctk.CTkFont(size=11), state=state,
            command=lambda: self._bulk_action("delete"))
        btn_d.grid(row=0, column=3, padx=(4, 12), pady=6)

    # ── Filter / pagination handlers ─────────────────────────────────────────

    def _on_page_change(self, delta: int):
        self._threat_page = max(0, self._threat_page + delta)
        self._build_threat_actions()

    def _on_search_change(self, value: str):
        self._threat_filter_text = value
        self._threat_page = 0
        self._build_threat_actions()

    def _on_chip_change(self, key: str):
        self._threat_filter_reason = key
        self._threat_page = 0
        self._build_threat_actions()

    # ── Row selection / checkbox handlers ────────────────────────────────────

    def _on_row_click(self, path: str):
        self._threat_selected_path = path
        # Recolor previous selected row (cheap: rebuild visible page)
        self._render_threat_master()
        self._render_threat_detail()

    def _on_row_check_toggle(self, path: str, var: ctk.BooleanVar):
        if var.get():
            self._threat_checked.add(path)
        else:
            self._threat_checked.discard(path)
        self._render_bulk_footer()

    def _on_select_all_page(self, checked: bool, paths: list[str]):
        if checked:
            self._threat_checked.update(paths)
        else:
            for p in paths:
                self._threat_checked.discard(p)
        self._render_threat_master()
        self._render_bulk_footer()

    def _on_select_all_filter(self, paths: list[str]):
        self._threat_checked.update(paths)
        self._render_threat_master()
        self._render_bulk_footer()

    def _on_clear_selection(self):
        self._threat_checked.clear()
        self._render_threat_master()
        self._render_bulk_footer()

    # ── Keyboard handlers ────────────────────────────────────────────────────

    def _on_kbd_move(self, delta: int):
        filtered = self._get_filtered_paths()
        if not filtered:
            return
        start = self._threat_page * self._threat_page_size
        end   = min(start + self._threat_page_size, len(filtered))
        page  = filtered[start:end]
        if not page:
            return
        try:
            idx = page.index(self._threat_selected_path) if self._threat_selected_path in page else -1
        except ValueError:
            idx = -1
        new_idx = max(0, min(len(page) - 1, idx + delta))
        self._on_row_click(page[new_idx])

    def _on_kbd_toggle_check(self):
        p = self._threat_selected_path
        if not p:
            return
        if p in self._threat_checked:
            self._threat_checked.discard(p)
        else:
            self._threat_checked.add(p)
        self._render_threat_master()
        self._render_bulk_footer()

    def _on_kbd_quarantine(self):
        p = self._threat_selected_path
        if p:
            self._action_quarantine(p)

    # ── Action implementations ───────────────────────────────────────────────

    def _action_quarantine(self, path: str):
        from ui.core import quarantine as quar
        ok, msg = quar.move_to_quarantine(path)
        self._status_cb(msg)
        self._log_append(f"[{'OK' if ok else 'ERR'}] {msg}",
                         _TAG_CLEAN if ok else _TAG_WARN)
        if ok:
            self._mark_resolved(path, "quarantined")

    def _open_in_explorer(self, path: str):
        """Open Windows Explorer with the given file pre-selected."""
        try:
            p = Path(path)
            if p.exists():
                subprocess.Popen(
                    ["explorer", "/select,", str(p)],
                    creationflags=subprocess.CREATE_NO_WINDOW)
            else:
                # File missing — open the parent directory instead
                parent = p.parent
                if parent.exists():
                    subprocess.Popen(
                        ["explorer", str(parent)],
                        creationflags=subprocess.CREATE_NO_WINDOW)
                else:
                    self._status_cb(f"Path no longer exists: {path}")
        except Exception as exc:
            self._status_cb(f"Open in Explorer failed: {exc}")

    def _action_ignore(self, paths: list[str]):
        """Open the Ignore… dialog (or batch dialog) for the given paths."""
        if not paths:
            return
        self._open_ignore_dialog(paths)

    def _open_ignore_dialog(self, paths: list[str]):
        """Modal note-prompt dialog for adding files to the ignore list."""
        dlg = ctk.CTkToplevel(self)
        dlg.title("Ignore hash" + ("es" if len(paths) > 1 else ""))
        dlg.geometry("460x180")
        dlg.resizable(False, False)
        dlg.configure(fg_color="#12121e")
        dlg.transient(self.winfo_toplevel())
        dlg.attributes("-topmost", True)

        head = "Ignore this file's hash" if len(paths) == 1 \
               else f"Ignore {len(paths)} files' hashes"
        ctk.CTkLabel(dlg, text=head,
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#ffb86c").pack(anchor="w", padx=20, pady=(16, 4))
        ctk.CTkLabel(dlg,
                     text="These files won't be flagged by Guardian AI on future scans.",
                     font=ctk.CTkFont(size=10), text_color="#888888").pack(
            anchor="w", padx=20, pady=(0, 8))
        ctk.CTkLabel(dlg, text="Note (optional):",
                     font=ctk.CTkFont(size=10),
                     text_color="#cdd6f4").pack(anchor="w", padx=20)

        note_var = ctk.StringVar()
        entry = ctk.CTkEntry(dlg, textvariable=note_var, width=420, height=28,
                              placeholder_text='e.g. "False positive — empty log file"')
        entry.pack(anchor="w", padx=20, pady=(2, 12))
        entry.focus_set()

        btn_row = ctk.CTkFrame(dlg, fg_color="transparent")
        btn_row.pack(anchor="e", padx=20, pady=(0, 14))

        def _on_confirm():
            note = note_var.get().strip()
            dlg.destroy()
            self._do_ignore(paths, note)

        def _on_cancel():
            dlg.destroy()

        ctk.CTkButton(btn_row, text="Cancel", width=80, height=28,
                      fg_color="#2a2a3a", hover_color="#3a3a4a",
                      command=_on_cancel).grid(row=0, column=0, padx=(0, 8))
        ctk.CTkButton(btn_row, text="Ignore", width=90, height=28,
                      fg_color="#4a4a1a", hover_color="#6a6a2a",
                      command=_on_confirm).grid(row=0, column=1)
        dlg.bind("<Return>", lambda e: _on_confirm())
        dlg.bind("<Escape>", lambda e: _on_cancel())

    def _do_ignore(self, paths: list[str], note: str):
        """Background-thread bulk ignore (computes MD5 per file)."""
        def _run():
            ok = 0
            for p in paths:
                try:
                    with open(p, "rb") as f:
                        md5 = hashlib.md5(f.read()).hexdigest()
                    reason = (self._g_infected.get(p)
                              or self._yara_infected.get(p)
                              or self._clamav_infected.get(p)
                              or self._defender_infected.get(p)
                              or "")
                    if ignore.add(md5, "md5", Path(p).name, note, reason):
                        ok += 1
                except Exception:
                    pass
            if self.winfo_exists():
                self.after(0, lambda: self._on_ignore_done(paths, ok))
        threading.Thread(target=_run, daemon=True).start()

    def _on_ignore_done(self, paths: list[str], ok: int):
        for p in paths:
            self._mark_resolved(p, "ignored")
            self._threat_checked.discard(p)
            # v1.10: track per-pattern session ignores to drive the auto-ignore prompt
            reason = self._g_infected.get(p, "")
            _SUSP = "Suspicious pattern: "
            if reason.startswith(_SUSP):
                label = reason[len(_SUSP):].strip()
                if label:
                    self._scan_session_ignored[label] = \
                        self._scan_session_ignored.get(label, 0) + 1
        self._log_append(
            f"[IGNORE] Added {ok}/{len(paths)} hash(es) to the ignore list.",
            _TAG_INFO)
        self._status_cb(f"Ignored {ok} file(s).")
        # Trigger the auto-ignore prompt if any pattern crossed the threshold.
        self._maybe_show_autoignore_prompt()
        self._build_threat_actions()

    def _maybe_show_autoignore_prompt(self) -> None:
        """If the user has ignored ≥3 files matching one pattern this session,
        prompt to disable the pattern in Guardian settings. v1.10."""
        try:
            if cfg.get("guardian_autoignore_prompt_dismissed"):
                return
        except Exception:
            pass
        # Pick the pattern with the highest session ignore count over threshold
        candidate = None
        candidate_count = 0
        for label, count in self._scan_session_ignored.items():
            if count >= 3 and count > candidate_count:
                candidate = label
                candidate_count = count
        if not candidate:
            return
        # Suppress duplicate prompts for the same pattern in this session
        toggles = cfg.get("guardian_pattern_toggles") or {}
        if candidate in toggles and toggles[candidate] is False:
            return   # already disabled
        self._show_autoignore_prompt(candidate, candidate_count)

    def _show_autoignore_prompt(self, pattern: str, count: int) -> None:
        """Non-modal CTkToplevel asking the user to disable a noisy pattern."""
        dlg = ctk.CTkToplevel(self)
        dlg.title("Disable noisy pattern?")
        dlg.geometry("520x220")
        dlg.resizable(False, False)
        dlg.configure(fg_color="#12121e")
        dlg.transient(self.winfo_toplevel())
        dlg.attributes("-topmost", True)

        ctk.CTkLabel(dlg, text="⚠  Frequent false positives",
                     font=ctk.CTkFont(size=14, weight="bold"),
                     text_color="#ffb86c").pack(anchor="w", padx=20, pady=(18, 4))
        ctk.CTkLabel(
            dlg,
            text=(f"You've ignored {count} files matching the Guardian pattern\n"
                  f"\"{pattern}\" in this scan session.\n\n"
                  "Disable this pattern in Guardian settings so it won't fire on "
                  "future scans? Existing ignored hashes remain on the ignore list."),
            font=ctk.CTkFont(size=11), text_color="#cdd6f4",
            wraplength=460, anchor="w", justify="left").pack(
            anchor="w", padx=20, pady=(0, 12))

        btn_row = ctk.CTkFrame(dlg, fg_color="transparent")
        btn_row.pack(anchor="e", padx=20, pady=(0, 16))

        def _disable():
            toggles = dict(cfg.get("guardian_pattern_toggles") or {})
            toggles[pattern] = False
            cfg.set_value("guardian_pattern_toggles", toggles)
            # Forget this pattern's session count so we don't re-prompt
            self._scan_session_ignored.pop(pattern, None)
            self._log_append(
                f"[Guardian] Disabled pattern '{pattern}' "
                "via auto-ignore prompt.", _TAG_INFO)
            dlg.destroy()
            self._build_threat_actions()

        def _keep():
            # Forget this pattern's session count so we don't re-prompt during this scan
            self._scan_session_ignored.pop(pattern, None)
            dlg.destroy()

        def _dont_ask():
            cfg.set_value("guardian_autoignore_prompt_dismissed", True)
            self._scan_session_ignored.clear()
            dlg.destroy()

        ctk.CTkButton(btn_row, text="Don't ask again", width=130, height=28,
                      fg_color="#2a2a3a", hover_color="#3a3a4a",
                      font=ctk.CTkFont(size=11),
                      command=_dont_ask).grid(row=0, column=0, padx=(0, 8))
        ctk.CTkButton(btn_row, text="Keep enabled", width=110, height=28,
                      fg_color="#3a3a4a", hover_color="#4a4a5a",
                      font=ctk.CTkFont(size=11),
                      command=_keep).grid(row=0, column=1, padx=(0, 8))
        ctk.CTkButton(btn_row, text="Disable pattern", width=130, height=28,
                      fg_color="#4a4a1a", hover_color="#6a6a2a",
                      font=ctk.CTkFont(size=11),
                      command=_disable).grid(row=0, column=2)

    def _mark_resolved(self, path: str, mode: str):
        """Mark a path as resolved (removes it from the default view)."""
        self._threat_resolved.add(path)
        self._threat_resolution[path] = mode

    def _resolve_dispute(self, path: str, side: str):
        """Trust K2 / Trust Guardian — adds path to resolved set + logs."""
        self._mark_resolved(path, side)
        dispute = self._dispute_for_path(path)
        if dispute:
            self._log_append(
                f"[DISPUTE] {side.replace('_', ' ').title()} for "
                f"'{Path(path).name}' (K2={dispute['k2_verdict']}, "
                f"Guardian={dispute['guardian_verdict']})",
                _TAG_GUARDIAN)
        self._status_cb(f"Resolved: {Path(path).name}")
        self._build_threat_actions()

    # ── Bulk action engine ───────────────────────────────────────────────────

    def _bulk_action(self, op: str):
        """Run a bulk op against self._threat_checked with progress UI."""
        paths = sorted(self._threat_checked)
        if not paths:
            return

        if op == "delete":
            n = len(paths)
            ok = messagebox.askyesno(
                "Confirm delete",
                f"Permanently delete {n} file{'s' if n != 1 else ''}?\n\n"
                f"They will be gone forever. This cannot be undone.")
            if not ok:
                return
        if op == "ignore":
            # Show note dialog first; ignore action runs from there
            self._open_ignore_dialog(paths)
            return

        # Replace footer with progress bar
        self._bulk_cancel_event = threading.Event()
        self._show_bulk_progress(op, len(paths))

        def _run():
            from ui.core import quarantine as quar
            done = 0
            ok_count = 0
            for p in paths:
                if self._bulk_cancel_event and self._bulk_cancel_event.is_set():
                    break
                try:
                    if op == "quarantine":
                        success, _msg = quar.move_to_quarantine(p)
                        if success:
                            ok_count += 1
                            if self.winfo_exists():
                                self.after(0, lambda pp=p:
                                           self._mark_resolved(pp, "quarantined"))
                    elif op == "delete":
                        os.remove(p)
                        ok_count += 1
                        if self.winfo_exists():
                            self.after(0, lambda pp=p:
                                       self._mark_resolved(pp, "deleted"))
                except Exception:
                    pass
                done += 1
                if self.winfo_exists():
                    self.after(0, lambda d=done, t=len(paths):
                               self._update_bulk_progress(d, t))
            if self.winfo_exists():
                self.after(0, lambda: self._on_bulk_done(op, ok_count, len(paths)))
        threading.Thread(target=_run, daemon=True).start()

    def _show_bulk_progress(self, op: str, total: int):
        """Replace bulk footer with progress bar + cancel button."""
        bf = self._threat_bulk_frame
        if bf is None:
            return
        for w in bf.winfo_children():
            w.destroy()

        title = {"quarantine": "Quarantining",
                 "delete":     "Deleting",
                 "ignore":     "Ignoring"}.get(op, op.title())

        self._bulk_progress_lbl = ctk.CTkLabel(
            bf, text=f"{title}  0 / {total}",
            font=ctk.CTkFont(size=11), text_color="#cdd6f4")
        self._bulk_progress_lbl.grid(row=0, column=0, sticky="w", padx=12, pady=6)

        self._bulk_progress_bar = ctk.CTkProgressBar(bf, width=240, height=14,
                                                     mode="determinate")
        self._bulk_progress_bar.grid(row=0, column=1, padx=(8, 8), pady=6)
        self._bulk_progress_bar.set(0)

        ctk.CTkButton(bf, text="Cancel", width=80, height=24,
                      fg_color="#3a3a3a", hover_color="#5a5a5a",
                      font=ctk.CTkFont(size=11),
                      command=self._cancel_bulk).grid(
            row=0, column=2, padx=(0, 12), pady=6)

    def _update_bulk_progress(self, done: int, total: int):
        try:
            self._bulk_progress_bar.set(done / total if total else 1.0)
            self._bulk_progress_lbl.configure(text=f"Processing  {done} / {total}")
        except Exception:
            pass

    def _cancel_bulk(self):
        if self._bulk_cancel_event:
            self._bulk_cancel_event.set()
        self._status_cb("Cancelling bulk operation…")

    def _on_bulk_done(self, op: str, ok: int, total: int):
        verb = {"quarantine": "Quarantined",
                "delete":     "Deleted",
                "ignore":     "Ignored"}.get(op, op.title())
        self._log_append(f"[BULK] {verb} {ok}/{total} file(s).",
                         _TAG_CLEAN if ok == total else _TAG_WARN)
        self._status_cb(f"{verb} {ok}/{total} file(s).")
        self._threat_checked.clear()
        self._bulk_cancel_event = None
        self._build_threat_actions()

    # ── Async hash + preview computation ─────────────────────────────────────

    def _compute_hashes_async(self, path: str,
                              md5_lbl: ctk.CTkLabel,
                              sha_lbl: ctk.CTkLabel):
        """Compute MD5/SHA-256 + content preview in a background thread."""
        def _run():
            entry: dict = {}
            try:
                with open(path, "rb") as f:
                    data = f.read()
                entry["size"]   = len(data)
                entry["md5"]    = hashlib.md5(data).hexdigest()
                entry["sha256"] = hashlib.sha256(data).hexdigest()
                # Content preview — text-safe, skip binary / huge
                if len(data) <= 50 * 1024 * 1024 and b"\x00" not in data[:512]:
                    sample = data[:200]
                    preview = "".join(
                        chr(b) if 32 <= b < 127 or b in (9, 10, 13) else "·"
                        for b in sample
                    )
                    entry["preview"] = preview or "(empty file)"
                else:
                    entry["preview"] = ""
            except Exception as exc:
                entry["md5"] = entry["sha256"] = f"error: {str(exc)[:40]}"
                entry["preview"] = ""
            if self.winfo_exists():
                self.after(0, lambda e=entry, p=path:
                           self._on_hashes_done(p, e, md5_lbl, sha_lbl))
        threading.Thread(target=_run, daemon=True).start()

    def _on_hashes_done(self, path: str, entry: dict,
                        md5_lbl: ctk.CTkLabel, sha_lbl: ctk.CTkLabel):
        self._hash_cache[path] = entry
        if self._threat_selected_path == path:
            try:
                md5_lbl.configure(text=entry.get("md5", ""))
                sha_lbl.configure(text=entry.get("sha256", ""))
            except Exception:
                pass
            # Re-render to show the preview if it's now available
            self._render_threat_detail()

    def _quarantine_all_threats(self, paths: list, btn) -> None:
        """
        Quarantine every detected threat in a background thread.
        ``btn`` is the "Quarantine All" CTkButton — it is disabled immediately
        and updated with a summary once the batch completes.
        """
        btn.configure(state="disabled", text="Quarantining…")

        def _run():
            from ui.core import quarantine as quar
            results = [(quar.move_to_quarantine(p)) for p in paths]
            if self.winfo_exists():
                self.after(0, lambda: self._on_quarantine_all_done(results, btn))

        threading.Thread(target=_run, daemon=True).start()

    def _on_quarantine_all_done(self, results: list, btn) -> None:
        ok_count = sum(1 for ok, _ in results if ok)
        total    = len(results)
        for ok, msg in results:
            self._log_append(f"[{'OK' if ok else 'ERR'}] {msg}",
                             _TAG_CLEAN if ok else _TAG_WARN)
        summary = f"Quarantine All: {ok_count}/{total} succeeded"
        if ok_count < total:
            summary += f"  ({total - ok_count} failed — see log)"
        self._status_cb(summary)
        try:
            btn.configure(
                text=f"✓ Done ({ok_count}/{total})",
                fg_color="#1a3a1a",
                hover_color="#1a3a1a",
            )
        except Exception:
            pass
