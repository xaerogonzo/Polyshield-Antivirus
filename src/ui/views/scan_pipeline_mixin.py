"""The Scan Pipeline panel: engine order, drag-and-drop, presets, toggles.

A partition of ScanView, not an independent component.  Its methods call back
into ScanView (`_refresh_drop_label`) and read state that `ScanView.__init__`
and `ScanView._build` own -- `_engine_queue`, `_pipeline_rows`, `_drag_*`, the
six `_use_*` flags.  It is split out because scan_view.py was 1,976 lines, not
because this is separable.

Combine it into a class that also inherits `ctk.CTkFrame`; see ScanView.
No method here calls `super()`, and no name here exists on ScanView,
`_ThreatActionsMixin` or `_ScanEngineMixin` -- a collision would resolve
silently by MRO order.
"""
import customtkinter as ctk
from pathlib import Path

import ui.theme as theme
from ui.core import scanner as sc
from ui.core import settings as cfg
from ui.core import guardian_engine as ge
from ui.core import yara_engine as ye
from ui.core import clamav_engine as ce
from ui.core import defender as df

try:
    from ui.core import emulate_engine as ee
    _SPEAKEASY_AVAIL = True
except ImportError:
    ee = None
    _SPEAKEASY_AVAIL = False


class _ScanPipelineMixin:
    """Pipeline panel construction, reordering and per-engine toggles."""

    def _build_pipeline_panel(self):
        """Build the collapsible Scan Pipeline panel (row 4)."""
        # Gather availability once
        k2_ok        = sc.is_available()
        guardian_ok  = ge.is_available()
        yara_ok      = ye.is_available()
        clamav_ok    = ce.is_available()
        defender_ok  = df.is_mpcmdrun_available()
        try:
            speakeasy_ok = _SPEAKEASY_AVAIL and ee is not None and ee.is_available()
        except Exception:
            speakeasy_ok = False

        # BooleanVars
        self._k2_var        = ctk.BooleanVar(
            value=cfg.get("pipeline_k2") if k2_ok else False)
        self._guardian_var  = ctk.BooleanVar(
            value=cfg.get("guardian_dual_scan") if guardian_ok else False)
        self._yara_var      = ctk.BooleanVar(
            value=cfg.get("yara_scan") if yara_ok else False)
        self._clamav_var    = ctk.BooleanVar(
            value=cfg.get("clamav_scan") if clamav_ok else False)
        self._defender_var  = ctk.BooleanVar(
            value=cfg.get("pipeline_defender") if defender_ok else False)
        self._speakeasy_var = ctk.BooleanVar(
            value=cfg.get("pipeline_speakeasy") if speakeasy_ok else False)

        # Outer container
        self._pipeline_outer = ctk.CTkFrame(self, fg_color="transparent")
        self._pipeline_outer.grid(row=4, column=0, sticky="ew", padx=24, pady=(0, 4))
        self._pipeline_outer.grid_columnconfigure(0, weight=1)

        # Toggle header button (built after vars so step count is accurate)
        self._pipeline_toggle_btn = ctk.CTkButton(
            self._pipeline_outer,
            text=self._pipeline_header_text(),
            anchor="w",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._toggle_pipeline_panel,
        )
        self._pipeline_toggle_btn.grid(row=0, column=0, sticky="ew", pady=(0, 2))
        theme.register(self._themed, self._pipeline_toggle_btn,
                       fg_color="card2", hover_color="divider")

        # Inner collapsible panel
        self._pipeline_inner = ctk.CTkFrame(
            self._pipeline_outer, corner_radius=8, border_width=1)
        self._pipeline_inner.grid(row=1, column=0, sticky="ew")
        self._pipeline_inner.grid_columnconfigure(0, weight=1)
        theme.register(self._themed, self._pipeline_inner,
                       fg_color="card", border_color="divider")

        yara_cnt = ye.get_rule_count() if yara_ok else 0
        clam_ver = ce.get_version() if clamav_ok else ""

        # Cache availability for use in _build_secondary_rows (called on reorder too)
        self._k2_ok       = k2_ok
        self._guardian_ok = guardian_ok
        self._yara_ok     = yara_ok
        self._clamav_ok   = clamav_ok
        self._defender_ok = defender_ok
        self._yara_cnt    = yara_cnt
        self._clam_ver    = clam_ver

        def _row(parent, row_idx, var, label, badge, badge_color, state, cmd):
            bg = theme.color("card2") if row_idx % 2 == 0 else theme.color("card")
            rf = ctk.CTkFrame(parent, fg_color=bg, corner_radius=4)
            rf.grid(row=row_idx, column=0, sticky="ew", pady=1, padx=4)
            rf.grid_columnconfigure(1, weight=1)
            ctk.CTkCheckBox(
                rf, text=label, variable=var,
                font=ctk.CTkFont(size=12), state=state,
                text_color=theme.color("text") if state == "normal" else theme.color("dim"),
                command=cmd, width=180,
            ).grid(row=0, column=0, padx=(12, 8), pady=6, sticky="w")
            ctk.CTkLabel(
                rf, text=badge, font=ctk.CTkFont(size=11),
                text_color=badge_color, anchor="w",
            ).grid(row=0, column=1, sticky="w")

        # ── Row 0: header note ────────────────────────────────────────────────
        _pipe_note = ctk.CTkLabel(
            self._pipeline_inner,
            text="  Engines run in listed order — drag with ↑/↓",
            font=ctk.CTkFont(size=10), anchor="w")
        _pipe_note.grid(row=0, column=0, sticky="ew", padx=8, pady=(4, 0))
        theme.register(self._themed, _pipe_note, text_color="subtext")

        # ── Row 1: reorderable engine rows (K2, Defender, Guardian, YARA, ClamAV)
        self._secondary_rows_frame = ctk.CTkFrame(
            self._pipeline_inner, fg_color="transparent")
        self._secondary_rows_frame.grid(row=1, column=0, sticky="ew")
        self._secondary_rows_frame.grid_columnconfigure(0, weight=1)
        self._build_secondary_rows(self._secondary_rows_frame)

        # ── Row 2: Reset order button ─────────────────────────────────────────
        _reset_bar = ctk.CTkFrame(self._pipeline_inner, fg_color="transparent")
        _reset_bar.grid(row=2, column=0, sticky="ew", padx=4, pady=(0, 2))
        _reset_bar.grid_columnconfigure(0, weight=1)
        _reset_btn = ctk.CTkButton(
            _reset_bar, text="↺  Reset order", width=110, height=22,
            font=ctk.CTkFont(size=10),
            command=self._reset_pipeline_order)
        _reset_btn.grid(row=0, column=0, sticky="e", padx=4)
        theme.register(self._themed, _reset_btn,
                       fg_color="input_bg", hover_color="input_hover")

        # ── Row 3: Speakeasy (always last — not reorderable) ──────────────────
        spk_badge = ("● always last — emulates flagged PEs"
                     if speakeasy_ok else "○ always last — not installed")
        _row(self._pipeline_inner, 3,
             self._speakeasy_var, "Speakeasy",
             spk_badge, "#50fa7b" if speakeasy_ok else "#888888",
             "normal" if speakeasy_ok else "disabled",
             self._on_speakeasy_toggle)

        # ── Rows 4–5: manual-only entries ─────────────────────────────────────
        r = 4
        for manual_label, manual_note in [
            ("Sandboxie",   "— manual via Threat Actions"),
            ("VirusTotal",  "— manual via Threat Actions"),
        ]:
            bg = theme.color("card2") if r % 2 == 0 else theme.color("card")
            rf = ctk.CTkFrame(self._pipeline_inner, fg_color=bg, corner_radius=4)
            rf.grid(row=r, column=0, sticky="ew", pady=1, padx=4)
            rf.grid_columnconfigure(1, weight=1)
            ctk.CTkLabel(rf, text=f"  {manual_label}",
                         font=ctk.CTkFont(size=12), text_color=theme.color("dim"),
                         width=196, anchor="w").grid(
                row=0, column=0, padx=(12, 8), pady=6, sticky="w")
            ctk.CTkLabel(rf, text=manual_note,
                         font=ctk.CTkFont(size=11), text_color=theme.color("dim"),
                         anchor="w").grid(row=0, column=1, sticky="w")
            r += 1

    def _pipeline_header_text(self) -> str:
        enabled = sum([
            bool(self._k2_var.get()),
            bool(self._guardian_var.get()),
            bool(self._yara_var.get()),
            bool(self._clamav_var.get()),
            bool(self._defender_var.get()),
            bool(self._speakeasy_var.get()),
        ])
        arrow = "▼" if self._pipeline_expanded else "►"
        return f"{arrow} Scan Pipeline  ({enabled} step{'s' if enabled != 1 else ''} enabled)"

    def _toggle_pipeline_panel(self):
        self._pipeline_expanded = not self._pipeline_expanded
        if self._pipeline_expanded:
            self._pipeline_inner.grid()
        else:
            self._pipeline_inner.grid_remove()
        self._pipeline_toggle_btn.configure(text=self._pipeline_header_text())

    def _update_pipeline_header(self):
        if hasattr(self, "_pipeline_toggle_btn"):
            self._pipeline_toggle_btn.configure(text=self._pipeline_header_text())

    _DEFAULT_PIPELINE_ORDER = ["k2", "defender", "guardian", "yara", "clamav"]

    def _normalized_pipeline_order(self) -> list[str]:
        """
        Return the saved pipeline_order with any newly-introduced engines
        appended at their default position (handles users upgrading from
        v1.6.0 settings that lacked 'k2').
        """
        saved = list(cfg.get("pipeline_order") or [])
        for i, eid in enumerate(self._DEFAULT_PIPELINE_ORDER):
            if eid not in saved:
                # Insert at default position (or end if position is out of range)
                saved.insert(min(i, len(saved)), eid)
        return saved

    def _build_secondary_rows(self, parent: ctk.CTkFrame) -> None:
        """
        Populate *parent* with engine rows in user-configured pipeline_order.
        Each row: drag-handle + checkbox + ↑/↓ move buttons + availability badge.
        K2 is a peer engine here (v1.6.1+) — reorderable like the rest.
        Called at build-time and again on every reorder.
        """
        self._drag_row_registry = {}   # reset for fresh build
        order = self._normalized_pipeline_order()
        meta = {
            "k2": (
                self._k2_var, "K2 Engine",
                "● ready" if self._k2_ok else "○ k2.exe not found",
                "#50fa7b" if self._k2_ok else "#888888",
                "normal" if self._k2_ok else "disabled",
                self._on_k2_toggle,
            ),
            "defender": (
                self._defender_var, "Defender",
                "● available" if self._defender_ok else "○ MpCmdRun.exe not found",
                "#50fa7b" if self._defender_ok else "#888888",
                "normal" if self._defender_ok else "disabled",
                self._on_defender_toggle,
            ),
            "guardian": (
                self._guardian_var, "Guardian AI",
                "● ready" if self._guardian_ok else "○ not installed",
                "#50fa7b" if self._guardian_ok else "#888888",
                "normal" if self._guardian_ok else "disabled",
                self._on_guardian_toggle,
            ),
            "yara": (
                self._yara_var, "YARA Rules",
                (f"● {self._yara_cnt} rule file{'s' if self._yara_cnt != 1 else ''}"
                 if self._yara_ok else "○ add .yar files to rules/user_rules/ to enable"),
                "#50fa7b" if self._yara_ok else "#888888",
                "normal" if self._yara_ok else "disabled",
                self._on_yara_toggle,
            ),
            "clamav": (
                self._clamav_var, "ClamAV",
                (f"● {self._clam_ver}" if self._clamav_ok
                 else "○ install from clamav.net — configure path in Settings"),
                "#50fa7b" if self._clamav_ok else "#888888",
                "normal" if self._clamav_ok else "disabled",
                self._on_clamav_toggle,
            ),
        }
        n = len(order)
        for i, engine_id in enumerate(order):
            if engine_id not in meta:
                continue
            var, label, badge, badge_color, state, cmd = meta[engine_id]
            bg = theme.color("card2") if i % 2 == 0 else theme.color("card")
            rf = ctk.CTkFrame(parent, fg_color=bg, corner_radius=4)
            rf.grid(row=i, column=0, sticky="ew", pady=1, padx=4)
            # col 0: drag handle | col 1: checkbox | col 2: ↑ | col 3: ↓ | col 4: badge
            rf.grid_columnconfigure(4, weight=1)
            self._drag_row_registry[engine_id] = rf

            # ── Drag handle ──────────────────────────────────────────────────
            handle = ctk.CTkLabel(
                rf, text="⠿", width=18,
                font=ctk.CTkFont(size=14), text_color=theme.color("dim"),
                cursor="fleur",
            )
            handle.grid(row=0, column=0, padx=(6, 0), pady=6)
            handle.bind("<ButtonPress-1>",
                        lambda e, eid=engine_id: self._on_drag_start(eid, e))
            handle.bind("<B1-Motion>",   self._on_drag_motion)
            handle.bind("<ButtonRelease-1>", self._on_drag_end)

            # ── Checkbox ─────────────────────────────────────────────────────
            ctk.CTkCheckBox(
                rf, text=f"{i + 1}. {label}", variable=var,
                font=ctk.CTkFont(size=12), state=state,
                text_color=theme.color("text") if state == "normal" else theme.color("dim"),
                command=cmd, width=200,
            ).grid(row=0, column=1, padx=(4, 4), pady=6, sticky="w")

            # ── ↑/↓ buttons ──────────────────────────────────────────────────
            ctk.CTkButton(
                rf, text="↑", width=22, height=20,
                font=ctk.CTkFont(size=10),
                fg_color=theme.color("input_bg"), hover_color=theme.color("input_hover"),
                state="normal" if i > 0 else "disabled",
                command=lambda eid=engine_id: self._move_engine(eid, -1),
            ).grid(row=0, column=2, padx=(0, 2), pady=6)

            ctk.CTkButton(
                rf, text="↓", width=22, height=20,
                font=ctk.CTkFont(size=10),
                fg_color=theme.color("input_bg"), hover_color=theme.color("input_hover"),
                state="normal" if i < n - 1 else "disabled",
                command=lambda eid=engine_id: self._move_engine(eid, 1),
            ).grid(row=0, column=3, padx=(0, 8), pady=6)

            # ── Badge ─────────────────────────────────────────────────────────
            ctk.CTkLabel(
                rf, text=badge, font=ctk.CTkFont(size=11),
                text_color=badge_color, anchor="w",
            ).grid(row=0, column=4, sticky="w")

    def _rebuild_secondary_rows(self) -> None:
        """Destroy and recreate engine rows in the current pipeline_order."""
        if self._secondary_rows_frame and self._secondary_rows_frame.winfo_exists():
            self._secondary_rows_frame.destroy()
        self._secondary_rows_frame = ctk.CTkFrame(
            self._pipeline_inner, fg_color="transparent")
        self._secondary_rows_frame.grid(row=1, column=0, sticky="ew")
        self._secondary_rows_frame.grid_columnconfigure(0, weight=1)
        self._build_secondary_rows(self._secondary_rows_frame)
        self._pipeline_toggle_btn.configure(text=self._pipeline_header_text())

    def _move_engine(self, engine_id: str, direction: int) -> None:
        """Move *engine_id* up (-1) or down (+1) in pipeline_order, then rebuild rows."""
        order = self._normalized_pipeline_order()
        if engine_id not in order:
            return
        idx = order.index(engine_id)
        new_idx = idx + direction
        if new_idx < 0 or new_idx >= len(order):
            return
        order[idx], order[new_idx] = order[new_idx], order[idx]
        cfg.set_value("pipeline_order", order)
        self._rebuild_secondary_rows()

    def _reset_pipeline_order(self) -> None:
        """Restore the default engine order: K2 → Defender → Guardian → YARA → ClamAV."""
        cfg.set_value("pipeline_order", list(self._DEFAULT_PIPELINE_ORDER))
        self._rebuild_secondary_rows()

    # ── Pipeline D&D ──────────────────────────────────────────────────────────

    def _on_drag_start(self, engine_id: str, event) -> None:
        """Begin dragging an engine row."""
        self._drag_engine_id    = engine_id
        self._drag_hover_engine = None
        rf = self._drag_row_registry.get(engine_id)
        if rf and rf.winfo_exists():
            rf.configure(border_width=2, border_color=theme.color("accent"))

    def _on_drag_motion(self, event) -> None:
        """Update drop-target highlight as the mouse moves."""
        if not self._drag_engine_id:
            return
        target = self._get_engine_at_y(event.y_root)
        if target == self._drag_hover_engine:
            return
        # Clear old hover highlight
        if self._drag_hover_engine and self._drag_hover_engine != self._drag_engine_id:
            old = self._drag_row_registry.get(self._drag_hover_engine)
            if old and old.winfo_exists():
                old.configure(border_width=0)
        self._drag_hover_engine = target
        # Set new hover highlight (amber, different from dragged-row blue)
        if target and target != self._drag_engine_id:
            rf = self._drag_row_registry.get(target)
            if rf and rf.winfo_exists():
                rf.configure(border_width=1, border_color="#888844")

    def _on_drag_end(self, event) -> None:
        """Snap the dragged engine to the row under the cursor."""
        src = self._drag_engine_id
        if not src:
            return
        target = self._get_engine_at_y(event.y_root)
        # Clear all visual highlights before rebuilding
        self._drag_engine_id    = None
        self._drag_hover_engine = None
        if target and target != src:
            order = self._normalized_pipeline_order()
            if src in order and target in order:
                src_idx = order.index(src)
                tgt_idx = order.index(target)
                order.pop(src_idx)
                order.insert(tgt_idx, src)
                cfg.set_value("pipeline_order", order)
                self._rebuild_secondary_rows()
                return
        # No move — just remove the blue outline on the dragged row
        rf = self._drag_row_registry.get(src)
        if rf and rf.winfo_exists():
            rf.configure(border_width=0)

    def _get_engine_at_y(self, y_root: int) -> str | None:
        """Return the engine_id whose row midpoint is closest to y_root (screen coords)."""
        best_id   = None
        best_dist = float("inf")
        for eid, rf in self._drag_row_registry.items():
            try:
                if not rf.winfo_exists():
                    continue
                mid = rf.winfo_rooty() + rf.winfo_height() // 2
                dist = abs(y_root - mid)
                if dist < best_dist:
                    best_dist = dist
                    best_id   = eid
            except Exception:
                pass
        return best_id

    # ── User-defined scan path presets ────────────────────────────────────────

    def _get_user_preset_names(self) -> list[str]:
        return [p["name"] for p in (cfg.get("scan_path_presets") or [])]

    def _refresh_preset_menu(self) -> None:
        """Rebuild the user preset OptionMenu from settings."""
        if not self._user_preset_menu:
            return
        names = self._get_user_preset_names()
        if names:
            self._user_preset_menu.configure(
                values=names, state="normal")
        else:
            self._user_preset_menu.configure(
                values=["— no presets saved —"], state="disabled")
            if self._user_preset_var:
                self._user_preset_var.set("— no presets saved —")

    def _on_user_preset_select(self, name: str) -> None:
        """Load the chosen user preset into the drop zone."""
        if name.startswith("—"):
            return
        presets_list = cfg.get("scan_path_presets") or []
        for p in presets_list:
            if p["name"] == name:
                # Switch segmented button to Custom without clearing paths
                self._loading_user_preset = True
                self._preset_btn.set("Custom")
                self._loading_user_preset = False
                self._preset = "Custom"
                self._paths  = [pp for pp in p["paths"] if Path(pp).exists()]
                self._refresh_drop_label()
                self._browse_file_btn.grid()
                self._browse_folder_btn.grid()
                self._startup_btn.grid()
                if self._user_preset_del_btn:
                    self._user_preset_del_btn.configure(state="normal")
                skipped = len(p["paths"]) - len(self._paths)
                msg = f"Loaded preset '{name}' — {len(self._paths)} path(s)"
                if skipped:
                    msg += f" ({skipped} missing, skipped)"
                self._status_cb(msg)
                return

    def _save_as_user_preset(self) -> None:
        """Prompt for a name and save the current Custom paths as a preset."""
        if not self._paths:
            self._status_cb("No paths to save — add files/folders first")
            return
        dialog = ctk.CTkInputDialog(text="Enter a name for this preset:",
                                    title="Save Scan Preset")
        name = dialog.get_input()
        if not name:
            return
        name = name.strip()[:40]
        if not name:
            return
        presets_list = list(cfg.get("scan_path_presets") or [])
        # Update existing preset with same name
        for p in presets_list:
            if p["name"] == name:
                p["paths"] = list(self._paths)
                cfg.set_value("scan_path_presets", presets_list)
                self._refresh_preset_menu()
                if self._user_preset_var:
                    self._user_preset_var.set(name)
                if self._user_preset_del_btn:
                    self._user_preset_del_btn.configure(state="normal")
                self._status_cb(f"Updated preset '{name}'")
                return
        # Enforce max 20 presets
        if len(presets_list) >= 20:
            self._status_cb("Maximum 20 presets reached — delete one first")
            return
        presets_list.append({"name": name, "paths": list(self._paths)})
        cfg.set_value("scan_path_presets", presets_list)
        self._refresh_preset_menu()
        if self._user_preset_var:
            self._user_preset_var.set(name)
        if self._user_preset_del_btn:
            self._user_preset_del_btn.configure(state="normal")
        self._status_cb(f"Saved preset '{name}' — {len(self._paths)} path(s)")

    def _delete_user_preset(self) -> None:
        """Delete the currently selected user preset."""
        if not self._user_preset_var:
            return
        name = self._user_preset_var.get()
        if name.startswith("—"):
            return
        presets_list = [p for p in (cfg.get("scan_path_presets") or [])
                        if p["name"] != name]
        cfg.set_value("scan_path_presets", presets_list)
        self._refresh_preset_menu()
        if self._user_preset_del_btn:
            self._user_preset_del_btn.configure(state="disabled")
        self._status_cb(f"Deleted preset '{name}'")

    # ── Pipeline toggle callbacks ──────────────────────────────────────────────

    def _on_k2_toggle(self):
        cfg.set_value("pipeline_k2", bool(self._k2_var.get()))
        self._update_pipeline_header()

    def _on_guardian_toggle(self):
        cfg.set_value("guardian_dual_scan", bool(self._guardian_var.get()))
        self._update_pipeline_header()

    def _on_yara_toggle(self):
        cfg.set_value("yara_scan", bool(self._yara_var.get()))
        self._update_pipeline_header()

    def _on_clamav_toggle(self):
        cfg.set_value("clamav_scan", bool(self._clamav_var.get()))
        self._update_pipeline_header()

    def _on_defender_toggle(self):
        cfg.set_value("pipeline_defender", bool(self._defender_var.get()))
        self._update_pipeline_header()

    def _on_speakeasy_toggle(self):
        cfg.set_value("pipeline_speakeasy", bool(self._speakeasy_var.get()))
        self._update_pipeline_header()
