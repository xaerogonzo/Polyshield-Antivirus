import hashlib
import threading
import customtkinter as ctk
from tkinter import messagebox
from pathlib import Path

from ui.core import quarantine as qm
from ui.core import settings as cfg
import ui.theme as theme


class QuarantineView(ctk.CTkFrame):
    def __init__(self, master, status_callback, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self._status_cb = status_callback
        self._entries: list[dict] = []
        self._row_widgets: list[dict] = []
        self._check_vars: list[ctk.BooleanVar] = []
        self._vt_in_flight = False
        self._build()
        self.refresh()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # ── Header ──
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=24, pady=(20, 8))
        header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(header, text="Quarantine Manager",
                     font=ctk.CTkFont(size=22, weight="bold")).grid(
            row=0, column=0, sticky="w")

        # Bulk action buttons (right side of header)
        btn_row = ctk.CTkFrame(header, fg_color="transparent")
        btn_row.grid(row=0, column=1)

        self._select_all_btn = ctk.CTkButton(
            btn_row, text="Select All", width=90,
            fg_color="#2a2a4a", hover_color="#3a3a6a",
            font=ctk.CTkFont(size=12),
            command=self._toggle_select_all)
        self._select_all_btn.grid(row=0, column=0, padx=(0, 6))

        self._restore_sel_btn = ctk.CTkButton(
            btn_row, text="Restore Selected", width=130,
            fg_color="#1f4a7a", hover_color=theme.color("accent_hover"),
            font=ctk.CTkFont(size=12),
            state="disabled",
            command=self._restore_selected)
        self._restore_sel_btn.grid(row=0, column=1, padx=(0, 6))

        self._delete_sel_btn = ctk.CTkButton(
            btn_row, text="Delete Selected", width=120,
            fg_color="#6a1a1a", hover_color="#5c0000",
            font=ctk.CTkFont(size=12),
            state="disabled",
            command=self._delete_selected)
        self._delete_sel_btn.grid(row=0, column=2, padx=(0, 6))

        ctk.CTkButton(btn_row, text="Refresh", width=90,
                      fg_color=theme.color("divider"), hover_color="#4a4a4a",
                      font=ctk.CTkFont(size=12),
                      command=self.refresh).grid(row=0, column=3)

        # ── Column headers ──
        # Columns: CB(0) | Threat(1) | Original Path(2) | Date(3) | Actions(4)
        col_frame = ctk.CTkFrame(self, fg_color=theme.color("divider"), height=32, corner_radius=0)
        col_frame.grid(row=1, column=0, sticky="ew", padx=24)
        col_frame.grid_propagate(False)
        col_frame.grid_columnconfigure(0, minsize=36)
        col_frame.grid_columnconfigure(1, weight=1)
        col_frame.grid_columnconfigure(2, weight=5)
        col_frame.grid_columnconfigure(3, weight=1)
        col_frame.grid_columnconfigure(4, minsize=220)

        ctk.CTkLabel(col_frame, text="", width=36).grid(row=0, column=0)
        for col, txt in enumerate(["Threat", "Original Path", "Date"], start=1):
            ctk.CTkLabel(col_frame, text=txt, font=ctk.CTkFont(size=12, weight="bold"),
                         text_color=theme.color("subtext")).grid(row=0, column=col, sticky="w", padx=12)
        ctk.CTkLabel(col_frame, text="Actions", font=ctk.CTkFont(size=12, weight="bold"),
                     text_color=theme.color("subtext")).grid(row=0, column=4, sticky="w", padx=12)

        # ── Scrollable list ──
        self._scroll = ctk.CTkScrollableFrame(self, fg_color=theme.color("card"), corner_radius=8)
        self._scroll.grid(row=2, column=0, sticky="nsew", padx=24, pady=(0, 16))
        self._scroll.grid_columnconfigure(0, minsize=36)
        self._scroll.grid_columnconfigure(1, weight=1)
        self._scroll.grid_columnconfigure(2, weight=5)
        self._scroll.grid_columnconfigure(3, weight=1)
        self._scroll.grid_columnconfigure(4, minsize=220)

        self._empty_label = ctk.CTkLabel(
            self._scroll, text="Quarantine is empty",
            text_color=theme.color("dim"), font=ctk.CTkFont(size=14))

    # ── Selection helpers ──────────────────────────────────────────────────────

    def _on_check_change(self):
        any_checked = any(v.get() for v in self._check_vars)
        all_checked = bool(self._check_vars) and all(v.get() for v in self._check_vars)
        state = "normal" if any_checked else "disabled"
        self._restore_sel_btn.configure(state=state)
        self._delete_sel_btn.configure(state=state)
        self._select_all_btn.configure(
            text="Deselect All" if all_checked else "Select All")

    def _toggle_select_all(self):
        all_checked = all(v.get() for v in self._check_vars)
        for var in self._check_vars:
            var.set(not all_checked)
        self._on_check_change()

    def _selected_entries(self) -> list[dict]:
        return [e for e, v in zip(self._entries, self._check_vars) if v.get()]

    # ── Bulk actions ───────────────────────────────────────────────────────────

    def _restore_selected(self):
        sel = self._selected_entries()
        if not sel:
            return
        names = "\n".join(f"  • {e['filename']}" for e in sel[:10])
        if len(sel) > 10:
            names += f"\n  … and {len(sel) - 10} more"
        if not messagebox.askyesno(
                "Restore Selected",
                f"Restore {len(sel)} file(s) to their original locations?\n\n{names}"):
            return
        failed = []
        for entry in sel:
            ok = qm.restore(entry)
            if not ok:
                failed.append(entry["filename"])
        if failed:
            messagebox.showwarning(
                "Partial Restore",
                f"{len(sel) - len(failed)} file(s) restored.\n"
                f"Failed ({len(failed)}):\n" + "\n".join(f"  • {f}" for f in failed))
        else:
            self._status_cb(f"Restored {len(sel)} file(s)")
        self.refresh()

    def _delete_selected(self):
        sel = self._selected_entries()
        if not sel:
            return
        names = "\n".join(f"  • {e['filename']}" for e in sel[:10])
        if len(sel) > 10:
            names += f"\n  … and {len(sel) - 10} more"
        if not messagebox.askyesno(
                "Delete Selected",
                f"Permanently delete {len(sel)} file(s)? This cannot be undone.\n\n{names}"):
            return
        for entry in sel:
            qm.delete(entry)
        self._status_cb(f"Deleted {len(sel)} file(s)")
        self.refresh()

    # ── Refresh / row building ─────────────────────────────────────────────────

    def refresh(self):
        for w in self._row_widgets:
            for widget in w.values():
                if hasattr(widget, "destroy"):
                    widget.destroy()
        self._row_widgets.clear()
        self._check_vars.clear()

        self._entries = qm.list_quarantined()

        if not self._entries:
            self._empty_label.grid(row=0, column=0, columnspan=5, pady=40)
            self._restore_sel_btn.configure(state="disabled")
            self._delete_sel_btn.configure(state="disabled")
            self._select_all_btn.configure(text="Select All")
            return

        self._empty_label.grid_remove()
        for i, entry in enumerate(self._entries):
            bg = "#1e1e2e" if i % 2 == 0 else "#232340"
            var = ctk.BooleanVar(value=False)
            self._check_vars.append(var)
            row_widgets = self._build_row(i, entry, bg, var)
            self._row_widgets.append(row_widgets)

        self._status_cb(f"{len(self._entries)} file(s) in quarantine")

    def _build_row(self, row: int, entry: dict, bg: str, var: ctk.BooleanVar) -> dict:
        def _cell(col, text, color="#cdd6f4", wrap=0):
            lbl = ctk.CTkLabel(self._scroll, text=text, anchor="w",
                               fg_color=bg, text_color=color,
                               font=ctk.CTkFont(size=12),
                               wraplength=wrap)
            lbl.grid(row=row, column=col, sticky="ew", padx=12, pady=4)
            return lbl

        cb = ctk.CTkCheckBox(self._scroll, text="", variable=var, width=20,
                             fg_color=bg, hover_color="#3a3a5a",
                             command=self._on_check_change)
        cb.grid(row=row, column=0, padx=(10, 4), pady=4)

        orig_path = entry["original_path"]
        widgets = {
            "cb":     cb,
            "threat": _cell(1, entry["threat_name"], "#ff5555"),
            "orig":   _cell(2, orig_path, wrap=480),
            "date":   _cell(3, entry["date"]),
        }

        btn_frame = ctk.CTkFrame(self._scroll, fg_color=bg)
        btn_frame.grid(row=row, column=4, sticky="ew", padx=8, pady=2)

        ctk.CTkButton(
            btn_frame, text="Restore", width=72, height=26,
            fg_color=theme.color("accent"), hover_color=theme.color("accent_hover"),
            font=ctk.CTkFont(size=11),
            command=lambda e=entry: self._restore(e),
        ).grid(row=0, column=0, padx=(4, 2))

        ctk.CTkButton(
            btn_frame, text="Delete", width=62, height=26,
            fg_color="#8b0000", hover_color="#5c0000",
            font=ctk.CTkFont(size=11),
            command=lambda e=entry: self._delete(e),
        ).grid(row=0, column=1, padx=(0, 2))

        vt_verdict_lbl = ctk.CTkLabel(
            btn_frame, text="", font=ctk.CTkFont(size=10),
            text_color=theme.color("subtext"), width=90, anchor="w")
        vt_verdict_lbl.grid(row=0, column=3, padx=(2, 4))

        api_key = cfg.get("vt_api_key") or ""
        vt_btn = ctk.CTkButton(
            btn_frame, text="VT", width=38, height=26,
            fg_color="#1a2a4a", hover_color="#1f3a6a",
            font=ctk.CTkFont(size=11),
            state="normal" if api_key else "disabled",
            command=lambda e=entry, lbl=vt_verdict_lbl: self._vt_check(e, lbl),
        )
        vt_btn.grid(row=0, column=2, padx=(0, 2))

        widgets["btn_frame"] = btn_frame
        widgets["vt_btn"] = vt_btn
        widgets["vt_verdict"] = vt_verdict_lbl
        return widgets

    # ── Per-row VT check ──────────────────────────────────────────────────────

    def _vt_check(self, entry: dict, verdict_lbl: ctk.CTkLabel):
        if self._vt_in_flight:
            return
        api_key = cfg.get("vt_api_key") or ""
        if not api_key:
            return

        q_path = entry.get("path")
        if not q_path or not Path(q_path).exists():
            verdict_lbl.configure(text="File not found", text_color=theme.color("subtext"))
            return
        q_path = str(q_path)

        self._vt_in_flight = True
        verdict_lbl.configure(text="hashing…", text_color=theme.color("subtext"))
        self._status_cb("Computing hash for VirusTotal…")

        def _run():
            try:
                with open(q_path, "rb") as f:
                    sha256 = hashlib.sha256(f.read()).hexdigest()
            except Exception:
                if self.winfo_exists():
                    self.after(0, lambda: verdict_lbl.configure(
                        text="hash error", text_color=theme.color("subtext")))
                self._vt_in_flight = False
                return

            if self.winfo_exists():
                self.after(0, lambda: verdict_lbl.configure(
                    text="checking VT…", text_color=theme.color("subtext")))

            import urllib.request, urllib.error, json as _json
            url = f"https://www.virustotal.com/api/v3/files/{sha256}"
            req = urllib.request.Request(url, headers={"x-apikey": api_key})
            try:
                with urllib.request.urlopen(req, timeout=15) as resp:
                    raw = _json.loads(resp.read().decode("utf-8"))
                attrs = raw.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                mal = stats.get("malicious", 0)
                total_eng = sum(stats.values()) if stats else 0
                text  = (f"{mal}/{total_eng} ⚠" if mal else f"0/{total_eng} ✓")
                color = "#ff5555" if mal else "#50fa7b"
            except urllib.error.HTTPError as exc:
                text  = ("Not in VT DB" if exc.code == 404
                         else "Rate limited" if exc.code == 429
                         else f"HTTP {exc.code}")
                color = "#888888" if exc.code != 429 else "#ffb86c"
            except Exception as exc:
                text, color = str(exc)[:20], "#888888"

            self._vt_in_flight = False
            if self.winfo_exists():
                self.after(0, lambda t=text, c=color: verdict_lbl.configure(
                    text=t, text_color=c))
                self.after(0, lambda t=text: self._status_cb(f"VT check done: {t}"))

        threading.Thread(target=_run, daemon=True).start()

    # ── Per-row single actions ────────────────────────────────────────────────

    def _restore(self, entry: dict):
        if messagebox.askyesno("Restore File",
                               f"Restore '{entry['filename']}' to its original location?"):
            ok = qm.restore(entry)
            if ok:
                messagebox.showinfo("Restored", "File restored successfully.")
            else:
                messagebox.showerror(
                    "Error",
                    "Could not restore file.\n"
                    "A file may already exist at the original path — PolyShield "
                    "will not overwrite it. The original path may also be "
                    "unknown or inaccessible.")
            self.refresh()

    def _delete(self, entry: dict):
        if messagebox.askyesno("Delete File",
                               f"Permanently delete '{entry['filename']}'?\n"
                               "This cannot be undone."):
            qm.delete(entry)
            self.refresh()
