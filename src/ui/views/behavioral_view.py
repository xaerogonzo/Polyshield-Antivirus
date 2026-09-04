"""
behavioral_view.py
──────────────────
"Behavioral Analysis" sidebar panel — the Hunter Workflow.

Stage 4: Behavioral Trace — Speakeasy observes what the file would do without executing it
Stage 5: Sandbox Test     — Sandboxie runs the file in an isolated box your OS can't see

Both stages are optional and independently available.  The view degrades
gracefully when either tool is not installed/configured.

Integration: scan_view.py can call load_file(path) on this view before
navigating to it, so the file input is pre-populated from DisputePopup.
"""
from __future__ import annotations

import json
import tkinter.filedialog as fd
from pathlib import Path

import customtkinter as ctk

from ui.core import emulate_engine as ee
from ui.core import sandbox_engine as se
import ui.theme as theme

# ── Text-box color tags ───────────────────────────────────────────────────────
_TAG_THREAT  = "threat"   # red
_TAG_WARN    = "warn"     # amber
_TAG_INFO    = "info"     # blue-grey
_TAG_CLEAN   = "clean"    # green
_TAG_DIM     = "dim"      # muted grey


class BehavioralView(ctk.CTkFrame):
    def __init__(self, master, status_callback, navigate_callback=None, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self._status_cb = status_callback
        self._nav_cb    = navigate_callback
        self._busy      = False          # blocks concurrent emulation runs
        self._detonating = False
        self._pending_file: str | None = None   # set by load_file() before on_show()
        self._build()

    # ── Public API ────────────────────────────────────────────────────────────

    def load_file(self, path: str) -> None:
        """Pre-populate the file input (called from DisputePopup / ScanView)."""
        self._pending_file = path

    def on_show(self) -> None:
        """Called every time the user navigates to this panel."""
        self._refresh_badges()
        if self._pending_file:
            self._set_path(self._pending_file)
            self._pending_file = None

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)   # log area expands

        # ── Header ──
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=24, pady=(20, 8))
        hdr.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(hdr, text="Behavioral Analysis — Trace & Sandbox",
                     font=ctk.CTkFont(size=22, weight="bold")).grid(
            row=0, column=0, sticky="w")
        ctk.CTkLabel(hdr,
                     text="Stage 4: Speakeasy traces API calls without executing the file  ·  "
                          "Stage 5: Sandboxie runs the file in an isolated box",
                     font=ctk.CTkFont(size=11), text_color=theme.color("subtext"), anchor="w").grid(
            row=1, column=0, columnspan=2, sticky="w", pady=(2, 0))

        badge_frame = ctk.CTkFrame(hdr, fg_color="transparent")
        badge_frame.grid(row=0, column=1, padx=(12, 0))

        self._sp_badge = ctk.CTkLabel(badge_frame, text="",
                                      font=ctk.CTkFont(size=11))
        self._sp_badge.grid(row=0, column=0, padx=(0, 12))

        self._sb_badge = ctk.CTkLabel(badge_frame, text="",
                                      font=ctk.CTkFont(size=11))
        self._sb_badge.grid(row=0, column=1)

        # ── File input ──
        file_card = ctk.CTkFrame(self, corner_radius=8, fg_color=theme.color("card2"))
        file_card.grid(row=1, column=0, sticky="ew", padx=24, pady=(0, 8))
        file_card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(file_card, text="Target file:",
                     font=ctk.CTkFont(size=12), text_color=theme.color("subtext"),
                     anchor="w").grid(row=0, column=0, padx=(14, 8), pady=12)

        self._path_entry = ctk.CTkEntry(
            file_card, placeholder_text="Drop or browse to a file…",
            font=ctk.CTkFont(family="Consolas", size=11))
        self._path_entry.grid(row=0, column=1, sticky="ew", padx=(0, 8), pady=8)

        ctk.CTkButton(file_card, text="Browse", width=80,
                      fg_color=theme.color("input_hover"), hover_color="#4a4a5a",
                      command=self._browse).grid(row=0, column=2, padx=(0, 14), pady=8)

        # ── Stage cards ──
        stages = ctk.CTkFrame(self, fg_color="transparent")
        stages.grid(row=2, column=0, sticky="ew", padx=24, pady=(0, 8))
        stages.grid_columnconfigure((0, 1), weight=1)

        self._build_emulation_card(stages)
        self._build_detonation_card(stages)

        # ── Output tabs ──
        self._tabs = ctk.CTkTabview(self, fg_color=theme.color("card"), corner_radius=8)
        self._tabs.grid(row=3, column=0, sticky="nsew", padx=24, pady=(0, 16))

        for tab_name in ("API Calls", "Network", "Registry", "File Ops", "Indicators", "Raw JSON"):
            self._tabs.add(tab_name)
            self._tabs.tab(tab_name).grid_columnconfigure(0, weight=1)
            self._tabs.tab(tab_name).grid_rowconfigure(0, weight=1)

        self._txt_api  = self._make_textbox("API Calls")
        self._txt_net  = self._make_textbox("Network")
        self._txt_reg  = self._make_textbox("Registry")
        self._txt_file = self._make_textbox("File Ops")
        self._txt_ind  = self._make_textbox("Indicators")
        self._txt_raw  = self._make_textbox("Raw JSON")

        self._refresh_badges()

    def _build_emulation_card(self, parent):
        card = ctk.CTkFrame(parent, corner_radius=8, fg_color=theme.color("card"))
        card.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        card.grid_columnconfigure(0, weight=1)

        title_row = ctk.CTkFrame(card, fg_color="transparent")
        title_row.grid(row=0, column=0, sticky="ew", padx=14, pady=(12, 2))
        title_row.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(title_row, text="Stage 4 — Behavioral Trace",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=theme.color("accent"), anchor="w").grid(row=0, column=0, sticky="w")

        ctk.CTkLabel(card,
                     text="Speakeasy simulates the Windows environment\n"
                          "and observes what the file would do —\n"
                          "API calls, registry, network, file access.\n"
                          "The file never actually runs. Safe on any system.",
                     font=ctk.CTkFont(size=11), text_color=theme.color("subtext"),
                     anchor="w", justify="left").grid(
            row=1, column=0, sticky="w", padx=14, pady=(0, 8))

        self._emu_prog = ctk.CTkProgressBar(card)
        self._emu_prog.grid(row=2, column=0, sticky="ew", padx=14, pady=(0, 4))
        self._emu_prog.set(0)
        self._emu_prog.grid_remove()

        self._emu_status = ctk.CTkLabel(
            card, text="", font=ctk.CTkFont(size=11), text_color=theme.color("subtext"))
        self._emu_status.grid(row=3, column=0, sticky="w", padx=14, pady=(0, 4))

        self._emu_btn = ctk.CTkButton(
            card, text="Run Trace", width=110,
            fg_color="#1a3a6a", hover_color="#1f4a8a",
            command=self._run_emulation)
        self._emu_btn.grid(row=4, column=0, padx=14, pady=(0, 14), sticky="w")

    def _build_detonation_card(self, parent):
        card = ctk.CTkFrame(parent, corner_radius=8, fg_color=theme.color("card"))
        card.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        card.grid_columnconfigure(0, weight=1)

        title_row = ctk.CTkFrame(card, fg_color="transparent")
        title_row.grid(row=0, column=0, sticky="ew", padx=14, pady=(12, 2))
        title_row.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(title_row, text="Stage 5 — Sandbox Test",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#f1fa8c", anchor="w").grid(row=0, column=0, sticky="w")

        ctk.CTkLabel(card,
                     text="Sandboxie-Plus runs the file for real,\n"
                          "but traps all changes in an invisible box.\n"
                          "Your real OS is never touched.\n"
                          "Click Wipe Sandbox to discard everything.",
                     font=ctk.CTkFont(size=11), text_color=theme.color("subtext"),
                     anchor="w", justify="left").grid(
            row=1, column=0, sticky="w", padx=14, pady=(0, 8))

        self._det_status = ctk.CTkLabel(
            card, text="", font=ctk.CTkFont(size=11), text_color=theme.color("subtext"))
        self._det_status.grid(row=2, column=0, sticky="w", padx=14, pady=(0, 4))

        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.grid(row=3, column=0, sticky="w", padx=14, pady=(0, 14))

        self._det_btn = ctk.CTkButton(
            btn_row, text="Run in Sandbox", width=120,
            fg_color="#6a1a1a", hover_color="#8a2a2a",
            command=self._run_detonation)
        self._det_btn.grid(row=0, column=0, padx=(0, 8))

        self._wipe_btn = ctk.CTkButton(
            btn_row, text="Wipe Sandbox", width=115,
            fg_color="#3a2a1a", hover_color="#5a4a2a",
            border_width=1, border_color="#6a5a3a",
            font=ctk.CTkFont(size=11),
            command=self._wipe_sandbox)
        self._wipe_btn.grid(row=0, column=1)

    def _make_textbox(self, tab_name: str) -> ctk.CTkTextbox:
        box = ctk.CTkTextbox(
            self._tabs.tab(tab_name),
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color=theme.color("card2"), text_color=theme.color("text"),
            wrap="none", state="disabled")
        box.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        # Configure color tags
        box.tag_config(_TAG_THREAT, foreground="#ff5555")
        box.tag_config(_TAG_WARN,   foreground="#ffb86c")
        box.tag_config(_TAG_INFO,   foreground=theme.color("accent"))
        box.tag_config(_TAG_CLEAN,  foreground="#50fa7b")
        box.tag_config(_TAG_DIM,    foreground=theme.color("dim"))
        return box

    # ── Badge refresh ─────────────────────────────────────────────────────────

    def _refresh_badges(self):
        if ee.is_available():
            self._sp_badge.configure(
                text="Speakeasy ● Ready", text_color="#50fa7b")
        else:
            self._sp_badge.configure(
                text="Speakeasy ✗ Not installed", text_color="#ffb86c")
        self._emu_btn.configure(state="normal" if ee.is_available() else "disabled")

        sb_status = se.get_status()
        if sb_status == "ready":
            self._sb_badge.configure(
                text="Sandboxie ● Ready", text_color="#50fa7b")
        else:
            label_map = {
                "not configured": "Sandboxie — Not configured",
                "Start.exe not found": "Sandboxie — Path invalid",
                "not portable build (SbieCtrl.ini missing)": "Sandboxie — Not portable build",
            }
            self._sb_badge.configure(
                text=label_map.get(sb_status, f"Sandboxie — {sb_status}"),
                text_color="#ffb86c")

        sb_ok = se.is_available()
        self._det_btn.configure(state="normal" if sb_ok else "disabled")
        self._wipe_btn.configure(state="normal" if sb_ok else "disabled")

    # ── File selection ────────────────────────────────────────────────────────

    def _browse(self):
        path = fd.askopenfilename(
            title="Select file to analyze",
            filetypes=[("Executable files", "*.exe *.dll *.scr"),
                       ("All files", "*.*")])
        if path:
            self._set_path(path)

    def _set_path(self, path: str):
        self._path_entry.delete(0, "end")
        self._path_entry.insert(0, path)

    def _get_path(self) -> str | None:
        p = self._path_entry.get().strip()
        return p if p else None

    # ── Emulation ─────────────────────────────────────────────────────────────

    def _run_emulation(self):
        if self._busy:
            return
        path = self._get_path()
        if not path:
            self._emu_status.configure(text="No file selected.", text_color="#ffb86c")
            return

        self._busy = True
        self._emu_btn.configure(state="disabled")
        self._emu_status.configure(
            text="Emulating… (this may take up to 30 seconds)",
            text_color=theme.color("subtext"))
        self._emu_prog.configure(mode="indeterminate")
        self._emu_prog.grid()
        self._emu_prog.start()
        self._clear_output()
        self._status_cb("Emulating — please wait…")

        ee.emulate_async(path, on_done=lambda r: self.after(0, self._on_emulation_done, r))

    def _on_emulation_done(self, report):
        # Stop progress bar
        self._emu_prog.stop()
        self._emu_prog.configure(mode="determinate")
        self._emu_prog.set(0)
        self._emu_prog.grid_remove()

        self._busy = False
        self._emu_btn.configure(state="normal")

        if report.error:
            self._emu_status.configure(text=report.error, text_color="#ff5555")
            self._status_cb("Emulation failed.")
            return

        self._emu_status.configure(
            text=f"Done — {len(report.api_calls)} API calls, "
                 f"{len(report.network)} network, "
                 f"{len(report.registry)} registry, "
                 f"{len(report.file_ops)} file ops",
            text_color="#50fa7b")
        self._status_cb("Emulation complete.")
        self._populate_output(report)

    # ── Output population ─────────────────────────────────────────────────────

    def _clear_output(self):
        for box in (self._txt_api, self._txt_net, self._txt_reg,
                    self._txt_file, self._txt_ind, self._txt_raw):
            box.configure(state="normal")
            box.delete("1.0", "end")
            box.configure(state="disabled")

    def _populate_output(self, report):
        # API Calls
        self._txt_api.configure(state="normal")
        if report.api_calls:
            for c in report.api_calls:
                args_str = ", ".join(
                    str(a.get("val", a) if isinstance(a, dict) else a)
                    for a in c.get("args", []))
                line = f"{c['api']}({args_str})  →  {c.get('ret', '')}\n"
                # Highlight known-dangerous APIs in red
                _danger = {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                           "CryptEncrypt", "BCryptEncrypt", "NtCreateThreadEx"}
                tag = _TAG_THREAT if c["api"] in _danger else _TAG_INFO
                self._txt_api.insert("end", line, tag)
        else:
            self._txt_api.insert("end", "No API calls captured.\n", _TAG_DIM)
        self._txt_api.configure(state="disabled")

        # Network
        self._txt_net.configure(state="normal")
        if report.network:
            for url in report.network:
                self._txt_net.insert("end", f"{url}\n", _TAG_THREAT)
        else:
            self._txt_net.insert("end", "No network activity detected.\n", _TAG_CLEAN)
        self._txt_net.configure(state="disabled")

        # Registry
        self._txt_reg.configure(state="normal")
        if report.registry:
            for r in report.registry:
                line = f"[{r['op'].upper()}]  {r['key']}\n"
                _PERSIST = "\\Run"
                tag = _TAG_THREAT if _PERSIST in r["key"] else _TAG_WARN
                self._txt_reg.insert("end", line, tag)
        else:
            self._txt_reg.insert("end", "No registry operations detected.\n", _TAG_CLEAN)
        self._txt_reg.configure(state="disabled")

        # File Ops
        self._txt_file.configure(state="normal")
        if report.file_ops:
            for f in report.file_ops:
                line = f"[{f['op'].upper()}]  {f['path']}\n"
                tag = _TAG_WARN if f["op"] in ("create", "write", "delete") else _TAG_DIM
                self._txt_file.insert("end", line, tag)
        else:
            self._txt_file.insert("end", "No file operations detected.\n", _TAG_CLEAN)
        self._txt_file.configure(state="disabled")

        # Threat Indicators
        self._txt_ind.configure(state="normal")
        indicators = report.threat_indicators
        if indicators:
            self._txt_ind.insert("end", "⚠  Threat Indicators Detected\n\n", _TAG_THREAT)
            for ind in indicators:
                self._txt_ind.insert("end", f"  • {ind}\n", _TAG_WARN)
        else:
            self._txt_ind.insert("end", "✓  No significant threat indicators detected.\n", _TAG_CLEAN)
        self._txt_ind.configure(state="disabled")

        # Raw JSON
        self._txt_raw.configure(state="normal")
        try:
            raw_text = json.dumps(report.raw, indent=2, default=str)
        except Exception:
            raw_text = str(report.raw)
        self._txt_raw.insert("end", raw_text, _TAG_DIM)
        self._txt_raw.configure(state="disabled")

        # Switch to Indicators tab if any threats found
        if indicators:
            self._tabs.set("Indicators")
        elif report.network:
            self._tabs.set("Network")
        else:
            self._tabs.set("API Calls")

    # ── Detonation ────────────────────────────────────────────────────────────

    def _run_detonation(self):
        if self._detonating:
            return
        path = self._get_path()
        if not path:
            self._det_status.configure(text="No file selected.", text_color="#ffb86c")
            return
        if not Path(path).exists():
            self._det_status.configure(text="File not found.", text_color="#ff5555")
            return

        self._detonating = True
        self._det_btn.configure(state="disabled")
        self._det_status.configure(
            text="Running in sandbox — close the application window to finish.",
            text_color="#f1fa8c")
        self._status_cb("Running in sandbox — close the application window when done.")

        se.detonate(
            path,
            on_started=None,
            on_finished=lambda rc: self.after(0, self._on_detonation_done, rc),
        )

    def _on_detonation_done(self, returncode: int):
        self._detonating = False
        self._det_btn.configure(state="normal")
        self._det_status.configure(
            text=f"Sandbox test finished (exit code {returncode}). "
                 "Use 'Wipe Sandbox' to discard all changes.",
            text_color="#50fa7b")
        self._status_cb("Sandbox test complete — contents preserved until wiped.")

    def _wipe_sandbox(self):
        self._wipe_btn.configure(state="disabled")
        self._det_status.configure(text="Wiping sandbox…", text_color=theme.color("subtext"))
        self._status_cb("Wiping KicomHunter sandbox…")
        se.wipe_sandbox(on_done=lambda ok: self.after(0, self._on_wipe_done, ok))

    def _on_wipe_done(self, success: bool):
        self._wipe_btn.configure(state="normal")
        if success:
            self._det_status.configure(
                text="Sandbox wiped — all isolated changes discarded.", text_color="#50fa7b")
            self._status_cb("Sandbox wiped.")
        else:
            self._det_status.configure(
                text="Wipe failed — try manually via Sandboxie-Plus UI.", text_color="#ff5555")
            self._status_cb("Sandbox wipe failed.")
