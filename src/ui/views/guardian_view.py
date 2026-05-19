"""
guardian_view.py
────────────────
Standalone "Guardian AI" panel in the PolyShield sidebar.

• If guardianai/ is not installed: shows a setup card with instructions.
• If installed: full file/folder scanner using guardian_engine.py.

Results use colour-coded tags matching the rest of the UI:
  red    = infected (known signature or pattern match)
  yellow = suspicious / pattern match
  green  = clean
  white  = info
  amber  = Guardian AI system messages
"""
import threading
from tkinter import filedialog
from pathlib import Path

import customtkinter as ctk

from ui.core import guardian_engine as ge
from ui.core import settings as cfg

try:
    from tkinterdnd2 import DND_FILES
    _DND_AVAILABLE = True
except ImportError:
    _DND_AVAILABLE = False

_TAG_INFECTED  = "infected"
_TAG_CLEAN     = "clean"
_TAG_WARN      = "warn"
_TAG_INFO      = "info"
_TAG_GUARDIAN  = "guardian"


class GuardianView(ctk.CTkFrame):
    def __init__(self, master, status_callback, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self._status_cb = status_callback
        self._scanning  = False
        self._paths: list[str] = []
        self._build()

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(5, weight=1)  # log row

        # ── Row 0: Title + availability badge ──
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=24, pady=(20, 6))
        header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(header, text="Guardian AI",
                     font=ctk.CTkFont(size=22, weight="bold")).grid(
            row=0, column=0, sticky="w")

        available = ge.is_available()
        badge_text  = "● Ready" if available else "● Not installed"
        badge_color = "#50fa7b" if available else "#ffb86c"
        ctk.CTkLabel(header, text=badge_text,
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color=badge_color).grid(row=0, column=1, padx=8)

        # ── Row 1: Info / setup card ──
        info_card = ctk.CTkFrame(self, corner_radius=10, fg_color="#1a1a2e")
        info_card.grid(row=1, column=0, sticky="ew", padx=24, pady=(0, 8))
        info_card.grid_columnconfigure(0, weight=1)

        if available:
            # Static first line
            ctk.CTkLabel(info_card,
                         text="Second-opinion scanner: MD5 signatures + heuristic pattern matching.",
                         anchor="w", justify="left",
                         font=ctk.CTkFont(size=11),
                         text_color="#666688").grid(
                row=0, column=0, sticky="w", padx=16, pady=(10, 2))

            # Dynamic lines — stored so _refresh_stats() can update them
            self._db_count_lbl = ctk.CTkLabel(
                info_card, text="", anchor="w", justify="left",
                font=ctk.CTkFont(size=11), text_color="#666688")
            self._db_count_lbl.grid(row=1, column=0, sticky="w", padx=16, pady=2)

            self._db_updated_lbl = ctk.CTkLabel(
                info_card, text="", anchor="w", justify="left",
                font=ctk.CTkFont(size=11), text_color="#666688")
            self._db_updated_lbl.grid(row=2, column=0, sticky="w", padx=16, pady=(2, 4))

            self._refresh_stats()   # populate the two dynamic labels now

            # Update Signatures button  (rows 3 and 4 — after the 3 dynamic label rows)
            update_row = ctk.CTkFrame(info_card, fg_color="transparent")
            update_row.grid(row=3, column=0, sticky="ew", padx=16, pady=(4, 12))
            update_row.grid_columnconfigure(1, weight=1)

            self._update_btn = ctk.CTkButton(
                update_row, text="↓  Update Signatures (recent 24h)",
                width=260, fg_color="#1a3a5a", hover_color="#1f4a7a",
                font=ctk.CTkFont(size=12),
                command=self._run_update_recent)
            self._update_btn.grid(row=0, column=0, padx=(0, 8))

            ctk.CTkButton(
                update_row, text="Full list",
                width=80, fg_color="#2a2a3a", hover_color="#3a3a4a",
                font=ctk.CTkFont(size=11),
                command=self._run_update_full).grid(row=0, column=1, sticky="w")

            self._update_status = ctk.CTkLabel(
                info_card, text="",
                font=ctk.CTkFont(size=11), text_color="#888888", anchor="w")
            self._update_status.grid(row=4, column=0,
                                      sticky="w", padx=16, pady=(0, 8))
        else:
            not_installed_lines = [
                "GuardianAI is not set up yet. Run setup_guardian.bat to get started.",
                "It will clone the GuardianAI repo and create a portable guardian_env/",
                "in your project folder — no global Python installation needed.",
            ]
            for i, text in enumerate(not_installed_lines):
                ctk.CTkLabel(info_card, text=text, anchor="w", justify="left",
                             font=ctk.CTkFont(size=11),
                             text_color="#666688").grid(
                    row=i, column=0, sticky="w", padx=16,
                    pady=(10 if i == 0 else 2, 4))
            ctk.CTkButton(
                info_card,
                text="Open setup_guardian.bat",
                width=210,
                fg_color="#2a5a2a",
                hover_color="#3a7a3a",
                command=self._open_setup_bat,
            ).grid(row=len(not_installed_lines), column=0,
                   sticky="w", padx=16, pady=(6, 12))

        if not available:
            return  # Nothing more to show until installed

        # ── Row 2: Drop zone ──
        self._drop_frame = ctk.CTkFrame(self, height=80, corner_radius=12,
                                        border_width=2, border_color="#3a3a3a")
        self._drop_frame.grid(row=2, column=0, sticky="ew", padx=24, pady=(0, 6))
        self._drop_frame.grid_propagate(False)
        self._drop_frame.grid_columnconfigure(0, weight=1)
        self._drop_frame.grid_rowconfigure(0, weight=1)

        self._drop_label = ctk.CTkLabel(
            self._drop_frame, text="Drop files or folders here",
            text_color="#888888", font=ctk.CTkFont(size=13))
        self._drop_label.grid(row=0, column=0)

        if _DND_AVAILABLE:
            self._drop_frame.drop_target_register(DND_FILES)
            self._drop_frame.dnd_bind("<<Drop>>", self._on_drop)

        # ── Row 3: Toolbar ──
        toolbar = ctk.CTkFrame(self, fg_color="transparent")
        toolbar.grid(row=3, column=0, sticky="ew", padx=24, pady=(0, 6))
        toolbar.grid_columnconfigure(2, weight=1)

        ctk.CTkButton(toolbar, text="Browse File", width=115,
                      command=self._browse_file).grid(row=0, column=0, padx=(0, 6))
        ctk.CTkButton(toolbar, text="Browse Folder", width=125,
                      command=self._browse_folder).grid(row=0, column=1, padx=(0, 16))

        self._scan_btn = ctk.CTkButton(
            toolbar, text="Scan", width=120,
            fg_color="#1f6aa5", hover_color="#144e7a",
            command=self._start_scan)
        self._scan_btn.grid(row=0, column=3)

        ctk.CTkButton(toolbar, text="Clear", width=75,
                      fg_color="#3a3a3a", hover_color="#4a4a4a",
                      command=self._clear).grid(row=0, column=4, padx=(8, 0))

        # ── Row 4: Progress (hidden until scan) ──
        self._progress_frame = ctk.CTkFrame(self, corner_radius=8, fg_color="#1a1a2e")
        self._progress_frame.grid(row=4, column=0, sticky="ew", padx=24, pady=(0, 6))
        self._progress_frame.grid_columnconfigure(0, weight=1)

        top = ctk.CTkFrame(self._progress_frame, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=12, pady=(10, 4))
        top.grid_columnconfigure(0, weight=1)

        self._progress_bar = ctk.CTkProgressBar(top, height=12, corner_radius=6)
        self._progress_bar.set(0)
        self._progress_bar.grid(row=0, column=0, sticky="ew", padx=(0, 10))

        self._pct_lbl = ctk.CTkLabel(top, text="0%", width=40,
                                      font=ctk.CTkFont(size=12), text_color="#cdd6f4")
        self._pct_lbl.grid(row=0, column=1)

        self._current_file_lbl = ctk.CTkLabel(
            self._progress_frame, text="",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color="#666688", anchor="w")
        self._current_file_lbl.grid(row=1, column=0, sticky="ew", padx=14, pady=(0, 8))

        self._progress_frame.grid_remove()

        # ── Row 5: Live log ──
        self._log = ctk.CTkTextbox(
            self, font=ctk.CTkFont(family="Consolas", size=12),
            wrap="word", state="disabled")
        self._log.grid(row=5, column=0, sticky="nsew", padx=24, pady=(0, 6))
        self._log.tag_config(_TAG_INFECTED, foreground="#ff5555")
        self._log.tag_config(_TAG_CLEAN,    foreground="#50fa7b")
        self._log.tag_config(_TAG_WARN,     foreground="#ffb86c")
        self._log.tag_config(_TAG_INFO,     foreground="#cdd6f4")
        self._log.tag_config(_TAG_GUARDIAN, foreground="#f1fa8c")

        # ── Row 6: Summary bar ──
        summary = ctk.CTkFrame(self, height=36, corner_radius=8, fg_color="#1e1e2e")
        summary.grid(row=6, column=0, sticky="ew", padx=24, pady=(0, 16))
        summary.grid_propagate(False)
        summary.grid_columnconfigure((0, 1, 2), weight=1)

        self._lbl_checked  = self._summary_lbl(summary, "Checked: —",  0)
        self._lbl_threats  = self._summary_lbl(summary, "Threats: —",  1, "#ff5555")
        self._lbl_clean    = self._summary_lbl(summary, "Clean: —",    2, "#50fa7b")

    @staticmethod
    def _summary_lbl(parent, text, col, color="#cdd6f4"):
        lbl = ctk.CTkLabel(parent, text=text, text_color=color,
                           font=ctk.CTkFont(size=12))
        lbl.grid(row=0, column=col, padx=8)
        return lbl

    # ── Stats refresh ─────────────────────────────────────────────────────────

    def _refresh_stats(self):
        """Re-read DB stats and update the live count / timestamp labels."""
        if not hasattr(self, "_db_count_lbl"):
            return
        stats   = ge.get_db_stats()
        known   = stats.get("known_bad", 0)
        safe    = stats.get("known_safe", 0)
        updated = stats.get("last_updated", "Never")

        if known:
            count_text = f"  🛡  {known:,} known-bad"
            if safe:
                count_text += f"  |  ✅ {safe:,} known-safe (NSRL)"
        else:
            count_text = "  🛡  No signatures yet — click 'Update Signatures' to fetch threat data"

        self._db_count_lbl.configure(text=count_text)
        self._db_updated_lbl.configure(text=f"  🕒  Last updated: {updated}")

    def on_show(self):
        """Called by app.py whenever the user navigates to this view."""
        self._refresh_stats()

    # ── Signature update ──────────────────────────────────────────────────────

    def _run_update_recent(self):
        self._start_update("recent")

    def _run_update_full(self):
        self._start_update("full")

    def _start_update(self, mode: str):
        if not hasattr(self, "_update_btn"):
            return
        self._update_btn.configure(state="disabled", text="Updating…")
        self._update_status.configure(text="Connecting to MalwareBazaar…",
                                       text_color="#ffb86c")
        self._status_cb("Guardian AI: fetching intelligence update…")

        def _run():
            try:
                import sys
                from pathlib import Path
                _root = Path(__file__).resolve().parents[3] / "src"
                if str(_root) not in sys.path:
                    sys.path.insert(0, str(_root))
                from tools.update_intelligence import run_update

                messages: list[str] = []

                def _log(msg: str):
                    messages.append(msg)
                    # Show last message live
                    if self.winfo_exists():
                        self.after(0, self._update_status.configure,
                                   {"text": msg[:80], "text_color": "#ffb86c"})

                result = run_update(on_progress=_log, mode=mode)

                from ui.core.guardian_engine import reload_signatures
                reload_signatures()

                if self.winfo_exists():
                    if "error" in result:
                        final = f"Update failed: {result['error']}"
                        color = "#ff5555"
                    else:
                        added = result.get("added", 0)
                        total = result.get("total_db", 0)
                        final = (f"✓ Added {added:,} new  |  DB total: {total:,}  "
                                 f"|  Signatures reloaded")
                        color = "#50fa7b"
                    self.after(0, self._finish_update, final, color)
            except Exception as exc:
                if self.winfo_exists():
                    self.after(0, self._finish_update, f"Error: {exc}", "#ff5555")

        threading.Thread(target=_run, daemon=True).start()

    def _finish_update(self, message: str, color: str):
        if hasattr(self, "_update_btn"):
            self._update_btn.configure(
                state="normal", text="↓  Update Signatures (recent 24h)")
        if hasattr(self, "_update_status"):
            self._update_status.configure(text=message, text_color=color)
        self._refresh_stats()   # update count / timestamp labels live
        self._status_cb("Guardian AI: update complete")

    # ── Setup helper ──────────────────────────────────────────────────────────

    @staticmethod
    def _open_setup_bat():
        import subprocess
        from pathlib import Path
        bat = Path(__file__).resolve().parents[3] / "scripts" / "setup_guardian.bat"
        if bat.exists():
            # Run in a visible cmd window intentionally (user needs to see progress)
            subprocess.Popen(["cmd", "/c", str(bat)])

    # ── Drop & browse ─────────────────────────────────────────────────────────

    def _on_drop(self, event):
        self._add_paths(self._parse_dnd_paths(event.data))

    @staticmethod
    def _parse_dnd_paths(raw: str) -> list[str]:
        paths, raw, i = [], raw.strip(), 0
        while i < len(raw):
            if raw[i] == "{":
                end = raw.index("}", i)
                paths.append(raw[i + 1:end])
                i = end + 2
            else:
                end = raw.find(" ", i)
                if end == -1:
                    paths.append(raw[i:])
                    break
                paths.append(raw[i:end])
                i = end + 1
        return [p for p in paths if p]

    def _add_paths(self, paths: list[str]):
        for p in paths:
            if p not in self._paths:
                self._paths.append(p)
        self._refresh_drop_label()

    def _refresh_drop_label(self):
        if self._paths:
            names = ", ".join(Path(p).name for p in self._paths[:3])
            extra = f" +{len(self._paths) - 3} more" if len(self._paths) > 3 else ""
            self._drop_label.configure(text=f"{names}{extra}", text_color="#cdd6f4")
        else:
            self._drop_label.configure(text="Drop files or folders here",
                                       text_color="#888888")

    def _browse_file(self):
        paths = filedialog.askopenfilenames(title="Select files to scan with Guardian AI")
        if paths:
            self._add_paths(list(paths))

    def _browse_folder(self):
        path = filedialog.askdirectory(title="Select folder to scan with Guardian AI")
        if path:
            self._add_paths([path])

    # ── Scan ──────────────────────────────────────────────────────────────────

    def _clear(self):
        if self._scanning:
            return
        self._paths.clear()
        self._refresh_drop_label()
        self._log_clear()
        self._progress_bar.set(0)
        self._pct_lbl.configure(text="0%")
        self._current_file_lbl.configure(text="")
        self._progress_frame.grid_remove()
        for lbl, text in [
            (self._lbl_checked, "Checked: —"),
            (self._lbl_threats, "Threats: —"),
            (self._lbl_clean,   "Clean: —"),
        ]:
            lbl.configure(text=text)

    def _start_scan(self):
        if self._scanning:
            return
        if not self._paths:
            self._log_append("[INFO] No targets. Browse or drop files first.", _TAG_INFO)
            return

        self._scanning = True
        self._scan_btn.configure(state="disabled", text="Scanning…")
        self._log_clear()
        self._progress_bar.set(0)
        self._pct_lbl.configure(text="0%")
        self._current_file_lbl.configure(text="")
        self._progress_frame.grid()
        self._status_cb("Guardian AI scan starting…")
        self._log_append("[Guardian AI] Scan started", _TAG_GUARDIAN)

        self._g_checked = 0
        self._g_threats = 0

        ge.scan_async(
            self._paths,
            on_result=self._on_result,
            on_done=self._on_done,
            on_progress=self._on_progress,
        )

    def _on_result(self, file_path: str, infected: bool, reason: str):
        def _upd():
            self._g_checked += 1
            if infected:
                self._g_threats += 1
                tag = _TAG_WARN if "pattern" in reason.lower() else _TAG_INFECTED
                self._log_append(f"[THREAT]  {file_path}", tag)
                self._log_append(f"           ↳ {reason}", tag)
            elif cfg.get("verbose_log"):
                self._log_append(f"[CLEAN]   {Path(file_path).name}", _TAG_CLEAN)
        self.after(0, _upd)

    def _on_progress(self, done: int, total: int, current_file: str):
        def _upd():
            if total > 0:
                pct = min(done / total, 1.0)
                self._progress_bar.set(pct)
                self._pct_lbl.configure(text=f"{int(pct * 100)}%")
            if current_file:
                self._current_file_lbl.configure(text=f"  {Path(current_file).name}")
            self._status_cb(f"Guardian AI: {done}/{total or '?'} files")
        self.after(0, _upd)

    def _on_done(self, infected_count: int):
        def _upd():
            self._scanning = False
            self._scan_btn.configure(state="normal", text="Scan")
            self._progress_bar.set(1.0)
            self._pct_lbl.configure(text="100%")
            self._current_file_lbl.configure(text="")

            clean = self._g_checked - infected_count
            self._lbl_checked.configure(text=f"Checked: {self._g_checked}")
            self._lbl_threats.configure(text=f"Threats: {infected_count}")
            self._lbl_clean.configure(text=f"Clean: {clean}")

            if infected_count:
                status = f"Guardian AI — {infected_count} threat(s) found!"
                self._log_append(f"\n[Guardian AI] {infected_count} threat(s) detected.", _TAG_INFECTED)
            else:
                status = "Guardian AI — all clear"
                self._log_append("\n[Guardian AI] Scan complete — no threats found.", _TAG_CLEAN)

            self._status_cb(status)
        self.after(0, _upd)

    # ── Log helpers ───────────────────────────────────────────────────────────

    def _log_append(self, line: str, tag: str = _TAG_INFO):
        self._log.configure(state="normal")
        self._log.insert("end", line + "\n", tag)
        self._log.see("end")
        self._log.configure(state="disabled")

    def _log_clear(self):
        self._log.configure(state="normal")
        self._log.delete("1.0", "end")
        self._log.configure(state="disabled")
