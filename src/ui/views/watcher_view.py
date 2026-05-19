from tkinter import filedialog
import customtkinter as ctk
from pathlib import Path

from ui.core import watcher as wtch
from ui.core import settings as cfg
from ui.core import guardian_engine as ge
from ui.core import yara_engine as ye
from ui.core import clamav_engine as ce
from ui.core import service_client as svc

# Threat notification callback — set by App after tray icon is created.
# Signature: (filename: str, threat: str) -> None
_notify_callback = None


def set_notify_callback(cb):
    """Called by App to wire tray balloon notifications into the watcher."""
    global _notify_callback
    _notify_callback = cb


def _on_new_file_detected(path: str, entry: dict):
    """Callback from watcher: scan the new file with k2, optionally Guardian AI."""
    wtch.scan_new_file(path, entry, notify_cb=_notify_callback)


class WatcherView(ctk.CTkFrame):
    def __init__(self, master, status_callback, navigate_callback=None, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self._status_cb = status_callback
        self._navigate_cb = navigate_callback
        self._folder_rows: list[dict] = []
        self._service_mode = False
        self._build()
        self._refresh_log()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        # ── Title + master toggle ──
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=24, pady=(20, 8))
        header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(header, text="Real-Time Folder Watcher",
                     font=ctk.CTkFont(size=22, weight="bold")).grid(
            row=0, column=0, sticky="w")

        self._toggle_btn = ctk.CTkButton(
            header, text="", width=130, height=34,
            command=self._toggle_watcher)
        self._toggle_btn.grid(row=0, column=1, padx=(8, 0))
        self._update_toggle_btn()

        self._status_dot = ctk.CTkLabel(
            header, text="", font=ctk.CTkFont(size=12), text_color="#888888")
        self._status_dot.grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 0))

        self._mode_badge = ctk.CTkLabel(
            header, text="", font=ctk.CTkFont(size=11), text_color="#888888",
            cursor="hand2")
        self._mode_badge.grid(row=2, column=0, columnspan=2, sticky="w", pady=(2, 0))
        self._mode_badge.bind("<Button-1>", self._on_mode_badge_click)
        self._update_status_dot()

        # ── Watched folders ──
        folders_card = ctk.CTkFrame(self, corner_radius=10, fg_color="#1a1a2e")
        folders_card.grid(row=1, column=0, sticky="ew", padx=24, pady=(0, 8))
        folders_card.grid_columnconfigure(0, weight=1)

        top = ctk.CTkFrame(folders_card, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=16, pady=(12, 4))
        top.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(top, text="Watched Folders",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#5294e2").grid(row=0, column=0, sticky="w")
        ctk.CTkButton(top, text="+ Add Folder", width=120, height=28,
                      fg_color="#1f6aa5", hover_color="#144e7a",
                      font=ctk.CTkFont(size=12),
                      command=self._add_folder).grid(row=0, column=1)

        self._folder_list = ctk.CTkScrollableFrame(
            folders_card, height=110, corner_radius=6, fg_color="#12121e")
        self._folder_list.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 8))
        self._folder_list.grid_columnconfigure(0, weight=1)

        self._no_folder_lbl = ctk.CTkLabel(
            self._folder_list, text="No folders configured",
            text_color="#555577", font=ctk.CTkFont(size=12))
        self._no_folder_lbl.grid(row=0, column=0, pady=16)

        # ── Options ──
        opts = ctk.CTkFrame(self, corner_radius=10, fg_color="#1a1a2e")
        opts.grid(row=2, column=0, sticky="ew", padx=24, pady=(0, 8))
        opts.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(opts, text="Options",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#5294e2").grid(
            row=0, column=0, sticky="w", padx=16, pady=(12, 4))

        opt_row = ctk.CTkFrame(opts, fg_color="transparent")
        opt_row.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 12))
        opt_row.grid_columnconfigure(1, weight=1)

        self._auto_q_switch = ctk.CTkSwitch(opt_row, text="Auto-quarantine threats",
                                             command=self._save_auto_q)
        self._auto_q_switch.grid(row=0, column=0)
        if cfg.get("watcher_auto_quarantine"):
            self._auto_q_switch.select()

        ctk.CTkLabel(opt_row, text="  When off: log only",
                     font=ctk.CTkFont(size=11), text_color="#555577").grid(
            row=0, column=1, sticky="w")

        # Guardian AI second opinion on detected files
        self._guard_scan_switch = ctk.CTkSwitch(
            opt_row, text="Guardian AI second opinion on detected files",
            command=self._save_guard_scan,
            state="normal" if ge.is_available() else "disabled",
        )
        self._guard_scan_switch.grid(row=1, column=0, columnspan=2, pady=(6, 0))
        if cfg.get("watcher_guardian_scan") and ge.is_available():
            self._guard_scan_switch.select()
        if not ge.is_available():
            ctk.CTkLabel(opt_row, text="  (Guardian AI not installed)",
                         font=ctk.CTkFont(size=11), text_color="#555577").grid(
                row=2, column=0, columnspan=2, sticky="w")

        # YARA rules scan on detected files
        yara_available = ye.is_available()
        self._yara_scan_switch = ctk.CTkSwitch(
            opt_row, text="YARA rules scan on detected files",
            command=self._save_yara_scan,
            state="normal" if yara_available else "disabled",
        )
        self._yara_scan_switch.grid(row=3, column=0, columnspan=2, pady=(6, 0))
        if cfg.get("watcher_yara_scan") and yara_available:
            self._yara_scan_switch.select()
        if not yara_available:
            ctk.CTkLabel(opt_row, text="  (no .yar files in rules/user_rules/)",
                         font=ctk.CTkFont(size=11), text_color="#555577").grid(
                row=4, column=0, columnspan=2, sticky="w")

        # ClamAV scan on detected files
        clamav_available = ce.is_available()
        self._clamav_scan_switch = ctk.CTkSwitch(
            opt_row, text="ClamAV scan on detected files",
            command=self._save_clamav_scan,
            state="normal" if clamav_available else "disabled",
        )
        self._clamav_scan_switch.grid(row=5, column=0, columnspan=2, pady=(6, 0))
        if cfg.get("watcher_clamav_scan") and clamav_available:
            self._clamav_scan_switch.select()
        if not clamav_available:
            ctk.CTkLabel(opt_row, text="  (ClamAV not configured — see Settings → ClamAV)",
                         font=ctk.CTkFont(size=11), text_color="#555577").grid(
                row=6, column=0, columnspan=2, sticky="w")

        # ── Detection log ──
        ctk.CTkLabel(self, text="Detection Log",
                     font=ctk.CTkFont(size=14, weight="bold")).grid(
            row=3, column=0, sticky="w", padx=24, pady=(4, 4))

        log_header = ctk.CTkFrame(self, fg_color="transparent")
        log_header.grid(row=3, column=0, sticky="e", padx=24, pady=(4, 4))
        ctk.CTkButton(log_header, text="Clear Log", width=90, height=26,
                      fg_color="#3a3a3a", hover_color="#4a4a4a",
                      font=ctk.CTkFont(size=11),
                      command=self._clear_log).pack()

        self._log_scroll = ctk.CTkScrollableFrame(
            self, corner_radius=8, fg_color="#1a1a2e")
        self._log_scroll.grid(row=4, column=0, sticky="nsew", padx=24, pady=(0, 16))
        self._log_scroll.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(4, weight=1)

        self._refresh_folder_list()
        wtch.add_detection_callback(self._on_detection)

    # ── Folder management ─────────────────────────────────────────────────────

    def _add_folder(self):
        path = filedialog.askdirectory(title="Select folder to watch")
        if not path:
            return
        folders = list(cfg.get("watcher_folders") or [])
        if path not in folders:
            folders.append(path)
            cfg.set_value("watcher_folders", folders)
        self._refresh_folder_list()

    def _remove_folder(self, path: str):
        folders = [f for f in (cfg.get("watcher_folders") or []) if f != path]
        cfg.set_value("watcher_folders", folders)
        self._refresh_folder_list()
        if wtch.is_running():
            wtch.stop()
            wtch.start(_on_new_file_detected)
            self._update_toggle_btn()
            self._update_status_dot()

    def _refresh_folder_list(self):
        for w in self._folder_list.winfo_children():
            w.destroy()
        folders = cfg.get("watcher_folders") or []
        if not folders:
            lbl = ctk.CTkLabel(self._folder_list, text="No folders configured",
                               text_color="#555577", font=ctk.CTkFont(size=12))
            lbl.grid(row=0, column=0, pady=16)
            return
        for i, folder in enumerate(folders):
            row_f = ctk.CTkFrame(self._folder_list,
                                  fg_color="#1e1e2e" if i % 2 == 0 else "#232340")
            row_f.grid(row=i, column=0, sticky="ew", pady=1)
            row_f.grid_columnconfigure(0, weight=1)
            exists = Path(folder).is_dir()
            color = "#cdd6f4" if exists else "#ff5555"
            ctk.CTkLabel(row_f, text=folder, anchor="w",
                         text_color=color, font=ctk.CTkFont(size=12)).grid(
                row=0, column=0, sticky="w", padx=10, pady=4)
            ctk.CTkButton(row_f, text="Remove", width=70, height=24,
                          fg_color="#3a3a3a", hover_color="#8b0000",
                          font=ctk.CTkFont(size=11),
                          command=lambda f=folder: self._remove_folder(f)).grid(
                row=0, column=1, padx=6)

    # ── Watcher control ───────────────────────────────────────────────────────

    def _toggle_watcher(self):
        if self._service_mode:
            import threading
            if wtch.is_running():
                def _stop():
                    svc.send_command("STOP_WATCHER")
                    if self.winfo_exists():
                        self.after(0, self._on_show_refresh)
                threading.Thread(target=_stop, daemon=True).start()
                self._status_cb("Stopping service watcher…")
            else:
                def _start():
                    result = svc.send_command("START_WATCHER")
                    msg = "Service watcher started" if (result and result.get("ok")) else "Failed to start watcher"
                    if self.winfo_exists():
                        self.after(0, self._on_show_refresh)
                        self.after(0, lambda m=msg: self._status_cb(m))
                threading.Thread(target=_start, daemon=True).start()
                self._status_cb("Starting service watcher…")
        else:
            if wtch.is_running():
                wtch.stop()
                self._status_cb("Folder watcher stopped")
            else:
                ok = wtch.start(_on_new_file_detected)
                if ok:
                    self._status_cb("Folder watcher started")
                else:
                    self._status_cb("No valid folders to watch")
            self._update_toggle_btn()
            self._update_status_dot()

    def _update_toggle_btn(self):
        if wtch.is_running():
            self._toggle_btn.configure(
                text="Stop Watching",
                fg_color="#8b0000", hover_color="#5c0000")
        else:
            self._toggle_btn.configure(
                text="Start Watching",
                fg_color="#1f6aa5", hover_color="#144e7a")

    def _update_status_dot(self):
        if wtch.is_running():
            folders = cfg.get("watcher_folders") or []
            self._status_dot.configure(
                text=f"● Monitoring {len(folders)} folder(s)",
                text_color="#50fa7b")
        else:
            self._status_dot.configure(text="● Idle", text_color="#888888")

    # ── Log ───────────────────────────────────────────────────────────────────

    def _on_detection(self, entry: dict):
        self.after(0, self._refresh_log)

    def _refresh_log(self):
        if self._service_mode:
            import threading
            threading.Thread(target=self._refresh_log_from_service, daemon=True).start()
            return
        self._render_log(wtch.get_log())

    def _refresh_log_from_service(self):
        log = svc.get_events()
        if self.winfo_exists():
            self.after(0, lambda l=log: self._render_log(l))

    def _render_log(self, log: list):
        for w in self._log_scroll.winfo_children():
            w.destroy()
        if not log:
            ctk.CTkLabel(self._log_scroll, text="No events yet",
                         text_color="#555577", font=ctk.CTkFont(size=12)).grid(
                row=0, column=0, pady=20)
            return
        for i, entry in enumerate(reversed(log)):
            status = entry.get("status", "pending")
            color = ("#ff5555" if "threat" in status
                     else "#50fa7b" if status == "clean"
                     else "#ffb86c")
            bg = "#1e1e2e" if i % 2 == 0 else "#232340"
            row_f = ctk.CTkFrame(self._log_scroll, fg_color=bg)
            row_f.grid(row=i, column=0, sticky="ew", pady=1)
            row_f.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(row_f, text=entry.get("filename", ""),
                         anchor="w", font=ctk.CTkFont(size=12),
                         text_color=color).grid(
                row=0, column=0, sticky="w", padx=10, pady=4)
            ctk.CTkLabel(row_f, text=entry.get("time", ""),
                         font=ctk.CTkFont(size=11),
                         text_color="#666688").grid(row=0, column=1, padx=8)
            ctk.CTkLabel(row_f, text=status.upper(),
                         font=ctk.CTkFont(size=11),
                         text_color=color).grid(row=0, column=2, padx=8)

    def _clear_log(self):
        if self._service_mode:
            import threading
            def _do():
                svc.send_command("CLEAR_EVENTS")
                if self.winfo_exists():
                    self.after(0, self._refresh_log)
            threading.Thread(target=_do, daemon=True).start()
        else:
            wtch.clear_log()
            self._refresh_log()

    def _save_auto_q(self):
        cfg.set_value("watcher_auto_quarantine", bool(self._auto_q_switch.get()))

    def _save_guard_scan(self):
        cfg.set_value("watcher_guardian_scan", bool(self._guard_scan_switch.get()))

    def _save_yara_scan(self):
        cfg.set_value("watcher_yara_scan", bool(self._yara_scan_switch.get()))

    def _save_clamav_scan(self):
        cfg.set_value("watcher_clamav_scan", bool(self._clamav_scan_switch.get()))

    def on_show(self):
        import threading
        def _probe():
            running = svc.is_service_running()
            if self.winfo_exists():
                self.after(0, lambda r=running: self._apply_service_mode(r))
        threading.Thread(target=_probe, daemon=True).start()
        self._update_toggle_btn()
        self._update_status_dot()
        self._refresh_folder_list()
        self._refresh_log()

    def _apply_service_mode(self, service_running: bool):
        self._service_mode = service_running
        self._update_mode_badge()
        self._update_toggle_btn()
        self._update_status_dot()
        if service_running:
            self._refresh_log()

    def _on_show_refresh(self):
        self._update_toggle_btn()
        self._update_status_dot()

    def _update_mode_badge(self):
        if self._service_mode:
            self._mode_badge.configure(
                text="● Service mode — watcher managed by PolyShield Service  [Go to Service →]",
                text_color="#50fa7b")
        else:
            self._mode_badge.configure(
                text="● In-process mode — watcher stops when UI closes  [Install Service →]",
                text_color="#ffb86c")

    def _on_mode_badge_click(self, _event=None):
        if self._navigate_cb:
            self._navigate_cb("service")
