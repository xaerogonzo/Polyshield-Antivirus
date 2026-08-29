import subprocess
import sys
import threading
from pathlib import Path

import customtkinter as ctk

from ui.core import service_client as svc
import ui.theme as theme
from ui.core import paths

_GREEN  = "#50fa7b"
_RED    = "#ff5555"
_AMBER  = "#ffb86c"
_GREY   = "#888888"
_BLUE   = "#5294e2"
_CARD   = "#1a1a2e"
_ROW0   = "#1e1e2e"
_ROW1   = "#232340"

_SVC_NAME   = "PolyShieldService"
_SVC_SCRIPT = str(paths.resource_root() / "polyshield_service.py")
_PYTHON_EXE = sys.executable


def _run_elevated(args: list[str], done_cb):
    """Run a list of commands elevated (UAC prompt) via a batch file, then call done_cb()."""
    bat_lines = "\n".join(args) + "\n"
    bat_path = Path(__file__).resolve().parent / "_svc_helper.bat"
    bat_path.write_text(bat_lines, encoding="ascii")
    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"Start-Process -FilePath '{bat_path}' -Verb RunAs -Wait"],
            creationflags=subprocess.CREATE_NO_WINDOW,
            timeout=60,
        )
    except Exception:
        pass
    finally:
        try:
            bat_path.unlink()
        except Exception:
            pass
    done_cb()


class ServiceView(ctk.CTkFrame):
    def __init__(self, master, status_callback, navigate_callback=None, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self._status_cb   = status_callback
        self._navigate_cb = navigate_callback
        self._busy        = False
        self._event_stop  = None   # threading.Event to stop subscribe loop
        self._last_event_id = 0
        self._build()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        # ── Header ──
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=24, pady=(20, 8))
        hdr.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(hdr, text="Realtime Protection Service",
                     font=ctk.CTkFont(size=22, weight="bold")).grid(
            row=0, column=0, sticky="w")
        self._refresh_btn = ctk.CTkButton(
            hdr, text="Refresh", width=90, height=32,
            fg_color="#2a2a4a", hover_color="#3a3a5a",
            font=ctk.CTkFont(size=12),
            command=self.on_show)
        self._refresh_btn.grid(row=0, column=1)

        # ── Status card ──
        status_card = ctk.CTkFrame(self, corner_radius=10, fg_color=_CARD)
        status_card.grid(row=1, column=0, sticky="ew", padx=24, pady=(0, 8))
        status_card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(status_card, text="Service Status",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=_BLUE).grid(
            row=0, column=0, sticky="w", padx=16, pady=(12, 4))

        self._state_lbl = ctk.CTkLabel(
            status_card, text="● Checking…",
            font=ctk.CTkFont(size=13), text_color=_GREY)
        self._state_lbl.grid(row=1, column=0, sticky="w", padx=16, pady=(0, 4))

        self._stats_lbl = ctk.CTkLabel(
            status_card, text="",
            font=ctk.CTkFont(size=11), text_color=theme.color("subtext"))
        self._stats_lbl.grid(row=2, column=0, sticky="w", padx=16, pady=(0, 4))

        # ── Crash banner (hidden until exit-1067 detected) ──
        self._crash_banner = ctk.CTkFrame(
            status_card, fg_color="#3d1a08", corner_radius=6)
        self._crash_banner.grid(row=3, column=0, sticky="ew", padx=12, pady=(0, 10))
        self._crash_banner.grid_columnconfigure(0, weight=1)
        self._crash_banner.grid_remove()

        _bi = ctk.CTkFrame(self._crash_banner, fg_color="transparent")
        _bi.grid(row=0, column=0, sticky="ew", padx=10, pady=8)
        _bi.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            _bi,
            text="⚠  Exit code 1067 — Windows Defender blocked python.exe",
            font=ctk.CTkFont(size=12), text_color=_AMBER, anchor="w",
        ).grid(row=0, column=0, sticky="w")
        self._fix_crash_btn = ctk.CTkButton(
            _bi, text="Fix automatically", width=130, height=28,
            fg_color="#7a3800", hover_color="#5a2800",
            font=ctk.CTkFont(size=11), command=self._fix_crash,
        )
        self._fix_crash_btn.grid(row=0, column=1, padx=(12, 0))

        # ── Control card ──
        ctrl_card = ctk.CTkFrame(self, corner_radius=10, fg_color=_CARD)
        ctrl_card.grid(row=2, column=0, sticky="ew", padx=24, pady=(0, 8))
        ctrl_card.grid_columnconfigure((0, 1), weight=1)

        ctk.CTkLabel(ctrl_card, text="Service Control",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=_BLUE).grid(
            row=0, column=0, columnspan=2, sticky="w", padx=16, pady=(12, 4))

        self._install_btn = ctk.CTkButton(
            ctrl_card, text="Install Service", height=34,
            fg_color=theme.color("accent"), hover_color=theme.color("accent_hover"),
            command=self._install)
        self._install_btn.grid(row=1, column=0, padx=(16, 4), pady=(0, 8), sticky="ew")

        self._uninstall_btn = ctk.CTkButton(
            ctrl_card, text="Uninstall Service", height=34,
            fg_color=theme.color("divider"), hover_color="#8b0000",
            command=self._uninstall)
        self._uninstall_btn.grid(row=1, column=1, padx=(4, 16), pady=(0, 8), sticky="ew")

        self._start_btn = ctk.CTkButton(
            ctrl_card, text="Start Service", height=34,
            fg_color="#2d5a27", hover_color="#1a3a18",
            command=self._start)
        self._start_btn.grid(row=2, column=0, padx=(16, 4), pady=(0, 8), sticky="ew")

        self._stop_btn = ctk.CTkButton(
            ctrl_card, text="Stop Service", height=34,
            fg_color="#8b0000", hover_color="#5c0000",
            command=self._stop)
        self._stop_btn.grid(row=2, column=1, padx=(4, 16), pady=(0, 8), sticky="ew")

        ctk.CTkLabel(ctrl_card,
                     text="All service control actions require a UAC elevation prompt.",
                     font=ctk.CTkFont(size=10), text_color=theme.color("dim")).grid(
            row=3, column=0, columnspan=2, padx=16, pady=(0, 10))

        # ── Events log header ──
        log_hdr = ctk.CTkFrame(self, fg_color="transparent")
        log_hdr.grid(row=3, column=0, sticky="ew", padx=24, pady=(4, 4))
        log_hdr.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(log_hdr, text="Live Threat Events",
                     font=ctk.CTkFont(size=14, weight="bold")).grid(
            row=0, column=0, sticky="w")
        ctk.CTkButton(log_hdr, text="Clear", width=70, height=26,
                      fg_color=theme.color("divider"), hover_color="#4a4a4a",
                      font=ctk.CTkFont(size=11),
                      command=self._clear_events).grid(row=0, column=1)

        # ── Events scroll ──
        self._log_scroll = ctk.CTkScrollableFrame(
            self, corner_radius=8, fg_color=_CARD)
        self._log_scroll.grid(row=4, column=0, sticky="nsew", padx=24, pady=(0, 16))
        self._log_scroll.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(4, weight=1)

        ctk.CTkLabel(self._log_scroll, text="No events yet",
                     text_color=theme.color("dim"), font=ctk.CTkFont(size=12)).grid(
            row=0, column=0, pady=20)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def on_show(self):
        self._update_status_async()

    def _update_status_async(self):
        def _run():
            running = svc.is_service_running()
            if running:
                status = svc.get_status() or {}
            else:
                status = {}
            if self.winfo_exists():
                self.after(0, lambda r=running, s=status: self._apply_status(r, s))

        threading.Thread(target=_run, daemon=True).start()

    def _apply_status(self, running: bool, status: dict):
        if running:
            uptime = status.get("uptime_seconds", 0)
            h, m, s = uptime // 3600, (uptime % 3600) // 60, uptime % 60
            watcher = "Active" if status.get("watcher_running") else "Idle"
            folders = len(status.get("folders_watched", []))
            events  = status.get("events_count", 0)

            self._state_lbl.configure(
                text="● RUNNING", text_color=_GREEN)
            updater = "On" if status.get("intel_updater_running") else "Off"
            self._stats_lbl.configure(
                text=f"Uptime: {h}h {m}m {s}s  |  Watcher: {watcher}  |  "
                     f"Folders: {folders}  |  Events: {events}  |  "
                     f"Intel updater: {updater}")
            self._crash_banner.grid_remove()

            self._install_btn.configure(state="disabled")
            self._uninstall_btn.configure(state="normal")
            self._start_btn.configure(state="disabled")
            self._stop_btn.configure(state="normal")

            # Start event subscription if not already running
            if self._event_stop is None or self._event_stop.is_set():
                self._start_event_stream()

            # Load existing events on first show
            if self._last_event_id == 0:
                events_list = svc.get_events()
                if events_list:
                    self._last_event_id = events_list[-1]["id"]
                    for ev in events_list:
                        self._add_event_row(ev)
        else:
            # Determine if installed (service exists in SCM) or not
            try:
                result = subprocess.run(
                    ["sc", "query", _SVC_NAME],
                    capture_output=True, text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                installed = _SVC_NAME.lower() in result.stdout.lower()
            except Exception:
                installed = False

            if installed:
                self._state_lbl.configure(text="● STOPPED", text_color=_AMBER)
                self._stats_lbl.configure(text="Service is installed but not running.")
                self._install_btn.configure(state="disabled")
                self._uninstall_btn.configure(state="normal")
                self._start_btn.configure(state="normal")
                self._stop_btn.configure(state="disabled")
                self._check_crash_code_async()
            else:
                self._state_lbl.configure(text="● NOT INSTALLED", text_color=_GREY)
                self._stats_lbl.configure(text="Install the service for persistent real-time protection.")
                self._crash_banner.grid_remove()
                self._install_btn.configure(state="normal")
                self._uninstall_btn.configure(state="disabled")
                self._start_btn.configure(state="disabled")
                self._stop_btn.configure(state="disabled")

    # ── Event stream ──────────────────────────────────────────────────────────

    def _start_event_stream(self):
        if self._event_stop and not self._event_stop.is_set():
            return
        self._event_stop = svc.subscribe_events(self._on_service_event)

    def _on_service_event(self, event: dict):
        if self.winfo_exists():
            self.after(0, lambda e=event: self._handle_event(e))

    def _handle_event(self, event: dict):
        ev_type = event.get("event")
        if ev_type == "scan_result":
            ev_id = event.get("id", 0)
            if ev_id > self._last_event_id:
                self._last_event_id = ev_id
                self._add_event_row(event)
        elif ev_type == "watcher_status":
            self._update_status_async()
        elif ev_type == "intel_update":
            self._add_intel_row(event)

    def _add_intel_row(self, event: dict):
        """Render an intelligence refresh in the event feed.

        Per-feed, not a single verdict: a run where MalwareBazaar succeeded and
        ThreatFox returned 403 must not read as a plain success.
        """
        for w in self._log_scroll.winfo_children():
            if isinstance(w, ctk.CTkLabel) and "No events" in str(w.cget("text")):
                w.destroy()

        row_idx = len(self._log_scroll.winfo_children())
        status = str(event.get("status", ""))
        colour = (_GREEN if status in ("updated", "unchanged")
                  else _RED if status == "failed"
                  else _AMBER)
        bg = _ROW0 if row_idx % 2 == 0 else _ROW1

        row_f = ctk.CTkFrame(self._log_scroll, fg_color=bg)
        row_f.grid(row=row_idx, column=0, sticky="ew", pady=1)
        row_f.grid_columnconfigure(0, weight=1)

        summary = event.get("summary") or event.get("error") or "no feeds run"
        ctk.CTkLabel(row_f, text=f"Intelligence — {summary}",
                     anchor="w", font=ctk.CTkFont(size=12),
                     text_color=colour).grid(row=0, column=0, sticky="w",
                                             padx=10, pady=4)
        ctk.CTkLabel(row_f, text=event.get("time", ""),
                     font=ctk.CTkFont(size=11),
                     text_color=theme.color("subtext")).grid(row=0, column=1, padx=8)
        ctk.CTkLabel(row_f, text=status.upper(),
                     font=ctk.CTkFont(size=11),
                     text_color=colour).grid(row=0, column=2, padx=8)

    def _add_event_row(self, entry: dict):
        # Remove placeholder if present
        for w in self._log_scroll.winfo_children():
            if isinstance(w, ctk.CTkLabel) and "No events" in str(w.cget("text")):
                w.destroy()

        row_idx = len(self._log_scroll.winfo_children())
        status = entry.get("status", "pending")
        color = (_RED if "threat" in status
                 else _GREEN if status == "clean"
                 else _AMBER)
        bg = _ROW0 if row_idx % 2 == 0 else _ROW1

        row_f = ctk.CTkFrame(self._log_scroll, fg_color=bg)
        row_f.grid(row=row_idx, column=0, sticky="ew", pady=1)
        row_f.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(row_f, text=entry.get("filename", ""),
                     anchor="w", font=ctk.CTkFont(size=12),
                     text_color=color).grid(row=0, column=0, sticky="w", padx=10, pady=4)
        ctk.CTkLabel(row_f, text=entry.get("time", ""),
                     font=ctk.CTkFont(size=11),
                     text_color=theme.color("subtext")).grid(row=0, column=1, padx=8)
        ctk.CTkLabel(row_f, text=status.upper(),
                     font=ctk.CTkFont(size=11),
                     text_color=color).grid(row=0, column=2, padx=8)

    # ── Control actions ───────────────────────────────────────────────────────

    def _install(self):
        if self._busy:
            return
        self._set_busy(True)
        self._status_cb("Installing service (UAC prompt will appear)…")

        def _run():
            _run_elevated([
                f'"{_PYTHON_EXE}" "{_SVC_SCRIPT}" install',
                f'sc start {_SVC_NAME}',
            ], done_cb=self._after_action)

        threading.Thread(target=_run, daemon=True).start()

    def _uninstall(self):
        if self._busy:
            return
        self._set_busy(True)
        self._status_cb("Uninstalling service (UAC prompt will appear)…")
        if self._event_stop:
            self._event_stop.set()

        def _run():
            _run_elevated([
                f'sc stop {_SVC_NAME}',
                'timeout /t 2 /nobreak > nul',
                f'"{_PYTHON_EXE}" "{_SVC_SCRIPT}" remove',
            ], done_cb=self._after_action)

        threading.Thread(target=_run, daemon=True).start()

    def _start(self):
        if self._busy:
            return
        self._set_busy(True)
        self._status_cb("Starting service (UAC prompt will appear)…")

        def _run():
            _run_elevated(
                [f'sc start {_SVC_NAME}'],
                done_cb=self._after_action,
            )

        threading.Thread(target=_run, daemon=True).start()

    def _stop(self):
        if self._busy:
            return
        self._set_busy(True)
        self._status_cb("Stopping service (UAC prompt will appear)…")
        if self._event_stop:
            self._event_stop.set()

        def _run():
            _run_elevated(
                [
                    f'sc stop {_SVC_NAME}',
                    'timeout /t 2 /nobreak > nul',
                ],
                done_cb=self._after_action,
            )

        threading.Thread(target=_run, daemon=True).start()

    def _clear_events(self):
        def _run():
            svc.send_command("CLEAR_EVENTS")
            if self.winfo_exists():
                self.after(0, self._clear_event_rows)

        threading.Thread(target=_run, daemon=True).start()

    def _clear_event_rows(self):
        for w in self._log_scroll.winfo_children():
            w.destroy()
        self._last_event_id = 0
        ctk.CTkLabel(self._log_scroll, text="No events yet",
                     text_color=theme.color("dim"), font=ctk.CTkFont(size=12)).grid(
            row=0, column=0, pady=20)

    def _after_action(self):
        import time; time.sleep(1)
        self._set_busy(False)
        if self.winfo_exists():
            self.after(0, self._update_status_async)
            self.after(0, lambda: self._status_cb(""))

    def _check_crash_code_async(self):
        """Check sc queryex for WIN32_EXIT_CODE 1067 (Defender blocked python.exe)."""
        def _run():
            try:
                result = subprocess.run(
                    ["sc", "queryex", _SVC_NAME],
                    capture_output=True, text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                crashed = "1067" in result.stdout
            except Exception:
                crashed = False
            if self.winfo_exists():
                self.after(0, lambda c=crashed: self._show_crash_banner(c))
        threading.Thread(target=_run, daemon=True).start()

    def _show_crash_banner(self, show: bool):
        if show:
            self._crash_banner.grid()
        else:
            self._crash_banner.grid_remove()

    def _fix_crash(self):
        """Run fix_service_crash.bat elevated — adds Defender exclusions and restarts service."""
        if self._busy:
            return
        self._set_busy(True)
        self._status_cb("Applying Defender fix (UAC prompt will appear)…")
        bat = paths.resource_root() / "scripts" / "service" / "fix_service_crash.bat"

        def _run():
            try:
                subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     f"Start-Process -FilePath '{bat}' -Verb RunAs -Wait"],
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    timeout=180,
                )
            except Exception:
                pass
            self._after_action()

        threading.Thread(target=_run, daemon=True).start()

    def _set_busy(self, busy: bool):
        self._busy = busy
        state = "disabled" if busy else "normal"
        for btn in (self._install_btn, self._uninstall_btn,
                    self._start_btn, self._stop_btn, self._refresh_btn,
                    self._fix_crash_btn):
            if self.winfo_exists():
                self.after(0, lambda b=btn, s=state: b.configure(state=s))
