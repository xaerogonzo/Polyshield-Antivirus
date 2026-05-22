"""
PolyShield — Process Monitor view.

Shows a live feed of process creation events detected by the WMI monitor.
Threats are highlighted in red.  Clean processes are shown in grey only when
"Show clean processes" is enabled (off by default — most users only want to
see threats).

Start/Stop behaviour
--------------------
• If the Windows service is running: the service owns the monitor (started at
  service boot).  The view shows status only; Start/Stop are advisory.
• If the service is NOT running: the monitor runs in-process (stops when the
  UI closes).  Start/Stop buttons control it directly.

Auto-terminate
--------------
When "Auto-terminate detected threats" is checked, the UI process calls
psutil.Process.kill() on the threat PID + its children.  LocalService (the
service account) has limited kill rights, so termination is always attempted
from the UI process for best results.
"""

import threading
from datetime import datetime

import customtkinter as ctk

from ui.core import settings as cfg
import ui.theme as theme

_MAX_ROWS = 200   # max event rows kept in the live log (each event ≈ 2 lines)


class ProcessView(ctk.CTkFrame):
    def __init__(self, parent, status_callback, **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)
        self._status_cb = status_callback
        self._monitor   = None    # ProcessMonitor instance (in-process mode)
        self._row_count = 0
        self._build()

    # ── Build UI ───────────────────────────────────────────────────────────────

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # ── Header card ──
        header = ctk.CTkFrame(self, fg_color=theme.color("card"), corner_radius=10)
        header.grid(row=0, column=0, sticky="ew", padx=16, pady=(16, 6))
        header.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            header, text="Process Monitor",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=theme.color("text"),
        ).grid(row=0, column=0, padx=14, pady=12, sticky="w")

        # Running / Stopped badge
        self._badge = ctk.CTkLabel(
            header, text="● Stopped",
            font=ctk.CTkFont(size=12),
            text_color=theme.color("subtext"),
        )
        self._badge.grid(row=0, column=1, padx=8, pady=12, sticky="w")

        # Start / Stop buttons
        btn_frame = ctk.CTkFrame(header, fg_color="transparent")
        btn_frame.grid(row=0, column=2, padx=14, pady=8)

        self._start_btn = ctk.CTkButton(
            btn_frame, text="Start", width=80,
            fg_color=theme.color("accent"), hover_color="#174f7a",
            command=self._on_start,
        )
        self._start_btn.pack(side="left", padx=(0, 6))

        self._stop_btn = ctk.CTkButton(
            btn_frame, text="Stop", width=80,
            fg_color="#5a2d2d", hover_color="#3d1e1e",
            state="disabled",
            command=self._on_stop,
        )
        self._stop_btn.pack(side="left")

        # ── Toggles row ──
        toggles = ctk.CTkFrame(self, fg_color="transparent")
        toggles.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 6))

        self._auto_terminate_var = ctk.BooleanVar(
            value=bool(cfg.get("process_monitor_auto_terminate"))
        )
        ctk.CTkCheckBox(
            toggles,
            text="Auto-terminate detected threats",
            variable=self._auto_terminate_var,
            font=ctk.CTkFont(size=12),
            command=self._on_auto_terminate_toggle,
        ).pack(side="left", padx=(0, 24))

        self._show_clean_var = ctk.BooleanVar(
            value=bool(cfg.get("process_monitor_show_clean"))
        )
        ctk.CTkCheckBox(
            toggles,
            text="Show clean processes",
            variable=self._show_clean_var,
            font=ctk.CTkFont(size=12),
            command=self._on_show_clean_toggle,
        ).pack(side="left")

        ctk.CTkButton(
            toggles, text="Clear Log", width=90,
            fg_color="transparent", border_width=1,
            border_color="#444466", text_color="#aaaacc",
            hover_color=theme.color("divider"),
            command=self._clear_log,
        ).pack(side="right", padx=4)

        # ── Event log ──
        log_frame = ctk.CTkFrame(self, fg_color="#0e0e1a", corner_radius=8)
        log_frame.grid(row=2, column=0, sticky="nsew", padx=16, pady=(0, 16))
        log_frame.grid_columnconfigure(0, weight=1)
        log_frame.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            log_frame,
            text="  Process Events  (live — last 200)",
            font=ctk.CTkFont(size=11),
            text_color=theme.color("dim"),
            anchor="w",
        ).grid(row=0, column=0, sticky="ew", padx=4, pady=(4, 0))

        self._log = ctk.CTkTextbox(
            log_frame,
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color="#0e0e1a",
            text_color="#aaaacc",
            wrap="none",
            state="disabled",
        )
        self._log.grid(row=1, column=0, sticky="nsew", padx=4, pady=(2, 4))

        # Colour tags
        self._log._textbox.tag_configure("threat", foreground="#ff6b6b")
        self._log._textbox.tag_configure("clean",  foreground=theme.color("dim"))
        self._log._textbox.tag_configure("info",   foreground=theme.color("accent"))

    # ── View lifecycle ─────────────────────────────────────────────────────────

    def on_show(self):
        """Called every time this view becomes active — sync badge + buttons."""
        self._refresh_state()

    # ── Button callbacks ───────────────────────────────────────────────────────

    def _on_start(self):
        try:
            from ui.core import service_client as _svc
            if _svc.is_service_running():
                # Service owns the monitor; it auto-starts with the service.
                self._status_cb(
                    "Process monitor is managed by the Windows service — "
                    "started automatically with the service."
                )
                self._set_badge_running(True)
                return
        except Exception:
            pass
        self._start_inprocess()

    def _on_stop(self):
        try:
            from ui.core import service_client as _svc
            if _svc.is_service_running():
                self._status_cb(
                    "Stop the Windows service to disable process monitoring."
                )
                return
        except Exception:
            pass
        self._stop_inprocess()

    def _on_auto_terminate_toggle(self):
        cfg.set_value(
            "process_monitor_auto_terminate",
            bool(self._auto_terminate_var.get()),
        )

    def _on_show_clean_toggle(self):
        cfg.set_value(
            "process_monitor_show_clean",
            bool(self._show_clean_var.get()),
        )

    # ── In-process monitor management ─────────────────────────────────────────

    def _start_inprocess(self):
        if self._monitor and self._monitor.is_running():
            return
        try:
            from ui.core.process_monitor import ProcessMonitor
            poll = int(cfg.get("process_monitor_poll_interval") or 1)
            self._monitor = ProcessMonitor(
                alert_callback=self._on_alert,
                poll_interval=poll,
            )
            self._monitor.start()
            self._set_badge_running(True)
            self._status_cb("Process monitor started.")
            self._log_info("─── Monitor started ───")
        except Exception as e:
            self._status_cb(f"Process monitor error: {e}")

    def _stop_inprocess(self):
        if self._monitor:
            self._monitor.stop()
            self._monitor = None
        self._set_badge_running(False)
        self._status_cb("Process monitor stopped.")
        self._log_info("─── Monitor stopped ───")

    # Public helper so app.py can inject an externally-created monitor instance
    def attach_monitor(self, monitor) -> None:
        """Attach a ProcessMonitor that was started by the caller (e.g. App.__init__)."""
        self._monitor = monitor
        self._refresh_state()

    # ── Alert / clean callbacks (called from WMI thread) ──────────────────────

    def _on_alert(
        self, pid: int, name: str, exe_path: str,
        reason: str, alert_level: str,
    ) -> None:
        """Receives threat alerts from ProcessMonitor (background thread)."""
        if not self.winfo_exists():
            return

        auto_terminate = bool(cfg.get("process_monitor_auto_terminate"))
        terminated = False
        if auto_terminate:
            terminated = _try_terminate(pid)

        ts      = datetime.now().strftime("%H:%M:%S")
        action  = "  [KILLED]" if terminated else ""
        line    = (
            f"  {ts}  THREAT  {name:<28s}  {exe_path}\n"
            f"           reason: {reason}{action}\n"
        )
        self.after(0, lambda l=line: self._append_log(l, "threat"))
        self.after(
            0,
            lambda: self._status_cb(f"⚠ Process threat: {name} — {reason}"),
        )

    def _on_clean_process(self, pid: int, name: str, exe_path: str) -> None:
        """Called when show_clean is on and a clean process is detected."""
        if not self.winfo_exists():
            return
        if not bool(cfg.get("process_monitor_show_clean")):
            return
        ts   = datetime.now().strftime("%H:%M:%S")
        line = f"  {ts}  CLEAN   {name:<28s}  {exe_path}\n"
        self.after(0, lambda l=line: self._append_log(l, "clean"))

    # ── Log helpers ────────────────────────────────────────────────────────────

    def _append_log(self, text: str, tag: str = "") -> None:
        self._log.configure(state="normal")
        if tag:
            self._log._textbox.insert("end", text, tag)
        else:
            self._log._textbox.insert("end", text)
        self._log.configure(state="disabled")
        self._log._textbox.see("end")
        self._row_count += 1
        # Trim when we exceed _MAX_ROWS
        if self._row_count > _MAX_ROWS:
            self._log.configure(state="normal")
            self._log._textbox.delete(
                "1.0", f"{self._row_count - _MAX_ROWS + 1}.0"
            )
            self._log.configure(state="disabled")
            self._row_count = _MAX_ROWS

    def _log_info(self, text: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self._append_log(f"  {ts}  {text}\n", "info")

    def _clear_log(self) -> None:
        self._log.configure(state="normal")
        self._log._textbox.delete("1.0", "end")
        self._log.configure(state="disabled")
        self._row_count = 0

    # ── Badge / button state ───────────────────────────────────────────────────

    def _set_badge_running(self, running: bool) -> None:
        if running:
            self._badge.configure(text="● Active", text_color="#44cc88")
            self._start_btn.configure(state="disabled")
            self._stop_btn.configure(state="normal")
        else:
            self._badge.configure(text="● Stopped", text_color=theme.color("subtext"))
            self._start_btn.configure(state="normal")
            self._stop_btn.configure(state="disabled")

    def _refresh_state(self) -> None:
        """Sync badge + buttons with the actual monitor state."""
        try:
            from ui.core import service_client as _svc
            if _svc.is_service_running():
                self._set_badge_running(True)
                return
        except Exception:
            pass
        running = bool(self._monitor and self._monitor.is_running())
        self._set_badge_running(running)


# ── Module-level terminate helper (used by service too) ───────────────────────

def _try_terminate(pid: int) -> bool:
    """
    Kill process tree for *pid*.

    Returns True if the root process was killed (children are best-effort).
    Silently ignores NoSuchProcess (already exited) and AccessDenied (PPL /
    SYSTEM process — document as known limitation).
    """
    try:
        import psutil
        proc     = psutil.Process(pid)
        children = proc.children(recursive=True)
        for child in children:
            try:
                child.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        proc.kill()
        psutil.wait_procs([proc] + children, timeout=2)
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False
    except Exception:
        return False
