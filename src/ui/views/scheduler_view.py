from tkinter import filedialog
import customtkinter as ctk
from ui.core import scheduler as sch
from ui.core import settings as cfg
import ui.theme as theme


class SchedulerView(ctk.CTkFrame):
    def __init__(self, master, status_callback, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self._status_cb = status_callback
        self._build()
        self.refresh_task_info()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(self, text="Scheduled Scans",
                     font=ctk.CTkFont(size=22, weight="bold")).grid(
            row=0, column=0, sticky="w", padx=24, pady=(20, 8))

        # ── Current task status card ──
        self._task_card = ctk.CTkFrame(self, corner_radius=10, fg_color=theme.color("card"))
        self._task_card.grid(row=1, column=0, sticky="ew", padx=24, pady=(0, 8))
        self._task_card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(self._task_card, text="Active Schedule",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=theme.color("accent")).grid(
            row=0, column=0, sticky="w", padx=16, pady=(12, 8))

        info_row = ctk.CTkFrame(self._task_card, fg_color="transparent")
        info_row.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 12))
        info_row.grid_columnconfigure((0, 1, 2), weight=1)

        self._task_status_lbl = ctk.CTkLabel(
            info_row, text="No task scheduled",
            font=ctk.CTkFont(size=16, weight="bold"), text_color=theme.color("subtext"))
        self._task_status_lbl.grid(row=0, column=0, sticky="w")

        self._next_run_lbl = ctk.CTkLabel(
            info_row, text="", font=ctk.CTkFont(size=12), text_color=theme.color("subtext"))
        self._next_run_lbl.grid(row=0, column=1)

        task_btns = ctk.CTkFrame(info_row, fg_color="transparent")
        task_btns.grid(row=0, column=2, sticky="e")

        self._run_now_btn = ctk.CTkButton(
            task_btns, text="Run Now", width=90, height=30,
            fg_color=theme.color("accent"), hover_color=theme.color("accent_hover"),
            state="disabled", command=self._run_now)
        self._run_now_btn.grid(row=0, column=0, padx=(0, 8))

        self._delete_btn = ctk.CTkButton(
            task_btns, text="Delete", width=80, height=30,
            fg_color="#8b0000", hover_color="#5c0000",
            state="disabled", command=self._delete_task)
        self._delete_btn.grid(row=0, column=1)

        # ── Create / update schedule ──
        form_card = ctk.CTkFrame(self, corner_radius=10, fg_color=theme.color("card"))
        form_card.grid(row=2, column=0, sticky="ew", padx=24, pady=(0, 8))
        form_card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(form_card, text="Configure Schedule",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=theme.color("accent")).grid(
            row=0, column=0, columnspan=3, sticky="w", padx=16, pady=(12, 8))

        # Scan path
        ctk.CTkLabel(form_card, text="Scan path:",
                     font=ctk.CTkFont(size=12)).grid(
            row=1, column=0, sticky="w", padx=16, pady=(0, 8))
        path_row = ctk.CTkFrame(form_card, fg_color="transparent")
        path_row.grid(row=1, column=1, sticky="ew", pady=(0, 8))
        path_row.grid_columnconfigure(0, weight=1)

        saved_path = cfg.get("scheduler_path") or ""
        self._path_var = ctk.StringVar(value=saved_path)
        self._path_entry = ctk.CTkEntry(path_row, textvariable=self._path_var,
                                         placeholder_text="e.g. C:\\Users\\you\\Downloads")
        self._path_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        ctk.CTkButton(path_row, text="Browse", width=80, height=28,
                      fg_color=theme.color("divider"), hover_color="#4a4a4a",
                      command=self._browse_path).grid(row=0, column=1)

        # Frequency
        ctk.CTkLabel(form_card, text="Frequency:",
                     font=ctk.CTkFont(size=12)).grid(
            row=2, column=0, sticky="w", padx=16, pady=(0, 8))
        saved_freq = cfg.get("scheduler_frequency") or "DAILY"
        self._freq_var = ctk.StringVar(value=saved_freq)
        ctk.CTkOptionMenu(form_card, values=["DAILY", "WEEKLY"],
                          variable=self._freq_var, width=140).grid(
            row=2, column=1, sticky="w", pady=(0, 8))

        # Time
        ctk.CTkLabel(form_card, text="Start time (HH:MM):",
                     font=ctk.CTkFont(size=12)).grid(
            row=3, column=0, sticky="w", padx=16, pady=(0, 12))
        saved_time = cfg.get("scheduler_time") or "02:00"
        self._time_var = ctk.StringVar(value=saved_time)
        ctk.CTkEntry(form_card, textvariable=self._time_var,
                     width=100, placeholder_text="02:00").grid(
            row=3, column=1, sticky="w", pady=(0, 12))

        # Save button
        self._save_btn = ctk.CTkButton(
            form_card, text="Save Schedule", width=160, height=36,
            fg_color=theme.color("accent"), hover_color=theme.color("accent_hover"),
            command=self._save_schedule)
        self._save_btn.grid(row=4, column=0, columnspan=3,
                             padx=16, pady=(0, 14))

        self._feedback_lbl = ctk.CTkLabel(
            form_card, text="", font=ctk.CTkFont(size=12))
        self._feedback_lbl.grid(row=5, column=0, columnspan=3,
                                 padx=16, pady=(0, 12))

        # ── Info note ──
        note = ctk.CTkFrame(self, corner_radius=8, fg_color=theme.color("card2"))
        note.grid(row=3, column=0, sticky="ew", padx=24, pady=(0, 16))
        ctk.CTkLabel(
            note,
            text=(
                "The scheduled task runs in the background via Windows Task Scheduler. "
                "Results appear in the History view automatically after each run. "
                "The task runs: scheduled_scan.py → k2.exe → saves JSON report to logs/"
            ),
            font=ctk.CTkFont(size=11),
            text_color=theme.color("dim"),
            wraplength=700,
            justify="left",
        ).grid(row=0, column=0, padx=16, pady=12, sticky="w")

    # app.py lists "scheduler" in _AUTO_REFRESH, which calls refresh() on every
    # navigation to this page.  The work has always lived in
    # refresh_task_info() — also called from __init__ and after create/delete —
    # so navigating here raised AttributeError into Tk's error handler and the
    # task status silently stayed as it was drawn at build time.
    def refresh(self):
        self.refresh_task_info()

    def refresh_task_info(self):
        info = sch.get_task_info()
        if info.get("exists"):
            self._task_status_lbl.configure(
                text=info.get("status", "Scheduled"), text_color="#50fa7b")
            self._next_run_lbl.configure(
                text=f"Next run: {info.get('next_run', '—')}")
            self._run_now_btn.configure(state="normal")
            self._delete_btn.configure(state="normal")
        else:
            self._task_status_lbl.configure(
                text="No task scheduled", text_color=theme.color("subtext"))
            self._next_run_lbl.configure(text="")
            self._run_now_btn.configure(state="disabled")
            self._delete_btn.configure(state="disabled")

    def _browse_path(self):
        path = filedialog.askdirectory(title="Select folder to scan on schedule")
        if path:
            self._path_var.set(path)

    def _save_schedule(self):
        path = self._path_var.get().strip()
        freq = self._freq_var.get()
        time_str = self._time_var.get().strip()

        if not path:
            self._feedback_lbl.configure(text="Please enter a scan path.",
                                          text_color="#ff5555")
            return
        if len(time_str) != 5 or time_str[2] != ":":
            self._feedback_lbl.configure(
                text="Time must be in HH:MM format (e.g. 02:00).",
                text_color="#ff5555")
            return

        # Save to settings
        cfg.set_value("scheduler_path", path)
        cfg.set_value("scheduler_frequency", freq)
        cfg.set_value("scheduler_time", time_str)

        self._save_btn.configure(state="disabled", text="Saving…")
        self._feedback_lbl.configure(text="Creating task…", text_color="#ffb86c")

        import threading
        def _create():
            ok, msg = sch.create_task(path, freq, time_str)
            def _update():
                self._save_btn.configure(state="normal", text="Save Schedule")
                if ok:
                    self._feedback_lbl.configure(
                        text="Task created successfully.", text_color="#50fa7b")
                    self._status_cb("Scheduled task created")
                else:
                    self._feedback_lbl.configure(
                        text=f"Failed: {msg[:80]}", text_color="#ff5555")
                    self._status_cb("Failed to create scheduled task")
                self.refresh_task_info()
            self.after(0, _update)
        threading.Thread(target=_create, daemon=True).start()

    def _delete_task(self):
        ok, msg = sch.delete_task()
        color = "#50fa7b" if ok else "#ff5555"
        self._feedback_lbl.configure(
            text="Task deleted." if ok else f"Error: {msg[:80]}",
            text_color=color)
        self._status_cb("Scheduled task deleted" if ok else "Delete failed")
        self.refresh_task_info()

    def _run_now(self):
        ok, msg = sch.run_now()
        color = "#50fa7b" if ok else "#ff5555"
        self._feedback_lbl.configure(
            text="Task triggered — check History shortly." if ok else f"Error: {msg[:80]}",
            text_color=color)
        self._status_cb("Scheduled task triggered" if ok else "Run failed")
