import base64
import json
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path

import customtkinter as ctk

from ui.core import service_client as svc
import ui.theme as theme
from ui.core import integration
from ui.core import paths
from ui.core import settings as cfg

_GREEN  = "#50fa7b"
_RED    = "#ff5555"
_AMBER  = "#ffb86c"
_GREY   = "#888888"
_BLUE   = "#5294e2"
_CARD   = "#1a1a2e"
_ROW0   = "#1e1e2e"
_ROW1   = "#232340"

_SVC_NAME = "PolyShieldService"

# How long to wait for the elevated helper.  60s was not enough: the sequence is
# a service registration, a start, and Defender scanning python.exe in the
# middle of it.  Matches _fix_crash, which already learned this.
_ELEVATED_TIMEOUT_S = 180

# `sc` exit codes that mean "already in the state this step wanted".
_SC_ABSENT          = 1060   # the specified service does not exist
_SC_NOT_STARTED     = 1062   # the service has not been started
_SC_ALREADY_RUNNING = 1056

# Defender blocking python.exe as the SCM memory-maps it. Its own banner.
_EXIT_DEFENDER_BLOCKED = 1067

# What each `integration.service_startup_commands()` entry is called in the UI.
# `sc.exe`, never bare `sc`.  In PowerShell `sc` is an ALIAS FOR Set-Content,
# so `& 'sc' 'config' ...` resolves to a cmdlet that will happily accept the
# arguments and do something entirely unrelated.  register_service.ps1 already
# writes `& sc.exe` for this reason.
_SC_EXE = "sc.exe"

_SC_STEP_LABELS = {
    "config":  "set the start type",
    "failure": "set the recovery actions",
}


def _step(label, argv, ok_codes=(0,), delay_after=0.0):
    """One elevated command, and what counts as success for it."""
    return {"label": label, "argv": [str(a) for a in argv],
            "ok": tuple(ok_codes), "delay": float(delay_after)}


def _ps_lit(value) -> str:
    """A PowerShell single-quoted literal.  Doubling is the only escape needed."""
    return "'" + str(value).replace("'", "''") + "'"


def _build_elevated_script(steps, result_path) -> str:
    """The script the elevated shell runs.

    Stops at the first step whose exit code is outside that step's allow-list,
    and records which one.  Without this, an `install` that succeeded followed
    by a `config` that failed would still run `start`, and the UI would report
    the result of the last command as though it were the result of the
    sequence.
    """
    lines = ["$ErrorActionPreference = 'Continue'", "$failed = $null"]
    for st in steps:
        exe, rest = st["argv"][0], st["argv"][1:]
        call = "& " + _ps_lit(exe)
        if rest:
            call += " " + " ".join(_ps_lit(a) for a in rest)
        ok_list = ",".join(str(c) for c in st["ok"])
        lines += [
            "if (-not $failed) {",
            # A sentinel, not 0.  If the executable cannot be found, PowerShell
            # raises into the error stream (captured by 2>&1) and NEVER TOUCHES
            # $LASTEXITCODE -- so seeding it with 0 would report a command that
            # never ran as a step that succeeded.
            "  $global:LASTEXITCODE = -1",
            "  $o = (" + call + " 2>&1 | Out-String)",
            "  $c = $LASTEXITCODE",
            "  if (@(" + ok_list + ") -notcontains $c) {",
            "    $failed = @{ step = " + _ps_lit(st["label"])
            + "; code = $c; detail = $o }",
            "  }",
        ]
        if st["delay"]:
            lines.append("  Start-Sleep -Seconds " + str(st["delay"]))
        lines.append("}")
    lines += [
        "if ($failed) { $payload = @{ ok = $false; step = $failed.step; "
        "code = $failed.code; detail = $failed.detail } }",
        "else { $payload = @{ ok = $true; step = ''; code = 0; detail = '' } }",
        "$payload | ConvertTo-Json -Compress | Set-Content -Path "
        + _ps_lit(str(result_path)) + " -Encoding UTF8",
    ]
    return "\n".join(lines)


def _run_elevated(steps, done_cb):
    r"""Run `steps` elevated, stopping at the first failure.

    **The script is never written to disk.**  Until v1.17 this function wrote a
    ``.bat`` next to ``__file__`` and asked an elevated shell to execute it,
    which had two problems.  The lesser is that the install directory is
    read-only in a packaged build.  The greater one is the obvious fix: moving
    that file to ``%TEMP%`` produces a *user-writable file that a privileged
    process then executes*, and the window between writing it and elevating is
    exactly the boundary elevation exists to cross.  A random filename does not
    close a window whose path is handed to the elevating call.

    So the script travels as ``-EncodedCommand`` (base64 UTF-16LE) and lives
    only on the elevated process's command line.  There is no artefact to swap.

    The result comes back through a JSON file, which is a different class of
    thing: it is *data*, never executed, and the worst a tampered copy can do is
    put a wrong sentence in the status bar.

    Calls ``done_cb(ok: bool, detail: str)``.  The old signature took no
    arguments and fired identically whether the sequence succeeded, failed, or
    was never elevated at all because the prompt was dismissed -- so the UI
    re-probed, saw that nothing had changed, and said nothing.
    """
    tmpdir = Path(tempfile.mkdtemp(prefix="polyshield-svc-"))
    result_path = tmpdir / "result.json"
    try:
        script = _build_elevated_script(steps, result_path)
        b64 = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        inner = ("@('-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',"
                 + _ps_lit(b64) + ")")
        launch = ("Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait "
                  "-WindowStyle Hidden -ArgumentList " + inner)
        try:
            subprocess.run(
                ["powershell", "-NoProfile", "-Command", launch],
                capture_output=True, text=True,
                # DEVNULL, not inherited: this view runs under pythonw, which
                # has no console and therefore no valid standard handles.
                stdin=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW,
                timeout=_ELEVATED_TIMEOUT_S,
            )
        except subprocess.TimeoutExpired:
            done_cb(False,
                    f"the elevated step did not finish in {_ELEVATED_TIMEOUT_S}s")
            return
        except Exception as exc:
            done_cb(False, f"could not elevate: {exc}")
            return

        if not result_path.exists():
            # Nothing wrote a result: the prompt was declined, or the elevated
            # shell never started.  Both are failures, and neither is silent.
            done_cb(False, "the elevated step reported nothing "
                           "(the prompt may have been declined)")
            return
        try:
            res = json.loads(result_path.read_text(encoding="utf-8-sig"))
        except Exception as exc:
            done_cb(False, f"unreadable result from the elevated step: {exc}")
            return

        if res.get("ok"):
            done_cb(True, "")
        else:
            first = (res.get("detail") or "").strip().splitlines()
            done_cb(False,
                    f"{res.get('step')} failed (exit {res.get('code')})"
                    + (f": {first[0]}" if first else ""))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


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

        # ── Start type ──
        # Its own line, beside the state and never folded into it. They are two
        # separate facts: `auto` + stopped is a service that is meant to be
        # running and is not, which is a different problem from one registered
        # `manual` -- and for a year this page showed neither, which is how a
        # DEMAND_START registration sat here unnoticed reporting exit code 1077.
        starttype_row = ctk.CTkFrame(status_card, fg_color="transparent")
        starttype_row.grid(row=3, column=0, sticky="ew", padx=16, pady=(0, 6))
        starttype_row.grid_columnconfigure(0, weight=1)

        self._starttype_lbl = ctk.CTkLabel(
            starttype_row, text="", anchor="w",
            font=ctk.CTkFont(size=11), text_color=theme.color("subtext"))
        self._starttype_lbl.grid(row=0, column=0, sticky="w")

        self._fix_start_btn = ctk.CTkButton(
            starttype_row, text="Set to Automatic", width=140, height=26,
            fg_color="#7a3800", hover_color="#5a2800",
            font=ctk.CTkFont(size=11), command=self._fix_start_type)
        self._fix_start_btn.grid(row=0, column=1, padx=(12, 0))
        self._fix_start_btn.grid_remove()

        # ── Crash banner (hidden until exit-1067 detected) ──
        self._crash_banner = ctk.CTkFrame(
            status_card, fg_color="#3d1a08", corner_radius=6)
        self._crash_banner.grid(row=4, column=0, sticky="ew", padx=12, pady=(0, 10))
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
            # max_age=0: this page's whole job is reporting service state, so
            # it takes the 0.5s probe rather than a cached answer that could be
            # two seconds behind the badge it is about to draw.
            running = svc.is_service_running(max_age=0)
            if running:
                status = svc.get_status() or {}
            else:
                status = {}
            # Registration facts come from the SCM's own record rather than from
            # parsing `sc` output: sc's field labels are localised, and this page
            # has to be right on a machine that is not in English.
            state = integration.service_state()
            if self.winfo_exists():
                self.after(0, lambda r=running, s=status, t=state:
                           self._apply_status(r, s, t))

        threading.Thread(target=_run, daemon=True).start()

    _START_TYPE_TEXT = {
        "auto":         ("Start type: Automatic", _GREEN, False),
        "delayed-auto": ("Start type: Automatic (delayed start)", _GREEN, False),
        "manual":       ("Start type: Manual — will not start at boot", _AMBER, True),
        "disabled":     ("Start type: Disabled — the SCM will refuse to start it",
                         _RED, True),
        "boot":         ("Start type: Boot", _GREEN, False),
        "system":       ("Start type: System", _GREEN, False),
    }

    def _apply_start_type(self, state: dict):
        if not state.get("present"):
            self._starttype_lbl.configure(text="")
            self._fix_start_btn.grid_remove()
            return
        text, color, offer_fix = self._START_TYPE_TEXT.get(
            state.get("start_type"), ("Start type: unknown", _GREY, False))
        self._starttype_lbl.configure(text=text, text_color=color)
        if offer_fix and not self._busy:
            self._fix_start_btn.grid()
        else:
            self._fix_start_btn.grid_remove()

    def _apply_status(self, running: bool, status: dict, state: dict | None = None):
        state = state or {}
        self._apply_start_type(state)
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
            if state.get("present"):
                self._state_lbl.configure(text="● STOPPED", text_color=_AMBER)
                # 1077 is its own diagnosis: registered, and the SCM has never
                # been asked to launch it since this boot. That is what a
                # manual-start registration looks like from the outside, and
                # saying so is more use than "installed but not running".
                if state.get("exit_code") == integration.SERVICE_NEVER_STARTED:
                    self._stats_lbl.configure(
                        text="Installed, and has not started since this boot.")
                else:
                    self._stats_lbl.configure(
                        text="Service is installed but not running.")
                self._install_btn.configure(state="disabled")
                self._uninstall_btn.configure(state="normal")
                self._start_btn.configure(state="normal")
                self._stop_btn.configure(state="disabled")
                self._show_crash_banner(
                    state.get("exit_code") == _EXIT_DEFENDER_BLOCKED)
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
        """Register the service the way the shell installers already do.

        Four steps, not two.  `polyshield_service.py install` now injects
        `--startup auto` itself, but `sc config` is still needed on the upgrade
        path -- an existing DEMAND_START registration survives a reinstall --
        and the failure actions have never been set from here at all.  The
        commands come from `integration.service_startup_commands()` so that this
        button, `setup_service.bat` and `register_service.ps1` cannot drift into
        three different ideas of how the service should be configured.
        """
        if self._busy:
            return
        try:
            install_argv = paths.service_install_argv("install")
        except paths.StagedRuntimeMissing as exc:
            self._status_cb(f"Cannot install: {exc}")
            return

        self._set_busy(True)
        self._status_cb("Installing service (UAC prompt will appear)…")

        delayed = bool(cfg.get("service_start_delayed"))
        steps = [_step("register the service", install_argv)]
        steps += [_step(_SC_STEP_LABELS.get(c[0], c[0]), [_SC_EXE, *c])
                  for c in integration.service_startup_commands(delayed)]
        steps.append(_step("start the service", [_SC_EXE, "start", _SVC_NAME],
                           (0, _SC_ALREADY_RUNNING)))

        def _run():
            _run_elevated(steps, done_cb=self._after_action)

        threading.Thread(target=_run, daemon=True).start()

    def _uninstall(self):
        if self._busy:
            return
        self._set_busy(True)
        self._status_cb("Uninstalling service (UAC prompt will appear)…")
        if self._event_stop:
            self._event_stop.set()

        try:
            remove_argv = paths.service_install_argv("remove")
        except paths.StagedRuntimeMissing as exc:
            self._set_busy(False)
            self._status_cb(f"Cannot uninstall: {exc}")
            return

        steps = [
            # `sc stop` RETURNS BEFORE THE SERVICE HAS STOPPED, hence the delay;
            # 1062/1060 mean it was already stopped or already gone, which is
            # the state this step wanted.
            _step("stop the service", [_SC_EXE, "stop", _SVC_NAME],
                  (0, _SC_NOT_STARTED, _SC_ABSENT), delay_after=2),
            _step("remove the registration", remove_argv),
        ]

        def _run():
            _run_elevated(steps, done_cb=self._after_action)

        threading.Thread(target=_run, daemon=True).start()

    def _start(self):
        if self._busy:
            return
        self._set_busy(True)
        self._status_cb("Starting service (UAC prompt will appear)…")

        def _run():
            _run_elevated(
                [_step("start the service", [_SC_EXE, "start", _SVC_NAME],
                       (0, _SC_ALREADY_RUNNING))],
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
                [_step("stop the service", [_SC_EXE, "stop", _SVC_NAME],
                       (0, _SC_NOT_STARTED), delay_after=2)],
                done_cb=self._after_action,
            )

        threading.Thread(target=_run, daemon=True).start()

    def _fix_start_type(self):
        """Repair a registration that will not start at boot.

        Reachable from the start-type row, which is the only place in the app
        that has ever said out loud that a service can be installed and still
        never run.
        """
        if self._busy:
            return
        self._set_busy(True)
        self._status_cb("Setting the service to start automatically…")
        delayed = bool(cfg.get("service_start_delayed"))
        steps = [_step(_SC_STEP_LABELS.get(c[0], c[0]), [_SC_EXE, *c])
                 for c in integration.service_startup_commands(delayed)]
        steps.append(_step("start the service", [_SC_EXE, "start", _SVC_NAME],
                           (0, _SC_ALREADY_RUNNING)))

        def _run():
            _run_elevated(steps, done_cb=self._after_action)

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

    def _after_action(self, ok: bool = True, detail: str = ""):
        import time; time.sleep(1)
        # Install, uninstall, start and stop all land here, and all four change
        # the answer every other screen caches. Drop it so the next caller
        # anywhere in the app probes for real rather than reporting the state
        # from before the button was pressed.
        svc.invalidate_service_probe()
        self._set_busy(False)
        if self.winfo_exists():
            self.after(0, self._update_status_async)
            # A failure keeps its sentence.  The old version cleared the status
            # bar either way, so a declined elevation prompt and a completed
            # install were indistinguishable from the outside.
            msg = "" if ok else f"Failed: {detail}"
            self.after(0, lambda m=msg: self._status_cb(m))

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
                    self._fix_crash_btn, self._fix_start_btn):
            if self.winfo_exists():
                self.after(0, lambda b=btn, s=state: b.configure(state=s))
