import sys
import os
import ctypes
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]   # project root (data dirs, service, config)
_SRC  = _ROOT / "src"                          # src/ dir (Python package imports)
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

try:
    from tkinterdnd2 import TkinterDnD
    _USE_DND = True
except ImportError:
    _USE_DND = False

try:
    import pystray
    from PIL import Image, ImageDraw
    _USE_TRAY = True
except ImportError:
    _USE_TRAY = False

import customtkinter as ctk

from ui.views.dashboard_view   import DashboardView
from ui.views.scan_view        import ScanView
from ui.views.defender_view    import DefenderView
from ui.views.watcher_view     import WatcherView
from ui.views.scheduler_view   import SchedulerView
from ui.views.virustotal_view  import VirusTotalView
from ui.views.update_view      import UpdateView
from ui.views.quarantine_view  import QuarantineView
from ui.views.history_view     import HistoryView
from ui.views.settings_view    import SettingsView
from ui.views.guardian_view    import GuardianView
from ui.views.behavioral_view  import BehavioralView
from ui.views.winsec_view      import WinSecView
from ui.views.service_view     import ServiceView
from ui.views.help_view        import HelpView
from ui.views.network_view     import NetworkView
from ui.views.process_view     import ProcessView
from ui.views.display_view     import DisplayView
from ui.core                   import watcher as wtch
from ui.core                   import settings as cfg
import ui.theme as theme

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

_SIDEBAR_WIDTH = 210

# Nav items: (label, key) — use None label for a section divider
_NAV_ITEMS = [
    ("  Dashboard",   "dashboard"),
    ("  Scan",        "scan"),
    (None, None),
    ("  Defender",    "defender"),
    ("  Win Security","winsec"),
    ("  Network",     "network"),
    ("  Watcher",     "watcher"),
    ("  Processes",   "process"),
    ("  Service",     "service"),
    ("  Scheduler",   "scheduler"),
    (None, None),
    ("  Guardian AI", "guardian"),
    ("  VirusTotal",  "virustotal"),
    ("  Behavioral",      "behavioral"),
    ("  Update",      "update"),
    (None, None),
    ("  Quarantine",  "quarantine"),
    ("  History",     "history"),
    (None, None),
    ("  Settings",    "settings"),
    ("  Display",     "display"),
    ("  Help",        "help"),
]

# Views that have an on_show() hook
_HAS_ON_SHOW = {"dashboard", "watcher", "process", "service", "virustotal", "guardian", "behavioral", "update", "winsec", "network", "display"}
# Views that refresh() on navigate
_AUTO_REFRESH = {"quarantine", "history", "scheduler", "defender"}

# ── Single-instance enforcement ───────────────────────────────────────────────
# The handle is kept at module level so it stays open (and the mutex held)
# for the entire process lifetime.
_MUTEX_HANDLE = None

def _acquire_instance_lock() -> bool:
    """Try to create a named Windows mutex.

    Returns True  — this is the first instance, proceed normally.
    Returns False — another instance is already running; the caller should
                    focus that window and exit.
    Silently returns True on non-Windows or if ctypes is unavailable.
    """
    global _MUTEX_HANDLE
    try:
        ERROR_ALREADY_EXISTS = 183
        handle = ctypes.windll.kernel32.CreateMutexW(
            None, False, "PolyShield_UI_SingleInstance_v1")
        if ctypes.windll.kernel32.GetLastError() == ERROR_ALREADY_EXISTS:
            # Another instance owns the mutex — try to surface its window
            hwnd = ctypes.windll.user32.FindWindowW(None, "PolyShield")
            if hwnd:
                # SW_RESTORE (9) un-minimises / un-withdraws the existing window
                ctypes.windll.user32.ShowWindow(hwnd, 9)
                ctypes.windll.user32.SetForegroundWindow(hwnd)
            return False
        _MUTEX_HANDLE = handle   # keep handle alive for process lifetime
        return True
    except Exception:
        return True   # non-Windows or ctypes unavailable — allow launch


class App(ctk.CTk if not _USE_DND else TkinterDnD.Tk):  # type: ignore[misc]
    def __init__(self, initial_scan_path: str | None = None):
        super().__init__()
        # ── Theme + appearance (must be after super().__init__() — Tk root required) ──
        theme.init(cfg)
        theme.init_colors(cfg)
        scale = float(cfg.get("display_widget_scale") or 1.0)
        if abs(scale - 1.0) > 0.01:
            ctk.set_widget_scaling(scale)
        self.title("PolyShield")
        self.geometry("1200x760")
        self.minsize(960, 620)
        self._active_view: str | None = None
        self._nav_buttons: dict[str, ctk.CTkButton] = {}
        self._views: dict[str, ctk.CTkFrame] = {}          # built on first show
        self._view_factories: dict = {}                    # filled by _build()
        self._tray_icon: "pystray.Icon | None" = None
        self._bg_label = None   # CTkLabel for background image (created on first use)
        self._bg_ctk_img = None
        self._build()
        self._apply_bg_image()   # apply stored background image if any

        # Wire in-memory intelligence consumers to the post-update hooks so an
        # Update Center run refreshes them without restarting the app.
        try:
            from ui.core.intel_hooks import register_intel_consumers
            register_intel_consumers()
        except Exception:
            pass   # non-fatal: updates still work, they just need a restart

        # Fallback scheduler for installs with no Windows Service.  Deferred so
        # it never delays first paint.
        self.after(5000, self._maybe_auto_update_intel)

        if initial_scan_path and Path(initial_scan_path).exists():
            self._navigate("scan")
            self.get_view("scan").load_paths([initial_scan_path])
        else:
            self._navigate("dashboard")

        # Auto-start watcher if it was enabled last session and the service isn't owning it
        if cfg.get("watcher_enabled") and cfg.get("watcher_folders"):
            from ui.core import service_client as _svc
            from ui.views.watcher_view import _on_new_file_detected
            if not _svc.is_service_running():
                wtch.start(_on_new_file_detected)

        # Auto-start process monitor in-process if service is not running
        self._process_monitor = None
        try:
            from ui.core import service_client as _svc2
            if not _svc2.is_service_running():
                from ui.core.process_monitor import ProcessMonitor
                self._process_monitor = ProcessMonitor(
                    alert_callback=self._on_process_threat,
                    poll_interval=int(cfg.get("process_monitor_poll_interval") or 1),
                )
                self._process_monitor.start()
                # ProcessView is built eagerly here, not lazily on first
                # navigation, because its _on_alert() is where
                # process_monitor_auto_terminate actually kills a flagged
                # process.  A view that does not exist cannot terminate
                # anything, so lazy-building this one would silently disable
                # auto-terminate for anyone who never opens the Processes
                # page.  It costs ~38 Tk windows and no USER handles.
                self.get_view("process").attach_monitor(self._process_monitor)
        except Exception:
            pass   # WMI / pywin32 unavailable — graceful degradation

        # Set up system tray
        if _USE_TRAY:
            self._tray_icon = self._build_tray_icon()
            self._tray_icon.run_detached()
            # Wire threat notifications from watcher to tray
            from ui.views.watcher_view import set_notify_callback
            set_notify_callback(self._notify_threat)

        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # Intercept the minimize button so it routes to tray (not taskbar)
        # when minimize_to_tray is enabled.
        self._quitting = False
        self.bind("<Unmap>", self._on_unmap)

    def _build(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # ── Sidebar ──
        sidebar = ctk.CTkScrollableFrame(
            self, width=_SIDEBAR_WIDTH, corner_radius=0, fg_color="#141422")
        sidebar.grid(row=0, column=0, sticky="nsew")
        self._sidebar = sidebar   # kept for live theme refresh
        sidebar.grid_columnconfigure(0, weight=1)

        # Logo
        logo = ctk.CTkFrame(sidebar, fg_color="transparent", height=70)
        logo.grid(row=0, column=0, sticky="ew", pady=(8, 4))
        logo.grid_columnconfigure(0, weight=1)
        self._logo_lbl = ctk.CTkLabel(logo, text="PolyShield",
                                       font=ctk.CTkFont(size=20, weight="bold"),
                                       text_color=theme.color("accent"))
        self._logo_lbl.grid(row=0, column=0, pady=(14, 0))
        ctk.CTkLabel(logo, text="Security Suite",
                     font=ctk.CTkFont(size=10),
                     text_color="#555577").grid(row=1, column=0)

        ctk.CTkFrame(sidebar, height=1, fg_color="#2a2a3a").grid(
            row=1, column=0, sticky="ew", padx=12, pady=(8, 4))

        nav_row = 2
        for label, key in _NAV_ITEMS:
            if label is None:
                # Divider
                ctk.CTkFrame(sidebar, height=1, fg_color="#2a2a3a").grid(
                    row=nav_row, column=0, sticky="ew", padx=20, pady=4)
            else:
                btn = ctk.CTkButton(
                    sidebar,
                    text=label,
                    anchor="w",
                    font=ctk.CTkFont(size=13),
                    fg_color="transparent",
                    hover_color="#2a2a3a",
                    text_color="#cdd6f4",
                    corner_radius=8,
                    height=38,
                    command=lambda k=key: self._navigate(k),
                )
                btn.grid(row=nav_row, column=0, sticky="ew", padx=8, pady=1)
                self._nav_buttons[key] = btn
            nav_row += 1

        # ── Content area ──
        self._content = ctk.CTkFrame(self, corner_radius=0, fg_color="#12121e")
        self._content.grid(row=0, column=1, sticky="nsew")
        self._content.grid_columnconfigure(0, weight=1)
        self._content.grid_rowconfigure(0, weight=1)
        self._content.grid_rowconfigure(1, minsize=28)

        # Status bar
        status_bar = ctk.CTkFrame(self._content, height=28, corner_radius=0,
                                  fg_color="#0e0e1a")
        status_bar.grid(row=1, column=0, sticky="ew")
        status_bar.grid_propagate(False)
        self._status_lbl = ctk.CTkLabel(status_bar, text="Ready",
                                         font=ctk.CTkFont(size=11),
                                         text_color="#555577")
        self._status_lbl.pack(side="left", padx=12)

        # -- View factories: each page is built the first time it is shown --
        #
        # Constructing all 18 up front cost 4,996 Tk windows, 3,715 USER
        # handles (37% of the 10,000 per-process quota) and 107.7 MB of
        # private bytes before the user had clicked anything, for 17 pages
        # that were not on screen.  Building on first show: 279 / 307 /
        # 39.0 MB.  That is what tipped a memory-constrained
        # Windows Sandbox into "Tk_GetPixmap: Error from CreateDIBSection /
        # Not enough memory resources": Tk allocates an offscreen DIB for
        # every canvas redraw, and there was nothing left to allocate from.
        # Measured with tools/uishot's hidden desktop; see docs/ARCHITECTURE.md
        # "Views are built on first show".
        #
        # Zero-argument factories rather than a list of classes: the
        # constructors take different keyword arguments, and a lambda keeps
        # that difference in one place instead of in a dispatch chain.
        self._view_factories = {
            "dashboard":  lambda: DashboardView(self._content,
                                                status_callback=self._set_status,
                                                navigate_callback=self._navigate),
            "scan":       lambda: ScanView(self._content, self._set_status,
                                           navigate_callback=self._navigate),
            "defender":   lambda: DefenderView(self._content, self._set_status),
            "winsec":     lambda: WinSecView(self._content, self._set_status),
            "network":    lambda: NetworkView(self._content, self._set_status),
            "watcher":    lambda: WatcherView(self._content, self._set_status,
                                              navigate_callback=self._navigate),
            "process":    lambda: ProcessView(self._content, self._set_status),
            "service":    lambda: ServiceView(self._content, self._set_status,
                                              navigate_callback=self._navigate),
            "scheduler":  lambda: SchedulerView(self._content, self._set_status),
            "guardian":   lambda: GuardianView(self._content, self._set_status),
            "virustotal": lambda: VirusTotalView(self._content, self._set_status),
            "behavioral": lambda: BehavioralView(self._content, self._set_status,
                                                 navigate_callback=self._navigate),
            "update":     lambda: UpdateView(self._content, self._set_status),
            "quarantine": lambda: QuarantineView(self._content, self._set_status),
            "history":    lambda: HistoryView(self._content, self._set_status),
            "settings":   lambda: SettingsView(self._content),
            "display":    lambda: DisplayView(self._content,
                                              status_callback=self._set_status,
                                              app_ref=self),
            "help":       lambda: HelpView(self._content, self._set_status),
        }

    def get_view(self, key: str):
        """Return the view for *key*, constructing it on first request.

        Anything that reaches into a page it did not navigate to must come
        through here.  ``self._views[key]`` is only populated for pages that
        have already been shown, so indexing it directly turns "hand this file
        to the VirusTotal page" into a silent no-op the first time.
        """
        view = self._views.get(key)
        if view is not None and view.winfo_exists():
            return view
        view = self._view_factories[key]()
        view.grid(row=0, column=0, sticky="nsew")
        view.grid_remove()
        self._views[key] = view
        return view

    def _navigate(self, key: str):
        if self._active_view:
            self._views[self._active_view].grid_remove()
            self._nav_buttons[self._active_view].configure(
                fg_color="transparent", text_color="#cdd6f4")

        view = self.get_view(key)
        self._active_view = key
        view.grid()
        self._nav_buttons[key].configure(fg_color=theme.color("nav_active"), text_color="#ffffff")

        if key in _HAS_ON_SHOW:
            view.on_show()
        elif key in _AUTO_REFRESH:
            view.refresh()

    def _apply_bg_image(self) -> None:
        """Composite and display a background image behind all content widgets.

        If no image is configured, resets the window background to the palette
        app_bg colour.  Safe to call from any thread via self.after(0, ...).
        """
        from pathlib import Path as _Path

        path    = cfg.get("display_bg_image") or ""
        opacity = float(cfg.get("display_bg_opacity") or 0.15)
        blur    = int(cfg.get("display_bg_blur") or 0)

        if not path or not _Path(path).exists():
            # No image — hide any existing overlay
            if self._bg_label is not None:
                try:
                    self._bg_label.place_forget()
                except Exception:
                    pass
            return

        def _run():
            try:
                from PIL import Image, ImageFilter
                img = Image.open(path).convert("RGBA")
                w = self.winfo_width()  or 1200
                h = self.winfo_height() or 760
                img = img.resize((w, h), Image.LANCZOS)
                if blur > 0:
                    img = img.filter(ImageFilter.GaussianBlur(radius=blur))
                bg_hex = theme.color("app_bg")
                bg_rgb = tuple(int(bg_hex[i:i+2], 16) for i in (1, 3, 5))
                bg = Image.new("RGBA", img.size, (*bg_rgb, 255))
                composited = Image.blend(bg, img, alpha=opacity)
                ctk_img = ctk.CTkImage(
                    light_image=composited, dark_image=composited, size=(w, h)
                )
                if self.winfo_exists():
                    self.after(0, lambda img_ref=ctk_img: self._show_bg(img_ref))
            except Exception:
                pass   # PIL not available or image unreadable — silently skip

        import threading as _th
        _th.Thread(target=_run, daemon=True).start()

    def _show_bg(self, ctk_img) -> None:
        """Place (or update) the background label behind all other widgets."""
        self._bg_ctk_img = ctk_img   # keep reference alive
        if self._bg_label is None or not self._bg_label.winfo_exists():
            self._bg_label = ctk.CTkLabel(self, image=ctk_img, text="")
            self._bg_label.place(x=0, y=0, relwidth=1, relheight=1)
            self._bg_label.lower()   # send behind sidebar + content area
        else:
            self._bg_label.configure(image=ctk_img)
            # Re-place in case it was hidden via place_forget()
            self._bg_label.place(x=0, y=0, relwidth=1, relheight=1)
            self._bg_label.lower()

    def refresh_nav_theme(self) -> None:
        """Update sidebar, content area, logo, active nav button, every
        view's themed widgets, and all CTk default-styled widgets to the
        current theme palette.  Called from DisplayView after any preset
        or accent change."""
        try:
            self._sidebar.configure(fg_color=theme.color("sidebar"))
        except Exception:
            pass
        try:
            self._content.configure(fg_color=theme.color("content_bg"))
        except Exception:
            pass
        try:
            self._logo_lbl.configure(text_color=theme.color("accent"))
        except Exception:
            pass
        if self._active_view and self._active_view in self._nav_buttons:
            self._nav_buttons[self._active_view].configure(
                fg_color=theme.color("nav_active"))
        # Cascade to every view that implements _refresh_theme()
        for view in self._views.values():
            fn = getattr(view, "_refresh_theme", None)
            if callable(fn):
                try:
                    fn()
                except Exception:
                    pass
        # Walk the widget tree to re-pull defaults from ctk.ThemeManager.theme
        # (which theme.apply_ctk_palette() just patched).
        self._refresh_ctk_widgets()

    def _refresh_ctk_widgets(self) -> None:
        """Walk the widget tree and force CTk default-styled widgets to
        re-pull their colours from ``ctk.ThemeManager.theme`` (which was
        just patched by ``theme.apply_ctk_palette()``).

        CTkButton and CTkCheckBox are deliberately excluded — many of our
        buttons carry semantic colour meaning (red Stop, yellow Pause).
        Anything that needs to follow the accent should use the explicit
        ``theme.register(self._themed, btn, fg_color="accent")`` pattern."""
        try:
            import customtkinter as ctk
            tm = ctk.ThemeManager.theme
        except Exception:
            return
        refresh_map = {
            "CTkSegmentedButton": ["selected_color", "selected_hover_color"],
            "CTkOptionMenu":      ["button_color", "button_hover_color"],
            "CTkComboBox":        ["button_color", "button_hover_color"],
            "CTkProgressBar":     ["progress_color"],
            "CTkSlider":          ["button_color", "button_hover_color"],
            "CTkSwitch":          ["progress_color"],
            "CTkScrollbar":       ["button_color", "button_hover_color"],
        }

        def _walk(w):
            cls = w.__class__.__name__
            if cls in refresh_map:
                try:
                    w.configure(**{k: tm[cls][k] for k in refresh_map[cls]})
                except Exception:
                    pass
            try:
                for child in w.winfo_children():
                    _walk(child)
            except Exception:
                pass

        _walk(self)

    def _maybe_auto_update_intel(self):
        """Refresh stale intelligence at launch when no service is running.

        The service is the designated writer whenever it exists, so this only
        covers source installs that never registered it.  The ownership test is
        repeated inside intel_updater immediately before any write — checking
        here as well just avoids spawning a thread we know will stand down.
        """
        from ui.core import settings as _cfg
        if not (_cfg.get("intel_auto_update") and _cfg.get("intel_update_on_launch")):
            return

        import threading as _th

        def _work():
            try:
                from ui.core import service_client as _svc
                if _svc.is_service_running():
                    return                      # the service owns updates
                from ui.core import intel_updater as _iu
                if not _iu.is_anything_due():
                    return
                result = _iu.run_updates(owner="ui")
                status = result.get("status", "")
                if status in ("skipped", "already_running"):
                    return
                failed = [n for n, i in (result.get("feeds") or {}).items()
                          if i.get("status") == "failed"]
                msg = (f"Intelligence update — failed: {', '.join(failed)}"
                       if failed else f"Intelligence update: {status}")
                if self.winfo_exists():
                    self.after(0, lambda m=msg: self._set_status(m))
            except Exception:
                pass    # never let a background refresh break the UI

        _th.Thread(target=_work, daemon=True, name="IntelLaunchUpdate").start()

    def _set_status(self, text: str):
        self.after(0, lambda t=text: self._status_lbl.configure(text=t))

    # ── System tray ───────────────────────────────────────────────────────────

    def _build_tray_icon(self) -> "pystray.Icon":
        """Build a shield-shaped tray icon programmatically (no image file needed)."""
        img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        # Outer shield shape
        d.polygon([32, 4, 60, 16, 60, 38, 32, 60, 4, 38, 4, 16], fill="#1f6aa5")
        # Inner highlight
        d.polygon([32, 12, 52, 22, 52, 36, 32, 52, 12, 36, 12, 22], fill="#144e7a")

        menu = pystray.Menu(
            pystray.MenuItem("Open PolyShield", self._restore_from_tray, default=True),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                "Real-time Protection",
                self._toggle_realtime_from_tray,
                checked=lambda item: bool(cfg.get("watcher_enabled")),
            ),
            pystray.MenuItem("Quick Scan Now", self._quick_scan_from_tray),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit", self._quit_from_tray),
        )
        return pystray.Icon("PolyShield", img, "PolyShield Security Suite", menu)

    def _restore_from_tray(self, icon=None, item=None):
        """Called from pystray thread — must marshal UI calls to main thread."""
        self.after(0, self._do_restore)

    def _do_restore(self):
        self.deiconify()
        self.lift()
        self.focus_force()

    def _toggle_realtime_from_tray(self, icon, item):
        """Toggle watcher on/off from tray right-click menu."""
        def _do():
            from ui.views.watcher_view import _on_new_file_detected
            if wtch.is_running():
                wtch.stop()
                cfg.set_value("watcher_enabled", False)
            else:
                wtch.start(_on_new_file_detected)
                cfg.set_value("watcher_enabled", True)
            # Refresh watcher view if it's currently visible
            if self._active_view == "watcher":
                self._views["watcher"].on_show()
        self.after(0, _do)

    def _quick_scan_from_tray(self, icon, item):
        """Navigate to Scan view from tray menu."""
        self.after(0, lambda: self._navigate("scan"))

    def _quit_from_tray(self, icon=None, item=None):
        """Fully exit the app — called from tray Quit or when minimize_to_tray is off."""
        def _do():
            self._quitting = True   # stop <Unmap> from re-entering withdraw logic
            if self._tray_icon:
                self._tray_icon.stop()
            wtch.stop()
            # Stop in-process process monitor (no-op if service owns it)
            if self._process_monitor is not None:
                try:
                    self._process_monitor.stop()
                except Exception:
                    pass
            self.destroy()
        self.after(0, _do)

    def _on_process_threat(
        self, pid: int, name: str, exe_path: str,
        reason: str, alert_level: str,
    ) -> None:
        """
        Alert callback from the in-process ProcessMonitor (background thread).
        Forwards to the ProcessView for display, and optionally shows a tray
        notification.
        """
        # Forward to the ProcessView (it will auto-terminate if that setting is on)
        try:
            pv = self._views.get("process")
            if pv and pv.winfo_exists():
                pv._on_alert(pid, name, exe_path, reason, alert_level)
        except Exception:
            pass

        # Tray balloon
        self._notify_threat(name, reason)

    def _notify_threat(self, filename: str, threat: str):
        """Show a tray balloon when the watcher detects a threat. Thread-safe."""
        if self._tray_icon and _USE_TRAY:
            try:
                self._tray_icon.notify(
                    f"Threat detected: {threat}",
                    f"File: {filename}",
                )
            except Exception:
                pass  # Notifications may be suppressed by focus assist / OS settings

    def _on_close(self):
        if cfg.get("minimize_to_tray") and self._tray_icon:
            self.withdraw()  # Hide window but keep process + tray icon alive
        else:
            self._quit_from_tray()

    def _on_unmap(self, event):
        """Fire when a widget is hidden.  We only care about the top-level itself
        being iconified (minimise button clicked).  Schedule a deferred check so
        the window state has been updated before we act."""
        if event.widget is not self or self._quitting:
            return
        if cfg.get("minimize_to_tray") and _USE_TRAY and self._tray_icon:
            # Small delay lets Tkinter finish the iconify state transition
            self.after(50, self._maybe_withdraw_to_tray)

    def _maybe_withdraw_to_tray(self):
        """Called ~50 ms after <Unmap> on the top-level.
        If the window ended up iconified (minimised), pull it fully off-screen
        and off the taskbar via withdraw() so only the tray icon remains."""
        try:
            if self.state() == "iconic":
                self.withdraw()
        except Exception:
            pass


def main():
    # ── Single-instance guard ──────────────────────────────────────────────────
    # Diagnostics, before the single-instance lock: these answer and exit, and
    # taking the lock would make them fail whenever the app is already open.
    #
    # They live on the GUI entry point rather than in tools/ because this is
    # the only entry point that survives the Nuitka build -- a standalone probe
    # compiled from tools/ faults during interpreter start-up (see
    # docs/ARCHITECTURE.md). Asking the shipped binary about itself is also the
    # more honest question: it reports what the *product* resolved, not what a
    # differently-built probe would have.
    if "--paths" in sys.argv[1:] or "--engines" in sys.argv[1:]:
        import json

        from ui.core import paths as _paths

        out = {
            "frozen":        _paths.is_frozen(),
            "distribution":  _paths.is_distribution(),
            "executable":    str(_paths.running_executable()),
            "app_root":      str(_paths.app_root()),
            "resource_root": str(_paths.resource_root()),
        }
        if "--engines" in sys.argv[1:]:
            from tools.engine_probe import CHECKS

            out["engines"] = {}
            for _name, _fn in CHECKS.items():
                try:
                    out["engines"][_name] = _fn()
                except Exception as _exc:      # one engine must not hide the rest
                    out["engines"][_name] = {
                        "available": None, "detected": None,
                        "detail": f"probe raised: {_exc!r}"}
        print(json.dumps(out, indent=2))
        # An engine that claims to be present and then detects nothing is the
        # one combination that must never ship.
        _liars = [n for n, r in out.get("engines", {}).items()
                  if r.get("available") and r.get("detected") is False]
        if _liars:
            print("FAIL: available but did not detect: " + ", ".join(_liars),
                  file=sys.stderr)
            sys.exit(1)
        sys.exit(0)

    # Uninstall / rollback, before the single-instance lock for the same reason
    # the diagnostics are: this has to work while the app is open, and an
    # uninstaller that silently exits 0 because a window was up would leave the
    # service and the Explorer verb behind.
    #
    # Lives on the GUI entry point because that is the binary a distribution
    # actually has -- the Inno uninstaller calls PolyShield.exe --unregister
    # before it deletes the files. Requires elevation for the service step,
    # which an uninstaller already has.
    if "--register-context-menu" in sys.argv[1:]:
        # The installer asks the app to write its own Explorer verb rather than
        # writing the keys itself: the command string is built by
        # paths.app_launch_argv(), and a second implementation in an .iss file
        # is a second thing to keep correct when the launch target changes.
        # Per-user (HKCU), so it needs no elevation and lands in the profile of
        # whoever is installing.
        from ui.core import shell_ext as _shell_ext

        ok, msg = _shell_ext.register()
        print(msg)
        sys.exit(0 if ok else 1)

    if "--unregister" in sys.argv[1:]:
        import json

        from ui.core import integration as _integration

        report = _integration.unregister_all(log=lambda line: print(line))
        print(json.dumps(report, indent=2))
        # Also written down. An uninstaller runs this hidden, and "the service
        # is still registered afterwards" cannot otherwise be told apart from
        # "this never ran" -- which are different bugs with different fixes.
        try:
            from ui.core import paths as _p

            _dest = _p.logs_dir()
            _dest.mkdir(parents=True, exist_ok=True)
            (_dest / "unregister.json").write_text(
                json.dumps(report, indent=2), encoding="utf-8")
        except Exception:
            pass            # diagnostics must never fail the uninstall
        sys.exit(0 if report["ok"] else 1)

    # If another PolyShield window is already running, focus it and exit immediately.
    if not _acquire_instance_lock():
        sys.exit(0)

    scan_path = None
    args = sys.argv[1:]
    if "--scan" in args:
        idx = args.index("--scan")
        if idx + 1 < len(args):
            scan_path = args[idx + 1]
    app = App(initial_scan_path=scan_path)
    app.mainloop()


if __name__ == "__main__":
    main()
