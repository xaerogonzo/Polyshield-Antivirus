"""
TkSession — build a CustomTkinter view on a hidden desktop and photograph it.

Usage:

    with TkSession(out_dir=Path("artifacts/ui")) as s:
        view = s.mount(DashboardView, status_callback=lambda m: None,
                       navigate_callback=lambda k: None)
        s.shot("dashboard")
        view._build_intel_card(some_stale_posture)
        s.shot("dashboard_stale")

Nothing appears on any screen, nothing takes focus, and the mouse is never
touched. Widgets are driven through Tk (`invoke()`, direct handler calls), not
by synthesising input — which is both faster and immune to whatever else the
machine is doing.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

from .capture import PW_RENDERFULLCONTENT, capture_window
from .desktop import DesktopUnavailable, hidden_desktop


@dataclass
class Shot:
    name: str
    path: Path
    size: tuple[int, int]
    scene: str = ""


class TkSession:
    """A Tk root living on a hidden desktop, plus a shot recorder."""

    def __init__(self, out_dir: Path | str = Path("artifacts/ui"),
                 size: tuple[int, int] = (1200, 760),
                 settle_cycles: int = 20,
                 project_root: Path | None = None):
        self.out_dir = Path(out_dir)
        self.size = size
        self.settle_cycles = settle_cycles
        self.shots: list[Shot] = []
        self._desktop_cm = None
        self._root = None
        self._mounted = []
        self._warned_clamp = False
        # Set by the CLI before each scene; initialised here so a session used
        # directly (as the docstring above shows) still works.
        self.current_scene = ""
        # Set by the CLI before each scene; initialised here so a session used
        # directly (as the docstring above shows) still works.
        self._project_root = project_root or Path(__file__).resolve().parents[2]

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def __enter__(self) -> "TkSession":
        # Order matters: bind the desktop before anything creates a window.
        self._desktop_cm = hidden_desktop()
        self._desktop_cm.__enter__()

        for path in (self._project_root, self._project_root / "src"):
            if str(path) not in sys.path:
                sys.path.insert(0, str(path))

        import customtkinter as ctk

        # Reproduce the real entry point's GLOBAL setup before building
        # anything. ui/app.py calls ctk.set_appearance_mode("dark") and
        # set_default_color_theme("blue") at *module* level, so importing only
        # the view modules leaves CustomTkinter in its default light appearance
        # — which renders every label that does not set an explicit text_color
        # as dark-on-dark. The shots come out looking confidently wrong, and
        # nothing in the harness would flag it. Import the entry point instead
        # of second-guessing what it configures.
        import ui.app  # noqa: F401  (imported for its module-level ctk setup)

        import ui.theme as theme
        from ui.core import settings as cfg

        self._ctk = ctk
        self._root = ctk.CTk()
        # Load tkdnd into this interpreter. ScanView registers a drop target
        # during _build(), and that Tcl package is loaded by the root, not by
        # the tkinterdnd2 import — without it the view raises TclError before
        # it finishes building and the scene fails outright.
        #
        # _require() rather than swapping the root for TkinterDnD.Tk: that
        # class is exactly tkinter.Tk plus this call, and the DnD methods are
        # already mixed into every widget at import. Swapping the class costs
        # CustomTkinter's themed root background and shifts every existing
        # golden by ~24%.
        try:
            from tkinterdnd2 import TkinterDnD
            TkinterDnD._require(self._root)
        except Exception:
            pass    # drag-and-drop unavailable; every other scene still works
        self._root.geometry(f"{self.size[0]}x{self.size[1]}+0+0")
        theme.init(cfg)
        theme.init_colors(cfg)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        return self

    def __exit__(self, *exc):
        if self._root is not None:
            self._cancel_pending()
            try:
                self._root.destroy()
            except Exception:
                pass
            self._root = None
        if self._desktop_cm is not None:
            self._desktop_cm.__exit__(*exc)
            self._desktop_cm = None
        return False

    def _cancel_pending(self) -> None:
        """Drop queued `after` callbacks before teardown.

        CustomTkinter schedules DPI and redraw callbacks; if they fire after
        destroy, Tcl prints 'invalid command name ...update' noise that looks
        like a failure but is not.
        """
        try:
            for job in self._root.tk.call("after", "info"):
                try:
                    self._root.after_cancel(job)
                except Exception:
                    pass
        except Exception:
            pass

    # ── Building ──────────────────────────────────────────────────────────────

    @property
    def root(self):
        if self._root is None:
            raise RuntimeError("TkSession must be used as a context manager")
        return self._root

    def mount(self, view_cls, **kwargs):
        """Instantiate a view, fill the window with it, and return it."""
        for existing in self._mounted:
            try:
                existing.pack_forget()
            except Exception:
                pass
        view = view_cls(self.root, **kwargs)
        view.pack(fill="both", expand=True)
        self._mounted.append(view)
        self.settle()
        return view

    def settle(self, cycles: int | None = None) -> None:
        """Let Tk finish layout and painting before a capture."""
        self.root.update_idletasks()
        for _ in range(cycles if cycles is not None else self.settle_cycles):
            self.root.update()

    # ── Capturing ─────────────────────────────────────────────────────────────

    def shot(self, name: str) -> Shot:
        self.settle()
        image = capture_window(self.root.winfo_id(), PW_RENDERFULLCONTENT)

        # A hidden desktop inherits the session's screen metrics, so a window
        # larger than the desktop is silently clamped — the shot then shows a
        # cropped layout rather than the one that was asked for. Measured on a
        # GitHub windows-latest runner: 1200x760 requested, 1028x749 delivered.
        # Say so once, because it is also why golden images do not travel.
        if image.size != self.size and not self._warned_clamp:
            self._warned_clamp = True
            print(f"uishot: window clamped to {image.size[0]}x{image.size[1]} "
                  f"(requested {self.size[0]}x{self.size[1]}) — the desktop is "
                  f"smaller than the window; shots will not match goldens "
                  f"recorded elsewhere", file=sys.stderr)

        path = self.out_dir / f"{name}.png"
        path.parent.mkdir(parents=True, exist_ok=True)
        image.save(path)
        shot = Shot(name=name, path=path, size=image.size,
                    scene=self.current_scene)
        self.shots.append(shot)
        return shot


def is_supported() -> tuple[bool, str]:
    """Whether hidden-desktop capture can run here."""
    if sys.platform != "win32":
        return False, "hidden-desktop capture is Windows-only"
    try:
        with hidden_desktop("UIShotProbe"):
            pass
    except DesktopUnavailable as exc:
        return False, str(exc)
    return True, ""
