"""PolyShield's capture session.

The generic machinery moved to ``polybedrock.ui.uishot.session``. What stays
here is the part that was never generic: **which entry point to import, and what
that entry point's startup does to the root**.

Both hooks exist because of a bug worth not repeating. ``ui/app.py`` calls
``ctk.set_appearance_mode("dark")`` at *module* level, so importing only the
view modules leaves CustomTkinter in its default light appearance and every
label without an explicit ``text_color`` renders dark-on-dark. The first
Settings capture looked like a real contrast bug in the application; it was the
harness. The session imports the real entry point rather than guessing.
"""
from __future__ import annotations

from pathlib import Path

from polybedrock.ui.uishot.session import Shot, is_supported  # noqa: F401
from polybedrock.ui.uishot.session import TkSession as _TkSession

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _prepare_root(root) -> None:
    """Everything PolyShield's startup does beyond creating the window."""
    # Load tkdnd into this interpreter. ScanView registers a drop target during
    # _build(), and that Tcl package is loaded by the root, not by the
    # tkinterdnd2 import — without it the view raises TclError before it
    # finishes building and the scene fails outright.
    #
    # _require() rather than swapping the root for TkinterDnD.Tk: that class is
    # exactly tkinter.Tk plus this call, and the DnD methods are already mixed
    # into every widget at import. Swapping the class costs CustomTkinter's
    # themed root background and shifts every existing golden by ~24%.
    try:
        from tkinterdnd2 import TkinterDnD
        TkinterDnD._require(root)
    except Exception:
        pass    # drag-and-drop unavailable; every other scene still works

    import ui.theme as theme
    from ui.core import settings as cfg
    theme.init(cfg)
    theme.init_colors(cfg)


class TkSession(_TkSession):
    """The shared session, wired to PolyShield's entry point."""

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("project_root", _PROJECT_ROOT)
        kwargs.setdefault("entry_module", "ui.app")
        kwargs.setdefault("on_root", _prepare_root)
        super().__init__(*args, **kwargs)
