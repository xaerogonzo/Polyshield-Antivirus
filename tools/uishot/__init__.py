"""uishot — photograph a GUI without it ever being on screen.

See README.md in this directory for the measurements behind the design.
"""
from .capture import capture_window, compare, write_diff
from .desktop import DesktopUnavailable, hidden_desktop
from .session import Shot, TkSession, is_supported

__all__ = ["capture_window", "compare", "write_diff", "hidden_desktop",
           "DesktopUnavailable", "TkSession", "Shot", "is_supported"]
