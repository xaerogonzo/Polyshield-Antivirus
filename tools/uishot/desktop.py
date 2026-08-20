"""
Hidden Win32 desktop.

Why a whole desktop, rather than just moving the window off-screen: Tk will not
paint a window positioned outside the virtual screen. Measured on this project,
a window parked at (-3200, -3200) captured its *text* but none of its frame
backgrounds or button fills — 95.58% of pixels differed from the real render,
including the page background colour. That is a materially wrong screenshot,
not a slightly worse one.

A separate desktop gives the window a full coordinate space in which it is
genuinely visible, so Tk paints normally. Nothing ever calls SwitchDesktop, so
it is never shown to anyone. Captured through this path the image is
byte-identical to the on-screen render (0 of 912,000 pixels differed).

Constraint worth knowing: SetThreadDesktop fails if the calling thread already
owns a window, so the binding has to happen *before* the GUI toolkit
initialises. Bind first, import/create windows after.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
from contextlib import contextmanager

_user32 = ctypes.windll.user32
_kernel32 = ctypes.windll.kernel32

GENERIC_ALL = 0x10000000

_user32.CreateDesktopW.restype = wintypes.HANDLE
_user32.CreateDesktopW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR,
                                   ctypes.c_void_p, wintypes.DWORD,
                                   wintypes.DWORD, ctypes.c_void_p]
_user32.GetThreadDesktop.restype = wintypes.HANDLE
_user32.SetThreadDesktop.argtypes = [wintypes.HANDLE]
_user32.CloseDesktop.argtypes = [wintypes.HANDLE]


class DesktopUnavailable(RuntimeError):
    """The hidden desktop could not be created or bound."""


@contextmanager
def hidden_desktop(name: str = "UIShot"):
    """Bind this thread to a freshly created, never-displayed desktop.

    Restores the original desktop on exit. Yields the desktop handle.

    Raises DesktopUnavailable rather than a bare OSError so callers can fall
    back to on-screen capture with a clear reason.
    """
    hdesk = _user32.CreateDesktopW(name, None, None, 0, GENERIC_ALL, None)
    if not hdesk:
        raise DesktopUnavailable(
            f"CreateDesktopW({name!r}) failed: {ctypes.WinError()}")

    original = _user32.GetThreadDesktop(_kernel32.GetCurrentThreadId())
    if not _user32.SetThreadDesktop(hdesk):
        _user32.CloseDesktop(hdesk)
        raise DesktopUnavailable(
            "SetThreadDesktop failed — the thread already owns a window? "
            f"({ctypes.WinError()})")

    try:
        yield hdesk
    finally:
        # Restore before closing, or the thread is left on a dead desktop.
        try:
            _user32.SetThreadDesktop(original)
        finally:
            _user32.CloseDesktop(hdesk)
