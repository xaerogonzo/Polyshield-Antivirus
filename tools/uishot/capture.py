"""
Window capture and image comparison.

Capture asks the window to render *itself* into a bitmap we own (WM_PRINT via
PrintWindow), rather than reading pixels off the screen. That is what makes it
work for a window nobody can see, and it is why the harness never needs focus,
never steals the cursor, and never captures anything else on the machine.

Flag choice is not cosmetic, and the right value depends on where the window
lives (all measured on this project, same view, same size):

    hidden desktop   + PW_RENDERFULLCONTENT -> identical to the real render
    hidden desktop   + flag 0               -> backgrounds missing (95% differ)
    off-screen coords+ PW_RENDERFULLCONTENT -> mostly blank white
    off-screen coords+ flag 0               -> backgrounds missing

So: hidden desktop and PW_RENDERFULLCONTENT together, which is what
`session.TkSession` sets up.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
from pathlib import Path

from PIL import Image, ImageChops

_user32 = ctypes.windll.user32
_gdi32 = ctypes.windll.gdi32

PW_CLIENTONLY = 0x00000001
PW_RENDERFULLCONTENT = 0x00000002


class _BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [("biSize", wintypes.DWORD), ("biWidth", wintypes.LONG),
                ("biHeight", wintypes.LONG), ("biPlanes", wintypes.WORD),
                ("biBitCount", wintypes.WORD), ("biCompression", wintypes.DWORD),
                ("biSizeImage", wintypes.DWORD), ("biXPelsPerMeter", wintypes.LONG),
                ("biYPelsPerMeter", wintypes.LONG), ("biClrUsed", wintypes.DWORD),
                ("biClrImportant", wintypes.DWORD)]


class CaptureError(RuntimeError):
    pass


def capture_window(hwnd: int, flags: int = PW_RENDERFULLCONTENT) -> Image.Image:
    """Render a window into a PIL image without it being visible or focused."""
    rect = wintypes.RECT()
    if not _user32.GetWindowRect(hwnd, ctypes.byref(rect)):
        raise CaptureError(f"GetWindowRect failed for hwnd {hwnd}")
    width, height = rect.right - rect.left, rect.bottom - rect.top
    if width <= 0 or height <= 0:
        raise CaptureError(f"window {hwnd} has no area ({width}x{height})")

    window_dc = _user32.GetWindowDC(hwnd)
    mem_dc = _gdi32.CreateCompatibleDC(window_dc)
    bitmap = _gdi32.CreateCompatibleBitmap(window_dc, width, height)
    _gdi32.SelectObject(mem_dc, bitmap)
    try:
        if not _user32.PrintWindow(hwnd, mem_dc, flags):
            raise CaptureError(f"PrintWindow failed for hwnd {hwnd}")

        header = _BITMAPINFOHEADER()
        header.biSize = ctypes.sizeof(_BITMAPINFOHEADER)
        header.biWidth = width
        header.biHeight = -height        # negative = top-down rows
        header.biPlanes = 1
        header.biBitCount = 32
        header.biCompression = 0         # BI_RGB

        buffer = ctypes.create_string_buffer(width * height * 4)
        if not _gdi32.GetDIBits(mem_dc, bitmap, 0, height, buffer,
                                ctypes.byref(header), 0):
            raise CaptureError("GetDIBits failed")

        return Image.frombuffer("RGBA", (width, height), buffer,
                                "raw", "BGRA", 0, 1).convert("RGB")
    finally:
        _gdi32.DeleteObject(bitmap)
        _gdi32.DeleteDC(mem_dc)
        _user32.ReleaseDC(hwnd, window_dc)


# ── Comparison ────────────────────────────────────────────────────────────────

def compare(actual: Image.Image, expected: Image.Image,
            tolerance: int = 8) -> dict:
    """Compare two shots.

    `tolerance` is the per-channel difference below which a pixel counts as
    unchanged — font antialiasing moves single channels by a few levels between
    otherwise identical runs.

    Returns {match, differing, total, ratio, bbox, size_changed}.
    """
    if actual.size != expected.size:
        return {"match": False, "differing": -1, "total": 0, "ratio": 1.0,
                "bbox": None, "size_changed": True,
                "detail": f"{actual.size} vs expected {expected.size}"}

    diff = ImageChops.difference(actual.convert("RGB"),
                                 expected.convert("RGB")).convert("L")
    # tobytes() over getdata(): not deprecated, and materially faster on the
    # ~1 MP images this deals with.
    data = diff.tobytes()
    total = actual.size[0] * actual.size[1]
    differing = sum(1 for value in data if value > tolerance)
    return {"match": differing == 0, "differing": differing, "total": total,
            "ratio": differing / total if total else 0.0,
            "bbox": diff.getbbox(), "size_changed": False, "detail": ""}


def write_diff(actual: Image.Image, expected: Image.Image, path: Path) -> None:
    """Save a side-by-side with the changed region highlighted."""
    from PIL import ImageDraw

    width = actual.size[0] + expected.size[0] + 12
    height = max(actual.size[1], expected.size[1])
    canvas = Image.new("RGB", (width, height), (24, 24, 28))
    canvas.paste(expected, (0, 0))
    canvas.paste(actual, (expected.size[0] + 12, 0))

    if actual.size == expected.size:
        bbox = ImageChops.difference(actual.convert("RGB"),
                                     expected.convert("RGB")).getbbox()
        if bbox:
            draw = ImageDraw.Draw(canvas)
            draw.rectangle(bbox, outline=(255, 85, 85), width=2)
            shifted = (bbox[0] + expected.size[0] + 12, bbox[1],
                       bbox[2] + expected.size[0] + 12, bbox[3])
            draw.rectangle(shifted, outline=(255, 85, 85), width=2)

    path.parent.mkdir(parents=True, exist_ok=True)
    canvas.save(path)
