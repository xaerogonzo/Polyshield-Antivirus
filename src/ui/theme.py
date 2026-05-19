"""
theme.py
────────
Centralised mutable font instances and colour palette for PolyShield.

Usage
-----
    import ui.theme as theme

    # Once, after the Tk root exists (call from App.__init__ after super().__init__()):
    theme.init(cfg)
    theme.init_colors(cfg)

    # In any view or widget:
    widget = ctk.CTkLabel(..., font=theme.get("body"))
    heading = ctk.CTkLabel(..., font=theme.get("heading"))

    # Live font update — propagates to ALL widgets sharing the font object instantly:
    theme.set_content_size(15)
    theme.set_log_size(14)
    theme.set_log_monospace(False)

    # Colour look-up:
    bg = theme.color("accent")
"""
from __future__ import annotations

import customtkinter as ctk

# ── Font registry ─────────────────────────────────────────────────────────────

_fonts: dict[str, ctk.CTkFont] = {}


def init(cfg) -> None:
    """Create all shared mutable font instances.

    Must be called **after** the Tk root exists (i.e. after super().__init__()
    in App).  Calling before a root exists will raise a TclError.
    """
    global _fonts
    body_sz = int(cfg.get("display_font_content_size") or 13)
    log_sz  = int(cfg.get("display_font_log_size")      or 12)
    mono    = bool(cfg.get("display_log_monospace") if cfg.get("display_log_monospace") is not None else True)
    log_fam = "Consolas" if mono else ""

    _fonts = {
        # ── Fixed (UI chrome — changing these would break layouts) ──
        "heading":       ctk.CTkFont(size=22, weight="bold"),
        "section_title": ctk.CTkFont(size=14, weight="bold"),
        "item_title":    ctk.CTkFont(size=13, weight="bold"),
        "small":         ctk.CTkFont(size=11),
        "code":          ctk.CTkFont(size=12, family="Consolas"),
        "nav":           ctk.CTkFont(size=13),
        # ── User-adjustable ──
        "body":          ctk.CTkFont(size=body_sz),
        "log":           ctk.CTkFont(size=log_sz, family=log_fam),
    }


def get(name: str) -> ctk.CTkFont:
    """Return the named shared font object.

    Falls back to a default CTkFont if the name is unknown (so callers
    don't crash before init() has run in edge cases during tests).
    """
    if name in _fonts:
        return _fonts[name]
    # Lazy fallback — avoids crashes if a view is instantiated before init()
    return ctk.CTkFont(size=13)


# ── Live font-update helpers ──────────────────────────────────────────────────

def set_content_size(size: int) -> None:
    """Update the reading-content tier: Help body, descriptions, detail pane.

    CTkFont.configure() propagates to every widget sharing the object instantly.
    """
    if "body" in _fonts:
        _fonts["body"].configure(size=size)
    if "item_title" in _fonts:
        _fonts["item_title"].configure(size=size, weight="bold")


def set_log_size(size: int) -> None:
    """Update the log/output tier: scan log, event feed, network rows."""
    if "log" in _fonts:
        _fonts["log"].configure(size=size)


def set_log_monospace(mono: bool) -> None:
    """Toggle Consolas (mono=True) vs proportional (mono=False) for log text."""
    if "log" in _fonts:
        _fonts["log"].configure(family="Consolas" if mono else "")


# ── Colour palette ────────────────────────────────────────────────────────────

# Five built-in presets.  Only the most-visible accent/card colours are
# controlled here; the remaining hardcoded colours in individual views are
# left in place (a full colour migration is deferred to a later pass).
_PRESET_PALETTES: dict[str, dict[str, str]] = {
    "classic": {
        "accent":     "#5294e2",
        "nav_active": "#1f3355",
        "card":       "#1a1a2e",
        "card2":      "#12121e",
        "app_bg":     "#0f0f1a",
        "sidebar":    "#141422",
        "content_bg": "#12121e",
    },
    "forest": {
        "accent":     "#50fa7b",
        "nav_active": "#1a3322",
        "card":       "#0f1e18",
        "card2":      "#0a1510",
        "app_bg":     "#080f0c",
        "sidebar":    "#060d08",
        "content_bg": "#0a1510",
    },
    "void": {
        "accent":     "#bd93f9",
        "nav_active": "#2a1f55",
        "card":       "#1a1a2e",
        "card2":      "#12121e",
        "app_bg":     "#0f0f1a",
        "sidebar":    "#0d0d1a",
        "content_bg": "#12121e",
    },
    "midnight": {
        "accent":     "#8be9fd",
        "nav_active": "#0a2040",
        "card":       "#101825",
        "card2":      "#08111a",
        "app_bg":     "#060d14",
        "sidebar":    "#040a10",
        "content_bg": "#08111a",
    },
    "stealth": {
        "accent":     "#aaaaaa",
        "nav_active": "#1a1a1a",
        "card":       "#111111",
        "card2":      "#0a0a0a",
        "app_bg":     "#080808",
        "sidebar":    "#060606",
        "content_bg": "#0a0a0a",
    },
}

_PRESET_DISPLAY_NAMES: dict[str, str] = {
    "classic":  "Classic PolyShield",
    "forest":   "Deep Forest",
    "void":     "Void",
    "midnight": "Midnight",
    "stealth":  "Stealth",
}

_DEFAULT_PALETTE = _PRESET_PALETTES["classic"]

_colors: dict[str, str] = dict(_DEFAULT_PALETTE)


def init_colors(cfg) -> None:
    """Load palette from config and apply any accent override."""
    preset_key = cfg.get("display_theme_preset") or "classic"
    palette    = _PRESET_PALETTES.get(preset_key, _DEFAULT_PALETTE)
    _colors.clear()
    _colors.update(palette)

    accent_override = cfg.get("display_accent_color") or ""
    if accent_override:
        _colors["accent"] = accent_override


def color(name: str) -> str:
    """Return a palette colour by name, falling back to the classic default."""
    return _colors.get(name, _DEFAULT_PALETTE.get(name, "#5294e2"))


def set_accent(hex_val: str) -> None:
    """Override just the accent colour (e.g. from the accent chip picker)."""
    _colors["accent"] = hex_val


def apply_preset(preset_key: str, cfg=None) -> None:
    """Switch to a built-in palette preset.

    Clears any accent override.  Pass `cfg` to also persist to settings.
    """
    palette = _PRESET_PALETTES.get(preset_key, _DEFAULT_PALETTE)
    _colors.clear()
    _colors.update(palette)
    if cfg is not None:
        cfg.set("display_theme_preset", preset_key)
        cfg.set("display_accent_color", "")


def preset_names() -> list[tuple[str, str]]:
    """Return [(key, display_name), ...] for all built-in presets."""
    return [(k, _PRESET_DISPLAY_NAMES[k]) for k in _PRESET_PALETTES]


def preset_palette(key: str) -> dict[str, str]:
    """Return the raw colour dict for a preset (for swatch rendering)."""
    return _PRESET_PALETTES.get(key, _DEFAULT_PALETTE)
