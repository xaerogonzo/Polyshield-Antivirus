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
        "accent":      "#5294e2",
        "accent_hover":"#144e7a",
        "nav_active":  "#1f3355",
        "card":        "#1a1a2e",
        "card2":       "#12121e",
        "app_bg":      "#0f0f1a",
        "sidebar":     "#141422",
        "content_bg":  "#12121e",
        "divider":     "#2a2a3a",
        "text":        "#cdd6f4",
        "subtext":     "#888899",
        "dim":         "#555577",
        "input_bg":    "#2a2a3a",
        "input_hover": "#3a3a4a",
    },
    "forest": {
        "accent":      "#50fa7b",
        "accent_hover":"#2a7a3a",
        "nav_active":  "#1a3322",
        "card":        "#0f1e18",
        "card2":       "#0a1510",
        "app_bg":      "#080f0c",
        "sidebar":     "#060d08",
        "content_bg":  "#0a1510",
        "divider":     "#1a3322",
        "text":        "#cdd6c4",
        "subtext":     "#88998a",
        "dim":         "#557758",
        "input_bg":    "#1a2a22",
        "input_hover": "#2a3a32",
    },
    "void": {
        "accent":      "#bd93f9",
        "accent_hover":"#7a5ab0",
        "nav_active":  "#2a1f55",
        "card":        "#1a1a2e",
        "card2":       "#12121e",
        "app_bg":      "#0f0f1a",
        "sidebar":     "#0d0d1a",
        "content_bg":  "#12121e",
        "divider":     "#2a2a4a",
        "text":        "#e0d4f4",
        "subtext":     "#9988aa",
        "dim":         "#665577",
        "input_bg":    "#2a2a4a",
        "input_hover": "#3a3a5a",
    },
    "midnight": {
        "accent":      "#8be9fd",
        "nav_active":  "#0a2040",
        "accent_hover":"#3a7a9a",
        "card":        "#101825",
        "card2":       "#08111a",
        "app_bg":      "#060d14",
        "sidebar":     "#040a10",
        "content_bg":  "#08111a",
        "divider":     "#1a2a3a",
        "text":        "#c4d6e4",
        "subtext":     "#7a8899",
        "dim":         "#556677",
        "input_bg":    "#1a2a3a",
        "input_hover": "#2a3a4a",
    },
    "stealth": {
        "accent":      "#aaaaaa",
        "accent_hover":"#666666",
        "nav_active":  "#1a1a1a",
        "card":        "#111111",
        "card2":       "#0a0a0a",
        "app_bg":      "#080808",
        "sidebar":     "#060606",
        "content_bg":  "#0a0a0a",
        "divider":     "#2a2a2a",
        "text":        "#cccccc",
        "subtext":     "#888888",
        "dim":         "#555555",
        "input_bg":    "#1a1a1a",
        "input_hover": "#2a2a2a",
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

    # Push the palette into CTk's global ThemeManager so default-styled
    # widgets (buttons, checkboxes, dropdowns, etc.) pick up the right
    # colours at construction time.
    apply_ctk_palette()


def color(name: str) -> str:
    """Return a palette colour by name, falling back to the classic default."""
    return _colors.get(name, _DEFAULT_PALETTE.get(name, "#5294e2"))


def set_accent(hex_val: str) -> None:
    """Override just the accent colour (e.g. from the accent chip picker)."""
    _colors["accent"] = hex_val
    apply_ctk_palette()


def apply_preset(preset_key: str, cfg=None) -> None:
    """Switch to a built-in palette preset.

    Clears any accent override.  Pass `cfg` to also persist to settings.
    """
    palette = _PRESET_PALETTES.get(preset_key, _DEFAULT_PALETTE)
    _colors.clear()
    _colors.update(palette)
    if cfg is not None:
        cfg.set_value("display_theme_preset", preset_key)
        cfg.set_value("display_accent_color", "")
    apply_ctk_palette()


def preset_names() -> list[tuple[str, str]]:
    """Return [(key, display_name), ...] for all built-in presets."""
    return [(k, _PRESET_DISPLAY_NAMES[k]) for k in _PRESET_PALETTES]


def preset_palette(key: str) -> dict[str, str]:
    """Return the raw colour dict for a preset (for swatch rendering)."""
    return _PRESET_PALETTES.get(key, _DEFAULT_PALETTE)


# ── Themed-widget registry ────────────────────────────────────────────────────
# Each view keeps its own list of (widget, {attr: token, ...}) tuples.
# Call register() at widget creation; call refresh() in _refresh_theme().

def register(registry: list, widget, **token_attrs):
    """Tag `widget` with theme tokens and apply them now.

    Example:
        card = ctk.CTkFrame(self)
        theme.register(self._themed, card, fg_color="card")

    Returns the widget for chained calls.
    """
    registry.append((widget, dict(token_attrs)))
    try:
        widget.configure(**{attr: color(token) for attr, token in token_attrs.items()})
    except Exception:
        pass
    return widget


def refresh(registry: list) -> None:
    """Re-apply current theme colours to every widget previously registered."""
    for widget, token_attrs in registry:
        try:
            widget.configure(**{attr: color(token) for attr, token in token_attrs.items()})
        except Exception:
            pass


def apply_ctk_palette() -> None:
    """Patch ``ctk.ThemeManager.theme`` so all CTk-default widgets follow the
    current preset palette.

    CTk's default ``"blue"`` theme is what causes the "patchwork" effect — any
    widget we didn't explicitly give an ``fg_color`` falls back to CTk's
    ``#1F6AA5`` blue.  Writing into ``ThemeManager.theme`` makes newly-created
    widgets pick up the preset accent automatically.

    For widgets that are *already mounted*, see ``App._refresh_ctk_widgets()``
    which walks the widget tree and re-configures default-styled widgets.

    Notes
    -----
    * The values are ``[light, dark]`` pairs.  We pass the same colour twice
      since the app only runs in dark mode.
    * Buttons and check-boxes are deliberately left alone because many of our
      buttons carry semantic colour meaning (red Stop, yellow Pause, etc.).
      The ThemeManager default for those classes IS still patched (so future
      buttons without explicit colours pick up the accent), but the widget-
      tree walker in ``app.py`` skips them so existing semantic colours are
      preserved.
    """
    try:
        import customtkinter as ctk
    except Exception:
        return
    a   = color("accent")
    ah  = color("accent_hover")
    nav = color("nav_active")
    tm  = ctk.ThemeManager.theme

    def _pair(c: str) -> list:
        return [c, c]

    try:
        tm["CTkButton"]["fg_color"]       = _pair(a)
        tm["CTkButton"]["hover_color"]    = _pair(ah)
        tm["CTkCheckBox"]["fg_color"]     = _pair(a)
        tm["CTkCheckBox"]["hover_color"]  = _pair(ah)
        tm["CTkRadioButton"]["fg_color"]  = _pair(a)
        tm["CTkRadioButton"]["hover_color"] = _pair(ah)
        tm["CTkOptionMenu"]["fg_color"]            = _pair(nav)
        tm["CTkOptionMenu"]["button_color"]        = _pair(a)
        tm["CTkOptionMenu"]["button_hover_color"]  = _pair(ah)
        tm["CTkComboBox"]["button_color"]          = _pair(a)
        tm["CTkComboBox"]["button_hover_color"]    = _pair(ah)
        tm["CTkSegmentedButton"]["selected_color"]       = _pair(a)
        tm["CTkSegmentedButton"]["selected_hover_color"] = _pair(ah)
        tm["CTkProgressBar"]["progress_color"]     = _pair(a)
        tm["CTkSlider"]["button_color"]            = _pair(a)
        tm["CTkSlider"]["button_hover_color"]      = _pair(ah)
        tm["CTkSwitch"]["progress_color"]          = _pair(a)
        tm["CTkScrollbar"]["button_color"]         = _pair(color("divider"))
        tm["CTkScrollbar"]["button_hover_color"]   = _pair(a)
    except Exception:
        pass
