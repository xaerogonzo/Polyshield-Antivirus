"""
display_view.py
───────────────
Display & Appearance settings view.

Sections
────────
1. Theme Presets       — 5 built-in palettes (swatch grid)
2. Accent Color        — 8 predefined chips + custom hex entry
3. Background Image    — browse / opacity slider / blur slider / live preview
4. Font Sizes          — segmented buttons for content & log tiers + monospace toggle
5. Widget Scale        — preset buttons (requires restart)
"""
from __future__ import annotations

import threading
from pathlib import Path
from tkinter import filedialog
from typing import TYPE_CHECKING

import customtkinter as ctk

import ui.theme as theme
from ui.core import settings as cfg

if TYPE_CHECKING:
    from ui.app import App

# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_light(hex_color: str) -> bool:
    """Return True if the hex colour is perceptually light (good for dark text)."""
    try:
        r = int(hex_color[1:3], 16)
        g = int(hex_color[3:5], 16)
        b = int(hex_color[5:7], 16)
        return (0.299 * r + 0.587 * g + 0.114 * b) > 160
    except Exception:
        return False


# ── Palette ───────────────────────────────────────────────────────────────────
_CARD  = "#1a1a2e"
_CARD2 = "#12121e"
_TEXT  = "#cdd6f4"
_DIM   = "#555577"
_SUBTEXT = "#888899"

# 8 accent chip colours
_ACCENT_CHIPS = [
    "#5294e2",  # classic blue
    "#50fa7b",  # forest green
    "#bd93f9",  # void purple
    "#ff79c6",  # pink
    "#ffb86c",  # orange
    "#ff5555",  # red
    "#8be9fd",  # cyan
    "#f1fa8c",  # yellow
]

# Font size options: (display_label, int_value)
_CONTENT_SIZES = [("Small (11)", 11), ("Medium (13)", 13), ("Large (15)", 15), ("XL (17)", 17)]
_LOG_SIZES     = [("Small (11)", 11), ("Medium (12)", 12), ("Large (14)", 14)]
_SCALE_OPTIONS = [("85%", 0.85), ("100%", 1.0), ("110%", 1.1), ("125%", 1.25)]


class DisplayView(ctk.CTkScrollableFrame):
    """Sidebar view for visual / appearance customisation."""

    def __init__(self, master, status_callback=None, app_ref=None, **kw):
        super().__init__(master, fg_color=theme.color("card2"), **kw)
        self._status_cb  = status_callback or (lambda _: None)
        self._app: App | None = app_ref
        self._preview_after_id: str | None = None   # debounce handle for image preview
        self._build()

    # ── Public lifecycle ──────────────────────────────────────────────────────

    def on_show(self) -> None:
        """Refresh controls to reflect current settings (in case changed elsewhere)."""
        self._refresh_controls()

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        row = 0

        # Page heading
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.grid(row=row, column=0, sticky="ew", padx=24, pady=(18, 4))
        hdr.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(hdr, text="Display & Appearance",
                     font=ctk.CTkFont(size=22, weight="bold"),
                     text_color=_TEXT, anchor="w").grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(hdr, text="Customise themes, colours, background, fonts, and scale.",
                     font=ctk.CTkFont(size=12), text_color=_SUBTEXT, anchor="w").grid(
            row=1, column=0, sticky="w", pady=(2, 0))
        row += 1

        row = self._build_theme_presets(row)
        row = self._build_accent_color(row)
        row = self._build_background(row)
        row = self._build_font_sizes(row)
        row = self._build_widget_scale(row)

        # Bottom padding
        ctk.CTkFrame(self, height=24, fg_color="transparent").grid(row=row, column=0)

    # ── Section 1: Theme Presets ──────────────────────────────────────────────

    def _build_theme_presets(self, start_row: int) -> int:
        card = self._section_card("Theme Presets", start_row)
        card.grid_columnconfigure((0, 1, 2), weight=1)

        presets = theme.preset_names()   # [(key, display_name), ...]
        current = cfg.get("display_theme_preset") or "classic"

        self._preset_btns: dict[str, ctk.CTkButton] = {}
        for idx, (key, name) in enumerate(presets):
            palette = theme.preset_palette(key)
            is_active = (key == current)

            # Use CTkButton — bind() on CTkFrame/CTkLabel doesn't fire reliably
            # in CustomTkinter because clicks land on the internal canvas, not
            # the outer Python widget.  CTkButton.command= always works.
            btn = ctk.CTkButton(
                card,
                text=f"●  {name}",
                anchor="center",
                font=ctk.CTkFont(size=12),
                fg_color=palette["card"],
                hover_color=palette["nav_active"],
                text_color=palette["accent"],
                corner_radius=10,
                border_width=2,
                border_color=palette["accent"] if is_active else "#2a2a3a",
                height=52,
                command=lambda k=key: self._apply_preset(k),
            )
            btn.grid(row=idx // 3, column=idx % 3, padx=6, pady=6, sticky="ew")
            self._preset_btns[key] = btn

        ctk.CTkLabel(card, text="Sidebar and nav colours update live. Card and panel colours inside each view apply on next restart.",
                     font=ctk.CTkFont(size=11), text_color=_DIM, anchor="w",
                     wraplength=560, justify="left").grid(
            row=2, column=0, columnspan=3, sticky="w", pady=(4, 0))

        return start_row + 1

    def _apply_preset(self, key: str) -> None:
        try:
            theme.apply_preset(key, cfg)
            self._status_cb(f"Theme preset: {dict(theme.preset_names()).get(key, key)}")
            # Refresh preset button borders to show active state
            for k, btn in self._preset_btns.items():
                palette = theme.preset_palette(k)
                is_active = (k == key)
                btn.configure(border_color=palette["accent"] if is_active else "#2a2a3a")
            # The preset clears any accent override — un-check all accent chips
            # so the two sections don't visually contradict each other.
            for hv, chip in self._accent_chips.items():
                chip.configure(border_color=hv, text="")
            # Update section title accent colours in this view
            self._refresh_section_titles()
            # Propagate sidebar / nav / content frame colours live
            if self._app:
                self._app.refresh_nav_theme()
                self._app._apply_bg_image()
        except Exception as e:
            import traceback
            traceback.print_exc()
            self._status_cb(f"⚠ Preset error: {type(e).__name__}: {e}")

    # ── Section 2: Accent Color ───────────────────────────────────────────────

    def _build_accent_color(self, start_row: int) -> int:
        card = self._section_card("Accent Color", start_row)
        card.grid_columnconfigure(0, weight=1)

        chips_row = ctk.CTkFrame(card, fg_color="transparent")
        chips_row.grid(row=0, column=0, sticky="w", pady=(0, 4))

        self._accent_chips: dict[str, ctk.CTkButton] = {}
        current_accent = cfg.get("display_accent_color") or theme.color("accent")

        for i, hex_val in enumerate(_ACCENT_CHIPS):
            is_active = (hex_val.lower() == current_accent.lower())
            # CTkButton with command= — reliable click handling vs bind() on CTkFrame
            chip = ctk.CTkButton(
                chips_row,
                text="✓" if is_active else "",
                width=32, height=32,
                fg_color=hex_val,
                hover_color=hex_val,
                text_color="#000000" if _is_light(hex_val) else "#ffffff",
                corner_radius=16,
                border_width=3,
                border_color="#ffffff" if is_active else hex_val,
                font=ctk.CTkFont(size=11, weight="bold"),
                command=lambda hv=hex_val: self._pick_chip(hv),
            )
            chip.grid(row=0, column=i, padx=4)
            self._accent_chips[hex_val] = chip

        # Custom... button
        ctk.CTkButton(
            chips_row, text="Custom…", width=80,
            fg_color=theme.color("divider"), hover_color=theme.color("input_hover"),
            text_color=_TEXT, font=ctk.CTkFont(size=12),
            command=self._open_custom_accent,
        ).grid(row=0, column=len(_ACCENT_CHIPS) + 1, padx=(8, 0))

        ctk.CTkLabel(card, text="Affects section headings, active nav highlight, and link colours.",
                     font=ctk.CTkFont(size=11), text_color=_DIM, anchor="w").grid(
            row=1, column=0, sticky="w")

        return start_row + 1

    def _pick_chip(self, hex_val: str) -> None:
        try:
            theme.set_accent(hex_val)
            cfg.set_value("display_accent_color", hex_val)
            # Update chip borders and checkmarks
            for hv, chip in self._accent_chips.items():
                active = (hv.lower() == hex_val.lower())
                chip.configure(
                    border_color="#ffffff" if active else hv,
                    text="✓" if active else "",
                )
            self._refresh_section_titles()
            if self._app:
                self._app.refresh_nav_theme()
            self._status_cb(f"Accent color: {hex_val}")
        except Exception as e:
            import traceback
            traceback.print_exc()
            self._status_cb(f"⚠ Accent error: {type(e).__name__}: {e}")

    def _open_custom_accent(self) -> None:
        dlg = ctk.CTkToplevel(self)
        dlg.title("Custom Accent Color")
        dlg.geometry("320x180")
        dlg.resizable(False, False)
        dlg.grab_set()

        ctk.CTkLabel(dlg, text="Enter a hex colour (e.g. #ff79c6):",
                     font=ctk.CTkFont(size=13)).pack(pady=(20, 4))
        entry = ctk.CTkEntry(dlg, width=160, font=ctk.CTkFont(size=13))
        entry.insert(0, cfg.get("display_accent_color") or "#5294e2")
        entry.pack()

        preview = ctk.CTkFrame(dlg, width=60, height=28, corner_radius=6,
                               fg_color=entry.get() or "#5294e2")
        preview.pack(pady=8)

        def _on_change(*_):
            try:
                val = entry.get().strip()
                if len(val) in (4, 7) and val.startswith("#"):
                    preview.configure(fg_color=val)
            except Exception:
                pass

        entry.bind("<KeyRelease>", _on_change)

        def _confirm():
            val = entry.get().strip()
            if val:
                self._pick_chip(val)
                # Add to chip display if not in standard set
                # (visual update only — custom chip area not rebuilt)
            dlg.destroy()

        ctk.CTkButton(dlg, text="Apply", command=_confirm,
                      fg_color=theme.color("accent"),
                      hover_color="#3a6ab0").pack(pady=(0, 8))

    # ── Section 3: Background Image ───────────────────────────────────────────

    def _build_background(self, start_row: int) -> int:
        card = self._section_card("Background Image", start_row)
        card.grid_columnconfigure(0, weight=1)

        # Browse row
        browse_row = ctk.CTkFrame(card, fg_color="transparent")
        browse_row.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        browse_row.grid_columnconfigure(1, weight=1)

        ctk.CTkButton(browse_row, text="Browse…", width=80,
                      fg_color=theme.color("divider"), hover_color=theme.color("input_hover"),
                      text_color=_TEXT, font=ctk.CTkFont(size=12),
                      command=self._browse_image).grid(row=0, column=0, padx=(0, 8))

        self._bg_path_lbl = ctk.CTkLabel(browse_row, text=self._short_path(),
                                          font=ctk.CTkFont(size=11),
                                          text_color=_TEXT, anchor="w")
        self._bg_path_lbl.grid(row=0, column=1, sticky="w")

        ctk.CTkButton(browse_row, text="✕ Clear", width=68,
                      fg_color=theme.color("divider"), hover_color="#5a2a2a",
                      text_color=_TEXT, font=ctk.CTkFont(size=12),
                      command=self._clear_image).grid(row=0, column=2, padx=(8, 0))

        # Opacity slider
        op_row = ctk.CTkFrame(card, fg_color="transparent")
        op_row.grid(row=1, column=0, sticky="ew", pady=2)
        op_row.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(op_row, text="Opacity:", width=62,
                     font=ctk.CTkFont(size=12), text_color=_TEXT, anchor="w").grid(
            row=0, column=0)
        self._opacity_slider = ctk.CTkSlider(
            op_row, from_=0, to=100, number_of_steps=100,
            command=self._on_opacity_change,
        )
        self._opacity_slider.set((cfg.get("display_bg_opacity") or 0.15) * 100)
        self._opacity_slider.grid(row=0, column=1, sticky="ew", padx=(8, 8))
        self._opacity_lbl = ctk.CTkLabel(op_row, text=f"{int(self._opacity_slider.get())}%",
                                          width=42, font=ctk.CTkFont(size=12),
                                          text_color=_TEXT, anchor="w")
        self._opacity_lbl.grid(row=0, column=2)

        # Blur slider
        blur_row = ctk.CTkFrame(card, fg_color="transparent")
        blur_row.grid(row=2, column=0, sticky="ew", pady=2)
        blur_row.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(blur_row, text="Blur:", width=62,
                     font=ctk.CTkFont(size=12), text_color=_TEXT, anchor="w").grid(
            row=0, column=0)
        self._blur_slider = ctk.CTkSlider(
            blur_row, from_=0, to=20, number_of_steps=20,
            command=self._on_blur_change,
        )
        self._blur_slider.set(int(cfg.get("display_bg_blur") or 0))
        self._blur_slider.grid(row=0, column=1, sticky="ew", padx=(8, 8))
        self._blur_lbl = ctk.CTkLabel(blur_row, text=f"Blur: {int(self._blur_slider.get())}",
                                       width=56, font=ctk.CTkFont(size=12),
                                       text_color=_TEXT, anchor="w")
        self._blur_lbl.grid(row=0, column=2)

        # Preview thumbnail
        self._preview_frame = ctk.CTkFrame(card, fg_color="#0a0a14",
                                            width=120, height=80, corner_radius=6)
        self._preview_frame.grid(row=3, column=0, sticky="w", pady=(8, 4))
        self._preview_frame.grid_propagate(False)
        self._preview_lbl = ctk.CTkLabel(self._preview_frame, text="No image",
                                          font=ctk.CTkFont(size=11),
                                          text_color=_DIM, image=None)
        self._preview_lbl.place(relx=0.5, rely=0.5, anchor="center")
        self._schedule_preview()

        # Tip
        ctk.CTkLabel(card, text="Low opacity + medium blur = frosted texture. "
                                "High opacity with a dark/muted image works best for readability.",
                     font=ctk.CTkFont(size=11), text_color=_DIM, anchor="w",
                     wraplength=560, justify="left").grid(
            row=4, column=0, sticky="w", pady=(4, 0))

        return start_row + 1

    def _short_path(self) -> str:
        p = cfg.get("display_bg_image") or ""
        if not p:
            return "No image selected"
        parts = Path(p).parts
        if len(parts) > 3:
            return "…/" + "/".join(parts[-2:])
        return p

    def _browse_image(self) -> None:
        path = filedialog.askopenfilename(
            title="Select background image",
            filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp *.webp"),
                       ("All files", "*.*")]
        )
        if path:
            cfg.set_value("display_bg_image", path)
            self._bg_path_lbl.configure(text=self._short_path())
            self._schedule_preview()
            if self._app:
                self._app._apply_bg_image()

    def _clear_image(self) -> None:
        cfg.set_value("display_bg_image", "")
        self._bg_path_lbl.configure(text="No image selected")
        self._preview_lbl.configure(text="No image", image=None)
        self._preview_img_ref = None
        if self._app:
            self._app._apply_bg_image()

    def _on_opacity_change(self, val) -> None:
        v = int(float(val))
        self._opacity_lbl.configure(text=f"{v}%")
        cfg.set_value("display_bg_opacity", round(v / 100, 2))
        self._schedule_preview()
        if self._app:
            self._app._apply_bg_image()

    def _on_blur_change(self, val) -> None:
        v = int(float(val))
        self._blur_lbl.configure(text=f"Blur: {v}")
        cfg.set_value("display_bg_blur", v)
        self._schedule_preview()
        if self._app:
            self._app._apply_bg_image()

    def _schedule_preview(self) -> None:
        """Debounced thumbnail regeneration (200 ms) to avoid PIL overhead on drag."""
        if self._preview_after_id is not None:
            try:
                self.after_cancel(self._preview_after_id)
            except Exception:
                pass
        self._preview_after_id = self.after(200, self._update_preview)

    def _update_preview(self) -> None:
        self._preview_after_id = None
        path = cfg.get("display_bg_image") or ""
        if not path or not Path(path).exists():
            self._preview_lbl.configure(text="No image", image=None)
            return

        def _gen():
            try:
                from PIL import Image, ImageFilter
                img = Image.open(path).convert("RGBA")
                img.thumbnail((120, 80), Image.LANCZOS)
                blur = int(cfg.get("display_bg_blur") or 0)
                if blur > 0:
                    img = img.filter(ImageFilter.GaussianBlur(radius=blur))
                opacity = float(cfg.get("display_bg_opacity") or 0.15)
                bg_hex = theme.color("app_bg")
                bg_rgb = tuple(int(bg_hex[i:i+2], 16) for i in (1, 3, 5))
                bg = Image.new("RGBA", img.size, (*bg_rgb, 255))
                composited = Image.blend(bg, img, alpha=opacity)
                ctk_img = ctk.CTkImage(
                    light_image=composited, dark_image=composited,
                    size=(120, 80)
                )
                if self.winfo_exists():
                    self.after(0, lambda: self._preview_lbl.configure(
                        image=ctk_img, text=""))
                    self._preview_img_ref = ctk_img   # keep reference
            except Exception:
                if self.winfo_exists():
                    self.after(0, lambda: self._preview_lbl.configure(
                        text="Preview error", image=None))

        threading.Thread(target=_gen, daemon=True).start()

    # ── Section 4: Font Sizes ─────────────────────────────────────────────────

    def _build_font_sizes(self, start_row: int) -> int:
        card = self._section_card("Font Sizes", start_row)
        card.grid_columnconfigure(0, weight=1)

        # Content tier — segmented button row
        self._build_font_row(card, 0,
                             "Reading content",
                             "(Help, descriptions, detail pane)",
                             "display_font_content_size",
                             _CONTENT_SIZES,
                             self._on_content_size)

        # Content preview — uses theme.get("body") so size changes show live
        self._content_preview = ctk.CTkLabel(
            card,
            text="The quick brown fox jumps over the lazy dog.  ← live body preview",
            font=theme.get("body"),
            text_color=_TEXT, anchor="w", justify="left", wraplength=560)
        self._content_preview.grid(row=2, column=0, sticky="w", pady=(4, 8))

        ctk.CTkFrame(card, height=1, fg_color=theme.color("divider")).grid(
            row=3, column=0, sticky="ew", pady=4)

        # Log tier — segmented button row
        self._build_font_row(card, 4,
                             "Log & output text",
                             "(Scan log, event feeds, network rows)",
                             "display_font_log_size",
                             _LOG_SIZES,
                             self._on_log_size)

        # Log preview — uses theme.get("log") so size and mono changes show live
        self._log_preview = ctk.CTkLabel(
            card,
            text="[12:34:56] scan complete — 0 infected, 1,247 clean  ← live log preview",
            font=theme.get("log"),
            text_color=_TEXT, anchor="w", justify="left", wraplength=560)
        self._log_preview.grid(row=6, column=0, sticky="w", pady=(4, 8))

        # Monospace toggle
        mono_row = ctk.CTkFrame(card, fg_color="transparent")
        mono_row.grid(row=7, column=0, sticky="ew", pady=(8, 0))
        mono_row.grid_columnconfigure(1, weight=1)

        current_mono = cfg.get("display_log_monospace")
        if current_mono is None:
            current_mono = True
        self._mono_switch = ctk.CTkSwitch(
            mono_row, text="Use monospace font (Consolas) for log & output text",
            font=ctk.CTkFont(size=12), text_color=_TEXT,
            command=self._on_mono_toggle,
            onvalue=True, offvalue=False,
        )
        self._mono_switch.grid(row=0, column=0, sticky="w")
        if current_mono:
            self._mono_switch.select()
        else:
            self._mono_switch.deselect()

        ctk.CTkLabel(card,
                     text="Previews above update live. Changes also appear in Help, Guardian AI, "
                          "Update, and the Scan log. UI chrome (buttons, nav labels) uses fixed "
                          "sizes to prevent layout breakage.",
                     font=ctk.CTkFont(size=11), text_color=_DIM, anchor="w",
                     wraplength=560, justify="left").grid(
            row=8, column=0, sticky="w", pady=(6, 0))

        return start_row + 1

    def _build_font_row(self, parent, base_row: int,
                        label: str, sublabel: str,
                        setting_key: str,
                        options: list[tuple[str, int]],
                        callback) -> None:
        row_frame = ctk.CTkFrame(parent, fg_color="transparent")
        row_frame.grid(row=base_row, column=0, sticky="ew", pady=(0, 4))
        row_frame.grid_columnconfigure(1, weight=1)

        lbl_frame = ctk.CTkFrame(row_frame, fg_color="transparent", width=180)
        lbl_frame.grid(row=0, column=0, sticky="w")
        lbl_frame.grid_propagate(False)
        ctk.CTkLabel(lbl_frame, text=label, font=ctk.CTkFont(size=13),
                     text_color=_TEXT, anchor="w").grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(lbl_frame, text=sublabel, font=ctk.CTkFont(size=10),
                     text_color=_DIM, anchor="w").grid(row=1, column=0, sticky="w")

        current_size = int(cfg.get(setting_key) or options[1][1])
        labels = [o[0] for o in options]
        seg = ctk.CTkSegmentedButton(
            row_frame,
            values=labels,
            font=ctk.CTkFont(size=12),
            command=lambda v, opts=options, cb=callback: cb(
                next((sz for lbl, sz in opts if lbl == v), opts[1][1])
            ),
        )
        # Select the matching segment
        for lbl, sz in options:
            if sz == current_size:
                seg.set(lbl)
                break
        seg.grid(row=0, column=1, sticky="e", padx=(12, 0), rowspan=2)

        # Separator
        ctk.CTkFrame(parent, height=1, fg_color=theme.color("divider")).grid(
            row=base_row + 1, column=0, sticky="ew", pady=4)

    def _on_content_size(self, size: int) -> None:
        cfg.set_value("display_font_content_size", size)
        theme.set_content_size(size)
        self._status_cb(f"Content font size: {size}pt")

    def _on_log_size(self, size: int) -> None:
        cfg.set_value("display_font_log_size", size)
        theme.set_log_size(size)
        self._status_cb(f"Log font size: {size}pt")

    def _on_mono_toggle(self) -> None:
        mono = bool(self._mono_switch.get())
        cfg.set_value("display_log_monospace", mono)
        theme.set_log_monospace(mono)
        self._status_cb("Log font: " + ("Consolas (monospace)" if mono else "proportional"))

    # ── Section 5: Widget Scale ───────────────────────────────────────────────

    def _build_widget_scale(self, start_row: int) -> int:
        card = self._section_card("Widget Scale", start_row)
        card.grid_columnconfigure(0, weight=1)

        current_scale = float(cfg.get("display_widget_scale") or 1.0)
        self._scale_btns: list[ctk.CTkButton] = []

        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.grid(row=0, column=0, sticky="w", pady=(0, 8))

        for i, (lbl, val) in enumerate(_SCALE_OPTIONS):
            is_active = abs(val - current_scale) < 0.01
            btn = ctk.CTkButton(
                btn_row, text=lbl, width=70,
                fg_color=theme.color("accent") if is_active else "#2a2a3a",
                hover_color="#3a6ab0",
                text_color="#ffffff",
                font=ctk.CTkFont(size=12),
                command=lambda v=val, lb=lbl: self._set_scale(v, lb),
            )
            btn.grid(row=0, column=i, padx=(0, 6))
            self._scale_btns.append(btn)

        # Amber warning note
        warning = ctk.CTkFrame(card, fg_color="#2a1e00", corner_radius=6)
        warning.grid(row=1, column=0, sticky="ew", pady=(0, 0))
        ctk.CTkLabel(warning,
                     text="⚠  Scale changes take effect after restarting PolyShield.",
                     font=ctk.CTkFont(size=12), text_color="#ffb86c").pack(
            padx=12, pady=8, anchor="w")

        return start_row + 1

    def _set_scale(self, val: float, label: str) -> None:
        try:
            cfg.set_value("display_widget_scale", val)
            # Update button highlights
            for btn, (lbl_text, lbl_val) in zip(self._scale_btns, _SCALE_OPTIONS):
                is_active = abs(lbl_val - val) < 0.01
                btn.configure(fg_color=theme.color("accent") if is_active else "#2a2a3a")
            self._status_cb(f"Widget scale set to {label} — restart to apply")
        except Exception as e:
            import traceback
            traceback.print_exc()
            self._status_cb(f"⚠ Scale error: {type(e).__name__}: {e}")

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _section_card(self, title: str, parent_row: int) -> ctk.CTkFrame:
        """Create a titled card section and return its content frame.

        The title label is stored in self._section_title_labels so
        _refresh_section_titles() can update accent colours on theme change.
        """
        outer = ctk.CTkFrame(self, fg_color=_CARD, corner_radius=10)
        outer.grid(row=parent_row, column=0, sticky="ew", padx=24, pady=(0, 12))
        outer.grid_columnconfigure(0, weight=1)

        lbl = ctk.CTkLabel(outer, text=title,
                           font=ctk.CTkFont(size=14, weight="bold"),
                           text_color=theme.color("accent"), anchor="w")
        lbl.grid(row=0, column=0, sticky="w", padx=16, pady=(12, 4))
        # Track all section title labels so we can re-colour them on theme change
        if not hasattr(self, "_section_title_labels"):
            self._section_title_labels: list[ctk.CTkLabel] = []
        self._section_title_labels.append(lbl)

        ctk.CTkFrame(outer, height=1, fg_color=theme.color("divider")).grid(
            row=1, column=0, sticky="ew", padx=16, pady=(0, 8))

        content = ctk.CTkFrame(outer, fg_color="transparent")
        content.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 12))
        content.grid_columnconfigure(0, weight=1)
        return content

    def _refresh_section_titles(self) -> None:
        """Re-colour all section card titles to match the current accent."""
        accent = theme.color("accent")
        for lbl in getattr(self, "_section_title_labels", []):
            try:
                lbl.configure(text_color=accent)
            except Exception:
                pass

    def _refresh_controls(self) -> None:
        """Sync all controls to current settings values (called on on_show)."""
        # Preset borders
        current_preset = cfg.get("display_theme_preset") or "classic"
        for k, btn in self._preset_btns.items():
            palette = theme.preset_palette(k)
            btn.configure(border_color=palette["accent"] if k == current_preset else "#2a2a3a")

        # Accent chip borders + checkmarks
        current_accent = (cfg.get("display_accent_color") or "").lower()
        for hv, chip in self._accent_chips.items():
            active = (hv.lower() == current_accent)
            chip.configure(
                border_color="#ffffff" if active else hv,
                text="✓" if active else "",
            )

        # Image path label
        self._bg_path_lbl.configure(text=self._short_path())

        # Sliders
        self._opacity_slider.set((cfg.get("display_bg_opacity") or 0.15) * 100)
        self._blur_slider.set(int(cfg.get("display_bg_blur") or 0))
        self._opacity_lbl.configure(text=f"{int(self._opacity_slider.get())}%")
        self._blur_lbl.configure(text=f"Blur: {int(self._blur_slider.get())}")

        # Mono switch
        mono = cfg.get("display_log_monospace")
        if mono is None:
            mono = True
        if mono:
            self._mono_switch.select()
        else:
            self._mono_switch.deselect()

        # Scale buttons
        current_scale = float(cfg.get("display_widget_scale") or 1.0)
        for btn, (_, val) in zip(self._scale_btns, _SCALE_OPTIONS):
            btn.configure(fg_color=theme.color("accent") if abs(val - current_scale) < 0.01 else "#2a2a3a")

        # Section title accent colours
        self._refresh_section_titles()
