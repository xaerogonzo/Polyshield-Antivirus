import subprocess
import time
import threading
from tkinter import filedialog
import customtkinter as ctk
from pathlib import Path
import ui.theme as theme

from ui.core import scanner as sc
from ui.core import settings as cfg
from ui.core import scan_presets as presets
from ui.core import virustotal as vt
from ui.core import guardian_engine as ge
from ui.core import yara_engine as ye
from ui.core import clamav_engine as ce
from ui.core import defender as df
from ui.views.threat_actions_mixin import _ThreatActionsMixin

try:
    from ui.core import emulate_engine as ee
    _SPEAKEASY_AVAIL = True
except ImportError:
    ee = None
    _SPEAKEASY_AVAIL = False

try:
    from tkinterdnd2 import DND_FILES
    _DND_AVAILABLE = True
except ImportError:
    _DND_AVAILABLE = False

_TAG_INFECTED  = "infected"
_TAG_CLEAN     = "clean"
_TAG_WARN      = "warn"
_TAG_INFO      = "info"
_TAG_GUARDIAN  = "guardian"
_TAG_YARA      = "yara"
_TAG_CLAMAV    = "clamav"
_TAG_DEFENDER  = "defender"
_TAG_SPEAKEASY = "speakeasy"

_KEYWORDS_INFECTED = ("infected", "virus", "malware", "threat", "trojan", "worm", "ransom")
_KEYWORDS_CLEAN    = ("ok", "clean", "no threat")
_KEYWORDS_WARN     = ("warning", "suspect", "suspicious")


def _classify(line: str) -> str:
    ll = line.lower()
    if any(k in ll for k in _KEYWORDS_INFECTED):
        return _TAG_INFECTED
    if any(k in ll for k in _KEYWORDS_CLEAN):
        return _TAG_CLEAN
    if any(k in ll for k in _KEYWORDS_WARN):
        return _TAG_WARN
    return _TAG_INFO


def _format_eta(seconds: float) -> str:
    if seconds <= 0:
        return "—"
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60}s"
    return f"{s // 3600}h {(s % 3600) // 60}m"


def _human_size(n: int) -> str:
    """Human-readable byte count (1.5 KB, 3.2 MB, etc.)."""
    if n < 1024:
        return f"{n} B"
    units = ["KB", "MB", "GB", "TB"]
    val = float(n) / 1024.0
    for u in units:
        if val < 1024 or u == units[-1]:
            return f"{val:.1f} {u}"
        val /= 1024.0
    return f"{n} B"


class ScanView(_ThreatActionsMixin, ctk.CTkFrame):
    def __init__(self, master, status_callback, navigate_callback=None, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self._status_cb = status_callback
        self._nav_cb    = navigate_callback   # optional: (view_key, *args) -> None
        self._scanning = False
        self._paused  = False
        self._paths: list[str] = []
        self._preset = "Custom"
        self._scan_start_time: float = 0.0
        self._scan_total: int = 0
        self._last_report_path: str | None = None
        self._scan_ctrl = None          # ScanController, set in _start_scan
        self._k2_infected_paths: list[str] = []
        self._g_infected: dict[str, str] = {}
        self._yara_infected: dict[str, str] = {}
        self._clamav_infected: dict[str, str] = {}
        # Pipeline state
        self._pipeline_expanded: bool = True
        self._pipeline_cancel_event: threading.Event | None = None
        self._pipeline_pause_event: threading.Event | None = None
        # Tracks which engine is currently running, for pause-status messages
        self._active_engine_label: str = ""
        self._engine_queue: list = []        # ordered list of engine run-functions
        self._secondary_paths: list[str] = []
        self._defender_infected: dict[str, str] = {}
        self._speakeasy_infected: dict[str, str] = {}
        # Pipeline panel — availability snapshots (set in _build_pipeline_panel)
        self._secondary_rows_frame: ctk.CTkFrame | None = None
        self._k2_ok:       bool = False
        self._guardian_ok: bool = False
        self._yara_ok:     bool = False
        self._clamav_ok:   bool = False
        self._defender_ok: bool = False
        self._yara_cnt:    int  = 0
        self._clam_ver:    str  = ""
        # User-defined scan path presets
        self._user_preset_var:      ctk.StringVar | None = None
        self._user_preset_menu:     ctk.CTkOptionMenu | None = None
        self._user_preset_del_btn:  ctk.CTkButton | None = None
        self._loading_user_preset:  bool = False   # suppress path-clear during load
        # Pipeline D&D drag state
        self._drag_engine_id:    str | None = None
        self._drag_hover_engine: str | None = None
        self._drag_row_registry: dict = {}   # engine_id → row CTkFrame
        # v1.9: Threat Actions master-detail state
        self._threat_page:            int  = 0
        self._threat_page_size:       int  = 50
        self._threat_filter_text:     str  = ""
        self._threat_filter_reason:   str  = "all"      # all|known|heuristic|dispute|resolved|suspicious
        self._threat_checked:         set[str] = set()
        self._threat_selected_path:   str | None = None
        self._threat_resolved:        set[str] = set()  # paths the user has resolved
        self._threat_resolution:      dict[str, str] = {}  # path -> "quarantined"|"kept"|"ignored"|"trust_k2"|"trust_guardian"
        self._disputes:               list[dict] = []
        self._hash_cache:             dict[str, dict] = {}   # path -> {md5, sha256, size, preview}
        self._row_registry:           dict = {}              # path -> row CTkFrame (current page)
        self._bulk_cancel_event:      threading.Event | None = None
        # v1.10 Guardian tier-aware state
        self._threat_severity:        dict[str, str] = {}    # path -> "confirmed"|"suspicious"
        self._g_tier:                 dict[str, str] = {}    # path -> guardian tier
        self._g_context:              dict[str, str] = {}    # path -> regex match context snippet
        self._circuit_state:          dict = {}              # populated by guardian when circuit trips
        self._circuit_banner_dismissed: bool = False
        self._scan_session_ignored:   dict[str, int] = {}    # pattern -> count of ignores this scan
        self._heuristic_collapsed:    bool = True            # for "collapsible" display mode
        # Frames built lazily inside _threat_actions_frame
        self._threat_pagination_frame: ctk.CTkFrame | None = None
        self._threat_master_frame:     ctk.CTkScrollableFrame | None = None
        self._threat_detail_frame:     ctk.CTkScrollableFrame | None = None
        self._threat_bulk_frame:       ctk.CTkFrame | None = None
        self._threat_dispute_banner:   ctk.CTkLabel | None = None
        self._threat_circuit_banner:   ctk.CTkFrame | None = None
        # Theme: list of (widget, {attr: token}) for live theme refresh
        self._themed: list = []
        self._build()

    def _refresh_theme(self) -> None:
        """Re-apply current theme colours to all registered widgets."""
        theme.refresh(self._themed)

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(6, weight=1)   # log row

        # ── Row 0: Title ──
        ctk.CTkLabel(self, text="Scan",
                     font=ctk.CTkFont(size=22, weight="bold")).grid(
            row=0, column=0, sticky="w", padx=24, pady=(20, 6))

        # ── Row 1: Preset selector ──
        self._preset_frame = ctk.CTkFrame(self, fg_color="transparent")
        self._preset_frame.grid(row=1, column=0, sticky="ew", padx=24, pady=(0, 6))
        self._preset_frame.grid_columnconfigure(1, weight=1)

        _scan_type_lbl = ctk.CTkLabel(self._preset_frame, text="Scan type:",
                                       font=ctk.CTkFont(size=12))
        _scan_type_lbl.grid(row=0, column=0, padx=(0, 10), sticky="w")
        theme.register(self._themed, _scan_type_lbl, text_color="subtext")

        self._preset_btn = ctk.CTkSegmentedButton(
            self._preset_frame,
            values=presets.PRESETS,
            command=self._on_preset_change,
            font=ctk.CTkFont(size=12),
        )
        self._preset_btn.set("Custom")
        self._preset_btn.grid(row=0, column=1, sticky="w")

        # ── Row 1b: User-defined scan path presets ──
        _my_presets_lbl = ctk.CTkLabel(self._preset_frame, text="My presets:",
                                        font=ctk.CTkFont(size=12))
        _my_presets_lbl.grid(row=1, column=0, padx=(0, 10), pady=(4, 0), sticky="w")
        theme.register(self._themed, _my_presets_lbl, text_color="subtext")

        _up_inner = ctk.CTkFrame(self._preset_frame, fg_color="transparent")
        _up_inner.grid(row=1, column=1, sticky="w", pady=(4, 0))

        _preset_names = self._get_user_preset_names()
        self._user_preset_var = ctk.StringVar(
            value=_preset_names[0] if _preset_names else "— no presets saved —")
        self._user_preset_menu = ctk.CTkOptionMenu(
            _up_inner,
            values=_preset_names if _preset_names else ["— no presets saved —"],
            variable=self._user_preset_var,
            command=self._on_user_preset_select,
            width=200, height=28,
            font=ctk.CTkFont(size=12),
            state="normal" if _preset_names else "disabled",
        )
        self._user_preset_menu.grid(row=0, column=0, padx=(0, 6))

        ctk.CTkButton(
            _up_inner, text="💾  Save", width=76, height=28,
            fg_color="#2a3a2e", hover_color="#3a5a3e",
            font=ctk.CTkFont(size=11),
            command=self._save_as_user_preset,
        ).grid(row=0, column=1, padx=(0, 4))

        self._user_preset_del_btn = ctk.CTkButton(
            _up_inner, text="🗑  Delete", width=80, height=28,
            fg_color="#3a1a1a", hover_color="#5a2020",
            font=ctk.CTkFont(size=11),
            state="disabled",
            command=self._delete_user_preset,
        )
        self._user_preset_del_btn.grid(row=0, column=2)

        # ── Row 2: Drop zone ──
        self._drop_frame = ctk.CTkFrame(self, height=90, corner_radius=12,
                                        border_width=2)
        self._drop_frame.grid(row=2, column=0, sticky="ew", padx=24, pady=(0, 6))
        self._drop_frame.grid_propagate(False)
        self._drop_frame.grid_columnconfigure(0, weight=1)
        self._drop_frame.grid_rowconfigure(0, weight=1)
        theme.register(self._themed, self._drop_frame, border_color="divider")

        self._drop_label = ctk.CTkLabel(
            self._drop_frame, text="Drop files or folders here",
            font=ctk.CTkFont(size=13),
        )
        self._drop_label.grid(row=0, column=0)
        theme.register(self._themed, self._drop_label, text_color="subtext")

        if _DND_AVAILABLE:
            self._drop_frame.drop_target_register(DND_FILES)
            self._drop_frame.dnd_bind("<<Drop>>", self._on_drop)

        # ── Row 3: Toolbar ──
        toolbar = ctk.CTkFrame(self, fg_color="transparent")
        toolbar.grid(row=3, column=0, sticky="ew", padx=24, pady=(0, 4))
        toolbar.grid_columnconfigure(3, weight=1)

        self._browse_file_btn = ctk.CTkButton(
            toolbar, text="Browse File", width=115,
            command=self._browse_file)
        self._browse_file_btn.grid(row=0, column=0, padx=(0, 6))
        theme.register(self._themed, self._browse_file_btn,
                       fg_color="nav_active", hover_color="accent_hover")

        self._browse_folder_btn = ctk.CTkButton(
            toolbar, text="Browse Folder", width=125,
            command=self._browse_folder)
        self._browse_folder_btn.grid(row=0, column=1, padx=(0, 6))
        theme.register(self._themed, self._browse_folder_btn,
                       fg_color="nav_active", hover_color="accent_hover")

        self._startup_btn = ctk.CTkButton(
            toolbar, text="Startup Items", width=115,
            command=self._load_startup_items)
        self._startup_btn.grid(row=0, column=2, padx=(0, 16))
        theme.register(self._themed, self._startup_btn,
                       fg_color="nav_active", hover_color="accent_hover")

        ctk.CTkLabel(toolbar, text="On threat:").grid(
            row=0, column=4, padx=(0, 6))
        self._action_var = ctk.StringVar(value="quarantine")
        ctk.CTkOptionMenu(toolbar, values=["quarantine", "delete", "report_only"],
                          variable=self._action_var, width=145).grid(
            row=0, column=5, padx=(0, 12))

        self._scan_btn = ctk.CTkButton(
            toolbar, text="Start Scan", width=130,
            command=self._start_scan)
        self._scan_btn.grid(row=0, column=6)
        theme.register(self._themed, self._scan_btn,
                       fg_color="accent", hover_color="accent_hover")

        _clear_btn = ctk.CTkButton(toolbar, text="Clear", width=75,
                                    command=self._clear)
        _clear_btn.grid(row=0, column=7, padx=(8, 0))
        theme.register(self._themed, _clear_btn,
                       fg_color="input_bg", hover_color="input_hover")

        # ── Row 4: Scan Pipeline panel ──
        self._build_pipeline_panel()

        # ── Row 5: Progress section (hidden until scan starts) ──
        self._progress_frame = ctk.CTkFrame(self, corner_radius=8)
        self._progress_frame.grid(row=5, column=0, sticky="ew", padx=24, pady=(0, 6))
        self._progress_frame.grid_columnconfigure(0, weight=1)
        theme.register(self._themed, self._progress_frame, fg_color="card")

        top = ctk.CTkFrame(self._progress_frame, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=12, pady=(10, 4))
        top.grid_columnconfigure(0, weight=1)

        self._progress_bar = ctk.CTkProgressBar(top, height=14, corner_radius=6)
        self._progress_bar.set(0)
        self._progress_bar.grid(row=0, column=0, sticky="ew", padx=(0, 10))

        self._pct_lbl = ctk.CTkLabel(top, text="0%", width=40,
                                      font=ctk.CTkFont(size=12))
        self._pct_lbl.grid(row=0, column=1)
        theme.register(self._themed, self._pct_lbl, text_color="text")

        self._eta_lbl = ctk.CTkLabel(top, text="ETA: —", width=90,
                                      font=ctk.CTkFont(size=12), anchor="e")
        self._eta_lbl.grid(row=0, column=2)
        theme.register(self._themed, self._eta_lbl, text_color="subtext")

        # Pause / Stop buttons live inside the progress frame
        self._pause_btn = ctk.CTkButton(
            top, text="⏸  Pause", width=90,
            fg_color="#4a4a20", hover_color="#6a6a28",
            font=ctk.CTkFont(size=12),
            command=self._toggle_pause)
        self._pause_btn.grid(row=0, column=3, padx=(10, 4))

        self._stop_btn = ctk.CTkButton(
            top, text="■  Stop", width=80,
            fg_color="#5a1a1a", hover_color="#7a2020",
            font=ctk.CTkFont(size=12),
            command=self._stop_scan)
        self._stop_btn.grid(row=0, column=4, padx=(0, 4))

        self._current_file_lbl = ctk.CTkLabel(
            self._progress_frame, text="",
            font=ctk.CTkFont(family="Consolas", size=11),
            anchor="w")
        self._current_file_lbl.grid(row=1, column=0, sticky="ew", padx=14, pady=(0, 8))
        theme.register(self._themed, self._current_file_lbl, text_color="subtext")

        # Pause indicator — shown only while paused
        self._paused_lbl = ctk.CTkLabel(
            top, text="⏸  PAUSED",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#ffb86c")
        self._paused_lbl.grid(row=1, column=0, columnspan=5, sticky="e",
                              padx=(0, 4), pady=(2, 0))
        self._paused_lbl.grid_remove()   # hidden until first pause

        # Initially disabled — enabled when scan is running
        self._pause_btn.configure(state="disabled")
        self._stop_btn.configure(state="disabled")
        self._progress_frame.grid_remove()

        # ── Row 6: Live log ──
        self._log = ctk.CTkTextbox(self, font=theme.get("log"),
                                   wrap="word", state="disabled")
        self._log.grid(row=6, column=0, sticky="nsew", padx=24, pady=(0, 6))
        self._log.tag_config(_TAG_INFECTED,  foreground="#ff5555")
        self._log.tag_config(_TAG_CLEAN,     foreground="#50fa7b")
        self._log.tag_config(_TAG_WARN,      foreground="#ffb86c")
        self._log.tag_config(_TAG_INFO,      foreground="#cdd6f4")
        self._log.tag_config(_TAG_GUARDIAN,  foreground="#f1fa8c")
        self._log.tag_config(_TAG_YARA,      foreground="#bd93f9")
        self._log.tag_config(_TAG_CLAMAV,    foreground="#8be9fd")
        self._log.tag_config(_TAG_DEFENDER,  foreground="#ff5555")
        self._log.tag_config(_TAG_SPEAKEASY, foreground="#bd93f9")

        # ── Row 7: Summary bar ──
        summary = ctk.CTkFrame(self, height=36, corner_radius=8)
        summary.grid(row=7, column=0, sticky="ew", padx=24, pady=(0, 4))
        theme.register(self._themed, summary, fg_color="card2")
        summary.grid_propagate(False)
        summary.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self._lbl_scanned  = self._summary_label(summary, "Scanned: —", 0)
        self._lbl_infected = self._summary_label(summary, "Infected: —", 1, "#ff5555")
        self._lbl_clean    = self._summary_label(summary, "Clean: —",   2, "#50fa7b")
        self._lbl_elapsed  = self._summary_label(summary, "Time: —",    3)

        # ── Row 8: VirusTotal verify panel (hidden until needed) ──
        self._vt_frame = ctk.CTkFrame(self, corner_radius=8)
        self._vt_frame.grid(row=8, column=0, sticky="ew", padx=24, pady=(0, 16))
        self._vt_frame.grid_columnconfigure(0, weight=1)
        self._vt_frame.grid_remove()
        theme.register(self._themed, self._vt_frame, fg_color="card")

        vt_header = ctk.CTkFrame(self._vt_frame, fg_color="transparent")
        vt_header.grid(row=0, column=0, sticky="ew", padx=14, pady=(10, 4))
        vt_header.grid_columnconfigure(0, weight=1)

        self._vt_title = ctk.CTkLabel(
            vt_header, text="VirusTotal Verification",
            font=ctk.CTkFont(size=12, weight="bold"),
            anchor="w")
        self._vt_title.grid(row=0, column=0, sticky="w")
        theme.register(self._themed, self._vt_title, text_color="accent")

        self._vt_status = ctk.CTkLabel(
            vt_header, text="", font=ctk.CTkFont(size=11))
        self._vt_status.grid(row=0, column=1, sticky="e")
        theme.register(self._themed, self._vt_status, text_color="subtext")

        self._vt_rows_frame = ctk.CTkFrame(self._vt_frame, fg_color="transparent")
        self._vt_rows_frame.grid(row=1, column=0, sticky="ew", padx=14, pady=(0, 10))
        self._vt_rows_frame.grid_columnconfigure(0, weight=1)

        # ── Row 9: Threat Actions panel (hidden until scan finds threats) ──
        self._threat_actions_frame = ctk.CTkFrame(self, corner_radius=8)
        self._threat_actions_frame.grid(row=9, column=0, sticky="ew",
                                        padx=24, pady=(0, 16))
        self._threat_actions_frame.grid_columnconfigure(0, weight=1)
        self._threat_actions_frame.grid_remove()
        theme.register(self._themed, self._threat_actions_frame, fg_color="card")

    # ── Pipeline panel ────────────────────────────────────────────────────────

    def _build_pipeline_panel(self):
        """Build the collapsible Scan Pipeline panel (row 4)."""
        # Gather availability once
        k2_ok        = sc.is_available()
        guardian_ok  = ge.is_available()
        yara_ok      = ye.is_available()
        clamav_ok    = ce.is_available()
        defender_ok  = df.is_mpcmdrun_available()
        try:
            speakeasy_ok = _SPEAKEASY_AVAIL and ee is not None and ee.is_available()
        except Exception:
            speakeasy_ok = False

        # BooleanVars
        self._k2_var        = ctk.BooleanVar(
            value=cfg.get("pipeline_k2") if k2_ok else False)
        self._guardian_var  = ctk.BooleanVar(
            value=cfg.get("guardian_dual_scan") if guardian_ok else False)
        self._yara_var      = ctk.BooleanVar(
            value=cfg.get("yara_scan") if yara_ok else False)
        self._clamav_var    = ctk.BooleanVar(
            value=cfg.get("clamav_scan") if clamav_ok else False)
        self._defender_var  = ctk.BooleanVar(
            value=cfg.get("pipeline_defender") if defender_ok else False)
        self._speakeasy_var = ctk.BooleanVar(
            value=cfg.get("pipeline_speakeasy") if speakeasy_ok else False)

        # Outer container
        self._pipeline_outer = ctk.CTkFrame(self, fg_color="transparent")
        self._pipeline_outer.grid(row=4, column=0, sticky="ew", padx=24, pady=(0, 4))
        self._pipeline_outer.grid_columnconfigure(0, weight=1)

        # Toggle header button (built after vars so step count is accurate)
        self._pipeline_toggle_btn = ctk.CTkButton(
            self._pipeline_outer,
            text=self._pipeline_header_text(),
            anchor="w",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._toggle_pipeline_panel,
        )
        self._pipeline_toggle_btn.grid(row=0, column=0, sticky="ew", pady=(0, 2))
        theme.register(self._themed, self._pipeline_toggle_btn,
                       fg_color="card2", hover_color="divider")

        # Inner collapsible panel
        self._pipeline_inner = ctk.CTkFrame(
            self._pipeline_outer, corner_radius=8, border_width=1)
        self._pipeline_inner.grid(row=1, column=0, sticky="ew")
        self._pipeline_inner.grid_columnconfigure(0, weight=1)
        theme.register(self._themed, self._pipeline_inner,
                       fg_color="card", border_color="divider")

        yara_cnt = ye.get_rule_count() if yara_ok else 0
        clam_ver = ce.get_version() if clamav_ok else ""

        # Cache availability for use in _build_secondary_rows (called on reorder too)
        self._k2_ok       = k2_ok
        self._guardian_ok = guardian_ok
        self._yara_ok     = yara_ok
        self._clamav_ok   = clamav_ok
        self._defender_ok = defender_ok
        self._yara_cnt    = yara_cnt
        self._clam_ver    = clam_ver

        def _row(parent, row_idx, var, label, badge, badge_color, state, cmd):
            bg = theme.color("card2") if row_idx % 2 == 0 else theme.color("card")
            rf = ctk.CTkFrame(parent, fg_color=bg, corner_radius=4)
            rf.grid(row=row_idx, column=0, sticky="ew", pady=1, padx=4)
            rf.grid_columnconfigure(1, weight=1)
            ctk.CTkCheckBox(
                rf, text=label, variable=var,
                font=ctk.CTkFont(size=12), state=state,
                text_color=theme.color("text") if state == "normal" else theme.color("dim"),
                command=cmd, width=180,
            ).grid(row=0, column=0, padx=(12, 8), pady=6, sticky="w")
            ctk.CTkLabel(
                rf, text=badge, font=ctk.CTkFont(size=11),
                text_color=badge_color, anchor="w",
            ).grid(row=0, column=1, sticky="w")

        # ── Row 0: header note ────────────────────────────────────────────────
        _pipe_note = ctk.CTkLabel(
            self._pipeline_inner,
            text="  Engines run in listed order — drag with ↑/↓",
            font=ctk.CTkFont(size=10), anchor="w")
        _pipe_note.grid(row=0, column=0, sticky="ew", padx=8, pady=(4, 0))
        theme.register(self._themed, _pipe_note, text_color="subtext")

        # ── Row 1: reorderable engine rows (K2, Defender, Guardian, YARA, ClamAV)
        self._secondary_rows_frame = ctk.CTkFrame(
            self._pipeline_inner, fg_color="transparent")
        self._secondary_rows_frame.grid(row=1, column=0, sticky="ew")
        self._secondary_rows_frame.grid_columnconfigure(0, weight=1)
        self._build_secondary_rows(self._secondary_rows_frame)

        # ── Row 2: Reset order button ─────────────────────────────────────────
        _reset_bar = ctk.CTkFrame(self._pipeline_inner, fg_color="transparent")
        _reset_bar.grid(row=2, column=0, sticky="ew", padx=4, pady=(0, 2))
        _reset_bar.grid_columnconfigure(0, weight=1)
        _reset_btn = ctk.CTkButton(
            _reset_bar, text="↺  Reset order", width=110, height=22,
            font=ctk.CTkFont(size=10),
            command=self._reset_pipeline_order)
        _reset_btn.grid(row=0, column=0, sticky="e", padx=4)
        theme.register(self._themed, _reset_btn,
                       fg_color="input_bg", hover_color="input_hover")

        # ── Row 3: Speakeasy (always last — not reorderable) ──────────────────
        spk_badge = ("● always last — emulates flagged PEs"
                     if speakeasy_ok else "○ always last — not installed")
        _row(self._pipeline_inner, 3,
             self._speakeasy_var, "Speakeasy",
             spk_badge, "#50fa7b" if speakeasy_ok else "#888888",
             "normal" if speakeasy_ok else "disabled",
             self._on_speakeasy_toggle)

        # ── Rows 4–5: manual-only entries ─────────────────────────────────────
        r = 4
        for manual_label, manual_note in [
            ("Sandboxie",   "— manual via Threat Actions"),
            ("VirusTotal",  "— manual via Threat Actions"),
        ]:
            bg = theme.color("card2") if r % 2 == 0 else theme.color("card")
            rf = ctk.CTkFrame(self._pipeline_inner, fg_color=bg, corner_radius=4)
            rf.grid(row=r, column=0, sticky="ew", pady=1, padx=4)
            rf.grid_columnconfigure(1, weight=1)
            ctk.CTkLabel(rf, text=f"  {manual_label}",
                         font=ctk.CTkFont(size=12), text_color=theme.color("dim"),
                         width=196, anchor="w").grid(
                row=0, column=0, padx=(12, 8), pady=6, sticky="w")
            ctk.CTkLabel(rf, text=manual_note,
                         font=ctk.CTkFont(size=11), text_color=theme.color("dim"),
                         anchor="w").grid(row=0, column=1, sticky="w")
            r += 1

    def _pipeline_header_text(self) -> str:
        enabled = sum([
            bool(self._k2_var.get()),
            bool(self._guardian_var.get()),
            bool(self._yara_var.get()),
            bool(self._clamav_var.get()),
            bool(self._defender_var.get()),
            bool(self._speakeasy_var.get()),
        ])
        arrow = "▼" if self._pipeline_expanded else "►"
        return f"{arrow} Scan Pipeline  ({enabled} step{'s' if enabled != 1 else ''} enabled)"

    def _toggle_pipeline_panel(self):
        self._pipeline_expanded = not self._pipeline_expanded
        if self._pipeline_expanded:
            self._pipeline_inner.grid()
        else:
            self._pipeline_inner.grid_remove()
        self._pipeline_toggle_btn.configure(text=self._pipeline_header_text())

    def _update_pipeline_header(self):
        if hasattr(self, "_pipeline_toggle_btn"):
            self._pipeline_toggle_btn.configure(text=self._pipeline_header_text())

    _DEFAULT_PIPELINE_ORDER = ["k2", "defender", "guardian", "yara", "clamav"]

    def _normalized_pipeline_order(self) -> list[str]:
        """
        Return the saved pipeline_order with any newly-introduced engines
        appended at their default position (handles users upgrading from
        v1.6.0 settings that lacked 'k2').
        """
        saved = list(cfg.get("pipeline_order") or [])
        for i, eid in enumerate(self._DEFAULT_PIPELINE_ORDER):
            if eid not in saved:
                # Insert at default position (or end if position is out of range)
                saved.insert(min(i, len(saved)), eid)
        return saved

    def _build_secondary_rows(self, parent: ctk.CTkFrame) -> None:
        """
        Populate *parent* with engine rows in user-configured pipeline_order.
        Each row: drag-handle + checkbox + ↑/↓ move buttons + availability badge.
        K2 is a peer engine here (v1.6.1+) — reorderable like the rest.
        Called at build-time and again on every reorder.
        """
        self._drag_row_registry = {}   # reset for fresh build
        order = self._normalized_pipeline_order()
        meta = {
            "k2": (
                self._k2_var, "K2 Engine",
                "● ready" if self._k2_ok else "○ k2.exe not found",
                "#50fa7b" if self._k2_ok else "#888888",
                "normal" if self._k2_ok else "disabled",
                self._on_k2_toggle,
            ),
            "defender": (
                self._defender_var, "Defender",
                "● available" if self._defender_ok else "○ MpCmdRun.exe not found",
                "#50fa7b" if self._defender_ok else "#888888",
                "normal" if self._defender_ok else "disabled",
                self._on_defender_toggle,
            ),
            "guardian": (
                self._guardian_var, "Guardian AI",
                "● ready" if self._guardian_ok else "○ not installed",
                "#50fa7b" if self._guardian_ok else "#888888",
                "normal" if self._guardian_ok else "disabled",
                self._on_guardian_toggle,
            ),
            "yara": (
                self._yara_var, "YARA Rules",
                (f"● {self._yara_cnt} rule file{'s' if self._yara_cnt != 1 else ''}"
                 if self._yara_ok else "○ add .yar files to rules/user_rules/ to enable"),
                "#50fa7b" if self._yara_ok else "#888888",
                "normal" if self._yara_ok else "disabled",
                self._on_yara_toggle,
            ),
            "clamav": (
                self._clamav_var, "ClamAV",
                (f"● {self._clam_ver}" if self._clamav_ok
                 else "○ install from clamav.net — configure path in Settings"),
                "#50fa7b" if self._clamav_ok else "#888888",
                "normal" if self._clamav_ok else "disabled",
                self._on_clamav_toggle,
            ),
        }
        n = len(order)
        for i, engine_id in enumerate(order):
            if engine_id not in meta:
                continue
            var, label, badge, badge_color, state, cmd = meta[engine_id]
            bg = theme.color("card2") if i % 2 == 0 else theme.color("card")
            rf = ctk.CTkFrame(parent, fg_color=bg, corner_radius=4)
            rf.grid(row=i, column=0, sticky="ew", pady=1, padx=4)
            # col 0: drag handle | col 1: checkbox | col 2: ↑ | col 3: ↓ | col 4: badge
            rf.grid_columnconfigure(4, weight=1)
            self._drag_row_registry[engine_id] = rf

            # ── Drag handle ──────────────────────────────────────────────────
            handle = ctk.CTkLabel(
                rf, text="⠿", width=18,
                font=ctk.CTkFont(size=14), text_color=theme.color("dim"),
                cursor="fleur",
            )
            handle.grid(row=0, column=0, padx=(6, 0), pady=6)
            handle.bind("<ButtonPress-1>",
                        lambda e, eid=engine_id: self._on_drag_start(eid, e))
            handle.bind("<B1-Motion>",   self._on_drag_motion)
            handle.bind("<ButtonRelease-1>", self._on_drag_end)

            # ── Checkbox ─────────────────────────────────────────────────────
            ctk.CTkCheckBox(
                rf, text=f"{i + 1}. {label}", variable=var,
                font=ctk.CTkFont(size=12), state=state,
                text_color=theme.color("text") if state == "normal" else theme.color("dim"),
                command=cmd, width=200,
            ).grid(row=0, column=1, padx=(4, 4), pady=6, sticky="w")

            # ── ↑/↓ buttons ──────────────────────────────────────────────────
            ctk.CTkButton(
                rf, text="↑", width=22, height=20,
                font=ctk.CTkFont(size=10),
                fg_color=theme.color("input_bg"), hover_color=theme.color("input_hover"),
                state="normal" if i > 0 else "disabled",
                command=lambda eid=engine_id: self._move_engine(eid, -1),
            ).grid(row=0, column=2, padx=(0, 2), pady=6)

            ctk.CTkButton(
                rf, text="↓", width=22, height=20,
                font=ctk.CTkFont(size=10),
                fg_color=theme.color("input_bg"), hover_color=theme.color("input_hover"),
                state="normal" if i < n - 1 else "disabled",
                command=lambda eid=engine_id: self._move_engine(eid, 1),
            ).grid(row=0, column=3, padx=(0, 8), pady=6)

            # ── Badge ─────────────────────────────────────────────────────────
            ctk.CTkLabel(
                rf, text=badge, font=ctk.CTkFont(size=11),
                text_color=badge_color, anchor="w",
            ).grid(row=0, column=4, sticky="w")

    def _rebuild_secondary_rows(self) -> None:
        """Destroy and recreate engine rows in the current pipeline_order."""
        if self._secondary_rows_frame and self._secondary_rows_frame.winfo_exists():
            self._secondary_rows_frame.destroy()
        self._secondary_rows_frame = ctk.CTkFrame(
            self._pipeline_inner, fg_color="transparent")
        self._secondary_rows_frame.grid(row=1, column=0, sticky="ew")
        self._secondary_rows_frame.grid_columnconfigure(0, weight=1)
        self._build_secondary_rows(self._secondary_rows_frame)
        self._pipeline_toggle_btn.configure(text=self._pipeline_header_text())

    def _move_engine(self, engine_id: str, direction: int) -> None:
        """Move *engine_id* up (-1) or down (+1) in pipeline_order, then rebuild rows."""
        order = self._normalized_pipeline_order()
        if engine_id not in order:
            return
        idx = order.index(engine_id)
        new_idx = idx + direction
        if new_idx < 0 or new_idx >= len(order):
            return
        order[idx], order[new_idx] = order[new_idx], order[idx]
        cfg.set_value("pipeline_order", order)
        self._rebuild_secondary_rows()

    def _reset_pipeline_order(self) -> None:
        """Restore the default engine order: K2 → Defender → Guardian → YARA → ClamAV."""
        cfg.set_value("pipeline_order", list(self._DEFAULT_PIPELINE_ORDER))
        self._rebuild_secondary_rows()

    # ── Pipeline D&D ──────────────────────────────────────────────────────────

    def _on_drag_start(self, engine_id: str, event) -> None:
        """Begin dragging an engine row."""
        self._drag_engine_id    = engine_id
        self._drag_hover_engine = None
        rf = self._drag_row_registry.get(engine_id)
        if rf and rf.winfo_exists():
            rf.configure(border_width=2, border_color=theme.color("accent"))

    def _on_drag_motion(self, event) -> None:
        """Update drop-target highlight as the mouse moves."""
        if not self._drag_engine_id:
            return
        target = self._get_engine_at_y(event.y_root)
        if target == self._drag_hover_engine:
            return
        # Clear old hover highlight
        if self._drag_hover_engine and self._drag_hover_engine != self._drag_engine_id:
            old = self._drag_row_registry.get(self._drag_hover_engine)
            if old and old.winfo_exists():
                old.configure(border_width=0)
        self._drag_hover_engine = target
        # Set new hover highlight (amber, different from dragged-row blue)
        if target and target != self._drag_engine_id:
            rf = self._drag_row_registry.get(target)
            if rf and rf.winfo_exists():
                rf.configure(border_width=1, border_color="#888844")

    def _on_drag_end(self, event) -> None:
        """Snap the dragged engine to the row under the cursor."""
        src = self._drag_engine_id
        if not src:
            return
        target = self._get_engine_at_y(event.y_root)
        # Clear all visual highlights before rebuilding
        self._drag_engine_id    = None
        self._drag_hover_engine = None
        if target and target != src:
            order = self._normalized_pipeline_order()
            if src in order and target in order:
                src_idx = order.index(src)
                tgt_idx = order.index(target)
                order.pop(src_idx)
                order.insert(tgt_idx, src)
                cfg.set_value("pipeline_order", order)
                self._rebuild_secondary_rows()
                return
        # No move — just remove the blue outline on the dragged row
        rf = self._drag_row_registry.get(src)
        if rf and rf.winfo_exists():
            rf.configure(border_width=0)

    def _get_engine_at_y(self, y_root: int) -> str | None:
        """Return the engine_id whose row midpoint is closest to y_root (screen coords)."""
        best_id   = None
        best_dist = float("inf")
        for eid, rf in self._drag_row_registry.items():
            try:
                if not rf.winfo_exists():
                    continue
                mid = rf.winfo_rooty() + rf.winfo_height() // 2
                dist = abs(y_root - mid)
                if dist < best_dist:
                    best_dist = dist
                    best_id   = eid
            except Exception:
                pass
        return best_id

    # ── User-defined scan path presets ────────────────────────────────────────

    def _get_user_preset_names(self) -> list[str]:
        return [p["name"] for p in (cfg.get("scan_path_presets") or [])]

    def _refresh_preset_menu(self) -> None:
        """Rebuild the user preset OptionMenu from settings."""
        if not self._user_preset_menu:
            return
        names = self._get_user_preset_names()
        if names:
            self._user_preset_menu.configure(
                values=names, state="normal")
        else:
            self._user_preset_menu.configure(
                values=["— no presets saved —"], state="disabled")
            if self._user_preset_var:
                self._user_preset_var.set("— no presets saved —")

    def _on_user_preset_select(self, name: str) -> None:
        """Load the chosen user preset into the drop zone."""
        if name.startswith("—"):
            return
        presets_list = cfg.get("scan_path_presets") or []
        for p in presets_list:
            if p["name"] == name:
                # Switch segmented button to Custom without clearing paths
                self._loading_user_preset = True
                self._preset_btn.set("Custom")
                self._loading_user_preset = False
                self._preset = "Custom"
                self._paths  = [pp for pp in p["paths"] if Path(pp).exists()]
                self._refresh_drop_label()
                self._browse_file_btn.grid()
                self._browse_folder_btn.grid()
                self._startup_btn.grid()
                if self._user_preset_del_btn:
                    self._user_preset_del_btn.configure(state="normal")
                skipped = len(p["paths"]) - len(self._paths)
                msg = f"Loaded preset '{name}' — {len(self._paths)} path(s)"
                if skipped:
                    msg += f" ({skipped} missing, skipped)"
                self._status_cb(msg)
                return

    def _save_as_user_preset(self) -> None:
        """Prompt for a name and save the current Custom paths as a preset."""
        if not self._paths:
            self._status_cb("No paths to save — add files/folders first")
            return
        dialog = ctk.CTkInputDialog(text="Enter a name for this preset:",
                                    title="Save Scan Preset")
        name = dialog.get_input()
        if not name:
            return
        name = name.strip()[:40]
        if not name:
            return
        presets_list = list(cfg.get("scan_path_presets") or [])
        # Update existing preset with same name
        for p in presets_list:
            if p["name"] == name:
                p["paths"] = list(self._paths)
                cfg.set_value("scan_path_presets", presets_list)
                self._refresh_preset_menu()
                if self._user_preset_var:
                    self._user_preset_var.set(name)
                if self._user_preset_del_btn:
                    self._user_preset_del_btn.configure(state="normal")
                self._status_cb(f"Updated preset '{name}'")
                return
        # Enforce max 20 presets
        if len(presets_list) >= 20:
            self._status_cb("Maximum 20 presets reached — delete one first")
            return
        presets_list.append({"name": name, "paths": list(self._paths)})
        cfg.set_value("scan_path_presets", presets_list)
        self._refresh_preset_menu()
        if self._user_preset_var:
            self._user_preset_var.set(name)
        if self._user_preset_del_btn:
            self._user_preset_del_btn.configure(state="normal")
        self._status_cb(f"Saved preset '{name}' — {len(self._paths)} path(s)")

    def _delete_user_preset(self) -> None:
        """Delete the currently selected user preset."""
        if not self._user_preset_var:
            return
        name = self._user_preset_var.get()
        if name.startswith("—"):
            return
        presets_list = [p for p in (cfg.get("scan_path_presets") or [])
                        if p["name"] != name]
        cfg.set_value("scan_path_presets", presets_list)
        self._refresh_preset_menu()
        if self._user_preset_del_btn:
            self._user_preset_del_btn.configure(state="disabled")
        self._status_cb(f"Deleted preset '{name}'")

    # ── Pipeline toggle callbacks ──────────────────────────────────────────────

    def _on_k2_toggle(self):
        cfg.set_value("pipeline_k2", bool(self._k2_var.get()))
        self._update_pipeline_header()

    def _on_guardian_toggle(self):
        cfg.set_value("guardian_dual_scan", bool(self._guardian_var.get()))
        self._update_pipeline_header()

    def _on_yara_toggle(self):
        cfg.set_value("yara_scan", bool(self._yara_var.get()))
        self._update_pipeline_header()

    def _on_clamav_toggle(self):
        cfg.set_value("clamav_scan", bool(self._clamav_var.get()))
        self._update_pipeline_header()

    def _on_defender_toggle(self):
        cfg.set_value("pipeline_defender", bool(self._defender_var.get()))
        self._update_pipeline_header()

    def _on_speakeasy_toggle(self):
        cfg.set_value("pipeline_speakeasy", bool(self._speakeasy_var.get()))
        self._update_pipeline_header()

    # ── Summary label helper ──────────────────────────────────────────────────

    @staticmethod
    def _summary_label(parent, text, col, color="#cdd6f4"):
        lbl = ctk.CTkLabel(parent, text=text, text_color=color,
                           font=ctk.CTkFont(size=12))
        lbl.grid(row=0, column=col, padx=8)
        return lbl

    # ── Preset selection ──────────────────────────────────────────────────────

    def _on_preset_change(self, value: str):
        self._preset = value
        # Reset user-preset selector when switching to a built-in preset
        if not self._loading_user_preset:
            if self._user_preset_var:
                names = self._get_user_preset_names()
                self._user_preset_var.set(
                    names[0] if names else "— no presets saved —")
            if self._user_preset_del_btn:
                self._user_preset_del_btn.configure(state="disabled")
        if value == "Custom":
            if not self._loading_user_preset:
                self._paths.clear()
            self._drop_label.configure(text="Drop files or folders here",
                                       text_color=theme.color("subtext"))
            self._drop_frame.configure(border_color=theme.color("divider"))
            self._browse_file_btn.grid()
            self._browse_folder_btn.grid()
            self._startup_btn.grid()
        else:
            self._drop_label.configure(text=f"Resolving {value} targets…",
                                       text_color="#ffb86c")
            self._browse_file_btn.grid_remove()
            self._browse_folder_btn.grid_remove()
            self._startup_btn.grid_remove()

            def _resolve():
                path_list, desc = presets.resolve(value)
                self._paths = path_list
                # Use lambda closures — passing a dict positionally to configure
                # is a silent no-op in CustomTkinter (only **kwargs accepted)
                self.after(0, lambda t=desc: self._drop_label.configure(
                    text=t, text_color=theme.color("text")))
                self.after(0, lambda: self._drop_frame.configure(
                    border_color=theme.color("nav_active")))

            threading.Thread(target=_resolve, daemon=True).start()

    # ── Drag & drop ───────────────────────────────────────────────────────────

    def _on_drop(self, event):
        if self._preset != "Custom":
            return
        self._add_paths(self._parse_dnd_paths(event.data))

    @staticmethod
    def _parse_dnd_paths(raw: str) -> list[str]:
        paths, raw, i = [], raw.strip(), 0
        while i < len(raw):
            if raw[i] == "{":
                end = raw.index("}", i)
                paths.append(raw[i + 1:end])
                i = end + 2
            else:
                end = raw.find(" ", i)
                if end == -1:
                    paths.append(raw[i:])
                    break
                paths.append(raw[i:end])
                i = end + 1
        return [p for p in paths if p]

    def load_paths(self, paths: list[str]) -> None:
        """Pre-populate scan targets (called from context menu / external trigger)."""
        self._preset_btn.set("Custom")
        self._preset = "Custom"
        self._add_paths(paths)

    def _add_paths(self, paths: list[str]):
        for p in paths:
            if p not in self._paths:
                self._paths.append(p)
        self._refresh_drop_label()

    def _refresh_drop_label(self):
        if self._preset != "Custom":
            return
        if self._paths:
            names = ", ".join(Path(p).name for p in self._paths[:3])
            extra = f" +{len(self._paths) - 3} more" if len(self._paths) > 3 else ""
            self._drop_label.configure(text=f"{names}{extra}", text_color=theme.color("text"))
        else:
            self._drop_label.configure(text="Drop files or folders here",
                                       text_color=theme.color("subtext"))

    # ── Browse / startup ──────────────────────────────────────────────────────

    def _browse_file(self):
        paths = filedialog.askopenfilenames(title="Select files to scan")
        if paths:
            self._add_paths(list(paths))

    def _browse_folder(self):
        path = filedialog.askdirectory(title="Select folder to scan")
        if path:
            self._add_paths([path])

    def _load_startup_items(self):
        from ui.core import startup_scanner as ss
        items = ss.enumerate_startup_items()
        paths = ss.get_scannable_paths(items)
        if paths:
            self._add_paths(paths)
            self._log_append(
                f"[INFO] Loaded {len(paths)} startup item(s) from "
                f"{len(items)} entries.", _TAG_INFO)
        else:
            self._log_append("[INFO] No scannable startup items found.", _TAG_INFO)

    # ── Clear ─────────────────────────────────────────────────────────────────

    def _clear(self):
        if self._scanning:
            return
        self._paths.clear()
        self._preset_btn.set("Custom")
        self._preset = "Custom"
        self._browse_file_btn.grid()
        self._browse_folder_btn.grid()
        self._startup_btn.grid()
        # Reset user preset selector
        if self._user_preset_var:
            names = self._get_user_preset_names()
            self._user_preset_var.set(names[0] if names else "— no presets saved —")
        if self._user_preset_del_btn:
            self._user_preset_del_btn.configure(state="disabled")
        self._drop_frame.configure(border_color=theme.color("divider"))
        self._refresh_drop_label()
        self._log_clear()
        self._progress_bar.set(0)
        self._pct_lbl.configure(text="0%")
        self._eta_lbl.configure(text="ETA: —")
        self._current_file_lbl.configure(text="")
        self._pause_btn.configure(text="⏸  Pause", state="disabled",
                                   fg_color="#4a4a20")
        self._paused_lbl.grid_remove()
        self._stop_btn.configure(text="■  Stop", state="disabled")
        self._progress_frame.grid_remove()
        self._vt_frame.grid_remove()
        for lbl, text in [
            (self._lbl_scanned,  "Scanned: —"),
            (self._lbl_infected, "Infected: —"),
            (self._lbl_clean,    "Clean: —"),
            (self._lbl_elapsed,  "Time: —"),
        ]:
            lbl.configure(text=text)

    # ── Scan ──────────────────────────────────────────────────────────────────

    def _start_scan(self):
        if self._scanning:
            return
        if not self._paths:
            self._log_append(
                "[INFO] No targets selected. Choose a preset or browse for files.",
                _TAG_INFO)
            return

        self._scanning = True
        self._paused  = False
        self._scan_start_time = time.time()
        self._scan_total = 0
        self._last_report_path = None
        self._scan_ctrl = None
        self._k2_infected_paths = []
        self._g_infected = {}
        self._yara_infected = {}
        self._clamav_infected = {}
        self._defender_infected = {}
        self._speakeasy_infected = {}
        # v1.10: reset Guardian tier/context/severity maps and session counters
        self._g_tier = {}
        self._g_context = {}
        self._threat_severity = {}
        self._circuit_state = {}
        self._circuit_banner_dismissed = False
        self._scan_session_ignored = {}
        self._pipeline_cancel_event = threading.Event()
        # Pause event — SET = running (default), CLEAR = paused. Every secondary
        # engine receives this and blocks/suspends accordingly.
        self._pipeline_pause_event = threading.Event()
        self._pipeline_pause_event.set()
        self._engine_queue = []
        self._secondary_paths = []

        self._scan_btn.configure(state="disabled", text="Scanning…")
        self._stop_btn.configure(text="■  Stop", state="normal")
        self._log_clear()
        self._vt_frame.grid_remove()
        self._threat_actions_frame.grid_remove()
        self._status_cb(f"{self._preset} scan starting…")

        show_bar = cfg.get("show_progress_bar")

        # Unified flow (v1.6.1+): K2 is now a peer engine in the queue, not a
        # special "primary" step. The progress bar starts indeterminate; when
        # K2 runs (if scheduled), _run_k2_scan flips it to determinate.
        if show_bar:
            self._progress_bar.configure(mode="indeterminate")
            self._progress_bar.start()
            self._pct_lbl.configure(text="…")
            self._eta_lbl.configure(text="ETA: —")
            self._current_file_lbl.configure(text="")
            self._progress_frame.grid()
            self._pause_btn.configure(state="normal")
            if not cfg.get("show_eta"):
                self._eta_lbl.grid_remove()
            else:
                self._eta_lbl.grid()
            if not cfg.get("show_current_file"):
                self._current_file_lbl.grid_remove()
            else:
                self._current_file_lbl.grid()
        else:
            self._progress_frame.grid_remove()

        self._run_secondary_engines(list(self._paths))

    def _on_line(self, line: str):
        tag = _classify(line)
        if not cfg.get("verbose_log") and tag in (_TAG_CLEAN, _TAG_INFO):
            return
        self.after(0, self._log_append, line, tag)

    def _on_progress(self, done: int, total: int, current_file: str):
        def _update():
            if total > 0:
                if self._progress_bar.cget("mode") == "indeterminate":
                    self._progress_bar.stop()
                    self._progress_bar.configure(mode="determinate")

                pct = min(done / total, 0.99)
                self._progress_bar.set(pct)
                self._pct_lbl.configure(text=f"{int(pct * 100)}% · {done:,}")

                if done > 0 and cfg.get("show_eta"):
                    elapsed = time.time() - self._scan_start_time
                    rate = done / elapsed if elapsed > 0 else 0
                    if self._scan_total and self._scan_total > done:
                        remaining = (self._scan_total - done) / rate if rate > 0 else 0
                    else:
                        remaining = 0
                    self._eta_lbl.configure(text=f"ETA: {_format_eta(remaining)}")

                self._scan_total = total
            else:
                if self._progress_bar.cget("mode") != "indeterminate":
                    self._progress_bar.configure(mode="indeterminate")
                    self._progress_bar.start()
                self._pct_lbl.configure(text="…")

            if current_file and cfg.get("show_current_file"):
                self._current_file_lbl.configure(text=f"  {Path(current_file).name}")
            self._status_cb(
                f"Scanning… {done:,}{f'/{self._scan_total:,}' if self._scan_total else ''} files")
        self.after(0, _update)

    def _on_done(self, returncode: int, report_path: str | None):
        """K2 completion callback — fires from background thread."""
        def _update():
            self._paused = False
            self._last_report_path = report_path
            was_cancelled = bool(self._scan_ctrl and self._scan_ctrl.cancelled)

            # K2 is done — pause stays enabled for secondary engines
            # (Guardian/YARA loops + ClamAV proc suspend respect the pause event)
            self._pause_btn.configure(text="⏸  Pause", fg_color="#4a4a20")
            self._progress_bar.stop()
            self._progress_bar.configure(mode="determinate")
            self._current_file_lbl.configure(text="")

            elapsed_str = _format_eta(time.time() - self._scan_start_time)
            infected_count = 0

            if was_cancelled:
                self._progress_bar.set(0)
                self._pct_lbl.configure(text="—")
                self._eta_lbl.configure(text="ETA: —")
                self._log_append("\n[CANCELLED] K2 scan cancelled by user.", _TAG_WARN)
            else:
                self._progress_bar.set(1.0)
                self._pct_lbl.configure(text="100%")
                self._eta_lbl.configure(text="done")

                if report_path:
                    summary = sc.parse_report(report_path)
                    infected_count = summary["infected"]
                    self._k2_infected_paths = sc.get_infected_paths(report_path)
                    self._lbl_scanned.configure(text=f"Scanned: {summary['total']}")
                    self._lbl_infected.configure(text=f"Infected: {infected_count}")
                    self._lbl_clean.configure(text=f"Clean: {summary['clean']}")
                    self._lbl_elapsed.configure(
                        text=f"Time: {summary['elapsed'] or elapsed_str}")
                    status = ("Scan complete — threats found!"
                              if infected_count else "Scan complete — all clear")
                else:
                    self._lbl_elapsed.configure(text=f"Time: {elapsed_str}")
                    status = ("Scan complete"
                              if returncode == 0 else f"Scan finished (code {returncode})")

                self._status_cb(status)
                tag = _TAG_CLEAN if returncode == 0 else _TAG_WARN
                self._log_append(f"\n[DONE] K2: {status}", tag)

                self._maybe_vt_verify(report_path, infected_count)

                if self._k2_infected_paths:
                    self._build_threat_actions()

            # If more engines follow K2 in the queue, switch the progress bar
            # back to indeterminate (only K2 pre-counts files for determinate
            # progress). If K2 was last (or only), _finalize_scan will reset it.
            if cfg.get("show_progress_bar") and self._engine_queue:
                self._progress_bar.configure(mode="indeterminate")
                self._progress_bar.start()
                self._pct_lbl.configure(text="…")
                self._eta_lbl.configure(text="ETA: —")

            # Proceed to next engine in the queue (K2 is now a peer step, not
            # the special "primary" step). _run_next_engine handles cancel state.
            self._run_next_engine()

        self.after(0, _update)

    # ── Pause / Stop controls ─────────────────────────────────────────────────

    def _toggle_pause(self):
        """
        Unified pause/resume across the whole pipeline.

        K2 (if running) is paused via its ScanController (NtSuspendProcess on
        k2.exe). Secondary engines respect ``_pipeline_pause_event``:
          - Guardian AI / YARA: their per-file loops call ``pause_event.wait()``
          - ClamAV: a watcher daemon suspends clamscan.exe when the event clears
          - Defender: not paused (each MpCmdRun.exe invocation is too short to
            suspend cleanly) — pause just sets the event so the BETWEEN-file
            cancel_event check effectively halts the loop on the next iteration

        The pause button stays enabled for the entire scan now, not just K2.
        """
        if not self._scanning:
            return

        self._paused = not self._paused

        if self._paused:
            # Pause everything
            if self._pipeline_pause_event:
                self._pipeline_pause_event.clear()
            if self._scan_ctrl and not self._scan_ctrl.paused:
                self._scan_ctrl.pause()
            self._pause_btn.configure(text="▶  Resume", fg_color="#2a5a2a")
            self._paused_lbl.grid()
            label = self._active_engine_label or "scan"
            self._status_cb(f"Paused — {label}")
            self._log_append(f"[INFO] Scan paused ({label}).", _TAG_INFO)
        else:
            # Resume everything
            if self._pipeline_pause_event:
                self._pipeline_pause_event.set()
            if self._scan_ctrl and self._scan_ctrl.paused:
                self._scan_ctrl.resume()
            self._pause_btn.configure(text="⏸  Pause", fg_color="#4a4a20")
            self._paused_lbl.grid_remove()
            self._status_cb("Scan resumed")
            self._log_append("[INFO] Scan resumed.", _TAG_INFO)

    def _stop_scan(self):
        if not self._scanning:
            return
        self._log_append("[INFO] Stopping scan pipeline…", _TAG_WARN)
        self._pause_btn.configure(state="disabled")
        self._stop_btn.configure(state="disabled", text="Stopping…")

        # Release pause first so any suspended subprocess (k2.exe, clamscan.exe)
        # can be terminated — TerminateProcess is ignored by suspended procs.
        # Also lets Guardian/YARA loops unblock from pause_event.wait() and
        # check cancel_event on the next iteration.
        if self._pipeline_pause_event:
            self._pipeline_pause_event.set()
        self._paused = False

        # Signal all secondary engines to exit their per-file loops
        if self._pipeline_cancel_event:
            self._pipeline_cancel_event.set()

        # Kill K2 subprocess if it is still running
        if self._scan_ctrl:
            self._scan_ctrl.cancel()
        # If K2 is disabled or already finished and no secondaries are pending,
        # the cancel_event is set and _run_secondary_engines / _maybe_run_speakeasy
        # will detect it on their next scheduled callback and call _finalize_scan.

    # ── Pipeline orchestration ─────────────────────────────────────────────────

    def _run_secondary_engines(self, paths: list[str]):
        """
        Build an ordered queue of enabled engines in user-configured pipeline_order
        (default: K2 → Defender → Guardian AI → YARA → ClamAV) and kick off the first.
        Engines run sequentially — each starts only after the previous completes.
        K2 is a peer engine here (v1.6.1+) — no longer hardcoded as "always first".
        Called on the main thread.
        """
        self._secondary_paths = paths
        self._engine_queue = []

        cancelled = bool(self._pipeline_cancel_event
                         and self._pipeline_cancel_event.is_set())

        if not cancelled:
            order = self._normalized_pipeline_order()
            dispatch = {
                "k2":       (self._k2_var,       sc.is_available,          self._run_k2_scan),
                "guardian": (self._guardian_var, ge.is_available,          self._run_guardian_scan),
                "yara":     (self._yara_var,     ye.is_available,          self._run_yara_scan),
                "clamav":   (self._clamav_var,   ce.is_available,          self._run_clamav_scan),
                "defender": (self._defender_var, df.is_mpcmdrun_available, self._run_defender_scan),
            }
            for engine_id in order:
                if engine_id in dispatch:
                    var, avail_fn, run_fn = dispatch[engine_id]
                    if var.get() and avail_fn():
                        self._engine_queue.append(run_fn)

        self._run_next_engine()

    def _run_next_engine(self):
        """
        Pop and start the next engine from the queue.
        If the queue is empty (or the pipeline is cancelled), proceed to
        the Speakeasy stage or finalize.
        Always called on the main thread.
        """
        if self._pipeline_cancel_event and self._pipeline_cancel_event.is_set():
            self._finalize_scan(aborted=True)
            return

        if not self._engine_queue:
            self._maybe_run_speakeasy_pipeline()
            return

        run_fn = self._engine_queue.pop(0)
        run_fn(self._secondary_paths)

    def _finalize_scan(self, aborted: bool = False):
        """
        Final cleanup after all pipeline stages complete or are cancelled.
        Guards against double-invocation — safe to call more than once.
        Always called on the main thread.
        """
        if not self._scanning:
            return   # already finalized
        self._scanning = False
        self._paused  = False
        self._scan_btn.configure(state="normal", text="Start Scan")
        self._stop_btn.configure(state="disabled", text="■  Stop")
        self._pause_btn.configure(state="disabled", text="⏸  Pause",
                                  fg_color="#4a4a20")
        self._paused_lbl.grid_remove()
        self._progress_bar.stop()
        self._progress_bar.configure(mode="determinate")
        self._current_file_lbl.configure(text="")

        if aborted:
            self._progress_bar.set(0)
            self._pct_lbl.configure(text="—")
            self._eta_lbl.configure(text="ETA: —")
            elapsed_str = _format_eta(time.time() - self._scan_start_time)
            self._lbl_elapsed.configure(text=f"Time: {elapsed_str}")
            self._log_append(
                "\n[STOPPED] Scan pipeline stopped — results above are partial.",
                _TAG_WARN)
            self._status_cb("Scan stopped — partial results available")

        # Always rebuild threat actions with all engine results
        self._build_threat_actions()

        # Dispute check runs once at the end now (instead of inside Guardian's
        # done callback). This way K2 and Guardian can run in any order — the
        # dispute popup fires only after both have reported.
        if not aborted:
            try:
                self._check_disputes()
            except Exception:
                pass

    # ── Guardian second-opinion scan ──────────────────────────────────────────

    def _run_k2_scan(self, paths: list[str]):
        """
        Run the K2 engine as a queue step (v1.6.1+).

        K2 is no longer hardcoded as "always first" — this method wraps
        sc.run_scan() so the engine queue can schedule K2 at any position.
        When K2 is configured to run, the progress bar flips to determinate
        mode (K2 is the only engine that pre-counts files); other engines
        run with indeterminate progress.
        """
        self._active_engine_label = "K2 Engine"
        self._log_append("\n── K2 Engine ──", _TAG_INFO)

        # Switch progress bar to determinate for K2's file-counted run
        show_bar = cfg.get("show_progress_bar")
        if show_bar:
            try:
                self._progress_bar.stop()
            except Exception:
                pass
            self._progress_bar.configure(mode="determinate")
            self._progress_bar.set(0)
            self._pct_lbl.configure(text="0%")
            self._eta_lbl.configure(text="ETA: —")

        self._scan_ctrl = sc.run_scan(
            paths,
            self._action_var.get(),
            self._on_line,
            self._on_progress if show_bar else None,
            self._on_done,
        )

    def _run_guardian_scan(self, paths: list[str]):
        """Run Guardian AI on the same paths as part of the pipeline."""
        try:
            stats = ge.get_db_stats()
            known_bad = stats.get("known_bad", 0)
            if known_bad > 10_000:
                self._log_append(
                    f"[Guardian AI] ⚠  Large intelligence DB "
                    f"({known_bad:,} hashes) — scan startup may take several seconds.",
                    _TAG_WARN)
        except Exception:
            pass

        self._log_append("\n── Guardian AI ──", _TAG_GUARDIAN)
        self._g_infected = {}
        # v1.10: capture per-file tier + match context for the master-detail UI
        self._g_tier:    dict[str, str] = {}
        self._g_context: dict[str, str] = {}
        self._active_engine_label = "Guardian AI"

        # v1.10: 5-arg callback receives tier + match_context; guardian_engine
        # auto-detects arity, so the legacy 3-arg form still works for other engines.
        def _on_result(fpath: str, infected: bool, reason: str,
                       tier: str = "", match_context: str = ""):
            def _upd():
                if infected:
                    self._g_infected[fpath] = reason
                    self._g_tier[fpath]    = tier or ""
                    self._g_context[fpath] = match_context or ""
                    # Map tier → severity for the master-detail panel.
                    # 'pattern' becomes 'suspicious' in Conservative/Balanced profiles
                    # (auto-downgraded by guardian_engine); becomes 'confirmed' in Power.
                    profile = (cfg.get("guardian_sensitivity_profile")
                               or "conservative").lower()
                    if tier == "pattern" and profile != "power":
                        severity = "suspicious"
                    else:
                        severity = "confirmed"
                    if not hasattr(self, "_threat_severity"):
                        self._threat_severity = {}
                    self._threat_severity[fpath] = severity
                    tag = _TAG_WARN if tier == "pattern" else _TAG_INFECTED
                    self._log_append(
                        f"[Guardian]  {Path(fpath).name}  — {reason}", tag)
                    if cfg.get("verbose_log"):
                        self._log_append(f"             ↳ {fpath}", tag)
                elif cfg.get("verbose_log"):
                    self._log_append(
                        f"[Guardian]  {Path(fpath).name}  — clean", _TAG_CLEAN)
            self.after(0, _upd)

        def _on_done(infected_count: int):
            def _upd():
                if infected_count:
                    self._log_append(
                        f"[Guardian AI] Done — {infected_count} threat(s) found.",
                        _TAG_INFECTED)
                    self._build_threat_actions()
                else:
                    self._log_append(
                        "[Guardian AI] Done — no additional threats.", _TAG_CLEAN)
                self._status_cb(
                    f"Guardian AI done — {infected_count} threat(s)")
                # v1.10: surface circuit-breaker trip if it fired this scan.
                try:
                    state = ge._get_scanner().get_circuit_state()
                    if state.get("tripped"):
                        self._circuit_state = state
                        self._render_circuit_banner()
                except Exception:
                    pass
                # Dispute check happens in _finalize_scan now, so it works
                # regardless of K2/Guardian ordering in the pipeline.
                self._run_next_engine()
            self.after(0, _upd)

        ge.scan_async(paths, _on_result, _on_done,
                      cancel_event=self._pipeline_cancel_event,
                      pause_event=self._pipeline_pause_event)

    # ── YARA rules scan ───────────────────────────────────────────────────────

    def _run_yara_scan(self, paths: list[str]):
        """Run YARA rules as part of the pipeline."""
        rule_count = ye.get_rule_count()
        self._log_append(
            f"\n── YARA Rules ({rule_count} rule file"
            f"{'s' if rule_count != 1 else ''}) ──", _TAG_YARA)
        self._yara_infected = {}
        self._active_engine_label = "YARA Rules"

        def _on_result(fpath: str, infected: bool, reason: str):
            def _upd():
                if infected:
                    self._yara_infected[fpath] = reason
                    self._log_append(f"[YARA]  {fpath}", _TAG_YARA)
                    self._log_append(f"         ↳ {reason}", _TAG_YARA)
                elif cfg.get("verbose_log"):
                    self._log_append(
                        f"[YARA]  {Path(fpath).name}  — no match", _TAG_YARA)
            self.after(0, _upd)

        failed: list[str] = []

        def _on_error(message: str):
            failed.append(str(message))

            def _upd():
                self._log_append(f"[YARA] ⚠ {message}", _TAG_YARA)
            self.after(0, _upd)

        def _on_done(infected_count: int):
            def _upd():
                if infected_count:
                    self._log_append(
                        f"[YARA] Done — {infected_count} match(es) found.", _TAG_YARA)
                    self._build_threat_actions()
                elif failed:
                    # Never "no rule matches" here. The engine did not finish,
                    # and a clean-looking log line is how a ruleset that will
                    # not compile passes for a scan that found nothing.
                    self._log_append(
                        "[YARA] Did not complete — results are incomplete.", _TAG_YARA)
                else:
                    self._log_append("[YARA] Done — no rule matches.", _TAG_YARA)
                self._status_cb(
                    "YARA did not complete" if failed and not infected_count
                    else f"YARA done — {infected_count} match(es)")
                self._run_next_engine()
            self.after(0, _upd)

        ye.scan_async(paths, _on_result, _on_done,
                      cancel_event=self._pipeline_cancel_event,
                      pause_event=self._pipeline_pause_event,
                      on_error=_on_error)

    # ── ClamAV scan ───────────────────────────────────────────────────────────

    def _run_clamav_scan(self, paths: list[str]):
        """Run ClamAV as part of the pipeline."""
        version = ce.get_version()
        self._log_append(
            f"\n── ClamAV{' — ' + version if version else ''} ──", _TAG_CLAMAV)
        self._clamav_infected = {}
        self._active_engine_label = "ClamAV"

        def _on_result(fpath: str, infected: bool, reason: str):
            def _upd():
                if infected:
                    self._clamav_infected[fpath] = reason
                    self._log_append(f"[ClamAV]  {fpath}", _TAG_CLAMAV)
                    self._log_append(f"           ↳ {reason}", _TAG_CLAMAV)
                elif cfg.get("verbose_log"):
                    self._log_append(
                        f"[ClamAV]  {Path(fpath).name}  — clean", _TAG_CLAMAV)
            self.after(0, _upd)

        failed: list[str] = []

        def _on_error(message: str):
            failed.append(str(message))

            def _upd():
                self._log_append(f"[ClamAV] ⚠ {message}", _TAG_CLAMAV)
            self.after(0, _upd)

        def _on_done(infected_count: int):
            def _upd():
                if infected_count:
                    self._log_append(
                        f"[ClamAV] Done — {infected_count} threat(s) found.",
                        _TAG_CLAMAV)
                    self._build_threat_actions()
                elif failed:
                    self._log_append(
                        "[ClamAV] Did not complete — results are incomplete.",
                        _TAG_CLAMAV)
                else:
                    self._log_append("[ClamAV] Done — no threats found.", _TAG_CLAMAV)
                self._status_cb(
                    "ClamAV did not complete" if failed and not infected_count
                    else f"ClamAV done — {infected_count} threat(s)")
                self._run_next_engine()
            self.after(0, _upd)

        ce.scan_async(paths, _on_result, _on_done,
                      cancel_event=self._pipeline_cancel_event,
                      pause_event=self._pipeline_pause_event,
                      on_error=_on_error)

    # ── Defender scan ──────────────────────────────────────────────────────────

    def _run_defender_scan(self, paths: list[str]):
        """Run Windows Defender as part of the pipeline."""
        self._log_append("\n── Windows Defender ──", _TAG_DEFENDER)
        self._defender_infected = {}
        self._active_engine_label = "Defender"

        def _on_result(fpath: str, infected: bool, reason: str):
            def _upd():
                if infected:
                    self._defender_infected[fpath] = reason
                    self._log_append(f"[Defender]  {fpath}", _TAG_DEFENDER)
                    self._log_append(f"             ↳ {reason}", _TAG_DEFENDER)
            self.after(0, _upd)

        def _on_done(infected_count: int):
            def _upd():
                if infected_count:
                    self._log_append(
                        f"[Defender] Done — {infected_count} threat(s) found.",
                        _TAG_DEFENDER)
                    self._build_threat_actions()
                else:
                    self._log_append("[Defender] Done — no threats found.", _TAG_DEFENDER)
                self._status_cb(f"Defender done — {infected_count} threat(s)")
                self._run_next_engine()
            self.after(0, _upd)

        df.scan_paths_async(
            paths,
            on_result=_on_result,
            on_done=_on_done,
            on_progress=None,
            cancel_event=self._pipeline_cancel_event,
        )

    # ── Speakeasy emulation (post-secondary stage) ────────────────────────────

    def _maybe_run_speakeasy_pipeline(self):
        """
        Called when all secondary engines are done.
        If Speakeasy is enabled, runs it on all PE files flagged by any engine.
        Otherwise, finalises the scan.
        Always called on the main thread.
        """
        # Double-check cancel state
        if self._pipeline_cancel_event and self._pipeline_cancel_event.is_set():
            self._finalize_scan(aborted=True)
            return

        if not self._speakeasy_var.get() or ee is None:
            self._finalize_scan(aborted=False)
            return

        try:
            avail = ee.is_available()
        except Exception:
            avail = False
        if not avail:
            self._finalize_scan(aborted=False)
            return

        PE_EXTS = {".exe", ".dll", ".sys", ".scr", ".drv", ".ocx"}
        all_flagged = (set(self._k2_infected_paths)
                       | set(self._g_infected.keys())
                       | set(self._yara_infected.keys())
                       | set(self._clamav_infected.keys())
                       | set(self._defender_infected.keys()))
        pe_files = [f for f in all_flagged if Path(f).suffix.lower() in PE_EXTS]

        if not pe_files:
            self._log_append(
                "[Speakeasy] No PE files flagged — skipping.", _TAG_SPEAKEASY)
            self._finalize_scan(aborted=False)
            return

        self._log_append(
            f"\n── Speakeasy Emulation ({len(pe_files)} flagged PE(s)) ──",
            _TAG_SPEAKEASY)
        self._run_speakeasy_inline(pe_files)

    def _run_speakeasy_inline(self, pe_files: list[str]):
        """Emulate each flagged PE sequentially in a daemon thread."""
        cancel_evt = self._pipeline_cancel_event

        def _run():
            cancelled = False
            for path in pe_files:
                if cancel_evt and cancel_evt.is_set():
                    cancelled = True
                    break

                done_evt   = threading.Event()
                result_box = [None]

                def _cb(report, _e=done_evt, _r=result_box):
                    _r[0] = report
                    _e.set()

                try:
                    ee.emulate_async(path, on_done=_cb)
                except Exception as exc:
                    result_box[0] = None
                    done_evt.set()

                done_evt.wait(timeout=30)
                report = result_box[0]

                if self.winfo_exists():
                    self.after(0, self._on_speakeasy_inline_result, path, report)

            # Speakeasy is the final stage — always call finalize
            if self.winfo_exists():
                self.after(0, self._finalize_scan, cancelled)

        threading.Thread(target=_run, daemon=True).start()

    def _on_speakeasy_inline_result(self, path: str, report):
        """Process a single Speakeasy emulation result on the main thread."""
        if report is None or getattr(report, "error", None):
            err = getattr(report, "error", "unknown error") if report else "emulation failed"
            self._log_append(
                f"  [Speakeasy] {Path(path).name}: {err}", _TAG_SPEAKEASY)
            return

        indicators: list[str] = []

        network = getattr(report, "network", None) or []
        if network:
            indicators.append(f"network: {', '.join(str(n) for n in network[:3])}")

        api_calls = getattr(report, "api_calls", None) or []
        _SUSP_APIS = {"writefile", "createremotethread", "virtualalloc",
                      "shellexecute", "wscript"}
        suspicious = [
            c.get("api", "") for c in api_calls
            if any(x in c.get("api", "").lower() for x in _SUSP_APIS)
        ]
        if suspicious:
            indicators.append(f"APIs: {', '.join(suspicious[:5])}")

        if indicators:
            reason = f"Speakeasy: {'; '.join(indicators)}"
            self._speakeasy_infected[path] = reason
            self._log_append(f"  [!] {Path(path).name}: {reason}", _TAG_SPEAKEASY)
            self._build_threat_actions()
        else:
            self._log_append(
                f"  [ok] {Path(path).name}: no suspicious indicators", _TAG_SPEAKEASY)

    # ── Dispute resolution ────────────────────────────────────────────────────

    # ── Threat Actions subsystem ─────────────────────────────────────────────
    # All Threat Actions master-detail / bulk-action / hashing / dispute logic
    # lives in _ThreatActionsMixin (see ui/views/threat_actions_mixin.py).
    # The methods below remain here because they are not part of the panel
    # itself — they are scan-flow / nav helpers used by the mixin.

    def _send_to_virustotal(self, path: str):
        if not self._nav_cb:
            return
        try:
            toplevel = self.winfo_toplevel()
            # get_view() rather than _views[...]: pages are built on first
            # navigation, so the one we are handing this file to may not exist
            # yet.  Testing membership in _views would quietly skip the
            # pre-load and land the user on an empty VirusTotal page.
            if hasattr(toplevel, "get_view"):
                toplevel.get_view("virustotal")._load_file(path)
        except Exception:
            pass
        self._nav_cb("virustotal")

    def _open_behavioral(self, view_key: str, file_path: str):
        """Navigate to the Behavioral Analysis view with the given file pre-loaded."""
        if not self._nav_cb:
            return
        try:
            toplevel = self.winfo_toplevel()
            # See _send_to_virustotal: build-on-first-show means _views is not
            # a reliable membership test for a page the user has not opened.
            if hasattr(toplevel, "get_view"):
                toplevel.get_view("behavioral").load_file(file_path)
        except Exception:
            pass
        self._nav_cb("behavioral")

    # ── VirusTotal post-scan verify ───────────────────────────────────────────

    @staticmethod
    def _should_vt_check(path: str, k2_paths: list, g_infected: dict, level: str) -> bool:
        if level == "off":
            return False
        in_k2 = path in k2_paths
        reason = g_infected.get(path, "")
        in_guardian = bool(reason)
        is_pattern = "pattern" in reason.lower()
        no_family = (reason and "known signature" in reason.lower()
                     and "[" not in reason and "nsrl" not in reason.lower())
        if level == "dual":
            return in_k2 and in_guardian
        if level == "pattern":
            return is_pattern or no_family
        return False

    def _maybe_vt_verify(self, report_path: str | None, infected_count: int):
        api_key = cfg.get("vt_api_key") or ""
        if not api_key:
            return

        smart_level = cfg.get("vt_smart_upload_level") or "off"
        legacy_auto = cfg.get("vt_verify_after_scan")

        paths_to_check: list[str] = []

        if legacy_auto and report_path:
            paths_to_check = sc.get_infected_paths(report_path)
        elif smart_level != "off":
            all_candidates = set(self._k2_infected_paths) | set(self._g_infected.keys())
            paths_to_check = [
                p for p in all_candidates
                if self._should_vt_check(p, self._k2_infected_paths,
                                         self._g_infected, smart_level)
            ]

        if not paths_to_check and infected_count > 0 and not legacy_auto:
            self._vt_title.configure(
                text="VirusTotal  —  enable 'Auto-verify threats' or "
                     "'Smart Upload' in Settings to check automatically")
            self._vt_status.configure(text="")
            for w in self._vt_rows_frame.winfo_children():
                w.destroy()
            self._vt_frame.grid()
            return

        if not paths_to_check:
            return

        self._vt_title.configure(text="VirusTotal Verification")
        self._vt_status.configure(
            text=f"Checking 0/{len(paths_to_check)}…", text_color="#ffb86c")
        for w in self._vt_rows_frame.winfo_children():
            w.destroy()
        self._vt_frame.grid()

        infected_paths = paths_to_check

        self._vt_row_labels: dict[str, dict] = {}
        for i, path in enumerate(infected_paths):
            name = Path(path).name
            bg = theme.color("card2") if i % 2 == 0 else theme.color("card")
            row_f = ctk.CTkFrame(self._vt_rows_frame, fg_color=bg)
            row_f.grid(row=i, column=0, sticky="ew", pady=1)
            row_f.grid_columnconfigure(0, weight=1)
            name_lbl = ctk.CTkLabel(row_f, text=name, anchor="w",
                                     font=ctk.CTkFont(size=12),
                                     text_color=theme.color("text"))
            name_lbl.grid(row=0, column=0, sticky="w", padx=10, pady=4)
            result_lbl = ctk.CTkLabel(row_f, text="queuing…",
                                       font=ctk.CTkFont(size=11),
                                       text_color=theme.color("subtext"))
            result_lbl.grid(row=0, column=1, padx=10)
            self._vt_row_labels[path] = {"result": result_lbl}

        def _verify_all():
            total = len(infected_paths)
            for idx, path in enumerate(infected_paths):
                if not self.winfo_exists():
                    break
                result_lbl = self._vt_row_labels[path]["result"]
                self.after(0, lambda lbl=result_lbl: lbl.configure(
                    text="hashing…", text_color="#ffb86c"))
                hashes = vt.hash_file(path)
                sha256 = hashes.get("sha256", "")
                if not sha256 or "error" in hashes:
                    self.after(0, lambda lbl=result_lbl: lbl.configure(
                        text="hash error", text_color="#888888"))
                    continue

                import urllib.request, urllib.error, json as _json
                import urllib.parse
                url = f"https://www.virustotal.com/api/v3/files/{sha256}"
                req = urllib.request.Request(url, headers={"x-apikey": api_key})
                try:
                    with urllib.request.urlopen(req, timeout=15) as resp:
                        raw = _json.loads(resp.read().decode("utf-8"))
                    parsed = vt.parse_result(raw)
                    if "error" in parsed:
                        text = parsed["error"][:50]
                        color = "#888888"
                    else:
                        mal = parsed["malicious"]
                        total_eng = parsed["total"]
                        verdict = f"{mal}/{total_eng} engines"
                        color = "#ff5555" if mal > 0 else "#50fa7b"
                        text = f"{'MALICIOUS' if mal > 0 else 'CLEAN'} — {verdict}"
                except urllib.error.HTTPError as exc:
                    text = f"HTTP {exc.code}"
                    color = "#888888"
                except Exception as exc:
                    text = str(exc)[:50]
                    color = "#888888"

                self.after(0, lambda lbl=result_lbl, t=text, c=color: lbl.configure(
                    text=t, text_color=c))
                done_count = idx + 1
                self.after(0, lambda dc=done_count, tot=total: self._vt_status.configure(
                    text=f"Checked {dc}/{tot}",
                    text_color="#50fa7b" if dc == tot else "#ffb86c",
                ))

                if idx < total - 1:
                    time.sleep(16)

        threading.Thread(target=_verify_all, daemon=True).start()

    # ── Log helpers ───────────────────────────────────────────────────────────

    def _log_append(self, line: str, tag: str = _TAG_INFO):
        self._log.configure(state="normal")
        self._log.insert("end", line + "\n", tag)
        self._log.see("end")
        self._log.configure(state="disabled")

    def _log_clear(self):
        self._log.configure(state="normal")
        self._log.delete("1.0", "end")
        self._log.configure(state="disabled")
