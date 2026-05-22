import threading
from datetime import datetime
from pathlib import Path
import customtkinter as ctk
import ui.theme as theme

from ui.core import defender as dfn
from ui.core import scanner as sc
from ui.core import watcher as wtch
from ui.core import settings as cfg
from ui.core import win_security as ws

_BASE_DIR  = Path(__file__).resolve().parents[3]
_LOGS_DIR  = _BASE_DIR / "logs"
_INTEL_DB  = _BASE_DIR / "intelligence" / "threat_db.sqlite"


def _svc_installed() -> bool:
    """Check if PolyShieldService is registered in the Windows SCM via registry."""
    try:
        import winreg
        winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\PolyShieldService",
        ).Close()
        return True
    except OSError:
        return False
    except Exception:
        return False


def _has_intel() -> bool:
    """True if the threat DB exists and contains more than the empty schema."""
    return _INTEL_DB.exists() and _INTEL_DB.stat().st_size > 8192


def _has_scan_history() -> bool:
    """True if at least one scan report exists in the logs directory."""
    return any(_LOGS_DIR.glob("scan_*.json"))


def _last_scan_info() -> dict:
    """Pull summary from the most recent scan JSON report."""
    reports = sorted(_LOGS_DIR.glob("scan_*.json"),
                     key=lambda p: p.stat().st_mtime, reverse=True)
    if not reports:
        return None
    try:
        summary = sc.parse_report(str(reports[0]))
        age_secs = datetime.now().timestamp() - reports[0].stat().st_mtime
        if age_secs < 3600:
            age_str = f"{int(age_secs / 60)}m ago"
        elif age_secs < 86400:
            age_str = f"{int(age_secs / 3600)}h ago"
        else:
            age_str = f"{int(age_secs / 86400)}d ago"
        summary["age"] = age_str
        return summary
    except Exception:
        return None


class DashboardView(ctk.CTkFrame):
    def __init__(self, master, status_callback, navigate_callback, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self._status_cb = status_callback
        self._navigate = navigate_callback
        self._cards: dict = {}
        self._themed: list = []          # for live theme refresh
        self._build()

    def _refresh_theme(self) -> None:
        """Re-apply current theme colours to all registered widgets."""
        theme.refresh(self._themed)
        # Rebuild the Getting Started card so its colours follow the theme
        if hasattr(self, "_gs_frame") and self._gs_frame.winfo_ismapped():
            self._refresh_getting_started()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)

        # ── Title row ──
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=24, pady=(20, 8))
        header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(header, text="System Health",
                     font=ctk.CTkFont(size=22, weight="bold")).grid(
            row=0, column=0, sticky="w")

        self._refresh_btn = ctk.CTkButton(
            header, text="Refresh", width=100,
            command=self.refresh,
        )
        self._refresh_btn.grid(row=0, column=1)
        theme.register(self._themed, self._refresh_btn,
                       fg_color="input_bg", hover_color="input_hover")

        self._last_refresh_lbl = ctk.CTkLabel(
            header, text="", font=ctk.CTkFont(size=11))
        self._last_refresh_lbl.grid(row=1, column=0, columnspan=2, sticky="w")
        theme.register(self._themed, self._last_refresh_lbl, text_color="dim")

        # ── Getting Started card (row=1, hidden by default) ──
        self._gs_frame = ctk.CTkFrame(self, corner_radius=10,
                                      border_width=1, border_color="#2a3a6a")
        self._gs_frame.grid(row=1, column=0, sticky="ew", padx=24, pady=(0, 8))
        theme.register(self._themed, self._gs_frame, fg_color="card2")
        self._gs_frame.grid_columnconfigure(0, weight=1)
        self._gs_frame.grid_remove()   # hidden until _refresh_getting_started() decides

        # ── Status card grid (2×2) ──
        grid = ctk.CTkFrame(self, fg_color="transparent")
        grid.grid(row=2, column=0, sticky="ew", padx=24, pady=(0, 8))
        grid.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self._cards["defender"]   = self._make_card(grid, 0, 0, "Security Posture",       "—", [],
                                                    lambda: self._navigate("winsec"))
        self._cards["signatures"] = self._make_card(grid, 0, 1, "K2 Engine Signatures",   "—", [],
                                                    lambda: self._navigate("update"))
        self._cards["last_scan"]  = self._make_card(grid, 0, 2, "Last Scan",              "—", [],
                                                    lambda: self._navigate("scan"))
        self._cards["watcher"]    = self._make_card(grid, 0, 3, "Folder Watcher",         "—", [],
                                                    lambda: self._navigate("watcher"))

        # ── Quick actions ──
        actions = ctk.CTkFrame(self, corner_radius=10)
        actions.grid(row=3, column=0, sticky="ew", padx=24, pady=(0, 8))
        actions.grid_columnconfigure((0, 1, 2, 3), weight=1)
        theme.register(self._themed, actions, fg_color="card")

        qa_title = ctk.CTkLabel(actions, text="Quick Actions",
                                font=ctk.CTkFont(size=13, weight="bold"))
        qa_title.grid(row=0, column=0, columnspan=4, sticky="w", padx=16, pady=(12, 8))
        theme.register(self._themed, qa_title, text_color="accent")

        quick_btns = [
            ("Defender Quick Scan", lambda: self._navigate("defender")),
            ("Scan Startup Items",  lambda: self._navigate("scan")),
            ("Update Signatures",   lambda: self._navigate("update")),
            ("VirusTotal Lookup",   lambda: self._navigate("virustotal")),
        ]
        for col, (label, cmd) in enumerate(quick_btns):
            qb = ctk.CTkButton(actions, text=label, height=34,
                               font=ctk.CTkFont(size=12),
                               command=cmd)
            qb.grid(row=1, column=col, padx=8, pady=(0, 14), sticky="ew")
            theme.register(self._themed, qb,
                           fg_color="nav_active", hover_color="accent_hover")

        # ── Recent threats ──
        ctk.CTkLabel(self, text="Recent Threats",
                     font=ctk.CTkFont(size=14, weight="bold")).grid(
            row=4, column=0, sticky="w", padx=24, pady=(4, 4))

        self._threats_frame = ctk.CTkScrollableFrame(
            self, height=140, corner_radius=8)
        self._threats_frame.grid(row=5, column=0, sticky="ew", padx=24, pady=(0, 16))
        self._threats_frame.grid_columnconfigure(0, weight=1)
        theme.register(self._themed, self._threats_frame, fg_color="card")

        self._no_threats_lbl = ctk.CTkLabel(
            self._threats_frame, text="No recent threats detected",
            font=ctk.CTkFont(size=13))
        self._no_threats_lbl.grid(row=0, column=0, pady=20)
        theme.register(self._themed, self._no_threats_lbl, text_color="dim")

    def _make_card(self, parent, row, col, title, status_text,
                   detail_lines, click_cmd):
        card = ctk.CTkFrame(parent, corner_radius=10, cursor="hand2")
        card.grid(row=row, column=col, padx=6, pady=6, sticky="ew")
        card.grid_columnconfigure(0, weight=1)
        card.bind("<Button-1>", lambda e: click_cmd())
        theme.register(self._themed, card, fg_color="nav_active")

        title_lbl = ctk.CTkLabel(card, text=title,
                                  font=ctk.CTkFont(size=11, weight="bold"),
                                  anchor="w")
        title_lbl.grid(row=0, column=0, sticky="w", padx=14, pady=(12, 2))
        theme.register(self._themed, title_lbl, text_color="subtext")

        status_lbl = ctk.CTkLabel(card, text=status_text,
                                   font=ctk.CTkFont(size=18, weight="bold"),
                                   anchor="w")
        status_lbl.grid(row=1, column=0, sticky="w", padx=14, pady=(0, 2))

        detail_lbls = []
        for i in range(3):
            text = detail_lines[i] if i < len(detail_lines) else ""
            lbl = ctk.CTkLabel(card, text=text, font=ctk.CTkFont(size=11),
                               anchor="w")
            lbl.grid(row=2 + i, column=0, sticky="w", padx=14,
                     pady=(0, 12 if i == 2 else 1))
            theme.register(self._themed, lbl, text_color="subtext")
            detail_lbls.append(lbl)

        return {"card": card, "status": status_lbl, "details": detail_lbls}

    def _update_card(self, key: str, status_text: str, color: str,
                     detail_lines: list[str]):
        card = self._cards[key]
        card["status"].configure(text=status_text, text_color=color)
        for i, lbl in enumerate(card["details"]):
            lbl.configure(text=detail_lines[i] if i < len(detail_lines) else "")

    def refresh(self):
        self._refresh_btn.configure(state="disabled", text="Refreshing…")
        self._status_cb("Refreshing dashboard…")

        def _load():
            dfn_status = dfn.get_status()
            sig_info = sc.get_update_cfg_info()
            last_scan = _last_scan_info()
            threats = dfn.get_threat_names(limit=10)
            fw = ws.get_firewall_profiles()
            ac = ws.get_app_browser_control()
            score_info = ws.get_security_score(
                defender_status=dfn_status,
                firewall_profiles=fw,
                app_control=ac,
            )
            self.after(0, self._apply, dfn_status, sig_info, last_scan, threats, score_info)

        threading.Thread(target=_load, daemon=True).start()

    def _apply(self, dfn_status, sig_info, last_scan, threats, score_info=None):
        # ── Security Posture card (composite score) ──
        if score_info:
            score = score_info.get("score", 0)
            label = score_info.get("label", "Unknown")
            top_issue = score_info.get("top_issue", "")
            color = "#50fa7b" if score >= 75 else ("#ffb86c" if score >= 55 else "#ff5555")
            rt = dfn_status.get("RealTimeProtectionEnabled", False) if dfn_status.get("available") else False
            fw_issues = score_info.get("breakdown", {}).get("Firewall", {}).get("issues", [])
            detail2 = fw_issues[0] if fw_issues else "Firewall OK"
            self._update_card("defender", f"{score}/100 — {label}", color, [
                f"Defender RT: {'ON' if rt else 'OFF'}",
                detail2,
                top_issue[:40] + "…" if top_issue and len(top_issue) > 40 else top_issue,
            ])
        else:
            self._update_card("defender", "Loading…", "#888888", ["", "", ""])

        # ── Signatures card ──
        sig_lines = [l for l in sig_info.get("raw", "").splitlines() if l.strip()]
        sig_count = len(sig_lines)
        sig_updated = sig_info.get("last_updated", "Unknown")
        self._update_card("signatures", f"{sig_count} files", theme.color("text"), [
            f"Updated: {sig_updated}", "", ""])

        # ── Last scan card ──
        if last_scan:
            inf = last_scan.get("infected", 0)
            color = "#ff5555" if inf else "#50fa7b"
            self._update_card("last_scan", last_scan.get("age", "—"), color, [
                f"{last_scan.get('total', 0)} files scanned",
                f"{inf} threat(s) found", "",
            ])
        else:
            self._update_card("last_scan", "Never", "#888888",
                              ["No scan history found", "", ""])

        # ── Watcher card ──
        folders = cfg.get("watcher_folders") or []
        running = wtch.is_running()
        color = "#50fa7b" if running else "#888888"
        status = "WATCHING" if running else "IDLE"
        self._update_card("watcher", status, color, [
            f"{len(folders)} folder(s) configured",
            f"{len(wtch.get_log())} events logged", "",
        ])

        # ── Recent threats ──
        for w in self._threats_frame.winfo_children():
            w.destroy()

        if threats:
            self._no_threats_lbl = None
            for i, t in enumerate(threats[:8]):
                name = t.get("ThreatName", "Unknown")
                active = t.get("IsActive", False)
                # Status colours are semantic — kept hardcoded across all themes
                color = "#ff5555" if active else "#ffb86c"
                bg = theme.color("card2") if i % 2 == 0 else theme.color("card")
                row_f = ctk.CTkFrame(self._threats_frame, fg_color=bg)
                row_f.grid(row=i, column=0, sticky="ew", pady=1)
                row_f.grid_columnconfigure(0, weight=1)
                ctk.CTkLabel(row_f, text=name, anchor="w",
                             text_color=color, font=ctk.CTkFont(size=12)).grid(
                    row=0, column=0, sticky="w", padx=12, pady=4)
                ctk.CTkLabel(row_f, text="Active" if active else "Resolved",
                             text_color=color, font=ctk.CTkFont(size=11)).grid(
                    row=0, column=1, padx=12)
        else:
            lbl = ctk.CTkLabel(self._threats_frame,
                               text="No recent threats detected",
                               text_color=theme.color("dim"),
                               font=ctk.CTkFont(size=13))
            lbl.grid(row=0, column=0, pady=20)

        self._last_refresh_lbl.configure(
            text=f"Last refreshed: {datetime.now().strftime('%H:%M:%S')}")
        self._refresh_btn.configure(state="normal", text="Refresh")
        self._status_cb("Dashboard updated")

    # ── Getting Started card ──────────────────────────────────────────────────

    def _refresh_getting_started(self) -> None:
        """Show/update/hide the Getting Started checklist card."""
        if cfg.get("getting_started_dismissed"):
            self._gs_frame.grid_remove()
            return

        has_db   = _has_intel()
        has_svc  = _svc_installed()
        has_scan = _has_scan_history()

        # All steps complete — auto-dismiss permanently
        if has_db and has_svc and has_scan:
            cfg.set_value("getting_started_dismissed", True)
            self._gs_frame.grid_remove()
            return

        self._build_getting_started(has_db, has_svc, has_scan)
        self._gs_frame.grid()

    def _build_getting_started(self, has_db: bool, has_svc: bool,
                                has_scan: bool) -> None:
        """Rebuild the Getting Started card contents."""
        for w in self._gs_frame.winfo_children():
            w.destroy()

        # Header
        hdr = ctk.CTkFrame(self._gs_frame, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=16, pady=(12, 6))
        hdr.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(hdr, text="🚀  Getting Started",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=theme.color("accent"), anchor="w").grid(
            row=0, column=0, sticky="w")
        ctk.CTkButton(
            hdr, text="Dismiss", width=76, height=24,
            fg_color=theme.color("input_bg"),
            hover_color=theme.color("input_hover"),
            font=ctk.CTkFont(size=11),
            command=self._dismiss_getting_started,
        ).grid(row=0, column=1, sticky="e")

        # Checklist items
        steps = [
            (has_db,
             "Populate the threat database",
             "Run Update All in Update Center to download MalwareBazaar signatures.",
             "update"),
            (has_svc,
             "Install Windows Service",
             "Enables persistent background protection and folder watching.",
             "service"),
            (has_scan,
             "Run your first scan",
             "Use the Scan view to scan a folder or your whole system.",
             "scan"),
        ]
        for i, (done, title, desc, nav_key) in enumerate(steps):
            row_f = ctk.CTkFrame(self._gs_frame, fg_color="transparent")
            row_f.grid(row=i + 1, column=0, sticky="ew", padx=16, pady=2)
            row_f.grid_columnconfigure(1, weight=1)

            icon  = "✓" if done else "○"
            # Done is semantic green; pending is theme text token for visibility
            icon_color = "#50fa7b" if done else theme.color("text")
            ctk.CTkLabel(row_f, text=icon, width=22,
                         font=ctk.CTkFont(size=14, weight="bold"),
                         text_color=icon_color).grid(row=0, column=0, padx=(0, 6))
            ctk.CTkLabel(row_f, text=title,
                         font=ctk.CTkFont(size=12,
                                          weight="normal" if done else "bold"),
                         text_color=theme.color("subtext") if done else theme.color("text"),
                         anchor="w").grid(row=0, column=1, sticky="w")
            if not done and self._navigate:
                ctk.CTkButton(
                    row_f, text="→", width=36, height=24,
                    fg_color=theme.color("nav_active"),
                    hover_color=theme.color("accent_hover"),
                    font=ctk.CTkFont(size=13),
                    command=lambda k=nav_key: self._navigate(k),
                ).grid(row=0, column=2, padx=(8, 0))

        # Bottom spacer
        ctk.CTkFrame(self._gs_frame, fg_color="transparent", height=10).grid(
            row=len(steps) + 1, column=0)

    def _dismiss_getting_started(self) -> None:
        cfg.set_value("getting_started_dismissed", True)
        self._gs_frame.grid_remove()

    # ── Lifecycle ────────────────────────────────────────────────────────────

    def on_show(self):
        """Called by App when this view becomes visible."""
        self._refresh_getting_started()
        self.refresh()
