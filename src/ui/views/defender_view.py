import threading
import customtkinter as ctk
from ui.core import defender as dfn
import ui.theme as theme

_PROTECTION_FIELDS = [
    ("RealTimeProtectionEnabled",  "Real-Time Protection"),
    ("AntivirusEnabled",           "Antivirus"),
    ("AntispywareEnabled",         "Antispyware"),
    ("BehaviorMonitorEnabled",     "Behavior Monitor"),
    ("IoavProtectionEnabled",      "Downloaded File Scan"),
    ("NISEnabled",                 "Network Inspection"),
]


class DefenderView(ctk.CTkFrame):
    def __init__(self, master, status_callback, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self._status_cb = status_callback
        self._status_labels: dict[str, ctk.CTkLabel] = {}
        self._build()
        self.refresh()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(6, weight=1)

        # ── Title ──
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=24, pady=(20, 8))
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(header, text="Windows Defender",
                     font=ctk.CTkFont(size=22, weight="bold")).grid(
            row=0, column=0, sticky="w")
        self._refresh_btn = ctk.CTkButton(
            header, text="Refresh", width=100,
            fg_color=theme.color("divider"), hover_color="#4a4a4a",
            command=self.refresh)
        self._refresh_btn.grid(row=0, column=1)

        # ── Protection status cards ──
        status_frame = ctk.CTkFrame(self, corner_radius=10, fg_color=theme.color("card"))
        status_frame.grid(row=1, column=0, sticky="ew", padx=24, pady=(0, 8))
        status_frame.grid_columnconfigure(tuple(range(len(_PROTECTION_FIELDS))), weight=1)

        ctk.CTkLabel(status_frame, text="Protection Status",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=theme.color("accent")).grid(
            row=0, column=0, columnspan=len(_PROTECTION_FIELDS),
            sticky="w", padx=16, pady=(12, 8))

        for col, (key, label) in enumerate(_PROTECTION_FIELDS):
            cell = ctk.CTkFrame(status_frame, corner_radius=8, fg_color=theme.color("card2"))
            cell.grid(row=1, column=col, padx=6, pady=(0, 12), sticky="ew")
            ctk.CTkLabel(cell, text=label, font=ctk.CTkFont(size=10),
                         text_color=theme.color("subtext"), wraplength=100, justify="center").grid(
                row=0, column=0, padx=8, pady=(8, 2))
            lbl = ctk.CTkLabel(cell, text="—", font=ctk.CTkFont(size=13, weight="bold"))
            lbl.grid(row=1, column=0, padx=8, pady=(0, 8))
            self._status_labels[key] = lbl

        # ── Signature info + scan ages ──
        info_frame = ctk.CTkFrame(self, corner_radius=10, fg_color=theme.color("card"))
        info_frame.grid(row=2, column=0, sticky="ew", padx=24, pady=(0, 8))
        info_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        ctk.CTkLabel(info_frame, text="Signature & Scan Info",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=theme.color("accent")).grid(
            row=0, column=0, columnspan=4, sticky="w", padx=16, pady=(12, 8))

        self._info_labels: dict[str, ctk.CTkLabel] = {}
        info_items = [
            ("sig_age",   "Signature Age"),
            ("sig_date",  "Last Updated"),
            ("quick_age", "Quick Scan Age"),
            ("full_age",  "Full Scan Age"),
        ]
        for col, (key, label) in enumerate(info_items):
            cell = ctk.CTkFrame(info_frame, corner_radius=8, fg_color=theme.color("card2"))
            cell.grid(row=1, column=col, padx=6, pady=(0, 12), sticky="ew")
            ctk.CTkLabel(cell, text=label, font=ctk.CTkFont(size=10),
                         text_color=theme.color("subtext")).grid(row=0, column=0, padx=12, pady=(8, 2))
            lbl = ctk.CTkLabel(cell, text="—", font=ctk.CTkFont(size=14, weight="bold"))
            lbl.grid(row=1, column=0, padx=12, pady=(0, 8))
            self._info_labels[key] = lbl

        # ── Scan trigger buttons ──
        scan_frame = ctk.CTkFrame(self, corner_radius=10, fg_color=theme.color("card"))
        scan_frame.grid(row=3, column=0, sticky="ew", padx=24, pady=(0, 8))
        scan_frame.grid_columnconfigure((0, 1, 2), weight=1)

        ctk.CTkLabel(scan_frame, text="Trigger Scan",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=theme.color("accent")).grid(
            row=0, column=0, columnspan=3, sticky="w", padx=16, pady=(12, 8))

        self._scan_btns = {}
        for col, (label, stype) in enumerate([
            ("Quick Scan", "QuickScan"),
            ("Full Scan",  "FullScan"),
        ]):
            btn = ctk.CTkButton(
                scan_frame, text=label, height=36,
                fg_color=theme.color("accent"), hover_color=theme.color("accent_hover"),
                command=lambda t=stype: self._trigger_scan(t),
            )
            btn.grid(row=1, column=col, padx=8, pady=(0, 14), sticky="ew")
            self._scan_btns[stype] = btn

        self._scan_status_lbl = ctk.CTkLabel(
            scan_frame, text="", font=ctk.CTkFont(size=12), text_color=theme.color("subtext"))
        self._scan_status_lbl.grid(row=1, column=2, padx=8, sticky="ew")

        # ── Coexistence ──
        #
        # PolyShield cannot register with Windows Security Center: that route is
        # Microsoft's antimalware-partner path (ELAM signing / the Microsoft
        # Virus Initiative) and is not open to an unsigned application shipped as
        # source. Nothing here tries. What this line does is stop the product
        # from implying otherwise -- and, when Defender's real-time protection is
        # off, say what PolyShield is actually covering instead of leaving the
        # user to assume.
        self._coexist_frame = ctk.CTkFrame(self, corner_radius=8,
                                           fg_color=theme.color("card2"))
        self._coexist_frame.grid(row=4, column=0, sticky="ew", padx=24, pady=(4, 8))
        self._coexist_frame.grid_columnconfigure(0, weight=1)
        self._coexist_lbl = ctk.CTkLabel(
            self._coexist_frame, text="", anchor="w", justify="left",
            font=ctk.CTkFont(size=11), wraplength=820)
        self._coexist_lbl.grid(row=0, column=0, sticky="w", padx=14, pady=9)

        # ── Threat history ──
        ctk.CTkLabel(self, text="Threat History",
                     font=ctk.CTkFont(size=14, weight="bold")).grid(
            row=5, column=0, sticky="w", padx=24, pady=(8, 4))

        self._threats_scroll = ctk.CTkScrollableFrame(
            self, corner_radius=8, fg_color=theme.color("card"))
        self._threats_scroll.grid(row=6, column=0, sticky="nsew",
                                   padx=24, pady=(0, 16))
        self._threats_scroll.grid_columnconfigure((0, 1), weight=1)
        self.grid_rowconfigure(6, weight=1)

        self._no_threat_lbl = ctk.CTkLabel(
            self._threats_scroll, text="No threat history found",
            text_color=theme.color("dim"), font=ctk.CTkFont(size=13))
        self._no_threat_lbl.grid(row=0, column=0, columnspan=2, pady=24)

    def refresh(self):
        self._refresh_btn.configure(state="disabled", text="Refreshing…")
        self._status_cb("Reading Defender status…")

        def _load():
            status = dfn.get_status()
            threats = dfn.get_threat_names(limit=30)
            self.after(0, self._apply, status, threats)

        threading.Thread(target=_load, daemon=True).start()

    #: (defender_rtp_on, polyshield_state) -> (text, colour).
    #: polyshield_state is "service" | "watcher" | "none".
    _COEXISTENCE = {
        (True, "service"): (
            "PolyShield runs alongside Microsoft Defender. Defender remains your "
            "registered antivirus in Windows Security; PolyShield adds real-time "
            "file, process and network monitoring on top of it.", "subtext"),
        (True, "watcher"): (
            "PolyShield runs alongside Microsoft Defender. Defender remains your "
            "registered antivirus in Windows Security; PolyShield is monitoring "
            "files in-process \u2014 process and network monitoring need the "
            "background service.", "subtext"),
        (True, "none"): (
            "PolyShield runs alongside Microsoft Defender, which is doing the "
            "real-time protection right now: PolyShield's own watcher and service "
            "are both stopped.", "subtext"),
        (False, "service"): (
            "Defender real-time protection is off. PolyShield's background service "
            "is running, but PolyShield is NOT a Windows Security Center-registered "
            "antivirus \u2014 Windows still lists Defender as your registered AV.",
            "#ffb86c"),
        (False, "watcher"): (
            "Defender real-time protection is off. PolyShield is monitoring files "
            "only \u2014 no process or network monitoring \u2014 and it does not "
            "replace Defender as your Windows-registered antivirus.", "#ffb86c"),
        (False, "none"): (
            "Defender real-time protection is off and PolyShield is not providing "
            "file, process or network protection either. Nothing on this machine "
            "is scanning in real time.", "#ff5555"),
    }

    def _polyshield_state(self) -> str:
        from ui.core import service_client as svc
        from ui.core import watcher as wtch

        try:
            if svc.is_service_running():
                return "service"
        except Exception:
            pass
        try:
            if wtch.is_running():
                return "watcher"
        except Exception:
            pass
        return "none"

    def _apply_coexistence(self, status: dict) -> None:
        """Say what is true, including when it is unflattering.

        Computed from the same two facts the Dashboard banner uses, so the two
        pages cannot disagree about whether PolyShield is protecting anything --
        which is how a reassuring sentence ends up on a machine that has nothing
        running.
        """
        if not status.get("available"):
            self._coexist_lbl.configure(
                text="Defender status is unavailable, so PolyShield cannot say what "
                     "is covering this machine. PolyShield is not a Windows Security "
                     "Center-registered antivirus in any case.",
                text_color=theme.color("subtext"))
            return
        rtp = bool(status.get("RealTimeProtectionEnabled"))
        text, colour = self._COEXISTENCE[(rtp, self._polyshield_state())]
        self._coexist_lbl.configure(
            text=text,
            text_color=theme.color(colour) if not colour.startswith("#") else colour)

    def _apply(self, status: dict, threats: list):
        self._apply_coexistence(status)
        if not status.get("available"):
            for lbl in self._status_labels.values():
                lbl.configure(text="N/A", text_color=theme.color("subtext"))
            for lbl in self._info_labels.values():
                lbl.configure(text="N/A")
            self._status_cb("Defender status unavailable")
        else:
            for key, lbl in self._status_labels.items():
                val = status.get(key, False)
                lbl.configure(
                    text="ON" if val else "OFF",
                    text_color="#50fa7b" if val else "#ff5555",
                )
            self._info_labels["sig_age"].configure(
                text=f"{status.get('AntivirusSignatureAge', '?')}d")
            self._info_labels["sig_date"].configure(
                text=str(status.get("AntivirusSignatureLastUpdated", "—")))
            self._info_labels["quick_age"].configure(
                text=f"{status.get('QuickScanAge', '?')}d")
            self._info_labels["full_age"].configure(
                text=f"{status.get('FullScanAge', '?')}d")
            self._status_cb("Defender status loaded")

        # Threats
        for w in self._threats_scroll.winfo_children():
            w.destroy()

        if not threats:
            lbl = ctk.CTkLabel(self._threats_scroll,
                               text="No threat history found",
                               text_color=theme.color("dim"), font=ctk.CTkFont(size=13))
            lbl.grid(row=0, column=0, columnspan=2, pady=24)
        else:
            for i, t in enumerate(threats):
                name = t.get("ThreatName", "Unknown")
                active = t.get("IsActive", False)
                bg = "#1e1e2e" if i % 2 == 0 else "#232340"
                color = "#ff5555" if active else "#cdd6f4"
                row_f = ctk.CTkFrame(self._threats_scroll, fg_color=bg)
                row_f.grid(row=i, column=0, columnspan=2, sticky="ew", pady=1)
                row_f.grid_columnconfigure(0, weight=1)
                ctk.CTkLabel(row_f, text=name, anchor="w",
                             text_color=color, font=ctk.CTkFont(size=12)).grid(
                    row=0, column=0, sticky="w", padx=12, pady=5)
                ctk.CTkLabel(row_f,
                             text="Active" if active else "Resolved",
                             text_color=color,
                             font=ctk.CTkFont(size=11)).grid(
                    row=0, column=1, padx=12)

        self._refresh_btn.configure(state="normal", text="Refresh")

    def _trigger_scan(self, scan_type: str):
        for btn in self._scan_btns.values():
            btn.configure(state="disabled")
        self._scan_status_lbl.configure(text=f"Starting {scan_type}…",
                                         text_color="#ffb86c")

        def _done(ok, msg):
            def _update():
                for btn in self._scan_btns.values():
                    btn.configure(state="normal")
                color = "#50fa7b" if ok else "#ff5555"
                self._scan_status_lbl.configure(text=msg, text_color=color)
                self._status_cb(msg)
            self.after(0, _update)

        dfn.start_scan_async(scan_type, "", _done)
