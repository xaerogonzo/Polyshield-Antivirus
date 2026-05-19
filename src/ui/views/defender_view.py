import threading
import customtkinter as ctk
from ui.core import defender as dfn

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
        self.grid_rowconfigure(3, weight=1)

        # ── Title ──
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=24, pady=(20, 8))
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(header, text="Windows Defender",
                     font=ctk.CTkFont(size=22, weight="bold")).grid(
            row=0, column=0, sticky="w")
        self._refresh_btn = ctk.CTkButton(
            header, text="Refresh", width=100,
            fg_color="#3a3a3a", hover_color="#4a4a4a",
            command=self.refresh)
        self._refresh_btn.grid(row=0, column=1)

        # ── Protection status cards ──
        status_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="#1a1a2e")
        status_frame.grid(row=1, column=0, sticky="ew", padx=24, pady=(0, 8))
        status_frame.grid_columnconfigure(tuple(range(len(_PROTECTION_FIELDS))), weight=1)

        ctk.CTkLabel(status_frame, text="Protection Status",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#5294e2").grid(
            row=0, column=0, columnspan=len(_PROTECTION_FIELDS),
            sticky="w", padx=16, pady=(12, 8))

        for col, (key, label) in enumerate(_PROTECTION_FIELDS):
            cell = ctk.CTkFrame(status_frame, corner_radius=8, fg_color="#12121e")
            cell.grid(row=1, column=col, padx=6, pady=(0, 12), sticky="ew")
            ctk.CTkLabel(cell, text=label, font=ctk.CTkFont(size=10),
                         text_color="#666688", wraplength=100, justify="center").grid(
                row=0, column=0, padx=8, pady=(8, 2))
            lbl = ctk.CTkLabel(cell, text="—", font=ctk.CTkFont(size=13, weight="bold"))
            lbl.grid(row=1, column=0, padx=8, pady=(0, 8))
            self._status_labels[key] = lbl

        # ── Signature info + scan ages ──
        info_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="#1a1a2e")
        info_frame.grid(row=2, column=0, sticky="ew", padx=24, pady=(0, 8))
        info_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        ctk.CTkLabel(info_frame, text="Signature & Scan Info",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#5294e2").grid(
            row=0, column=0, columnspan=4, sticky="w", padx=16, pady=(12, 8))

        self._info_labels: dict[str, ctk.CTkLabel] = {}
        info_items = [
            ("sig_age",   "Signature Age"),
            ("sig_date",  "Last Updated"),
            ("quick_age", "Quick Scan Age"),
            ("full_age",  "Full Scan Age"),
        ]
        for col, (key, label) in enumerate(info_items):
            cell = ctk.CTkFrame(info_frame, corner_radius=8, fg_color="#12121e")
            cell.grid(row=1, column=col, padx=6, pady=(0, 12), sticky="ew")
            ctk.CTkLabel(cell, text=label, font=ctk.CTkFont(size=10),
                         text_color="#666688").grid(row=0, column=0, padx=12, pady=(8, 2))
            lbl = ctk.CTkLabel(cell, text="—", font=ctk.CTkFont(size=14, weight="bold"))
            lbl.grid(row=1, column=0, padx=12, pady=(0, 8))
            self._info_labels[key] = lbl

        # ── Scan trigger buttons ──
        scan_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="#1a1a2e")
        scan_frame.grid(row=3, column=0, sticky="ew", padx=24, pady=(0, 8))
        scan_frame.grid_columnconfigure((0, 1, 2), weight=1)

        ctk.CTkLabel(scan_frame, text="Trigger Scan",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#5294e2").grid(
            row=0, column=0, columnspan=3, sticky="w", padx=16, pady=(12, 8))

        self._scan_btns = {}
        for col, (label, stype) in enumerate([
            ("Quick Scan", "QuickScan"),
            ("Full Scan",  "FullScan"),
        ]):
            btn = ctk.CTkButton(
                scan_frame, text=label, height=36,
                fg_color="#1f6aa5", hover_color="#144e7a",
                command=lambda t=stype: self._trigger_scan(t),
            )
            btn.grid(row=1, column=col, padx=8, pady=(0, 14), sticky="ew")
            self._scan_btns[stype] = btn

        self._scan_status_lbl = ctk.CTkLabel(
            scan_frame, text="", font=ctk.CTkFont(size=12), text_color="#888888")
        self._scan_status_lbl.grid(row=1, column=2, padx=8, sticky="ew")

        # ── Threat history ──
        ctk.CTkLabel(self, text="Threat History",
                     font=ctk.CTkFont(size=14, weight="bold")).grid(
            row=4, column=0, sticky="w", padx=24, pady=(8, 4))

        self._threats_scroll = ctk.CTkScrollableFrame(
            self, corner_radius=8, fg_color="#1a1a2e")
        self._threats_scroll.grid(row=5, column=0, sticky="nsew",
                                   padx=24, pady=(0, 16))
        self._threats_scroll.grid_columnconfigure((0, 1), weight=1)
        self.grid_rowconfigure(5, weight=1)

        self._no_threat_lbl = ctk.CTkLabel(
            self._threats_scroll, text="No threat history found",
            text_color="#555577", font=ctk.CTkFont(size=13))
        self._no_threat_lbl.grid(row=0, column=0, columnspan=2, pady=24)

    def refresh(self):
        self._refresh_btn.configure(state="disabled", text="Refreshing…")
        self._status_cb("Reading Defender status…")

        def _load():
            status = dfn.get_status()
            threats = dfn.get_threat_names(limit=30)
            self.after(0, self._apply, status, threats)

        threading.Thread(target=_load, daemon=True).start()

    def _apply(self, status: dict, threats: list):
        if not status.get("available"):
            for lbl in self._status_labels.values():
                lbl.configure(text="N/A", text_color="#888888")
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
                               text_color="#555577", font=ctk.CTkFont(size=13))
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
