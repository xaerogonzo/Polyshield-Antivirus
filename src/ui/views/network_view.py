"""
network_view.py
───────────────
"Network" sidebar panel — live connection monitor and C2 alert feed.

Two sections:
  • Live Connections — established outbound TCP connections with process
    attribution; flagged entries (known-bad C2 IPs) shown in amber/red.
  • Recent Alerts    — last 50 network_event pushes from the service,
    each listing the flagged connections with timestamp and reason.

When the service is running, connections are fetched from the service's
ring buffer; when not running, poll_connections() is called directly.
Blocking requires a UAC-elevated PowerShell call (New-NetFirewallRule).
"""
from __future__ import annotations

import subprocess
import threading
from datetime import datetime

import customtkinter as ctk

from ui.core import service_client as svc
from ui.core.network_monitor import poll_connections
import ui.theme as theme

_NO_WINDOW = subprocess.CREATE_NO_WINDOW

_GREEN  = "#50fa7b"
_RED    = "#ff5555"
_AMBER  = "#ffb86c"
_BLUE   = "#8be9fd"
_DIM    = "#555577"
_CARD   = "#1a1a2e"


class NetworkView(ctk.CTkScrollableFrame):
    def __init__(self, master, status_callback, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self._status_cb   = status_callback
        self._busy        = False
        self._conn_rows: list[ctk.CTkFrame] = []
        self._alert_rows: list[ctk.CTkFrame] = []
        self._build()

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self):
        self.grid_columnconfigure(0, weight=1)

        # Header
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=24, pady=(20, 8))
        hdr.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            hdr, text="Network Monitor",
            font=ctk.CTkFont(size=22, weight="bold"),
        ).grid(row=0, column=0, sticky="w")

        self._refresh_btn = ctk.CTkButton(
            hdr, text="↺  Refresh", width=110,
            fg_color=theme.color("accent"), hover_color=theme.color("accent_hover"),
            font=ctk.CTkFont(size=12),
            command=self._do_refresh,
        )
        self._refresh_btn.grid(row=0, column=1)

        ctk.CTkLabel(
            hdr,
            text="Monitors outbound TCP connections and checks IPs against the C2 blocklist.  "
                 "No kernel driver — monitoring works without admin.\n"
                 "Flagged: ● C2 known-bad IP (Feodo/ThreatFox)  ● Unsigned process with external connection  "
                 "— click Block to add a Windows Firewall outbound rule (requires a one-time admin approval).",
            font=ctk.CTkFont(size=11), text_color=_DIM, anchor="w", justify="left",
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(2, 0))

        # ── Live Connections section ──
        self._conn_card = ctk.CTkFrame(self, corner_radius=10, fg_color=_CARD)
        self._conn_card.grid(row=1, column=0, sticky="ew", padx=24, pady=(8, 6))
        self._conn_card.grid_columnconfigure(0, weight=1)

        conn_hdr = ctk.CTkFrame(self._conn_card, fg_color="transparent")
        conn_hdr.grid(row=0, column=0, sticky="ew", padx=16, pady=(12, 6))
        conn_hdr.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            conn_hdr, text="Live Connections",
            font=ctk.CTkFont(size=14, weight="bold"), text_color=_BLUE,
        ).grid(row=0, column=0, sticky="w")

        self._conn_status_lbl = ctk.CTkLabel(
            conn_hdr, text="Not loaded",
            font=ctk.CTkFont(size=11), text_color=_DIM,
        )
        self._conn_status_lbl.grid(row=0, column=1, sticky="e")

        # Table header row
        tbl_hdr = ctk.CTkFrame(self._conn_card, fg_color="#111122", corner_radius=6)
        tbl_hdr.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 2))
        tbl_hdr.grid_columnconfigure(0, weight=2)
        tbl_hdr.grid_columnconfigure(1, weight=3)
        tbl_hdr.grid_columnconfigure(2, weight=1)
        tbl_hdr.grid_columnconfigure(3, weight=1)

        for col, text in enumerate(["Process", "Remote IP:Port", "Status", ""]):
            ctk.CTkLabel(
                tbl_hdr, text=text,
                font=ctk.CTkFont(size=11, weight="bold"), text_color=theme.color("subtext"),
                anchor="w",
            ).grid(row=0, column=col, sticky="ew", padx=8, pady=4)

        # Container for data rows
        self._conn_table = ctk.CTkFrame(self._conn_card, fg_color="transparent")
        self._conn_table.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 12))
        self._conn_table.grid_columnconfigure(0, weight=2)
        self._conn_table.grid_columnconfigure(1, weight=3)
        self._conn_table.grid_columnconfigure(2, weight=1)
        self._conn_table.grid_columnconfigure(3, weight=1)

        self._conn_empty_lbl = ctk.CTkLabel(
            self._conn_table, text="Click Refresh to load connections.",
            font=ctk.CTkFont(size=11), text_color=_DIM,
        )
        self._conn_empty_lbl.grid(row=0, column=0, columnspan=4, pady=8)

        # ── Recent Alerts section ──
        self._alert_card = ctk.CTkFrame(self, corner_radius=10, fg_color=_CARD)
        self._alert_card.grid(row=2, column=0, sticky="ew", padx=24, pady=(0, 16))
        self._alert_card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            self._alert_card, text="Recent Alerts",
            font=ctk.CTkFont(size=14, weight="bold"), text_color=_AMBER,
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(12, 4))

        self._alert_lbl = ctk.CTkLabel(
            self._alert_card,
            text="No alerts yet. Alerts appear when flagged connections are detected.",
            font=ctk.CTkFont(size=11), text_color=_DIM, anchor="w", justify="left",
        )
        self._alert_lbl.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 6))

        self._alert_list = ctk.CTkTextbox(
            self._alert_card,
            font=ctk.CTkFont(family="Consolas", size=11),
            wrap="word", state="disabled", height=140,
        )
        self._alert_list.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 12))
        self._alert_list.tag_config("alert", foreground=_AMBER)
        self._alert_list.tag_config("ts",    foreground=_DIM)

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    def on_show(self):
        """Called every time user navigates to this view."""
        self._do_refresh()
        self._load_recent_alerts()

    # ── Data loading ───────────────────────────────────────────────────────────

    def _do_refresh(self):
        if self._busy:
            return
        self._busy = True
        self._refresh_btn.configure(state="disabled", text="…")
        self._conn_status_lbl.configure(text="Loading…", text_color=_DIM)
        threading.Thread(target=self._fetch_connections, daemon=True).start()

    def _fetch_connections(self):
        """Background: get connections via service if running, else direct psutil."""
        try:
            if svc.is_service_running():
                events = svc.get_network_events(limit=1)
                if events:
                    connections = events[-1].get("connections", [])
                else:
                    # Service running but no events yet — poll directly
                    connections = poll_connections()
            else:
                connections = poll_connections()
        except Exception:
            connections = []

        if self.winfo_exists():
            self.after(0, self._apply_connections, connections)

    def _apply_connections(self, connections: list[dict]):
        self._busy = False
        self._refresh_btn.configure(state="normal", text="↺  Refresh")

        # Clear existing rows
        for widget in self._conn_table.winfo_children():
            widget.destroy()

        if not connections:
            lbl = ctk.CTkLabel(
                self._conn_table,
                text="No external connections found (all local/private).",
                font=ctk.CTkFont(size=11), text_color=_DIM,
            )
            lbl.grid(row=0, column=0, columnspan=4, pady=8)
            self._conn_status_lbl.configure(
                text=f"0 connections  —  {datetime.now().strftime('%H:%M:%S')}",
                text_color=_DIM,
            )
            return

        flagged_count = sum(1 for c in connections if c["flagged"])
        status_color  = _RED if flagged_count else _GREEN
        status_text   = (
            f"{len(connections)} connections, {flagged_count} flagged"
            if flagged_count else
            f"{len(connections)} connections — all clean"
        )
        self._conn_status_lbl.configure(text=status_text, text_color=status_color)

        for row_idx, conn in enumerate(connections):
            bg = "#2a1a1a" if conn["flagged"] else "transparent"
            row_frame = ctk.CTkFrame(self._conn_table, fg_color=bg, corner_radius=4)
            row_frame.grid(row=row_idx, column=0, columnspan=4, sticky="ew", pady=1)
            row_frame.grid_columnconfigure(0, weight=2)
            row_frame.grid_columnconfigure(1, weight=3)
            row_frame.grid_columnconfigure(2, weight=1)
            row_frame.grid_columnconfigure(3, weight=1)

            proc_text  = conn.get("process_name", "?")
            remote     = f"{conn['remote_addr']}:{conn['remote_port']}"
            status_txt = conn.get("reason", "clean")
            txt_color  = _AMBER if conn["flagged"] else "#cccccc"

            ctk.CTkLabel(
                row_frame, text=proc_text,
                font=ctk.CTkFont(size=11), text_color=txt_color, anchor="w",
            ).grid(row=0, column=0, sticky="ew", padx=8, pady=2)

            ctk.CTkLabel(
                row_frame, text=remote,
                font=ctk.CTkFont(family="Consolas", size=11),
                text_color=txt_color, anchor="w",
            ).grid(row=0, column=1, sticky="ew", padx=4, pady=2)

            ctk.CTkLabel(
                row_frame, text=status_txt,
                font=ctk.CTkFont(size=11), text_color=txt_color, anchor="w",
            ).grid(row=0, column=2, sticky="ew", padx=4, pady=2)

            if conn["flagged"]:
                ip = conn["remote_addr"]
                btn = ctk.CTkButton(
                    row_frame, text="Block", width=60,
                    fg_color="#6a1a1a", hover_color="#9a2a2a",
                    font=ctk.CTkFont(size=11),
                    command=lambda _ip=ip: self._block_ip(_ip),
                )
                btn.grid(row=0, column=3, padx=4, pady=2)

        self._status_cb(
            f"Network: {len(connections)} connections"
            + (f", {flagged_count} flagged!" if flagged_count else "")
        )

    def _load_recent_alerts(self):
        """Load the last 50 network alert events from the service."""
        def _run():
            if not svc.is_service_running():
                return
            events = svc.get_network_events(limit=50)
            alert_events = [e for e in events if e.get("alerts")]
            if self.winfo_exists():
                self.after(0, self._apply_alerts, alert_events)

        threading.Thread(target=_run, daemon=True).start()

    def _apply_alerts(self, alert_events: list[dict]):
        self._alert_list.configure(state="normal")
        self._alert_list.delete("1.0", "end")

        if not alert_events:
            self._alert_lbl.configure(
                text="No alerts recorded in this session.",
                text_color=_DIM,
            )
            self._alert_list.grid_remove()
            return

        self._alert_lbl.configure(
            text=f"{len(alert_events)} alert event(s) recorded:",
            text_color=_AMBER,
        )
        self._alert_list.grid()

        for ev in reversed(alert_events):
            ts      = ev.get("ts", "")
            alerts  = ev.get("alerts", [])
            self._alert_list.insert("end", f"[{ts}] ", "ts")
            for a in alerts:
                reason = a.get("reason", "")
                proc   = a.get("process_name", "?")
                ip     = a.get("remote_addr", "?")
                port   = a.get("remote_port", "?")
                self._alert_list.insert(
                    "end", f"{proc} → {ip}:{port}  ({reason})\n", "alert"
                )

        self._alert_list.configure(state="disabled")

    # ── Blocking ───────────────────────────────────────────────────────────────

    def _block_ip(self, ip: str):
        """Ask service to add a firewall rule; fall back to direct elevated PS call."""
        self._status_cb(f"Blocking {ip}…")

        def _run():
            ok, err = svc.block_ip(ip)
            if not ok:
                # Service (LocalService) can't add firewall rules — run elevated
                ok, err = self._block_ip_elevated(ip)
            if self.winfo_exists():
                msg = f"Blocked {ip}" if ok else f"Block failed: {err}"
                self.after(0, lambda m=msg: self._status_cb(m))

        threading.Thread(target=_run, daemon=True).start()

    @staticmethod
    def _block_ip_elevated(ip: str) -> tuple[bool, str]:
        """Launch an elevated PowerShell window to create the firewall rule."""
        rule_name = f"PolyShield-Block-{ip}"
        ps_cmd = (
            f"New-NetFirewallRule -DisplayName '{rule_name}' "
            f"-Direction Outbound -RemoteAddress '{ip}' "
            f"-Action Block -Profile Any -Enabled True"
        )
        try:
            import ctypes
            ret = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", "powershell.exe",
                f"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{ps_cmd}\"",
                None, 0,  # SW_HIDE
            )
            # ShellExecuteW returns >32 on success
            return int(ret) > 32, "" if int(ret) > 32 else f"ShellExecute returned {ret}"
        except Exception as exc:
            return False, str(exc)
