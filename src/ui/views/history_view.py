import json
import os
import subprocess
import customtkinter as ctk
from pathlib import Path
from ui.core import scanner as sc

_BASE_DIR = Path(__file__).resolve().parents[3]
_LOGS_DIR = _BASE_DIR / "logs"


def _load_reports() -> list[dict]:
    reports = []
    for f in sorted(_LOGS_DIR.glob("scan_*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            summary = sc.parse_report(str(f))
            reports.append({
                "path": f,
                "name": f.stem,
                "date": _mtime_str(f),
                **summary,
            })
        except Exception:
            pass
    return reports


def _mtime_str(p: Path) -> str:
    try:
        import datetime
        return datetime.datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "Unknown"


class HistoryView(ctk.CTkFrame):
    def __init__(self, master, status_callback, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self._status_cb = status_callback
        self._reports: list[dict] = []
        self._selected: dict | None = None
        self._build()
        self.refresh()

    def _build(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # ── Title row ──
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, columnspan=2, sticky="ew", padx=24, pady=(20, 8))
        header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(header, text="Scan History",
                     font=ctk.CTkFont(size=22, weight="bold")).grid(row=0, column=0, sticky="w")
        ctk.CTkButton(header, text="Refresh", width=100,
                      fg_color="#3a3a3a", hover_color="#4a4a4a",
                      command=self.refresh).grid(row=0, column=1)

        # ── Left: report list ──
        self._list_frame = ctk.CTkScrollableFrame(self, width=260, fg_color="#1a1a2e",
                                                   corner_radius=8)
        self._list_frame.grid(row=1, column=0, sticky="ns", padx=(24, 8), pady=(0, 16))
        self._list_frame.grid_columnconfigure(0, weight=1)

        self._empty_lbl = ctk.CTkLabel(self._list_frame, text="No scans yet",
                                        text_color="#555555", font=ctk.CTkFont(size=13))

        # ── Right: detail panel ──
        self._detail = ctk.CTkFrame(self, fg_color="#1a1a2e", corner_radius=8)
        self._detail.grid(row=1, column=1, sticky="nsew", padx=(0, 24), pady=(0, 16))
        self._detail.grid_columnconfigure(0, weight=1)
        self._detail.grid_rowconfigure(1, weight=1)

        self._detail_header = ctk.CTkFrame(self._detail, fg_color="transparent")
        self._detail_header.grid(row=0, column=0, sticky="ew", padx=16, pady=(12, 4))
        self._detail_header.grid_columnconfigure(0, weight=1)

        self._detail_title = ctk.CTkLabel(self._detail_header, text="Select a scan",
                                           font=ctk.CTkFont(size=15, weight="bold"))
        self._detail_title.grid(row=0, column=0, sticky="w")

        self._open_btn = ctk.CTkButton(self._detail_header, text="Open JSON", width=100,
                                        fg_color="#3a3a3a", hover_color="#4a4a4a",
                                        state="disabled", command=self._open_json)
        self._open_btn.grid(row=0, column=1)

        self._summary_bar = ctk.CTkLabel(self._detail_header, text="",
                                          font=ctk.CTkFont(size=12), text_color="#888888")
        self._summary_bar.grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 0))

        self._detail_log = ctk.CTkTextbox(self._detail,
                                           font=ctk.CTkFont(family="Consolas", size=12),
                                           wrap="word", state="disabled")
        self._detail_log.grid(row=1, column=0, sticky="nsew", padx=16, pady=(8, 16))
        self._detail_log.tag_config("infected", foreground="#ff5555")
        self._detail_log.tag_config("clean",    foreground="#50fa7b")
        self._detail_log.tag_config("warn",     foreground="#ffb86c")
        self._detail_log.tag_config("info",     foreground="#cdd6f4")

    def refresh(self):
        for widget in self._list_frame.winfo_children():
            widget.destroy()

        self._reports = _load_reports()
        if not self._reports:
            self._empty_lbl = ctk.CTkLabel(self._list_frame, text="No scans yet",
                                            text_color="#555555", font=ctk.CTkFont(size=13))
            self._empty_lbl.grid(row=0, column=0, pady=24)
            self._status_cb("No scan history")
            return

        for i, report in enumerate(self._reports):
            infected = report["infected"]
            color = "#ff5555" if infected else "#50fa7b"
            label = f"{report['date']}\n{report['total']} scanned  •  {infected} threats"
            btn = ctk.CTkButton(
                self._list_frame,
                text=label,
                anchor="w",
                font=ctk.CTkFont(size=11),
                fg_color="#1e1e2e" if i % 2 == 0 else "#232340",
                hover_color="#2a2a4a",
                text_color=color,
                corner_radius=4,
                command=lambda r=report: self._select(r),
            )
            btn.grid(row=i, column=0, sticky="ew", padx=4, pady=2)

        self._status_cb(f"{len(self._reports)} scan(s) in history")

    def _select(self, report: dict):
        self._selected = report
        self._detail_title.configure(text=report["date"])
        self._summary_bar.configure(
            text=f"Total: {report['total']}   Infected: {report['infected']}   Clean: {report['clean']}   Time: {report['elapsed']}"
        )
        self._open_btn.configure(state="normal")
        self._populate_detail(report)

    def _populate_detail(self, report: dict):
        self._detail_log.configure(state="normal")
        self._detail_log.delete("1.0", "end")

        raw = report.get("raw", {})
        files = raw.get("files", raw.get("results", []))
        if files:
            for entry in files:
                path = entry.get("path", entry.get("file", ""))
                status = entry.get("status", entry.get("result", ""))
                name = entry.get("name", entry.get("virus_name", ""))
                line = f"{path}"
                if status:
                    line += f"  [{status}]"
                if name:
                    line += f"  — {name}"
                tag = "infected" if "infected" in str(status).lower() else \
                      "warn" if "suspect" in str(status).lower() else \
                      "clean" if "ok" in str(status).lower() else "info"
                self._detail_log.insert("end", line + "\n", tag)
        else:
            self._detail_log.insert("end", json.dumps(raw, indent=2) + "\n", "info")

        self._detail_log.configure(state="disabled")

    def _open_json(self):
        if self._selected:
            os.startfile(str(self._selected["path"]))
