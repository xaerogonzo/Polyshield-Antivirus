from tkinter import filedialog
import customtkinter as ctk
from pathlib import Path

from ui.core import virustotal as vt
from ui.core import settings as cfg

try:
    from tkinterdnd2 import DND_FILES
    _DND_AVAILABLE = True
except ImportError:
    _DND_AVAILABLE = False


class VirusTotalView(ctk.CTkFrame):
    def __init__(self, master, status_callback, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self._status_cb = status_callback
        self._current_hashes: dict = {}
        self._build()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(4, weight=1)

        ctk.CTkLabel(self, text="VirusTotal Lookup",
                     font=ctk.CTkFont(size=22, weight="bold")).grid(
            row=0, column=0, sticky="w", padx=24, pady=(20, 8))

        # ── API key status banner ──
        self._key_banner = ctk.CTkFrame(self, corner_radius=8, fg_color="#12121e")
        self._key_banner.grid(row=1, column=0, sticky="ew", padx=24, pady=(0, 8))
        self._key_banner.grid_columnconfigure(0, weight=1)
        self._key_lbl = ctk.CTkLabel(
            self._key_banner, text="", font=ctk.CTkFont(size=12), anchor="w")
        self._key_lbl.grid(row=0, column=0, sticky="w", padx=14, pady=8)
        self._update_key_banner()

        # ── File input card ──
        input_card = ctk.CTkFrame(self, corner_radius=10, fg_color="#1a1a2e")
        input_card.grid(row=2, column=0, sticky="ew", padx=24, pady=(0, 8))
        input_card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(input_card, text="File to Check",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#5294e2").grid(
            row=0, column=0, columnspan=3, sticky="w", padx=16, pady=(12, 6))

        # Drop zone
        self._drop_frame = ctk.CTkFrame(
            input_card, height=72, corner_radius=8,
            border_width=2, border_color="#3a3a3a")
        self._drop_frame.grid(row=1, column=0, columnspan=3,
                               sticky="ew", padx=16, pady=(0, 8))
        self._drop_frame.grid_propagate(False)
        self._drop_frame.grid_columnconfigure(0, weight=1)
        self._drop_frame.grid_rowconfigure(0, weight=1)
        self._drop_lbl = ctk.CTkLabel(
            self._drop_frame, text="Drop a file here or use Browse",
            text_color="#888888", font=ctk.CTkFont(size=13))
        self._drop_lbl.grid(row=0, column=0)

        if _DND_AVAILABLE:
            self._drop_frame.drop_target_register(DND_FILES)
            self._drop_frame.dnd_bind("<<Drop>>", self._on_drop)

        # Browse + lookup row
        btn_row = ctk.CTkFrame(input_card, fg_color="transparent")
        btn_row.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 12))
        btn_row.grid_columnconfigure(1, weight=1)

        ctk.CTkButton(btn_row, text="Browse File", width=120,
                      command=self._browse).grid(row=0, column=0, padx=(0, 8))

        self._lookup_btn = ctk.CTkButton(
            btn_row, text="Check on VirusTotal", width=180,
            fg_color="#1f6aa5", hover_color="#144e7a",
            state="disabled", command=self._lookup)
        self._lookup_btn.grid(row=0, column=2)

        # Hash display
        hash_frame = ctk.CTkFrame(input_card, fg_color="#12121e", corner_radius=6)
        hash_frame.grid(row=3, column=0, columnspan=3,
                         sticky="ew", padx=16, pady=(0, 12))
        hash_frame.grid_columnconfigure(1, weight=1)

        self._hash_labels: dict[str, ctk.CTkLabel] = {}
        for i, algo in enumerate(["sha256", "sha1", "md5"]):
            ctk.CTkLabel(hash_frame, text=f"{algo.upper()}:",
                         font=ctk.CTkFont(size=11, weight="bold"),
                         text_color="#5294e2", width=60, anchor="w").grid(
                row=i, column=0, padx=(10, 4), pady=3, sticky="w")
            lbl = ctk.CTkLabel(hash_frame, text="—",
                                font=ctk.CTkFont(family="Consolas", size=11),
                                text_color="#cdd6f4", anchor="w")
            lbl.grid(row=i, column=1, sticky="w", padx=(0, 10), pady=3)
            self._hash_labels[algo] = lbl

        # ── Results ──
        ctk.CTkLabel(self, text="Results",
                     font=ctk.CTkFont(size=14, weight="bold")).grid(
            row=3, column=0, sticky="w", padx=24, pady=(4, 4))

        self._results_frame = ctk.CTkScrollableFrame(
            self, corner_radius=8, fg_color="#1a1a2e")
        self._results_frame.grid(row=4, column=0, sticky="nsew", padx=24, pady=(0, 16))
        self._results_frame.grid_columnconfigure(0, weight=1)

        self._result_placeholder = ctk.CTkLabel(
            self._results_frame, text="No results yet",
            text_color="#555577", font=ctk.CTkFont(size=13))
        self._result_placeholder.grid(row=0, column=0, pady=24)

    def _update_key_banner(self):
        key = cfg.get("vt_api_key") or ""
        if key:
            self._key_lbl.configure(
                text="✓  API key configured — ready to query VirusTotal.",
                text_color="#50fa7b")
        else:
            self._key_lbl.configure(
                text="⚠  No VirusTotal API key set. Add your free API key in Settings → VirusTotal.",
                text_color="#ffb86c")

    def _on_drop(self, event):
        raw = event.data.strip()
        if raw.startswith("{"):
            path = raw[1:raw.index("}")]
        else:
            path = raw.split()[0]
        self._load_file(path)

    def _browse(self):
        path = filedialog.askopenfilename(title="Select file to check")
        if path:
            self._load_file(path)

    def _load_file(self, path: str):
        self._drop_lbl.configure(text="Hashing…", text_color="#ffb86c")
        self._lookup_btn.configure(state="disabled")
        for lbl in self._hash_labels.values():
            lbl.configure(text="—")

        import threading
        def _hash():
            hashes = vt.hash_file(path)
            self.after(0, self._apply_hashes, path, hashes)
        threading.Thread(target=_hash, daemon=True).start()

    def _apply_hashes(self, path: str, hashes: dict):
        if "error" in hashes:
            self._drop_lbl.configure(text=f"Error: {hashes['error']}",
                                      text_color="#ff5555")
            return
        self._current_hashes = hashes
        self._drop_lbl.configure(text=Path(path).name, text_color="#cdd6f4")
        for algo, lbl in self._hash_labels.items():
            lbl.configure(text=hashes.get(algo, "—"))
        has_key = bool(cfg.get("vt_api_key"))
        self._lookup_btn.configure(state="normal" if has_key else "disabled")
        self._status_cb(f"Hashed: {Path(path).name}")

    def _lookup(self):
        sha256 = self._current_hashes.get("sha256", "")
        api_key = cfg.get("vt_api_key") or ""
        if not sha256:
            return
        self._lookup_btn.configure(state="disabled", text="Querying…")
        self._status_cb("Querying VirusTotal…")
        self._clear_results()
        ctk.CTkLabel(self._results_frame, text="Querying VirusTotal…",
                     text_color="#ffb86c", font=ctk.CTkFont(size=13)).grid(
            row=0, column=0, pady=20)

        vt.lookup_hash_async(sha256, api_key, self._on_result)

    def _on_result(self, raw: dict):
        self.after(0, self._apply_result, raw)

    def _apply_result(self, raw: dict):
        self._lookup_btn.configure(state="normal", text="Check on VirusTotal")
        self._clear_results()

        result = vt.parse_result(raw)
        if "error" in result:
            ctk.CTkLabel(self._results_frame, text=result["error"],
                         text_color="#ff5555", font=ctk.CTkFont(size=13),
                         wraplength=600).grid(row=0, column=0, pady=20)
            self._status_cb("VirusTotal lookup failed")
            return

        mal = result["malicious"]
        sus = result["suspicious"]
        total = result["total"]
        color = "#ff5555" if mal > 0 else "#ffb86c" if sus > 0 else "#50fa7b"
        verdict = "MALICIOUS" if mal > 0 else "SUSPICIOUS" if sus > 0 else "CLEAN"

        # Summary banner
        banner = ctk.CTkFrame(self._results_frame, corner_radius=8, fg_color="#12121e")
        banner.grid(row=0, column=0, sticky="ew", padx=0, pady=(0, 8))
        banner.grid_columnconfigure((0, 1, 2, 3), weight=1)

        for col, (label, value, c) in enumerate([
            ("Verdict", verdict, color),
            ("Malicious", str(mal), "#ff5555" if mal else "#cdd6f4"),
            ("Suspicious", str(sus), "#ffb86c" if sus else "#cdd6f4"),
            ("Engines", f"{total}", "#cdd6f4"),
        ]):
            ctk.CTkLabel(banner, text=label,
                         font=ctk.CTkFont(size=11), text_color="#888888").grid(
                row=0, column=col, padx=12, pady=(10, 2))
            ctk.CTkLabel(banner, text=value,
                         font=ctk.CTkFont(size=18, weight="bold"),
                         text_color=c).grid(
                row=1, column=col, padx=12, pady=(0, 10))

        if result.get("name"):
            ctk.CTkLabel(self._results_frame,
                         text=f"File: {result['name']}  •  {result.get('type', '')}",
                         font=ctk.CTkFont(size=12), text_color="#888888",
                         anchor="w").grid(row=1, column=0, sticky="w", pady=(0, 8))

        # Detection list
        detections = result.get("detections", [])
        if detections:
            ctk.CTkLabel(self._results_frame,
                         text=f"Detections ({len(detections)})",
                         font=ctk.CTkFont(size=13, weight="bold")).grid(
                row=2, column=0, sticky="w", pady=(0, 4))
            for i, det in enumerate(detections):
                bg = "#1e1e2e" if i % 2 == 0 else "#232340"
                row_f = ctk.CTkFrame(self._results_frame, fg_color=bg)
                row_f.grid(row=3 + i, column=0, sticky="ew", pady=1)
                row_f.grid_columnconfigure(0, weight=1)
                ctk.CTkLabel(row_f, text=det["engine"], anchor="w",
                             font=ctk.CTkFont(size=12),
                             text_color="#cdd6f4").grid(
                    row=0, column=0, sticky="w", padx=12, pady=4)
                ctk.CTkLabel(row_f, text=det["result"],
                             font=ctk.CTkFont(size=12),
                             text_color="#ff5555").grid(
                    row=0, column=1, padx=12)

        self._status_cb(f"VT: {mal}/{total} engines detected")

    def _clear_results(self):
        for w in self._results_frame.winfo_children():
            w.destroy()

    def on_show(self):
        self._update_key_banner()
