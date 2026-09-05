"""The per-engine scan runners: K2, Guardian, YARA, ClamAV, Defender, Speakeasy.

A partition of ScanView, not an independent component.  Each runner reports
back through ScanView (`_log_append`, `_run_next_engine`, `_finalize_scan`) and
through `_ThreatActionsMixin` (`_build_threat_actions`, `_render_circuit_banner`),
and every result map it writes -- `_k2_infected_paths`, `_g_infected`,
`_yara_infected`, and the rest -- is owned by `ScanView.__init__`.

Combine it into a class that also inherits `ctk.CTkFrame`; see ScanView.
No method here calls `super()`, and no name here exists on ScanView,
`_ThreatActionsMixin` or `_ScanPipelineMixin` -- a collision would resolve
silently by MRO order.
"""
import threading
from pathlib import Path

from ui.core import scanner as sc
from ui.core import settings as cfg
from ui.core import guardian_engine as ge
from ui.core import yara_engine as ye
from ui.core import clamav_engine as ce
from ui.core import defender as df
from ui.views._view_utils import (
    _TAG_INFECTED, _TAG_CLEAN, _TAG_WARN, _TAG_INFO, _TAG_GUARDIAN,
    _TAG_YARA, _TAG_CLAMAV, _TAG_DEFENDER, _TAG_SPEAKEASY,
)

try:
    from ui.core import emulate_engine as ee
    _SPEAKEASY_AVAIL = True
except ImportError:
    ee = None
    _SPEAKEASY_AVAIL = False


class _ScanEngineMixin:
    """One method per engine, each launched from the scan pipeline."""

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
