@D:/Claude Co worker/Token Save Manager Source/templates\project-baseline.md

# PolyShield — Claude Project Instructions

## Tokensave: use it first

Tokensave is active for this project. **Before reaching for `Read` or `Grep`, try a tokensave tool first.** The index is cheaper and faster than reading raw files.

### Preferred lookup order

| Task | First tool | Fallback |
|------|-----------|---------|
| Find where a symbol is defined | `tokensave_search` | `Grep` |
| Understand what a file exports | `tokensave_module_api` | `Read` |
| Get context for a task/bug | `tokensave_context` | Read the specific file |
| Explore file structure | `tokensave_files` | `Glob` |
| Find TODOs / FIXMEs | `tokensave_todos` | `Grep` |
| Find the biggest/most-connected classes | `tokensave_hotspots`, `tokensave_god_class` | — |
| Check code health before/after a change | `tokensave_health`, `tokensave_session_start` / `tokensave_session_end` | — |
| Find callers of a function | `tokensave_callers` | `Grep` |
| Find what a function calls | `tokensave_callees` | `Read` |

Only fall back to `Read` when you need the actual implementation body (to edit it or understand precise logic). Use `tokensave_context` with `include_code: true` to pull snippets without reading whole files.

### Sync reminder

> **⚠ The tokensave index was last synced against a different project.**
> Run `tokensave sync` from `D:\Random Projects\KicomAI_Project\` once to index all the Python source. After that, the tools above will work properly. The index should exclude `kicomav_env/`, `guardian_env/`, `guardianai/`, `intelligence/`, and `logs/`.

Suggested `.tokensaveignore` (create at project root if it doesn't exist):
```
kicomav_env/
guardian_env/
guardianai/
intelligence/
logs/
quarantine/
```

---

## Documentation discipline

After completing any code change, update docs **in the same response** if the change affects the public interface, architecture, or user-visible behaviour. Keep edits minimal — only touch the specific section that changed.

| What changed | Update |
|---|---|
| New symbol, file, or pattern | **CLAUDE.md** — File Map or Common Edit Locations |
| Data flow, threading, module responsibilities | **docs/ARCHITECTURE.md** |
| User-visible feature, install step, known limitation | **README.md** |
| Service IPC, startup, crash recovery | **docs/WINDOWS_SERVICE.md** |
| New test scenario or battlespace test | **docs/TESTING.md** |
| VM/sandbox setup | **docs/VM_SETUP.md** |

**Skip** doc updates for pure internal bug fixes or refactors with no API/behaviour change. When in doubt, add a one-liner to the relevant section rather than leaving it stale.

---

## Project: PolyShield Security Suite

**Stack:** Python 3.11+, CustomTkinter (dark theme), Windows-only (uses `schtasks`, `MpCmdRun.exe`, `NtSuspendProcess`).  
**Entry point:** `launch_ui.vbs` → `src/ui/app.py` → `App.mainloop()`  
**Portable venvs:** `kicomav_env/` (main UI), `guardian_env/` (standalone GuardianAI launcher)  
**k2 scanner binary:** `kicomav_env/Scripts/k2.exe`

---

## File Map

### Documentation files
| File | Contents |
|------|---------|
| `README.md` | User-facing: feature overview, install guide, usage, troubleshooting |
| `docs/ARCHITECTURE.md` | Technical: detection layers, scan pipelines, DB schema, file structure, threading patterns |
| `docs/WINDOWS_SERVICE.md` | Service implementation deep-dive, IPC protocol, pywin32 war story |
| `docs/TESTING.md` | Testing procedures, battlespace tests (EICAR sprint, Ghost Connection, Service Recovery), Sandbox workflow, VM field test checklist |
| `docs/VM_SETUP.md` | Windows 11 VM setup: Tiny11 ISO build, local account bypass, HDD optimizations, activation, snapshot strategy |
| `CLAUDE.md` | This file — AI assistant project instructions |

### Root
| File | Purpose |
|------|---------|
| `src/ui/app.py` | `App` class — sidebar nav, view wiring, watcher auto-start, `_apply_bg_image()` |
| `src/ui/theme.py` | v1.11: Mutable CTkFont instances + 5 colour palettes (classic/forest/void/midnight/stealth). `init(cfg)` called from `App.__init__()` after Tk root exists. `get(name)` returns shared font. `set_content_size/set_log_size/set_log_monospace` propagate live to all widgets. `color(name)`, `apply_preset(key, cfg)`, `set_accent(hex)`. |
| `scheduled_scan.py` | Standalone script invoked by Windows Task Scheduler |
| `launch_ui.vbs` | No-console launcher for the main UI |
| `launch_guardian.vbs` | No-console standalone GuardianAI launcher |

### scripts/  *(entry points stay at root; component scripts are in subfolders)*
| File | Purpose |
|------|---------|
| `scripts/install.bat` | Full install (venvs, packages, service) — **main user entry point** |
| `scripts/manage.bat` | Component manager — install/update/uninstall individual parts |
| `scripts/service/setup_service.bat` | Windows Service installer (self-elevating, idempotent) |
| `scripts/service/fix_service_crash.bat` | Service crash recovery (Defender exit-1067 fix) |
| `scripts/service/fix_service_crash.ps1` | PowerShell version of the crash recovery helper |
| `scripts/components/setup_guardian.bat` | Clones guardianai repo + creates guardian_env |
| `scripts/components/setup_speakeasy.bat` | Speakeasy install helper |
| `scripts/components/add_defender_exclusions.ps1` | Defender exclusion helper (targeted — not whole project) |
| `scripts/vm_setup/build_tiny11_vm.bat` | **Double-click launcher** for building a Tiny11 VM ISO |
| `scripts/vm_setup/build_tiny11_vm.ps1` | Tiny11 ISO builder with GUI folder picker |
| `scripts/dev/launch_ui.bat` | Console launcher (dev/debug — shows Python output) |
| `scripts/sandbox/sandbox-auto-setup.bat` | Sandbox fresh-install script (runs inside Windows Sandbox **only**) |

### src/ui/core/ — backend logic, no UI widgets
| File | Key exports |
|------|-------------|
| `scanner.py` | `run_scan()→ScanController`, `run_update()`, `get_infected_paths()`, `get_update_cfg_info()`, `is_available()` — wraps k2.exe (optional in v1.6.1+) |
| `scanner.py` (`ScanController`) | `.pause()`, `.resume()`, `.toggle_pause()`, `.cancel()` — uses `NtSuspendProcess` via ctypes |
| `proc_pause.py` | `suspend_pid(pid)`, `resume_pid(pid)`, `watch_pause_event(proc, event)` — shared NtSuspendProcess helper for subprocess engines (K2, ClamAV); `watch_pause_event` spawns a daemon that suspends/resumes the process when the shared `threading.Event` is cleared/set |
| `guardian_engine.py` | `is_available()`, `scan_async(paths, on_result, on_done, ..., use_patterns_override=None)`, `get_db_stats()`, `reload_signatures()`, `_EnhancedScanner`. **v1.10 — `scan_file()` returns `(bool, reason, tier, match_context)`** where `tier ∈ {safe, hash, pattern, clean, skipped}` and `match_context` is a ~160 char snippet for pattern matches. Profile-aware pattern gating via `guardian_sensitivity_profile` (conservative/balanced/power) + `guardian_pattern_toggles` dict. Per-scan circuit breaker via `reset_scan_session()`/`get_circuit_state()`. `_capture_match_context()` static helper. v1.9 guards preserved: min-size check + `ignore_list.contains(md5)` short-circuit. |
| `pattern_stats.py` | `record_detection(pattern)`, `record_ignore(pattern)`, `get_stats()`, `fp_rate(pattern)`, `reset()` — SQLite-backed per-pattern telemetry (`intelligence/pattern_stats.sqlite`). Updated by `guardian_engine.scan_file()` on every pattern match and by `ignore_list.add()` when the original reason references a pattern. |
| `ignore_list.py` | `add(hash, hash_type, filename, note, original_reason)`, `remove(hash)`, `contains(hash)`, `list_all()`, `count()`, `clear_all()` — SQLite-backed user whitelist (`intelligence/ignore_list.sqlite`). Consulted by Guardian's `scan_file()` to short-circuit known false positives. In-process set cache refreshed on add/remove. v1.10: forwards `Suspicious pattern: <label>` reasons to `pattern_stats.record_ignore()`. |
| `defender.py` | `start_scan()`, `get_status()`, `enable()`, `disable()`, `get_defender_exclusions()` — wraps MpCmdRun.exe + PowerShell |
| `win_security.py` | `get_firewall_profiles()`, `get_device_security()`, `get_local_accounts()`, `get_app_browser_control()`, `get_system_health()`, `get_security_score()`, `fetch_overview_async()`, `fetch_detail_async()` — Windows Security supplement; registry-first, PowerShell fallback |
| `shell_ext.py` | `register()`, `unregister()`, `is_registered()` — Explorer "Scan with PolyShield" context menu via HKCU registry; no admin required |
| `network_monitor.py` | `poll_connections()`, `is_known_bad_ip()`, `NetworkMonitorThread` — psutil live TCP monitor; C2/unsigned-outbound flagging; IP+PID caches |
| `watcher.py` | `start(callback)`, `stop()` — watchdog filesystem monitor |
| `scheduler.py` | `create_task()`, `delete_task()`, `get_task_info()`, `run_now()` — wraps schtasks |
| `scan_presets.py` | `resolve(preset)→(paths,desc)`, `get_running_process_paths()` — Smart/Quick/Full/Downloads/Temp. Smart scan uses targeted high-risk subdirs (browser extensions, PowerShell profiles, `%LOCALAPPDATA%\Programs`, `WindowsApps`) instead of scanning all of `%APPDATA%`/`%LOCALAPPDATA%` |
| `startup_scanner.py` | `enumerate_startup_items()`, `get_scannable_paths()` — registry + startup folder enumeration |
| `quarantine.py` | `move_to_quarantine()`, `restore()`, `list_items()`, `delete_item()` |
| `virustotal.py` | `lookup_hash()`, `lookup_file()` — VirusTotal API v3 |
| `dispute.py` | `find_disputes(k2_infected, guardian_infected)→list[dict]` |
| `settings.py` | `get(key)`, `set(key, val)` — JSON-backed flat config. v1.9: `guardian_min_scan_bytes` (default 10). v1.10 keys: `guardian_sensitivity_profile` ("conservative"/"balanced"/"power"), `guardian_pattern_toggles` (dict per-pattern overrides), `guardian_suspicious_display` ("hidden"/"collapsible"/"inline"), `guardian_circuit_breaker_threshold` (default 200, 0=off), `guardian_autoignore_prompt_dismissed`, `watcher_guardian_patterns` (default False — real-time skips patterns). v1.11 display keys: `display_theme_preset`, `display_accent_color`, `display_bg_image`, `display_bg_opacity`, `display_bg_blur`, `display_font_content_size` (default 13), `display_font_log_size` (default 12), `display_log_monospace` (default True), `display_widget_scale` (default 1.0, restart-only). |

### src/ui/views/ — CTkFrame subclasses, one per sidebar item
| File | Class | Notable internals |
|------|-------|-------------------|
| `app.py` | `App` | `_navigate()`, `_HAS_ON_SHOW`, `_AUTO_REFRESH`. Parses `--scan <path>` from argv → pre-loads Scan view |
| `scan_view.py` | `ScanView` | Scan pipeline + engine orchestration. Inherits `_ThreatActionsMixin` (see `threat_actions_mixin.py`) for the whole master-detail/bulk/ignore subsystem. Five peer engines in `_engine_queue` (K2, Defender, Guardian, YARA, ClamAV). `_scan_ctrl:ScanController` (K2 only). `_pipeline_pause_event:threading.Event` shared across all engines. Owns the per-engine `_run_*_scan` methods, the pipeline UI (`_build_pipeline_panel`, drag-and-drop reordering, user-preset menu), preset/path entry handling, pause/cancel logic, and post-scan helpers (`_send_to_virustotal`, `_open_behavioral`, `_should_vt_check`, `_maybe_vt_verify`, `_log_append/clear`). `_check_disputes()` populates `self._disputes` for inline display in the mixin. Instance attributes consumed by the mixin (must be initialised here): engine result maps `_k2_infected_paths`/`_g_infected`/`_g_tier`/`_g_context`/`_yara_infected`/`_clamav_infected`/`_defender_infected`/`_speakeasy_infected`/`_threat_severity`/`_disputes`; panel state `_threat_*` family + `_row_registry` + `_hash_cache` + `_circuit_state`/`_circuit_banner_dismissed` + `_heuristic_collapsed` + `_scan_session_ignored` + `_bulk_*`. |
| `threat_actions_mixin.py` | `_ThreatActionsMixin` | Master-detail Threat Actions panel + bulk actions + hash computation + dispute resolution + auto-ignore prompt. Extracted from `scan_view.py` (was ~1400 lines bundled into `ScanView`). Combined into `ScanView` via multiple inheritance — every method accesses state owned by `ScanView.__init__`, so no plumbing is needed. Methods: `_check_disputes`, `_get_all_infected_paths`, `_get_engine_verdicts`, `_is_disputed`/`_dispute_for_path`, `_reason_bucket`, `_severity_for`, `_get_filtered_paths`, `_build_threat_actions`, `_build_threat_header`/`_pagination`, `_render_threat_master`/`_detail`, `_render_circuit_banner`, `_build_master_row`, `_build_heuristic_header`, `_build_dispute_mode_panel`, `_render_bulk_footer`, the row/keyboard/filter/chip handlers (`_on_*`), `_action_quarantine`/`_ignore`, `_open_in_explorer`, `_open_ignore_dialog`/`_do_ignore`/`_on_ignore_done`, `_maybe_show_autoignore_prompt`/`_show_autoignore_prompt`, `_mark_resolved`/`_resolve_dispute`, `_bulk_action` + `_show_bulk_progress`/`_update_bulk_progress`/`_cancel_bulk`/`_on_bulk_done`, `_compute_hashes_async`/`_on_hashes_done`, `_quarantine_all_threats`/`_on_quarantine_all_done`. Owns the module-level `_human_size()` helper. |
| `guardian_view.py` | `GuardianView` | `on_show()` refreshes DB stats. `_EnhancedScanner` scan pipeline. Update shortcut buttons. |
| `update_view.py` | `UpdateView` | 5-section update center: K2 Engine Signatures / Guardian AI / Local Intel DB / Speakeasy / Sandboxie. `on_show()`. |
| `dashboard_view.py` | `DashboardView` | `on_show()` live stats. Security Posture card (composite 0–100 score). `navigate_callback` for quick-action buttons. Getting Started card: `_gs_frame` (row=1, grid_remove by default), `_refresh_getting_started()` called from `on_show()`, `_build_getting_started(has_db, has_svc, has_scan)`, `_dismiss_getting_started()` sets `getting_started_dismissed` in settings. Auto-dismissed when all 3 conditions met. Module-level helpers: `_svc_installed()` (winreg), `_has_intel()` (DB size > 8KB), `_has_scan_history()` (glob). |
| `defender_view.py` | `DefenderView` | Wraps `ui.core.defender`. Start/stop real-time protection. |
| `winsec_view.py` | `WinSecView` | `on_show()`. Collapsible sections per Windows Security category. Composite score card. Lazy-loads detail via `fetch_detail_async()`. "Open →" deep-link buttons. |
| `network_view.py` | `NetworkView` | `on_show()`. Live Connections table (Process/Remote/Status/Block). Recent Alerts textbox. Falls back to direct `poll_connections()` if service not running. |
| `service_view.py` | `ServiceView` | `on_show()`. Live service status/events. Install/start/stop/uninstall buttons. Event stream via `subscribe_events`. Crash banner: `_crash_banner` (hidden by default), `_check_crash_code_async()` shows it when `sc queryex` reports WIN32_EXIT_CODE 1067. `_fix_crash()` runs `scripts/service/fix_service_crash.bat` elevated. |
| `watcher_view.py` | `WatcherView` | `on_show()`. Folder watchlist. `_on_new_file_detected` callback. |
| `virustotal_view.py` | `VirusTotalView` | `on_show()`. Hash/file lookup, drag-and-drop. |
| `scheduler_view.py` | `SchedulerView` | `refresh()` (in `_AUTO_REFRESH`). Create/delete/run-now Windows Task Scheduler jobs. |
| `quarantine_view.py` | `QuarantineView` | `refresh()`. Multi-select checkboxes. Bulk Restore/Delete Selected. Per-row Restore/Delete/VT. |
| `history_view.py` | `HistoryView` | `refresh()`. Reads JSON scan reports from `logs/`. |
| `settings_view.py` | `SettingsView` | All user preferences. Guardian AI, VT, Behavioral Analysis, Launch (context menu + admin) sections. VT section: `_vt_test_btn` + `_test_vt_key()` + `_on_vt_test_done()`. Guardian section (v1.9): `guardian_min_scan_bytes` entry + "Ignored Hashes" management via `_open_ignored_manager()` modal. **v1.10 reusable helpers:** `_collapsible_section(parent, title, badge)` and `_modal_settings_dialog(title, build_fn, width, height)`. **v1.10 Guardian additions:** `_build_guardian_sensitivity_section(parent, start_row)` (profile dropdown + Advanced button) + `_open_guardian_advanced()` → `_build_guardian_advanced_body()` modal containing per-pattern toggles with FP-rate statistics, suspicious display mode radio buttons, circuit-breaker threshold, watcher pattern toggle, auto-ignore prompt toggle; `_show_power_profile_warning()` warning popup. Class constants `_PROFILE_DESCRIPTIONS`, `_PATTERN_LABELS`. |
| `dispute_popup.py` | DEPRECATED v1.9 — stub module only. Dispute resolution is now inline in `scan_view.py`'s Threat Actions detail pane (Dispute Mode block via `_build_dispute_mode_panel()`). |
| `behavioral_view.py` | `BehavioralView` | Sidebar label: "Sandbox/Emulate". `on_show()`. `load_file(path)`. Speakeasy emulation + Sandboxie detonation. |
| `display_view.py` | `DisplayView` | v1.11: `on_show()`. 5-section appearance settings: Theme Presets (swatch grid), Accent Color (8 chips + custom hex CTkToplevel), Background Image (browse/clear/opacity-slider/blur-slider/live-preview thumbnail debounced 200ms/tip text), Font Sizes (segmented buttons for content 11/13/15/17 and log 11/12/14 + monospace CTkSwitch), Widget Scale (4 preset buttons + amber restart note). All changes apply live via `theme.py` + `App._apply_bg_image()`. |

### src/tools/
| File | Key exports |
|------|-------------|
| `update_intelligence.py` | `run_update(mode)`, `fetch_malwarebazaar(mode)`, `import_nsrl()`, `clear_malicious_db()`, `get_stats()`, `lookup_hash()`, `is_known_safe()` |

### Runtime directories (not source)
| Path | Contents |
|------|---------|
| `intelligence/threat_db.sqlite` | SQLite: `malicious` table (MalwareBazaar MD5s), `safe` table (NSRL), `meta` table |
| `intelligence/ignore_list.sqlite` | v1.9: SQLite `ignored_hashes` table — user-flagged false-positive whitelist consulted by Guardian's `scan_file()` short-circuit. Created on first ignore action. |
| `intelligence/pattern_stats.sqlite` | v1.10: SQLite `pattern_stats` table (per-pattern detection + ignore counts). Drives the FP-rate display in Settings → Advanced Guardian Settings. Created on first pattern detection. |
| `guardianai/data/known_bad.txt` | Flat MD5 list synced from SQLite — loaded into RAM at scan start |
| `logs/` | Timestamped JSON scan reports from k2.exe |
| `quarantine/` | Infected files moved here (original path stored in metadata) |

---

## Key Patterns & Conventions

### Navigation / view lifecycle
```python
# app.py wires these sets:
_HAS_ON_SHOW  = {"dashboard", "watcher", "virustotal", "guardian", "behavioral", "update", "winsec"}
_AUTO_REFRESH = {"quarantine", "history", "scheduler"}
```
- Views in `_HAS_ON_SHOW` must implement `on_show(self)` — called every time the user clicks the nav item.
- Views in `_AUTO_REFRESH` must implement `refresh(self)`.
- To add a new view: add entry to `_NAV_ITEMS`, add to `_views` dict in `_build()`, add to the right set.

### Status bar
All views receive `status_callback: Callable[[str], None]`. Call it from any thread — it uses `self.after(0, ...)` internally:
```python
self._status_cb("Scan complete — 3 threats found")
```

### Subprocess: NEVER show console windows
Every `subprocess.Popen` / `subprocess.run` call **must** include:
```python
creationflags=subprocess.CREATE_NO_WINDOW  # = 0x08000000
```
Forgetting this causes visible console flashes on Windows. Enforced in: `scanner.py`, `defender.py`, `win_security.py`, `scan_presets.py`, `scheduler.py`, `scheduled_scan.py`, `update_view.py`, `winsec_view.py`.

### Threading pattern for background work
```python
def _start_something(self):
    self._busy = True
    self._btn.configure(state="disabled")

    def _run():
        result = do_work()
        if self.winfo_exists():
            self.after(0, self._on_done, result)   # always marshal back to main thread

    threading.Thread(target=_run, daemon=True).start()

def _on_done(self, result):
    self._busy = False
    self._btn.configure(state="normal")
```
Always guard with `self.winfo_exists()` before `self.after()` calls in threads.

### CRITICAL: `self.after()` with `widget.configure`

**Never** pass a dict as a positional arg to `configure` via `self.after`:
```python
# BROKEN — CustomTkinter configure() only accepts **kwargs, not a positional dict
self.after(0, self._lbl.configure, {"text": value})

# CORRECT — use a lambda closure
self.after(0, lambda v=value: self._lbl.configure(text=v))
```
The broken pattern silently does nothing; the label stays at its initial "checking…" text forever. This bug has been fixed in `update_view.py`, `quarantine_view.py`, and `app.py`.

### Settings access
```python
from ui.core import settings as cfg
val = cfg.get("some_key")     # returns default if missing
cfg.set("some_key", value)    # persists immediately to JSON
```
Defaults are defined at the top of `src/ui/core/settings.py`. Add new keys there.

### `_EnhancedScanner` scan pipeline (guardian_engine.py)
Four-tier lookup per file, in order:
1. **NSRL allow-list** — `is_known_safe(md5)` → skip immediately if known-safe
2. **RAM set** — `known_bad.txt` loaded at init → instant known-bad hit
3. **SQLite metadata** — `lookup_hash(md5)` → enriched result with family name + detection count
4. **Heuristic regex patterns** — 7 patterns: AutoRun, WScript dropper, encoded PowerShell, MSHTA, Mimikatz strings, ransomware note, Bitcoin ransom address

### Dispute detection (scan_view.py)
After any scan where both K2 and Guardian AI ran, `_check_disputes()` compares:
- `self._k2_infected_paths: list[str]` — populated from k2 JSON report
- `self._g_infected: dict[str, str]` — `{path: reason}` accumulated during Guardian scan

`find_disputes()` returns files where exactly one engine flagged it. `DisputePopup` shows them one at a time.

`_check_disputes()` is called from `_finalize_scan(aborted=False)` — not from Guardian's `on_done` — so the comparison is valid regardless of whether K2 ran before or after Guardian in the queue.

### Unified Pause/Resume (v1.6.1)
All engines share `_pipeline_pause_event: threading.Event` (SET = running, CLEAR = paused):
- **Guardian AI / YARA** — `pause_event.wait()` per file; blocks while cleared
- **K2 / ClamAV** (subprocess) — `proc_pause.watch_pause_event(proc, event)` spawns a daemon that calls `NtSuspendProcess`/`NtResumeProcess` when the event flips
- **Defender** — not paused (each MpCmdRun.exe call is too short-lived); cancel_event still halts the between-dir loop
- **Stop** sets `_pipeline_pause_event` before cancelling — required because `TerminateProcess` is ignored on Windows for suspended processes

### ScanController pause/cancel (scanner.py)
K2-specific pause API retained for backward compat; `_toggle_pause` in scan_view drives both `_scan_ctrl` and `_pipeline_pause_event` simultaneously.  
Uses `ctypes.windll.ntdll.NtSuspendProcess` / `NtResumeProcess` — standard Unix SIGSTOP is not available on Windows.  
**Important:** `cancel()` always calls `resume()` first if paused, then `proc.kill()`. Killing a suspended process on Windows is unreliable without resuming first.

---

## Common Edit Locations

| If you need to… | Edit |
|----------------|------|
| Add a new sidebar view | `src/ui/app.py` (`_NAV_ITEMS`, `_views`, `_HAS_ON_SHOW`/`_AUTO_REFRESH`) + new `src/ui/views/<name>_view.py` |
| Add a user setting | `src/ui/core/settings.py` (defaults dict) + `src/ui/views/settings_view.py` (UI row) |
| Change scan behavior | `src/ui/core/scanner.py` + `src/ui/views/scan_view.py` |
| Change pause/resume for subprocess engines | `src/ui/core/proc_pause.py` — `watch_pause_event()` daemon, `suspend_pid()`, `resume_pid()` |
| Change Smart scan targets | `src/ui/core/scan_presets.py` — `_smart()` targeted-dirs list (browser extensions, PowerShell profiles, WindowsApps, etc.) |
| Add/change user scan path presets | `src/ui/views/scan_view.py` — `_save_as_user_preset`, `_delete_user_preset`, `_refresh_preset_menu`; stored in `scan_path_presets` setting |
| Change pipeline D&D behavior | `src/ui/views/scan_view.py` — `_on_drag_start/motion/end`, `_get_engine_at_y`, `_drag_row_registry` |
| Change first-launch onboarding | `src/ui/views/dashboard_view.py` — `_build_getting_started()` for card content; `_svc_installed()` / `_has_intel()` / `_has_scan_history()` for completion logic; `getting_started_dismissed` setting |
| Change Guardian AI detection | `src/ui/core/guardian_engine.py` (`_HEURISTIC_PATTERNS`, `_EnhancedScanner.scan_file`) |
| Change Guardian false-positive guards | `src/ui/core/guardian_engine.py` top of `scan_file()` — `_DEFAULT_MIN_SCAN_BYTES`, `ignore_list.contains()` short-circuit; setting `guardian_min_scan_bytes` |
| Change Guardian sensitivity / patterns | Profile defaults: `guardian_engine._CONSERVATIVE_DISABLED` set + `_pattern_enabled()` resolver. Toggle UI: `settings_view._build_guardian_advanced_body()`. Setting keys in `settings.py`: `guardian_sensitivity_profile`, `guardian_pattern_toggles`. |
| Change Guardian circuit-breaker | `guardian_engine._EnhancedScanner.reset_scan_session()`/`get_circuit_state()`, hit counter in `scan_file()` tier 4; UI banner `scan_view._render_circuit_banner()`; setting `guardian_circuit_breaker_threshold` |
| Change pattern detection telemetry | `src/ui/core/pattern_stats.py` — `record_detection/record_ignore/get_stats/fp_rate/reset`; SQLite at `intelligence/pattern_stats.sqlite` |
| Change suspicious tier display | `scan_view._get_filtered_paths()` (mode-aware sorting) + `_build_master_row()` (visual styling per severity) + `_build_heuristic_header()` for collapsible mode; setting `guardian_suspicious_display` |
| Change ignore list behavior | `src/ui/core/ignore_list.py` — `add/remove/contains/list_all/clear_all/count`; SQLite at `intelligence/ignore_list.sqlite`. v1.10: forwards pattern-derived reasons to `pattern_stats.record_ignore()` |
| Add a reusable collapsible settings section | `settings_view._collapsible_section(parent, title, badge)` — returns a body frame that toggles visibility on chevron click |
| Add a settings modal popup | `settings_view._modal_settings_dialog(title, build_fn, width, height)` — opens a sized CTkToplevel scrollable container with a Close button |
| Change theme / colour palette | `src/ui/theme.py` — `_PRESET_PALETTES` dict for built-in presets; `apply_preset(key, cfg)` to switch; `set_accent(hex)` for override; `color(name)` for look-up |
| Change font sizes live | `src/ui/theme.py` — `set_content_size(size)`, `set_log_size(size)`, `set_log_monospace(mono)`; also called from `display_view._on_content_size/log_size/mono_toggle` |
| Change Display settings UI | `src/ui/views/display_view.py` — 5-section `CTkScrollableFrame`; `_apply_bg_image()` on `App` instance for bg changes |
| Change background image compositing | `src/ui/app.py` — `_apply_bg_image()` (PIL load → GaussianBlur → `Image.blend` with app_bg colour → CTkImage → `_show_bg()`) |
| Change Threat Actions master-detail | `src/ui/views/threat_actions_mixin.py` — `_build_threat_actions()` + the rendering helpers (`_render_threat_master`, `_render_threat_detail`, `_build_master_row`, `_build_dispute_mode_panel`, `_render_bulk_footer`); filter state and selection state still live on the `ScanView` instance |
| Change bulk-action progress UX | `src/ui/views/threat_actions_mixin.py` — `_bulk_action`, `_show_bulk_progress`, `_update_bulk_progress`, `_cancel_bulk`, `_on_bulk_done` |
| Change inline Dispute Mode UI | `src/ui/views/threat_actions_mixin.py` — `_build_dispute_mode_panel`, `_resolve_dispute`, `_is_disputed`, `_dispute_for_path` |
| Change intelligence DB schema | `src/tools/update_intelligence.py` (`_SCHEMA`, migration needed if DB exists) |
| Add a new update source | `src/ui/views/update_view.py` (new section card + `_run_*` method) + `src/tools/update_intelligence.py` |
| Fix console window flashing | Add `creationflags=subprocess.CREATE_NO_WINDOW` to the offending `subprocess` call |
| Change Windows Security data | `src/ui/core/win_security.py` — registry reads or PowerShell queries per section |
| Change Windows Security UI | `src/ui/views/winsec_view.py` — `_make_section()`, `_toggle_section()`, `_apply_overview()` |
| Change Explorer context menu | `src/ui/core/shell_ext.py` — `_MENU_LABEL`, `_get_command()`, registry key paths |
| Change network monitor logic | `src/ui/core/network_monitor.py` — `poll_connections()`, `is_known_bad_ip()`, `_is_unsigned()`, caches |
| Change network monitor UI | `src/ui/views/network_view.py` — `_apply_connections()`, `_apply_alerts()`, `_block_ip()` |
| Change C2 blocklist import | `src/tools/update_intelligence.py` — `import_c2_blocklist()`, `_parse_feodo()`, `_parse_threatfox()` |

---

## Sandbox Testing

The sandbox setup lives **outside the main project** to keep the project root clean:

| Path | Contents |
|------|----------|
| `D:\Random Projects\Python Installer\python_embed\` | Portable Python 3.12 with pip + virtualenv |
| `D:\Random Projects\Python Installer\pip_cache\` | Persistent pip cache (survives sandbox restarts) |

**Workflow:** `PolyShield_Sandbox.wsb` (double-click) → right-click `scripts\sandbox\sandbox-auto-setup.bat` → Run as administrator.

The script copies source files fresh to `C:\PolyShield_Sandbox` each run (skipping venvs, `.env`, generated dirs), builds a clean venv there, and launches the UI. Host files are never modified (project is mapped read-only).

**Speed:** First run ~5 min (package download). Subsequent runs ~2 min (pip cache hit).

**Do NOT:**
- Run `scripts\sandbox\sandbox-auto-setup.bat` on the host — it targets sandbox paths (`C:\PolyShield_Sandbox`, `C:\python_embed`)
- Map the project as `ReadOnly=false` — source files must stay read-only to protect the host

---

## Health Snapshot (last recorded — pre v1.2)

```
Quality signal : 8725 / 10000
Acyclicity     : 1.000  (no circular imports)
Modularity     : 0.917  (good separation)
Redundancy     : 1.000  (no duplicate symbols)
Depth          : 1.000  (shallow hierarchy)
Equality       : 0.552  (some files carry more weight than others — expected for views)
```

Largest classes by method count (god-class risk): `ScanView`, `GuardianView`, `UpdateView`, `WinSecView`.  
Most-connected symbols: `run_scan`, `status_callback`, `on_show`, `_navigate`.

**New files since last snapshot** (re-run `tokensave sync` to refresh):
- `src/ui/core/win_security.py` — Windows Security supplement backend
- `src/ui/core/shell_ext.py` — Explorer context menu (HKCU)
- `src/ui/views/winsec_view.py` — Windows Security view
- `src/ui/core/network_monitor.py` — psutil-based network connection monitor, C2/unsigned-outbound detection
- `src/ui/views/network_view.py` — Network sidebar view (live connections table, alert feed, block button)
