@project-baseline.md

# PolyShield — Claude Project Instructions

## Tokensave in this project

The shared baseline above covers which tool to reach for. What is
specific to this repo:

### Index freshness

The index is this project's own (111 Python files as of 2026-09-13), not another
project's. It does fall behind: check `tokensave_status` and run `tokensave sync`
from `D:\Random Projects\KicomAI_Project\` when it reports stale commits. The index
should exclude `kicomav_env/`, `guardian_env/`, `guardianai/`, `intelligence/`, and `logs/`.

The exclusions live in `.tokensaveignore` at the project root, which should contain at least:
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
| `CHANGELOG.md` | What changed per release; `[Unreleased]` is the candidate next version. No git tags exist yet |
| `docs/RELEASING.md` | The release checklist: pin check, version bump (two files), signing, build, sandbox verification, tag |
| `CLAUDE.md` | This file — AI assistant project instructions |

### Root
| File | Purpose |
|------|---------|
| `src/ui/core/{ps_run,settings,win_security}.py`, `src/ui/theme.py`, `tools/uishot/{desktop,capture,session}.py` | **Module aliases for PolyBedrock**, not implementations — `sys.modules[__name__] = _impl`. A re-export would break the monkeypatch contract `tests/` relies on. PolyShield does not start without PolyBedrock; see docs/ARCHITECTURE.md, "PolyBedrock is a hard dependency". |
| `src/ui/app.py` | `App` class — sidebar nav, view wiring, watcher auto-start, `_apply_bg_image()`. **v1.17:** `App(start_minimized=)` withdraws to the tray, guarded on `_tray_started` (set only after `run_detached()` returns) and **not** on `_USE_TRAY` — withdrawing with no icon leaves a process reachable only from Task Manager. New argv: `--minimized`/`--tray`, `--register [--with-startup]`, `--register-autostart`, `--register-uninstall-entry`. `_schedule_login_scan()` arms the post-login Quick Scan (once; cancelled on quit; re-checks the setting, the service and whether a scan is already running before firing). **v1.16:** views are built on first show — `_view_factories` holds zero-arg lambdas, `get_view(key)` builds and caches, `_navigate()` goes through it. |
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
| `installer/polyshield.iss` | Inno Setup script — compiled by `build.bat -Target installer`. Payload, ordered install steps, rollback on failure, uninstall with an opt-in data-removal checkbox. |
| `installer/setup_data_root.ps1` | Creates `%ProgramData%\PolyShield` with per-subtree ACLs **before** the app first runs. `-Verify` re-probes the boundary as the current user (run it unelevated). |
| `installer/register_service.ps1` | Registers the service from the staged runtime. `-PreflightOnly` validates the payload read-only — it is what caught the stale-staging bug. No `pywin32_postinstall`. |
| `scripts/vm_setup/build_tiny11_vm.bat` | **Double-click launcher** for building a Tiny11 VM ISO |
| `scripts/vm_setup/build_tiny11_vm.ps1` | Tiny11 ISO builder with GUI folder picker |
| `scripts/dev/launch_ui.bat` | Console launcher (dev/debug — shows Python output) |
| `scripts/sandbox/sandbox-auto-setup.bat` | Sandbox fresh-install script (runs inside Windows Sandbox **only**) |

### src/ui/core/ — backend logic, no UI widgets
| File | Key exports |
|------|-------------|
| `scanner.py` | **v1.16:** `K2_EXE` binds `paths.k2_exe()` at import, which now resolves `<install>\runtime\Scripts\k2.exe` in a distribution. `run_scan()→ScanController`, `run_update()`, `get_infected_paths()`, `get_update_cfg_info()`, `is_available()` — wraps k2.exe (optional in v1.6.1+) |
| `scanner.py` (`ScanController`) | `.pause()`, `.resume()`, `.toggle_pause()`, `.cancel()` — uses `NtSuspendProcess` via ctypes |
| `proc_pause.py` | `suspend_pid(pid)`, `resume_pid(pid)`, `watch_pause_event(proc, event)` — shared NtSuspendProcess helper for subprocess engines (K2, ClamAV); `watch_pause_event` spawns a daemon that suspends/resumes the process when the shared `threading.Event` is cleared/set |
| `intel_db.py` | `get_stats()`, `lookup_hash()`, `is_known_safe()`, `_get_conn()` — read-only layer over `threat_db.sqlite`; memoises one connection per thread. `update_intelligence` re-exports these for backward compat. |
| `process_monitor.py` | `ProcessMonitor` (WMI `__InstanceCreationEvent`), `reload_all_known_bad()`, `_load_known_bad()`. `_check_process()` is the verdict path: allow-list → RAM set → SQLite. Alerts fire on the WMI thread. v1.13: `stop()` keeps the thread handle if the join times out, so `is_running()` cannot report stopped while the thread is alive. |
| `yara_engine.py` | `is_available()`, `get_rule_count()`, `scan_async()`, `active_community_dir()` — reads the atomic `.active` generation pointer. **v1.14:** `scan_file()` returns `(False, "YARA error: …")` for a file it could not scan, distinct from `(False, "")` for one it scanned and found clean; `scan_async()` takes `on_error`. `is_available()` still means "runtime installed and rule files exist" — it does **not** compile them. |
| `clamav_engine.py` | `is_available()`, `get_version()`, `scan_async()` — wraps `clamscan.exe --file-list`; pauses via `proc_pause`. **v1.14:** `scan_async()` takes `on_error`, fired for a missing executable, a `Popen` that raised, an exit code outside `{0, 1}`, or a pipe that died mid-scan. Cancellation is not an error. |
| `emulate_engine.py` | `emulate_async()`, `_parse_report()` — Speakeasy PE emulation. |
| `sandbox_engine.py` | `detonate()` — Sandboxie-Plus detonation. |
| `guardian_engine.py` | `is_available()`, `scan_async(paths, on_result, on_done, ..., use_patterns_override=None)`, `get_db_stats()`, `reload_signatures()`, `_EnhancedScanner`. **v1.10 — `scan_file()` returns `(bool, reason, tier, match_context)`** where `tier ∈ {safe, hash, pattern, clean, skipped}` and `match_context` is a ~160 char snippet for pattern matches. Profile-aware pattern gating via `guardian_sensitivity_profile` (conservative/balanced/power) + `guardian_pattern_toggles` dict. Per-scan circuit breaker via `reset_scan_session()`/`get_circuit_state()`. `_capture_match_context()` static helper. v1.9 guards preserved: min-size check + `ignore_list.contains(md5)` short-circuit. |
| `intel_updater.py` | v1.12 scheduler core. `run_updates(feeds, force, owner)` is the **one** execution path (scheduled, manual, IPC all enter here); `get_staleness()` returns per-feed `never/fresh/aging/stale/error/auth_required`; `request_update()` routes to the service when it is running, else runs locally; `IntelUpdaterThread` is the background scheduler. Cross-process single-writer guard: `intelligence/.update.lock` with PID + process-start identity — never stolen on age alone. Backoff state persists in the `meta` table. All freshness math is naive UTC via `_utcnow()`. |
| `intel_hooks.py` | `register_intel_consumers()` — wires this process's in-memory intelligence consumers (Guardian singleton, every live `ProcessMonitor`, the network IP cache) to `update_intelligence`'s post-update hook registry. Called eagerly from `App.__init__` and the service's `SvcDoRun`; idempotent. |
| `pattern_stats.py` | `record_detection(pattern)`, `record_ignore(pattern)`, `get_stats()`, `fp_rate(pattern)`, `reset()` — SQLite-backed per-pattern telemetry (**v1.16:** `telemetry/pattern_stats.sqlite`, moved out of the service-owned `intelligence/`). Updated by `guardian_engine.scan_file()` on every pattern match and by `ignore_list.add()` when the original reason references a pattern. |
| `ignore_list.py` | `add(...)` / `remove(hash)` / `clear_all()` **route**, `add_local()` / `remove_local()` / `clear_all_local()` **execute**, `contains(hash)`, `list_all()`, `count()`, `ServiceRequired` — SQLite-backed user whitelist (`intelligence/ignore_list.sqlite`). Consulted by Guardian's `scan_file()` to short-circuit known false positives. In-process set cache refreshed on add/remove. v1.10: forwards `Suspicious pattern: <label>` reasons to `pattern_stats.record_ignore()`. |
| `integration.py` | **v1.17** — both directions now. Teardown: `_STEPS` is five entries (service · context menu · startup entry · scheduled task · uninstall entry, in that order) driving `unregister_all(log)`; the uninstall entry is **last** because it advertises the uninstall and must survive an earlier step's failure. Registration: `register_context_menu()` / `register_startup_entry()` / `register_arp_entry()` and `register_all(startup=False)` — **startup must be passed explicitly; there is no opting in by omission.** Service config: `service_startup_commands(delayed)` returns the `sc config` / `sc failure` argv as data (one policy, three call sites), `configure_service_startup()` runs it and treats an **absent service as failure** — the one function here that does — and `service_state()` reports start type and current state as two separate facts, from the registry and `QueryServiceStatus` rather than by parsing localised `sc` output. Idempotent (absent is success) everywhere else. Touches no user data. |
| `ps_run.py` | `run_ps(command, timeout, timeout_message)` — the shared PowerShell runner for `defender.py` and `win_security.py` (19 call sites). Popen + bounded drain-after-kill: `subprocess.run(capture_output=True)` hangs forever when a WMI child holds the stdout pipe past `proc.kill()`. Never raises; stderr is discarded by design. |
| `virustotal.py` | `hash_file()`, `lookup_hash()`, `lookup_hash_async()`, `parse_result()` — VirusTotal API v3. **v1.15:** `hash_file()` returns either three digests or `error` alone, never both; both callers branch on that before indexing. `parse_result()` also catches `AttributeError` — a null `attributes` used to escape into a Tk callback. A 404 is still reported as an error (see docs/TESTING.md § *Absence and failure*). |
| `autostart.py` | **v1.17.** `register()`, `unregister()`, `is_registered()`, `current_command()`, `is_current()`, `startup_approval()`, `status()` — the per-user login entry at `HKCU\...\CurrentVersion\Run\PolyShield`, running `app_launch_argv("--minimized")`. Modelled on `shell_ext.py`. `startup_approval()` is **tri-state** (`enabled`/`disabled`/`unknown`): Task Manager records a switched-off entry in `StartupApproved\Run` without deleting the Run value, and the byte layout is undocumented — bit **0** of byte 0, measured on a live hive, and anything unrecognised degrades to `unknown`, never to `disabled`. `status()` fixes the precedence: not-registered → user-disabled → stale path → ok. |
| `dev_install.py` | **v1.17.** `register()`, `unregister()`, `is_registered()`, `current_uninstall_string()`, `is_current()`, `uninstaller_path()` — the Add/Remove Programs entry for a **source** install, at `HKCU\...\Uninstall\PolyShield`. `UninstallString` points at `scripts\uninstall_dev.bat`, **never** at `app.py --unregister`: Windows launches an uninstall string unelevated and the first teardown step is the service. DisplayName says *(development install)* because it removes registrations, not the checkout. No-op in a distribution — Inno owns that entry. |
| `shell_ext.py` | `register()`, `unregister()`, `is_registered()` — Explorer context menu via HKCU; no admin. **v1.15:** `is_registered()` swallows every `OSError`, matching `win_security._reg_key_exists`; it is called from `SettingsView._build()`, where a raise takes the page down. The registered command is `"<pythonw>" "<app.py>" "--scan" "%1"` — single-file by design, and pinned by test_integration_edges.py before Phase 4a repoints it at a frozen exe. |
| `startup_scanner.py` | `enumerate_startup_items()`, `get_scannable_paths()`, `_extract_path()` — registry Run keys + startup folders. **v1.15:** `_extract_path()` expands environment variables, matches executable extensions case-insensitively, and cuts at a token boundary rather than the first `.exe` substring. Each of those three used to yield a path that does not exist, dropping the autorun from the scan list without a word. |
| `paths.py` | `app_root()`, `resource_root()`, `is_frozen()`, plus `intelligence_dir()` / `quarantine_dir()` / `logs_dir()` / `config_dir()` / `rules_dir()` / `guardian_dir()` / `k2_exe()` / `venv_python()` / `venv_pip()`, `state_dir()` / `telemetry_dir()` / **`install_root()`** / **`runtime_python()`** / **`k2_rules_dir()`**, and `app_launch_argv()` / `script_launch_argv()` / `bootstrap_sys_path()`. **v1.15 — the only module that decides where anything lives.** **v1.16:** a distribution resolves `%ProgramData%\PolyShield`, not `%LOCALAPPDATA%` — the service runs as LocalService and would otherwise resolve a different profile from the GUI, including for the two cross-process lock files. See docs/ARCHITECTURE.md § *The shared data root*. DATA (must survive a restart) vs RESOURCE (ships with the program, may live in a temp extraction dir). `app_root()` is **not** `sys.executable.parent` — see docs/ARCHITECTURE.md § *Path Resolution*. |
| `defender.py` | `get_status()`, `get_threat_history()`, `get_threat_names()`, `start_scan()`, `scan_paths_async()`, `start_scan_async()`, `is_mpcmdrun_available()`, `get_defender_exclusions()` — wraps MpCmdRun.exe + PowerShell. **There is no `enable()` / `disable()`**; this row claimed both until v1.17. PolyShield reads Defender's state and drives its scanner, and never turns it off. |
| `win_security.py` | `get_firewall_profiles()`, `get_device_security()`, `get_local_accounts()`, `get_app_browser_control()`, `get_system_health()`, `get_security_score()`, `fetch_overview_async()`, `fetch_detail_async()` — Windows Security supplement; registry-first, PowerShell fallback. **v1.14:** `_run_ps` is now a thin wrapper over `ui.core.ps_run`. `get_security_score()` weights are Defender 25 / Firewall 20 / Device 20 / Account 15 / App+Browser 15 / Health 5, each floored at 0; it is pure **except** that the Account branch calls `get_account_policy()` live, and `defender_status=None` means *unavailable* (-25), not *fetch live* like the other five parameters. |
| `network_monitor.py` | `poll_connections()`, `is_known_bad_ip()`, `clear_ip_cache()`, `NetworkMonitorThread` — psutil live TCP monitor; C2/unsigned-outbound flagging. v1.13: `_is_private()` uses `ipaddress` against an explicit `_SKIP_NETWORKS` list (CGNAT stays monitored on purpose); the PID cache is keyed on `create_time` so a recycled PID cannot inherit the dead process's identity. |
| `watcher.py` | `start(callback)`, `stop()`, `scan_new_file(path, entry, notify_cb, on_complete)` — watchdog filesystem monitor. v1.13: every launched engine's verdict is accumulated into `entry["verdicts"]` and a `_CompletionBarrier` fires observers **once**, after all of them report. Detection callbacks mean *scan complete* and run on a worker thread. `_derive_status()` reduces verdicts to the legacy status string. |
| `scheduler.py` | `create_task()`, `delete_task()`, `get_task_info()`, `run_now()` — wraps schtasks |
| `scan_presets.py` | `resolve(preset)→(paths,desc)`, `get_running_process_paths()` — Smart/Quick/Full/Downloads/Temp. Smart scan uses targeted high-risk subdirs (browser extensions, PowerShell profiles, `%LOCALAPPDATA%\Programs`, `WindowsApps`) instead of scanning all of `%APPDATA%`/`%LOCALAPPDATA%` |
| `quarantine.py` | `add_file()`, `move_to_quarantine()` (view-facing wrapper → `(ok, msg)`), `restore()`, `list_quarantined()`, `delete()`. `restore()` refuses rather than overwrites when the original path is occupied; `add_file()` records an absolute origin. |
| `dispute.py` | `find_disputes(k2_infected, guardian_infected)→list[dict]` |
| `settings.py` | `get(key)`, `set_value(key, val)`, `load()` — JSON-backed flat config. v1.13: cross-process-safe persistence (OS-owned sidecar lock, re-read/merge/atomic-replace, `SAVE_OK`/`SAVE_DEGRADED`/`SAVE_FAILED` return, corrupt files preserved as `.corrupt`). v1.9: `guardian_min_scan_bytes` (default 10). v1.10 keys: `guardian_sensitivity_profile` ("conservative"/"balanced"/"power"), `guardian_pattern_toggles` (dict per-pattern overrides), `guardian_suspicious_display` ("hidden"/"collapsible"/"inline"), `guardian_circuit_breaker_threshold` (default 200, 0=off), `guardian_autoignore_prompt_dismissed`, `watcher_guardian_patterns` (default False — real-time skips patterns). v1.11 display keys: `display_theme_preset`, `display_accent_color`, `display_bg_image`, `display_bg_opacity`, `display_bg_blur`, `display_font_content_size` (default 13), `display_font_log_size` (default 12), `display_log_monospace` (default True), `display_widget_scale` (default 1.0, restart-only). |

### src/ui/views/ — CTkFrame subclasses, one per sidebar item
| File | Class | Notable internals |
|------|-------|-------------------|
| `app.py` | `App` | `_navigate()`, `get_view()`, `_view_factories`, `_HAS_ON_SHOW`, `_AUTO_REFRESH`. Parses `--scan <path>` from argv → pre-loads Scan view |
| `scan_view.py` | `ScanView` | Scan lifecycle and path input. `ScanView(_ThreatActionsMixin, _ScanPipelineMixin, _ScanEngineMixin, ctk.CTkFrame)` — 27 own methods; the other three groups live in their own modules and are combined by inheritance. Owns `__init__`, `_build`, the path/browse/drop handlers, the scan lifecycle (`_start_scan` … `_finalize_scan`, `_run_secondary_engines`, `_run_next_engine`), the post-scan handoffs (`_send_to_virustotal`, `_open_behavioral`, `_maybe_vt_verify`) and `_log_append`/`_log_clear`. **All instance state the three mixins read is initialised here** — engine result maps `_k2_infected_paths`/`_g_infected`/`_g_tier`/`_g_context`/`_yara_infected`/`_clamav_infected`/`_defender_infected`/`_speakeasy_infected`/`_threat_severity`/`_disputes`; panel state `_threat_*` + `_row_registry` + `_hash_cache` + `_circuit_state` + `_heuristic_collapsed` + `_scan_session_ignored` + `_bulk_*`; pipeline state `_engine_queue` + `_pipeline_rows` + `_drag_*` + the six `_use_*` flags. |
| `scan_pipeline_mixin.py` | `_ScanPipelineMixin` | The Scan Pipeline panel: `_build_pipeline_panel`, the header/collapse helpers, `_normalized_pipeline_order`, `_build_secondary_rows`/`_rebuild_secondary_rows`, `_move_engine`/`_reset_pipeline_order`, drag-and-drop (`_on_drag_start/motion/end`, `_get_engine_at_y`), the user-preset menu (`_get_user_preset_names`, `_refresh_preset_menu`, `_on_user_preset_select`, `_save_as_user_preset`, `_delete_user_preset`) and the six `_on_*_toggle` handlers. A **partition of `ScanView`**, not a standalone component — it calls back into `ScanView._refresh_drop_label` and reads state `ScanView.__init__` owns. |
| `scan_engine_mixin.py` | `_ScanEngineMixin` | One runner per engine: `_run_k2_scan`, `_run_guardian_scan`, `_run_yara_scan`, `_run_clamav_scan`, `_run_defender_scan`, `_maybe_run_speakeasy_pipeline`, `_run_speakeasy_inline`, `_on_speakeasy_inline_result`. Also a **partition of `ScanView`**: each runner reports through `ScanView._log_append`/`_run_next_engine`/`_finalize_scan` and through `_ThreatActionsMixin._build_threat_actions`/`_render_circuit_banner`, and writes the result maps `ScanView.__init__` owns. |
| `threat_actions_mixin.py` | `_ThreatActionsMixin` | Master-detail Threat Actions panel + bulk actions + hash computation + dispute resolution + auto-ignore prompt. Extracted from `scan_view.py` (was ~1400 lines bundled into `ScanView`). Combined into `ScanView` via multiple inheritance — every method accesses state owned by `ScanView.__init__`, so no plumbing is needed. Methods: `_check_disputes`, `_get_all_infected_paths`, `_get_engine_verdicts`, `_is_disputed`/`_dispute_for_path`, `_reason_bucket`, `_severity_for`, `_get_filtered_paths`, `_build_threat_actions`, `_build_threat_header`/`_pagination`, `_render_threat_master`/`_detail`, `_render_circuit_banner`, `_build_master_row`, `_build_heuristic_header`, `_build_dispute_mode_panel`, `_render_bulk_footer`, the row/keyboard/filter/chip handlers (`_on_*`), `_action_quarantine`/`_ignore`, `_open_in_explorer`, `_open_ignore_dialog`/`_do_ignore`/`_on_ignore_done`, `_maybe_show_autoignore_prompt`/`_show_autoignore_prompt`, `_mark_resolved`/`_resolve_dispute`, `_bulk_action` + `_show_bulk_progress`/`_update_bulk_progress`/`_cancel_bulk`/`_on_bulk_done`, `_compute_hashes_async`/`_on_hashes_done`, `_quarantine_all_threats`/`_on_quarantine_all_done`. |
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
| `_view_utils.py` | *(no class)* | Helpers shared by more than one view: `_format_eta()`, `_human_size()`, `_parse_dnd_paths()`. Views must not import each other — `scan_view` imports `threat_actions_mixin` for its mixin, so anything the mixin needs back from `scan_view` closes a cycle. That is how `_human_size` came to exist twice; this module is the third place both can reach. Keep it dependency-free: no widgets, no `ui.core`, no Tk root. |

### src/tools/
| File | Key exports |
|------|-------------|
| `update_intelligence.py` | `run_update(mode)`, `fetch_malwarebazaar(mode)`, `import_nsrl()`, `import_c2_blocklist()`, `clear_malicious_db()`, `download_yara_community()`, `get_stats()`, `lookup_hash()`, `is_known_safe()`. **v1.15:** every importer validates before it writes — a feed that returns nothing, an error page, an empty or corrupt archive returns `{"error": …}` and leaves both the table and its freshness stamp alone. `clear_malicious_db()` takes `notify=` and fires the `hashes` hooks like an import does (removal is an intelligence change), including when zero rows were deleted. `_rebuild_nsrl_bloom()` publishes atomically — temp sibling → fsync → `os.replace` → clear `nsrl_bloom_stale` last. Timestamps go through `_utcnow()`; IP feeds go through `_valid_ip()` / `_split_ioc_endpoint()`. |

### Runtime directories (not source)
| Path | Contents |
|------|---------|
| `intelligence/threat_db.sqlite` | SQLite: `malicious` table (MalwareBazaar MD5s), `safe` table (NSRL), `meta` table |
| `intelligence/ignore_list.sqlite` | v1.9: SQLite `ignored_hashes` table — user-flagged false-positive whitelist consulted by Guardian's `scan_file()` short-circuit. Created on first ignore action. |
| `telemetry/pattern_stats.sqlite` | v1.10 (moved v1.16): SQLite `pattern_stats` table (per-pattern detection + ignore counts). Drives the FP-rate display in Settings → Advanced Guardian Settings. Created on first pattern detection. |
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
- To add a new view: add entry to `_NAV_ITEMS`, add a **zero-argument lambda** to `_view_factories` in `_build()`, add to the right set. Views are constructed on first navigation, not at startup — `_views` is the cache, not the registry.

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
val = cfg.get("some_key")           # returns default if missing
cfg.set_value("some_key", value)    # persists immediately to JSON
                                    # (note: set_value, NOT set)
```

`set_value()` is the **key-granular** persistence primitive (v1.13). One call
does a locked re-read → merge-one-key → atomic replace, because the service
writes this file too and a whole-file write loses whatever the other process
changed. It returns `cfg.SAVE_OK` / `SAVE_DEGRADED` / `SAVE_FAILED` rather than
raising — the 73 call sites are bare calls in Tk event handlers, some firing per
slider drag tick. Ignoring the return is fine; treating `SAVE_DEGRADED` as a
durable merge is not. `save(dict)` still exists but is deprecated: it replaces
the file wholesale and reintroduces the lost-update bug.
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
| Add a new sidebar view | `src/ui/app.py` (`_NAV_ITEMS`, `_view_factories`, `_HAS_ON_SHOW`/`_AUTO_REFRESH`) + new `src/ui/views/<name>_view.py`. The factory is a zero-arg lambda; the view is built the first time it is shown. |
| Add a method to ScanView | Decide which of the four classes owns it: pipeline UI → `scan_pipeline_mixin.py`, a per-engine runner → `scan_engine_mixin.py`, threat panel → `threat_actions_mixin.py`, otherwise `scan_view.py`. **No name may exist in two of them** — a collision resolves silently by MRO order and the loser never runs. `tests/test_view_lifecycle.py` fails on one. Do not call `super()` between the mixins; they are siblings, and anything genuinely shared belongs in `_view_utils.py` or on `ScanView`. |
| Add a helper two views both need | `src/ui/views/_view_utils.py` — **never** by importing one view from another. `scan_view` already imports `threat_actions_mixin`, so the reverse edge is a cycle; the log-tag constants at the top of `threat_actions_mixin.py` are duplicated for exactly this reason and say so. |
| Reach into a view from another view | `App.get_view(key)` — **never** `app._views[key]` or `key in app._views`. `_views` only holds pages the user has already opened, so a membership test there is "has the user been here", not "does this page exist", and the handoff silently no-ops. See `ScanView._send_to_virustotal()`. |
| Make a view do work on every navigation | Put it in `_HAS_ON_SHOW` (implement `on_show()`) or `_AUTO_REFRESH` (implement `refresh()`) — and make sure the method actually exists under that name. `SchedulerView` sat in `_AUTO_REFRESH` with only `refresh_task_info()`, so every visit raised `AttributeError` into Tk's error handler and the page never refreshed. |
| Add a user setting | `src/ui/core/settings.py` (defaults dict) + `src/ui/views/settings_view.py` (UI row) |
| Change scan behavior | `src/ui/core/scanner.py` + `src/ui/views/scan_view.py` |
| Change pause/resume for subprocess engines | `src/ui/core/proc_pause.py` — `watch_pause_event()` daemon, `suspend_pid()`, `resume_pid()` |
| Change Smart scan targets | `src/ui/core/scan_presets.py` — `_smart()` targeted-dirs list (browser extensions, PowerShell profiles, WindowsApps, etc.) |
| Add/change user scan path presets | `src/ui/views/scan_pipeline_mixin.py` — `_save_as_user_preset`, `_delete_user_preset`, `_refresh_preset_menu`; stored in `scan_path_presets` setting |
| Change pipeline D&D behavior | `src/ui/views/scan_pipeline_mixin.py` — `_on_drag_start/motion/end`, `_get_engine_at_y`, `_drag_row_registry` |
| Change the intelligence freshness card | `src/ui/views/dashboard_view.py` — `_refresh_intel_card()` / `_build_intel_card()` (row 4; Recent Threats sits at 5/6). Posture text and level come from `intel_updater.get_posture()` — do not recompute state in the view. |
| Change intelligence update settings UI | `src/ui/views/settings_view.py` — `_build_intel_update_section()`. Note `SettingsView` has **no** status callback: report through the section's `_intel_feedback` label via `_intel_say()`, as the VT/ClamAV sections do. |
| Change first-launch onboarding | `src/ui/views/dashboard_view.py` — `_build_getting_started()` for card content; `_svc_installed()` / `_has_intel()` / `_has_scan_history()` for completion logic; `getting_started_dismissed` setting |
| Change real-time watcher verdicts or completion timing | `src/ui/core/watcher.py` — `_CompletionBarrier`, `_derive_status()`, `scan_new_file()`. Adding an engine means adding it to `_plan_secondary()` **and** `_SECONDARY_ORDER`. The service consumes completion via `polyshield_service._on_scan_complete`. |
| Change how an engine reports that it could not run | All three engines take `on_error` on `scan_async()` — fired at most once and **always before `on_done`**, because `on_done` releases the watcher's completion barrier. Consumers: `watcher._make_launch` (records `status="error"` → `"incomplete (<Engine> error)"`) and `scan_view._run_yara_scan` / `_run_clamav_scan`. A new engine must accept the parameter or `tests/test_engine_contract.py` fails. See [docs/TESTING.md](docs/TESTING.md#the-engine-failure-contract-v114). |
| Change Guardian AI detection | `src/ui/core/guardian_engine.py` (`_HEURISTIC_PATTERNS`, `_EnhancedScanner.scan_file`) |
| Change Guardian false-positive guards | `src/ui/core/guardian_engine.py` top of `scan_file()` — `_DEFAULT_MIN_SCAN_BYTES`, `ignore_list.contains()` short-circuit; setting `guardian_min_scan_bytes` |
| Add or rename a Guardian heuristic pattern | `src/ui/core/guardian_engine.py` — `_EnhancedScanner._PATTERNS` is the **only** place the labels live. Settings reads them through `pattern_labels()`, `conservative_disabled()` and `pattern_enabled()`; never re-declare the list or re-implement the profile rule in a view. The labels are the keys of `guardian_pattern_toggles`, so a second copy that drifts produces a switch that reads OFF over a pattern that still fires. |
| Update a widget from a worker thread | `self.after(0, lambda v=value: widget.configure(text=v))` — **never** `self.after(0, widget.configure, {"text": v})`. CTk's `configure()` is `(require_redraw=False, **kwargs)`, so a positional dict lands on `require_redraw` and the widget silently never changes. `tests/test_settings_update_views.py` scans `src/ui` for the shape. |
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
| Resolve a file path anywhere in the app | `src/ui/core/paths.py` — **never** `Path(__file__).resolve().parents[N]`. Ask whether the file is DATA (survives a restart → `app_root()` and its named accessors) or RESOURCE (ships with the program → `resource_root()`). `tests/test_paths.py` fails on a reintroduced root unless it is added to `_ALLOWED` with a reason. After changing a root, grep for every **use** of the variable it defined — and for `kicomav_env` / `guardianai` literals, which name a path without touching `__file__`. |
| Change intelligence DB schema | `src/tools/update_intelligence.py` (`_SCHEMA`, migration needed if DB exists) |
| Change what an importer does with a bad download | `src/tools/update_intelligence.py` — the validation branch of `fetch_malwarebazaar` / `import_c2_blocklist`. The rule is **download → validate → import → commit → freshness**: return `{"error": …}` before opening the DB, never a fabricated `total_db`. Returning the real total instead would read as `UNCHANGED` in `intel_updater._run_malwarebazaar` and advance freshness on an empty feed. |
| Change how a C2 feed line is parsed | `src/tools/update_intelligence.py` — `_parse_feodo` / `_parse_threatfox`, both routed through `_valid_ip()`; endpoint splitting lives in `_split_ioc_endpoint()` (IPv4:port, bracketed IPv6:port, bare IPv6). Never split an ioc_value on its last colon — that truncates every port-less IPv6 address. |
| Change NSRL bloom publication | `src/tools/update_intelligence.py` — `_rebuild_nsrl_bloom()`. Build to a sibling temp file (not `tempfile.mkstemp` — `os.replace` carries the ACL), `os.replace` into position, and clear `nsrl_bloom_stale` **last**. The reader is `guardian_engine._load_nsrl_bloom()`, which skips a filter marked stale and quarantines one it cannot parse. |
| Add or change an auto-updated feed | `src/ui/core/intel_updater.py` — `_FEEDS` registry (name → runner, domain, freshness meta key) plus a `_run_<feed>` adapter returning `{status, added, total, error, http_status}`. Status vocabulary: `updated` / `unchanged` / `skipped` / `failed` / `backoff`. |
| Change update cadence or staleness thresholds | `src/ui/core/settings.py` — `intel_update_interval_hours` (scheduling) is separate from `intel_aging_days` / `intel_stale_days` (UI warnings). Never hard-code these in `intel_updater`. |
| Create a file/dir the service writes and the UI reads | Use `os.mkdir` / normal file creation so the parent ACL is inherited. **Never `tempfile.mkdtemp()`** for anything promoted into shared application data — it yields a DACL with zero inherited ACEs, so LocalService publishes artefacts only LocalService can read, and the UI sees them as missing rather than as an error. |
| Change how YARA rules are published | `src/tools/update_intelligence.py` — `download_yara_community()`. Rules are published as immutable generation dirs under `rules/community/<gen>/`, switched by an atomic `.active` pointer replace; `yara_engine.active_community_dir()` is the reader. Never extract into the live directory — `_compile()` re-reads it on every scan. |
| Refresh an in-memory consumer after an intelligence update | Register it in `src/ui/core/intel_hooks.py`. Hooks are **domain-scoped** — `hashes` (malicious/safe tables), `ips` (ip_blocklist), `rules` (YARA files) — so a YARA download never triggers a Guardian MD5 rebuild. Importers take `notify=` : direct callers fire their own domain, a batch updater passes `notify=False` and fires once for the union. |
| See what a view actually looks like | `tools/uishot/` — `python tools\uishot\__main__.py [--only SCENE]` captures views to `artifacts/ui/` with no visible window and no mouse; `--check` diffs against `tests/golden/ui/`. Add scenes in `tools/uishot/scenes.py`. Read its README before touching the capture path — the hidden-desktop binding and the PrintWindow flag are both load-bearing and measured. |
| Update the PolyBedrock dependency | **Three files declare it and they must move together** — `requirements.txt`, `requirements-ci.txt` and `build.ps1` `$POLYBEDROCK`. All three are pinned to a commit; unpinned, `build.ps1` bakes whatever `master` was that day into the shipped interpreter. The supported range (`>=0.1,<0.2`) cannot live beside the URL — PEP 508 forbids a version specifier on a direct reference — so `tests/test_substrate_pin.py` asserts it against the installed metadata, and fails on an unpinned site or a revision that drifted. See docs/ARCHITECTURE.md, "The pin and the range are two different things". |
| Sign a build | `build.ps1` — **opt-in, environment variables only** (`POLYSHIELD_SIGN_THUMBPRINT` / `POLYSHIELD_SIGN_EXTRA_ARGS`; block at the top of the file). `Invoke-Sign` signs `PolyShield.exe` straight after the compile so the engine gate runs the *signed* binary; the installer and its uninstaller are signed through Inno's own `SignTool` hook (`/DSignInstaller` in `installer/polyshield.iss`). `-RequireSigning` makes a missing certificate a pre-flight failure. Never add a PFX-plus-password mode: the password lands in the process list and ISCC's log. See docs/ARCHITECTURE.md § *Code signing*. |
| Add a test | `tests/` (pytest). `kicomav_env\Scripts\pip.exe install -r requirements-dev.txt`, then `kicomav_env\Scripts\python.exe -m pytest`. Live-reload tests must assert through the production detection path, never by inspecting `virus_db` / `_known_bad`. |
| Add a detection-path test | Reuse the `conftest.py` sandboxes — `guardian_sandbox`, `ignore_db`, `pattern_db`, `quarantine_sandbox` — plus the `make_sample_file()` helper. Two autouse fixtures already restore module globals and assert at session end; see [docs/TESTING.md](docs/TESTING.md#isolating-module-global-state-v113). Build malware-pattern samples with `_payload()` fragments, never as literals. |
| Add a new update source | `src/ui/views/update_view.py` (new section card + `_run_*` method) + `src/tools/update_intelligence.py` |
| Fix console window flashing | Add `creationflags=subprocess.CREATE_NO_WINDOW` to the offending `subprocess` call |
| Change Windows Security data | `src/ui/core/win_security.py` — registry reads or PowerShell queries per section |
| Change Windows Security UI | `src/ui/views/winsec_view.py` — `_make_section()`, `_toggle_section()`, `_apply_overview()` |
| Change how an autorun value resolves to a path | `src/ui/core/startup_scanner.py` — `_extract_path()` and `_EXE_SUFFIXES`. Expand variables first, match the extension case-insensitively, and only cut where the extension **ends a token**. A wrong path here is silent: it fails `Path.exists()` and `get_scannable_paths()` drops it. |
| Change Explorer context menu | `src/ui/core/shell_ext.py` — `_MENU_LABEL`, `_get_command()`, registry key paths |
| Change network monitor logic | `src/ui/core/network_monitor.py` — `poll_connections()`, `is_known_bad_ip()`, `_is_unsigned()`, caches |
| Spawn a process from code that may run windowless | Pass `stdin=subprocess.DEVNULL`. An uninstaller runs the exe with `runhidden`, so it has no console and its standard handles are invalid; `sc.exe` and `schtasks` then fail with `[WinError 6] The handle is invalid` before doing anything. `capture_output` covers stdout and stderr — stdin is the one left inherited. |
| Change how the service registers, or its start type | `polyshield_service.py` `_with_startup_flag()` — **pywin32 never reads `_svc_start_type_`** (`win32serviceutil.py:221` defaults `startType` to `SERVICE_DEMAND_START`; it is filled only from an explicit `--startup`). The flag is injected at the one point all three callers funnel through, so `setup_service.bat`, `register_service.ps1` and the in-app Install button all get it. Verb-aware, and it never overrides a caller-supplied `--startup`. |
| Change the service's recovery or upgrade-path config | `integration.service_startup_commands()` — returned as data because three call sites need it in three shapes. `tests/test_service_startup.py` reads the two shell scripts from the real tree and fails if their literals drift from it. |
| Show service state anywhere | `integration.service_state()` — never `sc qc` parsing (localised field labels) and never start-type alone. `auto` + stopped is not "Automatic" and is not healthy; exit code 1077 means it has never started since boot. |
| Run something elevated from a view | `service_view._run_elevated(steps, done_cb)` — argv lists, per-step allow-listed exit codes, stops at the first failure, and `done_cb(ok, detail)`. **The script is never written to disk**: it goes over as PowerShell `-EncodedCommand`, because a helper file in `%TEMP%` is user-writable and then privileged-executed. Use `sc.exe`, never bare `sc` — in PowerShell `sc` is an alias for `Set-Content`. |
| Add a per-user registry integration | Copy the `shell_ext.py` shape: `register()`/`unregister()`/`is_registered()` returning `(bool, str)`, absent-is-success, every `OSError` swallowed in `is_registered()`, command built from `paths.app_launch_argv()`. Then add a teardown step to `integration._STEPS` — **and add the module to `_HKCU_MODULES` in `tests/conftest.py` FIRST**. That autouse floor fakes `winreg` for every test in the suite, and a session guard reads your real PolyShield entries at start and end and fails if they changed. Before it existed, the guard lived in one test file and three `register_all()` tests in another deleted the real Settings > Apps entry on every run. |
| Make a source checkout an installed product | `scripts/install_dev.bat` — **does not self-elevate** (an elevated spawn's console vanishes, and runs the HKCU work in the wrong profile); prompts `[y/N]`, registers per-user entries unelevated, lets `setup_service.bat` raise its own prompt, verifies the result with `service_state()`. A service step that fails exits 2 and keeps the per-user work; a per-user failure rolls back with `--unregister --keep-service`. And `scripts/uninstall_dev.bat` (self-elevating — Windows runs it unelevated). **Copies nothing** — every registered command points at the live checkout. Never write `.polyshield-distribution` into the checkout or set `POLYSHIELD_DATA_DIR` machine-wide: either flips `app_root()` to `%ProgramData%` and orphans the existing config, quarantine, logs and threat database silently. |
| Undo anything an installer registered | `ui.core.integration.unregister_all()` — not ad-hoc `sc delete` in a script. A failed install needs the same operation a successful uninstall does, and every step must be idempotent because rollback runs after an unknown amount of the install. |
| Run the k2 scanner | `paths.k2_argv(*args)` — never `K2_EXE` as a bare path. `k2.exe` is a setuptools stub embedding the ABSOLUTE interpreter path from pip-install time, so a relocated (i.e. installed) runtime makes it exit 1 with **no output at all** — which reads as a clean scan. A distribution runs `<runtime>\python.exe -m kicomav.k2`. |
| Invoke k2.exe for anything | Go through `scanner._k2_env()`. `k2 --update` PRUNES `%SYSTEM_RULES_BASE%` -- it deletes every file its downloaded manifest does not list. Pointed at PolyShield `rules\` (which `config/.env` did) it destroys `rules\community\` and the `.active` pointer, and `yara_engine` then reports "no rules" with no error. k2 gets `paths.k2_rules_dir()`, a tree it owns alone. |
| Resolve something that ships beside the executable | `paths.install_root()` — `runtime\`, `service\`, `k2.exe`. **Not** `resource_root()`: under onefile that is the extraction directory, deleted on exit. Three lifetimes now: `app_root()` durable+writable, `install_root()` durable+read-only, `resource_root()` disposable. See docs/ARCHITECTURE.md § *The install root is a third lifetime*. |
| Write a command into the registry or Task Scheduler | Build it from `install_root()` / `app_launch_argv()` / `script_launch_argv()` — never from `sys.executable` (it names a file that does not exist in a Nuitka build) and never from `resource_root()` (gone when the process exits). These commands must still be valid months later. |
| Write anything under `intelligence/` from the UI | It is service-owned in a distribution (`Users:Read`). Route through the authenticated IPC as `ignore_list.add()` does — router in `ui.core`, executor as `*_local()`, service handler calls the executor so it cannot recurse. Never fall back to a direct write: in a build it raises `PermissionError` inside an importer and surfaces as a network failure. |
| Decide whether new data is service-owned or user-writable | Ask whether the **service reads it to reach a verdict**. Detection input (`intelligence/`, `rules/community/`, `guardianai/`) is service-owned; output and preferences (`quarantine/`, `logs/`, `config/`, `telemetry/`) are user-writable. Quarantine stays user-writable **on purpose** — LocalService cannot read the user's own Downloads. `tests/test_privilege_boundary.py` fails if a detection module so much as names the quarantine directory. |
| Add a service IPC command | `polyshield_service.py` `_handle_client` dispatch chain + a `service_client.py` wrapper. Long-running commands must hand off to a worker thread and answer immediately (see `RUN_INTEL_UPDATE`), never block the socket. |
| Ask whether the service is running | `service_client.is_service_running()` — the answer is cached for `_PROBE_TTL_S` (2s). It is **not** a cheap call when the service is down: a closed loopback port here times out for the full 0.5s rather than refusing. Pass `max_age=0` only when **displaying** service state, and call `invalidate_service_probe()` after **changing** it. See [docs/WINDOWS_SERVICE.md](docs/WINDOWS_SERVICE.md). |
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

## Lessons (moved out of this file)

These were appended here after individual investigations. They live
in [`docs/LESSONS.md`](docs/LESSONS.md) and are **not** loaded on every
message — this index is. **If a title below names what you are
about to touch, read that section before you start.** Headings there
are verbatim, so grep the file for the line.

- Health Snapshot (last recorded — pre v1.2)
