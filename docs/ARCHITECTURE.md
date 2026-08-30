# PolyShield — Architecture Reference

Technical deep-dive: detection layers, scan pipeline, engine design, performance characteristics, database schema, and file structure.

For setup and usage, see [USAGE.md](USAGE.md). For a project overview, see [README.md](../README.md).  
For service internals and IPC protocol, see [WINDOWS_SERVICE.md](WINDOWS_SERVICE.md).  
For testing procedures, see [TESTING.md](TESTING.md).

---

## Detection Layers

### Four Layers (Cumulative by Version)

**1. K2 Engine (k2.exe)**
- Native Windows security scanner with proprietary signatures
- **Configurable** (v1.6+) — toggleable in the Scan Pipeline panel; can be disabled to let secondary engines serve as primary
- Produces JSON report: `infected_paths`, threat names, confidence
- Runs: ~10–30 sec for typical disk scan depending on scope (Smart/Quick/Full/Custom)
- Pause/resume via `NtSuspendProcess` / `NtResumeProcess` (no Unix SIGSTOP on Windows)

**2. Guardian AI (Optional Second Opinion)**
- Lightweight Python-based scanner for dual-scan verification
- Enabled via Scan Pipeline panel (v1.6+), previously a standalone checkbox
- Uses Local Intelligence Database for threat lookups
- Four-tier detection pipeline (see below)
- Slower than k2 but catches different threat patterns

**3. Local Intelligence Database (Optional for Guardian)**
- MalwareBazaar threat hash database (MD5 signatures)
- NSRL known-safe file hashes (allow-list — skip clean files faster)
- C2 IP blocklist (Feodo Tracker + ThreatFox — known botnet command-and-control IPs)
- Stored in `intelligence/threat_db.sqlite` (canonical); `guardianai/data/known_bad.txt` is a legacy fallback only (v1.8+)
- Hash tables consumed by Guardian AI; C2 blocklist consumed by the Network Monitor

**4. Network Monitor (Live Connection Analysis)**
- Polls established outbound TCP connections every 30 seconds via `psutil`
- No kernel driver required — monitoring works without elevation
- Checks each remote IP against the `ip_blocklist` table in `threat_db.sqlite`
- Flags connections to known C2 IPs (Feodo Tracker / ThreatFox feeds)
- Flags processes with no verifiable executable path phoning home (LotL/dropper indicator)
- "Block" button triggers a UAC-elevated `New-NetFirewallRule` outbound rule
- Runs inside the Windows Service; alert feed shown in the **Network** sidebar view

**5. WMI Process Monitor (Process Creation Events — v1.7)**
- Subscribes to `Win32_Process __InstanceCreationEvent WITHIN 1` via `win32com.client`
- For every new process: computes full-file MD5 (skip >100 MB), checks MalwareBazaar RAM set, checks `malicious` table in SQLite
- Detection latency: ≤ poll_interval seconds (default 1 s); configurable 1–10 s
- Session allow-list: hashes added via `ALLOW_HASH` IPC command are not re-killed (for user-restored files)
- Auto-terminate: optional; kills process tree via `psutil`; UI process does the kill for better permissions
- Service-autonomous mode: when UI is closed, service kills + quarantines per `process_monitor_ui_closed_action`
- Runs inside the Windows Service and in-process (fallback when service not running)
- Alert feed shown in the **Processes** sidebar view
- **Known limitation:** WMI fires *after* process launch (~1 s). Cannot block initial execution without a kernel minifilter driver. Processes under Protected Process Light (lsass.exe, MsMpEng.exe, DRM) are skipped — their executables deny read access for hashing.

---

## Full Scan Pipeline (v1.6.1 — Fully Modular Sequential Pipeline)

```
Scan view "▼ Scan Pipeline" panel
  ↓  all five engines are peers in pipeline_order; K2 is no longer "primary"
  ↓  default order shown below; user reorders any row with ↑/↓

[1. K2 Engine]    — toggleable; signature DB via a k2 subprocess (paths.k2_argv)
                    pause/resume via NtSuspendProcess; produces JSON report
                    can be removed entirely (k2.exe doesn't even need to exist)
[2. Defender]     — MpCmdRun.exe -ScanType 3; scans dirs as units, not per-file
                    detections found via Get-MpThreatDetection diff (before/after)
[3. Guardian AI]  — hash DB + 7 heuristic regex patterns; 4-tier lookup (see below)
[4. YARA Rules]   — user rules (rules/user_rules/) + community rules (rules/community/)
                    compiled once per scan; timeout per file
[5. ClamAV]       — community signature DB; all paths in a single clamscan invocation
                    (DB loads once, not once per file)
  ↓ (if Speakeasy checked AND any engine above flagged a PE file)
[Speakeasy]       — PE emulation on flagged .exe/.dll/.sys/.scr files only
                    always last; logs network activity + suspicious API calls
  ↓ (always)
[Threat Actions]  — per-file Quarantine / VirusTotal / Analyze buttons
                    rebuilt incrementally as each engine reports hits
  ↓ (manual — via Threat Actions panel)
[Sandboxie]       — manual detonation; not automated (requires user interaction)
[VirusTotal]      — manual or Smart Upload (hash-only; rate-limited to 4 req/min)
```

**Key properties:**
- **Sequential execution** — each engine starts only after the previous one completes; log output appears in engine order
- **User-configurable order (v1.6.1+)** — Every engine row has a **⠿ drag handle** (snap-on-release with blue/amber highlight) and **↑/↓** buttons for keyboard-style reordering. "↺ Reset order" restores the default (K2 → Defender → Guardian AI → YARA → ClamAV). Order persisted as `pipeline_order` in `ui_settings.json`. `_normalized_pipeline_order()` inserts newly-introduced engine IDs at their default position so old settings files migrate gracefully.
- **K2 is a peer engine (v1.6.1+)** — same row treatment as the others, reorderable, removable; `scanner.is_available()` reports whether `k2.exe` even exists; the suite runs fine without it
- **Dispute check fires from `_finalize_scan`** — regardless of K2 vs Guardian ordering, the comparison happens once at the end of the queue when both have results
- **Unified Pause/Resume (v1.6.1)** — one shared `threading.Event` (`_pipeline_pause_event`) gates the whole pipeline; **SET = running, CLEAR = paused**:
  - **K2 / ClamAV** (subprocess engines) — `ui/core/proc_pause.py` exposes `suspend_pid()`, `resume_pid()`, and `watch_pause_event(proc, event)` which spawns a daemon that suspends/resumes the subprocess via NtSuspendProcess whenever the event flips. ScanController for K2 retains its own pause API for backward compat; scan_view drives both.
  - **Guardian AI / YARA** (Python loops) — per-file loop calls `pause_event.wait()` which blocks while cleared. Re-checks `cancel_event` after wait returns so cancel-while-paused works.
  - **Defender** — not paused (each MpCmdRun.exe invocation is too short to suspend cleanly); cancel_event still halts the between-file loop.
  - Stop always sets the event before cancelling, because TerminateProcess is ignored by a suspended process.
- **Cancel-and-keep** — Stop button sets a shared `threading.Event`; each engine checks it per-file and exits cleanly; Threat Actions panel shows all results collected up to that point
- **K2 is optional** — unchecking K2 skips `sc.run_scan()` entirely; secondary engines become the first-tier scanners; progress bar runs in indeterminate mode
- **Speakeasy post-secondary** — always last; only runs after all other engines complete; skipped entirely if no PE-format files were flagged by any engine
- Each engine exposes `is_available()` — when not installed/configured, its row is disabled with an explanation badge rather than throwing an error
- `cancel_event: threading.Event | None` parameter on every `scan_async()` — thread-safe per-file cancellation without killing threads

---

## Guardian AI Scan Pipeline (4-tier + v1.9 false-positive guards)

When Guardian AI scans a file, it performs these checks in order:

```
File → Read content
  ↓
[v1.9 GUARD A — Minimum size]
  • If file size < guardian_min_scan_bytes (default 10), SKIP
  • Rationale: the null MD5 d41d8cd98f00b204e9800998ecf8427e (MD5 of any
    zero-byte file) is present in the MalwareBazaar threat DB, which would
    otherwise flag every empty lockfile, SQLite WAL/journal, and browser-
    extension placeholder on the system as "Known Signature"
  ↓
Compute MD5
  ↓
[v1.9 GUARD B — User ignore list]
  • ignore_list.contains(md5)? → SKIP ("User-ignored hash")
  • Backed by intelligence/ignore_list.sqlite (in-process set cache, O(1))
  • Populated from the Threat Actions panel "Ignore…" action (with note)
  ↓
[1. NSRL Allow-List] → Bloom filter first (v1.7)
  • "Definitely NOT in NSRL" → zero SQLite opens → fall through
  • "Probably in NSRL"       → one confirming SQLite query:
      is_known_safe(md5)? True  → SKIP (known-safe system file)
                          False → Bloom false-positive; fall through
  • No bloom file → direct SQLite query (legacy fallback)
  ↓ (if not safe)
[2. RAM Known-Bad Set] → is in MalwareBazaar set?
  • Dict lookup of hashes loaded from SQLite at scan start (v1.8+)
  • Capped at 500K entries; if DB > 500K entries, this tier is skipped (tier 3 covers it)
  • O(1), very fast (~0.1ms)
  • If match: falls through to tier 3 for enriched family name
  ↓ (if not in RAM set, or RAM set was skipped)
[3. SQLite Metadata] → lookup_hash(md5)
  • Retrieves malware family name + engine count if available
  • O(log n), ~1-5ms per query; always runs for any file that reaches this tier
  ↓ (if not in DB)
[4. Heuristic Patterns] → regex matching
  • 7 patterns: AutoRun, WScript dropper, encoded PowerShell, MSHTA,
    Mimikatz strings, ransomware notes, Bitcoin ransom addresses
  • Each pattern is a simple regex, ~0.5-2ms total
  ↓
Result: Clean, Infected, or Suspicious (pattern match)
```

**v1.9 false-positive guards** are deliberately Guardian-specific. K2, ClamAV
and YARA each have their own scanning logic that already handles empty files
correctly (K2 is signature-based with its own DB; ClamAV is mature; YARA rules
typically include `filesize > N`). We do NOT pre-filter 0-byte files at the
pipeline queue level — that would suppress legitimate detections those engines
might still want to make on files Guardian skips.

**v1.10 — Tier-aware verdicts + sensitivity profile system.** The four-tier
pipeline is unchanged in *structure*, but the return value is now a 4-tuple
`(infected, reason, tier, match_context)` where `tier ∈ {safe, hash, pattern,
clean, skipped}`. Tier 4 (pattern matching) is additionally gated by the
sensitivity profile and per-pattern toggles:

```
Tier 4: Heuristic Patterns
  ↓
[Sensitivity profile check]
  • Conservative — "Ransomware note" + "Ransomware payment" patterns are SKIPPED
  • Balanced     — all 7 patterns enabled
  • Power        — all 7 patterns enabled, severity NOT downgraded
  ↓
[Per-pattern toggle override]
  • If guardian_pattern_toggles[label] is False  → skip this pattern
  • If guardian_pattern_toggles[label] is True   → run regardless of profile
  ↓
[Circuit breaker]
  • If pattern_hit_count >= guardian_circuit_breaker_threshold (default 200)
    → mark scanner._circuit_tripped = True, short-circuit remaining tier-4 calls
    → UI surfaces red banner with hit count + threshold
  ↓
On match:
  • pattern_stats.record_detection(label)        — telemetry for FP-rate UI
  • Capture ~160 char context snippet            — drives the Match Context
                                                   block in the detail pane
  • Return tier='pattern' with match_context     — UI applies severity downgrade
                                                   (Suspicious) unless profile=power
```

The UI's master-detail Threat Actions panel uses `tier` to bucket findings:
`hash` → red "Confirmed"; `pattern` → amber "Suspicious" (Conservative/Balanced)
or red "Confirmed" (Power). The consensus badge counts how many engines flagged
each file and shows a specific warning for lone Guardian-pattern hits where
all hash engines say clean (>99% FP probability per Gemini's analysis).

Every engine the watcher launches records a verdict in `entry["verdicts"]`, and a
completion barrier notifies observers once all of them have reported — no engine's
result can be suppressed by another finishing first (v1.13).

The watcher path (`watcher.py::scan_new_file`) passes `use_patterns_override=False`
by default (controlled by `watcher_guardian_patterns` setting) so real-time
scanning runs hash tiers only — pattern false positives at watcher cadence
would cascade quickly on Downloads/Desktop/USB drops.

---

## Scan Pipeline State Machine (v1.6.1)

```
_start_scan()
  ├─ Always indeterminate progress bar (no special K2 branch)
  └─ _run_secondary_engines(paths)
        ← builds engine queue via _normalized_pipeline_order()
        ← K2 is just another entry ("k2") in that list
  │
_run_secondary_engines(paths)
  ├─ Reads pipeline_order from settings (with _normalized_pipeline_order() for upgrade safety)
  ├─ Skips unchecked / unavailable engines
  ├─ Builds self._engine_queue = [run_fn, ...]  in user-configured order
  └─ _run_next_engine()

_run_next_engine()
  ├─ cancel_event set? → _finalize_scan(aborted=True)
  ├─ queue empty?      → _maybe_run_speakeasy_pipeline()
  └─ pop queue head    → run_fn(paths)
       │
       ├─ [K2]        → sc.run_scan() → _on_done(returncode, report_path)
       │                  └─ switches progress bar to determinate while K2 runs
       │                  └─ reverts to indeterminate if more engines follow
       │                  └─ _run_next_engine()
       │
       ├─ [Guardian]  → ge.scan_async(..., pause_event=_pipeline_pause_event)
       │                  └─ per-file: pause_event.wait() → cancel check → on_done()
       │                  └─ _run_next_engine()
       │
       ├─ [YARA]      → ye.scan_async(..., pause_event=_pipeline_pause_event)
       │                  └─ per-file: pause_event.wait() → cancel check → on_done()
       │                  └─ _run_next_engine()
       │
       ├─ [ClamAV]    → ce.scan_async(..., pause_event=_pipeline_pause_event)
       │                  └─ proc_pause.watch_pause_event(proc, event) daemon
       │                  └─ cancel branch: resume_pid() + proc.terminate()
       │                  └─ _run_next_engine()
       │
       └─ [Defender]  → df.scan_paths_async(...)
                          └─ no pause (too short-lived); cancel_event between dirs
                          └─ _run_next_engine()

_maybe_run_speakeasy_pipeline()
  ├─ Speakeasy unchecked / unavailable? → _finalize_scan(aborted=False)
  ├─ No PE files flagged by any engine?  → _finalize_scan(aborted=False)
  └─ _run_speakeasy_inline(pe_files)
       ├─ per-PE: emulate_async() with 30s timeout
       ├─ check cancel_event between files
       └─ self.after(0, _finalize_scan, cancelled)

_finalize_scan(aborted)
  ├─ Guards against double-call: if not self._scanning: return
  ├─ Re-enables Scan button, disables Stop/Pause
  ├─ Logs [STOPPED] if aborted
  ├─ _check_disputes()  — compares K2 vs Guardian results regardless of run order
  └─ _build_threat_actions()  — rebuilds from all 6 engine dicts
```

**`_stop_scan()` flow:**
```
_stop_scan()
  ├─ _pipeline_pause_event.set()      — unblock any paused Python-loop engine
  ├─ _pipeline_cancel_event.set()     — signals per-file loops in all engines
  └─ _scan_ctrl.cancel()  (if K2 running)
       └─ sets pause_event FIRST (TerminateProcess fails on suspended procs)
       └─ k2 dies → _on_done(-1, None) → _run_next_engine()
            → cancel_event set → _finalize_scan(aborted=True)

Guardian/YARA: break on next file when cancel_event checked after pause_event.wait()
ClamAV:        cancel branch in scan_async resumes + terminates clamscan.exe
Defender:      cancel_event checked between MpCmdRun.exe invocations
```

**Threat Actions incremental updates:** `_build_threat_actions()` collects from `_k2_infected_paths + _g_infected + _yara_infected + _clamav_infected + _defender_infected + _speakeasy_infected`, deduplicates by insertion order, and rebuilds the panel. Each engine's `_on_done` calls it when it finds hits → user sees the panel grow as engines complete.

---

## Network Monitor Architecture

Two-tier design — monitoring requires no elevation; blocking requires UAC once.

```
[NetworkMonitorThread]  (runs inside polyshield_service.py)
  ↓  every 30 seconds
psutil.net_connections(kind="inet")
  ↓  per ESTABLISHED outbound connection
_resolve_process(pid)       → name, exe path  (PID cache, max 500 entries)
is_known_bad_ip(remote_ip)  → flagged, tags   (IP cache, reset every 20 polls)
_is_unsigned(process_path)  → True/False       (path empty or nonexistent)
  ↓
Tier 1: C2 match (ip_blocklist)  → reason "c2:<tags>"
Tier 2: Unsigned outbound        → reason "unsigned"  (LotL indicator)
Tier 3: Clean
  ↓  (if any alerts)
_push_event({"event": "network_event", "connections": [...], "alerts": [...]})
  → stored in _net_events ring buffer (cap 100)
  → broadcast to all SUBSCRIBE clients

[Block button in UI]
  ↓
service_client.block_ip(ip)
  → service._block_ip() → ShellExecute runas powershell New-NetFirewallRule
  → _record_manual_block() → ip_blocklist INSERT with tag "manual_block"
```

**Why not PyDivert / OpenSnitch / Moon Secure:** See [USAGE.md — Future Work](USAGE.md#future-work-roadmap).

---

## Packaging (v1.15, Phase 4b)

The build is `build.ps1` (launched by `build.bat`), which is **tracked**: a
release artifact that cannot be reproduced from the repository is not
reproducible. Its output — `dist/` and Nuitka's `*.build` / `*.onefile-build`
scratch directories — is ignored.

Toolchain lives in `requirements-build.txt`, deliberately apart from both
`requirements.txt` (nothing here is needed to *run* PolyShield) and
`requirements-dev.txt` (CI runs tests and never builds; adding Nuitka there
would cost every CI run a compiler download for nothing). It installs into
`kicomav_env` rather than a build-only venv because Nuitka compiles what it can
import — a separate environment would have to duplicate `requirements.txt` to
see `customtkinter`, `watchdog` and the rest.

### Milestones

Correctness before optimization. Each milestone must produce a **runnable**
artifact before the next packaging dimension is added; if a build breaks, stop
at that milestone rather than changing several variables at once. Compression,
UPX, onefile tuning, startup time and icon polish are all deferred to the last
step, after a clean-machine run passes.

| | Deliverable | Gate |
|---|---|---|
| 4b.1 | GUI exe, simplest working config | Starts; durable data lands outside the extraction directory |
| 4b.2 | Service, **source-mode** | Resolves the same canonical data root as the compiled GUI. Not compiled — only the GUI entry point survives the compiler; see below |
| 4b.3 | Scheduled-scan exe | Task runs (required — see `script_launch_argv`) |
| 4b.4 | Optional engines, one at a time | Each individually verified, by detection and not by launch |
| 4b.5 | Clean Windows Sandbox run | **20/20 pass** — see *Verified on a clean machine* |
| 4b.6 | onefile + console mode | **20/20 on a clean machine**, onefile layout. 105 MB folder → 26 MB single file |
| 4c.0 | Shared data root + privilege boundary | GUI and LocalService resolve the same root; intelligence writes routed |
| 4c.1 | `install_root()` and the launch seams | All three roots correct in a real build; scheduled scans runnable again |
| 4c.2 | The runtime builds itself, with K2 | Hash pinned, `import site` asserted, pywin32 off System32, k2 plugins counted |
| 4c.3 | Distribution-mode fixes | Menu icon resolves; dev-only sections say so; teardown is idempotent |
| 4c.4 | `PolyShield-Setup.exe` | Compiles; ACL boundary verified on a real tree; rollback wired |
| 4c.5 | Clean-machine verification | **47 checks, 0 failures** on a machine with nothing: install, reinstall over a dirty machine, uninstall |

**Failed milestones must be cleanly reversible.** A failed build must not
become the base for the next attempt: rebuild `dist/` rather than building over
it, treat staged files as disposable, and revert machine state before retrying.
From 4b.2 on that matters concretely — a run that registers the Windows service
and then fails elsewhere leaves the registration behind, and repeated attempts
accumulate dirty service and context-menu state.
`scripts/service/fix_service_crash.bat` and `shell_ext.unregister()` exist for
this and belong in the retry path.

### Three things a compiled build gets wrong that no test can catch (v1.15)

All three were found by building and running, not by reasoning, and none of
them is reachable from `tests/test_paths.py` — that file drives frozen
behaviour by monkeypatching a predicate, which covers the *policy* while
leaving the *environment* entirely unexamined. `tools/build_probe.py` exists
for the environment half: it is compiled with the same flags as the entry
points and exits non-zero when the build has resolved something wrongly.

**1. `sys.executable` is not the executable.** A Nuitka standalone build
reports a `python.exe` sitting beside the real binary, and **that file does not
exist**:

```
sys.executable               <dist>/PolyShield.dist/python.exe    ABSENT
sys.argv[0]                  <dist>/PolyShield.dist/PolyShield.exe
__compiled__.original_argv0  <dist>/PolyShield.dist/PolyShield.exe
__compiled__.containing_dir  <dist>                    (one level up)
```

Anything written into the registry or the SCM from `sys.executable` — the
Explorer context-menu verb, the elevated relaunch, the service image path —
points Windows at nothing, and does it silently. `paths.running_executable()`
is the answer, preferring `original_argv0` because onefile re-executes the
extracted binary: `argv[0]` is then the temporary copy, while `original_argv0`
stays the exe the user actually launched.

**2. The module tree is one level shallower.** A checkout is
`src/ui/core/paths.py`, so the project root is `parents[3]`. A build has no
`src/` level, so the same expression walks one *past* the directory the bundled
data is in. `resource_root()` therefore uses `parents[2]` when frozen — derived
from `__file__` rather than from `sys.executable`, which merely happens to
yield the right directory while resting on a path to nothing, and which would
be wrong for onefile besides.

**3. Every `mkdir` assumed its parent existed.** True in a checkout, which
always has a project root; false on a distribution's first run, where the
shared data root does not exist yet. `scanner.py`'s module-level
`LOGS_DIR.mkdir(exist_ok=True)` raised `WinError 3` at import and took the app
down before the first window was drawn.

### The service is a second, separate resolver

In a build the service and the UI are two executables that each resolve the
data root independently, and they *must* agree — they read the same threat
database, settings file and quarantine. The service is also the harder one to
inspect: it runs as LocalService, with a different environment from the
interactive user, and once installed there is no other way to ask it what it
concluded.

So `polyshield_service.py --paths` prints its resolution as JSON. It is the
gate for the packaged service build, and the first thing worth running when an
installed service misbehaves.

`_exe_name_` / `_exe_args_` come from `paths.service_registration()`: the
interpreter plus the script in a checkout, and the executable with **no**
arguments in a build, where the exe *is* the service and its no-argument branch
reaches the SCM dispatcher.

The build refuses to ship a service image containing `tcl\` or `tk\`. `ui.core`
is Tk-free today and the service imports nothing else, but a service that
acquires a display dependency fails on a session-0 desktop for reasons its own
logs will not explain — so it is enforced at build time rather than left as a
property someone has to keep remembering. It also keeps roughly 900 Tcl/Tk data
files out of the image.

Note that every `ui.core` import in the service is *inside a method*. A static
analyser sees none of them, so `--include-package=ui.core` is not
belt-and-braces: without it the service compiles cleanly and then cannot start.

### The runtime builds itself (v1.16, 4c.2)

`-Runtime <dir>` took a directory the developer had prepared by hand, so the
release artifact depended on a machine state nobody had recorded.
`build.bat -BuildRuntime` constructs it instead, from a hash-pinned python.org
embeddable distribution, and asserts every property the service depends on:

```
[runtime] hash verified
[runtime] import site enabled
[runtime] installed: pywin32, psutil, watchdog, kicomav
[runtime] pywin32 loads from the runtime, not System32
[runtime] k2: 1263 signatures across the loaded plugins
```

**`import site` is one commented-out line away from a runtime that imports
nothing.** The official `python-3.12.7-embed-amd64.zip` ships
`python312._pth` containing `#import site`. A `._pth` file replaces `sys.path`
wholesale, so with that line commented the path holds only `python312.zip` and
the runtime directory — `Lib\site-packages` never joins it and *nothing pip
installs there can be imported*. Measured both ways: commented, `sys.path` has
two entries and `import pythoncom` raises `ModuleNotFoundError`; uncommented,
six entries and pywin32 loads. The service would have failed at SCM start as
**error 1053**, and every explanation of 1053 in these docs points elsewhere.
The build enables the line and then asserts it took.

**pywin32 needs no System32 installation.** `pywin32_postinstall -install`
copies `pywintypes3XX.dll` / `pythoncom3XX.dll` into System32 — shared,
system-owned state an uninstaller must not casually remove. It is unnecessary
here: `pywin32.pth` imports `pywin32_bootstrap`, which calls
`os.add_dll_directory()` on the runtime's own `pywin32_system32\`. Proven
rather than assumed, by a version mismatch that removes all doubt — this
machine has only `pythoncom313.dll` in System32 while the runtime is 3.12, and
the runtime resolved `…\dist\runtime\Lib\site-packages\pywin32_system32\pythoncom312.dll`.
The build fails if pywin32 ever resolves outside the runtime, so the installer
can skip `pywin32_postinstall` entirely and the uninstaller never has to reason
about who else on the machine shares a copy.

**K2 ships, and its capability is measured rather than claimed.** K2 has no
signature data file: its ~1263 virus names live inside the 51 modules under
`kicomav/plugins/`, which pip installs with the package. `k2 --update` does
**not** add signatures — it fetches `whitelist.txt` and two YARA archives.
K2 loads those plugins with `SourceFileLoader` and swallows every per-plugin
failure, so a build that lost them still starts, still exits zero and still
reports every scan clean. `k2 --vlist` prints what actually loaded, and both
the build gate and `tools/engine_probe.py` require a non-trivial count.
Deliberately not detection-by-sample: EICAR is the obvious sample and Defender
deletes it between the write and the scan — measured, the file was gone before
k2 opened it.

**The build must not depend on which shell launched it.** `Get-FileHash` and
`Expand-Archive` live in auto-loaded modules, and a Windows PowerShell 5.1
child launched from a PowerShell 7 session inherits PS7 module paths and cannot
find them — measured, as *"The term Get-FileHash is not recognized"* from a
build started inside pwsh. Both are now .NET calls.

### k2 prunes the directory it is pointed at

`k2 --update` performs orphan detection: it downloads a manifest and **deletes
every file in its rules directory that the manifest does not list**
(`kavcore/k2updater.py`, `remove_orphan_files`). It finds that directory
through `%SYSTEM_RULES_BASE%`.

`config/.env` — generated by `install.bat` from `config/.env.template` — set
that to PolyShield's own `rules\`, which is also where
`download_yara_community()` publishes the YARA Forge generations. So every
*Update Center → K2 Engine Signatures* click deleted `rules\community\`, the
`.active` pointer included, and `yara_engine` then reported "no rules" with
nothing to explain it. Observed twice on a live tree before the cause was
found; the first diagnosis blamed the working directory, which was wrong — k2
never consults `cwd` for this.

k2 now gets `paths.k2_rules_dir()` (`<data>\k2\rules`), a tree it owns alone,
passed in the environment by `scanner._k2_env()`. Passing it there rather than
rewriting `.env` matters: kicomav calls `load_dotenv(override=False)`, so a
value already in the environment wins — which repairs existing installations
without touching a generated file, and works in a distribution that has no
`.env` at all.

### Verification that can fail (v1.16, 4c.5)

`tools/sandbox_verify.ps1` grew from 20 checks to 47. The additions are not
more of the same: the original set verified the **build**, and these verify the
**installer**, which registers a service and rewrites ACLs and has to be able
to undo both.

**The root invariant, tested the way it actually breaks.** The old check ran
`polyshield_service.py --paths` as the interactive user and compared it with
the GUI, also run by the interactive user -- it compared a process with itself
and could not fail. The service runs as `LocalSystem`, whose profile is
`C:\Windows\system32\config\systemprofile`, and that is the account whose
answer matters. `Invoke-AsSystem` runs it through `schtasks /ru SYSTEM` so the
comparison is between the two identities that actually differ. The unit test had
the same defect and was corrected the same way: `tests/test_paths.py` now hands
the two subprocesses *different* `%LOCALAPPDATA%` values.

**The privilege boundary, probed without elevation.** `setup_data_root.ps1
-Verify` refuses to run elevated. An administrator can write everywhere the
root grants `Administrators:F`, so the probe would report the whole tree
writable and fail for a reason that says nothing about the boundary -- and if
the expectations were ever inverted it would *pass* while proving nothing. The
sandbox drops to a basic-user token with `runas /trustlevel:0x20000`.

**A dirty machine, on purpose.** Rather than racing a kill against the
installer, the retry path is tested deterministically: a service is registered
under PolyShield's name pointing at a binary that does not exist, and the
installer has to recover from it. Installing twice over an existing install is
checked separately for idempotency.

**Retention, proved with something recognisable.** A sentinel file is written
into `quarantine\` before uninstall and checked afterwards. "The directory
still exists" is not the same claim.

**A scheduled scan is created end to end**, through the staged runtime with the
service tree on `sys.path` -- the 4c.1 fix, in the shape a real install has.
The registered command is then checked to name `runtime\python.exe` rather than
anything under a onefile extraction directory, which is gone the moment the
process that wrote it exits. It also makes the "scheduled task removed" check
after uninstall mean something: before this, no task was ever created, so that
check passed vacuously.

#### What eleven runs found

The harness was written, then run against a real install eleven times. Nothing
below was predicted; each was found by running it.

**The shipped binary did not contain the phase's central fix.** The first run
disagreed on the data root — because `dist\PolyShield.exe` had never been
rebuilt after 4c.0. Only `-Target service` had been run. The binary still had
the old `%LOCALAPPDATA%` root, no `--unregister`, and no context-menu flag.
Everything else in this phase was correct and none of it was in the product.

**The build's engine gate had never fired.** `--windows-console-mode=attach`
produces a GUI-subsystem binary, and PowerShell does not wait for those, so
`& $guiExe --engines` returned instantly with `$LASTEXITCODE` holding the
*previous* command's value and the probe's `FAIL:` line arriving after
"Build complete". Measured: unpiped `0`, piped `1`, `Start-Process -Wait` `1`,
same binary and same failure. The gate whose comment reads "The build must not
ship" was a no-op from 4b.4 until here. Consuming the output stream is what
makes PowerShell wait.

**`k2.exe` does not survive being installed.** It is a setuptools console stub
that embeds the ABSOLUTE PATH of the interpreter it was pip-installed against.
Installing relocates the runtime, and the stub then points at a directory that
is not on the machine — failing with **exit 1 and nothing on stdout or stderr**,
which a caller counting results reads as a clean scan. Reproduced on the build
machine by hiding `dist\runtime`: the same relocated stub that had just printed
23 signatures printed none. `paths.k2_argv()` now runs
`<runtime>\python.exe -m kicomav.k2`, which has no embedded path.

**A windowless process cannot spawn `sc.exe` with an inherited stdin.** An
uninstaller runs the exe with `runhidden`, so it has no console and its standard
handles are invalid; `sc.exe` failed with `[WinError 6] The handle is invalid`
before doing anything, and the uninstall reported success while the service was
still RUNNING. `capture_output` covers stdout and stderr — stdin is the one left
inherited, and it now gets `subprocess.DEVNULL`. The same bug made
`get_task_info()` report no scheduled task for one that existed, so the
uninstaller skipped deleting it. The context-menu step succeeded throughout,
because it uses `winreg` and spawns nothing.

**Restart Manager hung a silent uninstall.** `CloseApplications=yes` applies to
uninstall as well as install; a `/VERYSILENT` uninstall sat idle at 0% CPU
indefinitely and produced no report at all. Turning it off then broke *reinstall*
— a running service holds the staged runtime open and Inno failed with exit 5 —
so the installer now stops the service in `CurStepChanged(ssInstall)`, before
any file is replaced.

**Three checks passed for the wrong reason, and one asserted the defect.**
`data root under LOCALAPPDATA` asserted exactly what 4c.0 made wrong, and would
have gone green again the moment the bug came back. The ACL probe returned no
output from a detached `runas`, and an empty result satisfied a "contains no
[FAIL]" test. `schtasks /query` for a *missing* task prints an error containing
the task name, so a `-notmatch` test reported the task present precisely when it
had been removed. Reading a registry default value as a property named
`(default)` returned `System.Object[]`, which is truthy.

**A run that hangs writes no report at all**, which from outside is
indistinguishable from a run that failed. `Add-Check` now appends to
`progress.log` as it goes, and the findings are written before the richer report
is attempted. That is what localised the hang to the uninstall step, and what
made the last three iterations diagnosable rather than guesswork.

Final state: **47 checks, 0 failures**, on a machine with no Python, no
developer environment variables, and no source tree — through install, reinstall
over a deliberately dirty machine, and uninstall.

**`k2 --update` reports success when it cannot reach its source.** Measured on
a clean install: `[No updates available]`, exit 0, an empty rules directory, and
23 signatures instead of 1263 — a scanner at under 2% of its detection with
nothing anywhere saying so. k2 carries only ~23 signatures in its plugin
modules; the other ~1240 arrive in archives it downloads.

`installer/seed_k2_rules.ps1` therefore does not trust the exit code. It waits
for the update source to become reachable — an installer running seconds after a
machine boots is racing the network stack — runs the update, and then **counts
what the engine can actually name**, before and after. Everything it concludes
goes to `<data root>\logs\k2_seed.log`, because the step runs `runhidden` and a
failure there is otherwise invisible by construction.

If the archives are still missing it says so and exits 0: an install without a
network is ordinary, and the Update Center can fetch them later. What it does
not do is finish quietly.

The same number is surfaced in the product. The Update Center's K2 card shows
the count `k2 --vlist` reports rather than the number of files downloaded —
three files whether or not they contain anything — and renders a count under 100
as *"built-in only; run Update Now to download the rest"*.

Verified in the sandbox: `signatures before: 23` → `signatures after: 1263`.

Run it with `python tools\make_sandbox_wsb.py` and open the generated `.wsb`.
`--skip-install` keeps the build checks and skips the install cycle.

### The installer (v1.16, 4c.4)

`installer/polyshield.iss`, compiled by `build.bat -Target installer` into
`dist\PolyShield-Setup-<version>.exe` (52.5 MB from a 126 MB payload). Tracked,
for the same reason `build.ps1` is.

Three steps, and the order is the design:

1. **`setup_data_root.ps1`** creates `%ProgramData%\PolyShield` with explicit
   per-subtree ACLs, **before the application first runs**. If the unelevated
   GUI creates `intelligence\` first it inherits the root ACL, and the privilege
   boundary exists only in this document. `settings.py` and `intel_updater.py`
   both `mkdir(parents=True)` on their own, so this is not hypothetical.
2. **`register_service.ps1`** registers the service from the staged runtime.
3. The app writes its **own** Explorer verb (`--register-context-menu`), so the
   command string has one implementation — `paths.app_launch_argv()` — rather
   than a second copy inside an `.iss` file.

Directories are created *before* the root is locked down. Locking first makes
creating them depend on the caller being an Administrator, which is true of the
installer and needlessly untrue of a rollback retry.

`-Verify` re-runs the boundary as a probe: it tries to write into every
subdirectory as the **current** user and fails if any is on the wrong side.
Run it unelevated — an administrator can write anywhere and would see a
boundary that is not there. Measured on a real tree: `intelligence\`,
`rules\community\`, `state\`, `guardianai\`, `k2\` read-only; `config\`,
`logs\`, `telemetry\`, `quarantine\`, `rules\user_rules\` writable. That is the
half of the invariant no unit test can reach, because it is a property of the
installed directory rather than of the code.

**Rollback.** A failed or cancelled install runs `PolyShield.exe --unregister`
from `DeinitializeSetup`, which is reached on every exit. `unregister_all()`
treats absent as success, so it is safe after a failure at any point — including
before anything was registered. Without it, a run that registers the service and
then fails leaves the registration behind, and repeated attempts accumulate.

**Uninstall** removes program state always and user data only on request. The
threat database, quarantine, logs and settings are **kept** by default behind an
unticked checkbox: quarantine may hold the only copy of a file somebody wants
back, and an uninstaller that deletes it silently is one nobody can undo.

**No System32.** No `pywin32_postinstall`. The staged runtime carries its own
`pywin32_system32\` and `build.ps1` fails if pywin32 ever resolves outside it,
so the uninstaller never has to reason about who else on the machine shares a
system DLL.

**The service is required, not optional.** Intelligence updates, the ignore
list and k2 signature updates are all service-owned in a distribution, so a
service-less install would have no way to update its threat data.

#### Two bugs this phase found by running things

**The service account was not what everything said it was.** `sc qc` reports
`LocalSystem`; the docs and `setup_service.bat` both said
`NT AUTHORITY\LocalService`, and the script granted ACLs to that account —
rights handed to an identity nothing runs under. `pywin32` installs with no
account argument and LocalSystem is its default. Corrected in the docs and the
script; narrowing the account is deliberate work with its own verification,
because process termination, watched-folder reads and autonomous quarantine
currently work only because the account is wider than documented.

**`-NoClean` service builds shipped stale source.** `Copy-Item -Recurse` copies
*into* an existing destination rather than merging, so the second build produced
`dist\service\src\ui\core\core\` and left the original tree untouched — a
distribution carrying last week's `paths.py` under this week's version number,
silently. Only the iteration path hit it, which is where it was least likely to
be noticed. Found by `register_service.ps1 -PreflightOnly` on its first run: it
asks the staged service to resolve its own paths, and got an `AttributeError`
for a function added days earlier. The staging now clears each destination
first, and the pre-flight is the standing check.

### Undoing an install (v1.16, 4c.3)

`src/ui/core/integration.py` removes the three things that outlive the process:
the Windows service, the Explorer verb, and the scheduled task. It exists as a
module rather than as steps inside the installer because a *failed* install
needs the same operation a successful uninstall does -- this document already
records that a run which registers the service and then fails elsewhere leaves
the registration behind, and that repeated attempts accumulate dirty state.

Three properties, each load-bearing and none obvious:

- **Absent is success.** A rollback runs after an unknown amount of the install
  has happened, so "it was not there" is at least as common as "it was". `sc`
  1060 and a missing scheduled task are both reported as done.
- **Every step is attempted even when an earlier one fails.** They are
  independent, and the service step is the one needing elevation -- so an
  unelevated caller still gets the verb and the task cleaned up. Verified:
  `--unregister` without elevation reports `Access is denied` for the service
  and completes the other two.
- **The service is stopped before it is deleted.** Deleting a running service
  only marks it for deletion; it lingers until the last handle closes, and the
  next install then fails with *"marked for deletion"*, which reads as a
  corrupt system rather than as a reboot away.

Reached as `PolyShield.exe --unregister`, alongside `--paths` and `--engines`,
and handled *before* the single-instance lock for the same reason those are: an
uninstaller that silently exits 0 because a window happened to be open would
leave the service and the verb behind.

Nothing here touches user data. `tests/test_integration_teardown.py` fails if
the module so much as names `app_root`, `quarantine_dir`, `rmtree` or `unlink`.

### Sections that only apply to a checkout (4c.3)

Two of the five Update Center sections drive the *development* environment:
Speakeasy is pip-installed into `kicomav_env`, and Guardian AI is a git clone.
A distribution has neither. They did report -- `Popen` raised and the handler
logged `str(exc)` -- but what reached the log was *"[WinError 2] The system
cannot find the file specified"*, which reads as a broken installation rather
than as a section that does not apply to this one. Both now say so, and the
Guardian remedy no longer names a `scripts\` directory a distribution does not
ship.

The Explorer menu **icon** came from `sys.executable`, which in a Nuitka build
names a `python.exe` beside the real binary that does not exist -- so Explorer
silently showed no icon. The *command* beside it was already routed through
`paths` and was correct, which is what made the icon easy to miss.

### The shared data root, and why it is not the user profile (v1.16)

Until v1.16 `app_root()` resolved a distribution to `%LOCALAPPDATA%\PolyShield`.
That was wrong, and wrong in a way neither gate could see.

The service runs as `NT AUTHORITY\LocalService`, whose profile is
`C:\Windows\ServiceProfiles\LocalService`. So the two components resolved two
different directories:

```
GUI           C:\Users\<user>\AppData\Local\PolyShield
LocalService  C:\Windows\ServiceProfiles\LocalService\AppData\Local\PolyShield
```

A source checkout does not have the problem, because `setup_service.bat` grants
LocalService Modify on the project root. That is a *permission* fix, and it
cannot be applied here — two different paths are not a permission problem.

**Why this was worse than a split cache.** Two of the files underneath are
cross-process locks: `config/ui_settings.json.lock` (`settings.py`) and
`intelligence/.update.lock` (`intel_updater.py`). Both exist precisely because
two processes write the file. A lock at a path each process resolves
differently does not merely fail to protect: it hands **both** processes the
lock at once, and what it guards is a SQLite write.

**Neither gate could catch it**, and both are worth knowing about as a class:

- `tests/test_paths.py` passed *the same* `%LOCALAPPDATA%` to both subprocesses.
  It held constant the one variable that differs in production, so the assertion
  could not fail no matter what `app_root()` returned. It now passes deliberately
  different values.
- `tools/sandbox_verify.ps1` runs `polyshield_service.py --paths` as the
  interactive user, not as LocalService — so it compared a process against
  itself. `polyshield_service.py` even documents that diagnostic as "the only
  way to check the one that runs as LocalService"; that was the intent, not what
  the invocation delivered.

A distribution now resolves `%ProgramData%\PolyShield`, which is where the
service already kept `service_token.txt` and `service.log` — two absolute
literals that lived outside `paths.py` entirely, in two different modules, and
agreed only because someone kept them agreeing. They now resolve through
`state_dir()`.

### The privilege boundary (v1.16)

`%ProgramData%` is not user-writable by default, and for most of this tree that
default is correct. The invariant is narrower than "the GUI cannot write":

> An unprivileged process cannot modify authoritative intelligence that the
> privileged service trusts when making detection decisions.

The split is on **reach**, not on sensitivity:

| | Owner | Why |
|---|---|---|
| `intelligence/`, `rules/community/`, `guardianai/` | service | detection **input** — poisoning it disables protection machine-wide |
| `state/` | service | the IPC token, the log, the event feed |
| `quarantine/` | user | remediation **output**, never read to reach a verdict |
| `config/`, `logs/`, `telemetry/`, `rules/user_rules/` | user | settings, reports, FP-rate stats, user-authored rules |

Quarantine deliberately stays user-writable, and the reason that holds
regardless of the service account is that it is remediation *output*, never
detection *input*: nothing consults it to decide what is malicious. That is a
property of the code rather than a promise, so
`tests/test_privilege_boundary.py` fails if any module outside
`quarantine.py`, `scanner.py` and `paths.py` so much as names the directory.

A second reason binds only under the account this project *intends* to use.
Quarantine has to read and move files inside the interactive user profile, and
`LocalService` cannot reach those without a manual per-folder `icacls` (see
WINDOWS_SERVICE.md, *Service can't access watched folder*). The service in fact
runs as `LocalSystem`, which can — so that argument does not bind today, and
binds again the moment the account is narrowed to the documented one. Routing
quarantine through the service would then break the core action of the product
in order to protect data that is not a detection input.

**The deployed account is `LocalSystem`, not `LocalService`.** `pywin32`
installs with no account argument and that is its default; the docs and
`setup_service.bat` claimed the narrower account while granting it ACLs it
never used. Corrected in v1.16 — see WINDOWS_SERVICE.md, *Permission Setup*.
It does not weaken the boundary this section describes: the ACLs keep
`intelligence/` unwritable by unprivileged users either way, which is what the
invariant is about.

Two files moved to keep the boundary legible rather than to add structure:
`pattern_stats.sqlite` out of `intelligence/` (it is written on every scan by
the unelevated GUI, and feeds an FP-rate label, never a verdict), and
`service_events.json` out of `config/` (the process that only displays the
event feed should not be able to write it).

**GUI writes to `intelligence/` therefore route through the authenticated IPC** —
`RUN_INTEL_UPDATE` already existed; `IGNORE_HASH` / `UNIGNORE_HASH` /
`CLEAR_IGNORED` are new. `ignore_list.py` follows the same router/executor shape
`intel_updater` already uses: `add()` routes, `add_local()` executes, and the
service handler calls the executor so it cannot recurse into itself. Reads are
never routed — `Users:Read` is enough. A routed write invalidates this process's
Guardian cache, or the next scan keeps answering from the pre-write set.

**What this boundary does not stop.** The IPC token is readable by every local
user by design — the unelevated UI has to authenticate with it — so the handlers
are reachable by any process running as the user. The boundary constrains
*shape*, not *origin*: a hostile process can still request one whitelist entry,
but it can no longer corrupt the database file, drop the table, or write
arbitrary content into service-owned storage. Treat it as attack-surface
reduction, not as authentication of the caller.

### The service ships as source: only one entry point survives the compiler

**An earlier version of this section blamed pywin32. That was wrong**, and the
correction is worth keeping because the wrong answer was the plausible one.

The service links and then faults during interpreter start-up, before reaching
its own first line, in one of two ways depending on flags:

```
ImportError: cannot import name 'MappingProxyType' from 'types'   (from enum, at start-up)
Nuitka: A segmentation fault has occurred
```

pywin32 at module scope was the obvious difference between the service and the
GUI, so the first diagnosis stopped there. Then `tools/engine_probe.py` — which
imports **no pywin32 at all** — failed identically. Six builds:

| entry point | inclusion | result |
|---|---|---|
| `src/ui/app.py` (**inside** the package tree) | `--include-package=ui` | **works** |
| `tools/build_probe.py` | `--include-module=ui.core.paths` | **works** |
| `polyshield_service.py` | `--include-package=ui.core` | ImportError |
| `polyshield_service.py` | `--include-package=ui.core`, no Tk exclusions | segfault |
| `tools/engine_probe.py` | `--include-package=ui.core` | ImportError |
| `tools/engine_probe.py` | `--include-package=ui` | segfault |

What actually correlates is the **entry point's location**, not its imports.
The only script that compiles into a working binary is `src/ui/app.py`, which
lives *inside* the `ui` package it pulls in. Entry points outside that tree —
the repo root, `tools/` — fault whenever a whole package is included, and the
one that works from `tools/` includes a single module rather than a package.

Environment: Anaconda CPython 3.13.12, Nuitka 4.2, zig C backend, `PYTHONPATH`
set to `src` for the compile.

**Not pursued further.** Narrowing this to a minimal reproducer for an upstream
report is worth doing, and it is not a path-resolution question — which is what
this phase is about. The scope guard says stop and report.

**It does not block the product**, for two reasons. The GUI is the entry point
that compiles, and the service was always going to ship as source once the
first diagnosis landed — that decision stands on its own merits and its
data-root convergence is verified either way. And the diagnostics that would
otherwise have lived in `tools/` now live on the GUI entry point instead
(`PolyShield.exe --paths`, `--engines`), which is the more honest place for
them: they report what the *shipped product* resolved, not what a
differently-built probe would have.

`tools/engine_probe.py` remains as the source of the checks — `app.py` imports
`CHECKS` from it — and runs directly from a checkout. It simply cannot be
compiled into a standalone binary of its own.


**Resolution: option 1 — the service ships as source.** The distribution
carries `polyshield_service.py`, `scheduled_scan.py` and the engine-side tree
(`src/ui/core`, `src/tools`) beside the compiled GUI, run by a Python runtime
staged next to them. `ui/views` is deliberately excluded and the build asserts
its absence: the service must never need a display.

The one thing this breaks, and how it is fixed, is worth being precise about.
A source-mode service asks `is_frozen()`, gets `False`, and resolves
`app_root()` to **the directory it was installed in** — while the compiled GUI
two folders away resolves it to `%ProgramData%\PolyShield`. A service writing
detections somewhere the UI never looks is indistinguishable from a service that
found nothing, which is exactly the failure this phase exists to prevent.

So `app_root()` keys off `is_distribution()` rather than `is_frozen()`: a
compiled build always qualifies, and a source component qualifies when a
`.polyshield-distribution` marker sits beside it. Deliberately a **file** and
not an environment variable — a Windows service inherits almost nothing from
the installing user's environment, and a marker survives the service being
started by the SCM at boot, from `services.msc`, or by a developer from a shell.

Verified end to end: the staged service and the compiled build both report
`%ProgramData%\PolyShield`, while the service still reports `frozen: false`
and keeps its own `resource_root`. Data is shared; a component's own files are
not.

**Runtime is not staged by the build.** Supply a Python with `pywin32`,
`psutil` and `watchdog`; the project already keeps a portable one for the
Windows Sandbox workflow (see docs/TESTING.md). Staging it is an installer
concern rather than a compiler one.

### Verified on a clean machine (4b.5)

`tools/make_sandbox_wsb.py` generates a Windows Sandbox config that maps the
built `dist/` read-only, maps **no Python**, and runs `tools/sandbox_verify.ps1`
unattended. Results land in the one writable mapping, because everything else
in a sandbox is discarded when it closes.

That is a different thing from `PolyShield_Sandbox.wsb`, which is a
*development* sandbox: it maps the source tree, a portable Python and a pip
cache so a person can work in there. For a release check those are exactly the
four things that must be absent.

The script asserts the machine is clean before it asserts anything else — no
Python on PATH, no `PYTHONPATH` / `POLYSHIELD_DATA_DIR` / `VIRTUAL_ENV`, no
pre-existing `%ProgramData%\PolyShield`. Without that, every later result is
ambiguous: the binary might be finding a developer's interpreter.

**20 checks, 20 passed.** The ones worth naming:

* the binary reports itself frozen, and its data root is **not** inside the build
* `config/ intelligence/ logs/ quarantine/` are created on first run
* a sentinel written into `ui_settings.json` **survives a restart** — which is
  what proves the second launch read the durable location rather than
  recreating it; checking that a directory exists on the second run proves
  nothing
* nothing durable was written into the build tree
* **the source-mode service and the compiled GUI resolve the same data root**,
  on a machine where neither had ever run

`rules/` is deliberately *not* asserted. It is created when rules are
downloaded, not at start-up, so a fresh install legitimately has none — and
`yara_engine.is_available()` reports False for exactly that reason ("0 rule
file(s)"), which is the honest answer rather than a missing directory. An
earlier version of the script asserted it and failed, because the developer
checkout it was written against already had one. On a clean machine all four
engines report honestly unavailable.

The service half needs a runtime staged beside it (`build.ps1 -Runtime <dir>`,
with a Python carrying pywin32, psutil and watchdog). The build verifies the
staged runtime can import all three rather than trusting the copy — a runtime
missing pywin32 stages silently and then fails when the SCM starts the service,
which is the worst place to find out.

**Not covered here:** installing the service with the SCM. It needs elevation
and registers an auto-start service, so it is a deliberate manual step; the
sandbox is the right place to do it, being disposable.

### One variable at a time (4b.6)

Two changes, built and verified separately, because only one of them is
cosmetic.

**`--onefile` is not a size flag.** It changes runtime behaviour: the modules
are unpacked into a temporary directory that is **different on every run** and
deleted on exit. That is the case `resource_root()` was designed for and had
never actually met. Measured, from the shipped binary:

```
executable     D:\...\dist\PolyShield.exe                 <- the original, not the temp copy
resource_root  C:\Users\...\Temp\onefile_19912_..._FFX5Pi <- the extraction directory
app_root       C:\Users\...\AppData\Local\PolyShield      <- durable, outside it
```

Both of the non-obvious choices in `paths.py` earned their keep here:

* `running_executable()` prefers `__compiled__.original_argv0`, so the binary
  reports the file the user launched rather than the temporary copy that
  onefile re-executes. `sys.argv[0]` would have named the temp copy.
* `resource_root()` derives from the module tree, not from the executable's
  location. `Path(sys.executable).parent` would have returned `dist\` — beside
  the launcher, nowhere near the extracted data.

The clean-machine run was repeated against the onefile layout and passed
**20/20**, including the sentinel round-trip. That check matters more here than
it did for standalone: the extraction directory differs between the two
launches, so a settings value surviving proves the durable root is genuinely
independent of wherever the code happened to be unpacked.

**`--windows-console-mode=attach`, not `disable`.** `disable` would take stdout
with it, and this binary is also its own diagnostic tool — a support
conversation starts with `PolyShield.exe --paths` or `--engines`. `attach` gives
no console window when double-clicked and full output when run from a shell.

Size: **26 MB single file**, against a 47 MB executable inside a 105 MB folder.

**UPX is deliberately not used.** Packing an antivirus binary is a textbook
heuristic trigger — the product would spend its life being quarantined by the
competition, and by Defender on the build machine before it ever shipped. The
compression onefile already applies through `zstandard` is not a packer and
carries no such signature.

**No icon ships.** `build.ps1` picks up an `icon.ico` beside it automatically
and omits the flag when there is none, so adding branding later needs no code
change.

### Engine matrix

| Engine | Ships? | Mandatory | Detected in a frozen build by | Lives where | UI when unavailable |
|---|---|---|---|---|---|
| **K2 (kicomav)** | **No — deferred to 4b.4, see below** | No (optional since v1.6.1) | `scanner.is_available()` — `paths.k2_exe().exists()` | dev virtualenv only | Engine row reports unavailable; pipeline runs without it |
| **Guardian AI** | No — separately cloned repo | No | `guardian_engine.is_available()` | `guardianai/`, cloned by `scripts/components/setup_guardian.bat` | Guardian view offers the setup script |
| **YARA** | Yes — `yara-python` is a wheel | No | `yara_engine.is_available()` (runtime present *and* rule files exist) | compiled in; rules under `rules/` (DATA) | Engine reports no rules rather than clean |
| **ClamAV** | No — external install | No | `clamav_engine.is_available()` — `clamscan.exe` on disk | user-installed, `C:\Program Files\ClamAV` | Engine row reports unavailable |
| **Speakeasy** | **No — see below** | No | import guard in `emulate_engine` | dev virtualenv only | Sandbox/Emulate view reports it is not installed |
| **Sandboxie** | No — external install | No | `sandbox_engine` path probe | user-installed | Detonation button disabled |

### Verified in the build (4b.4)

`is_available()` is a claim, and for the subprocess engines it is a claim the
engine cannot check for itself. So the shipped binary is asked directly, and
anything claiming to be available is then asked to find something planted for
it:

```
PolyShield.exe --engines
```

Results from `dist/app.dist/PolyShield.exe`:

| Engine | Available | Detected | Detail |
|---|---|---|---|
| YARA | yes | **yes** | 1 rule file; a compiled rule matched a planted marker |
| Guardian | no | — | no `guardianai` tree; it is a separately cloned repo |
| K2 | no | — | not bundled, by decision (below) |
| ClamAV | no | — | `clamscan.exe` not found |

**YARA is the only detection engine inside the binary**, and it is verified by
detection: the probe compiles a rule at runtime and matches it against a file
planted with the marker. `--include-package=yara` is what puts it there.

The other three report **honestly unavailable**, which is the half of the
contract that matters for engines that do not ship. The gate fails only on the
combination that must never ship — available, and then detecting nothing.

ClamAV deserves a note, because it reports *available* from a checkout and
*unavailable* from the build, and that difference is correct rather than a
regression. `_find_exe()` consults the `clamav_path` setting first and then two
standard install locations. The developer checkout has that setting pointing at
a non-standard install; the build reads a fresh data root under
`%ProgramData%\PolyShield` that has no such key, and ClamAV is not at either
standard path. A fresh install has not been configured yet, and says so.

No EICAR anywhere in the probe: Defender quarantines it on write, which would
fail the gate for a reason with nothing to do with the build. The planted
samples are assembled from fragments at runtime, the same convention the test
suite uses, so the probe is not itself a pattern match.

### Why K2 does not ship in the first build

`k2.exe` is **not a standalone binary.** It is a 108 KB setuptools console-script
stub whose entire payload is:

```python
from kicomav.k2 import main
sys.exit(main())
```

It resolves the interpreter from a path baked into its header, so copying it
into a distribution accomplishes nothing. That rules out "bundle the exe" —
there is no exe to bundle.

The real obstacle is one layer down. `k2.py` locates its engines by filesystem
path (`os.path.join(k2_pwd, "plugins")`) and `k2engine.set_plugins()` loads each
of the 50 of them with

```python
SourceFileLoader(f"kicomav.plugins.{name}", plugin_path).load_module()
```

— that is, from **`.py` source files on disk**, listed in `plugins/kicom.lst`.
Nuitka compiles Python modules into the binary; it does not leave them on disk
for a runtime source loader. Shipping `plugins/` as data files alongside a
compiled `kicomav` is *possible*, but each plugin then imports from the
compiled `kicomav.kavcore`, which is precisely where mixed compiled/interpreted
imports get fragile.

What makes this worth deferring rather than attempting inside 4b.1 is the
failure mode. `set_plugins()` swallows every per-plugin load error:

```python
except (IOError, ImportError, Exception):
    ...
    pass
```

So a build where the plugins fail to load produces a K2 that starts, exits
zero, reports no threats, and is indistinguishable from a clean scan. **"The
exe launches" proves nothing here**; only an EICAR detection through the
packaged binary does.

The decision, therefore: the first distribution **ships without K2**.
`scanner.is_available()` has returned False for a missing K2 since v1.6.1 and
the pipeline already runs without it, so the app degrades honestly rather than
silently. Bundling it is a 4b.4 experiment gated on an EICAR detection test
through the packaged build — and if the plugin loader cannot be made reliable,
K2 stays out and the UI says so.

### Why Speakeasy does not ship

`speakeasy-emulator` pins `unicorn==1.0.2`, which imports `distutils.sysconfig`
and `pkg_resources` at module scope and locates its native libraries through
`pkg_resources.resource_filename()`. Both were removed from the standard library
in Python 3.12+, which is why `requirements.txt` carries a two-sided
`setuptools>=78.1.1,<82` pin whose upper bound exists solely because setuptools
82 removed `pkg_resources`.

A resource-filename lookup against a compiled package is the same class of
problem as K2's plugin loader, on top of a GPL-2.0 dependency in an MIT
application. `emulate_engine` already treats the import as optional and
`test_emulate_report.py` covers the half that matters — the report parser —
without an emulator. Speakeasy stays a source-checkout feature.

## Path Resolution (v1.15, extended v1.16)

`src/ui/core/paths.py` is the only module that decides where anything lives.
Before it, **33 sites across 26 files** each recomputed the project root from
`__file__`, in three different spellings, and nothing anywhere was aware the
code might not be running from a source checkout.

That is fine while it always is. It stops being fine the moment the app is
compiled: under a Nuitka onefile build the modules are unpacked into a
temporary directory that is deleted on exit, so every one of those sites would
have put the threat database, the quarantine, the logs and the user's settings
somewhere that does not survive the process.

The distinction the module encodes is **not** "Nuitka is weird". It is:

| | |
|---|---|
| **RESOURCE lifetime** | ships with the program, read-only, recreatable from the bundle, may live in a temporary extraction directory |
| **DATA lifetime** | created or modified by the user or the application, must survive a restart, must never live only in a temporary extraction directory |

That outlives any particular packager, which is why the API is about lifetimes
rather than about being frozen.

### The API

```python
paths.app_root()       # durable, writable   -- application data
paths.install_root()   # durable, read-only  -- where the product is installed
paths.resource_root()  # DISPOSABLE          -- the onefile extraction directory
paths.is_frozen()      # compiled build?
paths.is_distribution()  # compiled, OR shipped-as-source inside one
```

plus named accessors — `intelligence_dir()`, `quarantine_dir()`, `logs_dir()`,
`config_dir()`, `rules_dir()`, `guardian_dir()` — so a caller never has to
remember which of the two roots a directory belongs to. That is the mistake the
module exists to prevent.

### The install root is a third lifetime (v1.16)

DATA vs RESOURCE was enough while a build was a folder. `--onefile` split
RESOURCE in two, because the extraction directory is deleted on exit but the
directory the user installed into is not:

| | lifetime | writable | onefile location |
|---|---|---|---|
| `app_root()` | durable | **yes** | `%ProgramData%\PolyShield` |
| `install_root()` | durable | no | `C:\Program Files\PolyShield` |
| `resource_root()` | **disposable** | no | `%TEMP%\ONEFIL~1\` — deleted on exit |

`runtime\`, `service\` and the shipped `k2.exe` sit beside `PolyShield.exe` in
the install directory, and are reachable from neither of the other two roots.
Anything written into the Windows Task Scheduler or the registry must be built
from `install_root()`, because those commands have to still be valid months
later — long after the extraction directory is gone.

The contract is spelled out for **all four** contexts, so its meaning does not
depend on which of them happens to ship today:

| context | returns | note |
|---|---|---|
| frozen GUI | `running_executable().parent` | not `sys.executable` — that names a file which does not exist |
| frozen service | `running_executable().parent` | not shipped today; a frozen component **must sit at the install root** |
| source-mode staged service | `resource_root().parent` | its own module root is `<install>\service` |
| source checkout | `_MODULE_ROOT` | unchanged |

The staged-service row is the one worth reading twice. That component is a
*distribution* but is not *frozen*, and its interpreter is the staged
`runtime\python.exe` — so `running_executable().parent` would answer
`<install>\runtime`, one directory to the side, and would do it silently.

Verified by running both: a frozen GUI and a source-mode staged service, in
separate processes, resolve the same `install_root()`, `runtime_python()`,
`k2_exe()` and `app_root()`.

### What 4c.1 settled

Three questions `paths.py` had deliberately left open:

- **`k2_exe()`** resolved into `kicomav_env\` — a development virtualenv that no
  distribution contains. It is now `<install>\runtime\Scripts\k2.exe`. K2 is a
  setuptools console stub (a zip with a launcher prepended), so it cannot ship
  alone: it needs the `kicomav` package and an interpreter, and rides the
  runtime a distribution already carries for the service rather than shipping a
  second copy of Python.
- **`script_launch_argv()`** raised `FrozenLaunchUndecided` in any frozen build,
  which meant `scheduler.create_task()` was **dead in a shipped build** — the
  Scheduler view could not create a task at all. A scheduled scan now runs
  `<install>\runtime\python.exe <install>\service\scheduled_scan.py`, the same
  staged runtime the service uses. That is why 4b.3 needed no second executable.
- The exception is now **`StagedRuntimeMissing`**, raised only when a
  distribution genuinely has no staged runtime. `FrozenLaunchUndecided` remains
  as an alias; the condition it was named for no longer exists. `create_task()`
  catches it and returns `(False, msg)` rather than letting it propagate — its
  only caller runs on a worker thread with no handler, so a raise would leave
  the button disabled on "Saving…" forever.

`tools/build_probe.py` reports all three roots and fails the build when
`install_root()` resolves under the extraction directory, or does not exist. It
deliberately does **not** assert that `runtime\` and `service\` are present:
the probe is its own standalone binary in its own `.dist` directory, so its
install root is that directory and never contains the product layout.

`app_root()` is **deliberately not** `Path(sys.executable).parent`. A build
installed under `C:\Program Files\PolyShield` cannot write beside itself
without elevation, and PolyShield writes a threat database, a quarantine, logs
and settings on an ordinary run — so a beside-the-exe definition produces a
build that works from `dist\` and fails for every real installation. It
resolves:

1. `%POLYSHIELD_DATA_DIR%` if set — the seam for an installer, a portable
   launcher, or a deployment keeping data on another volume.
2. Any part of a distribution — compiled, or shipped-as-source beside a
   compiled component (see *The service ships as source* above):
   `%LOCALAPPDATA%\PolyShield`, writable in both portable and installed
   layouts. Keyed off `is_distribution()`, not `is_frozen()`, because the
   Windows service is a distribution component that is not compiled.
3. Source checkout: the project root, unchanged.

### Classification

| DATA | RESOURCE |
|---|---|
| `intelligence/threat_db.sqlite` | `src/` (sys.path) |
| `intelligence/nsrl_bloom.bin` | `src/ui/app.py` (launch target) |
| `intelligence/ignore_list.sqlite` | `polyshield_service.py` |
| `telemetry/pattern_stats.sqlite` | `scheduled_scan.py` |
| `intelligence/.update.lock` | `launch_ui.vbs` |
| `quarantine/` | `scripts/**.bat` |
| `logs/` | `_speakeasy_worker.py` |
| `config/ui_settings.json` (+ `.lock`) | `_svc_helper.bat` |
| `state/service_events.json` | |
| `rules/user_rules/` (user-authored) | |
| `rules/community/**` (downloaded intel) | |
| `rules/update.cfg` (written by `k2 --update`) | |
| `guardianai/data/known_bad.txt` | |

`rules/` is split rather than classified whole: `user_rules/` is the user's own
work and the community generations are downloaded intelligence, so both are
DATA even though a first-run tree ships neither.

### A third category the split does not describe

```
kicomav_env/Scripts/{k2,python,pip}.exe    the development virtualenv
guardianai/                                a separately cloned repository
```

Neither is shipped and neither is user data — they are the **development
environment**, and they do not exist in a distribution at all. `k2_exe()`,
`venv_python()`, `venv_pip()` and `guardian_dir()` resolve them anyway, and the
callers already degrade when they are absent (`scanner.is_available()` has
returned False for a missing k2 since v1.6.1). Deciding whether k2 ships, and
in what form, is an explicit **Phase 4b** decision; `paths.py` only makes the
question visible instead of scattering it across four files.

### Launch targets

Three places used to build their own `pythonw.exe` + `app.py` command line —
the Explorer context menu, the elevated relaunch in the Windows Security view,
and the launch-at-login shortcut. They now share `app_launch_argv()`, which in
a frozen build returns the running executable, because the executable *is* the
GUI.

`script_launch_argv()` covers the helper scripts (`scheduled_scan.py`, the
service) and **raises** `FrozenLaunchUndecided` in a frozen build. That is
deliberate. Returning the source command anyway would register a scheduled task
pointing at a virtualenv interpreter the distribution does not contain — a task
that fails at 02:00 some months later with nobody watching, which is the exact
failure class this work exists to prevent.

### Three modules may still derive a root themselves

`src/ui/app.py`, `polyshield_service.py`, `scheduled_scan.py` and
`src/tools/update_intelligence.py` each put the checkout on `sys.path` before
anything else runs — **the bootstrap cannot import the module that centralises
path resolution until `sys.path` can find it.** Each derives its own root for
that and only that; `tests/test_paths.py` asserts the raw root is not used
again below the `from ui.core import paths` line.

Two further exceptions are not root derivations at all:
`emulate_engine._WORKER` and `service_view`'s `_svc_helper.bat` resolve a file
**beside their own module**, which is correct in a checkout and correct in an
extraction directory. That is precisely why they are not routed through
`paths`.

## NSRL Bloom Filter (v1.7)

The NSRL known-safe dataset contains ~72 million unique hashes. Loading those into a Python `set` would consume 4–6 GB of RAM. A `ScalableBloomFilter` at 0.1% false-positive rate for 72M entries takes ~150 MB.

```
Guardian AI scan_file()
  ↓
[Bloom filter lookup]   → "definitely NOT in NSRL" → zero SQLite opens → continue checking
                         → "probably in NSRL"       → one confirming SQLite query
                             ↓
                         is_known_safe(md5) True?   → skip file (known-safe)
                                         False?     → false positive; continue checking

[Fallback — no bloom file]
  → direct is_known_safe(md5) SQLite query per file (legacy behaviour)
```

**Implementation:**
- `pybloom-live` `ScalableBloomFilter(initial_capacity, error_rate=0.001)` persisted to `intelligence/nsrl_bloom.bin`
- Bloom rebuild triggered after every NSRL import (`nsrl_bloom_stale=1` meta flag set at START of import, cleared after rebuild)
- **Atomic publication (v1.15):** the filter is built to a sibling temp file, flushed, `fsync`ed and size-checked, then moved into place with `os.replace`. A sibling rather than `tempfile.mkstemp` for the reason recorded under `_make_staging_dir` — `os.replace` carries the ACL with the file, and a hardened scratch DACL would yield a filter only the publishing account can read, which `_load_nsrl_bloom()` reports as simply "no bloom". Before this, `open(_BLOOM_PATH, "wb")` truncated a valid ~150 MB filter *before* `tofile()` wrote a byte, so a crash mid-write destroyed the old one and the only recovery was re-importing the multi-GB source file.
- **Publication order is the contract:** `import_nsrl` commits the `safe` rows → the filter is published → `nsrl_bloom_stale` is cleared **last**. This rules out both a filter advertised as current for a table it does not describe and the reverse.
- Crash-safety: on any failure the stale flag stays `1` and the previously published filter is left intact → consumers fall back to SQLite. Safe rather than merely tolerable: a stale filter can only *omit* entries, never invent them, so a miss falls through to the SQLite truth.
- Corruption recovery: `fromfile()` exception → delete `.bin`, set stale=1, return `None` (fall back to per-file SQLite)
- Startup cost: loading `.bin` takes ~2 seconds (mmap-backed read); rebuild from 72M SQLite rows takes 2–5 min (done only when stale)
- `fetchmany(10_000)` batching reduces Python/C boundary crossings ~7000× vs. single-row iteration

**Files:**
- `src/ui/core/guardian_engine.py` — `_load_nsrl_bloom()`, bloom-first lookup in `scan_file()`
- `src/tools/update_intelligence.py` — `_rebuild_nsrl_bloom()`, sets/clears `nsrl_bloom_stale` in meta table
- `intelligence/nsrl_bloom.bin` — persisted bloom filter (runtime; gitignored; rebuilt on NSRL import)

---

## Process Monitor Architecture (v1.7)

WMI-based process creation monitor. Detects new executables within ≤ poll_interval seconds; hashes them and checks the threat DB.

```
[ProcessMonitor thread]  (daemon thread, COM-initialized)
  ↓  Win32_Process __InstanceCreationEvent WITHIN 1 second
watcher.NextEvent(1000)  — 1s timeout (pywintypes.com_error = normal, loop continues)
  ↓  per new process
_fast_hash(exe_path)     → full-file MD5 (skip >100 MB; skip on PermissionError/PPL)
  ↓
session_allowlist check  → md5 in set?  → skip (user restored this file this session)
  ↓
known_bad RAM set        → O(1) lookup (loaded from SQLite at startup; empty if table > 500K)
  ↓ (if not in RAM set, or RAM set was not populated)
SQLite malicious table   → one query per process (persistent conn); returns enriched family name
  ↓ (if threat found)
alert_callback(pid, name, path, reason, level)
```

**Two execution contexts:**

| Context | When | Kill rights |
|---------|------|-------------|
| In-process (UI) | Service not running | User account — can kill most processes |
| Windows Service | Service running | LocalService — limited; AccessDenied on SYSTEM/PPL processes |

**Service-autonomous action (UI closed):**
```
_on_process_threat()
  ↓
  has_ui = bool(self._subscribers)   ← any SUBSCRIBE clients connected?
  ↓ (if no UI connected)
_autonomous_process_action(pid, exe_path, action)
  ↓
  psutil.Process(pid).kill() + children   ← AccessDenied on SYSTEM = logged, level→critical
  ↓ (if action == "kill_and_quarantine")
  time.sleep(0.15)   ← wait for kernel to release file locks
  quarantine.add_file(exe_path, threat_name=reason)
  ↓
  event["killed"] / event["quarantined"] written to service_events.json
  → UI shows banner on next open: "N threats quarantined while you were away"
```

**IPC commands (v1.7 additions):**

| Command | Direction | Description |
|---------|-----------|-------------|
| `ALLOW_HASH` | UI → Service | Add an MD5 to the session allow-list (user restored a file) |
| `START_PROCESS_MONITOR` | UI → Service | Start the process monitor (if stopped) |
| `STOP_PROCESS_MONITOR` | UI → Service | Stop the process monitor |

**Push events (v1.7 additions):**

| Event | Direction | Description |
|-------|-----------|-------------|
| `process_threat` | Service → UI | New threat detected; fields: `pid, name, path, reason, level, time, killed, quarantined` |

**`STATUS` response (updated):**
`process_monitor_running: bool` added alongside `watcher_running`.

**Known limitations:**
- ~1 s detection window (poll-based, not kernel intercept)
- LocalService cannot kill SYSTEM/PPL processes — partial kill logged, alert escalated to "critical"
- Files > 100 MB skipped entirely — binary-padding attack (malware padded to >100 MB) documented in logs at DEBUG level
- Executable may be deleted before hash completes (self-deleting installer temp) — silently skipped

**Files:**
- `src/ui/core/process_monitor.py` — `ProcessMonitor` class, WMI loop, `_fast_hash()`
- `src/ui/views/process_view.py` — Processes sidebar view (live log, Start/Stop, auto-terminate toggle)
- `polyshield_service.py` — `_start_process_monitor()`, `_on_process_threat()`, `_autonomous_process_action()`

---

## Intelligence Refresh (v1.12)

Three consumers hold intelligence in RAM and would otherwise serve stale data
until their process restarts. `tools/update_intelligence` owns a **domain-scoped**
post-update hook registry; `ui/core/intel_hooks.register_intel_consumers()` wires
them up, eagerly, once per process.

| Consumer | Domain | Refresh call | What staleness actually costs |
|---|---|---|---|
| `guardian_engine._scanner` (module singleton) | `hashes` | `reload_signatures()` → `_scanner.reload()` | No missed detections — `scan_file()` tier 3 falls back to a live `intel_db.lookup_hash()`. Cost is a SQLite round-trip per file instead of the O(1) RAM-set hit. |
| every live `ProcessMonitor` | `hashes` | `process_monitor.reload_all_known_bad()` (weak registry of live instances) | **Real blind spot.** The WMI thread opens its SQLite connection once at start-up and only if the DB already exists, so on a fresh install `con` stays `None` for the thread's life. With an empty RAM set that monitor detects nothing until the service restarts. |
| `network_monitor._ip_check_cache` | `ips` | `network_monitor.clear_ip_cache()` | **Real ~10-minute miss window.** Negative per-IP verdicts are memoised with no fallback and only swept every `_CACHE_RESET_POLLS` polls. |

YARA needs no hook — `yara_engine._compile()` re-reads the rule files on every
scan. `intel_db` queries live and caches no rows.

**Hook semantics.** A fired hook means *"local intelligence in domain D may have
changed; refresh your in-memory copy"* — never *"the feed update succeeded"*.
Each hook is isolated in its own `try/except`, so one failing reload cannot
suppress the others. Importers take `notify=`: a direct caller (Update Center
button, CLI) fires its own domain after committing; a batch updater passes
`notify=False` and fires exactly one notification phase for the union of domains
that actually changed.

### Scheduled updates (v1.12)

`ui/core/intel_updater.py` owns the refresh cycle. Three feeds are automated —
`malwarebazaar` (hashes), `c2` (ips), `yara` (rules); NSRL, ClamAV, K2 and
Speakeasy stay manual by design.

**One execution path.** `run_updates(feeds, force, owner)` holds all selection,
locking and backoff semantics. The scheduler thread, the service's
`RUN_INTEL_UPDATE` command and every UI button reach it — the UI through
`request_update()`, which decides service-vs-local so two surfaces can never
disagree about who writes.

**One writer, enforced inside the updater.** `intelligence/.update.lock` is
created `O_CREAT|O_EXCL` carrying the owner's PID *and* process creation time.
A lock is never stolen on age alone — an import can legitimately outrun any
timeout, and stealing from a live owner produces exactly the two-writer state
the design forbids:

| Lock state | Result |
|---|---|
| acquired | proceed |
| owner demonstrably alive | `already_running` |
| owner demonstrably dead (or PID recycled — creation time differs) | reclaim, retry once |
| ownership cannot be established | `already_running` (conservative) |

A maximum lock age exists only as a crash-recovery backstop for the last row.
The updater also re-checks service ownership immediately before the first write:
a caller that probed at start-up cannot close the race, because the service may
have started in between.

**Per-feed status, never a single verdict.** Each feed reports `updated`,
`unchanged`, `skipped`, `failed` or `backoff`; the batch derives
`updated`/`unchanged`/`partial`/`failed`/`skipped` from them. A feed that raises
is caught and marked failed without killing the batch.

**Freshness never advances on failure.** Both importers write their meta row in
the same transaction as the data and return before that write on every failure
path, so a timestamp means "refreshed or positively confirmed current". Backoff
state (`fail_count`, `next_retry`, `last_error`, `last_status`) lives in the
`meta` table so a service restart cannot reset the counter and hammer a failing
feed. HTTP 401/403 is classified `auth_required` and backs off further than a
transient timeout.

**Time frame.** All freshness arithmetic uses naive UTC (`_utcnow()`), matching
what the importers stamp. Mixing local time in makes ages wrong by the UTC
offset — west of UTC every fresh stamp reads as a future timestamp and clamps to
"age 0" permanently.

**YARA generations.** `download_yara_community()` publishes each download as an
immutable `rules/community/<generation>/` directory and switches to it by
replacing the `.active` pointer file — a single atomic operation on Windows.
`yara_engine.active_community_dir()` resolves it, falling back to the flat
legacy layout. This matters because `_compile()` re-reads the rule directory on
every scan: the previous implementation deleted the live rules first and
extracted one file at a time, so a scan starting in that window compiled a
partial or empty rule set. A failed or corrupt download now leaves the previous
generation live and untouched.

The staging directory is created with `os.mkdir()` (never `tempfile.mkdtemp()`,
which produces a DACL with no inherited ACEs) and its DACL is checked before the
pointer flip — otherwise a generation published by LocalService is readable only
by LocalService, and `yara_engine` reports it as "no rules" with no error. See
docs/WINDOWS_SERVICE.md for the measured ACL comparison.

---

### Intelligence posture (v1.12)

`intel_updater.get_posture()` is the single source of truth for the Dashboard
headline. It deliberately combines two different questions:

- **Freshness** — when did this feed last successfully refresh? (`get_staleness`)
- **Usability** — can the engine actually load what is on disk? (`get_usability`)

| State | Condition |
|---|---|
| `current` | every enabled feed usable and within its thresholds |
| `stale` | data exists and is usable, but a feed is past `intel_stale_days` |
| `update_required` | an enabled feed never populated, **or** has no usable data despite what its metadata says |
| `unavailable` | the intelligence store itself cannot be read |

The second half of `update_required` is the important one. Freshness metadata
describes the *download*: a YARA generation published with a non-inheriting ACL
reads as perfectly fresh while `yara_engine` reports zero rules and silently
stops contributing to scans. Usability evidence is per feed — malicious row
count, blocklist row count, compiled rule-file count — so a feed cannot report
healthy while the engine behind it has nothing to work with.

Stale intelligence degrades the headline but never claims zero protection: the
hash tiers keep working on what is already stored. The Windows security score is
left as the number it is, but the posture card's colour is clamped so a green
"92/100" cannot sit above a degraded intelligence layer.

---

### Journaling: WAL (v1.12)

`threat_db.sqlite` is opened `journal_mode=WAL` by `update_intelligence._open_db()`
(the writer side — journal mode is a persistent property of the file, so one write
connection converts it and every later reader inherits it).

Measured, not assumed: under the previous rollback journal a COMMIT needs an
EXCLUSIVE lock, so a *reader* holding an open read transaction blocks the writer —
the commit fails with `database is locked` once `busy_timeout` expires. That is
exactly the v1.12 access pattern (service updating in the background while the UI
holds one of `intel_db`'s long-lived per-thread connections). Under WAL the same
commit lands in ~1 ms. The reverse direction was never the problem: a write
transaction only holds RESERVED, which readers may cross.

Trade-off accepted: under WAL every process that *reads* the DB also needs write
permission on `intelligence/` for the `-wal`/`-shm` sidecars.

---

## Behavioral Analysis Architecture

### Speakeasy (Stage 4) — Subprocess Design

Speakeasy uses `unicorn-engine` (C library) for x86/x64 CPU emulation. Unicorn fires Python hook callbacks from C code on every emulated API call. Each hook re-acquires the Python GIL — if run in a thread, this starves the CustomTkinter main thread and freezes the UI.

**Fix (v1.5+):** Speakeasy runs in a completely separate subprocess (`_speakeasy_worker.py`), which has its own GIL. The main process remains fully responsive throughout emulation.

```
UI "Run Trace" click
  ↓
emulate_engine.emulate_async(path, on_done)
  ↓  [background thread — waits, doesn't block UI]
subprocess.Popen([sys.executable, "_speakeasy_worker.py", path, mode])
  ↓  [separate Python process — own GIL, unicorn runs here]
se.load_module(path) → se.run_module(module) → se.get_report()
  → stdout: {"ok": true, "report": {...}}
  ↓  [background thread parses JSON, calls on_done]
on_done(EmulationReport) → self.after(0, _on_emulation_done, report)
  ↓  [main thread updates UI]
```

Timeout: 90 seconds (configurable via `_TIMEOUT` in `emulate_engine.py`). On timeout, subprocess is killed and a clean error message is displayed.

### Sandboxie-Plus (Stage 5)

Runs the file in an isolated "glass box" via `sandbox_engine.py`. Supports both system-wide and portable installs. Uses `KicomHunter` sandbox box name. Wipe Sandbox deletes all sandboxed content after detonation.

---

## Performance Characteristics

### Intelligence Database Size

| Source | Size | Entries | Loading Time | RAM Cost |
|--------|------|---------|--------------|----------|
| **MalwareBazaar Recent (24h)** | ~20 KB | 500–1000 | <100ms | <1 MB |
| **MalwareBazaar Full** | 100–200 MB | 200,000–500,000 | 5–15 sec | 200–500 MB |
| **NSRL Safe Hashes** | N/A (SQLite) | 200M+ | Indexed, no load | Index overhead |
| **C2 IP Blocklist** | ~50 KB | ~400–600 | <50ms | Negligible |

### Scan Speed Impact (Rough Estimates)

**With Recent 24h data:**
- 10,000 files → 2–5 seconds Guardian overhead (RAM lookups + patterns dominant)
- Total scan time (k2 + Guardian): ~25–50 seconds

**With Full MalwareBazaar data:**
- 10,000 files → 5–15 seconds Guardian overhead (more SQLite hits)
- + minimal startup overhead (hashes loaded from SQLite, not flat file; large DBs skip RAM entirely)
- Total scan time (k2 + Guardian): ~35–75 seconds

### Bottlenecks

1. **Full database RAM load** — Large lists (200MB+) load into RAM at Guardian scan start → startup delay
2. **Per-file NSRL lookups** — 10K files = 10K SQLite queries (O(log n) each, still adds up). **v1.7:** Bloom filter front-end eliminates SQLite opens for the ~99.9% of files definitively not in NSRL.
3. **Heuristic patterns** — 7 regexes per file; fast individually but not free at scale
4. **Speakeasy emulation** — 5–30 seconds per file; subprocess isolation prevents UI freeze
5. **NSRL Bloom rebuild** — 2–5 minutes for 72M rows (only on first import and after import updates; progress shown in Update Center)

### Guardian AI Performance Toggles

Both in **Settings → Guardian AI**:

- **NSRL Allow-List Check** (default ON) — Skip per-file NSRL SQLite query to save ~1–5ms/file; trade-off: loses known-safe detection
- **Heuristic Patterns** (default ON) — Skip the 7 regex patterns to save ~1ms/file; trade-off: loses pattern-based zero-day detection

---

## Database Schema

### `intelligence/threat_db.sqlite`

```sql
CREATE TABLE malicious (
    hash TEXT PRIMARY KEY,
    hash_type TEXT,           -- 'md5'
    malware_family TEXT,      -- e.g., 'Emotet', 'LockBit'
    detection_count INTEGER,  -- how many AV engines flagged it
    trust_score INTEGER,      -- 0=malicious, 100=clean (unused here)
    source TEXT,              -- 'malwarebazaar'
    first_seen TEXT           -- ISO date
);

CREATE TABLE safe (
    hash TEXT PRIMARY KEY,
    hash_type TEXT,           -- 'md5'
    source TEXT,              -- 'nsrl'
    product TEXT,             -- Windows, Office, etc.
    added_at TEXT             -- ISO date
);

CREATE TABLE meta (
    key TEXT PRIMARY KEY,
    value TEXT                -- e.g., last_mb_update = "2026-05-13T..."
                              --       nsrl_bloom_stale = "0" | "1"
                              --       (1 = bloom needs rebuild after NSRL import)
);

CREATE TABLE ip_blocklist (
    ip TEXT PRIMARY KEY,
    tags TEXT NOT NULL DEFAULT '',    -- malware family tags (e.g., 'Emotet', 'AsyncRAT')
    port INTEGER NOT NULL DEFAULT 0,  -- C2 port (0 if unknown / port-agnostic block)
    malware TEXT NOT NULL DEFAULT '', -- malware name from feed
    added_ts TEXT NOT NULL DEFAULT '' -- ISO timestamp when imported
);
-- ip_blocklist populated by:
--   Update Center "C2 Blocklist" card (Feodo Tracker + ThreatFox feeds)
--   AND immediately when user clicks "Block" on a flagged network connection
```

### Related Files

| Path | Role |
|------|------|
| `intelligence/threat_db.sqlite` | Main database (SQLite; 100MB+ if full MalwareBazaar imported) |
| `guardianai/data/known_bad.txt` | Legacy fallback only (v1.8+); no longer auto-written after updates; used only if `threat_db.sqlite` is absent |
| `C:\ProgramData\PolyShield\service.log` | Windows Service runtime log |
| `state/service_events.json` | Persisted threat events from the service (atomic writes) |

### Clearing the Database

To switch from full → recent:
1. **Update Center** → **Local Intelligence DB** → **"🗑 Clear DB"**
2. Confirm deletion (clears `malicious` table; leaves NSRL intact)
3. Click **"↓ MalwareBazaar Recent (24h)"**

---

## File Structure

```
KicomAI_Project\
├── src\                         # All Python source
│   ├── ui\
│   │   ├── app.py               # App entry point, sidebar nav, --scan argv, service watcher guard
│   │   ├── core\                # Backend logic — no UI widgets
│   │   │   ├── scanner.py           # Wraps k2.exe; ScanController (pause/resume/cancel via NtSuspendProcess); is_available()
│   │   │   ├── proc_pause.py        # Shared NtSuspendProcess helper: suspend_pid(), resume_pid(), watch_pause_event()
│   │   │   ├── guardian_engine.py   # Guardian AI four-tier scanner; _EnhancedScanner
│   │   │   ├── emulate_engine.py    # Speakeasy subprocess wrapper; EmulationReport dataclass
│   │   │   ├── _speakeasy_worker.py # Isolated subprocess worker (own GIL, prevents UI freeze)
│   │   │   ├── sandbox_engine.py    # Sandboxie-Plus detonation wrapper
│   │   │   ├── defender.py          # Windows Defender integration; is_mpcmdrun_available(), scan_paths_async() (dir-level MpCmdRun + threat-history diff)
│   │   │   ├── win_security.py      # Windows Security data (registry-first, PowerShell fallback)
│   │   │   ├── network_monitor.py   # psutil TCP monitor; C2/unsigned-outbound flagging; IP+PID caches
│   │   │   ├── process_monitor.py   # WMI __InstanceCreationEvent; ProcessMonitor class; _fast_hash()
│   │   │   ├── shell_ext.py         # Explorer "Scan with PolyShield" context menu (HKCU, no admin)
│   │   │   ├── quarantine.py        # Move / restore infected files
│   │   │   ├── settings.py          # User preferences (JSON-backed flat config)
│   │   │   ├── dispute.py           # Find k2 vs Guardian disagreements
│   │   │   ├── virustotal.py        # VirusTotal API v3 lookups
│   │   │   ├── yara_engine.py       # YARA rules engine (yara-python; rules\user_rules\ + rules\community\)
│   │   │   ├── clamav_engine.py     # ClamAV engine (clamscan.exe --file-list batch; cancel_event mid-proc terminate)
│   │   │   ├── service_client.py    # IPC client — talks to service on 127.0.0.1:52614
│   │   │   ├── watcher.py           # Watchdog filesystem monitor
│   │   │   ├── scheduler.py         # Windows Task Scheduler wrapper (schtasks)
│   │   │   ├── scan_presets.py      # Smart/Quick/Full/Downloads/Temp path resolution; Smart uses targeted risk dirs (browser extensions, PowerShell profiles, WindowsApps) instead of broad AppData pass
│   │   │   └── startup_scanner.py   # Enumerate startup items (registry + startup folder)
│   │   └── views\               # CTkFrame subclasses — one per sidebar item
│   │       ├── scan_view.py         # Scan UI: collapsible Pipeline panel, sequential engine queue, cancel-and-keep, Threat Actions, D&D pipeline reorder, user-defined path presets
│   │       ├── guardian_view.py     # Guardian AI panel
│   │       ├── behavioral_view.py   # Sandbox/Emulate (Speakeasy + Sandboxie)
│   │       ├── winsec_view.py       # Windows Security supplement + composite score
│   │       ├── network_view.py      # Network monitor (live connections, alert feed, block button)
│   │       ├── process_view.py      # Process Monitor (live event log, Start/Stop, auto-terminate toggle)
│   │       ├── update_view.py       # Update center (6 independent sources)
│   │       ├── service_view.py      # Windows Service management + live event feed
│   │       ├── watcher_view.py      # Folder watchlist + new-file callbacks
│   │       ├── defender_view.py     # Defender start/stop + real-time protection
│   │       ├── dispute_popup.py     # k2 vs Guardian disagreement modal
│   │       ├── quarantine_view.py   # Quarantine manager (multi-select + bulk actions)
│   │       ├── virustotal_view.py   # VT hash/file lookup + drag-and-drop
│   │       ├── history_view.py      # Scan report history (JSON logs)
│   │       ├── scheduler_view.py    # Scheduled scan jobs
│   │       ├── dashboard_view.py    # Dashboard + Security Posture card
│   │       └── settings_view.py     # All user preferences
│   └── tools\
│       └── update_intelligence.py   # MalwareBazaar + NSRL + C2 blocklist import
├── scripts\
│   ├── install.bat                  # One-click fresh install
│   ├── manage.bat                   # Component manager (install/update/diagnostics)
│   ├── setup_guardian.bat           # Guardian AI setup
│   ├── setup_speakeasy.bat          # Speakeasy setup
│   ├── setup_service.bat            # Windows Service installer (self-elevating)
│   ├── add_defender_exclusions.ps1  # Targeted Defender exclusions (Speakeasy, YARA, k2)
│   ├── launch_ui.bat                # Console launcher (dev/debug)
│   └── sandbox-auto-setup.bat       # Sandbox fresh-install script (runs inside Windows Sandbox)
├── docs\
│   ├── ARCHITECTURE.md              # This file — technical deep-dive
│   ├── WINDOWS_SERVICE.md           # Service implementation, IPC protocol, war story
│   └── TESTING.md                   # Testing guide and battlespace tests
├── rules\
│   ├── user_rules\              # Drop .yar files here; YARA engine auto-discovers
│   └── community\               # Downloaded by Update Center (YARA Forge core pack); version in .version
├── intelligence\                # Runtime — created by Update Center
│   ├── threat_db.sqlite
│   └── nsrl_bloom.bin           # ScalableBloomFilter (~150 MB); rebuilt after each NSRL import
├── guardianai\                  # Cloned from GitHub by scripts\components\setup_guardian.bat
│   └── data\
│       └── known_bad.txt        # legacy fallback (v1.8: primary source is SQLite)
├── logs\                        # Scan reports (JSON, timestamped)
├── quarantine\                  # Quarantined files + metadata
├── kicomav_env\                 # Main venv (Python 3.11+, all packages)
├── guardian_env\                # Guardian AI venv
├── config\
│   ├── .env                     # Machine-specific paths (generated by scripts\install.bat)
│   ├── .env.template            # Template committed to source
│   ├── ui_settings.json         # User preferences (per-machine, not committed)
│   └── service_events.json      # Persisted service events
├── polyshield_service.py           # Windows Service class (pywin32, socket IPC, watcher host)
├── scheduled_scan.py            # Invoked by Windows Task Scheduler
├── launch_ui.vbs                # No-console app launcher (rewritten by admin toggle)
├── launch_guardian.vbs          # Standalone Guardian AI launcher
├── requirements.txt             # Package list
├── README.md                    # User-facing documentation
└── CLAUDE.md                    # AI assistant project instructions
```

---

## Key Patterns

### Threading Model

Every long-running operation follows this pattern:

```python
def _start_something(self):
    self._busy = True
    self._btn.configure(state="disabled")

    def _run():
        result = do_work()           # background thread — can block
        if self.winfo_exists():
            self.after(0, self._on_done, result)   # marshal back to main thread

    threading.Thread(target=_run, daemon=True).start()

def _on_done(self, result):
    self._busy = False
    self._btn.configure(state="normal")
```

**Never** call `widget.configure(dict)` via `self.after` — CustomTkinter only accepts `**kwargs`, not a positional dict. Use a lambda closure:

```python
# BROKEN — silently does nothing
self.after(0, self._lbl.configure, {"text": value})

# CORRECT
self.after(0, lambda v=value: self._lbl.configure(text=v))
```

### Subprocess Pattern (No Console Flash)

Every `subprocess.Popen` / `subprocess.run` call **must** include:

```python
creationflags=subprocess.CREATE_NO_WINDOW  # 0x08000000
```

Forgetting this causes visible console windows on Windows. Enforced in: `scanner.py`, `defender.py`, `win_security.py`, `scheduler.py`, `emulate_engine.py`, `update_view.py`.

### GIL-Intensive Libraries → Subprocess

Libraries that call Python callbacks from C (unicorn, some YARA internals) should run in a **subprocess**, not a thread, to avoid GIL starvation of the main thread. Pattern established in `emulate_engine.py` + `_speakeasy_worker.py`.

### ScanController Pause/Cancel

Uses `ctypes.windll.ntdll.NtSuspendProcess` / `NtResumeProcess` — Unix `SIGSTOP` is not available on Windows. `cancel()` always resumes first if paused; killing a suspended Windows process is unreliable without resuming first.
