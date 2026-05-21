# PolyShield — Architecture Reference

Technical deep-dive: detection layers, scan pipeline, engine design, performance characteristics, database schema, and file structure.

For setup and usage, see [USAGE.md](USAGE.md). For a project overview, see [README.md](../README.md).  
For service internals and IPC protocol, see [WINDOWS_SERVICE.md](WINDOWS_SERVICE.md).  
For testing procedures, see [TESTING.md](TESTING.md).

---

## Detection Layers

### Four Layers (Cumulative by Version)

**1. KicomAV Engine (k2.exe)**
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

[1. K2 Engine]    — toggleable; proprietary signature DB via k2.exe subprocess
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
[NetworkMonitorThread]  (runs inside kicomai_service.py)
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
- Crash-safety: if `tofile()` crashes mid-write, stale flag stays `1` → bloom not loaded until rebuilt
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
- `kicomai_service.py` — `_start_process_monitor()`, `_on_process_threat()`, `_autonomous_process_action()`

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
| `C:\ProgramData\KicomAI\service.log` | Windows Service runtime log |
| `config/service_events.json` | Persisted threat events from the service (atomic writes) |

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
│   │   │   ├── shell_ext.py         # Explorer "Scan with KicomAV" context menu (HKCU, no admin)
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
├── kicomai_service.py           # Windows Service class (pywin32, socket IPC, watcher host)
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
