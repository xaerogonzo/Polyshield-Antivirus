# PolyShield — Testing Guide

Procedures for verifying that PolyShield is working correctly — from basic sanity checks to stress tests for the service IPC plumbing.

For feature descriptions, see [USAGE.md](USAGE.md). For a project overview, see [README.md](../README.md).  
For architecture and internals, see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Quick Sanity Check (5 minutes)

After install or any significant code change, run these before anything else:

1. **UI launches** — Double-click `launch_ui.vbs` → app opens, no Python error window
2. **Scan works** — Scan view → Smart → Start Scan → completes, shows results
3. **Guardian AI** — Enable "Guardian AI second opinion" checkbox, re-scan → dual results shown
4. **Update Center** — Click "↓ MalwareBazaar Recent (24h)" → completes without error
5. **EICAR file** — Create a file containing exactly:
   ```
   X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
   ```
   Save as `eicar.com` and scan it → k2 should flag it as a virus
6. **Quarantine All** — After any scan that finds threats, confirm the "Quarantine All (N)" button appears in the Threat Actions panel header and successfully quarantines all items
7. **Pause indicator** — Start a scan, click ⏸ Pause → amber "⏸ PAUSED" label should appear next to the progress bar; click ▶ Resume → label disappears
8. **Getting Started card** — On a fresh install (or with `getting_started_dismissed` set to `false` in `config/ui_settings.json`), open Dashboard → the 🚀 Getting Started card should appear with incomplete steps shown; clicking a `→` button navigates to the correct view; Dismiss hides it permanently
9. **VT Test Key** — Settings → VirusTotal → paste a valid API key → click **Test Key** → should show "✓ Key valid" in green within ~5 seconds; try an invalid key → should show "✗ Invalid key (unauthorized)" in red

---

## Automated Test Suite (pytest)

```powershell
kicomav_env\Scripts\pip.exe install -r requirements-dev.txt
kicomav_env\Scripts\python.exe -m pytest
```

Tests live in `tests/` and are hermetic: `conftest.py` redirects every consumer's
`_DB_PATH` at a temp `threat_db.sqlite` built from the real `_SCHEMA`, so no test
touches the live ~146 MB intelligence database, and the post-update hook registry
is emptied between tests.

The suite is split by concern:

| File | Covers |
|---|---|
| `test_intel_hooks.py` | New intelligence reaching *already running* consumers without reconstructing them |
| `test_intel_updater.py` | The updater core — cross-process lock ownership, per-feed status, backoff, freshness, YARA publishing, posture |
| `test_service_intel.py` | Service IPC dispatch, the worker handoff, client wrappers, and the UI launch-time fallback |
| `test_dashboard_intel_card.py` | What the Dashboard actually renders (see *GUI tests without a screen* below) |
| `test_guardian_tiers.py` | The verdict ladder — every tier, profile gating, the circuit breaker, and live reload on the production singleton (v1.13) |
| `test_quarantine.py` | Capture, listing, restore, delete — including the two refusal cases that protect user data (v1.13) |
| `test_ignore_list.py` | The false-positive whitelist and its in-process cache (v1.13) |
| `test_pattern_stats.py` | Per-pattern telemetry and the FP-rate arithmetic behind the Settings display (v1.13) |
| `test_dispute.py` | K2-vs-Guardian disagreement detection (v1.13) |
| `test_scan_pipeline.py` | Engine queue construction and ordering, cancellation, finalize idempotence, pause/stop coordination, and the module-level log/ETA/path helpers (v1.13) |
| `test_threat_actions.py` | What the panel shows after a scan — result collection, severity, reason buckets, every filter chip and display mode, plus one end-to-end Guardian→UI contract test (v1.13) |
| `test_settings.py` | Settings persistence — the locked read-merge-replace, cross-process key preservation, the failure contract, and corruption recovery (v1.13) |
| `test_scan_control.py` | `ScanController`'s state machine, intent recorded before the k2 process exists, the two cancellation races, and the shared pause/resume helper (v1.13) |
| `test_scan_presets.py` | What a Smart/Quick/Full scan actually resolves to on disk (v1.13) |
| `test_process_monitor.py` | The verdict ladder of the component that kills processes, the allow-list/reload ordering, and stop() not lying about whether it stopped (v1.13) |
| `test_network_monitor.py` | Private-range policy, PID-reuse attribution, connection flagging tiers, and the IP verdict cache (v1.13) |
| `test_watcher.py` | Real-time engine verdicts surviving any completion order, and the completion contract that decides when observers see them (v1.13) |

### Isolating module-global state (v1.13)

Redirecting `_DB_PATH` is only half of hermeticity. The detection path also
keeps a scanner singleton, a hook registry, and a lazily-populated hash cache,
and a suite can leave every production *file* untouched while still polluting
all three.

The worked example: `guardian_engine.scan_async()`'s worker calls
`register_intel_hooks()` as a fallback, so *any* test touching the async
Guardian path registers `reload_signatures` into the real hook registry. A
later test that never asked for the `hooks` fixture then inherits a live
callback pointing at an earlier test's scanner.

Two autouse fixtures in `conftest.py` handle this:

- `_restore_global_state` — snapshots and **restores** `_post_update_hooks`,
  both registration latches, `guardian_engine._scanner`, and
  `ignore_list._cache` around every test. Restore rather than clear, because
  `test_intel_hooks.py` registers hooks on purpose.
- `_assert_session_leaves_no_trace` — asserts at session teardown that all of
  the above came back, and that no non-daemon thread outlived the run. The
  per-test fixture is the mechanism; this is the proof it worked.

What the session guard does **not** check is pending Tk `after` callbacks.
CustomTkinter schedules its own internally, so an assertion of "none pending"
would fail for reasons unrelated to any test. Thread leaks are checked;
scheduled callbacks are not.

The opt-in sandboxes are `guardian_sandbox` (the scanner's construction-time
reads: `_DATA_DIR`, `_KNOWN_BAD_TXT`, `_BLOOM_PATH`), `ignore_db`,
`pattern_db`, and `quarantine_sandbox`. `net_sandbox` empties the two network caches -- both are process-global and
both decide verdicts, so a test inheriting either is reading a previous test's
conclusions. `settings_file` is the odd one
out: `settings_sandbox` replaces `set_value()` outright, which is what most
tests want, so the tests *of* `set_value()` need the real functions pointed at
a temp file instead. It redirects the lock sidecar too — left at the real path,
a test would contend with a running PolyShield for the user's settings lock. Note `ignore_db` depends on
`pattern_db`: `ignore_list.add()` forwards a `"Suspicious pattern:"` reason to
telemetry, so whether a test touches the stats DB depends on a string argument
rather than on anything visible in its fixture list.

### The settings concurrency contract (v1.13)

`config/ui_settings.json` is written by two processes: the UI, and the service
via `SET_CONFIG` and `watcher.start()/stop()`. `set_value()` is the persistence
primitive and performs, under an OS-owned cross-process lock:

    re-read the file  ->  merge the one changed key  ->  atomic replace

Re-reading inside the lock is what makes concurrent writers preserve each
other's keys. **Atomic replacement alone does not** — it protects the file from
a torn write, not the read-merge-replace transaction. Without the lock this
interleaving silently loses `a=2`, which is what the code did before v1.13:

    A: read {a:1,b:1}            B: read {a:1,b:1}
    A: write {a:2,b:1}           B: write {a:1,b:2}

The lock is a byte-range lock on a **sidecar** (`ui_settings.json.lock`), for
two reasons that are both load-bearing: it is owned by the OS handle so a
crashed process releases it automatically (a PID-in-a-lockfile convention
leaves settings permanently locked after one crash), and it is not on the
target file because Windows refuses `os.replace()` over a file with an open
handle.

`set_value()` returns `SAVE_OK` / `SAVE_DEGRADED` / `SAVE_FAILED` rather than
raising. All 73 call sites are bare calls inside Tk event handlers — including
slider `command=` callbacks that fire on every drag tick — so an exception would
land in Tk's dispatcher per tick. **`SAVE_DEGRADED` is a named exception to the
guarantee:** the bounded lock wait timed out and a single best-effort write was
made, outside the lost-update contract. A test must never treat it as `SAVE_OK`.

What the suite cannot prove: that this holds across a real process boundary.
That needs two processes — change a setting in the UI, send `SET_CONFIG` for a
different key through `service_client`, and confirm both survive.

### Two races that were probed rather than assumed (v1.13)

The plan for this arc listed both as "fix only if a test confirms it". They
did not come out the same way, and the difference is worth recording so the
next reader does not re-litigate either one.

**`network_monitor._poll_count += 1` — not fixed.** It is a read-modify-write
outside `_ip_cache_lock`, while the cache clear it guards is inside. It looks
like a lost-update race. It does not reproduce: eight threads x 5000
increments, five trials, with `sys.setswitchinterval(1e-6)` forcing preemption,
lost zero increments on a GIL build. The consequence if it ever did occur is
also negligible — the periodic cache sweep would happen one poll later, and the
case that actually matters (a fresh C2 import) is handled by an explicit
`clear_ip_cache()` from the "ips" post-update hook, not by the counter. Left
alone deliberately. A free-threaded build would change this analysis.

**`ProcessMonitor.stop()` — fixed.** This one reproduces immediately. With a
watch loop that ignores `_stop_evt` (standing in for a hung
`GetObject("winmgmts:")`), `stop()` returned after its 5 s join, cleared
`_thread` regardless of the outcome, and `is_running()` then reported `False`
while the thread was still alive and still able to fire `alert_callback`. For
the one component that terminates processes, "I turned it off" must not be
able to lie. The handle is now dropped only on a successful join, and
`_STOP_JOIN_TIMEOUT_S` exists as a constant so the test can shrink it.

### The watcher callback contract (v1.13)

A registered detection callback means **scan complete**, not "file detected".
Specifically it:

- fires once per detected file, after every engine that was actually launched
  has reported
- receives the final entry, with `entry["verdicts"]` carrying one
  `{engine, infected, reason, status}` record per launched engine and
  `entry["status"]` as the derived summary
- **runs on a scan worker thread**, not the watchdog observer thread, so it
  must be thread-safe

That is a behaviour change. Callbacks used to fire from `on_created` straight
after `scan_callback` returned -- but `scan_new_file()` ends in `run_scan()`,
which returns before k2 has even started, so every observer saw `"pending"`.
The Windows Service had the same bug one level up: it read
`entry.get("status")` on the line after calling `scan_new_file`, and persisted
`"pending"` into `config/service_events.json` for essentially every real-time
detection. It now passes an `on_complete` callback instead.

`entry["verdicts"]` includes clean results deliberately. Without them a
consumer cannot tell *ran and found nothing* from *was never launched* from
*failed to produce a result* -- and an engine failure that reads as clean is
the worst of the three.

The status reduction keeps producing the strings the three existing consumers
already understand, plus one new one:

| Condition | Status |
|---|---|
| k2 flagged it | `threat found` |
| a secondary engine flagged it | `suspicious (<Engine>)`, fixed precedence |
| every launched engine completed cleanly | `clean` |
| nothing detected, but an engine errored | `incomplete (<Engine> error)` |
| the barrier is still open | `pending` |

The new string needs no UI change: both renderers colour on `"threat" in
status` and `status == "clean"` and print anything else verbatim, so
`incomplete (...)` renders amber -- which is the right signal for "did not
finish". The load-bearing half is that `clean` is the only string earning the
green all-clear, so it is reserved for runs where every launched engine
actually completed.

### The Tk root has to load tkdnd, but must stay a CTk

`ScanView._build()` registers a drop target, and the tkdnd Tcl package is
loaded by the **root**, not by the `tkinterdnd2` import. Without it the view
raises `TclError` before it finishes building — so both `conftest.py`'s
`tk_root` and `uishot`'s `TkSession` call `TkinterDnD._require(root)` after
creating an ordinary `ctk.CTk()`.

The tempting shortcut is to swap the root for `TkinterDnD.Tk`, which is what
`app.py` does for `App`. Don't: that class is exactly `tkinter.Tk` plus the
same `_require()` call, the DnD methods are already mixed into every widget at
import, and a raw `tkinter.Tk` root loses CustomTkinter's themed background.
Measured cost when tried: every existing golden drifted about 24%, and the new
captures rendered on light grey.

### Detection payloads are assembled at runtime

`test_guardian_tiers.py` builds its pattern-matching samples from string
fragments via a `_payload()` helper rather than writing them as literals. What
Guardian's regexes match is, by construction, what a real-time AV matches too:
Defender flagged an earlier draft of that file as `Trojan:Win32/ClickFix` on
the strength of one `mshta` line, and CI runs on a Defender-enabled Windows
runner where a quarantined test file is a red build for reasons unrelated to
the code. Do not collapse those fragments back into single literals.

**Rule for live-reload tests:** assert through the same public path production
uses — `scanner.scan_file()`, `monitor._check_process()`, `is_known_bad_ip()` —
never by inspecting `virus_db`, `_known_bad`, or the IP cache directly. Internal
state can look right while the real decision path still returns "clean". Each
test also asserts the *stale* state before firing the hook, so it fails if the
scenario stops being a genuine regression.

Guardian's tier-3 SQLite fallback masks a stale RAM set, so its test disables
that fallback (`lookup_hash` → `None`) to isolate the tier-2 RAM path.

### GUI tests without a screen

`test_dashboard_intel_card.py` builds a **withdrawn** Tk root and reads the
rendered widgets back — label text, colours, grid rows. No visible window, no
mouse, no focus stealing, and nothing on the developer's desktop. It checks what
a screenshot would show, but deterministically.

Two things to know before adding more:

- The Tk root fixture is **session-scoped on purpose**. Creating and destroying
  a CTk root per test tears down Tcl's library state, and the next root then
  fails with `invalid command name "tcl_findLibrary"` — which shows up as an
  intermittent *skip*, i.e. a test quietly protecting nothing. Build a fresh
  *view* per test on the shared root instead.
- Drive widgets through Tk, not the mouse: `button.invoke()`,
  `widget.event_generate(...)`, or call the handler directly. That is how the
  `_status_cb` crash and the blank auto-update label were caught before either
  reached a running app.

### Time frame in tests

All freshness arithmetic runs in **naive UTC** (`intel_updater._utcnow()`),
matching what the importers stamp. Using `datetime.now()` in a test passes on a
UTC machine and fails everywhere else — that mismatch was a real bug, not a
hypothetical one.

### What still needs a live service

Three things the suite cannot prove on its own, because they depend on the
LocalService account and the real filesystem:

1. That the service can write `intelligence/threat_db.sqlite` at all.
2. That artefacts it publishes are readable by the interactive user — see the
   `tempfile.mkdtemp` ACL gotcha in [WINDOWS_SERVICE.md](WINDOWS_SERVICE.md).
3. That `SvcStop` completes promptly while an update is in flight.

Run them by starting the service, sending `RUN_INTEL_UPDATE` through
`service_client`, and reading `C:\ProgramData\PolyShield\service.log`. Take a
copy of `intelligence/` and `rules/community/` first — the first live run of
this feature is what surfaced the ACL bug, and having a byte-exact backup is
what made recovery trivial.

---

## Battlespace Tests

These tests verify the *plumbing* — IPC concurrency, network detection logic, and service recovery — not just whether the scanners work. Run these before declaring a build stable.

### Test 1 — "EICAR Sprint" (IPC Concurrency Stress Test)

**What it tests:** Whether the Windows Service's `_push_event()` system handles rapid-fire simultaneous events without dropping events, overlapping UI notifications, or crashing.

**Why it matters:** The watcher calls `scan_new_file()` once per filesystem event. If 50 files land at once, 50 scan threads compete for the service socket simultaneously.

**Setup:**
1. Start the Windows Service (`manage.bat` → option 6 → Start)
2. Navigate to **Service** sidebar → verify "Running" status
3. Add a folder to the watcher (e.g., a temp folder on Desktop)
4. Create the batch script below and run it:

```batch
@echo off
rem Drops 50 EICAR files into a watched folder simultaneously
rem EICAR is a harmless 68-byte test file — every AV flags it, no actual malware
set FOLDER=C:\Users\%USERNAME%\Desktop\eicar_test
mkdir %FOLDER% 2>nul
for /L %%i in (1,1,50) do (
    echo X5O!P%%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H* > %FOLDER%\eicar_%%i.com
)
echo Done — 50 EICAR files created in %FOLDER%
```

**What to look for:**
- [ ] Service view live event feed populates with detections (may take a few seconds)
- [ ] No "Service Disconnected" error in the UI
- [ ] No Python crash dialog or traceback
- [ ] All (or most) 50 files appear as events — no silent drops
- [ ] UI remains responsive throughout

**Clean up:** Delete the `eicar_test` folder and remove it from the watcher list.

---

### Test 2 — "Ghost Connection" (Network Detection Logic)

**What it tests:** Whether the Network Monitor actually detects and displays flagged connections in real-time, and whether the Block button creates a real firewall rule.

**Why it matters:** It's easy to write a monitor that shows connections but doesn't actually check the blocklist. This test confirms the full path: IP in DB → connection flagged → block rule created.

**Setup:**
1. Open SQLite directly (or use the Python snippet below) and temporarily add a harmless, well-known IP to the blocklist:

```python
# Run this in kicomav_env — adds Google DNS to ip_blocklist temporarily
import sqlite3
from pathlib import Path

db = Path("intelligence/threat_db.sqlite")
con = sqlite3.connect(str(db))
con.execute("""INSERT OR REPLACE INTO ip_blocklist
               (ip, tags, port, malware, added_ts)
               VALUES ('8.8.8.8', 'test', 53, 'GoogleDNS-TEST', datetime('now'))""")
con.commit()
con.close()
print("Added 8.8.8.8 to ip_blocklist")
```

2. Open a browser and visit any website (browser will likely contact Google DNS)
3. Navigate to **Network** sidebar in PolyShield and click **↺ Refresh**

**What to look for:**
- [ ] `8.8.8.8` row appears with amber/red background and "c2:test" status
- [ ] The process name column shows your browser (or `svchost.exe` for system DNS)
- [ ] **Block** button is present on the flagged row
- [ ] Click **Block** → UAC prompt appears
- [ ] After approving: confirm rule exists:
  ```powershell
  Get-NetFirewallRule | Where-Object { $_.DisplayName -like "PolyShield*" }
  ```

**Clean up:**
```python
# Remove the test entry
con = sqlite3.connect(str(db))
con.execute("DELETE FROM ip_blocklist WHERE ip = '8.8.8.8'")
con.commit()
con.close()
# Remove the firewall rule (elevated PowerShell):
# Remove-NetFirewallRule -DisplayName "PolyShield-Block-8.8.8.8"
```

---

### Test 3 — "Service Recovery" (Resilience Test)

**What it tests:** Whether the UI handles a service process crash gracefully and can reconnect without requiring `setup_service.bat` to be re-run.

**Why it matters:** Windows services can "ghost" — appear running in SCM but be unresponsive. The UI should detect this and offer recovery, not hang indefinitely.

**Setup:**
1. Start the service and verify it's running in the **Service** sidebar view
2. Open **Task Manager** → Details tab → find the `python.exe` process associated with the service
   - Tip: sort by CPU — it will be the one periodically using a small amount
   - Or: `tasklist /fi "services eq PolyShield"` in an elevated prompt to get the PID
3. Right-click the process → **End Task** (this kills the service mid-run)

**What to look for:**
- [ ] Service sidebar changes from "Running" to "Stopped" or shows a connection error
- [ ] No Python exception dialog or uncaught exception in the UI
- [ ] The **Start** button in Service view becomes available
- [ ] Clicking **Start** restarts the service successfully (no need for `setup_service.bat`)
- [ ] After restart, live event feed resumes in the Service view

**What acceptable degradation looks like:**
- Brief "Service Disconnected" / "Connection refused" message in the status bar — OK
- The app continuing to function for scan, guardian, quarantine, etc. — expected (service is optional)
- Automatic reconnect attempt within ~10 seconds if the service restarts — ideal

---

### Test 4 — "Process Monitor Kill Chain" (WMI Detection → Kill → Quarantine)

**What it tests:** Whether the ProcessMonitor's WMI subscription fires, whether `_check_process()` correctly identifies a threat, and whether the kill + quarantine autonomous action works when no UI subscriber is connected.

**Why it matters:** The WMI path is entirely separate from the k2/Guardian scan pipeline. A file can be clean on disk but flagged when executed — this tests that execution-time detection works end-to-end.

**Understanding EICAR vs hash-lookup (important nuance):**

EICAR (`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`) is perfect for testing the **Watcher → k2 scan** path because every AV engine has a signature for it. However, ProcessMonitor does *hash lookup against MalwareBazaar* — and EICAR is a test file, not malware, so its MD5 (`44d88612fea8a8f36de82e1278abb02f`) is typically not in the MalwareBazaar dataset. Two approaches depending on what you need to test:

| What you want to test | Method |
|-----------------------|--------|
| Watcher file-creation detection + k2 scan | Drop an EICAR file into a watched folder |
| ProcessMonitor WMI subscription is firing at all | Enable `process_monitor_show_clean` in Settings; launch any .exe; confirm it appears in the Processes view log |
| ProcessMonitor hash-check path specifically | Insert EICAR MD5 into `malicious` table manually (see below), then run the test, then clean up |

**Setup — Watcher path (EICAR):**
1. Add a folder to the Watcher (e.g., `C:\Users\%USERNAME%\Desktop\watch_test`)
2. Enable "Auto-quarantine" in Watcher settings
3. Open a text editor, paste the EICAR string, save as `test_malware.exe` inside the watched folder

**What to look for:**
- [ ] Watcher view shows a new detection entry within ~2 seconds
- [ ] Status shows "threat found" (k2 flagged it)
- [ ] If auto-quarantine enabled: file disappears from disk, appears in Quarantine view

**Setup — ProcessMonitor hash-check path (manual DB injection):**
```python
# Run in kicomav_env — adds EICAR MD5 to malicious table temporarily
import sqlite3
from pathlib import Path

db = Path("intelligence/threat_db.sqlite")
con = sqlite3.connect(str(db))
con.execute("""INSERT OR IGNORE INTO malicious (hash, hash_type, malware_family, source)
               VALUES ('44d88612fea8a8f36de82e1278abb02f', 'md5', 'EICAR-Test', 'manual_test')""")
con.commit()
con.close()
print("EICAR MD5 added to malicious table")
```

Then reload signatures in the Guardian view (or restart the service / in-process monitor), and try to execute the EICAR `.exe`:

**What to look for:**
- [ ] Within ≤ poll_interval seconds (default: 1s), a "Threat Detected" alert banner appears in the Processes view
- [ ] If the service is running with no UI subscriber: process is killed + file quarantined autonomously
- [ ] `C:\ProgramData\PolyShield\service.log` shows: `THREAT PID=... name=test_malware.exe reason=known malicious hash`

**Clean up:**
```python
con = sqlite3.connect(str(db))
con.execute("DELETE FROM malicious WHERE source='manual_test'")
con.commit()
con.close()
```

**Testing WMI subscription restart (Bug 8 fix):**

To verify the subscription auto-recovers after WMI drops it (no longer silently dies):
1. Start the service or in-process monitor
2. In an elevated prompt: `net stop winmgmt && net start winmgmt`
3. Wait ~10 seconds
4. Launch any `.exe` — it should still appear in the Processes log
5. Check the service log for: `WMI subscription dropped — restarting in 5 s`

---

## Windows Sandbox Testing

For isolated testing without risking the host system. Uses Windows Sandbox (Hyper-V based, built into Windows Pro/Enterprise).

### Prerequisites (one-time)

Files that live outside the main project (you choose the locations and document them in your `PolyShield_Sandbox.wsb` — see `PolyShield_Sandbox.wsb.template` for placeholders):

| Folder | Purpose |
|--------|---------|
| Embedded Python (e.g. `python_embed/`) | Portable Python 3.12 |
| Pip cache (e.g. `pip_cache/`) | Pip cache (persists across sandbox runs) |

### Every-Run Workflow

1. **Double-click `PolyShield_Sandbox.wsb`** (copy from `.template` and fill in the paths first) — sandbox opens; project mapped read-only at `C:\PolyShield_Project`
2. **Right-click `sandbox-auto-setup.bat` → Run as administrator**
   - Copies source files to `C:\PolyShield_Sandbox` (skips venvs, generated dirs, `.env`)
   - Builds a fresh venv with sandbox paths
   - Installs all packages (uses `C:\pip_cache` — fast after first run)
   - Generates a clean `.env` and launches PolyShield automatically
3. **Test as needed** — nothing touches the host
4. **Close sandbox** — all changes discarded, host unchanged

### Timing

| Run | Duration | Why |
|-----|----------|-----|
| First ever | ~5 min | Downloads all packages (~200 MB) |
| Subsequent | ~2 min | pip cache hit |

### What's Safe to Test in Sandbox

| Test | Safe? |
|------|-------|
| Scan local files, Guardian AI, quarantine/restore | ✅ Safe |
| Settings changes, watcher, Defender integration | ✅ Safe |
| EICAR test file | ✅ Safe |
| Battlespace Test 1 (EICAR Sprint) | ✅ Safe |
| Battlespace Test 2 (Ghost Connection) | ✅ Safe — no real harm to sandbox |

### What Requires a Full Isolated VM (not just Sandbox)

| Test | Why |
|------|-----|
| Real malware samples | Use Hyper-V VM with a snapshot — always snapshot before detonating anything real |
| Speakeasy emulation of suspicious files | Runs code — fine in Sandbox actually, but need to verify |
| Sandboxie-Plus detonation | Requires VT-x passthrough — doesn't work in Windows Sandbox |
| Service recovery test (Test 3) | Needs to kill the service process — possible in Sandbox |
| Full reinstall field test | Needs a clean machine state (no Python, no venv) — see VM Field Testing section |
| ProcessMonitor kill chain (Test 4) | WMI autonomous kill + quarantine; need to test service persistence after UI closes |

### Picking Up Code Changes

Source files are **copied fresh** every time `sandbox-auto-setup.bat` runs. Changes to `ui/`, `tools/`, batch files, etc. are automatically picked up on the next run.

---

## VM Field Testing

For testing the full installation experience — especially on a fresh machine — Windows Sandbox is too ephemeral and too limited (no Sandboxie, no kernel-level service testing). A proper VM is the right tool.

### Choosing a Windows 11 VM Image

Modern Windows 11 is built for SSDs. Running it on an HDD in a VM will peg the disk at 100% constantly due to telemetry, Windows Update, Search indexing, and background app activity. Two options for a lightweight, HDD-friendly test environment:

#### Option A — Tiny11 (Community De-bloat, Recommended for Disposable VMs)

Tiny11 is built by a PowerShell script ([ntdevlabs/tiny11builder](https://github.com/ntdevlabs/tiny11builder)) that you run against a genuine Windows 11 ISO — it accepts **any edition** (Home, Pro, Education, Enterprise) and outputs a stripped ISO that installs in ~8 GB and runs on 2 GB RAM with minimal background HDD activity. The real Windows 11 kernel is preserved, so WMI, services, UAC, and registry all behave identically to a full install.

There are two variants: **Regular** (keeps Defender + Windows Update — use this for standard PolyShield testing) and **Core** (removes Defender entirely — co-pilot tests and `defender_view.py` will not work; only use Core if you specifically want to test PolyShield as the sole scanner).

**For complete setup instructions** — building the ISO, local account bypass, HDD optimizations, activation, snapshot strategy, and VM specs — see **[VM_SETUP.md](VM_SETUP.md)**.

The project includes `scripts\vm_setup\build_tiny11_vm.bat` — double-click it to build. A folder-picker dialog lets you choose where to save the output ISO.
```powershell
# Or from an elevated PowerShell prompt:
.\scripts\vm_setup\build_tiny11_vm.ps1 -ISODrive D -ScratchDrive E
```

After your VM is set up and you have a clean snapshot, follow the **Full Reinstall Field Test Checklist** below.

#### Option B — Windows 11 IoT Enterprise LTSC (Official Clean-Room)

LTSC is Microsoft's official edition for industrial/embedded use — zero bloatware, no feature updates, fully activatable. Use it when you need a "real" end-user environment for final validation before distribution, or when Tiny11's community provenance is a concern. Requires a VLSC/MSDN subscription or a free evaluation ISO from Microsoft.

The HDD optimizations in [VM_SETUP.md](VM_SETUP.md) apply here too and are strongly recommended before installing PolyShield.

### Full Reinstall Field Test Checklist

This is the primary test to run before declaring a build ready. The goal is to simulate a new user's first experience on a clean machine.

**Starting state:** Fresh VM, no PolyShield ever installed, no Python, no venv.

- [ ] **Python install** — Download Python 3.11+ installer; check "Add to PATH"; install
- [ ] **Copy project** — Copy the project folder to the VM (USB, shared folder, or zip)
- [ ] **`scripts\install.bat`** — Double-click; watch all 7 steps complete without error
- [ ] **`launch_ui.vbs`** — App opens; no Python console flash; no import errors
- [ ] **Getting Started card** — Dashboard shows 🚀 Getting Started card with all 3 items unchecked (no DB, no service, no scan history)
- [ ] **Update Center** — Run "↓ MalwareBazaar Recent (24h)"; DB populates; Getting Started card item 1 auto-checks on next Dashboard visit
- [ ] **Service install** — `scripts\service\setup_service.bat` (run as admin); service starts; Service view shows Running; Getting Started card item 2 auto-checks
- [ ] **First scan** — Scan view → Smart Scan → completes; Getting Started card item 3 auto-checks; card auto-dismisses
- [ ] **Watcher EICAR test** — See Battlespace Test 1 above — confirms watcher + k2 pipeline
- [ ] **Process view** — Enable `process_monitor_show_clean` in Settings; launch Notepad; it should appear in the Processes view log within ~1 second
- [ ] **Quarantine** — Quarantine view shows any threats found; Restore and Re-quarantine work; multi-select bulk operations work
- [ ] **Guardian AI setup** (optional) — `scripts\manage.bat` → option 2; run dual scan; dispute modal appears if k2 and Guardian disagree
- [ ] **Service recovery** — See Battlespace Test 3 above

**On HDD specifically, watch for:**
- Scan speed — expected to be slower than SSD; normal
- "100% disk" in Task Manager during update downloads — normal; if it persists after updates finish, investigate background services (Tiny11 should not do this)
- Service log growing large — confirm `_EVENTS_CAP = 2000` trim is working after a long test run

### EICAR: The Standard "Fake Virus"

The EICAR Standard Anti-Virus Test File is a legitimate 68-byte text file developed by the European Institute for Computer Antivirus Research. It is **not malware**. Its only purpose is to trigger a detection response from AV software — every legitimate engine including k2, Defender, and ClamAV has a built-in signature for it.

```
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```

**Key facts for testing:**
- It's a valid DOS COM program — you can save it as `.exe` or `.com` and "run" it (it prints "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" and exits)
- Its MD5 is `44d88612fea8a8f36de82e1278abb02f` — this is what k2 and Defender match on
- MalwareBazaar may or may not include it (it's a test file, not actual malware) — see Test 4 above for how to handle this for ProcessMonitor testing
- Safe to use anywhere, including on your host machine — no payload

**What it tests vs what it doesn't:**

| Scenario | Tested by EICAR? |
|----------|-----------------|
| k2 signature scan flags it | ✅ Yes — k2 has built-in EICAR signature |
| Watcher detects file creation + scans it | ✅ Yes |
| Guardian AI hash DB flags it | ❌ No — not in MalwareBazaar typically |
| ProcessMonitor WMI subscription fires | ✅ Yes — fires on any process launch |
| ProcessMonitor hash-check flags it | ❌ No — MD5 not in MalwareBazaar; requires DB injection (see Test 4) |
| Defender detection | ✅ Yes (if Defender is active) |

---

## Distribution Signing (Future — Pre-Release)

When distributing PolyShield as an executable, unsigned binaries acting as Windows Services that monitor network connections and files will trigger SmartScreen and Defender false positives. Two options:

**Option A — EV Code Signing Certificate (~$400/year)**
- Immediately trusted by SmartScreen on all Windows machines
- Required for kernel drivers (WFP, etc.) if we ever go that route
- Necessary for broad public distribution

**Option B — Self-signed "PolyShield Root CA" (development/personal use)**
- Add your own root certificate to `HKLM\ROOT\Certificates`
- Sign executables with that cert
- Stops your own machine from fighting the code, but won't help on other machines
- Useful for internal VM deployments or controlled lab environments
- Does NOT satisfy SmartScreen for new users

**Nuitka compiled build** — also relevant here; see [USAGE.md — Nuitka Compiled Build](USAGE.md#nuitka-compiled-build-planned-post-feature-freeze).

---

## Service Log Inspection

The service writes to `C:\ProgramData\PolyShield\service.log`. After long UI sessions, check for:

```
# Show last 50 lines of service log (PowerShell)
Get-Content "C:\ProgramData\PolyShield\service.log" -Tail 50
```

**Common entries and what they mean:**

| Log entry | Meaning |
|-----------|---------|
| `[INFO] Client connected` | UI connected to service socket |
| `[INFO] SUBSCRIBE registered` | UI subscribed to event push stream |
| `[INFO] network_event pushed` | Network monitor found flagged connection |
| `[WARNING] Socket timeout` | A client held a connection open too long — expected if UI was open for hours |
| `[ERROR] Connection reset` | UI process crashed or was killed mid-connection — service recovers automatically |
| `[INFO] NetworkMonitorThread started` | Network monitor polling thread is running |

**Socket timeouts after long sessions:** The SUBSCRIBE connection is a persistent socket. If the UI is open for many hours, OS-level TCP keepalive may time it out. The `service_client.py` reconnects with exponential backoff — this is expected behavior, not a bug.
