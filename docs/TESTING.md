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
