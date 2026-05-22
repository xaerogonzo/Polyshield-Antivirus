# PolyShield Realtime Protection — Windows Service

**Added in v1.3.** Technical deep-dive into the Windows Service implementation: what it is, why it was hard, what we did, and how to reproduce it on a new machine.

---

## What It Does

The folder watcher (`ui/core/watcher.py`) runs inside the UI process by default. When you close PolyShield, monitoring stops. Professional AV tools solve this with a **Windows Service** — a background process that starts at boot and keeps running regardless of whether any user is logged in or the UI is open.

`polyshield_service.py` implements `PolyShield Realtime Protection` as a proper Windows Service using `pywin32`. When the service is running:

- Folder monitoring continues 24/7, even after you close the UI
- **Process creation monitoring** runs in the background — every new executable is hashed and checked within ≤1 second; threats are killed + quarantined autonomously when the UI is closed
- Threat events are persisted to `config/service_events.json` so they survive UI restarts
- The UI connects to the service over a local socket and receives push notifications the instant a file or process is flagged
- The "Service" sidebar view shows live status, uptime, and a real-time event feed

When the service is **not** installed, the UI falls back to the existing in-process watcher and in-process process monitor (both stop when the UI closes).

---

## Architecture Overview

### IPC: Localhost TCP Socket

The UI and service communicate over `127.0.0.1:52614` using **newline-delimited JSON**. The UI is the client; the service is the server.

```
PolyShield ──(TCP 127.0.0.1:52614)──► PolyShield Service
             {"cmd": "PING", "token": "..."}
             ◄── {"ok": true, "msg": "PONG"}

             {"cmd": "SUBSCRIBE", "token": "..."}
             ◄── {"ok": true}
             ◄── {"event": "scan_result", "id": 7, "filename": "evil.exe", ...}
             ◄── {"event": "heartbeat"}   ← every 30s
```

**Why TCP over named pipes / COM / WCF:** Simple, language-agnostic, no registry COM registration, works across Python versions, easy to debug with raw sockets.

### Protocol Commands

| Command | Direction | Description |
|---------|-----------|-------------|
| `PING` | UI → Service | Liveness check (500ms timeout) |
| `STATUS` | UI → Service | Uptime, watcher state, process_monitor_running, event count |
| `START_WATCHER` | UI → Service | Tell service to start folder monitoring |
| `STOP_WATCHER` | UI → Service | Tell service to stop monitoring |
| `GET_EVENTS` | UI → Service | Fetch all (or since_id) scan + process threat events |
| `CLEAR_EVENTS` | UI → Service | Wipe event log |
| `SET_CONFIG` | UI → Service | Push a settings change (folders list, etc.) |
| `SUBSCRIBE` | UI → Service | Upgrade to push-event stream (stays open) |
| `GET_NETWORK_EVENTS` | UI → Service | Fetch last N network alert events (ring buffer, cap 100) |
| `BLOCK_IP` | UI → Service | Add a firewall outbound block rule for an IP |
| `ALLOW_HASH` | UI → Service | Add an MD5 to the session process-monitor allow-list (user restored a file) |
| `START_PROCESS_MONITOR` | UI → Service | Start the WMI process creation monitor (if stopped) |
| `STOP_PROCESS_MONITOR` | UI → Service | Stop the WMI process creation monitor |

**Push events (server → all SUBSCRIBE clients):**

| Event type | Trigger | Key fields |
|------------|---------|------------|
| `scan_result` | File flagged by watcher scan | `id, path, filename, time, status, source` |
| `watcher_status` | Watcher started or stopped | `running: bool` |
| `network_event` | New C2 / unsigned-outbound connection | `connections, alerts` |
| `heartbeat` | Every 30 s (keepalive) | — |
| `process_threat` | WMI process creation monitor found a threat | `pid, name, path, reason, level, time, killed, quarantined` |

### Token Authentication

Port 52614 is reachable by any process on the machine — including malware. Every command carries a `"token"` field. The service generates a UUID4 token at first start and writes it to `C:\ProgramData\PolyShield\service_token.txt`. Any command with the wrong or missing token gets `{"ok": false, "error": "unauthorized"}` and the connection is dropped.

**Token file ACLs** (set by `setup_service.bat`):
- `SYSTEM`: Full Control
- `NT AUTHORITY\LocalService`: Modify
- `Administrators`: Full Control
- `Users`: **Read only** (can read the token to authenticate, cannot overwrite it)

This prevents malware running in user context from replacing the token and impersonating the service client.

### Push Event Stream

Instead of polling every few seconds, the UI sends `SUBSCRIBE` and the service **pushes** events the instant a scan completes. The connection stays open with:
- **30-second heartbeats** to detect dead connections
- **Zombie cleanup**: every `sendall()` to subscribers is wrapped in `try/except OSError` — on any failure the subscriber is immediately removed
- **Exponential backoff reconnect** on the UI side: 1s → 2s → 4s → ... → 30s cap, indefinitely

### Atomic Event Persistence

Events are saved to `config/service_events.json` using the write-to-temp + `os.replace()` pattern:

```python
tmp = EVENTS_FILE.with_suffix(".tmp")
tmp.write_text(json.dumps(events, indent=2), encoding="utf-8")
os.replace(tmp, EVENTS_FILE)
```

A power cut or crash during the write leaves at worst a `.tmp` file. The original is never partially overwritten.

---

## The Critical Debugging Discovery

### The Problem: `pythonservice.exe` and Virtual Environments

When you use `pywin32` with a **virtual environment** on Python 3.11+, the default service binary `pythonservice.exe` **does not work**. Here's what happens:

1. `python polyshield_service.py install` registers the service with the SCM
2. When started, the SCM launches `pythonservice.exe` — a precompiled C binary included with pywin32
3. `pythonservice.exe` loads `python3XX.dll` and imports the service module
4. **But it never calls `__init__`**. The class is loaded, `SvcDoRun` is never reached.
5. After 30 seconds, Windows kills it with **Error 1053: The service did not respond to the start or control request in a timely fashion.**

The Event Log shows `PolyShieldService` starting then stopping with no Python error — because no Python code ran to produce an error.

We confirmed this by adding a trace file write at module import time (before any class definition):

```python
# Test: does this module even load?
with open(r"C:\ProgramData\PolyShield\trace.txt", "w") as f:
    f.write("module loaded\n")
```

The trace file was created. But a trace write **inside `__init__`** was never created. The module loads; the service class is never instantiated.

### Root Cause

`pythonservice.exe` was designed for system-wide Python installs. With a venv, `site-packages\win32` isn't on the path that `pythonservice.exe` uses to find `servicemanager.pyd`, and even when the path is patched, the C-level service dispatch loop doesn't properly hand off to the Python class inside a venv context.

This affects Python 3.11+ and is a known issue with pywin32 in virtualenvs.

### The Fix: `_exe_name_ = sys.executable`

`pywin32`'s `ServiceFramework` has a class attribute `_exe_name_` that controls which executable the SCM is told to run. The fix is to override it with `sys.executable` — the **actual `python.exe`** from the venv:

```python
class PolyShieldService(win32serviceutil.ServiceFramework):
    _svc_name_         = "PolyShieldService"
    _svc_display_name_ = "PolyShield Realtime Protection"
    _exe_name_  = sys.executable                              # ← THE FIX
    _exe_args_  = f'"{Path(__file__).resolve()}"'             # pass script path
```

When `_exe_name_` is set, `HandleCommandLine`/`InstallService` tells the SCM:
```
ImagePath = "D:\...\kicomav_env\Scripts\python.exe" "D:\...\polyshield_service.py"
```

The SCM then launches `python.exe` directly — with the full venv context — rather than `pythonservice.exe`. Python executes the script from `__main__`, which reaches the `if len(sys.argv) == 1:` branch (SCM passes no args):

```python
if __name__ == "__main__":
    if len(sys.argv) == 1:
        # Started by SCM — use modern entry point
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(PolyShieldService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        # Started manually (install, remove, start, stop, debug)
        win32serviceutil.HandleCommandLine(PolyShieldService)
```

This is the **modern pywin32 venv-compatible service entry point**. After this fix, `sc query PolyShieldService` shows `STATE: 4 RUNNING` immediately.

### DLL Registration (pywin32_postinstall)

Even with `_exe_name_` fixed, one more step is required. `pywin32` ships `pywintypes3XX.dll` and `pythoncom3XX.dll` inside the venv. The Windows Service host process needs these DLLs **before** Python can load anything. They must be copied to `C:\Windows\System32` so the loader finds them.

This is done by running (elevated):
```
kicomav_env\Scripts\python.exe -m pywin32_postinstall -install
```

Without this: `Error 1053` or `ModuleNotFoundError: No module named 'servicemanager'` in the service log.  
After this: DLLs appear in `C:\Windows\System32\pywintypes313.dll` (or equivalent version).

---

## Permission Setup (Why LocalService Needs icacls)

The service runs as `NT AUTHORITY\LocalService` — a heavily restricted account by design. It cannot read files in `C:\Users\<you>\Downloads` or write anywhere outside its own service-specific locations without explicit grants.

We need it to:
- Read `config/ui_settings.json` (watched folders list)
- Write `config/service_events.json` (threat event log)
- Write to `quarantine/` (if auto-quarantine is enabled)
- Write `C:\ProgramData\PolyShield\service.log` (service log)
- Write `C:\ProgramData\PolyShield\service_token.txt` (token file)

`setup_service.bat` applies the following (all in one script, elevated):

```batch
REM Shared data directory: SYSTEM+Admins = Full, LocalService = Modify, Users = Read
icacls "C:\ProgramData\PolyShield" ^
    /grant "SYSTEM:(OI)(CI)F" ^
    /grant "NT AUTHORITY\LocalService:(OI)(CI)M" ^
    /grant "Administrators:(OI)(CI)F" ^
    /grant "Users:(OI)(CI)R" ^
    /inheritance:r

REM Project root: LocalService can read config and write event log
icacls "<project root>" /grant "NT AUTHORITY\LocalService:(OI)(CI)M"

REM Quarantine folder: LocalService can write; do NOT deny Users read/list —
REM the UI (running as the logged-in user) must be able to list the directory.
REM Preventing accidental execution of quarantined files is handled by the
REM quarantine module itself (files are stored without their original extension).
icacls "<project root>\quarantine" ^
    /grant "NT AUTHORITY\LocalService:(OI)(CI)M"
```

**`(OI)(CI)`** = Object Inherit + Container Inherit — applies to the folder and all files/subfolders inside it.  
**`/inheritance:r`** on `C:\ProgramData\PolyShield` = remove inherited permissions, use only explicit ones.

---

## Files Involved

| File | Role | Category |
|------|------|----------|
| `polyshield_service.py` | Windows Service class, socket server, watcher + network + process monitor host | ✅ Source |
| `ui/core/service_client.py` | IPC client (UI → service), reconnect loop | ✅ Source |
| `ui/core/process_monitor.py` | WMI process creation monitor — `ProcessMonitor` class | ✅ Source |
| `ui/views/service_view.py` | Service management UI (install, start, stop, live events) | ✅ Source |
| `ui/views/process_view.py` | Process Monitor view (live event log, Start/Stop, auto-terminate toggle) | ✅ Source |
| `scripts\service\setup_service.bat` | One-click installer for the service (8 steps, including Defender exclusions) | ✅ Source |
| `WINDOWS_SERVICE.md` | This document | ✅ Source |
| `C:\ProgramData\PolyShield\` | Service data dir (log, token) — created at install | 📦 Installer |
| `C:\ProgramData\PolyShield\service_token.txt` | Shared secret token (UUID4) | 📦 Installer |
| `C:\ProgramData\PolyShield\service.log` | Service log (created by service on first run) | 🔄 Runtime |
| `config/service_events.json` | Persisted scan + process threat events (atomic writes) | 🔄 Runtime |

---

## Reproducing from Scratch (New Machine / VM)

### Prerequisites

Same as the main `scripts\install.bat` requirements, plus:
- **Windows 10/11 Pro or Enterprise** — Windows Home can run services but the SCM UI is limited
- **Administrator account** — `scripts\service\setup_service.bat` must run elevated (it self-elevates via UAC)
- `scripts\install.bat` must have completed successfully first (kicomav_env must exist)

### Step-by-Step

1. Run `scripts\install.bat` as normal (creates venv, installs packages, downloads signatures)

2. Double-click **`scripts\service\setup_service.bat`** — UAC prompt will appear. Accept it. The script runs 8 steps:
   - Verifies `kicomav_env` exists
   - Checks/installs `pywin32>=307`
   - Registers pywin32 DLLs in `System32` (`pywin32_postinstall`)
   - **Registers Defender exclusions** for `kicomav_env\`, `python.exe`, and `pythonw.exe` (prevents exit code 1067 crash)
   - Creates `C:\ProgramData\PolyShield\` with correct ACLs
   - Grants `NT AUTHORITY\LocalService` access to the project root and quarantine folder
   - Installs the service with the SCM
   - Starts the service

3. Verify: `sc query PolyShieldService` in an elevated prompt — should show `STATE: 4 RUNNING`

4. Launch PolyShield → click **Service** in the sidebar — status card should show `● RUNNING`

### Manual Verification

```powershell
# Check service state
sc query PolyShieldService

# Probe the socket directly (Python)
python -c "
import socket, json
s = socket.create_connection(('127.0.0.1', 52614), timeout=2)
token = open(r'C:\ProgramData\PolyShield\service_token.txt').read().strip()
s.sendall(json.dumps({'cmd': 'PING', 'token': token}).encode() + b'\n')
print(s.recv(4096))
"

# View service log
type "C:\ProgramData\PolyShield\service.log"

# View Event Log entries
eventvwr  # → Windows Logs → System, Source: PolyShieldService
```

### Uninstalling

```batch
scripts\service\setup_service.bat /remove
```

Or from `scripts\manage.bat` → option [6] Windows Service → Uninstall.

---

## Process Monitor Dual-Mode (v1.7)

The `ProcessView` follows the same dual-mode pattern as the Watcher:

| Condition | Mode | Badge text |
|-----------|------|-----------|
| `svc.is_service_running()` returns `True` | Service mode — monitor managed by service | `● Active` (service owns it; Start/Stop are advisory) |
| Service not running | In-process mode | `● Active` or `● Stopped` (direct control) |

In **service mode**, the process monitor starts automatically at service boot alongside the watcher and network monitor. `START_PROCESS_MONITOR` / `STOP_PROCESS_MONITOR` IPC commands control it without a service restart.

The `app.py` startup guard mirrors the watcher guard — prevents a duplicate in-process monitor when the service is already running:

```python
if not _svc.is_service_running():
    from ui.core.process_monitor import ProcessMonitor
    self._process_monitor = ProcessMonitor(
        alert_callback=self._on_process_threat,
        poll_interval=int(cfg.get("process_monitor_poll_interval") or 1),
    )
    self._process_monitor.start()
```

**`ALLOW_HASH` flow (restore → allow-list):**
```
User clicks "Restore" in Quarantine view
  → UI service_client.send_command({"cmd": "ALLOW_HASH", "md5": "..."})
  → service._proc_monitor.allow_hash(md5)
  → md5 added to session_allowlist (set)
  → next time that process is created: _check_process() returns early — no re-kill
```

---

## Watcher Dual-Mode

The `WatcherView` automatically detects which mode is active:

| Condition | Mode | Badge text |
|-----------|------|-----------|
| `svc.is_service_running()` returns `True` | Service mode | `● Service mode — watcher managed by PolyShield Service` |
| Service not running | In-process mode | `● In-process mode — watcher stops when UI closes` |

In **service mode**:
- Start/Stop buttons send `START_WATCHER`/`STOP_WATCHER` to the service instead of calling `wtch.start()/stop()` directly
- Detection log loads from `svc.get_events()` instead of the in-process `wtch.get_log()`
- Clear log sends `CLEAR_EVENTS` to the service

Clicking the mode badge navigates directly to the Service view.

The `ui/app.py` startup guard also prevents a double-watcher situation:

```python
if cfg.get("watcher_enabled") and cfg.get("watcher_folders"):
    from ui.core import service_client as _svc
    from ui.views.watcher_view import _on_new_file_detected
    if not _svc.is_service_running():
        wtch.start(_on_new_file_detected)   # fallback only
```

---

## Troubleshooting

### Exit code 1067 — service terminates immediately, no log entry

**Symptoms:**
- `sc query PolyShieldService` shows `WIN32_EXIT_CODE: 1067 (0x42b)` right after a start attempt
- `C:\ProgramData\PolyShield\service.log` has **no new entries** since the last successful run
- Windows Application Event Log shows `python.exe` crashing in `ntdll.dll` with exception code `0xc0000006` (`STATUS_IN_PAGE_ERROR`)
- The crash record may also reference error `0xC000026E` (`STATUS_VOLUME_DISMOUNTED`)

**Root cause:**  
A Windows Defender signature update can cause Defender to intercept the memory-mapping of `python.exe` when the SCM (running as `LocalSystem`) loads it during service start. The interception occurs at the OS page-fault handler level — inside `ntdll.dll`, before any Python code runs and before logging is set up. The crash is not caused by any PolyShield code.

This does not happen in an interactive session (user launches python.exe directly) because Defender applies different trust levels to user-session vs. service/SYSTEM-context process loads.

**Fix:**  
Add `python.exe` and `pythonw.exe` as Defender **process exclusions** (not just path exclusions). Process exclusions tell Defender not to intercept binary loads for the specified executables:

```powershell
# Run from an elevated PowerShell prompt
$root = "D:\path\to\KicomAI_Project"   # replace with actual path
Add-MpPreference -ExclusionProcess "$root\kicomav_env\Scripts\python.exe"
Add-MpPreference -ExclusionProcess "$root\kicomav_env\Scripts\pythonw.exe"
Add-MpPreference -ExclusionPath    "$root\kicomav_env"
```

Or run `scripts\service\fix_service_crash.bat` as Administrator — it applies the exclusions and immediately starts the service.

**Prevention (automatic on new installs):**  
`scripts\service\setup_service.bat` (step 4/8) and `scripts\install.bat` (step 5b) now register these exclusions automatically during install. `scripts\components\add_defender_exclusions.ps1` also applies them when run manually.

**Why not just exclude the whole project folder?**  
The `quarantine\` directory must remain Defender-monitored — it is a last line of defense. Excluding the entire project would leave quarantined malware invisible to Defender.

---

### `Error 1053: Service did not respond to start or control request`

Most common causes, in order:

1. **`pywin32_postinstall` not run** — DLLs not in System32. Fix: run `scripts\service\setup_service.bat` (it does this in step 3).

2. **Wrong service binary** — SCM is launching `pythonservice.exe` instead of `python.exe`. Check:
   ```
   sc qc PolyShieldService
   ```
   `BINARY_PATH_NAME` should start with `python.exe`, not `pythonservice.exe`. If it shows `pythonservice.exe`, uninstall and reinstall: the `_exe_name_ = sys.executable` attribute wasn't present.

3. **Module import error inside service** — Check `C:\ProgramData\PolyShield\service.log` and Event Viewer → System for Python tracebacks.

### Service starts but socket won't connect

- Check the log: `type "C:\ProgramData\PolyShield\service.log"` — look for "Socket bound" or any bind error
- Port 52614 may be taken: `netstat -ano | findstr 52614`
- Firewall blocking loopback (rare): Windows Firewall should allow `127.0.0.1` by default

### `unauthorized` on every command

The token file was regenerated (or doesn't exist yet). Restart the UI — it reads the token fresh from disk on every command.

### Service can't access watched folder / quarantine

LocalService doesn't have access to the folder. For watched folders added **after** service install, you need to grant access manually (or re-run `scripts\service\setup_service.bat` which re-applies the project root grant):

```batch
icacls "C:\Users\you\Downloads" /grant "NT AUTHORITY\LocalService:(OI)(CI)M"
```

### Event Viewer shows `PolyShieldService` error 1064

A Python exception propagated to `SvcDoRun`. Look at `service.log` for the traceback.

---

## Security Notes

- The service listens on `127.0.0.1` only — not reachable from the network
- The shared secret token prevents other local processes from sending commands without the token file
- `NT AUTHORITY\LocalService` is the minimum required privilege level — we do not use `LocalSystem`
- Quarantine folder grants `LocalService` write access; the UI (running as the logged-in user) retains read/list access. Do **not** add `deny Users:(RX)` — it blocks the quarantine view in the UI. Quarantined files are stored without their original extension, which prevents accidental execution.
- Device Security fields (Secure Boot, TPM, VBS) cannot be queried via WMI from `LocalService` — it lacks admin rights. Basic on/off state is read from the registry instead, which works for both the service context and standard user sessions.
- `C:\ProgramData\PolyShield\service_token.txt` is readable by all local users (required for the UI to authenticate) but writable only by `LocalService` and `Administrators`
