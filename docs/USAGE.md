# PolyShield Security Suite

A multi-engine Windows security suite combining signature detection, heuristic analysis, emulation, sandboxing, and live threat intelligence — built by Alexander L Corthell.

---

## Credits & Acknowledgements

**PolyShield is designed and built by [Alexander L Corthell](https://github.com/AlexanderCorthell)** — UI, scan pipeline architecture, Windows service, threat intelligence integration, network monitor, process monitor, dispute resolution system, and all original source files.

### Integrated Security Engines

| Engine | What it does | Author / Project |
|--------|-------------|------------------|
| **k2.exe** | Signature-based scanner; the primary detection engine | Kei Choi — [hanul93/kicomav](https://github.com/hanul93/kicomav) |
| **Guardian AI** | Hash DB + 7 heuristic patterns; tier-aware verdicts | Matt Emilien — [MattEmilien/GuardianAI](https://github.com/MattEmilien/GuardianAI) |
| **ClamAV** | Community-maintained AV signature database | [ClamAV / Cisco Talos](https://www.clamav.net/) |
| **Speakeasy** | Pure-Python PE emulator; Windows API trace without execution | Mandiant — [mandiant/speakeasy](https://github.com/mandiant/speakeasy) |
| **Sandboxie-Plus** | Live sandboxing; runs files in an isolated glass box | David Xanatos — [sandboxie-plus/Sandboxie](https://github.com/sandboxie-plus/Sandboxie) |
| **YARA** | User-supplied pattern rule engine | [VirusTotal / Google](https://virustotal.github.io/yara/) |
| **Windows Defender** | Real-time AV inline scan via MpCmdRun.exe | Microsoft — bundled with Windows |
| **VirusTotal** | Cloud verification across 70+ AV engines | [Google](https://www.virustotal.com/) |

### Threat Intelligence Feeds

| Feed | Provider | Data |
|------|----------|------|
| **MalwareBazaar** | [abuse.ch](https://bazaar.abuse.ch/) | Recent malware MD5 hashes |
| **NSRL** | [NIST](https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl) | Known-safe file hash allow-list (reduces false positives) |
| **Feodo Tracker** | [abuse.ch](https://feodotracker.abuse.ch/) | Active botnet C2 IP addresses |
| **ThreatFox** | [abuse.ch](https://threatfox.abuse.ch/) | Recent malware C2 infrastructure IPs |

### Key Python Libraries

[`customtkinter`](https://github.com/TomSchimansky/CustomTkinter) (Tom Schimansky) · [`yara-python`](https://github.com/VirusTotal/yara-python) · [`watchdog`](https://github.com/gorakhargosh/watchdog) · [`pywin32`](https://github.com/mhammond/pywin32) · [`psutil`](https://github.com/giampaolo/psutil) · [`pybloom-live`](https://github.com/joseph-fox/python-bloomfilter) · [`pystray`](https://github.com/moses-palmer/pystray) · [`requests`](https://requests.readthedocs.io/) · [`Pillow`](https://python-pillow.org/)

---

**Docs:** [ARCHITECTURE.md](ARCHITECTURE.md) · [WINDOWS_SERVICE.md](WINDOWS_SERVICE.md) · [TESTING.md](TESTING.md) · [VM_SETUP.md](VM_SETUP.md) · [Landing page](../README.md)

---

## Architecture Overview

PolyShield uses five cumulative detection layers:

| Layer | Always On? | What It Detects |
|-------|-----------|-----------------|
| **k2.exe** | Configurable | Known threats via proprietary signature DB |
| **Guardian AI** | Configurable | Hash DB + 7 heuristic patterns; tier-aware verdicts (Confirmed/Suspicious); sensitivity profiles (Conservative / Balanced / Power); per-pattern toggles with FP-rate stats; per-scan circuit breaker |
| **Local Intel DB** | Optional | MalwareBazaar MD5s, NSRL safe-list (Bloom-first since v1.7), C2 IP blocklist |
| **Network Monitor** | Yes (with Service) | Live outbound connections vs C2 blocklist; unsigned processes phoning home |
| **Process Monitor** | Yes (with Service) | WMI process creation events; hashes each new executable against threat DB within ~1 s of launch |

**v1.6.1 Fully Modular Scan Pipeline:** `K2 → Defender → Guardian AI → YARA → ClamAV → Speakeasy (always last)` — **all five engines are peers**, fully reorderable with ↑/↓ buttons in the Scan Pipeline panel, with a ↺ Reset order button. K2 is no longer "always first" — it's just another engine that can be moved, disabled, or even uninstalled entirely. All engines respect the unified pause event (Guardian/YARA via `pause_event.wait()`, K2/ClamAV via `NtSuspendProcess` through the shared `proc_pause` helper).

**v1.7 WMI Process Monitor:** A new **Processes** sidebar view adds always-on process creation monitoring. The WMI `__InstanceCreationEvent` subscription hashes each new executable within ≤1 second of launch and checks it against the threat DB. When the Windows Service is running, monitoring persists after the UI closes — the service kills + quarantines autonomously. When running in-process, monitoring stops when the UI closes. NSRL lookups now use a **Bloom filter** (`pybloom-live`) as a fast front-end (~150 MB vs 4–6 GB for a plain Python `set`), dramatically reducing SQLite query frequency for known-safe files.

For the Guardian AI 4-tier scan pipeline, performance benchmarks, database schema, file structure, threading patterns, and architectural notes → **[ARCHITECTURE.md](ARCHITECTURE.md)**.

---

## Fresh Install (New Machine / VM)

To set up PolyShield from scratch on a new machine:

### Prerequisites

- **Python 3.11 or newer** — Download from [python.org](https://python.org). During install, check **"Add Python to PATH"**
- **Internet connection** — Required for downloading packages and virus signatures
- **Git** (optional) — Only needed if cloning from a repo rather than copying the folder

### Steps

1. Copy or clone the project folder to wherever you want it (any drive, any path)
2. Double-click **`scripts\install.bat`**
3. Watch the progress — it runs 7 steps:
   - Verifies Python 3.11+
   - Creates `kicomav_env\` venv
   - Installs all packages (`pip install -r requirements.txt`) — includes k2.exe, Speakeasy, GUI
   - Creates runtime directories (`config\`, `logs\`, `quarantine\`, etc.)
   - Generates `config\.env` with correct absolute paths for your machine
   - Creates a `%USERPROFILE%\.kicomav` junction so k2 can find its config
   - Downloads k2 engine virus signatures
4. When it says **"Installation complete!"**, double-click **`launch_ui.vbs`**

### Optional Components

| Component | Setup | Notes |
|-----------|-------|-------|
| Guardian AI | `scripts\manage.bat` → option 2 | Clones guardianai repo, creates guardian_env |
| Speakeasy | Already installed by `scripts\install.bat` | Check Settings → Behavioral Analysis |
| Sandboxie-Plus | See Behavioral Analysis section below | System-wide installer or portable — both supported |
| Local Intel DB | Use Update Center in-app | MalwareBazaar + NSRL hashes |
| **Realtime Protection Service** | **`scripts\service\setup_service.bat`** (admin) | **Persistent background service — folder watching + process monitoring running after UI closes** |
| YARA Rules | Drop `.yar` files into `rules\user_rules\` | Zero install; `yara-python` is already bundled |
| ClamAV | `scripts\manage.bat` → option 8, then **Settings → ClamAV** | Download Windows MSI from clamav.net; configure path |

### Realtime Protection Service (Recommended)

By default, folder monitoring and process monitoring run inside the UI process and stop when you close PolyShield. The **Windows Service** makes real-time protection persistent — it starts at boot and keeps both monitors running 24/7.

```
Double-click scripts\service\setup_service.bat
  → UAC prompt (administrator required)
  → Installs pywin32 DLLs, sets ACLs, registers service
  → Starts PolyShield Realtime Protection
  → Open PolyShield → Service sidebar item to verify
```

**Uninstall:** `scripts\service\setup_service.bat /remove` or `scripts\manage.bat` → option 6.

For the full technical explanation of how this was built — the pywin32 venv incompatibility discovery, the `_exe_name_` fix, the ACL setup, the push-event socket protocol — see **[WINDOWS_SERVICE.md](WINDOWS_SERVICE.md)**.

### Ongoing Management

Use **`scripts\manage.bat`** for everything after the initial install:

```
╔══════════════════════════════════════════════════════╗
║       PolyShield Security Suite — Component Manager    ║
╚══════════════════════════════════════════════════════╝

  Component Status:

  [1]  k2 Core Engine + Python env        [*] Installed
  [2]  Guardian AI (second-opinion scan)  [ ] Not installed
  [3]  Speakeasy PE Emulator              [*] Installed
  [4]  Local Intelligence Database        [ ] No database
  [5]  System Junction (k2 compatibility) [*] Active

  ──────────────────────────────────────────────────────
  [A]  Install / Update ALL components
  [U]  Uninstall — remove a specific component
  [X]  Uninstall ALL (full clean removal)
  [0]  Exit
```

Each component option shows current status and offers install, update, or reinstall. The full uninstall removes all generated/downloaded content while leaving your source files untouched.

### Notes for VMs

- **Run `scripts\install.bat` as Administrator** if the `%USERPROFILE%\.kicomav` junction step fails — junction creation requires elevated rights on some Windows configurations
- The `.env` file is generated with absolute paths at install time, so the app will work regardless of which drive or folder the project lives in
- Guardian AI, intelligence databases, and scan logs are **not** included in the project files — they're built fresh after install

---

## Testing

For the full testing guide — including the **Windows Sandbox workflow**, **EICAR sprint stress test**, **Ghost Connection network test**, and **Service Recovery test** — see **[TESTING.md](TESTING.md)**.

**Quick check:** Create a file containing `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*` and scan it. k2 should flag it as a virus. This is a completely harmless 68-byte test string — no actual malware.

---

## How to Use

### Basic Workflow

1. **Open PolyShield** → double-click `launch_ui.vbs`

2. **Choose a scan type** (Scan view):
   - **Smart**: Running processes + startup items + temp + targeted AppData risk dirs (browser extensions, PowerShell profiles, WindowsApps shims). Deliberately skips Python venvs, pip caches, npm modules, and other large dev trees.
   - **Quick**: Startup items + temp (fast)
   - **Full**: Entire user profile (slow but thorough)
   - **Custom**: Drag/drop files or folders, or Browse File/Folder
   - **Downloads**: Just the Downloads folder
   - **Temp**: Just temp folders
   - **My presets** — Save any Custom path set as a named preset (💾 Save button), reload it in one click from the dropdown, delete with 🗑. Up to 20 presets. Presets survive restarts (stored in `config/ui_settings.json`).

3. **Configure the Scan Pipeline** (collapsible panel below the toolbar buttons)
   - Each engine has a checkbox, a **⠿ drag handle**, **↑/↓** buttons, and an availability badge
   - **All five engines are peers** — run sequentially in the numbered order shown:
     - **K2 Engine** — k2's bundled scanner (`kicomav_env/Scripts/k2.exe`); optional in v1.6.1+
     - **Defender** — Windows Defender inline scan via MpCmdRun.exe
     - **Guardian AI** — hash DB + heuristic patterns
     - **YARA Rules** — user-supplied `.yar` files (`rules/user_rules/` + community)
     - **ClamAV** — community signature DB (requires separate install)
   - **Reordering:** Drag any row by its **⠿** handle to reposition it, or use **↑/↓** buttons. Click **↺ Reset order** to restore the default (K2 → Defender → Guardian AI → YARA → ClamAV). Speakeasy always runs last.
   - **Speakeasy** — PE emulation on files flagged by any engine above; always the final stage
   - *Sandboxie* and *VirusTotal* remain manual-only actions in Threat Actions
   - Click **"▼ Scan Pipeline"** header to collapse the panel to a single step-count line

4. **Optional: Update Intelligence Database** (before scanning)
   - Go to **Update Center** view
   - **Local Intelligence Database** section:
     - Click "↓ MalwareBazaar Recent (24h)" for fast, small updates (recommended)
     - Click "↓ Full MD5 List" for comprehensive but slower (~5–15 sec scan overhead)
     - Click "Import NSRL…" to load known-safe hashes (optional, improves safety detection)
     - Click "🗑 Clear DB" to reset and switch from full → recent

5. **Review Results**
   - Each engine logs its output in order as it completes (colored by engine)
   - **Stop button** stops the entire pipeline but keeps all results found so far — Threat Actions panel shows partial results
   - **If k2 and Guardian agree**: File marked as infected or clean
   - **If they disagree**: A "Dispute" modal appears with side-by-side verdicts
     - **Quarantine**: Move file to quarantine/
     - **Keep**: Log decision and continue
     - **Open in VirusTotal**: Verify with web service
   - **Threat Actions panel**: After any scan that finds threats, a panel appears below the log with per-threat buttons:
     - **[Quarantine]** — Move immediately
     - **[VirusTotal]** — Navigate to VT view with file pre-loaded
     - **[Analyze]** — Open Sandbox/Emulate view with file pre-loaded

6. **Right-click shortcut**: If the context menu is registered (Settings → Launch), right-click any file in Explorer → "Scan with PolyShield" — opens the app directly to the Scan view with the file ready to go.

### Recommended Settings

**For speed (most users):**
- Use **MalwareBazaar Recent (24h)** in Update Center
- Pipeline: K2 ✓ + Guardian AI ✓  (others off)
- NSRL Allow-List: **Enabled** (optional, saves time on known-safe files)
- Heuristic Patterns: **Enabled** (catches zero-days and pattern-based malware)
- VirusTotal Smart Upload: **"Pattern matches & unknowns"** (verifies uncertain detections)
- Skip NSRL import (not essential)

**For thoroughness (security-conscious):**
- Use **MalwareBazaar Full**
- Pipeline: K2 ✓ + Guardian AI ✓ + YARA ✓ + Defender ✓
- NSRL Allow-List: **Enabled**
- Heuristic Patterns: **Enabled**
- VirusTotal Smart Upload: **"Both engines only"** (high-confidence only, conservative API usage)
- Import NSRL (adds allow-list, faster skipping of clean files)
- Note: First Guardian scan will be slow (~15 sec startup + scan)

**For performance (slow machines):**
- Pipeline: K2 ✓ only (uncheck everything else)
- Or skip K2 too and use Guardian AI + Defender as primary (no subprocess overhead)
- Use Recent 24h, disable NSRL/Patterns toggles, skip VT Smart Upload

**K2-free scan (Guardian + Defender primary):**
- Uncheck K2 in the pipeline panel
- Check Guardian AI + YARA + Defender
- Useful when running PolyShield purely as a supplementary layer alongside another AV

---

## Update Center

### Six Independent Update Sources

**K2 Engine Signatures**
- Updates k2.exe virus definitions
- Frequency: As needed (usually bundled with k2 releases)
- Impact: None (just signature data, not live detection)

**Guardian AI Engine**
- Git pull on `guardianai/` clone
- Pulls latest scanner code + heuristic patterns
- Frequency: Optional, bleeding-edge patches
- Impact: Only if Guardian scans run

**Local Intelligence Database**
- MalwareBazaar threat hashes (your choice: recent 24h or full)
- NSRL known-safe hashes (optional import)
- Frequency: Daily (for recent), monthly (for full)
- Impact: Affects Guardian scan speed; full DB can slow scans by 5–15 sec

**Speakeasy Emulator**
- `pip install --upgrade speakeasy-emulator` inside `kicomav_env\`
- Shows installed version vs. latest on PyPI ("Check PyPI" button)
- "Update Now" button runs upgrade and logs output
- Frequency: As needed; Mandiant releases new versions occasionally
- Impact: Only if Behavioral Analysis emulation is used

**Sandboxie-Plus**
- Cannot be auto-installed — portable build must be downloaded manually
- "Check Latest" queries GitHub API and opens the release page in browser
- Shows installed version (from `Start.exe` file properties) vs. latest GitHub release
- Frequency: As needed; update when GitHub shows a new version
- Impact: Only if Behavioral Analysis detonation is used

**C2 Blocklist (Feodo Tracker + ThreatFox)**
- Downloads Feodo Tracker botnet C2 CSV (`feodotracker.abuse.ch`) + ThreatFox recent IP feed (`threatfox.abuse.ch`)
- Both are free, publicly available threat intel feeds from abuse.ch
- Merges and deduplicates; imports into `ip_blocklist` table in `threat_db.sqlite`
- Typical size: ~400–600 active C2 IPs — lightweight, no performance impact
- Frequency: Daily or as needed (C2 infrastructure changes frequently)
- Impact: Directly feeds the Network Monitor's IP check; more entries = more detections
- Falls back gracefully if either feed is temporarily empty or unreachable

### Update All Button

Runs five sources in sequence: K2 Signatures → Guardian AI → Intelligence DB (recent) → Speakeasy → C2 Blocklist.
Sandboxie-Plus is excluded (manual download required); use "Check Latest" independently.

---

## Database Details

`intelligence/threat_db.sqlite` has four tables: `malicious` (MalwareBazaar MD5s), `safe` (NSRL allow-list), `meta` (update timestamps), and `ip_blocklist` (C2 IPs from Feodo Tracker + ThreatFox).

**To switch from full → recent:** Update Center → Local Intelligence DB → **"🗑 Clear DB"** → then "↓ MalwareBazaar Recent (24h)". This clears `malicious` but leaves NSRL intact.

Full schema → **[ARCHITECTURE.md — Database Schema](ARCHITECTURE.md#database-schema)**.

---

## VirusTotal Smart Upload

### Purpose

After a dual-scan (k2 + Guardian), automatically verify uncertain detections against VirusTotal without wasting API credits on high-confidence matches.

### Trigger Levels

Go to **Settings → VirusTotal** to choose:

| Level | Trigger | Use Case |
|-------|---------|----------|
| **Off** | Never | Conservative API usage, manual checking only |
| **Pattern matches & unknowns** (default) | Guardian flagged via regex pattern **OR** unknown malware (no family name) | Confirms uncertain heuristic hits; validates potential zero-days |
| **Both engines only** | Both k2 AND Guardian flagged the same file | Very conservative; only verifies high-confidence detections |

**Rate Limits:** Free tier = 4 requests/minute. Smart upload respects this automatically.

### Quarantine Manager

The **Quarantine** view supports both single-item and bulk operations:

**Per-row buttons:**
- **Restore** — Returns the file to its original location
- **Delete** — Permanently removes the file (confirms before acting)
- **VT** — Hash-checks the quarantined file against VirusTotal; shows inline verdict `"47/72 ⚠"` / `"0/72 ✓"` / `"Not in VT DB"`

**Bulk operations (for when you have many files to clear):**
1. Check individual rows using the checkbox on the left of each row, or click **Select All** to check everything at once
2. Click **Restore Selected** or **Delete Selected** — confirms once for the whole batch, showing a named list of affected files
3. **Select All** toggles to **Deselect All** when everything is checked

The Restore/Delete Selected buttons are disabled until at least one item is checked.

---

## Windows Security Supplement

### Overview

The **Windows Security** view (sidebar) supplements — not mirrors — every Windows Security Center category. Where Windows shows a simple on/off status, PolyShield adds analysis, context, and quick-action buttons.

| Windows Security says | PolyShield adds |
|---|---|
| Firewall: ON | Rule counts · unusual outbound processes |
| SmartScreen: ON | Count of unsigned startup items SmartScreen would catch |
| No recent threats | Defender exclusion list (blind spots) |
| Device Security: OK | Secure Boot / TPM / VBS status with elevation note |
| (no network section) | Active TCP connections with process attribution |

### Composite Security Score

A 0–100 score card appears at the top of the view with a transparent per-category breakdown:

```
Security Score: 87/100  GOOD
  ✓ Windows Defender     25/25
  ✓ Firewall             20/20
  ✓ Device Security      20/20
  ✓ Account Security     15/15
  ⚠ App Control           5/15  (-10 Controlled Folder Access disabled)
  ✓ System Health         5/5
```

Click **[Score Details ▼]** to expand or collapse the breakdown.

### Collapsible Sections

Each Windows Security category is a collapsible card with:
- **Summary** line (always visible — key status at a glance)
- **Open →** button (deep-links to the relevant Windows settings page)
- **Expandable detail** loaded on demand to keep the view fast

| Section | Open → target |
|---|---|
| Firewall & Network | `wf.msc` (Advanced Firewall MMC) |
| Device Security | `windowsdefender://devicesecurity` |
| Account Protection | `lusrmgr.msc` (Local Users and Groups) |
| App & Browser Control | `windowsdefender://appbrowser` |
| System Health | `ms-settings:windowsupdate` |

### Elevation Handling

Data that requires admin rights (Secure Boot, TPM, Credential Guard, VBS) shows **"Unknown (Admin Required)"** in amber — not red, because amber means *can't check*, not *detected problem*.

A **Run as Administrator** button appears in the view header when the app is not elevated. Alternatively, enable **Settings → Launch → Always launch as Administrator** to permanently rewrite `launch_ui.vbs` to use `RunAs` elevation on every start.

### Performance

- Lightweight data (registry reads) loads immediately on `on_show()`
- Expensive queries (PowerShell, WMI, network connections) are lazy-loaded — only run when you expand a section
- Network connections: only **unsigned** processes to non-local IPs are flagged; signed software (Discord, Steam, etc.) is silently allowed

---

## Windows Explorer Context Menu

A **"Scan with PolyShield"** right-click entry can be added to files, folders, and drives directly from the app — no administrator rights required.

### Setup

1. Open **Settings → Launch**
2. Toggle **"Windows Explorer context menu"** ON
3. Status shows **"Registered"** in green immediately

Right-clicking any file, folder, or drive in Explorer will now show **"Scan with PolyShield"**. Clicking it opens the app directly to the Scan view with that item pre-loaded in the drop zone.

### How It Works

Registers three HKCU registry keys (no admin, per-user only):
```
HKCU\Software\Classes\*\shell\PolyShield\command
HKCU\Software\Classes\Directory\shell\PolyShield\command
HKCU\Software\Classes\Drive\shell\PolyShield\command
```

Command: `"<pythonw.exe>" "<src\ui\app.py>" "--scan" "%1"`

Toggle the setting OFF to remove all three keys cleanly.

---

## Behavioral Analysis (Experimental)

### Purpose

Observe how suspicious files behave without risking your own system. Two stages:

**Stage 4: Emulation** (Speakeasy)
- Traces Windows API calls, registry access, network activity, file operations
- No actual execution on your OS
- Shows: API trace, threat indicators (persistence, injection, encryption, shadow copy deletion)

**Stage 5: Detonation** (Sandboxie-Plus)
- Runs the file in an isolated "glass box"
- All file-system changes trapped in sandbox
- Easily wiped afterward with one click

### Installation & Setup

#### 1. Speakeasy Emulator (Recommended)

**Speakeasy** is a pure Python PE emulator from Mandiant. Installation takes one click:

**Quick Setup (Recommended):**
1. In the project root folder, double-click **`scripts\components\setup_speakeasy.bat`**
2. Wait for the installation to complete (~30-60 seconds)
3. When it finishes, it will show **"[OK] Speakeasy installed successfully!"**
4. Close the window, then restart PolyShield: `launch_ui.vbs`
5. Go to **Settings → Behavioral Analysis**
6. Check the **Speakeasy** status line — should now show **"● Ready"** (green)

**Manual Setup (Alternative):**
If you prefer the command line:
1. Open Command Prompt or PowerShell in the project root
2. Run:
   ```batch
   kicomav_env\Scripts\pip.exe install speakeasy-emulator
   ```
3. Restart PolyShield and check Settings as above

**Verification:**  
Navigate to the **Behavioral Analysis** view from the sidebar. If Speakeasy is ready, you'll see a green badge. Load a suspicious `.exe` file and click **"Emulate"** to trace its API calls.

---

#### 2. Sandboxie-Plus (Optional but Recommended for Full Analysis)

**Sandboxie-Plus** is an open-source sandbox that runs suspicious files in an isolated "glass box." PolyShield supports **both** the system-wide installer and the portable build — use whichever you prefer.

##### Step-by-Step Download & Setup

**A. Download and Install**

1. Open your browser and navigate to:
   ```
   https://github.com/sandboxie-plus/Sandboxie/releases
   ```

2. Find the latest release (usually at the top) and scroll down to the **Assets** section.

3. Download **`Sandboxie-Plus-x64-v1.17.5.exe`** (or the latest version number).
   - Choose the **x64** version (not ARM64 or Classic)

4. **Choose your install type:**

   **Option A — System-wide installer (recommended):**
   - Run the `.exe` and follow the wizard using the default paths
   - Sandboxie installs as a Windows service (`SbieSvc`) — PolyShield detects it automatically
   - When asked about **"Additional Tasks"** (ImDisk driver, etc.), ImDisk is optional; PolyShield doesn't require it

   **Option B — Portable install:**
   - Run the `.exe` installer, but when asked **"Where to install?"** choose a custom folder (e.g., `C:\Sandboxie-Plus\`)
   - After the installer finishes, verify that **`Start.exe`** and **`SbieCtrl.ini`** both exist in the chosen folder — the presence of `SbieCtrl.ini` is how PolyShield detects portable mode

---

**B. Configure PolyShield to Use Sandboxie-Plus**

1. Open PolyShield: `launch_ui.vbs`

2. Navigate to **Settings** (bottom of sidebar)

3. Scroll down to the **Behavioral Analysis** section (you'll see the Speakeasy status badge)

4. In the **Sandboxie-Plus** subsection, click the **Browse** button next to the path field

5. Locate and select **`Start.exe`**:
   - System-wide install: typically `C:\Program Files\Sandboxie-Plus\Start.exe`
   - Portable install: wherever you installed it, e.g. `C:\Sandboxie-Plus\Start.exe`

6. Click **Open**, then **Save**

7. PolyShield validates the path and shows **"● Ready"** (green) when Sandboxie is detected correctly
   - If it shows **"service not running (SbieSvc not found)"**, for system-wide installs check that the Sandboxie service is running; for portable installs verify `SbieCtrl.ini` is in the same folder as `Start.exe`

8. Go back to **Behavioral Analysis** view and verify the status shows **"● Ready"** (green)

---

**C. Optional: Pre-create the KicomHunter Sandbox Box (Advanced)**

PolyShield automatically uses a sandbox box named `KicomHunter`. By default, Sandboxie-Plus creates it on first detonation. If you want to pre-configure it:

1. Run **`SbieCtrl.exe`** (the GUI control panel, in the same folder as `Start.exe`)

2. Right-click in the left panel → **Create New Sandbox**

3. Name it exactly: **`KicomHunter`**

4. Leave all settings at defaults (isolation level: Standard)

5. Click **OK**

Now when you use **Detonate** in PolyShield, it will use this pre-configured box. You can also manually tweak isolation settings here if you want (e.g., disable network access, restrict registry, etc.). See [Sandboxie documentation](https://sandboxie-plus.com/docs/) for advanced options.

---

**D. Verification: Test Emulation + Detonation**

1. Open a potentially suspicious file (e.g., a downloaded `.exe` from the internet)

2. Go to **Behavioral Analysis** view in PolyShield

3. Drag the file into the drop zone, or click **Browse File** and select it

4. Click **Emulate** → You should see:
   - Progress bar (indeterminate) with "Emulating… (this may take up to 30 seconds)"
   - API Calls tab populates with Windows API trace
   - Threat Indicators count updates

5. After emulation completes, if you have Sandboxie-Plus ready:
   - Click **Detonate** → Sandboxie-Plus window opens
   - The suspicious file runs in isolation
   - All changes (files, registry, network) are trapped in the sandbox
   - Close the file's window when done

6. Back in PolyShield, click **Wipe Sandbox** to delete all sandbox contents

If both Emulate and Detonate work, you're all set! ✓

---

### Setup Summary Table

| Component | Required? | Installation | Status Location |
|-----------|-----------|--------------|-----------------|
| **Speakeasy** | Recommended | `pip install speakeasy-emulator` | Settings → Behavioral → Speakeasy badge |
| **Sandboxie-Plus** | Optional | Download portable `.zip` from GitHub, extract, configure in Settings | Settings → Behavioral → Sandboxie badge |

**Minimal Setup:** Install Speakeasy only. You can emulate PE files and see API traces without a sandbox.

**Full Setup:** Install both. You can emulate AND detonate suspicious files for complete behavior analysis.

### Workflow

From **Dispute Modal**, the **Threat Actions panel** (post-scan), or standalone **Sandbox/Emulate** sidebar view:

1. Load file (drag/drop or browse)
2. Click **"Emulate"** → traces API calls without executing
3. Review threat indicators in the tabbed output
4. If needed, click **"Detonate"** → Sandboxie opens, file runs in isolation
5. Close the sandbox app window when done
6. Click **"Wipe Sandbox"** to discard all changes

---

## Dispute Resolution

### When It Triggers

After a dual-scan (k2 + Guardian), if they disagree on a file:
- k2 says **Infected**, Guardian says **Clean** → Dispute modal
- k2 says **Clean**, Guardian says **Infected** → Dispute modal

Single-engine agree → No modal, result is final.

### The Dispute Modal

Shows one file at a time (paginated "Dispute 1 of 3"):

| Field | Shows |
|-------|-------|
| File Path | Full path to disputed file |
| k2 Engine Verdict | Clean / Infected (color-coded) |
| Guardian Verdict | Clean / Infected / Suspicious (color-coded) + reason |
| SHA-256 Hash | Computed in background, links to VirusTotal |
| Actions | 3 buttons |

**Actions:**
- **Quarantine** → Move to `quarantine/`, logged as user override
- **Keep** → Leave file alone, log user decision
- **VirusTotal** → Look up the file's hash on VT API; shows inline result (`"12/72 engines"`) then opens full report in browser
- **Analyze** (if Behavioral Analysis available) → Navigate to Behavioral view with file pre-loaded for emulation or sandbox testing

---

## Source vs. Generated Files

A reference for what belongs in the repo / distribution archive vs. what gets created at install or runtime. Update this table whenever new files or folders are added to the project.

### Legend

| Symbol | Meaning |
|--------|---------|
| ✅ **Source** | Commit to git. Include in any archive/distribution. This is code you wrote. |
| 📦 **Installer** | Created by `install.bat`. Do NOT include — it will be rebuilt fresh on each machine. |
| 🔄 **Runtime** | Created by the running app. User-specific data. Never include. |
| ⬇️ **Downloaded** | Fetched from the internet at setup or update time. Do NOT include — re-downloaded on install. |
| 👤 **User** | User preference or decision. Never include — it's per-machine. |

### File Map

| Path | Category | Why |
|------|----------|-----|
| `src/ui/` | ✅ Source | All custom UI views and core logic |
| `src/tools/` | ✅ Source | Intelligence update scripts |
| `src/ui/app.py` | ✅ Source | Main app entry point |
| `scheduled_scan.py` | ✅ Source | Task Scheduler integration |
| `scripts\install.bat` | ✅ Source | Fresh install script (run once on a new machine) |
| `scripts\manage.bat` | ✅ Source | Component manager (install/update/uninstall individual parts) |
| `scripts\components\setup_guardian.bat` | ✅ Source | Guardian AI setup helper (also callable from manage.bat) |
| `scripts\components\setup_speakeasy.bat` | ✅ Source | Speakeasy install helper (also callable from manage.bat) |
| `scripts\service\setup_service.bat` | ✅ Source | Windows Service installer (self-elevating, idempotent) |
| `polyshield_service.py` | ✅ Source | Windows Service class (pywin32, socket server, watcher) |
| `src/ui/core/service_client.py` | ✅ Source | IPC client — talks to the service over localhost:52614 |
| `src/ui/views/service_view.py` | ✅ Source | Service management UI (install, start, stop, live events) |
| `docs\WINDOWS_SERVICE.md` | ✅ Source | Technical deep-dive: implementation, debug war story, reproduction guide |
| `src/ui/core/proc_pause.py` | ✅ Source | Shared NtSuspendProcess helper for subprocess engines (K2, ClamAV) — `suspend_pid()`, `resume_pid()`, `watch_pause_event()` |
| `src/ui/core/yara_engine.py` | ✅ Source | YARA rules engine (compiles .yar files, scan_async interface) |
| `src/ui/core/clamav_engine.py` | ✅ Source | ClamAV engine (clamscan.exe subprocess, --file-list batch, scan_async interface) |
| `src/ui/core/network_monitor.py` | ✅ Source | Network connection monitor (psutil + ip_blocklist, C2 detection, unsigned-outbound flag) |
| `src/ui/views/network_view.py` | ✅ Source | Network sidebar view (live connections table, alert feed, block button) |
| `rules/user_rules/` | 👤 User | YARA rule files added by the user; `kicomai_sample.yar` is the only committed example |
| `launch_ui.vbs` | ✅ Source | No-console app launcher |
| `scripts\dev\launch_ui.bat` | ✅ Source | Console launcher (dev/debug) |
| `launch_guardian.vbs` | ✅ Source | Standalone Guardian AI launcher |
| `requirements.txt` | ✅ Source | Pip package list — drives the installer |
| `config/.env.template` | ✅ Source | Path config template (no real paths) |
| `README.md` | ✅ Source | This file |
| `CLAUDE.md` | ✅ Source | AI assistant project instructions |
| `.gitignore` | ✅ Source | Git exclusion rules |
| | | |
| `kicomav_env/` | 📦 Installer | Python venv — rebuilt by `install.bat` via `pip install -r requirements.txt` |
| `guardian_env/` | 📦 Installer | Guardian AI venv — rebuilt by `setup_guardian.bat` |
| `config/.env` | 📦 Installer | Machine-specific paths — generated by `install.bat` from `.env.template` |
| `config/` (the dir) | 📦 Installer | Created by `install.bat` step 4 |
| `logs/` | 📦 Installer | Created empty by `install.bat` step 4 |
| `quarantine/` | 📦 Installer | Created empty by `install.bat` step 4 |
| `intelligence/` | 📦 Installer | Created empty by `install.bat` step 4 |
| `rules/` | 📦 Installer | Created empty by `install.bat` step 4 |
| | | |
| `rules/*` | ⬇️ Downloaded | k2 engine virus signatures — fetched by `k2 --update` during install and Update Center |
| `guardianai/` | ⬇️ Downloaded | Cloned from GitHub by `setup_guardian.bat` |
| `guardianai/data/known_bad.txt` | ⬇️ Downloaded | Synced from SQLite by Update Center |
| | | |
| `intelligence/threat_db.sqlite` | 🔄 Runtime | Built by Update Center (MalwareBazaar + NSRL + C2 IP blocklist) |
| `config/cache.db` | 🔄 Runtime | k2 internal cache — grows during scans |
| `logs/*.json` | 🔄 Runtime | Scan reports written by the app |
| `quarantine/*` | 🔄 Runtime | Files moved here when quarantined |
| | | |
| `state/service_events.json` | 🔄 Runtime | Persisted threat events from the Windows Service (atomic writes) |
| `C:\ProgramData\PolyShield\` | 📦 Installer | **The shared data root** — created with per-subtree permissions by the setup program (or by `setup_service.bat` in a source checkout) |
| `<data root>\state\service_token.txt` | 🔄 Runtime | UUID4 shared secret — generated by the service on first start |
| `<data root>\state\service.log` | 🔄 Runtime | Service log (written by the service process) |
| `config/ui_settings.json` | 👤 User | Saved preferences (VT key, Sandboxie path, toggles, etc.) |

### Minimum Archive for Sharing

To hand the project to someone else (or deploy to a VM), you only need these files — everything else is recreated by `install.bat`:

```
scripts\install.bat
scripts\manage.bat
scripts\components\setup_guardian.bat
scripts\components\setup_speakeasy.bat
scripts\components\add_defender_exclusions.ps1
scripts\service\setup_service.bat
scripts\service\fix_service_crash.bat
scripts\service\fix_service_crash.ps1
scripts\dev\launch_ui.bat
scripts\vm_setup\build_tiny11_vm.bat
scripts\vm_setup\build_tiny11_vm.ps1
scripts\sandbox\sandbox-auto-setup.bat
launch_ui.vbs
launch_guardian.vbs
kicomai_service.py
scheduled_scan.py
requirements.txt
config/.env.template
README.md
docs\WINDOWS_SERVICE.md
CLAUDE.md
.gitignore
src\         ← entire folder (includes src\ui\ and src\tools\)
rules\user_rules\   ← if you have custom .yar files you want to bundle
```

That's it. Zip those up, copy to the new machine:
1. Run `scripts\install.bat` (creates venv, packages, signatures)
2. Run `scripts\service\setup_service.bat` (elevated — installs Windows Service)
3. Double-click `launch_ui.vbs`
4. *(Optional)* Go to **Update Center** and run **Update All** to populate intelligence databases

> **Note:** `config/ui_settings.json` (user preferences like VT API key, Sandboxie path) is intentionally excluded. Each machine starts fresh defaults — the user configures their own preferences after install.

> **Deploying to VMs:** This project is designed to work in virtual machines (Hyper-V, VMware, VirtualBox). The only limitation is Sandboxie-Plus, which requires hardware virtualization extensions (VT-x/AMD-V) to be passed through to the VM — PolyShield itself works fine without it.

---

## File Organization

Full annotated file tree → **[ARCHITECTURE.md — File Structure](ARCHITECTURE.md#file-structure)**.

Key directories at a glance:

| Path | Contents |
|------|---------|
| `src/ui/core/` | All backend logic — no UI widgets |
| `src/ui/views/` | CTkFrame subclasses — one per sidebar item |
| `src/tools/` | Intelligence update scripts |
| `intelligence/` | Runtime SQLite database (created by Update Center) |
| `guardianai/` | Cloned from GitHub (optional) |
| `rules/user_rules/` | Drop `.yar` files here — YARA picks them up automatically |
| `logs/` | Scan reports (JSON, timestamped) |
| `quarantine/` | Quarantined files + metadata |

---

## Known Limitations & Future Work

### Current

- **Guardian AI heuristic patterns are simple regex** — No machine learning, just hand-crafted rules
- ~~Full MalwareBazaar loads into RAM~~ — Fixed in v1.8: both guardian_engine and the process monitor now load directly from SQLite. RAM set is capped at 500 K entries; above that, per-lookup SQLite queries are used with no RAM overhead.
- **No pause/resume for updates** — Update processes run to completion
- **WMI process monitor is ~1 s latency, not pre-execution** — Uses `__InstanceCreationEvent WITHIN 1` which fires after launch; cannot block execution. Processes that escalate to SYSTEM / Protected Process Light before the window closes are invisible (requires a kernel minifilter driver to close this gap)
- **Process kill from LocalService may be denied** — LocalService cannot terminate processes owned by SYSTEM or higher-privilege accounts; the UI process has better kill rights. When the UI is closed, partial kills are logged and escalated to "critical" alert level

### Potential Improvements

- [x] Smart-upload to VirusTotal for pattern-match & unknown detections
- [x] Sandbox execution for suspicious files (Speakeasy emulation + Sandboxie-Plus)
- [x] Windows Security supplement view with composite score
- [x] Explorer context menu integration
- [x] Quarantine multi-select bulk operations
- [x] Threat Actions panel after scan (Quarantine/VT/Analyze per file)
- [x] Windows Service for persistent realtime protection (persists after UI closes)
- [x] YARA rules engine (user-supplied .yar files, zero install cost)
- [x] ClamAV signatures engine (community DB, batch scanning via --file-list)
- [x] Network monitoring layer (psutil live connections, C2 IP blocklist, unsigned-outbound flagging, firewall block)
- [x] Configurable scan pipeline (collapsible panel, sequential order, K2 optional, Defender + Speakeasy inline, cancel-and-keep)
- [x] Drag-and-drop pipeline reordering (⠿ handle + ↑/↓ buttons; snap-on-release with visual highlight)
- [x] User-defined scan path presets (save/load/delete named folder sets; up to 20; persisted to settings)
- [x] Bloom filter for NSRL (ScalableBloomFilter ~150 MB; zero SQLite opens for definite non-members)
- [x] WMI process creation monitor (Processes sidebar; hashes new executables within ≤1 s; service kills + quarantines autonomously when UI closed)
- [x] SQLite-direct known_bad load (guardian_engine + process_monitor load MalwareBazaar hashes from SQLite; known_bad.txt intermediary eliminated; RAM set capped at 500K entries)
- [x] Win Security pre-fetch (all 5 section details load silently in background on view open; Device + Account summaries now populate without requiring a click)
- [x] **v1.9 — Null-MD5 false positive fix** (Guardian now skips files smaller than `guardian_min_scan_bytes` before MD5 lookup; default 10 bytes. The MalwareBazaar DB contains `d41d8cd98f00b204e9800998ecf8427e` — the MD5 of any 0-byte file — which previously caused every empty lockfile, SQLite WAL/journal, and browser-extension placeholder to be flagged as "Known Signature". Test scan dropped from ~1,610 false positives to single digits.)
- [x] **v1.9 — Local ignore list** (`intelligence/ignore_list.sqlite`; user marks any file as "false positive" with optional note; future scans short-circuit that hash; managed from Settings → Guardian AI → Ignored Hashes)
- [x] **v1.9 — Master-detail Threat Actions panel** (paginated 50/page, search + reason-chip filter, two-line rows showing filename + truncated path, bulk Quarantine/Ignore/Delete with progress bar + Cancel, "Open in Explorer" action, keyboard nav with Up/Down/Space/Enter, inline file detail pane with MD5/SHA-256/preview/per-engine verdicts)
- [x] **v1.9 — Inline Dispute Mode** (replaced the modal Dispute popup; dispute resolution happens inside the Threat Actions detail pane with Trust K2 / Trust Guardian quick-resolve actions; main UI stays interactive)
- [x] **v1.10 — Tier-aware Guardian verdicts** (`scan_file()` now returns `(infected, reason, tier, match_context)`. Hash matches are "Confirmed" (red); pattern matches default to "Suspicious" (amber, dimmer styling, lighter font weight). Visual separation lets users mentally tune out heuristic noise at a glance.)
- [x] **v1.10 — Three sensitivity profiles** (Conservative / Balanced / Power user). Conservative is the new install default — disables the two natural-language patterns ("Ransomware note", "Ransomware payment demand") that fire on legitimate security documentation. Balanced enables all 7 patterns but keeps the Suspicious downgrade. Power user removes the downgrade for researchers. Switchable via Settings → Guardian AI.
- [x] **v1.10 — Per-pattern toggles with FP-rate statistics** (`intelligence/pattern_stats.sqlite` tracks detections vs. ignores per pattern; Settings → Advanced Guardian Settings shows the empirical false-positive rate for each pattern so users know which to disable).
- [x] **v1.10 — Match Context block in detail pane** (when a pattern fires, the detail pane shows *which* pattern + a ~160-char snippet of the file content that tripped the regex. Transforms vague "Suspicious" into instantly-evaluable evidence.)
- [x] **v1.10 — Consensus badge** ("🛡 Confirmed by N engines" or "⚠ Single-engine heuristic — likely false positive (hash engines say clean)"). One-glance signal of confidence; specifically flags lone Guardian-pattern hits as low-trust.
- [x] **v1.10 — Circuit breaker** (auto-disables Guardian's pattern tier mid-scan when matches exceed the configurable threshold, default 200; hash tiers keep running. Prevents "hallucination state" runaway noise. Prominent red banner alerts the user.)
- [x] **v1.10 — Smart auto-ignore prompt** (after a scan, if the user ignored 3+ files matching the same pattern, prompts to disable the pattern entirely — Keep / Disable / Don't ask again).
- [x] **v1.10 — Watcher pattern tier OFF by default** (`watcher_guardian_patterns=False`; real-time scanning runs Guardian signatures only. Hash detection still fires; patterns are opt-in for those who want them at real-time cadence.)
- [x] **v1.10 — Suspicious display modes** (Hidden by default / Collapsible "Heuristic Findings ▸" sub-section / Inline with CONFIRMED|SUSPICIOUS badges). User-selectable via Advanced Guardian Settings.
- [x] **v1.10 — Reusable collapsible + modal-popup settings helpers** (`_collapsible_section()` + `_modal_settings_dialog()` in `settings_view.py`) — exercised by the Advanced Guardian Settings modal; available for future settings refactors.
- [x] **v1.12 — Automatic intelligence updates** (MalwareBazaar `recent`, C2 blocklist and YARA community rules refresh on a schedule — hosted by the Windows Service when it is running, otherwise checked once at launch. One execution path for scheduled, manual and IPC runs; per-feed status rather than a single verdict; persistent failure backoff that distinguishes an auth wall from a timeout. NSRL, ClamAV, K2 and Speakeasy stay manual by design.)
- [x] **v1.12 — Honest intelligence posture** (the Dashboard's Threat Intelligence card reports one of four states — *intelligence current* / *intelligence stale* / *update required* / *unavailable* — and checks that each feed's data is actually **usable**, not merely that it downloaded. A feed can be perfectly fresh and still have nothing the engine can load.)
- [x] **v1.12 — Atomic YARA rule publishing** (each download lands as an immutable generation directory, switched by an atomic pointer file. A scan sees the whole previous rule set or the whole new one — never a half-extracted tree — and a failed or corrupt download leaves the working rules untouched.)
- [x] **v1.15 — Progress messages that never appeared** (during an intelligence update, an NSRL import or a Guardian AI update, the status badge stayed on its opening text for the whole run — sometimes several minutes — while the log scrolled underneath. It now tracks the operation.)
- [x] **v1.15 — Per-pattern toggles read from the engine** (Settings kept its own copy of the seven pattern names and its own copy of the profile rules. They agreed, but nothing kept them agreeing: a rename would have left a switch that reads OFF over a pattern that keeps firing. The screen now shows what the scanner will actually do.)
- [x] **v1.15 — Startup items that were never actually scanned** (an autorun written with an uppercase `.EXE`, or with an environment variable such as `%ProgramFiles%`, resolved to a path that does not exist and was silently dropped from the scan list. Autoruns are where persistence lives, so these were the entries most worth checking.)
- [x] **v1.15 — The GuardianAI setup button works again** (it pointed at the pre-reorganisation `scripts\setup_guardian.bat`; clicking it did nothing at all — no window, no error. It now launches `scripts\components\setup_guardian.bat`, and says so if the script is missing.)
- [x] **v1.15 — Two crashes that showed as a frozen panel** (an unexpected VirusTotal response left the lookup stuck on “Querying…” with no error; a policy-locked registry could take down the Settings page on open.)
- [x] **v1.15 — Clearing the intelligence DB now reaches the running engines** (the *Clear Intelligence DB* button emptied the database but told nothing; Guardian AI kept reporting "Known Signature" and the process monitor kept terminating and quarantining on hashes the user had just deleted, until the app was restarted. Removal now fires the same consumer-refresh as an import does.)
- [x] **v1.15 — A failed intelligence update costs you nothing** (a feed that returns an error page, an empty response, or a corrupt archive is reported as a failure and leaves the existing database and its "last updated" time exactly as they were. Previously an empty MalwareBazaar response was reported to the Update Center as a database holding **0** hashes.)
- [x] **v1.15 — The NSRL allow-list filter survives a failed rebuild** (`nsrl_bloom.bin` is published atomically. A crash or a full disk during the rebuild used to destroy the working ~150 MB filter, and the only way back was re-importing the multi-GB NSRL source file.)
- [x] **v1.15 — C2 blocklist parsing fixes** (a port-less IPv6 indicator was truncated at its last colon and stored as an address that could never match; the Feodo export's uncommented column header was stored as an IP named `dst_ip`. Every feed record is now validated as a real address before it is written.)
- [x] **v1.15 — Nuitka compiled build** (`build.bat` produces `PolyShield.exe`: a 26 MB single file with no Python installation required. Verified on a clean Windows Sandbox with no Python, no developer environment variables and no source tree — 20 checks, all passing, including that settings written on one run are still there on the next.)
- [x] **v1.15 — Your data lives outside the program** (the threat database, quarantine, logs and settings are kept outside the install directory, so they survive an upgrade, and so the app works when installed somewhere only an administrator can write. The exact location moved to `%ProgramData%\PolyShield` in v1.16 — see below.)
- [x] **v1.16 — Installer** (`PolyShield-Setup-1.16.0.exe`, 52 MB. Installs the program, creates its data directory with the right permissions, registers the service and adds the Explorer menu entry. Uninstalling removes all of that and **keeps your quarantine, logs and settings** unless you tick the box asking it not to. Verified on a clean machine: 46 checks covering install, reinstall over a broken previous attempt, and uninstall.)
- [x] **v1.16 — The service and the app now use the same folder** (they did not. The app kept its data under your own user profile and the service ran under a different account with a different profile, so each was reading a threat database the other never wrote to. Two of the files involved are locks meant to stop them writing at the same time — at different paths those locks protected nothing. Data now lives in `%ProgramData%\PolyShield`, which is one place for both.)
- [x] **v1.16 — Threat intelligence can no longer be tampered with by an ordinary program** (the hash database, the allow-list and your ignored-files list are what the service trusts when deciding whether something is malware, and anything able to rewrite them could switch detection off. They are now read-only for normal users, and the app asks the service to make changes. Your quarantine, logs and settings stay directly writable — quarantine deliberately so, because it must be able to take files out of your own folders.)
- [x] **v1.16 — Scheduled scans work in an installed copy** (creating one silently failed in a compiled build: the Scheduler screen would sit on "Saving…" and never finish, because the app had no way to describe how to launch itself. It now records a command that is still valid months later.)
- [x] **v1.16 — The K2 signature update no longer deletes the YARA rules** (every click of *Update Center → K2 Engine Signatures* removed the downloaded YARA rule set, after which YARA reported "no rules" with nothing to explain why. K2 syncs its own folder by deleting anything it does not recognise, and it had been pointed at a folder PolyShield also uses.)
- [x] **v1.16 — The Explorer menu icon appears** (it pointed at a file that does not exist in a compiled build, so the entry showed with no icon.)
- [x] **v1.16 — Uninstalling actually removes the service** (it reported success while leaving the service installed and running. A program with no visible window cannot run the tool that removes services in the ordinary way, and the failure was invisible.)
- [x] **v1.16 — Sections that cannot work in an installed copy say so** (the Speakeasy and Guardian AI update buttons drive a developer setup that a normal install does not have. They used to report a Windows error code; they now say what is actually true.)

---

## Future Work: Roadmap

### Current Scope (Real-Time Protection Layer)

**Watchdog-based folder monitoring** (`src/ui/core/watcher.py`)
- Monitors user-specified folders for new/changed files
- Automatically scans on file creation/modification
- Quarantine or log-only action
- Use case: Downloads, Desktop, project folders, USB mounts

### Network Monitoring Layer (Implemented — v1.5)

The **Network** sidebar view delivers live connection monitoring and C2 alert detection — no kernel driver, no Secure Boot friction.

**What it provides:**
- Live table of established outbound TCP connections with process attribution (name, remote IP:port, status)
- Flags connections to known C2 IPs from **Feodo Tracker** and **ThreatFox** (both abuse.ch feeds, imported via Update Center)
- Flags processes with no verifiable executable path connecting to external IPs — a Living-off-the-Land / dropper indicator
- "Block" button on any flagged row: triggers a UAC-elevated `New-NetFirewallRule` outbound rule and writes the IP to `ip_blocklist` immediately
- Recent Alerts feed (last 50 `network_event` push messages from the service)

**Why not Moon Secure / PyDivert / OpenSnitch:**
- **Moon Secure** — Legacy Delphi/C++ project (2007). No Python API, no CLI. Its "firewall" is a thin wrapper over Windows Filtering Platform, which we call directly via PowerShell.
- **PyDivert (WinDivert)** — Kernel driver fails on Windows 11 Secure Boot (unsigned). Triggers AV false-positive detections. Requires admin even for monitoring — wrong for a security tool.
- **OpenSnitch** — Linux-only. The Windows community port is unmaintained.
- **psutil + Windows Firewall API** was already in `requirements.txt`, needs no kernel driver, and works without elevation for monitoring. Blocking is on-demand via UAC prompt.

**Architecture:**
- `src/ui/core/network_monitor.py` — psutil poll loop, IP blocklist check, process cache, `NetworkMonitorThread`
- `kicomai_service.py` — hosts `NetworkMonitorThread`; exposes `GET_NETWORK_EVENTS` and `BLOCK_IP` IPC commands
- `src/ui/core/service_client.py` — `get_network_events()` and `block_ip()` helpers
- `src/ui/views/network_view.py` — Live Connections table + Recent Alerts feed + Block buttons
- `src/tools/update_intelligence.py` — `import_c2_blocklist()` pulls Feodo + ThreatFox, merges into `ip_blocklist`

### Stage 6: System-Wide Process Monitoring (Implemented — v1.7)

WMI process creation monitoring is now live. The `Processes` sidebar view and `src/ui/core/process_monitor.py` implement `__InstanceCreationEvent WITHIN 1` subscriptions via `win32com.client`.

**What it provides:**
- Detects every new process system-wide within ≤1 second of launch
- Computes full-file MD5 and checks against MalwareBazaar RAM set + threat DB SQLite
- Auto-terminate (optional): kills process tree + quarantines via `psutil`
- Service integration: when UI is closed, service kills + quarantines autonomously per `process_monitor_ui_closed_action` setting
- Session allow-list: `ALLOW_HASH` IPC command prevents re-kill after user restores from quarantine

**Known limitation — ~1 s detection window, not pre-execution:**
WMI `__InstanceCreationEvent` fires *after* launch. PolyShield detects the process within ~1 second but cannot prevent initial execution. Closing this gap requires a kernel minifilter driver (`IRP_MJ_CREATE` intercept) — well out of scope for a Python-based tool. This is the same approach used by many third-party AV tools on Windows before they added kernel components.

**Known limitation — PPL / SYSTEM processes:**
Processes running as SYSTEM or under Protected Process Light (lsass.exe, MsMpEng.exe, DRM services) deny read access to their executable — the MD5 hash cannot be computed. These are silently skipped. See [ARCHITECTURE.md — Known Limitations](ARCHITECTURE.md).

**For deeper isolation:** Use Sandboxie-Plus detonation in the Behavioral Analysis view before execution.

### Why NSRL, ClamAV, K2 and Speakeasy are not auto-updated

The scheduler only touches feeds that are small, headless-safe and need no
elevation. The rest stay manual on purpose:

| Source | Why it stays manual |
|---|---|
| **NSRL** | A multi-GB local file the user supplies; there is nothing to download unattended |
| **ClamAV (`freshclam`)** | Writes into `C:\Program Files\ClamAV`, which needs administrator rights |
| **K2 signatures** | Writes inside `kicomav_env\`, which the LocalService account may not own |
| **Speakeasy** | A `pip install --upgrade` — never something a background service should run |

Automating any of these would mean either running the service elevated or
silently failing, so the Update Center keeps them as explicit buttons.

### Compiled Build and Installer (shipped, v1.15 — v1.16)

This section used to describe a plan. It shipped, and what shipped differs from
the plan in ways worth recording.

```
build.bat -BuildRuntime -Onefile -Target all     # dist\PolyShield.exe
build.bat -Target installer                      # dist\PolyShield-Setup-<ver>.exe
```

| | Planned | Shipped |
|---|---|---|
| GUI | `nuitka --onefile --windows-disable-console` | `--windows-console-mode=attach`, so `--paths` / `--engines` / `--unregister` can still answer on a console |
| Service | compiled, with `_exe_name_` pointed at the exe | **source**, run by a staged Python beside the GUI — only the entry point inside the package tree survives the compiler |
| Runtime | (not planned) | built by the build, from a hash-pinned python.org embeddable distribution |
| Packaging | (not planned) | Inno Setup, with per-subtree permissions on the data directory and a rollback that runs on any failed exit |

**Why the service is not compiled.** It links and then faults during interpreter
start-up. The first diagnosis blamed pywin32; that was wrong — a probe importing
no pywin32 at all failed identically. What correlates is the entry point's
*location*: only `src/ui/app.py`, which lives inside the package it pulls in,
compiles into a working binary. See docs/ARCHITECTURE.md.

**Why `sys.executable` is not used anywhere.** A Nuitka build reports a
`python.exe` beside the real binary, and **that file does not exist**. Anything
written into the registry, the Task Scheduler or the service registration from
it points Windows at nothing, silently. `paths.running_executable()` is the
answer; `tests/test_paths.py` and `tools/build_probe.py` keep it that way.

---

## Glossary

- **k2.exe** — k2's native scanner binary (signature-based)
- **Guardian AI** — Optional secondary scanner (signature + patterns)
- **MalwareBazaar** — abuse.ch threat intelligence feed (known-bad hashes)
- **NSRL** — NIST Software Reference Library (known-safe hashes)
- **Feodo Tracker** — abuse.ch botnet C2 IP blocklist (Emotet, QakBot, etc.); updates daily
- **ThreatFox** — abuse.ch threat intel feed; provides recent C2 IP:port IOCs across malware families
- **C2 (Command & Control)** — Server infrastructure used by malware to receive instructions; blocking C2 IPs cuts off infected machines from attackers
- **LotL (Living off the Land)** — Attacker technique using built-in Windows tools (PowerShell, WMI, etc.) to avoid dropping new files; PolyShield flags unsigned processes making external connections as a LotL indicator
- **Dual-Scan** — Running both k2 and Guardian on the same files
- **Dispute** — When k2 and Guardian disagree on a file's status
- **Quarantine** — Directory where infected files are moved (default: `quarantine/`)
- **ScanController** — Python class that manages k2 pause/resume/cancel via Windows API
- **Tokensave** — Code indexing tool for fast symbol lookup and codebase navigation

---

## Quick Reference: Settings

**Main Settings** (`Settings` view):

| Setting | Default | What It Does |
|---------|---------|--------------|
| Minimize to system tray on close | True | X hides the window; quit from tray icon |
| Show progress bar | True | Progress % during scan |
| Show current file | True | Filename under progress bar |
| Show ETA | True | Time-remaining estimate |
| Verbose log | True | Log every file; off = threats only |
| Auto-verify threats on VirusTotal | False | Post-scan VT check (requires API key) |
| VirusTotal Smart Upload Level | off | off / pattern / dual — which detections auto-upload to VT |
| K2 Engine (pipeline) | True | Include K2 in the scan pipeline |
| Guardian AI (pipeline) | False | Include Guardian AI in the scan pipeline |
| YARA Rules (pipeline) | False | Include YARA rules scan in the pipeline |
| ClamAV (pipeline) | False | Include ClamAV in the pipeline |
| Defender (pipeline) | False | Include Windows Defender in the pipeline |
| Speakeasy (pipeline) | False | Emulate flagged PE files after all engines complete |
| Pipeline order | k2→defender→guardian→yara→clamav | Execution order; drag ⠿ handles or ↑/↓ to reorder; persisted as `pipeline_order` |
| Scan path presets | [] | User-saved named folder sets; up to 20; accessible from the "My presets" row in the Scan view |
| Update intelligence automatically | True | Master switch for scheduled feed refreshes (`intel_auto_update`) |
| Check every N hours | 12 | How often a feed becomes due (`intel_update_interval_hours`). Separate from the warning thresholds below |
| Warn after N days | 3 | Amber "ageing" threshold in the UI (`intel_aging_days`) |
| Stale after N days | 7 | Red "stale" threshold in the UI (`intel_stale_days`) |
| Auto-updated feeds | malwarebazaar, c2, yara | Which feeds the scheduler may refresh (`intel_auto_feeds`). NSRL / ClamAV / K2 / Speakeasy are never in this list — see below |
| Update at launch | True | Fallback check when no Windows Service is running (`intel_update_on_launch`) |
| Guardian NSRL allow-list | True | Skip SQLite per-file NSRL check to save time |
| Guardian heuristic patterns | True | 7 regex patterns for zero-days |
| Sandboxie-Plus path | (empty) | Path to portable `Start.exe` |
| Minimize to tray | True | Window hides on close, keeps running in tray |
| Windows Explorer context menu | False | Adds "Scan with PolyShield" to right-click menu |
| Always launch as Administrator | False | Rewrites `launch_ui.vbs` to use RunAs on every start |
| Process monitor auto-terminate | False | Kill process tree when a threat is detected (UI process does the kill for best permissions) |
| Process monitor show clean | False | Log all clean processes in the Processes view (off = threats only) |
| Process monitor poll interval | 1 | WMI WITHIN N seconds (1–10); lower = faster detection, more CPU |
| Process monitor action (UI closed) | kill\_and\_quarantine | What service does autonomously: `kill_and_quarantine` or `kill_only` |

**Intelligence DB Settings** (Update Center):

| Action | Effect |
|--------|--------|
| "Recent 24h" | Fetch ~500 new hashes, fast (~10 sec total) |
| "Full MD5 List" | Fetch all ~200K hashes, slow (~5-15 sec startup + scan) |
| "Import NSRL…" | Load ~200M known-safe hashes into SQLite |
| "Clear DB" | Delete all malicious hashes (keeps NSRL) |

---

## Troubleshooting

**Service won't start — exit code 1067, no new entries in service.log**
- **Cause:** A Windows Defender signature update caused Defender to intercept `python.exe` when the Service Control Manager tried to load it as `LocalSystem`. The crash happens inside `ntdll.dll` before any Python code runs — that's why the log has no new entries.
- **Quick fix:** Run `scripts\service\fix_service_crash.bat` as Administrator. It adds the necessary Defender exclusions and starts the service.
- **Manual fix (elevated PowerShell):**
  ```powershell
  Add-MpPreference -ExclusionProcess "D:\...\kicomav_env\Scripts\python.exe"
  Add-MpPreference -ExclusionPath    "D:\...\kicomav_env"
  sc.exe start PolyShieldService
  ```
- **Prevention:** Re-run `scripts\service\setup_service.bat` — step 4/8 now registers these exclusions automatically. New installs via `install.bat` also cover this at step 5b.
- **Full details:** `docs\WINDOWS_SERVICE.md` → "Exit code 1067".

**Guardian AI says "Not installed"**
- Run `scripts\components\setup_guardian.bat` to clone the repo and create `guardian_env/`

**Scan is slow with Guardian enabled**
- Check: Are you using the "Full MD5 List"? Try "Recent 24h" instead
- Consider: Disable NSRL checking (when we add the toggle)

**Update Center shows "Update failed"**
- Check: Internet connection and MalwareBazaar availability
- Check: `intelligence/threat_db.sqlite` isn't locked by another process

**Dispute modal VT button shows no result**
- VirusTotal API lookups require a valid API key in Settings → VirusTotal section
- Get a free key at https://virustotal.com (free tier: 4 req/min, 500/day)

**Windows Defender view stuck on "Refreshing…" and never populates**
- On some machines `Get-MpComputerStatus` is slow to respond (WMI cold-start). Earlier versions would hang indefinitely in this case.
- v1.4+ uses a safe subprocess pattern that recovers from the timeout automatically — upgrade if you are on an older build.
- To confirm the issue: run `scripts\manage.bat` → **[9] Diagnostics** — it tests Defender PowerShell responsiveness and prints the response time.

**Windows Security — Device Security shows "Unknown (requires admin)" for Secure Boot / TPM / VBS**
- Basic on/off state for Secure Boot, TPM, and VBS is now read from the registry (no elevation needed) in v1.4+.
- If you still see "Unknown", it means the registry keys are absent on your system (rare — usually indicates a UEFI-less VM or very old hardware).
- Run `scripts\manage.bat` → **[9] Diagnostics** to confirm whether the keys are present and readable.
- For richer detail (TPM version, Credential Guard running services) you still need admin: click **"Run as Administrator"** in the Win Security view header or enable **Settings → Launch → Always launch as Administrator**.

**Context menu doesn't appear after registering**
- Restart Windows Explorer (`taskkill /f /im explorer.exe` + `start explorer`) or log off/on
- Verify the key exists: `reg query "HKCU\Software\Classes\*\shell\PolyShield"`

**Windows Defender quarantines Speakeasy files (Trojan:Win32/Malgent)**
- Speakeasy ships with PE "decoy" executables under `winenv\decoys\` that it uses as emulation templates. Defender correctly identifies them as executable-shaped but they are inert library files.
- Fix: run `scripts\components\add_defender_exclusions.ps1` as Administrator (right-click → Run with PowerShell). This adds targeted exclusions for `speakeasy\`, `yara\`, and `k2.exe` only.
- **Do not** exclude the entire project folder — the `quarantine\` directory must stay Defender-monitored.
- After adding exclusions, restore the quarantined file from Windows Security → Protection History → Allow on device.

**Behavioral Analysis says "Speakeasy not installed"**
- Double-click **`scripts\components\setup_speakeasy.bat`** (easiest)
- Or run: `kicomav_env\Scripts\pip.exe install speakeasy-emulator`
- Restart the app and check Settings → Behavioral Analysis

**Sandboxie not detected / Settings shows "not configured"**
- Both system-wide installs and portable builds are supported in v1.4+.
- System-wide: PolyShield checks for the `SbieSvc` Windows service — install Sandboxie-Plus normally via its installer.
- Portable: PolyShield checks for `SbieCtrl.ini` next to `Start.exe` — point Settings → Behavioral Analysis at the `Start.exe` in your portable folder.
- After setting the path, navigate away from Behavioral Analysis and back — the status indicator should turn green.

**Sandboxie error SBIE2331 "Service start failed [1060]"**
- Error 1060 = `ERROR_SERVICE_DOES_NOT_EXIST` — the `SbieSvc` service and/or `SbieDrv` kernel driver have been unregistered. Files are still present; only the SCM registration is missing.
- Most likely cause: Windows Defender interfered with `SbieDrv.sys` during a scan.
- Fix step 1: Check Windows Security → Protection History for quarantined Sandboxie files and restore them.
- Fix step 2: Run `SandMan.exe` as Administrator — it detects missing service registration and offers to reinstall automatically.
- Fix step 3 (manual fallback, elevated prompt):
  ```
  cd "<your Sandboxie-Plus install path>"
  KmdUtil.exe install SbieDrv
  SbieSvc.exe /installsvc
  ```
- Prevention: run `scripts\components\add_defender_exclusions.ps1` as Administrator — it auto-detects Sandboxie-Plus from common install locations and adds the directory to Defender exclusions so the driver is never touched again. Pass `-SandboxiePath '<path>'` if you have a custom install location.

---

## Contributing / Local Development

1. **Tokensave Index** — Run `tokensave sync` in project root to rebuild code index
2. **Testing** — No automated tests yet; see [TESTING.md](TESTING.md) for manual test procedures
3. **Code Style** — Python 3.11+, CustomTkinter for UI, no external dependencies beyond `requirements.txt`
4. **Adding a New View** — See `src/ui/app.py` `_NAV_ITEMS` and `_views` dict; implement `on_show()` or `refresh()` as needed

---

## Documentation Index

| Document | Contents |
|----------|---------|
| **README.md** (this file) | Feature overview, install guide, usage, troubleshooting |
| **[ARCHITECTURE.md](ARCHITECTURE.md)** | Detection layers, scan pipelines, performance, DB schema, file structure, threading patterns |
| **[WINDOWS_SERVICE.md](WINDOWS_SERVICE.md)** | Service implementation deep-dive, IPC protocol, pywin32 war story, ACL design |
| **[TESTING.md](TESTING.md)** | Testing procedures, battlespace tests, Windows Sandbox workflow, service log reference |
| **[CLAUDE.md](CLAUDE.md)** | AI assistant project instructions (codebase map, patterns, edit locations) |

---

**Last Updated:** 2026-05-14  
**Version:** 1.9 (Bug fix batch — 8 bugs resolved: thread-safety on service `_events` list, VT verify labels silently not updating, WMI subscription silent death + no auto-restart, SQLite connection leak in network monitor, dead subscriber sockets not closed, `_on_detection_callbacks` race condition; UX additions: Quarantine All batch button in Threat Actions panel, Getting Started onboarding checklist card on Dashboard, ⏸ PAUSED amber indicator next to progress bar, Test Key button in Settings → VirusTotal)
