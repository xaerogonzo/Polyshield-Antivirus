# PolyShield — Windows 11 VM Setup Guide

A repeatable, frustration-free procedure for getting a Windows 11 VM working well on mechanical HDD storage — from ISO to a stable golden snapshot ready for PolyShield field testing.

This guide covers setup decisions that are independent of PolyShield itself. For the PolyShield-specific installation and testing steps that happen *after* your VM is running, see [TESTING.md → VM Field Testing](TESTING.md#vm-field-testing).

---

## Contents

1. [Choosing a Windows 11 Image](#1-choosing-a-windows-11-image)
2. [Building a Tiny11 ISO](#2-building-a-tiny11-iso)
3. [Initial OS Setup — Local Account Bypass](#3-initial-os-setup--local-account-bypass)
4. [Unlocking Personalization (Activation)](#4-unlocking-personalization-activation)
5. [HDD Performance Optimizations](#5-hdd-performance-optimizations)
6. [Visual & UI Tweaks](#6-visual--ui-tweaks)
7. [Secondary Storage Setup](#7-secondary-storage-setup)
8. [Security & Network Isolation](#8-security--network-isolation)
9. [Taking Your Golden Snapshot](#9-taking-your-golden-snapshot)
10. [Ongoing Maintenance Workflow](#10-ongoing-maintenance-workflow)
11. [Recommended VM Specs](#11-recommended-vm-specs)

---

## 1. Choosing a Windows 11 Image

Running stock Windows 11 in a VM on an HDD is painful — telemetry, Search indexing, and automatic updates fight the disk constantly. Two practical alternatives:

### Option A — Tiny11 (Recommended for Disposable Test VMs)

Tiny11 is built by a PowerShell script ([ntdevlabs/tiny11builder](https://github.com/ntdevlabs/tiny11builder)) that you run against your own genuine Windows 11 ISO. It strips bloat and outputs a new ISO. The resulting install uses ~8 GB of disk, runs on 2 GB RAM, and has near-zero background HDD activity.

**Confirmed:** tiny11builder accepts **any Windows 11 edition** as input (Home, Pro, Education, Enterprise, any language). During the build you select the output SKU — choose **Pro** for PolyShield testing (Group Policy features, Hyper-V guest support).

See [Section 2](#2-building-a-tiny11-iso) for build instructions.

### Option B — Windows 11 IoT Enterprise LTSC (Official Clean-Room)

Microsoft's official edition for industrial/embedded use. Zero bloat, no feature updates, fully activatable.

- Requires a VLSC/MSDN subscription or a free evaluation ISO from Microsoft
- Best choice when you need a "real" end-user environment for final validation before distribution
- Still benefits from the HDD optimizations in Sections 5–6

### Option C — Stock Windows 11 (Last Resort)

Works, but expect the first 30 minutes after install to be completely unusable on an HDD as Windows Update and indexing run. Apply all optimizations in Sections 5–6 before doing anything else.

---

## 2. Building a Tiny11 ISO

### Tiny11 Variants

The repo has two scripts. Pick based on what you need to test:

| | `tiny11maker.ps1` **(Regular)** | `tiny11coremaker.ps1` **(Core)** |
|---|---|---|
| **Windows Defender** | ✅ Intact | ❌ Removed |
| **Windows Update** | ✅ Intact | ❌ Removed |
| **WinSxS component store** | ✅ Intact | ❌ Removed |
| **Windows Recovery (WinRE)** | ✅ Intact | ❌ Removed |
| **Serviceable post-build** | ✅ Yes | ❌ No |
| **Disk footprint** | ~8 GB | ~5–6 GB |
| **PolyShield Defender tests** | ✅ Work normally | ❌ Defender absent — co-pilot tests fail |
| **Use for** | Standard field testing | Ultra-minimal throwaway VMs only |

> **Rule of thumb:** Use Regular. Core is only useful if you specifically want to verify PolyShield operates correctly as the *sole* scanner with no Defender at all.

### What the Regular Build Removes

Apps stripped out (non-exhaustive):

Edge, Teams, OneDrive, Xbox/Gaming App, Microsoft News, Cortana, Feedback Hub, Get Help, Mail & Calendar, Maps, Microsoft 365 trial, Mixed Reality Portal, Mobile Plans, Movies & TV, MSN Weather, Office Hub, Paint 3D, People, Power Automate Desktop, Skype, Microsoft Solitaire, Sticky Notes, Tips, Microsoft To Do, Voice Recorder, Widgets, Windows Hello setup prompt, Your Phone / Phone Link.

**Preserved:** Windows Defender, Windows Update, WinSxS, WinRE, DirectX, .NET runtimes, PowerShell, Task Scheduler, WMI.

### Known Issues

| Issue | Notes |
|-------|-------|
| Edge shortcuts linger in Settings | Cosmetic — browser not installed but links remain |
| `winget` may need updating before use | Run `winget upgrade winget` first if winget commands fail |
| OOBE auto-creates a local account | This is a feature — see Section 3 for manual override |
| Core: Defender removed entirely | Expected; `defender_view.py` and Windows Security posture will show errors in PolyShield |

### Prerequisites

- A genuine Windows 11 ISO from [microsoft.com/software-download/windows11](https://www.microsoft.com/software-download/windows11)
- ~15 GB free on a scratch drive
- An elevated (administrator) PowerShell prompt

### Automated Build — `scripts\vm_setup\build_tiny11_vm.bat`

The project includes a helper — **double-click `scripts\vm_setup\build_tiny11_vm.bat`**. It self-elevates via UAC and opens a **folder-picker dialog** so you can choose where to store the tiny11builder clone and the output ISO. No command line required.

```powershell
# Or run from an elevated PowerShell prompt:
.\scripts\vm_setup\build_tiny11_vm.ps1 -ISODrive D -ScratchDrive E

# Core variant (no Defender):
.\scripts\vm_setup\build_tiny11_vm.ps1 -ISODrive D -ScratchDrive E -Variant core

# Skip the folder picker — specify output path directly:
.\scripts\vm_setup\build_tiny11_vm.ps1 -ISODrive D -ScratchDrive E -WorkDir E:\tiny11builder
```

The script will:
1. Open a folder-picker dialog (unless `-WorkDir` is specified) — pick any drive with ~15 GB free
2. Check prerequisites (admin, PowerShell 5.1+, scratch drive space ≥ 15 GB)
3. Clone `ntdevlabs/tiny11builder` from GitHub (ZIP fallback if git is unavailable)
4. Validate the ISO drive contains a Windows image
5. Warn you if Core variant would break PolyShield Defender tests
6. Prompt for SKU selection — **choose Windows 11 Pro**
7. Call `tiny11maker.ps1` or `tiny11coremaker.ps1` with your drives
8. Print VM creation guidance when done

> **Note:** The SKU selection prompt inside tiny11maker cannot be automated — it is intentionally interactive. You must answer it yourself.

### Manual Build

```powershell
# Clone the builder
git clone --depth 1 https://github.com/ntdevlabs/tiny11builder.git C:\tiny11builder

# Mount your ISO (right-click → Mount, or PowerShell:)
Mount-DiskImage -ImagePath "C:\path\to\Win11.iso"
# Note the drive letter Windows assigns (e.g. D:)

# Run the builder
Set-Location C:\tiny11builder
Set-ExecutionPolicy Bypass -Scope Process -Force
.\tiny11maker.ps1 -ISO D -SCRATCH E
# When prompted, select Windows 11 Pro
```

**Output:** `tiny11.iso` in the working directory (~3.8 GB compressed). Create your VM and point its boot drive at this ISO.

---

## 3. Initial OS Setup — Local Account Bypass

Windows 11 tries to force a Microsoft Account during OOBE (Out Of Box Experience). For a test VM, you want a clean local account with no Microsoft login required.

### Method 1 — Direct Local Account Trigger (Preferred)

Works on most Windows 11 builds:

1. At the "Let's connect you to a network" or Microsoft sign-in screen, press **Shift + F10** to open Command Prompt
2. Type the following and press Enter:
   ```
   start ms-cxh:localonly
   ```
3. The local user account creation screen opens immediately — name your account and set a password (or leave password blank for a test VM)

> **Tiny11 note:** tiny11builder includes an unattended answer file that handles this automatically — if you built with the script, OOBE may skip straight to the desktop with a default local account already created.

### Method 2 — OOBE\BYPASSNRO Fallback

If Method 1 doesn't work (usually on very new builds):

1. At the "Let's connect you to a network" screen, press **Shift + F10**
2. Type:
   ```
   OOBE\BYPASSNRO
   ```
3. The VM restarts and replaces the network screen with an **"I don't have internet"** option
4. Select it → continue to local account creation

### After Account Creation

- Do **not** link to a Microsoft Account when prompted later
- Skip all the "privacy settings" screens (telemetry — irrelevant in a test VM, but turning them off reduces background network traffic)
- Skip OneDrive setup

---

## 4. Unlocking Personalization (Activation)

Without activation, Windows blocks personalization settings — you can't change the theme, enable dark mode, or turn off transparency effects. On a test VM with no product key, use the **Microsoft Activation Scripts (MAS)**:

1. Right-click Start → **Terminal (Admin)**
2. Paste and run:
   ```powershell
   irm https://get.activated.win | iex
   ```
3. Press **[1]** for HWID Activation
4. Wait for the success beeps → press any key → exit

You now have full access to personalization settings and Windows won't nag about activation.

> **What this does:** HWID activation ties a digital license to the VM's virtual hardware ID. It's a community script widely used for lab environments. It does not require a product key. Do not use on production machines you intend to distribute or sell.

---

## 5. HDD Performance Optimizations

These are mandatory on mechanical storage. Windows 11 was designed for NVMe SSDs — its default background services generate constant random I/O that saturates an HDD. Apply these immediately after first login, before you do anything else.

### A. Disable High-Impact Background Services

Press **Win + R**, type `services.msc`, hit Enter.

For each service below: right-click → **Properties** → set **Startup type: Disabled** → click **Stop**.

| Service | What it does | Why disable it |
|---------|-------------|----------------|
| **Windows Search** | Continuously indexes every file on disk | Generates massive random reads — completely unnecessary in a test VM |
| **SysMain** (Superfetch) | Pre-loads apps into RAM based on usage patterns | Causes sustained background I/O bottlenecks; RAM pre-loading is counterproductive in a VM |

### B. Disable Hibernation

In an elevated Terminal (Admin):

```powershell
powercfg -h off
```

This removes `hiberfil.sys` — a file that can be several GB (equal to installed RAM). On a shared HDD, this file causes large write spikes and wastes disk space.

### C. Disable Scheduled Defragmentation

Search Start for **"Defragment and Optimize Drives"** → **Change settings** → uncheck **"Run on a schedule"**.

Without this, Windows will periodically try to defragment the VM's virtual disk while it is mounted, causing the guest OS and host OS to fight over the same physical HDD heads simultaneously. This is one of the most severe causes of VM lag on HDDs.

---

## 6. Visual & UI Tweaks

Animations and transparency effects add GPU/CPU overhead that translates directly to UI lag when the disk is already under pressure.

### Best Performance Mode (Kills All Animations)

1. Search Start for **"Adjust the appearance and performance of Windows"**
2. Select **"Adjust for best performance"**
3. Click Apply

This single setting turns off all visual effects at once — window animations, fade effects, thumbnail shadows, smooth-scroll. The UI looks like Windows 2000 but responds instantly even when the HDD is at 50% load.

### Individual Tweaks (If You Want to Keep Some Visual Effects)

If "best performance" mode looks too stark, re-enable only what you need:

| Setting | Path | Recommendation |
|---------|------|----------------|
| Transparency effects | Settings → Personalization → Colors | **Off** — causes constant GPU compositing |
| Dark mode | Settings → Personalization → Colors → Choose your mode | **Dark** — easier on eyes during long test sessions |
| Taskbar animations | Performance Options → Visual Effects | Off |

### 5-Minute Settling Rule

After every cold boot, **do not touch the VM for 2–5 minutes**. Watch Task Manager (Ctrl + Shift + Esc → Performance → Disk). Wait until disk usage drops to 0–5% before starting work. This is the OS finishing its startup background tasks. Trying to work during this window turns a 2-minute wait into a 20-minute fight.

---

## 7. Secondary Storage Setup

If your VM has a secondary virtual disk (e.g., a 128 GB VHDX for test artifacts, malware samples, downloads):

1. Right-click Start → **Disk Management**
2. If prompted to initialize the new disk: select **GPT** → OK
3. Right-click the **black bar** (unallocated space) → **New Simple Volume**
4. Follow the wizard: format as **NTFS**, assign a drive letter (e.g., `E:`)

### Moving the Downloads Folder

To keep `C:` clean and preserve samples across snapshots:

1. Go to `C:\Users\YourUsername`
2. Right-click **Downloads** → **Properties** → **Location** tab
3. Change the path to `E:\Downloads` (or wherever on your secondary drive)
4. Click **Yes** when asked to move existing files

Do the same for **Documents** if you'll be saving scan reports or test files there.

---

## 8. Security & Network Isolation

**Critical for malware testing.** Never detonate a real suspicious file without isolating the VM from your host network first.

### Network Kill Switch

The cleanest method — disconnect the virtual NIC entirely:

**Hyper-V:** VM Settings → Network Adapter → Virtual Switch: **"Not Connected"**  
**VMware:** VM Settings → Network Adapter → Connection: **Disconnected** (or Host-only)  
**VirtualBox:** VM Settings → Network → Adapter 1 → **Not Attached**

> Pull this before running any payload. Re-enable afterwards only if you need to pull tools in.

### DNS Leak Prevention

If you leave networking on (e.g., to test C2 detection in PolyShield), set the VM's DNS manually to avoid inheriting host DNS settings that could identify your network:

1. Settings → Network & Internet → Ethernet → DNS server assignment: **Manual**
2. Set IPv4 DNS to `1.1.1.1` (Cloudflare) or `8.8.8.8` (Google)

### VPN Passthrough Note

If the host machine is connected to a VPN when the VM uses NAT networking, VM traffic routes through the VPN by default. This is generally fine for testing but means C2 blocklist tests (PolyShield Network Monitor → Ghost Connection test) may see different IPs than expected.

### Audio Crackling Fix

If you hear crackling audio in Hyper-V:
Hyper-V Settings → Integration Services → uncheck **Audio**

---

## 9. Taking Your Golden Snapshot

A golden snapshot is your "reset point" — a clean state to revert to before every test run. Taken correctly, it saves hours of reinstallation work.

### When to Take It

Take the golden snapshot **after**:
- [x] OS installed and local account created
- [x] Activation done (personalization unlocked)
- [x] HDD optimizations applied (services disabled, defrag off, hibernation off)
- [x] Visual tweaks applied
- [x] Secondary drive initialized (if using one)

Take it **before**:
- Any malware or suspicious file is touched
- PolyShield is installed (so you can also have a "pre-PolyShield" baseline)
- Any registry changes from testing

### Cold Checkpoint Rule

**Always shut down the VM before taking a checkpoint.** Never snapshot a running VM ("live checkpoint") when on an HDD.

A live checkpoint captures the entire RAM contents to disk alongside the checkpoint data. On a mechanical drive this creates a massive write spike that can take many minutes and leaves a multi-gigabyte RAM dump file that slows every subsequent restore. A cold (powered-off) checkpoint is just the disk state — small, fast, clean.

**Hyper-V:** Start Menu → Shut Down → wait for VM to power off → Hyper-V Manager → Checkpoint  
**VMware:** VM → Power Off → Snapshots → Take Snapshot  
**VirtualBox:** Machine → ACPI Shutdown → Machine → Snapshots → Take

### Recommended Snapshot Ladder

```
[Golden Image]            ← OS + tweaks only, no PolyShield
    └── [PolyShield Clean] ← PolyShield installed, DB populated, service running
            └── [Pre-Test Run N] ← taken before each batch of tests
```

Revert to "PolyShield Clean" between test sessions. Revert to "Golden Image" only if you need to validate a fresh install.

---

## 10. Ongoing Maintenance Workflow

### Staying Fast

- **5-minute rule:** See Section 6 — let the VM settle after each boot before doing test work
- **Keep `C:` clean:** Move large files (samples, scan logs, reports) to the secondary drive
- **Revert, don't patch:** In a test VM it is almost always faster to revert to a snapshot than to manually undo whatever a test run did to the system

### Preventing Snapshot Bloat

Each checkpoint you keep grows your snapshot chain. Older snapshots in the middle of the chain cannot be deleted without merging, which is slow on HDD. The two-level strategy above (Golden + PolyShield Clean as permanent anchors, then rolling pre-test snapshots that you delete after each session) keeps the chain manageable.

### Windows Update in a Test VM

- **Tiny11 Regular / LTSC / Stock:** Windows Update is functional. Consider disabling it (Services → Windows Update → Disabled) after the first install-and-patch cycle. Running updates mid-test is a major HDD load and can change behaviour under test.
- **Tiny11 Core:** Windows Update is removed — no action needed.

---

## 11. Recommended VM Specs

### For Tiny11 on HDD

| Resource | Minimum | Comfortable |
|----------|---------|-------------|
| RAM allocated | 2 GB | 4 GB |
| Virtual disk (C:) | 20 GB | 25 GB |
| Virtual disk (secondary) | — | 128 GB |
| CPU cores | 2 | 2–4 |
| Virtualization platform | Hyper-V / VMware / VirtualBox | — |

**Why 25 GB for C::** Tiny11 installs at ~8 GB. PolyShield + Python venvs + MalwareBazaar intelligence DB takes ~3–4 GB. Leave headroom for Windows temp files, pagefile, and scan artifacts. Running below 5 GB free on C: causes severe Windows slowdowns.

### For Stock Windows 11 on HDD

| Resource | Minimum | Comfortable |
|----------|---------|-------------|
| RAM allocated | 4 GB | 8 GB |
| Virtual disk (C:) | 40 GB | 64 GB |
| CPU cores | 2 | 4 |

---

## Quick-Start Order Summary

For a new VM from scratch:

```
1. Build Tiny11 ISO  ──→  scripts\vm_setup\build_tiny11_vm.bat  (double-click)
2. Create VM         ──→  25 GB disk, 4 GB RAM, 2 cores
3. Install Windows   ──→  Boot ISO → follow OOBE
4. Local account     ──→  Shift+F10 → start ms-cxh:localonly
5. Activate          ──→  irm https://get.activated.win | iex → [1]
6. HDD tweaks        ──→  Disable Search + SysMain + defrag + hibernation
7. Visual tweaks     ──→  Best performance mode, transparency off
8. Secondary drive   ──→  Disk Management → initialize + format
9. Golden snapshot   ──→  Shut down → checkpoint
10. Install PolyShield ──→  scripts/install.bat (see TESTING.md)
11. PolyShield snapshot ──→  Shut down → checkpoint ("PolyShield Clean")
```

---

*For PolyShield-specific installation steps, the field test checklist, and battlespace tests — see [TESTING.md](TESTING.md).*
