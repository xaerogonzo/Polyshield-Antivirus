<#
.SYNOPSIS
    Downloads tiny11builder and builds a stripped-down Windows 11 ISO for PolyShield field testing.

.DESCRIPTION
    Automates the setup for tiny11builder (https://github.com/ntdevlabs/tiny11builder):
      1. Checks prerequisites (admin, PowerShell 5.1+, scratch-drive space)
      2. Prompts for a working directory via a folder-picker dialog (skipped if -WorkDir provided)
      3. Downloads tiny11builder from GitHub (git clone or ZIP fallback)
      4. Guides you through mounting your Windows 11 ISO
      5. Calls tiny11maker.ps1 or tiny11coremaker.ps1 with your chosen parameters
      6. Prints next steps for loading the resulting ISO into your VM

    You will still need to interactively select the SKU (edition) when prompted
    by the tiny11 script itself — this cannot be bypassed.

    Recommended: run via build_tiny11_vm.bat (double-click) rather than calling
    this script directly — the bat handles UAC elevation and execution policy.

.PARAMETER ISODrive
    Drive letter where your Windows 11 ISO is mounted (letter only, no colon).
    Example: -ISODrive D

.PARAMETER ScratchDrive
    Drive letter to use as a scratch/work area. Needs ~15 GB free.
    Example: -ScratchDrive E

.PARAMETER Variant
    Which tiny11 script to run:
      regular  (default) - removes bloat, keeps system serviceable (Windows Update, Defender, WinSxS intact)
      core               - removes everything including WinSxS, Defender, WinRE; NOT serviceable post-build
                           Use core only for quick throwaway test VMs.

.PARAMETER WorkDir
    Where to clone/extract tiny11builder and write the output ISO.
    If not supplied, a folder-picker dialog appears so you can choose interactively.
    The script appends "\tiny11builder" to whatever folder you pick.
    Example: -WorkDir E:\tiny11builder

.EXAMPLE
    .\build_tiny11_vm.ps1 -ISODrive D -ScratchDrive E
    Opens a folder picker for WorkDir, then builds using the regular variant.

.EXAMPLE
    .\build_tiny11_vm.ps1 -ISODrive D -ScratchDrive E -Variant core -WorkDir E:\tiny11builder
    Builds the core variant to a specific path — no folder picker shown.

.NOTES
    Tiny11builder by NTDEV: https://github.com/ntdevlabs/tiny11builder
    PolyShield recommendation: use 'regular' for field testing unless you specifically
    want to test without Defender as a co-pilot.
    See docs\VM_SETUP.md for the complete VM setup guide.
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$ISODrive    = "",
    [string]$ScratchDrive = "",
    [ValidateSet("regular", "core")]
    [string]$Variant     = "regular",
    [string]$WorkDir     = "$env:TEMP\tiny11builder"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Helpers ───────────────────────────────────────────────────────────────────

function Write-Header($msg) {
    Write-Host ""
    Write-Host "==> $msg" -ForegroundColor Cyan
}

function Write-Ok($msg)   { Write-Host "    [OK]  $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "    [!]   $msg" -ForegroundColor Yellow }
function Write-Err($msg)  { Write-Host "    [ERR] $msg" -ForegroundColor Red }

function Confirm-Continue($prompt) {
    $ans = Read-Host "$prompt [Y/n]"
    return ($ans -eq "" -or $ans -match "^[Yy]")
}

# ── Step 0: Choose working directory (folder picker) ─────────────────────────

if (-not $PSBoundParameters.ContainsKey('WorkDir')) {
    Write-Header "Choose working directory"
    Write-Host ""
    Write-Host "  tiny11builder will be cloned here and tiny11.iso saved here." -ForegroundColor White
    Write-Host "  The folder needs ~15 GB free. A 'tiny11builder' subfolder is created." -ForegroundColor Gray
    Write-Host ""

    $pickedPath = ""
    try {
        Add-Type -AssemblyName System.Windows.Forms
        $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
        $dlg.Description         = "Select a folder for tiny11builder output (~15 GB free needed)"
        $dlg.SelectedPath        = $env:TEMP
        $dlg.ShowNewFolderButton = $true
        $result = $dlg.ShowDialog()
        if ($result -eq [System.Windows.Forms.DialogResult]::OK -and $dlg.SelectedPath) {
            $pickedPath = $dlg.SelectedPath
        }
    } catch {
        Write-Warn "Folder picker unavailable — will use default."
    }

    if ($pickedPath) {
        $WorkDir = Join-Path $pickedPath "tiny11builder"
        Write-Ok "Working directory: $WorkDir"
    } else {
        Write-Warn "No folder selected — using default: $WorkDir"
    }
}

# ── Step 1: Prerequisite checks ───────────────────────────────────────────────

Write-Header "Checking prerequisites"

# PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Err "PowerShell 5.1 or newer required. Current: $($PSVersionTable.PSVersion)"
    exit 1
}
Write-Ok "PowerShell $($PSVersionTable.PSVersion)"

# Execution policy (scope = Process, so original policy is unchanged after this session)
Set-ExecutionPolicy Bypass -Scope Process -Force
Write-Ok "Execution policy set to Bypass for this session"

# ── Step 2: ISO drive ─────────────────────────────────────────────────────────

Write-Header "Windows 11 ISO"

if (-not $ISODrive) {
    Write-Host ""
    Write-Host "  You need a Windows 11 ISO mounted as a drive letter." -ForegroundColor White
    Write-Host "  To mount: right-click the .iso file in Explorer → 'Mount'" -ForegroundColor Gray
    Write-Host "  (Or use: Mount-DiskImage -ImagePath 'C:\path\to\win11.iso')" -ForegroundColor Gray
    Write-Host ""
    $ISODrive = (Read-Host "  Enter the drive letter where the ISO is mounted (e.g. D)").Trim().TrimEnd(':')
}

$ISODrive = $ISODrive.TrimEnd(':')
$ISORoot  = "${ISODrive}:\"

if (-not (Test-Path $ISORoot)) {
    Write-Err "Drive ${ISODrive}: not found. Mount your Windows 11 ISO first."
    exit 1
}

# Sanity-check it's actually a Windows image
if (-not (Test-Path "${ISORoot}sources\install.wim") -and
    -not (Test-Path "${ISORoot}sources\install.esd")) {
    Write-Err "No sources\install.wim or install.esd found on ${ISODrive}:. Is this a Windows 11 ISO?"
    exit 1
}
Write-Ok "Windows 11 image found on ${ISODrive}:"

# ── Step 3: Scratch drive ─────────────────────────────────────────────────────

Write-Header "Scratch drive (needs ~15 GB free)"

if (-not $ScratchDrive) {
    # Suggest any fixed drive with enough space that isn't the ISO drive or system drive
    $suggestion = Get-PSDrive -PSProvider FileSystem |
        Where-Object {
            $_.Used -ne $null -and
            $_.Free -gt 15GB -and
            $_.Name -ne $ISODrive -and
            $_.Name -ne $env:SystemDrive.TrimEnd(':')
        } | Select-Object -First 1 -ExpandProperty Name

    $hint = if ($suggestion) { " (suggested: $suggestion)" } else { "" }
    $ScratchDrive = (Read-Host "  Enter a scratch drive letter$hint (e.g. E)").Trim().TrimEnd(':')
}

$ScratchDrive = $ScratchDrive.TrimEnd(':')
$scratch = Get-PSDrive -PSProvider FileSystem -Name $ScratchDrive -ErrorAction SilentlyContinue

if (-not $scratch) {
    Write-Err "Drive ${ScratchDrive}: not found."
    exit 1
}
if ($scratch.Free -lt 15GB) {
    $freeGB = [math]::Round($scratch.Free / 1GB, 1)
    Write-Warn "Drive ${ScratchDrive}: has only ${freeGB} GB free. 15 GB recommended. Continuing anyway."
}
else {
    $freeGB = [math]::Round($scratch.Free / 1GB, 1)
    Write-Ok "Drive ${ScratchDrive}: has ${freeGB} GB free"
}

# ── Step 4: Variant selection ─────────────────────────────────────────────────

Write-Header "Script variant"

if ($Variant -eq "core") {
    Write-Warn "CORE variant selected."
    Write-Warn "  - Removes WinSxS, Windows Defender, Windows Update, WinRE"
    Write-Warn "  - Cannot be serviced (no updates, no language packs, no features)"
    Write-Warn "  - Defender WILL be disabled — PolyShield will run without Defender as co-pilot"
    Write-Warn "  - Recommended only for quick throwaway development VMs"
    if (-not (Confirm-Continue "  Continue with core variant?")) {
        $Variant = "regular"
        Write-Ok "Switched to regular variant"
    }
}

if ($Variant -eq "regular") {
    Write-Ok "Regular variant — removes bloat, keeps system serviceable (Defender + Windows Update intact)"
}

# ── Step 5: Download tiny11builder ───────────────────────────────────────────

Write-Header "Downloading tiny11builder"

$scriptFile = if ($Variant -eq "core") { "tiny11coremaker.ps1" } else { "tiny11maker.ps1" }

if (Test-Path (Join-Path $WorkDir $scriptFile)) {
    Write-Ok "tiny11builder already present at $WorkDir"
}
else {
    New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null

    # Try git first, fall back to ZIP download
    $gitAvailable = $null -ne (Get-Command git -ErrorAction SilentlyContinue)

    if ($gitAvailable) {
        Write-Host "    Cloning via git..." -ForegroundColor Gray
        git clone --depth 1 https://github.com/ntdevlabs/tiny11builder.git $WorkDir 2>&1 | Out-Null
        Write-Ok "Cloned to $WorkDir"
    }
    else {
        Write-Host "    git not found — downloading ZIP from GitHub..." -ForegroundColor Gray
        $zipUrl  = "https://github.com/ntdevlabs/tiny11builder/archive/refs/heads/main.zip"
        $zipPath = Join-Path $env:TEMP "tiny11builder.zip"
        Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing
        Expand-Archive -Path $zipPath -DestinationPath $env:TEMP -Force
        # GitHub ZIP extracts as "tiny11builder-main"
        $extracted = Join-Path $env:TEMP "tiny11builder-main"
        if (Test-Path $extracted) {
            if (Test-Path $WorkDir) { Remove-Item $WorkDir -Recurse -Force }
            Rename-Item $extracted $WorkDir
        }
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        Write-Ok "Downloaded and extracted to $WorkDir"
    }
}

$scriptPath = Join-Path $WorkDir $scriptFile
if (-not (Test-Path $scriptPath)) {
    Write-Err "$scriptFile not found in $WorkDir. Download may have failed."
    Write-Err "Manual fallback: clone https://github.com/ntdevlabs/tiny11builder to $WorkDir"
    exit 1
}
Write-Ok "Script ready: $scriptPath"

# ── Step 6: Run tiny11builder ─────────────────────────────────────────────────

Write-Header "Building Tiny11 image"
Write-Host ""
Write-Host "  Starting $scriptFile with:" -ForegroundColor White
Write-Host "    -ISO     $ISODrive" -ForegroundColor Gray
Write-Host "    -SCRATCH $ScratchDrive" -ForegroundColor Gray
Write-Host "    Output:  $WorkDir\tiny11.iso" -ForegroundColor Gray
Write-Host ""
Write-Warn "You will be prompted to select a SKU (edition). For PolyShield testing:"
Write-Warn "  - 'Windows 11 Pro' is recommended (has all features PolyShield relies on)"
Write-Warn "  - 'Windows 11 Home' also works but may lack some Group Policy features"
Write-Host ""

if (-not (Confirm-Continue "  Ready to start the build? (takes 10-30 min)")) {
    Write-Host "  Aborted." -ForegroundColor Yellow
    exit 0
}

Set-Location $WorkDir
& $scriptPath -ISO $ISODrive -SCRATCH $ScratchDrive

# ── Step 7: Post-build guidance ───────────────────────────────────────────────

Write-Header "Build complete"
Write-Host ""
Write-Host "  The output ISO is:" -ForegroundColor White
Write-Host "    $WorkDir\tiny11.iso" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Next steps for PolyShield field testing:" -ForegroundColor White
Write-Host ""
Write-Host "  1. Create a new VM in VMware / VirtualBox / Hyper-V" -ForegroundColor Gray
Write-Host "     Recommended specs for HDD-hosted VM:" -ForegroundColor Gray
Write-Host "       RAM:  2 GB minimum (4 GB comfortable)" -ForegroundColor Gray
Write-Host "       Disk: 25 GB (tiny11 uses ~8 GB; leave room for PolyShield + intel DB)" -ForegroundColor Gray
Write-Host "       CPU:  2 cores" -ForegroundColor Gray
Write-Host ""
Write-Host "  2. Mount tiny11.iso as the boot drive and install Windows" -ForegroundColor Gray
Write-Host "     The unattended answer file will bypass Microsoft Account on OOBE." -ForegroundColor Gray
Write-Host ""
Write-Host "  3. After Windows is set up, take a clean snapshot before installing anything." -ForegroundColor Gray
Write-Host ""
Write-Host "  4. See docs\VM_SETUP.md for HDD optimizations, activation, and the" -ForegroundColor Gray
Write-Host "     full field test checklist in docs\TESTING.md." -ForegroundColor Gray
Write-Host ""

if ($Variant -eq "core") {
    Write-Warn "CORE reminder: Defender is disabled in this image."
    Write-Warn "PolyShield will be the only scanner — Defender co-pilot tests will not work."
    Write-Warn "If you want to test Defender integration, rebuild with the 'regular' variant."
}

Write-Host ""
Write-Host "  Happy testing!" -ForegroundColor Green
Write-Host ""
