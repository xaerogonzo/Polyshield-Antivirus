# add_defender_exclusions.ps1
# ───────────────────────────
# Adds targeted Windows Defender exclusions for PolyShield project files that
# trigger false positives or interfere with service startup.
#
# Run once from an elevated PowerShell prompt:
#   Right-click PowerShell → "Run as Administrator"
#   cd "D:\Random Projects\KicomAI_Project"
#   .\scripts\components\add_defender_exclusions.ps1
#
# WHY TARGETED (not the whole project folder):
#   The quarantine\ directory must NOT be excluded — Defender should keep
#   watching it as a second line of defense in case something in there is
#   more dangerous than our own engines detected.
#
# PATH EXCLUSIONS (specific files/dirs Defender flags):
#   speakeasy\    — ships PE "decoy" .exe files used as emulation templates.
#                   Defender flags them as Trojan:Win32/Malgent.
#   yara\         — YARA Python extension sometimes triggers heuristics.
#   k2.exe        — the scanner binary can be flagged by other AV engines.
#   kicomav_env\  — the entire venv directory; prevents Defender from
#                   intercepting python.exe memory-mapping at file load time.
#
# PROCESS EXCLUSIONS (binaries that must run unimpeded by Defender):
#   python.exe    — when the Windows Service starts, SCM launches python.exe
#   pythonw.exe     as LocalSystem. Defender can intercept the memory-mapping
#                   of the binary during load and cause a STATUS_IN_PAGE_ERROR
#                   (exception 0xC0000006) crash BEFORE any Python code runs.
#                   This manifests as service exit code 1067 with no log entry.
#                   Process exclusions stop Defender from interfering.
#
# NOTE: install.bat and setup_service.bat call this logic automatically.
# Run this script manually only if you need to re-apply exclusions without
# a full reinstall.

# ── Require elevation ─────────────────────────────────────────────────────────
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host ""
    Write-Host "  [ERROR] This script must be run as Administrator." -ForegroundColor Red
    Write-Host "  Right-click PowerShell and choose 'Run as Administrator', then re-run." -ForegroundColor Red
    Write-Host ""
    exit 1
}

# ── Resolve project root relative to this script ──────────────────────────────
# Script lives in scripts\components\ — project root is two levels up
$root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path))

# ── Targeted exclusion paths ──────────────────────────────────────────────────
# Sandboxie-Plus: the kernel driver (SbieDrv.sys) and service binary are
# security tools that Defender sometimes flags or interferes with, which
# causes SBIE2331 "service does not exist" errors by unregistering the driver.
# NOTE: Sandboxie path is hardcoded — update if you move the installation.
$sandboxiePath = "D:\Random Programs\Sandboxie-Plus"

$pathExclusions = @(
    "$root\kicomav_env\Lib\site-packages\speakeasy",
    "$root\kicomav_env\Lib\site-packages\yara",
    "$root\kicomav_env\Scripts\k2.exe",
    "$root\kicomav_env",
    $sandboxiePath
)

# Process exclusions: prevent Defender from intercepting python.exe when
# the Windows Service is launched by SCM as LocalSystem.  Without this,
# a Defender signature update can cause STATUS_IN_PAGE_ERROR (0xC0000006)
# in ntdll.dll during binary load — service exit code 1067, no log entry.
$processExclusions = @(
    "$root\kicomav_env\Scripts\python.exe",
    "$root\kicomav_env\Scripts\pythonw.exe"
)

Write-Host ""
Write-Host "  PolyShield — Windows Defender Exclusions" -ForegroundColor Cyan
Write-Host "  Project root: $root"
Write-Host ""

Write-Host "  Path exclusions:" -ForegroundColor Cyan
foreach ($p in $pathExclusions) {
    try {
        Add-MpPreference -ExclusionPath $p -ErrorAction Stop
        Write-Host "  [OK] $p" -ForegroundColor Green
    } catch {
        Write-Host "  [WARN] $p — $_" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "  Process exclusions:" -ForegroundColor Cyan
foreach ($p in $processExclusions) {
    if (Test-Path $p) {
        try {
            Add-MpPreference -ExclusionProcess $p -ErrorAction Stop
            Write-Host "  [OK] $p" -ForegroundColor Green
        } catch {
            Write-Host "  [WARN] $p — $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [SKIP] Not found (not installed): $p" -ForegroundColor DarkGray
    }
}

# ── Verify quarantine is NOT excluded ─────────────────────────────────────────
$allExclusions = (Get-MpPreference).ExclusionPath
$quarantinePath = "$root\quarantine"

Write-Host ""
if ($allExclusions -contains $root) {
    Write-Host "  [WARN] Broad project root is still excluded — quarantine folder unprotected!" -ForegroundColor Yellow
    Write-Host "         Remove it with: Remove-MpPreference -ExclusionPath '$root'" -ForegroundColor Yellow
} elseif ($allExclusions -contains $quarantinePath) {
    Write-Host "  [WARN] quarantine\ is directly excluded — Defender cannot watch it!" -ForegroundColor Yellow
} else {
    Write-Host "  [OK] quarantine\ is NOT excluded — Defender still monitors it." -ForegroundColor Green
}

Write-Host ""
Write-Host "  Current exclusion list:" -ForegroundColor Cyan
if ($allExclusions) {
    $allExclusions | ForEach-Object { Write-Host "    $_" }
} else {
    Write-Host "    (none)"
}
Write-Host ""
