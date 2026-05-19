# ──────────────────────────────────────────────────────────────────────────────
#  PolyShield — Service Crash Recovery
#
#  Adds Defender exclusions for the service binary that SCM launches, and the
#  whole kicomav_env directory.  Run via fix_service_crash.bat (recommended)
#  or directly with PowerShell as Administrator:
#
#     Right-click this file → Run with PowerShell  (UAC prompt will appear)
#
#  Symptom this addresses:
#    • Service stops immediately after start with exit code 1067
#    • Application log shows Python.exe crashing with 0xc0000006
#      (STATUS_IN_PAGE_ERROR) paired with 0xC000026E (STATUS_VOLUME_DISMOUNTED)
#    • Service log (C:\ProgramData\PolyShield\service.log) has no new entries
# ──────────────────────────────────────────────────────────────────────────────

# Auto-elevate
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Requesting administrator privileges..." -ForegroundColor Yellow
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoExit","-NoProfile","-ExecutionPolicy","Bypass","-File","`"$PSCommandPath`""
    exit
}

# Script lives in scripts\service\ — project root is two levels up
$root      = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$venv      = Join-Path $root "kicomav_env"
$pyExe     = Join-Path $venv "Scripts\python.exe"
$pywExe    = Join-Path $venv "Scripts\pythonw.exe"

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   PolyShield — Service Crash Recovery               ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

Write-Host "[1/4] Adding Defender process exclusion for venv python.exe..." -ForegroundColor Yellow
try {
    Add-MpPreference -ExclusionProcess $pyExe -ErrorAction Stop
    Write-Host "  [OK] $pyExe" -ForegroundColor Green
} catch {
    Write-Host "  [WARN] $($_.Exception.Message)" -ForegroundColor Yellow
}
try {
    if (Test-Path $pywExe) {
        Add-MpPreference -ExclusionProcess $pywExe -ErrorAction Stop
        Write-Host "  [OK] $pywExe" -ForegroundColor Green
    }
} catch {
    Write-Host "  [WARN] $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[2/4] Adding Defender path exclusion for the venv directory..." -ForegroundColor Yellow
try {
    Add-MpPreference -ExclusionPath $venv -ErrorAction Stop
    Write-Host "  [OK] $venv" -ForegroundColor Green
} catch {
    Write-Host "  [WARN] $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[3/4] Re-registering pywin32 DLLs in System32..." -ForegroundColor Yellow
try {
    & $pyExe -m pywin32_postinstall -install 2>&1 | Out-Null
    Write-Host "  [OK] pywin32 system DLLs refreshed" -ForegroundColor Green
} catch {
    Write-Host "  [WARN] pywin32_postinstall: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[4/4] Starting PolyShieldService..." -ForegroundColor Yellow
$startResult = & sc.exe start PolyShieldService 2>&1
Write-Host $startResult
Start-Sleep -Seconds 3
$status = & sc.exe query PolyShieldService 2>&1 | Out-String
if ($status -match "RUNNING") {
    Write-Host "  [OK] Service is RUNNING" -ForegroundColor Green
} else {
    Write-Host "  [WARN] Service did not reach RUNNING state. Status:" -ForegroundColor Yellow
    Write-Host $status -ForegroundColor DarkYellow
    Write-Host ""
    Write-Host "  Diagnostics:" -ForegroundColor Cyan
    Write-Host "    Log:           C:\ProgramData\PolyShield\service.log"
    Write-Host "    Last crashes:  eventvwr → Windows Logs → Application (look for python.exe)"
}

Write-Host ""
Write-Host "Done. Close this window after reviewing output." -ForegroundColor Cyan
Write-Host ""
