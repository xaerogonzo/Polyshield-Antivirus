# =============================================================================
# register_service.ps1 - register PolyShieldService from an installed build
# =============================================================================
#
#   powershell -ExecutionPolicy Bypass -File register_service.ps1 `
#       -InstallDir "C:\Program Files\PolyShield"
#
# Run ELEVATED, by the installer. NOT a replacement for
# scripts\service\setup_service.bat, which remains the developer path and
# registers from a source checkout with its own virtualenv.
#
# The difference that matters: a distribution has no kicomav_env. The service
# ships as SOURCE (pywin32 does not survive the compiler -- docs/ARCHITECTURE.md)
# and runs under the staged runtime beside it.
#
# NO pywin32_postinstall. The developer script copies pywintypes3XX.dll and
# pythoncom3XX.dll into System32, which is shared, system-owned state an
# uninstaller must not casually remove. It is unnecessary here: the staged
# runtime carries its own pywin32_system32\ and pywin32.pth adds it to the DLL
# search path at import. Measured in build.ps1 (Test-StagedRuntime), which
# fails the build if pywin32 ever resolves outside the runtime. So PolyShield
# installs nothing into System32 and the uninstaller never has to reason about
# who else on the machine shares a copy.
#
# The account is LocalSystem -- pywin32 installs with no account argument and
# that is its default. NT AUTHORITY\LocalService is the documented intent and
# the narrower account; narrowing to it is a deliberate change that has to be
# tested against process termination, watched-folder reads and autonomous
# quarantine. See docs/WINDOWS_SERVICE.md.
# =============================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$InstallDir,

    # Register only; do not start. The installer starts it as a separate step so
    # a service that registers but will not run is a distinguishable failure.
    [switch]$NoStart,

    # Seconds to wait for RUNNING. "Registered" is not "working": the SCM
    # accepts the registration long before anything proves the process starts.
    [int]$StartTimeout = 30,

    # Run the pre-flight and stop. Every check below is read-only, so this is
    # safe unelevated and against a machine with a service already registered --
    # which is what makes the payload verifiable without touching the SCM.
    [switch]$PreflightOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$SERVICE = "PolyShieldService"
$rtPython = Join-Path $InstallDir "runtime\python.exe"
$svcDir = Join-Path $InstallDir "service"
$svcScript = Join-Path $svcDir "polyshield_service.py"
$marker = Join-Path $svcDir ".polyshield-distribution"

function Write-Step { param([string]$m) Write-Host "  $m" -ForegroundColor DarkGray }

# ---------- Pre-flight --------------------------------------------------------
# Each of these is a way the service registers and then cannot start, which is
# the worst place to discover any of them: the SCM reports a timeout and the
# logs it would have written do not exist yet.

if (-not (Test-Path $rtPython)) {
    throw "No staged runtime at $rtPython. Build with -BuildRuntime."
}
if (-not (Test-Path $svcScript)) {
    throw "No service source at $svcScript."
}
if (-not (Test-Path $marker)) {
    # Without it the service asks is_frozen(), gets False, and resolves its data
    # root to its own install directory -- while the GUI two folders away
    # resolves %ProgramData%\PolyShield. A service writing detections where the
    # UI never looks is indistinguishable from one that found nothing.
    throw "Missing $marker. The staged service would resolve a different data root than the GUI."
}

# What the service itself thinks, before the SCM is involved. Once it is
# installed there is no other way to ask.
$paths = & $rtPython $svcScript --paths 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "The staged service cannot start under its own runtime:`n$paths"
}
# The whole stream, not the last line: --paths prints indented JSON, so
# Select-Object -Last 1 hands ConvertFrom-Json a lone closing brace.
$resolved = ($paths | Out-String) | ConvertFrom-Json
Write-Step "service resolves app_root -> $($resolved.app_root)"
if (-not $resolved.app_root) { throw "The service did not report a data root." }

if ($PreflightOnly) {
    Write-Host "  Pre-flight passed (nothing registered)" -ForegroundColor Green
    exit 0
}

# ---------- Register ----------------------------------------------------------

$existing = & sc.exe query $SERVICE 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Step "$SERVICE already registered; removing it first"
    & sc.exe stop $SERVICE *> $null
    & $rtPython $svcScript remove *> $null
}

Write-Step "registering $SERVICE"
$out = & $rtPython $svcScript install 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "Service registration failed:`n$out"
}

# _svc_start_type_ sets this too; repeated because an upgrade over an older
# registration keeps the old value.
& sc.exe config $SERVICE start= auto *> $null

# Recovery: the developer script does not set this, and a service that dies
# once and stays dead is a protection product that is off without saying so.
& sc.exe failure $SERVICE reset= 86400 actions= restart/60000/restart/60000/restart/60000 *> $null
Write-Step "start=auto, restart-on-failure configured"

if ($NoStart) {
    Write-Host "  Registered (not started) -> $SERVICE" -ForegroundColor Green
    exit 0
}

# ---------- Start, and prove it ----------------------------------------------

& sc.exe start $SERVICE *> $null
$deadline = (Get-Date).AddSeconds($StartTimeout)
$state = ""
while ((Get-Date) -lt $deadline) {
    $q = & sc.exe query $SERVICE 2>&1
    if ($q -match "RUNNING") { $state = "RUNNING"; break }
    if ($q -match "STOPPED") { $state = "STOPPED" }
    Start-Sleep -Milliseconds 500
}

if ($state -ne "RUNNING") {
    $detail = & sc.exe queryex $SERVICE 2>&1 | Out-String
    throw ("$SERVICE registered but did not reach RUNNING within ${StartTimeout}s.`n" +
           "Registered-but-dead is the failure worth catching here.`n$detail")
}

Write-Host "  $SERVICE registered and RUNNING" -ForegroundColor Green
exit 0
