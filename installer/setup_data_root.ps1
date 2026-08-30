# =============================================================================
# setup_data_root.ps1 - create %ProgramData%\PolyShield with explicit ACLs
# =============================================================================
#
#   powershell -ExecutionPolicy Bypass -File setup_data_root.ps1
#   powershell -ExecutionPolicy Bypass -File setup_data_root.ps1 -WhatIf
#
# Run ELEVATED, by the installer, BEFORE the application first starts.
#
# Why the installer has to create this tree rather than letting the app do it:
# a directory created by the unelevated GUI inherits the root ACL and whatever
# CREATOR OWNER grants come with it. The boundary would then exist in the
# documentation and nowhere else. Two sites create data directories implicitly
# today -- settings.py and intel_updater.py both mkdir(parents=True) -- and
# neither is a good place to be deciding who may write threat intelligence.
#
# The split is by OWNERSHIP, not by sensitivity (docs/ARCHITECTURE.md, "The
# privilege boundary"):
#
#   detection INPUT   the service trusts it when deciding what is malicious,
#                     so an unprivileged process must not be able to rewrite it
#   everything else   remediation output, settings, reports, telemetry
#
# The service runs as LocalSystem, which SYSTEM:F covers. It is NOT granted to
# NT AUTHORITY\LocalService: that account is the documented intent but is not
# what gets registered, and until v1.16 these grants went to it -- rights
# handed to an identity nothing runs under. See docs/WINDOWS_SERVICE.md.
# =============================================================================

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    # Override for testing. Defaults to the same location paths.app_root()
    # resolves for a distribution.
    [string]$Root = (Join-Path $env:ProgramData "PolyShield"),

    # Probe the result instead of building it: try to write into every
    # subdirectory as the CURRENT user and report where that succeeds. Run it
    # unelevated -- an administrator can write anywhere and would see a boundary
    # that is not there. Exits non-zero if any directory is on the wrong side.
    [switch]$Verify
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Service-owned. Users may read (the UI displays quarantine and intel state)
# and may not write. These inherit the root ACL and are listed so the tree
# exists with the right shape before anything else can create it.
$SERVICE_OWNED = @(
    "intelligence",       # threat_db, nsrl_bloom, ignore_list, .update.lock
    "quarantine",         # remediation output; see the note below
    "state",              # IPC token, service log, event feed
    "rules",              # container; community\ is service-owned
    "rules\community",    # executable detection logic, atomically published
    "guardianai",         # hash list the engines consume
    "k2",                 # k2 prunes its own tree; see paths.k2_rules_dir()
    "k2\rules"
)

# User-writable: the unelevated GUI writes these on an ordinary run.
$USER_WRITABLE = @(
    "config",             # ui_settings.json and its cross-process lock
    "logs",               # scan reports
    "telemetry",          # per-pattern FP-rate counters
    "rules\user_rules"    # the user's own YARA rules
)

# quarantine\ is deliberately NOT in $USER_WRITABLE even though the GUI writes
# it. It inherits Users:R from the root and is then granted Modify below, for
# one specific reason: quarantine is remediation OUTPUT and never a detection
# input, so a user able to tamper with it still cannot change a verdict --
# while routing it through the service would break quarantining a file in the
# user's own profile. Kept separate from the list above so the distinction
# stays visible rather than becoming an unexplained entry.
$USER_WRITABLE_OUTPUT = @("quarantine")

if ($Verify) {
    # The half of the privilege boundary that no unit test can reach: it is a
    # property of the installed directory, not of the code. An unprivileged
    # process must not be able to rewrite what the service trusts when deciding
    # what is malicious.
    #
    # Refused when elevated, rather than run and reported. An administrator can
    # write everywhere the root grants Administrators:F -- which is everywhere --
    # so the probe would report the whole tree writable and "fail" for a reason
    # that says nothing about the boundary. Worse, if the expectations were ever
    # inverted it would PASS while proving nothing. A check that cannot fail
    # correctly must not be allowed to answer at all.
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "  [SKIP] -Verify must run UNELEVATED; an administrator can write" -ForegroundColor Yellow
        Write-Host "         anywhere, so the result would say nothing about the boundary." -ForegroundColor Yellow
        Write-Host "         Re-run without elevation, e.g." -ForegroundColor Yellow
        Write-Host "           runas /trustlevel:0x20000 ""powershell -File ...\setup_data_root.ps1 -Verify""" -ForegroundColor Yellow
        exit 2
    }

    $failed = 0
    foreach ($rel in ($SERVICE_OWNED + $USER_WRITABLE + $USER_WRITABLE_OUTPUT)) {
        $dir = Join-Path $Root $rel
        if (-not (Test-Path $dir)) {
            Write-Host "  [MISS] $rel does not exist" -ForegroundColor Red
            $failed++
            continue
        }
        $probe = Join-Path $dir ".acl_probe.tmp"
        try {
            Set-Content -Path $probe -Value "x" -ErrorAction Stop
            Remove-Item $probe -Force -ErrorAction SilentlyContinue
            $writable = $true
        } catch {
            $writable = $false
        }
        $shouldWrite = ($USER_WRITABLE + $USER_WRITABLE_OUTPUT) -contains $rel
        if ($writable -eq $shouldWrite) {
            $state = if ($writable) { "writable" } else { "read-only" }
            Write-Host ("  [OK  ] {0,-18} {1}" -f $rel, $state) -ForegroundColor DarkGray
        } else {
            $failed++
            $want = if ($shouldWrite) { "writable" } else { "read-only" }
            Write-Host ("  [FAIL] {0,-18} should be {1}" -f $rel, $want) -ForegroundColor Red
        }
    }
    if ($failed) {
        Write-Host "  $failed director(ies) on the wrong side of the boundary" -ForegroundColor Red
        exit 1
    }
    Write-Host "  Privilege boundary verified -> $Root" -ForegroundColor Green
    exit 0
}

function Write-Step { param([string]$m) Write-Host "  $m" -ForegroundColor DarkGray }

if (-not (Test-Path $Root)) {
    if ($PSCmdlet.ShouldProcess($Root, "create")) {
        New-Item -ItemType Directory -Path $Root -Force | Out-Null
    }
    Write-Step "created $Root"
} else {
    Write-Step "$Root already exists"
}

foreach ($rel in ($SERVICE_OWNED + $USER_WRITABLE + $USER_WRITABLE_OUTPUT)) {
    $dir = Join-Path $Root $rel
    if (-not (Test-Path $dir)) {
        if ($PSCmdlet.ShouldProcess($dir, "create")) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }
}
Write-Step "subdirectories created"

# Applied AFTER the tree exists: locking the root first makes creating the
# subdirectories depend on the caller being an Administrator, which is true
# for the installer and needlessly untrue for anything else that has to
# re-run this -- including a rollback retry.
#
# /inheritance:r removes inherited ACEs so the result is exactly what is
# granted here -- otherwise ProgramData's own "Users: create files" ACE
# survives and the boundary is decoration.
if ($PSCmdlet.ShouldProcess($Root, "set root ACL")) {
    $out = & icacls $Root /inheritance:r `
        /grant "SYSTEM:(OI)(CI)F" `
        /grant "Administrators:(OI)(CI)F" `
        /grant "Users:(OI)(CI)R" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "icacls failed on ${Root}: $out" }
}
Write-Step "root ACL: SYSTEM=Full, Administrators=Full, Users=Read"

foreach ($rel in ($USER_WRITABLE + $USER_WRITABLE_OUTPUT)) {
    $dir = Join-Path $Root $rel
    if ($PSCmdlet.ShouldProcess($dir, "grant Users:Modify")) {
        $out = & icacls $dir /grant "Users:(OI)(CI)M" 2>&1
        if ($LASTEXITCODE -ne 0) { throw "icacls failed on ${dir}: $out" }
    }
}
Write-Step ("user-writable: " + (($USER_WRITABLE + $USER_WRITABLE_OUTPUT) -join ", "))

Write-Host "  Data root ready -> $Root" -ForegroundColor Green
exit 0
