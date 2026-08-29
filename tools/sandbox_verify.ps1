# =============================================================================
# sandbox_verify.ps1 - release verification on a machine that has nothing
# =============================================================================
#
# Runs INSIDE Windows Sandbox, launched by the LogonCommand of a .wsb generated
# from tools/make_sandbox_wsb.py. Writes JSON to the mapped results folder so
# the findings survive the sandbox being torn down.
#
# The point is not that the build starts. It is that it starts on a machine
# with no Python, no developer environment variables, no source tree, and no
# %LOCALAPPDATA%\PolyShield -- the four assumptions a checkout quietly
# satisfies and a customer's machine does not.
#
#   powershell -ExecutionPolicy Bypass -File sandbox_verify.ps1 `
#       -DistDir C:\PolyShield_dist -ResultsDir C:\PolyShield_results
# =============================================================================

[CmdletBinding()]
param(
    [string]$DistDir    = "C:\PolyShield_dist",
    [string]$ResultsDir = "C:\PolyShield_results",
    # Installing a Windows service needs the sandbox's admin account; skip it
    # to check only the half that ships as a compiled binary.
    [switch]$SkipService
)

$ErrorActionPreference = "Continue"
$results = [ordered]@{}
$checks  = [System.Collections.ArrayList]::new()

function Add-Check {
    param([string]$Name, [bool]$Pass, $Detail)
    [void]$checks.Add([ordered]@{ name = $Name; pass = $Pass; detail = "$Detail" })
    $tag = if ($Pass) { "PASS" } else { "FAIL" }
    Write-Host ("  [{0}] {1} - {2}" -f $tag, $Name, $Detail)
}

New-Item -ItemType Directory -Force -Path $ResultsDir | Out-Null
Write-Host "=== PolyShield clean-machine verification ===" -ForegroundColor Cyan

# ---------- The machine is genuinely clean --------------------------------
# Asserted rather than assumed: if a Python turns up on PATH, every result
# below becomes ambiguous, because the binary might be finding it.

$pythonOnPath = @(Get-Command python, python3, py -ErrorAction SilentlyContinue)
Add-Check "no Python on PATH" ($pythonOnPath.Count -eq 0) `
    ($(if ($pythonOnPath) { ($pythonOnPath.Source -join ", ") } else { "none found" }))

$devVars = @("PYTHONPATH", "POLYSHIELD_DATA_DIR", "VIRTUAL_ENV") |
    Where-Object { [Environment]::GetEnvironmentVariable($_) }
Add-Check "no developer environment variables" ($devVars.Count -eq 0) `
    ($(if ($devVars) { $devVars -join ", " } else { "none set" }))

$appData = Join-Path $env:LOCALAPPDATA "PolyShield"
Add-Check "no pre-existing data root" (-not (Test-Path $appData)) $appData

# Both layouts are verified by the same script: a onefile build is a single exe
# at the top of dist\, a standalone build is an exe inside app.dist\. Preferring
# onefile when both exist means a release check exercises what actually ships.
$onefile  = Join-Path $DistDir "PolyShield.exe"
$standalone = Join-Path $DistDir "app.dist\PolyShield.exe"
if (Test-Path $onefile) {
    $gui = $onefile;    $layout = "onefile"
} else {
    $gui = $standalone; $layout = "standalone"
}
$results.layout = $layout
Add-Check "GUI binary present ($layout)" (Test-Path $gui) $gui
if (-not (Test-Path $gui)) {
    $results.checks = $checks
    $results | ConvertTo-Json -Depth 6 |
        Set-Content (Join-Path $ResultsDir "verify.json") -Encoding UTF8
    exit 1
}

# ---------- The binary reports on itself ----------------------------------

$pathsRaw = & $gui --paths 2>&1 | Out-String
$pathsOk  = $LASTEXITCODE -eq 0
try { $results.paths = $pathsRaw | ConvertFrom-Json } catch { $results.paths_raw = $pathsRaw }
Add-Check "--paths succeeded" $pathsOk "exit $LASTEXITCODE"

if ($results.paths) {
    Add-Check "reports itself frozen" ([bool]$results.paths.frozen) $results.paths.frozen
    Add-Check "data root under LOCALAPPDATA" `
        ($results.paths.app_root -like "$env:LOCALAPPDATA*") $results.paths.app_root
    # The failure this whole phase exists to prevent.
    Add-Check "data root is NOT inside the build" `
        (-not $results.paths.app_root.StartsWith($results.paths.resource_root)) `
        ("app_root=" + $results.paths.app_root)
}

$enginesRaw = & $gui --engines 2>&1 | Out-String
$enginesOk  = $LASTEXITCODE -eq 0
try { $results.engines = ($enginesRaw | ConvertFrom-Json).engines } catch { $results.engines_raw = $enginesRaw }
# Exit code is the gate: available-and-did-not-detect is the one combination
# that must never ship. Absent engines reporting absent is correct.
Add-Check "no engine claims availability it cannot back up" $enginesOk "exit $LASTEXITCODE"

# ---------- It actually runs ---------------------------------------------

$proc = Start-Process -FilePath $gui -PassThru -WindowStyle Minimized
Start-Sleep -Seconds 30
$alive = -not $proc.HasExited
Add-Check "GUI stays running for 30s" $alive `
    ($(if ($alive) { "still up" } else { "exited with $($proc.ExitCode)" }))
if ($alive) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 3

# rules\ is deliberately absent from this list. It is created when rules are
# downloaded, not at start-up, so a fresh install legitimately has none -- and
# yara_engine.is_available() reports False for exactly that reason ("0 rule
# file(s)"), which is the honest answer rather than a missing directory. An
# earlier version of this script asserted it and failed, because the developer
# checkout it was written against already had one.
foreach ($d in @("config", "intelligence", "logs", "quarantine")) {
    Add-Check "created $d\" (Test-Path (Join-Path $appData $d)) (Join-Path $appData $d)
}

# ---------- Persistence across a restart ---------------------------------
# Checking that a directory exists on the second run proves nothing: the app
# would recreate it either way. What has to be shown is that the second launch
# READ what the first one wrote.

$cfg = Join-Path $appData "config\ui_settings.json"
if (Test-Path $cfg) {
    $json = Get-Content $cfg -Raw | ConvertFrom-Json
    $json | Add-Member -NotePropertyName "sandbox_sentinel" `
                       -NotePropertyValue "survived" -Force
    $json | ConvertTo-Json -Depth 8 | Set-Content $cfg -Encoding UTF8

    $p2 = Start-Process -FilePath $gui -PassThru -WindowStyle Minimized
    Start-Sleep -Seconds 25
    if (-not $p2.HasExited) { Stop-Process -Id $p2.Id -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 3

    $after = Get-Content $cfg -Raw | ConvertFrom-Json
    Add-Check "settings survive a restart" ($after.sandbox_sentinel -eq "survived") `
        "sentinel=$($after.sandbox_sentinel)"
} else {
    Add-Check "settings survive a restart" $false "no settings file was written"
}

# Nothing durable may have been written into the build tree. Under onefile that
# tree is a temporary extraction directory which is deleted on exit, so this is
# the check that would have caught data being written into it.
$buildTree = if ($layout -eq "onefile") { $DistDir } else { Join-Path $DistDir "app.dist" }
$strays = @("logs", "quarantine", "intelligence", "config") |
    Where-Object { Test-Path (Join-Path $buildTree $_) }
Add-Check "build tree stayed read-only in effect" ($strays.Count -eq 0) `
    ($(if ($strays) { $strays -join ", " } else { "no data directories in the build" }))

# ---------- The source-mode service --------------------------------------

if (-not $SkipService) {
    $svcDir = Join-Path $DistDir "service"
    if (Test-Path $svcDir) {
        Add-Check "service staged" $true $svcDir
        Add-Check "service carries the distribution marker" `
            (Test-Path (Join-Path $svcDir ".polyshield-distribution")) ".polyshield-distribution"
        Add-Check "service tree excludes the GUI" `
            (-not (Test-Path (Join-Path $svcDir "src\ui\views"))) "no src\ui\views"

        # A runtime is an installer's job, not the compiler's; if one has been
        # staged beside the service, ask the service where it thinks data lives.
        $svcPy = Join-Path $DistDir "runtime\python.exe"
        if (Test-Path $svcPy) {
            $svcRaw = & $svcPy (Join-Path $svcDir "polyshield_service.py") --paths 2>&1 | Out-String
            try { $results.service_paths = $svcRaw | ConvertFrom-Json }
            catch { $results.service_paths_raw = $svcRaw }
            if ($results.service_paths -and $results.paths) {
                # The invariant: two independently-resolving components, one
                # compiled and one not, must agree on the durable data root.
                Add-Check "service and GUI agree on the data root" `
                    ($results.service_paths.app_root -eq $results.paths.app_root) `
                    ("service=" + $results.service_paths.app_root)
            }
        } else {
            Add-Check "service runtime staged" $false `
                "no runtime at $svcPy - service execution not verified"
        }
    } else {
        Add-Check "service staged" $false "$svcDir missing"
    }
}

# ---------- Report --------------------------------------------------------

$results.checks    = $checks
$results.passed    = @($checks | Where-Object { $_.pass }).Count
$results.failed    = @($checks | Where-Object { -not $_.pass }).Count
$results.timestamp = (Get-Date).ToString("s")

$out = Join-Path $ResultsDir "verify.json"
$results | ConvertTo-Json -Depth 8 | Set-Content $out -Encoding UTF8

Write-Host ""
Write-Host ("=== {0} passed, {1} failed -> {2}" -f $results.passed, $results.failed, $out) `
    -ForegroundColor $(if ($results.failed -eq 0) { "Green" } else { "Red" })
Write-Host ""
Write-Host "This window stays open so the results can be read on screen too."
Write-Host "The sandbox discards everything when it closes."
