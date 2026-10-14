# =============================================================================
# refusal_test.ps1 - prove that Setup REFUSES when the service cannot be registered
# =============================================================================
#
#   powershell -ExecutionPolicy Bypass -File tools\ci\refusal_test.ps1 `
#       -DistDir dist -ResultsDir artifacts\ci
#
# For an antivirus, a half-installed product is worse than none: it looks
# protected and is not. The installer therefore runs setup_data_root.ps1 and
# register_service.ps1 as REQUIRED steps (installer/polyshield.iss,
# RunRequiredStep), and this script is the evidence that a failure of one stops
# Setup rather than being swallowed.
#
# It builds a SECOND installer from a copy of the payload in which the service
# source has been replaced by a stub that exits 3. register_service.ps1's
# pre-flight runs that stub, fails, and exits 1. A correct installer must then:
#
#   * exit non-zero,
#   * leave no PolyShieldService registered,
#   * say WHY in its log (so the refusal is the intended one, not an unrelated
#     failure that happens to produce a non-zero exit).
#
# What it leaves in the program directory is MEASURED and reported, not asserted:
# whether Inno removes the files it had already copied is a fact to be read off a
# real run, and the report says what it found.
#
# DISPOSABLE MACHINES ONLY. It installs a product, runs scripts that touch the
# service manager and %ProgramData% ACLs, and compiles an installer. It refuses to
# run anywhere that is not a CI runner unless told, in so many words, that the
# machine can be thrown away.
# =============================================================================

[CmdletBinding()]
param(
    [string]$DistDir    = "dist",
    [string]$ResultsDir = "artifacts\ci",

    # Build the sabotaged installer and stop. Touches nothing but the output
    # directory, so it is safe anywhere -- it is how the payload preparation and
    # the compile are checked on a machine that must not be installed onto.
    [switch]$CompileOnly
)

$ErrorActionPreference = "Continue"

if (-not $CompileOnly -and -not $env:GITHUB_ACTIONS -and $env:POLYSHIELD_DISPOSABLE_MACHINE -ne "1") {
    throw ("Refusing to run: this installs the product and rewrites service and ACL state. " +
           "It only runs on a CI runner. On a machine you are certain can be discarded, " +
           "set POLYSHIELD_DISPOSABLE_MACHINE=1.")
}

$ROOT      = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$svcName   = "PolyShieldService"
$distAbs   = (Resolve-Path $DistDir).Path
New-Item -ItemType Directory -Force -Path $ResultsDir | Out-Null
$resultsAbs = (Resolve-Path $ResultsDir).Path

$checks = [System.Collections.ArrayList]::new()
function Add-Result {
    param([string]$Name, [bool]$Pass, $Detail)
    [void]$checks.Add([ordered]@{ name = $Name; pass = $Pass; detail = "$Detail" })
    Write-Host ("  [{0}] {1} - {2}" -f $(if ($Pass) { "PASS" } else { "FAIL" }), $Name, $Detail)
}

function Get-ServiceExists {
    & sc.exe query $svcName *> $null
    return ($LASTEXITCODE -eq 0)
}

# ---------- Find ISCC (same places build.ps1 looks) ---------------------------
$candidates = @(
    (Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"),
    (Join-Path $env:ProgramFiles "Inno Setup 6\ISCC.exe"),
    (Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 6\ISCC.exe")
)
$iscc = $candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $iscc) { throw "Inno Setup not found; looked in: $($candidates -join '; ')" }

# ---------- The precondition: nothing of ours is installed --------------------
# The install cycle that runs before this uninstalls everything. If a service is
# still registered, "no service afterwards" would prove nothing.
Write-Host "=== Refusal test ===" -ForegroundColor Cyan
if (-not $CompileOnly) {
    if (Get-ServiceExists) {
        throw "$svcName is already registered; the refusal test needs a clean starting point."
    }
    Add-Result "starts with no $svcName registered" $true "clean"
}

# ---------- Build the sabotaged payload ---------------------------------------
$broken = Join-Path (Split-Path $distAbs -Parent) "dist_refusal"
if (Test-Path $broken) { [IO.Directory]::Delete($broken, $true) }   # a re-run's leftovers
New-Item -ItemType Directory -Force -Path $broken | Out-Null
# Only what polyshield.iss packages: the exe, the runtime and the service.
foreach ($item in @("PolyShield.exe", "runtime", "service")) {
    Copy-Item -Path (Join-Path $distAbs $item) -Destination (Join-Path $broken $item) -Recurse -Force
}
$svcPy = Join-Path $broken "service\polyshield_service.py"
if (-not (Test-Path $svcPy)) { throw "service\polyshield_service.py is missing from the copied payload." }
# A stub that exits 3: the file still exists (so the installer compiles and the
# pre-flight reaches it) but the service "cannot start under its own runtime".
[IO.File]::WriteAllText($svcPy, "import sys`r`nsys.exit(3)`r`n", (New-Object System.Text.UTF8Encoding($false)))
Add-Result "sabotaged payload prepared" $true "polyshield_service.py replaced by a stub that exits 3"

# ---------- Compile the installer from it -------------------------------------
# Beside dist\, NOT under the results directory: the compiled installer is ~50 MB
# and the results directory is what CI uploads as an artifact.
$outDir = Join-Path (Split-Path $distAbs -Parent) "refusal_build"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$iss = Join-Path $ROOT "installer\polyshield.iss"
$compileOut = & $iscc "/DDistDir=$broken" "/O$outDir" "/FPolyShield-Setup-refusal" $iss 2>&1 | Out-String
$compiled = Join-Path $outDir "PolyShield-Setup-refusal.exe"
Add-Result "the sabotaged installer compiles" ((Test-Path $compiled) -and $LASTEXITCODE -eq 0) $compiled
if (-not (Test-Path $compiled)) {
    Set-Content (Join-Path $resultsAbs "refusal_compile.log") $compileOut
    throw "could not build the test installer; see refusal_compile.log"
}

if ($CompileOnly) {
    Write-Host "=== -CompileOnly: stopped before running the installer ===" -ForegroundColor Yellow
    exit 0
}

# ---------- Run it ------------------------------------------------------------
$innoLog = Join-Path $resultsAbs "inno_refusal.log"
Write-Host "  running the sabotaged installer (silent) ..."
$p = Start-Process -FilePath $compiled -PassThru `
        -ArgumentList "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/NOCANCEL", "/LOG=`"$innoLog`""
if (-not $p.WaitForExit(900000)) {
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    Add-Result "setup finished" $false "still running after 15 minutes; killed"
} else {
    $p.WaitForExit()    # populate ExitCode reliably
    Add-Result "setup REFUSED: exit code is non-zero" ($p.ExitCode -ne 0) "exit $($p.ExitCode)"
}

# ---------- What must be true afterwards --------------------------------------
Add-Result "no $svcName is left registered" (-not (Get-ServiceExists)) $(if (Get-ServiceExists) { "STILL REGISTERED" } else { "absent" })

# -LiteralPath: the '*' in this key name is the real registry key "*" (all file
# types), not a wildcard.
$verb = Test-Path -LiteralPath 'HKCU:\Software\Classes\*\shell\PolyShield' -ErrorAction SilentlyContinue
Add-Result "no Explorer context-menu verb was added" (-not $verb) $(if ($verb) { "present" } else { "absent" })

$logText = if (Test-Path $innoLog) { Get-Content $innoLog -Raw } else { "" }
Add-Result "the log names the required step that failed" `
    ($logText -match "Required step: Registering the PolyShield service") "step is in the Inno log"
Add-Result "the log says PolyShield was not installed" `
    ($logText -match "PolyShield was not installed") "refusal message is in the Inno log"

# The later [Run] entries (K2 rule download, Explorer verb) must NOT have run: the
# required steps come first, and a refusal ends Setup before the rest. A match on
# "Parameters:" is a [Run] entry that executed; the same file name also appears in
# the [Files] copy lines, which say nothing about being run.
Add-Result "no later [Run] entry ran after the refusal" `
    ($logText -notmatch 'Parameters: [^\r\n]*seed_k2_rules\.ps1') "seed_k2_rules.ps1 was never run"

# The product must be gone, not half there. Inno's own uninstaller does the undo
# (FailSetup in polyshield.iss), so the executable and the uninstaller must both be
# absent. Stray files that the program wrote while running (bytecode caches that
# Inno never recorded) may remain and are reported below, not asserted.
$appDir = Join-Path $env:ProgramFiles "PolyShield"
Add-Result "the program is not left installed (no PolyShield.exe)" `
    (-not (Test-Path (Join-Path $appDir "PolyShield.exe"))) $(if (Test-Path (Join-Path $appDir "PolyShield.exe")) { "STILL THERE" } else { "removed" })
Add-Result "no uninstaller is left behind" `
    (-not (Test-Path (Join-Path $appDir "unins000.exe"))) $(if (Test-Path (Join-Path $appDir "unins000.exe")) { "STILL THERE" } else { "removed" })

# ---------- Measured, not asserted --------------------------------------------
$leftover = @()
if (Test-Path $appDir) {
    $leftover = @(Get-ChildItem $appDir -Recurse -Force -File -ErrorAction SilentlyContinue)
}
$measured = [ordered]@{
    app_dir_exists        = (Test-Path $appDir)
    files_left_in_app_dir = $leftover.Count
    sample_of_files_left  = @($leftover | Select-Object -First 8 | ForEach-Object { $_.FullName.Substring($appDir.Length) })
}
Write-Host ("  measured (not asserted): app dir exists={0}, files left={1}" -f `
    $measured.app_dir_exists, $measured.files_left_in_app_dir)

$failed = @($checks | Where-Object { -not $_.pass }).Count
$report = [ordered]@{
    passed = @($checks | Where-Object { $_.pass }).Count
    failed = $failed
    checks = $checks
    measured_after_refusal = $measured
}
[IO.File]::WriteAllText((Join-Path $resultsAbs "refusal.json"),
    ($report | ConvertTo-Json -Depth 5), (New-Object System.Text.UTF8Encoding($false)))

if ($failed -ne 0) {
    Write-Host "=== Refusal test: $failed check(s) FAILED ===" -ForegroundColor Red
    exit 1
}
Write-Host "=== Refusal test: all $($report.passed) checks passed ===" -ForegroundColor Green
exit 0
