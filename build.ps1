# =============================================================================
# build.ps1 - PolyShield distribution build
# =============================================================================
#
#   kicomav_env\Scripts\pip.exe install -r requirements-build.txt
#   .\build.bat                       # or: powershell -File build.ps1
#   .\build.bat -Target probe         # just the path probe (fast)
#
# TRACKED ON PURPOSE. A release artifact that cannot be reproduced from the
# repository is not reproducible. Its output (dist/, *.build, *.onefile-build)
# is what .gitignore excludes.
#
# Milestones, and the order matters (docs/ARCHITECTURE.md, "Packaging"):
#
#   4b.1  GUI exe, simplest working config          <- implemented
#   4b.2  service, SOURCE-MODE (pywin32 will not    <- implemented
#         survive the compiler; see ARCHITECTURE)
#   4b.3  scheduled-scan exe                           not yet
#   4b.4  optional engines, one at a time              not yet
#   4b.5  clean Windows Sandbox run                    not yet
#   4b.6  size and startup tuning                      not yet
#
# CORRECTNESS BEFORE OPTIMIZATION. There is deliberately no --onefile, no
# compression, no UPX and no icon here yet. Each of those is a variable, and
# adding several at once turns "the build starts" into a bisect. They belong in
# 4b.6, after a clean-machine run passes.
# =============================================================================

[CmdletBinding()]
param(
    # gui | probe | all
    [ValidateSet("gui", "service", "probe", "all")]
    [string]$Target = "all",

    # Skip the destructive clean. Only for iterating on a single target.
    [switch]$NoClean
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ROOT   = $PSScriptRoot
$DIST   = Join-Path $ROOT "dist"
$PYTHON = Join-Path $ROOT "kicomav_env\Scripts\python.exe"

# ---------- Pre-flight --------------------------------------------------------

if (-not (Test-Path $PYTHON)) {
    throw "kicomav_env not found. Run scripts\install.bat first."
}

& $PYTHON -m nuitka --version *> $null
if ($LASTEXITCODE -ne 0) {
    throw "Nuitka not installed. Run: kicomav_env\Scripts\pip.exe install -r requirements-build.txt"
}

# ---------- Reversibility -----------------------------------------------------
# A failed build must never become the base for the next attempt. Nuitka leaves
# *.build scratch trees behind when a compile is interrupted (an AV file lock is
# enough), and building over a half-populated .dist yields an artifact that is
# part old and part new -- which then "works" for reasons nobody can reproduce.

function Reset-Dist {
    if (-not (Test-Path $DIST)) { return }
    Write-Host "  [clean] removing previous dist\" -ForegroundColor DarkGray
    try {
        Remove-Item $DIST -Recurse -Force -ErrorAction Stop
    } catch {
        throw ("Could not clear dist\ ($($_.Exception.Message)). " +
               "Close any running PolyShield.exe and retry; do not build over it.")
    }
}

# ---------- Build helper ------------------------------------------------------

function Invoke-Nuitka {
    param([string]$Script, [string[]]$ExtraArgs, [string]$Label)

    Write-Host ""
    Write-Host "  Building $Label ..." -ForegroundColor Cyan

    # src/ has to be importable at COMPILE time: Nuitka resolves imports
    # statically, and the entry points only put src/ on sys.path at runtime.
    $prevPythonPath = $env:PYTHONPATH
    $env:PYTHONPATH = Join-Path $ROOT "src"

    # Nuitka writes progress to stderr; with $ErrorActionPreference = "Stop"
    # PowerShell treats each stderr line as a NativeCommandError and aborts.
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & $PYTHON -m nuitka @ExtraArgs $Script 2>&1 | ForEach-Object { Write-Host $_ }
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prevEAP
        $env:PYTHONPATH = $prevPythonPath
    }

    if ($code -ne 0) { throw "Nuitka failed (exit $code) building $Label" }
}

# ---------- Targets -----------------------------------------------------------

# Shared: --standalone rather than --onefile for now. Standalone has no
# extraction directory, so it isolates "does the app compile and run" from
# "does the app survive being unpacked to temp" -- two failures worth telling
# apart. --onefile arrives in 4b.6.
$commonArgs = @(
    "--standalone",
    "--assume-yes-for-downloads",
    "--output-dir=$DIST"
)

$guiArgs = $commonArgs + @(
    "--enable-plugin=tk-inter",
    "--include-package=ui",
    # tools/ is imported lazily by the Update Center; a static analyser cannot
    # see those imports, so they have to be named.
    "--include-package=tools",
    # yara-python is a compiled wheel and the only detection engine that ships
    # inside the binary. Verified by detection rather than by import: see the
    # --engines gate below.
    "--include-package=yara",
    # customtkinter ships its themes and fonts as package data. Without this the
    # app starts and renders with no theme at all.
    "--include-package-data=customtkinter",
    "--output-filename=PolyShield.exe"
    # NOT --windows-console-mode=disable yet: while the build is still being
    # brought up, a startup traceback on the console is the whole diagnostic.
    # It goes in at 4b.6 together with the icon.
)

$serviceArgs = $commonArgs + @(
    # Every ui.core import in the service is inside a method, so a static
    # analyser sees none of them. Naming the package is not belt-and-braces:
    # without it the service compiles cleanly and then cannot start.
    "--include-package=ui.core",
    "--include-package=tools",
    # A service must never need a display. ui.core is Tk-free already; these
    # make that a build-time guarantee rather than a property someone has to
    # keep remembering, and they keep ~900 Tcl/Tk data files out of the image.
    "--nofollow-import-to=tkinter",
    "--nofollow-import-to=customtkinter",
    "--nofollow-import-to=ui.views",
    "--output-filename=PolyShieldService.exe"
)

$probeArgs = $commonArgs + @(
    "--include-module=ui.core.paths",
    "--remove-output"
)

# ---------- Main --------------------------------------------------------------

Write-Host ""
Write-Host "=== PolyShield build ($Target) ===" -ForegroundColor Cyan

if (-not $NoClean) { Reset-Dist }
New-Item -ItemType Directory -Force -Path $DIST | Out-Null

if ($Target -in @("gui", "all")) {
    Invoke-Nuitka -Script (Join-Path $ROOT "src\ui\app.py") `
                  -ExtraArgs $guiArgs -Label "PolyShield.exe (GUI)"
}

if ($Target -in @("service", "all")) {
    # NOT compiled. pywin32 does not survive this Nuitka build: the executable
    # links and then faults during interpreter start-up, two different ways
    # depending on flags, before reaching its own first line. See
    # docs/ARCHITECTURE.md, "4b.2 is BLOCKED". The service therefore ships as
    # source beside the compiled GUI, run by a Python runtime staged next to it.
    $svcDir = Join-Path $DIST "service"
    Write-Host ""
    Write-Host "  Staging source-mode service ..." -ForegroundColor Cyan

    New-Item -ItemType Directory -Force -Path $svcDir | Out-Null
    Copy-Item (Join-Path $ROOT "polyshield_service.py") $svcDir -Force
    Copy-Item (Join-Path $ROOT "scheduled_scan.py")     $svcDir -Force

    # Only the engine-side tree. ui/views is the GUI and would drag Tk into a
    # component that must never need a display.
    $svcSrc = Join-Path $svcDir "src"
    New-Item -ItemType Directory -Force -Path $svcSrc | Out-Null
    Copy-Item (Join-Path $ROOT "src\ui\core") (Join-Path $svcSrc "ui\core") -Recurse -Force
    Copy-Item (Join-Path $ROOT "src\tools")   (Join-Path $svcSrc "tools")   -Recurse -Force
    foreach ($initFor in @("ui")) {
        $init = Join-Path $svcSrc "$initFor\__init__.py"
        if (-not (Test-Path $init)) { New-Item -ItemType File -Path $init -Force | Out-Null }
    }
    Get-ChildItem $svcSrc -Recurse -Directory -Filter "__pycache__" |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

    # The marker is the whole point of the staging: without it the service
    # resolves app_root() to its own install directory, while the compiled GUI
    # two folders away resolves it to %LOCALAPPDATA%\PolyShield -- and a
    # service writing detections where the UI never looks is indistinguishable
    # from a service that found nothing.
    Set-Content -Path (Join-Path $svcDir ".polyshield-distribution") `
                -Value "Shipped as source; see docs/ARCHITECTURE.md 4b.2." -NoNewline

    if (Test-Path (Join-Path $svcSrc "ui\views")) {
        throw "Staged service contains ui\views - it must not need a display."
    }
    Write-Host "  Service staged (source mode, no Tk) -> $svcDir" -ForegroundColor Green
    Write-Host "  Runtime NOT staged: supply a Python with pywin32, psutil," -ForegroundColor DarkGray
    Write-Host "  watchdog. See docs/ARCHITECTURE.md." -ForegroundColor DarkGray
}

if ($Target -in @("probe", "all")) {
    Invoke-Nuitka -Script (Join-Path $ROOT "tools\build_probe.py") `
                  -ExtraArgs $probeArgs -Label "build_probe.exe"
}

# ---------- Gate --------------------------------------------------------------
# "The exe was produced" is not a result. The probe answers the one question
# that a compiled build can get wrong silently: whether it knows it is frozen,
# and whether anything durable resolves under the directory a onefile build
# deletes on exit. It exits non-zero if either is wrong.

$probeExe = Join-Path $DIST "build_probe.dist\build_probe.exe"
if (Test-Path $probeExe) {
    Write-Host ""
    Write-Host "  Path resolution in the built binary:" -ForegroundColor Cyan
    & $probeExe
    if ($LASTEXITCODE -ne 0) {
        throw "Path probe failed (exit $LASTEXITCODE) - see output above. " +
              "The build must not ship."
    }
    Write-Host "  Probe OK: frozen detected, data root outside the build." -ForegroundColor Green
}

$guiExe = Join-Path $DIST "app.dist\PolyShield.exe"
if (Test-Path $guiExe) {
    # Ask the shipped binary what it can actually detect. is_available() is a
    # claim; for the subprocess engines it is a claim they cannot check. The
    # gate fails only on the combination that must never ship -- an engine that
    # says it is present and then finds nothing planted for it.
    Write-Host ""
    Write-Host "  Engines in the built binary:" -ForegroundColor Cyan
    & $guiExe --engines
    if ($LASTEXITCODE -ne 0) {
        throw "Engine probe failed (exit $LASTEXITCODE) - an engine claims to be " +
              "available and did not detect. The build must not ship."
    }

    $mb = [math]::Round((Get-Item $guiExe).Length / 1MB, 1)
    Write-Host ""
    Write-Host "  $guiExe  ($mb MB)" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Not yet verified by this script (4b.5): a first run on a" -ForegroundColor DarkGray
    Write-Host "  machine with no Python, no dev environment variables, and" -ForegroundColor DarkGray
    Write-Host "  no source tree. See docs/TESTING.md." -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "Build complete -> $DIST" -ForegroundColor Green
Write-Host ""
exit 0
