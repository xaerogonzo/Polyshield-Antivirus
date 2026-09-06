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
#   4b.3  scheduled-scan exe                        <- not needed: it stages
#         beside the service and shares its runtime
#   4b.4  optional engines, one at a time           <- implemented (--engines)
#   4b.5  clean Windows Sandbox run                 <- implemented
#         (tools/make_sandbox_wsb.py)
#   4b.6  size and startup tuning                   <- implemented
#   4c.2  the runtime builds itself (-BuildRuntime) <- implemented
#
# CORRECTNESS BEFORE OPTIMIZATION, and 4b.6 keeps to it: one variable per
# build, each re-verified against the 4b.5 sandbox run before the next is
# added. -Onefile is the first, because it is the only one that changes runtime
# behaviour rather than just file size -- it introduces the temporary
# extraction directory that resource_root() has to survive.
#
# UPX is deliberately NOT offered. Packing an antivirus binary is a textbook
# Defender heuristic; the product would spend its life being quarantined by the
# competition. See docs/ARCHITECTURE.md.
# =============================================================================

[CmdletBinding()]
param(
    # gui | probe | all
    [ValidateSet("gui", "service", "probe", "installer", "all")]
    [string]$Target = "all",

    # Skip the destructive clean. Only for iterating on a single target.
    [switch]$NoClean,

    # A Python runtime to stage beside the source-mode service. The service
    # cannot be compiled (see docs/ARCHITECTURE.md), so a distribution has to
    # carry an interpreter for it. Prepare one with:
    #
    #   <python>\python.exe -m pip install pywin32 psutil watchdog
    #
    # Left empty the service is staged without a runtime, which is fine for a
    # GUI-only build and is reported rather than assumed.
    [string]$Runtime = "",

    # Build the runtime instead of being handed one. Downloads the pinned
    # python.org embeddable distribution, enables the one line that makes it
    # able to import anything, and installs the service dependencies plus
    # kicomav. See New-StagedRuntime.
    [switch]$BuildRuntime,

    # Build the GUI as a single self-extracting executable. This is the form
    # that ships: 26 MB against a 105 MB folder. Off by default because a
    # standalone tree is far easier to inspect when something is wrong -- you
    # can look at what actually got bundled.
    #
    # It changes runtime behaviour, not just size: the modules are unpacked to
    # a temporary directory that is DIFFERENT ON EVERY RUN and deleted on exit.
    # resource_root() therefore has to come from the module tree rather than
    # from the executable's location, and app_root() must not live under it.
    # Verified on a clean machine, both layouts: see docs/ARCHITECTURE.md.
    [switch]$Onefile
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
               "Close any running PolyShield.exe and retry; do not build over it. " +
               "A Windows Sandbox started from tools\make_sandbox_wsb.py also " +
               "holds dist\ open -- it maps the directory read-only, and the " +
               "handle survives until the sandbox itself is closed.")
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

# ---------- Runtime construction (4c.2) --------------------------------------
# The service does not survive the compiler, so a distribution carries an
# interpreter for it -- and, since 4c.1, k2.exe rides that same runtime rather
# than shipping a second copy of Python.
#
# Until now -Runtime took a directory the developer had prepared by hand, which
# means the release artifact depended on a machine state nobody recorded. This
# builds it, from a pinned download, with every assumption asserted.

#: python.org embeddable distribution. Pinned by hash: the build must fail
#: closed on a changed file rather than staging whatever arrived.
$RUNTIME_VERSION = "3.12.7"
$RUNTIME_SHA256  = "0D57BB6CB078B74D23DBFE91F77D6780D45BED328911609F1F7EE2BA1606BF44"
$RUNTIME_PKGS    = @("pywin32", "psutil", "watchdog", "kicomav")

function Get-Sha256 {
    param([string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        return [System.BitConverter]::ToString($sha.ComputeHash($stream)).Replace("-", "")
    } finally {
        $stream.Dispose()
        $sha.Dispose()
    }
}

function New-StagedRuntime {
    param([string]$Dest)

    $tag = "python-$RUNTIME_VERSION-embed-amd64"
    $url = "https://www.python.org/ftp/python/$RUNTIME_VERSION/$tag.zip"
    $zip = Join-Path ([System.IO.Path]::GetTempPath()) "$tag.zip"

    Write-Host ""
    Write-Host "  Building runtime ($RUNTIME_VERSION) ..." -ForegroundColor Cyan

    if (-not (Test-Path $zip)) {
        Write-Host "  [runtime] downloading $tag.zip" -ForegroundColor DarkGray
        Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
    }

    # .NET rather than Get-FileHash / Expand-Archive: both live in modules that
    # are auto-loaded from $env:PSModulePath, and a Windows PowerShell 5.1 child
    # launched from a PowerShell 7 session inherits PS7 module paths and cannot
    # find them. Measured -- "The term Get-FileHash is not recognized" from a
    # build started inside pwsh. The build must not depend on which shell
    # happened to launch it.
    $got = Get-Sha256 $zip
    if ($got -ne $RUNTIME_SHA256) {
        Remove-Item $zip -Force -ErrorAction SilentlyContinue
        throw ("Runtime hash mismatch for $tag.zip`n" +
               "  expected $RUNTIME_SHA256`n" +
               "  got      $got`n" +
               "Verify against python.org before changing the pin.")
    }
    Write-Host "  [runtime] hash verified" -ForegroundColor DarkGray

    if (Test-Path $Dest) { Remove-Item $Dest -Recurse -Force }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zip, $Dest)

    # THE load-bearing line. The embeddable distribution ships `import site`
    # COMMENTED OUT, and with it commented out a ._pth file replaces sys.path
    # wholesale: Lib\site-packages never joins it, so nothing pip installs here
    # can be imported at all. pywin32 then fails at SCM start as error 1053,
    # and every explanation of 1053 in our own docs points somewhere else.
    #
    # Measured, both ways: with the line commented, sys.path holds only
    # python312.zip and the runtime directory, and `import pythoncom` raises
    # ModuleNotFoundError.
    $pth = Get-ChildItem $Dest -Filter "python*._pth" | Select-Object -First 1
    if (-not $pth) { throw "No python*._pth in the expanded runtime." }
    (Get-Content $pth.FullName) -replace '^\s*#\s*import\s+site\s*$', 'import site' |
        Set-Content $pth.FullName -Encoding ASCII
    if (-not (Select-String -Path $pth.FullName -Pattern '^import site$' -Quiet)) {
        throw "Could not enable 'import site' in $($pth.Name); the runtime would import nothing."
    }
    Write-Host "  [runtime] import site enabled" -ForegroundColor DarkGray

    # pip is absent from the embeddable distribution. Installed with the build
    # environment's own pip rather than fetching get-pip.py -- one less
    # unpinned download, and pip is importable from site-packages once the
    # line above is in place.
    $sitePackages = Join-Path $Dest "Lib\site-packages"
    & $PYTHON -m pip install --quiet --disable-pip-version-check `
        --target $sitePackages pip
    if ($LASTEXITCODE -ne 0) { throw "Could not seed pip into the runtime." }

    $rtPython = Join-Path $Dest "python.exe"
    & $rtPython -m pip install --quiet --disable-pip-version-check `
        --no-warn-script-location @RUNTIME_PKGS
    if ($LASTEXITCODE -ne 0) { throw "Could not install $($RUNTIME_PKGS -join ', ')." }

    Write-Host "  [runtime] installed: $($RUNTIME_PKGS -join ', ')" -ForegroundColor DarkGray
    return $Dest
}

function Test-StagedRuntime {
    param([string]$Dir)

    $rtPython = Join-Path $Dir "python.exe"
    if (-not (Test-Path $rtPython)) { throw "No python.exe under '$Dir'." }

    # Asserted, not assumed: a runtime missing the service's dependencies
    # stages silently and then fails when the SCM starts the service, which is
    # the worst possible place to find out.
    $probe = & $rtPython -c @"
import json, os, sys
import win32serviceutil, psutil, watchdog, kicomav
import pythoncom
print(json.dumps({
    'pythoncom': pythoncom.__file__,
    'site_packages_on_path': any('site-packages' in p for p in sys.path),
}))
"@ 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Staged runtime cannot import the service dependencies: $probe"
    }
    $info = $probe | Select-Object -Last 1 | ConvertFrom-Json

    # pywin32 must load its DLLs from the runtime's own pywin32_system32, NOT
    # from System32. That is what lets the installer skip pywin32_postinstall
    # entirely -- so the uninstaller never has to reason about who else on the
    # machine is using a shared copy in a system directory.
    if ($info.pythoncom -notlike "*pywin32_system32*") {
        throw ("pywin32 resolved $($info.pythoncom), outside the runtime. " +
               "The build must not depend on a System32 installation.")
    }
    Write-Host "  [runtime] pywin32 loads from the runtime, not System32" -ForegroundColor DarkGray

    # K2 keeps its signatures inside its plugins and is asked to list them: a
    # plugin tree that did not survive still starts, exits zero and reports
    # every scan clean. See tools/engine_probe.py.
    $k2 = Join-Path $Dir "Scripts\k2.exe"
    if (-not (Test-Path $k2)) { throw "No k2.exe in the staged runtime." }
    $sigs = (& $k2 --vlist --no-color 2>&1 | Select-String -Pattern "\[kicomav\.plugins\." ).Count
    if ($sigs -lt 100) {
        throw "Staged k2 lists only $sigs signature(s); its plugin tree did not survive."
    }
    Write-Host "  [runtime] k2: $sigs signatures across the loaded plugins" -ForegroundColor DarkGray
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
    # PolyBedrock is installed as an editable package during development, which
    # Nuitka cannot always follow statically -- the __editable__ finder resolves
    # at import time. Named explicitly rather than as --include-package=polybedrock
    # because `polybedrock` is a PEP 420 namespace shared by two distributions and
    # naming the namespace is the less predictable of the two spellings.
    "--include-module=polybedrock.ps_run",
    "--include-module=polybedrock.win_security",
    "--include-module=polybedrock.settings",
    "--include-module=polybedrock.ui.theme",
    "--output-filename=PolyShield.exe",
    # attach, not disable. `disable` would take stdout with it, and this binary
    # is also its own diagnostic tool -- PolyShield.exe --paths / --engines are
    # what a support conversation starts with. `attach` gives no console window
    # when double-clicked and full output when run from a shell.
    "--windows-console-mode=attach"
)
if ($Onefile) { $guiArgs += "--onefile" }

# An icon.ico beside this script is picked up automatically; none is committed,
# so the build simply does not pass the flag rather than failing.
$ICON = Join-Path $ROOT "icon.ico"
if (Test-Path $ICON) { $guiArgs += "--windows-icon-from-ico=$ICON" }

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
    # ui.core.{ps_run,win_security,settings} are aliases for these; without them
    # the service compiles cleanly and then cannot start, which is the same
    # failure --include-package=ui.core exists to prevent.
    # polybedrock.ui.theme is deliberately absent: it would pull customtkinter back
    # in past the nofollow above.
    "--include-module=polybedrock.ps_run",
    "--include-module=polybedrock.win_security",
    "--include-module=polybedrock.settings",
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

    # Removed before copying, not merged onto. Copy-Item -Recurse copies the
    # source INTO an existing destination rather than merging with it, so a
    # second run produced dist\service\src\ui\core\core\ and left the
    # original tree STALE -- a distribution shipping last week source under
    # this week version number, silently. Only -NoClean builds hit it, which
    # is exactly the iteration path where it is least likely to be noticed.
    #
    # Found by installer\register_service.ps1 -PreflightOnly, which asks the
    # staged service to resolve its own paths and got an AttributeError for a
    # function that had been added days earlier.
    foreach ($sub in @("ui\core", "tools")) {
        $dest = Join-Path $svcSrc $sub
        if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
    }
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

    $rtDest = Join-Path $DIST "runtime"
    if ($BuildRuntime) {
        New-StagedRuntime -Dest $rtDest | Out-Null
        Test-StagedRuntime -Dir $rtDest
        Write-Host "  Runtime built and verified -> $rtDest" -ForegroundColor Green
    } elseif ($Runtime) {
        if (-not (Test-Path (Join-Path $Runtime "python.exe"))) {
            throw "No python.exe under -Runtime '$Runtime'."
        }
        Copy-Item $Runtime $rtDest -Recurse -Force
        Test-StagedRuntime -Dir $rtDest
        Write-Host "  Runtime staged and verified -> $rtDest" -ForegroundColor Green
    } else {
        Write-Host "  Runtime NOT staged: pass -BuildRuntime to build one, or" -ForegroundColor DarkGray
        Write-Host "  -Runtime <dir> to stage one you prepared. Without it the" -ForegroundColor DarkGray
        Write-Host "  service cannot run and k2 does not ship." -ForegroundColor DarkGray
    }
}

if ($Target -in @("probe", "all")) {
    Invoke-Nuitka -Script (Join-Path $ROOT "tools\build_probe.py") `
                  -ExtraArgs $probeArgs -Label "build_probe.exe"
}

if ($Target -eq "installer") {
    # ISCC is an external toolchain, so its absence is reported the way the
    # Nuitka pre-flight reports its own rather than failing somewhere obscure.
    $isccCandidates = @(
        (Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"),
        (Join-Path $env:ProgramFiles "Inno Setup 6\ISCC.exe"),
        # winget installs Inno per-user by default, which is where it actually
        # landed on the machine this was first run on -- measured, after a
        # "Successfully installed" that put nothing in either Program Files.
        (Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 6\ISCC.exe")
    )
    $ISCC = $isccCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $ISCC) {
        $found = Get-Command ISCC.exe -ErrorAction SilentlyContinue
        if ($found) { $ISCC = $found.Source }
    }
    if (-not $ISCC) {
        throw ("Inno Setup not found. Install it and retry:" + [Environment]::NewLine +
               "    winget install JRSoftware.InnoSetup" + [Environment]::NewLine +
               "Looked in: " + ($isccCandidates -join "; ") + " and PATH.")
    }

    # The payload has to be complete before it is packaged: an installer built
    # from a half-built dist\ produces a setup program that installs a product
    # which cannot start, and does it without complaining.
    $required = @(
        (Join-Path $DIST "PolyShield.exe"),
        (Join-Path $DIST "runtime\python.exe"),
        (Join-Path $DIST "service\polyshield_service.py"),
        (Join-Path $DIST "service\.polyshield-distribution")
    )
    $missing = $required | Where-Object { -not (Test-Path $_) }
    if ($missing) {
        throw ("dist\ is incomplete; build it first with" + [Environment]::NewLine +
               "    build.bat -BuildRuntime -Onefile -Target all" + [Environment]::NewLine +
               "Missing: " + ($missing -join "; "))
    }

    Write-Host ""
    Write-Host "  Compiling the installer ..." -ForegroundColor Cyan
    $iss = Join-Path $ROOT "installer\polyshield.iss"

    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & $ISCC $iss 2>&1 | ForEach-Object { Write-Host $_ }
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prevEAP
    }
    if ($code -ne 0) { throw "ISCC failed (exit $code)." }

    $setup = Get-ChildItem $DIST -Filter "PolyShield-Setup-*.exe" |
             Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($setup) {
        $mb = [math]::Round($setup.Length / 1MB, 1)
        Write-Host ""
        Write-Host "  $($setup.FullName)  ($mb MB)" -ForegroundColor Green
    }
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

# onefile drops a single exe at the top of dist\; standalone nests it.
$guiExe = if ($Onefile) { Join-Path $DIST "PolyShield.exe" }
          else { Join-Path $DIST "app.dist\PolyShield.exe" }
if (Test-Path $guiExe) {
    # Ask the shipped binary what it can actually detect. is_available() is a
    # claim; for the subprocess engines it is a claim they cannot check. The
    # gate fails only on the combination that must never ship -- an engine that
    # says it is present and then finds nothing planted for it.
    Write-Host ""
    Write-Host "  Engines in the built binary:" -ForegroundColor Cyan
    # PIPED, and that is not cosmetic. --windows-console-mode=attach produces a
    # GUI-subsystem binary, and PowerShell does not wait for those: the bare
    # `& $guiExe --engines` this replaced returned instantly, left
    # $LASTEXITCODE holding the PREVIOUS command's value, and printed the
    # engine probe's "FAIL:" line asynchronously after "Build complete".
    #
    # So this gate -- the one whose comment says the build must not ship --
    # never fired once between 4b.4 and 4c.5. Measured: unpiped 0, piped 1,
    # Start-Process -Wait 1, for the same binary and the same failure.
    # Consuming the output stream is what makes PowerShell wait for it.
    # ErrorActionPreference relaxed for the same reason Invoke-Nuitka relaxes
    # it: the probe writes its verdict to stderr, and with "Stop" in force
    # PowerShell turns that line into a NativeCommandError and aborts with its
    # own message instead of the one below.
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $engineOut = & $guiExe --engines 2>&1 | Out-String
    } finally {
        $ErrorActionPreference = $prevEAP
    }
    Write-Host $engineOut
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
