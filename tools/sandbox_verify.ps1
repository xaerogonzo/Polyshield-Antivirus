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
    [switch]$SkipService,

    # Skip the install/uninstall cycle (4c.5). It registers a service, rewrites
    # ACLs under %ProgramData% and then removes both, so it belongs in a
    # throwaway machine and nowhere else.
    [switch]$SkipInstall
)

$ErrorActionPreference = "Continue"
$results = [ordered]@{}
$checks  = [System.Collections.ArrayList]::new()

function ConvertFrom-MixedJson {
    <#
      --engines and --paths print JSON on stdout and a verdict line on stderr.
      Captured with 2>&1 the two are interleaved, and ConvertFrom-Json rejects
      the result -- which is why both engine reports came back null in an
      earlier run while the checks around them looked fine.

      Takes the outermost {...} and parses that.
    #>
    param([string]$Text)
    if (-not $Text) { return $null }
    $start = $Text.IndexOf("{")
    $end = $Text.LastIndexOf("}")
    if ($start -lt 0 -or $end -le $start) { return $null }
    try { return ($Text.Substring($start, $end - $start + 1) | ConvertFrom-Json) }
    catch { return $null }
}

function Add-Check {
    param([string]$Name, [bool]$Pass, $Detail)
    [void]$checks.Add([ordered]@{ name = $Name; pass = $Pass; detail = "$Detail" })
    $tag = if ($Pass) { "PASS" } else { "FAIL" }
    Write-Host ("  [{0}] {1} - {2}" -f $tag, $Name, $Detail)
    # Appended as it happens, not just collected for the final report. A run
    # that hangs writes no verify.json at all, and three of them in a row said
    # nothing about WHERE they stopped -- the last line of this file does.
    try {
        $line = "{0}`t{1}`t{2}" -f $tag, $Name, $Detail
        Add-Content -Path (Join-Path $ResultsDir "progress.log") -Value $line -Encoding UTF8
    } catch { }
}

function Write-Progress-Note {
    param([string]$Note)
    try {
        Add-Content -Path (Join-Path $ResultsDir "progress.log") `
            -Value ("....`tabout to: " + $Note) -Encoding UTF8
    } catch { }
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

# The shared machine-wide root, NOT %LOCALAPPDATA%. Every directory check
# below used to look under the user profile, which is where a distribution put
# its data until v1.16 -- and which the service could never have agreed on.
# Left pointing at the old location, five checks fail on a correct build and
# would pass again the moment the defect came back.
$appData = Join-Path $env:ProgramData "PolyShield"
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
    # NOT %LOCALAPPDATA%. That is what this asserted until v1.16, and it was
    # asserting the defect: %LOCALAPPDATA% differs between the interactive user
    # and the service account, so a root defined from it puts the GUI and the
    # service in two different directories. The check passed for the whole time
    # the product was broken.
    Add-Check "data root is machine-wide (ProgramData), not a user profile" `
        ($results.paths.app_root -like "$env:ProgramData*") $results.paths.app_root
    # The failure this whole phase exists to prevent.
    Add-Check "data root is NOT inside the build" `
        (-not $results.paths.app_root.StartsWith($results.paths.resource_root)) `
        ("app_root=" + $results.paths.app_root)
}

$enginesRaw = & $gui --engines 2>&1 | Out-String
$enginesOk  = $LASTEXITCODE -eq 0
$results.engines = (ConvertFrom-MixedJson $enginesRaw).engines
if (-not $results.engines) { $results.engines_raw = $enginesRaw }
# Exit code is the gate: available-and-did-not-detect is the one combination
# that must never ship. Absent engines reporting absent is correct.
Add-Check "no engine claims availability it cannot back up" $enginesOk "exit $LASTEXITCODE"

# ---------- It actually runs ---------------------------------------------

# Counting USER objects needs a P/Invoke. Declared before the process starts so
# a failure to compile it is a script error here rather than a surprise in the
# middle of the measurement.
Add-Type -Namespace Win32 -Name Gui -MemberDefinition @"
[DllImport("user32.dll")]
public static extern uint GetGuiResources(IntPtr hProcess, uint uiFlags);
"@

$proc = Start-Process -FilePath $gui -PassThru -WindowStyle Minimized
Start-Sleep -Seconds 30
$alive = -not $proc.HasExited
Add-Check "GUI stays running for 30s" $alive `
    ($(if ($alive) { "still up" } else { "exited with $($proc.ExitCode)" }))

# ---------- Startup footprint ---------------------------------------------
#
# A regression guard, not a budget.  Views used to be constructed all at once:
# 4,996 Tk windows and 3,715 USER objects -- 37% of the 10,000 per-process
# quota -- before the user clicked anything.  Every Tk widget is a real HWND on
# the desktop heap, and Tk allocates an offscreen DIB per canvas redraw, so a
# memory-constrained sandbox answered with "Tk_GetPixmap: Error from
# CreateDIBSection / Not enough memory resources are available to process this
# command" -- which reads as an application fault rather than as a machine that
# ran out of room.  Building views on first show took startup to 307.
#
# The gate sits far above the measured value and far below the old one on
# purpose: it is here to catch a return to eager construction, not to police a
# number.  Private bytes are RECORDED, not gated -- 39 MB was measured once on
# one developer machine, and sandbox variation has not been characterised.
# Both figures go into the report so a future failure is diagnosable.

if ($alive) {
    # Measure the process that owns the GUI, which is NOT the one Start-Process
    # handed back. PolyShield.exe is a Nuitka ONEFILE build: the exe launched is
    # a bootstrap that unpacks to a temp directory and runs the real application
    # as a CHILD. The first version of this check measured the bootstrap and
    # reported "1 USER objects, 0 GDI objects, 1.9 MB" while the full GUI was on
    # screen -- and passed, because everything is below 1200. A gate that
    # measures the wrong process is worse than no gate: it is a green check
    # standing where a real one should be.
    #
    # So: walk the whole process tree and take the member with the most USER
    # objects. Every candidate is recorded, because "which process did we
    # measure" is the first question any future failure raises.
    $candidates = @($proc.Id)
    try {
        $pending = @($proc.Id)
        while ($pending.Count -gt 0) {
            $next = @()
            foreach ($parentId in $pending) {
                $kids = @(Get-CimInstance Win32_Process `
                            -Filter "ParentProcessId = $parentId" `
                            -ErrorAction SilentlyContinue |
                          Select-Object -ExpandProperty ProcessId)
                $next += $kids
                $candidates += $kids
            }
            $pending = $next
        }
    } catch { }

    $measured = @()
    foreach ($procId in ($candidates | Select-Object -Unique)) {
        try {
            $p = Get-Process -Id $procId -ErrorAction Stop
            $measured += [ordered]@{
                pid          = $procId
                name         = $p.ProcessName
                user_objects = [int][Win32.Gui]::GetGuiResources($p.Handle, 1)  # GR_USEROBJECTS
                gdi_objects  = [int][Win32.Gui]::GetGuiResources($p.Handle, 0)  # GR_GDIOBJECTS
                private_mb   = [math]::Round($p.PrivateMemorySize64 / 1MB, 1)
            }
        } catch { }
    }

    $gui = $measured | Sort-Object { $_.user_objects } -Descending | Select-Object -First 1
    $userObjects = if ($gui) { [int]$gui.user_objects } else { -1 }
    $gdiObjects  = if ($gui) { [int]$gui.gdi_objects }  else { -1 }
    $privateMB   = if ($gui) { $gui.private_mb }        else { 0 }
    $guiPid      = if ($gui) { $gui.pid }               else { "?" }

    $results.startup_footprint = [ordered]@{
        chosen    = $gui
        processes = $measured
    }

    # The floor carries as much weight as the ceiling. A CustomTkinter window
    # with a sidebar cannot have 1 USER object; that number means the GUI was
    # not found, and must read as a failure rather than as a lean startup.
    Add-Check "startup USER objects between 50 and 1200" `
        ($userObjects -ge 50 -and $userObjects -lt 1200) `
        ("$userObjects USER objects in pid $guiPid, $($measured.Count) process(es) " +
         "in the tree (307 when measured; 3715 with eager views)")

    Add-Check "startup footprint measured" `
        ($privateMB -gt 0) `
        ("$privateMB MB private, $gdiObjects GDI objects in pid $guiPid - recorded, not gated")
}

if ($alive) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 3

# rules\ is deliberately absent from this list. It is created when rules are
# downloaded, not at start-up, so a fresh install legitimately has none -- and
# yara_engine.is_available() reports False for exactly that reason ("0 rule
# file(s)"), which is the honest answer rather than a missing directory. An
# earlier version of this script asserted it and failed, because the developer
# checkout it was written against already had one.
# logs\ and quarantine\ are created at import (scanner.py,
# quarantine.py). config\ and intelligence\ are created on first WRITE,
# which a short unattended run may never trigger -- so their absence is
# recorded rather than failed. On an installed machine the installer creates
# every one of them up front, and the install cycle checks that instead.
foreach ($d in @("logs", "quarantine")) {
    Add-Check "created $d\ at start-up" (Test-Path (Join-Path $appData $d)) (Join-Path $appData $d)
}
$results.lazy_dirs = @{}
foreach ($d in @("config", "intelligence")) {
    $results.lazy_dirs[$d] = (Test-Path (Join-Path $appData $d))
}

# ---------- Persistence across a restart ---------------------------------
# Checking that a directory exists on the second run proves nothing: the app
# would recreate it either way. What has to be shown is that the second launch
# READ what the first one wrote.

# The settings file is SEEDED here rather than waited for. The app writes it
# when a setting changes, and whether that happens during a 30-second
# unattended run is luck -- it did in one run and not the next, and the check
# reported "no settings file was written" as though that were a defect.
#
# Seeding also tests the more valuable property: settings.py re-reads and
# merges before writing, precisely because the service writes this file too,
# so a key it does not know about must survive a save rather than be replaced.
$cfgDir = Join-Path $appData "config"
if (-not (Test-Path $cfgDir)) { New-Item -ItemType Directory -Path $cfgDir -Force | Out-Null }
$cfg = Join-Path $cfgDir "ui_settings.json"
if (-not (Test-Path $cfg)) { Set-Content -Path $cfg -Value "{}" -Encoding UTF8 }
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

# ---------- Install cycle (4c.5) ------------------------------------------
# Everything above verifies the BUILD. This verifies the INSTALLER, which is a
# different artifact with different ways to be wrong: it registers a service,
# rewrites ACLs, and has to be able to undo both.
#
# Skipped with -SkipInstall to check only the half that ships as a binary.

function Invoke-AsSystem {
    <#
      Run a command as the service account and return its output.

      The reason this exists: the data-root invariant is that the GUI and the
      service resolve the SAME directory, and until v1.16 both sides of that
      comparison were run by the interactive user -- so it compared a process
      against itself and could not fail. The service runs as LocalSystem, whose
      profile is C:\Windows\system32\config\systemprofile, and that is the
      account whose answer matters.

      schtasks /ru SYSTEM rather than psexec: no extra tool to ship into the
      sandbox.
    #>
    param([string]$CommandLine, [string]$OutFile)

    $task = "PolyShieldVerifyAsSystem"
    # Written to a LOCAL path first. C:\PolyShield_results is a Sandbox mapped
    # folder, and SYSTEM does not see the interactive user's mappings -- the
    # redirect silently produced nothing, and the check reported "system=?".
    $localOut = Join-Path $env:SystemRoot "Temp\polyshield_assystem.txt"
    Remove-Item $localOut -Force -ErrorAction SilentlyContinue
    # A .cmd wrapper rather than nested quotes inside /tr, which schtasks parses
    # unforgivingly.
    $wrapper = Join-Path $env:SystemRoot "Temp\polyshield_assystem.cmd"
    Set-Content -Path $wrapper -Encoding ASCII -Value "@echo off`r`n$CommandLine > `"$localOut`" 2>&1"
    & schtasks /create /tn $task /tr "`"$wrapper`"" `
        /sc once /st 23:59 /ru SYSTEM /rl HIGHEST /f *> $null
    & schtasks /run /tn $task *> $null
    $deadline = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 500
        $q = & schtasks /query /tn $task /fo LIST 2>&1 | Out-String
        if ($q -notmatch "Running") { break }
    }
    & schtasks /delete /tn $task /f *> $null
    if (Test-Path $localOut) {
        Copy-Item $localOut $OutFile -Force -ErrorAction SilentlyContinue
        return (Get-Content $localOut -Raw)
    }
    return ""
}

function Get-ServiceState {
    param([string]$Name)
    $q = & sc.exe query $Name 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { return "ABSENT" }
    if ($q -match "RUNNING") { return "RUNNING" }
    if ($q -match "STOPPED") { return "STOPPED" }
    return "UNKNOWN"
}

function Wait-ServiceState {
    param([string]$Name, [string]$Want, [int]$Seconds = 45)
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        if ((Get-ServiceState $Name) -eq $Want) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

if (-not $SkipInstall) {
    Write-Host ""
    Write-Host "=== Install cycle ===" -ForegroundColor Cyan

    $setup = Get-ChildItem $DistDir -Filter "PolyShield-Setup-*.exe" -ErrorAction SilentlyContinue |
             Sort-Object Name -Descending | Select-Object -First 1
    Add-Check "installer present" ([bool]$setup) `
        ($(if ($setup) { $setup.Name } else { "no PolyShield-Setup-*.exe in $DistDir" }))

    if ($setup) {
        $appDir  = Join-Path ${env:ProgramFiles} "PolyShield"
        $dataDir = Join-Path $env:ProgramData "PolyShield"
        $svcName = "PolyShieldService"

        # -- A dirty machine, on purpose -------------------------------------
        # A failed install leaves a registered service behind, and the next
        # attempt has to be able to recover rather than compounding it. Rather
        # than racing a kill against the installer, the dirty state is created
        # deterministically: a service registered under our name pointing at a
        # binary that does not exist.
        & sc.exe create $svcName binPath= "C:\does\not\exist.exe" start= demand *> $null
        $dirty = (Get-ServiceState $svcName) -ne "ABSENT"
        Add-Check "dirty prior state created" $dirty "a stale $svcName registration"

        # -- Install ----------------------------------------------------------
        Write-Progress-Note "run the silent install"
        $p = Start-Process -FilePath $setup.FullName `
            -ArgumentList "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/NOCANCEL" `
            -Wait -PassThru
        Add-Check "silent install over a dirty machine succeeded" ($p.ExitCode -eq 0) `
            "exit $($p.ExitCode)"

        # Bounded wait, not a bare Test-Path: Inno can return from /VERYSILENT
        # a moment before the last file is closed. The check still fails if the
        # file never appears -- it just does not fail for being early.
        $exeDeadline = (Get-Date).AddSeconds(30)
        while (((Get-Date) -lt $exeDeadline) -and
               -not (Test-Path (Join-Path $appDir "PolyShield.exe"))) {
            Start-Sleep -Milliseconds 500
        }
        Add-Check "program files installed" (Test-Path (Join-Path $appDir "PolyShield.exe")) $appDir
        Add-Check "runtime installed" (Test-Path (Join-Path $appDir "runtime\python.exe")) "runtime\"
        Add-Check "service source installed" `
            (Test-Path (Join-Path $appDir "service\polyshield_service.py")) "service\"
        Add-Check "distribution marker installed" `
            (Test-Path (Join-Path $appDir "service\.polyshield-distribution")) ".polyshield-distribution"

        # -- Registered is not running ----------------------------------------
        $running = Wait-ServiceState $svcName "RUNNING"
        Add-Check "service reaches RUNNING" $running (Get-ServiceState $svcName)
        if (-not $running) {
            $results.service_queryex = (& sc.exe queryex $svcName 2>&1 | Out-String)
        }

        # -- The invariant, from the account that actually differs ------------
        $guiRaw = & (Join-Path $appDir "PolyShield.exe") --paths 2>&1 | Out-String
        $sysOut = Join-Path $ResultsDir "system_paths.txt"
        Write-Progress-Note "query the service as SYSTEM"
        $sysRaw = Invoke-AsSystem `
            -CommandLine ("`"$appDir\runtime\python.exe`" `"$appDir\service\polyshield_service.py`" --paths") `
            -OutFile $sysOut
        $gui = ConvertFrom-MixedJson $guiRaw
        $sys = ConvertFrom-MixedJson $sysRaw
        $results.installed_paths = @{ gui = $gui; system = $sys }

        Add-Check "GUI and the SYSTEM-context service agree on the data root" `
            ([bool]$gui -and [bool]$sys -and $gui.app_root -eq $sys.app_root) `
            ("gui=" + $(if ($gui) { $gui.app_root } else { "?" }) +
             " system=" + $(if ($sys) { $sys.app_root } else { "?" }))

        Add-Check "the shared root is machine-wide, not a user profile" `
            ([bool]$gui -and $gui.app_root -like "*ProgramData*") `
            $(if ($gui) { $gui.app_root } else { "?" })

        # -- Nothing was put in System32 --------------------------------------
        # No pywin32_postinstall: the staged runtime carries its own DLLs, so
        # uninstall never has to reason about a shared system component.
        $sys32 = @("pywintypes312.dll", "pythoncom312.dll") |
                 Where-Object { Test-Path (Join-Path $env:SystemRoot "System32\$_") }
        Add-Check "nothing installed into System32" ($sys32.Count -eq 0) `
            ($(if ($sys32) { $sys32 -join ", " } else { "no pywin32 DLLs in System32" }))

        # -- The Explorer verb names something that exists --------------------
        $cmdKey = "Registry::HKEY_CURRENT_USER\Software\Classes\*\shell\PolyShield\command"
        # GetValue("") -- the DEFAULT value has an empty name. Reading it as a
        # property called "(default)" returned System.Object[], which is truthy,
        # so the icon check passed on it while proving nothing.
        # OpenSubKey on the hive, not the provider item: Get-Item returns a
        # provider object whose GetValue("") does not yield the default value,
        # and the check reported the key PATH as though it were the command.
        $verb = $null
        $hkcu = [Microsoft.Win32.Registry]::CurrentUser
        $k = $hkcu.OpenSubKey("Software\Classes\*\shell\PolyShield\command")
        if ($k) { $verb = $k.GetValue(""); $k.Close() }
        $verbExe = ""
        if ($verb -and $verb -match '^"([^"]+)"') { $verbExe = $Matches[1] }
        Add-Check "context-menu command names a file that exists" `
            ([bool]$verbExe -and (Test-Path $verbExe)) `
            ($(if ($verb) { $verb } else { "no HKCU verb registered" }))

        $iconKey = "Registry::HKEY_CURRENT_USER\Software\Classes\*\shell\PolyShield"
        $icon = $null
        $k2key = $hkcu.OpenSubKey("Software\Classes\*\shell\PolyShield")
        if ($k2key) { $icon = $k2key.GetValue("Icon"); $k2key.Close() }
        Add-Check "context-menu icon names a file that exists" `
            ([bool]$icon -and (Test-Path $icon)) `
            ($(if ($icon) { $icon } else { "no Icon value" }))

        # -- Engines, from the installed copy ---------------------------------
        $enginesRaw = & (Join-Path $appDir "PolyShield.exe") --engines 2>&1 | Out-String
        $enginesOk = $LASTEXITCODE -eq 0
        $results.installed_engines = (ConvertFrom-MixedJson $enginesRaw).engines
        if (-not $results.installed_engines) { $results.installed_engines_raw = $enginesRaw }
        Add-Check "no engine claims availability it cannot back up" $enginesOk "exit $LASTEXITCODE"
        $k2 = $results.installed_engines.k2
        # Whether the installer actually seeded k2's rule archives. K2 carries
        # only 23 of its ~1263 signatures in its plugin modules; the rest arrive
        # in archives it downloads, so an install that skips this ships the
        # primary signature engine at under 2% of its detection -- and nothing
        # in the running product reports that as wrong.
        #
        # The seed step runs `runhidden`, so it says what it did in a log rather
        # than on a screen nobody is looking at.
        $seedLog = Join-Path $dataDir "logs\k2_seed.log"
        if (Test-Path $seedLog) {
            $results.k2_seed_log = (Get-Content $seedLog -Raw)
            Copy-Item $seedLog (Join-Path $ResultsDir "k2_seed.log") -Force -EA SilentlyContinue
        } else {
            $results.k2_seed_log = "NOT WRITTEN - seed_k2_rules.ps1 never ran"
        }
        $seedUpdateLog = Join-Path $dataDir "logs\k2_seed_update.log"
        if (Test-Path $seedUpdateLog) {
            Copy-Item $seedUpdateLog (Join-Path $ResultsDir "k2_seed_update.log") -Force -EA SilentlyContinue
        }
        $k2Rules = Join-Path $dataDir "k2\rules"
        $k2Manifest = Join-Path $k2Rules "update.cfg"
        $seeded = Test-Path $k2Manifest
        Add-Check "the installer seeded k2 rule archives" $seeded `
            ($(if ($seeded) {
                   "$((Get-ChildItem $k2Rules -Recurse -File -EA SilentlyContinue).Count) file(s)"
               } else { "no update.cfg -- see k2_seed.log" }))

        Add-Check "k2 ships and detects" `
            ([bool]$k2 -and $k2.available -and $k2.detected) `
            ($(if ($k2) { $k2.detail } else { "k2 not reported" }))

        # -- A scheduled scan can actually be created -------------------------
        # The 4c.1 fix, end to end. script_launch_argv() raised in any frozen
        # build before it, so scheduler.create_task() could not create a task at
        # all in a shipped product -- and the Scheduler view showed nothing
        # useful, because the exception died on a worker thread that had already
        # disabled the button.
        #
        # Driven through the staged runtime with the service tree on sys.path:
        # the same resolution path the installed service uses.
        $schedPy = @"
import sys
sys.path.insert(0, r'$appDir\service\src')
from ui.core import scheduler
ok, msg = scheduler.create_task(r'C:\Users\Public', 'DAILY', '03:00')
print('OK' if ok else 'FAIL', msg)
"@
        $schedFile = Join-Path $ResultsDir "make_task.py"
        Set-Content -Path $schedFile -Value $schedPy -Encoding UTF8
        $schedOut = & (Join-Path $appDir "runtime\python.exe") $schedFile 2>&1 | Out-String
        $results.scheduled_task_create = $schedOut
        Add-Check "a scheduled scan can be created from an installed build" `
            ($schedOut -match "OK") ($schedOut.Trim())

        $taskCmd = & schtasks /query /tn "PolyShield_ScheduledScan" /fo LIST /v 2>&1 | Out-String
        Add-Check "the scheduled task exists" ($taskCmd -match "PolyShield_ScheduledScan") `
            ($(if ($taskCmd -match "PolyShield_ScheduledScan") { "registered" } else { "not found" }))

        # The command it registers has to still be valid months later, so it must
        # name the staged runtime and the staged script -- never a onefile
        # extraction directory, which is gone the moment the process exits.
        Add-Check "the task runs the staged runtime, not a temp directory" `
            ($taskCmd -match [regex]::Escape("runtime\python.exe")) `
            "task command references runtime\python.exe"

        # -- The privilege boundary, read from the ACL itself ------------------
        # icacls rather than "try to write as a restricted user". runas
        # /trustlevel starts a DETACHED process in its own console: the output
        # never came back, and an empty result satisfied a "contains no [FAIL]"
        # test -- passing for exactly the reason this phase exists to remove.
        #
        # Reading the ACE is also the stronger statement. It says what the
        # directory grants, rather than what one particular token could do with
        # it on one particular machine.
        function Get-UsersAce {
            param([string]$Dir)
            $raw = & icacls $Dir 2>&1 | Out-String
            foreach ($line in $raw -split "`r?`n") {
                if ($line -match "BUILTIN\\Users:\(([^)]*(\)\()?[^)]*)\)*") {
                    return $line.Trim()
                }
            }
            return ""
        }

        $serviceOwned = @("intelligence", "state", "guardianai", "rules\community", "k2\rules")
        $userWritable = @("config", "logs", "telemetry", "quarantine", "rules\user_rules")
        $aclReport = @{}
        $aclBad = @()

        foreach ($rel in ($serviceOwned + $userWritable)) {
            $dir = Join-Path $dataDir $rel
            if (-not (Test-Path $dir)) { $aclBad += "$rel (missing)"; continue }
            $ace = Get-UsersAce $dir
            $aclReport[$rel] = $ace
            # (M) modify, (W) write, (F) full. Any of them means an ordinary
            # user can rewrite what is in there.
            $writable = $ace -match "\((M|W|F)\)"
            $shouldWrite = $userWritable -contains $rel
            if ($writable -ne $shouldWrite) {
                $aclBad += ("$rel is " + $(if ($writable) { "writable" } else { "read-only" }) +
                            ", expected " + $(if ($shouldWrite) { "writable" } else { "read-only" }))
            }
        }
        $results.acl_users_aces = $aclReport
        Add-Check "intelligence is not writable by ordinary users" `
            ($aclBad.Count -eq 0) `
            ($(if ($aclBad) { $aclBad -join "; " } else { "all 10 subtrees on the correct side" }))


        # An ordinary user must not be able to rewrite what the service trusts.
        # Checked directly as well, because the probe above is our own script.
        $intelDir = Join-Path $dataDir "intelligence"
        $canWrite = $false
        try {
            $t = Join-Path $intelDir "verify_probe.tmp"
            [System.IO.File]::WriteAllText($t, "x")
            Remove-Item $t -Force -ErrorAction SilentlyContinue
            $canWrite = $true
        } catch { $canWrite = $false }
        # The sandbox logon account is an administrator, so this is only
        # meaningful as a record of what an ELEVATED caller can do.
        $results.intelligence_writable_when_elevated = $canWrite

        # -- Idempotency -------------------------------------------------------
        Write-Progress-Note "reinstall over the existing install"
        $p2 = Start-Process -FilePath $setup.FullName `
            -ArgumentList "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/NOCANCEL" `
            -Wait -PassThru
        Add-Check "installing over an existing install succeeds" ($p2.ExitCode -eq 0) `
            "exit $($p2.ExitCode)"
        Add-Check "service still RUNNING after reinstall" `
            (Wait-ServiceState $svcName "RUNNING") (Get-ServiceState $svcName)

        # -- Data survives, program state goes --------------------------------
        # Something the user would recognise, to prove retention is real rather
        # than "the directory still exists".
        $sentinel = Join-Path $dataDir "quarantine\sentinel.txt"
        try { Set-Content -Path $sentinel -Value "keep me" -ErrorAction Stop } catch {}

        $uninst = Get-ChildItem $appDir -Filter "unins*.exe" -ErrorAction SilentlyContinue |
                  Select-Object -First 1
        Add-Check "uninstaller present" ([bool]$uninst) `
            ($(if ($uninst) { $uninst.Name } else { "no unins*.exe in $appDir" }))

        if ($uninst) {
            # Bounded. An uninstall CAN hang: leave the service registered and
            # running -- which is what a failed --unregister does -- and Inno's
            # CloseApplications finds {app}
untime\python.exe in use and waits
            # on Restart Manager forever. Observed: a run sat idle at 0% CPU for
            # twenty minutes and produced no report at all, so a single hang cost
            # every check after it.
        Write-Progress-Note "run the uninstaller"
            $pu = Start-Process -FilePath $uninst.FullName `
                -ArgumentList "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART" -PassThru
            if (-not $pu.WaitForExit(240000)) {
                Add-Check "silent uninstall completes" $false `
                    "still running after 240s -- killed; check whether the service was left registered"
                Stop-Process -Id $pu.Id -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 3
            } else {
                Add-Check "silent uninstall completes" ($pu.ExitCode -eq 0) "exit $($pu.ExitCode)"
            }

            Add-Check "service removed" `
                (Wait-ServiceState $svcName "ABSENT" 30) (Get-ServiceState $svcName)
            Add-Check "context-menu verb removed" (-not (Test-Path $cmdKey)) "HKCU verb"
            # Exit code, NOT the text. `schtasks /query` for a missing task
            # prints ERROR: ... "PolyShield_ScheduledScan" does not exist --
            # which CONTAINS the task name, so a -notmatch test reported the
            # task present precisely when it had been removed. The uninstall
            # report said "scheduled task removed" while this said otherwise.
            & schtasks /query /tn "PolyShield_ScheduledScan" *> $null
            $taskGone = ($LASTEXITCODE -ne 0)
            Add-Check "scheduled task removed" $taskGone "PolyShield_ScheduledScan"

            # What --unregister reported, if it ran at all. Written by the exe
            # itself (app.py --unregister), so an uninstall that did nothing is
            # distinguishable from one that never ran.
            $unregLog = Join-Path $dataDir "logs\unregister.json"
            if (Test-Path $unregLog) {
                # [string] is load-bearing. Get-Content returns its text with
                # PSPath / PSProvider note-properties attached, and
                # ConvertTo-Json follows them: a 374-byte report serialised the
                # provider internals as well and produced a 102 MB verify.json,
                # which is not a report anyone can read.
                $results.unregister_report = [string](Get-Content $unregLog -Raw)
                Copy-Item $unregLog (Join-Path $ResultsDir "unregister.json") -Force -ErrorAction SilentlyContinue
            } else {
                $results.unregister_report = "NOT WRITTEN - the exe never ran --unregister"
            }

            # The one that matters most: quarantine may hold the only copy of a
            # file somebody wants back, so it is kept unless explicitly asked
            # for. The checkbox defaults to unticked and /VERYSILENT never ticks it.
            Add-Check "user data survives an uninstall" (Test-Path $sentinel) $sentinel
            Add-Check "shared data root survives an uninstall" (Test-Path $dataDir) $dataDir
        }
    }
}

# ---------- Report --------------------------------------------------------

$results.checks    = $checks
$results.passed    = @($checks | Where-Object { $_.pass }).Count
$results.failed    = @($checks | Where-Object { -not $_.pass }).Count
$results.timestamp = (Get-Date).ToString("s")

$out = Join-Path $ResultsDir "verify.json"
# The findings first, unconditionally. The richer report is attempted after,
# and is allowed to fail.
[ordered]@{
    checks = $checks
    passed = @($checks | Where-Object { $_.pass }).Count
    failed = @($checks | Where-Object { -not $_.pass }).Count
    # Carried in the guaranteed report too. These are the fields that explain a
    # failure rather than restate it, and they were lost every time the richer
    # report did not serialise.
    engines = $results.engines
    installed_engines = $results.installed_engines
    installed_engines_raw = $results.installed_engines_raw
    unregister_report = $results.unregister_report
    # Same reasoning, measured the hard way: the richer report has never once
    # survived serialisation, so a field that only lives there does not exist.
    # The footprint numbers are the whole point of the check that produces
    # them -- a future regression is diagnosed by comparing them, not by
    # re-reading "pass".
    startup_footprint = $results.startup_footprint
} | ConvertTo-Json -Depth 6 | Set-Content $out -Encoding UTF8
Write-Host "  checks written -> $out" -ForegroundColor DarkGray

try {
    $results | ConvertTo-Json -Depth 8 | Set-Content $out -Encoding UTF8
} catch {
    # Never lose the findings to a serialisation problem. Run 7 completed every
    # check and wrote no verify.json at all, which read from outside exactly
    # like a hang.
    Write-Host "  ConvertTo-Json failed: $($_.Exception.Message)" -ForegroundColor Red
    [ordered]@{
        checks = $checks
        passed = @($checks | Where-Object { $_.pass }).Count
        failed = @($checks | Where-Object { -not $_.pass }).Count
        note   = "reduced report; full results failed to serialise"
    } | ConvertTo-Json -Depth 6 | Set-Content $out -Encoding UTF8
}

Write-Host ""
Write-Host ("=== {0} passed, {1} failed -> {2}" -f $results.passed, $results.failed, $out) `
    -ForegroundColor $(if ($results.failed -eq 0) { "Green" } else { "Red" })
Write-Host ""
Write-Host "This window stays open so the results can be read on screen too."
Write-Host "The sandbox discards everything when it closes."
