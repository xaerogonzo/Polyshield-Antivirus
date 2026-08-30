# =============================================================================
# seed_k2_rules.ps1 - fetch k2's rule archives after an install
# =============================================================================
#
#   powershell -ExecutionPolicy Bypass -File seed_k2_rules.ps1 `
#       -InstallDir "C:\Program Files\PolyShield"
#
# Run ELEVATED, by the installer, AFTER setup_data_root.ps1.
#
# Why this exists: k2 --vlist reports 23 signatures from its plugin modules
# alone and 1263 once its rules directory holds the YARA archives that
# `k2 --update` downloads. A fresh install has an empty rules directory, so
# without this step the primary signature engine ships at under 2% of the
# detection it has in a development checkout -- and nothing would say so.
#
# Not shipped in the payload instead: those archives are third-party
# (ReversingLabs, adware) and k2 fetches them from its own source. Downloading
# them is what k2 already does; redistributing them inside a setup program is a
# licensing question, not a packaging one.
#
# %SYSTEM_RULES_BASE% is set explicitly because k2 PRUNES whatever it is
# pointed at -- it deletes every file its manifest does not list. Pointed at
# PolyShield's own rules\ it destroys the published YARA community generation.
# See paths.k2_rules_dir().
#
# Failure is NOT fatal to the install. No network at install time is ordinary,
# and the Update Center can run this later. The alternative -- failing an
# otherwise good install because a download did not work -- is worse.
# =============================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$InstallDir,

    # Override for testing. Defaults to what paths.app_root() resolves for a
    # distribution -- the seam exists because this step runs `runhidden` inside
    # an installer, where a silent failure is invisible by construction.
    [string]$DataRoot = (Join-Path $env:ProgramData "PolyShield"),

    [int]$TimeoutSeconds = 180,

    # How long to wait for the update source to become reachable. An
    # installer running seconds after a machine boots is racing the network
    # stack, and k2 answers an unreachable source with "[No updates
    # available]" and exit 0.
    [int]$NetworkWaitSeconds = 45
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# Everything this step says is written down. The installer runs it `runhidden`,
# so a failure here is invisible by construction -- and this step failing is the
# difference between K2 shipping 1263 signatures and shipping 23, which nothing
# in the running product would report as wrong.
$logDir = Join-Path $DataRoot "logs"
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Force -Path $logDir | Out-Null }
$logFile = Join-Path $logDir "k2_seed.log"
function Say {
    param([string]$Message)
    $line = "{0}  {1}" -f (Get-Date -Format "s"), $Message
    Write-Host "  $Message" -ForegroundColor DarkGray
    try { Add-Content -Path $logFile -Value $line -Encoding UTF8 } catch { }
}
Say "seed starting: InstallDir=$InstallDir DataRoot=$DataRoot"

# The MODULE through the staged interpreter, not runtime\Scripts\k2.exe.
# That console stub embeds the absolute path of the interpreter it was
# pip-installed against, so once the runtime is relocated by installing it
# points at a directory that does not exist here -- and fails with exit 1 and
# no output at all. See paths.k2_argv().
$rtPython = Join-Path $InstallDir "runtime\python.exe"
$rules = Join-Path $DataRoot "k2\rules"

if (-not (Test-Path $rtPython)) {
    Say "no staged runtime at $rtPython; skipping signature seed"
    exit 0
}

New-Item -ItemType Directory -Force -Path $rules | Out-Null

$env:SYSTEM_RULES_BASE = $rules
$env:USER_RULES_BASE = Join-Path $DataRoot "rules\user_rules"

function Get-K2SignatureCount {
    $out = & $rtPython -m kicomav.k2 --vlist --no-color 2>&1 | Out-String
    return ([regex]::Matches($out, [regex]::Escape("[kicomav.plugins."))).Count
}

# k2 reports SUCCESS when it cannot reach its source. Measured on a clean
# machine: "[No updates available]", exit 0, an empty rules directory and 23
# signatures instead of 1263 -- a scanner at under 2% of its detection, with
# nothing anywhere saying so.
#
# So reachability is established first, and the result is verified afterwards.
# An installer that runs seconds after a machine boots is racing the network
# stack, which is exactly the case this hits.
$probeUrl = "https://raw.githubusercontent.com/hanul93/kicomav-db/master/update/update.cfg"
$online = $false
for ($i = 1; $i -le $NetworkWaitSeconds; $i += 5) {
    try {
        $r = Invoke-WebRequest -Uri $probeUrl -UseBasicParsing -TimeoutSec 10 -Method Head
        if ($r.StatusCode -ge 200 -and $r.StatusCode -lt 400) { $online = $true; break }
    } catch {
        Say "update source not reachable yet ($($_.Exception.Message.Split([Environment]::NewLine)[0]))"
    }
    Start-Sleep -Seconds 5
}

if (-not $online) {
    Say "SKIPPED: the k2 update source is not reachable from this machine."
    Say "K2 will scan with the $(Get-K2SignatureCount) signatures built into its"
    Say "plugins. Run Update Center -> K2 Engine Signatures once online."
    exit 0
}
Say "update source reachable"

$before = Get-K2SignatureCount
Say "signatures before: $before"

$updateOut = Join-Path $logDir "k2_seed_update.log"
$p = Start-Process -FilePath $rtPython `
    -ArgumentList "-m", "kicomav.k2", "--update", "--no-color" `
    -Wait -PassThru -NoNewWindow `
    -RedirectStandardOutput $updateOut -RedirectStandardError "$updateOut.err"
Say "k2 --update exit $($p.ExitCode)"

$after = Get-K2SignatureCount
$files = (Get-ChildItem $rules -Recurse -File -EA SilentlyContinue).Count
Say "signatures after: $after ($files file(s) in $rules)"

# The exit code is not the answer. k2 exits 0 having downloaded nothing, so
# what ships is judged by what is actually there.
if ($after -lt 100) {
    Say "WARNING: k2 reported success but the rule archives are not present."
    Say "K2 will scan with $after signatures until Update Center ->"
    Say "K2 Engine Signatures is run. PolyShield is installed and usable."
    exit 0
}

Say "k2 signatures available: $after"
exit 0
