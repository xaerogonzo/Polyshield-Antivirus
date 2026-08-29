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

    [int]$TimeoutSeconds = 180
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# The MODULE through the staged interpreter, not runtime\Scripts\k2.exe.
# That console stub embeds the absolute path of the interpreter it was
# pip-installed against, so once the runtime is relocated by installing it
# points at a directory that does not exist here -- and fails with exit 1 and
# no output at all. See paths.k2_argv().
$rtPython = Join-Path $InstallDir "runtime\python.exe"
$rules = Join-Path (Join-Path $env:ProgramData "PolyShield") "k2\rules"

if (-not (Test-Path $rtPython)) {
    Write-Host "  No staged runtime; skipping signature seed." -ForegroundColor DarkGray
    exit 0
}

New-Item -ItemType Directory -Force -Path $rules | Out-Null

$env:SYSTEM_RULES_BASE = $rules
$env:USER_RULES_BASE = Join-Path (Join-Path $env:ProgramData "PolyShield") "rules\user_rules"

Write-Host "  Downloading k2 signature archives ..." -ForegroundColor DarkGray
$p = Start-Process -FilePath $rtPython `
    -ArgumentList "-m", "kicomav.k2", "--update", "--no-color" `
    -Wait -PassThru -NoNewWindow
if ($p.ExitCode -ne 0) {
    Write-Host "  k2 signature download failed (exit $($p.ExitCode))." -ForegroundColor Yellow
    Write-Host "  PolyShield is installed and usable; run Update Center ->" -ForegroundColor Yellow
    Write-Host "  K2 Engine Signatures when a connection is available." -ForegroundColor Yellow
    exit 0
}

# Say what was actually achieved rather than that a command ran.
$out = & $rtPython -m kicomav.k2 --vlist --no-color 2>&1 | Out-String
$count = ([regex]::Matches($out, [regex]::Escape("[kicomav.plugins."))).Count
Write-Host "  k2 signatures available: $count" -ForegroundColor Green
exit 0
