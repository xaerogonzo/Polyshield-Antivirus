@echo off
setlocal

REM ============================================================
REM  PolyShield -- Build Tiny11 VM ISO
REM  Launcher for build_tiny11_vm.ps1. Double-click to run.
REM  Self-elevates and bypasses execution policy automatically.
REM
REM  Optional arguments passed through to the PowerShell script:
REM    -ISODrive D        Drive letter of your Win11 ISO
REM    -ScratchDrive E    Scratch drive (~15 GB free needed)
REM    -Variant regular   or: core  (core removes Defender --
REM                        PolyShield Defender tests will not work)
REM    -WorkDir C:\path   Skip the folder picker, use this path
REM
REM  See docs\VM_SETUP.md for the full build guide.
REM ============================================================

REM -- Self-elevate if not already running as Administrator -------
NET SESSION >nul 2>&1
if errorlevel 1 (
    echo.
    echo  Requesting administrator privileges ^(UAC prompt will appear^)...
    echo.
    REM  -ArgumentList is omitted when there are no arguments to pass.
    REM  `-ArgumentList '%*'` expands to `-ArgumentList ''` for an
    REM  argument-less run, and Windows PowerShell 5.1 validates that
    REM  parameter as NotNullOrEmpty -- so the elevation failed, the script
    REM  exited 0, and nothing happened. PowerShell 7 accepts it, which is
    REM  why this survives a test run under pwsh and dies under the
    REM  `powershell` these scripts actually invoke.
    if "%*"=="" (
        powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs -Wait"
    ) else (
        powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs -Wait"
    )
    exit /b
)

REM -- Run the PowerShell script from the same folder as this bat --
REM    -NoProfile        : skip user profile scripts (faster + cleaner)
REM    -ExecutionPolicy Bypass : avoids "script not digitally signed" errors
REM    %*                : pass any arguments this bat received into the ps1
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build_tiny11_vm.ps1" %*

echo.
pause
