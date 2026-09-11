@echo off
setlocal enabledelayedexpansion

REM ---------------------------------------------------------------------------
REM  PolyShield - remove every Windows integration a source install created
REM
REM    scripts\uninstall_dev.bat          interactive
REM    scripts\uninstall_dev.bat /quiet   no prompts, no pause
REM
REM  THIS IS WHAT THE Add/Remove Programs ENTRY RUNS. It exists as a separate
REM  file, rather than the entry pointing straight at `app.py --unregister`,
REM  because Windows launches an uninstall string UNELEVATED and the first
REM  teardown step is the Windows service, which needs administrator rights.
REM  Without this wrapper an uninstall from Settings > Apps would clear the
REM  HKCU entries, fail on the service, and report success anyway.
REM
REM  Removes registrations only. The checkout, the quarantine, the logs, the
REM  threat database and your settings are all left alone -- quarantine in
REM  particular may hold the only copy of a file somebody wants back.
REM ---------------------------------------------------------------------------

set "QUIET="
if /i "%~1"=="/quiet" set "QUIET=1"

REM -- Self-elevate ----------------------------------------------------------
NET SESSION >nul 2>&1
if errorlevel 1 (
    if not defined QUIET echo.
    if not defined QUIET echo  Requesting administrator privileges ^(a consent prompt will appear^)...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs -Wait"
    exit /b
)

pushd "%~dp0.."
set "PY=%CD%\kicomav_env\Scripts\python.exe"
set "APP=%CD%\src\ui\app.py"

if not defined QUIET (
    echo.
    echo  +-------------------------------------------------------+
    echo  ^|  PolyShield - removing Windows integrations            ^|
    echo  +-------------------------------------------------------+
    echo.
)

if not exist "%PY%" (
    REM  The virtualenv is gone but the service may not be. Fall back to the
    REM  one step that does not need Python, so an uninstall is still possible
    REM  from a half-deleted checkout.
    echo  [WARN] kicomav_env is missing; removing the service directly.
    sc stop PolyShieldService >nul 2>&1
    sc delete PolyShieldService >nul 2>&1
    echo  The Explorer menu, startup and Settings ^> Apps entries are per-user
    echo  registry keys under HKCU\Software\Microsoft\Windows\CurrentVersion.
    popd
    if not defined QUIET pause
    exit /b 1
)

"%PY%" "%APP%" --unregister
set "RC=%ERRORLEVEL%"

if not defined QUIET (
    echo.
    if "%RC%"=="0" (
        echo  Done. Your quarantine, logs, settings and threat database were kept.
    ) else (
        echo  Some steps did not complete. Re-running this is safe: every step
        echo  treats "it was not there" as success.
    )
    echo.
)
popd
if not defined QUIET pause
exit /b %RC%
