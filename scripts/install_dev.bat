@echo off
setlocal enabledelayedexpansion

REM ---------------------------------------------------------------------------
REM  PolyShield - register a SOURCE CHECKOUT as an installed product
REM
REM    scripts\install_dev.bat            interactive
REM    scripts\install_dev.bat /quiet     no prompts, no startup entry
REM
REM  What this does NOT do: copy anything. Every command it writes into the
REM  registry and the SCM points at THIS checkout, so you keep editing the
REM  source and the integration keeps working. That is the whole point -- a
REM  compiled build goes stale the moment you touch a .py file.
REM
REM  Two things it must never do, both of which look like improvements:
REM
REM    * create .polyshield-distribution in the project root. paths.py reads
REM      that marker and flips app_root() from the checkout to
REM      %ProgramData%\PolyShield -- orphaning the existing config, quarantine,
REM      logs and threat database, silently, with the app reporting a clean
REM      first-run state.
REM    * set POLYSHIELD_DATA_DIR machine-wide. Same outcome, different door.
REM
REM  Requires scripts\install.bat to have been run first (kicomav_env).
REM  Self-elevating: the service step needs administrator rights.
REM ---------------------------------------------------------------------------

set "QUIET="
if /i "%~1"=="/quiet" set "QUIET=1"

REM -- Self-elevate ----------------------------------------------------------
NET SESSION >nul 2>&1
if errorlevel 1 (
    echo.
    echo  Requesting administrator privileges ^(a consent prompt will appear^)...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs -Wait"
    exit /b
)

pushd "%~dp0.."
for %%I in ("%CD%") do set "ROOT=%%~fI"
set "PYW=%ROOT%\kicomav_env\Scripts\pythonw.exe"
set "PY=%ROOT%\kicomav_env\Scripts\python.exe"
set "APP=%ROOT%\src\ui\app.py"

echo.
echo  +-------------------------------------------------------+
echo  ^|  PolyShield - Windows integration for a source build   ^|
echo  +-------------------------------------------------------+
echo.
echo   Checkout: %ROOT%
echo.

REM -- Step 0: pre-flight ----------------------------------------------------
echo  [1/5] Checking the virtual environment...
if not exist "%PY%" (
    echo.
    echo  [ERROR] kicomav_env not found.
    echo          Run scripts\install.bat first, then re-run this script.
    echo.
    if not defined QUIET pause
    exit /b 1
)
echo   [OK] kicomav_env found

REM -- Step 1: ask about the login entry, BEFORE anything is registered ------
REM  Default is No. PolyShield writing a Run value into somebody's registry
REM  because they ran a script that mentioned "integration" is exactly the
REM  behaviour this feature is not allowed to have.
set "WITH_STARTUP="
if defined QUIET goto :SKIP_PROMPT
echo.
set /p ANSWER="  Start PolyShield when you sign in? (minimised to the tray) [y/N]: "
if /i "!ANSWER!"=="y" set "WITH_STARTUP=--with-startup"
:SKIP_PROMPT
echo.

REM -- Step 2: the service ---------------------------------------------------
echo  [2/5] Registering the realtime protection service...
call "%~dp0service\setup_service.bat" >nul 2>&1
sc query PolyShieldService >nul 2>&1
if errorlevel 1 (
    echo   [FAIL] the service did not register
    goto :ROLLBACK
)
echo   [OK] PolyShieldService registered

REM -- Step 3: the per-user integrations -------------------------------------
REM  Unelevated work done from an elevated shell lands in the ADMINISTRATOR's
REM  HKCU when the two are different accounts. Run it as the invoking user.
echo  [3/5] Registering the Explorer menu !WITH_STARTUP!...
"%PY%" "%APP%" --register !WITH_STARTUP!
if errorlevel 1 (
    echo   [FAIL] the per-user integrations did not register
    goto :ROLLBACK
)

REM -- Step 4: the uninstall entry -------------------------------------------
echo  [4/5] Adding PolyShield to Settings ^> Apps...
"%PY%" "%APP%" --register-uninstall-entry
if errorlevel 1 (
    echo   [FAIL] the uninstall entry could not be written
    goto :ROLLBACK
)

REM -- Step 5: report --------------------------------------------------------
echo  [5/5] Done.
echo.
echo  Registered against this checkout:
echo    - PolyShieldService, set to start automatically
echo    - "Scan with PolyShield" in the Explorer right-click menu
if defined WITH_STARTUP echo    - a startup entry ^(Task Manager ^> Startup^)
echo    - an entry in Settings ^> Apps
echo.
echo  To undo all of it:  scripts\uninstall_dev.bat
echo  Moving or renaming this folder invalidates every one of them; re-run
echo  this script afterwards to repoint them.
echo.
popd
if not defined QUIET pause
exit /b 0

REM ---------------------------------------------------------------------------
REM  A failed install must not leave a half-installed machine. unregister_all()
REM  treats absent as success, so this is safe to run after a failure at any
REM  point -- including before anything was registered.
REM ---------------------------------------------------------------------------
:ROLLBACK
echo.
echo  Rolling back...
"%PY%" "%APP%" --unregister
echo.
echo  [ERROR] Installation failed and was rolled back. Nothing was left behind.
echo.
popd
if not defined QUIET pause
exit /b 1
