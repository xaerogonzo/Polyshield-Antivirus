@echo off
setlocal enabledelayedexpansion

REM ---------------------------------------------------------------------------
REM  PolyShield - register a SOURCE CHECKOUT as an installed product
REM
REM    scripts\install_dev.bat            interactive
REM    scripts\install_dev.bat /quiet     no prompts, no startup entry
REM    scripts\install_dev.bat /dryrun    report what it WOULD do, change nothing
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
REM  THIS SCRIPT DOES NOT SELF-ELEVATE, and that is deliberate.
REM
REM  It used to, and it cost two failed installs. Elevating the whole script
REM  puts the prompt and every message into a SPAWNED console that closes the
REM  instant the script ends -- so a failure was unreadable, and a step that
REM  silently did nothing was indistinguishable from one that worked.
REM
REM  It was also wrong on its own terms: the three per-user registrations write
REM  to HKCU, and running them elevated writes to the ADMINISTRATOR's HKCU when
REM  that is a different account from the one installing.
REM
REM  So the per-user work runs here, unelevated, in the window you started it
REM  from. Only the service step elevates, and setup_service.bat raises that
REM  prompt itself and keeps its own window open until you have read it.
REM
REM  Requires scripts\install.bat to have been run first (kicomav_env).
REM ---------------------------------------------------------------------------

set "QUIET="
set "DRYRUN="
for %%A in (%*) do (
    if /i "%%~A"=="/quiet"  set "QUIET=1"
    if /i "%%~A"=="/dryrun" set "DRYRUN=1"
)

pushd "%~dp0.."
set "ROOT=%CD%"
set "PY=%ROOT%\kicomav_env\Scripts\python.exe"
set "APP=%ROOT%\src\ui\app.py"
set "SVC_SETUP=%~dp0service\setup_service.bat"

echo.
echo  +-------------------------------------------------------+
echo  ^|  PolyShield - Windows integration for a source build   ^|
echo  +-------------------------------------------------------+
echo.
echo   Checkout: %ROOT%
if defined DRYRUN echo   DRY RUN - nothing will be changed.
echo.

REM -- Step 1: pre-flight ----------------------------------------------------
echo  [1/4] Checking the virtual environment...
if not exist "%PY%" (
    echo.
    echo  [ERROR] kicomav_env not found.
    echo          Run scripts\install.bat first, then re-run this script.
    echo.
    goto :FAILED
)
if not exist "%SVC_SETUP%" (
    echo.
    echo  [ERROR] missing "%SVC_SETUP%"
    echo.
    goto :FAILED
)
echo   [OK] kicomav_env found

REM -- Step 2: ask, before anything is registered ----------------------------
REM  Default is No. PolyShield writing a Run value into somebody's registry
REM  because they ran a script that mentioned "integration" is exactly the
REM  behaviour this feature is not allowed to have.
set "WITH_STARTUP="
if defined QUIET goto :SKIP_PROMPT
echo.
set /p ANSWER="  [2/4] Start PolyShield when you sign in, minimised to the tray? [y/N]: "
if /i "!ANSWER!"=="y" set "WITH_STARTUP=--with-startup"
goto :ASKED
:SKIP_PROMPT
echo  [2/4] /quiet - not registering a startup entry.
:ASKED
echo.

REM -- Step 3: the per-user integrations, UNELEVATED --------------------------
REM  Explorer verb, Settings > Apps entry, and the startup entry if asked for.
REM  register_all() covers all three; it creates the startup entry only when
REM  --with-startup is passed, and there is no way to opt in by omission.
echo  [3/4] Registering the Explorer menu and the Settings ^> Apps entry !WITH_STARTUP!...
if defined DRYRUN (
    echo   [DRY] "%PY%" "%APP%" --register !WITH_STARTUP!
) else (
    "%PY%" "%APP%" --register !WITH_STARTUP!
    if errorlevel 1 (
        echo   [FAIL] the per-user integrations did not register
        goto :ROLLBACK
    )
)

REM -- Step 4: the service, and ONLY this step elevates -----------------------
REM  setup_service.bat raises its own consent prompt and keeps its window open
REM  until you dismiss it, so its output is readable even when it fails.
echo.
echo  [4/4] Registering the realtime protection service...
echo        A consent prompt will appear, and the service installer opens its
echo        own window. Read it, then press a key there to come back here.
if defined DRYRUN (
    echo   [DRY] call "%SVC_SETUP%"
) else (
    call "%SVC_SETUP%"
)

REM  Verify the OUTCOME, not the existence.
REM
REM  This check used to be `sc query PolyShieldService`, which succeeds for a
REM  service that was ALREADY registered -- so it passed whether or not this
REM  step had done anything, and a DEMAND_START registration survived a run of
REM  this script while it reported success. service_state() reads what the SCM
REM  actually holds, and needs no elevation to do it.
echo.
echo  Checking what the SCM actually holds...
"%PY%" -c "import sys;sys.path[:0]=['src','.'];from ui.core import integration as i;s=i.service_state();print('   present:',s['present'],' start type:',s['start_type'],' state:',s['state'],' exit code:',s['exit_code']);sys.exit(0 if s['present'] and s['start_type'] in ('auto','delayed-auto') else 1)"
if errorlevel 1 (
    if defined DRYRUN (
        echo   [DRY] the service is not set to start automatically yet - expected.
    ) else (
        echo.
        echo   [FAIL] The service is not set to start automatically.
        echo          Whatever the service installer printed above is the reason.
        goto :ROLLBACK
    )
)

echo.
echo  Registered against this checkout:
echo    - PolyShieldService, set to start automatically
echo    - "Scan with PolyShield" in the Explorer right-click menu
echo    - an entry in Settings ^> Apps
if defined WITH_STARTUP echo    - a startup entry ^(Task Manager ^> Startup^)
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
REM
REM  Unelevated, so the service step of the rollback may not succeed. It is
REM  reported rather than hidden: uninstall_dev.bat elevates and finishes it.
REM ---------------------------------------------------------------------------
:ROLLBACK
echo.
echo  Rolling back the per-user registrations...
REM  --keep-service: this script never elevates, so it has not registered
REM  or reconfigured a service, and a rollback must not delete one that was
REM  already on the machine before it ran.
"%PY%" "%APP%" --unregister --keep-service
echo.
echo  [ERROR] Installation failed and was rolled back.
echo          The service was left alone - this script never elevates, so
echo          it did not create one. To remove an existing service too, run
echo          scripts\uninstall_dev.bat - that one elevates.
echo.
popd
if not defined QUIET pause
exit /b 1

:FAILED
popd
if not defined QUIET pause
exit /b 1
