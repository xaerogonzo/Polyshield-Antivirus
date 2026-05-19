@echo off
setlocal enabledelayedexpansion
pushd "%~dp0..\.."

REM --------------------------------------------------------------------------
REM  PolyShield — Windows Service Installer / Uninstaller
REM
REM  Usage:
REM    setup_service.bat          — install and start the service
REM    setup_service.bat /remove  — stop and remove the service
REM
REM  Must run as Administrator (script auto-elevates via UAC if not already).
REM  Requires: install.bat to have been run first (kicomav_env must exist).
REM --------------------------------------------------------------------------

REM -- Self-elevate if not already running as Administrator ------------------
NET SESSION >nul 2>&1
if errorlevel 1 (
    echo.
    echo  Requesting administrator privileges ^(UAC prompt will appear^)...
    echo.
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs -Wait"
    exit /b
)

REM -- Handle /remove argument -----------------------------------------------
if /i "%1"=="/remove" goto UNINSTALL
if /i "%1"=="/uninstall" goto UNINSTALL

REM --------------------------------------------------------------------------
REM  INSTALL
REM --------------------------------------------------------------------------
:INSTALL
echo.
echo  +------------------------------------------------------+
echo  ^|    PolyShield Realtime Protection — Service Installer^|
echo  +------------------------------------------------------+
echo.

REM Derive project root: %~dp0 = scripts\service\, so ..\..\  = project root
for %%I in ("%~dp0..\..") do set "ROOT=%%~fI"

REM -- Step 0: Silently remove old KicomAIService if present -----------------
sc query KicomAIService >nul 2>&1
if not errorlevel 1 (
    echo  [0/8] Removing legacy KicomAIService...
    sc stop KicomAIService >nul 2>&1
    timeout /t 2 /nobreak >nul
    sc delete KicomAIService >nul 2>&1
    echo   [OK] Legacy service removed
)

REM -- Step 1: Verify kicomav_env exists ------------------------------------
echo  [1/8] Checking kicomav_env...
if not exist "kicomav_env\Scripts\python.exe" (
    echo.
    echo  [ERROR] kicomav_env not found.
    echo         Run install.bat first, then re-run this script.
    echo.
    pause
    exit /b 1
)
echo   [OK] kicomav_env found

REM -- Step 2: Ensure pywin32 is installed -----------------------------------
echo  [2/8] Checking pywin32...
kicomav_env\Scripts\python.exe -c "import win32serviceutil" >nul 2>&1
if errorlevel 1 (
    echo   Installing pywin32 (not found in venv)...
    kicomav_env\Scripts\pip.exe install "pywin32>=307"
    if errorlevel 1 (
        echo  [ERROR] pywin32 installation failed.
        pause & exit /b 1
    )
    echo   [OK] pywin32 installed
) else (
    echo   [OK] pywin32 already installed
)

REM -- Step 3: Register pywin32 DLLs in System32 ----------------------------
REM  CRITICAL: Without this, the SCM cannot find pywintypes3XX.dll and
REM  the service will fail with Error 1053 (timeout) or "module not found".
REM  This copies pywintypes313.dll + pythoncom313.dll to C:\Windows\System32.
echo  [3/8] Registering pywin32 DLLs in System32...
kicomav_env\Scripts\python.exe -m pywin32_postinstall -install >nul 2>&1
if errorlevel 1 (
    echo   [WARN] pywin32_postinstall reported an error (may already be registered).
    echo          Continuing — this is often non-fatal.
) else (
    echo   [OK] DLLs registered (pywintypes3XX.dll, pythoncom3XX.dll)
)

REM -- Step 4: Register Defender exclusions ---------------------------------
REM  Without these exclusions a Defender signature update can cause
REM  STATUS_IN_PAGE_ERROR (exception 0xC0000006) in ntdll.dll when SCM tries
REM  to memory-map python.exe as LocalSystem -- service exits with code 1067
REM  before any Python code runs and before service.log gets a new entry.
REM  Direct powershell calls (script is already elevated at this point).
echo  [4/8] Registering Defender exclusions for python.exe and kicomav_env...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Add-MpPreference -ExclusionPath '!ROOT!\kicomav_env\Lib\site-packages\speakeasy' -EA SilentlyContinue" >nul 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -Command "Add-MpPreference -ExclusionPath '!ROOT!\kicomav_env\Lib\site-packages\yara' -EA SilentlyContinue" >nul 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -Command "Add-MpPreference -ExclusionPath '!ROOT!\kicomav_env\Scripts\k2.exe' -EA SilentlyContinue" >nul 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -Command "Add-MpPreference -ExclusionPath '!ROOT!\kicomav_env' -EA SilentlyContinue" >nul 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -Command "Add-MpPreference -ExclusionProcess '!ROOT!\kicomav_env\Scripts\python.exe' -EA SilentlyContinue" >nul 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -Command "Add-MpPreference -ExclusionProcess '!ROOT!\kicomav_env\Scripts\pythonw.exe' -EA SilentlyContinue" >nul 2>&1
echo   [OK] Defender exclusions set (kicomav_env, python.exe, pythonw.exe)

REM -- Step 5: Create C:\ProgramData\PolyShield and set ACLs -----------------
REM  Token file lives here (readable by all users, writable only by SYSTEM +
REM  LocalService). This prevents malware running in user context from forging
REM  service commands by overwriting the token.
echo  [5/8] Setting up C:\ProgramData\PolyShield ...
if not exist "C:\ProgramData\PolyShield" (
    mkdir "C:\ProgramData\PolyShield"
    echo   [OK] Directory created
) else (
    echo   [OK] Directory already exists
)
icacls "C:\ProgramData\PolyShield" ^
    /grant "SYSTEM:(OI)(CI)F" ^
    /grant "NT AUTHORITY\LocalService:(OI)(CI)M" ^
    /grant "Administrators:(OI)(CI)F" ^
    /grant "Users:(OI)(CI)R" ^
    /inheritance:r >nul 2>&1
echo   [OK] ACLs set (SYSTEM=Full, LocalService=Modify, Users=Read-only)

REM -- Step 5: Grant LocalService access to project root --------------------
REM  NT AUTHORITY\LocalService cannot access arbitrary user directories by
REM  default. We grant Modify on the project root so the service can:
REM    - Read config/ui_settings.json (watched folders list)
REM    - Write config/service_events.json (event log)
REM    - Write to quarantine/ (if auto-quarantine is on)
REM    - Write to logs/ (scan reports)
echo  [6/8] Granting LocalService access to project folders...
icacls "!ROOT!" /grant "NT AUTHORITY\LocalService:(OI)(CI)M" >nul 2>&1
echo   [OK] Project root: NT AUTHORITY\LocalService granted Modify

REM  Quarantine folder: LocalService can write; UI (running as the user)
REM  also needs to list/read the directory to display the quarantine view.
if not exist "!ROOT!\quarantine" mkdir "!ROOT!\quarantine"
icacls "!ROOT!\quarantine" ^
    /grant "NT AUTHORITY\LocalService:(OI)(CI)M" >nul 2>&1
echo   [OK] quarantine\: LocalService=Modify (Users retain default access)

REM -- Step 6: Install the Windows Service ----------------------------------
echo  [7/8] Installing service with SCM...
sc query PolyShieldService >nul 2>&1
if not errorlevel 1 (
    echo   Service already registered — removing old registration first...
    sc stop PolyShieldService >nul 2>&1
    timeout /t 2 /nobreak >nul
    kicomav_env\Scripts\python.exe polyshield_service.py remove >nul 2>&1
)
kicomav_env\Scripts\python.exe polyshield_service.py install
if errorlevel 1 (
    echo.
    echo  [ERROR] Service installation failed.
    echo         Check that polyshield_service.py exists in the project root.
    echo.
    pause
    exit /b 1
)
echo   [OK] Service registered: PolyShield Realtime Protection

REM -- Step 7: Start the service --------------------------------------------
REM  Also force start= auto in case the service was previously registered as
REM  DEMAND_START (manual).  win32serviceutil install sets the type from the
REM  _svc_start_type_ attribute, but sc config ensures it on upgrade paths too.
sc config PolyShieldService start= auto >nul 2>&1
echo  [8/8] Starting service...
sc start PolyShieldService >nul 2>&1
timeout /t 3 /nobreak >nul
sc query PolyShieldService | find "RUNNING" >nul 2>&1
if errorlevel 1 (
    echo   [WARN] Service may not have started yet.
    echo          Check: Event Viewer ^> Windows Logs ^> System  (source: PolyShieldService^)
    echo          Log:   C:\ProgramData\PolyShield\service.log
    echo          Query: sc query PolyShieldService
) else (
    echo   [OK] Service is RUNNING
)

echo.
echo  +-------------------------------------------------------+
echo  ^|    Installation complete!                            ^|
echo  ^|-------------------------------------------------------^|
echo  ^|                                                      ^|
echo  ^|  Service:  PolyShield Realtime Protection            ^|
echo  ^|  Account:  NT AUTHORITY\LocalService                 ^|
echo  ^|  Port:     127.0.0.1:52614 (localhost only)          ^|
echo  ^|  Log:      C:\ProgramData\PolyShield\service.log     ^|
echo  ^|  Token:    C:\ProgramData\PolyShield\service_token.txt^|
echo  ^|                                                      ^|
echo  ^|  In PolyShield UI — click "Service" in the sidebar.  ^|
echo  +-------------------------------------------------------+
echo.
pause
exit /b 0


REM --------------------------------------------------------------------------
REM  UNINSTALL
REM --------------------------------------------------------------------------
:UNINSTALL
echo.
echo  +------------------------------------------------------+
echo  ^|    PolyShield Realtime Protection — Service Removal  ^|
echo  +------------------------------------------------------+
echo.

echo  [1/3] Stopping service...
sc stop PolyShieldService >nul 2>&1
timeout /t 2 /nobreak >nul
echo   [OK] Stop signal sent

echo  [2/3] Removing service registration...
if not exist "kicomav_env\Scripts\python.exe" (
    REM Fall back to sc.exe if venv is gone
    sc delete PolyShieldService >nul 2>&1
) else (
    kicomav_env\Scripts\python.exe polyshield_service.py remove >nul 2>&1
)
sc query PolyShieldService >nul 2>&1
if errorlevel 1 (
    echo   [OK] Service removed from SCM
) else (
    echo   [WARN] Service may still appear in SCM for a moment (Windows cleanup delay)
)

echo  [3/3] Cleaning up service data files...
set /p CLEAN_DATA="  Remove C:\ProgramData\PolyShield (log + token files)? [y/N]: "
if /i "!CLEAN_DATA!"=="y" (
    if exist "C:\ProgramData\PolyShield" (
        rmdir /s /q "C:\ProgramData\PolyShield"
        echo   [OK] C:\ProgramData\PolyShield removed
    )
) else (
    echo   [OK] Data files kept (re-install will reuse them)
)

echo.
echo  Service removed. The folder watcher will run in-process mode
echo  (stops when the PolyShield UI closes) until reinstalled.
echo.
pause
exit /b 0
