@echo off
setlocal enabledelayedexpansion
pushd "%~dp0.."

REM ==========================================================================
REM  PolyShield -- Component Manager
REM  Manages installation, updates, and removal of all components.
REM  Run as Administrator if junction creation or driver installs fail.
REM ==========================================================================

:MAIN_MENU
cls
echo.
echo  +========================================================+
echo  ^|       PolyShield Security Suite - Component Manager   ^|
echo  +========================================================+
echo.

REM -- Detect component status -----------------------------------------------
set "ST_CORE=[ ] Not installed"
set "ST_GUARD=[ ] Not installed"
set "ST_SPEAK=[ ] Not installed"
set "ST_INTEL=[ ] No database"
set "ST_JUNC=[ ] Not set up"
set "ST_SVC=[ ] Not installed"
set "ST_YARA=[ ] No rules"
set "ST_CLAM=[ ] Not configured"

if exist "kicomav_env\Scripts\k2.exe"          set "ST_CORE=[*] Installed"
if exist "guardian_env\Scripts\python.exe"     set "ST_GUARD=[*] Installed"
if exist "kicomav_env\Scripts\speakeasy.exe"   set "ST_SPEAK=[*] Installed"
if exist "intelligence\threat_db.sqlite"       set "ST_INTEL=[*] Database present"
if exist "%USERPROFILE%\.kicomav"              set "ST_JUNC=[*] Active"
sc query PolyShieldService >nul 2>&1
if not errorlevel 1                            set "ST_SVC=[*] Installed"
if exist "rules\user_rules\*.yar"              set "ST_YARA=[*] Rules present"
if exist "C:\Program Files\ClamAV\clamscan.exe"       set "ST_CLAM=[*] Installed"
if exist "C:\Program Files (x86)\ClamAV\clamscan.exe" set "ST_CLAM=[*] Installed"
if exist "kicomav_env\Scripts\python.exe" (
    for /f "delims=" %%L in ('kicomav_env\Scripts\python.exe -c "from ui.core import settings as s; print(s.get(\"clamav_path\") or \"\")" 2^>nul') do (
        if exist "%%L\clamscan.exe" set "ST_CLAM=[*] Installed (custom path)"
    )
)

echo   Component Status:
echo.
echo   [1]  k2 Core Engine + Python env         %ST_CORE%
echo   [2]  Guardian AI (second-opinion scan)  %ST_GUARD%
echo   [3]  Speakeasy PE Emulator              %ST_SPEAK%
echo   [4]  Local Intelligence Database        %ST_INTEL%
echo   [5]  System Junction (k2 compatibility) %ST_JUNC%
echo   [6]  Realtime Protection Service        %ST_SVC%
echo   [7]  YARA Rules Engine                  %ST_YARA%
echo   [8]  ClamAV Signatures Engine           %ST_CLAM%
echo.
echo   ------------------------------------------------------
echo   [9]  Diagnostics  (Defender + Device Security check^)
echo   [A]  Install / Update ALL components
echo   [U]  Uninstall - remove a specific component
echo   [X]  Uninstall ALL (full clean removal)
echo   [0]  Exit
echo.
set /p CHOICE="  Choose an option: "

if /i "!CHOICE!"=="1" goto MENU_CORE
if /i "!CHOICE!"=="2" goto MENU_GUARDIAN
if /i "!CHOICE!"=="3" goto MENU_SPEAKEASY
if /i "!CHOICE!"=="4" goto MENU_INTEL
if /i "!CHOICE!"=="5" goto MENU_JUNCTION
if /i "!CHOICE!"=="6" goto MENU_SERVICE
if /i "!CHOICE!"=="7" goto MENU_YARA
if /i "!CHOICE!"=="8" goto MENU_CLAMAV
if /i "!CHOICE!"=="9" goto MENU_DIAG
if /i "!CHOICE!"=="A" goto INSTALL_ALL
if /i "!CHOICE!"=="U" goto MENU_UNINSTALL
if /i "!CHOICE!"=="X" goto UNINSTALL_ALL
if /i "!CHOICE!"=="0" goto END
goto MAIN_MENU


REM ==========================================================================
REM  [1] k2 Core Engine
REM ==========================================================================
:MENU_CORE
cls
echo.
echo  -- k2 Core Engine ----------------------------------------------
echo.
echo   Includes: Python venv, k2.exe scanner, Speakeasy,
echo   customtkinter GUI, watchdog, VirusTotal module, and
echo   all packages in requirements.txt.
echo.
if exist "kicomav_env\Scripts\k2.exe" (
    echo   Status: INSTALLED
    echo.
    echo   [1] Update packages  (pip install --upgrade)
    echo   [2] Update k2 signatures  (k2 --update^)
    echo   [3] Reinstall from scratch
    echo   [0] Back
) else (
    echo   Status: NOT INSTALLED
    echo.
    echo   [1] Install now
    echo   [0] Back
)
echo.
set /p C2="  Choose: "
if "!C2!"=="0" goto MAIN_MENU
if exist "kicomav_env\Scripts\k2.exe" (
    if "!C2!"=="1" goto CORE_UPDATE_PKGS
    if "!C2!"=="2" goto CORE_UPDATE_SIGS
    if "!C2!"=="3" goto CORE_REINSTALL
) else (
    if "!C2!"=="1" goto CORE_INSTALL
)
goto MENU_CORE

:CORE_INSTALL
echo.
echo  Installing k2 Core engine...
call :CHECK_PYTHON || goto MENU_CORE
py -3.11 -m venv kicomav_env
kicomav_env\Scripts\pip.exe install --upgrade pip --quiet
kicomav_env\Scripts\pip.exe install -r requirements.txt
call :ENSURE_DIRS
call :ENSURE_ENV
call :ENSURE_JUNCTION
echo.
echo  Downloading signatures...
kicomav_env\Scripts\k2.exe --update
echo.
echo  [OK] Core installed. Press any key...
pause >nul
goto MAIN_MENU

:CORE_UPDATE_PKGS
echo.
echo  Upgrading all packages...
kicomav_env\Scripts\pip.exe install --upgrade -r requirements.txt
echo.
echo  [OK] Packages updated. Press any key...
pause >nul
goto MAIN_MENU

:CORE_UPDATE_SIGS
echo.
echo  Downloading latest K2 engine signatures...
kicomav_env\Scripts\k2.exe --update
echo.
echo  [OK] Signatures updated. Press any key...
pause >nul
goto MAIN_MENU

:CORE_REINSTALL
echo.
echo  WARNING: This will delete kicomav_env\ and reinstall from scratch.
set /p CONF="  Type YES to confirm: "
if /i not "!CONF!"=="YES" goto MENU_CORE
echo  Removing kicomav_env\...
rmdir /s /q kicomav_env
goto CORE_INSTALL


REM ==========================================================================
REM  [2] Guardian AI
REM ==========================================================================
:MENU_GUARDIAN
cls
echo.
echo  -- Guardian AI -------------------------------------------------
echo.
echo   Second-opinion scanner using regex patterns + hash DB.
echo   Requires: git (to clone the guardianai repo)
echo.
if exist "guardian_env\Scripts\python.exe" (
    echo   Status: INSTALLED
    echo.
    echo   [1] Update guardian_env packages
    echo   [2] Pull latest guardianai code  (git pull^)
    echo   [3] Reinstall from scratch
    echo   [0] Back
) else (
    echo   Status: NOT INSTALLED
    echo.
    echo   [1] Install now  (clones repo + creates venv^)
    echo   [0] Back
)
echo.
set /p C3="  Choose: "
if "!C3!"=="0" goto MAIN_MENU
if exist "guardian_env\Scripts\python.exe" (
    if "!C3!"=="1" goto GUARD_UPDATE_PKGS
    if "!C3!"=="2" goto GUARD_GIT_PULL
    if "!C3!"=="3" goto GUARD_REINSTALL
) else (
    if "!C3!"=="1" goto GUARD_INSTALL
)
goto MENU_GUARDIAN

:GUARD_INSTALL
echo.
if not exist "guardianai" (
    echo  Cloning guardianai repo...
    git clone https://github.com/MattEmilien/guardianai.git guardianai
    if errorlevel 1 ( echo  [ERROR] git clone failed. Is git installed? & pause >nul & goto MENU_GUARDIAN )
)
if not exist "guardianai\data" mkdir "guardianai\data"
if not exist "guardianai\data\known_bad.txt" type nul > "guardianai\data\known_bad.txt"
echo  Creating guardian_env...
kicomav_env\Scripts\python.exe -m venv guardian_env
echo  Installing Guardian AI dependencies...
guardian_env\Scripts\pip.exe install --quiet requests cryptography pywin32 Pillow pyuac
echo.
echo  [OK] Guardian AI installed. Press any key...
pause >nul
goto MAIN_MENU

:GUARD_UPDATE_PKGS
echo.
echo  Upgrading guardian_env packages...
guardian_env\Scripts\pip.exe install --upgrade requests cryptography pywin32 Pillow pyuac
echo  [OK] Done. Press any key...
pause >nul
goto MAIN_MENU

:GUARD_GIT_PULL
echo.
if not exist "guardianai" ( echo  [ERROR] guardianai\ folder not found & pause >nul & goto MENU_GUARDIAN )
echo  Pulling latest guardianai code...
git -C guardianai pull
echo  [OK] Done. Press any key...
pause >nul
goto MAIN_MENU

:GUARD_REINSTALL
echo.
echo  WARNING: This will delete guardian_env\ and guardianai\ and reinstall.
set /p CONF="  Type YES to confirm: "
if /i not "!CONF!"=="YES" goto MENU_GUARDIAN
if exist "guardian_env"  rmdir /s /q guardian_env
if exist "guardianai"    rmdir /s /q guardianai
goto GUARD_INSTALL


REM ==========================================================================
REM  [3] Speakeasy PE Emulator
REM ==========================================================================
:MENU_SPEAKEASY
cls
echo.
echo  -- Speakeasy PE Emulator ---------------------------------------
echo.
echo   Traces Windows API calls without executing the file.
echo   Part of kicomav_env -- uses the same Python venv.
echo.
if exist "kicomav_env\Scripts\speakeasy.exe" (
    echo   Status: INSTALLED
    echo.
    echo   [1] Update to latest version
    echo   [2] Reinstall current version
    echo   [0] Back
) else (
    echo   Status: NOT INSTALLED  (kicomav_env must exist first^)
    echo.
    if exist "kicomav_env\Scripts\python.exe" (
        echo   [1] Install now
    ) else (
        echo   [!] Install k2 Core first  (option 1 on main menu^)
    )
    echo   [0] Back
)
echo.
set /p C4="  Choose: "
if "!C4!"=="0" goto MAIN_MENU
if "!C4!"=="1" goto SPEAK_INSTALL
goto MENU_SPEAKEASY

:SPEAK_INSTALL
echo.
if not exist "kicomav_env\Scripts\python.exe" (
    echo  [ERROR] Install k2 Core first.
    pause >nul & goto MENU_SPEAKEASY
)
echo  Installing speakeasy-emulator...
kicomav_env\Scripts\pip.exe install --upgrade speakeasy-emulator
echo.
echo  [OK] Speakeasy installed. Restart PolyShield to see "Ready" in Settings.
pause >nul
goto MAIN_MENU


REM ==========================================================================
REM  [4] Local Intelligence Database
REM ==========================================================================
:MENU_INTEL
cls
echo.
echo  -- Local Intelligence Database ---------------------------------
echo.
echo   MalwareBazaar + NSRL hashes for Guardian AI offline scanning.
echo   Managed from inside the app (Update Center), but can be
echo   cleared here if you need a clean reset.
echo.
if exist "intelligence\threat_db.sqlite" (
    for %%F in ("intelligence\threat_db.sqlite") do set DB_SIZE=%%~zF
    set /a DB_MB=!DB_SIZE! / 1048576
    echo   Status: DATABASE PRESENT  (~!DB_MB! MB^)
    echo.
    echo   [1] Clear malicious hashes  (keeps NSRL^)
    echo   [2] Delete entire database  (full reset^)
    echo   [0] Back
) else (
    echo   Status: NO DATABASE
    echo.
    echo   Use Update Center inside the app to download hashes.
    echo   (Update Center ^> Local Intelligence Database^)
    echo.
    echo   [0] Back
)
echo.
set /p C5="  Choose: "
if "!C5!"=="0" goto MAIN_MENU
if not exist "intelligence\threat_db.sqlite" goto MENU_INTEL
if "!C5!"=="1" goto INTEL_CLEAR_MAL
if "!C5!"=="2" goto INTEL_DELETE_ALL
goto MENU_INTEL

:INTEL_CLEAR_MAL
echo.
echo  Clearing malicious hashes (NSRL kept)...
kicomav_env\Scripts\python.exe -c "import sqlite3; c=sqlite3.connect('intelligence/threat_db.sqlite'); c.execute('DELETE FROM malicious'); c.commit(); c.close(); print('Malicious table cleared.')"
echo  [OK] Done. Press any key...
pause >nul
goto MAIN_MENU

:INTEL_DELETE_ALL
echo.
echo  WARNING: This deletes the entire threat database.
set /p CONF="  Type YES to confirm: "
if /i not "!CONF!"=="YES" goto MENU_INTEL
del /f /q "intelligence\threat_db.sqlite" 2>nul
if exist "guardianai\data\known_bad.txt" type nul > "guardianai\data\known_bad.txt"
echo  [OK] Database deleted. Press any key...
pause >nul
goto MAIN_MENU


REM ==========================================================================
REM  [6] Realtime Protection Service
REM ==========================================================================
:MENU_SERVICE
cls
echo.
echo  -- Realtime Protection Windows Service -------------------------
echo.
echo   Runs the folder watcher as a Windows Service.
echo   Persists after UI is closed. Requires admin to install.
echo   See WINDOWS_SERVICE.md for the full technical details.
echo.
sc query PolyShieldService >nul 2>&1
if not errorlevel 1 (
    REM Service is registered -- check if running
    sc query PolyShieldService | find "RUNNING" >nul 2>&1
    if not errorlevel 1 (
        echo   Status: INSTALLED and RUNNING
    ) else (
        echo   Status: INSTALLED but STOPPED
    )
    echo.
    echo   [1] Start service
    echo   [2] Stop service
    echo   [3] Restart service
    echo   [4] View status  (sc query^)
    echo   [5] Uninstall service
    echo   [0] Back
) else (
    echo   Status: NOT INSTALLED
    echo.
    echo   [1] Install now  (runs setup_service.bat -- UAC required^)
    echo   [0] Back
)
echo.
set /p C7="  Choose: "
if "!C7!"=="0" goto MAIN_MENU
sc query PolyShieldService >nul 2>&1
if not errorlevel 1 (
    if "!C7!"=="1" goto SVC_START
    if "!C7!"=="2" goto SVC_STOP
    if "!C7!"=="3" goto SVC_RESTART
    if "!C7!"=="4" goto SVC_STATUS
    if "!C7!"=="5" goto SVC_UNINSTALL
) else (
    if "!C7!"=="1" goto SVC_INSTALL
)
goto MENU_SERVICE

:SVC_INSTALL
echo.
echo  Launching scripts\service\setup_service.bat (will request UAC elevation)...
start "" /wait "%~dp0service\setup_service.bat"
pause >nul
goto MAIN_MENU

:SVC_START
echo.
sc start PolyShieldService
timeout /t 2 /nobreak >nul
sc query PolyShieldService
echo.
echo  Press any key...
pause >nul
goto MAIN_MENU

:SVC_STOP
echo.
sc stop PolyShieldService
timeout /t 2 /nobreak >nul
sc query PolyShieldService
echo.
echo  Press any key...
pause >nul
goto MAIN_MENU

:SVC_RESTART
echo.
sc stop PolyShieldService >nul 2>&1
timeout /t 2 /nobreak >nul
sc start PolyShieldService
timeout /t 2 /nobreak >nul
sc query PolyShieldService
echo.
echo  Press any key...
pause >nul
goto MAIN_MENU

:SVC_STATUS
echo.
sc query PolyShieldService
echo.
echo  Log file: C:\ProgramData\PolyShield\service.log
type "C:\ProgramData\PolyShield\service.log" 2>nul | more
echo.
echo  Press any key...
pause >nul
goto MAIN_MENU

:SVC_UNINSTALL
echo.
echo  This will stop and remove the PolyShield Windows Service.
echo  (Data files in C:\ProgramData\PolyShield will be preserved.)
set /p CONF="  Type YES to confirm: "
if /i not "!CONF!"=="YES" goto MENU_SERVICE
echo  Launching scripts\service\setup_service.bat /remove (will request UAC elevation)...
start "" /wait "%~dp0service\setup_service.bat" /remove
pause >nul
goto MAIN_MENU


REM ==========================================================================
REM  [7] YARA Rules Engine
REM ==========================================================================
:MENU_YARA
cls
echo.
echo  -- YARA Rules Engine -------------------------------------------
echo.
echo   yara-python is bundled with kicomav_env (no separate install).
echo   Place .yar rule files in rules\user_rules\ to activate.
echo.
set YARA_COUNT=0
for %%F in ("rules\user_rules\*.yar") do set /a YARA_COUNT+=1
echo   Rules loaded: !YARA_COUNT! .yar file(s) in rules\user_rules\
echo.
echo   [1] Open rules folder in Explorer
echo   [2] Browse YARA-Rules community repo  (github.com/Yara-Rules/rules^)
echo   [3] Browse Signature-Base repo        (github.com/Neo23x0/signature-base^)
echo   [0] Back
echo.
set /p C8="  Choose: "
if "!C8!"=="0" goto MAIN_MENU
if "!C8!"=="1" goto YARA_OPEN_FOLDER
if "!C8!"=="2" start https://github.com/Yara-Rules/rules & goto MENU_YARA
if "!C8!"=="3" start https://github.com/Neo23x0/signature-base & goto MENU_YARA
goto MENU_YARA

:YARA_OPEN_FOLDER
if not exist "rules\user_rules" mkdir "rules\user_rules"
explorer "rules\user_rules"
goto MENU_YARA


REM ==========================================================================
REM  [8] ClamAV Signatures Engine
REM ==========================================================================
:MENU_CLAMAV
cls
echo.
echo  -- ClamAV Signatures Engine ------------------------------------
echo.
echo   ClamAV is a separate download (~200 MB with signature database).
echo   After install, set the path in PolyShield Settings ^> ClamAV.
echo.

set "CLAM_EXE="
if exist "C:\Program Files\ClamAV\clamscan.exe"       set "CLAM_EXE=C:\Program Files\ClamAV\clamscan.exe"
if exist "C:\Program Files (x86)\ClamAV\clamscan.exe" set "CLAM_EXE=C:\Program Files (x86)\ClamAV\clamscan.exe"
if exist "kicomav_env\Scripts\python.exe" (
    for /f "delims=" %%L in ('kicomav_env\Scripts\python.exe -c "from ui.core import settings as s; print(s.get(\"clamav_path\") or \"\")" 2^>nul') do (
        if exist "%%L\clamscan.exe" set "CLAM_EXE=%%L\clamscan.exe"
    )
)

if "!CLAM_EXE!"=="" (
    echo   Status: NOT CONFIGURED
    echo.
    echo   [1] Download ClamAV  (opens browser to clamav.net^)
    echo   [2] Set custom install path in Settings
    echo   [0] Back
) else (
    for /f "delims=" %%V in ('"!CLAM_EXE!" --version 2^>nul') do set CLAM_VER=%%V & goto CLAM_GOT_VER
    :CLAM_GOT_VER
    echo   Status: INSTALLED
    echo   Path:    !CLAM_EXE!
    echo   Version: !CLAM_VER!
    echo.
    echo   [1] Update virus definitions  (freshclam^)
    echo   [2] Set custom install path in Settings
    echo   [0] Back
)
echo.
set /p C9="  Choose: "
if "!C9!"=="0" goto MAIN_MENU
if "!CLAM_EXE!"=="" (
    if "!C9!"=="1" start https://www.clamav.net/downloads & goto MENU_CLAMAV
    if "!C9!"=="2" goto CLAM_SET_PATH
) else (
    if "!C9!"=="1" goto CLAM_FRESHCLAM
    if "!C9!"=="2" goto CLAM_SET_PATH
)
goto MENU_CLAMAV

:CLAM_FRESHCLAM
echo.
set "FRESH_EXE=!CLAM_EXE:clamscan.exe=freshclam.exe!"
if exist "!FRESH_EXE!" (
    echo  Running freshclam to update virus definitions...
    "!FRESH_EXE!"
) else (
    echo  [ERROR] freshclam.exe not found next to clamscan.exe
)
echo.
echo  Press any key...
pause >nul
goto MAIN_MENU

:CLAM_SET_PATH
echo.
echo  Enter the ClamAV install folder (the folder that contains clamscan.exe^):
echo  Example: C:\Program Files\ClamAV
echo.
set /p CLAM_NEW_PATH="  Path: "
if "!CLAM_NEW_PATH!"=="" goto MENU_CLAMAV
if exist "kicomav_env\Scripts\python.exe" (
    kicomav_env\Scripts\python.exe -c ^
      "import json,pathlib; p=pathlib.Path('config/ui_settings.json'); s=json.loads(p.read_text()) if p.exists() else {}; s['clamav_path']='!CLAM_NEW_PATH!'; p.parent.mkdir(exist_ok=True); p.write_text(json.dumps(s,indent=2))"
    echo  [OK] Path saved to config/ui_settings.json
) else (
    echo  [WARN] kicomav_env not found -- path not saved. Set it in Settings after install.
)
echo.
echo  Press any key...
pause >nul
goto MAIN_MENU


REM ==========================================================================
REM  [5] System Junction
REM ==========================================================================
:MENU_JUNCTION
cls
echo.
echo  -- System Junction ---------------------------------------------
echo.
echo   Links %%USERPROFILE%%\.kicomav to config\
echo   Required for k2.exe to find its config on some systems.
echo.
if exist "%USERPROFILE%\.kicomav" (
    echo   Status: ACTIVE
    echo   Location: %USERPROFILE%\.kicomav
    echo.
    echo   [1] Remove junction
    echo   [2] Recreate junction  (if target path changed^)
    echo   [0] Back
) else (
    echo   Status: NOT SET UP
    echo.
    echo   [1] Create junction now
    echo   [0] Back
)
echo.
set /p C6="  Choose: "
if "!C6!"=="0" goto MAIN_MENU
if "!C6!"=="1" (
    if exist "%USERPROFILE%\.kicomav" ( goto JUNC_REMOVE ) else ( goto JUNC_CREATE )
)
if "!C6!"=="2" goto JUNC_RECREATE
goto MENU_JUNCTION

:JUNC_CREATE
echo.
call :ENSURE_JUNCTION
echo  Press any key...
pause >nul
goto MAIN_MENU

:JUNC_REMOVE
echo.
rmdir "%USERPROFILE%\.kicomav" 2>nul
echo  [OK] Junction removed. Press any key...
pause >nul
goto MAIN_MENU

:JUNC_RECREATE
echo.
rmdir "%USERPROFILE%\.kicomav" 2>nul
call :ENSURE_JUNCTION
echo  Press any key...
pause >nul
goto MAIN_MENU


REM ==========================================================================
REM  [A] Install / Update ALL
REM ==========================================================================
:INSTALL_ALL
cls
echo.
echo  Installing / updating all components...
echo.

call :CHECK_PYTHON || goto MAIN_MENU

echo [1/6] k2 Core venv...
if not exist "kicomav_env\Scripts\python.exe" (
    py -3.11 -m venv kicomav_env
)
kicomav_env\Scripts\pip.exe install --upgrade pip --quiet
kicomav_env\Scripts\pip.exe install --upgrade -r requirements.txt
echo  [OK] Core packages updated

echo [2/6] Directories...
call :ENSURE_DIRS
echo  [OK] Directories ready

echo [3/6] Config .env...
call :ENSURE_ENV
echo  [OK] Config ready

echo [4/6] System junction...
call :ENSURE_JUNCTION

echo [5/6] K2 engine signatures...
kicomav_env\Scripts\k2.exe --update

echo [6/6] Guardian AI...
if not exist "guardianai" (
    git clone https://github.com/MattEmilien/guardianai.git guardianai 2>nul
    if errorlevel 1 ( echo  [WARN] git not found - skipping Guardian AI clone )
)
if not exist "guardianai\data" mkdir "guardianai\data" 2>nul
if not exist "guardianai\data\known_bad.txt" type nul > "guardianai\data\known_bad.txt"
if not exist "guardian_env\Scripts\python.exe" (
    kicomav_env\Scripts\python.exe -m venv guardian_env
    guardian_env\Scripts\pip.exe install --quiet requests cryptography pywin32 Pillow pyuac
    echo  [OK] Guardian AI installed
) else (
    guardian_env\Scripts\pip.exe install --upgrade --quiet requests cryptography pywin32 Pillow pyuac
    echo  [OK] Guardian AI updated
)

echo.
echo  == All components up to date ==
echo.
echo  Launch PolyShield: double-click launch_ui.vbs
echo  Sandboxie-Plus: must be installed manually (see README.md^)
echo.
pause
goto MAIN_MENU


REM ==========================================================================
REM  [U] Uninstall specific component
REM ==========================================================================
:MENU_UNINSTALL
cls
echo.
echo  -- Remove a Component ------------------------------------------
echo.
echo   [1]  k2 Core engine (kicomav_env\^)
echo   [2]  Guardian AI  (guardian_env\ + guardianai\^)
echo   [3]  Intelligence Database  (intelligence\threat_db.sqlite^)
echo   [4]  System Junction  (%%USERPROFILE%%\.kicomav^)
echo   [5]  Windows Service  (PolyShieldService^)
echo   [6]  YARA Rules  (rules\user_rules\*.yar^)
echo   [0]  Back
echo.
set /p CU="  Choose: "
if "!CU!"=="0" goto MAIN_MENU
if "!CU!"=="1" goto UNINSTALL_CORE
if "!CU!"=="2" goto UNINSTALL_GUARDIAN
if "!CU!"=="3" goto INTEL_DELETE_ALL
if "!CU!"=="4" goto JUNC_REMOVE
if "!CU!"=="5" goto SVC_UNINSTALL
if "!CU!"=="6" goto UNINSTALL_YARA
goto MENU_UNINSTALL

:UNINSTALL_CORE
echo.
echo  WARNING: Removes kicomav_env\ (the entire Python environment + k2.exe).
echo  The app will not work until you reinstall.
set /p CONF="  Type YES to confirm: "
if /i not "!CONF!"=="YES" goto MENU_UNINSTALL
echo  Removing kicomav_env\...
rmdir /s /q kicomav_env
echo  [OK] Core removed. Press any key...
pause >nul
goto MAIN_MENU

:UNINSTALL_GUARDIAN
echo.
echo  WARNING: Removes guardian_env\ and guardianai\.
set /p CONF="  Type YES to confirm: "
if /i not "!CONF!"=="YES" goto MENU_UNINSTALL
if exist "guardian_env"  rmdir /s /q guardian_env
if exist "guardianai"    rmdir /s /q guardianai
echo  [OK] Guardian AI removed. Press any key...
pause >nul
goto MAIN_MENU

:UNINSTALL_YARA
echo.
echo  WARNING: Deletes all .yar files in rules\user_rules\.
set /p CONF="  Type YES to confirm: "
if /i not "!CONF!"=="YES" goto MENU_UNINSTALL
del /f /q "rules\user_rules\*.yar" 2>nul
echo  [OK] YARA rules removed. Press any key...
pause >nul
goto MAIN_MENU


REM ==========================================================================
REM  [X] Uninstall ALL
REM ==========================================================================
:UNINSTALL_ALL
cls
echo.
echo  +========================================================+
echo  ^|              FULL UNINSTALL                            ^|
echo  +========================================================+
echo  ^|  This will remove:                                     ^|
echo  ^|    kicomav_env\     (Python venv + k2.exe^)             ^|
echo  ^|    guardian_env\    (Guardian AI venv^)                 ^|
echo  ^|    guardianai\      (cloned repo^)                      ^|
echo  ^|    intelligence\    (threat database^)                  ^|
echo  ^|    logs\            (scan history^)                     ^|
echo  ^|    quarantine\      (quarantined files^)                ^|
echo  ^|    rules\           (k2 signatures^)                    ^|
echo  ^|    config\.env      (machine config^)                   ^|
echo  ^|    %%USERPROFILE%%\.kicomav  (junction^)                 ^|
echo  ^|                                                        ^|
echo  ^|  Source files (ui\, tools\, *.bat, *.vbs^) are         ^|
echo  ^|  kept - only generated/downloaded content removed.    ^|
echo  +========================================================+
echo.
set /p CONF="  Type UNINSTALL to confirm: "
if /i not "!CONF!"=="UNINSTALL" goto MAIN_MENU

echo.
echo  Removing components...
if exist "kicomav_env"   rmdir /s /q kicomav_env   && echo  [OK] kicomav_env removed
if exist "guardian_env"  rmdir /s /q guardian_env  && echo  [OK] guardian_env removed
if exist "guardianai"    rmdir /s /q guardianai     && echo  [OK] guardianai removed
if exist "intelligence"  rmdir /s /q intelligence   && echo  [OK] intelligence removed
if exist "logs"          rmdir /s /q logs           && echo  [OK] logs removed
if exist "quarantine"    rmdir /s /q quarantine     && echo  [OK] quarantine removed
if exist "rules"         rmdir /s /q rules          && echo  [OK] rules removed
if exist "config\.env"   del /f /q "config\.env"   && echo  [OK] config\.env removed
if exist "%USERPROFILE%\.kicomav" rmdir "%USERPROFILE%\.kicomav" && echo  [OK] junction removed

echo.
echo  Uninstall complete. Source files and README are untouched.
echo  Run install.bat to reinstall from scratch.
echo.
pause
goto MAIN_MENU


REM ==========================================================================
REM  [9] Diagnostics
REM ==========================================================================
:MENU_DIAG
cls
echo.
echo  -- PolyShield Diagnostics --------------------------------------
echo.
echo  This is a read-only check -- nothing is changed on your system.
echo.
echo  Checking Windows Defender PowerShell responsiveness (10s timeout^)...
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command ^
  "$sw=[Diagnostics.Stopwatch]::StartNew(); try { Get-MpComputerStatus -ErrorAction Stop | Out-Null; $sw.Stop(); Write-Host ('  [OK] Get-MpComputerStatus responded in ' + [int]$sw.Elapsed.TotalMilliseconds + ' ms') } catch { $sw.Stop(); Write-Host ('  [FAIL] ' + $_.Exception.Message) }" ^
  2>nul
echo.
echo  Reading Device Security registry keys (no elevation required^)...
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command ^
  "$hklm = 'HKLM:\'; $sb = Get-ItemProperty -Path ($hklm+'SYSTEM\CurrentControlSet\Control\SecureBoot\State') -Name UEFISecureBootEnabled -ErrorAction SilentlyContinue; if ($sb) { Write-Host ('  Secure Boot : ' + $(if($sb.UEFISecureBootEnabled -eq 1){'ENABLED'}else{'DISABLED'}) + ' (raw=' + $sb.UEFISecureBootEnabled + ')') } else { Write-Host '  Secure Boot : key not found (UEFI not present or key missing)' }; $tpm = Test-Path ($hklm+'SYSTEM\CurrentControlSet\Services\TPM'); Write-Host ('  TPM driver  : ' + $(if($tpm){'PRESENT (service key exists)'}else{'NOT FOUND (no TPM or driver not loaded)'})); $vbs = Get-ItemProperty -Path ($hklm+'SYSTEM\CurrentControlSet\Control\DeviceGuard') -Name EnableVirtualizationBasedSecurity -ErrorAction SilentlyContinue; if ($vbs) { Write-Host ('  VBS enabled : ' + $(if($vbs.EnableVirtualizationBasedSecurity -eq 1){'YES'}else{'NO'}) + ' (raw=' + $vbs.EnableVirtualizationBasedSecurity + ')') } else { Write-Host '  VBS enabled : key not found (VBS not configured)' }" ^
  2>nul
echo.
echo  Checking quarantine folder access...
if exist "quarantine" (
    dir /b "quarantine" >nul 2>&1
    if not errorlevel 1 (
        echo   [OK] quarantine\ is readable by current user
    ) else (
        echo   [FAIL] quarantine\ exists but cannot be listed - ACL may be misconfigured
        echo   Fix: run setup_service.bat to reset ACLs, then verify no DENY ace exists
    )
) else (
    echo   [OK] quarantine\ does not exist yet (created on first use^)
)
echo.
echo  Done. Press any key to return to menu...
pause >nul
goto MAIN_MENU


REM ==========================================================================
REM  Shared subroutines
REM ==========================================================================

:CHECK_PYTHON
py --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python not found. Install Python 3.11+ from https://python.org
    pause >nul
    exit /b 1
)
exit /b 0

:ENSURE_DIRS
for %%d in (config logs quarantine intelligence rules) do (
    if not exist "%%d" mkdir "%%d"
)
if not exist "rules\user_rules" mkdir "rules\user_rules"
exit /b 0

:ENSURE_ENV
if not exist "config\.env" (
    set "ROOT=%~dp0"
    set "ROOT=!ROOT:~0,-1!"
    (
        echo SYSTEM_RULES_BASE=!ROOT!\rules
        echo USER_RULES_BASE=!ROOT!\user_rules
        echo KICOMAV_SUPPRESS_WARNINGS=1
    ) > config\.env
    echo  [OK] config\.env created
)
exit /b 0

:ENSURE_JUNCTION
if not exist "%USERPROFILE%\.kicomav" (
    mklink /J "%USERPROFILE%\.kicomav" "%~dp0config" >nul 2>&1
    if errorlevel 1 (
        echo  [WARN] Junction creation failed. Try running as Administrator.
    ) else (
        echo  [OK] Junction created: %%USERPROFILE%%\.kicomav -^> config\
    )
) else (
    echo  [OK] Junction already exists
)
exit /b 0

:END
echo.
exit /b 0
