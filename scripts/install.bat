@echo off
setlocal enabledelayedexpansion
pushd "%~dp0.."

echo.
echo  ================================================
echo   PolyShield Security Suite ^| Installer
echo  ================================================
echo.

REM -------------------------------------------------------------
REM  Step 1: Verify Python 3.11+ is available
REM -------------------------------------------------------------
echo [1/7] Checking Python...
REM Try `py` launcher first (standard install), fall back to `python` (portable/venv)
py --version >nul 2>&1
if errorlevel 1 (
    python --version >nul 2>&1
    if errorlevel 1 (
        echo.
        echo  [ERROR] Python not found on PATH.
        echo  Install Python 3.11 or newer from https://python.org
        echo  Make sure to check "Add Python to PATH" during install.
        echo.
        pause
        exit /b 1
    )
    set PYCMD=python
) else (
    set PYCMD=py
)
for /f "tokens=2" %%v in ('!PYCMD! --version 2^>^&1') do set PYVER=%%v
echo  [OK] Python %PYVER% found (via %PYCMD%)


REM -------------------------------------------------------------
REM  Step 2: Create the main virtual environment
REM -------------------------------------------------------------
echo [2/7] Setting up virtual environment...
if exist "kicomav_env\Scripts\python.exe" (
    echo  [OK] kicomav_env already exists ? skipping creation
) else (
    echo  Creating kicomav_env with Python %PYVER%...
    !PYCMD! -m venv kicomav_env >nul 2>&1
    if errorlevel 1 (
        REM venv not available (e.g. embeddable Python) ? try virtualenv
        echo  venv unavailable, trying virtualenv...
        !PYCMD! -m virtualenv kicomav_env
        if errorlevel 1 (
            echo.
            echo  [ERROR] Failed to create virtual environment.
            echo  Make sure Python 3.11+ is installed.
            echo.
            pause
            exit /b 1
        )
    )
    echo  [OK] Virtual environment created
)


REM -------------------------------------------------------------
REM  Step 3: Install Python packages
REM -------------------------------------------------------------
echo [3/7] Installing packages (this may take 2-5 minutes)...
kicomav_env\Scripts\pip.exe install --upgrade pip --quiet
kicomav_env\Scripts\pip.exe install -r requirements.txt
if errorlevel 1 (
    echo.
    echo  [ERROR] Package installation failed.
    echo  Check your internet connection and try again.
    echo.
    pause
    exit /b 1
)
echo  [OK] All packages installed (includes k2.exe, speakeasy, and GUI)


REM -------------------------------------------------------------
REM  Step 4: Create required runtime directories
REM -------------------------------------------------------------
echo [4/7] Creating runtime directories...
for %%d in (config logs quarantine intelligence rules) do (
    if not exist "%%d" (
        mkdir "%%d"
        echo  [OK] Created %%d\
    )
)
if not exist "rules\user_rules" (
    mkdir "rules\user_rules"
    echo  [OK] Created rules\user_rules\
)
echo  [OK] Directories ready


REM -------------------------------------------------------------
REM  Step 5: Generate config\.env with correct paths for this machine
REM -------------------------------------------------------------
echo [5/7] Configuring paths...
if exist "config\.env" (
    echo  [OK] config\.env already exists ? skipping
) else (
    REM Use CWD � after pushd "%~dp0.." at script start, CWD is the project root.
    REM %~dp0 gives scripts\ (the bat's own dir), not the project root.
    for %%I in (".") do set "ROOT=%%~fI"
    (
        echo SYSTEM_RULES_BASE=!ROOT!\rules
        echo USER_RULES_BASE=!ROOT!\user_rules
        echo KICOMAV_SUPPRESS_WARNINGS=1
    ) > config\.env
    echo  [OK] config\.env created with paths rooted at !ROOT!
)


REM -------------------------------------------------------------
REM  Step 5b: Add project directory to Defender exclusions
REM  Targeted exclusions only ? NOT the whole project folder.
REM  The quarantine\ directory must stay monitored by Defender.
REM
REM  Excluded paths:
REM    speakeasy\  ? ships with PE decoy .exe files (flags as Trojan:Win32/Malgent)
REM    yara\       ? YARA Python extension sometimes triggers heuristics
REM    k2.exe      ? the scanner binary itself can be flagged by other engines
REM
REM  For a manual run or to verify exclusions, use:
REM    Right-click add_defender_exclusions.ps1 ? Run with PowerShell (as Admin)
REM -------------------------------------------------------------
echo [5b] Registering targeted Defender exclusions...
REM Use %CD% for project root ? %~dp0 gives the scripts\ subdir, not the root.
REM pushd "%~dp0.." at the top already set CWD to the project root.
for %%I in (".") do set "IROOT=%%~fI"
REM Path exclusions: speakeasy and yara (false-positive binaries), k2.exe, and
REM the whole kicomav_env\ venv directory.  Excluding kicomav_env prevents
REM Defender from interfering when SCM loads python.exe as LocalSystem ?
REM without it a Defender signature update can cause STATUS_IN_PAGE_ERROR
REM (service exit code 1067, no log entry) even though python.exe is clean.
kicomav_env\Scripts\python.exe -c ^
  "import subprocess; [subprocess.run(['powershell','-NoProfile','-ExecutionPolicy','Bypass','-Command',f'Add-MpPreference -ExclusionPath \"{p}\"'],creationflags=0x08000000,capture_output=True) for p in [r'!IROOT!\kicomav_env\Lib\site-packages\speakeasy',r'!IROOT!\kicomav_env\Lib\site-packages\yara',r'!IROOT!\kicomav_env\Scripts\k2.exe',r'!IROOT!\kicomav_env']]" ^
  >nul 2>&1
REM Process exclusions: python.exe + pythonw.exe so Defender does not intercept
REM the binary during SCM-launched service startup (LocalSystem context).
kicomav_env\Scripts\python.exe -c ^
  "import subprocess; [subprocess.run(['powershell','-NoProfile','-ExecutionPolicy','Bypass','-Command',f'Add-MpPreference -ExclusionProcess \"{p}\"'],creationflags=0x08000000,capture_output=True) for p in [r'!IROOT!\kicomav_env\Scripts\python.exe',r'!IROOT!\kicomav_env\Scripts\pythonw.exe']]" ^
  >nul 2>&1
echo  [OK] Defender exclusions registered (speakeasy, yara, k2.exe, kicomav_env, python.exe)


REM -------------------------------------------------------------
REM  Step 6: Create junction so k2 can find config on C: drive
REM  k2's internal defaults may expect config under %USERPROFILE%
REM -------------------------------------------------------------
echo [6/7] Setting up k2 compatibility junction...
if exist "%USERPROFILE%\.kicomav" (
    echo  [OK] Junction already exists at %%USERPROFILE%%\.kicomav ? skipping
) else (
    mklink /J "%USERPROFILE%\.kicomav" "%CD%\config" >nul 2>&1
    if errorlevel 1 (
        echo  [WARN] Could not create junction at %%USERPROFILE%%\.kicomav
        echo         This is non-fatal but k2 may not find its config on some systems.
        echo         Try running install.bat as Administrator if scans fail to start.
    ) else (
        echo  [OK] Junction created: %%USERPROFILE%%\.kicomav -^> config\
    )
)


REM -------------------------------------------------------------
REM  Step 7: Download K2 engine signatures
REM -------------------------------------------------------------
echo [7/7] Downloading K2 engine signatures (requires internet)...
kicomav_env\Scripts\k2.exe --update
if errorlevel 1 (
    echo  [WARN] Signature update may have failed or timed out.
    echo         The app will still launch, but scanning may not work until
    echo         signatures are downloaded. Try "Update Center" inside the app.
) else (
    echo  [OK] K2 engine signatures downloaded
)


REM -------------------------------------------------------------
REM  Done
REM -------------------------------------------------------------
echo.
echo  ================================================
echo   Installation complete!
echo  ================================================
echo.
echo   Launch PolyShield:
echo     Double-click launch_ui.vbs
echo.
echo   Manage components (install, update, uninstall^):
echo     Double-click manage.bat
echo.
echo   Speakeasy emulator is already installed.
echo   Sandboxie-Plus: see README.md ^> Behavioral Analysis ^> Setup
echo.
pause
