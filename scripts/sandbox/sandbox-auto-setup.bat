@echo off
REM Sandbox auto-setup
REM Copies source files to a fresh local sandbox folder so the venv is
REM built with sandbox Python paths (not the host miniconda paths).
REM The host project folder is never modified.
REM Pip cache persists across sandbox runs via mapped C:\pip_cache folder.
REM
REM !! Run this INSIDE Windows Sandbox only -- not on the host machine !!
REM    Double-click from C:\PolyShield_Project\scripts\sandbox\ in the sandbox.

setlocal enabledelayedexpansion

set "SOURCE=C:\PolyShield_Project"
set "DEST=C:\PolyShield_Sandbox"
set "PYPATH=C:\python_embed;C:\python_embed\Scripts"

echo.
echo ================================================
echo   PolyShield Sandbox Setup
echo ================================================
echo.

REM Set PATH to include portable Python for this session
set "PATH=%PYPATH%;%PATH%"

REM Point pip at the persistent cache so packages survive sandbox restarts
set "PIP_CACHE_DIR=C:\pip_cache"

REM Verify Python
echo [1/3] Checking Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python not found. Is C:\python_embed mapped?
    pause
    exit /b 1
)
echo  [OK] Python available

REM Copy source files to local sandbox dir
REM Excludes: venvs, generated dirs, machine-specific config
echo.
echo [2/3] Copying source files to %DEST%...
if not exist "%DEST%" mkdir "%DEST%"
robocopy "%SOURCE%" "%DEST%" /E ^
  /XD kicomav_env guardian_env guardianai intelligence logs quarantine rules user_rules .tokensave ^
  /XF "*.db" ".env" "ui_settings.json" ^
  /NP /NJH /NJS >nul 2>&1
echo  [OK] Source files copied

REM Run install.bat from the clean local copy
cd /d "%DEST%"
echo.
echo [3/3] Installing and launching PolyShield...
call scripts\install.bat

start launch_ui.vbs
echo.
echo Done!
timeout /t 3 /nobreak >nul
