@echo off
pushd "%~dp0..\.."

echo =========================================
echo  GuardianAI Setup
echo =========================================
echo.

REM ── Clone the repo ─────────────────────────────────────────────────────────
if not exist "guardianai" (
    echo [1/3] Cloning GuardianAI repository...
    git clone https://github.com/MattEmilien/guardianai.git guardianai
    if errorlevel 1 (
        echo [ERROR] Git clone failed. Ensure git is installed and you have internet access.
        pause
        exit /b 1
    )
    echo       Done.
) else (
    echo [1/3] guardianai\ already exists — skipping clone.
)

REM ── Create portable venv ────────────────────────────────────────────────────
if not exist "guardian_env" (
    echo [2/3] Creating portable Python environment...
    kicomav_env\Scripts\python.exe -m venv guardian_env
    if errorlevel 1 (
        echo [ERROR] Failed to create venv. Ensure kicomav_env exists and is functional.
        pause
        exit /b 1
    )
    echo       Done.
) else (
    echo [2/3] guardian_env\ already exists — skipping creation.
)

REM ── Install dependencies ────────────────────────────────────────────────────
echo [3/3] Installing Guardian AI dependencies...
guardian_env\Scripts\pip.exe install --quiet requests cryptography pywin32 Pillow pyuac
if errorlevel 1 (
    echo [WARNING] Some packages may have failed to install. Check output above.
) else (
    echo       Done.
)

REM ── Ensure data directory exists ────────────────────────────────────────────
if not exist "guardianai\data" (
    mkdir guardianai\data
)
if not exist "guardianai\data\known_bad.txt" (
    echo. > guardianai\data\known_bad.txt
)

echo.
echo =========================================
echo  Setup complete!
echo  - Run launch_guardian.vbs to open the
echo    standalone GuardianAI window.
echo  - Or use "Guardian AI" in the PolyShield
echo    sidebar for the integrated experience.
echo =========================================
echo.
pause
