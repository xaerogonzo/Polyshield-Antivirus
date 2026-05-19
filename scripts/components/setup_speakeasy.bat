@echo off
REM Setup script for Speakeasy PE emulator
REM Installs speakeasy-emulator into the kicomav_env portable venv

pushd "%~dp0..\.."

echo Installing Speakeasy PE Emulator...
echo This may take 30-60 seconds...
echo.

kicomav_env\Scripts\pip.exe install speakeasy-emulator

if %errorlevel% equ 0 (
    echo.
    echo [OK] Speakeasy installed successfully!
    echo.
    echo Restart PolyShield and check Settings ^> Behavioral Analysis.
    echo You should see a green "Ready" badge for Speakeasy.
) else (
    echo.
    echo [ERROR] Installation failed. Check your internet connection.
)

pause
