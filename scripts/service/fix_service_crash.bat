@echo off
setlocal
pushd "%~dp0..\.."

REM -- Self-elevate -----------------------------------------------------------
NET SESSION >nul 2>&1
if errorlevel 1 (
    echo Requesting administrator privileges...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo.
echo  ============================================================
echo   PolyShield -- Service Crash Recovery
echo  ============================================================
echo.

REM After pushd "%~dp0..\.." above, CWD is the project root.
for %%I in (".") do set "ROOT=%%~fI"

set "VENV=%ROOT%\kicomav_env"
set "PYEXE=%VENV%\Scripts\python.exe"
set "PYWEXE=%VENV%\Scripts\pythonw.exe"

echo  Project root : %ROOT%
echo  Venv python  : %PYEXE%
echo.

echo [1/4] Adding Defender process exclusion for python.exe...
powershell -NoProfile -Command "Add-MpPreference -ExclusionProcess '%PYEXE%'"
if exist "%PYWEXE%" (
    powershell -NoProfile -Command "Add-MpPreference -ExclusionProcess '%PYWEXE%'"
)
echo   [OK]

echo [2/4] Adding Defender path exclusion for kicomav_env...
powershell -NoProfile -Command "Add-MpPreference -ExclusionPath '%VENV%'"
echo   [OK]

echo [3/4] Re-registering pywin32 system DLLs...
"%PYEXE%" -m pywin32_postinstall -install >nul 2>&1
echo   [OK]

echo [4/4] Starting PolyShieldService...
sc start PolyShieldService
timeout /t 3 /nobreak >nul
sc query PolyShieldService | find "RUNNING" >nul
if errorlevel 1 (
    echo.
    echo   [WARN] Service did NOT reach RUNNING state.
    echo          Check C:\ProgramData\PolyShield\service.log for new entries
    echo          and the Application event log for python.exe crashes.
    echo.
    sc query PolyShieldService
) else (
    echo.
    echo   [OK] Service is RUNNING.
)

echo.
echo  ============================================================
echo  Done. Press any key to close this window.
echo  ============================================================
pause >nul
