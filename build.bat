@echo off
REM Launcher for build.ps1 - bypasses execution policy and keeps the window
REM open at the end so build output stays visible.
REM
REM   build.bat                 build everything (4b.1: GUI + path probe)
REM   build.bat -Target probe   just the path probe (fast)
REM   build.bat -NoClean        iterate without wiping dist\ first
powershell -ExecutionPolicy Bypass -NoProfile -File "%~dp0build.ps1" %*
pause
