@echo off
pushd "%~dp0..\.."
call "kicomav_env\Scripts\activate.bat"
start "" "kicomav_env\Scripts\pythonw.exe" "src\ui\app.py"
