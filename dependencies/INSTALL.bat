@echo off
REM Launcher for the main installer - launches Install.ps1 from same directory

echo Starting Intellicrack installer...
cd /d "%~dp0"
powershell -ExecutionPolicy Bypass -File "Install.ps1"

REM After installation, fix tool paths
echo.
echo Fixing tool paths...
python fix_tool_paths.py

echo.
echo Installation complete!
pause