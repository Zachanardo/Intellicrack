@echo off
echo ============================================================================
echo                      Intellicrack Dependency Installer
echo ============================================================================
echo.

REM Navigate to project directory
cd /d "%~dp0"

REM Run the Python installer script
python install_helper.py

pause