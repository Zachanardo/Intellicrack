@echo off
cd /d "%~dp0"

echo Running Intellicrack diagnostics...
echo.

REM Activate the virtual environment
if exist "venv_windows\Scripts\activate.bat" (
    echo Activating virtual environment...
    call venv_windows\Scripts\activate.bat
) else (
    echo ERROR: Virtual environment not found
    pause
    exit /b 1
)

REM Set safe mode environment
set QT_OPENGL=software
set INTELLICRACK_NO_SPLASH=1

echo.
python diagnose.py
echo.
pause