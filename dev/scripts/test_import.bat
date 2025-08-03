@echo off
cd /d "%~dp0"

echo Testing Intellicrack imports...
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

echo.
python test_import.py
echo.
pause
