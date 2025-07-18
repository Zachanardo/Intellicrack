@echo off
cd /d "%~dp0"

echo Direct launch test...
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
python direct_launch.py
echo.
echo Exit code: %ERRORLEVEL%
pause