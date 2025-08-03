@echo off
cd /d "%~dp0"

echo DEBUG: Starting Intellicrack Debug Launch
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

REM Clear Qt platform if set to offscreen
if "%QT_QPA_PLATFORM%"=="offscreen" (
    echo WARNING: QT_QPA_PLATFORM was set to offscreen, clearing it...
    set QT_QPA_PLATFORM=
)

REM Set Qt to use Windows native platform
set QT_QPA_PLATFORM=windows

echo.
echo Environment:
echo - Python: %PYTHON%
echo - QT_QPA_PLATFORM: %QT_QPA_PLATFORM%
echo - Working Directory: %CD%
echo.

REM First test if Qt works at all
echo Testing basic Qt window...
python test_window.py
if errorlevel 1 (
    echo.
    echo ERROR: Basic Qt test failed!
    echo Qt may not be properly installed or configured.
    pause
    exit /b 1
)

echo.
echo Basic Qt test passed. Now launching Intellicrack...
echo.

REM Run Intellicrack with explicit platform
python -c "import os; os.environ['QT_QPA_PLATFORM']='windows'; from intellicrack.main import main; main()"

echo.
echo Exit code: %ERRORLEVEL%
pause
