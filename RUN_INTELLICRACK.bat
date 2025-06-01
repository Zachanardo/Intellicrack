@echo off
echo === Intellicrack Launcher ===
echo.

REM Navigate to project directory  
cd /d "%~dp0"

REM Quick verification
echo Verifying fixes...
python verify_fixes.py >nul 2>&1
if errorlevel 1 (
    echo WARNING: Some fixes may not be working properly
)

echo.
echo Launching Intellicrack...

REM Set environment to suppress warnings
set PYTHONWARNINGS=ignore::UserWarning:pytools.persistent_dict
set QT_QPA_FONTDIR=
set QT_LOGGING_RULES=*.debug=false;qt.qpa.fonts=false

REM Launch Intellicrack using the fixed launcher
python launch_intellicrack.py

if errorlevel 1 (
    echo.
    echo ============================================================================
    echo ERROR: Failed to launch Intellicrack
    echo.
    echo Check the error messages above.
    echo To reinstall PyQt5: python -m pip install PyQt5==5.15.9 --force-reinstall
    echo ============================================================================
    pause
)