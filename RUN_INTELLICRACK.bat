@echo off
cd /d "%~dp0"

echo Starting Intellicrack...
echo.

set PYTHONWARNINGS=ignore::UserWarning:pytools.persistent_dict
set QT_QPA_FONTDIR=%WINDIR%\Fonts
set QT_LOGGING_RULES=*.debug=false;qt.qpa.fonts=false
set QT_ASSUME_STDERR_HAS_CONSOLE=1
set QT_FONT_DPI=96

echo Running: python launch_intellicrack.py
echo.

python launch_intellicrack.py 2>&1

echo.
echo Exit code: %ERRORLEVEL%
echo.
if errorlevel 1 (
    echo ERROR: Intellicrack failed to start
) else (
    echo Intellicrack closed normally
)
echo.
echo Press any key to exit...
pause >nul