@echo off
cd /d "%~dp0"

echo Starting Intellicrack in SAFE MODE (Software Rendering)...
echo.

REM Activate the virtual environment
if exist "venv_windows\Scripts\activate.bat" (
    echo Activating virtual environment...
    call venv_windows\Scripts\activate.bat
) else (
    echo ERROR: Virtual environment not found at venv_windows\Scripts\activate.bat
    echo Please run dependencies\install_dependencies.bat first
    pause
    exit /b 1
)

REM Basic settings that apply to all systems
set PYTHONWARNINGS=ignore::UserWarning:pytools.persistent_dict
set QT_QPA_FONTDIR=%WINDIR%\Fonts
set QT_LOGGING_RULES=*.debug=false;qt.qpa.fonts=false
set QT_ASSUME_STDERR_HAS_CONSOLE=1
set QT_FONT_DPI=96

REM Suppress TensorFlow oneDNN messages
set TF_ENABLE_ONEDNN_OPTS=0

REM Force software rendering mode
set INTELLICRACK_FORCE_SOFTWARE=1

echo Running in SAFE MODE with software rendering...
echo This may be slower but should work on all systems.
echo.

REM Run the application
python launch_intellicrack.py

REM Capture the exit code
set EXIT_CODE=%ERRORLEVEL%

echo.
echo Exit code: %EXIT_CODE%
echo.

if %EXIT_CODE% equ 0 (
    echo Intellicrack closed normally
) else if %EXIT_CODE% equ 1 (
    echo ERROR: Intellicrack failed to start
    echo Check the logs for more information
) else if %EXIT_CODE% equ -1073741819 (
    echo ERROR: Qt application crashed (Access violation)
    echo Even safe mode failed - please check your graphics drivers
) else if %EXIT_CODE% equ -805306369 (
    echo ERROR: Graphics compatibility issue persists
    echo Please update your graphics drivers
) else (
    echo Intellicrack exited with code: %EXIT_CODE%
)

echo.
echo Press any key to exit...
pause >nul