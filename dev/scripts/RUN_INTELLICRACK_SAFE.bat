@echo off
cd /d "%~dp0"

echo Starting Intellicrack in Safe Mode (No splash screen, software rendering)...
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

set PYTHONWARNINGS=ignore::UserWarning:pytools.persistent_dict

REM Force software rendering for maximum compatibility
set QT_OPENGL=software
set QT_QUICK_BACKEND=software
set QT_ANGLE_PLATFORM=d3d11
set QT_ENABLE_HIGHDPI_SCALING=0
set QT_AUTO_SCREEN_SCALE_FACTOR=0
set QT_SCALE_FACTOR=1
set QT_QPA_PLATFORM=windows

REM Disable splash screen
set INTELLICRACK_NO_SPLASH=1

REM Qt settings
set QT_QPA_FONTDIR=%WINDIR%\Fonts
set QT_LOGGING_RULES=*.debug=false;qt.qpa.fonts=false
set QT_ASSUME_STDERR_HAS_CONSOLE=1
set QT_FONT_DPI=96

REM Disable hardware acceleration that might cause crashes
set QSG_RENDER_LOOP=basic

echo Environment configured for safe mode
echo.

echo Running: python -u launch_intellicrack.py
echo.

REM Run the application with unbuffered output
python -u launch_intellicrack.py

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
) else if %EXIT_CODE% equ -805306369 (
    echo ERROR: Qt/Graphics crash detected
    echo Please update your graphics drivers
) else if %EXIT_CODE% equ -1073741819 (
    echo ERROR: Access violation
    echo This might be a graphics driver issue
) else (
    echo Intellicrack exited with code: %EXIT_CODE%
)

echo.
echo Press any key to exit...
pause >nul