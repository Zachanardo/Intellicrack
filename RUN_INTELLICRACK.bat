@echo off
cd /d "%~dp0"

echo Starting Intellicrack...
echo.

REM This is a Windows batch file, so we're on Windows
REM Activate the Windows virtual environment
if exist ".venv_windows\Scripts\activate.bat" (
    echo Activating Windows UV virtual environment...
    call .venv_windows\Scripts\activate.bat
) else if exist ".venv\Scripts\activate.bat" (
    echo Activating fallback UV virtual environment...
    call .venv\Scripts\activate.bat
) else if exist "venv_windows\Scripts\activate.bat" (
    echo Activating legacy virtual environment...
    call venv_windows\Scripts\activate.bat
) else (
    echo ERROR: Virtual environment not found
    echo Please ensure Windows UV environment is created with 'uv venv .venv_windows'
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

REM The Python launcher will auto-detect GPU and apply appropriate settings

echo Running: python launch_intellicrack.py
echo.

REM Run the application only once
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
    echo This might be a graphics driver issue
) else (
    echo Intellicrack exited with code: %EXIT_CODE%
)

echo.
echo Press any key to exit...
pause >nul