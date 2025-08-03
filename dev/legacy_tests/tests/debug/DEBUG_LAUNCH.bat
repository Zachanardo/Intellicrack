@echo off
REM Minimal debug launcher for Intellicrack to isolate crash issues

echo =================================================================
echo INTELLICRACK DEBUG LAUNCHER
echo =================================================================
echo This script will attempt to identify where the crash occurs
echo.

REM Set minimal environment for debugging
set QT_DEBUG_PLUGINS=1
set QT_LOGGING_RULES=*.debug=true
set INTELLICRACK_FORCE_SOFTWARE=1
set INTELLICRACK_NO_SPLASH=1
set QT_OPENGL=software
set QT_QUICK_BACKEND=software

echo Environment variables set for debugging...
echo QT_OPENGL=%QT_OPENGL%
echo INTELLICRACK_FORCE_SOFTWARE=%INTELLICRACK_FORCE_SOFTWARE%
echo.

echo =================================================================
echo STEP 1: Testing Python import
echo =================================================================
if exist ".venv_windows\Scripts\python.exe" (
    echo Testing basic Python functionality...
    .venv_windows\Scripts\python.exe -c "print('Python is working'); import sys; print(f'Python version: {sys.version}')"
    if %ERRORLEVEL% NEQ 0 (
        echo ERROR: Python basic test failed
        goto :error
    )
    echo Python basic test: PASSED
    echo.

    echo =================================================================
    echo STEP 2: Testing PyQt5 import
    echo =================================================================
    echo Testing PyQt5 import...
    .venv_windows\Scripts\python.exe -c "from PyQt5.QtWidgets import QApplication; print('PyQt5 import: PASSED')"
    if %ERRORLEVEL% NEQ 0 (
        echo ERROR: PyQt5 import failed
        goto :error
    )
    echo.

    echo =================================================================
    echo STEP 3: Testing Intellicrack imports
    echo =================================================================
    echo Testing Intellicrack module imports...
    .venv_windows\Scripts\python.exe -c "import intellicrack; print('Intellicrack import: PASSED')"
    if %ERRORLEVEL% NEQ 0 (
        echo ERROR: Intellicrack import failed
        goto :error
    )
    echo.

    echo =================================================================
    echo STEP 4: Launching Intellicrack (clean output)
    echo =================================================================
    echo Starting Intellicrack...
    .venv_windows\Scripts\python.exe launch_intellicrack.py
    set FINAL_EXIT_CODE=%ERRORLEVEL%
    echo.
    echo =================================================================
    echo Intellicrack exited with code: %FINAL_EXIT_CODE%
    echo =================================================================
) else (
    echo ERROR: Virtual environment not found at .venv_windows\Scripts\python.exe
    goto :error
)

goto :end

:error
echo.
echo =================================================================
echo AN ERROR OCCURRED DURING DEBUGGING
echo =================================================================
echo The error occurred before the main application could start.
echo This helps narrow down the issue.

:end
echo.
echo Press any key to close this window...
pause > nul
