@echo off
echo Testing Intellicrack launch...

REM Set environment for Intel Arc
set QT_OPENGL=software
set QT_QUICK_BACKEND=software
set INTELLICRACK_FORCE_SOFTWARE=1

REM Simple timestamp
set LOG_FILE=test_launch_%RANDOM%.log

echo Log file: %LOG_FILE%

REM Run Python and exit immediately
if exist ".venv_windows\Scripts\python.exe" (
    echo Using Windows venv...
    .venv_windows\Scripts\python.exe launch_intellicrack.py > "%LOG_FILE%" 2>&1
) else (
    echo Using system Python...
    python launch_intellicrack.py > "%LOG_FILE%" 2>&1
)

echo Exit code: %ERRORLEVEL%
echo Check log: %LOG_FILE%
