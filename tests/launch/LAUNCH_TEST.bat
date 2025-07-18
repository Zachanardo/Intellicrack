@echo off
REM Simple test launcher for Intellicrack - no hanging

REM Set Intel Arc environment
set QT_OPENGL=software
set QT_QUICK_BACKEND=software
set INTELLICRACK_FORCE_SOFTWARE=1
set INTEL_DEBUG=nofc,sync
set INTELLICRACK_NO_SPLASH=1

REM Delete old log file
if exist output_test.log del output_test.log

REM Run Python and capture output
echo Starting Intellicrack test launch... > output_test.log 2>&1
echo. >> output_test.log 2>&1

if exist ".venv_windows\Scripts\python.exe" (
    echo Using Windows venv >> output_test.log 2>&1
    .venv_windows\Scripts\python.exe launch_intellicrack.py >> output_test.log 2>&1
) else (
    echo Using system Python >> output_test.log 2>&1
    python launch_intellicrack.py >> output_test.log 2>&1
)

echo. >> output_test.log 2>&1
echo Exit code: %ERRORLEVEL% >> output_test.log 2>&1