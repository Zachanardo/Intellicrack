@echo off
REM Intellicrack startup script for Intel Arc Graphics compatibility
REM This script forces software rendering to avoid Intel Arc driver crashes

echo Starting Intellicrack with Intel Arc Graphics compatibility...

REM Set Qt environment variables for maximum compatibility
set QT_OPENGL=software
set QT_QUICK_BACKEND=software
set QT_QPA_PLATFORM=windows
set QT_OPENGL_BUGLIST=1
set QT_DISABLE_WINDOWSCOMPOSITION=1
set QT_ENABLE_HIGHDPI_SCALING=0
set QT_AUTO_SCREEN_SCALE_FACTOR=0
set QT_SCALE_FACTOR=1
set INTELLICRACK_FORCE_SOFTWARE=1
set INTELLICRACK_NO_SPLASH=1

REM Intel specific workarounds
set INTEL_DEBUG=nofc,sync

REM Suppress CUDA warnings on Intel systems (but keep other warnings visible)
set CUPY_CUDA_PATH=
set CUDA_VISIBLE_DEVICES=
set TF_CPP_MIN_LOG_LEVEL=1

echo Environment configured for Intel Arc Graphics compatibility
echo Starting Intellicrack...

REM Create timestamp for log file
for /f "tokens=2 delims==" %%a in ('wmic OS Get localdatetime /value') do set "dt=%%a"
set "YY=%dt:~2,2%" & set "YYYY=%dt:~0,4%" & set "MM=%dt:~4,2%" & set "DD=%dt:~6,2%"
set "HH=%dt:~8,2%" & set "Min=%dt:~10,2%" & set "Sec=%dt:~12,2%"
set "datestamp=%YYYY%%MM%%DD%" & set "timestamp=%HH%%Min%%Sec%"
set "LOG_FILE=intellicrack_arc_crash_%datestamp%_%timestamp%.log"

echo.
echo Logging output to: %LOG_FILE%
echo This will help diagnose crashes...

REM Check if virtual environment exists and activate it
if exist ".venv_windows\Scripts\activate.bat" (
    echo Activating Windows virtual environment...
    call .venv_windows\Scripts\activate.bat
    echo.
    echo Virtual environment activated. Starting Intellicrack with Intel Arc compatibility...
    echo.
    echo ============================================================
    echo Starting Python execution - Console will remain open on crash
    echo ============================================================
    python launch_intellicrack.py 2>&1 | powershell -command "& {$input | Tee-Object -FilePath '%LOG_FILE%'}"
    set EXITCODE=%ERRORLEVEL%
    echo ============================================================
    echo Python execution finished with exit code: %EXITCODE%
    echo ============================================================
    deactivate
) else if exist ".venv_windows\Scripts\python.exe" (
    echo Using Windows virtual environment Python directly...
    echo.
    echo ============================================================
    echo Starting Python execution - Console will remain open on crash
    echo ============================================================
    .venv_windows\Scripts\python.exe launch_intellicrack.py 2>&1 | powershell -command "& {$input | Tee-Object -FilePath '%LOG_FILE%'}"
    set EXITCODE=%ERRORLEVEL%
    echo ============================================================
    echo Python execution finished with exit code: %EXITCODE%
    echo ============================================================
) else (
    echo No virtual environment found, running with system Python...
    echo.
    echo ============================================================
    echo Starting Python execution - Console will remain open on crash
    echo ============================================================
    python launch_intellicrack.py 2>&1 | powershell -command "& {$input | Tee-Object -FilePath '%LOG_FILE%'}"
    set EXITCODE=%ERRORLEVEL%
    echo ============================================================
    echo Python execution finished with exit code: %EXITCODE%
    echo ============================================================
)

echo.
echo Intellicrack has exited.

REM Always show the log file location
if exist "%LOG_FILE%" (
    echo.
    echo ============================================================
    echo CRASH LOG SAVED TO: %LOG_FILE%
    echo You can open this file to see what happened.
    echo ============================================================
)

echo.
echo Press any key to close this window...
pause > nul