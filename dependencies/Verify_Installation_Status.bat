@echo off
REM Quick setup verification for Intellicrack launch
REM This script performs essential tool checks before launching

setlocal enabledelayedexpansion

set PROJECT_ROOT=%~dp0..\..
set VERIFICATION_PASSED=1

REM Check Python and critical packages
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python not found - setup required
    set VERIFICATION_PASSED=0
    goto :end
)

REM Quick check of critical Python packages
python -c "import PyQt5, requests, capstone" >nul 2>&1
if errorlevel 1 (
    echo ⚠️  Critical Python packages missing - setup recommended
    set VERIFICATION_PASSED=0
)

REM Check if setup has been completed
if not exist "%PROJECT_ROOT%\intellicrack_tool_config.json" (
    echo 💡 Tool configuration missing - setup required
    set VERIFICATION_PASSED=0
) else (
    REM Check if setup log exists and is recent (less than 7 days old)
    if not exist "%PROJECT_ROOT%\tools\setup\setup.log" (
        echo 💡 Setup log missing - verification recommended
        set VERIFICATION_PASSED=0
    )
)

:end
if !VERIFICATION_PASSED! == 0 (
    echo.
    echo 🔧 Setup verification failed. Running full setup...
    echo.
    call "%PROJECT_ROOT%\tools\setup\setup_intellicrack.bat"
) else (
    echo ✅ Setup verification passed
)

exit /b !VERIFICATION_PASSED!