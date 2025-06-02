@echo off
REM Dedicated Radare2 Setup Script for Intellicrack

set SCRIPT_DIR=%~dp0
set PROJECT_ROOT=%SCRIPT_DIR%..\..
set RADARE2_DIR=%PROJECT_ROOT%\radare2
set RADARE2_BIN=%RADARE2_DIR%\radare2-5.9.8-w64\bin

echo ============================================================
echo Intellicrack - Radare2 Setup
echo ============================================================
echo.

REM Check if radare2 is already configured
if exist "%RADARE2_BIN%\radare2.exe" (
    echo ✓ Local radare2 found at: %RADARE2_BIN%
    
    REM Test functionality
    "%RADARE2_BIN%\radare2.exe" -v >nul 2>&1
    if errorlevel 1 (
        echo ❌ Radare2 found but not working properly
        goto :setup_needed
    ) else (
        echo ✓ Radare2 is working correctly
        echo.
        echo Current setup is ready. No action needed.
        goto :end
    )
)

:setup_needed
echo ⚠️  Radare2 not found or not working properly
echo.
echo Setting up radare2 for Intellicrack...
echo.
echo Radare2 is required for:
echo   - Binary analysis and disassembly
echo   - Control Flow Graph generation
echo   - Function analysis
echo   - Pattern recognition
echo.

REM Check for system radare2
r2 -v >nul 2>&1
if not errorlevel 1 (
    echo ✓ System radare2 found in PATH
    echo Intellicrack can use the system installation.
    goto :end
)

echo ⚠️  System radare2 not found either
echo.
echo To install radare2:
echo.
echo Option 1 - Local Installation (Recommended):
echo   1. Download radare2-5.9.8-w64.zip from:
echo      https://github.com/radareorg/radare2/releases/tag/5.9.8
echo   2. Create directory: %RADARE2_DIR%
echo   3. Extract the zip file to that directory
echo   4. Ensure this path exists: %RADARE2_BIN%\radare2.exe
echo   5. Run this script again to verify
echo.
echo Option 2 - System Installation:
echo   1. Download and install radare2 system-wide
echo   2. Add radare2 to your system PATH
echo   3. Restart command prompt and run this script again
echo.

REM Offer to create directory structure
set /p create_dir="Create local radare2 directory structure now? (y/n): "
if /i "%create_dir%"=="y" (
    mkdir "%RADARE2_DIR%" 2>nul
    if exist "%RADARE2_DIR%" (
        echo ✓ Created directory: %RADARE2_DIR%
        echo.
        echo Now download and extract radare2-5.9.8-w64.zip to this directory.
        echo After extraction, run this script again to verify the setup.
    ) else (
        echo ❌ Failed to create directory: %RADARE2_DIR%
    )
)

:end
echo.
echo For help with radare2 usage, run: %~dp0..\radare2\use_local_radare2.bat
echo.
pause