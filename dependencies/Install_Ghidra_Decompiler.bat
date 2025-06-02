@echo off
REM Dedicated Ghidra Setup Script for Intellicrack

set SCRIPT_DIR=%~dp0
set PROJECT_ROOT=%SCRIPT_DIR%..\..

echo ============================================================
echo Intellicrack - Ghidra Setup
echo ============================================================
echo.

REM Check if bundled Ghidra exists
set BUNDLED_GHIDRA=%PROJECT_ROOT%\ghidra\ghidra_11.3.2_PUBLIC\ghidraRun.bat
if exist "%BUNDLED_GHIDRA%" (
    echo ✓ Bundled Ghidra found at: %BUNDLED_GHIDRA%
    echo ✓ Ghidra is ready for use
    goto :configure
)

REM Check common system locations
set GHIDRA_LOCATIONS="C:\Program Files\Ghidra\ghidraRun.bat" "C:\ghidra\ghidraRun.bat" "C:\Tools\ghidra\ghidraRun.bat"

for %%G in (%GHIDRA_LOCATIONS%) do (
    if exist %%G (
        echo ✓ System Ghidra found at: %%G
        echo ✓ Ghidra is ready for use
        goto :configure
    )
)

echo ⚠️  Ghidra not found
echo.
echo Ghidra is recommended for:
echo   - Advanced reverse engineering
echo   - Decompilation
echo   - Advanced binary analysis
echo   - Plugin development
echo.
echo Setup Options:
echo.
echo Option 1 - Use Bundled Ghidra:
echo   ✓ Already included in project at: %PROJECT_ROOT%\ghidra\
echo   ✓ No additional setup required
echo   ✓ Ready to use immediately
echo.
echo Option 2 - Install System Ghidra:
echo   1. Download from: https://ghidra-sre.org/
echo   2. Install to: C:\Program Files\Ghidra\
echo   3. Ensure Java 11+ is installed
echo   4. Run this script again to verify
echo.

if exist "%PROJECT_ROOT%\ghidra\" (
    echo ✓ Bundled Ghidra directory exists
    echo This suggests Ghidra is already available in the project.
    echo Check: %PROJECT_ROOT%\ghidra\ghidra_11.3.2_PUBLIC\
)

goto :end

:configure
echo.
echo Configuring Ghidra for Intellicrack...
echo.
echo Ghidra configuration will be handled automatically by Intellicrack
echo when Ghidra analysis features are used.
echo.
echo ✓ Ghidra setup complete

:end
echo.
echo Ghidra can be launched manually using the ghidraRun.bat script
echo in the installation directory.
echo.
pause