@echo off
REM This script adds the pre-installed radare2 binaries to the PATH temporarily
REM Running this will allow you to use radare2 commands in the current terminal session

SETLOCAL

set SCRIPT_DIR=%~dp0
set RADARE2_BIN=%SCRIPT_DIR%radare2\radare2-5.9.8-w64\bin

REM Check if the radare2 binaries exist
if not exist "%RADARE2_BIN%\radare2.exe" (
    echo Error: radare2 binaries not found at %RADARE2_BIN%
    exit /b 1
)

REM Add the radare2 bin directory to the PATH for this session
set PATH=%RADARE2_BIN%;%PATH%

echo Radare2 5.9.8 has been added to your PATH for this terminal session.
echo You can now use commands like:
echo   - radare2  (or r2)
echo   - rabin2
echo   - radiff2
echo   - rafind2
echo   - rahash2
echo   - rasm2
echo   - and more...
echo.
echo Try 'radare2 -v' to verify it's working.
echo.

REM Start a new command prompt session with the updated PATH
cmd /k