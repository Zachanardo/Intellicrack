@echo off
setlocal EnableDelayedExpansion

echo ====================================================================
echo Intellicrack External Tools Setup Script (Windows)
echo ====================================================================
echo This script will download and configure external tools required by
echo Intellicrack for defensive security research and binary analysis.
echo.

REM Create tools directory
set TOOLS_DIR=%~dp0..\tools
if not exist "%TOOLS_DIR%" mkdir "%TOOLS_DIR%"

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running as Administrator - Good!
) else (
    echo WARNING: Not running as Administrator. Some operations may fail.
    echo Consider running as Administrator for full functionality.
)

echo.
echo [1/6] Setting up Ghidra...
echo ====================================================================

REM Download and setup Ghidra
set GHIDRA_VERSION=11.2.1
set GHIDRA_ZIP=ghidra_%GHIDRA_VERSION%_PUBLIC_%date:~10,4%%date:~4,2%%date:~7,2%.zip
set GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_%GHIDRA_VERSION%_build/ghidra_%GHIDRA_VERSION%_PUBLIC_%date:~10,4%%date:~4,2%%date:~7,2%.zip
set GHIDRA_DIR=%TOOLS_DIR%\ghidra_%GHIDRA_VERSION%_PUBLIC

if not exist "%GHIDRA_DIR%" (
    echo Downloading Ghidra %GHIDRA_VERSION%...
    powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_%GHIDRA_VERSION%_build/ghidra_%GHIDRA_VERSION%_PUBLIC_20241217.zip' -OutFile '%TOOLS_DIR%\ghidra.zip'}"
    
    echo Extracting Ghidra...
    powershell -Command "Expand-Archive -Path '%TOOLS_DIR%\ghidra.zip' -DestinationPath '%TOOLS_DIR%' -Force"
    del "%TOOLS_DIR%\ghidra.zip"
    
    echo Ghidra installed successfully!
) else (
    echo Ghidra already installed.
)

echo.
echo [2/6] Setting up Radare2...
echo ====================================================================

REM Download and setup Radare2
set R2_VERSION=5.9.8
if not exist "%TOOLS_DIR%\radare2" (
    echo Downloading Radare2 %R2_VERSION%...
    powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://github.com/radareorg/radare2/releases/download/%R2_VERSION%/radare2-%R2_VERSION%-w64.zip' -OutFile '%TOOLS_DIR%\radare2.zip'}"
    
    echo Extracting Radare2...
    powershell -Command "Expand-Archive -Path '%TOOLS_DIR%\radare2.zip' -DestinationPath '%TOOLS_DIR%\radare2' -Force"
    del "%TOOLS_DIR%\radare2.zip"
    
    echo Radare2 installed successfully!
) else (
    echo Radare2 already installed.
)

echo.
echo [3/6] Setting up QEMU...
echo ====================================================================

REM Download and setup QEMU
set QEMU_VERSION=9.2.0
if not exist "%TOOLS_DIR%\qemu" (
    echo Downloading QEMU %QEMU_VERSION%...
    powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://qemu.weilnetz.de/w64/qemu-w64-setup-%QEMU_VERSION%.exe' -OutFile '%TOOLS_DIR%\qemu-installer.exe'}"
    
    echo Installing QEMU (silent installation)...
    mkdir "%TOOLS_DIR%\qemu"
    "%TOOLS_DIR%\qemu-installer.exe" /S /D="%TOOLS_DIR%\qemu"
    del "%TOOLS_DIR%\qemu-installer.exe"
    
    echo QEMU installed successfully!
) else (
    echo QEMU already installed.
)

echo.
echo [4/6] Setting up DIE (Detect It Easy)...
echo ====================================================================

REM Download and setup DIE
if not exist "%TOOLS_DIR%\die" (
    echo Downloading DIE...
    powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://github.com/horsicq/DIE-engine/releases/latest/download/die_win64_portable.zip' -OutFile '%TOOLS_DIR%\die.zip'}"
    
    echo Extracting DIE...
    powershell -Command "Expand-Archive -Path '%TOOLS_DIR%\die.zip' -DestinationPath '%TOOLS_DIR%\die' -Force"
    del "%TOOLS_DIR%\die.zip"
    
    echo DIE installed successfully!
) else (
    echo DIE already installed.
)

echo.
echo [5/6] Setting up additional tools...
echo ====================================================================

REM Install additional Python dependencies for tool integration
echo Installing Python tool integration libraries...
call mamba activate C:\Intellicrack\mamba_env

REM Install ghidra_bridge for programmatic Ghidra control
uv pip install ghidra_bridge

REM Install additional analysis libraries
uv pip install r2pipe pwntools

echo Additional tools installed successfully!

echo.
echo [6/6] Creating configuration files...
echo ====================================================================

REM Create tools configuration file
set CONFIG_FILE=%~dp0..\intellicrack\config\tools_config.json
if not exist "%~dp0..\intellicrack\config" mkdir "%~dp0..\intellicrack\config"

echo Creating tools configuration...
(
echo {
echo   "tools": {
echo     "ghidra": {
echo       "path": "%GHIDRA_DIR%\\ghidraRun.bat",
echo       "analyzeHeadless": "%GHIDRA_DIR%\\support\\analyzeHeadless.bat",
echo       "version": "%GHIDRA_VERSION%",
echo       "enabled": true
echo     },
echo     "radare2": {
echo       "path": "%TOOLS_DIR%\\radare2\\bin\\radare2.exe",
echo       "r2": "%TOOLS_DIR%\\radare2\\bin\\r2.exe",
echo       "version": "%R2_VERSION%",
echo       "enabled": true
echo     },
echo     "qemu": {
echo       "path": "%TOOLS_DIR%\\qemu\\qemu-system-x86_64.exe",
echo       "qemu_img": "%TOOLS_DIR%\\qemu\\qemu-img.exe",
echo       "version": "%QEMU_VERSION%",
echo       "enabled": true
echo     },
echo     "die": {
echo       "path": "%TOOLS_DIR%\\die\\diec.exe",
echo       "enabled": true
echo     }
echo   },
echo   "environment": {
echo     "GHIDRA_INSTALL_DIR": "%GHIDRA_DIR%",
echo     "R2_HOME": "%TOOLS_DIR%\\radare2",
echo     "QEMU_HOME": "%TOOLS_DIR%\\qemu"
echo   }
echo }
) > "%CONFIG_FILE%"

REM Add tools to PATH for current session
set PATH=%GHIDRA_DIR%;%TOOLS_DIR%\radare2\bin;%TOOLS_DIR%\qemu;%TOOLS_DIR%\die;%PATH%

echo.
echo ====================================================================
echo External Tools Setup Complete!
echo ====================================================================
echo.
echo The following tools have been installed:
echo   - Ghidra %GHIDRA_VERSION% at %GHIDRA_DIR%
echo   - Radare2 %R2_VERSION% at %TOOLS_DIR%\radare2
echo   - QEMU %QEMU_VERSION% at %TOOLS_DIR%\qemu
echo   - DIE at %TOOLS_DIR%\die
echo.
echo Configuration saved to: %CONFIG_FILE%
echo.
echo IMPORTANT NEXT STEPS:
echo 1. Add the tools to your system PATH or use the configuration file
echo 2. Verify installation by running: python -m intellicrack --verify-tools
echo 3. For Java-based tools, ensure Java 11+ is installed for Ghidra
echo.
echo Tools are ready for use with Intellicrack!
echo ====================================================================

pause