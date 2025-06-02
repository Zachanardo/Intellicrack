@echo off
REM Comprehensive Intellicrack Setup Script
REM Automatically detects and configures all required tools
REM Enhanced with logging, progress tracking, and error recovery

echo [DEBUG] Script starting...
echo [DEBUG] Enabling delayed expansion...
setlocal enabledelayedexpansion
if errorlevel 1 (
    echo [ERROR] Failed to enable delayed expansion
    pause
    exit /b 1
)
echo [DEBUG] Delayed expansion enabled successfully

set SCRIPT_DIR=%~dp0
REM Remove trailing backslash from SCRIPT_DIR for proper path construction
if "%SCRIPT_DIR:~-1%" == "\" set SCRIPT_DIR=%SCRIPT_DIR:~0,-1%
set PROJECT_ROOT=%SCRIPT_DIR%\..\..
REM Resolve to absolute path
pushd %PROJECT_ROOT%
set PROJECT_ROOT=%CD%
popd
set TOOLS_DIR=%PROJECT_ROOT%\tools
set LOG_DIR=%PROJECT_ROOT%\dependencies\logs
set LOG_FILE=%LOG_DIR%\setup.log
set TIMESTAMP=%date:~-4,4%%date:~-10,2%%date:~-7,2%_%time:~0,2%%time:~3,2%%time:~6,2%
set TIMESTAMP=%TIMESTAMP: =0%

REM Create log directory if it doesn't exist
echo [DEBUG] Creating log directory: %LOG_DIR%
if not exist "%LOG_DIR%" (
    mkdir "%LOG_DIR%" 2>nul
    if errorlevel 1 (
        echo [ERROR] Failed to create log directory: %LOG_DIR%
        echo [ERROR] Please check permissions and try again
        pause
        exit /b 1
    )
)

REM Initialize log file
echo [DEBUG] About to create log file at: %LOG_FILE%
echo ============================================================ > "%LOG_FILE%" 2>nul
if errorlevel 1 (
    echo [ERROR] Failed to create log file at: %LOG_FILE%
    echo [ERROR] Check if directory exists and you have write permissions
    echo [ERROR] Setup cannot continue without log file access
    exit /b 1
)
echo Intellicrack Setup Log - %TIMESTAMP% >> "%LOG_FILE%" 2>nul
echo ============================================================ >> "%LOG_FILE%" 2>nul
echo. >> "%LOG_FILE%" 2>nul
echo [DEBUG] Log file created successfully

echo ============================================================
echo          Intellicrack Comprehensive Setup v2.0
echo ============================================================
echo.
echo This script will automatically detect and configure all tools
echo required by Intellicrack for optimal operation.
echo.
echo Tools to be checked:
echo   - Python dependencies (100+ analysis packages)
echo   - Radare2 (binary analysis and disassembly)
echo   - Ghidra (reverse engineering and decompilation)  
echo   - Frida (dynamic instrumentation)
echo   - Wireshark/pyshark (network packet analysis)
echo   - QEMU (system emulation and virtualization)
echo   - Docker (container management for distributed analysis)
echo   - Additional tools (Graphviz, wkhtmltopdf, mitmproxy)
echo   - Binary analysis utilities (binwalk, volatility3, file tools)
echo   - Network tools (nmap, OpenSSL)
echo   - System dependencies (GTK3, CUDA toolkit)
echo   - System directories and permissions
echo.
echo Setup log: %LOG_FILE%
echo.
echo [DEBUG] About to prompt for user input...
set /p continue="Press Enter to begin setup, or Ctrl+C to cancel..."
echo [DEBUG] User input received, continuing...
echo.

REM Initialize status tracking and progress
set PYTHON_OK=0
set RADARE2_OK=0
set GHIDRA_OK=0
set FRIDA_OK=0
set DIRS_OK=0
set WIRESHARK_OK=0
set QEMU_OK=0
set GRAPHVIZ_OK=0
set WKHTMLTOPDF_OK=0
set MITMPROXY_OK=0
set QILING_OK=0
set DOCKER_OK=0
set BINWALK_OK=0
set VOLATILITY_OK=0
set NMAP_OK=0
set OPENSSL_OK=0
set GTK3_OK=0
set CUDA_OK=0
set INTEL_PYTORCH_OK=0
set OPENVINO_OK=0
set ROCM_OK=0
set OPENCL_OK=0
set FILETOOLS_OK=0
set PHASE=0
set TOTAL_PHASES=10

REM Jump over function definitions
goto :main_start

REM Logging function - usage: call :log "message"
:log
echo %~1
echo [%TIMESTAMP%] %~1 >> "%LOG_FILE%" 2>nul
if errorlevel 1 (
    echo [ERROR] Failed to write to log file: %LOG_FILE%
)
goto :eof

REM PATH update function - usage: call :add_to_path "C:\Program Files\Tool\bin"
:add_to_path
set "NEW_PATH=%~1"
echo %PATH% | findstr /i /c:"%NEW_PATH%" >nul
if errorlevel 1 (
    echo [SETUP] Adding to PATH: %NEW_PATH%
    setx PATH "%PATH%;%NEW_PATH%" >nul 2>&1
    if not errorlevel 1 (
        call :log "Added to PATH: %NEW_PATH%"
    ) else (
        call :log "Failed to add to PATH: %NEW_PATH%"
    )
)
goto :eof

REM Environment refresh function
:refresh_environment
echo [REFRESH] Refreshing environment variables...
REM Refresh environment for current session
for /f "tokens=2*" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v PATH 2^>nul') do set "SYS_PATH=%%b"
for /f "tokens=2*" %%a in ('reg query "HKCU\Environment" /v PATH 2^>nul') do set "USER_PATH=%%b"
if defined USER_PATH (
    set "PATH=%SYS_PATH%;%USER_PATH%"
) else (
    set "PATH=%SYS_PATH%"
)
call :log "Environment variables refreshed"
goto :eof

:main_start
call :log "Starting Intellicrack setup process..."
echo [DEBUG] Setup process initialized successfully

:phase1
set /a PHASE+=1
echo ============================================================
echo Phase %PHASE%/%TOTAL_PHASES%: Python Environment Check
echo ============================================================
call :log "Phase %PHASE%: Starting Python environment check"
echo [DEBUG] Entering Phase 1 - Python Environment Check

REM Check Python version and compatibility
echo [DEBUG] About to check Python version
python --version >nul 2>&1
if errorlevel 1 (
    call :log "ERROR: Python not found in PATH"
    echo [ERROR] Python not found in PATH
    echo.
    echo [INFO] Required: Python 3.8 or higher
    echo [DOWNLOAD] Download: https://python.org/downloads/
    echo [TIP] Tip: Make sure to check "Add Python to PATH" during installation
    echo.
    goto :python_error
) else (
    for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
    call :log "Python found: version !PYTHON_VERSION!"
    echo [OK] Python found: !PYTHON_VERSION!
)

REM Check if pip is available
pip --version >nul 2>&1
if errorlevel 1 (
    call :log "ERROR: pip not found"
    echo [ERROR] pip not found
    echo [TIP] pip should be included with Python 3.4+
    echo [SETUP] Try: python -m ensurepip --upgrade
    goto :python_error
) else (
    for /f "tokens=2" %%i in ('pip --version 2^>^&1') do set PIP_VERSION=%%i
    call :log "pip found: version !PIP_VERSION!"
    echo [OK] pip found: !PIP_VERSION!
)

REM Check if requirements.txt exists
if not exist "requirements.txt" (
    call :log "ERROR: requirements.txt not found in script directory"
    echo [ERROR] requirements.txt not found
    goto :python_error
)

echo.
echo [DOWNLOAD] Installing/updating Python dependencies...
echo [INFO] This may take 5-15 minutes depending on your internet connection...
echo [TIP] Installing 100+ packages including ML, analysis, and security tools
echo.
call :log "Starting pip install from requirements.txt"

REM Install requirements with detailed error handling and progress
pip install -r "requirements.txt" --upgrade --progress-bar on
set PIP_EXIT_CODE=%errorlevel%

if %PIP_EXIT_CODE% neq 0 (
    call :log "WARNING: Some Python packages failed to install (exit code: %PIP_EXIT_CODE%)"
    echo.
    echo [WARNING] Some Python packages failed to install
    echo [INFO] This is normal for complex dependencies like:
    echo    - angr (symbolic execution) - requires specific compiler setup
    echo    - tensorflow (GPU support) - may need CUDA
    echo    - some binary analysis tools - platform specific
    echo.
    echo [OK] Intellicrack will work with reduced functionality
    echo [SCAN] Check setup.log for detailed error information
) else (
    call :log "All Python dependencies installed successfully"
    echo [OK] All Python dependencies installed successfully
)

REM Test critical imports
echo.
    echo [TEST] Testing critical Python imports...
python -c "import PyQt5; print('[OK] PyQt5 GUI framework')" 2>nul || echo "[WARNING] PyQt5 missing - GUI may not work"
python -c "import requests; print('[OK] requests HTTP library')" 2>nul || echo "[WARNING] requests missing"
python -c "import capstone; print('[OK] capstone disassembly')" 2>nul || echo "[WARNING] capstone missing"

set PYTHON_OK=1
call :log "Python phase completed successfully"
goto :phase2

:python_error
echo.
echo Python setup failed. Please fix Python installation before continuing.
echo Press any key to exit...
pause >nul
exit /b 1

:phase2
set /a PHASE+=1
echo.
echo ============================================================
echo Phase %PHASE%/%TOTAL_PHASES%: Radare2 Binary Analysis Setup
echo ============================================================
call :log "Phase %PHASE%: Starting Radare2 setup"

set RADARE2_BIN=%PROJECT_ROOT%\radare2\radare2-5.9.8-w64\bin\radare2.exe

echo [SCAN] Checking for radare2 installations...

REM Check if local radare2 exists
if exist "%RADARE2_BIN%" (
    call :log "Local radare2 found at: %RADARE2_BIN%"
    echo [OK] Local radare2 found: %RADARE2_BIN%
    
    REM Test if it works and get version
    "%RADARE2_BIN%" -v >temp_r2_version.txt 2>&1
    if errorlevel 1 (
        call :log "WARNING: Local radare2 found but not working properly"
        echo [WARNING] Local radare2 found but not working properly
        del temp_r2_version.txt 2>nul
    ) else (
        for /f "tokens=1,2" %%a in (temp_r2_version.txt) do (
            if "%%a"=="radare2" set R2_VERSION=%%b
        )
        call :log "Local radare2 is working: version !R2_VERSION!"
        echo [OK] Local radare2 working: version !R2_VERSION!
        set RADARE2_OK=1
        del temp_r2_version.txt 2>nul
    )
) else (
    call :log "Local radare2 not found at expected location"
    echo [WARNING] Local radare2 not found
)

REM Check system radare2 if local not available
if !RADARE2_OK! == 0 (
    r2 -v >temp_r2_version.txt 2>&1
    if errorlevel 1 (
        call :log "System radare2 not found in PATH"
        echo [WARNING] System radare2 not found in PATH
        del temp_r2_version.txt 2>nul
        echo.
        echo [INFO] Radare2 is recommended for:
        echo    - Binary disassembly and analysis
        echo    - Control Flow Graph generation
        echo    - Function analysis and pattern recognition
        echo    - Vulnerability research
        echo.
        echo [DOWNLOAD] Setup Options:
        echo    1. Download radare2-5.9.8-w64.zip to: %PROJECT_ROOT%\radare2\
        echo       From: https://github.com/radareorg/radare2/releases/tag/5.9.8
        echo    2. Install system-wide and add to PATH
        echo    3. Use dedicated setup: tools\setup\setup_radare2.bat
        echo.
    ) else (
        for /f "tokens=1,2" %%a in (temp_r2_version.txt) do (
            if "%%a"=="radare2" set R2_VERSION=%%b
        )
        call :log "System radare2 found in PATH: version !R2_VERSION!"
        echo [OK] System radare2 found: version !R2_VERSION!
        set RADARE2_OK=1
        del temp_r2_version.txt 2>nul
    )
)

REM Test r2pipe Python integration if radare2 available
if !RADARE2_OK! == 1 (
    echo [TEST] Testing r2pipe Python integration...
    python -c "import r2pipe; print('[OK] r2pipe Python library working')" 2>nul || (
        echo [WARNING] r2pipe Python library missing or broken
        call :log "WARNING: r2pipe Python library not working properly"
    )
)

:phase3
set /a PHASE+=1
echo.
echo ============================================================
echo Phase %PHASE%/%TOTAL_PHASES%: Ghidra Reverse Engineering Setup
echo ============================================================
call :log "Phase %PHASE%: Starting Ghidra setup"

echo [SCAN] Scanning for Ghidra installations...

REM Define Ghidra search locations with priority order
set GHIDRA_LOCATIONS="%PROJECT_ROOT%\ghidra\ghidra_11.3.2_PUBLIC\ghidraRun.bat" "C:\Program Files\Ghidra\ghidraRun.bat" "C:\ghidra\ghidraRun.bat" "C:\Tools\ghidra\ghidraRun.bat" "%USERPROFILE%\ghidra\ghidraRun.bat"

set GHIDRA_FOUND=0
for %%G in (%GHIDRA_LOCATIONS%) do (
    if exist %%G (
        set GHIDRA_PATH=%%G
        set GHIDRA_FOUND=1
        goto :ghidra_found
    )
)

:ghidra_found
if !GHIDRA_FOUND! == 1 (
    call :log "Ghidra found at: !GHIDRA_PATH!"
    echo [OK] Ghidra found: !GHIDRA_PATH!
    
    REM Test Ghidra functionality (check if it can start)
    echo [TEST] Testing Ghidra functionality...
    REM Note: We don't actually launch Ghidra GUI, just verify the script exists and is accessible
    if exist !GHIDRA_PATH! (
        echo [OK] Ghidra installation appears valid
        set GHIDRA_OK=1
        call :log "Ghidra installation validated"
        
        REM Check if it's the bundled version
        echo !GHIDRA_PATH! | findstr /C:"%PROJECT_ROOT%" >nul
        if not errorlevel 1 (
            echo [TIP] Using bundled Ghidra installation (recommended)
        ) else (
            echo [TIP] Using system Ghidra installation
        )
    )
) else (
    call :log "Ghidra not found in any standard locations"
    echo [WARNING] Ghidra not found in standard locations
    echo.
    echo [INFO] Ghidra provides:
    echo    - Advanced decompilation and reverse engineering
    echo    - Comprehensive binary analysis
    echo    - Plugin development framework
    echo    - Government-grade analysis tools
    echo.
    echo [DOWNLOAD] Setup Options:
    echo    1. [OK] Use bundled version: %PROJECT_ROOT%\ghidra\ (if available)
    echo    2. [DOWNLOAD] Download from: https://ghidra-sre.org/
    echo    3. [SETUP] Use dedicated setup: tools\setup\setup_ghidra.bat
    echo.
    echo [TIP] Note: Requires Java 11 or higher
    echo.
)

REM Check Java requirement for Ghidra
if !GHIDRA_OK! == 1 (
    echo [TEST] Checking Java requirement for Ghidra...
    java -version >temp_java_version.txt 2>&1
    if errorlevel 1 (
        echo [WARNING] Java not found - required for Ghidra
        call :log "WARNING: Java not found but required for Ghidra"
    ) else (
        for /f "tokens=3" %%a in ('java -version 2^>^&1 ^| findstr "version"') do set JAVA_VERSION=%%a
        echo [OK] Java found: !JAVA_VERSION!
        call :log "Java found for Ghidra: !JAVA_VERSION!"
    )
    del temp_java_version.txt 2>nul
)

:phase4
set /a PHASE+=1
echo.
echo ============================================================
echo Phase %PHASE%/%TOTAL_PHASES%: Frida Dynamic Instrumentation Setup
echo ============================================================
call :log "Phase %PHASE%: Starting Frida setup"

echo [SCAN] Checking Frida installation...

REM Check if frida is available
frida --version >temp_frida_version.txt 2>&1
if errorlevel 1 (
    call :log "Frida not found in PATH, attempting installation"
    echo [WARNING] Frida not found in PATH
    echo [DOWNLOAD] Installing Frida via pip...
    echo.
    
    pip install frida frida-tools --upgrade
    set FRIDA_INSTALL_CODE=%errorlevel%
    
    if !FRIDA_INSTALL_CODE! neq 0 (
        call :log "ERROR: Failed to install Frida (exit code: !FRIDA_INSTALL_CODE!)"
        echo [ERROR] Failed to install Frida
        echo [TIP] Try installing manually: pip install frida frida-tools
    ) else (
        call :log "Frida installed successfully via pip"
        echo [OK] Frida installed successfully
        set FRIDA_OK=1
        
        REM Get version after installation
        frida --version >temp_frida_version.txt 2>&1
        if not errorlevel 1 (
            for /f %%a in (temp_frida_version.txt) do set FRIDA_VERSION=%%a
            echo [OK] Frida version: !FRIDA_VERSION!
        )
    )
) else (
    for /f %%a in (temp_frida_version.txt) do set FRIDA_VERSION=%%a
    call :log "Frida found in PATH: version !FRIDA_VERSION!"
    echo [OK] Frida found: version !FRIDA_VERSION!
    set FRIDA_OK=1
)
del temp_frida_version.txt 2>nul

REM Test Frida functionality if available
if !FRIDA_OK! == 1 (
    echo [TEST] Testing Frida functionality...
    frida-ps --version >nul 2>&1
    if errorlevel 1 (
        echo [WARNING] frida-ps tool not working properly
        call :log "WARNING: frida-ps not working properly"
    ) else (
        echo [OK] Frida tools working correctly
        call :log "Frida tools validated successfully"
    )
    
    REM Test Python frida module
    python -c "import frida; print('[OK] Frida Python module working')" 2>nul || (
        echo [WARNING] Frida Python module not working
        call :log "WARNING: Frida Python module not working properly"
    )
)

if !FRIDA_OK! == 0 (
    echo.
    echo [INFO] Frida provides:
    echo    - Dynamic binary instrumentation
    echo    - Runtime API hooking and monitoring
    echo    - Mobile application security testing
    echo    - Real-time code injection and modification
    echo.
)

:phase5
set /a PHASE+=1
echo.
echo ============================================================
echo Phase %PHASE%/%TOTAL_PHASES%: Network Analysis Tools Setup
echo ============================================================
call :log "Phase %PHASE%: Starting network analysis tools setup"

echo [SCAN] Checking network analysis tools...

REM Check Wireshark installation
echo [TEST] Checking Wireshark installation...
set WIRESHARK_LOCATIONS="C:\Program Files\Wireshark\wireshark.exe" "C:\Program Files (x86)\Wireshark\wireshark.exe" "%PROGRAMFILES%\Wireshark\wireshark.exe"

set WIRESHARK_FOUND=0
for %%W in (%WIRESHARK_LOCATIONS%) do (
    if exist %%W (
        set WIRESHARK_PATH=%%W
        set WIRESHARK_FOUND=1
        goto :wireshark_found
    )
)

:wireshark_found
if !WIRESHARK_FOUND! == 1 (
    call :log "Wireshark found at: !WIRESHARK_PATH!"
    echo [OK] Wireshark found: !WIRESHARK_PATH!
    set WIRESHARK_OK=1
    
    REM Test pyshark Python integration
    echo [TEST] Testing pyshark integration...
    python -c "import pyshark; print('[OK] pyshark Python library working')" 2>nul || (
        echo [WARNING] pyshark Python library missing - install via pip
        call :log "WARNING: pyshark not available, but Wireshark found"
    )
) else (
    call :log "Wireshark not found in standard locations"
    echo [WARNING] Wireshark not found
    echo.
    echo [INFO] Wireshark provides:
    echo    - Network packet capture and analysis
    echo    - Protocol dissection and inspection
    echo    - Network troubleshooting and forensics
    echo    - Integration with pyshark for Python analysis
    echo.
    echo [DOWNLOAD] Install from: https://www.wireshark.org/download.html
)

REM Check mitmproxy
echo [TEST] Checking mitmproxy...
mitmproxy --version >temp_mitm_version.txt 2>&1
if errorlevel 1 (
    call :log "mitmproxy not found, attempting pip installation"
    echo [WARNING] mitmproxy not found - installing via pip...
    pip install mitmproxy --upgrade
    if errorlevel 1 (
        echo [ERROR] Failed to install mitmproxy
        call :log "ERROR: Failed to install mitmproxy"
    ) else (
        echo [OK] mitmproxy installed successfully
        set MITMPROXY_OK=1
        call :log "mitmproxy installed successfully"
    )
) else (
    for /f %%a in (temp_mitm_version.txt) do set MITMPROXY_VERSION=%%a
    call :log "mitmproxy found: version !MITMPROXY_VERSION!"
    echo [OK] mitmproxy found: !MITMPROXY_VERSION!
    set MITMPROXY_OK=1
)
del temp_mitm_version.txt 2>nul

:phase6
set /a PHASE+=1
echo.
echo ============================================================
echo Phase %PHASE%/%TOTAL_PHASES%: Emulation & Virtualization Setup
echo ============================================================
call :log "Phase %PHASE%: Starting emulation tools setup"

echo [SCAN] Checking emulation and virtualization tools...

REM Check QEMU installation
echo [TEST] Checking QEMU installation...
set QEMU_LOCATIONS="C:\Program Files\qemu\qemu-system-x86_64.exe" "C:\qemu\qemu-system-x86_64.exe" "%PROGRAMFILES%\qemu\qemu-system-x86_64.exe" "C:\Tools\qemu\qemu-system-x86_64.exe"

set QEMU_FOUND=0
for %%Q in (%QEMU_LOCATIONS%) do (
    if exist %%Q (
        set QEMU_PATH=%%Q
        set QEMU_FOUND=1
        goto :qemu_found
    )
)

REM Also check if qemu-system-x86_64 is in PATH
qemu-system-x86_64 --version >temp_qemu_version.txt 2>&1
if not errorlevel 1 (
    set QEMU_FOUND=1
    set QEMU_PATH="qemu-system-x86_64 (in PATH)"
)

:qemu_found
if !QEMU_FOUND! == 1 (
    call :log "QEMU found: !QEMU_PATH!"
    echo [OK] QEMU found: !QEMU_PATH!
    set QEMU_OK=1
    
    if exist temp_qemu_version.txt (
        for /f "tokens=3" %%a in ('findstr "version" temp_qemu_version.txt') do set QEMU_VERSION=%%a
        if defined QEMU_VERSION echo [OK] QEMU version: !QEMU_VERSION!
    )
) else (
    call :log "QEMU not found in standard locations"
    echo [WARNING]  QEMU not found
    echo.
    echo [INFO] QEMU provides:
    echo    - System emulation and virtualization
    echo    - Cross-platform binary execution
    echo    - Malware sandboxing and analysis
    echo    - Architecture emulation (x86, ARM, etc.)
    echo.
    echo [DOWNLOAD] Install from: https://www.qemu.org/download/#windows
    echo [TIP] Or use: winget install qemu
)
del temp_qemu_version.txt 2>nul

REM Check Qiling Framework
echo [TEST] Checking Qiling Framework...
python -c "import qiling; print('[OK] Qiling Framework: ' + qiling.__version__)" 2>nul
if errorlevel 1 (
    call :log "Qiling Framework not found, attempting pip installation"
    echo [WARNING]  Qiling Framework not found - installing via pip...
    pip install qiling --upgrade
    if errorlevel 1 (
        echo [ERROR] Failed to install Qiling Framework
        call :log "ERROR: Failed to install Qiling Framework"
        echo [TIP] Qiling provides binary emulation and analysis
        echo [DOWNLOAD] Manual install: pip install qiling
    ) else (
        echo [OK] Qiling Framework installed successfully
        set QILING_OK=1
        call :log "Qiling Framework installed successfully"
        
        REM Get version after installation
        python -c "import qiling; print('[OK] Qiling version:', qiling.__version__)" 2>nul
    )
) else (
    call :log "Qiling Framework found and working"
    echo [OK] Qiling Framework working
    set QILING_OK=1
)

:phase7
set /a PHASE+=1
echo.
echo ============================================================
echo Phase %PHASE%/%TOTAL_PHASES%: Additional Analysis Tools Setup
echo ============================================================
call :log "Phase %PHASE%: Starting additional tools setup"

echo [SCAN] Checking additional analysis tools...

REM Check Graphviz
echo [TEST] Checking Graphviz...
dot -V >temp_graphviz_version.txt 2>&1
if errorlevel 1 (
    call :log "Graphviz not found"
    echo [WARNING]  Graphviz not found
    echo [INFO] Graphviz provides graph visualization for CFG analysis
    echo [DOWNLOAD] Install from: https://graphviz.org/download/
    echo [TIP] Or use: winget install graphviz
) else (
    for /f "tokens=5" %%a in ('findstr "version" temp_graphviz_version.txt') do set GRAPHVIZ_VERSION=%%a
    call :log "Graphviz found: version !GRAPHVIZ_VERSION!"
    echo [OK] Graphviz found: !GRAPHVIZ_VERSION!
    set GRAPHVIZ_OK=1
    
    REM Test Python graphviz integration
    python -c "import graphviz; print('[OK] Python graphviz library working')" 2>nul || (
        echo [WARNING]  Python graphviz library missing
        call :log "WARNING: Python graphviz library not available"
    )
)
del temp_graphviz_version.txt 2>nul

REM Check wkhtmltopdf
echo [TEST] Checking wkhtmltopdf...
set WKHTMLTOPDF_LOCATIONS="C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe" "C:\Program Files (x86)\wkhtmltopdf\bin\wkhtmltopdf.exe" "C:\wkhtmltopdf\bin\wkhtmltopdf.exe"

set WKHTMLTOPDF_FOUND=0
for %%W in (%WKHTMLTOPDF_LOCATIONS%) do (
    if exist %%W (
        set WKHTMLTOPDF_PATH=%%W
        set WKHTMLTOPDF_FOUND=1
        goto :wkhtmltopdf_found
    )
)

REM Also check PATH
wkhtmltopdf --version >temp_wkhtmltopdf_version.txt 2>&1
if not errorlevel 1 (
    set WKHTMLTOPDF_FOUND=1
    set WKHTMLTOPDF_PATH="wkhtmltopdf (in PATH)"
)

:wkhtmltopdf_found
if !WKHTMLTOPDF_FOUND! == 1 (
    call :log "wkhtmltopdf found: !WKHTMLTOPDF_PATH!"
    echo [OK] wkhtmltopdf found: !WKHTMLTOPDF_PATH!
    set WKHTMLTOPDF_OK=1
    
    REM Test pdfkit integration
    python -c "import pdfkit; print('[OK] pdfkit Python library working')" 2>nul || (
        echo [WARNING]  pdfkit Python library missing
        call :log "WARNING: pdfkit not available for PDF generation"
    )
) else (
    call :log "wkhtmltopdf not found"
    echo [WARNING]  wkhtmltopdf not found
    echo [INFO] wkhtmltopdf provides HTML to PDF conversion for reports
    echo [DOWNLOAD] Install from: https://wkhtmltopdf.org/downloads.html
)
del temp_wkhtmltopdf_version.txt 2>nul

:phase8
set /a PHASE+=1
echo.
echo ============================================================
echo Phase %PHASE%/%TOTAL_PHASES%: Container & Binary Analysis Tools
echo ============================================================
call :log "Phase %PHASE%: Starting container and binary analysis tools setup"

echo [SCAN] Checking container and binary analysis tools...

REM Check Docker installation  
echo [TEST] Checking Docker installation...
docker --version >temp_docker_version.txt 2>&1
if errorlevel 1 (
    call :log "Docker not found - attempting installation"
    echo [WARNING]  Docker not found - installing Docker Desktop...
    echo [INFO] Docker is REQUIRED for distributed analysis features
    
    REM Install Docker Desktop via winget
    echo [SETUP] Installing Docker Desktop via winget...
    winget install Docker.DockerDesktop --accept-source-agreements --accept-package-agreements
    if errorlevel 1 (
        echo [ERROR] Failed to install Docker Desktop automatically
        echo [DOWNLOAD] Please install manually from: https://docs.docker.com/get-docker/
        echo [TIP] Docker is required for Intellicrack's distributed processing
        call :log "ERROR: Failed to install Docker Desktop"
    ) else (
        echo [OK] Docker Desktop installed successfully
        echo [TIP] Please start Docker Desktop and ensure it's running
        call :log "Docker Desktop installed successfully"
        set DOCKER_OK=1
        
        REM Refresh and check again
        call :refresh_environment
        docker --version >temp_docker_version_retry.txt 2>&1
        if not errorlevel 1 (
            for /f "tokens=3" %%a in ('findstr "version" temp_docker_version_retry.txt') do set DOCKER_VERSION=%%a
            echo [OK] Docker now available: !DOCKER_VERSION!
            del temp_docker_version_retry.txt 2>nul
        )
    )
) else (
    for /f "tokens=3" %%a in ('findstr "version" temp_docker_version.txt') do set DOCKER_VERSION=%%a
    call :log "Docker found: version !DOCKER_VERSION!"
    echo [OK] Docker found: !DOCKER_VERSION!
    set DOCKER_OK=1
    
    REM Test Docker functionality
    docker ps >nul 2>&1
    if errorlevel 1 (
        echo [WARNING]  Docker found but not running - start Docker Desktop
        call :log "WARNING: Docker not running"
    ) else (
        echo [OK] Docker is running and accessible
        call :log "Docker is running and accessible"
    )
)
del temp_docker_version.txt 2>nul

REM Check binwalk
echo [TEST] Checking binwalk...
binwalk --help >nul 2>&1
if errorlevel 1 (
    call :log "binwalk not found, attempting pip installation"
    echo [WARNING]  binwalk not found - installing via pip...
    pip install binwalk --upgrade
    if errorlevel 1 (
        echo [ERROR] Failed to install binwalk
        call :log "ERROR: Failed to install binwalk"
        echo [TIP] binwalk provides firmware analysis capabilities
    ) else (
        echo [OK] binwalk installed successfully
        set BINWALK_OK=1
        call :log "binwalk installed successfully"
    )
) else (
    call :log "binwalk found and working"
    echo [OK] binwalk found and working
    set BINWALK_OK=1
)

REM Check volatility3
echo [TEST] Checking volatility3...
python -c "import volatility3; print('[OK] Volatility3 version:', volatility3.__version__)" 2>nul
if errorlevel 1 (
    call :log "volatility3 not found, attempting pip installation"
    echo [WARNING]  volatility3 not found - installing via pip...
    pip install volatility3 --upgrade
    if errorlevel 1 (
        echo [ERROR] Failed to install volatility3
        call :log "ERROR: Failed to install volatility3"
        echo [TIP] volatility3 provides memory forensics capabilities
    ) else (
        echo [OK] volatility3 installed successfully
        set VOLATILITY_OK=1
        call :log "volatility3 installed successfully"
    )
) else (
    call :log "volatility3 found and working"
    echo [OK] volatility3 found and working
    set VOLATILITY_OK=1
)

:phase9
set /a PHASE+=1
echo.
echo ============================================================
echo Phase %PHASE%/%TOTAL_PHASES%: Network & Security Tools
echo ============================================================
call :log "Phase %PHASE%: Starting network and security tools setup"

echo [SCAN] Checking network and security tools...

REM Check nmap
echo [TEST] Checking nmap...
nmap --version >temp_nmap_version.txt 2>&1
if errorlevel 1 (
    call :log "nmap not found"
    echo [WARNING]  nmap not found
    echo [INFO] nmap provides network reconnaissance and security scanning
    echo [DOWNLOAD] Install from: https://nmap.org/download.html
    echo [TIP] Or use: winget install Insecure.Nmap
) else (
    for /f "tokens=2" %%a in ('findstr "version" temp_nmap_version.txt') do set NMAP_VERSION=%%a
    call :log "nmap found: version !NMAP_VERSION!"
    echo [OK] nmap found: !NMAP_VERSION!
    set NMAP_OK=1
)
del temp_nmap_version.txt 2>nul

REM Check OpenSSL
echo [TEST] Checking OpenSSL...
openssl version >temp_openssl_version.txt 2>&1
if errorlevel 1 (
    call :log "OpenSSL not found"
    echo [WARNING]  OpenSSL not found
    echo [INFO] OpenSSL provides cryptographic operations and certificate handling
    echo [DOWNLOAD] Usually included with Git for Windows or install separately
) else (
    for /f "tokens=2" %%a in (temp_openssl_version.txt) do set OPENSSL_VERSION=%%a
    call :log "OpenSSL found: version !OPENSSL_VERSION!"
    echo [OK] OpenSSL found: !OPENSSL_VERSION!
    set OPENSSL_OK=1
)
del temp_openssl_version.txt 2>nul

REM Check file analysis tools (REQUIRED by Intellicrack)
echo [TEST] Checking file analysis tools...
set FILETOOLS_COUNT=0

REM Check if tools are available
file --version >nul 2>&1
if not errorlevel 1 (
    echo [OK] file command available
    set /a FILETOOLS_COUNT+=1
)

strings --version >nul 2>&1
if not errorlevel 1 (
    echo [OK] strings command available
    set /a FILETOOLS_COUNT+=1
)

objdump --version >nul 2>&1
if not errorlevel 1 (
    echo [OK] objdump command available
    set /a FILETOOLS_COUNT+=1
)

if !FILETOOLS_COUNT! lss 3 (
    echo [WARNING]  Missing binary analysis tools - installing...
    echo [INFO] Intellicrack REQUIRES: file, strings, objdump, nm, readelf
    
    REM Try to install via winget (Git for Windows includes these tools)
    echo [SETUP] Installing Git for Windows (includes binary analysis tools)...
    winget list | findstr /i "Git.Git" >nul 2>&1
    if errorlevel 1 (
        winget install Git.Git --accept-source-agreements --accept-package-agreements
        if errorlevel 1 (
            echo [ERROR] Failed to install Git for Windows
            echo [DOWNLOAD] Please install manually: https://git-scm.com/download/win
            echo [TIP] Or install MSYS2 for binary analysis tools
            call :log "ERROR: Failed to install binary analysis tools"
        ) else (
            echo [OK] Git for Windows installed (includes binary tools)
            call :log "Git for Windows installed"
            
            REM Add Git tools to PATH
            if exist "C:\Program Files\Git\usr\bin" (
                call :add_to_path "C:\Program Files\Git\usr\bin"
                echo [TIP] Binary analysis tools added to PATH
            )
            if exist "C:\Program Files\Git\mingw64\bin" (
                call :add_to_path "C:\Program Files\Git\mingw64\bin"
            )
            
            REM Refresh and recheck
            call :refresh_environment
            strings --version >nul 2>&1
            if not errorlevel 1 (
                set FILETOOLS_COUNT=3
                echo [OK] Binary analysis tools now available
            )
        )
    ) else (
        echo [OK] Git for Windows already installed
        REM Ensure Git tools are in PATH
        if exist "C:\Program Files\Git\usr\bin" (
            call :add_to_path "C:\Program Files\Git\usr\bin"
        )
        if exist "C:\Program Files\Git\mingw64\bin" (
            call :add_to_path "C:\Program Files\Git\mingw64\bin" 
        )
        call :refresh_environment
        set FILETOOLS_COUNT=3
    )
)

if !FILETOOLS_COUNT! gtr 0 (
    echo [OK] Found !FILETOOLS_COUNT! file analysis tools
    set FILETOOLS_OK=1
    call :log "File analysis tools found: !FILETOOLS_COUNT!"
) else (
    echo [ERROR] Binary analysis tools still missing
    echo [TIP] Intellicrack functionality will be severely limited
    call :log "Binary analysis tools missing - major functionality loss"
)

:phase10
set /a PHASE+=1
echo.
echo ============================================================
echo Phase %PHASE%/%TOTAL_PHASES%: System Dependencies & GPU Support
echo ============================================================
call :log "Phase %PHASE%: Starting system dependencies setup"

echo [SCAN] Checking system dependencies and GPU support...

REM Check GTK3 runtime (required for weasyprint)
echo [TEST] Checking GTK3 runtime...
python -c "import gi; gi.require_version('Gtk', '3.0'); from gi.repository import Gtk; print('[OK] GTK3 available')" 2>nul
if errorlevel 1 (
    call :log "GTK3 not found"
    echo [WARNING]  GTK3 runtime not found
    echo [INFO] GTK3 is required for weasyprint PDF generation
    echo [DOWNLOAD] Windows: Install GTK3 runtime from https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer
    echo [TIP] Alternative: Use pdfkit with wkhtmltopdf instead
) else (
    call :log "GTK3 runtime found and working"
    echo [OK] GTK3 runtime found and working
    set GTK3_OK=1
)

REM Comprehensive GPU Detection and Configuration
echo [TEST] Scanning for all GPU types (NVIDIA, Intel, AMD)...
set NVIDIA_GPU_FOUND=0
set INTEL_GPU_FOUND=0
set AMD_GPU_FOUND=0
set GPU_VENDORS_DETECTED=

REM Check for NVIDIA GPUs using nvidia-smi (most reliable method)
nvidia-smi --query-gpu=name --format=csv,noheader >temp_gpu_info.txt 2>&1
if not errorlevel 1 (
    for /f "tokens=*" %%a in (temp_gpu_info.txt) do (
        echo [OK] NVIDIA GPU detected: %%a
        set NVIDIA_GPU_FOUND=1
        set GPU_VENDORS_DETECTED=!GPU_VENDORS_DETECTED! NVIDIA
        call :log "NVIDIA GPU detected: %%a"
    )
)
del temp_gpu_info.txt 2>nul

REM Check for all GPU types via WMI Device Manager
echo [SCAN] Scanning Device Manager for all GPU vendors...
wmic path win32_VideoController get name >temp_all_gpus.txt 2>&1
if not errorlevel 1 (
    for /f "skip=1 tokens=*" %%a in (temp_all_gpus.txt) do (
        if not "%%a"=="" (
            REM Check for NVIDIA (if not already found)
            echo %%a | findstr /i "nvidia" >nul
            if not errorlevel 1 (
                if !NVIDIA_GPU_FOUND! == 0 (
                    echo [OK] NVIDIA GPU detected: %%a
                    set NVIDIA_GPU_FOUND=1
                    set GPU_VENDORS_DETECTED=!GPU_VENDORS_DETECTED! NVIDIA
                    call :log "NVIDIA GPU detected via WMI: %%a"
                )
            )
            
            REM Check for Intel GPUs
            echo %%a | findstr /i "intel" >nul
            if not errorlevel 1 (
                echo [OK] Intel GPU detected: %%a
                set INTEL_GPU_FOUND=1
                set GPU_VENDORS_DETECTED=!GPU_VENDORS_DETECTED! Intel
                call :log "Intel GPU detected: %%a"
            )
            
            REM Check for AMD GPUs
            echo %%a | findstr /i /c:"amd" /c:"radeon" /c:"rx " >nul
            if not errorlevel 1 (
                echo [OK] AMD GPU detected: %%a
                set AMD_GPU_FOUND=1
                set GPU_VENDORS_DETECTED=!GPU_VENDORS_DETECTED! AMD
                call :log "AMD GPU detected: %%a"
            )
        )
    )
)
del temp_all_gpus.txt 2>nul

echo.
if defined GPU_VENDORS_DETECTED (
    echo [GPU] GPU Vendors detected:!GPU_VENDORS_DETECTED!
    call :log "GPU vendors detected:!GPU_VENDORS_DETECTED!"
) else (
    echo [OK] No discrete GPUs detected - CPU-only processing will be used
    call :log "No discrete GPUs detected"
    set CUDA_OK=1
    goto :end_gpu_config
)

REM Configure NVIDIA GPU support (CUDA)
if !NVIDIA_GPU_FOUND! == 1 (
    echo.
    echo [TEST] Configuring NVIDIA GPU support (CUDA toolkit)...
    
    nvcc --version >temp_cuda_version.txt 2>&1
    if errorlevel 1 (
        call :log "CUDA toolkit not found but NVIDIA GPU present"
        echo [WARNING]  CUDA toolkit not found - attempting automatic installation...
        echo [INFO] CUDA provides GPU acceleration for ML models and analysis
        
        REM Try to install CUDA via winget (Windows Package Manager)
        echo [SETUP] Attempting CUDA installation via winget...
        winget install NVIDIA.CUDA --accept-source-agreements --accept-package-agreements >nul 2>&1
        if not errorlevel 1 (
            echo [OK] CUDA toolkit installed successfully via winget
            call :log "CUDA toolkit installed via winget"
            
            REM Refresh PATH and check again
            call :refresh_environment
            REM Also try to add common CUDA paths
            if exist "C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA" (
                for /d %%d in ("C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v*") do (
                    call :add_to_path "%%d\bin"
                )
            )
            nvcc --version >temp_cuda_version_retry.txt 2>&1
            if not errorlevel 1 (
                for /f "tokens=*" %%a in ('findstr "release" temp_cuda_version_retry.txt') do set CUDA_VERSION=%%a
                echo [OK] CUDA toolkit now available: !CUDA_VERSION!
                set CUDA_OK=1
                del temp_cuda_version_retry.txt 2>nul
            )
        ) else (
            echo [ERROR] Automatic CUDA installation failed
            echo [DOWNLOAD] Manual install from: https://developer.nvidia.com/cuda-downloads
            echo [TIP] Or use: winget install NVIDIA.CUDA
            call :log "Automatic CUDA installation failed"
        )
    ) else (
        for /f "tokens=*" %%a in ('findstr "release" temp_cuda_version.txt') do set CUDA_VERSION=%%a
        call :log "CUDA toolkit found: !CUDA_VERSION!"
        echo [OK] CUDA toolkit found: !CUDA_VERSION!
        set CUDA_OK=1
        
        REM Test PyTorch CUDA support
        python -c "import torch; print('[OK] PyTorch CUDA available:', torch.cuda.is_available())" 2>nul || (
            echo [WARNING]  PyTorch CUDA support not working
            call :log "WARNING: PyTorch CUDA support not available"
        )
    )
    del temp_cuda_version.txt 2>nul
)

REM Configure Intel GPU support (Intel Extension for PyTorch + OpenVINO)
if !INTEL_GPU_FOUND! == 1 (
    echo.
    echo [TEST] Configuring Intel GPU support...
    
    REM Check and install Intel GPU drivers if needed
    echo [SETUP] Checking Intel GPU drivers and runtime...
    
    REM Try to install Intel GPU drivers via winget
    winget list | findstr /i "intel.*graphics" >nul 2>&1
    if errorlevel 1 (
        echo [WARNING]  Intel GPU drivers may be outdated - attempting update...
        winget install Intel.IntelGraphicsCommand --accept-source-agreements --accept-package-agreements >nul 2>&1
        if not errorlevel 1 (
            echo [OK] Intel Graphics Command Center installed
            call :log "Intel Graphics drivers updated"
        ) else (
            echo [TIP] Consider updating Intel GPU drivers manually from Intel.com
            call :log "Intel GPU driver update failed"
        )
    ) else (
        echo [OK] Intel GPU drivers detected
    )
    
    REM Check Intel Extension for PyTorch
    python -c "import intel_extension_for_pytorch as ipex; import torch; print('[OK] Intel Extension for PyTorch available:', torch.xpu.is_available())" 2>nul
    if errorlevel 1 (
        echo [WARNING]  Intel Extension for PyTorch not found - installing...
        call :log "Installing Intel Extension for PyTorch"
        
        REM Install Intel Extension with specific version that includes XPU support
        pip install intel-extension-for-pytorch[xpu] --upgrade --extra-index-url https://pytorch-extension.intel.com/release-whl/stable/xpu/us/
        if errorlevel 1 (
            echo [WARNING]  XPU version failed, trying standard version...
            pip install intel-extension-for-pytorch --upgrade
            if errorlevel 1 (
                echo [ERROR] Failed to install Intel Extension for PyTorch
                call :log "ERROR: Failed to install Intel Extension for PyTorch"
            ) else (
                echo [OK] Intel Extension for PyTorch (standard) installed successfully
                call :log "Intel Extension for PyTorch (standard) installed successfully"
                set INTEL_PYTORCH_OK=1
            )
        ) else (
            echo [OK] Intel Extension for PyTorch (XPU) installed successfully
            call :log "Intel Extension for PyTorch (XPU) installed successfully"
            set INTEL_PYTORCH_OK=1
        )
    ) else (
        echo [OK] Intel Extension for PyTorch already available
        set INTEL_PYTORCH_OK=1
        call :log "Intel Extension for PyTorch available"
    )
    
    REM Check OpenVINO toolkit
    python -c "import openvino; print('[OK] OpenVINO toolkit available:', openvino.__version__)" 2>nul
    if errorlevel 1 (
        echo [WARNING]  OpenVINO toolkit not found - installing...
        call :log "Installing OpenVINO toolkit"
        pip install openvino openvino-dev --upgrade
        if errorlevel 1 (
            echo [ERROR] Failed to install OpenVINO toolkit
            call :log "ERROR: Failed to install OpenVINO toolkit"
        ) else (
            echo [OK] OpenVINO toolkit installed successfully
            call :log "OpenVINO toolkit installed successfully"
            set OPENVINO_OK=1
        )
    ) else (
        echo [OK] OpenVINO toolkit already available
        set OPENVINO_OK=1
        call :log "OpenVINO toolkit available"
    )
    
    if !INTEL_PYTORCH_OK! == 1 (
        set CUDA_OK=1  REM Mark as OK since Intel GPU acceleration is available
    )
)

REM Configure AMD GPU support (ROCm - if available)
if !AMD_GPU_FOUND! == 1 (
    echo.
    echo [TEST] Configuring AMD GPU support...
    
    REM Check if ROCm PyTorch is available
    python -c "import torch; print('[OK] PyTorch ROCm available:', torch.cuda.is_available() and 'rocm' in torch.version.hip)" 2>nul
    if errorlevel 1 (
        echo [WARNING]  ROCm PyTorch not found - attempting installation...
        echo [INFO] Installing AMD GPU acceleration (ROCm-enabled PyTorch)
        call :log "Installing ROCm PyTorch for AMD GPU"
        
        REM Try to install ROCm PyTorch with latest stable version
        echo [SETUP] Installing PyTorch with ROCm support...
        pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/rocm5.7 --upgrade
        if errorlevel 1 (
            echo [ERROR] Failed to install ROCm PyTorch - trying older version...
            pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/rocm5.6 --upgrade
            if errorlevel 1 (
                echo [ERROR] Failed to install ROCm PyTorch
                echo [DOWNLOAD] Manual install from: https://pytorch.org/get-started/locally/ (select ROCm)
                echo [TIP] AMD GPU drivers may need to be updated first
                call :log "ERROR: Failed to install ROCm PyTorch"
            ) else (
                echo [OK] ROCm PyTorch (5.6) installed successfully
                set ROCM_OK=1
                call :log "ROCm PyTorch (5.6) installed successfully"
            )
        ) else (
            echo [OK] ROCm PyTorch (5.7) installed successfully
            set ROCM_OK=1
            call :log "ROCm PyTorch (5.7) installed successfully"
            
            REM Verify installation
            python -c "import torch; print('[OK] PyTorch ROCm verification:', torch.cuda.is_available())" 2>nul || (
                echo [WARNING]  ROCm PyTorch installed but not detecting GPU
                echo [TIP] AMD GPU drivers may need to be updated
                call :log "ROCm PyTorch installed but GPU not detected"
            )
        )
    ) else (
        echo [OK] ROCm PyTorch already available for AMD GPU
        set ROCM_OK=1
        call :log "ROCm PyTorch available"
    )
    
    if !ROCM_OK! == 1 (
        set CUDA_OK=1  REM Mark as OK since AMD GPU acceleration is available
    )
)

REM Universal OpenCL support (works with all GPU vendors)
echo.
echo [TEST] Checking universal OpenCL support...

REM First check if OpenCL runtime is available system-wide
echo [SETUP] Checking OpenCL runtime libraries...
python -c "import pyopencl; platforms = pyopencl.get_platforms(); print('[OK] OpenCL platforms found:', len(platforms)); [print('  -', p.name) for p in platforms]" 2>nul
if errorlevel 1 (
    echo [WARNING]  OpenCL runtime/drivers not detected - attempting installation...
    
    REM Try to install OpenCL runtime via winget
    if !NVIDIA_GPU_FOUND! == 1 (
        echo [SETUP] Installing NVIDIA OpenCL runtime...
        winget install NVIDIA.PhysX --accept-source-agreements --accept-package-agreements >nul 2>&1
        call :log "Attempted NVIDIA OpenCL runtime installation"
    )
    
    if !INTEL_GPU_FOUND! == 1 (
        echo [SETUP] Installing Intel OpenCL runtime...
        winget install Intel.IntelOpenCLRuntime --accept-source-agreements --accept-package-agreements >nul 2>&1
        if errorlevel 1 (
            echo [TIP] Intel OpenCL runtime not available via winget - included with Intel GPU drivers
        )
        call :log "Attempted Intel OpenCL runtime installation"
    )
    
    echo [TIP] OpenCL runtimes are typically included with GPU drivers
    echo [TIP] Ensure your GPU drivers are up to date for OpenCL support
    call :log "OpenCL runtime installation attempted"
)

REM Now install PyOpenCL Python package
python -c "import pyopencl; print('[OK] PyOpenCL available for universal GPU acceleration')" 2>nul
if errorlevel 1 (
    echo [WARNING]  PyOpenCL not found - installing...
    call :log "Installing PyOpenCL for universal GPU support"
    
    REM Install PyOpenCL with proper dependencies
    pip install pyopencl pytools numpy --upgrade
    if errorlevel 1 (
        echo [ERROR] Failed to install PyOpenCL
        echo [TIP] OpenCL drivers may be missing - update GPU drivers
        call :log "ERROR: Failed to install PyOpenCL"
    ) else (
        echo [OK] PyOpenCL installed successfully
        call :log "PyOpenCL installed successfully"
        
        REM Test OpenCL functionality
        python -c "import pyopencl; platforms = pyopencl.get_platforms(); print('[OK] OpenCL platforms available:', len(platforms)); devices = [d for p in platforms for d in p.get_devices()]; print('[OK] OpenCL devices found:', len(devices))" 2>nul
        if errorlevel 1 (
            echo [WARNING]  PyOpenCL installed but no OpenCL devices detected
            echo [TIP] GPU drivers may need to be updated for OpenCL support
            call :log "PyOpenCL installed but no devices detected"
        ) else (
            echo [OK] OpenCL devices successfully detected
            set OPENCL_OK=1
        )
    )
) else (
    echo [OK] PyOpenCL already available
    set OPENCL_OK=1
    call :log "PyOpenCL available"
    
    REM Test and display available OpenCL devices
    python -c "import pyopencl; platforms = pyopencl.get_platforms(); print('[OK] OpenCL platforms:', len(platforms)); devices = [d for p in platforms for d in p.get_devices()]; print('[OK] OpenCL devices:', len(devices)); [print('  -', d.name.strip()) for d in devices[:3]]" 2>nul
)

if !OPENCL_OK! == 1 (
    set CUDA_OK=1  REM Mark as OK since OpenCL provides universal GPU support
)

:end_gpu_config
REM If no GPU acceleration is available at all, still mark as OK for CPU-only mode
if !CUDA_OK! == 0 (
    if !NVIDIA_GPU_FOUND! == 0 (
        if !INTEL_GPU_FOUND! == 0 (
            if !AMD_GPU_FOUND! == 0 (
                echo [OK] No discrete GPUs detected - CPU-only mode configured
                set CUDA_OK=1
                call :log "No discrete GPUs - CPU-only mode"
            )
        )
    )
)

:phase11
set /a PHASE+=1
echo.
echo ============================================================
echo Phase %PHASE%/%TOTAL_PHASES%: Directory Setup
echo ============================================================
call :log "Phase %PHASE%: Starting directory setup phase"

:setup_directories
echo.
echo ============================================================
echo Directory Structure Setup
echo ============================================================

REM Create required directories
set DIRS_TO_CREATE=%USERPROFILE%\intellicrack\logs %USERPROFILE%\intellicrack\output %USERPROFILE%\intellicrack\temp %PROJECT_ROOT%\reports %PROJECT_ROOT%\models\downloads

for %%d in (%DIRS_TO_CREATE%) do (
    if not exist "%%d" (
        mkdir "%%d" 2>nul
        if exist "%%d" (
            echo [OK] Created directory: %%d
        ) else (
            echo [ERROR] Failed to create: %%d
        )
    ) else (
        echo [OK] Directory exists: %%d
    )
)

set DIRS_OK=1

:generate_report
set /a PHASE+=1
echo.
echo ============================================================
echo Phase %PHASE%/%TOTAL_PHASES%: Final System Validation & Report
echo ============================================================
call :log "Phase %PHASE%: Generating final status report"

echo [SCAN] Performing final system validation...
echo.

REM Test overall system readiness
echo [TEST] Testing integrated system components...

if !PYTHON_OK! == 1 (
    python -c "
import sys
print('[OK] Python:', sys.version.split()[0])
try:
    import PyQt5
    print('[OK] GUI Framework: PyQt5 ready')
except ImportError:
    print('[WARNING]  GUI Framework: PyQt5 missing')
    
try:
    import capstone, pefile, lief
    print('[OK] Binary Analysis: Core libraries ready')
except ImportError:
    print('[WARNING]  Binary Analysis: Some libraries missing')
" 2>nul
)

echo.
echo ============================================================
echo           [TARGET] INTELLICRACK SETUP STATUS REPORT
echo ============================================================
call :log "=== FINAL STATUS REPORT ==="

REM Core requirements
echo [INFO] CORE REQUIREMENTS:
if !PYTHON_OK! == 1 (
    echo [OK] Python Environment: Ready ^(!PYTHON_VERSION!^)
    call :log "[OK] Python Environment: Ready (!PYTHON_VERSION!)"
) else (
    echo [ERROR] Python Environment: FAILED
    call :log "[ERROR] Python Environment: FAILED"
)

if !DIRS_OK! == 1 (
    echo [OK] System Directories: Ready
    call :log "[OK] System Directories: Ready"
) else (
    echo [ERROR] System Directories: FAILED
    call :log "[ERROR] System Directories: FAILED"
)

echo.
echo [SETUP] CORE ANALYSIS TOOLS:
if !RADARE2_OK! == 1 (
    if defined R2_VERSION (
        echo [OK] Radare2: Ready ^(!R2_VERSION!^)
        call :log "[OK] Radare2: Ready (!R2_VERSION!)"
    ) else (
        echo [OK] Radare2: Ready
        call :log "[OK] Radare2: Ready"
    )
) else (
    echo [WARNING]  Radare2: Missing ^(binary analysis limited^)
    call :log "[WARNING] Radare2: Missing (binary analysis limited)"
)

if !GHIDRA_OK! == 1 (
    echo [OK] Ghidra: Ready ^(decompilation available^)
    call :log "[OK] Ghidra: Ready (decompilation available)"
) else (
    echo [WARNING]  Ghidra: Missing ^(advanced features limited^)
    call :log "[WARNING] Ghidra: Missing (advanced features limited)"
)

if !FRIDA_OK! == 1 (
    if defined FRIDA_VERSION (
        echo [OK] Frida: Ready ^(!FRIDA_VERSION!^)
        call :log "[OK] Frida: Ready (!FRIDA_VERSION!)"
    ) else (
        echo [OK] Frida: Ready
        call :log "[OK] Frida: Ready"
    )
) else (
    echo [WARNING]  Frida: Missing ^(dynamic analysis limited^)
    call :log "[WARNING] Frida: Missing (dynamic analysis limited)"
)

echo.
echo [NETWORK] NETWORK ANALYSIS TOOLS:
if !WIRESHARK_OK! == 1 (
    echo [OK] Wireshark: Available ^(packet analysis^)
    call :log "[OK] Wireshark: Available"
) else (
    echo [WARNING]  Wireshark: Missing ^(network analysis limited^)
    call :log "[WARNING] Wireshark: Missing (network analysis limited)"
)

if !MITMPROXY_OK! == 1 (
    if defined MITMPROXY_VERSION (
        echo [OK] mitmproxy: Ready ^(!MITMPROXY_VERSION!^)
        call :log "[OK] mitmproxy: Ready (!MITMPROXY_VERSION!)"
    ) else (
        echo [OK] mitmproxy: Ready
        call :log "[OK] mitmproxy: Ready"
    )
) else (
    echo [WARNING]  mitmproxy: Missing ^(HTTPS interception limited^)
    call :log "[WARNING] mitmproxy: Missing (HTTPS interception limited)"
)

echo.
echo [EMULATION]  EMULATION & VIRTUALIZATION TOOLS:
if !QEMU_OK! == 1 (
    if defined QEMU_VERSION (
        echo [OK] QEMU: Ready ^(!QEMU_VERSION!^)
        call :log "[OK] QEMU: Ready (!QEMU_VERSION!)"
    ) else (
        echo [OK] QEMU: Ready
        call :log "[OK] QEMU: Ready"
    )
) else (
    echo [WARNING]  QEMU: Missing ^(system emulation limited^)
    call :log "[WARNING] QEMU: Missing (system emulation limited)"
)

if !QILING_OK! == 1 (
    echo [OK] Qiling: Ready ^(binary emulation^)
    call :log "[OK] Qiling: Ready"
) else (
    echo [WARNING]  Qiling: Missing ^(binary emulation limited^)
    call :log "[WARNING] Qiling: Missing (binary emulation limited)"
)

echo.
echo [STATS] VISUALIZATION & REPORTING TOOLS:
if !GRAPHVIZ_OK! == 1 (
    if defined GRAPHVIZ_VERSION (
        echo [OK] Graphviz: Ready ^(!GRAPHVIZ_VERSION!^)
        call :log "[OK] Graphviz: Ready (!GRAPHVIZ_VERSION!)"
    ) else (
        echo [OK] Graphviz: Ready
        call :log "[OK] Graphviz: Ready"
    )
) else (
    echo [WARNING]  Graphviz: Missing ^(graph visualization limited^)
    call :log "[WARNING] Graphviz: Missing (graph visualization limited)"
)

if !WKHTMLTOPDF_OK! == 1 (
    echo [OK] wkhtmltopdf: Ready ^(PDF generation^)
    call :log "[OK] wkhtmltopdf: Ready"
) else (
    echo [WARNING]  wkhtmltopdf: Missing ^(PDF reports limited^)
    call :log "[WARNING] wkhtmltopdf: Missing (PDF reports limited)"
)


echo.
echo ============================================================

REM Calculate readiness score and provide recommendations
set /a CORE_SCORE=!PYTHON_OK! + !DIRS_OK!
set /a ANALYSIS_SCORE=!RADARE2_OK! + !GHIDRA_OK! + !FRIDA_OK! + !BINWALK_OK! + !VOLATILITY_OK!
set /a CONTAINER_SCORE=!DOCKER_OK!
set /a EMULATION_SCORE=!QEMU_OK! + !QILING_OK!
set /a NETWORK_SCORE=!WIRESHARK_OK! + !MITMPROXY_OK! + !NMAP_OK!
set /a REPORTING_SCORE=!GRAPHVIZ_OK! + !WKHTMLTOPDF_OK! + !GTK3_OK!
set /a SECURITY_SCORE=!OPENSSL_OK! + !FILETOOLS_OK!
set /a GPU_SCORE=!CUDA_OK!
set /a TOTAL_SCORE=!CORE_SCORE! + !ANALYSIS_SCORE! + !CONTAINER_SCORE! + !EMULATION_SCORE! + !NETWORK_SCORE! + !REPORTING_SCORE! + !SECURITY_SCORE! + !GPU_SCORE!
set /a MAX_SCORE=19

call :log "Readiness Score: !TOTAL_SCORE!/!MAX_SCORE! (Core: !CORE_SCORE!/2, Analysis: !ANALYSIS_SCORE!/5, Container: !CONTAINER_SCORE!/1, Emulation: !EMULATION_SCORE!/2, Network: !NETWORK_SCORE!/3, Reporting: !REPORTING_SCORE!/3, Security: !SECURITY_SCORE!/2, GPU: !GPU_SCORE!/1)"

if !CORE_SCORE! == 2 (
    if !TOTAL_SCORE! GEQ 16 (
        echo [EXCELLENT] EXCELLENT: Comprehensive tool suite configured perfectly!
        echo [READY] Intellicrack is ready for professional security analysis
        echo [EXCELLENT] All analysis, network, container, and reporting capabilities available
        call :log "STATUS: EXCELLENT - All tools ready (!TOTAL_SCORE!/!MAX_SCORE!)"
    ) else if !TOTAL_SCORE! GEQ 13 (
        echo [OK] VERY GOOD: Core and most advanced tools available
        echo [READY] Intellicrack is ready with comprehensive functionality
        echo [SETUP] Minor tools missing but won't impact core operations
        call :log "STATUS: VERY GOOD - Most tools ready (!TOTAL_SCORE!/!MAX_SCORE!)"
    ) else if !TOTAL_SCORE! GEQ 10 (
        echo [OK] GOOD: Core analysis tools ready, some advanced features limited
        echo [READY] Intellicrack is ready to run with standard functionality
        echo [STATS] Consider installing missing tools for full capabilities
        call :log "STATUS: GOOD - Core ready, some tools missing (!TOTAL_SCORE!/!MAX_SCORE!)"
    ) else if !TOTAL_SCORE! GEQ 7 (
        echo [WARNING]  PARTIAL: Basic functionality available
        echo [SETUP] Intellicrack will work with reduced capabilities
        echo [INFO] Many advanced features will be limited
        call :log "STATUS: PARTIAL - Limited functionality (!TOTAL_SCORE!/!MAX_SCORE!)"
    ) else (
        echo [WARNING]  MINIMAL: Only core Python environment ready
        echo [SETUP] Very limited functionality - install analysis tools
        echo [INFO] Most Intellicrack features will be unavailable
        call :log "STATUS: MINIMAL - Core only (!TOTAL_SCORE!/!MAX_SCORE!)"
    )
    
    echo.
    echo [STATS] Capability Breakdown:
    echo    [SETUP] Core System: !CORE_SCORE!/2 
    echo    [SCAN] Analysis Tools: !ANALYSIS_SCORE!/5 (Radare2, Ghidra, Frida, binwalk, volatility3)
    echo    [CONTAINER] Container Tools: !CONTAINER_SCORE!/1 (Docker)
    echo    [EMULATION]  Emulation Tools: !EMULATION_SCORE!/2 (QEMU, Qiling)
    echo    [NETWORK] Network Tools: !NETWORK_SCORE!/3 (Wireshark, mitmproxy, nmap)
    echo    [STATS] Reporting Tools: !REPORTING_SCORE!/3 (Graphviz, wkhtmltopdf, GTK3)
    echo    [SECURITY] Security Tools: !SECURITY_SCORE!/2 (OpenSSL, file analysis tools)
    echo    [GPU] GPU Support: !GPU_SCORE!/1 (CUDA toolkit if NVIDIA GPU present)
    
    echo.
    echo [TARGET] NEXT STEPS:
    echo    1. Launch Intellicrack: RUN_INTELLICRACK.bat
    echo    2. Check application logs for any runtime issues
    echo    3. Install missing tools to unlock additional features:
    if !ANALYSIS_SCORE! LSS 5 echo       - Install missing analysis tools (Radare2, Ghidra, Frida, binwalk, volatility3)
    if !CONTAINER_SCORE! LSS 1 echo       - Install Docker for distributed processing
    if !NETWORK_SCORE! LSS 3 echo       - Install network tools (Wireshark, mitmproxy, nmap)
    if !REPORTING_SCORE! LSS 3 echo       - Install reporting tools (Graphviz, wkhtmltopdf, GTK3)
    if !SECURITY_SCORE! LSS 2 echo       - Install security tools (OpenSSL, file analysis utilities)
    if !GPU_SCORE! LSS 1 echo       - Install CUDA toolkit for GPU acceleration (if NVIDIA GPU present)
    echo    4. Re-run setup to verify new installations
    
) else (
    echo [ERROR] INCOMPLETE: Core requirements not met
    echo [ERROR] Cannot launch Intellicrack - fix core issues first
    call :log "STATUS: INCOMPLETE - Core requirements not met (!TOTAL_SCORE!/!MAX_SCORE!)"
    echo.
    echo [SETUP] REQUIRED ACTIONS:
    echo    1. Fix Python installation and PATH
    echo    2. Ensure directory creation permissions  
    echo    3. Install Python dependencies: pip install -r requirements.txt
    echo    4. Re-run this setup script
)

echo.
echo [INFO] Setup Details:
echo    [INFO] Full log: %LOG_FILE%
echo    [INFO] Project: %PROJECT_ROOT%
echo    [INFO] Completed: %date% %time%
echo.

REM Configure Intellicrack paths based on detected tools
echo.
echo [SETUP] Configuring Intellicrack tool paths...

set CONFIG_FILE=%PROJECT_ROOT%\intellicrack_tool_config.json
echo { > "%CONFIG_FILE%"

REM Create complete Intellicrack configuration structure
echo   "log_dir": "%USERPROFILE%\\intellicrack\\logs", >> "%CONFIG_FILE%"
echo   "output_dir": "%USERPROFILE%\\intellicrack\\output", >> "%CONFIG_FILE%"
echo   "temp_dir": "%USERPROFILE%\\intellicrack\\temp", >> "%CONFIG_FILE%"

REM Configure detected tool paths (matching Intellicrack's expected structure)
if !RADARE2_OK! == 1 (
    if exist "%RADARE2_BIN%" (
        echo   "radare2_path": "%RADARE2_BIN:\=\\%", >> "%CONFIG_FILE%"
        call :log "Configured radare2_path: %RADARE2_BIN%"
    )
) else (
    echo   "radare2_path": "", >> "%CONFIG_FILE%"
)

if !GHIDRA_OK! == 1 (
    if defined GHIDRA_PATH (
        echo   "ghidra_path": "%GHIDRA_PATH:\=\\%", >> "%CONFIG_FILE%"
        call :log "Configured ghidra_path: %GHIDRA_PATH%"
    )
) else (
    echo   "ghidra_path": "", >> "%CONFIG_FILE%"
)


REM Add Frida path
echo   "frida_path": "frida", >> "%CONFIG_FILE%"

REM Add Docker configuration
if !DOCKER_OK! == 1 (
    echo   "docker_available": true, >> "%CONFIG_FILE%"
    echo   "docker_path": "docker", >> "%CONFIG_FILE%"
) else (
    echo   "docker_available": false, >> "%CONFIG_FILE%"
    echo   "docker_path": "", >> "%CONFIG_FILE%"
)

REM Add binary analysis tools paths
if !FILETOOLS_OK! == 1 (
    echo   "file_command": "file", >> "%CONFIG_FILE%"
    echo   "strings_command": "strings", >> "%CONFIG_FILE%"
    echo   "objdump_command": "objdump", >> "%CONFIG_FILE%"
    echo   "nm_command": "nm", >> "%CONFIG_FILE%"
    echo   "readelf_command": "readelf", >> "%CONFIG_FILE%"
) else (
    echo   "file_command": "", >> "%CONFIG_FILE%"
    echo   "strings_command": "", >> "%CONFIG_FILE%"
    echo   "objdump_command": "", >> "%CONFIG_FILE%"
    echo   "nm_command": "", >> "%CONFIG_FILE%"
    echo   "readelf_command": "", >> "%CONFIG_FILE%"
)

if !WIRESHARK_OK! == 1 (
    if defined WIRESHARK_PATH (
        echo   "wireshark_path": "%WIRESHARK_PATH:\=\\%", >> "%CONFIG_FILE%"
        call :log "Configured wireshark_path: %WIRESHARK_PATH%"
    )
)

if !QEMU_OK! == 1 (
    if defined QEMU_PATH (
        echo   "qemu_path": "%QEMU_PATH:\=\\%", >> "%CONFIG_FILE%"
        call :log "Configured qemu_path: %QEMU_PATH%"
    )
)

if !WKHTMLTOPDF_OK! == 1 (
    if defined WKHTMLTOPDF_PATH (
        echo   "wkhtmltopdf_path": "%WKHTMLTOPDF_PATH:\=\\%", >> "%CONFIG_FILE%"
        call :log "Configured wkhtmltopdf_path: %WKHTMLTOPDF_PATH%"
    )
)

REM Configure additional tools
if !DOCKER_OK! == 1 (
    echo   "docker_available": true, >> "%CONFIG_FILE%"
    call :log "Configured Docker as available"
)

if !BINWALK_OK! == 1 (
    echo   "binwalk_available": true, >> "%CONFIG_FILE%"
    call :log "Configured binwalk as available"
)

if !VOLATILITY_OK! == 1 (
    echo   "volatility3_available": true, >> "%CONFIG_FILE%"
    call :log "Configured volatility3 as available"
)

if !NMAP_OK! == 1 (
    if defined NMAP_VERSION (
        echo   "nmap_version": "%NMAP_VERSION%", >> "%CONFIG_FILE%"
        call :log "Configured nmap version: %NMAP_VERSION%"
    )
)

if !OPENSSL_OK! == 1 (
    if defined OPENSSL_VERSION (
        echo   "openssl_version": "%OPENSSL_VERSION%", >> "%CONFIG_FILE%"
        call :log "Configured OpenSSL version: %OPENSSL_VERSION%"
    )
)

if !GTK3_OK! == 1 (
    echo   "gtk3_available": true, >> "%CONFIG_FILE%"
    call :log "Configured GTK3 as available"
)

REM GPU Configuration - record all detected GPU types and their frameworks
if defined GPU_VENDORS_DETECTED (
    echo   "gpu_vendors_detected": "%GPU_VENDORS_DETECTED%", >> "%CONFIG_FILE%"
    call :log "Configured GPU vendors: %GPU_VENDORS_DETECTED%"
)

if !NVIDIA_GPU_FOUND! == 1 (
    echo   "nvidia_gpu_present": true, >> "%CONFIG_FILE%"
    if defined CUDA_VERSION (
        echo   "cuda_version": "%CUDA_VERSION%", >> "%CONFIG_FILE%"
        call :log "Configured CUDA version: %CUDA_VERSION%"
    ) else (
        echo   "cuda_missing": true, >> "%CONFIG_FILE%"
        call :log "CUDA missing but NVIDIA GPU present"
    )
)

if !INTEL_GPU_FOUND! == 1 (
    echo   "intel_gpu_present": true, >> "%CONFIG_FILE%"
    if !INTEL_PYTORCH_OK! == 1 (
        echo   "intel_extension_pytorch_available": true, >> "%CONFIG_FILE%"
        call :log "Intel Extension for PyTorch configured"
    )
    if !OPENVINO_OK! == 1 (
        echo   "openvino_available": true, >> "%CONFIG_FILE%"
        call :log "OpenVINO toolkit configured"
    )
)

if !AMD_GPU_FOUND! == 1 (
    echo   "amd_gpu_present": true, >> "%CONFIG_FILE%"
    if !ROCM_OK! == 1 (
        echo   "rocm_pytorch_available": true, >> "%CONFIG_FILE%"
        call :log "ROCm PyTorch configured"
    )
)

if !OPENCL_OK! == 1 (
    echo   "opencl_available": true, >> "%CONFIG_FILE%"
    call :log "Universal OpenCL support configured"
)

if !NVIDIA_GPU_FOUND! == 0 (
    if !INTEL_GPU_FOUND! == 0 (
        if !AMD_GPU_FOUND! == 0 (
            echo   "cpu_only_mode": true, >> "%CONFIG_FILE%"
            call :log "CPU-only mode configured"
        )
    )
)

if !FILETOOLS_OK! == 1 (
    echo   "file_analysis_tools_count": %FILETOOLS_COUNT%, >> "%CONFIG_FILE%"
    call :log "Configured file analysis tools count: %FILETOOLS_COUNT%"
)

echo   "setup_completed": true >> "%CONFIG_FILE%"
echo } >> "%CONFIG_FILE%"

echo [OK] Tool configuration saved to: %CONFIG_FILE%
call :log "Tool configuration saved successfully"

call :log "Setup process completed"
call :log "======================================"

echo ============================================================
echo.
echo Setup completed. Press any key to exit...
pause >nul

goto :end

:end
endlocal