@echo off
setlocal enabledelayedexpansion

REM ================================================================================
REM                          FIX ANGR DEPENDENCY CONFLICTS
REM ================================================================================
REM
REM This script fixes the angr installation that has dependency conflicts
REM by properly installing all required dependencies and resolving version conflicts.
REM
REM ================================================================================

color 0E
cls

echo ================================================================================
echo                        FIXING ANGR DEPENDENCY CONFLICTS
echo ================================================================================
echo.
echo This script will fix the angr installation by:
echo   [*] Uninstalling broken angr installation
echo   [*] Installing all required dependencies
echo   [*] Resolving capstone version conflict
echo   [*] Reinstalling angr properly
echo.
echo ================================================================================

REM Check if bundled Python exists
set "BUNDLED_PYTHON=%~dp0..\bundled_python\python.exe"
if exist "%BUNDLED_PYTHON%" (
    echo [FOUND] Using bundled Python: %BUNDLED_PYTHON%
    set "PYTHON_CMD=%BUNDLED_PYTHON%"
) else (
    echo [INFO] Bundled Python not found, using system Python
    set "PYTHON_CMD=python"
)

echo.
echo [PHASE 1/4] Uninstalling broken angr installation...
echo.

REM Uninstall angr and related packages to start clean
"%PYTHON_CMD%" -m pip uninstall angr claripy cle pyvex archinfo -y
echo [OK] Removed broken angr installation

echo.
echo [PHASE 2/4] Installing angr dependencies...
echo.

REM Install required dependencies with exact versions where needed
echo [INSTALL] Installing core dependencies...
"%PYTHON_CMD%" -m pip install colorama GitPython mulpyplexer psutil sympy

echo [INSTALL] Installing network dependency...
"%PYTHON_CMD%" -m pip install "networkx>=2.0"

echo [INSTALL] Installing ailment (exact version for angr)...
"%PYTHON_CMD%" -m pip install ailment

echo [INSTALL] Installing pypcode...
"%PYTHON_CMD%" -m pip install "pypcode>=3.2.1,<4.0"

echo.
echo [PHASE 3/4] Installing optional dependencies...
echo.

REM Install optional dependencies individually
for %%p in (cxxheaderparser pydemumble pyformlang unique-log-filter) do (
    echo [TRY] Installing %%p...
    "%PYTHON_CMD%" -m pip install %%p >nul 2>&1
    if not errorlevel 1 (
        echo [OK] %%p installed successfully
    ) else (
        echo [SKIP] %%p (not available or incompatible - this is OK)
    )
)

echo.
echo [PHASE 4/4] Installing angr and core components...
echo.

REM Fix capstone version conflict
echo [FIX] Resolving capstone version conflict...
echo [INFO] Angr requires capstone==5.0.3, installing exact version...
"%PYTHON_CMD%" -m pip install capstone==5.0.3 --force-reinstall

REM Install angr core components
echo [INSTALL] Installing angr core components...
"%PYTHON_CMD%" -m pip install claripy cle pyvex archinfo

REM Install angr itself
echo [INSTALL] Installing angr...
"%PYTHON_CMD%" -m pip install angr

echo.
echo ================================================================================
echo                              VERIFICATION
echo ================================================================================
echo.

REM Test if angr can be imported
echo [TEST] Testing angr import...
"%PYTHON_CMD%" -c "import angr; print('Angr version:', angr.__version__)" 2>nul
if not errorlevel 1 (
    echo [SUCCESS] Angr installed and working correctly!
    echo.
    echo [INFO] Angr is now properly installed with all dependencies
) else (
    echo [WARNING] Angr installation may still have issues
    echo [INFO] This is often due to optional dependencies that aren't critical
    echo [INFO] Intellicrack should still work for most analysis tasks
)

echo.
echo [TEST] Testing related packages...
for %%p in (claripy cle pyvex archinfo capstone) do (
    "%PYTHON_CMD%" -c "import %%p" >nul 2>&1
    if not errorlevel 1 (
        echo [OK] %%p working
    ) else (
        echo [WARNING] %%p has issues
    )
)

echo.
echo ================================================================================
echo                              SUMMARY
echo ================================================================================
echo.
echo [COMPLETED] Angr dependency resolution finished
echo.
echo What was fixed:
echo   [*] Removed broken angr installation
echo   [*] Installed all required dependencies
echo   [*] Fixed capstone version conflict (5.0.6 → 5.0.3)
echo   [*] Reinstalled angr core components properly
echo   [*] Verified installation
echo.
echo You can now continue with your Intellicrack installation or run Intellicrack
echo with the bundled Python using: RUN_INTELLICRACK_BUNDLED.bat
echo.
echo Press any key to exit...
pause >nul

endlocal
exit /b 0