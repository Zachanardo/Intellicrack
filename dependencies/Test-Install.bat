@echo off
REM Test script to diagnose PowerShell issues

echo Testing PowerShell execution...
echo.

echo 1. PowerShell version:
powershell -NoProfile -Command "$PSVersionTable.PSVersion"
echo.

echo 2. Execution Policy:
powershell -NoProfile -Command "Get-ExecutionPolicy"
echo.

echo 3. Testing simple PowerShell command:
powershell -NoProfile -ExecutionPolicy Bypass -Command "Write-Host 'PowerShell works!' -ForegroundColor Green"
echo.

echo 4. Checking if Install.ps1 exists:
if exist "%~dp0Install.ps1" (
    echo    Install.ps1 found
) else (
    echo    ERROR: Install.ps1 not found!
)
echo.

echo 5. Trying to read first line of Install.ps1:
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-Content '%~dp0Install.ps1' -First 1"
echo.

echo 6. Checking for syntax errors in Install.ps1:
powershell -NoProfile -ExecutionPolicy Bypass -Command "$null = [System.Management.Automation.PSParser]::Tokenize((Get-Content '%~dp0Install.ps1' -Raw), [ref]$null); if ($?) { 'No syntax errors found' } else { 'SYNTAX ERRORS DETECTED!' }"
echo.

pause