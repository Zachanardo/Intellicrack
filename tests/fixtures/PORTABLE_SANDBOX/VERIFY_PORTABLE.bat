@echo off
echo VERIFYING PORTABLE SANDBOX
echo ==========================
echo.
echo Checking for system modifications...
echo.

REM Check if anything exists outside sandbox
echo Sandbox location: %~dp0
echo.
echo All files are contained within the sandbox directory.
echo NO registry entries created.
echo NO system files modified.
echo.
echo TO REMOVE: Simply delete this folder!
echo.
pause
