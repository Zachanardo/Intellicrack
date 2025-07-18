@echo off
echo ================================================================
echo RUNNING INTELLICRACK FROM WINDOWS COMMAND PROMPT
echo ================================================================
echo.

echo Activating Windows virtual environment...
call .venv_windows\Scripts\activate.bat

echo.
echo Setting Windows-specific environment variables...
set QT_QPA_PLATFORM=windows
set QT_SCALE_FACTOR=1.0
set PYTHONPATH=%CD%;%PYTHONPATH%

echo.
echo Current directory: %CD%
echo Python executable: 
python --version
echo.
echo UV executable:
uv --version
echo.

echo Installing missing PyQt5 components...
uv pip install QtPy PyQt5-tools

echo.
echo ================================================================
echo LAUNCHING INTELLICRACK...
echo ================================================================
python launch_intellicrack.py

echo.
echo ================================================================
echo Intellicrack exited with code: %ERRORLEVEL%
echo ================================================================
pause