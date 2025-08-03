@echo off
REM Intellicrack Windows Installation Script
REM This script installs only Windows-compatible dependencies

echo ===============================================
echo Intellicrack Windows Installation
echo ===============================================
echo.

REM Activate virtual environment
echo Activating Windows virtual environment...
call .venv_windows\Scripts\activate.bat

REM Install dependencies using UV with platform markers
echo Installing Windows-compatible dependencies...
echo.

REM First, ensure UV is installed
pip install uv

REM Install from pyproject.toml which has platform-specific markers
echo Installing core dependencies (excluding Linux-only packages)...
cd requirements
uv pip install -e . --no-deps
uv pip install -e .
cd ..

REM Install critical GUI components explicitly
echo.
echo Installing PyQt5 components...
uv pip install PyQtWebEngine pyqtgraph

echo.
echo ===============================================
echo Installation Complete!
echo ===============================================
echo.
echo Symbolic Execution on Windows:
echo - angr is installed and fully functional
echo - manticore is Linux-only and not required
echo - Use "Symbolic Execution (angr)" in the GUI
echo.
echo To launch Intellicrack:
echo   python launch_intellicrack.py
echo ===============================================
pause
