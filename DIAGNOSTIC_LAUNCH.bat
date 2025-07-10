@echo off
echo ========================================
echo INTELLICRACK DIAGNOSTIC LAUNCH
echo ========================================
echo.
echo [%TIME%] Starting diagnostic launch...
echo.

cd /d "C:\Intellicrack"
echo [%TIME%] Changed to Intellicrack directory

echo.
echo [%TIME%] Setting environment variables...
set TF_CPP_MIN_LOG_LEVEL=2
set CUDA_VISIBLE_DEVICES=-1
set MKL_THREADING_LAYER=GNU
set QT_QPA_PLATFORM=windows
echo [%TIME%] Environment variables set

echo.
echo [%TIME%] Activating Windows virtual environment...
call .venv_windows\Scripts\activate.bat
if errorlevel 1 (
    echo [%TIME%] ERROR: Failed to activate virtual environment
    exit /b 1
)
echo [%TIME%] Virtual environment activated

echo.
echo [%TIME%] Python version:
python --version

echo.
echo [%TIME%] Testing PyQt6 import...
python -c "from PyQt6.QtWidgets import QApplication; print('[OK] PyQt6 import successful')"
if errorlevel 1 (
    echo [%TIME%] ERROR: PyQt6 import failed
    exit /b 1
)

echo.
echo [%TIME%] Testing Qt enum compatibility...
python -c "from PyQt6.QtCore import Qt; print(f'[OK] Qt.AlignmentFlag: {Qt.AlignmentFlag.AlignCenter}')"
if errorlevel 1 (
    echo [%TIME%] ERROR: Qt enum test failed
)

echo.
echo [%TIME%] Starting full Intellicrack launch...
echo ========================================
python -m intellicrack 2>&1

echo.
echo [%TIME%] Launch completed with exit code: %errorlevel%
echo ========================================