@echo off
echo ========================================
echo Launching Intellicrack on Windows
echo ========================================
echo.

:: Set the working directory to Intellicrack root
cd /d "C:\Intellicrack"

:: Activate the Windows virtual environment
echo Activating Windows Python environment...
call .venv_windows\Scripts\activate.bat

:: Set environment variables for Intel Arc B580 compatibility
echo Setting environment variables...
set TF_CPP_MIN_LOG_LEVEL=2
set CUDA_VISIBLE_DEVICES=-1
set MKL_THREADING_LAYER=GNU

:: Set Qt to use Windows native platform
set QT_QPA_PLATFORM=windows

:: Launch Intellicrack
echo.
echo Starting Intellicrack...
echo ========================================
python -m intellicrack %*

:: Keep window open if there's an error
if errorlevel 1 (
    echo.
    echo ========================================
    echo Error occurred! Press any key to exit...
    pause >nul
)