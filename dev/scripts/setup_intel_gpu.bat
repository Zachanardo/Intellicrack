@echo off
REM Setup Intel GPU Environment for Intellicrack

echo ================================================
echo Intel GPU Setup for Intellicrack
echo ================================================
echo.
echo This script will create a conda environment with
echo Intel Extension for PyTorch for Intel Arc GPUs
echo.

REM Check if conda is available
where conda >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Conda not found in PATH!
    echo.
    echo Please install Miniconda or Anaconda first:
    echo https://docs.conda.io/en/latest/miniconda.html
    echo.
    pause
    exit /b 1
)

set CONDA_ENV_NAME=intellicrack_gpu

REM Check if environment already exists
call conda env list | findstr /C:"%CONDA_ENV_NAME%" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Environment '%CONDA_ENV_NAME%' already exists.
    echo.
    choice /C YN /M "Do you want to remove and recreate it"
    if ERRORLEVEL 2 goto :activate_env
    if ERRORLEVEL 1 (
        echo Removing existing environment...
        call conda env remove -n %CONDA_ENV_NAME% -y
    )
)

:create_env
echo.
echo Creating conda environment '%CONDA_ENV_NAME%' with Python 3.10...
call conda create -n %CONDA_ENV_NAME% python=3.10 -y

:activate_env
echo.
echo Activating environment...
call conda activate %CONDA_ENV_NAME%

echo.
echo Installing PyTorch...
call conda install pytorch torchvision torchaudio cpuonly -c pytorch -y

echo.
echo Installing Intel Extension for PyTorch...
call conda install intel-extension-for-pytorch -c intel -y

echo.
echo Installing other Intellicrack dependencies from UV environment...
cd /d "%~dp0..\.."

REM Install basic requirements that work in conda
pip install PyQt6 PyQt6-WebEngine
pip install numpy pandas matplotlib seaborn
pip install requests beautifulsoup4 lxml
pip install cryptography keyring
pip install psutil GPUtil py-cpuinfo

echo.
echo ================================================
echo Setup Complete!
echo ================================================
echo.
echo To use Intel GPU acceleration:
echo 1. Run: RUN_INTELLICRACK.bat --intel-gpu
echo 2. Or set environment variable: set INTELLICRACK_USE_INTEL_GPU=1
echo.
echo To test Intel GPU:
echo   conda activate %CONDA_ENV_NAME%
echo   python dev\scripts\test_intel_gpu_setup.py
echo.
pause
