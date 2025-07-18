@echo off
REM Launch Intellicrack with Intel GPU Support
REM This script activates the conda environment with Intel Extension for PyTorch

echo ===========================================
echo Intellicrack Intel GPU Launcher
echo ===========================================
echo.

REM Check if conda is available
where conda >nul 2>1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Conda not found in PATH!
    echo Please install Miniconda or Anaconda and add to PATH
    pause
    exit /b 1
)

REM Set the conda environment name
set CONDA_ENV_NAME=intellicrack_gpu
echo Using conda environment: %CONDA_ENV_NAME%

REM Activate conda environment
echo Activating conda environment...
call conda activate %CONDA_ENV_NAME%
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Failed to activate conda environment '%CONDA_ENV_NAME%'
    echo.
    echo Creating new environment...
    call conda create -n %CONDA_ENV_NAME% python=3.10 -y
    call conda activate %CONDA_ENV_NAME%
    
    echo Installing PyTorch...
    call conda install pytorch torchvision torchaudio -c pytorch -y
    
    echo Installing Intel Extension for PyTorch...
    call conda install -c intel intel-extension-for-pytorch -y
    
    echo Installing Intellicrack dependencies...
    cd /d "%~dp0..\.."
    pip install -r requirements.txt
    pip install -e .
)

REM Set environment variables for Intel GPU
echo.
echo Setting Intel GPU environment variables...
set INTEL_DISABLE_XE_NEXT_FALLBACK=0
set USE_XPU=1
set INTELLICRACK_USE_CONDA=1
set CONDA_DEFAULT_ENV=%CONDA_ENV_NAME%

REM Test GPU availability
echo.
echo Testing Intel GPU availability...
python -c "import torch; import intel_extension_for_pytorch as ipex; print(f'PyTorch: {torch.__version__}'); print(f'IPEX: {ipex.__version__}'); print(f'XPU Available: {torch.xpu.is_available()}')"

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo WARNING: Intel GPU test failed!
    echo Continuing with CPU fallback...
)

REM Launch Intellicrack
echo.
echo Launching Intellicrack...
cd /d "%~dp0..\.."
python -m intellicrack.ui.main_app %*

pause