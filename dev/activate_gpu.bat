@echo off
REM Quick activation script for Intel GPU

echo Activating Intel GPU environment...
call conda activate ipex-only

echo.
echo Testing Intel GPU...
python -c "import torch, intel_extension_for_pytorch as ipex; print(f'XPU available: {torch.xpu.is_available() if hasattr(torch, \"xpu\") else \"Not detected\"}')"

echo.
echo To run Intellicrack with GPU:
echo   python gpu_bridge.py
echo.