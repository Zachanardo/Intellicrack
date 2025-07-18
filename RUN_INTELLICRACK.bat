@echo off
cd /d "%~dp0"

REM Set environment variables for Intel GPU
set CUDA_VISIBLE_DEVICES=-1
set INTELLICRACK_GPU_TYPE=intel

REM Qt settings for Intel Arc B580 - use WARP
set QT_OPENGL=software
set QT_ANGLE_PLATFORM=warp
set QT_D3D_ADAPTER_INDEX=1
set QT_QUICK_BACKEND=software
set QT_QPA_PLATFORM=windows

REM Use your existing UV environment
call .venv_windows\Scripts\activate.bat

echo Starting Intellicrack with Intel GPU support...
python launch_intellicrack.py
pause