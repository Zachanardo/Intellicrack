@echo off
cd /d C:\Intellicrack
call .venv_windows\Scripts\activate.bat
set TF_CPP_MIN_LOG_LEVEL=2
set CUDA_VISIBLE_DEVICES=-1
set MKL_THREADING_LAYER=GNU
set QT_QPA_PLATFORM=windows
python -m intellicrack
pause