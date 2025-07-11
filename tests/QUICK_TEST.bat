@echo off
echo Quick test at %TIME%
set QT_OPENGL=software
set INTELLICRACK_FORCE_SOFTWARE=1
del quick_output.log 2>nul
.venv_windows\Scripts\python.exe launch_intellicrack.py > quick_output.log 2>&1
echo Exit: %ERRORLEVEL%
type quick_output.log | findstr /C:"ERROR" /C:"Failed" /C:"Qt." /C:"ModelManager"