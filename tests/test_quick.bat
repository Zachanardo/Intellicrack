@echo off
set QT_OPENGL=software
set INTELLICRACK_FORCE_SOFTWARE=1
.venv_windows\Scripts\python.exe launch_intellicrack.py 2>&1 | more > quick_test.log
type quick_test.log