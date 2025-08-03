@echo off
echo Starting Intellicrack with first-run skip...
cd /d C:\Intellicrack

REM Set environment to skip first-run
set INTELLICRACK_SKIP_FIRSTRUN=1

REM Set MKL threading layer
set MKL_THREADING_LAYER=GNU

REM Run Intellicrack
echo.
echo Launching Intellicrack...
C:\Intellicrack\.venv_windows\Scripts\python.exe -m intellicrack

echo.
echo Intellicrack has exited.
pause
