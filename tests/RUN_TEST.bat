@echo off
cd /d C:\Intellicrack

echo Starting Intellicrack test at %date% %time% > test_output.log 2>&1

echo Activating virtual environment...
call .venv_windows\Scripts\activate >> test_output.log 2>&1

echo Starting Intellicrack...
python launch_intellicrack.py >> test_output.log 2>&1

echo.
echo Test completed at %date% %time% >> test_output.log 2>&1
type test_output.log
pause