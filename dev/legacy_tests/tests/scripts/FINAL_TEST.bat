@echo off
cd /d C:\Intellicrack

echo Final test of Intellicrack launch at %date% %time% > final_test.log 2>&1

echo Activating virtual environment...
call .venv_windows\Scripts\activate >> final_test.log 2>&1

echo Setting Intel Arc environment variables...
set QT_OPENGL=software
set QT_QUICK_BACKEND=software

echo Starting Intellicrack...
python launch_intellicrack.py >> final_test.log 2>&1

echo.
echo Test completed at %date% %time% >> final_test.log 2>&1
type final_test.log
