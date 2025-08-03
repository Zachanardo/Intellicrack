@echo off
echo Intel Arc B580 Debug Script
echo ==========================

REM Set minimal Qt variables for software rendering
set QT_OPENGL=software
set QT_QUICK_BACKEND=software
set INTELLICRACK_FORCE_SOFTWARE=1

REM Create log file
set LOG=arc_debug_%date:~-4,4%%date:~-10,2%%date:~-7,2%_%time:~0,2%%time:~3,2%%time:~6,2%.txt
set LOG=%LOG: =0%

echo Log file: %LOG%
echo.

REM Try to run Python with output capture
echo Testing Python launch... > "%LOG%" 2>&1

if exist ".venv_windows\Scripts\python.exe" (
    echo Using venv Python...
    echo Using venv Python... >> "%LOG%" 2>&1

    REM Run in a way that won't crash the console
    start /wait "" cmd /k ".venv_windows\Scripts\python.exe launch_intellicrack.py >> %LOG% 2>&1 & echo. & echo Exit code: %ERRORLEVEL% >> %LOG% & echo. & echo CHECK LOG FILE: %LOG% & pause & exit"
) else (
    echo Using system Python...
    echo Using system Python... >> "%LOG%" 2>&1

    REM Run in a way that won't crash the console
    start /wait "" cmd /k "python launch_intellicrack.py >> %LOG% 2>&1 & echo. & echo Exit code: %ERRORLEVEL% >> %LOG% & echo. & echo CHECK LOG FILE: %LOG% & pause & exit"
)

echo.
echo If the window closed, check: %LOG%
pause
