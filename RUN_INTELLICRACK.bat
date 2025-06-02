@echo off
cd /d "%~dp0"

set PYTHONWARNINGS=ignore::UserWarning:pytools.persistent_dict
set QT_QPA_FONTDIR=
set QT_LOGGING_RULES=*.debug=false;qt.qpa.fonts=false

python launch_intellicrack.py

if errorlevel 1 (
    echo ERROR: Failed to launch Intellicrack
    pause
)