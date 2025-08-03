@echo off
cd /d "%~dp0"

echo Starting Intellicrack with Intel GPU Support...
echo.

REM First activate conda for GPU support
echo Activating Intel GPU environment...
call conda activate intel-gpu

REM Add UV's site-packages to Python path
set PYTHONPATH=%~dp0\.venv\Lib\site-packages;%PYTHONPATH%

REM Copy UV's environment variables
set PYTHONWARNINGS=ignore::UserWarning:pytools.persistent_dict
set QT_QPA_FONTDIR=%WINDIR%\Fonts
set QT_LOGGING_RULES=*.debug=false;qt.qpa.fonts=false
set QT_ASSUME_STDERR_HAS_CONSOLE=1
set QT_FONT_DPI=96
set TF_ENABLE_ONEDNN_OPTS=0

REM Intel GPU specific
set INTEL_EXTENSION_FOR_PYTORCH_ENABLED=1
set IPEX_VERBOSE=1

echo Python:
where python
echo.
python --version
echo.

REM Run Intellicrack
python launch_intellicrack.py

set EXIT_CODE=%ERRORLEVEL%
echo.
echo Exit code: %EXIT_CODE%
echo.

pause
