@echo off
echo Running Coverage Analysis for exploitation __init__.py module...
echo ========================================================

REM Set environment variables for testing
set INTELLICRACK_TESTING=1
set DISABLE_AI_WORKERS=1
set DISABLE_BACKGROUND_THREADS=1
set NO_AUTO_START=1

REM Run simple validation first
echo Testing basic module import functionality...
python test_init_simple.py
if %ERRORLEVEL% NEQ 0 (
    echo Basic import test failed - aborting coverage analysis
    pause
    exit /b 1
)

echo.
echo Running comprehensive test suite with coverage...
python -m pytest tests/unit/utils/exploitation/test_init.py --cov=intellicrack.utils.exploitation --cov-report=term-missing --cov-report=html:htmlcov_init --cov-fail-under=80 -v --tb=short

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================================
    echo SUCCESS: Coverage analysis completed!
    echo Check htmlcov_init/index.html for detailed coverage report
    echo ========================================================
) else (
    echo.
    echo ========================================================
    echo WARNING: Coverage analysis failed or below 80%% threshold
    echo Check output above for details
    echo ========================================================
)

pause
