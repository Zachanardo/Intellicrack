@echo off
cd %INTELLICRACK_ROOT%
pixi run python -m pytest tests\unit\core\mitigation_bypass\test_cfi_bypass.py -v --cov=intellicrack.core.exploitation.cfi_bypass --cov-report=term-missing --cov-report=html
echo.
echo Test execution complete. Check htmlcov\index.html for detailed coverage report.
pause
