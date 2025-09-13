@echo off
call mamba activate C:\Intellicrack\mamba_env
python -m pytest tests\unit\core\mitigation_bypass\test_bypass_engine.py -v --cov=intellicrack.core.exploitation.bypass_engine --cov=intellicrack.core.mitigation_bypass.bypass_engine --cov-report=term-missing --cov-report=html:tests\reports\bypass_engine_coverage
echo.
echo Test execution complete. Check coverage report.
