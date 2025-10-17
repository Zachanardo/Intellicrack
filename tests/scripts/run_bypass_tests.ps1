# Run bypass engine tests with coverage

pixi run python -m pytest tests\unit\core\mitigation_bypass\test_bypass_engine.py -v --cov=intellicrack.core.exploitation.bypass_engine --cov=intellicrack.core.mitigation_bypass.bypass_engine --cov-report=term-missing --cov-report=html:tests\reports\bypass_engine_coverage

Write-Host "Test execution complete."
