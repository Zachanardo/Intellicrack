"""Direct test runner for bypass engine tests."""

import sys
import os

# Set up environment
os.chdir(r"C:\Intellicrack")
sys.path.insert(0, r"C:\Intellicrack")

# Import and run tests
import pytest

# Run tests with coverage
exit_code = pytest.main([
    "tests/unit/core/mitigation_bypass/test_bypass_engine.py",
    "-v",
    "--cov=intellicrack.core.exploitation.bypass_engine",
    "--cov=intellicrack.core.mitigation_bypass.bypass_engine",
    "--cov-report=term-missing",
    "--cov-report=html:tests/reports/bypass_engine_coverage",
    "-x"  # Stop on first failure to see issues
])

print(f"\nTest run completed with exit code: {exit_code}")
sys.exit(exit_code)
