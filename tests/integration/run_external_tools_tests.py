#!/usr/bin/env python3
"""
Test runner for external_tools_config.py tests
"""

import sys
import os
import pytest

# Add project root to Python path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

if __name__ == "__main__":
    # Change to project directory
    os.chdir(project_root)

    # Run tests with coverage
    exit_code = pytest.main([
        "tests/unit/core/config/test_external_tools_config.py",
        "-v",
        "--tb=short",
        "--cov=intellicrack.core.config.external_tools_config",
        "--cov-report=term-missing",
        "--cov-report=html:tests/reports/coverage_external_tools",
        "--no-header"
    ])

    print(f"\nTest execution completed with exit code: {exit_code}")
    sys.exit(exit_code)
