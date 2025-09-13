#!/usr/bin/env python3
"""
Coverage analysis script for exploitation __init__.py module.
"""

import subprocess
import sys
import os
from pathlib import Path

# Change to project root directory
project_root = Path(__file__).parent
os.chdir(project_root)

# Set environment variables for testing
os.environ["PYTHONPATH"] = str(project_root)
os.environ["INTELLICRACK_TESTING"] = "1"

print("Running coverage analysis for intellicrack.utils.exploitation.__init__.py")
print("=" * 70)

try:
    # Run pytest with coverage
    cmd = [
        sys.executable, "-m", "pytest",
        "tests/unit/utils/exploitation/test_init.py",
        "--cov=intellicrack.utils.exploitation",
        "--cov-report=term-missing",
        "--cov-report=html:htmlcov_init",
        "--cov-fail-under=80",
        "-v",
        "--tb=short"
    ]

    print(f"Executing: {' '.join(cmd)}")
    print("=" * 70)

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

    print("STDOUT:")
    print(result.stdout)
    print("\nSTDERR:")
    print(result.stderr)
    print(f"\nReturn code: {result.returncode}")

    if result.returncode == 0:
        print("\n✅ Coverage analysis completed successfully!")
        print("✅ 80% coverage target achieved!")
    else:
        print("\n❌ Coverage analysis failed or coverage below threshold")

except subprocess.TimeoutExpired:
    print("❌ Coverage analysis timed out")
except Exception as e:
    print(f"❌ Error running coverage analysis: {e}")

print("=" * 70)
