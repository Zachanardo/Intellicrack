#!/usr/bin/env python
"""Run bypass_base tests with coverage."""

import subprocess
import sys

# Run pytest with coverage
result = subprocess.run([
    sys.executable, "-m", "pytest",
    "tests/unit/core/mitigation_bypass/test_bypass_base.py",
    "-v",
    "--cov=intellicrack.core.mitigation_bypass.bypass_base",
    "--cov-report=term-missing",
    "--cov-report=html:coverage_bypass_base"
], capture_output=True, text=True)

print(result.stdout)
if result.stderr:
    print(result.stderr, file=sys.stderr)

sys.exit(result.returncode)
