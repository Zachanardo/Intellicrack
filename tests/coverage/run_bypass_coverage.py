"""Run bypass engine tests with coverage analysis."""

import sys
import subprocess
import os

# Add project root to path
project_root = r"C:\Intellicrack"
sys.path.insert(0, project_root)
os.chdir(project_root)

# Run pytest with coverage
cmd = [
    sys.executable,
    "-m", "pytest",
    "tests/unit/core/mitigation_bypass/test_bypass_engine.py",
    "-v",
    "--cov=intellicrack.core.exploitation.bypass_engine",
    "--cov=intellicrack.core.mitigation_bypass.bypass_engine",
    "--cov-report=term-missing",
    "--cov-report=html:tests/reports/bypass_engine_coverage",
    "-x"  # Stop on first failure
]

print("Running bypass engine tests with coverage analysis...")
print(f"Command: {' '.join(cmd)}")
print("-" * 80)

result = subprocess.run(cmd, capture_output=False, text=True)

print("-" * 80)
if result.returncode == 0:
    print("Tests completed successfully!")
else:
    print(f"Tests failed with return code: {result.returncode}")

sys.exit(result.returncode)
