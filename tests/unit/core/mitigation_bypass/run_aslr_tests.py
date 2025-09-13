"""
Run ASLR bypass tests with coverage report.
"""
import subprocess
import sys

def run_tests():
    cmd = [
        sys.executable, "-m", "pytest",
        "tests/unit/core/mitigation_bypass/test_aslr_bypass.py",
        "-v",
        "--cov=intellicrack.core.mitigation_bypass.aslr_bypass",
        "--cov-report=term-missing",
        "--tb=short"
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)
    return result.returncode

if __name__ == "__main__":
    sys.exit(run_tests())
