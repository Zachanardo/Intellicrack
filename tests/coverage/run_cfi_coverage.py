"""
Script to run CFI bypass tests and generate coverage report.
"""

import subprocess
import sys
import os

def run_tests():
    """Run the CFI bypass tests with coverage."""
    os.chdir(r"C:\Intellicrack")

    # Activate mamba environment
    activate_cmd = r"mamba activate C:\Intellicrack\mamba_env"

    # Run tests with coverage
    test_cmd = [
        sys.executable,
        "-m", "pytest",
        "tests/unit/core/mitigation_bypass/test_cfi_bypass.py",
        "-v",
        "--cov=intellicrack.core.exploitation.cfi_bypass",
        "--cov=intellicrack.core.mitigation_bypass.cfi_bypass",
        "--cov-report=term-missing",
        "--cov-report=html",
        "--tb=short"
    ]

    print("Running CFI bypass tests with coverage analysis...")
    print(f"Command: {' '.join(test_cmd)}")
    print("-" * 80)

    try:
        result = subprocess.run(test_cmd, capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)

        print("\n" + "=" * 80)
        print("COVERAGE SUMMARY")
        print("=" * 80)

        # Parse coverage from output
        lines = result.stdout.split('\n')
        for i, line in enumerate(lines):
            if 'TOTAL' in line or 'cfi_bypass' in line:
                print(line)

        print("\nDetailed HTML coverage report available at: htmlcov/index.html")

        return result.returncode

    except Exception as e:
        print(f"Error running tests: {e}")
        return 1

if __name__ == "__main__":
    exit_code = run_tests()
    sys.exit(exit_code)
