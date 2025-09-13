"""
Script to run DEP bypass tests and generate coverage report.
"""

import sys
import os
import subprocess

# Add project root to path
sys.path.insert(0, r'C:\Intellicrack')

def run_tests():
    """Run the DEP bypass tests with coverage."""
    print("=" * 80)
    print("Running DEP Bypass Module Tests with Coverage Analysis")
    print("=" * 80)

    # Change to project directory
    os.chdir(r'C:\Intellicrack')

    # Run pytest with coverage
    cmd = [
        sys.executable, '-m', 'pytest',
        'tests/unit/core/mitigation_bypass/test_dep_bypass.py',
        '-v',
        '--cov=intellicrack.core.mitigation_bypass.dep_bypass',
        '--cov-report=term-missing',
        '--cov-report=html',
        '--tb=short'
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    print(result.stdout)
    if result.stderr:
        print("Errors:", result.stderr)

    print("\n" + "=" * 80)
    print("Test Execution Complete")
    print("=" * 80)

    # Try to get coverage percentage
    if "TOTAL" in result.stdout:
        lines = result.stdout.split('\n')
        for line in lines:
            if "TOTAL" in line:
                print(f"\nCoverage Summary: {line.strip()}")
                # Extract percentage
                parts = line.split()
                for part in parts:
                    if '%' in part:
                        coverage_pct = float(part.strip('%'))
                        if coverage_pct >= 80:
                            print(f"✓ Coverage target of 80% achieved: {coverage_pct}%")
                        else:
                            print(f"✗ Coverage below target: {coverage_pct}% (need 80%)")
                        break

    return result.returncode

if __name__ == "__main__":
    exit_code = run_tests()

    print("\nCoverage HTML report available at: htmlcov\\index.html")
    print("\nTo view detailed coverage, open the HTML report in a browser.")

    sys.exit(exit_code)
