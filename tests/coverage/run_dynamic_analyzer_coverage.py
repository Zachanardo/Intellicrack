"""
Script to run tests and generate coverage report for dynamic_analyzer.py
"""

import subprocess
import sys
from pathlib import Path

def run_coverage():
    """Run tests with coverage analysis."""

    # Ensure we're in the right directory
    project_root = Path(r"C:\Intellicrack")

    # Run pytest with coverage
    cmd = [
        sys.executable, "-m", "pytest",
        str(project_root / "tests" / "unit" / "core" / "analysis" / "test_dynamic_analyzer.py"),
        "-v",
        "--cov=intellicrack.core.analysis.dynamic_analyzer",
        "--cov-report=term-missing",
        "--cov-report=html:coverage_reports/dynamic_analyzer",
        "--tb=short",
        "-x"  # Stop on first failure
    ]

    print(f"Running command: {' '.join(cmd)}")
    print("=" * 80)

    # Run the command
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(project_root))

    # Print output
    print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)

    # Print summary
    print("\n" + "=" * 80)
    print("COVERAGE ANALYSIS SUMMARY")
    print("=" * 80)

    # Parse coverage from output
    lines = result.stdout.split('\n')
    for i, line in enumerate(lines):
        if 'dynamic_analyzer.py' in line and '%' in line:
            print(f"Coverage Result: {line.strip()}")

            # Extract percentage
            parts = line.split()
            for part in parts:
                if part.endswith('%'):
                    coverage_pct = float(part.rstrip('%'))
                    print(f"\nCOVERAGE PERCENTAGE: {coverage_pct}%")

                    if coverage_pct >= 80:
                        print("✅ SUCCESS: 80%+ coverage achieved!")
                    else:
                        print(f"⚠️ WARNING: Coverage is {coverage_pct}%, below 80% target")
                    break

    return result.returncode

if __name__ == "__main__":
    sys.exit(run_coverage())
