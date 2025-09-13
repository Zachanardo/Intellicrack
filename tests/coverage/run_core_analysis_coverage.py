#!/usr/bin/env python3
"""
Coverage analysis script for core_analysis.py testing.
Runs tests and generates coverage report.
"""

import subprocess
import sys
import os
from pathlib import Path

def main():
    """Run coverage analysis for core_analysis module."""
    print("=== Core Analysis Coverage Analysis ===")

    # Change to project root
    project_root = Path(__file__).parent
    os.chdir(project_root)

    # Target module
    target_module = "intellicrack/core/analysis/core_analysis.py"
    test_module = "tests/unit/core/analysis/test_core_analysis.py"

    print(f"Target module: {target_module}")
    print(f"Test module: {test_module}")

    # Check if files exist
    if not Path(target_module).exists():
        print(f"ERROR: Target module not found: {target_module}")
        return 1

    if not Path(test_module).exists():
        print(f"ERROR: Test module not found: {test_module}")
        return 1

    try:
        # First, try to run basic import test
        print("\n=== Testing Basic Import ===")
        import_result = subprocess.run([
            sys.executable, "-c",
            "from intellicrack.core.analysis.core_analysis import get_machine_type; print('✓ Import successful')"
        ], capture_output=True, text=True, cwd=project_root)

        if import_result.returncode == 0:
            print("✓ Core analysis module imports successfully")
        else:
            print("✗ Import failed:")
            print("STDOUT:", import_result.stdout)
            print("STDERR:", import_result.stderr)

        # Run tests with coverage
        print("\n=== Running Tests with Coverage ===")
        coverage_cmd = [
            sys.executable, "-m", "coverage", "run",
            "--source=intellicrack/core/analysis/core_analysis.py",
            "-m", "pytest", test_module, "-v", "--tb=short"
        ]

        test_result = subprocess.run(
            coverage_cmd,
            capture_output=True,
            text=True,
            cwd=project_root
        )

        print("Test execution completed with return code:", test_result.returncode)
        print("\nSTDOUT:")
        print(test_result.stdout)
        if test_result.stderr:
            print("\nSTDERR:")
            print(test_result.stderr)

        # Generate coverage report
        print("\n=== Generating Coverage Report ===")
        report_result = subprocess.run([
            sys.executable, "-m", "coverage", "report",
            "--include=intellicrack/core/analysis/core_analysis.py"
        ], capture_output=True, text=True, cwd=project_root)

        print("Coverage report:")
        print(report_result.stdout)
        if report_result.stderr:
            print("Coverage stderr:")
            print(report_result.stderr)

        # Generate HTML coverage report
        print("\n=== Generating HTML Coverage Report ===")
        html_result = subprocess.run([
            sys.executable, "-m", "coverage", "html",
            "--include=intellicrack/core/analysis/core_analysis.py",
            "--directory=tests/reports/core_analysis_coverage"
        ], capture_output=True, text=True, cwd=project_root)

        if html_result.returncode == 0:
            print("✓ HTML coverage report generated in tests/reports/core_analysis_coverage/")
        else:
            print("HTML generation failed:")
            print(html_result.stderr)

        # Extract coverage percentage
        coverage_lines = report_result.stdout.split('\n')
        for line in coverage_lines:
            if 'core_analysis.py' in line:
                parts = line.split()
                if len(parts) >= 4:
                    coverage_pct = parts[-1]
                    print(f"\n=== COVERAGE RESULT ===")
                    print(f"Core Analysis Coverage: {coverage_pct}")

                    # Check if we met the 80% target
                    if coverage_pct.endswith('%'):
                        pct_val = float(coverage_pct[:-1])
                        if pct_val >= 80:
                            print("✓ TARGET MET: Coverage >= 80%")
                        else:
                            print(f"✗ TARGET NOT MET: Coverage {pct_val}% < 80%")
                    break

        return 0

    except Exception as e:
        print(f"Error running coverage analysis: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
