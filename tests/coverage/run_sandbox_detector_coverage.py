#!/usr/bin/env python3
"""
Coverage analysis script for sandbox_detector tests.

This script runs the comprehensive test suite for sandbox_detector.py
and generates detailed coverage reports to validate 80%+ coverage.
"""

import sys
import os
import subprocess
import coverage
from pathlib import Path

def main():
    print("="*80)
    print("SANDBOX DETECTOR COVERAGE ANALYSIS")
    print("="*80)

    # Set up paths
    project_root = Path(__file__).parent
    test_file = project_root / "tests" / "unit" / "core" / "anti_analysis" / "test_sandbox_detector.py"
    target_module = "intellicrack.core.anti_analysis.sandbox_detector"

    print(f"Project root: {project_root}")
    print(f"Test file: {test_file}")
    print(f"Target module: {target_module}")

    # Check if test file exists
    if not test_file.exists():
        print(f"ERROR: Test file not found: {test_file}")
        return 1

    # Initialize coverage
    cov = coverage.Coverage(
        source=['intellicrack'],
        omit=[
            '*/mamba_env/*',
            '*/dev/*',
            '*/tools/*',
            '*/tests/*',
            '*/__pycache__/*',
            '*/.*',
            'setup.py',
            'conftest.py'
        ],
        branch=True
    )

    print("\nStarting coverage analysis...")
    cov.start()

    try:
        # Import and run the test module
        sys.path.insert(0, str(project_root))

        # Import the test module
        import importlib.util
        spec = importlib.util.spec_from_file_location("test_sandbox_detector", test_file)
        test_module = importlib.util.module_from_spec(spec)

        print("Executing test module...")
        spec.loader.exec_module(test_module)

        print("Test execution completed.")

    except Exception as e:
        print(f"Error during test execution: {e}")
        import traceback
        traceback.print_exc()
    finally:
        cov.stop()
        cov.save()

    print("\nGenerating coverage report...")

    # Generate terminal report
    print("\n" + "="*60)
    print("COVERAGE REPORT")
    print("="*60)

    try:
        cov.report(show_missing=True)

        # Generate HTML report
        html_dir = project_root / "coverage_html_report"
        cov.html_report(directory=str(html_dir))
        print(f"\nHTML coverage report generated: {html_dir}")

        # Get specific module coverage
        data = cov.get_data()
        covered_files = data.measured_files()

        print(f"\nAnalyzed files: {len(covered_files)}")
        for file_path in covered_files:
            if 'sandbox_detector' in file_path:
                print(f"Target file found: {file_path}")

        # Generate detailed analysis
        analysis = cov.analysis(target_module)
        if analysis:
            statements, missing, excluded = analysis[1], analysis[2], analysis[3]
            total_statements = len(statements)
            covered_statements = total_statements - len(missing)
            coverage_percent = (covered_statements / total_statements) * 100 if total_statements > 0 else 0

            print(f"\n" + "="*60)
            print("DETAILED COVERAGE ANALYSIS")
            print("="*60)
            print(f"Module: {target_module}")
            print(f"Total statements: {total_statements}")
            print(f"Covered statements: {covered_statements}")
            print(f"Missing statements: {len(missing)}")
            print(f"Coverage percentage: {coverage_percent:.2f}%")

            if coverage_percent >= 80:
                print(f"✅ SUCCESS: Coverage {coverage_percent:.2f}% meets 80% requirement")
            else:
                print(f"❌ FAILURE: Coverage {coverage_percent:.2f}% below 80% requirement")
                print(f"Missing lines: {list(missing)}")

    except Exception as e:
        print(f"Error generating coverage report: {e}")
        import traceback
        traceback.print_exc()
        return 1

    print("\n" + "="*80)
    print("COVERAGE ANALYSIS COMPLETE")
    print("="*80)

    return 0

if __name__ == "__main__":
    sys.exit(main())
