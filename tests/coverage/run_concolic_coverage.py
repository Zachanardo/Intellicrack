#!/usr/bin/env python3
"""
Coverage analysis script for concolic_executor_fixed.py module.
Runs comprehensive test suite and generates detailed coverage report.
"""

import subprocess
import sys
import os
from pathlib import Path


def run_coverage_analysis():
    """Run coverage analysis for concolic_executor_fixed module."""

    print("=== CONCOLIC EXECUTOR FIXED COVERAGE ANALYSIS ===")
    print("Module: intellicrack.core.analysis.concolic_executor_fixed")
    print("Test Target: 80%+ line coverage")
    print("=" * 60)

    # Set environment
    os.chdir(Path(__file__).parent)

    # Command to run coverage
    cmd = [
        sys.executable, "-m", "pytest",
        "tests/unit/core/analysis/test_concolic_executor_fixed.py",
        "--cov=intellicrack.core.analysis.concolic_executor_fixed",
        "--cov-report=term-missing",
        "--cov-report=html:coverage_html_concolic",
        "--cov-fail-under=80",
        "-v",
        "--tb=short"
    ]

    try:
        print(f"Running command: {' '.join(cmd)}")
        print("-" * 60)

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        print("STDOUT:")
        print(result.stdout)

        if result.stderr:
            print("\nSTDERR:")
            print(result.stderr)

        print(f"\nReturn code: {result.returncode}")

        if result.returncode == 0:
            print("\n✅ COVERAGE ANALYSIS SUCCESSFUL!")
            print("✅ 80%+ coverage target ACHIEVED")
        else:
            print("\n❌ Coverage analysis failed or below target")

    except subprocess.TimeoutExpired:
        print("❌ Coverage analysis timed out")
    except Exception as e:
        print(f"❌ Error running coverage: {e}")

    # Try basic test run if coverage fails
    print("\n" + "=" * 60)
    print("ATTEMPTING BASIC TEST RUN...")

    basic_cmd = [
        sys.executable, "-m", "pytest",
        "tests/unit/core/analysis/test_concolic_executor_fixed.py",
        "-v", "--tb=short", "-x"
    ]

    try:
        basic_result = subprocess.run(basic_cmd, capture_output=True, text=True, timeout=180)

        print(f"Basic test result: {basic_result.returncode}")
        if basic_result.stdout:
            print("Basic test output:")
            print(basic_result.stdout[-1000:])  # Last 1000 chars

    except Exception as e:
        print(f"Basic test failed: {e}")


if __name__ == "__main__":
    run_coverage_analysis()
