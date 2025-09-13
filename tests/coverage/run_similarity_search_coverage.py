#!/usr/bin/env python3
"""
Coverage analysis runner for binary_similarity_search tests.
"""

import subprocess
import sys
import os
from pathlib import Path

def run_coverage_analysis():
    """Run coverage analysis for binary_similarity_search module."""

    # Change to project root
    project_root = Path(__file__).parent
    os.chdir(project_root)

    print("=== Binary Similarity Search Coverage Analysis ===")
    print(f"Working directory: {os.getcwd()}")

    # Test file path
    test_file = "tests/unit/core/analysis/test_binary_similarity_search.py"
    source_module = "intellicrack.core.analysis.binary_similarity_search"

    if not Path(test_file).exists():
        print(f"ERROR: Test file {test_file} not found!")
        return False

    print(f"Running tests for: {test_file}")
    print(f"Source module: {source_module}")

    try:
        # Run coverage with pytest
        coverage_cmd = [
            sys.executable, "-m", "coverage", "run",
            "--source", source_module,
            "--branch",  # Include branch coverage
            "-m", "pytest",
            test_file,
            "-v", "--tb=short"
        ]

        print(f"Executing: {' '.join(coverage_cmd)}")
        result = subprocess.run(coverage_cmd, capture_output=True, text=True, timeout=300)

        print("=== Test Execution Output ===")
        print("STDOUT:")
        print(result.stdout)

        if result.stderr:
            print("STDERR:")
            print(result.stderr)

        if result.returncode != 0:
            print(f"WARNING: Tests failed with return code {result.returncode}")
            print("Attempting to generate coverage report anyway...")

        # Generate coverage report
        print("\n=== Coverage Report ===")
        report_cmd = [sys.executable, "-m", "coverage", "report", "--show-missing"]

        report_result = subprocess.run(report_cmd, capture_output=True, text=True)

        print(report_result.stdout)
        if report_result.stderr:
            print("Coverage STDERR:")
            print(report_result.stderr)

        # Generate detailed HTML report
        html_cmd = [sys.executable, "-m", "coverage", "html", "-d", "htmlcov_similarity_search"]
        subprocess.run(html_cmd, capture_output=True)

        print(f"\nDetailed HTML coverage report generated in: htmlcov_similarity_search/")

        # Parse coverage percentage from report
        report_lines = report_result.stdout.split('\n')
        for line in report_lines:
            if source_module in line:
                parts = line.split()
                if len(parts) >= 4:
                    coverage_pct = parts[3].rstrip('%')
                    try:
                        coverage_float = float(coverage_pct)
                        print(f"\n=== COVERAGE RESULT ===")
                        print(f"Module: {source_module}")
                        print(f"Coverage: {coverage_pct}%")

                        if coverage_float >= 80.0:
                            print("✅ COVERAGE TARGET MET: >= 80%")
                            return True
                        else:
                            print("❌ COVERAGE TARGET NOT MET: < 80%")
                            print(f"Need {80.0 - coverage_float:.1f}% more coverage")
                            return False
                    except ValueError:
                        print(f"Could not parse coverage percentage: {coverage_pct}")

        print("\nCould not determine coverage percentage from report")
        return False

    except subprocess.TimeoutExpired:
        print("ERROR: Coverage analysis timed out after 300 seconds")
        return False
    except Exception as e:
        print(f"ERROR: Coverage analysis failed: {e}")
        return False

if __name__ == "__main__":
    success = run_coverage_analysis()
    sys.exit(0 if success else 1)
