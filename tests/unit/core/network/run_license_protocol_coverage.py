"""Coverage analysis runner for license protocol handler tests."""

import os
import sys
import subprocess
from pathlib import Path

def run_coverage_analysis():
    """Run coverage analysis for license protocol handler."""

    # Get the project root directory
    project_root = Path(__file__).parent.parent.parent.parent.parent
    os.chdir(project_root)

    # Target module for coverage
    target_module = "intellicrack.core.network.license_protocol_handler"

    # Test files
    test_files = [
        "tests/unit/core/network/test_license_protocol_handler.py",
        "tests/unit/core/network/test_license_protocol_exploitation.py"
    ]

    print("Running coverage analysis for license protocol handler...")
    print(f"Project root: {project_root}")
    print(f"Target module: {target_module}")
    print(f"Test files: {test_files}")

    # Run coverage
    try:
        cmd = [
            sys.executable, "-m", "coverage", "run",
            "--source", target_module,
            "--omit", "*/tests/*",
            "-m", "pytest"
        ] + test_files + ["-v", "--tb=short"]

        print(f"Running command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=project_root)

        print("STDOUT:")
        print(result.stdout)

        if result.stderr:
            print("STDERR:")
            print(result.stderr)

        # Generate coverage report
        print("\nGenerating coverage report...")
        report_cmd = [sys.executable, "-m", "coverage", "report", "--show-missing"]
        report_result = subprocess.run(report_cmd, capture_output=True, text=True, cwd=project_root)

        print("Coverage Report:")
        print(report_result.stdout)

        if report_result.stderr:
            print("Coverage Report Errors:")
            print(report_result.stderr)

        # Generate HTML report
        html_cmd = [sys.executable, "-m", "coverage", "html", "-d", "tests/coverage_html"]
        html_result = subprocess.run(html_cmd, capture_output=True, text=True, cwd=project_root)

        if html_result.returncode == 0:
            print(f"\nHTML coverage report generated in: {project_root}/tests/coverage_html")

        return result.returncode == 0 and report_result.returncode == 0

    except Exception as e:
        print(f"Error running coverage analysis: {e}")
        return False

def main():
    """Main function."""
    success = run_coverage_analysis()
    if success:
        print("\nOK Coverage analysis completed successfully")
    else:
        print("\nFAIL Coverage analysis failed")
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
