#!/usr/bin/env python3
"""
Execute test analysis scripts and generate reports.
"""

import sys
import os
import subprocess

def execute_script(script_path):
    """Execute a Python script and capture output."""

    try:
        # Execute the script directly
        result = subprocess.run([sys.executable, script_path],
                              capture_output=True,
                              text=True,
                              cwd=os.path.dirname(script_path))

        print(f"\n{'='*60}")
        print(f"Executing: {os.path.basename(script_path)}")
        print(f"{'='*60}")

        if result.stdout:
            print("STDOUT:")
            print(result.stdout)

        if result.stderr:
            print("STDERR:")
            print(result.stderr)

        print(f"Return code: {result.returncode}")

        return result.returncode == 0

    except Exception as e:
        print(f"Error executing {script_path}: {e}")
        return False

def main():
    """Execute all analysis scripts."""

    project_root = os.path.dirname(os.path.abspath(__file__))

    scripts = [
        os.path.join(project_root, "validate_base_detector_tests.py"),
        os.path.join(project_root, "test_coverage_report.py")
    ]

    print("BaseDetector Test Suite Analysis")
    print("=" * 80)

    results = {}

    for script in scripts:
        if os.path.exists(script):
            success = execute_script(script)
            results[script] = success
        else:
            print(f"Script not found: {script}")
            results[script] = False

    print("\n" + "=" * 80)
    print("ANALYSIS SUMMARY")
    print("=" * 80)

    for script, success in results.items():
        status = "✓ SUCCESS" if success else "✗ FAILED"
        print(f"{status}: {os.path.basename(script)}")

    overall_success = all(results.values())
    if overall_success:
        print("\n✓ All analysis scripts completed successfully")
    else:
        print("\n⚠ Some analysis scripts encountered issues")

    return 0 if overall_success else 1

if __name__ == '__main__':
    sys.exit(main())
