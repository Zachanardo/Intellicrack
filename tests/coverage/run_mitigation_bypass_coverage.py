#!/usr/bin/env python
"""
Comprehensive coverage check for all mitigation bypass modules.
This script runs all tests and generates a detailed coverage report.
"""

import sys
import os
import subprocess
import json
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.insert(0, r'C:\Intellicrack')

def run_coverage_check():
    """Run comprehensive coverage analysis for mitigation bypass modules."""

    print("=" * 80)
    print("INTELLICRACK MITIGATION BYPASS MODULE COVERAGE ANALYSIS")
    print("=" * 80)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    # Define test files and their corresponding modules
    test_mapping = {
        'test_aslr_bypass.py': 'intellicrack.core.mitigation_bypass.aslr_bypass',
        'test_bypass_base.py': 'intellicrack.core.mitigation_bypass.bypass_base',
        'test_bypass_engine.py': 'intellicrack.core.mitigation_bypass.bypass_engine',
        'test_cfi_bypass.py': 'intellicrack.core.mitigation_bypass.cfi_bypass',
        'test_dep_bypass.py': 'intellicrack.core.mitigation_bypass.dep_bypass'
    }

    test_dir = Path(r'C:\Intellicrack\tests\unit\core\mitigation_bypass')

    # Check which test files exist
    existing_tests = []
    missing_tests = []

    for test_file in test_mapping.keys():
        test_path = test_dir / test_file
        if test_path.exists():
            existing_tests.append(test_file)
            print(f"✅ Found: {test_file}")
        else:
            missing_tests.append(test_file)
            print(f"❌ Missing: {test_file}")

    print()
    print(f"Test files found: {len(existing_tests)}/{len(test_mapping)}")

    if missing_tests:
        print(f"Warning: Some test files are missing: {', '.join(missing_tests)}")

    print()
    print("Running coverage analysis...")
    print("-" * 40)

    # Prepare coverage command
    coverage_cmd = [
        sys.executable, '-m', 'coverage', 'run',
        '--source=intellicrack.core.mitigation_bypass',
        '--omit=*/tests/*,*/__init__.py',
        '-m', 'pytest'
    ]

    # Add test paths
    test_paths = [str(test_dir / test_file) for test_file in existing_tests]
    coverage_cmd.extend(test_paths)

    # Add pytest options
    coverage_cmd.extend([
        '-v',
        '--tb=short',
        '--no-header',
        '--disable-warnings'
    ])

    try:
        # Run tests with coverage
        print("Executing tests with coverage...")
        result = subprocess.run(
            coverage_cmd,
            cwd=r'C:\Intellicrack',
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            print(f"⚠️  Some tests failed (exit code: {result.returncode})")
            print("STDERR:", result.stderr[:500] if result.stderr else "None")

        # Generate coverage report
        print()
        print("Generating coverage report...")
        print("-" * 40)

        # Text report
        report_cmd = [sys.executable, '-m', 'coverage', 'report', '--show-missing']
        report_result = subprocess.run(
            report_cmd,
            cwd=r'C:\Intellicrack',
            capture_output=True,
            text=True
        )

        print(report_result.stdout)

        # Parse coverage percentage
        coverage_lines = report_result.stdout.split('\n')
        for line in coverage_lines:
            if 'TOTAL' in line:
                parts = line.split()
                if len(parts) >= 4:
                    coverage_percent = parts[-1].rstrip('%')
                    try:
                        coverage_value = float(coverage_percent)
                        print()
                        print("=" * 80)
                        print(f"OVERALL COVERAGE: {coverage_value}%")

                        if coverage_value >= 80:
                            print("✅ TARGET ACHIEVED: Coverage exceeds 80% requirement!")
                        else:
                            print(f"⚠️  Coverage ({coverage_value}%) is below 80% target")
                        print("=" * 80)
                    except ValueError:
                        print("Could not parse coverage percentage")

        # Generate HTML report
        html_cmd = [sys.executable, '-m', 'coverage', 'html', '-d', 'htmlcov_mitigation']
        subprocess.run(html_cmd, cwd=r'C:\Intellicrack', capture_output=True)
        print()
        print("📊 HTML coverage report generated in: htmlcov_mitigation/")

        # Generate JSON report for detailed analysis
        json_cmd = [sys.executable, '-m', 'coverage', 'json', '-o', 'coverage_mitigation.json']
        subprocess.run(json_cmd, cwd=r'C:\Intellicrack', capture_output=True)

        # Analyze JSON for per-module coverage
        json_path = Path(r'C:\Intellicrack\coverage_mitigation.json')
        if json_path.exists():
            with open(json_path, 'r') as f:
                coverage_data = json.load(f)

            print()
            print("Per-Module Coverage Breakdown:")
            print("-" * 40)

            for module in test_mapping.values():
                module_files = [f for f in coverage_data.get('files', {})
                              if module.replace('.', '/') in f.replace('\\', '/')]

                if module_files:
                    total_lines = 0
                    covered_lines = 0

                    for file_path in module_files:
                        file_data = coverage_data['files'][file_path]
                        total_lines += file_data['summary']['num_statements']
                        covered_lines += file_data['summary']['covered_lines']

                    if total_lines > 0:
                        module_coverage = (covered_lines / total_lines) * 100
                        status = "✅" if module_coverage >= 80 else "⚠️"
                        print(f"{status} {module}: {module_coverage:.1f}%")

        print()
        print("Coverage analysis complete!")
        print(f"Finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    except FileNotFoundError as e:
        print(f"Error: Required tool not found - {e}")
        print("Please ensure pytest and coverage are installed:")
        print("  pip install pytest coverage")
    except Exception as e:
        print(f"Error during coverage analysis: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    # Ensure we're in the right environment
    python_path = sys.executable
    if 'mamba_env' not in python_path:
        print("⚠️  Warning: Not running in mamba_env")
        print(f"Current Python: {python_path}")
        print("Switching to mamba_env...")

        mamba_python = r'C:\Intellicrack\mamba_env\python.exe'
        if Path(mamba_python).exists():
            subprocess.run([mamba_python, __file__])
            sys.exit(0)

    run_coverage_check()
