#!/usr/bin/env python3
"""
Coverage Analysis Runner for Timing Attacks Testing
Validates 80%+ coverage for timing_attacks.py module.
"""

import os
import sys
import subprocess
import json
from pathlib import Path
from datetime import datetime


def setup_environment():
    """Set up testing environment and paths."""
    project_root = Path(__file__).parent

    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    os.environ['PYTHONPATH'] = str(project_root)
    os.environ['INTELLICRACK_TEST_MODE'] = '1'

    return project_root


def run_coverage_analysis(project_root):
    """Run coverage analysis on timing attacks tests."""
    print("=== TIMING ATTACKS COVERAGE ANALYSIS ===")
    print("Testing Agent Mission: Validate 80%+ coverage achievement")
    print("Target Module: intellicrack.core.anti_analysis.timing_attacks")
    print()

    # Test file to run
    test_file = 'tests/unit/core/anti_analysis/test_timing_attacks.py'

    # Source module to analyze
    source_module = 'intellicrack/core/anti_analysis/timing_attacks.py'

    # Create reports directory
    reports_dir = project_root / 'tests' / 'reports'
    reports_dir.mkdir(exist_ok=True)

    # Run coverage analysis
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    coverage_file = reports_dir / f'timing_attacks_coverage_{timestamp}.txt'

    try:
        print("Running timing attacks tests with coverage...")

        # Run pytest with coverage
        cmd = [
            sys.executable, '-m', 'pytest',
            test_file,
            '--cov=' + source_module.replace('/', '.').replace('.py', ''),
            '--cov-report=term-missing',
            '--cov-report=html:tests/reports/timing_attacks_htmlcov',
            '-v'
        ]

        print(f"Command: {' '.join(cmd)}")
        print()

        # Change to project root
        os.chdir(project_root)

        # Run the command
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        # Print results
        print("STDOUT:")
        print(result.stdout)
        print()
        print("STDERR:")
        print(result.stderr)

        # Save coverage report
        with open(coverage_file, 'w') as f:
            f.write(f"Timing Attacks Coverage Report - {timestamp}\n")
            f.write("=" * 50 + "\n\n")
            f.write("STDOUT:\n")
            f.write(result.stdout)
            f.write("\n\nSTDERR:\n")
            f.write(result.stderr)
            f.write(f"\n\nReturn code: {result.returncode}\n")

        # Analyze coverage percentage
        lines = result.stdout.split('\n')
        coverage_line = None
        for line in lines:
            if 'timing_attacks' in line and '%' in line:
                coverage_line = line
                break

        if coverage_line:
            print(f"\nCOVERAGE ANALYSIS:")
            print(f"Found coverage line: {coverage_line}")

            # Extract percentage
            import re
            percentage_match = re.search(r'(\d+)%', coverage_line)
            if percentage_match:
                coverage_pct = int(percentage_match.group(1))
                print(f"Coverage percentage: {coverage_pct}%")

                if coverage_pct >= 80:
                    print("✅ SUCCESS: 80%+ coverage requirement MET!")
                else:
                    print(f"❌ REQUIREMENT NOT MET: {coverage_pct}% < 80%")
                    print("Additional tests may be needed for edge cases.")
            else:
                print("Could not extract coverage percentage from output")
        else:
            print("Coverage line not found in output")

        print(f"\nDetailed report saved to: {coverage_file}")

        return result.returncode == 0

    except subprocess.TimeoutExpired:
        print("❌ Test execution timed out after 5 minutes")
        return False
    except Exception as e:
        print(f"❌ Error running coverage analysis: {e}")
        return False


def main():
    """Main execution."""
    try:
        project_root = setup_environment()
        success = run_coverage_analysis(project_root)

        if success:
            print("\n🎉 Coverage analysis completed successfully!")
        else:
            print("\n💥 Coverage analysis encountered issues")

        return 0 if success else 1

    except Exception as e:
        print(f"Fatal error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
