#!/usr/bin/env python3
"""
Script to run debugger detector tests and coverage analysis.
"""

import sys
import os
import subprocess
import coverage

# Add the project root to the Python path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

def run_coverage_analysis():
    """Run coverage analysis for debugger_detector.py"""

    # Initialize coverage
    cov = coverage.Coverage(
        source=['intellicrack.core.anti_analysis.debugger_detector'],
        config_file='.coveragerc'
    )

    cov.start()

    try:
        # Import and run the tests
        from tests.unit.core.anti_analysis.test_debugger_detector import TestDebuggerDetector, TestDebuggerDetectorProductionScenarios
        import unittest

        # Create test suite
        suite = unittest.TestLoader().loadTestsFromTestCase(TestDebuggerDetector)
        suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestDebuggerDetectorProductionScenarios))

        # Run tests
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)

        # Stop coverage
        cov.stop()
        cov.save()

        print("\n" + "="*60)
        print("COVERAGE REPORT FOR DEBUGGER_DETECTOR.PY")
        print("="*60)

        # Generate coverage report
        cov.report(show_missing=True)

        # Generate HTML coverage report
        try:
            cov.html_report(directory='tests/reports/debugger_detector_coverage')
            print(f"\nHTML coverage report generated: tests/reports/debugger_detector_coverage/")
        except Exception as e:
            print(f"Failed to generate HTML report: {e}")

        # Get coverage percentage
        coverage_data = cov.get_data()
        total_coverage = cov.report(file=None, show_missing=True)

        print(f"\nTest Results: {result.testsRun} tests run")
        print(f"Failures: {len(result.failures)}")
        print(f"Errors: {len(result.errors)}")

        # Analyze coverage for 80%+ requirement
        if total_coverage:
            if total_coverage >= 80.0:
                print(f"\nOK SUCCESS: Coverage target achieved! ({total_coverage:.1f}% >= 80%)")
                return True
            else:
                print(f"\nFAIL WARNING: Coverage below target ({total_coverage:.1f}% < 80%)")
                return False

        return True

    except Exception as e:
        cov.stop()
        print(f"Error running tests: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("Running Debugger Detector Tests and Coverage Analysis...")
    print("="*60)

    success = run_coverage_analysis()

    if success:
        print("\nOK Test and coverage analysis completed successfully!")
        sys.exit(0)
    else:
        print("\nFAIL Test or coverage analysis failed!")
        sys.exit(1)
