#!/usr/bin/env python3
"""
Test runner script for BaseDetector coverage analysis.
This script runs the comprehensive test suite and generates coverage reports.
"""

import sys
import os
import subprocess
import importlib.util

def main():
    """Run BaseDetector tests with coverage analysis."""

    # Set up path for imports
    project_root = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, project_root)

    print("=== BaseDetector Test Coverage Analysis ===")
    print(f"Project root: {project_root}")
    print(f"Python version: {sys.version}")

    # Check if we can import the module
    try:
        spec = importlib.util.spec_from_file_location(
            "base_detector",
            os.path.join(project_root, "intellicrack", "core", "anti_analysis", "base_detector.py")
        )
        base_detector_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(base_detector_module)
        print("OK Successfully imported base_detector module")
    except Exception as e:
        print(f"FAIL Failed to import base_detector: {e}")
        return 1

    # Check if test file exists
    test_file = os.path.join(project_root, "tests", "unit", "core", "anti_analysis", "test_base_detector.py")
    if not os.path.exists(test_file):
        print(f"FAIL Test file not found: {test_file}")
        return 1

    print(f"OK Test file found: {test_file}")

    # Try to run tests with unittest
    print("\n=== Running Tests ===")
    try:
        import unittest

        # Load and run the test suite
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromName('tests.unit.core.anti_analysis.test_base_detector')

        # Run tests
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)

        print(f"\nTests run: {result.testsRun}")
        print(f"Failures: {len(result.failures)}")
        print(f"Errors: {len(result.errors)}")

        if result.failures:
            print("\nFailures:")
            for test, traceback in result.failures:
                print(f"  {test}: {traceback}")

        if result.errors:
            print("\nErrors:")
            for test, traceback in result.errors:
                print(f"  {test}: {traceback}")

    except Exception as e:
        print(f"Error running tests: {e}")
        import traceback
        traceback.print_exc()

    # Try to run coverage analysis
    print("\n=== Attempting Coverage Analysis ===")
    try:
        import coverage

        # Create coverage instance
        cov = coverage.Coverage(
            source=['intellicrack/core/anti_analysis/base_detector.py'],
            config_file=False
        )

        cov.start()

        # Import and run tests under coverage
        from tests.unit.core.anti_analysis.test_base_detector import TestBaseDetector, TestBaseDetectorIntegration

        loader = unittest.TestLoader()
        suite = unittest.TestSuite()

        # Load both test classes
        suite.addTests(loader.loadTestsFromTestCase(TestBaseDetector))
        suite.addTests(loader.loadTestsFromTestCase(TestBaseDetectorIntegration))

        runner = unittest.TextTestRunner(verbosity=1)
        result = runner.run(suite)

        cov.stop()
        cov.save()

        # Generate coverage report
        print("\n=== Coverage Report ===")
        cov.report(show_missing=True)

        # Get coverage percentage
        total_coverage = cov.report(show_missing=False)
        print(f"\nTotal Coverage: {total_coverage:.2f}%")

        if total_coverage >= 80:
            print("OK Coverage requirement met (80%+)")
        else:
            print("FAIL Coverage requirement not met (need 80%+)")

    except ImportError:
        print("Coverage module not available, skipping coverage analysis")
    except Exception as e:
        print(f"Error during coverage analysis: {e}")
        import traceback
        traceback.print_exc()

    print("\n=== Test Analysis Complete ===")
    return 0

if __name__ == '__main__':
    sys.exit(main())
