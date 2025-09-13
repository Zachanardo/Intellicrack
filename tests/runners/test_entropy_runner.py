#!/usr/bin/env python3
"""Test runner for entropy analyzer module to validate functionality and coverage."""

import sys
import os
sys.path.insert(0, os.path.abspath('.'))

import unittest
import coverage

# Start coverage measurement
cov = coverage.Coverage()
cov.start()

# Import and run tests
from tests.unit.core.analysis.test_entropy_analyzer import *

if __name__ == '__main__':
    # Run all tests
    unittest.main(argv=[''], exit=False, verbosity=2)

    # Stop coverage and generate report
    cov.stop()
    cov.save()

    print("\n" + "="*60)
    print("COVERAGE REPORT")
    print("="*60)

    # Show coverage for the entropy analyzer module
    cov.report(include=["intellicrack/core/analysis/entropy_analyzer.py"])

    # Get coverage percentage
    coverage_data = cov.get_data()
    files = coverage_data.measured_files()

    for filename in files:
        if "entropy_analyzer.py" in filename:
            lines = coverage_data.lines(filename)
            missing = coverage_data.missing_lines(filename)
            if lines:
                coverage_percent = ((len(lines) - len(missing)) / len(lines)) * 100
                print(f"\nOverall Coverage: {coverage_percent:.1f}%")
                if coverage_percent >= 90:
                    print("✅ COVERAGE TARGET ACHIEVED (90%+)")
                else:
                    print(f"❌ Coverage below target: {coverage_percent:.1f}% < 90%")
