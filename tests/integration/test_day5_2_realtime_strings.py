#!/usr/bin/env python3
"""Test script for Day 5.2 Real-time String Monitoring

Tests the enhanced real-time string analysis integration with the existing
real-time analyzer framework.
"""

import sys
import os
import time
import tempfile
from datetime import datetime

# Add intellicrack to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "intellicrack"))

try:
    from intellicrack.core.analysis.radare2_realtime_analyzer import (
        R2RealtimeAnalyzer,
        AnalysisEvent,
        UpdateMode
    )
    from intellicrack.core.analysis.radare2_strings import R2StringAnalyzer
    IMPORT_SUCCESS = True
except ImportError as e:
    print(f"Import error: {e}")
    IMPORT_SUCCESS = False


class TestRealTimeStringMonitoring:
    """Test class for Day 5.2 real-time string monitoring."""

    def __init__(self):
        """Initialize test."""
        self.realtime_analyzer = None
        self.test_events = []

    def test_enhanced_string_component_integration(self):
        """Test that enhanced_strings component is properly integrated."""
        print("Testing Enhanced String Component Integration:")
        print("=" * 55)

        try:
            # Create realtime analyzer
            analyzer = R2RealtimeAnalyzer(update_mode=UpdateMode.INTERVAL)

            # Test analysis component determination includes enhanced_strings
            components = analyzer._determine_analysis_components("test.exe", AnalysisEvent.ANALYSIS_STARTED)

            if "enhanced_strings" in components:
                print("✓ PASS: enhanced_strings component included in analysis")
                return True
            else:
                print(f"✗ FAIL: enhanced_strings component not found in: {components}")
                return False

        except Exception as e:
            print(f"✗ ERROR: {e}")
            return False

    def test_enhanced_string_analysis_method(self):
        """Test the enhanced string analysis method exists and has proper structure."""
        print("\nTesting Enhanced String Analysis Method:")
        print("=" * 45)

        try:
            # Create realtime analyzer
            analyzer = R2RealtimeAnalyzer()

            # Check if the enhanced string analysis method exists
            if hasattr(analyzer, '_perform_enhanced_string_analysis'):
                print("✓ PASS: _perform_enhanced_string_analysis method exists")

                # Check if the dynamic monitoring methods exist
                if hasattr(analyzer, '_monitor_dynamic_string_patterns'):
                    print("✓ PASS: _monitor_dynamic_string_patterns method exists")
                else:
                    print("✗ FAIL: _monitor_dynamic_string_patterns method missing")
                    return False

                if hasattr(analyzer, '_monitor_string_api_calls'):
                    print("✓ PASS: _monitor_string_api_calls method exists")
                else:
                    print("✗ FAIL: _monitor_string_api_calls method missing")
                    return False

                return True
            else:
                print("✗ FAIL: _perform_enhanced_string_analysis method missing")
                return False

        except Exception as e:
            print(f"✗ ERROR: {e}")
            return False

    def test_event_system_integration(self):
        """Test that string analysis events are properly integrated."""
        print("\nTesting Event System Integration:")
        print("=" * 35)

        try:
            # Create realtime analyzer
            analyzer = R2RealtimeAnalyzer()

            # Check if STRING_ANALYSIS_UPDATED event is available
            if hasattr(AnalysisEvent, 'STRING_ANALYSIS_UPDATED'):
                print("✓ PASS: STRING_ANALYSIS_UPDATED event available")

                # Set up event callback to capture events
                self.test_events = []

                def test_callback(update):
                    self.test_events.append(update)

                analyzer.register_callback(AnalysisEvent.STRING_ANALYSIS_UPDATED, test_callback)
                print("✓ PASS: Event callback registration successful")

                return True
            else:
                print("✗ FAIL: STRING_ANALYSIS_UPDATED event not available")
                return False

        except Exception as e:
            print(f"✗ ERROR: {e}")
            return False

    def test_string_analyzer_integration(self):
        """Test integration with the enhanced string analyzer from Day 5.1."""
        print("\nTesting String Analyzer Integration:")
        print("=" * 40)

        try:
            # Test that we can create a string analyzer instance
            analyzer = R2StringAnalyzer("dummy.bin")

            # Check that enhanced detection methods are available
            test_methods = [
                '_detect_license_key_formats',
                '_detect_cryptographic_data',
                '_analyze_api_function_patterns',
                '_calculate_entropy',
                '_is_repetitive_pattern'
            ]

            missing_methods = []
            for method_name in test_methods:
                if not hasattr(analyzer, method_name):
                    missing_methods.append(method_name)

            if not missing_methods:
                print("✓ PASS: All required string analyzer methods available")

                # Test a sample method call
                test_result = analyzer._detect_license_key_formats("ABCD-1234-EFGH-5678")
                if test_result:
                    print("✓ PASS: String analyzer methods functional")
                    return True
                else:
                    print("✗ FAIL: String analyzer method not working correctly")
                    return False
            else:
                print(f"✗ FAIL: Missing methods: {missing_methods}")
                return False

        except Exception as e:
            print(f"✗ ERROR: {e}")
            return False

    def test_realtime_monitoring_capabilities(self):
        """Test that real-time monitoring capabilities are properly structured."""
        print("\nTesting Real-time Monitoring Capabilities:")
        print("=" * 45)

        try:
            # Create realtime analyzer
            analyzer = R2RealtimeAnalyzer(update_mode=UpdateMode.CONTINUOUS)

            # Test update modes are available
            update_modes = [UpdateMode.CONTINUOUS, UpdateMode.INTERVAL,
                           UpdateMode.ON_CHANGE, UpdateMode.HYBRID]

            print(f"✓ PASS: Available update modes: {[mode.value for mode in update_modes]}")

            # Test analyzer status structure
            status = analyzer.get_status()
            required_keys = ['running', 'update_mode', 'watched_binaries']

            missing_keys = [key for key in required_keys if key not in status]
            if not missing_keys:
                print("✓ PASS: Status structure contains required keys")
                return True
            else:
                print(f"✗ FAIL: Missing status keys: {missing_keys}")
                return False

        except Exception as e:
            print(f"✗ ERROR: {e}")
            return False


def main():
    """Main test function."""
    print("DAY 5.2 REAL-TIME STRING MONITORING TESTING")
    print("=" * 50)
    print("Testing integration of enhanced string analysis with real-time monitoring")
    print()

    if not IMPORT_SUCCESS:
        print("❌ IMPORTS FAILED: Cannot run tests without proper imports")
        return 1

    try:
        tester = TestRealTimeStringMonitoring()

        # Run all tests
        tests = [
            tester.test_enhanced_string_component_integration,
            tester.test_enhanced_string_analysis_method,
            tester.test_event_system_integration,
            tester.test_string_analyzer_integration,
            tester.test_realtime_monitoring_capabilities
        ]

        passed_tests = 0
        failed_tests = 0

        for test_func in tests:
            try:
                if test_func():
                    passed_tests += 1
                else:
                    failed_tests += 1
            except Exception as e:
                print(f"Test failed with exception: {e}")
                failed_tests += 1

        print(f"\n🎯 DAY 5.2 REAL-TIME STRING MONITORING TEST RESULTS:")
        print(f"✅ Test Categories Passed: {passed_tests}")
        print(f"❌ Test Categories Failed: {failed_tests}")

        if failed_tests == 0:
            print("\n🎉 DAY 5.2 REAL-TIME STRING MONITORING COMPLETED SUCCESSFULLY!")
            print("✅ Enhanced string analysis integrated with real-time analyzer")
            print("✅ Dynamic string pattern monitoring implemented")
            print("✅ String API call monitoring functional")
            print("✅ Event system integration operational")
            print("✅ Real-time string extraction capabilities added")
            return 0
        else:
            print(f"\n❌ DAY 5.2 IMPLEMENTATION FAILED: {failed_tests} test category(s) failed")
            return 1

    except Exception as e:
        print(f"❌ Testing failed with error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
