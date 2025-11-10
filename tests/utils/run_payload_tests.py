#!/usr/bin/env python3
"""Simple test runner for payload_result_handler tests."""

import sys
import os

# Add the project root to the Python path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

# Import the module under test and the test class
from intellicrack.utils.exploitation.payload_result_handler import PayloadResultHandler
from tests.unit.utils.exploitation.test_payload_result_handler import TestPayloadResultHandler

def run_basic_test():
    """Run a basic test to verify functionality."""
    print("Testing PayloadResultHandler functionality...")

    # Create test instance
    test_instance = TestPayloadResultHandler()
    test_instance.setup_method()

    try:
        # Run minimal metadata test
        test_instance.test_successful_payload_processing_minimal_metadata()
        print("OK test_successful_payload_processing_minimal_metadata PASSED")

        # Run full metadata test
        test_instance.test_successful_payload_processing_full_metadata()
        print("OK test_successful_payload_processing_full_metadata PASSED")

        # Run failure test
        test_instance.test_failed_payload_with_error_message()
        print("OK test_failed_payload_with_error_message PASSED")

        # Run callback test
        test_instance.test_successful_payload_with_save_callback()
        print("OK test_successful_payload_with_save_callback PASSED")

        # Run edge case test
        test_instance.test_none_save_callback_handling()
        print("OK test_none_save_callback_handling PASSED")

        print("\n🎉 All basic tests PASSED!")
        return True

    except Exception as e:
        print(f"FAIL Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = run_basic_test()
    sys.exit(0 if success else 1)
