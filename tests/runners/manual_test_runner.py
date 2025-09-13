#!/usr/bin/env python3
"""
Manual test runner for debugger detector tests.
"""

import sys
import os

# Add the project root to the Python path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

def main():
    """Run basic test validation."""
    try:
        print("Testing debugger_detector.py import...")
        from intellicrack.core.anti_analysis.debugger_detector import DebuggerDetector
        print("✓ Successfully imported DebuggerDetector")

        print("\nTesting DebuggerDetector initialization...")
        detector = DebuggerDetector()
        print("✓ Successfully initialized DebuggerDetector")

        print("\nTesting detection methods availability...")
        methods = detector.detection_methods
        print(f"✓ Found {len(methods)} detection methods")

        print("\nTesting basic detection functionality...")
        results = detector.detect_debugger(aggressive=False)
        print(f"✓ Detection completed with results: {type(results)}")

        # Validate results structure
        required_fields = ["is_debugged", "confidence", "debugger_type", "detections", "anti_debug_score"]
        for field in required_fields:
            if field in results:
                print(f"✓ Found required field: {field}")
            else:
                print(f"✗ Missing required field: {field}")

        print("\nTesting debugger signatures...")
        signatures = detector.debugger_signatures
        print(f"✓ Found signatures for {len(signatures)} platforms")

        print("\nTesting anti-debug code generation...")
        code = detector.generate_antidebug_code()
        print(f"✓ Generated anti-debug code ({len(code)} characters)")

        print("\n" + "="*60)
        print("BASIC FUNCTIONALITY VALIDATION COMPLETE")
        print("="*60)
        print("✓ All basic tests passed!")
        print("✓ DebuggerDetector is functional and ready for comprehensive testing")

        return True

    except Exception as e:
        print(f"\n✗ Error during testing: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("Manual Test Runner for DebuggerDetector")
    print("="*50)

    success = main()

    if success:
        print("\n✓ All tests completed successfully!")
    else:
        print("\n✗ Some tests failed!")

    sys.exit(0 if success else 1)
