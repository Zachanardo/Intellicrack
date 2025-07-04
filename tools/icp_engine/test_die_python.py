#!/usr/bin/env python3
"""
Test script to verify die-python installation and functionality
"""

import sys
import os
from pathlib import Path

def test_die_python_import():
    """Test if die-python can be imported"""
    try:
        import die
        print("✓ die-python imported successfully")
        print(f"  Version: {die.__version__ if hasattr(die, '__version__') else 'Unknown'}")
        return True
    except ImportError as e:
        print(f"✗ Failed to import die-python: {e}")
        return False

def test_die_python_basic_functionality():
    """Test basic die-python functionality"""
    try:
        import die

        # Test creating a DIE instance
        die_instance = die.DIE()
        print("✓ DIE instance created successfully")

        # Test if we can get basic info
        if hasattr(die_instance, 'getVersion'):
            version = die_instance.getVersion()
            print(f"✓ DIE engine version: {version}")

        return True
    except Exception as e:
        print(f"✗ Failed basic functionality test: {e}")
        return False

def test_sample_analysis():
    """Test analysis on a sample file"""
    try:
        import die

        # Use one of the ICP engine executables as a test file
        test_file = Path(__file__).parent / "icp-engine.exe"
        if not test_file.exists():
            print("ℹ Sample file not found for analysis test")
            return True

        die_instance = die.DIE()

        # Test file analysis
        result = die_instance.scanFile(str(test_file))

        if result:
            print("✓ File analysis successful")
            print(f"  Detected {len(result)} entries")

            # Print first few detections
            for i, detection in enumerate(result[:3]):
                print(f"    {i+1}. {detection.name} ({detection.type})")
        else:
            print("ℹ No detections found (this is normal for some files)")

        return True
    except Exception as e:
        print(f"✗ Sample analysis failed: {e}")
        return False

def main():
    """Run all tests"""
    print("Testing die-python installation and functionality...\n")

    tests = [
        ("Import Test", test_die_python_import),
        ("Basic Functionality", test_die_python_basic_functionality),
        ("Sample Analysis", test_sample_analysis),
    ]

    passed = 0
    total = len(tests)

    for test_name, test_func in tests:
        print(f"Running {test_name}...")
        if test_func():
            passed += 1
        print()

    print(f"Results: {passed}/{total} tests passed")

    if passed == total:
        print("✓ All tests passed! die-python is ready for integration.")
        return True
    else:
        print(f"✗ {total - passed} tests failed. Check the output above.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)