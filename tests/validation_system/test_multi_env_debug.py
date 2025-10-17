#!/usr/bin/env python3
"""Debug test for multi-environment tester."""

import sys
sys.path.insert(0, r'D:\Intellicrack')

print("Starting imports...")

try:
    from tests.validation_system.multi_environment_tester import EnvironmentDetector
    print("EnvironmentDetector imported")
except Exception as e:
    print(f"Failed to import EnvironmentDetector: {e}")
    import traceback
    traceback.print_exc()

try:
    from tests.validation_system.multi_environment_tester import TestEnvironment
    print("TestEnvironment imported")
except Exception as e:
    print(f"Failed to import TestEnvironment: {e}")

try:
    from tests.validation_system.multi_environment_tester import MultiEnvironmentTester
    print("MultiEnvironmentTester imported")
except Exception as e:
    print(f"Failed to import MultiEnvironmentTester: {e}")
    import traceback
    traceback.print_exc()

print("All imports completed")

try:
    print("\nCreating EnvironmentDetector...")
    detector = EnvironmentDetector()
    print("EnvironmentDetector created")

    print("\nTesting container detection...")
    container_info = detector.detect_container()
    print(f"Container: {container_info}")

except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()

print("\nTest complete!")
