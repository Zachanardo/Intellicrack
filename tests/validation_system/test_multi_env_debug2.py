#!/usr/bin/env python3
"""Debug test for multi-environment tester initialization."""

import sys
sys.path.insert(0, r'C:\Intellicrack')

print("Starting test...")

try:
    from tests.validation_system.multi_environment_tester import MultiEnvironmentTester
    print("MultiEnvironmentTester imported")

    print("\nCreating MultiEnvironmentTester...")
    print("  Path: C:\\Intellicrack\\tests\\validation_system")

    # Try creating the tester
    tester = MultiEnvironmentTester(r"C:\Intellicrack\tests\validation_system")
    print("MultiEnvironmentTester created successfully!")

    print(f"\nEnvironments loaded: {len(tester.environments)}")
    print(f"Test suite loaded: {len(tester.test_suite)}")

    # Show first environment
    if tester.environments:
        env = tester.environments[0]
        print(f"\nFirst environment: {env.name}")
        print(f"  Type: {env.environment_type}")
        print(f"  OS: {env.platform_os}")

except Exception as e:
    print(f"\nError occurred: {e}")
    import traceback
    traceback.print_exc()

print("\nTest complete!")
