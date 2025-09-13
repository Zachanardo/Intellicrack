"""Quick syntax and import validation for cloud hooker tests."""
import sys
import os

# Add project to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    print("Checking test file syntax and imports...")

    # Import the test file
    import tests.unit.core.network.test_cloud_license_hooker as test_module

    print("✅ Test file imports successfully")

    # Check test classes exist
    assert hasattr(test_module, 'TestCloudLicenseResponseGenerator')
    assert hasattr(test_module, 'TestCloudLicenseHooker')
    assert hasattr(test_module, 'TestProductionReadiness')

    print("✅ All test classes found")

    # Count test methods
    test_classes = [
        test_module.TestCloudLicenseResponseGenerator,
        test_module.TestCloudLicenseHooker,
        test_module.TestProductionReadiness
    ]

    total_tests = 0
    for cls in test_classes:
        test_methods = [m for m in dir(cls) if m.startswith('test_')]
        total_tests += len(test_methods)
        print(f"✅ {cls.__name__}: {len(test_methods)} test methods")

    print(f"\n✅ Total test methods: {total_tests}")
    print("✅ Syntax validation PASSED")

    # Try to instantiate a test
    try:
        test_instance = test_module.TestCloudLicenseResponseGenerator()
        print("✅ Test class instantiation PASSED")
    except Exception as e:
        print(f"⚠️  Test instantiation issue: {e}")

    # Run the summary
    exec(open('cloud_hooker_test_summary.py').read())

except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
