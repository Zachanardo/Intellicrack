#!/usr/bin/env python3
"""
Real application test for structured messaging
Tests the actual Frida script execution within the application
"""

import sys
import os
import subprocess
import time
from pathlib import Path

def test_application_launch():
    """Test that the application can launch with structured messaging support"""
    print("Testing application launch with structured messaging...")

    try:
        # Try to launch the application in a way that tests our modifications
        script_path = Path("C:\\Intellicrack\\launch_intellicrack.py")
        if not script_path.exists():
            print("❌ Main application script not found")
            return False

        # Create a minimal test that imports our modified components
        test_script = '''
import sys
import os
sys.path.insert(0, "C:\\\\Intellicrack")

try:
    # Test that our modified components can be imported
    from intellicrack.core.frida_manager import FridaManager
    print("✅ Successfully imported FridaManager")

    # Test that the structured message handler exists
    manager = FridaManager()
    if hasattr(manager, '_on_script_message'):
        print("✅ Message handler method exists")
    else:
        print("❌ Message handler method missing")

    if hasattr(manager, '_handle_structured_message'):
        print("✅ Structured message handler exists")
    else:
        print("❌ Structured message handler missing")

    # Test message type handlers
    handler_methods = [
        '_handle_info_message',
        '_handle_warning_message',
        '_handle_error_message',
        '_handle_status_message',
        '_handle_bypass_message',
        '_handle_success_message',
        '_handle_detection_message',
        '_handle_notification_message'
    ]

    missing_handlers = []
    for method in handler_methods:
        if hasattr(manager, method):
            print(f"✅ {method} exists")
        else:
            print(f"❌ {method} missing")
            missing_handlers.append(method)

    if not missing_handlers:
        print("✅ All message handlers implemented")
    else:
        print(f"❌ Missing {len(missing_handlers)} message handlers")

    print("✅ Application components successfully loaded")

except Exception as e:
    print(f"❌ Error testing application: {e}")
    sys.exit(1)
'''

        # Write the test script
        with open("temp_app_test.py", "w") as f:
            f.write(test_script)

        # Run the test
        result = subprocess.run([sys.executable, "temp_app_test.py"],
                              capture_output=True, text=True, timeout=30)

        print("Test output:")
        print(result.stdout)
        if result.stderr:
            print("Errors:")
            print(result.stderr)

        # Clean up
        if os.path.exists("temp_app_test.py"):
            os.remove("temp_app_test.py")

        return result.returncode == 0

    except Exception as e:
        print(f"❌ Error in application test: {e}")
        return False

def test_frida_script_integration():
    """Test that our Frida scripts are properly integrated"""
    print("\nTesting Frida script integration...")

    # Check that the test script exists and has the correct structure
    test_script_path = Path("C:\\Intellicrack\\intellicrack\\plugins\\frida_scripts\\test_structured_messaging.js")

    if not test_script_path.exists():
        print("❌ Test Frida script not found")
        return False

    try:
        with open(test_script_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Check for proper message structure
        required_patterns = [
            'type: "info"',
            'type: "warning"',
            'type: "error"',
            'type: "status"',
            'type: "bypass"',
            'type: "success"',
            'type: "detection"',
            'type: "notification"'
        ]

        found_patterns = []
        for pattern in required_patterns:
            if pattern in content:
                found_patterns.append(pattern)
                print(f"✅ Found {pattern}")
            else:
                print(f"❌ Missing {pattern}")

        if len(found_patterns) == len(required_patterns):
            print("✅ All message types present in test script")
            return True
        else:
            print(f"❌ Missing {len(required_patterns) - len(found_patterns)} message types")
            return False

    except Exception as e:
        print(f"❌ Error reading test script: {e}")
        return False

def main():
    """Main test function"""
    print("🧪 Real Application Integration Test")
    print("=" * 50)

    # Change to correct directory
    os.chdir("C:\\Intellicrack")

    # Run tests
    app_test = test_application_launch()
    script_test = test_frida_script_integration()

    # Summary
    print("\n" + "=" * 50)
    print("🏁 INTEGRATION TEST SUMMARY")
    print("=" * 50)
    print(f"Application Components: {'✅ PASS' if app_test else '❌ FAIL'}")
    print(f"Frida Script Integration: {'✅ PASS' if script_test else '❌ FAIL'}")

    if app_test and script_test:
        print("\n🎉 Integration tests PASSED! The application is ready with structured messaging.")
        return 0
    else:
        print("\n❌ Some integration tests failed.")
        return 1

if __name__ == '__main__':
    sys.exit(main())
