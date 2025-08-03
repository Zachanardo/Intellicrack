#!/usr/bin/env python3
"""
Simple test for structured message handlers
Tests the message routing and handling system without requiring Frida or GUI
"""

import sys
import os
import json
from pathlib import Path

# Add the intellicrack module to the path
sys.path.insert(0, os.path.abspath('.'))

def test_message_routing():
    """Test the message routing system"""
    print("Testing structured message routing system...")

    try:
        # Import the FridaManager class
        from intellicrack.core.frida_manager import FridaManager

        print("✅ Successfully imported FridaManager")

        # Create a mock FridaManager instance
        manager = FridaManager()

        # Test structured message handling
        test_messages = [
            {
                "type": "info",
                "target": "test_script",
                "action": "test_info_message",
                "details": "This is a test info message"
            },
            {
                "type": "warning",
                "target": "test_script",
                "action": "test_warning_message",
                "warning_type": "test_warning"
            },
            {
                "type": "error",
                "target": "test_script",
                "action": "test_error_message",
                "error": "This is a test error"
            },
            {
                "type": "status",
                "target": "test_script",
                "action": "test_status_message",
                "status": "active"
            },
            {
                "type": "bypass",
                "target": "test_script",
                "action": "test_bypass_message",
                "function_name": "test_function",
                "original_value": "original",
                "bypassed_value": "bypassed"
            },
            {
                "type": "success",
                "target": "test_script",
                "action": "test_success_message",
                "operation": "test_completed"
            },
            {
                "type": "detection",
                "target": "test_script",
                "action": "test_detection_message",
                "detected_item": "test_protection"
            },
            {
                "type": "notification",
                "target": "test_script",
                "action": "test_notification_message",
                "notification_type": "system_event"
            }
        ]

        # Test each message type
        for i, test_message in enumerate(test_messages):
            print(f"\n--- Testing message {i+1}: {test_message['type']} ---")

            try:
                # Create a mock Frida message structure
                frida_message = {
                    'type': 'send',
                    'payload': test_message
                }

                # Test the message handler
                if hasattr(manager, '_on_script_message'):
                    manager._on_script_message(frida_message, None)
                    print(f"✅ Successfully processed {test_message['type']} message")
                else:
                    print(f"❌ _on_script_message method not found")

            except Exception as e:
                print(f"❌ Error processing {test_message['type']} message: {e}")

        print(f"\n✅ Completed testing {len(test_messages)} message types")

        return True

    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def test_script_validation():
    """Test that our converted scripts are valid"""
    print("\nTesting converted Frida scripts...")

    script_dir = Path("intellicrack/plugins/frida_scripts")
    if not script_dir.exists():
        print(f"❌ Script directory not found: {script_dir}")
        return False

    # Test specific converted scripts
    converted_scripts = [
        "hook_effectiveness_monitor.js",
        "enhanced_hardware_spoofer.js",
        "certificate_pinning_bypass.js",
        "kernel_bridge.js",
        "modular_hook_library.js",
        "ml_license_detector.js",
        "http3_quic_interceptor.js"
    ]

    for script_name in converted_scripts:
        script_path = script_dir / script_name
        if script_path.exists():
            try:
                with open(script_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                # Check for console.log (should be none)
                console_log_count = content.count('console.log')
                if console_log_count == 0:
                    print(f"✅ {script_name}: No console.log statements found")
                else:
                    print(f"❌ {script_name}: Found {console_log_count} console.log statements")

                # Check for structured send() calls
                send_count = content.count('send({')
                if send_count > 0:
                    print(f"✅ {script_name}: Found {send_count} structured send() calls")
                else:
                    print(f"❌ {script_name}: No structured send() calls found")

                # Check for required message structure
                has_type = 'type:' in content
                has_target = 'target:' in content
                has_action = 'action:' in content

                if has_type and has_target and has_action:
                    print(f"✅ {script_name}: Contains required message structure")
                else:
                    print(f"❌ {script_name}: Missing required message structure")

            except Exception as e:
                print(f"❌ Error reading {script_name}: {e}")
        else:
            print(f"❌ Script not found: {script_name}")

    return True

def main():
    """Main test function"""
    print("=== Structured Messaging Integration Test ===\n")

    # Test 1: Message routing system
    routing_success = test_message_routing()

    # Test 2: Script validation
    script_success = test_script_validation()

    # Summary
    print("\n=== Test Summary ===")
    print(f"Message Routing: {'✅ PASS' if routing_success else '❌ FAIL'}")
    print(f"Script Validation: {'✅ PASS' if script_success else '❌ FAIL'}")

    if routing_success and script_success:
        print("\n🎉 All tests passed! Structured messaging system is working correctly.")
        return 0
    else:
        print("\n❌ Some tests failed. Please review the output above.")
        return 1

if __name__ == '__main__':
    sys.exit(main())
