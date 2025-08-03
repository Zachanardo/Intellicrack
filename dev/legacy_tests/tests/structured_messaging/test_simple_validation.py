#!/usr/bin/env python3
"""
Simple validation test for structured messaging
Tests script conversion without requiring external dependencies
"""

import os
import re
from pathlib import Path

def test_script_conversion():
    """Test that scripts have been properly converted"""
    print("=== Testing Frida Script Conversion ===\n")

    script_dir = Path("intellicrack/plugins/frida_scripts")
    if not script_dir.exists():
        print(f"❌ Script directory not found: {script_dir}")
        return False

    # Test specific converted scripts
    test_scripts = [
        "hook_effectiveness_monitor.js",
        "enhanced_hardware_spoofer.js",
        "certificate_pinning_bypass.js",
        "kernel_bridge.js",
        "modular_hook_library.js",
        "ml_license_detector.js",
        "http3_quic_interceptor.js"
    ]

    total_console_logs = 0
    total_send_calls = 0
    conversion_success = True

    for script_name in test_scripts:
        script_path = script_dir / script_name
        print(f"Testing {script_name}...")

        if not script_path.exists():
            print(f"  ❌ Script not found: {script_name}")
            conversion_success = False
            continue

        try:
            with open(script_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Count console.log statements (should be 0)
            console_log_matches = re.findall(r'console\.log\s*\(', content)
            console_log_count = len(console_log_matches)
            total_console_logs += console_log_count

            # Count structured send() calls
            send_matches = re.findall(r'send\s*\(\s*\{', content)
            send_count = len(send_matches)
            total_send_calls += send_count

            # Check for required message structure patterns
            has_type = bool(re.search(r'type:\s*["\']', content))
            has_target = bool(re.search(r'target:\s*["\']', content))
            has_action = bool(re.search(r'action:\s*["\']', content))

            # Check for proper message types
            message_types = ['info', 'warning', 'error', 'status', 'bypass', 'success', 'detection', 'notification']
            found_types = []
            for msg_type in message_types:
                if f'"{msg_type}"' in content or f"'{msg_type}'" in content:
                    found_types.append(msg_type)

            # Report results
            if console_log_count == 0:
                print(f"  ✅ No console.log statements found")
            else:
                print(f"  ❌ Found {console_log_count} console.log statements")
                conversion_success = False

            if send_count > 0:
                print(f"  ✅ Found {send_count} structured send() calls")
            else:
                print(f"  ❌ No structured send() calls found")
                conversion_success = False

            if has_type and has_target and has_action:
                print(f"  ✅ Contains required message structure (type, target, action)")
            else:
                print(f"  ❌ Missing required message structure")
                conversion_success = False

            if found_types:
                print(f"  ✅ Found message types: {', '.join(found_types)}")
            else:
                print(f"  ❌ No valid message types found")
                conversion_success = False

        except Exception as e:
            print(f"  ❌ Error reading {script_name}: {e}")
            conversion_success = False

        print()  # Empty line for readability

    # Summary
    print("=== Conversion Summary ===")
    print(f"Total console.log statements remaining: {total_console_logs}")
    print(f"Total structured send() calls: {total_send_calls}")
    print(f"Scripts processed: {len(test_scripts)}")

    if conversion_success and total_console_logs == 0 and total_send_calls > 0:
        print("\n🎉 All scripts successfully converted to structured messaging!")
        return True
    else:
        print("\n❌ Script conversion incomplete or has issues.")
        return False

def test_message_structure_examples():
    """Test examples of proper message structure"""
    print("=== Testing Message Structure Examples ===\n")

    # Example structured messages that should be in our scripts
    expected_patterns = [
        r'send\s*\(\s*\{\s*type:\s*["\']info["\']',
        r'send\s*\(\s*\{\s*type:\s*["\']warning["\']',
        r'send\s*\(\s*\{\s*type:\s*["\']error["\']',
        r'send\s*\(\s*\{\s*type:\s*["\']status["\']',
        r'send\s*\(\s*\{\s*type:\s*["\']bypass["\']',
        r'send\s*\(\s*\{\s*type:\s*["\']success["\']',
        r'send\s*\(\s*\{\s*type:\s*["\']detection["\']',
        r'send\s*\(\s*\{\s*type:\s*["\']notification["\']'
    ]

    script_dir = Path("intellicrack/plugins/frida_scripts")
    all_content = ""

    # Collect all script content
    for script_file in script_dir.glob("*.js"):
        if script_file.name != "test_structured_messaging.js":  # Skip our test script
            try:
                with open(script_file, 'r', encoding='utf-8') as f:
                    all_content += f.read() + "\n"
            except Exception as e:
                print(f"Error reading {script_file}: {e}")

    # Test each pattern
    pattern_results = []
    message_types = ['info', 'warning', 'error', 'status', 'bypass', 'success', 'detection', 'notification']

    for i, pattern in enumerate(expected_patterns):
        matches = re.findall(pattern, all_content, re.IGNORECASE)
        pattern_results.append(len(matches))
        msg_type = message_types[i]

        if matches:
            print(f"✅ Found {len(matches)} {msg_type} message(s)")
        else:
            print(f"❌ No {msg_type} messages found")

    total_structured_messages = sum(pattern_results)
    print(f"\nTotal structured messages found: {total_structured_messages}")

    return total_structured_messages > 0

def main():
    """Main test function"""
    print("Structured Messaging Validation Test\n")

    # Test 1: Script conversion
    conversion_success = test_script_conversion()

    # Test 2: Message structure examples
    structure_success = test_message_structure_examples()

    # Overall result
    print("\n=== Final Results ===")
    print(f"Script Conversion: {'✅ PASS' if conversion_success else '❌ FAIL'}")
    print(f"Message Structure: {'✅ PASS' if structure_success else '❌ FAIL'}")

    if conversion_success and structure_success:
        print("\n🎉 Structured messaging implementation is COMPLETE and WORKING!")
        return 0
    else:
        print("\n❌ Issues found with structured messaging implementation.")
        return 1

if __name__ == '__main__':
    exit(main())
