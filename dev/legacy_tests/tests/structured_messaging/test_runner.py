#!/usr/bin/env python3
"""
Comprehensive test runner for structured messaging system
This script runs all structured messaging tests and validates the implementation
"""

import sys
import os
import subprocess
import json
from pathlib import Path

def run_test(test_script, description):
    """Run a single test script and return results"""
    print(f"\n{'='*60}")
    print(f"Running: {description}")
    print(f"Script: {test_script}")
    print(f"{'='*60}")

    try:
        # Change to the intellicrack root directory
        os.chdir("C:\\Intellicrack")

        # Run the test
        result = subprocess.run(
            [sys.executable, test_script],
            capture_output=True,
            text=True,
            timeout=30
        )

        print("STDOUT:")
        print(result.stdout)

        if result.stderr:
            print("STDERR:")
            print(result.stderr)

        print(f"\nReturn code: {result.returncode}")

        return result.returncode == 0

    except subprocess.TimeoutExpired:
        print("❌ Test timed out after 30 seconds")
        return False
    except Exception as e:
        print(f"❌ Error running test: {e}")
        return False

def check_test_prerequisites():
    """Check if all required files exist"""
    print("Checking test prerequisites...")

    required_files = [
        "intellicrack/core/frida_manager.py",
        "intellicrack/ui/dialogs/frida_manager_dialog.py",
        "intellicrack/plugins/frida_scripts/test_structured_messaging.js",
        "tests/structured_messaging/test_simple_validation.py",
        "tests/structured_messaging/test_message_handlers.py"
    ]

    all_exist = True
    for file_path in required_files:
        if Path(file_path).exists():
            print(f"✅ {file_path}")
        else:
            print(f"❌ {file_path} - MISSING")
            all_exist = False

    return all_exist

def validate_frida_scripts():
    """Validate that all Frida scripts have been converted"""
    print("\nValidating Frida script conversion...")

    script_dir = Path("intellicrack/plugins/frida_scripts")
    converted_scripts = [
        "hook_effectiveness_monitor.js",
        "enhanced_hardware_spoofer.js",
        "certificate_pinning_bypass.js",
        "kernel_bridge.js",
        "modular_hook_library.js",
        "ml_license_detector.js",
        "http3_quic_interceptor.js"
    ]

    validation_results = []

    for script_name in converted_scripts:
        script_path = script_dir / script_name
        if script_path.exists():
            try:
                with open(script_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                console_logs = content.count('console.log')
                send_calls = content.count('send({')

                result = {
                    'script': script_name,
                    'console_logs': console_logs,
                    'send_calls': send_calls,
                    'converted': console_logs == 0 and send_calls > 0
                }

                validation_results.append(result)

                if result['converted']:
                    print(f"✅ {script_name}: {send_calls} send() calls, 0 console.log")
                else:
                    print(f"❌ {script_name}: {console_logs} console.log, {send_calls} send() calls")

            except Exception as e:
                print(f"❌ Error reading {script_name}: {e}")
                validation_results.append({
                    'script': script_name,
                    'error': str(e),
                    'converted': False
                })
        else:
            print(f"❌ {script_name}: File not found")
            validation_results.append({
                'script': script_name,
                'error': 'File not found',
                'converted': False
            })

    return validation_results

def main():
    """Main test runner"""
    print("🧪 Structured Messaging Test Suite")
    print("=" * 60)

    # Check prerequisites
    if not check_test_prerequisites():
        print("\n❌ Prerequisites not met. Please ensure all required files exist.")
        return 1

    # Validate script conversion
    validation_results = validate_frida_scripts()
    converted_count = sum(1 for r in validation_results if r.get('converted', False))
    total_scripts = len(validation_results)

    print(f"\nScript conversion status: {converted_count}/{total_scripts} scripts converted")

    # Run tests
    tests = [
        ("tests/structured_messaging/test_simple_validation.py", "Script Validation Test"),
        ("tests/structured_messaging/test_message_handlers.py", "Message Handler Integration Test")
    ]

    results = []
    for test_script, description in tests:
        success = run_test(test_script, description)
        results.append((description, success))

    # Summary
    print("\n" + "=" * 60)
    print("🏁 TEST SUMMARY")
    print("=" * 60)

    print(f"Script Conversion: {converted_count}/{total_scripts} scripts converted")

    for description, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{description}: {status}")

    # Overall result
    all_converted = converted_count == total_scripts
    all_tests_passed = all(success for _, success in results)

    if all_converted and all_tests_passed:
        print("\n🎉 ALL TESTS PASSED! Structured messaging system is working correctly.")
        return 0
    else:
        print("\n❌ Some tests failed. Please review the output above.")
        return 1

if __name__ == '__main__':
    sys.exit(main())
