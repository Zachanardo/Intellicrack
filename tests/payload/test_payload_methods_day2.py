#!/usr/bin/env python3
"""
Test script for Day 2.1: Replace Template Payload Methods in radare2_vulnerability_engine.py

Critical test: Execute _generate_bof_payload() and verify output contains ACTUAL shellcode bytes
Zero tolerance for methods returning instructional text instead of functional code.
"""

import os
import sys

# Add Intellicrack to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'intellicrack'))

def test_bof_payload_generation():
    """Test BOF payload method generates actual shellcode bytes."""
    print("Testing _generate_bof_payload() method...")

    try:
        from intellicrack.core.analysis.radare2_vulnerability_engine import R2VulnerabilityEngine

        # Create test binary path (using notepad.exe as confirmed working)
        binary_path = "C:\\Windows\\System32\\notepad.exe"

        if not os.path.exists(binary_path):
            print(f"ERROR: Test binary not found at {binary_path}")
            return False

        # Initialize vulnerability engine
        engine = R2VulnerabilityEngine(binary_path)

        # Create test vulnerability data
        test_vuln = {
            "function": {"name": "vulnerable_func"},
            "offset": 128
        }

        # Execute the critical test
        print("Executing _generate_bof_payload()...")
        result = engine._generate_bof_payload(test_vuln)

        # Critical validation: Must contain ACTUAL shellcode bytes
        if not isinstance(result, dict):
            print("ERROR: Payload method returned invalid type")
            return False

        # Check for shellcode presence
        if "shellcode" not in result:
            print("ERROR: No 'shellcode' field in result")
            return False

        shellcode = result["shellcode"]

        # CRITICAL: Must be bytes, not strings
        if not isinstance(shellcode, bytes):
            print(f"ERROR: Shellcode is {type(shellcode)}, must be bytes")
            return False

        # CRITICAL: Must not contain template text
        template_indicators = [
            b"Platform-specific shellcode",
            b"Analyze with fuzzing",
            b"Add NOP sled for reliability",
            b"Overwrite with shellcode address"
        ]

        for indicator in template_indicators:
            if indicator in shellcode:
                print(f"ERROR: Template text found in shellcode: {indicator}")
                return False

        # CRITICAL: Must have actual shellcode content
        if len(shellcode) == 0:
            print("ERROR: Shellcode is empty")
            return False

        print(f"OK BOF payload contains {len(shellcode)} bytes of actual shellcode")
        print(f"OK Shellcode type: {type(shellcode)}")
        print(f"OK First 16 bytes (hex): {shellcode[:16].hex()}")

        # Check other required fields
        required_fields = ["complete_payload", "payload_size", "architecture", "return_address"]
        for field in required_fields:
            if field not in result:
                print(f"WARNING: Missing field '{field}' in result")
            else:
                print(f"OK Field '{field}': {type(result[field])}")

        # Validate complete payload is bytes
        if "complete_payload" in result:
            complete_payload = result["complete_payload"]
            if isinstance(complete_payload, bytes):
                print(f"OK Complete payload is {len(complete_payload)} bytes")
            else:
                print(f"ERROR: Complete payload is {type(complete_payload)}, should be bytes")
                return False

        return True

    except Exception as e:
        print(f"ERROR: BOF payload generation failed - {e}")
        return False

def test_format_string_payload_generation():
    """Test format string payload method generates actual exploitation code."""
    print("\nTesting _generate_format_string_payload() method...")

    try:
        from intellicrack.core.analysis.radare2_vulnerability_engine import R2VulnerabilityEngine

        # Create test binary path
        binary_path = "C:\\Windows\\System32\\notepad.exe"

        # Initialize vulnerability engine
        engine = R2VulnerabilityEngine(binary_path)

        # Create test vulnerability data
        test_vuln = {
            "function": {"name": "printf_vuln"},
            "offset": 64
        }

        # Execute the test
        print("Executing _generate_format_string_payload()...")
        result = engine._generate_format_string_payload(test_vuln)

        # Critical validation
        if not isinstance(result, dict):
            print("ERROR: Format string method returned invalid type")
            return False

        # Check for payload presence
        if "payload" not in result:
            print("ERROR: No 'payload' field in result")
            return False

        payload = result["payload"]

        # CRITICAL: Must be bytes, not template strings
        if not isinstance(payload, bytes):
            print(f"ERROR: Payload is {type(payload)}, must be bytes")
            return False

        # CRITICAL: Must not contain template text
        template_indicators = [
            b"Arbitrary write primitive",
            b"%n specifier for memory writes",
            b"GOT/PLT entries or return addresses"
        ]

        for indicator in template_indicators:
            if indicator in payload:
                print(f"ERROR: Template text found in payload: {indicator}")
                return False

        # CRITICAL: Must contain actual format string exploitation patterns
        if len(payload) == 0:
            print("ERROR: Payload is empty")
            return False

        # Check for format string patterns
        if b"%" not in payload:
            print("ERROR: Payload doesn't contain format string specifiers")
            return False

        print(f"OK Format string payload contains {len(payload)} bytes")
        print(f"OK Payload type: {type(payload)}")
        print(f"OK Payload (hex): {payload.hex()}")
        print(f"OK Payload (ascii): {payload}")

        # Check for shellcode
        if "shellcode" in result:
            shellcode = result["shellcode"]
            if isinstance(shellcode, bytes) and len(shellcode) > 0:
                print(f"OK Associated shellcode: {len(shellcode)} bytes")
            else:
                print("WARNING: No valid shellcode associated")

        return True

    except Exception as e:
        print(f"ERROR: Format string payload generation failed - {e}")
        return False

def main():
    """Run comprehensive payload method tests for Day 2.1."""
    print("Day 2.1 Test: Replace Template Payload Methods")
    print("=" * 60)
    print("CRITICAL REQUIREMENT: Methods must generate ACTUAL shellcode bytes")
    print("ZERO TOLERANCE: No template/instructional text allowed")
    print()

    tests = [
        ("BOF Payload Generation", test_bof_payload_generation),
        ("Format String Payload Generation", test_format_string_payload_generation)
    ]

    passed = 0
    total = len(tests)

    for test_name, test_func in tests:
        print(f"Running {test_name}:")
        if test_func():
            print(f"OK {test_name} PASSED")
            passed += 1
        else:
            print(f"FAIL {test_name} FAILED")
        print("-" * 40)

    print(f"\nResults: {passed}/{total} tests passed")

    if passed == total:
        print("OK DAY 2.1 PAYLOAD METHOD REPLACEMENT SUCCESSFUL")
        print("OK All methods generate ACTUAL shellcode bytes")
        print("OK Zero template/placeholder content detected")
        print("OK Ready to proceed to Day 2.2")
        return True
    else:
        print("FAIL DAY 2.1 PAYLOAD METHOD REPLACEMENT FAILED")
        print("FAIL Template methods still present or non-functional")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
