#!/usr/bin/env python3
"""
Simple test script to verify r2pipe integration
Part of Intellicrack Day 1, Step 1.2: Verify Radare2 Integration
"""

import r2pipe
import sys
import os
import subprocess

def test_radare2_direct() -> bool:
    """Test radare2 binary directly."""
    radare2_path = r"D:\Intellicrack\tools\radare2_extracted\radare2-5.9.4-w64\bin\radare2.exe"
    test_binary = r"C:\Windows\System32\notepad.exe"

    try:
        # Test direct radare2 execution
        result = subprocess.run(
            [radare2_path, "-v"],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0:
            print("OK Radare2 binary execution successful")
            print(f"Version: {result.stdout.strip()}")
            return True
        else:
            print(f"ERROR: Radare2 execution failed - {result.stderr}")
            return False

    except Exception as e:
        print(f"ERROR: Failed to execute radare2 - {e}")
        return False

def test_r2pipe_simple() -> bool:
    """Test r2pipe with minimal configuration."""
    radare2_path = r"D:\Intellicrack\tools\radare2_extracted\radare2-5.9.4-w64\bin\radare2.exe"
    test_binary = r"C:\Windows\System32\notepad.exe"

    # Add radare2 bin directory to PATH
    bin_dir = os.path.dirname(radare2_path)
    current_path = os.environ.get("PATH", "")
    os.environ["PATH"] = f"{bin_dir};{current_path}"

    try:
        # Use r2pipe.open with the executable path
        r2 = r2pipe.open(f"{radare2_path} -q0 " + f'"{test_binary}"')

        # Test basic command
        info = r2.cmd('i')
        if info and len(info.strip()) > 0:
            print("OK r2pipe integration successful")
            print("OK Binary information retrieved")
            r2.quit()
            return True
        else:
            print("ERROR: No output from r2pipe")
            r2.quit()
            return False

    except Exception as e:
        print(f"ERROR: r2pipe test failed - {e}")
        return False

def main() -> bool:
    print("Testing Radare2 Integration - Step 1.2")
    print("=" * 50)

    # Test 1: Direct radare2 execution
    print("\nTest 1: Direct Radare2 Execution")
    if not test_radare2_direct():
        return False

    # Test 2: r2pipe integration
    print("\nTest 2: r2pipe Integration")
    if not test_r2pipe_simple():
        return False

    print("\nOK ALL TESTS PASSED - Radare2 integration verified")
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
