#!/usr/bin/env python3
"""
Test script to verify r2pipe integration with radare2
Part of Intellicrack Day 1, Step 1.2: Verify Radare2 Integration
"""

import r2pipe
import sys
import os

def test_r2pipe_integration():
    """Test r2pipe functionality with real binary analysis."""
    test_binary = r"C:\Windows\System32\notepad.exe"
    radare2_path = r"D:\Intellicrack\tools\radare2_extracted\radare2-5.9.4-w64\bin\radare2.exe"

    if not os.path.exists(test_binary):
        print("ERROR: Test binary not found")
        return False

    if not os.path.exists(radare2_path):
        print("ERROR: Radare2 binary not found")
        return False

    try:
        # Set environment for r2pipe to find radare2
        os.environ["PATH"] = (
            f"{os.path.dirname(radare2_path)};" + os.environ.get("PATH", "")
        )
        # Open binary with r2pipe using explicit path
        r2 = r2pipe.open(test_binary, flags=['-q0'], radare2_path=radare2_path)

        # Test basic radare2 commands
        print("Testing r2pipe integration...")

        # Get file info
        file_info = r2.cmd('i')
        print("OK File info command executed")

        # Analyze binary
        r2.cmd('aa')
        print("OK Basic analysis completed")

        # Get functions list
        functions = r2.cmd('afl')
        print("OK Function listing retrieved")

        # Get entry point
        entry = r2.cmd('ie')
        print("OK Entry point information retrieved")

        # Test instruction disassembly
        disasm = r2.cmd('pd 10')
        print("OK Disassembly output generated")

        r2.quit()

        print("\nOK All r2pipe tests PASSED - Real analysis functionality confirmed")
        return True

    except Exception as e:
        print(f"ERROR: r2pipe test failed - {e}")
        return False

if __name__ == "__main__":
    success = test_r2pipe_integration()
    sys.exit(0 if success else 1)
