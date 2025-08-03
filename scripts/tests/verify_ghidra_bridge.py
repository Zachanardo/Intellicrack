#!/usr/bin/env python3
"""Verification script for Ghidra Bridge integration."""

import sys
import traceback

def test_imports():
    """Test all critical imports for ghidra_bridge integration."""
    tests = []
    
    # Test GhidraBridgeManager import
    try:
        from intellicrack.core.analysis.ghidra_bridge_manager import GhidraBridgeManager
        tests.append(("GhidraBridgeManager", True, None))
    except Exception as e:
        tests.append(("GhidraBridgeManager", False, str(e)))
    
    # Test GhidraDecompiler import
    try:
        from intellicrack.core.analysis.ghidra_decompiler import GhidraDecompiler
        tests.append(("GhidraDecompiler", True, None))
    except Exception as e:
        tests.append(("GhidraDecompiler", False, str(e)))
    
    # Test ghidra_common import
    try:
        from intellicrack.utils.ghidra_common import analyze_binary_with_bridge
        tests.append(("ghidra_common", True, None))
    except Exception as e:
        tests.append(("ghidra_common", False, str(e)))
    
    # Test path discovery import
    try:
        from intellicrack.utils.core.path_discovery import discover_ghidra_path
        tests.append(("discover_ghidra_path", True, None))
    except Exception as e:
        tests.append(("discover_ghidra_path", False, str(e)))
    
    # Test ghidra_bridge package
    try:
        import ghidra_bridge
        tests.append(("ghidra_bridge package", True, None))
    except Exception as e:
        tests.append(("ghidra_bridge package", False, str(e)))
    
    # Test pydantic-settings
    try:
        from pydantic_settings import BaseSettings
        tests.append(("pydantic_settings", True, None))
    except Exception as e:
        tests.append(("pydantic_settings", False, str(e)))
    
    return tests

def test_basic_functionality():
    """Test basic functionality without requiring Ghidra installation."""
    tests = []
    
    try:
        from intellicrack.core.analysis.ghidra_bridge_manager import GhidraBridgeManager
        manager = GhidraBridgeManager()
        tests.append(("GhidraBridgeManager init", True, None))
    except Exception as e:
        tests.append(("GhidraBridgeManager init", False, str(e)))
    
    try:
        from intellicrack.core.analysis.ghidra_decompiler import GhidraDecompiler
        decompiler = GhidraDecompiler("/fake/path/test.exe")
        tests.append(("GhidraDecompiler init", True, None))
    except Exception as e:
        tests.append(("GhidraDecompiler init", False, str(e)))
    
    try:
        from intellicrack.utils.core.path_discovery import discover_ghidra_path
        # This might return None but should not error
        path = discover_ghidra_path()
        tests.append(("discover_ghidra_path call", True, f"Returned: {path}"))
    except Exception as e:
        tests.append(("discover_ghidra_path call", False, str(e)))
    
    return tests

def main():
    """Run all verification tests."""
    print("="*60)
    print("Ghidra Bridge Integration Verification")
    print("="*60)
    
    # Test imports
    print("\n1. Import Tests:")
    print("-" * 40)
    import_tests = test_imports()
    import_success = 0
    
    for name, success, error in import_tests:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"{name:25} {status}")
        if not success:
            print(f"    Error: {error}")
        else:
            import_success += 1
    
    print(f"\nImport Results: {import_success}/{len(import_tests)} passed")
    
    # Test basic functionality
    print("\n2. Functionality Tests:")
    print("-" * 40)
    func_tests = test_basic_functionality()
    func_success = 0
    
    for name, success, info in func_tests:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"{name:25} {status}")
        if not success:
            print(f"    Error: {info}")
        elif info:
            print(f"    Info: {info}")
        else:
            func_success += 1
    
    print(f"\nFunctionality Results: {func_success}/{len(func_tests)} passed")
    
    # Overall result
    total_tests = len(import_tests) + len(func_tests)
    total_success = import_success + func_success
    
    print("\n" + "="*60)
    print(f"OVERALL RESULT: {total_success}/{total_tests} tests passed")
    
    if total_success == total_tests:
        print("✓ All tests passed - Ghidra Bridge integration is ready!")
        return 0
    else:
        print("✗ Some tests failed - Check errors above")
        return 1

if __name__ == "__main__":
    sys.exit(main())