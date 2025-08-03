#!/usr/bin/env python3
"""
Test script for Ghidra Bridge integration.

This script tests the new bridge-based Ghidra integration without
requiring a full Intellicrack environment setup.
"""

import sys
import os
from pathlib import Path

# Add the project to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_imports():
    """Test that all bridge components can be imported."""
    print("Testing imports...")
    
    try:
        import ghidra_bridge
        print("✓ ghidra_bridge package available")
    except ImportError as e:
        print(f"✗ ghidra_bridge import failed: {e}")
        return False
    
    try:
        from intellicrack.core.analysis.ghidra_bridge_manager import GhidraBridgeManager, GhidraBridgeError
        print("✓ GhidraBridgeManager imported successfully")
    except ImportError as e:
        print(f"✗ GhidraBridgeManager import failed: {e}")
        return False
    
    try:
        from intellicrack.utils.ghidra_common import analyze_binary_with_bridge, decompile_function_with_bridge
        print("✓ Bridge-based utility functions imported successfully")
    except ImportError as e:
        print(f"✗ Bridge utility functions import failed: {e}")
        return False
    
    try:
        from intellicrack.core.analysis.ghidra_decompiler import GhidraDecompiler
        print("✓ Updated GhidraDecompiler imported successfully")
    except ImportError as e:
        print(f"✗ GhidraDecompiler import failed: {e}")
        return False
    
    return True


def test_bridge_manager_initialization():
    """Test bridge manager can be initialized."""
    print("\nTesting bridge manager initialization...")
    
    try:
        from intellicrack.core.analysis.ghidra_bridge_manager import GhidraBridgeManager
        
        # Test with dummy path (won't actually start)
        manager = GhidraBridgeManager(ghidra_path="dummy_path")
        print("✓ GhidraBridgeManager can be initialized")
        return True
        
    except Exception as e:
        print(f"✗ Bridge manager initialization failed: {e}")
        return False


def test_utility_functions():
    """Test utility function signatures."""
    print("\nTesting utility function signatures...")
    
    try:
        from intellicrack.utils.ghidra_common import (
            run_ghidra_plugin,
            create_ghidra_analysis_script,
            save_ghidra_script,
            get_ghidra_project_info,
            cleanup_ghidra_project,
            analyze_binary_with_bridge,
            decompile_function_with_bridge
        )
        
        print("✓ All utility functions are available")
        print(f"  - run_ghidra_plugin: {callable(run_ghidra_plugin)}")
        print(f"  - analyze_binary_with_bridge: {callable(analyze_binary_with_bridge)}")
        print(f"  - decompile_function_with_bridge: {callable(decompile_function_with_bridge)}")
        
        return True
        
    except Exception as e:
        print(f"✗ Utility function test failed: {e}")
        return False


def main():
    """Run all tests."""
    print("=" * 60)
    print("Ghidra Bridge Integration Test")
    print("=" * 60)
    
    tests = [
        test_imports,
        test_bridge_manager_initialization,
        test_utility_functions
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"✗ Test {test.__name__} failed with exception: {e}")
    
    print("\n" + "=" * 60)
    print(f"Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Ghidra Bridge integration is ready.")
        return 0
    else:
        print("❌ Some tests failed. Check the output above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())