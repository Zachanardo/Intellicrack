#!/usr/bin/env python3
"""Debug script to find import issues."""

import traceback

def test_imports():
    """Test imports step by step to find the failing one."""
    print("Testing imports...")
    
    try:
        print("1. Testing intellicrack package...")
        print("   ✓ intellicrack package imported successfully")
    except Exception as e:
        print(f"   ✗ Failed to import intellicrack package: {e}")
        traceback.print_exc()
        return
    
    try:
        print("2. Testing intellicrack.core...")
        print("   ✓ intellicrack.core imported successfully")
    except Exception as e:
        print(f"   ✗ Failed to import intellicrack.core: {e}")
        traceback.print_exc()
        return
        
    try:
        print("3. Testing intellicrack.core.startup_checks...")
        print("   ✓ startup_checks imported successfully")
    except Exception as e:
        print(f"   ✗ Failed to import startup_checks: {e}")
        traceback.print_exc()
        return
        
    try:
        print("4. Testing intellicrack.main...")
        print("   ✓ intellicrack.main imported successfully")
    except Exception as e:
        print(f"   ✗ Failed to import intellicrack.main: {e}")
        traceback.print_exc()
        return
        
    print("All imports successful!")

if __name__ == "__main__":
    test_imports()