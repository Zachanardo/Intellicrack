#!/usr/bin/env python3
"""
Test script to verify Intellicrack dependencies are working correctly.
"""

import sys
import importlib

def test_import(module_name, description=""):
    """Test if a module can be imported."""
    try:
        importlib.import_module(module_name)
        print(f"✓ {module_name} {description}")
        return True
    except ImportError as e:
        print(f"✗ {module_name} {description} - {e}")
        return False

def test_version_compatibility():
    """Test version compatibility of key packages."""
    print("Testing version compatibility...")
    
    try:
        import numpy as np
        print(f"✓ NumPy {np.__version__}")
        
        import pandas as pd
        print(f"✓ Pandas {pd.__version__}")
        
        try:
            import matplotlib
            print(f"✓ Matplotlib {matplotlib.__version__}")
        except ImportError:
            print("⚠ Matplotlib not available (optional)")
            
        try:
            import numba
            print(f"✓ Numba {numba.__version__}")
        except ImportError:
            print("⚠ Numba not available (optional)")
            
    except ImportError as e:
        print(f"✗ Version test failed: {e}")
        return False
    
    return True

def main():
    """Main test routine."""
    print("Testing Intellicrack Dependencies")
    print("=" * 40)
    
    # Core dependencies
    core_tests = [
        ("PyQt5", "- GUI framework"),
        ("requests", "- HTTP library"),
        ("rich", "- Terminal formatting"),
        ("yaml", "- YAML parsing"),
        ("pefile", "- PE file analysis"),
        ("elftools", "- ELF file analysis"), 
        ("cryptography", "- Cryptographic functions"),
    ]
    
    print("\nCore Dependencies:")
    core_passed = 0
    for module, desc in core_tests:
        if test_import(module, desc):
            core_passed += 1
    
    print(f"\nCore: {core_passed}/{len(core_tests)} passed")
    
    # Optional dependencies
    print("\nOptional Dependencies:")
    optional_tests = [
        ("numpy", "- Numerical computing"),
        ("pandas", "- Data analysis"),
        ("matplotlib", "- Plotting"),
        ("numba", "- JIT compilation"),
        ("torch", "- PyTorch ML"),
        ("transformers", "- Hugging Face transformers"),
    ]
    
    optional_passed = 0
    for module, desc in optional_tests:
        if test_import(module, desc):
            optional_passed += 1
    
    print(f"\nOptional: {optional_passed}/{len(optional_tests)} passed")
    
    # Version compatibility test
    print("\nVersion Compatibility:")
    version_ok = test_version_compatibility()
    
    # Summary
    print("\n" + "=" * 40)
    print("SUMMARY:")
    
    if core_passed == len(core_tests):
        print("✓ Core dependencies: ALL GOOD")
    else:
        print(f"⚠ Core dependencies: {core_passed}/{len(core_tests)} available")
        
    print(f"✓ Optional dependencies: {optional_passed}/{len(optional_tests)} available")
    
    if version_ok:
        print("✓ Version compatibility: OK")
    else:
        print("⚠ Version compatibility: Issues detected")
    
    if core_passed >= len(core_tests) - 1:  # Allow 1 core failure
        print("\n🎉 Intellicrack should work with current dependencies!")
        return 0
    else:
        print("\n❌ Missing critical dependencies. Please install core requirements.")
        return 1

if __name__ == "__main__":
    sys.exit(main())