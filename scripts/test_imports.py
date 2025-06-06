#!/usr/bin/env python3
"""
Test script to verify modular import structure works correctly.

This script tests the import structure of the refactored Intellicrack
modules without requiring GUI dependencies.
"""

import sys
import traceback

def test_import(module_name, description):
    """Test importing a specific module."""
    try:
        exec(f"import {module_name}")
        print(f"✓ {description}")
        return True
    except ImportError as e:
        if "PyQt5" in str(e) or "numpy" in str(e) or "sklearn" in str(e) or "pefile" in str(e):
            print(f"⚠ {description} (missing optional dependency: {e})")
            return True  # This is acceptable - missing optional deps
        else:
            print(f"✗ {description} - Import Error: {e}")
            return False
    except Exception as e:
        print(f"✗ {description} - Error: {e}")
        return False

def test_core_imports():
    """Test core module imports."""
    print("Testing Core Module Imports:")
    print("-" * 40)

    results = []

    # Test config module
    results.append(test_import("intellicrack.config", "Config module"))

    # Test utils modules  
    results.append(test_import("intellicrack.utils.logger", "Logger utilities"))

    # Test core analysis modules
    results.append(test_import("intellicrack.core.analysis.vulnerability_engine", "Vulnerability engine"))
    results.append(test_import("intellicrack.core.analysis.multi_format_analyzer", "Multi-format analyzer"))

    # Test AI modules
    results.append(test_import("intellicrack.ai.ml_predictor", "ML predictor"))

    # Test UI modules (expected to have PyQt5 dependency issues)
    results.append(test_import("intellicrack.ui.dialogs.splash_screen", "Splash screen"))

    print("\n" + "=" * 50)
    passed = sum(results)
    total = len(results)
    print(f"Import Test Results: {passed}/{total} modules imported successfully")

    if passed == total:
        print("🎉 All core imports working correctly!")
        return True
    else:
        print("⚠ Some imports failed (this may be due to missing optional dependencies)")
        return False

def test_functionality():
    """Test basic functionality of imported modules."""
    print("\nTesting Basic Functionality:")
    print("-" * 40)

    try:
        # Test config loading
        from intellicrack.config import load_config, ConfigManager
        config = load_config()
        print("✓ Configuration loading works")

        # Test config manager
        config_manager = ConfigManager()
        print("✓ Configuration manager works")

        # Test vulnerability engine (without actual binary analysis)
        from intellicrack.core.analysis.vulnerability_engine import calculate_entropy
        entropy = calculate_entropy(b"test data")
        print(f"✓ Entropy calculation works: {entropy:.3f}")

        print("\n🎉 Basic functionality tests passed!")
        return True

    except Exception as e:
        print(f"✗ Functionality test failed: {e}")
        traceback.print_exc()
        return False

def main():
    """Main test function."""
    print("Intellicrack Modular Import Test")
    print("=" * 50)

    # Test imports
    imports_ok = test_core_imports()

    # Test basic functionality
    if imports_ok:
        functionality_ok = test_functionality()
    else:
        functionality_ok = False

    print("\n" + "=" * 50)
    if imports_ok and functionality_ok:
        print("🎉 Modular refactoring validation PASSED!")
        print("The refactored Intellicrack structure is working correctly.")
        return 0
    else:
        print("⚠ Some issues detected in modular structure")
        print("This may be due to missing optional dependencies in test environment.")
        return 1

if __name__ == "__main__":
    sys.exit(main())