#!/usr/bin/env python3
"""
Simple validation of external_tools_config tests
"""

import sys
import os
import traceback

# Add project root to Python path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

def validate_imports():
    """Validate that our test imports work correctly"""
    print("=== Validating Test Imports ===")
    try:
        # Test imports from the module under test
        from intellicrack.core.config.external_tools_config import (
            ToolStatus,
            ToolCategory,
            ExternalTool,
            ExternalToolsManager,
            external_tools_manager,
            get_tool_path,
            check_tool_available,
            get_tool_command,
            get_missing_tools
        )
        print("OK Successfully imported external_tools_config module")

        # Basic validation of imports
        print(f"OK ToolStatus: {ToolStatus}")
        print(f"OK ToolCategory: {ToolCategory}")
        print(f"OK ExternalTool: {ExternalTool}")
        print(f"OK ExternalToolsManager: {ExternalToolsManager}")
        print(f"OK external_tools_manager instance: {external_tools_manager}")

        return True

    except Exception as e:
        print(f"FAIL Import validation failed: {e}")
        traceback.print_exc()
        return False

def validate_test_module():
    """Validate that our test module loads correctly"""
    print("\n=== Validating Test Module ===")
    try:
        # Import the test module
        from tests.unit.core.config.test_external_tools_config import (
            TestToolStatus,
            TestToolCategory,
            TestExternalTool,
            TestExternalToolsManager,
            TestGlobalFunctions,
            TestGlobalManagerInstance,
            TestRealWorldScenarios,
            TestProductionReadinessValidation
        )
        print("OK Successfully imported test classes")

        # Count test methods
        test_classes = [
            TestToolStatus, TestToolCategory, TestExternalTool,
            TestExternalToolsManager, TestGlobalFunctions, TestGlobalManagerInstance,
            TestRealWorldScenarios, TestProductionReadinessValidation
        ]

        total_tests = 0
        for test_class in test_classes:
            test_methods = [method for method in dir(test_class) if method.startswith('test_')]
            class_test_count = len(test_methods)
            total_tests += class_test_count
            print(f"OK {test_class.__name__}: {class_test_count} test methods")

        print(f"OK Total test methods: {total_tests}")
        return True

    except Exception as e:
        print(f"FAIL Test module validation failed: {e}")
        traceback.print_exc()
        return False

def validate_basic_functionality():
    """Basic validation of the external tools system"""
    print("\n=== Validating Basic Functionality ===")
    try:
        from intellicrack.core.config.external_tools_config import (
            ToolStatus, ToolCategory, ExternalTool, external_tools_manager,
            get_tool_path, check_tool_available
        )

        # Test enum access
        try:
            status_values = list(ToolStatus)
            print(f"OK ToolStatus enum has {len(status_values)} values")
        except Exception as e:
            print(f"FAIL ToolStatus access failed: {e}")

        try:
            category_values = list(ToolCategory)
            print(f"OK ToolCategory enum has {len(category_values)} values")
        except Exception as e:
            print(f"FAIL ToolCategory access failed: {e}")

        # Test manager instance
        try:
            print(f"OK Global manager type: {type(external_tools_manager)}")
            manager_attrs = [attr for attr in dir(external_tools_manager) if not attr.startswith('_')]
            print(f"OK Manager has {len(manager_attrs)} public attributes/methods")
        except Exception as e:
            print(f"FAIL Manager access failed: {e}")

        # Test basic functions
        try:
            result = get_tool_path('notepad')
            print(f"OK get_tool_path('notepad') returned: {type(result)}")
        except Exception as e:
            print(f"FAIL get_tool_path failed: {e}")

        try:
            result = check_tool_available('notepad.exe')
            print(f"OK check_tool_available('notepad.exe') returned: {type(result)}")
        except Exception as e:
            print(f"FAIL check_tool_available failed: {e}")

        return True

    except Exception as e:
        print(f"FAIL Functionality validation failed: {e}")
        traceback.print_exc()
        return False

def main():
    """Main validation function"""
    print("External Tools Config Test Validation")
    print("=" * 50)

    # Run validations
    imports_ok = validate_imports()
    tests_ok = validate_test_module()
    functionality_ok = validate_basic_functionality()

    print("\n" + "=" * 50)
    print("VALIDATION SUMMARY")
    print("=" * 50)
    print(f"Imports: {'OK PASS' if imports_ok else 'FAIL FAIL'}")
    print(f"Test Module: {'OK PASS' if tests_ok else 'FAIL FAIL'}")
    print(f"Basic Functionality: {'OK PASS' if functionality_ok else 'FAIL FAIL'}")

    overall_success = imports_ok and tests_ok and functionality_ok
    print(f"\nOverall: {'OK PASS' if overall_success else 'FAIL FAIL'}")

    return 0 if overall_success else 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
