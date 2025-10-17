"""
Simple validation check for Intellicrack module imports and basic functionality.

This script performs basic validation of the Intellicrack project structure,
import functionality, and core module availability. It's used to verify
that the project can be properly imported and that key components are
accessible.
"""

import sys
import os

# Set working directory and add to path
os.chdir(r'D:\Intellicrack')
sys.path.insert(0, r'D:\Intellicrack')

print("Working directory:", os.getcwd())
print("Python path includes project root")

try:
    # Test imports
    from intellicrack.core.config.external_tools_config import (
        ToolStatus, ToolCategory, ExternalTool, ExternalToolsManager
    )
    print("✓ Main imports successful")
    print("ToolStatus:", ToolStatus)
    print("ToolCategory:", ToolCategory)

    # Test basic functionality
    from intellicrack.core.config.external_tools_config import (
        external_tools_manager, get_tool_path, check_tool_available
    )

    print("✓ Function imports successful")
    print("Manager type:", type(external_tools_manager))

    # Test a basic function call
    result = check_tool_available('cmd.exe')
    print(f"check_tool_available('cmd.exe') result: {result} (type: {type(result)})")

    # Import test classes
    from tests.unit.core.config.test_external_tools_config import TestToolStatus
    print("✓ Test class import successful")

    print("\n=== VALIDATION COMPLETE ===")

except Exception as e:
    print(f"Error during validation: {e}")
    import traceback
    traceback.print_exc()
