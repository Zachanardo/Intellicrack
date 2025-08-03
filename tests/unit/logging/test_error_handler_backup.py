#!/usr/bin/env python3
"""
Test script for radare2_error_handler syntax check
"""

try:
    from intellicrack.core.analysis.radare2_error_handler import R2ErrorHandler, get_error_handler
    print("✓ Import successful")
    
    # Test basic instantiation
    handler = R2ErrorHandler(enable_tool_validation=False)
    print("✓ Handler instantiation successful")
    
    # Test global handler
    global_handler = get_error_handler()
    print("✓ Global handler access successful")
    
    print("\n✓ All syntax checks passed!")
    
except ImportError as e:
    print(f"✗ Import error: {e}")
except SyntaxError as e:
    print(f"✗ Syntax error: {e}")
except Exception as e:
    print(f"✗ Other error: {e}")
    import traceback
    traceback.print_exc()