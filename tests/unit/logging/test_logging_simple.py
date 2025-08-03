#!/usr/bin/env python3
"""Simple test to verify logging imports work without circular dependencies."""

import sys
import os

# Add the project root to Python path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

def test_imports():
    """Test importing each logging module individually."""
    
    print("Testing individual logging module imports...")
    
    try:
        from intellicrack.core.logging import central_config
        print("✓ central_config imported successfully")
    except Exception as e:
        print(f"✗ central_config import failed: {e}")
        return False
    
    try:
        from intellicrack.core.logging import config_loader
        print("✓ config_loader imported successfully")
    except Exception as e:
        print(f"✗ config_loader import failed: {e}")
        return False
    
    try:
        from intellicrack.core.logging import log_monitor
        print("✓ log_monitor imported successfully")
    except Exception as e:
        print(f"✗ log_monitor import failed: {e}")
        return False
    
    try:
        from intellicrack.core.logging import audit_logger
        print("✓ audit_logger imported successfully")
    except Exception as e:
        print(f"✗ audit_logger import failed: {e}")
        return False
    
    try:
        from intellicrack.core.logging import integration
        print("✓ integration imported successfully")
    except Exception as e:
        print(f"✗ integration import failed: {e}")
        return False
    
    return True

def test_main_import():
    """Test importing the main logging package."""
    
    print("\nTesting main logging package import...")
    
    try:
        from intellicrack.core.logging import setup_logging, get_logger
        print("✓ Main logging package imported successfully")
        return True
    except Exception as e:
        print(f"✗ Main logging package import failed: {e}")
        return False

if __name__ == "__main__":
    print("=== Testing Centralized Logging Imports ===\n")
    
    imports_ok = test_imports()
    main_ok = test_main_import()
    
    if imports_ok and main_ok:
        print("\n✓ All logging imports successful!")
        sys.exit(0)
    else:
        print("\n✗ Some imports failed!")
        sys.exit(1)