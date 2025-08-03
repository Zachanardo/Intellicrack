#!/usr/bin/env python3
"""
Verify centralized logging imports work correctly.
"""

import sys
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent))

def test_individual_imports():
    """Test each module individually."""
    
    print("Testing individual module imports...")
    
    try:
        # Test central config
        print("  - Testing central_config...")
        from intellicrack.core.logging.central_config import CentralLoggingManager, LoggingConfig
        print("    ✓ central_config imported successfully")
    except Exception as e:
        print(f"    ✗ central_config failed: {e}")
        return False
    
    try:
        # Test config loader
        print("  - Testing config_loader...")
        from intellicrack.core.logging.config_loader import ConfigLoader
        print("    ✓ config_loader imported successfully")
    except Exception as e:
        print(f"    ✗ config_loader failed: {e}")
        return False
    
    try:
        # Test log monitor
        print("  - Testing log_monitor...")
        from intellicrack.core.logging.log_monitor import LogMonitor, AlertSeverity
        print("    ✓ log_monitor imported successfully")
    except Exception as e:
        print(f"    ✗ log_monitor failed: {e}")
        return False
    
    try:
        # Test audit logger
        print("  - Testing audit_logger...")
        from intellicrack.core.logging.audit_logger import AuditLogger, AuditEvent
        print("    ✓ audit_logger imported successfully")
    except Exception as e:
        print(f"    ✗ audit_logger failed: {e}")
        return False
    
    try:
        # Test integration (most complex)
        print("  - Testing integration...")
        from intellicrack.core.logging.integration import LoggingIntegration
        print("    ✓ integration imported successfully")
    except Exception as e:
        print(f"    ✗ integration failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True

def test_main_package_import():
    """Test main package import."""
    
    print("\nTesting main package import...")
    
    try:
        from intellicrack.core.logging import setup_logging, get_logger
        print("✓ Main package imported successfully")
        return True
    except Exception as e:
        print(f"✗ Main package import failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_basic_functionality():
    """Test basic functionality."""
    
    print("\nTesting basic functionality...")
    
    try:
        from intellicrack.core.logging import setup_logging, get_logger
        
        # Setup logging
        setup_logging(environment='development')
        logger = get_logger('test_verify')
        
        # Test logging
        logger.info("Test log message from verify script")
        
        print("✓ Basic functionality works")
        return True
        
    except Exception as e:
        print(f"✗ Basic functionality failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run verification tests."""
    
    print("Centralized Logging Import Verification")
    print("=======================================")
    
    # Test individual imports first
    if not test_individual_imports():
        print("\n❌ Individual imports failed!")
        return 1
    
    # Test main package import
    if not test_main_package_import():
        print("\n❌ Main package import failed!")
        return 1
    
    # Test basic functionality
    if not test_basic_functionality():
        print("\n❌ Basic functionality failed!")
        return 1
    
    print("\n🎉 All verification tests passed!")
    return 0

if __name__ == "__main__":
    sys.exit(main())