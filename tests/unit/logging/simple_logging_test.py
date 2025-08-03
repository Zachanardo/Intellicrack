#!/usr/bin/env python3
"""Simple test for centralized logging imports."""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_imports():
    """Test basic imports."""
    try:
        print("Testing centralized logging imports...")
        
        # Test main logging imports
        from intellicrack.core.logging import setup_logging, get_logger
        print("✓ Main logging imports successful")
        
        # Test central config
        from intellicrack.core.logging.central_config import CentralLoggingManager
        print("✓ Central config imports successful")
        
        # Test monitoring
        from intellicrack.core.logging.log_monitor import LogMonitor
        print("✓ Monitoring imports successful")
        
        # Test integration
        from intellicrack.core.logging.integration import LoggingIntegration
        print("✓ Integration imports successful")
        
        # Test config loader
        from intellicrack.core.logging.config_loader import ConfigLoader
        print("✓ Config loader imports successful")
        
        print("\n🎉 All imports successful!")
        return True
        
    except Exception as e:
        print(f"❌ Import failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_basic_functionality():
    """Test basic functionality."""
    try:
        print("\nTesting basic functionality...")
        
        from intellicrack.core.logging import setup_logging, get_logger
        
        # Initialize logging
        setup_logging()
        logger = get_logger('test')
        
        # Test basic logging
        logger.info("Test message")
        print("✓ Basic logging works")
        
        return True
        
    except Exception as e:
        print(f"❌ Basic functionality test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("Simple Centralized Logging Test")
    print("===============================")
    
    success = test_imports()
    if success:
        success = test_basic_functionality()
    
    if success:
        print("\n✅ Simple test passed!")
        sys.exit(0)
    else:
        print("\n❌ Simple test failed!")
        sys.exit(1)