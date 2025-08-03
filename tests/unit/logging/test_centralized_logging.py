#!/usr/bin/env python3
"""
Test script for the centralized logging system.

This script tests the basic functionality of the centralized logging system
to ensure it works correctly with the existing codebase.
"""

import sys
import time
from pathlib import Path

# Add the project root to the path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_basic_logging():
    """Test basic logging functionality."""
    print("Testing basic centralized logging...")
    
    try:
        from intellicrack.core.logging import setup_logging, get_logger
        
        # Initialize logging
        setup_logging(environment='development')
        logger = get_logger('test_logger')
        
        # Test different log levels
        logger.debug("Debug message test")
        logger.info("Info message test") 
        logger.warning("Warning message test")
        logger.error("Error message test")
        
        print("✓ Basic logging test passed")
        return True
        
    except Exception as e:
        print(f"✗ Basic logging test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_performance_logging():
    """Test performance logging functionality."""
    print("Testing performance logging...")
    
    try:
        from intellicrack.core.logging import PerformanceLogger, log_performance
        
        # Test context manager
        with PerformanceLogger("test_operation"):
            time.sleep(0.1)  # Simulate work
        
        # Test direct function
        log_performance("direct_test", 0.05, extra_data="test")
        
        print("✓ Performance logging test passed")
        return True
        
    except Exception as e:
        print(f"✗ Performance logging test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_security_logging():
    """Test security logging functionality."""
    print("Testing security logging...")
    
    try:
        from intellicrack.core.logging import log_security
        
        log_security("test_event", "info", "Test security event")
        log_security("auth_attempt", "warning", "Test authentication attempt")
        
        print("✓ Security logging test passed")
        return True
        
    except Exception as e:
        print(f"✗ Security logging test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_monitoring():
    """Test log monitoring functionality."""
    print("Testing log monitoring...")
    
    try:
        from intellicrack.core.logging import get_monitoring_status, start_log_monitoring
        
        # Start monitoring
        start_log_monitoring()
        
        # Get status
        status = get_monitoring_status()
        
        if status['running']:
            print(f"✓ Monitoring is running with {status['patterns_count']} patterns")
            return True
        else:
            print("✗ Monitoring is not running")
            return False
        
    except Exception as e:
        print(f"✗ Monitoring test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_configuration():
    """Test configuration loading."""
    print("Testing configuration loading...")
    
    try:
        from intellicrack.core.logging.config_loader import load_logging_config
        
        # Load configuration
        config = load_logging_config()
        
        if config:
            print(f"✓ Configuration loaded with {len(config)} settings")
            return True
        else:
            print("✓ No configuration file found (expected for test)")
            return True
        
    except Exception as e:
        print(f"✗ Configuration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_integration():
    """Test integration with existing code patterns."""
    print("Testing integration patterns...")
    
    try:
        from intellicrack.core.logging import performance_logged, security_logged
        
        @performance_logged("test_function")
        def test_perf_function():
            time.sleep(0.05)
            return "test_result"
        
        @security_logged("test_security", "info")
        def test_security_function():
            return "secure_result"
        
        # Test decorated functions
        result1 = test_perf_function()
        result2 = test_security_function()
        
        if result1 == "test_result" and result2 == "secure_result":
            print("✓ Integration decorators test passed")
            return True
        else:
            print("✗ Integration decorators test failed")
            return False
        
    except Exception as e:
        print(f"✗ Integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_system_status():
    """Test system status reporting."""
    print("Testing system status...")
    
    try:
        from intellicrack.core.logging import get_system_status
        
        status = get_system_status()
        
        if isinstance(status, dict) and 'central_logging' in status:
            print(f"✓ System status retrieved: {len(status)} components")
            return True
        else:
            print("✗ System status format unexpected")
            return False
        
    except Exception as e:
        print(f"✗ System status test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all tests."""
    print("Centralized Logging System Test Suite")
    print("=====================================")
    
    tests = [
        test_basic_logging,
        test_performance_logging,
        test_security_logging,
        test_monitoring,
        test_configuration,
        test_integration,
        test_system_status,
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"✗ Test {test.__name__} crashed: {e}")
        print()
    
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Centralized logging system is working correctly.")
        return 0
    else:
        print("❌ Some tests failed. Please check the implementation.")
        return 1
    
    # Cleanup
    try:
        from intellicrack.core.logging import shutdown_integrated_logging
        shutdown_integrated_logging()
        print("Logging system shutdown completed.")
    except Exception as e:
        print(f"Warning: Could not shutdown logging system cleanly: {e}")

if __name__ == "__main__":
    sys.exit(main())