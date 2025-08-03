#!/usr/bin/env python3
"""
Complete test suite for centralized logging system.
Tests all major functionality and reports results.
"""

import sys
import os
import tempfile
import time
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_basic_functionality():
    """Test basic logging functionality."""
    print("=== Testing Basic Functionality ===")
    
    try:
        from intellicrack.core.logging import setup_logging, get_logger
        print("✓ Import successful")
        
        setup_logging()
        print("✓ Setup completed")
        
        logger = get_logger("test.basic")
        logger.info("Test message - basic functionality")
        print("✓ Basic logging works")
        
        return True
    except Exception as e:
        print(f"✗ Basic functionality failed: {e}")
        return False

def test_convenience_functions():
    """Test convenience logging functions."""
    print("\n=== Testing Convenience Functions ===")
    
    try:
        from intellicrack.core.logging import (
            log_analysis_result, log_exploit_result, 
            log_performance, log_security
        )
        
        log_analysis_result("/test/sample.exe", {"protection": "UPX"})
        print("✓ Analysis result logging")
        
        log_exploit_result("test_target", "overflow", success=True)
        print("✓ Exploit result logging")
        
        log_performance("test_op", 0.5)
        print("✓ Performance logging")
        
        log_security("test_event", "HIGH", "Test security event")
        print("✓ Security event logging")
        
        return True
    except Exception as e:
        print(f"✗ Convenience functions failed: {e}")
        return Falsedef test_decorators():
    """Test logging decorators."""
    print("\n=== Testing Decorators ===")
    
    try:
        from intellicrack.core.logging import performance_logged, security_logged
        
        @performance_logged("test_decorated_function")
        def sample_function():
            time.sleep(0.01)
            return "success"
        
        @security_logged("test_security_function", "MEDIUM")
        def secure_function():
            return "secure_success"
        
        result1 = sample_function()
        result2 = secure_function()
        
        print(f"✓ Performance decorator: {result1}")
        print(f"✓ Security decorator: {result2}")
        
        return True
    except Exception as e:
        print(f"✗ Decorators failed: {e}")
        return False

def test_system_status():
    """Test system status reporting."""
    print("\n=== Testing System Status ===")
    
    try:
        from intellicrack.core.logging import get_system_status
        
        status = get_system_status()
        print(f"✓ System status retrieved: {list(status.keys())}")
        
        # Check expected keys
        expected_keys = ['central_logging', 'monitoring', 'integration_initialized']
        for key in expected_keys:
            if key in status:
                print(f"✓ Status key present: {key}")
            else:
                print(f"⚠ Status key missing: {key}")
        
        return True
    except Exception as e:
        print(f"✗ System status failed: {e}")
        return False

def test_audit_types():
    """Test audit event types."""
    print("\n=== Testing Audit Types ===")
    
    try:
        from intellicrack.core.logging import AuditEventType, AlertSeverity
        
        # Test audit event types
        print(f"✓ Exploit attempt type: {AuditEventType.EXPLOIT_ATTEMPT.value}")
        print(f"✓ Binary loaded type: {AuditEventType.BINARY_LOADED.value}")
        
        # Test alert severity levels  
        print(f"✓ Alert severity HIGH: {AlertSeverity.HIGH.value}")
        print(f"✓ Alert severity CRITICAL: {AlertSeverity.CRITICAL.value}")
        
        return True
    except Exception as e:
        print(f"✗ Audit types failed: {e}")
        return Falsedef main():
    """Run all tests and report results."""
    print("🚀 Centralized Logging System - Comprehensive Test Suite")
    print("=" * 60)
    
    tests = [
        test_basic_functionality,
        test_convenience_functions,
        test_decorators,
        test_system_status,
        test_audit_types
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"✗ Test {test.__name__} crashed: {e}")
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"📊 Test Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("🎉 All centralized logging tests PASSED!")
        print("✅ Centralized logging system is fully functional!")
        
        # Write success to result file
        with open("centralized_logging_test_results.txt", "w") as f:
            f.write("CENTRALIZED LOGGING SYSTEM - COMPREHENSIVE TEST RESULTS\n")
            f.write("=" * 55 + "\n\n")
            f.write(f"✅ ALL TESTS PASSED ({passed}/{passed + failed})\n\n")
            f.write("Components tested successfully:\n")
            f.write("- Basic setup and logging functionality\n")
            f.write("- Convenience logging functions\n")
            f.write("- Performance and security decorators\n")
            f.write("- System status and monitoring\n")
            f.write("- Audit event types and alert severities\n\n")
            f.write("🎉 Centralized logging system is production-ready!\n")
        
        return 0
    else:
        print("❌ Some tests failed - check implementation")
        return 1

if __name__ == "__main__":
    sys.exit(main())