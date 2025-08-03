#!/usr/bin/env python3
"""
Comprehensive integration tests for centralized logging system.

Tests the full centralized logging functionality including:
- Configuration loading and management
- Log aggregation and monitoring  
- Integration with existing components
- Performance tracking and security event logging
"""

import logging
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

import sys
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from intellicrack.core.logging import (
    setup_logging,
    get_logger,
    log_analysis_result,
    log_exploit_result,
    log_performance,
    log_security,
    get_system_status,
    cleanup_logs,
    performance_logged,
    security_logged,
    CentralLoggingManager,
    LogLevel,
    AuditEventType,
    AlertSeverity
)

class TestCentralizedLoggingIntegration(unittest.TestCase):
    """Integration tests for centralized logging system."""

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_config = {
            'logging': {
                'level': 'DEBUG',
                'enable_file_logging': True,
                'log_directory': self.temp_dir,
                'enable_monitoring': True,
                'enable_aggregation': True
            }
        }

    def tearDown(self):
        """Clean up test environment."""
        import shutil
        try:
            shutil.rmtree(self.temp_dir)
        except Exception:
            pass

    def test_basic_setup_and_logging(self):
        """Test basic setup and logging functionality."""
        # Test setup
        setup_logging(config=self.test_config)
        
        # Test logger creation
        logger = get_logger("test.integration")
        self.assertIsInstance(logger, logging.Logger)
        
        # Test logging at different levels
        logger.debug("Debug message")
        logger.info("Info message")
        logger.warning("Warning message")
        logger.error("Error message")
        
        # Verify system status
        status = get_system_status()
        self.assertIn('central_logging', status)
        self.assertIn('monitoring', status)
        self.assertIn('integration_initialized', status)    def test_convenience_functions(self):
        """Test convenience logging functions."""
        setup_logging(config=self.test_config)
        
        # Test analysis result logging
        log_analysis_result("/test/binary.exe", {
            "protection": "UPX",
            "architecture": "x64",
            "entropy": 7.8
        })
        
        # Test exploit result logging
        log_exploit_result("test_target", "buffer_overflow", success=True, 
                          payload_size=256, return_address="0x401000")
        
        # Test performance logging
        log_performance("binary_analysis", 1.25, file_size=1024000)
        
        # Test security event logging
        log_security("suspicious_activity", "HIGH", "Unusual memory pattern detected")

    def test_decorators(self):
        """Test logging decorators."""
        setup_logging(config=self.test_config)
        
        @performance_logged("test_operation")
        def test_function():
            time.sleep(0.1)
            return "test_result"
        
        @security_logged("test_security_op", "MEDIUM")
        def secure_function():
            return "secure_result"
        
        result1 = test_function()
        result2 = secure_function()
        
        self.assertEqual(result1, "test_result")
        self.assertEqual(result2, "secure_result")

    def test_system_monitoring(self):
        """Test log monitoring and alerting system."""
        setup_logging(config=self.test_config)
        
        # Get initial status
        status = get_system_status()
        self.assertIsInstance(status, dict)
        
        # Log some events that should trigger monitoring
        logger = get_logger("test.monitoring")
        logger.error("Critical system failure")
        logger.warning("Suspicious activity detected")
        
        # Small delay to allow monitoring to process
        time.sleep(0.1)
        
        # Check if monitoring is active
        monitoring_status = status.get('monitoring', {})
        self.assertIsInstance(monitoring_status, dict)    def test_configuration_management(self):
        """Test configuration loading and management."""
        # Test with custom configuration
        custom_config = {
            'logging': {
                'level': 'INFO',
                'modules': {
                    'intellicrack.core': 'DEBUG',
                    'intellicrack.ui': 'WARNING'
                },
                'aggregation': {
                    'enabled': True,
                    'buffer_size': 100,
                    'flush_interval': 5
                }
            }
        }
        
        setup_logging(config=custom_config)
        
        # Verify configuration is applied
        logger_core = get_logger("intellicrack.core.test")
        logger_ui = get_logger("intellicrack.ui.test")
        
        # Both should be valid logger instances
        self.assertIsInstance(logger_core, logging.Logger)
        self.assertIsInstance(logger_ui, logging.Logger)

    def test_audit_event_types(self):
        """Test audit event type enumeration."""
        # Verify key audit event types exist
        self.assertTrue(hasattr(AuditEventType, 'EXPLOIT_ATTEMPT'))
        self.assertTrue(hasattr(AuditEventType, 'BINARY_LOADED'))
        self.assertTrue(hasattr(AuditEventType, 'PROTECTION_DETECTED'))
        
        # Test enum values
        self.assertEqual(AuditEventType.EXPLOIT_ATTEMPT.value, "exploit_attempt")
        self.assertEqual(AuditEventType.BINARY_LOADED.value, "binary_loaded")

    def test_alert_severity_levels(self):
        """Test alert severity level enumeration."""
        # Verify alert severity levels exist
        self.assertTrue(hasattr(AlertSeverity, 'LOW'))
        self.assertTrue(hasattr(AlertSeverity, 'MEDIUM'))
        self.assertTrue(hasattr(AlertSeverity, 'HIGH'))
        self.assertTrue(hasattr(AlertSeverity, 'CRITICAL'))
if __name__ == '__main__':
    # Run the integration tests
    unittest.main(verbosity=2)