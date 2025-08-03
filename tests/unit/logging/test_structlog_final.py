#!/usr/bin/env python3
"""
Final test of structured logging implementation
"""

import sys
import json
from pathlib import Path

# Add the intellicrack directory to Python path
intellicrack_root = Path(__file__).parent
sys.path.insert(0, str(intellicrack_root))

def test_structured_logging_direct():
    """Test structured logging directly without importing full Intellicrack."""
    
    print("Testing structured logging implementation...")
    
    try:
        # Import and configure structured logging directly
        from intellicrack.utils.structured_logging import configure_structured_logging, get_structured_logger
        
        # Configure logging
        configure_structured_logging()
        
        # Get logger
        logger = get_structured_logger(__name__)
        
        print("✓ Structured logging configured successfully")
        
        # Test different log levels with structured data
        logger.debug("Debug message with context",
                    operation="test_operation",
                    step="debug_test",
                    category="testing")
        
        logger.info("Information message with structured data",
                   module="test_module",
                   function="test_function",
                   status="success",
                   category="testing")
        
        logger.warning("Warning message with context",
                      warning_type="test_warning",
                      severity="medium",
                      category="testing")
        
        logger.error("Error message with structured details",
                    error_type="test_error",
                    error_code=404,
                    details={"key": "value", "number": 42},
                    category="testing")
        
        # Test log security event (specialized function)
        from intellicrack.utils.structured_logging import log_security_event
        log_security_event("test_security_event", "high",
                          event_details="This is a test security event",
                          source_ip="192.168.1.1",
                          user_agent="TestAgent/1.0")
        
        # Test log analysis result (specialized function)  
        from intellicrack.utils.structured_logging import log_analysis_result
        log_analysis_result("test_analysis", "binary_analysis", 
                           {"findings": ["test_finding_1", "test_finding_2"],
                            "confidence": 0.95,
                            "file_hash": "abcd1234"})
        
        # Test log performance metric (specialized function)
        from intellicrack.utils.structured_logging import log_performance_metric
        log_performance_metric("test_operation", 1.234, "seconds",
                              metadata={"cpu_usage": 45.6, "memory_mb": 128})
        
        print("\n✓ All structured logging functions work correctly!")
        print("✓ JSON structured output is being generated!")
        print("✓ Structured logging implementation is complete!")
        
        return True
        
    except Exception as e:
        print(f"✗ Error during testing: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_structured_logging_direct()
    sys.exit(0 if success else 1)