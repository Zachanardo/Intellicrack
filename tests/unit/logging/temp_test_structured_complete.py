#!/usr/bin/env python3
"""Test structured logging implementation completeness."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'intellicrack'))

def test_structured_logging():
    """Test all structured logging functions."""
    from intellicrack.utils.structured_logging import (
        configure_structured_logging, 
        get_structured_logger,
        log_performance_metric,
        bind_context,
        clear_context
    )
    
    # Configure structured logging for testing
    configure_structured_logging(
        level="INFO",
        enable_json=True,
        enable_console=True
    )
    
    logger = get_structured_logger()
    
    print("Testing structured logging completeness...")
    
    # Test basic logging
    logger.info("Basic structured log test", module="test_module", category="testing")
    
    # Test context binding
    bind_context(test_session="session_123", environment="test")
    logger.info("Log with bound context", operation="context_test")
    
    # Test performance metric (the previously missing function)
    log_performance_metric("database_query", 45.2, "ms", query_type="SELECT")
    
    # Clear context
    clear_context()
    logger.info("Log after context clear", operation="cleanup_test")
    
    print("✅ All structured logging functions are working correctly!")

if __name__ == "__main__":
    test_structured_logging()