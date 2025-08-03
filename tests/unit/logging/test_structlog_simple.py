#!/usr/bin/env python3
"""
Simple test script for structured logging functionality.
"""

import sys
import tempfile
import json
from pathlib import Path

# Direct import of the structured logging module
sys.path.insert(0, str(Path(__file__).parent))

try:
    from intellicrack.utils.structured_logging import (
        configure_structured_logging,
        get_structured_logger,
        bind_context,
        clear_context,
        log_exception,
        log_performance,
        log_security_event,
        log_analysis_result
    )
    
    def test_structured_logging():
        """Test structured logging functionality."""
        print("Testing structured logging...")
        
        # Create temporary log file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            log_file = f.name
        
        # Configure structured logging
        configure_structured_logging(
            level="DEBUG",
            log_file=log_file,
            enable_json=True,
            enable_console=True,
            enable_caller_info=True,
            enable_filtering=True
        )
        
        print(f"✓ Structured logging configured, log file: {log_file}")
        
        # Get a logger
        logger = get_structured_logger("test_module")
        
        # Test basic structured logging
        logger.info("Testing structured logging", component="test", version="1.0.0")
        logger.warning("This is a warning", alert_level="medium", category="security")
        logger.error("This is an error", error_code=500, details="Test error message")
        
        # Test context binding
        bind_context(session_id="test-123", user="test_user")
        logger.info("Message with bound context", operation="test_operation")
        
        # Clear context
        clear_context()
        logger.info("Message after clearing context")
        
        # Test specialized logging functions
        log_analysis_result(
            logger,
            target="/path/to/binary.exe",
            analysis_type="static_analysis",
            results={
                "file_size": 1024000,
                "architecture": "x64",
                "detected_protections": ["UPX", "VMProtect"],
                "entropy": 7.8,
                "suspicious_sections": 3
            },
            duration=2.5
        )
        
        log_security_event(
            logger,
            event_type="suspicious_behavior",
            severity="high",
            process_name="test.exe",
            behavior="network_connection",
            destination="malicious.com",
            timestamp="2025-01-01T12:00:00Z"
        )
        
        log_performance(
            logger,
            operation="binary_analysis",
            duration=2.5,
            memory_usage_mb=512,
            cpu_percent=25.5,
            files_processed=150
        )
        
        # Test exception logging
        try:
            raise ValueError("Test exception for structured logging")
        except Exception as e:
            log_exception(logger, e, operation="test_operation", context="exception_test")
        
        print("✓ All logging tests completed")
        
        # Read and display log content
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                log_content = f.read()
                print(f"\n=== Log Content ({len(log_content)} chars) ===")
                print(log_content)
                
                # Parse and display JSON logs
                print("\n=== Structured Log Entries ===")
                log_lines = [line.strip() for line in log_content.strip().split('\n') if line.strip()]
                
                for i, line in enumerate(log_lines, 1):
                    try:
                        log_entry = json.loads(line)
                        print(f"\nEntry {i}:")
                        print(f"  Level: {log_entry.get('level', 'UNKNOWN')}")
                        print(f"  Message: {log_entry.get('event', 'No message')}")
                        print(f"  Timestamp: {log_entry.get('timestamp', 'No timestamp')}")
                        print(f"  Module: {log_entry.get('module', 'No module')}")
                        print(f"  Function: {log_entry.get('function', 'No function')}")
                        
                        # Show additional context
                        context_keys = [k for k in log_entry.keys() 
                                      if k not in ['level', 'event', 'timestamp', 'module', 'function', 'line']]
                        if context_keys:
                            print(f"  Context: {', '.join(f'{k}={log_entry[k]}' for k in context_keys[:5])}")
                            
                    except json.JSONDecodeError as e:
                        print(f"Non-JSON line {i}: {line[:100]}...")
                        print(f"  JSON error: {e}")
                
                print(f"\n✓ Parsed {len(log_lines)} log entries")
                
        except Exception as e:
            print(f"Error reading log file: {e}")
        
        print(f"\n✓ Structured logging test completed successfully!")
        print(f"Log file: {log_file}")
        return log_file
    
    if __name__ == "__main__":
        test_structured_logging()
        
except ImportError as e:
    print(f"Import error: {e}")
    print("Make sure structlog is installed: pip install structlog")
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()