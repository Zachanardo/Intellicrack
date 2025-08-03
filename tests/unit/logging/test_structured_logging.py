#!/usr/bin/env python3
"""
Test script for structured logging functionality in Intellicrack.
"""

import sys
import tempfile
import json
from pathlib import Path

# Add intellicrack to path
sys.path.insert(0, str(Path(__file__).parent / "intellicrack"))

try:
    from intellicrack.utils.logger import (
        initialize_logging,
        get_logger,
        log_message,
        log_analysis_operation,
        log_security_alert,
        log_performance_metric,
        STRUCTURED_LOGGING_AVAILABLE
    )
    
    def test_structured_logging():
        """Test structured logging functionality."""
        print(f"Structured logging available: {STRUCTURED_LOGGING_AVAILABLE}")
        
        # Create temporary log file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            log_file = f.name
        
        # Initialize structured logging
        initialize_logging(
            level="DEBUG",
            log_file=log_file,
            enable_structured=True,
            enable_json=True,
            enable_console=True
        )
        
        # Get a logger
        logger = get_logger("test_module")
        
        # Test basic logging
        logger.info("Testing structured logging", component="test", version="1.0.0")
        logger.warning("This is a warning", alert_level="medium")
        logger.error("This is an error", error_code=500, details="Test error")
        
        # Test specialized logging functions
        log_message("Simple message test", "INFO", category="test")
        
        log_analysis_operation(
            target="/path/to/binary.exe",
            operation="static_analysis",
            file_size=1024000,
            architecture="x64",
            detected_protections=["UPX", "VMProtect"]
        )
        
        log_security_alert(
            alert_type="suspicious_behavior",
            severity="high",
            process_name="test.exe",
            behavior="network_connection",
            destination="malicious.com"
        )
        
        log_performance_metric(
            operation="binary_analysis",
            duration=2.5,
            memory_usage=512000,
            cpu_percent=25.5
        )
        
        # Test exception logging
        try:
            raise ValueError("Test exception for logging")
        except Exception as e:
            logger.error("Exception occurred during test", exception=str(e), category="test_error")
        
        print(f"\nLog file created: {log_file}")
        
        # Read and display log content
        try:
            with open(log_file, 'r') as f:
                log_content = f.read()
                print("\n=== Log Content ===")
                print(log_content)
                
                # Try to parse JSON logs
                print("\n=== Parsed JSON Logs ===")
                for line in log_content.strip().split('\n'):
                    if line.strip():
                        try:
                            log_entry = json.loads(line)
                            print(f"Level: {log_entry.get('level', 'UNKNOWN')}")
                            print(f"Message: {log_entry.get('event', 'No message')}")
                            print(f"Timestamp: {log_entry.get('timestamp', 'No timestamp')}")
                            print(f"Module: {log_entry.get('module', 'No module')}")
                            print("---")
                        except json.JSONDecodeError:
                            print(f"Non-JSON line: {line}")
                            
        except Exception as e:
            print(f"Error reading log file: {e}")
        
        print("\n✓ Structured logging test completed!")
        return log_file
    
    if __name__ == "__main__":
        test_structured_logging()
        
except ImportError as e:
    print(f"Import error: {e}")
    print("Make sure you're running from the Intellicrack directory")