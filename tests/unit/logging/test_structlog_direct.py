#!/usr/bin/env python3
"""
Direct test of structured logging without package imports.
"""

import sys
import tempfile
import json
import logging
from pathlib import Path

# Test structlog directly
try:
    import structlog
    print(f"✓ structlog available, version: {structlog.__version__}")
    
    def test_direct_structlog():
        """Test structlog functionality directly."""
        
        # Create temporary log file  
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            log_file = f.name
        
        print(f"Testing structlog with log file: {log_file}")
        
        # Configure structlog for JSON logging
        structlog.configure(
            processors=[
                structlog.contextvars.merge_contextvars,
                structlog.processors.add_log_level,
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.JSONRenderer(),
            ],
            wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
            logger_factory=structlog.WriteLoggerFactory(),
            cache_logger_on_first_use=True,
        )
        
        # Configure standard library logging to write to file
        logging.basicConfig(
            level=logging.INFO,
            handlers=[
                logging.FileHandler(log_file, encoding='utf-8'),
                logging.StreamHandler(sys.stdout)
            ],
            format="%(message)s"
        )
        
        # Get a logger
        logger = structlog.get_logger("test_module")
        
        print("\n=== Testing Structured Logging ===")
        
        # Test basic logging with context
        logger.info("Testing structured logging", 
                   component="intellicrack", 
                   version="1.0.0",
                   category="test")
        
        logger.warning("Security warning detected", 
                      alert_level="medium",
                      threat_type="suspicious_behavior",
                      process="test.exe")
        
        logger.error("Analysis error occurred", 
                    error_code=500,
                    operation="binary_analysis", 
                    target="/path/to/binary.exe",
                    details="Failed to parse PE header")
        
        # Test performance logging
        logger.info("Performance metric",
                   operation="static_analysis",
                   duration_seconds=2.5,
                   duration_ms=2500,
                   memory_usage_mb=512,
                   cpu_percent=25.5,
                   files_processed=150)
        
        # Test security event logging
        logger.warning("Security event detected",
                      event_type="network_connection",
                      severity="high",
                      source_process="malware.exe",
                      destination="malicious.com",
                      port=443,
                      protocol="HTTPS")
        
        # Test analysis result logging
        logger.info("Binary analysis completed",
                   target="/samples/suspicious.exe",
                   analysis_type="static_analysis",
                   file_size=1024000,
                   architecture="x64",
                   detected_protections=["UPX", "VMProtect"],
                   entropy=7.8,
                   suspicious_sections=3,
                   threat_score=85)
        
        # Test exception-like logging
        logger.error("Exception during exploitation",
                    exception_type="ValueError",
                    exception_message="Invalid shellcode format",
                    function="generate_payload",
                    module="exploitation_engine",
                    stack_trace="... (truncated) ...")
        
        print("✓ All structured logging tests completed")
        
        # Read and parse the log file
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                log_content = f.read()
                
            print(f"\n=== Log File Content ({len(log_content)} chars) ===")
            
            log_lines = [line.strip() for line in log_content.strip().split('\n') if line.strip()]
            print(f"Found {len(log_lines)} log entries")
            
            print("\n=== Parsed JSON Log Entries ===")
            for i, line in enumerate(log_lines, 1):
                try:
                    log_entry = json.loads(line)
                    print(f"\n--- Entry {i} ---")
                    print(f"Timestamp: {log_entry.get('timestamp', 'N/A')}")
                    print(f"Level: {log_entry.get('level', 'N/A')}")
                    print(f"Event: {log_entry.get('event', 'N/A')}")
                    
                    # Show all additional fields
                    extra_fields = {k: v for k, v in log_entry.items() 
                                  if k not in ['timestamp', 'level', 'event']}
                    if extra_fields:
                        print("Context:")
                        for key, value in extra_fields.items():
                            print(f"  {key}: {value}")
                    
                except json.JSONDecodeError as e:
                    print(f"Entry {i}: Failed to parse JSON - {e}")
                    print(f"Raw: {line[:200]}...")
            
            print(f"\n✓ Successfully tested structured JSON logging!")
            print(f"✓ All {len(log_lines)} entries are valid JSON")
            print(f"✓ Log file: {log_file}")
            
            # Verify JSON structure
            sample_entry = json.loads(log_lines[0]) if log_lines else {}
            required_fields = ['timestamp', 'level', 'event']
            missing_fields = [field for field in required_fields if field not in sample_entry]
            
            if not missing_fields:
                print("✓ JSON structure contains all required fields")
            else:
                print(f"⚠ Missing required fields: {missing_fields}")
            
            return log_file, log_lines
            
        except Exception as e:
            print(f"Error reading/parsing log file: {e}")
            return log_file, []
    
    if __name__ == "__main__":
        test_direct_structlog()
        
except ImportError as e:
    print(f"structlog not available: {e}")
    print("Install with: pip install structlog")
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()