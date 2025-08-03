#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    print("Testing basic import...")
    from intellicrack.core.logging import setup_logging, get_logger
    print("SUCCESS: Basic import works")
    
    print("Testing setup...")
    setup_logging()
    print("SUCCESS: Setup completed")
    
    print("Testing logger creation...")
    logger = get_logger("test")
    print("SUCCESS: Logger created")
    
    print("Testing log message...")
    logger.info("Test message from centralized logging")
    print("SUCCESS: Log message sent")
    
    print("All tests passed!")
    
except Exception as e:
    print(f"ERROR: {e}")
    import traceback
    traceback.print_exc()