#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

result_file = "logging_test_result.txt"

try:
    from intellicrack.core.logging import setup_logging, get_logger
    setup_logging()
    logger = get_logger("test")
    logger.info("Test message from centralized logging")
    
    with open(result_file, "w") as f:
        f.write("SUCCESS: Centralized logging system is working!\n")
        f.write("- Imports successful\n")
        f.write("- Setup completed\n") 
        f.write("- Logger created and used\n")
    
except Exception as e:
    with open(result_file, "w") as f:
        f.write(f"ERROR: {e}\n")
        import traceback
        f.write(traceback.format_exc())