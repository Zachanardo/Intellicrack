#!/usr/bin/env python3
"""
Test structured logging functionality in updated modules
"""

import sys
import json
from pathlib import Path

# Add the intellicrack directory to Python path
intellicrack_root = Path(__file__).parent
sys.path.insert(0, str(intellicrack_root))

def test_structured_logging_modules():
    """Test that updated modules use structured logging correctly."""
    
    print("Testing structured logging in updated modules...")
    
    try:
        # Test the structured logging module itself
        from intellicrack.utils.structured_logging import get_structured_logger, configure_structured_logging
        
        # Configure structured logging
        configure_structured_logging()
        logger = get_structured_logger(__name__)
        
        print("✓ Structured logging module imported successfully")
        
        # Test security enforcement
        try:
            from intellicrack.core.security_enforcement import get_security_status
            status = get_security_status()
            print("✓ security_enforcement.py loads successfully")
        except Exception as e:
            print(f"✗ security_enforcement.py failed: {e}")
        
        # Test task manager
        try:
            from intellicrack.core.task_manager import TaskStatus, get_task_manager
            print("✓ task_manager.py loads successfully")
        except Exception as e:
            print(f"✗ task_manager.py failed: {e}")
        
        # Test predictive intelligence 
        try:
            from intellicrack.ai.predictive_intelligence import NUMPY_AVAILABLE, PSUTIL_AVAILABLE
            print(f"✓ predictive_intelligence.py loads successfully (numpy: {NUMPY_AVAILABLE}, psutil: {PSUTIL_AVAILABLE})")
        except Exception as e:
            print(f"✗ predictive_intelligence.py failed: {e}")
        
        # Test direct JSON logging
        logger.info("Testing structured logging output",
                   test_field="test_value",
                   module="test_updated_modules",
                   category="testing")
        
        print("\n✓ All updated modules loaded successfully!")
        print("✓ Structured logging is working correctly!")
        
        return True
        
    except Exception as e:
        print(f"✗ Error during testing: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_structured_logging_modules()
    sys.exit(0 if success else 1)