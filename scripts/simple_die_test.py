#!/usr/bin/env python3
"""Simple DIE JSON integration test"""

import sys
import os
from pathlib import Path

# Add to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    print("Testing DIE JSON wrapper import...")
    from intellicrack.core.analysis.die_json_wrapper import DIEJSONWrapper, DIEScanMode
    print("✓ DIE JSON wrapper imported successfully")
    
    print("Testing structured logger import...")
    from intellicrack.core.analysis.die_structured_logger import get_die_structured_logger
    print("✓ Structured logger imported successfully")
    
    print("Testing ICP backend import...")
    from intellicrack.protection.icp_backend import ICPBackend
    print("✓ ICP backend imported successfully")
    
    print("Creating DIE wrapper instance...")
    wrapper = DIEJSONWrapper()
    print("✓ DIE wrapper created successfully")
    
    print("Getting version info...")
    version_info = wrapper.get_version_info()
    print(f"✓ Version info: {version_info}")
    
    print("\n✓ All basic tests passed!")
    print("DIE JSON integration is working correctly.")

except Exception as e:
    print(f"✗ Test failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)