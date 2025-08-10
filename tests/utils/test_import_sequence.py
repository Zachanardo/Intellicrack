#!/usr/bin/env python
"""Debug script to trace exact import sequence."""

import sys
import os

# Add project root to path
sys.path.insert(0, "C:/Intellicrack")

print("Starting Intellicrack module-by-module import debug...")

try:
    print("\n1. Testing torch_gil_safety...")
    from intellicrack.utils.torch_gil_safety import initialize_gil_safety
    initialize_gil_safety()
    print("   ✓ GIL safety initialized")
    
    print("\n2. Testing config import...")
    from intellicrack.config import CONFIG, get_config
    print("   ✓ Config imported")
    
    print("\n3. Testing GPU autoloader...")
    from intellicrack.utils.gpu_autoloader import get_device, get_gpu_info, gpu_autoloader
    print("   ✓ GPU autoloader imported")
    
    print("\n4. Running GPU setup...")
    result = gpu_autoloader.setup()
    print(f"   ✓ GPU setup completed: {result}")
    
    print("\n5. Getting GPU info...")
    gpu_info = get_gpu_info()
    print(f"   ✓ GPU info: {gpu_info}")
    
    print("\n6. Getting config instance...")
    _config = get_config()
    print(f"   ✓ Config instance: {_config is not None}")
    
    if _config:
        print("\n7. Validating config...")
        valid = _config.validate_config()
        print(f"   ✓ Config valid: {valid}")
    
    print("\n8. Testing main module import...")
    from intellicrack.main import main
    print("   ✓ Main imported")
    
    print("\n9. Testing UI main_app import...")
    from intellicrack.ui.main_app import IntellicrackApp
    print("   ✓ IntellicrackApp imported")
    
    print("\n10. Testing core modules import...")
    from intellicrack import ai, core, utils
    print("   ✓ Core modules imported")
    
    print("\n11. Testing UI module import...")
    from intellicrack import ui
    print("   ✓ UI module imported")
    
    print("\n12. Testing plugins module import...")
    from intellicrack import plugins
    print("   ✓ Plugins module imported")
    
    print("\n✅ All imports successful!")
    
except Exception as e:
    import traceback
    print(f"\n❌ Error during import: {e}")
    print("\nFull traceback:")
    traceback.print_exc()
    sys.exit(1)