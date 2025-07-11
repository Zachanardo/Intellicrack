#!/usr/bin/env python3
"""Test launch script to check if Intellicrack can start properly."""

import os
import sys
import platform

def test_basic_import():
    """Test if basic imports work."""
    print("Testing basic Intellicrack imports...")
    try:
        # Test basic imports without GUI
        import intellicrack
        print("✓ intellicrack module imported successfully")
        
        from intellicrack.config import CONFIG
        print("✓ Config imported successfully")
        
        from intellicrack.core.analysis.binary_analyzer import BinaryAnalyzer
        print("✓ BinaryAnalyzer imported successfully")
        
        # Check platform
        print(f"\nPlatform information:")
        print(f"  System: {platform.system()}")
        print(f"  Python: {sys.version}")
        print(f"  Running in WSL: {'microsoft' in platform.uname().release.lower()}")
        
        return True
    except Exception as e:
        print(f"✗ Import error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_cli_components():
    """Test CLI components without GUI."""
    print("\nTesting CLI components...")
    try:
        from intellicrack.utils.analysis.binary_analysis import analyze_binary
        print("✓ Binary analysis functions available")
        
        from intellicrack.core.patching.payload_generator import PayloadGenerator
        generator = PayloadGenerator()
        print("✓ Payload generator initialized")
        
        # Test simple payload generation
        nop_sled = generator.generate_nop_sled(10)
        if len(nop_sled) == 10:
            print("✓ Payload generation working")
        
        return True
    except Exception as e:
        print(f"✗ CLI component error: {e}")
        return False

def main():
    """Main test function."""
    print("=== Intellicrack Launch Test ===\n")
    
    # Set environment for headless operation in WSL
    if 'microsoft' in platform.uname().release.lower():
        os.environ['QT_QPA_PLATFORM'] = 'offscreen'
        print("Detected WSL environment - using offscreen Qt backend\n")
    
    # Run tests
    import_ok = test_basic_import()
    cli_ok = test_cli_components() if import_ok else False
    
    print("\n=== Test Summary ===")
    print(f"Basic imports: {'PASSED' if import_ok else 'FAILED'}")
    print(f"CLI components: {'PASSED' if cli_ok else 'FAILED'}")
    
    if import_ok and cli_ok:
        print("\n✓ Intellicrack core components are working!")
        print("GUI launch may fail in WSL, but CLI functionality should work.")
        return 0
    else:
        print("\n✗ Some components failed to load.")
        return 1

if __name__ == "__main__":
    sys.exit(main())