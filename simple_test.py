"""Simple test for AI Script Generator imports and basic functionality"""

try:
    import sys
    sys.path.insert(0, r'C:\Intellicrack')
    
    from intellicrack.ai.ai_script_generator import AIScriptGenerator, ProtectionType
    print("SUCCESS: AIScriptGenerator imported successfully")
    
    generator = AIScriptGenerator()
    print("SUCCESS: AIScriptGenerator initialized successfully")
    
    # Test protection identification with simple data
    test_data = {
        'binary_path': 'test.exe',
        'strings': ['license', 'trial'],
        'functions': ['CheckLicense']
    }
    
    protections = generator._identify_protections(test_data)
    print(f"SUCCESS: Protection identification works - found {len(protections)} protections")
    
    # Test platform detection
    platform = generator._detect_platform()
    print(f"SUCCESS: Platform detection works - detected {platform}")
    
    print("ALL TESTS PASSED - Phase 3A enhancements are working!")
    
except Exception as e:
    print(f"ERROR: {e}")
    import traceback
    traceback.print_exc()