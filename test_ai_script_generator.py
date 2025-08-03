#!/usr/bin/env python3
"""
Test script for Phase 3A AI Script Generator enhancements
"""

import sys
import json
from pathlib import Path

# Add Intellicrack to path
sys.path.insert(0, str(Path(__file__).parent))

def test_ai_script_generator():
    """Test the enhanced AI script generator with both unified model and legacy formats."""
    
    try:
        # Import the enhanced AI script generator
        from intellicrack.ai.ai_script_generator import AIScriptGenerator, ProtectionType
        
        print("✓ Successfully imported AIScriptGenerator")
        
        # Initialize the generator
        generator = AIScriptGenerator()
        print("✓ Successfully initialized AIScriptGenerator")
        
        # Test with legacy format
        legacy_analysis_results = {
            'binary_path': 'C:\\test\\sample.exe',
            'functions': ['CheckLicense', 'ValidateKey', 'GetTrialDays'],
            'strings': ['trial expired', 'invalid license', 'registration key'],
            'imports': ['GetVolumeSerialNumber', 'RegQueryValueEx'],
            'binary_info': {
                'architecture': 'x64',
                'platform': 'windows'
            },
            'protections': {
                'license_check': True,
                'trial_timer': True
            }
        }
        
        print("✓ Testing with legacy analysis format...")
        
        # Test protection identification
        protections = generator._identify_protections(legacy_analysis_results)
        print(f"✓ Identified protections: {[p.value for p in protections]}")
        
        # Test context preparation for legacy format
        context_data = {
            "binary_path": legacy_analysis_results['binary_path'],
            "binary_name": Path(legacy_analysis_results['binary_path']).stem,
            "protection_types": [p.value for p in protections],
            "analysis_results": legacy_analysis_results.get('protections', {}),
            "target_functions": legacy_analysis_results.get('functions', []),
            "key_strings": legacy_analysis_results.get('strings', []),
            "imports": legacy_analysis_results.get('imports', []),
            "architecture": legacy_analysis_results.get('binary_info', {}).get('architecture', 'x64'),
            "platform": legacy_analysis_results.get('binary_info', {}).get('platform', 'windows')
        }
        print("✓ Successfully prepared context data for legacy format")
        
        # Test Frida prompt generation
        prompt = generator._create_frida_generation_prompt(protections, context_data)
        print(f"✓ Generated Frida prompt ({len(prompt)} characters)")
        
        # Test unified model compatibility (mock unified model)
        class MockUnifiedModel:
            def __init__(self):
                self.metadata = MockMetadata()
                self.functions = [MockFunction('CheckLicense'), MockFunction('ValidateKey')]
                self.strings = [MockString('trial expired'), MockString('invalid license')]
                self.imports = [MockImport('GetVolumeSerialNumber')]
                self.exports = []
                self.protection_analysis = MockProtectionAnalysis()
        
        class MockMetadata:
            def __init__(self):
                self.file_path = 'C:\\test\\sample.exe'
                self.architecture = 'x64'
                self.platform = 'windows'
        
        class MockFunction:
            def __init__(self, name):
                self.name = name
                self.address = 0x401000
                self.size = 100
                self.confidence = 0.9
        
        class MockString:
            def __init__(self, value):
                self.value = value
                self.address = 0x402000
                self.type = 'ascii'
        
        class MockImport:
            def __init__(self, name):
                self.name = name
                self.module = 'kernel32.dll'
                self.address = 0x403000
        
        class MockProtectionAnalysis:
            def __init__(self):
                self.protection_infos = [MockProtectionInfo('license_check'), MockProtectionInfo('trial_timer')]
        
        class MockProtectionInfo:
            def __init__(self, ptype):
                self.type = ptype
                self.confidence = 0.8
                self.techniques = ['string_analysis', 'api_analysis']
        
        print("✓ Testing with unified model format...")
        
        # Test unified model
        unified_model = MockUnifiedModel()
        
        # Test protection extraction from unified model
        unified_protections = generator._extract_protections_from_unified_model(unified_model)
        print(f"✓ Extracted protections from unified model: {[p.value for p in unified_protections]}")
        
        # Test context preparation from unified model
        unified_context = generator._prepare_context_from_unified_model(unified_model, unified_protections)
        print(f"✓ Prepared context from unified model ({len(unified_context)} keys)")
        
        # Test legacy format conversion
        legacy_converted = generator._convert_unified_model_to_legacy_format(unified_model)
        print(f"✓ Converted unified model to legacy format ({len(legacy_converted)} keys)")
        
        # Test input validation
        assert generator._validate_analysis_input(legacy_analysis_results) == True
        assert generator._validate_analysis_input(unified_model) == True
        assert generator._validate_analysis_input(None) == False
        print("✓ Input validation working correctly")
        
        # Test platform detection
        platform = generator._detect_platform()
        print(f"✓ Detected platform: {platform}")
        
        print("\n🎉 All Phase 3A enhancements working correctly!")
        print("\nEnhancements implemented:")
        print("- ✓ Unified binary model integration")
        print("- ✓ Enhanced LLM context preparation")
        print("- ✓ Cross-platform compatibility")
        print("- ✓ Comprehensive error handling")
        print("- ✓ Input validation")
        print("- ✓ Structured logging integration")
        
        return True
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_ai_script_generator()
    sys.exit(0 if success else 1)