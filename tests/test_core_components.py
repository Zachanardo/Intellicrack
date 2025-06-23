#!/usr/bin/env python3
"""
Direct test of core Intellicrack components without full import chain
"""

import sys
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_binary_analysis():
    """Test binary analysis directly."""
    try:
        # Import only what we need
        sys.path.insert(0, '.')
        from intellicrack.utils.analysis.binary_analysis import analyze_binary
        
        binary_path = 'test_samples/linux_license_app'
        logger.info(f"Testing binary analysis on: {binary_path}")
        
        result = analyze_binary(binary_path)
        
        if result:
            logger.info("✅ Binary analysis successful")
            logger.info(f"   File type: {result.get('file_type', 'Unknown')}")
            logger.info(f"   Architecture: {result.get('architecture', 'Unknown')}")
            logger.info(f"   Strings found: {len(result.get('strings', []))}")
            logger.info(f"   Functions found: {len(result.get('functions', []))}")
            logger.info(f"   Imports found: {len(result.get('imports', []))}")
            return result
        else:
            logger.error("❌ Binary analysis failed")
            return None
            
    except Exception as e:
        logger.error(f"❌ Binary analysis error: {e}")
        import traceback
        traceback.print_exc()
        return None

def test_ai_script_generator():
    """Test AI script generator directly."""
    try:
        from intellicrack.ai.ai_script_generator import AIScriptGenerator
        
        logger.info("Testing AI script generator...")
        
        generator = AIScriptGenerator()
        
        # Create a test request
        script_request = {
            'target_binary': 'test_samples/linux_license_app',
            'method': 'frida',
            'bypass_license': True,
            'analysis_result': {
                'file_type': 'ELF',
                'architecture': 'x86_64',
                'functions': ['license_check', 'validate_key', 'main'],
                'imports': ['malloc', 'free', 'printf', 'strcmp'],
                'strings': ['LICENSE_KEY', 'INVALID_LICENSE', 'EXPIRED'],
                'protection_mechanisms': ['license_validation', 'expiry_check']
            }
        }
        
        result = generator.generate_frida_script(script_request)
        
        if result and result.get('script'):
            logger.info("✅ AI script generation successful")
            script = result['script']
            logger.info(f"   Script length: {len(script)} characters")
            logger.info(f"   Contains license bypass: {'license' in script.lower()}")
            logger.info(f"   Contains Frida API: {'Java.perform' in script or 'Interceptor.attach' in script}")
            return result
        else:
            logger.error("❌ AI script generation failed")
            return None
            
    except Exception as e:
        logger.error(f"❌ AI script generator error: {e}")
        import traceback
        traceback.print_exc()
        return None

def test_autonomous_agent():
    """Test autonomous agent directly."""
    try:
        from intellicrack.ai.autonomous_agent import AutonomousAgent
        
        logger.info("Testing autonomous agent...")
        
        agent = AutonomousAgent()
        
        # Test the request parsing
        user_request = "Generate a Frida script to bypass license checks in test_samples/linux_license_app"
        
        parsed_request = agent._parse_request(user_request)
        
        if parsed_request:
            logger.info("✅ Autonomous agent request parsing successful")
            logger.info(f"   Binary path: {parsed_request.get('binary_path')}")
            logger.info(f"   Tool: {parsed_request.get('tool')}")
            logger.info(f"   Action: {parsed_request.get('action')}")
            return parsed_request
        else:
            logger.error("❌ Autonomous agent parsing failed")
            return None
            
    except Exception as e:
        logger.error(f"❌ Autonomous agent error: {e}")
        import traceback
        traceback.print_exc()
        return None

def test_patching_system():
    """Test patching system directly."""
    try:
        from intellicrack.utils.patching.patch_generator import generate_patch
        
        logger.info("Testing patching system...")
        
        # Create a simple patch request
        patch_request = {
            'target_file': 'test_samples/linux_license_app',
            'patch_type': 'nop_instruction',
            'target_address': 0x1200,
            'description': 'NOP out license check'
        }
        
        result = generate_patch(patch_request)
        
        if result:
            logger.info("✅ Patch generation successful")
            logger.info(f"   Patch type: {result.get('type', 'Unknown')}")
            logger.info(f"   Target address: 0x{result.get('address', 0):X}")
            return result
        else:
            logger.error("❌ Patch generation failed")
            return None
            
    except Exception as e:
        logger.error(f"❌ Patching system error: {e}")
        import traceback
        traceback.print_exc()
        return None

def main():
    """Run all core component tests."""
    print("=== TESTING INTELLICRACK CORE COMPONENTS ===")
    
    results = {}
    
    # Test 1: Binary Analysis
    print("\n1. Testing Binary Analysis:")
    results['binary_analysis'] = test_binary_analysis()
    
    # Test 2: AI Script Generator
    print("\n2. Testing AI Script Generator:")
    results['script_generator'] = test_ai_script_generator()
    
    # Test 3: Autonomous Agent
    print("\n3. Testing Autonomous Agent:")
    results['autonomous_agent'] = test_autonomous_agent()
    
    # Test 4: Patching System
    print("\n4. Testing Patching System:")
    results['patching'] = test_patching_system()
    
    # Summary
    print("\n=== TEST RESULTS SUMMARY ===")
    successful_tests = sum(1 for result in results.values() if result is not None)
    total_tests = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result is not None else "❌ FAIL"
        print(f"{test_name}: {status}")
    
    print(f"\nOverall: {successful_tests}/{total_tests} tests passed")
    
    return results

if __name__ == '__main__':
    main()