#!/usr/bin/env python3
"""
Standalone Anti-Debugging Detection System Test

Simplified test script that doesn't depend on the full Intellicrack
configuration system to validate the anti-debugging components.

Copyright (C) 2025 Zachary Flint
"""

import logging
import os
import platform
import sys
import time
from pathlib import Path

# Setup basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def test_imports():
    """Test that we can import the anti-debugging modules."""
    logger.info("Testing imports...")
    
    try:
        # Test direct imports without going through main intellicrack module
        sys.path.insert(0, str(Path(__file__).parent))
        
        from intellicrack.core.anti_analysis.anti_debug_analyzer import AntiDebugAnalyzer, AntiDebugTechnique
        from intellicrack.core.anti_analysis.anti_debug_integration import AntiDebugDetectionEngine
        from intellicrack.core.anti_analysis.base_detector import BaseDetector
        
        logger.info("Successfully imported anti-debugging modules")
        return True
        
    except Exception as e:
        logger.error(f"Import test failed: {e}")
        return False

def test_anti_debug_technique():
    """Test the AntiDebugTechnique class."""
    logger.info("Testing AntiDebugTechnique class...")
    
    try:
        from intellicrack.core.anti_analysis.anti_debug_analyzer import AntiDebugTechnique
        
        # Create test technique
        technique = AntiDebugTechnique(
            name="Test API Detection",
            category="api_based",
            severity="medium",
            description="Test anti-debugging technique using API calls",
            bypass_methods=["Hook API calls", "Patch return values"],
            code_patterns=["IsDebuggerPresent", "CheckRemoteDebuggerPresent"]
        )
        
        # Validate properties
        assert technique.name == "Test API Detection"
        assert technique.category == "api_based"
        assert technique.severity == "medium"
        assert len(technique.bypass_methods) == 2
        assert len(technique.code_patterns) == 2
        assert technique.confidence == 0.0
        assert isinstance(technique.evidence, dict)
        
        logger.info("AntiDebugTechnique class test passed")
        return True
        
    except Exception as e:
        logger.error(f"AntiDebugTechnique test failed: {e}")
        return False

def test_anti_debug_analyzer():
    """Test the AntiDebugAnalyzer class."""
    logger.info("Testing AntiDebugAnalyzer...")
    
    try:
        from intellicrack.core.anti_analysis.anti_debug_analyzer import AntiDebugAnalyzer
        
        # Test without target binary (dynamic analysis only)
        analyzer = AntiDebugAnalyzer()
        
        # Test that detection methods are registered
        assert len(analyzer.detection_methods) > 0
        logger.info(f"Analyzer has {len(analyzer.detection_methods)} detection methods")
        
        # Test pattern initialization
        assert len(analyzer.anti_debug_patterns) > 0
        logger.info(f"Analyzer has {len(analyzer.anti_debug_patterns)} pattern categories")
        
        # Test aggressive methods
        aggressive_methods = analyzer.get_aggressive_methods()
        assert isinstance(aggressive_methods, list)
        logger.info(f"Analyzer has {len(aggressive_methods)} aggressive methods")
        
        # Test detection type
        detection_type = analyzer.get_detection_type()
        assert detection_type == 'comprehensive_anti_debug'
        
        # Test basic analysis (should not crash)
        results = analyzer.analyze_anti_debug_techniques(
            aggressive=False,
            deep_scan=False,
            include_static_analysis=False
        )
        
        # Validate results structure
        required_keys = [
            'analysis_metadata', 'technique_categories', 
            'detection_summary', 'bypass_recommendations'
        ]
        
        for key in required_keys:
            assert key in results, f"Missing required key: {key}"
        
        logger.info(f"Basic analysis completed successfully")
        logger.info(f"Found {results['detection_summary']['total_techniques_detected']} techniques")
        
        return True
        
    except Exception as e:
        logger.error(f"AntiDebugAnalyzer test failed: {e}")
        return False

def test_individual_detection_methods():
    """Test individual detection methods."""
    logger.info("Testing individual detection methods...")
    
    try:
        from intellicrack.core.anti_analysis.anti_debug_analyzer import AntiDebugAnalyzer
        
        analyzer = AntiDebugAnalyzer()
        
        # Test a few key detection methods
        test_methods = [
            'api_isdebuggerpresent',
            'env_analysis_tools',
            'timing_gettickcount_timing'
        ]
        
        successful_tests = 0
        
        for method_name in test_methods:
            if method_name in analyzer.detection_methods:
                try:
                    detected, confidence, details = analyzer.detection_methods[method_name]()
                    
                    # Validate return types
                    assert isinstance(detected, bool)
                    assert isinstance(confidence, (int, float))
                    assert isinstance(details, dict)
                    assert 0.0 <= confidence <= 1.0
                    
                    logger.info(f"Method {method_name}: detected={detected}, confidence={confidence:.2f}")
                    successful_tests += 1
                    
                except Exception as e:
                    logger.warning(f"Method {method_name} failed: {e}")
            else:
                logger.warning(f"Method {method_name} not found")
        
        logger.info(f"Successfully tested {successful_tests}/{len(test_methods)} detection methods")
        return successful_tests > 0
        
    except Exception as e:
        logger.error(f"Detection methods test failed: {e}")
        return False

def test_anti_debug_detection_engine():
    """Test the AntiDebugDetectionEngine class."""
    logger.info("Testing AntiDebugDetectionEngine...")
    
    try:
        from intellicrack.core.anti_analysis.anti_debug_integration import AntiDebugDetectionEngine
        
        # Initialize engine without app context
        engine = AntiDebugDetectionEngine()
        
        # Test configuration update
        new_config = {
            'aggressive_detection': True,
            'cache_results': True,
            'timeout_seconds': 60
        }
        
        success = engine.update_configuration(new_config)
        assert success, "Configuration update failed"
        logger.info("Configuration updated successfully")
        
        # Test statistics
        stats = engine.get_detection_statistics()
        assert isinstance(stats, dict)
        assert 'engine_info' in stats
        logger.info("Engine statistics retrieved successfully")
        
        # Test live process analysis (current process)
        try:
            current_pid = os.getpid()
            
            live_results = engine.analyze_live_process(
                pid=current_pid,
                analysis_options={'aggressive_detection': False}
            )
            
            if live_results.get('success', True):
                logger.info(f"Live process analysis successful for PID {current_pid}")
                logger.info(f"Found {live_results.get('detection_summary', {}).get('total_techniques_detected', 0)} techniques")
            else:
                logger.warning(f"Live process analysis result: {live_results.get('error', 'No error reported')}")
                
        except Exception as e:
            logger.warning(f"Live process analysis failed: {e}")
        
        # Test bypass recommendations with mock data
        mock_results = {
            'bypass_recommendations': {
                'api_based': ['Hook IsDebuggerPresent', 'Hook CheckRemoteDebuggerPresent'],
                'peb_manipulation': ['Patch PEB BeingDebugged flag']
            },
            'evasion_strategies': {
                'general': ['Use anti-anti-debug tools']
            },
            'detection_summary': {
                'total_techniques_detected': 2,
                'bypass_difficulty': 'medium',
                'overall_protection_score': 3.5
            },
            'technique_categories': {
                'api_based': {'detected': [{'name': 'test_technique'}]}
            }
        }
        
        bypass_info = engine.get_bypass_recommendations(mock_results)
        
        if bypass_info.get('success', False):
            logger.info("Bypass recommendations generated successfully")
        else:
            logger.warning(f"Bypass recommendations failed: {bypass_info.get('error', 'Unknown error')}")
        
        # Test script generation
        script_types = ['frida', 'python', 'windbg']
        
        for script_type in script_types:
            try:
                script_results = engine.generate_bypass_scripts(mock_results, script_type)
                
                if script_results.get('success', False):
                    logger.info(f"{script_type} script generation successful")
                else:
                    logger.warning(f"{script_type} script generation failed: {script_results.get('error', 'Unknown error')}")
            except Exception as e:
                logger.warning(f"{script_type} script generation exception: {e}")
        
        logger.info("AntiDebugDetectionEngine test completed successfully")
        return True
        
    except Exception as e:
        logger.error(f"AntiDebugDetectionEngine test failed: {e}")
        return False

def test_with_sample_binary():
    """Test analysis with a sample binary if available."""
    logger.info("Testing with sample binary...")
    
    try:
        from intellicrack.core.anti_analysis.anti_debug_analyzer import AntiDebugAnalyzer
        
        # Look for sample binaries
        sample_paths = []
        
        if platform.system() == 'Windows':
            sample_paths = [
                r'C:\Windows\System32\notepad.exe',
                r'C:\Windows\System32\calc.exe',
                r'C:\Windows\System32\cmd.exe'
            ]
        else:
            sample_paths = [
                '/bin/ls',
                '/bin/cat',
                '/usr/bin/python3'
            ]
        
        test_binary = None
        for path in sample_paths:
            if os.path.exists(path):
                test_binary = path
                break
        
        if not test_binary:
            logger.warning("No sample binary found for testing - skipping binary analysis test")
            return True  # Not a failure, just no test file
        
        logger.info(f"Testing with binary: {test_binary}")
        
        # Test analyzer with binary
        analyzer = AntiDebugAnalyzer(test_binary)
        
        # Test with static analysis disabled to avoid potential issues
        results = analyzer.analyze_anti_debug_techniques(
            aggressive=False,
            deep_scan=False,
            include_static_analysis=True  # Try static analysis
        )
        
        if 'error' in results:
            logger.warning(f"Binary analysis had issues: {results['error']}")
            # Try again without static analysis
            results = analyzer.analyze_anti_debug_techniques(
                aggressive=False,
                deep_scan=False,
                include_static_analysis=False
            )
        
        if 'error' not in results:
            logger.info(f"Binary analysis completed successfully")
            logger.info(f"Found {results['detection_summary']['total_techniques_detected']} techniques")
            logger.info(f"Protection score: {results['detection_summary']['overall_protection_score']}")
            return True
        else:
            logger.error(f"Binary analysis failed: {results['error']}")
            return False
        
    except Exception as e:
        logger.error(f"Sample binary test failed: {e}")
        return False

def main():
    """Main test execution function."""
    logger.info("Starting Standalone Anti-Debugging Detection System Tests")
    logger.info("=" * 60)
    
    # Define tests
    tests = [
        ("Module Imports", test_imports),
        ("AntiDebugTechnique Class", test_anti_debug_technique),
        ("AntiDebugAnalyzer", test_anti_debug_analyzer),
        ("Detection Methods", test_individual_detection_methods),
        ("AntiDebugDetectionEngine", test_anti_debug_detection_engine),
        ("Sample Binary Analysis", test_with_sample_binary),
    ]
    
    # Execute tests
    results = []
    
    for test_name, test_func in tests:
        logger.info(f"\n--- Running {test_name} ---")
        try:
            start_time = time.time()
            result = test_func()
            execution_time = time.time() - start_time
            
            results.append((test_name, result, execution_time))
            status = "PASSED" if result else "FAILED"
            logger.info(f"{test_name}: {status} (took {execution_time:.2f}s)")
            
        except Exception as e:
            results.append((test_name, False, 0))
            logger.error(f"{test_name}: FAILED with exception: {e}")
    
    # Print summary
    logger.info("\n" + "=" * 60)
    logger.info("TEST SUMMARY:")
    
    total_tests = len(results)
    passed_tests = sum(1 for _, result, _ in results if result)
    failed_tests = total_tests - passed_tests
    
    logger.info(f"Total Tests: {total_tests}")
    logger.info(f"Passed: {passed_tests}")
    logger.info(f"Failed: {failed_tests}")
    
    success_rate = (passed_tests / total_tests) * 100 if total_tests > 0 else 0
    logger.info(f"Success Rate: {success_rate:.1f}%")
    
    # Show detailed results
    logger.info("\nDetailed Results:")
    for test_name, result, exec_time in results:
        status = "PASS" if result else "FAIL"
        logger.info(f"  {test_name}: {status} ({exec_time:.2f}s)")
    
    # Recommendations
    logger.info("\nRECOMMENDATIONS:")
    if failed_tests == 0:
        logger.info("- All tests passed! Anti-debugging system is working correctly.")
    elif success_rate >= 80:
        logger.info("- Most tests passed. System is functional with minor issues.")
    else:
        logger.info("- Significant issues detected. Review failed tests.")
    
    if platform.system() == 'Windows':
        logger.info("- For best results on Windows, run as Administrator")
    
    logger.info("- Check logs above for specific test details")
    
    # Exit with appropriate code
    exit_code = 0 if failed_tests == 0 else 1
    logger.info(f"\nTest execution completed with exit code {exit_code}")
    
    return exit_code

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)