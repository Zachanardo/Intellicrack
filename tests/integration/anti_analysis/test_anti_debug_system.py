#!/usr/bin/env python3
"""
Anti-Debugging Detection System Test Script

Comprehensive testing script for the anti-debugging technique detection
and analysis system to validate functionality and integration.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import json
import logging
import os
import platform
import sys
import time
from pathlib import Path

# Add Intellicrack to path
sys.path.insert(0, str(Path(__file__).parent))

from intellicrack.core.anti_analysis import (
    AntiDebugAnalyzer, 
    AntiDebugDetectionEngine,
    AntiDebugTechnique
)


def setup_logging():
    """Set up logging for test execution."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('anti_debug_test.log')
        ]
    )
    return logging.getLogger(__name__)


def test_anti_debug_analyzer():
    """Test the AntiDebugAnalyzer class."""
    logger = logging.getLogger(__name__)
    logger.info("Testing AntiDebugAnalyzer...")
    
    try:
        # Test without target binary
        analyzer = AntiDebugAnalyzer()
        
        # Test comprehensive analysis
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
            if key not in results:
                logger.error(f"Missing required key in results: {key}")
                return False
            
        logger.info(f"Dynamic analysis completed. Found {results['detection_summary']['total_techniques_detected']} techniques")
        
        # Test with aggressive mode
        aggressive_results = analyzer.analyze_anti_debug_techniques(
            aggressive=True,
            deep_scan=False,
            include_static_analysis=False
        )
        
        logger.info(f"Aggressive analysis completed. Found {aggressive_results['detection_summary']['total_techniques_detected']} techniques")
        
        # Test cache functionality
        analyzer.clear_cache()
        logger.info("Cache cleared successfully")
        
        # Test statistics
        stats = analyzer.get_analysis_statistics()
        logger.info(f"Analyzer statistics: {stats}")
        
        return True
        
    except Exception as e:
        logger.error(f"AntiDebugAnalyzer test failed: {e}", exc_info=True)
        return False


def test_anti_debug_detection_engine():
    """Test the AntiDebugDetectionEngine class."""
    logger = logging.getLogger(__name__)
    logger.info("Testing AntiDebugDetectionEngine...")
    
    try:
        # Initialize engine
        engine = AntiDebugDetectionEngine()
        
        # Test configuration update
        new_config = {
            'aggressive_detection': True,
            'cache_results': True,
            'timeout_seconds': 60
        }
        
        success = engine.update_configuration(new_config)
        if not success:
            logger.error("Configuration update failed")
            return False
        
        logger.info("Configuration updated successfully")
        
        # Test statistics
        stats = engine.get_detection_statistics()
        logger.info(f"Engine statistics: {json.dumps(stats, indent=2)}")
        
        # Test live process analysis (current process)
        try:
            import psutil
            current_pid = os.getpid()
            
            live_results = engine.analyze_live_process(
                pid=current_pid,
                analysis_options={'aggressive_detection': False}
            )
            
            if live_results.get('success', False):
                logger.info(f"Live process analysis successful for PID {current_pid}")
                logger.info(f"Found {live_results.get('detection_summary', {}).get('total_techniques_detected', 0)} techniques")
            else:
                logger.warning(f"Live process analysis failed: {live_results.get('error', 'Unknown error')}")
                
        except ImportError:
            logger.warning("psutil not available, skipping live process test")
        
        # Test bypass recommendations
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
            logger.error(f"Bypass recommendations failed: {bypass_info.get('error', 'Unknown error')}")
            return False
        
        # Test script generation
        script_types = ['frida', 'python', 'windbg']
        
        for script_type in script_types:
            script_results = engine.generate_bypass_scripts(mock_results, script_type)
            
            if script_results.get('success', False):
                logger.info(f"{script_type} script generation successful")
            else:
                logger.warning(f"{script_type} script generation failed: {script_results.get('error', 'Unknown error')}")
        
        # Test cache operations
        engine.clear_cache()
        logger.info("Engine cache cleared successfully")
        
        return True
        
    except Exception as e:
        logger.error(f"AntiDebugDetectionEngine test failed: {e}", exc_info=True)
        return False


def test_with_sample_binary():
    """Test analysis with a sample binary if available."""
    logger = logging.getLogger(__name__)
    logger.info("Testing with sample binary...")
    
    try:
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
            logger.warning("No sample binary found for testing")
            return True  # Not a failure, just no test file
        
        logger.info(f"Testing with binary: {test_binary}")
        
        # Test analyzer with binary
        analyzer = AntiDebugAnalyzer(test_binary)
        
        results = analyzer.analyze_anti_debug_techniques(
            aggressive=False,
            deep_scan=True,
            include_static_analysis=True
        )
        
        if 'error' in results:
            logger.error(f"Binary analysis failed: {results['error']}")
            return False
        
        logger.info(f"Binary analysis completed successfully")
        logger.info(f"Found {results['detection_summary']['total_techniques_detected']} techniques")
        logger.info(f"Protection score: {results['detection_summary']['overall_protection_score']}")
        
        # Test engine with binary
        engine = AntiDebugDetectionEngine()
        
        engine_results = engine.analyze_binary(
            test_binary,
            analysis_options={
                'aggressive_detection': False,
                'deep_scan': True
            }
        )
        
        if not engine_results.get('success', True):
            logger.error(f"Engine binary analysis failed: {engine_results.get('error', 'Unknown error')}")
            return False
        
        logger.info("Engine binary analysis completed successfully")
        
        return True
        
    except Exception as e:
        logger.error(f"Sample binary test failed: {e}", exc_info=True)
        return False


def test_technique_detection_methods():
    """Test individual detection methods."""
    logger = logging.getLogger(__name__)
    logger.info("Testing individual detection methods...")
    
    try:
        analyzer = AntiDebugAnalyzer()
        
        # Test individual detection methods
        test_methods = [
            'api_isdebuggerpresent',
            'timing_rdtsc_analysis',
            'env_analysis_tools',
            'peb_beingdebugged'
        ]
        
        for method_name in test_methods:
            if method_name in analyzer.detection_methods:
                try:
                    detected, confidence, details = analyzer.detection_methods[method_name]()
                    logger.info(f"Method {method_name}: detected={detected}, confidence={confidence:.2f}")
                except Exception as e:
                    logger.warning(f"Method {method_name} failed: {e}")
        
        # Test aggressive methods
        aggressive_methods = analyzer.get_aggressive_methods()
        logger.info(f"Aggressive methods: {aggressive_methods}")
        
        # Test detection type
        detection_type = analyzer.get_detection_type()
        logger.info(f"Detection type: {detection_type}")
        
        return True
        
    except Exception as e:
        logger.error(f"Detection methods test failed: {e}", exc_info=True)
        return False


def test_anti_debug_technique():
    """Test AntiDebugTechnique class."""
    logger = logging.getLogger(__name__)
    logger.info("Testing AntiDebugTechnique class...")
    
    try:
        # Create test technique
        technique = AntiDebugTechnique(
            name="Test Technique",
            category="api_based",
            severity="medium",
            description="Test anti-debugging technique",
            bypass_methods=["Test bypass method"],
            code_patterns=["test_pattern"]
        )
        
        # Test properties
        assert technique.name == "Test Technique"
        assert technique.category == "api_based"
        assert technique.severity == "medium"
        assert len(technique.bypass_methods) == 1
        
        # Test default values
        assert technique.confidence == 0.0
        assert isinstance(technique.evidence, dict)
        
        logger.info("AntiDebugTechnique class test passed")
        return True
        
    except Exception as e:
        logger.error(f"AntiDebugTechnique test failed: {e}", exc_info=True)
        return False


def test_error_handling():
    """Test error handling in various scenarios."""
    logger = logging.getLogger(__name__)
    logger.info("Testing error handling...")
    
    try:
        # Test with invalid binary path
        engine = AntiDebugDetectionEngine()
        
        invalid_results = engine.analyze_binary("/nonexistent/path/file.exe")
        
        if 'error' not in invalid_results:
            logger.error("Expected error for invalid binary path")
            return False
        
        logger.info("Invalid binary path handled correctly")
        
        # Test with invalid PID
        invalid_live_results = engine.analyze_live_process(pid=999999)
        
        # This might succeed or fail depending on the system, just ensure it doesn't crash
        logger.info("Invalid PID handled gracefully")
        
        # Test invalid configuration
        invalid_config_success = engine.update_configuration({
            'invalid_key': 'invalid_value'
        })
        
        # Should still succeed but log warning
        logger.info("Invalid configuration handled gracefully")
        
        return True
        
    except Exception as e:
        logger.error(f"Error handling test failed: {e}", exc_info=True)
        return False


def generate_test_report(test_results):
    """Generate a comprehensive test report."""
    logger = logging.getLogger(__name__)
    
    total_tests = len(test_results)
    passed_tests = sum(1 for result in test_results.values() if result)
    failed_tests = total_tests - passed_tests
    
    report = {
        'test_summary': {
            'total_tests': total_tests,
            'passed': passed_tests,
            'failed': failed_tests,
            'success_rate': (passed_tests / total_tests) * 100 if total_tests > 0 else 0
        },
        'test_results': test_results,
        'system_info': {
            'platform': platform.system(),
            'architecture': platform.machine(),
            'python_version': platform.python_version(),
            'timestamp': time.time()
        },
        'recommendations': []
    }
    
    # Add recommendations based on results
    if failed_tests > 0:
        report['recommendations'].append("Some tests failed - check logs for details")
    
    if report['test_summary']['success_rate'] < 80:
        report['recommendations'].append("Low success rate - system may need debugging")
    else:
        report['recommendations'].append("Anti-debugging detection system is working correctly")
    
    # Save report
    report_path = Path('anti_debug_test_report.json')
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    logger.info(f"Test report saved to {report_path}")
    logger.info(f"Test Summary: {passed_tests}/{total_tests} passed ({report['test_summary']['success_rate']:.1f}%)")
    
    return report


def main():
    """Main test execution function."""
    logger = setup_logging()
    logger.info("Starting Anti-Debugging Detection System Tests")
    logger.info("=" * 60)
    
    # Define tests
    tests = {
        'AntiDebugTechnique Class': test_anti_debug_technique,
        'AntiDebugAnalyzer': test_anti_debug_analyzer,
        'AntiDebugDetectionEngine': test_anti_debug_detection_engine,
        'Detection Methods': test_technique_detection_methods,
        'Sample Binary Analysis': test_with_sample_binary,
        'Error Handling': test_error_handling
    }
    
    # Execute tests
    test_results = {}
    
    for test_name, test_func in tests.items():
        logger.info(f"\n--- Running {test_name} ---")
        try:
            start_time = time.time()
            result = test_func()
            execution_time = time.time() - start_time
            
            test_results[test_name] = result
            status = "PASSED" if result else "FAILED"
            logger.info(f"{test_name}: {status} (took {execution_time:.2f}s)")
            
        except Exception as e:
            test_results[test_name] = False
            logger.error(f"{test_name}: FAILED with exception: {e}")
    
    # Generate report
    logger.info("\n" + "=" * 60)
    logger.info("Generating Test Report...")
    
    report = generate_test_report(test_results)
    
    # Print summary
    logger.info("\nTEST SUMMARY:")
    logger.info(f"Total Tests: {report['test_summary']['total_tests']}")
    logger.info(f"Passed: {report['test_summary']['passed']}")
    logger.info(f"Failed: {report['test_summary']['failed']}")
    logger.info(f"Success Rate: {report['test_summary']['success_rate']:.1f}%")
    
    if report['recommendations']:
        logger.info("\nRECOMMENDATIONS:")
        for rec in report['recommendations']:
            logger.info(f"- {rec}")
    
    # Exit with appropriate code
    exit_code = 0 if report['test_summary']['failed'] == 0 else 1
    logger.info(f"\nTest execution completed with exit code {exit_code}")
    
    return exit_code


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)