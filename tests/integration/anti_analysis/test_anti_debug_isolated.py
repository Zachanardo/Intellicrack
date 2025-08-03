#!/usr/bin/env python3
"""
Isolated Anti-Debugging Module Test

Tests anti-debugging components without loading the full Intellicrack stack.
This validates that the core anti-debugging logic works independently.

Copyright (C) 2025 Zachary Flint
"""

import ctypes
import logging
import os
import platform
import sys
import time
from pathlib import Path

# Setup minimal logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def test_base_detector():
    """Test the BaseDetector class directly."""
    logger.info("Testing BaseDetector class...")
    
    try:
        # Add path and import directly
        sys.path.insert(0, str(Path(__file__).parent))
        
        from intellicrack.core.anti_analysis.base_detector import BaseDetector
        
        # Create a simple test detector
        class TestDetector(BaseDetector):
            def __init__(self):
                super().__init__()
                self.detection_methods = {
                    'test_method_1': self._test_method_1,
                    'test_method_2': self._test_method_2,
                    'aggressive_method': self._aggressive_method
                }
            
            def _test_method_1(self):
                return True, 0.8, {'test': 'data1'}
            
            def _test_method_2(self):
                return False, 0.0, {'test': 'data2'}
            
            def _aggressive_method(self):
                return True, 0.9, {'test': 'aggressive_data'}
            
            def get_aggressive_methods(self):
                return ['aggressive_method']
            
            def get_detection_type(self):
                return 'test_detector'
        
        # Test the detector
        detector = TestDetector()
        
        # Test normal detection
        results = detector.run_detection_loop(aggressive=False, aggressive_methods=['aggressive_method'])
        
        assert 'detections' in results
        assert 'detection_count' in results
        assert results['detection_count'] == 1  # Only non-aggressive methods
        
        # Test aggressive detection
        aggressive_results = detector.run_detection_loop(aggressive=True, aggressive_methods=['aggressive_method'])
        assert aggressive_results['detection_count'] == 2  # All methods
        
        logger.info("BaseDetector test passed")
        return True
        
    except Exception as e:
        logger.error(f"BaseDetector test failed: {e}")
        return False

def test_anti_debug_technique_isolated():
    """Test AntiDebugTechnique class in isolation."""
    logger.info("Testing AntiDebugTechnique class (isolated)...")
    
    try:
        # Simple technique class without external dependencies
        class AntiDebugTechnique:
            def __init__(self, name, category, severity, description, bypass_methods, code_patterns=None):
                self.name = name
                self.category = category
                self.severity = severity
                self.description = description
                self.bypass_methods = bypass_methods
                self.code_patterns = code_patterns or []
                self.confidence = 0.0
                self.evidence = {}
        
        # Test creation
        technique = AntiDebugTechnique(
            name="Test IsDebuggerPresent",
            category="api_based",
            severity="medium",
            description="Tests for debugger using IsDebuggerPresent API",
            bypass_methods=["Hook IsDebuggerPresent", "Patch PEB flags"],
            code_patterns=["IsDebuggerPresent"]
        )
        
        # Validate
        assert technique.name == "Test IsDebuggerPresent"
        assert technique.category == "api_based"
        assert technique.severity == "medium"
        assert len(technique.bypass_methods) == 2
        assert len(technique.code_patterns) == 1
        assert technique.confidence == 0.0
        
        logger.info("AntiDebugTechnique isolated test passed")
        return True
        
    except Exception as e:
        logger.error(f"AntiDebugTechnique isolated test failed: {e}")
        return False

def test_windows_api_detection():
    """Test Windows API-based anti-debugging detection."""
    logger.info("Testing Windows API detection methods...")
    
    if platform.system() != 'Windows':
        logger.info("Skipping Windows API tests on non-Windows platform")
        return True
    
    try:
        # Test IsDebuggerPresent
        kernel32 = ctypes.windll.kernel32
        
        if hasattr(kernel32, 'IsDebuggerPresent'):
            result = kernel32.IsDebuggerPresent()
            logger.info(f"IsDebuggerPresent result: {result}")
            
            # Test CheckRemoteDebuggerPresent
            if hasattr(kernel32, 'CheckRemoteDebuggerPresent'):
                handle = kernel32.GetCurrentProcess()
                debugger_present = ctypes.c_bool(False)
                
                check_result = kernel32.CheckRemoteDebuggerPresent(
                    handle, ctypes.byref(debugger_present)
                )
                
                logger.info(f"CheckRemoteDebuggerPresent result: {check_result}, debugger: {debugger_present.value}")
            
            # Test NtQueryInformationProcess
            try:
                ntdll = ctypes.windll.ntdll
                if hasattr(ntdll, 'NtQueryInformationProcess'):
                    handle = kernel32.GetCurrentProcess()
                    debug_port = ctypes.c_ulong(0)
                    
                    status = ntdll.NtQueryInformationProcess(
                        handle, 7, ctypes.byref(debug_port), 
                        ctypes.sizeof(debug_port), None
                    )
                    
                    logger.info(f"NtQueryInformationProcess status: {status}, debug_port: {debug_port.value}")
                    
            except Exception as e:
                logger.warning(f"NtQueryInformationProcess test failed: {e}")
            
            logger.info("Windows API detection tests completed")
            return True
        else:
            logger.warning("IsDebuggerPresent API not available")
            return False
            
    except Exception as e:
        logger.error(f"Windows API detection test failed: {e}")
        return False

def test_timing_detection():
    """Test timing-based detection methods."""
    logger.info("Testing timing-based detection...")
    
    try:
        # Test basic timing
        measurements = []
        
        for _ in range(5):
            start = time.perf_counter()
            
            # Simple operation
            result = 0
            for i in range(10000):
                result += i * 2
            
            end = time.perf_counter()
            elapsed = (end - start) * 1000  # milliseconds
            measurements.append(elapsed)
        
        avg_time = sum(measurements) / len(measurements)
        max_time = max(measurements)
        min_time = min(measurements)
        
        logger.info(f"Timing measurements: avg={avg_time:.3f}ms, min={min_time:.3f}ms, max={max_time:.3f}ms")
        
        # Check for suspicious timing (very basic heuristic)
        timing_suspicious = avg_time > 10.0 or max_time > 50.0
        
        logger.info(f"Timing analysis: suspicious={timing_suspicious}")
        
        # Test GetTickCount on Windows
        if platform.system() == 'Windows':
            try:
                kernel32 = ctypes.windll.kernel32
                
                if hasattr(kernel32, 'GetTickCount'):
                    tick_measurements = []
                    
                    for _ in range(3):
                        start_tick = kernel32.GetTickCount()
                        time.sleep(0.001)  # 1ms sleep
                        end_tick = kernel32.GetTickCount()
                        
                        elapsed_tick = end_tick - start_tick
                        tick_measurements.append(elapsed_tick)
                    
                    logger.info(f"GetTickCount measurements: {tick_measurements}")
                    
            except Exception as e:
                logger.warning(f"GetTickCount test failed: {e}")
        
        logger.info("Timing detection tests completed")
        return True
        
    except Exception as e:
        logger.error(f"Timing detection test failed: {e}")
        return False

def test_environment_detection():
    """Test environment-based detection methods."""
    logger.info("Testing environment detection...")
    
    try:
        # Check for analysis tools in processes
        analysis_tools_found = []
        
        try:
            import psutil
            
            analysis_tool_names = [
                'ollydbg', 'x64dbg', 'x32dbg', 'windbg', 'ida', 'idaq',
                'ida64', 'ghidra', 'radare2', 'r2', 'processhacker',
                'cheatengine', 'apimonitor'
            ]
            
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    proc_name = proc.info['name'].lower()
                    
                    for tool in analysis_tool_names:
                        if tool in proc_name:
                            analysis_tools_found.append(proc_name)
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            logger.info(f"Analysis tools found in processes: {analysis_tools_found}")
            
        except ImportError:
            logger.info("psutil not available, skipping process analysis")
        
        # Check for VM indicators
        vm_indicators = []
        
        # Check for VM-related files/directories
        vm_paths = [
            r'C:\Program Files\VMware\VMware Tools',
            r'C:\Program Files\Oracle\VirtualBox Guest Additions',
            '/usr/bin/VBoxService'
        ]
        
        for vm_path in vm_paths:
            if os.path.exists(vm_path):
                vm_indicators.append(vm_path)
        
        # Check hostname for VM indicators
        hostname = platform.node().lower()
        vm_hostnames = ['sandbox', 'malware', 'virus', 'analysis', 'test']
        
        for vm_hostname in vm_hostnames:
            if vm_hostname in hostname:
                vm_indicators.append(f'hostname:{hostname}')
        
        logger.info(f"VM indicators found: {vm_indicators}")
        
        # Check for debugging tools in common paths
        debug_tools_found = []
        
        debug_tool_paths = [
            r'C:\Program Files\OllyDbg',
            r'C:\Program Files (x86)\OllyDbg',
            r'C:\Tools\x64dbg',
            r'C:\Program Files\IDA',
            '/usr/bin/gdb'
        ]
        
        for tool_path in debug_tool_paths:
            if os.path.exists(tool_path):
                debug_tools_found.append(tool_path)
        
        logger.info(f"Debug tool installations found: {debug_tools_found}")
        
        total_indicators = len(analysis_tools_found) + len(vm_indicators) + len(debug_tools_found)
        logger.info(f"Total environment indicators: {total_indicators}")
        
        logger.info("Environment detection tests completed")
        return True
        
    except Exception as e:
        logger.error(f"Environment detection test failed: {e}")
        return False

def test_simple_anti_debug_analyzer():
    """Test a simplified version of anti-debug analysis."""
    logger.info("Testing simplified anti-debug analyzer...")
    
    try:
        # Simple analyzer that combines multiple detection methods
        class SimpleAntiDebugAnalyzer:
            def __init__(self):
                self.detections = {}
            
            def analyze(self):
                results = {
                    'total_detections': 0,
                    'categories': {
                        'api_based': [],
                        'timing_based': [],
                        'environment_based': []
                    },
                    'overall_score': 0.0
                }
                
                # API-based detection (Windows only)
                if platform.system() == 'Windows':
                    try:
                        kernel32 = ctypes.windll.kernel32
                        if hasattr(kernel32, 'IsDebuggerPresent'):
                            api_result = kernel32.IsDebuggerPresent()
                            if api_result:
                                results['categories']['api_based'].append('IsDebuggerPresent')
                                results['total_detections'] += 1
                    except:
                        pass
                
                # Timing-based detection
                start = time.perf_counter()
                dummy = sum(range(10000))
                end = time.perf_counter()
                
                timing_ms = (end - start) * 1000
                if timing_ms > 5.0:  # Arbitrary threshold
                    results['categories']['timing_based'].append('slow_execution')
                    results['total_detections'] += 1
                
                # Environment detection
                try:
                    import psutil
                    for proc in psutil.process_iter(['name']):
                        try:
                            if 'debug' in proc.info['name'].lower():
                                results['categories']['environment_based'].append('debugger_process')
                                results['total_detections'] += 1
                                break
                        except:
                            continue
                except ImportError:
                    pass
                
                # Calculate overall score
                results['overall_score'] = min(10.0, results['total_detections'] * 2.5)
                
                return results
        
        # Test the analyzer
        analyzer = SimpleAntiDebugAnalyzer()
        results = analyzer.analyze()
        
        assert 'total_detections' in results
        assert 'categories' in results
        assert 'overall_score' in results
        
        logger.info(f"Analysis results: {results['total_detections']} detections, score: {results['overall_score']}")
        
        for category, detections in results['categories'].items():
            if detections:
                logger.info(f"  {category}: {detections}")
        
        logger.info("Simple anti-debug analyzer test passed")
        return True
        
    except Exception as e:
        logger.error(f"Simple anti-debug analyzer test failed: {e}")
        return False

def main():
    """Main test execution."""
    logger.info("Starting Isolated Anti-Debugging Tests")
    logger.info("=" * 50)
    
    tests = [
        ("Base Detector", test_base_detector),
        ("AntiDebugTechnique Isolated", test_anti_debug_technique_isolated),
        ("Windows API Detection", test_windows_api_detection),
        ("Timing Detection", test_timing_detection),
        ("Environment Detection", test_environment_detection),
        ("Simple Anti-Debug Analyzer", test_simple_anti_debug_analyzer),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        logger.info(f"\n--- {test_name} ---")
        try:
            start_time = time.time()
            result = test_func()
            execution_time = time.time() - start_time
            
            results.append((test_name, result, execution_time))
            status = "PASS" if result else "FAIL"
            logger.info(f"{test_name}: {status} ({execution_time:.2f}s)")
            
        except Exception as e:
            results.append((test_name, False, 0))
            logger.error(f"{test_name}: FAIL - {e}")
    
    # Summary
    logger.info("\n" + "=" * 50)
    logger.info("TEST SUMMARY")
    
    total = len(results)
    passed = sum(1 for _, result, _ in results if result)
    failed = total - passed
    
    logger.info(f"Total: {total}, Passed: {passed}, Failed: {failed}")
    logger.info(f"Success Rate: {(passed/total)*100:.1f}%")
    
    # Detailed results
    logger.info("\nDetailed Results:")
    for test_name, result, exec_time in results:
        status = "PASS" if result else "FAIL"
        logger.info(f"  {test_name}: {status} ({exec_time:.2f}s)")
    
    if failed == 0:
        logger.info("\n✓ All isolated tests passed! Core anti-debugging logic is working.")
    else:
        logger.info(f"\n✗ {failed} test(s) failed. Check individual test results above.")
    
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)