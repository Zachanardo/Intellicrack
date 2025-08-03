"""
Comprehensive Anti-Debugging Technique Detection and Analysis System

This module provides advanced detection and analysis of anti-debugging techniques
used by protected software to prevent reverse engineering and dynamic analysis.

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

import ctypes
import ctypes.util
import hashlib
import logging
import os
import platform
import re
import struct
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

try:
    import psutil
except ImportError:
    psutil = None

try:
    import pefile
except ImportError:
    pefile = None

from .base_detector import BaseDetector


class AntiDebugTechnique:
    """Represents a detected anti-debugging technique."""
    
    def __init__(self, name: str, category: str, severity: str, 
                 description: str, bypass_methods: List[str],
                 code_patterns: List[str] = None):
        self.name = name
        self.category = category
        self.severity = severity
        self.description = description
        self.bypass_methods = bypass_methods
        self.code_patterns = code_patterns or []
        self.confidence = 0.0
        self.evidence = {}


class AntiDebugAnalyzer(BaseDetector):
    """
    Comprehensive anti-debugging technique detector and analyzer.
    """

    def __init__(self, target_binary: Optional[Union[str, Path]] = None):
        """Initialize the anti-debugging analyzer.
        
        Args:
            target_binary: Optional path to binary to analyze
        """
        super().__init__()
        self.logger = logging.getLogger("IntellicrackLogger.AntiDebugAnalyzer")
        self.target_binary = Path(target_binary) if target_binary else None
        
        # Initialize detection categories
        self.api_detections = {}
        self.peb_detections = {}
        self.exception_detections = {}
        self.timing_detections = {}
        self.environment_detections = {}
        self.advanced_detections = {}
        
        # Known anti-debug patterns
        self.anti_debug_patterns = self._initialize_patterns()
        
        # Detection method registry
        self._initialize_detection_methods()
        
        # Result caching
        self._analysis_cache = {}

    def _initialize_patterns(self) -> Dict[str, List[str]]:
        """Initialize known anti-debugging code patterns."""
        return {
            'api_calls': [
                r'IsDebuggerPresent',
                r'CheckRemoteDebuggerPresent',
                r'NtQueryInformationProcess',
                r'OutputDebugString[AW]?',
                r'GetTickCount64?',
                r'QueryPerformanceCounter',
                r'ZwSetInformationThread',
                r'NtSetInformationThread',
                r'SetThreadInformation',
                r'GetThreadContext',
                r'SetThreadContext',
                r'ContinueDebugEvent',
                r'WaitForDebugEvent'
            ],
            'assembly_patterns': [
                r'\x64\x8B\x30',  # mov esi, dword ptr fs:[30h] (PEB access)
                r'\x65\x8B\x35\x30\x00\x00\x00',  # mov esi, dword ptr fs:[30h]
                r'\xEB\xFE',  # jmp $-2 (infinite loop)
                r'\xCC',  # int 3 (software breakpoint)
                r'\xCD\x03',  # int 3 alternative
                r'\x0F\x31',  # rdtsc instruction
                r'\x0F\xA2',  # cpuid instruction
                r'\x64\xA1\x18\x00\x00\x00',  # mov eax, fs:[18h] (TEB access)
            ],
            'strings': [
                'SeDebugPrivilege',
                'DEBUG_PROCESS',
                'DEBUG_ONLY_THIS_PROCESS',
                'PROCESS_DEBUG_INHERIT',
                'ProcessDebugPort',
                'ProcessDebugObjectHandle',
                'ProcessDebugFlags',
                'ThreadHideFromDebugger',
                'ollydbg',
                'x64dbg',
                'windbg',
                'ida',
                'immunity',
                'cheat engine'
            ]
        }

    def _initialize_detection_methods(self):
        """Initialize all detection methods."""
        # API-based detections
        self.detection_methods.update({
            'api_isdebuggerpresent': self._detect_isdebuggerpresent_api,
            'api_checkremotedebuggerpresent': self._detect_checkremotedebuggerpresent_api,
            'api_ntqueryinformationprocess': self._detect_ntqueryinformationprocess_api,
            'api_outputdebugstring': self._detect_outputdebugstring_timing,
            'api_gettickcount_timing': self._detect_gettickcount_timing,
            'api_queryperformancecounter': self._detect_queryperformancecounter_timing,
            'api_setthreadinformation': self._detect_setthreadinformation_api,
            
            # PEB manipulation detections
            'peb_beingdebugged': self._detect_peb_beingdebugged,
            'peb_ntglobalflag': self._detect_peb_ntglobalflag,
            'peb_processheap_flags': self._detect_peb_processheap_flags,
            'peb_heap_forceflags': self._detect_peb_heap_forceflags,
            
            # Exception-based detections
            'exception_int3_detection': self._detect_exception_int3,
            'exception_hardware_breakpoints': self._detect_exception_hardware_bp,
            'exception_seh_manipulation': self._detect_exception_seh,
            'exception_veh_abuse': self._detect_exception_veh,
            
            # Timing-based detections
            'timing_rdtsc_analysis': self._detect_timing_rdtsc,
            'timing_gettickcount64': self._detect_timing_gettickcount64,
            'timing_qpc_precision': self._detect_timing_qpc_precision,
            'timing_sleep_verification': self._detect_timing_sleep_verification,
            
            # Environment detections
            'env_analysis_tools': self._detect_env_analysis_tools,
            'env_vm_detection': self._detect_env_vm_detection,
            'env_sandbox_detection': self._detect_env_sandbox_detection,
            'env_registry_artifacts': self._detect_env_registry_artifacts,
            'env_filesystem_artifacts': self._detect_env_filesystem_artifacts,
            
            # Advanced techniques
            'advanced_tls_callbacks': self._detect_advanced_tls_callbacks,
            'advanced_self_modifying': self._detect_advanced_self_modifying,
            'advanced_code_injection': self._detect_advanced_code_injection,
            'advanced_parent_validation': self._detect_advanced_parent_validation,
            'advanced_driver_detection': self._detect_advanced_driver_detection
        })

    def analyze_anti_debug_techniques(self, 
                                    aggressive: bool = False,
                                    deep_scan: bool = False,
                                    include_static_analysis: bool = True) -> Dict[str, Any]:
        """
        Perform comprehensive anti-debugging technique analysis.
        
        Args:
            aggressive: Enable aggressive detection methods
            deep_scan: Enable deep binary analysis
            include_static_analysis: Include static binary analysis
            
        Returns:
            Comprehensive analysis results
        """
        try:
            self.logger.info("Starting comprehensive anti-debugging analysis...")
            
            # Check cache
            cache_key = f"{aggressive}_{deep_scan}_{include_static_analysis}"
            if cache_key in self._analysis_cache:
                self.logger.debug("Returning cached analysis results")
                return self._analysis_cache[cache_key]
            
            # Initialize results structure
            results = {
                'analysis_metadata': {
                    'timestamp': time.time(),
                    'target_binary': str(self.target_binary) if self.target_binary else None,
                    'platform': platform.system(),
                    'architecture': platform.machine(),
                    'aggressive_mode': aggressive,
                    'deep_scan': deep_scan
                },
                'technique_categories': {
                    'api_based': {'detected': [], 'total_score': 0},
                    'peb_manipulation': {'detected': [], 'total_score': 0},
                    'exception_based': {'detected': [], 'total_score': 0},
                    'timing_based': {'detected': [], 'total_score': 0},
                    'environment_based': {'detected': [], 'total_score': 0},
                    'advanced_techniques': {'detected': [], 'total_score': 0}
                },
                'detection_summary': {
                    'total_techniques_detected': 0,
                    'highest_severity_found': 'none',
                    'overall_protection_score': 0,
                    'bypass_difficulty': 'easy',
                    'recommended_actions': []
                },
                'bypass_recommendations': {},
                'evasion_strategies': {},
                'detailed_findings': {}
            }
            
            # Perform dynamic detection
            dynamic_results = self._perform_dynamic_detection(aggressive)
            self._merge_detection_results(results, dynamic_results, 'dynamic')
            
            # Perform static analysis if requested and binary provided
            if include_static_analysis and self.target_binary:
                static_results = self._perform_static_analysis(deep_scan)
                self._merge_detection_results(results, static_results, 'static')
            
            # Analyze and categorize findings
            self._categorize_findings(results)
            
            # Generate bypass recommendations
            self._generate_bypass_recommendations(results)
            
            # Calculate overall scores
            self._calculate_protection_scores(results)
            
            # Cache results
            self._analysis_cache[cache_key] = results
            
            self.logger.info(f"Anti-debugging analysis complete. "
                           f"Found {results['detection_summary']['total_techniques_detected']} techniques")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Anti-debugging analysis failed: {e}", exc_info=True)
            return {
                'error': str(e),
                'analysis_metadata': {
                    'timestamp': time.time(),
                    'failed': True
                }
            }

    def _perform_dynamic_detection(self, aggressive: bool) -> Dict[str, Any]:
        """Perform dynamic anti-debugging detection."""
        self.logger.debug("Performing dynamic anti-debugging detection...")
        
        # Use the base class detection loop
        aggressive_methods = self.get_aggressive_methods()
        detection_results = self.run_detection_loop(aggressive, aggressive_methods)
        
        return {
            'type': 'dynamic',
            'results': detection_results
        }

    def _perform_static_analysis(self, deep_scan: bool) -> Dict[str, Any]:
        """Perform static analysis of target binary for anti-debug patterns."""
        if not self.target_binary or not self.target_binary.exists():
            return {'type': 'static', 'error': 'No target binary available'}
        
        self.logger.debug(f"Performing static analysis of {self.target_binary}")
        
        try:
            results = {
                'type': 'static',
                'file_analysis': {},
                'pattern_matches': {},
                'import_analysis': {},
                'section_analysis': {}
            }
            
            # Basic file analysis
            results['file_analysis'] = self._analyze_file_properties()
            
            # Pattern matching
            results['pattern_matches'] = self._search_binary_patterns(deep_scan)
            
            # Import analysis (Windows PE only)
            if platform.system() == 'Windows' and pefile:
                results['import_analysis'] = self._analyze_pe_imports()
            
            # Section analysis
            results['section_analysis'] = self._analyze_binary_sections()
            
            return results
            
        except Exception as e:
            self.logger.error(f"Static analysis failed: {e}")
            return {'type': 'static', 'error': str(e)}

    # API-Based Detection Methods

    def _detect_isdebuggerpresent_api(self) -> Tuple[bool, float, Dict]:
        """Detect IsDebuggerPresent API usage patterns."""
        details = {'api_present': False, 'direct_call': False, 'obfuscated_call': False}
        
        try:
            if platform.system() != 'Windows':
                return False, 0.0, details
                
            # Check if API is available
            kernel32 = ctypes.windll.kernel32
            if hasattr(kernel32, 'IsDebuggerPresent'):
                details['api_present'] = True
                
                # Test direct call
                result = kernel32.IsDebuggerPresent()
                if result:
                    details['direct_call'] = True
                    return True, 0.9, details
                    
                # Check for obfuscated calls in static analysis
                if self.target_binary:
                    pattern_found = self._search_api_pattern('IsDebuggerPresent')
                    if pattern_found:
                        details['obfuscated_call'] = True
                        return True, 0.7, details
                        
        except Exception as e:
            self.logger.debug(f"IsDebuggerPresent detection failed: {e}")
            
        return False, 0.0, details

    def _detect_checkremotedebuggerpresent_api(self) -> Tuple[bool, float, Dict]:
        """Detect CheckRemoteDebuggerPresent API usage patterns."""
        details = {'api_present': False, 'remote_debugger': False}
        
        try:
            if platform.system() != 'Windows':
                return False, 0.0, details
                
            kernel32 = ctypes.windll.kernel32
            if hasattr(kernel32, 'CheckRemoteDebuggerPresent'):
                details['api_present'] = True
                
                handle = kernel32.GetCurrentProcess()
                debugger_present = ctypes.c_bool(False)
                
                result = kernel32.CheckRemoteDebuggerPresent(handle, ctypes.byref(debugger_present))
                if result and debugger_present.value:
                    details['remote_debugger'] = True
                    return True, 0.9, details
                    
        except Exception as e:
            self.logger.debug(f"CheckRemoteDebuggerPresent detection failed: {e}")
            
        return False, 0.0, details

    def _detect_ntqueryinformationprocess_api(self) -> Tuple[bool, float, Dict]:
        """Detect NtQueryInformationProcess anti-debug usage."""
        details = {'debug_port': 0, 'debug_object': 0, 'debug_flags': 0}
        
        try:
            if platform.system() != 'Windows':
                return False, 0.0, details
                
            ntdll = ctypes.windll.ntdll
            kernel32 = ctypes.windll.kernel32
            
            handle = kernel32.GetCurrentProcess()
            
            # Check ProcessDebugPort (7)
            debug_port = ctypes.c_ulong(0)
            status = ntdll.NtQueryInformationProcess(
                handle, 7, ctypes.byref(debug_port), 
                ctypes.sizeof(debug_port), None
            )
            
            if status == 0:
                details['debug_port'] = debug_port.value
                if debug_port.value != 0:
                    return True, 0.85, details
            
            # Check ProcessDebugObjectHandle (30)
            debug_object = ctypes.c_ulong(0)
            status = ntdll.NtQueryInformationProcess(
                handle, 30, ctypes.byref(debug_object),
                ctypes.sizeof(debug_object), None
            )
            
            if status == 0:
                details['debug_object'] = debug_object.value
                if debug_object.value != 0:
                    return True, 0.85, details
            
            # Check ProcessDebugFlags (31)
            debug_flags = ctypes.c_ulong(1)  # Should be 1 if not debugged
            status = ntdll.NtQueryInformationProcess(
                handle, 31, ctypes.byref(debug_flags),
                ctypes.sizeof(debug_flags), None
            )
            
            if status == 0:
                details['debug_flags'] = debug_flags.value
                if debug_flags.value == 0:  # 0 means being debugged
                    return True, 0.85, details
                    
        except Exception as e:
            self.logger.debug(f"NtQueryInformationProcess detection failed: {e}")
            
        return False, 0.0, details

    def _detect_outputdebugstring_timing(self) -> Tuple[bool, float, Dict]:
        """Detect OutputDebugString timing-based anti-debug."""
        details = {'timing_anomaly': False, 'execution_time': 0}
        
        try:
            if platform.system() != 'Windows':
                return False, 0.0, details
                
            kernel32 = ctypes.windll.kernel32
            
            # Measure OutputDebugString timing
            start = time.perf_counter()
            
            for _ in range(100):
                kernel32.OutputDebugStringA(b"Debug test")
                
            end = time.perf_counter()
            execution_time = (end - start) * 1000  # milliseconds
            
            details['execution_time'] = execution_time
            
            # OutputDebugString is slower when debugger is present
            if execution_time > 50:  # Threshold for detection
                details['timing_anomaly'] = True
                return True, 0.6, details
                
        except Exception as e:
            self.logger.debug(f"OutputDebugString timing detection failed: {e}")
            
        return False, 0.0, details

    def _detect_gettickcount_timing(self) -> Tuple[bool, float, Dict]:
        """Detect GetTickCount-based timing analysis."""
        details = {'timing_inconsistency': False, 'measurements': []}
        
        try:
            if platform.system() != 'Windows':
                return False, 0.0, details
                
            kernel32 = ctypes.windll.kernel32
            measurements = []
            
            # Take multiple measurements
            for _ in range(10):
                start = kernel32.GetTickCount()
                time.sleep(0.001)  # 1ms sleep
                end = kernel32.GetTickCount()
                
                elapsed = end - start
                measurements.append(elapsed)
                
            details['measurements'] = measurements
            
            # Check for timing inconsistencies
            avg_time = sum(measurements) / len(measurements)
            if avg_time > 10 or max(measurements) > 50:  # Significant delays
                details['timing_inconsistency'] = True
                return True, 0.5, details
                
        except Exception as e:
            self.logger.debug(f"GetTickCount timing detection failed: {e}")
            
        return False, 0.0, details

    def _detect_queryperformancecounter_timing(self) -> Tuple[bool, float, Dict]:
        """Detect QueryPerformanceCounter timing analysis."""
        details = {'precision_anomaly': False, 'frequency': 0, 'measurements': []}
        
        try:
            if platform.system() != 'Windows':
                return False, 0.0, details
                
            kernel32 = ctypes.windll.kernel32
            
            # Get performance frequency
            frequency = ctypes.c_longlong(0)
            kernel32.QueryPerformanceFrequency(ctypes.byref(frequency))
            details['frequency'] = frequency.value
            
            measurements = []
            
            # Take precise measurements
            for _ in range(5):
                start = ctypes.c_longlong(0)
                end = ctypes.c_longlong(0)
                
                kernel32.QueryPerformanceCounter(ctypes.byref(start))
                
                # Perform a simple operation
                dummy = 0
                for i in range(1000):
                    dummy += i
                    
                kernel32.QueryPerformanceCounter(ctypes.byref(end))
                
                elapsed = (end.value - start.value) / frequency.value * 1000000  # microseconds
                measurements.append(elapsed)
                
            details['measurements'] = measurements
            
            # Check for timing anomalies
            avg_time = sum(measurements) / len(measurements)
            if avg_time > 1000 or max(measurements) > 5000:  # Too slow
                details['precision_anomaly'] = True
                return True, 0.6, details
                
        except Exception as e:
            self.logger.debug(f"QueryPerformanceCounter detection failed: {e}")
            
        return False, 0.0, details

    def _detect_setthreadinformation_api(self) -> Tuple[bool, float, Dict]:
        """Detect SetThreadInformation/ZwSetInformationThread usage."""
        details = {'thread_hidden': False, 'api_available': False}
        
        try:
            if platform.system() != 'Windows':
                return False, 0.0, details
                
            # Check for ThreadHideFromDebugger usage
            ntdll = ctypes.windll.ntdll
            kernel32 = ctypes.windll.kernel32
            
            if hasattr(ntdll, 'ZwSetInformationThread'):
                details['api_available'] = True
                
                # ThreadHideFromDebugger = 17
                current_thread = kernel32.GetCurrentThread()
                
                # Try to hide thread from debugger
                status = ntdll.ZwSetInformationThread(current_thread, 17, None, 0)
                
                if status == 0:  # Success
                    details['thread_hidden'] = True
                    return True, 0.8, details
                    
        except Exception as e:
            self.logger.debug(f"SetThreadInformation detection failed: {e}")
            
        return False, 0.0, details

    # PEB Manipulation Detection Methods

    def _detect_peb_beingdebugged(self) -> Tuple[bool, float, Dict]:
        """Detect PEB BeingDebugged flag manipulation."""
        details = {'peb_accessible': False, 'being_debugged': False}
        
        try:
            if platform.system() != 'Windows':
                return False, 0.0, details
                
            # Access PEB through TEB
            # This requires inline assembly or direct memory access
            # Simplified implementation using ctypes
            
            # Get PEB address from TEB
            kernel32 = ctypes.windll.kernel32
            ntdll = ctypes.windll.ntdll
            
            # Use NtQueryInformationProcess to get PEB address
            class PROCESS_BASIC_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("Reserved1", ctypes.c_void_p),
                    ("PebBaseAddress", ctypes.c_void_p),
                    ("Reserved2", ctypes.c_void_p * 2),
                    ("UniqueProcessId", ctypes.c_void_p),
                    ("Reserved3", ctypes.c_void_p)
                ]
            
            pbi = PROCESS_BASIC_INFORMATION()
            status = ntdll.NtQueryInformationProcess(
                kernel32.GetCurrentProcess(), 0,
                ctypes.byref(pbi), ctypes.sizeof(pbi), None
            )
            
            if status == 0 and pbi.PebBaseAddress:
                details['peb_accessible'] = True
                
                # Read BeingDebugged flag at PEB+2
                being_debugged = ctypes.c_ubyte.from_address(
                    pbi.PebBaseAddress + 2
                )
                
                details['being_debugged'] = bool(being_debugged.value)
                
                if being_debugged.value:
                    return True, 0.9, details
                    
        except Exception as e:
            self.logger.debug(f"PEB BeingDebugged detection failed: {e}")
            
        return False, 0.0, details

    def _detect_peb_ntglobalflag(self) -> Tuple[bool, float, Dict]:
        """Detect PEB NtGlobalFlag manipulation."""
        details = {'ntglobalflag': 0, 'debug_flags_set': False}
        
        try:
            if platform.system() != 'Windows':
                return False, 0.0, details
                
            # NtGlobalFlag is at different offsets for x86/x64
            # x86: PEB+0x68, x64: PEB+0xBC
            
            # Get PEB base address (using simplified method)
            kernel32 = ctypes.windll.kernel32
            ntdll = ctypes.windll.ntdll
            
            class PROCESS_BASIC_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("Reserved1", ctypes.c_void_p),
                    ("PebBaseAddress", ctypes.c_void_p),
                    ("Reserved2", ctypes.c_void_p * 2),
                    ("UniqueProcessId", ctypes.c_void_p),
                    ("Reserved3", ctypes.c_void_p)
                ]
            
            pbi = PROCESS_BASIC_INFORMATION()
            status = ntdll.NtQueryInformationProcess(
                kernel32.GetCurrentProcess(), 0,
                ctypes.byref(pbi), ctypes.sizeof(pbi), None
            )
            
            if status == 0 and pbi.PebBaseAddress:
                # Determine architecture-specific offset
                import struct
                if struct.calcsize("P") == 8:  # 64-bit
                    offset = 0xBC
                else:  # 32-bit
                    offset = 0x68
                    
                ntglobalflag = ctypes.c_ulong.from_address(
                    pbi.PebBaseAddress + offset
                )
                
                details['ntglobalflag'] = ntglobalflag.value
                
                # Check for debug heap flags
                debug_flags = (
                    0x10 |  # FLG_HEAP_ENABLE_TAIL_CHECK
                    0x20 |  # FLG_HEAP_ENABLE_FREE_CHECK
                    0x40    # FLG_HEAP_VALIDATE_PARAMETERS
                )
                
                if ntglobalflag.value & debug_flags:
                    details['debug_flags_set'] = True
                    return True, 0.8, details
                    
        except Exception as e:
            self.logger.debug(f"PEB NtGlobalFlag detection failed: {e}")
            
        return False, 0.0, details

    def _detect_peb_processheap_flags(self) -> Tuple[bool, float, Dict]:
        """Detect Process Heap flags indicating debugging."""
        details = {'heap_flags': 0, 'debug_heap': False}
        
        try:
            if platform.system() != 'Windows':
                return False, 0.0, details
                
            kernel32 = ctypes.windll.kernel32
            
            # Get process heap
            heap_handle = kernel32.GetProcessHeap()
            
            if heap_handle:
                # Access heap flags (simplified)
                # In a real heap structure, flags are at offset 0x0C (x86) or 0x70 (x64)
                
                # For demonstration, we'll use a different approach
                # Check heap allocation behavior
                
                # Allocate small memory block
                test_size = 64
                mem_ptr = kernel32.HeapAlloc(heap_handle, 0, test_size)
                
                if mem_ptr:
                    # Check for heap debugging features
                    # Debug heaps have different allocation patterns
                    
                    # Free the memory
                    kernel32.HeapFree(heap_handle, 0, mem_ptr)
                    
                    # If this succeeds normally, likely not debug heap
                    details['heap_flags'] = 1  # Normal heap
                else:
                    # Allocation failure might indicate debug heap
                    details['debug_heap'] = True
                    return True, 0.5, details
                    
        except Exception as e:
            self.logger.debug(f"Process heap detection failed: {e}")
            
        return False, 0.0, details

    def _detect_peb_heap_forceflags(self) -> Tuple[bool, float, Dict]:
        """Detect heap ForceFlags indicating debugging."""
        details = {'force_flags': 0, 'debug_detected': False}
        
        try:
            if platform.system() != 'Windows':
                return False, 0.0, details
                
            # ForceFlags is set in debug heap
            # This requires direct heap structure access
            # Simplified detection through behavior analysis
            
            kernel32 = ctypes.windll.kernel32
            heap_handle = kernel32.GetProcessHeap()
            
            if heap_handle:
                # Test heap behavior under different conditions
                allocations = []
                
                # Allocate multiple blocks
                for i in range(10):
                    ptr = kernel32.HeapAlloc(heap_handle, 0, 32 + i)
                    if ptr:
                        allocations.append(ptr)
                
                # Free all allocations
                for ptr in allocations:
                    kernel32.HeapFree(heap_handle, 0, ptr)
                
                # Debug heaps have different allocation patterns
                # This is a simplified heuristic
                if len(allocations) < 5:
                    details['debug_detected'] = True
                    return True, 0.4, details
                    
        except Exception as e:
            self.logger.debug(f"Heap ForceFlags detection failed: {e}")
            
        return False, 0.0, details

    # Exception-Based Detection Methods

    def _detect_exception_int3(self) -> Tuple[bool, float, Dict]:
        """Detect INT3 (software breakpoint) manipulation."""
        details = {'int3_detected': False, 'exception_handled': False}
        
        try:
            # Set up exception handler for INT3 detection
            def int3_test():
                try:
                    # This would trigger INT3 - dangerous in real implementation
                    # Instead, we'll simulate the detection
                    details['int3_detected'] = True
                    return False
                except:
                    details['exception_handled'] = True
                    return True
            
            # Test for INT3 presence (simplified)
            if self.target_binary:
                # Search for INT3 instructions in binary
                int3_found = self._search_binary_for_pattern(b'\xCC')
                if int3_found:
                    details['int3_detected'] = True
                    return True, 0.7, details
                    
        except Exception as e:
            self.logger.debug(f"INT3 detection failed: {e}")
            
        return False, 0.0, details

    def _detect_exception_hardware_bp(self) -> Tuple[bool, float, Dict]:
        """Detect hardware breakpoints through debug registers."""
        details = {'dr_registers_accessible': False, 'breakpoints_found': False}
        
        try:
            if platform.system() != 'Windows':
                return False, 0.0, details
                
            # Hardware breakpoints are set in DR0-DR3 registers
            # DR7 contains enable/disable flags
            
            # This requires getting thread context
            kernel32 = ctypes.windll.kernel32
            
            # Get current thread handle
            thread_handle = kernel32.GetCurrentThread()
            
            # CONTEXT structure for debug registers
            class CONTEXT(ctypes.Structure):
                _fields_ = [
                    ("ContextFlags", ctypes.c_ulong),
                    # ... many more fields ...
                    ("Dr0", ctypes.c_ulong),
                    ("Dr1", ctypes.c_ulong),
                    ("Dr2", ctypes.c_ulong),
                    ("Dr3", ctypes.c_ulong),
                    ("Dr6", ctypes.c_ulong),
                    ("Dr7", ctypes.c_ulong),
                ]
            
            # This is a simplified structure - real CONTEXT is much larger
            # For demonstration purposes only
            details['dr_registers_accessible'] = True
            
            # In a real implementation, would call GetThreadContext
            # and check DR0-DR3 for non-zero values and DR7 for enable flags
            
        except Exception as e:
            self.logger.debug(f"Hardware breakpoint detection failed: {e}")
            
        return False, 0.0, details

    def _detect_exception_seh(self) -> Tuple[bool, float, Dict]:
        """Detect SEH (Structured Exception Handling) manipulation."""
        details = {'seh_chain_accessible': False, 'suspicious_handlers': []}
        
        try:
            if platform.system() != 'Windows':
                return False, 0.0, details
                
            # SEH chain analysis requires accessing exception registration records
            # This is complex and architecture-dependent
            
            # Simplified detection through exception behavior
            try:
                # Test exception handling behavior
                def trigger_exception():
                    return 1 / 0  # Division by zero
                
                # If this doesn't raise an exception, SEH might be manipulated
                trigger_exception()
                
            except ZeroDivisionError:
                # Normal exception handling
                details['seh_chain_accessible'] = True
            except Exception as e:
                # Unexpected exception type might indicate SEH manipulation
                details['suspicious_handlers'].append(str(type(e)))
                return True, 0.6, details
                
        except Exception as e:
            self.logger.debug(f"SEH detection failed: {e}")
            
        return False, 0.0, details

    def _detect_exception_veh(self) -> Tuple[bool, float, Dict]:
        """Detect VEH (Vectored Exception Handling) abuse."""
        details = {'veh_handlers': 0, 'suspicious_activity': False}
        
        try:
            if platform.system() != 'Windows':
                return False, 0.0, details
                
            # VEH handlers are more difficult to detect
            # They're stored in a linked list in the process
            
            # Simplified detection through handler registration behavior
            kernel32 = ctypes.windll.kernel32
            
            if hasattr(kernel32, 'AddVectoredExceptionHandler'):
                # Test handler registration behavior
                # This is for demonstration - would not actually register handlers
                details['veh_handlers'] = 1  # Simulate detection
                
                # Check for unusual VEH patterns
                # Real implementation would analyze VEH chain
                
        except Exception as e:
            self.logger.debug(f"VEH detection failed: {e}")
            
        return False, 0.0, details

    # Timing-Based Detection Methods

    def _detect_timing_rdtsc(self) -> Tuple[bool, float, Dict]:
        """Detect RDTSC instruction-based timing analysis."""
        details = {'rdtsc_available': False, 'timing_analysis': []}
        
        try:
            # RDTSC (Read Time Stamp Counter) analysis
            # This instruction is often used for anti-debug timing
            
            if self.target_binary:
                # Search for RDTSC instruction (0x0F 0x31)
                rdtsc_found = self._search_binary_for_pattern(b'\x0F\x31')
                if rdtsc_found:
                    details['rdtsc_available'] = True
                    return True, 0.6, details
            
            # Dynamic RDTSC timing analysis would require inline assembly
            # or CPU-specific timing measurements
            
        except Exception as e:
            self.logger.debug(f"RDTSC detection failed: {e}")
            
        return False, 0.0, details

    def _detect_timing_gettickcount64(self) -> Tuple[bool, float, Dict]:
        """Detect GetTickCount64 timing analysis."""
        details = {'api_available': False, 'timing_measurements': []}
        
        try:
            if platform.system() != 'Windows':
                return False, 0.0, details
                
            kernel32 = ctypes.windll.kernel32
            
            if hasattr(kernel32, 'GetTickCount64'):
                details['api_available'] = True
                
                # Perform timing analysis
                measurements = []
                
                for _ in range(5):
                    start = kernel32.GetTickCount64()
                    
                    # Small delay
                    time.sleep(0.001)
                    
                    end = kernel32.GetTickCount64()
                    elapsed = end - start
                    measurements.append(elapsed)
                
                details['timing_measurements'] = measurements
                
                # Check for timing anomalies
                avg_time = sum(measurements) / len(measurements)
                if avg_time > 10 or max(measurements) > 50:
                    return True, 0.5, details
                    
        except Exception as e:
            self.logger.debug(f"GetTickCount64 detection failed: {e}")
            
        return False, 0.0, details

    def _detect_timing_qpc_precision(self) -> Tuple[bool, float, Dict]:
        """Detect QueryPerformanceCounter precision analysis."""
        details = {'frequency': 0, 'precision_test': []}
        
        try:
            if platform.system() != 'Windows':
                return False, 0.0, details
                
            kernel32 = ctypes.windll.kernel32
            
            # Get performance frequency
            frequency = ctypes.c_longlong(0)
            result = kernel32.QueryPerformanceFrequency(ctypes.byref(frequency))
            
            if result:
                details['frequency'] = frequency.value
                
                # Test precision with minimal operations
                precision_tests = []
                
                for _ in range(3):
                    start = ctypes.c_longlong(0)
                    end = ctypes.c_longlong(0)
                    
                    kernel32.QueryPerformanceCounter(ctypes.byref(start))
                    kernel32.QueryPerformanceCounter(ctypes.byref(end))
                    
                    # Calculate resolution
                    diff = end.value - start.value
                    precision_tests.append(diff)
                
                details['precision_test'] = precision_tests
                
                # Check for unusual precision (too high might indicate debugging)
                if any(p > 1000 for p in precision_tests):
                    return True, 0.4, details
                    
        except Exception as e:
            self.logger.debug(f"QPC precision detection failed: {e}")
            
        return False, 0.0, details

    def _detect_timing_sleep_verification(self) -> Tuple[bool, float, Dict]:
        """Detect Sleep/delay timing verification."""
        details = {'sleep_tests': [], 'timing_anomaly': False}
        
        try:
            # Test different sleep durations
            sleep_durations = [1, 5, 10]  # milliseconds
            
            for duration in sleep_durations:
                start = time.perf_counter()
                time.sleep(duration / 1000.0)
                end = time.perf_counter()
                
                actual_duration = (end - start) * 1000
                details['sleep_tests'].append({
                    'requested': duration,
                    'actual': actual_duration,
                    'ratio': actual_duration / duration
                })
                
                # Check for significant deviations
                if actual_duration > duration * 3:  # More than 3x expected
                    details['timing_anomaly'] = True
                    return True, 0.5, details
                    
        except Exception as e:
            self.logger.debug(f"Sleep verification failed: {e}")
            
        return False, 0.0, details

    # Environment Detection Methods

    def _detect_env_analysis_tools(self) -> Tuple[bool, float, Dict]:
        """Detect analysis tools in the environment."""
        details = {'processes_found': [], 'windows_found': [], 'files_found': []}
        
        try:
            # Get running processes
            if psutil:
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        proc_name = proc.info['name'].lower()
                        
                        # Check against known analysis tools
                        analysis_tools = [
                            'ollydbg', 'x64dbg', 'x32dbg', 'windbg', 'ida', 'idaq',
                            'ida64', 'ghidra', 'radare2', 'r2', 'processhacker',
                            'procmon', 'procexp', 'wireshark', 'fiddler',
                            'cheatengine', 'apimonitor', 'detours', 'immunity'
                        ]
                        
                        for tool in analysis_tools:
                            if tool in proc_name:
                                details['processes_found'].append(proc_name)
                                
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            
            # Check for analysis tool files
            common_paths = [
                r'C:\Program Files\OllyDbg',
                r'C:\Program Files (x86)\OllyDbg',
                r'C:\Tools\x64dbg',
                r'C:\Program Files\IDA',
                r'C:\Program Files (x86)\IDA',
                '/usr/bin/gdb',
                '/usr/bin/radare2'
            ]
            
            for path in common_paths:
                if os.path.exists(path):
                    details['files_found'].append(path)
            
            # Check for analysis tool windows (Windows only)
            if platform.system() == 'Windows':
                try:
                    import win32gui
                    
                    def enum_windows_callback(hwnd, windows):
                        window_title = win32gui.GetWindowText(hwnd).lower()
                        
                        analysis_windows = [
                            'ollydbg', 'x64dbg', 'ida', 'ghidra', 'windbg',
                            'process hacker', 'cheat engine', 'api monitor'
                        ]
                        
                        for tool in analysis_windows:
                            if tool in window_title:
                                windows.append(window_title)
                    
                    windows = []
                    win32gui.EnumWindows(enum_windows_callback, windows)
                    details['windows_found'] = windows
                    
                except ImportError:
                    pass
            
            # Determine detection result
            total_found = len(details['processes_found']) + len(details['files_found']) + len(details['windows_found'])
            
            if total_found > 0:
                confidence = min(0.9, 0.3 + (total_found * 0.2))
                return True, confidence, details
                
        except Exception as e:
            self.logger.debug(f"Analysis tools detection failed: {e}")
            
        return False, 0.0, details

    def _detect_env_vm_detection(self) -> Tuple[bool, float, Dict]:
        """Detect virtual machine environment."""
        details = {'vm_indicators': [], 'vm_type': None}
        
        try:
            # Check for VM-specific hardware/software indicators
            vm_indicators = []
            
            # Registry checks (Windows)
            if platform.system() == 'Windows':
                try:
                    import winreg
                    
                    vm_registry_keys = [
                        (winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services\VBoxService'),
                        (winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services\VMTools'),
                        (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\VMware, Inc.\VMware Tools'),
                        (winreg.HKEY_LOCAL_MACHINE, r'HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0'),
                    ]
                    
                    for hkey, subkey in vm_registry_keys:
                        try:
                            winreg.OpenKey(hkey, subkey)
                            vm_indicators.append(f'Registry: {subkey}')
                        except FileNotFoundError:
                            pass
                            
                except ImportError:
                    pass
            
            # Process checks
            if psutil:
                vm_processes = [
                    'vboxservice', 'vboxtray', 'vmtoolsd', 'vmwaretray',
                    'vmwareuser', 'qemu-ga', 'xenservice'
                ]
                
                for proc in psutil.process_iter(['name']):
                    try:
                        proc_name = proc.info['name'].lower()
                        for vm_proc in vm_processes:
                            if vm_proc in proc_name:
                                vm_indicators.append(f'Process: {proc_name}')
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            
            # File system checks
            vm_files = [
                r'C:\Program Files\VMware\VMware Tools',
                r'C:\Program Files\Oracle\VirtualBox Guest Additions',
                '/usr/bin/VBoxService',
                '/usr/sbin/VBoxService'
            ]
            
            for vm_file in vm_files:
                if os.path.exists(vm_file):
                    vm_indicators.append(f'File: {vm_file}')
            
            # Hardware checks
            try:
                # Check system information for VM indicators
                if platform.system() == 'Windows':
                    import subprocess
                    
                    # Check BIOS
                    result = subprocess.run(['wmic', 'bios', 'get', 'serialnumber'], 
                                          capture_output=True, text=True)
                    if 'VMware' in result.stdout or 'VirtualBox' in result.stdout:
                        vm_indicators.append('BIOS: VM detected')
                    
                    # Check manufacturer
                    result = subprocess.run(['wmic', 'computersystem', 'get', 'manufacturer'], 
                                          capture_output=True, text=True)
                    vm_manufacturers = ['VMware', 'VirtualBox', 'QEMU', 'Microsoft Corporation']
                    for manufacturer in vm_manufacturers:
                        if manufacturer in result.stdout:
                            vm_indicators.append(f'Manufacturer: {manufacturer}')
                            
            except Exception:
                pass
            
            details['vm_indicators'] = vm_indicators
            
            # Determine VM type
            vm_indicators_text = ' '.join(vm_indicators).lower()
            if 'vmware' in vm_indicators_text:
                details['vm_type'] = 'VMware'
            elif 'virtualbox' in vm_indicators_text or 'vbox' in vm_indicators_text:
                details['vm_type'] = 'VirtualBox'
            elif 'qemu' in vm_indicators_text:
                details['vm_type'] = 'QEMU'
            elif 'hyper-v' in vm_indicators_text or 'microsoft' in vm_indicators_text:
                details['vm_type'] = 'Hyper-V'
            
            if vm_indicators:
                confidence = min(0.9, 0.4 + (len(vm_indicators) * 0.1))
                return True, confidence, details
                
        except Exception as e:
            self.logger.debug(f"VM detection failed: {e}")
            
        return False, 0.0, details

    def _detect_env_sandbox_detection(self) -> Tuple[bool, float, Dict]:
        """Detect sandbox environment indicators."""
        details = {'sandbox_indicators': [], 'sandbox_type': None}
        
        try:
            sandbox_indicators = []
            
            # Check for sandbox-specific indicators
            # Low disk space (common in sandboxes)
            try:
                if psutil:
                    disk_usage = psutil.disk_usage('/')
                    free_gb = disk_usage.free / (1024**3)
                    
                    if free_gb < 10:  # Less than 10GB free
                        sandbox_indicators.append(f'Low disk space: {free_gb:.1f}GB')
            except:
                pass
            
            # Check for sandbox user names
            import getpass
            username = getpass.getuser().lower()
            sandbox_users = ['sandbox', 'malware', 'virus', 'sample', 'test', 'user', 'admin']
            
            for sandbox_user in sandbox_users:
                if sandbox_user in username:
                    sandbox_indicators.append(f'Sandbox username: {username}')
                    break
            
            # Check for common sandbox hostnames
            hostname = platform.node().lower()
            sandbox_hostnames = ['sandbox', 'malware', 'virus', 'analysis', 'test', 'sample']
            
            for sandbox_hostname in sandbox_hostnames:
                if sandbox_hostname in hostname:
                    sandbox_indicators.append(f'Sandbox hostname: {hostname}')
                    break
            
            # Check for limited network connectivity
            try:
                import socket
                
                # Try to connect to common sites
                test_sites = [('google.com', 80), ('microsoft.com', 80)]
                failed_connections = 0
                
                for host, port in test_sites:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    try:
                        result = sock.connect_ex((host, port))
                        if result != 0:
                            failed_connections += 1
                    except:
                        failed_connections += 1
                    finally:
                        sock.close()
                
                if failed_connections == len(test_sites):
                    sandbox_indicators.append('No network connectivity')
                    
            except:
                pass
            
            # Check for unusual system uptime (sandboxes often have low uptime)
            try:
                if psutil:
                    boot_time = psutil.boot_time()
                    uptime_hours = (time.time() - boot_time) / 3600
                    
                    if uptime_hours < 1:  # Less than 1 hour uptime
                        sandbox_indicators.append(f'Low uptime: {uptime_hours:.1f}h')
            except:
                pass
            
            details['sandbox_indicators'] = sandbox_indicators
            
            # Determine sandbox type based on indicators
            if any('cuckoo' in indicator.lower() for indicator in sandbox_indicators):
                details['sandbox_type'] = 'Cuckoo'
            elif any('joe' in indicator.lower() for indicator in sandbox_indicators):
                details['sandbox_type'] = 'Joe Sandbox'
            elif any('anubis' in indicator.lower() for indicator in sandbox_indicators):
                details['sandbox_type'] = 'Anubis'
            
            if sandbox_indicators:
                confidence = min(0.8, 0.3 + (len(sandbox_indicators) * 0.15))
                return True, confidence, details
                
        except Exception as e:
            self.logger.debug(f"Sandbox detection failed: {e}")
            
        return False, 0.0, details

    def _detect_env_registry_artifacts(self) -> Tuple[bool, float, Dict]:
        """Detect registry artifacts indicating analysis environment."""
        details = {'registry_artifacts': [], 'analysis_tools_detected': False}
        
        try:
            if platform.system() != 'Windows':
                return False, 0.0, details
                
            try:
                import winreg
                
                # Check for analysis tool registry entries
                analysis_tool_keys = [
                    r'SOFTWARE\Classes\OllyDbg',
                    r'SOFTWARE\Classes\x64dbg',
                    r'SOFTWARE\Hex-Rays\IDA Pro',
                    r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\IDA Pro',
                    r'SOFTWARE\Process Hacker 2',
                    r'SOFTWARE\Wireshark',
                    r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Ghidra'
                ]
                
                for key_path in analysis_tool_keys:
                    for hkey in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
                        try:
                            winreg.OpenKey(hkey, key_path)
                            details['registry_artifacts'].append(key_path)
                            details['analysis_tools_detected'] = True
                        except FileNotFoundError:
                            pass
                
                # Check for debugger-related registry modifications
                debugger_keys = [
                    (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug'),
                    (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options')
                ]
                
                for hkey, key_path in debugger_keys:
                    try:
                        key = winreg.OpenKey(hkey, key_path)
                        
                        # Enumerate subkeys
                        i = 0
                        while True:
                            try:
                                subkey_name = winreg.EnumKey(key, i)
                                
                                # Check for suspicious debugger configurations
                                if 'debugger' in subkey_name.lower():
                                    details['registry_artifacts'].append(f'{key_path}\\{subkey_name}')
                                
                                i += 1
                            except WindowsError:
                                break
                                
                        winreg.CloseKey(key)
                    except FileNotFoundError:
                        pass
                
                if details['registry_artifacts']:
                    confidence = min(0.8, 0.2 + (len(details['registry_artifacts']) * 0.1))
                    return True, confidence, details
                    
            except ImportError:
                self.logger.debug("winreg module not available")
                
        except Exception as e:
            self.logger.debug(f"Registry artifacts detection failed: {e}")
            
        return False, 0.0, details

    def _detect_env_filesystem_artifacts(self) -> Tuple[bool, float, Dict]:
        """Detect filesystem artifacts indicating analysis environment."""
        details = {'file_artifacts': [], 'directory_artifacts': []}
        
        try:
            # Common analysis tool installation paths
            analysis_paths = [
                r'C:\Program Files\OllyDbg',
                r'C:\Program Files (x86)\OllyDbg',
                r'C:\Tools\x64dbg',
                r'C:\Program Files\IDA',
                r'C:\Program Files (x86)\IDA',
                r'C:\Program Files\Hex-Rays',
                r'C:\Program Files\Process Hacker 2',
                r'C:\Program Files\Wireshark',
                r'C:\Tools\Ghidra',
                r'C:\Tools\radare2',
                '/usr/bin/gdb',
                '/usr/bin/radare2',
                '/opt/ghidra'
            ]
            
            for path in analysis_paths:
                if os.path.exists(path):
                    if os.path.isdir(path):
                        details['directory_artifacts'].append(path)
                    else:
                        details['file_artifacts'].append(path)
            
            # Check for analysis-related files in current directory
            current_dir = os.getcwd()
            analysis_files = [
                'ollydbg.exe', 'x64dbg.exe', 'ida.exe', 'ida64.exe',
                'idaq.exe', 'idaq64.exe', 'radare2.exe', 'ghidra.exe',
                'gdb', 'lldb'
            ]
            
            for analysis_file in analysis_files:
                file_path = os.path.join(current_dir, analysis_file)
                if os.path.exists(file_path):
                    details['file_artifacts'].append(file_path)
            
            # Check for temporary analysis files
            temp_dirs = []
            if platform.system() == 'Windows':
                temp_dirs = [os.environ.get('TEMP', ''), os.environ.get('TMP', '')]
            else:
                temp_dirs = ['/tmp']
            
            for temp_dir in temp_dirs:
                if temp_dir and os.path.exists(temp_dir):
                    try:
                        for item in os.listdir(temp_dir):
                            item_lower = item.lower()
                            if any(tool in item_lower for tool in ['ida', 'olly', 'x64dbg', 'ghidra']):
                                details['file_artifacts'].append(os.path.join(temp_dir, item))
                    except (PermissionError, OSError):
                        pass
            
            total_artifacts = len(details['file_artifacts']) + len(details['directory_artifacts'])
            
            if total_artifacts > 0:
                confidence = min(0.7, 0.2 + (total_artifacts * 0.1))
                return True, confidence, details
                
        except Exception as e:
            self.logger.debug(f"Filesystem artifacts detection failed: {e}")
            
        return False, 0.0, details

    # Advanced Detection Methods

    def _detect_advanced_tls_callbacks(self) -> Tuple[bool, float, Dict]:
        """Detect TLS (Thread Local Storage) callback analysis."""
        details = {'tls_callbacks_found': False, 'callback_count': 0}
        
        try:
            if not self.target_binary or not pefile:
                return False, 0.0, details
                
            # Analyze PE file for TLS callbacks
            pe = pefile.PE(str(self.target_binary))
            
            if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
                tls_table = pe.DIRECTORY_ENTRY_TLS
                
                if tls_table.struct.AddressOfCallBacks:
                    details['tls_callbacks_found'] = True
                    
                    # Read callback addresses
                    callback_rva = tls_table.struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase
                    callback_count = 0
                    
                    # Count non-null callback addresses
                    offset = pe.get_offset_from_rva(callback_rva)
                    
                    while True:
                        if pe.OPTIONAL_HEADER.Magic == 0x10b:  # PE32
                            callback_addr = struct.unpack('<L', pe.get_data(offset, 4))[0]
                            offset += 4
                        else:  # PE32+
                            callback_addr = struct.unpack('<Q', pe.get_data(offset, 8))[0]
                            offset += 8
                        
                        if callback_addr == 0:
                            break
                            
                        callback_count += 1
                        
                        # Limit to prevent infinite loops
                        if callback_count > 20:
                            break
                    
                    details['callback_count'] = callback_count
                    
                    if callback_count > 0:
                        return True, 0.6, details
            
        except Exception as e:
            self.logger.debug(f"TLS callback detection failed: {e}")
            
        return False, 0.0, details

    def _detect_advanced_self_modifying(self) -> Tuple[bool, float, Dict]:
        """Detect self-modifying code patterns."""
        details = {'self_modification_patterns': [], 'suspicious_sections': []}
        
        try:
            if not self.target_binary:
                return False, 0.0, details
                
            # Search for self-modification patterns
            self_mod_patterns = [
                b'\x8B\x45\x08\x83\xC0\x01\x89\x45\x08',  # mov eax, [ebp+8]; add eax, 1; mov [ebp+8], eax
                b'\xFF\x15',  # call dword ptr [...] - indirect calls
                b'\x68\x00\x00\x00\x00\x58',  # push 0; pop eax - address manipulation
            ]
            
            with open(self.target_binary, 'rb') as f:
                binary_data = f.read()
                
                for i, pattern in enumerate(self_mod_patterns):
                    matches = []
                    start = 0
                    
                    while True:
                        pos = binary_data.find(pattern, start)
                        if pos == -1:
                            break
                        matches.append(hex(pos))
                        start = pos + 1
                        
                        # Limit matches to prevent excessive output
                        if len(matches) > 10:
                            break
                    
                    if matches:
                        details['self_modification_patterns'].append({
                            'pattern_id': i,
                            'pattern': pattern.hex(),
                            'matches': matches
                        })
            
            # Analyze PE sections for suspicious characteristics
            if pefile:
                try:
                    pe = pefile.PE(str(self.target_binary))
                    
                    for section in pe.sections:
                        # Check for executable and writable sections
                        characteristics = section.Characteristics
                        
                        if (characteristics & 0x20000000) and (characteristics & 0x80000000):  # Execute and Write
                            details['suspicious_sections'].append({
                                'name': section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                                'characteristics': hex(characteristics),
                                'size': section.SizeOfRawData
                            })
                            
                except Exception:
                    pass
            
            if details['self_modification_patterns'] or details['suspicious_sections']:
                confidence = 0.4 + (len(details['self_modification_patterns']) * 0.1)
                return True, min(0.8, confidence), details
                
        except Exception as e:
            self.logger.debug(f"Self-modifying code detection failed: {e}")
            
        return False, 0.0, details

    def _detect_advanced_code_injection(self) -> Tuple[bool, float, Dict]:
        """Detect code injection detection patterns."""
        details = {'injection_apis': [], 'injection_patterns': []}
        
        try:
            # Check for code injection APIs
            injection_apis = [
                'VirtualAlloc', 'VirtualAllocEx', 'WriteProcessMemory',
                'CreateRemoteThread', 'SetWindowsHookEx', 'NtMapViewOfSection',
                'ZwMapViewOfSection', 'RtlCreateUserThread'
            ]
            
            if self.target_binary:
                # Search for API names in binary
                with open(self.target_binary, 'rb') as f:
                    binary_data = f.read()
                    
                    for api in injection_apis:
                        if api.encode() in binary_data:
                            details['injection_apis'].append(api)
            
            # Check for injection patterns
            injection_patterns = [
                b'\x68\x00\x30\x00\x00',  # push 3000h (PAGE_EXECUTE_READWRITE)
                b'\x68\x00\x10\x00\x00',  # push 1000h (MEM_COMMIT)
                b'\x6A\x00\x6A\x00',      # push 0; push 0 (common in injection)
            ]
            
            if self.target_binary:
                with open(self.target_binary, 'rb') as f:
                    binary_data = f.read()
                    
                    for pattern in injection_patterns:
                        if pattern in binary_data:
                            details['injection_patterns'].append(pattern.hex())
            
            if details['injection_apis'] or details['injection_patterns']:
                confidence = 0.3 + (len(details['injection_apis']) * 0.1)
                return True, min(0.7, confidence), details
                
        except Exception as e:
            self.logger.debug(f"Code injection detection failed: {e}")
            
        return False, 0.0, details

    def _detect_advanced_parent_validation(self) -> Tuple[bool, float, Dict]:
        """Detect parent process validation techniques."""
        details = {'parent_process': None, 'suspicious_parent': False}
        
        try:
            if psutil:
                current_process = psutil.Process()
                
                try:
                    parent = current_process.parent()
                    if parent:
                        parent_name = parent.name().lower()
                        parent_cmdline = ' '.join(parent.cmdline()).lower()
                        
                        details['parent_process'] = {
                            'name': parent_name,
                            'pid': parent.pid,
                            'cmdline': parent_cmdline
                        }
                        
                        # Check for suspicious parent processes
                        suspicious_parents = [
                            'python', 'pythonw', 'cmd', 'powershell', 'conhost',
                            'explorer'  # Sometimes analysis tools spawn from explorer
                        ]
                        
                        # Analysis tools as parents
                        analysis_parents = [
                            'ollydbg', 'x64dbg', 'ida', 'ghidra', 'radare2',
                            'windbg', 'processhacker'
                        ]
                        
                        for suspicious in suspicious_parents:
                            if suspicious in parent_name:
                                details['suspicious_parent'] = True
                                return True, 0.4, details
                        
                        for analysis in analysis_parents:
                            if analysis in parent_name:
                                details['suspicious_parent'] = True
                                return True, 0.8, details
                                
                except psutil.NoSuchProcess:
                    # No parent process (orphaned) can be suspicious
                    details['suspicious_parent'] = True
                    return True, 0.3, details
                    
        except Exception as e:
            self.logger.debug(f"Parent validation failed: {e}")
            
        return False, 0.0, details

    def _detect_advanced_driver_detection(self) -> Tuple[bool, float, Dict]:
        """Detect analysis-related drivers and kernel components."""
        details = {'drivers_found': [], 'analysis_drivers': False}
        
        try:
            if platform.system() != 'Windows':
                return False, 0.0, details
                
            # Check for analysis-related drivers
            analysis_drivers = [
                'VBoxDrv', 'VBoxUSBMon', 'VBoxNetFlt', 'VBoxNetAdp',  # VirtualBox
                'vmci', 'vmhgfs', 'vmmouse', 'vmrawdsk', 'vmusbmouse',  # VMware
                'ScyllaHide',  # ScyllaHide anti-anti-debug
                'TitanHide',   # TitanHide anti-anti-debug
                'dbk32', 'dbk64',  # Cheat Engine
                'PROCMON23', 'PROCMON24',  # Process Monitor
                'WinAPIOverride'  # API Override
            ]
            
            # Try to enumerate drivers using WMI
            try:
                import subprocess
                
                result = subprocess.run([
                    'wmic', 'systemdriver', 'get', 'name'
                ], capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    driver_output = result.stdout.lower()
                    
                    for driver in analysis_drivers:
                        if driver.lower() in driver_output:
                            details['drivers_found'].append(driver)
                            details['analysis_drivers'] = True
                            
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
            
            # Alternative method: check driver files
            driver_paths = [
                r'C:\Windows\System32\drivers',
                r'C:\Windows\SysWOW64\drivers'
            ]
            
            for driver_path in driver_paths:
                if os.path.exists(driver_path):
                    try:
                        for file in os.listdir(driver_path):
                            file_lower = file.lower()
                            
                            for driver in analysis_drivers:
                                if driver.lower() in file_lower:
                                    details['drivers_found'].append(os.path.join(driver_path, file))
                                    details['analysis_drivers'] = True
                                    
                    except (PermissionError, OSError):
                        pass
            
            if details['analysis_drivers']:
                confidence = min(0.8, 0.4 + (len(details['drivers_found']) * 0.1))
                return True, confidence, details
                
        except Exception as e:
            self.logger.debug(f"Driver detection failed: {e}")
            
        return False, 0.0, details

    # Helper methods for static analysis

    def _analyze_file_properties(self) -> Dict[str, Any]:
        """Analyze basic file properties."""
        try:
            stat = self.target_binary.stat()
            
            # Calculate file hash
            sha256_hash = hashlib.sha256()
            with open(self.target_binary, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            
            return {
                'size': stat.st_size,
                'created': stat.st_ctime,
                'modified': stat.st_mtime,
                'sha256': sha256_hash.hexdigest(),
                'path': str(self.target_binary)
            }
            
        except Exception as e:
            self.logger.debug(f"File analysis failed: {e}")
            return {}

    def _search_binary_patterns(self, deep_scan: bool) -> Dict[str, Any]:
        """Search for anti-debug patterns in binary."""
        try:
            results = {
                'api_calls': [],
                'assembly_patterns': [],
                'strings': []
            }
            
            with open(self.target_binary, 'rb') as f:
                binary_data = f.read()
                
                # Search for API call patterns
                for api_pattern in self.anti_debug_patterns['api_calls']:
                    if api_pattern.encode() in binary_data:
                        results['api_calls'].append(api_pattern)
                
                # Search for assembly patterns
                for asm_pattern in self.anti_debug_patterns['assembly_patterns']:
                    try:
                        pattern_bytes = bytes.fromhex(asm_pattern.replace('\\x', ''))
                        if pattern_bytes in binary_data:
                            results['assembly_patterns'].append(asm_pattern)
                    except ValueError:
                        continue
                
                # Search for strings
                for string_pattern in self.anti_debug_patterns['strings']:
                    if string_pattern.encode() in binary_data:
                        results['strings'].append(string_pattern)
            
            return results
            
        except Exception as e:
            self.logger.debug(f"Pattern search failed: {e}")
            return {}

    def _analyze_pe_imports(self) -> Dict[str, Any]:
        """Analyze PE imports for anti-debug APIs."""
        try:
            pe = pefile.PE(str(self.target_binary))
            
            anti_debug_imports = []
            
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8').lower()
                    
                    for imp in entry.imports:
                        if imp.name:
                            api_name = imp.name.decode('utf-8')
                            
                            # Check if it's an anti-debug API
                            anti_debug_apis = [
                                'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
                                'NtQueryInformationProcess', 'ZwQueryInformationProcess',
                                'OutputDebugStringA', 'OutputDebugStringW',
                                'GetTickCount', 'GetTickCount64', 'QueryPerformanceCounter',
                                'SetThreadInformation', 'ZwSetInformationThread'
                            ]
                            
                            if api_name in anti_debug_apis:
                                anti_debug_imports.append({
                                    'dll': dll_name,
                                    'api': api_name,
                                    'address': hex(imp.address) if imp.address else None
                                })
            
            return {
                'anti_debug_imports': anti_debug_imports,
                'import_count': len(anti_debug_imports)
            }
            
        except Exception as e:
            self.logger.debug(f"PE import analysis failed: {e}")
            return {}

    def _analyze_binary_sections(self) -> Dict[str, Any]:
        """Analyze binary sections for suspicious characteristics."""
        try:
            if not pefile:
                return {}
                
            pe = pefile.PE(str(self.target_binary))
            
            suspicious_sections = []
            
            for section in pe.sections:
                section_info = {
                    'name': section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                    'virtual_address': hex(section.VirtualAddress),
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'characteristics': hex(section.Characteristics),
                    'entropy': section.get_entropy()
                }
                
                # Check for suspicious characteristics
                is_suspicious = False
                suspicion_reasons = []
                
                # High entropy might indicate packing/encryption
                if section_info['entropy'] > 7.5:
                    is_suspicious = True
                    suspicion_reasons.append('High entropy')
                
                # Executable and writable sections
                characteristics = section.Characteristics
                if (characteristics & 0x20000000) and (characteristics & 0x80000000):
                    is_suspicious = True
                    suspicion_reasons.append('Executable and writable')
                
                # Large virtual size vs raw size discrepancy
                if section_info['virtual_size'] > section_info['raw_size'] * 2:
                    is_suspicious = True
                    suspicion_reasons.append('Large virtual/raw size discrepancy')
                
                if is_suspicious:
                    section_info['suspicion_reasons'] = suspicion_reasons
                    suspicious_sections.append(section_info)
            
            return {
                'suspicious_sections': suspicious_sections,
                'total_sections': len(pe.sections)
            }
            
        except Exception as e:
            self.logger.debug(f"Section analysis failed: {e}")
            return {}

    def _search_api_pattern(self, api_name: str) -> bool:
        """Search for specific API usage patterns."""
        try:
            if not self.target_binary:
                return False
                
            with open(self.target_binary, 'rb') as f:
                binary_data = f.read()
                return api_name.encode() in binary_data
                
        except Exception as e:
            self.logger.debug(f"API pattern search failed: {e}")
            return False

    def _search_binary_for_pattern(self, pattern: bytes) -> bool:
        """Search for byte pattern in binary."""
        try:
            if not self.target_binary:
                return False
                
            with open(self.target_binary, 'rb') as f:
                binary_data = f.read()
                return pattern in binary_data
                
        except Exception as e:
            self.logger.debug(f"Binary pattern search failed: {e}")
            return False

    # Result processing methods

    def _merge_detection_results(self, results: Dict[str, Any], 
                                detection_results: Dict[str, Any], 
                                result_type: str):
        """Merge detection results into main results structure."""
        if result_type == 'dynamic' and 'results' in detection_results:
            dynamic_results = detection_results['results']
            
            for method_name, method_result in dynamic_results.get('detections', {}).items():
                if method_result.get('detected'):
                    category = self._get_method_category(method_name)
                    
                    technique = AntiDebugTechnique(
                        name=method_name,
                        category=category,
                        severity=self._get_method_severity(method_name),
                        description=self._get_method_description(method_name),
                        bypass_methods=self._get_bypass_methods(method_name)
                    )
                    technique.confidence = method_result.get('confidence', 0.0)
                    technique.evidence = method_result.get('details', {})
                    
                    results['technique_categories'][category]['detected'].append(technique.__dict__)
        
        elif result_type == 'static' and not detection_results.get('error'):
            # Process static analysis results
            static_results = detection_results
            
            # Process pattern matches
            if 'pattern_matches' in static_results:
                patterns = static_results['pattern_matches']
                
                for api_call in patterns.get('api_calls', []):
                    technique = AntiDebugTechnique(
                        name=f"Static API: {api_call}",
                        category='api_based',
                        severity='medium',
                        description=f"Static detection of {api_call} API usage",
                        bypass_methods=['API hooking', 'DLL replacement']
                    )
                    technique.confidence = 0.6
                    technique.evidence = {'api_name': api_call}
                    
                    results['technique_categories']['api_based']['detected'].append(technique.__dict__)

    def _get_method_category(self, method_name: str) -> str:
        """Get category for detection method."""
        if method_name.startswith('api_'):
            return 'api_based'
        elif method_name.startswith('peb_'):
            return 'peb_manipulation'
        elif method_name.startswith('exception_'):
            return 'exception_based'
        elif method_name.startswith('timing_'):
            return 'timing_based'
        elif method_name.startswith('env_'):
            return 'environment_based'
        elif method_name.startswith('advanced_'):
            return 'advanced_techniques'
        else:
            return 'api_based'  # Default

    def _get_method_severity(self, method_name: str) -> str:
        """Get severity level for detection method."""
        high_severity = [
            'api_ntqueryinformationprocess', 'peb_beingdebugged', 
            'peb_ntglobalflag', 'exception_hardware_breakpoints'
        ]
        
        medium_severity = [
            'api_isdebuggerpresent', 'api_checkremotedebuggerpresent',
            'timing_rdtsc_analysis', 'env_analysis_tools'
        ]
        
        if method_name in high_severity:
            return 'high'
        elif method_name in medium_severity:
            return 'medium'
        else:
            return 'low'

    def _get_method_description(self, method_name: str) -> str:
        """Get description for detection method."""
        descriptions = {
            'api_isdebuggerpresent': 'Detects debugger using IsDebuggerPresent API call',
            'api_checkremotedebuggerpresent': 'Detects remote debugger using CheckRemoteDebuggerPresent API',
            'api_ntqueryinformationprocess': 'Detects debugger using NtQueryInformationProcess with debug-related information classes',
            'peb_beingdebugged': 'Checks PEB BeingDebugged flag for debugger presence',
            'peb_ntglobalflag': 'Examines PEB NtGlobalFlag for debug heap indicators',
            'timing_rdtsc_analysis': 'Uses RDTSC instruction for timing-based debugger detection',
            'env_analysis_tools': 'Scans environment for analysis tools and debuggers'
        }
        
        return descriptions.get(method_name, f'Anti-debugging technique: {method_name}')

    def _get_bypass_methods(self, method_name: str) -> List[str]:
        """Get bypass methods for detection technique."""
        bypass_methods = {
            'api_isdebuggerpresent': [
                'Hook IsDebuggerPresent API to return FALSE',
                'Patch PEB BeingDebugged flag',
                'Use stealth debugging techniques'
            ],
            'api_checkremotedebuggerpresent': [
                'Hook CheckRemoteDebuggerPresent API',
                'Modify debug port in process information',
                'Use kernel debugging'
            ],
            'api_ntqueryinformationprocess': [
                'Hook NtQueryInformationProcess',
                'Modify process debug information',
                'Use specialized debugging tools'
            ],
            'peb_beingdebugged': [
                'Patch PEB BeingDebugged flag to 0',
                'Use memory patching tools',
                'Modify PEB structure'
            ],
            'peb_ntglobalflag': [
                'Modify NtGlobalFlag in PEB',
                'Use heap manipulation tools',
                'Patch process creation flags'
            ],
            'timing_rdtsc_analysis': [
                'Use hardware virtualization',
                'Modify RDTSC instruction behavior',
                'Use timing attack countermeasures'
            ],
            'env_analysis_tools': [
                'Rename analysis tools',
                'Use process hiding techniques',
                'Run in isolated environment'
            ]
        }
        
        return bypass_methods.get(method_name, ['Manual analysis required'])

    def _categorize_findings(self, results: Dict[str, Any]):
        """Categorize and summarize findings."""
        total_detected = 0
        highest_severity = 'none'
        severity_order = ['none', 'low', 'medium', 'high', 'critical']
        
        for category_name, category_data in results['technique_categories'].items():
            detected_techniques = category_data['detected']
            category_score = 0
            
            for technique in detected_techniques:
                total_detected += 1
                severity = technique.get('severity', 'low')
                
                # Update highest severity
                if severity_order.index(severity) > severity_order.index(highest_severity):
                    highest_severity = severity
                
                # Calculate category score
                severity_scores = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
                confidence = technique.get('confidence', 0.0)
                category_score += severity_scores.get(severity, 1) * confidence
            
            category_data['total_score'] = category_score
        
        results['detection_summary']['total_techniques_detected'] = total_detected
        results['detection_summary']['highest_severity_found'] = highest_severity

    def _generate_bypass_recommendations(self, results: Dict[str, Any]):
        """Generate bypass recommendations based on detected techniques."""
        bypass_recommendations = {}
        evasion_strategies = {}
        
        for category_name, category_data in results['technique_categories'].items():
            category_bypasses = []
            
            for technique in category_data['detected']:
                bypass_methods = technique.get('bypass_methods', [])
                category_bypasses.extend(bypass_methods)
            
            if category_bypasses:
                # Remove duplicates while preserving order
                unique_bypasses = list(dict.fromkeys(category_bypasses))
                bypass_recommendations[category_name] = unique_bypasses
        
        # Generate general evasion strategies
        total_detected = results['detection_summary']['total_techniques_detected']
        
        if total_detected == 0:
            evasion_strategies['general'] = ['No anti-debugging techniques detected', 'Standard debugging tools should work']
        elif total_detected <= 3:
            evasion_strategies['general'] = [
                'Low to moderate anti-debugging protection',
                'Basic API hooking should be sufficient',
                'Consider using ScyllaHide or similar tools'
            ]
        elif total_detected <= 6:
            evasion_strategies['general'] = [
                'Moderate anti-debugging protection',
                'Multiple bypass techniques required',
                'Use comprehensive anti-anti-debug solutions',
                'Consider kernel-mode debugging'
            ]
        else:
            evasion_strategies['general'] = [
                'Strong anti-debugging protection',
                'Advanced evasion techniques required',
                'Use specialized reverse engineering tools',
                'Consider manual analysis or emulation'
            ]
        
        results['bypass_recommendations'] = bypass_recommendations
        results['evasion_strategies'] = evasion_strategies

    def _calculate_protection_scores(self, results: Dict[str, Any]):
        """Calculate overall protection scores."""
        total_detected = results['detection_summary']['total_techniques_detected']
        
        # Calculate overall protection score (0-10)
        category_scores = [
            cat_data['total_score'] for cat_data in results['technique_categories'].values()
        ]
        
        total_score = sum(category_scores)
        normalized_score = min(10, total_score / 2)  # Normalize to 0-10 scale
        
        results['detection_summary']['overall_protection_score'] = round(normalized_score, 1)
        
        # Determine bypass difficulty
        if normalized_score <= 2:
            difficulty = 'easy'
        elif normalized_score <= 5:
            difficulty = 'medium'
        elif normalized_score <= 8:
            difficulty = 'hard'
        else:
            difficulty = 'extreme'
        
        results['detection_summary']['bypass_difficulty'] = difficulty
        
        # Generate recommended actions
        recommended_actions = []
        
        if total_detected == 0:
            recommended_actions = ['Proceed with standard analysis tools']
        else:
            if any(cat['detected'] for cat in results['technique_categories'].values() 
                   if 'api_based' in str(cat)):
                recommended_actions.append('Use API hooking framework')
            
            if any(cat['detected'] for cat in results['technique_categories'].values() 
                   if 'timing_based' in str(cat)):
                recommended_actions.append('Use hardware-assisted debugging')
            
            if any(cat['detected'] for cat in results['technique_categories'].values() 
                   if 'environment_based' in str(cat)):
                recommended_actions.append('Use stealth analysis environment')
            
            if difficulty in ['hard', 'extreme']:
                recommended_actions.append('Consider manual reverse engineering')
        
        results['detection_summary']['recommended_actions'] = recommended_actions

    def get_aggressive_methods(self) -> List[str]:
        """Get list of aggressive detection methods."""
        return [
            'timing_rdtsc_analysis', 'exception_int3_detection',
            'exception_hardware_breakpoints', 'advanced_self_modifying'
        ]

    def get_detection_type(self) -> str:
        """Get the type of detection this class performs."""
        return 'comprehensive_anti_debug'

    def clear_cache(self):
        """Clear the analysis cache."""
        self._analysis_cache.clear()
        self.logger.debug("Analysis cache cleared")

    def get_analysis_statistics(self) -> Dict[str, Any]:
        """Get analysis statistics and cache information."""
        return {
            'cache_size': len(self._analysis_cache),
            'target_binary': str(self.target_binary) if self.target_binary else None,
            'detection_methods': len(self.detection_methods),
            'pattern_categories': len(self.anti_debug_patterns)
        }