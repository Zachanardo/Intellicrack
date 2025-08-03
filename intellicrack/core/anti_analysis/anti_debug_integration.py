"""
Anti-Debugging Detection Integration Module

Integrates the comprehensive anti-debugging analyzer with the existing 
Intellicrack protection detection and analysis framework.

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

import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .anti_debug_analyzer import AntiDebugAnalyzer
from ..app_context import AppContext


class AntiDebugDetectionEngine:
    """
    Integration engine for anti-debugging detection capabilities.
    
    Provides a unified interface for anti-debugging analysis that integrates
    with the existing Intellicrack protection detection framework.
    """
    
    def __init__(self, app_context: Optional[AppContext] = None):
        """Initialize the anti-debugging detection engine.
        
        Args:
            app_context: Optional application context for configuration
        """
        self.logger = logging.getLogger("IntellicrackLogger.AntiDebugEngine")
        self.app_context = app_context
        
        # Initialize analyzer
        self.analyzer = None
        
        # Configuration
        self.config = {
            'enable_static_analysis': True,
            'enable_dynamic_analysis': True,
            'aggressive_detection': False,
            'deep_scan': False,
            'cache_results': True,
            'timeout_seconds': 30
        }
        
        # Results cache
        self._results_cache = {}
        
        self.logger.info("Anti-debugging detection engine initialized")

    def analyze_binary(self, 
                      binary_path: Union[str, Path],
                      analysis_options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform comprehensive anti-debugging analysis on a binary.
        
        Args:
            binary_path: Path to the binary to analyze
            analysis_options: Optional analysis configuration
            
        Returns:
            Comprehensive anti-debugging analysis results
        """
        try:
            binary_path = Path(binary_path)
            
            if not binary_path.exists():
                return {
                    'error': f'Binary file not found: {binary_path}',
                    'success': False
                }
            
            self.logger.info(f"Starting anti-debugging analysis of {binary_path}")
            
            # Merge configuration
            config = self.config.copy()
            if analysis_options:
                config.update(analysis_options)
            
            # Check cache
            cache_key = self._generate_cache_key(binary_path, config)
            if config.get('cache_results', True) and cache_key in self._results_cache:
                self.logger.debug("Returning cached anti-debugging analysis")
                return self._results_cache[cache_key]
            
            # Initialize analyzer with target binary
            self.analyzer = AntiDebugAnalyzer(binary_path)
            
            # Perform analysis
            start_time = time.time()
            
            results = self.analyzer.analyze_anti_debug_techniques(
                aggressive=config.get('aggressive_detection', False),
                deep_scan=config.get('deep_scan', False),
                include_static_analysis=config.get('enable_static_analysis', True)
            )
            
            analysis_time = time.time() - start_time
            
            # Enhance results with integration metadata
            enhanced_results = self._enhance_results(results, binary_path, analysis_time, config)
            
            # Cache results
            if config.get('cache_results', True):
                self._results_cache[cache_key] = enhanced_results
            
            self.logger.info(f"Anti-debugging analysis completed in {analysis_time:.2f}s")
            return enhanced_results
            
        except Exception as e:
            self.logger.error(f"Anti-debugging analysis failed: {e}", exc_info=True)
            return {
                'error': str(e),
                'success': False,
                'binary_path': str(binary_path),
                'timestamp': time.time()
            }

    def analyze_live_process(self, 
                           pid: Optional[int] = None,
                           process_name: Optional[str] = None,
                           analysis_options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform anti-debugging analysis on a live process.
        
        Args:
            pid: Process ID to analyze
            process_name: Process name to analyze
            analysis_options: Optional analysis configuration
            
        Returns:
            Anti-debugging analysis results for live process
        """
        try:
            if not pid and not process_name:
                return {
                    'error': 'Either PID or process name must be specified',
                    'success': False
                }
            
            # Find process if only name provided
            if process_name and not pid:
                try:
                    import psutil
                    for proc in psutil.process_iter(['pid', 'name']):
                        if proc.info['name'].lower() == process_name.lower():
                            pid = proc.info['pid']
                            break
                    
                    if not pid:
                        return {
                            'error': f'Process not found: {process_name}',
                            'success': False
                        }
                except ImportError:
                    return {
                        'error': 'psutil not available for process enumeration',
                        'success': False
                    }
            
            self.logger.info(f"Starting live anti-debugging analysis of PID {pid}")
            
            # Merge configuration
            config = self.config.copy()
            if analysis_options:
                config.update(analysis_options)
            
            # Initialize analyzer for live process analysis
            self.analyzer = AntiDebugAnalyzer()
            
            # Perform dynamic analysis only (no binary file)
            start_time = time.time()
            
            results = self.analyzer.analyze_anti_debug_techniques(
                aggressive=config.get('aggressive_detection', False),
                deep_scan=False,  # Deep scan requires binary file
                include_static_analysis=False  # Static analysis requires binary file
            )
            
            analysis_time = time.time() - start_time
            
            # Enhance results for live process
            enhanced_results = self._enhance_live_results(results, pid, analysis_time, config)
            
            self.logger.info(f"Live anti-debugging analysis completed in {analysis_time:.2f}s")
            return enhanced_results
            
        except Exception as e:
            self.logger.error(f"Live anti-debugging analysis failed: {e}", exc_info=True)
            return {
                'error': str(e),
                'success': False,
                'pid': pid,
                'process_name': process_name,
                'timestamp': time.time()
            }

    def get_bypass_recommendations(self, 
                                 analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get detailed bypass recommendations based on analysis results.
        
        Args:
            analysis_results: Results from anti-debugging analysis
            
        Returns:
            Detailed bypass recommendations and strategies
        """
        try:
            if 'bypass_recommendations' not in analysis_results:
                return {
                    'error': 'Invalid analysis results - no bypass recommendations found',
                    'success': False
                }
            
            bypass_info = analysis_results['bypass_recommendations']
            evasion_strategies = analysis_results.get('evasion_strategies', {})
            detection_summary = analysis_results.get('detection_summary', {})
            
            # Generate comprehensive bypass guide
            bypass_guide = {
                'summary': {
                    'difficulty_level': detection_summary.get('bypass_difficulty', 'unknown'),
                    'techniques_detected': detection_summary.get('total_techniques_detected', 0),
                    'protection_score': detection_summary.get('overall_protection_score', 0),
                    'recommended_approach': self._determine_bypass_approach(detection_summary)
                },
                'category_specific': {},
                'tool_recommendations': self._generate_tool_recommendations(analysis_results),
                'step_by_step_guide': self._generate_bypass_guide(analysis_results),
                'advanced_techniques': self._generate_advanced_bypass_techniques(analysis_results)
            }
            
            # Process category-specific bypasses
            for category, bypasses in bypass_info.items():
                bypass_guide['category_specific'][category] = {
                    'techniques': bypasses,
                    'priority': self._get_bypass_priority(category, analysis_results),
                    'difficulty': self._get_bypass_difficulty(category, analysis_results),
                    'tools': self._get_category_tools(category)
                }
            
            return {
                'success': True,
                'bypass_guide': bypass_guide,
                'timestamp': time.time()
            }
            
        except Exception as e:
            self.logger.error(f"Bypass recommendations generation failed: {e}")
            return {
                'error': str(e),
                'success': False
            }

    def generate_bypass_scripts(self, 
                              analysis_results: Dict[str, Any],
                              script_type: str = 'frida') -> Dict[str, Any]:
        """
        Generate bypass scripts based on detected anti-debugging techniques.
        
        Args:
            analysis_results: Results from anti-debugging analysis
            script_type: Type of script to generate ('frida', 'python', 'windbg')
            
        Returns:
            Generated bypass scripts and usage instructions
        """
        try:
            if script_type not in ['frida', 'python', 'windbg']:
                return {
                    'error': f'Unsupported script type: {script_type}',
                    'success': False
                }
            
            detected_techniques = self._extract_detected_techniques(analysis_results)
            
            if script_type == 'frida':
                scripts = self._generate_frida_scripts(detected_techniques)
            elif script_type == 'python':
                scripts = self._generate_python_scripts(detected_techniques)
            else:  # windbg
                scripts = self._generate_windbg_scripts(detected_techniques)
            
            return {
                'success': True,
                'script_type': script_type,
                'scripts': scripts,
                'usage_instructions': self._generate_script_usage_instructions(script_type),
                'timestamp': time.time()
            }
            
        except Exception as e:
            self.logger.error(f"Bypass script generation failed: {e}")
            return {
                'error': str(e),
                'success': False
            }

    def get_detection_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive detection statistics and capabilities.
        
        Returns:
            Detection statistics and system information
        """
        try:
            stats = {
                'engine_info': {
                    'version': '1.0.0',
                    'capabilities': [
                        'API-based detection',
                        'PEB manipulation detection',
                        'Exception-based detection',
                        'Timing-based detection',
                        'Environment detection',
                        'Advanced technique detection'
                    ],
                    'supported_platforms': ['Windows', 'Linux'],
                    'static_analysis': True,
                    'dynamic_analysis': True
                },
                'configuration': self.config.copy(),
                'cache_info': {
                    'cached_results': len(self._results_cache),
                    'cache_enabled': self.config.get('cache_results', True)
                }
            }
            
            # Add analyzer statistics if available
            if self.analyzer:
                analyzer_stats = self.analyzer.get_analysis_statistics()
                stats['analyzer_stats'] = analyzer_stats
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Statistics retrieval failed: {e}")
            return {
                'error': str(e),
                'engine_info': {'version': '1.0.0', 'status': 'error'}
            }

    def update_configuration(self, new_config: Dict[str, Any]) -> bool:
        """
        Update engine configuration.
        
        Args:
            new_config: New configuration parameters
            
        Returns:
            True if configuration updated successfully
        """
        try:
            # Validate configuration
            valid_keys = {
                'enable_static_analysis', 'enable_dynamic_analysis',
                'aggressive_detection', 'deep_scan', 'cache_results',
                'timeout_seconds'
            }
            
            for key in new_config:
                if key not in valid_keys:
                    self.logger.warning(f"Unknown configuration key: {key}")
            
            # Update configuration
            self.config.update(new_config)
            
            self.logger.info("Anti-debugging engine configuration updated")
            return True
            
        except Exception as e:
            self.logger.error(f"Configuration update failed: {e}")
            return False

    def clear_cache(self):
        """Clear the results cache."""
        self._results_cache.clear()
        if self.analyzer:
            self.analyzer.clear_cache()
        self.logger.info("Anti-debugging analysis cache cleared")

    # Private helper methods

    def _generate_cache_key(self, binary_path: Path, config: Dict[str, Any]) -> str:
        """Generate cache key for analysis results."""
        import hashlib
        
        # Include file modification time and config in cache key
        try:
            mtime = binary_path.stat().st_mtime
            config_str = str(sorted(config.items()))
            key_data = f"{binary_path}_{mtime}_{config_str}"
            return hashlib.md5(key_data.encode()).hexdigest()
        except:
            return f"{binary_path}_{hash(str(config))}"

    def _enhance_results(self, results: Dict[str, Any], 
                        binary_path: Path, 
                        analysis_time: float, 
                        config: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance analysis results with integration metadata."""
        enhanced = results.copy()
        
        # Add integration metadata
        enhanced['integration_metadata'] = {
            'engine_version': '1.0.0',
            'binary_path': str(binary_path),
            'analysis_time': analysis_time,
            'configuration': config,
            'success': True,
            'timestamp': time.time()
        }
        
        # Add file information if not present
        if 'file_info' not in enhanced:
            try:
                stat = binary_path.stat()
                enhanced['file_info'] = {
                    'size': stat.st_size,
                    'modified': stat.st_mtime,
                    'path': str(binary_path)
                }
            except:
                pass
        
        # Add compatibility information
        enhanced['compatibility'] = {
            'intellicrack_integration': True,
            'protection_analyzer_compatible': True,
            'gui_compatible': True
        }
        
        return enhanced

    def _enhance_live_results(self, results: Dict[str, Any], 
                            pid: int, 
                            analysis_time: float, 
                            config: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance live process analysis results."""
        enhanced = results.copy()
        
        # Add live process metadata
        enhanced['integration_metadata'] = {
            'engine_version': '1.0.0',
            'analysis_type': 'live_process',
            'target_pid': pid,
            'analysis_time': analysis_time,
            'configuration': config,
            'success': True,
            'timestamp': time.time()
        }
        
        # Add process information if available
        try:
            import psutil
            proc = psutil.Process(pid)
            enhanced['process_info'] = {
                'name': proc.name(),
                'pid': pid,
                'ppid': proc.ppid(),
                'create_time': proc.create_time(),
                'cmdline': proc.cmdline()
            }
        except:
            enhanced['process_info'] = {'pid': pid}
        
        return enhanced

    def _determine_bypass_approach(self, detection_summary: Dict[str, Any]) -> str:
        """Determine the recommended bypass approach."""
        difficulty = detection_summary.get('bypass_difficulty', 'unknown')
        technique_count = detection_summary.get('total_techniques_detected', 0)
        
        if technique_count == 0:
            return 'Standard debugging tools should work without modifications'
        elif difficulty == 'easy':
            return 'Basic API hooking and patching'
        elif difficulty == 'medium':
            return 'Comprehensive anti-anti-debug solution'
        elif difficulty == 'hard':
            return 'Advanced evasion techniques and specialized tools'
        else:  # extreme
            return 'Manual reverse engineering and custom solutions'

    def _generate_tool_recommendations(self, analysis_results: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate tool recommendations based on detected techniques."""
        tools = []
        
        technique_categories = analysis_results.get('technique_categories', {})
        
        # API-based techniques
        if technique_categories.get('api_based', {}).get('detected'):
            tools.append({
                'name': 'API Monitor',
                'purpose': 'Monitor and modify API calls',
                'category': 'API Hooking'
            })
            tools.append({
                'name': 'Detours',
                'purpose': 'Microsoft library for API interception',
                'category': 'API Hooking'
            })
        
        # PEB manipulation
        if technique_categories.get('peb_manipulation', {}).get('detected'):
            tools.append({
                'name': 'ScyllaHide',
                'purpose': 'Comprehensive anti-anti-debug plugin',
                'category': 'Anti-Anti-Debug'
            })
            tools.append({
                'name': 'TitanHide',
                'purpose': 'Kernel-mode anti-anti-debug driver',
                'category': 'Anti-Anti-Debug'
            })
        
        # Timing-based techniques
        if technique_categories.get('timing_based', {}).get('detected'):
            tools.append({
                'name': 'Hardware Debuggers',
                'purpose': 'Hardware-assisted debugging to avoid timing detection',
                'category': 'Hardware Debugging'
            })
        
        # Environment detection
        if technique_categories.get('environment_based', {}).get('detected'):
            tools.append({
                'name': 'VM Detection Bypass',
                'purpose': 'Tools to hide virtualization environment',
                'category': 'Environment Evasion'
            })
        
        return tools

    def _generate_bypass_guide(self, analysis_results: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate step-by-step bypass guide."""
        guide = []
        
        technique_categories = analysis_results.get('technique_categories', {})
        
        # Step 1: Basic preparation
        guide.append({
            'step': 1,
            'title': 'Environment Preparation',
            'description': 'Set up analysis environment with necessary tools',
            'actions': [
                'Install debugger (x64dbg, OllyDbg, or IDA)',
                'Install anti-anti-debug plugins (ScyllaHide)',
                'Prepare API hooking framework'
            ]
        })
        
        # Step 2: API-based bypasses
        if technique_categories.get('api_based', {}).get('detected'):
            guide.append({
                'step': 2,
                'title': 'API-Based Bypass',
                'description': 'Bypass API-based anti-debugging checks',
                'actions': [
                    'Hook IsDebuggerPresent to return FALSE',
                    'Hook CheckRemoteDebuggerPresent',
                    'Hook NtQueryInformationProcess for debug-related queries'
                ]
            })
        
        # Step 3: PEB manipulation bypasses
        if technique_categories.get('peb_manipulation', {}).get('detected'):
            guide.append({
                'step': 3,
                'title': 'PEB Manipulation Bypass',
                'description': 'Modify PEB flags to hide debugger presence',
                'actions': [
                    'Patch PEB BeingDebugged flag to 0',
                    'Modify NtGlobalFlag to remove debug indicators',
                    'Fix heap flags in debug heap'
                ]
            })
        
        return guide

    def _generate_advanced_bypass_techniques(self, analysis_results: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate advanced bypass techniques."""
        techniques = []
        
        difficulty = analysis_results.get('detection_summary', {}).get('bypass_difficulty', 'easy')
        
        if difficulty in ['hard', 'extreme']:
            techniques.extend([
                {
                    'name': 'Kernel Debugging',
                    'description': 'Use kernel-mode debugger to avoid user-mode detection',
                    'complexity': 'High'
                },
                {
                    'name': 'Hardware Breakpoints',
                    'description': 'Use hardware debugging features',
                    'complexity': 'High'
                },
                {
                    'name': 'Emulation',
                    'description': 'Use CPU emulation to avoid detection',
                    'complexity': 'Very High'
                }
            ])
        
        return techniques

    def _get_bypass_priority(self, category: str, analysis_results: Dict[str, Any]) -> str:
        """Get bypass priority for category."""
        category_data = analysis_results.get('technique_categories', {}).get(category, {})
        detected_count = len(category_data.get('detected', []))
        
        if detected_count >= 3:
            return 'High'
        elif detected_count >= 2:
            return 'Medium'
        else:
            return 'Low'

    def _get_bypass_difficulty(self, category: str, analysis_results: Dict[str, Any]) -> str:
        """Get bypass difficulty for category."""
        difficulty_map = {
            'api_based': 'Easy',
            'peb_manipulation': 'Medium',
            'exception_based': 'Medium',
            'timing_based': 'Hard',
            'environment_based': 'Easy',
            'advanced_techniques': 'Very Hard'
        }
        
        return difficulty_map.get(category, 'Medium')

    def _get_category_tools(self, category: str) -> List[str]:
        """Get recommended tools for category."""
        tools_map = {
            'api_based': ['API Monitor', 'Detours', 'WinAPIOverride'],
            'peb_manipulation': ['ScyllaHide', 'TitanHide', 'Manual patching'],
            'exception_based': ['x64dbg', 'IDA Pro', 'Custom exception handlers'],
            'timing_based': ['Hardware debuggers', 'QEMU', 'Bochs'],
            'environment_based': ['VM detection bypass', 'Environment spoofing'],
            'advanced_techniques': ['Custom tools', 'Manual analysis', 'Emulation']
        }
        
        return tools_map.get(category, ['Manual analysis'])

    def _extract_detected_techniques(self, analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract detected techniques from analysis results."""
        techniques = []
        
        for category_data in analysis_results.get('technique_categories', {}).values():
            techniques.extend(category_data.get('detected', []))
        
        return techniques

    def _generate_frida_scripts(self, techniques: List[Dict[str, Any]]) -> Dict[str, str]:
        """Generate Frida bypass scripts."""
        scripts = {}
        
        # Base Frida script template
        base_script = '''
// Anti-Debugging Bypass Script
// Generated by Intellicrack Anti-Debug Analyzer

console.log("[+] Starting anti-debugging bypass...");

// Hook IsDebuggerPresent
if (Module.findExportByName("kernel32.dll", "IsDebuggerPresent")) {
    Interceptor.replace(Module.findExportByName("kernel32.dll", "IsDebuggerPresent"), new NativeCallback(function () {
        console.log("[+] IsDebuggerPresent called - returning FALSE");
        return 0;
    }, 'int', []));
}

// Hook CheckRemoteDebuggerPresent
if (Module.findExportByName("kernel32.dll", "CheckRemoteDebuggerPresent")) {
    Interceptor.replace(Module.findExportByName("kernel32.dll", "CheckRemoteDebuggerPresent"), new NativeCallback(function (hProcess, pbDebuggerPresent) {
        console.log("[+] CheckRemoteDebuggerPresent called - returning FALSE");
        Memory.writeU8(pbDebuggerPresent, 0);
        return 1;
    }, 'int', ['pointer', 'pointer']));
}

// Hook NtQueryInformationProcess
if (Module.findExportByName("ntdll.dll", "NtQueryInformationProcess")) {
    Interceptor.replace(Module.findExportByName("ntdll.dll", "NtQueryInformationProcess"), new NativeCallback(function (ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength) {
        var result = this.original(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
        
        // ProcessDebugPort (7)
        if (ProcessInformationClass == 7) {
            console.log("[+] NtQueryInformationProcess(ProcessDebugPort) - patching result");
            Memory.writeU32(ProcessInformation, 0);
        }
        // ProcessDebugFlags (31)
        else if (ProcessInformationClass == 31) {
            console.log("[+] NtQueryInformationProcess(ProcessDebugFlags) - patching result");
            Memory.writeU32(ProcessInformation, 1);
        }
        
        return result;
    }, 'uint32', ['pointer', 'uint32', 'pointer', 'uint32', 'pointer']));
}

console.log("[+] Anti-debugging bypass hooks installed");
'''
        
        scripts['comprehensive_bypass'] = base_script
        
        # Generate specific scripts based on detected techniques
        for technique in techniques:
            technique_name = technique.get('name', 'unknown')
            
            if 'isdebuggerpresent' in technique_name.lower():
                scripts['isdebuggerpresent_bypass'] = '''
// IsDebuggerPresent Bypass
Interceptor.replace(Module.findExportByName("kernel32.dll", "IsDebuggerPresent"), new NativeCallback(function () {
    return 0;
}, 'int', []));
'''
        
        return scripts

    def _generate_python_scripts(self, techniques: List[Dict[str, Any]]) -> Dict[str, str]:
        """Generate Python bypass scripts."""
        scripts = {}
        
        base_script = '''
#!/usr/bin/env python3
"""
Anti-Debugging Bypass Script
Generated by Intellicrack Anti-Debug Analyzer
"""

import ctypes
import ctypes.wintypes
from ctypes import windll

def patch_peb_being_debugged():
    """Patch PEB BeingDebugged flag"""
    try:
        # Get PEB address
        ntdll = windll.ntdll
        kernel32 = windll.kernel32
        
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
            # Patch BeingDebugged flag at PEB+2
            being_debugged = ctypes.c_ubyte.from_address(pbi.PebBaseAddress + 2)
            being_debugged.value = 0
            print("[+] PEB BeingDebugged flag patched")
            
    except Exception as e:
        print(f"[-] PEB patching failed: {e}")

def install_api_hooks():
    """Install API hooks using Python ctypes"""
    try:
        # This is a simplified example - real implementation would use
        # DLL injection or other hooking mechanisms
        print("[+] API hooks would be installed here")
        
    except Exception as e:
        print(f"[-] API hooking failed: {e}")

if __name__ == "__main__":
    print("[+] Starting Python anti-debugging bypass")
    patch_peb_being_debugged()
    install_api_hooks()
    print("[+] Bypass complete")
'''
        
        scripts['python_bypass'] = base_script
        
        return scripts

    def _generate_windbg_scripts(self, techniques: List[Dict[str, Any]]) -> Dict[str, str]:
        """Generate WinDbg bypass scripts."""
        scripts = {}
        
        base_script = '''
.echo "Anti-Debugging Bypass Script for WinDbg"
.echo "Generated by Intellicrack Anti-Debug Analyzer"

.echo "Setting up anti-debugging bypasses..."

* Patch IsDebuggerPresent
bp kernel32!IsDebuggerPresent "r eax=0; gc"

* Patch CheckRemoteDebuggerPresent  
bp kernel32!CheckRemoteDebuggerPresent "r eax=1; gc"

* Patch NtQueryInformationProcess for ProcessDebugPort
bp ntdll!NtQueryInformationProcess ".if (@$parg2 == 7) { ed @$parg3 0; r eax=0 } .else { gc }"

* Clear PEB BeingDebugged flag
r $t0 = poi(@$peb+2)
.if ($t0 != 0) { eb @$peb+2 0; .echo "PEB BeingDebugged flag cleared" }

.echo "Anti-debugging bypasses installed"
.echo "Continue execution with 'g'"
'''
        
        scripts['windbg_bypass'] = base_script
        
        return scripts

    def _generate_script_usage_instructions(self, script_type: str) -> List[str]:
        """Generate usage instructions for scripts."""
        instructions = {
            'frida': [
                "1. Install Frida: pip install frida-tools",
                "2. Start target process",
                "3. Run script: frida -l script.js -p <PID>",
                "4. Or attach to process: frida -l script.js <process_name>"
            ],
            'python': [
                "1. Run as administrator (required for memory patching)",
                "2. Execute: python bypass_script.py",
                "3. Script should be run before or during target execution"
            ],
            'windbg': [
                "1. Attach WinDbg to target process",
                "2. Load script: .load script.wds",
                "3. Or copy commands manually into WinDbg command window",
                "4. Continue execution with 'g'"
            ]
        }
        
        return instructions.get(script_type, ["No instructions available"])