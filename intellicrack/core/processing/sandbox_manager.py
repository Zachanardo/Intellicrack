"""
This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
Sandbox Manager - Unified interface for QEMU and Qiling emulation.

This module provides a unified sandbox management system that intelligently
selects between QEMU (full system emulation) and Qiling (lightweight binary
emulation) based on analysis requirements.
"""

import asyncio
import os
import time
import threading
import json
import tempfile
import shutil
from typing import Any, Dict, List, Optional, Tuple, Union, Callable
from enum import Enum, auto
from dataclasses import dataclass, field
from pathlib import Path
import logging

from intellicrack.logger import logger

# Import runtime behavior monitoring components
try:
    from .runtime_behavior_monitor import RuntimeBehaviorMonitor, MonitoringLevel, BehaviorProfile
    from .memory_pattern_analyzer import MemoryPatternAnalyzer
    from .network_behavior_analyzer import NetworkBehaviorAnalyzer
    from .behavioral_pattern_detector import BehavioralPatternDetector
    RUNTIME_MONITORING_AVAILABLE = True
except ImportError:
    RUNTIME_MONITORING_AVAILABLE = False
    logger.warning("Runtime behavior monitoring components not available")

# Import emulators with error handling
try:
    from .qemu_emulator import QEMUSystemEmulator
    QEMU_AVAILABLE = True
except ImportError:
    QEMUSystemEmulator = None
    QEMU_AVAILABLE = False
    logger.warning("QEMU emulator not available")

try:
    from .qiling_emulator import QilingEmulator, QILING_AVAILABLE
except ImportError:
    QilingEmulator = None
    QILING_AVAILABLE = False
    logger.warning("Qiling emulator not available")


class SandboxType(Enum):
    """Type of sandbox to use."""
    QILING = "qiling"      # Lightweight binary emulation
    QEMU = "qemu"          # Full system emulation
    AUTO = "auto"          # Automatically select based on requirements
    BOTH = "both"          # Run in both sandboxes for comparison


class AnalysisDepth(Enum):
    """Depth of analysis required."""
    QUICK = "quick"        # Basic API monitoring
    STANDARD = "standard"  # Standard analysis with hooks
    DEEP = "deep"          # Deep analysis with system monitoring
    FORENSIC = "forensic"  # Full forensic analysis with snapshots


@dataclass
class SandboxConfig:
    """Configuration for sandbox execution."""
    sandbox_type: SandboxType = SandboxType.AUTO
    analysis_depth: AnalysisDepth = AnalysisDepth.STANDARD
    timeout: int = 300  # 5 minutes default
    enable_network: bool = False
    enable_filesystem: bool = True
    enable_registry: bool = True  # Windows only
    enable_api_hooks: bool = True
    enable_memory_monitoring: bool = True
    enable_snapshots: bool = False
    snapshot_interval: int = 30  # seconds
    custom_rootfs: Optional[str] = None
    custom_hooks: Dict[str, Callable] = field(default_factory=dict)
    environment_vars: Dict[str, str] = field(default_factory=dict)
    command_line_args: List[str] = field(default_factory=list)
    working_directory: Optional[str] = None
    max_memory: int = 512  # MB
    cpu_limit: int = 1  # Number of CPUs
    
    # Runtime behavior monitoring settings
    enable_runtime_monitoring: bool = True
    monitoring_level: str = "standard"  # minimal, standard, intensive, forensic
    enable_pattern_detection: bool = True
    enable_network_analysis: bool = True
    enable_memory_pattern_analysis: bool = True
    behavior_analysis_window: float = 300.0  # seconds


@dataclass
class SandboxResult:
    """Results from sandbox execution."""
    success: bool
    sandbox_type: SandboxType
    execution_time: float
    exit_code: Optional[int] = None
    
    # API monitoring
    api_calls: List[Dict[str, Any]] = field(default_factory=list)
    
    # File system activity
    files_created: List[str] = field(default_factory=list)
    files_modified: List[str] = field(default_factory=list)
    files_deleted: List[str] = field(default_factory=list)
    files_read: List[str] = field(default_factory=list)
    
    # Registry activity (Windows)
    registry_keys_created: List[str] = field(default_factory=list)
    registry_keys_modified: List[str] = field(default_factory=list)
    registry_keys_deleted: List[str] = field(default_factory=list)
    
    # Network activity
    network_connections: List[Dict[str, Any]] = field(default_factory=list)
    dns_queries: List[str] = field(default_factory=list)
    
    # Process activity
    processes_created: List[Dict[str, Any]] = field(default_factory=list)
    
    # Memory activity
    memory_allocations: List[Dict[str, Any]] = field(default_factory=list)
    suspicious_memory_patterns: List[Dict[str, Any]] = field(default_factory=list)
    
    # License detection
    license_checks: List[Dict[str, Any]] = field(default_factory=list)
    license_files_accessed: List[str] = field(default_factory=list)
    license_api_calls: List[Dict[str, Any]] = field(default_factory=list)
    
    # Anti-analysis detection
    anti_debug_techniques: List[Dict[str, Any]] = field(default_factory=list)
    anti_vm_checks: List[Dict[str, Any]] = field(default_factory=list)
    
    # Snapshots (if enabled)
    snapshots: List[Dict[str, Any]] = field(default_factory=list)
    snapshot_diffs: List[Dict[str, Any]] = field(default_factory=list)
    
    # Errors and warnings
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
    # Raw logs
    stdout: str = ""
    stderr: str = ""
    debug_log: str = ""
    
    # Runtime behavior analysis results
    behavior_profile: Optional[Any] = None  # BehaviorProfile from runtime monitor
    detected_patterns: List[Dict[str, Any]] = field(default_factory=list)
    memory_analysis: Dict[str, Any] = field(default_factory=dict)
    network_analysis: Dict[str, Any] = field(default_factory=dict)
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)


class SandboxManager:
    """
    Unified sandbox manager for dynamic binary analysis.
    
    This class provides intelligent sandbox selection and execution,
    choosing between QEMU and Qiling based on analysis requirements.
    """
    
    def __init__(self):
        """Initialize sandbox manager."""
        self.logger = logging.getLogger(__name__)
        self._running_sandboxes = {}
        self._lock = threading.Lock()
        
        # Check available emulators
        self.qemu_available = QEMU_AVAILABLE
        self.qiling_available = QILING_AVAILABLE
        self.runtime_monitoring_available = RUNTIME_MONITORING_AVAILABLE
        
        # Runtime monitoring components
        self.runtime_monitor: Optional[Any] = None
        self.memory_analyzer: Optional[Any] = None
        self.network_analyzer: Optional[Any] = None
        self.pattern_detector: Optional[Any] = None
        
        if not self.qemu_available and not self.qiling_available:
            self.logger.error("No sandbox emulators available!")
        else:
            available = []
            if self.qemu_available:
                available.append("QEMU")
            if self.qiling_available:
                available.append("Qiling")
            if self.runtime_monitoring_available:
                available.append("Runtime Monitoring")
            self.logger.info(f"Sandbox manager initialized. Available: {', '.join(available)}")
    
    def analyze_binary(self, binary_path: str, config: Optional[SandboxConfig] = None) -> SandboxResult:
        """
        Analyze a binary in sandbox environment.
        
        Args:
            binary_path: Path to binary to analyze
            config: Sandbox configuration
            
        Returns:
            SandboxResult with analysis data
        """
        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary not found: {binary_path}")
        
        if config is None:
            config = SandboxConfig()
        
        # Determine sandbox type
        sandbox_type = self._determine_sandbox_type(binary_path, config)
        
        self.logger.info(f"Analyzing {binary_path} using {sandbox_type.value} sandbox")
        
        start_time = time.time()
        
        try:
            if sandbox_type == SandboxType.QILING:
                result = self._run_qiling_analysis(binary_path, config)
            elif sandbox_type == SandboxType.QEMU:
                result = self._run_qemu_analysis(binary_path, config)
            elif sandbox_type == SandboxType.BOTH:
                # Run both and merge results
                qiling_result = self._run_qiling_analysis(binary_path, config)
                qemu_result = self._run_qemu_analysis(binary_path, config)
                result = self._merge_results(qiling_result, qemu_result)
            else:
                raise ValueError(f"Unknown sandbox type: {sandbox_type}")
            
            result.execution_time = time.time() - start_time
            result.success = True
            
            # Post-process results
            self._analyze_behavior_patterns(result)
            self._detect_license_patterns(result)
            
            # Integrate runtime monitoring results if available
            if config.enable_runtime_monitoring and self.runtime_monitoring_available:
                self._integrate_runtime_monitoring_results(result, config)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Sandbox analysis failed: {e}", exc_info=True)
            result = SandboxResult(
                success=False,
                sandbox_type=sandbox_type,
                execution_time=time.time() - start_time
            )
            result.errors.append(str(e))
            return result
    
    def _determine_sandbox_type(self, binary_path: str, config: SandboxConfig) -> SandboxType:
        """Intelligently determine which sandbox to use."""
        if config.sandbox_type != SandboxType.AUTO:
            # User specified sandbox type
            if config.sandbox_type == SandboxType.QILING and not self.qiling_available:
                self.logger.warning("Qiling requested but not available, falling back to QEMU")
                return SandboxType.QEMU if self.qemu_available else SandboxType.QILING
            elif config.sandbox_type == SandboxType.QEMU and not self.qemu_available:
                self.logger.warning("QEMU requested but not available, falling back to Qiling")
                return SandboxType.QILING if self.qiling_available else SandboxType.QEMU
            return config.sandbox_type
        
        # Auto-select based on requirements and file characteristics
        file_size = os.path.getsize(binary_path)
        file_ext = Path(binary_path).suffix.lower()
        
        # Prefer Qiling for:
        # - Smaller binaries (< 50MB)
        # - Quick analysis depth
        # - Windows PE files (better API emulation)
        # - When snapshots not required
        prefer_qiling = (
            file_size < 50 * 1024 * 1024 and
            config.analysis_depth in [AnalysisDepth.QUICK, AnalysisDepth.STANDARD] and
            file_ext in ['.exe', '.dll'] and
            not config.enable_snapshots and
            self.qiling_available
        )
        
        # Prefer QEMU for:
        # - Large binaries
        # - Deep/forensic analysis
        # - Linux ELF files
        # - When snapshots required
        # - Network analysis
        prefer_qemu = (
            file_size > 50 * 1024 * 1024 or
            config.analysis_depth in [AnalysisDepth.DEEP, AnalysisDepth.FORENSIC] or
            file_ext in ['.elf', ''] or
            config.enable_snapshots or
            config.enable_network
        ) and self.qemu_available
        
        if prefer_qemu:
            return SandboxType.QEMU
        elif prefer_qiling:
            return SandboxType.QILING
        elif self.qiling_available:
            return SandboxType.QILING
        elif self.qemu_available:
            return SandboxType.QEMU
        else:
            raise RuntimeError("No sandbox emulator available")
    
    def _run_qiling_analysis(self, binary_path: str, config: SandboxConfig) -> SandboxResult:
        """Run analysis using Qiling emulator."""
        result = SandboxResult(success=False, sandbox_type=SandboxType.QILING, execution_time=0)
        
        if not self.qiling_available:
            result.errors.append("Qiling emulator not available")
            return result
        
        try:
            # Detect OS type from binary
            ostype = self._detect_os_type(binary_path)
            
            # Create Qiling emulator
            emulator = QilingEmulator(
                binary_path=binary_path,
                ostype=ostype,
                verbose=config.analysis_depth in [AnalysisDepth.DEEP, AnalysisDepth.FORENSIC]
            )
            
            # Configure hooks based on config
            if config.enable_api_hooks:
                self._setup_qiling_api_hooks(emulator, result)
            
            if config.enable_memory_monitoring:
                self._setup_qiling_memory_hooks(emulator, result)
            
            if config.enable_filesystem:
                self._setup_qiling_filesystem_hooks(emulator, result)
            
            if config.enable_registry and ostype == 'windows':
                self._setup_qiling_registry_hooks(emulator, result)
            
            # Set up license detection hooks
            self._setup_qiling_license_hooks(emulator, result)
            
            # Run emulation
            emulation_result = emulator.run(
                timeout=config.timeout,
                args=config.command_line_args
            )
            
            # Extract results
            if emulation_result and emulation_result.get('success'):
                result.api_calls = emulation_result.get('api_calls', [])
                result.memory_allocations = emulation_result.get('memory_accesses', [])
                result.license_checks = emulation_result.get('license_checks', [])
                result.anti_debug_techniques = emulation_result.get('anti_debug', [])
                result.exit_code = emulation_result.get('exit_code')
                result.stdout = emulation_result.get('stdout', '')
                result.stderr = emulation_result.get('stderr', '')
                result.success = True
            else:
                result.errors.append("Qiling emulation failed")
                if emulation_result:
                    result.errors.extend(emulation_result.get('errors', []))
            
            return result
            
        except Exception as e:
            self.logger.error(f"Qiling analysis error: {e}", exc_info=True)
            result.errors.append(str(e))
            return result
    
    def _run_qemu_analysis(self, binary_path: str, config: SandboxConfig) -> SandboxResult:
        """Run analysis using QEMU emulator."""
        result = SandboxResult(success=False, sandbox_type=SandboxType.QEMU, execution_time=0)
        
        if not self.qemu_available:
            result.errors.append("QEMU emulator not available")
            return result
        
        try:
            # Detect architecture
            arch = self._detect_architecture(binary_path)
            
            # Create QEMU emulator
            emulator = QEMUSystemEmulator(
                binary_path=binary_path,
                architecture=arch,
                rootfs_path=config.custom_rootfs,
                config={
                    'memory': config.max_memory,
                    'cpus': config.cpu_limit,
                    'network': config.enable_network,
                    'snapshot_interval': config.snapshot_interval if config.enable_snapshots else 0
                }
            )
            
            # Start emulation
            with emulator:
                # Create initial snapshot if requested
                if config.enable_snapshots:
                    snapshot_before = emulator.create_snapshot("before_execution")
                    result.snapshots.append(snapshot_before)
                
                # Copy binary to VM
                emulator.copy_file_to_vm(binary_path, "/tmp/target_binary")
                
                # Execute binary
                execution_result = emulator.execute_binary(
                    "/tmp/target_binary",
                    args=config.command_line_args,
                    env=config.environment_vars,
                    timeout=config.timeout
                )
                
                # Monitor execution
                if config.analysis_depth in [AnalysisDepth.DEEP, AnalysisDepth.FORENSIC]:
                    # Collect system state periodically
                    monitor_thread = threading.Thread(
                        target=self._monitor_qemu_execution,
                        args=(emulator, result, config)
                    )
                    monitor_thread.daemon = True
                    monitor_thread.start()
                
                # Wait for execution to complete
                emulator.wait_for_completion(timeout=config.timeout)
                
                # Create final snapshot if requested
                if config.enable_snapshots:
                    snapshot_after = emulator.create_snapshot("after_execution")
                    result.snapshots.append(snapshot_after)
                    
                    # Compare snapshots
                    diff = emulator.compare_snapshots("before_execution", "after_execution")
                    result.snapshot_diffs.append(diff)
                    
                    # Extract changes
                    self._extract_snapshot_changes(diff, result)
                
                # Collect results
                vm_state = emulator.get_vm_state()
                result.exit_code = execution_result.get('exit_code')
                result.stdout = execution_result.get('stdout', '')
                result.stderr = execution_result.get('stderr', '')
                
                # Extract file system changes
                if config.enable_filesystem:
                    fs_changes = emulator.get_filesystem_changes()
                    result.files_created = fs_changes.get('created', [])
                    result.files_modified = fs_changes.get('modified', [])
                    result.files_deleted = fs_changes.get('deleted', [])
                
                # Extract network activity
                if config.enable_network:
                    net_activity = emulator.get_network_activity()
                    result.network_connections = net_activity.get('connections', [])
                    result.dns_queries = net_activity.get('dns_queries', [])
                
                # Extract process activity
                proc_activity = emulator.get_process_activity()
                result.processes_created = proc_activity.get('created', [])
                
                result.success = True
                
            return result
            
        except Exception as e:
            self.logger.error(f"QEMU analysis error: {e}", exc_info=True)
            result.errors.append(str(e))
            return result
    
    async def _monitor_qemu_execution(self, emulator: QEMUSystemEmulator, result: SandboxResult, config: SandboxConfig):
        """Monitor QEMU execution in background thread."""
        try:
            interval = 5  # seconds
            max_iterations = config.timeout // interval
            
            for _ in range(max_iterations):
                if not emulator.is_running():
                    break
                
                # Collect current state
                state = emulator.get_vm_state()
                
                # Monitor memory
                if config.enable_memory_monitoring:
                    mem_state = emulator.get_memory_state()
                    suspicious = self._detect_suspicious_memory_patterns(mem_state)
                    if suspicious:
                        result.suspicious_memory_patterns.extend(suspicious)
                
                # Monitor processes
                processes = emulator.get_running_processes()
                for proc in processes:
                    if self._is_suspicious_process(proc):
                        result.warnings.append(f"Suspicious process detected: {proc['name']}")
                
                await asyncio.sleep(interval)
                
        except Exception as e:
            self.logger.error(f"Monitoring error: {e}")
            result.errors.append(f"Monitoring error: {str(e)}")
    
    def _setup_qiling_api_hooks(self, emulator: QilingEmulator, result: SandboxResult):
        """Set up API hooks for Qiling emulator."""
        # Common Windows APIs for license checking
        license_apis = [
            'RegQueryValueExA', 'RegQueryValueExW',
            'GetVolumeInformationA', 'GetVolumeInformationW',
            'GetComputerNameA', 'GetComputerNameW',
            'GetUserNameA', 'GetUserNameW',
            'GetSystemTime', 'GetLocalTime',
            'InternetOpenA', 'InternetOpenW',
            'HttpSendRequestA', 'HttpSendRequestW',
            'CreateFileA', 'CreateFileW',
            'ReadFile', 'WriteFile'
        ]
        
        def api_hook(ql, address, params):
            """Generic API hook."""
            api_call = {
                'address': address,
                'timestamp': time.time(),
                'params': params
            }
            result.api_calls.append(api_call)
        
        for api in license_apis:
            emulator.hook_api(api, api_hook)
    
    def _setup_qiling_memory_hooks(self, emulator: QilingEmulator, result: SandboxResult):
        """Set up memory monitoring hooks."""
        def mem_hook(ql, access, address, size, value):
            """Memory access hook."""
            mem_access = {
                'type': access,
                'address': address,
                'size': size,
                'value': value,
                'timestamp': time.time()
            }
            result.memory_allocations.append(mem_access)
        
        emulator.hook_mem_read(mem_hook)
        emulator.hook_mem_write(mem_hook)
    
    def _setup_qiling_filesystem_hooks(self, emulator: QilingEmulator, result: SandboxResult):
        """Set up file system hooks."""
        def file_hook(ql, filename, flags):
            """File access hook."""
            if 'r' in flags:
                result.files_read.append(filename)
            if 'w' in flags or 'a' in flags:
                result.files_modified.append(filename)
            if 'license' in filename.lower() or 'key' in filename.lower():
                result.license_files_accessed.append(filename)
        
        emulator.hook_file_access(file_hook)
    
    def _setup_qiling_registry_hooks(self, emulator: QilingEmulator, result: SandboxResult):
        """Set up Windows registry hooks."""
        def reg_hook(ql, key, value, data):
            """Registry access hook."""
            reg_access = {
                'key': key,
                'value': value,
                'data': data,
                'timestamp': time.time()
            }
            
            if 'license' in key.lower() or 'serial' in key.lower():
                result.license_checks.append({
                    'type': 'registry',
                    'details': reg_access
                })
        
        emulator.hook_registry_access(reg_hook)
    
    def _setup_qiling_license_hooks(self, emulator: QilingEmulator, result: SandboxResult):
        """Set up specific hooks for license detection."""
        # Hook string comparisons
        def strcmp_hook(ql, s1, s2):
            """String comparison hook."""
            if any(lic in [s1, s2] for lic in ['LICENSE', 'TRIAL', 'DEMO', 'REGISTERED']):
                result.license_checks.append({
                    'type': 'string_compare',
                    'strings': [s1, s2],
                    'timestamp': time.time()
                })
        
        emulator.hook_api('strcmp', strcmp_hook)
        emulator.hook_api('wcscmp', strcmp_hook)
        
        # Hook time-based checks
        def time_hook(ql, *args):
            """Time API hook."""
            result.license_checks.append({
                'type': 'time_check',
                'api': ql.os.function,
                'timestamp': time.time()
            })
        
        for time_api in ['GetSystemTime', 'GetLocalTime', 'time', 'gettimeofday']:
            emulator.hook_api(time_api, time_hook)
    
    def _extract_snapshot_changes(self, diff: Dict[str, Any], result: SandboxResult):
        """Extract meaningful changes from snapshot diff."""
        if 'filesystem' in diff:
            fs_diff = diff['filesystem']
            result.files_created.extend(fs_diff.get('added', []))
            result.files_modified.extend(fs_diff.get('modified', []))
            result.files_deleted.extend(fs_diff.get('deleted', []))
        
        if 'registry' in diff:
            reg_diff = diff['registry']
            result.registry_keys_created.extend(reg_diff.get('added', []))
            result.registry_keys_modified.extend(reg_diff.get('modified', []))
            result.registry_keys_deleted.extend(reg_diff.get('deleted', []))
        
        if 'memory' in diff:
            mem_diff = diff['memory']
            if 'suspicious_patterns' in mem_diff:
                result.suspicious_memory_patterns.extend(mem_diff['suspicious_patterns'])
    
    def _analyze_behavior_patterns(self, result: SandboxResult):
        """Analyze collected behavior for patterns."""
        # Detect anti-analysis techniques
        anti_debug_apis = ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess']
        for api_call in result.api_calls:
            if any(api in str(api_call) for api in anti_debug_apis):
                result.anti_debug_techniques.append({
                    'type': 'api_call',
                    'details': api_call
                })
        
        # Detect VM detection attempts
        vm_indicators = ['VMware', 'VirtualBox', 'QEMU', 'Hyper-V', 'Xen']
        for file_read in result.files_read:
            if any(vm in file_read for vm in vm_indicators):
                result.anti_vm_checks.append({
                    'type': 'file_check',
                    'file': file_read
                })
        
        # Detect potential license checks
        license_patterns = ['trial', 'license', 'serial', 'key', 'activation', 'registered']
        for api_call in result.api_calls:
            if any(pattern in str(api_call).lower() for pattern in license_patterns):
                result.license_api_calls.append(api_call)
    
    def _detect_license_patterns(self, result: SandboxResult):
        """Detect license-related patterns in behavior."""
        # Time-based checks
        time_apis = ['GetSystemTime', 'GetLocalTime', 'time', 'gettimeofday']
        time_checks = [api for api in result.api_calls if any(t in str(api) for t in time_apis)]
        if len(time_checks) > 5:  # Suspicious number of time checks
            result.warnings.append("Excessive time API calls detected - possible time-based license")
        
        # Hardware fingerprinting
        hw_apis = ['GetVolumeInformation', 'GetComputerName', 'GetAdaptersInfo']
        hw_checks = [api for api in result.api_calls if any(h in str(api) for h in hw_apis)]
        if hw_checks:
            result.warnings.append("Hardware fingerprinting detected - possible hardware-locked license")
        
        # Network license validation
        net_patterns = ['activate', 'validate', 'license', 'auth']
        for conn in result.network_connections:
            if any(p in str(conn).lower() for p in net_patterns):
                result.warnings.append(f"Potential network license check: {conn}")
    
    def _detect_os_type(self, binary_path: str) -> str:
        """Detect OS type from binary."""
        with open(binary_path, 'rb') as f:
            header = f.read(4)
        
        if header[:2] == b'MZ':  # DOS/Windows header
            return 'windows'
        elif header == b'\x7fELF':  # ELF header
            return 'linux'
        elif header in [b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe']:  # Mach-O
            return 'macos'
        else:
            # Default to Windows for unknown
            return 'windows'
    
    def _detect_architecture(self, binary_path: str) -> str:
        """Detect architecture from binary."""
        with open(binary_path, 'rb') as f:
            data = f.read(1024)
        
        # Check PE header for Windows
        if data[:2] == b'MZ':
            pe_offset = int.from_bytes(data[0x3C:0x40], 'little')
            if pe_offset + 6 < len(data):
                machine = int.from_bytes(data[pe_offset+4:pe_offset+6], 'little')
                if machine == 0x14c:
                    return 'x86'
                elif machine == 0x8664:
                    return 'x86_64'
        
        # Check ELF header
        elif data[:4] == b'\x7fELF':
            ei_class = data[4]
            if ei_class == 1:
                return 'x86'
            elif ei_class == 2:
                return 'x86_64'
        
        # Default to x86_64
        return 'x86_64'
    
    def _detect_suspicious_memory_patterns(self, mem_state: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect suspicious memory patterns."""
        suspicious = []
        
        # Check for common shellcode patterns
        shellcode_patterns = [
            b'\x90\x90\x90\x90',  # NOP sled
            b'\xeb\xfe',          # Infinite loop
            b'\x31\xc0',          # xor eax, eax
            b'\x31\xdb',          # xor ebx, ebx
        ]
        
        memory_dump = mem_state.get('dump', b'')
        for pattern in shellcode_patterns:
            if pattern in memory_dump:
                suspicious.append({
                    'type': 'shellcode_pattern',
                    'pattern': pattern.hex(),
                    'confidence': 0.7
                })
        
        return suspicious
    
    def _is_suspicious_process(self, process: Dict[str, Any]) -> bool:
        """Check if a process is suspicious."""
        suspicious_names = ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe']
        proc_name = process.get('name', '').lower()
        return any(susp in proc_name for susp in suspicious_names)
    
    def _merge_results(self, qiling_result: SandboxResult, qemu_result: SandboxResult) -> SandboxResult:
        """Merge results from both sandboxes."""
        merged = SandboxResult(
            success=qiling_result.success and qemu_result.success,
            sandbox_type=SandboxType.BOTH,
            execution_time=max(qiling_result.execution_time, qemu_result.execution_time)
        )
        
        # Merge all lists
        for field in ['api_calls', 'files_created', 'files_modified', 'files_deleted',
                     'files_read', 'registry_keys_created', 'registry_keys_modified',
                     'registry_keys_deleted', 'network_connections', 'dns_queries',
                     'processes_created', 'memory_allocations', 'suspicious_memory_patterns',
                     'license_checks', 'license_files_accessed', 'license_api_calls',
                     'anti_debug_techniques', 'anti_vm_checks', 'errors', 'warnings']:
            merged_list = list(set(
                getattr(qiling_result, field, []) + 
                getattr(qemu_result, field, [])
            ))
            setattr(merged, field, merged_list)
        
        # Combine metadata
        merged.metadata = {
            'qiling': qiling_result.metadata,
            'qemu': qemu_result.metadata
        }
        
        return merged
    
    def compare_sandbox_results(self, result1: SandboxResult, result2: SandboxResult) -> Dict[str, Any]:
        """Compare results from different sandbox executions."""
        comparison = {
            'common_api_calls': set(map(str, result1.api_calls)) & set(map(str, result2.api_calls)),
            'unique_to_first': {
                'api_calls': set(map(str, result1.api_calls)) - set(map(str, result2.api_calls)),
                'files': set(result1.files_created) - set(result2.files_created),
                'network': set(map(str, result1.network_connections)) - set(map(str, result2.network_connections))
            },
            'unique_to_second': {
                'api_calls': set(map(str, result2.api_calls)) - set(map(str, result1.api_calls)),
                'files': set(result2.files_created) - set(result1.files_created),
                'network': set(map(str, result2.network_connections)) - set(map(str, result1.network_connections))
            },
            'behavior_consistency': self._calculate_behavior_consistency(result1, result2)
        }
        
        return comparison
    
    def _calculate_behavior_consistency(self, result1: SandboxResult, result2: SandboxResult) -> float:
        """Calculate consistency score between two results."""
        # Simple Jaccard similarity for behavior patterns
        patterns1 = set(map(str, result1.api_calls + result1.files_created + result1.network_connections))
        patterns2 = set(map(str, result2.api_calls + result2.files_created + result2.network_connections))
        
        if not patterns1 and not patterns2:
            return 1.0
        
        intersection = patterns1 & patterns2
        union = patterns1 | patterns2
        
        return len(intersection) / len(union) if union else 0.0
    
    def export_results(self, result: SandboxResult, output_path: str, format: str = 'json'):
        """Export sandbox results to file."""
        if format == 'json':
            # Convert dataclass to dict
            data = {
                'success': result.success,
                'sandbox_type': result.sandbox_type.value,
                'execution_time': result.execution_time,
                'exit_code': result.exit_code,
                'api_calls': result.api_calls,
                'files': {
                    'created': result.files_created,
                    'modified': result.files_modified,
                    'deleted': result.files_deleted,
                    'read': result.files_read
                },
                'registry': {
                    'created': result.registry_keys_created,
                    'modified': result.registry_keys_modified,
                    'deleted': result.registry_keys_deleted
                },
                'network': {
                    'connections': result.network_connections,
                    'dns_queries': result.dns_queries
                },
                'processes': result.processes_created,
                'memory': {
                    'allocations': result.memory_allocations,
                    'suspicious_patterns': result.suspicious_memory_patterns
                },
                'license_detection': {
                    'checks': result.license_checks,
                    'files_accessed': result.license_files_accessed,
                    'api_calls': result.license_api_calls
                },
                'anti_analysis': {
                    'anti_debug': result.anti_debug_techniques,
                    'anti_vm': result.anti_vm_checks
                },
                'snapshots': result.snapshots,
                'errors': result.errors,
                'warnings': result.warnings,
                'metadata': result.metadata
            }
            
            with open(output_path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        
        elif format == 'html':
            # Generate HTML report
            html = self._generate_html_report(result)
            with open(output_path, 'w') as f:
                f.write(html)
        
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _generate_html_report(self, result: SandboxResult) -> str:
        """Generate HTML report from results."""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Sandbox Analysis Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                h1 { color: #333; }
                h2 { color: #666; border-bottom: 1px solid #ccc; }
                .success { color: green; }
                .error { color: red; }
                .warning { color: orange; }
                table { border-collapse: collapse; width: 100%; margin: 10px 0; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                .code { font-family: monospace; background: #f5f5f5; padding: 2px 4px; }
            </style>
        </head>
        <body>
            <h1>Sandbox Analysis Report</h1>
            <p><strong>Sandbox Type:</strong> {sandbox_type}</p>
            <p><strong>Execution Time:</strong> {execution_time:.2f} seconds</p>
            <p><strong>Status:</strong> <span class="{status_class}">{status}</span></p>
            
            <h2>Summary</h2>
            <ul>
                <li>API Calls: {api_count}</li>
                <li>Files Created: {files_created}</li>
                <li>Network Connections: {network_count}</li>
                <li>License Checks: {license_count}</li>
            </ul>
            
            <h2>License Detection</h2>
            {license_section}
            
            <h2>Anti-Analysis Techniques</h2>
            {anti_analysis_section}
            
            <h2>Warnings</h2>
            {warnings_section}
            
            <h2>Errors</h2>
            {errors_section}
        </body>
        </html>
        """
        
        # Fill template
        return html_template.format(
            sandbox_type=result.sandbox_type.value,
            execution_time=result.execution_time,
            status_class='success' if result.success else 'error',
            status='Success' if result.success else 'Failed',
            api_count=len(result.api_calls),
            files_created=len(result.files_created),
            network_count=len(result.network_connections),
            license_count=len(result.license_checks),
            license_section=self._format_license_section(result),
            anti_analysis_section=self._format_anti_analysis_section(result),
            warnings_section=self._format_list(result.warnings, 'warning'),
            errors_section=self._format_list(result.errors, 'error')
        )
    
    def _format_license_section(self, result: SandboxResult) -> str:
        """Format license detection section for HTML."""
        if not result.license_checks:
            return "<p>No license checks detected.</p>"
        
        html = "<table><tr><th>Type</th><th>Details</th></tr>"
        for check in result.license_checks[:10]:  # Limit to first 10
            html += f"<tr><td>{check.get('type', 'unknown')}</td>"
            html += f"<td class='code'>{str(check.get('details', ''))[:100]}...</td></tr>"
        html += "</table>"
        
        if len(result.license_checks) > 10:
            html += f"<p>... and {len(result.license_checks) - 10} more license checks</p>"
        
        return html
    
    def _format_anti_analysis_section(self, result: SandboxResult) -> str:
        """Format anti-analysis section for HTML."""
        techniques = result.anti_debug_techniques + result.anti_vm_checks
        if not techniques:
            return "<p>No anti-analysis techniques detected.</p>"
        
        html = "<ul>"
        for tech in techniques[:10]:
            html += f"<li>{tech.get('type', 'unknown')}: {str(tech.get('details', ''))[:50]}...</li>"
        html += "</ul>"
        
        return html

    async def _integrate_runtime_monitoring_results(self, result: SandboxResult, 
                                                   config: SandboxConfig) -> None:
        """Integrate runtime behavior monitoring results into sandbox analysis."""
        if not config.enable_runtime_monitoring:
            return
        
        try:
            # Initialize runtime monitors
            runtime_monitor = RuntimeBehaviorMonitor(
                monitoring_level=MonitoringLevel(config.monitoring_level),
                target_process=None
            )
            
            memory_analyzer = MemoryPatternAnalyzer()
            network_analyzer = NetworkBehaviorAnalyzer()
            pattern_detector = BehavioralPatternDetector()
            
            # Start monitoring for the analysis duration
            monitoring_started = runtime_monitor.start_monitoring()
            if not monitoring_started:
                result.warnings.append("Failed to start runtime behavior monitoring")
                return
            
            # Let monitoring run during sandbox execution
            await asyncio.sleep(min(config.behavior_analysis_window, config.timeout))
            
            # Stop monitoring and collect results
            runtime_monitor.stop_monitoring()
            monitoring_results = runtime_monitor.get_monitoring_results()
            
            # Integrate monitoring data into results
            if monitoring_results:
                result.monitoring_events = monitoring_results.get('events', [])
                result.detected_patterns = monitoring_results.get('patterns', [])
                result.behavioral_analysis = monitoring_results.get('analysis', {})
                
                # Add license-related findings
                license_events = [e for e in result.monitoring_events 
                                if 'license' in str(e).lower()]
                if license_events:
                    result.license_checks.extend([
                        {'event': str(e), 'source': 'runtime_monitoring'} 
                        for e in license_events
                    ])
                
                # Add network findings
                network_events = [e for e in result.monitoring_events 
                                if hasattr(e, 'event_type') and e.event_type == 'network']
                if network_events:
                    result.network_connections.extend([
                        {'type': 'monitoring', 'details': str(e)} 
                        for e in network_events
                    ])
            
        except ImportError:
            result.warnings.append("Runtime monitoring dependencies not available")
        except Exception as e:
            result.warnings.append(f"Runtime monitoring failed: {e}")

    def _collect_monitoring_results(self, result: SandboxResult) -> Dict[str, Any]:
        """Collect and format all monitoring results for reporting."""
        monitoring_data = {
            'events_count': len(getattr(result, 'monitoring_events', [])),
            'patterns_detected': len(getattr(result, 'detected_patterns', [])),
            'behavioral_analysis': getattr(result, 'behavioral_analysis', {}),
            'monitoring_active': hasattr(result, 'monitoring_events')
        }
        
        # Categorize events by type
        events = getattr(result, 'monitoring_events', [])
        event_categories = {}
        for event in events:
            event_type = getattr(event, 'event_type', 'unknown')
            if event_type not in event_categories:
                event_categories[event_type] = 0
            event_categories[event_type] += 1
        
        monitoring_data['event_categories'] = event_categories
        
        # Extract pattern summaries
        patterns = getattr(result, 'detected_patterns', [])
        pattern_summaries = []
        for pattern in patterns:
            pattern_summaries.append({
                'type': getattr(pattern, 'pattern_type', 'unknown'),
                'confidence': getattr(pattern, 'confidence', 0.0),
                'description': getattr(pattern, 'description', 'No description')
            })
        
        monitoring_data['pattern_summaries'] = pattern_summaries
        
        return monitoring_data

    async def analyze_binary_with_comprehensive_monitoring(self, binary_path: str, 
                                                         config: SandboxConfig) -> SandboxResult:
        """Enhanced binary analysis with comprehensive runtime monitoring."""
        result = SandboxResult(binary_path=binary_path, sandbox_type=config.sandbox_type)
        
        try:
            # Start standard sandbox analysis
            standard_result = await self._run_standard_analysis(binary_path, config)
            
            # Copy standard results
            result = standard_result
            
            # Add comprehensive monitoring if enabled
            if config.enable_runtime_monitoring:
                await self._integrate_runtime_monitoring_results(result, config)
                
                # Run pattern detection on collected data
                if config.enable_pattern_detection and hasattr(result, 'monitoring_events'):
                    pattern_results = await self._run_pattern_detection(result)
                    if pattern_results:
                        result.detected_patterns.extend(pattern_results)
                
                # Run network behavior analysis
                if config.enable_network_analysis:
                    network_results = await self._run_network_analysis(result)
                    if network_results:
                        result.behavioral_analysis.update(network_results)
                
                # Run memory pattern analysis
                if config.enable_memory_pattern_analysis:
                    memory_results = await self._run_memory_analysis(result)
                    if memory_results:
                        result.behavioral_analysis.update(memory_results)
            
            result.success = True
            
        except Exception as e:
            result.success = False
            result.errors.append(f"Comprehensive analysis failed: {e}")
        
        return result

    async def _run_standard_analysis(self, binary_path: str, config: SandboxConfig) -> SandboxResult:
        """Run the standard sandbox analysis pipeline."""
        # This would call the existing analyze_binary method
        return self.analyze_binary(binary_path, config)

    async def _run_pattern_detection(self, result: SandboxResult) -> List[Any]:
        """Run behavioral pattern detection on monitoring data."""
        try:
            from .runtime_behavior_monitor import BehavioralPatternDetector
            detector = BehavioralPatternDetector()
            
            events = getattr(result, 'monitoring_events', [])
            if events:
                return detector.detect_patterns(events)
        except ImportError:
            pass
        except Exception as e:
            result.warnings.append(f"Pattern detection failed: {e}")
        
        return []

    async def _run_network_analysis(self, result: SandboxResult) -> Dict[str, Any]:
        """Run network behavior analysis on monitoring data."""
        try:
            from .network_behavior_analyzer import NetworkBehaviorAnalyzer
            analyzer = NetworkBehaviorAnalyzer()
            
            # Analyze network events from monitoring
            network_events = [e for e in getattr(result, 'monitoring_events', [])
                            if hasattr(e, 'event_type') and e.event_type == 'network']
            
            if network_events:
                return analyzer.analyze_behavior_patterns(network_events)
        except ImportError:
            pass
        except Exception as e:
            result.warnings.append(f"Network analysis failed: {e}")
        
        return {}

    async def _run_memory_analysis(self, result: SandboxResult) -> Dict[str, Any]:
        """Run memory pattern analysis on monitoring data."""
        try:
            from .memory_pattern_analyzer import MemoryPatternAnalyzer
            analyzer = MemoryPatternAnalyzer()
            
            # Analyze memory events from monitoring
            memory_events = [e for e in getattr(result, 'monitoring_events', [])
                           if hasattr(e, 'event_type') and e.event_type == 'memory']
            
            if memory_events:
                return analyzer.analyze_patterns(memory_events)
        except ImportError:
            pass
        except Exception as e:
            result.warnings.append(f"Memory analysis failed: {e}")
        
        return {}

    def _generate_comprehensive_report(self, result: SandboxResult, 
                                     format_type: str = 'html') -> str:
        """Generate comprehensive analysis report including monitoring data."""
        if format_type == 'html':
            return self._generate_html_report_with_monitoring(result)
        elif format_type == 'json':
            return self._generate_json_report_with_monitoring(result)
        elif format_type == 'xml':
            return self._generate_xml_report_with_monitoring(result)
        else:
            raise ValueError(f"Unsupported report format: {format_type}")

    def _generate_html_report_with_monitoring(self, result: SandboxResult) -> str:
        """Generate enhanced HTML report with monitoring data."""
        base_html = self.generate_html_report(result)
        
        # Add monitoring section
        monitoring_data = self._collect_monitoring_results(result)
        
        monitoring_section = f"""
        <div class="section monitoring-section">
            <h2>Runtime Behavior Monitoring</h2>
            <div class="monitoring-summary">
                <p><strong>Monitoring Active:</strong> {monitoring_data['monitoring_active']}</p>
                <p><strong>Events Captured:</strong> {monitoring_data['events_count']}</p>
                <p><strong>Patterns Detected:</strong> {monitoring_data['patterns_detected']}</p>
            </div>
            
            <h3>Event Categories</h3>
            <ul class="event-categories">
        """
        
        for category, count in monitoring_data['event_categories'].items():
            monitoring_section += f"<li>{category}: {count} events</li>"
        
        monitoring_section += """
            </ul>
            
            <h3>Detected Patterns</h3>
            <ul class="detected-patterns">
        """
        
        for pattern in monitoring_data['pattern_summaries']:
            monitoring_section += f"""
                <li>
                    <strong>{pattern['type']}</strong> 
                    (Confidence: {pattern['confidence']:.2f}): 
                    {pattern['description']}
                </li>
            """
        
        monitoring_section += """
            </ul>
        </div>
        """
        
        # Insert before closing body tag
        enhanced_html = base_html.replace('</body>', f'{monitoring_section}</body>')
        return enhanced_html

    def _generate_json_report_with_monitoring(self, result: SandboxResult) -> str:
        """Generate JSON report with monitoring data."""
        import json
        
        base_data = {
            'binary_path': result.binary_path,
            'sandbox_type': result.sandbox_type.value,
            'success': result.success,
            'execution_time': result.execution_time,
            'api_calls': result.api_calls,
            'files_created': result.files_created,
            'registry_changes': result.registry_changes,
            'network_connections': result.network_connections,
            'license_checks': result.license_checks,
            'protection_techniques': result.protection_techniques,
            'warnings': result.warnings,
            'errors': result.errors
        }
        
        # Add monitoring data
        monitoring_data = self._collect_monitoring_results(result)
        base_data['runtime_monitoring'] = monitoring_data
        
        if hasattr(result, 'monitoring_events'):
            base_data['runtime_monitoring']['events'] = [
                str(event) for event in result.monitoring_events
            ]
        
        if hasattr(result, 'detected_patterns'):
            base_data['runtime_monitoring']['patterns'] = [
                {
                    'type': getattr(p, 'pattern_type', 'unknown'),
                    'confidence': getattr(p, 'confidence', 0.0),
                    'description': getattr(p, 'description', '')
                } for p in result.detected_patterns
            ]
        
        if hasattr(result, 'behavioral_analysis'):
            base_data['runtime_monitoring']['behavioral_analysis'] = result.behavioral_analysis
        
        return json.dumps(base_data, indent=2, default=str)

    def _generate_xml_report_with_monitoring(self, result: SandboxResult) -> str:
        """Generate XML report with monitoring data."""
        from xml.etree.ElementTree import Element, SubElement, tostring
        from xml.dom.minidom import parseString
        
        root = Element('sandbox_analysis')
        
        # Basic info
        basic = SubElement(root, 'basic_info')
        SubElement(basic, 'binary_path').text = result.binary_path
        SubElement(basic, 'sandbox_type').text = result.sandbox_type.value
        SubElement(basic, 'success').text = str(result.success)
        SubElement(basic, 'execution_time').text = str(result.execution_time)
        
        # Monitoring section
        monitoring = SubElement(root, 'runtime_monitoring')
        monitoring_data = self._collect_monitoring_results(result)
        
        SubElement(monitoring, 'events_count').text = str(monitoring_data['events_count'])
        SubElement(monitoring, 'patterns_detected').text = str(monitoring_data['patterns_detected'])
        
        # Event categories
        categories = SubElement(monitoring, 'event_categories')
        for category, count in monitoring_data['event_categories'].items():
            cat_elem = SubElement(categories, 'category')
            cat_elem.set('type', category)
            cat_elem.text = str(count)
        
        # Detected patterns
        patterns = SubElement(monitoring, 'detected_patterns')
        for pattern in monitoring_data['pattern_summaries']:
            pattern_elem = SubElement(patterns, 'pattern')
            pattern_elem.set('type', pattern['type'])
            pattern_elem.set('confidence', str(pattern['confidence']))
            pattern_elem.text = pattern['description']
        
        # Format XML
        rough_string = tostring(root, 'unicode')
        reparsed = parseString(rough_string)
        return reparsed.toprettyxml(indent="  ")

    def export_comprehensive_results(self, result: SandboxResult, 
                                   output_path: str, format_type: str = 'html') -> bool:
        """Export comprehensive analysis results with monitoring data."""
        try:
            report_content = self._generate_comprehensive_report(result, format_type)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report_content)
            
            return True
            
        except Exception as e:
            result.errors.append(f"Failed to export results: {e}")
            return False
    
    def _format_list(self, items: List[str], css_class: str) -> str:
        """Format a list for HTML."""
        if not items:
            return f"<p class='{css_class}'>None</p>"
        
        html = "<ul>"
        for item in items:
            html += f"<li class='{css_class}'>{item}</li>"
        html += "</ul>"
        
        return html


# Convenience function
def analyze_in_sandbox(binary_path: str, sandbox_type: str = 'auto',
                      analysis_depth: str = 'standard', timeout: int = 300) -> Dict[str, Any]:
    """
    Convenience function to analyze a binary in sandbox.
    
    Args:
        binary_path: Path to binary
        sandbox_type: 'qiling', 'qemu', 'auto', or 'both'
        analysis_depth: 'quick', 'standard', 'deep', or 'forensic'
        timeout: Analysis timeout in seconds
        
    Returns:
        Dictionary with analysis results
    """
    manager = SandboxManager()
    
    config = SandboxConfig(
        sandbox_type=SandboxType(sandbox_type),
        analysis_depth=AnalysisDepth(analysis_depth),
        timeout=timeout
    )
    
    result = manager.analyze_binary(binary_path, config)
    
    return {
        'success': result.success,
        'sandbox_type': result.sandbox_type.value,
        'execution_time': result.execution_time,
        'api_calls': len(result.api_calls),
        'files_created': result.files_created,
        'network_connections': len(result.network_connections),
        'license_checks': len(result.license_checks),
        'warnings': result.warnings,
        'errors': result.errors
    }