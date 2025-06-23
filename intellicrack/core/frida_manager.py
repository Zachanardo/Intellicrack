"""
Comprehensive Frida Manager for Intellicrack

This module provides a production-ready Frida management system with:
- Comprehensive operation logging
- Real-time protection adaptation
- Protection technique classification
- Performance optimization
- GUI integration support
"""

import json
import logging
import queue
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Set, Union

# Import availability checks from shared utility
from ..utils.core.import_checks import FRIDA_AVAILABLE, frida, psutil

logger = logging.getLogger(__name__)


# Import constants from separate module to avoid cyclic imports
from .frida_constants import HookCategory, ProtectionType


class FridaOperationLogger:
    """Comprehensive logging system for Frida operations"""

    def __init__(self, log_dir: str = None):
        self.log_dir = Path(log_dir or "logs/frida_operations")
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Different log files for different types of operations
        self.operation_log = self.log_dir / f"operations_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        self.hook_log = self.log_dir / f"hooks_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        self.performance_log = self.log_dir / f"performance_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        self.bypass_log = self.log_dir / f"bypasses_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

        # In-memory buffers for real-time analysis
        self.operation_buffer = deque(maxlen=10000)
        self.hook_buffer = deque(maxlen=50000)
        self.performance_metrics = defaultdict(list)

        # Statistics tracking
        self.stats = {
            'total_operations': 0,
            'successful_hooks': 0,
            'failed_hooks': 0,
            'bypasses_attempted': 0,
            'bypasses_successful': 0,
            'total_cpu_time': 0.0,
            'total_memory_used': 0
        }

        self._init_loggers()

    def _init_loggers(self):
        """Initialize separate loggers for different operation types"""
        # Operation logger
        self.op_logger = logging.getLogger('frida.operations')
        op_handler = logging.FileHandler(self.operation_log)
        op_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        ))
        self.op_logger.addHandler(op_handler)
        self.op_logger.setLevel(logging.DEBUG)

        # Hook logger
        self.hook_logger = logging.getLogger('frida.hooks')
        hook_handler = logging.FileHandler(self.hook_log)
        hook_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(message)s'
        ))
        self.hook_logger.addHandler(hook_handler)
        self.hook_logger.setLevel(logging.DEBUG)

        # Performance logger
        self.perf_logger = logging.getLogger('frida.performance')
        perf_handler = logging.FileHandler(self.performance_log)
        perf_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(message)s'
        ))
        self.perf_logger.addHandler(perf_handler)
        self.perf_logger.setLevel(logging.INFO)

        # Bypass logger
        self.bypass_logger = logging.getLogger('frida.bypasses')
        bypass_handler = logging.FileHandler(self.bypass_log)
        bypass_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        ))
        self.bypass_logger.addHandler(bypass_handler)
        self.bypass_logger.setLevel(logging.INFO)

    def log_operation(self, operation: str, details: Dict[str, Any],
                     success: bool = True, error: str = None):
        """Log a Frida operation with comprehensive details"""
        timestamp = datetime.now()
        entry = {
            'timestamp': timestamp.isoformat(),
            'operation': operation,
            'details': details,
            'success': success,
            'error': error,
            'pid': details.get('pid'),
            'process': details.get('process_name')
        }

        # Add to buffer
        self.operation_buffer.append(entry)

        # Update stats
        self.stats['total_operations'] += 1

        # Log to file
        level = logging.INFO if success else logging.ERROR
        msg = f"Operation: {operation} | PID: {details.get('pid')} | Success: {success}"
        if error:
            msg += f" | Error: {error}"
        self.op_logger.log(level, msg)

        # Log details as JSON for parsing
        self.op_logger.debug(f"Details: {json.dumps(details, default=str)}")

    def log_hook(self, function_name: str, module: str, arguments: List[Any],
                 return_value: Any = None, modified: bool = False):
        """Log individual hook executions"""
        timestamp = datetime.now()
        entry = {
            'timestamp': timestamp.isoformat(),
            'function': function_name,
            'module': module,
            'arguments': str(arguments)[:200],  # Truncate long args
            'return_value': str(return_value)[:100] if return_value else None,
            'modified': modified
        }

        # Add to buffer
        self.hook_buffer.append(entry)

        # Update stats
        self.stats['successful_hooks'] += 1

        # Log to file (use INFO for modified returns, DEBUG for monitoring)
        level = logging.INFO if modified else logging.DEBUG
        # Add readable message to entry for better debugging
        entry['readable_msg'] = f"Hook: {module}!{function_name} | Modified: {modified}"
        self.hook_logger.log(level, json.dumps(entry, default=str))

    def log_performance(self, metric_name: str, value: float,
                       unit: str = "ms", metadata: Dict = None):
        """Log performance metrics"""
        timestamp = datetime.now()
        entry = {
            'timestamp': timestamp.isoformat(),
            'metric': metric_name,
            'value': value,
            'unit': unit,
            'metadata': metadata or {}
        }

        # Track in metrics
        self.performance_metrics[metric_name].append(value)

        # Log to file
        self.perf_logger.info(json.dumps(entry, default=str))

        # Update stats
        if metric_name == 'cpu_time':
            self.stats['total_cpu_time'] += value
        elif metric_name == 'memory_used':
            self.stats['total_memory_used'] = max(
                self.stats['total_memory_used'], value
            )

    def log_bypass_attempt(self, protection_type: ProtectionType,
                          technique: str, success: bool,
                          details: Dict[str, Any] = None):
        """Log bypass attempts with classification"""
        timestamp = datetime.now()
        entry = {
            'timestamp': timestamp.isoformat(),
            'protection_type': protection_type.value,
            'technique': technique,
            'success': success,
            'details': details or {}
        }

        # Log the entry to bypass logger
        self.bypass_logger.info(json.dumps(entry, default=str))

        # Update stats
        self.stats['bypasses_attempted'] += 1
        if success:
            self.stats['bypasses_successful'] += 1

        # Log to file
        level = logging.INFO if success else logging.WARNING
        msg = f"Bypass: {protection_type.value} | Technique: {technique} | Success: {success}"
        self.bypass_logger.log(level, msg)
        if details:
            self.bypass_logger.debug(f"Details: {json.dumps(details, default=str)}")

    def get_statistics(self) -> Dict[str, Any]:
        """Get current statistics"""
        stats = self.stats.copy()

        # Calculate success rates
        if stats['total_operations'] > 0:
            stats['operation_success_rate'] = (
                (stats['total_operations'] - stats.get('failed_operations', 0)) /
                stats['total_operations'] * 100
            )

        if stats['bypasses_attempted'] > 0:
            stats['bypass_success_rate'] = (
                stats['bypasses_successful'] / stats['bypasses_attempted'] * 100
            )

        # Add performance averages
        for metric, values in self.performance_metrics.items():
            if values:
                stats[f'avg_{metric}'] = sum(values) / len(values)
                stats[f'max_{metric}'] = max(values)
                stats[f'min_{metric}'] = min(values)

        return stats

    def export_logs(self, output_dir: str = None) -> str:
        """Export all logs to a directory"""
        export_dir = Path(output_dir or f"frida_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        export_dir.mkdir(parents=True, exist_ok=True)

        # Copy log files
        import shutil
        for log_file in [self.operation_log, self.hook_log,
                        self.performance_log, self.bypass_log]:
            if log_file.exists():
                shutil.copy2(log_file, export_dir / log_file.name)

        # Export statistics
        stats_file = export_dir / "statistics.json"
        with open(stats_file, 'w') as f:
            json.dump(self.get_statistics(), f, indent=2)

        # Export buffers for analysis
        buffers_file = export_dir / "buffers.json"
        with open(buffers_file, 'w') as f:
            json.dump({
                'operations': list(self.operation_buffer),
                'hooks': list(self.hook_buffer)[-1000:],  # Last 1000 hooks
                'performance_metrics': dict(self.performance_metrics)
            }, f, indent=2, default=str)

        return str(export_dir)

    def error(self, message: str):
        """Log error message using operation logger"""
        self.log_operation("error", {"message": message, "level": "error"})
        self.op_logger.error(message)


class ProtectionDetector:
    """Real-time protection detection and classification"""

    def __init__(self):
        self.detected_protections = defaultdict(set)
        self.protection_signatures = self._load_signatures()
        self.adaptation_callbacks = []

    def _load_signatures(self) -> Dict[ProtectionType, List[Dict]]:
        """Load protection signatures for classification"""
        return {
            ProtectionType.ANTI_DEBUG: [
                {'api': 'IsDebuggerPresent', 'module': 'kernel32.dll'},
                {'api': 'CheckRemoteDebuggerPresent', 'module': 'kernel32.dll'},
                {'api': 'NtQueryInformationProcess', 'module': 'ntdll.dll'},
                {'api': 'OutputDebugString', 'module': 'kernel32.dll'},
            ],
            ProtectionType.ANTI_VM: [
                {'api': 'GetSystemFirmwareTable', 'module': 'kernel32.dll'},
                {'pattern': 'VMware', 'type': 'string'},
                {'pattern': 'VirtualBox', 'type': 'string'},
                {'registry': r'SYSTEM\CurrentControlSet\Services\Disk\Enum'},
            ],
            ProtectionType.LICENSE: [
                {'api': 'RegQueryValueEx', 'module': 'advapi32.dll'},
                {'api': 'CryptDecrypt', 'module': 'advapi32.dll'},
                {'api': 'InternetOpenUrl', 'module': 'wininet.dll'},
                {'pattern': 'license', 'type': 'string', 'case_insensitive': True},
            ],
            ProtectionType.INTEGRITY: [
                {'api': 'CryptHashData', 'module': 'advapi32.dll'},
                {'api': 'MapFileAndCheckSum', 'module': 'imagehlp.dll'},
                {'pattern': 'checksum', 'type': 'string', 'case_insensitive': True},
            ],
            ProtectionType.HARDWARE: [
                {'api': 'GetVolumeInformation', 'module': 'kernel32.dll'},
                {'api': 'GetAdaptersInfo', 'module': 'iphlpapi.dll'},
                {'wmi': 'Win32_DiskDrive'},
                {'wmi': 'Win32_NetworkAdapter'},
            ],
            ProtectionType.CLOUD: [
                {'api': 'WinHttpOpen', 'module': 'winhttp.dll'},
                {'api': 'InternetConnect', 'module': 'wininet.dll'},
                {'pattern': 'https://', 'type': 'string'},
                {'pattern': 'api.', 'type': 'string'},
            ],
            ProtectionType.TIME: [
                {'api': 'GetSystemTime', 'module': 'kernel32.dll'},
                {'api': 'GetTickCount', 'module': 'kernel32.dll'},
                {'api': 'QueryPerformanceCounter', 'module': 'kernel32.dll'},
                {'pattern': 'trial', 'type': 'string', 'case_insensitive': True},
            ],
            ProtectionType.MEMORY: [
                {'api': 'VirtualProtect', 'module': 'kernel32.dll'},
                {'api': 'WriteProcessMemory', 'module': 'kernel32.dll'},
                {'api': 'NtProtectVirtualMemory', 'module': 'ntdll.dll'},
            ],
            ProtectionType.KERNEL: [
                {'api': 'DeviceIoControl', 'module': 'kernel32.dll'},
                {'api': 'NtLoadDriver', 'module': 'ntdll.dll'},
                {'pattern': '.sys', 'type': 'string'},
            ],
        }

    def analyze_api_call(self, module: str, function: str,
                        args: List[Any]) -> Set[ProtectionType]:
        """Analyze an API call to detect protection types"""
        detected = set()

        for prot_type, signatures in self.protection_signatures.items():
            for sig in signatures:
                if sig.get('api') == function and sig.get('module', '').lower() in module.lower():
                    detected.add(prot_type)
                    self.detected_protections[prot_type].add(f"{module}!{function}")
                    break

        # Analyze function arguments for additional protection indicators
        if args:
            for arg in args:
                if isinstance(arg, str):
                    # Check for protection-related strings in arguments
                    arg_protections = self.analyze_string(arg)
                    detected.update(arg_protections)
                elif isinstance(arg, (int, float)) and arg > 0:
                    # Analyze numeric arguments for suspicious patterns
                    if function.lower() in ['virtualprotect', 'ntprotectvirtualmemory'] and arg in [0x40, 0x20, 0x04]:
                        detected.add(ProtectionType.MEMORY_PROTECTION)
                        self.detected_protections[ProtectionType.MEMORY_PROTECTION].add(f"Memory protection flag: {hex(arg)}")

        return detected

    def analyze_string(self, string_data: str) -> Set[ProtectionType]:
        """Analyze strings for protection indicators"""
        detected = set()

        for prot_type, signatures in self.protection_signatures.items():
            for sig in signatures:
                if sig.get('type') == 'string':
                    pattern = sig['pattern']
                    if sig.get('case_insensitive'):
                        if pattern.lower() in string_data.lower():
                            detected.add(prot_type)
                            self.detected_protections[prot_type].add(f"String: {pattern}")
                    elif pattern in string_data:
                        detected.add(prot_type)
                        self.detected_protections[prot_type].add(f"String: {pattern}")

        return detected

    def register_adaptation_callback(self, callback: Callable):
        """Register callback for protection detection events"""
        self.adaptation_callbacks.append(callback)

    def notify_protection_detected(self, protection_type: ProtectionType,
                                 details: Dict[str, Any]):
        """Notify registered callbacks of detected protection"""
        for callback in self.adaptation_callbacks:
            try:
                callback(protection_type, details)
            except Exception as e:
                logger.error(f"Adaptation callback error: {e}")

    def get_detected_protections(self) -> Dict[str, List[str]]:
        """Get all detected protections with evidence"""
        return {
            prot_type.value: list(evidence)
            for prot_type, evidence in self.detected_protections.items()
        }


class HookBatcher:
    """Batch hooks for improved performance"""

    def __init__(self, max_batch_size: int = 50,
                 batch_timeout_ms: int = 100):
        self.max_batch_size = max_batch_size
        self.batch_timeout_ms = batch_timeout_ms
        self.pending_hooks = defaultdict(list)
        self.hook_queue = queue.Queue()
        self.batch_thread = None
        self.running = False

    def add_hook(self, category: HookCategory, hook_spec: Dict[str, Any]):
        """Add a hook to the batch queue"""
        hook_spec['timestamp'] = time.time()
        hook_spec['category'] = category
        self.hook_queue.put(hook_spec)

    def start_batching(self):
        """Start the batching thread"""
        self.running = True
        self.batch_thread = threading.Thread(target=self._batch_processor)
        self.batch_thread.daemon = True
        self.batch_thread.start()

    def stop_batching(self):
        """Stop the batching thread"""
        self.running = False
        if self.batch_thread:
            self.batch_thread.join()

    def _batch_processor(self):
        """Process hooks in batches"""
        while self.running:
            batch = []
            deadline = time.time() + (self.batch_timeout_ms / 1000.0)

            # Collect hooks until batch is full or timeout
            while len(batch) < self.max_batch_size and time.time() < deadline:
                try:
                    timeout = max(0, deadline - time.time())
                    hook = self.hook_queue.get(timeout=timeout)
                    batch.append(hook)
                except queue.Empty:
                    break

            if batch:
                # Sort by category priority
                batch.sort(key=lambda h: h['category'].value)

                # Group by module for efficiency
                module_groups = defaultdict(list)
                for hook in batch:
                    module_groups[hook.get('module', 'unknown')].append(hook)

                # Return batched hooks
                for module, hooks in module_groups.items():
                    yield module, hooks

    def get_batch_stats(self) -> Dict[str, int]:
        """Get batching statistics"""
        return {
            'pending_hooks': self.hook_queue.qsize(),
            'categories': {
                cat.name: sum(1 for h in list(self.hook_queue.queue)
                            if h.get('category') == cat)
                for cat in HookCategory
            }
        }


class FridaPerformanceOptimizer:
    """Optimize Frida operations for performance"""

    def __init__(self):
        self.process = psutil.Process()
        self.baseline_memory = 0
        self.baseline_cpu = 0
        self.optimization_enabled = True
        self.selective_hooks = {}
        self.hook_cache = {}
        self.performance_history = deque(maxlen=100)

    def measure_baseline(self):
        """Measure baseline resource usage"""
        self.baseline_memory = self.process.memory_info().rss
        self.baseline_cpu = self.process.cpu_percent(interval=0.1)

    def get_current_usage(self) -> Dict[str, float]:
        """Get current resource usage"""
        return {
            'memory_mb': (self.process.memory_info().rss - self.baseline_memory) / 1024 / 1024,
            'cpu_percent': self.process.cpu_percent(interval=0.1),
            'threads': self.process.num_threads(),
            'handles': len(self.process.open_files())
        }

    def should_hook_function(self, module: str, function: str,
                           importance: HookCategory) -> bool:
        """Determine if a function should be hooked based on performance"""
        if not self.optimization_enabled:
            return True

        # Always hook critical functions
        if importance == HookCategory.CRITICAL:
            return True

        # Check current resource usage
        usage = self.get_current_usage()

        # High memory usage - be selective
        if usage['memory_mb'] > 500:
            return importance in [HookCategory.CRITICAL, HookCategory.HIGH]

        # High CPU usage - be very selective
        if usage['cpu_percent'] > 80:
            return importance == HookCategory.CRITICAL

        # Check if this hook is frequently called
        hook_key = f"{module}!{function}"
        if hook_key in self.selective_hooks:
            call_rate = self.selective_hooks[hook_key].get('call_rate', 0)
            if call_rate > 1000:  # More than 1000 calls/sec
                return importance in [HookCategory.CRITICAL, HookCategory.HIGH]

        return True

    def optimize_script(self, script_code: str) -> str:
        """Optimize Frida script for performance"""
        optimizations = []

        # Add caching for frequently accessed values
        cache_code = """
        const _cache = new Map();
        const _cacheTimeout = 1000; // 1 second

        function cachedCall(key, fn) {
            const cached = _cache.get(key);
            if (cached && Date.now() - cached.time < _cacheTimeout) {
                return cached.value;
            }
            const value = fn();
            _cache.set(key, { value, time: Date.now() });
            return value;
        }
        """
        optimizations.append(cache_code)

        # Add batching for send() calls
        batch_code = """
        const _sendBuffer = [];
        const _sendInterval = 50; // 50ms

        function batchedSend(data) {
            _sendBuffer.push(data);
            if (_sendBuffer.length === 1) {
                setTimeout(() => {
                    if (_sendBuffer.length > 0) {
                        send({ type: 'batch', data: _sendBuffer });
                        _sendBuffer.length = 0;
                    }
                }, _sendInterval);
            }
        }
        """
        optimizations.append(batch_code)

        # Combine optimizations with original script
        return '\n'.join(optimizations) + '\n' + script_code

    def track_hook_performance(self, module: str, function: str,
                              execution_time: float):
        """Track individual hook performance"""
        hook_key = f"{module}!{function}"

        if hook_key not in self.selective_hooks:
            self.selective_hooks[hook_key] = {
                'total_time': 0,
                'call_count': 0,
                'call_rate': 0,
                'last_update': time.time()
            }

        stats = self.selective_hooks[hook_key]
        stats['total_time'] += execution_time
        stats['call_count'] += 1

        # Update call rate
        now = time.time()
        time_diff = now - stats['last_update']
        if time_diff > 1.0:  # Update rate every second
            stats['call_rate'] = stats['call_count'] / time_diff
            stats['call_count'] = 0
            stats['last_update'] = now

    def get_optimization_recommendations(self) -> List[str]:
        """Get recommendations for optimization"""
        recommendations = []
        usage = self.get_current_usage()

        if usage['memory_mb'] > 1000:
            recommendations.append(
                "High memory usage detected. Consider reducing hook scope or "
                "enabling selective instrumentation."
            )

        if usage['cpu_percent'] > 70:
            recommendations.append(
                "High CPU usage detected. Enable hook batching and consider "
                "disabling non-essential monitoring hooks."
            )

        # Check for hot functions
        hot_functions = [
            (k, v) for k, v in self.selective_hooks.items()
            if v.get('call_rate', 0) > 5000
        ]
        if hot_functions:
            recommendations.append(
                f"Found {len(hot_functions)} frequently called functions. "
                "Consider optimizing or selectively hooking these."
            )

        return recommendations


class FridaManager:
    """Main Frida management class with all advanced features"""

    def __init__(self, log_dir: str = None, script_dir: str = None):
        if not FRIDA_AVAILABLE:
            raise ImportError("Frida is not available. Please install frida-tools: pip install frida-tools")

        self.logger = FridaOperationLogger(log_dir)
        self.detector = ProtectionDetector()
        self.batcher = HookBatcher()
        self.optimizer = FridaPerformanceOptimizer()

        self.device = None
        self.sessions = {}
        self.scripts = {}

        # Use consistent absolute path for scripts
        if script_dir:
            self.script_dir = Path(script_dir)
        else:
            # Get Intellicrack root directory (parent of intellicrack package)
            import intellicrack
            package_dir = Path(intellicrack.__file__).parent
            root_dir = package_dir.parent
            self.script_dir = root_dir / "scripts" / "frida"

        # Ensure script directory exists
        self.script_dir.mkdir(parents=True, exist_ok=True)

        # Protection adaptation system
        self.protection_adaptations = {
            ProtectionType.ANTI_DEBUG: self._adapt_anti_debug,
            ProtectionType.ANTI_VM: self._adapt_anti_vm,
            ProtectionType.LICENSE: self._adapt_license,
            ProtectionType.INTEGRITY: self._adapt_integrity,
            ProtectionType.HARDWARE: self._adapt_hardware,
            ProtectionType.CLOUD: self._adapt_cloud,
            ProtectionType.TIME: self._adapt_time,
            ProtectionType.MEMORY: self._adapt_memory,
            ProtectionType.KERNEL: self._adapt_kernel,
        }

        # Register adaptation callback
        self.detector.register_adaptation_callback(self._on_protection_detected)

        # Start services
        self.batcher.start_batching()
        self.optimizer.measure_baseline()

    def attach_to_process(self, process_identifier: Union[int, str]) -> bool:
        """Attach to a process with comprehensive logging"""
        if not FRIDA_AVAILABLE:
            logger.error("Frida is not available")
            return False

        try:
            start_time = time.time()

            # Get device
            self.device = frida.get_local_device()

            # Attach to process
            if isinstance(process_identifier, int):
                session = self.device.attach(process_identifier)
                # Get process name from device, not session
                try:
                    processes = self.device.enumerate_processes()
                    process_name = next((p.name for p in processes if p.pid == process_identifier), f"pid_{process_identifier}")
                except:
                    process_name = f"pid_{process_identifier}"
            else:
                session = self.device.attach(process_identifier)
                process_name = process_identifier

            # Store session
            session_id = f"{process_name}_{process_identifier}"
            self.sessions[session_id] = session

            # Log operation
            self.logger.log_operation(
                "attach_to_process",
                {
                    'pid': process_identifier,
                    'process_name': process_name,
                    'session_id': session_id,
                    'device': str(self.device)
                },
                success=True
            )

            # Log performance
            attach_time = (time.time() - start_time) * 1000
            self.logger.log_performance("attach_time", attach_time, "ms",
                                      {'process': process_name})

            # Set up session handlers
            session.on('detached', lambda reason: self._on_session_detached(session_id, reason))

            return True

        except Exception as e:
            self.logger.log_operation(
                "attach_to_process",
                {'process_identifier': process_identifier},
                success=False,
                error=str(e)
            )
            return False

    def add_custom_script(self, script_content: str, script_name: str) -> Path:
        """Add a custom Frida script to the scripts directory

        Args:
            script_content: JavaScript code for the script
            script_name: Name for the script (without extension)

        Returns:
            Path to the created script file
        """
        # Ensure script name ends with .js
        if not script_name.endswith('.js'):
            script_name += '.js'

        # Create script path
        script_path = self.script_dir / script_name

        # Write script content
        script_path.write_text(script_content, encoding='utf-8')

        # Log operation
        self.logger.log_operation(
            "add_custom_script",
            {
                'script_name': script_name,
                'script_path': str(script_path),
                'content_length': len(script_content)
            },
            success=True
        )

        return script_path

    def list_available_scripts(self) -> List[Dict[str, Any]]:
        """List all available Frida scripts

        Returns:
            List of script information dictionaries
        """
        scripts = []

        if self.script_dir.exists():
            for script_file in self.script_dir.glob("*.js"):
                try:
                    # Get script info
                    stat = script_file.stat()

                    # Try to extract metadata from script
                    content = script_file.read_text(encoding='utf-8')
                    protection_type = "UNKNOWN"

                    # Look for protection type in script
                    if "PROTECTION_TYPE" in content:
                        import re
                        match = re.search(r'PROTECTION_TYPE\s*=\s*["\'](\w+)["\']', content)
                        if match:
                            protection_type = match.group(1)

                    scripts.append({
                        'name': script_file.stem,
                        'path': str(script_file),
                        'size': stat.st_size,
                        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        'protection_type': protection_type
                    })

                except Exception as e:
                    logger.error(f"Error reading script {script_file}: {e}")

        return scripts

    def load_script(self, session_id: str, script_name: str,
                   options: Dict[str, Any] = None) -> bool:
        """Load and inject a Frida script with optimization"""
        try:
            start_time = time.time()

            # Get session
            session = self.sessions.get(session_id)
            if not session:
                raise ValueError(f"No session found: {session_id}")

            # Load script file
            script_path = self.script_dir / f"{script_name}.js"
            if not script_path.exists():
                # Try without .js extension
                script_path = self.script_dir / script_name
                if not script_path.exists():
                    raise FileNotFoundError(f"Script not found: {script_name}")

            with open(script_path, 'r') as f:
                script_code = f.read()

            # Optimize script
            if self.optimizer.optimization_enabled:
                script_code = self.optimizer.optimize_script(script_code)

            # Add instrumentation for logging
            script_code = self._instrument_script(script_code, script_name)

            # Create script
            script = session.create_script(script_code)

            # Set up message handler
            script.on('message', lambda msg, data: self._on_script_message(
                session_id, script_name, msg, data
            ))

            # Load script
            script.load()

            # Store script with generated key
            script_key = f"{session_id}:{script_name}"
            self.scripts[script_key] = script
            logger.debug(f"Stored script with key: {script_key}")

            # Log operation
            self.logger.log_operation(
                "load_script",
                {
                    'session_id': session_id,
                    'script_name': script_name,
                    'script_size': len(script_code),
                    'options': options
                },
                success=True
            )

            # Log performance
            load_time = (time.time() - start_time) * 1000
            self.logger.log_performance("script_load_time", load_time, "ms",
                                      {'script': script_name})

            return True

        except Exception as e:
            self.logger.log_operation(
                "load_script",
                {
                    'session_id': session_id,
                    'script_name': script_name
                },
                success=False,
                error=str(e)
            )
            return False

    def _instrument_script(self, script_code: str, script_name: str) -> str:
        """Add instrumentation to script for logging"""
        instrumentation = f"""
        // Intellicrack Frida Instrumentation
        const _scriptName = '{script_name}';
        const _startTime = Date.now();

        // Hook tracking
        const _hookedFunctions = new Set();
        const _hookStats = new Map();

        // Wrap Interceptor.attach for logging
        const _originalAttach = Interceptor.attach;
        Interceptor.attach = function(target, callbacks) {{
            const moduleName = target.module || 'unknown';
            const functionName = target.name || target.toString();
            const hookId = `${{moduleName}}!${{functionName}}`;

            _hookedFunctions.add(hookId);

            // Wrap callbacks for stats
            const wrappedCallbacks = {{}};

            if (callbacks.onEnter) {{
                wrappedCallbacks.onEnter = function(args) {{
                    const start = Date.now();
                    const result = callbacks.onEnter.call(this, args);
                    const elapsed = Date.now() - start;

                    // Track performance
                    if (!_hookStats.has(hookId)) {{
                        _hookStats.set(hookId, {{ count: 0, totalTime: 0 }});
                    }}
                    const stats = _hookStats.get(hookId);
                    stats.count++;
                    stats.totalTime += elapsed;

                    // Send hook event
                    send({{
                        type: 'hook',
                        function: functionName,
                        module: moduleName,
                        phase: 'enter',
                        elapsed: elapsed
                    }});

                    return result;
                }};
            }}

            if (callbacks.onLeave) {{
                wrappedCallbacks.onLeave = function(retval) {{
                    const result = callbacks.onLeave.call(this, retval);

                    send({{
                        type: 'hook',
                        function: functionName,
                        module: moduleName,
                        phase: 'leave',
                        modified: retval !== result
                    }});

                    return result;
                }};
            }}

            return _originalAttach.call(this, target, wrappedCallbacks);
        }};

        // Protection detection helpers
        function detectProtection(type, evidence) {{
            send({{
                type: 'protection_detected',
                protection_type: type,
                evidence: evidence,
                timestamp: Date.now()
            }});
        }}

        // Performance reporting
        setInterval(function() {{
            const stats = [];
            _hookStats.forEach((value, key) => {{
                stats.push({{
                    hook: key,
                    count: value.count,
                    avgTime: value.totalTime / value.count
                }});
            }});

            send({{
                type: 'performance_report',
                uptime: Date.now() - _startTime,
                hooks: _hookedFunctions.size,
                stats: stats
            }});
        }}, 5000); // Every 5 seconds

        """

        return instrumentation + "\n" + script_code

    def _on_script_message(self, session_id: str, script_name: str,
                          message: Dict, data: Any):
        """Handle messages from Frida scripts including binary data"""
        msg_type = message.get('type')
        payload = message.get('payload', {})

        # Handle binary data if present
        if data is not None:
            # Log that we received binary data
            self.logger.log_operation(
                f"script_data:{script_name}",
                {
                    'session_id': session_id,
                    'data_size': len(data) if hasattr(data, '__len__') else 'unknown',
                    'data_type': type(data).__name__
                },
                success=True
            )

            # Process binary data based on payload type
            if isinstance(payload, dict):
                data_type = payload.get('data_type', 'unknown')

                if data_type == 'memory_dump':
                    # Handle memory dump data
                    self._handle_memory_dump(session_id, script_name, data, payload)
                elif data_type == 'screenshot':
                    # Handle screenshot data
                    self._handle_screenshot_data(session_id, script_name, data, payload)
                elif data_type == 'file_content':
                    # Handle file content
                    self._handle_file_content(session_id, script_name, data, payload)
                elif data_type == 'network_packet':
                    # Handle network packet data
                    self._handle_network_packet(session_id, script_name, data, payload)
                elif data_type == 'encrypted_data':
                    # Handle encrypted data that was intercepted
                    self._handle_encrypted_data(session_id, script_name, data, payload)
                else:
                    # Generic binary data handling
                    self._handle_generic_binary_data(session_id, script_name, data, payload)

        if msg_type == 'send':
            # Handle different message types
            if isinstance(payload, dict):
                payload_type = payload.get('type')

                if payload_type == 'hook':
                    # Log hook execution
                    self.logger.log_hook(
                        payload.get('function'),
                        payload.get('module'),
                        payload.get('args', []),
                        payload.get('retval'),
                        payload.get('modified', False)
                    )

                    # Track performance
                    if 'elapsed' in payload:
                        self.optimizer.track_hook_performance(
                            payload.get('module'),
                            payload.get('function'),
                            payload.get('elapsed')
                        )

                elif payload_type == 'protection_detected':
                    # Handle protection detection
                    prot_type = ProtectionType(payload.get('protection_type'))
                    self.detector.notify_protection_detected(
                        prot_type,
                        {
                            'evidence': payload.get('evidence'),
                            'script': script_name,
                            'session': session_id
                        }
                    )

                elif payload_type == 'performance_report':
                    # Log performance stats
                    self.logger.log_performance(
                        f"{script_name}_performance",
                        payload.get('uptime', 0),
                        "ms",
                        payload
                    )

                elif payload_type == 'batch':
                    # Handle batched messages
                    for item in payload.get('data', []):
                        self._on_script_message(session_id, script_name,
                                              {'type': 'send', 'payload': item}, None)

        elif msg_type == 'error':
            # Log script errors
            self.logger.log_operation(
                f"script_error:{script_name}",
                {
                    'session_id': session_id,
                    'error': payload
                },
                success=False,
                error=str(payload)
            )

    def _on_session_detached(self, session_id: str, reason: str):
        """Handle session detachment"""
        self.logger.log_operation(
            "session_detached",
            {
                'session_id': session_id,
                'reason': reason
            },
            success=True
        )

        # Clean up
        if session_id in self.sessions:
            del self.sessions[session_id]

        # Remove associated scripts
        script_keys = [k for k in self.scripts.keys() if k.startswith(session_id)]
        for key in script_keys:
            del self.scripts[key]

    def _on_protection_detected(self, protection_type: ProtectionType,
                              details: Dict[str, Any]):
        """Handle protection detection events"""
        # Log detection
        self.logger.log_bypass_attempt(
            protection_type,
            "detection",
            True,
            details
        )

        # Apply adaptation if available
        if protection_type in self.protection_adaptations:
            adaptation_func = self.protection_adaptations[protection_type]
            try:
                adaptation_func(details)
            except Exception as e:
                logger.error(f"Adaptation failed for {protection_type}: {e}")

    # Protection adaptation methods
    def _adapt_anti_debug(self, details: Dict[str, Any]):
        """Adapt to anti-debugging protections"""
        session_id = details.get('session')
        if not session_id:
            return

        # Load anti-debug bypass script
        self.load_script(session_id, "anti_debugger", {
            'aggressive': True,
            'stealth_mode': True
        })

        self.logger.log_bypass_attempt(
            ProtectionType.ANTI_DEBUG,
            "frida_anti_debug_bypass",
            True,
            {'method': 'script_injection'}
        )

    def _adapt_anti_vm(self, details: Dict[str, Any]):
        """Adapt to anti-VM protections"""
        session_id = details.get('session')
        if not session_id:
            return

        # Load VM detection bypass
        self.load_script(session_id, "virtualization_bypass", {
            'spoof_hardware': True,
            'hide_hypervisor': True
        })

        self.logger.log_bypass_attempt(
            ProtectionType.ANTI_VM,
            "frida_vm_bypass",
            True,
            {'method': 'hardware_spoofing'}
        )

    def _adapt_license(self, details: Dict[str, Any]):
        """Adapt to license verification"""
        session_id = details.get('session')
        if not session_id:
            return

        # Load license bypass script
        script_name = "cloud_licensing_bypass"
        evidence = details.get('evidence', '')

        if 'RegQueryValueEx' in evidence:
            script_name = "registry_monitor"

        self.load_script(session_id, script_name, {
            'patch_checks': True,
            'emulate_server': True
        })

        self.logger.log_bypass_attempt(
            ProtectionType.LICENSE,
            "frida_license_bypass",
            True,
            {'method': 'api_hooking', 'script': script_name}
        )

    def _adapt_integrity(self, details: Dict[str, Any]):
        """Adapt to integrity checks"""
        session_id = details.get('session')
        if not session_id:
            return

        # Load integrity bypass
        self.load_script(session_id, "code_integrity_bypass", {
            'patch_checksums': True,
            'hook_validation': True
        })

        self.logger.log_bypass_attempt(
            ProtectionType.INTEGRITY,
            "frida_integrity_bypass",
            True,
            {'method': 'checksum_patching'}
        )

    def _adapt_hardware(self, details: Dict[str, Any]):
        """Adapt to hardware binding"""
        session_id = details.get('session')
        if not session_id:
            return

        # Load hardware spoofer
        self.load_script(session_id, "enhanced_hardware_spoofer", {
            'spoof_all': True,
            'persistent': True
        })

        self.logger.log_bypass_attempt(
            ProtectionType.HARDWARE,
            "frida_hardware_spoof",
            True,
            {'method': 'hwid_spoofing'}
        )

    def _adapt_cloud(self, details: Dict[str, Any]):
        """Adapt to cloud verification"""
        session_id = details.get('session')
        if not session_id:
            return

        # Load cloud bypass
        self.load_script(session_id, "cloud_licensing_bypass", {
            'intercept_requests': True,
            'fake_responses': True
        })

        self.logger.log_bypass_attempt(
            ProtectionType.CLOUD,
            "frida_cloud_bypass",
            True,
            {'method': 'network_interception'}
        )

    def _adapt_time(self, details: Dict[str, Any]):
        """Adapt to time-based protections"""
        session_id = details.get('session')
        if not session_id:
            return

        # Load time manipulation script
        self.load_script(session_id, "time_bomb_defuser", {
            'freeze_time': True,
            'extend_trial': True
        })

        self.logger.log_bypass_attempt(
            ProtectionType.TIME,
            "frida_time_bypass",
            True,
            {'method': 'time_manipulation'}
        )

    def _adapt_memory(self, details: Dict[str, Any]):
        """Adapt to memory protections"""
        session_id = details.get('session')
        if not session_id:
            return

        # Load memory protection bypass
        self.load_script(session_id, "memory_integrity_bypass", {
            'bypass_guard_pages': True,
            'disable_protection': True
        })

        self.logger.log_bypass_attempt(
            ProtectionType.MEMORY,
            "frida_memory_bypass",
            True,
            {'method': 'memory_patching'}
        )

    def _adapt_kernel(self, details: Dict[str, Any]):
        """Adapt to kernel-mode protections"""
        session_id = details.get('session')
        if not session_id:
            return

        # Load kernel bypass script
        self.load_script(session_id, "kernel_mode_bypass", {
            'usermode_only': True,
            'avoid_kernel': True
        })

        self.logger.log_bypass_attempt(
            ProtectionType.KERNEL,
            "frida_kernel_bypass",
            True,
            {'method': 'usermode_emulation'}
        )

    def _handle_memory_dump(self, session_id: str, script_name: str,
                           data: Any, payload: Dict[str, Any]):
        """Handle memory dump data from Frida scripts"""
        # Extract metadata from payload
        address = payload.get('address', '0x0')
        size = payload.get('size', len(data) if hasattr(data, '__len__') else 0)
        process_name = payload.get('process_name', 'unknown')

        # Log the memory dump event
        self.logger.log_operation(
            f"memory_dump:{script_name}",
            {
                'session_id': session_id,
                'address': address,
                'size': size,
                'process': process_name
            },
            success=True
        )

        # Store memory dump for analysis
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        dump_file = self.logger.log_dir / f"memory_dump_{process_name}_{address}_{timestamp}.bin"

        try:
            # Write binary data to file
            if isinstance(data, (bytes, bytearray)):
                with open(dump_file, 'wb') as f:
                    f.write(data)
            else:
                # Convert to bytes if necessary
                with open(dump_file, 'wb') as f:
                    f.write(bytes(data))

            # Analyze memory dump for patterns
            self._analyze_memory_dump(data, payload)

        except Exception as e:
            logger.error(f"Failed to save memory dump: {e}")

    def _handle_screenshot_data(self, session_id: str, script_name: str,
                               data: Any, payload: Dict[str, Any]):
        """Handle screenshot data from Frida scripts"""
        # Extract metadata
        window_title = payload.get('window_title', 'unknown')
        capture_time = payload.get('capture_time', datetime.now().isoformat())
        format_type = payload.get('format', 'png')

        # Log screenshot event
        self.logger.log_operation(
            f"screenshot:{script_name}",
            {
                'session_id': session_id,
                'window': window_title,
                'time': capture_time,
                'format': format_type
            },
            success=True
        )

        # Save screenshot
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        screenshot_file = self.logger.log_dir / f"screenshot_{window_title}_{timestamp}.{format_type}"

        try:
            with open(screenshot_file, 'wb') as f:
                f.write(data if isinstance(data, bytes) else bytes(data))

            # Perform OCR or pattern detection if needed
            if payload.get('analyze', False):
                self._analyze_screenshot(data, payload)

        except Exception as e:
            logger.error(f"Failed to save screenshot: {e}")

    def _handle_file_content(self, session_id: str, script_name: str,
                            data: Any, payload: Dict[str, Any]):
        """Handle file content intercepted by Frida scripts"""
        # Extract file information
        file_path = payload.get('file_path', 'unknown')
        operation = payload.get('operation', 'read')  # read/write
        file_size = payload.get('size', len(data) if hasattr(data, '__len__') else 0)

        # Log file operation
        self.logger.log_operation(
            f"file_{operation}:{script_name}",
            {
                'session_id': session_id,
                'file_path': file_path,
                'size': file_size,
                'operation': operation
            },
            success=True
        )

        # Analyze file content for patterns
        if operation == 'read':
            # Check for license files, config files, etc.
            if any(pattern in file_path.lower() for pattern in ['license', 'key', 'config', 'serial']):
                self._analyze_license_file(data, file_path, payload)
        elif operation == 'write':
            # Monitor for persistence or modification attempts
            self._analyze_file_write(data, file_path, payload)

    def _handle_network_packet(self, session_id: str, script_name: str,
                              data: Any, payload: Dict[str, Any]):
        """Handle network packet data from Frida scripts"""
        # Extract packet information
        direction = payload.get('direction', 'unknown')  # send/recv
        protocol = payload.get('protocol', 'tcp')
        src_addr = payload.get('src_addr', '')
        dst_addr = payload.get('dst_addr', '')
        src_port = payload.get('src_port', 0)
        dst_port = payload.get('dst_port', 0)

        # Log network event
        self.logger.log_operation(
            f"network_{direction}:{script_name}",
            {
                'session_id': session_id,
                'protocol': protocol,
                'src': f"{src_addr}:{src_port}",
                'dst': f"{dst_addr}:{dst_port}",
                'size': len(data) if hasattr(data, '__len__') else 0
            },
            success=True
        )

        # Analyze packet content
        if protocol.lower() in ['http', 'https']:
            self._analyze_http_traffic(data, payload)
        elif any(port in [dst_port, src_port] for port in [443, 8443, 8080]):
            # Potential license server communication
            self._analyze_license_traffic(data, payload)

    def _handle_encrypted_data(self, session_id: str, script_name: str,
                              data: Any, payload: Dict[str, Any]):
        """Handle encrypted data intercepted by Frida scripts"""
        # Extract encryption information
        algorithm = payload.get('algorithm', 'unknown')
        operation = payload.get('operation', 'unknown')  # encrypt/decrypt
        key_info = payload.get('key_info', {})
        iv = payload.get('iv', None)

        # Log encryption event
        self.logger.log_operation(
            f"crypto_{operation}:{script_name}",
            {
                'session_id': session_id,
                'algorithm': algorithm,
                'operation': operation,
                'data_size': len(data) if hasattr(data, '__len__') else 0,
                'has_key': bool(key_info),
                'has_iv': bool(iv)
            },
            success=True
        )

        # Store encrypted/decrypted data for analysis
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        crypto_file = self.logger.log_dir / f"crypto_{operation}_{algorithm}_{timestamp}.bin"

        try:
            with open(crypto_file, 'wb') as f:
                f.write(data if isinstance(data, bytes) else bytes(data))

            # If we have decrypted data, analyze it
            if operation == 'decrypt':
                self._analyze_decrypted_data(data, payload)

        except Exception as e:
            logger.error(f"Failed to save crypto data: {e}")

    def _handle_generic_binary_data(self, session_id: str, script_name: str,
                                   data: Any, payload: Dict[str, Any]):
        """Handle generic binary data from Frida scripts"""
        # Extract any available metadata
        data_type = payload.get('data_type', 'binary')
        description = payload.get('description', 'Generic binary data')

        # Log the event
        self.logger.log_operation(
            f"binary_data:{script_name}",
            {
                'session_id': session_id,
                'type': data_type,
                'description': description,
                'size': len(data) if hasattr(data, '__len__') else 0
            },
            success=True
        )

        # Save the data for later analysis
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        data_file = self.logger.log_dir / f"binary_data_{script_name}_{timestamp}.bin"

        try:
            with open(data_file, 'wb') as f:
                f.write(data if isinstance(data, bytes) else bytes(data))
        except Exception as e:
            logger.error(f"Failed to save binary data: {e}")

    def _analyze_memory_dump(self, data: Any, payload: Dict[str, Any]):
        """Analyze memory dump for interesting patterns"""
        # Convert to bytes if necessary
        if not isinstance(data, bytes):
            data = bytes(data)

        # Look for common patterns
        patterns = {
            'license_key': [b'LICENSE', b'KEY', b'SERIAL', b'ACTIVATION'],
            'crypto_keys': [b'RSA', b'AES', b'-----BEGIN', b'-----END'],
            'urls': [b'http://', b'https://', b'ftp://'],
            'registry': [b'HKEY_', b'SOFTWARE\\', b'CurrentVersion'],
            'interesting_strings': [b'trial', b'expired', b'registered', b'cracked']
        }

        findings = {}
        for category, pattern_list in patterns.items():
            for pattern in pattern_list:
                if pattern in data:
                    if category not in findings:
                        findings[category] = []
                    # Find context around the pattern
                    idx = data.find(pattern)
                    context_start = max(0, idx - 50)
                    context_end = min(len(data), idx + 100)
                    context = data[context_start:context_end]
                    findings[category].append({
                        'pattern': pattern.decode('utf-8', errors='ignore'),
                        'offset': idx,
                        'context': context.hex()
                    })

        if findings:
            self.logger.log_operation(
                "memory_analysis",
                {
                    'findings': findings,
                    'source': payload
                },
                success=True
            )

    def _analyze_screenshot(self, data: Any, payload: Dict[str, Any]):
        """Analyze screenshot for UI elements or text"""
        # Analyze screenshot data for UI elements
        analysis_results = {
            'ui_elements': [],
            'text_content': [],
            'coordinates': {}
        }

        # Process image data if provided
        if data and hasattr(data, '__len__') and len(data) > 0:
            try:
                # Attempt basic image analysis on the data
                analysis_results['data_size'] = len(data)
                analysis_results['data_type'] = type(data).__name__

                # Look for common UI patterns in raw data
                if isinstance(data, (bytes, str)):
                    # Search for common dialog patterns
                    dialog_patterns = [
                        b'OK', b'Cancel', b'Yes', b'No', b'Apply',
                        b'License', b'Trial', b'Activate', b'Register'
                    ]
                    for pattern in dialog_patterns:
                        if pattern in (data if isinstance(data, bytes) else data.encode()):
                            analysis_results['ui_elements'].append({
                                'type': 'button',
                                'text': pattern.decode('utf-8', errors='ignore'),
                                'confidence': 0.7
                            })

            except Exception as e:
                self.logger.error(f"Data analysis failed: {e}")
                analysis_results['error'] = str(e)

        # Log analysis results with data info
        self.logger.log_operation(
            "screenshot_analysis",
            {
                'requested': True,
                'window': payload.get('window_title', 'unknown')
            },
            success=True
        )

    def _analyze_license_file(self, data: Any, file_path: str, payload: Dict[str, Any]):
        """Analyze potential license file content"""
        try:
            # Try to decode as text
            if isinstance(data, bytes):
                text_content = data.decode('utf-8', errors='ignore')
            else:
                text_content = str(data)

            # Look for license patterns
            license_indicators = ['expiry', 'trial', 'activation', 'serial', 'key', 'license']
            found_indicators = [ind for ind in license_indicators if ind in text_content.lower()]

            if found_indicators:
                # Extract additional context from payload
                operation_context = {
                    'file_path': file_path,
                    'indicators': found_indicators,
                    'size': len(data),
                    'process_name': payload.get('process_name', 'unknown'),
                    'thread_id': payload.get('thread_id'),
                    'timestamp': payload.get('timestamp'),
                    'operation_type': payload.get('operation', 'file_analysis')
                }

                self.logger.log_operation(
                    "license_file_detected",
                    operation_context,
                    success=True
                )

                # Notify protection detector
                self.detector.notify_protection_detected(
                    ProtectionType.LICENSE,
                    {
                        'evidence': f"License file accessed: {file_path}",
                        'indicators': found_indicators
                    }
                )

        except Exception as e:
            logger.debug(f"Failed to analyze license file: {e}")

    def _analyze_file_write(self, data: Any, file_path: str, payload: Dict[str, Any]):
        """Analyze file write operations for suspicious activity"""
        # Use payload data for comprehensive analysis
        write_context = {
            'file_path': file_path,
            'operation_type': payload.get('operation', 'write'),
            'bytes_written': payload.get('bytes', 0),
            'process_context': payload.get('process', {}),
            'data_size': len(data) if hasattr(data, '__len__') else 0,
            'timestamp': payload.get('timestamp')
        }

        # Check for persistence mechanisms
        persistence_paths = ['startup', 'autorun', 'scheduled tasks', 'services']
        if any(path in file_path.lower() for path in persistence_paths):
            # Use write_context for detailed logging
            self.logger.log_operation(
                "persistence_attempt",
                write_context,
                success=True
            )

    def _analyze_http_traffic(self, data: Any, payload: Dict[str, Any]):
        """Analyze HTTP/HTTPS traffic for license checks"""
        try:
            if isinstance(data, bytes):
                text_data = data.decode('utf-8', errors='ignore')
            else:
                text_data = str(data)

            # Look for license-related endpoints
            license_endpoints = ['activate', 'verify', 'license', 'validate', 'auth']
            for endpoint in license_endpoints:
                if endpoint in text_data.lower():
                    self.logger.log_operation(
                        "license_communication",
                        {
                            'endpoint_type': endpoint,
                            'protocol': payload.get('protocol', 'http')
                        },
                        success=True
                    )
                    break

        except Exception as e:
            logger.debug(f"Failed to analyze HTTP traffic: {e}")

    def _analyze_license_traffic(self, data: Any, payload: Dict[str, Any]):
        """Analyze potential license server communication"""
        self.logger.log_operation(
            "license_server_communication",
            {
                'dst_addr': payload.get('dst_addr', ''),
                'dst_port': payload.get('dst_port', 0),
                'size': len(data) if hasattr(data, '__len__') else 0
            },
            success=True
        )

        # Notify protection detector
        self.detector.notify_protection_detected(
            ProtectionType.CLOUD,
            {
                'evidence': f"License server communication to {payload.get('dst_addr', 'unknown')}",
                'port': payload.get('dst_port', 0)
            }
        )

    def _analyze_decrypted_data(self, data: Any, payload: Dict[str, Any]):
        """Analyze decrypted data for interesting content"""
        try:
            # Try to interpret as text
            if isinstance(data, bytes):
                text_data = data.decode('utf-8', errors='ignore')

                # Check if it looks like structured data
                if text_data.strip().startswith('{') or text_data.strip().startswith('['):
                    # Possible JSON
                    self.logger.log_operation(
                        "decrypted_json_detected",
                        {
                            'algorithm': payload.get('algorithm', 'unknown'),
                            'size': len(data)
                        },
                        success=True
                    )
                elif text_data.strip().startswith('<?xml'):
                    # Possible XML
                    self.logger.log_operation(
                        "decrypted_xml_detected",
                        {
                            'algorithm': payload.get('algorithm', 'unknown'),
                            'size': len(data)
                        },
                        success=True
                    )

        except Exception as e:
            logger.debug(f"Failed to analyze decrypted data: {e}")

    def create_selective_instrumentation(self, target_apis: List[str],
                                      analysis_requirements: Dict[str, Any]) -> str:
        """Create selective instrumentation based on analysis requirements"""
        script_parts = []

        # Header
        script_parts.append("// Selective Instrumentation Script")
        script_parts.append("// Generated by Intellicrack Frida Manager")
        script_parts.append("")

        # Determine what to instrument based on requirements
        if analysis_requirements.get('trace_api_calls'):
            for api in target_apis:
                if '!' in api:
                    module, func = api.split('!')
                else:
                    module, func = 'unknown', api

                # Determine hook priority
                priority = HookCategory.MEDIUM
                if 'critical' in analysis_requirements.get('critical_apis', []):
                    if api in analysis_requirements['critical_apis']:
                        priority = HookCategory.CRITICAL

                # Check if we should hook based on performance
                if self.optimizer.should_hook_function(module, func, priority):
                    hook_code = self._generate_hook_code(module, func, priority)
                    script_parts.append(hook_code)

        if analysis_requirements.get('monitor_memory'):
            script_parts.append(self._generate_memory_monitoring_code())

        if analysis_requirements.get('detect_protections'):
            script_parts.append(self._generate_protection_detection_code())

        return '\n'.join(script_parts)

    def _generate_hook_code(self, module: str, function: str,
                          priority: HookCategory) -> str:
        """Generate optimized hook code"""
        return f"""
        // Hook {module}!{function} (Priority: {priority.value})
        {{
            const target = Module.findExportByName('{module}', '{function}');
            if (target) {{
                Interceptor.attach(target, {{
                    onEnter: function(args) {{
                        // Selective logging based on priority
                        if ('{priority.value}' === 'critical' || Math.random() < 0.1) {{
                            send({{
                                type: 'api_call',
                                api: '{module}!{function}',
                                args: Array.from(args).map(a => a.toString()).slice(0, 5),
                                priority: '{priority.value}'
                            }});
                        }}
                    }},
                    onLeave: function(retval) {{
                        // Log only if return value is interesting
                        if (retval && retval.toInt32() !== 0) {{
                            send({{
                                type: 'api_return',
                                api: '{module}!{function}',
                                retval: retval.toString()
                            }});
                        }}
                    }}
                }});
            }}
        }}
        """

    def _generate_memory_monitoring_code(self) -> str:
        """Generate memory monitoring code"""
        return """
        // Memory Monitoring
        const memoryWatches = new Map();

        Interceptor.attach(Module.findExportByName('kernel32.dll', 'VirtualAlloc'), {
            onLeave: function(retval) {
                if (retval) {
                    const addr = retval;
                    const size = this.context.r8 || this.context.rdx;
                    memoryWatches.set(addr.toString(), {
                        size: size,
                        timestamp: Date.now()
                    });

                    send({
                        type: 'memory_alloc',
                        address: addr.toString(),
                        size: size
                    });
                }
            }
        });

        Interceptor.attach(Module.findExportByName('kernel32.dll', 'VirtualFree'), {
            onEnter: function(args) {
                const addr = args[0];
                if (memoryWatches.has(addr.toString())) {
                    const info = memoryWatches.get(addr.toString());
                    memoryWatches.delete(addr.toString());

                    send({
                        type: 'memory_free',
                        address: addr.toString(),
                        lifetime: Date.now() - info.timestamp
                    });
                }
            }
        });
        """

    def _generate_protection_detection_code(self) -> str:
        """Generate protection detection code"""
        return """
        // Protection Detection
        const protectionAPIs = {
            'IsDebuggerPresent': 'anti_debug',
            'CheckRemoteDebuggerPresent': 'anti_debug',
            'GetSystemFirmwareTable': 'anti_vm',
            'GetTickCount': 'timing',
            'CryptHashData': 'integrity'
        };

        Object.keys(protectionAPIs).forEach(api => {
            const target = Module.findExportByName(null, api);
            if (target) {
                Interceptor.attach(target, {
                    onEnter: function() {
                        detectProtection(protectionAPIs[api], api + ' called');
                    }
                });
            }
        });
        """

    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics"""
        stats = {
            'logger': self.logger.get_statistics(),
            'detector': self.detector.get_detected_protections(),
            'batcher': self.batcher.get_batch_stats(),
            'optimizer': {
                'current_usage': self.optimizer.get_current_usage(),
                'recommendations': self.optimizer.get_optimization_recommendations()
            },
            'sessions': len(self.sessions),
            'scripts': len(self.scripts)
        }

        return stats

    def export_analysis(self, output_path: str = None) -> str:
        """Export complete analysis results"""
        # Export logs
        log_dir = self.logger.export_logs(output_path)

        # Add analysis summary
        summary = {
            'analysis_time': datetime.now().isoformat(),
            'statistics': self.get_statistics(),
            'detected_protections': self.detector.get_detected_protections(),
            'bypass_attempts': {
                'total': self.logger.stats['bypasses_attempted'],
                'successful': self.logger.stats['bypasses_successful'],
                'success_rate': self.logger.stats.get('bypass_success_rate', 0)
            }
        }

        summary_file = Path(log_dir) / "analysis_summary.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)

        return log_dir

    def cleanup(self):
        """Clean up resources"""
        # Stop batching
        self.batcher.stop_batching()

        # Detach all sessions
        for session_id, session in self.sessions.items():
            try:
                session.detach()
                logger.debug(f"Detached session {session_id}")
            except Exception as e:
                logger.warning(f"Failed to detach session {session_id}: {e}")

        # Clear collections
        self.sessions.clear()
        self.scripts.clear()


# Export main components
__all__ = [
    'FridaManager',
    'FridaOperationLogger',
    'ProtectionDetector',
    'ProtectionType',
    'HookCategory',
    'HookBatcher',
    'FridaPerformanceOptimizer'
]
