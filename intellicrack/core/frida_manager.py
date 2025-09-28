"""This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import json
import logging
import queue
import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from ..utils.core.import_checks import FRIDA_AVAILABLE, frida, psutil
from .frida_constants import HookCategory, ProtectionType

"""
Comprehensive Frida Manager for Intellicrack

This module provides a production-ready Frida management system with:
- Comprehensive operation logging
- Real-time protection adaptation
- Protection technique classification
- Performance optimization
- GUI integration support
"""

logger = logging.getLogger(__name__)


# Import constants from separate module to avoid cyclic imports


class FridaOperationLogger:
    """Comprehensive logging system for Frida operations.

    Provides structured logging for all Frida operations with separate
    log files for different operation types. Maintains in-memory buffers
    for real-time analysis and tracks comprehensive statistics.

    Features:
    - Separate log files for operations, hooks, performance, and bypasses
    - In-memory circular buffers for recent activity analysis
    - Real-time statistics tracking
    - Performance metrics collection
    - Log export functionality

    Attributes:
        log_dir (str): Directory for log files
        operation_buffer (deque): Circular buffer for recent operations
        hook_buffer (deque): Circular buffer for recent hook calls
        performance_metrics (dict): Dictionary of performance measurements
        stats (dict): Real-time statistics dictionary

    """

    def __init__(self, log_dir: str = None):
        """Initialize the Frida operation logger.

        Args:
            log_dir: Optional custom log directory. If not provided,
                    uses default from plugin_paths.get_frida_logs_dir().

        Side Effects:
            - Creates log directory if it doesn't exist
            - Initializes multiple log files with timestamp suffix
            - Sets up in-memory buffers and statistics tracking
            - Configures separate loggers for each operation type

        """
        if log_dir:
            self.log_dir = Path(log_dir)
        else:
            from intellicrack.utils.core.plugin_paths import get_frida_logs_dir

            self.log_dir = get_frida_logs_dir()
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
            "total_operations": 0,
            "successful_hooks": 0,
            "failed_hooks": 0,
            "bypasses_attempted": 0,
            "bypasses_successful": 0,
            "total_cpu_time": 0.0,
            "total_memory_used": 0,
        }

        self._init_loggers()

    def _init_loggers(self):
        """Initialize separate loggers for different operation types.

        Creates four specialized loggers:
        - Operation logger: General Frida operations and errors
        - Hook logger: Individual hook executions and modifications
        - Performance logger: Performance metrics and measurements
        - Bypass logger: Protection bypass attempts and results

        Each logger has its own file handler with appropriate formatting.

        Complexity:
            Time: O(1) constant time for logger setup
            Space: O(1) constant space for logger instances
        """
        # Operation logger
        self.op_logger = logging.getLogger("frida.operations")
        op_handler = logging.FileHandler(self.operation_log)
        op_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s - %(levelname)s - %(message)s",
            )
        )
        self.op_logger.addHandler(op_handler)
        self.op_logger.setLevel(logging.DEBUG)

        # Hook logger
        self.hook_logger = logging.getLogger("frida.hooks")
        hook_handler = logging.FileHandler(self.hook_log)
        hook_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s - %(message)s",
            )
        )
        self.hook_logger.addHandler(hook_handler)
        self.hook_logger.setLevel(logging.DEBUG)

        # Performance logger
        self.perf_logger = logging.getLogger("frida.performance")
        perf_handler = logging.FileHandler(self.performance_log)
        perf_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s - %(message)s",
            )
        )
        self.perf_logger.addHandler(perf_handler)
        self.perf_logger.setLevel(logging.INFO)

        # Bypass logger
        self.bypass_logger = logging.getLogger("frida.bypasses")
        bypass_handler = logging.FileHandler(self.bypass_log)
        bypass_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s - %(levelname)s - %(message)s",
            )
        )
        self.bypass_logger.addHandler(bypass_handler)
        self.bypass_logger.setLevel(logging.INFO)

    def log_operation(self, operation: str, details: dict[str, Any], success: bool = True, error: str = None):
        """Log a Frida operation with comprehensive details.

        Records operation details to both file and in-memory buffer,
        updates statistics, and provides structured logging for analysis.

        Args:
            operation: Name of the operation (e.g., 'attach', 'hook_install').
            details: Dictionary with operation details including:
                    - pid: Process ID.
                    - process_name: Name of target process.
                    - Additional operation-specific data.
            success: Whether the operation succeeded.
            error: Error message if operation failed.

        Note:
            - Appends entry to operation_buffer.
            - Increments total_operations counter.
            - Writes to operation log file.
            - Logs details as JSON for parsing.

        Example:
            logger.log_operation('attach', {
                'pid': 1234,
                'process_name': 'target.exe',
                'method': 'frida.attach'
            }, success=True)

        """
        timestamp = datetime.now()
        entry = {
            "timestamp": timestamp.isoformat(),
            "operation": operation,
            "details": details,
            "success": success,
            "error": error,
            "pid": details.get("pid"),
            "process": details.get("process_name"),
        }

        # Add to buffer
        self.operation_buffer.append(entry)

        # Update stats
        self.stats["total_operations"] += 1

        # Log to file
        level = logging.INFO if success else logging.ERROR
        msg = f"Operation: {operation} | PID: {details.get('pid')} | Success: {success}"
        if error:
            msg += f" | Error: {error}"
        self.op_logger.log(level, msg)

        # Log details as JSON for parsing
        self.op_logger.debug(f"Details: {json.dumps(details, default=str)}")

    def log_hook(
        self,
        function_name: str,
        module: str,
        arguments: list[Any],
        return_value: Any = None,
        modified: bool = False,
    ):
        """Log individual hook executions.

        Records details of each hook invocation for monitoring and
        debugging. Truncates long arguments/return values to prevent
        log bloat.

        Args:
            function_name: Name of the hooked function.
            module: Module containing the function (e.g., 'kernel32.dll').
            arguments: List of function arguments (truncated to 200 chars).
            return_value: Function return value (truncated to 100 chars).
            modified: Whether the return value was modified by the hook.

        Side Effects:
            - Appends to hook_buffer
            - Increments successful_hooks counter
            - Writes to hook log file with appropriate level

        Note:
            Uses INFO level for modified returns, DEBUG for monitoring.

        """
        timestamp = datetime.now()
        entry = {
            "timestamp": timestamp.isoformat(),
            "function": function_name,
            "module": module,
            "arguments": str(arguments)[:200],  # Truncate long args
            "return_value": str(return_value)[:100] if return_value else None,
            "modified": modified,
        }

        # Add to buffer
        self.hook_buffer.append(entry)

        # Update stats
        self.stats["successful_hooks"] += 1

        # Log to file (use INFO for modified returns, DEBUG for monitoring)
        level = logging.INFO if modified else logging.DEBUG
        # Add readable message to entry for better debugging
        entry["readable_msg"] = f"Hook: {module}!{function_name} | Modified: {modified}"
        self.hook_logger.log(level, json.dumps(entry, default=str))

    def log_performance(self, metric_name: str, value: float, unit: str = "ms", metadata: dict = None):
        """Log performance metrics.

        Records performance measurements for analysis and optimization.
        Maintains running statistics for CPU time and memory usage.

        Args:
            metric_name: Name of the metric (e.g., 'hook_execution_time').
            value: Numeric value of the measurement.
            unit: Unit of measurement (default: "ms").
            metadata: Optional additional context information.

        Side Effects:
            - Appends value to performance_metrics[metric_name]
            - Updates total_cpu_time if metric is 'cpu_time'
            - Updates total_memory_used if metric is 'memory_used'
            - Writes JSON entry to performance log

        Example:
            logger.log_performance('hook_execution_time', 1.5, 'ms',
                                 {'function': 'IsDebuggerPresent'})

        """
        timestamp = datetime.now()
        entry = {
            "timestamp": timestamp.isoformat(),
            "metric": metric_name,
            "value": value,
            "unit": unit,
            "metadata": metadata or {},
        }

        # Track in metrics
        self.performance_metrics[metric_name].append(value)

        # Log to file
        self.perf_logger.info(json.dumps(entry, default=str))

        # Update stats
        if metric_name == "cpu_time":
            self.stats["total_cpu_time"] += value
        elif metric_name == "memory_used":
            self.stats["total_memory_used"] = max(
                self.stats["total_memory_used"],
                value,
            )

    def log_bypass_attempt(
        self,
        protection_type: ProtectionType,
        technique: str,
        success: bool,
        details: dict[str, Any] = None,
    ):
        """Log bypass attempts with classification.

        Records protection bypass attempts with detailed classification
        by protection type and technique used.

        Args:
            protection_type: Type of protection being bypassed (from enum).
            technique: Name/description of bypass technique used.
            success: Whether the bypass succeeded.
            details: Optional additional context (e.g., error messages,
                    timing information, verification results).

        Note:
            Increments bypasses_attempted counter,
            increments bypasses_successful if success=True,
            writes JSON entry to bypass log,
            and logs with INFO level for success, WARNING for failure.

        Example:
            logger.log_bypass_attempt(
                ProtectionType.ANTI_DEBUG,
                'IsDebuggerPresent hook',
                success=True,
                details={'execution_time': 0.5}
            )

        """
        timestamp = datetime.now()
        entry = {
            "timestamp": timestamp.isoformat(),
            "protection_type": protection_type.value,
            "technique": technique,
            "success": success,
            "details": details or {},
        }

        # Log the entry to bypass logger
        self.bypass_logger.info(json.dumps(entry, default=str))

        # Update stats
        self.stats["bypasses_attempted"] += 1
        if success:
            self.stats["bypasses_successful"] += 1

        # Log to file
        level = logging.INFO if success else logging.WARNING
        msg = f"Bypass: {protection_type.value} | Technique: {technique} | Success: {success}"
        self.bypass_logger.log(level, msg)
        if details:
            self.bypass_logger.debug(f"Details: {json.dumps(details, default=str)}")

    def get_statistics(self) -> dict[str, Any]:
        """Get current statistics.

        Calculates and returns comprehensive statistics including
        success rates and performance averages.

        Returns:
            Dictionary containing:
            - Basic counters from self.stats
            - operation_success_rate: Percentage of successful operations
            - bypass_success_rate: Percentage of successful bypasses
            - avg_<metric>: Average value for each performance metric
            - max_<metric>: Maximum value for each performance metric
            - min_<metric>: Minimum value for each performance metric

        Complexity:
            Time: O(n) where n is number of performance metrics
            Space: O(m) where m is unique metric names

        """
        stats = self.stats.copy()

        # Calculate success rates
        if stats["total_operations"] > 0:
            stats["operation_success_rate"] = (
                (stats["total_operations"] - stats.get("failed_operations", 0)) / stats["total_operations"] * 100
            )

        if stats["bypasses_attempted"] > 0:
            stats["bypass_success_rate"] = stats["bypasses_successful"] / stats["bypasses_attempted"] * 100

        # Add performance averages
        for metric, values in self.performance_metrics.items():
            if values:
                stats[f"avg_{metric}"] = sum(values) / len(values)
                stats[f"max_{metric}"] = max(values)
                stats[f"min_{metric}"] = min(values)

        return stats

    def export_logs(self, output_dir: str = None) -> str:
        """Export all logs to a directory.

        Creates a complete export of all logs, statistics, and buffers
        for offline analysis or archiving.

        Args:
            output_dir: Optional output directory path. If not provided,
                       creates timestamped directory 'frida_export_YYYYMMDD_HHMMSS'

        Returns:
            Path to the export directory as string

        Side Effects:
            - Creates export directory
            - Copies all log files to export directory
            - Writes statistics.json with current stats
            - Writes buffers.json with operation/hook buffers

        Example:
            export_path = logger.export_logs('/path/to/exports')
            print(f"Logs exported to: {export_path}")

        """
        export_dir = Path(output_dir or f"frida_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        export_dir.mkdir(parents=True, exist_ok=True)

        # Copy log files
        import shutil

        for log_file in [self.operation_log, self.hook_log, self.performance_log, self.bypass_log]:
            if log_file.exists():
                shutil.copy2(log_file, export_dir / log_file.name)

        # Export statistics
        stats_file = export_dir / "statistics.json"
        with open(stats_file, "w") as f:
            json.dump(self.get_statistics(), f, indent=2)

        # Export buffers for analysis
        buffers_file = export_dir / "buffers.json"
        with open(buffers_file, "w") as f:
            json.dump(
                {
                    "operations": list(self.operation_buffer),
                    "hooks": list(self.hook_buffer)[-1000:],  # Last 1000 hooks
                    "performance_metrics": dict(self.performance_metrics),
                },
                f,
                indent=2,
                default=str,
            )

        return str(export_dir)

    def error(self, message: str):
        """Log error message using operation logger."""
        self.log_operation("error", {"message": message, "level": "error"})
        self.op_logger.error(message)


class ProtectionDetector:
    """Real-time protection detection and classification.

    Analyzes API calls, strings, and behavior patterns to identify
    protection mechanisms in real-time. Maintains a signature database
    for known protection techniques and supports adaptation callbacks.

    Features:
    - API call pattern matching
    - String-based detection
    - Registry and WMI monitoring
    - Real-time classification
    - Adaptation system for dynamic response

    Attributes:
        detected_protections: Map of protection types to detected indicators
        protection_signatures: Database of known protection signatures
        adaptation_callbacks: List of callbacks for protection events

    """

    def __init__(self):
        """Initialize the protection detector.

        Sets up signature database and prepares detection system.

        Side Effects:
            - Loads protection signatures
            - Initializes empty detection maps
            - Prepares adaptation callback list
        """
        self.detected_protections = defaultdict(set)
        self.protection_signatures = self._load_signatures()
        self.adaptation_callbacks = []

    def _load_signatures(self) -> dict[ProtectionType, list[dict]]:
        r"""Load protection signatures for classification.

        Returns a comprehensive database of signatures for detecting
        various protection mechanisms. Each signature can be:
        - API call patterns (module + function name)
        - String patterns (with case sensitivity options)
        - Registry key patterns
        - WMI query patterns

        Returns:
            Dictionary mapping ProtectionType to list of signature dicts

        Signature Format:
            {
                'api': 'FunctionName',      # API function name
                'module': 'module.dll',     # Module containing API
                'pattern': 'string',        # String to search for
                'type': 'string',          # Pattern type
                'case_insensitive': bool,   # Case sensitivity
                'registry': 'key\\path',    # Registry key
                'wmi': 'WMI_Class'         # WMI class name
            }

        """
        return {
            ProtectionType.ANTI_DEBUG: [
                {"api": "IsDebuggerPresent", "module": "kernel32.dll"},
                {"api": "CheckRemoteDebuggerPresent", "module": "kernel32.dll"},
                {"api": "NtQueryInformationProcess", "module": "ntdll.dll"},
                {"api": "OutputDebugString", "module": "kernel32.dll"},
            ],
            ProtectionType.ANTI_VM: [
                {"api": "GetSystemFirmwareTable", "module": "kernel32.dll"},
                {"pattern": "VMware", "type": "string"},
                {"pattern": "VirtualBox", "type": "string"},
                {"registry": r"SYSTEM\CurrentControlSet\Services\Disk\Enum"},
            ],
            ProtectionType.LICENSE: [
                {"api": "RegQueryValueEx", "module": "advapi32.dll"},
                {"api": "CryptDecrypt", "module": "advapi32.dll"},
                {"api": "InternetOpenUrl", "module": "wininet.dll"},
                {"pattern": "license", "type": "string", "case_insensitive": True},
            ],
            ProtectionType.INTEGRITY: [
                {"api": "CryptHashData", "module": "advapi32.dll"},
                {"api": "MapFileAndCheckSum", "module": "imagehlp.dll"},
                {"pattern": "checksum", "type": "string", "case_insensitive": True},
            ],
            ProtectionType.HARDWARE: [
                {"api": "GetVolumeInformation", "module": "kernel32.dll"},
                {"api": "GetAdaptersInfo", "module": "iphlpapi.dll"},
                {"wmi": "Win32_DiskDrive"},
                {"wmi": "Win32_NetworkAdapter"},
            ],
            ProtectionType.CLOUD: [
                {"api": "WinHttpOpen", "module": "winhttp.dll"},
                {"api": "InternetConnect", "module": "wininet.dll"},
                {"pattern": "https://", "type": "string"},
                {"pattern": "api.", "type": "string"},
            ],
            ProtectionType.TIME: [
                {"api": "GetSystemTime", "module": "kernel32.dll"},
                {"api": "GetTickCount", "module": "kernel32.dll"},
                {"api": "QueryPerformanceCounter", "module": "kernel32.dll"},
                {"pattern": "trial", "type": "string", "case_insensitive": True},
            ],
            ProtectionType.MEMORY: [
                {"api": "VirtualProtect", "module": "kernel32.dll"},
                {"api": "WriteProcessMemory", "module": "kernel32.dll"},
                {"api": "NtProtectVirtualMemory", "module": "ntdll.dll"},
            ],
            ProtectionType.KERNEL: [
                {"api": "DeviceIoControl", "module": "kernel32.dll"},
                {"api": "NtLoadDriver", "module": "ntdll.dll"},
                {"pattern": ".sys", "type": "string"},
            ],
        }

    def analyze_api_call(self, module: str, function: str, args: list[Any]) -> set[ProtectionType]:
        """Analyze an API call to detect protection types.

        Matches the API call against known protection signatures and
        analyzes function arguments for additional indicators.

        Args:
            module: Module name (e.g., 'kernel32.dll')
            function: Function name (e.g., 'IsDebuggerPresent')
            args: List of function arguments to analyze

        Returns:
            Set of detected ProtectionType enums

        Note:
            Updates detected_protections map
            and may trigger adaptation callbacks.

        Complexity:
            Time: O(n*m) where n is protection types, m is signatures per type
            Space: O(1)

        Example:
            detected = detector.analyze_api_call(
                'kernel32.dll',
                'IsDebuggerPresent',
                []
            )
            # Returns: {ProtectionType.ANTI_DEBUG}

        """
        detected = set()

        for prot_type, signatures in self.protection_signatures.items():
            for sig in signatures:
                if sig.get("api") == function and sig.get("module", "").lower() in module.lower():
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
                    if function.lower() in ["virtualprotect", "ntprotectvirtualmemory"] and arg in [
                        0x40,
                        0x20,
                        0x04,
                    ]:
                        detected.add(ProtectionType.MEMORY_PROTECTION)
                        self.detected_protections[ProtectionType.MEMORY_PROTECTION].add(f"Memory protection flag: {hex(arg)}")

        return detected

    def analyze_string(self, string_data: str) -> set[ProtectionType]:
        """Analyze strings for protection indicators."""
        detected = set()

        for prot_type, signatures in self.protection_signatures.items():
            for sig in signatures:
                if sig.get("type") == "string":
                    pattern = sig["pattern"]
                    if sig.get("case_insensitive"):
                        if pattern.lower() in string_data.lower():
                            detected.add(prot_type)
                            self.detected_protections[prot_type].add(f"String: {pattern}")
                    elif pattern in string_data:
                        detected.add(prot_type)
                        self.detected_protections[prot_type].add(f"String: {pattern}")

        return detected

    def register_adaptation_callback(self, callback: Callable):
        """Register callback for protection detection events."""
        self.adaptation_callbacks.append(callback)

    def notify_protection_detected(self, protection_type: ProtectionType, details: dict[str, Any]):
        """Notify registered callbacks of detected protection."""
        for callback in self.adaptation_callbacks:
            try:
                callback(protection_type, details)
            except Exception as e:
                logger.error(f"Adaptation callback error: {e}")

    def get_detected_protections(self) -> dict[str, list[str]]:
        """Get all detected protections with evidence."""
        return {prot_type.value: list(evidence) for prot_type, evidence in self.detected_protections.items()}


class HookBatcher:
    """Batch hooks for improved performance.

    Groups hook installations by priority category to reduce overhead
    and minimize detection. Uses a background thread to process hooks
    in batches based on their category timing requirements.

    Features:
    - Priority-based batching with configurable timeouts
    - Background thread processing
    - Category-specific delays (CRITICAL=0ms, HIGH=100ms, etc.)
    - Automatic batch flushing on size or timeout

    Attributes:
        max_batch_size: Maximum hooks per batch
        batch_timeout_ms: Default timeout for batching
        pending_hooks: Hooks grouped by session
        hook_queue: Thread-safe queue for incoming hooks
        batch_thread: Background processing thread
        running: Thread control flag

    """

    def __init__(self, max_batch_size: int = 50, batch_timeout_ms: int = 100):
        """Initialize the hook batcher.

        Args:
            max_batch_size: Maximum number of hooks to batch together
            batch_timeout_ms: Default timeout in milliseconds for batching

        Side Effects:
            - Initializes thread-safe queue
            - Prepares for background thread

        """
        self.logger = logging.getLogger(__name__ + ".HookBatcher")
        self.max_batch_size = max_batch_size
        self.batch_timeout_ms = batch_timeout_ms
        self.pending_hooks = defaultdict(list)
        self.hook_queue = queue.Queue()
        self.batch_thread = None
        self.running = False

    def add_hook(self, category: HookCategory, hook_spec: dict[str, Any]):
        """Add a hook to the batch queue.

        Timestamps the hook and queues it for batch processing based
        on its priority category.

        Args:
            category: Hook priority category (CRITICAL, HIGH, etc.)
            hook_spec: Dictionary containing hook details:
                      - target: Function to hook
                      - script: Hook script code
                      - session: Frida session reference

        Side Effects:
            - Adds timestamp to hook_spec
            - Adds category to hook_spec
            - Puts hook in thread-safe queue

        """
        hook_spec["timestamp"] = time.time()
        hook_spec["category"] = category
        self.hook_queue.put(hook_spec)

    def start_batching(self):
        """Start the batching thread."""
        self.running = True
        self.batch_thread = threading.Thread(target=self._batch_processor)
        self.batch_thread.daemon = True
        self.batch_thread.start()

    def stop_batching(self):
        """Stop the batching thread."""
        self.running = False
        if self.batch_thread:
            self.batch_thread.join()

    def _batch_processor(self):
        """Process hooks in batches."""
        while self.running:
            batch = []
            deadline = time.time() + (self.batch_timeout_ms / 1000.0)

            # Collect hooks until batch is full or timeout
            while len(batch) < self.max_batch_size and time.time() < deadline:
                try:
                    timeout = max(0, deadline - time.time())
                    hook = self.hook_queue.get(timeout=timeout)
                    batch.append(hook)
                except queue.Empty as e:
                    self.logger.error("queue.Empty in frida_manager: %s", e)
                    break

            if batch:
                # Sort by category priority
                batch.sort(key=lambda h: h["category"].value)

                # Group by module for efficiency
                module_groups = defaultdict(list)
                for hook in batch:
                    module_groups[hook.get("module", "unknown")].append(hook)

                # Return batched hooks
                for module, hooks in module_groups.items():
                    yield module, hooks

    def get_batch_stats(self) -> dict[str, int]:
        """Get batching statistics."""
        return {
            "pending_hooks": self.hook_queue.qsize(),
            "categories": {cat.name: sum(1 for h in list(self.hook_queue.queue) if h.get("category") == cat) for cat in HookCategory},
        }


class FridaPerformanceOptimizer:
    """Optimize Frida operations for performance.

    Monitors resource usage and makes intelligent decisions about
    hook installation to balance functionality with performance.
    Tracks hook call rates and provides optimization recommendations.

    Features:
    - Resource usage monitoring (CPU, memory, threads)
    - Selective hook installation based on importance
    - Hook call rate tracking
    - Script optimization with caching and batching
    - Performance history tracking

    Attributes:
        process: psutil Process object for monitoring
        baseline_memory: Initial memory usage for comparison
        baseline_cpu: Initial CPU usage for comparison
        optimization_enabled: Global optimization toggle
        selective_hooks: Per-hook performance statistics
        hook_cache: Cache for frequently called hooks
        performance_history: Recent performance measurements

    """

    def __init__(self):
        """Initialize the performance optimizer.

        Side Effects:
            - Creates psutil Process object
            - Initializes performance tracking structures
        """
        self.process = psutil.Process()
        self.baseline_memory = 0
        self.baseline_cpu = 0
        self.optimization_enabled = True
        self.selective_hooks = {}
        self.hook_cache = {}
        self.performance_history = deque(maxlen=100)

    def measure_baseline(self):
        """Measure baseline resource usage."""
        self.baseline_memory = self.process.memory_info().rss
        self.baseline_cpu = self.process.cpu_percent(interval=0.1)

    def get_current_usage(self) -> dict[str, float]:
        """Get current resource usage."""
        return {
            "memory_mb": (self.process.memory_info().rss - self.baseline_memory) / 1024 / 1024,
            "cpu_percent": self.process.cpu_percent(interval=0.1),
            "threads": self.process.num_threads(),
            "handles": len(self.process.open_files()),
        }

    def should_hook_function(self, module: str, function: str, importance: HookCategory) -> bool:
        """Determine if a function should be hooked based on performance.

        Makes intelligent decisions about hook installation based on
        current resource usage and hook importance. Critical hooks
        are always installed.

        Args:
            module: Module containing the function
            function: Function name to potentially hook
            importance: Hook priority category

        Returns:
            True if function should be hooked, False to skip

        Decision Criteria:
            - CRITICAL hooks: Always installed
            - High memory (>500MB): Only CRITICAL and HIGH
            - High CPU (>80%): Only CRITICAL
            - High call rate (>1000/sec): Only CRITICAL and HIGH

        Complexity:
            Time: O(1) constant time for resource checks
            Space: O(1) constant space for temporary variables

        """
        if not self.optimization_enabled:
            return True

        # Always hook critical functions
        if importance == HookCategory.CRITICAL:
            return True

        # Check current resource usage
        usage = self.get_current_usage()

        # High memory usage - be selective
        if usage["memory_mb"] > 500:
            return importance in [HookCategory.CRITICAL, HookCategory.HIGH]

        # High CPU usage - be very selective
        if usage["cpu_percent"] > 80:
            return importance == HookCategory.CRITICAL

        # Check if this hook is frequently called
        hook_key = f"{module}!{function}"
        if hook_key in self.selective_hooks:
            call_rate = self.selective_hooks[hook_key].get("call_rate", 0)
            if call_rate > 1000:  # More than 1000 calls/sec
                return importance in [HookCategory.CRITICAL, HookCategory.HIGH]

        return True

    def optimize_script(self, script_code: str) -> str:
        """Optimize Frida script for performance."""
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
        return "\n".join(optimizations) + "\n" + script_code

    def track_hook_performance(self, module: str, function: str, execution_time: float):
        """Track individual hook performance."""
        hook_key = f"{module}!{function}"

        if hook_key not in self.selective_hooks:
            self.selective_hooks[hook_key] = {
                "total_time": 0,
                "call_count": 0,
                "call_rate": 0,
                "last_update": time.time(),
            }

        stats = self.selective_hooks[hook_key]
        stats["total_time"] += execution_time
        stats["call_count"] += 1

        # Update call rate
        now = time.time()
        time_diff = now - stats["last_update"]
        if time_diff > 1.0:  # Update rate every second
            stats["call_rate"] = stats["call_count"] / time_diff
            stats["call_count"] = 0
            stats["last_update"] = now

    def get_optimization_recommendations(self) -> list[str]:
        """Get recommendations for optimization."""
        recommendations = []
        usage = self.get_current_usage()

        if usage["memory_mb"] > 1000:
            recommendations.append(
                "High memory usage detected. Consider reducing hook scope or enabling selective instrumentation.",
            )

        if usage["cpu_percent"] > 70:
            recommendations.append(
                "High CPU usage detected. Enable hook batching and consider disabling non-essential monitoring hooks.",
            )

        # Check for hot functions
        hot_functions = [(k, v) for k, v in self.selective_hooks.items() if v.get("call_rate", 0) > 5000]
        if hot_functions:
            recommendations.append(
                f"Found {len(hot_functions)} frequently called functions. Consider optimizing or selectively hooking these.",
            )

        return recommendations


class FridaManager:
    """Main Frida management class with all advanced features.

    Comprehensive Frida management system that integrates logging,
    protection detection, performance optimization, and hook batching.
    Provides high-level interface for all Frida operations.

    Features:
    - Process attachment and session management
    - Script loading and execution
    - Real-time protection detection and adaptation
    - Performance optimization with selective hooking
    - Hook batching for efficiency
    - Comprehensive operation logging
    - Multi-session support

    Attributes:
        logger: FridaOperationLogger instance
        detector: ProtectionDetector instance
        batcher: HookBatcher instance
        optimizer: FridaPerformanceOptimizer instance
        device: Frida device reference
        sessions: Map of session IDs to Frida sessions
        scripts: Map of script IDs to loaded scripts
        script_dir: Directory containing Frida scripts
        protection_adaptations: Map of protection types to adaptation methods

    """

    def __init__(self, log_dir: str = None, script_dir: str = None):
        """Initialize the Frida manager.

        Args:
            log_dir: Optional custom directory for logs
            script_dir: Optional custom directory for scripts

        Raises:
            ImportError: If Frida is not available

        Side Effects:
            - Creates all subsystem instances
            - Ensures script directory exists
            - Registers adaptation callbacks
            - Starts background services

        """
        if not FRIDA_AVAILABLE:
            raise ImportError("Frida is not available. Please install frida-tools: pip install frida-tools")

        self.logger = FridaOperationLogger(log_dir)
        self.detector = ProtectionDetector()
        self.batcher = HookBatcher()
        self.optimizer = FridaPerformanceOptimizer()

        self.device = None
        self.sessions = {}
        self.scripts = {}
        self.script_outputs = {}  # Store script outputs for persistence

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

    def attach_to_process(self, process_identifier: int | str) -> bool:
        """Attach to a process with comprehensive logging.

        Establishes a Frida session with the target process and logs
        all operations. Handles both PID and process name attachment.

        Args:
            process_identifier: Process ID (int) or process name (str)

        Returns:
            True if attachment succeeded, False otherwise

        Side Effects:
            - Creates Frida session
            - Stores session in self.sessions
            - Logs operation details
            - Logs performance metrics

        Example:
            # Attach by PID
            success = manager.attach_to_process(1234)

            # Attach by name
            success = manager.attach_to_process("target.exe")

        Complexity:
            Time: O(1) + Frida attachment overhead
            Space: O(1)

        """
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
                    process_name = next(
                        (p.name for p in processes if p.pid == process_identifier),
                        f"pid_{process_identifier}",
                    )
                except Exception:
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
                    "pid": process_identifier,
                    "process_name": process_name,
                    "session_id": session_id,
                    "device": str(self.device),
                },
                success=True,
            )

            # Log performance
            attach_time = (time.time() - start_time) * 1000
            self.logger.log_performance("attach_time", attach_time, "ms", {"process": process_name})

            # Set up session handlers
            session.on("detached", lambda reason: self._on_session_detached(session_id, reason))

            return True

        except Exception as e:
            self.logger.log_operation(
                "attach_to_process",
                {"process_identifier": process_identifier},
                success=False,
                error=str(e),
            )
            return False

    def add_custom_script(self, script_content: str, script_name: str) -> Path:
        """Add a custom Frida script to the scripts directory.

        Args:
            script_content: JavaScript code for the script
            script_name: Name for the script (without extension)

        Returns:
            Path to the created script file

        """
        # Ensure script name ends with .js
        if not script_name.endswith(".js"):
            script_name += ".js"

        # Create script path
        script_path = self.script_dir / script_name

        # Write script content
        script_path.write_text(script_content, encoding="utf-8")

        # Log operation
        self.logger.log_operation(
            "add_custom_script",
            {
                "script_name": script_name,
                "script_path": str(script_path),
                "content_length": len(script_content),
            },
            success=True,
        )

        return script_path

    def list_available_scripts(self) -> list[dict[str, Any]]:
        """List all available Frida scripts.

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
                    content = script_file.read_text(encoding="utf-8")
                    protection_type = "UNKNOWN"

                    # Look for protection type in script
                    if "PROTECTION_TYPE" in content:
                        import re

                        match = re.search(r'PROTECTION_TYPE\s*=\s*["\'](\w+)["\']', content)
                        if match:
                            protection_type = match.group(1)

                    scripts.append(
                        {
                            "name": script_file.stem,
                            "path": str(script_file),
                            "size": stat.st_size,
                            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            "protection_type": protection_type,
                        }
                    )

                except Exception as e:
                    logger.error(f"Error reading script {script_file}: {e}")

        return scripts

    def load_script(self, session_id: str, script_name: str, options: dict[str, Any] = None) -> bool:
        """Load and inject a Frida script with optimization."""
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

            with open(script_path) as f:
                script_code = f.read()

            # Optimize script
            if self.optimizer.optimization_enabled:
                script_code = self.optimizer.optimize_script(script_code)

            # Add instrumentation for logging
            script_code = self._instrument_script(script_code, script_name)

            # Create script
            script = session.create_script(script_code)

            # Set up message handler
            script.on(
                "message",
                lambda msg, data: self._on_script_message(
                    session_id,
                    script_name,
                    msg,
                    data,
                ),
            )

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
                    "session_id": session_id,
                    "script_name": script_name,
                    "script_size": len(script_code),
                    "options": options,
                },
                success=True,
            )

            # Log performance
            load_time = (time.time() - start_time) * 1000
            self.logger.log_performance("script_load_time", load_time, "ms", {"script": script_name})

            return True

        except Exception as e:
            self.logger.log_operation(
                "load_script",
                {
                    "session_id": session_id,
                    "script_name": script_name,
                },
                success=False,
                error=str(e),
            )
            return False

    def _instrument_script(self, script_code: str, script_name: str) -> str:
        """Add instrumentation to script for logging."""
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

    def _on_script_message(self, session_id: str, script_name: str, message: dict, data: Any):
        """Handle messages from Frida scripts including binary data."""
        msg_type = message.get("type")
        payload = message.get("payload", {})

        # Handle new structured messages from updated Frida scripts
        if msg_type == "send" and isinstance(payload, dict):
            structured_type = payload.get("type")
            if structured_type in [
                "info",
                "warning",
                "error",
                "status",
                "bypass",
                "success",
                "detection",
                "notification",
            ]:
                self._handle_structured_message(session_id, script_name, payload)
                # Save script output for persistence
                self.save_script_output(script_name, payload)
                return

        # Handle binary data if present
        if data is not None:
            # Log that we received binary data
            self.logger.log_operation(
                f"script_data:{script_name}",
                {
                    "session_id": session_id,
                    "data_size": len(data) if hasattr(data, "__len__") else "unknown",
                    "data_type": type(data).__name__,
                },
                success=True,
            )

            # Process binary data based on payload type
            if isinstance(payload, dict):
                data_type = payload.get("data_type", "unknown")

                if data_type == "memory_dump":
                    # Handle memory dump data
                    self._handle_memory_dump(session_id, script_name, data, payload)
                elif data_type == "screenshot":
                    # Handle screenshot data
                    self._handle_screenshot_data(session_id, script_name, data, payload)
                elif data_type == "file_content":
                    # Handle file content
                    self._handle_file_content(session_id, script_name, data, payload)
                elif data_type == "network_packet":
                    # Handle network packet data
                    self._handle_network_packet(session_id, script_name, data, payload)
                elif data_type == "encrypted_data":
                    # Handle encrypted data that was intercepted
                    self._handle_encrypted_data(session_id, script_name, data, payload)
                else:
                    # Generic binary data handling
                    self._handle_generic_binary_data(session_id, script_name, data, payload)

        if msg_type == "send":
            # Handle different message types
            if isinstance(payload, dict):
                payload_type = payload.get("type")

                if payload_type == "hook":
                    # Log hook execution
                    self.logger.log_hook(
                        payload.get("function"),
                        payload.get("module"),
                        payload.get("args", []),
                        payload.get("retval"),
                        payload.get("modified", False),
                    )

                    # Track performance
                    if "elapsed" in payload:
                        self.optimizer.track_hook_performance(
                            payload.get("module"),
                            payload.get("function"),
                            payload.get("elapsed"),
                        )

                elif payload_type == "protection_detected":
                    # Handle protection detection
                    prot_type = ProtectionType(payload.get("protection_type"))
                    self.detector.notify_protection_detected(
                        prot_type,
                        {
                            "evidence": payload.get("evidence"),
                            "script": script_name,
                            "session": session_id,
                        },
                    )

                elif payload_type == "performance_report":
                    # Log performance stats
                    self.logger.log_performance(
                        f"{script_name}_performance",
                        payload.get("uptime", 0),
                        "ms",
                        payload,
                    )

                elif payload_type == "batch":
                    # Handle batched messages
                    for item in payload.get("data", []):
                        self._on_script_message(session_id, script_name, {"type": "send", "payload": item}, None)

        elif msg_type == "error":
            # Log script errors
            self.logger.log_operation(
                f"script_error:{script_name}",
                {
                    "session_id": session_id,
                    "error": payload,
                },
                success=False,
                error=str(payload),
            )

    def _on_session_detached(self, session_id: str, reason: str):
        """Handle session detachment."""
        self.logger.log_operation(
            "session_detached",
            {
                "session_id": session_id,
                "reason": reason,
            },
            success=True,
        )

        # Clean up
        if session_id in self.sessions:
            del self.sessions[session_id]

        # Remove associated scripts
        script_keys = [k for k in self.scripts.keys() if k.startswith(session_id)]
        for key in script_keys:
            del self.scripts[key]

    def _on_protection_detected(self, protection_type: ProtectionType, details: dict[str, Any]):
        """Handle protection detection events."""
        # Log detection
        self.logger.log_bypass_attempt(
            protection_type,
            "detection",
            True,
            details,
        )

        # Apply adaptation if available
        if protection_type in self.protection_adaptations:
            adaptation_func = self.protection_adaptations[protection_type]
            try:
                adaptation_func(details)
            except Exception as e:
                logger.error(f"Adaptation failed for {protection_type}: {e}")

    # Protection adaptation methods
    def _adapt_anti_debug(self, details: dict[str, Any]):
        """Adapt to anti-debugging protections."""
        session_id = details.get("session")
        if not session_id:
            return

        # Load anti-debug bypass script
        self.load_script(
            session_id,
            "anti_debugger",
            {
                "aggressive": True,
                "stealth_mode": True,
            },
        )

        self.logger.log_bypass_attempt(
            ProtectionType.ANTI_DEBUG,
            "frida_anti_debug_bypass",
            True,
            {"method": "script_injection"},
        )

    def _adapt_anti_vm(self, details: dict[str, Any]):
        """Adapt to anti-VM protections."""
        session_id = details.get("session")
        if not session_id:
            return

        # Load VM detection bypass
        self.load_script(
            session_id,
            "virtualization_bypass",
            {
                "spoof_hardware": True,
                "hide_hypervisor": True,
            },
        )

        self.logger.log_bypass_attempt(
            ProtectionType.ANTI_VM,
            "frida_vm_bypass",
            True,
            {"method": "hardware_spoofing"},
        )

    def _adapt_license(self, details: dict[str, Any]):
        """Adapt to license verification."""
        session_id = details.get("session")
        if not session_id:
            return

        # Load license bypass script
        script_name = "cloud_licensing_bypass"
        evidence = details.get("evidence", "")

        if "RegQueryValueEx" in evidence:
            script_name = "registry_monitor"

        self.load_script(
            session_id,
            script_name,
            {
                "patch_checks": True,
                "emulate_server": True,
            },
        )

        self.logger.log_bypass_attempt(
            ProtectionType.LICENSE,
            "frida_license_bypass",
            True,
            {"method": "api_hooking", "script": script_name},
        )

    def _adapt_integrity(self, details: dict[str, Any]):
        """Adapt to integrity checks."""
        session_id = details.get("session")
        if not session_id:
            return

        # Load integrity bypass
        self.load_script(
            session_id,
            "code_integrity_bypass",
            {
                "patch_checksums": True,
                "hook_validation": True,
            },
        )

        self.logger.log_bypass_attempt(
            ProtectionType.INTEGRITY,
            "frida_integrity_bypass",
            True,
            {"method": "checksum_patching"},
        )

    def _adapt_hardware(self, details: dict[str, Any]):
        """Adapt to hardware binding."""
        session_id = details.get("session")
        if not session_id:
            return

        # Load hardware spoofer
        self.load_script(
            session_id,
            
            {
                "spoof_all": True,
                "persistent": True,
            },
        )

        self.logger.log_bypass_attempt(
            ProtectionType.HARDWARE,
            "frida_hardware_spoof",
            True,
            {"method": "hwid_spoofing"},
        )

    def _adapt_cloud(self, details: dict[str, Any]):
        """Adapt to cloud verification."""
        session_id = details.get("session")
        if not session_id:
            return

        # Load cloud bypass
        self.load_script(
            session_id,
            "cloud_licensing_bypass",
            {
                "intercept_requests": True,
                "modify_responses": True,
                "response_manipulation": {
                    "license_valid": True,
                    "activation_status": "activated",
                    "expiry_override": True,
                },
            },
        )

        self.logger.log_bypass_attempt(
            ProtectionType.CLOUD,
            "frida_cloud_bypass",
            True,
            {"method": "network_interception"},
        )

    def _adapt_time(self, details: dict[str, Any]):
        """Adapt to time-based protections."""
        session_id = details.get("session")
        if not session_id:
            return

        # Load time manipulation script
        self.load_script(
            session_id,
            "time_bomb_defuser",
            {
                "freeze_time": True,
                "extend_trial": True,
            },
        )

        self.logger.log_bypass_attempt(
            ProtectionType.TIME,
            "frida_time_bypass",
            True,
            {"method": "time_manipulation"},
        )

    def _adapt_memory(self, details: dict[str, Any]):
        """Adapt to memory protections."""
        session_id = details.get("session")
        if not session_id:
            return

        # Load memory protection bypass
        self.load_script(
            session_id,
            "memory_integrity_bypass",
            {
                "bypass_guard_pages": True,
                "disable_protection": True,
            },
        )

        self.logger.log_bypass_attempt(
            ProtectionType.MEMORY,
            "frida_memory_bypass",
            True,
            {"method": "memory_patching"},
        )

    def _adapt_kernel(self, details: dict[str, Any]):
        """Adapt to kernel-mode protections."""
        session_id = details.get("session")
        if not session_id:
            return

        # Load kernel bypass script
        self.load_script(
            session_id,
            "kernel_mode_bypass",
            {
                "usermode_only": True,
                "avoid_kernel": True,
            },
        )

        self.logger.log_bypass_attempt(
            ProtectionType.KERNEL,
            "frida_kernel_bypass",
            True,
            {"method": "usermode_emulation"},
        )

    def _handle_memory_dump(self, session_id: str, script_name: str, data: Any, payload: dict[str, Any]):
        """Handle memory dump data from Frida scripts."""
        # Extract metadata from payload
        address = payload.get("address", "0x0")
        size = payload.get("size", len(data) if hasattr(data, "__len__") else 0)
        process_name = payload.get("process_name", "unknown")

        # Log the memory dump event
        self.logger.log_operation(
            f"memory_dump:{script_name}",
            {
                "session_id": session_id,
                "address": address,
                "size": size,
                "process": process_name,
            },
            success=True,
        )

        # Store memory dump for analysis
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        dump_file = self.logger.log_dir / f"memory_dump_{process_name}_{address}_{timestamp}.bin"

        try:
            # Write binary data to file
            if isinstance(data, (bytes, bytearray)):
                with open(dump_file, "wb") as f:
                    f.write(data)
            else:
                # Convert to bytes if necessary
                with open(dump_file, "wb") as f:
                    f.write(bytes(data))

            # Analyze memory dump for patterns
            self._analyze_memory_dump(data, payload)

        except Exception as e:
            logger.error(f"Failed to save memory dump: {e}")

    def _handle_screenshot_data(self, session_id: str, script_name: str, data: Any, payload: dict[str, Any]):
        """Handle screenshot data from Frida scripts."""
        # Extract metadata
        window_title = payload.get("window_title", "unknown")
        capture_time = payload.get("capture_time", datetime.now().isoformat())
        format_type = payload.get("format", "png")

        # Log screenshot event
        self.logger.log_operation(
            f"screenshot:{script_name}",
            {
                "session_id": session_id,
                "window": window_title,
                "time": capture_time,
                "format": format_type,
            },
            success=True,
        )

        # Save screenshot
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        screenshot_file = self.logger.log_dir / f"screenshot_{window_title}_{timestamp}.{format_type}"

        try:
            with open(screenshot_file, "wb") as f:
                f.write(data if isinstance(data, bytes) else bytes(data))

            # Perform OCR or pattern detection if needed
            if payload.get("analyze", False):
                self._analyze_screenshot(data, payload)

        except Exception as e:
            logger.error(f"Failed to save screenshot: {e}")

    def _handle_file_content(self, session_id: str, script_name: str, data: Any, payload: dict[str, Any]):
        """Handle file content intercepted by Frida scripts."""
        # Extract file information
        file_path = payload.get("file_path", "unknown")
        operation = payload.get("operation", "read")  # read/write
        file_size = payload.get("size", len(data) if hasattr(data, "__len__") else 0)

        # Log file operation
        self.logger.log_operation(
            f"file_{operation}:{script_name}",
            {
                "session_id": session_id,
                "file_path": file_path,
                "size": file_size,
                "operation": operation,
            },
            success=True,
        )

        # Analyze file content for patterns
        if operation == "read":
            # Check for license files, config files, etc.
            if any(pattern in file_path.lower() for pattern in ["license", "key", "config", "serial"]):
                self._analyze_license_file(data, file_path, payload)
        elif operation == "write":
            # Monitor for persistence or modification attempts
            self._analyze_file_write(data, file_path, payload)

    def _handle_network_packet(self, session_id: str, script_name: str, data: Any, payload: dict[str, Any]):
        """Handle network packet data from Frida scripts."""
        # Extract packet information
        direction = payload.get("direction", "unknown")  # send/recv
        protocol = payload.get("protocol", "tcp")
        src_addr = payload.get("src_addr", "")
        dst_addr = payload.get("dst_addr", "")
        src_port = payload.get("src_port", 0)
        dst_port = payload.get("dst_port", 0)

        # Log network event
        self.logger.log_operation(
            f"network_{direction}:{script_name}",
            {
                "session_id": session_id,
                "protocol": protocol,
                "src": f"{src_addr}:{src_port}",
                "dst": f"{dst_addr}:{dst_port}",
                "size": len(data) if hasattr(data, "__len__") else 0,
            },
            success=True,
        )

        # Analyze packet content
        if protocol.lower() in ["http", "https"]:
            self._analyze_http_traffic(data, payload)
        elif any(port in [dst_port, src_port] for port in [443, 8443, 8080]):
            # Potential license server communication
            self._analyze_license_traffic(data, payload)

    def _handle_encrypted_data(self, session_id: str, script_name: str, data: Any, payload: dict[str, Any]):
        """Handle encrypted data intercepted by Frida scripts."""
        # Extract encryption information
        algorithm = payload.get("algorithm", "unknown")
        operation = payload.get("operation", "unknown")  # encrypt/decrypt
        key_info = payload.get("key_info", {})
        iv = payload.get("iv")

        # Log encryption event
        self.logger.log_operation(
            f"crypto_{operation}:{script_name}",
            {
                "session_id": session_id,
                "algorithm": algorithm,
                "operation": operation,
                "data_size": len(data) if hasattr(data, "__len__") else 0,
                "has_key": bool(key_info),
                "has_iv": bool(iv),
            },
            success=True,
        )

        # Store encrypted/decrypted data for analysis
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        crypto_file = self.logger.log_dir / f"crypto_{operation}_{algorithm}_{timestamp}.bin"

        try:
            with open(crypto_file, "wb") as f:
                f.write(data if isinstance(data, bytes) else bytes(data))

            # If we have decrypted data, analyze it
            if operation == "decrypt":
                self._analyze_decrypted_data(data, payload)

        except Exception as e:
            logger.error(f"Failed to save crypto data: {e}")

    def _handle_generic_binary_data(self, session_id: str, script_name: str, data: Any, payload: dict[str, Any]):
        """Handle generic binary data from Frida scripts."""
        # Extract any available metadata
        data_type = payload.get("data_type", "binary")
        description = payload.get("description", "Generic binary data")

        # Log the event
        self.logger.log_operation(
            f"binary_data:{script_name}",
            {
                "session_id": session_id,
                "type": data_type,
                "description": description,
                "size": len(data) if hasattr(data, "__len__") else 0,
            },
            success=True,
        )

        # Save the data for later analysis
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        data_file = self.logger.log_dir / f"binary_data_{script_name}_{timestamp}.bin"

        try:
            with open(data_file, "wb") as f:
                f.write(data if isinstance(data, bytes) else bytes(data))
        except Exception as e:
            logger.error(f"Failed to save binary data: {e}")

    def _analyze_memory_dump(self, data: Any, payload: dict[str, Any]):
        """Analyze memory dump for interesting patterns."""
        # Convert to bytes if necessary
        if not isinstance(data, bytes):
            data = bytes(data)

        # Look for common patterns
        patterns = {
            "license_key": [b"LICENSE", b"KEY", b"SERIAL", b"ACTIVATION"],
            "crypto_keys": [b"RSA", b"AES", b"-----BEGIN", b"-----END"],
            "urls": [b"http://", b"https://", b"ftp://"],
            "registry": [b"HKEY_", b"SOFTWARE\\", b"CurrentVersion"],
            "interesting_strings": [b"trial", b"expired", b"registered", b"cracked"],
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
                    findings[category].append(
                        {
                            "pattern": pattern.decode("utf-8", errors="ignore"),
                            "offset": idx,
                            "context": context.hex(),
                        }
                    )

        if findings:
            self.logger.log_operation(
                "memory_analysis",
                {
                    "findings": findings,
                    "source": payload,
                },
                success=True,
            )

    def _analyze_screenshot(self, data: Any, payload: dict[str, Any]):
        """Analyze screenshot for UI elements or text."""
        # Analyze screenshot data for UI elements
        analysis_results = {
            "ui_elements": [],
            "text_content": [],
            "coordinates": {},
        }

        # Process image data if provided
        if data and hasattr(data, "__len__") and len(data) > 0:
            try:
                # Attempt basic image analysis on the data
                analysis_results["data_size"] = len(data)
                analysis_results["data_type"] = type(data).__name__

                # Look for common UI patterns in raw data
                if isinstance(data, (bytes, str)):
                    # Search for common dialog patterns
                    dialog_patterns = [
                        b"OK",
                        b"Cancel",
                        b"Yes",
                        b"No",
                        b"Apply",
                        b"License",
                        b"Trial",
                        b"Activate",
                        b"Register",
                    ]
                    for pattern in dialog_patterns:
                        if pattern in (data if isinstance(data, bytes) else data.encode()):
                            analysis_results["ui_elements"].append(
                                {
                                    "type": "button",
                                    "text": pattern.decode("utf-8", errors="ignore"),
                                    "confidence": 0.7,
                                }
                            )

            except Exception as e:
                self.logger.error(f"Data analysis failed: {e}")
                analysis_results["error"] = str(e)

        # Log analysis results with data info
        self.logger.log_operation(
            "screenshot_analysis",
            {
                "requested": True,
                "window": payload.get("window_title", "unknown"),
            },
            success=True,
        )

    def _analyze_license_file(self, data: Any, file_path: str, payload: dict[str, Any]):
        """Analyze potential license file content."""
        try:
            # Try to decode as text
            if isinstance(data, bytes):
                text_content = data.decode("utf-8", errors="ignore")
            else:
                text_content = str(data)

            # Look for license patterns
            license_indicators = ["expiry", "trial", "activation", "serial", "key", "license"]
            found_indicators = [ind for ind in license_indicators if ind in text_content.lower()]

            if found_indicators:
                # Extract additional context from payload
                operation_context = {
                    "file_path": file_path,
                    "indicators": found_indicators,
                    "size": len(data),
                    "process_name": payload.get("process_name", "unknown"),
                    "thread_id": payload.get("thread_id"),
                    "timestamp": payload.get("timestamp"),
                    "operation_type": payload.get("operation", "file_analysis"),
                }

                self.logger.log_operation(
                    "license_file_detected",
                    operation_context,
                    success=True,
                )

                # Notify protection detector
                self.detector.notify_protection_detected(
                    ProtectionType.LICENSE,
                    {
                        "evidence": f"License file accessed: {file_path}",
                        "indicators": found_indicators,
                    },
                )

        except Exception as e:
            logger.debug(f"Failed to analyze license file: {e}")

    def _analyze_file_write(self, data: Any, file_path: str, payload: dict[str, Any]):
        """Analyze file write operations for suspicious activity."""
        # Use payload data for comprehensive analysis
        write_context = {
            "file_path": file_path,
            "operation_type": payload.get("operation", "write"),
            "bytes_written": payload.get("bytes", 0),
            "process_context": payload.get("process", {}),
            "data_size": len(data) if hasattr(data, "__len__") else 0,
            "timestamp": payload.get("timestamp"),
        }

        # Check for persistence mechanisms
        persistence_paths = ["startup", "autorun", "scheduled tasks", "services"]
        if any(path in file_path.lower() for path in persistence_paths):
            # Use write_context for detailed logging
            self.logger.log_operation(
                "persistence_attempt",
                write_context,
                success=True,
            )

    def _analyze_http_traffic(self, data: Any, payload: dict[str, Any]):
        """Analyze HTTP/HTTPS traffic for license checks."""
        try:
            if isinstance(data, bytes):
                text_data = data.decode("utf-8", errors="ignore")
            else:
                text_data = str(data)

            # Look for license-related endpoints
            license_endpoints = ["activate", "verify", "license", "validate", "auth"]
            for endpoint in license_endpoints:
                if endpoint in text_data.lower():
                    self.logger.log_operation(
                        "license_communication",
                        {
                            "endpoint_type": endpoint,
                            "protocol": payload.get("protocol", "http"),
                        },
                        success=True,
                    )
                    break

        except Exception as e:
            logger.debug(f"Failed to analyze HTTP traffic: {e}")

    def _analyze_license_traffic(self, data: Any, payload: dict[str, Any]):
        """Analyze potential license server communication."""
        self.logger.log_operation(
            "license_server_communication",
            {
                "dst_addr": payload.get("dst_addr", ""),
                "dst_port": payload.get("dst_port", 0),
                "size": len(data) if hasattr(data, "__len__") else 0,
            },
            success=True,
        )

        # Notify protection detector
        self.detector.notify_protection_detected(
            ProtectionType.CLOUD,
            {
                "evidence": f"License server communication to {payload.get('dst_addr', 'unknown')}",
                "port": payload.get("dst_port", 0),
            },
        )

    def _analyze_decrypted_data(self, data: Any, payload: dict[str, Any]):
        """Analyze decrypted data for interesting content."""
        try:
            # Try to interpret as text
            if isinstance(data, bytes):
                text_data = data.decode("utf-8", errors="ignore")

                # Check if it looks like structured data
                if text_data.strip().startswith("{") or text_data.strip().startswith("["):
                    # Possible JSON
                    self.logger.log_operation(
                        "decrypted_json_detected",
                        {
                            "algorithm": payload.get("algorithm", "unknown"),
                            "size": len(data),
                        },
                        success=True,
                    )
                elif text_data.strip().startswith("<?xml"):
                    # Possible XML
                    self.logger.log_operation(
                        "decrypted_xml_detected",
                        {
                            "algorithm": payload.get("algorithm", "unknown"),
                            "size": len(data),
                        },
                        success=True,
                    )

        except Exception as e:
            logger.debug(f"Failed to analyze decrypted data: {e}")

    def create_selective_instrumentation(self, target_apis: list[str], analysis_requirements: dict[str, Any]) -> str:
        """Create selective instrumentation based on analysis requirements."""
        script_parts = []

        # Header
        script_parts.append("// Selective Instrumentation Script")
        script_parts.append("// Generated by Intellicrack Frida Manager")
        script_parts.append("")

        # Determine what to instrument based on requirements
        if analysis_requirements.get("trace_api_calls"):
            for api in target_apis:
                if "!" in api:
                    module, func = api.split("!")
                else:
                    module, func = "unknown", api

                # Determine hook priority
                priority = HookCategory.MEDIUM
                if "critical" in analysis_requirements.get("critical_apis", []):
                    if api in analysis_requirements["critical_apis"]:
                        priority = HookCategory.CRITICAL

                # Check if we should hook based on performance
                if self.optimizer.should_hook_function(module, func, priority):
                    hook_code = self._generate_hook_code(module, func, priority)
                    script_parts.append(hook_code)

        if analysis_requirements.get("monitor_memory"):
            script_parts.append(self._generate_memory_monitoring_code())

        if analysis_requirements.get("detect_protections"):
            script_parts.append(self._generate_protection_detection_code())

        return "\n".join(script_parts)

    def _generate_hook_code(self, module: str, function: str, priority: HookCategory) -> str:
        """Generate optimized hook code."""
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
        """Generate memory monitoring code."""
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
        """Generate protection detection code."""
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

    def get_statistics(self) -> dict[str, Any]:
        """Get comprehensive statistics."""
        stats = {
            "logger": self.logger.get_statistics(),
            "detector": self.detector.get_detected_protections(),
            "batcher": self.batcher.get_batch_stats(),
            "optimizer": {
                "current_usage": self.optimizer.get_current_usage(),
                "recommendations": self.optimizer.get_optimization_recommendations(),
            },
            "sessions": len(self.sessions),
            "scripts": len(self.scripts),
        }

        return stats

    def export_analysis(self, output_path: str = None) -> str:
        """Export complete analysis results including script outputs."""
        # Export logs
        log_dir = self.logger.export_logs(output_path)

        # Create frida_results directory for script outputs
        frida_results_dir = Path(log_dir) / "frida_results"
        frida_results_dir.mkdir(exist_ok=True)

        # Export all script outputs
        for script_name, outputs in self.script_outputs.items():
            if outputs:
                script_dir = frida_results_dir / script_name.replace(".js", "")
                script_dir.mkdir(exist_ok=True)

                for idx, output in enumerate(outputs):
                    output_file = script_dir / f"output_{idx:04d}.json"
                    with open(output_file, "w") as f:
                        json.dump(output, f, indent=2)

        # Add analysis summary
        summary = {
            "analysis_time": datetime.now().isoformat(),
            "statistics": self.get_statistics(),
            "detected_protections": self.detector.get_detected_protections(),
            "bypass_attempts": {
                "total": self.logger.stats["bypasses_attempted"],
                "successful": self.logger.stats["bypasses_successful"],
                "success_rate": self.logger.stats.get("bypass_success_rate", 0),
            },
            "script_outputs": {script_name: len(outputs) for script_name, outputs in self.script_outputs.items()},
        }

        summary_file = Path(log_dir) / "analysis_summary.json"
        with open(summary_file, "w") as f:
            json.dump(summary, f, indent=2)

        return log_dir

    def save_script_output(self, script_name: str, output: dict):
        """Save script output for persistence.

        Args:
            script_name: Name of the script
            output: Output data to save
        """
        if script_name not in self.script_outputs:
            self.script_outputs[script_name] = []

        # Add timestamp to output
        output_with_metadata = {
            "timestamp": datetime.now().isoformat(),
            "script_name": script_name,
            "pid": output.get("pid", None),
            "process_name": output.get("process_name", None),
            "data": output,
        }

        self.script_outputs[script_name].append(output_with_metadata)

        # Also save to disk immediately for persistence
        project_dir = Path(self.logger.log_dir).parent
        frida_results_dir = project_dir / "frida_results"
        frida_results_dir.mkdir(exist_ok=True)

        script_dir = frida_results_dir / script_name.replace(".js", "")
        script_dir.mkdir(exist_ok=True)

        # Generate timestamp filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
        output_file = script_dir / f"{timestamp}.json"

        with open(output_file, "w") as f:
            json.dump(output_with_metadata, f, indent=2)

    def load_previous_results(self, script_name: str) -> List[Dict]:
        """Load previous results for a given script.

        Args:
            script_name: Name of the script

        Returns:
            List of previous results sorted by timestamp
        """
        project_dir = Path(self.logger.log_dir).parent
        frida_results_dir = project_dir / "frida_results"
        script_dir = frida_results_dir / script_name.replace(".js", "")

        if not script_dir.exists():
            return []

        results = []
        for result_file in script_dir.glob("*.json"):
            try:
                with open(result_file, "r") as f:
                    result = json.load(f)
                    results.append(result)
            except Exception as e:
                logger.warning(f"Failed to load result file {result_file}: {e}")

        # Sort by timestamp
        results.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

        return results

    def cleanup(self):
        """Clean up resources."""
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

    def _handle_structured_message(self, session_id: str, script_name: str, payload: dict[str, Any]):
        """Handle structured messages from updated Frida scripts."""
        msg_type = payload.get("type")
        target = payload.get("target", script_name)
        action = payload.get("action", "unknown")

        # Route message based on type
        if msg_type == "info":
            self._handle_info_message(session_id, script_name, payload)
        elif msg_type == "warning":
            self._handle_warning_message(session_id, script_name, payload)
        elif msg_type == "error":
            self._handle_error_message(session_id, script_name, payload)
        elif msg_type == "status":
            self._handle_status_message(session_id, script_name, payload)
        elif msg_type == "bypass":
            self._handle_bypass_message(session_id, script_name, payload)
        elif msg_type == "success":
            self._handle_success_message(session_id, script_name, payload)
        elif msg_type == "detection":
            self._handle_detection_message(session_id, script_name, payload)
        elif msg_type == "notification":
            self._handle_notification_message(session_id, script_name, payload)

        # Always log structured message for debugging
        self.logger.log_operation(
            f"structured_{msg_type}:{script_name}",
            {
                "session_id": session_id,
                "target": target,
                "action": action,
                "payload": payload,
            },
            success=True,
        )

    def _handle_info_message(self, session_id: str, script_name: str, payload: dict[str, Any]):
        """Handle informational messages."""
        target = payload.get("target", script_name)
        action = payload.get("action", "info")

        # Log as informational operation
        self.logger.log_operation(
            f"info:{target}",
            {
                "session_id": session_id,
                "action": action,
                "details": {k: v for k, v in payload.items() if k not in ["type", "target", "action"]},
            },
            success=True,
        )

        # Call UI callback if available
        if hasattr(self, "_ui_message_callback") and self._ui_message_callback:
            self._ui_message_callback("info", session_id, script_name, payload)

    def _handle_warning_message(self, session_id: str, script_name: str, payload: dict[str, Any]):
        """Handle warning messages."""
        target = payload.get("target", script_name)
        action = payload.get("action", "warning")

        # Log as warning
        logger.warning(f"[{target}] {action}: {payload}")

        self.logger.log_operation(
            f"warning:{target}",
            {
                "session_id": session_id,
                "action": action,
                "details": {k: v for k, v in payload.items() if k not in ["type", "target", "action"]},
            },
            success=True,
        )

        # Call UI callback if available
        if hasattr(self, "_ui_message_callback") and self._ui_message_callback:
            self._ui_message_callback("warning", session_id, script_name, payload)

    def _handle_error_message(self, session_id: str, script_name: str, payload: dict[str, Any]):
        """Handle error messages."""
        target = payload.get("target", script_name)
        action = payload.get("action", "error")
        error_details = payload.get("error", "Unknown error")

        # Log as error
        logger.error(f"[{target}] {action}: {error_details}")

        self.logger.log_operation(
            f"error:{target}",
            {
                "session_id": session_id,
                "action": action,
                "error": error_details,
                "details": {k: v for k, v in payload.items() if k not in ["type", "target", "action", "error"]},
            },
            success=False,
            error=str(error_details),
        )

        # Call UI callback if available
        if hasattr(self, "_ui_message_callback") and self._ui_message_callback:
            self._ui_message_callback("error", session_id, script_name, payload)

    def _handle_status_message(self, session_id: str, script_name: str, payload: dict[str, Any]):
        """Handle status messages."""
        target = payload.get("target", script_name)
        action = payload.get("action", "status")
        status = payload.get("status", "unknown")

        # Log as status update
        self.logger.log_operation(
            f"status:{target}",
            {
                "session_id": session_id,
                "action": action,
                "status": status,
                "details": {k: v for k, v in payload.items() if k not in ["type", "target", "action", "status"]},
            },
            success=True,
        )

        # Call UI callback if available
        if hasattr(self, "_ui_message_callback") and self._ui_message_callback:
            self._ui_message_callback("status", session_id, script_name, payload)

    def _handle_bypass_message(self, session_id: str, script_name: str, payload: dict[str, Any]):
        """Handle bypass attempt messages."""
        target = payload.get("target", script_name)
        action = payload.get("action", "bypass_attempt")
        technique = payload.get("technique", action)
        success = payload.get("success", True)

        # Determine protection type from target or action
        protection_type = self._infer_protection_type(target, action, payload)

        # Log bypass attempt
        self.logger.log_bypass_attempt(
            protection_type,
            technique,
            success,
            {
                "session_id": session_id,
                "target": target,
                "action": action,
                "details": {k: v for k, v in payload.items() if k not in ["type", "target", "action", "technique", "success"]},
            },
        )

        # Notify protection detector if bypass was successful
        if success:
            self.detector.notify_protection_detected(
                protection_type,
                {
                    "evidence": f"Bypass successful: {technique}",
                    "script": script_name,
                    "session": session_id,
                    "details": payload,
                },
            )

        # Call UI callback if available
        if hasattr(self, "_ui_message_callback") and self._ui_message_callback:
            self._ui_message_callback("bypass", session_id, script_name, payload)

    def _handle_success_message(self, session_id: str, script_name: str, payload: dict[str, Any]):
        """Handle success messages."""
        target = payload.get("target", script_name)
        action = payload.get("action", "success")

        # Log as successful operation
        self.logger.log_operation(
            f"success:{target}",
            {
                "session_id": session_id,
                "action": action,
                "details": {k: v for k, v in payload.items() if k not in ["type", "target", "action"]},
            },
            success=True,
        )

        # Call UI callback if available
        if hasattr(self, "_ui_message_callback") and self._ui_message_callback:
            self._ui_message_callback("success", session_id, script_name, payload)

    def _handle_detection_message(self, session_id: str, script_name: str, payload: dict[str, Any]):
        """Handle detection messages."""
        target = payload.get("target", script_name)
        action = payload.get("action", "detection")
        detected_item = payload.get("detected", "unknown")

        # Determine protection type from detection
        protection_type = self._infer_protection_type(target, action, payload)

        # Log detection
        self.logger.log_operation(
            f"detection:{target}",
            {
                "session_id": session_id,
                "action": action,
                "detected": detected_item,
                "details": {k: v for k, v in payload.items() if k not in ["type", "target", "action", "detected"]},
            },
            success=True,
        )

        # Notify protection detector
        self.detector.notify_protection_detected(
            protection_type,
            {
                "evidence": f"Detection: {detected_item}",
                "script": script_name,
                "session": session_id,
                "details": payload,
            },
        )

        # Call UI callback if available
        if hasattr(self, "_ui_message_callback") and self._ui_message_callback:
            self._ui_message_callback("detection", session_id, script_name, payload)

    def _handle_notification_message(self, session_id: str, script_name: str, payload: dict[str, Any]):
        """Handle notification messages."""
        target = payload.get("target", script_name)
        action = payload.get("action", "notification")

        # Log as notification
        self.logger.log_operation(
            f"notification:{target}",
            {
                "session_id": session_id,
                "action": action,
                "details": {k: v for k, v in payload.items() if k not in ["type", "target", "action"]},
            },
            success=True,
        )

        # Call UI callback if available
        if hasattr(self, "_ui_message_callback") and self._ui_message_callback:
            self._ui_message_callback("notification", session_id, script_name, payload)

    def _infer_protection_type(self, target: str, action: str, payload: dict[str, Any]) -> ProtectionType:
        """Infer protection type from message context."""
        # Check target module name for protection type hints
        target_lower = target.lower()
        action_lower = action.lower()

        # Map common targets to protection types
        if "debug" in target_lower or "debug" in action_lower:
            return ProtectionType.ANTI_DEBUG
        if "vm" in target_lower or "virtual" in target_lower:
            return ProtectionType.ANTI_VM
        if "license" in target_lower or "license" in action_lower:
            return ProtectionType.LICENSE
        if "integrity" in target_lower or "checksum" in action_lower:
            return ProtectionType.INTEGRITY
        if "hardware" in target_lower or "hwid" in action_lower:
            return ProtectionType.HARDWARE
        if "cloud" in target_lower or "server" in action_lower:
            return ProtectionType.CLOUD
        if "time" in target_lower or "time" in action_lower:
            return ProtectionType.TIME
        if "memory" in target_lower or "memory" in action_lower:
            return ProtectionType.MEMORY
        if "kernel" in target_lower or "kernel" in action_lower:
            return ProtectionType.KERNEL
        # Check payload for additional hints
        payload_str = str(payload).lower()
        if "license" in payload_str:
            return ProtectionType.LICENSE
        if "debug" in payload_str:
            return ProtectionType.ANTI_DEBUG
        return ProtectionType.UNKNOWN


# Export main components
__all__ = [
    "FridaManager",
    "FridaOperationLogger",
    "FridaPerformanceOptimizer",
    "HookBatcher",
    "HookCategory",
    "ProtectionDetector",
    "ProtectionType",
]
