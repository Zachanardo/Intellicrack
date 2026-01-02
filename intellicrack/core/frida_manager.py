"""Frida manager for Intellicrack core functionality.

This file is part of Intellicrack.
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
from collections.abc import Callable, Generator
from datetime import datetime
from pathlib import Path
from typing import Any

from ..utils.core.import_checks import FRIDA_AVAILABLE, frida, psutil
from ..utils.logger import log_all_methods
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


@log_all_methods
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

    def __init__(self, log_dir: str | None = None) -> None:
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
        self.operation_buffer: deque[dict[str, Any]] = deque(maxlen=10000)
        self.hook_buffer: deque[dict[str, Any]] = deque(maxlen=50000)
        self.performance_metrics: dict[str, list[float]] = defaultdict(list)

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

    def _init_loggers(self) -> None:
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

        Side Effects:
            Sets up four file handlers for operation, hook, performance, and bypass logging.
        """
        # Operation logger
        self.op_logger = logging.getLogger("frida.operations")
        op_handler = logging.FileHandler(self.operation_log)
        op_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s - %(levelname)s - %(message)s",
            ),
        )
        self.op_logger.addHandler(op_handler)
        self.op_logger.setLevel(logging.DEBUG)

        # Hook logger
        self.hook_logger = logging.getLogger("frida.hooks")
        hook_handler = logging.FileHandler(self.hook_log)
        hook_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s - %(message)s",
            ),
        )
        self.hook_logger.addHandler(hook_handler)
        self.hook_logger.setLevel(logging.DEBUG)

        # Performance logger
        self.perf_logger = logging.getLogger("frida.performance")
        perf_handler = logging.FileHandler(self.performance_log)
        perf_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s - %(message)s",
            ),
        )
        self.perf_logger.addHandler(perf_handler)
        self.perf_logger.setLevel(logging.INFO)

        # Bypass logger
        self.bypass_logger = logging.getLogger("frida.bypasses")
        bypass_handler = logging.FileHandler(self.bypass_log)
        bypass_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s - %(levelname)s - %(message)s",
            ),
        )
        self.bypass_logger.addHandler(bypass_handler)
        self.bypass_logger.setLevel(logging.INFO)

    def log_operation(self, operation: str, details: dict[str, Any], success: bool = True, error: str | None = None) -> None:
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
        self.op_logger.debug("Details: %s", json.dumps(details, default=str))

    def log_hook(
        self,
        function_name: str,
        module: str,
        arguments: list[Any],
        return_value: bytes | bytearray | None = None,
        modified: bool = False,
    ) -> None:
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

    def log_performance(self, metric_name: str, value: float, unit: str = "ms", metadata: dict[str, Any] | None = None) -> None:
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
        details: dict[str, Any] | None = None,
    ) -> None:
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
            self.bypass_logger.debug("Details: %s", json.dumps(details, default=str))

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

    def export_logs(self, output_dir: str | None = None) -> str:
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

    def error(self, message: str) -> None:
        """Log error message using operation logger.

        Records an error message through both the structured operation logging
        system and the standard error logger for visibility.

        Args:
            message: Error message to log.

        Side Effects:
            - Calls log_operation with error classification
            - Writes to operation logger at ERROR level
        """
        self.log_operation("error", {"message": message, "level": "error"})
        self.op_logger.error(message)


@log_all_methods
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

    def __init__(self) -> None:
        """Initialize the protection detector.

        Sets up signature database and prepares detection system.

        Side Effects:
            - Loads protection signatures
            - Initializes empty detection maps
            - Prepares adaptation callback list
        """
        self.detected_protections: dict[ProtectionType, set[str]] = defaultdict(set)
        self.protection_signatures = self._load_signatures()
        self.adaptation_callbacks: list[Callable[[ProtectionType, dict[str, Any] | set[str]], None]] = []

    def _load_signatures(self) -> dict[ProtectionType, list[dict[str, Any]]]:
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
                    if function.lower() in {
                        "virtualprotect",
                        "ntprotectvirtualmemory",
                    } and arg in [
                        0x40,
                        0x20,
                        0x04,
                    ]:
                        detected.add(ProtectionType.MEMORY_PROTECTION)
                        self.detected_protections[ProtectionType.MEMORY_PROTECTION].add(f"Memory protection flag: {hex(int(arg))}")

        return detected

    def analyze_string(self, string_data: str) -> set[ProtectionType]:
        """Analyze strings for protection indicators.

        Searches input strings for patterns that match known protection
        techniques. Supports both case-sensitive and case-insensitive matching
        based on signature configuration.

        Args:
            string_data: String to analyze for protection indicators.

        Returns:
            Set of detected ProtectionType enums matching string patterns.

        Side Effects:
            - Updates detected_protections with matched string patterns
            - Records evidence for each detected protection type
        """
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

    def register_adaptation_callback(self, callback: Callable[[ProtectionType, dict[str, Any] | set[str]], None]) -> None:
        """Register callback for protection detection events.

        Registers a callback function that will be invoked when a new protection
        mechanism is detected, enabling real-time adaptation of bypass strategies.

        Args:
            callback: Function to call with signature (ProtectionType, dict/set).

        Side Effects:
            - Appends callback to adaptation_callbacks list
            - Callback will be invoked by notify_protection_detected()
        """
        self.adaptation_callbacks.append(callback)

    def notify_protection_detected(self, protection_type: ProtectionType, details: dict[str, Any]) -> None:
        """Notify registered callbacks of detected protection.

        Invokes all registered adaptation callbacks with the detected protection
        type and evidence details. Continues operation if individual callbacks fail.

        Args:
            protection_type: Type of protection detected.
            details: Dictionary containing evidence and context for the detection.

        Side Effects:
            - Calls each callback in adaptation_callbacks
            - Logs exceptions from callbacks without raising
        """
        for callback in self.adaptation_callbacks:
            try:
                callback(protection_type, details)
            except Exception as e:
                logger.exception("Adaptation callback error: %s", e)

    def get_detected_protections(self) -> dict[str, list[str]]:
        """Get all detected protections with evidence.

        Returns a summary of all detected protection mechanisms along with
        the specific evidence (API calls, strings, etc.) that triggered each detection.

        Returns:
            Dictionary mapping protection type names (strings) to lists of evidence strings.

        Example:
            {
                'ANTI_DEBUG': ['kernel32.dll!IsDebuggerPresent'],
                'LICENSE': ['license', 'api.example.com']
            }
        """
        return {prot_type.value: list(evidence) for prot_type, evidence in self.detected_protections.items()}


@log_all_methods
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

    def __init__(self, max_batch_size: int = 50, batch_timeout_ms: int = 100) -> None:
        """Initialize the hook batcher.

        Args:
            max_batch_size: Maximum number of hooks to batch together.
            batch_timeout_ms: Default timeout in milliseconds for batching.

        Side Effects:
            - Initializes thread-safe queue
            - Prepares for background thread

        """
        self.logger = logging.getLogger(f"{__name__}.HookBatcher")
        self.max_batch_size = max_batch_size
        self.batch_timeout_ms = batch_timeout_ms
        self.pending_hooks: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.hook_queue: queue.Queue[dict[str, Any]] = queue.Queue()
        self.batch_thread: threading.Thread | None = None
        self.running = False

    def add_hook(self, category: HookCategory, hook_spec: dict[str, Any]) -> None:
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

    def start_batching(self) -> None:
        """Start the batching thread.

        Starts a background daemon thread that processes hooks from the queue
        in batches according to configured size and timeout limits.

        Side Effects:
            - Sets running flag to True
            - Creates and starts batch processing thread
            - Thread processes queue until stop_batching() is called
        """
        self.running = True
        self.batch_thread = threading.Thread(target=self._batch_processor)
        self.batch_thread.daemon = True
        self.batch_thread.start()

    def stop_batching(self) -> None:
        """Stop the batching thread.

        Gracefully stops the background batch processing thread and waits for
        it to complete its current operation.

        Side Effects:
            - Sets running flag to False
            - Joins batch_thread if it exists
            - Blocks until thread exits
        """
        self.running = False
        if self.batch_thread:
            self.batch_thread.join()

    def _batch_processor(self) -> Generator[tuple[str, list[dict[str, Any]]], None, None]:
        """Process hooks in batches.

        Generator that continuously collects hooks from the queue and yields
        them in batches, grouped by module for efficient installation.

        Yields:
            Tuples of (module_name, list of hook specifications for that module).

        Complexity:
            Time: O(n log n) per batch due to sorting
            Space: O(b) where b is max_batch_size
        """
        while self.running:
            batch: list[dict[str, Any]] = []
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
                batch.sort(key=lambda h: h["category"].value)

                # Group by module for efficiency
                module_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
                for hook in batch:
                    module_groups[hook.get("module", "unknown")].append(hook)

                # Return batched hooks
                yield from module_groups.items()

    def get_batch_stats(self) -> dict[str, Any]:
        """Get batching statistics.

        Returns current statistics about the hook batching system including
        pending hooks and their distribution by priority category.

        Returns:
            Dictionary containing:
            - pending_hooks: Number of hooks waiting in queue
            - categories: Dict mapping category names to counts
        """
        return {
            "pending_hooks": self.hook_queue.qsize(),
            "categories": {cat.name: sum(h.get("category") == cat for h in list(self.hook_queue.queue)) for cat in HookCategory},
        }


@log_all_methods
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

    def __init__(self) -> None:
        """Initialize the performance optimizer.

        Side Effects:
            - Creates psutil Process object
            - Initializes performance tracking structures

        Raises:
            ImportError: If psutil module is not available.
        """
        if psutil is None:
            raise ImportError("psutil is not available")
        self.process = psutil.Process()
        self.baseline_memory = 0
        self.baseline_cpu = 0
        self.optimization_enabled = True
        self.selective_hooks: dict[str, dict[str, Any]] = {}
        self.hook_cache: dict[str, str] = {}
        self.performance_history: deque[dict[str, float]] = deque(maxlen=100)

    def measure_baseline(self) -> None:
        """Measure baseline resource usage.

        Records the current memory and CPU usage as a baseline for comparison
        with later measurements to determine resource overhead.

        Side Effects:
            - Sets baseline_memory to current RSS memory usage
            - Sets baseline_cpu to current CPU percentage
        """
        self.baseline_memory = self.process.memory_info().rss
        self.baseline_cpu = self.process.cpu_percent(interval=0.1)

    def get_current_usage(self) -> dict[str, float]:
        """Get current resource usage.

        Retrieves current resource utilization including memory, CPU, and
        file handle counts relative to the baseline measurements.

        Returns:
            Dictionary containing:
            - memory_mb: Memory usage in MB relative to baseline
            - cpu_percent: Current CPU percentage
            - threads: Number of active threads
            - handles: Number of open file handles
        """
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
        """Optimize Frida script for performance.

        Enhances provided Frida script with built-in caching and batching
        mechanisms to reduce overhead. Injects helper functions for efficient
        value caching and batched message sending.

        Args:
            script_code: Original Frida JavaScript script code.

        Returns:
            Enhanced script with optimization code prepended.

        Note:
            The optimization adds:
            - 1-second caching for function results
            - 50ms batching for send() messages
        """
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
        optimizations = [cache_code, batch_code]
        # Combine optimizations with original script
        return "\n".join(optimizations) + "\n" + script_code

    def track_hook_performance(self, module: str, function: str, execution_time: float) -> None:
        """Track individual hook performance.

        Records performance metrics for a specific hooked function including
        execution time and call rate. Updates call rates every second.

        Args:
            module: Module containing the hooked function.
            function: Name of the hooked function.
            execution_time: Execution time in milliseconds.

        Side Effects:
            - Creates entry in selective_hooks if new
            - Updates total_time and call_count
            - Recalculates call_rate every second
        """
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
        """Get recommendations for optimization.

        Analyzes current resource usage and hook performance to provide
        specific optimization recommendations for reducing overhead.

        Returns:
            List of recommendation strings for resource optimization.

        Example:
            ['High memory usage detected. Consider reducing hook scope...']
        """
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

        if hot_functions := [(k, v) for k, v in self.selective_hooks.items() if v.get("call_rate", 0) > 5000]:
            recommendations.append(
                f"Found {len(hot_functions)} frequently called functions. Consider optimizing or selectively hooking these.",
            )

        return recommendations


@log_all_methods
class DynamicScriptGenerator:
    """Dynamic Frida script generation based on target analysis.

    Generates customized Frida scripts in real-time based on:
    - Binary analysis results
    - Detected protection mechanisms
    - Runtime behavior patterns
    - Target architecture specifics
    - Historical bypass success rates

    Features:
    - Real-time script generation
    - Adaptive hooking strategies
    - Anti-detection techniques
    - Script obfuscation
    - Performance optimization
    """

    def __init__(self) -> None:
        """Initialize the dynamic script generator.

        Sets up script generation system with protection handlers, hooking
        strategies, and obfuscation engine for adaptive script generation.

        Side Effects:
            - Initializes protection handlers for all protection types
            - Loads hooking strategies (aggressive, stealthy, adaptive, etc.)
            - Configures obfuscation options
            - Creates empty script cache
        """
        self.protection_handlers = self._init_protection_handlers()
        self.hook_strategies = self._init_hook_strategies()
        self.obfuscation_engine = self._init_obfuscation()
        self.script_cache: dict[str, str] = {}
        self.success_metrics: dict[str, float] = defaultdict(float)

    def _init_protection_handlers(self) -> dict[ProtectionType, Callable[[dict[str, Any]], str]]:
        """Initialize protection-specific script generators.

        Creates mapping of protection types to their corresponding script
        generation methods for producing targeted bypass code.

        Returns:
            Dictionary mapping ProtectionType to script generator callables.

        Note:
            Each callable takes target_info dict and returns Frida script code.
        """
        return {
            ProtectionType.ANTI_DEBUG: self._gen_antidebug_script,
            ProtectionType.ANTI_VM: self._gen_antivm_script,
            ProtectionType.LICENSE: self._gen_license_script,
            ProtectionType.INTEGRITY: self._gen_integrity_script,
            ProtectionType.HARDWARE: self._gen_hardware_script,
            ProtectionType.CLOUD: self._gen_cloud_script,
            ProtectionType.TIME: self._gen_time_script,
            ProtectionType.MEMORY: self._gen_memory_script,
            ProtectionType.KERNEL: self._gen_kernel_script,
        }

    def _init_hook_strategies(self) -> dict[str, Callable[[dict[str, Any]], str]]:
        """Initialize adaptive hooking strategies.

        Creates mapping of strategy names to their corresponding hook
        generation methods for different attack approaches.

        Returns:
            Dictionary mapping strategy names to hook generator callables.

        Note:
            Available strategies: aggressive, stealthy, adaptive, minimal, comprehensive.
        """
        return {
            "aggressive": self._aggressive_hooks,
            "stealthy": self._stealthy_hooks,
            "adaptive": self._adaptive_hooks,
            "minimal": self._minimal_hooks,
            "comprehensive": self._comprehensive_hooks,
        }

    def _init_obfuscation(self) -> dict[str, bool]:
        """Initialize script obfuscation engine.

        Sets up obfuscation techniques to be applied to generated scripts
        to evade detection and analysis.

        Returns:
            Dictionary mapping obfuscation technique names to enabled status.

        Note:
            Obfuscation techniques include variable renaming, control flow
            modification, string encoding, dead code injection, and API hiding.
        """
        return {
            "variable_renaming": True,
            "control_flow": True,
            "string_encoding": True,
            "dead_code": True,
            "api_hiding": True,
        }

    def generate_script(
        self,
        target_info: dict[str, Any],
        detected_protections: list[ProtectionType],
        strategy: str = "adaptive",
        obfuscate: bool = True,
    ) -> str:
        """Generate dynamic Frida script based on target analysis.

        Synthesizes a complete Frida script tailored to the target's detected
        protections and specified hooking strategy. Combines base initialization,
        evasion layer, protection-specific bypasses, and strategy-specific hooks.

        Args:
            target_info: Dictionary containing binary analysis results including
                        process info, detected strings, and API calls.
            detected_protections: List of ProtectionType enums for protections
                                 to bypass.
            strategy: Hooking strategy name (aggressive, stealthy, adaptive,
                     minimal, comprehensive). Defaults to adaptive.
            obfuscate: Whether to apply obfuscation to the generated script.

        Returns:
            Complete Frida JavaScript script as a string ready for injection.

        Example:
            script = generator.generate_script(
                target_info={'process': 'app.exe'},
                detected_protections=[ProtectionType.ANTI_DEBUG],
                strategy='stealthy'
            )
        """
        script_parts = [self._generate_base_init()]

        # Add detection evasion
        script_parts.append(self._generate_evasion_layer())

        # Generate protection-specific bypasses
        for protection in detected_protections:
            if protection in self.protection_handlers:
                handler = self.protection_handlers[protection]
                script_parts.append(handler(target_info))

        # Apply hooking strategy
        if strategy in self.hook_strategies:
            strategy_handler = self.hook_strategies[strategy]
            script_parts.append(strategy_handler(target_info))

        # Add runtime adaptation
        script_parts.append(self._generate_runtime_adaptation())

        # Combine all parts
        script = "\n\n".join(script_parts)

        # Apply obfuscation if requested
        if obfuscate:
            script = self._obfuscate_script(script)

        return script

    def _generate_base_init(self) -> str:
        """Generate base initialization code.

        Creates the foundational Frida script code that establishes the global
        instrumentation context, API resolvers, and utility functions for all
        subsequent hooks and bypass code.

        Returns:
            Frida JavaScript code string containing:
            - Global context object (_IC) for tracking hooks and statistics
            - API resolver with caching for efficient function address resolution
            - Memory scanning utilities for pattern-based analysis
            - Dynamic hook installation wrapper with error recovery
        """
        return (
            """
// Dynamic Frida Script - Generated by Intellicrack
// Timestamp: """
            + str(datetime.now())
            + """

const _IC = {
    hooks: new Map(),
    bypasses: new Map(),
    stats: {calls: 0, bypassed: 0, failures: 0},
    config: {adaptive: true, stealth: true, aggressive: false}
};

// Enhanced API resolution with caching
const resolver = new ApiResolver('module');
const moduleCache = new Map();
const addressCache = new Map();

function resolveFunction(module, func) {
    const key = `${module}!${func}`;
    if (addressCache.has(key)) return addressCache.get(key);

    try {
        const matches = resolver.enumerateMatches(`exports:${module}!${func}`);
        if (matches.length > 0) {
            addressCache.set(key, matches[0].address);
            return matches[0].address;
        }
    } catch (e) {}

    try {
        const mod = Process.findModuleByName(module);
        if (mod) {
            const exp = mod.findExportByName(func);
            if (exp) {
                addressCache.set(key, exp);
                return exp;
            }
        }
    } catch (e) {}

    return null;
}

// Memory scanning with pattern matching
function scanMemory(pattern, protection = 'r--') {
    const results = [];
    Process.enumerateRanges(protection).forEach(range => {
        try {
            const matches = Memory.scanSync(range.base, range.size, pattern);
            results.push(...matches);
        } catch (e) {}
    });
    return results;
}

// Dynamic hook installation with error recovery
function installHook(target, handler, options = {}) {
    try {
        const hook = Interceptor.attach(target, {
            onEnter: function(args) {
                try {
                    _IC.stats.calls++;
                    if (handler.onEnter) {
                        handler.onEnter.call(this, args);
                    }
                } catch (e) {
                    _IC.stats.failures++;
                }
            },
            onLeave: function(retval) {
                try {
                    if (handler.onLeave) {
                        handler.onLeave.call(this, retval);
                    }
                } catch (e) {
                    _IC.stats.failures++;
                }
            }
        });
        _IC.hooks.set(target.toString(), hook);
        return hook;
    } catch (e) {
        console.error('Hook installation failed:', e);
        return null;
    }
}
"""
        )

    def _generate_evasion_layer(self) -> str:
        """Generate anti-detection evasion code.

        Creates JavaScript code that masks Frida's presence and defeats common
        anti-analysis techniques including object enumeration, timing attacks,
        thread detection, module filtering, and exception handler checks.

        Returns:
            Frida JavaScript evasion layer code string containing:
            - Object property filtering to hide Frida internals
            - Timing attack mitigation with jitter injection
            - Thread ID masking for detection evasion
            - Module enumeration filtering
            - Exception handler bypass for debug register access
        """
        return """
// Anti-detection evasion layer
(() => {
    // Hide Frida presence
    const originalGetOwnPropertyNames = Object.getOwnPropertyNames;
    Object.getOwnPropertyNames = function(obj) {
        const props = originalGetOwnPropertyNames.call(this, obj);
        return props.filter(prop => !prop.includes('frida') && !prop.includes('_IC'));
    };

    // Timing attack mitigation
    const timingOffsets = new Map();
    const originalDate = Date;
    const originalPerf = typeof performance !== 'undefined' ? performance : null;

    if (originalPerf) {
        const originalNow = originalPerf.now.bind(originalPerf);
        let lastTime = originalNow();
        let timeOffset = 0;

        originalPerf.now = function() {
            const realTime = originalNow();
            const elapsed = realTime - lastTime;

            // Detect timing checks
            if (elapsed < 1) {
                timeOffset += Math.random() * 0.5;
            }

            lastTime = realTime;
            return realTime - timeOffset;
        };
    }

    // Thread detection bypass
    const originalThreadId = Process.getCurrentThreadId;
    Process.getCurrentThreadId = function() {
        const id = originalThreadId();
        // Mask Frida's thread IDs
        return id & 0xFFFFF000;
    };

    // Module enumeration filtering
    const originalEnumModules = Process.enumerateModules;
    Process.enumerateModules = function() {
        const modules = originalEnumModules();
        return modules.filter(m =>
            !m.name.toLowerCase().includes('frida') &&
            !m.name.toLowerCase().includes('gadget')
        );
    };

    // Exception handler bypass
    Process.setExceptionHandler((details) => {
        // Check if exception is related to detection
        if (details.type === 'access-violation') {
            const addr = details.memory?.address;
            if (addr) {
                // Check if accessing debug registers
                const pc = details.context.pc;
                const inst = Instruction.parse(pc);
                if (inst && inst.mnemonic && inst.mnemonic.startsWith('dr')) {
                    // Skip debug register access
                    details.context.pc = ptr(details.context.pc).add(inst.size);
                    return true;
                }
            }
        }
        return false;
    });
})();
"""

    def _gen_antidebug_script(self, target_info: dict[str, Any]) -> str:
        """Generate anti-debug bypass script.

        Creates Frida hooks to bypass anti-debugging protections by intercepting
        common detection APIs and returning false/zero values to indicate no
        debugger presence.

        Args:
            target_info: Dictionary containing target process information for
                        customization.

        Returns:
            Frida JavaScript code for anti-debug bypass implementation.

        Note:
            Hooks target APIs including IsDebuggerPresent, CheckRemoteDebuggerPresent,
            NtQueryInformationProcess, and OutputDebugString.
        """
        return """
// Anti-debug bypass implementation
(() => {
    // IsDebuggerPresent bypass
    const isDebuggerPresent = resolveFunction('kernel32.dll', 'IsDebuggerPresent');
    if (isDebuggerPresent) {
        installHook(isDebuggerPresent, {
            onLeave: function(retval) {
                retval.replace(0);
                _IC.stats.bypassed++;
            }
        });
    }

    // CheckRemoteDebuggerPresent bypass
    const checkRemoteDebugger = resolveFunction('kernel32.dll', 'CheckRemoteDebuggerPresent');
    if (checkRemoteDebugger) {
        installHook(checkRemoteDebugger, {
            onLeave: function(retval) {
                if (this.context.rsp) {
                    Memory.writeU8(ptr(this.context.rsp).add(Process.pointerSize), 0);
                }
                retval.replace(1);
                _IC.stats.bypassed++;
            }
        });
    }

    // NtQueryInformationProcess bypass
    const ntQueryInfo = resolveFunction('ntdll.dll', 'NtQueryInformationProcess');
    if (ntQueryInfo) {
        installHook(ntQueryInfo, {
            onEnter: function(args) {
                this.infoClass = args[1].toInt32();
                this.buffer = args[2];
            },
            onLeave: function(retval) {
                if (retval.toInt32() === 0) {
                    switch(this.infoClass) {
                        case 7:  // ProcessDebugPort
                            Memory.writePointer(this.buffer, ptr(0));
                            _IC.stats.bypassed++;
                            break;
                        case 30: // ProcessDebugObjectHandle
                            Memory.writePointer(this.buffer, ptr(0));
                            _IC.stats.bypassed++;
                            break;
                        case 31: // ProcessDebugFlags
                            Memory.writeU32(this.buffer, 1);
                            _IC.stats.bypassed++;
                            break;
                    }
                }
            }
        });
    }

    // PEB manipulation
    const peb = Process.enumerateModules()[0].base;
    const pebBeingDebugged = peb.add(2);
    const pebNtGlobalFlag = peb.add(0x68);

    Memory.protect(pebBeingDebugged, 1, 'rw-');
    Memory.writeU8(pebBeingDebugged, 0);

    if (Process.arch === 'x64') {
        Memory.protect(pebNtGlobalFlag, 4, 'rw-');
        Memory.writeU32(pebNtGlobalFlag, 0);
    }

    // Hardware breakpoint detection
    const getThreadContext = resolveFunction('kernel32.dll', 'GetThreadContext');
    if (getThreadContext) {
        installHook(getThreadContext, {
            onLeave: function(retval) {
                if (retval.toInt32() !== 0 && this.context) {
                    // Clear debug registers
                    const ctx = this.context;
                    if (Process.arch === 'x64') {
                        Memory.writeU64(ctx.add(0x18), 0); // Dr0
                        Memory.writeU64(ctx.add(0x20), 0); // Dr1
                        Memory.writeU64(ctx.add(0x28), 0); // Dr2
                        Memory.writeU64(ctx.add(0x30), 0); // Dr3
                        Memory.writeU64(ctx.add(0x38), 0); // Dr6
                        Memory.writeU64(ctx.add(0x40), 0); // Dr7
                    }
                    _IC.stats.bypassed++;
                }
            }
        });
    }
})();
"""

    def _gen_antivm_script(self, target_info: dict[str, Any]) -> str:
        """Generate anti-VM bypass script.

        Creates Frida hooks to spoof VM detection mechanisms including CPUID
        instruction results, CPU vendor strings, and registry keys that indicate
        virtual machine presence.

        Args:
            target_info: Dictionary containing target process information.

        Returns:
            Frida JavaScript code for anti-VM bypass implementation.

        Note:
            Hooks and patches CPUID, registry queries, and system information APIs
            to appear as legitimate hardware without hypervisor indicators.
        """
        return """
// Anti-VM bypass implementation
(() => {
    // CPUID instruction hooking
    const cpuidPatterns = [
        '0F A2',           // CPUID
        '0F 01 D0',        // XGETBV
        '0F 01 C1',        // VMCALL
    ];

    cpuidPatterns.forEach(pattern => {
        const matches = scanMemory(pattern, 'r-x');
        matches.forEach(match => {
            try {
                Interceptor.attach(match.address, {
                    onEnter: function(args) {
                        // Modify CPU vendor string
                        if (this.context.eax === 0) {
                            this.context.ebx = 0x756E6547; // "Genu"
                            this.context.edx = 0x49656E69; // "ineI"
                            this.context.ecx = 0x6C65746E; // "ntel"
                        }
                        // Hypervisor bit
                        else if (this.context.eax === 1) {
                            this.cpuidModify = true;
                        }
                    },
                    onLeave: function(retval) {
                        if (this.cpuidModify) {
                            // Clear hypervisor bit
                            this.context.ecx = this.context.ecx & ~(1 << 31);
                            _IC.stats.bypassed++;
                        }
                    }
                });
            } catch (e) {}
        });
    });

    // Registry value spoofing
    const regQueryValue = resolveFunction('advapi32.dll', 'RegQueryValueExW');
    if (regQueryValue) {
        installHook(regQueryValue, {
            onEnter: function(args) {
                this.valueName = args[1].readUtf16String();
                this.dataBuffer = args[3];
            },
            onLeave: function(retval) {
                if (retval.toInt32() === 0 && this.valueName) {
                    const vmIndicators = ['vbox', 'vmware', 'virtual', 'qemu', 'xen'];
                    const nameL = this.valueName.toLowerCase();

                    if (vmIndicators.some(ind => nameL.includes(ind))) {
                        // Replace with generic values
                        if (this.dataBuffer) {
                            Memory.writeUtf16String(this.dataBuffer, 'Generic Device');
                            _IC.stats.bypassed++;
                        }
                    }
                }
            }
        });
    }

    // WMI query filtering
    const coCreate = resolveFunction('ole32.dll', 'CoCreateInstance');
    if (coCreate) {
        installHook(coCreate, {
            onEnter: function(args) {
                const clsid = args[0].readByteArray(16);
                // Check for WbemLocator CLSID
                const wbemClsid = [0xdc, 0x12, 0xa6, 0x87, 0x73, 0x7f, 0xcf, 0x11,
                                   0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24];
                if (clsid && JSON.stringify(Array.from(new Uint8Array(clsid))) ===
                    JSON.stringify(wbemClsid)) {
                    this.isWMI = true;
                }
            }
        });
    }

    // File system hiding
    const findFirstFile = resolveFunction('kernel32.dll', 'FindFirstFileW');
    if (findFirstFile) {
        installHook(findFirstFile, {
            onEnter: function(args) {
                const path = args[0].readUtf16String();
                if (path && path.toLowerCase().includes('vbox')) {
                    // Redirect to non-existent path
                    args[0] = Memory.allocUtf16String('C:\\\\NonExistent\\\\*');
                    _IC.stats.bypassed++;
                }
            }
        });
    }
})();
"""

    def _gen_license_script(self, target_info: dict[str, Any]) -> str:
        """Generate license validation bypass script.

        Generates Frida instrumentation code that intercepts licensing validation
        APIs including registry-based license checks, file-based license validation,
        and network-based activation verification to analyze protection mechanisms.

        Args:
            target_info: Dictionary containing target process analysis results
                        including process name, architecture, and detected APIs.

        Returns:
            Complete Frida JavaScript code as string for license protection analysis.

        Implementation:
            - Hooks registry operations (RegQueryValueEx, RegGetValue)
            - Intercepts file operations (CreateFile for .lic files)
            - Patches license validation decision points
            - Tracks successful bypass attempts in statistics
        """
        return """
// License bypass implementation
(() => {
    const licensePatterns = new Map();
    const serialValidation = new Map();

    // Registry-based license checks
    const regFuncs = ['RegQueryValueExW', 'RegQueryValueExA', 'RegGetValueW', 'RegGetValueA'];
    regFuncs.forEach(func => {
        const addr = resolveFunction('advapi32.dll', func);
        if (addr) {
            installHook(addr, {
                onEnter: function(args) {
                    const isWide = func.endsWith('W');
                    this.valueName = isWide ? args[1].readUtf16String() : args[1].readCString();
                    this.dataBuffer = args[3];
                    this.dataSize = args[4];
                },
                onLeave: function(retval) {
                    if (retval.toInt32() === 0 && this.valueName) {
                        const keywords = ['license', 'serial', 'key', 'activation', 'registration'];
                        const nameLower = this.valueName.toLowerCase();

                        if (keywords.some(kw => nameLower.includes(kw))) {
                            // Provide valid license data
                            if (this.dataBuffer) {
                                const validLicense = 'INTC-RACK-2025-FULL';
                                Memory.writeUtf16String(this.dataBuffer, validLicense);
                                if (this.dataSize) {
                                    Memory.writeU32(this.dataSize, validLicense.length * 2);
                                }
                                _IC.stats.bypassed++;
                            }
                        }
                    }
                }
            });
        }
    });

    // File-based license checks
    const fileFuncs = ['CreateFileW', 'CreateFileA'];
    fileFuncs.forEach(func => {
        const addr = resolveFunction('kernel32.dll', func);
        if (addr) {
            installHook(addr, {
                onEnter: function(args) {
                    const isWide = func.endsWith('W');
                    const filename = isWide ? args[0].readUtf16String() : args[0].readCString();

                    if (filename) {
                        const nameLower = filename.toLowerCase();
                        if (nameLower.includes('.lic') || nameLower.includes('license')) {
                            // Redirect to valid license file
                            const validPath = Memory.allocUtf16String('C:\\\\Windows\\\\System32\\\\kernel32.dll');
                            args[0] = validPath;
                            this.isLicenseFile = true;
                        }
                    }
                },
                onLeave: function(retval) {
                    if (this.isLicenseFile && retval.toInt32() === -1) {
                        // Create a real handle by duplicating an existing valid handle
                        const kernel32 = Process.getModuleByName('kernel32.dll');
                        const getCurrentProcess = kernel32.getExportByName('GetCurrentProcess');
                        const duplicateHandle = kernel32.getExportByName('DuplicateHandle');
                        const getStdHandle = kernel32.getExportByName('GetStdHandle');

                        // Get a valid handle to duplicate (stdout handle)
                        const STD_OUTPUT_HANDLE = -11;
                        const getStdHandleFunc = new NativeFunction(getStdHandle, 'pointer', ['int']);
                        const stdoutHandle = getStdHandleFunc(STD_OUTPUT_HANDLE);

                        if (stdoutHandle && !stdoutHandle.isNull()) {
                            // Use the stdout handle as a valid handle
                            retval.replace(stdoutHandle);
                        } else {
                            // Get current process pseudo-handle as fallback
                            const getCurrentProcessFunc = new NativeFunction(getCurrentProcess, 'pointer', []);
                            const processHandle = getCurrentProcessFunc();
                            retval.replace(processHandle);
                        }
                        _IC.stats.bypassed++;
                    }
                }
            });
        }
    });

    // Network license validation
    const netFuncs = ['InternetOpenUrlW', 'InternetOpenUrlA', 'HttpOpenRequestW', 'WinHttpOpen'];
    netFuncs.forEach(func => {
        const mod = func.startsWith('Win') ? 'winhttp.dll' : 'wininet.dll';
        const addr = resolveFunction(mod, func);
        if (addr) {
            installHook(addr, {
                onEnter: function(args) {
                    const url = func.endsWith('W') ?
                        (args[1] ? args[1].readUtf16String() : null) :
                        (args[1] ? args[1].readCString() : null);

                    if (url && (url.includes('license') || url.includes('activation'))) {
                        this.isLicenseCheck = true;
                    }
                },
                onLeave: function(retval) {
                    if (this.isLicenseCheck) {
                        // Force success
                        if (retval.toInt32() === 0) {
                            retval.replace(0x1338);
                        }
                        _IC.stats.bypassed++;
                    }
                }
            });
        }
    });

    // Cryptographic validation bypass
    const cryptVerify = resolveFunction('crypt32.dll', 'CryptVerifySignature');
    if (cryptVerify) {
        installHook(cryptVerify, {
            onLeave: function(retval) {
                // Force signature valid
                retval.replace(1);
                _IC.stats.bypassed++;
            }
        });
    }

    // Time-based trial bypass
    const getSystemTime = resolveFunction('kernel32.dll', 'GetSystemTime');
    if (getSystemTime) {
        installHook(getSystemTime, {
            onEnter: function(args) {
                this.timeStruct = args[0];
            },
            onLeave: function(retval) {
                if (this.timeStruct) {
                    // Set to year 2020 for trial reset
                    Memory.writeU16(this.timeStruct, 2020);
                    Memory.writeU16(this.timeStruct.add(2), 1);  // January
                    Memory.writeU16(this.timeStruct.add(6), 1);  // Day 1
                    _IC.stats.bypassed++;
                }
            }
        });
    }
})();
"""

    def _gen_integrity_script(self, target_info: dict[str, Any]) -> str:
        """Generate integrity check bypass script.

        Generates Frida code that intercepts code integrity verification APIs
        including hash computation, checksum validation, and signature verification
        to analyze protection against unauthorized code modification.

        Args:
            target_info: Dictionary containing target process analysis results.

        Returns:
            Complete Frida JavaScript code for integrity check analysis.

        Implementation:
            - Hooks cryptographic hash functions (CryptHashData)
            - Intercepts file validation (MapFileAndCheckSum)
            - Patches integrity check decision points
            - Provides valid checksums for modified code
        """
        return """
// Integrity check bypass implementation
(() => {
    const checksumCache = new Map();
    const hashCache = new Map();

    // CRC/Checksum bypass
    const mapFileChecksum = resolveFunction('imagehlp.dll', 'MapFileAndCheckSumW');
    if (mapFileChecksum) {
        installHook(mapFileChecksum, {
            onEnter: function(args) {
                this.filename = args[0].readUtf16String();
                this.headerSum = args[1];
                this.checkSum = args[2];
            },
            onLeave: function(retval) {
                if (retval.toInt32() === 0 && this.checkSum) {
                    // Provide expected checksum
                    const expectedSum = checksumCache.get(this.filename) || 0x12345678;
                    Memory.writeU32(this.checkSum, expectedSum);
                    if (this.headerSum) {
                        Memory.writeU32(this.headerSum, expectedSum);
                    }
                    _IC.stats.bypassed++;
                }
            }
        });
    }

    // Hash verification bypass
    const cryptFuncs = ['CryptHashData', 'CryptGetHashParam'];
    cryptFuncs.forEach(func => {
        const addr = resolveFunction('advapi32.dll', func);
        if (addr) {
            installHook(addr, {
                onEnter: function(args) {
                    if (func === 'CryptGetHashParam') {
                        this.param = args[1].toInt32();
                        this.buffer = args[2];
                        this.size = args[3];
                    }
                },
                onLeave: function(retval) {
                    if (func === 'CryptGetHashParam' && this.param === 2) { // HP_HASHVAL
                        if (this.buffer) {
                            // Provide known good hash
                            const goodHash = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                                            0x10, 0x11, 0x12, 0x13];
                            this.buffer.writeByteArray(goodHash);
                            if (this.size) {
                                Memory.writeU32(this.size, goodHash.length);
                            }
                            _IC.stats.bypassed++;
                        }
                    }
                }
            });
        }
    });

    // BCrypt hash bypass
    const bcryptHash = resolveFunction('bcrypt.dll', 'BCryptFinishHash');
    if (bcryptHash) {
        installHook(bcryptHash, {
            onEnter: function(args) {
                this.output = args[1];
                this.outputSize = args[2].toInt32();
            },
            onLeave: function(retval) {
                if (retval.toInt32() === 0 && this.output) {
                    // Replace with expected hash
                    const knownHash = new Uint8Array(this.outputSize);
                    for (let i = 0; i < this.outputSize; i++) {
                        knownHash[i] = i % 256;
                    }
                    this.output.writeByteArray(Array.from(knownHash));
                    _IC.stats.bypassed++;
                }
            }
        });
    }

    // Memory protection bypass
    const virtualProtect = resolveFunction('kernel32.dll', 'VirtualProtect');
    if (virtualProtect) {
        installHook(virtualProtect, {
            onEnter: function(args) {
                this.address = args[0];
                this.size = args[1].toInt32();
                this.newProtect = args[2].toInt32();
            },
            onLeave: function(retval) {
                // Always return success for protection changes
                if (retval.toInt32() === 0) {
                    retval.replace(1);
                    _IC.stats.bypassed++;
                }
            }
        });
    }
})();
"""

    def _gen_hardware_script(self, target_info: dict[str, Any]) -> str:
        """Generate hardware ID spoofing script.

        Generates Frida instrumentation for analyzing hardware-based licensing
        protections including WMI queries, hardware identifier collection, and
        hardware token/dongle validation mechanisms.

        Args:
            target_info: Dictionary containing target process analysis results.

        Returns:
            Complete Frida JavaScript code for hardware protection analysis.

        Implementation:
            - Spools hardware information queries (GetVolumeInformation, GetAdaptersInfo)
            - Intercepts WMI queries for hardware identification
            - Patches hardware validation routines
            - Provides synthesized hardware identifiers
        """
        return """
// Hardware ID spoofing implementation
(() => {
    const hwIdCache = new Map();

    // Volume serial number spoofing
    const getVolumeInfo = resolveFunction('kernel32.dll', 'GetVolumeInformationW');
    if (getVolumeInfo) {
        installHook(getVolumeInfo, {
            onEnter: function(args) {
                this.serialNumber = args[3];
            },
            onLeave: function(retval) {
                if (retval && this.serialNumber) {
                    Memory.writeU32(this.serialNumber, 0xDEADBEEF);
                    _IC.stats.bypassed++;
                }
            }
        });
    }

    // MAC address spoofing
    const getAdaptersInfo = resolveFunction('iphlpapi.dll', 'GetAdaptersInfo');
    if (getAdaptersInfo) {
        installHook(getAdaptersInfo, {
            onEnter: function(args) {
                this.adapterInfo = args[0];
            },
            onLeave: function(retval) {
                if (retval.toInt32() === 0 && this.adapterInfo) {
                    // Spoof MAC address
                    const macOffset = Process.arch === 'x64' ? 404 : 400;
                    const spoofedMac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
                    this.adapterInfo.add(macOffset).writeByteArray(spoofedMac);
                    _IC.stats.bypassed++;
                }
            }
        });
    }

    // CPU ID spoofing
    const cpuidPattern = '0F A2';
    const cpuidMatches = scanMemory(cpuidPattern, 'r-x');
    cpuidMatches.forEach(match => {
        try {
            Interceptor.attach(match.address, {
                onEnter: function(args) {
                    if (this.context.eax === 3) { // Processor serial number
                        this.spoofSerial = true;
                    }
                },
                onLeave: function(retval) {
                    if (this.spoofSerial) {
                        this.context.ecx = 0x12345678;
                        this.context.edx = 0x87654321;
                        _IC.stats.bypassed++;
                    }
                }
            });
        } catch (e) {}
    });

    // WMI hardware query bypass
    const sysInfo = resolveFunction('kernel32.dll', 'GetSystemInfo');
    if (sysInfo) {
        installHook(sysInfo, {
            onEnter: function(args) {
                this.sysInfoStruct = args[0];
            },
            onLeave: function(retval) {
                if (this.sysInfoStruct) {
                    // Modify processor info
                    Memory.writeU32(this.sysInfoStruct.add(24), 4); // 4 processors
                    Memory.writeU16(this.sysInfoStruct.add(32), 0x8664); // x64 arch
                    _IC.stats.bypassed++;
                }
            }
        });
    }
})();
"""

    def _gen_cloud_script(self, target_info: dict[str, Any]) -> str:
        """Generate cloud license bypass script.

        Generates Frida code for analyzing cloud-based licensing protections
        including SSL/TLS interception, HTTP/HTTPS license validation, and
        network-based activation mechanisms.

        Args:
            target_info: Dictionary containing target process analysis results.

        Returns:
            Complete Frida JavaScript code for cloud license protection analysis.

        Implementation:
            - Intercepts SSL/TLS write and read operations
            - Spools HTTP license validation requests
            - Patches network-based activation checks
            - Provides valid cloud responses
        """
        return """
// Cloud license bypass implementation
(() => {
    // SSL/TLS interception
    const sslWrite = resolveFunction('ssleay32.dll', 'SSL_write') ||
                    resolveFunction('libssl.dll', 'SSL_write');
    const sslRead = resolveFunction('ssleay32.dll', 'SSL_read') ||
                   resolveFunction('libssl.dll', 'SSL_read');

    if (sslWrite) {
        installHook(sslWrite, {
            onEnter: function(args) {
                const data = args[1].readCString();
                if (data && data.includes('license')) {
                    // Modify outgoing license check
                    const validRequest = '{"license":"VALID","type":"enterprise"}';
                    args[1] = Memory.allocUtf8String(validRequest);
                    args[2] = ptr(validRequest.length);
                    _IC.stats.bypassed++;
                }
            }
        });
    }

    if (sslRead) {
        installHook(sslRead, {
            onEnter: function(args) {
                this.buffer = args[1];
                this.size = args[2].toInt32();
            },
            onLeave: function(retval) {
                if (retval.toInt32() > 0 && this.buffer) {
                    const data = this.buffer.readCString();
                    if (data && data.includes('invalid')) {
                        // Replace with valid response
                        const validResponse = '{"status":"active","expires":"2099-12-31"}';
                        this.buffer.writeUtf8String(validResponse);
                        retval.replace(validResponse.length);
                        _IC.stats.bypassed++;
                    }
                }
            }
        });
    }

    // HTTP/HTTPS response modification
    const httpReceive = resolveFunction('winhttp.dll', 'WinHttpReceiveResponse');
    const httpRead = resolveFunction('winhttp.dll', 'WinHttpReadData');

    if (httpRead) {
        installHook(httpRead, {
            onEnter: function(args) {
                this.buffer = args[1];
                this.bytesToRead = args[2].toInt32();
                this.bytesRead = args[3];
            },
            onLeave: function(retval) {
                if (retval && this.buffer) {
                    try {
                        const data = this.buffer.readUtf8String();
                        if (data && (data.includes('expired') || data.includes('invalid'))) {
                            const validData = '{"valid":true,"features":"all"}';
                            this.buffer.writeUtf8String(validData);
                            if (this.bytesRead) {
                                Memory.writeU32(this.bytesRead, validData.length);
                            }
                            _IC.stats.bypassed++;
                        }
                    } catch (e) {}
                }
            }
        });
    }
})();
"""

    def _gen_time_script(self, target_info: dict[str, Any]) -> str:
        """Generate time-based protection bypass script.

        Generates Frida instrumentation for analyzing time-based protections
        including trial period enforcement, time-bomb checks, and timestamp
        validation in licensing mechanisms.

        Args:
            target_info: Dictionary containing target process analysis results.

        Returns:
            Complete Frida JavaScript code for time-based protection analysis.

        Implementation:
            - Hooks system time functions (GetSystemTime, GetLocalTime)
            - Manipulates returned time values to reset trial periods
            - Intercepts performance counter and tick count APIs
            - Bypasses timestamp-based validation checks
        """
        return """
// Time-based protection bypass
(() => {
    const baseTime = new Date('2020-01-01').getTime();
    let timeOffset = 0;

    // System time manipulation
    const timeFuncs = ['GetSystemTime', 'GetLocalTime', 'GetSystemTimeAsFileTime'];
    timeFuncs.forEach(func => {
        const addr = resolveFunction('kernel32.dll', func);
        if (addr) {
            installHook(addr, {
                onEnter: function(args) {
                    this.timeStruct = args[0];
                },
                onLeave: function(retval) {
                    if (this.timeStruct) {
                        // Set to base time for trial reset
                        if (func.includes('FileTime')) {
                            const fileTime = 116444736000000000n; // Jan 1, 2020
                            Memory.writeU64(this.timeStruct, fileTime);
                        } else {
                            Memory.writeU16(this.timeStruct, 2020);      // Year
                            Memory.writeU16(this.timeStruct.add(2), 1);   // Month
                            Memory.writeU16(this.timeStruct.add(6), 1);   // Day
                        }
                        _IC.stats.bypassed++;
                    }
                }
            });
        }
    });

    // Performance counter manipulation
    const queryPerf = resolveFunction('kernel32.dll', 'QueryPerformanceCounter');
    if (queryPerf) {
        let lastCounter = 0;
        installHook(queryPerf, {
            onEnter: function(args) {
                this.counter = args[0];
            },
            onLeave: function(retval) {
                if (this.counter) {
                    // Slow down time progression
                    lastCounter += 1000;
                    Memory.writeU64(this.counter, lastCounter);
                    _IC.stats.bypassed++;
                }
            }
        });
    }

    // Tick count manipulation
    const getTickCount = resolveFunction('kernel32.dll', 'GetTickCount64') ||
                        resolveFunction('kernel32.dll', 'GetTickCount');
    if (getTickCount) {
        let baseTickCount = 0;
        installHook(getTickCount, {
            onLeave: function(retval) {
                // Keep tick count low
                baseTickCount += 100;
                retval.replace(baseTickCount);
                _IC.stats.bypassed++;
            }
        });
    }
})();
"""

    def _gen_memory_script(self, target_info: dict[str, Any]) -> str:
        """Generate memory protection bypass script.

        Generates Frida instrumentation for analyzing memory-based protections
        including memory page protection validation, write protection detection,
        and runtime code modification prevention mechanisms.

        Args:
            target_info: Dictionary containing target process analysis results.

        Returns:
            Complete Frida JavaScript code for memory protection analysis.

        Implementation:
            - Hooks VirtualProtect and VirtualProtectEx for page protection
            - Intercepts WriteProcessMemory for memory write operations
            - Bypasses read-only page detection
            - Tracks memory protection changes for analysis
        """
        return """
// Memory protection bypass
(() => {
    // VirtualProtect monitoring and bypass
    const virtualProtect = resolveFunction('kernel32.dll', 'VirtualProtect');
    const virtualProtectEx = resolveFunction('kernel32.dll', 'VirtualProtectEx');

    [virtualProtect, virtualProtectEx].forEach(func => {
        if (func) {
            installHook(func, {
                onEnter: function(args) {
                    this.addr = args[func === virtualProtectEx ? 1 : 0];
                    this.size = args[func === virtualProtectEx ? 2 : 1].toInt32();
                    this.newProtect = args[func === virtualProtectEx ? 3 : 2].toInt32();
                },
                onLeave: function(retval) {
                    // Always report success
                    if (retval.toInt32() === 0) {
                        retval.replace(1);
                        _IC.stats.bypassed++;
                    }

                    // Log protection changes
                    send({
                        type: 'info',
                        target: 'memory_protection',
                        action: 'protection_change',
                        address: this.addr,
                        size: this.size,
                        protection: this.newProtect
                    });
                }
            });
        }
    });

    // WriteProcessMemory bypass
    const writeMemory = resolveFunction('kernel32.dll', 'WriteProcessMemory');
    if (writeMemory) {
        installHook(writeMemory, {
            onEnter: function(args) {
                this.process = args[0];
                this.address = args[1];
                this.buffer = args[2];
                this.size = args[3].toInt32();
            },
            onLeave: function(retval) {
                // Force success for self-modification
                if (this.process.toInt32() === -1) { // Current process
                    if (retval.toInt32() === 0) {
                        retval.replace(1);
                        _IC.stats.bypassed++;
                    }
                }
            }
        });
    }

    // Guard page bypass
    const exceptionHandler = Process.setExceptionHandler((details) => {
        if (details.type === 'guard-page') {
            // Remove guard page protection
            const page = ptr(details.address).and(~0xFFF);
            Memory.protect(page, 0x1000, 'rwx');
            _IC.stats.bypassed++;
            return true;
        }
        return false;
    });
})();
"""

    def _gen_kernel_script(self, target_info: dict[str, Any]) -> str:
        """Generate kernel-level protection bypass script.

        Generates Frida instrumentation for analyzing kernel-level protections
        including driver interactions, DeviceIoControl calls, and kernel-mode
        licensing validation mechanisms.

        Args:
            target_info: Dictionary containing target process analysis results.

        Returns:
            Complete Frida JavaScript code for kernel protection analysis.

        Implementation:
            - Hooks DeviceIoControl for driver communication
            - Intercepts kernel-level license queries
            - Patches driver response data
            - Analyzes protection driver interactions
        """
        return """
// Kernel protection bypass
(() => {
    // DeviceIoControl bypass
    const deviceIoControl = resolveFunction('kernel32.dll', 'DeviceIoControl');
    if (deviceIoControl) {
        installHook(deviceIoControl, {
            onEnter: function(args) {
                this.device = args[0];
                this.ioControlCode = args[1].toInt32();
                this.outBuffer = args[3];
                this.outSize = args[4].toInt32();
            },
            onLeave: function(retval) {
                // Process actual driver responses and modify as needed
                if (retval.toInt32() !== 0) {
                    // Successfully processed - check what was returned
                    const controlCodeHandlers = {
                        0x222000: () => { // Protection driver query
                            if (this.outBuffer && this.outSize >= 4) {
                                // Read actual value and modify if it indicates protection is active
                                const currentValue = Memory.readU32(this.outBuffer);
                                if (currentValue & 0x1000) { // Protection active flag
                                    // Clear protection flags while preserving other data
                                    Memory.writeU32(this.outBuffer, currentValue & ~0x1000);
                                    _IC.stats.bypassed++;
                                }
                            }
                        },
                        0x222004: () => { // License status query
                            if (this.outBuffer && this.outSize >= 8) {
                                // Ensure license appears valid by setting appropriate flags
                                const statusFlags = Memory.readU32(this.outBuffer);
                                const licenseType = Memory.readU32(this.outBuffer.add(4));
                                // Set valid license flags (0x01 = valid, 0x02 = activated)
                                if (!(statusFlags & 0x01)) {
                                    Memory.writeU32(this.outBuffer, statusFlags | 0x03);
                                    _IC.stats.bypassed++;
                                }
                            }
                        },
                        0x222008: () => { // Hardware ID query
                            if (this.outBuffer && this.outSize >= 16) {
                                // Normalize hardware ID to bypass hardware locks
                                const hwId = this.outBuffer.readByteArray(16);
                                const normalizedId = [
                                    0x44, 0x45, 0x56, 0x31, // DEV1
                                    0x32, 0x33, 0x34, 0x35, // 2345
                                    0x36, 0x37, 0x38, 0x39, // 6789
                                    0x41, 0x42, 0x43, 0x44  // ABCD
                                ];
                                this.outBuffer.writeByteArray(normalizedId);
                                _IC.stats.bypassed++;
                            }
                        }
                    };

                    // Handle known control codes
                    const handler = controlCodeHandlers[this.ioControlCode];
                    if (handler) {
                        handler();
                    }
                }
            }
        });
    }

    // NtQuerySystemInformation bypass
    const ntQuerySystem = resolveFunction('ntdll.dll', 'NtQuerySystemInformation');
    if (ntQuerySystem) {
        installHook(ntQuerySystem, {
            onEnter: function(args) {
                this.infoClass = args[0].toInt32();
                this.buffer = args[1];
                this.bufferSize = args[2].toInt32();
            },
            onLeave: function(retval) {
                // Filter kernel debugger information
                if (this.infoClass === 35) { // SystemKernelDebuggerInformation
                    if (this.buffer && retval.toInt32() === 0) {
                        Memory.writeU8(this.buffer, 0); // KernelDebuggerEnabled
                        Memory.writeU8(this.buffer.add(1), 0); // KernelDebuggerNotPresent
                        _IC.stats.bypassed++;
                    }
                }
            }
        });
    }

    // Driver communication interception
    const createFile = resolveFunction('kernel32.dll', 'CreateFileW');
    if (createFile) {
        installHook(createFile, {
            onEnter: function(args) {
                const filename = args[0].readUtf16String();
                if (filename && filename.startsWith('\\\\\\\\.\\\\')) {
                    // Device/driver access
                    this.isDriver = true;
                    this.driverName = filename;
                }
            },
            onLeave: function(retval) {
                if (this.isDriver) {
                    // Provide valid handle for protection drivers when access is denied
                    if (retval.toInt32() === -1) {
                        // Open a valid null device handle as a substitute
                        const kernel32 = Process.getModuleByName('kernel32.dll');
                        const createFileW = new NativeFunction(
                            kernel32.getExportByName('CreateFileW'),
                            'pointer',
                            ['pointer', 'uint32', 'uint32', 'pointer', 'uint32', 'uint32', 'pointer']
                        );

                        // Open NUL device which always succeeds and provides a valid handle
                        const nulDevice = Memory.allocUtf16String('\\\\\\\\.\\\\NUL');
                        const GENERIC_READ = 0x80000000;
                        const FILE_SHARE_READ = 0x1;
                        const OPEN_EXISTING = 3;
                        const FILE_ATTRIBUTE_NORMAL = 0x80;

                        const validHandle = createFileW(
                            nulDevice,
                            GENERIC_READ,
                            FILE_SHARE_READ,
                            ptr(0),
                            OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL,
                            ptr(0)
                        );

                        if (validHandle && validHandle.toInt32() !== -1) {
                            retval.replace(validHandle);
                            _IC.stats.bypassed++;
                        }
                    }
                }
            }
        });
    }
})();
"""

    def _aggressive_hooks(self, target_info: dict[str, Any]) -> str:
        """Generate aggressive hooking strategy.

        Creates Frida code that aggressively hooks all functions related to
        protection mechanisms. Hooks every function containing protection-related
        keywords to maximize coverage and bypass effectiveness.

        Args:
            target_info: Dictionary containing target process analysis results.

        Returns:
            Complete Frida JavaScript code for aggressive hooking strategy.

        Note:
            This strategy has high overhead and may trigger anti-debugging
            mechanisms. Best used for comprehensive analysis.
        """
        return """
// Aggressive hooking strategy
(() => {
    // Hook everything related to protection
    const modules = Process.enumerateModules();
    const protectionKeywords = ['check', 'verify', 'validate', 'license', 'auth', 'protect'];

    modules.forEach(module => {
        try {
            const exports = module.enumerateExports();
            exports.forEach(exp => {
                const nameLower = exp.name.toLowerCase();
                if (protectionKeywords.some(kw => nameLower.includes(kw))) {
                    try {
                        installHook(exp.address, {
                            onLeave: function(retval) {
                                // Force success on all validation functions
                                if (retval.toInt32() === 0) {
                                    retval.replace(1);
                                }
                            }
                        });
                    } catch (e) {}
                }
            });
        } catch (e) {}
    });
})();
"""

    def _stealthy_hooks(self, target_info: dict[str, Any]) -> str:
        """Generate stealthy hooking strategy.

        Creates Frida code that minimally hooks only critical protection functions
        with random timing delays to avoid detection by anti-analysis mechanisms.

        Args:
            target_info: Dictionary containing target process analysis results.

        Returns:
            Complete Frida JavaScript code for stealthy hooking strategy.

        Note:
            This strategy minimizes overhead and detection risk by hooking only
            the most essential functions with timing randomization.
        """
        return """
// Stealthy hooking strategy
(() => {
    // Minimal hooks with timing randomization
    const hookDelay = () => Math.floor(Math.random() * 1000) + 500;

    setTimeout(() => {
        // Hook only critical functions
        const criticalHooks = [
            {module: 'kernel32.dll', func: 'IsDebuggerPresent'},
            {module: 'advapi32.dll', func: 'RegQueryValueExW'},
        ];

        criticalHooks.forEach(hook => {
            setTimeout(() => {
                const addr = resolveFunction(hook.module, hook.func);
                if (addr) {
                    installHook(addr, {
                        onLeave: function(retval) {
                            if (hook.func === 'IsDebuggerPresent') {
                                retval.replace(0);
                            }
                        }
                    });
                }
            }, hookDelay());
        });
    }, hookDelay());
})();
"""

    def _adaptive_hooks(self, target_info: dict[str, Any]) -> str:
        """Generate adaptive hooking strategy.

        Creates Frida code that dynamically adjusts hooking based on detected
        protections and real-time analysis results. Hooks are installed and
        modified based on protection detection feedback.

        Args:
            target_info: Dictionary containing target process analysis results.

        Returns:
            Complete Frida JavaScript code for adaptive hooking strategy.

        Note:
            This is the default strategy balancing coverage and stealth through
            real-time adaptation based on protection detection.
        """
        return """
// Adaptive hooking strategy
(() => {
    const adaptiveSystem = {
        detectionCount: 0,
        bypassSuccess: 0,
        failureCount: 0,
        strategies: new Map(),

        adapt: function() {
            const successRate = this.bypassSuccess / (this.detectionCount + 1);

            if (successRate < 0.5) {
                // Switch to more aggressive strategy
                this.escalate();
            } else if (successRate > 0.9) {
                // Can be more stealthy
                this.deescalate();
            }
        },

        escalate: function() {
            // Add more comprehensive hooks
            send({type: 'info', action: 'escalating_bypass_strategy'});
            this.hookAdditionalFunctions();
        },

        deescalate: function() {
            // Remove some hooks for stealth
            send({type: 'info', action: 'reducing_hook_footprint'});
            this.removeNonEssentialHooks();
        },

        hookAdditionalFunctions: function() {
            // Dynamically add more hooks based on detection
            const additionalTargets = this.identifyNewTargets();
            additionalTargets.forEach(target => {
                const addr = resolveFunction(target.module, target.func);
                if (addr && !_IC.hooks.has(addr.toString())) {
                    installHook(addr, target.handler);
                }
            });
        },

        removeNonEssentialHooks: function() {
            // Remove hooks with low impact
            _IC.hooks.forEach((hook, key) => {
                const stats = this.strategies.get(key);
                if (stats && stats.calls > 0 && stats.bypasses === 0) {
                    hook.detach();
                    _IC.hooks.delete(key);
                }
            });
        },

        identifyNewTargets: function() {
            // Analyze runtime behavior to find new targets
            const targets = [];
            const modules = Process.enumerateModules();

            modules.forEach(module => {
                if (module.name.includes('protect') || module.name.includes('guard')) {
                    try {
                        const exports = module.enumerateExports();
                        exports.forEach(exp => {
                            targets.push({
                                module: module.name,
                                func: exp.name,
                                handler: {
                                    onLeave: function(retval) {
                                        retval.replace(1);
                                    }
                                }
                            });
                        });
                    } catch (e) {}
                }
            });

            return targets;
        }
    };

    // Start adaptive system
    setInterval(() => {
        adaptiveSystem.adapt();
    }, 5000);

    // Initial hook setup
    const initialTargets = [
        {module: 'kernel32.dll', func: 'IsDebuggerPresent'},
        {module: 'ntdll.dll', func: 'NtQueryInformationProcess'},
    ];

    initialTargets.forEach(target => {
        const addr = resolveFunction(target.module, target.func);
        if (addr) {
            installHook(addr, {
                onEnter: function(args) {
                    adaptiveSystem.detectionCount++;
                },
                onLeave: function(retval) {
                    if (target.func === 'IsDebuggerPresent') {
                        retval.replace(0);
                        adaptiveSystem.bypassSuccess++;
                    }
                }
            });
        }
    });

    return adaptiveSystem;
})();
"""

    def _minimal_hooks(self, target_info: dict[str, Any]) -> str:
        """Generate minimal hooking strategy.

        Creates Frida code that hooks only the absolute minimum set of functions
        required to bypass protections, prioritizing low detection risk and
        minimal system impact.

        Args:
            target_info: Dictionary containing target process analysis results.

        Returns:
            Complete Frida JavaScript code for minimal hooking strategy.

        Note:
            Best for lightweight instrumentation with minimal overhead.
        """
        return """
// Minimal hooking strategy - only essential bypasses
(() => {
    // Only hook the absolute minimum required
    const essential = [
        {module: 'kernel32.dll', func: 'IsDebuggerPresent', ret: 0},
    ];

    essential.forEach(hook => {
        const addr = resolveFunction(hook.module, hook.func);
        if (addr) {
            installHook(addr, {
                onLeave: function(retval) {
                    retval.replace(hook.ret);
                }
            });
        }
    });
})();
"""

    def _comprehensive_hooks(self, target_info: dict[str, Any]) -> str:
        """Generate comprehensive hooking strategy.

        Creates Frida code that comprehensively hooks all protection-related
        functions across multiple categories including debugging, registry,
        file operations, cryptography, networking, and memory management.

        Args:
            target_info: Dictionary containing target process analysis results.

        Returns:
            Complete Frida JavaScript code for comprehensive hooking strategy.

        Note:
            Maximum coverage strategy with highest overhead. Best for laboratory
            analysis where resource constraints are not a concern.
        """
        return """
// Comprehensive hooking strategy - maximum coverage
(() => {
    // Hook all possible protection-related functions
    const hookCategories = {
        debug: ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'OutputDebugString'],
        registry: ['RegQueryValueExW', 'RegGetValueW', 'RegOpenKeyExW'],
        file: ['CreateFileW', 'ReadFile', 'GetFileAttributesW'],
        crypto: ['CryptHashData', 'CryptVerifySignature', 'BCryptFinishHash'],
        network: ['InternetOpenUrlW', 'HttpSendRequestW', 'recv', 'send'],
        time: ['GetSystemTime', 'GetTickCount', 'QueryPerformanceCounter'],
        memory: ['VirtualProtect', 'WriteProcessMemory', 'ReadProcessMemory'],
    };

    Object.keys(hookCategories).forEach(category => {
        hookCategories[category].forEach(func => {
            const modules = ['kernel32.dll', 'advapi32.dll', 'ntdll.dll', 'ws2_32.dll'];

            modules.forEach(module => {
                const addr = resolveFunction(module, func);
                if (addr) {
                    installHook(addr, {
                        onEnter: function(args) {
                            send({
                                type: 'info',
                                category: category,
                                function: func,
                                module: module
                            });
                        },
                        onLeave: function(retval) {
                            // Generic success forcing
                            if (category === 'debug' || category === 'crypto') {
                                if (func.includes('Debug')) {
                                    retval.replace(0);
                                } else if (func.includes('Verify')) {
                                    retval.replace(1);
                                }
                            }
                        }
                    });
                }
            });
        });
    });
})();
"""

    def _generate_runtime_adaptation(self) -> str:
        """Generate runtime adaptation code.

        Creates Frida JavaScript code that monitors system state at runtime and
        dynamically adapts bypass techniques based on detection of anti-analysis
        or anti-debugging mechanisms.

        Returns:
            Complete Frida JavaScript code for runtime adaptation system.

        Implementation:
            - Monitors for suspicious patterns every 10 seconds
            - Dynamically adjusts bypass strategies based on detection
            - Sends adaptation notifications to control system
            - Logs adaptation history for analysis
        """
        return """
// Runtime adaptation system
(() => {
    const runtime = {
        startTime: Date.now(),
        adaptations: 0,
        lastCheck: Date.now(),

        monitor: function() {
            const now = Date.now();
            const elapsed = now - this.lastCheck;

            if (elapsed > 10000) { // Check every 10 seconds
                this.checkAndAdapt();
                this.lastCheck = now;
            }
        },

        checkAndAdapt: function() {
            // Check if we're being detected
            const suspiciousPatterns = [
                'frida',
                'hook',
                'inject',
                'debug'
            ];

            // Scan loaded modules for detection
            const modules = Process.enumerateModules();
            modules.forEach(module => {
                const nameLower = module.name.toLowerCase();
                if (suspiciousPatterns.some(pattern => nameLower.includes(pattern))) {
                    this.hidePresence();
                }
            });

            // Adapt based on success rate
            const successRate = _IC.stats.bypassed / (_IC.stats.calls + 1);
            if (successRate < 0.7) {
                this.increaseAggression();
            }
        },

        hidePresence: function() {
            // Additional hiding measures
            this.adaptations++;

            // Clear Frida artifacts
            if (typeof global !== 'undefined') {
                Object.keys(global).forEach(key => {
                    if (key.includes('frida') || key.includes('_IC')) {
                        delete global[key];
                    }
                });
            }
        },

        increaseAggression: function() {
            // Add more aggressive bypasses
            send({
                type: 'info',
                action: 'increasing_bypass_aggression',
                adaptations: this.adaptations
            });
        }
    };

    // Start monitoring
    setInterval(() => runtime.monitor(), 1000);

    return runtime;
})();

// Final statistics reporting
setInterval(() => {
    send({
        type: 'status',
        stats: _IC.stats,
        hooks: _IC.hooks.size,
        bypasses: _IC.bypasses.size
    });
}, 30000);
"""

    def _obfuscate_script(self, script: str) -> str:
        """Apply obfuscation to the generated script.

        Applies multiple obfuscation techniques to the generated Frida script
        to reduce detectability and make reverse engineering more difficult.

        Args:
            script: Original Frida JavaScript script code.

        Returns:
            Obfuscated script string with applied obfuscation techniques.

        Obfuscation Techniques:
            - Variable name mangling with random identifiers
            - String encoding using base64
            - Comment removal
            - Dead code injection
            - Control flow modification
        """
        import random
        import re
        import string

        # Variable name obfuscation
        var_mapping = {}

        # Find all variable names
        var_pattern = r"\b(const|let|var)\s+(\w+)\b"
        matches = re.findall(var_pattern, script)

        for _, var_name in matches:
            if var_name not in var_mapping and not var_name.startswith("_"):
                # Generate obfuscated name
                # Note: Using random module for variable obfuscation, not cryptographic purposes
                obf_name = "_" + "".join(random.choices(string.ascii_letters, k=8))  # noqa: S311
                var_mapping[var_name] = obf_name

        # Replace variable names
        obfuscated = script
        for original, obfuscated_name in var_mapping.items():
            pattern = r"\b" + re.escape(original) + r"\b"
            obfuscated = re.sub(pattern, obfuscated_name, obfuscated)

        # String encoding
        strings = re.findall(r'"([^"]*)"', obfuscated)
        for s in strings:
            if len(s) > 3 and not s.startswith("//"):
                # Base64 encode strings
                import base64

                encoded = base64.b64encode(s.encode()).decode()
                decoder = f"atob('{encoded}')"
                obfuscated = obfuscated.replace(f'"{s}"', decoder)

        # Add control flow obfuscation
        control_flow = """
// Control flow obfuscation
(() => {
    const _x = Math.random() > 0.5;
    if (_x) {
        // Dead code branch
        const _y = [1,2,3].map(x => x * 2);
    } else {
        // Another dead branch
        const _z = 'unused'.split('');
    }
})();
"""

        # Insert dead code at random positions
        lines = obfuscated.split("\n")
        insert_positions = random.sample(range(len(lines)), min(5, len(lines) // 10))

        for pos in sorted(insert_positions, reverse=True):
            lines.insert(pos, control_flow)

        return "\n".join(lines)


@log_all_methods
class FridaManager:
    """Run Frida management class with all advanced features.

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

    def __init__(self, log_dir: str | None = None, script_dir: str | None = None) -> None:
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
        self.script_generator = DynamicScriptGenerator()  # Add dynamic script generator

        self.device: Any | None = None
        self.sessions: dict[str, Any] = {}
        self.scripts: dict[str, Any] = {}
        self.script_outputs: dict[str, Any] = {}

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

        Raises:
            ImportError: If frida module is not available.

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
            if frida is None:
                raise ImportError("frida is not available")
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
                except Exception as e:
                    logger.debug("Failed to get process name for PID %s: %s", process_identifier, e)
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
            session.on("detached", lambda reason, crash: self._on_session_detached(session_id, reason))

            return True

        except Exception as e:
            self.logger.log_operation(
                "attach_to_process",
                {"process_identifier": process_identifier},
                success=False,
                error=str(e),
            )
            logger.exception("Failed to attach to process: %s", e)
            return False

    def add_custom_script(self, script_content: str, script_name: str) -> Path:
        """Add a custom Frida script to the scripts directory.

        Writes provided JavaScript script code to the scripts directory with
        appropriate naming and logging of the operation.

        Args:
            script_content: JavaScript code for the script.
            script_name: Name for the script file (extension added if missing).

        Returns:
            Path object pointing to the created script file.

        Side Effects:
            - Creates or overwrites script file in script directory
            - Logs operation to operation logger
            - Records script metadata (name, path, content length)
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

        Enumerates all JavaScript files in the scripts directory and extracts
        metadata including file size, modification time, and detected protection type.

        Returns:
            List of script information dictionaries, each containing:
            - name: Script file name without extension
            - path: Absolute path to script file
            - size: File size in bytes
            - modified: ISO format timestamp of last modification
            - protection_type: Detected protection type or 'UNKNOWN'

        Note:
            Skips scripts that fail to read, logging exceptions without raising.
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

                        if match := re.search(r'PROTECTION_TYPE\s*=\s*["\'](\w+)["\']', content):
                            protection_type = match.group(1)

                    scripts.append(
                        {
                            "name": script_file.stem,
                            "path": str(script_file),
                            "size": stat.st_size,
                            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            "protection_type": protection_type,
                        },
                    )

                except Exception as e:
                    logger.exception("Error reading script %s: %s", script_file, e)

        return scripts

    def load_script(self, session_id: str, script_name: str, options: dict[str, Any] | None = None) -> bool:
        """Load and inject a Frida script with optimization.

        Loads a Frida script from the scripts directory, applies optimization
        and instrumentation, then injects it into the target process session.

        Args:
            session_id: Identifier for the target Frida session.
            script_name: Name of the script file (with or without .js extension).
            options: Optional dictionary of script configuration options.

        Returns:
            True if script injection succeeded, False otherwise.

        Raises:
            ValueError: If session_id is not found in active sessions.
            FileNotFoundError: If script file cannot be located.

        Side Effects:
            - Loads and applies script optimization
            - Instruments script with logging hooks
            - Registers script message handler
            - Logs operation and performance metrics
        """
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

            script_code = Path(script_path).read_text()
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
            logger.debug("Stored script with key: %s", script_key)

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
            logger.exception("Failed to load script: %s", e)
            return False

    def load_dynamic_script(
        self,
        session_id: str,
        target_info: dict[str, Any] | None = None,
        detected_protections: list[ProtectionType] | None = None,
        strategy: str = "adaptive",
        obfuscate: bool = True,
    ) -> bool:
        """Generate and load a dynamic Frida script based on target analysis.

        Uses the dynamic script generator to create a customized Frida script
        tailored to detected protections, then injects it into the target session.
        Automatically detects protections if not explicitly provided.

        Args:
            session_id: Identifier for the target Frida session.
            target_info: Binary analysis results dict (optional, auto-detected if None).
            detected_protections: List of detected ProtectionType enums (optional,
                                 auto-detected if None).
            strategy: Hooking strategy to use (adaptive, aggressive, stealthy,
                     minimal, comprehensive). Defaults to adaptive.
            obfuscate: Whether to apply obfuscation to generated script. Defaults to True.

        Returns:
            True if script was successfully generated and loaded, False otherwise.

        Raises:
            ValueError: If session_id is not found in active sessions.

        Side Effects:
            - Auto-detects protections if not provided
            - Generates dynamic script using script generator
            - Injects script into target session
            - Logs operation and performance metrics
        """
        try:
            start_time = time.time()

            # Get session
            session = self.sessions.get(session_id)
            if not session:
                raise ValueError(f"No session found: {session_id}")

            # Auto-detect protections if not provided
            if detected_protections is None:
                detected_protections = self._detect_protections_for_session(session_id)

            # Get target info if not provided
            if target_info is None:
                target_info = self._analyze_target(session_id)

            # Generate dynamic script
            script_code = self.script_generator.generate_script(
                target_info=target_info,
                detected_protections=detected_protections,
                strategy=strategy,
                obfuscate=obfuscate,
            )

            # Save generated script for reference
            script_name = f"dynamic_{session_id}_{int(time.time())}"
            script_path = self.script_dir / f"{script_name}.js"
            with open(script_path, "w") as f:
                f.write(script_code)

            # Add instrumentation for logging
            script_code = self._instrument_script(script_code, script_name)

            # Create and load script
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

            # Store script
            script_key = f"{session_id}:{script_name}"
            self.scripts[script_key] = script
            logger.info("Loaded dynamic script: %s", script_name)

            # Log operation
            self.logger.log_operation(
                "load_dynamic_script",
                {
                    "session_id": session_id,
                    "script_name": script_name,
                    "protections": [str(p) for p in detected_protections],
                    "strategy": strategy,
                    "obfuscated": obfuscate,
                    "script_size": len(script_code),
                },
                success=True,
            )

            # Log performance
            load_time = (time.time() - start_time) * 1000
            self.logger.log_performance("dynamic_script_generation_time", load_time, "ms", {"script": script_name})

            return True

        except Exception as e:
            self.logger.log_operation(
                "load_dynamic_script",
                {
                    "session_id": session_id,
                    "error": str(e),
                },
                success=False,
                error=str(e),
            )
            logger.exception("Failed to load dynamic script: %s", e)
            return False

    def _detect_protections_for_session(self, session_id: str) -> list[ProtectionType]:
        """Auto-detect protections for a session by analyzing the target process.

        Injects a temporary detection script into the session to identify active
        protection mechanisms by checking for common anti-debug APIs, VM detection,
        and licensing DLLs.

        Args:
            session_id: Identifier for the target Frida session.

        Returns:
            List of detected ProtectionType enums. Empty list if session not found.

        Side Effects:
            - Creates temporary detection script
            - Loads and unloads detection script in session
            - Blocks for up to 500ms waiting for detection results
        """
        detected = []
        try:
            session = self.sessions.get(session_id)
            if not session:
                return []

            # Simple detection script
            detection_script = """
            const protections = [];

            // Check for common anti-debug APIs
            const antiDebugAPIs = ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess'];
            antiDebugAPIs.forEach(api => {
                try {
                    const addr = Module.findExportByName(null, api);
                    if (addr) protections.push('ANTI_DEBUG');
                } catch(e) {}
            });

            // Check for VM detection strings
            const modules = Process.enumerateModules();
            modules.forEach(m => {
                const name = m.name.toLowerCase();
                if (name.includes('vmware') || name.includes('vbox')) {
                    protections.push('ANTI_VM');
                }
            });

            // Check for licensing DLLs
            const licenseDlls = ['license.dll', 'activation.dll', 'flexnet.dll', 'rlm.dll'];
            licenseDlls.forEach(dll => {
                const mod = Process.findModuleByName(dll);
                if (mod) protections.push('LICENSE');
            });

            send({type: 'protections', data: [...new Set(protections)]});
            """

            # Create temporary detection script
            detection = session.create_script(detection_script)
            protections_found = []

            def on_message(message: dict[str, Any], data: bytes | bytearray) -> None:
                if message["type"] == "send":
                    payload = message.get("payload", {})
                    if payload.get("type") == "protections":
                        protections_found.extend(payload.get("data", []))

            detection.on("message", on_message)
            detection.load()

            # Wait briefly for detection to complete
            import time

            time.sleep(0.5)

            detection.unload()

            # Map string results to ProtectionType enum
            protection_map = {
                "ANTI_DEBUG": ProtectionType.ANTI_DEBUG,
                "ANTI_VM": ProtectionType.ANTI_VM,
                "LICENSE": ProtectionType.LICENSE,
            }

            for p in protections_found:
                if p in protection_map:
                    detected.append(protection_map[p])

            # If nothing detected, assume basic protections
            if not detected:
                detected = [ProtectionType.ANTI_DEBUG, ProtectionType.LICENSE]

        except Exception as e:
            logger.exception("Protection detection failed: %s", e)
            # Default to common protections
            detected = [ProtectionType.ANTI_DEBUG, ProtectionType.LICENSE]

        return detected

    def _analyze_target(self, session_id: str) -> dict[str, Any]:
        """Analyze target process to gather information for script generation.

        Injects a temporary analysis script to collect target process information
        including architecture, platform, loaded modules, and base addresses.

        Args:
            session_id: Identifier for the target Frida session.

        Returns:
            Dictionary containing analysis results with keys:
            - arch: Process architecture (x86, x64, etc.)
            - platform: OS platform (windows, linux, macos, etc.)
            - modules: List of loaded module info dicts (name, base, size)
            - base_address: Base address of main module
            - size: Size of main module

        Side Effects:
            - Creates temporary analysis script
            - Loads and unloads analysis script in session
            - Blocks for up to 500ms waiting for results
        """
        target_info: dict[str, Any] = {
            "arch": "unknown",
            "platform": "windows",
            "modules": [],
            "base_address": None,
            "size": 0,
        }

        try:
            session = self.sessions.get(session_id)
            if not session:
                return target_info

            # Quick analysis script
            analysis_script = """
            const info = {
                arch: Process.arch,
                platform: Process.platform,
                modules: [],
                base_address: null,
                size: 0
            };

            const modules = Process.enumerateModules();
            if (modules.length > 0) {
                info.base_address = modules[0].base;
                info.size = modules[0].size;

                modules.slice(0, 10).forEach(m => {
                    info.modules.push({
                        name: m.name,
                        base: m.base.toString(),
                        size: m.size
                    });
                });
            }

            send({type: 'target_info', data: info});
            """

            # Create temporary analysis script
            analyzer = session.create_script(analysis_script)

            def on_message(message: dict[str, Any], data: bytes | bytearray) -> None:
                if message["type"] == "send":
                    payload = message.get("payload", {})
                    if payload.get("type") == "target_info":
                        target_info.update(payload.get("data", {}))

            analyzer.on("message", on_message)
            analyzer.load()

            # Wait briefly for analysis
            import time

            time.sleep(0.5)

            analyzer.unload()

        except Exception as e:
            logger.exception("Target analysis failed: %s", e)

        return target_info

    def _instrument_script(self, script_code: str, script_name: str) -> str:
        """Add instrumentation to script for logging.

        Wraps the provided script code with instrumentation that tracks function
        hooks, hook statistics, and sends logging information to the controller.

        Args:
            script_code: Original Frida JavaScript script code.
            script_name: Name of the script being instrumented.

        Returns:
            Enhanced script code with logging instrumentation prepended.

        Implementation:
            - Tracks all installed hooks with unique identifiers
            - Records hook call statistics
            - Wraps Interceptor.attach for hook tracking
            - Sends hook events to controller
            - Measures script execution time
        """
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

    def _on_script_message(self, session_id: str, script_name: str, message: dict[str, Any], data: bytes | bytearray | None) -> None:
        """Handle messages from Frida scripts including binary data.

        Routes script messages to appropriate handlers based on message type.
        Processes both text-based structured messages and binary data from
        scripts including memory dumps, screenshots, files, and encrypted data.

        Args:
            session_id: Identifier for the source Frida session.
            script_name: Name of the script that sent the message.
            message: Message dictionary with 'type' and 'payload' keys.
            data: Optional binary data associated with the message.

        Side Effects:
            - Routes to specialized binary data handlers (_handle_*)
            - Logs hook executions and performance metrics
            - Notifies detector of detected protections
            - Triggers adaptation callbacks
            - Saves script output for persistence
        """
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
                    function = payload.get("function", "")
                    module = payload.get("module", "")
                    if isinstance(function, str) and isinstance(module, str):
                        self.logger.log_hook(
                            function,
                            module,
                            payload.get("args", []),
                            payload.get("retval"),
                            payload.get("modified", False),
                        )

                    # Track performance
                    if "elapsed" in payload:
                        module_perf = payload.get("module", "")
                        function_perf = payload.get("function", "")
                        elapsed = payload.get("elapsed", 0.0)
                        if isinstance(module_perf, str) and isinstance(function_perf, str) and isinstance(elapsed, (int, float)):
                            self.optimizer.track_hook_performance(
                                module_perf,
                                function_perf,
                                float(elapsed),
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

    def _on_session_detached(self, session_id: str, reason: str) -> None:
        """Handle session detachment.

        Performs cleanup when a Frida session is detached from the target process.
        Removes session and associated scripts from tracking structures.

        Args:
            session_id: Identifier for the detached session.
            reason: Reason for detachment (e.g., 'process_terminated', 'connection_lost').

        Side Effects:
            - Logs detachment operation
            - Removes session from self.sessions
            - Removes associated scripts from self.scripts
        """
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
        script_keys = [k for k in self.scripts if k.startswith(session_id)]
        for key in script_keys:
            del self.scripts[key]

    def _on_protection_detected(self, protection_type: ProtectionType, details: dict[str, Any] | set[str]) -> None:
        """Handle protection detection events.

        Called when a protection mechanism is detected in the target process.
        Logs the detection and triggers appropriate adaptation strategies.

        Args:
            protection_type: Type of detected protection mechanism.
            details: Detection details as dict or set of evidence strings.

        Side Effects:
            - Logs bypass attempt for detection
            - Calls appropriate adaptation function if available
            - Logs exceptions from adaptation without raising
        """
        # Log detection
        details_dict = details if isinstance(details, dict) else {"evidence": list(details)}
        self.logger.log_bypass_attempt(
            protection_type,
            "detection",
            True,
            details_dict,
        )

        # Apply adaptation if available
        if protection_type in self.protection_adaptations:
            adaptation_func = self.protection_adaptations[protection_type]
            try:
                adaptation_func(details)
            except Exception as e:
                logger.exception("Adaptation failed for %s: %s", protection_type, e)

    # Protection adaptation methods
    def _adapt_anti_debug(self, details: dict[str, Any] | set[str]) -> None:
        """Adapt to anti-debugging protections.

        Loads anti-debugging bypass scripts and configures aggressive anti-debug
        evasion when anti-debugging protection is detected.

        Args:
            details: Protection detection details containing session identifier.

        Side Effects:
            - Loads anti_debugger script if session available
            - Logs bypass attempt with success status
        """
        if isinstance(details, set):
            details = {"evidence": list(details)}
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

    def _adapt_anti_vm(self, details: dict[str, Any] | set[str]) -> None:
        """Adapt to anti-VM protections.

        Loads virtualization detection bypass scripts and configures hardware
        spoofing when anti-VM protection is detected.

        Args:
            details: Protection detection details containing session identifier.

        Side Effects:
            - Loads virtualization_bypass script if session available
            - Configures hardware and hypervisor spoofing
            - Logs bypass attempt with success status
        """
        if isinstance(details, set):
            details = {"evidence": list(details)}
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

    def _adapt_license(self, details: dict[str, Any] | set[str]) -> None:
        """Adapt to license verification.

        Loads appropriate license bypass scripts when license verification is detected.
        Chooses bypass script based on whether registry or network license checking
        is used.

        Args:
            details: Protection detection details containing session identifier.

        Side Effects:
            - Loads appropriate bypass script based on evidence
            - Configures license check patching and server emulation
            - Logs bypass attempt with success status
        """
        if isinstance(details, set):
            details = {"evidence": list(details)}
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

    def _adapt_integrity(self, details: dict[str, Any] | set[str]) -> None:
        """Adapt to integrity checks.

        Loads code integrity bypass scripts when code integrity protection is detected.
        Patches checksum validation and hooks validation functions.

        Args:
            details: Protection detection details containing session identifier.

        Side Effects:
            - Loads code_integrity_bypass script if session available
            - Configures checksum patching and validation hooking
            - Logs bypass attempt with success status
        """
        if isinstance(details, set):
            details = {"evidence": list(details)}
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

    def _adapt_hardware(self, details: dict[str, Any] | set[str]) -> None:
        """Adapt to hardware binding.

        Loads hardware spoofing scripts when hardware-based licensing is detected.
        Spools hardware identifiers to bypass hardware-locked licenses.

        Args:
            details: Protection detection details containing session identifier.

        Side Effects:
            - Loads hardware_spoofer script if session available
            - Configures persistent hardware ID spoofing
            - Logs bypass attempt with success status
        """
        if isinstance(details, set):
            details = {"evidence": list(details)}
        session_id = details.get("session")
        if not session_id:
            return

        # Load hardware spoofer
        self.load_script(
            session_id,
            "hardware_spoofer",
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

    def _adapt_cloud(self, details: dict[str, Any] | set[str]) -> None:
        """Adapt to cloud verification.

        Loads cloud licensing bypass scripts when network-based license verification
        is detected. Intercepts and modifies license verification responses.

        Args:
            details: Protection detection details containing session identifier.

        Side Effects:
            - Loads cloud_licensing_bypass script if session available
            - Configures request interception and response modification
            - Logs bypass attempt with success status
        """
        if isinstance(details, set):
            details = {"evidence": list(details)}
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

    def _adapt_time(self, details: dict[str, Any] | set[str]) -> None:
        """Adapt to time-based protections.

        Loads time manipulation scripts when time-based protections like trial limits
        or time-bombs are detected. Freezes or manipulates system time.

        Args:
            details: Protection detection details containing session identifier.

        Side Effects:
            - Loads time_bomb_defuser script if session available
            - Configures time freezing and trial extension
            - Logs bypass attempt with success status
        """
        if isinstance(details, set):
            details = {"evidence": list(details)}
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

    def _adapt_memory(self, details: dict[str, Any] | set[str]) -> None:
        """Adapt to memory protections.

        Loads memory protection bypass scripts when memory-based protections
        like page protection or write guards are detected.

        Args:
            details: Protection detection details containing session identifier.

        Side Effects:
            - Loads memory_integrity_bypass script if session available
            - Configures memory write protection bypass
            - Logs bypass attempt with success status
        """
        if isinstance(details, set):
            details = {"evidence": list(details)}
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

    def _adapt_kernel(self, details: dict[str, Any] | set[str]) -> None:
        """Adapt to kernel-mode protections.

        Loads kernel protection bypass scripts when kernel-mode protections
        are detected. Implements user-mode emulation to avoid kernel analysis.

        Args:
            details: Protection detection details containing session identifier.

        Side Effects:
            - Loads kernel_mode_bypass script if session available
            - Configures user-mode only operation
            - Logs bypass attempt with success status
        """
        if isinstance(details, set):
            details = {"evidence": list(details)}
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

    def _handle_memory_dump(self, session_id: str, script_name: str, data: bytes | bytearray, payload: dict[str, Any]) -> None:
        """Handle memory dump data from Frida scripts.

        Processes and stores memory dumps captured by Frida scripts. Analyzes
        memory contents for protection mechanisms and extracts relevant data.

        Args:
            session_id: Identifier for the source Frida session.
            script_name: Name of the script that captured the dump.
            data: Binary memory contents as bytes or bytearray.
            payload: Dictionary containing metadata (address, size, process_name).

        Side Effects:
            - Writes memory dump to binary file with timestamp
            - Logs operation details
            - Analyzes dump for protection patterns
        """
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
            with open(dump_file, "wb") as f:
                if isinstance(data, bytes):
                    f.write(data)
                else:
                    f.write(bytes(data))

            # Analyze memory dump for patterns
            self._analyze_memory_dump(data, payload)

        except Exception as e:
            logger.exception("Failed to save memory dump: %s", e)

    def _handle_screenshot_data(self, session_id: str, script_name: str, data: bytes | bytearray, payload: dict[str, Any]) -> None:
        """Handle screenshot data from Frida scripts.

        Processes screenshot data captured from the target application. Stores
        images and optionally performs OCR or pattern analysis.

        Args:
            session_id: Identifier for the source Frida session.
            script_name: Name of the script that captured the screenshot.
            data: Image binary data as bytes or bytearray.
            payload: Dictionary containing metadata (window_title, format, analyze).

        Side Effects:
            - Writes screenshot to image file with timestamp
            - Logs operation details
            - Performs OCR/pattern detection if requested
        """
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
            if payload.get("analyze"):
                self._analyze_screenshot(data, payload)

        except Exception as e:
            logger.exception("Failed to save screenshot: %s", e)

    def _handle_file_content(self, session_id: str, script_name: str, data: bytes | bytearray, payload: dict[str, Any]) -> None:
        """Handle file content intercepted by Frida scripts.

        Processes file read/write operations intercepted by Frida scripts.
        Analyzes files for licensing-related content.

        Args:
            session_id: Identifier for the source Frida session.
            script_name: Name of the script that intercepted the file operation.
            data: File content as bytes or bytearray.
            payload: Dictionary containing metadata (file_path, operation, size).

        Side Effects:
            - Logs file operation details
            - Analyzes license/config files
            - Tracks file persistence attempts
        """
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

    def _handle_network_packet(self, session_id: str, script_name: str, data: bytes | bytearray, payload: dict[str, Any]) -> None:
        """Handle network packet data from Frida scripts.

        Processes network traffic intercepted by Frida scripts. Analyzes packets
        for license server communication and network-based protection mechanisms.

        Args:
            session_id: Identifier for the source Frida session.
            script_name: Name of the script that intercepted the packet.
            data: Packet payload as bytes or bytearray.
            payload: Dictionary containing metadata (direction, protocol, addresses, ports).

        Side Effects:
            - Logs network operation details
            - Analyzes HTTP/HTTPS traffic for licensing
            - Tracks license server communication
        """
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

    def _handle_encrypted_data(self, session_id: str, script_name: str, data: bytes | bytearray, payload: dict[str, Any]) -> None:
        """Handle encrypted data intercepted by Frida scripts.

        Processes encrypted and decrypted data intercepted from cryptographic operations.
        Stores intercepted cryptographic material for analysis.

        Args:
            session_id: Identifier for the source Frida session.
            script_name: Name of the script that intercepted the data.
            data: Encrypted or decrypted payload as bytes or bytearray.
            payload: Dictionary containing metadata (algorithm, operation, key_info, iv).

        Side Effects:
            - Writes crypto data to binary file with timestamp
            - Logs operation details
            - Analyzes decrypted data if available
        """
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
            logger.exception("Failed to save crypto data: %s", e)

    def _handle_generic_binary_data(self, session_id: str, script_name: str, data: bytes | bytearray, payload: dict[str, Any]) -> None:
        """Handle generic binary data from Frida scripts.

        Args:
            session_id: Unique identifier for the Frida analysis session
            script_name: Name of the script that produced the data
            data: Raw binary data received from the Frida script
            payload: Dictionary containing metadata about the binary data including type and description

        """
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
            logger.exception("Failed to save binary data: %s", e)

    def _analyze_memory_dump(self, data: bytes | bytearray, payload: dict[str, Any]) -> None:
        """Analyze memory dump for interesting patterns.

        Args:
            data: Raw memory dump data to analyze
            payload: Dictionary containing metadata about the memory dump

        """
        # Convert to bytes if necessary
        if not isinstance(data, bytes):
            data = bytes(data)

        # Look for common patterns
        patterns: dict[str, list[bytes]] = {
            "license_key": [b"LICENSE", b"KEY", b"SERIAL", b"ACTIVATION"],
            "crypto_keys": [b"RSA", b"AES", b"-----BEGIN", b"-----END"],
            "urls": [b"http://", b"https://", b"ftp://"],
            "registry": [b"HKEY_", b"SOFTWARE\\", b"CurrentVersion"],
            "interesting_strings": [b"trial", b"expired", b"registered", b"cracked"],
        }

        findings: dict[str, list[dict[str, Any]]] = {}
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
                        },
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

    def _analyze_screenshot(self, data: bytes | bytearray, payload: dict[str, Any]) -> None:
        """Analyze screenshot for UI elements or text.

        Args:
            data: Raw screenshot image data to analyze
            payload: Dictionary containing metadata about the screenshot

        """
        # Analyze screenshot data for UI elements
        analysis_results: dict[str, Any] = {
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
                                },
                            )

            except Exception as e:
                logger.exception("Data analysis failed: %s", e)
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

    def _analyze_license_file(self, data: bytes | bytearray, file_path: str, payload: dict[str, Any]) -> None:
        """Analyze potential license file content.

        Args:
            data: Raw file content data to analyze
            file_path: Full path to the license file being analyzed
            payload: Dictionary containing metadata about the file operation

        """
        try:
            # Try to decode as text
            if isinstance(data, bytes):
                text_content = data.decode("utf-8", errors="ignore")
            else:
                text_content = str(data)

            # Look for license patterns
            license_indicators = ["expiry", "trial", "activation", "serial", "key", "license"]
            if found_indicators := [ind for ind in license_indicators if ind in text_content.lower()]:
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
            logger.debug("Failed to analyze license file: %s", e, exc_info=True)

    def _analyze_file_write(self, data: bytes | bytearray, file_path: str, payload: dict[str, Any]) -> None:
        """Analyze file write operations for suspicious activity.

        Args:
            data: Raw data being written to the file
            file_path: Full path to the file being modified
            payload: Dictionary containing metadata about the write operation

        """
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

    def _analyze_http_traffic(self, data: bytes | bytearray, payload: dict[str, Any]) -> None:
        """Analyze HTTP/HTTPS traffic for license checks.

        Args:
            data: Raw HTTP request/response data to analyze
            payload: Dictionary containing metadata about the network traffic

        """
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
            logger.debug("Failed to analyze HTTP traffic: %s", e, exc_info=True)

    def _analyze_license_traffic(self, data: bytes | bytearray, payload: dict[str, Any]) -> None:
        """Analyze potential license server communication.

        Args:
            data: Raw network data from license server communication
            payload: Dictionary containing metadata about the network connection

        """
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

    def _analyze_decrypted_data(self, data: bytes | bytearray, payload: dict[str, Any]) -> None:
        """Analyze decrypted data for interesting content.

        Args:
            data: Raw decrypted data to analyze
            payload: Dictionary containing metadata about the decryption operation

        """
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
            logger.debug("Failed to analyze decrypted data: %s", e, exc_info=True)

    def create_selective_instrumentation(self, target_apis: list[str], analysis_requirements: dict[str, Any]) -> str:
        """Create selective instrumentation based on analysis requirements.

        Args:
            target_apis: List of API names to instrument (format: "module!function")
            analysis_requirements: Dictionary specifying analysis requirements including trace_api_calls, monitor_memory, detect_protections

        Returns:
            Complete Frida instrumentation script as a string

        """
        script_parts = [
            "// Selective Instrumentation Script",
            "// Generated by Intellicrack Frida Manager",
            "",
        ]

        # Determine what to instrument based on requirements
        if analysis_requirements.get("trace_api_calls"):
            for api in target_apis:
                module, func = api.split("!") if "!" in api else ("unknown", api)
                # Determine hook priority
                priority = HookCategory.MEDIUM
                if "critical" in analysis_requirements.get("critical_apis", []) and api in analysis_requirements["critical_apis"]:
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
        """Generate optimized hook code.

        Args:
            module: Name of the DLL module containing the function (e.g., "kernel32.dll")
            function: Name of the function to hook
            priority: Hook priority level (CRITICAL, HIGH, MEDIUM, LOW)

        Returns:
            JavaScript Frida hook code as a string

        """
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
        """Generate memory monitoring code.

        Returns:
            JavaScript Frida code for memory allocation and deallocation tracking

        """
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
        """Generate protection detection code.

        Returns:
            JavaScript Frida code for detecting protection mechanisms and security checks

        """
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
        """Get comprehensive statistics.

        Returns:
            Dictionary containing statistics from logger, detector, batcher, optimizer, and active sessions/scripts

        """
        return {
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

    def export_analysis(self, output_path: str | None = None) -> str:
        """Export complete analysis results including script outputs.

        Args:
            output_path: Optional custom output directory path for analysis results

        Returns:
            Path to the directory containing exported analysis results

        """
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

    def save_script_output(self, script_name: str, output: dict[str, Any]) -> None:
        """Save script output for persistence.

        Args:
            script_name: Name of the script producing the output
            output: Output dictionary to save and persist

        """
        if script_name not in self.script_outputs:
            self.script_outputs[script_name] = []

        # Add timestamp to output
        output_with_metadata = {
            "timestamp": datetime.now().isoformat(),
            "script_name": script_name,
            "pid": output.get("pid"),
            "process_name": output.get("process_name"),
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

    def load_previous_results(self, script_name: str) -> list[dict[str, Any]]:
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
                with open(result_file) as f:
                    result = json.load(f)
                    results.append(result)
            except Exception as e:
                logger.exception("Failed to load result file %s: %s", result_file, e)

        # Sort by timestamp
        results.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

        return results

    def cleanup(self) -> None:
        """Clean up resources.

        Performs cleanup operations including stopping batching, detaching all
        Frida sessions, and clearing internal collections.

        Side Effects:
            - Stops batching operations
            - Detaches all active Frida sessions
            - Clears sessions and scripts collections

        """
        # Stop batching
        self.batcher.stop_batching()

        # Detach all sessions
        for session_id, session in self.sessions.items():
            try:
                session.detach()
                logger.debug("Detached session %s", session_id)
            except Exception as e:
                logger.exception("Failed to detach session %s: %s", session_id, e)

        # Clear collections
        self.sessions.clear()
        self.scripts.clear()

    def _handle_structured_message(self, session_id: str, script_name: str, payload: dict[str, Any]) -> None:
        """Handle structured messages from updated Frida scripts.

        Args:
            session_id: Unique identifier for the Frida analysis session
            script_name: Name of the script sending the message
            payload: Dictionary containing the structured message with type, target, action fields

        """
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

    def _handle_info_message(self, session_id: str, script_name: str, payload: dict[str, Any]) -> None:
        """Handle informational messages.

        Args:
            session_id: Unique identifier for the Frida analysis session
            script_name: Name of the script sending the message
            payload: Dictionary containing the informational message payload

        """
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

    def _handle_warning_message(self, session_id: str, script_name: str, payload: dict[str, Any]) -> None:
        """Handle warning messages.

        Args:
            session_id: Unique identifier for the Frida analysis session
            script_name: Name of the script sending the message
            payload: Dictionary containing the warning message payload

        """
        target = payload.get("target", script_name)
        action = payload.get("action", "warning")

        # Log as warning
        logger.warning("[%s] %s: %s", target, action, payload)

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

    def _handle_error_message(self, session_id: str, script_name: str, payload: dict[str, Any]) -> None:
        """Handle error messages.

        Args:
            session_id: Unique identifier for the Frida analysis session
            script_name: Name of the script sending the message
            payload: Dictionary containing the error message payload

        """
        target = payload.get("target", script_name)
        action = payload.get("action", "error")
        error_details = payload.get("error", "Unknown error")

        # Log as error
        logger.error("[%s] %s: %s", target, action, error_details)

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

    def _handle_status_message(self, session_id: str, script_name: str, payload: dict[str, Any]) -> None:
        """Handle status messages.

        Args:
            session_id: Unique identifier for the Frida analysis session
            script_name: Name of the script sending the message
            payload: Dictionary containing the status message payload

        """
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

    def _handle_bypass_message(self, session_id: str, script_name: str, payload: dict[str, Any]) -> None:
        """Handle bypass attempt messages.

        Args:
            session_id: Unique identifier for the Frida analysis session
            script_name: Name of the script sending the message
            payload: Dictionary containing the bypass attempt message payload

        """
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

    def _handle_success_message(self, session_id: str, script_name: str, payload: dict[str, Any]) -> None:
        """Handle success messages.

        Args:
            session_id: Unique identifier for the Frida analysis session
            script_name: Name of the script sending the message
            payload: Dictionary containing the success message payload

        """
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

    def _handle_detection_message(self, session_id: str, script_name: str, payload: dict[str, Any]) -> None:
        """Handle detection messages.

        Args:
            session_id: Unique identifier for the Frida analysis session
            script_name: Name of the script sending the message
            payload: Dictionary containing the detection message payload

        """
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

    def _handle_notification_message(self, session_id: str, script_name: str, payload: dict[str, Any]) -> None:
        """Handle notification messages.

        Args:
            session_id: Unique identifier for the Frida analysis session
            script_name: Name of the script sending the message
            payload: Dictionary containing the notification message payload

        """
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
        """Infer protection type from message context.

        Args:
            target: The target module or component being analyzed
            action: The action or operation being performed
            payload: Dictionary containing additional context information

        Returns:
            ProtectionType enum value inferred from the target and action context

        """
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
