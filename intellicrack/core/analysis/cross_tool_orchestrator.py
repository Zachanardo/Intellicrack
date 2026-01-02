"""Cross-Tool Analysis Orchestrator.

This module orchestrates analysis across multiple tools (Ghidra, Frida, Radare2)
and provides unified analysis workflows with result correlation.

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

from __future__ import annotations

import hashlib
import json
import logging
import mmap
import os
import queue
import struct
import threading
import time


from collections import defaultdict

from defusedxml import ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import psutil

from ...utils.core.plugin_paths import get_ghidra_scripts_dir
from ..frida_manager import FridaManager
from .ghidra_analyzer import GhidraFunction, MainAppProtocol, run_advanced_ghidra_analysis
from .ghidra_results import GhidraAnalysisResult
from .radare2_enhanced_integration import EnhancedR2Integration


if TYPE_CHECKING:
    from collections.abc import Callable


logger = logging.getLogger(__name__)


class MessageType(Enum):
    """Types of IPC messages."""

    DATA = 1
    STATUS = 2
    COMMAND = 3
    RESULT = 4
    ERROR = 5
    HEARTBEAT = 6
    SYNC = 7


class ToolStatus(Enum):
    """Tool execution status."""

    IDLE = "idle"
    INITIALIZING = "initializing"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    RECOVERING = "recovering"


class SharedMemoryIPC:
    """Windows-compatible shared memory IPC implementation."""

    def __init__(self, name: str, size: int = 10485760) -> None:  # 10MB default
        """Initialize shared memory IPC.

        Args:
            name: Unique identifier for shared memory segment
            size: Size of shared memory in bytes

        """
        self.name = f"Global\\{name}_intellicrack"
        self.size = size
        self.mmap_obj: mmap.mmap | None = None
        self.lock = threading.Lock()
        self.message_queue: queue.Queue[tuple[MessageType, Any]] = queue.Queue()
        self.is_creator = False

        # Message header format: msg_type(1) + size(4) + checksum(32) + data
        self.header_size = 37
        self.max_data_size = size - self.header_size

        self._initialize_shared_memory()

    def _initialize_shared_memory(self) -> None:
        """Create or connect to shared memory segment.

        Raises:
            Exception: If shared memory creation/connection fails.

        """
        try:
            # Try to create new shared memory
            self.mmap_obj = mmap.mmap(-1, self.size, tagname=self.name, access=mmap.ACCESS_WRITE)
            self.mmap_obj[: self.size] = b"\x00" * self.size
            self.is_creator = True
            logger.info("Created shared memory segment: %s", self.name)
        except Exception:
            # Connect to existing shared memory
            try:
                self.mmap_obj = mmap.mmap(-1, self.size, tagname=self.name, access=mmap.ACCESS_WRITE)
                logger.info("Connected to existing shared memory: %s", self.name)
            except Exception as conn_err:
                logger.exception("Failed to initialize shared memory: %s", conn_err)
                raise

    def send_message(self, msg_type: MessageType, data: dict[Any, Any] | list[Any] | str | int | bool | bytes | None) -> bool:
        """Send message through shared memory.

        Args:
            msg_type: Type of message
            data: Data to send (must be serializable)

        Returns:
            True if successful

        """
        with self.lock:
            try:
                if not self.mmap_obj:
                    logger.exception("Shared memory not initialized")
                    return False

                # Serialize data
                if isinstance(data, bytes):
                    serialized = data
                else:
                    serialized = json.dumps(data, ensure_ascii=False).encode("utf-8")
                if len(serialized) > self.max_data_size:
                    logger.exception("Message too large: %s > %s", len(serialized), self.max_data_size)
                    return False

                # Calculate checksum
                checksum = hashlib.sha256(serialized).hexdigest().encode("utf-8")

                # Pack message
                header = struct.pack("!BI", msg_type.value, len(serialized))
                message = header + checksum + serialized

                # Write to shared memory
                self.mmap_obj.seek(0)
                self.mmap_obj.write(message)
                self.mmap_obj.flush()

                return True

            except Exception as e:
                logger.exception("Failed to send message: %s", e)
                return False

    def receive_message(self) -> tuple[MessageType, Any] | None:
        """Receive message from shared memory.

        Returns:
            Tuple of (MessageType, data) or None

        """
        with self.lock:
            try:
                if not self.mmap_obj:
                    logger.exception("Shared memory not initialized")
                    return None

                # Read header
                self.mmap_obj.seek(0)
                header_data = self.mmap_obj.read(5)
                if not header_data or header_data == b"\x00" * 5:
                    return None

                msg_type_val, data_size = struct.unpack("!BI", header_data)
                msg_type = MessageType(msg_type_val)

                # Read checksum
                checksum = self.mmap_obj.read(32)

                # Read data
                data = self.mmap_obj.read(data_size)

                # Verify checksum
                calculated = hashlib.sha256(data).hexdigest().encode("utf-8")
                if checksum != calculated:
                    logger.exception("Checksum mismatch in received message")
                    return None

                # Deserialize
                deserialized = json.loads(data.decode("utf-8"))

                # Clear the message area
                self.mmap_obj.seek(0)
                self.mmap_obj.write(b"\x00" * (self.header_size + data_size))
                self.mmap_obj.flush()

                return (msg_type, deserialized)

            except Exception as e:
                logger.exception("Failed to receive message: %s", e)
                return None

    def cleanup(self) -> None:
        """Clean up shared memory resources."""
        if self.mmap_obj:
            try:
                self.mmap_obj.close()
                logger.info("Closed shared memory: %s", self.name)
            except Exception as e:
                logger.exception("Error closing shared memory: %s", e)


class ResultSerializer:
    """Serialization protocol for tool results."""

    PROTOCOL_VERSION = "1.0"

    @staticmethod
    def serialize_result(
        tool_name: str, result: dict[Any, Any] | list[Any] | str | object, metadata: dict[str, Any] | None = None
    ) -> bytes:
        """Serialize analysis result with metadata.

        Args:
            tool_name: Name of the tool
            result: Result data
            metadata: Optional metadata

        Returns:
            Serialized bytes

        Raises:
            TypeError: If package cannot be serialized to dict.

        """
        package = {
            "version": ResultSerializer.PROTOCOL_VERSION,
            "tool": tool_name,
            "timestamp": datetime.now().isoformat(),
            "result": result,
            "metadata": metadata or {},
        }

        # Handle special types
        if hasattr(result, "__dict__"):
            package["result"] = result.__dict__

        # Convert result to JSON-serializable format by converting datetime objects to strings
        def make_serializable(obj: object) -> object:
            """Convert object to JSON-serializable format.

            Args:
                obj: Object to convert.

            Returns:
                JSON-serializable representation of object.
            """
            if isinstance(obj, (datetime,)):
                return obj.isoformat()
            if isinstance(obj, dict):
                return {key: make_serializable(value) for key, value in obj.items()}
            if isinstance(obj, list):
                return [make_serializable(item) for item in obj]
            return obj

        serializable_package = make_serializable(package)
        if not isinstance(serializable_package, dict):
            raise TypeError("Package must be serializable to dict")
        return json.dumps(serializable_package, ensure_ascii=False).encode("utf-8")

    @staticmethod
    def deserialize_result(data: bytes) -> dict[str, Any]:
        """Deserialize analysis result.

        Args:
            data: Serialized data

        Returns:
            Deserialized package

        """
        try:
            decoded: Any = json.loads(data.decode("utf-8"))
            if not isinstance(decoded, dict):
                logger.exception("Decoded data is not a dictionary")
                return {}
            package: dict[str, Any] = decoded

            # Validate version
            if package.get("version") != ResultSerializer.PROTOCOL_VERSION:
                logger.warning("Protocol version mismatch: %s != %s", package.get("version"), ResultSerializer.PROTOCOL_VERSION)

            return package

        except Exception as e:
            logger.exception("Failed to deserialize result: %s", e)
            return {}


class ToolMonitor:
    """Monitor tool processes and status."""

    def __init__(self) -> None:
        """Initialize tool monitor."""
        self.processes: dict[str, psutil.Process] = {}
        self.status: dict[str, ToolStatus] = {}
        self.metrics: dict[str, dict[str, Any]] = {}
        self.monitoring_thread: threading.Thread | None = None
        self.stop_monitoring = threading.Event()

    def register_process(self, tool_name: str, pid: int) -> None:
        """Register a tool process for monitoring.

        Args:
            tool_name: Name of the tool
            pid: Process ID

        """
        try:
            process = psutil.Process(pid)
            self.processes[tool_name] = process
            self.status[tool_name] = ToolStatus.RUNNING
            self.metrics[tool_name] = {
                "cpu_percent": [],
                "memory_mb": [],
                "io_read_mb": 0,
                "io_write_mb": 0,
            }
            logger.info("Registered process %s for tool %s", pid, tool_name)
        except psutil.NoSuchProcess:
            logger.exception("Process %s not found for tool %s", pid, tool_name)
            self.status[tool_name] = ToolStatus.FAILED

    def start_monitoring(self, interval: float = 1.0) -> None:
        """Start monitoring registered processes.

        Args:
            interval: Monitoring interval in seconds

        """

        def monitor_loop() -> None:
            """Monitor tool processes in a loop.

            Continuously collects CPU and memory metrics for all registered
            processes. Removes processes that are no longer running and
            limits memory usage by keeping only last 100 metric samples.

            """
            while not self.stop_monitoring.is_set():
                for tool_name, process in list(self.processes.items()):
                    try:
                        if process.is_running():
                            # Collect metrics
                            cpu = process.cpu_percent()
                            memory = process.memory_info().rss / 1024 / 1024  # MB
                            io = process.io_counters()

                            self.metrics[tool_name]["cpu_percent"].append(cpu)
                            self.metrics[tool_name]["memory_mb"].append(memory)
                            self.metrics[tool_name]["io_read_mb"] = io.read_bytes / 1024 / 1024
                            self.metrics[tool_name]["io_write_mb"] = io.write_bytes / 1024 / 1024

                            # Keep only last 100 samples
                            if len(self.metrics[tool_name]["cpu_percent"]) > 100:
                                self.metrics[tool_name]["cpu_percent"].pop(0)
                                self.metrics[tool_name]["memory_mb"].pop(0)
                        else:
                            self.status[tool_name] = ToolStatus.COMPLETED
                            del self.processes[tool_name]

                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        self.status[tool_name] = ToolStatus.FAILED
                        if tool_name in self.processes:
                            del self.processes[tool_name]

                self.stop_monitoring.wait(interval)

        self.monitoring_thread = threading.Thread(target=monitor_loop, daemon=True)
        self.monitoring_thread.start()
        logger.info("Started tool monitoring")

    def stop(self) -> None:
        """Stop monitoring."""
        self.stop_monitoring.set()
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=2)
        logger.info("Stopped tool monitoring")

    def get_status(self, tool_name: str) -> ToolStatus:
        """Get tool status.

        Args:
            tool_name: Name of the tool

        Returns:
            Current tool status

        """
        return self.status.get(tool_name, ToolStatus.IDLE)

    def get_metrics(self, tool_name: str) -> dict[str, Any]:
        """Get tool metrics.

        Args:
            tool_name: Name of the tool

        Returns:
            Tool metrics dictionary

        """
        metrics = self.metrics.get(tool_name, {})
        if metrics and metrics.get("cpu_percent"):
            metrics["avg_cpu"] = sum(metrics["cpu_percent"]) / len(metrics["cpu_percent"])
            metrics["avg_memory"] = sum(metrics["memory_mb"]) / len(metrics["memory_mb"])
        return metrics


class FailureRecovery:
    """Handle tool failure and recovery."""

    def __init__(self, max_retries: int = 3) -> None:
        """Initialize failure recovery.

        Args:
            max_retries: Maximum retry attempts

        """
        self.max_retries = max_retries
        self.retry_counts: dict[str, int] = {}
        self.failure_history: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.recovery_strategies: dict[str, Callable[[Exception, dict[str, Any] | None], None]] = {}

    def register_recovery_strategy(self, tool_name: str, strategy: Callable[[Exception, dict[str, Any] | None], None]) -> None:
        """Register recovery strategy for a tool.

        Args:
            tool_name: Name of the tool
            strategy: Recovery function to call on failure

        """
        self.recovery_strategies[tool_name] = strategy
        logger.info("Registered recovery strategy for %s", tool_name)

    def handle_failure(self, tool_name: str, error: Exception, context: dict[str, Any] | None = None) -> bool:
        """Handle tool failure with recovery.

        Args:
            tool_name: Name of failed tool
            error: Exception that occurred
            context: Optional context information

        Returns:
            True if recovery successful

        """
        # Record failure
        self.failure_history[tool_name].append({"timestamp": datetime.now().isoformat(), "error": str(error), "context": context or {}})

        # Check retry count
        self.retry_counts[tool_name] = self.retry_counts.get(tool_name, 0) + 1
        if self.retry_counts[tool_name] > self.max_retries:
            logger.exception("Max retries exceeded for %s", tool_name)
            return False

        logger.warning("Attempting recovery for %s (attempt %s)", tool_name, self.retry_counts[tool_name])

        # Execute recovery strategy
        if tool_name in self.recovery_strategies:
            try:
                self.recovery_strategies[tool_name](error, context)
                logger.info("Recovery successful for %s", tool_name)
                return True
            except Exception as recovery_error:
                logger.exception("Recovery failed for %s: %s", tool_name, recovery_error)
                return False
        else:
            # Default recovery: wait and retry
            time.sleep(2 ** self.retry_counts[tool_name])  # Exponential backoff
            return True

    def reset_retry_count(self, tool_name: str) -> None:
        """Reset retry count for successful execution.

        Args:
            tool_name: Name of the tool

        """
        self.retry_counts[tool_name] = 0

    def get_failure_history(self, tool_name: str) -> list[dict[str, Any]]:
        """Get failure history for a tool.

        Args:
            tool_name: Name of the tool

        Returns:
            List of failure records

        """
        return self.failure_history.get(tool_name, [])


class ResultConflictResolver:
    """Resolve conflicts between tool results."""

    def __init__(self) -> None:
        """Initialize conflict resolver."""
        self.resolution_rules: list[tuple[int, Callable[[list[CorrelatedFunction]], CorrelatedFunction | None]]] = []
        self.conflict_log: list[dict[str, Any]] = []

    def add_resolution_rule(self, rule: Callable[[list[CorrelatedFunction]], CorrelatedFunction | None], priority: int = 0) -> None:
        """Add conflict resolution rule.

        Args:
            rule: Function that takes conflicting results and returns resolved result
            priority: Rule priority (higher = more important)

        """
        self.resolution_rules.append((priority, rule))
        self.resolution_rules.sort(key=lambda x: x[0], reverse=True)

    def resolve_function_conflicts(self, functions: list[CorrelatedFunction]) -> list[CorrelatedFunction]:
        """Resolve conflicts in function data.

        Args:
            functions: List of potentially conflicting functions

        Returns:
            Resolved function list

        """
        resolved: list[CorrelatedFunction] = []
        function_groups: dict[str, list[CorrelatedFunction]] = defaultdict(list)

        # Group by similar names (fuzzy matching)
        for func in functions:
            matched = False
            for key in function_groups:
                if self._fuzzy_match(func.name, key):
                    function_groups[key].append(func)
                    matched = True
                    break
            if not matched:
                function_groups[func.name].append(func)

        # Resolve each group
        for name, group in function_groups.items():
            if len(group) == 1:
                resolved.append(group[0])
            else:
                if resolved_func := self._apply_resolution_rules(group):
                    resolved.append(resolved_func)
                else:
                    # Default: merge data with highest confidence
                    merged = self._merge_functions(group)
                    resolved.append(merged)

                # Log conflict
                self.conflict_log.append({
                    "type": "function",
                    "name": name,
                    "sources": len(group),
                    "resolution": "merged",
                })

        return resolved

    def _fuzzy_match(self, name1: str, name2: str) -> bool:
        """Check if two names are similar enough to be the same function.

        Args:
            name1: First function name
            name2: Second function name

        Returns:
            True if names match

        """
        # Remove common prefixes/suffixes
        clean1 = name1.replace("sub_", "").replace("loc_", "").replace("_", "")
        clean2 = name2.replace("sub_", "").replace("loc_", "").replace("_", "")

        # Check exact match after cleaning
        if clean1 == clean2:
            return True

        # Check if one contains the other
        if clean1 in clean2 or clean2 in clean1:
            return True

        # Calculate similarity ratio
        return self._similarity_ratio(clean1, clean2) > 0.8

    def _similarity_ratio(self, s1: str, s2: str) -> float:
        """Calculate similarity between two strings.

        Args:
            s1: First string
            s2: Second string

        Returns:
            Similarity ratio (0-1)

        """
        if not s1 or not s2:
            return 0.0

        # Simple character-based similarity
        common = sum(c1 == c2 for c1, c2 in zip(s1, s2, strict=False))
        return common / max(len(s1), len(s2))

    def _apply_resolution_rules(self, group: list[CorrelatedFunction]) -> CorrelatedFunction | None:
        """Apply resolution rules to conflicting functions.

        Args:
            group: Group of conflicting functions

        Returns:
            Resolved function or None

        """
        for _priority, rule in self.resolution_rules:
            try:
                if result := rule(group):
                    return result
            except Exception as e:
                logger.exception("Resolution rule failed: %s", e)
        return None

    def _merge_functions(self, group: list[CorrelatedFunction]) -> CorrelatedFunction:
        """Merge multiple functions into one.

        Args:
            group: Functions to merge

        Returns:
            Merged function

        """
        # Start with highest confidence function
        group.sort(key=lambda f: f.confidence_score, reverse=True)
        merged = CorrelatedFunction(
            name=group[0].name,
            ghidra_data=group[0].ghidra_data,
            r2_data=group[0].r2_data,
            frida_data=group[0].frida_data,
            addresses=dict(group[0].addresses),
            sizes=dict(group[0].sizes),
            confidence_score=group[0].confidence_score,
            notes=list(group[0].notes),
        )

        # Merge data from others
        for func in group[1:]:
            if func.ghidra_data and merged.ghidra_data is None:
                merged.ghidra_data = func.ghidra_data
            if func.r2_data and merged.r2_data is None:
                merged.r2_data = func.r2_data
            if func.frida_data and merged.frida_data is None:
                merged.frida_data = func.frida_data

            # Merge addresses
            for tool, addr in func.addresses.items():
                if tool not in merged.addresses:
                    merged.addresses[tool] = addr

            # Merge sizes
            for tool, size in func.sizes.items():
                if tool not in merged.sizes:
                    merged.sizes[tool] = size

            # Combine notes
            merged.notes.extend(func.notes)

        # Recalculate confidence
        sources = sum([
            1 if merged.ghidra_data else 0,
            1 if merged.r2_data else 0,
            1 if merged.frida_data else 0,
        ])
        merged.confidence_score = sources / 3.0

        return merged


class LoadBalancer:
    """Balance analysis load across tools and resources."""

    def __init__(self, cpu_threshold: float = 80.0, memory_threshold: float = 80.0) -> None:
        """Initialize load balancer.

        Args:
            cpu_threshold: CPU usage threshold percentage
            memory_threshold: Memory usage threshold percentage

        """
        self.cpu_threshold = cpu_threshold
        self.memory_threshold = memory_threshold
        self.tool_queue: queue.PriorityQueue[tuple[int, str, dict[str, float]]] = queue.PriorityQueue()
        self.resource_monitor = None
        self.balancing_enabled = True

    def get_system_load(self) -> dict[str, float]:
        """Get current system load metrics.

        Returns:
            Dictionary with CPU and memory usage

        """
        return {
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_io": psutil.disk_io_counters(),
        }

    def can_start_tool(self, tool_name: str, estimated_resources: dict[str, float]) -> bool:
        """Check if system can handle starting a new tool.

        Args:
            tool_name: Name of the tool
            estimated_resources: Estimated resource requirements

        Returns:
            True if tool can be started

        """
        if not self.balancing_enabled:
            return True

        current_load = self.get_system_load()

        # Check CPU
        if current_load["cpu_percent"] + estimated_resources.get("cpu", 0) > self.cpu_threshold:
            logger.warning("CPU threshold would be exceeded by starting %s", tool_name)
            return False

        # Check memory
        if current_load["memory_percent"] + estimated_resources.get("memory", 0) > self.memory_threshold:
            logger.warning("Memory threshold would be exceeded by starting %s", tool_name)
            return False

        return True

    def schedule_tool(self, tool_name: str, priority: int = 5, estimated_resources: dict[str, float] | None = None) -> None:
        """Schedule tool for execution.

        Args:
            tool_name: Name of the tool
            priority: Execution priority (lower = higher priority)
            estimated_resources: Estimated resource requirements

        """
        self.tool_queue.put((priority, tool_name, estimated_resources or {}))

    def get_next_tool(self) -> tuple[str, dict[str, float]] | None:
        """Get next tool to execute based on load.

        Returns:
            Tuple of (tool_name, estimated_resources) or None

        """
        while not self.tool_queue.empty():
            priority, tool_name, resources = self.tool_queue.get()

            if self.can_start_tool(tool_name, resources):
                return (tool_name, resources)
            # Re-queue with lower priority
            self.tool_queue.put((priority + 1, tool_name, resources))
            time.sleep(1)  # Wait before checking next

        return None

    def optimize_parallel_execution(self, tools: list[str]) -> list[list[str]]:
        """Optimize tool execution order for parallel processing.

        Args:
            tools: List of tools to execute

        Returns:
            List of tool batches for parallel execution

        """
        # Estimate resources for each tool
        tool_resources = {
            "ghidra": {"cpu": 30, "memory": 20},
            "radare2": {"cpu": 25, "memory": 15},
            "frida": {"cpu": 20, "memory": 10},
            "ida": {"cpu": 35, "memory": 25},
        }

        batches = []
        current_batch = []
        current_cpu = 0
        current_memory = 0

        for tool in tools:
            resources = tool_resources.get(tool, {"cpu": 20, "memory": 10})

            if current_cpu + resources["cpu"] <= self.cpu_threshold and current_memory + resources["memory"] <= self.memory_threshold:
                current_batch.append(tool)
                current_cpu += resources["cpu"]
                current_memory += resources["memory"]
            else:
                if current_batch:
                    batches.append(current_batch)
                current_batch = [tool]
                current_cpu = resources["cpu"]
                current_memory = resources["memory"]

        if current_batch:
            batches.append(current_batch)

        return batches


@dataclass
class CorrelatedFunction:
    """Function data correlated across multiple tools."""

    name: str
    ghidra_data: dict[str, Any] | None = None
    r2_data: dict[str, Any] | None = None
    frida_data: dict[str, Any] | None = None
    addresses: dict[str, int] = field(default_factory=dict)
    sizes: dict[str, int] = field(default_factory=dict)
    confidence_score: float = 0.0
    notes: list[str] = field(default_factory=list)


@dataclass
class CorrelatedString:
    """String data correlated across tools."""

    value: str
    ghidra_refs: list[int] = field(default_factory=list)
    r2_refs: list[int] = field(default_factory=list)
    frida_refs: list[int] = field(default_factory=list)
    is_license_related: bool = False
    is_crypto_related: bool = False
    importance_score: float = 0.0


@dataclass
class UnifiedAnalysisResult:
    """Unified result from cross-tool analysis."""

    binary_path: str
    timestamp: datetime
    functions: list[CorrelatedFunction] = field(default_factory=list)
    strings: list[CorrelatedString] = field(default_factory=list)
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    protection_mechanisms: list[dict[str, Any]] = field(default_factory=list)
    bypass_strategies: list[dict[str, Any]] = field(default_factory=list)
    memory_maps: dict[str, Any] = field(default_factory=dict)
    call_graph: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


class CrossToolOrchestrator:
    """Orchestrates analysis across multiple binary analysis tools."""

    def __init__(self, binary_path: str, main_app: object | None = None) -> None:
        """Initialize the orchestrator.

        Args:
            binary_path: Path to the binary to analyze
            main_app: Optional reference to main application for GUI updates

        """
        self.binary_path = binary_path
        self.main_app = main_app
        self.logger = logger

        # Tool instances
        self.ghidra_results: GhidraAnalysisResult | None = None
        self.r2_integration: EnhancedR2Integration | None = None
        self.frida_manager: FridaManager | None = None

        # Analysis state
        self.analysis_complete = {"ghidra": False, "radare2": False, "frida": False}
        self.analysis_results: dict[str, Any] = {"ghidra": None, "radare2": None, "frida": None}

        # Threading
        self.analysis_lock = threading.Lock()
        self.analysis_threads: list[threading.Thread] = []

        # IPC and communication
        self.ipc_channel = SharedMemoryIPC(f"intellicrack_{os.getpid()}")
        self.result_serializer = ResultSerializer()

        # Monitoring and recovery
        self.tool_monitor = ToolMonitor()
        self.failure_recovery = FailureRecovery(max_retries=3)
        self.tool_monitor.start_monitoring()

        # Conflict resolution
        self.conflict_resolver = ResultConflictResolver()
        self._setup_resolution_rules()

        # Load balancing
        self.load_balancer = LoadBalancer()

        # Initialize tools
        self._initialize_tools()

        # Setup recovery strategies
        self._setup_recovery_strategies()

    def _setup_resolution_rules(self) -> None:
        """Set up conflict resolution rules for tool results.

        Configures rules to resolve conflicts when multiple analysis tools
        produce different results for the same functions. Rules are prioritized
        to prefer debug symbols and comprehensive cross-references.

        """

        # Rule 1: Prefer results with debug symbols
        def prefer_debug_symbols(functions: list[CorrelatedFunction]) -> CorrelatedFunction | None:
            """Prefer functions with debug symbol information.

            Args:
                functions: List of correlated functions.

            Returns:
                Function with debug information or None if no function has
                    debug symbols.

            """
            for func in functions:
                if func.ghidra_data and func.ghidra_data.get("has_debug_info"):
                    return func
                if func.r2_data and func.r2_data.get("has_symbols"):
                    return func
            return None

        # Rule 2: Prefer results with more cross-references
        def prefer_more_xrefs(functions: list[CorrelatedFunction]) -> CorrelatedFunction | None:
            """Prefer functions with most cross-references.

            Args:
                functions: List of correlated functions.

            Returns:
                Function with most cross-references or None if empty list
                    is provided.

            """
            max_xrefs = 0
            best_func = None
            for func in functions:
                xrefs = 0
                if func.ghidra_data:
                    xrefs += len(func.ghidra_data.get("xrefs", []))
                if func.r2_data:
                    xrefs += len(func.r2_data.get("xrefs", []))
                if xrefs > max_xrefs:
                    max_xrefs = xrefs
                    best_func = func
            return best_func

        self.conflict_resolver.add_resolution_rule(prefer_debug_symbols, priority=10)
        self.conflict_resolver.add_resolution_rule(prefer_more_xrefs, priority=5)

    def _setup_recovery_strategies(self) -> None:
        """Set up recovery strategies for tool failures.

        Registers recovery handlers for each analysis tool to handle transient
        failures and resource cleanup. Strategies include process termination,
        temporary file cleanup, and tool reinitialization.

        """

        # Ghidra recovery strategy
        def ghidra_recovery(error: Exception, context: dict[str, Any] | None) -> None:
            """Recover from Ghidra analysis failures.

            Args:
                error: Exception that occurred.
                context: Optional context information.

            """
            self.logger.info("Attempting Ghidra recovery")
            # Kill any hanging Ghidra process
            for proc in psutil.process_iter(["name"]):
                if "ghidra" in proc.info["name"].lower():
                    try:
                        proc.terminate()
                        proc.wait(timeout=5)
                    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                        proc.kill()
            # Clear temp files
            import tempfile

            temp_base = Path(tempfile.gettempdir())
            temp_dir = temp_base / "ghidra_temp"
            if temp_dir.exists():
                import shutil

                shutil.rmtree(temp_dir, ignore_errors=True)
            time.sleep(2)

        # Radare2 recovery strategy
        def r2_recovery(error: Exception, context: dict[str, Any] | None) -> None:
            """Recover from Radare2 analysis failures.

            Cleans up the Radare2 integration and reinitializes it to restore
            functional state after transient failures.

            Args:
                error: Exception that occurred.
                context: Optional context information.

            """
            self.logger.info("Attempting Radare2 recovery")
            # Re-initialize r2 integration
            if self.r2_integration:
                self.r2_integration.cleanup()
            time.sleep(1)
            self.r2_integration = EnhancedR2Integration(self.binary_path)

        # Frida recovery strategy
        def frida_recovery(error: Exception, context: dict[str, Any] | None) -> None:
            """Recover from Frida analysis failures.

            Cleans up the Frida manager and reinitializes it to restore
            functional state after transient failures.

            Args:
                error: Exception that occurred.
                context: Optional context information.

            """
            self.logger.info("Attempting Frida recovery")
            if self.frida_manager:
                self.frida_manager.cleanup()
            time.sleep(1)
            self.frida_manager = FridaManager()

        self.failure_recovery.register_recovery_strategy("ghidra", ghidra_recovery)
        self.failure_recovery.register_recovery_strategy("radare2", r2_recovery)
        self.failure_recovery.register_recovery_strategy("frida", frida_recovery)

    def _initialize_tools(self) -> None:
        """Initialize analysis tools.

        Sets up instances of Radare2, Frida, and Ghidra analysis tools.
        Tools are registered with the monitor and marked as IDLE. Failures
        in tool initialization are logged but do not prevent orchestrator
        instantiation.

        """
        try:
            # Initialize Radare2
            self.r2_integration = EnhancedR2Integration(self.binary_path)
            self.logger.info("Initialized Radare2 integration")
            self.tool_monitor.status["radare2"] = ToolStatus.IDLE

            # Initialize Frida if available
            try:
                self.frida_manager = FridaManager()
                self.logger.info("Initialized Frida manager")
                self.tool_monitor.status["frida"] = ToolStatus.IDLE
            except Exception as e:
                self.logger.warning("Frida initialization failed: %s", e)
                self.frida_manager = None
                self.tool_monitor.status["frida"] = ToolStatus.FAILED

            self.tool_monitor.status["ghidra"] = ToolStatus.IDLE

        except Exception as e:
            self.logger.exception("Failed to initialize tools: %s", e)

    def run_parallel_analysis(self, tools: list[str] | None = None) -> UnifiedAnalysisResult:
        """Run analysis in parallel across specified tools.

        Optimizes tool execution order based on resource constraints and
        batches tools to avoid resource exhaustion. Uses load balancing to
        determine which tools can be started simultaneously.

        Args:
            tools: List of tools to use ['ghidra', 'radare2', 'frida'] or
                None for all tools.

        Returns:
            UnifiedAnalysisResult containing correlated data from all tools.

        """
        if tools is None:
            tools = ["ghidra", "radare2", "frida"]

        self.logger.info("Starting parallel analysis with tools: %s", tools)

        # Use load balancer to optimize execution
        batches = self.load_balancer.optimize_parallel_execution(tools)
        self.logger.info("Optimized execution batches: %s", batches)

        for batch_idx, batch in enumerate(batches):
            self.logger.info("Starting batch %s: %s", batch_idx + 1, batch)
            batch_threads = []

            for tool in batch:
                # Check if tool can be started
                resources_map: dict[str, dict[str, float]] = {
                    "ghidra": {"cpu": 30.0, "memory": 20.0},
                    "radare2": {"cpu": 25.0, "memory": 15.0},
                    "frida": {"cpu": 20.0, "memory": 10.0},
                }
                resources: dict[str, float] = resources_map.get(tool, {"cpu": 20.0, "memory": 10.0})

                if not self.load_balancer.can_start_tool(tool, resources):
                    self.logger.warning("Skipping %s due to resource constraints", tool)
                    continue

                # Update tool status
                self.tool_monitor.status[tool] = ToolStatus.INITIALIZING

                # Start analysis thread
                if tool == "ghidra":
                    thread = threading.Thread(target=self._run_ghidra_analysis_with_ipc, daemon=True)
                elif tool == "radare2":
                    thread = threading.Thread(target=self._run_radare2_analysis_with_ipc, daemon=True)
                elif tool == "frida" and self.frida_manager:
                    thread = threading.Thread(target=self._run_frida_analysis_with_ipc, daemon=True)
                else:
                    continue

                thread.start()
                batch_threads.append((tool, thread))
                self.analysis_threads.append(thread)

                # Register process for monitoring (if we have PID)
                if tool == "radare2" and self.r2_integration:
                    self.tool_monitor.register_process(tool, os.getpid())

            # Wait for batch to complete
            for tool, thread in batch_threads:
                thread.join(timeout=60)
                if thread.is_alive():
                    self.logger.exception("%s analysis timed out", tool)
                    self.tool_monitor.status[tool] = ToolStatus.FAILED

            # Small delay between batches
            if batch_idx < len(batches) - 1:
                time.sleep(2)

        # Correlate results with conflict resolution
        return self._correlate_results_with_resolution()

    def run_sequential_analysis(self, workflow: list[dict[str, Any]]) -> UnifiedAnalysisResult:
        """Run analysis sequentially with data flow between tools.

        Executes analysis steps in order with dependency resolution. Each step
        waits for its dependencies to complete before running. Tools can pass
        intermediate results to downstream tools.

        Args:
            workflow: List of workflow steps with tool and configuration.
                Each step should contain 'tool', 'config', and optional
                'depends_on' fields.

        Returns:
            Unified analysis result from sequential tool execution.

        """
        self.logger.info("Starting sequential analysis with %s steps", len(workflow))

        for step in workflow:
            tool = step.get("tool")
            config = step.get("config", {})
            depends_on = step.get("depends_on", [])

            # Wait for dependencies
            for dep in depends_on:
                while not self.analysis_complete.get(dep, False):
                    time.sleep(0.5)

            # Run analysis
            if tool == "ghidra":
                self._run_ghidra_analysis(config)
            elif tool == "radare2":
                self._run_radare2_analysis(config)
            elif tool == "frida":
                self._run_frida_analysis(config)
            else:
                self.logger.warning("Unknown tool in workflow: %s", tool)

        return self._correlate_results()

    def _run_ghidra_analysis_with_ipc(self, config: dict[str, Any] | None = None) -> None:
        """Run Ghidra analysis with IPC communication.

        Executes Ghidra headless analysis or uses GUI integration if available.
        Results are serialized and transmitted via shared memory IPC. Handles
        recovery from transient failures via the failure recovery mechanism.

        Args:
            config: Optional configuration parameters for analysis.

        Raises:
            ValueError: If command validation fails or binary path is unsafe.

        """
        try:
            self.tool_monitor.status["ghidra"] = ToolStatus.RUNNING
            self.logger.info("Starting Ghidra analysis with IPC")

            # Send start message via IPC
            self.ipc_channel.send_message(
                MessageType.STATUS,
                {"tool": "ghidra", "status": "starting", "timestamp": datetime.now().isoformat()},
            )

            if self.main_app:
                # Use GUI integration
                run_advanced_ghidra_analysis(cast("MainAppProtocol", self.main_app))
                self.ghidra_results = GhidraAnalysisResult(
                    binary_path=self.binary_path,
                    architecture="",
                    compiler="",
                    functions={},
                    data_types={},
                    strings=[],
                    imports=[],
                    exports=[],
                    sections=[],
                    entry_point=0,
                    image_base=0,
                    vtables={},
                    exception_handlers=[],
                )
            else:
                # Run Ghidra headless and parse real output
                import subprocess
                import tempfile

                ghidra_path = os.environ.get("GHIDRA_HOME", "C:\\ghidra")
                script_path = os.path.join(ghidra_path, "support", "analyzeHeadless.bat")

                with tempfile.TemporaryDirectory() as project_dir:
                    project_name = "intellicrack_analysis"

                    # Run Ghidra headless analysis
                    cmd = [
                        script_path,
                        project_dir,
                        project_name,
                        "-import",
                        self.binary_path,
                        "-scriptPath",
                        str(get_ghidra_scripts_dir()),
                        "-postScript",
                        "ExportAnalysisData.java",
                        "-overwrite",
                    ]

                    # Validate that cmd contains only safe, expected commands
                    if not isinstance(cmd, list) or not all(isinstance(arg, str) for arg in cmd):
                        raise ValueError(f"Unsafe command: {cmd}")
                    subprocess.run(cmd, capture_output=True, text=True, timeout=300, shell=False)

                    # Parse Ghidra output files
                    output_file = os.path.join(project_dir, f"{os.path.basename(self.binary_path)}_analysis.xml")
                    functions = []
                    strings = []
                    imports = []

                    if os.path.exists(output_file):
                        tree = ET.parse(output_file)
                        root = tree.getroot()

                        # Parse functions
                        for func_elem in root.findall(".//function"):
                            functions.append(
                                {
                                    "name": func_elem.get("name"),
                                    "address": int(func_elem.get("address", "0"), 16),
                                    "size": int(func_elem.get("size", "0")),
                                    "signature": func_elem.get("signature", ""),
                                    "xrefs": [int(x.text, 16) for x in func_elem.findall(".//xref")],
                                },
                            )

                        # Parse strings
                        for str_elem in root.findall(".//string"):
                            strings.append(
                                {
                                    "value": str_elem.get("value"),
                                    "address": int(str_elem.get("address", "0"), 16),
                                    "xrefs": [int(x.text, 16) for x in str_elem.findall(".//xref")],
                                },
                            )

                        # Parse imports
                        for imp_elem in root.findall(".//import"):
                            imports.append(
                                {
                                    "name": imp_elem.get("name"),
                                    "library": imp_elem.get("library"),
                                    "address": int(imp_elem.get("address", "0"), 16),
                                },
                            )

                    # Create analysis result
                    self.ghidra_results = GhidraAnalysisResult(
                        binary_path=self.binary_path,
                        architecture="",
                        compiler="",
                        functions={
                            f["address"]: GhidraFunction(
                                name=f["name"],
                                address=f["address"],
                                size=f["size"],
                                signature=f.get("signature", ""),
                                return_type="",
                                parameters=[],
                                local_variables=[],
                                decompiled_code="",
                                assembly_code="",
                                xrefs_to=f.get("xrefs", []),
                                xrefs_from=[],
                                comments={},
                            )
                            for f in functions
                        },
                        data_types={},
                        strings=[(s["address"], s["value"]) for s in strings],
                        imports=[(i["library"], i["name"], i["address"]) for i in imports],
                        exports=[],
                        sections=[],
                        entry_point=0,
                        image_base=0,
                        vtables={},
                        exception_handlers=[],
                    )

            # Serialize and send results via IPC
            serialized = self.result_serializer.serialize_result("ghidra", self.ghidra_results, {"config": config})
            self.ipc_channel.send_message(MessageType.RESULT, serialized)

            with self.analysis_lock:
                self.analysis_complete["ghidra"] = True
                if self.ghidra_results:
                    self.analysis_results["ghidra"] = self.ghidra_results

            self.tool_monitor.status["ghidra"] = ToolStatus.COMPLETED
            self.failure_recovery.reset_retry_count("ghidra")
            self.logger.info("Ghidra analysis complete")

        except Exception as e:
            self.logger.exception("Ghidra analysis failed: %s", e)
            self.tool_monitor.status["ghidra"] = ToolStatus.FAILED

            # Try recovery
            if self.failure_recovery.handle_failure("ghidra", e, config):
                # Retry the analysis
                self._run_ghidra_analysis_with_ipc(config)
            else:
                with self.analysis_lock:
                    self.analysis_complete["ghidra"] = True

    def _run_ghidra_analysis(self, config: dict[str, Any] | None = None) -> None:
        """Run Ghidra analysis (legacy method for compatibility).

        Wrapper for _run_ghidra_analysis_with_ipc to maintain backwards
        compatibility with sequential workflow calling convention.

        Args:
            config: Optional configuration parameters for analysis.

        """
        self._run_ghidra_analysis_with_ipc(config)

    def _run_radare2_analysis_with_ipc(self, config: dict[str, Any] | None = None) -> None:
        """Run Radare2 analysis with IPC communication.

        Executes comprehensive Radare2 analysis including decompilation,
        function extraction, and vulnerability scanning. Results are serialized
        and transmitted via shared memory IPC. Handles recovery from transient
        failures via the failure recovery mechanism.

        Args:
            config: Optional configuration parameters for analysis. Can include
                'analysis_types' to specify which analysis components to run.

        """
        try:
            self.tool_monitor.status["radare2"] = ToolStatus.RUNNING
            self.logger.info("Starting Radare2 analysis with IPC")

            # Send start message via IPC
            self.ipc_channel.send_message(
                MessageType.STATUS,
                {"tool": "radare2", "status": "starting", "timestamp": datetime.now().isoformat()},
            )

            if not self.r2_integration:
                self.r2_integration = EnhancedR2Integration(self.binary_path)

            # Run comprehensive analysis
            analysis_types = config.get("analysis_types") if config else None
            results = self.r2_integration.run_comprehensive_analysis(analysis_types)

            # Serialize and send results via IPC
            serialized = self.result_serializer.serialize_result("radare2", results, {"config": config})
            self.ipc_channel.send_message(MessageType.RESULT, serialized)

            with self.analysis_lock:
                self.analysis_complete["radare2"] = True
                if results:
                    self.analysis_results["radare2"] = results

            self.tool_monitor.status["radare2"] = ToolStatus.COMPLETED
            self.failure_recovery.reset_retry_count("radare2")
            self.logger.info("Radare2 analysis complete")

        except Exception as e:
            self.logger.exception("Radare2 analysis failed: %s", e)
            self.tool_monitor.status["radare2"] = ToolStatus.FAILED

            # Try recovery
            if self.failure_recovery.handle_failure("radare2", e, config):
                # Retry the analysis
                self._run_radare2_analysis_with_ipc(config)
            else:
                with self.analysis_lock:
                    self.analysis_complete["radare2"] = True

    def _run_radare2_analysis(self, config: dict[str, Any] | None = None) -> None:
        """Run Radare2 analysis (legacy method for compatibility).

        Wrapper for _run_radare2_analysis_with_ipc to maintain backwards
        compatibility with sequential workflow calling convention.

        Args:
            config: Optional configuration parameters for analysis.

        """
        self._run_radare2_analysis_with_ipc(config)

    def _run_frida_analysis_with_ipc(self, config: dict[str, Any] | None = None) -> None:
        """Run Frida analysis with IPC communication.

        Executes Frida-based dynamic analysis including API monitoring,
        memory scanning, and hook detection. Can attach to existing processes
        or spawn new ones. Results are serialized and transmitted via shared
        memory IPC.

        Args:
            config: Optional configuration parameters for analysis. Can include
                'pid' for process attachment and 'scripts' list for which
                analysis scripts to execute.

        Raises:
            ValueError: If binary path is unsafe or contains path traversal.

        """
        try:
            if not self.frida_manager:
                self.logger.warning("Frida not available, skipping")
                self.tool_monitor.status["frida"] = ToolStatus.FAILED
                with self.analysis_lock:
                    self.analysis_complete["frida"] = True
                return

            self.tool_monitor.status["frida"] = ToolStatus.RUNNING
            self.logger.info("Starting Frida analysis with IPC")

            # Send start message via IPC
            self.ipc_channel.send_message(
                MessageType.STATUS,
                {"tool": "frida", "status": "starting", "timestamp": datetime.now().isoformat()},
            )

            # Attach to process or spawn
            pid: int | None = None
            if config:
                pid_value = config.get("pid")
                if isinstance(pid_value, int):
                    pid = pid_value
            if not pid:
                # Spawn process for real analysis
                import subprocess

                # Validate binary_path to prevent command injection
                if not Path(str(self.binary_path)).is_absolute() or ".." in str(self.binary_path):
                    raise ValueError(f"Unsafe binary path: {self.binary_path}")
                proc = subprocess.Popen([self.binary_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
                pid = proc.pid
                time.sleep(1)  # Let process initialize
            self.frida_manager.attach_to_process(pid)
            # Run standard scripts
            scripts: list[str] = []
            if config:
                scripts_value = config.get("scripts", ["memory_scan", "api_monitor", "hook_detection"])
                if isinstance(scripts_value, list):
                    scripts = scripts_value
                else:
                    scripts = ["memory_scan", "api_monitor", "hook_detection"]
            else:
                scripts = ["memory_scan", "api_monitor", "hook_detection"]
            results: dict[str, Any] = {}

            for script_name in scripts:
                if script_name == "api_monitor":
                    results["api_calls"] = self._frida_api_monitor()
                elif script_name == "hook_detection":
                    results["hooks"] = self._frida_hook_detection()

                elif script_name == "memory_scan":
                    results["memory"] = self._frida_memory_scan()
            # Serialize and send results via IPC
            serialized = self.result_serializer.serialize_result("frida", results, {"config": config})
            self.ipc_channel.send_message(MessageType.RESULT, serialized)

            with self.analysis_lock:
                self.analysis_complete["frida"] = True
                if results:
                    self.analysis_results["frida"] = results

            self.tool_monitor.status["frida"] = ToolStatus.COMPLETED
            self.failure_recovery.reset_retry_count("frida")
            self.logger.info("Frida analysis complete")

        except Exception as e:
            self.logger.exception("Frida analysis failed: %s", e)
            self.tool_monitor.status["frida"] = ToolStatus.FAILED

            # Try recovery
            if self.failure_recovery.handle_failure("frida", e, config):
                # Retry the analysis
                self._run_frida_analysis_with_ipc(config)
            else:
                with self.analysis_lock:
                    self.analysis_complete["frida"] = True

    def _run_frida_analysis(self, config: dict[str, Any] | None = None) -> None:
        """Run Frida analysis (legacy method for compatibility).

        Wrapper for _run_frida_analysis_with_ipc to maintain backwards
        compatibility with sequential workflow calling convention.

        Args:
            config: Optional configuration parameters for analysis.

        """
        self._run_frida_analysis_with_ipc(config)

    def _frida_memory_scan(self) -> dict[str, Any]:
        """Perform memory scanning with Frida.

        Returns:
            Dictionary containing strings, patterns, and suspicious regions found in memory.

        """
        results: dict[str, Any] = {"strings": [], "patterns": [], "suspicious_regions": []}

        if not self.frida_manager:
            return results

        # Memory scan script
        script_code = """
        function scanMemory() {
            var results = {
                strings: [],
                patterns: [],
                regions: []
            };

            Process.enumerateRanges('r--', {
                onMatch: function(range) {
                    try {
                        var data = Memory.readByteArray(range.base, Math.min(range.size, 4096));
                        // Look for license-related strings
                        var str = String.fromCharCode.apply(null, new Uint8Array(data));
                        if (str.includes('license') || str.includes('trial') || str.includes('expired')) {
                            results.strings.push({
                                address: range.base.toString(),
                                content: str.substring(0, 100)
                            });
                        }
                    } catch(e) {}
                },
                onComplete: function() {
                    send(results);
                }
            });
        }

        scanMemory();
        """

        try:
            # Execute the memory scan script
            if hasattr(self.frida_manager, "inject_script") and self.frida_manager.sessions:
                if first_pid := next(iter(self.frida_manager.sessions.keys()), None):
                    script_result = self.frida_manager.inject_script(first_pid, script_code)
                    if script_result and "data" in script_result:
                        results |= script_result["data"]
            else:
                self.logger.debug("Frida script injection method not available or no active sessions")
        except Exception as e:
            self.logger.exception("Memory scan failed: %s", e)

        return results

    def _frida_api_monitor(self) -> list[dict[str, Any]]:
        """Monitor API calls with Frida.

        Returns:
            List of monitored API calls with arguments and timestamps.

        """
        api_calls: list[dict[str, Any]] = []

        if not self.frida_manager:
            return api_calls

        # API monitoring script
        script_code = """
        var apis = [
            'CreateFileW', 'ReadFile', 'WriteFile',
            'RegOpenKeyExW', 'RegQueryValueExW',
            'InternetOpenW', 'HttpSendRequestW'
        ];

        apis.forEach(function(api) {
            try {
                var addr = Module.findExportByName(null, api);
                if (addr) {
                    Interceptor.attach(addr, {
                        onEnter: function(args) {
                            send({
                                api: api,
                                args: args,
                                timestamp: Date.now()
                            });
                        }
                    });
                }
            } catch(e) {}
        });
        """

        try:
            # Execute the API monitoring script
            if hasattr(self.frida_manager, "inject_script") and self.frida_manager.sessions:
                if first_pid := next(iter(self.frida_manager.sessions.keys()), None):
                    script_result = self.frida_manager.inject_script(first_pid, script_code)
                    if script_result and "calls" in script_result:
                        api_calls.extend(script_result["calls"])
            else:
                self.logger.debug("Frida script injection method not available or no active sessions")
        except Exception as e:
            self.logger.exception("API monitoring failed: %s", e)

        return api_calls

    def _frida_hook_detection(self) -> dict[str, Any]:
        """Detect hooks and patches with Frida.

        Returns:
            Dictionary containing detected inline hooks, IAT hooks, and patches.

        """
        hooks: dict[str, Any] = {"inline_hooks": [], "iat_hooks": [], "patches": []}

        if not self.frida_manager:
            return hooks

        # Hook detection script
        script_code = """
        function detectHooks() {
            var results = {
                inline: [],
                iat: [],
                patches: []
            };

            // Check for inline hooks
            var modules = Process.enumerateModules();
            modules.forEach(function(module) {
                var exports = module.enumerateExports();
                exports.forEach(function(exp) {
                    try {
                        var bytes = Memory.readByteArray(exp.address, 5);
                        var arr = new Uint8Array(bytes);
                        // Check for JMP (0xE9) or CALL (0xE8)
                        if (arr[0] == 0xE9 || arr[0] == 0xE8) {
                            results.inline.push({
                                module: module.name,
                                function: exp.name,
                                address: exp.address.toString()
                            });
                        }
                    } catch(e) {}
                });
            });

            send(results);
        }

        detectHooks();
        """

        try:
            # Execute the hook detection script
            if hasattr(self.frida_manager, "inject_script") and self.frida_manager.sessions:
                if first_pid := next(iter(self.frida_manager.sessions.keys()), None):
                    script_result = self.frida_manager.inject_script(first_pid, script_code)
                    if script_result and "hooks" in script_result:
                        hooks |= script_result["hooks"]
            else:
                self.logger.debug("Frida script injection method not available or no active sessions")
        except Exception as e:
            self.logger.exception("Hook detection failed: %s", e)

        return hooks

    def _correlate_results_with_resolution(self) -> UnifiedAnalysisResult:
        """Correlate results with conflict resolution.

        Combines data from multiple analysis tools while resolving conflicts
        using configured resolution rules. Produces comprehensive unified result
        with enhanced metadata including tool metrics and failure history.

        Returns:
            Unified analysis result with conflicts resolved and comprehensive
                metadata.

        """
        self.logger.info("Correlating results with conflict resolution")

        result = UnifiedAnalysisResult(binary_path=self.binary_path, timestamp=datetime.now())

        # Correlate functions with conflict resolution
        raw_functions = self._correlate_functions()
        result.functions = self.conflict_resolver.resolve_function_conflicts(raw_functions)

        # Correlate strings
        result.strings = self._correlate_strings()

        # Combine vulnerabilities
        result.vulnerabilities = self._combine_vulnerabilities()

        # Identify protection mechanisms
        result.protection_mechanisms = self._identify_protections()

        # Generate bypass strategies
        result.bypass_strategies = self._generate_bypass_strategies()

        # Build unified call graph
        result.call_graph = self._build_unified_call_graph()

        # Add enhanced metadata
        result.metadata = {
            "tools_used": list(self.analysis_complete.keys()),
            "analysis_complete": all(self.analysis_complete.values()),
            "correlation_confidence": self._calculate_correlation_confidence(),
            "tool_metrics": {tool: self.tool_monitor.get_metrics(tool) for tool in self.analysis_complete},
            "conflict_count": len(self.conflict_resolver.conflict_log),
            "failure_count": sum(len(self.failure_recovery.get_failure_history(tool)) for tool in self.analysis_complete),
        }

        return result

    def _correlate_results(self) -> UnifiedAnalysisResult:
        """Correlate results from all tools.

        Combines function, string, vulnerability, and protection data from
        all available analysis tools into a unified result. Includes basic
        metadata about tool completion status and correlation confidence.

        Returns:
            Unified analysis result combining data from all tools.

        """
        self.logger.info("Correlating results from all tools")

        result = UnifiedAnalysisResult(binary_path=self.binary_path, timestamp=datetime.now())

        # Correlate functions
        result.functions = self._correlate_functions()

        # Correlate strings
        result.strings = self._correlate_strings()

        # Combine vulnerabilities
        result.vulnerabilities = self._combine_vulnerabilities()

        # Identify protection mechanisms
        result.protection_mechanisms = self._identify_protections()

        # Generate bypass strategies
        result.bypass_strategies = self._generate_bypass_strategies()

        # Build unified call graph
        result.call_graph = self._build_unified_call_graph()

        # Add metadata
        result.metadata = {
            "tools_used": list(self.analysis_complete.keys()),
            "analysis_complete": all(self.analysis_complete.values()),
            "correlation_confidence": self._calculate_correlation_confidence(),
        }

        return result

    def _correlate_functions(self) -> list[CorrelatedFunction]:
        """Correlate function data across tools.

        Combines function information from Ghidra, Radare2, and Frida into
        unified function objects. Assigns confidence scores based on number
        of tools providing data for each function.

        Returns:
            List of functions correlated across multiple analysis tools.

        """
        correlated: list[CorrelatedFunction] = []
        function_map: dict[str, CorrelatedFunction] = {}

        # Process Ghidra functions
        if self.ghidra_results:
            for _func_addr, func in self.ghidra_results.functions.items():
                name = func.name
                if name not in function_map:
                    function_map[name] = CorrelatedFunction(name=name)
                cf = function_map[name]
                cf.ghidra_data = {"name": func.name, "address": func.address, "size": func.size}
                cf.addresses["ghidra"] = func.address
                cf.sizes["ghidra"] = func.size

        # Process Radare2 functions
        r2_results: Any = self.analysis_results.get("radare2", {})
        if r2_results and "components" in r2_results:
            decompiler = r2_results["components"].get("decompiler", {})
            if "functions" in decompiler:
                for func in decompiler["functions"]:
                    name = func.get("name", "")
                    if name not in function_map:
                        function_map[name] = CorrelatedFunction(name=name)
                    cf = function_map[name]
                    cf.r2_data = func
                    cf.addresses["r2"] = func.get("offset", 0)
                    cf.sizes["r2"] = func.get("size", 0)

        # Process Frida data
        frida_results: Any = self.analysis_results.get("frida", {})
        if frida_results and "hooks" in frida_results:
            for hook in frida_results["hooks"].get("inline", []):
                name = hook.get("function", "")
                if name not in function_map:
                    function_map[name] = CorrelatedFunction(name=name)
                cf = function_map[name]
                cf.frida_data = hook
                cf.notes.append("Has inline hook detected by Frida")

        # Calculate confidence scores
        for cf in function_map.values():
            sources = sum([1 if cf.ghidra_data else 0, 1 if cf.r2_data else 0, 1 if cf.frida_data else 0])
            cf.confidence_score = sources / 3.0
            correlated.append(cf)

        return correlated

    def _correlate_strings(self) -> list[CorrelatedString]:
        """Correlate string data across tools.

        Combines string references from Ghidra, Radare2, and Frida analysis.
        Classifies strings as license or crypto-related and assigns importance
        scores based on reference count and classification.

        Returns:
            List of strings correlated across multiple analysis tools.

        """
        correlated: list[CorrelatedString] = []
        string_map: dict[str, CorrelatedString] = {}

        # Process Ghidra strings
        if self.ghidra_results:
            for addr, value in self.ghidra_results.strings:
                if value not in string_map:
                    string_map[value] = CorrelatedString(value=value)
                cs = string_map[value]
                cs.ghidra_refs = [addr]

        # Process Radare2 strings
        r2_results: Any = self.analysis_results.get("radare2", {})
        if r2_results and "components" in r2_results:
            strings = r2_results["components"].get("strings", {})
            if "strings" in strings:
                for string_data in strings["strings"]:
                    value = string_data.get("string", "")
                    if value not in string_map:
                        string_map[value] = CorrelatedString(value=value)
                    cs = string_map[value]
                    cs.r2_refs = [string_data.get("vaddr", 0)]

        # Process Frida strings
        frida_results: Any = self.analysis_results.get("frida", {})
        if frida_results and "memory" in frida_results:
            for string_data in frida_results["memory"].get("strings", []):
                value = string_data.get("content", "")
                if value not in string_map:
                    string_map[value] = CorrelatedString(value=value)
                cs = string_map[value]
                cs.frida_refs = [int(string_data.get("address", "0"), 16)]

        # Classify strings
        for value, cs in string_map.items():
            # Check for license-related
            license_keywords = ["license", "trial", "expired", "activation", "serial", "key"]
            if any(kw in value.lower() for kw in license_keywords):
                cs.is_license_related = True
                cs.importance_score += 0.5

            # Check for crypto-related
            crypto_keywords = ["aes", "rsa", "sha", "md5", "encrypt", "decrypt", "cipher"]
            if any(kw in value.lower() for kw in crypto_keywords):
                cs.is_crypto_related = True
                cs.importance_score += 0.3

            # Score based on references
            total_refs = len(cs.ghidra_refs) + len(cs.r2_refs) + len(cs.frida_refs)
            cs.importance_score += min(total_refs * 0.1, 0.5)

            correlated.append(cs)

        return correlated

    def _combine_vulnerabilities(self) -> list[dict[str, Any]]:
        """Combine vulnerability findings from all tools.

        Aggregates vulnerability data from Radare2 static analysis and Frida
        runtime analysis. Adds source attribution for each finding.

        Returns:
            List of combined vulnerability findings with source attribution.

        """
        vulnerabilities: list[dict[str, Any]] = []

        # Get R2 vulnerabilities
        r2_results: Any = self.analysis_results.get("radare2", {})
        if r2_results and "components" in r2_results:
            vuln_data = r2_results["components"].get("vulnerability", {})
            if "vulnerabilities" in vuln_data:
                for vuln in vuln_data["vulnerabilities"]:
                    vuln["source"] = "radare2"
                    vulnerabilities.append(vuln)

        # Add Frida runtime vulnerabilities
        frida_results: Any = self.analysis_results.get("frida", {})
        if frida_results and "hooks" in frida_results:
            if inline_hooks := frida_results["hooks"].get("inline", []):
                vulnerabilities.append(
                    {
                        "type": "runtime_hooks",
                        "severity": "high",
                        "description": f"Detected {len(inline_hooks)} inline hooks",
                        "source": "frida",
                        "details": inline_hooks,
                    },
                )

        return vulnerabilities

    def _identify_protections(self) -> list[dict[str, Any]]:
        """Identify protection mechanisms from analysis.

        Detects anti-debugging APIs and obfuscation patterns from Radare2 and
        Ghidra results. Assigns confidence scores based on evidence strength.

        Returns:
            List of identified protection mechanisms with confidence scores.

        """
        protections: list[dict[str, Any]] = []

        if r2_results := self.analysis_results.get("radare2", {}):
            components = r2_results.get("components", {})
            imports = components.get("imports", {})
            if "imports" in imports:
                # Check for common anti-debug functions
                anti_debug_apis = [
                    "IsDebuggerPresent",
                    "CheckRemoteDebuggerPresent",
                    "NtQueryInformationProcess",
                    "OutputDebugString",
                ]

                protections.extend(
                    {
                        "type": "anti_debugging",
                        "mechanism": imp.get("name"),
                        "confidence": 0.9,
                    }
                    for imp in imports["imports"]
                    if any(api in imp.get("name", "") for api in anti_debug_apis)
                )
        # Check for obfuscation
        if self.ghidra_results:
            # High ratio of unnamed functions suggests obfuscation
            total_funcs = len(self.ghidra_results.functions)
            unnamed_funcs = sum(bool(f.name.startswith("sub_")) for f in self.ghidra_results.functions.values())
            if total_funcs > 0 and unnamed_funcs / total_funcs > 0.7:
                protections.append({
                    "type": "obfuscation",
                    "mechanism": "symbol_stripping",
                    "confidence": unnamed_funcs / total_funcs,
                })

        return protections

    def _generate_bypass_strategies(self) -> list[dict[str, Any]]:
        """Generate bypass strategies based on findings.

        Creates bypass recommendations for identified protections using Frida
        runtime patching techniques. Includes strategies from Radare2 analysis
        and custom implementation suggestions.

        Returns:
            List of bypass strategy recommendations with implementation details.

        """
        strategies: list[dict[str, Any]] = []

        # Get bypass suggestions from R2
        r2_results: Any = self.analysis_results.get("radare2", {})
        if r2_results and "components" in r2_results:
            bypass_data = r2_results["components"].get("bypass", {})
            if "strategies" in bypass_data:
                strategies.extend(bypass_data["strategies"])

        # Add Frida-based strategies
        if self.frida_manager:
            strategies.append(
                {
                    "name": "Runtime Patching",
                    "description": "Use Frida to patch protection checks at runtime",
                    "tool": "frida",
                    "confidence": 0.9,
                    "implementation": "Hook protection functions and return success",
                },
            )

        # Add strategies based on protections found
        strategies.extend(
            {
                "name": f"Bypass {protection['mechanism']}",
                "description": f"Hook and bypass {protection['mechanism']} check",
                "tool": "frida",
                "confidence": 0.8,
                "implementation": f"Interceptor.replace({protection['mechanism']}, () => 0);",
            }
            for protection in self._identify_protections()
            if protection["type"] == "anti_debugging"
        )
        return strategies

    def _build_unified_call_graph(self) -> dict[str, Any]:
        """Build unified call graph from all tools.

        Merges call graphs from Radare2 and Ghidra into a unified graph
        structure. Deduplicates nodes based on function identity while
        preserving tool-specific metadata.

        Returns:
            Dictionary containing nodes, edges, and metadata of unified
                call graph.

        """
        graph: dict[str, Any] = {"nodes": [], "edges": [], "metadata": {}}

        # Get R2 call graph
        if self.r2_integration:
            if r2_graph := self.r2_integration.generate_call_graph():
                graph["nodes"].extend(r2_graph.get("nodes", []))
                graph["edges"].extend(r2_graph.get("edges", []))

        # Merge with Ghidra data
        if self.ghidra_results:
            # Add Ghidra-specific nodes
            for _func_addr, func in self.ghidra_results.functions.items():
                node_id = func.name
                if all(n["id"] != node_id for n in graph["nodes"]):
                    graph["nodes"].append({
                        "id": node_id,
                        "label": node_id,
                        "source": "ghidra",
                        "address": func.address,
                    })

        return graph

    def _calculate_correlation_confidence(self) -> float:
        """Calculate overall correlation confidence.

        Computes confidence score based on proportion of analysis tools that
        successfully completed. Higher score indicates more comprehensive
        multi-tool correlated analysis.

        Returns:
            Confidence score between 0.0 and 1.0 based on tool completion.

        """
        tools_complete = sum(bool(v) for v in self.analysis_complete.values())
        total_tools = len(self.analysis_complete)

        return 0.0 if total_tools == 0 else tools_complete / total_tools

    def export_unified_report(self, output_path: str) -> None:
        """Export unified analysis report.

        Generates JSON report containing correlated analysis results from
        all tools. Includes functions, strings, vulnerabilities, protections,
        bypass strategies, and metadata.

        Args:
            output_path: Path for output file.

        """
        result = self._correlate_results()

        # Convert to JSON-serializable format
        report = {
            "binary_path": result.binary_path,
            "timestamp": result.timestamp.isoformat(),
            "functions": [
                {
                    "name": f.name,
                    "addresses": f.addresses,
                    "sizes": f.sizes,
                    "confidence": f.confidence_score,
                    "notes": f.notes,
                }
                for f in result.functions
            ],
            "strings": [
                {
                    "value": s.value,
                    "is_license_related": s.is_license_related,
                    "is_crypto_related": s.is_crypto_related,
                    "importance": s.importance_score,
                    "references": len(s.ghidra_refs) + len(s.r2_refs) + len(s.frida_refs),
                }
                for s in result.strings
            ],
            "vulnerabilities": result.vulnerabilities,
            "protections": result.protection_mechanisms,
            "bypass_strategies": result.bypass_strategies,
            "metadata": result.metadata,
        }

        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)

        self.logger.info("Exported unified report to %s", output_path)

    def cleanup(self) -> None:
        """Clean up resources.

        Stops monitoring threads, closes IPC channels, and cleans up all
        analysis tool instances. Waits for running threads to complete with
        timeout.

        """
        # Stop monitoring
        if self.tool_monitor:
            self.tool_monitor.stop()

        # Clean up IPC
        if self.ipc_channel:
            self.ipc_channel.cleanup()

        # Clean up tool instances
        if self.r2_integration:
            self.r2_integration.cleanup()

        if self.frida_manager:
            self.frida_manager.cleanup()

        # Wait for threads to complete
        for thread in self.analysis_threads:
            if thread.is_alive():
                thread.join(timeout=2)

        self.logger.info("CrossToolOrchestrator cleanup complete")


def create_orchestrator(binary_path: str, main_app: object | None = None) -> CrossToolOrchestrator:
    """Create orchestrator.

    Factory function to instantiate a CrossToolOrchestrator for multi-tool
    binary analysis orchestration.

    Args:
        binary_path: Path to binary file to analyze.
        main_app: Optional GUI application reference for UI integration.

    Returns:
        New CrossToolOrchestrator instance configured for the binary.

    """
    return CrossToolOrchestrator(binary_path, main_app)
