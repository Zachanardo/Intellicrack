"""Radare2 Performance Metrics Module.

This module provides real-time performance monitoring and metrics
collection for radare2 analysis operations.

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

import json
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

import psutil

try:
    import r2pipe
except ImportError:
    r2pipe = None

logger = logging.getLogger(__name__)


@dataclass
class OperationMetrics:
    """Metrics for a single r2 operation."""

    operation_name: str
    start_time: float
    end_time: Optional[float] = None
    duration_ms: Optional[float] = None
    memory_before: Optional[int] = None
    memory_after: Optional[int] = None
    memory_delta: Optional[int] = None
    cpu_percent: Optional[float] = None
    success: bool = False
    error_message: Optional[str] = None
    command_count: int = 0
    bytes_processed: int = 0


@dataclass
class SessionMetrics:
    """Aggregated metrics for an r2 session."""

    session_id: str
    start_time: datetime
    total_operations: int = 0
    successful_operations: int = 0
    failed_operations: int = 0
    total_duration_ms: float = 0.0
    average_duration_ms: float = 0.0
    peak_memory_mb: float = 0.0
    average_cpu_percent: float = 0.0
    total_bytes_processed: int = 0
    operations: List[OperationMetrics] = field(default_factory=list)
    cache_hits: int = 0
    cache_misses: int = 0
    cache_hit_rate: float = 0.0


class R2PerformanceMonitor:
    """Monitor and collect performance metrics for radare2 operations."""

    def __init__(self, enable_real_time: bool = True):
        """Initialize performance monitor.

        Args:
            enable_real_time: Enable real-time monitoring

        """
        self.logger = logger
        self.enable_real_time = enable_real_time
        self.current_session: Optional[SessionMetrics] = None
        self.operation_stack: List[OperationMetrics] = []
        self.metrics_lock = threading.Lock()
        self.monitoring_thread: Optional[threading.Thread] = None
        self.stop_monitoring = threading.Event()
        self.process_monitor: Optional[psutil.Process] = None

        # Performance thresholds
        self.thresholds = {
            "operation_duration_warn_ms": 5000,
            "operation_duration_critical_ms": 10000,
            "memory_usage_warn_mb": 500,
            "memory_usage_critical_mb": 1000,
            "cpu_usage_warn_percent": 70,
            "cpu_usage_critical_percent": 90,
        }

        # Historical data
        self.historical_sessions: List[SessionMetrics] = []
        self.max_history_size = 100

    def start_session(self, session_id: str) -> SessionMetrics:
        """Start a new metrics session.

        Args:
            session_id: Unique identifier for the session

        Returns:
            New SessionMetrics object

        """
        with self.metrics_lock:
            if self.current_session:
                self.end_session()

            self.current_session = SessionMetrics(session_id=session_id, start_time=datetime.now())

            if self.enable_real_time:
                self._start_monitoring()

            self.logger.info(f"Started metrics session: {session_id}")
            return self.current_session

    def end_session(self) -> Optional[SessionMetrics]:
        """End the current metrics session.

        Returns:
            Final session metrics

        """
        with self.metrics_lock:
            if not self.current_session:
                return None

            session = self.current_session

            # Calculate final statistics
            if session.total_operations > 0:
                session.average_duration_ms = session.total_duration_ms / session.total_operations

                if session.cache_hits + session.cache_misses > 0:
                    session.cache_hit_rate = session.cache_hits / (session.cache_hits + session.cache_misses)

            # Store in history
            self.historical_sessions.append(session)
            if len(self.historical_sessions) > self.max_history_size:
                self.historical_sessions.pop(0)

            self.current_session = None

            if self.enable_real_time:
                self._stop_monitoring()

            self.logger.info(f"Ended metrics session: {session.session_id}")
            return session

    def start_operation(self, operation_name: str) -> OperationMetrics:
        """Start tracking a new operation.

        Args:
            operation_name: Name of the operation

        Returns:
            New OperationMetrics object

        """
        metrics = OperationMetrics(operation_name=operation_name, start_time=time.time())

        # Capture initial memory
        if self.process_monitor:
            try:
                metrics.memory_before = self.process_monitor.memory_info().rss
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                self.logger.warning(f"Failed to get memory before operation: {e}")

        with self.metrics_lock:
            self.operation_stack.append(metrics)

            if self.current_session:
                self.current_session.total_operations += 1

        self.logger.debug(f"Started operation: {operation_name}")
        return metrics

    def end_operation(
        self, operation_metrics: OperationMetrics, success: bool = True, error_message: Optional[str] = None, bytes_processed: int = 0
    ) -> OperationMetrics:
        """End tracking an operation.

        Args:
            operation_metrics: The operation metrics to finalize
            success: Whether the operation succeeded
            error_message: Error message if failed
            bytes_processed: Number of bytes processed

        Returns:
            Finalized OperationMetrics

        """
        operation_metrics.end_time = time.time()
        operation_metrics.duration_ms = (operation_metrics.end_time - operation_metrics.start_time) * 1000
        operation_metrics.success = success
        operation_metrics.error_message = error_message
        operation_metrics.bytes_processed = bytes_processed

        # Capture final memory
        if self.process_monitor:
            try:
                operation_metrics.memory_after = self.process_monitor.memory_info().rss
                if operation_metrics.memory_before:
                    operation_metrics.memory_delta = operation_metrics.memory_after - operation_metrics.memory_before
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                self.logger.warning(f"Failed to get memory after operation: {e}")

        with self.metrics_lock:
            # Remove from stack
            if operation_metrics in self.operation_stack:
                self.operation_stack.remove(operation_metrics)

            # Update session metrics
            if self.current_session:
                self.current_session.operations.append(operation_metrics)
                self.current_session.total_duration_ms += operation_metrics.duration_ms

                if success:
                    self.current_session.successful_operations += 1
                else:
                    self.current_session.failed_operations += 1

                self.current_session.total_bytes_processed += bytes_processed

                # Update peak memory
                if operation_metrics.memory_after:
                    memory_mb = operation_metrics.memory_after / (1024 * 1024)
                    if memory_mb > self.current_session.peak_memory_mb:
                        self.current_session.peak_memory_mb = memory_mb

        # Check thresholds
        self._check_thresholds(operation_metrics)

        self.logger.debug(
            f"Ended operation: {operation_metrics.operation_name} (duration: {operation_metrics.duration_ms:.2f}ms, success: {success})"
        )

        return operation_metrics

    def record_cache_hit(self):
        """Record a cache hit."""
        with self.metrics_lock:
            if self.current_session:
                self.current_session.cache_hits += 1

    def record_cache_miss(self):
        """Record a cache miss."""
        with self.metrics_lock:
            if self.current_session:
                self.current_session.cache_misses += 1

    def get_current_metrics(self) -> Dict[str, Any]:
        """Get current session metrics.

        Returns:
            Dictionary containing current metrics

        """
        with self.metrics_lock:
            if not self.current_session:
                return {}

            return {
                "session_id": self.current_session.session_id,
                "uptime_seconds": (datetime.now() - self.current_session.start_time).total_seconds(),
                "total_operations": self.current_session.total_operations,
                "successful_operations": self.current_session.successful_operations,
                "failed_operations": self.current_session.failed_operations,
                "success_rate": self.current_session.successful_operations / max(1, self.current_session.total_operations),
                "average_duration_ms": self.current_session.average_duration_ms,
                "peak_memory_mb": self.current_session.peak_memory_mb,
                "average_cpu_percent": self.current_session.average_cpu_percent,
                "cache_hit_rate": self.current_session.cache_hit_rate,
                "total_bytes_processed": self.current_session.total_bytes_processed,
                "active_operations": len(self.operation_stack),
            }

    def get_operation_statistics(self) -> Dict[str, Any]:
        """Get statistics about operations.

        Returns:
            Dictionary containing operation statistics

        """
        with self.metrics_lock:
            if not self.current_session or not self.current_session.operations:
                return {}

            operations = self.current_session.operations

            # Group by operation name
            by_name: Dict[str, List[OperationMetrics]] = {}
            for op in operations:
                if op.operation_name not in by_name:
                    by_name[op.operation_name] = []
                by_name[op.operation_name].append(op)

            stats = {}
            for name, ops in by_name.items():
                durations = [op.duration_ms for op in ops if op.duration_ms is not None]
                if durations:
                    stats[name] = {
                        "count": len(ops),
                        "total_ms": sum(durations),
                        "average_ms": sum(durations) / len(durations),
                        "min_ms": min(durations),
                        "max_ms": max(durations),
                        "success_rate": len([op for op in ops if op.success]) / len(ops),
                    }

            return stats

    def get_performance_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance report.

        Returns:
            Dictionary containing full performance report

        """
        current = self.get_current_metrics()
        operations = self.get_operation_statistics()

        # Get system metrics
        system_metrics = {}
        if self.process_monitor:
            try:
                system_metrics = {
                    "cpu_percent": self.process_monitor.cpu_percent(),
                    "memory_mb": self.process_monitor.memory_info().rss / (1024 * 1024),
                    "num_threads": self.process_monitor.num_threads(),
                    "open_files": len(self.process_monitor.open_files()),
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                self.logger.warning(f"Failed to get system metrics: {e}")

        return {
            "timestamp": datetime.now().isoformat(),
            "current_session": current,
            "operation_statistics": operations,
            "system_metrics": system_metrics,
            "thresholds": self.thresholds,
            "historical_sessions": len(self.historical_sessions),
        }

    def _start_monitoring(self):
        """Start real-time monitoring thread."""
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            return

        try:
            self.process_monitor = psutil.Process()
        except Exception as e:
            self.logger.warning(f"Failed to initialize process monitor: {e}")
            self.process_monitor = None

        self.stop_monitoring.clear()
        self.monitoring_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitoring_thread.start()

    def _stop_monitoring(self):
        """Stop real-time monitoring thread."""
        self.stop_monitoring.set()
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=1)
        self.process_monitor = None

    def _monitor_loop(self):
        """Real-time monitoring loop."""
        cpu_samples = []

        while not self.stop_monitoring.is_set():
            try:
                if self.process_monitor and self.current_session:
                    # Sample CPU usage
                    cpu = self.process_monitor.cpu_percent()
                    cpu_samples.append(cpu)

                    # Keep rolling average of last 10 samples
                    if len(cpu_samples) > 10:
                        cpu_samples.pop(0)

                    with self.metrics_lock:
                        self.current_session.average_cpu_percent = sum(cpu_samples) / len(cpu_samples)

                # Check active operations for timeout
                with self.metrics_lock:
                    current_time = time.time()
                    for op in self.operation_stack:
                        duration_ms = (current_time - op.start_time) * 1000
                        if duration_ms > self.thresholds["operation_duration_critical_ms"]:
                            self.logger.warning(f"Operation '{op.operation_name}' exceeds critical duration: {duration_ms:.0f}ms")

            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")

            self.stop_monitoring.wait(timeout=1)

    def _check_thresholds(self, metrics: OperationMetrics):
        """Check if metrics exceed thresholds and log warnings.

        Args:
            metrics: Operation metrics to check

        """
        if metrics.duration_ms:
            if metrics.duration_ms > self.thresholds["operation_duration_critical_ms"]:
                self.logger.warning(f"Operation '{metrics.operation_name}' exceeded critical duration: {metrics.duration_ms:.0f}ms")
            elif metrics.duration_ms > self.thresholds["operation_duration_warn_ms"]:
                self.logger.info(f"Operation '{metrics.operation_name}' exceeded warning duration: {metrics.duration_ms:.0f}ms")

        if metrics.memory_after:
            memory_mb = metrics.memory_after / (1024 * 1024)
            if memory_mb > self.thresholds["memory_usage_critical_mb"]:
                self.logger.warning(f"Memory usage critical: {memory_mb:.0f}MB")
            elif memory_mb > self.thresholds["memory_usage_warn_mb"]:
                self.logger.info(f"Memory usage warning: {memory_mb:.0f}MB")

    def export_metrics(self, filepath: str):
        """Export metrics to JSON file.

        Args:
            filepath: Path to export file

        """
        report = self.get_performance_report()

        # Convert datetime objects to strings
        def convert_datetime(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            return obj

        with open(filepath, "w") as f:
            json.dump(report, f, indent=2, default=convert_datetime)

        self.logger.info(f"Exported metrics to {filepath}")


def create_performance_monitor(enable_real_time: bool = True) -> R2PerformanceMonitor:
    """Create performance monitor.

    Args:
        enable_real_time: Enable real-time monitoring

    Returns:
        New R2PerformanceMonitor instance

    """
    return R2PerformanceMonitor(enable_real_time=enable_real_time)
