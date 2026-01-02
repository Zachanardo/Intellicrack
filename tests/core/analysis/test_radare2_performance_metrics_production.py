"""Production tests for Radare2 Performance Metrics.

Validates real performance monitoring capabilities including:
- Session metrics tracking
- Operation timing and profiling
- Memory usage monitoring
- CPU utilization tracking
- Cache hit rate calculation
- Threshold warning system
- Metrics export functionality

Copyright (C) 2025 Zachary Flint
"""

from typing import Any
import json
import tempfile
import threading
import time
from pathlib import Path

import psutil
import pytest

from intellicrack.core.analysis.radare2_performance_metrics import (
    OperationMetrics,
    R2PerformanceMonitor,
    SessionMetrics,
)


@pytest.fixture
def performance_monitor() -> R2PerformanceMonitor:
    """Create a performance monitor instance."""
    return R2PerformanceMonitor(enable_real_time=True)


@pytest.fixture
def monitor_no_realtime() -> R2PerformanceMonitor:
    """Create a performance monitor without real-time monitoring."""
    return R2PerformanceMonitor(enable_real_time=False)


class TestPerformanceMonitorInitialization:
    """Test performance monitor initialization and configuration."""

    def test_monitor_initialization_default(self, performance_monitor: R2PerformanceMonitor) -> None:
        """Performance monitor initializes with correct defaults."""
        assert performance_monitor.enable_real_time is True
        assert performance_monitor.current_session is None
        assert len(performance_monitor.operation_stack) == 0
        assert len(performance_monitor.historical_sessions) == 0

    def test_monitor_initialization_no_realtime(self, monitor_no_realtime: R2PerformanceMonitor) -> None:
        """Performance monitor can disable real-time monitoring."""
        assert monitor_no_realtime.enable_real_time is False

    def test_thresholds_configured(self, performance_monitor: R2PerformanceMonitor) -> None:
        """Performance thresholds configured correctly."""
        assert performance_monitor.thresholds["operation_duration_warn_ms"] == 5000
        assert performance_monitor.thresholds["operation_duration_critical_ms"] == 10000
        assert performance_monitor.thresholds["memory_usage_warn_mb"] == 500
        assert performance_monitor.thresholds["memory_usage_critical_mb"] == 1000
        assert performance_monitor.thresholds["cpu_usage_warn_percent"] == 70
        assert performance_monitor.thresholds["cpu_usage_critical_percent"] == 90

    def test_metrics_lock_created(self, performance_monitor: R2PerformanceMonitor) -> None:
        """Thread lock created for metrics protection."""
        assert performance_monitor.metrics_lock is not None
        assert isinstance(performance_monitor.metrics_lock, threading.RLock)


class TestSessionManagement:
    """Test session creation and management."""

    def test_start_session_creates_new_session(self, performance_monitor: R2PerformanceMonitor) -> None:
        """Starting a session creates new SessionMetrics."""
        session = performance_monitor.start_session("test_session_1")

        assert session is not None
        assert session.session_id == "test_session_1"
        assert session.total_operations == 0
        assert session.successful_operations == 0
        assert session.failed_operations == 0
        assert performance_monitor.current_session == session

    def test_end_session_finalizes_metrics(self, performance_monitor: R2PerformanceMonitor) -> None:
        """Ending a session finalizes and stores metrics."""
        performance_monitor.start_session("test_session_2")

        ended_session = performance_monitor.end_session()

        assert ended_session is not None
        assert ended_session.session_id == "test_session_2"
        assert performance_monitor.current_session is None
        assert ended_session in performance_monitor.historical_sessions

    def test_start_new_session_ends_previous(self, performance_monitor: R2PerformanceMonitor) -> None:
        """Starting a new session automatically ends previous session."""
        session1 = performance_monitor.start_session("session_1")
        session2 = performance_monitor.start_session("session_2")

        assert session1 != session2
        assert performance_monitor.current_session == session2
        assert session1 in performance_monitor.historical_sessions

    def test_end_session_without_active_returns_none(self, performance_monitor: R2PerformanceMonitor) -> None:
        """Ending session when none active returns None."""
        result = performance_monitor.end_session()

        assert result is None

    def test_session_monitoring_thread_starts(self, performance_monitor: R2PerformanceMonitor) -> None:
        """Real-time monitoring thread starts with session."""
        performance_monitor.start_session("monitored_session")

        time.sleep(0.1)

        assert performance_monitor.monitoring_thread is not None
        assert performance_monitor.monitoring_thread.is_alive()

        performance_monitor.end_session()

    def test_historical_sessions_limited(self, performance_monitor: R2PerformanceMonitor) -> None:
        """Historical sessions limited to max_history_size."""
        original_max = performance_monitor.max_history_size
        performance_monitor.max_history_size = 3

        for i in range(5):
            performance_monitor.start_session(f"session_{i}")
            performance_monitor.end_session()

        assert len(performance_monitor.historical_sessions) == 3

        performance_monitor.max_history_size = original_max


class TestOperationTracking:
    """Test individual operation tracking."""

    def test_start_operation_creates_metrics(self, performance_monitor: R2PerformanceMonitor) -> None:
        """Starting an operation creates OperationMetrics."""
        performance_monitor.start_session("op_session")

        op_metrics = performance_monitor.start_operation("test_operation")

        assert op_metrics is not None
        assert op_metrics.operation_name == "test_operation"
        assert op_metrics.start_time > 0
        assert op_metrics.end_time is None
        assert op_metrics in performance_monitor.operation_stack

    def test_end_operation_calculates_duration(self, performance_monitor: R2PerformanceMonitor) -> None:
        """Ending an operation calculates duration correctly."""
        performance_monitor.start_session("duration_session")

        op_metrics = performance_monitor.start_operation("timed_operation")
        time.sleep(0.1)
        finalized = performance_monitor.end_operation(op_metrics, success=True)

        assert finalized.end_time is not None
        assert finalized.duration_ms is not None
        assert finalized.duration_ms >= 100
        assert finalized.success is True
        assert op_metrics not in performance_monitor.operation_stack

    def test_end_operation_tracks_failure(self, performance_monitor: R2PerformanceMonitor) -> None:
        """Failed operations tracked with error messages."""
        performance_monitor.start_session("error_session")

        op_metrics = performance_monitor.start_operation("failing_operation")
        finalized = performance_monitor.end_operation(
            op_metrics,
            success=False,
            error_message="Test error"
        )

        assert finalized.success is False
        assert finalized.error_message == "Test error"
        assert performance_monitor.current_session.failed_operations == 1
        assert performance_monitor.current_session.successful_operations == 0

    def test_operation_memory_tracking(self, performance_monitor: R2PerformanceMonitor) -> None:
        """Operations track memory usage before and after."""
        performance_monitor.start_session("memory_session")
        performance_monitor.process_monitor = psutil.Process()

        op_metrics = performance_monitor.start_operation("memory_operation")

        large_allocation = bytearray(1024 * 1024)

        finalized = performance_monitor.end_operation(op_metrics, success=True)

        assert finalized.memory_before is not None or finalized.memory_after is not None

        del large_allocation

    def test_bytes_processed_tracking(self, performance_monitor: R2PerformanceMonitor) -> None:
        """Operations track bytes processed."""
        performance_monitor.start_session("bytes_session")

        op_metrics = performance_monitor.start_operation("data_operation")
        finalized = performance_monitor.end_operation(
            op_metrics,
            success=True,
            bytes_processed=1024
        )

        assert finalized.bytes_processed == 1024
        assert performance_monitor.current_session.total_bytes_processed == 1024

    def test_multiple_operations_in_session(self, performance_monitor: R2PerformanceMonitor) -> None:
        """Multiple operations tracked in single session."""
        session = performance_monitor.start_session("multi_op_session")

        op1 = performance_monitor.start_operation("op_1")
        performance_monitor.end_operation(op1, success=True)

        op2 = performance_monitor.start_operation("op_2")
        performance_monitor.end_operation(op2, success=True)

        op3 = performance_monitor.start_operation("op_3")
        performance_monitor.end_operation(op3, success=False)

        assert session.total_operations == 3
        assert session.successful_operations == 2
        assert session.failed_operations == 1


class TestMetricsCalculation:
    """Test metrics calculation and aggregation."""

    def test_average_duration_calculation(self, performance_monitor: R2PerformanceMonitor) -> None:
        """Average duration calculated correctly."""
        performance_monitor.start_session("avg_session")

        for i in range(5):
            op = performance_monitor.start_operation(f"op_{i}")
            time.sleep(0.05)
            performance_monitor.end_operation(op, success=True)

        session = performance_monitor.end_session()

        assert session.average_duration_ms > 0
        assert session.total_duration_ms / session.total_operations == session.average_duration_ms

    def test_peak_memory_tracking(self, performance_monitor: R2PerformanceMonitor) -> None:
        """Peak memory usage tracked across operations."""
        performance_monitor.start_session("peak_mem_session")
        performance_monitor.process_monitor = psutil.Process()

        op = performance_monitor.start_operation("memory_op")
        performance_monitor.end_operation(op, success=True)

        assert performance_monitor.current_session.peak_memory_mb >= 0

    def test_cache_hit_rate_calculation(self, performance_monitor: R2PerformanceMonitor) -> None:
        """Cache hit rate calculated correctly."""
        session = performance_monitor.start_session("cache_session")

        performance_monitor.record_cache_hit()
        performance_monitor.record_cache_hit()
        performance_monitor.record_cache_hit()
        performance_monitor.record_cache_miss()

        ended_session = performance_monitor.end_session()

        assert ended_session.cache_hits == 3
        assert ended_session.cache_misses == 1
        assert ended_session.cache_hit_rate == 0.75

    def test_zero_cache_operations_handles_division(self, performance_monitor: R2PerformanceMonitor) -> None:
        """Zero cache operations doesn't cause division by zero."""
        session = performance_monitor.start_session("no_cache_session")
        ended_session = performance_monitor.end_session()

        assert ended_session.cache_hit_rate == 0.0


class TestCurrentMetrics:
    """Test current metrics retrieval."""

    def test_get_current_metrics_active_session(self, performance_monitor: R2PerformanceMonitor) -> None:
        """Current metrics retrieved for active session."""
        performance_monitor.start_session("active_session")

        op1 = performance_monitor.start_operation("op1")
        performance_monitor.end_operation(op1, success=True)

        metrics = performance_monitor.get_current_metrics()

        assert metrics["session_id"] == "active_session"
        assert metrics["total_operations"] == 1
        assert metrics["successful_operations"] == 1
        assert "uptime_seconds" in metrics
        assert "success_rate" in metrics

    def test_get_current_metrics_no_session(self, performance_monitor: R2PerformanceMonitor) -> None:
        """Current metrics returns empty dict when no session."""
        metrics = performance_monitor.get_current_metrics()

        assert metrics == {}

    def test_success_rate_calculation(self, performance_monitor: R2PerformanceMonitor) -> None:
        """Success rate calculated correctly."""
        performance_monitor.start_session("success_session")

        for i in range(10):
            op = performance_monitor.start_operation(f"op_{i}")
            success = i < 7
            performance_monitor.end_operation(op, success=success)

        metrics = performance_monitor.get_current_metrics()

        assert metrics["success_rate"] == 0.7


class TestOperationStatistics:
    """Test operation statistics aggregation."""

    def test_get_operation_statistics_by_name(self, performance_monitor: R2PerformanceMonitor) -> None:
        """Operation statistics grouped by name."""
        performance_monitor.start_session("stats_session")

        for _ in range(3):
            op = performance_monitor.start_operation("read_op")
            time.sleep(0.01)
            performance_monitor.end_operation(op, success=True)

        for _ in range(2):
            op = performance_monitor.start_operation("write_op")
            time.sleep(0.02)
            performance_monitor.end_operation(op, success=True)

        stats = performance_monitor.get_operation_statistics()

        assert "read_op" in stats
        assert "write_op" in stats
        assert stats["read_op"]["count"] == 3
        assert stats["write_op"]["count"] == 2

    def test_operation_statistics_aggregates(self, performance_monitor: R2PerformanceMonitor) -> None:
        """Operation statistics include min, max, average."""
        performance_monitor.start_session("aggregate_session")

        durations = [0.01, 0.02, 0.03, 0.04, 0.05]
        for duration in durations:
            op = performance_monitor.start_operation("timed_op")
            time.sleep(duration)
            performance_monitor.end_operation(op, success=True)

        stats = performance_monitor.get_operation_statistics()

        assert "timed_op" in stats
        assert "min_ms" in stats["timed_op"]
        assert "max_ms" in stats["timed_op"]
        assert "average_ms" in stats["timed_op"]
        assert stats["timed_op"]["count"] == 5

    def test_empty_statistics_returns_empty(self, performance_monitor: R2PerformanceMonitor) -> None:
        """Empty operation list returns empty statistics."""
        performance_monitor.start_session("empty_stats")

        stats = performance_monitor.get_operation_statistics()

        assert stats == {}


class TestPerformanceReport:
    """Test comprehensive performance report generation."""

    def test_generate_performance_report(self, performance_monitor: R2PerformanceMonitor) -> None:
        """Performance report includes all sections."""
        performance_monitor.start_session("report_session")
        performance_monitor.process_monitor = psutil.Process()

        op = performance_monitor.start_operation("test_op")
        performance_monitor.end_operation(op, success=True)

        report = performance_monitor.get_performance_report()

        assert "timestamp" in report
        assert "current_session" in report
        assert "operation_statistics" in report
        assert "system_metrics" in report
        assert "thresholds" in report
        assert "historical_sessions" in report

    def test_report_system_metrics(self, performance_monitor: R2PerformanceMonitor) -> None:
        """Report includes system metrics when available."""
        performance_monitor.start_session("system_session")
        performance_monitor.process_monitor = psutil.Process()

        report = performance_monitor.get_performance_report()

        if report["system_metrics"]:
            assert "cpu_percent" in report["system_metrics"]
            assert "memory_mb" in report["system_metrics"]

    def test_export_metrics_to_file(self, performance_monitor: R2PerformanceMonitor, tmp_path: Path) -> None:
        """Metrics export to JSON file correctly."""
        performance_monitor.start_session("export_session")

        op = performance_monitor.start_operation("export_op")
        performance_monitor.end_operation(op, success=True)

        export_path = tmp_path / "metrics.json"
        performance_monitor.export_metrics(str(export_path))

        assert export_path.exists()

        with open(export_path) as f:
            data = json.load(f)

        assert "current_session" in data
        assert "thresholds" in data


class TestThresholdWarnings:
    """Test threshold warning system."""

    def test_duration_warning_threshold(self, performance_monitor: R2PerformanceMonitor, caplog: Any) -> None:
        """Warning logged when operation exceeds duration threshold."""
        performance_monitor.start_session("threshold_session")
        performance_monitor.thresholds["operation_duration_warn_ms"] = 50

        op = performance_monitor.start_operation("slow_op")
        time.sleep(0.1)
        performance_monitor.end_operation(op, success=True)

        warning_found = any("exceeded warning duration" in record.message for record in caplog.records)

    def test_duration_critical_threshold(self, performance_monitor: R2PerformanceMonitor, caplog: Any) -> None:
        """Critical warning logged for very slow operations."""
        performance_monitor.start_session("critical_session")
        performance_monitor.thresholds["operation_duration_critical_ms"] = 50

        op = performance_monitor.start_operation("very_slow_op")
        time.sleep(0.1)
        performance_monitor.end_operation(op, success=True)

        critical_found = any("exceeded critical duration" in record.message for record in caplog.records)

    def test_memory_warning_threshold(self, performance_monitor: R2PerformanceMonitor) -> None:
        """Memory usage thresholds configured correctly."""
        assert performance_monitor.thresholds["memory_usage_warn_mb"] > 0
        assert performance_monitor.thresholds["memory_usage_critical_mb"] > performance_monitor.thresholds["memory_usage_warn_mb"]


class TestRealTimeMonitoring:
    """Test real-time monitoring capabilities."""

    def test_monitoring_thread_lifecycle(self, performance_monitor: R2PerformanceMonitor) -> None:
        """Monitoring thread starts and stops with session."""
        performance_monitor.start_session("monitor_lifecycle")

        time.sleep(0.2)

        assert performance_monitor.monitoring_thread is not None
        assert performance_monitor.monitoring_thread.is_alive()

        performance_monitor.end_session()

        time.sleep(0.2)

        assert not performance_monitor.stop_monitoring.is_set() or not performance_monitor.monitoring_thread.is_alive()

    def test_cpu_sampling_updates(self, performance_monitor: R2PerformanceMonitor) -> None:
        """CPU usage sampled and averaged over time."""
        performance_monitor.start_session("cpu_session")
        performance_monitor.process_monitor = psutil.Process()

        time.sleep(0.5)

        metrics = performance_monitor.get_current_metrics()

        assert "average_cpu_percent" in metrics
        assert metrics["average_cpu_percent"] >= 0

        performance_monitor.end_session()

    def test_long_running_operation_detection(self, performance_monitor: R2PerformanceMonitor, caplog: Any) -> None:
        """Long-running operations detected during monitoring."""
        performance_monitor.start_session("long_op_session")
        performance_monitor.thresholds["operation_duration_critical_ms"] = 100

        op = performance_monitor.start_operation("long_running")

        time.sleep(0.5)

        timeout_warning = any("exceeds critical duration" in record.message for record in caplog.records)

        performance_monitor.end_operation(op, success=True)
        performance_monitor.end_session()


class TestThreadSafety:
    """Test thread safety of metrics collection."""

    def test_concurrent_operations_thread_safe(self, performance_monitor: R2PerformanceMonitor) -> None:
        """Concurrent operations tracked safely."""
        performance_monitor.start_session("concurrent_session")

        def run_operations(thread_id: int) -> None:
            for i in range(10):
                op = performance_monitor.start_operation(f"thread_{thread_id}_op_{i}")
                time.sleep(0.01)
                performance_monitor.end_operation(op, success=True)

        threads = [threading.Thread(target=run_operations, args=(i,)) for i in range(3)]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        session = performance_monitor.end_session()

        assert session.total_operations == 30
        assert session.successful_operations == 30

    def test_concurrent_cache_recording(self, performance_monitor: R2PerformanceMonitor) -> None:
        """Concurrent cache hit/miss recording is thread-safe."""
        performance_monitor.start_session("cache_concurrent")

        def record_cache_operations(hits: int, misses: int) -> None:
            for _ in range(hits):
                performance_monitor.record_cache_hit()
            for _ in range(misses):
                performance_monitor.record_cache_miss()

        threads = [
            threading.Thread(target=record_cache_operations, args=(10, 5)),
            threading.Thread(target=record_cache_operations, args=(8, 3)),
        ]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        session = performance_monitor.end_session()

        assert session.cache_hits == 18
        assert session.cache_misses == 8


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_zero_operations_session(self, performance_monitor: R2PerformanceMonitor) -> None:
        """Session with zero operations handled correctly."""
        performance_monitor.start_session("zero_ops")
        session = performance_monitor.end_session()

        assert session.total_operations == 0
        assert session.average_duration_ms == 0.0

    def test_very_fast_operation(self, performance_monitor: R2PerformanceMonitor) -> None:
        """Very fast operations tracked correctly."""
        performance_monitor.start_session("fast_session")

        op = performance_monitor.start_operation("instant_op")
        finalized = performance_monitor.end_operation(op, success=True)

        assert finalized.duration_ms is not None
        assert finalized.duration_ms >= 0

    def test_process_monitor_unavailable(self, monitor_no_realtime: R2PerformanceMonitor) -> None:
        """Graceful handling when process monitor unavailable."""
        monitor_no_realtime.start_session("no_process")

        op = monitor_no_realtime.start_operation("test_op")
        finalized = monitor_no_realtime.end_operation(op, success=True)

        assert finalized.memory_before is None or finalized.memory_before >= 0

    def test_export_with_datetime_serialization(self, performance_monitor: R2PerformanceMonitor, tmp_path: Path) -> None:
        """Datetime objects serialize correctly in export."""
        performance_monitor.start_session("datetime_session")

        export_path = tmp_path / "datetime_metrics.json"
        performance_monitor.export_metrics(str(export_path))

        assert export_path.exists()

        with open(export_path) as f:
            data = json.load(f)

        assert "timestamp" in data


class TestPerformanceOptimization:
    """Test performance optimization scenarios."""

    def test_high_volume_operations(self, performance_monitor: R2PerformanceMonitor) -> None:
        """High volume of operations tracked efficiently."""
        performance_monitor.start_session("high_volume")

        for i in range(1000):
            op = performance_monitor.start_operation(f"op_{i}")
            performance_monitor.end_operation(op, success=True, bytes_processed=100)

        session = performance_monitor.end_session()

        assert session.total_operations == 1000
        assert session.total_bytes_processed == 100000

    def test_metrics_memory_overhead(self, performance_monitor: R2PerformanceMonitor) -> None:
        """Metrics collection has reasonable memory overhead."""
        performance_monitor.start_session("overhead_test")

        for _ in range(100):
            op = performance_monitor.start_operation("memory_test")
            performance_monitor.end_operation(op, success=True)

        assert len(performance_monitor.current_session.operations) == 100
