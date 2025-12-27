"""Production tests for simple performance monitor.

Tests real-time performance tracking for AI operations.
"""

import time
from typing import Any

import pytest

from intellicrack.ai.performance_monitor_simple import (
    AsyncPerformanceMonitor,
    PerformanceMonitor,
    get_async_monitor,
    get_performance_monitor,
    profile_ai_operation,
)


@pytest.fixture
def perf_monitor() -> PerformanceMonitor:
    """Create fresh performance monitor."""
    return PerformanceMonitor()


def test_performance_monitor_initialization(perf_monitor: PerformanceMonitor) -> None:
    """Test monitor initializes correctly."""
    assert len(perf_monitor.metrics) == 0
    assert len(perf_monitor.operation_counts) == 0
    assert len(perf_monitor.error_counts) == 0


def test_start_and_end_operation(perf_monitor: PerformanceMonitor) -> None:
    """Test operation timing."""
    operation_id = perf_monitor.start_operation("test_operation")

    assert operation_id in perf_monitor.start_times
    assert "test_operation" in operation_id

    time.sleep(0.1)

    perf_monitor.end_operation(operation_id, "test_operation", success=True)

    assert operation_id not in perf_monitor.start_times
    assert "test_operation" in perf_monitor.metrics
    assert len(perf_monitor.metrics["test_operation"]) == 1

    metric = perf_monitor.metrics["test_operation"][0]
    assert metric["duration"] >= 0.1
    assert metric["success"] is True


def test_operation_failure_tracking(perf_monitor: PerformanceMonitor) -> None:
    """Test failed operation tracking."""
    operation_id = perf_monitor.start_operation("failing_operation")
    perf_monitor.end_operation(operation_id, "failing_operation", success=False)

    assert perf_monitor.error_counts["failing_operation"] == 1
    assert perf_monitor.operation_counts["failing_operation"] == 1


def test_get_stats_success(perf_monitor: PerformanceMonitor) -> None:
    """Test statistics retrieval."""
    for i in range(5):
        op_id = perf_monitor.start_operation("stats_op")
        time.sleep(0.05)
        perf_monitor.end_operation(op_id, "stats_op", success=True)

    stats = perf_monitor.get_stats("stats_op")

    assert stats["count"] == 5
    assert stats["avg_duration"] >= 0.05
    assert stats["min_duration"] >= 0.05
    assert stats["max_duration"] >= 0.05
    assert stats["error_rate"] == 0.0
    assert stats["total_operations"] == 5


def test_get_stats_with_errors(perf_monitor: PerformanceMonitor) -> None:
    """Test statistics with errors."""
    for i in range(3):
        op_id = perf_monitor.start_operation("error_op")
        time.sleep(0.01)
        perf_monitor.end_operation(op_id, "error_op", success=(i != 1))

    stats = perf_monitor.get_stats("error_op")

    assert stats["count"] == 3
    assert stats["error_rate"] == pytest.approx(1 / 3, abs=0.01)


def test_get_stats_nonexistent_operation(perf_monitor: PerformanceMonitor) -> None:
    """Test stats for operation that doesn't exist."""
    stats = perf_monitor.get_stats("nonexistent")

    assert stats == {}


def test_metrics_history_limit(perf_monitor: PerformanceMonitor) -> None:
    """Test metrics history is limited."""
    for i in range(1500):
        op_id = perf_monitor.start_operation("overflow_op")
        perf_monitor.end_operation(op_id, "overflow_op", success=True)

    assert len(perf_monitor.metrics["overflow_op"]) == 1000


def test_concurrent_operations(perf_monitor: PerformanceMonitor) -> None:
    """Test multiple concurrent operations."""
    op1_id = perf_monitor.start_operation("op1")
    op2_id = perf_monitor.start_operation("op2")
    op3_id = perf_monitor.start_operation("op3")

    assert op1_id != op2_id != op3_id

    time.sleep(0.05)

    perf_monitor.end_operation(op1_id, "op1")
    perf_monitor.end_operation(op2_id, "op2")
    perf_monitor.end_operation(op3_id, "op3")

    assert len(perf_monitor.metrics["op1"]) == 1
    assert len(perf_monitor.metrics["op2"]) == 1
    assert len(perf_monitor.metrics["op3"]) == 1


def test_profile_ai_operation_decorator() -> None:
    """Test AI operation profiling decorator."""

    @profile_ai_operation("test_ai_operation")
    def ai_function(x: int, y: int) -> int:
        time.sleep(0.05)
        return x + y

    result = ai_function(3, 5)

    assert result == 8

    monitor = get_performance_monitor()
    assert "test_ai_operation" in monitor.metrics


def test_profile_ai_operation_with_exception() -> None:
    """Test decorator handles exceptions."""

    @profile_ai_operation("failing_ai_op")
    def failing_function() -> None:
        raise ValueError("Test error")

    with pytest.raises(ValueError, match="Test error"):
        failing_function()

    monitor = get_performance_monitor()
    assert "failing_ai_op" in monitor.metrics
    stats = monitor.get_stats("failing_ai_op")
    assert stats["error_rate"] > 0


def test_async_performance_monitor() -> None:
    """Test async monitor initialization."""
    async_monitor = AsyncPerformanceMonitor()

    assert len(async_monitor.active_operations) == 0
    assert len(async_monitor.completed_operations) == 0


@pytest.mark.asyncio
async def test_monitor_async_operation() -> None:
    """Test async operation monitoring."""
    async_monitor = AsyncPerformanceMonitor()

    async def async_task() -> str:
        import asyncio

        await asyncio.sleep(0.1)
        return "completed"

    result = await async_monitor.monitor_operation("test_async", async_task())

    assert result == "completed"
    assert len(async_monitor.completed_operations) == 1

    completed = async_monitor.completed_operations[0]
    assert completed["name"] == "test_async"
    assert completed["duration"] >= 0.1
    assert completed["success"] is True


@pytest.mark.asyncio
async def test_monitor_async_operation_failure() -> None:
    """Test async operation failure tracking."""
    async_monitor = AsyncPerformanceMonitor()

    async def failing_task() -> None:
        raise RuntimeError("Async error")

    with pytest.raises(RuntimeError, match="Async error"):
        await async_monitor.monitor_operation("failing_async", failing_task())

    assert len(async_monitor.completed_operations) == 1
    assert async_monitor.completed_operations[0]["success"] is False


def test_get_active_count(perf_monitor: PerformanceMonitor) -> None:
    """Test active operation count tracking."""
    async_monitor = AsyncPerformanceMonitor()

    assert async_monitor.get_active_count() == 0


def test_get_performance_monitor_singleton() -> None:
    """Test singleton pattern."""
    monitor1 = get_performance_monitor()
    monitor2 = get_performance_monitor()

    assert monitor1 is monitor2


def test_get_async_monitor_singleton() -> None:
    """Test async monitor singleton."""
    monitor1 = get_async_monitor()
    monitor2 = get_async_monitor()

    assert monitor1 is monitor2


def test_operation_id_uniqueness(perf_monitor: PerformanceMonitor) -> None:
    """Test operation IDs are unique."""
    ids = set()
    for _ in range(100):
        op_id = perf_monitor.start_operation("unique_test")
        ids.add(op_id)
        perf_monitor.end_operation(op_id, "unique_test")

    assert len(ids) == 100


def test_timestamp_recording(perf_monitor: PerformanceMonitor) -> None:
    """Test timestamps are recorded correctly."""
    op_id = perf_monitor.start_operation("timestamp_test")
    time.sleep(0.1)
    perf_monitor.end_operation(op_id, "timestamp_test")

    metric = perf_monitor.metrics["timestamp_test"][0]
    assert "timestamp" in metric
    assert metric["timestamp"] > 0
