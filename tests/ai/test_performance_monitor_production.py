"""Production tests for comprehensive performance monitoring.

Tests real system monitoring, metric collection, profiling,
and performance assessment capabilities.
"""

import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from intellicrack.ai.performance_monitor import (
    AsyncPerformanceMonitor,
    PerformanceMetric,
    PerformanceMonitor,
    PerformanceProfile,
    get_async_monitor,
    get_performance_monitor,
    monitor_memory_usage,
    profile_ai_operation,
)


@pytest.fixture
def perf_monitor() -> PerformanceMonitor:
    """Create fresh performance monitor for testing."""
    return PerformanceMonitor(max_history=100)


def test_performance_monitor_initialization(perf_monitor: PerformanceMonitor) -> None:
    """Test performance monitor initializes correctly."""
    assert perf_monitor.max_history == 100
    assert len(perf_monitor.metrics) == 0
    assert len(perf_monitor.profiles) == 0
    assert perf_monitor.baseline_memory >= 0


def test_record_metric(perf_monitor: PerformanceMonitor) -> None:
    """Test recording individual metrics."""
    perf_monitor.record_metric("test_metric", 42.5, "units", category="testing")

    assert "test_metric" in perf_monitor.metrics
    assert len(perf_monitor.metrics["test_metric"]) == 1

    metric = perf_monitor.metrics["test_metric"][0]
    assert metric.name == "test_metric"
    assert metric.value == 42.5
    assert metric.unit == "units"
    assert metric.category == "testing"


def test_profile_operation_context_manager(perf_monitor: PerformanceMonitor) -> None:
    """Test operation profiling with context manager."""
    with perf_monitor.profile_operation("test_operation", metadata={"type": "test"}):
        time.sleep(0.1)

    assert len(perf_monitor.profiles) == 1
    profile = perf_monitor.profiles[0]

    assert profile.operation_name == "test_operation"
    assert profile.execution_time >= 0.1
    assert profile.success is True
    assert profile.error_message is None
    assert profile.metadata["type"] == "test"


def test_profile_operation_with_exception(perf_monitor: PerformanceMonitor) -> None:
    """Test profiling captures exceptions correctly."""
    with pytest.raises(ValueError, match="Test error"):
        with perf_monitor.profile_operation("failing_operation"):
            raise ValueError("Test error")

    assert len(perf_monitor.profiles) == 1
    profile = perf_monitor.profiles[0]

    assert profile.success is False
    assert profile.error_message is not None
    assert "Test error" in profile.error_message


def test_time_function_decorator(perf_monitor: PerformanceMonitor) -> None:
    """Test function timing decorator."""

    @perf_monitor.time_function("test_function")
    def sample_function(x: int, y: int) -> int:
        time.sleep(0.05)
        return x + y

    result = sample_function(3, 5)

    assert result == 8
    assert len(perf_monitor.profiles) == 1
    assert perf_monitor.profiles[0].operation_name == "test_function"
    assert perf_monitor.profiles[0].execution_time >= 0.05


def test_start_stop_monitoring(perf_monitor: PerformanceMonitor) -> None:
    """Test background monitoring start and stop."""
    perf_monitor.start_monitoring(interval=0.5)

    assert perf_monitor._monitoring_active is True
    assert perf_monitor._monitor_thread is not None

    time.sleep(1.5)

    assert "system.cpu_usage" in perf_monitor.metrics
    assert "system.memory_rss" in perf_monitor.metrics

    perf_monitor.stop_monitoring()
    assert perf_monitor._monitoring_active is False


def test_get_metrics_summary(perf_monitor: PerformanceMonitor) -> None:
    """Test metrics summary generation."""
    perf_monitor.record_metric("cpu_usage", 45.5, "percent")
    perf_monitor.record_metric("cpu_usage", 50.0, "percent")
    perf_monitor.record_metric("cpu_usage", 42.0, "percent")

    with perf_monitor.profile_operation("op1"):
        time.sleep(0.1)

    summary = perf_monitor.get_metrics_summary(timedelta(minutes=5))

    assert "timeframe" in summary
    assert "metrics" in summary
    assert "operation_summary" in summary
    assert "system_health" in summary

    assert "cpu_usage" in summary["metrics"]
    cpu_metrics = summary["metrics"]["cpu_usage"]
    assert cpu_metrics["count"] == 3
    assert cpu_metrics["avg"] == pytest.approx(45.83, abs=0.01)
    assert cpu_metrics["min"] == 42.0
    assert cpu_metrics["max"] == 50.0


def test_system_health_assessment(perf_monitor: PerformanceMonitor) -> None:
    """Test system health assessment logic."""
    health = perf_monitor._assess_system_health()

    assert "score" in health
    assert "status" in health
    assert health["status"] in ["healthy", "degraded", "critical", "unknown"]
    assert 0 <= health["score"] <= 100


def test_threshold_checking(perf_monitor: PerformanceMonitor) -> None:
    """Test threshold breach detection."""
    perf_monitor.thresholds["cpu_usage"]["warning"] = 10.0
    perf_monitor.thresholds["cpu_usage"]["critical"] = 20.0

    triggered = False

    def optimization_rule(metric_name: str, level: str, value: float) -> None:
        nonlocal triggered
        if metric_name == "cpu_usage" and level == "critical":
            triggered = True

    perf_monitor.add_optimization_rule(optimization_rule)

    perf_monitor._check_thresholds(25.0, 100_000_000, 50_000_000)

    assert triggered is True


def test_get_performance_recommendations(perf_monitor: PerformanceMonitor) -> None:
    """Test performance recommendations generation."""
    with perf_monitor.profile_operation("slow_operation"):
        time.sleep(0.5)

    recommendations = perf_monitor.get_performance_recommendations()

    assert isinstance(recommendations, list)


def test_export_metrics(perf_monitor: PerformanceMonitor) -> None:
    """Test metrics export to file."""
    perf_monitor.record_metric("test_export", 123.45, "units")

    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        export_path = Path(f.name)

    try:
        perf_monitor.export_metrics(export_path, format="json")

        assert export_path.exists()

        import json

        with open(export_path) as f:
            data = json.load(f)

        assert "timeframe" in data
        assert "metrics" in data
    finally:
        export_path.unlink(missing_ok=True)


def test_performance_cache(perf_monitor: PerformanceMonitor) -> None:
    """Test performance result caching."""
    test_result = {"key": "value", "metric": 42}

    perf_monitor.cache_result("test_key", test_result)
    cached = perf_monitor.get_cached_result("test_key")

    assert cached is not None
    assert cached["key"] == "value"
    assert cached["metric"] == 42


def test_cache_expiration(perf_monitor: PerformanceMonitor) -> None:
    """Test cache expiration."""
    perf_monitor.cache_ttl = 1
    perf_monitor.cache_result("expire_key", {"data": "test"})

    time.sleep(0.2)

    cached = perf_monitor.get_cached_result("expire_key")
    assert cached is None


def test_optimize_cache(perf_monitor: PerformanceMonitor) -> None:
    """Test cache optimization removes expired entries."""
    perf_monitor.cache_ttl = 1

    perf_monitor.cache_result("key1", {"data": 1})
    perf_monitor.cache_result("key2", {"data": 2})

    time.sleep(0.2)
    perf_monitor.optimize_cache()

    assert len(perf_monitor.performance_cache) == 0


def test_context_manager_interface(perf_monitor: PerformanceMonitor) -> None:
    """Test performance monitor as context manager."""
    with perf_monitor as pm:
        assert pm._monitoring_active is True
        time.sleep(0.5)

    assert perf_monitor._monitoring_active is False


def test_async_performance_monitor() -> None:
    """Test async performance monitor initialization."""
    base_monitor = PerformanceMonitor()
    async_monitor = AsyncPerformanceMonitor(base_monitor)

    assert async_monitor.base_monitor is base_monitor
    assert len(async_monitor.async_operations) == 0


@pytest.mark.asyncio
async def test_profile_async_operation() -> None:
    """Test async operation profiling."""
    base_monitor = PerformanceMonitor()
    async_monitor = AsyncPerformanceMonitor(base_monitor)

    async def async_operation() -> str:
        import asyncio

        await asyncio.sleep(0.1)
        return "completed"

    result = await async_monitor.profile_async_operation("test_async", async_operation())

    assert result == "completed"
    assert len(base_monitor.profiles) == 1
    assert base_monitor.profiles[0].operation_name == "async.test_async"


@pytest.mark.asyncio
async def test_profile_async_decorator() -> None:
    """Test async profiling decorator."""
    base_monitor = PerformanceMonitor()
    async_monitor = AsyncPerformanceMonitor(base_monitor)

    @async_monitor.profile_async("decorated_async")
    async def decorated_function(value: int) -> int:
        import asyncio

        await asyncio.sleep(0.05)
        return value * 2

    result = await decorated_function(5)

    assert result == 10
    assert len(base_monitor.profiles) == 1


def test_get_performance_monitor_singleton() -> None:
    """Test global performance monitor singleton."""
    monitor1 = get_performance_monitor()
    monitor2 = get_performance_monitor()

    assert monitor1 is monitor2
    assert isinstance(monitor1, PerformanceMonitor)


def test_get_async_monitor_singleton() -> None:
    """Test global async monitor singleton."""
    monitor1 = get_async_monitor()
    monitor2 = get_async_monitor()

    assert monitor1 is monitor2
    assert isinstance(monitor1, AsyncPerformanceMonitor)


def test_monitor_memory_usage_context() -> None:
    """Test memory monitoring context manager."""
    with monitor_memory_usage(threshold_mb=1.0):
        data = [0] * 1000

    monitor = get_performance_monitor()
    assert "memory.operation_increase" in monitor.metrics


def test_performance_metric_dataclass() -> None:
    """Test PerformanceMetric dataclass."""
    timestamp = datetime.now()
    metric = PerformanceMetric(
        name="test_metric",
        value=123.45,
        unit="ms",
        timestamp=timestamp,
        category="performance",
        context={"source": "test"},
    )

    assert metric.name == "test_metric"
    assert metric.value == 123.45
    assert metric.unit == "ms"
    assert metric.timestamp == timestamp
    assert metric.category == "performance"
    assert metric.context["source"] == "test"


def test_performance_profile_dataclass() -> None:
    """Test PerformanceProfile dataclass."""
    timestamp = datetime.now()
    profile = PerformanceProfile(
        operation_name="test_op",
        execution_time=1.5,
        memory_usage=1024 * 1024,
        cpu_usage=45.5,
        success=True,
        error_message=None,
        timestamp=timestamp,
        metadata={"category": "test"},
    )

    assert profile.operation_name == "test_op"
    assert profile.execution_time == 1.5
    assert profile.memory_usage == 1024 * 1024
    assert profile.cpu_usage == 45.5
    assert profile.success is True


def test_max_history_enforcement(perf_monitor: PerformanceMonitor) -> None:
    """Test max history limit is enforced."""
    for i in range(150):
        perf_monitor.record_metric("overflow_metric", float(i), "count")

    assert len(perf_monitor.metrics["overflow_metric"]) == 100


def test_operation_summary_statistics(perf_monitor: PerformanceMonitor) -> None:
    """Test operation statistics in summary."""
    for i in range(5):
        with perf_monitor.profile_operation("repeated_op"):
            time.sleep(0.05)

    summary = perf_monitor.get_metrics_summary(timedelta(hours=1))

    assert "operation_summary" in summary
    assert "repeated_op" in summary["operation_summary"]

    op_stats = summary["operation_summary"]["repeated_op"]
    assert op_stats["count"] == 5
    assert op_stats["avg_execution_time"] >= 0.05
    assert op_stats["success_rate"] == 1.0
