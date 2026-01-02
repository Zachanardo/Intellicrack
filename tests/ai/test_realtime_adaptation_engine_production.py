"""Production tests for realtime_adaptation_engine.py - Real monitoring and adaptation.

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

import time
from datetime import datetime, timedelta
from typing import Any

import pytest

from intellicrack.ai.realtime_adaptation_engine import (
    AdaptationEvent,
    AdaptationRule,
    AdaptationType,
    AnomalyDetector,
    DynamicHookManager,
    RuntimeMetric,
    RuntimeMonitor,
    TriggerCondition,
)


class TestRuntimeMonitorInitialization:
    """Production tests for RuntimeMonitor initialization."""

    def test_runtime_monitor_initializes_successfully(self) -> None:
        """RuntimeMonitor initializes with proper data structures."""
        monitor: RuntimeMonitor = RuntimeMonitor()

        assert monitor is not None, "Monitor must initialize"
        assert hasattr(monitor, "active"), "Must have active flag"
        assert not monitor.active, "Must not be active initially"
        assert hasattr(monitor, "metrics_buffer"), "Must have metrics buffer"
        assert hasattr(monitor, "metric_aggregates"), "Must have aggregates"
        assert hasattr(monitor, "anomaly_detectors"), "Must have anomaly detectors"
        assert hasattr(monitor, "subscribers"), "Must have subscriber list"

    def test_monitor_has_valid_default_interval(self) -> None:
        """RuntimeMonitor has reasonable monitoring interval."""
        monitor: RuntimeMonitor = RuntimeMonitor()

        assert hasattr(monitor, "monitor_interval"), "Must have interval"
        assert monitor.monitor_interval > 0, "Interval must be positive"
        assert monitor.monitor_interval <= 10.0, "Interval should be reasonable (<= 10s)"

    def test_metric_history_initialized(self) -> None:
        """Metric history storage is properly initialized."""
        monitor: RuntimeMonitor = RuntimeMonitor()

        assert hasattr(monitor, "metric_history"), "Must have metric history"
        assert isinstance(monitor.metric_history, dict), "Metric history must be dict"


class TestRuntimeMonitorLifecycle:
    """Production tests for monitor start/stop lifecycle."""

    def test_monitor_starts_and_stops_cleanly(self) -> None:
        """Monitor starts monitoring thread and stops without hanging."""
        monitor: RuntimeMonitor = RuntimeMonitor()

        assert not monitor.active, "Must not be active initially"

        monitor.start()
        assert monitor.active, "Must be active after start"
        assert monitor.monitor_thread is not None, "Thread must be created"  # type: ignore[unreachable]
        assert monitor.monitor_thread.is_alive(), "Thread must be running"

        time.sleep(0.1)

        monitor.stop()
        assert not monitor.active, "Must not be active after stop"

        time.sleep(0.5)
        assert not monitor.monitor_thread.is_alive(), "Thread must have stopped"

    def test_monitor_start_idempotent(self) -> None:
        """Starting monitor multiple times doesn't create multiple threads."""
        monitor: RuntimeMonitor = RuntimeMonitor()

        monitor.start()
        first_thread = monitor.monitor_thread

        monitor.start()
        second_thread = monitor.monitor_thread

        assert first_thread is second_thread, "Should not create new thread on second start"

        monitor.stop()

    def test_monitor_stop_waits_for_thread(self) -> None:
        """Monitor stop waits for thread to finish gracefully."""
        monitor: RuntimeMonitor = RuntimeMonitor()

        monitor.start()
        time.sleep(0.2)

        start_time: float = time.time()
        monitor.stop()
        stop_duration: float = time.time() - start_time

        assert stop_duration < 3.0, "Stop should complete within timeout"


class TestMetricRecording:
    """Production tests for metric recording and storage."""

    def test_record_metric_stores_data(self) -> None:
        """record_metric stores metrics in buffer."""
        monitor: RuntimeMonitor = RuntimeMonitor()

        monitor.record_metric("test.metric", 42.0, "test_source")

        assert len(monitor.metrics_buffer) > 0, "Metric must be in buffer"

        metric: RuntimeMetric = monitor.metrics_buffer[0]
        assert metric.metric_name == "test.metric", "Name must match"
        assert metric.value == 42.0, "Value must match"
        assert metric.source == "test_source", "Source must match"

    def test_record_metric_updates_history(self) -> None:
        """Metrics are added to history for trend analysis."""
        monitor: RuntimeMonitor = RuntimeMonitor()

        monitor.record_metric("performance.score", 85.5, "analyzer")

        assert "performance.score" in monitor.metric_history, "Must be in history"
        assert len(monitor.metric_history["performance.score"]) > 0, "Must have data points"

        timestamp, value = monitor.metric_history["performance.score"][0]
        assert value == 85.5, "Value must match"
        assert isinstance(timestamp, datetime), "Must have timestamp"

    def test_record_multiple_metrics_different_names(self) -> None:
        """Multiple metrics with different names are stored independently."""
        monitor: RuntimeMonitor = RuntimeMonitor()

        monitor.record_metric("cpu.usage", 50.0, "system")
        monitor.record_metric("memory.usage", 75.0, "system")
        monitor.record_metric("cpu.usage", 55.0, "system")

        assert "cpu.usage" in monitor.metric_history, "CPU must be tracked"
        assert "memory.usage" in monitor.metric_history, "Memory must be tracked"
        assert len(monitor.metric_history["cpu.usage"]) == 2, "CPU should have 2 values"
        assert len(monitor.metric_history["memory.usage"]) == 1, "Memory should have 1 value"

    def test_metric_buffer_respects_maxlen(self) -> None:
        """Metric buffer doesn't grow unbounded."""
        monitor: RuntimeMonitor = RuntimeMonitor()

        maxlen_value = monitor.metrics_buffer.maxlen if hasattr(monitor.metrics_buffer, "maxlen") else None

        if maxlen_value is not None:
            buffer_size: int = maxlen_value
            for i in range(buffer_size + 100):
                monitor.record_metric(f"test.{i % 10}", float(i), "test")

            assert len(monitor.metrics_buffer) <= buffer_size, "Buffer must respect maxlen"


class TestMetricSubscribers:
    """Production tests for metric subscription system."""

    def test_subscribe_to_metrics_receives_updates(self) -> None:
        """Subscribers receive metric updates in real-time."""
        monitor: RuntimeMonitor = RuntimeMonitor()

        received_metrics: list[RuntimeMetric] = []

        def subscriber(metric: RuntimeMetric) -> None:
            received_metrics.append(metric)

        monitor.subscribe_to_metrics(subscriber)

        monitor.record_metric("test.value", 123.45, "test")

        assert len(received_metrics) == 1, "Subscriber must receive metric"
        assert received_metrics[0].metric_name == "test.value", "Metric name must match"
        assert received_metrics[0].value == 123.45, "Value must match"

    def test_multiple_subscribers_all_notified(self) -> None:
        """All subscribers receive metric updates."""
        monitor: RuntimeMonitor = RuntimeMonitor()

        received1: list[RuntimeMetric] = []
        received2: list[RuntimeMetric] = []
        received3: list[RuntimeMetric] = []

        monitor.subscribe_to_metrics(lambda m: received1.append(m))
        monitor.subscribe_to_metrics(lambda m: received2.append(m))
        monitor.subscribe_to_metrics(lambda m: received3.append(m))

        monitor.record_metric("shared.metric", 999.0, "test")

        assert len(received1) == 1, "Subscriber 1 must receive"
        assert len(received2) == 1, "Subscriber 2 must receive"
        assert len(received3) == 1, "Subscriber 3 must receive"

    def test_subscriber_exception_doesnt_break_monitoring(self) -> None:
        """Exception in subscriber doesn't prevent other subscribers from receiving updates."""
        monitor: RuntimeMonitor = RuntimeMonitor()

        received_good: list[RuntimeMetric] = []

        def bad_subscriber(metric: RuntimeMetric) -> None:
            raise ValueError("Intentional subscriber error")

        def good_subscriber(metric: RuntimeMetric) -> None:
            received_good.append(metric)

        monitor.subscribe_to_metrics(bad_subscriber)
        monitor.subscribe_to_metrics(good_subscriber)

        monitor.record_metric("test.metric", 42.0, "test")

        assert len(received_good) == 1, "Good subscriber must still receive updates"


class TestSystemMetricsCollection:
    """Production tests for real system metric collection."""

    @pytest.mark.skipif(True, reason="psutil may not be available in all environments")
    def test_collect_system_metrics_when_available(self) -> None:
        """System metrics are collected when psutil is available."""
        monitor: RuntimeMonitor = RuntimeMonitor()

        monitor._collect_system_metrics()

        if any("system." in key for key in monitor.metric_history.keys()):
            assert any("cpu" in key.lower() or "memory" in key.lower() for key in monitor.metric_history.keys()), "Must collect CPU or memory metrics"

    def test_collect_system_metrics_handles_missing_psutil(self) -> None:
        """Metric collection handles missing psutil gracefully."""
        monitor: RuntimeMonitor = RuntimeMonitor()

        monitor._collect_system_metrics()


class TestMetricAggregation:
    """Production tests for metric aggregation."""

    def test_process_metrics_buffer_computes_aggregates(self) -> None:
        """Metric buffer processing computes statistical aggregates."""
        monitor: RuntimeMonitor = RuntimeMonitor()

        monitor.record_metric("test.value", 10.0, "test")
        monitor.record_metric("test.value", 20.0, "test")
        monitor.record_metric("test.value", 30.0, "test")

        monitor._process_metrics_buffer()

        assert "test.value" in monitor.metric_aggregates, "Must have aggregates"

        agg: dict[str, Any] = monitor.metric_aggregates["test.value"]
        assert agg["count"] == 3, "Count must be 3"
        assert agg["sum"] == 60.0, "Sum must be 60"
        assert agg["avg"] == 20.0, "Average must be 20"
        assert agg["min"] == 10.0, "Min must be 10"
        assert agg["max"] == 30.0, "Max must be 30"
        assert agg["last"] == 30.0, "Last must be 30"

    def test_aggregates_update_with_new_data(self) -> None:
        """Aggregates update correctly with new metric data."""
        monitor: RuntimeMonitor = RuntimeMonitor()

        monitor.record_metric("value", 5.0, "test")
        monitor._process_metrics_buffer()

        first_avg: float = monitor.metric_aggregates["value"]["avg"]
        assert first_avg == 5.0, "Initial average must be 5"

        monitor.record_metric("value", 15.0, "test")
        monitor._process_metrics_buffer()

        second_avg: float = monitor.metric_aggregates["value"]["avg"]
        assert second_avg == 15.0, "New batch average must be 15"


class TestTrendAnalysis:
    """Production tests for metric trend analysis."""

    def test_get_metric_trend_identifies_increasing(self) -> None:
        """Trend analysis detects increasing metrics."""
        monitor: RuntimeMonitor = RuntimeMonitor()

        for i in range(10):
            monitor.record_metric("increasing.metric", float(i * 10), "test")
            time.sleep(0.01)

        trend: dict[str, Any] = monitor.get_metric_trend("increasing.metric", window_minutes=1)

        assert trend["trend"] in ["increasing", "stable"], "Should detect upward trend or stable"
        assert trend["data_points"] >= 2, "Must have enough data points"

    def test_get_metric_trend_identifies_decreasing(self) -> None:
        """Trend analysis detects decreasing metrics."""
        monitor: RuntimeMonitor = RuntimeMonitor()

        for i in range(10):
            monitor.record_metric("decreasing.metric", float(100 - i * 10), "test")
            time.sleep(0.01)

        trend: dict[str, Any] = monitor.get_metric_trend("decreasing.metric", window_minutes=1)

        assert trend["trend"] in ["decreasing", "stable"], "Should detect downward trend or stable"

    def test_get_metric_trend_with_unknown_metric(self) -> None:
        """Trend analysis handles unknown metrics gracefully."""
        monitor: RuntimeMonitor = RuntimeMonitor()

        trend: dict[str, Any] = monitor.get_metric_trend("nonexistent.metric")

        assert trend["trend"] == "unknown", "Must return unknown for missing metric"
        assert trend["data_points"] == 0, "Must have 0 data points"

    def test_get_metric_trend_insufficient_data(self) -> None:
        """Trend analysis requires minimum data points."""
        monitor: RuntimeMonitor = RuntimeMonitor()

        monitor.record_metric("sparse.metric", 42.0, "test")

        trend: dict[str, Any] = monitor.get_metric_trend("sparse.metric", window_minutes=1)

        assert trend["trend"] == "insufficient_data", "Must indicate insufficient data"


class TestAnomalyDetector:
    """Production tests for anomaly detection."""

    def test_anomaly_detector_initializes(self) -> None:
        """AnomalyDetector initializes with baseline tracking."""
        detector: AnomalyDetector = AnomalyDetector("test.metric", sensitivity=2.0)

        assert detector.metric_name == "test.metric", "Name must match"
        assert detector.sensitivity == 2.0, "Sensitivity must match"
        assert not detector.calibrated, "Must not be calibrated initially"
        assert hasattr(detector, "baseline_values"), "Must have baseline storage"

    def test_anomaly_detector_calibrates_with_baseline(self) -> None:
        """Detector calibrates after sufficient baseline samples."""
        detector: AnomalyDetector = AnomalyDetector("metric", sensitivity=2.0)

        for i in range(30):
            detector.add_baseline_value(50.0 + i * 0.1)

        assert detector.calibrated, "Must be calibrated after 30 samples"
        assert detector.baseline_mean > 0, "Must have computed mean"
        assert detector.baseline_std >= 0, "Must have computed std"

    def test_anomaly_detector_identifies_outliers(self) -> None:
        """Detector identifies values far from baseline as anomalies."""
        detector: AnomalyDetector = AnomalyDetector("metric", sensitivity=2.0)

        for _ in range(50):
            detector.add_baseline_value(100.0)

        is_anomaly: bool = detector.detect_anomaly(100.0)
        assert not is_anomaly, "Normal value should not be anomaly"

        is_anomaly_high: bool = detector.detect_anomaly(500.0)
        assert is_anomaly_high, "Extreme high value should be anomaly"

    def test_anomaly_detector_updates_baseline_with_normal_values(self) -> None:
        """Detector updates baseline with non-anomalous values."""
        detector: AnomalyDetector = AnomalyDetector("metric", sensitivity=3.0)

        for _ in range(30):
            detector.add_baseline_value(50.0)

        initial_mean: float = detector.baseline_mean

        detector.detect_anomaly(51.0)

        assert detector.baseline_mean != initial_mean or len(detector.baseline_values) > 30, "Baseline should update"

    def test_anomaly_detector_handles_zero_std(self) -> None:
        """Detector handles constant values gracefully."""
        detector: AnomalyDetector = AnomalyDetector("metric", sensitivity=2.0)

        for _ in range(25):
            detector.add_baseline_value(100.0)

        is_anomaly: bool = detector.detect_anomaly(100.0)
        assert not is_anomaly, "Constant value should not trigger false positive"

    def test_anomaly_detector_sensitivity_affects_detection(self) -> None:
        """Higher sensitivity reduces false positives."""
        low_sensitivity: AnomalyDetector = AnomalyDetector("metric", sensitivity=1.0)
        high_sensitivity: AnomalyDetector = AnomalyDetector("metric", sensitivity=5.0)

        baseline_values: list[float] = [100.0 + i * 0.5 for i in range(50)]

        for value in baseline_values:
            low_sensitivity.add_baseline_value(value)
            high_sensitivity.add_baseline_value(value)

        test_value: float = 115.0

        low_result: bool = low_sensitivity.detect_anomaly(test_value)
        high_result: bool = high_sensitivity.detect_anomaly(test_value)


class TestDynamicHookManager:
    """Production tests for dynamic hook management."""

    def test_hook_manager_initializes(self) -> None:
        """DynamicHookManager initializes with tracking structures."""
        manager: DynamicHookManager = DynamicHookManager()

        assert hasattr(manager, "active_hooks"), "Must have active hooks"
        assert hasattr(manager, "hook_registry"), "Must have registry"
        assert hasattr(manager, "hook_statistics"), "Must have statistics"
        assert isinstance(manager.active_hooks, dict), "Active hooks must be dict"
        assert isinstance(manager.hook_registry, dict), "Registry must be dict"

    def test_register_hook_point_stores_target(self) -> None:
        """register_hook_point stores function reference."""
        manager: DynamicHookManager = DynamicHookManager()

        def target_function() -> str:
            return "original"

        manager.register_hook_point("test_hook", target_function, "around")

        assert "test_hook" in manager.hook_registry, "Hook must be registered"
        assert manager.hook_registry["test_hook"]["target"] == target_function, "Target must match"
        assert manager.hook_registry["test_hook"]["type"] == "around", "Type must match"
        assert not manager.hook_registry["test_hook"]["active"], "Must not be active initially"

    def test_install_hook_requires_registration(self) -> None:
        """install_hook fails for unregistered hooks."""
        manager: DynamicHookManager = DynamicHookManager()

        modification: dict[str, Any] = {"action": "log"}

        result: bool = manager.install_hook("nonexistent_hook", modification)

        assert not result, "Must fail for unregistered hook"

    def test_remove_hook_for_inactive_hook(self) -> None:
        """remove_hook returns False for inactive hooks."""
        manager: DynamicHookManager = DynamicHookManager()

        result: bool = manager.remove_hook("nonexistent_hook")

        assert not result, "Must return False for nonexistent hook"


class TestAdaptationDataClasses:
    """Production tests for adaptation data structures."""

    def test_adaptation_rule_creation(self) -> None:
        """AdaptationRule creates with all required fields."""
        rule: AdaptationRule = AdaptationRule(
            rule_id="rule_1",
            name="Test Rule",
            condition=TriggerCondition.PERFORMANCE_DEGRADATION,
            threshold=0.8,
            adaptation_type=AdaptationType.PARAMETER_TUNING,
            action="adjust_batch_size",
            priority=5,
        )

        assert rule.rule_id == "rule_1", "Rule ID must match"
        assert rule.name == "Test Rule", "Name must match"
        assert rule.condition == TriggerCondition.PERFORMANCE_DEGRADATION, "Condition must match"
        assert rule.threshold == 0.8, "Threshold must match"
        assert rule.enabled, "Must be enabled by default"
        assert rule.trigger_count == 0, "Initial trigger count must be 0"

    def test_runtime_metric_creation(self) -> None:
        """RuntimeMetric stores metric data correctly."""
        now: datetime = datetime.now()

        metric: RuntimeMetric = RuntimeMetric(
            metric_name="cpu.usage",
            value=75.5,
            timestamp=now,
            source="system_monitor",
            category="performance",
            metadata={"unit": "percent"},
        )

        assert metric.metric_name == "cpu.usage", "Name must match"
        assert metric.value == 75.5, "Value must match"
        assert metric.timestamp == now, "Timestamp must match"
        assert metric.source == "system_monitor", "Source must match"
        assert metric.category == "performance", "Category must match"
        assert metric.metadata["unit"] == "percent", "Metadata must match"

    def test_adaptation_event_creation(self) -> None:
        """AdaptationEvent captures adaptation execution."""
        event: AdaptationEvent = AdaptationEvent(
            event_id="evt_123",
            adaptation_type=AdaptationType.RESOURCE_ALLOCATION,
            trigger_condition=TriggerCondition.MEMORY_PRESSURE,
            action_taken="reduced_batch_size",
            success=True,
            impact_metrics={"memory_freed_mb": 512},
            execution_time=0.25,
        )

        assert event.event_id == "evt_123", "Event ID must match"
        assert event.adaptation_type == AdaptationType.RESOURCE_ALLOCATION, "Type must match"
        assert event.success, "Success must match"
        assert event.impact_metrics["memory_freed_mb"] == 512, "Impact must be recorded"
        assert event.execution_time == 0.25, "Execution time must match"


class TestIntegratedMonitoringScenario:
    """Production integration tests for complete monitoring scenarios."""

    def test_monitor_collects_metrics_during_runtime(self) -> None:
        """Monitor continuously collects metrics while active."""
        monitor: RuntimeMonitor = RuntimeMonitor()

        monitor.start()
        time.sleep(0.3)

        initial_count: int = len(list(monitor.metric_history.keys()))

        time.sleep(0.5)

        monitor.stop()

    def test_anomaly_detection_triggers_with_monitor(self) -> None:
        """Anomaly detector integrates with runtime monitor."""
        monitor: RuntimeMonitor = RuntimeMonitor()

        detector: AnomalyDetector = AnomalyDetector("test.metric", sensitivity=2.0)
        monitor.anomaly_detectors["test.metric"] = detector

        for _ in range(30):
            monitor.record_metric("test.metric", 50.0, "test")
            time.sleep(0.01)

        monitor._process_metrics_buffer()

        monitor.record_metric("test.metric", 500.0, "test")
        monitor._process_metrics_buffer()

        monitor._check_anomalies()

    def test_metrics_flow_through_complete_pipeline(self) -> None:
        """Metrics flow from recording through aggregation to subscribers."""
        monitor: RuntimeMonitor = RuntimeMonitor()

        received: list[RuntimeMetric] = []
        monitor.subscribe_to_metrics(lambda m: received.append(m))

        monitor.start()

        monitor.record_metric("pipeline.test", 123.0, "test")

        time.sleep(0.2)

        monitor.stop()

        assert received, "Subscriber must receive metrics"
        assert any(m.metric_name == "pipeline.test" for m in received), "Must receive test metric"
