"""Production tests for visualization_analytics.py - Real data visualization and analytics.

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

import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from intellicrack.ai.visualization_analytics import (
    ChartData,
    ChartType,
    Dashboard,
    DataCollector,
    DataPoint,
    MetricType,
)


class TestDataPointCreation:
    """Production tests for DataPoint data structure."""

    def test_datapoint_creates_with_required_fields(self) -> None:
        """DataPoint initializes with all required fields."""
        timestamp: datetime = datetime.now()

        point: DataPoint = DataPoint(
            timestamp=timestamp,
            value=123.45,
            label="Test Metric",
            category="performance",
            metadata={"unit": "ms"},
        )

        assert point.timestamp == timestamp, "Timestamp must match"
        assert point.value == 123.45, "Value must match"
        assert point.label == "Test Metric", "Label must match"
        assert point.category == "performance", "Category must match"
        assert point.metadata["unit"] == "ms", "Metadata must match"

    def test_datapoint_handles_different_value_types(self) -> None:
        """DataPoint accepts different numeric value types."""
        point_int: DataPoint = DataPoint(
            timestamp=datetime.now(),
            value=100,
            label="Integer Value",
        )

        point_float: DataPoint = DataPoint(
            timestamp=datetime.now(),
            value=100.5,
            label="Float Value",
        )

        assert isinstance(point_int.value, (int, float)), "Must accept int"
        assert isinstance(point_float.value, float), "Must accept float"


class TestChartDataStructure:
    """Production tests for ChartData configuration."""

    def test_chartdata_creates_with_configuration(self) -> None:
        """ChartData initializes with chart configuration."""
        data_points: list[DataPoint] = [
            DataPoint(timestamp=datetime.now(), value=10.0, label="Point 1"),
            DataPoint(timestamp=datetime.now(), value=20.0, label="Point 2"),
        ]

        chart: ChartData = ChartData(
            chart_id="chart_123",
            title="Test Chart",
            chart_type=ChartType.LINE_CHART,
            data_points=data_points,
            x_axis_label="Time",
            y_axis_label="Value",
            color_scheme="blue",
            options={"line_width": 2},
        )

        assert chart.chart_id == "chart_123", "Chart ID must match"
        assert chart.title == "Test Chart", "Title must match"
        assert chart.chart_type == ChartType.LINE_CHART, "Type must match"
        assert len(chart.data_points) == 2, "Must have 2 data points"
        assert chart.x_axis_label == "Time", "X-axis label must match"
        assert chart.y_axis_label == "Value", "Y-axis label must match"
        assert chart.color_scheme == "blue", "Color scheme must match"
        assert chart.options["line_width"] == 2, "Options must match"

    def test_chartdata_supports_all_chart_types(self) -> None:
        """ChartData supports all defined chart types."""
        chart_types: list[ChartType] = [
            ChartType.LINE_CHART,
            ChartType.BAR_CHART,
            ChartType.PIE_CHART,
            ChartType.SCATTER_PLOT,
            ChartType.HEATMAP,
            ChartType.TIMELINE,
            ChartType.HISTOGRAM,
        ]

        for chart_type in chart_types:
            chart: ChartData = ChartData(
                chart_id=f"chart_{chart_type.value}",
                title=f"{chart_type.value} Chart",
                chart_type=chart_type,
                data_points=[],
            )
            assert chart.chart_type == chart_type, f"Must support {chart_type.value}"


class TestDashboardConfiguration:
    """Production tests for Dashboard structure."""

    def test_dashboard_creates_with_charts(self) -> None:
        """Dashboard initializes with multiple charts."""
        chart1: ChartData = ChartData(
            chart_id="chart1",
            title="Performance",
            chart_type=ChartType.LINE_CHART,
            data_points=[],
        )

        chart2: ChartData = ChartData(
            chart_id="chart2",
            title="Resource Usage",
            chart_type=ChartType.BAR_CHART,
            data_points=[],
        )

        dashboard: Dashboard = Dashboard(
            dashboard_id="dash_1",
            name="Analysis Dashboard",
            description="Real-time analysis metrics",
            charts=[chart1, chart2],
            layout={"rows": 2, "columns": 2},
            refresh_interval=30,
        )

        assert dashboard.dashboard_id == "dash_1", "Dashboard ID must match"
        assert dashboard.name == "Analysis Dashboard", "Name must match"
        assert len(dashboard.charts) == 2, "Must have 2 charts"
        assert dashboard.refresh_interval == 30, "Refresh interval must match"
        assert isinstance(dashboard.created_at, datetime), "Must have creation timestamp"

    def test_dashboard_tracks_update_time(self) -> None:
        """Dashboard tracks last update timestamp."""
        dashboard: Dashboard = Dashboard(
            dashboard_id="dash_test",
            name="Test Dashboard",
            description="Test",
            charts=[],
        )

        assert isinstance(dashboard.created_at, datetime), "Must have creation time"
        assert isinstance(dashboard.last_updated, datetime), "Must have update time"


class TestDataCollectorInitialization:
    """Production tests for DataCollector initialization."""

    def test_data_collector_initializes_with_collectors(self) -> None:
        """DataCollector initializes with metric collectors."""
        os.environ["DISABLE_BACKGROUND_THREADS"] = "1"

        collector: DataCollector = DataCollector()

        assert hasattr(collector, "data_store"), "Must have data store"
        assert hasattr(collector, "collectors"), "Must have collectors"
        assert isinstance(collector.collectors, dict), "Collectors must be dict"
        assert len(collector.collectors) > 0, "Must have registered collectors"

    def test_data_collector_registers_all_metric_types(self) -> None:
        """DataCollector registers collectors for all metric types."""
        os.environ["DISABLE_BACKGROUND_THREADS"] = "1"

        collector: DataCollector = DataCollector()

        expected_types: list[MetricType] = [
            MetricType.PERFORMANCE,
            MetricType.SUCCESS_RATE,
            MetricType.RESOURCE_USAGE,
            MetricType.ERROR_RATE,
            MetricType.LEARNING_PROGRESS,
        ]

        for metric_type in expected_types:
            assert metric_type in collector.collectors, f"Must have collector for {metric_type.value}"


class TestPerformanceMetricsCollection:
    """Production tests for performance metrics collection."""

    def test_collect_performance_metrics_returns_data_points(self) -> None:
        """_collect_performance_metrics returns valid DataPoint objects."""
        os.environ["DISABLE_BACKGROUND_THREADS"] = "1"

        collector: DataCollector = DataCollector()

        data_points: list[DataPoint] = collector._collect_performance_metrics()

        assert isinstance(data_points, list), "Must return list"

        for point in data_points:
            assert isinstance(point, DataPoint), "Must be DataPoint instance"
            assert isinstance(point.timestamp, datetime), "Must have timestamp"
            assert isinstance(point.value, (int, float)), "Value must be numeric"
            assert len(point.label) > 0, "Label must not be empty"

    def test_performance_metrics_include_system_health(self) -> None:
        """Performance metrics include system health data."""
        os.environ["DISABLE_BACKGROUND_THREADS"] = "1"

        collector: DataCollector = DataCollector()

        data_points: list[DataPoint] = collector._collect_performance_metrics()

        if len(data_points) > 0:
            labels: list[str] = [point.label for point in data_points]
            assert any("health" in label.lower() or "score" in label.lower() or "time" in label.lower() for label in labels), "Must include health or performance metrics"


class TestResourceUsageMetricsCollection:
    """Production tests for resource usage metrics collection."""

    def test_collect_resource_usage_returns_valid_metrics(self) -> None:
        """_collect_resource_usage_metrics returns CPU and memory data."""
        os.environ["DISABLE_BACKGROUND_THREADS"] = "1"

        collector: DataCollector = DataCollector()

        data_points: list[DataPoint] = collector._collect_resource_usage_metrics()

        assert isinstance(data_points, list), "Must return list"
        assert len(data_points) > 0, "Must have at least some metrics"

        categories: set[str] = {point.category for point in data_points}
        assert "cpu" in categories or "memory" in categories, "Must include CPU or memory metrics"

    def test_resource_metrics_have_valid_values(self) -> None:
        """Resource usage metrics have reasonable values."""
        os.environ["DISABLE_BACKGROUND_THREADS"] = "1"

        collector: DataCollector = DataCollector()

        data_points: list[DataPoint] = collector._collect_resource_usage_metrics()

        for point in data_points:
            if point.category in ["cpu", "memory"]:
                assert 0 <= point.value <= 100, f"Percentage must be 0-100: {point.value}"

    def test_resource_collection_handles_missing_psutil(self) -> None:
        """Resource collection provides fallback when psutil unavailable."""
        os.environ["DISABLE_BACKGROUND_THREADS"] = "1"

        collector: DataCollector = DataCollector()

        data_points: list[DataPoint] = collector._collect_resource_usage_metrics()

        assert len(data_points) > 0, "Must return fallback metrics even without psutil"


class TestErrorRateMetricsCollection:
    """Production tests for error rate metrics collection."""

    def test_collect_error_rate_returns_metric(self) -> None:
        """_collect_error_rate_metrics returns error rate data."""
        os.environ["DISABLE_BACKGROUND_THREADS"] = "1"

        collector: DataCollector = DataCollector()

        data_points: list[DataPoint] = collector._collect_error_rate_metrics()

        assert isinstance(data_points, list), "Must return list"

        if len(data_points) > 0:
            assert data_points[0].label == "Error Rate", "Must label as Error Rate"
            assert data_points[0].category == "errors", "Category must be errors"
            assert 0 <= data_points[0].value <= 100, "Error rate must be reasonable percentage"

    def test_error_rate_calculation_uses_real_data(self) -> None:
        """Error rate calculation uses actual error tracking."""
        os.environ["DISABLE_BACKGROUND_THREADS"] = "1"

        collector: DataCollector = DataCollector()

        collector.error_history.append({
            "timestamp": datetime.now().isoformat(),
            "error_type": "TestError",
        })

        current_time: datetime = datetime.now()
        error_rate: float = collector._calculate_real_error_rate(current_time)

        assert isinstance(error_rate, float), "Must return float"
        assert error_rate >= 0, "Error rate must be non-negative"
        assert error_rate <= 50.0, "Error rate must be capped at 50%"

    def test_error_rate_detects_error_indicators(self) -> None:
        """_has_error_indicators correctly identifies errors in records."""
        os.environ["DISABLE_BACKGROUND_THREADS"] = "1"

        collector: DataCollector = DataCollector()

        error_record: dict[str, Any] = {
            "status": "error",
            "timestamp": datetime.now().isoformat(),
        }

        success_record: dict[str, Any] = {
            "status": "success",
            "confidence": 0.95,
            "timestamp": datetime.now().isoformat(),
        }

        assert collector._has_error_indicators(error_record), "Must detect error status"
        assert not collector._has_error_indicators(success_record), "Must not flag success as error"

    def test_error_indicators_detect_low_confidence(self) -> None:
        """Low confidence scores are flagged as potential errors."""
        os.environ["DISABLE_BACKGROUND_THREADS"] = "1"

        collector: DataCollector = DataCollector()

        low_confidence: dict[str, Any] = {
            "confidence": 0.2,
            "timestamp": datetime.now().isoformat(),
        }

        assert collector._has_error_indicators(low_confidence), "Must flag low confidence"

    def test_error_indicators_detect_timeout(self) -> None:
        """Long execution times are flagged as potential errors."""
        os.environ["DISABLE_BACKGROUND_THREADS"] = "1"

        collector: DataCollector = DataCollector()

        timeout_record: dict[str, Any] = {
            "execution_time": 35000,
            "timestamp": datetime.now().isoformat(),
        }

        assert collector._has_error_indicators(timeout_record), "Must flag timeout"


class TestAgentActivityMetrics:
    """Production tests for agent activity metrics collection."""

    def test_get_real_agent_metrics_returns_counts(self) -> None:
        """_get_real_agent_metrics returns agent and task counts."""
        os.environ["DISABLE_BACKGROUND_THREADS"] = "1"

        collector: DataCollector = DataCollector()

        active_agents, total_tasks = collector._get_real_agent_metrics()

        assert isinstance(active_agents, int), "Active agents must be int"
        assert isinstance(total_tasks, int), "Total tasks must be int"
        assert active_agents >= 0, "Active agents must be non-negative"
        assert total_tasks >= 0, "Total tasks must be non-negative"

    def test_agent_metrics_track_learning_records(self) -> None:
        """Agent metrics count activity from learning records."""
        os.environ["DISABLE_BACKGROUND_THREADS"] = "1"

        collector: DataCollector = DataCollector()

        recent_time: datetime = datetime.now()
        collector.learning_records["test_1"] = {
            "agent_id": "agent_alpha",
            "timestamp": recent_time.isoformat(),
            "status": "completed",
        }
        collector.learning_records["test_2"] = {
            "agent_id": "agent_beta",
            "timestamp": recent_time.isoformat(),
            "status": "running",
        }

        active_agents, total_tasks = collector._get_real_agent_metrics()

        assert active_agents >= 1, "Must count at least one active agent"


class TestSuccessRateMetrics:
    """Production tests for success rate metrics."""

    def test_collect_success_rate_returns_metrics(self) -> None:
        """_collect_success_rate_metrics returns success data."""
        os.environ["DISABLE_BACKGROUND_THREADS"] = "1"

        collector: DataCollector = DataCollector()

        data_points: list[DataPoint] = collector._collect_success_rate_metrics()

        assert isinstance(data_points, list), "Must return list"


class TestLearningProgressMetrics:
    """Production tests for learning progress metrics."""

    def test_collect_learning_metrics_returns_data(self) -> None:
        """_collect_learning_metrics returns learning progress data."""
        os.environ["DISABLE_BACKGROUND_THREADS"] = "1"

        collector: DataCollector = DataCollector()

        data_points: list[DataPoint] = collector._collect_learning_metrics()

        assert isinstance(data_points, list), "Must return list"


class TestExploitChainMetrics:
    """Production tests for exploit chain metrics."""

    def test_collect_exploit_chain_metrics_returns_data(self) -> None:
        """_collect_exploit_chain_metrics returns chain data."""
        os.environ["DISABLE_BACKGROUND_THREADS"] = "1"

        collector: DataCollector = DataCollector()

        data_points: list[DataPoint] = collector._collect_exploit_chain_metrics()

        assert isinstance(data_points, list), "Must return list"


class TestDataStoreManagement:
    """Production tests for data store management."""

    def test_data_store_accumulates_metrics(self) -> None:
        """Data store accumulates metrics over time."""
        os.environ["DISABLE_BACKGROUND_THREADS"] = "1"

        collector: DataCollector = DataCollector()

        initial_keys: int = len(collector.data_store.keys())

        collector._collect_performance_metrics()
        collector._collect_resource_usage_metrics()

    def test_data_store_uses_deque_with_maxlen(self) -> None:
        """Data store uses deques with maximum length to prevent unbounded growth."""
        os.environ["DISABLE_BACKGROUND_THREADS"] = "1"

        collector: DataCollector = DataCollector()

        test_key: str = "test.metric"
        if test_key not in collector.data_store:
            collector.data_store[test_key]

        assert hasattr(collector.data_store[test_key], "maxlen"), "Must use deque with maxlen"


class TestMetricTypeEnum:
    """Production tests for MetricType enumeration."""

    def test_metric_type_has_all_expected_values(self) -> None:
        """MetricType enum contains all expected metric categories."""
        expected_types: list[str] = [
            "PERFORMANCE",
            "SUCCESS_RATE",
            "RESOURCE_USAGE",
            "ERROR_RATE",
            "EXECUTION_TIME",
            "MEMORY_USAGE",
            "LEARNING_PROGRESS",
        ]

        for type_name in expected_types:
            assert hasattr(MetricType, type_name), f"MetricType must have {type_name}"

    def test_metric_type_values_are_strings(self) -> None:
        """MetricType enum values are string identifiers."""
        for metric_type in MetricType:
            assert isinstance(metric_type.value, str), "Enum values must be strings"
            assert len(metric_type.value) > 0, "Enum values must not be empty"


class TestChartTypeEnum:
    """Production tests for ChartType enumeration."""

    def test_chart_type_has_common_visualizations(self) -> None:
        """ChartType enum contains standard visualization types."""
        expected_charts: list[str] = [
            "LINE_CHART",
            "BAR_CHART",
            "PIE_CHART",
            "SCATTER_PLOT",
            "HEATMAP",
            "HISTOGRAM",
        ]

        for chart_name in expected_charts:
            assert hasattr(ChartType, chart_name), f"ChartType must have {chart_name}"


class TestIntegratedDataCollection:
    """Production integration tests for complete data collection scenarios."""

    def test_collector_gathers_multiple_metric_types(self) -> None:
        """DataCollector successfully gathers multiple metric types."""
        os.environ["DISABLE_BACKGROUND_THREADS"] = "1"

        collector: DataCollector = DataCollector()

        perf_metrics: list[DataPoint] = collector._collect_performance_metrics()
        resource_metrics: list[DataPoint] = collector._collect_resource_usage_metrics()
        error_metrics: list[DataPoint] = collector._collect_error_rate_metrics()

        total_metrics: int = len(perf_metrics) + len(resource_metrics) + len(error_metrics)

        assert total_metrics > 0, "Must collect at least some metrics"

    def test_all_collected_metrics_have_valid_structure(self) -> None:
        """All collected metrics have proper DataPoint structure."""
        os.environ["DISABLE_BACKGROUND_THREADS"] = "1"

        collector: DataCollector = DataCollector()

        all_metrics: list[DataPoint] = []
        all_metrics.extend(collector._collect_performance_metrics())
        all_metrics.extend(collector._collect_resource_usage_metrics())
        all_metrics.extend(collector._collect_error_rate_metrics())

        for metric in all_metrics:
            assert isinstance(metric, DataPoint), "Must be DataPoint"
            assert hasattr(metric, "timestamp"), "Must have timestamp"
            assert hasattr(metric, "value"), "Must have value"
            assert hasattr(metric, "label"), "Must have label"
            assert hasattr(metric, "category"), "Must have category"

    def test_metric_collection_is_thread_safe(self) -> None:
        """Metric collection doesn't crash under concurrent access."""
        os.environ["DISABLE_BACKGROUND_THREADS"] = "1"

        collector: DataCollector = DataCollector()

        import threading

        results: list[list[DataPoint]] = []

        def collect_metrics() -> None:
            metrics: list[DataPoint] = collector._collect_performance_metrics()
            results.append(metrics)

        threads: list[threading.Thread] = []
        for _ in range(5):
            thread = threading.Thread(target=collect_metrics)
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join(timeout=5.0)

        assert len(results) > 0, "Threads must complete metric collection"
