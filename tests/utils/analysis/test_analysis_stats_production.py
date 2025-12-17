"""Production-ready tests for analysis_stats.py.

Tests validate REAL statistical analysis functionality with diverse data types.
All tests use real data structures and verify accurate statistical calculations.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import time
from typing import Any

import pytest

from intellicrack.utils.analysis.analysis_stats import (
    AnalysisStatsGenerator,
    PerformanceTracker,
)


class TestAnalysisStatsGenerator:
    """Test statistical analysis generation with real data."""

    def test_count_by_attribute_basic(self) -> None:
        """Count by attribute works with basic data types."""
        items = [
            {"type": "license_check", "severity": "high"},
            {"type": "trial_check", "severity": "medium"},
            {"type": "license_check", "severity": "low"},
            {"type": "activation", "severity": "high"},
        ]

        counts = AnalysisStatsGenerator.count_by_attribute(items, "type")

        assert counts["license_check"] == 2
        assert counts["trial_check"] == 1
        assert counts["activation"] == 1

    def test_count_by_attribute_numeric_values(self) -> None:
        """Count by attribute handles numeric values correctly."""
        items = [
            {"priority": 1, "name": "check1"},
            {"priority": 2, "name": "check2"},
            {"priority": 1, "name": "check3"},
            {"priority": 3, "name": "check4"},
        ]

        counts = AnalysisStatsGenerator.count_by_attribute(items, "priority")

        assert counts["1"] == 2
        assert counts["2"] == 1
        assert counts["3"] == 1

    def test_count_by_attribute_empty_list(self) -> None:
        """Count by attribute returns empty dict for empty input."""
        counts = AnalysisStatsGenerator.count_by_attribute([], "type")

        assert counts == {}

    def test_count_by_attribute_missing_attribute(self) -> None:
        """Count by attribute ignores items without the attribute."""
        items = [
            {"type": "license", "value": 1},
            {"value": 2},
            {"type": "trial", "value": 3},
        ]

        counts = AnalysisStatsGenerator.count_by_attribute(items, "type")

        assert counts["license"] == 1
        assert counts["trial"] == 1
        assert len(counts) == 2

    def test_calculate_distribution_percentages(self) -> None:
        """Calculate distribution returns accurate percentages."""
        items = [
            {"protection": "VMProtect"},
            {"protection": "Themida"},
            {"protection": "VMProtect"},
            {"protection": "VMProtect"},
        ]

        distribution = AnalysisStatsGenerator.calculate_distribution(items, "protection")

        assert distribution["VMProtect"] == 75.0
        assert distribution["Themida"] == 25.0

    def test_calculate_distribution_empty(self) -> None:
        """Calculate distribution handles empty data."""
        distribution = AnalysisStatsGenerator.calculate_distribution([], "type")

        assert distribution == {}

    def test_aggregate_numeric_stats_comprehensive(self) -> None:
        """Aggregate numeric stats calculates all statistics correctly."""
        items = [
            {"score": 10, "name": "test1"},
            {"score": 20, "name": "test2"},
            {"score": 30, "name": "test3"},
            {"score": 40, "name": "test4"},
            {"score": 50, "name": "test5"},
        ]

        stats = AnalysisStatsGenerator.aggregate_numeric_stats(items, "score")

        assert stats["count"] == 5
        assert stats["min"] == 10.0
        assert stats["max"] == 50.0
        assert stats["avg"] == 30.0
        assert stats["sum"] == 150.0

    def test_aggregate_numeric_stats_mixed_types(self) -> None:
        """Aggregate numeric stats filters non-numeric values."""
        items = [
            {"value": 10},
            {"value": "not_a_number"},
            {"value": 20},
            {"value": None},
            {"value": 30},
        ]

        stats = AnalysisStatsGenerator.aggregate_numeric_stats(items, "value")

        assert stats["count"] == 3
        assert stats["avg"] == 20.0

    def test_aggregate_numeric_stats_floats(self) -> None:
        """Aggregate numeric stats handles float values."""
        items = [
            {"entropy": 7.92},
            {"entropy": 6.45},
            {"entropy": 8.11},
        ]

        stats = AnalysisStatsGenerator.aggregate_numeric_stats(items, "entropy")

        assert stats["count"] == 3
        assert abs(stats["avg"] - 7.493333) < 0.001
        assert stats["min"] == 6.45
        assert stats["max"] == 8.11

    def test_generate_correlation_matrix(self) -> None:
        """Generate correlation matrix calculates correlations correctly."""
        items = [
            {"x": 1, "y": 2, "z": 3},
            {"x": 2, "y": 4, "z": 6},
            {"x": 3, "y": 6, "z": 9},
            {"x": 4, "y": 8, "z": 12},
        ]

        matrix = AnalysisStatsGenerator.generate_correlation_matrix(items, ["x", "y", "z"])

        assert matrix["x"]["x"] == 1.0
        assert matrix["y"]["y"] == 1.0
        assert abs(matrix["x"]["y"] - 1.0) < 0.01
        assert abs(matrix["x"]["z"] - 1.0) < 0.01

    def test_correlation_matrix_no_correlation(self) -> None:
        """Generate correlation matrix handles uncorrelated data."""
        items = [
            {"a": 1, "b": 10},
            {"a": 2, "b": 5},
            {"a": 3, "b": 15},
            {"a": 4, "b": 2},
        ]

        matrix = AnalysisStatsGenerator.generate_correlation_matrix(items, ["a", "b"])

        assert matrix["a"]["a"] == 1.0
        assert matrix["b"]["b"] == 1.0

    def test_generate_time_series_stats(self) -> None:
        """Generate time series stats aggregates data correctly."""
        current_time = int(time.time())
        items = [
            {"timestamp": current_time, "value": 10},
            {"timestamp": current_time + 1800, "value": 20},
            {"timestamp": current_time + 3600, "value": 15},
            {"timestamp": current_time + 3700, "value": 25},
        ]

        time_series = AnalysisStatsGenerator.generate_time_series_stats(
            items, "timestamp", "value", interval_seconds=3600
        )

        assert time_series["interval_seconds"] == 3600
        assert time_series["total_buckets"] >= 1

    def test_time_series_stats_handles_strings(self) -> None:
        """Generate time series stats filters non-numeric values."""
        current_time = int(time.time())
        items = [
            {"timestamp": current_time, "value": 10},
            {"timestamp": current_time + 100, "value": "invalid"},
            {"timestamp": current_time + 200, "value": 20},
        ]

        time_series = AnalysisStatsGenerator.generate_time_series_stats(
            items, "timestamp", "value", interval_seconds=3600
        )

        assert time_series["total_buckets"] >= 1

    def test_generate_summary_report_structure(self) -> None:
        """Generate summary report creates well-formatted output."""
        items = [
            {"type": "license", "risk": 0.8, "name": "check1"},
            {"type": "trial", "risk": 0.6, "name": "check2"},
            {"type": "license", "risk": 0.9, "name": "check3"},
        ]

        report = AnalysisStatsGenerator.generate_summary_report(items, "Security Analysis")

        assert "Security Analysis" in report
        assert "Total Items: 3" in report
        assert "Type:" in report or "Risk:" in report

    def test_summary_report_numeric_attributes(self) -> None:
        """Generate summary report displays numeric statistics."""
        items = [
            {"category": "vuln", "score": 85},
            {"category": "vuln", "score": 92},
            {"category": "vuln", "score": 78},
        ]

        report = AnalysisStatsGenerator.generate_summary_report(items, "Vulnerability Report")

        assert "Score:" in report
        assert "Min:" in report
        assert "Max:" in report
        assert "Average:" in report

    def test_summary_report_empty_data(self) -> None:
        """Generate summary report handles empty data gracefully."""
        report = AnalysisStatsGenerator.generate_summary_report([], "Empty Report")

        assert "Empty Report" in report
        assert "No data to analyze" in report

    def test_calculate_growth_rate_positive(self) -> None:
        """Calculate growth rate computes positive growth correctly."""
        growth = AnalysisStatsGenerator.calculate_growth_rate(150.0, 100.0)

        assert growth == 50.0

    def test_calculate_growth_rate_negative(self) -> None:
        """Calculate growth rate computes negative growth correctly."""
        growth = AnalysisStatsGenerator.calculate_growth_rate(75.0, 100.0)

        assert growth == -25.0

    def test_calculate_growth_rate_zero_previous(self) -> None:
        """Calculate growth rate handles zero previous value."""
        growth = AnalysisStatsGenerator.calculate_growth_rate(100.0, 0.0)

        assert growth == 100.0

    def test_detect_outliers_iqr_method(self) -> None:
        """Detect outliers using IQR method identifies anomalies."""
        values = [10, 12, 14, 13, 11, 15, 100, 9, 13, 14]

        outliers = AnalysisStatsGenerator.detect_outliers(values, method="iqr")

        assert 6 in outliers
        assert len(outliers) >= 1

    def test_detect_outliers_zscore_method(self) -> None:
        """Detect outliers using Z-score method identifies anomalies."""
        values = [50, 52, 51, 53, 50, 200, 49, 51, 52, 50]

        outliers = AnalysisStatsGenerator.detect_outliers(values, method="zscore")

        assert 5 in outliers
        assert len(outliers) >= 1

    def test_detect_outliers_no_outliers(self) -> None:
        """Detect outliers returns empty for normal distribution."""
        values = [10, 11, 12, 13, 14, 15, 16, 17, 18, 19]

        outliers = AnalysisStatsGenerator.detect_outliers(values, method="iqr")

        assert len(outliers) == 0

    def test_detect_outliers_insufficient_data(self) -> None:
        """Detect outliers handles insufficient data."""
        values = [10, 20]

        outliers = AnalysisStatsGenerator.detect_outliers(values, method="iqr")

        assert len(outliers) == 0

    def test_generate_percentiles_standard(self) -> None:
        """Generate percentiles calculates standard percentiles."""
        values = list(range(1, 101))

        percentiles = AnalysisStatsGenerator.generate_percentiles(values)

        assert 25 in percentiles
        assert 50 in percentiles
        assert 75 in percentiles
        assert 90 in percentiles
        assert 95 in percentiles

        assert abs(percentiles[50] - 50.5) < 1.0
        assert abs(percentiles[25] - 25.5) < 1.0

    def test_generate_percentiles_custom(self) -> None:
        """Generate percentiles handles custom percentile values."""
        values = list(range(1, 11))

        percentiles = AnalysisStatsGenerator.generate_percentiles(values, [10, 90])

        assert 10 in percentiles
        assert 90 in percentiles
        assert percentiles[10] <= values[1]
        assert percentiles[90] >= values[8]

    def test_generate_percentiles_empty(self) -> None:
        """Generate percentiles handles empty data."""
        percentiles = AnalysisStatsGenerator.generate_percentiles([])

        assert percentiles == {}

    def test_safe_stats_generation_success(self) -> None:
        """Safe stats generation executes function successfully."""

        def compute_stats() -> dict[str, int]:
            return {"count": 42, "sum": 100}

        result = AnalysisStatsGenerator.safe_stats_generation(compute_stats)

        assert result == {"count": 42, "sum": 100}

    def test_safe_stats_generation_exception(self) -> None:
        """Safe stats generation returns default on exception."""

        def failing_stats() -> None:
            raise ValueError("Test error")

        result = AnalysisStatsGenerator.safe_stats_generation(failing_stats, default_return={"error": True})

        assert result == {"error": True}

    def test_safe_recommendation_generation_success(self) -> None:
        """Safe recommendation generation returns recommendations."""

        def compute_recommendations() -> list[str]:
            return ["Update protection", "Review license"]

        result = AnalysisStatsGenerator.safe_recommendation_generation(compute_recommendations)

        assert len(result) == 2
        assert "Update protection" in result

    def test_safe_recommendation_generation_exception(self) -> None:
        """Safe recommendation generation handles exceptions."""

        def failing_recommendations() -> None:
            raise RuntimeError("Test error")

        result = AnalysisStatsGenerator.safe_recommendation_generation(failing_recommendations)

        assert len(result) > 0
        assert any("unable" in r.lower() for r in result)


class TestPerformanceTracker:
    """Test performance tracking functionality."""

    def test_tracks_single_operation(self) -> None:
        """Performance tracker records single operation metrics."""
        tracker = PerformanceTracker()

        tracker.start_operation("analyze_binary")
        time.sleep(0.1)
        tracker.end_operation("analyze_binary", item_count=1)

        metrics = tracker.get_metrics()

        assert "analyze_binary" in metrics
        assert metrics["analyze_binary"]["call_count"] == 1
        assert metrics["analyze_binary"]["total_time"] >= 0.1
        assert metrics["analyze_binary"]["total_items"] == 1

    def test_tracks_multiple_operations(self) -> None:
        """Performance tracker handles multiple different operations."""
        tracker = PerformanceTracker()

        tracker.start_operation("scan")
        time.sleep(0.05)
        tracker.end_operation("scan", item_count=10)

        tracker.start_operation("analyze")
        time.sleep(0.05)
        tracker.end_operation("analyze", item_count=5)

        metrics = tracker.get_metrics()

        assert "scan" in metrics
        assert "analyze" in metrics
        assert metrics["scan"]["total_items"] == 10
        assert metrics["analyze"]["total_items"] == 5

    def test_aggregates_repeated_operations(self) -> None:
        """Performance tracker aggregates metrics for repeated operations."""
        tracker = PerformanceTracker()

        for _ in range(3):
            tracker.start_operation("process")
            time.sleep(0.01)
            tracker.end_operation("process", item_count=1)

        metrics = tracker.get_metrics()

        assert metrics["process"]["call_count"] == 3
        assert metrics["process"]["total_items"] == 3
        assert metrics["process"]["total_time"] >= 0.03

    def test_calculates_averages(self) -> None:
        """Performance tracker calculates average times correctly."""
        tracker = PerformanceTracker()

        for i in range(5):
            tracker.start_operation("check")
            time.sleep(0.02)
            tracker.end_operation("check", item_count=2)

        metrics = tracker.get_metrics()

        assert metrics["check"]["call_count"] == 5
        assert metrics["check"]["total_items"] == 10
        assert metrics["check"]["avg_time_per_call"] >= 0.02
        assert metrics["check"]["avg_time_per_item"] >= 0.01

    def test_reset_metrics(self) -> None:
        """Performance tracker resets metrics correctly."""
        tracker = PerformanceTracker()

        tracker.start_operation("test")
        tracker.end_operation("test", item_count=1)

        tracker.reset_metrics()
        metrics = tracker.get_metrics()

        assert metrics == {}

    def test_handles_zero_items(self) -> None:
        """Performance tracker handles operations with zero items."""
        tracker = PerformanceTracker()

        tracker.start_operation("empty_op")
        time.sleep(0.01)
        tracker.end_operation("empty_op", item_count=0)

        metrics = tracker.get_metrics()

        assert metrics["empty_op"]["total_items"] == 0
        assert metrics["empty_op"]["avg_time_per_item"] == 0.0


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_non_dict_items(self) -> None:
        """Stats generator handles non-dict items gracefully."""
        items = [1, 2, "string", None, {"type": "valid"}]

        counts = AnalysisStatsGenerator.count_by_attribute(items, "type")

        assert counts["valid"] == 1

    def test_nested_data_structures(self) -> None:
        """Stats generator handles nested data structures."""
        items = [
            {"category": "protection", "details": {"level": "high"}},
            {"category": "license", "details": {"level": "medium"}},
            {"category": "protection", "details": {"level": "low"}},
        ]

        counts = AnalysisStatsGenerator.count_by_attribute(items, "category")

        assert counts["protection"] == 2
        assert counts["license"] == 1

    def test_large_dataset_performance(self) -> None:
        """Stats generator handles large datasets efficiently."""
        items = [{"value": i % 100, "category": f"cat_{i % 10}"} for i in range(10000)]

        start_time = time.time()
        counts = AnalysisStatsGenerator.count_by_attribute(items, "category")
        duration = time.time() - start_time

        assert len(counts) == 10
        assert duration < 1.0

    def test_unicode_attribute_values(self) -> None:
        """Stats generator handles Unicode attribute values."""
        items = [
            {"name": "Test 测试"},
            {"name": "Тест"},
            {"name": "Test 测试"},
        ]

        counts = AnalysisStatsGenerator.count_by_attribute(items, "name")

        assert counts["Test 测试"] == 2
        assert counts["Тест"] == 1

    def test_extreme_numeric_values(self) -> None:
        """Stats generator handles extreme numeric values."""
        items = [
            {"value": 1e-10},
            {"value": 1e10},
            {"value": 0},
        ]

        stats = AnalysisStatsGenerator.aggregate_numeric_stats(items, "value")

        assert stats["count"] == 3
        assert stats["min"] == 1e-10
        assert stats["max"] == 1e10
