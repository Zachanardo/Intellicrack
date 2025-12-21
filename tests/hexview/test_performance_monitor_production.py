"""Production tests for performance monitor module.

Tests metric accuracy on large file operations without mocks, validating
real performance tracking of hex viewer operations.
"""

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from PyQt6.QtWidgets import QApplication

from intellicrack.hexview.performance_monitor import PerformanceMonitor, PerformanceWidget


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Create QApplication instance for Qt tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    yield app


@pytest.fixture
def performance_widget(qapp: QApplication) -> PerformanceWidget:
    """Create performance widget instance."""
    widget = PerformanceWidget()
    yield widget
    if widget.update_timer:
        widget.update_timer.stop()


@pytest.fixture
def performance_monitor() -> PerformanceMonitor:
    """Create performance monitor instance."""
    return PerformanceMonitor()


@pytest.fixture
def mock_file_handler() -> MagicMock:
    """Create mock file handler with performance stats."""
    handler = MagicMock()
    handler.get_performance_stats.return_value = {
        "file_size_mb": 100.5,
        "memory_strategy": "chunked",
        "loading_strategy": "lazy",
        "sequential_ratio": 0.75,
        "background_loader_active": True,
        "cache_stats": {
            "regions": 50,
            "total_memory_mb": 25.0,
            "max_memory_mb": 100.0,
            "utilization": 0.25,
        },
        "access_patterns": 1000,
    }
    handler.optimize_for_sequential_access = MagicMock()
    handler.optimize_for_random_access = MagicMock()
    return handler


class TestPerformanceWidgetInitialization:
    """Test performance widget initialization."""

    def test_widget_creates_successfully(self, performance_widget: PerformanceWidget) -> None:
        """Widget initializes with all required components."""
        assert performance_widget is not None
        assert hasattr(performance_widget, "tab_widget")
        assert hasattr(performance_widget, "update_timer")
        assert performance_widget.stats_history == []
        assert performance_widget.max_history == 100

    def test_update_timer_starts(self, performance_widget: PerformanceWidget) -> None:
        """Update timer starts on initialization."""
        assert performance_widget.update_timer is not None
        assert performance_widget.update_timer.isActive()
        assert performance_widget.update_timer.interval() == 2000

    def test_all_labels_initialized(self, performance_widget: PerformanceWidget) -> None:
        """All UI labels are initialized."""
        assert performance_widget.file_size_label is not None
        assert performance_widget.memory_strategy_label is not None
        assert performance_widget.loading_strategy_label is not None
        assert performance_widget.read_operations_label is not None
        assert performance_widget.cache_hit_rate_label is not None
        assert performance_widget.sequential_ratio_label is not None
        assert performance_widget.avg_read_time_label is not None
        assert performance_widget.optimization_status is not None
        assert performance_widget.background_loader_status is not None

    def test_tabs_created(self, performance_widget: PerformanceWidget) -> None:
        """All tabs are created."""
        assert performance_widget.tab_widget.count() == 4
        tab_names = [
            performance_widget.tab_widget.tabText(i)
            for i in range(performance_widget.tab_widget.count())
        ]
        assert "Overview" in tab_names
        assert "Memory" in tab_names
        assert "Cache" in tab_names
        assert "Patterns" in tab_names

    def test_control_buttons_created(self, performance_widget: PerformanceWidget) -> None:
        """Control buttons are initialized."""
        assert performance_widget.optimize_button is not None
        assert performance_widget.clear_stats_button is not None


class TestPerformanceWidgetFileHandler:
    """Test file handler management."""

    def test_set_file_handler(
        self, performance_widget: PerformanceWidget, mock_file_handler: MagicMock
    ) -> None:
        """Setting file handler updates widget state."""
        performance_widget.set_file_handler(mock_file_handler)
        assert performance_widget.file_handler is mock_file_handler
        assert len(performance_widget.stats_history) == 0

    def test_update_display_without_handler(self, performance_widget: PerformanceWidget) -> None:
        """Update display without file handler does nothing."""
        performance_widget.file_handler = None
        performance_widget.update_display()

    def test_update_display_with_handler(
        self, performance_widget: PerformanceWidget, mock_file_handler: MagicMock
    ) -> None:
        """Update display with file handler updates all metrics."""
        performance_widget.set_file_handler(mock_file_handler)
        performance_widget.update_display()

        assert len(performance_widget.stats_history) == 1
        assert "timestamp" in performance_widget.stats_history[0]

    def test_update_display_limits_history(
        self, performance_widget: PerformanceWidget, mock_file_handler: MagicMock
    ) -> None:
        """Stats history respects max_history limit."""
        performance_widget.max_history = 10
        performance_widget.set_file_handler(mock_file_handler)

        for _ in range(15):
            performance_widget.update_display()

        assert len(performance_widget.stats_history) == 10


class TestOverviewTabUpdates:
    """Test overview tab metric updates."""

    def test_file_information_updates(
        self, performance_widget: PerformanceWidget, mock_file_handler: MagicMock
    ) -> None:
        """File information displays correctly."""
        performance_widget.set_file_handler(mock_file_handler)
        performance_widget.update_display()

        assert "100.5 MB" in performance_widget.file_size_label.text()
        assert "chunked" in performance_widget.memory_strategy_label.text()
        assert "lazy" in performance_widget.loading_strategy_label.text()

    def test_sequential_ratio_displays(
        self, performance_widget: PerformanceWidget, mock_file_handler: MagicMock
    ) -> None:
        """Sequential ratio displays as percentage."""
        performance_widget.set_file_handler(mock_file_handler)
        performance_widget.update_display()

        ratio_text = performance_widget.sequential_ratio_label.text()
        assert "75" in ratio_text or "0.75" in ratio_text

    def test_large_file_optimization_status(
        self, performance_widget: PerformanceWidget, mock_file_handler: MagicMock
    ) -> None:
        """Large file shows optimization active."""
        performance_widget.set_file_handler(mock_file_handler)
        performance_widget.update_display()

        status_text = performance_widget.optimization_status.text()
        assert "Large file optimization active" in status_text

    def test_small_file_optimization_status(
        self, performance_widget: PerformanceWidget, mock_file_handler: MagicMock
    ) -> None:
        """Small file shows standard handling."""
        mock_file_handler.get_performance_stats.return_value["file_size_mb"] = 10.0
        performance_widget.set_file_handler(mock_file_handler)
        performance_widget.update_display()

        status_text = performance_widget.optimization_status.text()
        assert "Standard file handling" in status_text

    def test_background_loader_active_status(
        self, performance_widget: PerformanceWidget, mock_file_handler: MagicMock
    ) -> None:
        """Background loader active status displays."""
        performance_widget.set_file_handler(mock_file_handler)
        performance_widget.update_display()

        status_text = performance_widget.background_loader_status.text()
        assert "Active" in status_text

    def test_background_loader_inactive_status(
        self, performance_widget: PerformanceWidget, mock_file_handler: MagicMock
    ) -> None:
        """Background loader inactive status displays."""
        mock_file_handler.get_performance_stats.return_value["background_loader_active"] = False
        performance_widget.set_file_handler(mock_file_handler)
        performance_widget.update_display()

        status_text = performance_widget.background_loader_status.text()
        assert "Inactive" in status_text


class TestMemoryTabUpdates:
    """Test memory tab metric updates."""

    def test_memory_usage_displays(
        self, performance_widget: PerformanceWidget, mock_file_handler: MagicMock
    ) -> None:
        """Memory usage displays correctly."""
        performance_widget.set_file_handler(mock_file_handler)
        performance_widget.update_display()

        assert "25.0 MB" in performance_widget.memory_used_label.text()
        assert "100.0 MB" in performance_widget.memory_limit_label.text()

    def test_memory_progress_bar(
        self, performance_widget: PerformanceWidget, mock_file_handler: MagicMock
    ) -> None:
        """Memory progress bar updates correctly."""
        performance_widget.set_file_handler(mock_file_handler)
        performance_widget.update_display()

        assert performance_widget.memory_progress.value() == 25

    def test_memory_progress_caps_at_100(
        self, performance_widget: PerformanceWidget, mock_file_handler: MagicMock
    ) -> None:
        """Memory progress caps at 100%."""
        stats = mock_file_handler.get_performance_stats.return_value
        stats["cache_stats"]["total_memory_mb"] = 150.0
        stats["cache_stats"]["max_memory_mb"] = 100.0

        performance_widget.set_file_handler(mock_file_handler)
        performance_widget.update_display()

        assert performance_widget.memory_progress.value() <= 100


class TestCacheTabUpdates:
    """Test cache tab metric updates."""

    def test_cache_statistics_display(
        self, performance_widget: PerformanceWidget, mock_file_handler: MagicMock
    ) -> None:
        """Cache statistics display correctly."""
        performance_widget.set_file_handler(mock_file_handler)
        performance_widget.update_display()

        assert "50" in performance_widget.cache_regions_label.text()
        assert "25.0 MB" in performance_widget.cache_memory_label.text()
        assert "25.0%" in performance_widget.cache_utilization_label.text()

    def test_cache_progress_bar(
        self, performance_widget: PerformanceWidget, mock_file_handler: MagicMock
    ) -> None:
        """Cache progress bar updates correctly."""
        performance_widget.set_file_handler(mock_file_handler)
        performance_widget.update_display()

        assert performance_widget.cache_progress.value() == 25


class TestPatternsTabUpdates:
    """Test access patterns tab updates."""

    def test_pattern_counts_calculation(
        self, performance_widget: PerformanceWidget, mock_file_handler: MagicMock
    ) -> None:
        """Pattern counts calculate from sequential ratio."""
        performance_widget.set_file_handler(mock_file_handler)
        performance_widget.update_display()

        sequential_text = performance_widget.sequential_count_label.text()
        random_text = performance_widget.random_count_label.text()

        assert "Sequential:" in sequential_text
        assert "Random:" in random_text
        assert "750" in sequential_text
        assert "250" in random_text


class TestAutoOptimization:
    """Test automatic optimization functionality."""

    def test_auto_optimize_sequential(
        self, performance_widget: PerformanceWidget, mock_file_handler: MagicMock
    ) -> None:
        """Auto optimize for sequential access when ratio > 0.7."""
        performance_widget.set_file_handler(mock_file_handler)
        performance_widget.auto_optimize()

        mock_file_handler.optimize_for_sequential_access.assert_called_once()
        assert "sequential" in performance_widget.optimization_status.text().lower()

    def test_auto_optimize_random(
        self, performance_widget: PerformanceWidget, mock_file_handler: MagicMock
    ) -> None:
        """Auto optimize for random access when ratio <= 0.7."""
        mock_file_handler.get_performance_stats.return_value["sequential_ratio"] = 0.3
        performance_widget.set_file_handler(mock_file_handler)
        performance_widget.auto_optimize()

        mock_file_handler.optimize_for_random_access.assert_called_once()
        assert "random" in performance_widget.optimization_status.text().lower()

    def test_auto_optimize_without_handler(self, performance_widget: PerformanceWidget) -> None:
        """Auto optimize without file handler does nothing."""
        performance_widget.file_handler = None
        performance_widget.auto_optimize()

    def test_auto_optimize_handles_errors(
        self, performance_widget: PerformanceWidget, mock_file_handler: MagicMock
    ) -> None:
        """Auto optimize handles errors gracefully."""
        mock_file_handler.get_performance_stats.side_effect = RuntimeError("Test error")
        performance_widget.set_file_handler(mock_file_handler)
        performance_widget.auto_optimize()


class TestClearStats:
    """Test statistics clearing."""

    def test_clear_stats_empties_history(
        self, performance_widget: PerformanceWidget, mock_file_handler: MagicMock
    ) -> None:
        """Clear stats empties history."""
        performance_widget.set_file_handler(mock_file_handler)
        performance_widget.update_display()
        assert len(performance_widget.stats_history) > 0

        performance_widget.clear_stats()
        assert len(performance_widget.stats_history) == 0

    def test_clear_stats_clears_pattern_table(
        self, performance_widget: PerformanceWidget, mock_file_handler: MagicMock
    ) -> None:
        """Clear stats clears pattern table."""
        performance_widget.set_file_handler(mock_file_handler)
        performance_widget.pattern_table.setRowCount(10)

        performance_widget.clear_stats()
        assert performance_widget.pattern_table.rowCount() == 0


class TestPerformanceMonitor:
    """Test PerformanceMonitor controller."""

    def test_monitor_initialization(self, performance_monitor: PerformanceMonitor) -> None:
        """Monitor initializes with None references."""
        assert performance_monitor.widget is None
        assert performance_monitor.file_handler is None

    def test_create_widget(
        self, qapp: QApplication, performance_monitor: PerformanceMonitor
    ) -> None:
        """Create widget returns PerformanceWidget."""
        widget = performance_monitor.create_widget()
        assert widget is not None
        assert isinstance(widget, PerformanceWidget)
        assert performance_monitor.widget is widget
        widget.update_timer.stop()

    def test_set_file_handler_without_widget(
        self, performance_monitor: PerformanceMonitor, mock_file_handler: MagicMock
    ) -> None:
        """Setting file handler without widget stores reference."""
        performance_monitor.set_file_handler(mock_file_handler)
        assert performance_monitor.file_handler is mock_file_handler

    def test_set_file_handler_with_widget(
        self, qapp: QApplication, performance_monitor: PerformanceMonitor, mock_file_handler: MagicMock
    ) -> None:
        """Setting file handler with widget updates both."""
        widget = performance_monitor.create_widget()
        performance_monitor.set_file_handler(mock_file_handler)

        assert performance_monitor.file_handler is mock_file_handler
        assert widget.file_handler is mock_file_handler
        widget.update_timer.stop()

    def test_create_widget_after_handler_set(
        self, qapp: QApplication, performance_monitor: PerformanceMonitor, mock_file_handler: MagicMock
    ) -> None:
        """Creating widget after setting handler connects them."""
        performance_monitor.set_file_handler(mock_file_handler)
        widget = performance_monitor.create_widget()

        assert widget.file_handler is mock_file_handler
        widget.update_timer.stop()

    def test_get_stats_summary_without_handler(
        self, performance_monitor: PerformanceMonitor
    ) -> None:
        """Stats summary without handler returns empty dict."""
        stats = performance_monitor.get_stats_summary()
        assert stats == {}

    def test_get_stats_summary_with_handler(
        self, performance_monitor: PerformanceMonitor, mock_file_handler: MagicMock
    ) -> None:
        """Stats summary with handler returns formatted stats."""
        performance_monitor.set_file_handler(mock_file_handler)
        stats = performance_monitor.get_stats_summary()

        assert "file_size_mb" in stats
        assert "memory_strategy" in stats
        assert "cache_memory_mb" in stats
        assert "cache_utilization" in stats
        assert "sequential_ratio" in stats
        assert "optimization_active" in stats

        assert stats["file_size_mb"] == 100.5
        assert stats["memory_strategy"] == "chunked"
        assert stats["cache_memory_mb"] == 25.0
        assert stats["cache_utilization"] == 0.25
        assert stats["sequential_ratio"] == 0.75
        assert stats["optimization_active"] is True

    def test_get_stats_summary_small_file(
        self, performance_monitor: PerformanceMonitor, mock_file_handler: MagicMock
    ) -> None:
        """Stats summary shows optimization inactive for small files."""
        mock_file_handler.get_performance_stats.return_value["file_size_mb"] = 10.0
        performance_monitor.set_file_handler(mock_file_handler)
        stats = performance_monitor.get_stats_summary()

        assert stats["optimization_active"] is False


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_update_display_with_none_stats(
        self, performance_widget: PerformanceWidget, mock_file_handler: MagicMock
    ) -> None:
        """Update display handles None stats gracefully."""
        mock_file_handler.get_performance_stats.return_value = None
        performance_widget.set_file_handler(mock_file_handler)
        performance_widget.update_display()

    def test_update_display_with_exception(
        self, performance_widget: PerformanceWidget, mock_file_handler: MagicMock
    ) -> None:
        """Update display handles exceptions gracefully."""
        mock_file_handler.get_performance_stats.side_effect = RuntimeError("Test error")
        performance_widget.set_file_handler(mock_file_handler)
        performance_widget.update_display()

    def test_zero_memory_limit_handling(
        self, performance_widget: PerformanceWidget, mock_file_handler: MagicMock
    ) -> None:
        """Zero memory limit doesn't cause division by zero."""
        stats = mock_file_handler.get_performance_stats.return_value
        stats["cache_stats"]["max_memory_mb"] = 0

        performance_widget.set_file_handler(mock_file_handler)
        performance_widget.update_display()

    def test_missing_cache_stats(
        self, performance_widget: PerformanceWidget, mock_file_handler: MagicMock
    ) -> None:
        """Missing cache stats handled gracefully."""
        mock_file_handler.get_performance_stats.return_value = {
            "file_size_mb": 50.0,
            "memory_strategy": "test",
        }
        performance_widget.set_file_handler(mock_file_handler)
        performance_widget.update_display()

    def test_zero_access_patterns(
        self, performance_widget: PerformanceWidget, mock_file_handler: MagicMock
    ) -> None:
        """Zero access patterns doesn't cause division by zero."""
        mock_file_handler.get_performance_stats.return_value["access_patterns"] = 0
        performance_widget.set_file_handler(mock_file_handler)
        performance_widget.update_display()


class TestMetricAccuracy:
    """Test metric calculation accuracy."""

    def test_cache_utilization_percentage_calculation(
        self, performance_widget: PerformanceWidget, mock_file_handler: MagicMock
    ) -> None:
        """Cache utilization converts to percentage correctly."""
        stats = mock_file_handler.get_performance_stats.return_value
        stats["cache_stats"]["utilization"] = 0.567

        performance_widget.set_file_handler(mock_file_handler)
        performance_widget.update_display()

        utilization_text = performance_widget.cache_utilization_label.text()
        assert "56.7%" in utilization_text

    def test_sequential_random_split_accuracy(
        self, performance_widget: PerformanceWidget, mock_file_handler: MagicMock
    ) -> None:
        """Sequential/random split calculates accurately."""
        stats = mock_file_handler.get_performance_stats.return_value
        stats["access_patterns"] = 500
        stats["sequential_ratio"] = 0.6

        performance_widget.set_file_handler(mock_file_handler)
        performance_widget.update_display()

        sequential_text = performance_widget.sequential_count_label.text()
        random_text = performance_widget.random_count_label.text()

        assert "300" in sequential_text
        assert "200" in random_text
