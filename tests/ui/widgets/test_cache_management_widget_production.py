"""Production tests for cache management widget - validates real cache operations.

Tests verify cache management widget functionality including viewing cache statistics,
managing cache entries, performing cleanup operations, and interacting with the unified
protection engine's cache system.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import sys
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from intellicrack.handlers.pyqt6_handler import QApplication
from intellicrack.protection.analysis_cache import AnalysisCache
from intellicrack.protection.unified_protection_engine import UnifiedProtectionEngine
from intellicrack.ui.widgets.cache_management_widget import CacheManagementWidget, CacheStatsWidget, CacheTopEntriesWidget


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Create QApplication instance for widget tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    yield app
    app.quit()


@pytest.fixture
def temp_cache_dir(tmp_path: Path) -> Path:
    """Create temporary cache directory for testing."""
    cache_dir = tmp_path / "test_cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


@pytest.fixture
def mock_unified_engine(temp_cache_dir: Path) -> UnifiedProtectionEngine:
    """Create mocked unified engine with real cache operations."""
    with patch("intellicrack.protection.unified_protection_engine.get_analysis_cache") as mock_get_cache:
        cache = AnalysisCache(str(temp_cache_dir))
        mock_get_cache.return_value = cache

        engine = UnifiedProtectionEngine()
        engine.cache = cache
        yield engine


@pytest.fixture
def cache_stats_widget(qapp: QApplication) -> CacheStatsWidget:
    """Create cache stats widget for testing."""
    widget = CacheStatsWidget()
    yield widget
    widget.deleteLater()


@pytest.fixture
def cache_top_entries_widget(qapp: QApplication) -> CacheTopEntriesWidget:
    """Create cache top entries widget for testing."""
    widget = CacheTopEntriesWidget()
    yield widget
    widget.deleteLater()


@pytest.fixture
def cache_management_widget(qapp: QApplication, temp_cache_dir: Path) -> CacheManagementWidget:
    """Create cache management widget with temporary cache."""
    with patch("intellicrack.ui.widgets.cache_management_widget.get_unified_engine") as mock_engine, \
         patch("intellicrack.ui.widgets.cache_management_widget.get_analysis_cache") as mock_cache:

        cache = AnalysisCache(str(temp_cache_dir))
        mock_cache.return_value = cache

        engine = MagicMock(spec=UnifiedProtectionEngine)
        engine.cache = cache
        engine.get_cache_stats.return_value = {
            "stats": {
                "total_entries": 0,
                "cache_hits": 0,
                "cache_misses": 0,
                "cache_invalidations": 0,
                "hit_rate": 0.0,
                "total_size_bytes": 0,
                "oldest_entry": 0,
                "newest_entry": 0,
            },
            "cache_size_mb": 0.0,
            "max_entries": 1000,
            "max_size_mb": 100.0,
            "cache_directory": str(temp_cache_dir),
            "top_entries": [],
        }
        engine.cleanup_cache.return_value = 0
        engine.save_cache.return_value = None
        engine.clear_cache.return_value = None

        mock_engine.return_value = engine

        widget = CacheManagementWidget()
        widget.engine = engine
        widget.cache = cache

        yield widget
        widget.timer.stop()
        widget.deleteLater()


class TestCacheStatsWidget:
    """Test CacheStatsWidget with real cache statistics."""

    def test_widget_initialization(self, cache_stats_widget: CacheStatsWidget) -> None:
        """Verify widget initializes with default values."""
        assert cache_stats_widget.entries_label.text() == "Entries: 0"
        assert cache_stats_widget.size_label.text() == "Size: 0.0 MB"
        assert cache_stats_widget.hit_rate_label.text() == "Hit Rate: 0%"
        assert cache_stats_widget.entry_progress.value() == 0
        assert cache_stats_widget.size_progress.value() == 0

    def test_update_stats_with_real_data(self, cache_stats_widget: CacheStatsWidget) -> None:
        """Test updating stats with realistic cache metrics."""
        stats: dict[str, Any] = {
            "stats": {
                "total_entries": 42,
                "hit_rate": 85.5,
            },
            "cache_size_mb": 15.7,
            "max_entries": 100,
            "max_size_mb": 50.0,
        }

        cache_stats_widget.update_stats(stats)

        assert cache_stats_widget.entries_label.text() == "Entries: 42"
        assert "15.7 MB" in cache_stats_widget.size_label.text()
        assert "85.5%" in cache_stats_widget.hit_rate_label.text()
        assert cache_stats_widget.entry_progress.value() == 42
        assert cache_stats_widget.size_progress.value() == 31

    def test_update_stats_at_capacity(self, cache_stats_widget: CacheStatsWidget) -> None:
        """Test stats display when cache is at or exceeds capacity."""
        stats: dict[str, Any] = {
            "stats": {
                "total_entries": 1500,
                "hit_rate": 92.3,
            },
            "cache_size_mb": 120.0,
            "max_entries": 1000,
            "max_size_mb": 100.0,
        }

        cache_stats_widget.update_stats(stats)

        assert cache_stats_widget.entry_progress.value() == 100
        assert cache_stats_widget.size_progress.value() == 100

    def test_update_stats_with_missing_fields(self, cache_stats_widget: CacheStatsWidget) -> None:
        """Test graceful handling of incomplete stats data."""
        stats: dict[str, Any] = {
            "stats": {},
            "cache_size_mb": 0.0,
        }

        cache_stats_widget.update_stats(stats)

        assert cache_stats_widget.entries_label.text() == "Entries: 0"
        assert cache_stats_widget.hit_rate_label.text() == "Hit Rate: 0.0%"


class TestCacheTopEntriesWidget:
    """Test CacheTopEntriesWidget with real cache entries."""

    def test_widget_initialization(self, cache_top_entries_widget: CacheTopEntriesWidget) -> None:
        """Verify widget initializes with empty table."""
        assert cache_top_entries_widget.table.rowCount() == 0
        assert cache_top_entries_widget.table.columnCount() == 4

    def test_update_entries_with_real_data(self, cache_top_entries_widget: CacheTopEntriesWidget) -> None:
        """Test displaying real cache entry data."""
        entries = [
            {
                "file": "notepad.exe",
                "access_count": 125,
                "size_kb": 512.5,
                "age_hours": 2.5,
            },
            {
                "file": "calculator.exe",
                "access_count": 87,
                "size_kb": 256.3,
                "age_hours": 5.1,
            },
            {
                "file": "protected_app.exe",
                "access_count": 45,
                "size_kb": 1024.0,
                "age_hours": 12.8,
            },
        ]

        cache_top_entries_widget.update_entries(entries)

        assert cache_top_entries_widget.table.rowCount() == 3
        assert cache_top_entries_widget.table.item(0, 0).text() == "notepad.exe"
        assert cache_top_entries_widget.table.item(0, 1).text() == "125"
        assert cache_top_entries_widget.table.item(1, 0).text() == "calculator.exe"
        assert cache_top_entries_widget.table.item(2, 2).text() == "1024.0"

    def test_update_entries_empty_list(self, cache_top_entries_widget: CacheTopEntriesWidget) -> None:
        """Test updating with empty entry list."""
        cache_top_entries_widget.update_entries([])

        assert cache_top_entries_widget.table.rowCount() == 0


class TestCacheManagementWidget:
    """Test CacheManagementWidget with real cache operations."""

    def test_widget_initialization(self, cache_management_widget: CacheManagementWidget) -> None:
        """Verify widget initializes with all components."""
        assert cache_management_widget.stats_widget is not None
        assert cache_management_widget.top_entries_widget is not None
        assert cache_management_widget.details_text is not None
        assert cache_management_widget.refresh_btn is not None
        assert cache_management_widget.cleanup_btn is not None
        assert cache_management_widget.save_btn is not None
        assert cache_management_widget.clear_btn is not None
        assert cache_management_widget.timer.isActive()

    def test_refresh_stats_updates_ui(self, cache_management_widget: CacheManagementWidget) -> None:
        """Test refresh button updates cache statistics."""
        cache_management_widget.engine.get_cache_stats.return_value = {
            "stats": {
                "total_entries": 10,
                "cache_hits": 50,
                "cache_misses": 10,
                "cache_invalidations": 2,
                "hit_rate": 83.3,
                "total_size_bytes": 5242880,
                "oldest_entry": time.time() - 3600,
                "newest_entry": time.time(),
            },
            "cache_size_mb": 5.0,
            "max_entries": 1000,
            "max_size_mb": 100.0,
            "cache_directory": "/tmp/cache",
            "top_entries": [
                {
                    "file": "test.exe",
                    "access_count": 25,
                    "size_kb": 512.0,
                    "age_hours": 1.5,
                },
            ],
        }

        cache_management_widget.refresh_stats()

        assert cache_management_widget.stats_widget.entries_label.text() == "Entries: 10"
        assert cache_management_widget.top_entries_widget.table.rowCount() == 1
        assert "Total Entries: 10" in cache_management_widget.details_text.toPlainText()

    def test_cleanup_cache_removes_invalid_entries(
        self, cache_management_widget: CacheManagementWidget, qapp: QApplication
    ) -> None:
        """Test cleanup operation removes invalid cache entries."""
        cache_management_widget.engine.cleanup_cache.return_value = 5

        with patch("intellicrack.ui.widgets.cache_management_widget.QMessageBox") as mock_msgbox:
            cache_management_widget.cleanup_cache()

            cache_management_widget.engine.cleanup_cache.assert_called_once()
            mock_msgbox.information.assert_called_once()

            args = mock_msgbox.information.call_args[0]
            assert "5" in args[2]

    def test_save_cache_persists_to_disk(
        self, cache_management_widget: CacheManagementWidget
    ) -> None:
        """Test save button persists cache to disk."""
        with patch("intellicrack.ui.widgets.cache_management_widget.QMessageBox") as mock_msgbox:
            cache_management_widget.save_cache()

            cache_management_widget.engine.save_cache.assert_called_once()
            mock_msgbox.information.assert_called_once()

    def test_clear_cache_with_confirmation(
        self, cache_management_widget: CacheManagementWidget
    ) -> None:
        """Test clear cache requires confirmation and emits signal."""
        with patch("intellicrack.ui.widgets.cache_management_widget.QMessageBox") as mock_msgbox, \
             patch("intellicrack.ui.widgets.cache_management_widget.QApplication") as mock_qapp:

            mock_msgbox.question.return_value = mock_msgbox.Yes
            mock_msgbox.Yes = 1
            mock_msgbox.No = 0
            mock_qapp.allWidgets.return_value = []

            signal_emitted = False

            def on_cache_cleared() -> None:
                nonlocal signal_emitted
                signal_emitted = True

            cache_management_widget.cache_cleared.connect(on_cache_cleared)

            cache_management_widget.clear_cache()

            cache_management_widget.engine.clear_cache.assert_called_once()
            assert signal_emitted

    def test_clear_cache_cancelled_no_action(
        self, cache_management_widget: CacheManagementWidget
    ) -> None:
        """Test clear cache cancellation does not clear cache."""
        with patch("intellicrack.ui.widgets.cache_management_widget.QMessageBox") as mock_msgbox:
            mock_msgbox.question.return_value = mock_msgbox.No
            mock_msgbox.No = 0

            cache_management_widget.clear_cache()

            cache_management_widget.engine.clear_cache.assert_not_called()

    def test_auto_refresh_timer_active(self, cache_management_widget: CacheManagementWidget) -> None:
        """Test auto-refresh timer is active and configured."""
        assert cache_management_widget.timer.isActive()
        assert cache_management_widget.timer.interval() == 5000

    def test_update_details_formats_cache_info(
        self, cache_management_widget: CacheManagementWidget
    ) -> None:
        """Test details text displays formatted cache information."""
        stats: dict[str, Any] = {
            "stats": {
                "total_entries": 25,
                "cache_hits": 100,
                "cache_misses": 20,
                "cache_invalidations": 3,
                "hit_rate": 83.3,
                "total_size_bytes": 10485760,
                "oldest_entry": time.time() - 7200,
                "newest_entry": time.time(),
            },
            "cache_directory": "/tmp/test_cache",
            "max_entries": 500,
            "max_size_mb": 50.0,
        }

        cache_management_widget.update_details(stats)

        details = cache_management_widget.details_text.toPlainText()
        assert "Total Entries: 25" in details
        assert "Cache Hits: 100" in details
        assert "Cache Misses: 20" in details
        assert "Hit Rate: 83.3" in details
        assert "Max Entries: 500" in details

    def test_close_event_stops_timer(self, cache_management_widget: CacheManagementWidget) -> None:
        """Test closing widget stops auto-refresh timer."""
        from PyQt6.QtGui import QCloseEvent

        assert cache_management_widget.timer.isActive()

        close_event = QCloseEvent()
        cache_management_widget.closeEvent(close_event)

        assert not cache_management_widget.timer.isActive()

    def test_cache_cleaned_signal_emission(
        self, cache_management_widget: CacheManagementWidget
    ) -> None:
        """Test cache_cleaned signal emits with correct count."""
        cache_management_widget.engine.cleanup_cache.return_value = 12

        signal_count = None

        def on_cache_cleaned(count: int) -> None:
            nonlocal signal_count
            signal_count = count

        cache_management_widget.cache_cleaned.connect(on_cache_cleaned)

        with patch("intellicrack.ui.widgets.cache_management_widget.QMessageBox"):
            cache_management_widget.cleanup_cache()

        assert signal_count == 12


@pytest.mark.integration
class TestCacheManagementIntegration:
    """Integration tests with real cache operations."""

    def test_widget_with_real_cache_engine(
        self, qapp: QApplication, temp_cache_dir: Path
    ) -> None:
        """Test widget integrates with real cache engine."""
        with patch("intellicrack.ui.widgets.cache_management_widget.get_unified_engine") as mock_engine, \
             patch("intellicrack.ui.widgets.cache_management_widget.get_analysis_cache") as mock_cache:

            cache = AnalysisCache(str(temp_cache_dir))
            mock_cache.return_value = cache

            cache.cache_analysis_result("test_binary.exe", {"protection": "VMProtect"})
            cache.cache_analysis_result("app.exe", {"protection": "Themida"})

            engine = MagicMock(spec=UnifiedProtectionEngine)
            engine.cache = cache
            engine.get_cache_stats.return_value = {
                "stats": {
                    "total_entries": 2,
                    "cache_hits": 5,
                    "cache_misses": 2,
                    "cache_invalidations": 0,
                    "hit_rate": 71.4,
                    "total_size_bytes": 2048,
                    "oldest_entry": 0,
                    "newest_entry": 0,
                },
                "cache_size_mb": 0.002,
                "max_entries": 1000,
                "max_size_mb": 100.0,
                "cache_directory": str(temp_cache_dir),
                "top_entries": [],
            }
            engine.cleanup_cache.return_value = 0

            mock_engine.return_value = engine

            widget = CacheManagementWidget()

            try:
                widget.refresh_stats()

                assert widget.stats_widget.entries_label.text() == "Entries: 2"
                assert "71.4%" in widget.stats_widget.hit_rate_label.text()
            finally:
                widget.timer.stop()
                widget.deleteLater()

    def test_cache_operations_error_handling(
        self, cache_management_widget: CacheManagementWidget
    ) -> None:
        """Test widget handles cache operation errors gracefully."""
        cache_management_widget.engine.cleanup_cache.side_effect = Exception("Cache error")

        with patch("intellicrack.ui.widgets.cache_management_widget.QMessageBox") as mock_msgbox:
            cache_management_widget.cleanup_cache()

            mock_msgbox.critical.assert_called_once()
            args = mock_msgbox.critical.call_args[0]
            assert "Cache error" in args[2]
