"""Production tests for cache management widget - validates real cache operations.

Tests verify cache management widget functionality including viewing cache statistics,
managing cache entries, performing cleanup operations, and interacting with the unified
protection engine's cache system.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import sys
import time
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest

from intellicrack.handlers.pyqt6_handler import QApplication
from intellicrack.protection.analysis_cache import AnalysisCache
from intellicrack.protection.unified_protection_engine import UnifiedProtectionEngine
from intellicrack.ui.widgets.cache_management_widget import CacheManagementWidget, CacheStatsWidget, CacheTopEntriesWidget


class FakeUnifiedProtectionEngine:
    """Real test double for UnifiedProtectionEngine with cache operations."""

    def __init__(self, cache: AnalysisCache, cache_dir: Path) -> None:
        self.cache = cache
        self._cache_dir = cache_dir
        self._cleanup_count = 0
        self._stats_override: dict[str, Any] | None = None
        self._cleanup_error: Exception | None = None

    def get_cache_stats(self) -> dict[str, Any]:
        """Get cache statistics with realistic structure."""
        if self._stats_override is not None:
            return self._stats_override

        return {
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
            "cache_directory": str(self._cache_dir),
            "top_entries": [],
        }

    def cleanup_cache(self) -> int:
        """Cleanup invalid cache entries."""
        if self._cleanup_error:
            raise self._cleanup_error
        return self._cleanup_count

    def save_cache(self) -> None:
        """Save cache to disk."""
        pass

    def clear_cache(self) -> None:
        """Clear all cache entries."""
        self.cache.clear()

    def set_stats_override(self, stats: dict[str, Any]) -> None:
        """Override stats for testing."""
        self._stats_override = stats

    def set_cleanup_count(self, count: int) -> None:
        """Set cleanup return count for testing."""
        self._cleanup_count = count

    def set_cleanup_error(self, error: Exception) -> None:
        """Set cleanup error for testing."""
        self._cleanup_error = error


class FakeMessageBox:
    """Real test double for QMessageBox."""

    Yes = 1
    No = 0

    def __init__(self) -> None:
        self.information_calls: list[tuple[Any, str, str]] = []
        self.critical_calls: list[tuple[Any, str, str]] = []
        self.question_calls: list[tuple[Any, str, str, int]] = []
        self._question_response = self.No

    def information(self, parent: Any, title: str, message: str) -> None:
        """Record information dialog call."""
        self.information_calls.append((parent, title, message))

    def critical(self, parent: Any, title: str, message: str) -> None:
        """Record critical dialog call."""
        self.critical_calls.append((parent, title, message))

    def question(self, parent: Any, title: str, message: str, buttons: int) -> int:
        """Record question dialog call and return preset response."""
        self.question_calls.append((parent, title, message, buttons))
        return self._question_response

    def set_question_response(self, response: int) -> None:
        """Set response for question dialogs."""
        self._question_response = response


class FakeQApplication:
    """Real test double for QApplication."""

    def __init__(self) -> None:
        self._widgets: list[Any] = []

    def allWidgets(self) -> list[Any]:
        """Return list of all widgets."""
        return self._widgets


@pytest.fixture(scope="module")
def qapp() -> Generator[Any, None, None]:
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
def fake_unified_engine(temp_cache_dir: Path) -> FakeUnifiedProtectionEngine:
    """Create fake unified engine with real cache operations."""
    cache = AnalysisCache(str(temp_cache_dir))
    return FakeUnifiedProtectionEngine(cache, temp_cache_dir)


@pytest.fixture
def cache_stats_widget(qapp: Any) -> Generator[CacheStatsWidget, None, None]:
    """Create cache stats widget for testing."""
    widget = CacheStatsWidget()
    yield widget
    widget.deleteLater()


@pytest.fixture
def cache_top_entries_widget(qapp: Any) -> Generator[CacheTopEntriesWidget, None, None]:
    """Create cache top entries widget for testing."""
    widget = CacheTopEntriesWidget()
    yield widget
    widget.deleteLater()


@pytest.fixture
def cache_management_widget(qapp: Any, temp_cache_dir: Path, monkeypatch: pytest.MonkeyPatch) -> Generator[CacheManagementWidget, None, None]:
    """Create cache management widget with temporary cache."""
    cache = AnalysisCache(str(temp_cache_dir))
    engine = FakeUnifiedProtectionEngine(cache, temp_cache_dir)

    def fake_get_unified_engine() -> FakeUnifiedProtectionEngine:
        return engine

    def fake_get_analysis_cache() -> AnalysisCache:
        return cache

    monkeypatch.setattr("intellicrack.ui.widgets.cache_management_widget.get_unified_engine", fake_get_unified_engine)
    monkeypatch.setattr("intellicrack.ui.widgets.cache_management_widget.get_analysis_cache", fake_get_analysis_cache)

    widget = CacheManagementWidget()
    widget.engine = engine  # type: ignore[assignment]
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
        item_0_0 = cache_top_entries_widget.table.item(0, 0)
        item_0_1 = cache_top_entries_widget.table.item(0, 1)
        item_1_0 = cache_top_entries_widget.table.item(1, 0)
        item_2_2 = cache_top_entries_widget.table.item(2, 2)
        assert item_0_0 is not None and item_0_0.text() == "notepad.exe"
        assert item_0_1 is not None and item_0_1.text() == "125"
        assert item_1_0 is not None and item_1_0.text() == "calculator.exe"
        assert item_2_2 is not None and item_2_2.text() == "1024.0"

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
        engine = cache_management_widget.engine
        assert isinstance(engine, FakeUnifiedProtectionEngine)

        engine.set_stats_override({
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
        })

        cache_management_widget.refresh_stats()

        assert cache_management_widget.stats_widget.entries_label.text() == "Entries: 10"
        assert cache_management_widget.top_entries_widget.table.rowCount() == 1
        assert "Total Entries: 10" in cache_management_widget.details_text.toPlainText()

    def test_cleanup_cache_removes_invalid_entries(
        self, cache_management_widget: CacheManagementWidget, qapp: QApplication, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test cleanup operation removes invalid cache entries."""
        engine = cache_management_widget.engine
        assert isinstance(engine, FakeUnifiedProtectionEngine)
        engine.set_cleanup_count(5)

        fake_msgbox = FakeMessageBox()
        monkeypatch.setattr("intellicrack.ui.widgets.cache_management_widget.QMessageBox", fake_msgbox)

        cache_management_widget.cleanup_cache()

        assert len(fake_msgbox.information_calls) == 1
        _, title, message = fake_msgbox.information_calls[0]
        assert "5" in message

    def test_save_cache_persists_to_disk(
        self, cache_management_widget: CacheManagementWidget, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test save button persists cache to disk."""
        fake_msgbox = FakeMessageBox()
        monkeypatch.setattr("intellicrack.ui.widgets.cache_management_widget.QMessageBox", fake_msgbox)

        cache_management_widget.save_cache()

        assert len(fake_msgbox.information_calls) == 1

    def test_clear_cache_with_confirmation(
        self, cache_management_widget: CacheManagementWidget, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test clear cache requires confirmation and emits signal."""
        fake_msgbox = FakeMessageBox()
        fake_msgbox.set_question_response(FakeMessageBox.Yes)
        monkeypatch.setattr("intellicrack.ui.widgets.cache_management_widget.QMessageBox", fake_msgbox)

        fake_qapp = FakeQApplication()
        monkeypatch.setattr("intellicrack.ui.widgets.cache_management_widget.QApplication", fake_qapp)

        signal_emitted = False

        def on_cache_cleared() -> None:
            nonlocal signal_emitted
            signal_emitted = True

        cache_management_widget.cache_cleared.connect(on_cache_cleared)

        cache_management_widget.clear_cache()

        assert len(fake_msgbox.question_calls) == 1
        assert signal_emitted

    def test_clear_cache_cancelled_no_action(
        self, cache_management_widget: CacheManagementWidget, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test clear cache cancellation does not clear cache."""
        fake_msgbox = FakeMessageBox()
        fake_msgbox.set_question_response(FakeMessageBox.No)
        monkeypatch.setattr("intellicrack.ui.widgets.cache_management_widget.QMessageBox", fake_msgbox)

        initial_cache_size = len(cache_management_widget.cache._cache)

        cache_management_widget.clear_cache()

        assert len(cache_management_widget.cache._cache) == initial_cache_size

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
        self, cache_management_widget: CacheManagementWidget, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test cache_cleaned signal emits with correct count."""
        engine = cache_management_widget.engine
        assert isinstance(engine, FakeUnifiedProtectionEngine)
        engine.set_cleanup_count(12)

        signal_count = None

        def on_cache_cleaned(count: int) -> None:
            nonlocal signal_count
            signal_count = count

        cache_management_widget.cache_cleaned.connect(on_cache_cleaned)

        fake_msgbox = FakeMessageBox()
        monkeypatch.setattr("intellicrack.ui.widgets.cache_management_widget.QMessageBox", fake_msgbox)

        cache_management_widget.cleanup_cache()

        assert signal_count == 12


@pytest.mark.integration
class TestCacheManagementIntegration:
    """Integration tests with real cache operations."""

    def test_widget_with_real_cache_engine(
        self, qapp: QApplication, temp_cache_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test widget integrates with real cache engine."""
        cache = AnalysisCache(str(temp_cache_dir))
        engine = FakeUnifiedProtectionEngine(cache, temp_cache_dir)

        cache.put("test_binary.exe", {"protection": "VMProtect"})
        cache.put("app.exe", {"protection": "Themida"})

        engine.set_stats_override({
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
        })

        def fake_get_unified_engine() -> FakeUnifiedProtectionEngine:
            return engine

        def fake_get_analysis_cache() -> AnalysisCache:
            return cache

        monkeypatch.setattr("intellicrack.ui.widgets.cache_management_widget.get_unified_engine", fake_get_unified_engine)
        monkeypatch.setattr("intellicrack.ui.widgets.cache_management_widget.get_analysis_cache", fake_get_analysis_cache)

        widget = CacheManagementWidget()

        try:
            widget.refresh_stats()

            assert widget.stats_widget.entries_label.text() == "Entries: 2"
            assert "71.4%" in widget.stats_widget.hit_rate_label.text()
        finally:
            widget.timer.stop()
            widget.deleteLater()

    def test_cache_operations_error_handling(
        self, cache_management_widget: CacheManagementWidget, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test widget handles cache operation errors gracefully."""
        engine = cache_management_widget.engine
        assert isinstance(engine, FakeUnifiedProtectionEngine)
        engine.set_cleanup_error(Exception("Cache error"))

        fake_msgbox = FakeMessageBox()
        monkeypatch.setattr("intellicrack.ui.widgets.cache_management_widget.QMessageBox", fake_msgbox)

        cache_management_widget.cleanup_cache()

        assert len(fake_msgbox.critical_calls) == 1
        _, title, message = fake_msgbox.critical_calls[0]
        assert "Cache error" in message
