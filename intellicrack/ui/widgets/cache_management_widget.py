"""
Cache Management Widget

Provides UI for monitoring and managing the analysis cache.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from typing import Any, Dict

from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ...protection.analysis_cache import get_analysis_cache
from ...protection.unified_protection_engine import get_unified_engine
from ...utils.logger import get_logger

logger = get_logger(__name__)


class CacheStatsWidget(QWidget):
    """Widget displaying cache statistics"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        """Initialize the UI"""
        layout = QVBoxLayout()

        # Cache metrics
        self.metrics_layout = QHBoxLayout()

        # Entry count
        self.entries_label = QLabel("Entries: 0")
        self.entries_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        self.metrics_layout.addWidget(self.entries_label)

        # Cache size
        self.size_label = QLabel("Size: 0.0 MB")
        self.size_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        self.metrics_layout.addWidget(self.size_label)

        # Hit rate
        self.hit_rate_label = QLabel("Hit Rate: 0%")
        self.hit_rate_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        self.metrics_layout.addWidget(self.hit_rate_label)

        layout.addLayout(self.metrics_layout)

        # Progress bars
        progress_group = QGroupBox("Cache Usage")
        progress_layout = QVBoxLayout()

        # Entry count progress
        entry_progress_layout = QHBoxLayout()
        entry_progress_layout.addWidget(QLabel("Entries:"))
        self.entry_progress = QProgressBar()
        self.entry_progress.setMaximum(100)
        entry_progress_layout.addWidget(self.entry_progress)
        progress_layout.addLayout(entry_progress_layout)

        # Size progress
        size_progress_layout = QHBoxLayout()
        size_progress_layout.addWidget(QLabel("Size:"))
        self.size_progress = QProgressBar()
        self.size_progress.setMaximum(100)
        size_progress_layout.addWidget(self.size_progress)
        progress_layout.addLayout(size_progress_layout)

        progress_group.setLayout(progress_layout)
        layout.addWidget(progress_group)

        self.setLayout(layout)

    def update_stats(self, stats: Dict[str, Any]):
        """Update displayed statistics"""
        try:
            stats_data = stats.get('stats', {})

            # Update labels
            self.entries_label.setText(f"Entries: {stats_data.get('total_entries', 0)}")
            self.size_label.setText(f"Size: {stats.get('cache_size_mb', 0):.1f} MB")
            self.hit_rate_label.setText(f"Hit Rate: {stats_data.get('hit_rate', 0):.1f}%")

            # Update progress bars
            max_entries = stats.get('max_entries', 1000)
            current_entries = stats_data.get('total_entries', 0)
            entry_percentage = min(100, (current_entries / max_entries) * 100)
            self.entry_progress.setValue(int(entry_percentage))

            max_size = stats.get('max_size_mb', 100)
            current_size = stats.get('cache_size_mb', 0)
            size_percentage = min(100, (current_size / max_size) * 100)
            self.size_progress.setValue(int(size_percentage))

        except Exception as e:
            logger.error(f"Failed to update cache stats: {e}")


class CacheTopEntriesWidget(QWidget):
    """Widget showing most accessed cache entries"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        """Initialize the UI"""
        layout = QVBoxLayout()

        # Header
        header = QLabel("Most Accessed Entries")
        header.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(header)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["File", "Access Count", "Size (KB)", "Age (Hours)"])

        # Configure table
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)

        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)

        layout.addWidget(self.table)
        self.setLayout(layout)

    def update_entries(self, entries: list):
        """Update top entries table"""
        self.table.setRowCount(len(entries))

        for row, entry in enumerate(entries):
            self.table.setItem(row, 0, QTableWidgetItem(entry.get('file', '')))
            self.table.setItem(row, 1, QTableWidgetItem(str(entry.get('access_count', 0))))
            self.table.setItem(row, 2, QTableWidgetItem(f"{entry.get('size_kb', 0):.1f}"))
            self.table.setItem(row, 3, QTableWidgetItem(f"{entry.get('age_hours', 0):.1f}"))


class CacheManagementWidget(QWidget):
    """Complete cache management interface"""

    cache_cleared = pyqtSignal()
    cache_cleaned = pyqtSignal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.engine = get_unified_engine()
        self.cache = get_analysis_cache()
        self.init_ui()
        self.setup_timer()

    def init_ui(self):
        """Initialize the UI"""
        layout = QVBoxLayout()

        # Title
        title = QLabel("Analysis Cache Management")
        title.setStyleSheet("font-weight: bold; font-size: 16px; color: #2c3e50;")
        layout.addWidget(title)

        # Create splitter for two-panel layout
        splitter = QSplitter(Qt.Horizontal)

        # Left panel - Stats and controls
        left_widget = QWidget()
        left_layout = QVBoxLayout()

        # Cache statistics
        stats_group = QGroupBox("Cache Statistics")
        stats_layout = QVBoxLayout()

        self.stats_widget = CacheStatsWidget()
        stats_layout.addWidget(self.stats_widget)

        stats_group.setLayout(stats_layout)
        left_layout.addWidget(stats_group)

        # Control buttons
        controls_group = QGroupBox("Cache Controls")
        controls_layout = QVBoxLayout()

        # Refresh button
        self.refresh_btn = QPushButton("Refresh Stats")
        self.refresh_btn.clicked.connect(self.refresh_stats)
        controls_layout.addWidget(self.refresh_btn)

        # Cleanup button
        self.cleanup_btn = QPushButton("Cleanup Invalid Entries")
        self.cleanup_btn.clicked.connect(self.cleanup_cache)
        controls_layout.addWidget(self.cleanup_btn)

        # Save button
        self.save_btn = QPushButton("Save Cache to Disk")
        self.save_btn.clicked.connect(self.save_cache)
        controls_layout.addWidget(self.save_btn)

        # Clear button
        self.clear_btn = QPushButton("Clear All Cache")
        self.clear_btn.setStyleSheet("QPushButton { background-color: #e74c3c; color: white; }")
        self.clear_btn.clicked.connect(self.clear_cache)
        controls_layout.addWidget(self.clear_btn)

        controls_group.setLayout(controls_layout)
        left_layout.addWidget(controls_group)

        left_layout.addStretch()
        left_widget.setLayout(left_layout)
        splitter.addWidget(left_widget)

        # Right panel - Top entries and details
        right_widget = QWidget()
        right_layout = QVBoxLayout()

        self.top_entries_widget = CacheTopEntriesWidget()
        right_layout.addWidget(self.top_entries_widget)

        # Cache details
        details_group = QGroupBox("Cache Details")
        details_layout = QVBoxLayout()

        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setMaximumHeight(150)
        self.details_text.setFont(QFont("Consolas", 9))
        details_layout.addWidget(self.details_text)

        details_group.setLayout(details_layout)
        right_layout.addWidget(details_group)

        right_widget.setLayout(right_layout)
        splitter.addWidget(right_widget)

        # Set splitter proportions
        splitter.setSizes([400, 600])

        layout.addWidget(splitter)
        self.setLayout(layout)

        # Initial refresh
        self.refresh_stats()

    def setup_timer(self):
        """Setup auto-refresh timer"""
        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh_stats)
        self.timer.start(5000)  # Refresh every 5 seconds

    def refresh_stats(self):
        """Refresh cache statistics"""
        try:
            stats = self.engine.get_cache_stats()

            # Update stats widget
            self.stats_widget.update_stats(stats)

            # Update top entries
            top_entries = stats.get('top_entries', [])
            self.top_entries_widget.update_entries(top_entries)

            # Update details
            self.update_details(stats)

        except Exception as e:
            logger.error(f"Failed to refresh cache stats: {e}")

    def update_details(self, stats: Dict[str, Any]):
        """Update cache details text"""
        details = []

        stats_data = stats.get('stats', {})

        details.append(f"Cache Directory: {stats.get('cache_directory', 'Unknown')}")
        details.append(f"Total Entries: {stats_data.get('total_entries', 0)}")
        details.append(f"Cache Hits: {stats_data.get('cache_hits', 0)}")
        details.append(f"Cache Misses: {stats_data.get('cache_misses', 0)}")
        details.append(f"Cache Invalidations: {stats_data.get('cache_invalidations', 0)}")
        details.append(f"Hit Rate: {stats_data.get('hit_rate', 0):.2f}%")
        details.append(f"Total Size: {stats_data.get('total_size_bytes', 0) / 1024 / 1024:.2f} MB")
        details.append(f"Max Entries: {stats.get('max_entries', 0)}")
        details.append(f"Max Size: {stats.get('max_size_mb', 0):.1f} MB")

        # Add AI coordination layer performance statistics if available
        try:
            from PyQt5.QtWidgets import QApplication
            main_window = None
            for widget in QApplication.allWidgets():
                if hasattr(widget, 'ai_coordinator') and widget.ai_coordinator:
                    main_window = widget
                    break

            if main_window and hasattr(main_window.ai_coordinator, 'get_performance_stats'):
                ai_stats = main_window.ai_coordinator.get_performance_stats()
                details.append("")
                details.append("=== AI Coordination Layer Performance ===")
                details.append(f"ML Analysis Calls: {ai_stats.get('ml_calls', 0)}")
                details.append(f"LLM Analysis Calls: {ai_stats.get('llm_calls', 0)}")
                details.append(f"Escalations: {ai_stats.get('escalations', 0)}")
                details.append(f"AI Cache Hits: {ai_stats.get('cache_hits', 0)}")
                details.append(f"AI Cache Size: {ai_stats.get('cache_size', 0)} entries")
                details.append(f"Average ML Time: {ai_stats.get('avg_ml_time', 0):.2f}s")
                details.append(f"Average LLM Time: {ai_stats.get('avg_llm_time', 0):.2f}s")
                details.append("Components Available:")
                components = ai_stats.get('components_available', {})
                details.append(f"  - ML Predictor: {'Yes' if components.get('ml_predictor', False) else 'No'}")
                details.append(f"  - Model Manager: {'Yes' if components.get('model_manager', False) else 'No'}")
        except Exception as e:
            logger.debug(f"Could not retrieve AI coordination stats: {e}")

        oldest = stats_data.get('oldest_entry', 0)
        newest = stats_data.get('newest_entry', 0)

        if oldest > 0:
            import datetime
            oldest_date = datetime.datetime.fromtimestamp(oldest).strftime('%Y-%m-%d %H:%M:%S')
            details.append(f"Oldest Entry: {oldest_date}")

        if newest > 0:
            import datetime
            newest_date = datetime.datetime.fromtimestamp(newest).strftime('%Y-%m-%d %H:%M:%S')
            details.append(f"Newest Entry: {newest_date}")

        self.details_text.setPlainText('\n'.join(details))

    def cleanup_cache(self):
        """Clean up invalid cache entries"""
        try:
            removed = self.engine.cleanup_cache()

            QMessageBox.information(
                self,
                "Cache Cleanup",
                f"Cleaned up {removed} invalid cache entries."
            )

            self.cache_cleaned.emit(removed)
            self.refresh_stats()

        except Exception as e:
            self.logger.error("Exception in cache_management_widget: %s", e)
            QMessageBox.critical(
                self,
                "Cleanup Error",
                f"Failed to cleanup cache: {e}"
            )

    def save_cache(self):
        """Save cache to disk"""
        try:
            self.engine.save_cache()

            QMessageBox.information(
                self,
                "Cache Saved",
                "Cache has been saved to disk successfully."
            )

        except Exception as e:
            self.logger.error("Exception in cache_management_widget: %s", e)
            QMessageBox.critical(
                self,
                "Save Error",
                f"Failed to save cache: {e}"
            )

    def clear_cache(self):
        """Clear all cache entries"""
        reply = QMessageBox.question(
            self,
            "Clear Cache",
            "Are you sure you want to clear all cache entries?\n"
            "This will remove all cached analysis results including AI coordination cache.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            try:
                # Clear protection analysis cache
                self.engine.clear_cache()

                # Also clear AI coordination layer cache if available
                try:
                    from PyQt5.QtWidgets import QApplication
                    main_window = None
                    for widget in QApplication.allWidgets():
                        if hasattr(widget, 'ai_coordinator') and widget.ai_coordinator:
                            main_window = widget
                            break

                    if main_window and hasattr(main_window.ai_coordinator, 'clear_cache'):
                        main_window.ai_coordinator.clear_cache()
                        logger.info("AI coordination cache cleared")

                except Exception as coord_e:
                    logger.warning("Could not clear AI coordination cache: %s", coord_e)

                QMessageBox.information(
                    self,
                    "Cache Cleared",
                    "All cache entries have been cleared including AI coordination cache."
                )

                self.cache_cleared.emit()
                self.refresh_stats()

            except Exception as e:
                logger.error("Exception in cache_management_widget: %s", e)
                QMessageBox.critical(
                    self,
                    "Clear Error",
                    f"Failed to clear cache: {e}"
                )

    def closeEvent(self, event):
        """Clean up on close"""
        if hasattr(self, 'timer'):
            self.timer.stop()
        super().closeEvent(event)
