"""Performance Monitor for Hex Viewer Large File Operations.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import logging
import time
from typing import TYPE_CHECKING, Any

from ..handlers.pyqt6_handler import (
    PYQT6_AVAILABLE,
    QFont,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QProgressBar,
    QPushButton,
    Qt,
    QTableWidget,
    QTabWidget,
    QTimer,
    QVBoxLayout,
    QWidget,
)


logger = logging.getLogger(__name__)

__all__ = ["PerformanceMonitor", "PerformanceWidget"]


_BaseClass = QWidget if TYPE_CHECKING or PYQT6_AVAILABLE else object


class PerformanceWidget(_BaseClass):  # type: ignore[misc, valid-type]
    """Widget for displaying performance statistics."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the performance widget."""
        if not PYQT6_AVAILABLE:
            logger.warning("PyQt6 not available, PerformanceWidget cannot be created")
            raise RuntimeError("PyQt6 not available")

        super().__init__(parent)
        self.file_handler: object | None = None
        self.stats_history: list[dict[str, Any]] = []
        self.max_history: int = 100

        self.file_size_label: QLabel
        self.memory_strategy_label: QLabel
        self.loading_strategy_label: QLabel
        self.read_operations_label: QLabel
        self.cache_hit_rate_label: QLabel
        self.sequential_ratio_label: QLabel
        self.avg_read_time_label: QLabel
        self.optimization_status: QLabel
        self.background_loader_status: QLabel
        self.memory_used_label: QLabel
        self.memory_limit_label: QLabel
        self.memory_progress: QProgressBar
        self.system_memory_label: QLabel
        self.system_memory_progress: QProgressBar
        self.cache_regions_label: QLabel
        self.cache_memory_label: QLabel
        self.cache_utilization_label: QLabel
        self.cache_hits_label: QLabel
        self.cache_misses_label: QLabel
        self.cache_progress: QProgressBar
        self.pattern_table: QTableWidget
        self.sequential_count_label: QLabel
        self.random_count_label: QLabel
        self.large_read_label: QLabel
        self.optimize_button: QPushButton
        self.clear_stats_button: QPushButton
        self.tab_widget: QTabWidget
        self.update_timer: QTimer

        self.setup_ui()

        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_display)
        self.update_timer.start(2000)

    def setup_ui(self) -> None:
        """Set up the user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        title_label = QLabel("Performance Monitor")
        title_label.setFont(QFont("", 10, QFont.Weight.Bold))
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title_label)

        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)

        # Overview tab
        self.create_overview_tab()

        # Memory tab
        self.create_memory_tab()

        # Cache tab
        self.create_cache_tab()

        # Access patterns tab
        self.create_patterns_tab()

        # Controls
        self.create_controls()

    def create_overview_tab(self) -> None:
        """Create the overview tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # File info
        file_group = QGroupBox("File Information")
        file_layout = QFormLayout(file_group)

        self.file_size_label = QLabel("N/A")
        self.memory_strategy_label = QLabel("N/A")
        self.loading_strategy_label = QLabel("N/A")

        file_layout.addRow("File Size:", self.file_size_label)
        file_layout.addRow("Memory Strategy:", self.memory_strategy_label)
        file_layout.addRow("Loading Strategy:", self.loading_strategy_label)

        layout.addWidget(file_group)

        # Performance metrics
        perf_group = QGroupBox("Performance Metrics")
        perf_layout = QFormLayout(perf_group)

        self.read_operations_label = QLabel("0")
        self.cache_hit_rate_label = QLabel("N/A")
        self.sequential_ratio_label = QLabel("N/A")
        self.avg_read_time_label = QLabel("N/A")

        perf_layout.addRow("Read Operations:", self.read_operations_label)
        perf_layout.addRow("Cache Hit Rate:", self.cache_hit_rate_label)
        perf_layout.addRow("Sequential Access:", self.sequential_ratio_label)
        perf_layout.addRow("Avg Read Time:", self.avg_read_time_label)

        layout.addWidget(perf_group)

        status_group = QGroupBox("Status")
        status_layout = QVBoxLayout(status_group)

        self.optimization_status = QLabel("No optimization active")
        self.optimization_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        status_layout.addWidget(self.optimization_status)

        self.background_loader_status = QLabel("Background loader: Inactive")
        self.background_loader_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        status_layout.addWidget(self.background_loader_status)

        layout.addWidget(status_group)

        layout.addStretch()
        self.tab_widget.addTab(tab, "Overview")

    def create_memory_tab(self) -> None:
        """Create the memory usage tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Memory usage
        memory_group = QGroupBox("Memory Usage")
        memory_layout = QFormLayout(memory_group)

        self.memory_used_label = QLabel("N/A")
        self.memory_limit_label = QLabel("N/A")
        self.memory_progress = QProgressBar()
        self.memory_progress.setRange(0, 100)

        memory_layout.addRow("Memory Used:", self.memory_used_label)
        memory_layout.addRow("Memory Limit:", self.memory_limit_label)
        memory_layout.addRow("Usage:", self.memory_progress)

        layout.addWidget(memory_group)

        # System memory
        system_group = QGroupBox("System Memory")
        system_layout = QFormLayout(system_group)

        self.system_memory_label = QLabel("N/A")
        self.system_memory_progress = QProgressBar()
        self.system_memory_progress.setRange(0, 100)

        # Color coding for memory pressure
        self.system_memory_progress.setStyleSheet("""
            QProgressBar::chunk {
                background-color: #4CAF50;
            }
            QProgressBar::chunk[value="75"] {
                background-color: #FF9800;
            }
            QProgressBar::chunk[value="90"] {
                background-color: #F44336;
            }
        """)

        system_layout.addRow("System Usage:", self.system_memory_label)
        system_layout.addRow("Progress:", self.system_memory_progress)

        layout.addWidget(system_group)

        layout.addStretch()
        self.tab_widget.addTab(tab, "Memory")

    def create_cache_tab(self) -> None:
        """Create the cache statistics tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Cache stats
        cache_group = QGroupBox("Cache Statistics")
        cache_layout = QFormLayout(cache_group)

        self.cache_regions_label = QLabel("0")
        self.cache_memory_label = QLabel("0 MB")
        self.cache_utilization_label = QLabel("0%")
        self.cache_hits_label = QLabel("0")
        self.cache_misses_label = QLabel("0")

        cache_layout.addRow("Cached Regions:", self.cache_regions_label)
        cache_layout.addRow("Cache Memory:", self.cache_memory_label)
        cache_layout.addRow("Utilization:", self.cache_utilization_label)
        cache_layout.addRow("Cache Hits:", self.cache_hits_label)
        cache_layout.addRow("Cache Misses:", self.cache_misses_label)

        layout.addWidget(cache_group)

        # Cache utilization progress
        progress_group = QGroupBox("Cache Utilization")
        progress_layout = QVBoxLayout(progress_group)

        self.cache_progress = QProgressBar()
        self.cache_progress.setRange(0, 100)
        progress_layout.addWidget(self.cache_progress)

        layout.addWidget(progress_group)

        layout.addStretch()
        self.tab_widget.addTab(tab, "Cache")

    def create_patterns_tab(self) -> None:
        """Create the access patterns tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Access pattern analysis
        pattern_group = QGroupBox("Access Pattern Analysis")
        pattern_layout = QVBoxLayout(pattern_group)

        self.pattern_table = QTableWidget(0, 4)
        self.pattern_table.setHorizontalHeaderLabels(["Time", "Offset", "Size", "Type"])
        header = self.pattern_table.horizontalHeader()
        if header is not None:
            header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        pattern_layout.addWidget(self.pattern_table)

        # Pattern summary
        summary_layout = QHBoxLayout()

        self.sequential_count_label = QLabel("Sequential: 0")
        self.random_count_label = QLabel("Random: 0")
        self.large_read_label = QLabel("Large Reads: 0")

        summary_layout.addWidget(self.sequential_count_label)
        summary_layout.addWidget(self.random_count_label)
        summary_layout.addWidget(self.large_read_label)

        pattern_layout.addLayout(summary_layout)
        layout.addWidget(pattern_group)

        self.tab_widget.addTab(tab, "Patterns")

    def create_controls(self) -> None:
        """Create control buttons."""
        controls_layout = QHBoxLayout()

        self.optimize_button = QPushButton("Auto Optimize")
        self.optimize_button.clicked.connect(self.auto_optimize)
        controls_layout.addWidget(self.optimize_button)

        self.clear_stats_button = QPushButton("Clear Stats")
        self.clear_stats_button.clicked.connect(self.clear_stats)
        controls_layout.addWidget(self.clear_stats_button)

        controls_layout.addStretch()

        main_layout = self.layout()
        if main_layout is not None:
            main_layout.addLayout(controls_layout)

    def set_file_handler(self, file_handler: object) -> None:
        """Set the file handler to monitor."""
        self.file_handler = file_handler
        self.stats_history.clear()
        self.update_display()

    def update_display(self) -> None:
        """Update the display with current statistics."""
        if not self.file_handler:
            return

        try:
            if not hasattr(self.file_handler, "get_performance_stats"):
                return

            stats_result = self.file_handler.get_performance_stats()  # type: ignore[attr-defined]
            if not stats_result or not isinstance(stats_result, dict):
                return

            stats: dict[str, Any] = stats_result
            stats["timestamp"] = time.time()
            self.stats_history.append(stats)
            if len(self.stats_history) > self.max_history:
                self.stats_history = self.stats_history[-self.max_history :]

            self.update_overview_tab(stats)
            self.update_memory_tab(stats)
            self.update_cache_tab(stats)
            self.update_patterns_tab(stats)

        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error updating performance display: %s", e)

    def update_overview_tab(self, stats: dict[str, Any]) -> None:
        """Update the overview tab."""
        # File information
        self.file_size_label.setText(f"{stats.get('file_size_mb', 0):.1f} MB")
        self.memory_strategy_label.setText(stats.get("memory_strategy", "N/A"))
        self.loading_strategy_label.setText(stats.get("loading_strategy", "N/A"))

        # Performance metrics
        self.sequential_ratio_label.setText(f"{stats.get('sequential_ratio', 0):.1%}")

        # Status
        if stats.get("file_size_mb", 0) > 50:
            self.optimization_status.setText("Large file optimization active")
            self.optimization_status.setStyleSheet("color: green; font-weight: bold;")
        else:
            self.optimization_status.setText("Standard file handling")
            self.optimization_status.setStyleSheet("color: blue;")

        loader_active = stats.get("background_loader_active", False)
        self.background_loader_status.setText(
            f"Background loader: {'Active' if loader_active else 'Inactive'}",
        )
        self.background_loader_status.setStyleSheet(
            "color: green;" if loader_active else "color: gray;",
        )

    def update_memory_tab(self, stats: dict[str, Any]) -> None:
        """Update the memory tab."""
        cache_stats_raw = stats.get("cache_stats", {})
        cache_stats: dict[str, Any] = cache_stats_raw if isinstance(cache_stats_raw, dict) else {}

        memory_used = float(cache_stats.get("total_memory_mb", 0))
        memory_limit = float(cache_stats.get("max_memory_mb", 0))

        self.memory_used_label.setText(f"{memory_used:.1f} MB")
        self.memory_limit_label.setText(f"{memory_limit:.1f} MB")

        if memory_limit > 0:
            usage_percent = min(100, (memory_used / memory_limit) * 100)
            self.memory_progress.setValue(int(usage_percent))

        try:
            from intellicrack.handlers.psutil_handler import psutil

            memory = psutil.virtual_memory()
            self.system_memory_label.setText(f"{memory.percent:.1f}%")
            self.system_memory_progress.setValue(int(memory.percent))
        except ImportError as e:
            logger.exception("Import error in performance_monitor: %s", e)
            self.system_memory_label.setText("N/A (psutil not available)")
            self.system_memory_progress.setValue(50)

    def update_cache_tab(self, stats: dict[str, Any]) -> None:
        """Update the cache tab."""
        cache_stats_raw = stats.get("cache_stats", {})
        cache_stats: dict[str, Any] = cache_stats_raw if isinstance(cache_stats_raw, dict) else {}

        regions = int(cache_stats.get("regions", 0))
        memory_mb = float(cache_stats.get("total_memory_mb", 0))
        utilization = float(cache_stats.get("utilization", 0)) * 100

        self.cache_regions_label.setText(str(regions))
        self.cache_memory_label.setText(f"{memory_mb:.1f} MB")
        self.cache_utilization_label.setText(f"{utilization:.1f}%")
        self.cache_progress.setValue(int(utilization))

    def update_patterns_tab(self, stats: dict[str, Any]) -> None:
        """Update the access patterns tab."""
        access_patterns = int(stats.get("access_patterns", 0))
        sequential_ratio = float(stats.get("sequential_ratio", 0))

        total_patterns = max(1, access_patterns)
        sequential_count = int(total_patterns * sequential_ratio)
        random_count = total_patterns - sequential_count

        self.sequential_count_label.setText(f"Sequential: {sequential_count}")
        self.random_count_label.setText(f"Random: {random_count}")

    def auto_optimize(self) -> None:
        """Automatically optimize based on access patterns."""
        if not self.file_handler:
            return

        try:
            if not hasattr(self.file_handler, "get_performance_stats"):
                return

            stats_result = self.file_handler.get_performance_stats()  # type: ignore[attr-defined]
            if not stats_result or not isinstance(stats_result, dict):
                return

            stats: dict[str, Any] = stats_result
            sequential_ratio = float(stats.get("sequential_ratio", 0))

            if sequential_ratio > 0.7:
                if hasattr(self.file_handler, "optimize_for_sequential_access"):
                    self.file_handler.optimize_for_sequential_access()
                self.optimization_status.setText("Optimized for sequential access")
            else:
                if hasattr(self.file_handler, "optimize_for_random_access"):
                    self.file_handler.optimize_for_random_access()
                self.optimization_status.setText("Optimized for random access")

            self.optimization_status.setStyleSheet("color: blue; font-weight: bold;")

        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Auto-optimization failed: %s", e)

    def clear_stats(self) -> None:
        """Clear statistics history."""
        self.stats_history.clear()
        self.pattern_table.setRowCount(0)


class PerformanceMonitor:
    """Run performance monitoring controller."""

    def __init__(self) -> None:
        """Initialize the performance monitor with widget and file handler references."""
        self.widget: PerformanceWidget | None = None
        self.file_handler: object | None = None

    def create_widget(self, parent: QWidget | None = None) -> QWidget | None:
        """Create and return the performance monitoring widget."""
        if not PYQT6_AVAILABLE:
            return None

        self.widget = PerformanceWidget(parent)
        if self.file_handler:
            self.widget.set_file_handler(self.file_handler)

        return self.widget

    def set_file_handler(self, file_handler: object) -> None:
        """Set the file handler to monitor."""
        self.file_handler = file_handler
        if self.widget:
            self.widget.set_file_handler(file_handler)

    def get_stats_summary(self) -> dict[str, Any]:
        """Get a summary of current performance statistics."""
        if not self.file_handler:
            return {}

        if not hasattr(self.file_handler, "get_performance_stats"):
            return {}

        stats_result = self.file_handler.get_performance_stats()  # type: ignore[attr-defined]
        if not stats_result or not isinstance(stats_result, dict):
            return {}

        stats: dict[str, Any] = stats_result
        cache_stats_raw = stats.get("cache_stats", {})
        cache_stats: dict[str, Any] = cache_stats_raw if isinstance(cache_stats_raw, dict) else {}

        return {
            "file_size_mb": stats.get("file_size_mb", 0),
            "memory_strategy": stats.get("memory_strategy", "unknown"),
            "cache_memory_mb": cache_stats.get("total_memory_mb", 0),
            "cache_utilization": cache_stats.get("utilization", 0),
            "sequential_ratio": stats.get("sequential_ratio", 0),
            "optimization_active": stats.get("file_size_mb", 0) > 50,
        }
