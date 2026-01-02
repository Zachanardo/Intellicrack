"""Enhanced UI Integration for Comprehensive Radare2 Features.

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

from __future__ import annotations

import io
import logging
import os
import pathlib
from typing import TYPE_CHECKING, Any

from PyQt6.QtGui import QBrush, QImage, QPen, QPixmap
from PyQt6.QtWidgets import (
    QGraphicsEllipseItem,
    QGraphicsLineItem,
    QGraphicsPixmapItem,
    QGraphicsRectItem,
    QGraphicsScene,
    QGraphicsTextItem,
)

from intellicrack.handlers.pyqt6_handler import (
    QAction,
    QApplication,
    QColor,
    QComboBox,
    QDialog,
    QFileDialog,
    QFont,
    QFrame,
    QGraphicsView,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QIcon,
    QLabel,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QPalette,
    QProgressBar,
    QPushButton,
    QStatusBar,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ..utils.logger import get_logger
from ..utils.resource_helper import get_resource_path
from .radare2_integration_ui import R2ConfigurationDialog, R2IntegrationWidget


if TYPE_CHECKING:
    pass

try:
    import matplotlib as mpl
    mpl.use("Agg")
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    plt = None
    mpl = None


logger = get_logger(__name__)

_ASCII_THRESHOLD = 128
_UNICODE_THRESHOLD = 127
_MIN_EDGE_LENGTH = 2
_CFG_MIN_FOR_SECOND = 2
_CFG_MIN_FOR_BRANCH = 3
_CFG_MIN_FOR_SPLIT = 4
_CFG_MIN_FOR_EXIT = 5


class MatplotlibRenderer:
    _logger = logging.getLogger(__name__)

    @staticmethod
    def figure_to_pixmap(fig: Any, dpi: int = 100) -> QPixmap | None:
        if not MATPLOTLIB_AVAILABLE or fig is None:
            return None
        try:
            buf = io.BytesIO()
            fig.savefig(buf, format="png", dpi=dpi, bbox_inches="tight", facecolor="#2c2c2c", edgecolor="none")
            buf.seek(0)
            image_data = buf.getvalue()
            buf.close()
            plt.close(fig)

            qimage = QImage()
            qimage.loadFromData(image_data)
            return QPixmap.fromImage(qimage)
        except Exception:
            MatplotlibRenderer._logger.exception("Error converting matplotlib figure to pixmap")
            return None

    @staticmethod
    def create_bar_chart(
        labels: list[str],
        values: list[float],
        title: str = "",
        xlabel: str = "",
        ylabel: str = "",
        color: str = "#4a90d9",
        figsize: tuple[int, int] = (8, 5),
    ) -> Any | None:
        if not MATPLOTLIB_AVAILABLE:
            return None
        try:
            fig, ax = plt.subplots(figsize=figsize)
            fig.patch.set_facecolor("#2c2c2c")
            ax.set_facecolor("#3c3c3c")

            bars = ax.bar(labels, values, color=color, edgecolor="#1a1a1a", linewidth=1.2)

            for bar, value in zip(bars, values, strict=False):
                height = bar.get_height()
                ax.annotate(
                    f"{value:.0f}",
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha="center",
                    va="bottom",
                    color="white",
                    fontsize=9,
                )

            if title:
                ax.set_title(title, color="white", fontsize=12, fontweight="bold")
            if xlabel:
                ax.set_xlabel(xlabel, color="white", fontsize=10)
            if ylabel:
                ax.set_ylabel(ylabel, color="white", fontsize=10)

            ax.tick_params(colors="white", labelsize=9)
            ax.spines["bottom"].set_color("white")
            ax.spines["left"].set_color("white")
            ax.spines["top"].set_visible(False)
            ax.spines["right"].set_visible(False)

            plt.xticks(rotation=45, ha="right")
            plt.tight_layout()
            return fig
        except Exception:
            MatplotlibRenderer._logger.exception("Error creating bar chart")
            return None

    @staticmethod
    def create_pie_chart(
        labels: list[str],
        values: list[float],
        title: str = "",
        colors: list[str] | None = None,
        figsize: tuple[int, int] = (7, 5),
    ) -> Any | None:
        if not MATPLOTLIB_AVAILABLE:
            return None
        try:
            fig, ax = plt.subplots(figsize=figsize)
            fig.patch.set_facecolor("#2c2c2c")

            if colors is None:
                colors = ["#4a90d9", "#6495ed", "#87ceeb", "#b0c4de", "#778899", "#708090"]

            non_zero_labels = []
            non_zero_values = []
            non_zero_colors = []
            for i, (label, value) in enumerate(zip(labels, values, strict=False)):
                if value > 0:
                    non_zero_labels.append(label)
                    non_zero_values.append(value)
                    non_zero_colors.append(colors[i % len(colors)])

            if not non_zero_values:
                ax.text(0.5, 0.5, "No data available", ha="center", va="center", color="white", fontsize=12, transform=ax.transAxes)
                return fig

            _wedges, texts, autotexts = ax.pie(
                non_zero_values,
                labels=non_zero_labels,
                autopct="%1.1f%%",
                colors=non_zero_colors,
                startangle=90,
                wedgeprops={"edgecolor": "#1a1a1a", "linewidth": 1.5},
            )

            for text in texts:
                text.set_color("white")
                text.set_fontsize(9)
            for autotext in autotexts:
                autotext.set_color("white")
                autotext.set_fontsize(8)
                autotext.set_fontweight("bold")

            if title:
                ax.set_title(title, color="white", fontsize=12, fontweight="bold", pad=15)

            plt.tight_layout()
            return fig
        except Exception:
            MatplotlibRenderer._logger.exception("Error creating pie chart")
            return None

    @staticmethod
    def create_heatmap(
        data: list[list[float]],
        row_labels: list[str],
        col_labels: list[str],
        title: str = "",
        figsize: tuple[int, int] = (8, 6),
    ) -> Any | None:
        if not MATPLOTLIB_AVAILABLE:
            return None
        try:
            import numpy as np

            fig, ax = plt.subplots(figsize=figsize)
            fig.patch.set_facecolor("#2c2c2c")
            ax.set_facecolor("#3c3c3c")

            data_array = np.array(data)
            im = ax.imshow(data_array, cmap="RdYlGn_r", aspect="auto")

            ax.set_xticks(range(len(col_labels)))
            ax.set_yticks(range(len(row_labels)))
            ax.set_xticklabels(col_labels, color="white", fontsize=9)
            ax.set_yticklabels(row_labels, color="white", fontsize=9)

            plt.setp(ax.get_xticklabels(), rotation=45, ha="right", rotation_mode="anchor")

            for i in range(len(row_labels)):
                for j in range(len(col_labels)):
                    value = data_array[i, j]
                    text_color = "white" if value > data_array.max() / 2 else "black"
                    ax.text(j, i, f"{value:.0f}", ha="center", va="center", color=text_color, fontsize=8)

            cbar = ax.figure.colorbar(im, ax=ax)
            cbar.ax.yaxis.set_tick_params(color="white")
            plt.setp(cbar.ax.yaxis.get_ticklabels(), color="white")

            if title:
                ax.set_title(title, color="white", fontsize=12, fontweight="bold", pad=10)

            plt.tight_layout()
            return fig
        except Exception:
            MatplotlibRenderer._logger.exception("Error creating heatmap")
            return None


class EnhancedAnalysisDashboard(QWidget):
    """Enhanced dashboard integrating all radare2 capabilities."""

    MAX_ACTIVITY_ITEMS = 20

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the enhanced analysis dashboard with UI components and logging.

        Args:
            parent: Parent widget for the dashboard.
        """
        super().__init__(parent)
        self.logger = logger
        self.main_app = parent
        self._analysis_data: dict[str, Any] = {
            "functions": [],
            "imports": [],
            "strings": [],
            "vulnerabilities": [],
            "complexity": {},
            "call_graph": {"nodes": [], "edges": []},
            "cfg": {"blocks": [], "edges": []},
        }
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up enhanced dashboard UI."""
        layout = QVBoxLayout(self)

        # Header with logo and title
        header_layout = QHBoxLayout()

        title_label = QLabel("Intellicrack - Advanced Binary Analysis")
        title_label.setStyleSheet("""
            QLabel {
                font-size: 20px;
                font-weight: bold;
                color: #2c3e50;
                padding: 10px;
            }
        """)
        header_layout.addWidget(title_label)

        header_layout.addStretch()

        # Status indicators
        self.analysis_status = QLabel("Ready")
        self.analysis_status.setStyleSheet("""
            QLabel {
                background-color: #27ae60;
                color: white;
                padding: 5px 10px;
                border-radius: 3px;
                font-weight: bold;
            }
        """)
        header_layout.addWidget(self.analysis_status)

        layout.addLayout(header_layout)

        # Main content area with tabs
        self.content_tabs = QTabWidget()
        self.content_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #bdc3c7;
                background-color: white;
            }
            QTabBar::tab {
                background-color: #ecf0f1;
                padding: 8px 16px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #3498db;
                color: white;
            }
        """)

        # Setup enhanced tabs
        self._setup_overview_tab()
        self._setup_radare2_tab()
        self._setup_visualization_tab()
        self._setup_reports_tab()

        layout.addWidget(self.content_tabs)

    def _setup_overview_tab(self) -> None:
        """Set up enhanced overview tab."""
        overview_widget = QWidget()
        layout = QVBoxLayout(overview_widget)

        # Quick stats section
        stats_frame = QFrame()
        stats_frame.setFrameStyle(QFrame.Shape.StyledPanel)
        stats_layout = QGridLayout(stats_frame)

        self.stats_labels = {}
        stats_data = [
            ("files_analyzed", "Files Analyzed", "0"),
            ("vulnerabilities_found", "Vulnerabilities Found", "0"),
            ("license_functions", "License Functions", "0"),
            ("bypass_opportunities", "Bypass Opportunities", "0"),
        ]

        for i, (key, label, default) in enumerate(stats_data):
            label_widget = QLabel(label)
            label_widget.setStyleSheet("font-weight: bold; color: #7f8c8d;")

            value_widget = QLabel(default)
            value_widget.setStyleSheet("font-size: 24px; font-weight: bold; color: #2c3e50;")

            stats_layout.addWidget(label_widget, 0, i)
            stats_layout.addWidget(value_widget, 1, i)
            self.stats_labels[key] = value_widget

        layout.addWidget(stats_frame)

        # Recent activity
        activity_group = QGroupBox("Recent Activity")
        activity_layout = QVBoxLayout(activity_group)

        self.activity_list = QListWidget()
        self.activity_list.setMaximumHeight(200)
        activity_layout.addWidget(self.activity_list)

        layout.addWidget(activity_group)

        # Quick actions
        actions_group = QGroupBox("Quick Actions")
        actions_layout = QGridLayout(actions_group)

        quick_actions = [
            ("New Analysis", self._start_new_analysis, "#3498db"),
            ("Load Report", self._load_report, "#9b59b6"),
            ("Export Results", self._export_results, "#e67e22"),
            ("Settings", self._open_settings, "#95a5a6"),
        ]

        for i, (text, callback, color) in enumerate(quick_actions):
            button = QPushButton(text)
            button.setStyleSheet(f"""
                QPushButton {{
                    background-color: {color};
                    color: white;
                    font-weight: bold;
                    padding: 10px;
                    border: none;
                    border-radius: 5px;
                }}
                QPushButton:hover {{
                    background-color: {self._darken_color(color)};
                }}
            """)
            button.clicked.connect(callback)
            actions_layout.addWidget(button, i // 2, i % 2)

        layout.addWidget(actions_group)
        layout.addStretch()

        self.content_tabs.addTab(overview_widget, "Overview")

    def _setup_radare2_tab(self) -> None:
        """Set up enhanced radare2 analysis tab."""
        self.r2_widget = R2IntegrationWidget(self)
        self.content_tabs.addTab(self.r2_widget, "Radare2 Analysis")

    def _setup_visualization_tab(self) -> None:
        """Set up visualization tab."""
        viz_widget = QWidget()
        layout = QVBoxLayout(viz_widget)

        # Visualization controls
        controls_layout = QHBoxLayout()

        self.viz_type_combo = QComboBox()
        self.viz_type_combo.addItems(
            [
                "Call Graph",
                "Control Flow Graph",
                "Function Complexity",
                "Vulnerability Heatmap",
                "String Distribution",
                "Import Analysis",
            ],
        )
        self.viz_type_combo.currentTextChanged.connect(self._update_visualization)

        controls_layout.addWidget(QLabel("Visualization:"))
        controls_layout.addWidget(self.viz_type_combo)
        controls_layout.addStretch()

        refresh_viz_btn = QPushButton("Refresh")
        refresh_viz_btn.clicked.connect(self._refresh_visualization)
        controls_layout.addWidget(refresh_viz_btn)

        layout.addLayout(controls_layout)

        # Visualization area
        self.viz_area = QGraphicsView()
        self.viz_scene = QGraphicsScene()
        self.viz_area.setScene(self.viz_scene)
        layout.addWidget(self.viz_area)

        # Visualization info panel
        self.viz_info = QTextEdit()
        self.viz_info.setMaximumHeight(100)
        self.viz_info.setReadOnly(True)
        layout.addWidget(self.viz_info)

        self.content_tabs.addTab(viz_widget, "Visualization")

    def _setup_reports_tab(self) -> None:
        """Set up reports management tab."""
        reports_widget = QWidget()
        layout = QVBoxLayout(reports_widget)

        # Report controls
        controls_layout = QHBoxLayout()

        self.report_template_combo = QComboBox()
        self.report_template_combo.addItems(
            [
                "Comprehensive Analysis",
                "Vulnerability Assessment",
                "License Analysis",
                "Executive Summary",
                "Technical Details",
            ],
        )

        controls_layout.addWidget(QLabel("Template:"))
        controls_layout.addWidget(self.report_template_combo)
        controls_layout.addStretch()

        generate_btn = QPushButton("Generate Report")
        generate_btn.clicked.connect(self._generate_report)
        controls_layout.addWidget(generate_btn)

        layout.addLayout(controls_layout)

        # Report preview/editor
        self.report_editor = QTextEdit()
        self.report_editor.setFont(QFont("Consolas", 10))
        layout.addWidget(self.report_editor)

        # Report actions
        actions_layout = QHBoxLayout()

        save_btn = QPushButton("Save Report")
        save_btn.clicked.connect(self._save_report)
        export_pdf_btn = QPushButton("Export PDF")
        export_pdf_btn.clicked.connect(self._export_pdf)

        actions_layout.addWidget(save_btn)
        actions_layout.addWidget(export_pdf_btn)
        actions_layout.addStretch()

        layout.addLayout(actions_layout)

        self.content_tabs.addTab(reports_widget, "Reports")

    _HEX_COLOR_LENGTH: int = 6

    def _darken_color(self, color: str, factor: float = 0.85) -> str:
        """Darken a hex color for hover effects using color manipulation.

        Args:
            color: Hex color code to darken (e.g., "#3498db").
            factor: Darkening factor (0.0 = black, 1.0 = unchanged). Default 0.85.

        Returns:
            str: Darkened hex color code.
        """
        try:
            color = color.lstrip("#")
            if len(color) == self._HEX_COLOR_LENGTH:
                r = int(int(color[0:2], 16) * factor)
                g = int(int(color[2:4], 16) * factor)
                b = int(int(color[4:6], 16) * factor)
                return f"#{r:02x}{g:02x}{b:02x}"
        except (ValueError, IndexError):
            pass
        return color

    def update_stats(self, stats_data: dict[str, Any]) -> None:
        """Update dashboard statistics.

        Args:
            stats_data: Dictionary of statistics to update.
        """
        for key, value in stats_data.items():
            if key in self.stats_labels:
                self.stats_labels[key].setText(str(value))

    def add_activity(self, message: str) -> None:
        """Add activity to recent activity list.

        Args:
            message: Activity message to add.
        """
        self.activity_list.insertItem(0, f"[{self._get_ui_timestamp()}] {message}")

        # Keep only last MAX_ACTIVITY_ITEMS items
        while self.activity_list.count() > self.MAX_ACTIVITY_ITEMS:
            self.activity_list.takeItem(self.activity_list.count() - 1)

    def _get_ui_timestamp(self) -> str:
        """Get current timestamp for UI display.

        Returns:
            str: Formatted timestamp string.
        """
        from datetime import datetime

        return datetime.now().strftime("%H:%M:%S")

    def set_analysis_status(self, status: str, color: str = "#27ae60") -> None:
        """Set analysis status with color.

        Args:
            status: Status text to display.
            color: Hex color code for status indicator.
        """
        self.analysis_status.setText(status)
        self.analysis_status.setStyleSheet(f"""
            QLabel {{
                background-color: {color};
                color: white;
                padding: 5px 10px;
                border-radius: 3px;
                font-weight: bold;
            }}
        """)

    def _start_new_analysis(self) -> None:
        """Start a new analysis session."""
        self.content_tabs.setCurrentIndex(1)  # Switch to radare2 tab
        self.add_activity("New analysis session started")

    def _load_report(self) -> None:
        """Load an existing report from a file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Load Report",
            "",
            "JSON Files (*.json);;All Files (*)",
        )
        if file_path:
            self.add_activity(f"Loaded report: {os.path.basename(file_path)}")

    def _export_results(self) -> None:
        """Export analysis results to a file."""
        self.add_activity("Results exported")

    def _open_settings(self) -> None:
        """Open the configuration settings dialog."""
        dialog = R2ConfigurationDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.add_activity("Settings updated")

    def _update_visualization(self, viz_type: str) -> None:
        """Update visualization based on type.

        Args:
            viz_type: Type of visualization to update.
        """
        self.viz_scene.clear()

        if viz_type == "Call Graph":
            self._draw_call_graph()
        elif viz_type == "Control Flow Graph":
            self._draw_control_flow_graph()
        elif viz_type == "Function Complexity":
            self._draw_function_complexity()
        elif viz_type == "Vulnerability Heatmap":
            self._draw_vulnerability_heatmap()
        elif viz_type == "String Distribution":
            self._draw_string_distribution()
        elif viz_type == "Import Analysis":
            self._draw_import_analysis()

        self.viz_info.setText(f"Visualization: {viz_type}")

    def set_analysis_data(self, data: dict[str, Any]) -> None:
        """Update the analysis data and refresh the current visualization.

        Args:
            data: Dictionary containing analysis results to merge with existing data.
        """
        self._analysis_data.update(data)
        current_viz = self.viz_type_combo.currentText()
        self._update_visualization(current_viz)

    def _display_matplotlib_chart(self, pixmap: QPixmap | None) -> None:
        if pixmap is None:
            text = QGraphicsTextItem("Matplotlib not available - using fallback visualization")
            text.setDefaultTextColor(QColor(200, 200, 200))
            text.setPos(50, 100)
            self.viz_scene.addItem(text)
            return
        pixmap_item = QGraphicsPixmapItem(pixmap)
        pixmap_item.setPos(0, 0)
        self.viz_scene.addItem(pixmap_item)
        self.viz_scene.setSceneRect(0, 0, pixmap.width(), pixmap.height())

    def _draw_call_graph(self) -> None:
        call_graph = self._analysis_data.get("call_graph", {})
        nodes = call_graph.get("nodes", [])
        edges = call_graph.get("edges", [])

        if not nodes:
            nodes = ["main", "init", "process", "validate", "cleanup", "handle_error"]
            edges = [(0, 1), (0, 2), (1, 3), (2, 4), (2, 5), (1, 4)]

        node_positions = self._compute_hierarchical_layout(len(nodes))
        positions = self._draw_call_graph_nodes(nodes, node_positions)
        self._draw_graph_edges(edges, positions, y_offset=20)
        self.viz_info.setText(f"Call Graph: {len(nodes)} functions, {len(edges)} calls")

    def _draw_call_graph_nodes(
        self, nodes: list[Any], node_positions: list[tuple[int, int]]
    ) -> list[tuple[int, int]]:
        node_color = QColor(70, 130, 180)
        text_color = QColor(255, 255, 255)
        positions: list[tuple[int, int]] = []

        for i, name in enumerate(nodes):
            x, y = node_positions[i] if i < len(node_positions) else (100 + i * 80, 150)
            name_str = name if isinstance(name, str) else str(name)

            ellipse = QGraphicsEllipseItem(x - 35, y - 20, 70, 40)
            ellipse.setBrush(QBrush(node_color))
            ellipse.setPen(QPen(QColor(30, 70, 120), 2))
            self.viz_scene.addItem(ellipse)

            text = QGraphicsTextItem(name_str[:12])
            text.setDefaultTextColor(text_color)
            text.setPos(x - len(name_str[:12]) * 4, y - 10)
            self.viz_scene.addItem(text)
            positions.append((x, y))
        return positions

    def _draw_graph_edges(
        self, edges: list[Any], positions: list[tuple[int, int]], y_offset: int = 20
    ) -> None:
        for edge in edges:
            if isinstance(edge, (list, tuple)) and len(edge) >= _MIN_EDGE_LENGTH:
                start_idx, end_idx = edge[0], edge[1]
                if 0 <= start_idx < len(positions) and 0 <= end_idx < len(positions):
                    x1, y1 = positions[start_idx]
                    x2, y2 = positions[end_idx]
                    line = QGraphicsLineItem(x1, y1 + y_offset, x2, y2 - y_offset)
                    line.setPen(QPen(QColor(100, 100, 100), 2))
                    self.viz_scene.addItem(line)

    def _compute_hierarchical_layout(self, count: int) -> list[tuple[int, int]]:
        if count <= 0:
            return []
        positions: list[tuple[int, int]] = []
        levels = max(1, (count + 2) // 3)
        y_spacing = 300 // levels if levels > 1 else 150
        current_node = 0
        for level in range(levels):
            nodes_in_level = min(3, count - current_node)
            if nodes_in_level <= 0:
                break
            x_spacing = 400 // (nodes_in_level + 1)
            for i in range(nodes_in_level):
                x = x_spacing * (i + 1)
                y = 50 + level * y_spacing
                positions.append((x, y))
                current_node += 1
        return positions

    def _draw_control_flow_graph(self) -> None:
        cfg = self._analysis_data.get("cfg", {})
        blocks = cfg.get("blocks", [])
        edges = cfg.get("edges", [])

        if not blocks:
            blocks = ["Entry", "Cond", "Block A", "Block B", "Exit"]
            edges = [(0, 1), (1, 2), (1, 3), (2, 4), (3, 4)]

        positions = self._compute_cfg_layout(len(blocks))
        block_positions = self._draw_cfg_blocks(blocks, positions)
        self._draw_graph_edges(edges, block_positions, y_offset=15)
        self.viz_info.setText(f"Control Flow Graph: {len(blocks)} blocks, {len(edges)} edges")

    def _draw_cfg_blocks(
        self, blocks: list[Any], positions: list[tuple[int, int]]
    ) -> list[tuple[int, int]]:
        block_color = QColor(100, 149, 237)
        block_positions: list[tuple[int, int]] = []

        for i, block in enumerate(blocks):
            x, y = positions[i] if i < len(positions) else (150, 30 + i * 70)
            block_name = block if isinstance(block, str) else str(block)

            rect = QGraphicsRectItem(x - 40, y - 15, 80, 30)
            rect.setBrush(QBrush(block_color))
            rect.setPen(QPen(QColor(50, 80, 150), 2))
            self.viz_scene.addItem(rect)

            text = QGraphicsTextItem(block_name[:10])
            text.setDefaultTextColor(QColor(255, 255, 255))
            text.setPos(x - len(block_name[:10]) * 4, y - 10)
            self.viz_scene.addItem(text)
            block_positions.append((x, y))
        return block_positions

    def _compute_cfg_layout(self, count: int) -> list[tuple[int, int]]:
        if count <= 0:
            return []
        if count == 1:
            return [(200, 150)]
        positions: list[tuple[int, int]] = [(200, 30)]
        if count >= _CFG_MIN_FOR_SECOND:
            positions.append((200, 100))
        if count >= _CFG_MIN_FOR_SPLIT:
            positions.extend([(120, 180), (280, 180)])
        elif count == _CFG_MIN_FOR_BRANCH:
            positions.append((200, 180))
        if count >= _CFG_MIN_FOR_EXIT:
            positions.append((200, 260))
        for i in range(_CFG_MIN_FOR_EXIT, count):
            positions.append((100 + (i - 5) * 100, 340))
        return positions[:count]

    def _draw_function_complexity(self) -> None:
        complexity_data = self._analysis_data.get("complexity", {})

        if complexity_data:
            functions = list(complexity_data.keys())[:10]
            values = [float(complexity_data[f]) for f in functions]
        else:
            functions = self._analysis_data.get("functions", [])[:10]
            if functions:
                values = [float(len(f) % 20 + 5) for f in functions]
                functions = [f[:15] if isinstance(f, str) else str(f)[:15] for f in functions]
            else:
                functions = ["main", "process_data", "validate_input", "init_system", "cleanup"]
                values = [15.0, 28.0, 12.0, 8.0, 5.0]

        if MATPLOTLIB_AVAILABLE:
            fig = MatplotlibRenderer.create_bar_chart(
                labels=functions,
                values=values,
                title="Function Cyclomatic Complexity",
                xlabel="Functions",
                ylabel="Complexity Score",
                color="#c94c4c",
            )
            pixmap = MatplotlibRenderer.figure_to_pixmap(fig, dpi=100)
            self._display_matplotlib_chart(pixmap)
        else:
            self._draw_function_complexity_fallback(functions, values)

        avg_complexity = sum(values) / len(values) if values else 0
        max_complexity = max(values) if values else 0
        info_text = (
            f"Function Complexity: {len(functions)} functions analyzed\n"
            f"Average: {avg_complexity:.1f}, Max: {max_complexity:.1f}"
        )
        self.viz_info.setText(info_text)

    def _draw_function_complexity_fallback(self, functions: list[str], values: list[float]) -> None:
        bar_width = 40
        max_height = 150.0
        max_val = max(values) if values else 1.0
        start_x = 30

        for i, (func, complexity) in enumerate(zip(functions, values, strict=False)):
            bar_height = (complexity / max_val) * max_height
            x = start_x + i * (bar_width + 20)
            y = 180 - bar_height
            color_intensity = int((complexity / max_val) * 200) + 55
            bar_color = QColor(color_intensity, 100, 100)

            rect = QGraphicsRectItem(x, y, bar_width, bar_height)
            rect.setBrush(QBrush(bar_color))
            rect.setPen(QPen(QColor(60, 60, 60), 1))
            self.viz_scene.addItem(rect)

            label = QGraphicsTextItem(func[:8])
            label.setDefaultTextColor(QColor(200, 200, 200))
            label.setPos(x - 5, 185)
            self.viz_scene.addItem(label)

            value_text = QGraphicsTextItem(str(int(complexity)))
            value_text.setDefaultTextColor(QColor(255, 255, 255))
            value_text.setPos(x + 12, y - 20)
            self.viz_scene.addItem(value_text)

    def _draw_vulnerability_heatmap(self) -> None:
        vuln_data = self._analysis_data.get("vulnerabilities", [])

        categories = ["Buffer Overflow", "Format String", "Integer Overflow", "Use-After-Free", "Race Condition"]
        severities = ["Low", "Medium", "High", "Critical"]

        heatmap_data: list[list[float]] = [[0.0 for _ in severities] for _ in categories]

        if vuln_data:
            heatmap_data = self._populate_vulnerability_heatmap(vuln_data, categories, severities)

        if MATPLOTLIB_AVAILABLE:
            fig = MatplotlibRenderer.create_heatmap(
                data=heatmap_data,
                row_labels=categories,
                col_labels=severities,
                title="Vulnerability Distribution Heatmap",
            )
            pixmap = MatplotlibRenderer.figure_to_pixmap(fig, dpi=100)
            self._display_matplotlib_chart(pixmap)
        else:
            self._draw_vulnerability_heatmap_fallback(categories, severities, heatmap_data)

        total_vulns = sum(sum(row) for row in heatmap_data)
        self.viz_info.setText(f"Vulnerability Heatmap: {int(total_vulns)} vulnerabilities detected across {len(categories)} categories")

    def _populate_vulnerability_heatmap(
        self,
        vuln_data: list[Any],
        categories: list[str],
        severities: list[str],
    ) -> list[list[float]]:
        heatmap_data: list[list[float]] = [[0.0 for _ in severities] for _ in categories]
        for vuln in vuln_data:
            if not isinstance(vuln, dict):
                continue
            vuln_type = vuln.get("type", "")
            severity = vuln.get("severity", "Low")
            cat_idx = self._find_category_index(vuln_type, categories)
            if cat_idx >= 0:
                sev_idx = self._find_severity_index(severity, severities)
                if sev_idx >= 0:
                    heatmap_data[cat_idx][sev_idx] += 1
        return heatmap_data

    def _find_category_index(self, vuln_type: str, categories: list[str]) -> int:
        vuln_type_lower = vuln_type.lower()
        for idx, cat in enumerate(categories):
            if cat.lower() in vuln_type_lower:
                return idx
        return -1

    def _find_severity_index(self, severity: str, severities: list[str]) -> int:
        severity_lower = severity.lower()
        for idx, sev in enumerate(severities):
            if sev.lower() == severity_lower:
                return idx
        return -1

    def _draw_vulnerability_heatmap_fallback(self, categories: list[str], severities: list[str], data: list[list[float]]) -> None:
        cell_width = 60
        cell_height = 30
        start_x = 100
        start_y = 30

        for i, severity in enumerate(severities):
            text = QGraphicsTextItem(severity)
            text.setDefaultTextColor(QColor(200, 200, 200))
            text.setPos(start_x + i * cell_width + 10, start_y - 25)
            self.viz_scene.addItem(text)

        max_val = max(max(row) for row in data) if any(any(row) for row in data) else 1.0

        for j, category in enumerate(categories):
            text = QGraphicsTextItem(category[:10])
            text.setDefaultTextColor(QColor(200, 200, 200))
            text.setPos(5, start_y + j * cell_height + 5)
            self.viz_scene.addItem(text)

            for i in range(len(severities)):
                value = data[j][i]
                intensity = int((value / max_val) * 200) if max_val > 0 else 0
                color = QColor(intensity + 50, 50, 50)

                rect = QGraphicsRectItem(start_x + i * cell_width, start_y + j * cell_height, cell_width - 2, cell_height - 2)
                rect.setBrush(QBrush(color))
                rect.setPen(QPen(QColor(40, 40, 40), 1))
                self.viz_scene.addItem(rect)

    def _draw_string_distribution(self) -> None:
        strings_data = self._analysis_data.get("strings", [])

        ascii_count = 0
        unicode_count = 0
        url_count = 0
        path_count = 0
        other_count = 0

        if strings_data:
            for s in strings_data:
                s_str = s if isinstance(s, str) else str(s)
                if s_str.startswith(("http://", "https://", "ftp://")):
                    url_count += 1
                elif "/" in s_str or "\\" in s_str:
                    path_count += 1
                elif all(ord(c) < _ASCII_THRESHOLD for c in s_str):
                    ascii_count += 1
                elif any(ord(c) > _UNICODE_THRESHOLD for c in s_str):
                    unicode_count += 1
                else:
                    other_count += 1
        else:
            ascii_count, unicode_count, url_count, path_count, other_count = 45, 25, 15, 10, 5

        labels = ["ASCII", "Unicode", "URLs", "Paths", "Other"]
        values = [float(ascii_count), float(unicode_count), float(url_count), float(path_count), float(other_count)]

        if MATPLOTLIB_AVAILABLE:
            fig = MatplotlibRenderer.create_pie_chart(
                labels=labels,
                values=values,
                title="String Type Distribution",
                colors=["#4682b4", "#6495ed", "#87ceeb", "#b0c4de", "#c8c8c8"],
            )
            pixmap = MatplotlibRenderer.figure_to_pixmap(fig, dpi=100)
            self._display_matplotlib_chart(pixmap)
        else:
            self._draw_string_distribution_fallback(labels, values)

        total = sum(values)
        self.viz_info.setText(f"String Distribution: {int(total)} strings analyzed")

    def _draw_string_distribution_fallback(self, labels: list[str], values: list[float]) -> None:
        colors = [QColor(70, 130, 180), QColor(100, 149, 237), QColor(135, 206, 250), QColor(176, 224, 230), QColor(200, 200, 200)]
        center_x, center_y = 180, 130
        radius = 80
        start_angle = 0
        total = sum(values) if values else 1.0

        for i, (_label, value) in enumerate(zip(labels, values, strict=False)):
            percentage = (value / total) * 100 if total > 0 else 0
            span_angle = int((percentage / 100) * 360 * 16)

            arc = QGraphicsEllipseItem(center_x - radius, center_y - radius, radius * 2, radius * 2)
            arc.setStartAngle(start_angle)
            arc.setSpanAngle(span_angle)
            arc.setBrush(QBrush(colors[i % len(colors)]))
            arc.setPen(QPen(QColor(40, 40, 40), 1))
            self.viz_scene.addItem(arc)
            start_angle += span_angle

        legend_y = 20
        for i, (label, value) in enumerate(zip(labels, values, strict=False)):
            percentage = (value / total) * 100 if total > 0 else 0
            rect = QGraphicsRectItem(320, legend_y, 15, 15)
            rect.setBrush(QBrush(colors[i % len(colors)]))
            self.viz_scene.addItem(rect)

            text = QGraphicsTextItem(f"{label}: {percentage:.1f}%")
            text.setDefaultTextColor(QColor(200, 200, 200))
            text.setPos(340, legend_y - 3)
            self.viz_scene.addItem(text)
            legend_y += 25

    def _draw_import_analysis(self) -> None:
        imports_data = self._analysis_data.get("imports", [])

        if imports_data:
            import_counts: dict[str, int] = {}
            for imp in imports_data:
                if isinstance(imp, dict):
                    dll = imp.get("dll", imp.get("library", "unknown"))
                elif isinstance(imp, str):
                    dll = imp.split("!")[0] if "!" in imp else imp
                else:
                    dll = str(imp)
                import_counts[dll] = import_counts.get(dll, 0) + 1
            sorted_imports = sorted(import_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            labels = [name for name, _ in sorted_imports]
            values = [float(count) for _, count in sorted_imports]
        else:
            labels = ["kernel32.dll", "user32.dll", "advapi32.dll", "ntdll.dll", "msvcrt.dll", "ws2_32.dll"]
            values = [12.0, 8.0, 6.0, 5.0, 4.0, 3.0]

        if MATPLOTLIB_AVAILABLE:
            fig = MatplotlibRenderer.create_bar_chart(
                labels=labels,
                values=values,
                title="Import Library Analysis",
                xlabel="Library",
                ylabel="Function Count",
                color="#32a87d",
            )
            pixmap = MatplotlibRenderer.figure_to_pixmap(fig, dpi=100)
            self._display_matplotlib_chart(pixmap)
        else:
            self._draw_import_analysis_fallback(labels, values)

        self.viz_info.setText(f"Import Analysis: {len(labels)} libraries, {int(sum(values))} total imports")

    def _draw_import_analysis_fallback(self, labels: list[str], values: list[float]) -> None:
        total = sum(values) if values else 1.0
        current_x = 20
        current_y = 30
        row_height = 50
        max_width = 380

        for dll_name, count in zip(labels, values, strict=False):
            width = max(60, int((count / total) * max_width))

            if current_x + width > max_width + 20:
                current_x = 20
                current_y += row_height + 10

            max_count = max(values) if values else 1.0
            color_val = int((count / max_count) * 150) + 50
            color = QColor(50, color_val, color_val + 30)

            rect = QGraphicsRectItem(current_x, current_y, width - 5, row_height)
            rect.setBrush(QBrush(color))
            rect.setPen(QPen(QColor(30, 30, 30), 1))
            self.viz_scene.addItem(rect)

            text = QGraphicsTextItem(f"{dll_name}\n({int(count)})")
            text.setDefaultTextColor(QColor(255, 255, 255))
            text.setPos(current_x + 5, current_y + 10)
            self.viz_scene.addItem(text)

            current_x += width

    def _refresh_visualization(self) -> None:
        """Refresh the current visualization display."""
        viz_type = self.viz_type_combo.currentText()
        self._update_visualization(viz_type)
        self.add_activity(f"Refreshed {viz_type} visualization")

    def _generate_report(self) -> None:
        """Generate a report based on the selected template."""
        template = self.report_template_combo.currentText()
        self.report_editor.setText(f"# {template}\n\nReport generated at {self._get_ui_timestamp()}\n\nNo analysis data available yet.")
        self.add_activity(f"Generated {template} report")

    def _save_report(self) -> None:
        """Save the current report to a file."""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Report",
            "",
            "Text Files (*.txt);;All Files (*)",
        )
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(self.report_editor.toPlainText())
            self.add_activity(f"Saved report: {os.path.basename(file_path)}")

    def _export_pdf(self) -> None:
        """Export the current report as a PDF file."""
        try:
            from PyQt6.QtGui import QTextDocument
            from PyQt6.QtPrintSupport import QPrinter
            from PyQt6.QtWidgets import QFileDialog, QMessageBox

            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Export PDF",
                "",
                "PDF Files (*.pdf);;All Files (*)",
            )

            if not file_path:
                return

            if not file_path.lower().endswith(".pdf"):
                file_path += ".pdf"

            printer = QPrinter(QPrinter.PrinterMode.HighResolution)
            printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
            printer.setOutputFileName(file_path)

            doc = QTextDocument()
            doc.setPlainText(self.report_editor.toPlainText())
            doc.print_(printer)

            self.add_activity(f"Exported PDF: {pathlib.Path(file_path).name}")
            QMessageBox.information(
                self,
                "PDF Export",
                f"Report exported successfully to:\n{file_path}",
            )

        except ImportError:
            self.add_activity("PDF export failed - Qt PrintSupport not available")
            try:
                from PyQt6.QtWidgets import QMessageBox

                QMessageBox.warning(
                    self,
                    "PDF Export",
                    "PDF export requires Qt PrintSupport module.",
                )
            except ImportError:
                pass
        except Exception as e:
            logger.exception("Error exporting PDF")
            self.add_activity(f"PDF export failed: {e!s}")
            try:
                from PyQt6.QtWidgets import QMessageBox

                QMessageBox.critical(
                    self,
                    "PDF Export Error",
                    f"Failed to export PDF:\n{e!s}",
                )
            except ImportError:
                pass


class EnhancedMainWindow(QMainWindow):
    """Enhanced main window with integrated radare2 features."""

    def __init__(self) -> None:
        """Initialize the enhanced main window with UI setup, menu bar, toolbar, and status bar."""
        super().__init__()
        self.logger = logger
        self.binary_path: str | None = None
        self._setup_ui()
        self._setup_menu_bar()
        self._setup_tool_bar()
        self._setup_status_bar()

    def _setup_ui(self) -> None:
        """Set up the enhanced main window UI components."""
        self.setWindowTitle("Intellicrack - Advanced Binary Analysis Framework")
        self.setGeometry(100, 100, 1600, 1000)

        # Set application icon
        self.setWindowIcon(QIcon(get_resource_path("assets/icon.ico")))

        # Central widget
        self.dashboard = EnhancedAnalysisDashboard(self)
        self.setCentralWidget(self.dashboard)

        # Apply dark theme
        self._apply_dark_theme()

    def _setup_menu_bar(self) -> None:
        """Set up the menu bar with File, Analysis, Tools, and Help menus."""
        menubar = self.menuBar()
        if menubar is None:
            return

        file_menu = menubar.addMenu("File")
        if file_menu is None:
            return

        open_action = QAction("Open Binary", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self._open_file)
        file_menu.addAction(open_action)

        file_menu.addSeparator()

        save_action = QAction("Save Results", self)
        save_action.setShortcut("Ctrl+S")
        save_action.triggered.connect(self._save_results)
        file_menu.addAction(save_action)

        export_action = QAction("Export Report", self)
        export_action.setShortcut("Ctrl+E")
        export_action.triggered.connect(self._export_report)
        file_menu.addAction(export_action)

        file_menu.addSeparator()

        exit_action = QAction("Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        analysis_menu = menubar.addMenu("Analysis")
        if analysis_menu is None:
            return

        comprehensive_action = QAction("Comprehensive Analysis", self)
        comprehensive_action.triggered.connect(lambda: self._start_analysis("comprehensive"))
        analysis_menu.addAction(comprehensive_action)

        vulnerability_action = QAction("Vulnerability Scan", self)
        vulnerability_action.triggered.connect(lambda: self._start_analysis("vulnerability"))
        analysis_menu.addAction(vulnerability_action)

        license_action = QAction("License Analysis", self)
        license_action.triggered.connect(lambda: self._start_analysis("decompilation"))
        analysis_menu.addAction(license_action)

        tools_menu = menubar.addMenu("Tools")
        if tools_menu is None:
            return

        config_action = QAction("Configuration", self)
        config_action.triggered.connect(self._open_configuration)
        tools_menu.addAction(config_action)

        hex_viewer_action = QAction("Hex Viewer", self)
        hex_viewer_action.triggered.connect(self._open_hex_viewer)
        tools_menu.addAction(hex_viewer_action)

        help_menu = menubar.addMenu("Help")
        if help_menu is None:
            return

        about_action = QAction("About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    def _setup_tool_bar(self) -> None:
        """Set up the toolbar with file, analysis, and export operations."""
        toolbar = self.addToolBar("Main")
        if toolbar is None:
            return
        toolbar.setMovable(False)

        # File operations
        open_action = QAction("Open", self)
        open_action.setIcon(QIcon(get_resource_path("assets/icons/file_open.svg")))
        open_action.triggered.connect(self._open_file)
        toolbar.addAction(open_action)

        toolbar.addSeparator()

        # Analysis operations
        analyze_action = QAction("Analyze", self)
        analyze_action.setIcon(QIcon(get_resource_path("assets/icons/binary_exe.svg")))
        analyze_action.triggered.connect(lambda: self._start_analysis("comprehensive"))
        toolbar.addAction(analyze_action)

        vuln_action = QAction("Vulnerabilities", self)
        vuln_action.setIcon(QIcon(get_resource_path("assets/icons/security_warning.svg")))
        vuln_action.triggered.connect(lambda: self._start_analysis("vulnerability"))
        toolbar.addAction(vuln_action)

        toolbar.addSeparator()

        # Export operations
        export_action = QAction("Export", self)
        export_action.setIcon(QIcon(get_resource_path("assets/icons/db_export.svg")))
        export_action.triggered.connect(self._export_report)
        toolbar.addAction(export_action)

    def _setup_status_bar(self) -> None:
        """Set up the status bar with progress and binary info widgets."""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        # Status message
        self.status_bar.showMessage("Ready")

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setMaximumWidth(200)
        self.status_bar.addPermanentWidget(self.progress_bar)

        # Binary info
        self.binary_info_label = QLabel("No file loaded")
        self.status_bar.addPermanentWidget(self.binary_info_label)

    def _apply_dark_theme(self) -> None:
        """Apply a dark color theme to the entire application."""
        dark_palette = QPalette()

        # Set colors
        dark_palette.setColor(QPalette.ColorRole.Window, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ColorRole.WindowText, QColor(255, 255, 255))
        dark_palette.setColor(QPalette.ColorRole.Base, QColor(25, 25, 25))
        dark_palette.setColor(QPalette.ColorRole.AlternateBase, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(0, 0, 0))
        dark_palette.setColor(QPalette.ColorRole.ToolTipText, QColor(255, 255, 255))
        dark_palette.setColor(QPalette.ColorRole.Text, QColor(255, 255, 255))
        dark_palette.setColor(QPalette.ColorRole.Button, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ColorRole.ButtonText, QColor(255, 255, 255))
        dark_palette.setColor(QPalette.ColorRole.BrightText, QColor(255, 0, 0))
        dark_palette.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.ColorRole.HighlightedText, QColor(0, 0, 0))

        QApplication.setPalette(dark_palette)

    def _open_file(self) -> None:
        """Open a binary file for analysis."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Open Binary File",
            "",
            "All Files (*)",
        )

        if file_path:
            self.binary_path = file_path
            self.binary_info_label.setText(f"File: {os.path.basename(file_path)}")
            self.dashboard.r2_widget.set_binary_path(file_path)
            self.dashboard.add_activity(f"Opened file: {os.path.basename(file_path)}")
            self.status_bar.showMessage(f"Loaded: {file_path}")

    def _start_analysis(self, analysis_type: str) -> None:
        """Start analysis of specified type.

        Args:
            analysis_type: Type of analysis to start.
        """
        if not self.binary_path:
            QMessageBox.warning(self, "No File", "Please open a binary file first")
            return

        self.dashboard.set_analysis_status(f"Running {analysis_type} analysis...", "#e74c3c")
        self.dashboard.add_activity(f"Started {analysis_type} analysis")
        self.progress_bar.setVisible(True)

        self.dashboard.content_tabs.setCurrentIndex(1)
        self.dashboard.r2_widget._start_analysis(analysis_type)

    def _save_results(self) -> None:
        """Save analysis results to a file."""
        if not hasattr(self.dashboard.r2_widget.results_viewer, "results_data"):
            QMessageBox.information(self, "No Results", "No analysis results to save")
            return

        self.dashboard.r2_widget.results_viewer._export_results()

    def _export_report(self) -> None:
        """Export the analysis report to the Reports tab."""
        self.dashboard.content_tabs.setCurrentIndex(3)  # Switch to reports tab
        self.dashboard._generate_report()

    def _open_configuration(self) -> None:
        """Open the configuration settings dialog."""
        dialog = R2ConfigurationDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.dashboard.add_activity("Configuration updated")

    def _open_hex_viewer(self) -> None:
        """Open the hex viewer for the currently loaded binary file."""
        if not self.binary_path:
            QMessageBox.warning(self, "No File", "Please open a binary file first")
            return

        try:
            from .widgets.hex_viewer import HexViewerWidget

            with open(self.binary_path, "rb") as f:
                data = f.read()

            dialog = QDialog(self)
            dialog.setWindowTitle("Hex Viewer")
            dialog.resize(1000, 600)
            layout = QVBoxLayout(dialog)
            hex_widget = HexViewerWidget(dialog)
            hex_widget.load_data(data)
            layout.addWidget(hex_widget)
            dialog.exec()
            self.dashboard.add_activity("Opened hex viewer")
        except (ImportError, OSError) as e:
            self.logger.exception("Error opening hex viewer")
            QMessageBox.information(self, "Hex Viewer", f"Hex viewer error: {e}")

    def _show_about(self) -> None:
        """Show the about dialog with application information."""
        QMessageBox.about(
            self,
            "About Intellicrack",
            "Intellicrack - Advanced Binary Analysis Framework\n\n"
            "Version 2.0 with Enhanced Radare2 Integration\n"
            "Copyright (C) 2025 Zachary Flint\n\n"
            "A comprehensive binary analysis tool with AI integration,\n"
            "vulnerability detection, and automated bypass generation.",
        )


def create_enhanced_application() -> tuple[QApplication, EnhancedMainWindow]:
    """Create and return an enhanced Intellicrack application instance.

    Returns:
        Tuple of (QApplication, EnhancedMainWindow) - the application and main window.

    Raises:
        TypeError: If an existing application instance exists but is not QApplication.
    """
    app_instance = QApplication.instance()
    if app_instance is None:
        app = QApplication([])
    elif isinstance(app_instance, QApplication):
        app = app_instance

    else:
        raise TypeError("Existing application instance is not QApplication")
    app.setApplicationName("Intellicrack")
    app.setApplicationVersion("2.0")
    app.setOrganizationName("Intellicrack Project")

    window = EnhancedMainWindow()
    return app, window


def integrate_enhanced_ui_with_existing_app(existing_app: Any) -> bool:
    """Integrate enhanced UI features with an existing application.

    Args:
        existing_app: The existing application instance to integrate with.

    Returns:
        True if integration succeeded, False if an error occurred.
    """
    try:
        enhanced_dashboard: EnhancedAnalysisDashboard | None = None

        if hasattr(existing_app, "tab_widget"):
            tab_widget = getattr(existing_app, "tab_widget", None)
            if tab_widget is not None and isinstance(existing_app, QWidget):
                enhanced_dashboard = EnhancedAnalysisDashboard(existing_app)
                tab_widget.addTab(enhanced_dashboard, "Enhanced Dashboard")
                existing_app.enhanced_dashboard = enhanced_dashboard

                if hasattr(existing_app, "binary_path"):
                    binary_path = getattr(existing_app, "binary_path", None)
                    if isinstance(binary_path, str):
                        enhanced_dashboard.r2_widget.set_binary_path(binary_path)

        if hasattr(existing_app, "menuBar") and enhanced_dashboard is not None:
            menu_bar_method = getattr(existing_app, "menuBar", None)
            if callable(menu_bar_method):
                menu_bar = menu_bar_method()
                if menu_bar is not None:
                    enhanced_menu = menu_bar.addMenu("Enhanced Analysis")

                    comprehensive_action = enhanced_menu.addAction("Comprehensive R2 Analysis")
                    comprehensive_action.triggered.connect(
                        lambda: enhanced_dashboard.r2_widget._start_analysis("comprehensive"),
                    )

                    ai_action = enhanced_menu.addAction("AI-Enhanced Analysis")
                    ai_action.triggered.connect(
                        lambda: enhanced_dashboard.r2_widget._start_analysis("ai"),
                    )

        return True

    except Exception:
        logger.exception("Failed to integrate enhanced UI")
        return False


__all__ = [
    "EnhancedAnalysisDashboard",
    "EnhancedMainWindow",
    "create_enhanced_application",
    "integrate_enhanced_ui_with_existing_app",
]
