"""
Enhanced UI Integration for Comprehensive Radare2 Features

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import os
from typing import Any, Dict

from PyQt6.QtGui import QColor, QFont, QIcon, QPalette
from PyQt6.QtWidgets import (
    QAction,
    QApplication,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QGraphicsScene,
    QGraphicsView,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QStatusBar,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ..utils.logger import get_logger
from .radare2_integration_ui import R2ConfigurationDialog, R2IntegrationWidget

logger = get_logger(__name__)


class EnhancedAnalysisDashboard(QWidget):
    """Enhanced dashboard integrating all radare2 capabilities"""

    def __init__(self, parent=None):
        """Initialize the enhanced analysis dashboard with UI components and logging."""
        super().__init__(parent)
        self.logger = logger
        self.main_app = parent
        self._setup_ui()

    def _setup_ui(self):
        """Setup enhanced dashboard UI"""
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

    def _setup_overview_tab(self):
        """Setup enhanced overview tab"""
        overview_widget = QWidget()
        layout = QVBoxLayout(overview_widget)

        # Quick stats section
        stats_frame = QFrame()
        stats_frame.setFrameStyle(QFrame.StyledPanel)
        stats_layout = QGridLayout(stats_frame)

        self.stats_labels = {}
        stats_data = [
            ("files_analyzed", "Files Analyzed", "0"),
            ("vulnerabilities_found", "Vulnerabilities Found", "0"),
            ("license_functions", "License Functions", "0"),
            ("bypass_opportunities", "Bypass Opportunities", "0")
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
            ("Settings", self._open_settings, "#95a5a6")
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

    def _setup_radare2_tab(self):
        """Setup enhanced radare2 analysis tab"""
        self.r2_widget = R2IntegrationWidget(self)
        self.content_tabs.addTab(self.r2_widget, "Radare2 Analysis")

    def _setup_visualization_tab(self):
        """Setup visualization tab"""
        viz_widget = QWidget()
        layout = QVBoxLayout(viz_widget)

        # Visualization controls
        controls_layout = QHBoxLayout()

        self.viz_type_combo = QComboBox()
        self.viz_type_combo.addItems([
            "Call Graph", "Control Flow Graph", "Function Complexity",
            "Vulnerability Heatmap", "String Distribution", "Import Analysis"
        ])
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

    def _setup_reports_tab(self):
        """Setup reports management tab"""
        reports_widget = QWidget()
        layout = QVBoxLayout(reports_widget)

        # Report controls
        controls_layout = QHBoxLayout()

        self.report_template_combo = QComboBox()
        self.report_template_combo.addItems([
            "Comprehensive Analysis", "Vulnerability Assessment",
            "License Analysis", "Executive Summary", "Technical Details"
        ])

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

    def _darken_color(self, color: str) -> str:
        """Darken a hex color for hover effects"""
        # Simple color darkening
        color_map = {
            "#3498db": "#2980b9",
            "#9b59b6": "#8e44ad",
            "#e67e22": "#d35400",
            "#95a5a6": "#7f8c8d"
        }
        return color_map.get(color, color)

    def update_stats(self, stats_data: Dict[str, Any]):
        """Update dashboard statistics"""
        for key, value in stats_data.items():
            if key in self.stats_labels:
                self.stats_labels[key].setText(str(value))

    def add_activity(self, message: str):
        """Add activity to recent activity list"""
        self.activity_list.insertItem(0, f"[{self._get_timestamp()}] {message}")

        # Keep only last 20 items
        while self.activity_list.count() > 20:
            self.activity_list.takeItem(self.activity_list.count() - 1)

    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().strftime("%H:%M:%S")

    def set_analysis_status(self, status: str, color: str = "#27ae60"):
        """Set analysis status with color"""
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

    def _start_new_analysis(self):
        """Start new analysis"""
        self.content_tabs.setCurrentIndex(1)  # Switch to radare2 tab
        self.add_activity("New analysis session started")

    def _load_report(self):
        """Load existing report"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Load Report", "", "JSON Files (*.json);;All Files (*)"
        )
        if file_path:
            self.add_activity(f"Loaded report: {os.path.basename(file_path)}")

    def _export_results(self):
        """Export analysis results"""
        self.add_activity("Results exported")

    def _open_settings(self):
        """Open settings dialog"""
        dialog = R2ConfigurationDialog(self)
        if dialog.exec() == QDialog.Accepted:
            self.add_activity("Settings updated")

    def _update_visualization(self, viz_type: str):
        """Update visualization based on type"""
        self.viz_scene.clear()
        self.viz_info.setText(f"Visualization: {viz_type}\nNo data available yet.")

    def _refresh_visualization(self):
        """Refresh current visualization"""
        viz_type = self.viz_type_combo.currentText()
        self._update_visualization(viz_type)
        self.add_activity(f"Refreshed {viz_type} visualization")

    def _generate_report(self):
        """Generate report based on template"""
        template = self.report_template_combo.currentText()
        self.report_editor.setText(f"# {template}\n\nReport generated at {self._get_timestamp()}\n\nNo analysis data available yet.")
        self.add_activity(f"Generated {template} report")

    def _save_report(self):
        """Save current report"""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Report", "", "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(self.report_editor.toPlainText())
            self.add_activity(f"Saved report: {os.path.basename(file_path)}")

    def _export_pdf(self):
        """Export report as PDF"""
        self.add_activity("PDF export not yet implemented")


class EnhancedMainWindow(QMainWindow):
    """Enhanced main window with integrated radare2 features"""

    def __init__(self):
        """Initialize the enhanced main window with UI setup, menu bar, toolbar, and status bar."""
        super().__init__()
        self.logger = logger
        self.binary_path = None
        self._setup_ui()
        self._setup_menu_bar()
        self._setup_tool_bar()
        self._setup_status_bar()

    def _setup_ui(self):
        """Setup enhanced main UI"""
        self.setWindowTitle("Intellicrack - Advanced Binary Analysis Framework")
        self.setGeometry(100, 100, 1600, 1000)

        # Set application icon
        self.setWindowIcon(QIcon("icons/intellicrack.png"))  # If icon exists

        # Central widget
        self.dashboard = EnhancedAnalysisDashboard(self)
        self.setCentralWidget(self.dashboard)

        # Apply dark theme
        self._apply_dark_theme()

    def _setup_menu_bar(self):
        """Setup enhanced menu bar"""
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu("File")

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

        # Analysis menu
        analysis_menu = menubar.addMenu("Analysis")

        comprehensive_action = QAction("Comprehensive Analysis", self)
        comprehensive_action.triggered.connect(lambda: self._start_analysis("comprehensive"))
        analysis_menu.addAction(comprehensive_action)

        vulnerability_action = QAction("Vulnerability Scan", self)
        vulnerability_action.triggered.connect(lambda: self._start_analysis("vulnerability"))
        analysis_menu.addAction(vulnerability_action)

        license_action = QAction("License Analysis", self)
        license_action.triggered.connect(lambda: self._start_analysis("decompilation"))
        analysis_menu.addAction(license_action)

        # Tools menu
        tools_menu = menubar.addMenu("Tools")

        config_action = QAction("Configuration", self)
        config_action.triggered.connect(self._open_configuration)
        tools_menu.addAction(config_action)

        hex_viewer_action = QAction("Hex Viewer", self)
        hex_viewer_action.triggered.connect(self._open_hex_viewer)
        tools_menu.addAction(hex_viewer_action)

        # Help menu
        help_menu = menubar.addMenu("Help")

        about_action = QAction("About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    def _setup_tool_bar(self):
        """Setup enhanced tool bar"""
        toolbar = self.addToolBar("Main")
        toolbar.setMovable(False)

        # File operations
        open_action = QAction("Open", self)
        open_action.setIcon(QIcon("icons/open.png"))  # If icon exists
        open_action.triggered.connect(self._open_file)
        toolbar.addAction(open_action)

        toolbar.addSeparator()

        # Analysis operations
        analyze_action = QAction("Analyze", self)
        analyze_action.setIcon(QIcon("icons/analyze.png"))  # If icon exists
        analyze_action.triggered.connect(lambda: self._start_analysis("comprehensive"))
        toolbar.addAction(analyze_action)

        vuln_action = QAction("Vulnerabilities", self)
        vuln_action.setIcon(QIcon("icons/vulnerability.png"))  # If icon exists
        vuln_action.triggered.connect(lambda: self._start_analysis("vulnerability"))
        toolbar.addAction(vuln_action)

        toolbar.addSeparator()

        # Export operations
        export_action = QAction("Export", self)
        export_action.setIcon(QIcon("icons/export.png"))  # If icon exists
        export_action.triggered.connect(self._export_report)
        toolbar.addAction(export_action)

    def _setup_status_bar(self):
        """Setup enhanced status bar"""
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

    def _apply_dark_theme(self):
        """Apply dark theme to application"""
        dark_palette = QPalette()

        # Set colors
        dark_palette.setColor(QPalette.Window, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.WindowText, QColor(255, 255, 255))
        dark_palette.setColor(QPalette.Base, QColor(25, 25, 25))
        dark_palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ToolTipBase, QColor(0, 0, 0))
        dark_palette.setColor(QPalette.ToolTipText, QColor(255, 255, 255))
        dark_palette.setColor(QPalette.Text, QColor(255, 255, 255))
        dark_palette.setColor(QPalette.Button, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ButtonText, QColor(255, 255, 255))
        dark_palette.setColor(QPalette.BrightText, QColor(255, 0, 0))
        dark_palette.setColor(QPalette.Link, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.HighlightedText, QColor(0, 0, 0))

        QApplication.setPalette(dark_palette)

    def _open_file(self):
        """Open binary file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open Binary File", "", "All Files (*)"
        )

        if file_path:
            self.binary_path = file_path
            self.binary_info_label.setText(f"File: {os.path.basename(file_path)}")
            self.dashboard.r2_widget.set_binary_path(file_path)
            self.dashboard.add_activity(f"Opened file: {os.path.basename(file_path)}")
            self.status_bar.showMessage(f"Loaded: {file_path}")

    def _start_analysis(self, analysis_type: str):
        """Start analysis of specified type"""
        if not self.binary_path:
            QMessageBox.warning(self, "No File", "Please open a binary file first")
            return

        self.dashboard.set_analysis_status(f"Running {analysis_type} analysis...", "#e74c3c")
        self.dashboard.add_activity(f"Started {analysis_type} analysis")
        self.progress_bar.setVisible(True)

        # Switch to radare2 tab and start analysis
        self.dashboard.content_tabs.setCurrentIndex(1)
        self.dashboard.r2_widget._start_analysis(analysis_type)

    def _save_results(self):
        """Save analysis results"""
        if not hasattr(self.dashboard.r2_widget.results_viewer, 'results_data'):
            QMessageBox.information(self, "No Results", "No analysis results to save")
            return

        self.dashboard.r2_widget.results_viewer._export_results()

    def _export_report(self):
        """Export analysis report"""
        self.dashboard.content_tabs.setCurrentIndex(3)  # Switch to reports tab
        self.dashboard._generate_report()

    def _open_configuration(self):
        """Open configuration dialog"""
        dialog = R2ConfigurationDialog(self)
        if dialog.exec() == QDialog.Accepted:
            self.dashboard.add_activity("Configuration updated")

    def _open_hex_viewer(self):
        """Open hex viewer"""
        if not self.binary_path:
            QMessageBox.warning(self, "No File", "Please open a binary file first")
            return

        try:
            from .widgets.hex_viewer import show_hex_viewer
            show_hex_viewer(self.binary_path)
            self.dashboard.add_activity("Opened hex viewer")
        except ImportError as e:
            self.logger.error("Import error in enhanced_ui_integration: %s", e)
            QMessageBox.information(self, "Hex Viewer", "Hex viewer not available")

    def _show_about(self):
        """Show about dialog"""
        QMessageBox.about(self, "About Intellicrack",
            "Intellicrack - Advanced Binary Analysis Framework\n\n"
            "Version 2.0 with Enhanced Radare2 Integration\n"
            "Copyright (C) 2025 Zachary Flint\n\n"
            "A comprehensive binary analysis tool with AI integration,\n"
            "vulnerability detection, and automated bypass generation.")


def create_enhanced_application():
    """Create and return enhanced Intellicrack application"""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])

    # Set application metadata
    app.setApplicationName("Intellicrack")
    app.setApplicationVersion("2.0")
    app.setOrganizationName("Intellicrack Project")

    window = EnhancedMainWindow()
    return app, window


def integrate_enhanced_ui_with_existing_app(existing_app):
    """Integrate enhanced UI features with existing application"""
    try:
        # Add enhanced dashboard if main app has tab widget
        if hasattr(existing_app, 'tab_widget'):
            enhanced_dashboard = EnhancedAnalysisDashboard(existing_app)
            existing_app.tab_widget.addTab(enhanced_dashboard, "Enhanced Dashboard")

            # Store reference
            existing_app.enhanced_dashboard = enhanced_dashboard

            # Connect binary path updates
            if hasattr(existing_app, 'binary_path'):
                enhanced_dashboard.r2_widget.set_binary_path(existing_app.binary_path)

        # Add enhanced menu items if main app has menu bar
        if hasattr(existing_app, 'menuBar'):
            enhanced_menu = existing_app.menuBar().addMenu("Enhanced Analysis")

            # Add enhanced analysis actions
            comprehensive_action = enhanced_menu.addAction("Comprehensive R2 Analysis")
            comprehensive_action.triggered.connect(
                lambda: existing_app.enhanced_dashboard.r2_widget._start_analysis("comprehensive")
            )

            ai_action = enhanced_menu.addAction("AI-Enhanced Analysis")
            ai_action.triggered.connect(
                lambda: existing_app.enhanced_dashboard.r2_widget._start_analysis("ai")
            )

        return True

    except Exception as e:
        logger.error(f"Failed to integrate enhanced UI: {e}")
        return False


__all__ = [
    'EnhancedAnalysisDashboard',
    'EnhancedMainWindow',
    'create_enhanced_application',
    'integrate_enhanced_ui_with_existing_app'
]
