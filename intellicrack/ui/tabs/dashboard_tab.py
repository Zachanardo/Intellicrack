"""Dashboard tab for Intellicrack.

This module provides the main dashboard interface with system monitoring,
project overview, and quick access to key features.

Copyright (C) 2025 Zachary Flint

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
from datetime import datetime

from intellicrack.handlers.pyqt6_handler import (
    QDialog,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    Qt,
    QTabWidget,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)

from ..config_manager import get_ui_config_manager
from ..widgets.cpu_status_widget import CPUStatusWidget
from ..widgets.gpu_status_widget import GPUStatusWidget
from ..widgets.system_monitor_widget import SystemMonitorWidget
from .base_tab import BaseTab


class DashboardTab(BaseTab):
    """Dashboard Tab - Manages project files, binary information, and workspace overview.
    Consolidates functionality from the previous Project & Dashboard tab.
    """

    binary_selected = pyqtSignal(str)
    analysis_saved = pyqtSignal(str)
    project_opened = pyqtSignal(str)
    project_closed = pyqtSignal()

    def __init__(self, shared_context=None, parent=None):
        """Initialize dashboard tab with system overview and status monitoring."""
        super().__init__(shared_context, parent)
        self.config_manager = get_ui_config_manager()

        # Subscribe to configuration changes
        self.config_manager.register_callback('theme', self.apply_theme)
        self.config_manager.register_callback('layout.dashboard', self.update_layout)
        self.config_manager.register_callback('font', self.update_fonts)

    def setup_content(self):
        """Setup the simplified dashboard content."""
        layout_config = self.config_manager.get_layout_config()
        layout = QVBoxLayout(self)
        layout.setSpacing(layout_config.panel_spacing)
        layout.setContentsMargins(layout_config.margin_size, layout_config.margin_size,
                                  layout_config.margin_size, layout_config.margin_size)

        # Top section - Quick Start (prominent)
        quick_start_panel = self.create_quick_start_panel()
        layout.addWidget(quick_start_panel)

        # Bottom section - Less prominent panels in tabs
        self.bottom_panel = QTabWidget()

        # Configure tab widget appearance from config
        if self.config_manager.get_setting('dashboard.show_tabs', True):
            self.bottom_panel.addTab(self.create_recent_files_panel(), "Recent Files")

            if self.config_manager.get_setting('dashboard.show_system_monitor', True):
                self.bottom_panel.addTab(self.create_system_monitor_panel(), "System Monitor")

            if self.config_manager.get_setting('dashboard.show_gpu_status', True):
                self.bottom_panel.addTab(self.create_gpu_status_panel(), "GPU Status")

            if self.config_manager.get_setting('dashboard.show_cpu_status', True):
                self.bottom_panel.addTab(self.create_cpu_status_panel(), "CPU Status")

        layout.addWidget(self.bottom_panel)

        # Apply initial theme
        self.apply_theme()

        self.is_loaded = True

    def create_quick_start_panel(self):
        """Create the prominent Quick Start panel."""
        panel = QGroupBox("Quick Start")

        # Apply theme-based styling
        theme = self.config_manager.get_theme_config()
        panel.setStyleSheet(f"""
            QGroupBox {{
                font-size: {self.config_manager.get_font_config().header_size}px;
                font-weight: bold;
                border: 2px solid {theme.accent_color};
                border-radius: {theme.border_radius}px;
                margin: 10px;
                padding-top: 15px;
                background-color: {theme.panel_color};
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                subcontrol-position: top center;
                padding: 0 10px;
                color: {theme.accent_color};
            }}
        """)

        layout = QVBoxLayout(panel)

        # Welcome message
        theme = self.config_manager.get_theme_config()
        font_config = self.config_manager.get_font_config()

        welcome_label = QLabel("Welcome to Intellicrack")
        welcome_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        welcome_label.setStyleSheet(f"""
            font-size: {font_config.header_size}px;
            font-weight: bold;
            color: {theme.text_color};
            margin: 10px;
        """)
        layout.addWidget(welcome_label)

        description_label = QLabel("Select an action to get started:")
        description_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        description_label.setStyleSheet(f"""
            font-size: {font_config.base_size}px;
            color: {theme.text_color_secondary};
            margin-bottom: 20px;
        """)
        layout.addWidget(description_label)

        # Quick start buttons layout
        buttons_layout = QHBoxLayout()
        buttons_layout.setSpacing(20)

        # Open File button
        open_file_btn = QPushButton("📄 Open File")
        open_file_btn.setMinimumHeight(60)
        self._style_quick_start_button(open_file_btn, theme.accent_color)
        open_file_btn.clicked.connect(self.open_file_action)
        buttons_layout.addWidget(open_file_btn)

        # Open Project button
        open_project_btn = QPushButton("📁 Open Project")
        open_project_btn.setMinimumHeight(60)
        self._style_quick_start_button(open_project_btn, theme.success_color)
        open_project_btn.clicked.connect(self.open_project)
        buttons_layout.addWidget(open_project_btn)

        # Select Program from Target button
        select_target_btn = QPushButton("🎯 Select Program from Target")
        select_target_btn.setMinimumHeight(60)
        self._style_quick_start_button(select_target_btn, theme.error_color)
        select_target_btn.clicked.connect(self.select_program_from_target)
        buttons_layout.addWidget(select_target_btn)

        layout.addLayout(buttons_layout)
        layout.addStretch()

        return panel

    def create_recent_files_panel(self):
        """Create the recent files panel."""
        panel = QWidget()
        layout = QVBoxLayout(panel)

        # Recent Files List with theme styling
        self.recent_files_list = QListWidget()
        self.recent_files_list.setAlternatingRowColors(True)

        # Apply theme-based styling
        theme = self.config_manager.get_theme_config()
        self.recent_files_list.setStyleSheet(f"""
            QListWidget {{
                background-color: {theme.input_background};
                color: {theme.text_color};
                border: 1px solid {theme.border_color};
                border-radius: {theme.border_radius // 2}px;
            }}
            QListWidget::item {{
                padding: 5px;
                border-bottom: 1px solid {theme.border_color};
            }}
            QListWidget::item:selected {{
                background-color: {theme.accent_color};
                color: white;
            }}
            QListWidget::item:hover {{
                background-color: {theme.hover_color};
            }}
        """)

        self.populate_recent_files()
        self.recent_files_list.itemDoubleClicked.connect(self.load_recent_file)
        layout.addWidget(self.recent_files_list)

        # Actions
        actions_layout = QHBoxLayout()

        theme = self.config_manager.get_theme_config()
        font_config = self.config_manager.get_font_config()

        refresh_recent_btn = QPushButton("Refresh")
        refresh_recent_btn.clicked.connect(self.populate_recent_files)
        refresh_recent_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {theme.button_color};
                color: {theme.text_color};
                border: 1px solid {theme.border_color};
                border-radius: {theme.border_radius // 2}px;
                padding: 5px 15px;
                font-size: {font_config.base_size}px;
            }}
            QPushButton:hover {{
                background-color: {theme.hover_color};
            }}
            QPushButton:pressed {{
                background-color: {theme.accent_color};
                color: white;
            }}
        """)
        actions_layout.addWidget(refresh_recent_btn)

        clear_recent_btn = QPushButton("Clear All")
        clear_recent_btn.clicked.connect(self.clear_recent_files)
        clear_recent_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {theme.button_color};
                color: {theme.error_color};
                border: 1px solid {theme.error_color};
                border-radius: {theme.border_radius // 2}px;
                padding: 5px 15px;
                font-size: {font_config.base_size}px;
            }}
            QPushButton:hover {{
                background-color: {theme.error_color};
                color: white;
            }}
            QPushButton:pressed {{
                background-color: {theme.error_color};
                color: white;
                border: 1px solid {theme.border_color};
            }}
        """)
        actions_layout.addWidget(clear_recent_btn)

        actions_layout.addStretch()
        layout.addLayout(actions_layout)

        return panel

    def open_file_action(self):
        """Handle Open File button action."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Open File for Analysis",
            "",
            "Executable Files (*.exe *.dll *.so *.dylib *.elf *.bin);;All Files (*)",
        )

        if file_path:
            # Add to recent files and emit signal
            self.add_to_recent_files(file_path)
            self.binary_selected.emit(file_path)

            # Use AppContext if available
            if self.app_context:
                self.app_context.load_binary(file_path)
                self.log_activity(f"Opened file via AppContext: {os.path.basename(file_path)}")
            else:
                self.log_activity(f"Opened file: {os.path.basename(file_path)}")

    def select_program_from_target(self):
        """Handle Select Program from Target button action."""
        try:
            from ..dialogs.program_selector_dialog import ProgramSelectorDialog

            dialog = ProgramSelectorDialog(self)
            if dialog.exec() == QDialog.DialogCode.Accepted:
                selected_program = dialog.get_selected_program()
                if selected_program:
                    self.add_to_recent_files(selected_program)
                    self.binary_selected.emit(selected_program)

                    if self.app_context:
                        self.app_context.load_binary(selected_program)
                        self.log_activity(f"Selected target program: {os.path.basename(selected_program)}")
                    else:
                        self.log_activity(f"Selected target program: {os.path.basename(selected_program)}")
        except ImportError:
            # Fallback to regular file dialog if ProgramSelectorDialog not available
            QMessageBox.information(
                self,
                "Feature Unavailable",
                "Program selector dialog not available. Using file browser instead."
            )
            self.open_file_action()

    def log_activity(self, message):
        """Log an activity message - simplified version for dashboard."""
        # For the simplified dashboard, we can log to console or a simple logger
        # The full activity log functionality will be moved to WorkspaceTab
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {message}")

    def create_system_monitor_panel(self):
        """Create system monitoring panel."""
        self.system_monitor = SystemMonitorWidget()
        self.system_monitor.alert_triggered.connect(self.handle_system_alert)

        # Configure monitoring based on settings
        refresh_interval = self.config_manager.get_setting(
            'dashboard.monitor_refresh_interval', 5000
        )
        self.system_monitor.set_refresh_interval(refresh_interval)

        # Only start monitoring if enabled
        if self.config_manager.get_setting('dashboard.auto_start_monitoring', True):
            self.system_monitor.start_monitoring()

        return self.system_monitor

    def handle_system_alert(self, alert_type: str, message: str):
        """Handle system monitoring alerts."""
        # Log the alert to activity log
        self.log_activity(f"[SYSTEM ALERT - {alert_type}] {message}")

        # Show a message box for critical alerts
        if alert_type in ["CPU", "Memory", "Disk"]:
            QMessageBox.warning(self, f"System Alert - {alert_type}", message)

    def create_gpu_status_panel(self):
        """Create GPU status monitoring panel."""
        self.gpu_status = GPUStatusWidget()

        # Configure GPU monitoring based on settings
        refresh_interval = self.config_manager.get_setting(
            'dashboard.gpu_refresh_interval', 3000
        )
        self.gpu_status.set_refresh_interval(refresh_interval)

        # Only start monitoring if enabled
        if self.config_manager.get_setting('dashboard.auto_start_gpu_monitoring', True):
            self.gpu_status.start_monitoring()

        return self.gpu_status

    def create_cpu_status_panel(self):
        """Create CPU status monitoring panel."""
        self.cpu_status = CPUStatusWidget()

        # Configure CPU monitoring based on settings
        refresh_interval = self.config_manager.get_setting(
            'dashboard.cpu_refresh_interval', 2000
        )
        self.cpu_status.set_refresh_interval(refresh_interval)

        # Only start monitoring if enabled
        if self.config_manager.get_setting('dashboard.auto_start_cpu_monitoring', True):
            self.cpu_status.start_monitoring()

        return self.cpu_status


    def open_project(self):
        """Simple project opening for Quick Start."""
        project_file, _ = QFileDialog.getOpenFileName(
            self,
            "Open Project",
            "",
            "Intellicrack Projects (*.icp);;All Files (*)",
        )

        if project_file:
            self.add_to_recent_files(project_file)
            self.project_opened.emit(project_file)
            self.log_activity(f"Opened project: {os.path.basename(project_file)}")


    def populate_recent_files(self):
        """Populate the recent files list."""
        self.recent_files_list.clear()

        recent_files = self.config_manager.get_setting("recent_files", [])
        max_recent = self.config_manager.get_setting("dashboard.max_recent_files", 10)

        # Limit to configured maximum
        recent_files = recent_files[:max_recent]

        for file_path in recent_files:
            if os.path.exists(file_path):
                item = QListWidgetItem(os.path.basename(file_path))
                item.setData(Qt.ItemDataRole.UserRole, file_path)
                item.setToolTip(file_path)

                # Add file type icon if available
                if self.config_manager.get_setting("dashboard.show_file_icons", True):
                    file_ext = os.path.splitext(file_path)[1].lower()
                    icon_prefix = "🗃️"  # Default file icon
                    if file_ext in ['.exe', '.dll']:
                        icon_prefix = "⚙️"
                    elif file_ext in ['.so', '.dylib']:
                        icon_prefix = "📦"
                    elif file_ext == '.icp':
                        icon_prefix = "📁"
                    item.setText(f"{icon_prefix} {os.path.basename(file_path)}")

                self.recent_files_list.addItem(item)

    def load_recent_file(self, item):
        """Load a file from the recent files list."""
        file_path = item.data(Qt.ItemDataRole.UserRole)
        if file_path and os.path.exists(file_path):
            # Add to recent files and emit signal
            self.add_to_recent_files(file_path)
            self.binary_selected.emit(file_path)

            # Use AppContext if available
            if self.app_context:
                self.app_context.load_binary(file_path)
                self.log_activity(f"Loaded recent file via AppContext: {os.path.basename(file_path)}")
            else:
                self.log_activity(f"Loaded recent file: {os.path.basename(file_path)}")

    def add_to_recent_files(self, file_path):
        """Add a file to the recent files list."""
        recent_files = self.config_manager.get_setting("recent_files", [])
        max_recent = self.config_manager.get_setting("dashboard.max_recent_files", 10)

        # Remove the file path if it already exists
        if file_path in recent_files:
            recent_files.remove(file_path)

        # Insert the file path at the beginning of the list
        recent_files.insert(0, file_path)

        # Limit the list to the configured maximum
        recent_files = recent_files[:max_recent]

        # Save the updated list back to config manager
        self.config_manager.set_setting("recent_files", recent_files)

        # Refresh the UI
        self.populate_recent_files()

    def clear_recent_files(self):
        """Clear the recent files list."""
        self.config_manager.set_setting("recent_files", [])
        self.recent_files_list.clear()
        self.log_activity("Recent files list cleared")

    def cleanup(self):
        """Cleanup resources when tab is closed."""
        # Stop system monitoring
        if hasattr(self, "system_monitor"):
            self.system_monitor.stop_monitoring()
            self.log_activity("System monitoring stopped")

        # Stop GPU monitoring
        if hasattr(self, "gpu_status"):
            self.gpu_status.stop_monitoring()
            self.log_activity("GPU monitoring stopped")

        # Stop CPU monitoring
        if hasattr(self, "cpu_status"):
            self.cpu_status.stop_monitoring()
            self.log_activity("CPU monitoring stopped")

        # Unregister callbacks
        self.config_manager.unregister_callback('theme', self.apply_theme)
        self.config_manager.unregister_callback('layout.dashboard', self.update_layout)
        self.config_manager.unregister_callback('font', self.update_fonts)

        # Call parent cleanup
        super().cleanup()

    def _style_quick_start_button(self, button, base_color):
        """Apply consistent styling to quick start buttons."""
        theme = self.config_manager.get_theme_config()
        font_config = self.config_manager.get_font_config()

        # Calculate hover and pressed colors
        from PyQt6.QtGui import QColor
        base = QColor(base_color)
        hover = base.lighter(120)
        pressed = base.darker(120)

        button.setStyleSheet(f"""
            QPushButton {{
                font-size: {font_config.base_size + 2}px;
                font-weight: bold;
                background-color: {base_color};
                color: white;
                border: none;
                border-radius: {theme.border_radius}px;
                padding: 10px;
            }}
            QPushButton:hover {{
                background-color: {hover.name()};
            }}
            QPushButton:pressed {{
                background-color: {pressed.name()};
            }}
            QPushButton:disabled {{
                background-color: {theme.disabled_color};
                color: {theme.text_color_secondary};
            }}
        """)

    def apply_theme(self):
        """Apply theme changes to dashboard components."""
        if not self.is_loaded:
            return

        theme = self.config_manager.get_theme_config()

        # Update main widget background
        self.setStyleSheet(f"""
            QWidget {{
                background-color: {theme.background_color};
                color: {theme.text_color};
            }}
        """)

        # Update bottom panel tabs
        if hasattr(self, 'bottom_panel'):
            self.bottom_panel.setStyleSheet(f"""
                QTabWidget::pane {{
                    background-color: {theme.panel_color};
                    border: 1px solid {theme.border_color};
                    border-radius: {theme.border_radius}px;
                }}
                QTabBar::tab {{
                    background-color: {theme.panel_color};
                    color: {theme.text_color};
                    padding: 8px 16px;
                    margin-right: 2px;
                }}
                QTabBar::tab:selected {{
                    background-color: {theme.accent_color};
                    color: white;
                }}
                QTabBar::tab:hover {{
                    background-color: {theme.hover_color};
                }}
            """)

    def update_layout(self):
        """Update layout configuration when settings change."""
        if not self.is_loaded:
            return

        layout_config = self.config_manager.get_layout_config()

        # Update layout spacing and margins
        if self.layout():
            self.layout().setSpacing(layout_config.panel_spacing)
            self.layout().setContentsMargins(
                layout_config.margin_size, layout_config.margin_size,
                layout_config.margin_size, layout_config.margin_size
            )

    def update_fonts(self):
        """Update font configuration when settings change."""
        if not self.is_loaded:
            return

        font_config = self.config_manager.get_font_config()

        # Update widget fonts
        from PyQt6.QtGui import QFont
        font = QFont(font_config.family, font_config.base_size)
        self.setFont(font)

        # Update all child widgets
        for widget in self.findChildren(QWidget):
            widget.setFont(font)

