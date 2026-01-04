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

import logging
import os
from datetime import datetime
from typing import Any, Protocol

from intellicrack.handlers.pyqt6_handler import (
    QColor,
    QDialog,
    QFileDialog,
    QFont,
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


logger = logging.getLogger(__name__)


class AppContextProtocol(Protocol):
    """Protocol for app context objects with binary loading capability."""

    def load_binary(self, file_path: str) -> None:
        """Load a binary file for analysis.

        Args:
            file_path: Path to the binary file to load.

        """
        ...


class DashboardTab(BaseTab):
    """Dashboard Tab - Manages project files, binary information, and workspace overview.

    Consolidates functionality from the previous Project & Dashboard tab.
    """

    binary_selected = pyqtSignal(str)
    analysis_saved = pyqtSignal(str)
    project_opened = pyqtSignal(str)
    project_closed = pyqtSignal()

    def __init__(
        self,
        shared_context: dict[str, Any] | AppContextProtocol | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize dashboard tab with system overview and status monitoring.

        Args:
            shared_context: Shared application context for cross-component communication.
            parent: Parent widget for Qt object hierarchy.

        """
        self.config_manager = get_ui_config_manager()
        self._typed_context: AppContextProtocol | None = None
        if shared_context is not None and not isinstance(shared_context, dict):
            self._typed_context = shared_context

        context_dict: dict[str, Any] | None = None
        if isinstance(shared_context, dict):
            context_dict = shared_context

        super().__init__(context_dict, parent)

        # Subscribe to configuration changes with automatic cleanup
        self.config_manager.register_callback("theme", self.apply_theme)
        self.register_callback_for_cleanup("theme", self.apply_theme)

        self.config_manager.register_callback("layout.dashboard", self.update_layout)
        self.register_callback_for_cleanup("layout.dashboard", self.update_layout)

        self.config_manager.register_callback("font", self.update_fonts)
        self.register_callback_for_cleanup("font", self.update_fonts)

    def setup_content(self) -> None:
        """Set up the simplified dashboard content.

        Initializes the dashboard layout with quick start panel, recent files,
        and system monitoring panels based on configuration settings.

        Returns:
            None

        """
        logger.debug("DashboardTab.setup_content() called")
        layout_config = self.config_manager.get_layout_config()
        layout = self.layout()
        if layout is None:
            logger.error("DashboardTab: layout is None! Cannot set up content.")
            return
        logger.debug("DashboardTab: layout found, type=%s", type(layout).__name__)

        layout.setSpacing(layout_config.panel_spacing)
        layout.setContentsMargins(
            layout_config.margin_size,
            layout_config.margin_size,
            layout_config.margin_size,
            layout_config.margin_size,
        )

        quick_start_panel = self.create_quick_start_panel()
        layout.addWidget(quick_start_panel)

        self.bottom_panel = QTabWidget()

        show_tabs = self.config_manager.get_setting("dashboard.show_tabs", True)
        if isinstance(show_tabs, bool) and show_tabs:
            self.bottom_panel.addTab(self.create_recent_files_panel(), "Recent Files")

            show_system_monitor = self.config_manager.get_setting("dashboard.show_system_monitor", True)
            if isinstance(show_system_monitor, bool) and show_system_monitor:
                self.bottom_panel.addTab(self.create_system_monitor_panel(), "System Monitor")

            show_gpu_status = self.config_manager.get_setting("dashboard.show_gpu_status", True)
            if isinstance(show_gpu_status, bool) and show_gpu_status:
                self.bottom_panel.addTab(self.create_gpu_status_panel(), "GPU Status")

            show_cpu_status = self.config_manager.get_setting("dashboard.show_cpu_status", True)
            if isinstance(show_cpu_status, bool) and show_cpu_status:
                self.bottom_panel.addTab(self.create_cpu_status_panel(), "CPU Status")

        layout.addWidget(self.bottom_panel)

        self.main_layout = layout

    def create_quick_start_panel(self) -> QGroupBox:
        """Create the prominent Quick Start panel.

        Returns:
            QGroupBox widget containing quick start action buttons for file operations.

        """
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
        open_file_btn.setToolTip(
            "Load a binary file (EXE, DLL, SO, ELF) for analysis. Supports Windows PE, Linux ELF, and other executable formats",
        )
        self._style_quick_start_button(open_file_btn, theme.accent_color)
        open_file_btn.clicked.connect(self.open_file_action)
        buttons_layout.addWidget(open_file_btn)

        # Open Project button
        open_project_btn = QPushButton(" Open Project")
        open_project_btn.setMinimumHeight(60)
        open_project_btn.setToolTip("Open an existing Intellicrack project workspace with saved analysis sessions and configurations")
        self._style_quick_start_button(open_project_btn, theme.success_color)
        open_project_btn.clicked.connect(self.open_project)
        buttons_layout.addWidget(open_project_btn)

        # Select Running Process button
        select_target_btn = QPushButton("Attach to Running Process")
        select_target_btn.setMinimumHeight(60)
        select_target_btn.setToolTip(
            "Attach to a currently running process for live analysis and debugging. Select from active processes on your system",
        )
        self._style_quick_start_button(select_target_btn, theme.error_color)
        select_target_btn.clicked.connect(self.select_program_from_target)
        buttons_layout.addWidget(select_target_btn)

        layout.addLayout(buttons_layout)
        layout.addStretch()

        return panel

    def create_recent_files_panel(self) -> QWidget:
        """Create the recent files panel.

        Returns:
            QWidget containing the recent files list and management controls.

        """
        panel = QWidget()
        layout = QVBoxLayout(panel)

        # Recent Files List with theme styling
        self.recent_files_list = QListWidget()
        self.recent_files_list.setToolTip("Double-click any file to open it for analysis. Files are sorted by last access time")
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
        refresh_recent_btn.setToolTip("Reload the list of recently accessed files from the analysis history")
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
        clear_recent_btn.setToolTip("Remove all entries from the recent files history. This action cannot be undone")
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

    def open_file_action(self) -> None:
        """Handle Open File button action.

        Opens a file dialog to select a binary file for analysis. When a file
        is selected, adds it to recent files, emits binary_selected signal,
        and logs the activity.

        Returns:
            None

        """
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Open File for Analysis",
            "",
            "Executable Files (*.exe *.dll *.so *.dylib *.elf *.bin);;All Files (*)",
        )

        if file_path:
            self.add_to_recent_files(file_path)
            self.binary_selected.emit(file_path)

            if self._typed_context is not None:
                self._typed_context.load_binary(file_path)
                self.log_activity(f"Opened file via AppContext: {os.path.basename(file_path)}")
            else:
                self.log_activity(f"Opened file: {os.path.basename(file_path)}")

    def select_program_from_target(self) -> None:
        """Handle Select Program from Target button action.

        Opens a program selector dialog to choose from running processes.
        Handles errors gracefully by falling back to file browser if dialog
        unavailable.

        Returns:
            None

        Raises:
            ImportError: If program selector dialog module is not available.
            Exception: If dialog execution encounters unexpected errors.

        """
        try:
            from ..dialogs.program_selector_dialog import ProgramSelectorDialog

            dialog = ProgramSelectorDialog(self)
            if dialog.exec() == QDialog.DialogCode.Accepted:
                selected_program = dialog.get_selected_program()
                if selected_program and os.path.exists(selected_program):
                    self.add_to_recent_files(selected_program)
                    self.binary_selected.emit(selected_program)

                    if self._typed_context is not None:
                        self._typed_context.load_binary(selected_program)
                    self.log_activity(f"Selected target program: {os.path.basename(selected_program)}")
                elif selected_program:
                    QMessageBox.warning(
                        self,
                        "File Not Found",
                        f"The selected program file does not exist:\n{selected_program}",
                    )
                else:
                    QMessageBox.information(self, "No Selection", "No program was selected from the dialog.")
            else:
                self.log_activity("Program selection cancelled by user")

        except ImportError as e:
            QMessageBox.information(
                self,
                "Feature Unavailable",
                f"Program selector dialog not available. Using file browser instead.\n\nTechnical details: {e!s}",
            )
            self.open_file_action()
        except Exception as e:
            QMessageBox.critical(
                self,
                "Program Selection Error",
                f"An error occurred while selecting a program:\n\n{e!s}\n\nPlease try using the Open File option instead.",
            )
            self.log_activity(f"Error in program selection: {e!s}")

    def log_activity(self, message: str) -> None:
        """Log an activity message - simplified version for dashboard.

        Args:
            message: Activity message to log with timestamp.

        Returns:
            None

        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        logger.info("[%s] %s", timestamp, message)

    def create_system_monitor_panel(self) -> SystemMonitorWidget:
        """Create system monitoring panel.

        Returns:
            SystemMonitorWidget configured with dashboard monitoring settings.

        """
        self.system_monitor = SystemMonitorWidget()
        self.system_monitor.alert_triggered.connect(self.handle_system_alert)

        refresh_interval_setting = self.config_manager.get_setting("dashboard.monitor_refresh_interval", 5000)
        refresh_interval = refresh_interval_setting if isinstance(refresh_interval_setting, int) else 5000
        self.system_monitor.set_refresh_interval(refresh_interval)

        auto_start = self.config_manager.get_setting("dashboard.auto_start_monitoring", True)
        if isinstance(auto_start, bool) and auto_start:
            self.system_monitor.start_monitoring()

        return self.system_monitor

    def handle_system_alert(self, alert_type: str, message: str) -> None:
        """Handle system monitoring alerts.

        Args:
            alert_type: Type of system alert (e.g., 'CPU', 'Memory', 'Disk').
            message: Alert message describing the system condition.

        Returns:
            None

        """
        # Log the alert to activity log
        self.log_activity(f"[SYSTEM ALERT - {alert_type}] {message}")

        # Show a message box for critical alerts
        if alert_type in {"CPU", "Memory", "Disk"}:
            QMessageBox.warning(self, f"System Alert - {alert_type}", message)

    def create_gpu_status_panel(self) -> GPUStatusWidget:
        """Create GPU status monitoring panel.

        Returns:
            GPUStatusWidget configured with GPU monitoring settings.

        """
        self.gpu_status = GPUStatusWidget()

        refresh_interval_setting = self.config_manager.get_setting("dashboard.gpu_refresh_interval", 3000)
        refresh_interval = refresh_interval_setting if isinstance(refresh_interval_setting, int) else 3000
        self.gpu_status.set_refresh_interval(refresh_interval)

        auto_start = self.config_manager.get_setting("dashboard.auto_start_gpu_monitoring", True)
        if isinstance(auto_start, bool) and auto_start:
            self.gpu_status.start_monitoring()

        return self.gpu_status

    def create_cpu_status_panel(self) -> CPUStatusWidget:
        """Create CPU status monitoring panel.

        Returns:
            CPUStatusWidget configured with CPU monitoring settings.

        """
        self.cpu_status = CPUStatusWidget()

        refresh_interval_setting = self.config_manager.get_setting("dashboard.cpu_refresh_interval", 2000)
        refresh_interval = refresh_interval_setting if isinstance(refresh_interval_setting, int) else 2000
        self.cpu_status.set_refresh_interval(refresh_interval)

        auto_start = self.config_manager.get_setting("dashboard.auto_start_cpu_monitoring", True)
        if isinstance(auto_start, bool) and auto_start:
            self.cpu_status.start_monitoring()

        return self.cpu_status

    def open_project(self) -> None:
        """Perform project opening for Quick Start.

        Opens a file dialog to select an Intellicrack project file (.icp).
        When selected, adds to recent files and emits project_opened signal.

        Returns:
            None

        """
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

    def populate_recent_files(self) -> None:
        """Populate the recent files list.

        Loads recent files from configuration, filters to max count, and
        populates the recent files list widget with items.

        Returns:
            None

        """
        self.recent_files_list.clear()

        recent_files_setting = self.config_manager.get_setting("recent_files", [])
        recent_files: list[Any] = recent_files_setting if isinstance(recent_files_setting, list) else []

        max_recent_setting = self.config_manager.get_setting("dashboard.max_recent_files", 10)
        max_recent = max_recent_setting if isinstance(max_recent_setting, int) else 10

        recent_files = recent_files[:max_recent]

        for file_path_obj in recent_files:
            if not isinstance(file_path_obj, str):
                continue

            file_path: str = file_path_obj
            if os.path.exists(file_path):
                item = QListWidgetItem(os.path.basename(file_path))
                item.setData(Qt.ItemDataRole.UserRole, file_path)
                item.setToolTip(file_path)

                show_file_icons = self.config_manager.get_setting("dashboard.show_file_icons", True)
                if isinstance(show_file_icons, bool) and show_file_icons:
                    file_ext = os.path.splitext(file_path)[1].lower()
                    icon_prefix = "🗃️"
                    if file_ext in {".exe", ".dll"}:
                        icon_prefix = "[CFG]️"
                    elif file_ext in {".so", ".dylib", ".icp"}:
                        icon_prefix = ""
                    item.setText(f"{icon_prefix} {os.path.basename(file_path)}")

                self.recent_files_list.addItem(item)

    def load_recent_file(self, item: QListWidgetItem) -> None:
        """Load a file from the recent files list.

        Args:
            item: List widget item containing the file path to load.

        """
        file_path = item.data(Qt.ItemDataRole.UserRole)
        if isinstance(file_path, str) and os.path.exists(file_path):
            self.add_to_recent_files(file_path)
            self.binary_selected.emit(file_path)

            if self._typed_context is not None:
                self._typed_context.load_binary(file_path)
                self.log_activity(f"Loaded recent file via AppContext: {os.path.basename(file_path)}")
            else:
                self.log_activity(f"Loaded recent file: {os.path.basename(file_path)}")

    def add_to_recent_files(self, file_path: str) -> None:
        """Add a file to the recent files list.

        Args:
            file_path: Absolute path to the file to add to recent files history.

        """
        recent_files_setting = self.config_manager.get_setting("recent_files", [])
        recent_files: list[str] = []

        if isinstance(recent_files_setting, list):
            recent_files = [f for f in recent_files_setting if isinstance(f, str)]

        max_recent_setting = self.config_manager.get_setting("dashboard.max_recent_files", 10)
        max_recent = max_recent_setting if isinstance(max_recent_setting, int) else 10

        if file_path in recent_files:
            recent_files.remove(file_path)

        recent_files.insert(0, file_path)

        recent_files = recent_files[:max_recent]

        self.config_manager.set_setting("recent_files", recent_files)

        self.populate_recent_files()

    def clear_recent_files(self) -> None:
        """Clear the recent files list.

        Removes all entries from the recent files history and clears the
        list widget display.

        Returns:
            None

        """
        self.config_manager.set_setting("recent_files", [])
        self.recent_files_list.clear()
        self.log_activity("Recent files list cleared")

    def cleanup(self) -> None:
        """Cleanup resources when tab is closed.

        Stops all monitoring threads (system, GPU, CPU) and unregisters
        configuration callbacks via base class cleanup.

        Returns:
            None

        """
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

        # Callbacks are automatically unregistered by base class via register_callback_for_cleanup()
        # Call parent cleanup which handles callback unregistration
        super().cleanup()

    def _style_quick_start_button(self, button: QPushButton, base_color: str) -> None:
        """Apply consistent styling to quick start buttons with improved contrast.

        Args:
            button: QPushButton to apply styling to.
            base_color: Base color string (hex format) for button theming.

        Returns:
            None

        """
        theme = self.config_manager.get_theme_config()
        font_config = self.config_manager.get_font_config()

        base = QColor(base_color)
        # Make base color darker for better contrast with white text
        base_darker = base.darker(140)
        hover = base_darker.lighter(130)
        pressed = base_darker.darker(130)

        button.setStyleSheet(f"""
            QPushButton {{
                font-size: {font_config.base_size + 2}px;
                font-weight: bold;
                background-color: {base_darker.name()};
                color: white;
                border: 2px solid {base.name()};
                border-radius: {theme.border_radius}px;
                padding: 12px;
                text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.5);
            }}
            QPushButton:hover {{
                background-color: {hover.name()};
                border-color: {base.lighter(120).name()};
                transform: translateY(-1px);
            }}
            QPushButton:pressed {{
                background-color: {pressed.name()};
                border-color: {base.darker(120).name()};
                transform: translateY(1px);
            }}
            QPushButton:disabled {{
                background-color: {theme.disabled_color};
                color: {theme.text_color_secondary};
                border-color: {theme.border_color};
            }}
        """)

    def apply_theme(self) -> None:
        """Apply theme changes to dashboard components.

        Updates stylesheet colors and appearance based on current theme
        configuration. Safely handles missing attributes and widget state.

        Returns:
            None

        Raises:
            AttributeError: If expected config attributes are missing.
            RuntimeError: If widget rendering encounters errors.

        """
        if not getattr(self, "is_loaded", False):
            return
        if not hasattr(self, "config_manager"):
            return

        try:
            theme = self.config_manager.get_theme_config()

            self.setStyleSheet(f"""
                QWidget {{
                    background-color: {theme.background_color};
                    color: {theme.text_color};
                }}
            """)

            if hasattr(self, "bottom_panel"):
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
        except (AttributeError, RuntimeError) as e:
            logger.debug("Theme application skipped: %s", e)

    def update_layout(self) -> None:
        """Update layout configuration when settings change.

        Applies spacing and margin settings from layout configuration to the
        dashboard's main layout. Safely handles missing widget state.

        Returns:
            None

        Raises:
            AttributeError: If expected config attributes are missing.
            RuntimeError: If layout updates encounter errors.

        """
        if not getattr(self, "is_loaded", False):
            return
        if not hasattr(self, "config_manager"):
            return

        try:
            layout_config = self.config_manager.get_layout_config()
            layout = self.layout()
            if layout is not None:
                layout.setSpacing(layout_config.panel_spacing)
                layout.setContentsMargins(
                    layout_config.margin_size,
                    layout_config.margin_size,
                    layout_config.margin_size,
                    layout_config.margin_size,
                )
        except (AttributeError, RuntimeError) as e:
            logger.debug("Layout update skipped: %s", e)

    def update_fonts(self) -> None:
        """Update font configuration when settings change.

        Applies font configuration to the dashboard widget and all child
        widgets. Safely handles missing widget state and configuration.

        Returns:
            None

        Raises:
            AttributeError: If expected config attributes are missing.
            RuntimeError: If font updates encounter errors.

        """
        if not getattr(self, "is_loaded", False):
            return
        if not hasattr(self, "config_manager"):
            return

        try:
            font_config = self.config_manager.get_font_config()
            font = QFont(font_config.family, font_config.base_size)
            self.setFont(font)
            for widget in self.findChildren(QWidget):
                widget.setFont(font)
        except (AttributeError, RuntimeError) as e:
            logger.debug("Font update skipped: %s", e)

    def refresh_from_manager(self, dashboard_manager: Any) -> None:
        """Refresh dashboard UI from DashboardManager stats.

        Args:
            dashboard_manager: DashboardManager instance with updated stats.

        Returns:
            None

        """
        if dashboard_manager is None:
            return

        try:
            if hasattr(dashboard_manager, "stats"):
                stats = dashboard_manager.stats
                if stats.get("binary"):
                    binary_info = stats["binary"]
                    self.log_activity(
                        f"Binary loaded: {binary_info.get('name', 'Unknown')} "
                        f"({binary_info.get('size_formatted', 'Unknown size')})",
                    )

            if hasattr(dashboard_manager, "recent_activities"):
                for activity in dashboard_manager.recent_activities[:5]:
                    desc = activity.get("description", "")
                    if desc:
                        self.log_activity(desc)
        except (AttributeError, KeyError, TypeError):
            pass
