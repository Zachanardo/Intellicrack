"""Settings tab for Intellicrack.

This module provides the settings interface for application configuration,
preferences, and system settings management.

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

import json
import logging
import os
import re
from typing import Any
from weakref import WeakKeyDictionary

from intellicrack.handlers.pyqt6_handler import (
    QCheckBox,
    QColor,
    QColorDialog,
    QComboBox,
    QDoubleSpinBox,
    QFileDialog,
    QFont,
    QFontComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSlider,
    QSpinBox,
    QSplitter,
    Qt,
    QTabWidget,
    QTextEdit,
    QTimer,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)

from .base_tab import BaseTab


class SettingsTab(BaseTab):
    """Settings tab for configuration management."""

    settings_changed = pyqtSignal(str, object)
    theme_changed = pyqtSignal(str)

    def __init__(self, shared_context: dict[str, Any] | None = None, parent: QWidget | None = None) -> None:
        """Initialize settings tab with application configuration and preferences.

        Args:
            shared_context: Optional shared context dictionary containing application state and utilities.
            parent: Optional parent widget for this settings tab.

        """
        from intellicrack.core.config_manager import IntellicrackConfig

        self.logger = logging.getLogger(f"{__name__}.SettingsTab")

        # Use centralized configuration system
        self.config = IntellicrackConfig()
        self.load_settings()

        self._original_tooltips: WeakKeyDictionary[QWidget, str] = WeakKeyDictionary()

        # Track current accent color for proper replacement
        self._current_accent_color = self.settings.get("accent_color", "#0078d4")

        super().__init__(shared_context, parent)

    def setup_content(self) -> None:
        """Set up the settings tab content."""
        layout = self.layout()
        if layout is None:
            return

        h_container = QWidget()
        h_layout = QHBoxLayout(h_container)

        left_panel = self.create_settings_panel()

        right_panel = self.create_preview_panel()

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setStretchFactor(0, 60)
        splitter.setStretchFactor(1, 40)

        h_layout.addWidget(splitter)
        layout.addWidget(h_container)
        self.is_loaded = True

    def create_settings_panel(self) -> QWidget:
        """Create the settings control panel.

        Returns:
            QWidget: The settings panel widget containing tabs and control buttons.

        """
        panel = QWidget()
        layout = QVBoxLayout(panel)

        # Settings tabs
        self.settings_tabs = QTabWidget()
        self.settings_tabs.setTabPosition(QTabWidget.TabPosition.North)

        # Add settings categories
        self.settings_tabs.addTab(self.create_appearance_tab(), "Appearance")
        self.settings_tabs.addTab(self.create_analysis_tab(), "Analysis")
        self.settings_tabs.addTab(self.create_performance_tab(), "Performance")
        self.settings_tabs.addTab(self.create_paths_tab(), "Paths")
        self.settings_tabs.addTab(self.create_advanced_tab(), "Advanced")

        layout.addWidget(self.settings_tabs)

        # Settings controls
        controls_layout = QHBoxLayout()

        save_btn = QPushButton("Save Settings")
        save_btn.setToolTip("Save all current settings and preferences to the configuration file")
        save_btn.clicked.connect(self.save_settings)
        save_btn.setObjectName("saveButton")

        reset_btn = QPushButton("Reset to Defaults")
        reset_btn.setToolTip("Reset all settings to their default values. This action cannot be undone")
        reset_btn.clicked.connect(self.reset_to_defaults)
        reset_btn.setObjectName("resetButton")

        export_btn = QPushButton("Export Settings")
        export_btn.setToolTip("Export current settings to a JSON file for backup or sharing")
        export_btn.clicked.connect(self.export_settings)

        import_btn = QPushButton("Import Settings")
        import_btn.setToolTip("Import settings from a previously exported JSON configuration file")
        import_btn.clicked.connect(self.import_settings)

        controls_layout.addWidget(save_btn)
        controls_layout.addWidget(reset_btn)
        controls_layout.addWidget(export_btn)
        controls_layout.addWidget(import_btn)
        controls_layout.addStretch()

        layout.addLayout(controls_layout)
        return panel

    def create_appearance_tab(self) -> QWidget:
        """Create appearance settings tab.

        Returns:
            QWidget: The appearance settings tab widget.

        """
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Theme Settings
        theme_group = QGroupBox("Theme Settings")
        theme_layout = QVBoxLayout(theme_group)

        theme_select_layout = QHBoxLayout()
        theme_select_layout.addWidget(QLabel("Theme:"))
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Dark", "Light", "Auto"])
        theme_value = self.settings.get("theme", "Light")
        if isinstance(theme_value, str):
            self.theme_combo.setCurrentText(theme_value)
        self.theme_combo.currentTextChanged.connect(self.on_theme_changed)
        theme_select_layout.addWidget(self.theme_combo)
        theme_select_layout.addStretch()

        # Color scheme
        color_layout = QHBoxLayout()
        color_layout.addWidget(QLabel("Accent Color:"))
        self.accent_color_btn = QPushButton("Select Color")
        self.accent_color_btn.clicked.connect(self.select_accent_color)
        current_color = self.settings.get("accent_color", "#0078d4")
        self.accent_color_btn.setStyleSheet(f"background-color: {current_color}; color: white; border: 2px solid #888888;")
        color_layout.addWidget(self.accent_color_btn)
        color_layout.addStretch()

        transparency_layout = QHBoxLayout()
        transparency_layout.addWidget(QLabel("Window Opacity:"))
        self.opacity_slider = QSlider(Qt.Orientation.Horizontal)
        self.opacity_slider.setRange(50, 100)
        opacity_value = self.settings.get("window_opacity", 100)
        if isinstance(opacity_value, int):
            self.opacity_slider.setValue(opacity_value)
        self.opacity_slider.valueChanged.connect(self.on_opacity_changed)
        self.opacity_label = QLabel(f"{self.opacity_slider.value()}%")
        transparency_layout.addWidget(self.opacity_slider)
        transparency_layout.addWidget(self.opacity_label)

        theme_layout.addLayout(theme_select_layout)
        theme_layout.addLayout(color_layout)
        theme_layout.addLayout(transparency_layout)

        # Font Settings
        font_group = QGroupBox("Font Settings")
        font_layout = QVBoxLayout(font_group)

        # UI Font
        ui_font_layout = QHBoxLayout()
        ui_font_layout.addWidget(QLabel("UI Font:"))
        self.ui_font_combo = QFontComboBox()
        self.ui_font_combo.setCurrentFont(QFont(self.settings.get("ui_font", "Segoe UI")))
        self.ui_font_combo.currentFontChanged.connect(self.on_ui_font_changed)
        ui_font_layout.addWidget(self.ui_font_combo)

        self.ui_font_size = QSpinBox()
        self.ui_font_size.setRange(8, 24)
        ui_font_size_value = self.settings.get("ui_font_size", 10)
        if isinstance(ui_font_size_value, int):
            self.ui_font_size.setValue(ui_font_size_value)
        self.ui_font_size.valueChanged.connect(self.on_ui_font_size_changed)
        ui_font_layout.addWidget(self.ui_font_size)

        # Console Font
        console_font_layout = QHBoxLayout()
        console_font_layout.addWidget(QLabel("Console Font:"))
        self.console_font_combo = QFontComboBox()
        self.console_font_combo.setCurrentFont(QFont(self.settings.get("console_font", "Consolas")))
        self.console_font_combo.currentFontChanged.connect(self.on_console_font_changed)
        console_font_layout.addWidget(self.console_font_combo)

        self.console_font_size = QSpinBox()
        self.console_font_size.setRange(8, 24)
        console_font_size_value = self.settings.get("console_font_size", 10)
        if isinstance(console_font_size_value, int):
            self.console_font_size.setValue(console_font_size_value)
        self.console_font_size.valueChanged.connect(self.on_console_font_size_changed)
        console_font_layout.addWidget(self.console_font_size)

        font_layout.addLayout(ui_font_layout)
        font_layout.addLayout(console_font_layout)

        # Icon Settings
        icon_group = QGroupBox("Icon Settings")
        icon_layout = QVBoxLayout(icon_group)

        icon_size_layout = QHBoxLayout()
        icon_size_layout.addWidget(QLabel("Icon Size:"))
        self.icon_size_combo = QComboBox()
        self.icon_size_combo.addItems(["Small (16px)", "Medium (24px)", "Large (32px)"])
        current_size = self.settings.get("icon_size", 24)
        if current_size == 16:
            self.icon_size_combo.setCurrentText("Small (16px)")
        elif current_size == 32:
            self.icon_size_combo.setCurrentText("Large (32px)")
        else:
            self.icon_size_combo.setCurrentText("Medium (24px)")
        icon_size_layout.addWidget(self.icon_size_combo)
        icon_size_layout.addStretch()

        self.show_tooltips_cb = QCheckBox("Show Tooltips")
        current_tooltip_state = self.settings.get("show_tooltips", True)
        tooltip_state_bool = bool(current_tooltip_state) if isinstance(current_tooltip_state, bool) else True
        self.show_tooltips_cb.setChecked(tooltip_state_bool)
        self.show_tooltips_cb.stateChanged.connect(self.on_tooltips_toggled)

        QTimer.singleShot(500, lambda: self.apply_tooltip_settings(tooltip_state_bool))

        self.enable_animations_cb = QCheckBox("Enable Smooth Animations")
        current_animation_state = self.settings.get("enable_animations", True)
        animation_state_bool = bool(current_animation_state) if isinstance(current_animation_state, bool) else True
        self.enable_animations_cb.setChecked(animation_state_bool)
        self.enable_animations_cb.stateChanged.connect(self.on_animations_toggled)

        QTimer.singleShot(100, lambda: self.apply_animation_settings(animation_state_bool))

        icon_layout.addLayout(icon_size_layout)
        icon_layout.addWidget(self.show_tooltips_cb)
        icon_layout.addWidget(self.enable_animations_cb)

        layout.addWidget(theme_group)
        layout.addWidget(font_group)
        layout.addWidget(icon_group)
        layout.addStretch()

        return tab

    def create_analysis_tab(self) -> QWidget:
        """Create analysis settings tab.

        Returns:
            QWidget: The analysis settings tab widget.

        """
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Default Analysis Settings
        analysis_group = QGroupBox("Default Analysis Settings")
        analysis_layout = QVBoxLayout(analysis_group)

        self.auto_analysis_cb = QCheckBox("Enable Auto-Analysis")
        auto_analysis_value = self.settings.get("auto_analysis", True)
        if isinstance(auto_analysis_value, bool):
            self.auto_analysis_cb.setChecked(auto_analysis_value)

        depth_layout = QHBoxLayout()
        depth_layout.addWidget(QLabel("Default Analysis Depth:"))
        self.analysis_depth_combo = QComboBox()
        self.analysis_depth_combo.addItems(["Quick", "Standard", "Deep", "Comprehensive"])
        analysis_depth_value = self.settings.get("analysis_depth", "Standard")
        if isinstance(analysis_depth_value, str):
            self.analysis_depth_combo.setCurrentText(analysis_depth_value)
        depth_layout.addWidget(self.analysis_depth_combo)
        depth_layout.addStretch()

        timeout_layout = QHBoxLayout()
        timeout_layout.addWidget(QLabel("Analysis Timeout (seconds):"))
        self.analysis_timeout = QSpinBox()
        self.analysis_timeout.setRange(10, 3600)
        timeout_value = self.settings.get("analysis_timeout", 300)
        if isinstance(timeout_value, int):
            self.analysis_timeout.setValue(timeout_value)
        timeout_layout.addWidget(self.analysis_timeout)
        timeout_layout.addStretch()

        analysis_layout.addWidget(self.auto_analysis_cb)
        analysis_layout.addLayout(depth_layout)
        analysis_layout.addLayout(timeout_layout)

        # AI Settings
        ai_group = QGroupBox("AI Integration Settings")
        ai_layout = QVBoxLayout(ai_group)

        # Default AI provider
        provider_layout = QHBoxLayout()
        provider_layout.addWidget(QLabel("Default AI Provider:"))
        self.ai_provider_combo = QComboBox()
        self.populate_ai_providers()
        provider_layout.addWidget(self.ai_provider_combo)

        refresh_providers_btn = QPushButton("🔄")
        refresh_providers_btn.setMaximumWidth(40)
        refresh_providers_btn.setToolTip("Refresh available AI providers")
        refresh_providers_btn.clicked.connect(self.populate_ai_providers)
        provider_layout.addWidget(refresh_providers_btn)

        provider_layout.addStretch()

        temp_layout = QHBoxLayout()
        temp_layout.addWidget(QLabel("AI Temperature:"))
        self.ai_temperature = QDoubleSpinBox()
        self.ai_temperature.setRange(0.0, 2.0)
        self.ai_temperature.setSingleStep(0.1)
        ai_temp_value = self.settings.get("ai_temperature", 0.7)
        if isinstance(ai_temp_value, (int, float)):
            self.ai_temperature.setValue(float(ai_temp_value))
        temp_layout.addWidget(self.ai_temperature)
        temp_layout.addStretch()

        tokens_layout = QHBoxLayout()
        tokens_layout.addWidget(QLabel("Max Tokens:"))
        self.ai_max_tokens = QSpinBox()
        self.ai_max_tokens.setRange(100, 8000)
        ai_tokens_value = self.settings.get("ai_max_tokens", 2000)
        if isinstance(ai_tokens_value, int):
            self.ai_max_tokens.setValue(ai_tokens_value)
        tokens_layout.addWidget(self.ai_max_tokens)
        tokens_layout.addStretch()

        ai_layout.addLayout(provider_layout)
        ai_layout.addLayout(temp_layout)
        ai_layout.addLayout(tokens_layout)

        # Script Generation Settings
        script_group = QGroupBox("Script Generation Settings")
        script_layout = QVBoxLayout(script_group)

        self.include_comments_cb = QCheckBox("Include Comments in Generated Scripts")
        include_comments_value = self.settings.get("include_comments", True)
        if isinstance(include_comments_value, bool):
            self.include_comments_cb.setChecked(include_comments_value)

        self.include_error_handling_cb = QCheckBox("Include Error Handling")
        include_error_handling_value = self.settings.get("include_error_handling", True)
        if isinstance(include_error_handling_value, bool):
            self.include_error_handling_cb.setChecked(include_error_handling_value)

        self.optimize_code_cb = QCheckBox("Optimize Generated Code")
        optimize_code_value = self.settings.get("optimize_code", False)
        if isinstance(optimize_code_value, bool):
            self.optimize_code_cb.setChecked(optimize_code_value)

        script_layout.addWidget(self.include_comments_cb)
        script_layout.addWidget(self.include_error_handling_cb)
        script_layout.addWidget(self.optimize_code_cb)

        layout.addWidget(analysis_group)
        layout.addWidget(ai_group)
        layout.addWidget(script_group)
        layout.addStretch()

        return tab

    def create_performance_tab(self) -> QWidget:
        """Create performance settings tab.

        Returns:
            QWidget: The performance settings tab widget.

        """
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Memory Settings
        memory_group = QGroupBox("Memory Settings")
        memory_layout = QVBoxLayout(memory_group)

        cache_layout = QHBoxLayout()
        cache_layout.addWidget(QLabel("Cache Size (MB):"))
        self.cache_size = QSpinBox()
        self.cache_size.setRange(100, 8192)
        cache_size_value = self.settings.get("cache_size", 512)
        if isinstance(cache_size_value, int):
            self.cache_size.setValue(cache_size_value)
        cache_layout.addWidget(self.cache_size)
        cache_layout.addStretch()

        memory_limit_layout = QHBoxLayout()
        memory_limit_layout.addWidget(QLabel("Memory Limit (MB):"))
        self.memory_limit = QSpinBox()
        self.memory_limit.setRange(512, 16384)
        memory_limit_value = self.settings.get("memory_limit", 2048)
        if isinstance(memory_limit_value, int):
            self.memory_limit.setValue(memory_limit_value)
        memory_limit_layout.addWidget(self.memory_limit)
        memory_limit_layout.addStretch()

        self.auto_cleanup_cb = QCheckBox("Auto Cleanup Memory")
        auto_cleanup_value = self.settings.get("auto_cleanup", True)
        if isinstance(auto_cleanup_value, bool):
            self.auto_cleanup_cb.setChecked(auto_cleanup_value)

        memory_layout.addLayout(cache_layout)
        memory_layout.addLayout(memory_limit_layout)
        memory_layout.addWidget(self.auto_cleanup_cb)

        # Threading Settings
        threading_group = QGroupBox("Threading Settings")
        threading_layout = QVBoxLayout(threading_group)

        threads_layout = QHBoxLayout()
        threads_layout.addWidget(QLabel("Worker Threads:"))
        self.worker_threads = QSpinBox()
        self.worker_threads.setRange(1, 16)
        worker_threads_value = self.settings.get("worker_threads", 4)
        if isinstance(worker_threads_value, int):
            self.worker_threads.setValue(worker_threads_value)
        threads_layout.addWidget(self.worker_threads)
        threads_layout.addStretch()

        self.parallel_processing_cb = QCheckBox("Enable Parallel Processing")
        parallel_processing_value = self.settings.get("parallel_processing", True)
        if isinstance(parallel_processing_value, bool):
            self.parallel_processing_cb.setChecked(parallel_processing_value)

        self.background_tasks_cb = QCheckBox("Enable Background Tasks")
        background_tasks_value = self.settings.get("background_tasks", True)
        if isinstance(background_tasks_value, bool):
            self.background_tasks_cb.setChecked(background_tasks_value)

        threading_layout.addLayout(threads_layout)
        threading_layout.addWidget(self.parallel_processing_cb)
        threading_layout.addWidget(self.background_tasks_cb)

        # GPU Acceleration
        gpu_group = QGroupBox("GPU Acceleration")
        gpu_layout = QVBoxLayout(gpu_group)

        self.enable_gpu_cb = QCheckBox("Enable GPU Acceleration")
        enable_gpu_value = self.settings.get("enable_gpu", False)
        if isinstance(enable_gpu_value, bool):
            self.enable_gpu_cb.setChecked(enable_gpu_value)

        gpu_device_layout = QHBoxLayout()
        gpu_device_layout.addWidget(QLabel("GPU Device:"))
        self.gpu_device_combo = QComboBox()
        self.gpu_device_combo.addItems(["Auto", "CUDA", "OpenCL", "DirectML"])
        gpu_device_value = self.settings.get("gpu_device", "Auto")
        if isinstance(gpu_device_value, str):
            self.gpu_device_combo.setCurrentText(gpu_device_value)
        gpu_device_layout.addWidget(self.gpu_device_combo)
        gpu_device_layout.addStretch()

        gpu_layout.addWidget(self.enable_gpu_cb)
        gpu_layout.addLayout(gpu_device_layout)

        layout.addWidget(memory_group)
        layout.addWidget(threading_group)
        layout.addWidget(gpu_group)
        layout.addStretch()

        return tab

    def create_paths_tab(self) -> QWidget:
        """Create paths settings tab with auto-discovery and visual feedback.

        Returns:
            QWidget: The paths settings tab widget with tool discovery capabilities.

        """
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Auto-discovery control
        discovery_header = QHBoxLayout()
        discovery_header.addWidget(QLabel("Tool Discovery"))

        self.auto_discovery_btn = QPushButton(" Discover Tools")
        self.auto_discovery_btn.setToolTip("Automatically scan for installed tools")
        self.auto_discovery_btn.clicked.connect(self.discover_tools)

        self.refresh_discovery_btn = QPushButton("🔄 Refresh")
        self.refresh_discovery_btn.setToolTip("Re-scan for tools")
        self.refresh_discovery_btn.clicked.connect(self.refresh_tool_discovery)

        discovery_header.addWidget(self.auto_discovery_btn)
        discovery_header.addWidget(self.refresh_discovery_btn)
        discovery_header.addStretch()

        layout.addLayout(discovery_header)

        # Tool Paths with enhanced UI
        tools_group = QGroupBox("Analysis Tools")
        tools_layout = QVBoxLayout(tools_group)

        # Initialize tool discovery
        from intellicrack.core.tool_discovery import AdvancedToolDiscovery

        self.tool_discovery = AdvancedToolDiscovery()

        self.tool_widgets: dict[str, dict[str, Any]] = {}

        # Create enhanced tool path entries
        tools_config = [
            ("ghidra", "Ghidra", "Select Ghidra Directory"),
            ("radare2", "Radare2", "Select Radare2 Executable"),
            ("x64dbg", "x64dbg", "Select x64dbg Executable"),
            ("nasm", "NASM", "Select NASM Executable"),
            ("masm", "MASM", "Select MASM Executable"),
            ("accesschk", "AccessChk", "Select AccessChk Executable"),
        ]

        for tool_key, tool_label, browse_title in tools_config:
            tool_widget = self.create_enhanced_tool_entry(tool_key, tool_label, browse_title)
            tools_layout.addWidget(tool_widget)

        # Output Paths
        output_group = QGroupBox("Output Directories")
        output_layout = QVBoxLayout(output_group)

        # Output directory
        output_dir_widget = self.create_directory_entry("output_directory", "Output Directory", "Select Output Directory")
        output_layout.addWidget(output_dir_widget)

        # Reports directory
        reports_dir_widget = self.create_directory_entry("reports_directory", "Reports Directory", "Select Reports Directory")
        output_layout.addWidget(reports_dir_widget)

        # Scripts directory
        scripts_dir_widget = self.create_directory_entry("scripts_directory", "Scripts Directory", "Select Scripts Directory")
        output_layout.addWidget(scripts_dir_widget)

        layout.addWidget(tools_group)
        layout.addWidget(output_group)
        layout.addStretch()

        # Auto-discover tools on tab creation
        QTimer.singleShot(100, self.discover_tools)

        return tab

    def create_enhanced_tool_entry(self, tool_key: str, tool_label: str, browse_title: str) -> QWidget:
        """Create an enhanced tool path entry with auto-discovery and status indicators.

        Args:
            tool_key: The unique identifier for the tool (e.g., 'ghidra', 'radare2').
            tool_label: The display label for the tool (e.g., 'Ghidra', 'Radare2').
            browse_title: The title shown in the file browser dialog when user browses for the tool.

        Returns:
            QWidget: A container widget with tool path entry, status indicator, and control buttons.

        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 5, 0, 5)

        # Main row with label, path, status, and browse button
        main_row = QHBoxLayout()

        # Tool label
        label = QLabel(f"{tool_label}:")
        label.setMinimumWidth(80)
        main_row.addWidget(label)

        path_edit = QLineEdit()
        current_path = self.settings.get(f"{tool_key}_path", "")
        if isinstance(current_path, str) and current_path:
            path_edit.setText(current_path)
        path_edit.textChanged.connect(lambda text, key=tool_key: self.on_tool_path_changed(key, text))

        # Status indicator
        status_label = QLabel("⚪")
        status_label.setToolTip("Tool status unknown")
        status_label.setMinimumWidth(30)

        # Browse button
        browse_btn = QPushButton("")
        browse_btn.setMaximumWidth(40)
        browse_btn.setToolTip("Browse for tool executable")
        def _on_browse(checked: bool = False, edit: QLineEdit = path_edit, title: str = browse_title) -> None:
            self.logger.debug(
                "Browse button clicked, checked state: %s for edit: %s, title: %s",
                checked,
                edit,
                title,
            )
            self.browse_tool_path(edit, title)
        browse_btn.clicked.connect(_on_browse)

        reset_btn = QPushButton("↻")
        reset_btn.setMaximumWidth(40)
        reset_btn.setToolTip("Reset to auto-discovered path")
        def _on_reset(checked: bool = False, key: str = tool_key) -> None:
            self.logger.debug("Reset button clicked, checked state: %s for key: %s", checked, key)
            self.reset_tool_path(key)
        reset_btn.clicked.connect(_on_reset)

        main_row.addWidget(path_edit)
        main_row.addWidget(status_label)
        main_row.addWidget(browse_btn)
        main_row.addWidget(reset_btn)

        # Status details (initially hidden)
        status_details = QLabel()
        status_details.setStyleSheet("color: #666; font-size: 10px; margin-left: 85px;")
        status_details.hide()

        layout.addLayout(main_row)
        layout.addWidget(status_details)

        # Store widget references
        self.tool_widgets[tool_key] = {
            "path_edit": path_edit,
            "status_label": status_label,
            "status_details": status_details,
            "container": container,
        }

        return container

    def create_directory_entry(self, dir_key: str, dir_label: str, browse_title: str) -> QWidget:
        """Create a directory path entry.

        Args:
            dir_key: The configuration key for the directory setting.
            dir_label: The display label for the directory field.
            browse_title: The title shown in the directory browser dialog.

        Returns:
            QWidget: A container widget with directory path entry and browse button.

        """
        container = QWidget()
        layout = QHBoxLayout(container)
        layout.setContentsMargins(0, 5, 0, 5)

        # Directory label
        label = QLabel(f"{dir_label}:")
        label.setMinimumWidth(80)
        layout.addWidget(label)

        path_edit = QLineEdit()
        current_dir_path = self.settings.get(dir_key, "")
        if isinstance(current_dir_path, str) and current_dir_path:
            path_edit.setText(current_dir_path)

        # Browse button
        browse_btn = QPushButton("")
        browse_btn.setMaximumWidth(40)
        browse_btn.setToolTip("Browse for directory")
        def _on_browse_dir(checked: bool = False, edit: QLineEdit = path_edit, title: str = browse_title) -> None:
            self.logger.debug(
                "Directory browse button clicked, checked state: %s for edit: %s, title: %s",
                checked,
                edit,
                title,
            )
            self.browse_directory(edit, title)
        browse_btn.clicked.connect(_on_browse_dir)

        layout.addWidget(path_edit)
        layout.addWidget(browse_btn)

        # Store reference for settings collection
        setattr(self, dir_key, path_edit)

        return container

    def discover_tools(self) -> None:
        """Discover all tools and update the UI with results."""
        if not hasattr(self, "tool_discovery"):
            return

        self.auto_discovery_btn.setEnabled(False)
        self.auto_discovery_btn.setText(" Discovering...")

        try:
            # Run discovery in background to avoid blocking UI
            discovered_tools = self.tool_discovery.discover_all_tools()

            # Update UI with discovered tools
            for tool_key, widgets in self.tool_widgets.items():
                if tool_key in discovered_tools:
                    tool_info = discovered_tools[tool_key]
                    self.update_tool_status(tool_key, tool_info)

                    # Auto-populate if path is empty and tool was found
                    current_path = widgets["path_edit"].text().strip()
                    if not current_path and tool_info.get("available") and tool_info.get("path"):
                        widgets["path_edit"].setText(tool_info["path"])

        except Exception as e:
            self.log_message(f"Tool discovery failed: {e}", "error")
        finally:
            self.auto_discovery_btn.setEnabled(True)
            self.auto_discovery_btn.setText(" Discover Tools")

    def refresh_tool_discovery(self) -> None:
        """Refresh tool discovery."""
        if hasattr(self, "tool_discovery"):
            self.tool_discovery.refresh_discovery()
            self.discover_tools()

    def update_tool_status(self, tool_key: str, tool_info: dict[str, object]) -> None:
        """Update the visual status indicator for a tool.

        Args:
            tool_key: The unique identifier for the tool being updated.
            tool_info: Dictionary containing tool information with keys like 'available', 'path', 'error'.

        """
        if tool_key not in self.tool_widgets:
            return

        widgets = self.tool_widgets[tool_key]
        status_label = widgets["status_label"]
        status_details = widgets["status_details"]

        if tool_info.get("available"):
            # Run health check for more detailed status
            try:
                health_info = self.tool_discovery.health_check_tool(tool_key)

                if health_info.get("healthy"):
                    status_label.setText("🟢")
                    status_label.setToolTip("Tool found and healthy")
                    version = health_info.get("version", "Unknown version")
                    status_details.setText(f"OK Found: {version}")
                    status_details.setStyleSheet("color: #28a745; font-size: 10px; margin-left: 85px;")

                elif health_info.get("available"):
                    status_label.setText("🟡")
                    status_label.setToolTip("Tool found but has issues")
                    issues = ", ".join(health_info.get("issues", ["Unknown issues"]))
                    status_details.setText(f"WARNING Issues: {issues}")
                    status_details.setStyleSheet("color: #ffc107; font-size: 10px; margin-left: 85px;")

                else:
                    status_label.setText("🔴")
                    status_label.setToolTip("Tool path exists but not functional")
                    status_details.setText("FAIL Not functional")
                    status_details.setStyleSheet("color: #dc3545; font-size: 10px; margin-left: 85px;")

            except Exception as e:
                status_label.setText("🟡")
                status_label.setToolTip(f"Health check failed: {e}")
                status_details.setText("WARNING Status check failed")
                status_details.setStyleSheet("color: #ffc107; font-size: 10px; margin-left: 85px;")
        else:
            status_label.setText("⚫")
            status_label.setToolTip("Tool not found")
            error_msg = tool_info.get("error", "Not found in common locations")
            status_details.setText(f"FAIL Not found: {error_msg}")
            status_details.setStyleSheet("color: #6c757d; font-size: 10px; margin-left: 85px;")

        # Show status details
        status_details.show()

    def on_tool_path_changed(self, tool_key: str, path: str) -> None:
        """Handle manual tool path changes.

        Args:
            tool_key: The unique identifier for the tool.
            path: The new tool path entered by the user.

        """
        if not path.strip():
            return

        # Validate the manually entered path
        if hasattr(self, "tool_discovery"):
            try:
                self.tool_discovery.health_check_tool(tool_key)

                # Update manual override in tool discovery
                self.tool_discovery.set_manual_override(tool_key, path)

                # Build tool info from validated path
                tool_info = {"available": os.path.exists(path), "path": path}
                self.update_tool_status(tool_key, tool_info)

            except Exception as e:
                self.log_message(f"Failed to validate path for {tool_key}: {e}", "warning")

    def reset_tool_path(self, tool_key: str) -> None:
        """Reset tool path to auto-discovered value.

        Args:
            tool_key: The unique identifier for the tool to reset.

        """
        if tool_key not in self.tool_widgets:
            return

        widgets = self.tool_widgets[tool_key]

        # Clear manual override
        if hasattr(self, "tool_discovery"):
            self.tool_discovery.clear_manual_override(tool_key)

        # Re-discover the tool
        try:
            tool_info = self.tool_discovery.discover_tool(
                tool_key,
                {
                    "executables": self.get_tool_executables(tool_key),
                    "search_strategy": "installation_based",
                    "required": False,
                },
            )

            if tool_info.get("available") and tool_info.get("path"):
                widgets["path_edit"].setText(tool_info["path"])
            else:
                widgets["path_edit"].clear()
            self.update_tool_status(tool_key, tool_info)
        except Exception as e:
            self.log_message(f"Failed to reset path for {tool_key}: {e}", "error")

    def get_tool_executables(self, tool_key: str) -> list[str]:
        """Get the list of possible executables for a tool.

        Args:
            tool_key: The unique identifier for the tool.

        Returns:
            list[str]: List of possible executable names for the given tool.

        """
        executables_map = {
            "ghidra": ["ghidra", "ghidraRun", "ghidraRun.bat"],
            "radare2": ["r2", "radare2"],
            "x64dbg": ["x64dbg", "x32dbg", "x96dbg"],
            "nasm": ["nasm", "nasm.exe"],
            "masm": ["ml", "ml.exe", "ml64", "ml64.exe"],
            "accesschk": ["accesschk", "accesschk.exe", "accesschk64.exe"],
        }
        return executables_map.get(tool_key, [tool_key])

    def browse_tool_path(self, line_edit: QLineEdit, title: str) -> None:
        """Browse for a tool executable path.

        Args:
            line_edit: The QLineEdit widget to update with the selected path.
            title: The title to show in the file browser dialog.

        """
        file_path, _ = QFileDialog.getOpenFileName(self, title, "", "All Files (*)")
        if file_path:
            line_edit.setText(file_path)

    def create_advanced_tab(self) -> QWidget:
        """Create advanced settings tab.

        Returns:
            QWidget: The advanced settings tab widget with logging, security, and network options.

        """
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Logging Settings
        logging_group = QGroupBox("Logging Settings")
        logging_layout = QVBoxLayout(logging_group)

        log_level_layout = QHBoxLayout()
        log_level_layout.addWidget(QLabel("Log Level:"))
        self.log_level_combo = QComboBox()
        self.log_level_combo.addItems(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
        log_level_value = self.settings.get("log_level", "INFO")
        if isinstance(log_level_value, str):
            self.log_level_combo.setCurrentText(log_level_value)
        log_level_layout.addWidget(self.log_level_combo)
        log_level_layout.addStretch()

        self.log_to_file_cb = QCheckBox("Log to File")
        log_to_file_value = self.settings.get("log_to_file", True)
        if isinstance(log_to_file_value, bool):
            self.log_to_file_cb.setChecked(log_to_file_value)

        log_file_layout = QHBoxLayout()
        log_file_layout.addWidget(QLabel("Log File:"))
        self.log_file_path = QLineEdit()
        log_file_path_value = self.settings.get("log_file_path", "intellicrack.log")
        if isinstance(log_file_path_value, str):
            self.log_file_path.setText(log_file_path_value)
        browse_log_btn = QPushButton("Browse")
        browse_log_btn.clicked.connect(lambda: self.browse_file(self.log_file_path, "Select Log File"))
        log_file_layout.addWidget(self.log_file_path)
        log_file_layout.addWidget(browse_log_btn)

        logging_layout.addLayout(log_level_layout)
        logging_layout.addWidget(self.log_to_file_cb)
        logging_layout.addLayout(log_file_layout)

        # Security Settings
        security_group = QGroupBox("Security Settings")
        security_layout = QVBoxLayout(security_group)

        self.safe_mode_cb = QCheckBox("Enable Safe Mode")
        safe_mode_value = self.settings.get("safe_mode", True)
        if isinstance(safe_mode_value, bool):
            self.safe_mode_cb.setChecked(safe_mode_value)

        self.confirm_dangerous_cb = QCheckBox("Confirm Dangerous Operations")
        confirm_dangerous_value = self.settings.get("confirm_dangerous", True)
        if isinstance(confirm_dangerous_value, bool):
            self.confirm_dangerous_cb.setChecked(confirm_dangerous_value)

        self.auto_backup_cb = QCheckBox("Auto Backup Before Modifications")
        auto_backup_value = self.settings.get("auto_backup", True)
        if isinstance(auto_backup_value, bool):
            self.auto_backup_cb.setChecked(auto_backup_value)

        security_layout.addWidget(self.safe_mode_cb)
        security_layout.addWidget(self.confirm_dangerous_cb)
        security_layout.addWidget(self.auto_backup_cb)

        # Network Settings
        network_group = QGroupBox("Network Settings")
        network_layout = QVBoxLayout(network_group)

        proxy_layout = QHBoxLayout()
        proxy_layout.addWidget(QLabel("Proxy:"))
        self.proxy_edit = QLineEdit()
        current_proxy = self.settings.get("proxy", "")
        if isinstance(current_proxy, str) and current_proxy:
            self.proxy_edit.setText(current_proxy)
        proxy_layout.addWidget(self.proxy_edit)

        timeout_layout = QHBoxLayout()
        timeout_layout.addWidget(QLabel("Network Timeout (seconds):"))
        self.network_timeout = QSpinBox()
        self.network_timeout.setRange(5, 300)
        network_timeout_value = self.settings.get("network_timeout", 30)
        if isinstance(network_timeout_value, int):
            self.network_timeout.setValue(network_timeout_value)
        timeout_layout.addWidget(self.network_timeout)
        timeout_layout.addStretch()

        network_layout.addLayout(proxy_layout)
        network_layout.addLayout(timeout_layout)

        # Developer Settings (keeping only functional ones)
        dev_group = QGroupBox("Developer Settings")
        dev_layout = QVBoxLayout(dev_group)

        self.debug_mode_cb = QCheckBox("Enable Debug Mode")
        debug_mode_value = self.settings.get("debug_mode", False)
        if isinstance(debug_mode_value, bool):
            self.debug_mode_cb.setChecked(debug_mode_value)
        dev_layout.addWidget(self.debug_mode_cb)

        layout.addWidget(logging_group)
        layout.addWidget(security_group)
        layout.addWidget(network_group)
        layout.addWidget(dev_group)
        layout.addStretch()

        return tab

    def create_preview_panel(self) -> QWidget:
        """Create the preview panel.

        Returns:
            QWidget: The preview panel widget displaying current settings.

        """
        panel = QWidget()
        layout = QVBoxLayout(panel)

        # Preview label
        preview_label = QLabel("Settings Preview")
        preview_label.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        layout.addWidget(preview_label)

        # Preview area
        self.preview_area = QTextEdit()
        self.preview_area.setReadOnly(True)
        self.preview_area.setFont(QFont("Consolas", 10))
        layout.addWidget(self.preview_area)

        # Update preview
        self.update_preview()

        return panel

    def update_preview(self) -> None:
        """Update the settings preview."""
        preview_text = "Current Settings:\n"
        preview_text += "=" * 40 + "\n\n"

        # Appearance settings
        preview_text += "Appearance:\n"
        preview_text += f"  Theme: {self.settings.get('theme', 'Dark')}\n"
        preview_text += f"  Accent Color: {self.settings.get('accent_color', '#0078d4')}\n"
        preview_text += f"  UI Font: {self.settings.get('ui_font', 'Segoe UI')} {self.settings.get('ui_font_size', 10)}pt\n"
        preview_text += f"  Console Font: {self.settings.get('console_font', 'Consolas')} {self.settings.get('console_font_size', 10)}pt\n"
        preview_text += f"  Icon Size: {self.settings.get('icon_size', 24)}px\n\n"

        # Analysis settings
        preview_text += "Analysis:\n"
        preview_text += f"  Auto Analysis: {self.settings.get('auto_analysis', True)}\n"
        preview_text += f"  Default Depth: {self.settings.get('analysis_depth', 'Standard')}\n"
        preview_text += f"  Timeout: {self.settings.get('analysis_timeout', 300)} seconds\n"
        preview_text += f"  AI Provider: {self.settings.get('ai_provider', 'OpenAI')}\n\n"

        # Performance settings
        preview_text += "Performance:\n"
        preview_text += f"  Cache Size: {self.settings.get('cache_size', 512)} MB\n"
        preview_text += f"  Memory Limit: {self.settings.get('memory_limit', 2048)} MB\n"
        preview_text += f"  Worker Threads: {self.settings.get('worker_threads', 4)}\n"
        preview_text += f"  GPU Acceleration: {self.settings.get('enable_gpu', False)}\n\n"

        # Security settings
        preview_text += "Security:\n"
        preview_text += f"  Safe Mode: {self.settings.get('safe_mode', True)}\n"
        preview_text += f"  Confirm Dangerous: {self.settings.get('confirm_dangerous', True)}\n"
        preview_text += f"  Auto Backup: {self.settings.get('auto_backup', True)}\n\n"

        self.preview_area.setText(preview_text)

    def load_settings(self) -> None:
        """Load settings from centralized configuration system."""
        # Initialize defaults in centralized config if not present
        default_settings = self.get_default_settings()

        # Check if UI settings exist in centralized config, if not, initialize them
        if not self.config.get("ui"):
            self.logger.info("Initializing UI settings in centralized config")
            for key, value in default_settings.items():
                self.config.set(f"ui.{key}", value, save=False)
            self.config.save()

        # Load settings from centralized config with type safety
        self.settings = {}
        for key in default_settings:
            value = self.config.get(f"ui.{key}", default_settings[key])
            # Ensure we don't store dictionary objects as settings values
            if isinstance(value, dict):
                self.logger.warning("Settings key %s returned dict, using default value", key)
                self.settings[key] = default_settings[key]
            else:
                self.settings[key] = value

        self.logger.info("Loaded settings from centralized configuration")

    def get_default_settings(self) -> dict[str, object]:
        """Get default settings.

        Returns:
            dict[str, object]: Dictionary of default settings with all configuration keys and values.

        """
        return {
            # Appearance
            "theme": "Light",
            "accent_color": "#0078d4",
            "window_opacity": 100,
            "ui_font": "Segoe UI",
            "ui_font_size": 10,
            "console_font": "Consolas",
            "console_font_size": 10,
            "icon_size": 24,
            "show_tooltips": True,
            "enable_animations": True,
            # Analysis
            "auto_analysis": True,
            "analysis_depth": "Standard",
            "analysis_timeout": 300,
            "ai_provider": "OpenAI",
            "ai_temperature": 0.7,
            "ai_max_tokens": 2000,
            "include_comments": True,
            "include_error_handling": True,
            "optimize_code": False,
            # Performance
            "cache_size": 512,
            "memory_limit": 2048,
            "auto_cleanup": True,
            "worker_threads": 4,
            "parallel_processing": True,
            "background_tasks": True,
            "enable_gpu": False,
            "gpu_device": "Auto",
            # Paths
            "ghidra_path": "",
            "radare2_path": "",
            "x64dbg_path": "",
            "output_directory": "",
            "reports_directory": "",
            "scripts_directory": "",
            # Advanced
            "log_level": "INFO",
            "log_to_file": True,
            "log_file_path": "intellicrack.log",
            "safe_mode": True,
            "confirm_dangerous": True,
            "auto_backup": True,
            "proxy": "",
            "network_timeout": 30,
            "debug_mode": False,
        }

    def save_settings(self) -> None:
        """Save current settings to centralized configuration system."""
        try:
            # Collect settings from UI
            self.collect_settings_from_ui()

            # Save to centralized config
            for key, value in self.settings.items():
                # Tool paths and directory paths should be saved at root level for tool discovery
                if key.endswith("_path") or key.endswith("_directory"):
                    self.config.set(key, value, save=False)
                else:
                    # Other UI settings go under ui prefix
                    self.config.set(f"ui.{key}", value, save=False)

            # Save config to disk
            self.config.save()

            QMessageBox.information(self, "Settings", "Settings saved successfully!")
            self.update_preview()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save settings: {e!s}")

    def collect_settings_from_ui(self) -> None:
        """Collect settings from UI elements.

        Iterates through all UI controls and updates the internal settings dictionary
        with current values from appearance, analysis, performance, and tool path widgets.

        """
        # Appearance settings
        if hasattr(self, "theme_combo"):
            self.settings["theme"] = self.theme_combo.currentText()
        if hasattr(self, "opacity_slider"):
            self.settings["window_opacity"] = self.opacity_slider.value()
        if hasattr(self, "ui_font_combo"):
            self.settings["ui_font"] = self.ui_font_combo.currentFont().family()
            self.settings["ui_font_size"] = self.ui_font_size.value()
        if hasattr(self, "console_font_combo"):
            self.settings["console_font"] = self.console_font_combo.currentFont().family()
            self.settings["console_font_size"] = self.console_font_size.value()

        # Get icon size from combo
        if hasattr(self, "icon_size_combo"):
            size_text = self.icon_size_combo.currentText()
            if "16px" in size_text:
                self.settings["icon_size"] = 16
            elif "32px" in size_text:
                self.settings["icon_size"] = 32
            else:
                self.settings["icon_size"] = 24

        if hasattr(self, "show_tooltips_cb"):
            self.settings["show_tooltips"] = self.show_tooltips_cb.isChecked()
        if hasattr(self, "enable_animations_cb"):
            self.settings["enable_animations"] = self.enable_animations_cb.isChecked()

        # Analysis settings
        if hasattr(self, "auto_analysis_cb"):
            self.settings["auto_analysis"] = self.auto_analysis_cb.isChecked()
        if hasattr(self, "analysis_depth_combo"):
            self.settings["analysis_depth"] = self.analysis_depth_combo.currentText()
        if hasattr(self, "analysis_timeout"):
            self.settings["analysis_timeout"] = self.analysis_timeout.value()
        if hasattr(self, "ai_provider_combo"):
            self.settings["ai_provider"] = self.ai_provider_combo.currentText()
        if hasattr(self, "ai_temperature"):
            self.settings["ai_temperature"] = self.ai_temperature.value()
        if hasattr(self, "ai_max_tokens"):
            self.settings["ai_max_tokens"] = self.ai_max_tokens.value()

        # Tool path settings
        if hasattr(self, "tool_widgets"):
            for tool_key, widgets in self.tool_widgets.items():
                path_value = widgets["path_edit"].text().strip()
                self.settings[f"{tool_key}_path"] = path_value

        # Directory path settings
        for dir_key in ["output_directory", "reports_directory", "scripts_directory"]:
            if hasattr(self, dir_key):
                dir_widget = getattr(self, dir_key)
                self.settings[dir_key] = dir_widget.text().strip()

        # Developer settings
        if hasattr(self, "debug_mode_cb"):
            self.settings["debug_mode"] = self.debug_mode_cb.isChecked()

        # Continue collecting other settings...
        # (Performance, Advanced settings would be collected similarly)

    def reset_to_defaults(self) -> None:
        """Reset settings to defaults."""
        reply = QMessageBox.question(
            self,
            "Reset Settings",
            "Are you sure you want to reset all settings to defaults?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                # Reset to default settings
                self.settings = self.get_default_settings()

                # Save defaults to centralized config
                for key, value in self.settings.items():
                    self.config.set(f"ui.{key}", value, save=False)

                self.config.save()
                self.update_ui_from_settings()
                self.update_preview()
                QMessageBox.information(self, "Settings", "Settings reset to defaults!")

            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to reset settings: {e!s}")

    def update_ui_from_settings(self) -> None:
        """Update UI elements from current settings.

        Synchronizes all UI controls with the current settings values to reflect
        any changes made programmatically or through settings import/reset.

        """
        if hasattr(self, "theme_combo"):
            theme_value = self.settings.get("theme", "Dark")
            if isinstance(theme_value, str):
                self.theme_combo.setCurrentText(theme_value)
        if hasattr(self, "opacity_slider"):
            opacity_value = self.settings.get("window_opacity", 100)
            if isinstance(opacity_value, int):
                self.opacity_slider.setValue(opacity_value)

        # Update tool path widgets
        if hasattr(self, "tool_widgets"):
            for tool_key, widgets in self.tool_widgets.items():
                path_value = self.settings.get(f"{tool_key}_path", "")
                widgets["path_edit"].setText(path_value)

        # Update directory path widgets
        for dir_key in ["output_directory", "reports_directory", "scripts_directory"]:
            if hasattr(self, dir_key):
                dir_widget = getattr(self, dir_key)
                dir_widget.setText(self.settings.get(dir_key, ""))

        # Continue updating other UI elements...

    def export_settings(self) -> None:
        """Export settings to file."""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Settings",
            "intellicrack_settings.json",
            "JSON Files (*.json);;All Files (*)",
        )

        if file_path:
            try:
                self.collect_settings_from_ui()
                with open(file_path, "w") as f:
                    json.dump(self.settings, f, indent=4)
                QMessageBox.information(self, "Export", f"Settings exported to: {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export settings: {e!s}")

    def import_settings(self) -> None:
        """Import settings from file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Import Settings",
            "",
            "JSON Files (*.json);;All Files (*)",
        )

        if file_path:
            try:
                with open(file_path) as f:
                    imported_settings = json.load(f)

                # Update local settings
                self.settings.update(imported_settings)

                # Save to centralized config
                for key, value in self.settings.items():
                    self.config.set(f"ui.{key}", value, save=False)

                self.config.save()
                self.update_ui_from_settings()
                self.update_preview()
                QMessageBox.information(self, "Import", "Settings imported successfully!")

            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to import settings: {e!s}")

    def browse_path(self, line_edit: QLineEdit, title: str) -> None:
        """Browse for file path.

        Args:
            line_edit: The QLineEdit widget to update with the selected path.
            title: The title to show in the file browser dialog.

        """
        file_path, _ = QFileDialog.getOpenFileName(self, title, "", "All Files (*)")
        if file_path:
            line_edit.setText(file_path)

    def browse_directory(self, line_edit: QLineEdit, title: str) -> None:
        """Browse for directory.

        Args:
            line_edit: The QLineEdit widget to update with the selected directory path.
            title: The title to show in the directory browser dialog.

        """
        if dir_path := QFileDialog.getExistingDirectory(self, title):
            line_edit.setText(dir_path)

    def browse_file(self, line_edit: QLineEdit, title: str) -> None:
        """Browse for file.

        Args:
            line_edit: The QLineEdit widget to update with the selected file path.
            title: The title to show in the file browser dialog.

        """
        file_path, _ = QFileDialog.getSaveFileName(self, title, "", "All Files (*)")
        if file_path:
            line_edit.setText(file_path)

    def on_theme_changed(self, theme: str) -> None:
        """Handle theme change.

        Args:
            theme: The selected theme name (e.g., 'Dark', 'Light', 'Auto').

        """
        self.settings["theme"] = theme

        from intellicrack.ui.theme_manager import get_theme_manager

        theme_manager = get_theme_manager()
        theme_manager.set_theme(theme.lower())

        self.theme_changed.emit(theme)
        self.update_preview()

    def on_opacity_changed(self, value: int) -> None:
        """Handle opacity change.

        Args:
            value: The opacity value as an integer from 0 to 100.

        """
        self.opacity_label.setText(f"{value}%")
        self.settings["window_opacity"] = value
        if hasattr(self.shared_context, "main_window"):
            self.shared_context.main_window.setWindowOpacity(value / 100.0)

    def select_accent_color(self) -> None:
        """Select accent color and apply it dynamically to the application stylesheet."""
        color = QColorDialog.getColor(QColor(self.settings.get("accent_color", "#0078d4")), self)
        if color.isValid():
            color_hex = color.name()
            self.settings["accent_color"] = color_hex
            self.accent_color_btn.setStyleSheet(f"background-color: {color_hex}; color: white; border: 2px solid #888888;")
            self.apply_accent_color(color_hex)
            self.update_preview()

    def apply_accent_color(self, color_hex: str) -> None:
        """Apply accent color by re-applying the theme and replacing default accent colors.

        Args:
            color_hex: The new accent color in hexadecimal format (e.g., '#0078d4').

        """
        from intellicrack.handlers.pyqt6_handler import QApplication

        app_instance = QApplication.instance()
        if not isinstance(app_instance, QApplication):
            return

        from intellicrack.ui.theme_manager import get_theme_manager

        theme_manager = get_theme_manager()
        theme_manager._apply_theme()

        current_stylesheet = app_instance.styleSheet()

        default_accent_colors = ["#0078D4", "#0078d4"]

        updated_stylesheet = current_stylesheet
        for default_color in default_accent_colors:
            default_color_str = str(default_color)
            pattern = re.compile(re.escape(default_color_str), re.IGNORECASE)
            updated_stylesheet = pattern.sub(color_hex, updated_stylesheet)

        if self._current_accent_color and self._current_accent_color not in default_accent_colors:
            current_accent_str = str(self._current_accent_color)
            old_color_pattern = re.compile(re.escape(current_accent_str), re.IGNORECASE)
            updated_stylesheet = old_color_pattern.sub(color_hex, updated_stylesheet)

        app_instance.setStyleSheet(updated_stylesheet)
        self._current_accent_color = color_hex

        self.logger.info("Applied accent color: %s", color_hex)

    def on_ui_font_changed(self, font: QFont) -> None:
        """Handle UI font change.

        Args:
            font: The selected QFont object for the UI.

        """
        self.settings["ui_font"] = font.family()
        self.apply_ui_font()
        self.update_preview()

    def on_ui_font_size_changed(self, size: int) -> None:
        """Handle UI font size change.

        Args:
            size: The selected font size in points.

        """
        self.settings["ui_font_size"] = size
        self.apply_ui_font()
        self.update_preview()

    def apply_ui_font(self) -> None:
        """Apply UI font to the application."""
        from intellicrack.handlers.pyqt6_handler import QApplication

        app_instance = QApplication.instance()
        if not isinstance(app_instance, QApplication):
            return

        ui_font_value = self.settings.get("ui_font", "Segoe UI")
        ui_font_size_value = self.settings.get("ui_font_size", 10)

        ui_font_str = str(ui_font_value) if isinstance(ui_font_value, str) else "Segoe UI"
        ui_font_size_int = int(ui_font_size_value) if isinstance(ui_font_size_value, int) else 10

        font = QFont(ui_font_str, ui_font_size_int)
        app_instance.setFont(font)

    def on_console_font_changed(self, font: QFont) -> None:
        """Handle console font change.

        Args:
            font: The selected QFont object for the console.

        """
        self.settings["console_font"] = font.family()
        self.apply_console_font()
        self.update_preview()

    def on_console_font_size_changed(self, size: int) -> None:
        """Handle console font size change.

        Args:
            size: The selected font size in points.

        """
        self.settings["console_font_size"] = size
        self.apply_console_font()
        self.update_preview()

    def apply_console_font(self) -> None:
        """Apply console font to all console/terminal widgets in the application."""
        from intellicrack.handlers.pyqt6_handler import QApplication, QPlainTextEdit, QTextEdit

        app_instance = QApplication.instance()
        if not isinstance(app_instance, QApplication):
            return

        console_font_value = self.settings.get("console_font", "Consolas")
        console_font_size_value = self.settings.get("console_font_size", 10)

        console_font_str = str(console_font_value) if isinstance(console_font_value, str) else "Consolas"
        console_font_size_int = int(console_font_size_value) if isinstance(console_font_size_value, int) else 10

        console_font = QFont(console_font_str, console_font_size_int)
        console_font.setFixedPitch(True)

        widgets_updated = 0
        for widget in app_instance.allWidgets():
            if isinstance(widget, (QTextEdit, QPlainTextEdit)):
                widget_name = widget.objectName().lower()
                widget_class = widget.__class__.__name__.lower()

                is_console = any(
                    keyword in widget_name or keyword in widget_class
                    for keyword in [
                        "console",
                        "terminal",
                        "output",
                        "log",
                        "command",
                        "shell",
                        "script",
                    ]
                )

                if is_console or widget.font().fixedPitch():
                    widget.setFont(console_font)
                    widgets_updated += 1

        if widgets_updated > 0:
            self.logger.info("Applied console font to %d widgets", widgets_updated)

    def on_tooltips_toggled(self, state: int) -> None:
        """Handle tooltips toggle.

        Args:
            state: The checkbox state (0=unchecked, 1=partially checked, 2=checked).

        """
        enabled = state == 2
        self.settings["show_tooltips"] = enabled
        self.apply_tooltip_settings(enabled)
        self.update_preview()

    def apply_tooltip_settings(self, enabled: bool) -> None:
        """Apply tooltip settings to all widgets in the application.

        Args:
            enabled: Boolean indicating whether tooltips should be shown.
                    When False, stores current tooltips and clears them from all widgets.
                    When True, restores previously stored tooltips to all widgets.

        """
        from intellicrack.handlers.pyqt6_handler import QApplication

        app_instance = QApplication.instance()
        if not isinstance(app_instance, QApplication):
            return

        all_widgets = app_instance.allWidgets()

        if not enabled:
            for widget in all_widgets:
                if tooltip := widget.toolTip():
                    try:
                        self._original_tooltips[widget] = tooltip
                        widget.setToolTip("")
                    except (TypeError, RuntimeError):
                        pass
                widget.setToolTipDuration(0)
            self.logger.info("Tooltips disabled. Stored %d tooltips.", len(self._original_tooltips))
        else:
            restored_count = 0
            for widget in all_widgets:
                try:
                    if widget in self._original_tooltips:
                        widget.setToolTip(self._original_tooltips[widget])
                        restored_count += 1
                    widget.setToolTipDuration(-1)
                except (TypeError, RuntimeError):
                    pass
            self.logger.info("Tooltips enabled. Restored %d tooltips.", restored_count)

    def on_animations_toggled(self, state: int) -> None:
        """Handle animations toggle.

        Args:
            state: The checkbox state (0=unchecked, 1=partially checked, 2=checked).

        """
        enabled = state == 2
        self.settings["enable_animations"] = enabled
        self.apply_animation_settings(enabled)
        self.update_preview()

    def apply_animation_settings(self, enabled: bool) -> None:
        """Apply smooth animation settings to UI elements.

        Args:
            enabled: Boolean indicating whether smooth animations should be active.
                    When True, injects CSS transitions (0.2s ease-in-out) into the application stylesheet.
                    When False, disables all transitions by setting duration to 0s.

        """
        from intellicrack.handlers.pyqt6_handler import QApplication

        app_instance = QApplication.instance()
        if not isinstance(app_instance, QApplication):
            return

        current_stylesheet = app_instance.styleSheet()

        marker_disable = "/* Disable all animations - instant transitions */"
        marker_enable = "/* Enable smooth animations and transitions */"

        has_disable = marker_disable in current_stylesheet
        has_enable = marker_enable in current_stylesheet

        if enabled:
            if has_disable:
                start_idx = current_stylesheet.find(marker_disable)
                end_idx = current_stylesheet.find("}", start_idx)
                if end_idx != -1:
                    end_idx += 1
                    current_stylesheet = current_stylesheet[:start_idx] + current_stylesheet[end_idx:]

            if not has_enable:
                enable_animations = """
/* Enable smooth animations and transitions */
QPushButton, QComboBox, QCheckBox::indicator, QRadioButton::indicator,
QSlider::handle, QTabBar::tab {
    transition: all 0.2s ease-in-out;
}

QPushButton:hover, QComboBox:hover, QTabBar::tab:hover {
    transition: all 0.15s ease-in-out;
}
"""

                current_stylesheet += enable_animations

            self.logger.info("Smooth animations enabled")
        else:
            if has_enable:
                start_idx = current_stylesheet.find(marker_enable)
                end_idx = current_stylesheet.find("}", start_idx)
                if end_idx != -1:
                    end_idx = current_stylesheet.find("}", end_idx + 1) + 1
                    current_stylesheet = current_stylesheet[:start_idx] + current_stylesheet[end_idx:]

            if not has_disable:
                disable_animations = """
/* Disable all animations - instant transitions */
* {
    transition-duration: 0s !important;
    animation-duration: 0s !important;
}
"""

                current_stylesheet += disable_animations

            self.logger.info("Animations disabled")

        app_instance.setStyleSheet(current_stylesheet)

    def populate_ai_providers(self) -> None:
        """Populate AI provider dropdown with dynamically detected providers."""
        current_selection = (
            self.ai_provider_combo.currentText() if self.ai_provider_combo.count() > 0 else self.settings.get("ai_provider", "")
        )

        self.ai_provider_combo.clear()

        available_providers: list[str] = []

        try:
            from intellicrack.ai.model_discovery_service import get_model_discovery_service

            discovery_service = get_model_discovery_service()

            discovered_models = discovery_service.discover_all_models(force_refresh=True)

            available_providers.extend(provider_name for provider_name, models in discovered_models.items() if models)
        except Exception as e:
            self.logger.warning("Failed to discover AI providers dynamically: %s", e)

        if not available_providers:
            available_providers = ["OpenAI", "Anthropic", "Ollama", "LM Studio", "Local GGUF"]

        self.ai_provider_combo.addItems(available_providers)

        if isinstance(current_selection, str) and current_selection and current_selection in available_providers:
            self.ai_provider_combo.setCurrentText(current_selection)
        elif available_providers:
            self.ai_provider_combo.setCurrentIndex(0)

    def log_message(self, message: str, level: str = "info") -> None:
        """Log message to console or status.

        Args:
            message: The message text to log.
            level: The logging level ('info', 'warning', 'error', 'debug').

        """
        if hasattr(self.shared_context, "log_message"):
            self.shared_context.log_message(message, level)
        else:
            print(f"[{level.upper()}] {message}")
