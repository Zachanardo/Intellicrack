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
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)

from .base_tab import BaseTab


class SettingsTab(BaseTab):
    """Settings tab for configuration management."""

    settings_changed = pyqtSignal(str, object)
    theme_changed = pyqtSignal(str)

    def __init__(self, shared_context=None, parent=None):
        """Initialize settings tab with application configuration and preferences."""
        super().__init__(shared_context, parent)
        self.logger = logging.getLogger(__name__ + ".SettingsTab")

    def setup_content(self):
        """Setup the settings tab content."""
        layout = QHBoxLayout(self)

        # Left panel - Settings categories
        left_panel = self.create_settings_panel()

        # Right panel - Settings details and preview
        right_panel = self.create_preview_panel()

        # Add panels with splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setStretchFactor(0, 60)
        splitter.setStretchFactor(1, 40)

        layout.addWidget(splitter)
        self.is_loaded = True

    def create_settings_panel(self):
        """Create the settings control panel."""
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
        save_btn.clicked.connect(self.save_settings)
        save_btn.setStyleSheet("font-weight: bold; color: green;")

        reset_btn = QPushButton("Reset to Defaults")
        reset_btn.clicked.connect(self.reset_to_defaults)
        reset_btn.setStyleSheet("color: red;")

        export_btn = QPushButton("Export Settings")
        export_btn.clicked.connect(self.export_settings)

        import_btn = QPushButton("Import Settings")
        import_btn.clicked.connect(self.import_settings)

        controls_layout.addWidget(save_btn)
        controls_layout.addWidget(reset_btn)
        controls_layout.addWidget(export_btn)
        controls_layout.addWidget(import_btn)
        controls_layout.addStretch()

        layout.addLayout(controls_layout)
        return panel

    def create_appearance_tab(self):
        """Create appearance settings tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Theme Settings
        theme_group = QGroupBox("Theme Settings")
        theme_layout = QVBoxLayout(theme_group)

        theme_select_layout = QHBoxLayout()
        theme_select_layout.addWidget(QLabel("Theme:"))
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Dark", "Light", "Auto"])
        self.theme_combo.setCurrentText(self.settings.get("theme", "Light"))
        self.theme_combo.currentTextChanged.connect(self.on_theme_changed)
        theme_select_layout.addWidget(self.theme_combo)
        theme_select_layout.addStretch()

        # Color scheme
        color_layout = QHBoxLayout()
        color_layout.addWidget(QLabel("Accent Color:"))
        self.accent_color_btn = QPushButton("Select Color")
        self.accent_color_btn.clicked.connect(self.select_accent_color)
        self.accent_color_btn.setStyleSheet(
            f"background-color: {self.settings.get('accent_color', '#0078d4')};"
        )
        color_layout.addWidget(self.accent_color_btn)
        color_layout.addStretch()

        # Transparency
        transparency_layout = QHBoxLayout()
        transparency_layout.addWidget(QLabel("Window Opacity:"))
        self.opacity_slider = QSlider(Qt.Orientation.Horizontal)
        self.opacity_slider.setRange(50, 100)
        self.opacity_slider.setValue(self.settings.get("window_opacity", 100))
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
        ui_font_layout.addWidget(self.ui_font_combo)

        self.ui_font_size = QSpinBox()
        self.ui_font_size.setRange(8, 24)
        self.ui_font_size.setValue(self.settings.get("ui_font_size", 10))
        ui_font_layout.addWidget(self.ui_font_size)

        # Console Font
        console_font_layout = QHBoxLayout()
        console_font_layout.addWidget(QLabel("Console Font:"))
        self.console_font_combo = QFontComboBox()
        self.console_font_combo.setCurrentFont(QFont(self.settings.get("console_font", "Consolas")))
        console_font_layout.addWidget(self.console_font_combo)

        self.console_font_size = QSpinBox()
        self.console_font_size.setRange(8, 24)
        self.console_font_size.setValue(self.settings.get("console_font_size", 10))
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

        # Show tooltips
        self.show_tooltips_cb = QCheckBox("Show Tooltips")
        self.show_tooltips_cb.setChecked(self.settings.get("show_tooltips", True))

        # Animations
        self.enable_animations_cb = QCheckBox("Enable Animations")
        self.enable_animations_cb.setChecked(self.settings.get("enable_animations", True))

        icon_layout.addLayout(icon_size_layout)
        icon_layout.addWidget(self.show_tooltips_cb)
        icon_layout.addWidget(self.enable_animations_cb)

        layout.addWidget(theme_group)
        layout.addWidget(font_group)
        layout.addWidget(icon_group)
        layout.addStretch()

        return tab

    def create_analysis_tab(self):
        """Create analysis settings tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Default Analysis Settings
        analysis_group = QGroupBox("Default Analysis Settings")
        analysis_layout = QVBoxLayout(analysis_group)

        # Auto-analysis
        self.auto_analysis_cb = QCheckBox("Enable Auto-Analysis")
        self.auto_analysis_cb.setChecked(self.settings.get("auto_analysis", True))

        # Analysis depth
        depth_layout = QHBoxLayout()
        depth_layout.addWidget(QLabel("Default Analysis Depth:"))
        self.analysis_depth_combo = QComboBox()
        self.analysis_depth_combo.addItems(["Quick", "Standard", "Deep", "Comprehensive"])
        self.analysis_depth_combo.setCurrentText(self.settings.get("analysis_depth", "Standard"))
        depth_layout.addWidget(self.analysis_depth_combo)
        depth_layout.addStretch()

        # Timeout settings
        timeout_layout = QHBoxLayout()
        timeout_layout.addWidget(QLabel("Analysis Timeout (seconds):"))
        self.analysis_timeout = QSpinBox()
        self.analysis_timeout.setRange(10, 3600)
        self.analysis_timeout.setValue(self.settings.get("analysis_timeout", 300))
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
        self.ai_provider_combo.addItems(["OpenAI", "Anthropic", "Local Ollama", "Google Gemini"])
        self.ai_provider_combo.setCurrentText(self.settings.get("ai_provider", "OpenAI"))
        provider_layout.addWidget(self.ai_provider_combo)
        provider_layout.addStretch()

        # AI temperature
        temp_layout = QHBoxLayout()
        temp_layout.addWidget(QLabel("AI Temperature:"))
        self.ai_temperature = QDoubleSpinBox()
        self.ai_temperature.setRange(0.0, 2.0)
        self.ai_temperature.setSingleStep(0.1)
        self.ai_temperature.setValue(self.settings.get("ai_temperature", 0.7))
        temp_layout.addWidget(self.ai_temperature)
        temp_layout.addStretch()

        # Max tokens
        tokens_layout = QHBoxLayout()
        tokens_layout.addWidget(QLabel("Max Tokens:"))
        self.ai_max_tokens = QSpinBox()
        self.ai_max_tokens.setRange(100, 8000)
        self.ai_max_tokens.setValue(self.settings.get("ai_max_tokens", 2000))
        tokens_layout.addWidget(self.ai_max_tokens)
        tokens_layout.addStretch()

        ai_layout.addLayout(provider_layout)
        ai_layout.addLayout(temp_layout)
        ai_layout.addLayout(tokens_layout)

        # Script Generation Settings
        script_group = QGroupBox("Script Generation Settings")
        script_layout = QVBoxLayout(script_group)

        # Include comments
        self.include_comments_cb = QCheckBox("Include Comments in Generated Scripts")
        self.include_comments_cb.setChecked(self.settings.get("include_comments", True))

        # Include error handling
        self.include_error_handling_cb = QCheckBox("Include Error Handling")
        self.include_error_handling_cb.setChecked(self.settings.get("include_error_handling", True))

        # Optimize code
        self.optimize_code_cb = QCheckBox("Optimize Generated Code")
        self.optimize_code_cb.setChecked(self.settings.get("optimize_code", False))

        script_layout.addWidget(self.include_comments_cb)
        script_layout.addWidget(self.include_error_handling_cb)
        script_layout.addWidget(self.optimize_code_cb)

        layout.addWidget(analysis_group)
        layout.addWidget(ai_group)
        layout.addWidget(script_group)
        layout.addStretch()

        return tab

    def create_performance_tab(self):
        """Create performance settings tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Memory Settings
        memory_group = QGroupBox("Memory Settings")
        memory_layout = QVBoxLayout(memory_group)

        # Cache size
        cache_layout = QHBoxLayout()
        cache_layout.addWidget(QLabel("Cache Size (MB):"))
        self.cache_size = QSpinBox()
        self.cache_size.setRange(100, 8192)
        self.cache_size.setValue(self.settings.get("cache_size", 512))
        cache_layout.addWidget(self.cache_size)
        cache_layout.addStretch()

        # Memory limit
        memory_limit_layout = QHBoxLayout()
        memory_limit_layout.addWidget(QLabel("Memory Limit (MB):"))
        self.memory_limit = QSpinBox()
        self.memory_limit.setRange(512, 16384)
        self.memory_limit.setValue(self.settings.get("memory_limit", 2048))
        memory_limit_layout.addWidget(self.memory_limit)
        memory_limit_layout.addStretch()

        # Auto cleanup
        self.auto_cleanup_cb = QCheckBox("Auto Cleanup Memory")
        self.auto_cleanup_cb.setChecked(self.settings.get("auto_cleanup", True))

        memory_layout.addLayout(cache_layout)
        memory_layout.addLayout(memory_limit_layout)
        memory_layout.addWidget(self.auto_cleanup_cb)

        # Threading Settings
        threading_group = QGroupBox("Threading Settings")
        threading_layout = QVBoxLayout(threading_group)

        # Worker threads
        threads_layout = QHBoxLayout()
        threads_layout.addWidget(QLabel("Worker Threads:"))
        self.worker_threads = QSpinBox()
        self.worker_threads.setRange(1, 16)
        self.worker_threads.setValue(self.settings.get("worker_threads", 4))
        threads_layout.addWidget(self.worker_threads)
        threads_layout.addStretch()

        # Parallel processing
        self.parallel_processing_cb = QCheckBox("Enable Parallel Processing")
        self.parallel_processing_cb.setChecked(self.settings.get("parallel_processing", True))

        # Background tasks
        self.background_tasks_cb = QCheckBox("Enable Background Tasks")
        self.background_tasks_cb.setChecked(self.settings.get("background_tasks", True))

        threading_layout.addLayout(threads_layout)
        threading_layout.addWidget(self.parallel_processing_cb)
        threading_layout.addWidget(self.background_tasks_cb)

        # GPU Acceleration
        gpu_group = QGroupBox("GPU Acceleration")
        gpu_layout = QVBoxLayout(gpu_group)

        # Enable GPU
        self.enable_gpu_cb = QCheckBox("Enable GPU Acceleration")
        self.enable_gpu_cb.setChecked(self.settings.get("enable_gpu", False))

        # GPU device
        gpu_device_layout = QHBoxLayout()
        gpu_device_layout.addWidget(QLabel("GPU Device:"))
        self.gpu_device_combo = QComboBox()
        self.gpu_device_combo.addItems(["Auto", "CUDA", "OpenCL", "DirectML"])
        self.gpu_device_combo.setCurrentText(self.settings.get("gpu_device", "Auto"))
        gpu_device_layout.addWidget(self.gpu_device_combo)
        gpu_device_layout.addStretch()

        gpu_layout.addWidget(self.enable_gpu_cb)
        gpu_layout.addLayout(gpu_device_layout)

        layout.addWidget(memory_group)
        layout.addWidget(threading_group)
        layout.addWidget(gpu_group)
        layout.addStretch()

        return tab

    def create_paths_tab(self):
        """Create paths settings tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Tool Paths
        tools_group = QGroupBox("Tool Paths")
        tools_layout = QVBoxLayout(tools_group)

        # Ghidra path
        ghidra_layout = QHBoxLayout()
        ghidra_layout.addWidget(QLabel("Ghidra:"))
        self.ghidra_path = QLineEdit()
        self.ghidra_path.setText(self.settings.get("ghidra_path", ""))
        browse_ghidra_btn = QPushButton("Browse")
        browse_ghidra_btn.clicked.connect(
            lambda: self.browse_path(self.ghidra_path, "Select Ghidra Directory")
        )
        ghidra_layout.addWidget(self.ghidra_path)
        ghidra_layout.addWidget(browse_ghidra_btn)

        # Radare2 path
        radare2_layout = QHBoxLayout()
        radare2_layout.addWidget(QLabel("Radare2:"))
        self.radare2_path = QLineEdit()
        self.radare2_path.setText(self.settings.get("radare2_path", ""))
        browse_radare2_btn = QPushButton("Browse")
        browse_radare2_btn.clicked.connect(
            lambda: self.browse_path(self.radare2_path, "Select Radare2 Executable")
        )
        radare2_layout.addWidget(self.radare2_path)
        radare2_layout.addWidget(browse_radare2_btn)

        # IDA Pro path
        ida_layout = QHBoxLayout()
        ida_layout.addWidget(QLabel("IDA Pro:"))
        self.ida_path = QLineEdit()
        self.ida_path.setText(self.settings.get("ida_path", ""))
        browse_ida_btn = QPushButton("Browse")
        browse_ida_btn.clicked.connect(
            lambda: self.browse_path(self.ida_path, "Select IDA Pro Executable")
        )
        ida_layout.addWidget(self.ida_path)
        ida_layout.addWidget(browse_ida_btn)

        # x64dbg path
        x64dbg_layout = QHBoxLayout()
        x64dbg_layout.addWidget(QLabel("x64dbg:"))
        self.x64dbg_path = QLineEdit()
        self.x64dbg_path.setText(self.settings.get("x64dbg_path", ""))
        browse_x64dbg_btn = QPushButton("Browse")
        browse_x64dbg_btn.clicked.connect(
            lambda: self.browse_path(self.x64dbg_path, "Select x64dbg Executable")
        )
        x64dbg_layout.addWidget(self.x64dbg_path)
        x64dbg_layout.addWidget(browse_x64dbg_btn)

        tools_layout.addLayout(ghidra_layout)
        tools_layout.addLayout(radare2_layout)
        tools_layout.addLayout(ida_layout)
        tools_layout.addLayout(x64dbg_layout)

        # Output Paths
        output_group = QGroupBox("Output Paths")
        output_layout = QVBoxLayout(output_group)

        # Output directory
        output_dir_layout = QHBoxLayout()
        output_dir_layout.addWidget(QLabel("Output Directory:"))
        self.output_directory = QLineEdit()
        self.output_directory.setText(self.settings.get("output_directory", ""))
        browse_output_btn = QPushButton("Browse")
        browse_output_btn.clicked.connect(
            lambda: self.browse_directory(self.output_directory, "Select Output Directory")
        )
        output_dir_layout.addWidget(self.output_directory)
        output_dir_layout.addWidget(browse_output_btn)

        # Reports directory
        reports_dir_layout = QHBoxLayout()
        reports_dir_layout.addWidget(QLabel("Reports Directory:"))
        self.reports_directory = QLineEdit()
        self.reports_directory.setText(self.settings.get("reports_directory", ""))
        browse_reports_btn = QPushButton("Browse")
        browse_reports_btn.clicked.connect(
            lambda: self.browse_directory(self.reports_directory, "Select Reports Directory")
        )
        reports_dir_layout.addWidget(self.reports_directory)
        reports_dir_layout.addWidget(browse_reports_btn)

        # Scripts directory
        scripts_dir_layout = QHBoxLayout()
        scripts_dir_layout.addWidget(QLabel("Scripts Directory:"))
        self.scripts_directory = QLineEdit()
        self.scripts_directory.setText(self.settings.get("scripts_directory", ""))
        browse_scripts_btn = QPushButton("Browse")
        browse_scripts_btn.clicked.connect(
            lambda: self.browse_directory(self.scripts_directory, "Select Scripts Directory")
        )
        scripts_dir_layout.addWidget(self.scripts_directory)
        scripts_dir_layout.addWidget(browse_scripts_btn)

        output_layout.addLayout(output_dir_layout)
        output_layout.addLayout(reports_dir_layout)
        output_layout.addLayout(scripts_dir_layout)

        layout.addWidget(tools_group)
        layout.addWidget(output_group)
        layout.addStretch()

        return tab

    def create_advanced_tab(self):
        """Create advanced settings tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Logging Settings
        logging_group = QGroupBox("Logging Settings")
        logging_layout = QVBoxLayout(logging_group)

        # Log level
        log_level_layout = QHBoxLayout()
        log_level_layout.addWidget(QLabel("Log Level:"))
        self.log_level_combo = QComboBox()
        self.log_level_combo.addItems(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
        self.log_level_combo.setCurrentText(self.settings.get("log_level", "INFO"))
        log_level_layout.addWidget(self.log_level_combo)
        log_level_layout.addStretch()

        # Log to file
        self.log_to_file_cb = QCheckBox("Log to File")
        self.log_to_file_cb.setChecked(self.settings.get("log_to_file", True))

        # Log file path
        log_file_layout = QHBoxLayout()
        log_file_layout.addWidget(QLabel("Log File:"))
        self.log_file_path = QLineEdit()
        self.log_file_path.setText(self.settings.get("log_file_path", "intellicrack.log"))
        browse_log_btn = QPushButton("Browse")
        browse_log_btn.clicked.connect(
            lambda: self.browse_file(self.log_file_path, "Select Log File")
        )
        log_file_layout.addWidget(self.log_file_path)
        log_file_layout.addWidget(browse_log_btn)

        logging_layout.addLayout(log_level_layout)
        logging_layout.addWidget(self.log_to_file_cb)
        logging_layout.addLayout(log_file_layout)

        # Security Settings
        security_group = QGroupBox("Security Settings")
        security_layout = QVBoxLayout(security_group)

        # Safe mode
        self.safe_mode_cb = QCheckBox("Enable Safe Mode")
        self.safe_mode_cb.setChecked(self.settings.get("safe_mode", True))

        # Confirm dangerous operations
        self.confirm_dangerous_cb = QCheckBox("Confirm Dangerous Operations")
        self.confirm_dangerous_cb.setChecked(self.settings.get("confirm_dangerous", True))

        # Auto backup
        self.auto_backup_cb = QCheckBox("Auto Backup Before Modifications")
        self.auto_backup_cb.setChecked(self.settings.get("auto_backup", True))

        security_layout.addWidget(self.safe_mode_cb)
        security_layout.addWidget(self.confirm_dangerous_cb)
        security_layout.addWidget(self.auto_backup_cb)

        # Network Settings
        network_group = QGroupBox("Network Settings")
        network_layout = QVBoxLayout(network_group)

        # Proxy settings
        proxy_layout = QHBoxLayout()
        proxy_layout.addWidget(QLabel("Proxy:"))
        self.proxy_edit = QLineEdit()
        self.proxy_edit.setText(self.settings.get("proxy", ""))
        self.proxy_edit.setPlaceholderText("http://proxy.internal:8080")
        proxy_layout.addWidget(self.proxy_edit)

        # Timeout
        timeout_layout = QHBoxLayout()
        timeout_layout.addWidget(QLabel("Network Timeout (seconds):"))
        self.network_timeout = QSpinBox()
        self.network_timeout.setRange(5, 300)
        self.network_timeout.setValue(self.settings.get("network_timeout", 30))
        timeout_layout.addWidget(self.network_timeout)
        timeout_layout.addStretch()

        network_layout.addLayout(proxy_layout)
        network_layout.addLayout(timeout_layout)

        # Developer Settings
        dev_group = QGroupBox("Developer Settings")
        dev_layout = QVBoxLayout(dev_group)

        # Debug mode
        self.debug_mode_cb = QCheckBox("Enable Debug Mode")
        self.debug_mode_cb.setChecked(self.settings.get("debug_mode", False))

        # Show debug console
        self.show_debug_console_cb = QCheckBox("Show Debug Console")
        self.show_debug_console_cb.setChecked(self.settings.get("show_debug_console", False))

        # Enable experimental features
        self.experimental_features_cb = QCheckBox("Enable Experimental Features")
        self.experimental_features_cb.setChecked(self.settings.get("experimental_features", False))

        dev_layout.addWidget(self.debug_mode_cb)
        dev_layout.addWidget(self.show_debug_console_cb)
        dev_layout.addWidget(self.experimental_features_cb)

        layout.addWidget(logging_group)
        layout.addWidget(security_group)
        layout.addWidget(network_group)
        layout.addWidget(dev_group)
        layout.addStretch()

        return tab

    def create_preview_panel(self):
        """Create the preview panel."""
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

    def update_preview(self):
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

    def load_settings(self):
        """Load settings from file."""
        settings_file = os.path.join(
            os.path.dirname(__file__), "..", "..", "config", "settings.json"
        )

        try:
            if os.path.exists(settings_file):
                with open(settings_file) as f:
                    self.settings = json.load(f)
            else:
                self.settings = self.get_default_settings()
        except Exception as e:
            print(f"Error loading settings: {e}")
            self.settings = self.get_default_settings()

    def get_default_settings(self):
        """Get default settings."""
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
            "ida_path": "",
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
            "show_debug_console": False,
            "experimental_features": False,
        }

    def save_settings(self):
        """Save current settings."""
        # Collect settings from UI
        self.collect_settings_from_ui()

        # Save to file
        settings_file = os.path.join(
            os.path.dirname(__file__), "..", "..", "config", "settings.json"
        )
        os.makedirs(os.path.dirname(settings_file), exist_ok=True)

        try:
            with open(settings_file, "w") as f:
                json.dump(self.settings, f, indent=4)

            QMessageBox.information(self, "Settings", "Settings saved successfully!")
            self.update_preview()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save settings: {e!s}")

    def collect_settings_from_ui(self):
        """Collect settings from UI elements."""
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

        # Continue collecting other settings...
        # (Performance, Paths, Advanced settings would be collected similarly)

    def reset_to_defaults(self):
        """Reset settings to defaults."""
        reply = QMessageBox.question(
            self,
            "Reset Settings",
            "Are you sure you want to reset all settings to defaults?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )

        if reply == QMessageBox.StandardButton.Yes:
            self.settings = self.get_default_settings()
            self.update_ui_from_settings()
            self.update_preview()
            QMessageBox.information(self, "Settings", "Settings reset to defaults!")

    def update_ui_from_settings(self):
        """Update UI elements from current settings."""
        # Update all UI elements to reflect current settings
        if hasattr(self, "theme_combo"):
            self.theme_combo.setCurrentText(self.settings.get("theme", "Dark"))
        if hasattr(self, "opacity_slider"):
            self.opacity_slider.setValue(self.settings.get("window_opacity", 100))
        # Continue updating other UI elements...

    def export_settings(self):
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

    def import_settings(self):
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

                self.settings.update(imported_settings)
                self.update_ui_from_settings()
                self.update_preview()
                QMessageBox.information(self, "Import", "Settings imported successfully!")

            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to import settings: {e!s}")

    def browse_path(self, line_edit, title):
        """Browse for file path."""
        file_path, _ = QFileDialog.getOpenFileName(self, title, "", "All Files (*)")
        if file_path:
            line_edit.setText(file_path)

    def browse_directory(self, line_edit, title):
        """Browse for directory."""
        dir_path = QFileDialog.getExistingDirectory(self, title)
        if dir_path:
            line_edit.setText(dir_path)

    def browse_file(self, line_edit, title):
        """Browse for file."""
        file_path, _ = QFileDialog.getSaveFileName(self, title, "", "All Files (*)")
        if file_path:
            line_edit.setText(file_path)

    def on_theme_changed(self, theme):
        """Handle theme change."""
        self.settings["theme"] = theme
        self.theme_changed.emit(theme)
        self.update_preview()

    def on_opacity_changed(self, value):
        """Handle opacity change."""
        self.opacity_label.setText(f"{value}%")
        self.settings["window_opacity"] = value
        if hasattr(self.shared_context, "main_window"):
            self.shared_context.main_window.setWindowOpacity(value / 100.0)

    def select_accent_color(self):
        """Select accent color."""
        color = QColorDialog.getColor(QColor(self.settings.get("accent_color", "#0078d4")), self)
        if color.isValid():
            color_hex = color.name()
            self.settings["accent_color"] = color_hex
            self.accent_color_btn.setStyleSheet(f"background-color: {color_hex};")
            self.update_preview()

    def log_message(self, message, level="info"):
        """Log message to console or status."""
        if hasattr(self.shared_context, "log_message"):
            self.shared_context.log_message(message, level)
        else:
            print(f"[{level.upper()}] {message}")
