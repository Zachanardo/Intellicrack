"""Preferences dialog for Intellicrack UI.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

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

from intellicrack.core.config_manager import get_config
from intellicrack.handlers.pyqt6_handler import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGroupBox,
    QLineEdit,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)

from .base_dialog import BaseDialog

"""Preferences dialog for Intellicrack settings."""

logger = logging.getLogger(__name__)


class PreferencesDialog(BaseDialog):
    """Dialog for managing application preferences."""

    preferences_changed = pyqtSignal()

    def __init__(self, parent=None) -> None:
        """Initialize the PreferencesDialog with default values."""
        super().__init__(parent, "Preferences")
        self.config = get_config()
        self.resize(600, 500)
        self.setup_content(self.content_widget.layout() or QVBoxLayout(self.content_widget))
        self.load_preferences()

        # Connect BaseDialog buttons to custom handlers
        self.button_box.button(self.button_box.StandardButton.Ok).clicked.disconnect()
        self.button_box.button(self.button_box.StandardButton.Ok).clicked.connect(self.accept_preferences)

        # Add Apply button
        self.apply_btn = self.button_box.addButton("Apply", self.button_box.ButtonRole.ApplyRole)
        self.apply_btn.clicked.connect(self.apply_preferences)

    def setup_content(self, layout) -> None:
        """Set up the preferences UI."""
        if not layout:
            layout = QVBoxLayout()
            self.content_widget.setLayout(layout)

        # Tab widget for different preference categories
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)

        # Add tabs
        self.tab_widget.addTab(self.create_general_tab(), "General")
        self.tab_widget.addTab(self.create_execution_tab(), "Script Execution")
        self.tab_widget.addTab(self.create_security_tab(), "Security")
        self.tab_widget.addTab(self.create_ai_tab(), "AI Settings")
        self.tab_widget.addTab(self.create_hex_viewer_tab(), "Hex Viewer")

    def create_general_tab(self):
        """Create the general preferences tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Theme settings
        theme_group = QGroupBox("Appearance")
        theme_layout = QFormLayout()

        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Dark", "Light", "System"])
        theme_layout.addRow("Theme:", self.theme_combo)

        theme_group.setLayout(theme_layout)
        layout.addWidget(theme_group)

        # File handling
        file_group = QGroupBox("File Handling")
        file_layout = QFormLayout()

        self.auto_save_checkbox = QCheckBox("Auto-save scripts before execution")
        file_layout.addRow(self.auto_save_checkbox)

        self.backup_checkbox = QCheckBox("Create backups before patching")
        file_layout.addRow(self.backup_checkbox)

        file_group.setLayout(file_layout)
        layout.addWidget(file_group)

        layout.addStretch()
        return widget

    def create_execution_tab(self):
        """Create the script execution preferences tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # QEMU Testing settings
        qemu_group = QGroupBox("QEMU Testing")
        qemu_layout = QFormLayout()

        self.qemu_preference_combo = QComboBox()
        self.qemu_preference_combo.addItems(
            [
                "Always ask",
                "Always test in QEMU first",
                "Never test in QEMU",
            ],
        )
        qemu_layout.addRow("QEMU testing preference:", self.qemu_preference_combo)

        self.qemu_timeout_spin = QSpinBox()
        self.qemu_timeout_spin.setRange(10, 300)
        self.qemu_timeout_spin.setSuffix(" seconds")
        self.qemu_timeout_spin.setValue(60)
        qemu_layout.addRow("QEMU test timeout:", self.qemu_timeout_spin)

        self.qemu_memory_spin = QSpinBox()
        self.qemu_memory_spin.setRange(512, 8192)
        self.qemu_memory_spin.setSuffix(" MB")
        self.qemu_memory_spin.setValue(2048)
        self.qemu_memory_spin.setSingleStep(512)
        qemu_layout.addRow("QEMU memory allocation:", self.qemu_memory_spin)

        qemu_group.setLayout(qemu_layout)
        layout.addWidget(qemu_group)

        # Script execution settings
        exec_group = QGroupBox("Script Execution")
        exec_layout = QFormLayout()

        self.script_timeout_spin = QSpinBox()
        self.script_timeout_spin.setRange(5, 600)
        self.script_timeout_spin.setSuffix(" seconds")
        self.script_timeout_spin.setValue(120)
        exec_layout.addRow("Script execution timeout:", self.script_timeout_spin)

        self.capture_output_checkbox = QCheckBox("Capture script output")
        self.capture_output_checkbox.setChecked(True)
        exec_layout.addRow(self.capture_output_checkbox)

        self.verbose_output_checkbox = QCheckBox("Verbose output logging")
        exec_layout.addRow(self.verbose_output_checkbox)

        exec_group.setLayout(exec_layout)
        layout.addWidget(exec_group)

        layout.addStretch()
        return widget

    def create_security_tab(self):
        """Create the security preferences tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Security warnings
        warning_group = QGroupBox("Security Warnings")
        warning_layout = QFormLayout()

        self.warn_dangerous_checkbox = QCheckBox("Warn about potentially dangerous operations")
        self.warn_dangerous_checkbox.setChecked(True)
        warning_layout.addRow(self.warn_dangerous_checkbox)

        self.confirm_patches_checkbox = QCheckBox("Confirm before applying patches")
        self.confirm_patches_checkbox.setChecked(True)
        warning_layout.addRow(self.confirm_patches_checkbox)

        self.sandbox_default_checkbox = QCheckBox("Use sandboxing by default")
        warning_layout.addRow(self.sandbox_default_checkbox)

        warning_group.setLayout(warning_layout)
        layout.addWidget(warning_group)

        # Protection settings
        protection_group = QGroupBox("Protection Analysis")
        protection_layout = QFormLayout()

        self.auto_detect_checkbox = QCheckBox("Auto-detect protections on binary load")
        self.auto_detect_checkbox.setChecked(True)
        protection_layout.addRow(self.auto_detect_checkbox)

        self.ml_analysis_checkbox = QCheckBox("Use ML models for protection analysis")
        self.ml_analysis_checkbox.setChecked(True)
        protection_layout.addRow(self.ml_analysis_checkbox)

        protection_group.setLayout(protection_layout)
        layout.addWidget(protection_group)

        layout.addStretch()
        return widget

    def create_ai_tab(self):
        """Create the AI settings tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # AI Model settings
        model_group = QGroupBox("AI Model Settings")
        model_layout = QFormLayout()

        self.default_model_combo = QComboBox()
        self.default_model_combo.addItems(
            [
                "GPT-4",
                "GPT-3.5-turbo",
                "Claude",
                "Local Model",
            ],
        )
        model_layout.addRow("Default AI model:", self.default_model_combo)

        self.api_key_edit = QLineEdit()
        self.api_key_edit.setEchoMode(QLineEdit.Password)
        self.api_key_edit.setPlaceholderText("Enter API key...")
        model_layout.addRow("API Key:", self.api_key_edit)

        self.max_tokens_spin = QSpinBox()
        self.max_tokens_spin.setRange(100, 4000)
        self.max_tokens_spin.setValue(2000)
        model_layout.addRow("Max tokens:", self.max_tokens_spin)

        model_group.setLayout(model_layout)
        layout.addWidget(model_group)

        # AI behavior settings
        behavior_group = QGroupBox("AI Behavior")
        behavior_layout = QFormLayout()

        self.auto_refine_checkbox = QCheckBox("Auto-refine generated scripts")
        behavior_layout.addRow(self.auto_refine_checkbox)

        self.explain_scripts_checkbox = QCheckBox("Include explanations in generated scripts")
        self.explain_scripts_checkbox.setChecked(True)
        behavior_layout.addRow(self.explain_scripts_checkbox)

        behavior_group.setLayout(behavior_layout)
        layout.addWidget(behavior_group)

        layout.addStretch()
        return widget

    def create_hex_viewer_tab(self):
        """Create the Hex Viewer preferences tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Display settings
        display_group = QGroupBox("Display Settings")
        display_layout = QFormLayout()

        self.hex_bytes_per_row = QSpinBox()
        self.hex_bytes_per_row.setRange(8, 32)
        self.hex_bytes_per_row.setSingleStep(8)
        self.hex_bytes_per_row.setValue(self.config.get("hex_viewer.ui.bytes_per_row", 16))
        self.hex_bytes_per_row.valueChanged.connect(self.on_hex_viewer_setting_changed)
        display_layout.addRow("Bytes per row:", self.hex_bytes_per_row)

        self.hex_group_size = QComboBox()
        self.hex_group_size.addItems(["1", "2", "4", "8"])
        current_group_size = str(self.config.get("hex_viewer.ui.group_size", 1))
        self.hex_group_size.setCurrentText(current_group_size)
        self.hex_group_size.currentTextChanged.connect(self.on_hex_viewer_setting_changed)
        display_layout.addRow("Group size:", self.hex_group_size)

        self.hex_uppercase = QCheckBox("Use uppercase hex")
        self.hex_uppercase.setChecked(self.config.get("hex_viewer.ui.uppercase_hex", True))
        self.hex_uppercase.toggled.connect(self.on_hex_viewer_setting_changed)
        display_layout.addRow(self.hex_uppercase)

        self.hex_show_address = QCheckBox("Show address column")
        self.hex_show_address.setChecked(self.config.get("hex_viewer.ui.show_address", True))
        self.hex_show_address.toggled.connect(self.on_hex_viewer_setting_changed)
        display_layout.addRow(self.hex_show_address)

        self.hex_show_ascii = QCheckBox("Show ASCII column")
        self.hex_show_ascii.setChecked(self.config.get("hex_viewer.ui.show_ascii", True))
        self.hex_show_ascii.toggled.connect(self.on_hex_viewer_setting_changed)
        display_layout.addRow(self.hex_show_ascii)

        display_group.setLayout(display_layout)
        layout.addWidget(display_group)

        # Font settings
        font_group = QGroupBox("Font Settings")
        font_layout = QFormLayout()

        self.hex_font_family = QComboBox()
        self.hex_font_family.addItems(["Consolas", "Courier New", "Monaco", "Menlo", "DejaVu Sans Mono"])
        current_font = self.config.get("hex_viewer.ui.font_family", "Consolas")
        self.hex_font_family.setCurrentText(current_font)
        self.hex_font_family.currentTextChanged.connect(self.on_hex_viewer_setting_changed)
        font_layout.addRow("Font family:", self.hex_font_family)

        self.hex_font_size = QSpinBox()
        self.hex_font_size.setRange(8, 24)
        self.hex_font_size.setValue(self.config.get("hex_viewer.ui.font_size", 11))
        self.hex_font_size.valueChanged.connect(self.on_hex_viewer_setting_changed)
        font_layout.addRow("Font size:", self.hex_font_size)

        font_group.setLayout(font_layout)
        layout.addWidget(font_group)

        # Performance settings
        performance_group = QGroupBox("Performance Settings")
        performance_layout = QFormLayout()

        self.hex_max_memory = QSpinBox()
        self.hex_max_memory.setRange(50, 2000)
        self.hex_max_memory.setSuffix(" MB")
        self.hex_max_memory.setValue(self.config.get("hex_viewer.performance.max_memory_mb", 500))
        self.hex_max_memory.valueChanged.connect(self.on_hex_viewer_setting_changed)
        performance_layout.addRow("Max memory usage:", self.hex_max_memory)

        self.hex_cache_size = QSpinBox()
        self.hex_cache_size.setRange(10, 500)
        self.hex_cache_size.setSuffix(" MB")
        self.hex_cache_size.setValue(self.config.get("hex_viewer.performance.cache_size_mb", 100))
        self.hex_cache_size.valueChanged.connect(self.on_hex_viewer_setting_changed)
        performance_layout.addRow("Cache size:", self.hex_cache_size)

        self.hex_chunk_size = QSpinBox()
        self.hex_chunk_size.setRange(16, 512)
        self.hex_chunk_size.setSuffix(" KB")
        self.hex_chunk_size.setValue(self.config.get("hex_viewer.performance.chunk_size_kb", 64))
        self.hex_chunk_size.valueChanged.connect(self.on_hex_viewer_setting_changed)
        performance_layout.addRow("Chunk size:", self.hex_chunk_size)

        self.hex_lazy_load = QCheckBox("Enable lazy loading for large files")
        self.hex_lazy_load.setChecked(self.config.get("hex_viewer.performance.lazy_load", True))
        self.hex_lazy_load.toggled.connect(self.on_hex_viewer_setting_changed)
        performance_layout.addRow(self.hex_lazy_load)

        performance_group.setLayout(performance_layout)
        layout.addWidget(performance_group)

        # Search settings
        search_group = QGroupBox("Search Settings")
        search_layout = QFormLayout()

        self.hex_search_history = QSpinBox()
        self.hex_search_history.setRange(10, 200)
        self.hex_search_history.setValue(self.config.get("hex_viewer.search.history_max_entries", 50))
        self.hex_search_history.valueChanged.connect(self.on_hex_viewer_setting_changed)
        search_layout.addRow("Search history size:", self.hex_search_history)

        self.hex_search_chunk = QSpinBox()
        self.hex_search_chunk.setRange(64, 1024)
        self.hex_search_chunk.setSuffix(" KB")
        self.hex_search_chunk.setValue(self.config.get("hex_viewer.search.search_chunk_size_kb", 256))
        self.hex_search_chunk.valueChanged.connect(self.on_hex_viewer_setting_changed)
        search_layout.addRow("Search chunk size:", self.hex_search_chunk)

        self.hex_incremental_search = QCheckBox("Enable incremental search")
        self.hex_incremental_search.setChecked(self.config.get("hex_viewer.search.incremental_search", True))
        self.hex_incremental_search.toggled.connect(self.on_hex_viewer_setting_changed)
        search_layout.addRow(self.hex_incremental_search)

        self.hex_highlight_all = QCheckBox("Highlight all matches")
        self.hex_highlight_all.setChecked(self.config.get("hex_viewer.search.highlight_all_matches", True))
        self.hex_highlight_all.toggled.connect(self.on_hex_viewer_setting_changed)
        search_layout.addRow(self.hex_highlight_all)

        search_group.setLayout(search_layout)
        layout.addWidget(search_group)

        layout.addStretch()
        return widget

    def on_hex_viewer_setting_changed(self) -> None:
        """Handle immediate saving of hex viewer settings when auto-save is enabled."""
        if self.config.get("general_preferences.auto_save", True):
            self.save_hex_viewer_settings()

    def save_hex_viewer_settings(self) -> None:
        """Save hex viewer settings to configuration."""
        # Display settings
        self.config.set("hex_viewer.ui.bytes_per_row", self.hex_bytes_per_row.value())
        self.config.set("hex_viewer.ui.group_size", int(self.hex_group_size.currentText()))
        self.config.set("hex_viewer.ui.uppercase_hex", self.hex_uppercase.isChecked())
        self.config.set("hex_viewer.ui.show_address", self.hex_show_address.isChecked())
        self.config.set("hex_viewer.ui.show_ascii", self.hex_show_ascii.isChecked())

        # Font settings
        self.config.set("hex_viewer.ui.font_family", self.hex_font_family.currentText())
        self.config.set("hex_viewer.ui.font_size", self.hex_font_size.value())

        # Performance settings
        self.config.set("hex_viewer.performance.max_memory_mb", self.hex_max_memory.value())
        self.config.set("hex_viewer.performance.cache_size_mb", self.hex_cache_size.value())
        self.config.set("hex_viewer.performance.chunk_size_kb", self.hex_chunk_size.value())
        self.config.set("hex_viewer.performance.lazy_load", self.hex_lazy_load.isChecked())

        # Search settings
        self.config.set("hex_viewer.search.history_max_entries", self.hex_search_history.value())
        self.config.set("hex_viewer.search.search_chunk_size_kb", self.hex_search_chunk.value())
        self.config.set("hex_viewer.search.incremental_search", self.hex_incremental_search.isChecked())
        self.config.set("hex_viewer.search.highlight_all_matches", self.hex_highlight_all.isChecked())

        # Save to disk if auto-save is enabled
        if self.config.get("general_preferences.auto_save", True):
            self.config.save()
            self.preferences_changed.emit()

    def load_preferences(self) -> None:
        """Load preferences from central config."""
        # General
        self.theme_combo.setCurrentText(
            self.config.get("general_preferences.theme", "Dark"),
        )
        self.auto_save_checkbox.setChecked(
            self.config.get("general_preferences.auto_save", True),
        )
        self.backup_checkbox.setChecked(
            self.config.get("general_preferences.create_backups", True),
        )

        # Execution
        qemu_pref = self.config.get("qemu_testing.default_preference", "ask")
        if qemu_pref == "ask":
            self.qemu_preference_combo.setCurrentIndex(0)
        elif qemu_pref == "always":
            self.qemu_preference_combo.setCurrentIndex(1)
        else:  # never
            self.qemu_preference_combo.setCurrentIndex(2)

        self.qemu_timeout_spin.setValue(
            self.config.get("qemu_testing.qemu_timeout", 60),
        )
        self.qemu_memory_spin.setValue(
            self.config.get("qemu_testing.qemu_memory", 2048),
        )
        self.script_timeout_spin.setValue(
            self.config.get("general_preferences.execution_timeout", 120),
        )
        self.capture_output_checkbox.setChecked(
            self.config.get("analysis_settings.save_intermediate_results", True),
        )
        self.verbose_output_checkbox.setChecked(
            self.config.get("logging.debug_mode", False),
        )

        # Security
        self.warn_dangerous_checkbox.setChecked(
            self.config.get("general_preferences.security_checks_enabled", True),
        )
        self.confirm_patches_checkbox.setChecked(
            self.config.get("patching.verify_patches", True),
        )
        self.sandbox_default_checkbox.setChecked(
            self.config.get("security.sandbox_analysis", False),
        )
        self.auto_detect_checkbox.setChecked(
            self.config.get("general_preferences.auto_detect_protections", True),
        )
        self.ml_analysis_checkbox.setChecked(
            self.config.get("general_preferences.use_ml_analysis", True),
        )

        # AI
        self.default_model_combo.setCurrentText(
            self.config.get("ai_models.model_preferences.script_generation", "GPT-4"),
        )
        self.api_key_edit.setText(
            self.config.get("secrets.api_keys.openai", ""),
        )
        self.max_tokens_spin.setValue(
            self.config.get("ai_models.max_tokens", 2000),
        )
        self.auto_refine_checkbox.setChecked(
            self.config.get("general_preferences.ai_auto_refine", False),
        )
        self.explain_scripts_checkbox.setChecked(
            self.config.get("general_preferences.ai_explain_scripts", True),
        )

    def validate_preferences(self):
        """Validate preference values before saving.

        Returns:
            tuple: (bool, str) - (is_valid, error_message)

        """
        errors = []

        # Validate QEMU settings
        qemu_timeout = self.qemu_timeout_spin.value()
        if qemu_timeout < 10 or qemu_timeout > 300:
            errors.append("QEMU timeout must be between 10 and 300 seconds")

        qemu_memory = self.qemu_memory_spin.value()
        if qemu_memory < 512 or qemu_memory > 8192:
            errors.append("QEMU memory must be between 512 and 8192 MB")

        # Validate script timeout
        script_timeout = self.script_timeout_spin.value()
        if script_timeout < 10 or script_timeout > 600:
            errors.append("Script timeout must be between 10 and 600 seconds")

        # Validate AI settings
        max_tokens = self.max_tokens_spin.value()
        if max_tokens < 100 or max_tokens > 32000:
            errors.append("Max tokens must be between 100 and 32000")

        # Validate API key format if provided
        api_key = self.api_key_edit.text().strip()
        if api_key and not api_key.startswith(("sk-", "api-", "key-")):
            logger.warning("API key format may be invalid")

        # Check for conflicting settings
        if self.sandbox_default_checkbox.isChecked() and not self.warn_dangerous_checkbox.isChecked():
            logger.warning("Sandbox enabled but dangerous operation warnings disabled")

        if errors:
            return False, "\n".join(errors)
        return True, ""

    def save_preferences(self) -> bool:
        """Save preferences to central config."""
        # Validate preferences first
        is_valid, error_msg = self.validate_preferences()
        if not is_valid:
            from intellicrack.handlers.pyqt6_handler import QMessageBox

            QMessageBox.warning(self, "Validation Error", f"Invalid preferences:\n{error_msg}")
            return False

        # General
        self.config.set("general_preferences.theme", self.theme_combo.currentText())
        self.config.set("general_preferences.auto_save", self.auto_save_checkbox.isChecked())
        self.config.set("general_preferences.create_backups", self.backup_checkbox.isChecked())

        # Execution
        qemu_index = self.qemu_preference_combo.currentIndex()
        if qemu_index == 0:
            qemu_pref = "ask"
        elif qemu_index == 1:
            qemu_pref = "always"
        else:
            qemu_pref = "never"
        self.config.set("qemu_testing.default_preference", qemu_pref)

        self.config.set("qemu_testing.qemu_timeout", self.qemu_timeout_spin.value())
        self.config.set("qemu_testing.qemu_memory", self.qemu_memory_spin.value())
        self.config.set("general_preferences.execution_timeout", self.script_timeout_spin.value())
        self.config.set("analysis_settings.save_intermediate_results", self.capture_output_checkbox.isChecked())
        self.config.set("logging.debug_mode", self.verbose_output_checkbox.isChecked())

        # Security
        self.config.set("general_preferences.security_checks_enabled", self.warn_dangerous_checkbox.isChecked())
        self.config.set("patching.verify_patches", self.confirm_patches_checkbox.isChecked())
        self.config.set("security.sandbox_analysis", self.sandbox_default_checkbox.isChecked())
        self.config.set("general_preferences.auto_detect_protections", self.auto_detect_checkbox.isChecked())
        self.config.set("general_preferences.use_ml_analysis", self.ml_analysis_checkbox.isChecked())

        # AI
        self.config.set("ai_models.model_preferences.script_generation", self.default_model_combo.currentText())
        self.config.set("secrets.api_keys.openai", self.api_key_edit.text())
        self.config.set("ai_models.max_tokens", self.max_tokens_spin.value())
        self.config.set("general_preferences.ai_auto_refine", self.auto_refine_checkbox.isChecked())
        self.config.set("general_preferences.ai_explain_scripts", self.explain_scripts_checkbox.isChecked())

        # Hex Viewer settings
        self.save_hex_viewer_settings()

        # Save config to disk
        self.config.save()

        # Emit signal
        self.preferences_changed.emit()
        return True

    def apply_preferences(self) -> None:
        """Apply preferences without closing dialog."""
        result = self.save_preferences()
        if result is False:
            # Validation failed, save_preferences already showed error dialog
            return
        # Successfully saved preferences

    def accept_preferences(self) -> None:
        """Save preferences and close dialog."""
        result = self.save_preferences()
        if result is False:
            # Validation failed, don't close dialog
            return
        # Successfully saved, close dialog
        self.accept()


if __name__ == "__main__":
    import sys

    from intellicrack.handlers.pyqt6_handler import QApplication

    app = QApplication(sys.argv)
    dialog = PreferencesDialog()
    dialog.show()
    sys.exit(app.exec())
