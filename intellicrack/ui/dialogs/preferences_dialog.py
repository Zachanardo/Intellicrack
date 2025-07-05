"""Preferences dialog for Intellicrack settings."""

import logging

from PyQt5.QtCore import QSettings, pyqtSignal
from PyQt5.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

logger = logging.getLogger(__name__)


class PreferencesDialog(QDialog):
    """Dialog for managing application preferences."""

    preferences_changed = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.settings = QSettings("Intellicrack", "Preferences")
        self.setup_ui()
        self.load_preferences()

    def setup_ui(self):
        """Set up the preferences UI."""
        self.setWindowTitle("Preferences")
        self.setModal(True)
        self.resize(600, 500)

        layout = QVBoxLayout(self)

        # Tab widget for different preference categories
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)

        # Add tabs
        self.tab_widget.addTab(self.create_general_tab(), "General")
        self.tab_widget.addTab(self.create_execution_tab(), "Script Execution")
        self.tab_widget.addTab(self.create_security_tab(), "Security")
        self.tab_widget.addTab(self.create_ai_tab(), "AI Settings")

        # Buttons
        button_layout = QHBoxLayout()

        self.apply_btn = QPushButton("Apply")
        self.apply_btn.clicked.connect(self.apply_preferences)

        self.ok_btn = QPushButton("OK")
        self.ok_btn.clicked.connect(self.accept_preferences)
        self.ok_btn.setDefault(True)

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)

        button_layout.addStretch()
        button_layout.addWidget(self.apply_btn)
        button_layout.addWidget(self.ok_btn)
        button_layout.addWidget(self.cancel_btn)

        layout.addLayout(button_layout)

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
        self.qemu_preference_combo.addItems([
            "Always ask",
            "Always test in QEMU first",
            "Never test in QEMU"
        ])
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
        self.default_model_combo.addItems([
            "GPT-4", "GPT-3.5-turbo", "Claude", "Local Model"
        ])
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

    def load_preferences(self):
        """Load preferences from settings."""
        # General
        self.theme_combo.setCurrentText(
            self.settings.value("general/theme", "Dark")
        )
        self.auto_save_checkbox.setChecked(
            self.settings.value("general/auto_save", True, type=bool)
        )
        self.backup_checkbox.setChecked(
            self.settings.value("general/create_backups", True, type=bool)
        )

        # Execution
        qemu_pref = self.settings.value("execution/qemu_preference", "ask")
        if qemu_pref == "ask":
            self.qemu_preference_combo.setCurrentIndex(0)
        elif qemu_pref == "always":
            self.qemu_preference_combo.setCurrentIndex(1)
        else:  # never
            self.qemu_preference_combo.setCurrentIndex(2)

        self.qemu_timeout_spin.setValue(
            self.settings.value("execution/qemu_timeout", 60, type=int)
        )
        self.qemu_memory_spin.setValue(
            self.settings.value("execution/qemu_memory", 2048, type=int)
        )
        self.script_timeout_spin.setValue(
            self.settings.value("execution/script_timeout", 120, type=int)
        )
        self.capture_output_checkbox.setChecked(
            self.settings.value("execution/capture_output", True, type=bool)
        )
        self.verbose_output_checkbox.setChecked(
            self.settings.value("execution/verbose_output", False, type=bool)
        )

        # Security
        self.warn_dangerous_checkbox.setChecked(
            self.settings.value("security/warn_dangerous", True, type=bool)
        )
        self.confirm_patches_checkbox.setChecked(
            self.settings.value("security/confirm_patches", True, type=bool)
        )
        self.sandbox_default_checkbox.setChecked(
            self.settings.value("security/sandbox_default", False, type=bool)
        )
        self.auto_detect_checkbox.setChecked(
            self.settings.value("security/auto_detect_protections", True, type=bool)
        )
        self.ml_analysis_checkbox.setChecked(
            self.settings.value("security/use_ml_analysis", True, type=bool)
        )

        # AI
        self.default_model_combo.setCurrentText(
            self.settings.value("ai/default_model", "GPT-4")
        )
        self.api_key_edit.setText(
            self.settings.value("ai/api_key", "")
        )
        self.max_tokens_spin.setValue(
            self.settings.value("ai/max_tokens", 2000, type=int)
        )
        self.auto_refine_checkbox.setChecked(
            self.settings.value("ai/auto_refine", False, type=bool)
        )
        self.explain_scripts_checkbox.setChecked(
            self.settings.value("ai/explain_scripts", True, type=bool)
        )

    def save_preferences(self):
        """Save preferences to settings."""
        # General
        self.settings.setValue("general/theme", self.theme_combo.currentText())
        self.settings.setValue("general/auto_save", self.auto_save_checkbox.isChecked())
        self.settings.setValue("general/create_backups", self.backup_checkbox.isChecked())

        # Execution
        qemu_index = self.qemu_preference_combo.currentIndex()
        if qemu_index == 0:
            qemu_pref = "ask"
        elif qemu_index == 1:
            qemu_pref = "always"
        else:
            qemu_pref = "never"
        self.settings.setValue("execution/qemu_preference", qemu_pref)

        self.settings.setValue("execution/qemu_timeout", self.qemu_timeout_spin.value())
        self.settings.setValue("execution/qemu_memory", self.qemu_memory_spin.value())
        self.settings.setValue("execution/script_timeout", self.script_timeout_spin.value())
        self.settings.setValue("execution/capture_output", self.capture_output_checkbox.isChecked())
        self.settings.setValue("execution/verbose_output", self.verbose_output_checkbox.isChecked())

        # Security
        self.settings.setValue("security/warn_dangerous", self.warn_dangerous_checkbox.isChecked())
        self.settings.setValue("security/confirm_patches", self.confirm_patches_checkbox.isChecked())
        self.settings.setValue("security/sandbox_default", self.sandbox_default_checkbox.isChecked())
        self.settings.setValue("security/auto_detect_protections", self.auto_detect_checkbox.isChecked())
        self.settings.setValue("security/use_ml_analysis", self.ml_analysis_checkbox.isChecked())

        # AI
        self.settings.setValue("ai/default_model", self.default_model_combo.currentText())
        self.settings.setValue("ai/api_key", self.api_key_edit.text())
        self.settings.setValue("ai/max_tokens", self.max_tokens_spin.value())
        self.settings.setValue("ai/auto_refine", self.auto_refine_checkbox.isChecked())
        self.settings.setValue("ai/explain_scripts", self.explain_scripts_checkbox.isChecked())

        # Emit signal
        self.preferences_changed.emit()

    def apply_preferences(self):
        """Apply preferences without closing dialog."""
        self.save_preferences()

    def accept_preferences(self):
        """Save preferences and close dialog."""
        self.save_preferences()
        self.accept()


if __name__ == "__main__":
    import sys

    from PyQt5.QtWidgets import QApplication

    app = QApplication(sys.argv)
    dialog = PreferencesDialog()
    dialog.show()
    sys.exit(app.exec_())
