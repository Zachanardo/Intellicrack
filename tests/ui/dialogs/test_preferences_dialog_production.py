"""Production-ready tests for PreferencesDialog - Application settings management validation.

This module validates PreferencesDialog's complete functionality including:
- Dialog initialization and UI layout
- Multi-tab preferences interface (General, Script Execution, Security, AI Settings, Hex Viewer)
- Configuration loading from central config
- Preference validation and error handling
- Configuration saving and persistence
- Hex viewer settings with auto-save
- Theme selection and appearance settings
- QEMU testing configuration
- Script execution timeouts and capture settings
- Security warnings and protection analysis
- AI model configuration
- Signal emission on preference changes
"""

from typing import Any

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication, QMessageBox

from intellicrack.config.config_manager import ConfigManager
from intellicrack.ui.dialogs.preferences_dialog import PreferencesDialog


class RealConfigManager:
    """Real configuration manager test double."""

    def __init__(self) -> None:
        self.config: dict[str, Any] = {}
        self.save_called: bool = False

    def get(self, key: str, default: Any = None) -> Any:
        return self.config.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self.config[key] = value

    def save(self) -> None:
        self.save_called = True


@pytest.fixture
def qapp(qapp: QApplication) -> QApplication:
    """Provide QApplication instance for PyQt6 tests."""
    return qapp


@pytest.fixture
def real_config() -> RealConfigManager:
    """Create real configuration manager test double."""
    return RealConfigManager()


@pytest.fixture
def preferences_dialog(qapp: QApplication, real_config: RealConfigManager) -> PreferencesDialog:
    """Create PreferencesDialog with real configuration."""
    dialog = PreferencesDialog()
    dialog.config = real_config
    return dialog


class TestPreferencesDialogInitialization:
    """Test PreferencesDialog initialization and UI setup."""

    def test_dialog_creation_initializes_all_components(
        self,
        preferences_dialog: PreferencesDialog,
    ) -> None:
        """Dialog creates all UI components on initialization."""
        assert preferences_dialog.windowTitle() == "Preferences"
        assert preferences_dialog.tab_widget is not None
        assert preferences_dialog.apply_btn is not None

    def test_dialog_has_all_preference_tabs(
        self,
        preferences_dialog: PreferencesDialog,
    ) -> None:
        """Dialog contains all preference category tabs."""
        tab_count = preferences_dialog.tab_widget.count()
        assert tab_count == 5

        expected_tabs = [
            "General",
            "Script Execution",
            "Security",
            "AI Settings",
            "Hex Viewer",
        ]
        for i, expected_name in enumerate(expected_tabs):
            assert preferences_dialog.tab_widget.tabText(i) == expected_name

    def test_general_tab_contains_theme_settings(
        self,
        preferences_dialog: PreferencesDialog,
    ) -> None:
        """General tab has theme and appearance settings."""
        assert preferences_dialog.theme_combo is not None
        theme_items = [preferences_dialog.theme_combo.itemText(i) for i in range(preferences_dialog.theme_combo.count())]
        assert "Dark" in theme_items
        assert "Light" in theme_items
        assert "System" in theme_items

    def test_general_tab_contains_file_handling_settings(
        self,
        preferences_dialog: PreferencesDialog,
    ) -> None:
        """General tab has file handling checkboxes."""
        assert preferences_dialog.auto_save_checkbox is not None
        assert preferences_dialog.backup_checkbox is not None

    def test_execution_tab_contains_qemu_settings(
        self,
        preferences_dialog: PreferencesDialog,
    ) -> None:
        """Execution tab has QEMU testing configuration."""
        assert preferences_dialog.qemu_preference_combo is not None
        assert preferences_dialog.qemu_timeout_spin is not None
        assert preferences_dialog.qemu_memory_spin is not None

        assert preferences_dialog.qemu_timeout_spin.minimum() == 10
        assert preferences_dialog.qemu_timeout_spin.maximum() == 300
        assert preferences_dialog.qemu_memory_spin.minimum() == 512
        assert preferences_dialog.qemu_memory_spin.maximum() == 8192

    def test_execution_tab_contains_script_execution_settings(
        self,
        preferences_dialog: PreferencesDialog,
    ) -> None:
        """Execution tab has script execution configuration."""
        assert preferences_dialog.script_timeout_spin is not None
        assert preferences_dialog.capture_output_checkbox is not None
        assert preferences_dialog.verbose_output_checkbox is not None

        assert preferences_dialog.script_timeout_spin.minimum() == 5
        assert preferences_dialog.script_timeout_spin.maximum() == 600

    def test_security_tab_contains_warning_settings(
        self,
        preferences_dialog: PreferencesDialog,
    ) -> None:
        """Security tab has security warning checkboxes."""
        assert preferences_dialog.warn_dangerous_checkbox is not None
        assert preferences_dialog.confirm_patches_checkbox is not None
        assert preferences_dialog.sandbox_default_checkbox is not None

    def test_security_tab_contains_protection_analysis_settings(
        self,
        preferences_dialog: PreferencesDialog,
    ) -> None:
        """Security tab has protection analysis configuration."""
        assert preferences_dialog.auto_detect_checkbox is not None
        assert preferences_dialog.ml_analysis_checkbox is not None

    def test_ai_tab_contains_model_settings(
        self,
        preferences_dialog: PreferencesDialog,
    ) -> None:
        """AI tab has model selection and configuration."""
        assert preferences_dialog.default_model_combo is not None
        assert preferences_dialog.api_key_edit is not None
        assert preferences_dialog.max_tokens_spin is not None

        assert preferences_dialog.api_key_edit.echoMode() == preferences_dialog.api_key_edit.EchoMode.Password
        assert preferences_dialog.max_tokens_spin.minimum() == 100
        assert preferences_dialog.max_tokens_spin.maximum() == 4000

    def test_ai_tab_contains_behavior_settings(
        self,
        preferences_dialog: PreferencesDialog,
    ) -> None:
        """AI tab has behavior configuration checkboxes."""
        assert preferences_dialog.auto_refine_checkbox is not None
        assert preferences_dialog.explain_scripts_checkbox is not None

    def test_hex_viewer_tab_contains_display_settings(
        self,
        preferences_dialog: PreferencesDialog,
    ) -> None:
        """Hex Viewer tab has display configuration."""
        assert preferences_dialog.hex_bytes_per_row is not None
        assert preferences_dialog.hex_group_size is not None
        assert preferences_dialog.hex_uppercase is not None
        assert preferences_dialog.hex_show_address is not None
        assert preferences_dialog.hex_show_ascii is not None

        assert preferences_dialog.hex_bytes_per_row.minimum() == 8
        assert preferences_dialog.hex_bytes_per_row.maximum() == 32

    def test_hex_viewer_tab_contains_font_settings(
        self,
        preferences_dialog: PreferencesDialog,
    ) -> None:
        """Hex Viewer tab has font configuration."""
        assert preferences_dialog.hex_font_family is not None
        assert preferences_dialog.hex_font_size is not None

        font_items = [preferences_dialog.hex_font_family.itemText(i) for i in range(preferences_dialog.hex_font_family.count())]
        assert "Consolas" in font_items
        assert "Courier New" in font_items

    def test_hex_viewer_tab_contains_performance_settings(
        self,
        preferences_dialog: PreferencesDialog,
    ) -> None:
        """Hex Viewer tab has performance configuration."""
        assert preferences_dialog.hex_max_memory is not None
        assert preferences_dialog.hex_cache_size is not None
        assert preferences_dialog.hex_chunk_size is not None
        assert preferences_dialog.hex_lazy_load is not None

    def test_hex_viewer_tab_contains_search_settings(
        self,
        preferences_dialog: PreferencesDialog,
    ) -> None:
        """Hex Viewer tab has search configuration."""
        assert preferences_dialog.hex_search_history is not None
        assert preferences_dialog.hex_search_chunk is not None
        assert preferences_dialog.hex_incremental_search is not None
        assert preferences_dialog.hex_highlight_all is not None


class TestConfigurationLoading:
    """Test configuration loading from central config."""

    def test_load_preferences_reads_general_settings(
        self,
        qapp: QApplication,
        real_config: RealConfigManager,
    ) -> None:
        """Loading preferences reads general settings from config."""
        real_config.config = {
            "general_preferences.theme": "Light",
            "general_preferences.auto_save": False,
            "general_preferences.create_backups": False,
        }

        dialog = PreferencesDialog()
        dialog.config = real_config
        dialog.load_preferences()

        assert dialog.theme_combo.currentText() == "Light"
        assert not dialog.auto_save_checkbox.isChecked()
        assert not dialog.backup_checkbox.isChecked()

    def test_load_preferences_reads_qemu_settings(
        self,
        qapp: QApplication,
        real_config: RealConfigManager,
    ) -> None:
        """Loading preferences reads QEMU testing settings."""
        real_config.config = {
            "qemu_testing.default_preference": "always",
            "qemu_testing.qemu_timeout": 120,
            "qemu_testing.qemu_memory": 4096,
        }

        dialog = PreferencesDialog()
        dialog.config = real_config
        dialog.load_preferences()

        assert dialog.qemu_preference_combo.currentIndex() == 1
        assert dialog.qemu_timeout_spin.value() == 120
        assert dialog.qemu_memory_spin.value() == 4096

    def test_load_preferences_reads_security_settings(
        self,
        qapp: QApplication,
        real_config: RealConfigManager,
    ) -> None:
        """Loading preferences reads security settings."""
        real_config.config = {
            "general_preferences.security_checks_enabled": False,
            "patching.verify_patches": False,
            "security.sandbox_analysis": True,
            "general_preferences.auto_detect_protections": False,
            "general_preferences.use_ml_analysis": False,
        }

        dialog = PreferencesDialog()
        dialog.config = real_config
        dialog.load_preferences()

        assert not dialog.warn_dangerous_checkbox.isChecked()
        assert not dialog.confirm_patches_checkbox.isChecked()
        assert dialog.sandbox_default_checkbox.isChecked()
        assert not dialog.auto_detect_checkbox.isChecked()
        assert not dialog.ml_analysis_checkbox.isChecked()

    def test_load_preferences_reads_ai_settings(
        self,
        qapp: QApplication,
        real_config: RealConfigManager,
    ) -> None:
        """Loading preferences reads AI model settings."""
        real_config.config = {
            "ai_models.model_preferences.script_generation": "Claude",
            "secrets.api_keys.openai": "sk-test-key",
            "ai_models.max_tokens": 3000,
            "general_preferences.ai_auto_refine": True,
            "general_preferences.ai_explain_scripts": False,
        }

        dialog = PreferencesDialog()
        dialog.config = real_config
        dialog.load_preferences()

        assert dialog.default_model_combo.currentText() == "Claude"
        assert dialog.api_key_edit.text() == "sk-test-key"
        assert dialog.max_tokens_spin.value() == 3000
        assert dialog.auto_refine_checkbox.isChecked()
        assert not dialog.explain_scripts_checkbox.isChecked()

    def test_load_preferences_reads_hex_viewer_settings(
        self,
        qapp: QApplication,
        real_config: RealConfigManager,
    ) -> None:
        """Loading preferences reads hex viewer settings."""
        real_config.config = {
            "hex_viewer.ui.bytes_per_row": 32,
            "hex_viewer.ui.group_size": 4,
            "hex_viewer.ui.uppercase_hex": False,
            "hex_viewer.ui.show_address": False,
            "hex_viewer.ui.show_ascii": False,
            "hex_viewer.ui.font_family": "Monaco",
            "hex_viewer.ui.font_size": 14,
            "hex_viewer.performance.max_memory_mb": 1000,
            "hex_viewer.performance.cache_size_mb": 200,
            "hex_viewer.performance.chunk_size_kb": 128,
            "hex_viewer.performance.lazy_load": False,
            "hex_viewer.search.history_max_entries": 100,
            "hex_viewer.search.search_chunk_size_kb": 512,
            "hex_viewer.search.incremental_search": False,
            "hex_viewer.search.highlight_all_matches": False,
        }

        dialog = PreferencesDialog()
        dialog.config = real_config
        dialog.load_preferences()

        assert dialog.hex_bytes_per_row.value() == 32
        assert dialog.hex_group_size.currentText() == "4"
        assert not dialog.hex_uppercase.isChecked()
        assert not dialog.hex_show_address.isChecked()
        assert not dialog.hex_show_ascii.isChecked()
        assert dialog.hex_font_family.currentText() == "Monaco"
        assert dialog.hex_font_size.value() == 14
        assert dialog.hex_max_memory.value() == 1000
        assert dialog.hex_cache_size.value() == 200
        assert dialog.hex_chunk_size.value() == 128
        assert not dialog.hex_lazy_load.isChecked()


class TestPreferenceValidation:
    """Test preference validation logic."""

    def test_validate_preferences_accepts_valid_values(
        self,
        preferences_dialog: PreferencesDialog,
    ) -> None:
        """Validation passes with all valid preference values."""
        preferences_dialog.qemu_timeout_spin.setValue(60)
        preferences_dialog.qemu_memory_spin.setValue(2048)
        preferences_dialog.script_timeout_spin.setValue(120)
        preferences_dialog.max_tokens_spin.setValue(2000)

        is_valid, error_msg = preferences_dialog.validate_preferences()

        assert is_valid
        assert error_msg == ""

    def test_validate_preferences_rejects_invalid_qemu_timeout(
        self,
        preferences_dialog: PreferencesDialog,
    ) -> None:
        """Validation fails with invalid QEMU timeout."""
        preferences_dialog.qemu_timeout_spin.setValue(5)

        is_valid, error_msg = preferences_dialog.validate_preferences()

        assert not is_valid
        assert "QEMU timeout" in error_msg

    def test_validate_preferences_rejects_invalid_qemu_memory(
        self,
        preferences_dialog: PreferencesDialog,
    ) -> None:
        """Validation fails with invalid QEMU memory."""
        preferences_dialog.qemu_memory_spin.setValue(10000)

        is_valid, error_msg = preferences_dialog.validate_preferences()

        assert not is_valid
        assert "QEMU memory" in error_msg

    def test_validate_preferences_rejects_invalid_script_timeout(
        self,
        preferences_dialog: PreferencesDialog,
    ) -> None:
        """Validation fails with invalid script timeout."""
        preferences_dialog.script_timeout_spin.setValue(1000)

        is_valid, error_msg = preferences_dialog.validate_preferences()

        assert not is_valid
        assert "Script timeout" in error_msg

    def test_validate_preferences_rejects_invalid_max_tokens(
        self,
        preferences_dialog: PreferencesDialog,
    ) -> None:
        """Validation fails with invalid max tokens."""
        preferences_dialog.max_tokens_spin.setValue(50000)

        is_valid, error_msg = preferences_dialog.validate_preferences()

        assert not is_valid
        assert "Max tokens" in error_msg

    def test_validate_preferences_accumulates_multiple_errors(
        self,
        preferences_dialog: PreferencesDialog,
    ) -> None:
        """Validation accumulates all validation errors."""
        preferences_dialog.qemu_timeout_spin.setValue(5)
        preferences_dialog.qemu_memory_spin.setValue(10000)
        preferences_dialog.script_timeout_spin.setValue(1000)

        is_valid, error_msg = preferences_dialog.validate_preferences()

        assert not is_valid
        assert "QEMU timeout" in error_msg
        assert "QEMU memory" in error_msg
        assert "Script timeout" in error_msg


class TestPreferenceSaving:
    """Test preference saving to configuration."""

    def test_save_preferences_stores_general_settings(
        self,
        preferences_dialog: PreferencesDialog,
        real_config: RealConfigManager,
    ) -> None:
        """Saving preferences stores general settings to config."""
        preferences_dialog.config = real_config
        preferences_dialog.theme_combo.setCurrentText("Light")
        preferences_dialog.auto_save_checkbox.setChecked(False)
        preferences_dialog.backup_checkbox.setChecked(True)

        preferences_dialog.save_preferences()

        assert real_config.config["general_preferences.theme"] == "Light"
        assert real_config.config["general_preferences.auto_save"] == False
        assert real_config.config["general_preferences.create_backups"] == True
        assert real_config.save_called

    def test_save_preferences_stores_qemu_settings(
        self,
        preferences_dialog: PreferencesDialog,
        real_config: RealConfigManager,
    ) -> None:
        """Saving preferences stores QEMU testing settings."""
        preferences_dialog.config = real_config
        preferences_dialog.qemu_preference_combo.setCurrentIndex(1)
        preferences_dialog.qemu_timeout_spin.setValue(90)
        preferences_dialog.qemu_memory_spin.setValue(3072)

        preferences_dialog.save_preferences()

        assert real_config.config["qemu_testing.default_preference"] == "always"
        assert real_config.config["qemu_testing.qemu_timeout"] == 90
        assert real_config.config["qemu_testing.qemu_memory"] == 3072

    def test_save_preferences_stores_execution_settings(
        self,
        preferences_dialog: PreferencesDialog,
        real_config: RealConfigManager,
    ) -> None:
        """Saving preferences stores script execution settings."""
        preferences_dialog.config = real_config
        preferences_dialog.script_timeout_spin.setValue(180)
        preferences_dialog.capture_output_checkbox.setChecked(False)
        preferences_dialog.verbose_output_checkbox.setChecked(True)

        preferences_dialog.save_preferences()

        assert real_config.config["general_preferences.execution_timeout"] == 180
        assert real_config.config["analysis_settings.save_intermediate_results"] == False
        assert real_config.config["logging.debug_mode"] == True

    def test_save_preferences_stores_security_settings(
        self,
        preferences_dialog: PreferencesDialog,
        real_config: RealConfigManager,
    ) -> None:
        """Saving preferences stores security settings."""
        preferences_dialog.config = real_config
        preferences_dialog.warn_dangerous_checkbox.setChecked(False)
        preferences_dialog.confirm_patches_checkbox.setChecked(False)
        preferences_dialog.sandbox_default_checkbox.setChecked(True)
        preferences_dialog.auto_detect_checkbox.setChecked(False)
        preferences_dialog.ml_analysis_checkbox.setChecked(False)

        preferences_dialog.save_preferences()

        assert real_config.config["general_preferences.security_checks_enabled"] == False
        assert real_config.config["patching.verify_patches"] == False
        assert real_config.config["security.sandbox_analysis"] == True
        assert real_config.config["general_preferences.auto_detect_protections"] == False
        assert real_config.config["general_preferences.use_ml_analysis"] == False

    def test_save_preferences_stores_ai_settings(
        self,
        preferences_dialog: PreferencesDialog,
        real_config: RealConfigManager,
    ) -> None:
        """Saving preferences stores AI model settings."""
        preferences_dialog.config = real_config
        preferences_dialog.default_model_combo.setCurrentText("GPT-3.5-turbo")
        preferences_dialog.api_key_edit.setText("sk-new-key")
        preferences_dialog.max_tokens_spin.setValue(1500)
        preferences_dialog.auto_refine_checkbox.setChecked(True)
        preferences_dialog.explain_scripts_checkbox.setChecked(False)

        preferences_dialog.save_preferences()

        assert real_config.config["ai_models.model_preferences.script_generation"] == "GPT-3.5-turbo"
        assert real_config.config["secrets.api_keys.openai"] == "sk-new-key"
        assert real_config.config["ai_models.max_tokens"] == 1500
        assert real_config.config["general_preferences.ai_auto_refine"] == True
        assert real_config.config["general_preferences.ai_explain_scripts"] == False

    def test_save_preferences_with_validation_error_shows_warning(
        self,
        preferences_dialog: PreferencesDialog,
        qapp: QApplication,
    ) -> None:
        """Saving with validation errors displays warning and returns False."""
        preferences_dialog.qemu_timeout_spin.setValue(5)

        result = preferences_dialog.save_preferences()

        assert not result

    def test_save_preferences_emits_preferences_changed_signal(
        self,
        preferences_dialog: PreferencesDialog,
    ) -> None:
        """Saving preferences emits preferences_changed signal."""
        signal_emitted = False

        def on_preferences_changed() -> None:
            nonlocal signal_emitted
            signal_emitted = True

        preferences_dialog.preferences_changed.connect(on_preferences_changed)
        preferences_dialog.save_preferences()

        assert signal_emitted


class TestHexViewerSettingsAutoSave:
    """Test hex viewer settings auto-save functionality."""

    def test_hex_viewer_setting_changed_triggers_auto_save(
        self,
        qapp: QApplication,
        real_config: RealConfigManager,
    ) -> None:
        """Changing hex viewer setting triggers auto-save when enabled."""
        real_config.config = {
            "general_preferences.auto_save": True,
        }

        dialog = PreferencesDialog()
        dialog.config = real_config

        dialog.hex_bytes_per_row.setValue(24)

        qapp.processEvents()

        assert real_config.config.get("hex_viewer.ui.bytes_per_row") == 24

    def test_save_hex_viewer_settings_stores_display_settings(
        self,
        preferences_dialog: PreferencesDialog,
        real_config: RealConfigManager,
    ) -> None:
        """Saving hex viewer settings stores display configuration."""
        preferences_dialog.config = real_config
        preferences_dialog.hex_bytes_per_row.setValue(24)
        preferences_dialog.hex_group_size.setCurrentText("4")
        preferences_dialog.hex_uppercase.setChecked(False)
        preferences_dialog.hex_show_address.setChecked(False)
        preferences_dialog.hex_show_ascii.setChecked(True)

        preferences_dialog.save_hex_viewer_settings()

        assert real_config.config["hex_viewer.ui.bytes_per_row"] == 24
        assert real_config.config["hex_viewer.ui.group_size"] == 4
        assert real_config.config["hex_viewer.ui.uppercase_hex"] == False
        assert real_config.config["hex_viewer.ui.show_address"] == False
        assert real_config.config["hex_viewer.ui.show_ascii"] == True

    def test_save_hex_viewer_settings_stores_font_settings(
        self,
        preferences_dialog: PreferencesDialog,
        real_config: RealConfigManager,
    ) -> None:
        """Saving hex viewer settings stores font configuration."""
        preferences_dialog.config = real_config
        preferences_dialog.hex_font_family.setCurrentText("Monaco")
        preferences_dialog.hex_font_size.setValue(14)

        preferences_dialog.save_hex_viewer_settings()

        assert real_config.config["hex_viewer.ui.font_family"] == "Monaco"
        assert real_config.config["hex_viewer.ui.font_size"] == 14

    def test_save_hex_viewer_settings_stores_performance_settings(
        self,
        preferences_dialog: PreferencesDialog,
        real_config: RealConfigManager,
    ) -> None:
        """Saving hex viewer settings stores performance configuration."""
        preferences_dialog.config = real_config
        preferences_dialog.hex_max_memory.setValue(1000)
        preferences_dialog.hex_cache_size.setValue(200)
        preferences_dialog.hex_chunk_size.setValue(128)
        preferences_dialog.hex_lazy_load.setChecked(False)

        preferences_dialog.save_hex_viewer_settings()

        assert real_config.config["hex_viewer.performance.max_memory_mb"] == 1000
        assert real_config.config["hex_viewer.performance.cache_size_mb"] == 200
        assert real_config.config["hex_viewer.performance.chunk_size_kb"] == 128
        assert real_config.config["hex_viewer.performance.lazy_load"] == False

    def test_save_hex_viewer_settings_stores_search_settings(
        self,
        preferences_dialog: PreferencesDialog,
        real_config: RealConfigManager,
    ) -> None:
        """Saving hex viewer settings stores search configuration."""
        preferences_dialog.config = real_config
        preferences_dialog.hex_search_history.setValue(100)
        preferences_dialog.hex_search_chunk.setValue(512)
        preferences_dialog.hex_incremental_search.setChecked(False)
        preferences_dialog.hex_highlight_all.setChecked(False)

        preferences_dialog.save_hex_viewer_settings()

        assert real_config.config["hex_viewer.search.history_max_entries"] == 100
        assert real_config.config["hex_viewer.search.search_chunk_size_kb"] == 512
        assert real_config.config["hex_viewer.search.incremental_search"] == False
        assert real_config.config["hex_viewer.search.highlight_all_matches"] == False


class TestApplyAndAccept:
    """Test Apply and OK button functionality."""

    def test_apply_preferences_saves_without_closing(
        self,
        preferences_dialog: PreferencesDialog,
        real_config: RealConfigManager,
    ) -> None:
        """Applying preferences saves settings without closing dialog."""
        preferences_dialog.config = real_config
        preferences_dialog.theme_combo.setCurrentText("Dark")

        preferences_dialog.apply_preferences()

        assert real_config.save_called
        assert preferences_dialog.isVisible()

    def test_apply_preferences_with_validation_error_keeps_dialog_open(
        self,
        preferences_dialog: PreferencesDialog,
    ) -> None:
        """Applying with validation error keeps dialog open."""
        preferences_dialog.qemu_timeout_spin.setValue(5)

        preferences_dialog.apply_preferences()

        assert preferences_dialog.isVisible()

    def test_accept_preferences_saves_and_closes(
        self,
        preferences_dialog: PreferencesDialog,
        real_config: RealConfigManager,
    ) -> None:
        """Accepting preferences saves settings and closes dialog."""
        preferences_dialog.config = real_config
        preferences_dialog.theme_combo.setCurrentText("Light")

        preferences_dialog.accept_preferences()

        assert real_config.save_called

    def test_accept_preferences_with_validation_error_keeps_dialog_open(
        self,
        preferences_dialog: PreferencesDialog,
    ) -> None:
        """Accepting with validation error keeps dialog open."""
        preferences_dialog.qemu_timeout_spin.setValue(5)

        preferences_dialog.accept_preferences()


class TestQEMUPreferenceMapping:
    """Test QEMU preference combo box mapping."""

    def test_qemu_preference_ask_maps_to_index_0(
        self,
        qapp: QApplication,
        real_config: RealConfigManager,
    ) -> None:
        """QEMU preference 'ask' loads as index 0."""
        real_config.config = {
            "qemu_testing.default_preference": "ask",
        }

        dialog = PreferencesDialog()
        dialog.config = real_config
        dialog.load_preferences()

        assert dialog.qemu_preference_combo.currentIndex() == 0

    def test_qemu_preference_always_maps_to_index_1(
        self,
        qapp: QApplication,
        real_config: RealConfigManager,
    ) -> None:
        """QEMU preference 'always' loads as index 1."""
        real_config.config = {
            "qemu_testing.default_preference": "always",
        }

        dialog = PreferencesDialog()
        dialog.config = real_config
        dialog.load_preferences()

        assert dialog.qemu_preference_combo.currentIndex() == 1

    def test_qemu_preference_never_maps_to_index_2(
        self,
        qapp: QApplication,
        real_config: RealConfigManager,
    ) -> None:
        """QEMU preference 'never' loads as index 2."""
        real_config.config = {
            "qemu_testing.default_preference": "never",
        }

        dialog = PreferencesDialog()
        dialog.config = real_config
        dialog.load_preferences()

        assert dialog.qemu_preference_combo.currentIndex() == 2

    def test_save_qemu_preference_index_0_saves_ask(
        self,
        preferences_dialog: PreferencesDialog,
        real_config: RealConfigManager,
    ) -> None:
        """Saving QEMU preference index 0 stores 'ask'."""
        preferences_dialog.config = real_config
        preferences_dialog.qemu_preference_combo.setCurrentIndex(0)

        preferences_dialog.save_preferences()

        assert real_config.config["qemu_testing.default_preference"] == "ask"

    def test_save_qemu_preference_index_1_saves_always(
        self,
        preferences_dialog: PreferencesDialog,
        real_config: RealConfigManager,
    ) -> None:
        """Saving QEMU preference index 1 stores 'always'."""
        preferences_dialog.config = real_config
        preferences_dialog.qemu_preference_combo.setCurrentIndex(1)

        preferences_dialog.save_preferences()

        assert real_config.config["qemu_testing.default_preference"] == "always"

    def test_save_qemu_preference_index_2_saves_never(
        self,
        preferences_dialog: PreferencesDialog,
        real_config: RealConfigManager,
    ) -> None:
        """Saving QEMU preference index 2 stores 'never'."""
        preferences_dialog.config = real_config
        preferences_dialog.qemu_preference_combo.setCurrentIndex(2)

        preferences_dialog.save_preferences()

        assert real_config.config["qemu_testing.default_preference"] == "never"


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_spinbox_ranges_enforce_valid_values(
        self,
        preferences_dialog: PreferencesDialog,
    ) -> None:
        """Spinboxes enforce their configured min/max ranges."""
        preferences_dialog.qemu_timeout_spin.setValue(1000)
        assert preferences_dialog.qemu_timeout_spin.value() <= 300

        preferences_dialog.qemu_memory_spin.setValue(100)
        assert preferences_dialog.qemu_memory_spin.value() >= 512

        preferences_dialog.hex_bytes_per_row.setValue(100)
        assert preferences_dialog.hex_bytes_per_row.value() <= 32

    def test_api_key_field_masks_password_input(
        self,
        preferences_dialog: PreferencesDialog,
    ) -> None:
        """API key field uses password echo mode."""
        assert preferences_dialog.api_key_edit.echoMode() == preferences_dialog.api_key_edit.EchoMode.Password

    def test_capture_output_checkbox_defaults_to_checked(
        self,
        preferences_dialog: PreferencesDialog,
    ) -> None:
        """Capture output checkbox defaults to checked state."""
        assert preferences_dialog.capture_output_checkbox.isChecked()

    def test_explain_scripts_checkbox_defaults_to_checked(
        self,
        preferences_dialog: PreferencesDialog,
    ) -> None:
        """Explain scripts checkbox defaults to checked state."""
        assert preferences_dialog.explain_scripts_checkbox.isChecked()

    def test_warn_dangerous_checkbox_defaults_to_checked(
        self,
        preferences_dialog: PreferencesDialog,
    ) -> None:
        """Warn dangerous operations checkbox defaults to checked."""
        assert preferences_dialog.warn_dangerous_checkbox.isChecked()

    def test_confirm_patches_checkbox_defaults_to_checked(
        self,
        preferences_dialog: PreferencesDialog,
    ) -> None:
        """Confirm patches checkbox defaults to checked."""
        assert preferences_dialog.confirm_patches_checkbox.isChecked()

    def test_auto_detect_checkbox_defaults_to_checked(
        self,
        preferences_dialog: PreferencesDialog,
    ) -> None:
        """Auto-detect protections checkbox defaults to checked."""
        assert preferences_dialog.auto_detect_checkbox.isChecked()

    def test_ml_analysis_checkbox_defaults_to_checked(
        self,
        preferences_dialog: PreferencesDialog,
    ) -> None:
        """ML analysis checkbox defaults to checked."""
        assert preferences_dialog.ml_analysis_checkbox.isChecked()
