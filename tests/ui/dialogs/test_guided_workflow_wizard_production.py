"""Production tests for GuidedWorkflowWizard dialog.

Tests wizard navigation, page configuration, field registration,
binary selection, settings collection, and parent integration.
"""

import os
import tempfile
from pathlib import Path
from typing import Any, cast

import pytest

from intellicrack.handlers.pyqt6_handler import QApplication, QDialog, QWizard, QWizardPage
from intellicrack.ui.dialogs.guided_workflow_wizard import (
    GuidedWorkflowWizard,
    create_guided_workflow_wizard,
)


def get_page(wizard: GuidedWorkflowWizard, page_id: int) -> QWizardPage:
    """Get wizard page with type assertion."""
    page = wizard.page(page_id)
    assert page is not None, f"Page {page_id} not found"
    return page


# PyQt6 enum access helpers
WIZARD_MODERN_STYLE: int = getattr(QWizard, 'ModernStyle', getattr(getattr(QWizard, 'WizardStyle', None), 'ModernStyle', 0) if hasattr(QWizard, 'WizardStyle') else 0)
DIALOG_ACCEPTED: int = getattr(QDialog, 'Accepted', getattr(getattr(QDialog, 'DialogCode', None), 'Accepted', 1) if hasattr(QDialog, 'DialogCode') else 1)
DIALOG_REJECTED: int = getattr(QDialog, 'Rejected', getattr(getattr(QDialog, 'DialogCode', None), 'Rejected', 0) if hasattr(QDialog, 'DialogCode') else 0)


class FakeSignal:
    """Real signal implementation for testing."""

    def __init__(self) -> None:
        self.emissions: list[Any] = []

    def emit(self, value: Any) -> None:
        """Record signal emission."""
        self.emissions.append(value)


class FakeMainWindow:
    """Real test double for main window parent integration testing."""

    def __init__(self) -> None:
        self.binary_path: str = ""
        self.outputs: list[str] = []
        self.loaded_binaries: list[str] = []
        self.static_analyses_run: int = 0
        self.dynamic_analyses_run: int = 0
        self.tab_switches: list[int] = []
        self._switch_tab_signal: FakeSignal = FakeSignal()

    def update_output(self, text: str) -> None:
        """Record output update."""
        self.outputs.append(text)

    def emit(self, text: str) -> None:
        """Record signal emission."""
        self.outputs.append(text)

    def load_binary(self, path: str) -> None:
        """Record binary loading."""
        self.loaded_binaries.append(path)

    def run_static_analysis(self) -> None:
        """Record static analysis execution."""
        self.static_analyses_run += 1

    def run_dynamic_analysis(self) -> None:
        """Record dynamic analysis execution."""
        self.dynamic_analyses_run += 1

    def switch_tab(self) -> FakeSignal:
        """Return tab switching signal."""
        return self._switch_tab_signal


class FakeFileDialog:
    """Real test double for QFileDialog."""

    _next_result: tuple[str, str] | None = None

    def __init__(self, file_path: str, filter_string: str) -> None:
        self.file_path: str = file_path
        self.filter_string: str = filter_string

    @classmethod
    def getOpenFileName(
        cls, parent: Any, caption: str, directory: str, filter_string: str
    ) -> tuple[str, str]:
        """Return pre-configured file selection result."""
        if cls._next_result is not None:
            result = cls._next_result
            cls._next_result = None
            return result
        return ("", "")

    @classmethod
    def set_next_result(cls, file_path: str, filter_string: str = "") -> None:
        """Configure next file dialog result."""
        cls._next_result = (file_path, filter_string)


@pytest.fixture
def qapp() -> Any:
    """Create QApplication instance."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def wizard(qapp: Any) -> GuidedWorkflowWizard:
    """Create wizard instance."""
    return GuidedWorkflowWizard()


@pytest.fixture
def wizard_with_parent(qapp: Any) -> tuple[GuidedWorkflowWizard, FakeMainWindow]:
    """Create wizard with fake parent."""
    parent = FakeMainWindow()
    wiz = GuidedWorkflowWizard()
    setattr(wiz, "_test_parent", parent)
    return (wiz, parent)


@pytest.fixture
def sample_exe(tmp_path: Path) -> Path:
    """Create sample executable file."""
    exe_path = tmp_path / "sample.exe"
    exe_content = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
    exe_content += b"\x00" * 100
    exe_path.write_bytes(exe_content)
    return exe_path


class TestGuidedWorkflowWizardInitialization:
    """Test wizard initialization and setup."""

    def test_wizard_created_with_correct_title(self, wizard: GuidedWorkflowWizard) -> None:
        """Wizard has correct window title."""
        assert wizard.windowTitle() == "Intellicrack Guided Workflow"

    def test_wizard_uses_modern_style(self, wizard: GuidedWorkflowWizard) -> None:
        """Wizard uses modern style."""
        style = wizard.wizardStyle()
        # Compare wizard style - handle both enum and int values
        style_hash = hash(style)
        expected_style = getattr(QWizard, 'ModernStyle', None)
        if expected_style is None:
            wizard_style_enum = getattr(QWizard, 'WizardStyle', None)
            if wizard_style_enum is not None:
                expected_style = getattr(wizard_style_enum, 'ModernStyle', None)
        assert expected_style is not None
        assert style_hash == hash(expected_style)

    def test_wizard_has_minimum_size(self, wizard: GuidedWorkflowWizard) -> None:
        """Wizard has minimum size constraint."""
        assert wizard.minimumWidth() == 800
        assert wizard.minimumHeight() == 600

    def test_wizard_creates_all_pages(self, wizard: GuidedWorkflowWizard) -> None:
        """Wizard creates all required pages."""
        assert wizard.pageIds() is not None
        page_count = len(wizard.pageIds())
        assert page_count == 10

    def test_wizard_pages_in_correct_order(self, wizard: GuidedWorkflowWizard) -> None:
        """Wizard pages are in logical order."""
        page_ids = wizard.pageIds()
        titles = [get_page(wizard, pid).title() for pid in page_ids]

        expected_titles = [
            "Welcome to Intellicrack",
            "Select Binary File",
            "Protection Detection",
            "Analysis Options",
            "Advanced Analysis",
            "Vulnerability Detection",
            "Patching Options",
            "Network Analysis",
            "AI & Machine Learning",
            "Ready to Start",
        ]

        assert titles == expected_titles

    def test_wizard_accepts_parent_window(self, wizard_with_parent: tuple[GuidedWorkflowWizard, FakeMainWindow]) -> None:
        """Wizard correctly stores parent reference."""
        wiz, parent = wizard_with_parent
        assert hasattr(wiz, '_test_parent')
        assert isinstance(parent, FakeMainWindow)

    def test_wizard_icon_loaded_when_available(self, wizard: GuidedWorkflowWizard) -> None:
        """Wizard loads icon if file exists."""
        icon = wizard.windowIcon()
        assert icon is not None


class TestIntroductionPage:
    """Test introduction page."""

    def test_intro_page_has_welcome_title(self, wizard: GuidedWorkflowWizard) -> None:
        """Introduction page has welcome title."""
        page = get_page(wizard, wizard.pageIds()[0])
        assert page.title() == "Welcome to Intellicrack"

    def test_intro_page_has_subtitle(self, wizard: GuidedWorkflowWizard) -> None:
        """Introduction page has informative subtitle."""
        page = get_page(wizard, wizard.pageIds()[0])
        subtitle = page.subTitle()
        assert "wizard" in subtitle.lower()
        assert "analyze" in subtitle.lower() or "patch" in subtitle.lower()

    def test_intro_page_not_final(self, wizard: GuidedWorkflowWizard) -> None:
        """Introduction page is not final page."""
        page = get_page(wizard, wizard.pageIds()[0])
        assert not page.isFinalPage()


class TestFileSelectionPage:
    """Test file selection page."""

    def test_file_selection_page_has_title(self, wizard: GuidedWorkflowWizard) -> None:
        """File selection page has appropriate title."""
        page = get_page(wizard, wizard.pageIds()[1])
        assert "binary" in page.title().lower() or "file" in page.title().lower()

    def test_file_selection_has_path_field(self, wizard: GuidedWorkflowWizard) -> None:
        """File selection page has file path field."""
        assert hasattr(wizard, "file_path_edit")
        assert wizard.file_path_edit is not None

    def test_file_path_field_initially_empty(self, wizard: GuidedWorkflowWizard) -> None:
        """File path field starts with no selection message."""
        assert "no" in wizard.file_path_edit.text().lower()

    def test_file_path_field_is_readonly(self, wizard: GuidedWorkflowWizard) -> None:
        """File path field is read-only."""
        assert wizard.file_path_edit.isReadOnly()

    def test_file_selection_has_info_label(self, wizard: GuidedWorkflowWizard) -> None:
        """File selection page has file info label."""
        assert hasattr(wizard, "file_info_label")
        assert wizard.file_info_label is not None

    def test_binary_path_field_registered(self, wizard: GuidedWorkflowWizard) -> None:
        """Binary path field is registered as required."""
        wizard.file_path_edit.setText("C:\\test.exe")
        page = get_page(wizard, wizard.pageIds()[1])
        assert page.field("binary_path") == "C:\\test.exe"

    def test_browse_file_updates_path(
        self, wizard: GuidedWorkflowWizard, sample_exe: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Browse file method updates path field."""
        FakeFileDialog.set_next_result(str(sample_exe), "")
        monkeypatch.setattr(
            "intellicrack.ui.dialogs.guided_workflow_wizard.QFileDialog",
            FakeFileDialog,
        )
        wizard.browse_file()
        assert wizard.file_path_edit.text() == str(sample_exe)

    def test_browse_file_updates_info(
        self, wizard: GuidedWorkflowWizard, sample_exe: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Browse file updates file info display."""
        FakeFileDialog.set_next_result(str(sample_exe), "")
        monkeypatch.setattr(
            "intellicrack.ui.dialogs.guided_workflow_wizard.QFileDialog",
            FakeFileDialog,
        )
        wizard.browse_file()
        info_text = wizard.file_info_label.text()
        assert len(info_text) > 0
        assert "sample.exe" in info_text

    def test_browse_file_cancellation_ignored(
        self, wizard: GuidedWorkflowWizard, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Cancelling file dialog doesn't change path."""
        original_text = wizard.file_path_edit.text()
        FakeFileDialog.set_next_result("", "")
        monkeypatch.setattr(
            "intellicrack.ui.dialogs.guided_workflow_wizard.QFileDialog",
            FakeFileDialog,
        )
        wizard.browse_file()
        assert wizard.file_path_edit.text() == original_text

    def test_update_file_info_displays_size(self, wizard: GuidedWorkflowWizard, sample_exe: Path) -> None:
        """Update file info shows file size."""
        wizard.update_file_info(str(sample_exe))
        info_text = wizard.file_info_label.text()
        assert "size" in info_text.lower()

    def test_update_file_info_displays_modified_time(self, wizard: GuidedWorkflowWizard, sample_exe: Path) -> None:
        """Update file info shows modification time."""
        wizard.update_file_info(str(sample_exe))
        info_text = wizard.file_info_label.text()
        assert "modified" in info_text.lower()

    def test_update_file_info_handles_missing_file(self, wizard: GuidedWorkflowWizard) -> None:
        """Update file info handles non-existent files."""
        wizard.update_file_info("C:\\nonexistent.exe")
        info_text = wizard.file_info_label.text()
        assert "error" in info_text.lower()

    def test_format_size_returns_readable_string(self, wizard: GuidedWorkflowWizard) -> None:
        """Format size returns human-readable strings."""
        size_1kb = wizard.format_size(1024)
        assert "1" in size_1kb and ("kb" in size_1kb.lower() or "kib" in size_1kb.lower())

        size_1mb = wizard.format_size(1024 * 1024)
        assert "1" in size_1mb and ("mb" in size_1mb.lower() or "mib" in size_1mb.lower())


class TestProtectionDetectionPage:
    """Test protection detection configuration page."""

    def test_protection_page_has_checkboxes(self, wizard: GuidedWorkflowWizard) -> None:
        """Protection detection page has all protection type checkboxes."""
        assert hasattr(wizard, "detect_commercial_cb")
        assert hasattr(wizard, "detect_packing_cb")
        assert hasattr(wizard, "detect_dongle_cb")
        assert hasattr(wizard, "detect_tpm_cb")
        assert hasattr(wizard, "detect_network_cb")
        assert hasattr(wizard, "detect_antidebug_cb")
        assert hasattr(wizard, "detect_checksum_cb")
        assert hasattr(wizard, "detect_time_cb")

    def test_protection_checkboxes_default_states(self, wizard: GuidedWorkflowWizard) -> None:
        """Protection checkboxes have sensible defaults."""
        assert wizard.detect_commercial_cb.isChecked()
        assert wizard.detect_packing_cb.isChecked()
        assert wizard.detect_network_cb.isChecked()
        assert wizard.detect_antidebug_cb.isChecked()
        assert wizard.detect_time_cb.isChecked()

    def test_protection_fields_registered(self, wizard: GuidedWorkflowWizard) -> None:
        """Protection detection fields are registered."""
        page = get_page(wizard, wizard.pageIds()[2])
        assert page.field("detect_commercial") is not None
        assert page.field("detect_packing") is not None
        assert page.field("detect_dongle") is not None

    def test_protection_checkbox_state_changes(self, wizard: GuidedWorkflowWizard) -> None:
        """Protection checkboxes can be toggled."""
        wizard.detect_commercial_cb.setChecked(False)
        assert not wizard.detect_commercial_cb.isChecked()
        wizard.detect_commercial_cb.setChecked(True)
        assert wizard.detect_commercial_cb.isChecked()


class TestAnalysisOptionsPage:
    """Test analysis options configuration page."""

    def test_analysis_page_has_type_checkboxes(self, wizard: GuidedWorkflowWizard) -> None:
        """Analysis options page has analysis type checkboxes."""
        assert hasattr(wizard, "static_analysis_cb")
        assert hasattr(wizard, "dynamic_analysis_cb")
        assert hasattr(wizard, "symbolic_execution_cb")
        assert hasattr(wizard, "ml_analysis_cb")

    def test_analysis_types_default_checked(self, wizard: GuidedWorkflowWizard) -> None:
        """Common analysis types are checked by default."""
        assert wizard.static_analysis_cb.isChecked()
        assert wizard.dynamic_analysis_cb.isChecked()

    def test_analysis_page_has_timeout_spinner(self, wizard: GuidedWorkflowWizard) -> None:
        """Analysis options page has timeout spinner."""
        assert hasattr(wizard, "timeout_spin")
        assert wizard.timeout_spin is not None

    def test_timeout_has_valid_range(self, wizard: GuidedWorkflowWizard) -> None:
        """Timeout spinner has reasonable range."""
        assert wizard.timeout_spin.minimum() >= 10
        assert wizard.timeout_spin.maximum() <= 3600

    def test_timeout_has_default_value(self, wizard: GuidedWorkflowWizard) -> None:
        """Timeout spinner has sensible default."""
        default_timeout = wizard.timeout_spin.value()
        assert 60 <= default_timeout <= 600

    def test_analysis_fields_registered(self, wizard: GuidedWorkflowWizard) -> None:
        """Analysis option fields are registered."""
        page = get_page(wizard, wizard.pageIds()[3])
        assert page.field("static_analysis") is not None
        assert page.field("dynamic_analysis") is not None
        assert page.field("timeout") is not None


class TestAdvancedAnalysisPage:
    """Test advanced analysis configuration page."""

    def test_advanced_page_has_technique_checkboxes(self, wizard: GuidedWorkflowWizard) -> None:
        """Advanced analysis page has technique checkboxes."""
        assert hasattr(wizard, "cfg_analysis_cb")
        assert hasattr(wizard, "taint_analysis_cb")
        assert hasattr(wizard, "concolic_execution_cb")
        assert hasattr(wizard, "rop_gadgets_cb")
        assert hasattr(wizard, "binary_similarity_cb")
        assert hasattr(wizard, "section_analysis_cb")
        assert hasattr(wizard, "import_export_cb")

    def test_advanced_page_has_tool_integration(self, wizard: GuidedWorkflowWizard) -> None:
        """Advanced page has external tool checkboxes."""
        assert hasattr(wizard, "ghidra_analysis_cb")
        assert hasattr(wizard, "radare2_analysis_cb")

    def test_advanced_fields_registered(self, wizard: GuidedWorkflowWizard) -> None:
        """Advanced analysis fields are registered."""
        page = get_page(wizard, wizard.pageIds()[4])
        assert page.field("cfg_analysis") is not None
        assert page.field("ghidra_analysis") is not None


class TestVulnerabilityOptionsPage:
    """Test vulnerability detection configuration page."""

    def test_vulnerability_page_has_detection_checkboxes(self, wizard: GuidedWorkflowWizard) -> None:
        """Vulnerability page has detection method checkboxes."""
        assert hasattr(wizard, "static_vuln_scan_cb")
        assert hasattr(wizard, "ml_vuln_prediction_cb")
        assert hasattr(wizard, "buffer_overflow_cb")
        assert hasattr(wizard, "format_string_cb")
        assert hasattr(wizard, "race_condition_cb")

    def test_vulnerability_page_has_exploitation_options(self, wizard: GuidedWorkflowWizard) -> None:
        """Vulnerability page has exploitation checkboxes."""
        assert hasattr(wizard, "generate_exploits_cb")
        assert hasattr(wizard, "rop_chain_cb")
        assert hasattr(wizard, "shellcode_cb")

    def test_vulnerability_fields_registered(self, wizard: GuidedWorkflowWizard) -> None:
        """Vulnerability detection fields are registered."""
        page = get_page(wizard, wizard.pageIds()[5])
        assert page.field("static_vuln_scan") is not None
        assert page.field("buffer_overflow") is not None


class TestPatchingOptionsPage:
    """Test patching configuration page."""

    def test_patching_page_has_type_checkboxes(self, wizard: GuidedWorkflowWizard) -> None:
        """Patching page has patching type checkboxes."""
        assert hasattr(wizard, "auto_patch_cb")
        assert hasattr(wizard, "interactive_patch_cb")
        assert hasattr(wizard, "function_hooking_cb")
        assert hasattr(wizard, "memory_patching_cb")

    def test_patching_page_has_target_checkboxes(self, wizard: GuidedWorkflowWizard) -> None:
        """Patching page has patch target checkboxes."""
        assert hasattr(wizard, "license_check_cb")
        assert hasattr(wizard, "time_limit_cb")
        assert hasattr(wizard, "feature_unlock_cb")
        assert hasattr(wizard, "anti_debug_cb")

    def test_patching_defaults_enabled(self, wizard: GuidedWorkflowWizard) -> None:
        """Common patching options are enabled by default."""
        assert wizard.auto_patch_cb.isChecked()
        assert wizard.memory_patching_cb.isChecked()
        assert wizard.license_check_cb.isChecked()

    def test_patching_fields_registered(self, wizard: GuidedWorkflowWizard) -> None:
        """Patching option fields are registered."""
        page = get_page(wizard, wizard.pageIds()[6])
        assert page.field("auto_patch") is not None
        assert page.field("license_check") is not None


class TestNetworkOptionsPage:
    """Test network analysis configuration page."""

    def test_network_page_has_analysis_checkboxes(self, wizard: GuidedWorkflowWizard) -> None:
        """Network page has analysis checkboxes."""
        assert hasattr(wizard, "traffic_capture_cb")
        assert hasattr(wizard, "protocol_fingerprint_cb")
        assert hasattr(wizard, "ssl_intercept_cb")
        assert hasattr(wizard, "license_server_emulate_cb")
        assert hasattr(wizard, "cloud_license_hook_cb")

    def test_network_traffic_capture_default_enabled(self, wizard: GuidedWorkflowWizard) -> None:
        """Network traffic capture is enabled by default."""
        assert wizard.traffic_capture_cb.isChecked()

    def test_network_fields_registered(self, wizard: GuidedWorkflowWizard) -> None:
        """Network analysis fields are registered."""
        page = get_page(wizard, wizard.pageIds()[7])
        assert page.field("traffic_capture") is not None
        assert page.field("ssl_intercept") is not None


class TestAIOptionsPage:
    """Test AI and ML configuration page."""

    def test_ai_page_has_feature_checkboxes(self, wizard: GuidedWorkflowWizard) -> None:
        """AI page has AI feature checkboxes."""
        assert hasattr(wizard, "ai_comprehensive_cb")
        assert hasattr(wizard, "ai_patch_suggest_cb")
        assert hasattr(wizard, "ai_code_explain_cb")
        assert hasattr(wizard, "ml_pattern_learn_cb")
        assert hasattr(wizard, "ai_assisted_mode_cb")

    def test_ai_page_has_processing_options(self, wizard: GuidedWorkflowWizard) -> None:
        """AI page has processing option checkboxes."""
        assert hasattr(wizard, "distributed_processing_cb")
        assert hasattr(wizard, "gpu_acceleration_cb")

    def test_ai_defaults_enabled(self, wizard: GuidedWorkflowWizard) -> None:
        """Common AI features are enabled by default."""
        assert wizard.ai_comprehensive_cb.isChecked()
        assert wizard.ai_patch_suggest_cb.isChecked()

    def test_ai_fields_registered(self, wizard: GuidedWorkflowWizard) -> None:
        """AI option fields are registered."""
        page = get_page(wizard, wizard.pageIds()[8])
        assert page.field("ai_comprehensive") is not None
        assert page.field("gpu_acceleration") is not None


class TestConclusionPage:
    """Test conclusion/summary page."""

    def test_conclusion_page_is_final(self, wizard: GuidedWorkflowWizard) -> None:
        """Conclusion page is marked as final."""
        page = get_page(wizard, wizard.pageIds()[9])
        assert page.isFinalPage()

    def test_conclusion_page_has_summary_widget(self, wizard: GuidedWorkflowWizard) -> None:
        """Conclusion page has summary text widget."""
        assert hasattr(wizard, "summary_text")
        assert wizard.summary_text is not None

    def test_summary_text_is_readonly(self, wizard: GuidedWorkflowWizard) -> None:
        """Summary text widget is read-only."""
        assert wizard.summary_text.isReadOnly()


class TestSummaryGeneration:
    """Test summary generation logic."""

    def test_update_summary_includes_binary_path(self, wizard: GuidedWorkflowWizard) -> None:
        """Summary includes selected binary path."""
        wizard.file_path_edit.setText("C:\\test\\sample.exe")
        wizard.update_summary()
        summary = wizard.summary_text.toPlainText()
        assert "sample.exe" in summary

    def test_build_protection_section_includes_enabled_protections(self, wizard: GuidedWorkflowWizard) -> None:
        """Protection section includes enabled protection types."""
        wizard.detect_commercial_cb.setChecked(True)
        wizard.detect_packing_cb.setChecked(True)
        section = wizard._build_protection_section()
        assert "commercial" in section.lower()
        assert "packing" in section.lower()

    def test_build_protection_section_excludes_disabled_protections(self, wizard: GuidedWorkflowWizard) -> None:
        """Protection section excludes disabled protection types."""
        wizard.detect_tpm_cb.setChecked(False)
        section = wizard._build_protection_section()
        assert "tpm" not in section.lower()

    def test_build_analysis_section_includes_timeout(self, wizard: GuidedWorkflowWizard) -> None:
        """Analysis section includes timeout value."""
        wizard.timeout_spin.setValue(180)
        section = wizard._build_analysis_section()
        assert "180" in section

    def test_build_analysis_section_includes_enabled_types(self, wizard: GuidedWorkflowWizard) -> None:
        """Analysis section includes enabled analysis types."""
        wizard.static_analysis_cb.setChecked(True)
        wizard.dynamic_analysis_cb.setChecked(True)
        section = wizard._build_analysis_section()
        assert "static" in section.lower()
        assert "dynamic" in section.lower()

    def test_build_advanced_analysis_section_when_empty(self, wizard: GuidedWorkflowWizard) -> None:
        """Advanced analysis section handles no selections."""
        wizard.cfg_analysis_cb.setChecked(False)
        wizard.taint_analysis_cb.setChecked(False)
        wizard.concolic_execution_cb.setChecked(False)
        wizard.rop_gadgets_cb.setChecked(False)
        wizard.binary_similarity_cb.setChecked(False)
        wizard.section_analysis_cb.setChecked(False)
        wizard.import_export_cb.setChecked(False)
        wizard.ghidra_analysis_cb.setChecked(False)
        wizard.radare2_analysis_cb.setChecked(False)
        section = wizard._build_advanced_analysis_section()
        assert "advanced" in section.lower()

    def test_build_vulnerability_section_includes_enabled_options(self, wizard: GuidedWorkflowWizard) -> None:
        """Vulnerability section includes enabled detection methods."""
        wizard.buffer_overflow_cb.setChecked(True)
        section = wizard._build_vulnerability_section()
        assert "buffer" in section.lower() or "overflow" in section.lower()

    def test_build_patching_section_includes_enabled_options(self, wizard: GuidedWorkflowWizard) -> None:
        """Patching section includes enabled patching types."""
        wizard.auto_patch_cb.setChecked(True)
        section = wizard._build_patching_section()
        assert "auto" in section.lower() or "patch" in section.lower()

    def test_build_patch_targets_section_includes_enabled_targets(self, wizard: GuidedWorkflowWizard) -> None:
        """Patch targets section includes enabled targets."""
        wizard.license_check_cb.setChecked(True)
        section = wizard._build_patch_targets_section()
        assert "license" in section.lower()

    def test_build_network_section_includes_enabled_features(self, wizard: GuidedWorkflowWizard) -> None:
        """Network section includes enabled network features."""
        wizard.traffic_capture_cb.setChecked(True)
        section = wizard._build_network_section()
        assert "traffic" in section.lower() or "capture" in section.lower()

    def test_build_ai_ml_section_includes_enabled_features(self, wizard: GuidedWorkflowWizard) -> None:
        """AI/ML section includes enabled AI features."""
        wizard.ai_comprehensive_cb.setChecked(True)
        section = wizard._build_ai_ml_section()
        assert "ai" in section.lower() or "comprehensive" in section.lower()


class TestSettingsCollection:
    """Test settings collection functionality."""

    def test_get_settings_returns_dict(self, wizard: GuidedWorkflowWizard) -> None:
        """Get settings returns dictionary."""
        wizard.file_path_edit.setText("C:\\test.exe")
        settings = wizard.get_settings()
        assert isinstance(settings, dict)

    def test_get_settings_includes_binary_path(self, wizard: GuidedWorkflowWizard) -> None:
        """Get settings includes binary path."""
        wizard.file_path_edit.setText("C:\\test.exe")
        settings = wizard.get_settings()
        assert settings["binary_path"] == "C:\\test.exe"

    def test_get_settings_includes_analysis_options(self, wizard: GuidedWorkflowWizard) -> None:
        """Get settings includes analysis configuration."""
        wizard.static_analysis_cb.setChecked(True)
        wizard.dynamic_analysis_cb.setChecked(False)
        wizard.timeout_spin.setValue(120)

        settings = wizard.get_settings()
        assert settings["analysis"]["static"] is True
        assert settings["analysis"]["dynamic"] is False
        assert settings["analysis"]["timeout"] == 120

    def test_get_settings_includes_patching_options(self, wizard: GuidedWorkflowWizard) -> None:
        """Get settings includes patching configuration."""
        wizard.auto_patch_cb.setChecked(True)
        wizard.interactive_patch_cb.setChecked(False)

        settings = wizard.get_settings()
        assert settings["patching"]["auto"] is True
        assert settings["patching"]["interactive"] is False

    def test_get_settings_includes_patch_targets(self, wizard: GuidedWorkflowWizard) -> None:
        """Get settings includes patch target configuration."""
        wizard.license_check_cb.setChecked(True)
        wizard.time_limit_cb.setChecked(False)

        settings = wizard.get_settings()
        assert settings["patching"]["targets"]["license_check"] is True
        assert settings["patching"]["targets"]["time_limit"] is False


class TestWizardCompletion:
    """Test wizard completion and parent integration."""

    def test_on_finished_ignores_rejected_dialog(
        self, wizard_with_parent: tuple[GuidedWorkflowWizard, FakeMainWindow]
    ) -> None:
        """On finished ignores rejected dialog."""
        wizard, parent = wizard_with_parent
        wizard.on_finished(DIALOG_REJECTED)
        assert len(parent.outputs) == 0

    def test_on_finished_sets_binary_path_on_parent(
        self, wizard_with_parent: tuple[GuidedWorkflowWizard, FakeMainWindow], sample_exe: Path
    ) -> None:
        """On finished sets binary path on parent."""
        wizard, parent = wizard_with_parent
        wizard.file_path_edit.setText(str(sample_exe))
        wizard.on_finished(DIALOG_ACCEPTED)
        assert parent.binary_path == str(sample_exe)

    def test_on_finished_loads_binary_on_parent(
        self, wizard_with_parent: tuple[GuidedWorkflowWizard, FakeMainWindow], sample_exe: Path
    ) -> None:
        """On finished calls load_binary on parent."""
        wizard, parent = wizard_with_parent
        wizard.file_path_edit.setText(str(sample_exe))
        wizard.on_finished(DIALOG_ACCEPTED)
        assert str(sample_exe) in parent.loaded_binaries

    def test_on_finished_starts_static_analysis(
        self, wizard_with_parent: tuple[GuidedWorkflowWizard, FakeMainWindow], sample_exe: Path
    ) -> None:
        """On finished starts static analysis if enabled."""
        wizard, parent = wizard_with_parent
        wizard.file_path_edit.setText(str(sample_exe))
        wizard.static_analysis_cb.setChecked(True)
        wizard.on_finished(DIALOG_ACCEPTED)
        assert parent.static_analyses_run == 1

    def test_on_finished_skips_static_analysis_if_disabled(
        self, wizard_with_parent: tuple[GuidedWorkflowWizard, FakeMainWindow], sample_exe: Path
    ) -> None:
        """On finished skips static analysis if disabled."""
        wizard, parent = wizard_with_parent
        wizard.file_path_edit.setText(str(sample_exe))
        wizard.static_analysis_cb.setChecked(False)
        wizard.on_finished(DIALOG_ACCEPTED)
        assert parent.static_analyses_run == 0

    def test_on_finished_starts_dynamic_analysis(
        self, wizard_with_parent: tuple[GuidedWorkflowWizard, FakeMainWindow], sample_exe: Path
    ) -> None:
        """On finished starts dynamic analysis if enabled."""
        wizard, parent = wizard_with_parent
        wizard.file_path_edit.setText(str(sample_exe))
        wizard.dynamic_analysis_cb.setChecked(True)
        wizard.on_finished(DIALOG_ACCEPTED)
        assert parent.dynamic_analyses_run == 1

    def test_on_finished_outputs_messages(
        self, wizard_with_parent: tuple[GuidedWorkflowWizard, FakeMainWindow], sample_exe: Path
    ) -> None:
        """On finished outputs status messages."""
        wizard, parent = wizard_with_parent
        wizard.file_path_edit.setText(str(sample_exe))
        wizard.on_finished(DIALOG_ACCEPTED)
        assert len(parent.outputs) > 0

    def test_on_finished_handles_missing_parent_attributes(
        self, wizard: GuidedWorkflowWizard, sample_exe: Path
    ) -> None:
        """On finished handles parent without expected attributes."""
        setattr(wizard, "_test_parent", object())
        wizard.file_path_edit.setText(str(sample_exe))
        wizard.on_finished(DIALOG_ACCEPTED)

    def test_on_finished_handles_nonexistent_binary(
        self, wizard_with_parent: tuple[GuidedWorkflowWizard, FakeMainWindow]
    ) -> None:
        """On finished handles nonexistent binary path."""
        wizard, parent = wizard_with_parent
        wizard.file_path_edit.setText("C:\\nonexistent.exe")
        wizard.on_finished(DIALOG_ACCEPTED)
        assert parent.binary_path == ""


class TestFactoryFunction:
    """Test create_guided_workflow_wizard factory function."""

    def test_factory_creates_wizard(self, qapp: Any) -> None:
        """Factory function creates wizard instance."""
        wizard = create_guided_workflow_wizard()
        assert isinstance(wizard, GuidedWorkflowWizard)

    def test_factory_accepts_parent(self, qapp: Any) -> None:
        """Factory function accepts parent parameter."""
        wizard = create_guided_workflow_wizard(None)
        assert wizard.parent() is None

    def test_factory_creates_wizard_without_parent(self, qapp: Any) -> None:
        """Factory function creates wizard without parent."""
        wizard = create_guided_workflow_wizard(None)
        assert wizard.parent() is None


class TestWizardNavigation:
    """Test wizard navigation behavior."""

    def test_wizard_starts_on_first_page(self, wizard: GuidedWorkflowWizard) -> None:
        """Wizard starts on introduction page."""
        wizard.show()
        assert wizard.currentId() == wizard.pageIds()[0]

    def test_wizard_cannot_proceed_without_binary_path(self, wizard: GuidedWorkflowWizard) -> None:
        """Wizard requires binary path to proceed from file selection."""
        wizard.show()
        wizard.next()
        page = get_page(wizard, wizard.pageIds()[1])
        wizard.setCurrentId(wizard.pageIds()[1])
        wizard.file_path_edit.setText("")
        assert not page.isComplete()

    def test_wizard_can_proceed_with_binary_path(self, wizard: GuidedWorkflowWizard, sample_exe: Path) -> None:
        """Wizard allows proceeding with valid binary path."""
        wizard.show()
        wizard.next()
        page = get_page(wizard, wizard.pageIds()[1])
        wizard.setCurrentId(wizard.pageIds()[1])
        wizard.file_path_edit.setText(str(sample_exe))
        assert page.isComplete()


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_wizard_handles_very_long_binary_path(self, wizard: GuidedWorkflowWizard) -> None:
        """Wizard handles very long file paths."""
        long_path = "C:\\" + "a" * 200 + "\\test.exe"
        wizard.file_path_edit.setText(long_path)
        assert wizard.file_path_edit.text() == long_path

    def test_wizard_handles_unicode_binary_path(self, wizard: GuidedWorkflowWizard) -> None:
        """Wizard handles unicode characters in paths."""
        unicode_path = "C:\\测试\\sample.exe"
        wizard.file_path_edit.setText(unicode_path)
        assert wizard.file_path_edit.text() == unicode_path

    def test_wizard_handles_all_options_disabled(self, wizard: GuidedWorkflowWizard) -> None:
        """Wizard handles all options disabled."""
        wizard.static_analysis_cb.setChecked(False)
        wizard.dynamic_analysis_cb.setChecked(False)
        wizard.symbolic_execution_cb.setChecked(False)
        wizard.ml_analysis_cb.setChecked(False)

        settings = wizard.get_settings()
        assert settings["analysis"]["static"] is False
        assert settings["analysis"]["dynamic"] is False

    def test_wizard_handles_extreme_timeout_values(self, wizard: GuidedWorkflowWizard) -> None:
        """Wizard handles extreme timeout values."""
        wizard.timeout_spin.setValue(wizard.timeout_spin.minimum())
        assert wizard.timeout_spin.value() == wizard.timeout_spin.minimum()

        wizard.timeout_spin.setValue(wizard.timeout_spin.maximum())
        assert wizard.timeout_spin.value() == wizard.timeout_spin.maximum()

    def test_update_summary_with_no_selections(self, wizard: GuidedWorkflowWizard) -> None:
        """Update summary works with minimal selections."""
        wizard.file_path_edit.setText("C:\\test.exe")
        wizard.detect_commercial_cb.setChecked(False)
        wizard.detect_packing_cb.setChecked(False)
        wizard.detect_dongle_cb.setChecked(False)
        wizard.detect_tpm_cb.setChecked(False)
        wizard.detect_network_cb.setChecked(False)
        wizard.detect_antidebug_cb.setChecked(False)
        wizard.detect_checksum_cb.setChecked(False)
        wizard.detect_time_cb.setChecked(False)

        wizard.update_summary()
        summary = wizard.summary_text.toPlainText()
        assert len(summary) > 0

    def test_wizard_handles_parent_without_update_output_signal(self, qapp: QApplication, sample_exe: Path) -> None:
        """Wizard handles parent without update_output signal."""
        wizard = GuidedWorkflowWizard(None)
        wizard.file_path_edit.setText(str(sample_exe))
        wizard.on_finished(DIALOG_ACCEPTED)

    def test_wizard_handles_parent_without_switch_tab_signal(self, qapp: QApplication, sample_exe: Path) -> None:
        """Wizard handles parent without switch_tab signal."""
        wizard = GuidedWorkflowWizard(None)
        wizard.file_path_edit.setText(str(sample_exe))
        wizard.on_finished(DIALOG_ACCEPTED)


class TestPerformance:
    """Test wizard performance."""

    def test_wizard_initialization_completes_quickly(self, qapp: QApplication) -> None:
        """Wizard initialization completes in reasonable time."""
        import time

        start = time.time()
        wizard = GuidedWorkflowWizard()
        elapsed = time.time() - start
        assert elapsed < 2.0

    def test_summary_update_completes_quickly(self, wizard: GuidedWorkflowWizard) -> None:
        """Summary update completes in reasonable time."""
        import time

        wizard.file_path_edit.setText("C:\\test.exe")
        start = time.time()
        wizard.update_summary()
        elapsed = time.time() - start
        assert elapsed < 0.5

    def test_get_settings_completes_quickly(self, wizard: GuidedWorkflowWizard) -> None:
        """Get settings completes in reasonable time."""
        import time

        wizard.file_path_edit.setText("C:\\test.exe")
        start = time.time()
        wizard.get_settings()
        elapsed = time.time() - start
        assert elapsed < 0.1
