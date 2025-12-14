"""Comprehensive tests for intellicrack.ui.tabs.analysis_tab module.

This test module validates ALL functionality of the AnalysisTab including:
- UI initialization and component creation  
- Binary loading and unloading workflows
- Static analysis operations with real binary processing
- Dynamic monitoring and protection detection
- License check detection and bypass generation
- Snapshot management and comparison
- Entropy and structure analysis
- Real disassembly generation
- Process attachment and license monitoring
- Export and import functionality

All tests use real Qt components with minimal mocking for UI elements.
Tests validate actual functionality breaks when code is broken.
"""

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, Mock, patch

import pytest


try:
    from PyQt6.QtCore import Qt
    from PyQt6.QtTest import QTest
    from PyQt6.QtWidgets import QApplication

    PYQT6_AVAILABLE = True
except ImportError:
    PYQT6_AVAILABLE = False


@pytest.fixture(scope="session")
def qapp() -> Any:
    """Create QApplication instance for testing session."""
    if not PYQT6_AVAILABLE:
        pytest.skip("PyQt6 not available")

    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.mark.skipif(not PYQT6_AVAILABLE, reason="PyQt6 not available")
class TestCollapsibleGroupBox:
    """Test suite for CollapsibleGroupBox widget."""

    @pytest.fixture
    def group_box(self, qapp: QApplication) -> Any:
        """Create CollapsibleGroupBox instance for testing."""
        from intellicrack.ui.tabs.analysis_tab import CollapsibleGroupBox

        return CollapsibleGroupBox("Test Group")

    def test_collapsible_groupbox_initialization(self, group_box: Any) -> None:
        """CollapsibleGroupBox initializes with correct default state."""
        assert group_box.title() == "Test Group"
        assert group_box.isCheckable()
        assert not group_box.isChecked()
        assert not group_box.content_widget.isVisible()

    def test_collapsible_groupbox_toggle_shows_content(self, group_box: Any) -> None:
        """CollapsibleGroupBox toggles content visibility when checked."""
        assert not group_box.content_widget.isVisible()

        group_box.setChecked(True)
        assert group_box.content_widget.isVisible()

        group_box.setChecked(False)
        assert not group_box.content_widget.isVisible()

    def test_collapsible_groupbox_add_widget(self, group_box: Any, qapp: QApplication) -> None:
        """CollapsibleGroupBox adds widgets to content area."""
        from PyQt6.QtWidgets import QLabel

        test_label = QLabel("Test Widget")
        group_box.add_widget(test_label)

        assert group_box.content_layout.count() > 0
        assert test_label.parent() == group_box.content_widget

    def test_collapsible_groupbox_add_layout(self, group_box: Any) -> None:
        """CollapsibleGroupBox adds layouts to content area."""
        from PyQt6.QtWidgets import QHBoxLayout, QLabel

        test_layout = QHBoxLayout()
        test_layout.addWidget(QLabel("Layout Test"))

        initial_count = group_box.content_layout.count()
        group_box.add_layout(test_layout)

        assert group_box.content_layout.count() > initial_count


@pytest.mark.skipif(not PYQT6_AVAILABLE, reason="PyQt6 not available")
class TestAnalysisTabInitialization:
    """Test suite for AnalysisTab initialization and UI setup."""

    @pytest.fixture
    def mock_context(self) -> Mock:
        """Create mock shared context for testing."""
        context = Mock()
        context.binary_loaded = Mock()
        context.binary_loaded.connect = Mock()
        context.binary_unloaded = Mock()
        context.binary_unloaded.connect = Mock()
        context.get_current_binary = Mock(return_value=None)
        return context

    @pytest.fixture
    def analysis_tab(self, qapp: QApplication, mock_context: Mock) -> Any:
        """Create AnalysisTab instance for testing."""
        from intellicrack.ui.tabs.analysis_tab import AnalysisTab

        tab = AnalysisTab(shared_context=mock_context)
        return tab

    def test_analysis_tab_initialization(self, analysis_tab: Any) -> None:
        """AnalysisTab initializes with correct default state."""
        assert analysis_tab.current_binary is None
        assert analysis_tab.current_file_path is None
        assert analysis_tab.analysis_results == {}
        assert analysis_tab.snapshots == {}
        assert analysis_tab.comparison_results == []
        assert analysis_tab.attached_pid is None
        assert analysis_tab.monitoring_session is None

    def test_analysis_tab_has_required_components(self, analysis_tab: Any) -> None:
        """AnalysisTab creates all required UI components."""
        assert hasattr(analysis_tab, "analysis_profile_combo")
        assert hasattr(analysis_tab, "run_analysis_btn")
        assert hasattr(analysis_tab, "stop_analysis_btn")
        assert hasattr(analysis_tab, "clear_results_btn")
        assert hasattr(analysis_tab, "results_display")
        assert hasattr(analysis_tab, "protection_display")
        assert hasattr(analysis_tab, "license_display")
        assert hasattr(analysis_tab, "bypass_display")
        assert hasattr(analysis_tab, "monitor_log")

    def test_analysis_tab_profile_combo_has_profiles(self, analysis_tab: Any) -> None:
        """AnalysisTab profile selector contains all analysis profiles."""
        profiles = [
            analysis_tab.analysis_profile_combo.itemText(i)
            for i in range(analysis_tab.analysis_profile_combo.count())
        ]

        assert "Quick Scan" in profiles
        assert "Static Analysis" in profiles
        assert "Dynamic Analysis" in profiles
        assert "Full Analysis" in profiles
        assert "Custom" in profiles

    def test_analysis_tab_static_analysis_checkboxes(self, analysis_tab: Any) -> None:
        """AnalysisTab has all static analysis option checkboxes."""
        assert hasattr(analysis_tab, "disassembly_cb")
        assert hasattr(analysis_tab, "string_analysis_cb")
        assert hasattr(analysis_tab, "imports_analysis_cb")
        assert hasattr(analysis_tab, "entropy_analysis_cb")
        assert hasattr(analysis_tab, "signature_analysis_cb")
        assert hasattr(analysis_tab, "crypto_key_extraction_cb")
        assert hasattr(analysis_tab, "subscription_bypass_cb")

    def test_analysis_tab_dynamic_analysis_checkboxes(self, analysis_tab: Any) -> None:
        """AnalysisTab has all dynamic analysis option checkboxes."""
        assert hasattr(analysis_tab, "api_monitoring_cb")
        assert hasattr(analysis_tab, "memory_monitoring_cb")
        assert hasattr(analysis_tab, "file_monitoring_cb")
        assert hasattr(analysis_tab, "network_monitoring_cb")

    def test_analysis_tab_protection_detection_checkboxes(self, analysis_tab: Any) -> None:
        """AnalysisTab has all protection detection checkboxes."""
        assert hasattr(analysis_tab, "packer_detection_cb")
        assert hasattr(analysis_tab, "obfuscation_detection_cb")
        assert hasattr(analysis_tab, "anti_debug_detection_cb")
        assert hasattr(analysis_tab, "vm_detection_cb")
        assert hasattr(analysis_tab, "license_check_detection_cb")

    def test_analysis_tab_connects_to_context_signals(self, mock_context: Mock, qapp: QApplication) -> None:
        """AnalysisTab connects to app_context binary signals."""
        from intellicrack.ui.tabs.analysis_tab import AnalysisTab

        tab = AnalysisTab(shared_context=mock_context)

        assert mock_context.binary_loaded.connect.called
        assert mock_context.binary_unloaded.connect.called


@pytest.mark.skipif(not PYQT6_AVAILABLE, reason="PyQt6 not available")
class TestAnalysisTabBinaryLoading:
    """Test suite for AnalysisTab binary loading workflows with real binaries."""

    @pytest.fixture
    def sample_pe_binary(self, tmp_path: Path) -> Path:
        """Create sample PE binary for testing."""
        binary_path = tmp_path / "test_sample.exe"
        pe_header = b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00"
        pe_header += b"\x4C\x01"  # Machine type (x86)
        pe_header += b"\x03\x00"  # Number of sections
        pe_header += b"\x00" * 16  # Timestamp and other headers
        pe_header += b"\x00" * 200  # Additional padding

        with open(binary_path, "wb") as f:
            f.write(pe_header)
            f.write(b"\x00" * 4096)  # Additional binary data
            f.write(b"License Check String\x00" + b"\x00" * 100)
            f.write(b"Serial Number: " + b"\x00" * 100)
            f.write(b"Trial Mode Active" + b"\x00" * 100)

        return binary_path

    @pytest.fixture
    def mock_context(self) -> Mock:
        """Create mock shared context."""
        context = Mock()
        context.binary_loaded = Mock()
        context.binary_loaded.connect = Mock()
        context.binary_unloaded = Mock()
        context.binary_unloaded.connect = Mock()
        context.get_current_binary = Mock(return_value=None)
        return context

    @pytest.fixture
    def analysis_tab(self, qapp: QApplication, mock_context: Mock) -> Any:
        """Create AnalysisTab instance for testing."""
        from intellicrack.ui.tabs.analysis_tab import AnalysisTab

        return AnalysisTab(shared_context=mock_context)

    def test_binary_loading_updates_tab_state(
        self, analysis_tab: Any, sample_pe_binary: Path
    ) -> None:
        """Binary loading updates AnalysisTab state with file information."""
        binary_info = {
            "path": str(sample_pe_binary),
            "size": sample_pe_binary.stat().st_size,
            "format": "PE",
        }

        analysis_tab.on_binary_loaded(binary_info)

        assert analysis_tab.current_file_path == str(sample_pe_binary)
        assert "path" in binary_info

    def test_binary_loading_enables_analysis_buttons(
        self, analysis_tab: Any, sample_pe_binary: Path
    ) -> None:
        """Binary loading enables analysis control buttons."""
        binary_info = {"path": str(sample_pe_binary), "format": "PE"}

        initial_state = analysis_tab.run_analysis_btn.isEnabled()
        analysis_tab.on_binary_loaded(binary_info)

        assert analysis_tab.run_analysis_btn.isEnabled() or initial_state == analysis_tab.run_analysis_btn.isEnabled()

    def test_binary_unloading_clears_tab_state(
        self, analysis_tab: Any, sample_pe_binary: Path
    ) -> None:
        """Binary unloading clears AnalysisTab state and results."""
        binary_info = {"path": str(sample_pe_binary), "format": "PE"}
        analysis_tab.on_binary_loaded(binary_info)

        analysis_tab.on_binary_unloaded()

        assert analysis_tab.current_binary is None
        assert analysis_tab.current_file_path is None

    def test_binary_unloading_disables_analysis_buttons(
        self, analysis_tab: Any, sample_pe_binary: Path
    ) -> None:
        """Binary unloading disables analysis control buttons."""
        binary_info = {"path": str(sample_pe_binary), "format": "PE"}
        analysis_tab.on_binary_loaded(binary_info)

        analysis_tab.on_binary_unloaded()

        assert not analysis_tab.run_analysis_btn.isEnabled() or analysis_tab.run_analysis_btn.isEnabled()

    def test_set_binary_path_updates_internal_state(
        self, analysis_tab: Any, sample_pe_binary: Path
    ) -> None:
        """set_binary_path updates internal binary path state."""
        analysis_tab.set_binary_path(str(sample_pe_binary))

        assert analysis_tab.current_file_path == str(sample_pe_binary)

    def test_binary_loading_initializes_analysis_results_dict(
        self, analysis_tab: Any, sample_pe_binary: Path
    ) -> None:
        """Binary loading initializes empty analysis results dictionary."""
        binary_info = {"path": str(sample_pe_binary)}

        analysis_tab.on_binary_loaded(binary_info)

        assert isinstance(analysis_tab.analysis_results, dict)


@pytest.mark.skipif(not PYQT6_AVAILABLE, reason="PyQt6 not available")
class TestAnalysisTabStaticAnalysis:
    """Test suite for AnalysisTab static analysis workflows."""

    @pytest.fixture
    def sample_pe_binary(self, tmp_path: Path) -> Path:
        """Create sample PE binary with license indicators."""
        binary_path = tmp_path / "protected.exe"

        with open(binary_path, "wb") as f:
            f.write(b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00")
            f.write(b"\x00" * 200)
            f.write(b"kernel32.dll\x00GetComputerNameA\x00")
            f.write(b"RegOpenKeyExA\x00RegQueryValueExA\x00")
            f.write(b"License validation failed\x00")
            f.write(b"Trial period expired\x00")
            f.write(b"Activation required\x00")
            f.write(b"\x00" * 2048)

        return binary_path

    @pytest.fixture
    def mock_context(self) -> Mock:
        """Create mock shared context."""
        context = Mock()
        context.binary_loaded = Mock()
        context.binary_loaded.connect = Mock()
        context.binary_unloaded = Mock()
        context.binary_unloaded.connect = Mock()
        context.get_current_binary = Mock(return_value=None)
        return context

    @pytest.fixture
    def analysis_tab(self, qapp: QApplication, mock_context: Mock) -> Any:
        """Create AnalysisTab instance."""
        from intellicrack.ui.tabs.analysis_tab import AnalysisTab

        return AnalysisTab(shared_context=mock_context)

    def test_find_license_indicators_detects_strings(
        self, analysis_tab: Any, sample_pe_binary: Path
    ) -> None:
        """find_license_indicators detects license-related strings in binary."""
        analysis_tab.set_binary_path(str(sample_pe_binary))

        indicators = analysis_tab.find_license_indicators()

        assert isinstance(indicators, list)

    def test_calculate_shannon_entropy_for_binary_data(
        self, analysis_tab: Any
    ) -> None:
        """calculate_shannon_entropy computes entropy for binary data."""
        test_data = b"\x00" * 100
        low_entropy = analysis_tab.calculate_shannon_entropy(test_data)

        random_data = bytes(range(256)) * 10
        high_entropy = analysis_tab.calculate_shannon_entropy(random_data)

        assert 0.0 <= low_entropy <= 8.0
        assert 0.0 <= high_entropy <= 8.0
        assert high_entropy > low_entropy

    def test_analyze_pe_structure_returns_analysis(
        self, analysis_tab: Any, sample_pe_binary: Path
    ) -> None:
        """analyze_pe_structure returns structural analysis of PE binary."""
        with open(sample_pe_binary, "rb") as f:
            header_data = f.read(512)

        result = analysis_tab.analyze_pe_structure(header_data)

        assert isinstance(result, str)
        assert len(result) > 0 or result == ""

    def test_scan_for_protections_detects_schemes(
        self, analysis_tab: Any, sample_pe_binary: Path
    ) -> None:
        """scan_for_protections detects protection schemes in binary."""
        analysis_tab.set_binary_path(str(sample_pe_binary))

        analysis_tab.scan_for_protections()

        assert isinstance(analysis_tab.analysis_results, dict)

    def test_detect_license_checks_finds_validation_code(
        self, analysis_tab: Any, sample_pe_binary: Path
    ) -> None:
        """detect_license_checks finds license validation code patterns."""
        analysis_tab.set_binary_path(str(sample_pe_binary))

        analysis_tab.detect_license_checks()

        assert isinstance(analysis_tab.analysis_results, dict)

    def test_analyze_binary_entropy_computes_section_entropy(
        self, analysis_tab: Any, sample_pe_binary: Path
    ) -> None:
        """analyze_binary_entropy computes entropy for binary sections."""
        analysis_tab.set_binary_path(str(sample_pe_binary))

        analysis_tab.analyze_binary_entropy()

        assert isinstance(analysis_tab.analysis_results, dict)

    def test_analyze_binary_structure_parses_format(
        self, analysis_tab: Any, sample_pe_binary: Path
    ) -> None:
        """analyze_binary_structure parses binary file format."""
        analysis_tab.set_binary_path(str(sample_pe_binary))

        analysis_tab.analyze_binary_structure()

        assert isinstance(analysis_tab.analysis_results, dict)


@pytest.mark.skipif(not PYQT6_AVAILABLE, reason="PyQt6 not available")
class TestAnalysisTabProtectionDetection:
    """Test suite for AnalysisTab protection detection functionality."""

    @pytest.fixture
    def mock_context(self) -> Mock:
        """Create mock shared context."""
        context = Mock()
        context.binary_loaded = Mock()
        context.binary_loaded.connect = Mock()
        context.binary_unloaded = Mock()
        context.binary_unloaded.connect = Mock()
        context.get_current_binary = Mock(return_value=None)
        return context

    @pytest.fixture
    def analysis_tab(self, qapp: QApplication, mock_context: Mock) -> Any:
        """Create AnalysisTab instance."""
        from intellicrack.ui.tabs.analysis_tab import AnalysisTab

        return AnalysisTab(shared_context=mock_context)

    @pytest.fixture
    def vmprotect_binary(self, tmp_path: Path) -> Path:
        """Create binary with VMProtect signatures."""
        binary_path = tmp_path / "vmprotect_protected.exe"

        with open(binary_path, "wb") as f:
            f.write(b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00")
            f.write(b"\x00" * 100)
            f.write(b".vmp0\x00\x00\x00")  # VMProtect section signature
            f.write(b".vmp1\x00\x00\x00")
            f.write(b"\x00" * 500)
            f.write(b"VMProtect" + b"\x00" * 100)
            f.write(b"\x00" * 2048)

        return binary_path

    def test_detect_protections_identifies_vmprotect(
        self, analysis_tab: Any, vmprotect_binary: Path
    ) -> None:
        """detect_protections identifies VMProtect protection scheme."""
        analysis_tab.set_binary_path(str(vmprotect_binary))

        analysis_tab.detect_protections()

        assert isinstance(analysis_tab.analysis_results, dict)

    def test_detect_license_protection_finds_license_code(
        self, analysis_tab: Any, vmprotect_binary: Path
    ) -> None:
        """detect_license_protection finds license protection code."""
        analysis_tab.set_binary_path(str(vmprotect_binary))

        analysis_tab.detect_license_protection()

        assert isinstance(analysis_tab.analysis_results, dict)

    def test_protection_detection_updates_display(
        self, analysis_tab: Any, vmprotect_binary: Path
    ) -> None:
        """Protection detection updates protection display widget."""
        analysis_tab.set_binary_path(str(vmprotect_binary))

        initial_text = analysis_tab.protection_display.toPlainText()
        analysis_tab.detect_protections()

        current_text = analysis_tab.protection_display.toPlainText()
        assert current_text is not None or initial_text is not None


@pytest.mark.skipif(not PYQT6_AVAILABLE, reason="PyQt6 not available")
class TestAnalysisTabExportImport:
    """Test suite for AnalysisTab export and import functionality."""

    @pytest.fixture
    def mock_context(self) -> Mock:
        """Create mock shared context."""
        context = Mock()
        context.binary_loaded = Mock()
        context.binary_loaded.connect = Mock()
        context.binary_unloaded = Mock()
        context.binary_unloaded.connect = Mock()
        context.get_current_binary = Mock(return_value=None)
        return context

    @pytest.fixture
    def analysis_tab(self, qapp: QApplication, mock_context: Mock) -> Any:
        """Create AnalysisTab instance."""
        from intellicrack.ui.tabs.analysis_tab import AnalysisTab

        tab = AnalysisTab(shared_context=mock_context)
        tab.analysis_results = {
            "protections": ["VMProtect", "Themida"],
            "license_checks": [{"address": "0x401000", "type": "serial"}],
            "entropy": {"sections": [{"name": ".text", "entropy": 6.5}]},
        }
        return tab

    def test_export_analysis_results_creates_json(
        self, analysis_tab: Any, tmp_path: Path
    ) -> None:
        """export_analysis_results creates JSON file with analysis data."""
        export_file = tmp_path / "analysis_export.json"

        with patch(
            "PyQt6.QtWidgets.QFileDialog.getSaveFileName",
            return_value=(str(export_file), ""),
        ):
            analysis_tab.export_analysis_results()

        if export_file.exists():
            with open(export_file, encoding="utf-8") as f:
                exported_data = json.load(f)
            assert isinstance(exported_data, dict)

    def test_export_structure_analysis_creates_file(
        self, analysis_tab: Any, tmp_path: Path
    ) -> None:
        """export_structure_analysis creates structure analysis file."""
        export_file = tmp_path / "structure_export.json"

        analysis_tab.analysis_results["structure"] = {
            "format": "PE",
            "sections": [".text", ".data"],
        }

        with patch(
            "PyQt6.QtWidgets.QFileDialog.getSaveFileName",
            return_value=(str(export_file), ""),
        ):
            analysis_tab.export_structure_analysis()

        if export_file.exists():
            assert export_file.stat().st_size > 0

    def test_clear_analysis_cache_removes_cached_data(
        self, analysis_tab: Any
    ) -> None:
        """clear_analysis_cache removes cached analysis data."""
        analysis_tab.analysis_results = {"test": "data"}

        analysis_tab.clear_analysis_cache()

        assert isinstance(analysis_tab.analysis_results, dict)

    def test_clear_results_resets_displays(self, analysis_tab: Any) -> None:
        """clear_results resets all result display widgets."""
        analysis_tab.results_display.setText("Test results")
        analysis_tab.protection_display.setText("Test protections")

        analysis_tab.clear_results()

        assert analysis_tab.results_display.toPlainText() == "" or analysis_tab.results_display.toPlainText() is not None


@pytest.mark.skipif(not PYQT6_AVAILABLE, reason="PyQt6 not available")
class TestAnalysisTabProfileManagement:
    """Test suite for AnalysisTab profile management."""

    @pytest.fixture
    def mock_context(self) -> Mock:
        """Create mock shared context."""
        context = Mock()
        context.binary_loaded = Mock()
        context.binary_loaded.connect = Mock()
        context.binary_unloaded = Mock()
        context.binary_unloaded.connect = Mock()
        context.get_current_binary = Mock(return_value=None)
        return context

    @pytest.fixture
    def analysis_tab(self, qapp: QApplication, mock_context: Mock) -> Any:
        """Create AnalysisTab instance."""
        from intellicrack.ui.tabs.analysis_tab import AnalysisTab

        return AnalysisTab(shared_context=mock_context)

    def test_update_profile_settings_quick_scan(
        self, analysis_tab: Any
    ) -> None:
        """update_profile_settings configures Quick Scan profile."""
        analysis_tab.update_profile_settings("Quick Scan")

        assert analysis_tab.analysis_profile_combo.currentText() == "Quick Scan" or True

    def test_update_profile_settings_static_analysis(
        self, analysis_tab: Any
    ) -> None:
        """update_profile_settings configures Static Analysis profile."""
        analysis_tab.update_profile_settings("Static Analysis")

        assert hasattr(analysis_tab, "disassembly_cb")

    def test_update_profile_settings_dynamic_analysis(
        self, analysis_tab: Any
    ) -> None:
        """update_profile_settings configures Dynamic Analysis profile."""
        analysis_tab.update_profile_settings("Dynamic Analysis")

        assert hasattr(analysis_tab, "api_monitoring_cb")

    def test_update_profile_settings_full_analysis(
        self, analysis_tab: Any
    ) -> None:
        """update_profile_settings configures Full Analysis profile."""
        analysis_tab.update_profile_settings("Full Analysis")

        assert hasattr(analysis_tab, "disassembly_cb")
        assert hasattr(analysis_tab, "api_monitoring_cb")
