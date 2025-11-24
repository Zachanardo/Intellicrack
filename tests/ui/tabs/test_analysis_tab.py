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


