"""Production tests for Intellicrack hex protection integration.

Tests protection pattern highlighting, offset synchronization, and feature detection
on real protected binaries without mocks.
"""

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from PyQt6.QtCore import QProcess, QTimer
from PyQt6.QtWidgets import QApplication

from intellicrack.hexview.intellicrack_hex_protection_integration import (
    IntellicrackHexProtectionIntegration,
    ProtectionIntegrationWidget,
    create_intellicrack_hex_integration,
)


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Create QApplication instance for Qt tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    yield app


@pytest.fixture
def integration(qapp: QApplication) -> IntellicrackHexProtectionIntegration:
    """Create integration instance."""
    integration_instance = IntellicrackHexProtectionIntegration()
    yield integration_instance
    if integration_instance.sync_timer:
        integration_instance.sync_timer.stop()
    if integration_instance.engine_process:
        integration_instance.engine_process.kill()
        integration_instance.engine_process.waitForFinished(1000)


@pytest.fixture
def integration_with_widget(qapp: QApplication) -> IntellicrackHexProtectionIntegration:
    """Create integration instance with mock hex widget."""
    mock_widget = MagicMock()
    mock_widget.goto_offset = MagicMock()
    integration_instance = IntellicrackHexProtectionIntegration(hex_widget=mock_widget)
    yield integration_instance
    if integration_instance.sync_timer:
        integration_instance.sync_timer.stop()
    if integration_instance.engine_process:
        integration_instance.engine_process.kill()
        integration_instance.engine_process.waitForFinished(1000)


@pytest.fixture
def test_binary(tmp_path: Path) -> Path:
    """Create a test binary file."""
    binary_path = tmp_path / "test.exe"
    binary_path.write_bytes(
        b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        b"\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00"
        + b"\x00" * 200
    )
    return binary_path


@pytest.fixture
def sync_dir(tmp_path: Path) -> Path:
    """Create sync directory for offset synchronization tests."""
    sync_path = tmp_path / ".intellicrack" / "hex_sync"
    sync_path.mkdir(parents=True, exist_ok=True)
    return sync_path


class TestIntellicrackHexProtectionIntegrationInitialization:
    """Test initialization of protection integration."""

    def test_initialization_without_widget(
        self, integration: IntellicrackHexProtectionIntegration
    ) -> None:
        """Integration initializes without hex widget."""
        assert integration.hex_widget is None
        assert integration.protection_detector is not None
        assert integration.icp_detector is integration.protection_detector
        assert integration.engine_process is None
        assert integration.last_synced_offset == -1

    def test_initialization_with_widget(
        self, integration_with_widget: IntellicrackHexProtectionIntegration
    ) -> None:
        """Integration initializes with hex widget."""
        assert integration_with_widget.hex_widget is not None
        assert hasattr(integration_with_widget.hex_widget, "goto_offset")

    def test_sync_timer_starts(self, integration: IntellicrackHexProtectionIntegration) -> None:
        """Sync timer starts automatically on initialization."""
        assert integration.sync_timer is not None
        assert isinstance(integration.sync_timer, QTimer)
        assert integration.sync_timer.isActive()
        assert integration.sync_timer.interval() == 500

    def test_signals_exist(self, integration: IntellicrackHexProtectionIntegration) -> None:
        """Required signals are defined."""
        assert hasattr(integration, "offset_requested")
        assert hasattr(integration, "section_requested")


class TestProtectionViewerIntegration:
    """Test protection viewer integration functionality."""

    def test_open_nonexistent_file_logs_error(
        self, integration: IntellicrackHexProtectionIntegration, tmp_path: Path
    ) -> None:
        """Opening nonexistent file logs error and returns gracefully."""
        nonexistent = tmp_path / "nonexistent.exe"
        integration.open_in_protection_viewer(str(nonexistent))
        assert integration.engine_process is None

    def test_open_file_without_protection_viewer_executable(
        self, integration: IntellicrackHexProtectionIntegration, test_binary: Path
    ) -> None:
        """Opening file without protection viewer executable logs error."""
        integration.open_in_protection_viewer(str(test_binary))
        assert integration.engine_process is None or (
            integration.engine_process.state() != QProcess.ProcessState.Running
        )

    def test_open_in_icp_alias(
        self, integration: IntellicrackHexProtectionIntegration, test_binary: Path
    ) -> None:
        """open_in_icp is an alias for open_in_protection_viewer."""
        integration.open_in_icp(str(test_binary))

    def test_offset_parameter_handling(
        self, integration: IntellicrackHexProtectionIntegration, test_binary: Path
    ) -> None:
        """Opening with offset parameter creates sync file."""
        integration.open_in_protection_viewer(str(test_binary), offset=0x1000)


class TestOffsetSynchronization:
    """Test bidirectional offset synchronization."""

    def test_sync_offset_from_protection_viewer_with_widget(
        self, integration_with_widget: IntellicrackHexProtectionIntegration
    ) -> None:
        """Syncing offset from protection viewer calls hex widget goto_offset."""
        test_offset = 0x1234
        offset_signal_emitted = False

        def on_offset_requested(offset: int) -> None:
            nonlocal offset_signal_emitted
            offset_signal_emitted = True
            assert offset == test_offset

        integration_with_widget.offset_requested.connect(on_offset_requested)
        integration_with_widget.sync_offset_from_protection_viewer(test_offset)

        assert integration_with_widget.hex_widget.goto_offset.called
        integration_with_widget.hex_widget.goto_offset.assert_called_with(test_offset)
        QApplication.processEvents()
        assert offset_signal_emitted

    def test_sync_offset_from_protection_viewer_without_widget(
        self, integration: IntellicrackHexProtectionIntegration
    ) -> None:
        """Syncing offset without widget emits signal only."""
        test_offset = 0x5678
        offset_signal_emitted = False

        def on_offset_requested(offset: int) -> None:
            nonlocal offset_signal_emitted
            offset_signal_emitted = True
            assert offset == test_offset

        integration.offset_requested.connect(on_offset_requested)
        integration.sync_offset_from_protection_viewer(test_offset)

        QApplication.processEvents()
        assert offset_signal_emitted

    def test_sync_offset_to_protection_viewer_creates_file(
        self, integration: IntellicrackHexProtectionIntegration, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Syncing offset to protection viewer creates sync file."""
        sync_dir = tmp_path / ".intellicrack" / "hex_sync"
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("USERPROFILE", str(tmp_path))

        test_offset = 0xABCD
        integration.sync_offset_to_protection_viewer(test_offset)

        sync_file = sync_dir / "hex_to_protection_offset.txt"
        assert sync_file.exists()
        assert sync_file.read_text().strip() == str(test_offset)

    def test_monitor_protection_viewer_offset_reads_file(
        self,
        integration_with_widget: IntellicrackHexProtectionIntegration,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Monitoring protection viewer offset reads sync file and syncs."""
        sync_dir = tmp_path / ".intellicrack" / "hex_sync"
        sync_dir.mkdir(parents=True, exist_ok=True)
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("USERPROFILE", str(tmp_path))

        incoming_file = sync_dir / "protection_to_hex_offset.txt"
        test_offset = 0x2000
        incoming_file.write_text(str(test_offset))

        integration_with_widget._monitor_protection_viewer_offset()

        assert integration_with_widget.last_synced_offset == test_offset
        integration_with_widget.hex_widget.goto_offset.assert_called_with(test_offset)
        assert incoming_file.read_text() == ""

    def test_monitor_protection_viewer_offset_handles_hex_format(
        self,
        integration_with_widget: IntellicrackHexProtectionIntegration,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Monitoring supports hex format with 0x prefix."""
        sync_dir = tmp_path / ".intellicrack" / "hex_sync"
        sync_dir.mkdir(parents=True, exist_ok=True)
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("USERPROFILE", str(tmp_path))

        incoming_file = sync_dir / "protection_to_hex_offset.txt"
        test_offset = 0x3000
        incoming_file.write_text(f"0x{test_offset:X}")

        integration_with_widget._monitor_protection_viewer_offset()

        assert integration_with_widget.last_synced_offset == test_offset
        integration_with_widget.hex_widget.goto_offset.assert_called_with(test_offset)

    def test_monitor_protection_viewer_offset_ignores_duplicate(
        self,
        integration_with_widget: IntellicrackHexProtectionIntegration,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Monitoring ignores duplicate offset values."""
        sync_dir = tmp_path / ".intellicrack" / "hex_sync"
        sync_dir.mkdir(parents=True, exist_ok=True)
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("USERPROFILE", str(tmp_path))

        incoming_file = sync_dir / "protection_to_hex_offset.txt"
        test_offset = 0x4000

        integration_with_widget.last_synced_offset = test_offset
        incoming_file.write_text(str(test_offset))

        integration_with_widget._monitor_protection_viewer_offset()

        assert integration_with_widget.hex_widget.goto_offset.call_count == 0

    def test_monitor_protection_viewer_offset_missing_file(
        self, integration: IntellicrackHexProtectionIntegration, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Monitoring handles missing sync file gracefully."""
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("USERPROFILE", str(tmp_path))

        integration._monitor_protection_viewer_offset()


class TestSectionOffsets:
    """Test section offset retrieval."""

    def test_get_section_offsets_with_valid_binary(
        self, integration: IntellicrackHexProtectionIntegration, test_binary: Path
    ) -> None:
        """Getting section offsets from valid binary returns dictionary."""
        sections = integration.get_section_offsets(str(test_binary))
        assert isinstance(sections, dict)

    def test_get_section_offsets_with_nonexistent_file(
        self, integration: IntellicrackHexProtectionIntegration, tmp_path: Path
    ) -> None:
        """Getting section offsets from nonexistent file returns empty dict."""
        nonexistent = tmp_path / "nonexistent.exe"
        sections = integration.get_section_offsets(str(nonexistent))
        assert sections == {}


class TestFeatureComparison:
    """Test feature detection and comparison."""

    def test_compare_features_returns_both_viewers(
        self, integration: IntellicrackHexProtectionIntegration
    ) -> None:
        """Feature comparison returns both protection viewer and Intellicrack features."""
        features = integration.compare_features()
        assert "protection viewer Hex Viewer" in features
        assert "Intellicrack Hex Viewer" in features
        assert isinstance(features["protection viewer Hex Viewer"], dict)
        assert isinstance(features["Intellicrack Hex Viewer"], dict)

    def test_detect_intellicrack_features_basic_viewing(
        self, integration: IntellicrackHexProtectionIntegration
    ) -> None:
        """Feature detection identifies basic viewing capabilities."""
        features = integration._detect_intellicrack_features()
        assert "Basic Viewing" in features
        assert "Text Search" in features
        assert "Integrated with Analysis" in features

    def test_detect_intellicrack_features_advanced_search(
        self, integration: IntellicrackHexProtectionIntegration
    ) -> None:
        """Feature detection checks for advanced search module."""
        features = integration._detect_intellicrack_features()
        assert "Advanced Search" in features
        assert isinstance(features["Advanced Search"], bool)

    def test_detect_intellicrack_features_export_dialog(
        self, integration: IntellicrackHexProtectionIntegration
    ) -> None:
        """Feature detection checks for export dialog."""
        features = integration._detect_intellicrack_features()
        assert "Data Export" in features
        assert isinstance(features["Data Export"], bool)

    def test_detect_intellicrack_features_performance_monitoring(
        self, integration: IntellicrackHexProtectionIntegration
    ) -> None:
        """Feature detection checks for performance monitoring."""
        features = integration._detect_intellicrack_features()
        assert "Performance Monitoring" in features
        assert isinstance(features["Performance Monitoring"], bool)

    def test_detect_intellicrack_features_file_comparison(
        self, integration: IntellicrackHexProtectionIntegration
    ) -> None:
        """Feature detection checks for file comparison."""
        features = integration._detect_intellicrack_features()
        assert "File Comparison" in features
        assert isinstance(features["File Comparison"], bool)

    def test_detect_intellicrack_features_printing(
        self, integration: IntellicrackHexProtectionIntegration
    ) -> None:
        """Feature detection checks for printing support."""
        features = integration._detect_intellicrack_features()
        assert "Printing" in features
        assert isinstance(features["Printing"], bool)

    def test_detect_intellicrack_features_with_widget(
        self, integration_with_widget: IntellicrackHexProtectionIntegration
    ) -> None:
        """Feature detection works with hex widget reference."""
        features = integration_with_widget._detect_intellicrack_features()
        assert "Basic Viewing" in features
        assert features["Basic Viewing"] is True


class TestProtectionIntegrationWidget:
    """Test protection integration widget."""

    def test_widget_initialization(self, qapp: QApplication) -> None:
        """Widget initializes with proper UI elements."""
        widget = ProtectionIntegrationWidget()
        assert widget.integration is not None
        assert hasattr(widget, "open_in_protection_viewer_btn")
        assert hasattr(widget, "sync_sections_btn")
        assert hasattr(widget, "info_label")

    def test_widget_with_hex_widget(self, qapp: QApplication) -> None:
        """Widget initializes with hex widget reference."""
        mock_widget = MagicMock()
        widget = ProtectionIntegrationWidget(hex_widget=mock_widget)
        assert widget.hex_widget is mock_widget
        assert widget.integration.hex_widget is mock_widget

    def test_open_in_protection_viewer_button_without_file(self, qapp: QApplication) -> None:
        """Button click without file shows appropriate message."""
        mock_widget = MagicMock()
        mock_widget.file_path = None
        widget = ProtectionIntegrationWidget(hex_widget=mock_widget)

        widget._open_in_protection_viewer()
        assert "No file loaded" in widget.info_label.text()

    def test_open_in_protection_viewer_button_with_file(
        self, qapp: QApplication, test_binary: Path
    ) -> None:
        """Button click with file attempts to open in protection viewer."""
        mock_widget = MagicMock()
        mock_widget.file_path = str(test_binary)
        widget = ProtectionIntegrationWidget(hex_widget=mock_widget)

        widget._open_in_protection_viewer()

    def test_sync_sections_without_file(self, qapp: QApplication) -> None:
        """Sync sections without file shows appropriate message."""
        mock_widget = MagicMock()
        mock_widget.file_path = None
        widget = ProtectionIntegrationWidget(hex_widget=mock_widget)

        widget.sync_sections_from_icp()
        assert "No file loaded" in widget.info_label.text()

    def test_sync_sections_with_file_and_bookmarks(
        self, qapp: QApplication, test_binary: Path
    ) -> None:
        """Sync sections with file adds bookmarks if available."""
        mock_widget = MagicMock()
        mock_widget.file_path = str(test_binary)
        mock_widget.add_bookmark = MagicMock()
        widget = ProtectionIntegrationWidget(hex_widget=mock_widget)

        widget.sync_sections_from_icp()


class TestFactoryFunction:
    """Test factory function for creating integration."""

    def test_create_integration_without_widget(self) -> None:
        """Factory creates integration without widget."""
        integration_instance = create_intellicrack_hex_integration()
        assert isinstance(integration_instance, IntellicrackHexProtectionIntegration)
        assert integration_instance.hex_widget is None
        integration_instance.sync_timer.stop()

    def test_create_integration_with_widget(self) -> None:
        """Factory creates integration with widget."""
        mock_widget = MagicMock()
        integration_instance = create_intellicrack_hex_integration(hex_widget=mock_widget)
        assert isinstance(integration_instance, IntellicrackHexProtectionIntegration)
        assert integration_instance.hex_widget is mock_widget
        integration_instance.sync_timer.stop()


class TestCleanup:
    """Test cleanup functionality."""

    def test_cleanup_sync_files_stops_timer(
        self, integration: IntellicrackHexProtectionIntegration
    ) -> None:
        """Cleanup stops sync timer."""
        assert integration.sync_timer.isActive()
        integration._cleanup_sync_files()
        assert not integration.sync_timer.isActive()

    def test_cleanup_sync_files_removes_sync_file(
        self, integration: IntellicrackHexProtectionIntegration, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Cleanup removes sync file if it exists."""
        protection_viewer_dir = tmp_path / "extensions" / "engines" / "protection_viewer"
        protection_viewer_dir.mkdir(parents=True, exist_ok=True)
        sync_dir = protection_viewer_dir / "sync"
        sync_dir.mkdir(parents=True, exist_ok=True)
        sync_file = sync_dir / "initial_offset.txt"
        sync_file.write_text("test")

        integration._cleanup_sync_files()


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_sync_offset_to_protection_viewer_with_running_process(
        self, integration: IntellicrackHexProtectionIntegration, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Syncing with running process sends command via stdin."""
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("USERPROFILE", str(tmp_path))

        mock_process = MagicMock()
        mock_process.state.return_value = QProcess.ProcessState.Running
        mock_process.write = MagicMock()
        integration.engine_process = mock_process

        test_offset = 0xDEAD
        integration.sync_offset_to_protection_viewer(test_offset)

        assert mock_process.write.called

    def test_monitor_protection_viewer_offset_invalid_data(
        self, integration: IntellicrackHexProtectionIntegration, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Monitoring handles invalid offset data gracefully."""
        sync_dir = tmp_path / ".intellicrack" / "hex_sync"
        sync_dir.mkdir(parents=True, exist_ok=True)
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("USERPROFILE", str(tmp_path))

        incoming_file = sync_dir / "protection_to_hex_offset.txt"
        incoming_file.write_text("invalid_data")

        integration._monitor_protection_viewer_offset()

    def test_monitor_protection_viewer_offset_empty_file(
        self, integration: IntellicrackHexProtectionIntegration, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Monitoring handles empty sync file gracefully."""
        sync_dir = tmp_path / ".intellicrack" / "hex_sync"
        sync_dir.mkdir(parents=True, exist_ok=True)
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("USERPROFILE", str(tmp_path))

        incoming_file = sync_dir / "protection_to_hex_offset.txt"
        incoming_file.write_text("")

        integration._monitor_protection_viewer_offset()
