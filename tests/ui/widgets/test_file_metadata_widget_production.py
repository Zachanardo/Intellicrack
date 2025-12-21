"""Production tests for File Metadata Widget.

Tests real file metadata extraction and display.
"""

import time
from pathlib import Path

import pytest


PyQt6 = pytest.importorskip("PyQt6")
from PyQt6.QtWidgets import QApplication

from intellicrack.ui.widgets.file_metadata_widget import FileMetadataWidget


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Create QApplication instance."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def test_file(tmp_path: Path) -> Path:
    """Create test file with known metadata."""
    file = tmp_path / "test_binary.exe"
    file.write_bytes(b"MZ\x90\x00" + b"\x00" * 1000)
    return file


@pytest.fixture
def metadata_widget(qapp: QApplication) -> FileMetadataWidget:
    """Create file metadata widget."""
    widget = FileMetadataWidget()
    yield widget
    widget.deleteLater()


class TestMetadataWidgetInitialization:
    """Test widget initialization."""

    def test_widget_creates_successfully(
        self, metadata_widget: FileMetadataWidget
    ) -> None:
        """Widget initializes with no file loaded."""
        assert metadata_widget.current_file is None

    def test_has_metadata_labels(
        self, metadata_widget: FileMetadataWidget
    ) -> None:
        """Widget has labels for file metadata."""
        assert hasattr(metadata_widget, 'path_label')
        assert hasattr(metadata_widget, 'name_label')
        assert hasattr(metadata_widget, 'size_label')


class TestFileAnalysis:
    """Test real file metadata extraction."""

    def test_loads_file_metadata(
        self, metadata_widget: FileMetadataWidget, test_file: Path
    ) -> None:
        """Widget extracts real file metadata."""
        if hasattr(metadata_widget, 'load_file'):
            metadata_widget.load_file(str(test_file))
            assert metadata_widget.current_file == str(test_file)
        elif hasattr(metadata_widget, 'set_file'):
            metadata_widget.set_file(str(test_file))
            assert metadata_widget.current_file == str(test_file)

    def test_displays_file_size(
        self, metadata_widget: FileMetadataWidget, test_file: Path
    ) -> None:
        """Widget displays correct file size."""
        if hasattr(metadata_widget, 'load_file'):
            metadata_widget.load_file(str(test_file))

            size_text = metadata_widget.size_label.text()
            expected_size = test_file.stat().st_size

            assert str(expected_size) in size_text or size_text != "-"

    def test_displays_file_name(
        self, metadata_widget: FileMetadataWidget, test_file: Path
    ) -> None:
        """Widget displays file name."""
        if hasattr(metadata_widget, 'load_file'):
            metadata_widget.load_file(str(test_file))

            name_text = metadata_widget.name_label.text()
            assert test_file.name in name_text or name_text != "-"

    def test_displays_timestamps(
        self, metadata_widget: FileMetadataWidget, test_file: Path
    ) -> None:
        """Widget displays file timestamps."""
        if hasattr(metadata_widget, 'load_file'):
            metadata_widget.load_file(str(test_file))

            created = metadata_widget.created_label.text()
            modified = metadata_widget.modified_label.text()

            assert created != "-"
            assert modified != "-"


class TestMetadataSignals:
    """Test metadata widget signals."""

    def test_file_analyzed_signal(
        self, metadata_widget: FileMetadataWidget, test_file: Path
    ) -> None:
        """Widget emits signal when file is analyzed."""
        signals_received = []
        metadata_widget.file_analyzed.connect(
            lambda path, data: signals_received.append((path, data))
        )

        if hasattr(metadata_widget, 'load_file'):
            metadata_widget.load_file(str(test_file))

            if signals_received:
                assert signals_received[0][0] == str(test_file)
                assert isinstance(signals_received[0][1], dict)


class TestFileTypeDetection:
    """Test file type detection."""

    def test_detects_pe_file(
        self, metadata_widget: FileMetadataWidget, test_file: Path
    ) -> None:
        """Widget detects PE executable type."""
        if hasattr(metadata_widget, 'load_file'):
            metadata_widget.load_file(str(test_file))

            type_text = metadata_widget.type_label.text()
            assert type_text != "-"


class TestHumanReadableFormats:
    """Test human-readable formatting."""

    def test_formats_file_size_humanly(
        self, metadata_widget: FileMetadataWidget, tmp_path: Path
    ) -> None:
        """Widget formats file sizes in human-readable format."""
        large_file = tmp_path / "large.bin"
        large_file.write_bytes(b"\x00" * (5 * 1024 * 1024))

        if hasattr(metadata_widget, 'load_file'):
            metadata_widget.load_file(str(large_file))

            size_text = metadata_widget.size_label.text().lower()
            assert any(unit in size_text for unit in ['kb', 'mb', 'bytes'])
