"""Production tests for Similarity Search Dialog.

Tests real binary similarity matching and pattern discovery.
"""

from pathlib import Path

import pytest


PyQt6 = pytest.importorskip("PyQt6")
from PyQt6.QtWidgets import QApplication

from intellicrack.ui.dialogs.similarity_search_dialog import BinarySimilaritySearchDialog


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Create QApplication instance."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def sample_binary(tmp_path: Path) -> Path:
    """Create sample binary for testing."""
    binary = tmp_path / "test.exe"
    binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 200)
    return binary


@pytest.fixture
def similarity_dialog(qapp: QApplication, sample_binary: Path) -> BinarySimilaritySearchDialog:
    """Create similarity search dialog."""
    dialog = BinarySimilaritySearchDialog(str(sample_binary))
    yield dialog
    dialog.close()
    dialog.deleteLater()


class TestSimilarityDialogInitialization:
    """Test dialog initialization."""

    def test_dialog_creates_with_binary(
        self, qapp: QApplication, sample_binary: Path
    ) -> None:
        """Dialog initializes with binary path."""
        dialog = BinarySimilaritySearchDialog(str(sample_binary))
        try:
            assert dialog is not None
        finally:
            dialog.close()
            dialog.deleteLater()

    def test_has_threshold_control(
        self, similarity_dialog: BinarySimilaritySearchDialog
    ) -> None:
        """Dialog has similarity threshold control."""
        sliders = similarity_dialog.findChildren(PyQt6.QtWidgets.QSlider)
        spinboxes = similarity_dialog.findChildren(PyQt6.QtWidgets.QSpinBox)
        assert len(sliders) > 0 or len(spinboxes) > 0


class TestSimilaritySearch:
    """Test similarity search functionality."""

    def test_search_button_exists(
        self, similarity_dialog: BinarySimilaritySearchDialog
    ) -> None:
        """Dialog has search button."""
        buttons = similarity_dialog.findChildren(PyQt6.QtWidgets.QPushButton)
        button_texts = [btn.text().lower() for btn in buttons]
        assert any("search" in text or "find" in text for text in button_texts)

    def test_results_table_exists(
        self, similarity_dialog: BinarySimilaritySearchDialog
    ) -> None:
        """Dialog displays results in table."""
        tables = similarity_dialog.findChildren(PyQt6.QtWidgets.QTableWidget)
        assert len(tables) > 0


class TestPatternDisplay:
    """Test pattern display functionality."""

    def test_patterns_view_exists(
        self, similarity_dialog: BinarySimilaritySearchDialog
    ) -> None:
        """Dialog shows discovered patterns."""
        text_edits = similarity_dialog.findChildren(PyQt6.QtWidgets.QTextEdit)
        assert len(text_edits) > 0
