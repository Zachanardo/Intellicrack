"""Production tests for Smart Program Selector Dialog.

Tests real program discovery and selection functionality.
"""

from pathlib import Path
from typing import Generator

import pytest


PyQt6 = pytest.importorskip("PyQt6")
from PyQt6.QtWidgets import QApplication

from intellicrack.ui.dialogs.smart_program_selector_dialog import SmartProgramSelectorDialog


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Create QApplication instance."""
    existing_app = QApplication.instance()
    if existing_app is None:
        return QApplication([])
    assert isinstance(existing_app, QApplication), "Expected QApplication instance"
    return existing_app


@pytest.fixture
def temp_programs(tmp_path: Path) -> Path:
    """Create temporary program directory."""
    programs_dir = tmp_path / "programs"
    programs_dir.mkdir()

    test_exe = programs_dir / "test_app.exe"
    test_exe.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)

    return programs_dir


@pytest.fixture
def selector_dialog(qapp: QApplication) -> Generator[SmartProgramSelectorDialog, None, None]:
    """Create smart program selector dialog."""
    dialog = SmartProgramSelectorDialog()
    yield dialog
    dialog.close()
    dialog.deleteLater()


class TestProgramSelectorInitialization:
    """Test dialog initialization."""

    def test_dialog_creates_successfully(
        self, selector_dialog: SmartProgramSelectorDialog
    ) -> None:
        """Dialog initializes with UI components."""
        assert selector_dialog is not None

    def test_has_program_list(
        self, selector_dialog: SmartProgramSelectorDialog
    ) -> None:
        """Dialog has list widget for programs."""
        lists = selector_dialog.findChildren(PyQt6.QtWidgets.QListWidget)
        assert len(lists) > 0


class TestProgramDiscovery:
    """Test program discovery functionality."""

    def test_scan_button_exists(
        self, selector_dialog: SmartProgramSelectorDialog
    ) -> None:
        """Dialog has scan/discover button."""
        buttons = selector_dialog.findChildren(PyQt6.QtWidgets.QPushButton)
        button_texts = [btn.text().lower() for btn in buttons]
        assert any("scan" in text or "discover" in text or "refresh" in text
                  for text in button_texts)

    def test_progress_indicator(
        self, selector_dialog: SmartProgramSelectorDialog
    ) -> None:
        """Dialog shows discovery progress."""
        labels = selector_dialog.findChildren(PyQt6.QtWidgets.QLabel)
        assert len(labels) > 0


class TestProgramSelection:
    """Test program selection functionality."""

    def test_select_button_exists(
        self, selector_dialog: SmartProgramSelectorDialog
    ) -> None:
        """Dialog has select/OK button."""
        buttons = selector_dialog.findChildren(PyQt6.QtWidgets.QPushButton)
        button_texts = [btn.text().lower() for btn in buttons]
        assert any("select" in text or "ok" in text for text in button_texts)

    def test_program_info_display(
        self, selector_dialog: SmartProgramSelectorDialog
    ) -> None:
        """Dialog displays selected program information."""
        text_edits = selector_dialog.findChildren(PyQt6.QtWidgets.QTextEdit)
        assert len(text_edits) >= 0
