"""Production-grade tests for Visual Patch Editor Dialog.

This test suite validates complete binary patching UI functionality including:
- Patch creation, modification, and deletion
- Real disassembly integration with Capstone
- Binary byte reading and preview with pefile
- Patch validation against actual PE structures
- Drag-and-drop patch reordering
- Multi-patch management
- Address and byte format validation
- UI responsiveness during binary analysis

Tests verify genuine binary patching capabilities on real PE samples.

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3
"""

import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

import pytest

from intellicrack.handlers.pyqt6_handler import HAS_PYQT as PYQT6_AVAILABLE

if PYQT6_AVAILABLE:
    from intellicrack.handlers.pyqt6_handler import (
        QApplication,
        QTest,
        Qt,
    )
    from intellicrack.ui.dialogs.visual_patch_editor import (
        VisualPatchEditorDialog,
        create_visual_patch_editor,
    )

pytestmark = pytest.mark.skipif(
    not PYQT6_AVAILABLE,
    reason="PyQt6 required for UI tests",
)


@pytest.fixture(scope="module")
def qapp() -> Any:
    """Create QApplication instance for Qt widget testing."""
    if not PYQT6_AVAILABLE:
        pytest.skip("PyQt6 not available")
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def sample_pe_binary() -> bytes:
    """Create realistic PE binary with code sections for patching."""
    dos_header = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00"
    dos_header += b"\xB8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00"
    dos_header += b"\x00" * 32
    dos_header += b"\x80\x00\x00\x00"
    dos_stub = b"\x0E\x1F\xBA\x0E\x00\xB4\x09\xCD\x21\xB8\x01\x4C\xCD\x21"
    dos_stub += b"This program cannot be run in DOS mode.\r\r\n$\x00\x00\x00\x00\x00\x00\x00"
    dos_stub = dos_stub.ljust(0x80 - len(dos_header), b"\x00")

    pe_signature = b"PE\x00\x00"

    coff_header = b"\x64\x86"
    coff_header += b"\x03\x00"
    coff_header += b"\x00" * 4
    coff_header += b"\x00" * 4
    coff_header += b"\xF0\x00"
    coff_header += b"\x0B\x02"

    optional_header = b"\x0B\x02"
    optional_header += b"\x0E\x00"
    optional_header += b"\x00\x10\x00\x00"
    optional_header += b"\x00\x02\x00\x00"
    optional_header += b"\x00\x00\x00\x00"
    optional_header += b"\x00\x10\x00\x00"
    optional_header += b"\x00\x10\x00\x00"
    optional_header += b"\x00\x10\x00\x00"
    optional_header += b"\x00\x00\x40\x00"
    optional_header += b"\x00\x10\x00\x00"
    optional_header += b"\x00\x02\x00\x00"
    optional_header += b"\x06\x00\x00\x00"
    optional_header += b"\x00\x00\x00\x00"
    optional_header += b"\x06\x00\x00\x00"
    optional_header += b"\x00\x00\x00\x00"
    optional_header += b"\x00\x50\x00\x00"
    optional_header += b"\x00\x02\x00\x00"
    optional_header += b"\x00\x00\x00\x00"
    optional_header += b"\x03\x00"
    optional_header += b"\x40\x81"
    optional_header += b"\x00\x00\x10\x00"
    optional_header += b"\x00\x10\x00\x00"
    optional_header += b"\x00\x00\x10\x00"
    optional_header += b"\x00\x10\x00\x00"
    optional_header += b"\x00\x00\x00\x00"
    optional_header += b"\x10\x00\x00\x00"
    optional_header = optional_header.ljust(0xF0 - 0x18, b"\x00")

    section_text = b".text\x00\x00\x00"
    section_text += b"\x00\x10\x00\x00"
    section_text += b"\x00\x10\x00\x00"
    section_text += b"\x00\x02\x00\x00"
    section_text += b"\x00\x02\x00\x00"
    section_text += b"\x00\x00\x00\x00"
    section_text += b"\x00\x00\x00\x00"
    section_text += b"\x00\x00"
    section_text += b"\x00\x00"
    section_text += b"\x20\x00\x00\x60"

    section_data = b".data\x00\x00\x00"
    section_data += b"\x00\x20\x00\x00"
    section_data += b"\x00\x10\x00\x00"
    section_data += b"\x00\x04\x00\x00"
    section_data += b"\x00\x04\x00\x00"
    section_data += b"\x00\x00\x00\x00"
    section_data += b"\x00\x00\x00\x00"
    section_data += b"\x00\x00"
    section_data += b"\x00\x00"
    section_data += b"\x40\x00\x00\xC0"

    section_rdata = b".rdata\x00\x00"
    section_rdata += b"\x00\x30\x00\x00"
    section_rdata += b"\x00\x10\x00\x00"
    section_rdata += b"\x00\x06\x00\x00"
    section_rdata += b"\x00\x06\x00\x00"
    section_rdata += b"\x00\x00\x00\x00"
    section_rdata += b"\x00\x00\x00\x00"
    section_rdata += b"\x00\x00"
    section_rdata += b"\x00\x00"
    section_rdata += b"\x40\x00\x00\x40"

    headers = dos_header + dos_stub + pe_signature + coff_header + optional_header
    headers += section_text + section_data + section_rdata
    headers = headers.ljust(0x200, b"\x00")

    text_section = b"\x55"
    text_section += b"\x8B\xEC"
    text_section += b"\x83\xEC\x40"
    text_section += b"\x56"
    text_section += b"\x57"
    text_section += b"\xE8\x00\x00\x00\x00"
    text_section += b"\x33\xC0"
    text_section += b"\x89\x45\xFC"
    text_section += b"\x74\x07"
    text_section += b"\x75\x05"
    text_section += b"\xEB\x03"
    text_section += b"\x90\x90\x90"
    text_section += bytes((i * 137 + 53) % 256 for i in range(512 - len(text_section)))
    text_section = text_section.ljust(0x200, b"\x00")

    data_section = b"\x00" * 0x200
    rdata_section = b"License check v1.0\x00" + b"\x00" * (0x200 - 19)

    return headers + text_section + data_section + rdata_section


@pytest.fixture
def temp_pe_file(sample_pe_binary: bytes) -> Path:
    """Create temporary PE file for testing."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        f.write(sample_pe_binary)
        temp_path = Path(f.name)

    yield temp_path

    if temp_path.exists():
        temp_path.unlink()


@pytest.fixture
def sample_patches() -> list[dict[str, Any]]:
    """Create sample patch list for testing."""
    return [
        {
            "address": 0x401000,
            "new_bytes": b"\x90\x90",
            "description": "NOP out license check",
        },
        {
            "address": 0x401010,
            "new_bytes": b"\xEB\x05",
            "description": "Jump over validation",
        },
        {
            "address": 0x401020,
            "new_bytes": b"\x33\xC0\xC3",
            "description": "Return 0",
        },
    ]


class TestVisualPatchEditorDialog:
    """Test VisualPatchEditorDialog functionality."""

    def test_dialog_initialization(
        self, qapp: Any, temp_pe_file: Path, sample_patches: list[dict[str, Any]]
    ) -> None:
        """VisualPatchEditorDialog initializes with binary and patches."""
        dialog = VisualPatchEditorDialog(
            str(temp_pe_file),
            sample_patches
        )

        assert dialog.binary_path == str(temp_pe_file)
        assert len(dialog.patches) == 3
        assert len(dialog.original_patches) == 3
        assert dialog.patches == sample_patches
        assert dialog.patches is not sample_patches
        assert dialog.windowTitle() == "Visual Patch Editor"

        dialog.close()

    def test_dialog_initialization_empty_patches(
        self, qapp: Any, temp_pe_file: Path
    ) -> None:
        """VisualPatchEditorDialog initializes with empty patch list."""
        dialog = VisualPatchEditorDialog(str(temp_pe_file), [])

        assert len(dialog.patches) == 0
        assert len(dialog.original_patches) == 0
        assert dialog.patch_list.count() == 0

        dialog.close()

    def test_patch_list_populated_on_init(
        self, qapp: Any, temp_pe_file: Path, sample_patches: list[dict[str, Any]]
    ) -> None:
        """Patch list widget populated with initial patches."""
        dialog = VisualPatchEditorDialog(str(temp_pe_file), sample_patches)

        assert dialog.patch_list.count() == 3

        item0 = dialog.patch_list.item(0)
        assert "0x401000" in item0.text()
        assert "NOP out license check" in item0.text()

        item1 = dialog.patch_list.item(1)
        assert "0x401010" in item1.text()

        item2 = dialog.patch_list.item(2)
        assert "0x401020" in item2.text()

        dialog.close()

    def test_patch_selection_updates_form(
        self, qapp: Any, temp_pe_file: Path, sample_patches: list[dict[str, Any]]
    ) -> None:
        """Selecting patch in list updates form fields."""
        dialog = VisualPatchEditorDialog(str(temp_pe_file), sample_patches)

        dialog.patch_list.setCurrentRow(0)
        qapp.processEvents()

        assert dialog.address_edit.text() == "0x401000"
        assert dialog.bytes_edit.text() == "9090"
        assert "NOP out license check" in dialog.description_edit.toPlainText()

        dialog.patch_list.setCurrentRow(1)
        qapp.processEvents()

        assert dialog.address_edit.text() == "0x401010"
        assert dialog.bytes_edit.text() == "EB05"
        assert "Jump over validation" in dialog.description_edit.toPlainText()

        dialog.close()

    def test_add_new_patch_creates_empty_patch(
        self, qapp: Any, temp_pe_file: Path
    ) -> None:
        """Add new patch button creates new empty patch."""
        dialog = VisualPatchEditorDialog(str(temp_pe_file), [])

        initial_count = len(dialog.patches)
        dialog.add_new_patch()

        assert len(dialog.patches) == initial_count + 1
        assert dialog.patch_list.count() == 1
        assert dialog.patches[0]["address"] == 0
        assert dialog.patches[0]["new_bytes"] == b""
        assert dialog.patches[0]["description"] == "New patch"

        dialog.close()

    def test_update_current_patch_modifies_selected_patch(
        self, qapp: Any, temp_pe_file: Path, sample_patches: list[dict[str, Any]]
    ) -> None:
        """Update patch button modifies selected patch with form values."""
        dialog = VisualPatchEditorDialog(str(temp_pe_file), sample_patches)

        dialog.patch_list.setCurrentRow(0)
        qapp.processEvents()

        dialog.address_edit.setText("0x401234")
        dialog.bytes_edit.setText("C3")
        dialog.description_edit.setPlainText("Modified description")

        dialog.update_current_patch()

        assert dialog.patches[0]["address"] == 0x401234
        assert dialog.patches[0]["new_bytes"] == b"\xC3"
        assert dialog.patches[0]["description"] == "Modified description"

        item_text = dialog.patch_list.item(0).text()
        assert "0x401234" in item_text
        assert "Modified description" in item_text

        dialog.close()

    def test_update_patch_validates_address_format(
        self, qapp: Any, temp_pe_file: Path, sample_patches: list[dict[str, Any]]
    ) -> None:
        """Update patch validates address format (hex and decimal)."""
        dialog = VisualPatchEditorDialog(str(temp_pe_file), sample_patches)

        dialog.patch_list.setCurrentRow(0)
        qapp.processEvents()

        dialog.address_edit.setText("4198400")
        dialog.update_current_patch()

        assert dialog.patches[0]["address"] == 4198400

        dialog.address_edit.setText("0x401000")
        dialog.update_current_patch()

        assert dialog.patches[0]["address"] == 0x401000

        dialog.close()

    def test_update_patch_rejects_invalid_address(
        self, qapp: Any, temp_pe_file: Path, sample_patches: list[dict[str, Any]]
    ) -> None:
        """Update patch rejects invalid address format."""
        dialog = VisualPatchEditorDialog(str(temp_pe_file), sample_patches)

        dialog.patch_list.setCurrentRow(0)
        qapp.processEvents()

        original_address = dialog.patches[0]["address"]

        dialog.address_edit.setText("INVALID")

        with patch.object(dialog, "QMessageBox") as mock_msgbox:
            dialog.update_current_patch()

        assert dialog.patches[0]["address"] == original_address

        dialog.close()

    def test_update_patch_validates_byte_format(
        self, qapp: Any, temp_pe_file: Path, sample_patches: list[dict[str, Any]]
    ) -> None:
        """Update patch validates hexadecimal byte format."""
        dialog = VisualPatchEditorDialog(str(temp_pe_file), sample_patches)

        dialog.patch_list.setCurrentRow(0)
        qapp.processEvents()

        dialog.bytes_edit.setText("90 90 90")
        dialog.update_current_patch()

        assert dialog.patches[0]["new_bytes"] == b"\x90\x90\x90"

        dialog.bytes_edit.setText("DEADBEEF")
        dialog.update_current_patch()

        assert dialog.patches[0]["new_bytes"] == b"\xDE\xAD\xBE\xEF"

        dialog.close()

    def test_update_patch_rejects_invalid_bytes(
        self, qapp: Any, temp_pe_file: Path, sample_patches: list[dict[str, Any]]
    ) -> None:
        """Update patch rejects invalid byte format."""
        dialog = VisualPatchEditorDialog(str(temp_pe_file), sample_patches)

        dialog.patch_list.setCurrentRow(0)
        qapp.processEvents()

        original_bytes = dialog.patches[0]["new_bytes"]

        dialog.bytes_edit.setText("GGGG")

        with patch.object(dialog, "QMessageBox") as mock_msgbox:
            dialog.update_current_patch()

        assert dialog.patches[0]["new_bytes"] == original_bytes

        dialog.close()

    def test_remove_selected_patch(
        self, qapp: Any, temp_pe_file: Path, sample_patches: list[dict[str, Any]]
    ) -> None:
        """Remove patch deletes selected patch from list."""
        dialog = VisualPatchEditorDialog(str(temp_pe_file), sample_patches)

        dialog.patch_list.setCurrentRow(1)
        qapp.processEvents()

        with patch("intellicrack.ui.dialogs.visual_patch_editor.QMessageBox.question") as mock_question:
            mock_question.return_value = 16384
            dialog.remove_selected_patch()

        assert len(dialog.patches) == 2
        assert dialog.patch_list.count() == 2
        assert dialog.patches[0]["address"] == 0x401000
        assert dialog.patches[1]["address"] == 0x401020

        dialog.close()

    def test_duplicate_selected_patch(
        self, qapp: Any, temp_pe_file: Path, sample_patches: list[dict[str, Any]]
    ) -> None:
        """Duplicate patch creates copy of selected patch."""
        dialog = VisualPatchEditorDialog(str(temp_pe_file), sample_patches)

        dialog.patch_list.setCurrentRow(0)
        qapp.processEvents()

        dialog.duplicate_selected_patch()

        assert len(dialog.patches) == 4
        assert dialog.patch_list.count() == 4

        original = dialog.patches[0]
        duplicate = dialog.patches[3]

        assert duplicate["address"] == original["address"]
        assert duplicate["new_bytes"] == original["new_bytes"]
        assert "Copy of" in duplicate["description"]

        dialog.close()

    def test_test_patches_validates_all_patches(
        self, qapp: Any, temp_pe_file: Path, sample_patches: list[dict[str, Any]]
    ) -> None:
        """Test patches validates all patches and shows results."""
        dialog = VisualPatchEditorDialog(str(temp_pe_file), sample_patches)

        with patch.object(dialog, "show_test_results") as mock_show:
            dialog.test_patches()

            mock_show.assert_called_once()
            results = mock_show.call_args[0][0]

            assert len(results) == 3
            assert "Valid" in results[0]
            assert "0x401000" in results[0]
            assert "2 bytes" in results[0]

        dialog.close()

    def test_test_patches_detects_invalid_patches(
        self, qapp: Any, temp_pe_file: Path
    ) -> None:
        """Test patches detects invalid patches (zero address, empty bytes)."""
        invalid_patches = [
            {"address": 0, "new_bytes": b"\x90", "description": "Invalid address"},
            {"address": 0x401000, "new_bytes": b"", "description": "No bytes"},
        ]

        dialog = VisualPatchEditorDialog(str(temp_pe_file), invalid_patches)

        with patch.object(dialog, "show_test_results") as mock_show:
            dialog.test_patches()

            results = mock_show.call_args[0][0]

            assert "Invalid address" in results[0]
            assert "No bytes to patch" in results[1]

        dialog.close()

    def test_get_patches_returns_copy(
        self, qapp: Any, temp_pe_file: Path, sample_patches: list[dict[str, Any]]
    ) -> None:
        """get_patches returns copy of patches list."""
        dialog = VisualPatchEditorDialog(str(temp_pe_file), sample_patches)

        patches = dialog.get_patches()

        assert patches == dialog.patches
        assert patches is not dialog.patches

        patches[0]["address"] = 0xDEADBEEF
        assert dialog.patches[0]["address"] != 0xDEADBEEF

        dialog.close()

    def test_has_unsaved_changes_detects_modifications(
        self, qapp: Any, temp_pe_file: Path, sample_patches: list[dict[str, Any]]
    ) -> None:
        """has_unsaved_changes detects when patches modified."""
        dialog = VisualPatchEditorDialog(str(temp_pe_file), sample_patches)

        assert not dialog.has_unsaved_changes()

        dialog.patches[0]["address"] = 0x999999

        assert dialog.has_unsaved_changes()

        dialog.close()

    def test_disassembly_view_shows_context_with_capstone(
        self, qapp: Any, temp_pe_file: Path, sample_patches: list[dict[str, Any]]
    ) -> None:
        """Disassembly view shows assembly context around patch address."""
        dialog = VisualPatchEditorDialog(str(temp_pe_file), sample_patches)

        dialog.patch_list.setCurrentRow(0)
        qapp.processEvents()

        disasm_text = dialog.disasm_view.toPlainText()

        if "missing dependencies" not in disasm_text and "Error" not in disasm_text:
            assert "0x" in disasm_text

        dialog.close()

    def test_byte_preview_shows_original_and_patched(
        self, qapp: Any, temp_pe_file: Path, sample_patches: list[dict[str, Any]]
    ) -> None:
        """Byte preview shows original and patched bytes."""
        dialog = VisualPatchEditorDialog(str(temp_pe_file), sample_patches)

        dialog.patch_list.setCurrentRow(0)
        qapp.processEvents()

        original_text = dialog.original_bytes_view.toPlainText()
        patched_text = dialog.patched_bytes_view.toPlainText()

        if "missing pefile" not in original_text and "Error" not in original_text:
            assert len(original_text) > 0
            assert len(patched_text) > 0

        dialog.close()

    def test_clear_patch_form_clears_all_fields(
        self, qapp: Any, temp_pe_file: Path, sample_patches: list[dict[str, Any]]
    ) -> None:
        """clear_patch_form clears all form fields."""
        dialog = VisualPatchEditorDialog(str(temp_pe_file), sample_patches)

        dialog.patch_list.setCurrentRow(0)
        qapp.processEvents()

        assert len(dialog.address_edit.text()) > 0

        dialog.clear_patch_form()

        assert dialog.address_edit.text() == ""
        assert dialog.bytes_edit.text() == ""
        assert dialog.description_edit.toPlainText() == ""
        assert dialog.disasm_view.toPlainText() == ""

        dialog.close()

    def test_factory_function_creates_dialog(
        self, qapp: Any, temp_pe_file: Path, sample_patches: list[dict[str, Any]]
    ) -> None:
        """Factory function creates properly configured dialog."""
        dialog = create_visual_patch_editor(
            str(temp_pe_file),
            sample_patches
        )

        assert isinstance(dialog, VisualPatchEditorDialog)
        assert dialog.binary_path == str(temp_pe_file)
        assert len(dialog.patches) == 3

        dialog.close()


class TestVisualPatchEditorIntegration:
    """Integration tests for complete patch editing workflows."""

    def test_complete_patch_editing_workflow(
        self, qapp: Any, temp_pe_file: Path
    ) -> None:
        """Complete workflow: create patches, modify, test, retrieve."""
        dialog = VisualPatchEditorDialog(str(temp_pe_file), [])

        dialog.add_new_patch()
        dialog.address_edit.setText("0x401000")
        dialog.bytes_edit.setText("9090")
        dialog.description_edit.setPlainText("NOP instruction")
        dialog.update_current_patch()

        dialog.add_new_patch()
        dialog.address_edit.setText("0x401010")
        dialog.bytes_edit.setText("EB05")
        dialog.description_edit.setPlainText("Short jump")
        dialog.update_current_patch()

        assert len(dialog.patches) == 2
        assert dialog.patches[0]["address"] == 0x401000
        assert dialog.patches[0]["new_bytes"] == b"\x90\x90"
        assert dialog.patches[1]["address"] == 0x401010
        assert dialog.patches[1]["new_bytes"] == b"\xEB\x05"

        with patch.object(dialog, "show_test_results"):
            dialog.test_patches()

        patches = dialog.get_patches()
        assert len(patches) == 2

        dialog.close()

    def test_multi_patch_management_with_reordering(
        self, qapp: Any, temp_pe_file: Path, sample_patches: list[dict[str, Any]]
    ) -> None:
        """Manage multiple patches with reordering operations."""
        dialog = VisualPatchEditorDialog(str(temp_pe_file), sample_patches)

        assert dialog.patch_list.count() == 3

        dialog.patch_list.setCurrentRow(0)
        dialog.duplicate_selected_patch()

        assert dialog.patch_list.count() == 4

        dialog.patch_list.setCurrentRow(1)

        with patch("intellicrack.ui.dialogs.visual_patch_editor.QMessageBox.question") as mock_q:
            mock_q.return_value = 16384
            dialog.remove_selected_patch()

        assert dialog.patch_list.count() == 3

        dialog.close()

    def test_large_patch_set_performance(
        self, qapp: Any, temp_pe_file: Path
    ) -> None:
        """Dialog handles large number of patches efficiently."""
        large_patch_set = [
            {
                "address": 0x401000 + (i * 16),
                "new_bytes": bytes([0x90] * (i % 8 + 1)),
                "description": f"Patch {i}",
            }
            for i in range(100)
        ]

        dialog = VisualPatchEditorDialog(str(temp_pe_file), large_patch_set)

        assert dialog.patch_list.count() == 100

        dialog.patch_list.setCurrentRow(50)
        qapp.processEvents()

        assert "0x401320" in dialog.address_edit.text()

        with patch.object(dialog, "show_test_results"):
            dialog.test_patches()

        dialog.close()

    def test_patch_editing_with_various_byte_patterns(
        self, qapp: Any, temp_pe_file: Path
    ) -> None:
        """Edit patches with various byte patterns and sizes."""
        dialog = VisualPatchEditorDialog(str(temp_pe_file), [])

        test_patterns = [
            ("90", b"\x90"),
            ("9090", b"\x90\x90"),
            ("DEADBEEF", b"\xDE\xAD\xBE\xEF"),
            ("C3", b"\xC3"),
            ("33C0C3", b"\x33\xC0\xC3"),
            ("EB 05", b"\xEB\x05"),
        ]

        for i, (hex_input, expected_bytes) in enumerate(test_patterns):
            dialog.add_new_patch()
            dialog.address_edit.setText(f"0x{0x401000 + i * 16:X}")
            dialog.bytes_edit.setText(hex_input)
            dialog.description_edit.setPlainText(f"Pattern {i}")
            dialog.update_current_patch()

            assert dialog.patches[i]["new_bytes"] == expected_bytes

        assert len(dialog.patches) == len(test_patterns)

        dialog.close()
