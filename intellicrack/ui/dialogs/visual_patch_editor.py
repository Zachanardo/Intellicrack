"""Visual patch editor dialog for graphical binary patching.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import os
from typing import Any

from intellicrack.handlers.pyqt6_handler import (
    QAbstractItemView,
    QDialog,
    QFont,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QSplitter,
    Qt,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)
from intellicrack.utils.logger import logger


"""
Visual Patch Editor Dialog

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""


try:
    from intellicrack.handlers.pefile_handler import pefile

    HAS_PEFILE = True
except ImportError as e:
    logger.error("Import error in visual_patch_editor: %s", e)
    HAS_PEFILE = False

try:
    from intellicrack.handlers.capstone_handler import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

    HAS_CAPSTONE = True
except ImportError as e:
    logger.error("Import error in visual_patch_editor: %s", e)
    HAS_CAPSTONE = False

__all__ = ["VisualPatchEditorDialog"]


class VisualPatchEditorDialog(QDialog):
    """Visual patch editor dialog with drag-and-drop functionality.

    Provides an intuitive interface for creating and managing binary patches
    with real-time disassembly view and byte preview capabilities.
    """

    def __init__(
        self, binary_path: str, patches: list[dict[str, Any]], parent: QWidget | None = None
    ) -> None:
        """Initialize the Visual Patch Editor dialog.

        Args:
            binary_path: Path to the binary file
            patches: List of patch dictionaries to edit
            parent: Parent widget

        """
        super().__init__(parent)
        self.binary_path = binary_path
        self.patches = patches.copy() if patches else []
        self.original_patches = patches.copy() if patches else []
        self.disassembly_cache = {}

        self.setWindowTitle("Visual Patch Editor")
        self.setGeometry(100, 100, 1000, 800)
        self.setModal(True)

        self.init_ui()
        self.populate_patch_list()

    def init_ui(self) -> None:
        """Initialize the user interface."""
        layout = QVBoxLayout(self)

        # Header with binary info
        header_layout = QHBoxLayout()
        header_layout.addWidget(QLabel(f"<b>Binary:</b> {os.path.basename(self.binary_path)}"))
        header_layout.addStretch()
        patch_count_label = QLabel(f"<b>Patches:</b> {len(self.patches)}")
        header_layout.addWidget(patch_count_label)
        layout.addLayout(header_layout)

        # Main splitter
        splitter = QSplitter(Qt.Horizontal)

        # Left panel - Patch list
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)

        # Toolbar for patch list
        list_toolbar = QHBoxLayout()
        add_btn = QPushButton("Add Patch")
        add_btn.clicked.connect(self.add_new_patch)
        list_toolbar.addWidget(add_btn)

        remove_btn = QPushButton("Remove Patch")
        remove_btn.clicked.connect(self.remove_selected_patch)
        list_toolbar.addWidget(remove_btn)

        duplicate_btn = QPushButton("Duplicate")
        duplicate_btn.clicked.connect(self.duplicate_selected_patch)
        list_toolbar.addWidget(duplicate_btn)

        left_layout.addLayout(list_toolbar)

        # Patch list with drag-drop support
        self.patch_list = QListWidget()
        self.patch_list.setDragDropMode(QAbstractItemView.InternalMove)
        self.patch_list.setSelectionMode(QAbstractItemView.SingleSelection)
        self.patch_list.currentItemChanged.connect(self.patch_selected)
        left_layout.addWidget(self.patch_list)

        splitter.addWidget(left_panel)

        # Right panel - Patch editor
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)

        # Patch details form
        form_layout = QFormLayout()

        self.address_edit = QLineEdit()
        self.address_edit.setText("0x401000")
        self.address_edit.setToolTip(
            "Enter memory address in hexadecimal format (e.g., 0x401000 or 401000 in decimal)"
        )
        form_layout.addRow("Address:", self.address_edit)

        self.bytes_edit = QLineEdit()
        self.bytes_edit.setText("9090")
        self.bytes_edit.setToolTip(
            "Enter replacement bytes as hexadecimal without spaces (e.g., 9090909090 for NOP instructions)"
        )
        form_layout.addRow("New Bytes:", self.bytes_edit)

        self.description_edit = QTextEdit()
        self.description_edit.setMaximumHeight(80)
        form_layout.addRow("Description:", self.description_edit)

        # Apply changes button
        update_btn = QPushButton("Update Patch")
        update_btn.clicked.connect(self.update_current_patch)
        form_layout.addRow("", update_btn)

        right_layout.addLayout(form_layout)

        # Disassembly view
        right_layout.addWidget(QLabel("<b>Disassembly Context:</b>"))

        self.disasm_view = QTextEdit()
        self.disasm_view.setReadOnly(True)
        self.disasm_view.setFont(QFont("Courier New", 10))
        right_layout.addWidget(self.disasm_view)

        # Byte preview
        right_layout.addWidget(QLabel("<b>Byte Preview:</b>"))

        byte_preview_layout = QHBoxLayout()

        self.original_bytes_view = QTextEdit()
        self.original_bytes_view.setReadOnly(True)
        self.original_bytes_view.setMaximumHeight(80)
        self.original_bytes_view.setFont(QFont("Courier New", 10))

        self.patched_bytes_view = QTextEdit()
        self.patched_bytes_view.setReadOnly(True)
        self.patched_bytes_view.setMaximumHeight(80)
        self.patched_bytes_view.setFont(QFont("Courier New", 10))

        byte_preview_layout.addWidget(QLabel("Original:"))
        byte_preview_layout.addWidget(self.original_bytes_view)
        byte_preview_layout.addWidget(QLabel("Patched:"))
        byte_preview_layout.addWidget(self.patched_bytes_view)

        right_layout.addLayout(byte_preview_layout)

        splitter.addWidget(right_panel)

        # Set initial sizes
        splitter.setSizes([300, 700])

        layout.addWidget(splitter)

        # Bottom buttons
        button_layout = QHBoxLayout()

        test_btn = QPushButton("Test Patches")
        test_btn.clicked.connect(self.test_patches)
        button_layout.addWidget(test_btn)

        button_layout.addStretch()

        save_btn = QPushButton("Save Changes")
        save_btn.clicked.connect(self.accept)
        button_layout.addWidget(save_btn)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)

        layout.addLayout(button_layout)

        # Status bar
        self.status_label = QLabel("Ready")
        layout.addWidget(self.status_label)

    def populate_patch_list(self) -> None:
        """Populate the patch list with current patches."""
        self.patch_list.clear()

        for i, patch in enumerate(self.patches):
            address = patch.get("address", 0)
            description = patch.get("description", "No description")

            item = QListWidgetItem(f"Patch {i + 1}: 0x{address:X} - {description[:30]}")
            item.setData(Qt.UserRole, i)  # Store patch index
            self.patch_list.addItem(item)

        if self.patches:
            self.patch_list.setCurrentRow(0)

    def patch_selected(
        self, current: QListWidgetItem | None, previous: QListWidgetItem | None
    ) -> None:
        """Handle patch selection in the list.

        Args:
            current: The currently selected list widget item.
            previous: The previously selected list widget item.

        """
        _ = previous
        if not current:
            self.clear_patch_form()
            return

        index = current.data(Qt.UserRole)
        if index < 0 or index >= len(self.patches):
            return

        patch = self.patches[index]

        # Update form
        address = patch.get("address", 0)
        self.address_edit.setText(f"0x{address:X}")

        new_bytes = patch.get("new_bytes", b"")
        if isinstance(new_bytes, bytes):
            self.bytes_edit.setText(new_bytes.hex().upper())
        else:
            self.bytes_edit.setText(str(new_bytes))

        self.description_edit.setText(patch.get("description", ""))

        # Update disassembly view
        self.update_disassembly_view(address)

        # Update byte preview
        self.update_byte_preview(address, new_bytes)

    def clear_patch_form(self) -> None:
        """Clear the patch form."""
        self.address_edit.clear()
        self.bytes_edit.clear()
        self.description_edit.clear()
        self.disasm_view.clear()
        self.original_bytes_view.clear()
        self.patched_bytes_view.clear()

    def update_current_patch(self) -> None:
        """Update the currently selected patch with form values."""
        current_item = self.patch_list.currentItem()
        if not current_item:
            return

        index = current_item.data(Qt.UserRole)
        if index < 0 or index >= len(self.patches):
            return

        # Get form values
        address_text = self.address_edit.text().strip()
        bytes_text = self.bytes_edit.text().strip()
        description = self.description_edit.toPlainText().strip()

        # Validate address
        try:
            if address_text.startswith("0x"):
                address = int(address_text, 16)
            else:
                address = int(address_text)
        except ValueError as e:
            logger.error("Value error in visual_patch_editor: %s", e)
            QMessageBox.warning(
                self, "Invalid Address", "Please enter a valid hexadecimal address."
            )
            return

        # Validate bytes
        try:
            if bytes_text:
                # Remove spaces if present
                bytes_text = bytes_text.replace(" ", "")
                new_bytes = bytes.fromhex(bytes_text)
            else:
                new_bytes = b""
        except ValueError as e:
            logger.error("Value error in visual_patch_editor: %s", e)
            QMessageBox.warning(self, "Invalid Bytes", "Please enter valid hexadecimal bytes.")
            return

        # Update patch
        self.patches[index]["address"] = address
        self.patches[index]["new_bytes"] = new_bytes
        self.patches[index]["description"] = description

        # Update list item
        current_item.setText(f"Patch {index + 1}: 0x{address:X} - {description[:30]}")

        # Update views
        self.update_disassembly_view(address)
        self.update_byte_preview(address, new_bytes)

        self.status_label.setText(f"Updated patch {index + 1}")

    def update_disassembly_view(self, address: int) -> None:
        """Update the disassembly view for the given address."""
        if not HAS_PEFILE or not HAS_CAPSTONE:
            self.disasm_view.setText("Disassembly not available - missing dependencies")
            return

        try:
            # Check if we have cached disassembly
            if address in self.disassembly_cache:
                self.disasm_view.setText(self.disassembly_cache[address])
                return

            # Use pefile to analyze the binary
            pe = pefile.PE(self.binary_path)

            # Determine if 32 or 64 bit
            is_64bit = getattr(pe.FILE_HEADER, "Machine", 0) == 0x8664
            mode = CS_MODE_64 if is_64bit else CS_MODE_32

            section = next(
                (
                    _s
                    for _s in pe.sections
                    if (
                        _s.VirtualAddress
                        <= address - pe.OPTIONAL_HEADER.ImageBase
                        < _s.VirtualAddress + _s.Misc_VirtualSize
                    )
                ),
                None,
            )
            if not section:
                self.disasm_view.setText(f"Address 0x{address:X} not found in any section")
                return

            # Calculate file offset
            offset = (
                address
                - pe.OPTIONAL_HEADER.ImageBase
                - section.VirtualAddress
                + section.PointerToRawData
            )

            # Read bytes from file
            with open(self.binary_path, "rb") as f:
                f.seek(max(0, offset - 16))  # Read some bytes before
                code_data = f.read(64)  # Read some bytes after

            # Disassemble
            md = Cs(CS_ARCH_X86, mode)

            disasm_text = f"Disassembly around 0x{address:X}:\n\n"

            for insn in md.disasm(code_data, max(0, address - 16)):
                disasm_text += (
                    f"=> 0x{insn.address:X}: {insn.mnemonic} {insn.op_str}\n"
                    if insn.address == address
                    else f"   0x{insn.address:X}: {insn.mnemonic} {insn.op_str}\n"
                )
            # Cache the result
            self.disassembly_cache[address] = disasm_text

            self.disasm_view.setText(disasm_text)

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error in visual_patch_editor: %s", e)
            self.disasm_view.setText(f"Error disassembling: {e}")

    def update_byte_preview(self, address: int, new_bytes: bytes) -> None:
        """Update the byte preview for the given address and new bytes."""
        if not HAS_PEFILE:
            self.original_bytes_view.setText("Byte preview not available - missing pefile")
            self.patched_bytes_view.setText("Byte preview not available - missing pefile")
            return

        try:
            pe = pefile.PE(self.binary_path)

            section = next(
                (
                    _s
                    for _s in pe.sections
                    if (
                        _s.VirtualAddress
                        <= address - pe.OPTIONAL_HEADER.ImageBase
                        < _s.VirtualAddress + _s.Misc_VirtualSize
                    )
                ),
                None,
            )
            if not section:
                self.original_bytes_view.setText("Address not found in any section")
                self.patched_bytes_view.setText("Cannot preview patched bytes")
                return

            # Calculate file offset
            offset = (
                address
                - pe.OPTIONAL_HEADER.ImageBase
                - section.VirtualAddress
                + section.PointerToRawData
            )

            # Read original bytes
            with open(self.binary_path, "rb") as f:
                f.seek(offset)
                original_bytes = f.read(max(1, len(new_bytes)))

            # Format original bytes
            original_hex = " ".join(f"{_b:02X}" for _b in original_bytes)
            self.original_bytes_view.setText(original_hex)

            # Format new bytes
            if isinstance(new_bytes, bytes):
                new_hex = " ".join(f"{_b:02X}" for _b in new_bytes)
                self.patched_bytes_view.setText(new_hex)
            else:
                self.patched_bytes_view.setText(str(new_bytes))

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error in visual_patch_editor: %s", e)
            self.original_bytes_view.setText(f"Error: {e}")
            self.patched_bytes_view.setText(f"Error: {e}")

    def add_new_patch(self) -> None:
        """Add a new empty patch."""
        # Create a new patch with default values
        new_patch = {
            "address": 0,
            "new_bytes": b"",
            "description": "New patch",
        }

        # Add to patches list
        self.patches.append(new_patch)

        # Add to list widget
        index = len(self.patches) - 1
        item = QListWidgetItem(f"Patch {index + 1}: 0x0 - New patch")
        item.setData(Qt.UserRole, index)
        self.patch_list.addItem(item)

        # Select the new item
        self.patch_list.setCurrentRow(index)

        self.status_label.setText("Added new patch")

    def remove_selected_patch(self) -> None:
        """Remove the selected patch."""
        current_item = self.patch_list.currentItem()
        if not current_item:
            return

        index = current_item.data(Qt.UserRole)
        if index < 0 or index >= len(self.patches):
            return

        # Confirm deletion
        response = QMessageBox.question(
            self,
            "Remove Patch",
            f"Are you sure you want to remove patch {index + 1}?",
            QMessageBox.Yes | QMessageBox.No,
        )

        if response == QMessageBox.No:
            return

        # Remove patch
        del self.patches[index]

        # Refresh list
        self.populate_patch_list()

        self.status_label.setText(f"Removed patch {index + 1}")

    def duplicate_selected_patch(self) -> None:
        """Duplicate the selected patch."""
        current_item = self.patch_list.currentItem()
        if not current_item:
            return

        index = current_item.data(Qt.UserRole)
        if index < 0 or index >= len(self.patches):
            return

        # Copy patch
        new_patch = self.patches[index].copy()
        new_patch["description"] = f"Copy of {new_patch['description']}"

        # Add to patches list
        self.patches.append(new_patch)

        # Refresh list
        self.populate_patch_list()

        # Select the new item
        self.patch_list.setCurrentRow(len(self.patches) - 1)

        self.status_label.setText(f"Duplicated patch {index + 1}")

    def test_patches(self) -> None:
        """Test the current patches without applying them."""
        if not self.patches:
            QMessageBox.information(self, "No Patches", "No patches to test.")
            return

        # Simple validation check
        validation_results = []
        for i, patch in enumerate(self.patches):
            address = patch.get("address", 0)
            new_bytes = patch.get("new_bytes", b"")

            if address <= 0:
                validation_results.append(f"Patch {i + 1}: Invalid address (0x{address:X})")
            elif not new_bytes:
                validation_results.append(f"Patch {i + 1}: No bytes to patch")
            else:
                validation_results.append(
                    f"Patch {i + 1}: Valid (0x{address:X}, {len(new_bytes)} bytes)"
                )

        # Show results
        self.show_test_results(validation_results)

    def show_test_results(self, results: list[str]) -> None:
        """Show patch test results."""
        # Create a dialog to show results
        dialog = QDialog(self)
        dialog.setWindowTitle("Patch Test Results")
        dialog.setMinimumSize(600, 400)

        layout = QVBoxLayout(dialog)

        result_text = QTextEdit()
        result_text.setReadOnly(True)
        result_text.setFont(QFont("Courier New", 10))
        result_text.setText("\n".join(results))

        layout.addWidget(result_text)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.accept)
        layout.addWidget(close_btn)

        dialog.exec()

        self.status_label.setText("Patch test complete")

    def get_patches(self) -> list[dict[str, Any]]:
        """Get the current list of patches.

        Returns:
            List of patch dictionaries

        """
        return self.patches.copy()

    def has_unsaved_changes(self) -> bool:
        """Check if there are unsaved changes.

        Returns:
            True if patches have been modified

        """
        return self.patches != self.original_patches


def create_visual_patch_editor(
    binary_path: str, patches: list[dict[str, Any]], parent: QWidget | None = None
) -> VisualPatchEditorDialog:
    """Create a VisualPatchEditorDialog.

    Args:
        binary_path: Path to binary file
        patches: List of patch dictionaries
        parent: Parent widget

    Returns:
        Configured dialog instance

    """
    return VisualPatchEditorDialog(binary_path, patches, parent)
