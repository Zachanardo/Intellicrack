"""API for the enhanced hex viewer/editor.

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

import logging
import os
from typing import Any

from PyQt6.QtWidgets import QApplication, QDialog, QWidget

from .ai_bridge import AIBinaryBridge, BinaryContextBuilder
from .file_handler import VirtualFileAccess
from .hex_dialog import HexViewerDialog
from .hex_widget import HexViewerWidget
from .integration import integrate_enhanced_hex_viewer, register_hex_viewer_ai_tools


logger = logging.getLogger("Intellicrack.HexView")


# File operations


def open_hex_file(file_path: str, read_only: bool = True) -> VirtualFileAccess | None:
    """Open a file for hex viewing/editing.

    Args:
        file_path: Path to the file to open.
        read_only: Whether to open the file in read-only mode.

    Returns:
        VirtualFileAccess instance or None if the file couldn't be opened.

    """
    try:
        if not os.path.exists(file_path):
            logger.exception("File not found: %s", file_path)
            return None

        file_handler = VirtualFileAccess(file_path, read_only)
        logger.info("Opened file %s for hex viewing/editing", file_path)
        return file_handler
    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error opening file: %s", e)
        return None


def read_hex_region(file_path: str, offset: int, size: int) -> bytes | None:
    """Read a region of a file as binary data.

    Args:
        file_path: Path to the file to read.
        offset: Starting offset in bytes.
        size: Number of bytes to read.

    Returns:
        Binary data or None if the file couldn't be read.

    """
    try:
        file_handler = open_hex_file(file_path, True)
        return file_handler.read(offset, size) if file_handler else None
    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error reading hex region: %s", e)
        return None


def write_hex_region(file_path: str, offset: int, data: bytes) -> bool:
    """Write binary data to a region of a file.

    Args:
        file_path: Path to the file to write.
        offset: Starting offset in bytes.
        data: Binary data to write.

    Returns:
        True if the write was successful, False otherwise.

    """
    try:
        file_handler = open_hex_file(file_path, False)
        if not file_handler:
            return False

        result = file_handler.write(offset, data)
        if result:
            file_handler.apply_edits()

        return result
    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error writing hex region: %s", e)
        return False


# Analysis operations


def analyze_binary_data(data: bytes, query: str | None = None, model_manager: object | None = None) -> dict[str, Any]:
    """Analyze binary data using AI assistance.

    Args:
        data: Binary data to analyze.
        query: User query to guide the analysis, or None.
        model_manager: Model manager instance, or None.

    Returns:
        Dictionary with analysis results, or dict with error key on failure.

    """
    try:
        ai_bridge = AIBinaryBridge(model_manager)
        return ai_bridge.analyze_binary_region(data, 0, len(data), query)
    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error analyzing binary data: %s", e)
        return {"error": str(e)}


def search_binary_pattern(data: bytes, pattern_desc: str, model_manager: object | None = None) -> list[dict[str, Any]]:
    """Search for a pattern in binary data using AI assistance.

    Args:
        data: Binary data to search.
        pattern_desc: Description of the pattern to search for.
        model_manager: Model manager instance, or None.

    Returns:
        List of search results, or empty list on failure.

    """
    try:
        ai_bridge = AIBinaryBridge(model_manager)
        return ai_bridge.search_binary_semantic(data, pattern_desc)
    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error searching binary pattern: %s", e)
        return []


def suggest_binary_edits(data: bytes, edit_intent: str, model_manager: object | None = None) -> dict[str, Any]:
    """Suggest edits to binary data using AI assistance.

    Args:
        data: Binary data to edit.
        edit_intent: Description of the desired edit.
        model_manager: Model manager instance, or None.

    Returns:
        Dictionary with edit suggestions, or dict with error key on failure.

    """
    try:
        ai_bridge = AIBinaryBridge(model_manager)
        return ai_bridge.suggest_edits(data, 0, len(data), edit_intent)
    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error suggesting binary edits: %s", e)
        return {"error": str(e)}


# UI operations


def create_hex_viewer_widget(parent: QWidget | None = None) -> HexViewerWidget:
    """Create a new hex viewer widget.

    Args:
        parent: Parent widget, or None.

    Returns:
        HexViewerWidget instance.

    """
    return HexViewerWidget(parent)


def create_hex_viewer_dialog(parent: QWidget | None = None, file_path: str | None = None, read_only: bool = True) -> HexViewerDialog:
    """Create a new hex viewer dialog.

    Args:
        parent: Parent widget, or None.
        file_path: Path to the file to load, or None.
        read_only: Whether to open the file in read-only mode.

    Returns:
        HexViewerDialog instance.

    """
    return HexViewerDialog(parent, file_path, read_only)


def launch_hex_viewer(file_path: str, read_only: bool = True) -> QDialog:
    """Launch the hex viewer as a standalone application.

    Args:
        file_path: Path to the file to open.
        read_only: Whether to open the file in read-only mode.

    Returns:
        QDialog instance.

    """
    app = QApplication.instance() or QApplication([])
    dialog = create_hex_viewer_dialog(None, file_path, read_only)
    dialog.show()
    app.exec()
    return dialog


# Integration operations


def integrate_with_intellicrack(app_instance: object) -> bool:
    """Integrate the enhanced hex viewer with Intellicrack.

    Args:
        app_instance: Intellicrack application instance.

    Returns:
        True if integration was successful, False otherwise.

    """
    result = integrate_enhanced_hex_viewer(app_instance)
    return result if result is not None else False


def add_hex_viewer_to_application(app_instance: object) -> bool:
    """Add the enhanced hex viewer to an application.

    Args:
        app_instance: Application instance.

    Returns:
        True if the hex viewer was added successfully, False otherwise.

    """
    try:
        from .integration import add_hex_viewer_menu, add_hex_viewer_toolbar_button

        # Add to menu
        add_hex_viewer_menu(app_instance)

        # Add to toolbar
        add_hex_viewer_toolbar_button(app_instance)

        logger.info("Enhanced hex viewer added to application")
        return True
    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error adding hex viewer to application: %s", e)
        return False


def register_ai_tools(app_instance: object) -> bool:
    """Register hex viewer AI tools with the application.

    Args:
        app_instance: Application instance.

    Returns:
        True if tools were registered successfully, False otherwise.

    """
    try:
        register_hex_viewer_ai_tools(app_instance)
        return True
    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Error registering AI tools: %s", e)
        return False


# Utility operations


def bytes_to_hex_string(data: bytes, bytes_per_line: int = 16) -> str:
    """Convert binary data to a formatted hex string.

    Args:
        data: Binary data to convert.
        bytes_per_line: Number of bytes per line.

    Returns:
        Formatted hex string with offset and ASCII representation.

    """
    if not data:
        return ""

    result = []

    for i in range(0, len(data), bytes_per_line):
        line = data[i : i + bytes_per_line]
        hex_part = " ".join(f"{b:02X}" for b in line)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in line)

        result.append(f"{i:08X}: {hex_part.ljust(bytes_per_line * 3 - 1)} | {ascii_part}")

    return "\n".join(result)


def hex_string_to_bytes(hex_string: str) -> bytes:
    """Convert a hex string to binary data.

    Args:
        hex_string: Hex string to convert, may include formatting.

    Returns:
        Binary data.

    """
    # Remove formatting, spaces, line numbers, and ASCII parts
    cleaned = ""

    for line in hex_string.splitlines():
        # Skip empty lines
        if not line.strip():
            continue

        # Check if the line has offset and ASCII parts
        parts = line.split("|")
        hex_part = parts[0]

        # Remove line number/offset if present
        if ":" in hex_part:
            hex_part = hex_part.split(":", 1)[1]

        # Add to cleaned string
        cleaned += f"{hex_part.strip()} "

    # Convert to bytes
    hex_values = cleaned.split()
    result = bytearray()

    for hex_val in hex_values:
        try:
            result.append(int(hex_val, 16))
        except ValueError as e:
            logger.exception("Value error in api: %s", e)
            # Skip invalid hex values

    return bytes(result)


def create_binary_context(data: bytes) -> dict[str, Any]:
    """Create a context dictionary for binary data.

    Args:
        data: Binary data.

    Returns:
        Context dictionary with entropy, strings, and structure hints.

    """
    context_builder = BinaryContextBuilder()
    return context_builder.build_context(
        data,
        0,
        len(data),
        include_entropy=True,
        include_strings=True,
        include_structure_hints=True,
    )


# Main entry point for running as a script
if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        target_file_path = sys.argv[1]
        is_read_only = len(sys.argv) <= 2 or sys.argv[2].lower() != "edit"
        launch_hex_viewer(target_file_path, is_read_only)
    else:
        print("Usage: python -m Intellicrack.hexview.api <file_path> [edit]")
