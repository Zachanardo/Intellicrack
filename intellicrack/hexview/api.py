"""
API for the enhanced hex viewer/editor.

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""


import logging
import os
from typing import Any, Dict, List, Optional

from PyQt6.QtWidgets import QApplication, QDialog

from .ai_bridge import AIBinaryBridge, BinaryContextBuilder
from .file_handler import VirtualFileAccess
from .hex_dialog import HexViewerDialog
from .hex_widget import HexViewerWidget
from .integration import (
    integrate_enhanced_hex_viewer,
    register_hex_viewer_ai_tools,
)

logger = logging.getLogger('Intellicrack.HexView')


# File operations

def open_hex_file(file_path: str, read_only: bool = True) -> Optional[VirtualFileAccess]:
    """
    Open a file for hex viewing/editing.

    Args:
        file_path: Path to the file to open
        read_only: Whether to open the file in read-only mode

    Returns:
        VirtualFileAccess instance or None if the file couldn't be opened
    """
    try:
        if not os.path.exists(file_path):
            logger.error("File not found: %s", file_path)
            return None

        file_handler = VirtualFileAccess(file_path, read_only)
        logger.info("Opened file %s for hex viewing/editing", file_path)
        return file_handler
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error opening file: %s", e)
        return None


def read_hex_region(file_path: str, offset: int, size: int) -> Optional[bytes]:
    """
    Read a region of a file as binary data.

    Args:
        file_path: Path to the file to read
        offset: Starting offset
        size: Number of bytes to read

    Returns:
        Binary data or None if the file couldn't be read
    """
    try:
        file_handler = open_hex_file(file_path, True)
        if not file_handler:
            return None

        data = file_handler.read(offset, size)
        return data
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error reading hex region: %s", e)
        return None


def write_hex_region(file_path: str, offset: int, data: bytes) -> bool:
    """
    Write binary data to a region of a file.

    Args:
        file_path: Path to the file to write
        offset: Starting offset
        data: Binary data to write

    Returns:
        True if the write was successful, False otherwise
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
        logger.error("Error writing hex region: %s", e)
        return False


# Analysis operations

def analyze_binary_data(data: bytes, query: Optional[str] = None,
                      model_manager=None) -> Dict[str, Any]:
    """
    Analyze binary data using AI assistance.

    Args:
        data: Binary data to analyze
        query: User query to guide the analysis
        model_manager: Model manager instance

    Returns:
        Dictionary with analysis results
    """
    try:
        ai_bridge = AIBinaryBridge(model_manager)
        result = ai_bridge.analyze_binary_region(data, 0, len(data), query)
        return result
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error analyzing binary data: %s", e)
        return {"error": str(e)}


def search_binary_pattern(data: bytes, pattern_desc: str,
                        model_manager=None) -> List[Dict[str, Any]]:
    """
    Search for a pattern in binary data using AI assistance.

    Args:
        data: Binary data to search
        pattern_desc: Description of the pattern to search for
        model_manager: Model manager instance

    Returns:
        List of search results
    """
    try:
        ai_bridge = AIBinaryBridge(model_manager)
        results = ai_bridge.search_binary_semantic(data, pattern_desc)
        return results
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error searching binary pattern: %s", e)
        return []


def suggest_binary_edits(data: bytes, edit_intent: str,
                       model_manager=None) -> Dict[str, Any]:
    """
    Suggest edits to binary data using AI assistance.

    Args:
        data: Binary data to edit
        edit_intent: Description of the desired edit
        model_manager: Model manager instance

    Returns:
        Dictionary with edit suggestions
    """
    try:
        ai_bridge = AIBinaryBridge(model_manager)
        result = ai_bridge.suggest_edits(data, 0, len(data), edit_intent)
        return result
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error suggesting binary edits: %s", e)
        return {"error": str(e)}


# UI operations

def create_hex_viewer_widget(parent=None) -> HexViewerWidget:
    """
    Create a new hex viewer widget.

    Args:
        parent: Parent widget

    Returns:
        HexViewerWidget instance
    """
    return HexViewerWidget(parent)


def create_hex_viewer_dialog(parent=None, file_path: Optional[str] = None,
                           read_only: bool = True) -> HexViewerDialog:
    """
    Create a new hex viewer dialog.

    Args:
        parent: Parent widget
        file_path: Path to the file to load
        read_only: Whether to open the file in read-only mode

    Returns:
        HexViewerDialog instance
    """
    dialog = HexViewerDialog(parent, file_path, read_only)
    return dialog


def launch_hex_viewer(file_path: str, read_only: bool = True) -> QDialog:
    """
    Launch the hex viewer as a standalone application.

    Args:
        file_path: Path to the file to open
        read_only: Whether to open the file in read-only mode

    Returns:
        QDialog instance
    """
    app = QApplication.instance() or QApplication([])
    dialog = create_hex_viewer_dialog(None, file_path, read_only)
    dialog.show()
    app.exec()
    return dialog


# Integration operations

def integrate_with_intellicrack(app_instance) -> bool:
    """
    Integrate the enhanced hex viewer with Intellicrack.

    Args:
        app_instance: Intellicrack application instance

    Returns:
        True if integration was successful, False otherwise
    """
    return integrate_enhanced_hex_viewer(app_instance)


def add_hex_viewer_to_application(app_instance) -> bool:
    """
    Add the enhanced hex viewer to an application.

    Args:
        app_instance: Application instance

    Returns:
        True if the hex viewer was added successfully, False otherwise
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
        logger.error("Error adding hex viewer to application: %s", e)
        return False


def register_ai_tools(app_instance) -> bool:
    """
    Register hex viewer AI tools with the application.

    Args:
        app_instance: Application instance

    Returns:
        True if tools were registered successfully, False otherwise
    """
    try:
        register_hex_viewer_ai_tools(app_instance)
        return True
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error registering AI tools: %s", e)
        return False


# Utility operations

def bytes_to_hex_string(data: bytes, bytes_per_line: int = 16) -> str:
    """
    Convert binary data to a formatted hex string.

    Args:
        data: Binary data to convert
        bytes_per_line: Number of bytes per line

    Returns:
        Formatted hex string
    """
    if not data:
        return ""

    result = []

    for i in range(0, len(data), bytes_per_line):
        line = data[i:i + bytes_per_line]
        hex_part = " ".join(f"{b:02X}" for b in line)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in line)

        result.append(f"{i:08X}: {hex_part.ljust(bytes_per_line * 3 - 1)} | {ascii_part}")

    return "\n".join(result)


def hex_string_to_bytes(hex_string: str) -> bytes:
    """
    Convert a hex string to binary data.

    Args:
        hex_string: Hex string to convert

    Returns:
        Binary data
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
        cleaned += hex_part.strip() + " "

    # Convert to bytes
    hex_values = cleaned.split()
    result = bytearray()

    for hex_val in hex_values:
        try:
            result.append(int(hex_val, 16))
        except ValueError as e:
            logger.error("Value error in api: %s", e)
            # Skip invalid hex values
            pass

    return bytes(result)


def create_binary_context(data: bytes) -> Dict[str, Any]:
    """
    Create a context dictionary for binary data.

    Args:
        data: Binary data

    Returns:
        Context dictionary
    """
    context_builder = BinaryContextBuilder()
    context = context_builder.build_context(
        data, 0, len(data),
        include_entropy=True,
        include_strings=True,
        include_structure_hints=True
    )
    return context


# Main entry point for running as a script
if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        target_file_path = sys.argv[1]
        is_read_only = len(sys.argv) <= 2 or sys.argv[2].lower() != "edit"
        launch_hex_viewer(target_file_path, is_read_only)
    else:
        print("Usage: python -m Intellicrack.hexview.api <file_path> [edit]")
