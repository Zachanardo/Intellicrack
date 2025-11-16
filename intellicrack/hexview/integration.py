"""Integration module for hex viewer functionality."""

from __future__ import annotations

import logging
import os
from collections import Counter
from typing import TYPE_CHECKING, Any

from PyQt6.QtWidgets import QDialog, QMessageBox, QToolBar

from intellicrack.handlers.pyqt6_handler import QAction
from intellicrack.utils.logger import logger

if TYPE_CHECKING:
    from collections.abc import Callable

"""
Integration between enhanced hex viewer/editor and Intellicrack.

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
    from .hex_dialog import HexViewerDialog
except ImportError as e:
    logger.error("Import error in integration: %s", e)
    HexViewerDialog = None

try:
    from .ai_bridge import (
        wrapper_ai_binary_analyze,
        wrapper_ai_binary_edit_suggest,
        wrapper_ai_binary_pattern_search,
    )
except ImportError as e:
    logger.error("Import error in integration: %s", e)

    import re
    from collections import Counter

    def wrapper_ai_binary_analyze(app_instance: Any, parameters: dict[str, Any]) -> dict[str, Any]:
        """Perform static binary analysis when AI bridge is not available.

        Analyzes binary data using entropy calculation, string extraction,
        pattern detection, and structural analysis techniques.

        Args:
            app_instance: Application instance
            parameters: Dictionary with 'data' (bytes) and optional 'offset' (int)

        Returns:
            dict: Analysis results including entropy, strings, patterns, and structure

        """
        try:
            data = parameters.get("data", b"")
            offset = parameters.get("offset", 0)

            if not data:
                return {"analysis": "No data provided for analysis"}

            analysis_results = {
                "entropy": _calculate_entropy(data),
                "size": len(data),
                "offset": offset,
                "strings": _extract_strings(data, min_length=4),
                "patterns": _detect_patterns(data),
                "structure": _analyze_structure(data),
                "byte_distribution": _analyze_byte_distribution(data),
            }

            return {"analysis": analysis_results}
        except Exception as e:
            logger.error("Error in fallback binary analyze: %s", e)
            return {"error": f"Analysis failed: {e!s}"}

    def wrapper_ai_binary_pattern_search(app_instance: Any, parameters: dict[str, Any]) -> dict[str, Any]:
        """Search for patterns in binary data when AI bridge is not available.

        Performs pattern matching using regex, byte sequences, and common
        binary signatures for license checks, validation routines, and protection schemes.

        Args:
            app_instance: Application instance
            parameters: Dictionary with 'data' (bytes), 'pattern' (str), and 'pattern_type' (str)

        Returns:
            dict: Search results with matches and their offsets

        """
        try:
            data = parameters.get("data", b"")
            pattern = parameters.get("pattern", "")
            pattern_type = parameters.get("pattern_type", "hex")

            if not data or not pattern:
                return {"matches": [], "count": 0}

            matches = []

            if pattern_type == "hex":
                search_bytes = bytes.fromhex(pattern.replace(" ", ""))
                idx = 0
                while idx < len(data):
                    pos = data.find(search_bytes, idx)
                    if pos == -1:
                        break
                    matches.append({"offset": pos, "length": len(search_bytes)})
                    idx = pos + 1

            elif pattern_type == "regex":
                for match in re.finditer(pattern.encode(), data):
                    matches.append({"offset": match.start(), "length": len(match.group())})

            elif pattern_type == "string":
                search_bytes = pattern.encode("utf-8")
                idx = 0
                while idx < len(data):
                    pos = data.find(search_bytes, idx)
                    if pos == -1:
                        break
                    matches.append({"offset": pos, "length": len(search_bytes)})
                    idx = pos + 1

            elif pattern_type == "license_check":
                license_patterns = [
                    b"license",
                    b"LICENSE",
                    b"registration",
                    b"REGISTRATION",
                    b"serial",
                    b"SERIAL",
                    b"activation",
                    b"ACTIVATION",
                    b"trial",
                    b"TRIAL",
                    b"expired",
                    b"EXPIRED",
                ]
                for lp in license_patterns:
                    idx = 0
                    while idx < len(data):
                        pos = data.find(lp, idx)
                        if pos == -1:
                            break
                        matches.append({"offset": pos, "length": len(lp), "type": lp.decode("utf-8", errors="ignore")})
                        idx = pos + 1

            return {"matches": matches, "count": len(matches), "pattern": pattern, "pattern_type": pattern_type}
        except Exception as e:
            logger.error("Error in fallback pattern search: %s", e)
            return {"error": f"Pattern search failed: {e!s}"}

    def wrapper_ai_binary_edit_suggest(app_instance: Any, parameters: dict[str, Any]) -> dict[str, Any]:
        """Suggest binary edits for license bypass when AI bridge is not available.

        Analyzes binary code to suggest patches for common license validation
        patterns, including jump instructions, comparison operations, and
        return value modifications.

        Args:
            app_instance: Application instance
            parameters: Dictionary with 'data' (bytes), 'offset' (int), and 'context' (str)

        Returns:
            dict: Edit suggestions with offsets, original bytes, and patch bytes

        """
        try:
            data = parameters.get("data", b"")
            offset = parameters.get("offset", 0)
            context = parameters.get("context", "general")

            if not data:
                return {"suggestions": []}

            suggestions = []

            if context == "license_check":
                for i in range(len(data) - 6):
                    if data[i : i + 2] == b"\x74\x05":
                        suggestions.append(
                            {
                                "offset": offset + i,
                                "description": "Replace JE (jump if equal) with NOP to bypass check",
                                "original": data[i : i + 2].hex(),
                                "patched": "9090",
                                "type": "conditional_jump_bypass",
                            },
                        )
                    elif data[i : i + 2] == b"\x75\x05":
                        suggestions.append(
                            {
                                "offset": offset + i,
                                "description": "Replace JNE (jump if not equal) with NOP to bypass check",
                                "original": data[i : i + 2].hex(),
                                "patched": "9090",
                                "type": "conditional_jump_bypass",
                            },
                        )
                    elif data[i : i + 5] == b"\xe8" + data[i + 1 : i + 5]:
                        suggestions.append(
                            {
                                "offset": offset + i,
                                "description": "Replace CALL instruction with NOPs to skip validation function",
                                "original": data[i : i + 5].hex(),
                                "patched": "9090909090",
                                "type": "call_bypass",
                            },
                        )

            elif context == "return_value":
                for i in range(len(data) - 5):
                    if data[i : i + 5] == b"\xb8\x00\x00\x00\x00":
                        suggestions.append(
                            {
                                "offset": offset + i,
                                "description": "Change return value from 0 to 1 (success)",
                                "original": data[i : i + 5].hex(),
                                "patched": "b801000000",
                                "type": "return_value_modification",
                            },
                        )
                    elif data[i : i + 2] == b"\x31\xc0":
                        suggestions.append(
                            {
                                "offset": offset + i,
                                "description": "Replace XOR EAX,EAX with MOV EAX,1 for success return",
                                "original": data[i : i + 2].hex(),
                                "patched": "b801000000",
                                "type": "return_value_modification",
                            },
                        )

            elif context == "comparison":
                for i in range(len(data) - 6):
                    if data[i : i + 2] in [b"\x3b", b"\x39"]:
                        suggestions.append(
                            {
                                "offset": offset + i,
                                "description": "Replace comparison with operation that always succeeds",
                                "original": data[i : i + 2].hex(),
                                "patched": "3939",
                                "type": "comparison_bypass",
                            },
                        )

            else:
                for i in range(min(len(data) - 2, 100)):
                    if data[i] == 0x74 or data[i] == 0x75:
                        suggestions.append(
                            {
                                "offset": offset + i,
                                "description": f"Conditional jump at offset {offset + i:#x}",
                                "original": data[i : i + 2].hex(),
                                "patched": "9090",
                                "type": "general_conditional_bypass",
                            },
                        )

            return {"suggestions": suggestions, "count": len(suggestions)}
        except Exception as e:
            logger.error("Error in fallback edit suggest: %s", e)
            return {"error": f"Edit suggestion failed: {e!s}"}

    def _calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of binary data."""
        if not data:
            return 0.0
        counter = Counter(data)
        entropy = 0.0
        length = len(data)
        for count in counter.values():
            probability = count / length
            entropy -= probability * ((probability and (probability * 0.434294482)) or 0)
        return entropy * 2.302585093

    def _extract_strings(data: bytes, min_length: int = 4) -> list[str]:
        """Extract printable ASCII strings from binary data."""
        strings: list[str] = []
        current_string = []
        for byte in data:
            if 32 <= byte <= 126:
                current_string.append(chr(byte))
            else:
                if len(current_string) >= min_length:
                    strings.append("".join(current_string))
                current_string = []
        if len(current_string) >= min_length:
            strings.append("".join(current_string))
        return strings[:50]

    def _detect_patterns(data: bytes) -> dict[str, Any]:
        """Detect common binary patterns and signatures."""
        patterns: dict[str, Any] = {}
        if b"MZ" in data[:2]:
            patterns["file_type"] = "PE executable"
        elif b"\x7fELF" in data[:4]:
            patterns["file_type"] = "ELF executable"
        elif b"\xca\xfe\xba\xbe" in data[:4] or b"\xfe\xed\xfa\xce" in data[:4]:
            patterns["file_type"] = "Mach-O executable"

        if b"license" in data.lower() or b"registration" in data.lower():
            patterns["license_strings"] = True
        if b"trial" in data.lower() or b"expired" in data.lower():
            patterns["trial_strings"] = True

        return patterns

    def _analyze_structure(data: bytes) -> dict[str, Any]:
        """Analyze structural characteristics of binary data."""
        structure: dict[str, Any] = {
            "null_bytes": data.count(b"\x00"),
            "high_entropy_sections": 0,
            "code_like_patterns": 0,
        }

        chunk_size = 256
        for i in range(0, len(data), chunk_size):
            chunk = data[i : i + chunk_size]
            if _calculate_entropy(chunk) > 7.0:
                structure["high_entropy_sections"] += 1

        for i in range(0, len(data) - 10, 16):
            chunk = data[i : i + 16]
            if any(b in chunk for b in [b"\xe8", b"\xff", b"\x8b", b"\x89", b"\xc3"]):
                structure["code_like_patterns"] += 1

        return structure

    def _analyze_byte_distribution(data: bytes) -> dict[str, Any]:
        """Analyze distribution of byte values."""
        if not data:
            return {}
        counter = Counter(data)
        total = len(data)
        distribution = {
            "most_common": [{"byte": f"{b:#04x}", "count": c, "percentage": (c / total) * 100} for b, c in counter.most_common(5)],
            "unique_bytes": len(counter),
            "diversity_ratio": len(counter) / 256.0,
        }
        return distribution


logger = logging.getLogger("Intellicrack.HexView")

# Tool registry for hex viewer AI tools
TOOL_REGISTRY = {}


def show_enhanced_hex_viewer(app_instance: Any, file_path: str | None = None, read_only: bool = True) -> QDialog | None:
    """Show the enhanced hex viewer/editor dialog.

    This function creates and shows the enhanced hex viewer dialog, optionally
    loading a file if provided.

    Args:
        app_instance: Intellicrack application instance
        file_path: Path to the file to load (optional)
        read_only: Whether to open the file in read-only mode

    Returns:
        The created dialog instance

    """
    try:
        # If no file path is provided, use the currently loaded binary
        if not file_path:
            if hasattr(app_instance, "binary_path") and app_instance.binary_path:
                file_path = app_instance.binary_path
                logger.debug("Using current binary path: %s", file_path)
            else:
                # Show a message box if no file is loaded
                logger.warning("No file path provided and no binary loaded")
                QMessageBox.warning(
                    app_instance,
                    "No File Loaded",
                    "Please load a binary file first.",
                )
                return None

        # Validate file before creating dialog
        if not os.path.exists(file_path):
            logger.error("File does not exist: %s", file_path)
            QMessageBox.critical(
                app_instance,
                "Error Opening File",
                f"The file does not exist: {file_path}",
            )
            return None

        # Check for read permission
        if not os.access(file_path, os.R_OK):
            logger.error("No permission to read file: %s", file_path)
            QMessageBox.critical(
                app_instance,
                "Error Opening File",
                f"No permission to read file: {file_path}",
            )
            return None

        # Check file size
        try:
            file_size = os.path.getsize(file_path)
            logger.debug("File size: %s bytes", file_size)
            if file_size == 0:
                logger.warning("File is empty: %s", file_path)
                QMessageBox.warning(
                    app_instance,
                    "Empty File",
                    f"The file is empty: {file_path}",
                )
                # Continue anyway - we'll show an empty hex view
        except (OSError, ValueError, RuntimeError) as e:
            logger.warning("Could not get file size: %s", e)

        # Create the dialog
        logger.debug("Creating HexViewerDialog for %s, read_only=%s", file_path, read_only)
        dialog = HexViewerDialog(app_instance, file_path, read_only)

        # Show the dialog (non-modal)
        dialog.show()
        dialog.raise_()  # Bring to front
        dialog.activateWindow()  # Make it the active window

        # Force update after showing
        dialog.hex_viewer.viewport().update()

        logger.info("Opened enhanced hex viewer for %s", file_path)
        return dialog
    except (OSError, ValueError, RuntimeError) as e:
        logger.error(f"Error showing enhanced hex viewer: {e}", exc_info=True)
        QMessageBox.critical(
            app_instance,
            "Error Opening Hex Viewer",
            f"Failed to open hex viewer: {e!s}",
        )
        return None


def initialize_hex_viewer(app_instance: Any) -> None:
    """Initialize the hex viewer functionality.

    This function sets up the hex viewer methods on the application instance
    to enable both read-only viewing and editable modes.

    Args:
        app_instance: Intellicrack application instance

    """
    # Store the original method
    if not hasattr(app_instance, "_original_show_editable_hex_viewer"):
        app_instance._original_show_editable_hex_viewer = app_instance.show_editable_hex_viewer

    # Replace with enhanced version
    # Ensure the proper way to open hex viewer in edit mode is used
    app_instance.show_editable_hex_viewer = lambda: show_enhanced_hex_viewer(
        app_instance,
        app_instance.binary_path if hasattr(app_instance, "binary_path") else None,
        False,
    )

    # Add function to show writable hex viewer explicitly (fixes the menu-only integration)
    if not hasattr(app_instance, "show_writable_hex_viewer"):
        app_instance.show_writable_hex_viewer = app_instance.show_editable_hex_viewer

    logger.info("Initialized hex viewer functionality")


def restore_standard_hex_viewer(app_instance: Any) -> None:
    """Restore the standard hex viewer.

    This function restores the original hex viewer function if it was
    previously replaced.

    Args:
        app_instance: Intellicrack application instance

    """
    if hasattr(app_instance, "_original_show_editable_hex_viewer"):
        app_instance.show_editable_hex_viewer = app_instance._original_show_editable_hex_viewer
        logger.info("Restored standard hex viewer")


def add_hex_viewer_menu(app_instance: Any, menu_name: str | None = None) -> None:
    """Add the enhanced hex viewer to a menu.

    This function adds a menu item for the enhanced hex viewer to the
    specified menu in the application.

    Args:
        app_instance: Intellicrack application instance
        menu_name: Name of the menu to add the item to

    """
    # Check if menu_name is None - skip menu creation if so
    if menu_name is None:
        # Skip adding hex viewer menu items - they're already available in the dedicated tab
        logger.info("Skipping hex viewer menu creation - using dedicated tab instead")
        return

    # Find the menu
    menu = None
    for action in app_instance.menuBar().actions():
        if action.text() == menu_name:
            menu = action.menu()
            break

    if not menu:
        # Create the menu if it doesn't exist
        menu = app_instance.menuBar().addMenu(menu_name)

    # Add view action (read-only)
    enhanced_hex_action = QAction("Hex Viewer (View)", app_instance)
    enhanced_hex_action.triggered.connect(lambda: show_enhanced_hex_viewer(app_instance, None, True))
    enhanced_hex_action.setStatusTip("Open binary in read-only hex viewer")
    menu.addAction(enhanced_hex_action)

    # Add edit action
    edit_hex_action = QAction("Hex Editor (Editable)", app_instance)
    edit_hex_action.triggered.connect(lambda: show_enhanced_hex_viewer(app_instance, None, False))
    edit_hex_action.setStatusTip("Open binary in editable hex editor")
    menu.addAction(edit_hex_action)

    logger.info("Added Enhanced Hex Viewer options to %s menu", menu_name)


def add_hex_viewer_toolbar_button(app_instance: Any, toolbar: QToolBar | None = None) -> None:
    """Add the enhanced hex viewer to a toolbar.

    This function adds a toolbar button for the enhanced hex viewer to the
    specified toolbar in the application.

    Args:
        app_instance: Intellicrack application instance
        toolbar: Toolbar to add the button to, or None to use the main toolbar

    """
    # Find the toolbar if not provided
    if not toolbar:
        for child in app_instance.children():
            if isinstance(child, QToolBar):
                toolbar = child
                break

    if not toolbar:
        logger.warning("Could not find a toolbar to add the hex viewer button to")
        return

    # Add the action
    enhanced_hex_action = QAction("Enhanced Hex", app_instance)
    enhanced_hex_action.triggered.connect(lambda: show_enhanced_hex_viewer(app_instance))
    toolbar.addAction(enhanced_hex_action)

    logger.info("Added Enhanced Hex Viewer button to toolbar")


def register_hex_viewer_ai_tools(app_instance: Any) -> None:
    """Register the AI tool wrappers for the hex viewer.

    This function registers the AI tool wrappers that provide integration
    between the hex viewer and the AI model.

    Args:
        app_instance: Intellicrack application instance

    """
    # Check if TOOL_REGISTRY exists
    if not hasattr(app_instance, "TOOL_REGISTRY"):
        logger.warning("TOOL_REGISTRY not found in app_instance")
        return

    # Register the tool wrappers
    tool_registry = {
        "tool_ai_binary_analyze": wrapper_ai_binary_analyze,
        "tool_ai_binary_pattern_search": wrapper_ai_binary_pattern_search,
        "tool_ai_binary_edit_suggest": wrapper_ai_binary_edit_suggest,
    }

    # Update the registry
    app_instance.TOOL_REGISTRY.update(tool_registry)

    logger.info(f"Registered {len(tool_registry)} hex viewer AI tools")


def integrate_enhanced_hex_viewer(app_instance: Any) -> bool | None:
    """Fully integrate the enhanced hex viewer with Intellicrack.

    This function performs all necessary steps to integrate the enhanced hex
    viewer with the main Intellicrack application.

    Args:
        app_instance: Intellicrack application instance

    Returns:
        True if integration succeeded, False if it failed, None on error

    """
    try:
        # Check if already integrated to prevent duplicates
        if hasattr(app_instance, "_hex_viewer_integrated"):
            logger.info("Enhanced hex viewer already integrated - skipping")
            return True

        # Initialize hex viewer
        initialize_hex_viewer(app_instance)

        # Skip adding to menu since we have a dedicated tab
        # add_hex_viewer_menu(app_instance)
        logger.info("Skipping hex viewer menu integration - using dedicated tab instead")

        # Register AI tools
        register_hex_viewer_ai_tools(app_instance)

        # Mark as integrated
        app_instance._hex_viewer_integrated = True

        logger.info("Hex viewer integration completed successfully")
        return True
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error integrating enhanced hex viewer: %s", e)
        return False


# Decorator for hex viewer AI tool wrappers
def hex_viewer_ai_tool(func: Callable[[Any, dict[str, Any]], dict[str, Any]]) -> Callable[[Any, dict[str, Any]], dict[str, Any]]:
    """Decorate hex viewer AI tool wrappers.

    This decorator adds common functionality to all hex viewer AI tool wrappers,
    such as error handling and logging.

    Args:
        func: The tool wrapper function

    Returns:
        Decorated function with error handling and logging

    """

    def wrapper(app_instance: Any, parameters: dict[str, Any]) -> dict[str, Any]:
        """Add error handling and logging to hex viewer AI tools.

        Args:
            app_instance: The application instance
            parameters: Parameters to pass to the wrapped function

        Returns:
            Result from the wrapped function or error dictionary on failure

        """
        try:
            logger.debug("Calling hex viewer AI tool: %s", func.__name__)
            result = func(app_instance, parameters)
            logger.debug("Hex viewer AI tool %s completed successfully", func.__name__)
            return result
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error in hex viewer AI tool %s: %s", func.__name__, e)
            return {"error": str(e)}

    return wrapper
