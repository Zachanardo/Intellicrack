"""UI helper utilities for common interface operations."""

from typing import TYPE_CHECKING, Any, cast

from intellicrack.utils.logger import logger


if TYPE_CHECKING:
    from intellicrack.handlers.pyqt6_handler import QMessageBox as QMessageBoxType
    from intellicrack.handlers.pyqt6_handler import QWidget

"""
Common UI helper functions to reduce code duplication.

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


def check_binary_path_and_warn(app_instance: object) -> bool:
    """Check if binary path exists and show warning if not.

    Args:
        app_instance: Application instance with binary_path and QMessageBox access

    Returns:
        bool: True if binary path exists, False if missing

    """
    if not hasattr(app_instance, "binary_path") or not getattr(app_instance, "binary_path", None):
        try:
            from intellicrack.handlers.pyqt6_handler import QFileDialog, QMessageBox

            _ = QFileDialog.__name__
            QMessageBox.warning(cast(Any, app_instance), "No File Selected", "Please select a program first.")
        except ImportError as e:
            logger.error("Import error in ui_helpers: %s", e)
        return False
    return True


def emit_log_message(app_instance: object, message: str) -> None:
    """Emit log message if app instance supports it.

    Args:
        app_instance: Application instance
        message: Message to log

    """
    if hasattr(app_instance, "update_output"):
        update_output: Any = getattr(app_instance, "update_output")
        if hasattr(update_output, "emit"):
            try:
                from ..core.misc_utils import log_message

                update_output.emit(log_message(message))
            except ImportError as e:
                logger.error("Import error in ui_helpers: %s", e)
                update_output.emit(message)
        else:
            update_output.emit(message)


def show_file_dialog(parent: object, title: str, file_filter: str = "HTML Files (*.html);;All Files (*)") -> str:
    """Show file save dialog and return filename.

    Args:
        parent: Parent widget
        title: Dialog title
        file_filter: File filter string

    Returns:
        str: Selected filename or empty string if cancelled

    """
    try:
        from intellicrack.handlers.pyqt6_handler import QFileDialog

        filename, _ = QFileDialog.getSaveFileName(cast(Any, parent), title, "", file_filter)
        return filename or ""
    except ImportError as e:
        logger.error("Import error in ui_helpers: %s", e)
        return ""


def ask_yes_no_question(parent: object, title: str, question: str) -> bool:
    """Show yes/no question dialog.

    Args:
        parent: Parent widget
        title: Dialog title
        question: Question text

    Returns:
        bool: True if Yes clicked, False otherwise

    """
    try:
        from intellicrack.handlers.pyqt6_handler import QMessageBox

        qmb: Any = cast(Any, QMessageBox)
        result: Any = qmb.question(
            cast(Any, parent),
            title,
            question,
            qmb.Yes | qmb.No,
        )
        return bool(result == qmb.Yes)
    except ImportError as e:
        logger.error("Import error in ui_helpers: %s", e)
        return False


def generate_exploit_payload_common(payload_type: str, target_path: str = "target_software") -> dict[str, str | bool | list[str]]:
    """Generate exploit payload of specified type.

    This is the common implementation extracted from duplicate code
    in main_app.py and missing_methods.py.

    Args:
        payload_type: Type of payload to generate ("License Bypass", "Function Hijack", "Buffer Overflow")
        target_path: Target path for license bypass payload

    Returns:
        dict: Payload result with fields like 'method', 'payload_bytes', 'description', or 'error'

    """
    try:
        import os

        if payload_type == "License Bypass":
            bypass_patch = b"\xb8\x01\x00\x00\x00\xc3"
            payload_result: dict[str, str | bool | list[str]] = {
                "method": "patch",
                "payload_bytes": bypass_patch.hex(),
                "description": "License bypass patch - always return success",
                "patch_type": "license_bypass",
                "instructions": [
                    "Locate license validation function",
                    "Replace function prologue with payload bytes",
                    "Function will always return true (1)",
                ],
            }
        elif payload_type == "Function Hijack":
            hijack_payload = b"\xe9\x00\x00\x00\x00"
            payload_result = {
                "method": "function_hijacking",
                "payload_bytes": hijack_payload.hex(),
                "description": "Function hijacking payload for license bypass",
                "patch_type": "function_hijack",
                "instructions": [
                    "Replace license check function entry with JMP",
                    "Redirect to handler that returns success",
                    "Calculate relative offset for JMP target",
                ],
            }
        elif payload_type == "NOP Slide":
            nop_slide = b"\x90" * 10
            payload_result = {
                "method": "nop_slide",
                "payload_bytes": nop_slide.hex(),
                "description": "NOP slide to bypass conditional checks",
                "patch_type": "nop_bypass",
                "instructions": [
                    "Locate conditional jump for license check",
                    "Replace with NOP instructions",
                    "Execution flows through without checking",
                ],
            }
        else:
            payload_result = {"error": f"Unknown payload type: {payload_type}"}

        if os.path.exists(target_path):
            payload_result["target"] = target_path
            target_exists: bool = True
            payload_result["target_exists"] = target_exists
        else:
            payload_result["target"] = target_path
            target_exists = False
            payload_result["target_exists"] = target_exists

        return payload_result

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in ui_helpers: %s", e)
        return {"error": str(e)}


def generate_exploit_strategy_common(binary_path: str, vulnerability_type: str = "buffer_overflow") -> dict[str, str | object]:
    """Generate exploit strategy for given binary and vulnerability type.

    This is the common implementation extracted from duplicate code.

    Args:
        binary_path: Path to binary file
        vulnerability_type: Type of vulnerability to exploit

    Returns:
        dict: Strategy result with 'strategy', 'automation_script' fields or 'error'

    """
    try:
        from ..exploitation.exploitation import generate_bypass_script

        result: dict[str, Any] = generate_bypass_script(binary_path, vulnerability_type)
        return cast(dict[str, str | object], result)
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in ui_helpers: %s", e)
        return {"error": str(e)}
