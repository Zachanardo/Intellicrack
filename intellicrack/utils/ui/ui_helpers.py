"""UI helper utilities for common interface operations."""

from __future__ import annotations

import os
from typing import Protocol, runtime_checkable

from intellicrack.types.analysis import ExploitPayloadResult, ExploitStrategyResult
from intellicrack.types.ui import (
    StandardButton,
    WidgetProtocol,
    get_file_dialog,
    get_message_box,
)
from intellicrack.utils.logger import logger


@runtime_checkable
class SignalEmitterProtocol(Protocol):
    """Protocol for objects that can emit signals."""

    def emit(self, message: str) -> None:
        """Emit a signal with the given message."""
        ...


@runtime_checkable
class LoggableAppProtocol(Protocol):
    """Protocol for application instances with logging capabilities."""

    @property
    def update_output(self) -> SignalEmitterProtocol:
        """Signal for output updates."""
        ...


@runtime_checkable
class AppInstanceProtocol(Protocol):
    """Protocol for application instances that can show warnings."""

    @property
    def binary_path(self) -> str | None:
        """Path to the binary being analyzed."""
        ...


def check_binary_path_and_warn(app_instance: AppInstanceProtocol | WidgetProtocol) -> bool:
    """Check if binary path exists and show warning if not.

    Args:
        app_instance: Application instance with binary_path and QMessageBox access

    Returns:
        bool: True if binary path exists, False if missing

    """
    binary_path = getattr(app_instance, "binary_path", None)
    if not binary_path:
        MessageBox = get_message_box()
        MessageBox.warning(
            app_instance if isinstance(app_instance, WidgetProtocol) else None,
            "No File Selected",
            "Please select a program first.",
        )
        return False
    return True


def emit_log_message(app_instance: LoggableAppProtocol | object, message: str) -> None:
    """Emit log message if app instance supports it.

    Args:
        app_instance: Application instance (LoggableAppProtocol or any object)
        message: Message to log

    """
    if not hasattr(app_instance, "update_output"):
        return

    update_output = getattr(app_instance, "update_output", None)
    if update_output is None or not hasattr(update_output, "emit"):
        return

    try:
        from ..core.misc_utils import log_message

        update_output.emit(log_message(message))
    except ImportError as e:
        logger.error("Import error in ui_helpers: %s", e)
        update_output.emit(message)


def show_file_dialog(
    parent: WidgetProtocol | None,
    title: str,
    file_filter: str = "HTML Files (*.html);;All Files (*)",
) -> str:
    """Show file save dialog and return filename.

    Args:
        parent: Parent widget (WidgetProtocol or None)
        title: Dialog title
        file_filter: File filter string

    Returns:
        Selected filename or empty string if cancelled

    """
    FileDialog = get_file_dialog()
    filename, _ = FileDialog.getSaveFileName(parent, title, "", file_filter)
    return filename or ""


def ask_yes_no_question(
    parent: WidgetProtocol | None,
    title: str,
    question: str,
) -> bool:
    """Show yes/no question dialog.

    Args:
        parent: Parent widget (WidgetProtocol or None)
        title: Dialog title
        question: Question text

    Returns:
        True if Yes clicked, False otherwise

    """
    MessageBox = get_message_box()
    result = MessageBox.question(
        parent,
        title,
        question,
        StandardButton.Yes | StandardButton.No,
    )
    return result == StandardButton.Yes


def generate_exploit_payload_common(
    payload_type: str,
    target_path: str = "target_software",
) -> ExploitPayloadResult:
    """Generate exploit payload of specified type.

    This is the common implementation extracted from duplicate code
    in main_app.py and missing_methods.py.

    Args:
        payload_type: Type of payload to generate ("License Bypass", "Function Hijack", "NOP Slide")
        target_path: Target path for license bypass payload

    Returns:
        ExploitPayloadResult with payload details or error

    """
    try:
        if payload_type == "License Bypass":
            bypass_patch = b"\xb8\x01\x00\x00\x00\xc3"
            return ExploitPayloadResult(
                method="patch",
                payload_bytes=bypass_patch.hex(),
                description="License bypass patch - always return success",
                patch_type="license_bypass",
                instructions=[
                    "Locate license validation function",
                    "Replace function prologue with payload bytes",
                    "Function will always return true (1)",
                ],
                target=target_path,
                target_exists=os.path.exists(target_path),
            )

        if payload_type == "Function Hijack":
            hijack_payload = b"\xe9\x00\x00\x00\x00"
            return ExploitPayloadResult(
                method="function_hijacking",
                payload_bytes=hijack_payload.hex(),
                description="Function hijacking payload for license bypass",
                patch_type="function_hijack",
                instructions=[
                    "Replace license check function entry with JMP",
                    "Redirect to handler that returns success",
                    "Calculate relative offset for JMP target",
                ],
                target=target_path,
                target_exists=os.path.exists(target_path),
            )

        if payload_type == "NOP Slide":
            nop_slide = b"\x90" * 10
            return ExploitPayloadResult(
                method="nop_slide",
                payload_bytes=nop_slide.hex(),
                description="NOP slide to bypass conditional checks",
                patch_type="nop_bypass",
                instructions=[
                    "Locate conditional jump for license check",
                    "Replace with NOP instructions",
                    "Execution flows through without checking",
                ],
                target=target_path,
                target_exists=os.path.exists(target_path),
            )

        return ExploitPayloadResult(
            error=f"Unknown payload type: {payload_type}",
            target=target_path,
            target_exists=os.path.exists(target_path),
        )

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in ui_helpers: %s", e)
        return ExploitPayloadResult(error=str(e))


def generate_exploit_strategy_common(
    binary_path: str,
    vulnerability_type: str = "buffer_overflow",
) -> ExploitStrategyResult:
    """Generate exploit strategy for given binary and vulnerability type.

    This is the common implementation extracted from duplicate code.

    Args:
        binary_path: Path to binary file
        vulnerability_type: Type of vulnerability to exploit

    Returns:
        ExploitStrategyResult with strategy details or error

    """
    try:
        from ..exploitation.exploitation import generate_bypass_script

        result = generate_bypass_script(binary_path, vulnerability_type)
        return ExploitStrategyResult(
            strategy=result.get("strategy", ""),
            automation_script=result.get("automation_script", ""),
            error=result.get("error"),
        )
    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Error in ui_helpers: %s", e)
        return ExploitStrategyResult(error=str(e))
