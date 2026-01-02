"""Emulator UI enhancements for improved user experience.

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

from collections.abc import Callable
from typing import ParamSpec, TypeVar

from intellicrack.utils.logger import logger


P = ParamSpec("P")
R = TypeVar("R")


try:
    from intellicrack.handlers.pyqt6_handler import QHBoxLayout, QLabel, QMessageBox, QWidget
except ImportError as e:
    logger.error("Import error in emulator_ui_enhancements: %s", e)
    from intellicrack.handlers.pyqt6_handler import QHBoxLayout, QLabel, QMessageBox, QWidget


class EmulatorStatusWidget(QWidget):
    """Widget showing emulator status with visual indicators."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the emulator status widget with UI components and status tracking.

        Args:
            parent: Parent widget for this status widget.
        """
        super().__init__(parent)
        self.qemu_label: QLabel
        self.qemu_status: QLabel
        self.qiling_label: QLabel
        self.qiling_status: QLabel
        self.emulator_status: dict[str, dict[str, bool | str]] = {
            "QEMU": {"running": False, "message": "Not started"},
            "Qiling": {"running": False, "message": "Not initialized"},
        }
        self.setup_ui()

    def setup_ui(self) -> None:
        """Create the status indicator UI."""
        layout = QHBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)

        # QEMU status
        self.qemu_label = QLabel("QEMU:")
        self.qemu_status = QLabel("\u2b55 Not Running")  # Red circle
        self.qemu_status.setStyleSheet("color: #ff6b6b;")  # Red

        # Qiling status
        self.qiling_label = QLabel("Qiling:")
        self.qiling_status = QLabel("\u2b55 Not Ready")  # Red circle
        self.qiling_status.setStyleSheet("color: #ff6b6b;")  # Red

        layout.addWidget(self.qemu_label)
        layout.addWidget(self.qemu_status)
        layout.addSpacing(20)
        layout.addWidget(self.qiling_label)
        layout.addWidget(self.qiling_status)
        layout.addStretch()

    def update_emulator_status(
        self, emulator_type: str, *, is_running: bool, message: str
    ) -> None:
        """Update the status display for an emulator.

        Args:
            emulator_type: Type of emulator (QEMU or Qiling).
            is_running: Whether the emulator is currently running.
            message: Status message to display in the tooltip.
        """
        self.emulator_status[emulator_type] = {
            "running": is_running,
            "message": message,
        }

        if emulator_type == "QEMU":
            if is_running:
                self.qemu_status.setText("\u2705 Running")  # Green checkmark
                self.qemu_status.setStyleSheet("color: #51cf66;")  # Green
            else:
                self.qemu_status.setText("\u2b55 Not Running")  # Red circle
                self.qemu_status.setStyleSheet("color: #ff6b6b;")  # Red
            self.qemu_status.setToolTip(message)

        elif emulator_type == "Qiling":
            if is_running:
                self.qiling_status.setText("\u2705 Ready")  # Green checkmark
                self.qiling_status.setStyleSheet("color: #51cf66;")  # Green
            else:
                self.qiling_status.setText("\u2b55 Not Ready")  # Red circle
                self.qiling_status.setStyleSheet("color: #ff6b6b;")  # Red
            self.qiling_status.setToolTip(message)


def add_emulator_tooltips(widget_dict: dict[str, QWidget]) -> None:
    """Add informative tooltips to emulator-dependent widgets.

    Args:
        widget_dict: Dictionary mapping feature names to their widgets.
    """
    tooltips = {
        "start_qemu": "Start or stop the QEMU virtual machine emulator.\nRequired for: Full system analysis, DNS monitoring, snapshot comparisons.",
        "create_snapshot": "Create a VM snapshot (requires QEMU to be running).\nQEMU will start automatically if not already running.",
        "restore_snapshot": "Restore a VM snapshot (requires QEMU to be running).\nQEMU will start automatically if not already running.",
        "execute_vm": "Execute commands inside the QEMU VM.\nQEMU will start automatically if not already running.",
        "compare_snapshots": "Compare VM snapshots for behavioral analysis.\nQEMU will start automatically if not already running.",
        "qiling_emulation": "Enable Qiling framework for lightweight emulation.\nQiling will initialize automatically when analysis begins.",
        "dynamic_analysis": "Run dynamic analysis on the binary.\nWill automatically start required emulators based on configuration.",
        "behavioral_analysis": "Analyze runtime behavior of the binary.\nRequires either QEMU or Qiling (will auto-select based on binary type).",
    }

    for feature, widget in widget_dict.items():
        if feature in tooltips:
            widget.setToolTip(tooltips[feature])


def show_emulator_warning(parent: QWidget, emulator_type: str, feature_name: str) -> bool:
    """Show a warning dialog when an emulator is required but not running.

    Args:
        parent: Parent widget for the dialog.
        emulator_type: Type of emulator (QEMU/Qiling).
        feature_name: Name of the feature requiring the emulator.

    Returns:
        bool: True if user wants to proceed with auto-start, False otherwise.
    """
    msg = QMessageBox(parent)
    msg.setIcon(QMessageBox.Icon.Warning)
    msg.setWindowTitle(f"{emulator_type} Required")

    if emulator_type == "QEMU":
        msg.setText(f"The '{feature_name}' feature requires QEMU to be running.")
        msg.setInformativeText("Would you like to start QEMU automatically?")
        msg.setDetailedText(
            "QEMU provides full system emulation for advanced analysis features.\n\n"
            "Starting QEMU may take a few moments and requires:\n"
            "- QEMU installed on your system\n"
            "- Available system resources (RAM/CPU)\n"
            "- A compatible rootfs image",
        )
    else:  # Qiling
        msg.setText(f"The '{feature_name}' feature requires Qiling framework.")
        msg.setInformativeText("Qiling will be initialized automatically when you proceed.")
        msg.setDetailedText(
            "Qiling provides lightweight binary emulation.\n\n"
            "Requirements:\n"
            "- Qiling framework installed (pip install qiling)\n"
            "- Compatible binary format\n"
            "- Python 3.7 or higher",
        )

    msg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
    msg.setDefaultButton(QMessageBox.StandardButton.Yes)

    return msg.exec() == QMessageBox.StandardButton.Yes


class EmulatorRequiredDecorator:
    """Decorator to ensure emulators are running before executing functions.

    Usage:
        Decorator for functions that require emulators to be running.
        Apply to methods that need QEMU or Qiling functionality.
    """

    @staticmethod
    def requires_qemu(func: Callable[P, R]) -> Callable[P, R | None]:
        """Decorate functions requiring QEMU.

        Args:
            func: Function to decorate that requires QEMU to be running.

        Returns:
            Callable: Decorated function that ensures QEMU is running before
                execution.
        """

        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R | None:
            """Wrapper function that ensures QEMU is running.

            Args:
                *args: Positional arguments to pass to the decorated function.
                **kwargs: Keyword arguments to pass to the decorated function.

            Returns:
                R | None: Result of the decorated function or None if QEMU
                    startup fails.
            """
            from ..core.processing.emulator_manager import get_emulator_manager

            if not args:
                return None
            self_arg = args[0]
            if not isinstance(self_arg, QWidget):
                return None

            binary_path = getattr(self_arg, "binary_path", None)
            if not binary_path:
                QMessageBox.warning(self_arg, "No Binary", "Please select a binary file first.")
                return None

            manager = get_emulator_manager()
            if not manager.qemu_running:
                feature_name = func.__name__.replace("_", " ").title()
                if show_emulator_warning(self_arg, "QEMU", feature_name):
                    if not manager.ensure_qemu_running(binary_path):
                        QMessageBox.critical(
                            self_arg, "QEMU Error", "Failed to start QEMU. Check the logs for details."
                        )
                        return None
                else:
                    return None

            return func(*args, **kwargs)

        return wrapper

    @staticmethod
    def requires_qiling(func: Callable[P, R]) -> Callable[P, R | None]:
        """Decorate functions requiring Qiling.

        Args:
            func: Function to decorate that requires Qiling to be ready.

        Returns:
            Callable: Decorated function that ensures Qiling is initialized
                before execution.
        """

        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R | None:
            """Wrapper function that ensures Qiling is ready.

            Args:
                *args: Positional arguments to pass to the decorated function.
                **kwargs: Keyword arguments to pass to the decorated function.

            Returns:
                R | None: Result of the decorated function or None if Qiling
                    initialization fails.
            """
            from ..core.processing.emulator_manager import get_emulator_manager

            if not args:
                return None
            self_arg = args[0]
            if not isinstance(self_arg, QWidget):
                return None

            binary_path = getattr(self_arg, "binary_path", None)
            if not binary_path:
                QMessageBox.warning(self_arg, "No Binary", "Please select a binary file first.")
                return None

            manager = get_emulator_manager()
            if not manager.ensure_qiling_ready(binary_path):
                QMessageBox.critical(
                    self_arg,
                    "Qiling Error",
                    "Failed to initialize Qiling. Ensure it's installed: pip install qiling",
                )
                return None

            return func(*args, **kwargs)

        return wrapper
