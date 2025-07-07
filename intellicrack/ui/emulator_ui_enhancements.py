"""Emulator UI enhancements for improved user experience."""
from typing import Dict

from intellicrack.logger import logger

"""
UI enhancements for emulator status and warnings.

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

try:
    from PyQt6.QtWidgets import (
        QHBoxLayout,
        QLabel,
        QMessageBox,
        QWidget,
    )
except ImportError as e:
    logger.error("Import error in emulator_ui_enhancements: %s", e)
    from PyQt6.QtWidgets import (
        QHBoxLayout,
        QLabel,
        QMessageBox,
        QWidget,
    )


class EmulatorStatusWidget(QWidget):
    """Widget showing emulator status with visual indicators."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()

        # Status tracking
        self.emulator_status = {
            "QEMU": {"running": False, "message": "Not started"},
            "Qiling": {"running": False, "message": "Not initialized"}
        }

    def setup_ui(self):
        """Create the status indicator UI."""
        layout = QHBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)

        # QEMU status
        self.qemu_label = QLabel("QEMU:")
        self.qemu_status = QLabel("⭕ Not Running")
        self.qemu_status.setStyleSheet("color: #ff6b6b;")  # Red

        # Qiling status
        self.qiling_label = QLabel("Qiling:")
        self.qiling_status = QLabel("⭕ Not Ready")
        self.qiling_status.setStyleSheet("color: #ff6b6b;")  # Red

        layout.addWidget(self.qemu_label)
        layout.addWidget(self.qemu_status)
        layout.addSpacing(20)
        layout.addWidget(self.qiling_label)
        layout.addWidget(self.qiling_status)
        layout.addStretch()

    def update_emulator_status(self, emulator_type: str, is_running: bool, message: str):
        """Update the status display for an emulator."""
        self.emulator_status[emulator_type] = {
            "running": is_running,
            "message": message
        }

        if emulator_type == "QEMU":
            if is_running:
                self.qemu_status.setText("✅ Running")
                self.qemu_status.setStyleSheet("color: #51cf66;")  # Green
            else:
                self.qemu_status.setText("⭕ Not Running")
                self.qemu_status.setStyleSheet("color: #ff6b6b;")  # Red
            self.qemu_status.setToolTip(message)

        elif emulator_type == "Qiling":
            if is_running:
                self.qiling_status.setText("✅ Ready")
                self.qiling_status.setStyleSheet("color: #51cf66;")  # Green
            else:
                self.qiling_status.setText("⭕ Not Ready")
                self.qiling_status.setStyleSheet("color: #ff6b6b;")  # Red
            self.qiling_status.setToolTip(message)


def add_emulator_tooltips(widget_dict: Dict[str, QWidget]):
    """
    Add informative tooltips to emulator-dependent widgets.

    Args:
        widget_dict: Dictionary mapping feature names to their widgets
    """
    tooltips = {
        "start_qemu": "Start or stop the QEMU virtual machine emulator.\nRequired for: Full system analysis, DNS monitoring, snapshot comparisons.",
        "create_snapshot": "Create a VM snapshot (requires QEMU to be running).\nQEMU will start automatically if not already running.",
        "restore_snapshot": "Restore a VM snapshot (requires QEMU to be running).\nQEMU will start automatically if not already running.",
        "execute_vm": "Execute commands inside the QEMU VM.\nQEMU will start automatically if not already running.",
        "compare_snapshots": "Compare VM snapshots for behavioral analysis.\nQEMU will start automatically if not already running.",
        "qiling_emulation": "Enable Qiling framework for lightweight emulation.\nQiling will initialize automatically when analysis begins.",
        "dynamic_analysis": "Run dynamic analysis on the binary.\nWill automatically start required emulators based on configuration.",
        "behavioral_analysis": "Analyze runtime behavior of the binary.\nRequires either QEMU or Qiling (will auto-select based on binary type)."
    }

    for feature, widget in widget_dict.items():
        if feature in tooltips:
            widget.setToolTip(tooltips[feature])


def show_emulator_warning(parent: QWidget, emulator_type: str, feature_name: str) -> bool:
    """
    Show a warning dialog when an emulator is required but not running.

    Args:
        parent: Parent widget for the dialog
        emulator_type: Type of emulator (QEMU/Qiling)
        feature_name: Name of the feature requiring the emulator

    Returns:
        True if user wants to proceed with auto-start, False otherwise
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
            "- A compatible rootfs image"
        )
    else:  # Qiling
        msg.setText(f"The '{feature_name}' feature requires Qiling framework.")
        msg.setInformativeText("Qiling will be initialized automatically when you proceed.")
        msg.setDetailedText(
            "Qiling provides lightweight binary emulation.\n\n"
            "Requirements:\n"
            "- Qiling framework installed (pip install qiling)\n"
            "- Compatible binary format\n"
            "- Python 3.7 or higher"
        )

    msg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
    msg.setDefaultButton(QMessageBox.StandardButton.Yes)

    return msg.exec() == QMessageBox.StandardButton.Yes


class EmulatorRequiredDecorator:
    """
    Decorator to ensure emulators are running before executing functions.

    Usage:
        @EmulatorRequiredDecorator.requires_qemu
        def my_qemu_function(self):
            # Function code
    """

    @staticmethod
    def requires_qemu(func):
        """Decorator for functions requiring QEMU."""
        def wrapper(self, *args, **kwargs):
            from ..core.processing.emulator_manager import get_emulator_manager

            if not hasattr(self, 'binary_path') or not self.binary_path:
                QMessageBox.warning(self, "No Binary", "Please select a binary file first.")
                return

            manager = get_emulator_manager()
            if not manager.qemu_running:
                feature_name = func.__name__.replace('_', ' ').title()
                if show_emulator_warning(self, "QEMU", feature_name):
                    if not manager.ensure_qemu_running(self.binary_path):
                        QMessageBox.critical(self, "QEMU Error",
                                           "Failed to start QEMU. Check the logs for details.")
                        return
                else:
                    return

            return func(self, *args, **kwargs)
        return wrapper

    @staticmethod
    def requires_qiling(func):
        """Decorator for functions requiring Qiling."""
        def wrapper(self, *args, **kwargs):
            from ..core.processing.emulator_manager import get_emulator_manager

            if not hasattr(self, 'binary_path') or not self.binary_path:
                QMessageBox.warning(self, "No Binary", "Please select a binary file first.")
                return

            manager = get_emulator_manager()
            if not manager.ensure_qiling_ready(self.binary_path):
                QMessageBox.critical(self, "Qiling Error",
                                   "Failed to initialize Qiling. Ensure it's installed: pip install qiling")
                return

            return func(self, *args, **kwargs)
        return wrapper
