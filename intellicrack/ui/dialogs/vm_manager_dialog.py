"""VM Manager Dialog for Intellicrack.

Provides a user interface for managing QEMU virtual machines, including
starting, stopping, deleting VMs and configuring base images.

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

from typing import Any

from intellicrack.handlers.pyqt6_handler import (
    QAbstractItemView,
    QAbstractTableModel,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QMessageBox,
    QModelIndex,
    QPushButton,
    Qt,
    QTableView,
    QVariant,
    QVBoxLayout,
)

from ...ai.qemu_manager import QEMUManager
from ...utils.logger import get_logger

logger = get_logger(__name__)


class VMTableModel(QAbstractTableModel):
    """Table model for displaying VM information."""

    def __init__(self, vm_data: list[dict]) -> None:
        """Initialize the VM table model with VM data for display in the table view."""
        super().__init__()
        self.vm_data = vm_data
        self.headers = [
            "Snapshot ID",
            "VM Name",
            "Binary Path",
            "Created At",
            "SSH Port",
            "VNC Port",
            "Status",
            "Version",
        ]

    def rowCount(self, parent: QModelIndex = None) -> int:
        """Return number of rows."""
        if parent is None:
            parent = QModelIndex()
        return len(self.vm_data)

    def columnCount(self, parent: QModelIndex = None) -> int:
        """Return number of columns."""
        if parent is None:
            parent = QModelIndex()
        return len(self.headers)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        """Return data for display."""
        if not index.isValid() or index.row() >= len(self.vm_data):
            return QVariant()

        if role == Qt.ItemDataRole.DisplayRole:
            vm_info = self.vm_data[index.row()]
            column = index.column()

            if column == 0:
                return vm_info.get("snapshot_id", "N/A")
            if column == 1:
                return vm_info.get("vm_name", "N/A")
            if column == 2:
                binary_path = vm_info.get("binary_path", "N/A")
                if binary_path != "N/A" and len(binary_path) > 50:
                    return "..." + binary_path[-47:]  # Show last 47 chars with ...
                return binary_path
            if column == 3:
                created_at = vm_info.get("created_at", "N/A")
                if created_at != "N/A":
                    return created_at.split("T")[0]  # Show just date part
                return created_at
            if column == 4:
                return str(vm_info.get("ssh_port", "N/A"))
            if column == 5:
                return str(vm_info.get("vnc_port", "N/A"))
            if column == 6:
                return "Running" if vm_info.get("vm_running", False) else "Stopped"
            if column == 7:
                return vm_info.get("version", "N/A")

        return QVariant()

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        """Return header data."""
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            if 0 <= section < len(self.headers):
                return self.headers[section]
        return QVariant()

    def update_data(self, new_data: list[dict]) -> None:
        """Update the model with new VM data."""
        self.beginResetModel()
        self.vm_data = new_data
        self.endResetModel()


class VMManagerDialog(QDialog):
    """Dialog for managing QEMU virtual machines."""

    def __init__(self, parent=None) -> None:
        """Initialize the VM Manager dialog for QEMU virtual machine management."""
        super().__init__(parent)
        self.qemu_manager = QEMUManager()
        self._init_ui()
        self._load_vm_data()

    def _init_ui(self) -> None:
        """Initialize the user interface."""
        self.setWindowTitle("Intellicrack VM Manager")
        self.setModal(True)
        self.resize(1000, 600)

        # Create main layout
        main_layout = QVBoxLayout(self)

        # Create table view for VM list
        self.vm_table = QTableView()
        self.vm_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.vm_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)

        # Set horizontal header resize mode
        header = self.vm_table.horizontalHeader()
        header.setResizeMode(QHeaderView.ResizeMode.Stretch)

        main_layout.addWidget(self.vm_table)

        # Create button layout
        button_layout = QHBoxLayout()

        # Create control buttons
        self.start_btn = QPushButton("Start VM")
        self.start_btn.clicked.connect(self._start_selected_vm)
        button_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Stop VM")
        self.stop_btn.clicked.connect(self._stop_selected_vm)
        button_layout.addWidget(self.stop_btn)

        self.delete_btn = QPushButton("Delete VM")
        self.delete_btn.clicked.connect(self._delete_selected_vm)
        button_layout.addWidget(self.delete_btn)

        self.create_btn = QPushButton("Create New VM")
        self.create_btn.clicked.connect(self._create_new_vm_dialog)
        button_layout.addWidget(self.create_btn)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self._load_vm_data)
        button_layout.addWidget(self.refresh_btn)

        self.config_btn = QPushButton("Configure Base Images")
        self.config_btn.clicked.connect(self._configure_base_images)
        button_layout.addWidget(self.config_btn)

        # Add close button
        self.close_btn = QPushButton("Close")
        self.close_btn.clicked.connect(self.accept)
        button_layout.addWidget(self.close_btn)

        main_layout.addLayout(button_layout)

    def _load_vm_data(self) -> None:
        """Load VM data and update the table."""
        try:
            vm_info_list = self.qemu_manager.get_all_vm_info()

            # Create or update model
            if not hasattr(self, "vm_model"):
                self.vm_model = VMTableModel(vm_info_list)
                self.vm_table.setModel(self.vm_model)
            else:
                self.vm_model.update_data(vm_info_list)

            logger.info(f"Loaded {len(vm_info_list)} VM instances")

        except Exception as e:
            logger.error(f"Failed to load VM data: {e}")
            QMessageBox.critical(self, "Error", f"Failed to load VM data: {e}")

    def _get_selected_vm_id(self) -> str | None:
        """Get the snapshot ID of the currently selected VM."""
        selection_model = self.vm_table.selectionModel()
        if not selection_model.hasSelection():
            return None

        selected_rows = selection_model.selectedRows()
        if not selected_rows:
            return None

        row = selected_rows[0].row()
        if row < 0 or row >= len(self.vm_model.vm_data):
            return None

        return self.vm_model.vm_data[row].get("snapshot_id")

    def _start_selected_vm(self) -> None:
        """Start the selected VM."""
        snapshot_id = self._get_selected_vm_id()
        if not snapshot_id:
            QMessageBox.warning(self, "Warning", "Please select a VM to start.")
            return

        try:
            success = self.qemu_manager.start_vm_instance(snapshot_id)
            if success:
                QMessageBox.information(self, "Success", f"VM {snapshot_id} started successfully.")
                self._load_vm_data()  # Refresh to show updated status
            else:
                QMessageBox.critical(self, "Error", f"Failed to start VM {snapshot_id}.")
        except Exception as e:
            logger.error(f"Error starting VM {snapshot_id}: {e}")
            QMessageBox.critical(self, "Error", f"Error starting VM: {e}")

    def _stop_selected_vm(self) -> None:
        """Stop the selected VM."""
        snapshot_id = self._get_selected_vm_id()
        if not snapshot_id:
            QMessageBox.warning(self, "Warning", "Please select a VM to stop.")
            return

        try:
            success = self.qemu_manager.stop_vm_instance(snapshot_id)
            if success:
                QMessageBox.information(self, "Success", f"VM {snapshot_id} stopped successfully.")
                self._load_vm_data()  # Refresh to show updated status
            else:
                QMessageBox.critical(self, "Error", f"Failed to stop VM {snapshot_id}.")
        except Exception as e:
            logger.error(f"Error stopping VM {snapshot_id}: {e}")
            QMessageBox.critical(self, "Error", f"Error stopping VM: {e}")

    def _delete_selected_vm(self) -> None:
        """Delete the selected VM."""
        snapshot_id = self._get_selected_vm_id()
        if not snapshot_id:
            QMessageBox.warning(self, "Warning", "Please select a VM to delete.")
            return

        # Confirm deletion
        reply = QMessageBox.question(
            self,
            "Confirm Deletion",
            f"Are you sure you want to delete VM {snapshot_id}?\nThis action cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )

        if reply != QMessageBox.StandardButton.Yes:
            return

        try:
            success = self.qemu_manager.delete_vm_instance(snapshot_id)
            if success:
                QMessageBox.information(self, "Success", f"VM {snapshot_id} deleted successfully.")
                self._load_vm_data()  # Refresh to remove deleted VM
            else:
                QMessageBox.critical(self, "Error", f"Failed to delete VM {snapshot_id}.")
        except Exception as e:
            logger.error(f"Error deleting VM {snapshot_id}: {e}")
            QMessageBox.critical(self, "Error", f"Error deleting VM: {e}")

    def _create_new_vm_dialog(self) -> None:
        """Open dialog to create a new VM."""
        QMessageBox.information(
            self,
            "Create New VM",
            "VM creation will be implemented in the workflow manager.\nUse the main application's binary analysis features to create VMs.",
        )

    def _configure_base_images(self) -> None:
        """Open dialog to configure base images."""
        try:
            current_config = self.qemu_manager.get_base_image_configuration()

            # Create a simple configuration dialog
            config_text = "Current base image configuration:\n\n"
            config_text += f"Windows images: {current_config.get('windows', [])}\n"
            config_text += f"Linux images: {current_config.get('linux', [])}\n\n"
            config_text += "To modify base images, edit the vm_framework.base_images section\n"
            config_text += "in config/config.json and restart the application."

            QMessageBox.information(self, "Base Image Configuration", config_text)

        except Exception as e:
            logger.error(f"Error loading base image configuration: {e}")
            QMessageBox.critical(self, "Error", f"Error loading configuration: {e}")
