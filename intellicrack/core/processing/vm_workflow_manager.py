"""VM Workflow Manager for Intellicrack.

High-level orchestrator for complete binary analysis workflows using QEMU VMs,
including binary modification, testing, and file export with user dialog integration.

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

import tempfile
from pathlib import Path
from typing import Any

from intellicrack.ai.qemu_manager import QEMUManager
from intellicrack.handlers.pyqt6_handler import QApplication, QFileDialog
from intellicrack.utils.logger import get_logger


class VMWorkflowManager:
    """High-level workflow orchestrator for VM-based binary analysis."""

    def __init__(self) -> None:
        """Initialize the VM workflow manager."""
        self.qemu_manager = QEMUManager()
        self.logger = get_logger(__name__)

    def run_full_analysis_roundtrip(
        self,
        binary_path: str,
        modification_script_content: str,
        test_script_content: str,
        platform: str = "windows",
    ) -> dict[str, Any]:
        """Run complete analysis roundtrip: create VM, modify binary, test, and export.

        Args:
            binary_path: Path to original binary for analysis
            modification_script_content: Script content for binary modification
            test_script_content: Script content for testing modified binary
            platform: Target platform ('windows' or 'linux')

        Returns:
            Dictionary with results including success status, paths, and test results

        """
        self.logger.info("Starting full analysis roundtrip for %s", binary_path)

        # Step 1: Create temporary directory
        try:
            temp_dir = tempfile.TemporaryDirectory()
            temp_path = Path(temp_dir.name)
            self.logger.info("Created temporary directory: %s", temp_path)
        except Exception as e:
            self.logger.exception("Failed to create temporary directory: %s", e)
            return {
                "success": False,
                "error": f"Failed to create temporary directory: {e}",
                "stage": "temp_directory_creation",
            }

        snapshot_id = None
        try:
            # Step 2: Create VM snapshot
            self.logger.info("Creating VM snapshot for platform: %s", platform)
            try:
                snapshot_id = self.qemu_manager.create_script_test_snapshot(
                    binary_path,
                    platform=platform,
                )
                if not snapshot_id:
                    msg = "Snapshot creation returned None"
                    raise RuntimeError(msg)

                self.logger.info("Created VM snapshot: %s", snapshot_id)
            except Exception as e:
                self.logger.exception("Failed to create VM snapshot: %s", e)
                return {
                    "success": False,
                    "error": f"Failed to create VM snapshot: {e}",
                    "stage": "vm_snapshot_creation",
                }

            # Step 3: Upload original binary
            binary_filename = Path(binary_path).name
            remote_original_path = f"/opt/intellicrack/original_{binary_filename}"

            self.logger.info("Uploading binary to VM: %s", remote_original_path)
            try:
                upload_success = self._upload_binary_to_vm(
                    snapshot_id,
                    binary_path,
                    remote_original_path,
                )
                if not upload_success:
                    msg = "Binary upload failed"
                    raise RuntimeError(msg)

                self.logger.info("Binary upload successful")
            except Exception as e:
                self.logger.exception("Failed to upload binary: %s", e)
                return {
                    "success": False,
                    "error": f"Failed to upload binary: {e}",
                    "stage": "binary_upload",
                    "vm_snapshot_used": snapshot_id,
                }

            # Step 4: Prepare modification script with output contract
            remote_modified_path = f"/opt/intellicrack/modified_{binary_filename}"

            self.logger.info("Preparing modification script with OUTPUT_PATH contract")
            wrapped_script = self._wrap_modification_script(
                modification_script_content,
                remote_modified_path,
                remote_original_path,
            )

            # Step 5: Execute modification script
            self.logger.info("Executing modification script in VM")
            try:
                mod_result = self.qemu_manager.test_script_in_vm(
                    snapshot_id,
                    wrapped_script,
                )
                if not mod_result.success:
                    error_msg = f"Modification script failed: {mod_result.error}"
                    raise RuntimeError(error_msg)

                self.logger.info("Modification script executed successfully")
            except Exception as e:
                self.logger.exception("Failed to execute modification script: %s", e)
                return {
                    "success": False,
                    "error": f"Failed to execute modification script: {e}",
                    "stage": "modification_execution",
                    "vm_snapshot_used": snapshot_id,
                }

            # Step 6: Open file dialog for user to select export location
            self.logger.info("Opening file dialog for user to select export location")
            try:
                user_selected_path = self._get_user_export_path(binary_filename)
                if not user_selected_path:
                    self.logger.info("User cancelled file export")
                    return {
                        "success": False,
                        "user_cancelled": True,
                        "stage": "file_dialog",
                        "vm_snapshot_used": snapshot_id,
                    }

                self.logger.info("User selected export path: %s", user_selected_path)
            except Exception as e:
                self.logger.exception("Failed to get user export path: %s", e)
                return {
                    "success": False,
                    "error": f"Failed to get user export path: {e}",
                    "stage": "file_dialog",
                    "vm_snapshot_used": snapshot_id,
                }

            # Step 7: Download modified binary to user-selected location
            self.logger.info("Downloading modified binary to: %s", user_selected_path)
            try:
                download_success = self.qemu_manager.download_file_from_vm(
                    self.qemu_manager.snapshots[snapshot_id],
                    remote_modified_path,
                    user_selected_path,
                )
                if not download_success:
                    msg = "File download failed"
                    raise RuntimeError(msg)

                self.logger.info("Modified binary download successful")
            except Exception as e:
                self.logger.exception("Failed to download modified binary: %s", e)
                return {
                    "success": False,
                    "error": f"Failed to download modified binary: {e}",
                    "stage": "binary_download",
                    "vm_snapshot_used": snapshot_id,
                }

            # Step 8: Execute test script
            self.logger.info("Executing test script in VM")
            try:
                test_wrapped_script = self._wrap_test_script(
                    test_script_content,
                    remote_modified_path,
                )
                test_result = self.qemu_manager.test_script_in_vm(
                    snapshot_id,
                    test_wrapped_script,
                )

                self.logger.info("Test script execution completed. Success: %s", test_result.success)
            except Exception as e:
                self.logger.exception("Failed to execute test script: %s", e)
                test_result = type(
                    "TestResult",
                    (),
                    {
                        "success": False,
                        "error": str(e),
                        "output": "",
                        "exit_code": -1,
                    },
                )()

            # Step 10: Return results dictionary
            return {
                "success": True,
                "original_binary": binary_path,
                "modified_binary_path": user_selected_path,
                "modification_result": {
                    "success": mod_result.success,
                    "output": mod_result.output,
                    "exit_code": getattr(mod_result, "exit_code", 0),
                },
                "test_result": {
                    "success": test_result.success,
                    "output": test_result.output,
                    "exit_code": getattr(test_result, "exit_code", 0),
                },
                "vm_snapshot_used": snapshot_id,
                "platform": platform,
            }

        finally:
            # Step 9: Cleanup
            if snapshot_id:
                try:
                    self.logger.info("Cleaning up VM snapshot: %s", snapshot_id)
                    self.qemu_manager.cleanup_snapshot(snapshot_id)
                except Exception as e:
                    self.logger.exception("Failed to cleanup snapshot %s: %s", snapshot_id, e)

            # Cleanup temporary directory
            try:
                temp_dir.cleanup()
                self.logger.info("Temporary directory cleaned up")
            except Exception as e:
                self.logger.exception("Failed to cleanup temporary directory: %s", e)

    def _upload_binary_to_vm(self, snapshot_id: str, local_path: str, remote_path: str) -> bool:
        """Upload binary file to VM via SFTP."""
        try:
            snapshot = self.qemu_manager.snapshots[snapshot_id]
            # Access public method instead of private
            ssh_client = getattr(self.qemu_manager, "get_ssh_connection", self.qemu_manager._get_ssh_connection)(snapshot)

            if ssh_client is None:
                self.logger.error("Failed to get SSH connection to %s", snapshot.vm_name)
                return False

            # Create SFTP client and upload
            sftp = ssh_client.open_sftp()
            try:
                # Ensure remote directory exists
                remote_dir = str(Path(remote_path).parent)
                if remote_dir:
                    try:
                        sftp.mkdir(remote_dir)
                    except OSError:
                        # Directory might already exist
                        pass

                # Upload the file
                sftp.put(local_path, remote_path)

                # Set executable permissions
                sftp.chmod(remote_path, 0o755)

                self.logger.info("Successfully uploaded %s to %s", local_path, remote_path)
                return True

            finally:
                sftp.close()

        except Exception as e:
            self.logger.exception("Failed to upload binary to VM: %s", e)
            return False

    def _wrap_modification_script(
        self,
        script_content: str,
        output_path: str,
        input_path: str,
    ) -> str:
        """Wrap modification script with OUTPUT_PATH contract and validation."""
        wrapper = f"""#!/bin/bash
# Modification script wrapper with OUTPUT_PATH contract
export OUTPUT_PATH="{output_path}"
export INPUT_PATH="{input_path}"

echo "Starting binary modification..."
echo "Input binary: $INPUT_PATH"
echo "Output will be saved to: $OUTPUT_PATH"

# Execute user modification script
{script_content}

# Validate that output file was created
if [ ! -f "$OUTPUT_PATH" ]; then
    echo "ERROR: Modification script failed to create output file at $OUTPUT_PATH"
    exit 1
fi

echo "Binary modification completed successfully"
echo "Modified binary saved to: $OUTPUT_PATH"
exit 0
"""
        return wrapper

    def _wrap_test_script(self, script_content: str, modified_binary_path: str) -> str:
        """Wrap test script with modified binary path."""
        wrapper = f"""#!/bin/bash
# Test script wrapper
export MODIFIED_BINARY="{modified_binary_path}"

echo "Starting test of modified binary..."
echo "Testing binary: $MODIFIED_BINARY"

# Execute user test script
{script_content}

echo "Test execution completed"
exit $?
"""
        return wrapper

    def _get_user_export_path(self, suggested_filename: str) -> str:
        """Open file dialog for user to select export location."""
        app = QApplication.instance()
        if app is None:
            self.logger.error("No QApplication instance found")
            msg = "No QApplication instance available for file dialog"
            raise RuntimeError(msg)

        # Prepare suggested filename and default directory
        suggested_name = f"modified_{suggested_filename}"
        default_dir = Path.home() / "Documents" / "Intellicrack_Output"
        default_dir.mkdir(parents=True, exist_ok=True)
        default_path = default_dir / suggested_name

        # Open file dialog
        file_path, _ = QFileDialog.getSaveFileName(
            None,
            "Select Output Location for Modified Binary",
            str(default_path),
            "Binary Files (*.exe *.bin *.elf *.so *.dll);;All Files (*.*)",
        )

        return file_path if file_path else None
