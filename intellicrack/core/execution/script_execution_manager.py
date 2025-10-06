"""This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

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

import datetime
import hashlib
import logging
import os
import subprocess
from typing import Any

from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtWidgets import QDialog, QMessageBox

from ...utils.logger import get_logger
from ..config_manager import get_config

"""Central script execution manager with QEMU testing options."""

logger = logging.getLogger(__name__)

try:
    from ..terminal_manager import get_terminal_manager

    HAS_TERMINAL_MANAGER = True
except ImportError:
    HAS_TERMINAL_MANAGER = False
    logger.warning("Terminal manager not available for script execution")


class ScriptExecutionManager(QObject):
    """Central manager for all script executions with optional QEMU testing."""

    # Signals
    #: Signal emitted when script execution starts (type: script_type: str, target_binary: str)
    execution_started = pyqtSignal(str, str)
    #: Signal emitted when script execution completes (type: script_type: str, success: bool, results: dict)
    execution_completed = pyqtSignal(str, bool, dict)
    #: Signal emitted when QEMU test starts (type: script_type: str, target_binary: str)
    qemu_test_started = pyqtSignal(str, str)
    #: Signal emitted when QEMU test completes (type: script_type: str, success: bool, results: dict)
    qemu_test_completed = pyqtSignal(str, bool, dict)

    def __init__(self):
        """Initialize the script execution manager with task queues and monitoring."""
        super().__init__()
        self.running_scripts = {}
        self.script_history = {}
        self.script_queue = []
        self.logger = get_logger(__name__)
        self.max_concurrent_scripts = 5
        self.config = get_config()
        self.qemu_manager = None
        self.QEMUTestDialog = None
        self.QEMUTestResultsDialog = None
        self._initialize_managers()

    def _initialize_managers(self):
        try:
            from intellicrack.ai.qemu_manager import QEMUManager as EnhancedQEMUManager
            from intellicrack.ui.dialogs.qemu_test_dialog import QEMUTestDialog
            from intellicrack.ui.dialogs.qemu_test_results_dialog import QEMUTestResultsDialog

            self.qemu_manager = EnhancedQEMUManager()
            self.QEMUTestDialog = QEMUTestDialog
            self.QEMUTestResultsDialog = QEMUTestResultsDialog
        except ImportError as e:
            logger.warning(f"Could not initialize QEMU components: {e}")
            self.qemu_manager = None

    def execute_script(
        self,
        script_type: str,
        script_content: str,
        target_binary: str,
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute a script with optional QEMU testing.

        Args:
            script_type: Type of script ('frida', 'ghidra', etc.)
            script_content: The actual script content
            target_binary: Path to the target binary
            options: Additional execution options
        Returns:
            Execution results dictionary

        """
        options = options or {}

        # Check if we should ask about QEMU testing
        if self._should_ask_qemu_testing(script_type, target_binary, options):
            user_choice = self._show_qemu_test_dialog(script_type, target_binary, script_content)

            if user_choice == "test_qemu":
                # Run QEMU test first
                qemu_results = self._run_qemu_test(script_type, script_content, target_binary, options)

                if qemu_results and qemu_results.get("success"):
                    # Show results and ask if they want to proceed with host execution
                    if self._show_qemu_results_and_confirm(qemu_results):
                        return self._execute_on_host(script_type, script_content, target_binary, options)
                    return {
                        "success": False,
                        "cancelled": True,
                        "message": "User cancelled after QEMU test",
                    }
                # QEMU test failed
                return {"success": False, "qemu_failed": True, "results": qemu_results}

            if user_choice == "run_host":
                # Skip QEMU, run directly on host
                return self._execute_on_host(script_type, script_content, target_binary, options)
            if user_choice == "always_test":
                # Save preference and run QEMU test
                self._save_qemu_preference("always", script_type)
                qemu_results = self._run_qemu_test(script_type, script_content, target_binary, options)

                if qemu_results and qemu_results.get("success"):
                    if self._show_qemu_results_and_confirm(qemu_results):
                        return self._execute_on_host(script_type, script_content, target_binary, options)
                    return {"success": False, "cancelled": True}
                return {"success": False, "qemu_failed": True, "results": qemu_results}

            if user_choice == "never_test":
                # Save preference and run on host
                self._save_qemu_preference("never", script_type)
                return self._execute_on_host(script_type, script_content, target_binary, options)

            # cancelled
            return {"success": False, "cancelled": True, "message": "User cancelled execution"}

        # Based on saved preferences or options, either test or execute directly
        if self._should_auto_test_qemu(script_type, options):
            qemu_results = self._run_qemu_test(script_type, script_content, target_binary, options)
            if qemu_results and qemu_results.get("success"):
                return self._execute_on_host(script_type, script_content, target_binary, options)
            return {"success": False, "qemu_failed": True, "results": qemu_results}
        return self._execute_on_host(script_type, script_content, target_binary, options)

    def _should_ask_qemu_testing(self, script_type: str, target_binary: str, options: dict[str, Any]) -> bool:
        """Determine if we should ask the user about QEMU testing."""
        # Check if force option is set
        if options.get("force_qemu_test") is not None:
            return False  # Don't ask, use the forced option

        # Check saved preferences
        # First check general preference from preferences dialog
        general_pref = self.config.get("qemu_testing.default_preference", "ask")
        if general_pref in ["always", "never"]:
            return False  # Don't ask, use general preference

        # Then check script-specific preference
        saved_pref = self.config.get(f"qemu_testing.script_type_preferences.{script_type}", "ask")

        if saved_pref in ["always", "never"]:
            return False  # Don't ask, use saved preference

        # Check if binary is trusted
        if self._is_trusted_binary(target_binary):
            return False  # Don't ask for trusted binaries

        return True  # Ask the user

    def _should_auto_test_qemu(self, script_type: str, options: dict[str, Any]) -> bool:
        """Check if we should automatically test in QEMU."""
        if options.get("force_qemu_test"):
            return True

        # Check general preference first
        general_pref = self.config.get("qemu_testing.default_preference", "ask")
        if general_pref == "always":
            return True
        if general_pref == "never":
            return False

        # Then check script-specific preference
        saved_pref = self.config.get(f"qemu_testing.script_type_preferences.{script_type}", "ask")

        return saved_pref == "always"

    def _is_trusted_binary(self, binary_path: str) -> bool:
        """Check if a binary is in the trusted list."""
        trusted_binaries = self.config.get("qemu_testing.trusted_binaries", [])

        if not isinstance(trusted_binaries, list):
            trusted_binaries = []

        # Normalize path
        binary_path = os.path.abspath(binary_path)

        return binary_path in trusted_binaries

    def _show_qemu_test_dialog(self, script_type: str, target_binary: str, script_content: str) -> str:
        """Show QEMU test dialog and return user choice."""
        if not self.QEMUTestDialog:
            logger.warning("QEMUTestDialog not available, defaulting to host execution")
            return "run_host"
        dialog = self.QEMUTestDialog(
            script_type=script_type,
            target_binary=target_binary,
            script_preview=script_content[:500],  # Show first 500 chars
            parent=self.parent(),
        )

        result = dialog.exec()

        if result == QDialog.Accepted:
            return dialog.get_user_choice()
        return "cancelled"

    def _run_qemu_test(self, script_type: str, script_content: str, target_binary: str, options: dict[str, Any]) -> dict[str, Any]:
        """Run script in QEMU environment."""
        if not self.qemu_manager:
            logger.error("QEMU manager not available")
            return {"success": False, "error": "QEMU testing not available"}

        self.qemu_test_started.emit(script_type, target_binary)

        try:
            # Create snapshot for testing
            snapshot_id = self._create_qemu_snapshot(target_binary, options)

            if not snapshot_id:
                return {"success": False, "error": "Failed to create QEMU snapshot"}

            # Run the appropriate test based on script type
            if script_type == "frida":
                results = self.qemu_manager.test_frida_script_enhanced(
                    snapshot_id,
                    script_content,
                    target_binary,
                )
            elif script_type == "ghidra":
                results = self.qemu_manager.test_ghidra_script_enhanced(
                    snapshot_id,
                    script_content,
                    target_binary,
                )
            else:
                results = {"success": False, "error": f"Unsupported script type: {script_type}"}

            self.qemu_test_completed.emit(script_type, results.get("success", False), results)
            return results

        except Exception as e:
            logger.exception(f"Error during QEMU test: {e}")
            error_results = {"success": False, "error": str(e)}
            self.qemu_test_completed.emit(script_type, False, error_results)
            return error_results

    def _create_qemu_snapshot(self, target_binary: str, options: dict[str, Any]) -> str | None:
        """Create QEMU snapshot for testing."""
        if not self.qemu_manager:
            return None
        try:
            # Generate unique snapshot ID
            snapshot_id = (
                f"test_{hashlib.sha256(target_binary.encode()).hexdigest()[:8]}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
            )

            # Create snapshot with binary
            success = self.qemu_manager.create_snapshot(
                snapshot_id=snapshot_id,
                binary_path=target_binary,
                os_type=options.get("os_type", "windows"),
                architecture=options.get("architecture", "x64"),
            )

            return snapshot_id if success else None

        except Exception as e:
            logger.exception(f"Error creating QEMU snapshot: {e}")
            return None

    def _show_qemu_results_and_confirm(self, qemu_results: dict[str, Any]) -> bool:
        """Show QEMU test results and ask for confirmation to proceed."""
        if not self.QEMUTestResultsDialog:
            # Fallback to simple message box
            msg = QMessageBox(self.parent())
            msg.setWindowTitle("QEMU Test Results")
            msg.setText("QEMU test completed successfully.\nProceed with host execution?")
            msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
            return msg.exec() == QMessageBox.Yes

        dialog = self.QEMUTestResultsDialog(
            test_results=qemu_results,
            parent=self.parent(),
        )

        dialog.add_action_button("Deploy to Host", "deploy")
        dialog.add_action_button("Cancel Deployment", "cancel")

        result = dialog.exec()
        user_action = dialog.get_user_action()

        # Handle dialog result based on both exec result and user action
        if result == dialog.Accepted:
            # Dialog was accepted - check user action
            if user_action == "deploy":
                logger.info("User confirmed deployment to host after reviewing QEMU results")
                return True
            logger.info("User cancelled deployment despite dialog acceptance")
            return False
        if result == dialog.Rejected:
            # Dialog was rejected (X button, Escape, etc.)
            logger.info("User rejected QEMU results dialog")
            return False
        # Handle other dialog results
        logger.warning(f"Unexpected dialog result: {result}")
        return user_action == "deploy"

    def _execute_on_host(self, script_type: str, script_content: str, target_binary: str, options: dict[str, Any]) -> dict[str, Any]:
        """Execute script on the host system."""
        self.execution_started.emit(script_type, target_binary)

        try:
            if script_type == "frida":
                results = self._execute_frida_host(script_content, target_binary, options)
            elif script_type == "ghidra":
                results = self._execute_ghidra_host(script_content, target_binary, options)
            else:
                results = {"success": False, "error": f"Unsupported script type: {script_type}"}

            self.execution_completed.emit(script_type, results.get("success", False), results)
            return results

        except Exception as e:
            logger.exception(f"Error during host execution: {e}")
            error_results = {"success": False, "error": str(e)}
            self.execution_completed.emit(script_type, False, error_results)
            return error_results

    def _execute_frida_host(self, script_content: str, target_binary: str, options: dict[str, Any]) -> dict[str, Any]:
        try:
            import tempfile

            # Save script to temporary file
            with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
                f.write(script_content)
                script_path = f.name

            # Prepare Frida command
            cmd = ["frida", "-f", target_binary, "-l", script_path]

            if options.get("no_pause"):
                cmd.append("--no-pause")

            # Execute
            if options.get("use_terminal") and HAS_TERMINAL_MANAGER:
                logger.info(f"Executing Frida script in terminal: {target_binary}")
                terminal_mgr = get_terminal_manager()

                session_id = terminal_mgr.execute_command(command=cmd, capture_output=False, auto_switch=True)

                # Note: Don't clean up script_path immediately for terminal execution
                return {
                    "success": True,
                    "terminal_session": session_id,
                    "script_path": script_path,  # Caller should clean up after terminal session ends
                    "message": "Frida script running in terminal",
                }
            else:
                # Standard execution
                result = subprocess.run(cmd, check=False, capture_output=True, text=True)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603

                # Clean up
                os.unlink(script_path)

                return {
                    "success": result.returncode == 0,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "returncode": result.returncode,
                }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _execute_ghidra_host(self, script_content: str, target_binary: str, options: dict[str, Any]) -> dict[str, Any]:
        try:
            import tempfile

            # Find Ghidra installation
            ghidra_path = self._find_ghidra_installation()
            if not ghidra_path:
                return {"success": False, "error": "Ghidra installation not found"}

            # Save script to temporary file
            with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
                f.write(script_content)
                script_path = f.name

            # Prepare Ghidra command with options support
            analyze_headless = os.path.join(ghidra_path, "support", "analyzeHeadless")
            project_path = tempfile.mkdtemp()
            project_name = "temp_project"

            cmd = [
                analyze_headless,
                project_path,
                project_name,
                "-import",
                target_binary,
                "-postScript",
                script_path,
            ]

            # Add command-line options from the options parameter
            if options:
                # Memory settings
                if "max_memory" in options:
                    cmd.extend(["-max-cpu", str(options["max_memory"])])

                # Analysis options
                if options.get("analyze", True):
                    cmd.append("-analyse")

                # Processor specification
                if "processor" in options:
                    cmd.extend(["-processor", options["processor"]])

                # Custom script arguments
                if "script_args" in options:
                    for arg in options["script_args"]:
                        cmd.append(str(arg))

                # Output options
                if options.get("verbose", False):
                    cmd.append("-log-level")
                    cmd.append("DEBUG")

                # Timeout settings
                timeout = options.get("timeout", 300)  # Default 5 minutes
            else:
                timeout = 300

            # Execute with timeout support
            if options.get("use_terminal") and HAS_TERMINAL_MANAGER:
                logger.info(f"Executing Ghidra script in terminal: {target_binary}")
                terminal_mgr = get_terminal_manager()

                session_id = terminal_mgr.execute_command(command=cmd, capture_output=False, auto_switch=True)

                # Note: Don't clean up immediately for terminal execution
                return {
                    "success": True,
                    "terminal_session": session_id,
                    "script_path": script_path,
                    "project_path": str(project_path),
                    "message": "Ghidra script running in terminal",
                }
            else:
                # Standard execution
                result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis  # noqa: S603
                    cmd, check=False, capture_output=True, text=True, timeout=timeout
                )

                # Clean up
                os.unlink(script_path)
                import shutil

                shutil.rmtree(project_path, ignore_errors=True)

                return {
                    "success": result.returncode == 0,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "returncode": result.returncode,
                }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _find_ghidra_installation(self) -> str | None:
        """Find Ghidra installation path."""
        # Check common locations
        possible_paths = [
            os.environ.get("GHIDRA_HOME"),
            os.path.expanduser("~/ghidra"),
            "/opt/ghidra",
            "C:\\ghidra",
            "C:\\Program Files\\ghidra",
        ]

        for path in possible_paths:
            if path and os.path.exists(path):
                return path
        return None

    def _save_qemu_preference(self, preference: str, script_type: str):
        """Save QEMU testing preference."""
        self.config.set(f"qemu_testing.script_type_preferences.{script_type}", preference)

    def add_trusted_binary(self, binary_path: str):
        """Add binary to trusted list."""
        binary_path = os.path.abspath(binary_path)
        trusted_binaries = self.config.get("qemu_testing.trusted_binaries", [])

        if not isinstance(trusted_binaries, list):
            trusted_binaries = []

        if binary_path not in trusted_binaries:
            trusted_binaries.append(binary_path)
            self.config.set("qemu_testing.trusted_binaries", trusted_binaries)

    def remove_trusted_binary(self, binary_path: str):
        """Remove binary from trusted list."""
        binary_path = os.path.abspath(binary_path)
        trusted_binaries = self.config.get("qemu_testing.trusted_binaries", [])

        if not isinstance(trusted_binaries, list):
            trusted_binaries = []

        if binary_path in trusted_binaries:
            trusted_binaries.remove(binary_path)
            self.config.set("qemu_testing.trusted_binaries", trusted_binaries)

    def get_execution_history(self, limit: int = 50) -> list[dict[str, Any]]:
        """Get recent execution history."""
        history = self.config.get("qemu_testing.execution_history", [])

        if not isinstance(history, list):
            history = []

        return history[:limit]

    def _add_to_history(self, script_type: str, target_binary: str, success: bool, timestamp: datetime.datetime):
        """Add execution to history."""
        history = self.config.get("qemu_testing.execution_history", [])

        if not isinstance(history, list):
            history = []

        entry = {
            "script_type": script_type,
            "target_binary": target_binary,
            "success": success,
            "timestamp": timestamp.isoformat(),
        }

        history.insert(0, entry)  # Add to beginning

        # Keep only last 100 entries
        history = history[:100]

        self.config.set("qemu_testing.execution_history", history)
