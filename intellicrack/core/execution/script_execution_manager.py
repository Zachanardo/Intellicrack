"""Script execution manager for Intellicrack core execution.

This file is part of Intellicrack.
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
from pathlib import Path
from typing import TYPE_CHECKING, Any

from intellicrack.handlers.pyqt6_handler import QDialog, QMessageBox, QObject, QWidget, pyqtSignal
from intellicrack.utils.type_safety import validate_type


if TYPE_CHECKING:
    from intellicrack.ai.qemu_manager import QEMUManager
    from intellicrack.ui.dialogs.qemu_test_dialog import QEMUTestDialog
    from intellicrack.ui.dialogs.qemu_test_results_dialog import QEMUTestResultsDialog

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

    def __init__(self) -> None:
        """Initialize the script execution manager with task queues and monitoring."""
        super().__init__()
        self.running_scripts: dict[str, Any] = {}
        self.script_history: dict[str, Any] = {}
        self.script_queue: list[dict[str, Any]] = []
        self.logger = get_logger(__name__)
        self.max_concurrent_scripts = 5
        self.config = get_config()
        self.qemu_manager: QEMUManager | None = None
        self.QEMUTestDialog: type[QEMUTestDialog] | None = None
        self.QEMUTestResultsDialog: type[QEMUTestResultsDialog] | None = None
        self._initialize_managers()

    def _initialize_managers(self) -> None:
        """Initialize QEMU manager and dialog components.

        Attempts to load QEMU manager and related dialog classes from their
        respective modules. If import fails, components are left uninitialized
        and a warning is logged for graceful degradation.
        """
        try:
            from intellicrack.ai.qemu_manager import QEMUManager as EnhancedQEMUManager
            from intellicrack.ui.dialogs.qemu_test_dialog import QEMUTestDialog
            from intellicrack.ui.dialogs.qemu_test_results_dialog import QEMUTestResultsDialog

            self.qemu_manager = EnhancedQEMUManager()
            self.QEMUTestDialog = QEMUTestDialog
            self.QEMUTestResultsDialog = QEMUTestResultsDialog
        except ImportError as e:
            logger.warning("Could not initialize QEMU components: %s", e)
            self.qemu_manager = None

    def execute_script(
        self,
        script_type: str,
        script_content: str,
        target_binary: str,
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute a script with optional QEMU pre-testing and user prompts.

        Orchestrates full script execution workflow including optional QEMU
        testing before host deployment. Evaluates user preferences and QEMU
        testing configuration to determine whether to prompt user, test in
        QEMU first, or execute directly on host. Manages preference storage
        and handles all execution branches.

        Args:
            script_type: Type of script to execute ('frida', 'ghidra', etc.)
            script_content: Complete script code content
            target_binary: Path to the binary for analysis
            options: Execution options dict with optional keys: force_qemu_test,
                use_terminal, no_pause, os_type, architecture, timeout, etc.

        Returns:
            Execution results dictionary with success (bool), and execution
            output depending on execution path (stdout, stderr, returncode,
            terminal_session, error message, etc.).
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
        """Determine if user should be prompted about QEMU testing.

        Evaluates whether to show the QEMU testing dialog based on forced
        options, global preferences, script-type preferences, and binary trust
        status. Returns False if execution should proceed without user prompt.

        Args:
            script_type: Type of script being executed ('frida', 'ghidra', etc.)
            target_binary: Path to the binary being analyzed
            options: Execution options including 'force_qemu_test'

        Returns:
            True if user should be prompted for QEMU testing; False if preferences
            or forced options determine behavior automatically.
        """
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
            return False

        return not self._is_trusted_binary(target_binary)

    def _should_auto_test_qemu(self, script_type: str, options: dict[str, Any]) -> bool:
        """Check if QEMU testing should be performed automatically.

        Evaluates global and script-type specific preferences to determine
        whether QEMU testing should proceed without user intervention. Forced
        options take precedence over all saved preferences.

        Args:
            script_type: Type of script being executed ('frida', 'ghidra', etc.)
            options: Execution options including 'force_qemu_test'

        Returns:
            True if QEMU testing should proceed; False otherwise.
        """
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
        """Check if a binary is in the trusted list.

        Normalizes the provided binary path and checks against the configured
        list of trusted binaries. Trusted binaries can skip QEMU testing
        requirements.

        Args:
            binary_path: Path to the binary to check

        Returns:
            True if binary is in the trusted list; False otherwise.
        """
        trusted_binaries = self.config.get("qemu_testing.trusted_binaries", [])

        if not isinstance(trusted_binaries, list):
            trusted_binaries = []

        # Normalize path
        binary_path = os.path.abspath(binary_path)

        return binary_path in trusted_binaries

    def _show_qemu_test_dialog(self, script_type: str, target_binary: str, script_content: str) -> str:
        """Display QEMU testing dialog and retrieve user selection.

        Shows a modal dialog prompting the user for QEMU testing preferences.
        If the dialog component is unavailable, defaults to host execution.
        The dialog displays a preview of the script content (first 500 chars).

        Args:
            script_type: Type of script being executed ('frida', 'ghidra', etc.)
            target_binary: Path to the binary being analyzed
            script_content: The complete script content to preview

        Returns:
            User's choice as string ('test_qemu', 'run_host', 'always_test',
            'never_test', or 'cancelled'). Defaults to 'run_host' if dialog
            is unavailable.
        """
        if not self.QEMUTestDialog:
            logger.warning("QEMUTestDialog not available, defaulting to host execution")
            return "run_host"

        parent_widget = validate_type(self.parent(), QWidget) if self.parent() is not None else None
        dialog = self.QEMUTestDialog(
            script_type=script_type,
            target_binary=target_binary,
            script_preview=script_content[:500],
            parent=parent_widget,
        )

        result = dialog.exec()
        accepted_value = getattr(QDialog, "Accepted", 1)
        return dialog.get_user_choice() if result == accepted_value else "cancelled"

    def _run_qemu_test(self, script_type: str, script_content: str, target_binary: str, options: dict[str, Any]) -> dict[str, Any]:
        """Execute script in isolated QEMU environment for testing.

        Creates a QEMU snapshot and executes the provided script within that
        isolated environment. Supports both Frida and Ghidra script types.
        Emits signals at start and completion of testing. Returns detailed
        results including success status and error information.

        Args:
            script_type: Type of script to execute ('frida' or 'ghidra')
            script_content: The script code to execute
            target_binary: Path to the binary to analyze
            options: Execution options including os_type and architecture

        Returns:
            Dictionary with keys: success (bool), error (str if failed), and
            additional execution results depending on script type. Returns
            failure response if QEMU manager unavailable or snapshot creation fails.
        """
        if not self.qemu_manager:
            logger.error("QEMU manager not available")
            return {"success": False, "error": "QEMU testing not available"}

        self.qemu_test_started.emit(script_type, target_binary)

        try:
            snapshot_id = self._create_qemu_snapshot(target_binary, options)

            if not snapshot_id:
                return {"success": False, "error": "Failed to create QEMU snapshot"}

            results: dict[str, Any]
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
            logger.exception("Error during QEMU test: %s", e)
            error_results: dict[str, Any] = {"success": False, "error": str(e)}
            self.qemu_test_completed.emit(script_type, False, error_results)
            return error_results

    def _create_qemu_snapshot(self, target_binary: str, options: dict[str, Any]) -> str | None:
        """Create QEMU snapshot for isolated testing environment.

        Generates a unique snapshot identifier based on the binary path and
        current timestamp, then creates a QEMU snapshot with the specified
        OS type and architecture. Used for pre-testing scripts in isolation
        before deployment to host system.

        Args:
            target_binary: Path to the binary to snapshot
            options: Configuration with 'os_type' (default 'windows') and
                'architecture' (default 'x64')

        Returns:
            Snapshot ID string if creation succeeds; None if QEMU manager
            unavailable, creation fails, or exception occurs.
        """
        if not self.qemu_manager:
            return None
        try:
            snapshot_id = (
                f"test_{hashlib.sha256(target_binary.encode()).hexdigest()[:8]}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
            )

            success = self.qemu_manager.create_snapshot(
                snapshot_id=snapshot_id,
                binary_path=target_binary,
                os_type=options.get("os_type", "windows"),
                architecture=options.get("architecture", "x64"),
            )

            return snapshot_id if success else None

        except Exception as e:
            logger.exception("Error creating QEMU snapshot: %s", e)
            return None

    def _show_qemu_results_and_confirm(self, qemu_results: dict[str, Any]) -> bool:
        """Display QEMU test results and prompt user for deployment confirmation.

        Shows test results from QEMU execution and requests user confirmation
        to proceed with host deployment. Uses dedicated results dialog if
        available; falls back to simple message box. Returns True only if user
        explicitly confirms deployment.

        Args:
            qemu_results: Dictionary containing QEMU test results

        Returns:
            True if user confirms deployment to host; False if user cancels
            or dialog is rejected.
        """
        if not self.QEMUTestResultsDialog:
            parent_widget = validate_type(self.parent(), QWidget) if self.parent() is not None else None
            msg = QMessageBox(parent_widget)
            msg.setWindowTitle("QEMU Test Results")
            msg.setText("QEMU test completed successfully.\nProceed with host execution?")
            msg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            result = msg.exec()
            return result == int(QMessageBox.StandardButton.Yes)

        parent_widget = validate_type(self.parent(), QWidget) if self.parent() is not None else None
        dialog = self.QEMUTestResultsDialog(
            test_results=qemu_results,
            parent=parent_widget,
        )

        dialog.add_action_button("Deploy to Host", "deploy")
        dialog.add_action_button("Cancel Deployment", "cancel")

        result = dialog.exec()
        user_action: str = dialog.get_user_action()

        accepted_value = getattr(dialog, "Accepted", 1)
        rejected_value = getattr(dialog, "Rejected", 0)

        if result == accepted_value:
            if user_action == "deploy":
                logger.info("User confirmed deployment to host after reviewing QEMU results")
                return True
            logger.info("User cancelled deployment despite dialog acceptance")
            return False
        if result == rejected_value:
            logger.info("User rejected QEMU results dialog")
            return False
        logger.warning("Unexpected dialog result: %s", result)
        return bool(user_action == "deploy")

    def _execute_on_host(self, script_type: str, script_content: str, target_binary: str, options: dict[str, Any]) -> dict[str, Any]:
        """Execute script on the host system.

        Dispatches script execution to the appropriate handler based on script
        type (Frida or Ghidra). Emits execution start and completion signals
        with execution results. Returns detailed execution results including
        stdout, stderr, and return code.

        Args:
            script_type: Type of script to execute ('frida' or 'ghidra')
            script_content: The script code to execute
            target_binary: Path to the binary to analyze
            options: Execution options (use_terminal, no_pause, etc.)

        Returns:
            Dictionary with keys: success (bool), stdout (str), stderr (str),
            returncode (int), and error (str if failed).
        """
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
            logger.exception("Error during host execution: %s", e)
            error_results = {"success": False, "error": str(e)}
            self.execution_completed.emit(script_type, False, error_results)
            return error_results

    def _execute_frida_host(self, script_content: str, target_binary: str, options: dict[str, Any]) -> dict[str, Any]:
        """Execute Frida script on host system against target binary.

        Writes script content to temporary file and executes Frida with the
        target binary. Supports both terminal (interactive) and subprocess
        execution modes. Terminal execution does not clean up script file
        immediately; caller must handle cleanup after session ends.

        Args:
            script_content: JavaScript code for Frida instrumentation
            target_binary: Path to binary to instrument with Frida
            options: Execution options with 'no_pause' (bool) and
                'use_terminal' (bool) keys

        Returns:
            For terminal execution: Dictionary with success, terminal_session,
            script_path, message keys. For subprocess execution: Dictionary
            with success (bool), stdout (str), stderr (str), returncode (int).
        """
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
                logger.info("Executing Frida script in terminal: %s", target_binary)
                terminal_mgr = get_terminal_manager()

                session_id = terminal_mgr.execute_command(command=cmd, capture_output=False, auto_switch=True)

                # Note: Don't clean up script_path immediately for terminal execution
                return {
                    "success": True,
                    "terminal_session": session_id,
                    "script_path": script_path,  # Caller should clean up after terminal session ends
                    "message": "Frida script running in terminal",
                }
            # Standard execution
            result = subprocess.run(cmd, check=False, capture_output=True, text=True)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis

            # Clean up
            Path(script_path).unlink()

            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _execute_ghidra_host(self, script_content: str, target_binary: str, options: dict[str, Any]) -> dict[str, Any]:
        """Execute Ghidra headless analysis script on host system.

        Locates Ghidra installation, creates temporary project and script files,
        then executes Ghidra's analyzeHeadless with the target binary. Supports
        both terminal (interactive) and subprocess execution modes. Terminal
        execution does not clean up script/project files immediately; caller
        must handle cleanup after session ends.

        Args:
            script_content: Python code for Ghidra analysis script
            target_binary: Path to binary to analyze with Ghidra
            options: Execution options with 'max_memory', 'analyze' (bool),
                'processor', 'script_args', 'verbose' (bool), 'timeout' (int,
                default 300), 'use_terminal' (bool)

        Returns:
            For terminal execution: Dictionary with success, terminal_session,
            script_path, project_path, message keys. For subprocess execution:
            Dictionary with success (bool), stdout (str), stderr (str),
            returncode (int).
        """
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
                    cmd.extend(str(arg) for arg in options["script_args"])
                # Output options
                if options.get("verbose"):
                    cmd.extend(("-log-level", "DEBUG"))
                # Timeout settings
                timeout = options.get("timeout", 300)  # Default 5 minutes
            else:
                timeout = 300

            # Execute with timeout support
            if options.get("use_terminal") and HAS_TERMINAL_MANAGER:
                logger.info("Executing Ghidra script in terminal: %s", target_binary)
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
            # Standard execution
            result = subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
                cmd,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            # Clean up
            Path(script_path).unlink()
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
        """Locate Ghidra installation directory on the system.

        Searches common installation locations including the GHIDRA_HOME
        environment variable, user home directory, system directories, and
        Windows Program Files. Returns the first existing path found.

        Returns:
            Path to Ghidra installation directory if found; None if no
            installation is detected.
        """
        # Check common locations
        possible_paths = [
            os.environ.get("GHIDRA_HOME"),
            os.path.expanduser("~/ghidra"),
            "/opt/ghidra",
            "C:\\ghidra",
            "C:\\Program Files\\ghidra",
        ]

        return next(
            (path for path in possible_paths if path and os.path.exists(path)),
            None,
        )

    def _save_qemu_preference(self, preference: str, script_type: str) -> None:
        """Save user's QEMU testing preference for script type.

        Persists the user's preference for QEMU testing (always, never, ask)
        to the configuration for the specified script type. Preferences are
        used to determine future behavior without user prompts.

        Args:
            preference: Testing preference ('always', 'never', or 'ask')
            script_type: Script type to apply preference to ('frida', 'ghidra', etc.)
        """
        self.config.set(f"qemu_testing.script_type_preferences.{script_type}", preference)

    def add_trusted_binary(self, binary_path: str) -> None:
        """Add binary to trusted binaries list for QEMU testing exemption.

        Registers a binary as trusted, allowing it to skip QEMU testing
        requirements. Path is normalized to absolute form. If binary is already
        in the list, no action is taken.

        Args:
            binary_path: Path to the binary to add to trusted list
        """
        binary_path = os.path.abspath(binary_path)
        trusted_binaries = self.config.get("qemu_testing.trusted_binaries", [])

        if not isinstance(trusted_binaries, list):
            trusted_binaries = []

        if binary_path not in trusted_binaries:
            trusted_binaries.append(binary_path)
            self.config.set("qemu_testing.trusted_binaries", trusted_binaries)

    def remove_trusted_binary(self, binary_path: str) -> None:
        """Remove binary from trusted binaries list.

        Revokes trusted status from a binary, requiring QEMU testing for future
        script executions against it. Path is normalized to absolute form. If
        binary is not in the list, no action is taken.

        Args:
            binary_path: Path to the binary to remove from trusted list
        """
        binary_path = os.path.abspath(binary_path)
        trusted_binaries = self.config.get("qemu_testing.trusted_binaries", [])

        if not isinstance(trusted_binaries, list):
            trusted_binaries = []

        if binary_path in trusted_binaries:
            trusted_binaries.remove(binary_path)
            self.config.set("qemu_testing.trusted_binaries", trusted_binaries)

    def get_execution_history(self, limit: int = 50) -> list[dict[str, Any]]:
        """Retrieve recent script execution history.

        Returns the most recent script execution records up to the specified
        limit. Each record contains script type, target binary, success status,
        and timestamp of the execution.

        Args:
            limit: Maximum number of history entries to return (default 50)

        Returns:
            List of execution history dictionaries, newest first, limited to
            specified count.
        """
        history = self.config.get("qemu_testing.execution_history", [])

        if not isinstance(history, list):
            history = []

        return history[:limit]

    def _add_to_history(self, script_type: str, target_binary: str, success: bool, timestamp: datetime.datetime) -> None:
        """Add script execution record to execution history.

        Records the execution of a script with its metadata. New entries are
        inserted at the beginning of the history list. History is trimmed to
        keep only the most recent 100 entries to prevent unbounded growth.

        Args:
            script_type: Type of script executed ('frida', 'ghidra', etc.)
            target_binary: Path to the binary that was analyzed
            success: Whether the execution succeeded
            timestamp: Datetime when execution occurred
        """
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
