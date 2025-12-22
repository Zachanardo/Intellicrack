"""Terminal Manager for Intellicrack core functionality.

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

Terminal Manager

Centralized singleton service for all terminal operations and subprocess
management in Intellicrack. Provides unified interface for executing scripts
and commands with optional terminal display.
"""

import logging
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from intellicrack.ui.main_app import IntellicrackApp
    from intellicrack.ui.widgets.terminal_session_widget import TerminalSessionWidget

logger = logging.getLogger(__name__)


class TerminalManager:
    """Singleton manager for all terminal operations in Intellicrack.

    Provides centralized management of:
    - Terminal widget registration
    - Script execution in terminal
    - Command execution (with or without capture)
    - Auto-navigation to Terminal tab
    - Script path resolution
    """

    _instance: "TerminalManager | None" = None

    def __new__(cls) -> "TerminalManager":
        """Singleton pattern implementation."""
        if cls._instance is None:
            instance = super().__new__(cls)
            instance._initialized = False
            cls._instance = instance

        return cls._instance

    def __init__(self) -> None:
        """Initialize terminal manager."""
        if getattr(self, "_initialized", False):
            return

        self._terminal_widget: "TerminalSessionWidget | None" = None
        self._main_app: "IntellicrackApp | None" = None
        self._sessions: dict[str, Any] = {}
        self._logger: logging.Logger = logging.getLogger(__name__)

        self._initialized: bool = True

        logger.info("TerminalManager singleton initialized")

    def register_terminal_widget(self, widget: "TerminalSessionWidget") -> None:
        """Register the main terminal widget from Terminal tab.

        Args:
            widget: TerminalSessionWidget instance

        Raises:
            TypeError: If widget is not correct type

        """
        self._terminal_widget = widget
        logger.info("Terminal widget registered with TerminalManager")

    def set_main_app(self, app: "IntellicrackApp") -> None:
        """Set reference to main app for tab switching.

        Args:
            app: IntellicrackApp instance

        Raises:
            ValueError: If app doesn't have required 'tabs' attribute

        """
        if not hasattr(app, "tabs"):
            error_msg = "Main app must have 'tabs' attribute for tab switching"
            logger.error(error_msg)
            raise ValueError(error_msg)

        self._main_app = app
        logger.info("Main app registered with TerminalManager")

    def _switch_to_terminal_tab(self) -> None:
        """Switch main app to Terminal tab."""
        if not self._main_app:
            logger.warning("Cannot switch to terminal tab: main app not registered")
            return

        tabs = self._main_app.tabs

        for i in range(tabs.count()):
            tab_text = tabs.tabText(i)
            if "terminal" in tab_text.lower():
                tabs.setCurrentIndex(i)
                logger.info("Switched to Terminal tab (index %d)", i)

                if self._terminal_widget:
                    _session_id, terminal = self._terminal_widget.get_active_session()
                    if terminal:
                        terminal.terminal_display.setFocus()

                return

        logger.warning("Terminal tab not found in main app")

    def _resolve_script_path(self, script_path: str | Path) -> Path:
        """Resolve script path relative to intellicrack/scripts/ directory.

        Args:
            script_path: Path to script (absolute or relative)

        Returns:
            Resolved Path object

        Raises:
            FileNotFoundError: If script doesn't exist

        """
        path = Path(script_path)

        if path.is_absolute():
            if not path.exists():
                error_msg = f"Script not found: {path}"
                logger.error(error_msg)
                raise FileNotFoundError(error_msg)
            return path

        base_scripts_dir = Path(__file__).parent.parent / "scripts"

        resolved = base_scripts_dir / path

        if not resolved.exists():
            error_msg = f"Script not found: {resolved}\nLooked in: {base_scripts_dir}"
            logger.error(error_msg)
            raise FileNotFoundError(error_msg)

        return resolved

    def execute_script(
        self,
        script_path: str | Path,
        interactive: bool = True,
        auto_switch: bool = True,
        cwd: str | Path | None = None,
    ) -> str:
        """Execute script in terminal session.

        Args:
            script_path: Path to script (relative to intellicrack/scripts/ or absolute)
            interactive: Whether script requires user interaction
            auto_switch: Whether to auto-switch to Terminal tab
            cwd: Working directory (defaults to script's directory)

        Returns:
            Session ID (string)

        Raises:
            RuntimeError: If terminal widget not registered
            FileNotFoundError: If script doesn't exist

        """
        if not self._terminal_widget:
            error_msg = "Terminal widget not registered. Cannot execute script in terminal."
            logger.error(error_msg)
            raise RuntimeError(error_msg)

        resolved_path = self._resolve_script_path(script_path)

        logger.info("Executing script: %s", resolved_path)

        if cwd is None:
            cwd = str(resolved_path.parent)

        suffix = resolved_path.suffix.lower()

        if suffix in [".cmd", ".bat"]:
            if interactive:
                command = ["cmd", "/k", str(resolved_path)]
            else:
                command = ["cmd", "/c", str(resolved_path)]

        elif suffix == ".ps1":
            command = ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(resolved_path)]

        elif suffix == ".py":
            python_exe = sys.executable
            command = [python_exe, str(resolved_path)]

        elif suffix == ".js":
            logger.warning("JavaScript files require Frida. Use frida_handler for .js scripts.")
            command = ["node", str(resolved_path)]

        else:
            logger.warning("Unknown script type: %s, attempting direct execution", suffix)
            command = [str(resolved_path)]

        if auto_switch:
            self._switch_to_terminal_tab()

        session_id, terminal = self._terminal_widget.get_active_session()

        if not terminal:
            session_id = self._terminal_widget.create_new_session()
            session_id, terminal = self._terminal_widget.get_active_session()

        if terminal is not None:
            cwd_str = str(cwd) if isinstance(cwd, Path) else cwd
            if pid := terminal.start_process(command, cwd=cwd_str):
                logger.info("Script started in terminal session %s with PID %s", session_id, pid)
            else:
                logger.error("Failed to start script in terminal")

        return session_id if session_id is not None else ""

    def execute_command(
        self,
        command: str | list[str],
        capture_output: bool = False,
        auto_switch: bool = False,
        cwd: str | Path | None = None,
    ) -> str | tuple[int, str, str]:
        """Execute command, return output if capture_output=True.

        Args:
            command: Command as list of strings
            capture_output: If True, capture and return output instead of showing in terminal
            auto_switch: If True, switch to Terminal tab (only when not capturing)
            cwd: Working directory

        Returns:
            If capture_output=True: tuple (returncode, stdout, stderr)
            If capture_output=False: session_id (string)

        Raises:
            RuntimeError: If terminal widget not registered (when not capturing)

        """
        if isinstance(command, str):
            command = command.split()

        if capture_output:
            logger.info("Executing command with capture: %s", " ".join(command))

            try:
                # Validate that command and cwd contain only safe values to prevent command injection
                if not isinstance(command, list) or not all(isinstance(arg, str) for arg in command):
                    error_msg = f"Unsafe command: {command}"
                    logger.error(error_msg)
                    raise ValueError(error_msg)
                cwd_clean = str(cwd).replace(";", "").replace("|", "").replace("&", "")
                result = subprocess.run(command, capture_output=True, text=True, cwd=cwd_clean, timeout=300, shell=False)

                return (result.returncode, result.stdout, result.stderr)

            except subprocess.TimeoutExpired:
                logger.exception("Command execution timed out")
                return (1, "", "Command timed out")

            except Exception as e:
                logger.exception("Error executing command: %s", e)
                return (1, "", str(e))

        else:
            if not self._terminal_widget:
                error_msg = "Terminal widget not registered. Cannot execute command in terminal."
                logger.error(error_msg)
                raise RuntimeError(error_msg)

            logger.info("Executing command in terminal: %s", " ".join(command))

            if auto_switch:
                self._switch_to_terminal_tab()

            session_id, terminal = self._terminal_widget.get_active_session()

            if not terminal:
                session_id = self._terminal_widget.create_new_session()
                session_id, terminal = self._terminal_widget.get_active_session()

            if terminal is not None:
                cwd_str = str(cwd) if isinstance(cwd, Path) else cwd
                if pid := terminal.start_process(command, cwd=cwd_str):
                    logger.info("Command started in terminal session %s with PID %s", session_id, pid)
                else:
                    logger.error("Failed to start command in terminal")

            return session_id if session_id is not None else ""

    def is_terminal_available(self) -> bool:
        """Check if terminal widget is available for use.

        Returns:
            bool: True if terminal widget is registered

        """
        return self._terminal_widget is not None

    def get_terminal_widget(self) -> "TerminalSessionWidget | None":
        """Get the registered terminal widget.

        Returns:
            TerminalSessionWidget or None

        """
        return self._terminal_widget

    def log_terminal_message(self, message: str, level: str = "INFO") -> None:
        """Log a message to the terminal widget.

        Args:
            message: Message to log
            level: Log level (INFO, WARNING, ERROR)

        """
        if self._terminal_widget:
            try:
                _session_id, terminal = self._terminal_widget.get_active_session()
                if terminal and hasattr(terminal, "write_output"):
                    formatted_message = f"[{level}] {message}\n"
                    terminal.write_output(formatted_message)
                else:
                    logger.debug("Terminal widget available but session not ready: %s", message)
            except Exception as e:
                logger.warning("Failed to log to terminal widget: %s", e)
        else:
            logger.debug("Terminal widget not available, logging to logger: %s", message)


def get_terminal_manager() -> TerminalManager:
    """Get TerminalManager singleton instance.

    Returns:
        TerminalManager: The singleton instance

    """
    return TerminalManager()
