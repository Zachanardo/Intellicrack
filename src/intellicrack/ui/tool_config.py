"""Tool configuration dialog for Intellicrack.

This module provides the UI for configuring reverse engineering tool
bridges, including path settings, installation, and connection options.
"""

from __future__ import annotations

import json
import os
import subprocess  # noqa: S404
import tempfile
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

import httpx
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)


if TYPE_CHECKING:
    from intellicrack.core.tools import ToolRegistry

HTTP_OK = 200
EXPECTED_TOOL_COUNT = 6


class ToolInstallWorker(QThread):
    """Worker thread for installing tools.

    Downloads and installs tools in a separate thread to avoid blocking UI.

    Attributes:
        progress: Signal emitted with progress percentage (0-100).
        finished: Signal emitted when installation completes with (success, message).
    """

    progress: pyqtSignal = pyqtSignal(int)
    finished: pyqtSignal = pyqtSignal(bool, str)

    DOWNLOAD_URLS: ClassVar[dict[str, dict[str, str]]] = {
        "ghidra": {
            "url": "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.2.1_build/ghidra_11.2.1_PUBLIC_20241105.zip",
            "name": "Ghidra 11.2.1",
        },
        "x64dbg": {
            "url": "https://github.com/x64dbg/x64dbg/releases/download/snapshot/snapshot_2024-01-01_00-00.zip",
            "name": "x64dbg Snapshot",
        },
        "radare2": {
            "url": "https://github.com/radareorg/radare2/releases/download/5.9.6/radare2-5.9.6-w64.zip",
            "name": "radare2 5.9.6",
        },
    }

    def __init__(
        self,
        tool_id: str,
        install_path: Path,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the tool install worker.

        Args:
            tool_id: The tool identifier.
            install_path: Directory to install the tool.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._tool_id = tool_id
        self._install_path = install_path

    def run(self) -> None:
        """Run the installation in a separate thread."""
        try:
            self._install_tool()
        except Exception as e:
            self.finished.emit(False, f"Installation failed: {e}")

    def _install_tool(self) -> None:
        """Download and install the tool."""
        if self._tool_id not in self.DOWNLOAD_URLS:
            self.finished.emit(False, f"No download URL for {self._tool_id}")
            return

        tool_info = self.DOWNLOAD_URLS[self._tool_id]
        url = tool_info["url"]
        name = tool_info["name"]

        self.progress.emit(5)

        self._install_path.mkdir(parents=True, exist_ok=True)

        with tempfile.TemporaryDirectory() as temp_dir:  # noqa: PLR1702
            temp_path = Path(temp_dir)
            zip_path = temp_path / f"{self._tool_id}.zip"

            self.progress.emit(10)

            try:
                with (
                    httpx.Client(timeout=httpx.Timeout(300.0, connect=30.0)) as client,
                    client.stream("GET", url, follow_redirects=True) as response,
                ):
                    if response.status_code != HTTP_OK:
                        self.finished.emit(
                            False,
                            f"Download failed: HTTP {response.status_code}",
                        )
                        return

                    total = int(response.headers.get("content-length", 0))
                    downloaded = 0

                    with open(zip_path, "wb") as f:
                        for chunk in response.iter_bytes(chunk_size=8192):
                            f.write(chunk)
                            downloaded += len(chunk)
                            if total > 0:
                                pct = int(10 + (downloaded / total) * 70)
                                self.progress.emit(pct)

            except httpx.TimeoutException:
                self.finished.emit(False, "Download timed out")
                return
            except httpx.ConnectError:
                self.finished.emit(False, "Could not connect to download server")
                return

            self.progress.emit(85)

            try:
                with zipfile.ZipFile(zip_path, "r") as zf:
                    zf.extractall(self._install_path)
            except zipfile.BadZipFile:
                self.finished.emit(False, "Downloaded file is not a valid ZIP archive")
                return

            self.progress.emit(95)

            if self._tool_id == "ghidra":
                self._post_install_ghidra()
            elif self._tool_id == "radare2":
                self._post_install_radare2()

            self.progress.emit(100)
            self.finished.emit(True, f"{name} installed successfully")

    def _post_install_ghidra(self) -> None:
        """Post-installation setup for Ghidra."""
        for item in self._install_path.iterdir():
            if item.is_dir() and item.name.startswith("ghidra_"):
                break

    def _post_install_radare2(self) -> None:
        """Post-installation setup for radare2."""
        bin_path = self._install_path / "bin"
        if bin_path.exists():
            current_path = os.environ.get("PATH", "")
            if str(bin_path) not in current_path:
                pass


class ToolStatusCheckWorker(QThread):
    """Worker thread for checking tool status.

    Attributes:
        finished: Signal emitted when check completes with (tool_id, is_available, message).
    """

    finished: pyqtSignal = pyqtSignal(str, bool, str)

    def __init__(
        self,
        tool_id: str,
        tool_path: str,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the status check worker.

        Args:
            tool_id: The tool identifier.
            tool_path: Path to the tool installation.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._tool_id = tool_id
        self._tool_path = tool_path

    def run(self) -> None:
        """Run the status check in a separate thread."""
        try:
            is_available, message = self._check_tool()
            self.finished.emit(self._tool_id, is_available, message)
        except Exception as e:
            self.finished.emit(self._tool_id, False, f"Check failed: {e}")

    def _check_tool(self) -> tuple[bool, str]:
        """Check if the tool is available and working.

        Returns:
            Tuple of (is_available, status_message).
        """
        if self._tool_id in {"frida", "process", "binary"}:
            return self._check_builtin()

        if not self._tool_path:
            return False, "Path not configured"

        tool_path = Path(self._tool_path)
        if not tool_path.exists():
            return False, "Path does not exist"

        if self._tool_id == "ghidra":
            return self._check_ghidra(tool_path)
        if self._tool_id == "x64dbg":
            return self._check_x64dbg(tool_path)
        if self._tool_id == "radare2":
            return self._check_radare2(tool_path)

        return True, "Installed"

    def _check_builtin(self) -> tuple[bool, str]:
        """Check built-in tools.

        Returns:
            Tuple of (is_available, status_message).
        """
        if self._tool_id == "frida":
            try:
                import frida  # noqa: F401, PLC0415
            except ImportError:
                return False, "Frida not installed (pip install frida)"
            else:
                return True, "Frida available"

        return True, "Available (built-in)"

    def _check_ghidra(self, tool_path: Path) -> tuple[bool, str]:  # noqa: PLR6301
        """Check Ghidra installation.

        Args:
            tool_path: Path to Ghidra installation.

        Returns:
            Tuple of (is_available, status_message).
        """
        ghidra_run = None
        for item in tool_path.iterdir():
            if item.is_dir() and item.name.startswith("ghidra_"):
                ghidra_run = item / "ghidraRun.bat"
                if not ghidra_run.exists():
                    ghidra_run = item / "ghidraRun"
                break

        if ghidra_run is None:
            for candidate in [
                tool_path / "ghidraRun.bat",
                tool_path / "ghidraRun",
            ]:
                if candidate.exists():
                    ghidra_run = candidate
                    break

        if ghidra_run and ghidra_run.exists():
            return True, "Ghidra installed"

        return False, "ghidraRun not found in installation"

    def _check_x64dbg(self, tool_path: Path) -> tuple[bool, str]:  # noqa: PLR6301
        """Check x64dbg installation.

        Args:
            tool_path: Path to x64dbg installation.

        Returns:
            Tuple of (is_available, status_message).
        """
        x64dbg_exe = tool_path / "release" / "x64" / "x64dbg.exe"
        x32dbg_exe = tool_path / "release" / "x32" / "x32dbg.exe"

        for candidate in [
            x64dbg_exe,
            x32dbg_exe,
            tool_path / "x64" / "x64dbg.exe",
            tool_path / "x64dbg.exe",
        ]:
            if candidate.exists():
                return True, "x64dbg installed"

        return False, "x64dbg.exe not found"

    def _check_radare2(self, tool_path: Path) -> tuple[bool, str]:  # noqa: PLR6301
        """Check radare2 installation.

        Args:
            tool_path: Path to radare2 installation.

        Returns:
            Tuple of (is_available, status_message).
        """
        for candidate in [
            tool_path / "bin" / "radare2.exe",
            tool_path / "radare2.exe",
            tool_path / "bin" / "r2.exe",
        ]:
            if candidate.exists():
                return True, "radare2 installed"

        try:
            result = subprocess.run(
                ["r2", "-v"],
                check=False, capture_output=True,
                timeout=5,
            )
            if result.returncode == 0:
                return True, "radare2 available in PATH"
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        return False, "radare2 executable not found"


class ToolConfigDialog(QDialog):
    """Dialog for configuring reverse engineering tools.

    Allows users to:
    - Configure tool installation paths
    - Enable/disable specific tools
    - Set startup timeouts
    - Install missing tools
    - Test tool connections

    Attributes:
        tool_updated: Signal emitted when a tool config changes.
    """

    tool_updated: pyqtSignal = pyqtSignal(str)

    def __init__(
        self,
        tool_registry: ToolRegistry | None = None,
        tools_directory: Path | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the tool configuration dialog.

        Args:
            tool_registry: Registry containing tool bridge instances.
            tools_directory: Directory for tool installations.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._registry = tool_registry
        self._tools_directory = tools_directory or Path("D:/Intellicrack/tools")
        self._tool_widgets: dict[str, ToolSettingsWidget] = {}
        self._current_tool: str | None = None
        self._config_path = Path.home() / ".intellicrack" / "tools.json"

        self._setup_ui()
        self._load_tools()

        self.setWindowTitle("Tool Settings")
        self.resize(750, 550)

    def _setup_ui(self) -> None:
        """Set up the dialog UI layout."""
        layout = QVBoxLayout(self)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        self._tool_list = QListWidget()
        self._tool_list.setMaximumWidth(180)
        self._tool_list.currentRowChanged.connect(self._on_tool_selected)

        self._settings_stack = QStackedWidget()

        splitter.addWidget(self._tool_list)
        splitter.addWidget(self._settings_stack)
        splitter.setSizes([180, 570])

        layout.addWidget(splitter, stretch=1)

        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel
            | QDialogButtonBox.StandardButton.Apply
        )
        button_box.accepted.connect(self._on_accept)
        button_box.rejected.connect(self.reject)

        apply_button = button_box.button(QDialogButtonBox.StandardButton.Apply)
        if apply_button:
            apply_button.clicked.connect(self._on_apply)

        layout.addWidget(button_box)

    def _load_tools(self) -> None:
        """Load tool configurations into the list."""
        tools = [
            ("Ghidra", "ghidra", "Static analysis and decompilation"),
            ("x64dbg", "x64dbg", "Windows debugger"),
            ("Frida", "frida", "Dynamic instrumentation"),
            ("radare2", "radare2", "Reverse engineering framework"),
            ("Process Control", "process", "Windows process manipulation"),
            ("Binary Operations", "binary", "Binary file analysis"),
        ]

        for display_name, tool_id, description in tools:
            item = QListWidgetItem(display_name)
            item.setData(Qt.ItemDataRole.UserRole, tool_id)
            item.setToolTip(description)
            self._tool_list.addItem(item)

            widget = ToolSettingsWidget(
                tool_id,
                display_name,
                description,
                self._tools_directory,
                self._registry,
                self._config_path,
            )
            self._settings_stack.addWidget(widget)
            self._tool_widgets[tool_id] = widget

        if self._tool_list.count() > 0:
            self._tool_list.setCurrentRow(0)

    def _on_tool_selected(self, index: int) -> None:
        """Handle tool selection change.

        Args:
            index: The selected tool index.
        """
        if index >= 0:
            item = self._tool_list.item(index)
            if item:
                tool_id = item.data(Qt.ItemDataRole.UserRole)
                self._current_tool = tool_id
                self._settings_stack.setCurrentIndex(index)

    def _on_accept(self) -> None:
        """Handle dialog acceptance."""
        self._save_all_settings()
        self.accept()

    def _on_apply(self) -> None:
        """Handle apply button click."""
        self._save_all_settings()

    def _save_all_settings(self) -> None:
        """Save settings for all tools."""
        for tool_id, widget in self._tool_widgets.items():
            widget.save_settings()
            self.tool_updated.emit(tool_id)

    def get_settings(self) -> dict[str, dict[str, Any]]:
        """Get all tool settings.

        Returns:
            Dictionary mapping tool IDs to their settings.
        """
        settings: dict[str, dict[str, Any]] = {}
        for tool_id, widget in self._tool_widgets.items():
            settings[tool_id] = widget.get_settings()
        return settings


class ToolSettingsWidget(QFrame):
    """Widget for configuring a single tool.

    Displays path configuration, enable/disable toggle, and
    installation options for a specific tool.

    Attributes:
        status_changed: Signal emitted when tool status changes.
    """

    status_changed: pyqtSignal = pyqtSignal(str, bool)

    def __init__(
        self,
        tool_id: str,
        display_name: str,
        description: str,
        tools_directory: Path,
        registry: ToolRegistry | None = None,
        config_path: Path | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the tool settings widget.

        Args:
            tool_id: The tool identifier.
            display_name: Human-readable tool name.
            description: Tool description.
            tools_directory: Base directory for tool installations.
            registry: Tool registry for status checking.
            config_path: Path to configuration file.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._tool_id = tool_id
        self._display_name = display_name
        self._description = description
        self._tools_directory = tools_directory
        self._registry = registry
        self._config_path = config_path or Path.home() / ".intellicrack" / "tools.json"
        self._install_worker: ToolInstallWorker | None = None
        self._status_worker: ToolStatusCheckWorker | None = None

        self._setup_ui()
        self._load_settings()

    def _setup_ui(self) -> None:
        """Set up the widget UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)

        title = QLabel(f"<h3>{self._display_name}</h3>")
        layout.addWidget(title)

        desc_label = QLabel(self._description)
        desc_label.setStyleSheet("color: #888;")
        desc_label.setWordWrap(True)
        layout.addWidget(desc_label)

        status_group = QGroupBox("Status")
        status_layout = QFormLayout()

        self._enabled_checkbox = QCheckBox("Enable this tool")
        self._enabled_checkbox.setChecked(True)
        status_layout.addRow(self._enabled_checkbox)

        self._status_label = QLabel("Unknown")
        self._status_label.setStyleSheet("color: #888;")
        status_layout.addRow("Status:", self._status_label)

        self._check_status_btn = QPushButton("Check Status")
        self._check_status_btn.clicked.connect(self._check_status)
        status_layout.addRow(self._check_status_btn)

        status_group.setLayout(status_layout)
        layout.addWidget(status_group)

        path_group = QGroupBox("Installation")
        path_layout = QFormLayout()

        path_row = QHBoxLayout()
        self._path_input = QLineEdit()
        self._path_input.setMinimumWidth(300)
        path_row.addWidget(self._path_input)

        self._browse_btn = QPushButton("Browse...")
        self._browse_btn.clicked.connect(self._browse_path)
        path_row.addWidget(self._browse_btn)

        path_layout.addRow("Installation Path:", path_row)

        self._auto_install_checkbox = QCheckBox("Auto-install if missing")
        self._auto_install_checkbox.setChecked(True)
        path_layout.addRow(self._auto_install_checkbox)

        install_row = QHBoxLayout()
        self._install_btn = QPushButton("Install Now")
        self._install_btn.clicked.connect(self._install_tool)
        install_row.addWidget(self._install_btn)

        self._install_progress = QProgressBar()
        self._install_progress.setVisible(False)
        self._install_progress.setMaximumWidth(200)
        install_row.addWidget(self._install_progress)
        install_row.addStretch()

        path_layout.addRow(install_row)

        path_group.setLayout(path_layout)
        layout.addWidget(path_group)

        options_group = QGroupBox("Options")
        options_layout = QFormLayout()

        self._timeout_spin = QSpinBox()
        self._timeout_spin.setRange(5, 300)
        self._timeout_spin.setValue(60)
        self._timeout_spin.setSuffix(" seconds")
        options_layout.addRow("Startup Timeout:", self._timeout_spin)

        options_group.setLayout(options_layout)
        layout.addWidget(options_group)

        layout.addStretch()

    def _load_settings(self) -> None:
        """Load settings from config file."""
        saved_settings = self._load_from_config()

        default_paths: dict[str, str] = {
            "ghidra": str(self._tools_directory / "ghidra"),
            "x64dbg": str(self._tools_directory / "x64dbg"),
            "radare2": str(self._tools_directory / "radare2"),
            "frida": "",
            "process": "",
            "binary": "",
        }

        path = saved_settings.get("path", default_paths.get(self._tool_id, ""))
        self._path_input.setText(path)

        self._enabled_checkbox.setChecked(saved_settings.get("enabled", True))
        self._auto_install_checkbox.setChecked(saved_settings.get("auto_install", True))
        self._timeout_spin.setValue(saved_settings.get("startup_timeout_seconds", 60))

        if self._tool_id in {"frida", "process", "binary"}:
            self._path_input.setEnabled(False)
            self._browse_btn.setEnabled(False)
            self._install_btn.setEnabled(False)
            self._auto_install_checkbox.setEnabled(False)
            self._path_input.setToolTip("This tool does not require a path")

    def _load_from_config(self) -> dict[str, Any]:
        """Load settings from the config file.

        Returns:
            Dictionary of saved settings for this tool.
        """
        if not self._config_path.exists():
            return {}

        try:
            with open(self._config_path, encoding="utf-8") as f:
                all_settings: dict[str, Any] = json.load(f)
                result: dict[str, Any] = all_settings.get(self._tool_id, {})
                return result
        except (json.JSONDecodeError, OSError):
            return {}

    def _browse_path(self) -> None:
        """Open file browser for tool path."""
        path = QFileDialog.getExistingDirectory(
            self,
            f"Select {self._display_name} Installation",
            str(self._tools_directory),
        )
        if path:
            self._path_input.setText(path)

    def _check_status(self) -> None:
        """Check the tool installation status."""
        self._status_label.setText("Checking...")
        self._status_label.setStyleSheet("color: #888;")
        self._check_status_btn.setEnabled(False)

        self._status_worker = ToolStatusCheckWorker(
            self._tool_id,
            self._path_input.text().strip(),
            self,
        )
        self._status_worker.finished.connect(self._on_status_checked)
        self._status_worker.start()

    def _on_status_checked(
        self, tool_id: str, is_available: bool, message: str
    ) -> None:
        """Handle status check completion.

        Args:
            tool_id: The tool that was checked.
            is_available: Whether the tool is available.
            message: Status message.
        """
        self._check_status_btn.setEnabled(True)

        if is_available:
            self._status_label.setText(message)
            self._status_label.setStyleSheet("color: #4CAF50;")
        else:
            self._status_label.setText(message)
            self._status_label.setStyleSheet("color: #F44336;")

        self.status_changed.emit(tool_id, is_available)

    def _install_tool(self) -> None:
        """Install the tool."""
        if self._tool_id in {"frida", "process", "binary"}:
            QMessageBox.information(
                self,
                "Installation",
                f"{self._display_name} is built-in and does not require installation.",
            )
            return

        if self._tool_id not in ToolInstallWorker.DOWNLOAD_URLS:
            QMessageBox.warning(
                self,
                "Installation",
                f"Automatic installation not available for {self._display_name}.\n\n"
                f"Please download and install manually.",
            )
            return

        install_path = Path(self._path_input.text().strip())
        if not install_path:
            install_path = self._tools_directory / self._tool_id
            self._path_input.setText(str(install_path))

        reply = QMessageBox.question(
            self,
            "Install Tool",
            f"Download and install {self._display_name}?\n\n"
            f"Installation path:\n{install_path}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )

        if reply == QMessageBox.StandardButton.Yes:
            self._install_progress.setVisible(True)
            self._install_progress.setValue(0)
            self._install_btn.setEnabled(False)

            self._install_worker = ToolInstallWorker(
                self._tool_id, install_path, self
            )
            self._install_worker.progress.connect(self._install_progress.setValue)
            self._install_worker.finished.connect(self._on_install_finished)
            self._install_worker.start()

    def _on_install_finished(self, success: bool, message: str) -> None:
        """Handle installation completion.

        Args:
            success: Whether installation was successful.
            message: Status message.
        """
        self._install_btn.setEnabled(True)
        self._install_progress.setVisible(False)

        if success:
            QMessageBox.information(self, "Installation Complete", message)
            self._check_status()
        else:
            QMessageBox.warning(self, "Installation Failed", message)

    def get_settings(self) -> dict[str, Any]:
        """Get current settings as a dictionary.

        Returns:
            Dictionary of current settings.
        """
        return {
            "enabled": self._enabled_checkbox.isChecked(),
            "path": self._path_input.text().strip(),
            "auto_install": self._auto_install_checkbox.isChecked(),
            "startup_timeout_seconds": self._timeout_spin.value(),
        }

    def save_settings(self) -> None:
        """Save current settings to config file."""
        self._config_path.parent.mkdir(parents=True, exist_ok=True)

        all_settings: dict[str, dict[str, Any]] = {}
        if self._config_path.exists():
            try:
                with open(self._config_path, encoding="utf-8") as f:
                    all_settings = json.load(f)
            except (json.JSONDecodeError, OSError):
                all_settings = {}

        all_settings[self._tool_id] = self.get_settings()

        try:
            with open(self._config_path, "w", encoding="utf-8") as f:
                json.dump(all_settings, f, indent=2)
        except OSError as e:
            QMessageBox.warning(
                self,
                "Save Error",
                f"Failed to save settings: {e}",
            )


class ToolStatusDialog(QDialog):
    """Dialog showing status of all configured tools.

    Displays a summary of which tools are installed, connected,
    and ready to use.
    """

    def __init__(
        self,
        tool_registry: ToolRegistry | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the tool status dialog.

        Args:
            tool_registry: Registry containing tool bridge instances.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._registry = tool_registry
        self._config_path = Path.home() / ".intellicrack" / "tools.json"
        self._status_workers: list[ToolStatusCheckWorker] = []
        self._tool_statuses: dict[str, tuple[bool, str]] = {}

        self._setup_ui()
        self._refresh_status()

        self.setWindowTitle("Tool Status")
        self.resize(450, 350)

    def _setup_ui(self) -> None:
        """Set up the dialog UI."""
        layout = QVBoxLayout(self)

        self._status_list = QListWidget()
        layout.addWidget(self._status_list)

        button_layout = QHBoxLayout()

        self._refresh_btn = QPushButton("Refresh")
        self._refresh_btn.clicked.connect(self._refresh_status)
        button_layout.addWidget(self._refresh_btn)

        button_layout.addStretch()

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        button_layout.addWidget(close_btn)

        layout.addLayout(button_layout)

    def _load_settings(self) -> dict[str, dict[str, Any]]:
        """Load all tool settings from config.

        Returns:
            Dictionary mapping tool IDs to their settings.
        """
        if not self._config_path.exists():
            return {}

        try:
            with open(self._config_path, encoding="utf-8") as f:
                result: dict[str, dict[str, Any]] = json.load(f)
                return result
        except (json.JSONDecodeError, OSError):
            return {}

    def _refresh_status(self) -> None:
        """Refresh tool status display."""
        self._status_list.clear()
        self._tool_statuses.clear()
        self._refresh_btn.setEnabled(False)

        tools = [
            ("Ghidra", "ghidra", "Static analysis"),
            ("x64dbg", "x64dbg", "Debugging"),
            ("Frida", "frida", "Dynamic instrumentation"),
            ("radare2", "radare2", "Analysis framework"),
            ("Process Control", "process", "Process manipulation"),
            ("Binary Operations", "binary", "File analysis"),
        ]

        saved_settings = self._load_settings()

        for display_name, tool_id, _category in tools:
            item = QListWidgetItem(f"... {display_name} - Checking...")
            self._status_list.addItem(item)

            tool_settings = saved_settings.get(tool_id, {})
            tool_path = tool_settings.get("path", "")

            worker = ToolStatusCheckWorker(tool_id, tool_path, self)
            worker.finished.connect(self._on_tool_status_received)
            self._status_workers.append(worker)
            worker.start()

    def _on_tool_status_received(
        self, tool_id: str, is_available: bool, message: str
    ) -> None:
        """Handle status check completion for a single tool.

        Args:
            tool_id: The tool that was checked.
            is_available: Whether the tool is available.
            message: Status message.
        """
        self._tool_statuses[tool_id] = (is_available, message)

        tool_names = {
            "ghidra": "Ghidra",
            "x64dbg": "x64dbg",
            "frida": "Frida",
            "radare2": "radare2",
            "process": "Process Control",
            "binary": "Binary Operations",
        }

        display_name = tool_names.get(tool_id, tool_id)
        status_icon = "\u2713" if is_available else "\u2717"
        status_text = message

        for i in range(self._status_list.count()):
            item = self._status_list.item(i)
            if item and display_name in item.text():
                item.setText(f"{status_icon}  {display_name} - {status_text}")
                break

        if len(self._tool_statuses) == EXPECTED_TOOL_COUNT:
            self._refresh_btn.setEnabled(True)
            self._status_workers.clear()
