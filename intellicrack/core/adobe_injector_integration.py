"""Adobe Injector Integration Module.

This module provides native integration of the AutoIt3-based Adobe Injector tool
into Intellicrack without converting it to Python, using Win32 API
window embedding and process control.

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3.0
"""

from __future__ import annotations

import ctypes
import json
import logging
import subprocess
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from intellicrack.handlers.pyqt6_handler import (
    PYQT6_AVAILABLE,
    QCloseEvent,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QResizeEvent,
    Qt,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)


logger = logging.getLogger(__name__)


# Win32 API constants
GWL_STYLE = -16
WS_CHILD = 0x40000000
WS_VISIBLE = 0x10000000
WS_BORDER = 0x00800000
SW_HIDE = 0
SW_SHOW = 5
HWND_TOP = 0
SWP_NOSIZE = 0x0001
SWP_NOZORDER = 0x0004


class Win32API:
    """Win32 API wrapper for window manipulation."""

    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32

    @classmethod
    def find_window(cls, class_name: str, window_name: str) -> int:
        """Find a window by its class name and window title.

        Args:
            class_name: The window class name to search for.
            window_name: The window title to search for.

        Returns:
            int: The window handle (HWND) if found, zero if not found.

        """
        result: int = cls.user32.FindWindowW(class_name, window_name)
        return result

    @classmethod
    def set_parent(cls, child_hwnd: int, parent_hwnd: int) -> int:
        """Set parent window for child window embedding.

        Args:
            child_hwnd: The window handle of the child window.
            parent_hwnd: The window handle of the parent window.

        Returns:
            int: The previous parent window handle.

        """
        result: int = cls.user32.SetParent(child_hwnd, parent_hwnd)
        return result

    @classmethod
    def set_window_long(cls, hwnd: int, index: int, new_long: int) -> int:
        """Modify a window's extended style or other properties.

        Args:
            hwnd: The window handle to modify.
            index: The zero-based offset to the value to modify (e.g., GWL_STYLE).
            new_long: The new value for the specified property.

        Returns:
            int: The previous value at the specified offset.

        """
        result: int = cls.user32.SetWindowLongW(hwnd, index, new_long)
        return result

    @classmethod
    def get_window_long(cls, hwnd: int, index: int) -> int:
        """Retrieve a window's extended style or other properties.

        Args:
            hwnd: The window handle to query.
            index: The zero-based offset to the value to retrieve (e.g., GWL_STYLE).

        Returns:
            int: The value at the specified offset.

        """
        result: int = cls.user32.GetWindowLongW(hwnd, index)
        return result

    @classmethod
    def move_window(cls, hwnd: int, x: int, y: int, width: int, height: int, repaint: bool = True) -> bool:
        """Move and resize a window to the specified position and dimensions.

        Args:
            hwnd: The window handle to move and resize.
            x: The new x-coordinate of the window's top-left corner.
            y: The new y-coordinate of the window's top-left corner.
            width: The new width of the window in pixels.
            height: The new height of the window in pixels.
            repaint: Whether to repaint the window. Defaults to True.

        Returns:
            bool: True if successful, False otherwise.

        """
        result: bool = bool(cls.user32.MoveWindow(hwnd, x, y, width, height, repaint))
        return result

    @classmethod
    def show_window(cls, hwnd: int, cmd_show: int) -> bool:
        """Show or hide a window.

        Args:
            hwnd: The window handle to show or hide.
            cmd_show: The command specifying how to show the window (e.g., SW_SHOW, SW_HIDE).

        Returns:
            bool: True if the window was previously visible, False otherwise.

        """
        result: bool = bool(cls.user32.ShowWindow(hwnd, cmd_show))
        return result

    @classmethod
    def set_window_pos(cls, hwnd: int, insert_after: int, x: int, y: int, cx: int, cy: int, flags: int) -> bool:
        """Set window position, size, and z-order.

        Args:
            hwnd: The window handle to position.
            insert_after: The window handle to position ahead of (or HWND_TOP).
            x: The new x-coordinate of the window's top-left corner.
            y: The new y-coordinate of the window's top-left corner.
            cx: The new width of the window in pixels.
            cy: The new height of the window in pixels.
            flags: Positioning and sizing flags (e.g., SWP_NOSIZE, SWP_NOZORDER).

        Returns:
            bool: True if successful, False otherwise.

        """
        result: bool = bool(cls.user32.SetWindowPos(hwnd, insert_after, x, y, cx, cy, flags))
        return result

    @classmethod
    def send_message(cls, hwnd: int, msg: int, wparam: int, lparam: int) -> int:
        """Send a Windows message to a window.

        Args:
            hwnd: The window handle to send the message to.
            msg: The message to send.
            wparam: The first message parameter.
            lparam: The second message parameter.

        Returns:
            int: The return value from the window's message handler.

        """
        result: int = cls.user32.SendMessageW(hwnd, msg, wparam, lparam)
        return result


class AdobeInjectorProcess:
    """Manages the Adobe Injector AutoIt3 process."""

    def __init__(self, adobe_injector_path: Path) -> None:
        """Initialize the Adobe Injector process manager.

        Args:
            adobe_injector_path: Path to the Adobe Injector executable file.

        """
        self.adobe_injector_path = adobe_injector_path
        self.process: subprocess.Popen[bytes] | None = None
        self.hwnd: int | None = None
        self.embedded = False
        self.config_path = adobe_injector_path.parent / "config.ini"
        self.monitoring_thread: Any = None
        self.output_callback: Any = None

    def start(self, silent: bool = False) -> bool:
        """Start the Adobe Injector process.

        Args:
            silent: If True, start the process in silent mode. Defaults to False.

        Returns:
            bool: True if the process started and window was found, False otherwise.

        Raises:
            FileNotFoundError: If the Adobe Injector executable does not exist.
            ValueError: If the command construction results in unsafe arguments.

        """
        if not self.adobe_injector_path.exists():
            raise FileNotFoundError(f"Adobe Injector executable not found: {self.adobe_injector_path}")

        # Prepare command line arguments
        cmd = [str(self.adobe_injector_path)]
        if silent:
            cmd.append("/silent")

        # Start process
        try:
            # Validate that cmd contains only safe, expected commands
            if not isinstance(cmd, list) or not all(isinstance(arg, str) for arg in cmd):
                raise ValueError(f"Unsafe command: {cmd}")
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                cwd=str(self.adobe_injector_path.parent),
                shell=False,
            )

            # Wait for window to appear
            time.sleep(1.0)

            # Find Adobe Injector window
            self.hwnd = self._find_adobe_injector_window()

            return self.hwnd is not None

        except Exception:
            logger.exception("Failed to start Adobe Injector")
            return False

    def _find_adobe_injector_window(self, max_attempts: int = 10) -> int | None:
        """Find the Adobe Injector window by its title.

        Args:
            max_attempts: Maximum number of attempts to find the window. Defaults to 10.

        Returns:
            int | None: The window handle (HWND) if found, None otherwise.

        """
        window_titles = ["Adobe Injector v", "GenP v"]  # Check both for compatibility

        for _attempt in range(max_attempts):
            # Enumerate windows to find Adobe Injector
            windows: list[int] = []

            def enum_callback(hwnd: int, _l_param: int, windows: list[int] = windows) -> bool:
                length = Win32API.user32.GetWindowTextLengthW(hwnd)
                if length > 0:
                    buffer = ctypes.create_unicode_buffer(length + 1)
                    Win32API.user32.GetWindowTextW(hwnd, buffer, length + 1)
                    for title in window_titles:
                        if title in buffer.value:
                            windows.append(hwnd)
                            break
                return True

            wnd_enum_proc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_int)
            Win32API.user32.EnumWindows(wnd_enum_proc(enum_callback), 0)

            if windows:
                return windows[0]

            time.sleep(0.5)

        return None

    def embed_in_widget(self, parent_widget: QWidget) -> bool:
        """Embed the Adobe Injector window inside a Qt widget.

        Args:
            parent_widget: The Qt widget to embed the Adobe Injector window into.

        Returns:
            bool: True if embedding was successful, False otherwise.

        """
        if not self.hwnd:
            return False

        try:
            # Get parent widget's window handle
            parent_hwnd = int(parent_widget.winId())

            # Change Adobe Injector window style to child window
            style = Win32API.get_window_long(self.hwnd, GWL_STYLE)
            style = (style & ~0x00CF0000) | WS_CHILD  # Remove caption and borders
            Win32API.set_window_long(self.hwnd, GWL_STYLE, style)

            # Set parent
            Win32API.set_parent(self.hwnd, parent_hwnd)

            # Move to fill parent widget
            geometry = parent_widget.geometry()
            Win32API.move_window(self.hwnd, 0, 0, geometry.width(), geometry.height())

            # Show window
            Win32API.show_window(self.hwnd, SW_SHOW)

            self.embedded = True
            return True

        except Exception:
            logger.exception("Failed to embed Adobe Injector window")
            return False

    def resize_to_parent(self, width: int, height: int) -> None:
        """Resize the embedded window to match parent dimensions.

        Args:
            width: The new width in pixels.
            height: The new height in pixels.

        """
        if self.hwnd and self.embedded:
            Win32API.move_window(self.hwnd, 0, 0, width, height)

    def send_command(self, command: str) -> None:
        """Send a command to the Adobe Injector process via IPC.

        Args:
            command: The command string to send to the process.

        """
        if self.process and self.process.stdin:
            self.process.stdin.write(f"{command}\n".encode())
            self.process.stdin.flush()

    def terminate(self) -> None:
        """Terminate Adobe Injector process.

        """
        if self.process:
            self.process.terminate()
            self.process.wait(timeout=5)
            self.process = None
            self.hwnd = None


if TYPE_CHECKING:
    BaseWidget = QWidget
else:
    # Determine base class based on PyQt6 availability
    BaseWidget = QWidget if PYQT6_AVAILABLE else object


class AdobeInjectorWidget(BaseWidget):
    """Qt widget that hosts the embedded Adobe Injector."""

    if PYQT6_AVAILABLE:
        status_updated = pyqtSignal(str)
        patch_completed = pyqtSignal(bool, str)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the AdobeInjectorWidget.

        Args:
            parent: Parent widget for this widget. Defaults to None.

        Raises:
            ImportError: If PyQt6 is not available.

        """
        if not PYQT6_AVAILABLE:
            raise ImportError("PyQt6 not available - AdobeInjectorWidget requires PyQt6")

        super().__init__(parent)
        self.adobe_injector_process: AdobeInjectorProcess | None = None
        self.adobe_injector_path: Path | None = None
        self.embed_container: QWidget
        self.status_label: QLabel
        self.launch_btn: QPushButton
        self.terminate_btn: QPushButton
        self.rebrand_btn: QPushButton
        self.setup_ui()
        self.init_adobe_injector()

    def setup_ui(self) -> None:
        """Set up the UI layout.

        """
        layout = QVBoxLayout(self)

        control_group = QGroupBox("Adobe Injector Control")
        control_layout = QHBoxLayout(control_group)

        self.launch_btn = QPushButton("Launch Adobe Injector")
        self.launch_btn.clicked.connect(self.launch_injector)
        self.launch_btn.setStyleSheet("font-weight: bold; color: green;")

        self.terminate_btn = QPushButton("Terminate")
        self.terminate_btn.clicked.connect(self.terminate_injector)
        self.terminate_btn.setEnabled(False)
        self.terminate_btn.setStyleSheet("font-weight: bold; color: red;")

        self.rebrand_btn = QPushButton("Apply Rebranding")
        self.rebrand_btn.clicked.connect(self.apply_rebranding)
        self.rebrand_btn.setToolTip("Modify Adobe Injector resources for custom branding")

        control_layout.addWidget(self.launch_btn)
        control_layout.addWidget(self.terminate_btn)
        control_layout.addWidget(self.rebrand_btn)
        control_layout.addStretch()

        layout.addWidget(control_group)

        self.embed_container = QWidget()
        self.embed_container.setMinimumHeight(600)
        self.embed_container.setStyleSheet("background-color: #1e1e1e; border: 2px solid #444;")

        self.status_label = QLabel("Adobe Injector not launched")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet("color: #888; font-size: 14px;")

        container_layout = QVBoxLayout(self.embed_container)
        container_layout.addWidget(self.status_label)

        layout.addWidget(self.embed_container)

    def init_adobe_injector(self) -> None:
        """Initialize Adobe Injector integration.

        """
        from intellicrack.utils.path_resolver import get_project_root

        adobe_injector_paths = [
            Path(get_project_root() / "tools/AdobeInjector/AdobeInjector.exe"),
            Path("./tools/AdobeInjector/AdobeInjector.exe"),
        ]

        self.adobe_injector_path = None
        for path in adobe_injector_paths:
            if path.exists():
                self.adobe_injector_path = path
                break

        if self.adobe_injector_path:
            self.status_label.setText(f"Ready to launch: {self.adobe_injector_path.name}")
        else:
            self.status_label.setText("Adobe Injector executable not found")
            self.launch_btn.setEnabled(False)

    def launch_injector(self) -> None:
        """Launch and embed Adobe Injector.

        Returns:
            None

        """
        if not self.adobe_injector_path:
            if hasattr(self, "status_updated"):
                self.status_updated.emit("Adobe Injector executable not found")
            return

        try:
            adobe_process = AdobeInjectorProcess(self.adobe_injector_path)
            self.adobe_injector_process = adobe_process

            if adobe_process.start():
                self.status_label.hide()

                if adobe_process.embed_in_widget(self.embed_container):
                    if hasattr(self, "status_updated"):
                        self.status_updated.emit("Adobe Injector embedded successfully")
                    self.launch_btn.setEnabled(False)
                    self.terminate_btn.setEnabled(True)
                else:
                    if hasattr(self, "status_updated"):
                        self.status_updated.emit("Failed to embed Adobe Injector window")
                    adobe_process.terminate()
            else:
                if hasattr(self, "status_updated"):
                    self.status_updated.emit("Failed to start Adobe Injector")

        except Exception as e:
            logger.exception("Error launching Adobe Injector")
            if hasattr(self, "status_updated"):
                self.status_updated.emit(f"Error: {e}")

    def terminate_injector(self) -> None:
        """Terminate embedded Adobe Injector.

        """
        adobe_process = self.adobe_injector_process
        if adobe_process is not None:
            adobe_process.terminate()
            self.adobe_injector_process = None

            self.status_label.show()
            self.status_label.setText("Adobe Injector terminated")

            self.launch_btn.setEnabled(True)
            self.terminate_btn.setEnabled(False)

            if hasattr(self, "status_updated"):
                self.status_updated.emit("Adobe Injector terminated")

    def apply_rebranding(self) -> None:
        """Apply rebranding to Adobe Injector resources.

        Returns:
            None

        """
        if not self.adobe_injector_path:
            return

        rebrand_config: dict[str, str | bool] = {
            "window_title": "Adobe Injector - Intellicrack Integration",
            "version_string": "Adobe Injector v1.0",
            "copyright": "Intellicrack 2025",
            "remove_community_refs": True,
        }

        config_path = self.adobe_injector_path.parent / "rebrand_config.json"
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(rebrand_config, f, indent=2)
        if hasattr(self, "status_updated"):
            self.status_updated.emit("Rebranding configuration created")

    def resizeEvent(self, event: QResizeEvent | None) -> None:  # noqa: N802
        """Handle widget resize to adjust embedded window.

        Args:
            event: The resize event containing new size information.

        """
        super().resizeEvent(event)
        adobe_process = self.adobe_injector_process
        if adobe_process is not None and adobe_process.embedded:
            size = self.embed_container.size()
            adobe_process.resize_to_parent(size.width(), size.height())

    def closeEvent(self, event: QCloseEvent | None) -> None:  # noqa: N802
        """Clean up the Adobe Injector process on widget close.

        Args:
            event: The close event.

        """
        adobe_process = self.adobe_injector_process
        if adobe_process is not None:
            adobe_process.terminate()
        super().closeEvent(event)


class AutoIt3COMInterface:
    """Alternative integration using AutoIt3 COM interface."""

    def __init__(self) -> None:
        """Initialize COM interface to AutoIt3."""
        self.autoit: Any = None
        self.available = False
        try:
            import win32com.client

            self.autoit = win32com.client.Dispatch("AutoItX3.Control")
            self.available = True
        except (AttributeError, OSError):
            self.available = False

    def control_adobe_injector(self, action: str, params: dict[str, str] | None = None) -> bool | str:
        """Control Adobe Injector via AutoIt3 COM interface.

        Args:
            action: The action to perform ('click_button', 'set_text', or 'get_text').
            params: Dictionary of parameters for the action. Defaults to None.

        Returns:
            True if successful, False if COM interface unavailable, or the text
            value when action is 'get_text'.

        """
        if not self.available or self.autoit is None:
            return False

        if params is None:
            params = {}

        if action == "click_button":
            self.autoit.ControlClick("Adobe Injector", "", params.get("control_id", ""))
            return True
        elif action == "set_text":
            self.autoit.ControlSetText("Adobe Injector", "", params.get("control_id", ""), params.get("text", ""))
            return True
        elif action == "get_text":
            result: str = str(self.autoit.ControlGetText("Adobe Injector", "", params.get("control_id", "")))
            return result

        return True


class IPCController:
    """Inter-Process Communication controller for Adobe Injector."""

    def __init__(self, adobe_injector_process: AdobeInjectorProcess) -> None:
        """Initialize the IPC controller for the Adobe Injector process.

        Args:
            adobe_injector_process: The AdobeInjectorProcess instance to control via IPC.

        """
        self.process = adobe_injector_process
        self.pipe_name = r"\\.\pipe\IntellicrackAdobeInjector"
        self.pipe: Any = None

    def create_named_pipe(self) -> bool:
        """Create a named pipe for IPC communication.

        Returns:
            bool: True if the named pipe was created successfully, False otherwise.

        """
        try:
            import win32pipe

            self.pipe = win32pipe.CreateNamedPipe(
                self.pipe_name,
                win32pipe.PIPE_ACCESS_DUPLEX,
                win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
                1,
                65536,
                65536,
                0,
                None,
            )
            return True
        except (AttributeError, OSError):
            return False

    def send_command(self, command: dict[str, Any]) -> None:
        """Send a command to the Adobe Injector via the named pipe.

        Args:
            command: A dictionary containing the command and its parameters.

        """
        if self.pipe is not None:
            import win32file

            message = json.dumps(command).encode()
            win32file.WriteFile(self.pipe, message)

    def receive_response(self) -> dict[str, Any]:
        """Receive a response from the Adobe Injector via the named pipe.

        Returns:
            The decoded JSON response from the Adobe Injector, or an empty dict
            if no response.

        """
        if self.pipe is not None:
            import win32file

            result, data = win32file.ReadFile(self.pipe, 65536)
            if result == 0:
                decoded_data: dict[str, Any] = json.loads(data.decode())
                return decoded_data
        return {}


# Export main widget
__all__ = ["AdobeInjectorWidget"]
