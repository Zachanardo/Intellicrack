"""Adobe Injector Integration Module.

This module provides native integration of the AutoIt3-based Adobe Injector tool
into Intellicrack without converting it to Python, using Win32 API
window embedding and process control.

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3.0
"""

import ctypes
import ctypes.wintypes
import json
import subprocess
import time
from pathlib import Path
from typing import Any

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
        """Find window by class name and window title."""
        return cls.user32.FindWindowW(class_name, window_name)

    @classmethod
    def set_parent(cls, child_hwnd: int, parent_hwnd: int) -> int:
        """Set parent window for embedding."""
        return cls.user32.SetParent(child_hwnd, parent_hwnd)

    @classmethod
    def set_window_long(cls, hwnd: int, index: int, new_long: int) -> int:
        """Modify window style."""
        return cls.user32.SetWindowLongW(hwnd, index, new_long)

    @classmethod
    def get_window_long(cls, hwnd: int, index: int) -> int:
        """Get window style."""
        return cls.user32.GetWindowLongW(hwnd, index)

    @classmethod
    def move_window(cls, hwnd: int, x: int, y: int, width: int, height: int, repaint: bool = True) -> bool:
        """Move and resize window."""
        return cls.user32.MoveWindow(hwnd, x, y, width, height, repaint)

    @classmethod
    def show_window(cls, hwnd: int, cmd_show: int) -> bool:
        """Show or hide window."""
        return cls.user32.ShowWindow(hwnd, cmd_show)

    @classmethod
    def set_window_pos(cls, hwnd: int, insert_after: int, x: int, y: int, cx: int, cy: int, flags: int) -> bool:
        """Set window position and size."""
        return cls.user32.SetWindowPos(hwnd, insert_after, x, y, cx, cy, flags)

    @classmethod
    def send_message(cls, hwnd: int, msg: int, wparam: int, lparam: int) -> int:
        """Send Windows message to window."""
        return cls.user32.SendMessageW(hwnd, msg, wparam, lparam)


class AdobeInjectorProcess:
    """Manages the Adobe Injector AutoIt3 process."""

    def __init__(self, adobe_injector_path: Path) -> None:
        """Initialize with path to Adobe Injector executable."""
        self.adobe_injector_path = adobe_injector_path
        self.process: subprocess.Popen | None = None
        self.hwnd: int | None = None
        self.embedded = False
        self.config_path = adobe_injector_path.parent / "config.ini"
        self.monitoring_thread = None
        self.output_callback = None

    def start(self, silent: bool = False) -> bool:
        """Start Adobe Injector process."""
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

        except Exception as e:
            print(f"Failed to start Adobe Injector: {e}")
            return False

    def _find_adobe_injector_window(self, max_attempts: int = 10) -> int | None:
        """Find Adobe Injector window by title."""
        window_titles = ["Adobe Injector v", "GenP v"]  # Check both for compatibility

        for _attempt in range(max_attempts):
            # Enumerate windows to find Adobe Injector
            windows: list[int] = []

            def enum_callback(hwnd: int, lParam: int, windows: list[int] = windows) -> bool:
                length = Win32API.user32.GetWindowTextLengthW(hwnd)
                if length > 0:
                    buffer = ctypes.create_unicode_buffer(length + 1)
                    Win32API.user32.GetWindowTextW(hwnd, buffer, length + 1)
                    for title in window_titles:
                        if title in buffer.value:
                            windows.append(hwnd)
                            break
                return True

            WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_int)
            Win32API.user32.EnumWindows(WNDENUMPROC(enum_callback), 0)

            if windows:
                return windows[0]

            time.sleep(0.5)

        return None

    def embed_in_widget(self, parent_widget: QWidget) -> bool:
        """Embed Adobe Injector window inside a Qt widget."""
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

        except Exception as e:
            print(f"Failed to embed Adobe Injector window: {e}")
            return False

    def resize_to_parent(self, width: int, height: int) -> None:
        """Resize embedded window to match parent."""
        if self.hwnd and self.embedded:
            Win32API.move_window(self.hwnd, 0, 0, width, height)

    def send_command(self, command: str) -> None:
        """Send command to Adobe Injector process via IPC."""
        if self.process and self.process.stdin:
            self.process.stdin.write(f"{command}\n".encode())
            self.process.stdin.flush()

    def terminate(self) -> None:
        """Terminate Adobe Injector process."""
        if self.process:
            self.process.terminate()
            self.process.wait(timeout=5)
            self.process = None
            self.hwnd = None


class AdobeInjectorWidget(QWidget if PYQT6_AVAILABLE else object):
    """Qt widget that hosts the embedded Adobe Injector."""

    if PYQT6_AVAILABLE:
        status_updated = pyqtSignal(str)
        patch_completed = pyqtSignal(bool, str)
    else:
        status_updated = None
        patch_completed = None

    def __init__(self, parent: Any | None = None) -> None:
        """Initialize the AdobeInjectorWidget.

        Args:
            parent: Parent widget for this widget. Defaults to None.

        """
        if not PYQT6_AVAILABLE:
            raise ImportError("PyQt6 not available - AdobeInjectorWidget requires PyQt6")

        super().__init__(parent)
        self.adobe_injector_process = None
        self.setup_ui()
        self.init_adobe_injector()

    def setup_ui(self) -> None:
        """Set up the UI layout."""
        layout = QVBoxLayout(self)

        # Control panel
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

        # Embedding container
        self.embed_container = QWidget()
        self.embed_container.setMinimumHeight(600)
        self.embed_container.setStyleSheet("background-color: #1e1e1e; border: 2px solid #444;")

        # Status label for when not embedded
        self.status_label = QLabel("Adobe Injector not launched")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet("color: #888; font-size: 14px;")

        container_layout = QVBoxLayout(self.embed_container)
        container_layout.addWidget(self.status_label)

        layout.addWidget(self.embed_container)

    def init_adobe_injector(self) -> None:
        """Initialize Adobe Injector integration."""
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
        """Launch and embed Adobe Injector."""
        if not self.adobe_injector_path:
            self.status_updated.emit("Adobe Injector executable not found")
            return

        try:
            # Create process manager
            self.adobe_injector_process = AdobeInjectorProcess(self.adobe_injector_path)

            # Start Adobe Injector
            if self.adobe_injector_process.start():
                self.status_label.hide()

                # Embed in container
                if self.adobe_injector_process.embed_in_widget(self.embed_container):
                    self.status_updated.emit("Adobe Injector embedded successfully")
                    self.launch_btn.setEnabled(False)
                    self.terminate_btn.setEnabled(True)
                else:
                    self.status_updated.emit("Failed to embed Adobe Injector window")
                    self.adobe_injector_process.terminate()
            else:
                self.status_updated.emit("Failed to start Adobe Injector")

        except Exception as e:
            self.status_updated.emit(f"Error: {e}")

    def terminate_injector(self) -> None:
        """Terminate embedded Adobe Injector."""
        if self.adobe_injector_process:
            self.adobe_injector_process.terminate()
            self.adobe_injector_process = None

            self.status_label.show()
            self.status_label.setText("Adobe Injector terminated")

            self.launch_btn.setEnabled(True)
            self.terminate_btn.setEnabled(False)

            self.status_updated.emit("Adobe Injector terminated")

    def apply_rebranding(self) -> None:
        """Apply rebranding to Adobe Injector resources."""
        if not self.adobe_injector_path:
            return

        # Create rebranding configuration
        rebrand_config = {
            "window_title": "Adobe Injector - Intellicrack Integration",
            "version_string": "Adobe Injector v1.0",
            "copyright": "Intellicrack 2025",
            "remove_community_refs": True,
        }

        config_path = self.adobe_injector_path.parent / "rebrand_config.json"
        with open(config_path, "w") as f:
            json.dump(rebrand_config, f, indent=2)

        self.status_updated.emit("Rebranding configuration created")

    def resizeEvent(self, event: QResizeEvent) -> None:
        """Handle widget resize to adjust embedded window."""
        super().resizeEvent(event)
        if self.adobe_injector_process and self.adobe_injector_process.embedded:
            size = self.embed_container.size()
            self.adobe_injector_process.resize_to_parent(size.width(), size.height())

    def closeEvent(self, event: QCloseEvent) -> None:
        """Clean up on widget close."""
        if self.adobe_injector_process:
            self.adobe_injector_process.terminate()
        super().closeEvent(event)


class AutoIt3COMInterface:
    """Alternative integration using AutoIt3 COM interface."""

    def __init__(self) -> None:
        """Initialize COM interface to AutoIt3."""
        try:
            import win32com.client

            self.autoit = win32com.client.Dispatch("AutoItX3.Control")
            self.available = True
        except (AttributeError, OSError):
            self.available = False

    def control_adobe_injector(self, action: str, params: dict = None):
        """Control Adobe Injector via AutoIt3 COM interface."""
        if not self.available:
            return False

        if action == "click_button":
            # Click a button in Adobe Injector window
            self.autoit.ControlClick("Adobe Injector", "", params.get("control_id", ""))
        elif action == "set_text":
            # Set text in a control
            self.autoit.ControlSetText("Adobe Injector", "", params.get("control_id", ""), params.get("text", ""))
        elif action == "get_text":
            # Get text from a control
            return self.autoit.ControlGetText("Adobe Injector", "", params.get("control_id", ""))

        return True


class IPCController:
    """Inter-Process Communication controller for Adobe Injector."""

    def __init__(self, adobe_injector_process: AdobeInjectorProcess) -> None:
        """Initialize IPC controller."""
        self.process = adobe_injector_process
        self.pipe_name = r"\\.\pipe\IntellicrackAdobeInjector"
        self.pipe = None

    def create_named_pipe(self) -> bool | None:
        """Create named pipe for IPC."""
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

    def send_command(self, command: dict) -> None:
        """Send command via named pipe."""
        if self.pipe:
            import win32file

            message = json.dumps(command).encode()
            win32file.WriteFile(self.pipe, message)

    def receive_response(self) -> dict:
        """Receive response from named pipe."""
        if self.pipe:
            import win32file

            result, data = win32file.ReadFile(self.pipe, 65536)
            if result == 0:
                return json.loads(data.decode())
        return {}


# Export main widget
__all__ = ["AdobeInjectorWidget"]
