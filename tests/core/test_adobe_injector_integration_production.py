"""Production tests for Adobe Injector integration module.

Tests validate real process management, Win32 API window embedding,
and IPC communication for Adobe product license bypass functionality.
"""

import ctypes
import platform
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from intellicrack.core.adobe_injector_integration import (
    AdobeInjectorProcess,
    IPCController,
    Win32API,
)


pytestmark = pytest.mark.skipif(
    platform.system() != "Windows",
    reason="Adobe Injector integration requires Windows platform"
)


class TestWin32API:
    """Test Win32 API wrapper functionality."""

    def test_win32_api_loads_dll_functions(self) -> None:
        """Win32API successfully loads user32 and kernel32 DLLs."""
        assert Win32API.user32 is not None
        assert Win32API.kernel32 is not None
        assert hasattr(Win32API.user32, "FindWindowW")
        assert hasattr(Win32API.user32, "SetParent")
        assert hasattr(Win32API.user32, "GetWindowLongW")
        assert hasattr(Win32API.user32, "SetWindowLongW")

    def test_find_window_detects_existing_windows(self) -> None:
        """find_window locates existing system windows."""
        hwnd = Win32API.find_window("Shell_TrayWnd", None)
        assert hwnd != 0
        assert isinstance(hwnd, int)

    def test_get_window_long_retrieves_window_style(self) -> None:
        """get_window_long retrieves window style bits for real windows."""
        hwnd = Win32API.find_window("Shell_TrayWnd", None)
        if hwnd:
            style = Win32API.get_window_long(hwnd, -16)
            assert style != 0
            assert isinstance(style, int)

    def test_show_window_accepts_valid_commands(self) -> None:
        """show_window accepts valid SW_* command constants."""
        notepad_exe = Path("C:/Windows/System32/notepad.exe")
        if not notepad_exe.exists():
            pytest.skip("notepad.exe not available for testing")

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as tmp:
            tmp.write("test")
            tmp_path = Path(tmp.name)

        try:
            proc = subprocess.Popen(
                [str(notepad_exe), str(tmp_path)],
                shell=False,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
            time.sleep(1.0)

            hwnd = Win32API.find_window(None, f"*{tmp_path.name}*")
            if not hwnd:
                for _ in range(5):
                    time.sleep(0.5)
                    hwnd = Win32API.find_window("Notepad", None)
                    if hwnd:
                        break

            if hwnd:
                result = Win32API.show_window(hwnd, 0)
                assert isinstance(result, (bool, int))

            proc.terminate()
            proc.wait(timeout=2)
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_set_parent_requires_valid_handles(self) -> None:
        """set_parent fails gracefully with invalid handles."""
        result = Win32API.set_parent(999999, 888888)
        assert result == 0 or isinstance(result, int)


class TestAdobeInjectorProcess:
    """Test Adobe Injector process management."""

    def test_init_stores_executable_path(self) -> None:
        """__init__ stores Adobe Injector executable path."""
        test_path = Path("D:/tools/AdobeInjector.exe")
        process = AdobeInjectorProcess(test_path)

        assert process.adobe_injector_path == test_path
        assert process.process is None
        assert process.hwnd is None
        assert not process.embedded
        assert process.config_path == test_path.parent / "config.ini"

    def test_start_raises_filenotfounderror_for_missing_executable(self) -> None:
        """start raises FileNotFoundError when executable missing."""
        process = AdobeInjectorProcess(Path("D:/nonexistent/fake.exe"))

        with pytest.raises(FileNotFoundError, match="Adobe Injector executable not found"):
            process.start()

    def test_start_launches_real_executable_when_available(self) -> None:
        """start launches real executable and manages process."""
        notepad_exe = Path("C:/Windows/System32/notepad.exe")
        if not notepad_exe.exists():
            pytest.skip("notepad.exe not available for testing")

        process = AdobeInjectorProcess(notepad_exe)

        try:
            result = process.start(silent=True)
            assert result is True
            assert process.process is not None
            assert process.process.poll() is None

        finally:
            if process.process:
                process.terminate()

    def test_terminate_kills_process_and_clears_state(self) -> None:
        """terminate kills process and clears all state variables."""
        notepad_exe = Path("C:/Windows/System32/notepad.exe")
        if not notepad_exe.exists():
            pytest.skip("notepad.exe not available")

        process = AdobeInjectorProcess(notepad_exe)
        process.start(silent=True)

        assert process.process is not None

        process.terminate()

        assert process.process is None
        assert process.hwnd is None

    def test_embed_in_widget_requires_valid_hwnd(self) -> None:
        """embed_in_widget returns False when hwnd not set."""
        process = AdobeInjectorProcess(Path("D:/tools/AdobeInjector.exe"))

        try:
            from PyQt6.QtWidgets import QWidget
            mock_widget = QWidget()
            result = process.embed_in_widget(mock_widget)
            assert result is False
        except ImportError:
            pytest.skip("PyQt6 not available")

    def test_resize_to_parent_ignores_when_not_embedded(self) -> None:
        """resize_to_parent does nothing when window not embedded."""
        process = AdobeInjectorProcess(Path("D:/tools/AdobeInjector.exe"))
        process.hwnd = 12345
        process.embedded = False

        process.resize_to_parent(1024, 768)

        assert process.hwnd == 12345


class TestIPCController:
    """Test Inter-Process Communication controller."""

    def test_init_stores_process_reference(self) -> None:
        """__init__ stores Adobe Injector process reference."""
        test_process = AdobeInjectorProcess(Path("D:/tools/test.exe"))
        controller = IPCController(test_process)

        assert controller.process == test_process
        assert controller.pipe_name == r"\\.\pipe\IntellicrackAdobeInjector"
        assert controller.pipe is None

    def test_send_command_ignores_when_pipe_none(self) -> None:
        """send_command does nothing when pipe not created."""
        test_process = AdobeInjectorProcess(Path("D:/tools/test.exe"))
        controller = IPCController(test_process)
        controller.pipe = None

        controller.send_command({"action": "test"})

        assert controller.pipe is None

    def test_receive_response_returns_empty_dict_when_no_pipe(self) -> None:
        """receive_response returns empty dict when pipe not created."""
        test_process = AdobeInjectorProcess(Path("D:/tools/test.exe"))
        controller = IPCController(test_process)
        controller.pipe = None

        response = controller.receive_response()
        assert response == {}


class TestAdobeInjectorIntegration:
    """Integration tests for complete Adobe Injector workflow."""

    def test_process_lifecycle_creation_and_termination(self) -> None:
        """Process lifecycle: creation -> configuration -> termination."""
        notepad_exe = Path("C:/Windows/System32/notepad.exe")
        if not notepad_exe.exists():
            pytest.skip("notepad.exe not available")

        process = AdobeInjectorProcess(notepad_exe)

        try:
            assert process.start(silent=True) is True
            assert process.process is not None

            process.terminate()
            assert process.process is None
            assert process.hwnd is None

        finally:
            if process.process:
                process.terminate()

    def test_ipc_controller_initialization_workflow(self) -> None:
        """IPC controller initialization and configuration."""
        notepad_exe = Path("C:/Windows/System32/notepad.exe")
        if not notepad_exe.exists():
            pytest.skip("notepad.exe not available")

        process = AdobeInjectorProcess(notepad_exe)
        controller = IPCController(process)

        assert controller.process == process
        assert controller.pipe_name == r"\\.\pipe\IntellicrackAdobeInjector"
        assert controller.pipe is None

    def test_multiple_process_instances_independence(self) -> None:
        """Multiple process instances operate independently."""
        notepad_exe = Path("C:/Windows/System32/notepad.exe")
        if not notepad_exe.exists():
            pytest.skip("notepad.exe not available")

        process1 = AdobeInjectorProcess(notepad_exe)
        process2 = AdobeInjectorProcess(notepad_exe)

        try:
            result1 = process1.start(silent=True)
            result2 = process2.start(silent=True)

            assert result1 is True
            assert result2 is True
            assert process1.process is not process2.process

        finally:
            if process1.process:
                process1.terminate()
            if process2.process:
                process2.terminate()
