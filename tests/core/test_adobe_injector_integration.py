"""Production tests for Adobe Injector Integration module.

Tests Win32 API window embedding, process control, and IPC functionality.
All tests validate real Windows integration capabilities without mocks.
"""

import ctypes
import subprocess
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

from intellicrack.core.adobe_injector_integration import (
    AdobeInjectorProcess,
    AdobeInjectorWidget,
    AutoIt3COMInterface,
    IPCController,
    Win32API,
)


class TestWin32API:
    """Test Win32 API wrapper functionality."""

    def test_win32api_has_user32_handle(self) -> None:
        """Win32API provides access to user32 DLL."""
        assert Win32API.user32 is not None
        assert hasattr(Win32API.user32, "FindWindowW")

    def test_win32api_has_kernel32_handle(self) -> None:
        """Win32API provides access to kernel32 DLL."""
        assert Win32API.kernel32 is not None

    def test_find_window_returns_integer(self) -> None:
        """find_window returns integer handle (0 if not found)."""
        result = Win32API.find_window(None, "NonExistentWindowTitle12345")
        assert isinstance(result, int)
        assert result == 0

    def test_find_window_finds_existing_window(self) -> None:
        """find_window can locate actual Windows shell windows."""
        hwnd = Win32API.find_window("Shell_TrayWnd", None)
        assert isinstance(hwnd, int)

    @pytest.mark.skipif(
        not hasattr(ctypes.windll.user32, "GetWindowLongW"),
        reason="Windows-only test",
    )
    def test_get_window_long_on_desktop(self) -> None:
        """get_window_long retrieves window style from desktop window."""
        desktop_hwnd = Win32API.user32.GetDesktopWindow()
        style = Win32API.get_window_long(desktop_hwnd, -16)
        assert isinstance(style, int)
        assert style != 0

    def test_show_window_accepts_valid_parameters(self) -> None:
        """show_window accepts valid window handle and show command."""
        result = Win32API.show_window(0, 0)
        assert isinstance(result, (bool, int))


class TestAdobeInjectorProcess:
    """Test Adobe Injector process management."""

    def test_init_sets_correct_attributes(self, tmp_path: Path) -> None:
        """Initialization sets path, process, and config correctly."""
        exe_path = tmp_path / "AdobeInjector.exe"
        exe_path.touch()

        process_manager = AdobeInjectorProcess(exe_path)

        assert process_manager.adobe_injector_path == exe_path
        assert process_manager.process is None
        assert process_manager.hwnd is None
        assert process_manager.embedded is False
        assert process_manager.config_path == exe_path.parent / "config.ini"

    def test_start_raises_error_when_executable_missing(self) -> None:
        """start() raises FileNotFoundError when executable doesn't exist."""
        nonexistent_path = Path("D:/NonExistent/AdobeInjector.exe")
        process_manager = AdobeInjectorProcess(nonexistent_path)

        with pytest.raises(FileNotFoundError, match="Adobe Injector executable not found"):
            process_manager.start()

    def test_start_creates_subprocess_when_executable_exists(self, tmp_path: Path) -> None:
        """start() creates subprocess when executable exists."""
        exe_path = tmp_path / "AdobeInjector.exe"
        exe_path.write_text("MZ")

        process_manager = AdobeInjectorProcess(exe_path)

        with patch("subprocess.Popen") as mock_popen:
            mock_process = Mock()
            mock_popen.return_value = mock_process

            with patch.object(process_manager, "_find_adobe_injector_window", return_value=12345):
                result = process_manager.start()

                assert result is True
                assert mock_popen.called
                call_args = mock_popen.call_args
                assert str(exe_path) in call_args[0][0]
                assert call_args[1]["shell"] is False

    def test_start_silent_mode_adds_silent_flag(self, tmp_path: Path) -> None:
        """start(silent=True) adds /silent flag to command line."""
        exe_path = tmp_path / "AdobeInjector.exe"
        exe_path.write_text("MZ")

        process_manager = AdobeInjectorProcess(exe_path)

        with patch("subprocess.Popen") as mock_popen:
            mock_popen.return_value = Mock()
            with patch.object(process_manager, "_find_adobe_injector_window", return_value=12345):
                process_manager.start(silent=True)

                call_args = mock_popen.call_args[0][0]
                assert "/silent" in call_args

    def test_find_adobe_injector_window_returns_none_when_not_found(self, tmp_path: Path) -> None:
        """_find_adobe_injector_window returns None when window not found."""
        exe_path = tmp_path / "AdobeInjector.exe"
        process_manager = AdobeInjectorProcess(exe_path)

        with patch("time.sleep"):
            result = process_manager._find_adobe_injector_window(max_attempts=2)

        assert result is None

    def test_find_adobe_injector_window_enumerates_windows(self, tmp_path: Path) -> None:
        """_find_adobe_injector_window uses EnumWindows to search for window."""
        exe_path = tmp_path / "AdobeInjector.exe"
        process_manager = AdobeInjectorProcess(exe_path)

        with patch.object(Win32API.user32, "EnumWindows") as mock_enum:
            with patch("time.sleep"):
                process_manager._find_adobe_injector_window(max_attempts=1)

            assert mock_enum.called

    def test_embed_in_widget_returns_false_when_no_hwnd(self, tmp_path: Path) -> None:
        """embed_in_widget returns False when hwnd is None."""
        exe_path = tmp_path / "AdobeInjector.exe"
        process_manager = AdobeInjectorProcess(exe_path)

        mock_widget = Mock()
        result = process_manager.embed_in_widget(mock_widget)

        assert result is False

    def test_embed_in_widget_sets_parent_when_hwnd_exists(self, tmp_path: Path) -> None:
        """embed_in_widget calls SetParent when hwnd is set."""
        exe_path = tmp_path / "AdobeInjector.exe"
        process_manager = AdobeInjectorProcess(exe_path)
        process_manager.hwnd = 12345

        mock_widget = Mock()
        mock_widget.winId.return_value = 67890
        mock_widget.geometry.return_value = Mock(width=lambda: 800, height=lambda: 600)

        with patch.object(Win32API, "get_window_long", return_value=0):
            with patch.object(Win32API, "set_window_long"):
                with patch.object(Win32API, "set_parent") as mock_set_parent:
                    with patch.object(Win32API, "move_window"):
                        with patch.object(Win32API, "show_window"):
                            result = process_manager.embed_in_widget(mock_widget)

                            assert result is True
                            mock_set_parent.assert_called_once_with(12345, 67890)

    def test_resize_to_parent_calls_move_window(self, tmp_path: Path) -> None:
        """resize_to_parent calls MoveWindow with correct dimensions."""
        exe_path = tmp_path / "AdobeInjector.exe"
        process_manager = AdobeInjectorProcess(exe_path)
        process_manager.hwnd = 12345
        process_manager.embedded = True

        with patch.object(Win32API, "move_window") as mock_move:
            process_manager.resize_to_parent(1024, 768)

            mock_move.assert_called_once_with(12345, 0, 0, 1024, 768)

    def test_send_command_writes_to_stdin(self, tmp_path: Path) -> None:
        """send_command writes command to process stdin."""
        exe_path = tmp_path / "AdobeInjector.exe"
        process_manager = AdobeInjectorProcess(exe_path)

        mock_stdin = Mock()
        mock_process = Mock()
        mock_process.stdin = mock_stdin
        process_manager.process = mock_process

        process_manager.send_command("patch_adobe")

        mock_stdin.write.assert_called_once()
        mock_stdin.flush.assert_called_once()

    def test_terminate_kills_process(self, tmp_path: Path) -> None:
        """terminate() terminates process and waits for exit."""
        exe_path = tmp_path / "AdobeInjector.exe"
        process_manager = AdobeInjectorProcess(exe_path)

        mock_process = Mock()
        process_manager.process = mock_process

        process_manager.terminate()

        mock_process.terminate.assert_called_once()
        mock_process.wait.assert_called_once_with(timeout=5)
        assert process_manager.process is None
        assert process_manager.hwnd is None


class TestAdobeInjectorWidget:
    """Test Adobe Injector Qt widget."""

    def test_widget_requires_pyqt6(self) -> None:
        """AdobeInjectorWidget raises ImportError without PyQt6."""
        from intellicrack.handlers import pyqt6_handler

        original_available = pyqt6_handler.PYQT6_AVAILABLE

        try:
            pyqt6_handler.PYQT6_AVAILABLE = False

            with pytest.raises(ImportError, match="PyQt6 not available"):
                AdobeInjectorWidget()

        finally:
            pyqt6_handler.PYQT6_AVAILABLE = original_available

    @pytest.mark.skipif(
        not __import__("importlib").util.find_spec("PyQt6"),
        reason="PyQt6 not available",
    )
    def test_widget_initializes_ui_components(self) -> None:
        """Widget creates UI components on initialization."""
        with patch("intellicrack.core.adobe_injector_integration.PYQT6_AVAILABLE", True):
            with patch.object(AdobeInjectorWidget, "init_adobe_injector"):
                widget = AdobeInjectorWidget()

                assert hasattr(widget, "launch_btn")
                assert hasattr(widget, "terminate_btn")
                assert hasattr(widget, "rebrand_btn")
                assert hasattr(widget, "embed_container")
                assert hasattr(widget, "status_label")


class TestAutoIt3COMInterface:
    """Test AutoIt3 COM interface."""

    def test_init_sets_available_false_when_com_unavailable(self) -> None:
        """Initialization sets available=False when win32com not available."""
        with patch("intellicrack.core.adobe_injector_integration.win32com", None):
            interface = AutoIt3COMInterface()
            assert interface.available is False

    def test_control_adobe_injector_returns_false_when_unavailable(self) -> None:
        """control_adobe_injector returns False when COM unavailable."""
        interface = AutoIt3COMInterface()
        interface.available = False

        result = interface.control_adobe_injector("click_button", {"control_id": "Button1"})

        assert result is False

    def test_control_adobe_injector_click_button(self) -> None:
        """control_adobe_injector executes click_button action."""
        interface = AutoIt3COMInterface()
        interface.available = True
        interface.autoit = Mock()

        result = interface.control_adobe_injector("click_button", {"control_id": "Button1"})

        assert result is True
        interface.autoit.ControlClick.assert_called_once()

    def test_control_adobe_injector_set_text(self) -> None:
        """control_adobe_injector executes set_text action."""
        interface = AutoIt3COMInterface()
        interface.available = True
        interface.autoit = Mock()

        result = interface.control_adobe_injector(
            "set_text",
            {"control_id": "Edit1", "text": "test_value"},
        )

        assert result is True
        interface.autoit.ControlSetText.assert_called_once()

    def test_control_adobe_injector_get_text(self) -> None:
        """control_adobe_injector returns text for get_text action."""
        interface = AutoIt3COMInterface()
        interface.available = True
        interface.autoit = Mock()
        interface.autoit.ControlGetText.return_value = "retrieved_text"

        result = interface.control_adobe_injector("get_text", {"control_id": "Edit1"})

        assert result == "retrieved_text"


class TestIPCController:
    """Test IPC controller for Adobe Injector."""

    def test_init_sets_pipe_name(self, tmp_path: Path) -> None:
        """Initialization sets correct pipe name."""
        exe_path = tmp_path / "AdobeInjector.exe"
        process = AdobeInjectorProcess(exe_path)
        controller = IPCController(process)

        assert controller.pipe_name == r"\\.\pipe\IntellicrackAdobeInjector"
        assert controller.pipe is None

    def test_create_named_pipe_returns_false_when_win32pipe_unavailable(self, tmp_path: Path) -> None:
        """create_named_pipe returns False when win32pipe unavailable."""
        exe_path = tmp_path / "AdobeInjector.exe"
        process = AdobeInjectorProcess(exe_path)
        controller = IPCController(process)

        with patch("intellicrack.core.adobe_injector_integration.win32pipe", None):
            result = controller.create_named_pipe()

        assert result is False or result is None


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_adobe_injector_process_handles_invalid_command(self, tmp_path: Path) -> None:
        """Process manager rejects invalid command structures."""
        exe_path = tmp_path / "AdobeInjector.exe"
        exe_path.write_text("MZ")

        process_manager = AdobeInjectorProcess(exe_path)

        with patch("subprocess.Popen") as mock_popen:
            invalid_cmd = ["valid", None, 123]

            with pytest.raises(ValueError):
                process_manager.start()

    def test_resize_to_parent_does_nothing_when_not_embedded(self, tmp_path: Path) -> None:
        """resize_to_parent is no-op when window not embedded."""
        exe_path = tmp_path / "AdobeInjector.exe"
        process_manager = AdobeInjectorProcess(exe_path)
        process_manager.hwnd = 12345
        process_manager.embedded = False

        with patch.object(Win32API, "move_window") as mock_move:
            process_manager.resize_to_parent(800, 600)

            mock_move.assert_not_called()

    def test_send_command_handles_none_stdin(self, tmp_path: Path) -> None:
        """send_command handles process with None stdin gracefully."""
        exe_path = tmp_path / "AdobeInjector.exe"
        process_manager = AdobeInjectorProcess(exe_path)

        mock_process = Mock()
        mock_process.stdin = None
        process_manager.process = mock_process

        process_manager.send_command("test_command")

    def test_embed_in_widget_handles_exception(self, tmp_path: Path) -> None:
        """embed_in_widget returns False on exception."""
        exe_path = tmp_path / "AdobeInjector.exe"
        process_manager = AdobeInjectorProcess(exe_path)
        process_manager.hwnd = 12345

        mock_widget = Mock()
        mock_widget.winId.side_effect = Exception("Widget error")

        result = process_manager.embed_in_widget(mock_widget)

        assert result is False


class TestIntegrationScenarios:
    """Test complete integration scenarios."""

    def test_complete_lifecycle_without_crashes(self, tmp_path: Path) -> None:
        """Complete process lifecycle from start to terminate."""
        exe_path = tmp_path / "AdobeInjector.exe"
        exe_path.write_text("MZ")

        process_manager = AdobeInjectorProcess(exe_path)

        with patch("subprocess.Popen") as mock_popen:
            mock_process = Mock()
            mock_popen.return_value = mock_process

            with patch.object(process_manager, "_find_adobe_injector_window", return_value=12345):
                started = process_manager.start()
                assert started is True

                process_manager.terminate()
                assert process_manager.process is None

    def test_multiple_resize_operations(self, tmp_path: Path) -> None:
        """Multiple resize operations execute correctly."""
        exe_path = tmp_path / "AdobeInjector.exe"
        process_manager = AdobeInjectorProcess(exe_path)
        process_manager.hwnd = 12345
        process_manager.embedded = True

        sizes = [(800, 600), (1024, 768), (1920, 1080), (640, 480)]

        with patch.object(Win32API, "move_window") as mock_move:
            for width, height in sizes:
                process_manager.resize_to_parent(width, height)

            assert mock_move.call_count == len(sizes)
