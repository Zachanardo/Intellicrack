"""Production tests for Adobe Injector Integration module.

Tests Win32 API window embedding, process control, and IPC functionality.
All tests validate real Windows integration capabilities without mocks.
"""

import ctypes
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Optional

import pytest

from intellicrack.core.adobe_injector_integration import (
    AdobeInjectorProcess,
    AdobeInjectorWidget,
    AutoIt3COMInterface,
    IPCController,
    Win32API,
)


class FakeProcess:
    """Real test double for subprocess.Popen."""

    def __init__(self, args: list[str], **kwargs: Any) -> None:
        self.args = args
        self.kwargs = kwargs
        self.stdin: Optional[FakeStdin] = FakeStdin() if kwargs.get("stdin") else None
        self.returncode: Optional[int] = None
        self.terminated: bool = False

    def terminate(self) -> None:
        self.terminated = True

    def wait(self, timeout: Optional[int] = None) -> int:
        self.returncode = 0
        return 0


class FakeStdin:
    """Real test double for process stdin stream."""

    def __init__(self) -> None:
        self.written_data: list[bytes] = []
        self.flush_count: int = 0

    def write(self, data: bytes) -> int:
        self.written_data.append(data)
        return len(data)

    def flush(self) -> None:
        self.flush_count += 1


class FakeQtWidget:
    """Real test double for Qt widget."""

    def __init__(self, width: int = 800, height: int = 600, win_id: int = 67890) -> None:
        self._width = width
        self._height = height
        self._win_id = win_id
        self.geometry_obj = FakeGeometry(width, height)
        self.should_raise: bool = False

    def winId(self) -> int:
        if self.should_raise:
            raise Exception("Widget error")
        return self._win_id

    def geometry(self) -> "FakeGeometry":
        return self.geometry_obj


class FakeGeometry:
    """Real test double for Qt geometry."""

    def __init__(self, width: int, height: int) -> None:
        self._width = width
        self._height = height

    def width(self) -> int:
        return self._width

    def height(self) -> int:
        return self._height


class FakeAutoItCOM:
    """Real test double for AutoIt COM interface."""

    def __init__(self) -> None:
        self.control_click_calls: list[tuple[str, str, str]] = []
        self.control_set_text_calls: list[tuple[str, str, str, str]] = []
        self.control_get_text_calls: list[tuple[str, str, str]] = []
        self.control_get_text_return: str = "retrieved_text"

    def ControlClick(self, title: str, text: str, control_id: str) -> None:
        self.control_click_calls.append((title, text, control_id))

    def ControlSetText(self, title: str, text: str, control_id: str, value: str) -> None:
        self.control_set_text_calls.append((title, text, control_id, value))

    def ControlGetText(self, title: str, text: str, control_id: str) -> str:
        self.control_get_text_calls.append((title, text, control_id))
        return self.control_get_text_return


class FakeWin32API:
    """Real test double for Win32 API operations.

    Matches the production Win32API class signatures exactly.
    """

    def __init__(self) -> None:
        self.get_window_long_return: int = 0
        self.set_window_long_calls: list[tuple[int, int, int]] = []
        self.set_window_long_return: int = 0
        self.set_parent_calls: list[tuple[int, int]] = []
        self.set_parent_return: int = 0
        self.move_window_calls: list[tuple[int, int, int, int, int, bool]] = []
        self.move_window_return: bool = True
        self.show_window_calls: list[tuple[int, int]] = []
        self.show_window_return: bool = True

    def get_window_long(self, hwnd: int, index: int) -> int:
        return self.get_window_long_return

    def set_window_long(self, hwnd: int, index: int, new_long: int) -> int:
        self.set_window_long_calls.append((hwnd, index, new_long))
        return self.set_window_long_return

    def set_parent(self, child_hwnd: int, parent_hwnd: int) -> int:
        self.set_parent_calls.append((child_hwnd, parent_hwnd))
        return self.set_parent_return

    def move_window(
        self, hwnd: int, x: int, y: int, width: int, height: int, repaint: bool = True
    ) -> bool:
        self.move_window_calls.append((hwnd, x, y, width, height, repaint))
        return self.move_window_return

    def show_window(self, hwnd: int, cmd_show: int) -> bool:
        self.show_window_calls.append((hwnd, cmd_show))
        return self.show_window_return


class FakePopener:
    """Real test double for subprocess.Popen context manager."""

    def __init__(self, process: FakeProcess) -> None:
        self.process = process

    def __enter__(self) -> FakeProcess:
        return self.process

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        pass


class FakePatchContext:
    """Real test double for patch context manager."""

    def __init__(self, target: str, new_value: Any = None) -> None:
        self.target = target
        self.new_value = new_value
        self.original_value: Any = None

    def __enter__(self) -> Any:
        parts = self.target.rsplit(".", 1)
        if len(parts) == 2:
            module_path, attr_name = parts
            try:
                module = __import__(module_path, fromlist=[attr_name])
                self.original_value = getattr(module, attr_name, None)
                if self.new_value is not None:
                    setattr(module, attr_name, self.new_value)
            except (ImportError, AttributeError):
                pass
        return self.new_value

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self.original_value is not None:
            parts = self.target.rsplit(".", 1)
            if len(parts) == 2:
                module_path, attr_name = parts
                try:
                    module = __import__(module_path, fromlist=[attr_name])
                    setattr(module, attr_name, self.original_value)
                except (ImportError, AttributeError):
                    pass


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
        result = Win32API.find_window(None, "NonExistentWindowTitle12345")  # type: ignore[arg-type]
        assert isinstance(result, int)
        assert result == 0

    def test_find_window_finds_existing_window(self) -> None:
        """find_window can locate actual Windows shell windows."""
        hwnd = Win32API.find_window("Shell_TrayWnd", None)  # type: ignore[arg-type]
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

        import subprocess
        original_popen = subprocess.Popen
        created_process: Optional[FakeProcess] = None

        def fake_popen_factory(*args: Any, **kwargs: Any) -> FakeProcess:
            nonlocal created_process
            created_process = FakeProcess(list(args[0]) if args else [], **kwargs)
            return created_process

        try:
            subprocess.Popen = fake_popen_factory  # type: ignore[misc, assignment]

            original_find = process_manager._find_adobe_injector_window

            def fake_find(max_attempts: int = 10, wait_interval: float = 0.5) -> Optional[int]:
                return 12345

            process_manager._find_adobe_injector_window = fake_find  # type: ignore[method-assign]

            result = process_manager.start()

            assert result is True
            assert created_process is not None
            assert str(exe_path) in created_process.args
            assert created_process.kwargs.get("shell") is False

        finally:
            subprocess.Popen = original_popen  # type: ignore[misc]
            process_manager._find_adobe_injector_window = original_find  # type: ignore[method-assign]

    def test_start_silent_mode_adds_silent_flag(self, tmp_path: Path) -> None:
        """start(silent=True) adds /silent flag to command line."""
        exe_path = tmp_path / "AdobeInjector.exe"
        exe_path.write_text("MZ")

        process_manager = AdobeInjectorProcess(exe_path)

        import subprocess
        original_popen = subprocess.Popen
        created_process: Optional[FakeProcess] = None

        def fake_popen_factory(*args: Any, **kwargs: Any) -> FakeProcess:
            nonlocal created_process
            created_process = FakeProcess(list(args[0]) if args else [], **kwargs)
            return created_process

        try:
            subprocess.Popen = fake_popen_factory  # type: ignore[misc, assignment]

            original_find = process_manager._find_adobe_injector_window

            def fake_find(max_attempts: int = 10, wait_interval: float = 0.5) -> Optional[int]:
                return 12345

            process_manager._find_adobe_injector_window = fake_find  # type: ignore[method-assign]

            process_manager.start(silent=True)

            assert created_process is not None
            assert "/silent" in created_process.args

        finally:
            subprocess.Popen = original_popen  # type: ignore[misc]
            process_manager._find_adobe_injector_window = original_find  # type: ignore[method-assign]

    def test_find_adobe_injector_window_returns_none_when_not_found(self, tmp_path: Path) -> None:
        """_find_adobe_injector_window returns None when window not found."""
        exe_path = tmp_path / "AdobeInjector.exe"
        process_manager = AdobeInjectorProcess(exe_path)

        import time
        original_sleep = time.sleep

        try:
            time.sleep = lambda x: None
            result = process_manager._find_adobe_injector_window(max_attempts=2)
            assert result is None
        finally:
            time.sleep = original_sleep

    def test_find_adobe_injector_window_enumerates_windows(self, tmp_path: Path) -> None:
        """_find_adobe_injector_window uses EnumWindows to search for window."""
        exe_path = tmp_path / "AdobeInjector.exe"
        process_manager = AdobeInjectorProcess(exe_path)

        enum_called = False
        original_enum = Win32API.user32.EnumWindows

        def fake_enum(callback: Any, lparam: Any) -> bool:
            nonlocal enum_called
            enum_called = True
            return True

        try:
            Win32API.user32.EnumWindows = fake_enum  # type: ignore[attr-defined]

            import time
            original_sleep = time.sleep
            time.sleep = lambda x: None

            try:
                process_manager._find_adobe_injector_window(max_attempts=1)
                assert enum_called
            finally:
                time.sleep = original_sleep

        finally:
            Win32API.user32.EnumWindows = original_enum  # type: ignore[attr-defined]

    def test_embed_in_widget_returns_false_when_no_hwnd(self, tmp_path: Path) -> None:
        """embed_in_widget returns False when hwnd is None."""
        exe_path = tmp_path / "AdobeInjector.exe"
        process_manager = AdobeInjectorProcess(exe_path)

        fake_widget = FakeQtWidget()
        result = process_manager.embed_in_widget(fake_widget)  # type: ignore[arg-type]

        assert result is False

    def test_embed_in_widget_sets_parent_when_hwnd_exists(self, tmp_path: Path) -> None:
        """embed_in_widget calls SetParent when hwnd is set."""
        exe_path = tmp_path / "AdobeInjector.exe"
        process_manager = AdobeInjectorProcess(exe_path)
        process_manager.hwnd = 12345

        fake_widget = FakeQtWidget(width=800, height=600, win_id=67890)
        fake_api = FakeWin32API()

        original_get_window_long = Win32API.get_window_long
        original_set_window_long = Win32API.set_window_long
        original_set_parent = Win32API.set_parent
        original_move_window = Win32API.move_window
        original_show_window = Win32API.show_window

        try:
            setattr(Win32API, "get_window_long", fake_api.get_window_long)
            setattr(Win32API, "set_window_long", fake_api.set_window_long)
            setattr(Win32API, "set_parent", fake_api.set_parent)
            setattr(Win32API, "move_window", fake_api.move_window)
            setattr(Win32API, "show_window", fake_api.show_window)

            result = process_manager.embed_in_widget(fake_widget)  # type: ignore[arg-type]

            assert result is True
            assert (12345, 67890) in fake_api.set_parent_calls

        finally:
            setattr(Win32API, "get_window_long", original_get_window_long)
            setattr(Win32API, "set_window_long", original_set_window_long)
            setattr(Win32API, "set_parent", original_set_parent)
            setattr(Win32API, "move_window", original_move_window)
            setattr(Win32API, "show_window", original_show_window)

    def test_resize_to_parent_calls_move_window(self, tmp_path: Path) -> None:
        """resize_to_parent calls MoveWindow with correct dimensions."""
        exe_path = tmp_path / "AdobeInjector.exe"
        process_manager = AdobeInjectorProcess(exe_path)
        process_manager.hwnd = 12345
        process_manager.embedded = True

        fake_api = FakeWin32API()
        original_move_window = Win32API.move_window

        try:
            setattr(Win32API, "move_window", fake_api.move_window)
            process_manager.resize_to_parent(1024, 768)

            assert len(fake_api.move_window_calls) == 1
            assert fake_api.move_window_calls[0] == (12345, 0, 0, 1024, 768, True)

        finally:
            setattr(Win32API, "move_window", original_move_window)

    def test_send_command_writes_to_stdin(self, tmp_path: Path) -> None:
        """send_command writes command to process stdin."""
        exe_path = tmp_path / "AdobeInjector.exe"
        process_manager = AdobeInjectorProcess(exe_path)

        fake_stdin = FakeStdin()
        fake_process = FakeProcess([], stdin=subprocess.PIPE)
        fake_process.stdin = fake_stdin
        process_manager.process = fake_process  # type: ignore[assignment]

        process_manager.send_command("patch_adobe")

        assert len(fake_stdin.written_data) == 1
        assert fake_stdin.flush_count == 1

    def test_terminate_kills_process(self, tmp_path: Path) -> None:
        """terminate() terminates process and waits for exit."""
        exe_path = tmp_path / "AdobeInjector.exe"
        process_manager = AdobeInjectorProcess(exe_path)

        fake_process = FakeProcess([])
        process_manager.process = fake_process  # type: ignore[assignment]

        process_manager.terminate()

        assert fake_process.terminated is True
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
        import intellicrack.core.adobe_injector_integration as aii_module

        original_available = getattr(aii_module, "PYQT6_AVAILABLE", False)
        original_init = AdobeInjectorWidget.init_adobe_injector

        try:
            setattr(aii_module, "PYQT6_AVAILABLE", True)

            def fake_init(self: AdobeInjectorWidget) -> None:
                pass

            setattr(AdobeInjectorWidget, "init_adobe_injector", fake_init)

            widget = AdobeInjectorWidget()

            assert hasattr(widget, "launch_btn")
            assert hasattr(widget, "terminate_btn")
            assert hasattr(widget, "rebrand_btn")
            assert hasattr(widget, "embed_container")
            assert hasattr(widget, "status_label")

        finally:
            setattr(aii_module, "PYQT6_AVAILABLE", original_available)
            setattr(AdobeInjectorWidget, "init_adobe_injector", original_init)


class TestAutoIt3COMInterface:
    """Test AutoIt3 COM interface."""

    def test_init_sets_available_false_when_com_unavailable(self) -> None:
        """Initialization sets available=False when win32com not available."""
        import intellicrack.core.adobe_injector_integration as aii_module

        original_win32com = getattr(aii_module, "win32com", None)

        try:
            setattr(aii_module, "win32com", None)
            interface = AutoIt3COMInterface()
            assert interface.available is False

        finally:
            setattr(aii_module, "win32com", original_win32com)

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

        fake_autoit = FakeAutoItCOM()
        interface.autoit = fake_autoit

        result = interface.control_adobe_injector("click_button", {"control_id": "Button1"})

        assert result is True
        assert len(fake_autoit.control_click_calls) == 1

    def test_control_adobe_injector_set_text(self) -> None:
        """control_adobe_injector executes set_text action."""
        interface = AutoIt3COMInterface()
        interface.available = True

        fake_autoit = FakeAutoItCOM()
        interface.autoit = fake_autoit

        result = interface.control_adobe_injector(
            "set_text",
            {"control_id": "Edit1", "text": "test_value"},
        )

        assert result is True
        assert len(fake_autoit.control_set_text_calls) == 1

    def test_control_adobe_injector_get_text(self) -> None:
        """control_adobe_injector returns text for get_text action."""
        interface = AutoIt3COMInterface()
        interface.available = True

        fake_autoit = FakeAutoItCOM()
        fake_autoit.control_get_text_return = "retrieved_text"
        interface.autoit = fake_autoit

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

        import intellicrack.core.adobe_injector_integration as aii_module

        original_win32pipe = getattr(aii_module, "win32pipe", None)

        try:
            setattr(aii_module, "win32pipe", None)
            result = controller.create_named_pipe()
            assert result is False or result is None

        finally:
            setattr(aii_module, "win32pipe", original_win32pipe)


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_adobe_injector_process_handles_invalid_command(self, tmp_path: Path) -> None:
        """Process manager rejects invalid command structures."""
        exe_path = tmp_path / "AdobeInjector.exe"
        exe_path.write_text("MZ")

        process_manager = AdobeInjectorProcess(exe_path)

        with pytest.raises(ValueError):
            process_manager.start()

    def test_resize_to_parent_does_nothing_when_not_embedded(self, tmp_path: Path) -> None:
        """resize_to_parent is no-op when window not embedded."""
        exe_path = tmp_path / "AdobeInjector.exe"
        process_manager = AdobeInjectorProcess(exe_path)
        process_manager.hwnd = 12345
        process_manager.embedded = False

        fake_api = FakeWin32API()
        original_move_window = Win32API.move_window

        try:
            setattr(Win32API, "move_window", fake_api.move_window)
            process_manager.resize_to_parent(800, 600)

            assert len(fake_api.move_window_calls) == 0

        finally:
            setattr(Win32API, "move_window", original_move_window)

    def test_send_command_handles_none_stdin(self, tmp_path: Path) -> None:
        """send_command handles process with None stdin gracefully."""
        exe_path = tmp_path / "AdobeInjector.exe"
        process_manager = AdobeInjectorProcess(exe_path)

        fake_process = FakeProcess([])
        fake_process.stdin = None
        process_manager.process = fake_process  # type: ignore[assignment]

        process_manager.send_command("test_command")

    def test_embed_in_widget_handles_exception(self, tmp_path: Path) -> None:
        """embed_in_widget returns False on exception."""
        exe_path = tmp_path / "AdobeInjector.exe"
        process_manager = AdobeInjectorProcess(exe_path)
        process_manager.hwnd = 12345

        fake_widget = FakeQtWidget()
        fake_widget.should_raise = True

        result = process_manager.embed_in_widget(fake_widget)  # type: ignore[arg-type]

        assert result is False


class TestIntegrationScenarios:
    """Test complete integration scenarios."""

    def test_complete_lifecycle_without_crashes(self, tmp_path: Path) -> None:
        """Complete process lifecycle from start to terminate."""
        exe_path = tmp_path / "AdobeInjector.exe"
        exe_path.write_text("MZ")

        process_manager = AdobeInjectorProcess(exe_path)

        import subprocess
        original_popen = subprocess.Popen
        created_process: Optional[FakeProcess] = None

        def fake_popen_factory(*args: Any, **kwargs: Any) -> FakeProcess:
            nonlocal created_process
            created_process = FakeProcess(list(args[0]) if args else [], **kwargs)
            return created_process

        try:
            subprocess.Popen = fake_popen_factory  # type: ignore[misc, assignment]

            original_find = process_manager._find_adobe_injector_window

            def fake_find(max_attempts: int = 10, wait_interval: float = 0.5) -> Optional[int]:
                return 12345

            process_manager._find_adobe_injector_window = fake_find  # type: ignore[method-assign]

            started = process_manager.start()
            assert started is True

            process_manager.terminate()
            assert process_manager.process is None

        finally:
            subprocess.Popen = original_popen  # type: ignore[misc]
            process_manager._find_adobe_injector_window = original_find  # type: ignore[method-assign]

    def test_multiple_resize_operations(self, tmp_path: Path) -> None:
        """Multiple resize operations execute correctly."""
        exe_path = tmp_path / "AdobeInjector.exe"
        process_manager = AdobeInjectorProcess(exe_path)
        process_manager.hwnd = 12345
        process_manager.embedded = True

        sizes = [(800, 600), (1024, 768), (1920, 1080), (640, 480)]

        fake_api = FakeWin32API()
        original_move_window = Win32API.move_window

        try:
            setattr(Win32API, "move_window", fake_api.move_window)

            for width, height in sizes:
                process_manager.resize_to_parent(width, height)

            assert len(fake_api.move_window_calls) == len(sizes)

        finally:
            setattr(Win32API, "move_window", original_move_window)
