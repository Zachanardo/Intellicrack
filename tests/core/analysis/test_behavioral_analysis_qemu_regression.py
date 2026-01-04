"""Regression tests for QEMU integration in behavioral analysis module.

These tests verify that previously completed QEMU integration functionality
continues to work correctly, specifically validating API hooks and event
monitoring remain operational.
"""

import json
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, PropertyMock, patch

import pytest

from intellicrack.core.analysis.behavioral_analysis import (
    BehavioralAnalyzer,
    FridaAPIHookingFramework,
    HookPoint,
    MonitorEvent,
    QEMUConfig,
    QEMUController,
)


class RegressionTestBehavioralAnalysisQEMU:
    """Regression test suite for behavioral analysis QEMU integration.

    Validates that API hooks and event monitoring functionality remain
    operational after previous implementation was completed.
    """

    @pytest.fixture
    def test_binary(self, tmp_path: Path) -> Path:
        """Create a minimal test PE binary.

        Args:
            tmp_path: Temporary directory path.

        Returns:
            Path to created test binary.
        """
        binary_path = tmp_path / "test.exe"

        mz_header = b"MZ" + b"\x90" * 58
        pe_offset = b"\x80\x00\x00\x00"
        mz_stub = mz_header + pe_offset + b"\x00" * (0x80 - len(mz_header) - len(pe_offset))

        pe_signature = b"PE\x00\x00"
        machine = b"\x4c\x01"
        sections = b"\x03\x00"
        timestamp = b"\x00" * 4
        symbol_table = b"\x00" * 4
        symbol_count = b"\x00" * 4
        optional_size = b"\xe0\x00"
        characteristics = b"\x22\x00"

        coff_header = (
            machine
            + sections
            + timestamp
            + symbol_table
            + symbol_count
            + optional_size
            + characteristics
        )

        magic = b"\x0b\x02"
        optional_header = magic + b"\x00" * 222

        binary_content = mz_stub + pe_signature + coff_header + optional_header + b"\x00" * 512
        binary_path.write_bytes(binary_content)

        return binary_path

    @pytest.fixture
    def qemu_config(self, tmp_path: Path) -> QEMUConfig:
        """Create QEMU configuration for testing.

        Args:
            tmp_path: Temporary directory path.

        Returns:
            Configured QEMUConfig instance.
        """
        disk_image = tmp_path / "test_disk.img"
        disk_image.write_bytes(b"\x00" * (10 * 1024 * 1024))

        return QEMUConfig(
            machine_type="pc",
            cpu_model="qemu64",
            memory_size="512M",
            disk_image=disk_image,
            enable_kvm=False,
            enable_gdb=True,
            gdb_port=12345,
            monitor_port=14444,
            qmp_port=15555,
            vnc_display=None,
        )

    @pytest.fixture
    def mock_qemu_process(self) -> Mock:
        """Create mock QEMU process.

        Returns:
            Mock subprocess.Popen instance.
        """
        process_mock = Mock(spec=subprocess.Popen)
        process_mock.poll.return_value = None
        process_mock.pid = 12345
        process_mock.returncode = None
        process_mock.stdout = Mock()
        process_mock.stderr = Mock()
        process_mock.stdin = Mock()
        return process_mock

    @pytest.fixture
    def mock_monitor_socket(self) -> Mock:
        """Create mock monitor socket.

        Returns:
            Mock socket instance for QEMU monitor.
        """
        sock = Mock(spec=socket.socket)
        sock.recv.return_value = b"(qemu) info registers\r\nEAX=00000000\r\n(qemu) "
        return sock

    @pytest.fixture
    def mock_qmp_socket(self) -> Mock:
        """Create mock QMP socket.

        Returns:
            Mock socket instance for QEMU QMP interface.
        """
        sock = Mock(spec=socket.socket)

        qmp_recv_call_count = 0

        def qmp_recv_side_effect(size: int) -> bytes:
            nonlocal qmp_recv_call_count
            qmp_recv_call_count += 1

            if qmp_recv_call_count == 1:
                return b'{"QMP": {"version": {"qemu": "6.2.0"}}, "capabilities": []}\n'
            elif qmp_recv_call_count == 2:
                return b'{"return": {}}\n'
            else:
                return b'{"return": {"status": "running"}}\n'

        sock.recv.side_effect = qmp_recv_side_effect
        return sock

    def test_qemu_controller_initializes_correctly(self, qemu_config: QEMUConfig) -> None:
        """Verify QEMU controller initializes with proper configuration.

        Args:
            qemu_config: QEMU configuration fixture.
        """
        controller = QEMUController(qemu_config)

        assert controller.config == qemu_config
        assert controller.process is None
        assert controller.monitor_socket is None
        assert controller.qmp_socket is None
        assert controller.gdb_socket is None
        assert controller.is_running is False

    def test_qemu_controller_finds_qemu_binary(self, qemu_config: QEMUConfig) -> None:
        """Verify QEMU binary detection works on system.

        Args:
            qemu_config: QEMU configuration fixture.
        """
        controller = QEMUController(qemu_config)

        with patch("shutil.which") as mock_which:
            mock_which.return_value = "/usr/bin/qemu-system-x86_64"
            binary = controller._find_qemu_binary()

            assert binary == "/usr/bin/qemu-system-x86_64"
            assert mock_which.called

    def test_qemu_controller_starts_with_correct_command_line(
        self,
        qemu_config: QEMUConfig,
        test_binary: Path,
        mock_qemu_process: Mock,
        mock_monitor_socket: Mock,
        mock_qmp_socket: Mock,
    ) -> None:
        """Verify QEMU starts with correct command-line arguments.

        Args:
            qemu_config: QEMU configuration fixture.
            test_binary: Test binary fixture.
            mock_qemu_process: Mock QEMU process.
            mock_monitor_socket: Mock monitor socket.
            mock_qmp_socket: Mock QMP socket.
        """
        controller = QEMUController(qemu_config)

        with (
            patch("shutil.which", return_value="/usr/bin/qemu-system-x86_64"),
            patch("subprocess.Popen", return_value=mock_qemu_process) as mock_popen,
            patch("socket.socket") as mock_socket,
            patch.object(controller, "_prepare_disk_image"),
        ):
            mock_socket.side_effect = [mock_monitor_socket, mock_qmp_socket, Mock()]

            result = controller.start(test_binary)

            assert result is True
            assert controller.is_running is True
            assert mock_popen.called

            call_args = mock_popen.call_args[0][0]
            assert "/usr/bin/qemu-system-x86_64" in call_args
            assert "-machine" in call_args
            assert "pc" in call_args
            assert "-cpu" in call_args
            assert "qemu64" in call_args
            assert "-m" in call_args
            assert "512M" in call_args
            assert "-monitor" in call_args
            assert "-qmp" in call_args
            assert "-gdb" in call_args

    def test_qemu_controller_connects_to_monitor_interface(
        self,
        qemu_config: QEMUConfig,
        test_binary: Path,
        mock_qemu_process: Mock,
        mock_monitor_socket: Mock,
        mock_qmp_socket: Mock,
    ) -> None:
        """Verify QEMU monitor interface connection works correctly.

        Args:
            qemu_config: QEMU configuration fixture.
            test_binary: Test binary fixture.
            mock_qemu_process: Mock QEMU process.
            mock_monitor_socket: Mock monitor socket.
            mock_qmp_socket: Mock QMP socket.
        """
        controller = QEMUController(qemu_config)

        with (
            patch("shutil.which", return_value="/usr/bin/qemu-system-x86_64"),
            patch("subprocess.Popen", return_value=mock_qemu_process),
            patch("socket.socket") as mock_socket,
            patch.object(controller, "_prepare_disk_image"),
        ):
            mock_socket.side_effect = [mock_monitor_socket, mock_qmp_socket, Mock()]

            result = controller.start(test_binary)

            assert result is True
            monitor_connect_calls = [
                call for call in mock_monitor_socket.connect.call_args_list
            ]
            assert len(monitor_connect_calls) > 0
            assert monitor_connect_calls[0][0][0] == ("127.0.0.1", 14444)

    def test_qemu_controller_connects_to_qmp_interface(
        self,
        qemu_config: QEMUConfig,
        test_binary: Path,
        mock_qemu_process: Mock,
        mock_monitor_socket: Mock,
        mock_qmp_socket: Mock,
    ) -> None:
        """Verify QEMU QMP interface connection and initialization works.

        Args:
            qemu_config: QEMU configuration fixture.
            test_binary: Test binary fixture.
            mock_qemu_process: Mock QEMU process.
            mock_monitor_socket: Mock monitor socket.
            mock_qmp_socket: Mock QMP socket.
        """
        controller = QEMUController(qemu_config)

        with (
            patch("shutil.which", return_value="/usr/bin/qemu-system-x86_64"),
            patch("subprocess.Popen", return_value=mock_qemu_process),
            patch("socket.socket") as mock_socket,
            patch.object(controller, "_prepare_disk_image"),
        ):
            mock_socket.side_effect = [mock_monitor_socket, mock_qmp_socket, Mock()]

            result = controller.start(test_binary)

            assert result is True
            qmp_connect_calls = [call for call in mock_qmp_socket.connect.call_args_list]
            assert len(qmp_connect_calls) > 0
            assert qmp_connect_calls[0][0][0] == ("127.0.0.1", 15555)

            qmp_send_calls = [call for call in mock_qmp_socket.send.call_args_list]
            qmp_capabilities_sent = False
            for call in qmp_send_calls:
                sent_data = call[0][0]
                if b"qmp_capabilities" in sent_data:
                    qmp_capabilities_sent = True
                    break
            assert qmp_capabilities_sent

    def test_qemu_controller_sends_monitor_commands(
        self,
        qemu_config: QEMUConfig,
        test_binary: Path,
        mock_qemu_process: Mock,
        mock_monitor_socket: Mock,
        mock_qmp_socket: Mock,
    ) -> None:
        """Verify monitor command sending works correctly.

        Args:
            qemu_config: QEMU configuration fixture.
            test_binary: Test binary fixture.
            mock_qemu_process: Mock QEMU process.
            mock_monitor_socket: Mock monitor socket.
            mock_qmp_socket: Mock QMP socket.
        """
        controller = QEMUController(qemu_config)

        with (
            patch("shutil.which", return_value="/usr/bin/qemu-system-x86_64"),
            patch("subprocess.Popen", return_value=mock_qemu_process),
            patch("socket.socket") as mock_socket,
            patch.object(controller, "_prepare_disk_image"),
        ):
            mock_socket.side_effect = [mock_monitor_socket, mock_qmp_socket, Mock()]

            controller.start(test_binary)
            response = controller.send_monitor_command("info registers")

            assert "EAX=00000000" in response
            mock_monitor_socket.send.assert_called()
            sent_command = mock_monitor_socket.send.call_args_list[-1][0][0]
            assert b"info registers" in sent_command

    def test_qemu_controller_sends_qmp_commands(
        self,
        qemu_config: QEMUConfig,
        test_binary: Path,
        mock_qemu_process: Mock,
        mock_monitor_socket: Mock,
        mock_qmp_socket: Mock,
    ) -> None:
        """Verify QMP command sending works correctly.

        Args:
            qemu_config: QEMU configuration fixture.
            test_binary: Test binary fixture.
            mock_qemu_process: Mock QEMU process.
            mock_monitor_socket: Mock monitor socket.
            mock_qmp_socket: Mock QMP socket.
        """
        controller = QEMUController(qemu_config)

        with (
            patch("shutil.which", return_value="/usr/bin/qemu-system-x86_64"),
            patch("subprocess.Popen", return_value=mock_qemu_process),
            patch("socket.socket") as mock_socket,
            patch.object(controller, "_prepare_disk_image"),
        ):
            mock_socket.side_effect = [mock_monitor_socket, mock_qmp_socket, Mock()]

            controller.start(test_binary)
            response = controller.send_qmp_command({"execute": "query-status"})

            assert isinstance(response, dict)
            assert "return" in response or "status" in response
            mock_qmp_socket.send.assert_called()

    def test_qemu_controller_takes_snapshots(
        self,
        qemu_config: QEMUConfig,
        test_binary: Path,
        mock_qemu_process: Mock,
        mock_monitor_socket: Mock,
    ) -> None:
        """Verify snapshot creation works via QMP.

        Args:
            qemu_config: QEMU configuration fixture.
            test_binary: Test binary fixture.
            mock_qemu_process: Mock QEMU process.
            mock_monitor_socket: Mock monitor socket.
        """
        controller = QEMUController(qemu_config)

        mock_qmp_socket = Mock(spec=socket.socket)

        qmp_snapshot_call_count = 0

        def qmp_recv_snapshot(size: int) -> bytes:
            nonlocal qmp_snapshot_call_count
            qmp_snapshot_call_count += 1

            if qmp_snapshot_call_count == 1:
                return b'{"QMP": {"version": {}}}\n'
            elif qmp_snapshot_call_count == 2:
                return b'{"return": {}}\n'
            else:
                return b'{"return": "snapshot_created"}\n'

        mock_qmp_socket.recv.side_effect = qmp_recv_snapshot

        with (
            patch("shutil.which", return_value="/usr/bin/qemu-system-x86_64"),
            patch("subprocess.Popen", return_value=mock_qemu_process),
            patch("socket.socket") as mock_socket,
            patch.object(controller, "_prepare_disk_image"),
        ):
            mock_socket.side_effect = [mock_monitor_socket, mock_qmp_socket, Mock()]

            controller.start(test_binary)
            result = controller.take_snapshot("test_snapshot")

            assert result is True
            snapshot_calls = [
                call
                for call in mock_qmp_socket.send.call_args_list
                if b"savevm" in call[0][0]
            ]
            assert len(snapshot_calls) > 0

    def test_qemu_controller_stops_gracefully(
        self,
        qemu_config: QEMUConfig,
        test_binary: Path,
        mock_qemu_process: Mock,
        mock_monitor_socket: Mock,
        mock_qmp_socket: Mock,
    ) -> None:
        """Verify QEMU stops gracefully and cleans up resources.

        Args:
            qemu_config: QEMU configuration fixture.
            test_binary: Test binary fixture.
            mock_qemu_process: Mock QEMU process.
            mock_monitor_socket: Mock monitor socket.
            mock_qmp_socket: Mock QMP socket.
        """
        controller = QEMUController(qemu_config)

        with (
            patch("shutil.which", return_value="/usr/bin/qemu-system-x86_64"),
            patch("subprocess.Popen", return_value=mock_qemu_process),
            patch("socket.socket") as mock_socket,
            patch.object(controller, "_prepare_disk_image"),
        ):
            mock_socket.side_effect = [mock_monitor_socket, mock_qmp_socket, Mock()]

            controller.start(test_binary)
            controller.stop()

            assert controller.is_running is False
            assert controller.process is None
            assert controller.monitor_socket is None
            assert controller.qmp_socket is None
            mock_qemu_process.terminate.assert_called_once()

    def test_frida_api_hooks_initialize_correctly(self) -> None:
        """Verify Frida API hooking framework initializes with platform hooks."""
        framework = FridaAPIHookingFramework()

        assert framework.hooks is not None
        assert len(framework.hooks) > 0
        assert framework.events == []
        assert isinstance(framework.active_hooks, set)

    def test_frida_api_hooks_register_windows_hooks(self) -> None:
        """Verify Windows API hooks are registered correctly."""
        with patch("platform.system", return_value="Windows"):
            framework = FridaAPIHookingFramework()

            assert "kernel32.dll:CreateFileW" in framework.hooks
            assert "kernel32.dll:ReadFile" in framework.hooks
            assert "kernel32.dll:WriteFile" in framework.hooks
            assert "advapi32.dll:RegOpenKeyExW" in framework.hooks
            assert "advapi32.dll:RegQueryValueExW" in framework.hooks
            assert "advapi32.dll:RegSetValueExW" in framework.hooks
            assert "ws2_32.dll:connect" in framework.hooks
            assert "ws2_32.dll:send" in framework.hooks
            assert "ws2_32.dll:recv" in framework.hooks
            assert "ntdll.dll:NtCreateProcess" in framework.hooks
            assert "ntdll.dll:NtOpenProcess" in framework.hooks

    def test_frida_api_hooks_register_linux_hooks(self) -> None:
        """Verify Linux API hooks are registered correctly."""
        with patch("platform.system", return_value="Linux"):
            framework = FridaAPIHookingFramework()

            assert "libc.so.6:open" in framework.hooks
            assert "libc.so.6:read" in framework.hooks
            assert "libc.so.6:write" in framework.hooks
            assert "libc.so.6:socket" in framework.hooks
            assert "libc.so.6:connect" in framework.hooks

    def test_frida_api_hooks_add_custom_hook(self) -> None:
        """Verify custom hooks can be added to framework."""
        framework = FridaAPIHookingFramework()

        custom_hook = HookPoint(
            module="custom.dll",
            function="CustomFunc",
            on_enter=lambda args, ctx: None,
            priority=50,
        )

        framework.add_hook(custom_hook)

        assert "custom.dll:CustomFunc" in framework.hooks
        assert len(framework.hooks["custom.dll:CustomFunc"]) == 1
        assert framework.hooks["custom.dll:CustomFunc"][0] == custom_hook

    def test_frida_api_hooks_enable_disable_hooks(self) -> None:
        """Verify hooks can be enabled and disabled."""
        framework = FridaAPIHookingFramework()

        framework.enable_hook("kernel32.dll", "CreateFileW")
        assert "kernel32.dll:CreateFileW" in framework.active_hooks

        framework.disable_hook("kernel32.dll", "CreateFileW")
        assert "kernel32.dll:CreateFileW" not in framework.active_hooks

    def test_frida_api_hooks_generate_script(self) -> None:
        """Verify Frida JavaScript script generation works correctly."""
        with patch("platform.system", return_value="Windows"):
            framework = FridaAPIHookingFramework()

            framework.enable_hook("kernel32.dll", "CreateFileW")
            framework.enable_hook("advapi32.dll", "RegOpenKeyExW")

            script = framework._generate_frida_script()

            assert "CreateFileW" in script
            assert "RegOpenKeyExW" in script
            assert "Interceptor.attach" in script
            assert "onEnter" in script
            assert "onLeave" in script
            assert "kernel32.dll" in script
            assert "advapi32.dll" in script

    def test_frida_api_hooks_attach_to_process(self, test_binary: Path) -> None:
        """Verify Frida attaches to process and installs hooks.

        Args:
            test_binary: Test binary fixture.
        """
        framework = FridaAPIHookingFramework()

        mock_session = Mock()
        mock_script = Mock()
        mock_session.create_script.return_value = mock_script

        with patch("frida.attach", return_value=mock_session) as mock_attach:
            result = framework.attach_to_process(12345)

            assert result is True
            mock_attach.assert_called_once_with(12345)
            mock_session.create_script.assert_called_once()
            mock_script.on.assert_called_once()
            mock_script.load.assert_called_once()

    def test_frida_api_hooks_handle_process_not_found(self) -> None:
        """Verify Frida handles process not found gracefully."""
        framework = FridaAPIHookingFramework()

        with patch("frida.attach") as mock_attach:
            import frida

            mock_attach.side_effect = frida.ProcessNotFoundError("Process not found")

            result = framework.attach_to_process(99999)

            assert result is False

    def test_frida_api_hooks_detach_from_process(self) -> None:
        """Verify Frida detaches from process correctly."""
        framework = FridaAPIHookingFramework()

        mock_session = Mock()
        mock_script = Mock()
        framework.frida_session = mock_session
        framework.frida_script = mock_script

        framework.detach_from_process()

        mock_script.unload.assert_called_once()
        mock_session.detach.assert_called_once()
        assert framework.frida_session is None
        assert framework.frida_script is None

    def test_frida_api_hooks_capture_api_calls(self) -> None:
        """Verify API call events are captured correctly."""
        with patch("platform.system", return_value="Windows"):
            framework = FridaAPIHookingFramework()

            message = {
                "type": "send",
                "payload": {
                    "type": "api_call",
                    "module": "kernel32.dll",
                    "function": "CreateFileW",
                    "args": ["C:\\test.txt", "0x80000000", "0", "0"],
                    "timestamp": 1234567890.123,
                    "pid": 5678,
                    "tid": 1234,
                },
            }

            framework._on_frida_message(message, None)

            assert len(framework.events) == 1
            event = framework.events[0]
            assert event.event_type == "api_createfilew"
            assert event.process_id == 5678
            assert event.thread_id == 1234
            assert event.data["module"] == "kernel32.dll"
            assert event.data["function"] == "CreateFileW"
            assert "C:\\test.txt" in event.data["args"]

    def test_frida_api_hooks_execute_callbacks(self) -> None:
        """Verify hook callbacks are executed on API calls."""
        callback_executed = False

        def test_callback(args: list[Any], context: dict[str, Any]) -> None:
            nonlocal callback_executed
            callback_executed = True

        with patch("platform.system", return_value="Windows"):
            framework = FridaAPIHookingFramework()

            custom_hook = HookPoint(
                module="kernel32.dll",
                function="CreateFileW",
                on_enter=test_callback,
            )
            framework.add_hook(custom_hook)

            message = {
                "type": "send",
                "payload": {
                    "type": "api_call",
                    "module": "kernel32.dll",
                    "function": "CreateFileW",
                    "args": ["test.txt"],
                    "timestamp": time.time(),
                    "pid": 1234,
                    "tid": 5678,
                },
            }

            framework._on_frida_message(message, None)

            assert callback_executed

    def test_behavioral_analyzer_initializes_with_qemu(self, test_binary: Path) -> None:
        """Verify behavioral analyzer initializes with QEMU components.

        Args:
            test_binary: Test binary fixture.
        """
        analyzer = BehavioralAnalyzer(test_binary)

        assert analyzer.binary_path == test_binary
        assert isinstance(analyzer.qemu_config, QEMUConfig)
        assert isinstance(analyzer.qemu_controller, QEMUController)
        assert isinstance(analyzer.api_hooks, FridaAPIHookingFramework)
        assert analyzer.events == []

    def test_behavioral_analyzer_runs_qemu_analysis(
        self,
        test_binary: Path,
        mock_qemu_process: Mock,
        mock_monitor_socket: Mock,
        mock_qmp_socket: Mock,
    ) -> None:
        """Verify behavioral analyzer runs QEMU analysis correctly.

        Args:
            test_binary: Test binary fixture.
            mock_qemu_process: Mock QEMU process.
            mock_monitor_socket: Mock monitor socket.
            mock_qmp_socket: Mock QMP socket.
        """
        analyzer = BehavioralAnalyzer(test_binary)
        analyzer.qemu_config.disk_image = test_binary.parent / "test_disk.img"
        analyzer.qemu_config.disk_image.write_bytes(b"\x00" * 1024)

        with (
            patch("shutil.which", return_value="/usr/bin/qemu-system-x86_64"),
            patch("subprocess.Popen", return_value=mock_qemu_process),
            patch("socket.socket") as mock_socket,
            patch.object(analyzer.qemu_controller, "_prepare_disk_image"),
        ):
            qmp_socket_called = False

            def socket_side_effect(*args: Any) -> Mock:
                nonlocal qmp_socket_called
                if args == ():
                    return mock_monitor_socket
                elif qmp_socket_called:
                    return mock_qmp_socket
                else:
                    qmp_socket_called = True
                    return mock_monitor_socket

            mock_socket.side_effect = socket_side_effect

            mock_qmp_recv_count = 0

            def qmp_recv(size: int) -> bytes:
                nonlocal mock_qmp_recv_count
                mock_qmp_recv_count += 1
                if mock_qmp_recv_count == 1:
                    return b'{"QMP": {"version": {}}}\n'
                elif mock_qmp_recv_count == 2:
                    return b'{"return": {}}\n'
                elif mock_qmp_recv_count == 3:
                    return b'{"return": {"status": "running"}}\n'
                else:
                    return b'{"return": "success"}\n'

            mock_monitor_socket.recv.return_value = b"(qemu) registers\r\n"
            mock_qmp_socket.recv.side_effect = qmp_recv

            mock_socket_instance = Mock(spec=socket.socket)
            mock_socket_instance.recv = Mock()

            call_count = 0

            def socket_factory(*args: Any, **kwargs: Any) -> Mock:
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    return mock_monitor_socket
                elif call_count == 2:
                    return mock_qmp_socket
                else:
                    return Mock(spec=socket.socket)

            mock_socket.side_effect = socket_factory

            results = analyzer._run_qemu_analysis(duration=1)

            assert results["started"] is True
            assert len(results["snapshots"]) >= 2
            assert "clean_state" in results["snapshots"]
            assert "post_execution" in results["snapshots"]

    def test_behavioral_analyzer_captures_events_during_execution(
        self, test_binary: Path
    ) -> None:
        """Verify behavioral analyzer captures events during execution.

        Args:
            test_binary: Test binary fixture.
        """
        analyzer = BehavioralAnalyzer(test_binary)

        test_event = MonitorEvent(
            timestamp=time.time(),
            event_type="file_read",
            process_id=1234,
            thread_id=5678,
            data={"filename": "test.dat", "size": "1024"},
            context={},
        )

        analyzer.events.append(test_event)

        assert len(analyzer.events) == 1
        assert analyzer.events[0].event_type == "file_read"
        assert analyzer.events[0].data["filename"] == "test.dat"

    def test_monitor_event_to_dict_conversion(self) -> None:
        """Verify MonitorEvent converts to dictionary correctly."""
        event = MonitorEvent(
            timestamp=1234567890.123,
            event_type="registry_set",
            process_id=9876,
            thread_id=4321,
            data={"key": "HKLM\\Software\\Test", "value": "registered"},
            context={"module": "test.exe"},
        )

        event_dict = event.to_dict()

        assert event_dict["timestamp"] == 1234567890.123
        assert event_dict["type"] == "registry_set"
        assert event_dict["pid"] == 9876
        assert event_dict["tid"] == 4321
        assert event_dict["data"]["key"] == "HKLM\\Software\\Test"
        assert event_dict["context"]["module"] == "test.exe"

    def test_qemu_integration_full_workflow(
        self,
        test_binary: Path,
        mock_qemu_process: Mock,
        mock_monitor_socket: Mock,
        mock_qmp_socket: Mock,
    ) -> None:
        """Verify complete QEMU integration workflow from start to finish.

        Args:
            test_binary: Test binary fixture.
            mock_qemu_process: Mock QEMU process.
            mock_monitor_socket: Mock monitor socket.
            mock_qmp_socket: Mock QMP socket.
        """
        analyzer = BehavioralAnalyzer(test_binary)
        analyzer.qemu_config.disk_image = test_binary.parent / "disk.img"
        analyzer.qemu_config.disk_image.write_bytes(b"\x00" * 1024)

        qmp_call_count = 0

        def qmp_recv_workflow(size: int) -> bytes:
            nonlocal qmp_call_count
            qmp_call_count += 1
            if qmp_call_count == 1:
                return b'{"QMP": {"version": {}}}\n'
            elif qmp_call_count == 2:
                return b'{"return": {}}\n'
            elif qmp_call_count == 3:
                return b'{"return": {"status": "running"}}\n'
            else:
                return b'{"return": "snapshot_created"}\n'

        mock_qmp_socket.recv.side_effect = qmp_recv_workflow
        mock_monitor_socket.recv.return_value = b"(qemu) EAX=0x12345678\r\n"

        with (
            patch("shutil.which", return_value="/usr/bin/qemu"),
            patch("subprocess.Popen", return_value=mock_qemu_process),
            patch("socket.socket") as mock_socket,
            patch.object(analyzer.qemu_controller, "_prepare_disk_image"),
        ):
            socket_instances = [mock_monitor_socket, mock_qmp_socket, Mock()]
            mock_socket.side_effect = socket_instances

            started = analyzer.qemu_controller.start(test_binary)
            assert started is True

            snapshot_result = analyzer.qemu_controller.take_snapshot("before_exec")
            assert snapshot_result is True

            monitor_output = analyzer.qemu_controller.send_monitor_command(
                "info registers"
            )
            assert "EAX" in monitor_output

            qmp_response = analyzer.qemu_controller.send_qmp_command(
                {"execute": "query-status"}
            )
            assert isinstance(qmp_response, dict)

            analyzer.qemu_controller.stop()
            assert analyzer.qemu_controller.is_running is False

    def test_api_hooks_remain_operational_after_qemu_integration(self) -> None:
        """Verify API hooks continue working after QEMU integration."""
        with patch("platform.system", return_value="Windows"):
            framework = FridaAPIHookingFramework()

            framework.enable_hook("kernel32.dll", "ReadFile")
            framework.enable_hook("advapi32.dll", "RegQueryValueExW")

            file_read_message = {
                "type": "send",
                "payload": {
                    "type": "api_call",
                    "module": "kernel32.dll",
                    "function": "ReadFile",
                    "args": ["0x1234", "buffer", "1024", "bytes_read"],
                    "timestamp": time.time(),
                    "pid": 8888,
                    "tid": 9999,
                },
            }

            registry_message = {
                "type": "send",
                "payload": {
                    "type": "api_call",
                    "module": "advapi32.dll",
                    "function": "RegQueryValueExW",
                    "args": ["0x5678", "LicenseKey", "0", "type", "buffer"],
                    "timestamp": time.time(),
                    "pid": 8888,
                    "tid": 9999,
                },
            }

            framework._on_frida_message(file_read_message, None)
            framework._on_frida_message(registry_message, None)

            assert len(framework.events) == 2
            assert framework.events[0].event_type == "api_readfile"
            assert framework.events[1].event_type == "api_regqueryvalueexw"

    def test_event_monitoring_captures_license_related_activity(self) -> None:
        """Verify event monitoring captures license-related API calls."""
        with patch("platform.system", return_value="Windows"):
            framework = FridaAPIHookingFramework()

            license_file_message = {
                "type": "send",
                "payload": {
                    "type": "api_call",
                    "module": "kernel32.dll",
                    "function": "CreateFileW",
                    "args": ["C:\\ProgramData\\License.dat", "0x80000000", "0", "0"],
                    "timestamp": time.time(),
                    "pid": 2222,
                    "tid": 3333,
                },
            }

            license_reg_message = {
                "type": "send",
                "payload": {
                    "type": "api_call",
                    "module": "advapi32.dll",
                    "function": "RegOpenKeyExW",
                    "args": [
                        "0x80000002",
                        "SOFTWARE\\Company\\Product\\License",
                        "0",
                        "0xF003F",
                    ],
                    "timestamp": time.time(),
                    "pid": 2222,
                    "tid": 3333,
                },
            }

            framework._on_frida_message(license_file_message, None)
            framework._on_frida_message(license_reg_message, None)

            assert len(framework.events) == 2

            license_events = [e for e in framework.events if "license" in str(e.data).lower()]
            assert len(license_events) == 2
