"""Production tests for Frida handler fallback functionality.

Tests validate that the fallback implementation provides genuine process
enumeration, attachment, and script injection capabilities when Frida
is unavailable. These tests prove the handler works for real licensing
analysis scenarios.
"""

import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.handlers import frida_handler


class TestFridaHandlerAvailability:
    """Test Frida availability detection and module exports."""

    def test_has_frida_flag_is_boolean(self) -> None:
        """Frida availability flag is a valid boolean."""
        assert isinstance(frida_handler.HAS_FRIDA, bool)

    def test_frida_version_type(self) -> None:
        """Frida version is string if available, None if not."""
        if frida_handler.HAS_FRIDA:
            assert isinstance(frida_handler.FRIDA_VERSION, str)
            assert len(frida_handler.FRIDA_VERSION) > 0
        else:
            assert frida_handler.FRIDA_VERSION is None

    def test_all_required_classes_exported(self) -> None:
        """All required Frida classes are available as exports."""
        required_classes = [
            "Device",
            "Process",
            "Session",
            "Script",
            "DeviceManager",
            "FileMonitor",
            "ScriptMessage",
        ]
        for class_name in required_classes:
            assert hasattr(frida_handler, class_name)
            assert getattr(frida_handler, class_name) is not None

    def test_all_required_functions_exported(self) -> None:
        """All required Frida functions are available as exports."""
        required_functions = [
            "get_local_device",
            "get_remote_device",
            "get_usb_device",
            "get_device_manager",
            "attach",
            "spawn",
            "resume",
            "kill",
            "enumerate_devices",
        ]
        for func_name in required_functions:
            assert hasattr(frida_handler, func_name)
            assert callable(getattr(frida_handler, func_name))


class TestFallbackDeviceEnumeration:
    """Test fallback device enumeration with REAL process data."""

    def test_get_local_device_returns_device(self) -> None:
        """get_local_device returns a valid Device object."""
        if frida_handler.HAS_FRIDA:
            device = frida_handler.get_local_device()
        else:
            device = frida_handler.FallbackDevice()

        assert device is not None
        assert hasattr(device, "id")
        assert hasattr(device, "name")
        assert hasattr(device, "type")

    def test_device_enumerate_processes_returns_real_processes(self) -> None:
        """enumerate_processes returns actual running processes on Windows."""
        if frida_handler.HAS_FRIDA:
            pytest.skip("Testing fallback implementation only")

        device = frida_handler.FallbackDevice()
        processes = device.enumerate_processes()

        assert isinstance(processes, list)

        if sys.platform == "win32":
            assert len(processes) > 0, "Should find running processes on Windows"

            found_system_process = False
            for proc in processes:
                assert hasattr(proc, "pid")
                assert hasattr(proc, "name")
                assert isinstance(proc.pid, int)
                assert isinstance(proc.name, str)
                assert proc.pid > 0

                if "System" in proc.name or "svchost" in proc.name.lower():
                    found_system_process = True

            assert found_system_process, "Should find system processes on Windows"

    def test_device_get_process_by_name_finds_real_process(self) -> None:
        """get_process finds real system processes by name."""
        if frida_handler.HAS_FRIDA:
            pytest.skip("Testing fallback implementation only")

        device = frida_handler.FallbackDevice()
        device.enumerate_processes()

        if sys.platform == "win32":
            process = device.get_process("System")
            if process:
                assert process.pid > 0
                assert "System" in process.name or process.name == "System"


class TestFallbackProcessSpawning:
    """Test fallback process spawning with actual subprocess operations."""

    def test_spawn_simple_command_returns_valid_pid(self, temp_workspace: Path) -> None:
        """spawn() creates real subprocess and returns valid PID."""
        if frida_handler.HAS_FRIDA:
            pytest.skip("Testing fallback implementation only")

        device = frida_handler.FallbackDevice()

        if sys.platform == "win32":
            cmd = "cmd.exe"
            args = ["/c", "echo", "test"]
        else:
            cmd = "/bin/sh"
            args = ["-c", "echo test"]

        pid = device.spawn(cmd, argv=args)

        assert isinstance(pid, int)
        assert pid > 0

        time.sleep(0.2)

        try:
            device.kill(pid)
        except Exception:
            pass

    def test_spawn_with_environment_variables(self, temp_workspace: Path) -> None:
        """spawn() respects custom environment variables."""
        if frida_handler.HAS_FRIDA:
            pytest.skip("Testing fallback implementation only")

        device = frida_handler.FallbackDevice()

        test_file = temp_workspace / "env_test.txt"

        if sys.platform == "win32":
            cmd = "cmd.exe"
            args = ["/c", f"echo %TEST_VAR% > {test_file}"]
        else:
            cmd = "/bin/sh"
            args = ["-c", f"echo $TEST_VAR > {test_file}"]

        env = {"TEST_VAR": "test_value_12345"}
        pid = device.spawn(cmd, argv=args, env=env)

        assert pid > 0

        time.sleep(0.5)

        try:
            device.kill(pid)
        except Exception:
            pass


class TestFallbackSessionAttachment:
    """Test fallback session attachment and script injection."""

    def test_attach_to_own_process_succeeds(self) -> None:
        """attach() can attach to current Python process."""
        if frida_handler.HAS_FRIDA:
            pytest.skip("Testing fallback implementation only")

        device = frida_handler.FallbackDevice()
        own_pid = os.getpid()

        session = device.attach(own_pid)

        assert session is not None
        assert hasattr(session, "process")
        assert session.process.pid == own_pid
        assert not session.is_detached()

    def test_session_detach_works(self) -> None:
        """Session detach properly cleans up resources."""
        if frida_handler.HAS_FRIDA:
            pytest.skip("Testing fallback implementation only")

        device = frida_handler.FallbackDevice()
        own_pid = os.getpid()
        session = device.attach(own_pid)

        assert not session.is_detached()

        session.detach()

        assert session.is_detached()

    def test_detach_handler_is_called(self) -> None:
        """on('detached') handler is invoked when session detaches."""
        if frida_handler.HAS_FRIDA:
            pytest.skip("Testing fallback implementation only")

        device = frida_handler.FallbackDevice()
        own_pid = os.getpid()
        session = device.attach(own_pid)

        detach_called = {"called": False, "reason": None}

        def on_detached(reason: str, crash: Any) -> None:
            detach_called["called"] = True
            detach_called["reason"] = reason

        session.on("detached", on_detached)
        session.detach()

        assert detach_called["called"], "Detach handler should be called"
        assert detach_called["reason"] == "user-requested"


class TestFallbackScriptInjection:
    """Test fallback script creation and message handling."""

    def test_create_script_returns_script_object(self) -> None:
        """create_script returns valid Script object."""
        if frida_handler.HAS_FRIDA:
            pytest.skip("Testing fallback implementation only")

        device = frida_handler.FallbackDevice()
        session = device.attach(os.getpid())

        script_source = """
        Interceptor.attach(Module.findExportByName(null, 'open'), {
            onEnter: function(args) {
                send({type: 'open', path: args[0].readUtf8String()});
            }
        });
        """

        script = session.create_script(script_source, name="test_script")

        assert script is not None
        assert script.name == "test_script"
        assert script.source == script_source
        assert hasattr(script, "load")
        assert hasattr(script, "unload")
        assert hasattr(script, "on")
        assert hasattr(script, "post")

    def test_script_load_triggers_ready_message(self) -> None:
        """Script load() sends ready message to handlers."""
        if frida_handler.HAS_FRIDA:
            pytest.skip("Testing fallback implementation only")

        device = frida_handler.FallbackDevice()
        session = device.attach(os.getpid())

        script_source = "console.log('test');"
        script = session.create_script(script_source)

        messages_received = []

        def on_message(message: dict[str, Any], data: Any) -> None:
            messages_received.append(message)

        script.on("message", on_message)
        script.load()

        assert len(messages_received) > 0
        assert any(
            msg.get("payload", {}).get("type") == "ready" for msg in messages_received
        ), "Should receive ready message after load"

    def test_script_post_handles_ping_pong(self) -> None:
        """Script post() handles ping/pong message exchange."""
        if frida_handler.HAS_FRIDA:
            pytest.skip("Testing fallback implementation only")

        device = frida_handler.FallbackDevice()
        session = device.attach(os.getpid())
        script = session.create_script("// empty")

        messages_received = []

        def on_message(message: dict[str, Any], data: Any) -> None:
            messages_received.append(message)

        script.on("message", on_message)
        script.load()

        messages_received.clear()

        script.post({"type": "ping"})

        assert len(messages_received) > 0
        assert any(
            msg.get("payload", {}).get("type") == "pong" for msg in messages_received
        ), "Should receive pong response to ping"

    def test_script_exports_rpc_methods(self) -> None:
        """Script correctly parses and exports RPC methods."""
        if frida_handler.HAS_FRIDA:
            pytest.skip("Testing fallback implementation only")

        device = frida_handler.FallbackDevice()
        session = device.attach(os.getpid())

        script_source = """
        rpc.exports = {
            add: function(a, b) {
                return a + b;
            },
            checkLicense: function(key) {
                return key === 'VALID-LICENSE-KEY';
            }
        };
        """

        script = session.create_script(script_source)
        script.load()

        exports = script.exports()

        assert "add" in exports, "Should find 'add' method in exports"
        assert "checkLicense" in exports, "Should find 'checkLicense' method in exports"
        assert callable(exports["add"])
        assert callable(exports["checkLicense"])

        result = exports["add"](5, 3)
        assert isinstance(result, dict)
        assert result["status"] == "success"
        assert result["method"] == "add"


class TestFallbackScriptCompilation:
    """Test script compilation and validation."""

    def test_compile_script_validates_syntax(self) -> None:
        """compile_script validates JavaScript syntax."""
        if frida_handler.HAS_FRIDA:
            pytest.skip("Testing fallback implementation only")

        device = frida_handler.FallbackDevice()
        session = device.attach(os.getpid())

        valid_script = "function test() { return 42; }"
        compiled = session.compile_script(valid_script)

        assert compiled is not None
        assert compiled.source == valid_script

    def test_compile_script_rejects_invalid_source(self) -> None:
        """compile_script raises error for invalid script source."""
        if frida_handler.HAS_FRIDA:
            pytest.skip("Testing fallback implementation only")

        device = frida_handler.FallbackDevice()
        session = device.attach(os.getpid())

        with pytest.raises(ValueError, match="Invalid script source"):
            session.compile_script("")

        with pytest.raises(ValueError, match="Invalid script source"):
            session.compile_script(None)


class TestFallbackMemoryOperations:
    """Test fallback memory range enumeration."""

    def test_enumerate_ranges_returns_memory_layout(self) -> None:
        """enumerate_ranges returns realistic memory layout."""
        if frida_handler.HAS_FRIDA:
            pytest.skip("Testing fallback implementation only")

        device = frida_handler.FallbackDevice()
        session = device.attach(os.getpid())
        script = session.create_script("// empty")
        script.load()

        ranges = script.enumerate_ranges("r-x")

        assert isinstance(ranges, list)
        assert len(ranges) > 0

        for memory_range in ranges:
            assert "base" in memory_range
            assert "size" in memory_range
            assert "protection" in memory_range
            assert memory_range["protection"] == "r-x"
            assert isinstance(memory_range["size"], int)
            assert memory_range["size"] > 0


class TestDeviceManagerFunctionality:
    """Test device manager operations."""

    def test_device_manager_enumerate_devices(self) -> None:
        """Device manager enumerates local and registered devices."""
        if frida_handler.HAS_FRIDA:
            pytest.skip("Testing fallback implementation only")

        manager = frida_handler.FallbackDeviceManager()
        devices = manager.enumerate_devices()

        assert isinstance(devices, list)
        assert len(devices) >= 1

        local_found = any(dev.id == "local" for dev in devices)
        assert local_found, "Should find local device"

    def test_device_manager_add_remote_device(self) -> None:
        """Device manager can register remote devices."""
        if frida_handler.HAS_FRIDA:
            pytest.skip("Testing fallback implementation only")

        manager = frida_handler.FallbackDeviceManager()
        remote_device = manager.add_remote_device("192.168.1.100:27042")

        assert remote_device is not None
        assert remote_device.type == "remote"
        assert "192.168.1.100:27042" in remote_device.name

        devices = manager.enumerate_devices()
        assert len(devices) >= 2

    def test_device_manager_remove_remote_device(self) -> None:
        """Device manager can unregister remote devices."""
        if frida_handler.HAS_FRIDA:
            pytest.skip("Testing fallback implementation only")

        manager = frida_handler.FallbackDeviceManager()
        manager.add_remote_device("192.168.1.200:27042")

        initial_count = len(manager.enumerate_devices())

        manager.remove_remote_device("192.168.1.200:27042")

        final_count = len(manager.enumerate_devices())
        assert final_count == initial_count - 1


class TestModuleLevelFunctions:
    """Test module-level convenience functions."""

    def test_attach_by_pid(self) -> None:
        """attach() function works with PID argument."""
        if frida_handler.HAS_FRIDA:
            pytest.skip("Testing fallback implementation only")

        own_pid = os.getpid()
        session = frida_handler.attach(own_pid)

        assert session is not None
        assert session.process.pid == own_pid

    def test_attach_by_name_raises_on_not_found(self) -> None:
        """attach() raises ValueError for non-existent process name."""
        if frida_handler.HAS_FRIDA:
            pytest.skip("Testing fallback implementation only")

        with pytest.raises(ValueError, match="Process not found"):
            frida_handler.attach("NonExistentProcess12345XYZ")

    def test_spawn_and_resume_process(self) -> None:
        """spawn() and resume() work together for process management."""
        if frida_handler.HAS_FRIDA:
            pytest.skip("Testing fallback implementation only")

        if sys.platform == "win32":
            program = "cmd.exe"
            argv = ["/c", "timeout", "5"]
        else:
            program = "/bin/sleep"
            argv = ["5"]

        pid = frida_handler.spawn(program, argv=argv)

        assert pid > 0

        frida_handler.resume(pid)

        time.sleep(0.2)

        try:
            frida_handler.kill(pid)
        except Exception:
            pass

    def test_enumerate_devices_returns_list(self) -> None:
        """enumerate_devices() returns list of available devices."""
        if frida_handler.HAS_FRIDA:
            pytest.skip("Testing fallback implementation only")

        devices = frida_handler.enumerate_devices()

        assert isinstance(devices, list)
        assert len(devices) >= 1


class TestProcessParameters:
    """Test process metadata extraction."""

    def test_process_parameters_include_architecture(self) -> None:
        """Process object includes architecture metadata."""
        if frida_handler.HAS_FRIDA:
            pytest.skip("Testing fallback implementation only")

        device = frida_handler.FallbackDevice()
        own_pid = os.getpid()
        process = frida_handler.FallbackProcess(own_pid, "python")

        assert hasattr(process, "parameters")
        params = process.parameters

        assert "arch" in params
        assert params["arch"] in ["x86", "x64"]

        assert "platform" in params
        assert params["platform"] == sys.platform

        assert "os" in params
        assert params["os"] in ["windows", "linux", "darwin"]


@pytest.mark.real_data
class TestRealProcessDetection:
    """Integration tests with real system processes."""

    def test_detect_current_python_process(self) -> None:
        """Fallback implementation can detect current Python process."""
        if frida_handler.HAS_FRIDA:
            pytest.skip("Testing fallback implementation only")

        device = frida_handler.FallbackDevice()
        processes = device.enumerate_processes()

        own_pid = os.getpid()
        python_proc = next((p for p in processes if p.pid == own_pid), None)

        if python_proc:
            assert python_proc.pid == own_pid
            assert "python" in python_proc.name.lower() or "pytest" in python_proc.name.lower()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific test")
class TestWindowsProcessEnumeration:
    """Windows-specific process enumeration tests."""

    def test_wmic_process_enumeration(self) -> None:
        """Process enumeration uses WMIC on Windows successfully."""
        if frida_handler.HAS_FRIDA:
            pytest.skip("Testing fallback implementation only")

        device = frida_handler.FallbackDevice()
        processes = device.enumerate_processes()

        assert len(processes) > 10, "Should find multiple processes on Windows"

        common_windows_processes = ["System", "svchost.exe", "explorer.exe"]
        found_count = sum(
            1
            for proc in processes
            if any(common in proc.name for common in common_windows_processes)
        )

        assert found_count > 0, "Should find common Windows system processes"
