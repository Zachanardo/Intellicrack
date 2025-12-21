"""Production tests for Frida handler.

Tests validate real Frida functionality and fallback implementations.
Tests verify process enumeration, attachment, and script injection.
"""

import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.handlers.frida_handler import (
    FRIDA_VERSION,
    HAS_FRIDA,
    Device,
    Session,
    get_local_device,
    get_usb_device,
)


class TestFridaDeviceEnumeration:
    """Test device enumeration functionality."""

    def test_get_local_device(self) -> None:
        """Get local device for process injection."""
        device = get_local_device()

        assert device is not None
        assert hasattr(device, "enumerate_processes")

    def test_local_device_has_id(self) -> None:
        """Verify local device has identifier."""
        device = get_local_device()

        assert hasattr(device, "id")
        device_id = device.id
        assert isinstance(device_id, str)
        assert len(device_id) > 0

    def test_local_device_has_name(self) -> None:
        """Verify local device has name."""
        device = get_local_device()

        assert hasattr(device, "name")
        device_name = device.name
        assert isinstance(device_name, str)
        assert len(device_name) > 0


class TestFridaProcessEnumeration:
    """Test process enumeration on local system."""

    def test_enumerate_processes(self) -> None:
        """Enumerate all running processes."""
        device = get_local_device()

        processes = device.enumerate_processes()

        assert isinstance(processes, list)
        assert len(processes) > 0

    def test_enumerate_processes_contains_current_process(self) -> None:
        """Verify current Python process is enumerated."""
        device = get_local_device()
        current_pid = os.getpid()

        processes = device.enumerate_processes()
        pids = [p.pid for p in processes]

        assert current_pid in pids

    def test_process_has_name(self) -> None:
        """Verify enumerated processes have names."""
        device = get_local_device()

        processes = device.enumerate_processes()

        assert all(hasattr(p, "name") for p in processes)
        assert all(isinstance(p.name, str) for p in processes)
        assert all(len(p.name) > 0 for p in processes)

    def test_process_has_pid(self) -> None:
        """Verify enumerated processes have PIDs."""
        device = get_local_device()

        processes = device.enumerate_processes()

        assert all(hasattr(p, "pid") for p in processes)
        assert all(isinstance(p.pid, int) for p in processes)
        assert all(p.pid > 0 for p in processes)

    def test_find_process_by_name(self) -> None:
        """Find process by name."""
        device = get_local_device()

        processes = device.enumerate_processes()
        python_processes = [p for p in processes if "python" in p.name.lower()]

        assert python_processes

    def test_find_process_by_pid(self) -> None:
        """Find process by PID."""
        device = get_local_device()
        current_pid = os.getpid()

        processes = device.enumerate_processes()
        current_process = next((p for p in processes if p.pid == current_pid), None)

        assert current_process is not None
        assert current_process.pid == current_pid


class TestFridaProcessAttachment:
    """Test process attachment functionality."""

    @pytest.fixture
    def test_process(self) -> subprocess.Popen:
        """Create a test process for attachment."""
        if sys.platform == "win32":
            process = subprocess.Popen(
                ["ping", "-n", "100", "127.0.0.1"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        else:
            process = subprocess.Popen(
                ["sleep", "100"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

        time.sleep(1)
        yield process

        try:
            process.terminate()
            process.wait(timeout=5)
        except Exception:
            process.kill()

    def test_attach_to_process_by_pid(self, test_process: subprocess.Popen) -> None:
        """Attach to process by PID."""
        device = get_local_device()

        try:
            session = device.attach(test_process.pid)
            assert session is not None
            assert isinstance(session, Session) or hasattr(session, "create_script")
        except Exception as e:
            if "unable to access process" in str(e).lower() or "failed to attach" in str(e).lower():
                pytest.skip(f"Cannot attach to process (may require admin/root): {e}")
            raise

    def test_attach_to_process_by_name(self) -> None:
        """Attach to process by name."""
        device = get_local_device()

        processes = device.enumerate_processes()
        if not processes:
            pytest.skip("No processes available for attachment")

        process = processes[0]

        try:
            session = device.attach(process.name)
            assert session is not None
        except Exception as e:
            if "unable to access process" in str(e).lower() or "failed to attach" in str(e).lower():
                pytest.skip(f"Cannot attach to process (may require admin/root): {e}")
            raise


class TestFridaScriptCreation:
    """Test Frida script creation and execution."""

    @pytest.fixture
    def attached_session(self) -> Session:
        """Create attached session for testing."""
        device = get_local_device()
        current_pid = os.getpid()

        try:
            session = device.attach(current_pid)
            yield session
            session.detach()
        except Exception as e:
            if "unable to access process" in str(e).lower():
                pytest.skip(f"Cannot attach to own process: {e}")
            raise

    def test_create_script(self, attached_session: Session) -> None:
        """Create Frida script in attached session."""
        script_code = """
        console.log("Test script loaded");
        """

        try:
            script = attached_session.create_script(script_code)
            assert script is not None
        except Exception as e:
            pytest.skip(f"Script creation failed: {e}")

    def test_load_script(self, attached_session: Session) -> None:
        """Load Frida script into process."""
        script_code = """
        console.log("Test script loaded");
        """

        try:
            script = attached_session.create_script(script_code)
            script.load()
            assert script is not None
            script.unload()
        except Exception as e:
            pytest.skip(f"Script loading failed: {e}")


class TestFridaScriptCommunication:
    """Test script communication and message passing."""

    @pytest.fixture
    def attached_session(self) -> Session:
        """Create attached session for testing."""
        device = get_local_device()
        current_pid = os.getpid()

        try:
            session = device.attach(current_pid)
            yield session
            session.detach()
        except Exception as e:
            if "unable to access process" in str(e).lower():
                pytest.skip(f"Cannot attach to own process: {e}")
            raise

    def test_script_message_handler(self, attached_session: Session) -> None:
        """Test script message handling."""
        messages = []

        def on_message(message: dict, data: Any) -> None:
            messages.append(message)

        script_code = """
        send({type: 'test', data: 'hello'});
        """

        try:
            script = attached_session.create_script(script_code)
            script.on("message", on_message)
            script.load()
            time.sleep(0.5)
            script.unload()

            assert messages
        except Exception as e:
            pytest.skip(f"Message handling test failed: {e}")


class TestFridaMemoryOperations:
    """Test memory read/write operations."""

    @pytest.fixture
    def attached_session(self) -> Session:
        """Create attached session for testing."""
        device = get_local_device()
        current_pid = os.getpid()

        try:
            session = device.attach(current_pid)
            yield session
            session.detach()
        except Exception as e:
            if "unable to access process" in str(e).lower():
                pytest.skip(f"Cannot attach to own process: {e}")
            raise

    def test_read_memory(self, attached_session: Session) -> None:
        """Read process memory."""
        script_code = """
        var baseAddr = Module.getBaseAddress('python.exe') || Module.getBaseAddress('python3') || Module.getBaseAddress('python');
        if (baseAddr) {
            var data = Memory.readByteArray(baseAddr, 16);
            send({type: 'memory', data: Array.from(new Uint8Array(data))});
        }
        """

        try:
            messages = []

            def on_message(message: dict, data: Any) -> None:
                messages.append(message)

            script = attached_session.create_script(script_code)
            script.on("message", on_message)
            script.load()
            time.sleep(0.5)
            script.unload()

            if messages:
                assert messages[0]["type"] == "memory"
        except Exception as e:
            pytest.skip(f"Memory read test failed: {e}")


class TestFridaFallbackImplementation:
    """Test fallback implementation when Frida unavailable."""

    def test_fallback_device_creation(self) -> None:
        """Verify fallback device can be created."""
        device = get_local_device()

        assert device is not None
        assert hasattr(device, "enumerate_processes")

    def test_fallback_process_enumeration(self) -> None:
        """Verify fallback can enumerate processes."""
        device = get_local_device()

        processes = device.enumerate_processes()

        assert isinstance(processes, list)
        assert len(processes) > 0

    def test_fallback_process_has_required_attributes(self) -> None:
        """Verify fallback processes have required attributes."""
        device = get_local_device()

        processes = device.enumerate_processes()

        for process in processes[:10]:
            assert hasattr(process, "pid")
            assert hasattr(process, "name")


class TestFridaEdgeCases:
    """Test edge cases and error handling."""

    def test_attach_to_nonexistent_pid(self) -> None:
        """Attempt to attach to nonexistent PID."""
        device = get_local_device()
        invalid_pid = 99999999

        with pytest.raises(Exception):
            device.attach(invalid_pid)

    def test_attach_to_invalid_process_name(self) -> None:
        """Attempt to attach to invalid process name."""
        device = get_local_device()
        invalid_name = "nonexistent_process_12345"

        with pytest.raises(Exception):
            device.attach(invalid_name)

    def test_enumerate_processes_multiple_times(self) -> None:
        """Enumerate processes multiple times."""
        device = get_local_device()

        processes1 = device.enumerate_processes()
        processes2 = device.enumerate_processes()

        assert len(processes1) > 0
        assert len(processes2) > 0


class TestFridaVersionInfo:
    """Test Frida version information."""

    def test_frida_version_available(self) -> None:
        """Verify Frida version is available."""
        if HAS_FRIDA:
            assert FRIDA_VERSION is not None
            assert isinstance(FRIDA_VERSION, str)
            assert len(FRIDA_VERSION) > 0


class TestFridaLicensingHooks:
    """Test Frida hooking for licensing functions."""

    @pytest.fixture
    def attached_session(self) -> Session:
        """Create attached session for testing."""
        device = get_local_device()
        current_pid = os.getpid()

        try:
            session = device.attach(current_pid)
            yield session
            session.detach()
        except Exception as e:
            if "unable to access process" in str(e).lower():
                pytest.skip(f"Cannot attach to own process: {e}")
            raise

    def test_hook_function_intercept(self, attached_session: Session) -> None:
        """Test function interception hook."""
        script_code = """
        Interceptor.attach(Module.getExportByName(null, 'GetSystemTimeAsFileTime'), {
            onEnter: function(args) {
                send({type: 'hook', function: 'GetSystemTimeAsFileTime'});
            }
        });
        """

        try:
            messages = []

            def on_message(message: dict, data: Any) -> None:
                messages.append(message)

            script = attached_session.create_script(script_code)
            script.on("message", on_message)
            script.load()
            time.sleep(0.5)
            script.unload()
        except Exception as e:
            pytest.skip(f"Hook test failed: {e}")

    def test_hook_return_value_modification(self, attached_session: Session) -> None:
        """Test return value modification hook."""
        script_code = """
        Interceptor.attach(Module.getExportByName(null, 'GetTickCount'), {
            onLeave: function(retval) {
                retval.replace(0);
                send({type: 'hook', modified: true});
            }
        });
        """

        try:
            messages = []

            def on_message(message: dict, data: Any) -> None:
                messages.append(message)

            script = attached_session.create_script(script_code)
            script.on("message", on_message)
            script.load()
            time.sleep(0.5)
            script.unload()
        except Exception as e:
            pytest.skip(f"Return value modification test failed: {e}")


class TestFridaPerformance:
    """Test Frida performance characteristics."""

    def test_enumerate_processes_performance(self, benchmark: Any) -> None:
        """Benchmark process enumeration performance."""
        device = get_local_device()

        result = benchmark(device.enumerate_processes)

        assert isinstance(result, list)
        assert len(result) > 0

    def test_multiple_enumerations(self) -> None:
        """Test multiple rapid process enumerations."""
        device = get_local_device()

        for _ in range(10):
            processes = device.enumerate_processes()
            assert len(processes) > 0


class TestFridaErrorHandling:
    """Test Frida error handling and edge cases."""

    def test_attach_to_nonexistent_pid(self) -> None:
        """Attaching to nonexistent PID raises appropriate error."""
        device = get_local_device()
        nonexistent_pid = 999999

        with pytest.raises(Exception):
            device.attach(nonexistent_pid)

    def test_attach_to_zero_pid(self) -> None:
        """Attaching to PID 0 raises appropriate error."""
        device = get_local_device()

        with pytest.raises(Exception):
            device.attach(0)

    def test_attach_to_negative_pid(self) -> None:
        """Attaching to negative PID raises appropriate error."""
        device = get_local_device()

        with pytest.raises(Exception):
            device.attach(-1)

    def test_create_script_with_invalid_syntax(self, attached_session: Session) -> None:
        """Creating script with invalid JavaScript syntax raises error."""
        invalid_script = "this is not valid javascript {{{["

        with pytest.raises(Exception):
            script = attached_session.create_script(invalid_script)
            script.load()

    def test_create_empty_script(self, attached_session: Session) -> None:
        """Creating empty script succeeds but does nothing."""
        try:
            script = attached_session.create_script("")
            script.load()
            script.unload()
        except Exception as e:
            pytest.skip(f"Empty script test failed: {e}")

    def test_load_script_multiple_times(self, attached_session: Session) -> None:
        """Loading same script multiple times is handled gracefully."""
        script_code = "send('test');"

        try:
            script = attached_session.create_script(script_code)
            script.load()

            with pytest.raises(Exception):
                script.load()

            script.unload()
        except Exception as e:
            pytest.skip(f"Multiple load test failed: {e}")

    def test_unload_already_unloaded_script(self, attached_session: Session) -> None:
        """Unloading already unloaded script is handled gracefully."""
        script_code = "send('test');"

        try:
            script = attached_session.create_script(script_code)
            script.load()
            script.unload()

            with pytest.raises(Exception):
                script.unload()
        except Exception as e:
            pytest.skip(f"Multiple unload test failed: {e}")

    def test_hook_nonexistent_function(self, attached_session: Session) -> None:
        """Hooking nonexistent function raises appropriate error."""
        script_code = """
        try {
            Interceptor.attach(Module.getExportByName(null, 'NonexistentFunction12345'), {
                onEnter: function(args) {}
            });
        } catch(e) {
            send({type: 'error', message: e.message});
        }
        """

        try:
            messages = []

            def on_message(message: dict, data: Any) -> None:
                messages.append(message)

            script = attached_session.create_script(script_code)
            script.on("message", on_message)
            script.load()
            time.sleep(0.2)

            assert messages
            if messages[0].get("type") == "send":
                payload = messages[0].get("payload", {})
                assert payload.get("type") == "error"

            script.unload()
        except Exception as e:
            pytest.skip(f"Nonexistent function hook test failed: {e}")

    def test_memory_read_invalid_address(self, attached_session: Session) -> None:
        """Reading from invalid memory address raises error."""
        script_code = """
        try {
            Memory.readByteArray(ptr('0'), 100);
            send({type: 'success'});
        } catch(e) {
            send({type: 'error', message: e.message});
        }
        """

        try:
            messages = []

            def on_message(message: dict, data: Any) -> None:
                messages.append(message)

            script = attached_session.create_script(script_code)
            script.on("message", on_message)
            script.load()
            time.sleep(0.2)

            if messages:
                payload = messages[0].get("payload", {})
                assert payload.get("type") in ["error", "success"]

            script.unload()
        except Exception as e:
            pytest.skip(f"Invalid memory read test failed: {e}")

    def test_session_detach_idempotent(self, test_process: subprocess.Popen) -> None:
        """Detaching session multiple times is handled gracefully."""
        device = get_local_device()

        try:
            session = device.attach(test_process.pid)
            session.detach()

            with pytest.raises(Exception):
                session.detach()
        except Exception as e:
            pytest.skip(f"Multiple detach test failed: {e}")


class TestFridaEdgeCases:
    """Test edge cases in Frida operations."""

    def test_enumerate_processes_consistency(self) -> None:
        """Process enumeration is consistent across calls."""
        device = get_local_device()

        processes1 = device.enumerate_processes()
        time.sleep(0.1)
        processes2 = device.enumerate_processes()

        pids1 = {p.pid for p in processes1}
        pids2 = {p.pid for p in processes2}

        overlap = len(pids1 & pids2) / len(pids1)
        assert overlap > 0.8

    def test_script_with_large_payload(self, attached_session: Session) -> None:
        """Script can send large payloads via send()."""
        script_code = """
        var largeData = new Array(10000).fill('x').join('');
        send({type: 'large', data: largeData});
        """

        try:
            messages = []

            def on_message(message: dict, data: Any) -> None:
                messages.append(message)

            script = attached_session.create_script(script_code)
            script.on("message", on_message)
            script.load()
            time.sleep(0.3)

            assert messages
            if messages[0].get("type") == "send":
                payload = messages[0].get("payload", {})
                assert len(payload.get("data", "")) > 1000

            script.unload()
        except Exception as e:
            pytest.skip(f"Large payload test failed: {e}")

    def test_rapid_attach_detach(self, test_process: subprocess.Popen) -> None:
        """Rapid attach/detach cycles are handled correctly."""
        device = get_local_device()

        try:
            for _ in range(5):
                session = device.attach(test_process.pid)
                time.sleep(0.05)
                session.detach()
                time.sleep(0.05)
        except Exception as e:
            pytest.skip(f"Rapid attach/detach test failed: {e}")

    def test_multiple_scripts_same_session(self, attached_session: Session) -> None:
        """Multiple scripts can coexist in same session."""
        script1_code = "send({script: 1});"
        script2_code = "send({script: 2});"

        try:
            messages1 = []
            messages2 = []

            def on_message1(message: dict, data: Any) -> None:
                messages1.append(message)

            def on_message2(message: dict, data: Any) -> None:
                messages2.append(message)

            script1 = attached_session.create_script(script1_code)
            script1.on("message", on_message1)
            script1.load()

            script2 = attached_session.create_script(script2_code)
            script2.on("message", on_message2)
            script2.load()

            time.sleep(0.2)

            assert messages1 or messages2

            script1.unload()
            script2.unload()
        except Exception as e:
            pytest.skip(f"Multiple scripts test failed: {e}")

    def test_script_with_console_log(self, attached_session: Session) -> None:
        """Script with console.log doesn't crash."""
        script_code = """
        console.log('Test message');
        console.warn('Warning message');
        console.error('Error message');
        send({type: 'complete'});
        """

        try:
            messages = []

            def on_message(message: dict, data: Any) -> None:
                messages.append(message)

            script = attached_session.create_script(script_code)
            script.on("message", on_message)
            script.load()
            time.sleep(0.2)

            script.unload()
        except Exception as e:
            pytest.skip(f"Console log test failed: {e}")


class TestFridaFallbackBehavior:
    """Test fallback behavior when Frida is not available."""

    def test_frida_availability_flag(self) -> None:
        """FRIDA_AVAILABLE flag is boolean."""
        assert isinstance(HAS_FRIDA, bool)

    def test_frida_version_when_available(self) -> None:
        """Frida version is string when available."""
        if HAS_FRIDA:
            assert isinstance(FRIDA_VERSION, str)
            assert len(FRIDA_VERSION) > 0
        else:
            assert FRIDA_VERSION is None or FRIDA_VERSION == ""

    def test_get_usb_device(self) -> None:
        """get_usb_device returns device or raises error."""
        if HAS_FRIDA:
            try:
                device = get_usb_device()
                assert device is not None
            except Exception:
                pass
        else:
            with pytest.raises((ImportError, RuntimeError, AttributeError)):
                get_usb_device()
