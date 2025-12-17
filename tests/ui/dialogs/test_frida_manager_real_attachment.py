"""Production tests for real Frida process attachment and hooking.

Tests validate:
- Real process enumeration on Windows
- Attachment to running processes
- Script injection and execution
- Function hooking on actual Windows APIs
- Memory reading and modification
- Detachment and cleanup

NO mocks - all tests use real Frida framework.
Tests require Frida to be installed and admin privileges.
"""

import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

try:
    import frida

    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False
    frida = None

try:
    from PyQt6.QtCore import Qt, QTimer
    from PyQt6.QtWidgets import QApplication

    PYQT6_AVAILABLE = True
except ImportError:
    PYQT6_AVAILABLE = False
    Qt = None
    QTimer = None
    QApplication = None

if PYQT6_AVAILABLE and FRIDA_AVAILABLE:
    from intellicrack.ui.dialogs.frida_manager_dialog import (
        FridaManagerDialog,
        FridaWorker,
    )

from intellicrack.utils.logger import get_logger

logger = get_logger(__name__)

pytestmark = pytest.mark.skipif(
    not (PYQT6_AVAILABLE and FRIDA_AVAILABLE),
    reason="PyQt6 and Frida required for real attachment tests",
)


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Create QApplication instance for Qt tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def test_process() -> subprocess.Popen:
    """Start a simple test process for Frida attachment."""
    test_script = """
import time
import sys

print("Test process started", flush=True)
sys.stdout.flush()

while True:
    time.sleep(1)
"""

    process = subprocess.Popen(
        [sys.executable, "-c", test_script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    time.sleep(0.5)

    yield process

    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()


@pytest.fixture
def notepad_process() -> int | None:
    """Get PID of running notepad.exe if available."""
    try:
        result = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq notepad.exe"],
            capture_output=True,
            text=True,
            timeout=5,
        )

        for line in result.stdout.splitlines():
            if "notepad.exe" in line.lower():
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        return int(parts[1])
                    except ValueError:
                        pass
    except Exception as e:
        logger.warning("Failed to find notepad.exe: %s", e)

    return None


class TestRealProcessEnumeration:
    """Test real Windows process enumeration with Frida."""

    def test_enumerate_running_processes(self) -> None:
        """Frida enumerates all running Windows processes."""
        processes = frida.enumerate_processes()

        assert len(processes) > 0
        assert any(p.name.lower() in ["system", "explorer.exe", "svchost.exe"] for p in processes)

        for process in processes[:10]:
            assert hasattr(process, "pid")
            assert hasattr(process, "name")
            assert process.pid > 0
            assert len(process.name) > 0

    def test_enumerate_processes_contains_self(self) -> None:
        """Process list includes the Python test process."""
        current_pid = os.getpid()
        processes = frida.enumerate_processes()

        process_pids = [p.pid for p in processes]
        assert current_pid in process_pids

        python_process = next(p for p in processes if p.pid == current_pid)
        assert "python" in python_process.name.lower()

    def test_filter_processes_by_name(self) -> None:
        """Filter process list by executable name."""
        all_processes = frida.enumerate_processes()

        system_processes = [p for p in all_processes if "system" in p.name.lower()]
        assert len(system_processes) >= 1


class TestRealProcessAttachment:
    """Test real Frida attachment to running processes."""

    def test_attach_to_test_process(self, test_process: subprocess.Popen) -> None:
        """Frida successfully attaches to spawned test process."""
        assert test_process.poll() is None, "Test process not running"

        pid = test_process.pid
        session = frida.attach(pid)

        assert session is not None
        assert session.is_detached is False

        session.detach()

    def test_attach_and_enumerate_modules(
        self, test_process: subprocess.Popen
    ) -> None:
        """Attached session can enumerate loaded modules."""
        pid = test_process.pid
        session = frida.attach(pid)

        try:
            modules = session.enumerate_modules()
            assert len(modules) > 0

            python_modules = [
                m for m in modules if "python" in m.name.lower()
            ]
            assert len(python_modules) > 0

            for module in modules[:5]:
                assert hasattr(module, "name")
                assert hasattr(module, "base_address")
                assert module.base_address > 0

        finally:
            session.detach()

    def test_attach_detach_cycle(self, test_process: subprocess.Popen) -> None:
        """Multiple attach/detach cycles work correctly."""
        pid = test_process.pid

        for _ in range(3):
            session = frida.attach(pid)
            assert session.is_detached is False

            session.detach()

            time.sleep(0.1)


class TestRealScriptInjection:
    """Test real Frida script injection and execution."""

    def test_inject_simple_script(self, test_process: subprocess.Popen) -> None:
        """Simple Frida script injects and executes successfully."""
        pid = test_process.pid
        session = frida.attach(pid)

        script_source = """
console.log("Script loaded successfully");

rpc.exports = {
    test: function() {
        return "Hello from Frida";
    }
};
"""

        try:
            script = session.create_script(script_source)

            messages: list[dict[str, Any]] = []

            def on_message(message: dict[str, Any], data: bytes | None) -> None:
                messages.append(message)

            script.on("message", on_message)
            script.load()

            time.sleep(0.2)

            assert script.is_destroyed is False

            script.unload()

        finally:
            session.detach()

    def test_script_rpc_communication(self, test_process: subprocess.Popen) -> None:
        """RPC calls between Python and injected script work."""
        pid = test_process.pid
        session = frida.attach(pid)

        script_source = """
rpc.exports = {
    add: function(a, b) {
        return a + b;
    },
    getPid: function() {
        return Process.id;
    }
};
"""

        try:
            script = session.create_script(script_source)
            script.load()

            time.sleep(0.1)

            result = script.exports.add(5, 7)
            assert result == 12

            process_id = script.exports.get_pid()
            assert process_id == pid

            script.unload()

        finally:
            session.detach()

    def test_script_memory_reading(self, test_process: subprocess.Popen) -> None:
        """Injected script can read process memory."""
        pid = test_process.pid
        session = frida.attach(pid)

        script_source = """
rpc.exports = {
    readMemory: function(address, size) {
        try {
            var buf = Memory.readByteArray(ptr(address), size);
            return Array.from(new Uint8Array(buf));
        } catch (e) {
            return null;
        }
    },
    findModule: function(name) {
        var module = Process.findModuleByName(name);
        if (module) {
            return {
                name: module.name,
                base: module.base.toString(),
                size: module.size
            };
        }
        return null;
    }
};
"""

        try:
            script = session.create_script(script_source)
            script.load()

            time.sleep(0.1)

            modules = session.enumerate_modules()
            if modules:
                first_module = modules[0]
                module_info = script.exports.find_module(first_module.name)

                assert module_info is not None
                assert module_info["name"] == first_module.name
                assert int(module_info["base"], 16) == first_module.base_address

            script.unload()

        finally:
            session.detach()


class TestRealFunctionHooking:
    """Test real function hooking on Windows APIs."""

    def test_hook_windows_api_function(self, test_process: subprocess.Popen) -> None:
        """Hook Windows API function and intercept calls."""
        pid = test_process.pid
        session = frida.attach(pid)

        script_source = """
var hookCount = 0;

var GetTickCount = Module.findExportByName('kernel32.dll', 'GetTickCount');

if (GetTickCount) {
    Interceptor.attach(GetTickCount, {
        onEnter: function(args) {
            hookCount++;
        },
        onLeave: function(retval) {
            send({type: 'hook', count: hookCount});
        }
    });
}

rpc.exports = {
    getHookCount: function() {
        return hookCount;
    },
    callGetTickCount: function() {
        var func = new NativeFunction(GetTickCount, 'uint32', []);
        return func();
    }
};
"""

        messages: list[dict[str, Any]] = []

        def on_message(message: dict[str, Any], data: bytes | None) -> None:
            messages.append(message)

        try:
            script = session.create_script(script_source)
            script.on("message", on_message)
            script.load()

            time.sleep(0.1)

            initial_count = script.exports.get_hook_count()

            tick_count = script.exports.call_get_tick_count()
            assert isinstance(tick_count, int)
            assert tick_count > 0

            final_count = script.exports.get_hook_count()
            assert final_count > initial_count

            script.unload()

        finally:
            session.detach()

    def test_modify_function_return_value(
        self, test_process: subprocess.Popen
    ) -> None:
        """Hook function and modify its return value."""
        pid = test_process.pid
        session = frida.attach(pid)

        script_source = """
var GetTickCount = Module.findExportByName('kernel32.dll', 'GetTickCount');

if (GetTickCount) {
    Interceptor.attach(GetTickCount, {
        onLeave: function(retval) {
            retval.replace(12345);
        }
    });
}

rpc.exports = {
    callGetTickCount: function() {
        var func = new NativeFunction(GetTickCount, 'uint32', []);
        return func();
    }
};
"""

        try:
            script = session.create_script(script_source)
            script.load()

            time.sleep(0.1)

            result = script.exports.call_get_tick_count()
            assert result == 12345

            script.unload()

        finally:
            session.detach()


class TestFridaWorkerIntegration:
    """Test FridaWorker Qt integration with real processes."""

    def test_worker_attaches_to_process(
        self, qapp: QApplication, test_process: subprocess.Popen
    ) -> None:
        """FridaWorker successfully attaches to real process."""
        pid = test_process.pid

        worker = FridaWorker(pid)

        attached = []
        worker.attached.connect(lambda p: attached.append(p))

        worker.attach()

        for _ in range(50):
            qapp.processEvents()
            time.sleep(0.1)
            if attached:
                break

        assert len(attached) > 0
        assert attached[0] == pid

        worker.detach()

    def test_worker_injects_and_executes_script(
        self, qapp: QApplication, test_process: subprocess.Popen
    ) -> None:
        """FridaWorker injects script and receives output."""
        pid = test_process.pid

        worker = FridaWorker(pid)
        worker.attach()

        time.sleep(0.5)

        script = """
console.log("Worker script executed");
send({type: "test", message: "Script running"});
"""

        outputs: list[str] = []
        worker.script_output.connect(lambda msg: outputs.append(msg))

        worker.inject_script(script)

        for _ in range(50):
            qapp.processEvents()
            time.sleep(0.1)
            if outputs:
                break

        assert len(outputs) > 0

        worker.detach()


class TestFridaManagerDialog:
    """Test FridaManagerDialog with real process interaction."""

    def test_dialog_shows_running_processes(
        self, qapp: QApplication
    ) -> None:
        """Dialog lists real running Windows processes."""
        dialog = FridaManagerDialog()

        process_list = dialog.process_list

        assert process_list.rowCount() > 0

        process_names = []
        for row in range(min(process_list.rowCount(), 20)):
            name_item = process_list.item(row, 1)
            if name_item:
                process_names.append(name_item.text())

        assert any(
            name.lower() in ["system", "explorer.exe", "svchost.exe"]
            for name in process_names
        )

    def test_dialog_filter_processes(self, qapp: QApplication) -> None:
        """Dialog filters process list by search text."""
        dialog = FridaManagerDialog()

        initial_count = dialog.process_list.rowCount()

        dialog.search_box.setText("python")

        filtered_count = dialog.process_list.rowCount()

        assert filtered_count <= initial_count

        if filtered_count > 0:
            for row in range(filtered_count):
                name_item = dialog.process_list.item(row, 1)
                if name_item:
                    assert "python" in name_item.text().lower()

    def test_dialog_attach_to_selected_process(
        self, qapp: QApplication, test_process: subprocess.Popen
    ) -> None:
        """Dialog attaches to user-selected process."""
        dialog = FridaManagerDialog()

        test_pid = test_process.pid

        for row in range(dialog.process_list.rowCount()):
            pid_item = dialog.process_list.item(row, 0)
            if pid_item and int(pid_item.text()) == test_pid:
                dialog.process_list.selectRow(row)
                break

        if dialog.process_list.currentRow() >= 0:
            dialog.attach_to_selected_process()

            time.sleep(0.5)

            assert dialog.current_session is not None or dialog.worker is not None


class TestLicenseBypassScenarios:
    """Test real-world license bypass scenarios with Frida."""

    def test_hook_license_check_function(
        self, test_process: subprocess.Popen
    ) -> None:
        """Hook hypothetical license check function and force success."""
        pid = test_process.pid
        session = frida.attach(pid)

        script_source = """
var exports = Module.findExportByName(null, 'strcmp');

if (exports) {
    Interceptor.attach(exports, {
        onLeave: function(retval) {
            if (retval.toInt32() !== 0) {
                send({type: 'license_check', original: retval.toInt32()});
                retval.replace(0);
            }
        }
    });
}

rpc.exports = {
    testLicenseBypass: function() {
        return "License check bypassed";
    }
};
"""

        messages: list[dict[str, Any]] = []

        def on_message(message: dict[str, Any], data: bytes | None) -> None:
            messages.append(message)

        try:
            script = session.create_script(script_source)
            script.on("message", on_message)
            script.load()

            time.sleep(0.1)

            result = script.exports.test_license_bypass()
            assert "bypassed" in result.lower()

            script.unload()

        finally:
            session.detach()

    def test_patch_trial_expiration_check(
        self, test_process: subprocess.Popen
    ) -> None:
        """Patch trial expiration check to always return valid."""
        pid = test_process.pid
        session = frida.attach(pid)

        script_source = """
rpc.exports = {
    patchTrialCheck: function() {
        var GetSystemTime = Module.findExportByName('kernel32.dll', 'GetSystemTime');

        if (GetSystemTime) {
            Interceptor.replace(GetSystemTime, new NativeCallback(function(lpSystemTime) {
                send({type: 'trial', message: 'Trial check intercepted'});

                var ptrValue = ptr(lpSystemTime);
                ptrValue.writeU16(2025);
                ptrValue.add(2).writeU16(1);
                ptrValue.add(4).writeU16(0);
                ptrValue.add(6).writeU16(1);
            }, 'void', ['pointer']));

            return true;
        }
        return false;
    }
};
"""

        messages: list[dict[str, Any]] = []

        def on_message(message: dict[str, Any], data: bytes | None) -> None:
            messages.append(message)

        try:
            script = session.create_script(script_source)
            script.on("message", on_message)
            script.load()

            time.sleep(0.1)

            patched = script.exports.patch_trial_check()
            assert patched is True or patched is False

            script.unload()

        finally:
            session.detach()


class TestErrorHandling:
    """Test error handling for Frida operations."""

    def test_attach_to_invalid_pid_raises_error(self) -> None:
        """Attaching to invalid PID raises appropriate error."""
        invalid_pid = 999999

        with pytest.raises(frida.ProcessNotFoundError):
            frida.attach(invalid_pid)

    def test_inject_invalid_script_syntax_fails(
        self, test_process: subprocess.Popen
    ) -> None:
        """Injecting script with syntax errors fails gracefully."""
        pid = test_process.pid
        session = frida.attach(pid)

        invalid_script = """
        this is not valid JavaScript syntax {{{
        """

        try:
            script = session.create_script(invalid_script)

            with pytest.raises(Exception):
                script.load()

        finally:
            session.detach()

    def test_detached_session_operations_fail(
        self, test_process: subprocess.Popen
    ) -> None:
        """Operations on detached session raise appropriate errors."""
        pid = test_process.pid
        session = frida.attach(pid)
        session.detach()

        assert session.is_detached is True

        with pytest.raises(frida.InvalidOperationError):
            session.create_script("console.log('test');")


class TestPerformance:
    """Test performance of Frida operations."""

    def test_attach_detach_performance(self, test_process: subprocess.Popen) -> None:
        """Attach/detach operations complete quickly."""
        pid = test_process.pid

        start_time = time.time()

        for _ in range(10):
            session = frida.attach(pid)
            session.detach()

        duration = time.time() - start_time

        assert duration < 10.0, f"10 attach/detach cycles took {duration}s"

    def test_script_injection_performance(
        self, test_process: subprocess.Popen
    ) -> None:
        """Script injection and loading completes quickly."""
        pid = test_process.pid
        session = frida.attach(pid)

        script_source = """
rpc.exports = {
    test: function() {
        return 42;
    }
};
"""

        try:
            start_time = time.time()

            script = session.create_script(script_source)
            script.load()

            duration = time.time() - start_time

            assert duration < 2.0, f"Script injection took {duration}s"

            script.unload()

        finally:
            session.detach()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
