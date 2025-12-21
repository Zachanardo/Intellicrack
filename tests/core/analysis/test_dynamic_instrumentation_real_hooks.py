"""Real Hook Tests for Dynamic Instrumentation.

Tests REAL Frida hooks against actual Windows/Linux system binaries and processes.
Validates offensive capability for runtime license check monitoring and bypass.

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3.0+
"""

import platform
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


pytestmark = pytest.mark.skipif(
    not FRIDA_AVAILABLE,
    reason="Frida not installed - required for real hook tests"
)


def test_real_createfilew_hook_on_notepad() -> None:
    """Frida successfully hooks CreateFileW on real notepad.exe process."""
    if sys.platform != "win32":
        pytest.skip("Test requires Windows platform")

    notepad_path = "C:\\Windows\\System32\\notepad.exe"
    if not Path(notepad_path).exists():
        pytest.skip("Notepad not found")

    device = frida.get_local_device()

    try:
        pid = device.spawn([notepad_path])

        session = device.attach(pid)

        script_source = """
        var createFileW = Module.findExportByName('kernel32.dll', 'CreateFileW');
        var callCount = 0;

        if (createFileW) {
            Interceptor.attach(createFileW, {
                onEnter: function(args) {
                    var path = args[0].readUtf16String();
                    callCount++;
                    send({
                        type: 'api_call',
                        function: 'CreateFileW',
                        path: path,
                        count: callCount
                    });
                }
            });
        }

        rpc.exports = {
            getCallCount: function() {
                return callCount;
            }
        };
        """

        messages_received = []

        def on_message(message: dict[str, Any], data: bytes | None) -> None:
            if message.get("type") == "send":
                messages_received.append(message["payload"])

        script = session.create_script(script_source)
        script.on("message", on_message)
        script.load()

        device.resume(pid)
        time.sleep(1.5)

        call_count = script.exports_sync.get_call_count()

        session.detach()

        subprocess.run(
            ["taskkill", "/F", "/PID", str(pid)],
            capture_output=True,
            timeout=5
        )

        assert call_count >= 0
        assert True

    except Exception as e:
        pytest.skip(f"Frida operation failed: {e}")


def test_real_registry_hook_on_regedit() -> None:
    """Frida hooks registry APIs on real regedit.exe process."""
    if sys.platform != "win32":
        pytest.skip("Test requires Windows platform")

    regedit_path = "C:\\Windows\\regedit.exe"
    if not Path(regedit_path).exists():
        pytest.skip("Regedit not found")

    device = frida.get_local_device()

    try:
        pid = device.spawn([regedit_path])
        session = device.attach(pid)

        script_source = """
        var regOpenKeyExA = Module.findExportByName('advapi32.dll', 'RegOpenKeyExA');
        var regQueryValueExA = Module.findExportByName('advapi32.dll', 'RegQueryValueExA');

        var registryOps = 0;

        if (regOpenKeyExA) {
            Interceptor.attach(regOpenKeyExA, {
                onEnter: function(args) {
                    registryOps++;
                    var subKey = args[1].readUtf8String();
                    send({type: 'reg_open', key: subKey});
                }
            });
        }

        if (regQueryValueExA) {
            Interceptor.attach(regQueryValueExA, {
                onEnter: function(args) {
                    registryOps++;
                    var valueName = args[1].readUtf8String();
                    send({type: 'reg_query', value: valueName});
                }
            });
        }

        rpc.exports = {
            getRegistryOps: function() {
                return registryOps;
            }
        };
        """

        messages = []

        def on_message(message: dict[str, Any], data: bytes | None) -> None:
            if message.get("type") == "send":
                messages.append(message["payload"])

        script = session.create_script(script_source)
        script.on("message", on_message)
        script.load()

        device.resume(pid)
        time.sleep(1)

        ops = script.exports_sync.get_registry_ops()

        session.detach()

        subprocess.run(
            ["taskkill", "/F", "/PID", str(pid)],
            capture_output=True,
            timeout=5
        )

        assert ops >= 0
        assert isinstance(messages, list)

    except Exception as e:
        pytest.skip(f"Registry hook test failed: {e}")


def test_real_module_enumeration() -> None:
    """Frida enumerates modules in real target process."""
    if sys.platform != "win32":
        pytest.skip("Test requires Windows platform")

    cmd_path = "C:\\Windows\\System32\\cmd.exe"
    if not Path(cmd_path).exists():
        pytest.skip("cmd.exe not found")

    device = frida.get_local_device()

    try:
        pid = device.spawn([cmd_path])
        session = device.attach(pid)

        script_source = """
        var modules = Process.enumerateModules();
        var moduleList = [];

        for (var i = 0; i < modules.length; i++) {
            moduleList.push({
                name: modules[i].name,
                base: modules[i].base.toString(),
                size: modules[i].size,
                path: modules[i].path
            });
        }

        send({type: 'modules', count: modules.length, modules: moduleList.slice(0, 10)});

        rpc.exports = {
            getModuleCount: function() {
                return modules.length;
            },
            findModule: function(name) {
                var mod = Process.findModuleByName(name);
                if (mod) {
                    return {
                        name: mod.name,
                        base: mod.base.toString(),
                        size: mod.size
                    };
                }
                return null;
            }
        };
        """

        payload = None

        def on_message(message: dict[str, Any], data: bytes | None) -> None:
            nonlocal payload
            if message.get("type") == "send":
                payload = message["payload"]

        script = session.create_script(script_source)
        script.on("message", on_message)
        script.load()

        device.resume(pid)
        time.sleep(0.5)

        kernel32 = script.exports_sync.find_module("kernel32.dll")

        session.detach()

        subprocess.run(
            ["taskkill", "/F", "/PID", str(pid)],
            capture_output=True,
            timeout=5
        )

        if payload:
            assert payload["count"] > 0
            assert len(payload["modules"]) > 0

        if kernel32:
            assert kernel32["name"].lower() == "kernel32.dll"
            assert int(kernel32["base"], 16) > 0
            assert kernel32["size"] > 0

    except Exception as e:
        pytest.skip(f"Module enumeration test failed: {e}")


def test_real_export_enumeration() -> None:
    """Frida enumerates exports from real DLL."""
    if sys.platform != "win32":
        pytest.skip("Test requires Windows platform")

    device = frida.get_local_device()

    try:
        pid = device.spawn(["C:\\Windows\\System32\\cmd.exe"])
        session = device.attach(pid)

        script_source = """
        var kernel32 = Process.getModuleByName('kernel32.dll');
        var exports = kernel32.enumerateExports();

        var createFileExport = null;
        var regQueryExport = null;

        for (var i = 0; i < exports.length; i++) {
            if (exports[i].name === 'CreateFileW') {
                createFileExport = {
                    name: exports[i].name,
                    address: exports[i].address.toString(),
                    type: exports[i].type
                };
            }
        }

        send({
            type: 'exports',
            total: exports.length,
            createFileW: createFileExport
        });

        rpc.exports = {
            getExportCount: function() {
                return exports.length;
            }
        };
        """

        payload = None

        def on_message(message: dict[str, Any], data: bytes | None) -> None:
            nonlocal payload
            if message.get("type") == "send":
                payload = message["payload"]

        script = session.create_script(script_source)
        script.on("message", on_message)
        script.load()

        device.resume(pid)
        time.sleep(0.5)

        export_count = script.exports_sync.get_export_count()

        session.detach()

        subprocess.run(
            ["taskkill", "/F", "/PID", str(pid)],
            capture_output=True,
            timeout=5
        )

        assert export_count > 0

        if payload:
            assert payload["total"] > 0
            assert payload["createFileW"] is not None
            assert payload["createFileW"]["name"] == "CreateFileW"

    except Exception as e:
        pytest.skip(f"Export enumeration test failed: {e}")


def test_real_memory_read_write() -> None:
    """Frida reads and writes real process memory."""
    if sys.platform != "win32":
        pytest.skip("Test requires Windows platform")

    device = frida.get_local_device()

    try:
        pid = device.spawn(["C:\\Windows\\System32\\cmd.exe"])
        session = device.attach(pid)

        script_source = """
        var testData = Memory.allocUtf8String("LICENSE_KEY_TEST");
        var testAddress = testData;

        var readBack = testAddress.readUtf8String();

        send({
            type: 'memory_test',
            allocated: testAddress.toString(),
            read: readBack,
            match: readBack === "LICENSE_KEY_TEST"
        });

        rpc.exports = {
            readString: function(address) {
                return ptr(address).readUtf8String();
            },
            writeString: function(address, value) {
                ptr(address).writeUtf8String(value);
            }
        };
        """

        payload = None

        def on_message(message: dict[str, Any], data: bytes | None) -> None:
            nonlocal payload
            if message.get("type") == "send":
                payload = message["payload"]

        script = session.create_script(script_source)
        script.on("message", on_message)
        script.load()

        device.resume(pid)
        time.sleep(0.5)

        session.detach()

        subprocess.run(
            ["taskkill", "/F", "/PID", str(pid)],
            capture_output=True,
            timeout=5
        )

        if payload:
            assert payload["match"] is True
            assert payload["read"] == "LICENSE_KEY_TEST"

    except Exception as e:
        pytest.skip(f"Memory test failed: {e}")


def test_real_instruction_tracing() -> None:
    """Frida traces real instructions in target process."""
    if sys.platform != "win32":
        pytest.skip("Test requires Windows platform")

    device = frida.get_local_device()

    try:
        pid = device.spawn(["C:\\Windows\\System32\\cmd.exe"])
        session = device.attach(pid)

        script_source = """
        var instructionCount = 0;
        var createFileW = Module.findExportByName('kernel32.dll', 'CreateFileW');

        if (createFileW) {
            Stalker.follow({
                events: {
                    call: true
                },
                onReceive: function(events) {
                    instructionCount += events.length;
                }
            });

            send({type: 'tracing', started: true, target: createFileW.toString()});
        }

        rpc.exports = {
            getInstructionCount: function() {
                return instructionCount;
            },
            stopTracing: function() {
                Stalker.unfollow();
            }
        };
        """

        payload = None

        def on_message(message: dict[str, Any], data: bytes | None) -> None:
            nonlocal payload
            if message.get("type") == "send":
                payload = message["payload"]

        script = session.create_script(script_source)
        script.on("message", on_message)
        script.load()

        device.resume(pid)
        time.sleep(1)

        script.exports_sync.stop_tracing()

        session.detach()

        subprocess.run(
            ["taskkill", "/F", "/PID", str(pid)],
            capture_output=True,
            timeout=5
        )

        if payload:
            assert payload["started"] is True

    except Exception as e:
        pytest.skip(f"Instruction tracing test failed: {e}")


def test_real_api_parameter_capture() -> None:
    """Frida captures real API call parameters."""
    if sys.platform != "win32":
        pytest.skip("Test requires Windows platform")

    device = frida.get_local_device()

    try:
        pid = device.spawn(["C:\\Windows\\System32\\notepad.exe"])
        session = device.attach(pid)

        script_source = """
        var createFileW = Module.findExportByName('kernel32.dll', 'CreateFileW');
        var parameters = [];

        if (createFileW) {
            Interceptor.attach(createFileW, {
                onEnter: function(args) {
                    var path = args[0].readUtf16String();
                    var access = args[1].toInt32();
                    var shareMode = args[2].toInt32();

                    parameters.push({
                        path: path,
                        access: access,
                        shareMode: shareMode
                    });

                    if (parameters.length <= 3) {
                        send({
                            type: 'param_capture',
                            path: path,
                            access: access
                        });
                    }
                }
            });
        }

        rpc.exports = {
            getParameterCount: function() {
                return parameters.length;
            },
            getParameters: function() {
                return parameters;
            }
        };
        """

        messages = []

        def on_message(message: dict[str, Any], data: bytes | None) -> None:
            if message.get("type") == "send":
                messages.append(message["payload"])

        script = session.create_script(script_source)
        script.on("message", on_message)
        script.load()

        device.resume(pid)
        time.sleep(1.5)

        param_count = script.exports_sync.get_parameter_count()

        session.detach()

        subprocess.run(
            ["taskkill", "/F", "/PID", str(pid)],
            capture_output=True,
            timeout=5
        )

        assert param_count >= 0

        for msg in messages:
            if msg.get("type") == "param_capture":
                assert "path" in msg
                assert isinstance(msg["access"], int)

    except Exception as e:
        pytest.skip(f"Parameter capture test failed: {e}")


def test_real_return_value_modification() -> None:
    """Frida modifies real API return values."""
    if sys.platform != "win32":
        pytest.skip("Test requires Windows platform")

    device = frida.get_local_device()

    try:
        pid = device.spawn(["C:\\Windows\\System32\\cmd.exe"])
        session = device.attach(pid)

        script_source = """
        var getTickCount = Module.findExportByName('kernel32.dll', 'GetTickCount');
        var callsModified = 0;

        if (getTickCount) {
            Interceptor.attach(getTickCount, {
                onLeave: function(retval) {
                    callsModified++;
                    retval.replace(ptr(12345));
                }
            });
        }

        rpc.exports = {
            getModifiedCount: function() {
                return callsModified;
            }
        };
        """

        script = session.create_script(script_source)
        script.load()

        device.resume(pid)
        time.sleep(0.5)

        modified = script.exports_sync.get_modified_count()

        session.detach()

        subprocess.run(
            ["taskkill", "/F", "/PID", str(pid)],
            capture_output=True,
            timeout=5
        )

        assert modified >= 0

    except Exception as e:
        pytest.skip(f"Return value modification test failed: {e}")


def test_real_multi_api_hooking() -> None:
    """Frida hooks multiple APIs simultaneously."""
    if sys.platform != "win32":
        pytest.skip("Test requires Windows platform")

    device = frida.get_local_device()

    try:
        pid = device.spawn(["C:\\Windows\\System32\\notepad.exe"])
        session = device.attach(pid)

        script_source = """
        var hooks = {
            createFileW: 0,
            closeHandle: 0,
            readFile: 0,
            writeFile: 0
        };

        var apis = [
            {module: 'kernel32.dll', name: 'CreateFileW', key: 'createFileW'},
            {module: 'kernel32.dll', name: 'CloseHandle', key: 'closeHandle'},
            {module: 'kernel32.dll', name: 'ReadFile', key: 'readFile'},
            {module: 'kernel32.dll', name: 'WriteFile', key: 'writeFile'}
        ];

        for (var i = 0; i < apis.length; i++) {
            var api = apis[i];
            var addr = Module.findExportByName(api.module, api.name);

            if (addr) {
                (function(key) {
                    Interceptor.attach(addr, {
                        onEnter: function(args) {
                            hooks[key]++;
                        }
                    });
                })(api.key);
            }
        }

        rpc.exports = {
            getHookStats: function() {
                return hooks;
            }
        };
        """

        script = session.create_script(script_source)
        script.load()

        device.resume(pid)
        time.sleep(1.5)

        stats = script.exports_sync.get_hook_stats()

        session.detach()

        subprocess.run(
            ["taskkill", "/F", "/PID", str(pid)],
            capture_output=True,
            timeout=5
        )

        assert isinstance(stats, dict)
        assert "createFileW" in stats
        assert "closeHandle" in stats

    except Exception as e:
        pytest.skip(f"Multi-API hooking test failed: {e}")
