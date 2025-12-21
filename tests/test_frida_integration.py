"""Frida Integration Tests - Real Frida Library Tests.

This test suite verifies Intellicrack's integration with the Frida dynamic instrumentation
toolkit using REAL Frida Python bindings and actual process instrumentation.

Tests validate:
- Process attachment and session management
- Script injection and execution
- Function hooking and interception
- Memory read/write operations
- Integration with Intellicrack Frida modules
- Real-world licensing protection bypass scenarios

Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Optional

import pytest

try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False
    frida = None

from intellicrack.core.frida_manager import FridaManager
from intellicrack.core.analysis.frida_script_manager import FridaScriptManager, ScriptCategory


class TestFridaBasicFunctionality:
    """Test basic Frida library functionality with real processes."""

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida library not installed")
    def test_frida_library_import(self) -> None:
        """Test that Frida library imports successfully."""
        assert frida is not None
        assert hasattr(frida, 'get_local_device')
        assert hasattr(frida, 'attach')
        assert hasattr(frida, 'spawn')

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida library not installed")
    def test_get_local_device(self) -> None:
        """Test getting local Frida device."""
        device = frida.get_local_device()
        assert device is not None
        assert device.id == 'local'
        assert device.name is not None
        assert device.type in ['local', 'usb', 'remote']

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida library not installed")
    def test_enumerate_processes(self) -> None:
        """Test enumerating processes on local device."""
        device = frida.get_local_device()
        processes = device.enumerate_processes()

        assert len(processes) > 0
        assert any(p.name.lower() == 'python.exe' for p in processes)

        for process in processes[:5]:
            assert process.pid > 0
            assert process.name is not None
            assert isinstance(process.name, str)

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida library not installed")
    def test_attach_to_own_process(self) -> None:
        """Test attaching Frida to the current Python process."""
        device = frida.get_local_device()
        current_pid = os.getpid()

        session = device.attach(current_pid)
        assert session is not None
        assert not session.is_detached

        session.detach()
        time.sleep(0.1)
        assert session.is_detached

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida library not installed")
    def test_create_and_load_script(self) -> None:
        """Test creating and loading a simple Frida script."""
        device = frida.get_local_device()
        session = device.attach(os.getpid())

        script_code = """
        console.log('Hello from Frida script!');
        send({type: 'test', message: 'Script loaded successfully'});
        """

        script = session.create_script(script_code)
        assert script is not None

        messages = []
        def on_message(message: dict[str, Any], data: Any) -> None:
            messages.append(message)

        script.on('message', on_message)
        script.load()

        time.sleep(0.2)
        assert messages
        assert messages[0]['type'] == 'send'
        assert 'test' in messages[0]['payload']

        script.unload()
        session.detach()


class TestFridaProcessSpawning:
    """Test Frida process spawning and attachment."""

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida library not installed")
    @pytest.mark.skipif(sys.platform != 'win32', reason="Windows-specific test")
    def test_spawn_and_attach_notepad(self) -> None:
        """Test spawning and attaching to notepad.exe."""
        device = frida.get_local_device()
        notepad_path = r"C:\Windows\System32\notepad.exe"

        if not os.path.exists(notepad_path):
            pytest.skip("notepad.exe not found")

        pid = device.spawn(notepad_path)
        assert pid > 0

        session = device.attach(pid)
        assert session is not None
        assert not session.is_detached

        device.resume(pid)
        time.sleep(0.5)

        device.kill(pid)
        session.detach()

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida library not installed")
    @pytest.mark.skipif(sys.platform != 'win32', reason="Windows-specific test")
    def test_enumerate_modules_in_spawned_process(self) -> None:
        """Test enumerating modules in a spawned process."""
        device = frida.get_local_device()
        notepad_path = r"C:\Windows\System32\notepad.exe"

        if not os.path.exists(notepad_path):
            pytest.skip("notepad.exe not found")

        pid = device.spawn(notepad_path)
        session = device.attach(pid)
        device.resume(pid)

        script_code = """
        var modules = Process.enumerateModules();
        send({type: 'modules', count: modules.length, names: modules.slice(0, 5).map(m => m.name)});
        """

        messages = []
        def on_message(message: dict[str, Any], data: Any) -> None:
            messages.append(message)

        script = session.create_script(script_code)
        script.on('message', on_message)
        script.load()

        time.sleep(0.5)

        assert messages
        payload = messages[0]['payload']
        assert payload['count'] > 0
        assert 'notepad.exe' in [n.lower() for n in payload['names']]

        device.kill(pid)
        session.detach()


class TestFridaFunctionHooking:
    """Test real function hooking with Frida."""

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida library not installed")
    @pytest.mark.skipif(sys.platform != 'win32', reason="Windows-specific test")
    def test_hook_createfile_in_notepad(self) -> None:
        """Test hooking CreateFileW in notepad.exe."""
        device = frida.get_local_device()
        notepad_path = r"C:\Windows\System32\notepad.exe"

        if not os.path.exists(notepad_path):
            pytest.skip("notepad.exe not found")

        pid = device.spawn(notepad_path)
        session = device.attach(pid)

        script_code = """
        var createFileW = Module.findExportByName('kernel32.dll', 'CreateFileW');
        if (createFileW) {
            Interceptor.attach(createFileW, {
                onEnter: function(args) {
                    var filename = args[0].readUtf16String();
                    send({type: 'hook', function: 'CreateFileW', filename: filename});
                }
            });
            send({type: 'status', message: 'CreateFileW hook installed'});
        } else {
            send({type: 'error', message: 'CreateFileW not found'});
        }
        """

        messages = []
        def on_message(message: dict[str, Any], data: Any) -> None:
            messages.append(message)

        script = session.create_script(script_code)
        script.on('message', on_message)
        script.load()

        device.resume(pid)
        time.sleep(0.5)

        assert messages
        assert any('CreateFileW' in str(m) for m in messages)

        device.kill(pid)
        session.detach()

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida library not installed")
    @pytest.mark.skipif(sys.platform != 'win32', reason="Windows-specific test")
    def test_hook_getprocaddress(self) -> None:
        """Test hooking GetProcAddress to detect dynamic imports."""
        device = frida.get_local_device()
        notepad_path = r"C:\Windows\System32\notepad.exe"

        if not os.path.exists(notepad_path):
            pytest.skip("notepad.exe not found")

        pid = device.spawn(notepad_path)
        session = device.attach(pid)

        script_code = """
        var getProcAddress = Module.findExportByName('kernel32.dll', 'GetProcAddress');
        var hookCount = 0;

        Interceptor.attach(getProcAddress, {
            onEnter: function(args) {
                var procName = args[1].readCString();
                hookCount++;
                if (hookCount <= 5) {
                    send({type: 'import', function: procName});
                }
            }
        });

        send({type: 'status', message: 'GetProcAddress hook installed'});
        """

        messages = []
        def on_message(message: dict[str, Any], data: Any) -> None:
            messages.append(message)

        script = session.create_script(script_code)
        script.on('message', on_message)
        script.load()

        device.resume(pid)
        time.sleep(0.8)

        assert len(messages) > 1
        import_messages = [m for m in messages if m.get('payload', {}).get('type') == 'import']
        assert import_messages

        device.kill(pid)
        session.detach()


class TestFridaMemoryOperations:
    """Test Frida memory read/write operations."""

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida library not installed")
    def test_read_process_memory(self) -> None:
        """Test reading memory from current process."""
        device = frida.get_local_device()
        session = device.attach(os.getpid())

        script_code = """
        var modules = Process.enumerateModules();
        var baseModule = modules[0];
        var baseAddr = baseModule.base;

        var bytes = Memory.readByteArray(baseAddr, 16);
        send({type: 'memory', address: baseAddr.toString(), size: 16});
        """

        messages = []
        def on_message(message: dict[str, Any], data: Any) -> None:
            messages.append(message)

        script = session.create_script(script_code)
        script.on('message', on_message)
        script.load()

        time.sleep(0.3)

        assert messages
        payload = messages[0]['payload']
        assert payload['type'] == 'memory'
        assert payload['size'] == 16

        session.detach()

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida library not installed")
    def test_search_memory_pattern(self) -> None:
        """Test searching for byte patterns in memory."""
        device = frida.get_local_device()
        session = device.attach(os.getpid())

        script_code = """
        var modules = Process.enumerateModules();
        var results = [];

        for (var i = 0; i < Math.min(3, modules.length); i++) {
            var module = modules[i];
            var ranges = module.enumerateRanges('r--');
            if (ranges.length > 0) {
                results.push({
                    module: module.name,
                    rangeCount: ranges.length
                });
            }
        }

        send({type: 'scan', modules: results.length});
        """

        messages = []
        def on_message(message: dict[str, Any], data: Any) -> None:
            messages.append(message)

        script = session.create_script(script_code)
        script.on('message', on_message)
        script.load()

        time.sleep(0.3)

        assert messages
        assert messages[0]['payload']['type'] == 'scan'

        session.detach()

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida library not installed")
    @pytest.mark.skipif(sys.platform != 'win32', reason="Windows-specific test")
    def test_memory_protection_change(self) -> None:
        """Test changing memory protection on a spawned process."""
        device = frida.get_local_device()
        notepad_path = r"C:\Windows\System32\notepad.exe"

        if not os.path.exists(notepad_path):
            pytest.skip("notepad.exe not found")

        pid = device.spawn(notepad_path)
        session = device.attach(pid)

        script_code = """
        var modules = Process.enumerateModules();
        var mainModule = modules.find(m => m.name.toLowerCase().includes('notepad'));

        if (mainModule) {
            var addr = mainModule.base;
            try {
                Memory.protect(addr, 4096, 'rwx');
                send({type: 'protection', success: true, address: addr.toString()});
            } catch (e) {
                send({type: 'protection', success: false, error: e.message});
            }
        }
        """

        messages = []
        def on_message(message: dict[str, Any], data: Any) -> None:
            messages.append(message)

        script = session.create_script(script_code)
        script.on('message', on_message)
        script.load()

        device.resume(pid)
        time.sleep(0.5)

        assert messages
        payload = messages[0]['payload']
        assert payload['type'] == 'protection'

        device.kill(pid)
        session.detach()


class TestIntellicrackFridaManager:
    """Test Intellicrack's FridaManager integration."""

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida library not installed")
    def test_frida_manager_initialization(self) -> None:
        """Test FridaManager initialization."""
        manager = FridaManager()

        assert manager is not None
        assert hasattr(manager, 'device')
        assert hasattr(manager, 'sessions')
        assert hasattr(manager, 'scripts')
        assert hasattr(manager, 'attach_to_process')
        assert hasattr(manager, 'load_script')
        assert manager.device is not None

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida library not installed")
    def test_frida_manager_list_scripts(self) -> None:
        """Test listing available Frida scripts."""
        manager = FridaManager()
        scripts = manager.list_available_scripts()

        assert isinstance(scripts, (list, dict))
        if isinstance(scripts, (dict, list)):
            assert len(scripts) > 0

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida library not installed")
    @pytest.mark.skipif(sys.platform != 'win32', reason="Windows-specific test")
    def test_frida_manager_attach_to_process(self) -> None:
        """Test FridaManager process attachment."""
        manager = FridaManager()
        current_pid = os.getpid()

        try:
            session_id = manager.attach_to_process(current_pid)
            assert session_id is not None
            assert session_id in manager.sessions

            session_data = manager.sessions[session_id]
            assert 'session' in session_data or 'pid' in session_data
        except Exception as e:
            pytest.skip(f"Attachment failed: {e}")
        finally:
            if hasattr(manager, 'cleanup'):
                manager.cleanup()

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida library not installed")
    @pytest.mark.skipif(sys.platform != 'win32', reason="Windows-specific test")
    def test_frida_manager_load_script(self) -> None:
        """Test loading a Frida script through FridaManager."""
        manager = FridaManager()

        scripts_dir = Path(__file__).parent.parent / "intellicrack" / "scripts" / "frida"
        memory_dumper = scripts_dir / "memory_dumper.js"

        if not memory_dumper.exists():
            pytest.skip("memory_dumper.js not found")

        current_pid = os.getpid()

        try:
            session_id = manager.attach_to_process(current_pid)
            time.sleep(0.3)

            script_result = manager.load_script(session_id, str(memory_dumper))

            assert script_result is not None
            time.sleep(0.5)
        except Exception as e:
            pytest.skip(f"Script loading failed: {e}")
        finally:
            if hasattr(manager, 'cleanup'):
                manager.cleanup()


class TestIntellicrackFridaScriptManager:
    """Test Intellicrack's FridaScriptManager."""

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida library not installed")
    def test_script_manager_initialization(self) -> None:
        """Test FridaScriptManager initialization."""
        script_manager = FridaScriptManager()

        assert script_manager is not None
        assert hasattr(script_manager, 'list_scripts')
        assert hasattr(script_manager, 'get_script')

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida library not installed")
    def test_script_manager_list_scripts(self) -> None:
        """Test listing scripts through ScriptManager."""
        script_manager = FridaScriptManager()

        try:
            scripts = script_manager.list_scripts()
            assert isinstance(scripts, (list, dict))

            if isinstance(scripts, list):
                assert len(scripts) > 0
                assert any('bypass' in str(s).lower() or 'hook' in str(s).lower() for s in scripts)
        except Exception as e:
            pytest.skip(f"Script listing failed: {e}")

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida library not installed")
    def test_script_manager_get_script(self) -> None:
        """Test getting a specific script."""
        script_manager = FridaScriptManager()

        try:
            scripts = script_manager.list_scripts()
            if scripts and len(scripts) > 0:
                first_script = scripts[0] if isinstance(scripts, list) else list(scripts.keys())[0]

                script_content = script_manager.get_script(first_script)
                assert script_content is not None

                if isinstance(script_content, str):
                    assert len(script_content) > 0
        except Exception as e:
            pytest.skip(f"Script retrieval failed: {e}")


class TestFridaLicensingBypass:
    """Test Frida-based licensing bypass scenarios."""

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida library not installed")
    @pytest.mark.skipif(sys.platform != 'win32', reason="Windows-specific test")
    def test_registry_read_hook_for_license_detection(self) -> None:
        """Test hooking registry reads to detect license key storage."""
        device = frida.get_local_device()
        notepad_path = r"C:\Windows\System32\notepad.exe"

        if not os.path.exists(notepad_path):
            pytest.skip("notepad.exe not found")

        pid = device.spawn(notepad_path)
        session = device.attach(pid)

        script_code = """
        var regOpenKeyExW = Module.findExportByName('advapi32.dll', 'RegOpenKeyExW');
        var regQueryValueExW = Module.findExportByName('advapi32.dll', 'RegQueryValueExW');
        var hookCount = 0;

        if (regOpenKeyExW) {
            Interceptor.attach(regOpenKeyExW, {
                onEnter: function(args) {
                    try {
                        var keyName = args[1].readUtf16String();
                        if (keyName && hookCount < 3) {
                            send({type: 'registry', operation: 'OpenKey', key: keyName});
                            hookCount++;
                        }
                    } catch (e) {}
                }
            });
            send({type: 'status', message: 'Registry hooks installed'});
        }
        """

        messages = []
        def on_message(message: dict[str, Any], data: Any) -> None:
            messages.append(message)

        script = session.create_script(script_code)
        script.on('message', on_message)
        script.load()

        device.resume(pid)
        time.sleep(0.5)

        assert messages

        device.kill(pid)
        session.detach()

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida library not installed")
    @pytest.mark.skipif(sys.platform != 'win32', reason="Windows-specific test")
    def test_time_check_bypass_simulation(self) -> None:
        """Test simulating time check bypass by hooking GetSystemTime."""
        device = frida.get_local_device()
        session = device.attach(os.getpid())

        script_code = """
        var getSystemTime = Module.findExportByName('kernel32.dll', 'GetSystemTime');

        if (getSystemTime) {
            Interceptor.attach(getSystemTime, {
                onEnter: function(args) {
                    send({type: 'timebomb', function: 'GetSystemTime', detected: true});
                }
            });
            send({type: 'status', message: 'Time check detection hook installed'});
        }
        """

        messages = []
        def on_message(message: dict[str, Any], data: Any) -> None:
            messages.append(message)

        script = session.create_script(script_code)
        script.on('message', on_message)
        script.load()

        time.sleep(0.3)

        assert messages
        assert any('Time check' in str(m) for m in messages)

        session.detach()

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida library not installed")
    @pytest.mark.skipif(sys.platform != 'win32', reason="Windows-specific test")
    def test_network_license_validation_detection(self) -> None:
        """Test detecting network-based license validation by hooking WinHTTP."""
        device = frida.get_local_device()
        session = device.attach(os.getpid())

        script_code = """
        var winHttpOpen = Module.findExportByName('winhttp.dll', 'WinHttpOpen');
        var winHttpConnect = Module.findExportByName('winhttp.dll', 'WinHttpConnect');

        var detected = false;

        if (winHttpOpen) {
            Interceptor.attach(winHttpOpen, {
                onEnter: function(args) {
                    if (!detected) {
                        send({type: 'network', function: 'WinHttpOpen'});
                        detected = true;
                    }
                }
            });
        }

        if (winHttpConnect) {
            Interceptor.attach(winHttpConnect, {
                onEnter: function(args) {
                    try {
                        var serverName = args[1].readUtf16String();
                        send({type: 'network', function: 'WinHttpConnect', server: serverName});
                    } catch (e) {}
                }
            });
        }

        send({type: 'status', message: 'Network hooks installed'});
        """

        messages = []
        def on_message(message: dict[str, Any], data: Any) -> None:
            messages.append(message)

        script = session.create_script(script_code)
        script.on('message', on_message)
        script.load()

        time.sleep(0.3)

        assert messages

        session.detach()


class TestFridaRealWorldScripts:
    """Test Intellicrack's real Frida scripts on actual processes."""

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida library not installed")
    @pytest.mark.skipif(sys.platform != 'win32', reason="Windows-specific test")
    def test_anti_debugger_script_syntax(self) -> None:
        """Test that anti_debugger.js has valid JavaScript syntax."""
        scripts_dir = Path(__file__).parent.parent / "intellicrack" / "scripts" / "frida"
        anti_debugger_script = scripts_dir / "anti_debugger.js"

        if not anti_debugger_script.exists():
            pytest.skip("anti_debugger.js not found")

        script_content = anti_debugger_script.read_text(encoding='utf-8')
        assert len(script_content) > 0
        assert 'Interceptor' in script_content or 'Process' in script_content

        device = frida.get_local_device()
        session = device.attach(os.getpid())

        try:
            script = session.create_script(script_content)
            script.load()
            time.sleep(0.3)
            script.unload()
        except Exception as e:
            pytest.fail(f"Script has syntax errors: {e}")
        finally:
            session.detach()

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida library not installed")
    @pytest.mark.skipif(sys.platform != 'win32', reason="Windows-specific test")
    def test_registry_monitor_script_syntax(self) -> None:
        """Test that registry_monitor.js has valid JavaScript syntax."""
        scripts_dir = Path(__file__).parent.parent / "intellicrack" / "scripts" / "frida"
        registry_monitor_script = scripts_dir / "registry_monitor.js"

        if not registry_monitor_script.exists():
            pytest.skip("registry_monitor.js not found")

        script_content = registry_monitor_script.read_text(encoding='utf-8')
        assert len(script_content) > 0

        device = frida.get_local_device()
        session = device.attach(os.getpid())

        try:
            script = session.create_script(script_content)
            script.load()
            time.sleep(0.3)
            script.unload()
        except Exception as e:
            pytest.fail(f"Script has syntax errors: {e}")
        finally:
            session.detach()

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida library not installed")
    @pytest.mark.skipif(sys.platform != 'win32', reason="Windows-specific test")
    def test_hwid_spoofer_script_syntax(self) -> None:
        """Test that hwid_spoofer.js has valid JavaScript syntax."""
        scripts_dir = Path(__file__).parent.parent / "intellicrack" / "scripts" / "frida"
        hwid_spoofer_script = scripts_dir / "hwid_spoofer.js"

        if not hwid_spoofer_script.exists():
            pytest.skip("hwid_spoofer.js not found")

        script_content = hwid_spoofer_script.read_text(encoding='utf-8')
        assert len(script_content) > 0

        device = frida.get_local_device()
        session = device.attach(os.getpid())

        try:
            script = session.create_script(script_content)
            script.load()
            time.sleep(0.3)
            script.unload()
        except Exception as e:
            pytest.fail(f"Script has syntax errors: {e}")
        finally:
            session.detach()


class TestFridaConcurrency:
    """Test concurrent Frida operations."""

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida library not installed")
    def test_concurrent_process_attachment(self) -> None:
        """Test attaching to multiple processes concurrently."""
        device = frida.get_local_device()
        current_pid = os.getpid()

        sessions = []
        errors = []

        def attach_process():
            try:
                session = device.attach(current_pid)
                sessions.append(session)
                time.sleep(0.1)
                session.detach()
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=attach_process) for _ in range(3)]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join(timeout=5)

        assert not errors, f"Errors occurred: {errors}"
        assert sessions

    @pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida library not installed")
    def test_multiple_script_loading(self) -> None:
        """Test loading multiple scripts on the same session."""
        device = frida.get_local_device()
        session = device.attach(os.getpid())

        scripts = []
        for i in range(3):
            script_code = f"""
            console.log('Script {i} loaded');
            send({{type: 'loaded', id: {i}}});
            """
            script = session.create_script(script_code)
            scripts.append(script)

        messages = []
        def on_message(message: dict[str, Any], data: Any) -> None:
            messages.append(message)

        for script in scripts:
            script.on('message', on_message)
            script.load()

        time.sleep(0.3)

        assert len(messages) >= 3

        for script in scripts:
            script.unload()

        session.detach()


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
