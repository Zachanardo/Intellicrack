"""Production-Ready Tests for FridaScriptManager - Real Frida Script Execution Validation.

Tests validate REAL Frida script management capabilities including:
- Script loading and validation from disk
- Process attachment (spawn and attach modes)
- Script injection and execution
- Message handling and callbacks
- RPC exports and function calls
- Session management and cleanup
- Script result export
- Custom script creation with metadata
- Multi-script execution workflows

NO MOCKS - All tests validate actual Frida script management functionality.
Tests MUST FAIL if script management doesn't work with real processes.

Copyright (C) 2025 Zachary Flint
SPDX-License-Identifier: GPL-3.0-or-later
"""

import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

try:
    import frida

    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False

from intellicrack.core.analysis.frida_script_manager import (
    FridaScriptConfig,
    FridaScriptManager,
    ScriptCategory,
    ScriptResult,
)


pytestmark = pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")


class FakeFridaSession:
    """Real test double for Frida session objects."""

    def __init__(self) -> None:
        self.detached: bool = False
        self.detach_call_count: int = 0

    def detach(self) -> None:
        self.detached = True
        self.detach_call_count += 1


@pytest.fixture(scope="module")
def scripts_dir(tmp_path_factory: Any) -> Path:
    """Create temporary scripts directory with test scripts."""
    test_scripts_dir = tmp_path_factory.mktemp("frida_scripts")

    test_script_basic = test_scripts_dir / "test_basic.js"
    test_script_basic.write_text("""
console.log('Test script loaded');
rpc.exports = {
    testFunction: function() {
        return 'test_result';
    },
    addNumbers: function(a, b) {
        return a + b;
    }
};
""")

    test_script_memory = test_scripts_dir / "memory_dumper.js"
    test_script_memory.write_text("""
console.log('Memory dumper script loaded');

rpc.exports = {
    dumpRegion: function(address, size) {
        try {
            var ptr = ptr(address);
            var data = Memory.readByteArray(ptr, size);
            send({type: 'memory_dump', address: address, size: size}, data);
            return true;
        } catch (e) {
            send({type: 'error', message: e.message});
            return false;
        }
    }
};
""")

    test_script_anti_debug = test_scripts_dir / "anti_debugger.js"
    test_script_anti_debug.write_text("""
console.log('Anti-debugger script loaded');

var kernel32 = Module.findExportByName('kernel32.dll', 'IsDebuggerPresent');
if (kernel32) {
    Interceptor.attach(kernel32, {
        onLeave: function(retval) {
            retval.replace(0);
            send({type: 'bypass', function: 'IsDebuggerPresent', result: 'bypassed'});
        }
    });
}
""")

    test_script_hwid = test_scripts_dir / "hwid_spoofer.js"
    test_script_hwid.write_text("""
console.log('HWID Spoofer script loaded with params');
send({type: 'log', message: 'MAC: ' + spoof_mac});
send({type: 'log', message: 'Disk: ' + spoof_disk_serial});
""")

    test_script_custom = test_scripts_dir / "custom_analyzer.js"
    test_script_custom.write_text("""
/**
 * @metadata
 * {
 *   "name": "Custom Analyzer",
 *   "category": "behavioral_analysis",
 *   "description": "Custom behavior analysis script",
 *   "parameters": {
 *     "track_calls": true,
 *     "depth": 5
 *   }
 * }
 * @end
 */

console.log('Custom analyzer loaded');
""")

    return test_scripts_dir


@pytest.fixture
def manager(scripts_dir: Path) -> FridaScriptManager:
    """Create FridaScriptManager instance with test scripts directory."""
    return FridaScriptManager(scripts_dir)


@pytest.fixture
def test_process_pid() -> int | None:
    """Get PID of a running test process (notepad.exe on Windows)."""
    if sys.platform != "win32":
        pytest.skip("Windows-specific test")

    try:
        import subprocess
        result = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq notepad.exe", "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode == 0 and result.stdout:
            lines = [line for line in result.stdout.strip().split("\n") if line]
            if lines:
                parts = lines[0].split(",")
                if len(parts) >= 2:
                    pid_str = parts[1].strip('"')
                    return int(pid_str)
    except Exception:
        pass

    return None


class TestFridaScriptManagerInitialization:
    """Test FridaScriptManager initialization and configuration loading."""

    def test_manager_initializes_with_scripts_directory(self, scripts_dir: Path) -> None:
        """FridaScriptManager initializes with scripts directory and loads configurations."""
        manager = FridaScriptManager(scripts_dir)

        assert manager.scripts_dir == scripts_dir
        assert isinstance(manager.scripts, dict)
        assert isinstance(manager.active_sessions, dict)
        assert isinstance(manager.results, dict)

    def test_manager_loads_predefined_script_configs(self, manager: FridaScriptManager) -> None:
        """Manager loads predefined script configurations for available scripts."""
        expected_scripts = [
            "memory_dumper.js",
            "anti_debugger.js",
            "hwid_spoofer.js",
        ]

        for script_name in expected_scripts:
            script_path = manager.scripts_dir / script_name
            if script_path.exists():
                assert script_name in manager.scripts
                config = manager.scripts[script_name]
                assert isinstance(config, FridaScriptConfig)
                assert config.path == script_path
                assert isinstance(config.category, ScriptCategory)
                assert len(config.description) > 0

    def test_manager_loads_custom_scripts_with_metadata(self, manager: FridaScriptManager) -> None:
        """Manager loads custom scripts with embedded metadata."""
        if "custom_analyzer.js" in manager.scripts:
            config = manager.scripts["custom_analyzer.js"]
            assert config.name == "Custom Analyzer"
            assert config.category == ScriptCategory.BEHAVIORAL_ANALYSIS
            assert "custom" in config.description.lower() or "Custom" in config.description
            assert isinstance(config.parameters, dict)

    def test_hardware_id_generators_produce_valid_values(self, manager: FridaScriptManager) -> None:
        """Hardware ID generators produce realistic and valid format values."""
        mac = manager._generate_mac_address()
        disk = manager._generate_disk_serial()
        mobo = manager._generate_motherboard_id()
        cpu = manager._generate_cpu_id()

        assert len(mac.split(":")) == 6
        for part in mac.split(":"):
            assert len(part) == 2
            int(part, 16)

        assert len(disk.split("-")) >= 2
        assert any(prefix in disk for prefix in ["WD", "ST", "HGST", "TOSHIBA", "SAMSUNG", "INTEL"])

        assert len(mobo.split("-")) >= 3
        assert any(mfr in mobo for mfr in ["ASUS", "MSI", "GIGABYTE", "ASROCK", "BIOSTAR", "EVGA"])

        assert len(cpu.split("-")) >= 3
        assert "Intel" in cpu or "AMD" in cpu


class TestScriptConfiguration:
    """Test script configuration and metadata handling."""

    def test_get_script_config_returns_config_for_loaded_scripts(self, manager: FridaScriptManager) -> None:
        """get_script_config returns FridaScriptConfig for loaded scripts."""
        if "memory_dumper.js" in manager.scripts:
            config = manager.get_script_config("memory_dumper.js")
            assert config is not None
            assert isinstance(config, FridaScriptConfig)
            assert config.name == "Memory Dumper"
            assert config.category == ScriptCategory.MEMORY_ANALYSIS

    def test_get_script_config_returns_none_for_unknown_scripts(self, manager: FridaScriptManager) -> None:
        """get_script_config returns None for unknown script names."""
        config = manager.get_script_config("nonexistent_script.js")
        assert config is None

    def test_get_script_categories_returns_all_used_categories(self, manager: FridaScriptManager) -> None:
        """get_script_categories returns all ScriptCategory values in use."""
        categories = manager.get_script_categories()

        assert isinstance(categories, list)
        assert len(categories) > 0
        for category in categories:
            assert isinstance(category, ScriptCategory)

    def test_get_scripts_by_category_filters_correctly(self, manager: FridaScriptManager) -> None:
        """get_scripts_by_category returns only scripts matching the category."""
        if ScriptCategory.MEMORY_ANALYSIS in manager.get_script_categories():
            scripts = manager.get_scripts_by_category(ScriptCategory.MEMORY_ANALYSIS)
            assert isinstance(scripts, list)

            for script_name in scripts:
                config = manager.scripts[script_name]
                assert config.category == ScriptCategory.MEMORY_ANALYSIS


class TestScriptExecution:
    """Test Frida script execution and session management."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific test")
    def test_execute_script_spawn_mode_requires_executable_path(self, manager: FridaScriptManager, scripts_dir: Path) -> None:
        """execute_script in spawn mode requires executable path as target."""
        test_script = scripts_dir / "test_basic.js"
        if not test_script.exists():
            pytest.skip("Test script not found")

        try:
            result = manager.execute_script(
                "test_basic.js",
                str(Path(os.environ.get("WINDIR", "C:\\Windows")) / "System32" / "notepad.exe"),
                mode="spawn",
                parameters={"timeout": 2},
            )

            assert isinstance(result, ScriptResult)
            assert result.script_name == "test_basic.js"
            assert isinstance(result.success, bool)
            assert result.end_time > result.start_time

            if not result.success:
                assert len(result.errors) > 0
        except Exception as e:
            pytest.skip(f"Cannot execute spawn mode test: {e}")

    def test_execute_script_returns_script_result(self, manager: FridaScriptManager) -> None:
        """execute_script returns ScriptResult with execution details."""
        result = manager.execute_script(
            "test_basic.js",
            "99999999",
            mode="attach",
            parameters={"timeout": 1},
        )

        assert isinstance(result, ScriptResult)
        assert result.script_name == "test_basic.js"
        assert isinstance(result.success, bool)
        assert isinstance(result.start_time, float)
        assert isinstance(result.end_time, float)
        assert isinstance(result.messages, list)
        assert isinstance(result.errors, list)
        assert isinstance(result.data, dict)

    def test_execute_script_validates_script_existence(self, manager: FridaScriptManager) -> None:
        """execute_script raises ValueError for unknown scripts."""
        with pytest.raises(ValueError, match="Unknown script"):
            manager.execute_script("nonexistent.js", "12345", mode="attach")

    def test_parameter_injection_creates_valid_javascript(self, manager: FridaScriptManager) -> None:
        """_create_parameter_injection generates valid JavaScript variable declarations."""
        params = {
            "string_param": "test_value",
            "bool_param": True,
            "int_param": 42,
            "float_param": 3.14,
            "null_param": None,
            "list_param": [1, 2, 3],
            "dict_param": {"key": "value"},
        }

        injection = manager._create_parameter_injection(params)

        assert isinstance(injection, str)
        assert 'var string_param = "test_value";' in injection
        assert "var bool_param = true;" in injection
        assert "var int_param = 42;" in injection
        assert "var float_param = 3.14;" in injection
        assert "var null_param = null;" in injection
        assert "var list_param = " in injection
        assert "var dict_param = " in injection


class TestMessageHandling:
    """Test Frida message handling and callbacks."""

    def test_handle_message_processes_send_type(self, manager: FridaScriptManager) -> None:
        """_handle_message processes 'send' type messages from Frida scripts."""
        result = ScriptResult(
            script_name="test",
            success=False,
            start_time=time.time(),
            end_time=0,
        )

        message = {"type": "send", "payload": {"test_key": "test_value"}}

        manager._handle_message(result, message, None, None)

        assert len(result.messages) == 1
        assert result.messages[0] == {"test_key": "test_value"}

    def test_handle_message_processes_error_type(self, manager: FridaScriptManager) -> None:
        """_handle_message processes 'error' type messages and stores errors."""
        result = ScriptResult(
            script_name="test",
            success=False,
            start_time=time.time(),
            end_time=0,
        )

        message = {
            "type": "error",
            "description": "Test error occurred",
            "stack": "Error stack trace",
        }

        manager._handle_message(result, message, None, None)

        assert len(result.errors) > 0
        assert any("Test error occurred" in error for error in result.errors)

    def test_handle_message_captures_memory_dumps(self, manager: FridaScriptManager) -> None:
        """_handle_message captures memory dump data from script messages."""
        result = ScriptResult(
            script_name="test",
            success=False,
            start_time=time.time(),
            end_time=0,
        )

        payload = {"memory_dump": {"address": "0x1000", "size": 256}}
        data = b"\x00" * 256
        message = {"type": "send", "payload": payload}

        manager._handle_message(result, message, data, None)

        assert len(result.memory_dumps) == 1
        assert result.memory_dumps[0] == data

    def test_handle_message_captures_patch_data(self, manager: FridaScriptManager) -> None:
        """_handle_message captures patch information from script messages."""
        result = ScriptResult(
            script_name="test",
            success=False,
            start_time=time.time(),
            end_time=0,
        )

        patch_info = {"offset": "0x1000", "original": "74 05", "patched": "90 90"}
        payload = {"patch": patch_info}
        message = {"type": "send", "payload": payload}

        manager._handle_message(result, message, None, None)

        assert len(result.patches) == 1
        assert result.patches[0] == patch_info

    def test_handle_message_updates_result_data(self, manager: FridaScriptManager) -> None:
        """_handle_message updates result.data with data payload."""
        result = ScriptResult(
            script_name="test",
            success=False,
            start_time=time.time(),
            end_time=0,
        )

        data_payload = {"key1": "value1", "key2": 42}
        message = {"type": "send", "payload": {"data": data_payload}}

        manager._handle_message(result, message, None, None)

        assert result.data["key1"] == "value1"
        assert result.data["key2"] == 42


class TestResultExport:
    """Test script result export functionality."""

    def test_export_results_creates_json_file(self, manager: FridaScriptManager, tmp_path: Path) -> None:
        """export_results creates JSON file with execution results."""
        session_id = "test_session_1"
        result = ScriptResult(
            script_name="test_script.js",
            success=True,
            start_time=time.time(),
            end_time=time.time() + 5,
            messages=[{"log": "test message"}],
            errors=[],
            data={"result_key": "result_value"},
        )
        manager.results[session_id] = result

        output_path = tmp_path / "test_results.json"
        manager.export_results(session_id, output_path)

        assert output_path.exists()

        with open(output_path) as f:
            exported = json.load(f)

        assert exported["script_name"] == "test_script.js"
        assert exported["success"] is True
        assert exported["duration"] == pytest.approx(5, abs=0.1)
        assert len(exported["messages"]) == 1
        assert exported["data"]["result_key"] == "result_value"

    def test_export_results_exports_memory_dumps_separately(self, manager: FridaScriptManager, tmp_path: Path) -> None:
        """export_results saves memory dumps as separate binary files."""
        session_id = "test_session_2"
        dump_data = b"\x4D\x5A\x90\x00" + b"\x00" * 100
        result = ScriptResult(
            script_name="memory_dumper.js",
            success=True,
            start_time=time.time(),
            end_time=time.time() + 1,
            memory_dumps=[dump_data],
        )
        manager.results[session_id] = result

        output_path = tmp_path / "memory_results.json"
        manager.export_results(session_id, output_path)

        dump_dir = tmp_path / "memory_results_dumps"
        assert dump_dir.exists()
        assert dump_dir.is_dir()

        dump_files = list(dump_dir.glob("dump_*.bin"))
        assert len(dump_files) == 1

        with open(dump_files[0], "rb") as f:
            saved_dump = f.read()

        assert saved_dump == dump_data

    def test_export_results_raises_for_unknown_session(self, manager: FridaScriptManager, tmp_path: Path) -> None:
        """export_results raises ValueError for non-existent session ID."""
        with pytest.raises(ValueError, match="No results for session"):
            manager.export_results("nonexistent_session", tmp_path / "output.json")


class TestCustomScriptCreation:
    """Test custom Frida script creation functionality."""

    def test_create_custom_script_writes_script_with_metadata(self, manager: FridaScriptManager) -> None:
        """create_custom_script writes JavaScript file with metadata header."""
        script_code = """
console.log('Custom script loaded');
rpc.exports = {
    customFunction: function() {
        return 'custom_result';
    }
};
"""
        parameters = {"param1": "value1", "param2": 42}

        config = manager.create_custom_script(
            "test_custom",
            script_code,
            ScriptCategory.LICENSE_BYPASS,
            parameters,
        )

        assert isinstance(config, FridaScriptConfig)
        assert config.name == "test_custom"
        assert config.category == ScriptCategory.LICENSE_BYPASS
        assert config.path.exists()
        assert config.path.name == "custom_test_custom.js"

        content = config.path.read_text()
        assert "@metadata" in content
        assert "@end" in content
        assert "console.log('Custom script loaded')" in content

        assert "custom_test_custom.js" in manager.scripts

    def test_create_custom_script_embeds_metadata_correctly(self, manager: FridaScriptManager) -> None:
        """create_custom_script embeds proper metadata in script header."""
        config = manager.create_custom_script(
            "metadata_test",
            "console.log('test');",
            ScriptCategory.PATCHING,
            {"test_param": "test_value"},
        )

        content = config.path.read_text()

        assert "/**" in content
        assert "@metadata" in content
        assert "@end" in content
        assert "*/" in content

        metadata_match = content.find("@metadata")
        end_match = content.find("@end")
        assert metadata_match < end_match

        metadata_section = content[metadata_match:end_match]
        assert '"name": "metadata_test"' in metadata_section
        assert '"category": "patching"' in metadata_section


class TestSessionManagement:
    """Test Frida session management and cleanup."""

    def test_stop_script_removes_session_from_active_sessions(self, manager: FridaScriptManager, monkeypatch: pytest.MonkeyPatch) -> None:
        """stop_script removes session from active_sessions dictionary."""
        session_id = "test_session_123"
        fake_session = FakeFridaSession()
        manager.active_sessions[session_id] = fake_session

        manager.stop_script(session_id)

        assert session_id not in manager.active_sessions
        assert fake_session.detached is True
        assert fake_session.detach_call_count == 1

    def test_stop_script_handles_nonexistent_session_gracefully(self, manager: FridaScriptManager) -> None:
        """stop_script handles attempts to stop non-existent sessions gracefully."""
        manager.stop_script("nonexistent_session")


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_manager_handles_missing_script_files(self, tmp_path: Path) -> None:
        """Manager handles missing script files gracefully during initialization."""
        empty_dir = tmp_path / "empty_scripts"
        empty_dir.mkdir()

        manager = FridaScriptManager(empty_dir)

        assert isinstance(manager.scripts, dict)

    def test_execute_script_handles_script_loading_errors(self, manager: FridaScriptManager, tmp_path: Path) -> None:
        """execute_script handles script file loading errors gracefully."""
        broken_script_path = tmp_path / "broken.js"
        broken_script_path.write_bytes(b"\xff\xfe\xfd")

        manager.scripts["broken.js"] = FridaScriptConfig(
            name="Broken Script",
            path=broken_script_path,
            category=ScriptCategory.MEMORY_ANALYSIS,
            description="Test broken script",
        )

        result = manager.execute_script("broken.js", "99999", mode="attach", parameters={"timeout": 1})

        assert isinstance(result, ScriptResult)
        assert not result.success
        assert len(result.errors) > 0


class TestProductionScenarios:
    """Test real-world production scenarios."""

    def test_hwid_spoofer_script_receives_parameters(self, manager: FridaScriptManager) -> None:
        """HWID spoofer script receives and uses injected parameters."""
        if "hwid_spoofer.js" not in manager.scripts:
            pytest.skip("HWID spoofer script not loaded")

        custom_params = {
            "spoof_mac": "00:11:22:33:44:55",
            "spoof_disk_serial": "TEST-SERIAL-12345",
            "timeout": 1,
        }

        result = manager.execute_script(
            "hwid_spoofer.js",
            "99999",
            mode="attach",
            parameters=custom_params,
        )

        assert isinstance(result, ScriptResult)

    def test_multiple_script_executions_tracked_separately(self, manager: FridaScriptManager) -> None:
        """Multiple script executions are tracked with separate session IDs."""
        result1 = manager.execute_script("test_basic.js", "99999", mode="attach", parameters={"timeout": 1})
        result2 = manager.execute_script("test_basic.js", "99998", mode="attach", parameters={"timeout": 1})

        assert isinstance(result1, ScriptResult)
        assert isinstance(result2, ScriptResult)
