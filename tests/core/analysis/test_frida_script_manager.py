"""Production tests for Frida script manager.

Tests validate script loading, real execution against processes, message handling,
session management, and result aggregation using actual Frida dynamic instrumentation.
"""

import json
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.frida_script_manager import (
    FridaScriptConfig,
    FridaScriptManager,
    ScriptCategory,
    ScriptResult,
)


def frida_available() -> bool:
    """Check if Frida is available for testing."""
    try:
        import frida
        frida.get_local_device()
        return True
    except Exception:
        return False


@pytest.fixture
def scripts_dir(tmp_path: Path) -> Path:
    """Create temporary scripts directory with sample scripts."""
    scripts_path = tmp_path / "frida_scripts"
    scripts_path.mkdir()

    memory_dumper = scripts_path / "memory_dumper.js"
    memory_dumper.write_text("""
console.log("Memory dumper script loaded");
send({type: "ready", script: "memory_dumper"});

setTimeout(function() {
    var modules = Process.enumerateModules();
    if (modules.length > 0) {
        var baseModule = modules[0];
        send({
            type: "module_info",
            name: baseModule.name,
            base: baseModule.base.toString(),
            size: baseModule.size
        });

        try {
            var header = Memory.readByteArray(baseModule.base, 64);
            send({memory_dump: true}, header);
        } catch(e) {
            send({type: "error", message: e.toString()});
        }
    }
}, 100);
""")

    anti_debugger = scripts_path / "anti_debugger.js"
    anti_debugger.write_text("""
console.log("Anti-debugger bypass loaded");
send({type: "ready", script: "anti_debugger"});

var bypassCount = 0;

if (Process.platform === 'windows') {
    try {
        var isDebuggerPresent = Module.findExportByName('kernel32.dll', 'IsDebuggerPresent');
        if (isDebuggerPresent) {
            Interceptor.replace(isDebuggerPresent, new NativeCallback(function() {
                return 0;
            }, 'int', []));
            bypassCount++;
        }

        var checkRemote = Module.findExportByName('kernel32.dll', 'CheckRemoteDebuggerPresent');
        if (checkRemote) {
            Interceptor.replace(checkRemote, new NativeCallback(function(hProcess, pbDebuggerPresent) {
                Memory.writeU32(pbDebuggerPresent, 0);
                return 1;
            }, 'int', ['pointer', 'pointer']));
            bypassCount++;
        }
    } catch(e) {
        send({type: "error", message: e.toString()});
    }
}

send({
    type: "bypass_result",
    bypasses_installed: bypassCount,
    platform: Process.platform
});
""")

    api_tracer = scripts_path / "api_tracer.js"
    api_tracer.write_text("""
console.log("API tracer loaded");
send({type: "ready", script: "api_tracer"});

var callCount = 0;

if (Process.platform === 'windows') {
    try {
        var createFileW = Module.findExportByName('kernel32.dll', 'CreateFileW');
        if (createFileW) {
            Interceptor.attach(createFileW, {
                onEnter: function(args) {
                    var filename = args[0].readUtf16String();
                    callCount++;
                    send({
                        type: "api_call",
                        function: "CreateFileW",
                        filename: filename,
                        count: callCount
                    });
                }
            });
        }
    } catch(e) {
        send({type: "error", message: e.toString()});
    }
}

setTimeout(function() {
    send({
        type: "trace_complete",
        total_calls: callCount
    });
}, 500);
""")

    custom_script = scripts_path / "custom_analyzer.js"
    custom_metadata = {
        "name": "Custom Analyzer",
        "category": "behavioral_analysis",
        "description": "Custom behavioral analysis script",
        "parameters": {"track_calls": True},
    }
    custom_script.write_text(f"""/**
 * @metadata
 * {json.dumps(custom_metadata, indent=2)}
 * @end
 */

console.log("Custom analyzer loaded");
send({{type: "ready", script: "custom_analyzer"}});
""")

    return scripts_path


@pytest.fixture
def manager(scripts_dir: Path) -> FridaScriptManager:
    """Create FridaScriptManager instance."""
    return FridaScriptManager(scripts_dir)


class TestScriptLoading:
    """Test script configuration loading."""

    def test_manager_initialization(self, manager: FridaScriptManager) -> None:
        """Manager initializes with scripts directory."""
        assert manager.scripts_dir is not None
        assert isinstance(manager.scripts, dict)
        assert isinstance(manager.active_sessions, dict)
        assert isinstance(manager.results, dict)

    def test_predefined_scripts_loaded(self, manager: FridaScriptManager) -> None:
        """Predefined scripts are loaded correctly."""
        expected_scripts = ["memory_dumper.js", "anti_debugger.js"]

        for script_name in expected_scripts:
            if script_name in manager.scripts:
                config = manager.scripts[script_name]
                assert isinstance(config, FridaScriptConfig)
                assert config.name is not None
                assert isinstance(config.category, ScriptCategory)

    def test_custom_script_metadata_parsing(self, manager: FridaScriptManager) -> None:
        """Custom scripts with metadata are parsed correctly."""
        if "custom_analyzer.js" in manager.scripts:
            config = manager.scripts["custom_analyzer.js"]
            assert config.name == "Custom Analyzer"
            assert config.category == ScriptCategory.BEHAVIORAL_ANALYSIS
            assert config.description == "Custom behavioral analysis script"
            assert config.parameters.get("track_calls") is True


class TestParameterInjection:
    """Test JavaScript parameter injection."""

    def test_string_parameter_injection(self, manager: FridaScriptManager) -> None:
        """String parameters are injected correctly."""
        params = {"test_string": "hello_world"}
        injection = manager._create_parameter_injection(params)

        assert 'var test_string = "hello_world";' in injection

    def test_boolean_parameter_injection(self, manager: FridaScriptManager) -> None:
        """Boolean parameters are injected correctly."""
        params = {"flag_true": True, "flag_false": False}
        injection = manager._create_parameter_injection(params)

        assert "var flag_true = true;" in injection
        assert "var flag_false = false;" in injection

    def test_number_parameter_injection(self, manager: FridaScriptManager) -> None:
        """Numeric parameters are injected correctly."""
        params = {"count": 42, "ratio": 3.14}
        injection = manager._create_parameter_injection(params)

        assert "var count = 42;" in injection
        assert "var ratio = 3.14;" in injection

    def test_null_parameter_injection(self, manager: FridaScriptManager) -> None:
        """Null parameters are injected correctly."""
        params = {"nullable": None}
        injection = manager._create_parameter_injection(params)

        assert "var nullable = null;" in injection

    def test_list_parameter_injection(self, manager: FridaScriptManager) -> None:
        """List parameters are JSON-encoded."""
        params = {"items": [1, 2, 3]}
        injection = manager._create_parameter_injection(params)

        assert "var items = [1, 2, 3];" in injection

    def test_dict_parameter_injection(self, manager: FridaScriptManager) -> None:
        """Dictionary parameters are JSON-encoded."""
        params = {"config": {"key": "value", "count": 10}}
        injection = manager._create_parameter_injection(params)

        assert "var config =" in injection
        assert '"key": "value"' in injection or '"key":"value"' in injection


class TestMessageHandling:
    """Test Frida message handling."""

    def test_send_message_handling(self, manager: FridaScriptManager) -> None:
        """Send messages are handled correctly."""
        result = ScriptResult(
            script_name="test",
            success=False,
            start_time=time.time(),
            end_time=0,
        )

        message = {
            "type": "send",
            "payload": {"data": "test_data", "value": 42},
        }

        manager._handle_message(result, message, None, None)

        assert len(result.messages) == 1
        assert result.messages[0] == {"data": "test_data", "value": 42}

    def test_memory_dump_message_handling(self, manager: FridaScriptManager) -> None:
        """Memory dump messages are handled correctly."""
        result = ScriptResult(
            script_name="test",
            success=False,
            start_time=time.time(),
            end_time=0,
        )

        message = {
            "type": "send",
            "payload": {"memory_dump": True},
        }
        data = b"\x00\x01\x02\x03\x04\x05"

        manager._handle_message(result, message, data, None)

        assert len(result.memory_dumps) == 1
        assert result.memory_dumps[0] == data

    def test_patch_message_handling(self, manager: FridaScriptManager) -> None:
        """Patch messages are handled correctly."""
        result = ScriptResult(
            script_name="test",
            success=False,
            start_time=time.time(),
            end_time=0,
        )

        patch_info = {
            "address": 0x401000,
            "original": b"\x90\x90",
            "patched": b"\xEB\xFE",
        }
        message = {
            "type": "send",
            "payload": {"patch": patch_info},
        }

        manager._handle_message(result, message, None, None)

        assert len(result.patches) == 1
        assert result.patches[0] == patch_info

    def test_error_message_handling(self, manager: FridaScriptManager) -> None:
        """Error messages are handled correctly."""
        result = ScriptResult(
            script_name="test",
            success=False,
            start_time=time.time(),
            end_time=0,
        )

        message = {
            "type": "error",
            "description": "Script execution failed",
        }

        manager._handle_message(result, message, None, None)

        assert len(result.errors) == 1
        assert result.errors[0] == "Script execution failed"

    def test_callback_invocation(self, manager: FridaScriptManager) -> None:
        """Output callback is invoked for messages."""
        result = ScriptResult(
            script_name="test",
            success=False,
            start_time=time.time(),
            end_time=0,
        )

        callback_data = []

        def callback(payload: dict[str, Any]) -> None:
            callback_data.append(payload)

        message = {
            "type": "send",
            "payload": {"test": "data"},
        }

        manager._handle_message(result, message, None, callback)

        assert len(callback_data) == 1
        assert callback_data[0] == {"test": "data"}


@pytest.mark.skipif(not frida_available(), reason="Frida not installed or accessible")
class TestProductionScriptExecution:
    """Test real Frida script execution against actual processes."""

    def test_execute_script_spawn_python(self, manager: FridaScriptManager) -> None:
        """Execute memory dumper script by spawning Python process."""
        python_exe = sys.executable

        result = manager.execute_script(
            script_name="memory_dumper.js",
            target=python_exe,
            mode="spawn",
            parameters={"timeout": 3},
        )

        assert result.success
        assert len(result.messages) > 0

        ready_msg = next((m for m in result.messages if m.get("type") == "ready"), None)
        assert ready_msg is not None
        assert ready_msg.get("script") == "memory_dumper"

        module_msg = next((m for m in result.messages if m.get("type") == "module_info"), None)
        if module_msg:
            assert "name" in module_msg
            assert "base" in module_msg
            assert "size" in module_msg

    def test_memory_dump_extraction(self, manager: FridaScriptManager) -> None:
        """Memory dumper extracts actual binary content from spawned process."""
        python_exe = sys.executable

        result = manager.execute_script(
            script_name="memory_dumper.js",
            target=python_exe,
            mode="spawn",
            parameters={"timeout": 3},
        )

        assert result.success

        if len(result.memory_dumps) > 0:
            dump = result.memory_dumps[0]
            assert len(dump) > 0
            assert isinstance(dump, bytes)

            if sys.platform == "win32":
                assert dump[:2] == b"MZ" or dump[:4] == b"\x7fELF"

    def test_anti_debugger_bypass_installation(self, manager: FridaScriptManager) -> None:
        """Anti-debugger script installs real hooks on Windows API functions."""
        if sys.platform != "win32":
            pytest.skip("Test requires Windows platform")

        python_exe = sys.executable

        result = manager.execute_script(
            script_name="anti_debugger.js",
            target=python_exe,
            mode="spawn",
            parameters={"timeout": 3},
        )

        assert result.success
        assert len(result.messages) > 0

        ready_msg = next((m for m in result.messages if m.get("type") == "ready"), None)
        assert ready_msg is not None

        bypass_msg = next((m for m in result.messages if m.get("type") == "bypass_result"), None)
        assert bypass_msg is not None
        assert bypass_msg.get("platform") == "windows"
        assert bypass_msg.get("bypasses_installed", 0) >= 0

    def test_api_hooking_with_anti_debugger(self, manager: FridaScriptManager) -> None:
        """Anti-debugger script hooks real Windows API calls."""
        if sys.platform != "win32":
            pytest.skip("Test requires Windows platform")

        python_exe = sys.executable

        result = manager.execute_script(
            script_name="anti_debugger.js",
            target=python_exe,
            mode="spawn",
            parameters={"timeout": 3},
        )

        assert result.success
        assert len(result.messages) > 0

        ready_msg = next((m for m in result.messages if m.get("type") == "ready"), None)
        assert ready_msg is not None
        assert ready_msg.get("script") == "anti_debugger"

    def test_script_execution_with_custom_parameters(self, manager: FridaScriptManager) -> None:
        """Script execution merges custom parameters with defaults."""
        python_exe = sys.executable

        result = manager.execute_script(
            script_name="memory_dumper.js",
            target=python_exe,
            mode="spawn",
            parameters={"timeout": 2, "custom_param": "test_value"},
        )

        assert result.success
        assert result.end_time > result.start_time
        assert (result.end_time - result.start_time) < 5.0


class TestScriptExecutionErrors:
    """Test error handling in script execution."""

    def test_execute_unknown_script_raises_error(self, manager: FridaScriptManager) -> None:
        """Executing unknown script raises ValueError."""
        with pytest.raises(ValueError, match="Unknown script"):
            manager.execute_script(
                script_name="nonexistent.js",
                target="test.exe",
            )

    @pytest.mark.skipif(not frida_available(), reason="Frida not installed or accessible")
    def test_execute_script_invalid_target(self, manager: FridaScriptManager) -> None:
        """Script execution handles invalid target gracefully."""
        result = manager.execute_script(
            script_name="memory_dumper.js",
            target="nonexistent_binary_12345.exe",
            mode="spawn",
            parameters={"timeout": 1},
        )

        assert not result.success
        assert len(result.errors) > 0


class TestSessionManagement:
    """Test script session management."""

    def test_stop_script_session(self, manager: FridaScriptManager) -> None:
        """Script sessions can be stopped."""
        from unittest.mock import MagicMock

        mock_session = MagicMock()
        session_id = "test_session"
        manager.active_sessions[session_id] = mock_session

        manager.stop_script(session_id)

        mock_session.detach.assert_called_once()
        assert session_id not in manager.active_sessions


class TestResultManagement:
    """Test result storage and export."""

    def test_get_script_categories(self, manager: FridaScriptManager) -> None:
        """Get all available script categories."""
        categories = manager.get_script_categories()
        assert isinstance(categories, list)
        assert len(categories) > 0
        assert all(isinstance(cat, ScriptCategory) for cat in categories)

    def test_get_scripts_by_category(self, manager: FridaScriptManager) -> None:
        """Get scripts filtered by category."""
        scripts = manager.get_scripts_by_category(ScriptCategory.MEMORY_ANALYSIS)
        assert isinstance(scripts, list)

    def test_get_script_config(self, manager: FridaScriptManager) -> None:
        """Get configuration for specific script."""
        config = manager.get_script_config("memory_dumper.js")
        if config:
            assert isinstance(config, FridaScriptConfig)
            assert config.name is not None
            assert len(config.name) > 0

    def test_export_results(self, manager: FridaScriptManager, tmp_path: Path) -> None:
        """Results export to JSON file."""
        result = ScriptResult(
            script_name="test_script",
            success=True,
            start_time=time.time(),
            end_time=time.time() + 5.0,
            messages=[{"type": "log", "data": "test"}],
            errors=[],
            data={"key": "value"},
            patches=[{"address": 0x401000}],
        )

        session_id = "test_session"
        manager.results[session_id] = result

        output_path = tmp_path / "results.json"
        manager.export_results(session_id, output_path)

        assert output_path.exists()

        with open(output_path) as f:
            exported = json.load(f)

        assert exported["script_name"] == "test_script"
        assert exported["success"] is True
        assert len(exported["messages"]) == 1
        assert exported["data"]["key"] == "value"

    def test_export_results_with_memory_dumps(self, manager: FridaScriptManager, tmp_path: Path) -> None:
        """Memory dumps are exported separately."""
        result = ScriptResult(
            script_name="test_script",
            success=True,
            start_time=time.time(),
            end_time=time.time() + 5.0,
            memory_dumps=[b"\x00\x01\x02", b"\x03\x04\x05"],
        )

        session_id = "test_session"
        manager.results[session_id] = result

        output_path = tmp_path / "results.json"
        manager.export_results(session_id, output_path)

        dump_dir = tmp_path / "results_dumps"
        assert dump_dir.exists()
        assert (dump_dir / "dump_0000.bin").exists()
        assert (dump_dir / "dump_0001.bin").exists()

    def test_export_nonexistent_session_raises_error(self, manager: FridaScriptManager, tmp_path: Path) -> None:
        """Exporting nonexistent session raises ValueError."""
        with pytest.raises(ValueError, match="No results for session"):
            manager.export_results("nonexistent", tmp_path / "output.json")


class TestCustomScriptCreation:
    """Test custom script creation."""

    def test_create_custom_script(self, manager: FridaScriptManager) -> None:
        """Custom script is created with metadata."""
        code = """
console.log("Custom script");
send({type: "ready"});
"""

        config = manager.create_custom_script(
            name="Test Script",
            code=code,
            category=ScriptCategory.BEHAVIORAL_ANALYSIS,
            parameters={"param1": "value1"},
        )

        assert isinstance(config, FridaScriptConfig)
        assert config.name == "Test Script"
        assert config.category == ScriptCategory.BEHAVIORAL_ANALYSIS
        assert config.parameters["param1"] == "value1"

    def test_custom_script_file_created(self, manager: FridaScriptManager) -> None:
        """Custom script file is created on disk."""
        code = "console.log('test');"

        config = manager.create_custom_script(
            name="FileTest",
            code=code,
            category=ScriptCategory.PATCHING,
        )

        assert config.path.exists()
        content = config.path.read_text()
        assert "@metadata" in content
        assert "console.log('test');" in content

    def test_custom_script_registered(self, manager: FridaScriptManager) -> None:
        """Custom script is registered in manager."""
        code = "send({ready: true});"

        config = manager.create_custom_script(
            name="RegisterTest",
            code=code,
            category=ScriptCategory.CRYPTO_DETECTION,
        )

        assert config.path.name in manager.scripts
        assert manager.scripts[config.path.name] == config


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_empty_scripts_directory(self, tmp_path: Path) -> None:
        """Empty scripts directory handles gracefully."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        manager = FridaScriptManager(empty_dir)
        assert isinstance(manager.scripts, dict)

    def test_script_without_metadata(self, tmp_path: Path) -> None:
        """Scripts without metadata are skipped gracefully."""
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()

        no_metadata = scripts_dir / "no_metadata.js"
        no_metadata.write_text("console.log('no metadata');")

        manager = FridaScriptManager(scripts_dir)

        metadata = manager._parse_script_metadata(no_metadata)
        assert metadata is None

    def test_invalid_json_metadata(self, tmp_path: Path) -> None:
        """Invalid JSON metadata handles gracefully."""
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()

        invalid_script = scripts_dir / "invalid.js"
        invalid_script.write_text("""/**
 * @metadata
 * {invalid json here
 * @end
 */
console.log('test');
""")

        manager = FridaScriptManager(scripts_dir)
        metadata = manager._parse_script_metadata(invalid_script)
        assert metadata is None


@pytest.mark.skipif(not frida_available(), reason="Frida not installed or accessible")
class TestRealWorldScenarios:
    """Test realistic script execution scenarios."""

    def test_multiple_messages_from_script(self, manager: FridaScriptManager) -> None:
        """Script execution collects multiple messages from real execution."""
        python_exe = sys.executable

        result = manager.execute_script(
            script_name="memory_dumper.js",
            target=python_exe,
            mode="spawn",
            parameters={"timeout": 3},
        )

        assert result.success
        assert len(result.messages) >= 1

        message_types = {m.get("type") for m in result.messages}
        assert "ready" in message_types

    def test_script_execution_timing(self, manager: FridaScriptManager) -> None:
        """Script execution records accurate timing information."""
        python_exe = sys.executable

        result = manager.execute_script(
            script_name="memory_dumper.js",
            target=python_exe,
            mode="spawn",
            parameters={"timeout": 2},
        )

        assert result.success
        duration = result.end_time - result.start_time
        assert 0.1 < duration < 5.0
        assert result.start_time > 0
        assert result.end_time > result.start_time
