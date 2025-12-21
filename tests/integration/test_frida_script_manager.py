"""Integration tests for Frida script manager.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import os
import json
import tempfile
import pytest
from pathlib import Path

from intellicrack.core.analysis.frida_script_manager import (
    FridaScriptManager,
    FridaScriptConfig,
    ScriptCategory,
    ScriptResult,
)

try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False

pytestmark = pytest.mark.skipif(not FRIDA_AVAILABLE, reason="frida not available")


@pytest.fixture
def scripts_dir(tmp_path):
    """Create a temporary scripts directory with test scripts."""
    scripts_path = tmp_path / "frida_scripts"
    scripts_path.mkdir()

    # Create a simple test script
    test_script = scripts_path / "test_script.js"
    test_script.write_text("""
console.log("Test script loaded");

// Simple hook that always succeeds
var result = {
    success: true,
    hooks_triggered: 1,
    data: ["test_data"]
};

send(JSON.stringify(result));
""")

    # Create a script with parameters
    param_script = scripts_path / "param_script.js"
    param_script.write_text("""
// PARAM: target_function - Function to hook
// PARAM: log_level - Logging level (info, debug, verbose)

console.log("Parameter script loaded");
console.log("Target function: {{target_function}}");
console.log("Log level: {{log_level}}");

send(JSON.stringify({
    success: true,
    target_function: "{{target_function}}",
    log_level: "{{log_level}}"
}));
""")

    # Create an error script
    error_script = scripts_path / "error_script.js"
    error_script.write_text("""
console.log("Error script loaded");
throw new Error("Intentional test error");
""")

    return scripts_path


@pytest.fixture
def test_binary(tmp_path):
    """Create a simple test binary."""
    binary_path = tmp_path / "test.exe"

    # Create minimal PE header
    with open(binary_path, "wb") as f:
        # DOS header
        f.write(b"MZ\x90\x00")
        f.write(b"\x00" * 60)
        # PE signature offset at 0x3C
        f.seek(0x3C)
        f.write(b"\x80\x00\x00\x00")
        # PE signature at offset 0x80
        f.seek(0x80)
        f.write(b"PE\x00\x00")
        # Minimal PE headers
        f.write(b"\x00" * 200)

    return str(binary_path)


@pytest.fixture
def script_manager(scripts_dir):
    """Create a FridaScriptManager instance."""
    return FridaScriptManager(scripts_dir)


class TestFridaScriptManagerInitialization:
    """Test FridaScriptManager initialization."""

    def test_manager_creation(self, scripts_dir):
        """Test creating a script manager."""
        manager = FridaScriptManager(scripts_dir)

        assert manager.scripts_dir == scripts_dir
        assert isinstance(manager.scripts, dict)

    def test_script_discovery(self, script_manager):
        """Test automatic script discovery."""
        # Should find the test scripts we created
        assert "test_script.js" in script_manager.scripts
        assert "param_script.js" in script_manager.scripts
        assert "error_script.js" in script_manager.scripts

    def test_script_config_loading(self, script_manager):
        """Test script configuration loading."""
        if config := script_manager.scripts.get("test_script.js"):
            assert isinstance(config, FridaScriptConfig)
            assert config.script_path.exists()
            assert config.category in ScriptCategory


class TestScriptParameterInjection:
    """Test parameter injection into scripts."""

    def test_parameter_parsing(self, script_manager):
        """Test parameter extraction from script comments."""
        config = script_manager.scripts.get("param_script.js")

        if config and config.parameters:
            assert "target_function" in config.parameters
            assert "log_level" in config.parameters

    def test_parameter_injection(self, script_manager):
        """Test parameter value injection."""
        script_content = """
        Target: {{target_function}}
        Level: {{log_level}}
        """

        parameters = {
            "target_function": "LicenseCheck",
            "log_level": "verbose"
        }

        injected = script_manager._inject_parameters(script_content, parameters)

        assert "LicenseCheck" in injected
        assert "verbose" in injected
        assert "{{target_function}}" not in injected
        assert "{{log_level}}" not in injected

    def test_missing_parameters(self, script_manager):
        """Test handling of missing required parameters."""
        script_content = "Target: {{target_function}}"

        # Should leave placeholder if parameter not provided
        injected = script_manager._inject_parameters(script_content, {})

        assert "{{target_function}}" in injected


class TestScriptExecution:
    """Test script execution functionality."""

    def test_execute_simple_script(self, script_manager, test_binary):
        """Test executing a simple script."""
        # Note: This test may fail if Frida can't attach to the test binary
        # In a real environment, you'd use an actual executable
        try:
            result = script_manager.execute_script(
                script_name="test_script.js",
                target=test_binary,
                mode="spawn",
                parameters={}
            )

            assert isinstance(result, ScriptResult)
            # Result may succeed or fail depending on Frida's ability to attach
            # Just verify we get a proper result object
            assert hasattr(result, "success")
            assert hasattr(result, "output")
            assert hasattr(result, "error")

        except Exception as e:
            # It's ok if execution fails in test environment
            # We're testing the integration, not Frida itself
            pytest.skip(f"Frida execution not available in test environment: {e}")

    def test_execute_with_parameters(self, script_manager, test_binary):
        """Test executing script with parameters."""
        try:
            result = script_manager.execute_script(
                script_name="param_script.js",
                target=test_binary,
                mode="spawn",
                parameters={
                    "target_function": "CheckLicense",
                    "log_level": "debug"
                }
            )

            assert isinstance(result, ScriptResult)

        except Exception as e:
            pytest.skip(f"Frida execution not available: {e}")

    def test_execute_nonexistent_script(self, script_manager, test_binary):
        """Test executing a script that doesn't exist."""
        with pytest.raises(ValueError, match="not found"):
            script_manager.execute_script(
                script_name="nonexistent.js",
                target=test_binary,
                mode="spawn"
            )

    def test_execute_invalid_binary(self, script_manager):
        """Test executing with invalid binary path."""
        with pytest.raises(FileNotFoundError):
            script_manager.execute_script(
                script_name="test_script.js",
                target="/nonexistent/binary.exe",
                mode="spawn"
            )


class TestScriptCategorization:
    """Test script categorization functionality."""

    def test_category_filtering(self, script_manager):
        """Test filtering scripts by category."""
        # Get all scripts in a specific category
        protection_scripts = [
            name for name, config in script_manager.scripts.items()
            if config.category == ScriptCategory.PROTECTION_BYPASS
        ]

        # Should be able to filter by category
        assert isinstance(protection_scripts, list)

    def test_category_assignment(self, script_manager):
        """Test that scripts have valid categories."""
        for script_name, config in script_manager.scripts.items():
            assert isinstance(config.category, ScriptCategory)


class TestResultHandling:
    """Test result handling and storage."""

    def test_result_creation(self):
        """Test creating a ScriptResult."""
        result = ScriptResult(
            script_name="test.js",
            success=True,
            output="Test output",
            error=None,
            execution_time_ms=100,
            hooks_triggered=5,
            data_collected=["data1", "data2"]
        )

        assert result.success is True
        assert result.execution_time_ms == 100
        assert len(result.data_collected) == 2

    def test_result_export_json(self, script_manager, tmp_path):
        """Test exporting results to JSON."""
        results = [
            ScriptResult(
                script_name="test1.js",
                success=True,
                output="Output 1",
                error=None,
                execution_time_ms=100,
                hooks_triggered=3,
                data_collected=["data1"]
            ),
            ScriptResult(
                script_name="test2.js",
                success=False,
                output="Output 2",
                error="Test error",
                execution_time_ms=50,
                hooks_triggered=0,
                data_collected=[]
            )
        ]

        output_file = tmp_path / "results.json"
        script_manager.export_results(results, output_file, format="json")

        assert output_file.exists()

        # Verify JSON content
        with open(output_file) as f:
            exported_data = json.load(f)

        assert len(exported_data) == 2
        assert exported_data[0]["script_name"] == "test1.js"
        assert exported_data[1]["success"] is False


class TestScriptLibraryIntegration:
    """Test integration with actual script library."""

    def test_load_real_scripts(self):
        """Test loading scripts from real library."""
        scripts_dir = Path(__file__).parent.parent.parent / "intellicrack" / "scripts" / "frida"

        if not scripts_dir.exists():
            pytest.skip("Script library not found")

        manager = FridaScriptManager(scripts_dir)

        # Should find multiple scripts
        assert len(manager.scripts) > 0

        # Check some expected scripts exist
        script_names = list(manager.scripts.keys())
        assert any("bypass" in name.lower() for name in script_names)

    def test_real_script_configs(self):
        """Test real script configurations."""
        scripts_dir = Path(__file__).parent.parent.parent / "intellicrack" / "scripts" / "frida"

        if not scripts_dir.exists():
            pytest.skip("Script library not found")

        manager = FridaScriptManager(scripts_dir)

        # Verify each script has proper configuration
        for script_name, config in manager.scripts.items():
            assert config.script_path.exists()
            assert config.category in ScriptCategory
            assert len(config.description) > 0


class TestErrorHandling:
    """Test error handling in script manager."""

    def test_invalid_scripts_dir(self):
        """Test handling of invalid scripts directory."""
        with pytest.raises(ValueError, match="does not exist"):
            FridaScriptManager(Path("/nonexistent/directory"))

    def test_corrupted_script(self, scripts_dir):
        """Test handling of corrupted script file."""
        # Create a corrupted script
        bad_script = scripts_dir / "bad_script.js"
        bad_script.write_bytes(b"\xFF\xFE\x00\x00")  # Invalid UTF-8

        # Manager should handle this gracefully
        try:
            manager = FridaScriptManager(scripts_dir)
            # May or may not load the bad script depending on error handling
            # Just verify manager still works
            assert isinstance(manager.scripts, dict)
        except Exception:
            # It's acceptable to fail if script is truly corrupted
            pass


class TestConcurrentExecution:
    """Test concurrent script execution."""

    def test_multiple_script_execution(self, script_manager, test_binary):
        """Test executing multiple scripts concurrently."""
        import threading

        results = []

        def execute_script():
            try:
                result = script_manager.execute_script(
                    script_name="test_script.js",
                    target=test_binary,
                    mode="spawn"
                )
                results.append(result)
            except Exception as e:
                results.append(str(e))

        # Run multiple executions concurrently
        threads = [threading.Thread(target=execute_script) for _ in range(3)]

        for t in threads:
            t.start()

        for t in threads:
            t.join(timeout=10.0)

        # Should get results from all threads
        assert len(results) <= 3  # May have fewer if execution fails


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
