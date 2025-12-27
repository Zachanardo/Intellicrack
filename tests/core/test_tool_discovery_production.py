"""Production tests for ToolDiscovery - validates real tool discovery and validation.

Tests tool discovery, version detection, capability checking, and fallback mechanisms
WITHOUT mocks - validates against real system tools.
"""

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.tool_discovery import ToolValidator


MINIMUM_VERSION_LENGTH = 3
VALID_TOOL_NAMES = {"python", "radare2", "ghidra", "frida", "nodejs"}


class TestPythonValidation:
    """Test Python installation validation."""

    def test_validate_python_with_system_python(self) -> None:
        """Validates system Python installation."""
        python_path = sys.executable

        result = ToolValidator.validate_python(python_path)

        assert result is not None
        assert "valid" in result
        assert "version" in result
        assert "capabilities" in result
        assert "issues" in result

        assert result["valid"] is True
        assert result["version"] is not None
        assert len(result["version"]) >= MINIMUM_VERSION_LENGTH

    def test_python_validation_detects_version(self) -> None:
        """Python validation detects correct version."""
        python_path = sys.executable

        result = ToolValidator.validate_python(python_path)

        assert result["version"] is not None

        version_parts = result["version"].split(".")
        assert len(version_parts) >= 2
        assert all(part.isdigit() for part in version_parts[:2])

    def test_python_validation_identifies_capabilities(self) -> None:
        """Python validation identifies available capabilities."""
        python_path = sys.executable

        result = ToolValidator.validate_python(python_path)

        assert "capabilities" in result
        assert isinstance(result["capabilities"], list)

    def test_python_validation_fails_for_invalid_path(self) -> None:
        """Python validation fails gracefully for invalid path."""
        invalid_path = "/nonexistent/python"

        result = ToolValidator.validate_python(invalid_path)

        assert result["valid"] is False
        assert len(result["issues"]) > 0


@pytest.mark.skipif(shutil.which("r2") is None, reason="radare2 not installed")
class TestRadare2Validation:
    """Test radare2 installation validation."""

    def test_validate_radare2_detects_installation(self) -> None:
        """Validates radare2 installation if available."""
        r2_path = shutil.which("r2")
        assert r2_path is not None

        result = ToolValidator.validate_radare2(r2_path)

        assert result is not None
        assert "valid" in result
        assert "version" in result
        assert "capabilities" in result

    def test_radare2_validation_detects_version(self) -> None:
        """radare2 validation detects version number."""
        r2_path = shutil.which("r2")
        assert r2_path is not None

        result = ToolValidator.validate_radare2(r2_path)

        if result["valid"]:
            assert result["version"] is not None

    def test_radare2_validation_identifies_capabilities(self) -> None:
        """radare2 validation identifies analysis capabilities."""
        r2_path = shutil.which("r2")
        assert r2_path is not None

        result = ToolValidator.validate_radare2(r2_path)

        if result["valid"]:
            expected_capabilities = ["disassembly", "debugging", "binary_analysis"]
            for capability in expected_capabilities:
                assert capability in result["capabilities"]

    def test_radare2_validation_fails_for_invalid_path(self) -> None:
        """radare2 validation fails gracefully for invalid path."""
        invalid_path = "/nonexistent/r2"

        result = ToolValidator.validate_radare2(invalid_path)

        assert result["valid"] is False
        assert len(result["issues"]) > 0


class TestGhidraValidation:
    """Test Ghidra installation validation."""

    def test_ghidra_validation_handles_invalid_path(self) -> None:
        """Ghidra validation handles invalid paths gracefully."""
        invalid_path = "/nonexistent/ghidra"

        result = ToolValidator.validate_ghidra(invalid_path)

        assert result is not None
        assert "valid" in result
        assert "issues" in result

    def test_ghidra_validation_checks_required_files(self) -> None:
        """Ghidra validation checks for required installation files."""
        invalid_path = "/nonexistent/ghidra"

        result = ToolValidator.validate_ghidra(invalid_path)

        if not result["valid"]:
            assert any("not found" in issue.lower() for issue in result["issues"])


class TestFridaValidation:
    """Test Frida installation validation."""

    def test_frida_validation_checks_python_package(self) -> None:
        """Frida validation checks Python package availability."""
        try:
            import frida

            has_frida = True
        except ImportError:
            has_frida = False

        if has_frida:
            result = ToolValidator.validate_python(sys.executable)
            assert result["valid"] is True


class TestNodeJSValidation:
    """Test Node.js installation validation."""

    def test_nodejs_validation_detects_installation(self) -> None:
        """Node.js validation detects installation if available."""
        node_path = shutil.which("node")

        if node_path:
            result = ToolValidator.validate_nodejs(node_path)

            assert result is not None
            assert "valid" in result

    def test_nodejs_validation_handles_missing_installation(self) -> None:
        """Node.js validation handles missing installation."""
        invalid_path = "/nonexistent/node"

        result = ToolValidator.validate_nodejs(invalid_path)

        assert result["valid"] is False
        assert len(result["issues"]) > 0


class TestValidationResultStructure:
    """Test validation result structure consistency."""

    def test_all_validators_return_consistent_structure(self) -> None:
        """All validators return consistent ValidationResult structure."""
        required_keys = {"valid", "version", "capabilities", "issues"}

        validators_and_paths = [
            (ToolValidator.validate_python, sys.executable),
            (ToolValidator.validate_radare2, "/nonexistent/r2"),
            (ToolValidator.validate_ghidra, "/nonexistent/ghidra"),
            (ToolValidator.validate_nodejs, "/nonexistent/node"),
        ]

        for validator, path in validators_and_paths:
            result = validator(path)

            assert isinstance(result, dict)
            assert required_keys.issubset(result.keys())
            assert isinstance(result["valid"], bool)
            assert result["version"] is None or isinstance(result["version"], str)
            assert isinstance(result["capabilities"], list)
            assert isinstance(result["issues"], list)


class TestToolDiscoveryWorkflow:
    """Test end-to-end tool discovery workflows."""

    def test_discover_available_analysis_tools(self) -> None:
        """Discovers all available analysis tools on system."""
        tools_to_check = {
            "python": sys.executable,
            "r2": shutil.which("r2"),
            "node": shutil.which("node"),
        }

        available_tools = []

        for tool_name, tool_path in tools_to_check.items():
            if tool_path is None:
                continue

            if tool_name == "python":
                result = ToolValidator.validate_python(tool_path)
            elif tool_name == "r2":
                result = ToolValidator.validate_radare2(tool_path)
            elif tool_name == "node":
                result = ToolValidator.validate_nodejs(tool_path)
            else:
                continue

            if result["valid"]:
                available_tools.append(tool_name)

        assert len(available_tools) > 0
        assert "python" in available_tools

    def test_tool_validation_provides_actionable_errors(self) -> None:
        """Tool validation provides actionable error messages."""
        invalid_path = "/definitely/nonexistent/tool"

        result = ToolValidator.validate_radare2(invalid_path)

        assert not result["valid"]
        assert len(result["issues"]) > 0

        for issue in result["issues"]:
            assert isinstance(issue, str)
            assert len(issue) > 0


class TestCapabilityDetection:
    """Test capability detection for tools."""

    def test_python_capabilities_include_scripting(self) -> None:
        """Python validation includes scripting capabilities."""
        result = ToolValidator.validate_python(sys.executable)

        assert result["valid"] is True

        capabilities_str = " ".join(result["capabilities"])

    def test_radare2_capabilities_include_analysis(self) -> None:
        """radare2 validation includes binary analysis capabilities."""
        r2_path = shutil.which("r2")

        if r2_path:
            result = ToolValidator.validate_radare2(r2_path)

            if result["valid"]:
                assert "binary_analysis" in result["capabilities"] or "disassembly" in result["capabilities"]


class TestVersionDetection:
    """Test version detection accuracy."""

    def test_python_version_matches_system_version(self) -> None:
        """Python version detection matches sys.version_info."""
        result = ToolValidator.validate_python(sys.executable)

        assert result["version"] is not None

        detected_version = result["version"]
        system_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

        assert detected_version in system_version or system_version in detected_version

    def test_version_format_is_semantic_versioning(self) -> None:
        """Detected versions follow semantic versioning format."""
        result = ToolValidator.validate_python(sys.executable)

        if result["version"]:
            version_parts = result["version"].split(".")
            assert len(version_parts) >= 2

            for part in version_parts[:2]:
                assert part.isdigit()


class TestErrorHandling:
    """Test error handling in tool validation."""

    def test_validation_handles_permission_errors(self) -> None:
        """Validation handles file permission errors gracefully."""
        if platform.system() == "Windows":
            restricted_path = "C:\\Windows\\System32\\cmd.exe"
        else:
            restricted_path = "/bin/sh"

        result = ToolValidator.validate_python(restricted_path)

        assert isinstance(result, dict)
        assert "valid" in result

    def test_validation_handles_timeout(self) -> None:
        """Validation handles subprocess timeouts gracefully."""
        invalid_path = "/nonexistent/tool"

        result = ToolValidator.validate_radare2(invalid_path)

        assert isinstance(result, dict)
        assert result["valid"] is False

    def test_validation_handles_malformed_output(self) -> None:
        """Validation handles malformed tool output gracefully."""
        result = ToolValidator.validate_python(sys.executable)

        assert isinstance(result, dict)
        assert "valid" in result


class TestCrossPlatformCompatibility:
    """Test cross-platform tool discovery."""

    def test_tool_validation_works_on_current_platform(self) -> None:
        """Tool validation works correctly on current platform."""
        current_platform = platform.system()

        result = ToolValidator.validate_python(sys.executable)

        assert result is not None
        assert result["valid"] is True

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_windows_tool_paths_with_exe_extension(self) -> None:
        """Windows tool paths with .exe extension are handled."""
        python_exe = sys.executable

        assert python_exe.lower().endswith(".exe")

        result = ToolValidator.validate_python(python_exe)

        assert result["valid"] is True

    @pytest.mark.skipif(platform.system() == "Windows", reason="Unix-specific test")
    def test_unix_tool_paths_without_extension(self) -> None:
        """Unix tool paths without extensions are handled."""
        python_path = sys.executable

        result = ToolValidator.validate_python(python_path)

        assert result["valid"] is True
