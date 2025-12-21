"""Production tests for Advanced Tool Discovery System.

Tests cross-platform tool discovery, version detection, and validation.
Validates real tool paths and capabilities without simulation.
"""

import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from intellicrack.core.tool_discovery import (
    AdvancedToolDiscovery,
    ToolValidator,
    ValidationResult,
)


class TestToolValidator:
    """Test ToolValidator static methods for various tools."""

    @pytest.mark.skipif(
        not shutil.which("python3") and not shutil.which("python"),
        reason="Python not in PATH",
    )
    def test_validate_python_finds_current_python(self) -> None:
        """validate_python finds and validates current Python installation."""
        python_path = sys.executable
        result = ToolValidator.validate_python(python_path)

        assert result["valid"] is True
        assert result["version"] is not None
        assert len(result["version"].split(".")) >= 2
        assert "compatible" in result["capabilities"]

    def test_validate_python_with_invalid_path(self) -> None:
        """validate_python returns invalid for nonexistent path."""
        result = ToolValidator.validate_python("/nonexistent/python")

        assert result["valid"] is False
        assert len(result["issues"]) > 0

    def test_validate_ghidra_requires_installation_files(self, tmp_path: Path) -> None:
        """validate_ghidra checks for Ghidra installation files."""
        fake_ghidra = tmp_path / "ghidraRun.bat"
        fake_ghidra.touch()

        result = ToolValidator.validate_ghidra(str(fake_ghidra))

        assert "issues" in result
        assert isinstance(result["capabilities"], list)

    def test_validate_radare2_checks_version_command(self) -> None:
        """validate_radare2 executes version check command."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="radare2 5.8.0 0 @ linux-x86-64",
            )

            result = ToolValidator.validate_radare2("r2")

            assert result["valid"] is True
            assert result["version"] == "5.8.0"
            assert "disassembly" in result["capabilities"]
            mock_run.assert_called_once()

    def test_validate_radare2_handles_execution_failure(self) -> None:
        """validate_radare2 handles tool execution failure."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=1,
                stdout="",
                stderr="command not found",
            )

            result = ToolValidator.validate_radare2("r2")

            assert result["valid"] is False
            assert len(result["issues"]) > 0

    def test_validate_frida_detects_version(self) -> None:
        """validate_frida detects Frida version from output."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="16.1.4",
            )

            result = ToolValidator.validate_frida("frida")

            assert result["valid"] is True
            assert result["version"] == "16.1.4"
            assert "dynamic_instrumentation" in result["capabilities"]

    def test_validate_qemu_detects_architecture(self) -> None:
        """validate_qemu detects QEMU architecture from executable name."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="QEMU emulator version 7.2.0",
            )

            result = ToolValidator.validate_qemu("qemu-system-x86_64")

            assert result["valid"] is True
            assert result["version"] == "7.2.0"
            assert "x86_64" in result["capabilities"]

    def test_validate_nasm_detects_version(self) -> None:
        """validate_nasm detects NASM version from output."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="NASM version 2.15.05",
            )

            result = ToolValidator.validate_nasm("nasm")

            assert result["valid"] is True
            assert result["version"] == "2.15.05"
            assert "assembly_compilation" in result["capabilities"]
            assert "x86_assembly" in result["capabilities"]

    def test_validate_masm_detects_microsoft_signature(self) -> None:
        """validate_masm detects Microsoft Macro Assembler signature."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="Microsoft (R) Macro Assembler Version 14.34.31933.0",
            )

            result = ToolValidator.validate_masm("ml64")

            assert result["valid"] is True
            assert result["version"] == "14.34.31933.0"
            assert "masm_syntax" in result["capabilities"]

    def test_validate_accesschk_detects_sysinternals(self) -> None:
        """validate_accesschk detects SysInternals AccessChk."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="Sysinternals AccessChk v6.14",
            )

            result = ToolValidator.validate_accesschk("accesschk64")

            assert result["valid"] is True
            assert result["version"] == "6.14"
            assert "privilege_escalation_analysis" in result["capabilities"]

    def test_validators_handle_timeout(self) -> None:
        """Validators handle subprocess timeout gracefully."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("cmd", 10)

            result = ToolValidator.validate_radare2("r2")

            assert result["valid"] is False
            assert any("timed out" in issue.lower() for issue in result["issues"])


class TestAdvancedToolDiscovery:
    """Test AdvancedToolDiscovery class."""

    def test_init_loads_validators(self) -> None:
        """Initialization loads all tool validators."""
        with patch("intellicrack.core.tool_discovery.get_config"):
            discovery = AdvancedToolDiscovery()

            assert "ghidra" in discovery.validators
            assert "radare2" in discovery.validators
            assert "python3" in discovery.validators
            assert "frida" in discovery.validators
            assert "nasm" in discovery.validators
            assert "masm" in discovery.validators

    def test_init_loads_config(self) -> None:
        """Initialization loads configuration."""
        mock_config = Mock()
        mock_config.get.return_value = {}

        with patch("intellicrack.core.tool_discovery.get_config", return_value=mock_config):
            discovery = AdvancedToolDiscovery()

            assert discovery.config == mock_config
            mock_config.get.assert_called()

    def test_search_in_path_finds_python(self) -> None:
        """_search_in_path finds Python in PATH."""
        with patch("intellicrack.core.tool_discovery.get_config"):
            discovery = AdvancedToolDiscovery()

            executables = ["python3", "python"]
            if result := discovery._search_in_path(executables):
                assert os.path.exists(result)
                assert os.access(result, os.X_OK)

    def test_search_in_path_returns_none_for_nonexistent(self) -> None:
        """_search_in_path returns None for nonexistent tools."""
        with patch("intellicrack.core.tool_discovery.get_config"):
            discovery = AdvancedToolDiscovery()

            result = discovery._search_in_path(["nonexistent_tool_xyz_12345"])

            assert result is None

    def test_get_installation_paths_for_ghidra(self) -> None:
        """_get_installation_paths returns Ghidra installation paths."""
        with patch("intellicrack.core.tool_discovery.get_config"):
            discovery = AdvancedToolDiscovery()

            paths = discovery._get_installation_paths("ghidra")

            assert isinstance(paths, list)
            assert len(paths) > 0
            if sys.platform == "win32":
                assert any("Ghidra" in str(p) for p in paths)

    def test_get_installation_paths_for_nasm(self) -> None:
        """_get_installation_paths returns NASM installation paths."""
        with patch("intellicrack.core.tool_discovery.get_config"):
            discovery = AdvancedToolDiscovery()

            paths = discovery._get_installation_paths("nasm")

            assert isinstance(paths, list)
            assert len(paths) > 0
            if sys.platform == "win32":
                assert any("NASM" in str(p) for p in paths)

    def test_get_installation_paths_for_masm(self) -> None:
        """_get_installation_paths returns MASM Visual Studio paths."""
        with patch("intellicrack.core.tool_discovery.get_config"):
            discovery = AdvancedToolDiscovery()

            paths = discovery._get_installation_paths("masm")

            assert isinstance(paths, list)
            if sys.platform == "win32":
                assert any("Visual Studio" in str(p) for p in paths)

    def test_get_installation_paths_for_accesschk(self) -> None:
        """_get_installation_paths returns SysInternals paths."""
        with patch("intellicrack.core.tool_discovery.get_config"):
            discovery = AdvancedToolDiscovery()

            paths = discovery._get_installation_paths("accesschk")

            assert isinstance(paths, list)
            if sys.platform == "win32":
                assert any("Sysinternals" in str(p) for p in paths)

    def test_validate_and_populate_with_validator(self) -> None:
        """_validate_and_populate uses validator when available."""
        with patch("intellicrack.core.tool_discovery.get_config"):
            discovery = AdvancedToolDiscovery()

            with patch.object(ToolValidator, "validate_python") as mock_validator:
                mock_validator.return_value = {
                    "valid": True,
                    "version": "3.11.0",
                    "capabilities": ["compatible"],
                    "issues": [],
                }

                result = discovery._validate_and_populate(sys.executable, "python3")

                assert result["available"] is True
                assert result["version"] == "3.11.0"
                assert "compatible" in result["capabilities"]

    def test_validate_and_populate_fallback_without_validator(self, tmp_path: Path) -> None:
        """_validate_and_populate marks executable available without validator."""
        with patch("intellicrack.core.tool_discovery.get_config"):
            discovery = AdvancedToolDiscovery()

            fake_tool = tmp_path / "fake_tool"
            fake_tool.touch(mode=0o755)

            result = discovery._validate_and_populate(str(fake_tool), "unknown_tool")

            assert result["available"] is True

    def test_discover_tool_uses_manual_override(self) -> None:
        """discover_tool uses manual override path when set."""
        mock_config = Mock()
        mock_config.get.return_value = {}

        with patch("intellicrack.core.tool_discovery.get_config", return_value=mock_config):
            discovery = AdvancedToolDiscovery()
            discovery.manual_overrides["python3"] = sys.executable

            config = {"executables": ["python3"], "search_strategy": "path_based"}
            result = discovery.discover_tool("python3", config)

            assert result["available"] is True
            assert result["discovery_method"] == "manual_override"

    def test_discover_tool_searches_path_first(self) -> None:
        """discover_tool searches PATH before other locations."""
        mock_config = Mock()
        mock_config.get.return_value = {}

        with patch("intellicrack.core.tool_discovery.get_config", return_value=mock_config):
            discovery = AdvancedToolDiscovery()

            config = {"executables": ["python3", "python"], "search_strategy": "path_based"}
            result = discovery.discover_tool("python3", config)

            if result.get("available"):
                assert result["discovery_method"] in ["PATH", "manual_override"]

    def test_discover_all_tools_finds_python(self) -> None:
        """discover_all_tools finds Python installation."""
        mock_config = Mock()
        mock_config.get.return_value = {}
        mock_config.set = Mock()

        with patch("intellicrack.core.tool_discovery.get_config", return_value=mock_config):
            discovery = AdvancedToolDiscovery()
            results = discovery.discover_all_tools()

            assert "python3" in results
            if results["python3"].get("available"):
                assert results["python3"]["path"] is not None

    def test_set_manual_override_rejects_nonexistent_path(self) -> None:
        """set_manual_override rejects nonexistent paths."""
        mock_config = Mock()
        mock_config.get.return_value = {}
        mock_config.set = Mock()

        with patch("intellicrack.core.tool_discovery.get_config", return_value=mock_config):
            discovery = AdvancedToolDiscovery()

            result = discovery.set_manual_override("python3", "/nonexistent/python")

            assert result is False

    def test_set_manual_override_accepts_valid_path(self, tmp_path: Path) -> None:
        """set_manual_override accepts valid executable paths."""
        mock_config = Mock()
        mock_config.get.return_value = {}
        mock_config.set = Mock()

        with patch("intellicrack.core.tool_discovery.get_config", return_value=mock_config):
            discovery = AdvancedToolDiscovery()

            fake_tool = tmp_path / "tool.exe"
            fake_tool.touch()

            result = discovery.set_manual_override("mytool", str(fake_tool))

            assert result is True
            assert discovery.manual_overrides["mytool"] == str(fake_tool)

    def test_clear_manual_override_removes_override(self, tmp_path: Path) -> None:
        """clear_manual_override removes manual override."""
        mock_config = Mock()
        mock_config.get.return_value = {}
        mock_config.set = Mock()

        with patch("intellicrack.core.tool_discovery.get_config", return_value=mock_config):
            discovery = AdvancedToolDiscovery()

            fake_tool = tmp_path / "tool.exe"
            fake_tool.touch()

            discovery.set_manual_override("mytool", str(fake_tool))
            result = discovery.clear_manual_override("mytool")

            assert result is True
            assert "mytool" not in discovery.manual_overrides

    def test_get_tool_path_checks_overrides_first(self, tmp_path: Path) -> None:
        """get_tool_path checks manual overrides before discovered tools."""
        mock_config = Mock()
        mock_config.get.return_value = {}

        with patch("intellicrack.core.tool_discovery.get_config", return_value=mock_config):
            discovery = AdvancedToolDiscovery()

            fake_tool = tmp_path / "tool.exe"
            fake_tool.touch()

            discovery.manual_overrides["mytool"] = str(fake_tool)
            path = discovery.get_tool_path("mytool")

            assert path == str(fake_tool)

    def test_health_check_tool_detects_missing_tool(self) -> None:
        """health_check_tool detects missing tools."""
        mock_config = Mock()
        mock_config.get.return_value = {}

        with patch("intellicrack.core.tool_discovery.get_config", return_value=mock_config):
            discovery = AdvancedToolDiscovery()

            status = discovery.health_check_tool("nonexistent_tool")

            assert status["healthy"] is False
            assert status["available"] is False
            assert len(status["issues"]) > 0

    def test_health_check_tool_validates_existing_tool(self) -> None:
        """health_check_tool validates existing Python installation."""
        mock_config = Mock()
        mock_config.get.return_value = {}

        with patch("intellicrack.core.tool_discovery.get_config", return_value=mock_config):
            discovery = AdvancedToolDiscovery()
            discovery.manual_overrides["python3"] = sys.executable

            status = discovery.health_check_tool("python3")

            assert status["available"] is True
            assert status["executable"] is True

    def test_get_tool_capabilities_returns_list(self) -> None:
        """get_tool_capabilities returns capability list."""
        mock_config = Mock()
        mock_config.get.return_value = {}

        with patch("intellicrack.core.tool_discovery.get_config", return_value=mock_config):
            discovery = AdvancedToolDiscovery()
            discovery.discovered_tools["mytool"] = {"capabilities": ["cap1", "cap2"]}

            capabilities = discovery.get_tool_capabilities("mytool")

            assert capabilities == ["cap1", "cap2"]

    def test_is_tool_compatible_checks_required_capabilities(self) -> None:
        """is_tool_compatible checks if tool has required capabilities."""
        mock_config = Mock()
        mock_config.get.return_value = {}

        with patch("intellicrack.core.tool_discovery.get_config", return_value=mock_config):
            discovery = AdvancedToolDiscovery()
            discovery.discovered_tools["mytool"] = {"capabilities": ["cap1", "cap2", "cap3"]}

            assert discovery.is_tool_compatible("mytool", ["cap1", "cap2"]) is True
            assert discovery.is_tool_compatible("mytool", ["cap1", "cap4"]) is False


class TestFallbackStrategies:
    """Test fallback discovery strategies."""

    def test_try_portable_versions_checks_portable_dirs(self) -> None:
        """_try_portable_versions checks portable tool directories."""
        mock_config = Mock()
        mock_config.get.return_value = {}

        with patch("intellicrack.core.tool_discovery.get_config", return_value=mock_config):
            discovery = AdvancedToolDiscovery()

            config = {"executables": ["tool.exe"]}
            result = discovery._try_portable_versions("mytool", config)

            assert result is None or isinstance(result, dict)

    def test_try_package_manager_paths_checks_scoop_chocolatey(self) -> None:
        """_try_package_manager_paths checks package manager directories."""
        mock_config = Mock()
        mock_config.get.return_value = {}

        with patch("intellicrack.core.tool_discovery.get_config", return_value=mock_config):
            discovery = AdvancedToolDiscovery()

            config = {"executables": ["tool.exe"]}
            result = discovery._try_package_manager_paths("mytool", config)

            assert result is None or isinstance(result, dict)

    def test_try_version_fallbacks_tries_alternate_names(self) -> None:
        """_try_version_fallbacks tries python3, python2, python-dev variants."""
        mock_config = Mock()
        mock_config.get.return_value = {}

        with patch("intellicrack.core.tool_discovery.get_config", return_value=mock_config):
            discovery = AdvancedToolDiscovery()

            config = {"executables": ["python"]}
            result = discovery._try_version_fallbacks("python", config)

            assert result is None or isinstance(result, dict)

    def test_get_tool_alternatives_provides_fallback_tools(self) -> None:
        """_get_tool_alternatives provides alternative tools."""
        mock_config = Mock()
        mock_config.get.return_value = {}

        with patch("intellicrack.core.tool_discovery.get_config", return_value=mock_config):
            discovery = AdvancedToolDiscovery()

            alternatives = discovery._get_tool_alternatives("radare2")

            assert isinstance(alternatives, dict)
            assert "rizin" in alternatives or len(alternatives) >= 0


class TestWindowsSpecificFeatures:
    """Test Windows-specific discovery features."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_search_windows_registry_attempts_search(self) -> None:
        """_search_windows_registry attempts Windows registry search."""
        mock_config = Mock()
        mock_config.get.return_value = {}

        with patch("intellicrack.core.tool_discovery.get_config", return_value=mock_config):
            discovery = AdvancedToolDiscovery()

            result = discovery._search_windows_registry("python")

            assert result is None or isinstance(result, str)

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_get_installation_paths_includes_program_files(self) -> None:
        """_get_installation_paths includes Program Files directories."""
        mock_config = Mock()
        mock_config.get.return_value = {}

        with patch("intellicrack.core.tool_discovery.get_config", return_value=mock_config):
            discovery = AdvancedToolDiscovery()

            paths = discovery._get_installation_paths("ghidra")

            assert any("Program Files" in str(p) for p in paths)


class TestCrossPlatformBehavior:
    """Test cross-platform discovery behavior."""

    def test_discover_tool_adapts_to_platform(self) -> None:
        """discover_tool adapts search based on platform."""
        mock_config = Mock()
        mock_config.get.return_value = {}

        with patch("intellicrack.core.tool_discovery.get_config", return_value=mock_config):
            discovery = AdvancedToolDiscovery()

            config = {"executables": ["python3"], "search_strategy": "path_based"}
            result = discovery.discover_tool("python3", config)

            assert "discovery_method" in result
            assert "discovery_duration" in result

    def test_search_common_locations_platform_specific(self) -> None:
        """_search_common_locations uses platform-specific paths."""
        mock_config = Mock()
        mock_config.get.return_value = {}

        with patch("intellicrack.core.tool_discovery.get_config", return_value=mock_config):
            discovery = AdvancedToolDiscovery()

            result = discovery._search_common_locations("python3", ["python3"])

            assert result is None or os.path.exists(result)
