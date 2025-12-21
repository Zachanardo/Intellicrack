"""Production tests for path discovery system.

Tests validate real tool discovery, system path resolution, Windows registry
searches, and cross-platform tool location strategies.

Copyright (C) 2025 Zachary Flint
"""

import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest

from intellicrack.utils.core.path_discovery import (
    PathDiscovery,
    ensure_tool_available,
    find_tool,
    get_path_discovery,
    get_system_path,
)


class TestPathDiscoveryInitialization:
    """Test PathDiscovery initialization and platform detection."""

    def test_path_discovery_initialization(self) -> None:
        """PathDiscovery initializes with correct platform detection."""
        pd = PathDiscovery()

        assert pd.platform == sys.platform
        assert isinstance(pd.cache, dict)
        assert isinstance(pd.tool_specs, dict)
        assert isinstance(pd.system_paths, dict)

        assert pd.is_windows == sys.platform.startswith("win")
        assert pd.is_linux == sys.platform.startswith("linux")
        assert pd.is_mac == sys.platform.startswith("darwin")

        assert pd.is_windows + pd.is_linux + pd.is_mac == 1

    def test_tool_specs_completeness(self) -> None:
        """All tool specs have required fields."""
        pd = PathDiscovery()

        required_keys = {"executables", "search_paths", "env_vars"}

        for tool_name, spec in pd.tool_specs.items():
            assert required_keys.issubset(
                spec.keys(),
            ), f"Tool {tool_name} missing required keys"

            assert isinstance(spec["executables"], dict)
            assert isinstance(spec["search_paths"], dict)
            assert isinstance(spec["env_vars"], list)

            for platform_key in ["win32", "linux", "darwin"]:
                assert platform_key in spec["executables"]
                assert platform_key in spec["search_paths"]

    def test_system_paths_available(self) -> None:
        """System path handlers properly defined."""
        pd = PathDiscovery()

        expected_paths = [
            "windows_system",
            "windows_system32",
            "program_files",
            "user_home",
            "temp",
        ]

        for path_type in expected_paths:
            assert path_type in pd.system_paths


class TestRealToolDiscovery:
    """Test real tool discovery on the system."""

    def test_find_python_executable(self) -> None:
        """Discover Python executable (always available during tests)."""
        pd = PathDiscovery()

        python_path = pd.find_tool("python")

        assert python_path is not None
        assert os.path.exists(python_path)
        assert os.path.isfile(python_path)

        result = subprocess.run(
            [python_path, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        assert result.returncode == 0
        assert "python" in result.stdout.lower() or "python" in result.stderr.lower()

    def test_find_tool_in_path(self) -> None:
        """Find tools available in system PATH."""
        pd = PathDiscovery()

        common_tools = ["python", "git"]
        if sys.platform.startswith("win"):
            common_tools.append("cmd")
        else:
            common_tools.extend(["bash", "sh"])

        found_tools = []
        for tool in common_tools:
            if shutil.which(tool):
                path = pd.find_tool(tool)
                if path:
                    found_tools.append(tool)

        assert len(found_tools) > 0

    def test_find_tool_caching(self) -> None:
        """Tool discovery results are cached for performance."""
        pd = PathDiscovery()

        tool_name = "python"

        first_result = pd.find_tool(tool_name)

        if first_result:
            cache_key = f"{tool_name}:"
            assert cache_key in pd.cache

            second_result = pd.find_tool(tool_name)
            assert second_result == first_result

    def test_find_tool_with_config_manager(self) -> None:
        """Tool discovery uses config manager when available."""
        mock_config = Mock()
        mock_config.get.return_value = None
        mock_config.set = Mock()

        pd = PathDiscovery(config_manager=mock_config)

        pd.find_tool("python")

        if hasattr(mock_config, "get"):
            mock_config.get.assert_called()

    def test_generic_tool_search(self) -> None:
        """Generic tool search works for unknown tools."""
        pd = PathDiscovery()

        git_path = pd._generic_tool_search("git")

        if shutil.which("git"):
            assert git_path is not None
            assert os.path.exists(git_path)


class TestSystemPathResolution:
    """Test system path resolution functionality."""

    def test_get_system_path_user_home(self) -> None:
        """Get user home directory."""
        pd = PathDiscovery()

        home = pd.get_system_path("user_home")

        assert home is not None
        assert os.path.exists(home)
        assert Path(home).is_dir()

    def test_get_system_path_temp(self) -> None:
        """Get temporary directory."""
        pd = PathDiscovery()

        temp = pd.get_system_path("temp")

        assert temp is not None
        assert os.path.exists(temp)
        assert Path(temp).is_dir()

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific test")
    def test_get_windows_system_paths(self) -> None:
        """Get Windows-specific system paths."""
        pd = PathDiscovery()

        system_root = pd.get_system_path("windows_system")
        assert system_root is not None
        assert os.path.exists(system_root)

        system32 = pd.get_system_path("windows_system32")
        assert system32 is not None
        assert os.path.exists(system32)

        program_files = pd.get_system_path("program_files")
        assert program_files is not None

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific test")
    def test_get_windows_appdata_paths(self) -> None:
        """Get Windows AppData paths."""
        pd = PathDiscovery()

        appdata = pd.get_system_path("appdata")
        localappdata = pd.get_system_path("localappdata")

        assert appdata is not None or localappdata is not None

    def test_get_system_path_invalid(self) -> None:
        """Invalid system path type returns None."""
        pd = PathDiscovery()

        result = pd.get_system_path("nonexistent_path_type")

        assert result is None


class TestEnvironmentVariableSearch:
    """Test environment variable-based tool discovery."""

    def test_search_env_vars_with_path(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """Search environment variables for tool paths."""
        pd = PathDiscovery()

        test_exe = tmp_path / "test_tool.exe" if sys.platform.startswith("win") else tmp_path / "test_tool"
        test_exe.touch()
        test_exe.chmod(0o755)

        monkeypatch.setenv("TEST_TOOL_PATH", str(test_exe))

        result = pd._search_env_vars(["TEST_TOOL_PATH"])

        assert result == str(test_exe)

    def test_search_env_vars_directory(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """Search environment variable pointing to directory."""
        pd = PathDiscovery()

        tool_dir = tmp_path / "tools"
        tool_dir.mkdir()

        tool_exe = tool_dir / ("tool.exe" if sys.platform.startswith("win") else "tool")
        tool_exe.touch()
        tool_exe.chmod(0o755)

        monkeypatch.setenv("TOOL_DIR", str(tool_dir))

        result = pd._search_env_vars(["TOOL_DIR"])

        if result:
            assert os.path.exists(result)


class TestCommonLocationSearch:
    """Test common installation location searches."""

    def test_search_common_locations(self, tmp_path: Path) -> None:
        """Search common installation locations for tools."""
        pd = PathDiscovery()

        exe_name = "test_tool.exe" if sys.platform.startswith("win") else "test_tool"

        tool_dir = tmp_path / "tool_install"
        tool_dir.mkdir()

        tool_exe = tool_dir / exe_name
        tool_exe.touch()

        spec = {
            "executables": {pd.platform: [exe_name]},
            "search_paths": {pd.platform: [str(tool_dir)]},
        }

        result = pd._search_common_locations(spec)

        assert result == str(tool_exe)

    def test_search_common_locations_subdirectories(self, tmp_path: Path) -> None:
        """Search tool subdirectories (bin, scripts)."""
        pd = PathDiscovery()

        exe_name = "tool.exe" if sys.platform.startswith("win") else "tool"

        tool_dir = tmp_path / "tool_root"
        bin_dir = tool_dir / "bin"
        bin_dir.mkdir(parents=True)

        tool_exe = bin_dir / exe_name
        tool_exe.touch()

        spec = {
            "executables": {pd.platform: [exe_name]},
            "search_paths": {pd.platform: [str(tool_dir)]},
        }

        result = pd._search_common_locations(spec)

        assert result == str(tool_exe)


class TestToolValidation:
    """Test tool validation methods."""

    def test_validate_python(self) -> None:
        """Validate Python installation."""
        pd = PathDiscovery()

        python_path = shutil.which("python") or shutil.which("python3")

        if python_path:
            is_valid = pd._validate_python(python_path)
            assert is_valid is True

    def test_validate_radare2(self) -> None:
        """Validate radare2 installation if available."""
        pd = PathDiscovery()

        r2_path = shutil.which("radare2") or shutil.which("r2")

        if r2_path:
            is_valid = pd._validate_radare2(r2_path)
            assert isinstance(is_valid, bool)

    def test_validate_frida(self) -> None:
        """Validate Frida installation if available."""
        pd = PathDiscovery()

        frida_path = shutil.which("frida")

        if frida_path:
            is_valid = pd._validate_frida(frida_path)
            assert isinstance(is_valid, bool)

    def test_validate_ghidra(self, tmp_path: Path) -> None:
        """Validate Ghidra installation structure."""
        pd = PathDiscovery()

        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        ghidra_app_dir = ghidra_dir / "Ghidra"

        support_dir.mkdir(parents=True)
        ghidra_app_dir.mkdir(parents=True)

        ghidra_exe = ghidra_dir / "ghidraRun"
        ghidra_exe.touch()

        is_valid = pd._validate_ghidra(str(ghidra_exe))
        assert is_valid is True

    def test_validate_wireshark(self, tmp_path: Path) -> None:
        """Validate Wireshark installation (file existence check)."""
        pd = PathDiscovery()

        wireshark_exe = tmp_path / "Wireshark.exe"
        wireshark_exe.touch()

        is_valid = pd._validate_wireshark(str(wireshark_exe))
        assert is_valid is True


@pytest.mark.skipif(sys.platform != "win32", reason="Windows registry test")
class TestWindowsRegistrySearch:
    """Test Windows registry-based tool discovery."""

    def test_search_registry_available(self) -> None:
        """Windows registry search is available on Windows."""
        pd = PathDiscovery()

        assert pd.is_windows
        assert hasattr(pd, "_search_registry")

    def test_search_registry_common_software(self) -> None:
        """Search registry for commonly installed software."""
        pd = PathDiscovery()

        result = pd._search_registry("git")

        if result:
            assert os.path.exists(result)


class TestCUDAPathDiscovery:
    """Test CUDA installation path discovery."""

    def test_get_cuda_path_structure(self) -> None:
        """get_cuda_path returns valid path or None."""
        pd = PathDiscovery()

        cuda_path = pd.get_cuda_path()

        if cuda_path:
            assert os.path.exists(cuda_path)
            assert Path(cuda_path).is_dir()

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows CUDA path test")
    def test_get_cuda_path_windows(self) -> None:
        """Windows CUDA path discovery checks expected locations."""
        pd = PathDiscovery()

        cuda_path = pd.get_cuda_path()

        if cuda_path:
            assert "CUDA" in cuda_path or "cuda" in cuda_path


class TestEnsureToolAvailable:
    """Test interactive tool availability checking."""

    def test_ensure_tool_available_found(self) -> None:
        """ensure_tool_available returns path for found tool."""
        pd = PathDiscovery()

        python_path = pd.ensure_tool_available("python")

        if python_path:
            assert os.path.exists(python_path)
            assert os.path.isfile(python_path)

    def test_ensure_tool_available_not_found_no_gui(self) -> None:
        """ensure_tool_available handles missing tool without GUI."""
        pd = PathDiscovery()

        result = pd.ensure_tool_available("nonexistent_tool_xyz_123")

        assert result is None


class TestModuleLevelFunctions:
    """Test module-level convenience functions."""

    def test_get_path_discovery_singleton(self) -> None:
        """get_path_discovery returns singleton instance."""
        pd1 = get_path_discovery()
        pd2 = get_path_discovery()

        assert pd1 is pd2
        assert isinstance(pd1, PathDiscovery)

    def test_find_tool_module_function(self) -> None:
        """Module-level find_tool works correctly."""
        result = find_tool("python")

        if result:
            assert os.path.exists(result)

    def test_get_system_path_module_function(self) -> None:
        """Module-level get_system_path works correctly."""
        home = get_system_path("user_home")

        assert home is not None
        assert os.path.exists(home)

    def test_ensure_tool_available_module_function(self) -> None:
        """Module-level ensure_tool_available works correctly."""
        result = ensure_tool_available("python")

        if result:
            assert os.path.exists(result)


class TestPlatformSpecificBehavior:
    """Test platform-specific discovery behavior."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific test")
    def test_windows_executable_extensions(self) -> None:
        """Windows searches for .exe, .bat, .cmd extensions."""
        pd = PathDiscovery()

        assert pd.is_windows

        for tool_name, spec in pd.tool_specs.items():
            win_executables = spec["executables"].get("win32", [])
            if win_executables:
                assert any(exe.endswith((".exe", ".bat", ".cmd")) for exe in win_executables)

    @pytest.mark.skipif(sys.platform != "linux", reason="Linux-specific test")
    def test_linux_search_paths(self) -> None:
        """Linux searches standard Unix paths."""
        pd = PathDiscovery()

        assert pd.is_linux

        common_unix_paths = ["/usr/bin", "/usr/local/bin", "/opt"]

        for tool_name, spec in pd.tool_specs.items():
            linux_paths = spec["search_paths"].get("linux", [])
            if linux_paths:
                assert any(any(unix_path in path for unix_path in common_unix_paths) for path in linux_paths)

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS-specific test")
    def test_macos_homebrew_paths(self) -> None:
        """macOS searches Homebrew installation paths."""
        pd = PathDiscovery()

        assert pd.is_mac

        homebrew_paths = ["/opt/homebrew", "/usr/local"]

        for tool_name, spec in pd.tool_specs.items():
            darwin_paths = spec["search_paths"].get("darwin", [])
            if darwin_paths:
                assert any(
                    any(brew_path in path for brew_path in homebrew_paths) for path in darwin_paths
                ), f"Tool {tool_name} missing Homebrew paths"


class TestRealWorldScenarios:
    """Test real-world usage scenarios."""

    def test_discover_multiple_tools(self) -> None:
        """Discover multiple tools in sequence."""
        pd = PathDiscovery()

        tools_to_find = ["python", "git"]

        found_tools = {}
        for tool in tools_to_find:
            path = pd.find_tool(tool)
            if path:
                found_tools[tool] = path

        assert len(found_tools) > 0

        for tool_name, tool_path in found_tools.items():
            assert os.path.exists(tool_path)

    def test_tool_discovery_with_validation(self) -> None:
        """Tool discovery with validation ensures executable works."""
        pd = PathDiscovery()

        python_path = pd.find_tool("python")

        if python_path:
            result = subprocess.run(
                [python_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )

            assert result.returncode == 0

    def test_system_path_collection(self) -> None:
        """Collect all available system paths."""
        pd = PathDiscovery()

        system_paths = {}
        for path_type in pd.system_paths.keys():
            path = pd.get_system_path(path_type)
            if path:
                system_paths[path_type] = path

        assert len(system_paths) > 0

        for path_type, path_value in system_paths.items():
            if path_value:
                assert isinstance(path_value, str)

    def test_cached_vs_fresh_discovery(self) -> None:
        """Cached discovery matches fresh discovery."""
        pd = PathDiscovery()

        tool = "python"

        first_path = pd.find_tool(tool)

        pd.cache.clear()

        second_path = pd.find_tool(tool)

        if first_path and second_path:
            assert first_path == second_path

    def test_multiple_path_discovery_instances(self) -> None:
        """Multiple PathDiscovery instances work independently."""
        pd1 = PathDiscovery()
        pd2 = PathDiscovery()

        result1 = pd1.find_tool("python")
        result2 = pd2.find_tool("python")

        if result1 and result2:
            assert result1 == result2

        assert pd1.cache is not pd2.cache
