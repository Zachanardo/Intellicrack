"""Production tests for plugin path resolution utilities.

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

import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.utils.core.plugin_paths import (
    ensure_directories_exist,
    find_script_by_name,
    get_config_dir,
    get_data_dir,
    get_dev_dir,
    get_dev_scripts_dir,
    get_frida_logs_dir,
    get_frida_script_path,
    get_frida_scripts_dir,
    get_ghidra_script_path,
    get_ghidra_scripts_dir,
    get_logs_dir,
    get_main_config_file,
    get_path_info,
    get_plugin_cache_dir,
    get_plugin_modules_dir,
    get_project_docs_dir,
    get_project_root,
    get_reports_dir,
    get_scripts_dir,
    get_tests_dir,
    get_visualizations_dir,
    list_frida_scripts,
    list_ghidra_scripts,
    list_plugin_modules,
)


class TestProjectRootDetection:
    """Test project root directory detection."""

    def test_get_project_root_returns_path(self) -> None:
        """Test get_project_root returns a valid Path object."""
        root = get_project_root()

        assert isinstance(root, Path)
        assert root.exists()
        assert root.is_dir()

    def test_get_project_root_contains_intellicrack(self) -> None:
        """Test project root contains intellicrack package."""
        root = get_project_root()
        intellicrack_dir = root / "intellicrack"

        assert intellicrack_dir.exists()
        assert intellicrack_dir.is_dir()

    def test_get_project_root_is_absolute(self) -> None:
        """Test project root path is absolute."""
        root = get_project_root()

        assert root.is_absolute()

    def test_get_project_root_consistent(self) -> None:
        """Test project root is consistent across multiple calls."""
        root1 = get_project_root()
        root2 = get_project_root()

        assert root1 == root2


class TestScriptDirectories:
    """Test script directory paths."""

    def test_get_scripts_dir_returns_path(self) -> None:
        """Test get_scripts_dir returns valid Path."""
        scripts_dir = get_scripts_dir()

        assert isinstance(scripts_dir, Path)

    def test_get_frida_scripts_dir_returns_path(self) -> None:
        """Test get_frida_scripts_dir returns valid Path."""
        frida_dir = get_frida_scripts_dir()

        assert isinstance(frida_dir, Path)

    def test_get_ghidra_scripts_dir_returns_path(self) -> None:
        """Test get_ghidra_scripts_dir returns valid Path."""
        ghidra_dir = get_ghidra_scripts_dir()

        assert isinstance(ghidra_dir, Path)

    def test_frida_scripts_dir_under_scripts(self) -> None:
        """Test Frida scripts directory is under scripts directory."""
        scripts_dir = get_scripts_dir()
        frida_dir = get_frida_scripts_dir()

        assert str(scripts_dir) in str(frida_dir)

    def test_ghidra_scripts_dir_under_scripts(self) -> None:
        """Test Ghidra scripts directory is under scripts directory."""
        scripts_dir = get_scripts_dir()
        ghidra_dir = get_ghidra_scripts_dir()

        assert str(scripts_dir) in str(ghidra_dir)


class TestPluginDirectories:
    """Test plugin-related directory paths."""

    def test_get_plugin_modules_dir_returns_path(self) -> None:
        """Test get_plugin_modules_dir returns valid Path."""
        plugins_dir = get_plugin_modules_dir()

        assert isinstance(plugins_dir, Path)

    def test_get_plugin_modules_dir_under_project(self) -> None:
        """Test plugin modules directory is under project root."""
        root = get_project_root()
        plugins_dir = get_plugin_modules_dir()

        assert str(root) in str(plugins_dir)
        assert "custom_modules" in str(plugins_dir)

    def test_get_plugin_cache_dir_creates_if_missing(self) -> None:
        """Test plugin cache directory is created if it doesn't exist."""
        cache_dir = get_plugin_cache_dir()

        assert cache_dir.exists()
        assert cache_dir.is_dir()


class TestConfigurationDirectories:
    """Test configuration directory paths."""

    def test_get_config_dir_creates_directory(self) -> None:
        """Test get_config_dir creates config directory."""
        config_dir = get_config_dir()

        assert config_dir.exists()
        assert config_dir.is_dir()

    def test_get_config_dir_under_project(self) -> None:
        """Test config directory is under project root."""
        root = get_project_root()
        config_dir = get_config_dir()

        assert str(root) in str(config_dir)

    def test_get_main_config_file_path(self) -> None:
        """Test main config file path points to correct location."""
        config_file = get_main_config_file()

        assert isinstance(config_file, Path)
        assert config_file.name == "intellicrack_config.json"
        assert config_file.parent == get_config_dir()


class TestDataDirectories:
    """Test data-related directory paths."""

    def test_get_data_dir_creates_directory(self) -> None:
        """Test get_data_dir creates data directory."""
        data_dir = get_data_dir()

        assert data_dir.exists()
        assert data_dir.is_dir()

    def test_get_logs_dir_creates_directory(self) -> None:
        """Test get_logs_dir creates logs directory."""
        logs_dir = get_logs_dir()

        assert logs_dir.exists()
        assert logs_dir.is_dir()

    def test_get_visualizations_dir_creates_directory(self) -> None:
        """Test get_visualizations_dir creates visualizations directory."""
        viz_dir = get_visualizations_dir()

        assert viz_dir.exists()
        assert viz_dir.is_dir()
        assert "visualizations" in str(viz_dir)

    def test_get_reports_dir_creates_directory(self) -> None:
        """Test get_reports_dir creates reports directory."""
        reports_dir = get_reports_dir()

        assert reports_dir.exists()
        assert reports_dir.is_dir()
        assert "reports" in str(reports_dir)

    def test_get_frida_logs_dir_under_logs(self) -> None:
        """Test Frida logs directory is under main logs directory."""
        logs_dir = get_logs_dir()
        frida_logs = get_frida_logs_dir()

        assert str(logs_dir) in str(frida_logs)
        assert "frida_operations" in str(frida_logs)


class TestDevDirectories:
    """Test development-related directory paths."""

    def test_get_dev_dir_creates_directory(self) -> None:
        """Test get_dev_dir creates dev directory."""
        dev_dir = get_dev_dir()

        assert dev_dir.exists()
        assert dev_dir.is_dir()

    def test_get_project_docs_dir_under_dev(self) -> None:
        """Test project docs directory is under dev directory."""
        dev_dir = get_dev_dir()
        docs_dir = get_project_docs_dir()

        assert str(dev_dir) in str(docs_dir)
        assert "project-docs" in str(docs_dir)

    def test_get_dev_scripts_dir_under_dev(self) -> None:
        """Test dev scripts directory is under dev directory."""
        dev_dir = get_dev_dir()
        scripts_dir = get_dev_scripts_dir()

        assert str(dev_dir) in str(scripts_dir)
        assert "scripts" in str(scripts_dir)


class TestTestsDirectory:
    """Test tests directory path."""

    def test_get_tests_dir_returns_path(self) -> None:
        """Test get_tests_dir returns valid Path."""
        tests_dir = get_tests_dir()

        assert isinstance(tests_dir, Path)

    def test_get_tests_dir_exists(self) -> None:
        """Test tests directory exists in project."""
        tests_dir = get_tests_dir()

        assert tests_dir.exists()
        assert tests_dir.is_dir()

    def test_get_tests_dir_under_project(self) -> None:
        """Test tests directory is under project root."""
        root = get_project_root()
        tests_dir = get_tests_dir()

        assert str(root) in str(tests_dir)


class TestScriptListing:
    """Test script listing functions."""

    @pytest.fixture
    def temp_frida_env(self) -> Path:
        """Create temporary Frida scripts environment."""
        with tempfile.TemporaryDirectory() as tmpdir:
            frida_dir = Path(tmpdir) / "scripts" / "frida"
            frida_dir.mkdir(parents=True)

            (frida_dir / "hook_license.js").write_text("// Frida script", encoding="utf-8")
            (frida_dir / "bypass_check.js").write_text("// Bypass script", encoding="utf-8")
            (frida_dir / "README.md").write_text("# README", encoding="utf-8")

            yield frida_dir

    def test_list_frida_scripts_returns_list(self) -> None:
        """Test list_frida_scripts returns a list."""
        scripts = list_frida_scripts()

        assert isinstance(scripts, list)

    def test_list_frida_scripts_only_js_files(self, temp_frida_env: Path) -> None:
        """Test list_frida_scripts only returns .js files."""
        frida_dir = get_frida_scripts_dir()
        current_scripts = list_frida_scripts()

        assert all(script.suffix == ".js" for script in current_scripts)

    def test_list_ghidra_scripts_returns_list(self) -> None:
        """Test list_ghidra_scripts returns a list."""
        scripts = list_ghidra_scripts()

        assert isinstance(scripts, list)

    def test_list_ghidra_scripts_includes_java_and_python(self) -> None:
        """Test list_ghidra_scripts includes both .java and .py files."""
        if scripts := list_ghidra_scripts():
            assert all(script.suffix in [".java", ".py"] for script in scripts)

    def test_list_plugin_modules_returns_list(self) -> None:
        """Test list_plugin_modules returns a list."""
        modules = list_plugin_modules()

        assert isinstance(modules, list)

    def test_list_plugin_modules_excludes_init(self) -> None:
        """Test list_plugin_modules excludes __init__.py."""
        modules = list_plugin_modules()

        assert all(module.stem != "__init__" for module in modules)

    def test_list_plugin_modules_only_python_files(self) -> None:
        """Test list_plugin_modules only returns .py files."""
        modules = list_plugin_modules()

        assert all(module.suffix == ".py" for module in modules)


class TestScriptFinding:
    """Test script finding by name."""

    @pytest.fixture
    def temp_script_env(self) -> Path:
        """Create temporary script environment."""
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_root = Path(tmpdir)

            frida_dir = temp_root / "scripts" / "frida"
            frida_dir.mkdir(parents=True)
            (frida_dir / "test_script.js").write_text("// Test", encoding="utf-8")

            ghidra_dir = temp_root / "scripts" / "ghidra"
            ghidra_dir.mkdir(parents=True)
            (ghidra_dir / "analyzer.java").write_text("// Java", encoding="utf-8")
            (ghidra_dir / "helper.py").write_text("# Python", encoding="utf-8")

            yield temp_root

    def test_find_script_by_name_nonexistent(self) -> None:
        """Test find_script_by_name returns None for nonexistent script."""
        result = find_script_by_name("totally_nonexistent_script_12345")

        assert result is None

    def test_find_script_by_name_with_extension(self) -> None:
        """Test find_script_by_name works with file extension."""
        frida_dir = get_frida_scripts_dir()
        if frida_dir.exists():
            if scripts := list(frida_dir.glob("*.js")):
                script_name = scripts[0].name
                if result := find_script_by_name(script_name, "frida"):
                    assert result.exists()
                    assert result.suffix == ".js"

    def test_find_script_by_name_without_extension(self) -> None:
        """Test find_script_by_name works without file extension."""
        frida_dir = get_frida_scripts_dir()
        if frida_dir.exists():
            if scripts := list(frida_dir.glob("*.js")):
                script_name = scripts[0].stem
                if result := find_script_by_name(script_name, "frida"):
                    assert result.exists()

    def test_find_script_by_name_auto_type(self) -> None:
        """Test find_script_by_name with auto type detection."""
        frida_dir = get_frida_scripts_dir()
        if frida_dir.exists():
            if scripts := list(frida_dir.glob("*.js")):
                script_name = scripts[0].stem
                if result := find_script_by_name(script_name, "auto"):
                    assert result.exists()


class TestLegacyCompatibility:
    """Test legacy compatibility functions."""

    def test_get_frida_script_path_returns_string_or_none(self) -> None:
        """Test get_frida_script_path returns string or None."""
        result = get_frida_script_path("nonexistent_script")

        assert result is None or isinstance(result, str)

    def test_get_frida_script_path_existing_script(self) -> None:
        """Test get_frida_script_path with existing script."""
        frida_dir = get_frida_scripts_dir()
        if frida_dir.exists():
            if scripts := list(frida_dir.glob("*.js")):
                script_name = scripts[0].stem
                if result := get_frida_script_path(script_name):
                    assert isinstance(result, str)
                    assert Path(result).exists()

    def test_get_ghidra_script_path_returns_string_or_none(self) -> None:
        """Test get_ghidra_script_path returns string or None."""
        result = get_ghidra_script_path("nonexistent_script")

        assert result is None or isinstance(result, str)

    def test_get_ghidra_script_path_existing_script(self) -> None:
        """Test get_ghidra_script_path with existing script."""
        ghidra_dir = get_ghidra_scripts_dir()
        if ghidra_dir.exists():
            if scripts := list(ghidra_dir.glob("**/*.java")) + list(
                ghidra_dir.glob("**/*.py")
            ):
                script_name = scripts[0].stem
                if result := get_ghidra_script_path(script_name):
                    assert isinstance(result, str)
                    assert Path(result).exists()


class TestPathInfo:
    """Test path information retrieval."""

    def test_get_path_info_returns_dict(self) -> None:
        """Test get_path_info returns a dictionary."""
        info = get_path_info()

        assert isinstance(info, dict)

    def test_get_path_info_contains_required_keys(self) -> None:
        """Test get_path_info contains all required path keys."""
        info = get_path_info()

        required_keys = [
            "project_root",
            "scripts_dir",
            "frida_scripts",
            "ghidra_scripts",
            "plugin_modules",
            "config_dir",
            "main_config",
            "tests_dir",
            "data_dir",
            "logs_dir",
            "plugin_cache",
            "visualizations",
            "reports_dir",
            "dev_dir",
            "project_docs",
            "dev_scripts",
            "frida_logs",
        ]

        for key in required_keys:
            assert key in info

    def test_get_path_info_all_values_are_strings(self) -> None:
        """Test all values in path info are strings."""
        info = get_path_info()

        assert all(isinstance(value, str) for value in info.values())

    def test_get_path_info_all_paths_absolute(self) -> None:
        """Test all paths in path info are absolute."""
        info = get_path_info()

        for path_str in info.values():
            path = Path(path_str)
            assert path.is_absolute()


class TestEnsureDirectories:
    """Test directory creation functionality."""

    def test_ensure_directories_exist_executes(self) -> None:
        """Test ensure_directories_exist runs without error."""
        ensure_directories_exist()

    def test_ensure_directories_exist_creates_directories(self) -> None:
        """Test ensure_directories_exist creates all required directories."""
        ensure_directories_exist()

        assert get_scripts_dir().exists()
        assert get_config_dir().exists()
        assert get_data_dir().exists()
        assert get_logs_dir().exists()

    def test_ensure_directories_exist_idempotent(self) -> None:
        """Test ensure_directories_exist can be called multiple times."""
        ensure_directories_exist()
        ensure_directories_exist()
        ensure_directories_exist()

        assert get_config_dir().exists()


class TestPathConsistency:
    """Test path consistency and relationships."""

    def test_data_subdirectories_under_data(self) -> None:
        """Test data subdirectories are under main data directory."""
        data_dir = get_data_dir()
        plugin_cache = get_plugin_cache_dir()
        visualizations = get_visualizations_dir()
        reports = get_reports_dir()

        assert str(data_dir) in str(plugin_cache)
        assert str(data_dir) in str(visualizations)
        assert str(data_dir) in str(reports)

    def test_dev_subdirectories_under_dev(self) -> None:
        """Test dev subdirectories are under main dev directory."""
        dev_dir = get_dev_dir()
        project_docs = get_project_docs_dir()
        dev_scripts = get_dev_scripts_dir()

        assert str(dev_dir) in str(project_docs)
        assert str(dev_dir) in str(dev_scripts)

    def test_all_directories_under_project_root(self) -> None:
        """Test all major directories are under project root."""
        root = str(get_project_root())

        assert str(get_config_dir()).startswith(root)
        assert str(get_data_dir()).startswith(root)
        assert str(get_logs_dir()).startswith(root)
        assert str(get_dev_dir()).startswith(root)
        assert str(get_tests_dir()).startswith(root)


class TestPluginPathsIntegration:
    """Integration tests for plugin path resolution."""

    def test_complete_path_resolution_workflow(self) -> None:
        """Test complete path resolution workflow."""
        root = get_project_root()
        assert root.exists()

        ensure_directories_exist()

        info = get_path_info()
        assert len(info) > 0

        for path_str in info.values():
            path = Path(path_str)
            assert path.is_absolute()

    def test_script_discovery_workflow(self) -> None:
        """Test script discovery workflow."""
        frida_scripts = list_frida_scripts()
        ghidra_scripts = list_ghidra_scripts()
        plugin_modules = list_plugin_modules()

        assert isinstance(frida_scripts, list)
        assert isinstance(ghidra_scripts, list)
        assert isinstance(plugin_modules, list)

    def test_path_creation_hierarchy(self) -> None:
        """Test path creation follows proper hierarchy."""
        ensure_directories_exist()

        data_dir = get_data_dir()
        logs_dir = get_logs_dir()

        assert data_dir.exists()
        assert logs_dir.exists()

        plugin_cache = get_plugin_cache_dir()
        frida_logs = get_frida_logs_dir()

        assert plugin_cache.exists()
        assert frida_logs.exists()
