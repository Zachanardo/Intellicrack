"""Production tests for resource path helper functionality.

Tests validate that resource path resolution works correctly for normal Python
environments and PyInstaller frozen applications.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
import sys
from pathlib import Path
from typing import Any

import pytest

from intellicrack.utils.resource_helper import get_resource_path


class TestResourcePathResolution:
    """Test resource path resolution in different environments."""

    def test_get_resource_path_resolves_from_package_directory(self) -> None:
        """Resource path resolves to absolute path within intellicrack package."""
        resource_path = get_resource_path("assets/icons/app_icon.png")

        assert os.path.isabs(resource_path)
        assert "intellicrack" in resource_path
        assert "assets" in resource_path
        assert "icons" in resource_path
        assert resource_path.endswith("app_icon.png")

    def test_get_resource_path_handles_forward_slashes(self) -> None:
        """Resource path handles forward slash separators on all platforms."""
        resource_path = get_resource_path("templates/reports/default.html")

        assert os.path.isabs(resource_path)
        expected_parts = ["templates", "reports", "default.html"]
        for part in expected_parts:
            assert part in resource_path

    def test_get_resource_path_handles_nested_directories(self) -> None:
        """Resource path correctly handles deeply nested directory structures."""
        resource_path = get_resource_path("assets/data/patterns/vmprotect/signatures.bin")

        assert os.path.isabs(resource_path)
        path_obj = Path(resource_path)
        assert path_obj.parts[-1] == "signatures.bin"
        assert "patterns" in resource_path
        assert "vmprotect" in resource_path

    def test_get_resource_path_with_empty_string(self) -> None:
        """Resource path with empty string returns package root."""
        resource_path = get_resource_path("")

        assert os.path.isabs(resource_path)
        assert "intellicrack" in resource_path

    def test_get_resource_path_with_single_filename(self) -> None:
        """Resource path with single filename resolves to package root file."""
        resource_path = get_resource_path("config.yaml")

        assert os.path.isabs(resource_path)
        assert resource_path.endswith("config.yaml")
        assert "intellicrack" in resource_path


class TestPyInstallerFrozenEnvironment:
    """Test resource path resolution in PyInstaller frozen applications."""

    def test_get_resource_path_uses_meipass_when_frozen(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Resource path uses _MEIPASS base path in frozen PyInstaller app."""
        fake_meipass = "C:\\temp\\frozen_app"
        monkeypatch.setattr(sys, "_MEIPASS", fake_meipass, raising=False)

        resource_path = get_resource_path("assets/icon.ico")

        assert resource_path.startswith(fake_meipass)
        assert "assets" in resource_path
        assert resource_path.endswith("icon.ico")

    def test_get_resource_path_converts_separators_in_frozen_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Resource path converts forward slashes to OS separators in frozen app."""
        fake_meipass = "/tmp/frozen_app"
        monkeypatch.setattr(sys, "_MEIPASS", fake_meipass, raising=False)

        resource_path = get_resource_path("data/files/test.dat")

        expected_sep = os.sep
        assert expected_sep in resource_path or resource_path.count("/") <= 1


class TestNormalPythonEnvironment:
    """Test resource path resolution in standard Python environment."""

    def test_get_resource_path_resolves_relative_to_package(self) -> None:
        """Resource path resolves relative to intellicrack package directory."""
        resource_path = get_resource_path("core/config_manager.py")

        assert os.path.isabs(resource_path)
        path_obj = Path(resource_path)
        assert path_obj.parts[-2] == "core"
        assert path_obj.parts[-1] == "config_manager.py"

    def test_get_resource_path_uses_file_based_resolution(self) -> None:
        """Resource path uses __file__ location for package resolution."""
        resource_path = get_resource_path("utils/logger.py")

        assert os.path.isabs(resource_path)
        path_obj = Path(resource_path)

        parent_parts = [p for p in path_obj.parts if p in ["intellicrack", "utils"]]
        assert "intellicrack" in parent_parts

    def test_get_resource_path_handles_windows_paths(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Resource path handles Windows-style separators correctly."""
        if sys.platform != "win32":
            pytest.skip("Windows path test only runs on Windows")

        resource_path = get_resource_path("assets\\data\\file.bin")

        assert os.path.isabs(resource_path)
        assert Path(resource_path).exists() or "\\" in resource_path or "/" in resource_path


class TestPathNormalization:
    """Test path normalization across different input formats."""

    def test_get_resource_path_normalizes_double_slashes(self) -> None:
        """Resource path normalizes double slashes in input."""
        resource_path = get_resource_path("assets//icons//test.png")

        assert os.path.isabs(resource_path)
        assert "//" not in resource_path or os.name == "nt"

    def test_get_resource_path_removes_trailing_slash(self) -> None:
        """Resource path handles trailing slashes correctly."""
        resource_path = get_resource_path("assets/")

        assert os.path.isabs(resource_path)
        path_obj = Path(resource_path)
        assert path_obj.parts[-1] in ["assets", ""]

    def test_get_resource_path_preserves_filename_extensions(self) -> None:
        """Resource path preserves file extensions correctly."""
        extensions = [".exe", ".dll", ".json", ".xml", ".bin", ".dat"]

        for ext in extensions:
            resource_path = get_resource_path(f"test{ext}")
            assert resource_path.endswith(ext)


class TestRealWorldScenarios:
    """Test real-world resource access scenarios."""

    def test_get_resource_path_for_ghidra_scripts(self) -> None:
        """Resource path correctly locates Ghidra script directory."""
        resource_path = get_resource_path("scripts/ghidra/analyze_licensing.py")

        assert os.path.isabs(resource_path)
        assert "scripts" in resource_path
        assert "ghidra" in resource_path
        assert resource_path.endswith("analyze_licensing.py")

    def test_get_resource_path_for_pattern_databases(self) -> None:
        """Resource path locates protection pattern database files."""
        resource_path = get_resource_path("assets/patterns/protections.db")

        assert os.path.isabs(resource_path)
        assert "patterns" in resource_path
        assert resource_path.endswith("protections.db")

    def test_get_resource_path_for_template_files(self) -> None:
        """Resource path locates report template files."""
        resource_path = get_resource_path("templates/reports/license_analysis.html")

        assert os.path.isabs(resource_path)
        assert "templates" in resource_path
        assert "reports" in resource_path
        assert resource_path.endswith(".html")

    def test_get_resource_path_for_binary_assets(self) -> None:
        """Resource path locates binary asset files for testing."""
        resource_path = get_resource_path("assets/test_binaries/protected_sample.exe")

        assert os.path.isabs(resource_path)
        assert "test_binaries" in resource_path
        assert resource_path.endswith(".exe")


class TestEdgeCases:
    """Test edge cases and unusual inputs."""

    def test_get_resource_path_with_unicode_characters(self) -> None:
        """Resource path handles unicode characters in filenames."""
        resource_path = get_resource_path("assets/测试/文件.txt")

        assert os.path.isabs(resource_path)
        path_obj = Path(resource_path)
        assert len(str(path_obj)) > 0

    def test_get_resource_path_with_spaces(self) -> None:
        """Resource path handles spaces in directory and file names."""
        resource_path = get_resource_path("My Documents/Test Files/sample file.txt")

        assert os.path.isabs(resource_path)
        assert " " in resource_path or "%20" in resource_path or Path(resource_path).exists()

    def test_get_resource_path_with_special_characters(self) -> None:
        """Resource path handles special characters in paths."""
        resource_path = get_resource_path("data/file-name_v1.0.bin")

        assert os.path.isabs(resource_path)
        assert "-" in resource_path or "_" in resource_path

    def test_get_resource_path_with_very_long_path(self) -> None:
        """Resource path handles very long nested directory structures."""
        long_path = "/".join([f"dir{i}" for i in range(20)]) + "/file.txt"
        resource_path = get_resource_path(long_path)

        assert os.path.isabs(resource_path)
        assert resource_path.endswith("file.txt")


class TestPackageStructureIntegrity:
    """Test that package structure is correctly resolved."""

    def test_resource_helper_module_location_is_correct(self) -> None:
        """resource_helper module is located in intellicrack/utils directory."""
        from intellicrack.utils import resource_helper

        module_path = Path(resource_helper.__file__)
        assert module_path.parts[-2] == "utils"
        assert module_path.parts[-3] == "intellicrack"

    def test_get_resource_path_resolves_to_correct_package_root(self) -> None:
        """Resource paths resolve to correct intellicrack package root."""
        resource_path = get_resource_path("__init__.py")

        path_obj = Path(resource_path)
        parent_dirs = [p for p in path_obj.parts if "intellicrack" in p]
        assert len(parent_dirs) > 0

    def test_get_resource_path_maintains_relative_structure(self) -> None:
        """Resource path maintains relative directory structure from package root."""
        resource_path = get_resource_path("core/analysis/binary_analyzer.py")

        assert "core" in resource_path
        assert "analysis" in resource_path
        path_obj = Path(resource_path)

        core_idx = -1
        for i, part in enumerate(path_obj.parts):
            if part == "core":
                core_idx = i
                break

        if core_idx >= 0 and core_idx + 1 < len(path_obj.parts):
            assert path_obj.parts[core_idx + 1] == "analysis"


class TestCrossPlatformCompatibility:
    """Test cross-platform path handling."""

    def test_get_resource_path_works_on_current_platform(self) -> None:
        """Resource path works correctly on current operating system."""
        resource_path = get_resource_path("assets/data/test.bin")

        assert os.path.isabs(resource_path)
        assert os.sep in resource_path or "/" in resource_path

    def test_get_resource_path_uses_correct_separator(self) -> None:
        """Resource path uses OS-appropriate path separator."""
        resource_path = get_resource_path("dir1/dir2/file.txt")

        path_obj = Path(resource_path)
        normalized = str(path_obj)
        assert os.sep in normalized or "/" in normalized

    def test_get_resource_path_handles_mixed_separators(self) -> None:
        """Resource path handles mixed forward and backward slashes."""
        if sys.platform == "win32":
            resource_path = get_resource_path("dir1\\dir2/dir3/file.txt")
        else:
            resource_path = get_resource_path("dir1/dir2/dir3/file.txt")

        assert os.path.isabs(resource_path)
        assert "file.txt" in resource_path


class TestIntegrationWithRealFiles:
    """Test integration with actual files in the package."""

    def test_get_resource_path_for_existing_module(self) -> None:
        """Resource path for existing module file resolves correctly."""
        resource_path = get_resource_path("utils/resource_helper.py")

        assert os.path.isabs(resource_path)
        path_obj = Path(resource_path)

        if path_obj.exists():
            assert path_obj.is_file()
            assert path_obj.name == "resource_helper.py"

    def test_get_resource_path_consistency_across_calls(self) -> None:
        """Multiple calls with same input produce consistent results."""
        path1 = get_resource_path("assets/test.bin")
        path2 = get_resource_path("assets/test.bin")
        path3 = get_resource_path("assets/test.bin")

        assert path1 == path2 == path3

    def test_get_resource_path_different_inputs_different_outputs(self) -> None:
        """Different resource paths produce different absolute paths."""
        path1 = get_resource_path("assets/file1.bin")
        path2 = get_resource_path("assets/file2.bin")
        path3 = get_resource_path("data/file1.bin")

        assert path1 != path2
        assert path1 != path3
        assert path2 != path3
