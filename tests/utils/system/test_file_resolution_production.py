"""Production tests for file resolution system.

Tests validate real shortcut resolution, file type detection, metadata extraction,
and cross-platform file handling.

Copyright (C) 2025 Zachary Flint
"""

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from intellicrack.utils.system.file_resolution import (
    FileResolver,
    FileTypeInfo,
    file_resolver,
)


class TestFileTypeInfo:
    """Test FileTypeInfo class functionality."""

    def test_file_type_info_initialization(self) -> None:
        """FileTypeInfo initializes with correct attributes."""
        file_type = FileTypeInfo(
            extension=".exe",
            description="Windows Executable",
            category="executable",
            supported=True,
            analyzer_hint="pe",
        )

        assert file_type.extension == ".exe"
        assert file_type.description == "Windows Executable"
        assert file_type.category == "executable"
        assert file_type.supported is True
        assert file_type.analyzer_hint == "pe"

    def test_file_type_info_lowercase_extension(self) -> None:
        """FileTypeInfo normalizes extension to lowercase."""
        file_type = FileTypeInfo(".EXE", "Executable", "executable")

        assert file_type.extension == ".exe"

    def test_file_type_info_default_analyzer(self) -> None:
        """FileTypeInfo uses default analyzer hint when not provided."""
        file_type = FileTypeInfo(".dat", "Data File", "data")

        assert file_type.analyzer_hint == "generic"


class TestFileResolverInitialization:
    """Test FileResolver initialization and file type registry."""

    def test_file_resolver_initialization(self) -> None:
        """FileResolver initializes with complete file type registry."""
        resolver = FileResolver()

        assert isinstance(resolver.FILE_TYPES, dict)
        assert len(resolver.FILE_TYPES) > 0

    def test_file_types_registry_completeness(self) -> None:
        """File types registry has comprehensive coverage."""
        resolver = FileResolver()

        expected_categories = {
            "executable",
            "library",
            "installer",
            "shortcut",
            "archive",
            "firmware",
        }

        found_categories = {
            file_type.category for file_type in resolver.FILE_TYPES.values()
        }
        assert expected_categories.issubset(found_categories)

    def test_windows_executable_types(self) -> None:
        """Windows executable types properly registered."""
        resolver = FileResolver()

        windows_exts = [".exe", ".dll", ".sys", ".scr"]

        for ext in windows_exts:
            assert ext in resolver.FILE_TYPES
            file_type = resolver.FILE_TYPES[ext]
            assert file_type.category in ["executable", "library", "driver"]
            assert file_type.supported is True

    def test_linux_executable_types(self) -> None:
        """Linux executable types properly registered."""
        resolver = FileResolver()

        linux_exts = [".so", ".o", ".a", ".elf"]

        for ext in linux_exts:
            assert ext in resolver.FILE_TYPES
            file_type = resolver.FILE_TYPES[ext]
            assert file_type.supported is True

    def test_macos_executable_types(self) -> None:
        """macOS executable types properly registered."""
        resolver = FileResolver()

        macos_exts = [".app", ".dylib", ".bundle", ".framework"]

        for ext in macos_exts:
            assert ext in resolver.FILE_TYPES
            file_type = resolver.FILE_TYPES[ext]
            assert file_type.supported is True

    def test_installer_types(self) -> None:
        """Installer package types properly registered."""
        resolver = FileResolver()

        installer_exts = [".msi", ".deb", ".rpm", ".pkg", ".dmg"]

        for ext in installer_exts:
            assert ext in resolver.FILE_TYPES
            file_type = resolver.FILE_TYPES[ext]
            assert file_type.category == "installer"


class TestFileTypeDetection:
    """Test file type detection and information retrieval."""

    def test_get_file_type_info_executable(self, tmp_path: Path) -> None:
        """Correctly identify executable file type."""
        resolver = FileResolver()

        exe_file = tmp_path / "test.exe"
        exe_file.touch()

        file_type = resolver.get_file_type_info(exe_file)

        assert file_type.extension == ".exe"
        assert file_type.category == "executable"
        assert file_type.supported is True
        assert file_type.analyzer_hint == "pe"

    def test_get_file_type_info_library(self, tmp_path: Path) -> None:
        """Correctly identify library file type."""
        resolver = FileResolver()

        dll_file = tmp_path / "library.dll"
        dll_file.touch()

        file_type = resolver.get_file_type_info(dll_file)

        assert file_type.extension == ".dll"
        assert file_type.category == "library"
        assert file_type.analyzer_hint == "pe"

    def test_get_file_type_info_archive(self, tmp_path: Path) -> None:
        """Correctly identify archive file type."""
        resolver = FileResolver()

        zip_file = tmp_path / "archive.zip"
        zip_file.touch()

        file_type = resolver.get_file_type_info(zip_file)

        assert file_type.extension == ".zip"
        assert file_type.category == "archive"

    def test_get_file_type_info_unknown(self, tmp_path: Path) -> None:
        """Handle unknown file types gracefully."""
        resolver = FileResolver()

        unknown_file = tmp_path / "file.unknownext"
        unknown_file.touch()

        file_type = resolver.get_file_type_info(unknown_file)

        assert file_type.extension == ".unknownext"
        assert file_type.category == "unknown"
        assert file_type.supported is False

    def test_get_file_type_info_directory(self, tmp_path: Path) -> None:
        """Handle directory as file type."""
        resolver = FileResolver()

        directory = tmp_path / "test_dir"
        directory.mkdir()

        file_type = resolver.get_file_type_info(directory)

        assert file_type.category == "directory"
        assert file_type.supported is False

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS-specific test")
    def test_get_file_type_info_app_bundle(self, tmp_path: Path) -> None:
        """macOS app bundle recognized as executable."""
        resolver = FileResolver()

        app_bundle = tmp_path / "Test.app"
        app_bundle.mkdir()

        file_type = resolver.get_file_type_info(app_bundle)

        assert file_type.extension == ".app"
        assert file_type.category == "executable"
        assert file_type.supported is True


class TestFilePathResolution:
    """Test file path resolution including shortcuts."""

    def test_resolve_file_path_regular_file(self, tmp_path: Path) -> None:
        """Resolve regular file returns direct path."""
        resolver = FileResolver()

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"test content")

        resolved_path, metadata = resolver.resolve_file_path(test_file)

        assert resolved_path == str(test_file)
        assert metadata["original_path"] == str(test_file)
        assert metadata["is_shortcut"] is False
        assert metadata["resolution_method"] == "direct"
        assert "file_type" in metadata
        assert "size" in metadata

    def test_resolve_file_path_nonexistent(self, tmp_path: Path) -> None:
        """Nonexistent file returns error metadata."""
        resolver = FileResolver()

        nonexistent = tmp_path / "nonexistent.exe"

        resolved_path, metadata = resolver.resolve_file_path(nonexistent)

        assert resolved_path == str(nonexistent)
        assert "error" in metadata
        assert "not found" in metadata["error"].lower()

    def test_resolve_file_path_symlink(self, tmp_path: Path) -> None:
        """Symbolic link resolution works correctly."""
        resolver = FileResolver()

        target_file = tmp_path / "target.exe"
        target_file.write_bytes(b"target content")

        if sys.platform != "win32":
            link_file = tmp_path / "link.exe"
            link_file.symlink_to(target_file)

            resolved_path, metadata = resolver.resolve_file_path(link_file)

            assert resolved_path == str(target_file.resolve())
            assert metadata["is_shortcut"] is True
            assert metadata["resolution_method"] == "symlink"
            assert metadata["target_path"] == str(target_file.resolve())

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows shortcut test")
    def test_resolve_windows_shortcut_real(self, tmp_path: Path) -> None:
        """Resolve real Windows .lnk shortcut."""
        try:
            import pythoncom
            import win32com.client

            resolver = FileResolver()

            target_exe = tmp_path / "target.exe"
            target_exe.write_bytes(b"target")

            lnk_file = tmp_path / "shortcut.lnk"

            pythoncom.CoInitialize()
            shell = win32com.client.Dispatch("WScript.Shell")
            shortcut = shell.CreateShortCut(str(lnk_file))
            shortcut.Targetpath = str(target_exe)
            shortcut.WorkingDirectory = str(tmp_path)
            shortcut.Description = "Test shortcut"
            shortcut.Save()
            pythoncom.CoUninitialize()

            resolved_path, metadata = resolver.resolve_file_path(lnk_file)

            assert resolved_path == str(target_exe)
            assert metadata["is_shortcut"] is True
            assert metadata["resolution_method"] == "windows_shortcut"
            assert metadata["target_path"] == str(target_exe)
            assert metadata["working_directory"] == str(tmp_path)
            assert metadata["description"] == "Test shortcut"

        except ImportError:
            pytest.skip("win32com not available")

    def test_resolve_url_shortcut(self, tmp_path: Path) -> None:
        """Resolve .url internet shortcut."""
        resolver = FileResolver()

        url_file = tmp_path / "website.url"
        url_content = "[InternetShortcut]\nURL=https://example.com\n"
        url_file.write_text(url_content, encoding="utf-8")

        resolved_path, metadata = resolver.resolve_file_path(url_file)

        assert resolved_path == "https://example.com"
        assert metadata["is_shortcut"] is True
        assert metadata["resolution_method"] == "url_shortcut"
        assert metadata["target_url"] == "https://example.com"


class TestFileMetadata:
    """Test comprehensive file metadata extraction."""

    def test_get_file_metadata_basic(self, tmp_path: Path) -> None:
        """Extract basic file metadata."""
        resolver = FileResolver()

        test_file = tmp_path / "test.exe"
        content = b"test content data"
        test_file.write_bytes(content)

        metadata = resolver.get_file_metadata(test_file)

        assert metadata["path"] == str(test_file)
        assert metadata["name"] == "test.exe"
        assert metadata["stem"] == "test"
        assert metadata["extension"] == ".exe"
        assert metadata["size"] == len(content)
        assert "size_human" in metadata
        assert metadata["is_file"] is True
        assert metadata["is_dir"] is False

    def test_get_file_metadata_timestamps(self, tmp_path: Path) -> None:
        """File metadata includes timestamp information."""
        resolver = FileResolver()

        test_file = tmp_path / "file.txt"
        test_file.write_text("content")

        metadata = resolver.get_file_metadata(test_file)

        assert "created" in metadata
        assert "modified" in metadata
        assert "accessed" in metadata
        assert isinstance(metadata["created"], float)
        assert isinstance(metadata["modified"], float)

    def test_get_file_metadata_file_type(self, tmp_path: Path) -> None:
        """File metadata includes file type information."""
        resolver = FileResolver()

        exe_file = tmp_path / "program.exe"
        exe_file.write_bytes(b"PE executable content")

        metadata = resolver.get_file_metadata(exe_file)

        assert "file_type" in metadata
        file_type = metadata["file_type"]
        assert file_type["extension"] == ".exe"
        assert file_type["category"] == "executable"
        assert file_type["supported"] is True

    def test_get_file_metadata_nonexistent(self, tmp_path: Path) -> None:
        """Nonexistent file returns error metadata."""
        resolver = FileResolver()

        nonexistent = tmp_path / "nonexistent.exe"

        metadata = resolver.get_file_metadata(nonexistent)

        assert "error" in metadata
        assert "not found" in metadata["error"].lower()

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows metadata test")
    def test_get_windows_metadata(self, tmp_path: Path) -> None:
        """Windows-specific metadata extraction."""
        resolver = FileResolver()

        exe_file = tmp_path / "program.exe"
        exe_file.write_bytes(b"MZ" + b"\x00" * 100)

        metadata = resolver.get_file_metadata(exe_file)

        assert "is_pe" in metadata or "format_hint" in metadata

    @pytest.mark.skipif(sys.platform != "linux", reason="Linux metadata test")
    def test_get_linux_metadata(self, tmp_path: Path) -> None:
        """Linux-specific metadata extraction."""
        resolver = FileResolver()

        elf_file = tmp_path / "program"
        elf_file.write_bytes(b"\x7fELF" + b"\x00" * 100)

        metadata = resolver.get_file_metadata(elf_file)

        if "is_elf" in metadata:
            assert metadata["is_elf"] is True
            assert metadata["format_hint"] == "elf"


class TestFileSizeFormatting:
    """Test human-readable file size formatting."""

    def test_format_bytes_small(self) -> None:
        """Format small byte sizes."""
        resolver = FileResolver()

        assert "B" in resolver._format_bytes(512)
        assert "512" in resolver._format_bytes(512)

    def test_format_bytes_kilobytes(self) -> None:
        """Format kilobyte sizes."""
        resolver = FileResolver()

        result = resolver._format_bytes(2048)

        assert "KB" in result
        assert "2.0" in result

    def test_format_bytes_megabytes(self) -> None:
        """Format megabyte sizes."""
        resolver = FileResolver()

        result = resolver._format_bytes(5 * 1024 * 1024)

        assert "MB" in result
        assert "5.0" in result

    def test_format_bytes_gigabytes(self) -> None:
        """Format gigabyte sizes."""
        resolver = FileResolver()

        result = resolver._format_bytes(3 * 1024 * 1024 * 1024)

        assert "GB" in result
        assert "3.0" in result


class TestSupportedFileFilters:
    """Test Qt file dialog filter generation."""

    def test_get_supported_file_filters_structure(self) -> None:
        """File filter string properly structured for Qt."""
        resolver = FileResolver()

        filters = resolver.get_supported_file_filters()

        assert isinstance(filters, str)
        assert "All Supported Files" in filters
        assert "All Files (*)" in filters
        assert ";;" in filters

    def test_get_supported_file_filters_categories(self) -> None:
        """File filters include all major categories."""
        resolver = FileResolver()

        filters = resolver.get_supported_file_filters()

        expected_categories = [
            "Executable Files",
            "Library Files",
            "Installer Packages",
            "Archive Files",
        ]

        for category in expected_categories:
            assert category in filters

    def test_get_supported_file_filters_extensions(self) -> None:
        """File filters include common extensions."""
        resolver = FileResolver()

        filters = resolver.get_supported_file_filters()

        common_extensions = ["*.exe", "*.dll", "*.so", "*.zip", "*.elf"]

        for ext in common_extensions:
            assert ext in filters


class TestModuleLevelSingleton:
    """Test module-level file_resolver singleton."""

    def test_file_resolver_singleton(self) -> None:
        """Module-level file_resolver is properly initialized."""
        assert isinstance(file_resolver, FileResolver)
        assert hasattr(file_resolver, "FILE_TYPES")
        assert len(file_resolver.FILE_TYPES) > 0

    def test_singleton_file_type_access(self) -> None:
        """Singleton provides access to file type information."""
        assert ".exe" in file_resolver.FILE_TYPES
        assert ".dll" in file_resolver.FILE_TYPES
        assert ".so" in file_resolver.FILE_TYPES


class TestRealWorldScenarios:
    """Test real-world file resolution scenarios."""

    def test_resolve_multiple_file_types(self, tmp_path: Path) -> None:
        """Resolve multiple different file types."""
        resolver = FileResolver()

        files = [
            ("program.exe", b"PE content"),
            ("library.dll", b"DLL content"),
            ("archive.zip", b"ZIP content"),
            ("data.bin", b"Binary data"),
        ]

        for filename, content in files:
            file_path = tmp_path / filename
            file_path.write_bytes(content)

            resolved, metadata = resolver.resolve_file_path(file_path)

            assert resolved == str(file_path)
            assert metadata["is_shortcut"] is False
            assert metadata["size"] == len(content)

    def test_file_type_detection_workflow(self, tmp_path: Path) -> None:
        """Complete file type detection workflow."""
        resolver = FileResolver()

        test_files = [
            "app.exe",
            "lib.dll",
            "installer.msi",
            "firmware.bin",
        ]

        for filename in test_files:
            file_path = tmp_path / filename
            file_path.write_bytes(b"content")

            file_type = resolver.get_file_type_info(file_path)

            assert file_type.supported is True
            assert len(file_type.extension) > 0
            assert len(file_type.description) > 0

    def test_metadata_extraction_workflow(self, tmp_path: Path) -> None:
        """Complete metadata extraction workflow."""
        resolver = FileResolver()

        exe_file = tmp_path / "analysis_target.exe"
        exe_file.write_bytes(b"MZ" + b"\x00" * 1000)

        metadata = resolver.get_file_metadata(exe_file)

        assert metadata["path"] == str(exe_file)
        assert metadata["size"] > 0
        assert metadata["is_file"] is True
        assert metadata["file_type"]["extension"] == ".exe"

    def test_shortcut_resolution_chain(self, tmp_path: Path) -> None:
        """Resolve chain of shortcuts to final target."""
        resolver = FileResolver()

        target = tmp_path / "target.exe"
        target.write_bytes(b"target executable")

        if sys.platform != "win32":
            link1 = tmp_path / "link1"
            link1.symlink_to(target)

            link2 = tmp_path / "link2"
            link2.symlink_to(link1)

            resolved, metadata = resolver.resolve_file_path(link2)

            assert Path(resolved).resolve() == target.resolve()
            assert metadata["is_shortcut"] is True

    def test_installer_package_detection(self, tmp_path: Path) -> None:
        """Detect various installer package formats."""
        resolver = FileResolver()

        installer_files = [
            "setup.msi",
            "package.deb",
            "software.rpm",
            "app.dmg",
        ]

        for filename in installer_files:
            file_path = tmp_path / filename
            file_path.write_bytes(b"installer content")

            file_type = resolver.get_file_type_info(file_path)

            assert file_type.category == "installer"
            assert file_type.supported is True

    def test_cross_platform_file_handling(self, tmp_path: Path) -> None:
        """Handle files from different platforms."""
        resolver = FileResolver()

        cross_platform_files = [
            ("windows.exe", ".exe", "executable"),
            ("linux.so", ".so", "library"),
            ("mac.dylib", ".dylib", "library"),
            ("universal.zip", ".zip", "archive"),
        ]

        for filename, extension, expected_category in cross_platform_files:
            file_path = tmp_path / filename
            file_path.write_bytes(b"content")

            file_type = resolver.get_file_type_info(file_path)

            assert file_type.extension == extension
            assert file_type.category == expected_category
