"""Production tests for os_detection.py.

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
import platform
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.utils.system.os_detection import (
    detect_file_type,
    detect_operating_system,
    get_default_persistence_method,
    get_platform_details,
    get_platform_specific_paths,
    is_linux_like,
    is_unix_like,
    is_windows,
)


class TestOperatingSystemDetection:
    """Test real operating system detection."""

    def test_detect_operating_system_returns_valid_value(self) -> None:
        """OS detection returns one of the expected values."""
        detected_os: str = detect_operating_system()

        assert detected_os in {"windows", "linux", "unknown"}

    def test_detect_operating_system_matches_platform(self) -> None:
        """OS detection matches actual platform.system()."""
        detected_os: str = detect_operating_system()
        system: str = platform.system().lower()

        if system == "windows":
            assert detected_os == "windows"
        elif system in {"linux", "darwin"}:
            assert detected_os == "linux"

    def test_detect_operating_system_consistency(self) -> None:
        """Multiple calls return consistent OS detection."""
        result1: str = detect_operating_system()
        result2: str = detect_operating_system()
        result3: str = detect_operating_system()

        assert result1 == result2 == result3

    def test_is_windows_correct_for_platform(self) -> None:
        """is_windows() returns correct value for current platform."""
        result: bool = is_windows()

        if sys.platform == "win32":
            assert result
        else:
            assert not result

    def test_is_linux_like_correct_for_platform(self) -> None:
        """is_linux_like() returns correct value for current platform."""
        result: bool = is_linux_like()

        if sys.platform.startswith("linux") or sys.platform == "darwin":
            assert result
        else:
            assert not result

    def test_is_unix_like_matches_linux_like(self) -> None:
        """is_unix_like() matches is_linux_like() output."""
        unix_result: bool = is_unix_like()
        linux_result: bool = is_linux_like()

        assert unix_result == linux_result

    def test_windows_and_linux_mutually_exclusive(self) -> None:
        """Windows and Linux detection are mutually exclusive."""
        windows: bool = is_windows()
        linux: bool = is_linux_like()

        assert not (windows and linux)


class TestPlatformDetails:
    """Test platform information retrieval."""

    def test_get_platform_details_returns_all_fields(self) -> None:
        """Platform details contains all required fields."""
        details: dict[str, Any] = get_platform_details()

        required_fields: list[str] = [
            "system",
            "release",
            "version",
            "machine",
            "processor",
            "architecture",
            "normalized_os",
        ]

        for field in required_fields:
            assert field in details
            assert details[field] is not None

    def test_get_platform_details_system_matches_platform(self) -> None:
        """Platform details system field matches platform.system()."""
        details: dict[str, Any] = get_platform_details()

        assert details["system"] == platform.system()

    def test_get_platform_details_release_matches_platform(self) -> None:
        """Platform details release matches platform.release()."""
        details: dict[str, Any] = get_platform_details()

        assert details["release"] == platform.release()

    def test_get_platform_details_version_matches_platform(self) -> None:
        """Platform details version matches platform.version()."""
        details: dict[str, Any] = get_platform_details()

        assert details["version"] == platform.version()

    def test_get_platform_details_machine_matches_platform(self) -> None:
        """Platform details machine matches platform.machine()."""
        details: dict[str, Any] = get_platform_details()

        assert details["machine"] == platform.machine()

    def test_get_platform_details_architecture_is_tuple(self) -> None:
        """Platform details architecture is tuple from platform.architecture()."""
        details: dict[str, Any] = get_platform_details()

        assert isinstance(details["architecture"], tuple)
        assert len(details["architecture"]) == 2

    def test_get_platform_details_normalized_os_valid(self) -> None:
        """Platform details normalized_os is valid value."""
        details: dict[str, Any] = get_platform_details()

        assert details["normalized_os"] in ["windows", "linux", "unknown"]

    def test_get_platform_details_consistency(self) -> None:
        """Multiple calls return consistent platform details."""
        details1: dict[str, Any] = get_platform_details()
        details2: dict[str, Any] = get_platform_details()

        assert details1 == details2


class TestPersistenceMethod:
    """Test default persistence method selection."""

    def test_get_default_persistence_method_returns_string(self) -> None:
        """Default persistence method returns non-empty string."""
        method: str = get_default_persistence_method()

        assert isinstance(method, str)
        assert method != ""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_get_default_persistence_method_windows(self) -> None:
        """Windows returns scheduled_task as default persistence."""
        method: str = get_default_persistence_method()

        assert method == "scheduled_task"

    @pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux-only test")
    def test_get_default_persistence_method_linux(self) -> None:
        """Linux returns systemd_service as default persistence."""
        method: str = get_default_persistence_method()

        assert method == "systemd_service"

    def test_get_default_persistence_method_valid_options(self) -> None:
        """Persistence method is one of the valid options."""
        method: str = get_default_persistence_method()
        valid_methods: list[str] = ["scheduled_task", "systemd_service", "cron_job"]

        assert method in valid_methods


class TestPlatformSpecificPaths:
    """Test platform-specific path resolution."""

    def test_get_platform_specific_paths_returns_dict(self) -> None:
        """Platform specific paths returns dictionary."""
        paths: dict[str, str] = get_platform_specific_paths()

        assert isinstance(paths, dict)
        assert paths

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_get_platform_specific_paths_windows_keys(self) -> None:
        """Windows platform paths contain expected keys."""
        paths: dict[str, str] = get_platform_specific_paths()

        expected_keys: list[str] = [
            "temp",
            "appdata",
            "localappdata",
            "programfiles",
            "system32",
            "documents",
        ]

        for key in expected_keys:
            assert key in paths

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_get_platform_specific_paths_windows_temp_valid(self) -> None:
        """Windows temp path exists and is directory."""
        paths: dict[str, str] = get_platform_specific_paths()

        temp_path: str = paths["temp"]
        assert os.path.exists(temp_path)
        assert os.path.isdir(temp_path)

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_get_platform_specific_paths_windows_system32_exists(self) -> None:
        """Windows System32 path exists."""
        paths: dict[str, str] = get_platform_specific_paths()

        system32: str = paths["system32"]
        assert os.path.exists(system32)
        assert os.path.isdir(system32)

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_get_platform_specific_paths_windows_programfiles_exists(self) -> None:
        """Windows Program Files path exists."""
        paths: dict[str, str] = get_platform_specific_paths()

        programfiles: str = paths["programfiles"]
        assert os.path.exists(programfiles)
        assert os.path.isdir(programfiles)

    @pytest.mark.skipif(not sys.platform.startswith("linux") and sys.platform != "darwin", reason="Unix-like only")
    def test_get_platform_specific_paths_unix_keys(self) -> None:
        """Unix-like platform paths contain expected keys."""
        paths: dict[str, str] = get_platform_specific_paths()

        expected_keys: list[str] = ["temp", "home", "etc", "var", "usr", "bin"]

        for key in expected_keys:
            assert key in paths

    @pytest.mark.skipif(not sys.platform.startswith("linux") and sys.platform != "darwin", reason="Unix-like only")
    def test_get_platform_specific_paths_unix_temp_valid(self) -> None:
        """Unix temp path exists and is directory."""
        paths: dict[str, str] = get_platform_specific_paths()

        temp_path: str = paths["temp"]
        assert os.path.exists(temp_path)
        assert os.path.isdir(temp_path)

    def test_get_platform_specific_paths_temp_matches_tempfile(self) -> None:
        """Temp path matches system temp directory."""
        paths: dict[str, str] = get_platform_specific_paths()

        temp_from_paths: str = paths["temp"]
        system_temp: str = tempfile.gettempdir()

        if sys.platform == "win32":
            temp_normalized: str = os.path.normpath(temp_from_paths).lower()
            system_normalized: str = os.path.normpath(system_temp).lower()
            assert temp_normalized in system_normalized or system_normalized in temp_normalized
        else:
            assert temp_from_paths == system_temp


class TestFileTypeDetection:
    """Test binary file type detection."""

    def test_detect_file_type_nonexistent_file(self) -> None:
        """Non-existent file returns unknown type."""
        file_type: str = detect_file_type("/nonexistent/path/file.exe")

        assert file_type == "unknown"

    def test_detect_file_type_pe_executable(self, tmp_path: Path) -> None:
        """PE executable detected correctly."""
        pe_file: Path = tmp_path / "test.exe"
        pe_file.write_bytes(b"MZ\x90\x00" + b"\x00" * 60)

        file_type: str = detect_file_type(str(pe_file))

        assert file_type == "pe"

    def test_detect_file_type_elf_executable(self, tmp_path: Path) -> None:
        """ELF executable detected correctly."""
        elf_file: Path = tmp_path / "test.elf"
        elf_file.write_bytes(b"\x7fELF" + b"\x00" * 60)

        file_type: str = detect_file_type(str(elf_file))

        assert file_type == "elf"

    def test_detect_file_type_macho_executable_be(self, tmp_path: Path) -> None:
        """Mach-O big-endian executable detected correctly."""
        macho_file: Path = tmp_path / "test.macho"
        macho_file.write_bytes(b"\xfe\xed\xfa\xce" + b"\x00" * 60)

        file_type: str = detect_file_type(str(macho_file))

        assert file_type == "macho"

    def test_detect_file_type_macho_executable_le(self, tmp_path: Path) -> None:
        """Mach-O little-endian executable detected correctly."""
        macho_file: Path = tmp_path / "test_le.macho"
        macho_file.write_bytes(b"\xce\xfa\xed\xfe" + b"\x00" * 60)

        file_type: str = detect_file_type(str(macho_file))

        assert file_type == "macho"

    def test_detect_file_type_macho_64bit_be(self, tmp_path: Path) -> None:
        """Mach-O 64-bit big-endian detected correctly."""
        macho_file: Path = tmp_path / "test_64be.macho"
        macho_file.write_bytes(b"\xfe\xed\xfa\xcf" + b"\x00" * 60)

        file_type: str = detect_file_type(str(macho_file))

        assert file_type == "macho"

    def test_detect_file_type_macho_64bit_le(self, tmp_path: Path) -> None:
        """Mach-O 64-bit little-endian detected correctly."""
        macho_file: Path = tmp_path / "test_64le.macho"
        macho_file.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 60)

        file_type: str = detect_file_type(str(macho_file))

        assert file_type == "macho"

    def test_detect_file_type_text_file(self, tmp_path: Path) -> None:
        """Text file returns unknown type."""
        text_file: Path = tmp_path / "test.txt"
        text_file.write_text("This is a text file")

        file_type: str = detect_file_type(str(text_file))

        assert file_type == "unknown"

    def test_detect_file_type_empty_file(self, tmp_path: Path) -> None:
        """Empty file returns unknown type."""
        empty_file: Path = tmp_path / "empty.bin"
        empty_file.write_bytes(b"")

        file_type: str = detect_file_type(str(empty_file))

        assert file_type == "unknown"

    def test_detect_file_type_short_file(self, tmp_path: Path) -> None:
        """File shorter than header returns unknown."""
        short_file: Path = tmp_path / "short.bin"
        short_file.write_bytes(b"MZ")

        file_type: str = detect_file_type(str(short_file))

        assert file_type in {"pe", "unknown"}

    def test_detect_file_type_consistency(self, tmp_path: Path) -> None:
        """Multiple detections of same file return same result."""
        pe_file: Path = tmp_path / "consistent.exe"
        pe_file.write_bytes(b"MZ\x90\x00" + b"\x00" * 60)

        type1: str = detect_file_type(str(pe_file))
        type2: str = detect_file_type(str(pe_file))
        type3: str = detect_file_type(str(pe_file))

        assert type1 == type2 == type3


class TestOSDetectionIntegration:
    """Integration tests for OS detection utilities."""

    def test_all_detection_methods_agree(self) -> None:
        """All OS detection methods return consistent results."""
        detected_os: str = detect_operating_system()
        windows: bool = is_windows()
        unix: bool = is_unix_like()

        if detected_os == "linux":
            assert not windows
            assert unix
        elif detected_os == "windows":
            assert windows is True
            assert unix is False

    def test_platform_paths_accessible(self) -> None:
        """Platform-specific paths are accessible on real system."""
        paths: dict[str, str] = get_platform_specific_paths()

        for key, path in paths.items():
            if path and os.path.exists(path):
                assert os.access(path, os.R_OK) or key in ["appdata", "localappdata"]

    def test_platform_details_complete(self) -> None:
        """Platform details provide complete system information."""
        details: dict[str, Any] = get_platform_details()

        assert len(details["system"]) > 0
        assert len(details["machine"]) > 0
        assert details["architecture"][0] in ["32bit", "64bit"]

    def test_persistence_method_platform_appropriate(self) -> None:
        """Persistence method is appropriate for detected platform."""
        os_type: str = detect_operating_system()
        method: str = get_default_persistence_method()

        if os_type == "linux":
            assert method in {"systemd_service", "cron_job"}
        elif os_type == "windows":
            assert method == "scheduled_task"
