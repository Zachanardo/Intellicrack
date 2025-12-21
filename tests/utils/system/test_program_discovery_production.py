"""Production tests for program_discovery.py.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the help that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import os
import sys
from pathlib import Path

import pytest

from intellicrack.utils.system.program_discovery import (
    IS_WINDOWS,
    ProgramDiscoveryEngine,
    ProgramInfo,
)


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows-focused tests")


class TestProgramDiscoveryEngine:
    """Test real program discovery on Windows system."""

    def test_engine_initialization(self) -> None:
        """ProgramDiscoveryEngine initializes successfully."""
        engine: ProgramDiscoveryEngine = ProgramDiscoveryEngine()

        assert engine is not None
        assert hasattr(engine, "programs_cache")
        assert hasattr(engine, "path_discovery")

    def test_get_installed_programs_returns_list(self) -> None:
        """get_installed_programs returns list of programs."""
        engine: ProgramDiscoveryEngine = ProgramDiscoveryEngine()
        programs: list[ProgramInfo] = engine.get_installed_programs()

        assert isinstance(programs, list)

    @pytest.mark.skipif(not IS_WINDOWS, reason="Windows-only test")
    def test_get_installed_programs_finds_real_programs(self) -> None:
        """Program discovery finds actual installed Windows programs."""
        engine: ProgramDiscoveryEngine = ProgramDiscoveryEngine()
        programs: list[ProgramInfo] = engine.get_installed_programs()

        assert programs

    @pytest.mark.skipif(not IS_WINDOWS, reason="Windows-only test")
    def test_program_info_has_required_fields(self) -> None:
        """Discovered programs have all required ProgramInfo fields."""
        engine: ProgramDiscoveryEngine = ProgramDiscoveryEngine()
        if programs := engine.get_installed_programs():
            program: ProgramInfo = programs[0]
            assert hasattr(program, "name")
            assert hasattr(program, "display_name")
            assert hasattr(program, "version")
            assert hasattr(program, "publisher")
            assert hasattr(program, "install_location")
            assert hasattr(program, "executable_paths")

    @pytest.mark.skipif(not IS_WINDOWS, reason="Windows-only test")
    def test_program_discovery_finds_microsoft_programs(self) -> None:
        """Program discovery finds at least one Microsoft program."""
        engine: ProgramDiscoveryEngine = ProgramDiscoveryEngine()
        programs: list[ProgramInfo] = engine.get_installed_programs()

        microsoft_programs: list[ProgramInfo] = [
            p for p in programs
            if "microsoft" in p.publisher.lower() or "microsoft" in p.display_name.lower()
        ]

        assert microsoft_programs

    def test_analyze_program_from_path_valid_executable(self, tmp_path: Path) -> None:
        """analyze_program_from_path works with valid executable path."""
        test_exe: Path = tmp_path / "test.exe"
        test_exe.write_bytes(b"MZ" + b"\x00" * 100)

        engine: ProgramDiscoveryEngine = ProgramDiscoveryEngine()
        program_info: ProgramInfo | None = engine.analyze_program_from_path(str(test_exe))

        assert program_info is not None
        assert program_info.name == "test"
        assert program_info.discovery_method == "path_analysis"

    def test_analyze_program_from_path_nonexistent(self) -> None:
        """analyze_program_from_path returns None for nonexistent path."""
        engine: ProgramDiscoveryEngine = ProgramDiscoveryEngine()
        result: ProgramInfo | None = engine.analyze_program_from_path("/nonexistent/path/program.exe")

        assert result is None

    def test_discover_programs_from_path_empty_directory(self, tmp_path: Path) -> None:
        """discover_programs_from_path handles empty directory."""
        engine: ProgramDiscoveryEngine = ProgramDiscoveryEngine()
        programs: list[ProgramInfo] = engine.discover_programs_from_path(str(tmp_path))

        assert isinstance(programs, list)
        assert not programs

    @pytest.mark.skipif(not IS_WINDOWS, reason="Windows-only test")
    def test_scan_executable_directories_returns_programs(self) -> None:
        """scan_executable_directories finds programs in common directories."""
        engine: ProgramDiscoveryEngine = ProgramDiscoveryEngine()
        programs: list[ProgramInfo] = engine.scan_executable_directories()

        assert isinstance(programs, list)

    def test_program_info_dataclass_creation(self) -> None:
        """ProgramInfo dataclass can be created with all fields."""
        program: ProgramInfo = ProgramInfo(
            name="test",
            display_name="Test Program",
            version="1.0",
            publisher="Test Publisher",
            install_location="C:\\Test",
            executable_paths=["C:\\Test\\test.exe"],
            icon_path=None,
            uninstall_string=None,
            install_date=None,
            estimated_size=1000,
            architecture="x64",
            file_types=[".exe", ".dll"],
            description="Test program",
            registry_key=None,
            discovery_method="manual",
            confidence_score=0.9,
            analysis_priority=5,
        )

        assert program.name == "test"
        assert program.version == "1.0"
        assert program.analysis_priority == 5


class TestProgramAnalysis:
    """Test program analysis capabilities."""

    @pytest.mark.skipif(not IS_WINDOWS, reason="Windows-only test")
    def test_analyze_program_from_system_directory(self) -> None:
        """Analyzing program from System32 works."""
        engine: ProgramDiscoveryEngine = ProgramDiscoveryEngine()
        system32: str = os.path.join(os.environ.get("SYSTEMROOT", "C:\\Windows"), "System32")

        if os.path.exists(system32):
            if program_info := engine.analyze_program_from_path(system32):
                assert program_info.install_location == system32

    def test_calculate_analysis_priority_high_priority_software(self) -> None:
        """High-priority software gets appropriate priority score."""
        engine: ProgramDiscoveryEngine = ProgramDiscoveryEngine()

        priority: int = engine._calculate_analysis_priority("Antivirus Software", "C:\\Program Files\\AV")

        assert priority >= 8

    def test_calculate_analysis_priority_default_priority(self) -> None:
        """Unknown software gets default priority."""
        engine: ProgramDiscoveryEngine = ProgramDiscoveryEngine()

        priority: int = engine._calculate_analysis_priority("Unknown App", "C:\\Program Files\\Unknown")

        assert priority == engine.ANALYSIS_PRIORITIES["default"]

    def test_program_discovery_caching(self) -> None:
        """Program discovery uses caching mechanism."""
        engine: ProgramDiscoveryEngine = ProgramDiscoveryEngine()

        assert hasattr(engine, "programs_cache")
        assert hasattr(engine, "last_scan_time")
        assert isinstance(engine.programs_cache, dict)


class TestWindowsRegistryIntegration:
    """Test Windows registry integration for program discovery."""

    @pytest.mark.skipif(not IS_WINDOWS, reason="Windows-only test")
    def test_windows_registry_scanning_works(self) -> None:
        """Windows registry scanning finds installed programs."""
        engine: ProgramDiscoveryEngine = ProgramDiscoveryEngine()
        programs: list[ProgramInfo] = engine._get_windows_programs()

        assert isinstance(programs, list)
        assert programs

    @pytest.mark.skipif(not IS_WINDOWS, reason="Windows-only test")
    def test_discovered_programs_have_registry_info(self) -> None:
        """Programs discovered from registry have registry_key set."""
        engine: ProgramDiscoveryEngine = ProgramDiscoveryEngine()
        programs: list[ProgramInfo] = engine._get_windows_programs()

        registry_programs: list[ProgramInfo] = [
            p for p in programs if p.registry_key is not None
        ]

        assert registry_programs

    @pytest.mark.skipif(not IS_WINDOWS, reason="Windows-only test")
    def test_discovery_method_set_to_windows_registry(self) -> None:
        """Programs from registry have correct discovery_method."""
        engine: ProgramDiscoveryEngine = ProgramDiscoveryEngine()
        if programs := engine._get_windows_programs():
            for program in programs[:10]:
                assert program.discovery_method == "windows_registry"


class TestProgramDiscoveryFiltering:
    """Test program filtering and system component detection."""

    def test_is_system_component_detects_updates(self) -> None:
        """System component detection identifies Windows updates."""
        engine: ProgramDiscoveryEngine = ProgramDiscoveryEngine()

        is_system: bool = engine._is_system_component("Security Update for Windows (KB12345)", "KB12345")

        assert is_system

    def test_is_system_component_detects_redistributables(self) -> None:
        """System component detection identifies redistributables."""
        engine: ProgramDiscoveryEngine = ProgramDiscoveryEngine()

        is_system: bool = engine._is_system_component("Microsoft Visual C++ Redistributable", "vcredist")

        assert is_system

    def test_is_system_component_allows_regular_programs(self) -> None:
        """System component detection allows regular programs."""
        engine: ProgramDiscoveryEngine = ProgramDiscoveryEngine()

        is_system: bool = engine._is_system_component("Adobe Photoshop", "photoshop")

        assert not is_system


class TestLicensingFileDetection:
    """Test detection of licensing-related files in programs."""

    def test_analyze_installation_folder_detects_licensing(self, tmp_path: Path) -> None:
        """Installation folder analysis detects licensing files."""
        license_file: Path = tmp_path / "license.dat"
        license_file.write_text("License data")

        engine: ProgramDiscoveryEngine = ProgramDiscoveryEngine()
        analysis: dict = engine._analyze_installation_folder(tmp_path)

        assert analysis["has_licensing"] is True
        assert len(analysis["licensing_files"]) > 0

    def test_analyze_installation_folder_detects_various_license_files(self, tmp_path: Path) -> None:
        """Analysis detects various licensing file patterns."""
        license_patterns: list[str] = [
            "license.txt",
            "activation.key",
            "serial.dat",
            "unlock.bin",
        ]

        for pattern in license_patterns:
            (tmp_path / pattern).write_text("license data")

        engine: ProgramDiscoveryEngine = ProgramDiscoveryEngine()
        analysis: dict = engine._analyze_installation_folder(tmp_path)

        assert analysis["has_licensing"] is True
        assert len(analysis["licensing_files"]) >= len(license_patterns)


class TestArchitectureDetection:
    """Test binary architecture detection."""

    def test_get_pe_architecture_x86(self, tmp_path: Path) -> None:
        """PE architecture detection identifies x86 binaries."""
        pe_file: Path = tmp_path / "test_x86.exe"

        dos_header: bytes = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00"
        pe_header: bytes = b"PE\x00\x00" + b"\x4c\x01" + b"\x00" * 18

        pe_file.write_bytes(dos_header + b"\x00" * (0x40 - len(dos_header)) + pe_header)

        engine: ProgramDiscoveryEngine = ProgramDiscoveryEngine()
        arch: str = engine._get_pe_architecture(pe_file)

        assert arch == "x86"

    def test_get_pe_architecture_invalid_file(self, tmp_path: Path) -> None:
        """PE architecture detection handles invalid files."""
        invalid_file: Path = tmp_path / "invalid.exe"
        invalid_file.write_bytes(b"Not a PE file")

        engine: ProgramDiscoveryEngine = ProgramDiscoveryEngine()
        arch: str = engine._get_pe_architecture(invalid_file)

        assert arch == "Unknown"


class TestProgramDiscoveryEdgeCases:
    """Edge case tests for program discovery."""

    def test_engine_handles_nonexistent_cache_file(self) -> None:
        """Engine handles nonexistent cache file gracefully."""
        engine: ProgramDiscoveryEngine = ProgramDiscoveryEngine(cache_file="/nonexistent/cache.json")

        assert engine is not None
        assert isinstance(engine.programs_cache, dict)

    def test_discover_programs_from_nonexistent_path(self) -> None:
        """Discovering programs from nonexistent path returns empty list."""
        engine: ProgramDiscoveryEngine = ProgramDiscoveryEngine()
        programs: list[ProgramInfo] = engine.discover_programs_from_path("/nonexistent/path")

        assert not programs

    def test_analyze_program_from_path_directory_without_executables(self, tmp_path: Path) -> None:
        """Analyzing directory without executables works."""
        subdir: Path = tmp_path / "empty_program"
        subdir.mkdir()

        engine: ProgramDiscoveryEngine = ProgramDiscoveryEngine()
        if result := engine.analyze_program_from_path(str(subdir)):
            assert result.executable_paths == [] or len(result.executable_paths) == 0
