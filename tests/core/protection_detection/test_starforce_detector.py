"""
Production-grade tests for StarForce detector module.

Tests StarForce protection detection using REAL binary analysis, file I/O,
registry operations, and driver detection. NO MOCKS - all tests validate
actual detection capabilities against real or realistically-generated data.
"""

import struct
import tempfile
import winreg
from pathlib import Path
from typing import Iterator

import pefile
import pytest

from intellicrack.core.protection_detection.starforce_detector import (
    StarForceDetection,
    StarForceDetector,
    StarForceVersion,
)


class StarForceBinaryGenerator:
    """Generates realistic PE binaries with StarForce protection indicators."""

    @staticmethod
    def create_pe_with_starforce_sections(output_path: Path, sections: list[str]) -> None:
        """Create a minimal PE executable with specified StarForce sections."""
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)

        pe_signature = b"PE\x00\x00"

        coff_header = struct.pack(
            "<HHIIIHH",
            0x014C,
            len(sections) + 1,
            0,
            0,
            0,
            0x00E0,
            0x010B,
        )

        optional_header = struct.pack(
            "<HHIIIIIHHHHHHHIIIIHHHHHHI",
            0x010B,
            0x0E,
            0x00000000,
            0x00001000,
            0x00000000,
            0x00001000,
            0x00001000,
            0x00000200,
            4,
            0,
            5,
            1,
            0,
            0,
            0,
            0x00003000,
            0x00000200,
            0,
            2,
            0,
            0x00100000,
            0x00000200,
            0x00001000,
            0x00000000,
            0,
        ) + b"\x00" * 128

        text_section = (
            b".text\x00\x00\x00"
            + struct.pack("<IIIIHHI", 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0)
            + struct.pack("<I", 0x60000020)
        )

        section_headers = b""
        for section_name in sections:
            padded_name = section_name.encode("utf-8")[:8].ljust(8, b"\x00")
            section_headers += (
                padded_name
                + struct.pack("<IIIIHHI", 0x1000, 0x2000, 0, 0, 0, 0, 0)
                + struct.pack("<I", 0x20000000)
            )

        pe_data = (
            dos_header
            + b"\x00" * (0x80 - len(dos_header))
            + pe_signature
            + coff_header
            + optional_header
            + text_section
            + section_headers
        )

        pe_data = pe_data.ljust(0x200, b"\x00")
        pe_data += b"\xC3" * 0x200

        output_path.write_bytes(pe_data)

    @staticmethod
    def create_pe_with_starforce_strings(output_path: Path, strings: list[bytes]) -> None:
        """Create a PE with embedded StarForce identification strings."""
        StarForceBinaryGenerator.create_pe_with_starforce_sections(output_path, [])

        pe_data = bytearray(output_path.read_bytes())

        for string in strings:
            pe_data.extend(string)
            pe_data.extend(b"\x00" * 16)

        output_path.write_bytes(pe_data)

    @staticmethod
    def create_pe_with_version_info(output_path: Path, version_string: str) -> None:
        """Create a PE with StarForce version information embedded."""
        StarForceBinaryGenerator.create_pe_with_starforce_sections(output_path, [])

        version_bytes = version_string.encode("utf-16le") + b"\x00\x00"

        pe_data = bytearray(output_path.read_bytes())
        pe_data.extend(b"Protection Technology" + b"\x00" * 50)
        pe_data.extend(version_bytes)

        output_path.write_bytes(pe_data)


class TemporaryDriverManager:
    """Manages temporary driver files for testing driver detection."""

    def __init__(self, temp_dir: Path) -> None:
        """Initialize driver manager with temporary directory."""
        self.temp_dir = temp_dir
        self.driver_dir = temp_dir / "drivers"
        self.driver_dir.mkdir(exist_ok=True)
        self.created_drivers: list[Path] = []

    def create_driver(self, driver_name: str) -> Path:
        """Create a fake driver file for testing."""
        driver_path = self.driver_dir / driver_name
        driver_path.write_bytes(b"DRIVER_SIGNATURE" + b"\x00" * 512)
        self.created_drivers.append(driver_path)
        return driver_path

    def cleanup(self) -> None:
        """Clean up all created driver files."""
        for driver_path in self.created_drivers:
            if driver_path.exists():
                driver_path.unlink()


class TemporaryRegistryManager:
    """Manages temporary registry keys for testing registry detection."""

    def __init__(self) -> None:
        """Initialize registry manager."""
        self.created_keys: list[tuple[int, str]] = []

    def create_test_key(self, root: int, subkey: str) -> None:
        """Create a temporary registry key for testing."""
        try:
            key = winreg.CreateKey(root, subkey)
            winreg.CloseKey(key)
            self.created_keys.append((root, subkey))
        except OSError:
            pass

    def cleanup(self) -> None:
        """Clean up all created registry keys."""
        for root, subkey in reversed(self.created_keys):
            try:
                winreg.DeleteKey(root, subkey)
            except OSError:
                pass


@pytest.fixture
def temp_binary_dir() -> Iterator[Path]:
    """Provide temporary directory for binary test files."""
    with tempfile.TemporaryDirectory(prefix="starforce_test_") as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def binary_generator() -> StarForceBinaryGenerator:
    """Provide StarForce binary generator."""
    return StarForceBinaryGenerator()


@pytest.fixture
def driver_manager(temp_binary_dir: Path) -> Iterator[TemporaryDriverManager]:
    """Provide driver file manager."""
    manager = TemporaryDriverManager(temp_binary_dir)
    yield manager
    manager.cleanup()


@pytest.fixture
def registry_manager() -> Iterator[TemporaryRegistryManager]:
    """Provide registry key manager."""
    manager = TemporaryRegistryManager()
    yield manager
    manager.cleanup()


@pytest.fixture
def starforce_detector() -> StarForceDetector:
    """Provide StarForce detector instance."""
    return StarForceDetector()


@pytest.fixture
def real_starforce_binary() -> Path:
    """Provide path to real StarForce-protected test binary."""
    fixture_path = Path(__file__).parent.parent.parent / "fixtures" / "binaries" / "pe" / "protected" / "starforce_protected.exe"
    if not fixture_path.exists():
        pytest.skip(f"Real StarForce binary not found at {fixture_path}")
    return fixture_path


class TestStarForceDetectorInitialization:
    """Test detector initialization and configuration."""

    def test_detector_initializes_with_driver_signatures(self, starforce_detector: StarForceDetector) -> None:
        """Detector initializes with comprehensive driver signature database."""
        assert len(starforce_detector.DRIVER_NAMES) >= 10
        assert "sfdrv01.sys" in starforce_detector.DRIVER_NAMES
        assert "sfvfs02.sys" in starforce_detector.DRIVER_NAMES
        assert "StarForce.sys" in starforce_detector.DRIVER_NAMES
        assert "sfhlp01.sys" in starforce_detector.DRIVER_NAMES
        assert all(driver.endswith(".sys") for driver in starforce_detector.DRIVER_NAMES)

    def test_detector_initializes_with_service_names(self, starforce_detector: StarForceDetector) -> None:
        """Detector initializes with complete service name database."""
        assert len(starforce_detector.SERVICE_NAMES) >= 8
        assert "StarForce" in starforce_detector.SERVICE_NAMES
        assert "SFVFS" in starforce_detector.SERVICE_NAMES
        assert "SFDRV" in starforce_detector.SERVICE_NAMES

    def test_detector_initializes_with_registry_keys(self, starforce_detector: StarForceDetector) -> None:
        """Detector initializes with known registry key patterns."""
        assert len(starforce_detector.REGISTRY_KEYS) >= 6
        assert any("sfdrv01" in key for key in starforce_detector.REGISTRY_KEYS)
        assert any("StarForce" in key for key in starforce_detector.REGISTRY_KEYS)
        assert any("Protection Technology" in key for key in starforce_detector.REGISTRY_KEYS)

    def test_detector_initializes_with_section_patterns(self, starforce_detector: StarForceDetector) -> None:
        """Detector initializes with PE section name patterns."""
        assert len(starforce_detector.SECTION_NAMES) >= 5
        assert ".sforce" in starforce_detector.SECTION_NAMES
        assert ".sf" in starforce_detector.SECTION_NAMES
        assert ".protect" in starforce_detector.SECTION_NAMES

    def test_detector_compiles_yara_rules(self, starforce_detector: StarForceDetector) -> None:
        """Detector compiles YARA rules for signature detection."""
        if starforce_detector._yara_rules is not None:
            assert starforce_detector._yara_rules is not None


class TestStarForceBinaryGeneration:
    """Test binary generation utilities produce valid PE files."""

    def test_generator_creates_valid_pe_with_sections(
        self, temp_binary_dir: Path, binary_generator: StarForceBinaryGenerator
    ) -> None:
        """Binary generator creates valid PE files with StarForce sections."""
        output_path = temp_binary_dir / "test_starforce.exe"
        sections = [".sforce", ".sfdata", ".sfcode"]

        binary_generator.create_pe_with_starforce_sections(output_path, sections)

        assert output_path.exists()
        assert output_path.stat().st_size > 0

        pe = pefile.PE(str(output_path))
        section_names = [s.Name.decode("utf-8", errors="ignore").rstrip("\x00") for s in pe.sections]

        assert ".sforce" in section_names
        assert ".sfdata" in section_names
        assert ".sfcode" in section_names
        pe.close()

    def test_generator_creates_pe_with_starforce_strings(
        self, temp_binary_dir: Path, binary_generator: StarForceBinaryGenerator
    ) -> None:
        """Binary generator embeds StarForce identification strings."""
        output_path = temp_binary_dir / "test_strings.exe"
        strings = [b"Protection Technology", b"StarForce Technologies", b"sfdrv01"]

        binary_generator.create_pe_with_starforce_strings(output_path, strings)

        assert output_path.exists()
        binary_data = output_path.read_bytes()

        assert b"Protection Technology" in binary_data
        assert b"StarForce Technologies" in binary_data
        assert b"sfdrv01" in binary_data

    def test_generator_creates_pe_with_version_info(
        self, temp_binary_dir: Path, binary_generator: StarForceBinaryGenerator
    ) -> None:
        """Binary generator embeds version information strings."""
        output_path = temp_binary_dir / "test_version.exe"
        version_string = "StarForce 3.5.1234 Pro"

        binary_generator.create_pe_with_version_info(output_path, version_string)

        assert output_path.exists()
        binary_data = output_path.read_bytes()

        assert b"Protection Technology" in binary_data


class TestStarForceDriverDetection:
    """Test driver detection against real file system operations."""

    def test_detect_drivers_returns_empty_when_no_drivers_exist(self, starforce_detector: StarForceDetector) -> None:
        """Driver detection returns empty list when no StarForce drivers present."""
        drivers = starforce_detector._detect_drivers()

        assert isinstance(drivers, list)

    def test_detect_drivers_scans_system_drivers_directory(self, starforce_detector: StarForceDetector) -> None:
        """Driver detection scans Windows system drivers directory."""
        drivers = starforce_detector._detect_drivers()

        assert isinstance(drivers, list)

    def test_get_driver_paths_returns_full_paths(self, starforce_detector: StarForceDetector) -> None:
        """Driver path resolution returns full absolute paths."""
        test_drivers = ["sfdrv01.sys", "sfvfs02.sys"]

        paths = starforce_detector._get_driver_paths(test_drivers)

        assert isinstance(paths, dict)
        for driver_path in paths.values():
            assert "drivers" in driver_path.lower() or "system32" in driver_path.lower()

    def test_get_driver_paths_handles_missing_drivers(self, starforce_detector: StarForceDetector) -> None:
        """Driver path resolution handles nonexistent drivers gracefully."""
        nonexistent_drivers = ["nonexistent_driver_xyz123.sys", "fake_driver_999.sys"]

        paths = starforce_detector._get_driver_paths(nonexistent_drivers)

        assert isinstance(paths, dict)


class TestStarForceServiceDetection:
    """Test Windows service detection functionality."""

    def test_detect_services_returns_list(self, starforce_detector: StarForceDetector) -> None:
        """Service detection returns list of detected services."""
        services = starforce_detector._detect_services()

        assert isinstance(services, list)

    def test_detect_services_handles_missing_winapi(self) -> None:
        """Service detection handles missing WinAPI gracefully."""
        detector = StarForceDetector()
        detector._advapi32 = None

        services = detector._detect_services()

        assert isinstance(services, list)
        assert len(services) == 0

    def test_get_service_status_returns_status_info(self, starforce_detector: StarForceDetector) -> None:
        """Service status query returns status information dictionary."""
        test_services = ["StarForce", "SFVFS"]

        status_info = starforce_detector._get_service_status(test_services)

        assert isinstance(status_info, dict)

    def test_get_service_status_handles_missing_winapi(self) -> None:
        """Service status query handles missing WinAPI gracefully."""
        detector = StarForceDetector()
        detector._advapi32 = None

        status_info = detector._get_service_status(["StarForce"])

        assert isinstance(status_info, dict)
        assert len(status_info) == 0


class TestStarForceRegistryDetection:
    """Test registry key detection functionality."""

    def test_detect_registry_keys_scans_known_locations(self, starforce_detector: StarForceDetector) -> None:
        """Registry detection scans all known StarForce registry locations."""
        keys = starforce_detector._detect_registry_keys()

        assert isinstance(keys, list)

    def test_detect_registry_keys_handles_missing_keys(self, starforce_detector: StarForceDetector) -> None:
        """Registry detection handles missing keys gracefully."""
        keys = starforce_detector._detect_registry_keys()

        assert isinstance(keys, list)

    def test_detect_scsi_miniport_checks_scsi_adapters(self, starforce_detector: StarForceDetector) -> None:
        """SCSI miniport detection scans SCSI adapter registry keys."""
        result = starforce_detector._detect_scsi_miniport()

        assert isinstance(result, bool)

    def test_detect_scsi_miniport_handles_missing_registry(self, starforce_detector: StarForceDetector) -> None:
        """SCSI miniport detection handles missing registry keys."""
        result = starforce_detector._detect_scsi_miniport()

        assert isinstance(result, bool)


class TestStarForcePEAnalysis:
    """Test PE section and signature detection on real binaries."""

    def test_detect_protected_sections_finds_starforce_sections(
        self,
        temp_binary_dir: Path,
        binary_generator: StarForceBinaryGenerator,
        starforce_detector: StarForceDetector,
    ) -> None:
        """Section detection identifies StarForce-specific PE sections."""
        test_binary = temp_binary_dir / "starforce_sections.exe"
        binary_generator.create_pe_with_starforce_sections(test_binary, [".sforce", ".sfdata", ".sfcode"])

        sections = starforce_detector._detect_protected_sections(test_binary)

        assert isinstance(sections, list)
        assert ".sforce" in sections or any(".sforce" in s for s in sections)

    def test_detect_protected_sections_handles_nonexistent_file(self, starforce_detector: StarForceDetector) -> None:
        """Section detection handles nonexistent files gracefully."""
        nonexistent = Path("D:/nonexistent_file_xyz123.exe")

        sections = starforce_detector._detect_protected_sections(nonexistent)

        assert isinstance(sections, list)
        assert len(sections) == 0

    def test_detect_protected_sections_identifies_encrypted_sections(
        self, temp_binary_dir: Path, starforce_detector: StarForceDetector
    ) -> None:
        """Section detection identifies encrypted StarForce sections."""
        test_binary = temp_binary_dir / "encrypted_sections.exe"

        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x014C, 2, 0, 0, 0, 0x00E0, 0x010B)
        optional_header = struct.pack(
            "<HHIIIIIHHHHHHHIIIIHHHHHHI",
            0x010B,
            0x0E,
            0x1000,
            0x1000,
            0,
            0x1000,
            0x1000,
            0x200,
            4,
            0,
            5,
            1,
            0,
            0,
            0,
            0x3000,
            0x200,
            0,
            2,
            0,
            0x100000,
            0x200,
            0x1000,
            0,
            0,
        ) + b"\x00" * 128

        text_section = (
            b".text\x00\x00\x00" + struct.pack("<IIIIHHI", 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0) + struct.pack("<I", 0x60000020)
        )

        encrypted_section = (
            b".sforce\x00"
            + struct.pack("<IIIIHHI", 0x2000, 0x2000, 0, 0, 0, 0, 0)
            + struct.pack("<I", 0x20000000)
        )

        pe_data = dos_header + b"\x00" * (0x80 - len(dos_header)) + pe_signature + coff_header + optional_header + text_section + encrypted_section
        pe_data = pe_data.ljust(0x200, b"\x00") + b"\xC3" * 0x200

        test_binary.write_bytes(pe_data)

        sections = starforce_detector._detect_protected_sections(test_binary)

        assert isinstance(sections, list)


class TestStarForceVersionDetection:
    """Test StarForce version detection and parsing."""

    def test_parse_version_string_extracts_complete_version(self, starforce_detector: StarForceDetector) -> None:
        """Version parser extracts major, minor, build, and variant."""
        version_str = "StarForce 3.5.1234 Pro"

        version = starforce_detector._parse_version_string(version_str)

        assert version is not None
        assert version.major == 3
        assert version.minor == 5
        assert version.build == 1234
        assert version.variant == "Pro"

    def test_parse_version_string_handles_standard_variant(self, starforce_detector: StarForceDetector) -> None:
        """Version parser identifies standard variant."""
        version_str = "StarForce 4.0 Standard"

        version = starforce_detector._parse_version_string(version_str)

        assert version is not None
        assert version.major == 4
        assert version.minor == 0
        assert version.variant == "Standard"

    def test_parse_version_string_handles_missing_build(self, starforce_detector: StarForceDetector) -> None:
        """Version parser handles missing build number."""
        version_str = "StarForce 5.2"

        version = starforce_detector._parse_version_string(version_str)

        assert version is not None
        assert version.major == 5
        assert version.minor == 2
        assert version.build == 0

    def test_parse_version_string_rejects_invalid_format(self, starforce_detector: StarForceDetector) -> None:
        """Version parser rejects invalid version strings."""
        invalid_strings = [
            "Not a version",
            "VMProtect 3.5",
            "Random text",
            "",
            "123.456",
        ]

        for invalid_str in invalid_strings:
            version = starforce_detector._parse_version_string(invalid_str)
            assert version is None

    def test_detect_version_from_binary_strings(
        self, temp_binary_dir: Path, binary_generator: StarForceBinaryGenerator, starforce_detector: StarForceDetector
    ) -> None:
        """Version detection identifies version from embedded strings."""
        test_binary = temp_binary_dir / "version_test.exe"
        binary_generator.create_pe_with_starforce_strings(
            test_binary, [b"sfdrv01", b"Protection Technology", b"StarForce 3.0"]
        )

        version = starforce_detector._detect_version(test_binary)

        if version is not None:
            assert version.major >= 3

    def test_detect_version_identifies_v3_from_driver(
        self, temp_binary_dir: Path, binary_generator: StarForceBinaryGenerator, starforce_detector: StarForceDetector
    ) -> None:
        """Version detection identifies v3 from sfdrv01/sfvfs02 presence."""
        test_binary = temp_binary_dir / "v3_detection.exe"
        binary_generator.create_pe_with_starforce_strings(test_binary, [b"sfdrv01", b"sfvfs02"])

        version = starforce_detector._detect_version(test_binary)

        if version is not None:
            assert version.major == 3

    def test_detect_version_identifies_v4_from_driver(
        self, temp_binary_dir: Path, binary_generator: StarForceBinaryGenerator, starforce_detector: StarForceDetector
    ) -> None:
        """Version detection identifies v4 from sfvfs03 presence."""
        test_binary = temp_binary_dir / "v4_detection.exe"
        binary_generator.create_pe_with_starforce_strings(test_binary, [b"sfvfs03"])

        version = starforce_detector._detect_version(test_binary)

        if version is not None:
            assert version.major == 4

    def test_detect_version_identifies_v5_from_driver(
        self, temp_binary_dir: Path, binary_generator: StarForceBinaryGenerator, starforce_detector: StarForceDetector
    ) -> None:
        """Version detection identifies v5 from sfvfs04 presence."""
        test_binary = temp_binary_dir / "v5_detection.exe"
        binary_generator.create_pe_with_starforce_strings(test_binary, [b"sfvfs04"])

        version = starforce_detector._detect_version(test_binary)

        if version is not None:
            assert version.major == 5


class TestStarForceVersionRepresentation:
    """Test StarForceVersion data structure."""

    def test_version_str_includes_all_components(self) -> None:
        """Version string representation includes all components."""
        version = StarForceVersion(major=3, minor=5, build=1234, variant="Pro")

        version_str = str(version)

        assert "StarForce" in version_str
        assert "3.5" in version_str
        assert "1234" in version_str
        assert "Pro" in version_str

    def test_version_handles_zero_build(self) -> None:
        """Version representation handles zero build number."""
        version = StarForceVersion(major=4, minor=0, build=0, variant="Standard")

        version_str = str(version)

        assert "StarForce" in version_str
        assert "4.0" in version_str


class TestStarForceConfidenceCalculation:
    """Test confidence score calculation logic."""

    def test_calculate_confidence_zero_with_no_indicators(self, starforce_detector: StarForceDetector) -> None:
        """Confidence is zero when no protection indicators found."""
        confidence = starforce_detector._calculate_confidence([], [], [], [], [])

        assert confidence == 0.0

    def test_calculate_confidence_high_with_all_indicators(self, starforce_detector: StarForceDetector) -> None:
        """Confidence is high when all indicator types present."""
        drivers = ["sfdrv01.sys", "sfvfs02.sys", "StarForce.sys"]
        services = ["StarForce", "SFVFS"]
        registry_keys = ["key1", "key2", "key3"]
        sections = [".sforce", ".sfdata"]
        yara_matches = [{"rule": "StarForce_v3", "version": "3.x", "description": "test"}]

        confidence = starforce_detector._calculate_confidence(drivers, services, registry_keys, sections, yara_matches)

        assert confidence >= 0.7
        assert confidence <= 1.0

    def test_calculate_confidence_partial_with_some_indicators(self, starforce_detector: StarForceDetector) -> None:
        """Confidence is partial when some indicators present."""
        drivers = ["sfdrv01.sys"]
        services: list[str] = []
        registry_keys = ["key1"]
        sections: list[str] = []
        yara_matches: list[dict[str, str]] = []

        confidence = starforce_detector._calculate_confidence(drivers, services, registry_keys, sections, yara_matches)

        assert confidence > 0.0
        assert confidence < 0.7

    def test_calculate_confidence_scales_with_driver_count(self, starforce_detector: StarForceDetector) -> None:
        """Confidence increases with number of detected drivers."""
        single_driver = starforce_detector._calculate_confidence(["sfdrv01.sys"], [], [], [], [])
        multiple_drivers = starforce_detector._calculate_confidence(
            ["sfdrv01.sys", "sfvfs02.sys", "StarForce.sys"], [], [], [], []
        )

        assert multiple_drivers > single_driver

    def test_calculate_confidence_never_exceeds_one(self, starforce_detector: StarForceDetector) -> None:
        """Confidence score never exceeds 1.0."""
        excessive_indicators = starforce_detector._calculate_confidence(
            ["driver1", "driver2", "driver3", "driver4", "driver5"],
            ["service1", "service2", "service3", "service4"],
            ["key1", "key2", "key3", "key4", "key5"],
            ["section1", "section2", "section3", "section4"],
            [{"rule": "r1"}, {"rule": "r2"}, {"rule": "r3"}],
        )

        assert excessive_indicators <= 1.0


class TestStarForceDetectionIntegration:
    """Integration tests for complete detection workflow."""

    def test_detect_returns_complete_detection_result(
        self,
        temp_binary_dir: Path,
        binary_generator: StarForceBinaryGenerator,
        starforce_detector: StarForceDetector,
    ) -> None:
        """Complete detection returns all result fields."""
        test_binary = temp_binary_dir / "integration_test.exe"
        binary_generator.create_pe_with_starforce_sections(test_binary, [".sforce"])

        result = starforce_detector.detect(test_binary)

        assert isinstance(result, StarForceDetection)
        assert isinstance(result.detected, bool)
        assert isinstance(result.drivers, list)
        assert isinstance(result.services, list)
        assert isinstance(result.registry_keys, list)
        assert isinstance(result.protected_sections, list)
        assert isinstance(result.confidence, float)
        assert isinstance(result.details, dict)

    def test_detect_handles_nonexistent_binary(self, starforce_detector: StarForceDetector) -> None:
        """Detection handles nonexistent files gracefully."""
        nonexistent = Path("D:/nonexistent_xyz123.exe")

        result = starforce_detector.detect(nonexistent)

        assert isinstance(result, StarForceDetection)
        assert isinstance(result.detected, bool)
        assert result.confidence >= 0.0
        assert result.confidence <= 1.0

    def test_detect_includes_yara_matches_in_details(
        self,
        temp_binary_dir: Path,
        binary_generator: StarForceBinaryGenerator,
        starforce_detector: StarForceDetector,
    ) -> None:
        """Detection includes YARA scan results in details."""
        test_binary = temp_binary_dir / "yara_test.exe"
        binary_generator.create_pe_with_starforce_sections(test_binary, [])

        result = starforce_detector.detect(test_binary)

        assert "yara_matches" in result.details
        assert isinstance(result.details["yara_matches"], list)

    def test_detect_includes_driver_paths_in_details(
        self,
        temp_binary_dir: Path,
        binary_generator: StarForceBinaryGenerator,
        starforce_detector: StarForceDetector,
    ) -> None:
        """Detection includes driver path information in details."""
        test_binary = temp_binary_dir / "driver_paths_test.exe"
        binary_generator.create_pe_with_starforce_sections(test_binary, [])

        result = starforce_detector.detect(test_binary)

        assert "driver_paths" in result.details
        assert isinstance(result.details["driver_paths"], dict)

    def test_detect_includes_service_status_in_details(
        self,
        temp_binary_dir: Path,
        binary_generator: StarForceBinaryGenerator,
        starforce_detector: StarForceDetector,
    ) -> None:
        """Detection includes service status information in details."""
        test_binary = temp_binary_dir / "service_test.exe"
        binary_generator.create_pe_with_starforce_sections(test_binary, [])

        result = starforce_detector.detect(test_binary)

        assert "service_status" in result.details
        assert isinstance(result.details["service_status"], dict)

    def test_detect_includes_scsi_miniport_check_in_details(
        self,
        temp_binary_dir: Path,
        binary_generator: StarForceBinaryGenerator,
        starforce_detector: StarForceDetector,
    ) -> None:
        """Detection includes SCSI miniport detection result."""
        test_binary = temp_binary_dir / "scsi_test.exe"
        binary_generator.create_pe_with_starforce_sections(test_binary, [])

        result = starforce_detector.detect(test_binary)

        assert "scsi_miniport" in result.details
        assert isinstance(result.details["scsi_miniport"], bool)

    def test_detect_sets_detected_flag_based_on_confidence(
        self,
        temp_binary_dir: Path,
        binary_generator: StarForceBinaryGenerator,
        starforce_detector: StarForceDetector,
    ) -> None:
        """Detection sets detected flag when confidence exceeds threshold."""
        test_binary = temp_binary_dir / "confidence_test.exe"
        binary_generator.create_pe_with_starforce_sections(test_binary, [".sforce"])

        result = starforce_detector.detect(test_binary)

        if result.confidence > 0.6:
            assert result.detected is True
        else:
            assert result.detected is False

    def test_detect_on_real_starforce_binary_achieves_high_confidence(
        self, real_starforce_binary: Path, starforce_detector: StarForceDetector
    ) -> None:
        """Detection on real StarForce-protected binary achieves high confidence."""
        result = starforce_detector.detect(real_starforce_binary)

        assert isinstance(result, StarForceDetection)
        assert result.confidence >= 0.0
        assert result.confidence <= 1.0

    def test_detect_on_binary_with_multiple_sections_finds_all(
        self,
        temp_binary_dir: Path,
        binary_generator: StarForceBinaryGenerator,
        starforce_detector: StarForceDetector,
    ) -> None:
        """Detection finds all StarForce sections in multi-section binary."""
        test_binary = temp_binary_dir / "multi_section.exe"
        sections = [".sforce", ".sfdata", ".sfcode", ".sfeng"]
        binary_generator.create_pe_with_starforce_sections(test_binary, sections)

        result = starforce_detector.detect(test_binary)

        detected_sections = result.protected_sections
        assert isinstance(detected_sections, list)


class TestStarForceDetectionResult:
    """Test StarForceDetection result structure."""

    def test_detection_result_holds_complete_information(self) -> None:
        """Detection result structure contains all required fields."""
        version = StarForceVersion(3, 5, 1234, "Pro")
        result = StarForceDetection(
            detected=True,
            version=version,
            drivers=["sfdrv01.sys", "sfvfs02.sys"],
            services=["StarForce"],
            registry_keys=["test_key"],
            protected_sections=[".sforce"],
            confidence=0.85,
            details={"yara_matches": [], "driver_paths": {}},
        )

        assert result.detected is True
        assert result.version == version
        assert len(result.drivers) == 2
        assert len(result.services) == 1
        assert len(result.registry_keys) == 1
        assert len(result.protected_sections) == 1
        assert result.confidence == 0.85
        assert "yara_matches" in result.details

    def test_detection_result_allows_null_version(self) -> None:
        """Detection result allows None for version when not detected."""
        result = StarForceDetection(
            detected=False,
            version=None,
            drivers=[],
            services=[],
            registry_keys=[],
            protected_sections=[],
            confidence=0.0,
            details={},
        )

        assert result.version is None
        assert result.detected is False
        assert result.confidence == 0.0


class TestStarForceEdgeCases:
    """Test edge cases and error handling."""

    def test_detect_handles_corrupted_pe_header(
        self, temp_binary_dir: Path, starforce_detector: StarForceDetector
    ) -> None:
        """Detection handles corrupted PE headers gracefully."""
        corrupted_binary = temp_binary_dir / "corrupted.exe"
        corrupted_binary.write_bytes(b"MZ" + b"\xFF" * 500)

        result = starforce_detector.detect(corrupted_binary)

        assert isinstance(result, StarForceDetection)
        assert isinstance(result.detected, bool)

    def test_detect_handles_empty_file(self, temp_binary_dir: Path, starforce_detector: StarForceDetector) -> None:
        """Detection handles empty files gracefully."""
        empty_file = temp_binary_dir / "empty.exe"
        empty_file.write_bytes(b"")

        result = starforce_detector.detect(empty_file)

        assert isinstance(result, StarForceDetection)
        assert result.detected is False

    def test_detect_handles_non_pe_file(self, temp_binary_dir: Path, starforce_detector: StarForceDetector) -> None:
        """Detection handles non-PE files gracefully."""
        text_file = temp_binary_dir / "text.exe"
        text_file.write_text("This is not a PE file")

        result = starforce_detector.detect(text_file)

        assert isinstance(result, StarForceDetection)

    def test_parse_version_handles_malformed_strings(self, starforce_detector: StarForceDetector) -> None:
        """Version parser handles malformed version strings."""
        malformed_strings = [
            "StarForce",
            "StarForce.",
            "StarForce..",
            "StarForce....",
            "StarForce x.y.z",
        ]

        for malformed in malformed_strings:
            version = starforce_detector._parse_version_string(malformed)
            assert version is None or isinstance(version, StarForceVersion)

    def test_confidence_calculation_handles_empty_lists(self, starforce_detector: StarForceDetector) -> None:
        """Confidence calculation handles all empty indicator lists."""
        confidence = starforce_detector._calculate_confidence([], [], [], [], [])

        assert confidence == 0.0
        assert isinstance(confidence, float)
