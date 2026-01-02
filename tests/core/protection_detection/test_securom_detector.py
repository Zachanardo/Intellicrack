"""Comprehensive tests for SecuROM Protection Detector.

Tests signature detection, registry analysis, confidence scoring,
version detection, and activation state detection using REAL implementations
with actual test binaries and fixtures.
"""

import struct
import tempfile
import winreg
from collections.abc import Iterator
from pathlib import Path

import pytest

from intellicrack.core.protection_detection.securom_detector import (
    SecuROMActivation,
    SecuROMDetection,
    SecuROMDetector,
    SecuROMVersion,
)


class SecuROMBinaryGenerator:
    """Real class for generating test binaries with SecuROM-like patterns."""

    @staticmethod
    def create_driver_with_signature(signature: bytes) -> bytes:
        """Create a realistic driver binary with SecuROM signature.

        Args:
            signature: Signature bytes to embed in the driver.

        Returns:
            Binary data representing a minimal driver file.

        """
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        pe_header = b"PE\x00\x00" + b"\x4C\x01" + b"\x00" * 18
        section_header = b".text\x00\x00\x00" + b"\x00" * 32
        padding = b"\x00" * 100
        signature_data = signature + b"\x00" * 100
        return dos_header + pe_header + section_header + padding + signature_data

    @staticmethod
    def create_pe_with_version(version_major: int, variant: str) -> bytes:
        """Create a PE binary with SecuROM version strings.

        Args:
            version_major: Major version number (7 or 8).
            variant: Variant string ('Standard' or 'PA').

        Returns:
            Binary data representing a PE executable.

        """
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x100)
        pe_sig = b"PE\x00\x00"
        coff_header = struct.pack("<H", 0x014C) + b"\x00" * 18

        version_string = f"UserAccess{version_major}".encode("utf-8") + b"\x00"
        variant_string = b""

        if variant == "PA":
            variant_string = b"ProductActivation\x00OnlineActivation\x00"
        elif variant == "Standard":
            variant_string = b"OfflineMode\x00StandardProtection\x00"

        securom_data = b"Sony DADC\x00SecuROM\x00" + version_string + variant_string

        padding = b"\x00" * (256 - len(dos_header + pe_sig + coff_header))

        return dos_header + padding + pe_sig + coff_header + b"\x00" * 100 + securom_data

    @staticmethod
    def create_pe_with_sections(section_names: list[str]) -> bytes:
        """Create a PE binary with specific section names.

        Args:
            section_names: List of section names to include.

        Returns:
            Binary data representing a PE executable with sections.

        """
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x100)
        pe_header = b"PE\x00\x00" + struct.pack("<H", 0x014C) + struct.pack("<H", len(section_names))
        pe_header += b"\x00" * 16

        sections_data = b""
        for name in section_names:
            section_name = name.encode("utf-8")[:8].ljust(8, b"\x00")
            virtual_size = struct.pack("<I", 0x1000)
            virtual_addr = struct.pack("<I", 0x1000)
            raw_size = struct.pack("<I", 0x800)
            raw_ptr = struct.pack("<I", 0x400)
            characteristics = struct.pack("<I", 0x60000020)

            sections_data += section_name + virtual_size + virtual_addr + raw_size + raw_ptr + b"\x00" * 12 + characteristics

        return dos_header + b"\x00" * 100 + pe_header + sections_data + b"\x00" * 500

    @staticmethod
    def create_binary_with_entropy(low_entropy: bool) -> bytes:
        """Create binary data with controlled entropy.

        Args:
            low_entropy: If True, creates low entropy data; otherwise high entropy.

        Returns:
            Binary data with specified entropy characteristics.

        """
        if low_entropy:
            return b"\x00" * 1000
        return bytes(range(256)) * 4

    @staticmethod
    def create_pe_with_disc_auth() -> bytes:
        """Create a PE binary with disc authentication indicators.

        Returns:
            Binary data with disc authentication patterns.

        """
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x100)
        pe_header = b"PE\x00\x00" + b"\x00" * 20

        disc_auth_code = (
            b"DiscSignature\x00"
            b"DiscFingerprint\x00"
            b"\\\\.\\Scsi0:\x00"
            b"\\\\.\\CdRom0:\x00"
            b"DeviceIoControl\x00"
            b"IOCTL_SCSI_PASS_THROUGH\x00"
        )

        return dos_header + b"\x00" * 100 + pe_header + b"\x00" * 200 + disc_auth_code

    @staticmethod
    def create_pe_with_online_activation() -> bytes:
        """Create a PE binary with online activation indicators.

        Returns:
            Binary data with online activation patterns.

        """
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x100)
        pe_header = b"PE\x00\x00" + b"\x00" * 20

        activation_code = (
            b"ProductActivation\x00"
            b"OnlineActivation\x00"
            b"https://activation.securom.com/validate\x00"
            b"WinHttpSendRequest\x00"
            b"InternetOpenUrl\x00"
        )

        return dos_header + b"\x00" * 100 + pe_header + b"\x00" * 200 + activation_code


class RealRegistryHelper:
    """Helper for creating and cleaning up real registry test keys."""

    def __init__(self, base_key: str) -> None:
        """Initialize registry helper.

        Args:
            base_key: Base registry key path for testing.

        """
        self.base_key = base_key
        self.created_keys: list[str] = []

    def create_test_key(self, subkey: str, values: dict[str, tuple[int, int]] | None = None) -> None:
        """Create a real test registry key with values.

        Args:
            subkey: Subkey path to create.
            values: Dictionary of value names to (data, type) tuples.

        """
        full_path = f"{self.base_key}\\{subkey}" if subkey else self.base_key

        try:
            key = winreg.CreateKeyEx(
                winreg.HKEY_CURRENT_USER,
                full_path,
                0,
                winreg.KEY_WRITE | winreg.KEY_READ,
            )

            if values:
                for name, (data, reg_type) in values.items():
                    winreg.SetValueEx(key, name, 0, reg_type, data)

            winreg.CloseKey(key)
            self.created_keys.append(full_path)

        except OSError as e:
            pytest.skip(f"Cannot create registry key for testing: {e}")

    def cleanup(self) -> None:
        """Clean up all created test registry keys."""
        for key_path in reversed(self.created_keys):
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
            except OSError:
                pass


@pytest.fixture
def temp_binary_dir() -> Iterator[Path]:
    """Provide a temporary directory for test binaries.

    Yields:
        Path to temporary directory.

    """
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def detector() -> SecuROMDetector:
    """Provide a real SecuROMDetector instance.

    Returns:
        Configured SecuROMDetector instance.

    """
    return SecuROMDetector()


@pytest.fixture
def binary_generator() -> SecuROMBinaryGenerator:
    """Provide a binary generator for test fixtures.

    Returns:
        SecuROMBinaryGenerator instance.

    """
    return SecuROMBinaryGenerator()


class TestSecuROMDriverDetection:
    """Tests for SecuROM driver file detection."""

    def test_is_securom_driver_with_sony_dadc_signature(
        self,
        detector: SecuROMDetector,
        temp_binary_dir: Path,
        binary_generator: SecuROMBinaryGenerator,
    ) -> None:
        """Detector identifies driver with Sony DADC signature."""
        driver_path = temp_binary_dir / "secdrv.sys"
        driver_data = binary_generator.create_driver_with_signature(b"Sony DADC SecuROM")
        driver_path.write_bytes(driver_data)

        assert detector._is_securom_driver(driver_path)

    def test_is_securom_driver_with_useraccess_signature(
        self,
        detector: SecuROMDetector,
        temp_binary_dir: Path,
        binary_generator: SecuROMBinaryGenerator,
    ) -> None:
        """Detector identifies driver with UserAccess signature."""
        driver_path = temp_binary_dir / "SR8.sys"
        driver_data = binary_generator.create_driver_with_signature(b"UserAccess8 Driver Component")
        driver_path.write_bytes(driver_data)

        assert detector._is_securom_driver(driver_path)

    def test_is_securom_driver_rejects_generic_driver(
        self,
        detector: SecuROMDetector,
        temp_binary_dir: Path,
        binary_generator: SecuROMBinaryGenerator,
    ) -> None:
        """Detector rejects driver without SecuROM signatures."""
        driver_path = temp_binary_dir / "generic.sys"
        driver_data = binary_generator.create_driver_with_signature(b"Generic Windows Driver Data")
        driver_path.write_bytes(driver_data)

        assert not detector._is_securom_driver(driver_path)

    def test_is_securom_driver_handles_nonexistent_file(
        self,
        detector: SecuROMDetector,
        temp_binary_dir: Path,
    ) -> None:
        """Detector handles nonexistent driver file gracefully."""
        nonexistent_path = temp_binary_dir / "nonexistent.sys"

        assert not detector._is_securom_driver(nonexistent_path)

    def test_is_securom_driver_with_sr7_signature(
        self,
        detector: SecuROMDetector,
        temp_binary_dir: Path,
        binary_generator: SecuROMBinaryGenerator,
    ) -> None:
        """Detector identifies SecuROM v7 driver signature."""
        driver_path = temp_binary_dir / "SR7.sys"
        driver_data = binary_generator.create_driver_with_signature(b"SR7 SecuROM Version 7")
        driver_path.write_bytes(driver_data)

        assert detector._is_securom_driver(driver_path)


class TestSecuROMVersionDetection:
    """Tests for SecuROM version identification."""

    def test_parse_version_string_v7_standard(
        self,
        detector: SecuROMDetector,
    ) -> None:
        """Parser extracts version 7.x Standard from version string."""
        version = detector._parse_version_string("SecuROM 7.5.0 Standard Protection")

        assert version is not None
        assert version.major == 7
        assert version.minor == 5
        assert version.build == 0
        assert version.variant == "Standard"

    def test_parse_version_string_v8_pa(
        self,
        detector: SecuROMDetector,
    ) -> None:
        """Parser extracts version 8.x PA from version string."""
        version = detector._parse_version_string("SecuROM 8.1.2 PA Product Activation")

        assert version is not None
        assert version.major == 8
        assert version.minor == 1
        assert version.build == 2
        assert version.variant == "PA"

    def test_parse_version_string_invalid_format(
        self,
        detector: SecuROMDetector,
    ) -> None:
        """Parser returns None for invalid version string."""
        version = detector._parse_version_string("Not a SecuROM version string")

        assert version is None

    def test_parse_version_string_no_build_number(
        self,
        detector: SecuROMDetector,
    ) -> None:
        """Parser handles version string without build number."""
        version = detector._parse_version_string("SecuROM 7.5")

        assert version is not None
        assert version.major == 7
        assert version.minor == 5
        assert version.build == 0


class TestSecuROMEntropyCalculation:
    """Tests for Shannon entropy calculation."""

    def test_entropy_calculation_low_entropy_data(
        self,
        detector: SecuROMDetector,
        binary_generator: SecuROMBinaryGenerator,
    ) -> None:
        """Entropy calculation returns low value for uniform data."""
        low_entropy_data = binary_generator.create_binary_with_entropy(low_entropy=True)
        entropy = detector._calculate_section_entropy(low_entropy_data)

        assert entropy < 1.0

    def test_entropy_calculation_high_entropy_data(
        self,
        detector: SecuROMDetector,
        binary_generator: SecuROMBinaryGenerator,
    ) -> None:
        """Entropy calculation returns high value for random data."""
        high_entropy_data = binary_generator.create_binary_with_entropy(low_entropy=False)
        entropy = detector._calculate_section_entropy(high_entropy_data)

        assert entropy > 5.0

    def test_entropy_calculation_empty_data(
        self,
        detector: SecuROMDetector,
    ) -> None:
        """Entropy calculation handles empty data."""
        entropy = detector._calculate_section_entropy(b"")

        assert entropy == 0.0


class TestSecuROMConfidenceScoring:
    """Tests for detection confidence calculation."""

    def test_confidence_high_with_all_indicators(
        self,
        detector: SecuROMDetector,
    ) -> None:
        """Confidence score is high when all indicators present."""
        drivers = ["secdrv.sys", "SR8.sys"]
        services = ["SecuROM8", "UserAccess8"]
        registry_keys = ["SOFTWARE\\SecuROM", "SOFTWARE\\SecuROM\\Activation"]
        sections = [".securom", ".sdata"]
        yara_matches = [{"rule": "SecuROM_v8", "version": "8.x", "description": "SecuROM v8"}]
        activation_state = SecuROMActivation(
            is_activated=True,
            activation_date="2024-01-01",
            product_key="TEST-KEY-12345",
            machine_id="MACHINE-ID-TEST",
            activation_count=1,
            remaining_activations=4,
        )

        confidence = detector._calculate_confidence(
            drivers,
            services,
            registry_keys,
            sections,
            yara_matches,
            activation_state,
        )

        assert confidence > 0.8
        assert confidence <= 1.0

    def test_confidence_zero_with_no_indicators(
        self,
        detector: SecuROMDetector,
    ) -> None:
        """Confidence score is zero when no indicators found."""
        confidence = detector._calculate_confidence(
            drivers=[],
            services=[],
            registry_keys=[],
            sections=[],
            yara_matches=[],
            activation_state=None,
        )

        assert confidence == 0.0

    def test_confidence_medium_with_partial_indicators(
        self,
        detector: SecuROMDetector,
    ) -> None:
        """Confidence score is medium with some indicators."""
        drivers = ["secdrv.sys"]
        registry_keys = ["SOFTWARE\\SecuROM"]
        sections = [".securom"]

        confidence = detector._calculate_confidence(
            drivers,
            services=[],
            registry_keys=registry_keys,
            sections=sections,
            yara_matches=[],
            activation_state=None,
        )

        assert 0.3 < confidence < 0.7

    def test_confidence_capped_at_one(
        self,
        detector: SecuROMDetector,
    ) -> None:
        """Confidence score never exceeds 1.0."""
        drivers = ["secdrv.sys", "SR7.sys", "SR8.sys", "SecuROM.sys"]
        services = ["SecuROM", "SecuROM7", "SecuROM8", "UserAccess7", "UserAccess8"]
        registry_keys = ["SOFTWARE\\SecuROM"] * 10
        sections = [".securom", ".sdata", ".cms_t", ".cms_d"]
        yara_matches = [{"rule": "rule1"}, {"rule": "rule2"}, {"rule": "rule3"}]
        activation_state = SecuROMActivation(True, "2024-01-01", "KEY", "ID", 1, 4)

        confidence = detector._calculate_confidence(
            drivers,
            services,
            registry_keys,
            sections,
            yara_matches,
            activation_state,
        )

        assert confidence == 1.0


class TestSecuROMDiscAuthentication:
    """Tests for disc authentication detection."""

    def test_detect_disc_authentication_present(
        self,
        detector: SecuROMDetector,
        temp_binary_dir: Path,
        binary_generator: SecuROMBinaryGenerator,
    ) -> None:
        """Detector identifies disc authentication in binary."""
        binary_path = temp_binary_dir / "test.exe"
        binary_data = binary_generator.create_pe_with_disc_auth()
        binary_path.write_bytes(binary_data)

        assert detector._detect_disc_authentication(binary_path)

    def test_detect_disc_authentication_absent(
        self,
        detector: SecuROMDetector,
        temp_binary_dir: Path,
        binary_generator: SecuROMBinaryGenerator,
    ) -> None:
        """Detector returns False when no disc auth indicators."""
        binary_path = temp_binary_dir / "test.exe"
        binary_data = binary_generator.create_pe_with_version(7, "Standard")
        binary_path.write_bytes(binary_data)

        assert not detector._detect_disc_authentication(binary_path)

    def test_detect_disc_authentication_nonexistent_file(
        self,
        detector: SecuROMDetector,
        temp_binary_dir: Path,
    ) -> None:
        """Detector handles nonexistent file gracefully."""
        nonexistent_path = temp_binary_dir / "nonexistent.exe"

        assert not detector._detect_disc_authentication(nonexistent_path)


class TestSecuROMOnlineActivation:
    """Tests for online activation detection."""

    def test_detect_online_activation_present(
        self,
        detector: SecuROMDetector,
        temp_binary_dir: Path,
        binary_generator: SecuROMBinaryGenerator,
    ) -> None:
        """Detector identifies online activation in binary."""
        binary_path = temp_binary_dir / "test.exe"
        binary_data = binary_generator.create_pe_with_online_activation()
        binary_path.write_bytes(binary_data)

        assert detector._detect_online_activation(binary_path)

    def test_detect_online_activation_absent(
        self,
        detector: SecuROMDetector,
        temp_binary_dir: Path,
        binary_generator: SecuROMBinaryGenerator,
    ) -> None:
        """Detector returns False when insufficient activation indicators."""
        binary_path = temp_binary_dir / "test.exe"
        binary_data = binary_generator.create_pe_with_version(7, "Standard")
        binary_path.write_bytes(binary_data)

        assert not detector._detect_online_activation(binary_path)

    def test_detect_online_activation_requires_multiple_indicators(
        self,
        detector: SecuROMDetector,
        temp_binary_dir: Path,
    ) -> None:
        """Detector requires at least 2 indicators for positive detection."""
        binary_path = temp_binary_dir / "test.exe"
        binary_data = b"MZ" + b"\x00" * 100 + b"ProductActivation\x00" + b"\x00" * 500
        binary_path.write_bytes(binary_data)

        assert not detector._detect_online_activation(binary_path)


class TestSecuROMFullDetection:
    """Tests for complete SecuROM detection workflow."""

    def test_detect_with_real_binary_v7(
        self,
        detector: SecuROMDetector,
        temp_binary_dir: Path,
        binary_generator: SecuROMBinaryGenerator,
    ) -> None:
        """Full detection works on SecuROM v7 binary."""
        binary_path = temp_binary_dir / "securom_v7.exe"
        binary_data = binary_generator.create_pe_with_version(7, "Standard")
        binary_path.write_bytes(binary_data)

        result = detector.detect(binary_path)

        assert isinstance(result, SecuROMDetection)
        assert result.details is not None

    def test_detect_with_real_binary_v8_pa(
        self,
        detector: SecuROMDetector,
        temp_binary_dir: Path,
        binary_generator: SecuROMBinaryGenerator,
    ) -> None:
        """Full detection works on SecuROM v8 PA binary."""
        binary_path = temp_binary_dir / "securom_v8.exe"
        binary_data = binary_generator.create_pe_with_version(8, "PA")
        binary_path.write_bytes(binary_data)

        result = detector.detect(binary_path)

        assert isinstance(result, SecuROMDetection)
        assert result.details is not None

    def test_detect_nonexistent_binary(
        self,
        detector: SecuROMDetector,
        temp_binary_dir: Path,
    ) -> None:
        """Detector handles nonexistent binary gracefully."""
        nonexistent_path = temp_binary_dir / "nonexistent.exe"

        result = detector.detect(nonexistent_path)

        assert isinstance(result, SecuROMDetection)
        assert not result.detected
        assert result.confidence <= 0.5

    def test_detect_details_include_expected_fields(
        self,
        detector: SecuROMDetector,
        temp_binary_dir: Path,
        binary_generator: SecuROMBinaryGenerator,
    ) -> None:
        """Detection result details contain all expected fields."""
        binary_path = temp_binary_dir / "test.exe"
        binary_data = binary_generator.create_pe_with_online_activation()
        binary_path.write_bytes(binary_data)

        result = detector.detect(binary_path)

        assert "yara_matches" in result.details
        assert "driver_paths" in result.details
        assert "service_status" in result.details
        assert "disc_auth_present" in result.details
        assert "online_activation_present" in result.details
        assert "encryption_detected" in result.details


class TestSecuROMVersionDataclass:
    """Tests for SecuROMVersion dataclass."""

    def test_version_string_representation(self) -> None:
        """Version string representation is correctly formatted."""
        version = SecuROMVersion(8, 1, 2, "PA")
        version_str = str(version)

        assert version_str == "SecuROM 8.1.2 PA"

    def test_version_creation_standard(self) -> None:
        """Version object creation with standard variant."""
        version = SecuROMVersion(
            major=7,
            minor=5,
            build=10,
            variant="Standard",
        )

        assert version.major == 7
        assert version.minor == 5
        assert version.build == 10
        assert version.variant == "Standard"

    def test_version_creation_pa_variant(self) -> None:
        """Version object creation with PA variant."""
        version = SecuROMVersion(8, 0, 0, "PA (Product Activation)")

        assert version.major == 8
        assert version.variant == "PA (Product Activation)"


class TestSecuROMActivationDataclass:
    """Tests for SecuROMActivation dataclass."""

    def test_activation_state_activated(self) -> None:
        """Activation state creation for activated software."""
        activation = SecuROMActivation(
            is_activated=True,
            activation_date="2024-01-01",
            product_key="TEST-KEY-12345",
            machine_id="MACHINE-ID-ABCDEF",
            activation_count=2,
            remaining_activations=3,
        )

        assert activation.is_activated
        assert activation.activation_date == "2024-01-01"
        assert activation.product_key == "TEST-KEY-12345"
        assert activation.machine_id == "MACHINE-ID-ABCDEF"
        assert activation.activation_count == 2
        assert activation.remaining_activations == 3

    def test_activation_state_not_activated(self) -> None:
        """Activation state creation for non-activated software."""
        activation = SecuROMActivation(
            is_activated=False,
            activation_date=None,
            product_key=None,
            machine_id=None,
            activation_count=0,
            remaining_activations=5,
        )

        assert not activation.is_activated
        assert activation.activation_date is None
        assert activation.product_key is None
        assert activation.machine_id is None
        assert activation.activation_count == 0
        assert activation.remaining_activations == 5


class TestSecuROMDetectionEdgeCases:
    """Tests for edge cases and error handling."""

    def test_detect_with_corrupted_binary(
        self,
        detector: SecuROMDetector,
        temp_binary_dir: Path,
    ) -> None:
        """Detector handles corrupted binary gracefully."""
        binary_path = temp_binary_dir / "corrupted.exe"
        binary_path.write_bytes(b"\x00" * 100)

        result = detector.detect(binary_path)

        assert isinstance(result, SecuROMDetection)

    def test_detect_with_empty_binary(
        self,
        detector: SecuROMDetector,
        temp_binary_dir: Path,
    ) -> None:
        """Detector handles empty binary file."""
        binary_path = temp_binary_dir / "empty.exe"
        binary_path.write_bytes(b"")

        result = detector.detect(binary_path)

        assert isinstance(result, SecuROMDetection)
        assert not result.detected

    def test_entropy_calculation_single_byte(
        self,
        detector: SecuROMDetector,
    ) -> None:
        """Entropy calculation handles single byte data."""
        entropy = detector._calculate_section_entropy(b"\x42")

        assert entropy == 0.0

    def test_driver_detection_with_partial_signature(
        self,
        detector: SecuROMDetector,
        temp_binary_dir: Path,
    ) -> None:
        """Driver detection succeeds with partial signature match."""
        driver_path = temp_binary_dir / "test.sys"
        driver_data = b"\x00" * 100 + b"SecuROM" + b"\x00" * 100
        driver_path.write_bytes(driver_data)

        assert detector._is_securom_driver(driver_path)


class TestSecuROMDetectorRealWorldScenarios:
    """Tests simulating real-world detection scenarios."""

    def test_detect_layered_protection_v8_with_disc_auth(
        self,
        detector: SecuROMDetector,
        temp_binary_dir: Path,
    ) -> None:
        """Detection of SecuROM v8 with disc authentication."""
        binary_path = temp_binary_dir / "protected_game.exe"
        binary_data = (
            b"MZ"
            + b"\x00" * 256
            + b"PE\x00\x00"
            + b"\x00" * 200
            + b"UserAccess8\x00"
            + b"ProductActivation\x00"
            + b"OnlineActivation\x00"
            + b"DiscSignature\x00"
            + b"DeviceIoControl\x00"
            + b"Sony DADC\x00"
        )
        binary_path.write_bytes(binary_data)

        result = detector.detect(binary_path)

        assert isinstance(result, SecuROMDetection)
        if result.details:
            assert isinstance(result.details.get("disc_auth_present"), bool)
            assert isinstance(result.details.get("online_activation_present"), bool)

    def test_detect_multiple_protection_indicators(
        self,
        detector: SecuROMDetector,
        temp_binary_dir: Path,
        binary_generator: SecuROMBinaryGenerator,
    ) -> None:
        """Detection with multiple protection scheme indicators."""
        binary_path = temp_binary_dir / "multi_protected.exe"

        binary_data = (
            binary_generator.create_pe_with_version(8, "PA")
            + b"\x00" * 100
            + b"DiscSignature\x00"
            + b"DeviceIoControl\x00"
        )

        binary_path.write_bytes(binary_data)

        result = detector.detect(binary_path)

        assert isinstance(result, SecuROMDetection)

    def test_performance_with_large_binary(
        self,
        detector: SecuROMDetector,
        temp_binary_dir: Path,
    ) -> None:
        """Detection performance on large binary file."""
        binary_path = temp_binary_dir / "large.exe"
        large_binary = b"MZ" + b"\x00" * (10 * 1024 * 1024) + b"Sony DADC\x00SecuROM\x00"
        binary_path.write_bytes(large_binary)

        result = detector.detect(binary_path)

        assert isinstance(result, SecuROMDetection)
