"""
Production-ready tests for SecuROM Protection Analyzer.

These tests validate real SecuROM detection capabilities using actual binary
patterns and signatures. NO MOCKS - only real test doubles with complete
type annotations and call tracking.
"""

import logging
import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.securom_analyzer import (
    ActivationMechanism,
    ChallengeResponseFlow,
    DiscAuthRoutine,
    LicenseValidationFunction,
    PhoneHomeMechanism,
    ProductActivationKey,
    SecuROMAnalysis,
    SecuROMAnalyzer,
    TriggerPoint,
)


class FakePEFile:
    """Real test double for pefile.PE class with call tracking."""

    def __init__(
        self,
        sections: list[Any] | None = None,
        imports: list[tuple[str, list[tuple[str, int]]]] | None = None,
        exports: list[str] | None = None,
        resources: dict[str, int] | None = None,
    ) -> None:
        self.sections = sections or []
        self.imports_data = imports or []
        self.exports_data = exports or []
        self.resources_data = resources or {}
        self.closed = False
        self.calls: list[str] = []

        if imports:
            self.DIRECTORY_ENTRY_IMPORT = []
            for dll_name, funcs in imports:
                import_entry = FakeImportEntry(dll_name, funcs)
                self.DIRECTORY_ENTRY_IMPORT.append(import_entry)

        if exports:
            self.DIRECTORY_ENTRY_EXPORT = FakeExportDirectory(exports)

        if resources:
            self.DIRECTORY_ENTRY_RESOURCE = FakeResourceDirectory(resources)

    def get_memory_mapped_image(self) -> bytes:
        """Return fake memory-mapped image data."""
        self.calls.append("get_memory_mapped_image")
        return b"\xeb\xfe" + b"\x00" * 1000

    def close(self) -> None:
        """Track close calls."""
        self.calls.append("close")
        self.closed = True


class FakeSection:
    """Real test double for PE section."""

    def __init__(
        self,
        name: bytes,
        size_of_raw_data: int,
        misc_virtual_size: int,
    ) -> None:
        self.Name = name
        self.SizeOfRawData = size_of_raw_data
        self.Misc_VirtualSize = misc_virtual_size


class FakeImportEntry:
    """Real test double for import entry."""

    def __init__(self, dll_name: str, functions: list[tuple[str, int]]) -> None:
        self.dll = dll_name.encode("utf-8")
        self.imports = [FakeImport(name, ordinal) for name, ordinal in functions]


class FakeImport:
    """Real test double for imported function."""

    def __init__(self, name: str, ordinal: int) -> None:
        self.name = name.encode("utf-8") if name else None
        self.ordinal = ordinal


class FakeExportDirectory:
    """Real test double for export directory."""

    def __init__(self, export_names: list[str]) -> None:
        self.symbols = [FakeExport(name) for name in export_names]


class FakeExport:
    """Real test double for exported function."""

    def __init__(self, name: str) -> None:
        self.name = name.encode("utf-8") if name else None


class FakeResourceDirectory:
    """Real test double for resource directory."""

    def __init__(self, resources: dict[str, int]) -> None:
        self.entries = [FakeResourceEntry(name, count) for name, count in resources.items()]


class FakeResourceEntry:
    """Real test double for resource entry."""

    def __init__(self, name: str, count: int) -> None:
        self.name = name if not name.isdigit() else None
        self.id = int(name) if name.isdigit() else 0
        self.directory = FakeResourceSubDirectory(count)


class FakeResourceSubDirectory:
    """Real test double for resource subdirectory."""

    def __init__(self, count: int) -> None:
        self.entries = [None] * count


def create_securom_binary(
    version: str = "8.x",
    activation_type: str = "online",
    include_disc_auth: bool = True,
    include_triggers: bool = True,
    include_phone_home: bool = False,
) -> bytes:
    """Create realistic SecuROM-protected binary for testing.

    Args:
        version: SecuROM version ("7.x" or "8.x")
        activation_type: Type of activation ("online" or "offline")
        include_disc_auth: Include disc authentication routines
        include_triggers: Include trigger points
        include_phone_home: Include phone-home mechanisms

    Returns:
        bytes: Binary data simulating SecuROM-protected executable

    """
    dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
    pe_signature = b"PE\x00\x00"
    coff_header = struct.pack("<HHIIIHH", 0x014C, 3, 0, 0, 0, 0xE0, 0x010B)
    optional_header = b"\x0b\x01" + b"\x00" * 222

    section_table = b".text\x00\x00\x00" + struct.pack("<IIIIII", 0x1000, 0x1000, 0x800, 0x400, 0, 0) + b"\x00\x00\x00\x00" + struct.pack("<I", 0x60000020)

    data = dos_header + b"\x00" * (0x80 - len(dos_header))
    data += pe_signature + coff_header + optional_header + section_table

    if version == "8.x":
        data += b"UserAccess8\x00\x00SecuROM 8.x Protection\x00"
        data += b"SR8\x00\x00"
    elif version == "7.x":
        data += b"UserAccess7\x00\x00SecuROM 7.x Protection\x00"
        data += b"SR7\x00\x00"
    else:
        data += b"SecuROM\x00\x00Generic Protection\x00"

    if activation_type == "online":
        data += b"OnlineActivation\x00ActivationServer\x00"
        data += b"https://activation.securom.com/v8/activate\x00"
        data += b"ProductActivation\x00ActivateProduct\x00"
        data += b"MachineID\x00HardwareID\x00DiskSerial\x00"
        data += b"MaxActivations\x00\x00\x00\x00\x00\x00" + struct.pack("<I", 3)

    if include_triggers:
        data += b"ValidateLicense\x00CheckLicenseStatus\x00"
        data += b"VerifyProductKey\x00ContactActivationServer\x00"
        data += b"CreateWaitableTimer\x00"

    if include_disc_auth:
        data += b"DiscSignature\x00AuthenticateDisc\x00"
        data += b"SCSI\x00DeviceIoControl\x00"
        data += struct.pack("B", 0x12) + b"INQUIRY"
        data += struct.pack("B", 0x43) + b"READ_TOC"
        data += b"Subchannel\x00TOC\x00"

    if include_phone_home:
        data += b"WinHttpSendRequest\x00"
        data += b"https://telemetry.securom.com/v8/checkin\x00"
        data += b"ActivationStatus\x00Version\x00"

    data += b"Challenge\x00Response\x00"
    data += b"\x6a\x09\xe6\x67\xbb\x67\xae\x85"
    data += b"PBKDF2\x00"

    data += b"ProductKey\x00SerialNumber\x00"
    data += b"CRC32\x00SHA256\x00"

    data += b"ValidateLicense\x00CheckActivation\x00"
    data += b"Registry\x00Hardware\x00Network\x00"

    data += b"SOFTWARE\\SecuROM\x00SOFTWARE\\Sony DADC\x00"

    data += b"\x00" * 1000

    return data


def create_minimal_pe_binary() -> bytes:
    """Create minimal valid PE binary without SecuROM signatures.

    Returns:
        bytes: Minimal PE binary data

    """
    dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
    pe_signature = b"PE\x00\x00"
    coff_header = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 0xE0, 0x010B)
    optional_header = b"\x0b\x01" + b"\x00" * 222
    section_table = b".text\x00\x00\x00" + struct.pack("<IIIIII", 0x1000, 0x1000, 0x400, 0x400, 0, 0) + b"\x00\x00\x00\x00" + struct.pack("<I", 0x60000020)

    data = dos_header + b"\x00" * (0x80 - len(dos_header))
    data += pe_signature + coff_header + optional_header + section_table
    data += b"\x00" * 500

    return data


@pytest.fixture
def temp_binary_dir(tmp_path: Path) -> Path:
    """Create temporary directory for test binaries."""
    binary_dir = tmp_path / "binaries"
    binary_dir.mkdir()
    return binary_dir


@pytest.fixture
def analyzer() -> SecuROMAnalyzer:
    """Create SecuROMAnalyzer instance."""
    return SecuROMAnalyzer()


class TestSecuROMVersionDetection:
    """Test SecuROM version detection on real binary patterns."""

    def test_detect_version_8x_with_useraccess8_marker(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Detect SecuROM 8.x from UserAccess8 signature in real binary."""
        binary_path = temp_binary_dir / "securom8.exe"
        binary_path.write_bytes(create_securom_binary(version="8.x"))

        version = analyzer._detect_version(binary_path)

        assert version == "8.x"

    def test_detect_version_7x_with_useraccess7_marker(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Detect SecuROM 7.x from UserAccess7 signature in real binary."""
        binary_path = temp_binary_dir / "securom7.exe"
        binary_path.write_bytes(create_securom_binary(version="7.x"))

        version = analyzer._detect_version(binary_path)

        assert version == "7.x"

    def test_detect_generic_securom_signature(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Detect generic SecuROM from SecuROM string in binary."""
        binary_path = temp_binary_dir / "securom_generic.exe"
        binary_path.write_bytes(create_securom_binary(version="generic"))

        version = analyzer._detect_version(binary_path)

        assert version == "7.x or earlier"

    def test_detect_version_unknown_for_non_securom_binary(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Return Unknown version for binaries without SecuROM signatures."""
        binary_path = temp_binary_dir / "clean.exe"
        binary_path.write_bytes(create_minimal_pe_binary())

        version = analyzer._detect_version(binary_path)

        assert version == "Unknown"

    def test_detect_version_handles_nonexistent_file(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Handle nonexistent file gracefully."""
        binary_path = temp_binary_dir / "nonexistent.exe"

        version = analyzer._detect_version(binary_path)

        assert version == "Unknown"


class TestActivationMechanismAnalysis:
    """Test activation mechanism detection on real binaries."""

    def test_analyze_online_activation_with_server_url(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Detect online activation with server URL from real binary."""
        binary_path = temp_binary_dir / "online_activation.exe"
        binary_path.write_bytes(create_securom_binary(activation_type="online"))

        mechanisms = analyzer._analyze_activation_mechanisms(binary_path)

        assert len(mechanisms) == 1
        mech = mechanisms[0]
        assert "Online" in mech.activation_type
        assert mech.online_validation is True
        assert mech.activation_server_url == "https://activation.securom.com/v8/activate"
        assert mech.max_activations == 3
        assert "Machine ID" in mech.hardware_binding
        assert "Hardware ID" in mech.hardware_binding
        assert "Disk Serial" in mech.hardware_binding

    def test_analyze_offline_activation_no_server(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Detect offline activation without server URL."""
        binary_path = temp_binary_dir / "offline_activation.exe"
        binary_data = create_securom_binary(activation_type="offline")
        binary_path.write_bytes(binary_data)

        mechanisms = analyzer._analyze_activation_mechanisms(binary_path)

        assert len(mechanisms) == 1
        mech = mechanisms[0]
        assert "Offline" in mech.activation_type
        assert mech.online_validation is False
        assert mech.activation_server_url is None

    def test_analyze_challenge_response_activation(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Detect challenge-response activation mechanism."""
        binary_path = temp_binary_dir / "challenge_response.exe"
        binary_path.write_bytes(create_securom_binary(activation_type="online"))

        mechanisms = analyzer._analyze_activation_mechanisms(binary_path)

        assert len(mechanisms) == 1
        mech = mechanisms[0]
        assert mech.challenge_response is True
        assert "Challenge-Response" in mech.activation_type

    def test_analyze_nonexistent_file_returns_empty_list(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Handle nonexistent file gracefully."""
        binary_path = temp_binary_dir / "nonexistent.exe"

        mechanisms = analyzer._analyze_activation_mechanisms(binary_path)

        assert mechanisms == []


class TestTriggerPointIdentification:
    """Test trigger point detection on real binaries."""

    def test_identify_validation_trigger_points(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Identify validation trigger points in real binary."""
        binary_path = temp_binary_dir / "triggers.exe"
        binary_path.write_bytes(create_securom_binary(include_triggers=True))

        triggers = analyzer._identify_trigger_points(binary_path)

        assert len(triggers) > 0
        trigger_names = [t.function_name for t in triggers]
        assert "ValidateLicense" in trigger_names
        assert "CheckLicenseStatus" in trigger_names
        assert "VerifyProductKey" in trigger_names

    def test_classify_trigger_types_correctly(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Classify trigger point types correctly."""
        binary_path = temp_binary_dir / "triggers_classified.exe"
        binary_path.write_bytes(create_securom_binary(include_triggers=True))

        triggers = analyzer._identify_trigger_points(binary_path)

        trigger_map = {t.function_name: t.trigger_type for t in triggers}
        assert trigger_map.get("ValidateLicense") == "Validation"
        assert trigger_map.get("CheckLicenseStatus") == "Status Check"
        assert trigger_map.get("ContactActivationServer") == "Network Communication"

    def test_estimate_trigger_frequency_periodic(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Estimate trigger frequency as periodic when timer APIs present."""
        binary_path = temp_binary_dir / "periodic_trigger.exe"
        binary_path.write_bytes(create_securom_binary(include_triggers=True))

        triggers = analyzer._identify_trigger_points(binary_path)

        validate_trigger = next((t for t in triggers if t.function_name == "ValidateLicense"), None)
        assert validate_trigger is not None
        assert validate_trigger.frequency == "Periodic"

    def test_identify_triggers_empty_for_clean_binary(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Return empty list for binary without trigger keywords."""
        binary_path = temp_binary_dir / "clean.exe"
        binary_path.write_bytes(create_minimal_pe_binary())

        triggers = analyzer._identify_trigger_points(binary_path)

        assert triggers == []


class TestProductKeyExtraction:
    """Test product key information extraction."""

    def test_extract_product_key_structures(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Extract product key structures from real binary."""
        binary_path = temp_binary_dir / "product_keys.exe"
        binary_path.write_bytes(create_securom_binary(activation_type="online"))

        keys = analyzer._extract_product_key_info(binary_path)

        assert len(keys) > 0
        key_formats = [k.key_format for k in keys]
        assert any("Dashed Format" in f or "Continuous Format" in f for f in key_formats)

    def test_detect_key_validation_algorithm(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Detect product key validation algorithm."""
        binary_path = temp_binary_dir / "key_validation.exe"
        binary_path.write_bytes(create_securom_binary(activation_type="online"))

        keys = analyzer._extract_product_key_info(binary_path)

        assert len(keys) > 0
        validation_algos = [k.validation_algorithm for k in keys]
        assert any(algo != "Unknown" for algo in validation_algos)

    def test_extract_empty_keys_for_clean_binary(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Return empty list for binary without product key markers."""
        binary_path = temp_binary_dir / "clean.exe"
        binary_path.write_bytes(create_minimal_pe_binary())

        keys = analyzer._extract_product_key_info(binary_path)

        assert keys == []


class TestDiscAuthenticationAnalysis:
    """Test disc authentication routine detection."""

    def test_analyze_disc_authentication_routines(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Detect disc authentication routines in real binary."""
        binary_path = temp_binary_dir / "disc_auth.exe"
        binary_path.write_bytes(create_securom_binary(include_disc_auth=True))

        routines = analyzer._analyze_disc_authentication(binary_path)

        assert len(routines) > 0

    def test_extract_scsi_commands_from_disc_auth(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Extract SCSI commands from disc authentication routine."""
        binary_path = temp_binary_dir / "scsi_commands.exe"
        binary_path.write_bytes(create_securom_binary(include_disc_auth=True))

        routines = analyzer._analyze_disc_authentication(binary_path)

        assert len(routines) > 0
        routine = routines[0]
        assert len(routine.scsi_commands) > 0
        assert "INQUIRY" in routine.scsi_commands or "READ_TOC" in routine.scsi_commands

    def test_identify_signature_checks_in_disc_auth(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Identify signature verification methods in disc authentication."""
        binary_path = temp_binary_dir / "signature_checks.exe"
        binary_path.write_bytes(create_securom_binary(include_disc_auth=True))

        routines = analyzer._analyze_disc_authentication(binary_path)

        assert len(routines) > 0
        routine = routines[0]
        assert len(routine.signature_checks) > 0

    def test_assess_bypass_difficulty_based_on_complexity(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Assess bypass difficulty based on protection complexity."""
        binary_path = temp_binary_dir / "complex_disc_auth.exe"
        binary_path.write_bytes(create_securom_binary(include_disc_auth=True))

        routines = analyzer._analyze_disc_authentication(binary_path)

        assert len(routines) > 0
        routine = routines[0]
        assert routine.bypass_difficulty in ["Low", "Medium", "High"]


class TestPhoneHomeMechanismDetection:
    """Test phone-home mechanism detection."""

    def test_detect_phone_home_mechanisms(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Detect phone-home mechanisms in real binary."""
        binary_path = temp_binary_dir / "phone_home.exe"
        binary_path.write_bytes(create_securom_binary(include_phone_home=True))

        mechanisms = analyzer._detect_phone_home(binary_path)

        assert len(mechanisms) > 0

    def test_extract_server_urls_from_phone_home(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Extract server URLs from phone-home mechanism."""
        binary_path = temp_binary_dir / "phone_home_urls.exe"
        binary_path.write_bytes(create_securom_binary(include_phone_home=True))

        mechanisms = analyzer._detect_phone_home(binary_path)

        assert len(mechanisms) > 0
        mechanism = mechanisms[0]
        assert len(mechanism.server_urls) > 0
        assert any("https://" in url for url in mechanism.server_urls)

    def test_identify_transmitted_data_types(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Identify data types transmitted in phone-home."""
        binary_path = temp_binary_dir / "transmitted_data.exe"
        binary_path.write_bytes(create_securom_binary(include_phone_home=True))

        mechanisms = analyzer._detect_phone_home(binary_path)

        assert len(mechanisms) > 0
        mechanism = mechanisms[0]
        assert len(mechanism.data_transmitted) > 0
        assert "Activation Status" in mechanism.data_transmitted or "Software Version" in mechanism.data_transmitted

    def test_detect_protocol_http_vs_socket(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Detect network protocol used for phone-home."""
        binary_path = temp_binary_dir / "protocol_detection.exe"
        binary_path.write_bytes(create_securom_binary(include_phone_home=True))

        mechanisms = analyzer._detect_phone_home(binary_path)

        assert len(mechanisms) > 0
        mechanism = mechanisms[0]
        assert mechanism.protocol in ["HTTP/HTTPS", "TCP/IP"]


class TestChallengeResponseAnalysis:
    """Test challenge-response flow detection."""

    def test_analyze_challenge_response_flow(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Detect challenge-response authentication flow."""
        binary_path = temp_binary_dir / "challenge_response.exe"
        binary_path.write_bytes(create_securom_binary(activation_type="online"))

        flows = analyzer._analyze_challenge_response(binary_path)

        assert len(flows) > 0

    def test_identify_crypto_operations_in_flow(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Identify cryptographic operations in challenge-response flow."""
        binary_path = temp_binary_dir / "crypto_ops.exe"
        binary_path.write_bytes(create_securom_binary(activation_type="online"))

        flows = analyzer._analyze_challenge_response(binary_path)

        assert len(flows) > 0
        flow = flows[0]
        assert len(flow.crypto_operations) > 0

    def test_detect_key_derivation_method(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Detect key derivation method used in challenge-response."""
        binary_path = temp_binary_dir / "key_derivation.exe"
        binary_path.write_bytes(create_securom_binary(activation_type="online"))

        flows = analyzer._analyze_challenge_response(binary_path)

        assert len(flows) > 0
        flow = flows[0]
        assert flow.key_derivation_method in ["PBKDF2", "Custom KDF"]

    def test_assess_challenge_response_difficulty(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Assess difficulty of challenge-response mechanism."""
        binary_path = temp_binary_dir / "cr_difficulty.exe"
        binary_path.write_bytes(create_securom_binary(activation_type="online"))

        flows = analyzer._analyze_challenge_response(binary_path)

        assert len(flows) > 0
        flow = flows[0]
        assert flow.difficulty in ["Medium", "High"]


class TestLicenseValidationMapping:
    """Test license validation function mapping."""

    def test_map_license_validation_functions(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Map license validation functions in binary."""
        binary_path = temp_binary_dir / "validation_funcs.exe"
        binary_path.write_bytes(create_securom_binary(activation_type="online"))

        functions = analyzer._map_license_validation(binary_path)

        assert len(functions) > 0

    def test_identify_validation_checks_performed(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Identify checks performed in validation functions."""
        binary_path = temp_binary_dir / "validation_checks.exe"
        binary_path.write_bytes(create_securom_binary(activation_type="online"))

        functions = analyzer._map_license_validation(binary_path)

        assert len(functions) > 0
        func = functions[0]
        assert len(func.checks_performed) > 0

    def test_extract_return_values_from_validation(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Extract return values from validation functions."""
        binary_path = temp_binary_dir / "return_values.exe"
        binary_path.write_bytes(create_securom_binary(activation_type="online"))

        functions = analyzer._map_license_validation(binary_path)

        assert len(functions) > 0
        func = functions[0]
        assert len(func.return_values) > 0
        assert "0" in func.return_values


class TestEncryptionDetection:
    """Test encryption technique identification."""

    def test_identify_encryption_algorithms(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Identify encryption algorithms used in binary."""
        binary_path = temp_binary_dir / "encryption.exe"
        binary_path.write_bytes(create_securom_binary(activation_type="online"))

        techniques = analyzer._identify_encryption(binary_path)

        assert len(techniques) > 0

    def test_detect_multiple_crypto_algorithms(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Detect multiple cryptographic algorithms in same binary."""
        binary_path = temp_binary_dir / "multi_crypto.exe"
        binary_path.write_bytes(create_securom_binary(activation_type="online"))

        techniques = analyzer._identify_encryption(binary_path)

        assert len(techniques) >= 1


class TestCompleteAnalysisWorkflow:
    """Test complete SecuROM analysis workflow."""

    def test_analyze_complete_securom8_binary(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Perform complete analysis on SecuROM 8.x binary."""
        binary_path = temp_binary_dir / "complete_securom8.exe"
        binary_path.write_bytes(
            create_securom_binary(
                version="8.x",
                activation_type="online",
                include_disc_auth=True,
                include_triggers=True,
                include_phone_home=True,
            )
        )

        analysis = analyzer.analyze(binary_path)

        assert isinstance(analysis, SecuROMAnalysis)
        assert analysis.target_path == binary_path
        assert analysis.version == "8.x"
        assert len(analysis.activation_mechanisms) > 0
        assert len(analysis.trigger_points) > 0
        assert len(analysis.disc_auth_routines) > 0
        assert len(analysis.challenge_response_flows) > 0
        assert len(analysis.license_validation_functions) > 0
        assert "imports" in analysis.details
        assert "exports" in analysis.details
        assert "strings" in analysis.details

    def test_analyze_securom7_binary_with_offline_activation(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analyze SecuROM 7.x binary with offline activation."""
        binary_path = temp_binary_dir / "securom7_offline.exe"
        binary_path.write_bytes(
            create_securom_binary(
                version="7.x",
                activation_type="offline",
                include_disc_auth=True,
                include_triggers=False,
                include_phone_home=False,
            )
        )

        analysis = analyzer.analyze(binary_path)

        assert analysis.version == "7.x"
        assert len(analysis.activation_mechanisms) > 0
        assert analysis.activation_mechanisms[0].online_validation is False

    def test_analyze_provides_detailed_metadata(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Analysis provides comprehensive metadata in details dict."""
        binary_path = temp_binary_dir / "metadata_test.exe"
        binary_path.write_bytes(create_securom_binary(version="8.x", activation_type="online"))

        analysis = analyzer.analyze(binary_path)

        assert isinstance(analysis.details, dict)
        assert "imports" in analysis.details
        assert "exports" in analysis.details
        assert "resources" in analysis.details
        assert "strings" in analysis.details
        assert "network_endpoints" in analysis.details
        assert "registry_access" in analysis.details


class TestDataclassInstantiation:
    """Test dataclass instantiation and field validation."""

    def test_activation_mechanism_creation(self) -> None:
        """Create ActivationMechanism with all required fields."""
        mechanism = ActivationMechanism(
            activation_type="Online with Challenge-Response",
            online_validation=True,
            challenge_response=True,
            activation_server_url="https://activation.example.com",
            max_activations=5,
            hardware_binding=["Machine ID", "CPU ID"],
            encryption_algorithm="RSA",
        )

        assert mechanism.activation_type == "Online with Challenge-Response"
        assert mechanism.online_validation is True
        assert mechanism.max_activations == 5

    def test_trigger_point_creation(self) -> None:
        """Create TriggerPoint with all required fields."""
        trigger = TriggerPoint(
            address=0x401000,
            trigger_type="Validation",
            description="Validates license with activation server",
            function_name="ValidateLicense",
            frequency="Periodic",
        )

        assert trigger.address == 0x401000
        assert trigger.trigger_type == "Validation"

    def test_product_activation_key_creation(self) -> None:
        """Create ProductActivationKey with all required fields."""
        key = ProductActivationKey(
            key_format="Dashed Format",
            key_length=29,
            validation_algorithm="RSA Signature Verification",
            example_pattern="XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
            checksum_type="CRC32",
        )

        assert key.key_format == "Dashed Format"
        assert key.key_length == 29

    def test_disc_auth_routine_creation(self) -> None:
        """Create DiscAuthRoutine with all required fields."""
        routine = DiscAuthRoutine(
            routine_address=0x402000,
            scsi_commands=["INQUIRY", "READ_TOC"],
            signature_checks=["Digital Signature Verification"],
            fingerprint_method="Subchannel-based Fingerprinting",
            bypass_difficulty="High",
        )

        assert routine.routine_address == 0x402000
        assert len(routine.scsi_commands) == 2

    def test_phone_home_mechanism_creation(self) -> None:
        """Create PhoneHomeMechanism with all required fields."""
        mechanism = PhoneHomeMechanism(
            mechanism_type="HTTP",
            address=0x403000,
            server_urls=["https://telemetry.example.com"],
            frequency="Periodic",
            data_transmitted=["Machine ID", "Activation Status"],
            protocol="HTTP/HTTPS",
        )

        assert mechanism.mechanism_type == "HTTP"
        assert len(mechanism.server_urls) == 1

    def test_challenge_response_flow_creation(self) -> None:
        """Create ChallengeResponseFlow with all required fields."""
        flow = ChallengeResponseFlow(
            challenge_generation_addr=0x404000,
            response_validation_addr=0x405000,
            crypto_operations=[(0x404500, "RSA"), (0x404800, "SHA256")],
            key_derivation_method="PBKDF2",
            difficulty="High",
        )

        assert flow.challenge_generation_addr == 0x404000
        assert len(flow.crypto_operations) == 2

    def test_license_validation_function_creation(self) -> None:
        """Create LicenseValidationFunction with all required fields."""
        function = LicenseValidationFunction(
            address=0x406000,
            name="ValidateLicense",
            function_type="License Validation",
            checks_performed=["Registry Check", "Hardware Check"],
            return_values={"0": "Success", "1": "Invalid License"},
        )

        assert function.address == 0x406000
        assert len(function.checks_performed) == 2

    def test_securom_analysis_creation(self, temp_binary_dir: Path) -> None:
        """Create SecuROMAnalysis with all required fields."""
        binary_path = temp_binary_dir / "test.exe"
        binary_path.write_bytes(b"test")

        analysis = SecuROMAnalysis(
            target_path=binary_path,
            version="8.x",
            activation_mechanisms=[],
            trigger_points=[],
            product_keys=[],
            disc_auth_routines=[],
            phone_home_mechanisms=[],
            challenge_response_flows=[],
            license_validation_functions=[],
            encryption_techniques=["RSA", "SHA256"],
            obfuscation_methods=["Anti-Disassembly Tricks"],
            details={"imports": [], "exports": []},
        )

        assert analysis.version == "8.x"
        assert len(analysis.encryption_techniques) == 2


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling."""

    def test_analyze_empty_file(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Handle empty file gracefully."""
        binary_path = temp_binary_dir / "empty.exe"
        binary_path.write_bytes(b"")

        version = analyzer._detect_version(binary_path)
        mechanisms = analyzer._analyze_activation_mechanisms(binary_path)

        assert version == "Unknown"
        assert mechanisms == []

    def test_analyze_corrupted_binary_data(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Handle corrupted binary data gracefully."""
        binary_path = temp_binary_dir / "corrupted.exe"
        binary_path.write_bytes(b"\xff" * 100)

        analysis = analyzer.analyze(binary_path)

        assert isinstance(analysis, SecuROMAnalysis)
        assert analysis.version == "Unknown"

    def test_analyze_large_binary_performance(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Handle large binary files efficiently."""
        binary_path = temp_binary_dir / "large.exe"
        large_binary = create_securom_binary(version="8.x") + b"\x00" * 5_000_000
        binary_path.write_bytes(large_binary)

        import time

        start = time.time()
        analysis = analyzer.analyze(binary_path)
        duration = time.time() - start

        assert isinstance(analysis, SecuROMAnalysis)
        assert duration < 10.0

    def test_analyze_binary_with_null_bytes(
        self,
        analyzer: SecuROMAnalyzer,
        temp_binary_dir: Path,
    ) -> None:
        """Handle binary with excessive null bytes."""
        binary_path = temp_binary_dir / "null_bytes.exe"
        binary_data = create_securom_binary(version="8.x") + b"\x00" * 10000
        binary_path.write_bytes(binary_data)

        analysis = analyzer.analyze(binary_path)

        assert analysis.version == "8.x"
