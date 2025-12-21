"""Production tests for SecuROM analyzer - NO MOCKS.

Tests validate real SecuROM protection detection capabilities against actual
Windows binaries and custom-crafted test binaries with embedded SecuROM signatures.
"""

from __future__ import annotations

import os
import struct
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

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

if TYPE_CHECKING:
    from typing import Any

SYSTEM32 = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32"


class TestBinaryFactory:
    """Factory for creating test binaries with SecuROM signatures."""

    @staticmethod
    def create_dos_stub() -> bytes:
        """Create minimal DOS stub."""
        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)
        return bytes(dos_header)

    @staticmethod
    def create_pe_header(num_sections: int = 1) -> bytes:
        """Create minimal PE header."""
        pe_signature = b"PE\x00\x00"

        coff_header = struct.pack(
            "<HHIIIHH",
            0x014C,
            num_sections,
            0,
            0,
            0,
            0xE0,
            0x010B,
        )

        optional_header = bytearray(224)
        optional_header[:2] = struct.pack("<H", 0x010B)

        return pe_signature + coff_header + bytes(optional_header)

    @staticmethod
    def create_section_header(
        name: bytes, virtual_size: int, virtual_address: int, raw_size: int, raw_offset: int
    ) -> bytes:
        """Create PE section header."""
        header = bytearray(40)
        header[:8] = name.ljust(8, b"\x00")[:8]
        header[8:12] = struct.pack("<I", virtual_size)
        header[12:16] = struct.pack("<I", virtual_address)
        header[16:20] = struct.pack("<I", raw_size)
        header[20:24] = struct.pack("<I", raw_offset)
        header[36:40] = struct.pack("<I", 0xE0000020)
        return bytes(header)

    @classmethod
    def create_securom_v8_binary(cls, include_activation: bool = True) -> bytes:
        """Create test binary with SecuROM v8 signatures."""
        dos_stub = cls.create_dos_stub()
        pe_header = cls.create_pe_header(num_sections=2)

        text_section = cls.create_section_header(b".text", 0x1000, 0x1000, 0x1000, 0x400)
        data_section = cls.create_section_header(b".data", 0x1000, 0x2000, 0x1000, 0x1400)

        text_data = bytearray(0x1000)
        text_data[:20] = b"UserAccess8\x00SR8\x00SecuROM"

        if include_activation:
            text_data[100:115] = b"OnlineActivation"
            text_data[200:217] = b"ActivationServer\x00"
            text_data[300:350] = b"https://activation.securom.com/validate\x00"
            text_data[400:414] = b"MaxActivations"
            text_data[420:424] = struct.pack("<I", 3)
            text_data[500:510] = b"MachineID\x00"
            text_data[520:531] = b"HardwareID\x00"
            text_data[600:609] = b"Challenge"
            text_data[650:658] = b"Response"

        text_data[700:715] = b"ProductKey\x00\x00\x00\x00\x00"
        text_data[800:813] = b"SerialNumber\x00"
        text_data[900:913] = b"ActivationKey"

        text_data[1000:1014] = b"DiscSignature\x00"
        text_data[1100:1115] = b"AuthenticateDisc"
        text_data[1200:1212] = b"DeviceIoControl\x00"
        text_data[1300:1304] = struct.pack("B", 0x43)

        text_data[1400:1417] = b"WinHttpSendRequest"
        text_data[1500:1544] = b"https://telemetry.securom.com/phone-home\x00"

        text_data[1600:1615] = b"ValidateLicense"
        text_data[1700:1716] = b"CheckActivation\x00"
        text_data[1800:1817] = b"VerifyProductKey\x00"

        text_data[1900:1908] = b"\x63\x7c\x77\x7b\xf2\x6b\x00\x00"
        text_data[2000:2008] = b"\x6a\x09\xe6\x67\xbb\x67\xae\x85"

        data_data = bytearray(0x1000)
        data_data[:40] = b"SOFTWARE\\SecuROM\\Activation\\Data\x00"
        data_data[100:140] = b"SOFTWARE\\Sony DADC\\Protection\x00"

        binary = dos_stub + pe_header + text_section + data_section
        binary = binary.ljust(0x400, b"\x00")
        binary += bytes(text_data)
        binary = binary.ljust(0x1400, b"\x00")
        binary += bytes(data_data)

        return binary

    @classmethod
    def create_securom_v7_binary(cls) -> bytes:
        """Create test binary with SecuROM v7 signatures."""
        dos_stub = cls.create_dos_stub()
        pe_header = cls.create_pe_header(num_sections=1)
        text_section = cls.create_section_header(b".text", 0x1000, 0x1000, 0x1000, 0x400)

        text_data = bytearray(0x1000)
        text_data[:20] = b"UserAccess7\x00SR7\x00SecuROM"
        text_data[100:115] = b"ProductActivation"
        text_data[200:215] = b"DiscFingerprint"
        text_data[300:318] = b"ValidateOnline\x00"

        binary = dos_stub + pe_header + text_section
        binary = binary.ljust(0x400, b"\x00")
        binary += bytes(text_data)

        return binary

    @classmethod
    def create_partial_securom_binary(cls) -> bytes:
        """Create binary with partial SecuROM signatures (stripped/damaged)."""
        dos_stub = cls.create_dos_stub()
        pe_header = cls.create_pe_header(num_sections=1)
        text_section = cls.create_section_header(b".text", 0x1000, 0x1000, 0x1000, 0x400)

        text_data = bytearray(0x1000)
        text_data[:7] = b"SecuROM"
        text_data[100:110] = b"ProductKey"

        binary = dos_stub + pe_header + text_section
        binary = binary.ljust(0x400, b"\x00")
        binary += bytes(text_data)

        return binary

    @classmethod
    def create_non_securom_binary(cls) -> bytes:
        """Create binary without SecuROM signatures."""
        dos_stub = cls.create_dos_stub()
        pe_header = cls.create_pe_header(num_sections=1)
        text_section = cls.create_section_header(b".text", 0x1000, 0x1000, 0x1000, 0x400)

        text_data = bytearray(0x1000)
        text_data[:15] = b"Regular Binary\x00"

        binary = dos_stub + pe_header + text_section
        binary = binary.ljust(0x400, b"\x00")
        binary += bytes(text_data)

        return binary


@pytest.fixture(scope="module")
def securom_v8_binary(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Create SecuROM v8 test binary."""
    tmp_dir = tmp_path_factory.mktemp("binaries")
    binary_path = tmp_dir / "securom_v8_test.exe"
    binary_path.write_bytes(TestBinaryFactory.create_securom_v8_binary())
    return binary_path


@pytest.fixture(scope="module")
def securom_v7_binary(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Create SecuROM v7 test binary."""
    tmp_dir = tmp_path_factory.mktemp("binaries")
    binary_path = tmp_dir / "securom_v7_test.exe"
    binary_path.write_bytes(TestBinaryFactory.create_securom_v7_binary())
    return binary_path


@pytest.fixture(scope="module")
def partial_securom_binary(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Create partial SecuROM binary."""
    tmp_dir = tmp_path_factory.mktemp("binaries")
    binary_path = tmp_dir / "partial_securom_test.exe"
    binary_path.write_bytes(TestBinaryFactory.create_partial_securom_binary())
    return binary_path


@pytest.fixture(scope="module")
def non_securom_binary(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Create non-SecuROM binary."""
    tmp_dir = tmp_path_factory.mktemp("binaries")
    binary_path = tmp_dir / "non_securom_test.exe"
    binary_path.write_bytes(TestBinaryFactory.create_non_securom_binary())
    return binary_path


@pytest.fixture(scope="module")
def analyzer() -> SecuROMAnalyzer:
    """Create SecuROM analyzer instance."""
    return SecuROMAnalyzer()


class TestSecuROMVersionDetection:
    """Test SecuROM version detection capabilities."""

    def test_detect_securom_v8_with_useraccess8_marker(
        self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path
    ) -> None:
        """Analyzer detects SecuROM v8.x from UserAccess8 marker."""
        version = analyzer._detect_version(securom_v8_binary)

        assert version == "8.x"

    def test_detect_securom_v8_with_sr8_marker(self, analyzer: SecuROMAnalyzer, tmp_path: Path) -> None:
        """Analyzer detects SecuROM v8.x from SR8 marker."""
        binary_data = TestBinaryFactory.create_dos_stub()
        binary_data += TestBinaryFactory.create_pe_header()
        binary_data += b"\x00" * 0x200
        binary_data += b"SR8\x00" + b"\x00" * 100

        binary_path = tmp_path / "sr8_marker.exe"
        binary_path.write_bytes(binary_data)

        version = analyzer._detect_version(binary_path)

        assert version == "8.x"

    def test_detect_securom_v7_with_useraccess7_marker(
        self, analyzer: SecuROMAnalyzer, securom_v7_binary: Path
    ) -> None:
        """Analyzer detects SecuROM v7.x from UserAccess7 marker."""
        version = analyzer._detect_version(securom_v7_binary)

        assert version == "7.x"

    def test_detect_securom_v7_with_sr7_marker(self, analyzer: SecuROMAnalyzer, tmp_path: Path) -> None:
        """Analyzer detects SecuROM v7.x from SR7 marker."""
        binary_data = TestBinaryFactory.create_dos_stub()
        binary_data += TestBinaryFactory.create_pe_header()
        binary_data += b"\x00" * 0x200
        binary_data += b"SR7\x00" + b"\x00" * 100

        binary_path = tmp_path / "sr7_marker.exe"
        binary_path.write_bytes(binary_data)

        version = analyzer._detect_version(binary_path)

        assert version == "7.x"

    def test_detect_generic_securom_marker(self, analyzer: SecuROMAnalyzer, tmp_path: Path) -> None:
        """Analyzer detects generic SecuROM marker for earlier versions."""
        binary_data = TestBinaryFactory.create_dos_stub()
        binary_data += TestBinaryFactory.create_pe_header()
        binary_data += b"\x00" * 0x200
        binary_data += b"SecuROM\x00" + b"\x00" * 100

        binary_path = tmp_path / "generic_securom.exe"
        binary_path.write_bytes(binary_data)

        version = analyzer._detect_version(binary_path)

        assert version == "7.x or earlier"

    def test_detect_unknown_version_without_markers(
        self, analyzer: SecuROMAnalyzer, non_securom_binary: Path
    ) -> None:
        """Analyzer returns Unknown for binaries without SecuROM markers."""
        version = analyzer._detect_version(non_securom_binary)

        assert version == "Unknown"

    def test_detect_version_nonexistent_file(self, analyzer: SecuROMAnalyzer, tmp_path: Path) -> None:
        """Analyzer handles nonexistent files gracefully."""
        nonexistent = tmp_path / "does_not_exist.exe"

        version = analyzer._detect_version(nonexistent)

        assert version == "Unknown"

    def test_detect_version_on_real_windows_binary(self, analyzer: SecuROMAnalyzer) -> None:
        """Analyzer processes real Windows binaries without crashing."""
        notepad = SYSTEM32 / "notepad.exe"

        if notepad.exists():
            version = analyzer._detect_version(notepad)
            assert version in ["Unknown", "7.x or earlier", "7.x", "8.x"]


class TestActivationMechanismAnalysis:
    """Test activation mechanism detection and analysis."""

    def test_detect_online_activation_mechanism(
        self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path
    ) -> None:
        """Analyzer detects online activation mechanisms."""
        mechanisms = analyzer._analyze_activation_mechanisms(securom_v8_binary)

        assert len(mechanisms) > 0
        assert any(m.online_validation for m in mechanisms)
        assert any(m.activation_type.startswith("Online") for m in mechanisms)

    def test_detect_challenge_response_activation(
        self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path
    ) -> None:
        """Analyzer detects challenge-response activation."""
        mechanisms = analyzer._analyze_activation_mechanisms(securom_v8_binary)

        assert len(mechanisms) > 0
        assert any(m.challenge_response for m in mechanisms)
        assert any("Challenge-Response" in m.activation_type for m in mechanisms)

    def test_extract_activation_server_url(self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path) -> None:
        """Analyzer extracts activation server URLs."""
        mechanisms = analyzer._analyze_activation_mechanisms(securom_v8_binary)

        assert len(mechanisms) > 0
        urls = [m.activation_server_url for m in mechanisms if m.activation_server_url]
        assert urls
        assert any("https://" in url for url in urls)
        assert any("activation.securom.com" in url for url in urls)

    def test_detect_max_activations_limit(self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path) -> None:
        """Analyzer detects maximum activation limits."""
        mechanisms = analyzer._analyze_activation_mechanisms(securom_v8_binary)

        assert len(mechanisms) > 0
        assert any(m.max_activations == 3 for m in mechanisms)

    def test_detect_hardware_binding_methods(
        self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path
    ) -> None:
        """Analyzer detects hardware binding methods."""
        mechanisms = analyzer._analyze_activation_mechanisms(securom_v8_binary)

        assert len(mechanisms) > 0
        mechanism = mechanisms[0]
        assert "Machine ID" in mechanism.hardware_binding
        assert "Hardware ID" in mechanism.hardware_binding

    def test_identify_encryption_algorithms(self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path) -> None:
        """Analyzer identifies encryption algorithms used in activation."""
        mechanisms = analyzer._analyze_activation_mechanisms(securom_v8_binary)

        assert len(mechanisms) > 0
        assert any(m.encryption_algorithm in ["AES", "SHA256", "RSA", "MD5"] for m in mechanisms if m.encryption_algorithm)

    def test_activation_analysis_on_non_securom_binary(
        self, analyzer: SecuROMAnalyzer, non_securom_binary: Path
    ) -> None:
        """Analyzer detects minimal activation data for binaries without SecuROM."""
        mechanisms = analyzer._analyze_activation_mechanisms(non_securom_binary)

        if len(mechanisms) > 0:
            mechanism = mechanisms[0]
            assert mechanism.online_validation is False
            assert mechanism.challenge_response is False
            assert mechanism.activation_server_url is None

    def test_activation_mechanism_dataclass_structure(
        self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path
    ) -> None:
        """Activation mechanism results use proper dataclass structure."""
        mechanisms = analyzer._analyze_activation_mechanisms(securom_v8_binary)

        assert len(mechanisms) > 0
        mechanism = mechanisms[0]
        assert isinstance(mechanism, ActivationMechanism)
        assert isinstance(mechanism.activation_type, str)
        assert isinstance(mechanism.online_validation, bool)
        assert isinstance(mechanism.challenge_response, bool)
        assert isinstance(mechanism.max_activations, int)
        assert isinstance(mechanism.hardware_binding, list)


class TestTriggerPointIdentification:
    """Test online validation trigger point detection."""

    def test_identify_validate_license_trigger(
        self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path
    ) -> None:
        """Analyzer identifies ValidateLicense trigger points."""
        triggers = analyzer._identify_trigger_points(securom_v8_binary)

        assert len(triggers) > 0
        assert any("ValidateLicense" in t.function_name for t in triggers)

    def test_identify_verify_product_key_trigger(
        self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path
    ) -> None:
        """Analyzer identifies VerifyProductKey trigger points."""
        triggers = analyzer._identify_trigger_points(securom_v8_binary)

        assert any("VerifyProductKey" in t.function_name for t in triggers)

    def test_classify_validation_trigger_types(
        self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path
    ) -> None:
        """Analyzer correctly classifies trigger types."""
        triggers = analyzer._identify_trigger_points(securom_v8_binary)

        trigger_types = [t.trigger_type for t in triggers]
        assert "Validation" in trigger_types or "Status Check" in trigger_types

    def test_trigger_point_addresses_are_valid(
        self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path
    ) -> None:
        """Trigger point addresses are valid offsets in binary."""
        binary_size = securom_v8_binary.stat().st_size
        triggers = analyzer._identify_trigger_points(securom_v8_binary)

        for trigger in triggers:
            assert 0 <= trigger.address < binary_size

    def test_estimate_trigger_frequency(self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path) -> None:
        """Analyzer estimates trigger call frequency."""
        triggers = analyzer._identify_trigger_points(securom_v8_binary)

        assert len(triggers) > 0
        frequencies = [t.frequency for t in triggers]
        assert any(f in ["Periodic", "On Startup", "On User Action", "Unknown"] for f in frequencies)

    def test_trigger_descriptions_are_meaningful(
        self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path
    ) -> None:
        """Trigger descriptions provide meaningful information."""
        triggers = analyzer._identify_trigger_points(securom_v8_binary)

        assert len(triggers) > 0
        for trigger in triggers:
            assert len(trigger.description) > 0
            assert trigger.description != "Unknown trigger point" or "Unknown" in trigger.trigger_type


class TestProductKeyExtraction:
    """Test product key structure extraction."""

    def test_extract_product_key_formats(self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path) -> None:
        """Analyzer extracts product key format information."""
        keys = analyzer._extract_product_key_info(securom_v8_binary)

        assert len(keys) > 0
        formats = [k.key_format for k in keys]
        assert any(f in ["Dashed Format", "Continuous Format", "GUID Format"] for f in formats)

    def test_detect_key_validation_algorithms(
        self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path
    ) -> None:
        """Analyzer detects product key validation algorithms."""
        keys = analyzer._extract_product_key_info(securom_v8_binary)

        assert len(keys) > 0
        algorithms = [k.validation_algorithm for k in keys]
        assert all(alg in [
            "RSA Signature Verification",
            "SHA256 Hash Validation",
            "CRC32 Checksum",
            "Luhn Algorithm",
            "Custom Algorithm",
            "Unknown",
        ] for alg in algorithms)

    def test_product_key_lengths_are_valid(self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path) -> None:
        """Product key lengths are reasonable values."""
        keys = analyzer._extract_product_key_info(securom_v8_binary)

        assert len(keys) > 0
        for key in keys:
            assert 10 <= key.key_length <= 100

    def test_detect_checksum_types(self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path) -> None:
        """Analyzer detects checksum types in product keys."""
        keys = analyzer._extract_product_key_info(securom_v8_binary)

        assert len(keys) > 0
        if checksums := [k.checksum_type for k in keys if k.checksum_type]:
            assert all(c in ["CRC32", "MD5", "SHA", "Custom Checksum"] for c in checksums)


class TestDiscAuthenticationAnalysis:
    """Test disc authentication routine detection."""

    def test_identify_disc_auth_routines(self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path) -> None:
        """Analyzer identifies disc authentication routines."""
        routines = analyzer._analyze_disc_authentication(securom_v8_binary)

        assert len(routines) > 0

    def test_extract_scsi_commands(self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path) -> None:
        """Analyzer extracts SCSI commands from disc auth routines."""
        routines = analyzer._analyze_disc_authentication(securom_v8_binary)

        assert len(routines) > 0
        scsi_commands = [cmd for routine in routines for cmd in routine.scsi_commands]
        assert scsi_commands
        valid_commands = [
            "INQUIRY",
            "READ_10",
            "READ_12",
            "READ_TOC",
            "READ_SUBCHANNEL",
            "READ_CD",
            "READ_CAPACITY",
            "READ_DISC_INFORMATION",
        ]
        assert all(cmd in valid_commands for cmd in scsi_commands)

    def test_identify_signature_checks(self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path) -> None:
        """Analyzer identifies disc signature verification methods."""
        routines = analyzer._analyze_disc_authentication(securom_v8_binary)

        assert len(routines) > 0
        if signature_checks := [
            check for routine in routines for check in routine.signature_checks
        ]:
            valid_checks = [
                "Digital Signature Verification",
                "Table of Contents Check",
                "Subchannel Data Analysis",
                "Physical Format Verification",
                "Disc Serial Number Check",
            ]
            assert all(check in valid_checks for check in signature_checks)

    def test_determine_fingerprint_methods(self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path) -> None:
        """Analyzer determines disc fingerprinting methods."""
        routines = analyzer._analyze_disc_authentication(securom_v8_binary)

        assert len(routines) > 0
        methods = [r.fingerprint_method for r in routines]
        valid_methods = [
            "Subchannel-based Fingerprinting",
            "TOC-based Fingerprinting",
            "Physical Sector Analysis",
            "Unknown Method",
        ]
        assert all(m in valid_methods for m in methods)

    def test_assess_bypass_difficulty(self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path) -> None:
        """Analyzer assesses bypass difficulty of disc authentication."""
        routines = analyzer._analyze_disc_authentication(securom_v8_binary)

        assert len(routines) > 0
        difficulties = [r.bypass_difficulty for r in routines]
        assert all(d in ["Low", "Medium", "High"] for d in difficulties)


class TestPhoneHomeMechanisms:
    """Test phone-home mechanism detection."""

    def test_detect_http_phone_home(self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path) -> None:
        """Analyzer detects HTTP-based phone-home mechanisms."""
        mechanisms = analyzer._detect_phone_home(securom_v8_binary)

        assert len(mechanisms) > 0
        assert any(m.mechanism_type == "HTTP" for m in mechanisms)

    def test_extract_phone_home_server_urls(
        self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path
    ) -> None:
        """Analyzer extracts phone-home server URLs."""
        mechanisms = analyzer._detect_phone_home(securom_v8_binary)

        assert len(mechanisms) > 0
        urls = [url for m in mechanisms for url in m.server_urls]
        assert urls
        assert any("https://" in url for url in urls)

    def test_identify_transmitted_data(self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path) -> None:
        """Analyzer identifies data transmitted in phone-home."""
        mechanisms = analyzer._detect_phone_home(securom_v8_binary)

        assert len(mechanisms) > 0
        if data_items := [item for m in mechanisms for item in m.data_transmitted]:
            valid_items = [
                "Machine ID",
                "Product Key",
                "Activation Status",
                "Software Version",
                "Hardware ID",
                "User Name",
                "Computer Name",
            ]
            assert all(item in valid_items for item in data_items)

    def test_detect_network_protocol(self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path) -> None:
        """Analyzer detects network protocols used for phone-home."""
        mechanisms = analyzer._detect_phone_home(securom_v8_binary)

        assert len(mechanisms) > 0
        protocols = [m.protocol for m in mechanisms]
        assert all(p in ["HTTP/HTTPS", "TCP/IP", "Unknown"] for p in protocols)


class TestChallengeResponseAnalysis:
    """Test challenge-response authentication flow analysis."""

    def test_detect_challenge_response_flow(
        self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path
    ) -> None:
        """Analyzer detects challenge-response authentication flows."""
        flows = analyzer._analyze_challenge_response(securom_v8_binary)

        assert len(flows) > 0

    def test_identify_challenge_generation_address(
        self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path
    ) -> None:
        """Analyzer identifies challenge generation code location."""
        flows = analyzer._analyze_challenge_response(securom_v8_binary)

        assert len(flows) > 0
        binary_size = securom_v8_binary.stat().st_size
        for flow in flows:
            assert 0 <= flow.challenge_generation_addr < binary_size

    def test_identify_response_validation_address(
        self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path
    ) -> None:
        """Analyzer identifies response validation code location."""
        flows = analyzer._analyze_challenge_response(securom_v8_binary)

        assert len(flows) > 0
        binary_size = securom_v8_binary.stat().st_size
        for flow in flows:
            assert 0 <= flow.response_validation_addr < binary_size

    def test_identify_cryptographic_operations(
        self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path
    ) -> None:
        """Analyzer identifies cryptographic operations in challenge-response."""
        flows = analyzer._analyze_challenge_response(securom_v8_binary)

        assert len(flows) > 0
        for flow in flows:
            for offset, algo in flow.crypto_operations:
                assert algo in ["RSA", "AES", "SHA256", "MD5"]
                assert offset >= 0

    def test_detect_key_derivation_method(self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path) -> None:
        """Analyzer detects key derivation methods."""
        flows = analyzer._analyze_challenge_response(securom_v8_binary)

        assert len(flows) > 0
        methods = [f.key_derivation_method for f in flows]
        assert all(m in ["PBKDF2", "Custom KDF"] for m in methods)

    def test_assess_challenge_response_difficulty(
        self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path
    ) -> None:
        """Analyzer assesses challenge-response bypass difficulty."""
        flows = analyzer._analyze_challenge_response(securom_v8_binary)

        assert len(flows) > 0
        difficulties = [f.difficulty for f in flows]
        assert all(d in ["Medium", "High"] for d in difficulties)


class TestLicenseValidationMapping:
    """Test license validation function mapping."""

    def test_map_license_validation_functions(
        self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path
    ) -> None:
        """Analyzer maps license validation functions."""
        functions = analyzer._map_license_validation(securom_v8_binary)

        assert len(functions) > 0

    def test_identify_validation_function_types(
        self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path
    ) -> None:
        """Analyzer identifies validation function types."""
        functions = analyzer._map_license_validation(securom_v8_binary)

        assert len(functions) > 0
        types = [f.function_type for f in functions]
        valid_types = [
            "License Validation",
            "Activation Check",
            "Product Key Verification",
            "User Authentication",
            "Expiration Check",
        ]
        assert all(t in valid_types for t in types)

    def test_identify_validation_checks_performed(
        self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path
    ) -> None:
        """Analyzer identifies checks performed in validation functions."""
        functions = analyzer._map_license_validation(securom_v8_binary)

        assert len(functions) > 0
        if all_checks := [
            check for func in functions for check in func.checks_performed
        ]:
            valid_checks = [
                "Registry Check",
                "File Existence Check",
                "Network Validation",
                "Hardware Check",
                "Expiration Check",
                "Digital Signature Verification",
            ]
            assert all(check in valid_checks for check in all_checks)

    def test_extract_return_value_meanings(
        self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path
    ) -> None:
        """Analyzer extracts return value meanings from validation functions."""
        functions = analyzer._map_license_validation(securom_v8_binary)

        assert len(functions) > 0
        for func in functions:
            assert isinstance(func.return_values, dict)
            assert "0" in func.return_values
            assert func.return_values["0"] == "Validation Success"


class TestEncryptionDetection:
    """Test encryption technique identification."""

    def test_identify_aes_encryption(self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path) -> None:
        """Analyzer identifies AES encryption usage."""
        techniques = analyzer._identify_encryption(securom_v8_binary)

        assert "AES" in techniques

    def test_identify_sha256_hashing(self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path) -> None:
        """Analyzer identifies SHA256 hashing usage."""
        techniques = analyzer._identify_encryption(securom_v8_binary)

        assert "SHA256" in techniques

    def test_encryption_detection_returns_unique_algorithms(
        self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path
    ) -> None:
        """Encryption detection returns unique algorithm list."""
        techniques = analyzer._identify_encryption(securom_v8_binary)

        assert len(techniques) == len(set(techniques))

    def test_no_encryption_detected_in_non_securom_binary(
        self, analyzer: SecuROMAnalyzer, non_securom_binary: Path
    ) -> None:
        """Analyzer returns empty list for binaries without crypto patterns."""
        techniques = analyzer._identify_encryption(non_securom_binary)

        assert len(techniques) == 0


class TestObfuscationDetection:
    """Test code obfuscation detection."""

    def test_obfuscation_detection_does_not_crash(
        self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path
    ) -> None:
        """Obfuscation detection completes without errors."""
        methods = analyzer._detect_obfuscation(securom_v8_binary)

        assert isinstance(methods, list)

    def test_obfuscation_detection_on_real_windows_dll(self, analyzer: SecuROMAnalyzer) -> None:
        """Obfuscation detection works on real Windows DLLs."""
        kernel32 = SYSTEM32 / "kernel32.dll"

        if kernel32.exists():
            methods = analyzer._detect_obfuscation(kernel32)
            assert isinstance(methods, list)


class TestImportExportAnalysis:
    """Test PE import/export analysis."""

    def test_get_imports_from_real_windows_binary(self, analyzer: SecuROMAnalyzer) -> None:
        """Analyzer extracts imports from real Windows binaries."""
        notepad = SYSTEM32 / "notepad.exe"

        if notepad.exists():
            imports = analyzer._get_imports(notepad)
            assert len(imports) > 0
            assert any("!" in imp for imp in imports)

    def test_get_exports_from_real_windows_dll(self, analyzer: SecuROMAnalyzer) -> None:
        """Analyzer extracts exports from real Windows DLLs."""
        kernel32 = SYSTEM32 / "kernel32.dll"

        if kernel32.exists():
            exports = analyzer._get_exports(kernel32)
            assert len(exports) > 0


class TestResourceAnalysis:
    """Test PE resource analysis."""

    def test_analyze_resources_on_real_windows_binary(self, analyzer: SecuROMAnalyzer) -> None:
        """Analyzer analyzes resources in real Windows binaries."""
        notepad = SYSTEM32 / "notepad.exe"

        if notepad.exists():
            resources = analyzer._analyze_resources(notepad)
            assert isinstance(resources, dict)


class TestStringExtraction:
    """Test relevant string extraction."""

    def test_extract_relevant_strings_from_securom_binary(
        self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path
    ) -> None:
        """Analyzer extracts relevant strings from SecuROM binary."""
        strings = analyzer._extract_relevant_strings(securom_v8_binary)

        assert len(strings) > 0
        assert any("OnlineActivation" in s or "ProductKey" in s or "DiscSignature" in s for s in strings)

    def test_string_extraction_limits_results(
        self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path
    ) -> None:
        """String extraction limits results to reasonable count."""
        strings = analyzer._extract_relevant_strings(securom_v8_binary)

        assert len(strings) <= 50


class TestNetworkEndpointExtraction:
    """Test network endpoint extraction."""

    def test_extract_https_endpoints(self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path) -> None:
        """Analyzer extracts HTTPS endpoints from binary."""
        endpoints = analyzer._extract_network_endpoints(securom_v8_binary)

        assert len(endpoints) > 0
        assert any("https://" in ep for ep in endpoints)

    def test_endpoint_extraction_returns_unique_urls(
        self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path
    ) -> None:
        """Endpoint extraction returns unique URLs."""
        endpoints = analyzer._extract_network_endpoints(securom_v8_binary)

        assert len(endpoints) == len(set(endpoints))

    def test_extracted_urls_are_reasonable_length(
        self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path
    ) -> None:
        """Extracted URLs are reasonable length (not corrupted data)."""
        endpoints = analyzer._extract_network_endpoints(securom_v8_binary)

        for endpoint in endpoints:
            assert len(endpoint) < 200


class TestRegistryAccessIdentification:
    """Test registry key access identification."""

    def test_identify_securom_registry_keys(
        self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path
    ) -> None:
        """Analyzer identifies SecuROM registry keys."""
        registry_keys = analyzer._identify_registry_access(securom_v8_binary)

        assert len(registry_keys) > 0
        assert any("SecuROM" in key or "Sony DADC" in key for key in registry_keys)


class TestFullAnalysisIntegration:
    """Test complete SecuROM analysis workflow."""

    def test_complete_analysis_of_securom_v8_binary(
        self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path
    ) -> None:
        """Complete analysis of SecuROM v8 binary succeeds."""
        result = analyzer.analyze(securom_v8_binary)

        assert isinstance(result, SecuROMAnalysis)
        assert result.target_path == securom_v8_binary
        assert result.version == "8.x"
        assert len(result.activation_mechanisms) > 0
        assert len(result.trigger_points) > 0
        assert len(result.details) > 0

    def test_complete_analysis_of_securom_v7_binary(
        self, analyzer: SecuROMAnalyzer, securom_v7_binary: Path
    ) -> None:
        """Complete analysis of SecuROM v7 binary succeeds."""
        result = analyzer.analyze(securom_v7_binary)

        assert isinstance(result, SecuROMAnalysis)
        assert result.version == "7.x"

    def test_analysis_result_structure_is_complete(
        self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path
    ) -> None:
        """Analysis result contains all expected fields."""
        result = analyzer.analyze(securom_v8_binary)

        assert hasattr(result, "target_path")
        assert hasattr(result, "version")
        assert hasattr(result, "activation_mechanisms")
        assert hasattr(result, "trigger_points")
        assert hasattr(result, "product_keys")
        assert hasattr(result, "disc_auth_routines")
        assert hasattr(result, "phone_home_mechanisms")
        assert hasattr(result, "challenge_response_flows")
        assert hasattr(result, "license_validation_functions")
        assert hasattr(result, "encryption_techniques")
        assert hasattr(result, "obfuscation_methods")
        assert hasattr(result, "details")

    def test_analysis_details_contain_expected_keys(
        self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path
    ) -> None:
        """Analysis details dictionary contains expected keys."""
        result = analyzer.analyze(securom_v8_binary)

        assert "imports" in result.details
        assert "exports" in result.details
        assert "resources" in result.details
        assert "strings" in result.details
        assert "network_endpoints" in result.details
        assert "registry_access" in result.details


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_analyze_partial_securom_binary(
        self, analyzer: SecuROMAnalyzer, partial_securom_binary: Path
    ) -> None:
        """Analyzer handles binaries with partial SecuROM signatures."""
        result = analyzer.analyze(partial_securom_binary)

        assert isinstance(result, SecuROMAnalysis)
        assert result.version in ["7.x or earlier", "Unknown"]

    def test_analyze_non_securom_binary(self, analyzer: SecuROMAnalyzer, non_securom_binary: Path) -> None:
        """Analyzer handles binaries without SecuROM protection."""
        result = analyzer.analyze(non_securom_binary)

        assert isinstance(result, SecuROMAnalysis)
        assert result.version == "Unknown"
        if len(result.activation_mechanisms) > 0:
            assert not any(m.online_validation for m in result.activation_mechanisms)
            assert not any(m.challenge_response for m in result.activation_mechanisms)

    def test_analyze_corrupted_pe_header(self, analyzer: SecuROMAnalyzer, tmp_path: Path) -> None:
        """Analyzer handles corrupted PE headers gracefully."""
        corrupted = tmp_path / "corrupted.exe"
        corrupted.write_bytes(b"MZ" + b"\x00" * 100)

        result = analyzer.analyze(corrupted)

        assert isinstance(result, SecuROMAnalysis)

    def test_analyze_empty_file(self, analyzer: SecuROMAnalyzer, tmp_path: Path) -> None:
        """Analyzer handles empty files gracefully."""
        empty = tmp_path / "empty.exe"
        empty.write_bytes(b"")

        result = analyzer.analyze(empty)

        assert isinstance(result, SecuROMAnalysis)
        assert result.version == "Unknown"

    def test_analyze_very_large_binary(self, analyzer: SecuROMAnalyzer, tmp_path: Path) -> None:
        """Analyzer handles large binaries without performance issues."""
        large_binary = TestBinaryFactory.create_securom_v8_binary()
        large_binary += b"\x00" * (10 * 1024 * 1024)

        binary_path = tmp_path / "large.exe"
        binary_path.write_bytes(large_binary)

        result = analyzer.analyze(binary_path)

        assert isinstance(result, SecuROMAnalysis)
        assert result.version == "8.x"


class TestRealWorldBinaries:
    """Test against real Windows system binaries."""

    def test_analyze_notepad_executable(self, analyzer: SecuROMAnalyzer) -> None:
        """Analyzer processes notepad.exe without errors."""
        notepad = SYSTEM32 / "notepad.exe"

        if notepad.exists():
            result = analyzer.analyze(notepad)
            assert isinstance(result, SecuROMAnalysis)
            assert result.target_path == notepad

    def test_analyze_kernel32_dll(self, analyzer: SecuROMAnalyzer) -> None:
        """Analyzer processes kernel32.dll without errors."""
        kernel32 = SYSTEM32 / "kernel32.dll"

        if kernel32.exists():
            result = analyzer.analyze(kernel32)
            assert isinstance(result, SecuROMAnalysis)

    def test_analyze_ntdll_dll(self, analyzer: SecuROMAnalyzer) -> None:
        """Analyzer processes ntdll.dll without errors."""
        ntdll = SYSTEM32 / "ntdll.dll"

        if ntdll.exists():
            result = analyzer.analyze(ntdll)
            assert isinstance(result, SecuROMAnalysis)


@pytest.mark.benchmark
class TestPerformance:
    """Performance benchmark tests."""

    def test_version_detection_performance(
        self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path, benchmark: Any
    ) -> None:
        """Version detection completes within reasonable time."""

        def detect_version() -> str:
            return analyzer._detect_version(securom_v8_binary)

        result = benchmark(detect_version)
        assert result in ["8.x", "7.x", "7.x or earlier", "Unknown"]

    def test_full_analysis_performance(
        self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path, benchmark: Any
    ) -> None:
        """Full analysis completes within reasonable time."""

        def full_analysis() -> SecuROMAnalysis:
            return analyzer.analyze(securom_v8_binary)

        result = benchmark(full_analysis)
        assert isinstance(result, SecuROMAnalysis)

    def test_string_extraction_performance(
        self, analyzer: SecuROMAnalyzer, securom_v8_binary: Path, benchmark: Any
    ) -> None:
        """String extraction completes within reasonable time."""

        def extract_strings() -> list[str]:
            return analyzer._extract_relevant_strings(securom_v8_binary)

        result = benchmark(extract_strings)
        assert isinstance(result, list)
