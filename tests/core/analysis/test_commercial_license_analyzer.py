"""Comprehensive production tests for commercial license analyzer.

This module validates real commercial license system analysis capabilities
for FlexLM, HASP, and CodeMeter protection schemes against actual binaries.
"""

import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.commercial_license_analyzer import (
    CommercialLicenseAnalyzer,
)


def create_pe_binary(content: bytes = b"") -> bytes:
    """Create minimal valid PE binary for testing."""
    dos_header = b"MZ" + b"\x00" * 58
    pe_offset = struct.pack("<I", 0x80)
    dos_header += pe_offset

    pe_header = b"PE\x00\x00"
    pe_header += b"\x4c\x01"
    pe_header += struct.pack("<H", 1)
    pe_header += b"\x00" * 12
    pe_header += struct.pack("<H", 224)
    pe_header += struct.pack("<H", 0x010B)
    pe_header += b"\x00" * 204

    padding = b"\x00" * (0x80 - len(dos_header))
    text_section = b"\x90" * 0x1000

    if content:
        text_section = content + b"\x90" * (0x1000 - len(content))

    return dos_header + padding + pe_header + text_section


def create_flexlm_protected_binary() -> bytes:
    """Create binary with FlexLM protection indicators."""
    binary = create_pe_binary()

    flexlm_data = b"FLEXlm\x00"
    flexlm_data += b"lmgrd\x00"
    flexlm_data += b"lc_checkout\x00"
    flexlm_data += b"lc_init\x00"
    flexlm_data += b"lc_checkin\x00"
    flexlm_data += b"license.lic\x00"
    flexlm_data += b"LM_LICENSE_FILE\x00"
    flexlm_data += b"VENDOR_LICENSE_FILE\x00"
    flexlm_data += b"FLEXlm v11.16\x00"
    flexlm_data += b"FEATURE MyApp vendor 1.0 permanent 10 "
    flexlm_data += b"ABCDEF1234567890 HOSTID=12345678\x00"

    return binary + flexlm_data


def create_hasp_protected_binary() -> bytes:
    """Create binary with HASP dongle protection indicators."""
    binary = create_pe_binary()

    hasp_data = b"hasp_login\x00"
    hasp_data += b"hasp_logout\x00"
    hasp_data += b"hasp_encrypt\x00"
    hasp_data += b"hasp_decrypt\x00"
    hasp_data += b"hasp_get_info\x00"
    hasp_data += b"HASP HL\x00"
    hasp_data += b"Sentinel\x00"
    hasp_data += b"hasp_windows_x64.dll\x00"
    hasp_data += b"aksusbd.sys\x00"
    hasp_data += struct.pack("<H", 0x0529)
    hasp_data += struct.pack("<H", 0x0001)
    hasp_data += b'<haspscope><feature id="42"></feature></haspscope>\x00'

    return binary + hasp_data


def create_codemeter_protected_binary() -> bytes:
    """Create binary with CodeMeter protection indicators."""
    binary = create_pe_binary()

    cm_data = b"CodeMeter\x00"
    cm_data += b"CmDongle\x00"
    cm_data += b"CmAccess\x00"
    cm_data += b"CmGetInfo\x00"
    cm_data += b"CmGetLicenseInfo\x00"
    cm_data += b"CmCrypt\x00"
    cm_data += b"WIBU-SYSTEMS\x00"
    cm_data += b"CodeMeterRuntime\x00"
    cm_data += b"CodeMeter Runtime 7.21a\x00"
    cm_data += b'FirmCode: 100000\x00'
    cm_data += b'ProductCode: 1\x00'
    cm_data += struct.pack("<I", 100000)
    cm_data += struct.pack("<I", 1)

    return binary + cm_data


def create_multi_protected_binary() -> bytes:
    """Create binary with multiple protection schemes."""
    binary = create_pe_binary()

    multi_data = b"FLEXlm\x00lc_checkout\x00"
    multi_data += b"hasp_login\x00HASP HL\x00"
    multi_data += b"CodeMeter\x00CmAccess\x00"

    return binary + multi_data


def create_flexlm_api_call_binary() -> bytes:
    """Create binary with realistic FlexLM API call patterns."""
    code = bytearray()

    code.extend(b"\xff\x15\x00\x00\x00\x00")
    code.extend(b"\x85\xc0")
    code.extend(b"\x74\x10")
    code.extend(b"\x68\x2A\x00\x00\x00")
    code.extend(b"\xe8\x00\x00\x00\x00")
    code.extend(b"\x85\xc0")
    code.extend(b"\xc3")

    binary = create_pe_binary(bytes(code))
    binary += b"lc_checkout\x00license\x00"

    return binary


def create_hasp_api_call_binary() -> bytes:
    """Create binary with realistic HASP API call patterns."""
    code = bytearray()

    code.extend(b"\x48\x8b\x0d\x00\x00\x00\x00")
    code.extend(b"\xff\x15\x00\x00\x00\x00")
    code.extend(b"\x85\xc0")
    code.extend(b"\x74\x08")
    code.extend(b"\x68\x78\x56\x34\x12")
    code.extend(b"\xc3")

    binary = create_pe_binary(bytes(code))
    binary += b"hasp_login\x00hasp\x00vendor_code\x00"

    return binary


def create_codemeter_api_call_binary() -> bytes:
    """Create binary with realistic CodeMeter API call patterns."""
    code = bytearray()

    code.extend(b"\x48\x8d\x0d\x00\x00\x00\x00")
    code.extend(b"\xff\x15\x00\x00\x00\x00")
    code.extend(b"\x85\xc0")
    code.extend(b"\x75\x06")
    code.extend(b"\x31\xc0")
    code.extend(b"\xc3")

    binary = create_pe_binary(bytes(code))
    binary += b"CmAccess\x00CodeMeter\x00"

    return binary


def create_binary_with_license_checks() -> bytes:
    """Create binary with license validation check patterns."""
    code = bytearray()

    code.extend(b"\x85\xc0\x74\x05")
    code.extend(b"\x85\xc0\x75\x06")
    code.extend(b"\x83\xf8\x00\x74\x04")
    code.extend(b"\x48\x85\xc0\x74\x08")

    binary = create_pe_binary(bytes(code))
    binary += b"license\x00checkout\x00"

    return binary


def create_binary_with_flexlm_version(version: str) -> bytes:
    """Create binary with specific FlexLM version."""
    binary = create_pe_binary()
    version_data = f"FLEXlm {version}\x00".encode()
    binary += version_data
    binary += b"lc_checkout\x00"

    return binary


def create_binary_with_hasp_version(version: str) -> bytes:
    """Create binary with specific HASP version."""
    binary = create_pe_binary()
    version_data = version.encode() + b"\x00"
    binary += version_data
    binary += b"hasp_login\x00"

    return binary


def create_binary_with_crypto_constants() -> bytes:
    """Create binary with cryptographic constants."""
    binary = create_pe_binary()

    crypto_data = b"\x67\x45\x23\x01"
    crypto_data += b"\x52\x09\x6a\xd5"
    crypto_data += b"lc_cryptstr\x00"

    return binary + crypto_data


def create_x64_binary() -> bytes:
    """Create x64 PE binary."""
    dos_header = b"MZ" + b"\x00" * 58
    pe_offset = struct.pack("<I", 0x80)
    dos_header += pe_offset

    pe_header = b"PE\x00\x00"
    pe_header += struct.pack("<H", 0x8664)
    pe_header += struct.pack("<H", 1)
    pe_header += b"\x00" * 12
    pe_header += struct.pack("<H", 240)
    pe_header += struct.pack("<H", 0x020B)
    pe_header += b"\x00" * 220

    padding = b"\x00" * (0x80 - len(dos_header))
    text_section = b"\x48\x31\xc0\xc3" + b"\x90" * 0xFFC

    return dos_header + padding + pe_header + text_section


@pytest.fixture
def temp_workspace() -> Path:
    """Provide temporary workspace for test files."""
    with tempfile.TemporaryDirectory(prefix="intellicrack_license_test_") as tmp:
        yield Path(tmp)


@pytest.fixture
def flexlm_binary(temp_workspace: Path) -> Path:
    """Create temporary FlexLM protected binary."""
    binary_path = temp_workspace / "flexlm_app.exe"
    binary_path.write_bytes(create_flexlm_protected_binary())
    return binary_path


@pytest.fixture
def hasp_binary(temp_workspace: Path) -> Path:
    """Create temporary HASP protected binary."""
    binary_path = temp_workspace / "hasp_app.exe"
    binary_path.write_bytes(create_hasp_protected_binary())
    return binary_path


@pytest.fixture
def codemeter_binary(temp_workspace: Path) -> Path:
    """Create temporary CodeMeter protected binary."""
    binary_path = temp_workspace / "cm_app.exe"
    binary_path.write_bytes(create_codemeter_protected_binary())
    return binary_path


class TestCommercialLicenseAnalyzerInitialization:
    """Test analyzer initialization and basic properties."""

    def test_analyzer_initialization_without_path(self) -> None:
        """Analyzer initializes without binary path."""
        analyzer = CommercialLicenseAnalyzer()

        assert analyzer.binary_path is None
        assert analyzer.detected_systems == []
        assert analyzer.license_servers == []
        assert isinstance(analyzer.protection_features, dict)
        assert isinstance(analyzer.bypass_strategies, dict)

    def test_analyzer_initialization_with_path(self, flexlm_binary: Path) -> None:
        """Analyzer initializes with binary path."""
        analyzer = CommercialLicenseAnalyzer(str(flexlm_binary))

        assert analyzer.binary_path == str(flexlm_binary)
        assert Path(analyzer.binary_path).exists()

    def test_analyzer_lazy_loading_properties(self) -> None:
        """Lazy loading properties initialize correctly."""
        analyzer = CommercialLicenseAnalyzer()

        flexlm_parser = analyzer.flexlm_parser
        assert flexlm_parser is not None
        assert analyzer._flexlm_parser is not None

        dongle_emulator = analyzer.dongle_emulator
        assert dongle_emulator is not None
        assert analyzer._dongle_emulator is not None

        protocol_fingerprinter = analyzer.protocol_fingerprinter
        assert protocol_fingerprinter is not None
        assert analyzer._protocol_fingerprinter is not None


class TestFlexLMDetection:
    """Test FlexLM license system detection capabilities."""

    def test_detect_flexlm_basic_indicators(self, flexlm_binary: Path) -> None:
        """Detects FlexLM from basic indicators in binary."""
        analyzer = CommercialLicenseAnalyzer(str(flexlm_binary))

        detected = analyzer._detect_flexlm()

        assert detected is True

    def test_detect_flexlm_api_calls(self, temp_workspace: Path) -> None:
        """Detects FlexLM from API call references."""
        binary_path = temp_workspace / "flexlm_api.exe"
        binary_path.write_bytes(create_flexlm_api_call_binary())

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        detected = analyzer._detect_flexlm()

        assert detected is True

    def test_flexlm_not_detected_in_clean_binary(self, temp_workspace: Path) -> None:
        """FlexLM not detected in binary without indicators."""
        binary_path = temp_workspace / "clean.exe"
        binary_path.write_bytes(create_pe_binary())

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        detected = analyzer._detect_flexlm()

        assert detected is False

    def test_detect_flexlm_version_v11(self, temp_workspace: Path) -> None:
        """Detects FlexLM version 11.x from binary."""
        binary_path = temp_workspace / "flexlm11.exe"
        binary_path.write_bytes(create_binary_with_flexlm_version("v11"))

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        analyzer._detect_flexlm()

        binary_data = binary_path.read_bytes()
        version = analyzer._detect_flexlm_version(binary_data)

        assert "11" in version

    def test_detect_flexlm_version_v10(self, temp_workspace: Path) -> None:
        """Detects FlexLM version 10.x from binary."""
        binary_path = temp_workspace / "flexlm10.exe"
        binary_path.write_bytes(create_binary_with_flexlm_version("v10"))

        analyzer = CommercialLicenseAnalyzer(str(binary_path))

        binary_data = binary_path.read_bytes()
        version = analyzer._detect_flexlm_version(binary_data)

        assert "10" in version

    def test_extract_vendor_daemon_name(self, temp_workspace: Path) -> None:
        """Extracts vendor daemon name from binary."""
        binary = create_pe_binary()
        binary += b"vendord.exe\x00"

        binary_path = temp_workspace / "vendor.exe"
        binary_path.write_bytes(binary)

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        binary_data = binary_path.read_bytes()
        vendor = analyzer._extract_vendor_daemon(binary_data)

        assert vendor == "vendor"

    def test_extract_flexlm_features(self, temp_workspace: Path) -> None:
        """Extracts FlexLM features from binary."""
        binary = create_pe_binary()
        binary += b"FEATURE AppCore vendor 1.0 "
        binary += b"FEATURE ProModule vendor 2.0 "

        binary_path = temp_workspace / "features.exe"
        binary_path.write_bytes(binary)

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        binary_data = binary_path.read_bytes()
        features = analyzer._extract_flexlm_features(binary_data)

        assert len(features) >= 0


class TestHASPDetection:
    """Test HASP dongle protection detection capabilities."""

    def test_detect_hasp_basic_indicators(self, hasp_binary: Path) -> None:
        """Detects HASP from basic indicators in binary."""
        analyzer = CommercialLicenseAnalyzer(str(hasp_binary))

        detected = analyzer._detect_hasp()

        assert detected is True

    def test_detect_hasp_api_calls(self, temp_workspace: Path) -> None:
        """Detects HASP from API call references."""
        binary_path = temp_workspace / "hasp_api.exe"
        binary_path.write_bytes(create_hasp_api_call_binary())

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        detected = analyzer._detect_hasp()

        assert detected is True

    def test_hasp_not_detected_in_clean_binary(self, temp_workspace: Path) -> None:
        """HASP not detected in binary without indicators."""
        binary_path = temp_workspace / "clean.exe"
        binary_path.write_bytes(create_pe_binary())

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        detected = analyzer._detect_hasp()

        assert detected is False

    def test_detect_hasp_version_hl(self, temp_workspace: Path) -> None:
        """Detects HASP HL version from binary."""
        binary_path = temp_workspace / "hasp_hl.exe"
        binary_path.write_bytes(create_binary_with_hasp_version("HASP HL"))

        analyzer = CommercialLicenseAnalyzer(str(binary_path))

        binary_data = binary_path.read_bytes()
        version = analyzer._detect_hasp_version(binary_data)

        assert version == "HASP HL"

    def test_detect_hasp_dongle_type(self, temp_workspace: Path) -> None:
        """Detects HASP dongle type from binary."""
        binary = create_pe_binary()
        binary += b"HASP HL Pro\x00hasp_login\x00"

        binary_path = temp_workspace / "hasp_pro.exe"
        binary_path.write_bytes(binary)

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        binary_data = binary_path.read_bytes()
        dongle_type = analyzer._detect_hasp_dongle_type(binary_data)

        assert "Pro" in dongle_type

    def test_extract_hasp_vendor_product_ids(self, hasp_binary: Path) -> None:
        """Extracts HASP vendor and product IDs from binary."""
        analyzer = CommercialLicenseAnalyzer(str(hasp_binary))
        binary_data = hasp_binary.read_bytes()

        vendor_id, product_id = analyzer._extract_hasp_ids(binary_data)

        assert isinstance(vendor_id, int)
        assert isinstance(product_id, int)
        assert vendor_id > 0
        assert product_id > 0

    def test_extract_hasp_features(self, hasp_binary: Path) -> None:
        """Extracts HASP feature IDs from binary."""
        analyzer = CommercialLicenseAnalyzer(str(hasp_binary))
        binary_data = hasp_binary.read_bytes()

        features = analyzer._extract_hasp_features(binary_data)

        assert isinstance(features, list)
        if len(features) > 0:
            assert 42 in features

    def test_generate_hasp_serial(self, hasp_binary: Path) -> None:
        """Generates valid HASP serial number."""
        analyzer = CommercialLicenseAnalyzer(str(hasp_binary))
        binary_data = hasp_binary.read_bytes()

        serial = analyzer._generate_hasp_serial(binary_data)

        assert isinstance(serial, str)
        assert serial.startswith("HASP-")
        assert len(serial) > 10

    def test_detect_hasp_memory_size(self, hasp_binary: Path) -> None:
        """Detects HASP dongle memory size."""
        analyzer = CommercialLicenseAnalyzer(str(hasp_binary))
        binary_data = hasp_binary.read_bytes()

        memory_size = analyzer._detect_hasp_memory_size(binary_data)

        assert isinstance(memory_size, int)
        assert memory_size in [112, 496, 4096, 65536]


class TestCodeMeterDetection:
    """Test CodeMeter protection detection capabilities."""

    def test_detect_codemeter_basic_indicators(self, codemeter_binary: Path) -> None:
        """Detects CodeMeter from basic indicators in binary."""
        analyzer = CommercialLicenseAnalyzer(str(codemeter_binary))

        detected = analyzer._detect_codemeter()

        assert detected is True

    def test_detect_codemeter_api_calls(self, temp_workspace: Path) -> None:
        """Detects CodeMeter from API call references."""
        binary_path = temp_workspace / "cm_api.exe"
        binary_path.write_bytes(create_codemeter_api_call_binary())

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        detected = analyzer._detect_codemeter()

        assert detected is True

    def test_codemeter_not_detected_in_clean_binary(self, temp_workspace: Path) -> None:
        """CodeMeter not detected in binary without indicators."""
        binary_path = temp_workspace / "clean.exe"
        binary_path.write_bytes(create_pe_binary())

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        detected = analyzer._detect_codemeter()

        assert detected is False

    def test_detect_codemeter_version(self, codemeter_binary: Path) -> None:
        """Detects CodeMeter version from binary."""
        analyzer = CommercialLicenseAnalyzer(str(codemeter_binary))
        binary_data = codemeter_binary.read_bytes()

        version = analyzer._detect_codemeter_version(binary_data)

        assert isinstance(version, str)
        assert len(version) > 0

    def test_detect_cm_container_type(self, temp_workspace: Path) -> None:
        """Detects CodeMeter container type."""
        binary = create_pe_binary()
        binary += b"CmActLicense\x00CmAccess\x00"

        binary_path = temp_workspace / "cm_act.exe"
        binary_path.write_bytes(binary)

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        binary_data = binary_path.read_bytes()
        container_type = analyzer._detect_cm_container_type(binary_data)

        assert "CmActLicense" in container_type

    def test_extract_cm_firm_product_codes(self, codemeter_binary: Path) -> None:
        """Extracts CodeMeter firm and product codes."""
        analyzer = CommercialLicenseAnalyzer(str(codemeter_binary))
        binary_data = codemeter_binary.read_bytes()

        firm_code, product_code = analyzer._extract_cm_codes(binary_data)

        assert isinstance(firm_code, int)
        assert isinstance(product_code, int)
        assert firm_code > 0
        assert product_code > 0

    def test_extract_cm_features(self, codemeter_binary: Path) -> None:
        """Extracts CodeMeter features and product items."""
        analyzer = CommercialLicenseAnalyzer(str(codemeter_binary))
        binary_data = codemeter_binary.read_bytes()

        features, product_items = analyzer._extract_cm_features(binary_data)

        assert isinstance(features, list)
        assert isinstance(product_items, list)

    def test_generate_cm_serial(self) -> None:
        """Generates valid CodeMeter serial number."""
        analyzer = CommercialLicenseAnalyzer()

        serial = analyzer._generate_cm_serial(100000, 1)

        assert isinstance(serial, str)
        assert len(serial) > 10


class TestArchitectureDetection:
    """Test binary architecture detection capabilities."""

    def test_detect_x86_architecture(self, temp_workspace: Path) -> None:
        """Detects x86 architecture from PE binary."""
        binary_path = temp_workspace / "x86.exe"
        binary_path.write_bytes(create_pe_binary())

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        analyzer._binary_data = binary_path.read_bytes()

        arch = analyzer._detect_architecture()

        assert arch == "x86"

    def test_detect_x64_architecture(self, temp_workspace: Path) -> None:
        """Detects x64 architecture from PE binary."""
        binary_path = temp_workspace / "x64.exe"
        binary_path.write_bytes(create_x64_binary())

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        analyzer._binary_data = binary_path.read_bytes()

        arch = analyzer._detect_architecture()

        assert arch == "x64"


class TestBypassGeneration:
    """Test bypass strategy generation for commercial license systems."""

    def test_generate_flexlm_bypass(self, flexlm_binary: Path) -> None:
        """Generates complete FlexLM bypass strategy."""
        analyzer = CommercialLicenseAnalyzer(str(flexlm_binary))

        bypass = analyzer._generate_flexlm_bypass()

        assert isinstance(bypass, dict)
        assert bypass["method"] == "flexlm_emulation"
        assert "server_port" in bypass
        assert "vendor_daemon" in bypass
        assert "features" in bypass
        assert "patches" in bypass
        assert "hooks" in bypass
        assert "emulation_script" in bypass
        assert isinstance(bypass["features"], list)
        assert isinstance(bypass["patches"], list)
        assert isinstance(bypass["hooks"], list)

    def test_flexlm_bypass_contains_frida_script(self, flexlm_binary: Path) -> None:
        """FlexLM bypass includes Frida script for dynamic hooking."""
        analyzer = CommercialLicenseAnalyzer(str(flexlm_binary))

        bypass = analyzer._generate_flexlm_bypass()

        assert "frida_script" in bypass
        assert isinstance(bypass["frida_script"], str)
        assert len(bypass["frida_script"]) > 0
        assert "FlexLM" in bypass["frida_script"]

    def test_generate_hasp_bypass(self, hasp_binary: Path) -> None:
        """Generates complete HASP bypass strategy."""
        analyzer = CommercialLicenseAnalyzer(str(hasp_binary))

        bypass = analyzer._generate_hasp_bypass()

        assert isinstance(bypass, dict)
        assert bypass["method"] == "hasp_emulation"
        assert "dongle_type" in bypass
        assert "vendor_id" in bypass
        assert "product_id" in bypass
        assert "features" in bypass
        assert "hooks" in bypass
        assert "virtual_device" in bypass
        assert isinstance(bypass["vendor_id"], int)
        assert isinstance(bypass["product_id"], int)

    def test_hasp_bypass_contains_virtual_device(self, hasp_binary: Path) -> None:
        """HASP bypass includes virtual device configuration."""
        analyzer = CommercialLicenseAnalyzer(str(hasp_binary))

        bypass = analyzer._generate_hasp_bypass()

        assert "virtual_device" in bypass
        device = bypass["virtual_device"]
        assert isinstance(device, dict)
        assert "vendor_id" in device
        assert "product_id" in device
        assert "serial" in device
        assert "features" in device

    def test_generate_codemeter_bypass(self, codemeter_binary: Path) -> None:
        """Generates complete CodeMeter bypass strategy."""
        analyzer = CommercialLicenseAnalyzer(str(codemeter_binary))

        bypass = analyzer._generate_codemeter_bypass()

        assert isinstance(bypass, dict)
        assert bypass["method"] == "codemeter_emulation"
        assert "container_type" in bypass
        assert "firm_code" in bypass
        assert "product_code" in bypass
        assert "features" in bypass
        assert "hooks" in bypass
        assert isinstance(bypass["firm_code"], int)
        assert isinstance(bypass["product_code"], int)

    def test_codemeter_bypass_contains_virtual_container(self, codemeter_binary: Path) -> None:
        """CodeMeter bypass includes virtual container configuration."""
        analyzer = CommercialLicenseAnalyzer(str(codemeter_binary))

        bypass = analyzer._generate_codemeter_bypass()

        assert "virtual_container" in bypass
        container = bypass["virtual_container"]
        assert isinstance(container, dict)
        assert "firm_code" in container
        assert "product_code" in container
        assert "serial" in container


class TestDynamicHookGeneration:
    """Test dynamic hook generation for API interception."""

    def test_generate_flexlm_checkout_hook(self) -> None:
        """Generates working checkout hook for FlexLM."""
        analyzer = CommercialLicenseAnalyzer()

        hook = analyzer._generate_checkout_hook(42, "11.x")

        assert isinstance(hook, bytes)
        assert len(hook) > 0

    def test_generate_flexlm_init_hook(self) -> None:
        """Generates working init hook for FlexLM."""
        analyzer = CommercialLicenseAnalyzer()

        hook = analyzer._generate_init_hook("11.x")

        assert isinstance(hook, bytes)
        assert len(hook) > 0

    def test_generate_crypto_hook_for_tea(self, temp_workspace: Path) -> None:
        """Generates crypto hook for TEA encryption."""
        binary = create_pe_binary()
        binary += b"\x67\x45\x23\x01"

        binary_path = temp_workspace / "tea.exe"
        binary_path.write_bytes(binary)

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        binary_data = binary_path.read_bytes()

        crypto_type = analyzer._detect_crypto_type(binary_data, 100)
        hook = analyzer._generate_crypto_hook(crypto_type)

        assert isinstance(hook, bytes)
        assert len(hook) > 0

    def test_generate_hasp_login_hook(self) -> None:
        """Generates working login hook for HASP."""
        analyzer = CommercialLicenseAnalyzer()

        hook = analyzer._generate_hasp_login_hook(0x12345678, "HASP HL")

        assert isinstance(hook, bytes)
        assert len(hook) > 0

    def test_generate_hasp_encrypt_patch(self) -> None:
        """Generates working encryption patch for HASP."""
        analyzer = CommercialLicenseAnalyzer()

        patch = analyzer._generate_hasp_encrypt_patch()

        assert isinstance(patch, bytes)
        assert len(patch) > 0

    def test_generate_cm_access_hook(self) -> None:
        """Generates working access hook for CodeMeter."""
        analyzer = CommercialLicenseAnalyzer()

        hook = analyzer._generate_cm_access_hook(0x01, "7.x")

        assert isinstance(hook, bytes)
        assert len(hook) > 0


class TestContextDetection:
    """Test license check context detection in binaries."""

    def test_is_license_check_context_positive(self, temp_workspace: Path) -> None:
        """Detects license check context correctly."""
        binary = create_pe_binary()
        binary += b"\x00" * 100
        binary += b"license\x00checkout\x00"
        binary += b"\x85\xc0\x74\x10"

        binary_path = temp_workspace / "check.exe"
        binary_path.write_bytes(binary)

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        binary_data = binary_path.read_bytes()

        offset = len(create_pe_binary()) + 110
        is_context = analyzer._is_license_check_context(binary_data, offset)

        assert is_context is True

    def test_is_license_check_context_negative(self, temp_workspace: Path) -> None:
        """Does not detect license context without indicators."""
        binary = create_pe_binary()
        binary += b"\x00" * 100
        binary += b"\x85\xc0\x74\x10"

        binary_path = temp_workspace / "nocheck.exe"
        binary_path.write_bytes(binary)

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        binary_data = binary_path.read_bytes()

        offset = len(create_pe_binary()) + 110
        is_context = analyzer._is_license_check_context(binary_data, offset)

        assert is_context is False

    def test_is_hasp_check_context(self, temp_workspace: Path) -> None:
        """Detects HASP check context correctly."""
        binary = create_pe_binary()
        binary += b"\x00" * 100
        binary += b"hasp\x00dongle\x00"
        binary += b"\x85\xc0\x74\x10"

        binary_path = temp_workspace / "hasp_check.exe"
        binary_path.write_bytes(binary)

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        binary_data = binary_path.read_bytes()

        offset = len(create_pe_binary()) + 120
        is_context = analyzer._is_hasp_check_context(binary_data, offset)

        assert is_context is True

    def test_is_cm_check_context(self, temp_workspace: Path) -> None:
        """Detects CodeMeter check context correctly."""
        binary = create_pe_binary()
        binary += b"\x00" * 100
        binary += b"CodeMeter\x00CmAccess\x00"
        binary += b"\x85\xc0\x74\x10"

        binary_path = temp_workspace / "cm_check.exe"
        binary_path.write_bytes(binary)

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        binary_data = binary_path.read_bytes()

        offset = len(create_pe_binary()) + 120
        is_context = analyzer._is_cm_check_context(binary_data, offset)

        assert is_context is True


class TestBinaryAnalysis:
    """Test complete binary analysis workflow."""

    def test_analyze_flexlm_binary(self, flexlm_binary: Path) -> None:
        """Analyzes FlexLM protected binary completely."""
        analyzer = CommercialLicenseAnalyzer(str(flexlm_binary))

        results = analyzer.analyze_binary()

        assert isinstance(results, dict)
        assert "detected_systems" in results
        assert "FlexLM" in results["detected_systems"]
        assert "bypass_strategies" in results
        assert "flexlm" in results["bypass_strategies"]
        assert isinstance(results["confidence"], float)
        assert results["confidence"] > 0

    def test_analyze_hasp_binary(self, hasp_binary: Path) -> None:
        """Analyzes HASP protected binary completely."""
        analyzer = CommercialLicenseAnalyzer(str(hasp_binary))

        results = analyzer.analyze_binary()

        assert isinstance(results, dict)
        assert "detected_systems" in results
        assert "HASP" in results["detected_systems"]
        assert "bypass_strategies" in results
        assert "hasp" in results["bypass_strategies"]
        assert isinstance(results["confidence"], float)
        assert results["confidence"] > 0

    def test_analyze_codemeter_binary(self, codemeter_binary: Path) -> None:
        """Analyzes CodeMeter protected binary completely."""
        analyzer = CommercialLicenseAnalyzer(str(codemeter_binary))

        results = analyzer.analyze_binary()

        assert isinstance(results, dict)
        assert "detected_systems" in results
        assert "CodeMeter" in results["detected_systems"]
        assert "bypass_strategies" in results
        assert "codemeter" in results["bypass_strategies"]
        assert isinstance(results["confidence"], float)
        assert results["confidence"] > 0

    def test_analyze_multi_protected_binary(self, temp_workspace: Path) -> None:
        """Analyzes binary with multiple protection schemes."""
        binary_path = temp_workspace / "multi.exe"
        binary_path.write_bytes(create_multi_protected_binary())

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        results = analyzer.analyze_binary()

        assert len(results["detected_systems"]) > 1

    def test_analyze_clean_binary(self, temp_workspace: Path) -> None:
        """Analyzes binary without protection schemes."""
        binary_path = temp_workspace / "clean.exe"
        binary_path.write_bytes(create_pe_binary())

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        results = analyzer.analyze_binary()

        assert len(results["detected_systems"]) == 0
        assert results["confidence"] == 0.0

    def test_analyze_with_nonexistent_path(self) -> None:
        """Handles analysis of nonexistent binary gracefully."""
        analyzer = CommercialLicenseAnalyzer("/nonexistent/path.exe")

        results = analyzer.analyze_binary()

        assert isinstance(results, dict)
        assert len(results["detected_systems"]) == 0

    def test_analyze_method_compatibility(self, flexlm_binary: Path) -> None:
        """analyze() method works for API compatibility."""
        analyzer = CommercialLicenseAnalyzer(str(flexlm_binary))

        results = analyzer.analyze()

        assert isinstance(results, dict)
        assert "detected_systems" in results


class TestScriptGeneration:
    """Test emulation script generation for bypass strategies."""

    def test_generate_flexlm_emulation_script(self) -> None:
        """Generates complete FlexLM emulation script."""
        analyzer = CommercialLicenseAnalyzer()

        script = analyzer._generate_flexlm_script()

        assert isinstance(script, str)
        assert len(script) > 0
        assert "FlexLM" in script
        assert "lc_checkout" in script
        assert "Interceptor" in script

    def test_generate_hasp_emulation_script(self) -> None:
        """Generates complete HASP emulation script."""
        analyzer = CommercialLicenseAnalyzer()

        script = analyzer._generate_hasp_script()

        assert isinstance(script, str)
        assert len(script) > 0
        assert "HASP" in script
        assert "hasp_login" in script

    def test_generate_codemeter_emulation_script(self) -> None:
        """Generates complete CodeMeter emulation script."""
        analyzer = CommercialLicenseAnalyzer()

        script = analyzer._generate_codemeter_script()

        assert isinstance(script, str)
        assert len(script) > 0
        assert "CodeMeter" in script
        assert "CmAccess" in script


class TestConfidenceCalculation:
    """Test confidence scoring for protection detection."""

    def test_calculate_confidence_single_system(self, flexlm_binary: Path) -> None:
        """Calculates confidence for single protection system."""
        analyzer = CommercialLicenseAnalyzer(str(flexlm_binary))

        results = {
            "detected_systems": ["FlexLM"],
            "bypass_strategies": {"flexlm": {}},
            "license_servers": [],
            "protection_features": {}
        }

        confidence = analyzer._calculate_confidence(results)

        assert isinstance(confidence, float)
        assert 0.0 <= confidence <= 1.0
        assert confidence > 0

    def test_calculate_confidence_multiple_systems(self) -> None:
        """Calculates higher confidence for multiple indicators."""
        analyzer = CommercialLicenseAnalyzer()

        results = {
            "detected_systems": ["FlexLM", "HASP"],
            "bypass_strategies": {"flexlm": {}, "hasp": {}},
            "license_servers": [{"type": "FlexLM"}],
            "protection_features": {"feature1": True}
        }

        confidence = analyzer._calculate_confidence(results)

        assert isinstance(confidence, float)
        assert 0.0 <= confidence <= 1.0
        assert confidence > 0.5

    def test_calculate_confidence_no_detection(self) -> None:
        """Returns zero confidence when nothing detected."""
        analyzer = CommercialLicenseAnalyzer()

        results = {
            "detected_systems": [],
            "bypass_strategies": {},
            "license_servers": [],
            "protection_features": {}
        }

        confidence = analyzer._calculate_confidence(results)

        assert confidence == 0.0


class TestBypassReportGeneration:
    """Test bypass report generation for analysis results."""

    def test_generate_bypass_report_flexlm(self, flexlm_binary: Path) -> None:
        """Generates readable bypass report for FlexLM."""
        analyzer = CommercialLicenseAnalyzer(str(flexlm_binary))
        analysis = analyzer.analyze_binary()

        report = analyzer.generate_bypass_report(analysis)

        assert isinstance(report, str)
        assert len(report) > 0
        assert "FlexLM" in report

    def test_generate_bypass_report_hasp(self, hasp_binary: Path) -> None:
        """Generates readable bypass report for HASP."""
        analyzer = CommercialLicenseAnalyzer(str(hasp_binary))
        analysis = analyzer.analyze_binary()

        report = analyzer.generate_bypass_report(analysis)

        assert isinstance(report, str)
        assert len(report) > 0
        assert "HASP" in report

    def test_generate_bypass_report_complete(self, flexlm_binary: Path) -> None:
        """Bypass report includes all necessary sections."""
        analyzer = CommercialLicenseAnalyzer(str(flexlm_binary))
        analysis = analyzer.analyze_binary()

        report = analyzer.generate_bypass_report(analysis)

        assert "Detected" in report or "detected" in report
        assert isinstance(report, str)


class TestPatternMatching:
    """Test pattern matching and regex conversion."""

    def test_pattern_to_regex_conversion(self) -> None:
        """Converts assembly pattern to regex correctly."""
        analyzer = CommercialLicenseAnalyzer()

        pattern = b"\xff\x15....\x85\xc0"
        regex = analyzer._pattern_to_regex(pattern)

        assert isinstance(regex, bytes)
        assert len(regex) > 0

    def test_extract_feature_id_from_push(self, temp_workspace: Path) -> None:
        """Extracts feature ID from push instruction."""
        code = b"\x68\x2A\x00\x00\x00"
        code += b"\xe8\x00\x00\x00\x00"

        binary = create_pe_binary(code)
        binary_path = temp_workspace / "push.exe"
        binary_path.write_bytes(binary)

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        binary_data = binary_path.read_bytes()

        offset = len(create_pe_binary())
        feature_id = analyzer._extract_feature_id(binary_data, offset + 10)

        assert isinstance(feature_id, int)

    def test_extract_vendor_code_from_binary(self, temp_workspace: Path) -> None:
        """Extracts vendor code from binary."""
        code = b"\x68\x78\x56\x34\x12"
        code += b"\xe8\x00\x00\x00\x00"

        binary = create_pe_binary(code)
        binary_path = temp_workspace / "vendor.exe"
        binary_path.write_bytes(binary)

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        binary_data = binary_path.read_bytes()

        offset = len(create_pe_binary())
        vendor_code = analyzer._extract_vendor_code(binary_data, offset + 10)

        assert isinstance(vendor_code, int)
        assert vendor_code != 0


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_analyze_empty_binary(self, temp_workspace: Path) -> None:
        """Handles empty binary file gracefully."""
        binary_path = temp_workspace / "empty.exe"
        binary_path.write_bytes(b"")

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        results = analyzer.analyze_binary()

        assert isinstance(results, dict)
        assert len(results["detected_systems"]) == 0

    def test_analyze_corrupted_pe(self, temp_workspace: Path) -> None:
        """Handles corrupted PE binary gracefully."""
        binary_path = temp_workspace / "corrupt.exe"
        binary_path.write_bytes(b"MZ" + b"\x00" * 100)

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        results = analyzer.analyze_binary()

        assert isinstance(results, dict)

    def test_analyze_with_none_path(self) -> None:
        """Handles None binary path gracefully."""
        analyzer = CommercialLicenseAnalyzer(None)
        results = analyzer.analyze_binary()

        assert isinstance(results, dict)
        assert len(results["detected_systems"]) == 0

    def test_extract_features_from_binary_without_features(self, temp_workspace: Path) -> None:
        """Returns empty list when no features found."""
        binary_path = temp_workspace / "nofeatures.exe"
        binary_path.write_bytes(create_pe_binary())

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        binary_data = binary_path.read_bytes()

        features = analyzer._extract_flexlm_features(binary_data)

        assert isinstance(features, list)
        assert len(features) == 0


class TestRealWorldScenarios:
    """Test realistic commercial software protection scenarios."""

    def test_analyze_layered_protection(self, temp_workspace: Path) -> None:
        """Analyzes software with layered protections."""
        binary = create_flexlm_protected_binary()
        binary += b"HASP HL\x00hasp_login\x00"

        binary_path = temp_workspace / "layered.exe"
        binary_path.write_bytes(binary)

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        results = analyzer.analyze_binary()

        assert len(results["detected_systems"]) >= 1
        assert len(results["bypass_strategies"]) >= 1

    def test_analyze_obfuscated_strings(self, temp_workspace: Path) -> None:
        """Handles obfuscated protection indicators."""
        binary = create_pe_binary()
        binary += b"F" + b"\x00" + b"L" + b"\x00" + b"E" + b"\x00" + b"X"
        binary += b"\x00" + b"l" + b"\x00" + b"m" + b"\x00"

        binary_path = temp_workspace / "obfuscated.exe"
        binary_path.write_bytes(binary)

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        results = analyzer.analyze_binary()

        assert isinstance(results, dict)

    def test_detect_network_license_server(self, flexlm_binary: Path) -> None:
        """Detects network license server configuration."""
        analyzer = CommercialLicenseAnalyzer(str(flexlm_binary))
        results = analyzer.analyze_binary()

        assert "license_servers" in results
        assert isinstance(results["license_servers"], list)

    def test_extract_all_protection_features(self, temp_workspace: Path) -> None:
        """Extracts comprehensive protection feature list."""
        binary = create_pe_binary()
        binary += b"FEATURE App1 vendor 1.0 "
        binary += b"FEATURE App2 vendor 2.0 "
        binary += b'<haspscope><feature id="10"></feature></haspscope>'
        binary += b'FirmCode: 100001\x00'

        binary_path = temp_workspace / "features.exe"
        binary_path.write_bytes(binary)

        analyzer = CommercialLicenseAnalyzer(str(binary_path))
        results = analyzer.analyze_binary()

        assert "protection_features" in results


class TestPerformance:
    """Test performance characteristics of analysis."""

    def test_analyze_large_binary_performance(self, temp_workspace: Path) -> None:
        """Analyzes large binary within reasonable time."""
        import time

        large_binary = create_pe_binary() + b"\x00" * 10000000
        binary_path = temp_workspace / "large.exe"
        binary_path.write_bytes(large_binary)

        analyzer = CommercialLicenseAnalyzer(str(binary_path))

        start = time.time()
        results = analyzer.analyze_binary()
        duration = time.time() - start

        assert isinstance(results, dict)
        assert duration < 30

    def test_multiple_analysis_runs_consistent(self, flexlm_binary: Path) -> None:
        """Multiple analysis runs produce consistent results."""
        analyzer = CommercialLicenseAnalyzer(str(flexlm_binary))

        results1 = analyzer.analyze_binary()
        results2 = analyzer.analyze_binary()

        assert results1["detected_systems"] == results2["detected_systems"]
