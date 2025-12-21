"""Production tests for StarForce analyzer - NO MOCKS.

Tests validate real StarForce protection detection capabilities against actual
Windows binaries and custom-crafted test binaries with embedded StarForce signatures.
"""

from __future__ import annotations

import os
import struct
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.analysis.starforce_analyzer import (
    AntiDebugTechnique,
    IOCTLCommand,
    LicenseValidationFlow,
    StarForceAnalysis,
    StarForceAnalyzer,
)

if TYPE_CHECKING:
    from typing import Any

SYSTEM32 = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32"


class TestBinaryFactory:
    """Factory for creating test binaries with StarForce signatures."""

    @staticmethod
    def create_dos_stub() -> bytes:
        """Create minimal DOS stub."""
        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)
        return bytes(dos_header)

    @staticmethod
    def create_pe_header(num_sections: int = 1, is_driver: bool = False) -> bytes:
        """Create minimal PE header."""
        pe_signature = b"PE\x00\x00"

        machine_type = 0x014C
        characteristics = 0x2102 if is_driver else 0x0102

        coff_header = struct.pack(
            "<HHIIIHH",
            machine_type,
            num_sections,
            0,
            0,
            0,
            0xE0,
            characteristics,
        )

        optional_header = bytearray(224)
        optional_header[:2] = struct.pack("<H", 0x010B)
        optional_header[16:20] = struct.pack("<I", 0x1000)
        optional_header[20:24] = struct.pack("<I", 0x400000)

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
    def create_starforce_v5_driver(cls) -> bytes:
        """Create test driver binary with StarForce v5 signatures."""
        dos_stub = cls.create_dos_stub()
        pe_header = cls.create_pe_header(num_sections=3, is_driver=True)

        text_section = cls.create_section_header(b".text", 0x2000, 0x1000, 0x2000, 0x400)
        data_section = cls.create_section_header(b".data", 0x1000, 0x3000, 0x1000, 0x2400)
        init_section = cls.create_section_header(b"INIT", 0x1000, 0x4000, 0x1000, 0x3400)

        text_data = bytearray(0x2000)

        text_data[:10] = b"StarForce"
        text_data[20:32] = b"SF_DRIVER_V5"
        text_data[50:57] = b"5.3.0.0"

        text_data[100:104] = struct.pack("<I", 0x80002000)
        text_data[110:114] = struct.pack("<I", 0x80002004)
        text_data[120:124] = struct.pack("<I", 0x80002008)
        text_data[130:134] = struct.pack("<I", 0x8000200C)
        text_data[140:144] = struct.pack("<I", 0x80002010)
        text_data[150:154] = struct.pack("<I", 0x80002014)
        text_data[160:164] = struct.pack("<I", 0x80002018)
        text_data[170:174] = struct.pack("<I", 0x8000201C)
        text_data[180:184] = struct.pack("<I", 0x80002020)
        text_data[190:194] = struct.pack("<I", 0x80002024)

        text_data[250:256] = b"\x64\xa1\x1c\x00\x00\x00"
        text_data[300:305] = b"\xa1\x34\x00\x00\x00"
        text_data[350:358] = b"\x0f\x20\xc0\xa9\x00\x00\x01\x00"

        text_data[400:402] = b"\x0f\x31"
        text_data[450:453] = b"\xf0\x0f\xc1"

        text_data[500:502] = b"\xcd\x2d"
        text_data[550:552] = b"\xcc\xcc"

        text_data[600:603] = b"\x0f\x21\xc0"
        text_data[650:653] = b"\x0f\x21\xc1"
        text_data[700:703] = b"\x0f\x21\xc2"
        text_data[750:753] = b"\x0f\x21\xc3"

        text_data[800:806] = b"VMware"
        text_data[850:858] = b"\x56\x4d\x58\x68"
        text_data[900:910] = b"VBoxGuest"
        text_data[950:954] = b"VBOX"
        text_data[1000:1004] = b"QEMU"
        text_data[1050:1057] = b"Hyper-V"

        text_data[1100:1102] = b"\x0f\xa2"
        text_data[1150:1152] = b"\x0f\x01"

        text_data[1200:1245] = b"\\Registry\\Machine\\Hardware\\Description\\System"

        text_data[1300:1305] = b"SCSI"
        text_data[1350:1360] = b"\\\\.\\Scsi"
        text_data[1400:1408] = b"READ_TOC"
        text_data[1450:1451] = b"\x43"
        text_data[1500:1513] = b"READ_CAPACITY"
        text_data[1550:1551] = b"\xa8"
        text_data[1600:1601] = b"\xbe"
        text_data[1650:1651] = b"\x28"
        text_data[1700:1717] = b"GetDriveGeometry"
        text_data[1750:1762] = b"IOCTL_STORAGE"
        text_data[1800:1810] = b"subchannel"
        text_data[1850:1851] = b"\x42"

        text_data[1900:1912] = b"NtCreateFile"
        text_data[1920:1930] = b"NtOpenFile"
        text_data[1940:1950] = b"NtReadFile"
        text_data[1960:1971] = b"NtWriteFile"
        text_data[1980:2001] = b"NtDeviceIoControlFile"
        text_data[2020:2046] = b"NtQuerySystemInformation"
        text_data[2060:2084] = b"NtSetSystemInformation"
        text_data[2100:2128] = b"NtQueryInformationProcess"
        text_data[2140:2160] = b"ObRegisterCallbacks"
        text_data[2180:2213] = b"PsSetCreateProcessNotifyRoutine"
        text_data[2230:2260] = b"PsSetLoadImageNotifyRoutine"
        text_data[2280:2294] = b"IoCreateDevice"
        text_data[2310:2329] = b"IofCompleteRequest"
        text_data[2350:2367] = b"KeInsertQueueApc"

        text_data[2400:2407] = b"License"
        text_data[2450:2456] = b"Serial"
        text_data[2500:2510] = b"Activation"
        text_data[2550:2562] = b"Registration"
        text_data[2600:2608] = b"Validate"
        text_data[2650:2655] = b"Check"
        text_data[2700:2706] = b"Verify"

        text_data[2750:2753] = b"RSA"
        text_data[2800:2803] = b"AES"
        text_data[2850:2853] = b"SHA"
        text_data[2900:2903] = b"MD5"
        text_data[2950:2955] = b"CRC32"
        text_data[3000:3007] = b"Encrypt"
        text_data[3050:3057] = b"Decrypt"
        text_data[3100:3104] = b"Hash"

        text_data[3200:3235] = b"\\Registry\\Machine\\SOFTWARE"

        text_data[3300:3310] = b"\\\\.\\CdRom"

        text_data[3400:3404] = b"http"

        text_data[3500:3508] = b"\x67\x45\x23\x01\xef\xcd\xab\x89"
        text_data[3550:3558] = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        text_data[3600:3604] = b"\x6a\x09\xe6\x67"
        text_data[3650:3654] = struct.pack("<I", 0x09000000)
        text_data[3700:3704] = struct.pack("<I", 0x10000000)
        text_data[3750:3754] = struct.pack("<I", 0x18000000)
        text_data[3800:3804] = struct.pack("<I", 0x20000000)

        text_data[3900:3964] = bytes(range(64))

        text_data[4000:4002] = b"\xc7\x87"
        text_data[4002:4004] = struct.pack("<H", 0x38)
        text_data[4004:4008] = struct.pack("<I", 0x401000)

        data_data = bytearray(0x1000)
        data_data[:20] = b"StarForce_Data\x00"

        init_data = bytearray(0x1000)
        init_data[:20] = b"StarForce_Init\x00"

        binary = dos_stub + pe_header + text_section + data_section + init_section
        binary = binary.ljust(0x400, b"\x00")
        binary += bytes(text_data)
        binary = binary.ljust(0x2400, b"\x00")
        binary += bytes(data_data)
        binary = binary.ljust(0x3400, b"\x00")
        binary += bytes(init_data)

        return binary

    @classmethod
    def create_starforce_v4_driver(cls) -> bytes:
        """Create test driver binary with StarForce v4 signatures."""
        dos_stub = cls.create_dos_stub()
        pe_header = cls.create_pe_header(num_sections=2, is_driver=True)

        text_section = cls.create_section_header(b".text", 0x1000, 0x1000, 0x1000, 0x400)
        data_section = cls.create_section_header(b".data", 0x1000, 0x2000, 0x1000, 0x1400)

        text_data = bytearray(0x1000)
        text_data[:10] = b"StarForce"
        text_data[20:32] = b"SF_DRIVER_V4"
        text_data[50:57] = b"4.7.2.0"

        text_data[100:104] = struct.pack("<I", 0x80002000)
        text_data[110:114] = struct.pack("<I", 0x80002004)
        text_data[120:124] = struct.pack("<I", 0x80002008)

        text_data[200:206] = b"\x64\xa1\x1c\x00\x00\x00"
        text_data[250:252] = b"\x0f\x31"
        text_data[300:302] = b"\xcd\x2d"

        text_data[400:406] = b"VMware"
        text_data[450:460] = b"VBoxGuest"

        text_data[500:505] = b"SCSI"
        text_data[550:558] = b"READ_TOC"

        text_data[600:612] = b"NtCreateFile"
        text_data[650:660] = b"NtReadFile"

        text_data[700:707] = b"License"
        text_data[750:753] = b"RSA"
        text_data[800:803] = b"AES"

        data_data = bytearray(0x1000)
        data_data[:20] = b"StarForce_V4_Data\x00"

        binary = dos_stub + pe_header + text_section + data_section
        binary = binary.ljust(0x400, b"\x00")
        binary += bytes(text_data)
        binary = binary.ljust(0x1400, b"\x00")
        binary += bytes(data_data)

        return binary

    @classmethod
    def create_starforce_v3_driver(cls) -> bytes:
        """Create test driver binary with StarForce v3 signatures."""
        dos_stub = cls.create_dos_stub()
        pe_header = cls.create_pe_header(num_sections=1, is_driver=True)

        text_section = cls.create_section_header(b".text", 0x1000, 0x1000, 0x1000, 0x400)

        text_data = bytearray(0x1000)
        text_data[:10] = b"StarForce"
        text_data[20:32] = b"SF_DRIVER_V3"
        text_data[50:57] = b"3.9.1.0"

        text_data[100:104] = struct.pack("<I", 0x80002000)
        text_data[110:114] = struct.pack("<I", 0x80002004)

        text_data[200:202] = b"\x0f\x31"
        text_data[250:252] = b"\xcd\x2d"

        text_data[300:305] = b"SCSI"

        text_data[400:412] = b"NtCreateFile"

        text_data[500:507] = b"License"

        binary = dos_stub + pe_header + text_section
        binary = binary.ljust(0x400, b"\x00")
        binary += bytes(text_data)

        return binary

    @classmethod
    def create_partial_starforce_driver(cls) -> bytes:
        """Create driver with partial StarForce signatures."""
        dos_stub = cls.create_dos_stub()
        pe_header = cls.create_pe_header(num_sections=1, is_driver=True)

        text_section = cls.create_section_header(b".text", 0x1000, 0x1000, 0x1000, 0x400)

        text_data = bytearray(0x1000)
        text_data[:10] = b"StarForce"
        text_data[100:104] = struct.pack("<I", 0x80002000)
        text_data[200:202] = b"\x0f\x31"

        binary = dos_stub + pe_header + text_section
        binary = binary.ljust(0x400, b"\x00")
        binary += bytes(text_data)

        return binary

    @classmethod
    def create_corrupted_starforce_driver(cls) -> bytes:
        """Create corrupted StarForce driver binary."""
        dos_stub = cls.create_dos_stub()

        text_data = bytearray(0x1000)
        text_data[:10] = b"StarForce"
        text_data[20:32] = b"CORRUPTED!!!"

        return dos_stub + bytes(text_data)

    @classmethod
    def create_custom_ioctl_driver(cls) -> bytes:
        """Create driver with custom IOCTL codes."""
        dos_stub = cls.create_dos_stub()
        pe_header = cls.create_pe_header(num_sections=1, is_driver=True)

        text_section = cls.create_section_header(b".text", 0x1000, 0x1000, 0x1000, 0x400)

        text_data = bytearray(0x1000)
        text_data[:10] = b"StarForce"

        text_data[100:102] = b"\x81\x7d"
        text_data[102:106] = struct.pack("<I", 0x80003000)

        text_data[150:152] = b"\x81\x7d"
        text_data[152:156] = struct.pack("<I", 0x80004000)

        text_data[200:202] = b"\x81\x7d"
        text_data[202:206] = struct.pack("<I", 0x80005000)

        binary = dos_stub + pe_header + text_section
        binary = binary.ljust(0x400, b"\x00")
        binary += bytes(text_data)

        return binary

    @classmethod
    def create_multi_vm_detection_driver(cls) -> bytes:
        """Create driver with multiple VM detection methods."""
        dos_stub = cls.create_dos_stub()
        pe_header = cls.create_pe_header(num_sections=1, is_driver=True)

        text_section = cls.create_section_header(b".text", 0x2000, 0x1000, 0x2000, 0x400)

        text_data = bytearray(0x2000)
        text_data[:10] = b"StarForce"

        text_data[100:106] = b"VMware"
        text_data[200:208] = b"\x56\x4d\x58\x68"
        text_data[300:307] = b"\x0f\x3f\x07\x0b"

        text_data[400:410] = b"VBoxGuest"
        text_data[500:504] = b"VBOX"
        text_data[600:608] = b"\x56\x42\x4f\x58"

        text_data[700:704] = b"QEMU"
        text_data[800:808] = b"\x51\x45\x4d\x55"

        text_data[900:907] = b"Hyper-V"
        text_data[1000:1028] = b"\x4d\x69\x63\x72\x6f\x73\x6f\x66\x74\x20\x48\x76"

        text_data[1100:1102] = b"\x0f\xa2"
        text_data[1200:1202] = b"\x0f\x01"
        text_data[1300:1345] = b"\\Registry\\Machine\\Hardware\\Description\\System"

        binary = dos_stub + pe_header + text_section
        binary = binary.ljust(0x400, b"\x00")
        binary += bytes(text_data)

        return binary


@pytest.fixture
def analyzer() -> StarForceAnalyzer:
    """Create StarForce analyzer instance."""
    return StarForceAnalyzer()


@pytest.fixture
def starforce_v5_driver(tmp_path: Path) -> Path:
    """Create temporary StarForce v5 driver binary."""
    binary_path = tmp_path / "starforce_v5.sys"
    binary_path.write_bytes(TestBinaryFactory.create_starforce_v5_driver())
    return binary_path


@pytest.fixture
def starforce_v4_driver(tmp_path: Path) -> Path:
    """Create temporary StarForce v4 driver binary."""
    binary_path = tmp_path / "starforce_v4.sys"
    binary_path.write_bytes(TestBinaryFactory.create_starforce_v4_driver())
    return binary_path


@pytest.fixture
def starforce_v3_driver(tmp_path: Path) -> Path:
    """Create temporary StarForce v3 driver binary."""
    binary_path = tmp_path / "starforce_v3.sys"
    binary_path.write_bytes(TestBinaryFactory.create_starforce_v3_driver())
    return binary_path


@pytest.fixture
def partial_starforce_driver(tmp_path: Path) -> Path:
    """Create temporary partial StarForce driver binary."""
    binary_path = tmp_path / "partial_starforce.sys"
    binary_path.write_bytes(TestBinaryFactory.create_partial_starforce_driver())
    return binary_path


@pytest.fixture
def corrupted_driver(tmp_path: Path) -> Path:
    """Create temporary corrupted driver binary."""
    binary_path = tmp_path / "corrupted.sys"
    binary_path.write_bytes(TestBinaryFactory.create_corrupted_starforce_driver())
    return binary_path


@pytest.fixture
def custom_ioctl_driver(tmp_path: Path) -> Path:
    """Create temporary custom IOCTL driver binary."""
    binary_path = tmp_path / "custom_ioctl.sys"
    binary_path.write_bytes(TestBinaryFactory.create_custom_ioctl_driver())
    return binary_path


@pytest.fixture
def multi_vm_driver(tmp_path: Path) -> Path:
    """Create temporary multi-VM detection driver binary."""
    binary_path = tmp_path / "multi_vm.sys"
    binary_path.write_bytes(TestBinaryFactory.create_multi_vm_detection_driver())
    return binary_path


class TestStarForceAnalyzerInitialization:
    """Test StarForce analyzer initialization."""

    def test_analyzer_initialization(self, analyzer: StarForceAnalyzer) -> None:
        """Analyzer initializes with proper configuration."""
        assert analyzer is not None
        assert hasattr(analyzer, "KNOWN_IOCTLS")
        assert hasattr(analyzer, "ANTI_DEBUG_PATTERNS")
        assert hasattr(analyzer, "VM_DETECTION_PATTERNS")
        assert len(analyzer.KNOWN_IOCTLS) >= 10

    def test_ioctl_device_types_defined(self, analyzer: StarForceAnalyzer) -> None:
        """Analyzer has StarForce device types defined."""
        assert 0x8000 in analyzer.IOCTL_DEVICE_TYPES
        assert analyzer.IOCTL_DEVICE_TYPES[0x8000] == "STARFORCE_DEVICE"
        assert 0x8001 in analyzer.IOCTL_DEVICE_TYPES
        assert 0x8002 in analyzer.IOCTL_DEVICE_TYPES
        assert 0x8003 in analyzer.IOCTL_DEVICE_TYPES

    def test_known_ioctls_structure(self, analyzer: StarForceAnalyzer) -> None:
        """Known IOCTLs have proper structure."""
        for code, (name, purpose) in analyzer.KNOWN_IOCTLS.items():
            assert isinstance(code, int)
            assert isinstance(name, str)
            assert isinstance(purpose, str)
            assert code >= 0x80000000
            assert len(name) > 0
            assert len(purpose) > 0

    def test_anti_debug_patterns_defined(self, analyzer: StarForceAnalyzer) -> None:
        """Anti-debugging patterns are properly defined."""
        assert "kernel_debugger_check" in analyzer.ANTI_DEBUG_PATTERNS
        assert "timing_check" in analyzer.ANTI_DEBUG_PATTERNS
        assert "int2d_detection" in analyzer.ANTI_DEBUG_PATTERNS
        assert "hardware_breakpoint" in analyzer.ANTI_DEBUG_PATTERNS

    def test_vm_detection_patterns_defined(self, analyzer: StarForceAnalyzer) -> None:
        """VM detection patterns are properly defined."""
        assert "vmware" in analyzer.VM_DETECTION_PATTERNS
        assert "virtualbox" in analyzer.VM_DETECTION_PATTERNS
        assert "qemu" in analyzer.VM_DETECTION_PATTERNS
        assert "hyperv" in analyzer.VM_DETECTION_PATTERNS


class TestStarForceDriverVersionDetection:
    """Test StarForce driver version detection."""

    def test_detect_version_5_driver(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """Detects StarForce v5 driver version or returns Unknown."""
        version = analyzer._get_driver_version(starforce_v5_driver)
        assert isinstance(version, str)
        assert len(version) > 0

    def test_detect_version_4_driver(self, analyzer: StarForceAnalyzer, starforce_v4_driver: Path) -> None:
        """Detects StarForce v4 driver version or returns Unknown."""
        version = analyzer._get_driver_version(starforce_v4_driver)
        assert isinstance(version, str)
        assert len(version) > 0

    def test_detect_version_3_driver(self, analyzer: StarForceAnalyzer, starforce_v3_driver: Path) -> None:
        """Detects StarForce v3 driver version or returns Unknown."""
        version = analyzer._get_driver_version(starforce_v3_driver)
        assert isinstance(version, str)
        assert len(version) > 0

    def test_version_detection_nonexistent_file(self, analyzer: StarForceAnalyzer, tmp_path: Path) -> None:
        """Returns Unknown for nonexistent file."""
        nonexistent = tmp_path / "nonexistent.sys"
        version = analyzer._get_driver_version(nonexistent)
        assert version == "Unknown"

    def test_version_detection_corrupted_file(self, analyzer: StarForceAnalyzer, corrupted_driver: Path) -> None:
        """Handles corrupted file gracefully."""
        version = analyzer._get_driver_version(corrupted_driver)
        assert isinstance(version, str)

    def test_version_detection_real_binary(self, analyzer: StarForceAnalyzer) -> None:
        """Extracts version from real Windows binary."""
        if not SYSTEM32.exists():
            pytest.skip("System32 not accessible")

        kernel32 = SYSTEM32 / "kernel32.dll"
        if not kernel32.exists():
            pytest.skip("kernel32.dll not found")

        version = analyzer._get_driver_version(kernel32)
        assert isinstance(version, str)
        assert len(version) > 0


class TestStarForceIOCTLDetection:
    """Test StarForce IOCTL command detection."""

    def test_detect_known_ioctls_v5(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """Detects all known IOCTLs in v5 driver."""
        ioctls = analyzer._analyze_ioctls(starforce_v5_driver)
        assert len(ioctls) >= 10

        ioctl_codes = {ioctl.code for ioctl in ioctls}
        assert 0x80002000 in ioctl_codes
        assert 0x80002004 in ioctl_codes
        assert 0x80002008 in ioctl_codes
        assert 0x8000200C in ioctl_codes
        assert 0x80002010 in ioctl_codes
        assert 0x80002014 in ioctl_codes
        assert 0x80002018 in ioctl_codes
        assert 0x8000201C in ioctl_codes
        assert 0x80002020 in ioctl_codes
        assert 0x80002024 in ioctl_codes

    def test_ioctl_structure_validation(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """IOCTL structures are properly parsed."""
        ioctls = analyzer._analyze_ioctls(starforce_v5_driver)
        for ioctl in ioctls:
            assert isinstance(ioctl, IOCTLCommand)
            assert isinstance(ioctl.code, int)
            assert isinstance(ioctl.device_type, int)
            assert isinstance(ioctl.function, int)
            assert isinstance(ioctl.method, int)
            assert isinstance(ioctl.access, int)
            assert isinstance(ioctl.name, str)
            assert isinstance(ioctl.purpose, str)
            assert len(ioctl.name) > 0
            assert len(ioctl.purpose) > 0

    def test_ioctl_names_correct(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """IOCTL names match expected values."""
        ioctls = analyzer._analyze_ioctls(starforce_v5_driver)
        ioctl_map = {ioctl.code: ioctl.name for ioctl in ioctls}

        assert ioctl_map.get(0x80002000) == "SF_IOCTL_GET_VERSION"
        assert ioctl_map.get(0x80002004) == "SF_IOCTL_CHECK_DISC"
        assert ioctl_map.get(0x80002008) == "SF_IOCTL_VALIDATE_LICENSE"
        assert ioctl_map.get(0x8000200C) == "SF_IOCTL_GET_HWID"
        assert ioctl_map.get(0x80002010) == "SF_IOCTL_DECRYPT_DATA"
        assert ioctl_map.get(0x80002014) == "SF_IOCTL_CHECK_DEBUGGER"
        assert ioctl_map.get(0x80002018) == "SF_IOCTL_VM_DETECT"
        assert ioctl_map.get(0x8000201C) == "SF_IOCTL_READ_SECTOR"
        assert ioctl_map.get(0x80002020) == "SF_IOCTL_VERIFY_SIGNATURE"
        assert ioctl_map.get(0x80002024) == "SF_IOCTL_GET_CHALLENGE"

    def test_detect_custom_ioctls(self, analyzer: StarForceAnalyzer, custom_ioctl_driver: Path) -> None:
        """Detects custom IOCTL codes."""
        ioctls = analyzer._analyze_ioctls(custom_ioctl_driver)
        assert len(ioctls) >= 3

        custom_codes = {ioctl.code for ioctl in ioctls if "CUSTOM" in ioctl.name}
        assert len(custom_codes) >= 3

    def test_custom_ioctl_naming(self, analyzer: StarForceAnalyzer, custom_ioctl_driver: Path) -> None:
        """Custom IOCTLs have proper naming convention."""
        ioctls = analyzer._analyze_ioctls(custom_ioctl_driver)
        for ioctl in ioctls:
            if "CUSTOM" in ioctl.name:
                assert ioctl.name.startswith("SF_IOCTL_CUSTOM_")
                assert "purpose unknown" in ioctl.purpose.lower()

    def test_ioctl_detection_empty_file(self, analyzer: StarForceAnalyzer, tmp_path: Path) -> None:
        """Handles empty file gracefully."""
        empty_file = tmp_path / "empty.sys"
        empty_file.write_bytes(b"")
        ioctls = analyzer._analyze_ioctls(empty_file)
        assert isinstance(ioctls, list)
        assert len(ioctls) == 0


class TestStarForceAntiDebuggingDetection:
    """Test StarForce anti-debugging technique detection."""

    def test_detect_kernel_debugger_checks(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """Detects kernel debugger checks."""
        techniques = analyzer._detect_anti_debug(starforce_v5_driver)
        kernel_checks = [t for t in techniques if t.technique == "kernel_debugger_check"]
        assert len(kernel_checks) >= 2

    def test_detect_timing_checks(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """Detects timing-based anti-debugging."""
        techniques = analyzer._detect_anti_debug(starforce_v5_driver)
        timing_checks = [t for t in techniques if t.technique == "timing_check"]
        assert len(timing_checks) >= 2

    def test_detect_int2d_detection(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """Detects INT 2D exception detection."""
        techniques = analyzer._detect_anti_debug(starforce_v5_driver)
        int2d_checks = [t for t in techniques if t.technique == "int2d_detection"]
        assert len(int2d_checks) >= 2

    def test_detect_hardware_breakpoints(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """Detects hardware breakpoint checks."""
        techniques = analyzer._detect_anti_debug(starforce_v5_driver)
        hw_bp_checks = [t for t in techniques if t.technique == "hardware_breakpoint"]
        assert len(hw_bp_checks) >= 4

    def test_anti_debug_structure_validation(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """Anti-debug technique structures are valid."""
        techniques = analyzer._detect_anti_debug(starforce_v5_driver)
        for technique in techniques:
            assert isinstance(technique, AntiDebugTechnique)
            assert isinstance(technique.technique, str)
            assert isinstance(technique.address, int)
            assert isinstance(technique.description, str)
            assert isinstance(technique.bypass_method, str)
            assert len(technique.technique) > 0
            assert technique.address >= 0
            assert len(technique.description) > 0
            assert len(technique.bypass_method) > 0

    def test_anti_debug_bypass_recommendations(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """Anti-debug techniques include bypass recommendations."""
        techniques = analyzer._detect_anti_debug(starforce_v5_driver)
        for technique in techniques:
            assert len(technique.bypass_method) > 10
            assert any(
                keyword in technique.bypass_method.lower()
                for keyword in ["patch", "hook", "clear", "normalize", "flag", "register"]
            )

    def test_anti_debug_multiple_versions(
        self,
        analyzer: StarForceAnalyzer,
        starforce_v5_driver: Path,
        starforce_v4_driver: Path,
        starforce_v3_driver: Path,
    ) -> None:
        """Detects anti-debug in multiple StarForce versions."""
        v5_techniques = analyzer._detect_anti_debug(starforce_v5_driver)
        v4_techniques = analyzer._detect_anti_debug(starforce_v4_driver)
        v3_techniques = analyzer._detect_anti_debug(starforce_v3_driver)

        assert len(v5_techniques) > len(v4_techniques)
        assert len(v4_techniques) > len(v3_techniques)
        assert len(v3_techniques) >= 2


class TestStarForceVMDetection:
    """Test StarForce virtual machine detection."""

    def test_detect_vmware_detection(self, analyzer: StarForceAnalyzer, multi_vm_driver: Path) -> None:
        """Detects VMware detection mechanisms."""
        vm_methods = analyzer._detect_vm_checks(multi_vm_driver)
        vmware_methods = [m for m in vm_methods if "vmware" in m.lower()]
        assert vmware_methods

    def test_detect_virtualbox_detection(self, analyzer: StarForceAnalyzer, multi_vm_driver: Path) -> None:
        """Detects VirtualBox detection mechanisms."""
        vm_methods = analyzer._detect_vm_checks(multi_vm_driver)
        vbox_methods = [m for m in vm_methods if "virtualbox" in m.lower()]
        assert vbox_methods

    def test_detect_qemu_detection(self, analyzer: StarForceAnalyzer, multi_vm_driver: Path) -> None:
        """Detects QEMU detection mechanisms."""
        vm_methods = analyzer._detect_vm_checks(multi_vm_driver)
        qemu_methods = [m for m in vm_methods if "qemu" in m.lower()]
        assert qemu_methods

    def test_detect_hyperv_detection(self, analyzer: StarForceAnalyzer, multi_vm_driver: Path) -> None:
        """Detects Hyper-V detection mechanisms."""
        vm_methods = analyzer._detect_vm_checks(multi_vm_driver)
        hyperv_methods = [m for m in vm_methods if "hyperv" in m.lower() or "hyper-v" in m.lower()]
        assert hyperv_methods

    def test_detect_cpuid_vm_detection(self, analyzer: StarForceAnalyzer, multi_vm_driver: Path) -> None:
        """Detects CPUID-based VM detection."""
        vm_methods = analyzer._detect_vm_checks(multi_vm_driver)
        cpuid_methods = [m for m in vm_methods if "cpuid" in m.lower()]
        assert cpuid_methods

    def test_detect_sidt_sgdt_detection(self, analyzer: StarForceAnalyzer, multi_vm_driver: Path) -> None:
        """Detects SIDT/SGDT VM detection."""
        vm_methods = analyzer._detect_vm_checks(multi_vm_driver)
        sidt_methods = [m for m in vm_methods if "sidt" in m.lower() or "sgdt" in m.lower()]
        assert sidt_methods

    def test_detect_registry_vm_detection(self, analyzer: StarForceAnalyzer, multi_vm_driver: Path) -> None:
        """Detects registry-based VM detection."""
        vm_methods = analyzer._detect_vm_checks(multi_vm_driver)
        registry_methods = [m for m in vm_methods if "registry" in m.lower()]
        assert registry_methods

    def test_vm_detection_comprehensive(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """Comprehensive VM detection in v5 driver."""
        vm_methods = analyzer._detect_vm_checks(starforce_v5_driver)
        assert len(vm_methods) >= 7

    def test_vm_detection_empty_for_v3(self, analyzer: StarForceAnalyzer, starforce_v3_driver: Path) -> None:
        """Older v3 driver has minimal VM detection."""
        vm_methods = analyzer._detect_vm_checks(starforce_v3_driver)
        assert len(vm_methods) == 0


class TestStarForceDiscAuthentication:
    """Test StarForce disc authentication mechanism detection."""

    def test_detect_scsi_authentication(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """Detects SCSI command-based authentication."""
        mechanisms = analyzer._analyze_disc_auth(starforce_v5_driver)
        scsi_mechs = [m for m in mechanisms if "scsi" in m.lower()]
        assert scsi_mechs

    def test_detect_toc_verification(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """Detects CD-ROM TOC verification."""
        mechanisms = analyzer._analyze_disc_auth(starforce_v5_driver)
        toc_mechs = [m for m in mechanisms if "toc" in m.lower()]
        assert toc_mechs

    def test_detect_capacity_validation(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """Detects disc capacity validation."""
        mechanisms = analyzer._analyze_disc_auth(starforce_v5_driver)
        capacity_mechs = [m for m in mechanisms if "capacity" in m.lower()]
        assert capacity_mechs

    def test_detect_raw_sector_reading(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """Detects raw sector reading for fingerprinting."""
        mechanisms = analyzer._analyze_disc_auth(starforce_v5_driver)
        sector_mechs = [m for m in mechanisms if "sector" in m.lower() or "fingerprint" in m.lower()]
        assert sector_mechs

    def test_detect_geometry_verification(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """Detects drive geometry verification."""
        mechanisms = analyzer._analyze_disc_auth(starforce_v5_driver)
        geometry_mechs = [m for m in mechanisms if "geometry" in m.lower()]
        assert geometry_mechs

    def test_detect_subchannel_analysis(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """Detects subchannel data analysis."""
        mechanisms = analyzer._analyze_disc_auth(starforce_v5_driver)
        subchannel_mechs = [m for m in mechanisms if "subchannel" in m.lower()]
        assert subchannel_mechs

    def test_disc_auth_comprehensive_v5(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """v5 driver has comprehensive disc authentication."""
        mechanisms = analyzer._analyze_disc_auth(starforce_v5_driver)
        assert len(mechanisms) >= 6

    def test_disc_auth_reduced_v3(self, analyzer: StarForceAnalyzer, starforce_v3_driver: Path) -> None:
        """v3 driver has reduced disc authentication."""
        mechanisms = analyzer._analyze_disc_auth(starforce_v3_driver)
        assert len(mechanisms) >= 1
        assert len(mechanisms) < 6


class TestStarForceKernelHooks:
    """Test StarForce kernel hook detection."""

    def test_detect_file_operation_hooks(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """Detects file operation hooks."""
        hooks = analyzer._detect_kernel_hooks(starforce_v5_driver)
        file_hooks = [h for h in hooks if any(fn in h[0] for fn in ["CreateFile", "OpenFile", "ReadFile", "WriteFile"])]
        assert len(file_hooks) >= 4

    def test_detect_ioctl_hooks(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """Detects DeviceIoControl hooks."""
        hooks = analyzer._detect_kernel_hooks(starforce_v5_driver)
        ioctl_hooks = [h for h in hooks if "DeviceIoControl" in h[0]]
        assert ioctl_hooks

    def test_detect_query_hooks(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """Detects system information query hooks."""
        hooks = analyzer._detect_kernel_hooks(starforce_v5_driver)
        query_hooks = [h for h in hooks if "Query" in h[0]]
        assert len(query_hooks) >= 2

    def test_detect_callback_registration(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """Detects callback registration hooks."""
        hooks = analyzer._detect_kernel_hooks(starforce_v5_driver)
        callback_hooks = [h for h in hooks if "Callback" in h[0] or "Notify" in h[0]]
        assert len(callback_hooks) >= 3

    def test_kernel_hooks_structure(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """Kernel hooks have proper structure."""
        hooks = analyzer._detect_kernel_hooks(starforce_v5_driver)
        for func_name, offset in hooks:
            assert isinstance(func_name, str)
            assert isinstance(offset, int)
            assert len(func_name) > 0
            assert offset >= 0

    def test_kernel_hooks_comprehensive_v5(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """v5 driver has comprehensive kernel hooks."""
        hooks = analyzer._detect_kernel_hooks(starforce_v5_driver)
        assert len(hooks) >= 14


class TestStarForceLicenseValidation:
    """Test StarForce license validation flow detection."""

    def test_license_validation_flow_exists(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """License validation flow is detected."""
        license_flow = analyzer._analyze_license_validation(starforce_v5_driver)
        assert license_flow is not None
        assert isinstance(license_flow, LicenseValidationFlow)

    def test_validation_functions_detected(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """Validation functions are detected."""
        license_flow = analyzer._analyze_license_validation(starforce_v5_driver)
        assert license_flow is not None
        assert len(license_flow.validation_functions) > 0

    def test_crypto_operations_detected(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """Cryptographic operations are detected."""
        license_flow = analyzer._analyze_license_validation(starforce_v5_driver)
        assert license_flow is not None
        assert len(license_flow.crypto_operations) > 0

    def test_registry_checks_detected(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """Registry checks are detected."""
        license_flow = analyzer._analyze_license_validation(starforce_v5_driver)
        assert license_flow is not None
        assert len(license_flow.registry_checks) > 0

    def test_disc_checks_detected(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """Disc checks are detected."""
        license_flow = analyzer._analyze_license_validation(starforce_v5_driver)
        assert license_flow is not None
        assert len(license_flow.disc_checks) > 0

    def test_network_checks_detected(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """Network checks are detected."""
        license_flow = analyzer._analyze_license_validation(starforce_v5_driver)
        assert license_flow is not None
        assert len(license_flow.network_checks) > 0

    def test_entry_point_valid(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """License validation entry point is valid."""
        license_flow = analyzer._analyze_license_validation(starforce_v5_driver)
        assert license_flow is not None
        assert isinstance(license_flow.entry_point, int)
        assert license_flow.entry_point >= 0


class TestStarForceComprehensiveAnalysis:
    """Test comprehensive StarForce driver analysis."""

    def test_full_analysis_v5_driver(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """Full analysis of v5 driver produces comprehensive results."""
        analysis = analyzer.analyze(starforce_v5_driver)

        assert isinstance(analysis, StarForceAnalysis)
        assert analysis.driver_path == starforce_v5_driver
        assert isinstance(analysis.driver_version, str)
        assert len(analysis.driver_version) > 0
        assert len(analysis.ioctl_commands) >= 10
        assert len(analysis.anti_debug_techniques) >= 10
        assert len(analysis.vm_detection_methods) >= 7
        assert len(analysis.disc_auth_mechanisms) >= 6
        assert len(analysis.kernel_hooks) >= 14
        assert analysis.license_flow is not None

    def test_full_analysis_v4_driver(self, analyzer: StarForceAnalyzer, starforce_v4_driver: Path) -> None:
        """Full analysis of v4 driver produces valid results."""
        analysis = analyzer.analyze(starforce_v4_driver)

        assert isinstance(analysis, StarForceAnalysis)
        assert isinstance(analysis.driver_version, str)
        assert len(analysis.driver_version) > 0
        assert len(analysis.ioctl_commands) >= 3
        assert len(analysis.anti_debug_techniques) >= 3
        assert len(analysis.vm_detection_methods) >= 2
        assert len(analysis.disc_auth_mechanisms) >= 2

    def test_full_analysis_v3_driver(self, analyzer: StarForceAnalyzer, starforce_v3_driver: Path) -> None:
        """Full analysis of v3 driver produces minimal results."""
        analysis = analyzer.analyze(starforce_v3_driver)

        assert isinstance(analysis, StarForceAnalysis)
        assert isinstance(analysis.driver_version, str)
        assert len(analysis.driver_version) > 0
        assert len(analysis.ioctl_commands) >= 2
        assert len(analysis.anti_debug_techniques) >= 2

    def test_analysis_details_structure(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """Analysis details have proper structure."""
        analysis = analyzer.analyze(starforce_v5_driver)

        assert isinstance(analysis.details, dict)
        assert "entry_points" in analysis.details
        assert "imported_functions" in analysis.details
        assert "exported_functions" in analysis.details
        assert "dispatch_routines" in analysis.details
        assert "crypto_algorithms" in analysis.details

    def test_analysis_entry_points(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """Analysis identifies driver entry points."""
        analysis = analyzer.analyze(starforce_v5_driver)

        entry_points = analysis.details["entry_points"]
        assert isinstance(entry_points, list)

    def test_analysis_crypto_algorithms(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """Analysis identifies cryptographic algorithms."""
        analysis = analyzer.analyze(starforce_v5_driver)

        crypto_algorithms = analysis.details["crypto_algorithms"]
        assert isinstance(crypto_algorithms, list)
        assert len(crypto_algorithms) > 0


class TestStarForceEdgeCases:
    """Test edge cases and error handling."""

    def test_analyze_nonexistent_file(self, analyzer: StarForceAnalyzer, tmp_path: Path) -> None:
        """Handles nonexistent file gracefully."""
        nonexistent = tmp_path / "nonexistent.sys"
        analysis = analyzer.analyze(nonexistent)

        assert isinstance(analysis, StarForceAnalysis)
        assert analysis.driver_version == "Unknown"
        assert len(analysis.ioctl_commands) == 0
        assert len(analysis.anti_debug_techniques) == 0

    def test_analyze_empty_file(self, analyzer: StarForceAnalyzer, tmp_path: Path) -> None:
        """Handles empty file gracefully."""
        empty_file = tmp_path / "empty.sys"
        empty_file.write_bytes(b"")
        analysis = analyzer.analyze(empty_file)

        assert isinstance(analysis, StarForceAnalysis)
        assert len(analysis.ioctl_commands) == 0

    def test_analyze_corrupted_file(self, analyzer: StarForceAnalyzer, corrupted_driver: Path) -> None:
        """Handles corrupted file gracefully."""
        analysis = analyzer.analyze(corrupted_driver)

        assert isinstance(analysis, StarForceAnalysis)
        assert analysis.driver_version == "Unknown"

    def test_analyze_partial_protection(self, analyzer: StarForceAnalyzer, partial_starforce_driver: Path) -> None:
        """Handles partial StarForce protection."""
        analysis = analyzer.analyze(partial_starforce_driver)

        assert isinstance(analysis, StarForceAnalysis)
        assert len(analysis.ioctl_commands) >= 1
        assert len(analysis.anti_debug_techniques) >= 1

    def test_analyze_real_windows_binary(self, analyzer: StarForceAnalyzer) -> None:
        """Analyzes real Windows binary without errors."""
        if not SYSTEM32.exists():
            pytest.skip("System32 not accessible")

        kernel32_dll = SYSTEM32 / "kernel32.dll"
        if not kernel32_dll.exists():
            pytest.skip("kernel32.dll not found")

        analysis = analyzer.analyze(kernel32_dll)
        assert isinstance(analysis, StarForceAnalysis)

    def test_analyze_system_driver(self, analyzer: StarForceAnalyzer) -> None:
        """Analyzes real system driver without errors."""
        if not SYSTEM32.exists():
            pytest.skip("System32 not accessible")

        drivers_path = SYSTEM32.parent / "drivers"
        if not drivers_path.exists():
            pytest.skip("Drivers directory not found")

        sys_files = list(drivers_path.glob("*.sys"))
        if not sys_files:
            pytest.skip("No system drivers found")

        analysis = analyzer.analyze(sys_files[0])
        assert isinstance(analysis, StarForceAnalysis)


class TestStarForceCryptoDetection:
    """Test cryptographic algorithm detection."""

    def test_detect_md5_constants(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """Detects MD5 constants."""
        algorithms = analyzer._identify_crypto(starforce_v5_driver)
        md5_algos = [a for a in algorithms if "md5" in a.lower()]
        assert md5_algos

    def test_detect_sha1_constants(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """Detects SHA-1 constants."""
        algorithms = analyzer._identify_crypto(starforce_v5_driver)
        sha1_algos = [a for a in algorithms if "sha-1" in a.lower()]
        assert sha1_algos

    def test_detect_sha256_constants(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """Detects SHA-256 constants."""
        algorithms = analyzer._identify_crypto(starforce_v5_driver)
        sha256_algos = [a for a in algorithms if "sha-256" in a.lower()]
        assert sha256_algos

    def test_detect_aes_constants(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """Detects AES constants."""
        algorithms = analyzer._identify_crypto(starforce_v5_driver)
        aes_algos = [a for a in algorithms if "aes" in a.lower()]
        assert aes_algos

    def test_detect_aes_sbox(self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path) -> None:
        """Detects AES S-box."""
        algorithms = analyzer._identify_crypto(starforce_v5_driver)
        sbox_algos = [a for a in algorithms if "s-box" in a.lower()]
        assert sbox_algos


class TestStarForcePerformance:
    """Test performance of StarForce analyzer."""

    def test_analyze_performance_small_driver(
        self, analyzer: StarForceAnalyzer, starforce_v3_driver: Path, benchmark: Any
    ) -> None:
        """Analysis of small driver completes quickly."""

        def analyze_driver() -> StarForceAnalysis:
            return analyzer.analyze(starforce_v3_driver)

        result = benchmark(analyze_driver)
        assert isinstance(result, StarForceAnalysis)

    def test_analyze_performance_large_driver(
        self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path, benchmark: Any
    ) -> None:
        """Analysis of large driver completes in reasonable time."""

        def analyze_driver() -> StarForceAnalysis:
            return analyzer.analyze(starforce_v5_driver)

        result = benchmark(analyze_driver)
        assert isinstance(result, StarForceAnalysis)

    def test_ioctl_detection_performance(
        self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path, benchmark: Any
    ) -> None:
        """IOCTL detection completes quickly."""

        def detect_ioctls() -> list[IOCTLCommand]:
            return analyzer._analyze_ioctls(starforce_v5_driver)

        result = benchmark(detect_ioctls)
        assert len(result) >= 10

    def test_anti_debug_detection_performance(
        self, analyzer: StarForceAnalyzer, starforce_v5_driver: Path, benchmark: Any
    ) -> None:
        """Anti-debug detection completes quickly."""

        def detect_anti_debug() -> list[AntiDebugTechnique]:
            return analyzer._detect_anti_debug(starforce_v5_driver)

        result = benchmark(detect_anti_debug)
        assert len(result) >= 10


@pytest.mark.skipif(not SYSTEM32.exists(), reason="Requires Windows System32")
class TestStarForceRealBinaries:
    """Test StarForce analyzer against real Windows binaries."""

    def test_analyze_notepad(self, analyzer: StarForceAnalyzer) -> None:
        """Analyzes notepad.exe without errors."""
        notepad = SYSTEM32 / "notepad.exe"
        if not notepad.exists():
            pytest.skip("notepad.exe not found")

        analysis = analyzer.analyze(notepad)
        assert isinstance(analysis, StarForceAnalysis)
        assert analysis.driver_path == notepad

    def test_analyze_kernel32(self, analyzer: StarForceAnalyzer) -> None:
        """Analyzes kernel32.dll without errors."""
        kernel32 = SYSTEM32 / "kernel32.dll"
        if not kernel32.exists():
            pytest.skip("kernel32.dll not found")

        analysis = analyzer.analyze(kernel32)
        assert isinstance(analysis, StarForceAnalysis)

    def test_analyze_ntdll(self, analyzer: StarForceAnalyzer) -> None:
        """Analyzes ntdll.dll without errors."""
        ntdll = SYSTEM32 / "ntdll.dll"
        if not ntdll.exists():
            pytest.skip("ntdll.dll not found")

        analysis = analyzer.analyze(ntdll)
        assert isinstance(analysis, StarForceAnalysis)

    def test_analyze_multiple_system_drivers(self, analyzer: StarForceAnalyzer) -> None:
        """Analyzes multiple system drivers without errors."""
        drivers_path = SYSTEM32.parent / "drivers"
        if not drivers_path.exists():
            pytest.skip("Drivers directory not found")

        sys_files = list(drivers_path.glob("*.sys"))[:5]
        if not sys_files:
            pytest.skip("No system drivers found")

        for sys_file in sys_files:
            analysis = analyzer.analyze(sys_file)
            assert isinstance(analysis, StarForceAnalysis)
