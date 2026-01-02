"""Production tests for StarForce analyzer - NO MOCKS ALLOWED.

Tests validate real StarForce driver analysis capabilities using custom-crafted
test binaries with embedded StarForce signatures. NO unittest.mock usage permitted.
"""

from __future__ import annotations

import struct
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


class RealBinaryFactory:
    """Factory for creating real test binaries with StarForce signatures.

    Creates actual PE binaries with embedded StarForce driver signatures,
    IOCTL codes, anti-debugging patterns, and protection mechanisms.
    """

    @staticmethod
    def create_minimal_pe_driver() -> bytes:
        """Create minimal valid PE driver binary."""
        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        pe_header = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 0xE0, 0x2102)

        optional_header = bytearray(224)
        optional_header[:2] = struct.pack("<H", 0x010B)
        optional_header[16:20] = struct.pack("<I", 0x1000)
        optional_header[20:24] = struct.pack("<I", 0x400000)

        section_header = bytearray(40)
        section_header[:8] = b".text\x00\x00\x00"
        section_header[8:12] = struct.pack("<I", 0x1000)
        section_header[12:16] = struct.pack("<I", 0x1000)
        section_header[16:20] = struct.pack("<I", 0x1000)
        section_header[20:24] = struct.pack("<I", 0x400)
        section_header[36:40] = struct.pack("<I", 0xE0000020)

        section_data = bytearray(0x1000)

        binary = bytes(dos_header) + pe_header + coff_header + bytes(optional_header)
        binary += bytes(section_header)
        binary = binary.ljust(0x400, b"\x00")
        binary += bytes(section_data)

        return binary

    @classmethod
    def create_starforce_basic_driver(cls) -> bytes:
        """Create basic StarForce driver with minimal signatures."""
        binary = bytearray(cls.create_minimal_pe_driver())

        binary[0x400:0x40A] = b"StarForce"
        binary[0x450:0x454] = struct.pack("<I", 0x80002000)
        binary[0x460:0x464] = struct.pack("<I", 0x80002004)
        binary[0x500:0x502] = b"\x0f\x31"
        binary[0x600:0x606] = b"VMware"

        return bytes(binary)

    @classmethod
    def create_advanced_starforce_driver(cls) -> bytes:
        """Create advanced StarForce driver with comprehensive protections."""
        binary = bytearray(cls.create_minimal_pe_driver())

        binary[0x400:0x40A] = b"StarForce"
        binary[0x420:0x427] = b"5.2.1.0"

        ioctl_offset = 0x500
        for ioctl_code in [
            0x80002000,
            0x80002004,
            0x80002008,
            0x8000200C,
            0x80002010,
            0x80002014,
            0x80002018,
            0x8000201C,
        ]:
            binary[ioctl_offset : ioctl_offset + 4] = struct.pack("<I", ioctl_code)
            ioctl_offset += 10

        binary[0x600:0x606] = b"\x64\xa1\x1c\x00\x00\x00"
        binary[0x650:0x655] = b"\xa1\x34\x00\x00\x00"
        binary[0x700:0x702] = b"\x0f\x31"
        binary[0x750:0x753] = b"\xf0\x0f\xc1"
        binary[0x800:0x802] = b"\xcd\x2d"
        binary[0x850:0x852] = b"\xcc\xcc"
        binary[0x900:0x903] = b"\x0f\x21\xc0"
        binary[0x950:0x953] = b"\x0f\x21\xc1"

        binary[0xA00:0xA06] = b"VMware"
        binary[0xA50:0xA5A] = b"VBoxGuest"
        binary[0xB00:0xB04] = b"QEMU"
        binary[0xB50:0xB57] = b"Hyper-V"
        binary[0xC00:0xC02] = b"\x0f\xa2"
        binary[0xC50:0xC52] = b"\x0f\x01"

        binary[0xD00:0xD04] = b"SCSI"
        binary[0xD50:0xD58] = b"READ_TOC"
        binary[0xE00:0xE0D] = b"READ_CAPACITY"
        binary[0xE50:0xE51] = b"\xa8"
        binary[0xF00:0xF10] = b"GetDriveGeometry"
        binary[0xF50:0xF5A] = b"subchannel"

        binary[0x1000:0x100C] = b"NtCreateFile"
        binary[0x1050:0x105A] = b"NtOpenFile"
        binary[0x1100:0x110A] = b"NtReadFile"
        binary[0x1150:0x1165] = b"NtDeviceIoControlFile"

        binary[0x1200:0x1207] = b"License"
        binary[0x1250:0x1256] = b"Serial"
        binary[0x1300:0x130A] = b"Activation"
        binary[0x1350:0x1358] = b"Validate"

        binary[0x1400:0x1403] = b"RSA"
        binary[0x1450:0x1453] = b"AES"
        binary[0x1500:0x1503] = b"SHA"
        binary[0x1550:0x1553] = b"MD5"

        binary[0x1600:0x1608] = b"\x67\x45\x23\x01\xef\xcd\xab\x89"
        binary[0x1650:0x1658] = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        binary[0x1700:0x1704] = b"\x6a\x09\xe6\x67"

        binary[0x1800:0x181B] = b"\\Registry\\Machine\\SOFTWARE"
        binary[0x1850:0x185A] = b"\\\\.\\CdRom"
        binary[0x1900:0x1904] = b"http"

        return bytes(binary)

    @classmethod
    def create_custom_ioctl_binary(cls) -> bytes:
        """Create binary with custom IOCTL detection patterns."""
        binary = bytearray(cls.create_minimal_pe_driver())

        binary[0x400:0x40A] = b"StarForce"

        binary[0x500:0x502] = b"\x81\x7d"
        binary[0x502:0x506] = struct.pack("<I", 0x80003000)

        binary[0x550:0x552] = b"\x81\x7d"
        binary[0x552:0x556] = struct.pack("<I", 0x80004000)

        binary[0x600:0x602] = b"\x81\x7d"
        binary[0x602:0x606] = struct.pack("<I", 0x80005000)

        return bytes(binary)

    @classmethod
    def create_empty_binary(cls) -> bytes:
        """Create minimal PE binary without StarForce signatures."""
        return cls.create_minimal_pe_driver()

    @classmethod
    def create_corrupted_binary(cls) -> bytes:
        """Create corrupted binary for error handling tests."""
        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        garbage = bytearray(1000)
        garbage[:10] = b"StarForce"
        garbage[20:30] = b"CORRUPTED!"

        return bytes(dos_header) + bytes(garbage)


@pytest.fixture
def analyzer() -> StarForceAnalyzer:
    """Create StarForce analyzer instance."""
    return StarForceAnalyzer()


@pytest.fixture
def basic_starforce_driver(tmp_path: Path) -> Path:
    """Create basic StarForce test driver."""
    driver_path = tmp_path / "basic_starforce.sys"
    driver_path.write_bytes(RealBinaryFactory.create_starforce_basic_driver())
    return driver_path


@pytest.fixture
def advanced_starforce_driver(tmp_path: Path) -> Path:
    """Create advanced StarForce test driver."""
    driver_path = tmp_path / "advanced_starforce.sys"
    driver_path.write_bytes(RealBinaryFactory.create_advanced_starforce_driver())
    return driver_path


@pytest.fixture
def custom_ioctl_binary(tmp_path: Path) -> Path:
    """Create custom IOCTL test binary."""
    binary_path = tmp_path / "custom_ioctl.sys"
    binary_path.write_bytes(RealBinaryFactory.create_custom_ioctl_binary())
    return binary_path


@pytest.fixture
def empty_binary(tmp_path: Path) -> Path:
    """Create empty test binary."""
    binary_path = tmp_path / "empty.sys"
    binary_path.write_bytes(RealBinaryFactory.create_empty_binary())
    return binary_path


@pytest.fixture
def corrupted_binary(tmp_path: Path) -> Path:
    """Create corrupted test binary."""
    binary_path = tmp_path / "corrupted.sys"
    binary_path.write_bytes(RealBinaryFactory.create_corrupted_binary())
    return binary_path


class TestStarForceAnalyzerBasics:
    """Test basic StarForce analyzer functionality."""

    def test_analyzer_initialization_succeeds(self, analyzer: StarForceAnalyzer) -> None:
        """Analyzer initializes with proper configuration."""
        assert analyzer is not None
        assert hasattr(analyzer, "KNOWN_IOCTLS")
        assert hasattr(analyzer, "ANTI_DEBUG_PATTERNS")
        assert hasattr(analyzer, "VM_DETECTION_PATTERNS")
        assert hasattr(analyzer, "IOCTL_DEVICE_TYPES")

    def test_analyzer_has_known_ioctls_defined(self, analyzer: StarForceAnalyzer) -> None:
        """Analyzer contains known StarForce IOCTL definitions."""
        assert len(analyzer.KNOWN_IOCTLS) >= 10
        assert 0x80002000 in analyzer.KNOWN_IOCTLS
        assert 0x80002004 in analyzer.KNOWN_IOCTLS
        assert 0x80002008 in analyzer.KNOWN_IOCTLS

    def test_analyzer_has_anti_debug_patterns(self, analyzer: StarForceAnalyzer) -> None:
        """Analyzer contains anti-debugging pattern definitions."""
        assert "kernel_debugger_check" in analyzer.ANTI_DEBUG_PATTERNS
        assert "timing_check" in analyzer.ANTI_DEBUG_PATTERNS
        assert "int2d_detection" in analyzer.ANTI_DEBUG_PATTERNS
        assert "hardware_breakpoint" in analyzer.ANTI_DEBUG_PATTERNS

    def test_analyzer_has_vm_detection_patterns(self, analyzer: StarForceAnalyzer) -> None:
        """Analyzer contains VM detection pattern definitions."""
        assert "vmware" in analyzer.VM_DETECTION_PATTERNS
        assert "virtualbox" in analyzer.VM_DETECTION_PATTERNS
        assert "qemu" in analyzer.VM_DETECTION_PATTERNS
        assert "hyperv" in analyzer.VM_DETECTION_PATTERNS

    def test_analyzer_has_device_types(self, analyzer: StarForceAnalyzer) -> None:
        """Analyzer contains StarForce device type definitions."""
        assert 0x8000 in analyzer.IOCTL_DEVICE_TYPES
        assert analyzer.IOCTL_DEVICE_TYPES[0x8000] == "STARFORCE_DEVICE"
        assert 0x8001 in analyzer.IOCTL_DEVICE_TYPES
        assert 0x8002 in analyzer.IOCTL_DEVICE_TYPES
        assert 0x8003 in analyzer.IOCTL_DEVICE_TYPES


class TestStarForceIOCTLDetection:
    """Test StarForce IOCTL detection capabilities."""

    def test_detects_known_ioctls_in_basic_driver(
        self, analyzer: StarForceAnalyzer, basic_starforce_driver: Path
    ) -> None:
        """Detects known IOCTL codes in basic StarForce driver."""
        ioctls = analyzer._analyze_ioctls(basic_starforce_driver)
        assert len(ioctls) >= 2

        ioctl_codes = {ioctl.code for ioctl in ioctls}
        assert 0x80002000 in ioctl_codes
        assert 0x80002004 in ioctl_codes

    def test_detects_multiple_ioctls_in_advanced_driver(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """Detects multiple IOCTL codes in advanced StarForce driver."""
        ioctls = analyzer._analyze_ioctls(advanced_starforce_driver)
        assert len(ioctls) >= 8

        ioctl_codes = {ioctl.code for ioctl in ioctls}
        assert 0x80002000 in ioctl_codes
        assert 0x80002004 in ioctl_codes
        assert 0x80002008 in ioctl_codes
        assert 0x8000200C in ioctl_codes
        assert 0x80002010 in ioctl_codes
        assert 0x80002014 in ioctl_codes
        assert 0x80002018 in ioctl_codes
        assert 0x8000201C in ioctl_codes

    def test_ioctl_structures_are_properly_parsed(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """IOCTL structures contain valid parsed data."""
        ioctls = analyzer._analyze_ioctls(advanced_starforce_driver)

        for ioctl in ioctls:
            assert isinstance(ioctl, IOCTLCommand)
            assert isinstance(ioctl.code, int)
            assert isinstance(ioctl.device_type, int)
            assert isinstance(ioctl.function, int)
            assert isinstance(ioctl.method, int)
            assert isinstance(ioctl.access, int)
            assert isinstance(ioctl.name, str)
            assert isinstance(ioctl.purpose, str)
            assert ioctl.code >= 0x80000000
            assert len(ioctl.name) > 0
            assert len(ioctl.purpose) > 0

    def test_ioctl_names_match_expected_values(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """IOCTL names are correctly mapped."""
        ioctls = analyzer._analyze_ioctls(advanced_starforce_driver)
        ioctl_map = {ioctl.code: ioctl.name for ioctl in ioctls}

        assert ioctl_map.get(0x80002000) == "SF_IOCTL_GET_VERSION"
        assert ioctl_map.get(0x80002004) == "SF_IOCTL_CHECK_DISC"
        assert ioctl_map.get(0x80002008) == "SF_IOCTL_VALIDATE_LICENSE"
        assert ioctl_map.get(0x8000200C) == "SF_IOCTL_GET_HWID"

    def test_detects_custom_ioctls_with_pattern_matching(
        self, analyzer: StarForceAnalyzer, custom_ioctl_binary: Path
    ) -> None:
        """Detects custom IOCTL codes through pattern analysis."""
        ioctls = analyzer._analyze_ioctls(custom_ioctl_binary)
        assert len(ioctls) >= 3

        custom_ioctls = [ioctl for ioctl in ioctls if "CUSTOM" in ioctl.name]
        assert len(custom_ioctls) >= 3

        custom_codes = {ioctl.code for ioctl in custom_ioctls}
        assert 0x80003000 in custom_codes
        assert 0x80004000 in custom_codes
        assert 0x80005000 in custom_codes

    def test_custom_ioctls_have_proper_naming(
        self, analyzer: StarForceAnalyzer, custom_ioctl_binary: Path
    ) -> None:
        """Custom IOCTLs use correct naming convention."""
        ioctls = analyzer._analyze_ioctls(custom_ioctl_binary)

        for ioctl in ioctls:
            if "CUSTOM" in ioctl.name:
                assert ioctl.name.startswith("SF_IOCTL_CUSTOM_")
                assert "unknown" in ioctl.purpose.lower()

    def test_handles_empty_binary_gracefully(
        self, analyzer: StarForceAnalyzer, empty_binary: Path
    ) -> None:
        """Returns empty list for binary without IOCTL codes."""
        ioctls = analyzer._analyze_ioctls(empty_binary)
        assert isinstance(ioctls, list)
        assert len(ioctls) == 0

    def test_handles_nonexistent_file_gracefully(
        self, analyzer: StarForceAnalyzer, tmp_path: Path
    ) -> None:
        """Returns empty list for nonexistent file."""
        nonexistent = tmp_path / "nonexistent.sys"
        ioctls = analyzer._analyze_ioctls(nonexistent)
        assert isinstance(ioctls, list)
        assert len(ioctls) == 0


class TestStarForceAntiDebuggingDetection:
    """Test anti-debugging technique detection."""

    def test_detects_kernel_debugger_checks(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """Detects kernel debugger check patterns."""
        techniques = analyzer._detect_anti_debug(advanced_starforce_driver)
        kernel_checks = [t for t in techniques if t.technique == "kernel_debugger_check"]
        assert len(kernel_checks) >= 2

    def test_detects_timing_checks(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """Detects timing-based anti-debugging patterns."""
        techniques = analyzer._detect_anti_debug(advanced_starforce_driver)
        timing_checks = [t for t in techniques if t.technique == "timing_check"]
        assert len(timing_checks) >= 2

    def test_detects_int2d_exception_detection(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """Detects INT 2D exception detection patterns."""
        techniques = analyzer._detect_anti_debug(advanced_starforce_driver)
        int2d_checks = [t for t in techniques if t.technique == "int2d_detection"]
        assert len(int2d_checks) >= 2

    def test_detects_hardware_breakpoint_checks(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """Detects hardware breakpoint detection patterns."""
        techniques = analyzer._detect_anti_debug(advanced_starforce_driver)
        hw_checks = [t for t in techniques if t.technique == "hardware_breakpoint"]
        assert len(hw_checks) >= 2

    def test_anti_debug_structures_are_valid(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """Anti-debug technique structures contain valid data."""
        techniques = analyzer._detect_anti_debug(advanced_starforce_driver)

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

    def test_anti_debug_includes_bypass_recommendations(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """Anti-debug techniques include actionable bypass methods."""
        techniques = analyzer._detect_anti_debug(advanced_starforce_driver)

        for technique in techniques:
            assert len(technique.bypass_method) > 10
            assert any(
                keyword in technique.bypass_method.lower()
                for keyword in ["patch", "hook", "clear", "normalize"]
            )

    def test_handles_binary_without_anti_debug(
        self, analyzer: StarForceAnalyzer, empty_binary: Path
    ) -> None:
        """Returns empty list for binary without anti-debug patterns."""
        techniques = analyzer._detect_anti_debug(empty_binary)
        assert isinstance(techniques, list)
        assert len(techniques) == 0


class TestStarForceVMDetection:
    """Test virtual machine detection capabilities."""

    def test_detects_vmware_detection_methods(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """Detects VMware detection patterns."""
        vm_methods = analyzer._detect_vm_checks(advanced_starforce_driver)
        vmware_methods = [m for m in vm_methods if "vmware" in m.lower()]
        assert len(vmware_methods) >= 1

    def test_detects_virtualbox_detection_methods(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """Detects VirtualBox detection patterns."""
        vm_methods = analyzer._detect_vm_checks(advanced_starforce_driver)
        vbox_methods = [m for m in vm_methods if "virtualbox" in m.lower()]
        assert len(vbox_methods) >= 1

    def test_detects_qemu_detection_methods(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """Detects QEMU detection patterns."""
        vm_methods = analyzer._detect_vm_checks(advanced_starforce_driver)
        qemu_methods = [m for m in vm_methods if "qemu" in m.lower()]
        assert len(qemu_methods) >= 1

    def test_detects_hyperv_detection_methods(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """Detects Hyper-V detection patterns."""
        vm_methods = analyzer._detect_vm_checks(advanced_starforce_driver)
        hyperv_methods = [m for m in vm_methods if "hyperv" in m.lower() or "hyper-v" in m.lower()]
        assert len(hyperv_methods) >= 1

    def test_detects_cpuid_based_vm_detection(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """Detects CPUID-based VM detection."""
        vm_methods = analyzer._detect_vm_checks(advanced_starforce_driver)
        cpuid_methods = [m for m in vm_methods if "cpuid" in m.lower()]
        assert len(cpuid_methods) >= 1

    def test_detects_sidt_sgdt_vm_detection(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """Detects SIDT/SGDT-based VM detection."""
        vm_methods = analyzer._detect_vm_checks(advanced_starforce_driver)
        sidt_methods = [m for m in vm_methods if "sidt" in m.lower() or "sgdt" in m.lower()]
        assert len(sidt_methods) >= 1

    def test_handles_binary_without_vm_detection(
        self, analyzer: StarForceAnalyzer, empty_binary: Path
    ) -> None:
        """Returns empty list for binary without VM detection."""
        vm_methods = analyzer._detect_vm_checks(empty_binary)
        assert isinstance(vm_methods, list)
        assert len(vm_methods) == 0


class TestStarForceDiscAuthentication:
    """Test disc authentication mechanism detection."""

    def test_detects_scsi_authentication(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """Detects SCSI-based disc authentication."""
        mechanisms = analyzer._analyze_disc_auth(advanced_starforce_driver)
        scsi_mechs = [m for m in mechanisms if "scsi" in m.lower()]
        assert len(scsi_mechs) >= 1

    def test_detects_toc_verification(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """Detects TOC verification mechanism."""
        mechanisms = analyzer._analyze_disc_auth(advanced_starforce_driver)
        toc_mechs = [m for m in mechanisms if "toc" in m.lower()]
        assert len(toc_mechs) >= 1

    def test_detects_capacity_validation(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """Detects disc capacity validation."""
        mechanisms = analyzer._analyze_disc_auth(advanced_starforce_driver)
        capacity_mechs = [m for m in mechanisms if "capacity" in m.lower()]
        assert len(capacity_mechs) >= 1

    def test_detects_raw_sector_reading(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """Detects raw sector reading for disc fingerprinting."""
        mechanisms = analyzer._analyze_disc_auth(advanced_starforce_driver)
        sector_mechs = [m for m in mechanisms if "sector" in m.lower() or "fingerprint" in m.lower()]
        assert len(sector_mechs) >= 1

    def test_detects_geometry_verification(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """Detects drive geometry verification."""
        mechanisms = analyzer._analyze_disc_auth(advanced_starforce_driver)
        geometry_mechs = [m for m in mechanisms if "geometry" in m.lower()]
        assert len(geometry_mechs) >= 1

    def test_detects_subchannel_analysis(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """Detects subchannel data analysis."""
        mechanisms = analyzer._analyze_disc_auth(advanced_starforce_driver)
        subchannel_mechs = [m for m in mechanisms if "subchannel" in m.lower()]
        assert len(subchannel_mechs) >= 1

    def test_handles_binary_without_disc_auth(
        self, analyzer: StarForceAnalyzer, empty_binary: Path
    ) -> None:
        """Returns empty list for binary without disc authentication."""
        mechanisms = analyzer._analyze_disc_auth(empty_binary)
        assert isinstance(mechanisms, list)
        assert len(mechanisms) == 0


class TestStarForceKernelHooks:
    """Test kernel hook detection."""

    def test_detects_file_operation_hooks(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """Detects file operation kernel hooks."""
        hooks = analyzer._detect_kernel_hooks(advanced_starforce_driver)
        file_hooks = [
            h for h in hooks if any(fn in h[0] for fn in ["CreateFile", "OpenFile", "ReadFile"])
        ]
        assert len(file_hooks) >= 3

    def test_detects_deviceiocontrol_hooks(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """Detects DeviceIoControl hooks."""
        hooks = analyzer._detect_kernel_hooks(advanced_starforce_driver)
        ioctl_hooks = [h for h in hooks if "DeviceIoControl" in h[0]]
        assert len(ioctl_hooks) >= 1

    def test_hook_structures_are_valid(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """Kernel hook structures contain valid data."""
        hooks = analyzer._detect_kernel_hooks(advanced_starforce_driver)

        for func_name, offset in hooks:
            assert isinstance(func_name, str)
            assert isinstance(offset, int)
            assert len(func_name) > 0
            assert offset >= 0

    def test_handles_binary_without_hooks(
        self, analyzer: StarForceAnalyzer, empty_binary: Path
    ) -> None:
        """Returns empty list for binary without kernel hooks."""
        hooks = analyzer._detect_kernel_hooks(empty_binary)
        assert isinstance(hooks, list)
        assert len(hooks) == 0


class TestStarForceLicenseValidation:
    """Test license validation flow detection."""

    def test_detects_license_validation_flow(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """Detects license validation flow in driver."""
        license_flow = analyzer._analyze_license_validation(advanced_starforce_driver)
        assert license_flow is not None
        assert isinstance(license_flow, LicenseValidationFlow)

    def test_detects_validation_functions(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """Detects license validation functions."""
        license_flow = analyzer._analyze_license_validation(advanced_starforce_driver)
        assert license_flow is not None
        assert len(license_flow.validation_functions) > 0

    def test_detects_crypto_operations(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """Detects cryptographic operations in license validation."""
        license_flow = analyzer._analyze_license_validation(advanced_starforce_driver)
        assert license_flow is not None
        assert len(license_flow.crypto_operations) > 0

    def test_detects_registry_checks(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """Detects registry checks in license validation."""
        license_flow = analyzer._analyze_license_validation(advanced_starforce_driver)
        assert license_flow is not None
        assert len(license_flow.registry_checks) > 0

    def test_detects_disc_checks(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """Detects disc checks in license validation."""
        license_flow = analyzer._analyze_license_validation(advanced_starforce_driver)
        assert license_flow is not None
        assert len(license_flow.disc_checks) > 0

    def test_detects_network_checks(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """Detects network checks in license validation."""
        license_flow = analyzer._analyze_license_validation(advanced_starforce_driver)
        assert license_flow is not None
        assert len(license_flow.network_checks) > 0

    def test_entry_point_is_valid(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """Entry point address is valid."""
        license_flow = analyzer._analyze_license_validation(advanced_starforce_driver)
        assert license_flow is not None
        assert isinstance(license_flow.entry_point, int)
        assert license_flow.entry_point >= 0

    def test_returns_none_for_nonexistent_file(
        self, analyzer: StarForceAnalyzer, tmp_path: Path
    ) -> None:
        """Returns None for nonexistent file."""
        nonexistent = tmp_path / "nonexistent.sys"
        license_flow = analyzer._analyze_license_validation(nonexistent)
        assert license_flow is None


class TestStarForceCryptographicDetection:
    """Test cryptographic algorithm detection."""

    def test_detects_md5_constants(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """Detects MD5 cryptographic constants."""
        algorithms = analyzer._identify_crypto(advanced_starforce_driver)
        md5_algos = [a for a in algorithms if "md5" in a.lower()]
        assert len(md5_algos) >= 1

    def test_detects_sha1_constants(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """Detects SHA-1 cryptographic constants."""
        algorithms = analyzer._identify_crypto(advanced_starforce_driver)
        sha1_algos = [a for a in algorithms if "sha-1" in a.lower()]
        assert len(sha1_algos) >= 1

    def test_detects_sha256_constants(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """Detects SHA-256 cryptographic constants."""
        algorithms = analyzer._identify_crypto(advanced_starforce_driver)
        sha256_algos = [a for a in algorithms if "sha-256" in a.lower()]
        assert len(sha256_algos) >= 1

    def test_handles_binary_without_crypto(
        self, analyzer: StarForceAnalyzer, empty_binary: Path
    ) -> None:
        """Returns empty list for binary without crypto algorithms."""
        algorithms = analyzer._identify_crypto(empty_binary)
        assert isinstance(algorithms, list)
        assert len(algorithms) == 0


class TestStarForceComprehensiveAnalysis:
    """Test comprehensive full driver analysis."""

    def test_full_analysis_produces_complete_results(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """Full analysis produces comprehensive StarForceAnalysis results."""
        analysis = analyzer.analyze(advanced_starforce_driver)

        assert isinstance(analysis, StarForceAnalysis)
        assert analysis.driver_path == advanced_starforce_driver
        assert isinstance(analysis.driver_version, str)
        assert len(analysis.driver_version) > 0
        assert len(analysis.ioctl_commands) >= 8
        assert len(analysis.anti_debug_techniques) >= 8
        assert len(analysis.vm_detection_methods) >= 6
        assert len(analysis.disc_auth_mechanisms) >= 6
        assert len(analysis.kernel_hooks) >= 4
        assert analysis.license_flow is not None

    def test_analysis_details_have_proper_structure(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """Analysis details dictionary has expected keys."""
        analysis = analyzer.analyze(advanced_starforce_driver)

        assert isinstance(analysis.details, dict)
        assert "entry_points" in analysis.details
        assert "imported_functions" in analysis.details
        assert "exported_functions" in analysis.details
        assert "dispatch_routines" in analysis.details
        assert "crypto_algorithms" in analysis.details

    def test_analysis_identifies_crypto_algorithms(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """Analysis identifies cryptographic algorithms."""
        analysis = analyzer.analyze(advanced_starforce_driver)

        crypto_algorithms = analysis.details["crypto_algorithms"]
        assert isinstance(crypto_algorithms, list)
        assert len(crypto_algorithms) > 0

    def test_basic_driver_produces_minimal_results(
        self, analyzer: StarForceAnalyzer, basic_starforce_driver: Path
    ) -> None:
        """Basic driver produces minimal but valid results."""
        analysis = analyzer.analyze(basic_starforce_driver)

        assert isinstance(analysis, StarForceAnalysis)
        assert len(analysis.ioctl_commands) >= 2
        assert len(analysis.anti_debug_techniques) >= 1
        assert len(analysis.vm_detection_methods) >= 1


class TestStarForceEdgeCases:
    """Test edge cases and error handling."""

    def test_handles_nonexistent_file_gracefully(
        self, analyzer: StarForceAnalyzer, tmp_path: Path
    ) -> None:
        """Handles nonexistent file without crashing."""
        nonexistent = tmp_path / "nonexistent.sys"
        analysis = analyzer.analyze(nonexistent)

        assert isinstance(analysis, StarForceAnalysis)
        assert analysis.driver_version == "Unknown"
        assert len(analysis.ioctl_commands) == 0
        assert len(analysis.anti_debug_techniques) == 0
        assert len(analysis.vm_detection_methods) == 0
        assert len(analysis.disc_auth_mechanisms) == 0
        assert len(analysis.kernel_hooks) == 0

    def test_handles_empty_file_gracefully(
        self, analyzer: StarForceAnalyzer, tmp_path: Path
    ) -> None:
        """Handles empty file without crashing."""
        empty_file = tmp_path / "empty.sys"
        empty_file.write_bytes(b"")
        analysis = analyzer.analyze(empty_file)

        assert isinstance(analysis, StarForceAnalysis)
        assert len(analysis.ioctl_commands) == 0

    def test_handles_corrupted_file_gracefully(
        self, analyzer: StarForceAnalyzer, corrupted_binary: Path
    ) -> None:
        """Handles corrupted file without crashing."""
        analysis = analyzer.analyze(corrupted_binary)

        assert isinstance(analysis, StarForceAnalysis)
        assert isinstance(analysis.driver_version, str)

    def test_handles_minimal_binary_gracefully(
        self, analyzer: StarForceAnalyzer, empty_binary: Path
    ) -> None:
        """Handles minimal PE binary without StarForce signatures."""
        analysis = analyzer.analyze(empty_binary)

        assert isinstance(analysis, StarForceAnalysis)
        assert len(analysis.ioctl_commands) == 0
        assert len(analysis.anti_debug_techniques) == 0


class TestStarForceVersionDetection:
    """Test driver version detection."""

    def test_version_detection_returns_valid_string(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path
    ) -> None:
        """Version detection returns valid version string or Unknown."""
        version = analyzer._get_driver_version(advanced_starforce_driver)
        assert isinstance(version, str)
        assert len(version) > 0

    def test_version_detection_handles_nonexistent_file(
        self, analyzer: StarForceAnalyzer, tmp_path: Path
    ) -> None:
        """Returns Unknown for nonexistent file."""
        nonexistent = tmp_path / "nonexistent.sys"
        version = analyzer._get_driver_version(nonexistent)
        assert version == "Unknown"

    def test_version_detection_handles_corrupted_file(
        self, analyzer: StarForceAnalyzer, corrupted_binary: Path
    ) -> None:
        """Handles corrupted file gracefully."""
        version = analyzer._get_driver_version(corrupted_binary)
        assert isinstance(version, str)


class TestStarForcePerformance:
    """Test performance characteristics."""

    @pytest.mark.benchmark
    def test_full_analysis_completes_quickly(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path, benchmark: Any
    ) -> None:
        """Full analysis completes in reasonable time."""

        def analyze_driver() -> StarForceAnalysis:
            return analyzer.analyze(advanced_starforce_driver)

        result = benchmark(analyze_driver)
        assert isinstance(result, StarForceAnalysis)

    @pytest.mark.benchmark
    def test_ioctl_detection_completes_quickly(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path, benchmark: Any
    ) -> None:
        """IOCTL detection completes quickly."""

        def detect_ioctls() -> list[IOCTLCommand]:
            return analyzer._analyze_ioctls(advanced_starforce_driver)

        result = benchmark(detect_ioctls)
        assert len(result) >= 8

    @pytest.mark.benchmark
    def test_anti_debug_detection_completes_quickly(
        self, analyzer: StarForceAnalyzer, advanced_starforce_driver: Path, benchmark: Any
    ) -> None:
        """Anti-debug detection completes quickly."""

        def detect_anti_debug() -> list[AntiDebugTechnique]:
            return analyzer._detect_anti_debug(advanced_starforce_driver)

        result = benchmark(detect_anti_debug)
        assert len(result) >= 8
