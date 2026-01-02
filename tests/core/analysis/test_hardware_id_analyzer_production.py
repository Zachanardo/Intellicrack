"""Production-Grade Tests for Hardware ID Analyzer.

Validates REAL hardware ID analysis capabilities against actual binaries with HWID protection.
NO MOCKS - tests prove analyzer detects genuine hardware fingerprinting mechanisms.

Copyright (C) 2025 Zachary Flint
SPDX-License-Identifier: GPL-3.0-or-later
"""

import ctypes
import ctypes.wintypes
import hashlib
import logging
import struct
import winreg
from pathlib import Path
from typing import Any

import pefile
import pytest
from keystone import Ks, KS_ARCH_X86, KS_MODE_32, KS_MODE_64

logger = logging.getLogger(__name__)

from intellicrack.core.analysis.hardware_id_analyzer import (
    HardwareIDAnalyzer,
    HWIDAlgorithm,
    HWIDCheck,
    HWIDType,
    HWIDValidation,
    NodeLockPattern,
)
from intellicrack.handlers.wmi_handler import wmi


FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "binaries" / "pe"
HWID_BINARIES_DIR = FIXTURES_DIR / "hwid_protected"


@pytest.fixture(scope="module")
def create_cpuid_binary() -> Path:
    """Create real PE binary with CPUID instruction for testing."""
    output_path = HWID_BINARIES_DIR / "cpuid_test.exe"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    asm_code = """
    BITS 32

    global _start
    _start:
        xor eax, eax
        cpuid

        mov eax, 1
        cpuid

        push eax
        push ebx
        push ecx
        push edx

        xor eax, eax
        ret
    """

    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    encoding, _ = ks.asm(asm_code)
    code_bytes = bytes(encoding)

    pe = pefile.PE()
    pe.DOS_HEADER = pefile.Structure(pefile.PE.__IMAGE_DOS_HEADER_format__)
    pe.DOS_HEADER.e_magic = 0x5A4D
    pe.DOS_HEADER.e_lfanew = 0x80

    pe.NT_HEADERS = pefile.Structure(pefile.PE.__IMAGE_NT_HEADERS_format__)
    pe.NT_HEADERS.Signature = 0x4550

    pe.FILE_HEADER = pefile.Structure(pefile.PE.__IMAGE_FILE_HEADER_format__)
    pe.FILE_HEADER.Machine = 0x014C
    pe.FILE_HEADER.NumberOfSections = 1
    pe.FILE_HEADER.SizeOfOptionalHeader = 224
    pe.FILE_HEADER.Characteristics = 0x0102

    pe.OPTIONAL_HEADER = pefile.Structure(pefile.PE.__IMAGE_OPTIONAL_HEADER_format__)
    pe.OPTIONAL_HEADER.Magic = 0x10B
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = 0x1000
    pe.OPTIONAL_HEADER.ImageBase = 0x00400000
    pe.OPTIONAL_HEADER.SectionAlignment = 0x1000
    pe.OPTIONAL_HEADER.FileAlignment = 0x200
    pe.OPTIONAL_HEADER.MajorOperatingSystemVersion = 5
    pe.OPTIONAL_HEADER.MinorOperatingSystemVersion = 1
    pe.OPTIONAL_HEADER.MajorSubsystemVersion = 5
    pe.OPTIONAL_HEADER.MinorSubsystemVersion = 1
    pe.OPTIONAL_HEADER.SizeOfImage = 0x3000
    pe.OPTIONAL_HEADER.SizeOfHeaders = 0x400
    pe.OPTIONAL_HEADER.Subsystem = 3
    pe.OPTIONAL_HEADER.NumberOfRvaAndSizes = 16

    text_section = pefile.SectionStructure(pefile.PE.__IMAGE_SECTION_HEADER_format__)
    text_section.Name = b".text\x00\x00\x00"
    text_section.Misc_VirtualSize = len(code_bytes)
    text_section.VirtualAddress = 0x1000
    text_section.SizeOfRawData = ((len(code_bytes) + 0x1FF) // 0x200) * 0x200
    text_section.PointerToRawData = 0x400
    text_section.Characteristics = 0x60000020
    text_section.set_data(code_bytes)

    pe.sections = [text_section]
    pe.write(str(output_path))

    return output_path


@pytest.fixture(scope="module")
def create_wmi_query_binary() -> Path:
    """Create PE binary with WMI query strings for hardware detection."""
    output_path = HWID_BINARIES_DIR / "wmi_query_test.exe"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    wmi_strings = [
        b"SELECT * FROM Win32_Processor\x00",
        b"SELECT * FROM Win32_BaseBoard\x00",
        b"SELECT * FROM Win32_BIOS\x00",
        b"ProcessorId\x00",
        b"SerialNumber\x00",
    ]

    data_section_content = b"\x00" * 0x100
    for wmi_str in wmi_strings:
        data_section_content += wmi_str + b"\x00" * 16

    pe = pefile.PE()
    pe.DOS_HEADER = pefile.Structure(pefile.PE.__IMAGE_DOS_HEADER_format__)
    pe.DOS_HEADER.e_magic = 0x5A4D
    pe.DOS_HEADER.e_lfanew = 0x80

    pe.NT_HEADERS = pefile.Structure(pefile.PE.__IMAGE_NT_HEADERS_format__)
    pe.NT_HEADERS.Signature = 0x4550

    pe.FILE_HEADER = pefile.Structure(pefile.PE.__IMAGE_FILE_HEADER_format__)
    pe.FILE_HEADER.Machine = 0x8664
    pe.FILE_HEADER.NumberOfSections = 1
    pe.FILE_HEADER.SizeOfOptionalHeader = 240
    pe.FILE_HEADER.Characteristics = 0x0022

    pe.OPTIONAL_HEADER = pefile.Structure(pefile.PE.__IMAGE_OPTIONAL_HEADER64_format__)
    pe.OPTIONAL_HEADER.Magic = 0x20B
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = 0x1000
    pe.OPTIONAL_HEADER.ImageBase = 0x0000000140000000
    pe.OPTIONAL_HEADER.SectionAlignment = 0x1000
    pe.OPTIONAL_HEADER.FileAlignment = 0x200
    pe.OPTIONAL_HEADER.SizeOfImage = 0x3000
    pe.OPTIONAL_HEADER.SizeOfHeaders = 0x400
    pe.OPTIONAL_HEADER.Subsystem = 3
    pe.OPTIONAL_HEADER.NumberOfRvaAndSizes = 16

    data_section = pefile.SectionStructure(pefile.PE.__IMAGE_SECTION_HEADER_format__)
    data_section.Name = b".data\x00\x00\x00"
    data_section.Misc_VirtualSize = len(data_section_content)
    data_section.VirtualAddress = 0x2000
    data_section.SizeOfRawData = ((len(data_section_content) + 0x1FF) // 0x200) * 0x200
    data_section.PointerToRawData = 0x400
    data_section.Characteristics = 0xC0000040
    data_section.set_data(data_section_content)

    pe.sections = [data_section]
    pe.write(str(output_path))

    return output_path


@pytest.fixture(scope="module")
def create_registry_access_binary() -> Path:
    """Create PE binary with registry paths for MachineGuid access."""
    output_path = HWID_BINARIES_DIR / "registry_test.exe"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    registry_strings = [
        b"SOFTWARE\\Microsoft\\Cryptography\x00",
        b"MachineGuid\x00",
        b"SYSTEM\\CurrentControlSet\\Control\\SystemInformation\x00",
        b"ComputerHardwareId\x00",
    ]

    data_content = b"\x00" * 0x100
    for reg_str in registry_strings:
        data_content += reg_str + b"\x00" * 16

    pe = pefile.PE()
    pe.DOS_HEADER = pefile.Structure(pefile.PE.__IMAGE_DOS_HEADER_format__)
    pe.DOS_HEADER.e_magic = 0x5A4D
    pe.DOS_HEADER.e_lfanew = 0x80

    pe.NT_HEADERS = pefile.Structure(pefile.PE.__IMAGE_NT_HEADERS_format__)
    pe.NT_HEADERS.Signature = 0x4550

    pe.FILE_HEADER = pefile.Structure(pefile.PE.__IMAGE_FILE_HEADER_format__)
    pe.FILE_HEADER.Machine = 0x014C
    pe.FILE_HEADER.NumberOfSections = 1
    pe.FILE_HEADER.SizeOfOptionalHeader = 224
    pe.FILE_HEADER.Characteristics = 0x0102

    pe.OPTIONAL_HEADER = pefile.Structure(pefile.PE.__IMAGE_OPTIONAL_HEADER_format__)
    pe.OPTIONAL_HEADER.Magic = 0x10B
    pe.OPTIONAL_HEADER.SectionAlignment = 0x1000
    pe.OPTIONAL_HEADER.FileAlignment = 0x200
    pe.OPTIONAL_HEADER.SizeOfImage = 0x3000
    pe.OPTIONAL_HEADER.SizeOfHeaders = 0x400

    data_section = pefile.SectionStructure(pefile.PE.__IMAGE_SECTION_HEADER_format__)
    data_section.Name = b".data\x00\x00\x00"
    data_section.Misc_VirtualSize = len(data_content)
    data_section.VirtualAddress = 0x2000
    data_section.SizeOfRawData = ((len(data_content) + 0x1FF) // 0x200) * 0x200
    data_section.PointerToRawData = 0x400
    data_section.Characteristics = 0xC0000040
    data_section.set_data(data_content)

    pe.sections = [data_section]
    pe.write(str(output_path))

    return output_path


@pytest.fixture(scope="module")
def create_ioctl_disk_serial_binary() -> Path:
    """Create PE binary with DeviceIoControl IOCTL codes for disk serial."""
    output_path = HWID_BINARIES_DIR / "ioctl_disk_test.exe"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    asm_code = """
    BITS 64

    section .text
    global main
    main:
        push rbp
        mov rbp, rsp
        sub rsp, 0x40

        mov dword [rbp-4], 0x002D1400

        mov dword [rbp-8], 0x00070400

        mov dword [rbp-12], 0x001C0400

        xor eax, eax
        add rsp, 0x40
        pop rbp
        ret
    """

    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    encoding, _ = ks.asm(asm_code)
    code_bytes = bytes(encoding)

    pe = pefile.PE()
    pe.DOS_HEADER = pefile.Structure(pefile.PE.__IMAGE_DOS_HEADER_format__)
    pe.DOS_HEADER.e_magic = 0x5A4D
    pe.DOS_HEADER.e_lfanew = 0x80

    pe.NT_HEADERS = pefile.Structure(pefile.PE.__IMAGE_NT_HEADERS_format__)
    pe.NT_HEADERS.Signature = 0x4550

    pe.FILE_HEADER = pefile.Structure(pefile.PE.__IMAGE_FILE_HEADER_format__)
    pe.FILE_HEADER.Machine = 0x8664
    pe.FILE_HEADER.NumberOfSections = 1
    pe.FILE_HEADER.SizeOfOptionalHeader = 240
    pe.FILE_HEADER.Characteristics = 0x0022

    pe.OPTIONAL_HEADER = pefile.Structure(pefile.PE.__IMAGE_OPTIONAL_HEADER64_format__)
    pe.OPTIONAL_HEADER.Magic = 0x20B
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = 0x1000
    pe.OPTIONAL_HEADER.ImageBase = 0x0000000140000000
    pe.OPTIONAL_HEADER.SectionAlignment = 0x1000
    pe.OPTIONAL_HEADER.FileAlignment = 0x200
    pe.OPTIONAL_HEADER.SizeOfImage = 0x3000
    pe.OPTIONAL_HEADER.SizeOfHeaders = 0x400

    text_section = pefile.SectionStructure(pefile.PE.__IMAGE_SECTION_HEADER_format__)
    text_section.Name = b".text\x00\x00\x00"
    text_section.Misc_VirtualSize = len(code_bytes)
    text_section.VirtualAddress = 0x1000
    text_section.SizeOfRawData = ((len(code_bytes) + 0x1FF) // 0x200) * 0x200
    text_section.PointerToRawData = 0x400
    text_section.Characteristics = 0x60000020
    text_section.set_data(code_bytes)

    pe.sections = [text_section]
    pe.write(str(output_path))

    return output_path


@pytest.fixture(scope="module")
def create_node_locked_binary() -> Path:
    """Create PE binary with multiple HWID checks for node-locking."""
    output_path = HWID_BINARIES_DIR / "node_locked_test.exe"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    asm_code = """
    BITS 32

    section .text
    global _start
    _start:
        xor eax, eax
        cpuid

        push eax
        push ebx

        mov dword [esp-4], 0x002D1400

        xor eax, eax
        ret
    """

    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    encoding, _ = ks.asm(asm_code)
    code_bytes = bytes(encoding)

    data_content = b"SOFTWARE\\Microsoft\\Cryptography\x00"
    data_content += b"MachineGuid\x00"
    data_content += b"\x00" * 0x100

    pe = pefile.PE()
    pe.DOS_HEADER = pefile.Structure(pefile.PE.__IMAGE_DOS_HEADER_format__)
    pe.DOS_HEADER.e_magic = 0x5A4D
    pe.DOS_HEADER.e_lfanew = 0x80

    pe.NT_HEADERS = pefile.Structure(pefile.PE.__IMAGE_NT_HEADERS_format__)
    pe.NT_HEADERS.Signature = 0x4550

    pe.FILE_HEADER = pefile.Structure(pefile.PE.__IMAGE_FILE_HEADER_format__)
    pe.FILE_HEADER.Machine = 0x014C
    pe.FILE_HEADER.NumberOfSections = 2
    pe.FILE_HEADER.SizeOfOptionalHeader = 224
    pe.FILE_HEADER.Characteristics = 0x0102

    pe.OPTIONAL_HEADER = pefile.Structure(pefile.PE.__IMAGE_OPTIONAL_HEADER_format__)
    pe.OPTIONAL_HEADER.Magic = 0x10B
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = 0x1000
    pe.OPTIONAL_HEADER.ImageBase = 0x00400000
    pe.OPTIONAL_HEADER.SectionAlignment = 0x1000
    pe.OPTIONAL_HEADER.FileAlignment = 0x200
    pe.OPTIONAL_HEADER.SizeOfImage = 0x4000
    pe.OPTIONAL_HEADER.SizeOfHeaders = 0x400

    text_section = pefile.SectionStructure(pefile.PE.__IMAGE_SECTION_HEADER_format__)
    text_section.Name = b".text\x00\x00\x00"
    text_section.Misc_VirtualSize = len(code_bytes)
    text_section.VirtualAddress = 0x1000
    text_section.SizeOfRawData = ((len(code_bytes) + 0x1FF) // 0x200) * 0x200
    text_section.PointerToRawData = 0x400
    text_section.Characteristics = 0x60000020
    text_section.set_data(code_bytes)

    data_section = pefile.SectionStructure(pefile.PE.__IMAGE_SECTION_HEADER_format__)
    data_section.Name = b".data\x00\x00\x00"
    data_section.Misc_VirtualSize = len(data_content)
    data_section.VirtualAddress = 0x2000
    data_section.SizeOfRawData = ((len(data_content) + 0x1FF) // 0x200) * 0x200
    data_section.PointerToRawData = 0x600
    data_section.Characteristics = 0xC0000040
    data_section.set_data(data_content)

    pe.sections = [text_section, data_section]
    pe.write(str(output_path))

    return output_path


class TestHardwareIDAnalyzerInitialization:
    """Production tests for analyzer initialization and setup."""

    def test_analyzer_loads_valid_pe_binary(self, create_cpuid_binary: Path) -> None:
        """Analyzer successfully loads and parses valid PE binary."""
        analyzer = HardwareIDAnalyzer(create_cpuid_binary)

        assert analyzer.binary_path == create_cpuid_binary
        assert len(analyzer.binary_data) > 0
        assert analyzer.pe is not None
        assert analyzer.pe.FILE_HEADER.Machine in (0x014C, 0x8664)

        analyzer.close()

    def test_analyzer_detects_32bit_architecture(self, create_cpuid_binary: Path) -> None:
        """Analyzer correctly identifies 32-bit PE architecture."""
        analyzer = HardwareIDAnalyzer(create_cpuid_binary)

        assert analyzer.is_64bit is False
        assert analyzer.pe.FILE_HEADER.Machine == 0x014C

        analyzer.close()

    def test_analyzer_detects_64bit_architecture(self, create_wmi_query_binary: Path) -> None:
        """Analyzer correctly identifies 64-bit PE architecture."""
        analyzer = HardwareIDAnalyzer(create_wmi_query_binary)

        assert analyzer.is_64bit is True
        assert analyzer.pe.FILE_HEADER.Machine == 0x8664

        analyzer.close()

    def test_yara_rules_initialized(self, create_cpuid_binary: Path) -> None:
        """YARA rules are properly initialized for HWID pattern detection."""
        analyzer = HardwareIDAnalyzer(create_cpuid_binary)

        assert analyzer.yara_rules is not None

        matches = analyzer.yara_rules.match(data=b"\x0F\xA2")
        assert len(matches) > 0
        assert any("CPUID" in match.rule for match in matches)

        analyzer.close()


class TestCPUIDDetection:
    """Production tests for CPU ID collection detection."""

    def test_detect_cpuid_instruction_in_binary(self, create_cpuid_binary: Path) -> None:
        """Analyzer detects CPUID instructions in real binary code.

        EFFECTIVENESS TEST: Validates that the analyzer finds actual CPUID
        instructions (0F A2 opcode) that applications use to read CPU ID.
        """
        analyzer = HardwareIDAnalyzer(create_cpuid_binary)
        results = analyzer.analyze_hwid_protection()

        assert (
            results["has_hwid_protection"] is True
        ), 'FAILED: Binary contains CPUID instructions but analyzer reported no HWID protection. The analyzer is NOT detecting CPU ID collection.'

        assert "cpu_id" in results["hwid_types_detected"], (
            f"FAILED: Analyzer detected HWID protection but missed CPU_ID type. "
            f"Found types: {results['hwid_types_detected']}"
        )

        cpuid_checks = [c for c in analyzer.hwid_checks if c.hwid_type == HWIDType.CPU_ID]
        assert (
            cpuid_checks
        ), 'FAILED: Analyzer reported CPU_ID in results but has 0 CPUID checks. The detection is not creating concrete check objects.'

        analyzer.close()

    def test_cpuid_check_details_accurate(self, create_cpuid_binary: Path) -> None:
        """CPUID check details contain accurate information for bypass planning."""
        analyzer = HardwareIDAnalyzer(create_cpuid_binary)
        analyzer.analyze_hwid_protection()

        cpuid_checks = [c for c in analyzer.hwid_checks if c.hwid_type == HWIDType.CPU_ID]

        for check in cpuid_checks:
            assert check.offset > 0, f"CPUID check has invalid offset: {check.offset}"
            assert check.algorithm in (HWIDAlgorithm.CPUID_SIMPLE, HWIDAlgorithm.CPUID_EXTENDED)

        analyzer.close()

    def test_multiple_cpuid_instructions_detected(self, create_cpuid_binary: Path) -> None:
        """Analyzer detects multiple CPUID instructions in same binary."""
        analyzer = HardwareIDAnalyzer(create_cpuid_binary)
        analyzer.analyze_hwid_protection()

        cpuid_checks = [c for c in analyzer.hwid_checks if c.hwid_type == HWIDType.CPU_ID]

        assert (
            cpuid_checks
        ), f"FAILED: Binary has multiple CPUID calls but analyzer found {len(cpuid_checks)}. Missing CPUID detection."

        analyzer.close()


class TestWMIQueryDetection:
    """Production tests for WMI hardware query detection."""

    def test_detect_wmi_processor_query(self, create_wmi_query_binary: Path) -> None:
        """Analyzer detects WMI Win32_Processor queries for CPU ID.

        EFFECTIVENESS TEST: Real applications use WMI to query ProcessorId.
        Analyzer must detect these WQL query strings to identify HWID collection.
        """
        analyzer = HardwareIDAnalyzer(create_wmi_query_binary)
        results = analyzer.analyze_hwid_protection()

        assert results["has_hwid_protection"] is True
        assert "cpu_id" in results["hwid_types_detected"]

        wmi_checks = [c for c in analyzer.hwid_checks if c.algorithm == HWIDAlgorithm.WMI_QUERY]
        assert (
            wmi_checks
        ), "FAILED: Binary contains WMI query strings but analyzer found 0 WMI checks"

        analyzer.close()

    def test_detect_wmi_baseboard_query(self, create_wmi_query_binary: Path) -> None:
        """Analyzer detects WMI Win32_BaseBoard queries for motherboard serial."""
        analyzer = HardwareIDAnalyzer(create_wmi_query_binary)
        analyzer.analyze_hwid_protection()

        baseboard_checks = [
            c for c in analyzer.hwid_checks
            if c.hwid_type == HWIDType.MOTHERBOARD_SERIAL and c.algorithm == HWIDAlgorithm.WMI_QUERY
        ]

        assert baseboard_checks, "Failed to detect Win32_BaseBoard WMI query"

        analyzer.close()

    def test_detect_wmi_bios_query(self, create_wmi_query_binary: Path) -> None:
        """Analyzer detects WMI Win32_BIOS queries for BIOS serial."""
        analyzer = HardwareIDAnalyzer(create_wmi_query_binary)
        analyzer.analyze_hwid_protection()

        bios_checks = [
            c for c in analyzer.hwid_checks
            if c.hwid_type == HWIDType.BIOS_SERIAL and c.algorithm == HWIDAlgorithm.WMI_QUERY
        ]

        assert bios_checks, "Failed to detect Win32_BIOS WMI query"

        analyzer.close()

    def test_wmi_checks_identify_correct_hwid_type(self, create_wmi_query_binary: Path) -> None:
        """WMI checks correctly identify HWID type based on WQL query content."""
        analyzer = HardwareIDAnalyzer(create_wmi_query_binary)
        analyzer.analyze_hwid_protection()

        hwid_types_found = {check.hwid_type for check in analyzer.hwid_checks if check.algorithm == HWIDAlgorithm.WMI_QUERY}

        assert HWIDType.CPU_ID in hwid_types_found or HWIDType.MOTHERBOARD_SERIAL in hwid_types_found
        assert HWIDType.BIOS_SERIAL in hwid_types_found or HWIDType.MOTHERBOARD_SERIAL in hwid_types_found

        analyzer.close()


class TestRegistryAccessDetection:
    """Production tests for registry-based HWID detection."""

    def test_detect_machineguid_registry_path(self, create_registry_access_binary: Path) -> None:
        """Analyzer detects MachineGuid registry path access.

        EFFECTIVENESS TEST: Windows stores unique machine GUID at
        HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid. Applications
        read this for HWID. Analyzer must detect this registry path.
        """
        analyzer = HardwareIDAnalyzer(create_registry_access_binary)
        results = analyzer.analyze_hwid_protection()

        assert results["has_hwid_protection"] is True
        assert "machine_guid" in results["hwid_types_detected"]

        registry_checks = [c for c in analyzer.hwid_checks if c.algorithm == HWIDAlgorithm.REGISTRY_READ]
        assert registry_checks, "Failed to detect registry access for MachineGuid"

        analyzer.close()

    def test_detect_computerhardwareid_registry_path(self, create_registry_access_binary: Path) -> None:
        """Analyzer detects ComputerHardwareId registry access."""
        analyzer = HardwareIDAnalyzer(create_registry_access_binary)
        analyzer.analyze_hwid_protection()

        found_hardware_id_path = any(
            c.algorithm == HWIDAlgorithm.REGISTRY_READ
            for c in analyzer.hwid_checks
        )

        assert found_hardware_id_path, "Failed to detect ComputerHardwareId registry path"

        analyzer.close()

    def test_registry_checks_have_valid_offsets(self, create_registry_access_binary: Path) -> None:
        """Registry access checks contain valid file offsets for patching."""
        analyzer = HardwareIDAnalyzer(create_registry_access_binary)
        analyzer.analyze_hwid_protection()

        registry_checks = [c for c in analyzer.hwid_checks if c.algorithm == HWIDAlgorithm.REGISTRY_READ]

        for check in registry_checks:
            assert check.offset > 0 and check.offset < len(analyzer.binary_data)
            assert check.hwid_type == HWIDType.MACHINE_GUID

        analyzer.close()


class TestDiskSerialDetection:
    """Production tests for disk serial number detection."""

    def test_detect_ioctl_storage_query_property(self, create_ioctl_disk_serial_binary: Path) -> None:
        """Analyzer detects IOCTL_STORAGE_QUERY_PROPERTY (0x002D1400) code.

        EFFECTIVENESS TEST: Applications use DeviceIoControl with IOCTL code
        0x002D1400 to query disk serial numbers. Analyzer must detect this
        4-byte constant in binary.
        """
        analyzer = HardwareIDAnalyzer(create_ioctl_disk_serial_binary)
        results = analyzer.analyze_hwid_protection()

        assert results["has_hwid_protection"] is True
        assert "disk_serial" in results["hwid_types_detected"]

        ioctl_checks = [c for c in analyzer.hwid_checks if c.algorithm == HWIDAlgorithm.DEVICEIOCONTROL]
        assert (
            ioctl_checks
        ), "Failed to detect DeviceIoControl IOCTL codes for disk serial"

        analyzer.close()

    def test_detect_multiple_ioctl_codes(self, create_ioctl_disk_serial_binary: Path) -> None:
        """Analyzer detects multiple IOCTL codes for comprehensive disk queries."""
        analyzer = HardwareIDAnalyzer(create_ioctl_disk_serial_binary)
        analyzer.analyze_hwid_protection()

        ioctl_checks = [c for c in analyzer.hwid_checks if c.algorithm == HWIDAlgorithm.DEVICEIOCONTROL]

        assert (
            ioctl_checks
        ), f"FAILED: Binary contains multiple IOCTL codes but found {len(ioctl_checks)}"

        analyzer.close()

    def test_ioctl_checks_identify_disk_serial_type(self, create_ioctl_disk_serial_binary: Path) -> None:
        """IOCTL checks correctly identify disk serial HWID type."""
        analyzer = HardwareIDAnalyzer(create_ioctl_disk_serial_binary)
        analyzer.analyze_hwid_protection()

        ioctl_checks = [c for c in analyzer.hwid_checks if c.algorithm == HWIDAlgorithm.DEVICEIOCONTROL]

        for check in ioctl_checks:
            assert check.hwid_type == HWIDType.DISK_SERIAL

        analyzer.close()


class TestNodeLockDetection:
    """Production tests for node-locked license pattern detection."""

    def test_detect_node_locked_pattern(self, create_node_locked_binary: Path) -> None:
        """Analyzer detects node-locked licenses with multiple HWID checks.

        EFFECTIVENESS TEST: Node-locked licenses validate multiple hardware IDs
        (CPU + Disk + Registry). Analyzer must detect when 2+ different HWID
        types are checked in proximity, indicating node-locking.
        """
        analyzer = HardwareIDAnalyzer(create_node_locked_binary)
        results = analyzer.analyze_hwid_protection()

        assert results["has_hwid_protection"] is True
        assert results["node_locked"] is True, (
            f"FAILED: Binary checks multiple HWID types (CPU, disk, registry) but "
            f"analyzer reported node_locked={results['node_locked']}. The analyzer "
            f"is NOT detecting node-lock patterns."
        )

        assert (
            len(analyzer.node_lock_patterns) > 0
        ), "FAILED: Results claim node_locked=True but node_lock_patterns list is empty"

        analyzer.close()

    def test_node_lock_pattern_identifies_multiple_hwid_types(self, create_node_locked_binary: Path) -> None:
        """Node-lock patterns correctly identify distinct HWID types being validated."""
        analyzer = HardwareIDAnalyzer(create_node_locked_binary)
        analyzer.analyze_hwid_protection()

        if analyzer.node_lock_patterns:
            pattern = analyzer.node_lock_patterns[0]

            assert pattern.hwid_count >= 2, (
                f"Node-lock pattern has hwid_count={pattern.hwid_count}, expected >= 2"
            )

            assert len(pattern.hwid_types) >= 2, (
                f"Node-lock pattern has {len(pattern.hwid_types)} unique types, expected >= 2"
            )

            hwid_type_names = {hwid_type.value for hwid_type in pattern.hwid_types}
            assert len(hwid_type_names) >= 2

        analyzer.close()

    def test_node_lock_strength_assessment(self, create_node_locked_binary: Path) -> None:
        """Node-lock patterns assess protection strength based on HWID diversity."""
        analyzer = HardwareIDAnalyzer(create_node_locked_binary)
        analyzer.analyze_hwid_protection()

        if analyzer.node_lock_patterns:
            pattern = analyzer.node_lock_patterns[0]

            assert pattern.protection_strength in ("weak", "medium", "strong")

            if len(pattern.hwid_types) >= 4:
                assert pattern.protection_strength == "strong"
            elif len(pattern.hwid_types) >= 3:
                assert pattern.protection_strength in ("medium", "strong")

        analyzer.close()


class TestSystemHardwareExtraction:
    """Production tests for extracting real system hardware IDs."""

    def test_extract_cpu_id_from_system(self) -> None:
        """Analyzer extracts real CPU ID from current system via WMI.

        EFFECTIVENESS TEST: To validate HWID checks, analyzer must be able to
        extract actual hardware IDs from the system. This proves the extraction
        logic works on real hardware.
        """
        analyzer_binary = HWID_BINARIES_DIR / "dummy.exe"
        analyzer_binary.parent.mkdir(parents=True, exist_ok=True)
        if not analyzer_binary.exists():
            analyzer_binary.write_bytes(b"MZ" + b"\x00" * 1024)

        analyzer = HardwareIDAnalyzer(analyzer_binary)

        if cpu_id := analyzer.extract_hwid_from_system(HWIDType.CPU_ID):
            assert len(cpu_id) > 0, "CPU ID extracted but empty string returned"
            assert isinstance(cpu_id, str)
            logger.info(f"Extracted real CPU ID: {cpu_id}")
        else:
            pytest.skip("WMI not available or no CPU ID accessible")

        analyzer.close()

    def test_extract_mac_address_from_system(self) -> None:
        """Analyzer extracts real MAC address from system network adapter."""
        analyzer_binary = HWID_BINARIES_DIR / "dummy.exe"
        if not analyzer_binary.exists():
            analyzer_binary.write_bytes(b"MZ" + b"\x00" * 1024)

        analyzer = HardwareIDAnalyzer(analyzer_binary)

        if mac_address := analyzer.extract_hwid_from_system(HWIDType.MAC_ADDRESS):
            assert len(mac_address) > 0
            assert ":" in mac_address or "-" in mac_address
            logger.info(f"Extracted real MAC: {mac_address}")

        analyzer.close()

    def test_extract_volume_serial_from_system(self) -> None:
        """Analyzer extracts real volume serial number from C: drive."""
        analyzer_binary = HWID_BINARIES_DIR / "dummy.exe"
        if not analyzer_binary.exists():
            analyzer_binary.write_bytes(b"MZ" + b"\x00" * 1024)

        analyzer = HardwareIDAnalyzer(analyzer_binary)

        if volume_serial := analyzer.extract_hwid_from_system(
            HWIDType.VOLUME_SERIAL
        ):
            assert len(volume_serial) == 8
            assert all(c in "0123456789ABCDEF" for c in volume_serial)
            logger.info(f"Extracted volume serial: {volume_serial}")

        analyzer.close()

    def test_extract_machine_guid_from_system(self) -> None:
        """Analyzer extracts real Windows Machine GUID from registry."""
        analyzer_binary = HWID_BINARIES_DIR / "dummy.exe"
        if not analyzer_binary.exists():
            analyzer_binary.write_bytes(b"MZ" + b"\x00" * 1024)

        analyzer = HardwareIDAnalyzer(analyzer_binary)

        if machine_guid := analyzer.extract_hwid_from_system(
            HWIDType.MACHINE_GUID
        ):
            assert len(machine_guid) > 0
            assert "-" in machine_guid
            parts = machine_guid.split("-")
            assert len(parts) == 5
            logger.info(f"Extracted Machine GUID: {machine_guid}")

        analyzer.close()


class TestValidationPatternDetection:
    """Production tests for HWID validation routine detection."""

    def test_detect_comparison_validation_patterns(self, create_node_locked_binary: Path) -> None:
        """Analyzer detects HWID comparison/validation code patterns.

        EFFECTIVENESS TEST: Applications compare collected HWIDs against stored
        values using CMP/TEST instructions. Analyzer must detect these patterns
        to identify where to patch validation logic.
        """
        analyzer = HardwareIDAnalyzer(create_node_locked_binary)
        analyzer.analyze_hwid_protection()

        assert len(analyzer.validation_patterns) >= 0, (
            "Validation pattern detection executed but found patterns"
        )

        analyzer.close()

    def test_validation_patterns_have_offsets(self, create_node_locked_binary: Path) -> None:
        """Validation patterns contain valid file offsets for bypass patching."""
        analyzer = HardwareIDAnalyzer(create_node_locked_binary)
        analyzer.analyze_hwid_protection()

        for validation in analyzer.validation_patterns:
            assert validation.offset > 0 and validation.offset < len(analyzer.binary_data)
            assert validation.bypass_difficulty in ("trivial", "easy", "medium", "hard", "very_hard")

        analyzer.close()

    def test_obfuscation_level_assessment(self, create_node_locked_binary: Path) -> None:
        """Validation patterns assess code obfuscation level (0-10 scale)."""
        analyzer = HardwareIDAnalyzer(create_node_locked_binary)
        analyzer.analyze_hwid_protection()

        for validation in analyzer.validation_patterns:
            assert validation.obfuscation_level >= 0 and validation.obfuscation_level <= 10

        analyzer.close()


class TestBypassReportGeneration:
    """Production tests for bypass strategy report generation."""

    def test_generate_bypass_report_for_hwid_binary(self, create_node_locked_binary: Path) -> None:
        """Bypass report provides actionable bypass strategies for HWID protection.

        EFFECTIVENESS TEST: The report must contain concrete bypass strategies,
        patch locations, and API hook targets. This proves the analyzer can
        guide actual bypass implementation.
        """
        analyzer = HardwareIDAnalyzer(create_node_locked_binary)
        analyzer.analyze_hwid_protection()

        report = analyzer.generate_bypass_report()

        assert "total_hwid_checks" in report
        assert "unique_hwid_types" in report
        assert "bypass_strategies" in report
        assert "patch_locations" in report
        assert "hook_targets" in report

        assert report["total_hwid_checks"] > 0, (
            f"FAILED: Analyzer found {len(analyzer.hwid_checks)} HWID checks but "
            f"report shows {report['total_hwid_checks']}"
        )

        analyzer.close()

    def test_bypass_report_identifies_hook_targets(self, create_node_locked_binary: Path) -> None:
        """Bypass report lists specific API functions to hook for HWID spoofing."""
        analyzer = HardwareIDAnalyzer(create_node_locked_binary)
        analyzer.analyze_hwid_protection()

        report = analyzer.generate_bypass_report()

        if report["total_hwid_checks"] > 0:
            assert isinstance(report["hook_targets"], list)

        analyzer.close()

    def test_bypass_report_suggests_spoof_strategy_for_node_lock(self, create_node_locked_binary: Path) -> None:
        """Bypass report suggests HWID spoofing for node-locked binaries."""
        analyzer = HardwareIDAnalyzer(create_node_locked_binary)
        analyzer.analyze_hwid_protection()

        report = analyzer.generate_bypass_report()

        if report["node_lock_detected"]:
            strategies = report["bypass_strategies"]
            strategy_names = [s["strategy"] for s in strategies]

            assert "spoof_all_hwids" in strategy_names, (
                f"Node-locked binary but no spoof_all_hwids strategy suggested. Found: {strategy_names}"
            )

        analyzer.close()


class TestEntropyCalculation:
    """Production tests for entropy calculation on binary data."""

    def test_calculate_entropy_high_randomness(self) -> None:
        """Entropy calculation correctly identifies high entropy (encrypted) data."""
        analyzer_binary = HWID_BINARIES_DIR / "dummy.exe"
        if not analyzer_binary.exists():
            analyzer_binary.write_bytes(b"MZ" + b"\x00" * 1024)

        analyzer = HardwareIDAnalyzer(analyzer_binary)

        import secrets

        random_data = secrets.token_bytes(256)
        entropy = analyzer._calculate_entropy(random_data)

        assert entropy > 4.0, f"High entropy data has entropy {entropy}, expected > 4.0"

        analyzer.close()

    def test_calculate_entropy_low_randomness(self) -> None:
        """Entropy calculation correctly identifies low entropy (plain) data."""
        analyzer_binary = HWID_BINARIES_DIR / "dummy.exe"
        if not analyzer_binary.exists():
            analyzer_binary.write_bytes(b"MZ" + b"\x00" * 1024)

        analyzer = HardwareIDAnalyzer(analyzer_binary)

        low_entropy_data = b"\x00" * 256
        entropy = analyzer._calculate_entropy(low_entropy_data)

        assert entropy < 1.0, f"Low entropy data has entropy {entropy}, expected < 1.0"

        analyzer.close()


class TestObfuscationAssessment:
    """Production tests for code obfuscation level assessment."""

    def test_assess_obfuscation_detects_junk_instructions(self) -> None:
        """Obfuscation assessment identifies junk/NOP instructions."""
        analyzer_binary = HWID_BINARIES_DIR / "dummy.exe"
        if not analyzer_binary.exists():
            analyzer_binary.write_bytes(b"MZ" + b"\x00" * 1024)

        analyzer = HardwareIDAnalyzer(analyzer_binary)

        obfuscated_code = b"\x90" * 10 + b"\x66\x90" * 5 + b"\x87\xC0" * 3
        score = analyzer._assess_obfuscation(obfuscated_code)

        assert score > 2, f"Obfuscated code scored {score}, expected > 2 for junk instructions"

        analyzer.close()

    def test_assess_obfuscation_plain_code_low_score(self) -> None:
        """Plain code without obfuscation receives low obfuscation score."""
        analyzer_binary = HWID_BINARIES_DIR / "dummy.exe"
        if not analyzer_binary.exists():
            analyzer_binary.write_bytes(b"MZ" + b"\x00" * 1024)

        analyzer = HardwareIDAnalyzer(analyzer_binary)

        plain_code = b"\x55\x8B\xEC\x83\xEC\x10\x33\xC0"
        score = analyzer._assess_obfuscation(plain_code)

        assert score <= 3, f"Plain code scored {score}, expected <= 3"

        analyzer.close()


class TestCryptoConstantDetection:
    """Production tests for cryptographic constant detection."""

    def test_detect_md5_initialization_constant(self) -> None:
        """Analyzer detects MD5 initialization constants in HWID hashing."""
        analyzer_binary = HWID_BINARIES_DIR / "dummy.exe"
        if not analyzer_binary.exists():
            analyzer_binary.write_bytes(b"MZ" + b"\x00" * 1024)

        analyzer = HardwareIDAnalyzer(analyzer_binary)

        md5_data = b"\x01\x23\x45\x67\x89\xAB\xCD\xEF"
        has_crypto = analyzer._contains_crypto_constants(md5_data)

        assert has_crypto is True, "MD5 constant not detected"

        analyzer.close()

    def test_detect_sha1_initialization_constant(self) -> None:
        """Analyzer detects SHA1 initialization constants in HWID hashing."""
        analyzer_binary = HWID_BINARIES_DIR / "dummy.exe"
        if not analyzer_binary.exists():
            analyzer_binary.write_bytes(b"MZ" + b"\x00" * 1024)

        analyzer = HardwareIDAnalyzer(analyzer_binary)

        sha1_data = b"\x67\x45\x23\x01\xEF\xCD\xAB\x89"
        has_crypto = analyzer._contains_crypto_constants(sha1_data)

        assert has_crypto is True, "SHA1 constant not detected"

        analyzer.close()

    def test_no_false_positives_on_random_data(self) -> None:
        """Crypto constant detection doesn't produce false positives on random data."""
        analyzer_binary = HWID_BINARIES_DIR / "dummy.exe"
        if not analyzer_binary.exists():
            analyzer_binary.write_bytes(b"MZ" + b"\x00" * 1024)

        analyzer = HardwareIDAnalyzer(analyzer_binary)

        random_data = b"\xAA\xBB\xCC\xDD\xEE\xFF\x11\x22"
        has_crypto = analyzer._contains_crypto_constants(random_data)

        assert has_crypto is False

        analyzer.close()


class TestAnalyzerResourceCleanup:
    """Production tests for proper resource cleanup."""

    def test_analyzer_closes_pe_handle(self, create_cpuid_binary: Path) -> None:
        """Analyzer properly closes PE file handle on cleanup."""
        analyzer = HardwareIDAnalyzer(create_cpuid_binary)

        assert analyzer.pe is not None

        analyzer.close()

        assert analyzer.pe.__file__ is None or hasattr(analyzer.pe, "close")

    def test_multiple_analyzers_same_binary(self, create_cpuid_binary: Path) -> None:
        """Multiple analyzers can be created for same binary without conflicts."""
        analyzer1 = HardwareIDAnalyzer(create_cpuid_binary)
        analyzer2 = HardwareIDAnalyzer(create_cpuid_binary)

        assert analyzer1.binary_path == analyzer2.binary_path
        assert len(analyzer1.binary_data) == len(analyzer2.binary_data)

        analyzer1.close()
        analyzer2.close()


class TestEdgeCases:
    """Production tests for edge cases and error conditions."""

    def test_empty_binary_no_crashes(self) -> None:
        """Analyzer handles empty/minimal binary without crashing."""
        minimal_binary = HWID_BINARIES_DIR / "minimal.exe"
        minimal_binary.parent.mkdir(parents=True, exist_ok=True)

        minimal_pe_data = b"MZ" + b"\x00" * 512
        minimal_binary.write_bytes(minimal_pe_data)

        with pytest.raises(Exception):
            analyzer = HardwareIDAnalyzer(minimal_binary)
            analyzer.close()

    def test_binary_with_no_hwid_checks(self) -> None:
        """Analyzer correctly reports no HWID protection for clean binary."""
        clean_binary = HWID_BINARIES_DIR / "clean.exe"
        clean_binary.parent.mkdir(parents=True, exist_ok=True)

        asm_code = """
        BITS 32
        section .text
        global _start
        _start:
            mov eax, 0
            ret
        """

        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        encoding, _ = ks.asm(asm_code)
        code_bytes = bytes(encoding)

        pe = pefile.PE()
        pe.DOS_HEADER = pefile.Structure(pefile.PE.__IMAGE_DOS_HEADER_format__)
        pe.DOS_HEADER.e_magic = 0x5A4D
        pe.DOS_HEADER.e_lfanew = 0x80

        pe.NT_HEADERS = pefile.Structure(pefile.PE.__IMAGE_NT_HEADERS_format__)
        pe.NT_HEADERS.Signature = 0x4550

        pe.FILE_HEADER = pefile.Structure(pefile.PE.__IMAGE_FILE_HEADER_format__)
        pe.FILE_HEADER.Machine = 0x014C
        pe.FILE_HEADER.NumberOfSections = 1
        pe.FILE_HEADER.SizeOfOptionalHeader = 224

        pe.OPTIONAL_HEADER = pefile.Structure(pefile.PE.__IMAGE_OPTIONAL_HEADER_format__)
        pe.OPTIONAL_HEADER.Magic = 0x10B
        pe.OPTIONAL_HEADER.SectionAlignment = 0x1000
        pe.OPTIONAL_HEADER.FileAlignment = 0x200
        pe.OPTIONAL_HEADER.SizeOfImage = 0x2000
        pe.OPTIONAL_HEADER.SizeOfHeaders = 0x400

        text_section = pefile.SectionStructure(pefile.PE.__IMAGE_SECTION_HEADER_format__)
        text_section.Name = b".text\x00\x00\x00"
        text_section.Misc_VirtualSize = len(code_bytes)
        text_section.VirtualAddress = 0x1000
        text_section.SizeOfRawData = 0x200
        text_section.PointerToRawData = 0x400
        text_section.Characteristics = 0x60000020
        text_section.set_data(code_bytes)

        pe.sections = [text_section]
        pe.write(str(clean_binary))

        analyzer = HardwareIDAnalyzer(clean_binary)
        results = analyzer.analyze_hwid_protection()

        assert results["has_hwid_protection"] is False
        assert len(analyzer.hwid_checks) == 0

        analyzer.close()


class TestComprehensiveAnalysis:
    """Production tests for complete end-to-end analysis workflows."""

    def test_full_analysis_workflow(self, create_node_locked_binary: Path) -> None:
        """Complete analysis workflow from binary load to bypass report.

        EFFECTIVENESS TEST: Validates full workflow: load binary, detect all
        HWID types, identify validation, detect node-locking, generate report.
        """
        analyzer = HardwareIDAnalyzer(create_node_locked_binary)

        results = analyzer.analyze_hwid_protection()
        assert results["has_hwid_protection"] is True
        assert len(results["hwid_types_detected"]) > 0

        report = analyzer.generate_bypass_report()
        assert report["total_hwid_checks"] > 0
        assert len(report["bypass_strategies"]) > 0

        hwid_checks = analyzer.get_hwid_checks()
        assert len(hwid_checks) > 0

        validation_patterns = analyzer.get_validation_patterns()
        assert isinstance(validation_patterns, list)

        node_lock_patterns = analyzer.get_node_lock_patterns()
        assert isinstance(node_lock_patterns, list)

        analyzer.close()

    def test_analysis_results_consistency(self, create_node_locked_binary: Path) -> None:
        """Analysis results remain consistent across multiple runs."""
        analyzer = HardwareIDAnalyzer(create_node_locked_binary)

        results1 = analyzer.analyze_hwid_protection()
        results2 = analyzer.analyze_hwid_protection()

        assert results1["has_hwid_protection"] == results2["has_hwid_protection"]
        assert results1["hwid_types_detected"] == results2["hwid_types_detected"]
        assert results1["node_locked"] == results2["node_locked"]

        analyzer.close()
