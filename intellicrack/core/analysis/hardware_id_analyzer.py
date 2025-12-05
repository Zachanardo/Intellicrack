"""Hardware ID Analysis Engine for Detecting and Analyzing HWID-Based License Protection.

Analyzes binaries to identify hardware ID collection, validation, and node-locking mechanisms.
Detects CPU ID, disk serial, MAC address, BIOS/SMBIOS, and other hardware fingerprinting methods.

Copyright (C) 2025 Zachary Flint
SPDX-License-Identifier: GPL-3.0-or-later
"""

import ctypes
import ctypes.wintypes
import hashlib
import logging
import re
import struct
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

import pefile
import yara
from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

from intellicrack.handlers.wmi_handler import wmi


logger = logging.getLogger(__name__)


class HWIDType(Enum):
    """Types of hardware identifiers."""

    CPU_ID = "cpu_id"
    DISK_SERIAL = "disk_serial"
    MAC_ADDRESS = "mac_address"
    MOTHERBOARD_SERIAL = "motherboard_serial"
    BIOS_SERIAL = "bios_serial"
    VOLUME_SERIAL = "volume_serial"
    GPU_ID = "gpu_id"
    SYSTEM_UUID = "system_uuid"
    MACHINE_GUID = "machine_guid"
    USB_DEVICE = "usb_device"
    NETWORK_ADAPTER = "network_adapter"


class HWIDAlgorithm(Enum):
    """Known HWID generation algorithms."""

    CPUID_SIMPLE = "cpuid_simple"
    CPUID_EXTENDED = "cpuid_extended"
    WMI_QUERY = "wmi_query"
    REGISTRY_READ = "registry_read"
    SMBIOS_TABLE = "smbios_table"
    DEVICEIOCONTROL = "device_io_control"
    SETUPAPI = "setup_api"
    NETAPI = "net_api"
    WBEM = "wbem"
    CUSTOM_HASH = "custom_hash"


@dataclass
class HWIDCheck:
    """Detected hardware ID check in binary."""

    offset: int
    hwid_type: HWIDType
    algorithm: HWIDAlgorithm
    api_calls: list[str]
    validation_routine: int
    entropy: float
    disassembly: str
    is_encrypted: bool
    hash_algorithm: str | None


@dataclass
class HWIDValidation:
    """Hardware ID validation pattern detected in binary."""

    offset: int
    validation_type: str
    comparison_value: bytes
    encryption_used: bool
    obfuscation_level: int
    bypass_difficulty: str


@dataclass
class NodeLockPattern:
    """Node-locked license pattern."""

    offset: int
    hwid_count: int
    hwid_types: list[HWIDType]
    validation_address: int
    is_layered: bool
    protection_strength: str


class HardwareIDAnalyzer:
    """Analyzes binaries for hardware ID based license protection mechanisms."""

    def __init__(self, binary_path: str | Path) -> None:
        """Initialize hardware ID analyzer with target binary."""
        self.binary_path = Path(binary_path)
        self.binary_data = self.binary_path.read_bytes()
        self.pe = pefile.PE(data=self.binary_data, fast_load=False)
        self.pe.parse_data_directories()

        self.hwid_checks: list[HWIDCheck] = []
        self.validation_patterns: list[HWIDValidation] = []
        self.node_lock_patterns: list[NodeLockPattern] = []

        self.is_64bit = self.pe.FILE_HEADER.Machine == 0x8664
        self.disasm = Cs(CS_ARCH_X86, CS_MODE_64 if self.is_64bit else CS_MODE_32)
        self.disasm.detail = True

        self.kernel32 = ctypes.windll.kernel32
        self.wmi_conn = wmi.WMI()

        self._init_yara_rules()

    def _init_yara_rules(self) -> None:
        """Initialize YARA rules for detecting HWID collection patterns."""
        rules_source = r"""
        rule CPUID_Instruction {
            meta:
                description = "Detects CPUID instruction for CPU ID collection"
            strings:
                $cpuid = { 0F A2 }
                $cpuid_with_eax = { 31 C0 0F A2 }
                $cpuid_leaf1 = { B8 01 00 00 00 0F A2 }
                $cpuid_vendor = { 31 C0 0F A2 }
            condition:
                any of them
        }

        rule WMI_Hardware_Query {
            meta:
                description = "Detects WMI queries for hardware information"
            strings:
                $wmi1 = "Win32_Processor" wide ascii
                $wmi2 = "Win32_BaseBoard" wide ascii
                $wmi3 = "Win32_BIOS" wide ascii
                $wmi4 = "Win32_DiskDrive" wide ascii
                $wmi5 = "Win32_NetworkAdapter" wide ascii
                $wmi6 = "Win32_ComputerSystemProduct" wide ascii
                $processorid = "ProcessorId" wide ascii
                $serialnumber = "SerialNumber" wide ascii
            condition:
                2 of ($wmi*) or any of ($processorid, $serialnumber)
        }

        rule Disk_Serial_Query {
            meta:
                description = "Detects disk serial number queries"
            strings:
                $ioctl1 = { 00 14 2D 00 }
                $ioctl2 = { 00 04 74 00 }
                $api1 = "GetVolumeInformationW" ascii
                $api2 = "GetVolumeInformationA" ascii
                $smartctl = "SMART_RCV_DRIVE_DATA" wide ascii
            condition:
                any of them
        }

        rule MAC_Address_Collection {
            meta:
                description = "Detects MAC address collection methods"
            strings:
                $api1 = "GetAdaptersInfo" ascii
                $api2 = "GetAdaptersAddresses" ascii
                $iphlp = "IPHLPAPI.dll" wide ascii nocase
                $netbios = "NetBIOS" wide ascii
                $arp = "SendARP" ascii
            condition:
                any of them
        }

        rule SMBIOS_Table_Access {
            meta:
                description = "Detects SMBIOS/DMI table parsing"
            strings:
                $smbios1 = { 5F 53 4D 5F }
                $smbios2 = { 5F 53 4D 33 5F }
                $api = "GetSystemFirmwareTable" ascii
                $firm_type = { 52 53 4D 42 }
            condition:
                any of them
        }

        rule Registry_MachineGuid {
            meta:
                description = "Detects Windows Machine GUID access"
            strings:
                $reg1 = "SOFTWARE\\Microsoft\\Cryptography" wide ascii
                $reg2 = "MachineGuid" wide ascii
                $reg3 = "ComputerHardwareId" wide ascii
                $reg4 = "SYSTEM\\CurrentControlSet\\Control\\SystemInformation" wide ascii
            condition:
                any of them
        }

        rule HWID_Hashing_Pattern {
            meta:
                description = "Detects hardware ID hashing/fingerprinting"
            strings:
                $md5_init = { 01 23 45 67 89 AB CD EF }
                $sha1_init = { 67 45 23 01 EF CD AB 89 }
                $sha256_init = { 6A 09 E667 BB 67 AE 85 }
                $crc32_table = { 00 00 00 00 77 07 30 96 }
            condition:
                any of them
        }

        rule USB_Device_Enumeration {
            meta:
                description = "Detects USB device enumeration for dongles"
            strings:
                $setupapi = "SetupDiEnumDeviceInfo" ascii
                $setupapi2 = "SetupDiGetDeviceRegistryProperty" ascii
                $usb_guid = { A5 DC BF 10 }
                $hid_guid = { 74 5A 17 A0 }
            condition:
                any of them
        }

        rule Node_Lock_Validation {
            meta:
                description = "Detects node-locked license validation"
            strings:
                $compare1 = { 3B ?? 75 ?? 3B ?? 75 ?? 3B ?? 75 }
                $compare2 = { 39 ?? 0F 85 ?? ?? ?? ?? 39 ?? 0F 85 }
                $multi_check = { 85 C0 74 ?? E8 ?? ?? ?? ?? 85 C0 74 ?? E8 ?? ?? ?? ?? 85 C0 74 }
            condition:
                any of them
        }
        """

        self.yara_rules = yara.compile(source=rules_source)

    def analyze_hwid_protection(self) -> dict[str, Any]:
        """Perform comprehensive analysis of hardware ID protection mechanisms."""
        results: dict[str, Any] = {
            "has_hwid_protection": False,
            "hwid_types_detected": [],
            "algorithms_used": [],
            "api_imports": [],
            "validation_count": 0,
            "node_locked": False,
            "obfuscation_level": "none",
            "bypass_difficulty": "easy",
        }

        self._scan_imports()
        self._scan_yara_patterns()
        self._analyze_code_sections()
        self._detect_cpuid_usage()
        self._detect_wmi_queries()
        self._detect_registry_access()
        self._detect_smbios_access()
        self._detect_device_io_control()
        self._detect_validation_routines()
        self._detect_node_locking()

        if self.hwid_checks:
            results["has_hwid_protection"] = True
            results["hwid_types_detected"] = list({check.hwid_type.value for check in self.hwid_checks})
            results["algorithms_used"] = list({check.algorithm.value for check in self.hwid_checks})
            results["validation_count"] = len(self.validation_patterns)
            results["node_locked"] = len(self.node_lock_patterns) > 0

            obfuscation_levels = [v.obfuscation_level for v in self.validation_patterns]
            if obfuscation_levels:
                avg_obfuscation = sum(obfuscation_levels) / len(obfuscation_levels)
                if avg_obfuscation > 7:
                    results["obfuscation_level"] = "high"
                elif avg_obfuscation > 4:
                    results["obfuscation_level"] = "medium"
                else:
                    results["obfuscation_level"] = "low"

        return results

    def _scan_imports(self) -> None:
        """Scan IAT for hardware ID related API imports."""
        hwid_apis = {
            "GetVolumeInformationW": (HWIDType.VOLUME_SERIAL, HWIDAlgorithm.DEVICEIOCONTROL),
            "GetVolumeInformationA": (HWIDType.VOLUME_SERIAL, HWIDAlgorithm.DEVICEIOCONTROL),
            "GetAdaptersInfo": (HWIDType.MAC_ADDRESS, HWIDAlgorithm.NETAPI),
            "GetAdaptersAddresses": (HWIDType.NETWORK_ADAPTER, HWIDAlgorithm.NETAPI),
            "DeviceIoControl": (HWIDType.DISK_SERIAL, HWIDAlgorithm.DEVICEIOCONTROL),
            "GetSystemFirmwareTable": (HWIDType.BIOS_SERIAL, HWIDAlgorithm.SMBIOS_TABLE),
            "SetupDiEnumDeviceInfo": (HWIDType.USB_DEVICE, HWIDAlgorithm.SETUPAPI),
            "SetupDiGetDeviceRegistryPropertyW": (HWIDType.USB_DEVICE, HWIDAlgorithm.SETUPAPI),
            "RegQueryValueExW": (HWIDType.MACHINE_GUID, HWIDAlgorithm.REGISTRY_READ),
        }

        if not hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            return

        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    api_name = imp.name.decode() if isinstance(imp.name, bytes) else imp.name
                    if api_name in hwid_apis:
                        hwid_type, algorithm = hwid_apis[api_name]

                        check = HWIDCheck(
                            offset=imp.address,
                            hwid_type=hwid_type,
                            algorithm=algorithm,
                            api_calls=[api_name],
                            validation_routine=0,
                            entropy=0.0,
                            disassembly="",
                            is_encrypted=False,
                            hash_algorithm=None,
                        )
                        self.hwid_checks.append(check)

    def _scan_yara_patterns(self) -> None:
        """Scan binary with YARA rules for HWID patterns."""
        matches = self.yara_rules.match(data=self.binary_data)

        for match in matches:
            for string_match in match.strings:
                offset = string_match.instances[0].offset

                hwid_type = HWIDType.CPU_ID
                algorithm = HWIDAlgorithm.CPUID_SIMPLE

                if "CPUID" in match.rule:
                    hwid_type = HWIDType.CPU_ID
                    algorithm = HWIDAlgorithm.CPUID_SIMPLE
                elif "WMI" in match.rule:
                    hwid_type = HWIDType.MOTHERBOARD_SERIAL
                    algorithm = HWIDAlgorithm.WMI_QUERY
                elif "Disk" in match.rule:
                    hwid_type = HWIDType.DISK_SERIAL
                    algorithm = HWIDAlgorithm.DEVICEIOCONTROL
                elif "MAC" in match.rule:
                    hwid_type = HWIDType.MAC_ADDRESS
                    algorithm = HWIDAlgorithm.NETAPI
                elif "SMBIOS" in match.rule:
                    hwid_type = HWIDType.BIOS_SERIAL
                    algorithm = HWIDAlgorithm.SMBIOS_TABLE
                elif "MachineGuid" in match.rule:
                    hwid_type = HWIDType.MACHINE_GUID
                    algorithm = HWIDAlgorithm.REGISTRY_READ
                elif "USB" in match.rule:
                    hwid_type = HWIDType.USB_DEVICE
                    algorithm = HWIDAlgorithm.SETUPAPI

                check = HWIDCheck(
                    offset=offset,
                    hwid_type=hwid_type,
                    algorithm=algorithm,
                    api_calls=[],
                    validation_routine=0,
                    entropy=self._calculate_entropy(self.binary_data[offset : offset + 64]),
                    disassembly="",
                    is_encrypted=False,
                    hash_algorithm=None,
                )
                self.hwid_checks.append(check)

    def _analyze_code_sections(self) -> None:
        """Analyze executable code sections for HWID collection patterns."""
        for section in self.pe.sections:
            if section.Characteristics & 0x20000000:
                section_data = section.get_data()
                section_va = section.VirtualAddress

                self._find_cpuid_patterns(section_data, section_va)
                self._find_ioctl_patterns(section_data, section_va)
                self._find_hash_patterns(section_data, section_va)

    def _find_cpuid_patterns(self, data: bytes, base_va: int) -> None:
        """Find CPUID instruction patterns in code section."""
        cpuid_pattern = rb'\x0f\xa2'

        offset = 0
        while (pos := data.find(cpuid_pattern, offset)) != -1:
            context_start = max(0, pos - 20)
            context_end = min(len(data), pos + 20)
            context = data[context_start:context_end]

            disasm_text = ""
            for instr in self.disasm.disasm(context, base_va + context_start):
                disasm_text += f"{instr.mnemonic} {instr.op_str}\n"

            check = HWIDCheck(
                offset=base_va + pos,
                hwid_type=HWIDType.CPU_ID,
                algorithm=HWIDAlgorithm.CPUID_EXTENDED,
                api_calls=[],
                validation_routine=0,
                entropy=self._calculate_entropy(context),
                disassembly=disasm_text,
                is_encrypted=False,
                hash_algorithm=None,
            )
            self.hwid_checks.append(check)

            offset = pos + 2

    def _find_ioctl_patterns(self, data: bytes, base_va: int) -> None:
        """Find DeviceIoControl patterns for disk serial queries."""
        ioctl_codes = [
            b'\x00\x14\x2D\x00',
            b'\x00\x04\x74\x00',
            b'\x00\x1C\x04\x00',
        ]

        for ioctl_code in ioctl_codes:
            offset = 0
            while (pos := data.find(ioctl_code, offset)) != -1:
                check = HWIDCheck(
                    offset=base_va + pos,
                    hwid_type=HWIDType.DISK_SERIAL,
                    algorithm=HWIDAlgorithm.DEVICEIOCONTROL,
                    api_calls=["DeviceIoControl"],
                    validation_routine=0,
                    entropy=0.0,
                    disassembly="",
                    is_encrypted=False,
                    hash_algorithm=None,
                )
                self.hwid_checks.append(check)
                offset = pos + 4

    def _find_hash_patterns(self, data: bytes, base_va: int) -> None:
        """Find cryptographic hash initialization patterns for HWID fingerprinting."""
        hash_patterns = {
            b'\x01\x23\x45\x67\x89\xAB\xCD\xEF': "MD5",
            b'\x67\x45\x23\x01\xEF\xCD\xAB\x89': "SHA1",
            b'\x6A\x09\xE6\x67\xBB\x67\xAE\x85': "SHA256",
        }

        for pattern, algorithm in hash_patterns.items():
            offset = 0
            while (pos := data.find(pattern, offset)) != -1:
                context = data[max(0, pos - 32) : min(len(data), pos + 32)]

                check = HWIDCheck(
                    offset=base_va + pos,
                    hwid_type=HWIDType.SYSTEM_UUID,
                    algorithm=HWIDAlgorithm.CUSTOM_HASH,
                    api_calls=[],
                    validation_routine=0,
                    entropy=self._calculate_entropy(context),
                    disassembly="",
                    is_encrypted=True,
                    hash_algorithm=algorithm,
                )
                self.hwid_checks.append(check)
                offset = pos + len(pattern)

    def _detect_cpuid_usage(self) -> None:
        """Detect direct CPUID instruction usage for CPU ID collection."""
        for section in self.pe.sections:
            if section.Characteristics & 0x20000000:
                section_data = section.get_data()

                pattern = re.compile(rb'[\x31\x33\xB8].{0,5}\x0f\xa2', re.DOTALL)
                for match in pattern.finditer(section_data):
                    offset = section.VirtualAddress + match.start()

                    if not any(check.offset == offset for check in self.hwid_checks):
                        check = HWIDCheck(
                            offset=offset,
                            hwid_type=HWIDType.CPU_ID,
                            algorithm=HWIDAlgorithm.CPUID_EXTENDED,
                            api_calls=[],
                            validation_routine=0,
                            entropy=0.0,
                            disassembly="",
                            is_encrypted=False,
                            hash_algorithm=None,
                        )
                        self.hwid_checks.append(check)

    def _detect_wmi_queries(self) -> None:
        """Detect WMI query patterns for hardware information."""
        wmi_strings = [
            b"SELECT * FROM Win32_Processor",
            b"SELECT * FROM Win32_BaseBoard",
            b"SELECT * FROM Win32_BIOS",
            b"SELECT * FROM Win32_DiskDrive",
            b"SELECT ProcessorId FROM Win32_Processor",
            b"SELECT SerialNumber FROM",
        ]

        for wmi_string in wmi_strings:
            offset = 0
            while (pos := self.binary_data.find(wmi_string, offset)) != -1:
                hwid_type = HWIDType.MOTHERBOARD_SERIAL
                if b"Processor" in wmi_string:
                    hwid_type = HWIDType.CPU_ID
                elif b"BIOS" in wmi_string:
                    hwid_type = HWIDType.BIOS_SERIAL
                elif b"DiskDrive" in wmi_string:
                    hwid_type = HWIDType.DISK_SERIAL

                check = HWIDCheck(
                    offset=pos,
                    hwid_type=hwid_type,
                    algorithm=HWIDAlgorithm.WMI_QUERY,
                    api_calls=["IWbemServices::ExecQuery"],
                    validation_routine=0,
                    entropy=0.0,
                    disassembly="",
                    is_encrypted=False,
                    hash_algorithm=None,
                )
                self.hwid_checks.append(check)
                offset = pos + len(wmi_string)

    def _detect_registry_access(self) -> None:
        """Detect registry access for MachineGuid and hardware IDs."""
        registry_paths = [
            b"SOFTWARE\\Microsoft\\Cryptography",
            b"MachineGuid",
            b"ComputerHardwareId",
            b"SYSTEM\\CurrentControlSet\\Control\\SystemInformation",
        ]

        for reg_path in registry_paths:
            offset = 0
            while (pos := self.binary_data.find(reg_path, offset)) != -1:
                check = HWIDCheck(
                    offset=pos,
                    hwid_type=HWIDType.MACHINE_GUID,
                    algorithm=HWIDAlgorithm.REGISTRY_READ,
                    api_calls=["RegQueryValueExW"],
                    validation_routine=0,
                    entropy=0.0,
                    disassembly="",
                    is_encrypted=False,
                    hash_algorithm=None,
                )
                self.hwid_checks.append(check)
                offset = pos + len(reg_path)

    def _detect_smbios_access(self) -> None:
        """Detect SMBIOS/DMI table access for hardware serial numbers."""
        smbios_signatures = [b"_SM_", b"_SM3_", b"_DMI_"]

        for signature in smbios_signatures:
            offset = 0
            while (pos := self.binary_data.find(signature, offset)) != -1:
                check = HWIDCheck(
                    offset=pos,
                    hwid_type=HWIDType.BIOS_SERIAL,
                    algorithm=HWIDAlgorithm.SMBIOS_TABLE,
                    api_calls=["GetSystemFirmwareTable"],
                    validation_routine=0,
                    entropy=0.0,
                    disassembly="",
                    is_encrypted=False,
                    hash_algorithm=None,
                )
                self.hwid_checks.append(check)
                offset = pos + len(signature)

    def _detect_device_io_control(self) -> None:
        """Detect DeviceIoControl calls for disk and USB device queries."""
        ioctl_constants = {
            0x002D1400: HWIDType.DISK_SERIAL,
            0x00070400: HWIDType.DISK_SERIAL,
            0x001C0400: HWIDType.DISK_SERIAL,
        }

        for ioctl_code, hwid_type in ioctl_constants.items():
            ioctl_bytes = struct.pack("<I", ioctl_code)
            offset = 0
            while (pos := self.binary_data.find(ioctl_bytes, offset)) != -1:
                check = HWIDCheck(
                    offset=pos,
                    hwid_type=hwid_type,
                    algorithm=HWIDAlgorithm.DEVICEIOCONTROL,
                    api_calls=["DeviceIoControl"],
                    validation_routine=0,
                    entropy=0.0,
                    disassembly="",
                    is_encrypted=False,
                    hash_algorithm=None,
                )
                self.hwid_checks.append(check)
                offset = pos + 4

    def _detect_validation_routines(self) -> None:
        """Detect HWID validation comparison routines."""
        for section in self.pe.sections:
            if section.Characteristics & 0x20000000:
                section_data = section.get_data()
                section_va = section.VirtualAddress

                comparison_patterns = [
                    rb'\x3B.{1,2}\x75',
                    rb'\x39.{1,2}\x0F\x85',
                    rb'\x81.{1,5}\x0F\x85',
                ]

                for pattern in comparison_patterns:
                    for match in re.finditer(pattern, section_data):
                        offset = section_va + match.start()

                        context = section_data[match.start() : match.start() + 32]
                        obfuscation_score = self._assess_obfuscation(context)

                        validation = HWIDValidation(
                            offset=offset,
                            validation_type="comparison",
                            comparison_value=context[:8],
                            encryption_used=self._contains_crypto_constants(context),
                            obfuscation_level=obfuscation_score,
                            bypass_difficulty=self._assess_bypass_difficulty(obfuscation_score),
                        )
                        self.validation_patterns.append(validation)

    def _detect_node_locking(self) -> None:
        """Detect node-locked license patterns with multiple HWID checks."""
        if len(self.hwid_checks) < 2:
            return

        hwid_groups: dict[int, list[HWIDCheck]] = {}
        for check in self.hwid_checks:
            group_key = check.offset // 0x1000
            if group_key not in hwid_groups:
                hwid_groups[group_key] = []
            hwid_groups[group_key].append(check)

        for group_offset, checks in hwid_groups.items():
            if len(checks) >= 2:
                unique_types = list({check.hwid_type for check in checks})

                if len(unique_types) >= 2:
                    validation_addr = checks[0].validation_routine

                    is_layered = len(unique_types) >= 3
                    strength = "strong" if len(unique_types) >= 4 else "medium" if len(unique_types) >= 3 else "weak"

                    pattern = NodeLockPattern(
                        offset=group_offset * 0x1000,
                        hwid_count=len(checks),
                        hwid_types=unique_types,
                        validation_address=validation_addr,
                        is_layered=is_layered,
                        protection_strength=strength,
                    )
                    self.node_lock_patterns.append(pattern)

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0

        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                freq = count / data_len
                entropy -= freq * (freq.bit_length() - 1 if freq > 0 else 0)

        return entropy

    def _assess_obfuscation(self, code: bytes) -> int:
        """Assess obfuscation level of code sequence (0-10 scale)."""
        score = 0

        if len(code) < 8:
            return score

        entropy = self._calculate_entropy(code)
        if entropy > 6.0:
            score += 3
        elif entropy > 4.0:
            score += 2
        elif entropy > 2.0:
            score += 1

        junk_instructions = [b'\x90', b'\x66\x90', b'\x87\xC0', b'\x87\xDB']
        junk_count = sum(code.count(pattern) for pattern in junk_instructions)
        if junk_count > 3:
            score += 2
        elif junk_count > 1:
            score += 1

        if b'\xE8' in code or b'\xFF\x15' in code:
            score += 2

        if b'\x0F\x85' in code or b'\x0F\x84' in code:
            score += 1

        return min(score, 10)

    def _contains_crypto_constants(self, data: bytes) -> bool:
        """Check if data contains cryptographic constants."""
        crypto_patterns = [
            b'\x01\x23\x45\x67',
            b'\x67\x45\x23\x01',
            b'\x6A\x09\xE6\x67',
            b'\x98\xBA\xDC\xFE',
        ]

        return any(pattern in data for pattern in crypto_patterns)

    def _assess_bypass_difficulty(self, obfuscation_score: int) -> str:
        """Assess difficulty of bypassing HWID check based on obfuscation."""
        if obfuscation_score >= 8:
            return "very_hard"
        elif obfuscation_score >= 6:
            return "hard"
        elif obfuscation_score >= 4:
            return "medium"
        elif obfuscation_score >= 2:
            return "easy"
        return "trivial"

    def extract_hwid_from_system(self, hwid_type: HWIDType) -> str | None:
        """Extract actual hardware ID from current system."""
        try:
            if hwid_type == HWIDType.CPU_ID:
                return self._get_cpu_id()
            elif hwid_type == HWIDType.DISK_SERIAL:
                return self._get_disk_serial()
            elif hwid_type == HWIDType.MAC_ADDRESS:
                return self._get_mac_address()
            elif hwid_type == HWIDType.MOTHERBOARD_SERIAL:
                return self._get_motherboard_serial()
            elif hwid_type == HWIDType.BIOS_SERIAL:
                return self._get_bios_serial()
            elif hwid_type == HWIDType.VOLUME_SERIAL:
                return self._get_volume_serial()
            elif hwid_type == HWIDType.MACHINE_GUID:
                return self._get_machine_guid()
        except Exception as e:
            logger.error(f"Failed to extract {hwid_type.value}: {e}")
            return None

    def _get_cpu_id(self) -> str:
        """Get CPU ID from system."""
        for cpu in self.wmi_conn.Win32_Processor():
            return cpu.ProcessorId
        return ""

    def _get_disk_serial(self) -> str:
        """Get primary disk serial number."""
        for disk in self.wmi_conn.Win32_DiskDrive():
            if disk.SerialNumber:
                return disk.SerialNumber
        return ""

    def _get_mac_address(self) -> str:
        """Get primary MAC address."""
        for adapter in self.wmi_conn.Win32_NetworkAdapter():
            if adapter.MACAddress:
                return adapter.MACAddress
        return ""

    def _get_motherboard_serial(self) -> str:
        """Get motherboard serial number."""
        for board in self.wmi_conn.Win32_BaseBoard():
            if board.SerialNumber:
                return board.SerialNumber
        return ""

    def _get_bios_serial(self) -> str:
        """Get BIOS serial number."""
        for bios in self.wmi_conn.Win32_BIOS():
            if bios.SerialNumber:
                return bios.SerialNumber
        return ""

    def _get_volume_serial(self) -> str:
        """Get C: volume serial number."""
        volume_serial = ctypes.wintypes.DWORD()
        if self.kernel32.GetVolumeInformationW(
            "C:\\",
            None,
            0,
            ctypes.byref(volume_serial),
            None,
            None,
            None,
            0,
        ):
            return f"{volume_serial.value:08X}"
        return ""

    def _get_machine_guid(self) -> str:
        """Get Windows Machine GUID from registry."""
        import winreg

        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
                return winreg.QueryValueEx(key, "MachineGuid")[0]
        except OSError:
            return ""

    def generate_bypass_report(self) -> dict[str, Any]:
        """Generate comprehensive report on HWID protection bypass strategies."""
        report: dict[str, Any] = {
            "total_hwid_checks": len(self.hwid_checks),
            "unique_hwid_types": list({check.hwid_type.value for check in self.hwid_checks}),
            "validation_points": len(self.validation_patterns),
            "node_lock_detected": len(self.node_lock_patterns) > 0,
            "bypass_strategies": [],
            "patch_locations": [],
            "hook_targets": [],
        }

        for check in self.hwid_checks:
            if check.api_calls:
                report["hook_targets"].extend(check.api_calls)

        for validation in self.validation_patterns:
            patch_info = {
                "offset": validation.offset,
                "type": "nop_validation" if validation.bypass_difficulty in ("easy", "trivial") else "hook_comparison",
                "difficulty": validation.bypass_difficulty,
                "obfuscation": validation.obfuscation_level,
            }
            report["patch_locations"].append(patch_info)

        if self.node_lock_patterns:
            report["bypass_strategies"].append({
                "strategy": "spoof_all_hwids",
                "hwid_types": list({hwid_type.value for pattern in self.node_lock_patterns for hwid_type in pattern.hwid_types}),
                "priority": "high",
            })
        else:
            report["bypass_strategies"].append({
                "strategy": "hook_single_api",
                "target_apis": list(set(report["hook_targets"])),
                "priority": "medium",
            })

        return report

    def get_hwid_checks(self) -> list[HWIDCheck]:
        """Return all detected HWID checks."""
        return self.hwid_checks

    def get_validation_patterns(self) -> list[HWIDValidation]:
        """Return all detected validation patterns."""
        return self.validation_patterns

    def get_node_lock_patterns(self) -> list[NodeLockPattern]:
        """Return all detected node-lock patterns."""
        return self.node_lock_patterns

    def close(self) -> None:
        """Clean up resources."""
        if self.pe:
            self.pe.close()
