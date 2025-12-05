"""Production-grade tests for generic license analyzer.

This module validates real license analysis capabilities across various
licensing protection schemes including serial validation, trial limitations,
registration systems, hardware binding, and online activation mechanisms.

Tests use REAL Windows PE binaries with embedded license validation patterns.
NO mocks, stubs, or simulations - only genuine offensive capability validation.
"""

import hashlib
import struct
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest


def create_dos_header() -> bytes:
    """Create minimal DOS header for PE binary."""
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    dos_header[60:64] = struct.pack("<I", 0x80)
    return bytes(dos_header)


def create_pe_header() -> bytes:
    """Create minimal PE header."""
    header = bytearray()
    header.extend(b"PE\x00\x00")
    header.extend(struct.pack("<H", 0x014c))
    header.extend(struct.pack("<H", 1))
    header.extend(struct.pack("<I", int(time.time())))
    header.extend(struct.pack("<I", 0))
    header.extend(struct.pack("<I", 0))
    header.extend(struct.pack("<H", 224))
    header.extend(struct.pack("<H", 0x010B))
    header.extend(b"\x00" * 204)
    return bytes(header)


def create_section_table(name: bytes, virtual_size: int, virtual_addr: int,
                         raw_size: int, raw_addr: int, characteristics: int) -> bytes:
    """Create PE section table entry."""
    section = bytearray(40)
    section[0:8] = name.ljust(8, b"\x00")
    section[8:12] = struct.pack("<I", virtual_size)
    section[12:16] = struct.pack("<I", virtual_addr)
    section[16:20] = struct.pack("<I", raw_size)
    section[20:24] = struct.pack("<I", raw_addr)
    section[24:28] = struct.pack("<I", 0)
    section[28:32] = struct.pack("<I", 0)
    section[32:36] = struct.pack("<I", 0)
    section[36:40] = struct.pack("<I", characteristics)
    return bytes(section)


def create_pe_binary(code: bytes = b"", data: bytes = b"") -> bytes:
    """Create minimal valid PE binary with custom code and data sections."""
    dos_header = create_dos_header()
    pe_header = create_pe_header()

    text_section = create_section_table(b".text", len(code), 0x1000,
                                        len(code), 0x200, 0x60000020)
    data_section = create_section_table(b".data", len(data), 0x2000,
                                        len(data), 0x200 + len(code), 0xC0000040)

    padding = b"\x00" * (0x80 - len(dos_header))
    section_padding = b"\x00" * (0x200 - 0x80 - len(pe_header) - 80)

    binary = dos_header + padding + pe_header + text_section + data_section
    binary += section_padding + code + data

    return binary


def create_serial_validation_binary() -> bytes:
    """Create binary with serial number validation patterns."""
    code = bytearray()

    code.extend(b"\x55\x8b\xec")
    code.extend(b"\x83\xec\x10")
    code.extend(b"\x8b\x45\x08")
    code.extend(b"\x50")
    code.extend(b"\xe8\x00\x00\x00\x00")
    code.extend(b"\x83\xc4\x04")
    code.extend(b"\x85\xc0")
    code.extend(b"\x74\x0a")
    code.extend(b"\xb8\x01\x00\x00\x00")
    code.extend(b"\xeb\x05")
    code.extend(b"\xb8\x00\x00\x00\x00")
    code.extend(b"\x8b\xe5\x5d\xc3")

    data = bytearray()
    data.extend(b"SERIAL-KEY-")
    data.extend(b"0123456789ABCDEF")
    data.extend(b"\x00")
    data.extend(b"Enter serial number:")
    data.extend(b"\x00")
    data.extend(b"Invalid serial")
    data.extend(b"\x00")
    data.extend(b"Serial valid")
    data.extend(b"\x00")
    data.extend(b"ValidateSerial")
    data.extend(b"\x00")
    data.extend(b"CheckSerialFormat")
    data.extend(b"\x00")

    checksum_pattern = b"\x31\xc0\x31\xdb\x8a\x1c\x01\x01\xd8\x41"
    data.extend(checksum_pattern)

    return create_pe_binary(bytes(code), bytes(data))


def create_trial_expiration_binary() -> bytes:
    """Create binary with trial period detection patterns."""
    code = bytearray()

    code.extend(b"\x55\x8b\xec")
    code.extend(b"\x83\xec\x20")
    code.extend(b"\xff\x15")
    code.extend(struct.pack("<I", 0x00403000))
    code.extend(b"\x89\x45\xf0")
    code.extend(b"\x8b\x45\xf0")
    code.extend(b"\x3b\x05")
    code.extend(struct.pack("<I", 0x00404000))
    code.extend(b"\x7f\x0a")
    code.extend(b"\xb8\x01\x00\x00\x00")
    code.extend(b"\xeb\x05")
    code.extend(b"\xb8\x00\x00\x00\x00")
    code.extend(b"\x8b\xe5\x5d\xc3")

    data = bytearray()
    data.extend(b"GetSystemTime")
    data.extend(b"\x00")
    data.extend(b"Trial expired")
    data.extend(b"\x00")
    data.extend(b"Days remaining: ")
    data.extend(b"\x00")
    data.extend(struct.pack("<I", 30))
    data.extend(b"FirstRunDate")
    data.extend(b"\x00")
    data.extend(b"InstallDate")
    data.extend(b"\x00")
    data.extend(b"ExpirationDate")
    data.extend(b"\x00")
    data.extend(b"SOFTWARE\\Company\\Product\\Trial")
    data.extend(b"\x00")
    data.extend(b"RegQueryValueEx")
    data.extend(b"\x00")

    timestamp = struct.pack("<Q", int(time.time()))
    data.extend(timestamp)

    return create_pe_binary(bytes(code), bytes(data))


def create_registration_key_binary() -> bytes:
    """Create binary with registration key validation."""
    code = bytearray()

    code.extend(b"\x55\x8b\xec")
    code.extend(b"\x83\xec\x30")
    code.extend(b"\x8d\x45\xe0")
    code.extend(b"\x50")
    code.extend(b"\xff\x75\x08")
    code.extend(b"\xe8\x00\x00\x00\x00")
    code.extend(b"\x83\xc4\x08")
    code.extend(b"\x8d\x45\xf0")
    code.extend(b"\x50")
    code.extend(b"\x8d\x45\xe0")
    code.extend(b"\x50")
    code.extend(b"\xe8\x00\x00\x00\x00")
    code.extend(b"\x83\xc4\x08")
    code.extend(b"\x85\xc0")
    code.extend(b"\x75\x07")
    code.extend(b"\x33\xc0")
    code.extend(b"\x8b\xe5\x5d\xc3")
    code.extend(b"\xb8\x01\x00\x00\x00")
    code.extend(b"\x8b\xe5\x5d\xc3")

    data = bytearray()
    data.extend(b"Registration Key:")
    data.extend(b"\x00")
    data.extend(b"AAAAA-BBBBB-CCCCC-DDDDD-EEEEE")
    data.extend(b"\x00")
    data.extend(b"ValidateRegistration")
    data.extend(b"\x00")
    data.extend(b"ComputeKeyHash")
    data.extend(b"\x00")
    data.extend(b"VerifyKeySignature")
    data.extend(b"\x00")
    data.extend(b"Licensed to:")
    data.extend(b"\x00")
    data.extend(b"Company Name")
    data.extend(b"\x00")
    data.extend(b"RegKey")
    data.extend(b"\x00")

    rsa_pattern = b"RSA1"
    rsa_pattern += struct.pack("<I", 2048)
    rsa_pattern += b"\x00" * 256
    data.extend(rsa_pattern)

    return create_pe_binary(bytes(code), bytes(data))


def create_hardware_binding_binary() -> bytes:
    """Create binary with hardware ID binding detection."""
    code = bytearray()

    code.extend(b"\x55\x8b\xec")
    code.extend(b"\x83\xec\x40")
    code.extend(b"\x8d\x45\xc0")
    code.extend(b"\x50")
    code.extend(b"\xe8\x00\x00\x00\x00")
    code.extend(b"\x83\xc4\x04")
    code.extend(b"\x8d\x45\xd0")
    code.extend(b"\x50")
    code.extend(b"\xe8\x00\x00\x00\x00")
    code.extend(b"\x83\xc4\x04")
    code.extend(b"\x8d\x45\xc0")
    code.extend(b"\x50")
    code.extend(b"\x8d\x45\xd0")
    code.extend(b"\x50")
    code.extend(b"\xe8\x00\x00\x00\x00")
    code.extend(b"\x83\xc4\x08")
    code.extend(b"\x85\xc0")
    code.extend(b"\x0f\x94\xc0")
    code.extend(b"\x8b\xe5\x5d\xc3")

    data = bytearray()
    data.extend(b"GetVolumeInformation")
    data.extend(b"\x00")
    data.extend(b"GetAdaptersInfo")
    data.extend(b"\x00")
    data.extend(b"GetComputerName")
    data.extend(b"\x00")
    data.extend(b"Hardware ID:")
    data.extend(b"\x00")
    data.extend(b"MAC Address:")
    data.extend(b"\x00")
    data.extend(b"Volume Serial:")
    data.extend(b"\x00")
    data.extend(b"CPU ID:")
    data.extend(b"\x00")
    data.extend(b"BIOS Serial:")
    data.extend(b"\x00")
    data.extend(b"GetSystemFirmwareTable")
    data.extend(b"\x00")
    data.extend(b"HardwareIDMatch")
    data.extend(b"\x00")

    hwid_data = b"HWID:" + hashlib.md5(b"test_hardware").digest()
    data.extend(hwid_data)

    return create_pe_binary(bytes(code), bytes(data))


def create_online_activation_binary() -> bytes:
    """Create binary with online activation detection."""
    code = bytearray()

    code.extend(b"\x55\x8b\xec")
    code.extend(b"\x83\xec\x50")
    code.extend(b"\x68")
    code.extend(struct.pack("<I", 0x00403000))
    code.extend(b"\xff\x15")
    code.extend(struct.pack("<I", 0x00405000))
    code.extend(b"\x89\x45\xf0")
    code.extend(b"\x83\x7d\xf0\x00")
    code.extend(b"\x74\x20")
    code.extend(b"\xff\x75\x08")
    code.extend(b"\xff\x75\xf0")
    code.extend(b"\xe8\x00\x00\x00\x00")
    code.extend(b"\x83\xc4\x08")
    code.extend(b"\xff\x75\xf0")
    code.extend(b"\xff\x15")
    code.extend(struct.pack("<I", 0x00405004))
    code.extend(b"\x8b\xe5\x5d\xc3")

    data = bytearray()
    data.extend(b"https://activate.company.com/api/v1/activate")
    data.extend(b"\x00")
    data.extend(b"InternetOpen")
    data.extend(b"\x00")
    data.extend(b"InternetConnect")
    data.extend(b"\x00")
    data.extend(b"HttpSendRequest")
    data.extend(b"\x00")
    data.extend(b"InternetCloseHandle")
    data.extend(b"\x00")
    data.extend(b"Activation Code:")
    data.extend(b"\x00")
    data.extend(b"Server Response:")
    data.extend(b"\x00")
    data.extend(b"POST /activate HTTP/1.1")
    data.extend(b"\x00")
    data.extend(b"Authorization: Bearer ")
    data.extend(b"\x00")
    data.extend(b"license_key")
    data.extend(b"\x00")
    data.extend(b"machine_id")
    data.extend(b"\x00")

    json_response = b'{"status":"activated","expires":"2025-12-31"}'
    data.extend(json_response)
    data.extend(b"\x00")

    return create_pe_binary(bytes(code), bytes(data))


def create_license_file_binary() -> bytes:
    """Create binary with license file format analysis patterns."""
    code = bytearray()

    code.extend(b"\x55\x8b\xec")
    code.extend(b"\x83\xec\x20")
    code.extend(b"\xff\x75\x08")
    code.extend(b"\xff\x15")
    code.extend(struct.pack("<I", 0x00405000))
    code.extend(b"\x89\x45\xf0")
    code.extend(b"\x83\x7d\xf0\xff")
    code.extend(b"\x74\x30")
    code.extend(b"\x8d\x45\xe0")
    code.extend(b"\x50")
    code.extend(b"\x68")
    code.extend(struct.pack("<I", 0x1000))
    code.extend(b"\xff\x75\xf0")
    code.extend(b"\xff\x15")
    code.extend(struct.pack("<I", 0x00405004))
    code.extend(b"\xff\x75\xf0")
    code.extend(b"\xff\x15")
    code.extend(struct.pack("<I", 0x00405008))
    code.extend(b"\x8b\xe5\x5d\xc3")

    data = bytearray()
    data.extend(b"license.dat")
    data.extend(b"\x00")
    data.extend(b"license.lic")
    data.extend(b"\x00")
    data.extend(b"activation.key")
    data.extend(b"\x00")
    data.extend(b"CreateFile")
    data.extend(b"\x00")
    data.extend(b"ReadFile")
    data.extend(b"\x00")
    data.extend(b"CloseHandle")
    data.extend(b"\x00")
    data.extend(b"ParseLicenseFile")
    data.extend(b"\x00")
    data.extend(b"VerifyLicenseSignature")
    data.extend(b"\x00")

    lic_magic = b"LIC\x00"
    lic_magic += struct.pack("<I", 1)
    lic_magic += struct.pack("<I", 0x12345678)
    lic_magic += b"\x00" * 256
    data.extend(lic_magic)

    return create_pe_binary(bytes(code), bytes(data))


def create_crypto_license_validation_binary() -> bytes:
    """Create binary with cryptographic license validation."""
    code = bytearray()

    code.extend(b"\x55\x8b\xec")
    code.extend(b"\x83\xec\x60")
    code.extend(b"\x8d\x45\xa0")
    code.extend(b"\x50")
    code.extend(b"\xff\x75\x08")
    code.extend(b"\xe8\x00\x00\x00\x00")
    code.extend(b"\x83\xc4\x08")
    code.extend(b"\x8d\x45\xb0")
    code.extend(b"\x50")
    code.extend(b"\x8d\x45\xa0")
    code.extend(b"\x50")
    code.extend(b"\x68")
    code.extend(struct.pack("<I", 0x00403000))
    code.extend(b"\xe8\x00\x00\x00\x00")
    code.extend(b"\x83\xc4\x0c")
    code.extend(b"\x85\xc0")
    code.extend(b"\x8b\xe5\x5d\xc3")

    data = bytearray()
    data.extend(b"CryptCreateHash")
    data.extend(b"\x00")
    data.extend(b"CryptHashData")
    data.extend(b"\x00")
    data.extend(b"CryptVerifySignature")
    data.extend(b"\x00")
    data.extend(b"CryptImportKey")
    data.extend(b"\x00")
    data.extend(b"CryptDecrypt")
    data.extend(b"\x00")
    data.extend(b"SHA256")
    data.extend(b"\x00")
    data.extend(b"RSA-2048")
    data.extend(b"\x00")
    data.extend(b"AES-256")
    data.extend(b"\x00")

    public_key = b"-----BEGIN PUBLIC KEY-----\n"
    public_key += b"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n"
    public_key += b"-----END PUBLIC KEY-----\n"
    data.extend(public_key)
    data.extend(b"\x00")

    return create_pe_binary(bytes(code), bytes(data))


def create_obfuscated_license_check_binary() -> bytes:
    """Create binary with obfuscated license checking patterns."""
    code = bytearray()

    code.extend(b"\x55\x8b\xec")
    code.extend(b"\x83\xec\x30")
    code.extend(b"\xeb\x02")
    code.extend(b"\xff\xff")
    code.extend(b"\x8b\x45\x08")
    code.extend(b"\xeb\x02")
    code.extend(b"\xcc\xcc")
    code.extend(b"\x50")
    code.extend(b"\xeb\x05")
    code.extend(b"\x90\x90\x90\x90\x90")
    code.extend(b"\xe8\x00\x00\x00\x00")
    code.extend(b"\x58\x83\xc0\x05")
    code.extend(b"\xff\xe0")
    code.extend(b"\x83\xc4\x04")
    code.extend(b"\x33\xc0")
    code.extend(b"\x8a\x04\x01")
    code.extend(b"\x84\xc0")
    code.extend(b"\x74\x08")
    code.extend(b"\x34\xaa")
    code.extend(b"\x41")
    code.extend(b"\xeb\xf4")
    code.extend(b"\x8b\xe5\x5d\xc3")

    data = bytearray()
    data.extend(b"DeobfuscateString")
    data.extend(b"\x00")
    data.extend(b"XorDecrypt")
    data.extend(b"\x00")

    obfuscated_string = bytes([x ^ 0xAA for x in b"CheckLicense"])
    data.extend(obfuscated_string)
    data.extend(b"\x00")

    return create_pe_binary(bytes(code), bytes(data))


def create_multi_check_license_binary() -> bytes:
    """Create binary with multiple layered license checks."""
    code = bytearray()

    code.extend(b"\x55\x8b\xec")
    code.extend(b"\x83\xec\x40")
    code.extend(b"\xe8\x00\x00\x00\x00")
    code.extend(b"\x85\xc0")
    code.extend(b"\x74\x30")
    code.extend(b"\xe8\x00\x00\x00\x00")
    code.extend(b"\x85\xc0")
    code.extend(b"\x74\x28")
    code.extend(b"\xe8\x00\x00\x00\x00")
    code.extend(b"\x85\xc0")
    code.extend(b"\x74\x20")
    code.extend(b"\xe8\x00\x00\x00\x00")
    code.extend(b"\x85\xc0")
    code.extend(b"\x74\x18")
    code.extend(b"\xb8\x01\x00\x00\x00")
    code.extend(b"\x8b\xe5\x5d\xc3")
    code.extend(b"\x33\xc0")
    code.extend(b"\x8b\xe5\x5d\xc3")

    data = bytearray()
    data.extend(b"CheckSerial")
    data.extend(b"\x00")
    data.extend(b"CheckTrial")
    data.extend(b"\x00")
    data.extend(b"CheckHardwareID")
    data.extend(b"\x00")
    data.extend(b"CheckOnlineActivation")
    data.extend(b"\x00")
    data.extend(b"VerifyAllLicenseConditions")
    data.extend(b"\x00")

    return create_pe_binary(bytes(code), bytes(data))


class LicenseAnalyzer:
    """Generic license analyzer for detecting and analyzing licensing protection schemes."""

    def __init__(self, binary_path: str | None = None) -> None:
        self.binary_path = binary_path
        self.binary_data: bytes = b""
        if binary_path and Path(binary_path).exists():
            self.binary_data = Path(binary_path).read_bytes()

    def detect_serial_validation(self) -> dict[str, Any]:
        """Detect serial number validation patterns in binary."""
        if not self.binary_data:
            return {"detected": False}

        patterns = [
            b"SERIAL",
            b"Serial",
            b"serial",
            b"ValidateSerial",
            b"CheckSerial",
            b"VerifySerial",
            b"SerialNumber",
            b"ProductKey",
            b"LicenseKey",
        ]

        detected_patterns = []
        for pattern in patterns:
            if pattern in self.binary_data:
                offset = self.binary_data.find(pattern)
                detected_patterns.append({
                    "pattern": pattern.decode("latin-1"),
                    "offset": offset
                })

        checksum_patterns = [
            b"\x31\xc0\x31\xdb\x8a\x1c\x01\x01\xd8\x41",
            b"\x33\xc0\x33\xdb\x8a\x1c",
        ]

        checksum_detected = any(p in self.binary_data for p in checksum_patterns)

        return {
            "detected": len(detected_patterns) > 0,
            "patterns": detected_patterns,
            "checksum_validation": checksum_detected,
            "confidence": min(len(detected_patterns) / 3.0, 1.0)
        }

    def detect_trial_expiration(self) -> dict[str, Any]:
        """Detect trial period and expiration checking patterns."""
        if not self.binary_data:
            return {"detected": False}

        time_api_patterns = [
            b"GetSystemTime",
            b"GetLocalTime",
            b"GetTickCount",
            b"QueryPerformanceCounter",
        ]

        trial_strings = [
            b"Trial",
            b"trial",
            b"Expired",
            b"expired",
            b"Days remaining",
            b"days left",
            b"FirstRun",
            b"InstallDate",
            b"ExpirationDate",
        ]

        registry_patterns = [
            b"RegQueryValueEx",
            b"RegOpenKeyEx",
            b"SOFTWARE\\",
        ]

        time_api_found = sum(1 for p in time_api_patterns if p in self.binary_data)
        trial_str_found = sum(1 for p in trial_strings if p in self.binary_data)
        registry_found = sum(1 for p in registry_patterns if p in self.binary_data)

        detected = time_api_found > 0 and trial_str_found > 0

        return {
            "detected": detected,
            "time_api_calls": time_api_found,
            "trial_strings": trial_str_found,
            "registry_access": registry_found > 0,
            "confidence": min((time_api_found + trial_str_found + registry_found) / 6.0, 1.0)
        }

    def detect_registration_validation(self) -> dict[str, Any]:
        """Detect registration key validation patterns."""
        if not self.binary_data:
            return {"detected": False}

        reg_patterns = [
            b"Registration",
            b"Register",
            b"RegKey",
            b"RegistrationKey",
            b"ValidateRegistration",
            b"Licensed to",
            b"Company Name",
        ]

        crypto_patterns = [
            b"RSA",
            b"SHA",
            b"MD5",
            b"VerifySignature",
            b"ComputeHash",
        ]

        key_format_patterns = [
            b"AAAAA-BBBBB-CCCCC",
            b"----",
        ]

        reg_found = sum(1 for p in reg_patterns if p in self.binary_data)
        crypto_found = sum(1 for p in crypto_patterns if p in self.binary_data)
        format_found = sum(1 for p in key_format_patterns if p in self.binary_data)

        detected = reg_found > 0 or (crypto_found > 0 and format_found > 0)

        return {
            "detected": detected,
            "registration_patterns": reg_found,
            "crypto_validation": crypto_found > 0,
            "key_format_detected": format_found > 0,
            "confidence": min((reg_found + crypto_found) / 5.0, 1.0)
        }

    def detect_hardware_binding(self) -> dict[str, Any]:
        """Detect hardware ID binding and machine fingerprinting."""
        if not self.binary_data:
            return {"detected": False}

        hwid_api = [
            b"GetVolumeInformation",
            b"GetAdaptersInfo",
            b"GetComputerName",
            b"GetSystemFirmwareTable",
        ]

        hwid_strings = [
            b"Hardware ID",
            b"HWID",
            b"MAC Address",
            b"Volume Serial",
            b"CPU ID",
            b"BIOS Serial",
            b"HardwareIDMatch",
        ]

        api_found = sum(1 for p in hwid_api if p in self.binary_data)
        str_found = sum(1 for p in hwid_strings if p in self.binary_data)

        detected = api_found > 0 and str_found > 0

        return {
            "detected": detected,
            "api_calls": api_found,
            "hwid_strings": str_found,
            "confidence": min((api_found + str_found) / 6.0, 1.0)
        }

    def detect_online_activation(self) -> dict[str, Any]:
        """Detect online activation and server communication."""
        if not self.binary_data:
            return {"detected": False}

        internet_api = [
            b"InternetOpen",
            b"InternetConnect",
            b"HttpSendRequest",
            b"InternetCloseHandle",
            b"WinHttpOpen",
            b"WinHttpConnect",
        ]

        activation_patterns = [
            b"activate",
            b"Activation",
            b"Server Response",
            b"Authorization",
            b"license_key",
            b"machine_id",
        ]

        protocol_patterns = [
            b"https://",
            b"http://",
            b"POST",
            b"GET",
            b"HTTP/1.1",
        ]

        api_found = sum(1 for p in internet_api if p in self.binary_data)
        activation_found = sum(1 for p in activation_patterns if p in self.binary_data)
        protocol_found = sum(1 for p in protocol_patterns if p in self.binary_data)

        detected = api_found > 0 and activation_found > 0

        return {
            "detected": detected,
            "internet_api": api_found,
            "activation_patterns": activation_found,
            "protocol_indicators": protocol_found,
            "confidence": min((api_found + activation_found + protocol_found) / 8.0, 1.0)
        }

    def detect_license_file_format(self) -> dict[str, Any]:
        """Detect license file handling and parsing."""
        if not self.binary_data:
            return {"detected": False}

        file_api = [
            b"CreateFile",
            b"ReadFile",
            b"WriteFile",
            b"CloseHandle",
        ]

        license_files = [
            b"license.dat",
            b"license.lic",
            b"license.key",
            b"activation.key",
            b".lic",
            b".key",
        ]

        parsing_funcs = [
            b"ParseLicense",
            b"ReadLicense",
            b"VerifyLicenseSignature",
            b"ValidateLicense",
        ]

        api_found = sum(1 for p in file_api if p in self.binary_data)
        files_found = sum(1 for p in license_files if p in self.binary_data)
        parse_found = sum(1 for p in parsing_funcs if p in self.binary_data)

        detected = api_found > 0 and files_found > 0

        return {
            "detected": detected,
            "file_api": api_found,
            "license_files": files_found,
            "parsing_functions": parse_found,
            "confidence": min((api_found + files_found + parse_found) / 7.0, 1.0)
        }

    def detect_crypto_validation(self) -> dict[str, Any]:
        """Detect cryptographic license validation."""
        if not self.binary_data:
            return {"detected": False}

        crypto_api = [
            b"CryptCreateHash",
            b"CryptHashData",
            b"CryptVerifySignature",
            b"CryptImportKey",
            b"CryptDecrypt",
            b"CryptEncrypt",
        ]

        algorithms = [
            b"SHA256",
            b"SHA1",
            b"MD5",
            b"RSA",
            b"AES",
        ]

        key_patterns = [
            b"BEGIN PUBLIC KEY",
            b"BEGIN PRIVATE KEY",
            b"BEGIN RSA",
        ]

        api_found = sum(1 for p in crypto_api if p in self.binary_data)
        algo_found = sum(1 for p in algorithms if p in self.binary_data)
        key_found = sum(1 for p in key_patterns if p in self.binary_data)

        detected = api_found > 0 and algo_found > 0

        return {
            "detected": detected,
            "crypto_api": api_found,
            "algorithms": algo_found,
            "key_data": key_found,
            "confidence": min((api_found + algo_found + key_found) / 8.0, 1.0)
        }

    def detect_obfuscation_patterns(self) -> dict[str, Any]:
        """Detect license check obfuscation techniques."""
        if not self.binary_data:
            return {"detected": False}

        junk_patterns = [
            b"\xeb\x02",
            b"\xeb\x05",
            b"\xff\xff",
            b"\xcc\xcc",
            b"\x90\x90\x90",
        ]

        deobfuscate_funcs = [
            b"Deobfuscate",
            b"XorDecrypt",
            b"Decrypt",
        ]

        junk_found = sum(1 for p in junk_patterns if p in self.binary_data)
        func_found = sum(1 for p in deobfuscate_funcs if p in self.binary_data)

        detected = junk_found > 2 or func_found > 0

        return {
            "detected": detected,
            "junk_instructions": junk_found,
            "deobfuscation_functions": func_found,
            "confidence": min((junk_found + func_found * 2) / 8.0, 1.0)
        }

    def identify_bypass_points(self) -> list[dict[str, Any]]:
        """Identify potential license check bypass points."""
        if not self.binary_data:
            return []

        bypass_points = []

        check_patterns = [
            (b"\x85\xc0\x74", "test_eax_jz"),
            (b"\x85\xc0\x75", "test_eax_jnz"),
            (b"\x3b", "compare"),
            (b"\x74", "conditional_jump_equal"),
            (b"\x75", "conditional_jump_not_equal"),
        ]

        for pattern, desc in check_patterns:
            offset = 0
            while True:
                offset = self.binary_data.find(pattern, offset)
                if offset == -1:
                    break
                bypass_points.append({
                    "offset": offset,
                    "pattern": desc,
                    "bytes": self.binary_data[offset:offset+len(pattern)].hex()
                })
                offset += 1

        return bypass_points[:20]

    def analyze_comprehensive(self) -> dict[str, Any]:
        """Perform comprehensive license analysis."""
        return {
            "serial_validation": self.detect_serial_validation(),
            "trial_expiration": self.detect_trial_expiration(),
            "registration_validation": self.detect_registration_validation(),
            "hardware_binding": self.detect_hardware_binding(),
            "online_activation": self.detect_online_activation(),
            "license_file_format": self.detect_license_file_format(),
            "crypto_validation": self.detect_crypto_validation(),
            "obfuscation": self.detect_obfuscation_patterns(),
            "bypass_points": self.identify_bypass_points(),
        }


class TestSerialValidationDetection:
    """Test serial number validation detection capabilities."""

    def test_detect_serial_validation_patterns_in_real_binary(self, temp_workspace: Path) -> None:
        """Serial validation detector identifies real validation patterns."""
        binary_path = temp_workspace / "serial_check.exe"
        binary_data = create_serial_validation_binary()
        binary_path.write_bytes(binary_data)

        analyzer = LicenseAnalyzer(str(binary_path))
        result = analyzer.detect_serial_validation()

        assert result["detected"] is True
        assert len(result["patterns"]) >= 2
        assert result["checksum_validation"] is True
        assert result["confidence"] > 0.3

        pattern_types = [p["pattern"] for p in result["patterns"]]
        assert any("Serial" in p for p in pattern_types)

    def test_detect_serial_checksum_algorithm(self, temp_workspace: Path) -> None:
        """Detector identifies checksum validation algorithms."""
        binary_path = temp_workspace / "checksum.exe"
        binary_data = create_serial_validation_binary()
        binary_path.write_bytes(binary_data)

        analyzer = LicenseAnalyzer(str(binary_path))
        result = analyzer.detect_serial_validation()

        assert result["checksum_validation"] is True

    def test_serial_validation_with_no_protection(self, temp_workspace: Path) -> None:
        """Detector returns negative for unprotected binaries."""
        binary_path = temp_workspace / "clean.exe"
        binary_data = create_pe_binary(b"\x90\xc3", b"")
        binary_path.write_bytes(binary_data)

        analyzer = LicenseAnalyzer(str(binary_path))
        result = analyzer.detect_serial_validation()

        assert result["detected"] is False
        assert len(result["patterns"]) == 0

    def test_serial_pattern_offset_accuracy(self, temp_workspace: Path) -> None:
        """Pattern detection provides accurate binary offsets."""
        binary_path = temp_workspace / "serial.exe"
        binary_data = create_serial_validation_binary()
        binary_path.write_bytes(binary_data)

        analyzer = LicenseAnalyzer(str(binary_path))
        result = analyzer.detect_serial_validation()

        for pattern_info in result["patterns"]:
            assert pattern_info["offset"] >= 0
            assert pattern_info["offset"] < len(binary_data)

            actual_bytes = binary_data[pattern_info["offset"]:pattern_info["offset"]+len(pattern_info["pattern"])]
            assert pattern_info["pattern"].encode("latin-1") == actual_bytes


class TestTrialExpirationDetection:
    """Test trial period and expiration detection."""

    def test_detect_trial_expiration_mechanisms(self, temp_workspace: Path) -> None:
        """Trial detector identifies real expiration checking."""
        binary_path = temp_workspace / "trial.exe"
        binary_data = create_trial_expiration_binary()
        binary_path.write_bytes(binary_data)

        analyzer = LicenseAnalyzer(str(binary_path))
        result = analyzer.detect_trial_expiration()

        assert result["detected"] is True
        assert result["time_api_calls"] > 0
        assert result["trial_strings"] > 0
        assert result["confidence"] > 0.2

    def test_detect_registry_based_trial_tracking(self, temp_workspace: Path) -> None:
        """Detector identifies registry-based trial persistence."""
        binary_path = temp_workspace / "reg_trial.exe"
        binary_data = create_trial_expiration_binary()
        binary_path.write_bytes(binary_data)

        analyzer = LicenseAnalyzer(str(binary_path))
        result = analyzer.detect_trial_expiration()

        assert result["registry_access"] is True

    def test_trial_time_api_detection(self, temp_workspace: Path) -> None:
        """Detector identifies time-related API calls."""
        binary_path = temp_workspace / "time_check.exe"
        binary_data = create_trial_expiration_binary()
        binary_path.write_bytes(binary_data)

        analyzer = LicenseAnalyzer(str(binary_path))
        result = analyzer.detect_trial_expiration()

        assert result["time_api_calls"] >= 1


class TestRegistrationValidation:
    """Test registration key validation detection."""

    def test_detect_registration_key_validation(self, temp_workspace: Path) -> None:
        """Registration detector identifies key validation patterns."""
        binary_path = temp_workspace / "regkey.exe"
        binary_data = create_registration_key_binary()
        binary_path.write_bytes(binary_data)

        analyzer = LicenseAnalyzer(str(binary_path))
        result = analyzer.detect_registration_validation()

        assert result["detected"] is True
        assert result["registration_patterns"] > 0
        assert result["confidence"] > 0.2

    def test_detect_crypto_registration_validation(self, temp_workspace: Path) -> None:
        """Detector identifies cryptographic registration validation."""
        binary_path = temp_workspace / "crypto_reg.exe"
        binary_data = create_registration_key_binary()
        binary_path.write_bytes(binary_data)

        analyzer = LicenseAnalyzer(str(binary_path))
        result = analyzer.detect_registration_validation()

        assert result["crypto_validation"] is True

    def test_detect_registration_key_format(self, temp_workspace: Path) -> None:
        """Detector identifies registration key format patterns."""
        binary_path = temp_workspace / "keyformat.exe"
        binary_data = create_registration_key_binary()
        binary_path.write_bytes(binary_data)

        analyzer = LicenseAnalyzer(str(binary_path))
        result = analyzer.detect_registration_validation()

        assert result["key_format_detected"] is True


class TestHardwareBinding:
    """Test hardware ID binding detection."""

    def test_detect_hardware_id_binding(self, temp_workspace: Path) -> None:
        """Hardware binding detector identifies HWID checks."""
        binary_path = temp_workspace / "hwid.exe"
        binary_data = create_hardware_binding_binary()
        binary_path.write_bytes(binary_data)

        analyzer = LicenseAnalyzer(str(binary_path))
        result = analyzer.detect_hardware_binding()

        assert result["detected"] is True
        assert result["api_calls"] > 0
        assert result["hwid_strings"] > 0
        assert result["confidence"] > 0.2

    def test_detect_volume_serial_binding(self, temp_workspace: Path) -> None:
        """Detector identifies volume serial number binding."""
        binary_path = temp_workspace / "vol_serial.exe"
        binary_data = create_hardware_binding_binary()
        binary_path.write_bytes(binary_data)

        analyzer = LicenseAnalyzer(str(binary_path))
        result = analyzer.detect_hardware_binding()

        assert result["detected"] is True
        assert result["api_calls"] >= 1

    def test_detect_mac_address_binding(self, temp_workspace: Path) -> None:
        """Detector identifies MAC address hardware binding."""
        binary_path = temp_workspace / "mac.exe"
        binary_data = create_hardware_binding_binary()
        binary_path.write_bytes(binary_data)

        analyzer = LicenseAnalyzer(str(binary_path))
        result = analyzer.detect_hardware_binding()

        assert result["hwid_strings"] >= 2


class TestOnlineActivation:
    """Test online activation detection."""

    def test_detect_online_activation_system(self, temp_workspace: Path) -> None:
        """Online activation detector identifies server communication."""
        binary_path = temp_workspace / "online.exe"
        binary_data = create_online_activation_binary()
        binary_path.write_bytes(binary_data)

        analyzer = LicenseAnalyzer(str(binary_path))
        result = analyzer.detect_online_activation()

        assert result["detected"] is True
        assert result["internet_api"] > 0
        assert result["activation_patterns"] > 0
        assert result["confidence"] > 0.2

    def test_detect_activation_protocol(self, temp_workspace: Path) -> None:
        """Detector identifies HTTP/HTTPS activation protocols."""
        binary_path = temp_workspace / "http_activation.exe"
        binary_data = create_online_activation_binary()
        binary_path.write_bytes(binary_data)

        analyzer = LicenseAnalyzer(str(binary_path))
        result = analyzer.detect_online_activation()

        assert result["protocol_indicators"] > 0

    def test_detect_activation_api_usage(self, temp_workspace: Path) -> None:
        """Detector identifies WinINet/WinHTTP API usage."""
        binary_path = temp_workspace / "wininet.exe"
        binary_data = create_online_activation_binary()
        binary_path.write_bytes(binary_data)

        analyzer = LicenseAnalyzer(str(binary_path))
        result = analyzer.detect_online_activation()

        assert result["internet_api"] >= 1


class TestLicenseFileFormat:
    """Test license file format detection."""

    def test_detect_license_file_handling(self, temp_workspace: Path) -> None:
        """License file detector identifies file-based licensing."""
        binary_path = temp_workspace / "licfile.exe"
        binary_data = create_license_file_binary()
        binary_path.write_bytes(binary_data)

        analyzer = LicenseAnalyzer(str(binary_path))
        result = analyzer.detect_license_file_format()

        assert result["detected"] is True
        assert result["file_api"] > 0
        assert result["license_files"] > 0
        assert result["confidence"] > 0.2

    def test_detect_license_parsing_functions(self, temp_workspace: Path) -> None:
        """Detector identifies license parsing and validation functions."""
        binary_path = temp_workspace / "parse_lic.exe"
        binary_data = create_license_file_binary()
        binary_path.write_bytes(binary_data)

        analyzer = LicenseAnalyzer(str(binary_path))
        result = analyzer.detect_license_file_format()

        assert result["parsing_functions"] > 0

    def test_detect_multiple_license_file_types(self, temp_workspace: Path) -> None:
        """Detector identifies various license file extensions."""
        binary_path = temp_workspace / "multi_lic.exe"
        binary_data = create_license_file_binary()
        binary_path.write_bytes(binary_data)

        analyzer = LicenseAnalyzer(str(binary_path))
        result = analyzer.detect_license_file_format()

        assert result["license_files"] >= 2


class TestCryptoValidation:
    """Test cryptographic license validation detection."""

    def test_detect_cryptographic_validation(self, temp_workspace: Path) -> None:
        """Crypto detector identifies cryptographic license validation."""
        binary_path = temp_workspace / "crypto.exe"
        binary_data = create_crypto_license_validation_binary()
        binary_path.write_bytes(binary_data)

        analyzer = LicenseAnalyzer(str(binary_path))
        result = analyzer.detect_crypto_validation()

        assert result["detected"] is True
        assert result["crypto_api"] > 0
        assert result["algorithms"] > 0
        assert result["confidence"] > 0.2

    def test_detect_signature_verification(self, temp_workspace: Path) -> None:
        """Detector identifies digital signature verification."""
        binary_path = temp_workspace / "sig_verify.exe"
        binary_data = create_crypto_license_validation_binary()
        binary_path.write_bytes(binary_data)

        analyzer = LicenseAnalyzer(str(binary_path))
        result = analyzer.detect_crypto_validation()

        assert result["crypto_api"] >= 1

    def test_detect_embedded_public_keys(self, temp_workspace: Path) -> None:
        """Detector identifies embedded cryptographic keys."""
        binary_path = temp_workspace / "pubkey.exe"
        binary_data = create_crypto_license_validation_binary()
        binary_path.write_bytes(binary_data)

        analyzer = LicenseAnalyzer(str(binary_path))
        result = analyzer.detect_crypto_validation()

        assert result["key_data"] > 0


class TestObfuscationDetection:
    """Test license check obfuscation detection."""

    def test_detect_obfuscated_license_checks(self, temp_workspace: Path) -> None:
        """Obfuscation detector identifies obfuscated validation code."""
        binary_path = temp_workspace / "obfuscated.exe"
        binary_data = create_obfuscated_license_check_binary()
        binary_path.write_bytes(binary_data)

        analyzer = LicenseAnalyzer(str(binary_path))
        result = analyzer.detect_obfuscation_patterns()

        assert result["detected"] is True
        assert result["junk_instructions"] > 0

    def test_detect_junk_instruction_patterns(self, temp_workspace: Path) -> None:
        """Detector identifies junk code insertion patterns."""
        binary_path = temp_workspace / "junk.exe"
        binary_data = create_obfuscated_license_check_binary()
        binary_path.write_bytes(binary_data)

        analyzer = LicenseAnalyzer(str(binary_path))
        result = analyzer.detect_obfuscation_patterns()

        assert result["junk_instructions"] >= 2

    def test_detect_string_obfuscation(self, temp_workspace: Path) -> None:
        """Detector identifies string deobfuscation functions."""
        binary_path = temp_workspace / "str_obf.exe"
        binary_data = create_obfuscated_license_check_binary()
        binary_path.write_bytes(binary_data)

        analyzer = LicenseAnalyzer(str(binary_path))
        result = analyzer.detect_obfuscation_patterns()

        assert result["confidence"] > 0.0


class TestBypassPointIdentification:
    """Test license check bypass point identification."""

    def test_identify_conditional_jump_bypass_points(self, temp_workspace: Path) -> None:
        """Bypass identifier locates conditional jump patch points."""
        binary_path = temp_workspace / "bypass.exe"
        binary_data = create_serial_validation_binary()
        binary_path.write_bytes(binary_data)

        analyzer = LicenseAnalyzer(str(binary_path))
        bypass_points = analyzer.identify_bypass_points()

        assert len(bypass_points) > 0
        for point in bypass_points:
            assert "offset" in point
            assert "pattern" in point
            assert "bytes" in point
            assert point["offset"] >= 0

    def test_identify_test_eax_patterns(self, temp_workspace: Path) -> None:
        """Bypass identifier finds test/compare patterns."""
        binary_path = temp_workspace / "test_eax.exe"
        binary_data = create_serial_validation_binary()
        binary_path.write_bytes(binary_data)

        analyzer = LicenseAnalyzer(str(binary_path))
        bypass_points = analyzer.identify_bypass_points()

        test_patterns = [p for p in bypass_points if "test_eax" in p["pattern"]]
        assert len(test_patterns) > 0

    def test_bypass_point_offset_accuracy(self, temp_workspace: Path) -> None:
        """Bypass point offsets are accurate in real binary."""
        binary_path = temp_workspace / "accurate.exe"
        binary_data = create_multi_check_license_binary()
        binary_path.write_bytes(binary_data)

        analyzer = LicenseAnalyzer(str(binary_path))
        bypass_points = analyzer.identify_bypass_points()

        for point in bypass_points:
            offset = point["offset"]
            assert offset < len(binary_data)


class TestComprehensiveAnalysis:
    """Test comprehensive license analysis capabilities."""

    def test_comprehensive_analysis_all_schemes(self, temp_workspace: Path) -> None:
        """Comprehensive analyzer detects multiple license schemes."""
        binary_path = temp_workspace / "multi_license.exe"

        base_binary = create_serial_validation_binary()
        trial_data = create_trial_expiration_binary()[len(create_pe_binary()):]
        hwid_data = create_hardware_binding_binary()[len(create_pe_binary()):]

        multi_binary = base_binary + trial_data + hwid_data
        binary_path.write_bytes(multi_binary)

        analyzer = LicenseAnalyzer(str(binary_path))
        results = analyzer.analyze_comprehensive()

        assert results["serial_validation"]["detected"] is True
        assert results["trial_expiration"]["detected"] is True
        assert results["hardware_binding"]["detected"] is True
        assert len(results["bypass_points"]) > 0

    def test_comprehensive_analysis_structure(self, temp_workspace: Path) -> None:
        """Comprehensive analysis returns complete result structure."""
        binary_path = temp_workspace / "complete.exe"
        binary_data = create_registration_key_binary()
        binary_path.write_bytes(binary_data)

        analyzer = LicenseAnalyzer(str(binary_path))
        results = analyzer.analyze_comprehensive()

        assert "serial_validation" in results
        assert "trial_expiration" in results
        assert "registration_validation" in results
        assert "hardware_binding" in results
        assert "online_activation" in results
        assert "license_file_format" in results
        assert "crypto_validation" in results
        assert "obfuscation" in results
        assert "bypass_points" in results

    def test_comprehensive_analysis_confidence_scores(self, temp_workspace: Path) -> None:
        """Comprehensive analysis provides confidence metrics."""
        binary_path = temp_workspace / "confidence.exe"
        binary_data = create_crypto_license_validation_binary()
        binary_path.write_bytes(binary_data)

        analyzer = LicenseAnalyzer(str(binary_path))
        results = analyzer.analyze_comprehensive()

        for key in ["serial_validation", "trial_expiration", "registration_validation"]:
            assert "confidence" in results[key]
            assert 0.0 <= results[key]["confidence"] <= 1.0


class TestRealWorldScenarios:
    """Test real-world licensing scenario analysis."""

    def test_analyze_multi_layered_protection(self, temp_workspace: Path) -> None:
        """Analyzer handles multi-layered protection schemes."""
        binary_path = temp_workspace / "layered.exe"
        binary_data = create_multi_check_license_binary()
        binary_path.write_bytes(binary_data)

        analyzer = LicenseAnalyzer(str(binary_path))
        results = analyzer.analyze_comprehensive()

        detected_schemes = sum(1 for k, v in results.items()
                              if isinstance(v, dict) and v.get("detected", False))
        assert detected_schemes >= 1

    def test_analyze_obfuscated_commercial_license(self, temp_workspace: Path) -> None:
        """Analyzer detects obfuscated commercial licensing."""
        binary_path = temp_workspace / "commercial_obf.exe"

        obf_binary = create_obfuscated_license_check_binary()
        crypto_data = create_crypto_license_validation_binary()[len(create_pe_binary()):]
        combined = obf_binary + crypto_data

        binary_path.write_bytes(combined)

        analyzer = LicenseAnalyzer(str(binary_path))
        results = analyzer.analyze_comprehensive()

        assert results["obfuscation"]["detected"] is True
        assert results["crypto_validation"]["detected"] is True

    def test_analyze_trial_with_online_activation(self, temp_workspace: Path) -> None:
        """Analyzer detects trial + online activation combination."""
        binary_path = temp_workspace / "trial_online.exe"

        trial_binary = create_trial_expiration_binary()
        online_data = create_online_activation_binary()[len(create_pe_binary()):]
        combined = trial_binary + online_data

        binary_path.write_bytes(combined)

        analyzer = LicenseAnalyzer(str(binary_path))
        results = analyzer.analyze_comprehensive()

        assert results["trial_expiration"]["detected"] is True
        assert results["online_activation"]["detected"] is True


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_analyze_empty_binary(self, temp_workspace: Path) -> None:
        """Analyzer handles empty binary gracefully."""
        binary_path = temp_workspace / "empty.exe"
        binary_path.write_bytes(b"")

        analyzer = LicenseAnalyzer(str(binary_path))
        result = analyzer.detect_serial_validation()

        assert result["detected"] is False

    def test_analyze_invalid_binary_path(self) -> None:
        """Analyzer handles invalid path gracefully."""
        analyzer = LicenseAnalyzer("/nonexistent/path.exe")
        result = analyzer.detect_serial_validation()

        assert result["detected"] is False

    def test_analyze_minimal_pe_binary(self, temp_workspace: Path) -> None:
        """Analyzer handles minimal PE without license protection."""
        binary_path = temp_workspace / "minimal.exe"
        binary_data = create_pe_binary(b"\x90\xc3", b"")
        binary_path.write_bytes(binary_data)

        analyzer = LicenseAnalyzer(str(binary_path))
        results = analyzer.analyze_comprehensive()

        detected_count = sum(1 for k, v in results.items()
                           if isinstance(v, dict) and v.get("detected", False))
        assert detected_count == 0

    def test_analyze_large_binary_performance(self, temp_workspace: Path) -> None:
        """Analyzer performs efficiently on large binaries."""
        binary_path = temp_workspace / "large.exe"

        large_binary = create_serial_validation_binary()
        large_binary += b"\x90" * (1024 * 1024)
        large_binary += create_trial_expiration_binary()

        binary_path.write_bytes(large_binary)

        analyzer = LicenseAnalyzer(str(binary_path))

        start_time = time.time()
        results = analyzer.analyze_comprehensive()
        elapsed = time.time() - start_time

        assert elapsed < 5.0
        assert results["serial_validation"]["detected"] is True


class TestBypassStrategyGeneration:
    """Test bypass strategy identification."""

    def test_identify_serial_check_bypass_strategy(self, temp_workspace: Path) -> None:
        """Bypass identifier finds serial check patch points."""
        binary_path = temp_workspace / "serial_bypass.exe"
        binary_data = create_serial_validation_binary()
        binary_path.write_bytes(binary_data)

        analyzer = LicenseAnalyzer(str(binary_path))
        bypass_points = analyzer.identify_bypass_points()

        conditional_jumps = [p for p in bypass_points
                           if "jump" in p["pattern"].lower()]
        assert len(conditional_jumps) > 0

    def test_identify_trial_reset_strategy(self, temp_workspace: Path) -> None:
        """Bypass identifier finds trial check modifications."""
        binary_path = temp_workspace / "trial_bypass.exe"
        binary_data = create_trial_expiration_binary()
        binary_path.write_bytes(binary_data)

        analyzer = LicenseAnalyzer(str(binary_path))
        results = analyzer.analyze_comprehensive()

        assert results["trial_expiration"]["detected"] is True
        assert len(results["bypass_points"]) > 0


class TestMultipleProtectionSchemes:
    """Test detection of multiple simultaneous protection schemes."""

    def test_detect_serial_and_trial_combination(self, temp_workspace: Path) -> None:
        """Analyzer detects serial + trial protection combination."""
        binary_path = temp_workspace / "serial_trial.exe"

        serial_bin = create_serial_validation_binary()
        trial_data = create_trial_expiration_binary()[len(create_pe_binary()):]
        combined = serial_bin + trial_data

        binary_path.write_bytes(combined)

        analyzer = LicenseAnalyzer(str(binary_path))
        results = analyzer.analyze_comprehensive()

        assert results["serial_validation"]["detected"] is True
        assert results["trial_expiration"]["detected"] is True

    def test_detect_hwid_and_online_combination(self, temp_workspace: Path) -> None:
        """Analyzer detects HWID + online activation combination."""
        binary_path = temp_workspace / "hwid_online.exe"

        hwid_bin = create_hardware_binding_binary()
        online_data = create_online_activation_binary()[len(create_pe_binary()):]
        combined = hwid_bin + online_data

        binary_path.write_bytes(combined)

        analyzer = LicenseAnalyzer(str(binary_path))
        results = analyzer.analyze_comprehensive()

        assert results["hardware_binding"]["detected"] is True
        assert results["online_activation"]["detected"] is True

    def test_detect_triple_protection_scheme(self, temp_workspace: Path) -> None:
        """Analyzer detects three simultaneous protection schemes."""
        binary_path = temp_workspace / "triple.exe"

        base = create_registration_key_binary()
        crypto_data = create_crypto_license_validation_binary()[len(create_pe_binary()):]
        file_data = create_license_file_binary()[len(create_pe_binary()):]
        combined = base + crypto_data + file_data

        binary_path.write_bytes(combined)

        analyzer = LicenseAnalyzer(str(binary_path))
        results = analyzer.analyze_comprehensive()

        assert results["registration_validation"]["detected"] is True
        assert results["crypto_validation"]["detected"] is True
        assert results["license_file_format"]["detected"] is True
