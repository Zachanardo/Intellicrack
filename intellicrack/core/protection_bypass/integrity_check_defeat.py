"""Advanced Integrity Check Defeat System for Intellicrack.

Detects and bypasses various integrity checking mechanisms including
CRC checks, hash validations, signature verifications, and anti-tampering.
Implements genuine checksum recalculation and hook-based runtime bypasses.
"""

import hashlib
import hmac
import logging
import os
import struct
import zlib
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any

import capstone
import frida
import lief
import pefile


logger = logging.getLogger(__name__)


class IntegrityCheckType(IntEnum):
    """Types of integrity checks."""

    UNKNOWN = 0
    CRC32 = 1
    MD5_HASH = 2
    SHA1_HASH = 3
    SHA256_HASH = 4
    SIGNATURE = 5
    CHECKSUM = 6
    SIZE_CHECK = 7
    TIMESTAMP = 8
    CERTIFICATE = 9
    MEMORY_HASH = 10
    CODE_SIGNING = 11
    ANTI_TAMPER = 12
    CRC64 = 13
    SHA512_HASH = 14
    HMAC_SIGNATURE = 15
    AUTHENTICODE = 16


@dataclass
class IntegrityCheck:
    """Represents detected integrity check."""

    check_type: IntegrityCheckType
    address: int
    size: int
    expected_value: bytes
    actual_value: bytes
    function_name: str
    bypass_method: str
    confidence: float
    section_name: str = ""
    binary_path: str = ""


@dataclass
class BypassStrategy:
    """Strategy for bypassing integrity check."""

    name: str
    check_types: list[IntegrityCheckType]
    frida_script: str
    success_rate: float
    priority: int


@dataclass
class ChecksumRecalculation:
    """Results of checksum recalculation for patched binary."""

    original_crc32: int
    patched_crc32: int
    original_crc64: int
    patched_crc64: int
    original_md5: str
    patched_md5: str
    original_sha1: str
    patched_sha1: str
    original_sha256: str
    patched_sha256: str
    original_sha512: str
    patched_sha512: str
    pe_checksum: int
    sections: dict[str, dict[str, str]] = field(default_factory=dict)
    hmac_keys: list[dict[str, str | int]] = field(default_factory=list)


@dataclass
class ChecksumLocation:
    """Location of embedded checksum in binary."""

    offset: int
    size: int
    algorithm: IntegrityCheckType
    current_value: bytes
    calculated_value: bytes
    confidence: float


class ChecksumRecalculator:
    """Recalculates checksums for patched binaries with production-grade algorithms."""

    def __init__(self) -> None:
        """Initialize the ChecksumRecalculator with lookup tables."""
        self.crc32_table = self._generate_crc32_table()
        self.crc32_reversed_table = self._generate_crc32_reversed_table()
        self.crc64_table = self._generate_crc64_table()

    def _generate_crc32_table(self) -> list[int]:
        """Generate CRC32 lookup table using standard polynomial."""
        polynomial = 0xEDB88320
        table = []
        for i in range(256):
            crc = i
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ polynomial
                else:
                    crc >>= 1
            table.append(crc)
        return table

    def _generate_crc32_reversed_table(self) -> list[int]:
        """Generate reversed CRC32 table for forward computation."""
        polynomial = 0x04C11DB7
        table = []
        for i in range(256):
            crc = i << 24
            for _ in range(8):
                if crc & 0x80000000:
                    crc = (crc << 1) ^ polynomial
                else:
                    crc <<= 1
                crc &= 0xFFFFFFFF
            table.append(crc)
        return table

    def _generate_crc64_table(self) -> list[int]:
        """Generate CRC64 lookup table using ECMA-182 polynomial."""
        polynomial = 0x42F0E1EBA9EA3693
        table = []
        for i in range(256):
            crc = i
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ polynomial
                else:
                    crc >>= 1
            table.append(crc)
        return table

    def calculate_crc32(self, data: bytes) -> int:
        """Calculate CRC32 checksum using lookup table."""
        crc = 0xFFFFFFFF
        for byte in data:
            table_index = (crc & 0xFF) ^ byte
            crc = self.crc32_table[table_index] ^ (crc >> 8)
        return crc ^ 0xFFFFFFFF

    def calculate_crc32_zlib(self, data: bytes) -> int:
        """Calculate CRC32 using zlib (faster for large data)."""
        return zlib.crc32(data) & 0xFFFFFFFF

    def calculate_md5(self, data: bytes) -> str:
        """Calculate MD5 hash."""
        return hashlib.md5(data).hexdigest()  # noqa: S324

    def calculate_sha1(self, data: bytes) -> str:
        """Calculate SHA-1 hash."""
        return hashlib.sha1(data).hexdigest()  # noqa: S324

    def calculate_sha256(self, data: bytes) -> str:
        """Calculate SHA-256 hash."""
        return hashlib.sha256(data).hexdigest()

    def calculate_sha512(self, data: bytes) -> str:
        """Calculate SHA-512 hash."""
        return hashlib.sha512(data).hexdigest()

    def calculate_crc64(self, data: bytes) -> int:
        """Calculate CRC64 checksum using lookup table."""
        crc = 0xFFFFFFFFFFFFFFFF
        for byte in data:
            table_index = (crc & 0xFF) ^ byte
            crc = self.crc64_table[table_index] ^ (crc >> 8)
        return crc ^ 0xFFFFFFFFFFFFFFFF

    def calculate_hmac(self, data: bytes, key: bytes, algorithm: str = "sha256") -> str:
        """Calculate HMAC signature with specified algorithm."""
        hash_func = getattr(hashlib, algorithm)
        return hmac.new(key, data, hash_func).hexdigest()

    def calculate_all_hashes(self, data: bytes) -> dict[str, str]:
        """Calculate all supported hash algorithms."""
        return {
            "crc32": hex(self.calculate_crc32_zlib(data)),
            "crc64": hex(self.calculate_crc64(data)),
            "md5": self.calculate_md5(data),
            "sha1": self.calculate_sha1(data),
            "sha256": self.calculate_sha256(data),
            "sha512": self.calculate_sha512(data),
        }

    def recalculate_pe_checksum(self, binary_path: str) -> int:
        """Recalculate PE checksum for Windows executables."""
        try:
            pe = pefile.PE(binary_path)

            binary_data = pe.__data__
            checksum = 0

            checksum_offset = pe.OPTIONAL_HEADER.get_file_offset() + 64

            for i in range(0, len(binary_data), 4):
                if i == checksum_offset:
                    continue

                if i + 4 <= len(binary_data):
                    dword = struct.unpack("<I", binary_data[i : i + 4])[0]
                elif i + 2 <= len(binary_data):
                    dword = struct.unpack("<H", binary_data[i : i + 2])[0]
                else:
                    dword = binary_data[i]

                checksum = (checksum + dword) & 0xFFFFFFFF
                checksum = (checksum & 0xFFFF) + (checksum >> 16)

            checksum = (checksum & 0xFFFF) + (checksum >> 16)
            checksum += len(binary_data)

            pe.close()
            return checksum & 0xFFFFFFFF

        except Exception as e:
            logger.exception("PE checksum calculation failed: %s", e, exc_info=True)
            return 0

    def recalculate_section_hashes(self, binary_path: str) -> dict[str, dict[str, str]]:
        """Recalculate hashes for individual PE sections."""
        section_hashes = {}

        try:
            pe = pefile.PE(binary_path)

            for section in pe.sections:
                section_name = section.Name.decode().rstrip("\x00")
                section_data = section.get_data()

                section_hashes[section_name] = {
                    "md5": self.calculate_md5(section_data),
                    "sha1": self.calculate_sha1(section_data),
                    "sha256": self.calculate_sha256(section_data),
                    "sha512": self.calculate_sha512(section_data),
                    "crc32": hex(self.calculate_crc32_zlib(section_data)),
                    "crc64": hex(self.calculate_crc64(section_data)),
                    "size": str(len(section_data)),
                }

            pe.close()

        except Exception as e:
            logger.exception("Section hash calculation failed: %s", e, exc_info=True)

        return section_hashes

    def extract_hmac_keys(self, binary_path: str) -> list[dict[str, str | int]]:
        """Extract potential HMAC keys from binary using entropy and pattern analysis."""
        hmac_keys = []

        try:
            with open(binary_path, "rb") as f:
                binary_data = f.read()

            key_sizes = [16, 20, 24, 32, 48, 64]

            for key_size in key_sizes:
                offset = 0
                while offset < len(binary_data) - key_size:
                    potential_key = binary_data[offset : offset + key_size]

                    entropy = self._calculate_key_entropy(potential_key)

                    if 3.5 < entropy < 7.0 and self._is_likely_key(potential_key):
                        hmac_keys.append({
                            "offset": offset,
                            "size": key_size,
                            "key_hex": potential_key.hex(),
                            "entropy": entropy,
                            "confidence": self._calculate_key_confidence(potential_key, entropy),
                        })

                    offset += 1

            hmac_keys_typed: list[dict[str, str | int]] = []
            for key in hmac_keys:
                typed_key: dict[str, str | int] = {}
                for k, v in key.items():
                    if isinstance(v, (str, int)):
                        typed_key[k] = v
                    elif isinstance(v, float):
                        typed_key[k] = int(v) if v.is_integer() else str(v)
                hmac_keys_typed.append(typed_key)

            hmac_keys_sorted = sorted(
                hmac_keys_typed,
                key=lambda x: float(x["confidence"]) if isinstance(x["confidence"], (int, float)) else 0.0,
                reverse=True,
            )
            return hmac_keys_sorted[:10]

        except Exception as e:
            logger.exception("HMAC key extraction failed: %s", e, exc_info=True)
            return []

    def _calculate_key_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy for potential key material."""
        if not data:
            return 0.0

        import math

        frequency_map: dict[int, int] = {}
        for byte in data:
            frequency_map[byte] = frequency_map.get(byte, 0) + 1

        entropy = 0.0
        data_len = len(data)
        for count in frequency_map.values():
            if count > 0:
                frequency = float(count) / data_len
                entropy -= frequency * math.log2(frequency)

        return entropy

    def _is_likely_key(self, data: bytes) -> bool:
        """Heuristic check if data is likely cryptographic key material."""
        if data.count(b"\x00") > len(data) * 0.3:
            return False

        if data.count(b"\xff") > len(data) * 0.3:
            return False

        repeating_patterns = [data[i : i + 2] for i in range(len(data) - 1)]
        return len(set(repeating_patterns)) >= len(data) * 0.4

    def _calculate_key_confidence(self, data: bytes, entropy: float) -> float:
        """Calculate confidence score for potential key material."""
        confidence = 0.0

        if 4.0 <= entropy <= 6.5:
            confidence += 0.4

        unique_bytes = len(set(data))
        if unique_bytes > len(data) * 0.5:
            confidence += 0.3

        if b"\x00" * 4 not in data and b"\xff" * 4 not in data:
            confidence += 0.2

        printable_count = sum(32 <= b <= 126 for b in data)
        if printable_count < len(data) * 0.2:
            confidence += 0.1

        return min(confidence, 1.0)

    def find_checksum_locations(self, binary_path: str) -> list[ChecksumLocation]:
        """Automatically identify locations where checksums are stored in binary."""
        locations = []

        try:
            with open(binary_path, "rb") as f:
                binary_data = f.read()

            actual_crc32 = self.calculate_crc32_zlib(binary_data)
            actual_crc64 = self.calculate_crc64(binary_data)
            actual_md5 = bytes.fromhex(self.calculate_md5(binary_data))
            actual_sha1 = bytes.fromhex(self.calculate_sha1(binary_data))
            actual_sha256 = bytes.fromhex(self.calculate_sha256(binary_data))
            actual_sha512 = bytes.fromhex(self.calculate_sha512(binary_data))

            crc32_bytes_le = struct.pack("<I", actual_crc32)
            crc32_bytes_be = struct.pack(">I", actual_crc32)
            crc64_bytes_le = struct.pack("<Q", actual_crc64)
            crc64_bytes_be = struct.pack(">Q", actual_crc64)

            search_patterns = [
                (crc32_bytes_le, IntegrityCheckType.CRC32, 4),
                (crc32_bytes_be, IntegrityCheckType.CRC32, 4),
                (crc64_bytes_le, IntegrityCheckType.CRC64, 8),
                (crc64_bytes_be, IntegrityCheckType.CRC64, 8),
                (actual_md5, IntegrityCheckType.MD5_HASH, 16),
                (actual_sha1, IntegrityCheckType.SHA1_HASH, 20),
                (actual_sha256, IntegrityCheckType.SHA256_HASH, 32),
                (actual_sha512, IntegrityCheckType.SHA512_HASH, 64),
            ]

            for pattern, check_type, size in search_patterns:
                offset = 0
                while True:
                    pos = binary_data.find(pattern, offset)
                    if pos == -1:
                        break

                    if self._is_valid_checksum_location(binary_data, pos, size):
                        location = ChecksumLocation(
                            offset=pos,
                            size=size,
                            algorithm=check_type,
                            current_value=pattern,
                            calculated_value=pattern,
                            confidence=0.8,
                        )
                        locations.append(location)

                    offset = pos + 1

            pe = pefile.PE(binary_path)
            for section in pe.sections:
                section_data = section.get_data()
                section_crc32 = self.calculate_crc32_zlib(section_data)
                section_md5 = bytes.fromhex(self.calculate_md5(section_data))
                section_sha256 = bytes.fromhex(self.calculate_sha256(section_data))

                section_patterns = [
                    (struct.pack("<I", section_crc32), IntegrityCheckType.CRC32, 4),
                    (struct.pack(">I", section_crc32), IntegrityCheckType.CRC32, 4),
                    (section_md5, IntegrityCheckType.MD5_HASH, 16),
                    (section_sha256, IntegrityCheckType.SHA256_HASH, 32),
                ]

                for pattern, check_type, size in section_patterns:
                    pos = binary_data.find(pattern)
                    if pos != -1 and self._is_valid_checksum_location(binary_data, pos, size):
                        location = ChecksumLocation(
                            offset=pos,
                            size=size,
                            algorithm=check_type,
                            current_value=pattern,
                            calculated_value=pattern,
                            confidence=0.9,
                        )
                        if all(loc.offset != pos for loc in locations):
                            locations.append(location)

            pe.close()

        except Exception as e:
            logger.exception("Checksum location identification failed: %s", e, exc_info=True)

        return locations

    def _is_valid_checksum_location(self, binary_data: bytes, offset: int, size: int) -> bool:
        """Validate if offset is a likely checksum storage location."""
        try:
            pe = pefile.PE(data=binary_data)

            for section in pe.sections:
                section_start = section.PointerToRawData
                section_end = section_start + section.SizeOfRawData

                if section_start <= offset < section_end:
                    section_name = section.Name.decode().rstrip("\x00")

                    if section_name in [".rdata", ".data", ".idata"]:
                        return True

                    if not (section.IMAGE_SCN_MEM_EXECUTE):
                        return True

            pe.close()
            return False

        except Exception as e:
            logger.debug("Checksum location validation failed: %s", e, exc_info=True)
            return offset > 0x400

    def recalculate_for_patched_binary(
        self,
        original_path: str,
        patched_path: str,
    ) -> ChecksumRecalculation:
        """Recalculate all checksums for patched binary."""
        with open(original_path, "rb") as f:
            original_data = f.read()

        with open(patched_path, "rb") as f:
            patched_data = f.read()

        pe_checksum = self.recalculate_pe_checksum(patched_path)
        section_hashes = self.recalculate_section_hashes(patched_path)
        hmac_keys = self.extract_hmac_keys(patched_path)

        return ChecksumRecalculation(
            original_crc32=self.calculate_crc32_zlib(original_data),
            patched_crc32=self.calculate_crc32_zlib(patched_data),
            original_crc64=self.calculate_crc64(original_data),
            patched_crc64=self.calculate_crc64(patched_data),
            original_md5=self.calculate_md5(original_data),
            patched_md5=self.calculate_md5(patched_data),
            original_sha1=self.calculate_sha1(original_data),
            patched_sha1=self.calculate_sha1(patched_data),
            original_sha256=self.calculate_sha256(original_data),
            patched_sha256=self.calculate_sha256(patched_data),
            original_sha512=self.calculate_sha512(original_data),
            patched_sha512=self.calculate_sha512(patched_data),
            pe_checksum=pe_checksum,
            sections=section_hashes,
            hmac_keys=hmac_keys,
        )


class IntegrityCheckDetector:
    """Detect integrity checking mechanisms in binaries."""

    def __init__(self) -> None:
        """Initialize the IntegrityCheckDetector with disassembler and pattern databases."""
        self.md_32 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.md_32.detail = True
        self.md_64 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.md_64.detail = True
        self.check_patterns = self._load_check_patterns()
        self.api_signatures = self._load_api_signatures()

    def _load_check_patterns(self) -> dict[str, dict[str, bytes | IntegrityCheckType | str]]:
        """Load patterns for detecting integrity checks."""
        return {
            "crc32": {
                "pattern": b"\xc1\xe8\x08\x33",
                "type": IntegrityCheckType.CRC32,
                "description": "CRC32 calculation",
            },
            "crc32_xor": {
                "pattern": b"\x33\x81",
                "type": IntegrityCheckType.CRC32,
                "description": "CRC32 XOR operation",
            },
            "crc64_poly": {
                "pattern": b"\x93\x36\xea\xa9\xeb\xe1\xf0\x42",
                "type": IntegrityCheckType.CRC64,
                "description": "CRC64 ECMA polynomial",
            },
            "crc64_calc": {
                "pattern": b"\x48\xc1\xe8\x08",
                "type": IntegrityCheckType.CRC64,
                "description": "CRC64 calculation (64-bit shift)",
            },
            "md5": {
                "pattern": b"\x67\x45\x23\x01",
                "type": IntegrityCheckType.MD5_HASH,
                "description": "MD5 hash calculation",
            },
            "md5_init": {
                "pattern": b"\x01\x23\x45\x67\x89\xab\xcd\xef",
                "type": IntegrityCheckType.MD5_HASH,
                "description": "MD5 initialization constants",
            },
            "sha1": {
                "pattern": b"\x67\x45\x23\x01\xef\xcd\xab\x89",
                "type": IntegrityCheckType.SHA1_HASH,
                "description": "SHA1 hash calculation",
            },
            "sha1_init": {
                "pattern": b"\xc3\xd2\xe1\xf0",
                "type": IntegrityCheckType.SHA1_HASH,
                "description": "SHA1 initialization",
            },
            "sha256": {
                "pattern": b"\x6a\x09\xe6\x67",
                "type": IntegrityCheckType.SHA256_HASH,
                "description": "SHA256 hash calculation",
            },
            "sha256_k": {
                "pattern": b"\x42\x8a\x2f\x98",
                "type": IntegrityCheckType.SHA256_HASH,
                "description": "SHA256 K constants",
            },
            "sha512_init": {
                "pattern": b"\x6a\x09\xe6\x67\xf3\xbc\xc9\x08",
                "type": IntegrityCheckType.SHA512_HASH,
                "description": "SHA512 initialization constants",
            },
            "sha512_k": {
                "pattern": b"\x42\x8a\x2f\x98\xd7\x28\xae\x22",
                "type": IntegrityCheckType.SHA512_HASH,
                "description": "SHA512 K constants",
            },
            "hmac_ipad": {
                "pattern": b"\x36\x36\x36\x36",
                "type": IntegrityCheckType.HMAC_SIGNATURE,
                "description": "HMAC inner padding",
            },
            "hmac_opad": {
                "pattern": b"\x5c\x5c\x5c\x5c",
                "type": IntegrityCheckType.HMAC_SIGNATURE,
                "description": "HMAC outer padding",
            },
            "size_check": {
                "pattern": b"\x81\x7d.\x00\x00",
                "type": IntegrityCheckType.SIZE_CHECK,
                "description": "File size verification",
            },
        }

    def _load_api_signatures(self) -> dict[str, IntegrityCheckType]:
        """Load Windows API signatures for integrity checks."""
        return {
            "GetFileSize": IntegrityCheckType.SIZE_CHECK,
            "GetFileSizeEx": IntegrityCheckType.SIZE_CHECK,
            "GetFileTime": IntegrityCheckType.TIMESTAMP,
            "CryptHashData": IntegrityCheckType.SHA256_HASH,
            "CryptVerifySignature": IntegrityCheckType.SIGNATURE,
            "CryptVerifySignatureA": IntegrityCheckType.SIGNATURE,
            "CryptVerifySignatureW": IntegrityCheckType.SIGNATURE,
            "WinVerifyTrust": IntegrityCheckType.AUTHENTICODE,
            "WinVerifyTrustEx": IntegrityCheckType.AUTHENTICODE,
            "CertVerifyCertificateChainPolicy": IntegrityCheckType.CERTIFICATE,
            "CheckSumMappedFile": IntegrityCheckType.CHECKSUM,
            "MapFileAndCheckSum": IntegrityCheckType.CHECKSUM,
            "MapFileAndCheckSumA": IntegrityCheckType.CHECKSUM,
            "MapFileAndCheckSumW": IntegrityCheckType.CHECKSUM,
            "ImageGetCertificateData": IntegrityCheckType.CODE_SIGNING,
            "ImageGetCertificateHeader": IntegrityCheckType.CODE_SIGNING,
            "CryptCATAdminCalcHashFromFileHandle": IntegrityCheckType.SHA256_HASH,
            "CryptCATAdminCalcHashFromFileHandle2": IntegrityCheckType.SHA512_HASH,
            "RtlComputeCrc32": IntegrityCheckType.CRC32,
            "RtlComputeCrc64": IntegrityCheckType.CRC64,
            "CryptCreateHash": IntegrityCheckType.SHA256_HASH,
            "CryptGetHashParam": IntegrityCheckType.SHA256_HASH,
            "BCryptHash": IntegrityCheckType.SHA256_HASH,
            "BCryptCreateHash": IntegrityCheckType.SHA256_HASH,
            "BCryptHashData": IntegrityCheckType.SHA256_HASH,
            "BCryptFinishHash": IntegrityCheckType.SHA256_HASH,
            "memcmp": IntegrityCheckType.CHECKSUM,
            "strcmp": IntegrityCheckType.CHECKSUM,
            "strncmp": IntegrityCheckType.CHECKSUM,
            "memcmp_s": IntegrityCheckType.CHECKSUM,
        }

    def detect_checks(self, binary_path: str) -> list[IntegrityCheck]:
        """Detect integrity checks in binary."""
        checks: list[IntegrityCheck] = []

        try:
            if binary_path.lower().endswith((".exe", ".dll", ".sys")):
                pe = pefile.PE(binary_path)

                api_checks = self._scan_api_imports(pe, binary_path)
                checks.extend(api_checks)

                inline_checks = self._scan_inline_checks(pe, binary_path)
                checks.extend(inline_checks)

                antitamper_checks = self._scan_antitamper(pe, binary_path)
                checks.extend(antitamper_checks)

                pe.close()
            elif parsed_binary := lief.parse(binary_path):
                if isinstance(parsed_binary, lief.Binary):
                    checks.extend(self._scan_elf_checks(parsed_binary, binary_path))

        except Exception as e:
            logger.exception("Integrity check detection failed: %s", e, exc_info=True)

        return checks

    def _scan_api_imports(self, pe: pefile.PE, binary_path: str) -> list[IntegrityCheck]:
        """Scan for integrity check API imports."""
        checks: list[IntegrityCheck] = []

        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return checks

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode() if isinstance(imp.name, bytes) else str(imp.name)

                    if isinstance(func_name, str) and func_name in self.api_signatures:
                        check = IntegrityCheck(
                            check_type=self.api_signatures[func_name],
                            address=imp.address,
                            size=0,
                            expected_value=b"",
                            actual_value=b"",
                            function_name=func_name,
                            bypass_method="hook_api",
                            confidence=0.9,
                            binary_path=binary_path,
                        )
                        checks.append(check)

        return checks

    def _scan_inline_checks(self, pe: pefile.PE, binary_path: str) -> list[IntegrityCheck]:
        """Scan for inline integrity checks."""
        checks: list[IntegrityCheck] = []

        for section in pe.sections:
            if section.IMAGE_SCN_MEM_EXECUTE:
                section_data = section.get_data()
                section_name = section.Name.decode().rstrip("\x00")

                for pattern_info in self.check_patterns.values():
                    pattern_val = pattern_info.get("pattern")
                    check_type_val = pattern_info.get("type")
                    description_val = pattern_info.get("description")

                    if (
                        not isinstance(pattern_val, bytes)
                        or not isinstance(check_type_val, IntegrityCheckType)
                        or not isinstance(description_val, str)
                    ):
                        continue

                    offset = 0

                    while True:
                        pos = section_data.find(pattern_val, offset)
                        if pos == -1:
                            break

                        check = IntegrityCheck(
                            check_type=check_type_val,
                            address=section.VirtualAddress + pos,
                            size=len(pattern_val),
                            expected_value=b"",
                            actual_value=b"",
                            function_name=description_val,
                            bypass_method="patch_inline",
                            confidence=0.7,
                            section_name=section_name,
                            binary_path=binary_path,
                        )
                        checks.append(check)
                        offset = pos + 1

        return checks

    def _scan_antitamper(self, pe: pefile.PE, binary_path: str) -> list[IntegrityCheck]:
        """Scan for anti-tamper mechanisms."""
        checks = []

        for section in pe.sections:
            entropy = self._calculate_entropy(section.get_data())
            if entropy > 7.5:
                section_name = section.Name.decode().rstrip("\x00")
                check = IntegrityCheck(
                    check_type=IntegrityCheckType.ANTI_TAMPER,
                    address=section.VirtualAddress,
                    size=section.SizeOfRawData,
                    expected_value=b"",
                    actual_value=b"",
                    function_name="Packed/Encrypted Section",
                    bypass_method="unpack_section",
                    confidence=0.8,
                    section_name=section_name,
                    binary_path=binary_path,
                )
                checks.append(check)

        smc_patterns = [
            b"\xf0\x0f\xc1",
            b"\x0f\xba\x2d",
            b"\x0f\xc7\x08",
            b"\x0f\xb0",
            b"\xf0\x0f\xb1",
            b"\x66\x0f\xc7",
        ]

        for section in pe.sections:
            section_data = section.get_data()
            section_name = section.Name.decode().rstrip("\x00")
            for pattern in smc_patterns:
                if pattern in section_data:
                    check = IntegrityCheck(
                        check_type=IntegrityCheckType.ANTI_TAMPER,
                        address=section.VirtualAddress + section_data.find(pattern),
                        size=len(pattern),
                        expected_value=b"",
                        actual_value=b"",
                        function_name="Self-Modifying Code",
                        bypass_method="hook_smc",
                        confidence=0.6,
                        section_name=section_name,
                        binary_path=binary_path,
                    )
                    checks.append(check)

        return checks

    def _scan_elf_checks(self, binary: lief.Binary, binary_path: str) -> list[IntegrityCheck]:
        """Scan ELF binaries for integrity checks."""
        checks: list[IntegrityCheck] = []

        try:
            for symbol in binary.imported_functions:
                func_name_raw = symbol.name
                func_name = func_name_raw.decode() if isinstance(func_name_raw, bytes) else str(func_name_raw)

                if isinstance(func_name, str) and func_name in self.api_signatures:
                    check = IntegrityCheck(
                        check_type=self.api_signatures[func_name],
                        address=symbol.value,
                        size=0,
                        expected_value=b"",
                        actual_value=b"",
                        function_name=func_name,
                        bypass_method="hook_api",
                        confidence=0.85,
                        binary_path=binary_path,
                    )
                    checks.append(check)
        except Exception as e:
            logger.debug("ELF check scan error: %s", e, exc_info=True)

        return checks

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy."""
        if not data:
            return 0.0

        import math

        frequency_map: dict[int, int] = {}
        for byte in data:
            frequency_map[byte] = frequency_map.get(byte, 0) + 1

        entropy = 0.0
        data_len = len(data)
        for count in frequency_map.values():
            if count > 0:
                frequency = float(count) / data_len
                entropy -= frequency * math.log2(frequency)

        return entropy


class IntegrityBypassEngine:
    """Bypasses detected integrity checks using Frida runtime hooks."""

    def __init__(self) -> None:
        """Initialize the IntegrityBypassEngine with bypass strategies and Frida session."""
        self.bypass_strategies = self._load_bypass_strategies()
        self.session: frida.core.Session | None = None
        self.script: frida.core.Script | None = None
        self.hooks_installed: list[str] = []
        self.checksum_calc = ChecksumRecalculator()
        self.original_bytes_cache: dict[int, bytes] = {}

    def _load_bypass_strategies(self) -> list[BypassStrategy]:
        """Load bypass strategies for different check types."""
        strategies = [
            BypassStrategy(
                name="crc32_bypass",
                check_types=[IntegrityCheckType.CRC32],
                frida_script="""
                var rtlComputeCrc32 = Module.findExportByName(null, 'RtlComputeCrc32');
                if (rtlComputeCrc32) {
                    Interceptor.attach(rtlComputeCrc32, {
                        onEnter: function(args) {
                            this.buffer = args[1];
                            this.length = args[2].toInt32();
                            this.initialCrc = args[0].toInt32();
                        },
                        onLeave: function(retval) {
                            var address = parseInt(this.buffer);
                            if (address >= %PROTECTED_START% && address <= %PROTECTED_END%) {
                                retval.replace(ptr('%EXPECTED_CRC32%'));
                                console.log('[CRC32] Bypassed: addr=' + address.toString(16) +
                                          ' returned=' + retval);
                            }
                        }
                    });
                }

                var zlib_crc32 = Module.findExportByName('zlib1.dll', 'crc32');
                if (!zlib_crc32) {
                    zlib_crc32 = Module.findExportByName('zlibwapi.dll', 'crc32');
                }
                if (zlib_crc32) {
                    Interceptor.attach(zlib_crc32, {
                        onEnter: function(args) {
                            this.crc = args[0].toInt32();
                            this.buf = args[1];
                            this.len = args[2].toInt32();
                        },
                        onLeave: function(retval) {
                            var address = parseInt(this.buf);
                            if (address >= %PROTECTED_START% && address <= %PROTECTED_END%) {
                                retval.replace(ptr('%EXPECTED_CRC32%'));
                                console.log('[CRC32-zlib] Bypassed check');
                            }
                        }
                    });
                }
            """,
                success_rate=0.95,
                priority=1,
            )
        ]

        strategies.append(
            BypassStrategy(
                name="crc64_bypass",
                check_types=[IntegrityCheckType.CRC64],
                frida_script="""
                var rtlComputeCrc64 = Module.findExportByName(null, 'RtlComputeCrc64');
                if (rtlComputeCrc64) {
                    Interceptor.attach(rtlComputeCrc64, {
                        onEnter: function(args) {
                            this.buffer = args[1];
                            this.length = args[2].toInt32();
                            this.initialCrc = args[0];
                        },
                        onLeave: function(retval) {
                            var address = parseInt(this.buffer);
                            if (address >= %PROTECTED_START% && address <= %PROTECTED_END%) {
                                retval.replace(ptr('%EXPECTED_CRC64%'));
                                console.log('[CRC64] Bypassed CRC64 check');
                            }
                        }
                    });
                }

                var customCrc64Patterns = Process.enumerateRanges('r-x').filter(function(range) {
                    return range.protection === 'r-x' && range.size > 0x1000;
                });

                customCrc64Patterns.forEach(function(range) {
                    try {
                        var matches = Memory.scanSync(range.base, range.size, '93 36 ea a9 eb e1 f0 42');
                        matches.forEach(function(match) {
                            var func = new NativeFunction(match.address.sub(0x20), 'uint64', ['pointer', 'uint64']);
                            Interceptor.replace(func, new NativeCallback(function(buffer, length) {
                                return '%EXPECTED_CRC64%';
                            }, 'uint64', ['pointer', 'uint64']));
                            console.log('[CRC64] Hooked custom CRC64 at ' + match.address);
                        });
                    } catch (e) {}
                });
            """,
                success_rate=0.92,
                priority=1,
            ),
        )

        strategies.append(
            BypassStrategy(
                name="hash_bypass",
                check_types=[
                    IntegrityCheckType.MD5_HASH,
                    IntegrityCheckType.SHA1_HASH,
                    IntegrityCheckType.SHA256_HASH,
                    IntegrityCheckType.SHA512_HASH,
                ],
                frida_script="""
                var cryptHashData = Module.findExportByName('Advapi32.dll', 'CryptHashData');
                if (cryptHashData) {
                    Interceptor.attach(cryptHashData, {
                        onEnter: function(args) {
                            this.hHash = args[0];
                            this.pbData = args[1];
                            this.dwDataLen = args[2].toInt32();
                            this.dwFlags = args[3].toInt32();

                            var address = parseInt(this.pbData);
                            if (address >= %PROTECTED_START% && address <= %PROTECTED_END%) {
                                this.skipHash = true;
                                console.log('[Hash] Intercepted hash of protected region');
                            }
                        },
                        onLeave: function(retval) {
                            if (this.skipHash) {
                                retval.replace(1);
                                console.log('[Hash] Skipped hashing protected region');
                            }
                        }
                    });
                }

                var cryptGetHashParam = Module.findExportByName('Advapi32.dll', 'CryptGetHashParam');
                if (cryptGetHashParam) {
                    Interceptor.attach(cryptGetHashParam, {
                        onEnter: function(args) {
                            this.hHash = args[0];
                            this.dwParam = args[1].toInt32();
                            this.pbData = args[2];
                            this.pdwDataLen = args[3];
                        },
                        onLeave: function(retval) {
                            if (retval.toInt32() !== 0 && this.dwParam === 2) {
                                var dataLen = this.pdwDataLen.readU32();
                                if (dataLen === 16) {
                                    var expectedMd5 = '%EXPECTED_MD5%';
                                    if (expectedMd5 && expectedMd5.length === 32) {
                                        for (var i = 0; i < 16; i++) {
                                            this.pbData.add(i).writeU8(
                                                parseInt(expectedMd5.substr(i*2, 2), 16)
                                            );
                                        }
                                        console.log('[Hash] Replaced MD5 with expected value');
                                    }
                                } else if (dataLen === 20) {
                                    var expectedSha1 = '%EXPECTED_SHA1%';
                                    if (expectedSha1 && expectedSha1.length === 40) {
                                        for (var i = 0; i < 20; i++) {
                                            this.pbData.add(i).writeU8(
                                                parseInt(expectedSha1.substr(i*2, 2), 16)
                                            );
                                        }
                                        console.log('[Hash] Replaced SHA1 with expected value');
                                    }
                                } else if (dataLen === 32) {
                                    var expectedSha256 = '%EXPECTED_SHA256%';
                                    if (expectedSha256 && expectedSha256.length === 64) {
                                        for (var i = 0; i < 32; i++) {
                                            this.pbData.add(i).writeU8(
                                                parseInt(expectedSha256.substr(i*2, 2), 16)
                                            );
                                        }
                                        console.log('[Hash] Replaced SHA256 with expected value');
                                    }
                                } else if (dataLen === 64) {
                                    var expectedSha512 = '%EXPECTED_SHA512%';
                                    if (expectedSha512 && expectedSha512.length === 128) {
                                        for (var i = 0; i < 64; i++) {
                                            this.pbData.add(i).writeU8(
                                                parseInt(expectedSha512.substr(i*2, 2), 16)
                                            );
                                        }
                                        console.log('[Hash] Replaced SHA512 with expected value');
                                    }
                                }
                            }
                        }
                    });
                }

                var bcryptHashData = Module.findExportByName('Bcrypt.dll', 'BCryptHashData');
                if (bcryptHashData) {
                    Interceptor.attach(bcryptHashData, {
                        onEnter: function(args) {
                            this.hHash = args[0];
                            this.pbInput = args[1];
                            this.cbInput = args[2].toInt32();
                            var address = parseInt(this.pbInput);
                            if (address >= %PROTECTED_START% && address <= %PROTECTED_END%) {
                                this.skipBCryptHash = true;
                                console.log('[BCrypt] Intercepted hash of protected region');
                            }
                        },
                        onLeave: function(retval) {
                            if (this.skipBCryptHash) {
                                retval.replace(0);
                                console.log('[BCrypt] Bypassed BCryptHashData');
                            }
                        }
                    });
                }

                var bcryptFinishHash = Module.findExportByName('Bcrypt.dll', 'BCryptFinishHash');
                if (bcryptFinishHash) {
                    Interceptor.attach(bcryptFinishHash, {
                        onEnter: function(args) {
                            this.pbOutput = args[1];
                            this.cbOutput = args[2].toInt32();
                        },
                        onLeave: function(retval) {
                            if (retval.toInt32() === 0) {
                                if (this.cbOutput === 32) {
                                    var expectedSha256 = '%EXPECTED_SHA256%';
                                    if (expectedSha256 && expectedSha256.length === 64) {
                                        for (var i = 0; i < 32; i++) {
                                            this.pbOutput.add(i).writeU8(
                                                parseInt(expectedSha256.substr(i*2, 2), 16)
                                            );
                                        }
                                        console.log('[BCrypt] Replaced SHA256 with expected value');
                                    }
                                } else if (this.cbOutput === 64) {
                                    var expectedSha512 = '%EXPECTED_SHA512%';
                                    if (expectedSha512 && expectedSha512.length === 128) {
                                        for (var i = 0; i < 64; i++) {
                                            this.pbOutput.add(i).writeU8(
                                                parseInt(expectedSha512.substr(i*2, 2), 16)
                                            );
                                        }
                                        console.log('[BCrypt] Replaced SHA512 with expected value');
                                    }
                                }
                            }
                        }
                    });
                }

                var memcmpFunc = Module.findExportByName(null, 'memcmp');
                if (memcmpFunc) {
                    Interceptor.attach(memcmpFunc, {
                        onEnter: function(args) {
                            this.buf1 = args[0];
                            this.buf2 = args[1];
                            this.size = args[2].toInt32();
                        },
                        onLeave: function(retval) {
                            if (this.size === 16 || this.size === 20 || this.size === 32 || this.size === 64) {
                                retval.replace(0);
                                console.log('[Hash] Forced hash comparison match (size=' + this.size + ')');
                            }
                        }
                    });
                }
            """,
                success_rate=0.90,
                priority=2,
            ),
        )

        strategies.append(
            BypassStrategy(
                name="hmac_bypass",
                check_types=[IntegrityCheckType.HMAC_SIGNATURE],
                frida_script="""
                var expectedHmacKeys = %HMAC_KEYS%;

                var cryptCreateHash = Module.findExportByName('Advapi32.dll', 'CryptCreateHash');
                if (cryptCreateHash) {
                    Interceptor.attach(cryptCreateHash, {
                        onEnter: function(args) {
                            this.hProv = args[0];
                            this.algId = args[1].toInt32();
                            this.hKey = args[2];
                            this.dwFlags = args[3].toInt32();
                            this.phHash = args[4];

                            if (this.hKey && !this.hKey.isNull()) {
                                console.log('[HMAC] Detected HMAC creation with key');
                                this.isHmac = true;
                            }
                        }
                    });
                }

                var cryptHashData = Module.findExportByName('Advapi32.dll', 'CryptHashData');
                if (cryptHashData) {
                    var originalCryptHashData = new NativeFunction(cryptHashData, 'int', ['pointer', 'pointer', 'uint32', 'uint32']);
                    Interceptor.replace(cryptHashData, new NativeCallback(function(hHash, pbData, dwDataLen, dwFlags) {
                        var address = parseInt(pbData);
                        if (address >= %PROTECTED_START% && address <= %PROTECTED_END%) {
                            console.log('[HMAC] Bypassed HMAC hash of protected region');
                            return 1;
                        }
                        return originalCryptHashData(hHash, pbData, dwDataLen, dwFlags);
                    }, 'int', ['pointer', 'pointer', 'uint32', 'uint32']));
                }

                var bcryptCreateHash = Module.findExportByName('Bcrypt.dll', 'BCryptCreateHash');
                if (bcryptCreateHash) {
                    Interceptor.attach(bcryptCreateHash, {
                        onEnter: function(args) {
                            this.hAlgorithm = args[0];
                            this.phHash = args[1];
                            this.pbHashObject = args[2];
                            this.cbHashObject = args[3].toInt32();
                            this.pbSecret = args[4];
                            this.cbSecret = args[5].toInt32();

                            if (this.pbSecret && !this.pbSecret.isNull() && this.cbSecret > 0) {
                                console.log('[HMAC] Detected BCrypt HMAC with ' + this.cbSecret + ' byte key');
                                this.isHmac = true;
                            }
                        }
                    });
                }
            """,
                success_rate=0.85,
                priority=2,
            ),
        )

        strategies.append(
            BypassStrategy(
                name="authenticode_bypass",
                check_types=[IntegrityCheckType.AUTHENTICODE, IntegrityCheckType.CODE_SIGNING],
                frida_script="""
                var winVerifyTrust = Module.findExportByName('Wintrust.dll', 'WinVerifyTrust');
                if (winVerifyTrust) {
                    Interceptor.attach(winVerifyTrust, {
                        onEnter: function(args) {
                            this.hWnd = args[0];
                            this.pgActionID = args[1];
                            this.pWinTrustData = args[2];
                            console.log('[Authenticode] WinVerifyTrust called');
                        },
                        onLeave: function(retval) {
                            retval.replace(0);
                            console.log('[Authenticode] Bypassed WinVerifyTrust - returned success');
                        }
                    });
                }

                var winVerifyTrustEx = Module.findExportByName('Wintrust.dll', 'WinVerifyTrustEx');
                if (winVerifyTrustEx) {
                    Interceptor.attach(winVerifyTrustEx, {
                        onLeave: function(retval) {
                            retval.replace(0);
                            console.log('[Authenticode] Bypassed WinVerifyTrustEx');
                        }
                    });
                }

                var imageGetCertificateData = Module.findExportByName('Imagehlp.dll', 'ImageGetCertificateData');
                if (imageGetCertificateData) {
                    Interceptor.attach(imageGetCertificateData, {
                        onEnter: function(args) {
                            this.fileHandle = args[0];
                            this.certIndex = args[1].toInt32();
                            this.certificate = args[2];
                            this.requiredLength = args[3];
                        },
                        onLeave: function(retval) {
                            if (retval.toInt32() !== 0 && this.certificate && !this.certificate.isNull()) {
                                console.log('[Authenticode] Intercepted certificate data retrieval');
                            }
                        }
                    });
                }

                var imageGetCertificateHeader = Module.findExportByName('Imagehlp.dll', 'ImageGetCertificateHeader');
                if (imageGetCertificateHeader) {
                    Interceptor.attach(imageGetCertificateHeader, {
                        onLeave: function(retval) {
                            console.log('[Authenticode] Intercepted certificate header');
                        }
                    });
                }

                var cryptCATAdminCalcHash = Module.findExportByName('Wintrust.dll', 'CryptCATAdminCalcHashFromFileHandle');
                if (cryptCATAdminCalcHash) {
                    Interceptor.attach(cryptCATAdminCalcHash, {
                        onEnter: function(args) {
                            this.hFile = args[0];
                            this.pcbHash = args[1];
                            this.pbHash = args[2];
                            this.dwFlags = args[3].toInt32();
                        },
                        onLeave: function(retval) {
                            if (retval.toInt32() !== 0 && this.pbHash && !this.pbHash.isNull()) {
                                var hashSize = this.pcbHash.readU32();
                                if (hashSize === 32) {
                                    var expectedSha256 = '%EXPECTED_SHA256%';
                                    if (expectedSha256 && expectedSha256.length === 64) {
                                        for (var i = 0; i < 32; i++) {
                                            this.pbHash.add(i).writeU8(
                                                parseInt(expectedSha256.substr(i*2, 2), 16)
                                            );
                                        }
                                        console.log('[Authenticode] Replaced catalog hash');
                                    }
                                }
                            }
                        }
                    });
                }
            """,
                success_rate=0.88,
                priority=3,
            ),
        )

        strategies.append(
            BypassStrategy(
                name="certificate_bypass",
                check_types=[IntegrityCheckType.CERTIFICATE, IntegrityCheckType.SIGNATURE],
                frida_script="""
                var certVerify = Module.findExportByName('Crypt32.dll', 'CertVerifyCertificateChainPolicy');
                if (certVerify) {
                    Interceptor.attach(certVerify, {
                        onEnter: function(args) {
                            this.pszPolicyOID = args[0];
                            this.pChainContext = args[1];
                            this.pPolicyPara = args[2];
                            this.pPolicyStatus = args[3];
                        },
                        onLeave: function(retval) {
                            if (this.pPolicyStatus && !this.pPolicyStatus.isNull()) {
                                this.pPolicyStatus.writeU32(0);
                                this.pPolicyStatus.add(4).writeU32(0);
                                console.log('[Certificate] Cleared policy status errors');
                            }
                            retval.replace(1);
                            console.log('[Certificate] Bypassed certificate chain verification');
                        }
                    });
                }

                var certGetCertificateChain = Module.findExportByName('Crypt32.dll', 'CertGetCertificateChain');
                if (certGetCertificateChain) {
                    Interceptor.attach(certGetCertificateChain, {
                        onLeave: function(retval) {
                            console.log('[Certificate] Certificate chain retrieved');
                        }
                    });
                }

                var cryptVerifySignature = Module.findExportByName('Advapi32.dll', 'CryptVerifySignatureW');
                if (!cryptVerifySignature) {
                    cryptVerifySignature = Module.findExportByName('Advapi32.dll', 'CryptVerifySignatureA');
                }
                if (cryptVerifySignature) {
                    Interceptor.attach(cryptVerifySignature, {
                        onLeave: function(retval) {
                            retval.replace(1);
                            console.log('[Certificate] Bypassed signature verification');
                        }
                    });
                }
            """,
                success_rate=0.85,
                priority=3,
            ),
        )

        strategies.append(
            BypassStrategy(
                name="size_check_bypass",
                check_types=[IntegrityCheckType.SIZE_CHECK],
                frida_script="""
                var getFileSize = Module.findExportByName('kernel32.dll', 'GetFileSize');
                if (getFileSize) {
                    Interceptor.attach(getFileSize, {
                        onLeave: function(retval) {
                            retval.replace(%EXPECTED_SIZE%);
                            console.log('[Size] Returned expected size: ' + retval);
                        }
                    });
                }

                var getFileSizeEx = Module.findExportByName('kernel32.dll', 'GetFileSizeEx');
                if (getFileSizeEx) {
                    Interceptor.attach(getFileSizeEx, {
                        onEnter: function(args) {
                            this.sizePtr = args[1];
                        },
                        onLeave: function(retval) {
                            if (retval.toInt32() !== 0 && this.sizePtr) {
                                this.sizePtr.writeS64(%EXPECTED_SIZE%);
                                console.log('[Size] Set expected size');
                            }
                        }
                    });
                }
            """,
                success_rate=0.92,
                priority=4,
            ),
        )

        strategies.append(
            BypassStrategy(
                name="checksum_bypass",
                check_types=[IntegrityCheckType.CHECKSUM],
                frida_script="""
                var checkSumMapped = Module.findExportByName('Imagehlp.dll', 'CheckSumMappedFile');
                if (checkSumMapped) {
                    Interceptor.attach(checkSumMapped, {
                        onEnter: function(args) {
                            this.headerSumPtr = args[2];
                            this.checkSumPtr = args[3];
                        },
                        onLeave: function(retval) {
                            if (this.headerSumPtr && !this.headerSumPtr.isNull()) {
                                this.headerSumPtr.writeU32(%HEADER_CHECKSUM%);
                            }
                            if (this.checkSumPtr && !this.checkSumPtr.isNull()) {
                                this.checkSumPtr.writeU32(%IMAGE_CHECKSUM%);
                            }
                            console.log('[Checksum] Set PE checksums');
                        }
                    });
                }

                var mapFileAndCheckSum = Module.findExportByName('Imagehlp.dll', 'MapFileAndCheckSumW');
                if (mapFileAndCheckSum) {
                    Interceptor.attach(mapFileAndCheckSum, {
                        onEnter: function(args) {
                            this.headerSumPtr = args[1];
                            this.checkSumPtr = args[2];
                        },
                        onLeave: function(retval) {
                            if (this.headerSumPtr && !this.headerSumPtr.isNull()) {
                                this.headerSumPtr.writeU32(%HEADER_CHECKSUM%);
                            }
                            if (this.checkSumPtr && !this.checkSumPtr.isNull()) {
                                this.checkSumPtr.writeU32(%IMAGE_CHECKSUM%);
                            }
                            console.log('[Checksum] Set PE checksums (MapFileAndCheckSum)');
                        }
                    });
                }
            """,
                success_rate=0.88,
                priority=5,
            ),
        )

        strategies.append(
            BypassStrategy(
                name="memory_hash_bypass",
                check_types=[IntegrityCheckType.MEMORY_HASH],
                frida_script="""
                var protectedRegions = %PROTECTED_REGIONS%;

                var readProcessMemory = Module.findExportByName('kernel32.dll', 'ReadProcessMemory');
                if (readProcessMemory) {
                    Interceptor.attach(readProcessMemory, {
                        onEnter: function(args) {
                            this.hProcess = args[0];
                            this.lpBaseAddress = args[1];
                            this.lpBuffer = args[2];
                            this.nSize = args[3].toInt32();
                        },
                        onLeave: function(retval) {
                            if (retval.toInt32() !== 0) {
                                var address = parseInt(this.lpBaseAddress);
                                for (var i = 0; i < protectedRegions.length; i++) {
                                    var region = protectedRegions[i];
                                    if (address >= region.start && address < region.end) {
                                        if (region.original && region.original.length > 0) {
                                            Memory.writeByteArray(this.lpBuffer, region.original);
                                            console.log('[MemHash] Restored original bytes');
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                    });
                }
            """,
                success_rate=0.80,
                priority=6,
            ),
        )

        return strategies

    def bypass_checks(self, process_name: str, checks: list[IntegrityCheck]) -> bool:
        """Bypass detected integrity checks using runtime hooks."""
        try:
            self.session = frida.attach(process_name)

            combined_script = self._build_bypass_script(checks)

            self.script = self.session.create_script(combined_script)

            def message_wrapper(message: Any, data: bytes | None) -> None:
                if isinstance(message, dict):
                    self._on_message(message, data)

            self.script.on("message", message_wrapper)
            self.script.load()

            logger.info("Installed %d integrity check bypasses", len(checks))
            return True

        except Exception as e:
            logger.exception("Failed to bypass integrity checks: %s", e, exc_info=True)
            return False

    def _build_bypass_script(self, checks: list[IntegrityCheck]) -> str:
        """Build combined Frida script for all checks."""
        script_parts: list[str] = []

        checks_by_type: dict[IntegrityCheckType, list[IntegrityCheck]] = {}
        for check in checks:
            if check.check_type not in checks_by_type:
                checks_by_type[check.check_type] = []
            checks_by_type[check.check_type].append(check)

        for check_type, type_checks in checks_by_type.items():
            if strategy := self._get_best_strategy(check_type):
                script = self._customize_script(strategy.frida_script, type_checks)
                script_parts.extend((f"// {strategy.name}", script))
        return "\n".join(script_parts)

    def _get_best_strategy(self, check_type: IntegrityCheckType) -> BypassStrategy | None:
        """Get best bypass strategy for check type."""
        best_strategy = None
        best_priority = 999

        for strategy in self.bypass_strategies:
            if check_type in strategy.check_types and strategy.priority < best_priority:
                best_strategy = strategy
                best_priority = strategy.priority

        return best_strategy

    def _customize_script(self, script_template: str, checks: list[IntegrityCheck]) -> str:
        """Customize script template with actual recalculated values."""
        script = script_template

        if checks:
            first_check = checks[0]

            min_addr = min(c.address for c in checks)
            max_addr = max(c.address + c.size for c in checks)
            script = script.replace("%PROTECTED_START%", str(min_addr))
            script = script.replace("%PROTECTED_END%", str(max_addr))

            try:
                binary_path = first_check.binary_path
                if binary_path and os.path.exists(binary_path):
                    with open(binary_path, "rb") as f:
                        binary_data = f.read()

                    expected_crc32 = self.checksum_calc.calculate_crc32_zlib(binary_data)
                    expected_crc64 = self.checksum_calc.calculate_crc64(binary_data)
                    expected_md5 = self.checksum_calc.calculate_md5(binary_data)
                    expected_sha1 = self.checksum_calc.calculate_sha1(binary_data)
                    expected_sha256 = self.checksum_calc.calculate_sha256(binary_data)
                    expected_sha512 = self.checksum_calc.calculate_sha512(binary_data)

                    script = script.replace("%EXPECTED_CRC32%", str(expected_crc32))
                    script = script.replace("%EXPECTED_CRC64%", str(expected_crc64))
                    script = script.replace("%EXPECTED_MD5%", expected_md5)
                    script = script.replace("%EXPECTED_SHA1%", expected_sha1)
                    script = script.replace("%EXPECTED_SHA256%", expected_sha256)
                    script = script.replace("%EXPECTED_SHA512%", expected_sha512)

                    hmac_keys = self.checksum_calc.extract_hmac_keys(binary_path)
                    hmac_keys_json = str(hmac_keys).replace("'", '"') if hmac_keys else "[]"
                    script = script.replace("%HMAC_KEYS%", hmac_keys_json)

                    if binary_path.lower().endswith((".exe", ".dll", ".sys")):
                        pe = pefile.PE(binary_path)
                        actual_size = pe.OPTIONAL_HEADER.SizeOfImage
                        actual_header_checksum = pe.OPTIONAL_HEADER.CheckSum
                        actual_image_checksum = self.checksum_calc.recalculate_pe_checksum(binary_path)
                        pe.close()

                        script = script.replace("%EXPECTED_SIZE%", str(actual_size))
                        script = script.replace("%HEADER_CHECKSUM%", str(actual_header_checksum))
                        script = script.replace("%IMAGE_CHECKSUM%", str(actual_image_checksum))

                    protected_regions = [
                        {
                            "start": check.address,
                            "end": check.address + check.size,
                            "original": (
                                list(binary_data[check.address : check.address + check.size]) if check.address < len(binary_data) else []
                            ),
                        }
                        for check in checks
                        if check.address and check.size
                    ]
                    script = script.replace("%PROTECTED_REGIONS%", str(protected_regions))

            except Exception as e:
                logger.debug("Script customization error: %s", e, exc_info=True)
                script = script.replace("%EXPECTED_CRC32%", "0")
                script = script.replace("%EXPECTED_CRC64%", "0")
                script = script.replace("%EXPECTED_MD5%", "")
                script = script.replace("%EXPECTED_SHA1%", "")
                script = script.replace("%EXPECTED_SHA256%", "")
                script = script.replace("%EXPECTED_SHA512%", "")
                script = script.replace("%EXPECTED_SIZE%", "1048576")
                script = script.replace("%HEADER_CHECKSUM%", "0")
                script = script.replace("%IMAGE_CHECKSUM%", "0")
                script = script.replace("%PROTECTED_REGIONS%", "[]")
                script = script.replace("%HMAC_KEYS%", "[]")

        return script

    def _on_message(self, message: dict[str, Any], data: bytes | None) -> None:
        """Handle Frida script messages."""
        if message.get("type") == "send":
            logger.info("[Frida] %s", message.get("payload", ""))
        elif message.get("type") == "error":
            logger.exception("[Frida Error] %s", message.get("stack", ""))

    def cleanup(self) -> None:
        """Clean up Frida session."""
        if self.script is not None:
            self.script.unload()
        if self.session is not None:
            self.session.detach()


class BinaryPatcher:
    """Patches binaries to remove integrity checks and recalculates checksums."""

    def __init__(self) -> None:
        """Initialize the BinaryPatcher with checksum calculator."""
        self.checksum_calc = ChecksumRecalculator()
        self.patch_history: list[dict[str, int | bytes | str]] = []

    def patch_integrity_checks(
        self,
        binary_path: str,
        checks: list[IntegrityCheck],
        output_path: str | None = None,
    ) -> tuple[bool, ChecksumRecalculation | None]:
        """Patch binary to remove integrity checks and recalculate all checksums."""
        final_output_path = (
            output_path if output_path is not None else str(Path(binary_path).with_suffix(f".patched{Path(binary_path).suffix}"))
        )

        try:
            with open(binary_path, "rb") as f:
                original_data = bytearray(f.read())

            pe = pefile.PE(binary_path)
            patch_data = bytearray(original_data)

            for check in checks:
                if check.bypass_method == "patch_inline":
                    offset = self._rva_to_offset(pe, check.address)
                    if offset and offset + check.size <= len(patch_data):
                        for i in range(check.size):
                            patch_data[offset + i] = 0x90

                        self.patch_history.append({
                            "address": check.address,
                            "size": check.size,
                            "original": bytes(original_data[offset : offset + check.size]),
                            "patched": bytes([0x90] * check.size),
                            "type": check.check_type.name,
                        })

                elif check.check_type in [IntegrityCheckType.CRC32, IntegrityCheckType.CHECKSUM]:
                    if offset := self._rva_to_offset(pe, check.address):
                        patch_bytes = b"\xb8\x00\x00\x00\x00\xc3"

                        for i, byte in enumerate(patch_bytes):
                            if offset + i < len(patch_data):
                                patch_data[offset + i] = byte

                        self.patch_history.append({
                            "address": check.address,
                            "size": len(patch_bytes),
                            "original": bytes(original_data[offset : offset + len(patch_bytes)]),
                            "patched": patch_bytes,
                            "type": check.check_type.name,
                        })

            with open(final_output_path, "wb") as f:
                f.write(patch_data)

            pe_patched = pefile.PE(final_output_path)
            new_checksum = self.checksum_calc.recalculate_pe_checksum(final_output_path)
            pe_patched.OPTIONAL_HEADER.CheckSum = new_checksum

            with open(final_output_path, "wb") as f:
                f.write(pe_patched.write())

            pe.close()
            pe_patched.close()

            checksums = self.checksum_calc.recalculate_for_patched_binary(binary_path, final_output_path)

            logger.info("Binary patched: %s", final_output_path)
            logger.info("Applied %d patches", len(self.patch_history))
            logger.info("Recalculated PE checksum: %s", hex(new_checksum))
            logger.info("Original CRC32: %s", hex(checksums.original_crc32))
            logger.info("Patched CRC32: %s", hex(checksums.patched_crc32))

            return True, checksums

        except Exception as e:
            logger.exception("Binary patching failed: %s", e, exc_info=True)
            return False, None

    def _rva_to_offset(self, pe: pefile.PE, rva: int) -> int | None:
        """Convert RVA to file offset."""
        return next(
            (
                section.PointerToRawData + (rva - section.VirtualAddress)
                for section in pe.sections
                if section.VirtualAddress <= rva < section.VirtualAddress + section.Misc_VirtualSize
            ),
            None,
        )


class IntegrityCheckDefeatSystem:
    """Complete integrity check defeat system with detection, bypass, and patching."""

    def __init__(self) -> None:
        """Initialize the IntegrityCheckDefeatSystem with all components."""
        self.detector = IntegrityCheckDetector()
        self.bypasser = IntegrityBypassEngine()
        self.patcher = BinaryPatcher()
        self.checksum_calc = ChecksumRecalculator()

    def find_embedded_checksums(self, binary_path: str) -> list[ChecksumLocation]:
        """Find locations where checksums are embedded in the binary."""
        return self.checksum_calc.find_checksum_locations(binary_path)

    def extract_hmac_keys(self, binary_path: str) -> list[dict[str, str | int]]:
        """Extract potential HMAC keys from binary."""
        return self.checksum_calc.extract_hmac_keys(binary_path)

    def patch_embedded_checksums(
        self,
        binary_path: str,
        checksum_locations: list[ChecksumLocation],
        output_path: str | None = None,
    ) -> bool:
        """Patch embedded checksums in binary with recalculated values."""
        final_output_path = (
            output_path if output_path is not None else str(Path(binary_path).with_suffix(f".patched{Path(binary_path).suffix}"))
        )

        try:
            with open(binary_path, "rb") as f:
                binary_data = bytearray(f.read())

            for location in checksum_locations:
                if location.offset + location.size <= len(binary_data):
                    binary_data[location.offset : location.offset + location.size] = location.calculated_value
                    logger.info("Patched %s at offset %s", location.algorithm.name, hex(location.offset))

            with open(final_output_path, "wb") as f:
                f.write(binary_data)

            logger.info("Patched %d embedded checksums: %s", len(checksum_locations), final_output_path)
            return True

        except Exception as e:
            logger.exception("Failed to patch embedded checksums: %s", e, exc_info=True)
            return False

    def defeat_integrity_checks(
        self,
        binary_path: str,
        process_name: str | None = None,
        patch_binary: bool = False,
    ) -> dict[str, Any]:
        """Complete integrity check defeat workflow."""
        logger.info("Detecting integrity checks: %s", binary_path)
        checks = self.detector.detect_checks(binary_path)
        result: dict[str, Any] = {
            "success": False,
            "checks_bypassed": 0,
            "binary_patched": False,
            "checksums": None,
            "details": [],
            "checks_detected": len(checks),
        }
        if not checks:
            logger.info("No integrity checks detected")
            result["success"] = True
            return result

        logger.info("Detected %d integrity checks", len(checks))

        for check in checks:
            details_list = result.get("details")
            if isinstance(details_list, list):
                details_list.append({
                    "type": check.check_type.name,
                    "address": hex(check.address),
                    "function": check.function_name,
                    "bypass_method": check.bypass_method,
                    "confidence": check.confidence,
                    "section": check.section_name,
                })

        if process_name:
            logger.info("Applying runtime bypasses: %s", process_name)
            if self.bypasser.bypass_checks(process_name, checks):
                result["checks_bypassed"] = len(checks)
                result["success"] = True
                logger.info("Successfully installed runtime bypasses")
            else:
                logger.exception("Runtime bypass installation failed")

        if patch_binary:
            logger.info("Patching binary to remove integrity checks")
            success, checksums = self.patcher.patch_integrity_checks(binary_path, checks)
            result["binary_patched"] = success
            if checksums:
                result["checksums"] = {
                    "original_crc32": hex(checksums.original_crc32),
                    "patched_crc32": hex(checksums.patched_crc32),
                    "original_crc64": hex(checksums.original_crc64),
                    "patched_crc64": hex(checksums.patched_crc64),
                    "original_md5": checksums.original_md5,
                    "patched_md5": checksums.patched_md5,
                    "original_sha1": checksums.original_sha1,
                    "patched_sha1": checksums.patched_sha1,
                    "original_sha256": checksums.original_sha256,
                    "patched_sha256": checksums.patched_sha256,
                    "original_sha512": checksums.original_sha512,
                    "patched_sha512": checksums.patched_sha512,
                    "pe_checksum": hex(checksums.pe_checksum),
                    "sections": dict(checksums.sections),
                    "hmac_keys": list(checksums.hmac_keys),
                }
                result["success"] = True

        return result

    def generate_bypass_script(self, binary_path: str) -> str:
        """Generate Frida script for bypassing integrity checks."""
        checks = self.detector.detect_checks(binary_path)

        if not checks:
            return "// No integrity checks detected"

        for check in checks:
            check.binary_path = binary_path

        return self.bypasser._build_bypass_script(checks)

    def recalculate_checksums(self, original_path: str, patched_path: str) -> ChecksumRecalculation:
        """Recalculate all checksums for comparison."""
        return self.checksum_calc.recalculate_for_patched_binary(original_path, patched_path)


def main() -> None:
    """Test entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Integrity Check Defeat System")
    parser.add_argument("binary", help="Binary file to analyze")
    parser.add_argument("-p", "--process", help="Process name for runtime bypass")
    parser.add_argument("-s", "--script", action="store_true", help="Generate bypass script")
    parser.add_argument("--patch", action="store_true", help="Patch binary")
    parser.add_argument("--find-checksums", action="store_true", help="Find embedded checksums")
    parser.add_argument("--extract-keys", action="store_true", help="Extract HMAC keys")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    defeat_system = IntegrityCheckDefeatSystem()

    if args.find_checksums:
        locations = defeat_system.find_embedded_checksums(args.binary)
        logger.info("=== Found %d Embedded Checksums ===", len(locations))
        for loc in locations:
            logger.info(
                "- %s at offset %s (size=%d, confidence=%.1f%%)", loc.algorithm.name, hex(loc.offset), loc.size, loc.confidence * 100
            )
            logger.info("  Current:    %s", loc.current_value.hex())
            logger.info("  Calculated: %s", loc.calculated_value.hex())
        return

    if args.extract_keys:
        keys = defeat_system.extract_hmac_keys(args.binary)
        logger.info("=== Found %d Potential HMAC Keys ===", len(keys))
        for key in keys:
            offset_val = key.get("offset")
            size_val = key.get("size")
            key_hex_val = key.get("key_hex")
            entropy_val = key.get("entropy")
            confidence_val = key.get("confidence")
            if isinstance(offset_val, int) and isinstance(size_val, int):
                logger.info("- Offset: %s Size: %d bytes", hex(offset_val), size_val)
            if isinstance(key_hex_val, str):
                logger.info("  Key: %s", key_hex_val)
            if isinstance(entropy_val, (int, float)) and isinstance(confidence_val, (int, float)):
                logger.info("  Entropy: %.2f Confidence: %.1f%%", float(entropy_val), float(confidence_val) * 100)
        return

    if args.script:
        script = defeat_system.generate_bypass_script(args.binary)
        logger.info("=== Generated Bypass Script ===")
        logger.info("%s", script)
    else:
        result = defeat_system.defeat_integrity_checks(
            args.binary,
            args.process,
            patch_binary=args.patch,
        )

        logger.info("=== Integrity Check Defeat Results ===")
        logger.info("Checks Detected: %d", result["checks_detected"])
        logger.info("Checks Bypassed: %d", result["checks_bypassed"])
        logger.info("Binary Patched: %s", result["binary_patched"])
        logger.info("Success: %s", result["success"])

        if result["details"]:
            logger.info("=== Detected Checks ===")
            for detail in result["details"]:
                logger.info("- %s at %s", detail["type"], detail["address"])
                logger.info("  Function: %s", detail["function"])
                logger.info("  Bypass: %s", detail["bypass_method"])
                logger.info("  Confidence: %.1f%%", detail["confidence"] * 100)

        if result["checksums"]:
            logger.info("=== Checksum Recalculation ===")
            cs = result["checksums"]
            logger.info("Original CRC32: %s", cs["original_crc32"])
            logger.info("Patched CRC32:  %s", cs["patched_crc32"])
            logger.info("Original CRC64: %s", cs["original_crc64"])
            logger.info("Patched CRC64:  %s", cs["patched_crc64"])
            logger.info("Original MD5:   %s", cs["original_md5"])
            logger.info("Patched MD5:    %s", cs["patched_md5"])
            logger.info("Original SHA1:  %s", cs["original_sha1"])
            logger.info("Patched SHA1:   %s", cs["patched_sha1"])
            logger.info("Original SHA256: %s", cs["original_sha256"])
            logger.info("Patched SHA256:  %s", cs["patched_sha256"])
            logger.info("Original SHA512: %s", cs["original_sha512"])
            logger.info("Patched SHA512:  %s", cs["patched_sha512"])
            logger.info("PE Checksum:    %s", cs["pe_checksum"])

            hmac_keys_list = cs.get("hmac_keys")
            if isinstance(hmac_keys_list, list) and hmac_keys_list:
                logger.info("=== Extracted HMAC Keys ===")
                for key in hmac_keys_list[:5]:
                    if isinstance(key, dict):
                        offset_val = key.get("offset")
                        key_hex_val = key.get("key_hex")
                        confidence_val = key.get("confidence")
                        if isinstance(offset_val, int) and isinstance(key_hex_val, str) and isinstance(confidence_val, (int, float)):
                            logger.info(
                                "- Key at offset %s: %s... (confidence=%.1f%%)",
                                hex(offset_val),
                                key_hex_val[:32],
                                float(confidence_val) * 100,
                            )


if __name__ == "__main__":
    main()
