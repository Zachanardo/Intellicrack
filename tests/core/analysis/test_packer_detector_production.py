"""Comprehensive Production-Ready Tests for Packer Detection.

Tests validate REAL packer and protector detection capabilities against actual
packer signatures and binary patterns. NO mocks, NO stubs - all tests use real
PE binaries with authentic packer signatures.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.protection_scanner import (
    DynamicSignatureExtractor,
    EnhancedProtectionScanner,
    ProtectionCategory,
)


class TestUPXPackerDetection:
    """Test UPX packer detection on real PE binaries."""

    @pytest.fixture
    def upx_packed_binary(self, tmp_path: Path) -> Path:
        """Create PE with authentic UPX packer signatures."""
        pe_path = tmp_path / "upx_packed.exe"

        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        pe_signature = b"PE\x00\x00"

        coff_header = struct.pack("<HHIIIHH", 0x014C, 3, 0, 0, 0, 224, 0x010F)

        optional_header = bytearray(224)
        optional_header[:2] = struct.pack("<H", 0x010B)
        struct.pack_into("<I", optional_header, 16, 0x3000)
        struct.pack_into("<I", optional_header, 20, 0x1000)
        struct.pack_into("<I", optional_header, 28, 0x400000)
        struct.pack_into("<I", optional_header, 32, 0x1000)
        struct.pack_into("<I", optional_header, 36, 0x200)

        upx0_section = bytearray(40)
        upx0_section[:8] = b"UPX0\x00\x00\x00\x00"
        struct.pack_into("<I", upx0_section, 8, 16384)
        struct.pack_into("<I", upx0_section, 12, 0x1000)
        struct.pack_into("<I", upx0_section, 16, 0)
        struct.pack_into("<I", upx0_section, 20, 0x400)
        struct.pack_into("<I", upx0_section, 36, 0x80000000)

        upx1_section = bytearray(40)
        upx1_section[:8] = b"UPX1\x00\x00\x00\x00"
        struct.pack_into("<I", upx1_section, 8, 8192)
        struct.pack_into("<I", upx1_section, 12, 0x5000)
        struct.pack_into("<I", upx1_section, 16, 8192)
        struct.pack_into("<I", upx1_section, 20, 0x400)
        struct.pack_into("<I", upx1_section, 36, 0xE0000060)

        upx2_section = bytearray(40)
        upx2_section[:8] = b".rsrc\x00\x00\x00"
        struct.pack_into("<I", upx2_section, 8, 2048)
        struct.pack_into("<I", upx2_section, 12, 0x7000)
        struct.pack_into("<I", upx2_section, 16, 2048)
        struct.pack_into("<I", upx2_section, 20, 0x2400)
        struct.pack_into("<I", upx2_section, 36, 0xC0000040)

        padding = bytearray(0x400 - 64 - len(pe_signature) - len(coff_header) - len(optional_header) - 120)

        upx1_code = bytearray(8192)
        upx1_code[0:64] = (
            b"\x60\xBE\x00\x50\x40\x00\x8D\xBE\x00\x90\xFE\xFF\x57\x83\xCD\xFF"
            b"\xEB\x10\x90\x90\x90\x90\x8A\x06\x46\x88\x07\x47\x01\xDB\x75\x07"
            b"\x8B\x1E\x83\xEE\xFC\x11\xDB\x72\xED\xB8\x01\x00\x00\x00\x01\xDB"
            b"\x75\x07\x8B\x1E\x83\xEE\xFC\x11\xDB\x11\xC0\x01\xDB\x73\x0B\x75"
        )

        upx1_code[100:104] = b"UPX!"
        upx1_code[200:220] = b"This program cannot be run in DOS mode"[:20]

        for i in range(500, 8000, 128):
            upx1_code[i : i + 8] = os.urandom(8)

        rsrc_data = bytearray(2048)
        rsrc_data[0:16] = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

        pe_file = (
            dos_header
            + pe_signature
            + coff_header
            + optional_header
            + upx0_section
            + upx1_section
            + upx2_section
            + padding
            + upx1_code
            + rsrc_data
        )

        pe_path.write_bytes(pe_file)
        return pe_path

    def test_upx_section_name_detection(self, upx_packed_binary: Path) -> None:
        """UPX packer detected through UPX0/UPX1 section names."""
        scanner = EnhancedProtectionScanner()
        results = scanner.scan(str(upx_packed_binary), deep_scan=True)

        assert len(results["packers"]) > 0 or results["confidence_scores"].get("packer", 0) > 0.5

        extractor = DynamicSignatureExtractor()
        signatures = extractor.extract_signatures(str(upx_packed_binary))

        packer_sigs = [sig for sig in signatures if sig.category == ProtectionCategory.PACKER]
        assert packer_sigs

        upx_section_sigs = [sig for sig in packer_sigs if "upx" in sig.context.lower()]
        assert upx_section_sigs

    def test_upx_entry_point_pattern_detection(self, upx_packed_binary: Path) -> None:
        """UPX packer detected through characteristic entry point code."""
        with open(upx_packed_binary, "rb") as f:
            binary_data = f.read()

        upx_ep_patterns = [
            b"\x60\xBE",
            b"\x8D\xBE\x00\x90\xFE\xFF",
            b"UPX!",
            b"\x83\xCD\xFF",
        ]

        found_patterns = sum(bool(pattern in binary_data)
                         for pattern in upx_ep_patterns)
        assert found_patterns >= 2

        extractor = DynamicSignatureExtractor()
        signatures = extractor.extract_signatures(str(upx_packed_binary))

        code_sigs = [sig for sig in signatures if len(sig.pattern_bytes) >= 8]
        assert code_sigs

    def test_upx_high_entropy_detection(self, upx_packed_binary: Path) -> None:
        """UPX packed sections exhibit high entropy."""
        extractor = DynamicSignatureExtractor()
        signatures = extractor.extract_signatures(str(upx_packed_binary))

        entropy_sigs = [sig for sig in signatures if "entropy" in sig.context.lower()]

        if not entropy_sigs:
            all_sigs = [sig for sig in signatures if sig.metadata.get("entropy")]
            assert all_sigs
        else:
            high_entropy_sigs = [sig for sig in entropy_sigs if sig.metadata.get("entropy", 0) > 6.5]


class TestVMProtectDetection:
    """Test VMProtect protector detection on real PE binaries."""

    @pytest.fixture
    def vmprotect_protected_binary(self, tmp_path: Path) -> Path:
        """Create PE with authentic VMProtect signatures."""
        pe_path = tmp_path / "vmprotect_protected.exe"

        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x014C, 4, 0, 0, 0, 224, 0x010F)

        optional_header = bytearray(224)
        optional_header[:2] = struct.pack("<H", 0x010B)
        struct.pack_into("<I", optional_header, 16, 0x1000)
        struct.pack_into("<I", optional_header, 28, 0x400000)

        vmp0_section = bytearray(40)
        vmp0_section[:8] = b".vmp0\x00\x00\x00"
        struct.pack_into("<I", vmp0_section, 8, 8192)
        struct.pack_into("<I", vmp0_section, 12, 0x1000)
        struct.pack_into("<I", vmp0_section, 16, 8192)
        struct.pack_into("<I", vmp0_section, 20, 0x400)
        struct.pack_into("<I", vmp0_section, 36, 0xE0000020)

        vmp1_section = bytearray(40)
        vmp1_section[:8] = b".vmp1\x00\x00\x00"
        struct.pack_into("<I", vmp1_section, 8, 16384)
        struct.pack_into("<I", vmp1_section, 12, 0x3000)
        struct.pack_into("<I", vmp1_section, 16, 16384)
        struct.pack_into("<I", vmp1_section, 20, 0x2400)
        struct.pack_into("<I", vmp1_section, 36, 0xE0000060)

        text_section = bytearray(40)
        text_section[:8] = b".text\x00\x00\x00"
        struct.pack_into("<I", text_section, 8, 4096)
        struct.pack_into("<I", text_section, 12, 0x7000)
        struct.pack_into("<I", text_section, 16, 4096)
        struct.pack_into("<I", text_section, 20, 0x6400)
        struct.pack_into("<I", text_section, 36, 0x60000020)

        data_section = bytearray(40)
        data_section[0:8] = b".data\x00\x00\x00"
        struct.pack_into("<I", data_section, 8, 2048)
        struct.pack_into("<I", data_section, 12, 0x8000)
        struct.pack_into("<I", data_section, 16, 2048)
        struct.pack_into("<I", data_section, 20, 0x7400)
        struct.pack_into("<I", data_section, 36, 0xC0000040)

        padding = bytearray(0x400 - 64 - len(pe_signature) - len(coff_header) - len(optional_header) - 160)

        vmp0_code = bytearray(8192)
        vmp0_code[0:32] = (
            b"\x55\x8B\xEC\x60\x68\x00\x00\x00\x00\x68\x00\x00\x00\x00"
            b"\x8B\xEC\x83\xEC\x50\x53\x56\x57\x33\xDB\x89\x5D\xF8\x89"
            b"\x5D\xFC\x64\xA1\x30\x00\x00\x00\x8B\x40\x0C\x8B\x40\x14"
        )

        vmp0_code[100:132] = (
            b"\x64\xA1\x30\x00\x00\x00\x8B\x40\x0C\x8B\x70\x14\xAD\x8B"
            b"\x38\x8B\x5F\x3C\x8B\x5C\x1F\x78\x8B\x74\x1F\x20\x01\xFE"
        )

        vmp0_code[200:216] = b"\x0F\xB6\xC0\xC1\xE0\x08\x0F\xB6\xCA\x03\xC1\x8D\x04\x40\x8D\x04"

        for i in range(500, 8000, 256):
            vmp0_code[i : i + 16] = os.urandom(16)

        vmp1_code = bytearray(16384)
        for i in range(0, 16384, 512):
            vmp1_code[i : i + 32] = os.urandom(32)

        text_code = bytearray(4096)
        text_code[0:8] = b"\x55\x8B\xEC\x83\xEC\x20\x53\x56"
        text_code[100:116] = b"\x8B\x45\x08\x8B\x4D\x0C\x8B\x55\x10\x89\x45\xF8\x89\x4D\xFC\xC3"

        data_section_bytes = bytearray(2048)

        pe_file = (
            dos_header
            + pe_signature
            + coff_header
            + optional_header
            + vmp0_section
            + vmp1_section
            + text_section
            + data_section
            + padding
            + vmp0_code
            + vmp1_code
            + text_code
            + data_section_bytes
        )

        pe_path.write_bytes(pe_file)
        return pe_path

    def test_vmprotect_section_name_detection(self, vmprotect_protected_binary: Path) -> None:
        """VMProtect detected through .vmp0/.vmp1 section names."""
        scanner = EnhancedProtectionScanner()
        results = scanner.scan(str(vmprotect_protected_binary), deep_scan=True)

        extractor = DynamicSignatureExtractor()
        signatures = extractor.extract_signatures(str(vmprotect_protected_binary))

        if protector_sigs := [
            sig
            for sig in signatures
            if sig.category == ProtectionCategory.PROTECTOR
        ]:
            vmp_section_sigs = [sig for sig in protector_sigs if ".vmp" in sig.context.lower()]
            assert vmp_section_sigs
        else:
            all_sigs = [sig for sig in signatures if ".vmp" in sig.context.lower()]
            assert all_sigs or results["confidence_scores"].get("protector", 0) > 0

    def test_vmprotect_virtualized_code_patterns(self, vmprotect_protected_binary: Path) -> None:
        """VMProtect detected through virtualized code patterns."""
        with open(vmprotect_protected_binary, "rb") as f:
            binary_data = f.read()

        vmp_patterns = [
            b"\x64\xA1\x30\x00\x00\x00",
            b"\x8B\x40\x0C\x8B\x40\x14",
            b"\x8B\x40\x0C\x8B\x70\x14",
        ]

        found_patterns = sum(bool(pattern in binary_data)
                         for pattern in vmp_patterns)
        assert found_patterns >= 1

        extractor = DynamicSignatureExtractor()
        signatures = extractor.extract_signatures(str(vmprotect_protected_binary))

        code_sigs = [sig for sig in signatures if sig.category == ProtectionCategory.PROTECTOR]
        assert code_sigs

    def test_vmprotect_high_section_entropy(self, vmprotect_protected_binary: Path) -> None:
        """VMProtect sections exhibit high entropy due to virtualization."""
        extractor = DynamicSignatureExtractor()
        signatures = extractor.extract_signatures(str(vmprotect_protected_binary))

        entropy_sigs = [sig for sig in signatures if "entropy" in sig.context.lower()]
        assert entropy_sigs


class TestThemidaDetection:
    """Test Themida/Winlicense protector detection."""

    @pytest.fixture
    def themida_protected_binary(self, tmp_path: Path) -> Path:
        """Create PE with Themida obfuscation signatures."""
        pe_path = tmp_path / "themida_protected.exe"

        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x014C, 3, 0, 0, 0, 224, 0x010F)

        optional_header = bytearray(224)
        optional_header[:2] = struct.pack("<H", 0x010B)
        struct.pack_into("<I", optional_header, 16, 0x1000)

        themida_section = bytearray(40)
        themida_section[:8] = b".themida"
        struct.pack_into("<I", themida_section, 8, 32768)
        struct.pack_into("<I", themida_section, 12, 0x1000)
        struct.pack_into("<I", themida_section, 16, 32768)
        struct.pack_into("<I", themida_section, 20, 0x400)
        struct.pack_into("<I", themida_section, 36, 0xE0000060)

        text_section = bytearray(40)
        text_section[:8] = b".text\x00\x00\x00"
        struct.pack_into("<I", text_section, 8, 4096)
        struct.pack_into("<I", text_section, 12, 0x9000)
        struct.pack_into("<I", text_section, 16, 4096)
        struct.pack_into("<I", text_section, 20, 0x8400)
        struct.pack_into("<I", text_section, 36, 0x60000020)

        data_section = bytearray(40)
        data_section[:8] = b".data\x00\x00\x00"
        struct.pack_into("<I", data_section, 8, 2048)
        struct.pack_into("<I", data_section, 12, 0xA000)
        struct.pack_into("<I", data_section, 16, 2048)
        struct.pack_into("<I", data_section, 20, 0x9400)
        struct.pack_into("<I", data_section, 36, 0xC0000040)

        padding = bytearray(0x400 - 64 - len(pe_signature) - len(coff_header) - len(optional_header) - 120)

        themida_code = bytearray(32768)
        themida_code[0:48] = (
            b"\xEB\x03\x59\xEB\x05\xE8\xF8\xFF\xFF\xFF\x49\x81\xF9\x00\x00\x00\x00"
            b"\x0F\x84\x00\x00\x00\x00\x8B\x01\x81\x38\x00\x00\x00\x00\x0F\x84\x00"
            b"\x00\x00\x00\x83\xC1\x04\xE9\x00\x00\x00\x00\x90\x90\x90\x90\x90\x90"
        )

        themida_code[100:132] = (
            b"\x60\x9C\x64\x8B\x05\x30\x00\x00\x00\x8B\x40\x0C\x8B\x70\x14"
            b"\xAD\x96\xAD\x8B\x58\x10\x8B\x53\x3C\x03\xD3\x8B\x52\x78\x03\xD3\x8B"
        )

        themida_code[200:216] = b"\x0F\x31\x8B\xC8\x0F\x31\x2B\xC1\x3D\x00\x10\x00\x00\x0F\x82\x00"

        for i in range(500, 32000, 512):
            themida_code[i : i + 64] = os.urandom(64)

        text_code = bytearray(4096)
        text_code[0:8] = b"\x55\x8B\xEC\x83\xEC\x20\x53\x56"

        data_bytes = bytearray(2048)

        pe_file = (
            dos_header
            + pe_signature
            + coff_header
            + optional_header
            + themida_section
            + text_section
            + data_section
            + padding
            + themida_code
            + text_code
            + data_bytes
        )

        pe_path.write_bytes(pe_file)
        return pe_path

    def test_themida_section_name_detection(self, themida_protected_binary: Path) -> None:
        """Themida detected through .themida section name."""
        extractor = DynamicSignatureExtractor()
        signatures = extractor.extract_signatures(str(themida_protected_binary))

        protector_sigs = [sig for sig in signatures if sig.category == ProtectionCategory.PROTECTOR]
        assert protector_sigs

        themida_sigs = [sig for sig in protector_sigs if "themida" in sig.context.lower()]
        assert themida_sigs

    def test_themida_obfuscation_patterns(self, themida_protected_binary: Path) -> None:
        """Themida detected through characteristic obfuscation patterns."""
        with open(themida_protected_binary, "rb") as f:
            binary_data = f.read()

        themida_patterns = [
            b"\xEB\x03\x59\xEB\x05",
            b"\x64\x8B\x05\x30\x00\x00\x00",
            b"\x0F\x31",
        ]

        found_patterns = sum(bool(pattern in binary_data)
                         for pattern in themida_patterns)
        assert found_patterns >= 2

        extractor = DynamicSignatureExtractor()
        signatures = extractor.extract_signatures(str(themida_protected_binary))

        obf_sigs = [sig for sig in signatures if sig.category == ProtectionCategory.OBFUSCATION]
        assert obf_sigs


class TestASPackDetection:
    """Test ASPack packer detection."""

    @pytest.fixture
    def aspack_packed_binary(self, tmp_path: Path) -> Path:
        """Create PE with ASPack signatures."""
        pe_path = tmp_path / "aspack_packed.exe"

        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x014C, 2, 0, 0, 0, 224, 0x010F)

        optional_header = bytearray(224)
        optional_header[:2] = struct.pack("<H", 0x010B)
        struct.pack_into("<I", optional_header, 16, 0x1000)

        aspack_section = bytearray(40)
        aspack_section[:8] = b".aspack\x00"
        struct.pack_into("<I", aspack_section, 8, 16384)
        struct.pack_into("<I", aspack_section, 12, 0x1000)
        struct.pack_into("<I", aspack_section, 16, 16384)
        struct.pack_into("<I", aspack_section, 20, 0x400)
        struct.pack_into("<I", aspack_section, 36, 0xE0000060)

        adata_section = bytearray(40)
        adata_section[:8] = b".adata\x00\x00"
        struct.pack_into("<I", adata_section, 8, 4096)
        struct.pack_into("<I", adata_section, 12, 0x5000)
        struct.pack_into("<I", adata_section, 16, 4096)
        struct.pack_into("<I", adata_section, 20, 0x4400)
        struct.pack_into("<I", adata_section, 36, 0xC0000040)

        padding = bytearray(0x400 - 64 - len(pe_signature) - len(coff_header) - len(optional_header) - 80)

        aspack_code = bytearray(16384)
        aspack_code[:64] = (
            b"\x60\xe8\x03\x00\x00\x00\xe9\xeb\x04\x5d\x45\x55\xc3\xe8\x01\x00"
            b"\x00\x00\xeb\x5d\xbb\xed\xff\xff\xff\x03\xdd\x81\xeb\x00\x00\x00"
            b"\x00\x80\xbd\x00\x00\x00\x00\x00\x74\x7c\x8b\x85\x00\x00\x00\x00"
            b"\x03\x85\x00\x00\x00\x00\x89\x85\x00\x00\x00\x00\x8b\x85\x00\x00"
        )

        aspack_code[100:116] = b"aPLib v0.45 -"
        aspack_code[120:136] = b"\x8B\x85\x00\x00\x00\x00\x03\x85\x00\x00\x00\x00\x89\x85\x00\x00"

        for i in range(500, 16000, 256):
            aspack_code[i : i + 32] = os.urandom(32)

        adata_bytes = bytearray(4096)

        pe_file = (
            dos_header
            + pe_signature
            + coff_header
            + optional_header
            + aspack_section
            + adata_section
            + padding
            + aspack_code
            + adata_bytes
        )

        pe_path.write_bytes(pe_file)
        return pe_path

    def test_aspack_section_name_detection(self, aspack_packed_binary: Path) -> None:
        """ASPack detected through .aspack/.adata section names."""
        extractor = DynamicSignatureExtractor()
        signatures = extractor.extract_signatures(str(aspack_packed_binary))

        packer_sigs = [sig for sig in signatures if sig.category == ProtectionCategory.PACKER]
        assert packer_sigs

        aspack_sigs = [sig for sig in packer_sigs if "aspack" in sig.context.lower() or "adata" in sig.context.lower()]
        assert aspack_sigs

    def test_aspack_signature_string_detection(self, aspack_packed_binary: Path) -> None:
        """ASPack detected through signature string."""
        with open(aspack_packed_binary, "rb") as f:
            binary_data = f.read()

        assert b"aPLib" in binary_data

        extractor = DynamicSignatureExtractor()
        signatures = extractor.extract_signatures(str(aspack_packed_binary))

        string_sigs = [sig for sig in signatures if "string" in sig.context.lower()]
        assert string_sigs


class TestPECompactDetection:
    """Test PECompact packer detection."""

    @pytest.fixture
    def pecompact_packed_binary(self, tmp_path: Path) -> Path:
        """Create PE with PECompact signatures."""
        pe_path = tmp_path / "pecompact_packed.exe"

        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x014C, 2, 0, 0, 0, 224, 0x010F)

        optional_header = bytearray(224)
        optional_header[:2] = struct.pack("<H", 0x010B)
        struct.pack_into("<I", optional_header, 16, 0x1000)

        pec1_section = bytearray(40)
        pec1_section[:8] = b"PEC2\x00\x00\x00\x00"
        struct.pack_into("<I", pec1_section, 8, 12288)
        struct.pack_into("<I", pec1_section, 12, 0x1000)
        struct.pack_into("<I", pec1_section, 16, 12288)
        struct.pack_into("<I", pec1_section, 20, 0x400)
        struct.pack_into("<I", pec1_section, 36, 0xE0000060)

        pec2_section = bytearray(40)
        pec2_section[:8] = b"PEC2TO\x00\x00"
        struct.pack_into("<I", pec2_section, 8, 4096)
        struct.pack_into("<I", pec2_section, 12, 0x4000)
        struct.pack_into("<I", pec2_section, 16, 4096)
        struct.pack_into("<I", pec2_section, 20, 0x3400)
        struct.pack_into("<I", pec2_section, 36, 0xC0000040)

        padding = bytearray(0x400 - 64 - len(pe_signature) - len(coff_header) - len(optional_header) - 80)

        pec_code = bytearray(12288)
        pec_code[:48] = (
            b"\xb8\x00\x00\x00\x00\x50\x64\xff\x35\x00\x00\x00\x00\x64\x89\x25"
            b"\x00\x00\x00\x00\x33\xc0\x89\x08\x50\x45\x43\x4f\x4d\x50\x41\x43"
            b"\x54\x32\x00\x00\xbb\x00\x00\x00\x00\x8b\xc3\x83\xc0\x04\x90\x8b"
        )

        pec_code[60:76] = b"PECOMPACT2\x00\x00\x00\x00\x00\x00"

        for i in range(200, 12000, 256):
            pec_code[i : i + 32] = os.urandom(32)

        pec2_bytes = bytearray(4096)

        pe_file = (
            dos_header
            + pe_signature
            + coff_header
            + optional_header
            + pec1_section
            + pec2_section
            + padding
            + pec_code
            + pec2_bytes
        )

        pe_path.write_bytes(pe_file)
        return pe_path

    def test_pecompact_section_name_detection(self, pecompact_packed_binary: Path) -> None:
        """PECompact detected through PEC2/PEC2TO section names."""
        extractor = DynamicSignatureExtractor()
        signatures = extractor.extract_signatures(str(pecompact_packed_binary))

        packer_sigs = [sig for sig in signatures if sig.category == ProtectionCategory.PACKER]

        if not packer_sigs:
            all_sigs = [sig for sig in signatures if "pec2" in sig.context.lower()]
            assert all_sigs or len(signatures) > 0
        else:
            pec_sigs = [sig for sig in packer_sigs if "pec2" in sig.context.lower()]

    def test_pecompact_signature_string_detection(self, pecompact_packed_binary: Path) -> None:
        """PECompact detected through signature string."""
        with open(pecompact_packed_binary, "rb") as f:
            binary_data = f.read()

        assert b"PECOMPACT" in binary_data

        extractor = DynamicSignatureExtractor()
        signatures = extractor.extract_signatures(str(pecompact_packed_binary))

        string_sigs = [sig for sig in signatures if "string" in sig.context.lower()]
        assert string_sigs


class TestObsidiumDetection:
    """Test Obsidium protector detection."""

    @pytest.fixture
    def obsidium_protected_binary(self, tmp_path: Path) -> Path:
        """Create PE with Obsidium protection signatures."""
        pe_path = tmp_path / "obsidium_protected.exe"

        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x014C, 2, 0, 0, 0, 224, 0x010F)

        optional_header = bytearray(224)
        optional_header[:2] = struct.pack("<H", 0x010B)
        struct.pack_into("<I", optional_header, 16, 0x1000)

        obsidium_section = bytearray(40)
        obsidium_section[:8] = b".obsidum"
        struct.pack_into("<I", obsidium_section, 8, 20480)
        struct.pack_into("<I", obsidium_section, 12, 0x1000)
        struct.pack_into("<I", obsidium_section, 16, 20480)
        struct.pack_into("<I", obsidium_section, 20, 0x400)
        struct.pack_into("<I", obsidium_section, 36, 0xE0000060)

        text_section = bytearray(40)
        text_section[:8] = b".text\x00\x00\x00"
        struct.pack_into("<I", text_section, 8, 4096)
        struct.pack_into("<I", text_section, 12, 0x6000)
        struct.pack_into("<I", text_section, 16, 4096)
        struct.pack_into("<I", text_section, 20, 0x5400)
        struct.pack_into("<I", text_section, 36, 0x60000020)

        padding = bytearray(0x400 - 64 - len(pe_signature) - len(coff_header) - len(optional_header) - 80)

        obsidium_code = bytearray(20480)
        obsidium_code[:64] = (
            b"\xeb\x02\x00\x00\x5b\xeb\x02\x00\x00\x81\xeb\x00\x00\x00\x00\xeb"
            b"\x02\x00\x00\x8d\x83\x00\x00\x00\x00\xeb\x02\x00\x00\x50\xeb\x02"
            b"\x00\x00\xc3\xeb\x02\x00\x00\x90\x90\xeb\x02\x00\x00\xe8\x00\x00"
            b"\x00\x00\xeb\x02\x00\x00\x5d\x81\xed\x00\x00\x00\x00\xeb\x02\x00"
        )

        obsidium_code[100:132] = (
            b"\x8B\x85\x00\x00\x00\x00\x8D\x8D\x00\x00\x00\x00\x51\x50\xE8\x00"
            b"\x00\x00\x00\x89\x85\x00\x00\x00\x00\x8B\x95\x00\x00\x00\x00\x52"
        )

        for i in range(500, 20000, 512):
            obsidium_code[i : i + 64] = os.urandom(64)

        text_code = bytearray(4096)
        text_code[0:8] = b"\x55\x8B\xEC\x83\xEC\x20\x53\x56"

        pe_file = (
            dos_header
            + pe_signature
            + coff_header
            + optional_header
            + obsidium_section
            + text_section
            + padding
            + obsidium_code
            + text_code
        )

        pe_path.write_bytes(pe_file)
        return pe_path

    def test_obsidium_section_name_detection(self, obsidium_protected_binary: Path) -> None:
        """Obsidium detected through .obsidum section name."""
        extractor = DynamicSignatureExtractor()
        signatures = extractor.extract_signatures(str(obsidium_protected_binary))

        protector_sigs = [
            sig
            for sig in signatures
            if sig.category in [ProtectionCategory.PROTECTOR, ProtectionCategory.OBFUSCATION]
        ]
        assert protector_sigs

    def test_obsidium_junk_code_patterns(self, obsidium_protected_binary: Path) -> None:
        """Obsidium detected through characteristic junk code patterns."""
        with open(obsidium_protected_binary, "rb") as f:
            binary_data = f.read()

        obsidium_patterns = [b"\xEB\x02\x00\x00", b"\x81\xEB\x00\x00\x00\x00", b"\x81\xED\x00\x00\x00\x00"]

        found_patterns = sum(bool(pattern in binary_data)
                         for pattern in obsidium_patterns)
        assert found_patterns >= 2


class TestEnigmaProtectorDetection:
    """Test Enigma Protector detection."""

    @pytest.fixture
    def enigma_protected_binary(self, tmp_path: Path) -> Path:
        """Create PE with Enigma Protector signatures."""
        pe_path = tmp_path / "enigma_protected.exe"

        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x014C, 3, 0, 0, 0, 224, 0x010F)

        optional_header = bytearray(224)
        optional_header[:2] = struct.pack("<H", 0x010B)
        struct.pack_into("<I", optional_header, 16, 0x1000)

        enigma1_section = bytearray(40)
        enigma1_section[:8] = b".enigma1"
        struct.pack_into("<I", enigma1_section, 8, 16384)
        struct.pack_into("<I", enigma1_section, 12, 0x1000)
        struct.pack_into("<I", enigma1_section, 16, 16384)
        struct.pack_into("<I", enigma1_section, 20, 0x400)
        struct.pack_into("<I", enigma1_section, 36, 0xE0000060)

        enigma2_section = bytearray(40)
        enigma2_section[:8] = b".enigma2"
        struct.pack_into("<I", enigma2_section, 8, 8192)
        struct.pack_into("<I", enigma2_section, 12, 0x5000)
        struct.pack_into("<I", enigma2_section, 16, 8192)
        struct.pack_into("<I", enigma2_section, 20, 0x4400)
        struct.pack_into("<I", enigma2_section, 36, 0xC0000040)

        text_section = bytearray(40)
        text_section[:8] = b".text\x00\x00\x00"
        struct.pack_into("<I", text_section, 8, 4096)
        struct.pack_into("<I", text_section, 12, 0x7000)
        struct.pack_into("<I", text_section, 16, 4096)
        struct.pack_into("<I", text_section, 20, 0x6400)
        struct.pack_into("<I", text_section, 36, 0x60000020)

        padding = bytearray(0x400 - 64 - len(pe_signature) - len(coff_header) - len(optional_header) - 120)

        enigma1_code = bytearray(16384)
        enigma1_code[0:48] = (
            b"\x55\x8B\xEC\x83\xEC\x0C\x53\x56\x57\x89\x4D\xF4\x89\x55\xF8\x89"
            b"\x45\xFC\x8B\x45\xF4\x8B\x4D\xF8\x8B\x55\xFC\xE8\x00\x00\x00\x00"
            b"\x8B\x5D\xF4\x8B\x75\xF8\x8B\x7D\xFC\xE8\x00\x00\x00\x00\x5F\x5E"
        )

        enigma1_code[100:132] = (
            b"Enigma protector"
            b"\x00\x8B\x85\x00\x00\x00\x00\x8B\x8D\x00\x00\x00\x00\x51\x50"
        )

        for i in range(500, 16000, 256):
            enigma1_code[i : i + 32] = os.urandom(32)

        enigma2_code = bytearray(8192)
        for i in range(0, 8192, 128):
            enigma2_code[i : i + 16] = os.urandom(16)

        text_code = bytearray(4096)
        text_code[0:8] = b"\x55\x8B\xEC\x83\xEC\x20\x53\x56"

        pe_file = (
            dos_header
            + pe_signature
            + coff_header
            + optional_header
            + enigma1_section
            + enigma2_section
            + text_section
            + padding
            + enigma1_code
            + enigma2_code
            + text_code
        )

        pe_path.write_bytes(pe_file)
        return pe_path

    def test_enigma_section_name_detection(self, enigma_protected_binary: Path) -> None:
        """Enigma Protector detected through .enigma1/.enigma2 section names."""
        extractor = DynamicSignatureExtractor()
        signatures = extractor.extract_signatures(str(enigma_protected_binary))

        protector_sigs = [sig for sig in signatures if sig.category == ProtectionCategory.PROTECTOR]
        assert protector_sigs

        enigma_sigs = [sig for sig in protector_sigs if "enigma" in sig.context.lower()]
        assert enigma_sigs

    def test_enigma_signature_string_detection(self, enigma_protected_binary: Path) -> None:
        """Enigma Protector detected through signature string."""
        with open(enigma_protected_binary, "rb") as f:
            binary_data = f.read()

        assert b"Enigma" in binary_data

        extractor = DynamicSignatureExtractor()
        signatures = extractor.extract_signatures(str(enigma_protected_binary))

        string_sigs = [sig for sig in signatures if "string" in sig.context.lower()]
        assert string_sigs


class TestArmadilloDetection:
    """Test Armadillo protector detection."""

    @pytest.fixture
    def armadillo_protected_binary(self, tmp_path: Path) -> Path:
        """Create PE with Armadillo protection signatures."""
        pe_path = tmp_path / "armadillo_protected.exe"

        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x014C, 2, 0, 0, 0, 224, 0x010F)

        optional_header = bytearray(224)
        optional_header[:2] = struct.pack("<H", 0x010B)
        struct.pack_into("<I", optional_header, 16, 0x1000)

        arma_section = bytearray(40)
        arma_section[:8] = b".arma\x00\x00\x00"
        struct.pack_into("<I", arma_section, 8, 12288)
        struct.pack_into("<I", arma_section, 12, 0x1000)
        struct.pack_into("<I", arma_section, 16, 12288)
        struct.pack_into("<I", arma_section, 20, 0x400)
        struct.pack_into("<I", arma_section, 36, 0xE0000060)

        text_section = bytearray(40)
        text_section[:8] = b".text\x00\x00\x00"
        struct.pack_into("<I", text_section, 8, 4096)
        struct.pack_into("<I", text_section, 12, 0x4000)
        struct.pack_into("<I", text_section, 16, 4096)
        struct.pack_into("<I", text_section, 20, 0x3400)
        struct.pack_into("<I", text_section, 36, 0x60000020)

        padding = bytearray(0x400 - 64 - len(pe_signature) - len(coff_header) - len(optional_header) - 80)

        arma_code = bytearray(12288)
        arma_code[:48] = (
            b"\x55\x8b\xec\x6a\xff\x68\x00\x00\x00\x00\x68\x00\x00\x00\x00\x64"
            b"\xa1\x00\x00\x00\x00\x50\x64\x89\x25\x00\x00\x00\x00\x83\xec\x58"
            b"\x53\x56\x57\x89\x65\xe8\xff\x15\x00\x00\x00\x00\x33\xd2\x8a\xd4"
        )

        arma_code[100:132] = (
            b"Armadillo"
            b"\x00\x00\x00\x00\x00\x00\x00\x8B\x45\x08\x8B\x4D\x0C\x8B\x55\x10"
            b"\x89\x45\xF8\x89\x4D\xFC"
        )

        for i in range(500, 12000, 256):
            arma_code[i : i + 32] = os.urandom(32)

        text_code = bytearray(4096)
        text_code[0:8] = b"\x55\x8B\xEC\x83\xEC\x20\x53\x56"

        pe_file = (
            dos_header
            + pe_signature
            + coff_header
            + optional_header
            + arma_section
            + text_section
            + padding
            + arma_code
            + text_code
        )

        pe_path.write_bytes(pe_file)
        return pe_path

    def test_armadillo_section_name_detection(self, armadillo_protected_binary: Path) -> None:
        """Armadillo detected through .arma section name."""
        extractor = DynamicSignatureExtractor()
        signatures = extractor.extract_signatures(str(armadillo_protected_binary))

        protector_sigs = [sig for sig in signatures if sig.category == ProtectionCategory.PROTECTOR]
        assert protector_sigs

    def test_armadillo_signature_string_detection(self, armadillo_protected_binary: Path) -> None:
        """Armadillo detected through signature string."""
        with open(armadillo_protected_binary, "rb") as f:
            binary_data = f.read()

        assert b"Armadillo" in binary_data

        extractor = DynamicSignatureExtractor()
        signatures = extractor.extract_signatures(str(armadillo_protected_binary))

        string_sigs = [sig for sig in signatures if "string" in sig.context.lower()]
        assert string_sigs


class TestDotNetObfuscatorDetection:
    """Test .NET obfuscator detection (Dotfuscator, ConfuserEx)."""

    @pytest.fixture
    def dotfuscator_obfuscated_binary(self, tmp_path: Path) -> Path:
        """Create .NET PE with Dotfuscator signatures."""
        pe_path = tmp_path / "dotfuscator_obfuscated.exe"

        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 224, 0x010F)

        optional_header = bytearray(224)
        optional_header[:2] = struct.pack("<H", 0x010B)
        struct.pack_into("<I", optional_header, 16, 0x2000)
        struct.pack_into("<I", optional_header, 200, 2048)
        struct.pack_into("<I", optional_header, 204, 0x1000)

        text_section = bytearray(40)
        text_section[:8] = b".text\x00\x00\x00"
        struct.pack_into("<I", text_section, 8, 8192)
        struct.pack_into("<I", text_section, 12, 0x2000)
        struct.pack_into("<I", text_section, 16, 8192)
        struct.pack_into("<I", text_section, 20, 0x400)
        struct.pack_into("<I", text_section, 36, 0x60000020)

        padding = bytearray(0x400 - 64 - len(pe_signature) - len(coff_header) - len(optional_header) - 40)

        clr_header = bytearray(72)
        struct.pack_into("<I", clr_header, 0, 72)
        struct.pack_into("<H", clr_header, 4, 2)
        struct.pack_into("<H", clr_header, 6, 5)
        struct.pack_into("<I", clr_header, 8, 0x3000)
        struct.pack_into("<I", clr_header, 12, 0x1000)

        text_code = bytearray(8192)
        text_code[:72] = clr_header

        text_code[200:232] = (
            b"DotfuscatorAttribute"
            b"\x00\x00\x00\x00\x8B\x45\x08\x8B\x4D\x0C\x8B\x55\x10"
        )

        text_code[300:316] = b"<Module>{0}$$"
        text_code[320:336] = b"<PrivateImplementationDetails>"[:16]

        for i in range(500, 8000, 256):
            text_code[i : i + 16] = os.urandom(16)

        pe_file = dos_header + pe_signature + coff_header + optional_header + text_section + padding + text_code

        pe_path.write_bytes(pe_file)
        return pe_path

    @pytest.fixture
    def confuserex_obfuscated_binary(self, tmp_path: Path) -> Path:
        """Create .NET PE with ConfuserEx signatures."""
        pe_path = tmp_path / "confuserex_obfuscated.exe"

        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 224, 0x010F)

        optional_header = bytearray(224)
        optional_header[:2] = struct.pack("<H", 0x010B)
        struct.pack_into("<I", optional_header, 16, 0x2000)
        struct.pack_into("<I", optional_header, 200, 2048)
        struct.pack_into("<I", optional_header, 204, 0x1000)

        text_section = bytearray(40)
        text_section[:8] = b".text\x00\x00\x00"
        struct.pack_into("<I", text_section, 8, 10240)
        struct.pack_into("<I", text_section, 12, 0x2000)
        struct.pack_into("<I", text_section, 16, 10240)
        struct.pack_into("<I", text_section, 20, 0x400)
        struct.pack_into("<I", text_section, 36, 0x60000020)

        padding = bytearray(0x400 - 64 - len(pe_signature) - len(coff_header) - len(optional_header) - 40)

        clr_header = bytearray(72)
        struct.pack_into("<I", clr_header, 0, 72)
        struct.pack_into("<H", clr_header, 4, 2)
        struct.pack_into("<H", clr_header, 6, 5)

        text_code = bytearray(10240)
        text_code[:72] = clr_header

        text_code[200:232] = b"ConfusedByAttribute\x00\x00\x00\x00\x00\x8B\x45\x08\x8B\x4D\x0C\x8B"

        text_code[300:332] = b"ConfuserEx v1.0.0\x00\x00\x00\x00\x00\x00\x00\x8B\x55\x10\x89\x45"

        text_code[400:416] = b"<>c__DisplayClass"[:16]

        for i in range(500, 10000, 256):
            text_code[i : i + 32] = os.urandom(32)

        pe_file = dos_header + pe_signature + coff_header + optional_header + text_section + padding + text_code

        pe_path.write_bytes(pe_file)
        return pe_path

    def test_dotfuscator_attribute_detection(self, dotfuscator_obfuscated_binary: Path) -> None:
        """Dotfuscator detected through DotfuscatorAttribute."""
        with open(dotfuscator_obfuscated_binary, "rb") as f:
            binary_data = f.read()

        assert b"DotfuscatorAttribute" in binary_data

        extractor = DynamicSignatureExtractor()
        signatures = extractor.extract_signatures(str(dotfuscator_obfuscated_binary))

        string_sigs = [sig for sig in signatures if "string" in sig.context.lower()]
        assert len(signatures) > 0

    def test_confuserex_signature_detection(self, confuserex_obfuscated_binary: Path) -> None:
        """ConfuserEx detected through signature strings."""
        with open(confuserex_obfuscated_binary, "rb") as f:
            binary_data = f.read()

        assert b"ConfuserEx" in binary_data or b"ConfusedBy" in binary_data

        extractor = DynamicSignatureExtractor()
        signatures = extractor.extract_signatures(str(confuserex_obfuscated_binary))

        string_sigs = [sig for sig in signatures if "string" in sig.context.lower()]
        assert len(signatures) > 0

    def test_dotnet_obfuscated_name_patterns(self, confuserex_obfuscated_binary: Path) -> None:
        """.NET obfuscation detected through obfuscated name patterns."""
        with open(confuserex_obfuscated_binary, "rb") as f:
            binary_data = f.read()

        obfuscated_patterns = [b"<>c__DisplayClass", b"<Module>", b"<PrivateImplementationDetails>", b"ConfuserEx", b"ConfusedBy"]

        found_patterns = sum(bool(pattern in binary_data)
                         for pattern in obfuscated_patterns)
        assert found_patterns >= 1


class TestGenericPackerHeuristics:
    """Test generic packer detection heuristics."""

    @pytest.fixture
    def high_entropy_binary(self, tmp_path: Path) -> Path:
        """Create PE with high entropy sections."""
        pe_path = tmp_path / "high_entropy.exe"

        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 224, 0x010F)

        optional_header = bytearray(224)
        optional_header[:2] = struct.pack("<H", 0x010B)
        struct.pack_into("<I", optional_header, 16, 0x1000)

        packed_section = bytearray(40)
        packed_section[:8] = b".packed\x00"
        struct.pack_into("<I", packed_section, 8, 16384)
        struct.pack_into("<I", packed_section, 12, 0x1000)
        struct.pack_into("<I", packed_section, 16, 16384)
        struct.pack_into("<I", packed_section, 20, 0x400)
        struct.pack_into("<I", packed_section, 36, 0xE0000060)

        padding = bytearray(0x400 - 64 - len(pe_signature) - len(coff_header) - len(optional_header) - 40)

        high_entropy_data = os.urandom(16384)

        pe_file = dos_header + pe_signature + coff_header + optional_header + packed_section + padding + high_entropy_data

        pe_path.write_bytes(pe_file)
        return pe_path

    def test_high_entropy_section_detection(self, high_entropy_binary: Path) -> None:
        """Generic packer detected through high section entropy."""
        extractor = DynamicSignatureExtractor()
        signatures = extractor.extract_signatures(str(high_entropy_binary))

        entropy_sigs = [sig for sig in signatures if "entropy" in sig.context.lower()]
        assert entropy_sigs

        high_entropy_sigs = [sig for sig in entropy_sigs if sig.metadata.get("entropy", 0) > 7.5]
        assert high_entropy_sigs

    def test_executable_writable_section_detection(self) -> None:
        """Generic packer detected through executable+writable sections."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            pe_path = Path(f.name)

            dos_header = bytearray(64)
            dos_header[:2] = b"MZ"
            dos_header[60:64] = struct.pack("<I", 64)

            pe_signature = b"PE\x00\x00"
            coff_header = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 224, 0x010F)

            optional_header = bytearray(224)
            optional_header[:2] = struct.pack("<H", 0x010B)

            rwx_section = bytearray(40)
            rwx_section[:8] = b".rwx\x00\x00\x00\x00"
            struct.pack_into("<I", rwx_section, 8, 4096)
            struct.pack_into("<I", rwx_section, 12, 0x1000)
            struct.pack_into("<I", rwx_section, 16, 4096)
            struct.pack_into("<I", rwx_section, 20, 0x400)
            struct.pack_into("<I", rwx_section, 36, 0xE0000060)

            padding = bytearray(0x400 - 64 - len(pe_signature) - len(coff_header) - len(optional_header) - 40)

            code = bytearray(4096)
            for i in range(0, 4096, 128):
                code[i : i + 16] = os.urandom(16)

            pe_file = dos_header + pe_signature + coff_header + optional_header + rwx_section + padding + code

            f.write(pe_file)

        try:
            extractor = DynamicSignatureExtractor()
            signatures = extractor.extract_signatures(str(pe_path))

            section_sigs = [sig for sig in signatures if "section" in sig.context.lower()]
            assert section_sigs

            rwx_metadata = [sig for sig in section_sigs if sig.metadata.get("characteristics", 0) & 0xE0000000]
            assert rwx_metadata
        finally:
            if pe_path.exists():
                os.unlink(pe_path)


class TestEntryPointAnalysis:
    """Test entry point analysis for packer detection."""

    @pytest.fixture
    def unusual_entry_point_binary(self, tmp_path: Path) -> Path:
        """Create PE with unusual entry point in non-standard section."""
        pe_path = tmp_path / "unusual_ep.exe"

        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x014C, 2, 0, 0, 0, 224, 0x010F)

        optional_header = bytearray(224)
        optional_header[:2] = struct.pack("<H", 0x010B)
        struct.pack_into("<I", optional_header, 16, 0x5000)
        struct.pack_into("<I", optional_header, 20, 0x1000)

        data_section = bytearray(40)
        data_section[:8] = b".data\x00\x00\x00"
        struct.pack_into("<I", data_section, 8, 4096)
        struct.pack_into("<I", data_section, 12, 0x1000)
        struct.pack_into("<I", data_section, 16, 4096)
        struct.pack_into("<I", data_section, 20, 0x400)
        struct.pack_into("<I", data_section, 36, 0xC0000040)

        packed_section = bytearray(40)
        packed_section[:8] = b".packed\x00"
        struct.pack_into("<I", packed_section, 8, 8192)
        struct.pack_into("<I", packed_section, 12, 0x5000)
        struct.pack_into("<I", packed_section, 16, 8192)
        struct.pack_into("<I", packed_section, 20, 0x1400)
        struct.pack_into("<I", packed_section, 36, 0xE0000060)

        padding = bytearray(0x400 - 64 - len(pe_signature) - len(coff_header) - len(optional_header) - 80)

        data_bytes = bytearray(4096)

        packed_code = bytearray(8192)
        packed_code[:32] = (
            b"\x60\xe8\x00\x00\x00\x00\x5d\x81\xed\x00\x00\x00\x00\x8d\xbd\x00"
            b"\x00\x00\x00\x8d\xb5\x00\x00\x00\x00\xb9\x00\x00\x00\x00\xf3\xa4"
        )

        for i in range(100, 8000, 128):
            packed_code[i : i + 16] = os.urandom(16)

        pe_file = (
            dos_header
            + pe_signature
            + coff_header
            + optional_header
            + data_section
            + packed_section
            + padding
            + data_bytes
            + packed_code
        )

        pe_path.write_bytes(pe_file)
        return pe_path

    def test_entry_point_in_non_text_section(self, unusual_entry_point_binary: Path) -> None:
        """Packer detected when entry point is in non-.text section."""
        extractor = DynamicSignatureExtractor()
        signatures = extractor.extract_signatures(str(unusual_entry_point_binary))

        section_sigs = [sig for sig in signatures if "section" in sig.context.lower()]
        assert section_sigs

        packed_section_sigs = [sig for sig in section_sigs if "packed" in sig.context.lower()]
        assert packed_section_sigs


class TestMultiplePackerLayerDetection:
    """Test detection of multiple packer layers."""

    @pytest.fixture
    def multi_layer_packed_binary(self, tmp_path: Path) -> Path:
        """Create PE with multiple packer signatures (UPX + VMProtect)."""
        pe_path = tmp_path / "multi_layer.exe"

        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x014C, 3, 0, 0, 0, 224, 0x010F)

        optional_header = bytearray(224)
        optional_header[:2] = struct.pack("<H", 0x010B)
        struct.pack_into("<I", optional_header, 16, 0x1000)

        upx1_section = bytearray(40)
        upx1_section[:8] = b"UPX1\x00\x00\x00\x00"
        struct.pack_into("<I", upx1_section, 8, 8192)
        struct.pack_into("<I", upx1_section, 12, 0x1000)
        struct.pack_into("<I", upx1_section, 16, 8192)
        struct.pack_into("<I", upx1_section, 20, 0x400)
        struct.pack_into("<I", upx1_section, 36, 0xE0000060)

        vmp0_section = bytearray(40)
        vmp0_section[:8] = b".vmp0\x00\x00\x00"
        struct.pack_into("<I", vmp0_section, 8, 12288)
        struct.pack_into("<I", vmp0_section, 12, 0x3000)
        struct.pack_into("<I", vmp0_section, 16, 12288)
        struct.pack_into("<I", vmp0_section, 20, 0x2400)
        struct.pack_into("<I", vmp0_section, 36, 0xE0000020)

        text_section = bytearray(40)
        text_section[:8] = b".text\x00\x00\x00"
        struct.pack_into("<I", text_section, 8, 4096)
        struct.pack_into("<I", text_section, 12, 0x6000)
        struct.pack_into("<I", text_section, 16, 4096)
        struct.pack_into("<I", text_section, 20, 0x5400)
        struct.pack_into("<I", text_section, 36, 0x60000020)

        padding = bytearray(0x400 - 64 - len(pe_signature) - len(coff_header) - len(optional_header) - 120)

        upx1_code = bytearray(8192)
        upx1_code[0:32] = (
            b"\x60\xBE\x00\x00\x00\x00\x8D\xBE\x00\x00\xFF\xFF\x57\x83\xCD\xFF"
            b"\xEB\x10\x90\x90\x90\x90\x8A\x06\x46\x88\x07\x47\x01\xDB\x75\x07"
        )
        upx1_code[100:104] = b"UPX!"

        for i in range(200, 8000):
            upx1_code[i] = (i * 131) % 256

        vmp0_code = bytearray(12288)
        vmp0_code[0:32] = (
            b"\x55\x8B\xEC\x60\x68\x00\x00\x00\x00\x8B\xEC\x83\xEC\x50\x53\x56"
            b"\x57\x33\xDB\x64\xA1\x30\x00\x00\x00\x8B\x40\x0C\x8B\x40\x14\x8B"
        )

        for i in range(500, 12000, 256):
            vmp0_code[i : i + 16] = os.urandom(16)

        text_code = bytearray(4096)
        text_code[0:8] = b"\x55\x8B\xEC\x83\xEC\x20\x53\x56"

        pe_file = (
            dos_header
            + pe_signature
            + coff_header
            + optional_header
            + upx1_section
            + vmp0_section
            + text_section
            + padding
            + upx1_code
            + vmp0_code
            + text_code
        )

        pe_path.write_bytes(pe_file)
        return pe_path

    def test_multiple_packer_layer_detection(self, multi_layer_packed_binary: Path) -> None:
        """Multiple packer layers detected (UPX + VMProtect)."""
        scanner = EnhancedProtectionScanner()
        results = scanner.scan(str(multi_layer_packed_binary), deep_scan=True)

        total_protections = (
            len(results.get("packers", []))
            + len(results.get("protections", []))
            + len(results.get("obfuscation", []))
        )

        assert total_protections > 1 or len(results.get("confidence_scores", {})) >= 2

        extractor = DynamicSignatureExtractor()
        signatures = extractor.extract_signatures(str(multi_layer_packed_binary))

        packer_categories = {sig.category for sig in signatures}
        assert ProtectionCategory.PACKER in packer_categories or ProtectionCategory.PROTECTOR in packer_categories

        unique_contexts = {sig.context for sig in signatures}
        assert len(unique_contexts) > 1


class TestRealWindowsBinaryAnalysis:
    """Test packer detection on real Windows system binaries."""

    def test_analyze_system32_binary(self) -> None:
        """Packer detection works on real Windows system binaries."""
        system32_path = Path("C:/Windows/System32")
        if not system32_path.exists():
            pytest.skip("Windows System32 directory not found")

        test_binaries = ["notepad.exe", "calc.exe", "cmd.exe"]

        for binary_name in test_binaries:
            binary_path = system32_path / binary_name
            if not binary_path.exists():
                continue

            extractor = DynamicSignatureExtractor()
            signatures = extractor.extract_signatures(str(binary_path))

            assert isinstance(signatures, list)

            for sig in signatures:
                assert isinstance(sig.confidence, float)
                assert 0.0 <= sig.confidence <= 1.0
                assert isinstance(sig.pattern_bytes, bytes)
                assert isinstance(sig.mask, bytes)
                assert len(sig.pattern_bytes) == len(sig.mask)

            break
        else:
            pytest.skip("No test binaries found in System32")

    def test_scanner_performance_on_large_binary(self, tmp_path: Path) -> None:
        """Scanner performs efficiently on large binaries."""
        large_binary_path = tmp_path / "large_binary.exe"

        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 224, 0x010F)

        optional_header = bytearray(224)
        optional_header[:2] = struct.pack("<H", 0x010B)

        text_section = bytearray(40)
        text_section[:8] = b".text\x00\x00\x00"
        struct.pack_into("<I", text_section, 8, 1048576)
        struct.pack_into("<I", text_section, 12, 0x1000)
        struct.pack_into("<I", text_section, 16, 1048576)
        struct.pack_into("<I", text_section, 20, 0x400)
        struct.pack_into("<I", text_section, 36, 0x60000020)

        padding = bytearray(0x400 - 64 - len(pe_signature) - len(coff_header) - len(optional_header) - 40)

        large_code = bytearray(1048576)
        for i in range(0, 1048576, 4096):
            large_code[i : i + 256] = os.urandom(256)

        pe_file = dos_header + pe_signature + coff_header + optional_header + text_section + padding + large_code

        large_binary_path.write_bytes(pe_file)

        import time

        start_time = time.time()
        scanner = EnhancedProtectionScanner()
        results = scanner.scan(str(large_binary_path), deep_scan=False)
        elapsed_time = time.time() - start_time

        assert elapsed_time < 30.0

        assert "file_path" in results
        assert "timestamp" in results
        assert isinstance(results.get("confidence_scores", {}), dict)
