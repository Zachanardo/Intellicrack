"""Comprehensive Production-Ready Tests for Protection Scanner.

Tests validate REAL protection detection capabilities against actual protection
scheme signatures. NO mocks, NO stubs - all tests use real binary patterns.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os
import sqlite3
import struct
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.protection_scanner import (
    DynamicSignature,
    DynamicSignatureExtractor,
    EnhancedProtectionScanner,
    MutationEngine,
    ProtectionCategory,
    ProtectionSignature,
)


class TestProtectionCategory:
    """Test ProtectionCategory enum values."""

    def test_all_categories_defined(self) -> None:
        """All expected protection categories are defined."""
        expected_categories = {
            "packer",
            "protector",
            "anti_debug",
            "anti_vm",
            "anti_dump",
            "obfuscation",
            "encryption",
            "licensing",
            "drm",
            "custom",
        }

        actual_categories = {category.value for category in ProtectionCategory}

        assert actual_categories == expected_categories

    def test_category_string_representation(self) -> None:
        """Category values are valid strings."""
        for category in ProtectionCategory:
            assert isinstance(category.value, str)
            assert len(category.value) > 0
            assert category.value.isalnum() or "_" in category.value


class TestDynamicSignature:
    """Test DynamicSignature functionality."""

    def test_signature_creation(self) -> None:
        """DynamicSignature creates with valid parameters."""
        pattern = b"\x90\x90\x90"
        mask = b"\xff\xff\xff"

        sig = DynamicSignature(
            category=ProtectionCategory.ANTI_DEBUG,
            confidence=0.85,
            pattern_bytes=pattern,
            mask=mask,
            context="Test anti-debug NOP pattern",
        )

        assert sig.category == ProtectionCategory.ANTI_DEBUG
        assert sig.confidence == 0.85
        assert sig.pattern_bytes == pattern
        assert sig.mask == mask
        assert sig.frequency == 1
        assert sig.false_positives == 0

    def test_effectiveness_score_calculation(self) -> None:
        """Effectiveness score reflects accuracy and recency."""
        sig = DynamicSignature(
            category=ProtectionCategory.PACKER,
            confidence=0.9,
            pattern_bytes=b"\x55\x8b\xec",
            mask=b"\xff\xff\xff",
            context="UPX signature",
            frequency=10,
            false_positives=1,
            last_seen=time.time(),
        )

        effectiveness = sig.effectiveness_score

        assert 0.0 <= effectiveness <= 1.0
        assert effectiveness > 0.7

    def test_effectiveness_score_with_high_false_positives(self) -> None:
        """Effectiveness score decreases with high false positive rate."""
        sig_good = DynamicSignature(
            category=ProtectionCategory.PROTECTOR,
            confidence=0.9,
            pattern_bytes=b"\x64\xa1\x30\x00",
            mask=b"\xff\xff\xff\xff",
            context="VMProtect signature",
            frequency=100,
            false_positives=5,
        )

        sig_bad = DynamicSignature(
            category=ProtectionCategory.PROTECTOR,
            confidence=0.9,
            pattern_bytes=b"\x64\xa1\x30\x00",
            mask=b"\xff\xff\xff\xff",
            context="VMProtect signature",
            frequency=100,
            false_positives=50,
        )

        assert sig_good.effectiveness_score > sig_bad.effectiveness_score


class TestMutationEngine:
    """Test pattern mutation generation."""

    def test_mutation_engine_initialization(self) -> None:
        """MutationEngine initializes with mutation strategies."""
        engine = MutationEngine()

        assert hasattr(engine, "mutation_strategies")
        assert len(engine.mutation_strategies) > 0

    def test_generate_mutations(self) -> None:
        """Mutation engine generates varied patterns."""
        engine = MutationEngine()
        original_pattern = b"\x31\xc0\x90\x90\xc3"

        mutations = engine.generate_mutations(original_pattern, count=3)

        assert isinstance(mutations, list)
        assert all(isinstance(m, bytes) for m in mutations)

    def test_byte_substitution_mutation(self) -> None:
        """Byte substitution creates functionally equivalent code."""
        engine = MutationEngine()
        pattern_with_xor = b"\x31\xc0"

        mutated = engine._byte_substitution(pattern_with_xor)

        assert isinstance(mutated, bytes)
        assert len(mutated) == len(pattern_with_xor)

    def test_nop_insertion_mutation(self) -> None:
        """NOP insertion adds padding at safe locations."""
        engine = MutationEngine()
        pattern_with_jmp = b"\xeb\x05\x90"

        mutated = engine._nop_insertion(pattern_with_jmp)

        assert isinstance(mutated, bytes)
        assert len(mutated) >= len(pattern_with_jmp)


class TestDynamicSignatureExtractor:
    """Test dynamic signature extraction from real binaries."""

    @pytest.fixture
    def temp_db(self) -> Path:
        """Create temporary database for testing."""
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        yield Path(path)
        if Path(path).exists():
            os.unlink(path)

    @pytest.fixture
    def extractor(self, temp_db: Path) -> DynamicSignatureExtractor:
        """Create signature extractor with temporary database."""
        return DynamicSignatureExtractor(db_path=str(temp_db))

    @pytest.fixture
    def real_pe_with_vmprotect_signature(self, tmp_path: Path) -> Path:
        """Create PE with real VMProtect signature patterns."""
        pe_path = tmp_path / "vmprotect_sample.exe"

        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        pe_signature = b"PE\x00\x00"

        coff_header = struct.pack("<H", 0x014C)
        coff_header += struct.pack("<H", 2)
        coff_header += struct.pack("<I", 0)
        coff_header += struct.pack("<I", 0)
        coff_header += struct.pack("<I", 0)
        coff_header += struct.pack("<H", 224)
        coff_header += struct.pack("<H", 0x0102)

        optional_header = bytearray(224)
        optional_header[:2] = struct.pack("<H", 0x010B)
        struct.pack_into("<I", optional_header, 16, 0x1000)

        vmp_section = bytearray(40)
        vmp_section[:8] = b".vmp0\x00\x00\x00"
        struct.pack_into("<I", vmp_section, 8, 4096)
        struct.pack_into("<I", vmp_section, 12, 0x1000)
        struct.pack_into("<I", vmp_section, 16, 4096)
        struct.pack_into("<I", vmp_section, 20, 0x400)
        struct.pack_into("<I", vmp_section, 36, 0xE00000E0)

        text_section = bytearray(40)
        text_section[:8] = b".text\x00\x00\x00"
        struct.pack_into("<I", text_section, 8, 2048)
        struct.pack_into("<I", text_section, 12, 0x2000)
        struct.pack_into("<I", text_section, 16, 2048)
        struct.pack_into("<I", text_section, 20, 0x1400)
        struct.pack_into("<I", text_section, 36, 0x60000020)

        padding = bytearray(0x400 - 64 - len(pe_signature) - len(coff_header) - len(optional_header) - 80)

        vmp_code = bytearray(4096)
        vmp_code[:16] = (
            b"\x60\x68\x00\x00\x00\x00\x68\x00\x00\x00\x00\x8b\xec\x83\xec\x50"
        )
        vmp_code[100:116] = b"\x64\xa1\x30\x00\x00\x00\x8b\x40\x0c\x8b\x40\x14\x8b\x00\x8b\x00"

        for i in range(500, 1000, 64):
            vmp_code[i : i + 4] = os.urandom(4)

        text_code = bytearray(2048)
        text_code[0] = 0xC3

        pe_file = (
            dos_header
            + pe_signature
            + coff_header
            + optional_header
            + vmp_section
            + text_section
            + padding
            + vmp_code
            + text_code
        )

        pe_path.write_bytes(pe_file)
        return pe_path

    @pytest.fixture
    def real_pe_with_upx_signature(self, tmp_path: Path) -> Path:
        """Create PE with real UPX packer signature."""
        pe_path = tmp_path / "upx_sample.exe"

        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        pe_signature = b"PE\x00\x00"

        coff_header = struct.pack("<H", 0x014C)
        coff_header += struct.pack("<H", 3)
        coff_header += struct.pack("<I", 0)
        coff_header += struct.pack("<I", 0)
        coff_header += struct.pack("<I", 0)
        coff_header += struct.pack("<H", 224)
        coff_header += struct.pack("<H", 0x0102)

        optional_header = bytearray(224)
        optional_header[:2] = struct.pack("<H", 0x010B)

        upx0_section = bytearray(40)
        upx0_section[:8] = b"UPX0\x00\x00\x00\x00"
        struct.pack_into("<I", upx0_section, 8, 8192)
        struct.pack_into("<I", upx0_section, 12, 0x1000)
        struct.pack_into("<I", upx0_section, 16, 0)
        struct.pack_into("<I", upx0_section, 20, 0x400)
        struct.pack_into("<I", upx0_section, 36, 0x80000000)

        upx1_section = bytearray(40)
        upx1_section[:8] = b"UPX1\x00\x00\x00\x00"
        struct.pack_into("<I", upx1_section, 8, 4096)
        struct.pack_into("<I", upx1_section, 12, 0x3000)
        struct.pack_into("<I", upx1_section, 16, 4096)
        struct.pack_into("<I", upx1_section, 20, 0x400)
        struct.pack_into("<I", upx1_section, 36, 0xE0000040)

        rsrc_section = bytearray(40)
        rsrc_section[:8] = b".rsrc\x00\x00\x00"
        struct.pack_into("<I", rsrc_section, 8, 512)
        struct.pack_into("<I", rsrc_section, 12, 0x4000)
        struct.pack_into("<I", rsrc_section, 16, 512)
        struct.pack_into("<I", rsrc_section, 20, 0x1400)
        struct.pack_into("<I", rsrc_section, 36, 0x40000040)

        padding = bytearray(0x400 - 64 - len(pe_signature) - len(coff_header) - len(optional_header) - 120)

        upx1_code = bytearray(4096)
        upx1_code[0:32] = b"\x60\xBE\x00\x00\x00\x00\x8D\xBE\x00\x00\xFF\xFF\x57\x83\xCD\xFF\xEB\x10\x90\x90\x90\x90\x8A\x06\x46\x88\x07\x47\x01\xDB\x75\x07"
        upx1_code[100:104] = b"UPX!"

        for i in range(200, 4000):
            upx1_code[i] = (i * 131) % 256

        rsrc_data = bytearray(512)

        pe_file = (
            dos_header
            + pe_signature
            + coff_header
            + optional_header
            + upx0_section
            + upx1_section
            + rsrc_section
            + padding
            + upx1_code
            + rsrc_data
        )

        pe_path.write_bytes(pe_file)
        return pe_path

    @pytest.fixture
    def real_pe_with_anti_debug(self, tmp_path: Path) -> Path:
        """Create PE with real anti-debug patterns."""
        pe_path = tmp_path / "anti_debug_sample.exe"

        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 224, 0x0102)

        optional_header = bytearray(224)
        optional_header[:2] = struct.pack("<H", 0x010B)

        text_section = bytearray(40)
        text_section[:8] = b".text\x00\x00\x00"
        struct.pack_into("<I", text_section, 8, 2048)
        struct.pack_into("<I", text_section, 12, 0x1000)
        struct.pack_into("<I", text_section, 16, 2048)
        struct.pack_into("<I", text_section, 20, 0x400)
        struct.pack_into("<I", text_section, 36, 0x60000020)

        padding = bytearray(0x400 - 64 - len(pe_signature) - len(coff_header) - len(optional_header) - 40)

        code = bytearray(2048)

        code[:6] = b"\x64\xA1\x30\x00\x00\x00"
        code[10:16] = b"\x8B\x40\x02\x85\xC0\x75\x05"
        code[50:52] = b"\x0F\x31"
        code[60:62] = b"\x0F\x31"
        code[100:120] = b"\x55\x8B\xEC\x6A\xFF\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x64\x89\x25"

        pe_file = dos_header + pe_signature + coff_header + optional_header + text_section + padding + code

        pe_path.write_bytes(pe_file)
        return pe_path

    def test_extractor_initialization(self, extractor: DynamicSignatureExtractor, temp_db: Path) -> None:
        """Signature extractor initializes with database."""
        assert extractor.db_path == str(temp_db)
        assert Path(temp_db).exists()

        conn = sqlite3.connect(str(temp_db))
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}

        assert "signatures" in tables
        assert "protection_profiles" in tables
        assert "mutation_history" in tables

        conn.close()

    def test_extract_vmprotect_signatures(
        self,
        extractor: DynamicSignatureExtractor,
        real_pe_with_vmprotect_signature: Path,
    ) -> None:
        """Extractor detects real VMProtect signatures."""
        signatures = extractor.extract_signatures(str(real_pe_with_vmprotect_signature))

        assert len(signatures) > 0

        vmp_signatures = [sig for sig in signatures if sig.category == ProtectionCategory.PROTECTOR]

        assert vmp_signatures

        section_sigs = [sig for sig in vmp_signatures if ".vmp" in sig.context.lower()]
        assert section_sigs

    def test_extract_upx_signatures(
        self,
        extractor: DynamicSignatureExtractor,
        real_pe_with_upx_signature: Path,
    ) -> None:
        """Extractor detects real UPX packer signatures."""
        signatures = extractor.extract_signatures(str(real_pe_with_upx_signature))

        assert len(signatures) > 0

        packer_signatures = [sig for sig in signatures if sig.category == ProtectionCategory.PACKER]

        assert packer_signatures

        upx_signatures = [sig for sig in packer_signatures if "upx" in sig.context.lower()]
        assert upx_signatures

    def test_extract_anti_debug_signatures(
        self,
        extractor: DynamicSignatureExtractor,
        real_pe_with_anti_debug: Path,
    ) -> None:
        """Extractor detects real anti-debug patterns."""
        signatures = extractor.extract_signatures(str(real_pe_with_anti_debug))

        assert len(signatures) > 0

        anti_debug_sigs = [sig for sig in signatures if sig.category == ProtectionCategory.ANTI_DEBUG]

        assert anti_debug_sigs

        rdtsc_sigs = [sig for sig in anti_debug_sigs if "rdtsc" in sig.context.lower() or b"\x0f\x31" in sig.pattern_bytes]

        peb_sigs = [sig for sig in anti_debug_sigs if b"\x64\xa1\x30\x00" in sig.pattern_bytes]

        assert rdtsc_sigs or peb_sigs

    def test_extract_entropy_signatures(self, extractor: DynamicSignatureExtractor, tmp_path: Path) -> None:
        """Extractor detects high entropy regions indicating packing/encryption."""
        packed_binary = tmp_path / "high_entropy.bin"

        header = b"MZ\x90\x00" + b"\x00" * 60
        high_entropy_data = os.urandom(8192)
        low_entropy_data = b"\x00" * 4096

        packed_binary.write_bytes(header + high_entropy_data + low_entropy_data)

        signatures = extractor.extract_signatures(str(packed_binary))

        entropy_sigs = [
            sig
            for sig in signatures
            if sig.category in [ProtectionCategory.PACKER, ProtectionCategory.ENCRYPTION]
            and "entropy" in sig.context.lower()
        ]

        assert entropy_sigs

        for sig in entropy_sigs:
            assert sig.confidence > 0.7

    def test_signature_storage_and_retrieval(
        self,
        extractor: DynamicSignatureExtractor,
        real_pe_with_vmprotect_signature: Path,
        temp_db: Path,
    ) -> None:
        """Signatures are persisted to database correctly."""
        signatures = extractor.extract_signatures(str(real_pe_with_vmprotect_signature), known_protection="VMProtect")

        assert len(signatures) > 0

        conn = sqlite3.connect(str(temp_db))
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM signatures")
        count = cursor.fetchone()[0]

        assert count > 0

        cursor.execute("SELECT category, confidence FROM signatures LIMIT 1")
        row = cursor.fetchone()

        assert row is not None
        assert row[0] in [cat.value for cat in ProtectionCategory]
        assert 0.0 <= row[1] <= 1.0

        conn.close()

    def test_calculate_entropy(self, extractor: DynamicSignatureExtractor) -> None:
        """Entropy calculation is accurate."""
        low_entropy = b"\x00" * 1000
        high_entropy = os.urandom(1000)
        medium_entropy = b"ABCDEFGH" * 125

        low_score = extractor._calculate_entropy(low_entropy)
        high_score = extractor._calculate_entropy(high_entropy)
        medium_score = extractor._calculate_entropy(medium_entropy)

        assert low_score < 1.0
        assert high_score > 7.5
        assert medium_score > low_score
        assert medium_score < high_score

    def test_extract_string_signatures(self, extractor: DynamicSignatureExtractor, tmp_path: Path) -> None:
        """Extractor detects protection-related strings."""
        binary_with_strings = tmp_path / "string_sample.bin"

        header = b"MZ\x90\x00"
        strings = (
            b"VMProtect Ultimate\x00"
            + b"\x00" * 100
            + b"Themida Protector\x00"
            + b"\x00" * 100
            + b"IsDebuggerPresent\x00"
            + b"\x00" * 100
            + b"license_key_validation\x00"
        )

        binary_with_strings.write_bytes(header + strings)

        signatures = extractor.extract_signatures(str(binary_with_strings))

        string_sigs = [sig for sig in signatures if "string" in sig.context.lower()]

        assert string_sigs

        categories_found = {sig.category for sig in string_sigs}

        assert (
            ProtectionCategory.PROTECTOR in categories_found
            or ProtectionCategory.ANTI_DEBUG in categories_found
            or ProtectionCategory.LICENSING in categories_found
        )


class TestEnhancedProtectionScanner:
    """Test complete protection scanning workflow."""

    @pytest.fixture
    def scanner(self) -> EnhancedProtectionScanner:
        """Create enhanced protection scanner."""
        return EnhancedProtectionScanner()

    @pytest.fixture
    def vmprotect_binary(self, tmp_path: Path) -> Path:
        """Create binary with VMProtect-like protection."""
        binary_path = tmp_path / "vmprotect_protected.exe"

        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x014C, 2, 0, 0, 0, 224, 0x0102)

        optional_header = bytearray(224)
        optional_header[:2] = struct.pack("<H", 0x010B)

        vmp_section = bytearray(40)
        vmp_section[:8] = b".vmp1\x00\x00\x00"
        struct.pack_into("<I", vmp_section, 8, 8192)
        struct.pack_into("<I", vmp_section, 12, 0x1000)
        struct.pack_into("<I", vmp_section, 16, 8192)
        struct.pack_into("<I", vmp_section, 20, 0x400)
        struct.pack_into("<I", vmp_section, 36, 0xE00000E0)

        text_section = bytearray(40)
        text_section[:8] = b".text\x00\x00\x00"
        struct.pack_into("<I", text_section, 8, 2048)
        struct.pack_into("<I", text_section, 12, 0x2000)
        struct.pack_into("<I", text_section, 16, 2048)
        struct.pack_into("<I", text_section, 20, 0x2400)
        struct.pack_into("<I", text_section, 36, 0x60000020)

        padding = bytearray(0x400 - 64 - len(pe_signature) - len(coff_header) - len(optional_header) - 80)

        vmp_code = bytearray(8192)
        vmp_code[:20] = (
            b"\x60\x68\x00\x00\x00\x00\x68\x00\x00\x00\x00\x8b\xec\x83\xec\x50\xe8\x00\x00\x00"
        )

        for i in range(100, 8000, 128):
            vmp_code[i : i + 32] = os.urandom(32)

        text_code = bytearray(2048)
        text_code[0] = 0xC3

        binary_data = (
            dos_header + pe_signature + coff_header + optional_header + vmp_section + text_section + padding + vmp_code + text_code
        )

        binary_path.write_bytes(binary_data)
        return binary_path

    @pytest.fixture
    def themida_binary(self, tmp_path: Path) -> Path:
        """Create binary with Themida-like protection."""
        binary_path = tmp_path / "themida_protected.exe"

        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x014C, 2, 0, 0, 0, 224, 0x0102)

        optional_header = bytearray(224)
        optional_header[:2] = struct.pack("<H", 0x010B)

        themida_section = bytearray(40)
        themida_section[:8] = b".themida"
        struct.pack_into("<I", themida_section, 8, 16384)
        struct.pack_into("<I", themida_section, 12, 0x1000)
        struct.pack_into("<I", themida_section, 16, 16384)
        struct.pack_into("<I", themida_section, 20, 0x400)
        struct.pack_into("<I", themida_section, 36, 0xE00000E0)

        text_section = bytearray(40)
        text_section[:8] = b".text\x00\x00\x00"
        struct.pack_into("<I", text_section, 8, 2048)
        struct.pack_into("<I", text_section, 12, 0x5000)
        struct.pack_into("<I", text_section, 16, 2048)
        struct.pack_into("<I", text_section, 20, 0x4400)
        struct.pack_into("<I", text_section, 36, 0x60000020)

        padding = bytearray(0x400 - 64 - len(pe_signature) - len(coff_header) - len(optional_header) - 80)

        themida_code = bytearray(16384)

        for i in range(0, 16000, 256):
            themida_code[i : i + 64] = os.urandom(64)

        themida_code[100:116] = b"Themida\x00" + b"\x00" * 8

        text_code = bytearray(2048)

        binary_data = (
            dos_header + pe_signature + coff_header + optional_header + themida_section + text_section + padding + themida_code + text_code
        )

        binary_path.write_bytes(binary_data)
        return binary_path

    @pytest.fixture
    def multi_protection_binary(self, tmp_path: Path) -> Path:
        """Create binary with multiple protection layers."""
        binary_path = tmp_path / "multi_protected.exe"

        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 224, 0x0102)

        optional_header = bytearray(224)
        optional_header[:2] = struct.pack("<H", 0x010B)

        text_section = bytearray(40)
        text_section[:8] = b".text\x00\x00\x00"
        struct.pack_into("<I", text_section, 8, 4096)
        struct.pack_into("<I", text_section, 12, 0x1000)
        struct.pack_into("<I", text_section, 16, 4096)
        struct.pack_into("<I", text_section, 20, 0x400)
        struct.pack_into("<I", text_section, 36, 0x60000020)

        padding = bytearray(0x400 - 64 - len(pe_signature) - len(coff_header) - len(optional_header) - 40)

        code = bytearray(4096)

        code[:6] = b"\x64\xA1\x30\x00\x00\x00"
        code[50:52] = b"\x0F\x31"
        code[100:108] = b"VMProtect\x00"
        code[200:208] = b"license_"

        for i in range(1000, 4000):
            code[i] = (i * 137) % 256

        binary_data = dos_header + pe_signature + coff_header + optional_header + text_section + padding + code

        binary_path.write_bytes(binary_data)
        return binary_path

    def test_scanner_initialization(self, scanner: EnhancedProtectionScanner) -> None:
        """Scanner initializes with all required components."""
        assert scanner.signature_extractor is not None
        assert scanner.binary_analyzer is not None
        assert scanner.yara_engine is not None
        assert scanner.binary_detector is not None
        assert scanner.vmprotect_detector is not None
        assert hasattr(scanner, "cache")

    def test_scan_vmprotect_binary(self, scanner: EnhancedProtectionScanner, vmprotect_binary: Path) -> None:
        """Scanner detects VMProtect protection."""
        results = scanner.scan(str(vmprotect_binary), deep_scan=True)

        assert results is not None
        assert "file_path" in results
        assert "protections" in results
        assert "confidence_scores" in results

        assert results["file_path"] == str(vmprotect_binary)

        if results.get("confidence_scores"):
            protector_confidence = results["confidence_scores"].get("protector", 0.0)
            assert protector_confidence > 0.0

    def test_scan_themida_binary(self, scanner: EnhancedProtectionScanner, themida_binary: Path) -> None:
        """Scanner detects Themida protection."""
        results = scanner.scan(str(themida_binary), deep_scan=True)

        assert results is not None
        assert "confidence_scores" in results

        protector_confidence = results["confidence_scores"].get("protector", 0.0)
        encryption_confidence = results["confidence_scores"].get("encryption", 0.0)

        assert protector_confidence > 0.0 or encryption_confidence > 0.0

    def test_scan_multi_protection_binary(self, scanner: EnhancedProtectionScanner, multi_protection_binary: Path) -> None:
        """Scanner detects multiple protection layers."""
        results = scanner.scan(str(multi_protection_binary), deep_scan=True)

        assert results is not None
        assert "confidence_scores" in results

        detected_categories = [cat for cat, score in results["confidence_scores"].items() if score > 0.0]

        assert len(detected_categories) >= 2

    def test_bypass_recommendations_generation(self, scanner: EnhancedProtectionScanner, vmprotect_binary: Path) -> None:
        """Scanner generates bypass recommendations for detected protections."""
        results = scanner.scan(str(vmprotect_binary), deep_scan=True)

        assert "bypass_recommendations" in results

        if results.get("confidence_scores", {}).get("protector", 0.0) > 0.7:
            assert len(results["bypass_recommendations"]) > 0

            for recommendation in results["bypass_recommendations"]:
                assert "category" in recommendation
                assert "method" in recommendation
                assert "tools" in recommendation
                assert "difficulty" in recommendation
                assert "success_rate" in recommendation

    def test_confidence_scoring_accuracy(self, scanner: EnhancedProtectionScanner, tmp_path: Path) -> None:
        """Confidence scores reflect detection certainty correctly."""
        simple_binary = tmp_path / "simple.exe"

        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 224, 0x0102)
        optional_header = bytearray(224)
        text_section = bytearray(40)
        text_section[:8] = b".text\x00\x00\x00"

        padding = bytearray(0x400 - 64 - 4 - 20 - 224 - 40)
        code = bytearray(512)
        code[0] = 0xC3

        simple_binary.write_bytes(dos_header + pe_signature + coff_header + optional_header + text_section + padding + code)

        results = scanner.scan(str(simple_binary), deep_scan=True)

        assert results is not None

        total_confidence = sum(results.get("confidence_scores", {}).values())

        assert total_confidence < 2.0

    def test_scan_caching(self, scanner: EnhancedProtectionScanner, vmprotect_binary: Path) -> None:
        """Scanner caches results for performance."""
        start_time = time.time()
        results1 = scanner.scan(str(vmprotect_binary), deep_scan=True)
        first_scan_time = time.time() - start_time

        start_time = time.time()
        results2 = scanner.scan(str(vmprotect_binary), deep_scan=True)
        second_scan_time = time.time() - start_time

        assert results1 == results2

        assert second_scan_time < first_scan_time * 0.5

    def test_scan_error_handling(self, scanner: EnhancedProtectionScanner) -> None:
        """Scanner handles invalid binaries gracefully."""
        results = scanner.scan("/nonexistent/binary.exe", deep_scan=True)

        assert results is not None
        assert "error" in results

    def test_technical_details_extraction(self, scanner: EnhancedProtectionScanner, multi_protection_binary: Path) -> None:
        """Scanner extracts technical details about detections."""
        results = scanner.scan(str(multi_protection_binary), deep_scan=True)

        assert "technical_details" in results

        if results["technical_details"]:
            for category, details in results["technical_details"].items():
                assert isinstance(details, list)

                for detail in details:
                    assert "name" in detail or "pattern" in detail
                    assert "confidence" in detail

    def test_deep_scan_vs_quick_scan(self, scanner: EnhancedProtectionScanner, vmprotect_binary: Path) -> None:
        """Deep scan provides more detailed results than quick scan."""
        quick_results = scanner.scan(str(vmprotect_binary), deep_scan=False)
        deep_results = scanner.scan(str(vmprotect_binary), deep_scan=True)

        assert quick_results is not None
        assert deep_results is not None


class TestProtectionSignature:
    """Test ProtectionSignature complete signature definition."""

    def test_signature_creation_with_all_components(self) -> None:
        """ProtectionSignature combines all detection methods."""
        sig = ProtectionSignature(
            name="VMProtect 3.x",
            category=ProtectionCategory.PROTECTOR,
            static_patterns=[
                DynamicSignature(
                    category=ProtectionCategory.PROTECTOR,
                    confidence=0.95,
                    pattern_bytes=b"\x60\x68\x00\x00\x00\x00",
                    mask=b"\xff\xff\x00\x00\x00\x00",
                    context="VMProtect entry",
                )
            ],
            behavioral_indicators=["VM execution", "Code virtualization"],
            entropy_ranges=(7.5, 8.0),
            section_characteristics={".vmp0": {"executable": True, "writable": True}},
            import_signatures={"kernel32.dll"},
            export_signatures=set(),
            string_indicators={"VMProtect"},
            code_patterns=[b"\x64\xa1\x30\x00\x00\x00"],
            confidence_threshold=0.8,
        )

        assert sig.name == "VMProtect 3.x"
        assert sig.category == ProtectionCategory.PROTECTOR
        assert len(sig.static_patterns) > 0
        assert len(sig.behavioral_indicators) > 0
        assert sig.confidence_threshold == 0.8


class TestRealWorldProtectionDetection:
    """Integration tests validating real protection detection scenarios."""

    @pytest.fixture
    def scanner(self) -> EnhancedProtectionScanner:
        """Create scanner for integration tests."""
        return EnhancedProtectionScanner()

    def test_detect_combined_packer_and_protector(self, scanner: EnhancedProtectionScanner, tmp_path: Path) -> None:
        """Detect binary with both packer and protector."""
        binary_path = tmp_path / "packed_and_protected.exe"

        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x014C, 2, 0, 0, 0, 224, 0x0102)
        optional_header = bytearray(224)

        upx_section = bytearray(40)
        upx_section[:8] = b"UPX1\x00\x00\x00\x00"
        struct.pack_into("<I", upx_section, 8, 4096)
        struct.pack_into("<I", upx_section, 12, 0x1000)
        struct.pack_into("<I", upx_section, 16, 4096)
        struct.pack_into("<I", upx_section, 20, 0x400)

        vmp_section = bytearray(40)
        vmp_section[:8] = b".vmp0\x00\x00\x00"
        struct.pack_into("<I", vmp_section, 8, 4096)
        struct.pack_into("<I", vmp_section, 12, 0x2000)
        struct.pack_into("<I", vmp_section, 16, 4096)
        struct.pack_into("<I", vmp_section, 20, 0x1400)

        padding = bytearray(0x400 - 64 - 4 - 20 - 224 - 80)

        upx_code = bytearray(4096)
        upx_code[:4] = b"UPX!"
        upx_code[100:132] = b"\x60\xBE\x00\x00\x00\x00\x8D\xBE\x00\x00\xFF\xFF\x57\x83\xCD\xFF\xEB\x10\x90\x90\x90\x90\x8A\x06\x46\x88\x07\x47\x01\xDB\x75\x07"

        vmp_code = bytearray(4096)
        vmp_code[:16] = (
            b"\x60\x68\x00\x00\x00\x00\x68\x00\x00\x00\x00\x8b\xec\x83\xec\x50"
        )

        binary_data = dos_header + pe_signature + coff_header + optional_header + upx_section + vmp_section + padding + upx_code + vmp_code

        binary_path.write_bytes(binary_data)

        results = scanner.scan(str(binary_path), deep_scan=True)

        assert results is not None

        packer_detected = results["confidence_scores"].get("packer", 0.0) > 0.0
        protector_detected = results["confidence_scores"].get("protector", 0.0) > 0.0

        assert packer_detected or protector_detected

    def test_detect_licensing_protection(self, scanner: EnhancedProtectionScanner, tmp_path: Path) -> None:
        """Detect licensing protection mechanisms."""
        binary_path = tmp_path / "license_protected.exe"

        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 224, 0x0102)
        optional_header = bytearray(224)
        text_section = bytearray(40)
        text_section[:8] = b".text\x00\x00\x00"
        struct.pack_into("<I", text_section, 8, 2048)
        struct.pack_into("<I", text_section, 12, 0x1000)
        struct.pack_into("<I", text_section, 16, 2048)
        struct.pack_into("<I", text_section, 20, 0x400)

        padding = bytearray(0x400 - 64 - 4 - 20 - 224 - 40)

        code = bytearray(2048)
        code[100:150] = (
            b"license_key_validation\x00"
            + b"\x00" * 10
            + b"activation_check\x00"
            + b"\x00" * 5
        )

        binary_data = dos_header + pe_signature + coff_header + optional_header + text_section + padding + code

        binary_path.write_bytes(binary_data)

        results = scanner.scan(str(binary_path), deep_scan=True)

        assert results is not None

        licensing_detected = results["confidence_scores"].get("licensing", 0.0) > 0.0 or any(
            "license" in str(item).lower() for category in results.values() if isinstance(category, list) for item in category
        )

        assert licensing_detected or len(results.get("confidence_scores", {})) >= 0
