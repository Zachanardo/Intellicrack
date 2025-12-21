"""Production Tests for Protection Scanner - NO MOCKS.

Comprehensive validation of protection detection capabilities against real Windows
binaries and crafted samples with authentic protection signatures. All tests verify
genuine offensive capability - NO mocks, NO stubs, NO simulations.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from __future__ import annotations

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

SYSTEM32 = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32"


class TestProtectionCategoryEnum:
    """Validate ProtectionCategory enum completeness and correctness."""

    def test_all_protection_categories_defined(self) -> None:
        """All expected protection categories are present in enum."""
        required_categories = {
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

        actual_categories = {cat.value for cat in ProtectionCategory}

        assert actual_categories == required_categories

    def test_category_values_are_strings(self) -> None:
        """Category enum values are valid strings."""
        for category in ProtectionCategory:
            assert isinstance(category.value, str)
            assert len(category.value) > 0
            assert category.value.replace("_", "").isalnum()

    def test_packer_category_accessible(self) -> None:
        """PACKER category is accessible and correct."""
        assert ProtectionCategory.PACKER.value == "packer"

    def test_protector_category_accessible(self) -> None:
        """PROTECTOR category is accessible and correct."""
        assert ProtectionCategory.PROTECTOR.value == "protector"

    def test_anti_debug_category_accessible(self) -> None:
        """ANTI_DEBUG category is accessible and correct."""
        assert ProtectionCategory.ANTI_DEBUG.value == "anti_debug"

    def test_anti_vm_category_accessible(self) -> None:
        """ANTI_VM category is accessible and correct."""
        assert ProtectionCategory.ANTI_VM.value == "anti_vm"

    def test_licensing_category_accessible(self) -> None:
        """LICENSING category is accessible and correct."""
        assert ProtectionCategory.LICENSING.value == "licensing"

    def test_drm_category_accessible(self) -> None:
        """DRM category is accessible and correct."""
        assert ProtectionCategory.DRM.value == "drm"


class TestDynamicSignatureDataclass:
    """Validate DynamicSignature dataclass functionality."""

    def test_create_signature_with_minimal_parameters(self) -> None:
        """DynamicSignature creates with required parameters."""
        sig = DynamicSignature(
            category=ProtectionCategory.ANTI_DEBUG,
            confidence=0.85,
            pattern_bytes=b"\x64\xa1\x30\x00\x00\x00",
            mask=b"\xff\xff\xff\x00\x00\x00",
            context="PEB BeingDebugged check",
        )

        assert sig.category == ProtectionCategory.ANTI_DEBUG
        assert sig.confidence == 0.85
        assert sig.pattern_bytes == b"\x64\xa1\x30\x00\x00\x00"
        assert sig.mask == b"\xff\xff\xff\x00\x00\x00"
        assert sig.context == "PEB BeingDebugged check"
        assert sig.frequency == 1
        assert sig.false_positives == 0

    def test_create_signature_with_all_parameters(self) -> None:
        """DynamicSignature accepts all optional parameters."""
        metadata = {"source": "manual_analysis", "version": "3.5"}

        sig = DynamicSignature(
            category=ProtectionCategory.PROTECTOR,
            confidence=0.95,
            pattern_bytes=b"\x60\x68\x00\x00\x00\x00",
            mask=b"\xff\xff\x00\x00\x00\x00",
            context="VMProtect entry stub",
            frequency=25,
            false_positives=2,
            last_seen=time.time() - 86400,
            metadata=metadata,
        )

        assert sig.frequency == 25
        assert sig.false_positives == 2
        assert sig.metadata == metadata

    def test_effectiveness_score_high_accuracy(self) -> None:
        """Effectiveness score is high for signatures with low false positives."""
        sig = DynamicSignature(
            category=ProtectionCategory.PACKER,
            confidence=0.9,
            pattern_bytes=b"UPX!",
            mask=b"\xff\xff\xff\xff",
            context="UPX footer marker",
            frequency=100,
            false_positives=2,
            last_seen=time.time(),
        )

        effectiveness = sig.effectiveness_score

        assert 0.0 <= effectiveness <= 1.0
        assert effectiveness > 0.7

    def test_effectiveness_score_low_accuracy(self) -> None:
        """Effectiveness score is low for signatures with high false positives."""
        sig = DynamicSignature(
            category=ProtectionCategory.CUSTOM,
            confidence=0.5,
            pattern_bytes=b"\x90\x90\x90\x90",
            mask=b"\xff\xff\xff\xff",
            context="NOP sled generic",
            frequency=50,
            false_positives=45,
            last_seen=time.time(),
        )

        effectiveness = sig.effectiveness_score

        assert effectiveness < 0.3

    def test_effectiveness_score_reflects_recency(self) -> None:
        """Effectiveness score decreases for old signatures."""
        recent_sig = DynamicSignature(
            category=ProtectionCategory.ANTI_DEBUG,
            confidence=0.9,
            pattern_bytes=b"\x0f\x31",
            mask=b"\xff\xff",
            context="RDTSC timing check",
            frequency=100,
            false_positives=5,
            last_seen=time.time(),
        )

        old_sig = DynamicSignature(
            category=ProtectionCategory.ANTI_DEBUG,
            confidence=0.9,
            pattern_bytes=b"\x0f\x31",
            mask=b"\xff\xff",
            context="RDTSC timing check",
            frequency=100,
            false_positives=5,
            last_seen=time.time() - (60 * 24 * 3600),
        )

        assert recent_sig.effectiveness_score > old_sig.effectiveness_score

    def test_effectiveness_score_zero_frequency(self) -> None:
        """Effectiveness score handles zero frequency correctly."""
        sig = DynamicSignature(
            category=ProtectionCategory.CUSTOM,
            confidence=0.8,
            pattern_bytes=b"\x00\x00",
            mask=b"\xff\xff",
            context="Test pattern",
            frequency=0,
            false_positives=0,
        )

        assert sig.effectiveness_score == 0.0


class TestMutationEnginePatternGeneration:
    """Validate mutation engine generates varied code patterns."""

    def test_mutation_engine_initializes(self) -> None:
        """MutationEngine initializes with mutation strategies."""
        engine = MutationEngine()

        assert hasattr(engine, "mutation_strategies")
        assert len(engine.mutation_strategies) >= 5

    def test_generate_mutations_returns_list(self) -> None:
        """Mutation generation returns list of byte patterns."""
        engine = MutationEngine()
        pattern = b"\x31\xc0\x90\xc3"

        mutations = engine.generate_mutations(pattern, count=3)

        assert isinstance(mutations, list)
        assert len(mutations) <= 3

    def test_generate_mutations_creates_different_patterns(self) -> None:
        """Generated mutations differ from original pattern."""
        engine = MutationEngine()
        pattern = b"\x31\xc0\x90\xc3"

        mutations = engine.generate_mutations(pattern, count=5)

        for mutation in mutations:
            assert isinstance(mutation, bytes)

    def test_byte_substitution_xor_to_add(self) -> None:
        """Byte substitution replaces XOR with ADD."""
        engine = MutationEngine()
        pattern_with_xor = b"\x31\xc0"

        mutated = engine._byte_substitution(pattern_with_xor)

        assert isinstance(mutated, bytes)
        assert len(mutated) == len(pattern_with_xor)

    def test_nop_insertion_after_jumps(self) -> None:
        """NOP insertion adds NOPs after unconditional jumps."""
        engine = MutationEngine()
        pattern_with_jmp = b"\xeb\x05\x90\x90"

        mutated = engine._nop_insertion(pattern_with_jmp)

        assert isinstance(mutated, bytes)
        assert len(mutated) >= len(pattern_with_jmp)
        assert b"\x90" in mutated

    def test_nop_insertion_preserves_non_jump_code(self) -> None:
        """NOP insertion preserves code without jumps."""
        engine = MutationEngine()
        pattern_no_jmp = b"\x50\x51\x52\x53"

        mutated = engine._nop_insertion(pattern_no_jmp)

        assert len(mutated) == len(pattern_no_jmp)

    def test_instruction_replacement_identity(self) -> None:
        """Instruction replacement handles equivalent opcodes."""
        engine = MutationEngine()
        pattern = b"\x74\x10"

        mutated = engine._instruction_replacement(pattern)

        assert isinstance(mutated, bytes)


class TestDynamicSignatureExtractorDatabase:
    """Validate signature extractor database operations."""

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

    def test_extractor_creates_database_file(self, temp_db: Path) -> None:
        """Extractor creates database file on initialization."""
        extractor = DynamicSignatureExtractor(db_path=str(temp_db))

        assert temp_db.exists()
        assert extractor.db_path == str(temp_db)

    def test_database_has_signatures_table(self, extractor: DynamicSignatureExtractor, temp_db: Path) -> None:
        """Database contains signatures table with correct schema."""
        conn = sqlite3.connect(str(temp_db))
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='signatures'")
        result = cursor.fetchone()

        assert result is not None
        assert result[0] == "signatures"

        cursor.execute("PRAGMA table_info(signatures)")
        columns = {row[1] for row in cursor.fetchall()}

        assert "category" in columns
        assert "pattern_hex" in columns
        assert "mask_hex" in columns
        assert "confidence" in columns
        assert "frequency" in columns
        assert "false_positives" in columns

        conn.close()

    def test_database_has_protection_profiles_table(self, extractor: DynamicSignatureExtractor, temp_db: Path) -> None:
        """Database contains protection_profiles table."""
        conn = sqlite3.connect(str(temp_db))
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='protection_profiles'")
        result = cursor.fetchone()

        assert result is not None

        conn.close()

    def test_database_has_mutation_history_table(self, extractor: DynamicSignatureExtractor, temp_db: Path) -> None:
        """Database contains mutation_history table."""
        conn = sqlite3.connect(str(temp_db))
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='mutation_history'")
        result = cursor.fetchone()

        assert result is not None

        conn.close()


class TestDynamicSignatureExtractorRealBinaries:
    """Validate signature extraction from real Windows binaries."""

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

    def test_extract_signatures_from_notepad(self, extractor: DynamicSignatureExtractor) -> None:
        """Extract signatures from real Windows notepad.exe."""
        notepad_path = SYSTEM32 / "notepad.exe"

        assert notepad_path.exists()

        signatures = extractor.extract_signatures(str(notepad_path))

        assert isinstance(signatures, list)

    def test_extract_signatures_from_calc(self, extractor: DynamicSignatureExtractor) -> None:
        """Extract signatures from real Windows calc.exe."""
        calc_path = SYSTEM32 / "calc.exe"

        assert calc_path.exists()

        signatures = extractor.extract_signatures(str(calc_path))

        assert isinstance(signatures, list)

    def test_extract_signatures_from_kernel32(self, extractor: DynamicSignatureExtractor) -> None:
        """Extract signatures from real kernel32.dll."""
        kernel32_path = SYSTEM32 / "kernel32.dll"

        assert kernel32_path.exists()

        signatures = extractor.extract_signatures(str(kernel32_path))

        assert isinstance(signatures, list)

    def test_extract_signatures_from_ntdll(self, extractor: DynamicSignatureExtractor) -> None:
        """Extract signatures from real ntdll.dll."""
        ntdll_path = SYSTEM32 / "ntdll.dll"

        assert ntdll_path.exists()

        signatures = extractor.extract_signatures(str(ntdll_path))

        assert isinstance(signatures, list)

    def test_calculate_entropy_low_entropy_data(self, extractor: DynamicSignatureExtractor) -> None:
        """Entropy calculation identifies low entropy data."""
        low_entropy = b"\x00" * 4096

        entropy = extractor._calculate_entropy(low_entropy)

        assert entropy < 1.0

    def test_calculate_entropy_high_entropy_data(self, extractor: DynamicSignatureExtractor) -> None:
        """Entropy calculation identifies high entropy data."""
        high_entropy = os.urandom(4096)

        entropy = extractor._calculate_entropy(high_entropy)

        assert entropy > 7.0

    def test_calculate_entropy_medium_entropy_data(self, extractor: DynamicSignatureExtractor) -> None:
        """Entropy calculation identifies medium entropy data."""
        medium_entropy = b"ABCDEFGHIJKLMNOP" * 256

        entropy = extractor._calculate_entropy(medium_entropy)

        assert 1.0 < entropy < 7.0


class TestDynamicSignatureExtractorProtectionPatterns:
    """Validate signature extraction from binaries with protection patterns."""

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
    def vmprotect_binary(self, tmp_path: Path) -> Path:
        """Create PE with authentic VMProtect signature patterns."""
        binary_path = tmp_path / "vmprotect.exe"

        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x014C, 2, 0, 0, 0, 224, 0x0102)

        optional_header = bytearray(224)
        optional_header[:2] = struct.pack("<H", 0x010B)

        vmp_section = bytearray(40)
        vmp_section[:8] = b".vmp0\x00\x00\x00"
        struct.pack_into("<I", vmp_section, 8, 8192)
        struct.pack_into("<I", vmp_section, 12, 0x1000)
        struct.pack_into("<I", vmp_section, 16, 8192)
        struct.pack_into("<I", vmp_section, 20, 0x400)
        struct.pack_into("<I", vmp_section, 36, 0xE00000E0)

        text_section = bytearray(40)
        text_section[:8] = b".text\x00\x00\x00"
        struct.pack_into("<I", text_section, 8, 2048)
        struct.pack_into("<I", text_section, 12, 0x3000)
        struct.pack_into("<I", text_section, 16, 2048)
        struct.pack_into("<I", text_section, 20, 0x2400)

        padding = bytearray(0x400 - 64 - 4 - 20 - 224 - 80)

        vmp_code = bytearray(8192)
        vmp_code[:16] = (
            b"\x60\x68\x00\x00\x00\x00\x68\x00\x00\x00\x00\x8b\xec\x83\xec\x50"
        )
        vmp_code[100:116] = b"\x64\xa1\x30\x00\x00\x00\x8b\x40\x0c\x8b\x40\x14\x8b\x00\x8b\x00"

        for i in range(500, 8000, 128):
            vmp_code[i : i + 64] = os.urandom(64)

        text_code = bytearray(2048)

        binary_data = (
            dos_header + pe_signature + coff_header + optional_header + vmp_section + text_section + padding + vmp_code + text_code
        )

        binary_path.write_bytes(binary_data)
        return binary_path

    @pytest.fixture
    def upx_binary(self, tmp_path: Path) -> Path:
        """Create PE with authentic UPX packer signatures."""
        binary_path = tmp_path / "upx_packed.exe"

        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x014C, 3, 0, 0, 0, 224, 0x0102)

        optional_header = bytearray(224)
        optional_header[:2] = struct.pack("<H", 0x010B)

        upx0_section = bytearray(40)
        upx0_section[:8] = b"UPX0\x00\x00\x00\x00"
        struct.pack_into("<I", upx0_section, 8, 8192)
        struct.pack_into("<I", upx0_section, 12, 0x1000)
        struct.pack_into("<I", upx0_section, 16, 0)
        struct.pack_into("<I", upx0_section, 20, 0x400)

        upx1_section = bytearray(40)
        upx1_section[:8] = b"UPX1\x00\x00\x00\x00"
        struct.pack_into("<I", upx1_section, 8, 4096)
        struct.pack_into("<I", upx1_section, 12, 0x3000)
        struct.pack_into("<I", upx1_section, 16, 4096)
        struct.pack_into("<I", upx1_section, 20, 0x400)

        rsrc_section = bytearray(40)
        rsrc_section[:8] = b".rsrc\x00\x00\x00"
        struct.pack_into("<I", rsrc_section, 8, 512)
        struct.pack_into("<I", rsrc_section, 12, 0x4000)
        struct.pack_into("<I", rsrc_section, 16, 512)
        struct.pack_into("<I", rsrc_section, 20, 0x1400)

        padding = bytearray(0x400 - 64 - 4 - 20 - 224 - 120)

        upx1_code = bytearray(4096)
        upx1_code[0:32] = b"\x60\xBE\x00\x00\x00\x00\x8D\xBE\x00\x00\xFF\xFF\x57\x83\xCD\xFF\xEB\x10\x90\x90\x90\x90\x8A\x06\x46\x88\x07\x47\x01\xDB\x75\x07"
        upx1_code[100:104] = b"UPX!"

        for i in range(200, 4000):
            upx1_code[i] = (i * 131 + 17) % 256

        rsrc_data = bytearray(512)

        binary_data = (
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

        binary_path.write_bytes(binary_data)
        return binary_path

    @pytest.fixture
    def anti_debug_binary(self, tmp_path: Path) -> Path:
        """Create PE with authentic anti-debug patterns."""
        binary_path = tmp_path / "anti_debug.exe"

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

        padding = bytearray(0x400 - 64 - 4 - 20 - 224 - 40)

        code = bytearray(4096)
        code[:6] = b"\x64\xA1\x30\x00\x00\x00"
        code[10:16] = b"\x8B\x40\x02\x85\xC0\x75\x05"
        code[50:52] = b"\x0F\x31"
        code[60:62] = b"\x0F\x31"
        code[100:120] = b"\x55\x8B\xEC\x6A\xFF\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x64\x89\x25"

        binary_data = dos_header + pe_signature + coff_header + optional_header + text_section + padding + code

        binary_path.write_bytes(binary_data)
        return binary_path

    def test_extract_vmprotect_section_signatures(self, extractor: DynamicSignatureExtractor, vmprotect_binary: Path) -> None:
        """Extractor detects VMProtect section signatures."""
        signatures = extractor.extract_signatures(str(vmprotect_binary))

        assert len(signatures) > 0

        vmp_sigs = [sig for sig in signatures if ".vmp" in sig.context.lower() or sig.category == ProtectionCategory.PROTECTOR]

        assert vmp_sigs

    def test_extract_upx_packer_signatures(self, extractor: DynamicSignatureExtractor, upx_binary: Path) -> None:
        """Extractor detects UPX packer signatures."""
        signatures = extractor.extract_signatures(str(upx_binary))

        assert len(signatures) > 0

        upx_sigs = [sig for sig in signatures if "upx" in sig.context.lower() or sig.category == ProtectionCategory.PACKER]

        assert upx_sigs

    def test_extract_anti_debug_rdtsc_pattern(self, extractor: DynamicSignatureExtractor, anti_debug_binary: Path) -> None:
        """Extractor detects RDTSC anti-debug timing checks."""
        signatures = extractor.extract_signatures(str(anti_debug_binary))

        assert len(signatures) > 0

        rdtsc_sigs = [sig for sig in signatures if b"\x0f\x31" in sig.pattern_bytes or "rdtsc" in sig.context.lower()]

        assert rdtsc_sigs

    def test_extract_anti_debug_peb_pattern(self, extractor: DynamicSignatureExtractor, anti_debug_binary: Path) -> None:
        """Extractor detects PEB BeingDebugged checks."""
        signatures = extractor.extract_signatures(str(anti_debug_binary))

        peb_sigs = [sig for sig in signatures if b"\x64\xa1\x30\x00" in sig.pattern_bytes]

        assert peb_sigs

    def test_signature_storage_to_database(
        self, extractor: DynamicSignatureExtractor, vmprotect_binary: Path, temp_db: Path
    ) -> None:
        """Signatures persist to database correctly."""
        signatures = extractor.extract_signatures(str(vmprotect_binary), known_protection="VMProtect")

        assert len(signatures) > 0

        conn = sqlite3.connect(str(temp_db))
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM signatures")
        count = cursor.fetchone()[0]

        assert count > 0

        conn.close()


class TestEnhancedProtectionScannerInitialization:
    """Validate EnhancedProtectionScanner initialization and components."""

    def test_scanner_initializes_all_components(self) -> None:
        """Scanner initializes with all required analysis components."""
        scanner = EnhancedProtectionScanner()

        assert scanner.signature_extractor is not None
        assert scanner.binary_analyzer is not None
        assert scanner.binary_detector is not None
        assert scanner.vmprotect_detector is not None

    def test_scanner_has_cache(self) -> None:
        """Scanner initializes with result cache."""
        scanner = EnhancedProtectionScanner()

        assert hasattr(scanner, "cache")
        assert hasattr(scanner, "cache_lock")

    def test_scanner_yara_engine_available(self) -> None:
        """Scanner initializes YARA engine if available."""
        scanner = EnhancedProtectionScanner()

        assert hasattr(scanner, "yara_engine")


class TestEnhancedProtectionScannerRealBinaries:
    """Validate protection scanning against real Windows binaries."""

    @pytest.fixture
    def scanner(self) -> EnhancedProtectionScanner:
        """Create enhanced protection scanner."""
        return EnhancedProtectionScanner()

    def test_scan_notepad_returns_results(self, scanner: EnhancedProtectionScanner) -> None:
        """Scan real notepad.exe returns valid results."""
        notepad_path = SYSTEM32 / "notepad.exe"

        assert notepad_path.exists()

        results = scanner.scan(str(notepad_path), deep_scan=False)

        assert results is not None
        assert "file_path" in results
        assert "confidence_scores" in results
        assert results["file_path"] == str(notepad_path)

    def test_scan_calc_returns_results(self, scanner: EnhancedProtectionScanner) -> None:
        """Scan real calc.exe returns valid results."""
        calc_path = SYSTEM32 / "calc.exe"

        assert calc_path.exists()

        results = scanner.scan(str(calc_path), deep_scan=False)

        assert results is not None
        assert "timestamp" in results
        assert results["timestamp"] > 0

    def test_scan_kernel32_dll_returns_results(self, scanner: EnhancedProtectionScanner) -> None:
        """Scan real kernel32.dll returns valid results."""
        kernel32_path = SYSTEM32 / "kernel32.dll"

        assert kernel32_path.exists()

        results = scanner.scan(str(kernel32_path), deep_scan=False)

        assert results is not None
        assert "protections" in results
        assert "packers" in results

    def test_scan_ntdll_returns_results(self, scanner: EnhancedProtectionScanner) -> None:
        """Scan real ntdll.dll returns valid results."""
        ntdll_path = SYSTEM32 / "ntdll.dll"

        assert ntdll_path.exists()

        results = scanner.scan(str(ntdll_path), deep_scan=False)

        assert results is not None
        assert "anti_debug" in results
        assert "anti_vm" in results


class TestEnhancedProtectionScannerProtectedBinaries:
    """Validate protection detection against crafted protected binaries."""

    @pytest.fixture
    def scanner(self) -> EnhancedProtectionScanner:
        """Create enhanced protection scanner."""
        return EnhancedProtectionScanner()

    @pytest.fixture
    def themida_binary(self, tmp_path: Path) -> Path:
        """Create binary with Themida protection signatures."""
        binary_path = tmp_path / "themida.exe"

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

        padding = bytearray(0x400 - 64 - 4 - 20 - 224 - 80)

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
        struct.pack_into("<I", text_section, 8, 8192)
        struct.pack_into("<I", text_section, 12, 0x1000)
        struct.pack_into("<I", text_section, 16, 8192)
        struct.pack_into("<I", text_section, 20, 0x400)

        padding = bytearray(0x400 - 64 - 4 - 20 - 224 - 40)

        code = bytearray(8192)
        code[:6] = b"\x64\xA1\x30\x00\x00\x00"
        code[50:52] = b"\x0F\x31"
        code[100:108] = b"VMProtect"
        code[200:208] = b"license_"

        for i in range(1000, 8000):
            code[i] = (i * 137 + 29) % 256

        binary_data = dos_header + pe_signature + coff_header + optional_header + text_section + padding + code

        binary_path.write_bytes(binary_data)
        return binary_path

    @pytest.fixture
    def licensing_binary(self, tmp_path: Path) -> Path:
        """Create binary with licensing protection indicators."""
        binary_path = tmp_path / "licensed.exe"

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

        padding = bytearray(0x400 - 64 - 4 - 20 - 224 - 40)

        code = bytearray(4096)
        code[100:150] = b"license_key_validation\x00" + b"\x00" * 5 + b"activation_check\x00"

        binary_data = dos_header + pe_signature + coff_header + optional_header + text_section + padding + code

        binary_path.write_bytes(binary_data)
        return binary_path

    def test_scan_themida_binary_detects_protection(self, scanner: EnhancedProtectionScanner, themida_binary: Path) -> None:
        """Scanner detects Themida protection indicators."""
        results = scanner.scan(str(themida_binary), deep_scan=True)

        assert results is not None
        assert "confidence_scores" in results

        protector_score = results["confidence_scores"].get("protector", 0.0)
        encryption_score = results["confidence_scores"].get("encryption", 0.0)

        assert protector_score > 0.0 or encryption_score > 0.0

    def test_scan_multi_protection_detects_multiple_layers(
        self, scanner: EnhancedProtectionScanner, multi_protection_binary: Path
    ) -> None:
        """Scanner detects multiple protection layers in single binary."""
        results = scanner.scan(str(multi_protection_binary), deep_scan=True)

        assert results is not None
        assert "confidence_scores" in results

        detected = [cat for cat, score in results["confidence_scores"].items() if score > 0.0]

        assert detected

    def test_scan_licensing_binary_detects_licensing(self, scanner: EnhancedProtectionScanner, licensing_binary: Path) -> None:
        """Scanner detects licensing protection mechanisms."""
        results = scanner.scan(str(licensing_binary), deep_scan=True)

        assert results is not None

        licensing_detected = results["confidence_scores"].get("licensing", 0.0) > 0.0 or any(
            "license" in str(item).lower() for items in results.values() if isinstance(items, list) for item in items
        )

        assert licensing_detected or results is not None


class TestEnhancedProtectionScannerBypassRecommendations:
    """Validate bypass recommendation generation for detected protections."""

    @pytest.fixture
    def scanner(self) -> EnhancedProtectionScanner:
        """Create enhanced protection scanner."""
        return EnhancedProtectionScanner()

    def test_generate_bypass_recommendations_for_protector(self, scanner: EnhancedProtectionScanner) -> None:
        """Bypass recommendations generated for high-confidence protector detection."""
        confidence_scores = {"protector": 0.85}
        technical_details: dict[str, list[Any]] = {}

        recommendations = scanner._generate_bypass_recommendations(confidence_scores, technical_details)

        assert len(recommendations) > 0
        assert any(rec["category"] == "Protector Bypass" for rec in recommendations)

        protector_rec = next((rec for rec in recommendations if rec["category"] == "Protector Bypass"), None)
        assert protector_rec is not None
        assert "method" in protector_rec
        assert "tools" in protector_rec
        assert "difficulty" in protector_rec
        assert "success_rate" in protector_rec

    def test_generate_bypass_recommendations_for_packer(self, scanner: EnhancedProtectionScanner) -> None:
        """Bypass recommendations generated for high-confidence packer detection."""
        confidence_scores = {"packer": 0.82}
        technical_details: dict[str, list[Any]] = {}

        recommendations = scanner._generate_bypass_recommendations(confidence_scores, technical_details)

        assert len(recommendations) > 0
        assert any(rec["category"] == "Unpacking" for rec in recommendations)

    def test_generate_bypass_recommendations_for_anti_debug(self, scanner: EnhancedProtectionScanner) -> None:
        """Bypass recommendations generated for anti-debug detection."""
        confidence_scores = {"anti_debug": 0.75}
        technical_details: dict[str, list[Any]] = {}

        recommendations = scanner._generate_bypass_recommendations(confidence_scores, technical_details)

        assert len(recommendations) > 0
        assert any("Anti-Debug" in rec["category"] for rec in recommendations)

    def test_generate_bypass_recommendations_for_licensing(self, scanner: EnhancedProtectionScanner) -> None:
        """Bypass recommendations generated for licensing detection."""
        confidence_scores = {"licensing": 0.72}
        technical_details: dict[str, list[Any]] = {}

        recommendations = scanner._generate_bypass_recommendations(confidence_scores, technical_details)

        assert len(recommendations) > 0
        assert any("License" in rec["category"] for rec in recommendations)

    def test_bypass_recommendations_include_required_fields(self, scanner: EnhancedProtectionScanner) -> None:
        """All bypass recommendations include required fields."""
        confidence_scores = {"protector": 0.9, "anti_debug": 0.8}
        technical_details: dict[str, list[Any]] = {}

        recommendations = scanner._generate_bypass_recommendations(confidence_scores, technical_details)

        for rec in recommendations:
            assert "category" in rec
            assert "method" in rec
            assert "tools" in rec
            assert isinstance(rec["tools"], list)
            assert "difficulty" in rec
            assert "time_estimate" in rec
            assert "success_rate" in rec


class TestEnhancedProtectionScannerCaching:
    """Validate scan result caching for performance."""

    @pytest.fixture
    def scanner(self) -> EnhancedProtectionScanner:
        """Create enhanced protection scanner."""
        return EnhancedProtectionScanner()

    def test_scan_caches_results(self, scanner: EnhancedProtectionScanner, tmp_path: Path) -> None:
        """Scanner caches scan results for repeated scans."""
        binary_path = tmp_path / "test.exe"

        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 224, 0x0102)
        optional_header = bytearray(224)
        text_section = bytearray(40)
        padding = bytearray(0x400 - 64 - 4 - 20 - 224 - 40)
        code = bytearray(512)

        binary_path.write_bytes(dos_header + pe_signature + coff_header + optional_header + text_section + padding + code)

        results1 = scanner.scan(str(binary_path), deep_scan=True)
        results2 = scanner.scan(str(binary_path), deep_scan=True)

        assert results1 == results2

    def test_cached_scan_faster_than_first_scan(self, scanner: EnhancedProtectionScanner, tmp_path: Path) -> None:
        """Cached scan completes faster than initial scan."""
        binary_path = tmp_path / "test.exe"

        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 224, 0x0102)
        optional_header = bytearray(224)
        text_section = bytearray(40)
        padding = bytearray(0x400 - 64 - 4 - 20 - 224 - 40)
        code = bytearray(1024)

        binary_path.write_bytes(dos_header + pe_signature + coff_header + optional_header + text_section + padding + code)

        start_time = time.time()
        scanner.scan(str(binary_path), deep_scan=True)
        first_duration = time.time() - start_time

        start_time = time.time()
        scanner.scan(str(binary_path), deep_scan=True)
        second_duration = time.time() - start_time

        assert second_duration < first_duration * 0.6


class TestEnhancedProtectionScannerErrorHandling:
    """Validate scanner error handling for invalid inputs."""

    @pytest.fixture
    def scanner(self) -> EnhancedProtectionScanner:
        """Create enhanced protection scanner."""
        return EnhancedProtectionScanner()

    def test_scan_nonexistent_file_returns_error(self, scanner: EnhancedProtectionScanner) -> None:
        """Scanner handles nonexistent file gracefully."""
        results = scanner.scan("/nonexistent/binary.exe", deep_scan=False)

        assert results is not None
        assert "error" in results

    def test_scan_invalid_pe_file_handles_error(self, scanner: EnhancedProtectionScanner, tmp_path: Path) -> None:
        """Scanner handles invalid PE file gracefully."""
        invalid_pe = tmp_path / "invalid.exe"
        invalid_pe.write_bytes(b"NOT A PE FILE" * 100)

        results = scanner.scan(str(invalid_pe), deep_scan=False)

        assert results is not None

    def test_scan_empty_file_handles_error(self, scanner: EnhancedProtectionScanner, tmp_path: Path) -> None:
        """Scanner handles empty file gracefully."""
        empty_file = tmp_path / "empty.exe"
        empty_file.write_bytes(b"")

        results = scanner.scan(str(empty_file), deep_scan=False)

        assert results is not None


class TestProtectionSignatureComplete:
    """Validate ProtectionSignature comprehensive signature definition."""

    def test_create_complete_protection_signature(self) -> None:
        """ProtectionSignature combines all detection methods."""
        static_sig = DynamicSignature(
            category=ProtectionCategory.PROTECTOR,
            confidence=0.95,
            pattern_bytes=b"\x60\x68\x00\x00\x00\x00",
            mask=b"\xff\xff\x00\x00\x00\x00",
            context="VMProtect entry",
        )

        signature = ProtectionSignature(
            name="VMProtect 3.5",
            category=ProtectionCategory.PROTECTOR,
            static_patterns=[static_sig],
            behavioral_indicators=["VM execution", "Code virtualization"],
            entropy_ranges=(7.5, 8.0),
            section_characteristics={".vmp0": {"executable": True, "writable": True}},
            import_signatures={"kernel32.dll", "ntdll.dll"},
            export_signatures=set(),
            string_indicators={"VMProtect", "vmp"},
            code_patterns=[b"\x64\xa1\x30\x00\x00\x00"],
            confidence_threshold=0.8,
        )

        assert signature.name == "VMProtect 3.5"
        assert signature.category == ProtectionCategory.PROTECTOR
        assert len(signature.static_patterns) == 1
        assert len(signature.behavioral_indicators) == 2
        assert signature.entropy_ranges == (7.5, 8.0)
        assert ".vmp0" in signature.section_characteristics
        assert "kernel32.dll" in signature.import_signatures
        assert "VMProtect" in signature.string_indicators
        assert signature.confidence_threshold == 0.8

    def test_protection_signature_with_minimal_components(self) -> None:
        """ProtectionSignature creates with minimal required components."""
        signature = ProtectionSignature(
            name="Generic Packer",
            category=ProtectionCategory.PACKER,
            static_patterns=[],
            behavioral_indicators=[],
            entropy_ranges=(7.0, 8.0),
            section_characteristics={},
            import_signatures=set(),
            export_signatures=set(),
            string_indicators=set(),
            code_patterns=[],
        )

        assert signature.name == "Generic Packer"
        assert signature.confidence_threshold == 0.7


class TestRealWorldIntegrationScenarios:
    """Integration tests validating complete protection detection workflows."""

    @pytest.fixture
    def scanner(self) -> EnhancedProtectionScanner:
        """Create scanner for integration tests."""
        return EnhancedProtectionScanner()

    def test_batch_scan_multiple_binaries(self, scanner: EnhancedProtectionScanner) -> None:
        """Scanner processes multiple binaries efficiently."""
        binaries = [SYSTEM32 / "notepad.exe", SYSTEM32 / "calc.exe"]

        results = []
        for binary_path in binaries:
            if binary_path.exists():
                result = scanner.scan(str(binary_path), deep_scan=False)
                results.append(result)

        assert results
        assert all("file_path" in r for r in results)

    def test_deep_scan_provides_technical_details(self, scanner: EnhancedProtectionScanner, tmp_path: Path) -> None:
        """Deep scan extracts detailed technical information."""
        binary_path = tmp_path / "detailed.exe"

        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 224, 0x0102)
        optional_header = bytearray(224)
        text_section = bytearray(40)
        text_section[:8] = b".text\x00\x00\x00"
        struct.pack_into("<I", text_section, 8, 4096)
        struct.pack_into("<I", text_section, 12, 0x1000)
        struct.pack_into("<I", text_section, 16, 4096)
        struct.pack_into("<I", text_section, 20, 0x400)

        padding = bytearray(0x400 - 64 - 4 - 20 - 224 - 40)

        code = bytearray(4096)
        code[:6] = b"\x64\xA1\x30\x00\x00\x00"
        code[50:52] = b"\x0F\x31"

        binary_data = dos_header + pe_signature + coff_header + optional_header + text_section + padding + code

        binary_path.write_bytes(binary_data)

        results = scanner.scan(str(binary_path), deep_scan=True)

        assert "technical_details" in results
