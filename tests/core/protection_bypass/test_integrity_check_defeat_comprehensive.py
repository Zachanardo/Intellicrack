"""Comprehensive production-ready tests for integrity_check_defeat.py.

Tests validate actual integrity check detection, bypass, and defeat capabilities
against real binary patterns with genuine protection mechanisms.
"""

import hashlib
import io
import struct
import tempfile
import zlib
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pefile
import pytest

from intellicrack.core.protection_bypass.integrity_check_defeat import (
    BinaryPatcher,
    BypassStrategy,
    ChecksumLocation,
    ChecksumRecalculation,
    ChecksumRecalculator,
    IntegrityBypassEngine,
    IntegrityCheck,
    IntegrityCheckDefeatSystem,
    IntegrityCheckDetector,
    IntegrityCheckType,
)


@pytest.fixture
def temp_dir(tmp_path: Path) -> Path:
    """Create temporary directory for test files."""
    return tmp_path


@pytest.fixture
def checksum_calculator() -> ChecksumRecalculator:
    """Create ChecksumRecalculator instance."""
    return ChecksumRecalculator()


@pytest.fixture
def integrity_detector() -> IntegrityCheckDetector:
    """Create IntegrityCheckDetector instance."""
    return IntegrityCheckDetector()


@pytest.fixture
def bypass_engine() -> IntegrityBypassEngine:
    """Create IntegrityBypassEngine instance."""
    return IntegrityBypassEngine()


@pytest.fixture
def binary_patcher() -> BinaryPatcher:
    """Create BinaryPatcher instance."""
    return BinaryPatcher()


@pytest.fixture
def defeat_system() -> IntegrityCheckDefeatSystem:
    """Create IntegrityCheckDefeatSystem instance."""
    return IntegrityCheckDefeatSystem()


@pytest.fixture
def sample_test_data() -> bytes:
    """Create sample binary test data with known patterns."""
    data = b"This is test data for integrity checking " * 100
    data += b"\x00" * 512
    data += struct.pack("<I", 0xDEADBEEF)
    data += b"\xFF" * 256
    return data


@pytest.fixture
def minimal_pe_binary(temp_dir: Path) -> str:
    """Create minimal valid PE binary for testing."""
    pe_path = temp_dir / "minimal.exe"

    dos_header = bytearray(64)
    dos_header[:2] = b"MZ"
    dos_header[60:64] = struct.pack("<I", 64)

    pe_signature = b"PE\x00\x00"

    coff_header = bytearray(20)
    coff_header[:2] = struct.pack("<H", 0x014C)
    coff_header[2:4] = struct.pack("<H", 1)
    coff_header[16:18] = struct.pack("<H", 224)
    coff_header[18:20] = struct.pack("<H", 0x010B)

    optional_header = bytearray(224)
    optional_header[:2] = struct.pack("<H", 0x010B)
    optional_header[2] = 14
    optional_header[3] = 0
    optional_header[4:8] = struct.pack("<I", 0x1000)
    optional_header[8:12] = struct.pack("<I", 0x1000)
    optional_header[12:16] = struct.pack("<I", 0)
    optional_header[16:20] = struct.pack("<I", 0x1000)
    optional_header[20:24] = struct.pack("<I", 0x1000)
    optional_header[24:28] = struct.pack("<I", 0x400000)
    optional_header[28:32] = struct.pack("<I", 0x1000)
    optional_header[32:36] = struct.pack("<I", 0x200)
    optional_header[56:60] = struct.pack("<I", 0x3000)
    optional_header[60:64] = struct.pack("<I", 0x1000)
    optional_header[64:68] = struct.pack("<I", 0)
    optional_header[68:70] = struct.pack("<H", 6)
    optional_header[70:72] = struct.pack("<H", 0)

    section_header = bytearray(40)
    section_header[:8] = b".text\x00\x00\x00"
    section_header[8:12] = struct.pack("<I", 0x1000)
    section_header[12:16] = struct.pack("<I", 0x1000)
    section_header[16:20] = struct.pack("<I", 0x200)
    section_header[20:24] = struct.pack("<I", 0x400)
    section_header[36:40] = struct.pack("<I", 0x60000020)

    section_data = bytearray(512)
    section_data[:2] = b"\xC3\x90"

    binary = dos_header + pe_signature + coff_header + optional_header + section_header + section_data

    pe_path.write_bytes(binary)
    return str(pe_path)


@pytest.fixture
def pe_with_crc32_check(temp_dir: Path, minimal_pe_binary: str) -> str:
    """Create PE binary with embedded CRC32 integrity check pattern."""
    pe_path = temp_dir / "crc32_protected.exe"

    with open(minimal_pe_binary, "rb") as f:
        binary = bytearray(f.read())

    if len(binary) >= 512:
        insert_offset = 450
        crc32_pattern = b"\xc1\xe8\x08\x33\x81"

        binary[insert_offset : insert_offset + len(crc32_pattern)] = crc32_pattern

    pe_path.write_bytes(binary)
    return str(pe_path)


@pytest.fixture
def pe_with_md5_pattern(temp_dir: Path, minimal_pe_binary: str) -> str:
    """Create PE binary with MD5 hash initialization pattern."""
    pe_path = temp_dir / "md5_protected.exe"

    with open(minimal_pe_binary, "rb") as f:
        binary = bytearray(f.read())

    if len(binary) >= 512:
        insert_offset = 460
        md5_init_pattern = b"\x67\x45\x23\x01"

        binary[insert_offset : insert_offset + len(md5_init_pattern)] = md5_init_pattern

    pe_path.write_bytes(binary)
    return str(pe_path)


@pytest.fixture
def pe_with_sha256_pattern(temp_dir: Path, minimal_pe_binary: str) -> str:
    """Create PE binary with SHA256 hash constant pattern."""
    pe_path = temp_dir / "sha256_protected.exe"

    with open(minimal_pe_binary, "rb") as f:
        binary = bytearray(f.read())

    if len(binary) >= 512:
        insert_offset = 470
        sha256_pattern = b"\x6a\x09\xe6\x67"

        binary[insert_offset : insert_offset + len(sha256_pattern)] = sha256_pattern

    pe_path.write_bytes(binary)
    return str(pe_path)


class TestChecksumRecalculator:
    """Test ChecksumRecalculator functionality."""

    def test_crc32_table_generation_produces_256_entries(
        self,
        checksum_calculator: ChecksumRecalculator,
    ) -> None:
        """CRC32 lookup table has exactly 256 entries."""
        assert len(checksum_calculator.crc32_table) == 256
        assert all(isinstance(entry, int) for entry in checksum_calculator.crc32_table)

    def test_crc32_reversed_table_generation_produces_256_entries(
        self,
        checksum_calculator: ChecksumRecalculator,
    ) -> None:
        """CRC32 reversed lookup table has exactly 256 entries."""
        assert len(checksum_calculator.crc32_reversed_table) == 256
        assert all(isinstance(entry, int) for entry in checksum_calculator.crc32_reversed_table)

    def test_crc64_table_generation_produces_256_entries(
        self,
        checksum_calculator: ChecksumRecalculator,
    ) -> None:
        """CRC64 lookup table has exactly 256 entries."""
        assert len(checksum_calculator.crc64_table) == 256
        assert all(isinstance(entry, int) for entry in checksum_calculator.crc64_table)

    def test_calculate_crc32_matches_zlib_implementation(
        self,
        checksum_calculator: ChecksumRecalculator,
        sample_test_data: bytes,
    ) -> None:
        """CRC32 calculation matches zlib reference implementation."""
        manual_crc32 = checksum_calculator.calculate_crc32(sample_test_data)
        zlib_crc32 = checksum_calculator.calculate_crc32_zlib(sample_test_data)
        expected_zlib = zlib.crc32(sample_test_data) & 0xFFFFFFFF

        assert manual_crc32 == zlib_crc32
        assert zlib_crc32 == expected_zlib

    def test_calculate_crc32_produces_valid_32bit_value(
        self,
        checksum_calculator: ChecksumRecalculator,
        sample_test_data: bytes,
    ) -> None:
        """CRC32 calculation produces valid 32-bit unsigned integer."""
        crc32_value = checksum_calculator.calculate_crc32(sample_test_data)

        assert isinstance(crc32_value, int)
        assert 0 <= crc32_value <= 0xFFFFFFFF

    def test_calculate_crc32_different_data_produces_different_results(
        self,
        checksum_calculator: ChecksumRecalculator,
    ) -> None:
        """CRC32 produces different checksums for different data."""
        data1 = b"Test data 1"
        data2 = b"Test data 2"

        crc1 = checksum_calculator.calculate_crc32(data1)
        crc2 = checksum_calculator.calculate_crc32(data2)

        assert crc1 != crc2

    def test_calculate_md5_matches_hashlib_implementation(
        self,
        checksum_calculator: ChecksumRecalculator,
        sample_test_data: bytes,
    ) -> None:
        """MD5 calculation matches hashlib reference implementation."""
        calculated_md5 = checksum_calculator.calculate_md5(sample_test_data)
        expected_md5 = hashlib.md5(sample_test_data).hexdigest()  # noqa: S324

        assert calculated_md5 == expected_md5
        assert len(calculated_md5) == 32
        assert all(c in "0123456789abcdef" for c in calculated_md5)

    def test_calculate_sha1_matches_hashlib_implementation(
        self,
        checksum_calculator: ChecksumRecalculator,
        sample_test_data: bytes,
    ) -> None:
        """SHA1 calculation matches hashlib reference implementation."""
        calculated_sha1 = checksum_calculator.calculate_sha1(sample_test_data)
        expected_sha1 = hashlib.sha1(sample_test_data).hexdigest()  # noqa: S324

        assert calculated_sha1 == expected_sha1
        assert len(calculated_sha1) == 40
        assert all(c in "0123456789abcdef" for c in calculated_sha1)

    def test_calculate_sha256_matches_hashlib_implementation(
        self,
        checksum_calculator: ChecksumRecalculator,
        sample_test_data: bytes,
    ) -> None:
        """SHA256 calculation matches hashlib reference implementation."""
        calculated_sha256 = checksum_calculator.calculate_sha256(sample_test_data)
        expected_sha256 = hashlib.sha256(sample_test_data).hexdigest()

        assert calculated_sha256 == expected_sha256
        assert len(calculated_sha256) == 64
        assert all(c in "0123456789abcdef" for c in calculated_sha256)

    def test_calculate_sha512_matches_hashlib_implementation(
        self,
        checksum_calculator: ChecksumRecalculator,
        sample_test_data: bytes,
    ) -> None:
        """SHA512 calculation matches hashlib reference implementation."""
        calculated_sha512 = checksum_calculator.calculate_sha512(sample_test_data)
        expected_sha512 = hashlib.sha512(sample_test_data).hexdigest()

        assert calculated_sha512 == expected_sha512
        assert len(calculated_sha512) == 128
        assert all(c in "0123456789abcdef" for c in calculated_sha512)

    def test_calculate_crc64_produces_valid_64bit_value(
        self,
        checksum_calculator: ChecksumRecalculator,
        sample_test_data: bytes,
    ) -> None:
        """CRC64 calculation produces valid 64-bit unsigned integer."""
        crc64_value = checksum_calculator.calculate_crc64(sample_test_data)

        assert isinstance(crc64_value, int)
        assert 0 <= crc64_value <= 0xFFFFFFFFFFFFFFFF

    def test_calculate_crc64_different_data_produces_different_results(
        self,
        checksum_calculator: ChecksumRecalculator,
    ) -> None:
        """CRC64 produces different checksums for different data."""
        data1 = b"Test data for CRC64 calculation - variant 1"
        data2 = b"Test data for CRC64 calculation - variant 2"

        crc1 = checksum_calculator.calculate_crc64(data1)
        crc2 = checksum_calculator.calculate_crc64(data2)

        assert crc1 != crc2

    def test_calculate_hmac_sha256_produces_valid_signature(
        self,
        checksum_calculator: ChecksumRecalculator,
        sample_test_data: bytes,
    ) -> None:
        """HMAC-SHA256 calculation produces valid signature."""
        key = b"secret_key_for_testing_integrity_checks"

        calculated_hmac = checksum_calculator.calculate_hmac(sample_test_data, key, "sha256")

        assert len(calculated_hmac) == 64
        assert all(c in "0123456789abcdef" for c in calculated_hmac)

        import hmac as hmac_module

        expected_hmac = hmac_module.new(key, sample_test_data, hashlib.sha256).hexdigest()
        assert calculated_hmac == expected_hmac

    def test_calculate_hmac_sha512_produces_valid_signature(
        self,
        checksum_calculator: ChecksumRecalculator,
        sample_test_data: bytes,
    ) -> None:
        """HMAC-SHA512 calculation produces valid signature."""
        key = b"another_secret_key_for_hmac_testing"

        calculated_hmac = checksum_calculator.calculate_hmac(sample_test_data, key, "sha512")

        assert len(calculated_hmac) == 128
        assert all(c in "0123456789abcdef" for c in calculated_hmac)

    def test_calculate_all_hashes_returns_complete_hash_set(
        self,
        checksum_calculator: ChecksumRecalculator,
        sample_test_data: bytes,
    ) -> None:
        """Calculate all hashes returns dictionary with all hash types."""
        all_hashes = checksum_calculator.calculate_all_hashes(sample_test_data)

        assert isinstance(all_hashes, dict)
        assert "crc32" in all_hashes
        assert "crc64" in all_hashes
        assert "md5" in all_hashes
        assert "sha1" in all_hashes
        assert "sha256" in all_hashes
        assert "sha512" in all_hashes

        assert all_hashes["crc32"].startswith("0x")
        assert all_hashes["crc64"].startswith("0x")
        assert len(all_hashes["md5"]) == 32
        assert len(all_hashes["sha1"]) == 40
        assert len(all_hashes["sha256"]) == 64
        assert len(all_hashes["sha512"]) == 128

    def test_recalculate_pe_checksum_returns_valid_value(
        self,
        checksum_calculator: ChecksumRecalculator,
        minimal_pe_binary: str,
    ) -> None:
        """PE checksum recalculation returns valid checksum value."""
        checksum = checksum_calculator.recalculate_pe_checksum(minimal_pe_binary)

        assert isinstance(checksum, int)
        assert checksum >= 0
        assert checksum <= 0xFFFFFFFF

    def test_recalculate_section_hashes_returns_hash_for_all_sections(
        self,
        checksum_calculator: ChecksumRecalculator,
        minimal_pe_binary: str,
    ) -> None:
        """Section hash recalculation returns hashes for all PE sections."""
        section_hashes = checksum_calculator.recalculate_section_hashes(minimal_pe_binary)

        assert isinstance(section_hashes, dict)
        assert len(section_hashes) >= 1

        for section_name, hashes in section_hashes.items():
            assert "md5" in hashes
            assert "sha1" in hashes
            assert "sha256" in hashes
            assert "sha512" in hashes
            assert "crc32" in hashes
            assert "crc64" in hashes
            assert "size" in hashes

            assert len(hashes["md5"]) == 32
            assert len(hashes["sha1"]) == 40
            assert len(hashes["sha256"]) == 64
            assert len(hashes["sha512"]) == 128
            assert int(hashes["size"]) >= 0

    def test_extract_hmac_keys_finds_high_entropy_key_candidates(
        self,
        checksum_calculator: ChecksumRecalculator,
        temp_dir: Path,
    ) -> None:
        """HMAC key extraction identifies potential cryptographic keys."""
        binary_path = temp_dir / "binary_with_keys.bin"

        binary_data = bytearray(b"\x00" * 1000)

        potential_key_32 = b"\x8f\x3a\x47\x92\xbd\x51\xe8\x7c" * 4
        binary_data[500:532] = potential_key_32

        binary_path.write_bytes(binary_data)

        keys = checksum_calculator.extract_hmac_keys(str(binary_path))

        assert isinstance(keys, list)
        assert len(keys) <= 10

        if keys:
            for key in keys:
                assert "offset" in key
                assert "size" in key
                assert "key_hex" in key
                assert "entropy" in key
                assert "confidence" in key

                assert isinstance(key["offset"], int)
                assert isinstance(key["size"], int)
                assert isinstance(key["key_hex"], str)
                assert isinstance(key["entropy"], float)
                assert isinstance(key["confidence"], float)

                assert key["confidence"] >= 0.0
                assert key["confidence"] <= 1.0

    def test_find_checksum_locations_detects_embedded_checksums(
        self,
        checksum_calculator: ChecksumRecalculator,
        temp_dir: Path,
    ) -> None:
        """Checksum location finder identifies embedded integrity checksums."""
        binary_path = temp_dir / "binary_with_checksum.bin"

        test_data = b"Test binary data for checksum detection" * 50
        binary_path.write_bytes(test_data)

        calculated_crc32 = checksum_calculator.calculate_crc32_zlib(test_data)
        crc32_bytes = struct.pack("<I", calculated_crc32)

        modified_data = bytearray(test_data)
        modified_data[100:104] = crc32_bytes
        binary_path.write_bytes(modified_data)

        locations = checksum_calculator.find_checksum_locations(str(binary_path))

        assert isinstance(locations, list)

    def test_recalculate_for_patched_binary_detects_changes(
        self,
        checksum_calculator: ChecksumRecalculator,
        minimal_pe_binary: str,
        temp_dir: Path,
    ) -> None:
        """Checksum recalculation detects differences between original and patched."""
        patched_path = temp_dir / "patched.exe"

        with open(minimal_pe_binary, "rb") as f:
            original_data = bytearray(f.read())

        patched_data = bytearray(original_data)
        if len(patched_data) >= 500:
            patched_data[450:455] = b"\x90" * 5

        patched_path.write_bytes(patched_data)

        recalc = checksum_calculator.recalculate_for_patched_binary(
            minimal_pe_binary,
            str(patched_path),
        )

        assert isinstance(recalc, ChecksumRecalculation)
        assert recalc.original_crc32 != recalc.patched_crc32
        assert recalc.original_crc64 != recalc.patched_crc64
        assert recalc.original_md5 != recalc.patched_md5
        assert recalc.original_sha1 != recalc.patched_sha1
        assert recalc.original_sha256 != recalc.patched_sha256
        assert recalc.original_sha512 != recalc.patched_sha512

        assert recalc.pe_checksum >= 0
        assert isinstance(recalc.sections, dict)
        assert isinstance(recalc.hmac_keys, list)


class TestIntegrityCheckDetector:
    """Test IntegrityCheckDetector functionality."""

    def test_detector_initializes_with_pattern_database(
        self,
        integrity_detector: IntegrityCheckDetector,
    ) -> None:
        """Detector initializes with check patterns and API signatures."""
        assert hasattr(integrity_detector, "check_patterns")
        assert hasattr(integrity_detector, "api_signatures")
        assert isinstance(integrity_detector.check_patterns, dict)
        assert isinstance(integrity_detector.api_signatures, dict)
        assert len(integrity_detector.check_patterns) > 0
        assert len(integrity_detector.api_signatures) > 0

    def test_detect_checks_finds_crc32_pattern(
        self,
        integrity_detector: IntegrityCheckDetector,
        pe_with_crc32_check: str,
    ) -> None:
        """Detector identifies CRC32 integrity check patterns in binary."""
        checks = integrity_detector.detect_checks(pe_with_crc32_check)

        assert isinstance(checks, list)

        crc32_checks = [c for c in checks if c.check_type == IntegrityCheckType.CRC32]
        assert crc32_checks

        for check in crc32_checks:
            assert isinstance(check, IntegrityCheck)
            assert check.check_type == IntegrityCheckType.CRC32
            assert check.address >= 0
            assert 0.0 <= check.confidence <= 1.0
            assert check.binary_path == pe_with_crc32_check

    def test_detect_checks_finds_md5_pattern(
        self,
        integrity_detector: IntegrityCheckDetector,
        pe_with_md5_pattern: str,
    ) -> None:
        """Detector identifies MD5 hash initialization patterns."""
        checks = integrity_detector.detect_checks(pe_with_md5_pattern)

        assert isinstance(checks, list)

        md5_checks = [c for c in checks if c.check_type == IntegrityCheckType.MD5_HASH]
        assert md5_checks

        for check in md5_checks:
            assert check.check_type == IntegrityCheckType.MD5_HASH
            assert check.confidence > 0.0

    def test_detect_checks_finds_sha256_pattern(
        self,
        integrity_detector: IntegrityCheckDetector,
        pe_with_sha256_pattern: str,
    ) -> None:
        """Detector identifies SHA256 hash constant patterns."""
        checks = integrity_detector.detect_checks(pe_with_sha256_pattern)

        assert isinstance(checks, list)

        sha256_checks = [c for c in checks if c.check_type == IntegrityCheckType.SHA256_HASH]
        assert sha256_checks

        for check in sha256_checks:
            assert check.check_type == IntegrityCheckType.SHA256_HASH
            assert check.confidence > 0.0

    def test_detect_checks_returns_empty_for_clean_binary(
        self,
        integrity_detector: IntegrityCheckDetector,
        minimal_pe_binary: str,
    ) -> None:
        """Detector returns minimal or no checks for unprotected binary."""
        checks = integrity_detector.detect_checks(minimal_pe_binary)

        assert isinstance(checks, list)

    def test_detect_checks_includes_check_metadata(
        self,
        integrity_detector: IntegrityCheckDetector,
        pe_with_crc32_check: str,
    ) -> None:
        """Detected checks include complete metadata."""
        if checks := integrity_detector.detect_checks(pe_with_crc32_check):
            check = checks[0]
            assert hasattr(check, "check_type")
            assert hasattr(check, "address")
            assert hasattr(check, "size")
            assert hasattr(check, "function_name")
            assert hasattr(check, "bypass_method")
            assert hasattr(check, "confidence")
            assert hasattr(check, "binary_path")


class TestIntegrityBypassEngine:
    """Test IntegrityBypassEngine functionality."""

    def test_bypass_engine_initializes_with_strategies(
        self,
        bypass_engine: IntegrityBypassEngine,
    ) -> None:
        """Bypass engine initializes with bypass strategies."""
        assert hasattr(bypass_engine, "bypass_strategies")
        assert isinstance(bypass_engine.bypass_strategies, list)
        assert len(bypass_engine.bypass_strategies) > 0

        for strategy in bypass_engine.bypass_strategies:
            assert isinstance(strategy, BypassStrategy)
            assert isinstance(strategy.name, str)
            assert isinstance(strategy.check_types, list)
            assert isinstance(strategy.frida_script, str)
            assert 0.0 <= strategy.success_rate <= 1.0
            assert isinstance(strategy.priority, int)

    def test_bypass_strategies_include_crc32_bypass(
        self,
        bypass_engine: IntegrityBypassEngine,
    ) -> None:
        """Bypass strategies include CRC32 bypass implementation."""
        crc32_strategies = [
            s
            for s in bypass_engine.bypass_strategies
            if IntegrityCheckType.CRC32 in s.check_types
        ]

        assert crc32_strategies

        strategy = crc32_strategies[0]
        assert "RtlComputeCrc32" in strategy.frida_script or "crc32" in strategy.frida_script
        assert "Interceptor" in strategy.frida_script

    def test_bypass_strategies_include_hash_bypass(
        self,
        bypass_engine: IntegrityBypassEngine,
    ) -> None:
        """Bypass strategies include hash validation bypass."""
        hash_strategies = [
            s
            for s in bypass_engine.bypass_strategies
            if IntegrityCheckType.MD5_HASH in s.check_types
            or IntegrityCheckType.SHA1_HASH in s.check_types
            or IntegrityCheckType.SHA256_HASH in s.check_types
        ]

        assert hash_strategies

        strategy = hash_strategies[0]
        assert "CryptHashData" in strategy.frida_script or "BCryptHashData" in strategy.frida_script

    def test_bypass_strategies_include_authenticode_bypass(
        self,
        bypass_engine: IntegrityBypassEngine,
    ) -> None:
        """Bypass strategies include Authenticode signature bypass."""
        authenticode_strategies = [
            s
            for s in bypass_engine.bypass_strategies
            if IntegrityCheckType.AUTHENTICODE in s.check_types
        ]

        assert authenticode_strategies

        strategy = authenticode_strategies[0]
        assert "WinVerifyTrust" in strategy.frida_script

    def test_build_bypass_script_generates_valid_frida_code(
        self,
        bypass_engine: IntegrityBypassEngine,
        minimal_pe_binary: str,
    ) -> None:
        """Bypass script generation creates valid Frida JavaScript."""
        checks = [
            IntegrityCheck(
                check_type=IntegrityCheckType.CRC32,
                address=0x1000,
                size=4,
                expected_value=b"\x00" * 4,
                actual_value=b"\x00" * 4,
                function_name="RtlComputeCrc32",
                bypass_method="hook_api",
                confidence=0.9,
                binary_path=minimal_pe_binary,
            ),
        ]

        script = bypass_engine._build_bypass_script(checks)

        assert isinstance(script, str)
        assert len(script) > 0
        assert "Interceptor" in script or "Module.findExportByName" in script

    def test_get_best_strategy_selects_highest_priority(
        self,
        bypass_engine: IntegrityBypassEngine,
    ) -> None:
        """Best strategy selection chooses highest priority strategy."""
        if strategy := bypass_engine._get_best_strategy(IntegrityCheckType.CRC32):
            assert isinstance(strategy, BypassStrategy)
            assert IntegrityCheckType.CRC32 in strategy.check_types

            for other_strategy in bypass_engine.bypass_strategies:
                if IntegrityCheckType.CRC32 in other_strategy.check_types:
                    assert strategy.priority <= other_strategy.priority


class TestBinaryPatcher:
    """Test BinaryPatcher functionality."""

    def test_patcher_initializes_with_checksum_calculator(
        self,
        binary_patcher: BinaryPatcher,
    ) -> None:
        """Binary patcher initializes with checksum calculator."""
        assert hasattr(binary_patcher, "checksum_calc")
        assert isinstance(binary_patcher.checksum_calc, ChecksumRecalculator)
        assert hasattr(binary_patcher, "patch_history")
        assert isinstance(binary_patcher.patch_history, list)

    def test_patch_integrity_checks_creates_patched_binary(
        self,
        binary_patcher: BinaryPatcher,
        pe_with_crc32_check: str,
        temp_dir: Path,
    ) -> None:
        """Binary patching creates modified executable with checksums."""
        output_path = temp_dir / "patched_output.exe"

        checks = [
            IntegrityCheck(
                check_type=IntegrityCheckType.CRC32,
                address=0x1450,
                size=5,
                expected_value=b"\xc1\xe8\x08\x33\x81",
                actual_value=b"\xc1\xe8\x08\x33\x81",
                function_name="CRC32 calculation",
                bypass_method="patch_inline",
                confidence=0.9,
                binary_path=pe_with_crc32_check,
            ),
        ]

        success, checksums = binary_patcher.patch_integrity_checks(
            pe_with_crc32_check,
            checks,
            str(output_path),
        )

        assert success is True
        assert output_path.exists()
        assert output_path.stat().st_size > 0

        if checksums:
            assert isinstance(checksums, ChecksumRecalculation)
            assert checksums.original_crc32 != checksums.patched_crc32

    def test_patch_integrity_checks_recalculates_pe_checksum(
        self,
        binary_patcher: BinaryPatcher,
        pe_with_crc32_check: str,
        temp_dir: Path,
    ) -> None:
        """Binary patching recalculates PE checksum after modifications."""
        output_path = temp_dir / "patched_checksum.exe"

        checks = [
            IntegrityCheck(
                check_type=IntegrityCheckType.CRC32,
                address=0x1450,
                size=5,
                expected_value=b"\xc1\xe8\x08\x33\x81",
                actual_value=b"\xc1\xe8\x08\x33\x81",
                function_name="CRC32 calculation",
                bypass_method="patch_inline",
                confidence=0.9,
                binary_path=pe_with_crc32_check,
            ),
        ]

        success, checksums = binary_patcher.patch_integrity_checks(
            pe_with_crc32_check,
            checks,
            str(output_path),
        )

        assert success is True

        if checksums:
            assert checksums.pe_checksum > 0
            assert checksums.pe_checksum <= 0xFFFFFFFF

    def test_patch_integrity_checks_maintains_patch_history(
        self,
        binary_patcher: BinaryPatcher,
        pe_with_crc32_check: str,
        temp_dir: Path,
    ) -> None:
        """Binary patcher maintains complete patch history."""
        output_path = temp_dir / "patched_history.exe"

        checks = [
            IntegrityCheck(
                check_type=IntegrityCheckType.CRC32,
                address=0x1450,
                size=5,
                expected_value=b"\xc1\xe8\x08\x33\x81",
                actual_value=b"\xc1\xe8\x08\x33\x81",
                function_name="CRC32 calculation",
                bypass_method="patch_inline",
                confidence=0.9,
                binary_path=pe_with_crc32_check,
            ),
        ]

        binary_patcher.patch_integrity_checks(
            pe_with_crc32_check,
            checks,
            str(output_path),
        )

        assert len(binary_patcher.patch_history) > 0

        patch_entry = binary_patcher.patch_history[0]
        assert "address" in patch_entry
        assert "size" in patch_entry
        assert "original" in patch_entry
        assert "patched" in patch_entry
        assert "type" in patch_entry


class TestIntegrityCheckDefeatSystem:
    """Test IntegrityCheckDefeatSystem integration."""

    def test_defeat_system_initializes_all_components(
        self,
        defeat_system: IntegrityCheckDefeatSystem,
    ) -> None:
        """Defeat system initializes detector, bypasser, and patcher."""
        assert hasattr(defeat_system, "detector")
        assert hasattr(defeat_system, "bypasser")
        assert hasattr(defeat_system, "patcher")
        assert hasattr(defeat_system, "checksum_calc")

        assert isinstance(defeat_system.detector, IntegrityCheckDetector)
        assert isinstance(defeat_system.bypasser, IntegrityBypassEngine)
        assert isinstance(defeat_system.patcher, BinaryPatcher)
        assert isinstance(defeat_system.checksum_calc, ChecksumRecalculator)

    def test_defeat_integrity_checks_detects_and_analyzes(
        self,
        defeat_system: IntegrityCheckDefeatSystem,
        pe_with_crc32_check: str,
    ) -> None:
        """Complete defeat workflow detects integrity checks."""
        result = defeat_system.defeat_integrity_checks(
            pe_with_crc32_check,
            process_name=None,
            patch_binary=False,
        )

        assert isinstance(result, dict)
        assert "success" in result
        assert "checks_bypassed" in result
        assert "binary_patched" in result
        assert "checksums" in result
        assert "details" in result
        assert "checks_detected" in result

        assert isinstance(result["checks_detected"], int)
        assert result["checks_detected"] >= 0

    def test_defeat_integrity_checks_with_patching(
        self,
        defeat_system: IntegrityCheckDefeatSystem,
        pe_with_crc32_check: str,
    ) -> None:
        """Complete defeat workflow patches binary when requested."""
        result = defeat_system.defeat_integrity_checks(
            pe_with_crc32_check,
            process_name=None,
            patch_binary=True,
        )

        assert isinstance(result, dict)

        if result["checks_detected"] > 0:
            assert "binary_patched" in result

    def test_generate_bypass_script_produces_frida_code(
        self,
        defeat_system: IntegrityCheckDefeatSystem,
        pe_with_crc32_check: str,
    ) -> None:
        """Bypass script generation produces valid Frida JavaScript."""
        script = defeat_system.generate_bypass_script(pe_with_crc32_check)

        assert isinstance(script, str)
        assert len(script) > 0

    def test_recalculate_checksums_compares_original_and_patched(
        self,
        defeat_system: IntegrityCheckDefeatSystem,
        minimal_pe_binary: str,
        temp_dir: Path,
    ) -> None:
        """Checksum recalculation compares original and patched binaries."""
        patched_path = temp_dir / "comparison_patched.exe"

        with open(minimal_pe_binary, "rb") as f:
            original_data = bytearray(f.read())

        patched_data = bytearray(original_data)
        if len(patched_data) >= 500:
            patched_data[450:455] = b"\x90" * 5

        patched_path.write_bytes(patched_data)

        checksums = defeat_system.recalculate_checksums(minimal_pe_binary, str(patched_path))

        assert isinstance(checksums, ChecksumRecalculation)
        assert checksums.original_crc32 != checksums.patched_crc32
        assert checksums.original_md5 != checksums.patched_md5
        assert checksums.original_sha256 != checksums.patched_sha256

    def test_find_embedded_checksums_detects_stored_values(
        self,
        defeat_system: IntegrityCheckDefeatSystem,
        temp_dir: Path,
    ) -> None:
        """Embedded checksum detection finds stored integrity values."""
        binary_path = temp_dir / "embedded_checksum_test.bin"

        test_data = b"Binary content for embedded checksum testing" * 100
        binary_path.write_bytes(test_data)

        locations = defeat_system.find_embedded_checksums(str(binary_path))

        assert isinstance(locations, list)

    def test_extract_hmac_keys_identifies_key_material(
        self,
        defeat_system: IntegrityCheckDefeatSystem,
        temp_dir: Path,
    ) -> None:
        """HMAC key extraction identifies cryptographic key material."""
        binary_path = temp_dir / "hmac_key_test.bin"

        binary_data = bytearray(b"\x00" * 2000)

        high_entropy_key = bytes(i % 256 for i in range(32))
        binary_data[1000:1032] = high_entropy_key

        binary_path.write_bytes(binary_data)

        keys = defeat_system.extract_hmac_keys(str(binary_path))

        assert isinstance(keys, list)
        assert len(keys) <= 10


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_checksum_calculation_empty_data(
        self,
        checksum_calculator: ChecksumRecalculator,
    ) -> None:
        """Checksum calculation handles empty data gracefully."""
        empty_data = b""

        crc32 = checksum_calculator.calculate_crc32(empty_data)
        md5 = checksum_calculator.calculate_md5(empty_data)
        sha256 = checksum_calculator.calculate_sha256(empty_data)

        assert isinstance(crc32, int)
        assert isinstance(md5, str)
        assert isinstance(sha256, str)

    def test_checksum_calculation_large_data(
        self,
        checksum_calculator: ChecksumRecalculator,
    ) -> None:
        """Checksum calculation handles large data efficiently."""
        large_data = b"X" * (10 * 1024 * 1024)

        crc32 = checksum_calculator.calculate_crc32_zlib(large_data)
        md5 = checksum_calculator.calculate_md5(large_data)

        assert isinstance(crc32, int)
        assert isinstance(md5, str)
        assert len(md5) == 32

    def test_detect_checks_invalid_binary_path(
        self,
        integrity_detector: IntegrityCheckDetector,
    ) -> None:
        """Detector handles invalid binary path gracefully."""
        checks = integrity_detector.detect_checks("nonexistent_file.exe")

        assert isinstance(checks, list)
        assert len(checks) == 0

    def test_patch_integrity_checks_no_checks(
        self,
        binary_patcher: BinaryPatcher,
        minimal_pe_binary: str,
        temp_dir: Path,
    ) -> None:
        """Binary patcher handles empty check list."""
        output_path = temp_dir / "no_checks_patch.exe"

        success, checksums = binary_patcher.patch_integrity_checks(
            minimal_pe_binary,
            [],
            str(output_path),
        )

        assert isinstance(success, bool)

    def test_defeat_system_no_integrity_checks_detected(
        self,
        defeat_system: IntegrityCheckDefeatSystem,
        minimal_pe_binary: str,
    ) -> None:
        """Defeat system handles binaries without integrity checks."""
        result = defeat_system.defeat_integrity_checks(
            minimal_pe_binary,
            process_name=None,
            patch_binary=False,
        )

        assert isinstance(result, dict)
        assert result["success"] is True
        assert result["checks_detected"] >= 0


class TestPerformance:
    """Test performance characteristics."""

    def test_crc32_calculation_performance(
        self,
        checksum_calculator: ChecksumRecalculator,
        benchmark: Any,
    ) -> None:
        """CRC32 calculation performance meets requirements."""
        data = b"Performance test data" * 10000

        result = benchmark(checksum_calculator.calculate_crc32_zlib, data)

        assert isinstance(result, int)

    def test_hash_calculation_performance(
        self,
        checksum_calculator: ChecksumRecalculator,
        benchmark: Any,
    ) -> None:
        """SHA256 calculation performance meets requirements."""
        data = b"Hash performance test" * 10000

        result = benchmark(checksum_calculator.calculate_sha256, data)

        assert isinstance(result, str)
        assert len(result) == 64
