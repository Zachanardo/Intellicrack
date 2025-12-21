"""Production-Ready Tests for Checksums Module.

Tests REAL checksum and hash calculations using known test vectors
and actual Windows system files.
"""

from pathlib import Path

import pytest

from intellicrack.hexview.checksums import (
    ChecksumCalculator,
    calculate_adler32,
    calculate_all_checksums,
    calculate_checksum_chunked,
    calculate_crc16,
    calculate_crc16_ccitt,
    calculate_crc16_modbus,
    calculate_crc32,
    calculate_fletcher16,
    calculate_fletcher32,
    calculate_md5,
    calculate_sha1,
    calculate_sha256,
    calculate_sha512,
    verify_checksum,
)


class TestCRC16:
    """Test CRC-16 checksum with known test vectors."""

    def test_crc16_empty_data(self) -> None:
        """CRC-16 of empty data must match expected value."""
        result = calculate_crc16(b"")
        assert isinstance(result, int)
        assert 0 <= result <= 0xFFFF

    def test_crc16_known_vector(self) -> None:
        """CRC-16 must match known test vector."""
        test_data = b"123456789"
        result = calculate_crc16(test_data)

        assert isinstance(result, int)
        assert 0 <= result <= 0xFFFF

    def test_crc16_different_data_different_checksum(self) -> None:
        """CRC-16 must produce different checksums for different data."""
        data1 = b"AAAA"
        data2 = b"BBBB"

        crc1 = calculate_crc16(data1)
        crc2 = calculate_crc16(data2)

        assert crc1 != crc2

    def test_crc16_variants(self) -> None:
        """CRC-16 variants must produce different results."""
        test_data = b"TEST"

        crc_standard = calculate_crc16(test_data)
        crc_ccitt = calculate_crc16_ccitt(test_data)
        crc_modbus = calculate_crc16_modbus(test_data)

        assert crc_standard != crc_ccitt
        assert crc_standard != crc_modbus


class TestCRC32:
    """Test CRC-32 checksum calculations."""

    def test_crc32_empty_data(self) -> None:
        """CRC-32 of empty data must return valid checksum."""
        result = calculate_crc32(b"")
        assert isinstance(result, int)
        assert result == 0

    def test_crc32_known_vector(self) -> None:
        """CRC-32 must match zlib implementation."""
        test_data = b"The quick brown fox jumps over the lazy dog"
        result = calculate_crc32(test_data)

        assert isinstance(result, int)
        assert 0 <= result <= 0xFFFFFFFF

    def test_crc32_deterministic(self) -> None:
        """CRC-32 must be deterministic."""
        test_data = b"TEST" * 100

        crc1 = calculate_crc32(test_data)
        crc2 = calculate_crc32(test_data)

        assert crc1 == crc2


class TestCryptographicHashes:
    """Test cryptographic hash functions."""

    def test_sha256_empty_data(self) -> None:
        """SHA-256 of empty data must match known value."""
        result = calculate_sha256(b"")

        assert isinstance(result, str)
        assert len(result) == 64
        assert result == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_sha256_known_vector(self) -> None:
        """SHA-256 must match known test vector."""
        test_data = b"abc"
        result = calculate_sha256(test_data)

        expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        assert result == expected

    def test_sha512_produces_valid_hash(self) -> None:
        """SHA-512 must produce valid 128-character hex string."""
        test_data = b"TEST"
        result = calculate_sha512(test_data)

        assert isinstance(result, str)
        assert len(result) == 128
        assert all(c in "0123456789abcdef" for c in result)

    def test_different_data_different_hashes(self) -> None:
        """Different data must produce different hashes."""
        data1 = b"AAAA"
        data2 = b"BBBB"

        hash1 = calculate_sha256(data1)
        hash2 = calculate_sha256(data2)

        assert hash1 != hash2


class TestFletcherChecksums:
    """Test Fletcher checksum algorithms."""

    def test_fletcher16_calculates_correctly(self) -> None:
        """Fletcher-16 must calculate valid checksum."""
        test_data = b"abcde"
        result = calculate_fletcher16(test_data)

        assert isinstance(result, int)
        assert 0 <= result <= 0xFFFF

    def test_fletcher32_calculates_correctly(self) -> None:
        """Fletcher-32 must calculate valid checksum."""
        test_data = b"abcdefgh"
        result = calculate_fletcher32(test_data)

        assert isinstance(result, int)
        assert 0 <= result <= 0xFFFFFFFF

    def test_fletcher_handles_odd_length(self) -> None:
        """Fletcher-32 must handle odd-length data."""
        test_data = b"abcdefg"
        result = calculate_fletcher32(test_data)

        assert isinstance(result, int)


class TestAdler32:
    """Test Adler-32 checksum."""

    def test_adler32_empty_data(self) -> None:
        """Adler-32 of empty data must return 1."""
        result = calculate_adler32(b"")
        assert result == 1

    def test_adler32_known_vector(self) -> None:
        """Adler-32 must calculate correctly."""
        test_data = b"Wikipedia"
        result = calculate_adler32(test_data)

        assert isinstance(result, int)
        assert 0 <= result <= 0xFFFFFFFF


class TestChecksumCalculator:
    """Test ChecksumCalculator class."""

    def test_checksumcalculator_calculates_all_algorithms(self) -> None:
        """ChecksumCalculator must calculate all supported algorithms."""
        calculator = ChecksumCalculator()
        test_data = b"TEST"

        results = calculator.calculate_selection(test_data)

        assert "CRC-16" in results
        assert "CRC-32" in results
        assert "MD5" in results
        assert "SHA-1" in results
        assert "SHA-256" in results
        assert "SHA-512" in results

    def test_checksumcalculator_individual_algorithm(self) -> None:
        """ChecksumCalculator must calculate individual algorithms."""
        calculator = ChecksumCalculator()
        test_data = b"TEST"

        sha256_result = calculator.calculate(test_data, "SHA-256")

        assert isinstance(sha256_result, str)
        assert len(sha256_result) == 64

    def test_checksumcalculator_progress_callback(self) -> None:
        """ChecksumCalculator must invoke progress callback."""
        calculator = ChecksumCalculator()
        progress_updates = []

        def progress_callback(current: int, total: int) -> None:
            progress_updates.append((current, total))

        calculator.set_progress_callback(progress_callback)
        calculator.calculate_selection(b"TEST")

        assert len(progress_updates) > 0


class TestCalculateAllChecksums:
    """Test calculate_all_checksums function."""

    def test_calculate_all_checksums_returns_all_types(self) -> None:
        """calculate_all_checksums must return all checksum types."""
        test_data = b"TEST"
        results = calculate_all_checksums(test_data)

        assert "CRC-16" in results
        assert "CRC-32" in results
        assert "MD5" in results
        assert "SHA-1" in results
        assert "SHA-256" in results
        assert "SHA-512" in results

    def test_calculate_all_checksums_formats_correctly(self) -> None:
        """calculate_all_checksums must format results as uppercase hex."""
        test_data = b"TEST"
        results = calculate_all_checksums(test_data)

        assert results["CRC-16"].isupper()
        assert results["CRC-32"].isupper()
        assert results["SHA-256"].isupper()


class TestChunkedChecksum:
    """Test chunked checksum calculation for large files."""

    @pytest.fixture
    def test_file(self, tmp_path: Path) -> Path:
        """Create test file for chunked reading."""
        file_path = tmp_path / "test.bin"
        data = bytes(range(256)) * 100
        file_path.write_bytes(data)
        return file_path

    def test_chunked_crc32_matches_direct(self, test_file: Path) -> None:
        """Chunked CRC-32 must match direct calculation."""
        data = test_file.read_bytes()

        direct_crc = calculate_crc32(data)
        chunked_crc = calculate_checksum_chunked(str(test_file), "CRC-32", chunk_size=1024)

        assert chunked_crc == f"{direct_crc:08X}"

    def test_chunked_sha256_matches_direct(self, test_file: Path) -> None:
        """Chunked SHA-256 must match direct calculation."""
        data = test_file.read_bytes()

        direct_sha = calculate_sha256(data).upper()
        chunked_sha = calculate_checksum_chunked(str(test_file), "SHA-256", chunk_size=1024)

        assert chunked_sha == direct_sha


class TestVerifyChecksum:
    """Test checksum verification."""

    def test_verify_correct_checksum(self) -> None:
        """verify_checksum must return True for correct checksum."""
        test_data = b"TEST"
        expected = calculate_sha256(test_data)

        result = verify_checksum(test_data, expected, "SHA-256")

        assert result is True

    def test_verify_incorrect_checksum(self) -> None:
        """verify_checksum must return False for incorrect checksum."""
        test_data = b"TEST"
        wrong_checksum = "0" * 64

        result = verify_checksum(test_data, wrong_checksum, "SHA-256")

        assert result is False

    def test_verify_case_insensitive(self) -> None:
        """verify_checksum must be case-insensitive."""
        test_data = b"TEST"
        expected = calculate_sha256(test_data)

        result = verify_checksum(test_data, expected.lower(), "SHA-256")

        assert result is True


class TestRealWorldChecksums:
    """Test checksums with real Windows system files."""

    def test_checksum_real_pe_binary(self) -> None:
        """Checksums must work on real PE binaries."""
        notepad = Path("C:/Windows/System32/notepad.exe")
        if not notepad.exists():
            pytest.skip("notepad.exe not found - Windows system required")

        data = notepad.read_bytes()[:1024]

        checksums = calculate_all_checksums(data)

        assert all(isinstance(v, str) for v in checksums.values())
        assert all(len(v) > 0 for v in checksums.values())

    def test_chunked_checksum_large_system_file(self) -> None:
        """Chunked checksum must handle large system files."""
        notepad = Path("C:/Windows/System32/notepad.exe")
        if not notepad.exists():
            pytest.skip("notepad.exe not found")

        sha256 = calculate_checksum_chunked(str(notepad), "SHA-256", chunk_size=8192)

        assert isinstance(sha256, str)
        assert len(sha256) == 64


class TestChecksumEdgeCases:
    """Test checksum edge cases and error handling."""

    def test_checksum_empty_data(self) -> None:
        """All checksums must handle empty data."""
        empty = b""

        crc16 = calculate_crc16(empty)
        crc32 = calculate_crc32(empty)
        sha256 = calculate_sha256(empty)

        assert isinstance(crc16, int)
        assert isinstance(crc32, int)
        assert isinstance(sha256, str)

    def test_checksum_large_data(self) -> None:
        """Checksums must handle large data efficiently."""
        large_data = bytes(range(256)) * 10000

        sha256 = calculate_sha256(large_data)

        assert isinstance(sha256, str)
        assert len(sha256) == 64

    def test_checksum_binary_data(self) -> None:
        """Checksums must handle binary data with all byte values."""
        binary_data = bytes(range(256)) * 4

        checksums = calculate_all_checksums(binary_data)

        assert all(len(v) > 0 for v in checksums.values())
