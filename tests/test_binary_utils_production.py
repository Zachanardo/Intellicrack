"""Production tests for intellicrack/utils/binary/binary_utils.py

Tests validate REAL offensive capabilities:
- File hash computation with progress callbacks for UI integration
- Binary file format detection (PE, ELF, Mach-O, APK)
- Binary file reading and writing with backup functionality
- File entropy calculation for detecting packed/encrypted code
- Suspicious PE section detection (W+X permissions)
- Binary file validation
"""

import hashlib
import os
from pathlib import Path
from typing import Any

import pytest

from intellicrack.utils.binary.binary_utils import (
    analyze_binary_format,
    check_suspicious_pe_sections,
    compute_file_hash,
    get_file_entropy,
    get_file_hash,
    is_binary_file,
    read_binary,
    validate_binary_path,
    write_binary,
)

try:
    from intellicrack.handlers.pefile_handler import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


class TestFileHashComputation:
    """Test file hash computation with various algorithms and progress tracking."""

    def test_sha256_hash_computation_on_real_file(self, tmp_path: Path) -> None:
        """SHA-256 hash correctly computed for real file."""
        test_file = tmp_path / "test.bin"
        test_data = b"Test data for hashing" * 100
        test_file.write_bytes(test_data)

        computed_hash: str = compute_file_hash(test_file, algorithm="sha256")

        expected_hash = hashlib.sha256(test_data).hexdigest()
        assert computed_hash == expected_hash
        assert len(computed_hash) == 64

    def test_md5_hash_computation_on_real_file(self, tmp_path: Path) -> None:
        """MD5 hash correctly computed for real file."""
        test_file = tmp_path / "test.bin"
        test_data = b"MD5 test data" * 50
        test_file.write_bytes(test_data)

        computed_hash: str = compute_file_hash(test_file, algorithm="md5")

        expected_hash = hashlib.md5(test_data).hexdigest()
        assert computed_hash == expected_hash
        assert len(computed_hash) == 32

    def test_sha1_hash_computation_on_real_file(self, tmp_path: Path) -> None:
        """SHA-1 hash correctly computed for real file."""
        test_file = tmp_path / "test.bin"
        test_data = b"SHA-1 test data" * 75
        test_file.write_bytes(test_data)

        computed_hash: str = compute_file_hash(test_file, algorithm="sha1")

        expected_hash = hashlib.sha1(test_data).hexdigest()
        assert computed_hash == expected_hash
        assert len(computed_hash) == 40

    def test_progress_callback_function_called_during_hashing(self, tmp_path: Path) -> None:
        """Progress callback receives updates during file hashing."""
        test_file = tmp_path / "large.bin"
        test_data = b"A" * (10 * 1024 * 1024)
        test_file.write_bytes(test_data)

        progress_values: list[int] = []

        def progress_callback(percent: int) -> None:
            progress_values.append(percent)

        compute_file_hash(test_file, progress_signal=progress_callback)

        assert progress_values
        assert all(0 <= p <= 100 for p in progress_values)
        assert 100 in progress_values

    def test_progress_signal_object_with_emit_called(self, tmp_path: Path) -> None:
        """Progress signal object's emit method called during hashing."""
        test_file = tmp_path / "data.bin"
        test_data = b"B" * (5 * 1024 * 1024)
        test_file.write_bytes(test_data)

        class MockSignal:
            def __init__(self) -> None:
                self.values: list[int] = []

            def emit(self, value: int) -> None:
                self.values.append(value)

        signal = MockSignal()

        compute_file_hash(test_file, progress_signal=signal)

        assert len(signal.values) > 0
        assert all(0 <= v <= 100 for v in signal.values)

    def test_hash_computation_on_empty_file(self, tmp_path: Path) -> None:
        """Hash correctly computed for empty file."""
        test_file = tmp_path / "empty.bin"
        test_file.write_bytes(b"")

        computed_hash: str = compute_file_hash(test_file, algorithm="sha256")

        expected_hash = hashlib.sha256(b"").hexdigest()
        assert computed_hash == expected_hash

    def test_hash_computation_on_large_file(self, tmp_path: Path) -> None:
        """Hash correctly computed for large file (multi-chunk processing)."""
        test_file = tmp_path / "large.bin"
        chunk_data = b"X" * (5 * 1024 * 1024)
        test_file.write_bytes(chunk_data)

        computed_hash: str = compute_file_hash(test_file, algorithm="sha256")

        expected_hash = hashlib.sha256(chunk_data).hexdigest()
        assert computed_hash == expected_hash

    def test_hash_computation_nonexistent_file_returns_empty_string(self) -> None:
        """Hash computation returns empty string for nonexistent file."""
        nonexistent_file = "D:/nonexistent/fake.bin"

        computed_hash: str = compute_file_hash(nonexistent_file)

        assert not computed_hash

    def test_hash_computation_invalid_algorithm_returns_empty_string(self, tmp_path: Path) -> None:
        """Hash computation returns empty string for unsupported algorithm."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"data")

        computed_hash: str = compute_file_hash(test_file, algorithm="invalid_algo")

        assert not computed_hash

    def test_get_file_hash_wrapper_function(self, tmp_path: Path) -> None:
        """get_file_hash wrapper correctly computes hash without progress."""
        test_file = tmp_path / "test.bin"
        test_data = b"wrapper test data"
        test_file.write_bytes(test_data)

        computed_hash: str = get_file_hash(test_file, algorithm="sha256")

        expected_hash = hashlib.sha256(test_data).hexdigest()
        assert computed_hash == expected_hash


class TestBinaryFormatDetection:
    """Test binary format detection for PE, ELF, Mach-O, and other formats."""

    def test_pe_format_detection_from_mz_header(self, tmp_path: Path) -> None:
        """PE format detected from MZ header."""
        pe_file = tmp_path / "test.exe"
        pe_header = b"MZ" + b"\x00" * 100
        pe_file.write_bytes(pe_header)

        format_info: dict[str, Any] = analyze_binary_format(pe_file)

        assert format_info["type"] == "PE"

    def test_pe32_format_detection_with_pe_signature(self, tmp_path: Path) -> None:
        """PE32/PE32+ format detected with PE signature."""
        pe_file = tmp_path / "test.exe"
        pe_data = bytearray(512)
        pe_data[:2] = b"MZ"
        pe_data[0x3C:0x40] = (0x80).to_bytes(4, "little")
        pe_data[0x80:0x84] = b"PE\x00\x00"
        pe_file.write_bytes(bytes(pe_data))

        format_info: dict[str, Any] = analyze_binary_format(pe_file)

        assert "PE32" in format_info["type"]

    def test_elf_32bit_format_detection(self, tmp_path: Path) -> None:
        """ELF 32-bit format detected from magic bytes and class field."""
        elf_file = tmp_path / "test.elf"
        elf_header = b"\x7fELF\x01" + b"\x00" * 100
        elf_file.write_bytes(elf_header)

        format_info: dict[str, Any] = analyze_binary_format(elf_file)

        assert format_info["type"] == "ELF"
        assert format_info["architecture"] == "32-bit"

    def test_elf_64bit_format_detection(self, tmp_path: Path) -> None:
        """ELF 64-bit format detected from magic bytes and class field."""
        elf_file = tmp_path / "test.elf"
        elf_header = b"\x7fELF\x02" + b"\x00" * 100
        elf_file.write_bytes(elf_header)

        format_info: dict[str, Any] = analyze_binary_format(elf_file)

        assert format_info["type"] == "ELF"
        assert format_info["architecture"] == "64-bit"

    def test_macho_32bit_format_detection(self, tmp_path: Path) -> None:
        """Mach-O 32-bit format detected from magic bytes."""
        macho_file = tmp_path / "test.macho"
        macho_header = b"\xce\xfa\xed\xfe" + b"\x00" * 100
        macho_file.write_bytes(macho_header)

        format_info: dict[str, Any] = analyze_binary_format(macho_file)

        assert format_info["type"] == "Mach-O"
        assert format_info["architecture"] == "32-bit"

    def test_macho_64bit_format_detection(self, tmp_path: Path) -> None:
        """Mach-O 64-bit format detected from magic bytes."""
        macho_file = tmp_path / "test.macho"
        macho_header = b"\xcf\xfa\xed\xfe" + b"\x00" * 100
        macho_file.write_bytes(macho_header)

        format_info: dict[str, Any] = analyze_binary_format(macho_file)

        assert format_info["type"] == "Mach-O"
        assert format_info["architecture"] == "64-bit"

    def test_apk_format_detection(self, tmp_path: Path) -> None:
        """APK format detected from ZIP magic and .apk extension."""
        apk_file = tmp_path / "test.apk"
        apk_header = b"PK\x03\x04" + b"\x00" * 100
        apk_file.write_bytes(apk_header)

        format_info: dict[str, Any] = analyze_binary_format(apk_file)

        assert format_info["type"] == "APK"

    def test_zip_format_detection(self, tmp_path: Path) -> None:
        """ZIP/JAR format detected from PK magic bytes."""
        zip_file = tmp_path / "test.zip"
        zip_header = b"PK\x03\x04" + b"\x00" * 100
        zip_file.write_bytes(zip_header)

        format_info: dict[str, Any] = analyze_binary_format(zip_file)

        assert "ZIP" in format_info["type"] or "APK" in format_info["type"]

    def test_unknown_format_detection(self, tmp_path: Path) -> None:
        """Unknown format returned for unrecognized binary."""
        unknown_file = tmp_path / "test.dat"
        unknown_file.write_bytes(b"UNKNOWN_FORMAT" * 100)

        format_info: dict[str, Any] = analyze_binary_format(unknown_file)

        assert format_info["type"] == "unknown"

    def test_format_detection_includes_file_size(self, tmp_path: Path) -> None:
        """Binary format detection includes file size."""
        test_file = tmp_path / "test.bin"
        test_data = b"A" * 1234
        test_file.write_bytes(test_data)

        format_info: dict[str, Any] = analyze_binary_format(test_file)

        assert format_info["size"] == 1234

    def test_format_detection_nonexistent_file_returns_error(self) -> None:
        """Format detection returns error for nonexistent file."""
        nonexistent = "D:/nonexistent/fake.bin"

        format_info: dict[str, Any] = analyze_binary_format(nonexistent)

        assert "error" in format_info


class TestBinaryFileOperations:
    """Test binary file reading and writing operations."""

    def test_read_binary_small_file(self, tmp_path: Path) -> None:
        """Binary file correctly read in full."""
        test_file = tmp_path / "test.bin"
        test_data = b"Binary data content"
        test_file.write_bytes(test_data)

        read_data: bytes = read_binary(test_file)

        assert read_data == test_data

    def test_read_binary_large_file_multi_chunk(self, tmp_path: Path) -> None:
        """Large binary file correctly read across multiple chunks."""
        test_file = tmp_path / "large.bin"
        test_data = b"X" * (50 * 1024)
        test_file.write_bytes(test_data)

        read_data: bytes = read_binary(test_file, chunk_size=8192)

        assert read_data == test_data
        assert len(read_data) == 50 * 1024

    def test_read_binary_empty_file(self, tmp_path: Path) -> None:
        """Empty binary file read returns empty bytes."""
        test_file = tmp_path / "empty.bin"
        test_file.write_bytes(b"")

        read_data: bytes = read_binary(test_file)

        assert read_data == b""

    def test_read_binary_nonexistent_file_raises_error(self) -> None:
        """Reading nonexistent binary raises FileNotFoundError."""
        nonexistent = "D:/nonexistent/fake.bin"

        with pytest.raises(FileNotFoundError):
            read_binary(nonexistent)

    def test_write_binary_creates_new_file(self, tmp_path: Path) -> None:
        """Writing binary data creates new file."""
        test_file = tmp_path / "new.bin"
        test_data = b"New binary data"

        success: bool = write_binary(test_file, test_data, create_backup=False)

        assert success
        assert test_file.exists()
        assert test_file.read_bytes() == test_data

    def test_write_binary_overwrites_existing_file(self, tmp_path: Path) -> None:
        """Writing binary data overwrites existing file."""
        test_file = tmp_path / "existing.bin"
        test_file.write_bytes(b"Old data")

        new_data = b"New overwritten data"
        success: bool = write_binary(test_file, new_data, create_backup=False)

        assert success
        assert test_file.read_bytes() == new_data

    def test_write_binary_creates_backup_of_existing_file(self, tmp_path: Path) -> None:
        """Writing binary with backup creates .bak file."""
        test_file = tmp_path / "file.bin"
        original_data = b"Original data"
        test_file.write_bytes(original_data)

        new_data = b"New data"
        success: bool = write_binary(test_file, new_data, create_backup=True)

        backup_file = test_file.with_suffix(".bin.bak")
        assert success
        assert backup_file.exists()
        assert backup_file.read_bytes() == original_data
        assert test_file.read_bytes() == new_data

    def test_write_binary_large_data(self, tmp_path: Path) -> None:
        """Writing large binary data succeeds."""
        test_file = tmp_path / "large.bin"
        large_data = b"Z" * (10 * 1024 * 1024)

        success: bool = write_binary(test_file, large_data, create_backup=False)

        assert success
        assert test_file.stat().st_size == 10 * 1024 * 1024


class TestFileEntropyCalculation:
    """Test entropy calculation for detecting encrypted/packed binaries."""

    def test_low_entropy_for_repetitive_data(self, tmp_path: Path) -> None:
        """Entropy is low for repetitive data."""
        test_file = tmp_path / "repetitive.bin"
        test_file.write_bytes(b"\x00" * 256)

        entropy: float = get_file_entropy(test_file, block_size=256)

        assert 0.0 <= entropy < 1.0

    def test_high_entropy_for_random_data(self, tmp_path: Path) -> None:
        """Entropy is high for random data."""
        import random

        test_file = tmp_path / "random.bin"
        random.seed(42)
        random_data = bytes(random.randint(0, 255) for _ in range(256))
        test_file.write_bytes(random_data)

        entropy: float = get_file_entropy(test_file, block_size=256)

        assert entropy > 7.0

    def test_medium_entropy_for_text_data(self, tmp_path: Path) -> None:
        """Entropy is medium for text data."""
        test_file = tmp_path / "text.txt"
        test_data = b"The quick brown fox jumps over the lazy dog " * 10
        test_file.write_bytes(test_data)

        entropy: float = get_file_entropy(test_file, block_size=256)

        assert 3.0 < entropy < 6.0

    def test_entropy_value_within_valid_range(self, tmp_path: Path) -> None:
        """Entropy value falls within valid range (0-8)."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"Mixed data 123 \x00\xFF" * 50)

        entropy: float = get_file_entropy(test_file, block_size=256)

        assert 0.0 <= entropy <= 8.0

    def test_entropy_on_empty_file_returns_zero(self, tmp_path: Path) -> None:
        """Entropy calculation on empty file returns 0.0."""
        test_file = tmp_path / "empty.bin"
        test_file.write_bytes(b"")

        entropy: float = get_file_entropy(test_file, block_size=256)

        assert entropy == 0.0

    def test_entropy_nonexistent_file_returns_zero(self) -> None:
        """Entropy calculation on nonexistent file returns 0.0."""
        nonexistent = "D:/nonexistent/fake.bin"

        entropy: float = get_file_entropy(nonexistent)

        assert entropy == 0.0


class TestBinaryFileTypeDetection:
    """Test binary vs text file detection."""

    def test_binary_file_detected_by_null_bytes(self, tmp_path: Path) -> None:
        """File with null bytes detected as binary."""
        test_file = tmp_path / "binary.bin"
        test_file.write_bytes(b"Data\x00with\x00nulls")

        is_binary: bool = is_binary_file(test_file)

        assert is_binary

    def test_text_file_without_null_bytes_not_binary(self, tmp_path: Path) -> None:
        """Text file without null bytes not detected as binary."""
        test_file = tmp_path / "text.txt"
        test_file.write_bytes(b"Plain text without null bytes")

        is_binary: bool = is_binary_file(test_file)

        assert not is_binary

    def test_executable_detected_as_binary(self, tmp_path: Path) -> None:
        """Executable with null bytes detected as binary."""
        test_file = tmp_path / "exe.exe"
        exe_data = b"MZ\x90\x00\x03\x00\x00\x00"
        test_file.write_bytes(exe_data)

        is_binary: bool = is_binary_file(test_file)

        assert is_binary

    def test_binary_detection_custom_sample_size(self, tmp_path: Path) -> None:
        """Binary detection with custom sample size."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"A" * 5000 + b"\x00" + b"B" * 5000)

        is_binary: bool = is_binary_file(test_file, sample_size=10000)

        assert is_binary


@pytest.mark.skipif(not PEFILE_AVAILABLE, reason="pefile library not available")
class TestSuspiciousPESections:
    """Test detection of suspicious PE sections with W+X permissions."""

    @pytest.fixture
    def legitimate_pe_binaries(self) -> list[Path]:
        """Provide paths to legitimate PE binaries."""
        binaries_dir = Path("D:/Intellicrack/tests/fixtures/binaries/pe/legitimate")
        return list(binaries_dir.glob("*.exe")) if binaries_dir.exists() else []

    def test_check_suspicious_sections_on_real_pe(self, legitimate_pe_binaries: list[Path]) -> None:
        """Suspicious section detection runs on real PE files."""
        if not legitimate_pe_binaries:
            pytest.skip("No legitimate PE binaries available")

        binary_path = legitimate_pe_binaries[0]
        pe = pefile.PE(str(binary_path))

        suspicious: list[str] = check_suspicious_pe_sections(pe)

        assert isinstance(suspicious, list)
        pe.close()

    def test_suspicious_sections_identifies_wx_permissions(self) -> None:
        """Suspicious sections correctly identified by W+X characteristics."""

        class MockSection:
            def __init__(self, name: bytes, characteristics: int) -> None:
                self.Name = name
                self.Characteristics = characteristics

        class MockPE:
            def __init__(self) -> None:
                self.sections = [
                    MockSection(b".text\x00\x00\x00", 0x60000020),
                    MockSection(b".rwxsec\x00", 0xA0000000),
                ]

        pe = MockPE()
        suspicious: list[str] = check_suspicious_pe_sections(pe)

        assert ".rwxsec" in suspicious

    def test_suspicious_sections_no_wx_sections_returns_empty(self) -> None:
        """No suspicious sections returned for safe PE."""

        class MockSection:
            def __init__(self, name: bytes, characteristics: int) -> None:
                self.Name = name
                self.Characteristics = characteristics

        class MockPE:
            def __init__(self) -> None:
                self.sections = [
                    MockSection(b".text\x00\x00\x00", 0x60000020),
                    MockSection(b".data\x00\x00\x00", 0xC0000040),
                ]

        pe = MockPE()
        suspicious: list[str] = check_suspicious_pe_sections(pe)

        assert not suspicious


class TestBinaryPathValidation:
    """Test binary path validation utility."""

    def test_validate_existing_binary_returns_true(self, tmp_path: Path) -> None:
        """Validation returns True for existing binary."""
        test_file = tmp_path / "valid.exe"
        test_file.write_bytes(b"MZ\x90\x00")

        is_valid: bool = validate_binary_path(str(test_file))

        assert is_valid

    def test_validate_nonexistent_binary_returns_false(self) -> None:
        """Validation returns False for nonexistent binary."""
        nonexistent = "D:/nonexistent/fake.exe"

        is_valid: bool = validate_binary_path(nonexistent)

        assert not is_valid

    def test_validate_empty_path_returns_false(self) -> None:
        """Validation returns False for empty path."""
        is_valid: bool = validate_binary_path("")

        assert not is_valid

    def test_validate_with_custom_logger(self, tmp_path: Path) -> None:
        """Validation uses custom logger when provided."""
        import logging

        custom_logger = logging.getLogger("test_logger")
        nonexistent = "D:/nonexistent/fake.exe"

        is_valid: bool = validate_binary_path(nonexistent, logger_instance=custom_logger)

        assert not is_valid


class TestRealBinaryFileOperations:
    """Test operations on real binary files from fixtures."""

    @pytest.fixture
    def legitimate_binaries(self) -> list[Path]:
        """Provide paths to legitimate binaries."""
        binaries_dir = Path("D:/Intellicrack/tests/fixtures/binaries/pe/legitimate")
        return list(binaries_dir.glob("*.exe")) if binaries_dir.exists() else []

    def test_hash_computation_on_real_binaries(self, legitimate_binaries: list[Path]) -> None:
        """Hash computation succeeds on real binary files."""
        if not legitimate_binaries:
            pytest.skip("No legitimate binaries available")

        binary_path = legitimate_binaries[0]

        computed_hash: str = compute_file_hash(binary_path, algorithm="sha256")

        assert len(computed_hash) == 64
        assert all(c in "0123456789abcdef" for c in computed_hash)

    def test_format_detection_on_real_binaries(self, legitimate_binaries: list[Path]) -> None:
        """Format detection correctly identifies real PE files."""
        if not legitimate_binaries:
            pytest.skip("No legitimate binaries available")

        binary_path = legitimate_binaries[0]

        format_info: dict[str, Any] = analyze_binary_format(binary_path)

        assert "PE" in format_info["type"]
        assert format_info["size"] > 0

    def test_entropy_calculation_on_real_binaries(self, legitimate_binaries: list[Path]) -> None:
        """Entropy calculation succeeds on real binaries."""
        if not legitimate_binaries:
            pytest.skip("No legitimate binaries available")

        binary_path = legitimate_binaries[0]

        entropy: float = get_file_entropy(binary_path, block_size=1024)

        assert 0.0 <= entropy <= 8.0

    def test_binary_read_on_real_files(self, legitimate_binaries: list[Path]) -> None:
        """Binary read succeeds on real executable files."""
        if not legitimate_binaries:
            pytest.skip("No legitimate binaries available")

        binary_path = legitimate_binaries[0]

        binary_data: bytes = read_binary(binary_path)

        assert binary_data
        assert binary_data.startswith(b"MZ")


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling."""

    def test_hash_with_permission_denied_returns_empty(self, tmp_path: Path) -> None:
        """Hash computation handles permission errors gracefully."""
        if os.name == "nt":
            pytest.skip("Permission test not reliable on Windows")

        test_file = tmp_path / "restricted.bin"
        test_file.write_bytes(b"data")
        os.chmod(test_file, 0o000)

        try:
            computed_hash: str = compute_file_hash(test_file)
            assert not computed_hash
        finally:
            os.chmod(test_file, 0o644)

    def test_read_binary_with_special_characters_in_path(self, tmp_path: Path) -> None:
        """Binary read handles paths with special characters."""
        test_file = tmp_path / "file with spaces & special@chars.bin"
        test_data = b"Special path data"
        test_file.write_bytes(test_data)

        read_data: bytes = read_binary(test_file)

        assert read_data == test_data

    def test_write_binary_to_readonly_directory_fails_gracefully(self, tmp_path: Path) -> None:
        """Binary write handles read-only directory gracefully."""
        if os.name == "nt":
            pytest.skip("Permission test not reliable on Windows")

        readonly_dir = tmp_path / "readonly"
        readonly_dir.mkdir()
        os.chmod(readonly_dir, 0o444)

        try:
            test_file = readonly_dir / "test.bin"
            success: bool = write_binary(test_file, b"data", create_backup=False)
            assert not success
        finally:
            os.chmod(readonly_dir, 0o755)
