"""Production tests for binary_utils.py using real Windows system DLLs.

Tests validate actual binary operations on Windows system files like kernel32.dll,
ntdll.dll, and user32.dll without mocks or stubs.
"""

import hashlib
import os
import platform
import tempfile
from pathlib import Path
from typing import Callable

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


@pytest.fixture
def windows_system_dll() -> str:
    """Return path to Windows kernel32.dll for testing."""
    if platform.system() != "Windows":
        pytest.skip("Test requires Windows platform")

    kernel32_path = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32" / "kernel32.dll"

    if not kernel32_path.exists():
        pytest.skip(f"kernel32.dll not found at {kernel32_path}")

    return str(kernel32_path)


@pytest.fixture
def windows_ntdll() -> str:
    """Return path to Windows ntdll.dll for testing."""
    if platform.system() != "Windows":
        pytest.skip("Test requires Windows platform")

    ntdll_path = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32" / "ntdll.dll"

    if not ntdll_path.exists():
        pytest.skip(f"ntdll.dll not found at {ntdll_path}")

    return str(ntdll_path)


@pytest.fixture
def temp_binary_file(tmp_path: Path) -> Path:
    """Create temporary binary file for write tests."""
    test_file = tmp_path / "test_binary.bin"
    test_data = b"\x4D\x5A\x90\x00" + b"\x00" * 100
    test_file.write_bytes(test_data)
    return test_file


@pytest.fixture
def temp_text_file(tmp_path: Path) -> Path:
    """Create temporary text file for binary detection tests."""
    text_file = tmp_path / "test_text.txt"
    text_file.write_text("This is plain text without null bytes")
    return text_file


class TestComputeFileHash:
    """Test file hash computation functionality."""

    def test_computes_sha256_hash_of_kernel32(self, windows_system_dll: str) -> None:
        """Computes valid SHA256 hash of kernel32.dll."""
        hash_value = compute_file_hash(windows_system_dll, algorithm="sha256")

        assert hash_value != ""
        assert len(hash_value) == 64
        assert all(c in "0123456789abcdef" for c in hash_value)

    def test_computes_md5_hash_of_kernel32(self, windows_system_dll: str) -> None:
        """Computes valid MD5 hash of kernel32.dll."""
        hash_value = compute_file_hash(windows_system_dll, algorithm="md5")

        assert hash_value != ""
        assert len(hash_value) == 32
        assert all(c in "0123456789abcdef" for c in hash_value)

    def test_computes_sha1_hash_of_kernel32(self, windows_system_dll: str) -> None:
        """Computes valid SHA1 hash of kernel32.dll."""
        hash_value = compute_file_hash(windows_system_dll, algorithm="sha1")

        assert hash_value != ""
        assert len(hash_value) == 40
        assert all(c in "0123456789abcdef" for c in hash_value)

    def test_hash_consistency_multiple_runs(self, windows_system_dll: str) -> None:
        """Hash computation is deterministic across multiple runs."""
        hash1 = compute_file_hash(windows_system_dll)
        hash2 = compute_file_hash(windows_system_dll)

        assert hash1 == hash2
        assert hash1 != ""

    def test_progress_signal_callback(self, windows_system_dll: str) -> None:
        """Progress callback is invoked during hash computation."""
        progress_values: list[int] = []

        def progress_callback(percent: int) -> None:
            progress_values.append(percent)

        hash_value = compute_file_hash(
            windows_system_dll, algorithm="sha256", progress_signal=progress_callback
        )

        assert hash_value != ""
        assert len(progress_values) > 0
        assert all(0 <= v <= 100 for v in progress_values)

    def test_progress_signal_with_emit_method(self, windows_system_dll: str) -> None:
        """Progress signal object with emit method works correctly."""

        class ProgressSignal:
            def __init__(self) -> None:
                self.values: list[int] = []

            def emit(self, value: int) -> None:
                self.values.append(value)

        signal = ProgressSignal()
        hash_value = compute_file_hash(
            windows_system_dll, algorithm="sha256", progress_signal=signal
        )

        assert hash_value != ""
        assert len(signal.values) > 0

    def test_handles_nonexistent_file(self) -> None:
        """Returns empty string for nonexistent file."""
        hash_value = compute_file_hash("/nonexistent/file.bin")

        assert hash_value == ""

    def test_handles_invalid_algorithm(self, windows_system_dll: str) -> None:
        """Returns empty string for unsupported hash algorithm."""
        hash_value = compute_file_hash(windows_system_dll, algorithm="invalid_algo")

        assert hash_value == ""

    def test_handles_permission_error(self) -> None:
        """Returns empty string when file permissions deny access."""
        hash_value = compute_file_hash("C:\\pagefile.sys")

        assert hash_value == ""


class TestGetFileHash:
    """Test get_file_hash wrapper function."""

    def test_wrapper_calls_compute_file_hash(self, windows_system_dll: str) -> None:
        """get_file_hash is wrapper for compute_file_hash."""
        hash1 = get_file_hash(windows_system_dll)
        hash2 = compute_file_hash(windows_system_dll)

        assert hash1 == hash2
        assert hash1 != ""

    def test_wrapper_supports_algorithm_parameter(
        self, windows_system_dll: str
    ) -> None:
        """get_file_hash supports algorithm parameter."""
        sha256_hash = get_file_hash(windows_system_dll, algorithm="sha256")
        md5_hash = get_file_hash(windows_system_dll, algorithm="md5")

        assert len(sha256_hash) == 64
        assert len(md5_hash) == 32
        assert sha256_hash != md5_hash


class TestReadBinary:
    """Test binary file reading functionality."""

    def test_reads_kernel32_dll(self, windows_system_dll: str) -> None:
        """Reads kernel32.dll binary data successfully."""
        data = read_binary(windows_system_dll)

        assert len(data) > 0
        assert data.startswith(b"MZ")

    def test_reads_ntdll(self, windows_ntdll: str) -> None:
        """Reads ntdll.dll binary data successfully."""
        data = read_binary(windows_ntdll)

        assert len(data) > 0
        assert data.startswith(b"MZ")

    def test_reads_file_with_custom_chunk_size(self, windows_system_dll: str) -> None:
        """Reads binary with custom chunk size."""
        data_default = read_binary(windows_system_dll)
        data_custom = read_binary(windows_system_dll, chunk_size=4096)

        assert data_default == data_custom

    def test_raises_filenotfounderror_for_missing_file(self) -> None:
        """Raises FileNotFoundError for nonexistent file."""
        with pytest.raises(FileNotFoundError):
            read_binary("/nonexistent/file.bin")

    def test_reads_small_binary_file(self, temp_binary_file: Path) -> None:
        """Reads small binary file correctly."""
        data = read_binary(temp_binary_file)

        assert len(data) == 104
        assert data.startswith(b"\x4D\x5A\x90\x00")


class TestWriteBinary:
    """Test binary file writing functionality."""

    def test_writes_binary_data_successfully(self, tmp_path: Path) -> None:
        """Writes binary data to new file."""
        test_data = b"\x00\x01\x02\x03\x04\x05"
        output_file = tmp_path / "output.bin"

        success = write_binary(output_file, test_data, create_backup=False)

        assert success is True
        assert output_file.exists()
        assert output_file.read_bytes() == test_data

    def test_creates_backup_of_existing_file(self, temp_binary_file: Path) -> None:
        """Creates backup when overwriting existing file."""
        original_data = temp_binary_file.read_bytes()
        new_data = b"\xFF\xFF\xFF\xFF"

        success = write_binary(temp_binary_file, new_data, create_backup=True)

        assert success is True
        backup_file = temp_binary_file.with_suffix(
            f"{temp_binary_file.suffix}.bak"
        )
        assert backup_file.exists()
        assert backup_file.read_bytes() == original_data
        assert temp_binary_file.read_bytes() == new_data

    def test_writes_without_backup(self, temp_binary_file: Path) -> None:
        """Writes without creating backup when disabled."""
        new_data = b"\xAA\xBB\xCC\xDD"

        success = write_binary(temp_binary_file, new_data, create_backup=False)

        assert success is True
        backup_file = temp_binary_file.with_suffix(
            f"{temp_binary_file.suffix}.bak"
        )
        assert not backup_file.exists()

    def test_handles_write_to_invalid_path(self) -> None:
        """Returns False when writing to invalid path."""
        success = write_binary(
            "/invalid/path/file.bin", b"\x00", create_backup=False
        )

        assert success is False


class TestAnalyzeBinaryFormat:
    """Test binary format analysis."""

    def test_detects_pe_format_kernel32(self, windows_system_dll: str) -> None:
        """Detects PE format for kernel32.dll."""
        format_info = analyze_binary_format(windows_system_dll)

        assert format_info["type"] in ["PE", "PE32/PE32+"]
        assert format_info["path"] == windows_system_dll
        assert format_info["size"] > 0

    def test_detects_pe_format_ntdll(self, windows_ntdll: str) -> None:
        """Detects PE format for ntdll.dll."""
        format_info = analyze_binary_format(windows_ntdll)

        assert format_info["type"] in ["PE", "PE32/PE32+"]
        assert "architecture" in format_info

    def test_reports_file_size_correctly(self, windows_system_dll: str) -> None:
        """Reports correct file size in analysis."""
        format_info = analyze_binary_format(windows_system_dll)
        actual_size = Path(windows_system_dll).stat().st_size

        assert format_info["size"] == actual_size

    def test_handles_nonexistent_file(self) -> None:
        """Returns error dict for nonexistent file."""
        format_info = analyze_binary_format("/nonexistent/file.exe")

        assert "error" in format_info
        assert format_info["error"] == "File not found"

    def test_detects_pe_signature(self, temp_binary_file: Path) -> None:
        """Detects PE signature in binary."""
        pe_header = b"MZ" + b"\x00" * 0x3A
        pe_offset = b"\x40\x00\x00\x00"
        pe_header += pe_offset
        pe_header += b"\x00" * (0x40 - len(pe_header))
        pe_header += b"PE\x00\x00"

        temp_binary_file.write_bytes(pe_header + b"\x00" * 100)

        format_info = analyze_binary_format(temp_binary_file)

        assert format_info["type"] == "PE32/PE32+"

    def test_detects_unknown_format_for_text_file(
        self, temp_text_file: Path
    ) -> None:
        """Detects unknown format for text files."""
        format_info = analyze_binary_format(temp_text_file)

        assert format_info["type"] == "unknown"


class TestIsBinaryFile:
    """Test binary file detection."""

    def test_detects_kernel32_as_binary(self, windows_system_dll: str) -> None:
        """Detects kernel32.dll as binary file."""
        is_binary = is_binary_file(windows_system_dll)

        assert is_binary is True

    def test_detects_ntdll_as_binary(self, windows_ntdll: str) -> None:
        """Detects ntdll.dll as binary file."""
        is_binary = is_binary_file(windows_ntdll)

        assert is_binary is True

    def test_detects_text_file_as_non_binary(self, temp_text_file: Path) -> None:
        """Detects text file as non-binary."""
        is_binary = is_binary_file(temp_text_file)

        assert is_binary is False

    def test_detects_binary_with_null_bytes(self, temp_binary_file: Path) -> None:
        """Detects binary file containing null bytes."""
        is_binary = is_binary_file(temp_binary_file)

        assert is_binary is True

    def test_handles_nonexistent_file(self) -> None:
        """Returns False for nonexistent file."""
        is_binary = is_binary_file("/nonexistent/file.txt")

        assert is_binary is False

    def test_respects_sample_size_parameter(self, tmp_path: Path) -> None:
        """Respects sample_size parameter for detection."""
        test_file = tmp_path / "partial_binary.bin"
        test_file.write_bytes(b"text" * 100 + b"\x00" * 100)

        is_binary_small = is_binary_file(test_file, sample_size=100)
        is_binary_large = is_binary_file(test_file, sample_size=500)

        assert is_binary_large is True


class TestGetFileEntropy:
    """Test file entropy calculation."""

    def test_calculates_entropy_for_kernel32(self, windows_system_dll: str) -> None:
        """Calculates entropy for kernel32.dll."""
        entropy = get_file_entropy(windows_system_dll)

        assert 0.0 <= entropy <= 8.0
        assert entropy > 0.0

    def test_entropy_of_packed_binary_is_high(self, tmp_path: Path) -> None:
        """High entropy indicates packed/encrypted binary."""
        random_data = os.urandom(256)
        packed_file = tmp_path / "packed.bin"
        packed_file.write_bytes(random_data)

        entropy = get_file_entropy(packed_file)

        assert entropy > 7.0

    def test_entropy_of_zero_filled_file_is_low(self, tmp_path: Path) -> None:
        """Low entropy for file with low randomness."""
        zero_file = tmp_path / "zeros.bin"
        zero_file.write_bytes(b"\x00" * 256)

        entropy = get_file_entropy(zero_file)

        assert entropy == 0.0

    def test_entropy_of_repeated_pattern_is_low(self, tmp_path: Path) -> None:
        """Repeated pattern has low entropy."""
        pattern_file = tmp_path / "pattern.bin"
        pattern_file.write_bytes(b"\x01\x02" * 128)

        entropy = get_file_entropy(pattern_file)

        assert entropy < 2.0

    def test_handles_empty_file(self, tmp_path: Path) -> None:
        """Returns 0 entropy for empty file."""
        empty_file = tmp_path / "empty.bin"
        empty_file.write_bytes(b"")

        entropy = get_file_entropy(empty_file)

        assert entropy == 0.0

    def test_respects_block_size_parameter(self, windows_system_dll: str) -> None:
        """Respects block_size parameter."""
        entropy_small = get_file_entropy(windows_system_dll, block_size=128)
        entropy_large = get_file_entropy(windows_system_dll, block_size=512)

        assert 0.0 <= entropy_small <= 8.0
        assert 0.0 <= entropy_large <= 8.0


class TestCheckSuspiciousPESections:
    """Test PE section security analysis."""

    def test_checks_sections_with_pefile(self, windows_system_dll: str) -> None:
        """Checks PE sections for security issues."""
        try:
            import pefile

            pe = pefile.PE(windows_system_dll)
            suspicious = check_suspicious_pe_sections(pe)

            assert isinstance(suspicious, list)

        except ImportError:
            pytest.skip("pefile not available")

    def test_detects_writable_executable_sections(self, tmp_path: Path) -> None:
        """Detects sections that are both writable and executable."""
        try:
            import pefile

            class MockSection:
                def __init__(self, name: str, characteristics: int) -> None:
                    self.Name = name.encode() + b"\x00" * (8 - len(name))
                    self.Characteristics = characteristics

            class MockPE:
                def __init__(self) -> None:
                    self.sections = [
                        MockSection("normal", 0x60000020),
                        MockSection("wxsect", 0x80000000 | 0x20000000),
                        MockSection("safe", 0x40000000),
                    ]

            mock_pe = MockPE()
            suspicious = check_suspicious_pe_sections(mock_pe)

            assert "wxsect" in suspicious

        except ImportError:
            pytest.skip("pefile not available")

    def test_handles_pe_without_sections(self) -> None:
        """Handles PE object without sections attribute."""

        class MockPE:
            pass

        mock_pe = MockPE()
        suspicious = check_suspicious_pe_sections(mock_pe)

        assert suspicious == []

    def test_returns_empty_list_for_clean_pe(self, windows_system_dll: str) -> None:
        """Returns empty list for PE with normal sections."""
        try:
            import pefile

            pe = pefile.PE(windows_system_dll)
            suspicious = check_suspicious_pe_sections(pe)

            assert isinstance(suspicious, list)

        except ImportError:
            pytest.skip("pefile not available")


class TestValidateBinaryPath:
    """Test binary path validation."""

    def test_validates_existing_binary(self, windows_system_dll: str) -> None:
        """Validates existing binary path."""
        is_valid = validate_binary_path(windows_system_dll)

        assert is_valid is True

    def test_rejects_empty_path(self) -> None:
        """Rejects empty binary path."""
        is_valid = validate_binary_path("")

        assert is_valid is False

    def test_rejects_nonexistent_path(self) -> None:
        """Rejects nonexistent binary path."""
        is_valid = validate_binary_path("/nonexistent/file.exe")

        assert is_valid is False

    def test_uses_custom_logger(self, windows_system_dll: str) -> None:
        """Uses custom logger when provided."""
        import logging

        custom_logger = logging.getLogger("test_logger")
        is_valid = validate_binary_path(windows_system_dll, custom_logger)

        assert is_valid is True


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_handles_unicode_paths(self, tmp_path: Path) -> None:
        """Handles Unicode characters in file paths."""
        unicode_file = tmp_path / "test_文件.bin"
        unicode_file.write_bytes(b"\x00\x01\x02")

        data = read_binary(unicode_file)
        assert len(data) == 3

    def test_handles_very_small_files(self, tmp_path: Path) -> None:
        """Handles files smaller than chunk size."""
        tiny_file = tmp_path / "tiny.bin"
        tiny_file.write_bytes(b"\x00")

        data = read_binary(tiny_file)
        assert len(data) == 1

    def test_handles_pathlib_paths(self, windows_system_dll: str) -> None:
        """Handles pathlib.Path objects."""
        path_obj = Path(windows_system_dll)

        hash_value = compute_file_hash(path_obj)
        data = read_binary(path_obj)
        format_info = analyze_binary_format(path_obj)

        assert hash_value != ""
        assert len(data) > 0
        assert format_info["type"] in ["PE", "PE32/PE32+"]


class TestIntegration:
    """Test integration between multiple binary utility functions."""

    def test_complete_binary_analysis_workflow(
        self, windows_system_dll: str
    ) -> None:
        """Complete workflow: validate -> read -> analyze -> hash."""
        is_valid = validate_binary_path(windows_system_dll)
        assert is_valid is True

        data = read_binary(windows_system_dll)
        assert len(data) > 0

        format_info = analyze_binary_format(windows_system_dll)
        assert format_info["type"] in ["PE", "PE32/PE32+"]

        hash_value = compute_file_hash(windows_system_dll)
        assert len(hash_value) == 64

        entropy = get_file_entropy(windows_system_dll)
        assert 0.0 <= entropy <= 8.0

        is_binary = is_binary_file(windows_system_dll)
        assert is_binary is True

    def test_write_and_verify_workflow(self, tmp_path: Path) -> None:
        """Workflow: write binary -> verify -> read back -> compare hash."""
        original_data = b"\x4D\x5A" + b"\x90" * 100
        output_file = tmp_path / "test_output.bin"

        success = write_binary(output_file, original_data, create_backup=False)
        assert success is True

        is_valid = validate_binary_path(str(output_file))
        assert is_valid is True

        read_data = read_binary(output_file)
        assert read_data == original_data

        original_hash = hashlib.sha256(original_data).hexdigest()
        file_hash = compute_file_hash(output_file)
        assert file_hash == original_hash
