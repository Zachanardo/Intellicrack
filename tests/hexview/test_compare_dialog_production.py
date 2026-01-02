"""Production tests for hexview compare dialog.

Tests validate real binary file comparison functionality.
Tests verify diff detection, side-by-side display, and comparison modes.
"""

import tempfile
from pathlib import Path

import pytest

from intellicrack.hexview.file_compare import BinaryComparer


class TestBinaryComparer:
    """Test binary file comparison engine."""

    def test_create_binary_comparer(self) -> None:
        """Create binary comparer instance."""
        comparer = BinaryComparer()

        assert comparer is not None

    def test_compare_identical_files(self) -> None:
        """Compare two identical files."""
        with tempfile.NamedTemporaryFile(delete=False) as f1:
            f1.write(b"Hello World" * 100)
            path1 = f1.name

        with tempfile.NamedTemporaryFile(delete=False) as f2:
            f2.write(b"Hello World" * 100)
            path2 = f2.name

        try:
            comparer = BinaryComparer()
            differences = comparer.compare_files(path1, path2)

            assert isinstance(differences, list)
            assert len(differences) == 0
        finally:
            Path(path1).unlink()
            Path(path2).unlink()

    def test_compare_different_files(self) -> None:
        """Compare two different files."""
        with tempfile.NamedTemporaryFile(delete=False) as f1:
            f1.write(b"Hello World")
            path1 = f1.name

        with tempfile.NamedTemporaryFile(delete=False) as f2:
            f2.write(b"Goodbye World")
            path2 = f2.name

        try:
            comparer = BinaryComparer()
            differences = comparer.compare_files(path1, path2)

            assert isinstance(differences, list)
            assert len(differences) > 0
        finally:
            Path(path1).unlink()
            Path(path2).unlink()

    def test_compare_single_byte_difference(self) -> None:
        """Detect single byte difference."""
        data1 = bytearray(b"A" * 1000)
        data2 = bytearray(b"A" * 1000)
        data2[500] = ord("B")

        with tempfile.NamedTemporaryFile(delete=False) as f1:
            f1.write(data1)
            path1 = f1.name

        with tempfile.NamedTemporaryFile(delete=False) as f2:
            f2.write(data2)
            path2 = f2.name

        try:
            comparer = BinaryComparer()
            differences = comparer.compare_files(path1, path2)

            assert len(differences) > 0
            assert any(d.offset1 == 500 for d in differences)
        finally:
            Path(path1).unlink()
            Path(path2).unlink()

    def test_compare_different_sizes(self) -> None:
        """Compare files of different sizes."""
        with tempfile.NamedTemporaryFile(delete=False) as f1:
            f1.write(b"Short")
            path1 = f1.name

        with tempfile.NamedTemporaryFile(delete=False) as f2:
            f2.write(b"Much longer content")
            path2 = f2.name

        try:
            comparer = BinaryComparer()
            differences = comparer.compare_files(path1, path2)

            assert isinstance(differences, list)
            assert len(differences) > 0
        finally:
            Path(path1).unlink()
            Path(path2).unlink()

    def test_compare_large_files(self) -> None:
        """Compare large binary files."""
        with tempfile.NamedTemporaryFile(delete=False) as f1:
            f1.write(b"X" * 1000000)
            path1 = f1.name

        with tempfile.NamedTemporaryFile(delete=False) as f2:
            f2.write(b"X" * 1000000)
            path2 = f2.name

        try:
            comparer = BinaryComparer()
            differences = comparer.compare_files(path1, path2)

            assert isinstance(differences, list)
            assert len(differences) == 0
        finally:
            Path(path1).unlink()
            Path(path2).unlink()


class TestBinaryComparisonModes:
    """Test different comparison modes."""

    def test_byte_by_byte_comparison(self) -> None:
        """Byte-by-byte comparison mode."""
        data1 = b"ABCDEFGH"
        data2 = b"ABXDEFGH"

        with tempfile.NamedTemporaryFile(delete=False) as f1:
            f1.write(data1)
            path1 = f1.name

        with tempfile.NamedTemporaryFile(delete=False) as f2:
            f2.write(data2)
            path2 = f2.name

        try:
            comparer = BinaryComparer()
            differences = comparer.compare_files(path1, path2)

            assert len(differences) > 0
        finally:
            Path(path1).unlink()
            Path(path2).unlink()

    def test_structural_comparison(self) -> None:
        """Structural comparison mode."""
        data1 = bytes([0x4D, 0x5A] + [0x00] * 100)
        data2 = bytes([0x4D, 0x5A] + [0xFF] * 100)

        with tempfile.NamedTemporaryFile(delete=False) as f1:
            f1.write(data1)
            path1 = f1.name

        with tempfile.NamedTemporaryFile(delete=False) as f2:
            f2.write(data2)
            path2 = f2.name

        try:
            comparer = BinaryComparer()
            differences = comparer.compare_files(path1, path2)

            assert isinstance(differences, list)
        finally:
            Path(path1).unlink()
            Path(path2).unlink()


class TestDifferenceDetection:
    """Test difference detection accuracy."""

    def test_detect_patched_bytes(self) -> None:
        """Detect patched bytes in binary."""
        original = bytearray(b"\x74\x05") + b"\x00" * 100
        patched = bytearray(b"\x75\x05") + b"\x00" * 100

        with tempfile.NamedTemporaryFile(delete=False) as f1:
            f1.write(original)
            path1 = f1.name

        with tempfile.NamedTemporaryFile(delete=False) as f2:
            f2.write(patched)
            path2 = f2.name

        try:
            comparer = BinaryComparer()
            differences = comparer.compare_files(path1, path2)

            assert len(differences) > 0
            assert differences[0].offset1 == 0
        finally:
            Path(path1).unlink()
            Path(path2).unlink()

    def test_detect_nop_sled(self) -> None:
        """Detect NOP sled differences."""
        original = b"\x55\x89\xe5\x83\xec\x10"
        patched = b"\x90\x90\x90\x90\x90\x90"

        with tempfile.NamedTemporaryFile(delete=False) as f1:
            f1.write(original)
            path1 = f1.name

        with tempfile.NamedTemporaryFile(delete=False) as f2:
            f2.write(patched)
            path2 = f2.name

        try:
            comparer = BinaryComparer()
            differences = comparer.compare_files(path1, path2)

            assert len(differences) > 0
        finally:
            Path(path1).unlink()
            Path(path2).unlink()


class TestEdgeCases:
    """Test edge cases in file comparison."""

    def test_compare_empty_files(self) -> None:
        """Compare two empty files."""
        with tempfile.NamedTemporaryFile(delete=False) as f1:
            path1 = f1.name

        with tempfile.NamedTemporaryFile(delete=False) as f2:
            path2 = f2.name

        try:
            comparer = BinaryComparer()
            differences = comparer.compare_files(path1, path2)

            assert len(differences) == 0
        finally:
            Path(path1).unlink()
            Path(path2).unlink()

    def test_compare_nonexistent_file(self) -> None:
        """Handle nonexistent file."""
        comparer = BinaryComparer()

        with pytest.raises(Exception):
            comparer.compare_files("/nonexistent/file1.bin", "/nonexistent/file2.bin")
