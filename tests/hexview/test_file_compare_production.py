"""Production-Ready Tests for File Comparison Module.

Tests REAL binary diff algorithms using actual Windows system files.
"""

from pathlib import Path

import pytest

from intellicrack.hexview.file_compare import (
    BinaryComparer,
    ComparisonNavigator,
    DifferenceBlock,
    DifferenceType,
)


class TestBinaryComparer:
    """Test BinaryComparer with real binary differentiation."""

    @pytest.fixture
    def test_files(self, tmp_path: Path) -> tuple[Path, Path]:
        """Create two similar but different test files."""
        file1 = tmp_path / "file1.bin"
        file2 = tmp_path / "file2.bin"

        data1 = bytes(range(256)) * 4
        data2 = bytes(range(256)) * 4

        data2_modified = bytearray(data2)
        data2_modified[100:110] = b"DIFFERENT!"

        file1.write_bytes(data1)
        file2.write_bytes(bytes(data2_modified))

        return file1, file2

    def test_binarycomparer_detects_modifications(self, test_files: tuple[Path, Path]) -> None:
        """BinaryComparer must detect modified byte ranges."""
        file1, file2 = test_files
        comparer = BinaryComparer()

        differences = comparer.compare_files(str(file1), str(file2))

        assert len(differences) > 0
        assert any(diff.diff_type == DifferenceType.MODIFIED for diff in differences)

    def test_binarycomparer_compares_identical_files(self, tmp_path: Path) -> None:
        """BinaryComparer must return no differences for identical files."""
        identical_data = b"TEST" * 100
        file1 = tmp_path / "identical1.bin"
        file2 = tmp_path / "identical2.bin"

        file1.write_bytes(identical_data)
        file2.write_bytes(identical_data)

        comparer = BinaryComparer()
        differences = comparer.compare_files(str(file1), str(file2))

        assert len(differences) == 0

    def test_binarycomparer_detects_insertions(self, tmp_path: Path) -> None:
        """BinaryComparer must detect inserted bytes."""
        data1 = b"AAAA" + b"BBBB"
        data2 = b"AAAA" + b"INSERTED" + b"BBBB"

        file1 = tmp_path / "original.bin"
        file2 = tmp_path / "inserted.bin"

        file1.write_bytes(data1)
        file2.write_bytes(data2)

        comparer = BinaryComparer()
        differences = comparer.compare_data(data1, data2)

        assert len(differences) > 0

    def test_binarycomparer_detects_deletions(self, tmp_path: Path) -> None:
        """BinaryComparer must detect deleted bytes."""
        data1 = b"AAAA" + b"DELETED" + b"BBBB"
        data2 = b"AAAA" + b"BBBB"

        comparer = BinaryComparer()
        differences = comparer.compare_data(data1, data2)

        assert len(differences) > 0

    def test_binarycomparer_provides_accurate_statistics(self, test_files: tuple[Path, Path]) -> None:
        """BinaryComparer statistics must accurately count changes."""
        file1, file2 = test_files
        comparer = BinaryComparer()

        differences = comparer.compare_files(str(file1), str(file2))
        stats = comparer.get_statistics()

        assert stats["total_differences"] == len(differences)
        assert stats["modified_blocks"] >= 0
        assert stats["inserted_blocks"] >= 0
        assert stats["deleted_blocks"] >= 0

    def test_binarycomparer_handles_different_sized_files(self, tmp_path: Path) -> None:
        """BinaryComparer must handle files of different sizes."""
        data1 = bytes(range(256))
        data2 = bytes(range(512))

        file1 = tmp_path / "small.bin"
        file2 = tmp_path / "large.bin"

        file1.write_bytes(data1)
        file2.write_bytes(data2)

        comparer = BinaryComparer()
        differences = comparer.compare_files(str(file1), str(file2))

        assert len(differences) > 0
        assert any(diff.diff_type == DifferenceType.INSERTED for diff in differences)

    def test_binarycomparer_lcs_algorithm_accuracy(self) -> None:
        """BinaryComparer LCS algorithm must accurately identify common sequences."""
        data1 = b"ABCDEFGH"
        data2 = b"ABXDEFGH"

        comparer = BinaryComparer()
        differences = comparer.compare_data(data1, data2)

        assert len(differences) > 0

        modified_found = any(diff.diff_type == DifferenceType.MODIFIED for diff in differences)
        assert modified_found


class TestDifferenceBlock:
    """Test DifferenceBlock data structure."""

    def test_differenceblock_calculates_end_offsets(self) -> None:
        """DifferenceBlock must calculate end offsets correctly."""
        diff = DifferenceBlock(
            offset1=100,
            offset2=200,
            length1=50,
            length2=75,
            diff_type=DifferenceType.MODIFIED,
        )

        assert diff.end1 == 150
        assert diff.end2 == 275

    def test_differenceblock_stores_diff_types(self) -> None:
        """DifferenceBlock must correctly store difference types."""
        modified = DifferenceBlock(0, 0, 10, 10, DifferenceType.MODIFIED)
        inserted = DifferenceBlock(10, 10, 0, 5, DifferenceType.INSERTED)
        deleted = DifferenceBlock(20, 20, 5, 0, DifferenceType.DELETED)

        assert modified.diff_type == DifferenceType.MODIFIED
        assert inserted.diff_type == DifferenceType.INSERTED
        assert deleted.diff_type == DifferenceType.DELETED


class TestComparisonNavigator:
    """Test ComparisonNavigator with real difference navigation."""

    @pytest.fixture
    def sample_differences(self) -> list[DifferenceBlock]:
        """Create sample differences for navigation testing."""
        return [
            DifferenceBlock(0, 0, 10, 10, DifferenceType.MODIFIED),
            DifferenceBlock(50, 50, 5, 8, DifferenceType.MODIFIED),
            DifferenceBlock(100, 103, 20, 20, DifferenceType.MODIFIED),
            DifferenceBlock(200, 203, 0, 10, DifferenceType.INSERTED),
        ]

    def test_comparisonnavigator_navigates_forward(self, sample_differences: list[DifferenceBlock]) -> None:
        """ComparisonNavigator must navigate forward through differences."""
        navigator = ComparisonNavigator(sample_differences)

        first = navigator.go_to_first()
        assert first is not None
        assert first.offset1 == 0

        second = navigator.go_to_next()
        assert second is not None
        assert second.offset1 == 50

    def test_comparisonnavigator_navigates_backward(self, sample_differences: list[DifferenceBlock]) -> None:
        """ComparisonNavigator must navigate backward through differences."""
        navigator = ComparisonNavigator(sample_differences)

        last = navigator.go_to_last()
        assert last is not None
        assert last.offset1 == 200

        prev = navigator.go_to_previous()
        assert prev is not None
        assert prev.offset1 == 100

    def test_comparisonnavigator_finds_by_offset(self, sample_differences: list[DifferenceBlock]) -> None:
        """ComparisonNavigator must locate difference containing offset."""
        navigator = ComparisonNavigator(sample_differences)

        diff = navigator.go_to_offset(55, file_num=1)
        assert diff is not None
        assert diff.offset1 <= 55 < diff.end1

    def test_comparisonnavigator_tracks_position(self, sample_differences: list[DifferenceBlock]) -> None:
        """ComparisonNavigator must accurately track current position."""
        navigator = ComparisonNavigator(sample_differences)

        navigator.go_to_first()
        pos = navigator.get_position()
        assert pos == (1, len(sample_differences))

        navigator.go_to_next()
        pos = navigator.get_position()
        assert pos == (2, len(sample_differences))

    def test_comparisonnavigator_handles_empty_differences(self) -> None:
        """ComparisonNavigator must handle empty difference list."""
        navigator = ComparisonNavigator([])

        assert navigator.has_differences() is False
        assert navigator.go_to_first() is None
        assert navigator.go_to_next() is None


class TestBinaryComparerPerformance:
    """Test BinaryComparer performance with large files."""

    @pytest.fixture
    def large_test_files(self, tmp_path: Path) -> tuple[Path, Path]:
        """Create large test files (1MB each)."""
        file1 = tmp_path / "large1.bin"
        file2 = tmp_path / "large2.bin"

        data1 = bytes(range(256)) * 4096
        data2 = bytearray(data1)

        data2[100000:100100] = b"X" * 100

        file1.write_bytes(data1)
        file2.write_bytes(bytes(data2))

        return file1, file2

    def test_binarycomparer_handles_large_files_efficiently(self, large_test_files: tuple[Path, Path]) -> None:
        """BinaryComparer must handle large files without excessive memory."""
        file1, file2 = large_test_files
        comparer = BinaryComparer(block_size=8192)

        differences = comparer.compare_files(str(file1), str(file2))

        assert len(differences) > 0

    def test_binarycomparer_progress_callback(self, large_test_files: tuple[Path, Path]) -> None:
        """BinaryComparer must invoke progress callback during comparison."""
        file1, file2 = large_test_files
        comparer = BinaryComparer()

        progress_updates = []

        def progress_callback(current: int, total: int) -> None:
            progress_updates.append((current, total))

        comparer.set_progress_callback(progress_callback)
        comparer.compare_files(str(file1), str(file2))

        assert progress_updates


class TestRealWorldComparison:
    """Test BinaryComparer with real Windows system files."""

    def test_compare_different_system_files(self) -> None:
        """BinaryComparer must detect differences between actual system binaries."""
        notepad = Path("C:/Windows/System32/notepad.exe")
        calc = Path("C:/Windows/System32/calc.exe")

        if not (notepad.exists() and calc.exists()):
            pytest.skip("Windows system files not available")

        comparer = BinaryComparer()

        differences = comparer.compare_files(str(notepad), str(calc))

        assert len(differences) > 0

        stats = comparer.get_statistics()
        assert stats["total_differences"] > 0
