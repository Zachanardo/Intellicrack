"""File Comparison Module for Hex Viewer.

This module provides binary file comparison functionality with
difference highlighting and synchronization support.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import os
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Tuple

from ..utils.logger import get_logger

logger = get_logger(__name__)


class DifferenceType(Enum):
    """Types of differences between files."""

    MODIFIED = "modified"
    INSERTED = "inserted"
    DELETED = "deleted"


@dataclass
class DifferenceBlock:
    """Represents a block of differences between two files."""

    offset1: int  # Offset in file 1
    offset2: int  # Offset in file 2
    length1: int  # Length of block in file 1
    length2: int  # Length of block in file 2
    diff_type: DifferenceType

    @property
    def end1(self) -> int:
        """End offset in file 1."""
        return self.offset1 + self.length1

    @property
    def end2(self) -> int:
        """End offset in file 2."""
        return self.offset2 + self.length2


class BinaryComparer:
    """Compares two binary files and identifies differences."""

    def __init__(self, block_size: int = 4096):
        """Initialize the comparer.

        Args:
            block_size: Size of blocks to read for comparison

        """
        self.block_size = block_size
        self.differences = []
        self.progress_callback = None

    def set_progress_callback(self, callback):
        """Set callback for progress updates.

        Args:
            callback: Function that takes (current, total) parameters

        """
        self.progress_callback = callback

    def compare_files(self, file1_path: str, file2_path: str) -> List[DifferenceBlock]:
        """Compare two files and return list of differences.

        Args:
            file1_path: Path to first file
            file2_path: Path to second file

        Returns:
            List of DifferenceBlock objects

        """
        self.differences = []

        try:
            file1_size = os.path.getsize(file1_path)
            file2_size = os.path.getsize(file2_path)

            with open(file1_path, "rb") as f1, open(file2_path, "rb") as f2:
                self._compare_streams(f1, f2, file1_size, file2_size)

        except Exception as e:
            logger.error(f"Error comparing files: {e}")
            raise

        return self.differences

    def compare_data(self, data1: bytes, data2: bytes) -> List[DifferenceBlock]:
        """Compare two byte arrays and return list of differences.

        Args:
            data1: First byte array
            data2: Second byte array

        Returns:
            List of DifferenceBlock objects

        """
        self.differences = []

        # Use LCS (Longest Common Subsequence) based diff algorithm
        self._find_differences_lcs(data1, data2)

        return self.differences

    def _compare_streams(self, f1, f2, size1: int, size2: int):
        """Compare two file streams block by block.

        Args:
            f1: First file stream
            f2: Second file stream
            size1: Size of first file
            size2: Size of second file

        """
        offset = 0
        max_size = max(size1, size2)
        total_blocks = (max_size + self.block_size - 1) // self.block_size
        current_block = 0

        current_diff = None

        while offset < max_size:
            # Read blocks
            block1 = f1.read(self.block_size) if offset < size1 else b""
            block2 = f2.read(self.block_size) if offset < size2 else b""

            # Compare blocks
            if block1 == block2:
                # Blocks are identical, close any open difference
                if current_diff:
                    self.differences.append(current_diff)
                    current_diff = None
            else:
                # Blocks differ
                if current_diff:
                    # Extend existing difference
                    if block1:
                        current_diff.length1 += len(block1)
                    if block2:
                        current_diff.length2 += len(block2)
                else:
                    # Start new difference
                    diff_type = self._determine_diff_type(block1, block2)
                    current_diff = DifferenceBlock(
                        offset1=offset, offset2=offset, length1=len(block1), length2=len(block2), diff_type=diff_type
                    )

            offset += self.block_size
            current_block += 1

            # Update progress
            if self.progress_callback:
                self.progress_callback(current_block, total_blocks)

        # Close any remaining difference
        if current_diff:
            self.differences.append(current_diff)

    def _determine_diff_type(self, block1: bytes, block2: bytes) -> DifferenceType:
        """Determine the type of difference between two blocks.

        Args:
            block1: First block
            block2: Second block

        Returns:
            Type of difference

        """
        if not block1:
            return DifferenceType.INSERTED
        elif not block2:
            return DifferenceType.DELETED
        else:
            return DifferenceType.MODIFIED

    def _find_differences_lcs(self, data1: bytes, data2: bytes):
        """Find differences using LCS algorithm for smaller data.

        Args:
            data1: First data
            data2: Second data

        """
        # For large files, fall back to block comparison
        if len(data1) > 10000 or len(data2) > 10000:
            self._find_differences_simple(data1, data2)
            return

        # Build LCS table
        m, n = len(data1), len(data2)
        lcs = [[0] * (n + 1) for _ in range(m + 1)]

        for i in range(1, m + 1):
            for j in range(1, n + 1):
                if data1[i - 1] == data2[j - 1]:
                    lcs[i][j] = lcs[i - 1][j - 1] + 1
                else:
                    lcs[i][j] = max(lcs[i - 1][j], lcs[i][j - 1])

        # Trace back to find differences
        self._trace_lcs(data1, data2, lcs)

    def _find_differences_simple(self, data1: bytes, data2: bytes):
        """Perform simple byte-by-byte comparison for finding differences.

        Args:
            data1: First data
            data2: Second data

        """
        i = 0
        j = 0
        current_diff = None

        while i < len(data1) or j < len(data2):
            if i >= len(data1):
                # Rest of data2 is inserted
                if current_diff and current_diff.diff_type == DifferenceType.INSERTED:
                    current_diff.length2 += len(data2) - j
                else:
                    if current_diff:
                        self.differences.append(current_diff)
                    current_diff = DifferenceBlock(
                        offset1=i, offset2=j, length1=0, length2=len(data2) - j, diff_type=DifferenceType.INSERTED
                    )
                break

            elif j >= len(data2):
                # Rest of data1 is deleted
                if current_diff and current_diff.diff_type == DifferenceType.DELETED:
                    current_diff.length1 += len(data1) - i
                else:
                    if current_diff:
                        self.differences.append(current_diff)
                    current_diff = DifferenceBlock(
                        offset1=i, offset2=j, length1=len(data1) - i, length2=0, diff_type=DifferenceType.DELETED
                    )
                break

            elif data1[i] == data2[j]:
                # Bytes match
                if current_diff:
                    self.differences.append(current_diff)
                    current_diff = None
                i += 1
                j += 1

            else:
                # Bytes differ
                if current_diff and current_diff.diff_type == DifferenceType.MODIFIED:
                    current_diff.length1 += 1
                    current_diff.length2 += 1
                else:
                    if current_diff:
                        self.differences.append(current_diff)
                    current_diff = DifferenceBlock(offset1=i, offset2=j, length1=1, length2=1, diff_type=DifferenceType.MODIFIED)
                i += 1
                j += 1

        if current_diff:
            self.differences.append(current_diff)

    def _trace_lcs(self, data1: bytes, data2: bytes, lcs):
        """Trace LCS table to find differences.

        Args:
            data1: First data
            data2: Second data
            lcs: LCS table

        """
        i, j = len(data1), len(data2)

        while i > 0 or j > 0:
            if i == 0:
                # Insertion in data2
                self.differences.insert(0, DifferenceBlock(offset1=0, offset2=0, length1=0, length2=j, diff_type=DifferenceType.INSERTED))
                break

            elif j == 0:
                # Deletion from data1
                self.differences.insert(0, DifferenceBlock(offset1=0, offset2=0, length1=i, length2=0, diff_type=DifferenceType.DELETED))
                break

            elif data1[i - 1] == data2[j - 1]:
                # Match, move diagonally
                i -= 1
                j -= 1

            elif lcs[i - 1][j] > lcs[i][j - 1]:
                # Deletion from data1
                start_i = i - 1
                while i > 1 and lcs[i - 1][j] == lcs[i - 2][j]:
                    i -= 1

                self.differences.insert(
                    0, DifferenceBlock(offset1=i - 1, offset2=j, length1=start_i - i + 1, length2=0, diff_type=DifferenceType.DELETED)
                )
                i -= 1

            else:
                # Insertion in data2
                start_j = j - 1
                while j > 1 and lcs[i][j - 1] == lcs[i][j - 2]:
                    j -= 1

                self.differences.insert(
                    0, DifferenceBlock(offset1=i, offset2=j - 1, length1=0, length2=start_j - j + 1, diff_type=DifferenceType.INSERTED)
                )
                j -= 1

        # Merge adjacent differences of the same type
        self._merge_adjacent_differences()

    def _merge_adjacent_differences(self):
        """Merge adjacent difference blocks of the same type."""
        if len(self.differences) <= 1:
            return

        merged = []
        current = self.differences[0]

        for diff in self.differences[1:]:
            # Check if adjacent and same type
            if current.end1 == diff.offset1 and current.end2 == diff.offset2 and current.diff_type == diff.diff_type:
                # Merge
                current.length1 += diff.length1
                current.length2 += diff.length2
            else:
                # Can't merge, save current and start new
                merged.append(current)
                current = diff

        merged.append(current)
        self.differences = merged

    def get_statistics(self) -> dict:
        """Get statistics about the comparison.

        Returns:
            Dictionary with comparison statistics

        """
        stats = {
            "total_differences": len(self.differences),
            "modified_blocks": 0,
            "inserted_blocks": 0,
            "deleted_blocks": 0,
            "modified_bytes": 0,
            "inserted_bytes": 0,
            "deleted_bytes": 0,
        }

        for diff in self.differences:
            if diff.diff_type == DifferenceType.MODIFIED:
                stats["modified_blocks"] += 1
                stats["modified_bytes"] += max(diff.length1, diff.length2)
            elif diff.diff_type == DifferenceType.INSERTED:
                stats["inserted_blocks"] += 1
                stats["inserted_bytes"] += diff.length2
            elif diff.diff_type == DifferenceType.DELETED:
                stats["deleted_blocks"] += 1
                stats["deleted_bytes"] += diff.length1

        return stats


class ComparisonNavigator:
    """Helps navigate through differences in compared files."""

    def __init__(self, differences: List[DifferenceBlock]):
        """Initialize the navigator.

        Args:
            differences: List of difference blocks

        """
        self.differences = differences
        self.current_index = -1

    def has_differences(self) -> bool:
        """Check if there are any differences.

        Returns:
            True if differences exist

        """
        return len(self.differences) > 0

    def go_to_first(self) -> Optional[DifferenceBlock]:
        """Go to the first difference.

        Returns:
            First difference block or None

        """
        if self.differences:
            self.current_index = 0
            return self.differences[0]
        return None

    def go_to_last(self) -> Optional[DifferenceBlock]:
        """Go to the last difference.

        Returns:
            Last difference block or None

        """
        if self.differences:
            self.current_index = len(self.differences) - 1
            return self.differences[self.current_index]
        return None

    def go_to_next(self) -> Optional[DifferenceBlock]:
        """Go to the next difference.

        Returns:
            Next difference block or None

        """
        if self.current_index < len(self.differences) - 1:
            self.current_index += 1
            return self.differences[self.current_index]
        return None

    def go_to_previous(self) -> Optional[DifferenceBlock]:
        """Go to the previous difference.

        Returns:
            Previous difference block or None

        """
        if self.current_index > 0:
            self.current_index -= 1
            return self.differences[self.current_index]
        return None

    def go_to_offset(self, offset: int, file_num: int = 1) -> Optional[DifferenceBlock]:
        """Go to the difference containing the specified offset.

        Args:
            offset: Offset to find
            file_num: Which file's offset to use (1 or 2)

        Returns:
            Difference block containing offset or None

        """
        for i, diff in enumerate(self.differences):
            if file_num == 1:
                if diff.offset1 <= offset < diff.end1:
                    self.current_index = i
                    return diff
            else:
                if diff.offset2 <= offset < diff.end2:
                    self.current_index = i
                    return diff
        return None

    def get_current(self) -> Optional[DifferenceBlock]:
        """Get the current difference.

        Returns:
            Current difference block or None

        """
        if 0 <= self.current_index < len(self.differences):
            return self.differences[self.current_index]
        return None

    def get_position(self) -> Tuple[int, int]:
        """Get current position in difference list.

        Returns:
            Tuple of (current_index + 1, total_differences)

        """
        return (self.current_index + 1, len(self.differences))
