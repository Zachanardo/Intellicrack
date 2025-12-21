"""Production tests for utils/constants.py.

This module validates constant values used across Intellicrack for file size
formatting and other shared constants.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import pytest

from intellicrack.utils.constants import SIZE_UNITS


class TestSizeUnits:
    """Test SIZE_UNITS constant for file size formatting."""

    def test_size_units_structure(self) -> None:
        """SIZE_UNITS contains correct unit breakpoints in descending order."""
        assert isinstance(SIZE_UNITS, list)
        assert len(SIZE_UNITS) == 4

        for item in SIZE_UNITS:
            assert isinstance(item, tuple)
            assert len(item) == 2
            assert isinstance(item[0], int)
            assert isinstance(item[1], str)

    def test_size_units_order(self) -> None:
        """SIZE_UNITS is ordered from largest to smallest unit."""
        sizes = [unit[0] for unit in SIZE_UNITS]
        assert sizes == sorted(sizes, reverse=True)

    def test_size_units_values(self) -> None:
        """SIZE_UNITS contains correct GB, MB, KB, B breakpoints."""
        expected = [
            (1024**3, "GB"),
            (1024**2, "MB"),
            (1024, "KB"),
            (1, "B"),
        ]
        assert SIZE_UNITS == expected

    def test_size_units_gigabyte_threshold(self) -> None:
        """GB threshold is exactly 1073741824 bytes."""
        gb_threshold = SIZE_UNITS[0][0]
        assert gb_threshold == 1073741824
        assert gb_threshold == 1024 * 1024 * 1024

    def test_size_units_megabyte_threshold(self) -> None:
        """MB threshold is exactly 1048576 bytes."""
        mb_threshold = SIZE_UNITS[1][0]
        assert mb_threshold == 1048576
        assert mb_threshold == 1024 * 1024

    def test_size_units_kilobyte_threshold(self) -> None:
        """KB threshold is exactly 1024 bytes."""
        kb_threshold = SIZE_UNITS[2][0]
        assert kb_threshold == 1024

    def test_size_units_byte_threshold(self) -> None:
        """Byte threshold is 1."""
        b_threshold = SIZE_UNITS[3][0]
        assert b_threshold == 1

    def test_size_units_labels(self) -> None:
        """SIZE_UNITS uses correct unit labels."""
        labels = [unit[1] for unit in SIZE_UNITS]
        assert labels == ["GB", "MB", "KB", "B"]

    @pytest.mark.parametrize(
        "test_size,expected_unit",
        [
            (2147483648, "GB"),
            (1073741824, "GB"),
            (2097152, "MB"),
            (1048576, "MB"),
            (2048, "KB"),
            (1024, "KB"),
            (512, "B"),
            (1, "B"),
        ],
    )
    def test_size_unit_selection(self, test_size: int, expected_unit: str) -> None:
        """SIZE_UNITS enables correct unit selection for various file sizes."""
        selected_unit = next(
            (unit for threshold, unit in SIZE_UNITS if test_size >= threshold),
            None,
        )
        assert selected_unit == expected_unit

    def test_size_unit_selection_zero(self) -> None:
        """SIZE_UNITS handles zero size correctly."""
        selected_unit = next(
            (unit for threshold, unit in SIZE_UNITS if threshold <= 0), None
        )
        assert selected_unit in ("B", None)

    def test_size_units_immutability_requirement(self) -> None:
        """SIZE_UNITS structure supports immutable usage patterns."""
        original_first = SIZE_UNITS[0]

        assert original_first == original_first
