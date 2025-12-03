"""Tests for can_merge_with merge compatibility in hex_commands.py.

This tests that the merge compatibility check properly uses the 'other'
command's properties (type, offset proximity) to determine if commands
can be merged.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    pass


class TestHexCommandMergeCompatibility:
    """Test suite for HexCommand merge compatibility checking."""

    def test_hex_command_imports(self) -> None:
        """Verify HexCommand classes can be imported."""
        from intellicrack.hexview.hex_commands import (
            HexCommand,
            OperationType,
            ReplaceCommand,
        )

        assert HexCommand is not None
        assert OperationType is not None
        assert ReplaceCommand is not None

    def test_same_type_adjacent_offsets_can_merge(self) -> None:
        """Test that commands of same type with adjacent offsets can merge."""
        from intellicrack.hexview.hex_commands import ReplaceCommand

        cmd1 = ReplaceCommand(offset=100, new_data=b"\x00\x01", old_data=b"\xFF\xFE")
        cmd2 = ReplaceCommand(offset=102, new_data=b"\x02\x03", old_data=b"\xFD\xFC")

        assert cmd1.can_merge_with(cmd2) is True

    def test_same_type_distant_offsets_cannot_merge(self) -> None:
        """Test that commands with distant offsets cannot merge."""
        from intellicrack.hexview.hex_commands import ReplaceCommand

        cmd1 = ReplaceCommand(offset=100, new_data=b"\x00", old_data=b"\xFF")
        cmd2 = ReplaceCommand(offset=200, new_data=b"\x01", old_data=b"\xFE")

        assert cmd1.can_merge_with(cmd2) is False

    def test_different_types_cannot_merge(self) -> None:
        """Test that commands of different types cannot merge."""
        from intellicrack.hexview.hex_commands import InsertCommand, ReplaceCommand

        replace_cmd = ReplaceCommand(offset=100, new_data=b"\x00", old_data=b"\xFF")
        insert_cmd = InsertCommand(offset=101, data=b"\x01")

        assert replace_cmd.can_merge_with(insert_cmd) is False

    def test_replace_commands_must_be_adjacent(self) -> None:
        """Test that ReplaceCommands can only merge when exactly adjacent."""
        from intellicrack.hexview.hex_commands import ReplaceCommand

        cmd1 = ReplaceCommand(offset=100, new_data=b"\x00", old_data=b"\xFF")
        cmd2_adjacent = ReplaceCommand(offset=101, new_data=b"\x01", old_data=b"\xFE")
        cmd2_gap = ReplaceCommand(offset=102, new_data=b"\x01", old_data=b"\xFE")

        assert cmd1.can_merge_with(cmd2_adjacent) is True
        assert cmd1.can_merge_with(cmd2_gap) is False

    def test_insert_commands_merge_compatibility(self) -> None:
        """Test merge compatibility for InsertCommand."""
        from intellicrack.hexview.hex_commands import InsertCommand

        cmd1 = InsertCommand(offset=100, data=b"\x00\x01\x02")
        cmd2 = InsertCommand(offset=103, data=b"\x03\x04\x05")

        assert cmd1.can_merge_with(cmd2) is True

    def test_delete_commands_merge_compatibility(self) -> None:
        """Test merge compatibility for DeleteCommand."""
        from intellicrack.hexview.hex_commands import DeleteCommand

        cmd1 = DeleteCommand(offset=100, length=5, deleted_data=b"\x00\x01\x02\x03\x04")
        cmd2 = DeleteCommand(offset=105, length=5, deleted_data=b"\x05\x06\x07\x08\x09")

        assert cmd1.can_merge_with(cmd2) is True

    def test_affected_range_used_in_merge_check(self) -> None:
        """Test that get_affected_range is properly used in merge checking."""
        from intellicrack.hexview.hex_commands import ReplaceCommand

        cmd1 = ReplaceCommand(offset=100, new_data=b"\x00" * 10, old_data=b"\xFF" * 10)
        cmd2 = ReplaceCommand(offset=110, new_data=b"\x01", old_data=b"\xFE")

        range1 = cmd1.get_affected_range()
        range2 = cmd2.get_affected_range()

        assert range1 == (100, 110)
        assert range2 == (110, 111)

        assert cmd1.can_merge_with(cmd2) is True

    def test_operation_type_attribute_exists(self) -> None:
        """Test that operation_type attribute exists on commands."""
        from intellicrack.hexview.hex_commands import (
            DeleteCommand,
            InsertCommand,
            OperationType,
            ReplaceCommand,
        )

        replace = ReplaceCommand(offset=100, new_data=b"\x00", old_data=b"\xFF")
        insert = InsertCommand(offset=100, data=b"\x00")
        delete = DeleteCommand(offset=100, length=1, deleted_data=b"\xFF")

        assert replace.operation_type == OperationType.REPLACE
        assert insert.operation_type == OperationType.INSERT
        assert delete.operation_type == OperationType.DELETE

    def test_zero_offset_commands(self) -> None:
        """Test merge behavior for commands at offset 0."""
        from intellicrack.hexview.hex_commands import ReplaceCommand

        cmd1 = ReplaceCommand(offset=0, new_data=b"\x00\x01", old_data=b"\xFF\xFE")
        cmd2 = ReplaceCommand(offset=2, new_data=b"\x02\x03", old_data=b"\xFD\xFC")

        assert cmd1.can_merge_with(cmd2) is True

    def test_large_data_commands(self) -> None:
        """Test merge behavior with large data blocks."""
        from intellicrack.hexview.hex_commands import ReplaceCommand

        large_data = b"\x00" * 1000
        cmd1 = ReplaceCommand(offset=0, new_data=large_data, old_data=large_data)
        cmd2 = ReplaceCommand(offset=1000, new_data=b"\x01", old_data=b"\xFF")

        assert cmd1.can_merge_with(cmd2) is True

    def test_non_adjacent_replace_commands_fail(self) -> None:
        """Test that non-adjacent ReplaceCommands cannot merge."""
        from intellicrack.hexview.hex_commands import ReplaceCommand

        cmd1 = ReplaceCommand(offset=0, new_data=b"\x00" * 1000, old_data=b"\xFF" * 1000)
        cmd3 = ReplaceCommand(offset=1020, new_data=b"\x02", old_data=b"\xFE")

        assert cmd1.can_merge_with(cmd3) is False

    def test_get_affected_range_returns_tuple(self) -> None:
        """Test that get_affected_range returns correct tuple."""
        from intellicrack.hexview.hex_commands import ReplaceCommand

        cmd = ReplaceCommand(offset=50, new_data=b"\x00" * 20, old_data=b"\xFF" * 20)
        range_tuple = cmd.get_affected_range()

        assert isinstance(range_tuple, tuple)
        assert len(range_tuple) == 2
        assert range_tuple[0] == 50
        assert range_tuple[1] == 70

    def test_insert_command_affected_range(self) -> None:
        """Test InsertCommand affected range calculation."""
        from intellicrack.hexview.hex_commands import InsertCommand

        cmd = InsertCommand(offset=100, data=b"\x00\x01\x02")
        range_tuple = cmd.get_affected_range()

        assert range_tuple[0] == 100
        assert range_tuple[1] == 103

    def test_delete_command_affected_range(self) -> None:
        """Test DeleteCommand affected range calculation."""
        from intellicrack.hexview.hex_commands import DeleteCommand

        cmd = DeleteCommand(offset=100, length=10, deleted_data=b"\x00" * 10)
        range_tuple = cmd.get_affected_range()

        assert range_tuple[0] == 100
        assert range_tuple[1] == 110

