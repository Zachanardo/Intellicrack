"""Production-Ready Tests for Hex Commands Module.

Tests REAL command execution, undo/redo functionality with actual binary data.
"""

from pathlib import Path
from typing import cast

import pytest

from intellicrack.hexview.file_handler import VirtualFileAccess
from intellicrack.hexview.hex_commands import (
    CommandManager,
    DeleteCommand,
    FillCommand,
    InsertCommand,
    OperationType,
    PasteCommand,
    ReplaceCommand,
)


class TestReplaceCommand:
    """Test ReplaceCommand with real binary modifications."""

    @pytest.fixture
    def test_file_handler(self, tmp_path: Path) -> VirtualFileAccess:
        """Create file handler for testing."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(bytes(range(256)))
        return VirtualFileAccess(str(test_file), read_only=False)

    def test_replacecommand_modifies_data(self, test_file_handler: VirtualFileAccess) -> None:
        """ReplaceCommand must actually modify binary data."""
        original_data = test_file_handler.read(100, 10)

        cmd = ReplaceCommand(offset=100, new_data=b"REPLACED!!")
        success = cmd.execute(test_file_handler)

        assert success is True
        assert cmd.executed is True

        modified_data = test_file_handler.read(100, 10)
        assert modified_data == b"REPLACED!!"
        assert modified_data != original_data

    def test_replacecommand_undo_restores_original(self, test_file_handler: VirtualFileAccess) -> None:
        """ReplaceCommand undo must restore original data."""
        original_data = test_file_handler.read(50, 8)

        cmd = ReplaceCommand(offset=50, new_data=b"MODIFIED")
        cmd.execute(test_file_handler)

        undo_success = cmd.undo(test_file_handler)

        assert undo_success is True
        restored_data = test_file_handler.read(50, 8)
        assert restored_data == original_data

    def test_replacecommand_affected_range(self) -> None:
        """ReplaceCommand must report correct affected range."""
        cmd = ReplaceCommand(offset=100, new_data=b"TEST")

        start, end = cmd.get_affected_range()
        assert start == 100
        assert end == 104

    def test_replacecommand_merges_adjacent_replacements(self) -> None:
        """ReplaceCommand must merge adjacent replace operations."""
        cmd1 = ReplaceCommand(offset=100, new_data=b"AAAA", old_data=b"0000")
        cmd2 = ReplaceCommand(offset=104, new_data=b"BBBB", old_data=b"1111")

        assert cmd1.can_merge_with(cmd2) is True

        merged = cast(ReplaceCommand, cmd1.merge_with(cmd2))
        assert merged.offset == 100
        assert merged.new_data == b"AAAABBBB"


class TestInsertCommand:
    """Test InsertCommand with real data insertion."""

    @pytest.fixture
    def test_file_handler(self, tmp_path: Path) -> VirtualFileAccess:
        """Create file handler for testing."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"AAAA" + b"BBBB")
        return VirtualFileAccess(str(test_file), read_only=False)

    def test_insertcommand_merges_consecutive_inserts(self) -> None:
        """InsertCommand must merge consecutive insert operations."""
        cmd1 = InsertCommand(offset=100, data=b"AAA")
        cmd2 = InsertCommand(offset=103, data=b"BBB")

        assert cmd1.can_merge_with(cmd2) is True

        merged = cast(InsertCommand, cmd1.merge_with(cmd2))
        assert merged.offset == 100
        assert merged.data == b"AAABBB"


class TestDeleteCommand:
    """Test DeleteCommand with real data deletion."""

    @pytest.fixture
    def test_file_handler(self, tmp_path: Path) -> VirtualFileAccess:
        """Create file handler for testing."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(bytes(range(256)))
        return VirtualFileAccess(str(test_file), read_only=False)

    def test_deletecommand_affected_range(self) -> None:
        """DeleteCommand must report correct affected range."""
        cmd = DeleteCommand(offset=100, length=50)

        start, end = cmd.get_affected_range()
        assert start == 100
        assert end == 150

    def test_deletecommand_merges_adjacent_deletions(self) -> None:
        """DeleteCommand must merge adjacent delete operations."""
        cmd1 = DeleteCommand(offset=100, length=10, deleted_data=b"A" * 10)
        cmd2 = DeleteCommand(offset=110, length=10, deleted_data=b"B" * 10)

        assert cmd1.can_merge_with(cmd2) is True

        merged = cast(DeleteCommand, cmd1.merge_with(cmd2))
        assert merged.offset == 100
        assert merged.length == 20


class TestFillCommand:
    """Test FillCommand with real fill operations."""

    @pytest.fixture
    def test_file_handler(self, tmp_path: Path) -> VirtualFileAccess:
        """Create file handler for testing."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(bytes(range(256)))
        return VirtualFileAccess(str(test_file), read_only=False)

    def test_fillcommand_fills_range_with_value(self, test_file_handler: VirtualFileAccess) -> None:
        """FillCommand must fill range with specified byte value."""
        cmd = FillCommand(offset=100, length=50, fill_value=0xFF)
        success = cmd.execute(test_file_handler)

        assert success is True

        filled_data = test_file_handler.read(100, 50)
        assert filled_data == b"\xFF" * 50

    def test_fillcommand_undo_restores_original(self, test_file_handler: VirtualFileAccess) -> None:
        """FillCommand undo must restore original data."""
        original_data = test_file_handler.read(100, 20)

        cmd = FillCommand(offset=100, length=20, fill_value=0x00)
        cmd.execute(test_file_handler)

        undo_success = cmd.undo(test_file_handler)

        assert undo_success is True
        restored_data = test_file_handler.read(100, 20)
        assert restored_data == original_data


class TestPasteCommand:
    """Test PasteCommand with real paste operations."""

    @pytest.fixture
    def test_file_handler(self, tmp_path: Path) -> VirtualFileAccess:
        """Create file handler for testing."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(bytes(range(256)))
        return VirtualFileAccess(str(test_file), read_only=False)

    def test_pastecommand_overwrite_mode(self, test_file_handler: VirtualFileAccess) -> None:
        """PasteCommand must overwrite data in overwrite mode."""
        cmd = PasteCommand(offset=100, data=b"PASTE", insert_mode=False)
        success = cmd.execute(test_file_handler)

        assert success is True

        pasted_data = test_file_handler.read(100, 5)
        assert pasted_data == b"PASTE"


class TestCommandManager:
    """Test CommandManager with real command execution and undo/redo."""

    @pytest.fixture
    def test_file_handler(self, tmp_path: Path) -> VirtualFileAccess:
        """Create file handler for testing."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(bytes(range(256)))
        return VirtualFileAccess(str(test_file), read_only=False)

    @pytest.fixture
    def command_manager(self, test_file_handler: VirtualFileAccess) -> CommandManager:
        """Create command manager with file handler."""
        manager = CommandManager()
        manager.set_file_handler(test_file_handler)
        return manager

    def test_commandmanager_executes_commands(self, command_manager: CommandManager, test_file_handler: VirtualFileAccess) -> None:
        """CommandManager must execute commands and track history."""
        cmd = ReplaceCommand(offset=100, new_data=b"TEST")
        success = command_manager.execute_command(cmd)

        assert success is True
        assert len(command_manager.command_history) == 1

        data = test_file_handler.read(100, 4)
        assert data == b"TEST"

    def test_commandmanager_undo_functionality(self, command_manager: CommandManager, test_file_handler: VirtualFileAccess) -> None:
        """CommandManager undo must reverse command execution."""
        original_data = test_file_handler.read(50, 10)

        cmd = ReplaceCommand(offset=50, new_data=b"MODIFIED!!")
        command_manager.execute_command(cmd)

        undo_success = command_manager.undo()

        assert undo_success is True

        restored_data = test_file_handler.read(50, 10)
        assert restored_data == original_data

    def test_commandmanager_redo_functionality(self, command_manager: CommandManager, test_file_handler: VirtualFileAccess) -> None:
        """CommandManager redo must re-execute undone commands."""
        cmd = ReplaceCommand(offset=100, new_data=b"REDO")
        command_manager.execute_command(cmd)

        command_manager.undo()
        redo_success = command_manager.redo()

        assert redo_success is True

        data = test_file_handler.read(100, 4)
        assert data == b"REDO"

    def test_commandmanager_multiple_undo_redo(self, command_manager: CommandManager, test_file_handler: VirtualFileAccess) -> None:
        """CommandManager must handle multiple undo/redo operations."""
        cmd1 = ReplaceCommand(offset=10, new_data=b"AAA")
        cmd2 = ReplaceCommand(offset=20, new_data=b"BBB")
        cmd3 = ReplaceCommand(offset=30, new_data=b"CCC")

        command_manager.execute_command(cmd1)
        command_manager.execute_command(cmd2)
        command_manager.execute_command(cmd3)

        command_manager.undo()
        command_manager.undo()

        assert test_file_handler.read(10, 3) == b"AAA"
        assert test_file_handler.read(30, 3) != b"CCC"

        command_manager.redo()

        assert test_file_handler.read(20, 3) == b"BBB"

    def test_commandmanager_clears_redo_history_on_new_command(self, command_manager: CommandManager) -> None:
        """CommandManager must clear redo history when new command executed after undo."""
        cmd1 = ReplaceCommand(offset=10, new_data=b"AAA")
        cmd2 = ReplaceCommand(offset=20, new_data=b"BBB")

        command_manager.execute_command(cmd1)
        command_manager.execute_command(cmd2)

        command_manager.undo()

        cmd3 = ReplaceCommand(offset=30, new_data=b"CCC")
        command_manager.execute_command(cmd3)

        assert command_manager.can_redo() is False

    def test_commandmanager_auto_merge_consecutive_commands(self, command_manager: CommandManager, test_file_handler: VirtualFileAccess) -> None:
        """CommandManager must auto-merge compatible consecutive commands."""
        command_manager.set_auto_merge(True)

        cmd1 = ReplaceCommand(offset=100, new_data=b"AAAA", old_data=b"0000")
        cmd2 = ReplaceCommand(offset=104, new_data=b"BBBB", old_data=b"1111")

        command_manager.execute_command(cmd1)
        command_manager.execute_command(cmd2)

        assert len(command_manager.command_history) == 1

        merged_cmd = command_manager.command_history[0]
        assert isinstance(merged_cmd, ReplaceCommand)
        assert merged_cmd.new_data == b"AAAABBBB"

    def test_commandmanager_respects_max_history(self) -> None:
        """CommandManager must respect maximum history size."""
        manager = CommandManager(max_history=5)
        file_path = Path("test.bin")

        for i in range(10):
            cmd = ReplaceCommand(offset=i * 10, new_data=f"CMD{i}".encode())
            if i == 0:
                manager.file_handler = VirtualFileAccess.__new__(VirtualFileAccess)
            if manager.file_handler:
                cmd.execute(manager.file_handler)
                manager.command_history.append(cmd)
                manager.current_index = len(manager.command_history) - 1

        assert len(manager.command_history) <= 5

    def test_commandmanager_history_summary(self, command_manager: CommandManager) -> None:
        """CommandManager must provide accurate history summary."""
        cmd1 = ReplaceCommand(offset=10, new_data=b"A")
        cmd2 = FillCommand(offset=20, length=10, fill_value=0xFF)

        command_manager.execute_command(cmd1)
        command_manager.execute_command(cmd2)

        summary = command_manager.get_history_summary()

        assert len(summary) == 2
        assert summary[0]["type"] == OperationType.REPLACE.value
        assert summary[1]["type"] == OperationType.FILL.value

    def test_commandmanager_get_undo_description(self, command_manager: CommandManager) -> None:
        """CommandManager must provide undo description."""
        cmd = ReplaceCommand(offset=100, new_data=b"TEST")
        command_manager.execute_command(cmd)

        description = command_manager.get_undo_description()
        assert description is not None
        assert "Replace" in description

    def test_commandmanager_clear_history(self, command_manager: CommandManager) -> None:
        """CommandManager must clear all command history."""
        cmd1 = ReplaceCommand(offset=10, new_data=b"A")
        cmd2 = ReplaceCommand(offset=20, new_data=b"B")

        command_manager.execute_command(cmd1)
        command_manager.execute_command(cmd2)

        command_manager.clear_history()

        assert len(command_manager.command_history) == 0
        assert command_manager.current_index == -1
        assert command_manager.can_undo() is False
