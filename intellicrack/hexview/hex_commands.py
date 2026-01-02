"""Command system for hex editor operations with undo/redo support.

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

import logging
import sys
from abc import ABC, abstractmethod
from enum import Enum
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from .file_handler import VirtualFileAccess

logger = logging.getLogger(__name__)

__all__ = [
    "CommandManager",
    "DeleteCommand",
    "FillCommand",
    "HexCommand",
    "InsertCommand",
    "OperationType",
    "PasteCommand",
    "ReplaceCommand",
]


class OperationType(Enum):
    """Types of hex editor operations."""

    REPLACE = "replace"
    INSERT = "insert"
    DELETE = "delete"
    FILL = "fill"
    PASTE = "paste"
    MOVE = "move"
    COPY = "copy"


class HexCommand(ABC):
    """Abstract base class for hex editor commands."""

    def __init__(self, description: str, operation_type: OperationType) -> None:
        """Initialize the HexCommand with description and operation type.

        Args:
            description: Text description of the command
            operation_type: Type of operation (from OperationType enum)

        """
        self.description: str = description
        self.operation_type: OperationType = operation_type
        self.timestamp: float | None = None
        self.executed: bool = False

    @abstractmethod
    def execute(self, file_handler: "VirtualFileAccess") -> bool:
        """Execute the command.

        Args:
            file_handler: VirtualFileAccess instance

        Returns:
            True if successful, False otherwise

        """

    @abstractmethod
    def undo(self, file_handler: "VirtualFileAccess") -> bool:
        """Undo the command.

        Args:
            file_handler: VirtualFileAccess instance

        Returns:
            True if successful, False otherwise

        """

    @abstractmethod
    def get_affected_range(self) -> tuple[int, int]:
        """Get the range of bytes affected by this command.

        Returns:
            Tuple of (start_offset, end_offset)

        """

    def can_merge_with(self, other: "HexCommand") -> bool:
        """Check if this command can be merged with another command.

        Args:
            other: Another command

        Returns:
            True if commands can be merged

        """
        if self.operation_type != other.operation_type:
            return False

        self_range = self.get_affected_range()
        other_range = other.get_affected_range()

        self_end = self_range[1]
        other_start = other_range[0]
        proximity_threshold = 16

        if abs(self_end - other_start) <= proximity_threshold:
            return True
        return abs(other_range[1] - self_range[0]) <= proximity_threshold

    def merge_with(self, other: "HexCommand") -> "HexCommand":
        """Merge this command with another command.

        Args:
            other: Another command to merge with

        Raises:
            ValueError: If commands cannot be merged

        """
        # Default implementation for commands that don't support merging
        # Subclasses should override this method if they support merging
        error_msg = f"Command type {self.__class__.__name__} does not support merging with {other.__class__.__name__}"
        logger.exception(error_msg)
        raise ValueError(error_msg)


class ReplaceCommand(HexCommand):
    """Command for replacing bytes at a specific offset."""

    def __init__(self, offset: int, new_data: bytes, old_data: bytes | None = None) -> None:
        """Initialize the ReplaceCommand with offset and data.

        Args:
            offset: Starting offset for replacement
            new_data: New bytes to insert
            old_data: Original bytes at this location (optional)

        """
        super().__init__(f"Replace {len(new_data)} bytes at 0x{offset:X}", OperationType.REPLACE)
        self.offset = offset
        self.new_data = new_data
        self.old_data = old_data

    def execute(self, file_handler: "VirtualFileAccess") -> bool:
        """Execute the replace operation.

        Args:
            file_handler: VirtualFileAccess instance for file operations

        Returns:
            True if operation succeeded, False otherwise

        """
        try:
            # Store old data if not already stored
            if self.old_data is None:
                self.old_data = file_handler.read(self.offset, len(self.new_data))

            # Write new data
            success = file_handler.write(self.offset, self.new_data)
            if success:
                self.executed = True
                logger.debug("Replaced %d bytes at offset 0x%X", len(self.new_data), self.offset)
            return success
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error executing replace command: %s", e)
            return False

    def undo(self, file_handler: "VirtualFileAccess") -> bool:
        """Undo the replace operation.

        Args:
            file_handler: VirtualFileAccess instance for file operations

        Returns:
            True if operation succeeded, False otherwise

        """
        try:
            if not self.executed or self.old_data is None:
                return False

            success = file_handler.write(self.offset, self.old_data)
            if success:
                self.executed = False
                logger.debug("Undid replace of %d bytes at offset 0x%X", len(self.old_data), self.offset)
            return success
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error undoing replace command: %s", e)
            return False

    def get_affected_range(self) -> tuple[int, int]:
        """Get the affected byte range.

        Returns:
            Tuple of (start_offset, end_offset)

        """
        return (self.offset, self.offset + len(self.new_data))

    def can_merge_with(self, other: "HexCommand") -> bool:
        """Check if this command can be merged with a consecutive replace.

        Args:
            other: Another command to check

        Returns:
            True if commands can be merged, False otherwise

        """
        if not isinstance(other, ReplaceCommand):
            return False

        # Can merge if the operations are adjacent
        this_end = self.offset + len(self.new_data)
        return other.offset == this_end

    def merge_with(self, other: "HexCommand") -> "HexCommand":
        """Merge with another replace command.

        Args:
            other: Another command to merge with

        Returns:
            New merged ReplaceCommand

        Raises:
            ValueError: If commands cannot be merged

        """
        if not self.can_merge_with(other):
            error_msg = "Cannot merge non-adjacent replace commands"
            logger.exception(error_msg)
            raise ValueError(error_msg)

        # Combine the data
        other_cmd = other if isinstance(other, ReplaceCommand) else None
        if other_cmd is None:
            raise ValueError("Cannot merge with non-ReplaceCommand")
        combined_new_data = self.new_data + other_cmd.new_data
        combined_old_data = self.old_data + other_cmd.old_data if self.old_data and other_cmd.old_data else None

        return ReplaceCommand(self.offset, combined_new_data, combined_old_data)


class InsertCommand(HexCommand):
    """Command for inserting bytes at a specific offset."""

    def __init__(self, offset: int, data: bytes) -> None:
        """Initialize the InsertCommand with offset and data.

        Args:
            offset: Starting offset for insertion
            data: Bytes to insert

        """
        super().__init__(f"Insert {len(data)} bytes at 0x{offset:X}", OperationType.INSERT)
        self.offset = offset
        self.data = data

    def execute(self, file_handler: "VirtualFileAccess") -> bool:
        """Execute the insert operation.

        Args:
            file_handler: VirtualFileAccess instance for file operations

        Returns:
            True if operation succeeded, False otherwise

        """
        try:
            success = file_handler.insert(self.offset, self.data)
            if success:
                self.executed = True
                logger.debug("Inserted %d bytes at offset 0x%X", len(self.data), self.offset)
            return success
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error executing insert command: %s", e)
            return False

    def undo(self, file_handler: "VirtualFileAccess") -> bool:
        """Undo the insert operation.

        Args:
            file_handler: VirtualFileAccess instance for file operations

        Returns:
            True if operation succeeded, False otherwise

        """
        try:
            if not self.executed:
                return False

            success = file_handler.delete(self.offset, len(self.data))
            if success:
                self.executed = False
                logger.debug("Undid insert of %d bytes at offset 0x%X", len(self.data), self.offset)
            return success
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error undoing insert command: %s", e)
            return False

    def get_affected_range(self) -> tuple[int, int]:
        """Get the affected byte range.

        Returns:
            Tuple of (start_offset, end_offset)

        """
        return (self.offset, self.offset + len(self.data))

    def can_merge_with(self, other: "HexCommand") -> bool:
        """Check if this command can be merged with another insert command.

        Two InsertCommands can be merged if:
        - They are both InsertCommands
        - The second command's offset is at the end of the first command's insertion

        Args:
            other: Another command to check

        Returns:
            True if commands can be merged, False otherwise

        """
        if not isinstance(other, InsertCommand):
            return False

        # Can merge if insertions are consecutive
        # When we insert at offset X with N bytes, the next insertion point is X + N
        return other.offset == self.offset + len(self.data)

    def merge_with(self, other: "HexCommand") -> "HexCommand":
        """Merge with another insert command.

        Args:
            other: Another InsertCommand to merge with

        Returns:
            New merged InsertCommand

        Raises:
            ValueError: If commands cannot be merged

        """
        if not self.can_merge_with(other):
            error_msg = "Cannot merge non-consecutive insert commands"
            logger.exception(error_msg)
            raise ValueError(error_msg)

        # Combine the data
        other_cmd = other if isinstance(other, InsertCommand) else None
        if other_cmd is None:
            raise ValueError("Cannot merge with non-InsertCommand")
        combined_data = self.data + other_cmd.data

        # Create new merged command
        return InsertCommand(self.offset, combined_data)


class DeleteCommand(HexCommand):
    """Command for deleting bytes at a specific offset."""

    def __init__(self, offset: int, length: int, deleted_data: bytes | None = None) -> None:
        """Initialize the DeleteCommand with offset, length, and deleted data.

        Args:
            offset: Starting offset for deletion
            length: Number of bytes to delete
            deleted_data: Original bytes that were deleted (optional)

        """
        super().__init__(f"Delete {length} bytes at 0x{offset:X}", OperationType.DELETE)
        self.offset = offset
        self.length = length
        self.deleted_data = deleted_data

    def execute(self, file_handler: "VirtualFileAccess") -> bool:
        """Execute the delete operation.

        Args:
            file_handler: VirtualFileAccess instance for file operations

        Returns:
            True if operation succeeded, False otherwise

        """
        try:
            # Store data being deleted if not already stored
            if self.deleted_data is None:
                self.deleted_data = file_handler.read(self.offset, self.length)

            success = file_handler.delete(self.offset, self.length)
            if success:
                self.executed = True
                logger.debug("Deleted %s bytes at offset 0x%s", self.length, self.offset)
            return success
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error executing delete command: %s", e)
            return False

    def undo(self, file_handler: "VirtualFileAccess") -> bool:
        """Undo the delete operation.

        Args:
            file_handler: VirtualFileAccess instance for file operations

        Returns:
            True if operation succeeded, False otherwise

        """
        try:
            if not self.executed or self.deleted_data is None:
                return False

            success = file_handler.insert(self.offset, self.deleted_data)
            if success:
                self.executed = False
                logger.debug("Undid delete of %s bytes at offset 0x%s", self.length, self.offset)
            return success
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error undoing delete command: %s", e)
            return False

    def get_affected_range(self) -> tuple[int, int]:
        """Get the affected byte range.

        Returns:
            Tuple of (start_offset, end_offset)

        """
        return (self.offset, self.offset + self.length)

    def can_merge_with(self, other: "HexCommand") -> bool:
        """Check if this command can be merged with another delete command.

        Two DeleteCommands can be merged if:
        - They are both DeleteCommands
        - They are adjacent (either consecutive or overlapping)

        Args:
            other: Another command

        Returns:
            True if commands can be merged

        """
        if not isinstance(other, DeleteCommand):
            return False

        # Can merge if deletions are adjacent or overlapping
        # Check if the other deletion starts where this one ends
        if other.offset == self.offset + self.length:
            return True

        # Check if this deletion ends where the other one starts
        if self.offset == other.offset + other.length:
            return True

        # Check for overlap
        return self.offset <= other.offset < self.offset + self.length or other.offset <= self.offset < other.offset + other.length

    def merge_with(self, other: "HexCommand") -> "HexCommand":
        """Merge with another delete command.

        Args:
            other: Another DeleteCommand to merge with

        Returns:
            New merged DeleteCommand

        Raises:
            ValueError: If commands cannot be merged

        """
        if not self.can_merge_with(other):
            error_msg = "Cannot merge non-adjacent delete commands"
            logger.exception(error_msg)
            raise ValueError(error_msg)

        # Determine the range of the merged deletion
        other_cmd = other if isinstance(other, DeleteCommand) else None
        if other_cmd is None:
            raise ValueError("Cannot merge with non-DeleteCommand")

        min_offset = min(self.offset, other_cmd.offset)
        max_end = max(self.offset + self.length, other_cmd.offset + other_cmd.length)
        combined_length = max_end - min_offset

        # Combine deleted data if available
        combined_deleted_data = None
        if self.deleted_data and other_cmd.deleted_data:
            # Need to properly combine the deleted data based on offsets
            if self.offset <= other_cmd.offset:
                # This command comes first
                if self.offset + self.length >= other_cmd.offset:
                    # Overlapping or adjacent
                    overlap_start = other_cmd.offset - self.offset
                    overlap_length = min(self.length - overlap_start, other_cmd.length)
                    # Take self.deleted_data and append non-overlapping part of other
                    if other_cmd.offset + other_cmd.length > self.offset + self.length:
                        extra_data = other_cmd.deleted_data[overlap_length:]
                        combined_deleted_data = self.deleted_data + extra_data
                    else:
                        combined_deleted_data = self.deleted_data
                else:
                    # Gap between deletions - shouldn't happen if can_merge_with is correct
                    combined_deleted_data = None
            # Other command comes first
            elif other_cmd.offset + other_cmd.length >= self.offset:
                # Overlapping or adjacent
                overlap_start = self.offset - other_cmd.offset
                overlap_length = min(other_cmd.length - overlap_start, self.length)
                # Take other.deleted_data and append non-overlapping part of self
                if self.offset + self.length > other_cmd.offset + other_cmd.length:
                    extra_data = self.deleted_data[overlap_length:]
                    combined_deleted_data = other_cmd.deleted_data + extra_data
                else:
                    combined_deleted_data = other_cmd.deleted_data
            else:
                # Gap between deletions - shouldn't happen if can_merge_with is correct
                combined_deleted_data = None

        # Create new merged command
        return DeleteCommand(min_offset, combined_length, combined_deleted_data)


class FillCommand(HexCommand):
    """Command for filling a range with a specific value."""

    def __init__(self, offset: int, length: int, fill_value: int, old_data: bytes | None = None) -> None:
        """Initialize the FillCommand with offset, length, fill value, and old data.

        Args:
            offset: Starting offset for fill operation
            length: Number of bytes to fill
            fill_value: Byte value to fill with
            old_data: Original bytes before fill (optional)

        """
        super().__init__(f"Fill {length} bytes at 0x{offset:X} with 0x{fill_value:02X}", OperationType.FILL)
        self.offset = offset
        self.length = length
        self.fill_value = fill_value
        self.old_data = old_data

    def execute(self, file_handler: "VirtualFileAccess") -> bool:
        """Execute the fill operation.

        Args:
            file_handler: VirtualFileAccess instance for file operations

        Returns:
            True if operation succeeded, False otherwise

        """
        try:
            # Store old data if not already stored
            if self.old_data is None:
                self.old_data = file_handler.read(self.offset, self.length)

            # Create fill data
            fill_data = bytes([self.fill_value] * self.length)

            success = file_handler.write(self.offset, fill_data)
            if success:
                self.executed = True
                logger.debug(
                    "Filled %s bytes at offset 0x%s with 0x%s",
                    self.length,
                    self.offset,
                    self.fill_value,
                )
            return success
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error executing fill command: %s", e)
            return False

    def undo(self, file_handler: "VirtualFileAccess") -> bool:
        """Undo the fill operation.

        Args:
            file_handler: VirtualFileAccess instance for file operations

        Returns:
            True if operation succeeded, False otherwise

        """
        try:
            if not self.executed or self.old_data is None:
                return False

            success = file_handler.write(self.offset, self.old_data)
            if success:
                self.executed = False
                logger.debug("Undid fill of %s bytes at offset 0x%s", self.length, self.offset)
            return success
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error undoing fill command: %s", e)
            return False

    def get_affected_range(self) -> tuple[int, int]:
        """Get the affected byte range.

        Returns:
            Tuple of (start_offset, end_offset)

        """
        return (self.offset, self.offset + self.length)


class PasteCommand(HexCommand):
    """Command for pasting data at a specific offset."""

    def __init__(self, offset: int, data: bytes, insert_mode: bool = False, old_data: bytes | None = None) -> None:
        """Initialize the PasteCommand with offset, data, insert mode, and old data.

        Args:
            offset: Starting offset for paste operation
            data: Bytes to paste
            insert_mode: True to insert, False to overwrite
            old_data: Original bytes before paste (optional)

        """
        mode_str = "insert" if insert_mode else "overwrite"
        super().__init__(f"Paste {len(data)} bytes at 0x{offset:X} ({mode_str})", OperationType.PASTE)
        self.offset = offset
        self.data = data
        self.insert_mode = insert_mode
        self.old_data = old_data

    def execute(self, file_handler: "VirtualFileAccess") -> bool:
        """Execute the paste operation.

        Args:
            file_handler: VirtualFileAccess instance for file operations

        Returns:
            True if operation succeeded, False otherwise

        """
        try:
            if self.insert_mode:
                # Insert mode - insert the data
                success = file_handler.insert(self.offset, self.data)
            else:
                # Overwrite mode - replace existing data
                if self.old_data is None:
                    self.old_data = file_handler.read(self.offset, len(self.data))
                success = file_handler.write(self.offset, self.data)

            if success:
                self.executed = True
                mode_str = "inserted" if self.insert_mode else "overwrote"
                logger.debug("Pasted %d bytes at offset 0x%X (%s)", len(self.data), self.offset, mode_str)
            return success
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error executing paste command: %s", e)
            return False

    def undo(self, file_handler: "VirtualFileAccess") -> bool:
        """Undo the paste operation.

        Args:
            file_handler: VirtualFileAccess instance for file operations

        Returns:
            True if operation succeeded, False otherwise

        """
        try:
            if not self.executed:
                return False

            if self.insert_mode:
                # Undo insert by deleting
                success = file_handler.delete(self.offset, len(self.data))
            elif self.old_data is None:
                return False
            else:
                success = file_handler.write(self.offset, self.old_data)

            if success:
                self.executed = False
                mode_str = "insert" if self.insert_mode else "overwrite"
                logger.debug("Undid paste (%s) of %d bytes at offset 0x%X", mode_str, len(self.data), self.offset)
            return success
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error undoing paste command: %s", e)
            return False

    def get_affected_range(self) -> tuple[int, int]:
        """Get the affected byte range.

        Returns:
            Tuple of (start_offset, end_offset)

        """
        return (self.offset, self.offset + len(self.data))


class CommandManager:
    """Manages command execution and undo/redo functionality."""

    def __init__(self, max_history: int = sys.maxsize) -> None:
        """Initialize the CommandManager with maximum history size.

        Args:
            max_history: Maximum number of commands to keep in history.
                        Defaults to sys.maxsize for virtually unlimited undo/redo.

        """
        self.max_history: int = max_history
        self.command_history: list[HexCommand] = []
        self.current_index: int = -1
        self.file_handler: Any = None
        self.auto_merge: bool = True

    def set_file_handler(self, file_handler: "VirtualFileAccess") -> None:
        """Set the file handler for command execution.

        Args:
            file_handler: VirtualFileAccess instance to use for command execution

        """
        self.file_handler = file_handler

    def execute_command(self, command: HexCommand) -> bool:
        """Execute a command and add it to the history.

        Args:
            command: Command to execute

        Returns:
            True if successful, False otherwise

        """
        if not self.file_handler:
            logger.exception("No file handler set for command execution")
            return False

        # Try to merge with previous command if auto-merge is enabled
        if self.auto_merge and self.command_history and self.current_index >= 0 and self.current_index < len(self.command_history):
            last_command = self.command_history[self.current_index]
            if last_command.can_merge_with(command):
                try:
                    # Create merged command
                    merged_command = last_command.merge_with(command)

                    # Undo the last command
                    if last_command.executed:
                        last_command.undo(self.file_handler)

                    # Execute the merged command
                    if merged_command.execute(self.file_handler):
                        # Replace the last command with the merged one
                        self.command_history[self.current_index] = merged_command
                        logger.debug("Merged command: %s", merged_command.description)
                        return True
                    # If merge fails, re-execute the last command and continue with normal execution
                    last_command.execute(self.file_handler)
                except (OSError, ValueError, RuntimeError) as e:
                    logger.warning("Command merge failed: %s", e)
                    # Continue with normal execution

        # Execute the command
        if not command.execute(self.file_handler):
            return False

        # Remove any commands after the current index (redo history)
        if self.current_index < len(self.command_history) - 1:
            self.command_history = self.command_history[: self.current_index + 1]

        # Add the command to history
        self.command_history.append(command)
        self.current_index += 1

        # Maintain maximum history size
        if len(self.command_history) > self.max_history:
            self.command_history.pop(0)
            self.current_index -= 1

        logger.debug("Executed command: %s", command.description)
        return True

    def undo(self) -> bool:
        """Undo the last command.

        Returns:
            True if successful, False otherwise

        """
        if not self.can_undo() or self.file_handler is None:
            return False

        command = self.command_history[self.current_index]
        if command.undo(self.file_handler):
            self.current_index -= 1
            logger.debug("Undid command: %s", command.description)
            return True
        logger.exception("Failed to undo command: %s", command.description)
        return False

    def redo(self) -> bool:
        """Redo the next command.

        Returns:
            True if successful, False otherwise

        """
        if not self.can_redo() or self.file_handler is None:
            return False

        command = self.command_history[self.current_index + 1]
        if command.execute(self.file_handler):
            self.current_index += 1
            logger.debug("Redid command: %s", command.description)
            return True
        logger.exception("Failed to redo command: %s", command.description)
        return False

    def can_undo(self) -> bool:
        """Check if undo is possible.

        Returns:
            True if undo can be performed, False otherwise

        """
        return self.current_index >= 0 and len(self.command_history) > 0

    def can_redo(self) -> bool:
        """Check if redo is possible.

        Returns:
            True if redo can be performed, False otherwise

        """
        return self.current_index < len(self.command_history) - 1

    def clear_history(self) -> None:
        """Clear the command history.

        Removes all commands from the history and resets the current index.
        After calling this, both undo and redo operations will be unavailable.

        """
        self.command_history.clear()
        self.current_index = -1
        logger.debug("Cleared command history")

    def get_undo_description(self) -> str | None:
        """Get description of the command that would be undone.

        Returns:
            Description string of the command to be undone, or None if no undo available

        """
        if self.can_undo():
            return self.command_history[self.current_index].description
        return None

    def get_redo_description(self) -> str | None:
        """Get description of the command that would be redone.

        Returns:
            Description string of the command to be redone, or None if no redo available

        """
        if self.can_redo():
            return self.command_history[self.current_index + 1].description
        return None

    def get_history_summary(self) -> list[dict[str, Any]]:
        """Get a summary of the command history.

        Returns:
            List of command information dictionaries

        """
        return [
            {
                "index": i,
                "description": command.description,
                "type": command.operation_type.value,
                "executed": command.executed,
                "is_current": i == self.current_index,
                "affected_range": command.get_affected_range(),
            }
            for i, command in enumerate(self.command_history)
        ]

    def set_auto_merge(self, enabled: bool) -> None:
        """Enable or disable automatic command merging.

        Args:
            enabled: True to enable auto-merging, False to disable

        """
        self.auto_merge = enabled
        logger.debug("Auto-merge %s", "enabled" if enabled else "disabled")
