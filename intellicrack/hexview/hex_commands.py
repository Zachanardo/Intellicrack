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
from typing import Any

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

    def __init__(self, description: str, operation_type: OperationType):
        """Initialize the HexCommand with description and operation type."""
        self.description = description
        self.operation_type = operation_type
        self.timestamp = None
        self.executed = False

    @abstractmethod
    def execute(self, file_handler) -> bool:
        """Execute the command.

        Args:
            file_handler: VirtualFileAccess instance

        Returns:
            True if successful, False otherwise

        """

    @abstractmethod
    def undo(self, file_handler) -> bool:
        """Undo the command.

        Args:
            file_handler: VirtualFileAccess instance

        Returns:
            True if successful, False otherwise

        """

    @abstractmethod
    def get_affected_range(self) -> tuple:
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
        _other = other  # Store for potential future use
        return False

    def merge_with(self, other: "HexCommand") -> "HexCommand":
        """Merge this command with another command.

        Args:
            other: Another command to merge with

        Returns:
            New merged command

        Raises:
            ValueError: If commands cannot be merged

        """
        # Default implementation for commands that don't support merging
        # Subclasses should override this method if they support merging
        raise ValueError(
            f"Command type {self.__class__.__name__} does not support merging with {other.__class__.__name__}"
        )


class ReplaceCommand(HexCommand):
    """Command for replacing bytes at a specific offset."""

    def __init__(self, offset: int, new_data: bytes, old_data: bytes = None):
        """Initialize the ReplaceCommand with offset and data."""
        super().__init__(f"Replace {len(new_data)} bytes at 0x{offset:X}", OperationType.REPLACE)
        self.offset = offset
        self.new_data = new_data
        self.old_data = old_data

    def execute(self, file_handler) -> bool:
        """Execute the replace operation."""
        try:
            # Store old data if not already stored
            if self.old_data is None:
                self.old_data = file_handler.read(self.offset, len(self.new_data))

            # Write new data
            success = file_handler.write(self.offset, self.new_data)
            if success:
                self.executed = True
                logger.debug(f"Replaced {len(self.new_data)} bytes at offset 0x{self.offset:X}")
            return success
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error executing replace command: %s", e)
            return False

    def undo(self, file_handler) -> bool:
        """Undo the replace operation."""
        try:
            if not self.executed or self.old_data is None:
                return False

            success = file_handler.write(self.offset, self.old_data)
            if success:
                self.executed = False
                logger.debug(
                    f"Undid replace of {len(self.old_data)} bytes at offset 0x{self.offset:X}"
                )
            return success
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error undoing replace command: %s", e)
            return False

    def get_affected_range(self) -> tuple:
        """Get the affected byte range."""
        return (self.offset, self.offset + len(self.new_data))

    def can_merge_with(self, other: "HexCommand") -> bool:
        """Check if this command can be merged with a consecutive replace."""
        if not isinstance(other, ReplaceCommand):
            return False

        # Can merge if the operations are adjacent
        this_end = self.offset + len(self.new_data)
        return other.offset == this_end

    def merge_with(self, other: "HexCommand") -> "HexCommand":
        """Merge with another replace command."""
        if not self.can_merge_with(other):
            raise ValueError("Cannot merge non-adjacent replace commands")

        # Combine the data
        combined_new_data = self.new_data + other.new_data
        combined_old_data = (
            self.old_data + other.old_data if self.old_data and other.old_data else None
        )

        return ReplaceCommand(self.offset, combined_new_data, combined_old_data)


class InsertCommand(HexCommand):
    """Command for inserting bytes at a specific offset."""

    def __init__(self, offset: int, data: bytes):
        """Initialize the InsertCommand with offset and data."""
        super().__init__(f"Insert {len(data)} bytes at 0x{offset:X}", OperationType.INSERT)
        self.offset = offset
        self.data = data

    def execute(self, file_handler) -> bool:
        """Execute the insert operation."""
        try:
            success = file_handler.insert(self.offset, self.data)
            if success:
                self.executed = True
                logger.debug(f"Inserted {len(self.data)} bytes at offset 0x{self.offset:X}")
            return success
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error executing insert command: %s", e)
            return False

    def undo(self, file_handler) -> bool:
        """Undo the insert operation."""
        try:
            if not self.executed:
                return False

            success = file_handler.delete(self.offset, len(self.data))
            if success:
                self.executed = False
                logger.debug(f"Undid insert of {len(self.data)} bytes at offset 0x{self.offset:X}")
            return success
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error undoing insert command: %s", e)
            return False

    def get_affected_range(self) -> tuple:
        """Get the affected byte range."""
        return (self.offset, self.offset + len(self.data))

    def can_merge_with(self, other: "HexCommand") -> bool:
        """Check if this command can be merged with another insert command.

        Two InsertCommands can be merged if:
        - They are both InsertCommands
        - The second command's offset is at the end of the first command's insertion

        Args:
            other: Another command

        Returns:
            True if commands can be merged

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
            raise ValueError("Cannot merge non-consecutive insert commands")

        # Combine the data
        combined_data = self.data + other.data

        # Create new merged command
        return InsertCommand(self.offset, combined_data)


class DeleteCommand(HexCommand):
    """Command for deleting bytes at a specific offset."""

    def __init__(self, offset: int, length: int, deleted_data: bytes = None):
        """Initialize the DeleteCommand with offset, length, and deleted data."""
        super().__init__(f"Delete {length} bytes at 0x{offset:X}", OperationType.DELETE)
        self.offset = offset
        self.length = length
        self.deleted_data = deleted_data

    def execute(self, file_handler) -> bool:
        """Execute the delete operation."""
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
            logger.error("Error executing delete command: %s", e)
            return False

    def undo(self, file_handler) -> bool:
        """Undo the delete operation."""
        try:
            if not self.executed or self.deleted_data is None:
                return False

            success = file_handler.insert(self.offset, self.deleted_data)
            if success:
                self.executed = False
                logger.debug("Undid delete of %s bytes at offset 0x%s", self.length, self.offset)
            return success
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error undoing delete command: %s", e)
            return False

    def get_affected_range(self) -> tuple:
        """Get the affected byte range."""
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
        if (self.offset <= other.offset < self.offset + self.length or
            other.offset <= self.offset < other.offset + other.length):
            return True

        return False

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
            raise ValueError("Cannot merge non-adjacent delete commands")

        # Determine the range of the merged deletion
        min_offset = min(self.offset, other.offset)
        max_end = max(self.offset + self.length, other.offset + other.length)
        combined_length = max_end - min_offset

        # Combine deleted data if available
        combined_deleted_data = None
        if self.deleted_data and other.deleted_data:
            # Need to properly combine the deleted data based on offsets
            if self.offset <= other.offset:
                # This command comes first
                if self.offset + self.length >= other.offset:
                    # Overlapping or adjacent
                    overlap_start = other.offset - self.offset
                    overlap_length = min(self.length - overlap_start, other.length)
                    # Take self.deleted_data and append non-overlapping part of other
                    if other.offset + other.length > self.offset + self.length:
                        extra_data = other.deleted_data[overlap_length:]
                        combined_deleted_data = self.deleted_data + extra_data
                    else:
                        combined_deleted_data = self.deleted_data
                else:
                    # Gap between deletions - shouldn't happen if can_merge_with is correct
                    combined_deleted_data = None
            else:
                # Other command comes first
                if other.offset + other.length >= self.offset:
                    # Overlapping or adjacent
                    overlap_start = self.offset - other.offset
                    overlap_length = min(other.length - overlap_start, self.length)
                    # Take other.deleted_data and append non-overlapping part of self
                    if self.offset + self.length > other.offset + other.length:
                        extra_data = self.deleted_data[overlap_length:]
                        combined_deleted_data = other.deleted_data + extra_data
                    else:
                        combined_deleted_data = other.deleted_data
                else:
                    # Gap between deletions - shouldn't happen if can_merge_with is correct
                    combined_deleted_data = None

        # Create new merged command
        return DeleteCommand(min_offset, combined_length, combined_deleted_data)


class FillCommand(HexCommand):
    """Command for filling a range with a specific value."""

    def __init__(self, offset: int, length: int, fill_value: int, old_data: bytes = None):
        """Initialize the FillCommand with offset, length, fill value, and old data."""
        super().__init__(
            f"Fill {length} bytes at 0x{offset:X} with 0x{fill_value:02X}", OperationType.FILL
        )
        self.offset = offset
        self.length = length
        self.fill_value = fill_value
        self.old_data = old_data

    def execute(self, file_handler) -> bool:
        """Execute the fill operation."""
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
            logger.error("Error executing fill command: %s", e)
            return False

    def undo(self, file_handler) -> bool:
        """Undo the fill operation."""
        try:
            if not self.executed or self.old_data is None:
                return False

            success = file_handler.write(self.offset, self.old_data)
            if success:
                self.executed = False
                logger.debug("Undid fill of %s bytes at offset 0x%s", self.length, self.offset)
            return success
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error undoing fill command: %s", e)
            return False

    def get_affected_range(self) -> tuple:
        """Get the affected byte range."""
        return (self.offset, self.offset + self.length)


class PasteCommand(HexCommand):
    """Command for pasting data at a specific offset."""

    def __init__(self, offset: int, data: bytes, insert_mode: bool = False, old_data: bytes = None):
        """Initialize the PasteCommand with offset, data, insert mode, and old data."""
        mode_str = "insert" if insert_mode else "overwrite"
        super().__init__(
            f"Paste {len(data)} bytes at 0x{offset:X} ({mode_str})", OperationType.PASTE
        )
        self.offset = offset
        self.data = data
        self.insert_mode = insert_mode
        self.old_data = old_data

    def execute(self, file_handler) -> bool:
        """Execute the paste operation."""
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
                logger.debug(
                    f"Pasted {len(self.data)} bytes at offset 0x{self.offset:X} ({mode_str})"
                )
            return success
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error executing paste command: %s", e)
            return False

    def undo(self, file_handler) -> bool:
        """Undo the paste operation."""
        try:
            if not self.executed:
                return False

            if self.insert_mode:
                # Undo insert by deleting
                success = file_handler.delete(self.offset, len(self.data))
            else:
                # Undo overwrite by restoring old data
                if self.old_data is None:
                    return False
                success = file_handler.write(self.offset, self.old_data)

            if success:
                self.executed = False
                mode_str = "insert" if self.insert_mode else "overwrite"
                logger.debug(
                    f"Undid paste ({mode_str}) of {len(self.data)} bytes at offset 0x{self.offset:X}"
                )
            return success
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error undoing paste command: %s", e)
            return False

    def get_affected_range(self) -> tuple:
        """Get the affected byte range."""
        return (self.offset, self.offset + len(self.data))


class CommandManager:
    """Manages command execution and undo/redo functionality."""

    def __init__(self, max_history: int = sys.maxsize):
        """Initialize the CommandManager with maximum history size.

        Args:
            max_history: Maximum number of commands to keep in history.
                        Defaults to sys.maxsize for virtually unlimited undo/redo.

        """
        self.max_history = max_history
        self.command_history: list[HexCommand] = []
        self.current_index = -1
        self.file_handler = None
        self.auto_merge = True

    def set_file_handler(self, file_handler):
        """Set the file handler for command execution."""
        self.file_handler = file_handler

    def execute_command(self, command: HexCommand) -> bool:
        """Execute a command and add it to the history.

        Args:
            command: Command to execute

        Returns:
            True if successful, False otherwise

        """
        if not self.file_handler:
            logger.error("No file handler set for command execution")
            return False

        # Try to merge with previous command if auto-merge is enabled
        if (
            self.auto_merge
            and self.command_history
            and self.current_index >= 0
            and self.current_index < len(self.command_history)
        ):
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
        if not self.can_undo():
            return False

        command = self.command_history[self.current_index]
        if command.undo(self.file_handler):
            self.current_index -= 1
            logger.debug("Undid command: %s", command.description)
            return True
        logger.error("Failed to undo command: %s", command.description)
        return False

    def redo(self) -> bool:
        """Redo the next command.

        Returns:
            True if successful, False otherwise

        """
        if not self.can_redo():
            return False

        command = self.command_history[self.current_index + 1]
        if command.execute(self.file_handler):
            self.current_index += 1
            logger.debug("Redid command: %s", command.description)
            return True
        logger.error("Failed to redo command: %s", command.description)
        return False

    def can_undo(self) -> bool:
        """Check if undo is possible."""
        return self.current_index >= 0 and len(self.command_history) > 0

    def can_redo(self) -> bool:
        """Check if redo is possible."""
        return self.current_index < len(self.command_history) - 1

    def clear_history(self):
        """Clear the command history."""
        self.command_history.clear()
        self.current_index = -1
        logger.debug("Cleared command history")

    def get_undo_description(self) -> str | None:
        """Get description of the command that would be undone."""
        if self.can_undo():
            return self.command_history[self.current_index].description
        return None

    def get_redo_description(self) -> str | None:
        """Get description of the command that would be redone."""
        if self.can_redo():
            return self.command_history[self.current_index + 1].description
        return None

    def get_history_summary(self) -> list[dict[str, Any]]:
        """Get a summary of the command history.

        Returns:
            List of command information dictionaries

        """
        summary = []
        for i, command in enumerate(self.command_history):
            summary.append(
                {
                    "index": i,
                    "description": command.description,
                    "type": command.operation_type.value,
                    "executed": command.executed,
                    "is_current": i == self.current_index,
                    "affected_range": command.get_affected_range(),
                }
            )
        return summary

    def set_auto_merge(self, enabled: bool):
        """Enable or disable automatic command merging."""
        self.auto_merge = enabled
        logger.debug(f"Auto-merge {'enabled' if enabled else 'disabled'}")
