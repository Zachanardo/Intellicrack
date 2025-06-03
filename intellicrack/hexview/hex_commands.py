"""
Command system for hex editor operations with undo/redo support.

This module provides a command pattern implementation for all hex editor
operations, enabling comprehensive undo/redo functionality.
"""

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Union
from enum import Enum

logger = logging.getLogger(__name__)

__all__ = [
    'HexCommand', 'CommandManager', 'OperationType',
    'ReplaceCommand', 'InsertCommand', 'DeleteCommand',
    'FillCommand', 'PasteCommand'
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
        self.description = description
        self.operation_type = operation_type
        self.timestamp = None
        self.executed = False
        
    @abstractmethod
    def execute(self, file_handler) -> bool:
        """
        Execute the command.
        
        Args:
            file_handler: VirtualFileAccess instance
            
        Returns:
            True if successful, False otherwise
        """
        pass
        
    @abstractmethod
    def undo(self, file_handler) -> bool:
        """
        Undo the command.
        
        Args:
            file_handler: VirtualFileAccess instance
            
        Returns:
            True if successful, False otherwise
        """
        pass
        
    @abstractmethod
    def get_affected_range(self) -> tuple:
        """
        Get the range of bytes affected by this command.
        
        Returns:
            Tuple of (start_offset, end_offset)
        """
        pass
        
    def can_merge_with(self, other: 'HexCommand') -> bool:
        """
        Check if this command can be merged with another command.
        
        Args:
            other: Another command
            
        Returns:
            True if commands can be merged
        """
        return False
        
    def merge_with(self, other: 'HexCommand') -> 'HexCommand':
        """
        Merge this command with another command.
        
        Args:
            other: Another command to merge with
            
        Returns:
            New merged command
        """
        raise NotImplementedError("Command merging not implemented")


class ReplaceCommand(HexCommand):
    """Command for replacing bytes at a specific offset."""
    
    def __init__(self, offset: int, new_data: bytes, old_data: bytes = None):
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
        except Exception as e:
            logger.error(f"Error executing replace command: {e}")
            return False
            
    def undo(self, file_handler) -> bool:
        """Undo the replace operation."""
        try:
            if not self.executed or self.old_data is None:
                return False
                
            success = file_handler.write(self.offset, self.old_data)
            if success:
                self.executed = False
                logger.debug(f"Undid replace of {len(self.old_data)} bytes at offset 0x{self.offset:X}")
            return success
        except Exception as e:
            logger.error(f"Error undoing replace command: {e}")
            return False
            
    def get_affected_range(self) -> tuple:
        """Get the affected byte range."""
        return (self.offset, self.offset + len(self.new_data))
        
    def can_merge_with(self, other: 'HexCommand') -> bool:
        """Check if this command can be merged with a consecutive replace."""
        if not isinstance(other, ReplaceCommand):
            return False
            
        # Can merge if the operations are adjacent
        this_end = self.offset + len(self.new_data)
        return other.offset == this_end
        
    def merge_with(self, other: 'HexCommand') -> 'HexCommand':
        """Merge with another replace command."""
        if not self.can_merge_with(other):
            raise ValueError("Cannot merge non-adjacent replace commands")
            
        # Combine the data
        combined_new_data = self.new_data + other.new_data
        combined_old_data = self.old_data + other.old_data if self.old_data and other.old_data else None
        
        return ReplaceCommand(self.offset, combined_new_data, combined_old_data)


class InsertCommand(HexCommand):
    """Command for inserting bytes at a specific offset."""
    
    def __init__(self, offset: int, data: bytes):
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
        except Exception as e:
            logger.error(f"Error executing insert command: {e}")
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
        except Exception as e:
            logger.error(f"Error undoing insert command: {e}")
            return False
            
    def get_affected_range(self) -> tuple:
        """Get the affected byte range."""
        return (self.offset, self.offset + len(self.data))


class DeleteCommand(HexCommand):
    """Command for deleting bytes at a specific offset."""
    
    def __init__(self, offset: int, length: int, deleted_data: bytes = None):
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
                logger.debug(f"Deleted {self.length} bytes at offset 0x{self.offset:X}")
            return success
        except Exception as e:
            logger.error(f"Error executing delete command: {e}")
            return False
            
    def undo(self, file_handler) -> bool:
        """Undo the delete operation."""
        try:
            if not self.executed or self.deleted_data is None:
                return False
                
            success = file_handler.insert(self.offset, self.deleted_data)
            if success:
                self.executed = False
                logger.debug(f"Undid delete of {self.length} bytes at offset 0x{self.offset:X}")
            return success
        except Exception as e:
            logger.error(f"Error undoing delete command: {e}")
            return False
            
    def get_affected_range(self) -> tuple:
        """Get the affected byte range."""
        return (self.offset, self.offset + self.length)


class FillCommand(HexCommand):
    """Command for filling a range with a specific value."""
    
    def __init__(self, offset: int, length: int, fill_value: int, old_data: bytes = None):
        super().__init__(f"Fill {length} bytes at 0x{offset:X} with 0x{fill_value:02X}", OperationType.FILL)
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
                logger.debug(f"Filled {self.length} bytes at offset 0x{self.offset:X} with 0x{self.fill_value:02X}")
            return success
        except Exception as e:
            logger.error(f"Error executing fill command: {e}")
            return False
            
    def undo(self, file_handler) -> bool:
        """Undo the fill operation."""
        try:
            if not self.executed or self.old_data is None:
                return False
                
            success = file_handler.write(self.offset, self.old_data)
            if success:
                self.executed = False
                logger.debug(f"Undid fill of {self.length} bytes at offset 0x{self.offset:X}")
            return success
        except Exception as e:
            logger.error(f"Error undoing fill command: {e}")
            return False
            
    def get_affected_range(self) -> tuple:
        """Get the affected byte range."""
        return (self.offset, self.offset + self.length)


class PasteCommand(HexCommand):
    """Command for pasting data at a specific offset."""
    
    def __init__(self, offset: int, data: bytes, insert_mode: bool = False, old_data: bytes = None):
        mode_str = "insert" if insert_mode else "overwrite"
        super().__init__(f"Paste {len(data)} bytes at 0x{offset:X} ({mode_str})", OperationType.PASTE)
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
                logger.debug(f"Pasted {len(self.data)} bytes at offset 0x{self.offset:X} ({mode_str})")
            return success
        except Exception as e:
            logger.error(f"Error executing paste command: {e}")
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
                logger.debug(f"Undid paste ({mode_str}) of {len(self.data)} bytes at offset 0x{self.offset:X}")
            return success
        except Exception as e:
            logger.error(f"Error undoing paste command: {e}")
            return False
            
    def get_affected_range(self) -> tuple:
        """Get the affected byte range."""
        return (self.offset, self.offset + len(self.data))


class CommandManager:
    """Manages command execution and undo/redo functionality."""
    
    def __init__(self, max_history: int = 100):
        self.max_history = max_history
        self.command_history: List[HexCommand] = []
        self.current_index = -1
        self.file_handler = None
        self.auto_merge = True
        
    def set_file_handler(self, file_handler):
        """Set the file handler for command execution."""
        self.file_handler = file_handler
        
    def execute_command(self, command: HexCommand) -> bool:
        """
        Execute a command and add it to the history.
        
        Args:
            command: Command to execute
            
        Returns:
            True if successful, False otherwise
        """
        if not self.file_handler:
            logger.error("No file handler set for command execution")
            return False
            
        # Try to merge with previous command if auto-merge is enabled
        if (self.auto_merge and self.command_history and 
            self.current_index >= 0 and self.current_index < len(self.command_history)):
            
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
                        logger.debug(f"Merged command: {merged_command.description}")
                        return True
                    else:
                        # If merge fails, re-execute the last command and continue with normal execution
                        last_command.execute(self.file_handler)
                except Exception as e:
                    logger.warning(f"Command merge failed: {e}")
                    # Continue with normal execution
        
        # Execute the command
        if not command.execute(self.file_handler):
            return False
            
        # Remove any commands after the current index (redo history)
        if self.current_index < len(self.command_history) - 1:
            self.command_history = self.command_history[:self.current_index + 1]
            
        # Add the command to history
        self.command_history.append(command)
        self.current_index += 1
        
        # Maintain maximum history size
        if len(self.command_history) > self.max_history:
            self.command_history.pop(0)
            self.current_index -= 1
            
        logger.debug(f"Executed command: {command.description}")
        return True
        
    def undo(self) -> bool:
        """
        Undo the last command.
        
        Returns:
            True if successful, False otherwise
        """
        if not self.can_undo():
            return False
            
        command = self.command_history[self.current_index]
        if command.undo(self.file_handler):
            self.current_index -= 1
            logger.debug(f"Undid command: {command.description}")
            return True
        else:
            logger.error(f"Failed to undo command: {command.description}")
            return False
            
    def redo(self) -> bool:
        """
        Redo the next command.
        
        Returns:
            True if successful, False otherwise
        """
        if not self.can_redo():
            return False
            
        command = self.command_history[self.current_index + 1]
        if command.execute(self.file_handler):
            self.current_index += 1
            logger.debug(f"Redid command: {command.description}")
            return True
        else:
            logger.error(f"Failed to redo command: {command.description}")
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
        
    def get_undo_description(self) -> Optional[str]:
        """Get description of the command that would be undone."""
        if self.can_undo():
            return self.command_history[self.current_index].description
        return None
        
    def get_redo_description(self) -> Optional[str]:
        """Get description of the command that would be redone."""
        if self.can_redo():
            return self.command_history[self.current_index + 1].description
        return None
        
    def get_history_summary(self) -> List[Dict[str, Any]]:
        """
        Get a summary of the command history.
        
        Returns:
            List of command information dictionaries
        """
        summary = []
        for i, command in enumerate(self.command_history):
            summary.append({
                'index': i,
                'description': command.description,
                'type': command.operation_type.value,
                'executed': command.executed,
                'is_current': i == self.current_index,
                'affected_range': command.get_affected_range()
            })
        return summary
        
    def set_auto_merge(self, enabled: bool):
        """Enable or disable automatic command merging."""
        self.auto_merge = enabled
        logger.debug(f"Auto-merge {'enabled' if enabled else 'disabled'}")