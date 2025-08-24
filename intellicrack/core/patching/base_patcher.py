"""This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import logging
from abc import ABC, abstractmethod
from typing import Any

from ...utils.system.windows_common import WindowsConstants, get_windows_kernel32, get_windows_ntdll

"""
Base Patcher Module

Provides common functionality for Windows patching operations.
"""


class BaseWindowsPatcher(ABC):
    """Base class for Windows patching operations.
    Provides common Windows constants and library initialization.
    """

    def __init__(self):
        """Initialize the base Windows patcher with logging and NTDLL detection."""
        self.logger = logging.getLogger(self.__class__.__name__)
        # Optional flag that derived classes can set to require ntdll
        self.requires_ntdll = False

    def _initialize_windows_libraries(self):
        """Initialize Windows libraries required for patching operations."""
        self.kernel32 = get_windows_kernel32()
        if not self.kernel32:
            raise RuntimeError("Failed to load kernel32")

        # Optional ntdll loading for classes that need it
        self.ntdll = get_windows_ntdll()
        if hasattr(self, "_requires_ntdll") and self._requires_ntdll and not self.ntdll:
            raise RuntimeError("Failed to load required Windows libraries")

    def _initialize_windows_constants(self):
        """Initialize common Windows constants for patching operations."""
        # Process creation constants
        self.CREATE_SUSPENDED = WindowsConstants.CREATE_SUSPENDED
        self.CREATE_NO_WINDOW = WindowsConstants.CREATE_NO_WINDOW

        # Memory allocation constants
        self.MEM_COMMIT = WindowsConstants.MEM_COMMIT
        self.MEM_RESERVE = WindowsConstants.MEM_RESERVE
        self.PAGE_EXECUTE_READWRITE = WindowsConstants.PAGE_EXECUTE_READWRITE

        # Thread constants
        self.THREAD_SET_CONTEXT = 0x0010
        self.THREAD_GET_CONTEXT = 0x0008
        self.THREAD_SUSPEND_RESUME = 0x0002

    def handle_suspended_process_result(self, result, logger_instance=None):
        """Common pattern for handling suspended process creation result.

        Args:
            result: Result from create_suspended_process_with_context
            logger_instance: Logger instance to use (defaults to self.logger)

        Returns:
            Tuple of (success, process_info, context) or (False, None, None)

        """
        if logger_instance is None:
            logger_instance = self.logger

        if not result["success"]:
            logger_instance.error("Failed to create suspended process")
            return False, None, None

        process_info = result["process_info"]
        context = result["context"]

        return True, process_info, context

    def create_and_handle_suspended_process(
        self, target_exe: str, logger_instance=None
    ) -> tuple[bool, Any, Any]:
        """Create a suspended process and handle the result in one operation.
        Common pattern to eliminate duplication between early bird injection and process hollowing.

        Args:
            target_exe: Path to target executable
            logger_instance: Optional logger instance to use

        Returns:
            Tuple of (success, process_info, context) or (False, None, None)

        """
        from ...utils.system.process_common import create_suspended_process_with_context

        if logger_instance is None:
            logger_instance = self.logger

        # Create process and get context using common function
        result = create_suspended_process_with_context(
            self._create_suspended_process,
            self._get_thread_context,
            target_exe,
            logger_instance,
        )

        return self.handle_suspended_process_result(result, logger_instance)

    @abstractmethod
    def get_required_libraries(self) -> list:
        """Get list of required Windows libraries for this patcher."""

    @abstractmethod
    def _create_suspended_process(self, target_exe: str):
        """Create a suspended process."""

    @abstractmethod
    def _get_thread_context(self, thread_handle):
        """Get thread context."""
