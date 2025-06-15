"""
Base Patcher Module

Provides common functionality for Windows patching operations.
"""

import logging
from abc import ABC, abstractmethod

from ...utils.windows_common import WindowsConstants, get_windows_kernel32, get_windows_ntdll


class BaseWindowsPatcher(ABC):
    """
    Base class for Windows patching operations.
    Provides common Windows constants and library initialization.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self._initialize_windows_libraries()
        self._initialize_windows_constants()
    
    def _initialize_windows_libraries(self):
        """Initialize Windows libraries required for patching operations."""
        self.kernel32 = get_windows_kernel32()
        if not self.kernel32:
            raise RuntimeError("Failed to load kernel32")
        
        # Optional ntdll loading for classes that need it
        self.ntdll = get_windows_ntdll()
        if hasattr(self, '_requires_ntdll') and self._requires_ntdll and not self.ntdll:
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
        """
        Common pattern for handling suspended process creation result.
        
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

    @abstractmethod
    def get_required_libraries(self) -> list:
        """Get list of required Windows libraries for this patcher."""
        pass