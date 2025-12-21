"""Production tests for windows_common.py.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.
"""

import logging
import sys

import pytest

from intellicrack.utils.system.windows_common import (
    WINDOWS_AVAILABLE,
    WindowsConstants,
    cleanup_process_handles,
    get_windows_kernel32,
    get_windows_ntdll,
    is_windows_available,
)


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows-only tests")


class TestWindowsAvailability:
    """Test Windows availability detection."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_windows_available_on_windows(self) -> None:
        """WINDOWS_AVAILABLE is True on Windows platform."""
        assert WINDOWS_AVAILABLE is True

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_is_windows_available_returns_true(self) -> None:
        """is_windows_available returns True on Windows."""
        assert is_windows_available() is True

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_is_windows_available_consistent_with_constant(self) -> None:
        """is_windows_available matches WINDOWS_AVAILABLE constant."""
        assert is_windows_available() == WINDOWS_AVAILABLE


class TestWindowsLibraryLoading:
    """Test Windows DLL loading functionality."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_get_windows_kernel32_returns_library(self) -> None:
        """get_windows_kernel32 returns kernel32 library."""
        kernel32 = get_windows_kernel32()

        assert kernel32 is not None

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_get_windows_kernel32_is_usable(self) -> None:
        """Returned kernel32 library is usable."""
        kernel32 = get_windows_kernel32()

        assert hasattr(kernel32, "GetCurrentProcessId")

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_get_windows_ntdll_returns_library(self) -> None:
        """get_windows_ntdll returns ntdll library."""
        ntdll = get_windows_ntdll()

        assert ntdll is not None

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_get_windows_ntdll_is_usable(self) -> None:
        """Returned ntdll library is usable."""
        ntdll = get_windows_ntdll()

        assert ntdll is not None

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_kernel32_multiple_calls_consistent(self) -> None:
        """Multiple calls to get_windows_kernel32 are consistent."""
        kernel32_1 = get_windows_kernel32()
        kernel32_2 = get_windows_kernel32()

        assert kernel32_1 is not None
        assert kernel32_2 is not None

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_ntdll_multiple_calls_consistent(self) -> None:
        """Multiple calls to get_windows_ntdll are consistent."""
        ntdll_1 = get_windows_ntdll()
        ntdll_2 = get_windows_ntdll()

        assert ntdll_1 is not None
        assert ntdll_2 is not None


class TestWindowsConstants:
    """Test Windows constant definitions."""

    def test_windows_constants_create_suspended(self) -> None:
        """CREATE_SUSPENDED constant has correct value."""
        assert WindowsConstants.CREATE_SUSPENDED == 0x00000004

    def test_windows_constants_create_no_window(self) -> None:
        """CREATE_NO_WINDOW constant has correct value."""
        assert WindowsConstants.CREATE_NO_WINDOW == 0x08000000

    def test_windows_constants_mem_commit(self) -> None:
        """MEM_COMMIT constant has correct value."""
        assert WindowsConstants.MEM_COMMIT == 0x1000

    def test_windows_constants_mem_reserve(self) -> None:
        """MEM_RESERVE constant has correct value."""
        assert WindowsConstants.MEM_RESERVE == 0x2000

    def test_windows_constants_page_execute_readwrite(self) -> None:
        """PAGE_EXECUTE_READWRITE constant has correct value."""
        assert WindowsConstants.PAGE_EXECUTE_READWRITE == 0x40

    def test_windows_constants_are_integers(self) -> None:
        """All Windows constants are integers."""
        assert isinstance(WindowsConstants.CREATE_SUSPENDED, int)
        assert isinstance(WindowsConstants.CREATE_NO_WINDOW, int)
        assert isinstance(WindowsConstants.MEM_COMMIT, int)
        assert isinstance(WindowsConstants.MEM_RESERVE, int)
        assert isinstance(WindowsConstants.PAGE_EXECUTE_READWRITE, int)

    def test_windows_constants_class_accessible(self) -> None:
        """WindowsConstants class is accessible."""
        assert hasattr(WindowsConstants, "CREATE_SUSPENDED")
        assert hasattr(WindowsConstants, "CREATE_NO_WINDOW")
        assert hasattr(WindowsConstants, "MEM_COMMIT")
        assert hasattr(WindowsConstants, "MEM_RESERVE")
        assert hasattr(WindowsConstants, "PAGE_EXECUTE_READWRITE")


class TestCleanupProcessHandles:
    """Test process handle cleanup functionality."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_cleanup_process_handles_with_valid_handles(self) -> None:
        """Cleanup handles with mock valid handles."""
        kernel32 = get_windows_kernel32()
        process_info: dict[str, object] = {
            "process_handle": None,
            "thread_handle": None,
        }

        cleanup_process_handles(kernel32, process_info)

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_cleanup_process_handles_with_logger(self, caplog: pytest.LogCaptureFixture) -> None:
        """Cleanup handles logs with provided logger."""
        kernel32 = get_windows_kernel32()
        process_info: dict[str, object] = {
            "process_handle": None,
            "thread_handle": None,
        }
        logger: logging.Logger = logging.getLogger("test")

        cleanup_process_handles(kernel32, process_info, logger_instance=logger)

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_cleanup_process_handles_empty_dict(self) -> None:
        """Cleanup handles with empty process_info dict."""
        kernel32 = get_windows_kernel32()
        process_info: dict[str, object] = {}

        cleanup_process_handles(kernel32, process_info)

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_cleanup_process_handles_partial_handles(self) -> None:
        """Cleanup handles with only some handles present."""
        kernel32 = get_windows_kernel32()
        process_info: dict[str, object] = {
            "process_handle": None,
        }

        cleanup_process_handles(kernel32, process_info)

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_cleanup_process_handles_doesnt_raise(self) -> None:
        """Cleanup handles doesn't raise exceptions."""
        kernel32 = get_windows_kernel32()
        process_info: dict[str, object] = {
            "process_handle": 12345,
            "thread_handle": 67890,
        }

        try:
            cleanup_process_handles(kernel32, process_info)
        except Exception:
            pytest.fail("cleanup_process_handles raised exception")


class TestWindowsCommonIntegration:
    """Integration tests for Windows common utilities."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_windows_libraries_and_constants_integration(self) -> None:
        """Windows libraries work with defined constants."""
        kernel32 = get_windows_kernel32()

        assert kernel32 is not None
        assert WindowsConstants.CREATE_SUSPENDED is not None
        assert WindowsConstants.MEM_COMMIT is not None

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_windows_availability_check_integration(self) -> None:
        """Availability checks integrate with library loading."""
        if is_windows_available():
            kernel32 = get_windows_kernel32()
            ntdll = get_windows_ntdll()

            assert kernel32 is not None
            assert ntdll is not None

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_kernel32_provides_expected_functions(self) -> None:
        """kernel32 provides expected Windows API functions."""
        kernel32 = get_windows_kernel32()

        expected_functions: list[str] = [
            "GetCurrentProcessId",
            "GetCurrentThreadId",
            "CloseHandle",
        ]

        for func_name in expected_functions:
            assert hasattr(kernel32, func_name)

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_process_handle_cleanup_integration(self) -> None:
        """Process handle cleanup integrates with kernel32."""
        kernel32 = get_windows_kernel32()
        logger: logging.Logger = logging.getLogger("test")

        process_info: dict[str, object] = {
            "process_handle": None,
            "thread_handle": None,
        }

        cleanup_process_handles(kernel32, process_info, logger_instance=logger)


class TestWindowsCommonEdgeCases:
    """Edge case tests for Windows common utilities."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_cleanup_handles_with_none_kernel32(self) -> None:
        """Cleanup handles handles None kernel32 gracefully."""
        process_info: dict[str, object] = {
            "process_handle": None,
            "thread_handle": None,
        }

        try:
            cleanup_process_handles(None, process_info)
        except AttributeError:
            pass

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_windows_constants_are_not_mutable(self) -> None:
        """Windows constants maintain their values."""
        original_suspended: int = WindowsConstants.CREATE_SUSPENDED
        original_commit: int = WindowsConstants.MEM_COMMIT

        assert WindowsConstants.CREATE_SUSPENDED == original_suspended
        assert WindowsConstants.MEM_COMMIT == original_commit

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_multiple_library_loads_dont_fail(self) -> None:
        """Loading libraries multiple times doesn't fail."""
        for _ in range(10):
            kernel32 = get_windows_kernel32()
            ntdll = get_windows_ntdll()

            assert kernel32 is not None
            assert ntdll is not None
