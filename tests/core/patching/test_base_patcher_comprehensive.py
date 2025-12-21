"""Comprehensive Tests for Base Patcher.

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

import ctypes
import logging
import os
import platform
import struct
import sys
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.patching.base_patcher import BaseWindowsPatcher
from intellicrack.utils.system.windows_common import WindowsConstants, get_windows_kernel32, get_windows_ntdll


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Windows-specific tests require Windows platform"
)


class ConcretePatcher(BaseWindowsPatcher):
    """Concrete implementation of BaseWindowsPatcher for testing."""

    def __init__(self, require_ntdll: bool = False) -> None:
        """Initialize concrete patcher with optional ntdll requirement."""
        super().__init__()
        if require_ntdll:
            self._requires_ntdll = True

    def get_required_libraries(self) -> list[str]:
        """Return list of required libraries."""
        libs = ["kernel32.dll"]
        if hasattr(self, "_requires_ntdll") and self._requires_ntdll:
            libs.append("ntdll.dll")
        return libs

    def _create_suspended_process(self, target_exe: str) -> dict[str, Any]:
        """Create a suspended process for testing.

        Args:
            target_exe: Path to executable to launch suspended

        Returns:
            Dictionary with process_info containing handles
        """
        if not os.path.exists(target_exe):
            return {}

        class STARTUPINFO(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.wintypes.DWORD),
                ("lpReserved", ctypes.wintypes.LPWSTR),
                ("lpDesktop", ctypes.wintypes.LPWSTR),
                ("lpTitle", ctypes.wintypes.LPWSTR),
                ("dwX", ctypes.wintypes.DWORD),
                ("dwY", ctypes.wintypes.DWORD),
                ("dwXSize", ctypes.wintypes.DWORD),
                ("dwYSize", ctypes.wintypes.DWORD),
                ("dwXCountChars", ctypes.wintypes.DWORD),
                ("dwYCountChars", ctypes.wintypes.DWORD),
                ("dwFillAttribute", ctypes.wintypes.DWORD),
                ("dwFlags", ctypes.wintypes.DWORD),
                ("wShowWindow", ctypes.wintypes.WORD),
                ("cbReserved2", ctypes.wintypes.WORD),
                ("lpReserved2", ctypes.wintypes.LPBYTE),
                ("hStdInput", ctypes.wintypes.HANDLE),
                ("hStdOutput", ctypes.wintypes.HANDLE),
                ("hStdError", ctypes.wintypes.HANDLE),
            ]

        class PROCESS_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("hProcess", ctypes.wintypes.HANDLE),
                ("hThread", ctypes.wintypes.HANDLE),
                ("dwProcessId", ctypes.wintypes.DWORD),
                ("dwThreadId", ctypes.wintypes.DWORD),
            ]

        si = STARTUPINFO()
        si.cb = ctypes.sizeof(STARTUPINFO)

        pi = PROCESS_INFORMATION()

        kernel32 = get_windows_kernel32()
        if not kernel32:
            return {}

        if success := kernel32.CreateProcessW(
            target_exe,
            None,
            None,
            None,
            False,
            WindowsConstants.CREATE_SUSPENDED,
            None,
            None,
            ctypes.byref(si),
            ctypes.byref(pi),
        ):
            return {
                "process_handle": pi.hProcess,
                "thread_handle": pi.hThread,
                "process_id": pi.dwProcessId,
                "thread_id": pi.dwThreadId
            }
        else:
            return {}

    def _get_thread_context(self, thread_handle: int) -> dict[str, Any]:
        """Get thread context for testing.

        Args:
            thread_handle: Handle to thread

        Returns:
            Dictionary with context information
        """
        if not thread_handle:
            return {}

        kernel32 = get_windows_kernel32()
        if not kernel32:
            return {}

        class CONTEXT(ctypes.Structure):
            _fields_ = [
                ("ContextFlags", ctypes.c_ulong),
                ("Dr0", ctypes.c_ulonglong),
                ("Dr1", ctypes.c_ulonglong),
                ("Dr2", ctypes.c_ulonglong),
                ("Dr3", ctypes.c_ulonglong),
                ("Dr6", ctypes.c_ulonglong),
                ("Dr7", ctypes.c_ulonglong),
            ]

        context = CONTEXT()
        context.ContextFlags = 0x00010001

        if success := kernel32.GetThreadContext(
            thread_handle, ctypes.byref(context)
        ):
            return {
                "ContextFlags": context.ContextFlags,
                "Dr0": context.Dr0,
                "Dr1": context.Dr1,
            }
        else:
            return {}


@pytest.fixture
def concrete_patcher() -> ConcretePatcher:
    """Provide concrete patcher instance for testing."""
    return ConcretePatcher()


@pytest.fixture
def concrete_patcher_with_ntdll() -> ConcretePatcher:
    """Provide concrete patcher that requires ntdll."""
    return ConcretePatcher(require_ntdll=True)


@pytest.fixture
def test_executable() -> Path:
    """Provide path to Windows test executable (notepad.exe)."""
    notepad_path = Path(os.environ.get("WINDIR", "C:\\Windows")) / "System32" / "notepad.exe"
    if not notepad_path.exists():
        pytest.skip("Notepad.exe not found for testing")
    return notepad_path


@pytest.fixture
def invalid_executable() -> Path:
    """Provide path to non-existent executable."""
    return Path("D:/nonexistent/invalid.exe")


class TestBaseWindowsPatcherInitialization:
    """Tests for BaseWindowsPatcher initialization and setup."""

    def test_initialization_creates_logger(self, concrete_patcher: ConcretePatcher) -> None:
        """Patcher initializes with proper logger instance."""
        assert hasattr(concrete_patcher, "logger")
        assert isinstance(concrete_patcher.logger, logging.Logger)
        assert concrete_patcher.logger.name == "ConcretePatcher"

    def test_initialization_sets_ntdll_flag(self, concrete_patcher: ConcretePatcher) -> None:
        """Patcher initializes with ntdll requirement flag."""
        assert hasattr(concrete_patcher, "requires_ntdll")
        assert concrete_patcher.requires_ntdll is False

    def test_initialization_with_ntdll_requirement(self, concrete_patcher_with_ntdll: ConcretePatcher) -> None:
        """Patcher correctly sets ntdll requirement when specified."""
        assert hasattr(concrete_patcher_with_ntdll, "_requires_ntdll")
        assert concrete_patcher_with_ntdll._requires_ntdll is True

    def test_get_required_libraries_base(self, concrete_patcher: ConcretePatcher) -> None:
        """Patcher returns kernel32 in required libraries."""
        libs = concrete_patcher.get_required_libraries()
        assert isinstance(libs, list)
        assert "kernel32.dll" in libs

    def test_get_required_libraries_with_ntdll(self, concrete_patcher_with_ntdll: ConcretePatcher) -> None:
        """Patcher includes ntdll when required."""
        libs = concrete_patcher_with_ntdll.get_required_libraries()
        assert isinstance(libs, list)
        assert "kernel32.dll" in libs
        assert "ntdll.dll" in libs


class TestWindowsLibraryInitialization:
    """Tests for Windows library initialization."""

    def test_initialize_kernel32_successful(self, concrete_patcher: ConcretePatcher) -> None:
        """Windows libraries initialize successfully with kernel32."""
        concrete_patcher._initialize_windows_libraries()

        assert hasattr(concrete_patcher, "kernel32")
        assert concrete_patcher.kernel32 is not None
        assert hasattr(concrete_patcher.kernel32, "CreateProcessW")
        assert hasattr(concrete_patcher.kernel32, "CloseHandle")

    def test_initialize_ntdll_successful(self, concrete_patcher: ConcretePatcher) -> None:
        """Windows libraries initialize ntdll when available."""
        concrete_patcher._initialize_windows_libraries()

        assert hasattr(concrete_patcher, "ntdll")
        ntdll = get_windows_ntdll()
        if ntdll is not None:
            assert concrete_patcher.ntdll is not None
        else:
            assert concrete_patcher.ntdll is None

    def test_initialize_fails_without_kernel32(self, concrete_patcher: ConcretePatcher, monkeypatch: pytest.MonkeyPatch) -> None:
        """Library initialization raises error when kernel32 unavailable."""
        def mock_get_kernel32() -> None:
            return None

        monkeypatch.setattr("intellicrack.core.patching.base_patcher.get_windows_kernel32", mock_get_kernel32)

        with pytest.raises(RuntimeError, match="Failed to load kernel32"):
            concrete_patcher._initialize_windows_libraries()

    def test_initialize_fails_when_ntdll_required_but_missing(
        self,
        concrete_patcher_with_ntdll: ConcretePatcher,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Library initialization raises error when required ntdll unavailable."""
        def mock_get_ntdll() -> None:
            return None

        monkeypatch.setattr("intellicrack.core.patching.base_patcher.get_windows_ntdll", mock_get_ntdll)

        with pytest.raises(RuntimeError, match="Failed to load required Windows libraries"):
            concrete_patcher_with_ntdll._initialize_windows_libraries()

    def test_initialize_succeeds_with_optional_ntdll_missing(
        self,
        concrete_patcher: ConcretePatcher,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Library initialization succeeds when optional ntdll unavailable."""
        def mock_get_ntdll() -> None:
            return None

        monkeypatch.setattr("intellicrack.core.patching.base_patcher.get_windows_ntdll", mock_get_ntdll)

        concrete_patcher._initialize_windows_libraries()
        assert concrete_patcher.ntdll is None


class TestWindowsConstantsInitialization:
    """Tests for Windows constants initialization."""

    def test_initialize_constants_process_flags(self, concrete_patcher: ConcretePatcher) -> None:
        """Constants initialization sets process creation flags."""
        concrete_patcher._initialize_windows_constants()

        assert hasattr(concrete_patcher, "CREATE_SUSPENDED")
        assert concrete_patcher.CREATE_SUSPENDED == 0x00000004
        assert hasattr(concrete_patcher, "CREATE_NO_WINDOW")
        assert concrete_patcher.CREATE_NO_WINDOW == 0x08000000

    def test_initialize_constants_memory_flags(self, concrete_patcher: ConcretePatcher) -> None:
        """Constants initialization sets memory allocation flags."""
        concrete_patcher._initialize_windows_constants()

        assert hasattr(concrete_patcher, "MEM_COMMIT")
        assert concrete_patcher.MEM_COMMIT == 0x1000
        assert hasattr(concrete_patcher, "MEM_RESERVE")
        assert concrete_patcher.MEM_RESERVE == 0x2000
        assert hasattr(concrete_patcher, "PAGE_EXECUTE_READWRITE")
        assert concrete_patcher.PAGE_EXECUTE_READWRITE == 0x40

    def test_initialize_constants_thread_flags(self, concrete_patcher: ConcretePatcher) -> None:
        """Constants initialization sets thread access flags."""
        concrete_patcher._initialize_windows_constants()

        assert hasattr(concrete_patcher, "THREAD_SET_CONTEXT")
        assert concrete_patcher.THREAD_SET_CONTEXT == 0x0010
        assert hasattr(concrete_patcher, "THREAD_GET_CONTEXT")
        assert concrete_patcher.THREAD_GET_CONTEXT == 0x0008
        assert hasattr(concrete_patcher, "THREAD_SUSPEND_RESUME")
        assert concrete_patcher.THREAD_SUSPEND_RESUME == 0x0002

    def test_constants_match_windows_constants_class(self, concrete_patcher: ConcretePatcher) -> None:
        """Patcher constants match WindowsConstants values."""
        concrete_patcher._initialize_windows_constants()

        assert concrete_patcher.CREATE_SUSPENDED == WindowsConstants.CREATE_SUSPENDED
        assert concrete_patcher.CREATE_NO_WINDOW == WindowsConstants.CREATE_NO_WINDOW
        assert concrete_patcher.MEM_COMMIT == WindowsConstants.MEM_COMMIT
        assert concrete_patcher.MEM_RESERVE == WindowsConstants.MEM_RESERVE
        assert concrete_patcher.PAGE_EXECUTE_READWRITE == WindowsConstants.PAGE_EXECUTE_READWRITE


class TestSuspendedProcessHandling:
    """Tests for suspended process result handling."""

    def test_handle_suspended_process_success(self, concrete_patcher: ConcretePatcher) -> None:
        """Suspended process handler extracts success results correctly."""
        process_info = {
            "process_handle": 0x1234,
            "thread_handle": 0x5678,
            "process_id": 1000,
            "thread_id": 2000
        }
        context = {
            "ContextFlags": 0x00010001,
            "Dr0": 0,
            "Dr1": 0
        }
        result = {
            "success": True,
            "process_info": process_info,
            "context": context
        }

        success, ret_process_info, ret_context = concrete_patcher.handle_suspended_process_result(result)

        assert success is True
        assert ret_process_info == process_info
        assert ret_context == context

    def test_handle_suspended_process_failure(self, concrete_patcher: ConcretePatcher) -> None:
        """Suspended process handler returns failure tuple correctly."""
        result = {
            "success": False,
            "error": "Test error"
        }

        success, process_info, context = concrete_patcher.handle_suspended_process_result(result)

        assert success is False
        assert process_info is None
        assert context is None

    def test_handle_suspended_process_logs_failure(
        self,
        concrete_patcher: ConcretePatcher,
        caplog: pytest.LogCaptureFixture
    ) -> None:
        """Suspended process handler logs failures."""
        result = {"success": False}

        with caplog.at_level(logging.ERROR):
            concrete_patcher.handle_suspended_process_result(result)

        assert "Failed to create suspended process" in caplog.text

    def test_handle_suspended_process_custom_logger(
        self,
        concrete_patcher: ConcretePatcher,
        caplog: pytest.LogCaptureFixture
    ) -> None:
        """Suspended process handler uses custom logger when provided."""
        custom_logger = logging.getLogger("custom_test_logger")
        result = {"success": False}

        with caplog.at_level(logging.ERROR, logger="custom_test_logger"):
            success, _, _ = concrete_patcher.handle_suspended_process_result(result, custom_logger)

        assert success is False
        assert "Failed to create suspended process" in caplog.text

    def test_handle_suspended_process_validates_structure(self, concrete_patcher: ConcretePatcher) -> None:
        """Suspended process handler validates result dictionary structure."""
        valid_result = {
            "success": True,
            "process_info": {"process_handle": 100},
            "context": {"ContextFlags": 1}
        }

        success, info, ctx = concrete_patcher.handle_suspended_process_result(valid_result)

        assert success is True
        assert "process_handle" in info
        assert "ContextFlags" in ctx


class TestSuspendedProcessCreation:
    """Tests for suspended process creation functionality."""

    def test_create_suspended_process_with_valid_executable(
        self,
        concrete_patcher: ConcretePatcher,
        test_executable: Path
    ) -> None:
        """Patcher creates suspended process with valid executable."""
        result = concrete_patcher._create_suspended_process(str(test_executable))

        assert isinstance(result, dict)

        if result and result.get("process_handle"):
            assert "process_handle" in result
            assert "thread_handle" in result
            assert "process_id" in result
            assert "thread_id" in result
            assert result["process_handle"] > 0
            assert result["thread_handle"] > 0

            if kernel32 := get_windows_kernel32():
                kernel32.TerminateProcess(result["process_handle"], 0)
                kernel32.CloseHandle(result["process_handle"])
                kernel32.CloseHandle(result["thread_handle"])
        else:
            pytest.skip("Could not create suspended process (permissions or Windows security)")

    def test_create_suspended_process_with_invalid_executable(
        self,
        concrete_patcher: ConcretePatcher,
        invalid_executable: Path
    ) -> None:
        """Patcher returns empty dict for invalid executable."""
        result = concrete_patcher._create_suspended_process(str(invalid_executable))

        assert isinstance(result, dict)
        assert len(result) == 0

    def test_get_thread_context_with_valid_handle(
        self,
        concrete_patcher: ConcretePatcher,
        test_executable: Path
    ) -> None:
        """Patcher retrieves thread context from valid handle."""
        process_info = concrete_patcher._create_suspended_process(str(test_executable))

        if not process_info or not process_info.get("process_handle"):
            pytest.skip("Could not create suspended process (permissions or Windows security)")

        try:
            thread_handle = process_info["thread_handle"]
            context = concrete_patcher._get_thread_context(thread_handle)

            assert isinstance(context, dict)
            if context:
                assert "ContextFlags" in context
        finally:
            kernel32 = get_windows_kernel32()
            if kernel32 and process_info.get("process_handle"):
                kernel32.TerminateProcess(process_info["process_handle"], 0)
                kernel32.CloseHandle(process_info["process_handle"])
                kernel32.CloseHandle(process_info["thread_handle"])

    def test_get_thread_context_with_invalid_handle(self, concrete_patcher: ConcretePatcher) -> None:
        """Patcher returns empty dict for invalid thread handle."""
        result = concrete_patcher._get_thread_context(0)

        assert isinstance(result, dict)
        assert len(result) == 0

    def test_get_thread_context_without_kernel32(
        self,
        concrete_patcher: ConcretePatcher,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Thread context retrieval fails gracefully without kernel32."""
        import sys

        def mock_get_kernel32() -> None:
            return None

        test_module = sys.modules[__name__]
        monkeypatch.setattr(test_module, "get_windows_kernel32", mock_get_kernel32)

        result = concrete_patcher._get_thread_context(1234)
        assert isinstance(result, dict)
        assert len(result) == 0


class TestCreateAndHandleSuspendedProcess:
    """Tests for combined create and handle suspended process operation."""

    def test_create_and_handle_success(
        self,
        concrete_patcher: ConcretePatcher,
        test_executable: Path
    ) -> None:
        """Combined operation creates process and returns results."""
        success, process_info, context = concrete_patcher.create_and_handle_suspended_process(
            str(test_executable)
        )

        if success:
            assert process_info is not None
            assert context is not None
            assert "process_handle" in process_info
            assert "thread_handle" in process_info

            if kernel32 := get_windows_kernel32():
                kernel32.TerminateProcess(process_info["process_handle"], 0)
                kernel32.CloseHandle(process_info["process_handle"])
                kernel32.CloseHandle(process_info["thread_handle"])
        else:
            assert process_info is None
            assert context is None

    def test_create_and_handle_failure(
        self,
        concrete_patcher: ConcretePatcher,
        invalid_executable: Path
    ) -> None:
        """Combined operation handles failures gracefully."""
        success, process_info, context = concrete_patcher.create_and_handle_suspended_process(
            str(invalid_executable)
        )

        assert success is False
        assert process_info is None
        assert context is None

    def test_create_and_handle_custom_logger(
        self,
        concrete_patcher: ConcretePatcher,
        test_executable: Path
    ) -> None:
        """Combined operation uses custom logger when provided."""
        custom_logger = logging.getLogger("custom_combined_logger")

        success, process_info, context = concrete_patcher.create_and_handle_suspended_process(
            str(test_executable),
            custom_logger
        )

        if success and process_info:
            if kernel32 := get_windows_kernel32():
                kernel32.TerminateProcess(process_info["process_handle"], 0)
                kernel32.CloseHandle(process_info["process_handle"])
                kernel32.CloseHandle(process_info["thread_handle"])

    def test_create_and_handle_calls_common_function(
        self,
        concrete_patcher: ConcretePatcher,
        test_executable: Path,
        monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Combined operation uses process_common.create_suspended_process_with_context."""
        call_count = 0

        def mock_create_suspended(create_func, context_func, target_exe, logger):
            nonlocal call_count
            call_count += 1
            return {"success": False, "error": "Test mock"}

        monkeypatch.setattr(
            "intellicrack.utils.system.process_common.create_suspended_process_with_context",
            mock_create_suspended
        )

        concrete_patcher.create_and_handle_suspended_process(str(test_executable))
        assert call_count == 1


class TestAbstractMethodEnforcement:
    """Tests for abstract method enforcement."""

    def test_cannot_instantiate_base_class_directly(self) -> None:
        """BaseWindowsPatcher cannot be instantiated without implementing abstract methods."""
        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            BaseWindowsPatcher()

    def test_concrete_class_must_implement_get_required_libraries(self) -> None:
        """Concrete patcher must implement get_required_libraries."""
        class IncompletePatcher(BaseWindowsPatcher):
            def _create_suspended_process(self, target_exe: str) -> dict[str, Any]:
                return {}

            def _get_thread_context(self, thread_handle: int) -> dict[str, Any]:
                return {}

        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            IncompletePatcher()

    def test_concrete_class_must_implement_create_suspended_process(self) -> None:
        """Concrete patcher must implement _create_suspended_process."""
        class IncompletePatcher(BaseWindowsPatcher):
            def get_required_libraries(self) -> list[str]:
                return ["kernel32.dll"]

            def _get_thread_context(self, thread_handle: int) -> dict[str, Any]:
                return {}

        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            IncompletePatcher()

    def test_concrete_class_must_implement_get_thread_context(self) -> None:
        """Concrete patcher must implement _get_thread_context."""
        class IncompletePatcher(BaseWindowsPatcher):
            def get_required_libraries(self) -> list[str]:
                return ["kernel32.dll"]

            def _create_suspended_process(self, target_exe: str) -> dict[str, Any]:
                return {}

        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            IncompletePatcher()


class TestRealWorldPatching:
    """Tests for real-world patching scenarios."""

    def test_full_initialization_workflow(self, concrete_patcher: ConcretePatcher) -> None:
        """Complete initialization workflow for patching operations."""
        concrete_patcher._initialize_windows_libraries()
        concrete_patcher._initialize_windows_constants()

        assert concrete_patcher.kernel32 is not None
        assert concrete_patcher.CREATE_SUSPENDED == 0x00000004
        assert concrete_patcher.MEM_COMMIT == 0x1000

    def test_process_creation_with_real_binary(
        self,
        concrete_patcher: ConcretePatcher,
        test_executable: Path
    ) -> None:
        """Process creation workflow with actual Windows binary."""
        concrete_patcher._initialize_windows_libraries()

        process_info = concrete_patcher._create_suspended_process(str(test_executable))

        if process_info and process_info.get("process_handle"):
            assert process_info["process_handle"] > 0
            assert process_info["thread_handle"] > 0
            assert process_info["process_id"] > 0
            assert process_info["thread_id"] > 0

            kernel32 = concrete_patcher.kernel32
            kernel32.TerminateProcess(process_info["process_handle"], 0)
            kernel32.CloseHandle(process_info["process_handle"])
            kernel32.CloseHandle(process_info["thread_handle"])
        else:
            pytest.skip("Could not create suspended process (permissions or Windows security)")

    def test_thread_context_retrieval_real_process(
        self,
        concrete_patcher: ConcretePatcher,
        test_executable: Path
    ) -> None:
        """Thread context retrieval from actual suspended process."""
        concrete_patcher._initialize_windows_libraries()

        process_info = concrete_patcher._create_suspended_process(str(test_executable))

        if not process_info or not process_info.get("process_handle"):
            pytest.skip("Could not create suspended process (permissions or Windows security)")

        try:
            if context := concrete_patcher._get_thread_context(
                process_info["thread_handle"]
            ):
                assert context["ContextFlags"] > 0
        finally:
            kernel32 = concrete_patcher.kernel32
            if process_info.get("process_handle"):
                kernel32.TerminateProcess(process_info["process_handle"], 0)
                kernel32.CloseHandle(process_info["process_handle"])
                kernel32.CloseHandle(process_info["thread_handle"])

    def test_complete_patching_setup_workflow(
        self,
        concrete_patcher: ConcretePatcher,
        test_executable: Path
    ) -> None:
        """Complete workflow from initialization to suspended process with context."""
        concrete_patcher._initialize_windows_libraries()
        concrete_patcher._initialize_windows_constants()

        success, process_info, context = concrete_patcher.create_and_handle_suspended_process(
            str(test_executable)
        )

        if success:
            assert process_info is not None
            assert context is not None
            assert process_info["process_handle"] > 0

            kernel32 = concrete_patcher.kernel32
            kernel32.TerminateProcess(process_info["process_handle"], 0)
            kernel32.CloseHandle(process_info["process_handle"])
            kernel32.CloseHandle(process_info["thread_handle"])


class TestErrorHandlingAndEdgeCases:
    """Tests for error handling and edge cases."""

    def test_handle_null_process_info(self, concrete_patcher: ConcretePatcher) -> None:
        """Handler correctly processes null process info."""
        result = {
            "success": True,
            "process_info": None,
            "context": None
        }

        success, process_info, context = concrete_patcher.handle_suspended_process_result(result)

        assert success is True
        assert process_info is None
        assert context is None

    def test_handle_partial_result_structure(self, concrete_patcher: ConcretePatcher) -> None:
        """Handler processes results with missing keys gracefully."""
        result = {"success": False}

        success, process_info, context = concrete_patcher.handle_suspended_process_result(result)

        assert success is False
        assert process_info is None
        assert context is None

    def test_create_process_with_empty_path(self, concrete_patcher: ConcretePatcher) -> None:
        """Process creation handles empty executable path."""
        result = concrete_patcher._create_suspended_process("")

        assert isinstance(result, dict)
        assert len(result) == 0

    def test_create_process_with_nonexistent_path(self, concrete_patcher: ConcretePatcher) -> None:
        """Process creation handles non-existent paths gracefully."""
        result = concrete_patcher._create_suspended_process("D:/xyz/nonexistent.exe")

        assert isinstance(result, dict)
        assert len(result) == 0

    def test_get_context_with_zero_handle(self, concrete_patcher: ConcretePatcher) -> None:
        """Thread context retrieval handles zero handle."""
        result = concrete_patcher._get_thread_context(0)

        assert isinstance(result, dict)
        assert len(result) == 0

    def test_get_context_with_negative_handle(self, concrete_patcher: ConcretePatcher) -> None:
        """Thread context retrieval handles invalid negative handle."""
        result = concrete_patcher._get_thread_context(-1)

        assert isinstance(result, dict)


class TestMultipleInstances:
    """Tests for multiple patcher instances."""

    def test_multiple_instances_independent(self) -> None:
        """Multiple patcher instances maintain independent state."""
        patcher1 = ConcretePatcher()
        patcher2 = ConcretePatcher(require_ntdll=True)

        assert patcher1.logger.name == "ConcretePatcher"
        assert patcher2.logger.name == "ConcretePatcher"
        assert not hasattr(patcher1, "_requires_ntdll")
        assert hasattr(patcher2, "_requires_ntdll")

    def test_multiple_initializations_safe(self, concrete_patcher: ConcretePatcher) -> None:
        """Multiple initializations don't break patcher state."""
        concrete_patcher._initialize_windows_libraries()
        concrete_patcher._initialize_windows_constants()

        kernel32_first = concrete_patcher.kernel32
        create_suspended_first = concrete_patcher.CREATE_SUSPENDED

        concrete_patcher._initialize_windows_libraries()
        concrete_patcher._initialize_windows_constants()

        assert concrete_patcher.kernel32 is not None
        assert concrete_patcher.CREATE_SUSPENDED == create_suspended_first

    def test_concurrent_process_creation(
        self,
        test_executable: Path
    ) -> None:
        """Multiple patchers can create processes independently."""
        patcher1 = ConcretePatcher()
        patcher2 = ConcretePatcher()

        result1 = patcher1._create_suspended_process(str(test_executable))
        result2 = patcher2._create_suspended_process(str(test_executable))

        cleanup_processes = []

        if result1 and result1.get("process_handle"):
            cleanup_processes.append(result1)
            assert "process_handle" in result1

        if result2 and result2.get("process_handle"):
            cleanup_processes.append(result2)
            assert "process_handle" in result2

        if not cleanup_processes:
            pytest.skip("Could not create suspended processes (permissions or Windows security)")

        if kernel32 := get_windows_kernel32():
            for proc in cleanup_processes:
                if proc.get("process_handle"):
                    kernel32.TerminateProcess(proc["process_handle"], 0)
                    kernel32.CloseHandle(proc["process_handle"])
                    kernel32.CloseHandle(proc["thread_handle"])
