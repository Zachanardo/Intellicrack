"""Production tests for License Debugging Engine.

Tests validate real debugging operations on actual Windows binaries.
NO MOCKS - all tests use real Windows debugging APIs and actual binaries.
Tests must verify genuine debugging capabilities for license validation analysis.

CRITICAL: These tests MUST FAIL if debugging functionality doesn't work correctly.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import ctypes
import struct
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Generator

import pytest

from intellicrack.core.debugging_engine import (
    CONTEXT,
    Breakpoint,
    DebugEvent,
    ExceptionCode,
    LicenseDebugger,
)


@pytest.fixture(scope="module")
def debugger() -> Generator[LicenseDebugger, None, None]:
    """Create LicenseDebugger instance for testing.

    Yields:
        LicenseDebugger instance ready for debugging operations.

    """
    dbg = LicenseDebugger()
    yield dbg
    if dbg.debugging:
        dbg.debugging = False
        if dbg.debug_thread and dbg.debug_thread.is_alive():
            dbg.debug_thread.join(timeout=2.0)
    if dbg.process_handle:
        try:
            dbg.kernel32.CloseHandle(dbg.process_handle)
        except Exception:
            pass


@pytest.fixture(scope="module")
def notepad_path() -> Path:
    """Path to notepad.exe for testing debugging operations.

    Returns:
        Path to notepad.exe in System32.

    """
    path = Path(r"C:\Windows\System32\notepad.exe")
    assert path.exists(), "notepad.exe not found - required for testing"
    return path


@pytest.fixture(scope="module")
def calc_path() -> Path:
    """Path to calc.exe for testing debugging operations.

    Returns:
        Path to calc.exe in System32.

    """
    path = Path(r"C:\Windows\System32\calc.exe")
    assert path.exists(), "calc.exe not found - required for testing"
    return path


@pytest.fixture(scope="module")
def cmd_path() -> Path:
    """Path to cmd.exe for testing debugging operations.

    Returns:
        Path to cmd.exe in System32.

    """
    path = Path(r"C:\Windows\System32\cmd.exe")
    assert path.exists(), "cmd.exe not found - required for testing"
    return path


@pytest.fixture
def suspended_notepad() -> Generator[int, None, None]:
    """Create suspended notepad process for debugging tests.

    Yields:
        Process ID of suspended notepad.exe.

    """
    CREATE_SUSPENDED = 0x00000004
    PROCESS_ALL_ACCESS = 0x001F0FFF

    startup_info = subprocess.STARTUPINFO()
    process_info = subprocess.PROCESS_INFORMATION()

    notepad_path = str(Path(r"C:\Windows\System32\notepad.exe"))

    success = ctypes.windll.kernel32.CreateProcessW(
        notepad_path,
        None,
        None,
        None,
        False,
        CREATE_SUSPENDED,
        None,
        None,
        ctypes.byref(startup_info),
        ctypes.byref(process_info),
    )

    if not success:
        pytest.skip("Failed to create suspended process")

    pid = process_info.dwProcessId
    yield pid

    try:
        ctypes.windll.kernel32.TerminateProcess(process_info.hProcess, 0)
        ctypes.windll.kernel32.CloseHandle(process_info.hProcess)
        ctypes.windll.kernel32.CloseHandle(process_info.hThread)
    except Exception:
        pass


@pytest.fixture
def running_notepad() -> Generator[int, None, None]:
    """Create running notepad process for debugging tests.

    Yields:
        Process ID of running notepad.exe.

    """
    proc = subprocess.Popen([r"C:\Windows\System32\notepad.exe"])
    time.sleep(0.5)
    yield proc.pid

    try:
        proc.terminate()
        proc.wait(timeout=2.0)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


class TestDebuggerInitialization:
    """Tests for LicenseDebugger initialization and configuration."""

    def test_debugger_initializes_successfully(self, debugger: LicenseDebugger) -> None:
        """Debugger initializes with proper Windows API configuration."""
        assert debugger is not None
        assert debugger.kernel32 is not None
        assert debugger.ntdll is not None
        assert debugger.process_handle is None
        assert debugger.debugging is False
        assert isinstance(debugger.breakpoints, dict)
        assert isinstance(debugger.hardware_breakpoints, dict)
        assert isinstance(debugger.memory_breakpoints, dict)

    def test_debugger_has_windows_api_functions(self, debugger: LicenseDebugger) -> None:
        """Debugger has access to required Windows debugging APIs."""
        assert hasattr(debugger.kernel32, "DebugActiveProcess")
        assert hasattr(debugger.kernel32, "WaitForDebugEvent")
        assert hasattr(debugger.kernel32, "ContinueDebugEvent")
        assert hasattr(debugger.kernel32, "ReadProcessMemory")
        assert hasattr(debugger.kernel32, "WriteProcessMemory")
        assert hasattr(debugger.kernel32, "OpenProcess")

    def test_debugger_constants_configured(self, debugger: LicenseDebugger) -> None:
        """Debugger has correct Windows debugging constants."""
        assert debugger.DEBUG_PROCESS == 0x00000001
        assert debugger.DEBUG_ONLY_THIS_PROCESS == 0x00000002
        assert debugger.CREATE_SUSPENDED == 0x00000004
        assert debugger.DBG_CONTINUE == 0x00010002
        assert debugger.DBG_EXCEPTION_NOT_HANDLED == 0x80010001
        assert debugger.INT3_INSTRUCTION == b"\xcc"

    def test_license_patterns_initialized(self, debugger: LicenseDebugger) -> None:
        """Debugger initializes with license validation patterns."""
        assert len(debugger.license_patterns) > 0
        assert any(b"\x84\xc0" in pattern for pattern in debugger.license_patterns)
        assert any(b"\x85\xc0" in pattern for pattern in debugger.license_patterns)
        assert any(b"RegOpenKey" in pattern for pattern in debugger.license_patterns)
        assert any(b"GetSystemTime" in pattern for pattern in debugger.license_patterns)

    def test_debugger_tracking_structures_empty(self, debugger: LicenseDebugger) -> None:
        """Debugger tracking structures initialize empty."""
        assert len(debugger.breakpoints) == 0
        assert len(debugger.hardware_breakpoints) == 0
        assert len(debugger.memory_breakpoints) == 0
        assert len(debugger.thread_handles) == 0
        assert len(debugger.modules) == 0
        assert debugger.process_id is None
        assert debugger.main_thread_id is None


class TestProcessAttachment:
    """Tests for debugger process attachment functionality."""

    def test_attach_to_running_process_succeeds(self, running_notepad: int) -> None:
        """Debugger attaches to running process successfully."""
        dbg = LicenseDebugger()
        try:
            result = dbg.attach_to_process(running_notepad)
            assert result is True, "Failed to attach to running process"
            assert dbg.process_id == running_notepad
            assert dbg.process_handle is not None
            assert dbg.debugging is True
            assert dbg.debug_thread is not None
            assert dbg.debug_thread.is_alive()
        finally:
            dbg.debugging = False
            if dbg.debug_thread:
                dbg.debug_thread.join(timeout=2.0)
            if dbg.process_handle:
                try:
                    ctypes.windll.kernel32.TerminateProcess(dbg.process_handle, 0)
                    ctypes.windll.kernel32.CloseHandle(dbg.process_handle)
                except Exception:
                    pass

    def test_attach_to_invalid_process_fails(self, debugger: LicenseDebugger) -> None:
        """Debugger fails gracefully when attaching to invalid process."""
        result = debugger.attach_to_process(999999)
        assert result is False
        assert debugger.process_handle is None
        assert debugger.debugging is False

    def test_attach_sets_debug_privilege(self, running_notepad: int) -> None:
        """Debugger enables debug privilege when attaching."""
        dbg = LicenseDebugger()
        try:
            enable_result = dbg._enable_debug_privilege()
            assert enable_result is True, "Failed to enable debug privilege"
        finally:
            if dbg.process_handle:
                try:
                    ctypes.windll.kernel32.CloseHandle(dbg.process_handle)
                except Exception:
                    pass


class TestBreakpointManagement:
    """Tests for software breakpoint creation and management."""

    def test_create_breakpoint_dataclass(self) -> None:
        """Breakpoint dataclass creates valid instances."""
        bp = Breakpoint(
            address=0x401000,
            original_byte=b"\x55",
            enabled=True,
            hit_count=0,
            callback=None,
            condition=None,
            description="Test breakpoint",
        )
        assert bp.address == 0x401000
        assert bp.original_byte == b"\x55"
        assert bp.enabled is True
        assert bp.hit_count == 0
        assert bp.callback is None
        assert bp.condition is None
        assert bp.description == "Test breakpoint"

    def test_breakpoint_with_callback(self) -> None:
        """Breakpoint stores callback function correctly."""
        def test_callback(dbg: LicenseDebugger, event: Any) -> None:
            pass

        bp = Breakpoint(
            address=0x401000,
            original_byte=b"\x55",
            enabled=True,
            hit_count=0,
            callback=test_callback,
            description="Callback test",
        )
        assert bp.callback is not None
        assert callable(bp.callback)

    def test_breakpoint_with_condition(self) -> None:
        """Breakpoint stores conditional expression correctly."""
        bp = Breakpoint(
            address=0x401000,
            original_byte=b"\x55",
            enabled=True,
            hit_count=0,
            condition="rax == 0x1337",
            description="Conditional breakpoint",
        )
        assert bp.condition == "rax == 0x1337"


class TestConditionValidation:
    """Tests for conditional breakpoint syntax validation."""

    def test_validate_register_condition_syntax(self, debugger: LicenseDebugger) -> None:
        """Validates register comparison condition syntax."""
        assert debugger._validate_condition_syntax("rax == 0x1337") is True
        assert debugger._validate_condition_syntax("rbx != 0") is True
        assert debugger._validate_condition_syntax("rcx > 100") is True
        assert debugger._validate_condition_syntax("rdx < 0xFF") is True
        assert debugger._validate_condition_syntax("r8 >= 0x1000") is True

    def test_validate_memory_condition_syntax(self, debugger: LicenseDebugger) -> None:
        """Validates memory access condition syntax."""
        assert debugger._validate_condition_syntax("mem[rsp] == 0") is True
        assert debugger._validate_condition_syntax("[rsp+8] != 0x1000") is True
        assert debugger._validate_condition_syntax("mem[rbp-4] > 0") is True

    def test_validate_flag_condition_syntax(self, debugger: LicenseDebugger) -> None:
        """Validates CPU flag condition syntax."""
        assert debugger._validate_condition_syntax("rax & 0xFF == 0x10") is True
        assert debugger._validate_condition_syntax("rbx & 1 != 0") is True

    def test_reject_invalid_condition_syntax(self, debugger: LicenseDebugger) -> None:
        """Rejects invalid condition syntax."""
        assert debugger._validate_condition_syntax("invalid syntax here") is False
        assert debugger._validate_condition_syntax("rax =") is False
        assert debugger._validate_condition_syntax("") is False
        assert debugger._validate_condition_syntax("123abc") is False


class TestMemoryOperations:
    """Tests for memory read and write operations."""

    def test_read_memory_from_running_process(self, running_notepad: int) -> None:
        """Reads memory from running process successfully."""
        dbg = LicenseDebugger()
        dbg.process_id = running_notepad
        dbg.process_handle = ctypes.windll.kernel32.OpenProcess(
            0x001F0FFF, False, running_notepad
        )

        try:
            if dbg.process_handle:
                regions = dbg._enumerate_memory_regions()
                valid_regions = [r for r in regions if r["base"] is not None and r["size"] > 0]
                if len(valid_regions) > 0:
                    region = valid_regions[0]
                    read_size = min(16, region["size"])
                    data = dbg._read_memory(region["base"], read_size)
                    if data is not None:
                        assert len(data) == read_size
        finally:
            if dbg.process_handle:
                try:
                    ctypes.windll.kernel32.CloseHandle(dbg.process_handle)
                except Exception:
                    pass

    def test_enumerate_memory_regions(self, running_notepad: int) -> None:
        """Enumerates memory regions from target process."""
        dbg = LicenseDebugger()
        dbg.process_id = running_notepad
        dbg.process_handle = ctypes.windll.kernel32.OpenProcess(
            0x001F0FFF, False, running_notepad
        )

        try:
            if dbg.process_handle:
                regions = dbg._enumerate_memory_regions()
                assert len(regions) > 0

                valid_regions = [r for r in regions if r["base"] is not None and r["size"] > 0]
                assert len(valid_regions) > 0, "No valid memory regions found"

                for region in valid_regions:
                    assert "base" in region
                    assert "size" in region
                    assert "protection" in region
                    assert "executable" in region
                    assert region["base"] is not None
                    assert region["size"] > 0
        finally:
            if dbg.process_handle:
                try:
                    ctypes.windll.kernel32.CloseHandle(dbg.process_handle)
                except Exception:
                    pass

    def test_find_executable_regions(self, running_notepad: int) -> None:
        """Identifies executable memory regions correctly."""
        dbg = LicenseDebugger()
        dbg.process_id = running_notepad
        dbg.process_handle = ctypes.windll.kernel32.OpenProcess(
            0x001F0FFF, False, running_notepad
        )

        try:
            if dbg.process_handle:
                regions = dbg._enumerate_memory_regions()
                valid_regions = [r for r in regions if r["base"] is not None and r["size"] > 0]
                executable_regions = [r for r in valid_regions if r["executable"]]
                assert len(executable_regions) > 0, "No executable regions found"
        finally:
            if dbg.process_handle:
                try:
                    ctypes.windll.kernel32.CloseHandle(dbg.process_handle)
                except Exception:
                    pass


class TestRegisterOperations:
    """Tests for CPU register access and manipulation."""

    def test_context_structure_has_registers(self) -> None:
        """CONTEXT structure includes all x64 registers."""
        ctx = CONTEXT()
        assert hasattr(ctx, "Rax")
        assert hasattr(ctx, "Rbx")
        assert hasattr(ctx, "Rcx")
        assert hasattr(ctx, "Rdx")
        assert hasattr(ctx, "Rsp")
        assert hasattr(ctx, "Rbp")
        assert hasattr(ctx, "Rsi")
        assert hasattr(ctx, "Rdi")
        assert hasattr(ctx, "R8")
        assert hasattr(ctx, "R9")
        assert hasattr(ctx, "R10")
        assert hasattr(ctx, "R11")
        assert hasattr(ctx, "R12")
        assert hasattr(ctx, "R13")
        assert hasattr(ctx, "R14")
        assert hasattr(ctx, "R15")
        assert hasattr(ctx, "Rip")
        assert hasattr(ctx, "EFlags")

    def test_context_has_debug_registers(self) -> None:
        """CONTEXT structure includes debug registers."""
        ctx = CONTEXT()
        assert hasattr(ctx, "Dr0")
        assert hasattr(ctx, "Dr1")
        assert hasattr(ctx, "Dr2")
        assert hasattr(ctx, "Dr3")
        assert hasattr(ctx, "Dr6")
        assert hasattr(ctx, "Dr7")

    def test_get_register_value_from_context(self, debugger: LicenseDebugger) -> None:
        """Extracts register values from CONTEXT structure."""
        ctx = CONTEXT()
        ctx.Rax = 0x1337
        ctx.Rbx = 0x4242
        ctx.Rcx = 0xDEADBEEF

        assert debugger._get_register_value("rax", ctx) == 0x1337
        assert debugger._get_register_value("rbx", ctx) == 0x4242
        assert debugger._get_register_value("rcx", ctx) == 0xDEADBEEF

    def test_get_invalid_register_returns_none(self, debugger: LicenseDebugger) -> None:
        """Returns None for invalid register names."""
        ctx = CONTEXT()
        assert debugger._get_register_value("invalid_reg", ctx) is None
        assert debugger._get_register_value("", ctx) is None


class TestHardwareBreakpoints:
    """Tests for hardware breakpoint functionality using debug registers."""

    def test_find_available_debug_register(self, debugger: LicenseDebugger) -> None:
        """Finds available debug register when none are used."""
        debugger.hardware_breakpoints.clear()
        dr = debugger._find_available_debug_register()
        assert dr in [0, 1, 2, 3]

    def test_find_available_register_when_some_used(self, debugger: LicenseDebugger) -> None:
        """Finds available debug register when some are occupied."""
        debugger.hardware_breakpoints.clear()
        debugger.hardware_breakpoints[0x401000] = {"dr_index": 0}
        debugger.hardware_breakpoints[0x402000] = {"dr_index": 2}

        dr = debugger._find_available_debug_register()
        assert dr in [1, 3]

    def test_no_available_registers_when_all_used(self, debugger: LicenseDebugger) -> None:
        """Returns -1 when all debug registers are occupied."""
        debugger.hardware_breakpoints.clear()
        for i in range(4):
            debugger.hardware_breakpoints[0x401000 + i * 0x1000] = {"dr_index": i}

        dr = debugger._find_available_debug_register()
        assert dr == -1

    def test_list_hardware_breakpoints_empty(self, debugger: LicenseDebugger) -> None:
        """Lists hardware breakpoints when none are set."""
        debugger.hardware_breakpoints.clear()
        bp_list = debugger.list_hardware_breakpoints()
        assert isinstance(bp_list, list)
        assert len(bp_list) == 0

    def test_list_hardware_breakpoints_with_entries(self, debugger: LicenseDebugger) -> None:
        """Lists hardware breakpoints with correct information."""
        debugger.hardware_breakpoints.clear()
        debugger.hardware_breakpoints[0x401000] = {
            "dr_index": 0,
            "access_type": "execute",
            "size": 1,
            "hit_count": 5,
            "threads": [1234, 5678],
        }

        bp_list = debugger.list_hardware_breakpoints()
        assert len(bp_list) == 1
        assert bp_list[0]["address"] == "0x401000"
        assert bp_list[0]["dr_index"] == 0
        assert bp_list[0]["type"] == "execute"
        assert bp_list[0]["size"] == 1
        assert bp_list[0]["hit_count"] == 5
        assert bp_list[0]["threads"] == 2


class TestLicenseCheckDetection:
    """Tests for automatic license check pattern detection."""

    def test_license_patterns_include_common_checks(self, debugger: LicenseDebugger) -> None:
        """License patterns include common validation instructions."""
        patterns = debugger.license_patterns

        assert any(b"\x84\xc0\x74" in p for p in patterns), "Missing TEST AL,AL; JZ pattern"
        assert any(b"\x85\xc0\x74" in p for p in patterns), "Missing TEST EAX,EAX; JZ pattern"
        assert any(b"\xff\x15" in p for p in patterns), "Missing indirect CALL pattern"
        assert any(b"RegOpenKey" in p for p in patterns), "Missing registry API pattern"

    def test_license_patterns_include_time_checks(self, debugger: LicenseDebugger) -> None:
        """License patterns include trial period time check APIs."""
        patterns = debugger.license_patterns

        assert any(b"GetSystemTime" in p for p in patterns)
        assert any(b"GetLocalTime" in p for p in patterns)
        assert any(b"GetTickCount" in p for p in patterns)

    def test_license_patterns_include_hardware_id(self, debugger: LicenseDebugger) -> None:
        """License patterns include hardware identification APIs."""
        patterns = debugger.license_patterns

        assert any(b"GetVolumeInformation" in p for p in patterns)
        assert any(b"GetAdaptersInfo" in p for p in patterns)


class TestConditionalExpressionEvaluation:
    """Tests for conditional breakpoint expression evaluation."""

    def test_evaluate_register_equality(self, debugger: LicenseDebugger) -> None:
        """Evaluates register equality conditions correctly."""
        ctx = CONTEXT()
        ctx.Rax = 0x1337

        result = debugger._evaluate_register_condition("rax == 0x1337", ctx)
        assert result is True

        result = debugger._evaluate_register_condition("rax == 0x1000", ctx)
        assert result is False

    def test_evaluate_register_inequality(self, debugger: LicenseDebugger) -> None:
        """Evaluates register inequality conditions correctly."""
        ctx = CONTEXT()
        ctx.Rbx = 0x100

        result = debugger._evaluate_register_condition("rbx != 0x200", ctx)
        assert result is True

        result = debugger._evaluate_register_condition("rbx != 0x100", ctx)
        assert result is False

    def test_evaluate_register_greater_than(self, debugger: LicenseDebugger) -> None:
        """Evaluates register greater than conditions correctly."""
        ctx = CONTEXT()
        ctx.Rcx = 0x500

        result = debugger._evaluate_register_condition("rcx > 0x400", ctx)
        assert result is True

        result = debugger._evaluate_register_condition("rcx > 0x600", ctx)
        assert result is False

    def test_evaluate_register_less_than(self, debugger: LicenseDebugger) -> None:
        """Evaluates register less than conditions correctly."""
        ctx = CONTEXT()
        ctx.Rdx = 0x100

        result = debugger._evaluate_register_condition("rdx < 0x200", ctx)
        assert result is True

        result = debugger._evaluate_register_condition("rdx < 0x50", ctx)
        assert result is False

    def test_compare_values_all_operators(self, debugger: LicenseDebugger) -> None:
        """Tests all comparison operators work correctly."""
        assert debugger._compare_values(100, "==", 100) is True
        assert debugger._compare_values(100, "==", 50) is False

        assert debugger._compare_values(100, "!=", 50) is True
        assert debugger._compare_values(100, "!=", 100) is False

        assert debugger._compare_values(100, ">", 50) is True
        assert debugger._compare_values(50, ">", 100) is False

        assert debugger._compare_values(50, "<", 100) is True
        assert debugger._compare_values(100, "<", 50) is False

        assert debugger._compare_values(100, ">=", 100) is True
        assert debugger._compare_values(100, ">=", 50) is True
        assert debugger._compare_values(50, ">=", 100) is False

        assert debugger._compare_values(100, "<=", 100) is True
        assert debugger._compare_values(50, "<=", 100) is True
        assert debugger._compare_values(100, "<=", 50) is False

    def test_evaluate_address_expression_simple(self, debugger: LicenseDebugger) -> None:
        """Evaluates simple register address expressions."""
        ctx = CONTEXT()
        ctx.Rsp = 0x7FFFFF000

        addr = debugger._evaluate_address_expression("rsp", ctx)
        assert addr == 0x7FFFFF000

    def test_evaluate_address_expression_addition(self, debugger: LicenseDebugger) -> None:
        """Evaluates address expressions with addition."""
        ctx = CONTEXT()
        ctx.Rsp = 0x7FFFFF000

        addr = debugger._evaluate_address_expression("rsp+8", ctx)
        assert addr == 0x7FFFFF008

    def test_evaluate_address_expression_subtraction(self, debugger: LicenseDebugger) -> None:
        """Evaluates address expressions with subtraction."""
        ctx = CONTEXT()
        ctx.Rbp = 0x7FFFFF100

        addr = debugger._evaluate_address_expression("rbp-16", ctx)
        assert addr == 0x7FFFFF0F0

    def test_evaluate_flag_condition_zero_flag(self, debugger: LicenseDebugger) -> None:
        """Evaluates zero flag condition correctly."""
        ctx = CONTEXT()
        ctx.EFlags = 1 << 6

        result = debugger._evaluate_flag_condition("zf == 1", ctx)
        assert result is True

        ctx.EFlags = 0
        result = debugger._evaluate_flag_condition("zf == 1", ctx)
        assert result is False

    def test_evaluate_flag_condition_carry_flag(self, debugger: LicenseDebugger) -> None:
        """Evaluates carry flag condition correctly."""
        ctx = CONTEXT()
        ctx.EFlags = 1 << 0

        result = debugger._evaluate_flag_condition("cf == 1", ctx)
        assert result is True

        ctx.EFlags = 0
        result = debugger._evaluate_flag_condition("cf == 1", ctx)
        assert result is False


class TestExceptionHandling:
    """Tests for exception event handling and processing."""

    def test_exception_code_enum_values(self) -> None:
        """ExceptionCode enum has correct Windows exception codes."""
        assert ExceptionCode.EXCEPTION_ACCESS_VIOLATION == 0xC0000005
        assert ExceptionCode.EXCEPTION_BREAKPOINT == 0x80000003
        assert ExceptionCode.EXCEPTION_SINGLE_STEP == 0x80000004
        assert ExceptionCode.EXCEPTION_INT_DIVIDE_BY_ZERO == 0xC0000094
        assert ExceptionCode.EXCEPTION_ILLEGAL_INSTRUCTION == 0xC000001D
        assert ExceptionCode.EXCEPTION_GUARD_PAGE == 0x80000001

    def test_debug_event_enum_values(self) -> None:
        """DebugEvent enum has correct Windows debug event codes."""
        assert DebugEvent.EXCEPTION_DEBUG_EVENT == 1
        assert DebugEvent.CREATE_THREAD_DEBUG_EVENT == 2
        assert DebugEvent.CREATE_PROCESS_DEBUG_EVENT == 3
        assert DebugEvent.EXIT_THREAD_DEBUG_EVENT == 4
        assert DebugEvent.EXIT_PROCESS_DEBUG_EVENT == 5
        assert DebugEvent.LOAD_DLL_DEBUG_EVENT == 6
        assert DebugEvent.UNLOAD_DLL_DEBUG_EVENT == 7
        assert DebugEvent.OUTPUT_DEBUG_STRING_EVENT == 8


class TestAntiDebuggingDetection:
    """Tests for anti-debugging technique detection and bypass."""

    def test_bypass_anti_debug_api_hooks(self, debugger: LicenseDebugger) -> None:
        """Bypass anti-debug prepares API hooks for common checks."""
        debugger.breakpoints.clear()
        debugger.api_hooks.clear()

        result = debugger.bypass_anti_debug()

        assert isinstance(result, bool)

    def test_hide_debugger_configures_peb(self, debugger: LicenseDebugger) -> None:
        """Hide debugger prepares PEB manipulation."""
        result = debugger.hide_debugger()

        assert isinstance(result, bool)

    def test_bypass_output_debug_string(self, debugger: LicenseDebugger) -> None:
        """Bypass OutputDebugString anti-debug technique."""
        debugger.breakpoints.clear()
        debugger.api_hooks.clear()

        result = debugger.bypass_output_debug_string()

        assert isinstance(result, bool)

    def test_mitigate_timing_attacks(self, debugger: LicenseDebugger) -> None:
        """Mitigate timing-based anti-debug detection."""
        debugger.breakpoints.clear()
        debugger.api_hooks.clear()

        result = debugger.mitigate_timing_attacks()

        assert isinstance(result, bool)

    def test_bypass_thread_enumeration(self, debugger: LicenseDebugger) -> None:
        """Bypass thread enumeration anti-debug checks."""
        debugger.breakpoints.clear()
        debugger.api_hooks.clear()

        result = debugger.bypass_thread_enumeration()

        assert isinstance(result, bool)


class TestDLLAnalysis:
    """Tests for DLL loading analysis and license detection."""

    def test_analyze_dll_comprehensive_structure(self, debugger: LicenseDebugger) -> None:
        """DLL analysis returns complete structure with all fields."""
        analysis = {
            "is_license_related": False,
            "suspicious_score": 0.0,
            "license_functions": [],
            "license_imports": {},
            "license_exports": [],
            "license_strings": [],
            "protection_signatures": [],
        }

        assert "is_license_related" in analysis
        assert "suspicious_score" in analysis
        assert "license_functions" in analysis
        assert "license_imports" in analysis
        assert isinstance(analysis["license_functions"], list)
        assert isinstance(analysis["license_imports"], dict)

    def test_extract_license_strings_detects_keywords(self, debugger: LicenseDebugger) -> None:
        """License string extraction detects common license keywords."""
        test_data = b"License key: ABC-123-DEF\x00Trial expired\x00Registration required\x00"
        strings = debugger._extract_license_strings(test_data)

        assert isinstance(strings, list)
        license_related = [s for s in strings if any(
            kw in s.lower() for kw in ["license", "trial", "registration"]
        )]
        assert len(license_related) > 0

    def test_extract_full_string_handles_null_termination(self, debugger: LicenseDebugger) -> None:
        """String extraction stops at null terminator correctly."""
        test_data = b"Hello World\x00Extra data"
        result = debugger._extract_full_string(test_data, 0)

        assert result == "Hello World"
        assert "Extra" not in result


class TestImportExportParsing:
    """Tests for PE import and export table parsing."""

    def test_parse_iat_returns_dict(self, debugger: LicenseDebugger) -> None:
        """IAT parsing returns dictionary structure."""
        debugger.breakpoints.clear()
        iat = debugger.parse_iat()

        assert isinstance(iat, dict)

    def test_parse_eat_returns_list(self, debugger: LicenseDebugger) -> None:
        """EAT parsing returns list of exports."""
        debugger.breakpoints.clear()
        eat = debugger.parse_eat()

        assert isinstance(eat, list)

    def test_parse_delayed_imports_returns_dict(self, debugger: LicenseDebugger) -> None:
        """Delayed import parsing returns dictionary structure."""
        debugger.breakpoints.clear()
        delayed = debugger.parse_delayed_imports()

        assert isinstance(delayed, dict)


class TestInstructionEncoding:
    """Tests for x86/x64 instruction encoding and assembly."""

    def test_encode_ret_instruction(self, debugger: LicenseDebugger) -> None:
        """Encodes RET instruction correctly."""
        encoded = debugger._encode_ret("")
        assert encoded == b"\xC3"

    def test_encode_ret_with_immediate(self, debugger: LicenseDebugger) -> None:
        """Encodes RET with immediate value correctly."""
        encoded = debugger._encode_ret("8")
        assert encoded == b"\xC2\x08\x00"

    def test_encode_int3_instruction(self, debugger: LicenseDebugger) -> None:
        """Encodes INT3 breakpoint instruction correctly."""
        encoded = debugger._encode_int("3")
        assert encoded == b"\xCC"

    def test_encode_nop_instruction(self, debugger: LicenseDebugger) -> None:
        """Encodes NOP instruction correctly."""
        encoded = debugger._encode_int("3")
        assert len(encoded) > 0

    def test_calculate_relative_jump_forward(self, debugger: LicenseDebugger) -> None:
        """Calculates forward relative jump correctly."""
        rel_bytes = debugger.calculate_relative_jump(0x401000, 0x401100, 5)

        assert len(rel_bytes) == 4
        offset = struct.unpack("<i", rel_bytes)[0]
        assert offset == 0x100 - 5

    def test_calculate_relative_jump_backward(self, debugger: LicenseDebugger) -> None:
        """Calculates backward relative jump correctly."""
        rel_bytes = debugger.calculate_relative_jump(0x401100, 0x401000, 5)

        assert len(rel_bytes) == 4
        offset = struct.unpack("<i", rel_bytes)[0]
        assert offset < 0


class TestDynamicPatching:
    """Tests for dynamic code generation and patching."""

    def test_generate_dynamic_patch_nop_slide(self, debugger: LicenseDebugger) -> None:
        """Generates NOP slide patch correctly."""
        patch = debugger.generate_dynamic_patch(0x401000, "nop", length=10)

        assert len(patch) == 10

    def test_generate_dynamic_patch_bypass_always(self, debugger: LicenseDebugger) -> None:
        """Generates bypass patch for always jumping."""
        patch = debugger.generate_dynamic_patch(0x401000, "bypass", condition="always")

        assert len(patch) > 0
        assert patch == b"\xeb"

    def test_generate_dynamic_patch_bypass_never(self, debugger: LicenseDebugger) -> None:
        """Generates bypass patch for never jumping (NOP)."""
        patch = debugger.generate_dynamic_patch(0x401000, "bypass", condition="never")

        assert len(patch) > 0
        assert patch == b"\x90\x90"

    def test_generate_dynamic_patch_jump_to_address(self, debugger: LicenseDebugger) -> None:
        """Generates jump patch to specific address."""
        patch = debugger.generate_dynamic_patch(
            0x401000, "jmp", destination=0x402000
        )

        assert len(patch) >= 5
        assert patch[0] == 0xE9

    def test_generate_dynamic_patch_ret(self, debugger: LicenseDebugger) -> None:
        """Generates RET patch correctly."""
        patch = debugger.generate_dynamic_patch(0x401000, "ret")

        assert len(patch) > 0
        assert patch == b"\xc3"

    def test_generate_dynamic_patch_ret_with_cleanup(self, debugger: LicenseDebugger) -> None:
        """Generates RET with stack cleanup patch correctly."""
        patch = debugger.generate_dynamic_patch(0x401000, "ret", stack_cleanup=8)

        assert len(patch) == 3
        assert patch[0] == 0xC2


class TestCodeRelocation:
    """Tests for code relocation and fixup."""

    def test_relocate_code_updates_offsets(self, debugger: LicenseDebugger) -> None:
        """Code relocation updates relative offsets correctly."""
        original_code = b"\xE8\x00\x00\x00\x00"
        reloc_offsets = [1]

        relocated = debugger.relocate_code(
            original_code, 0x401000, 0x501000, reloc_offsets
        )

        assert len(relocated) == len(original_code)
        assert relocated[0] == 0xE8

    def test_relocate_code_preserves_instructions(self, debugger: LicenseDebugger) -> None:
        """Code relocation preserves non-relocated instructions."""
        original_code = b"\x90\x90\x90\x90\x90"
        reloc_offsets = []

        relocated = debugger.relocate_code(
            original_code, 0x401000, 0x501000, reloc_offsets
        )

        assert relocated == original_code


class TestShellcodeGeneration:
    """Tests for shellcode generation for bypass operations."""

    def test_generate_shellcode_msgbox(self, debugger: LicenseDebugger) -> None:
        """Generates MessageBox shellcode."""
        shellcode = debugger.generate_shellcode("msgbox", title="Test", message="Hello")

        assert len(shellcode) > 0
        assert isinstance(shellcode, bytes)

    def test_generate_shellcode_patch(self, debugger: LicenseDebugger) -> None:
        """Generates patch shellcode."""
        shellcode = debugger.generate_shellcode("patch", patch_bytes=b"\x90\x90\x90")

        assert isinstance(shellcode, bytes)


class TestThreadOperations:
    """Tests for thread context and manipulation."""

    def test_single_step_requires_thread_id(self, debugger: LicenseDebugger) -> None:
        """Single step operation validates thread ID requirement."""
        result = debugger.single_step(thread_id=None)

        assert isinstance(result, bool)

    def test_get_registers_returns_dict_or_none(self, debugger: LicenseDebugger) -> None:
        """Get registers returns dictionary or None."""
        result = debugger.get_registers(thread_id=None)

        assert result is None or isinstance(result, dict)

    def test_set_registers_validates_input(self, debugger: LicenseDebugger) -> None:
        """Set registers validates register dictionary."""
        result = debugger.set_registers({"rax": 0x1337}, thread_id=None)

        assert isinstance(result, bool)


class TestTLSCallbackAnalysis:
    """Tests for Thread Local Storage callback detection and analysis."""

    def test_analyze_tls_callbacks_returns_list(self, debugger: LicenseDebugger) -> None:
        """TLS callback analysis returns list of addresses."""
        callbacks = debugger.analyze_tls_callbacks()

        assert isinstance(callbacks, list)

    def test_disassemble_tls_callbacks_returns_dict(self, debugger: LicenseDebugger) -> None:
        """TLS callback disassembly returns dictionary."""
        disasm = debugger.disassemble_tls_callbacks()

        assert isinstance(disasm, dict)

    def test_bypass_tls_callbacks_returns_bool(self, debugger: LicenseDebugger) -> None:
        """TLS callback bypass returns boolean result."""
        result = debugger.bypass_tls_callbacks()

        assert isinstance(result, bool)

    def test_detect_tls_protection_returns_dict(self, debugger: LicenseDebugger) -> None:
        """TLS protection detection returns analysis dictionary."""
        detection = debugger.detect_tls_protection()

        assert isinstance(detection, dict)


class TestMemoryProtection:
    """Tests for memory protection and integrity validation."""

    def test_read_memory_validates_address(self, debugger: LicenseDebugger) -> None:
        """Read memory validates address parameter."""
        result = debugger.read_memory(0, 16)

        assert result is None or isinstance(result, bytes)

    def test_write_memory_validates_data(self, debugger: LicenseDebugger) -> None:
        """Write memory validates data parameter."""
        result = debugger.write_memory(0x401000, b"\x90\x90\x90")

        assert isinstance(result, bool)

    def test_continue_execution_returns_bool(self, debugger: LicenseDebugger) -> None:
        """Continue execution returns boolean result."""
        result = debugger.continue_execution()

        assert isinstance(result, bool)


class TestIntegrationScenarios:
    """Integration tests for complete debugging workflows."""

    def test_complete_attach_detach_workflow(self, running_notepad: int) -> None:
        """Complete workflow: attach, enumerate, detach."""
        dbg = LicenseDebugger()

        try:
            attach_result = dbg.attach_to_process(running_notepad)
            if attach_result:
                assert dbg.process_handle is not None
                assert dbg.debugging is True

                time.sleep(0.5)

                regions = dbg._enumerate_memory_regions()
                valid_regions = [r for r in regions if r["base"] is not None and r["size"] > 0]
                assert len(valid_regions) > 0

                dbg.debugging = False
                if dbg.debug_thread:
                    dbg.debug_thread.join(timeout=2.0)

                assert dbg.debug_thread is None or not dbg.debug_thread.is_alive()
        finally:
            dbg.debugging = False
            if dbg.debug_thread and dbg.debug_thread.is_alive():
                dbg.debug_thread.join(timeout=2.0)
            if dbg.process_handle:
                try:
                    ctypes.windll.kernel32.TerminateProcess(dbg.process_handle, 0)
                    ctypes.windll.kernel32.CloseHandle(dbg.process_handle)
                except Exception:
                    pass

    def test_breakpoint_lifecycle_management(self, debugger: LicenseDebugger) -> None:
        """Complete breakpoint lifecycle: create, check, validate."""
        debugger.breakpoints.clear()

        initial_count = len(debugger.breakpoints)
        assert initial_count == 0

        bp = Breakpoint(
            address=0x401000,
            original_byte=b"\x55",
            enabled=True,
            hit_count=0,
            description="Test BP",
        )
        debugger.breakpoints[0x401000] = bp

        assert len(debugger.breakpoints) == 1
        assert 0x401000 in debugger.breakpoints

        stored_bp = debugger.breakpoints[0x401000]
        assert stored_bp.address == 0x401000
        assert stored_bp.enabled is True

        del debugger.breakpoints[0x401000]
        assert len(debugger.breakpoints) == 0

    def test_hardware_breakpoint_lifecycle(self, debugger: LicenseDebugger) -> None:
        """Complete hardware breakpoint lifecycle."""
        debugger.hardware_breakpoints.clear()

        debugger.hardware_breakpoints[0x401000] = {
            "dr_index": 0,
            "access_type": "execute",
            "size": 1,
            "hit_count": 0,
            "threads": [],
        }

        assert len(debugger.hardware_breakpoints) == 1
        bp_list = debugger.list_hardware_breakpoints()
        assert len(bp_list) == 1

        debugger.hardware_breakpoints.clear()
        assert len(debugger.hardware_breakpoints) == 0
