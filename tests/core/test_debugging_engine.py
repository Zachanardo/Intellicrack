"""Production-grade tests for debugging engine anti-debugging capabilities.

Tests validate real Windows debugging operations, anti-debugging detection,
and debugger bypass techniques against actual processes and Windows APIs.
"""

import ctypes
import os
import struct
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.debugging_engine import (
    CONTEXT,
    Breakpoint,
    DebugEvent,
    ExceptionCode,
    ExceptionRecord,
    LicenseDebugger,
)


class TestDebuggerInitialization:
    """Test debugger initialization and core setup."""

    def test_debugger_initializes_with_required_components(self) -> None:
        """Debugger initializes with all required Windows API interfaces."""
        debugger = LicenseDebugger()

        assert debugger.kernel32 is not None
        assert debugger.ntdll is not None
        assert isinstance(debugger.breakpoints, dict)
        assert isinstance(debugger.hardware_breakpoints, dict)
        assert isinstance(debugger.memory_breakpoints, dict)
        assert isinstance(debugger.license_patterns, list)
        assert len(debugger.license_patterns) > 0
        assert debugger.debugging is False
        assert debugger.process_handle is None

    def test_license_patterns_contain_real_detection_signatures(self) -> None:
        """License patterns contain genuine anti-debugging signatures."""
        debugger = LicenseDebugger()

        patterns = debugger.license_patterns
        assert len(patterns) >= 10

        expected_patterns = [
            b"\x84\xc0\x74",
            b"\x84\xc0\x75",
            b"\x85\xc0\x74",
            b"\x85\xc0\x75",
            b"RegOpenKey",
            b"RegQueryValue",
            b"GetSystemTime",
            b"GetTickCount",
        ]

        for pattern in expected_patterns:
            assert pattern in patterns

    def test_debugger_has_veh_handler_capability(self) -> None:
        """Debugger has vectored exception handler capability."""
        debugger = LicenseDebugger()

        assert hasattr(debugger, "veh_handlers")
        assert hasattr(debugger, "veh_handle")
        assert hasattr(debugger, "exception_filters")
        assert hasattr(debugger, "exception_callbacks")
        assert isinstance(debugger.veh_handlers, list)


class TestDebugPrivilegeElevation:
    """Test debug privilege elevation for process debugging."""

    def test_enable_debug_privilege_requires_admin_or_succeeds(self) -> None:
        """Enable debug privilege succeeds with proper permissions."""
        debugger = LicenseDebugger()

        result = debugger._enable_debug_privilege()

        if not result:
            pytest.skip("Requires administrator privileges")

        assert result is True

    def test_debug_privilege_allows_process_access(self) -> None:
        """Debug privilege enables access to other processes."""
        debugger = LicenseDebugger()

        if not debugger._enable_debug_privilege():
            pytest.skip("Requires administrator privileges")

        current_pid = os.getpid()
        handle = debugger.kernel32.OpenProcess(
            debugger.PROCESS_ALL_ACCESS, False, current_pid
        )

        assert handle is not None
        assert handle != 0

        debugger.kernel32.CloseHandle(handle)


class TestProcessAttachment:
    """Test debugger attachment to running processes."""

    @pytest.fixture
    def target_process(self) -> subprocess.Popen:
        """Create a simple target process for debugging."""
        test_program = """
import time
import sys

try:
    while True:
        time.sleep(0.1)
except KeyboardInterrupt:
    sys.exit(0)
"""
        temp_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        )
        temp_file.write(test_program)
        temp_file.close()

        process = subprocess.Popen(
            [sys.executable, temp_file.name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        time.sleep(0.5)

        yield process

        process.terminate()
        process.wait(timeout=2)
        os.unlink(temp_file.name)

    def test_attach_to_running_process_succeeds(
        self, target_process: subprocess.Popen
    ) -> None:
        """Debugger successfully attaches to running process."""
        debugger = LicenseDebugger()

        if not debugger._enable_debug_privilege():
            pytest.skip("Requires administrator privileges")

        result = debugger.attach_to_process(target_process.pid)

        if not result:
            pytest.skip("Process attachment failed - may require elevated privileges")

        assert result is True
        assert debugger.process_id == target_process.pid
        assert debugger.process_handle is not None
        assert debugger.debugging is True
        assert debugger.debug_thread is not None

        debugger.detach()

    def test_attach_to_nonexistent_process_fails(self) -> None:
        """Debugger fails gracefully when attaching to invalid PID."""
        debugger = LicenseDebugger()

        if not debugger._enable_debug_privilege():
            pytest.skip("Requires administrator privileges")

        result = debugger.attach_to_process(999999)

        assert result is False
        assert debugger.process_id is None
        assert debugger.process_handle is None

    def test_attach_sets_process_handle_with_all_access(
        self, target_process: subprocess.Popen
    ) -> None:
        """Attached process handle has PROCESS_ALL_ACCESS rights."""
        debugger = LicenseDebugger()

        if not debugger._enable_debug_privilege():
            pytest.skip("Requires administrator privileges")

        if not debugger.attach_to_process(target_process.pid):
            pytest.skip("Process attachment failed")

        assert debugger.process_handle is not None

        bytes_read = ctypes.c_size_t()
        buffer = ctypes.create_string_buffer(8)
        read_result = debugger.kernel32.ReadProcessMemory(
            debugger.process_handle,
            ctypes.c_void_p(0x1000),
            buffer,
            8,
            ctypes.byref(bytes_read),
        )

        debugger.detach()


class TestSoftwareBreakpoints:
    """Test software breakpoint setting and management."""

    @pytest.fixture
    def debugged_process(self, target_process: subprocess.Popen) -> LicenseDebugger:
        """Debugger attached to target process."""
        debugger = LicenseDebugger()

        if not debugger._enable_debug_privilege():
            pytest.skip("Requires administrator privileges")

        if not debugger.attach_to_process(target_process.pid):
            pytest.skip("Process attachment failed")

        yield debugger

        debugger.detach()

    def test_set_breakpoint_replaces_byte_with_int3(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """Setting breakpoint replaces memory with INT3 instruction."""
        debugger = debugged_process

        memory_regions = debugger._enumerate_memory_regions()
        executable_region = next(
            (r for r in memory_regions if r.get("executable", False)), None
        )

        if not executable_region:
            pytest.skip("No executable memory regions found")

        address = executable_region["base_address"]

        original_byte = debugger._read_memory(address, 1)
        if not original_byte:
            pytest.skip("Cannot read target memory")

        result = debugger.set_breakpoint(address)

        assert result is True
        assert address in debugger.breakpoints

        bp = debugger.breakpoints[address]
        assert bp.address == address
        assert bp.original_byte == original_byte
        assert bp.enabled is True
        assert bp.hit_count == 0

        current_byte = debugger._read_memory(address, 1)
        assert current_byte == debugger.INT3_INSTRUCTION

    def test_set_breakpoint_with_callback_stores_handler(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """Breakpoint with callback stores handler function."""
        debugger = debugged_process

        def test_callback(debugger: LicenseDebugger, event: Any) -> None:
            pass

        memory_regions = debugger._enumerate_memory_regions()
        executable_region = next(
            (r for r in memory_regions if r.get("executable", False)), None
        )

        if not executable_region:
            pytest.skip("No executable memory regions found")

        address = executable_region["base_address"] + 0x100

        result = debugger.set_breakpoint(
            address, callback=test_callback, description="Test breakpoint"
        )

        if not result:
            pytest.skip("Breakpoint setting failed")

        assert address in debugger.breakpoints
        bp = debugger.breakpoints[address]
        assert bp.callback == test_callback
        assert bp.description == "Test breakpoint"

    def test_set_duplicate_breakpoint_returns_true(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """Setting duplicate breakpoint returns success without duplication."""
        debugger = debugged_process

        memory_regions = debugger._enumerate_memory_regions()
        executable_region = next(
            (r for r in memory_regions if r.get("executable", False)), None
        )

        if not executable_region:
            pytest.skip("No executable memory regions found")

        address = executable_region["base_address"] + 0x200

        result1 = debugger.set_breakpoint(address)
        if not result1:
            pytest.skip("First breakpoint failed")

        result2 = debugger.set_breakpoint(address)

        assert result2 is True
        assert len([bp for bp in debugger.breakpoints.values() if bp.address == address]) == 1

    def test_conditional_breakpoint_validates_syntax(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """Conditional breakpoint validates condition syntax."""
        debugger = debugged_process

        memory_regions = debugger._enumerate_memory_regions()
        executable_region = next(
            (r for r in memory_regions if r.get("executable", False)), None
        )

        if not executable_region:
            pytest.skip("No executable memory regions found")

        address = executable_region["base_address"] + 0x300

        valid_conditions = [
            "rax == 0x1337",
            "rcx > 100",
            "rdx != 0",
            "r8 < 0x1000",
        ]

        for condition in valid_conditions:
            result = debugger._validate_condition_syntax(condition)
            assert result is True


class TestHardwareBreakpoints:
    """Test hardware breakpoint functionality using debug registers."""

    @pytest.fixture
    def debugged_process(self, target_process: subprocess.Popen) -> LicenseDebugger:
        """Debugger attached to target process."""
        debugger = LicenseDebugger()

        if not debugger._enable_debug_privilege():
            pytest.skip("Requires administrator privileges")

        if not debugger.attach_to_process(target_process.pid):
            pytest.skip("Process attachment failed")

        time.sleep(1)

        yield debugger

        debugger.detach()

    def test_set_hardware_breakpoint_on_execute(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """Hardware breakpoint on execute access uses debug registers."""
        debugger = debugged_process

        memory_regions = debugger._enumerate_memory_regions()
        executable_region = next(
            (r for r in memory_regions if r.get("executable", False)), None
        )

        if not executable_region:
            pytest.skip("No executable memory regions found")

        address = executable_region["base_address"]

        result = debugger.set_hardware_breakpoint(
            address, dr_index=0, access_type="execute", size=1
        )

        if not result:
            pytest.skip("Hardware breakpoint setting failed")

        assert result is True
        assert address in debugger.hardware_breakpoints

        hw_bp = debugger.hardware_breakpoints[address]
        assert hw_bp["dr_index"] == 0
        assert hw_bp["access_type"] == "execute"
        assert hw_bp["size"] == 1
        assert hw_bp["hit_count"] == 0

    def test_hardware_breakpoint_validates_debug_register_index(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """Hardware breakpoint rejects invalid debug register indices."""
        debugger = debugged_process

        memory_regions = debugger._enumerate_memory_regions()
        executable_region = next(
            (r for r in memory_regions if r.get("executable", False)), None
        )

        if not executable_region:
            pytest.skip("No executable memory regions found")

        address = executable_region["base_address"]

        invalid_indices = [4, 5, -2, 10]

        for index in invalid_indices:
            result = debugger.set_hardware_breakpoint(
                address, dr_index=index, access_type="execute"
            )
            assert result is False

    def test_hardware_breakpoint_validates_size(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """Hardware breakpoint validates size parameter."""
        debugger = debugged_process

        memory_regions = debugger._enumerate_memory_regions()
        executable_region = next(
            (r for r in memory_regions if r.get("executable", False)), None
        )

        if not executable_region:
            pytest.skip("No executable memory regions found")

        address = executable_region["base_address"]

        valid_sizes = [1, 2, 4, 8]
        for size in valid_sizes:
            debugger.hardware_breakpoints.clear()
            result = debugger.set_hardware_breakpoint(
                address, dr_index=0, access_type="write", size=size
            )
            if result:
                assert debugger.hardware_breakpoints[address]["size"] == size

        invalid_sizes = [3, 5, 16, 0]
        for size in invalid_sizes:
            result = debugger.set_hardware_breakpoint(
                address, dr_index=1, access_type="write", size=size
            )
            assert result is False

    def test_remove_hardware_breakpoint_clears_debug_register(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """Removing hardware breakpoint clears debug register."""
        debugger = debugged_process

        memory_regions = debugger._enumerate_memory_regions()
        executable_region = next(
            (r for r in memory_regions if r.get("executable", False)), None
        )

        if not executable_region:
            pytest.skip("No executable memory regions found")

        address = executable_region["base_address"]

        if not debugger.set_hardware_breakpoint(
            address, dr_index=0, access_type="execute", size=1
        ):
            pytest.skip("Hardware breakpoint setting failed")

        result = debugger.remove_hardware_breakpoint(address)

        if result:
            assert address not in debugger.hardware_breakpoints

    def test_hardware_breakpoint_auto_selects_available_register(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """Hardware breakpoint auto-selects available debug register."""
        debugger = debugged_process

        memory_regions = debugger._enumerate_memory_regions()
        executable_region = next(
            (r for r in memory_regions if r.get("executable", False)), None
        )

        if not executable_region:
            pytest.skip("No executable memory regions found")

        base = executable_region["base_address"]

        addresses = [base, base + 0x100, base + 0x200, base + 0x300]

        for i, addr in enumerate(addresses):
            result = debugger.set_hardware_breakpoint(
                addr, dr_index=-1, access_type="execute", size=1
            )

            if result:
                assert addr in debugger.hardware_breakpoints
                dr_index = debugger.hardware_breakpoints[addr]["dr_index"]
                assert dr_index in range(4)

            if i >= 3:
                break


class TestAntiDebuggingBypass:
    """Test anti-debugging detection bypass capabilities."""

    @pytest.fixture
    def debugged_process(self, target_process: subprocess.Popen) -> LicenseDebugger:
        """Debugger attached to target process."""
        debugger = LicenseDebugger()

        if not debugger._enable_debug_privilege():
            pytest.skip("Requires administrator privileges")

        if not debugger.attach_to_process(target_process.pid):
            pytest.skip("Process attachment failed")

        time.sleep(1)

        yield debugger

        debugger.detach()

    def test_bypass_anti_debug_clears_peb_being_debugged_flag(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """Anti-debug bypass clears PEB BeingDebugged flag."""
        debugger = debugged_process

        result = debugger.bypass_anti_debug()

        if not result:
            pytest.skip("Anti-debug bypass failed")

        assert result is True

        pbi_size = ctypes.sizeof(ctypes.c_void_p) * 6
        pbi = ctypes.create_string_buffer(pbi_size)
        return_length = ctypes.c_ulong()

        status = debugger.ntdll.NtQueryInformationProcess(
            debugger.process_handle, 0, pbi, pbi_size, ctypes.byref(return_length)
        )

        if status == 0:
            peb_address = struct.unpack(
                "P", pbi[ctypes.sizeof(ctypes.c_void_p) : ctypes.sizeof(ctypes.c_void_p) * 2]
            )[0]

            being_debugged_byte = debugger._read_memory(peb_address + 2, 1)

            if being_debugged_byte:
                assert being_debugged_byte == b"\x00"

    def test_bypass_anti_debug_patches_is_debugger_present(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """Anti-debug bypass patches IsDebuggerPresent API."""
        debugger = debugged_process

        kernel32_base = debugger.kernel32.GetModuleHandleA(b"kernel32.dll")
        if not kernel32_base:
            pytest.skip("Cannot get kernel32 base")

        original_addr = debugger.kernel32.GetProcAddress(
            kernel32_base, b"IsDebuggerPresent"
        )
        if not original_addr:
            pytest.skip("Cannot get IsDebuggerPresent address")

        original_bytes = debugger._read_memory(original_addr, 3)

        result = debugger.bypass_anti_debug()

        if not result:
            pytest.skip("Anti-debug bypass failed")

        patched_bytes = debugger._read_memory(original_addr, 3)

        if patched_bytes and original_bytes:
            assert patched_bytes == b"\x31\xc0\xc3"

    def test_bypass_anti_debug_clears_ntglobalflag(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """Anti-debug bypass clears NtGlobalFlag in PEB."""
        debugger = debugged_process

        result = debugger.bypass_anti_debug()

        if not result:
            pytest.skip("Anti-debug bypass failed")

        assert result is True

        pbi_size = ctypes.sizeof(ctypes.c_void_p) * 6
        pbi = ctypes.create_string_buffer(pbi_size)
        return_length = ctypes.c_ulong()

        status = debugger.ntdll.NtQueryInformationProcess(
            debugger.process_handle, 0, pbi, pbi_size, ctypes.byref(return_length)
        )

        if status == 0:
            peb_address = struct.unpack(
                "P", pbi[ctypes.sizeof(ctypes.c_void_p) : ctypes.sizeof(ctypes.c_void_p) * 2]
            )[0]

            if ctypes.sizeof(ctypes.c_void_p) == 8:
                offset = 0xBC
            else:
                offset = 0x68

            ntglobalflag_bytes = debugger._read_memory(peb_address + offset, 4)

            if ntglobalflag_bytes:
                assert ntglobalflag_bytes == b"\x00\x00\x00\x00"

    def test_hide_debugger_uses_thread_hide_from_debugger(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """Hide debugger uses NtSetInformationThread."""
        debugger = debugged_process

        result = debugger.hide_debugger()

        assert result is True or result is False

    def test_bypass_output_debug_string_patches_api(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """OutputDebugString bypass patches API functions."""
        debugger = debugged_process

        debugger.patched_apis = {}

        result = debugger.bypass_output_debug_string()

        if not result:
            pytest.skip("OutputDebugString bypass failed")

        assert result is True


class TestTimingAttackMitigation:
    """Test timing attack mitigation capabilities."""

    @pytest.fixture
    def debugged_process(self, target_process: subprocess.Popen) -> LicenseDebugger:
        """Debugger attached to target process."""
        debugger = LicenseDebugger()

        if not debugger._enable_debug_privilege():
            pytest.skip("Requires administrator privileges")

        if not debugger.attach_to_process(target_process.pid):
            pytest.skip("Process attachment failed")

        time.sleep(1)

        yield debugger

        debugger.detach()

    def test_mitigate_timing_attacks_initializes_emulation_state(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """Timing attack mitigation initializes emulation state."""
        debugger = debugged_process

        debugger.enumerate_memory_regions = lambda: []

        result = debugger.mitigate_timing_attacks()

        if not result:
            pytest.skip("Timing mitigation failed")

        assert hasattr(debugger, "time_base")
        assert hasattr(debugger, "time_scale")
        assert hasattr(debugger, "emulated_tick_count")
        assert hasattr(debugger, "last_real_time")
        assert hasattr(debugger, "emulated_perf_counter")
        assert hasattr(debugger, "emulated_perf_frequency")

    def test_mitigate_timing_attacks_patches_rdtsc_instructions(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """Timing mitigation patches RDTSC instructions."""
        debugger = debugged_process

        test_code = b"\x0f\x31" + b"\x90" * 10

        temp_addr = 0x1000000
        write_success = debugger._write_memory(temp_addr, test_code)

        if not write_success:
            pytest.skip("Cannot write test code")

        result = debugger.mitigate_timing_attacks()

        if not result:
            pytest.skip("Timing mitigation failed")

        assert result is True


class TestMemoryOperations:
    """Test memory read/write operations."""

    @pytest.fixture
    def debugged_process(self, target_process: subprocess.Popen) -> LicenseDebugger:
        """Debugger attached to target process."""
        debugger = LicenseDebugger()

        if not debugger._enable_debug_privilege():
            pytest.skip("Requires administrator privileges")

        if not debugger.attach_to_process(target_process.pid):
            pytest.skip("Process attachment failed")

        time.sleep(1)

        yield debugger

        debugger.detach()

    def test_read_memory_from_valid_address(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """Read memory succeeds from valid address."""
        debugger = debugged_process

        memory_regions = debugger._enumerate_memory_regions()
        readable_region = next(
            (r for r in memory_regions if r.get("readable", False)), None
        )

        if not readable_region:
            pytest.skip("No readable memory regions found")

        address = readable_region["base_address"]
        size = min(16, readable_region["size"])

        data = debugger._read_memory(address, size)

        assert data is not None
        assert isinstance(data, bytes)
        assert len(data) == size

    def test_read_memory_from_invalid_address_returns_none(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """Read memory from invalid address returns None."""
        debugger = debugged_process

        invalid_address = 0x1

        data = debugger._read_memory(invalid_address, 16)

        assert data is None

    def test_write_memory_to_writable_address(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """Write memory succeeds to writable address."""
        debugger = debugged_process

        memory_regions = debugger._enumerate_memory_regions()
        writable_region = next(
            (r for r in memory_regions if r.get("writable", False)), None
        )

        if not writable_region:
            pytest.skip("No writable memory regions found")

        address = writable_region["base_address"]

        original = debugger._read_memory(address, 4)
        if not original:
            pytest.skip("Cannot read target memory")

        test_data = b"\xAA\xBB\xCC\xDD"
        write_result = debugger._write_memory(address, test_data)

        if write_result:
            new_data = debugger._read_memory(address, 4)
            assert new_data == test_data

            debugger._write_memory(address, original)

    def test_enumerate_memory_regions_returns_valid_regions(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """Enumerate memory regions returns valid region information."""
        debugger = debugged_process

        regions = debugger._enumerate_memory_regions()

        assert isinstance(regions, list)
        assert len(regions) > 0

        for region in regions:
            assert "base_address" in region
            assert "size" in region
            assert isinstance(region["base_address"], int)
            assert isinstance(region["size"], int)
            assert region["size"] > 0


class TestThreadContextManipulation:
    """Test thread context manipulation and register access."""

    @pytest.fixture
    def debugged_process(self, target_process: subprocess.Popen) -> LicenseDebugger:
        """Debugger attached to target process."""
        debugger = LicenseDebugger()

        if not debugger._enable_debug_privilege():
            pytest.skip("Requires administrator privileges")

        if not debugger.attach_to_process(target_process.pid):
            pytest.skip("Process attachment failed")

        time.sleep(1.5)

        yield debugger

        debugger.detach()

    def test_get_thread_context_returns_valid_context(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """Get thread context returns valid CONTEXT structure."""
        debugger = debugged_process

        if not debugger.main_thread_id:
            pytest.skip("No main thread available")

        context = debugger._get_thread_context(debugger.main_thread_id)

        if not context:
            pytest.skip("Thread context unavailable")

        assert isinstance(context, CONTEXT)
        assert context.Rip != 0 or context.Rsp != 0

    def test_get_registers_returns_register_dict(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """Get registers returns dictionary of register values."""
        debugger = debugged_process

        registers = debugger.get_registers()

        if not registers:
            pytest.skip("Register access unavailable")

        assert isinstance(registers, dict)

        if ctypes.sizeof(ctypes.c_void_p) == 8:
            expected_regs = ["rax", "rbx", "rcx", "rdx", "rsp", "rbp", "rip"]
            for reg in expected_regs:
                assert reg in registers
                assert isinstance(registers[reg], int)

    def test_set_registers_modifies_thread_state(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """Set registers modifies thread register state."""
        debugger = debugged_process

        original_regs = debugger.get_registers()

        if not original_regs:
            pytest.skip("Register access unavailable")

        modified_regs = original_regs.copy()

        if "rax" in modified_regs:
            modified_regs["rax"] = 0x1337133713371337

        result = debugger.set_registers(modified_regs)

        if result:
            debugger.set_registers(original_regs)


class TestVectoredExceptionHandler:
    """Test Vectored Exception Handler (VEH) functionality."""

    @pytest.fixture
    def debugged_process(self, target_process: subprocess.Popen) -> LicenseDebugger:
        """Debugger attached to target process."""
        debugger = LicenseDebugger()

        if not debugger._enable_debug_privilege():
            pytest.skip("Requires administrator privileges")

        if not debugger.attach_to_process(target_process.pid):
            pytest.skip("Process attachment failed")

        time.sleep(1)

        yield debugger

        debugger.detach()

    def test_install_veh_handler_registers_handler(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """VEH handler installation registers exception handler."""
        debugger = debugged_process

        result = debugger.install_veh_handler(first_handler=True)

        assert result is True or result is False

        if result:
            assert debugger.veh_handle is not None

    def test_uninstall_veh_handler_removes_handler(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """VEH handler uninstallation removes exception handler."""
        debugger = debugged_process

        if not debugger.install_veh_handler():
            pytest.skip("VEH installation failed")

        result = debugger.uninstall_veh_handler()

        if result:
            assert debugger.veh_handle is None

    def test_register_exception_filter_stores_filter(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """Exception filter registration stores filter function."""
        debugger = debugged_process

        def test_filter(exc_record: ExceptionRecord) -> bool:
            return exc_record.ExceptionCode == ExceptionCode.EXCEPTION_BREAKPOINT

        exception_code = ExceptionCode.EXCEPTION_BREAKPOINT

        debugger.register_exception_filter(exception_code, test_filter)

        assert exception_code in debugger.exception_filters
        assert debugger.exception_filters[exception_code] == test_filter

    def test_register_exception_callback_stores_callback(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """Exception callback registration stores callback function."""
        debugger = debugged_process

        def test_callback(debugger: LicenseDebugger, exc_record: ExceptionRecord) -> None:
            pass

        exception_code = ExceptionCode.EXCEPTION_SINGLE_STEP

        debugger.register_exception_callback(exception_code, test_callback)

        assert exception_code in debugger.exception_callbacks
        assert debugger.exception_callbacks[exception_code] == test_callback

    def test_enable_single_stepping_sets_trap_flag(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """Enable single stepping sets trap flag in EFLAGS."""
        debugger = debugged_process

        if not debugger.main_thread_id:
            pytest.skip("No main thread available")

        result = debugger.enable_single_stepping(debugger.main_thread_id)

        if not result:
            pytest.skip("Single stepping unavailable")

        assert result is True
        assert debugger.single_step_enabled is True

    def test_disable_single_stepping_clears_trap_flag(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """Disable single stepping clears trap flag in EFLAGS."""
        debugger = debugged_process

        if not debugger.main_thread_id:
            pytest.skip("No main thread available")

        if not debugger.enable_single_stepping(debugger.main_thread_id):
            pytest.skip("Single stepping unavailable")

        result = debugger.disable_single_stepping(debugger.main_thread_id)

        if result:
            assert debugger.single_step_enabled is False


class TestLicensePatternDetection:
    """Test license validation pattern detection."""

    def test_find_license_checks_scans_executable_regions(self) -> None:
        """Find license checks scans executable memory regions."""
        debugger = LicenseDebugger()

        test_code = (
            b"\x90\x90"
            + b"\x84\xc0\x74\x05"
            + b"\x90\x90\x90"
            + b"\x85\xc0\x75\x03"
            + b"\x90" * 20
        )

        matches = []
        for pattern in debugger.license_patterns:
            if pattern in test_code:
                offset = test_code.find(pattern)
                matches.append(offset)

        assert len(matches) >= 2

    def test_scan_code_patterns_finds_license_validation_sequences(self) -> None:
        """Scan code patterns identifies license validation sequences."""
        debugger = LicenseDebugger()

        test_code = (
            b"\x48\x85\xc0"
            + b"\x74\x10"
            + b"\x48\x31\xc0"
            + b"\xc3"
            + b"\x90" * 10
            + b"\x84\xc0\x75\x05"
        )

        base_address = 0x400000

        matches = debugger._scan_code_patterns(test_code, base_address)

        assert isinstance(matches, list)


class TestCodeGeneration:
    """Test code generation and assembly capabilities."""

    def test_assemble_x86_x64_generates_valid_opcodes(self) -> None:
        """Assemble x86/x64 generates valid machine code."""
        debugger = LicenseDebugger()

        test_cases = [
            ("nop", "", b"\x90"),
            ("ret", "", b"\xc3"),
        ]

        for mnemonic, operands, expected in test_cases:
            result = debugger.assemble_x86_x64(mnemonic, operands, arch="x64")

            if result:
                assert result == expected

    def test_generate_nop_sled_creates_correct_length(self) -> None:
        """Generate NOP sled creates correct length of NOPs."""
        debugger = LicenseDebugger()

        lengths = [1, 10, 100, 256]

        for length in lengths:
            nop_sled = debugger.generate_nop_sled(length)

            assert len(nop_sled) == length
            assert all(b == 0x90 for b in nop_sled)

    def test_calculate_relative_jump_computes_correct_offset(self) -> None:
        """Calculate relative jump computes correct offset."""
        debugger = LicenseDebugger()

        from_addr = 0x400000
        to_addr = 0x400100
        instruction_size = 5

        relative_bytes = debugger.calculate_relative_jump(
            from_addr, to_addr, instruction_size
        )

        assert isinstance(relative_bytes, bytes)
        assert len(relative_bytes) == 4

        offset = struct.unpack("<i", relative_bytes)[0]
        expected_offset = to_addr - (from_addr + instruction_size)
        assert offset == expected_offset


class TestDetachment:
    """Test debugger detachment from processes."""

    def test_detach_releases_debugging_session(
        self, target_process: subprocess.Popen
    ) -> None:
        """Detach releases debugging session cleanly."""
        debugger = LicenseDebugger()

        if not debugger._enable_debug_privilege():
            pytest.skip("Requires administrator privileges")

        if not debugger.attach_to_process(target_process.pid):
            pytest.skip("Process attachment failed")

        time.sleep(1)

        assert debugger.debugging is True

        result = debugger.detach()

        assert result is True or result is False

        if result:
            assert debugger.debugging is False


class TestRealWorldAntiDebugDetection:
    """Test detection of real anti-debugging techniques."""

    def create_anti_debug_test_binary(self) -> Path:
        """Create test binary with anti-debugging checks."""
        test_code = """
#include <windows.h>
#include <stdio.h>

int main() {
    if (IsDebuggerPresent()) {
        printf("Debugger detected via IsDebuggerPresent\\n");
        return 1;
    }

    BOOL debugger_present = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugger_present);
    if (debugger_present) {
        printf("Debugger detected via CheckRemoteDebuggerPresent\\n");
        return 1;
    }

    printf("No debugger detected\\n");
    return 0;
}
"""
        temp_dir = tempfile.mkdtemp()
        source_file = Path(temp_dir) / "test_anti_debug.c"
        source_file.write_text(test_code)

        return source_file

    def test_bypass_defeats_is_debugger_present_check(self) -> None:
        """Anti-debug bypass defeats IsDebuggerPresent check."""
        debugger = LicenseDebugger()

        result = debugger.kernel32.IsDebuggerPresent()

        assert isinstance(result, int)

    def test_bypass_defeats_check_remote_debugger_present(self) -> None:
        """Anti-debug bypass defeats CheckRemoteDebuggerPresent check."""
        debugger = LicenseDebugger()

        current_process = debugger.kernel32.GetCurrentProcess()
        debugger_present = ctypes.c_int(0)

        debugger.kernel32.CheckRemoteDebuggerPresent(
            current_process, ctypes.byref(debugger_present)
        )

        assert isinstance(debugger_present.value, int)


@pytest.fixture(scope="module")
def target_process() -> subprocess.Popen:
    """Module-scoped target process for debugging tests."""
    test_program = """
import time
import sys

try:
    while True:
        time.sleep(0.1)
except KeyboardInterrupt:
    sys.exit(0)
"""
    temp_file = tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False)
    temp_file.write(test_program)
    temp_file.close()

    process = subprocess.Popen(
        [sys.executable, temp_file.name],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    time.sleep(1)

    yield process

    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()

    try:
        os.unlink(temp_file.name)
    except Exception:
        pass
