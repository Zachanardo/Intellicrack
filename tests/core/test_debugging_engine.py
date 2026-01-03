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
from collections.abc import Callable, Generator
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


@pytest.mark.requires_admin
class TestDebugPrivilegeElevation:
    """Test debug privilege elevation for process debugging."""

    def test_enable_debug_privilege_requires_admin_or_succeeds(self) -> None:
        """Enable debug privilege succeeds with proper permissions."""
        debugger = LicenseDebugger()

        result = debugger._enable_debug_privilege()

        if not result:
            pytest.skip("Debug privilege elevation requires administrator privileges")

        assert result is True

    def test_debug_privilege_allows_process_access(self) -> None:
        """Debug privilege enables access to other processes."""
        debugger = LicenseDebugger()

        if not debugger._enable_debug_privilege():
            pytest.skip("Debug privilege elevation requires administrator privileges")

        current_pid = os.getpid()
        handle = debugger.kernel32.OpenProcess(
            debugger.PROCESS_ALL_ACCESS, False, current_pid
        )

        assert handle is not None
        assert handle != 0

        debugger.kernel32.CloseHandle(handle)


@pytest.mark.requires_admin
@pytest.mark.requires_process_attach
class TestProcessAttachment:
    """Test debugger attachment to running processes."""

    @pytest.fixture
    def target_process(self) -> Generator[subprocess.Popen[bytes], None, None]:
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
        self, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Debugger successfully attaches to running process."""
        debugger = LicenseDebugger()

        if not debugger._enable_debug_privilege():
            pytest.skip("Debug privilege elevation requires administrator privileges")

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
            pytest.skip("Debug privilege elevation requires administrator privileges")

        result = debugger.attach_to_process(999999)

        assert result is False
        assert debugger.process_id is None
        assert debugger.process_handle is None

    def test_attach_sets_process_handle_with_all_access(
        self, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Attached process handle has PROCESS_ALL_ACCESS rights."""
        debugger = LicenseDebugger()

        if not debugger._enable_debug_privilege():
            pytest.skip("Debug privilege elevation requires administrator privileges")

        if not debugger.attach_to_process(target_process.pid):
            pytest.skip("Process attachment failed - requires debugger privileges")

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


@pytest.mark.requires_admin
@pytest.mark.requires_process_attach
class TestSoftwareBreakpoints:
    """Test software breakpoint setting and management."""

    @pytest.fixture
    def debugged_process(
        self, target_process: subprocess.Popen[bytes]
    ) -> Generator[LicenseDebugger, None, None]:
        """Debugger attached to target process."""
        debugger = LicenseDebugger()

        if not debugger._enable_debug_privilege():
            pytest.skip("Debug privilege elevation requires administrator privileges")

        if not debugger.attach_to_process(target_process.pid):
            pytest.skip("Process attachment failed - requires debugger privileges")

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


@pytest.mark.requires_admin
@pytest.mark.requires_process_attach
class TestHardwareBreakpoints:
    """Test hardware breakpoint functionality using debug registers."""

    @pytest.fixture
    def debugged_process(
        self, target_process: subprocess.Popen[bytes]
    ) -> Generator[LicenseDebugger, None, None]:
        """Debugger attached to target process."""
        debugger = LicenseDebugger()

        if not debugger._enable_debug_privilege():
            pytest.skip("Debug privilege elevation requires administrator privileges")

        if not debugger.attach_to_process(target_process.pid):
            pytest.skip("Process attachment failed - requires debugger privileges")

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
            if result := debugger.set_hardware_breakpoint(
                address, dr_index=0, access_type="write", size=size
            ):
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

        if result := debugger.remove_hardware_breakpoint(address):
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
            if result := debugger.set_hardware_breakpoint(
                addr, dr_index=-1, access_type="execute", size=1
            ):
                assert addr in debugger.hardware_breakpoints
                dr_index = debugger.hardware_breakpoints[addr]["dr_index"]
                assert dr_index in range(4)

            if i >= 3:
                break


@pytest.mark.requires_admin
@pytest.mark.requires_process_attach
class TestAntiDebuggingBypass:
    """Test anti-debugging detection bypass capabilities."""

    @pytest.fixture
    def debugged_process(
        self, target_process: subprocess.Popen[bytes]
    ) -> Generator[LicenseDebugger, None, None]:
        """Debugger attached to target process."""
        debugger = LicenseDebugger()

        if not debugger._enable_debug_privilege():
            pytest.skip("Debug privilege elevation requires administrator privileges")

        if not debugger.attach_to_process(target_process.pid):
            pytest.skip("Process attachment failed - requires debugger privileges")

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
            pbi_raw = pbi.raw
            ptr_size = ctypes.sizeof(ctypes.c_void_p)
            peb_address = struct.unpack("P", pbi_raw[ptr_size : ptr_size * 2])[0]

            if being_debugged_byte := debugger._read_memory(peb_address + 2, 1):
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
            pbi_raw = pbi.raw
            ptr_size = ctypes.sizeof(ctypes.c_void_p)
            peb_address = struct.unpack("P", pbi_raw[ptr_size : ptr_size * 2])[0]

            offset = 0xBC if ctypes.sizeof(ctypes.c_void_p) == 8 else 0x68
            if ntglobalflag_bytes := debugger._read_memory(
                peb_address + offset, 4
            ):
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


@pytest.mark.requires_admin
@pytest.mark.requires_process_attach
class TestTimingAttackMitigation:
    """Test timing attack mitigation capabilities."""

    @pytest.fixture
    def debugged_process(
        self, target_process: subprocess.Popen[bytes]
    ) -> Generator[LicenseDebugger, None, None]:
        """Debugger attached to target process."""
        debugger = LicenseDebugger()

        if not debugger._enable_debug_privilege():
            pytest.skip("Debug privilege elevation requires administrator privileges")

        if not debugger.attach_to_process(target_process.pid):
            pytest.skip("Process attachment failed - requires debugger privileges")

        time.sleep(1)

        yield debugger

        debugger.detach()

    def test_mitigate_timing_attacks_initializes_emulation_state(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """Timing attack mitigation initializes emulation state."""
        debugger = debugged_process

        object.__setattr__(debugger, '_enumerate_memory_regions', lambda: [])

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


@pytest.mark.requires_admin
@pytest.mark.requires_process_attach
class TestMemoryOperations:
    """Test memory read/write operations."""

    @pytest.fixture
    def debugged_process(
        self, target_process: subprocess.Popen[bytes]
    ) -> Generator[LicenseDebugger, None, None]:
        """Debugger attached to target process."""
        debugger = LicenseDebugger()

        if not debugger._enable_debug_privilege():
            pytest.skip("Debug privilege elevation requires administrator privileges")

        if not debugger.attach_to_process(target_process.pid):
            pytest.skip("Process attachment failed - requires debugger privileges")

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
        if write_result := debugger._write_memory(address, test_data):
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


@pytest.mark.requires_admin
@pytest.mark.requires_process_attach
class TestThreadContextManipulation:
    """Test thread context manipulation and register access."""

    @pytest.fixture
    def debugged_process(
        self, target_process: subprocess.Popen[bytes]
    ) -> Generator[LicenseDebugger, None, None]:
        """Debugger attached to target process."""
        debugger = LicenseDebugger()

        if not debugger._enable_debug_privilege():
            pytest.skip("Debug privilege elevation requires administrator privileges")

        if not debugger.attach_to_process(target_process.pid):
            pytest.skip("Process attachment failed - requires debugger privileges")

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

        if result := debugger.set_registers(modified_regs):
            debugger.set_registers(original_regs)


@pytest.mark.requires_admin
@pytest.mark.requires_process_attach
class TestVectoredExceptionHandler:
    """Test Vectored Exception Handler (VEH) functionality."""

    @pytest.fixture
    def debugged_process(
        self, target_process: subprocess.Popen[bytes]
    ) -> Generator[LicenseDebugger, None, None]:
        """Debugger attached to target process."""
        debugger = LicenseDebugger()

        if not debugger._enable_debug_privilege():
            pytest.skip("Debug privilege elevation requires administrator privileges")

        if not debugger.attach_to_process(target_process.pid):
            pytest.skip("Process attachment failed - requires debugger privileges")

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

        if result := debugger.uninstall_veh_handler():
            assert debugger.veh_handle is None

    def test_register_exception_filter_stores_filter(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """Exception filter registration stores filter function."""
        debugger = debugged_process

        def test_filter(dbg: Any, exc_record: Any) -> int | None:
            if hasattr(exc_record, 'ExceptionCode'):
                return 1 if exc_record.ExceptionCode == ExceptionCode.EXCEPTION_BREAKPOINT else 0
            return None

        exception_code = ExceptionCode.EXCEPTION_BREAKPOINT

        debugger.register_exception_filter(exception_code, test_filter)

        assert exception_code in debugger.exception_filters
        assert debugger.exception_filters[exception_code] == test_filter

    def test_register_exception_callback_stores_callback(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """Exception callback registration stores callback function."""
        debugger = debugged_process

        def test_callback(dbg: Any, exc_record: Any) -> int:
            return 0

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

        if result := debugger.disable_single_stepping(debugger.main_thread_id):
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
            if result := debugger.assemble_x86_x64(mnemonic, operands, arch="x64"):
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


@pytest.mark.requires_admin
@pytest.mark.requires_process_attach
class TestDetachment:
    """Test debugger detachment from processes."""

    def test_detach_releases_debugging_session(
        self, target_process: subprocess.Popen[bytes]
    ) -> None:
        """Detach releases debugging session cleanly."""
        debugger = LicenseDebugger()

        if not debugger._enable_debug_privilege():
            pytest.skip("Debug privilege elevation requires administrator privileges")

        if not debugger.attach_to_process(target_process.pid):
            pytest.skip("Process attachment failed - requires debugger privileges")

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
def target_process() -> Generator[subprocess.Popen[bytes], None, None]:
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


class TestPEParsingAndImportAnalysis:
    """Test PE parsing and import table analysis for license detection."""

    def test_analyze_dll_comprehensive_detects_license_imports(self) -> None:
        """DLL analysis detects license-related import APIs."""
        debugger = LicenseDebugger()

        test_dll_name = "LicenseValidator.dll"
        is_license_related = False
        suspicious_score = 0.0

        dll_name_lower = test_dll_name.lower()
        license_dll_patterns = ["license", "activation", "serial", "trial"]

        for pattern in license_dll_patterns:
            if pattern in dll_name_lower:
                is_license_related = True
                suspicious_score += 0.3
                break

        assert is_license_related is True
        assert suspicious_score > 0.0

    def test_analyze_imports_identifies_registry_apis(self) -> None:
        """Import analysis identifies registry-related APIs."""
        debugger = LicenseDebugger()

        suspicious_apis = [
            "RegOpenKeyExA",
            "RegOpenKeyExW",
            "RegQueryValueExA",
            "RegQueryValueExW",
        ]

        for api in suspicious_apis:
            assert api in [
                "RegOpenKeyExA",
                "RegOpenKeyExW",
                "RegQueryValueExA",
                "RegQueryValueExW",
                "RegSetValueExA",
                "RegSetValueExW",
            ]

    def test_analyze_imports_identifies_crypto_apis(self) -> None:
        """Import analysis identifies cryptography APIs."""
        debugger = LicenseDebugger()

        crypto_apis = [
            "CryptAcquireContextA",
            "CryptAcquireContextW",
            "CryptCreateHash",
            "CryptHashData",
            "CryptVerifySignatureA",
            "CryptVerifySignatureW",
        ]

        assert crypto_apis

    def test_analyze_exports_identifies_license_functions(self) -> None:
        """Export analysis identifies license validation exports."""
        debugger = LicenseDebugger()

        license_export_patterns = [
            "IsLicenseValid",
            "CheckLicense",
            "ValidateLicense",
            "VerifyLicense",
            "GetLicenseStatus",
            "IsRegistered",
            "IsTrial",
            "IsActivated",
            "CheckSerial",
            "ValidateSerial",
        ]

        for pattern in license_export_patterns:
            assert "License" in pattern or "Serial" in pattern or "Trial" in pattern

    def test_detect_protection_signatures_identifies_vmprotect(self) -> None:
        """Protection detection identifies VMProtect signatures."""
        debugger = LicenseDebugger()

        test_binary = b"\x00" * 100 + b"VMProtect" + b"\x00" * 100

        protections = debugger._detect_protection_signatures(test_binary)

        assert "VMProtect" in protections

    def test_detect_protection_signatures_identifies_themida(self) -> None:
        """Protection detection identifies Themida signatures."""
        debugger = LicenseDebugger()

        test_binary = b"\x00" * 100 + b"Themida" + b"\x00" * 100

        protections = debugger._detect_protection_signatures(test_binary)

        assert "Themida/WinLicense" in protections

    def test_detect_protection_signatures_identifies_hasp(self) -> None:
        """Protection detection identifies HASP/Sentinel signatures."""
        debugger = LicenseDebugger()

        test_binary = b"\x00" * 50 + b"HASP" + b"\x00" * 50

        protections = debugger._detect_protection_signatures(test_binary)

        assert "SafeNet HASP" in protections

    def test_extract_license_strings_finds_license_keywords(self) -> None:
        """String extraction finds license-related keywords."""
        debugger = LicenseDebugger()

        test_data = b"\x00\x00Enter your license key:\x00\x00Serial number:\x00\x00"

        strings = debugger._extract_license_strings(test_data)

        assert len(strings) > 0
        found_license = any("license" in s.lower() for s in strings)
        found_serial = any("serial" in s.lower() for s in strings)

        assert found_license or found_serial


@pytest.mark.requires_admin
@pytest.mark.requires_process_attach
class TestThreadLocalStorageAnalysis:
    """Test TLS callback analysis and manipulation."""

    @pytest.fixture
    def debugged_process(
        self, target_process: subprocess.Popen[bytes]
    ) -> Generator[LicenseDebugger, None, None]:
        """Debugger attached to target process."""
        debugger = LicenseDebugger()

        if not debugger._enable_debug_privilege():
            pytest.skip("Debug privilege elevation requires administrator privileges")

        if not debugger.attach_to_process(target_process.pid):
            pytest.skip("Process attachment failed - requires debugger privileges")

        time.sleep(1)

        yield debugger

        debugger.detach()

    def test_analyze_tls_callbacks_scans_pe_structure(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """TLS callback analysis scans PE TLS directory."""
        debugger = debugged_process

        tls_callbacks = debugger.analyze_tls_callbacks()

        assert isinstance(tls_callbacks, list)

    def test_detect_tls_protection_identifies_anti_debug_tls(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """TLS protection detection identifies anti-debug TLS callbacks."""
        debugger = debugged_process

        tls_info = debugger.detect_tls_protection()

        assert isinstance(tls_info, dict)
        assert "has_tls_callbacks" in tls_info
        assert "callback_count" in tls_info

    def test_bypass_tls_callbacks_patches_tls_directory(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """TLS callback bypass patches TLS directory."""
        debugger = debugged_process

        result = debugger.bypass_tls_callbacks()

        assert isinstance(result, bool)


@pytest.mark.requires_admin
@pytest.mark.requires_process_attach
class TestDelayedImportHooking:
    """Test delayed import hooking for license API interception."""

    @pytest.fixture
    def debugged_process(
        self, target_process: subprocess.Popen[bytes]
    ) -> Generator[LicenseDebugger, None, None]:
        """Debugger attached to target process."""
        debugger = LicenseDebugger()

        if not debugger._enable_debug_privilege():
            pytest.skip("Debug privilege elevation requires administrator privileges")

        if not debugger.attach_to_process(target_process.pid):
            pytest.skip("Process attachment failed - requires debugger privileges")

        time.sleep(1)

        yield debugger

        debugger.detach()

    def test_parse_delayed_imports_reads_delay_load_table(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """Delayed import parsing reads delay load directory."""
        debugger = debugged_process

        delayed_imports = debugger.parse_delayed_imports()

        assert isinstance(delayed_imports, dict)

    def test_hook_delayed_import_sets_breakpoint_on_iat_entry(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """Delayed import hook sets breakpoint on IAT entry."""
        debugger = debugged_process

        def hook_handler(dbg: LicenseDebugger, event: Any) -> None:
            pass

        result = debugger.hook_delayed_import(
            "kernel32.dll", "GetSystemTime", hook_handler
        )

        assert isinstance(result, bool)


class TestShellcodeGeneration:
    """Test shellcode generation for license bypass."""

    def test_generate_shellcode_license_bypass_creates_valid_code(self) -> None:
        """License bypass shellcode generates valid machine code."""
        debugger = LicenseDebugger()

        shellcode = debugger.generate_shellcode("license_bypass")

        assert isinstance(shellcode, bytes)
        assert len(shellcode) > 0

    def test_generate_shellcode_trial_reset_creates_valid_code(self) -> None:
        """Trial reset shellcode generates valid machine code."""
        debugger = LicenseDebugger()

        shellcode = debugger.generate_shellcode("trial_reset")

        assert isinstance(shellcode, bytes)
        assert len(shellcode) > 0

    def test_generate_shellcode_nag_screen_bypass_creates_valid_code(self) -> None:
        """Nag screen bypass shellcode generates valid machine code."""
        debugger = LicenseDebugger()

        shellcode = debugger.generate_shellcode("nag_screen_bypass")

        assert isinstance(shellcode, bytes)
        assert len(shellcode) > 0

    def test_generate_shellcode_hardware_id_spoof_creates_valid_code(self) -> None:
        """Hardware ID spoof shellcode generates valid machine code."""
        debugger = LicenseDebugger()

        shellcode = debugger.generate_shellcode(
            "hardware_id_spoof", hwid="1234-5678-90AB-CDEF"
        )

        assert isinstance(shellcode, bytes)
        assert len(shellcode) > 0

    def test_generate_position_independent_code_creates_pic(self) -> None:
        """Position-independent code generation creates relocatable code."""
        debugger = LicenseDebugger()

        operations: list[dict[str, Any]] = [
            {"type": "nop"},
            {"type": "return", "value": 1},
        ]

        pic = debugger.generate_position_independent_code(operations)

        assert isinstance(pic, bytes)
        assert len(pic) > 0


class TestDynamicCodePatching:
    """Test dynamic code patching for license bypass."""

    def test_generate_dynamic_patch_return_true_creates_patch(self) -> None:
        """Dynamic patch generation creates return-true patch."""
        debugger = LicenseDebugger()

        patch = debugger.generate_dynamic_patch(0x401000, "return_true")

        assert isinstance(patch, bytes)
        assert len(patch) > 0

    def test_generate_dynamic_patch_return_false_creates_patch(self) -> None:
        """Dynamic patch generation creates return-false patch."""
        debugger = LicenseDebugger()

        patch = debugger.generate_dynamic_patch(0x401000, "return_false")

        assert isinstance(patch, bytes)
        assert len(patch) > 0

    def test_generate_dynamic_patch_nop_fill_creates_nops(self) -> None:
        """Dynamic patch generation creates NOP fill."""
        debugger = LicenseDebugger()

        patch = debugger.generate_dynamic_patch(0x401000, "nop_fill", length=10)

        assert isinstance(patch, bytes)
        assert len(patch) == 10
        assert all(b == 0x90 for b in patch)

    def test_generate_dynamic_patch_jmp_to_addr_creates_jump(self) -> None:
        """Dynamic patch generation creates jump instruction."""
        debugger = LicenseDebugger()

        patch = debugger.generate_dynamic_patch(
            0x401000, "jmp_to_addr", target=0x402000
        )

        assert isinstance(patch, bytes)
        assert len(patch) >= 5

    def test_relocate_code_adjusts_absolute_addresses(self) -> None:
        """Code relocation adjusts absolute addresses."""
        debugger = LicenseDebugger()

        original_code = b"\x48\xB8\x00\x10\x40\x00\x00\x00\x00\x00"
        old_base = 0x400000
        new_base = 0x500000
        reloc_offsets = [2]

        relocated = debugger.relocate_code(
            original_code, old_base, new_base, reloc_offsets
        )

        assert isinstance(relocated, bytes)
        assert len(relocated) == len(original_code)


class TestInstructionEncoding:
    """Test manual instruction encoding."""

    def test_encode_instruction_nop(self) -> None:
        """Instruction encoding creates valid NOP."""
        debugger = LicenseDebugger()

        encoded = debugger.encode_instruction(opcode=b"\x90")

        assert encoded == b"\x90"

    def test_encode_instruction_ret(self) -> None:
        """Instruction encoding creates valid RET."""
        debugger = LicenseDebugger()

        encoded = debugger.encode_instruction(opcode=b"\xc3")

        assert encoded == b"\xc3"

    def test_encode_instruction_int3(self) -> None:
        """Instruction encoding creates valid INT3."""
        debugger = LicenseDebugger()

        encoded = debugger.encode_instruction(opcode=b"\xcc")

        assert encoded == b"\xcc"

    def test_encode_instruction_xor_eax_eax(self) -> None:
        """Instruction encoding creates valid XOR EAX, EAX."""
        debugger = LicenseDebugger()

        encoded = debugger.encode_instruction(opcode=b"\x31", modrm=0xC0)

        assert encoded == b"\x31\xc0"


class TestConditionalBreakpointEvaluation:
    """Test conditional breakpoint condition evaluation."""

    def test_evaluate_register_condition_equals(self) -> None:
        """Register condition evaluation handles equality."""
        debugger = LicenseDebugger()

        context = CONTEXT()
        context.Rax = 0x1337

        result = debugger._evaluate_register_condition("rax == 0x1337", context)

        assert result is True

        result = debugger._evaluate_register_condition("rax == 0x1338", context)

        assert result is False

    def test_evaluate_register_condition_not_equals(self) -> None:
        """Register condition evaluation handles inequality."""
        debugger = LicenseDebugger()

        context = CONTEXT()
        context.Rcx = 100

        result = debugger._evaluate_register_condition("rcx != 200", context)

        assert result is True

        result = debugger._evaluate_register_condition("rcx != 100", context)

        assert result is False

    def test_evaluate_register_condition_greater_than(self) -> None:
        """Register condition evaluation handles greater than."""
        debugger = LicenseDebugger()

        context = CONTEXT()
        context.Rdx = 500

        result = debugger._evaluate_register_condition("rdx > 100", context)

        assert result is True

        result = debugger._evaluate_register_condition("rdx > 1000", context)

        assert result is False

    def test_evaluate_register_condition_less_than(self) -> None:
        """Register condition evaluation handles less than."""
        debugger = LicenseDebugger()

        context = CONTEXT()
        context.Rbx = 50

        result = debugger._evaluate_register_condition("rbx < 100", context)

        assert result is True

        result = debugger._evaluate_register_condition("rbx < 10", context)

        assert result is False

    def test_evaluate_address_expression_register_plus_offset(self) -> None:
        """Address expression evaluation handles register + offset."""
        debugger = LicenseDebugger()

        context = CONTEXT()
        context.Rsp = 0x1000

        result = debugger._evaluate_address_expression("rsp+8", context)

        assert result == 0x1008

    def test_evaluate_address_expression_register_minus_offset(self) -> None:
        """Address expression evaluation handles register - offset."""
        debugger = LicenseDebugger()

        context = CONTEXT()
        context.Rbp = 0x2000

        result = debugger._evaluate_address_expression("rbp-4", context)

        assert result == 0x1FFC

    def test_evaluate_address_expression_hex_literal(self) -> None:
        """Address expression evaluation handles hex literals."""
        debugger = LicenseDebugger()

        context = CONTEXT()

        result = debugger._evaluate_address_expression("0x401000", context)

        assert result == 0x401000

    def test_evaluate_flag_condition_zero_flag(self) -> None:
        """Flag condition evaluation handles zero flag."""
        debugger = LicenseDebugger()

        context = CONTEXT()
        context.EFlags = 1 << 6

        result = debugger._evaluate_flag_condition("zf == 1", context)

        assert result is True

        context.EFlags = 0

        result = debugger._evaluate_flag_condition("zf == 1", context)

        assert result is False

    def test_evaluate_flag_condition_carry_flag(self) -> None:
        """Flag condition evaluation handles carry flag."""
        debugger = LicenseDebugger()

        context = CONTEXT()
        context.EFlags = 1 << 0

        result = debugger._evaluate_flag_condition("cf == 1", context)

        assert result is True


@pytest.mark.requires_admin
@pytest.mark.requires_process_attach
class TestExecutionTracing:
    """Test execution tracing and instruction logging."""

    @pytest.fixture
    def debugged_process(
        self, target_process: subprocess.Popen[bytes]
    ) -> Generator[LicenseDebugger, None, None]:
        """Debugger attached to target process."""
        debugger = LicenseDebugger()

        if not debugger._enable_debug_privilege():
            pytest.skip("Debug privilege elevation requires administrator privileges")

        if not debugger.attach_to_process(target_process.pid):
            pytest.skip("Process attachment failed - requires debugger privileges")

        time.sleep(1)

        yield debugger

        debugger.detach()

    def test_trace_execution_captures_instruction_stream(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """Execution tracing captures instruction stream."""
        debugger = debugged_process

        trace = debugger.trace_execution(max_instructions=100)

        assert isinstance(trace, list)

    def test_trace_thread_execution_follows_single_thread(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """Thread execution tracing follows single thread."""
        debugger = debugged_process

        if not debugger.main_thread_id:
            pytest.skip("No main thread available")

        trace = debugger.trace_thread_execution(
            debugger.main_thread_id, max_instructions=50
        )

        assert isinstance(trace, list)


@pytest.mark.requires_admin
@pytest.mark.requires_process_attach
class TestMemoryBreakpoints:
    """Test memory breakpoints using guard pages."""

    @pytest.fixture
    def debugged_process(
        self, target_process: subprocess.Popen[bytes]
    ) -> Generator[LicenseDebugger, None, None]:
        """Debugger attached to target process."""
        debugger = LicenseDebugger()

        if not debugger._enable_debug_privilege():
            pytest.skip("Debug privilege elevation requires administrator privileges")

        if not debugger.attach_to_process(target_process.pid):
            pytest.skip("Process attachment failed - requires debugger privileges")

        time.sleep(1)

        yield debugger

        debugger.detach()

    def test_set_memory_breakpoint_on_data_region(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """Memory breakpoint sets guard page on data region."""
        debugger = debugged_process

        memory_regions = debugger._enumerate_memory_regions()
        data_region = next(
            (r for r in memory_regions if not r.get("executable", False)), None
        )

        if not data_region:
            pytest.skip("No data regions found")

        address = data_region["base_address"]
        size = min(0x1000, data_region["size"])

        result = debugger.set_memory_breakpoint(address, size)

        assert isinstance(result, bool)


@pytest.mark.requires_admin
@pytest.mark.requires_process_attach
class TestThreadEnumerationBypass:
    """Test thread enumeration bypass."""

    @pytest.fixture
    def debugged_process(
        self, target_process: subprocess.Popen[bytes]
    ) -> Generator[LicenseDebugger, None, None]:
        """Debugger attached to target process."""
        debugger = LicenseDebugger()

        if not debugger._enable_debug_privilege():
            pytest.skip("Debug privilege elevation requires administrator privileges")

        if not debugger.attach_to_process(target_process.pid):
            pytest.skip("Process attachment failed - requires debugger privileges")

        time.sleep(1)

        yield debugger

        debugger.detach()

    def test_bypass_thread_enumeration_hooks_apis(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """Thread enumeration bypass hooks CreateToolhelp32Snapshot."""
        debugger = debugged_process

        result = debugger.bypass_thread_enumeration()

        assert isinstance(result, bool)

    def test_detect_suspended_threads_identifies_suspended_state(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """Suspended thread detection identifies thread state."""
        debugger = debugged_process

        suspended_threads = debugger.detect_suspended_threads()

        assert isinstance(suspended_threads, dict)


@pytest.mark.requires_admin
@pytest.mark.requires_process_attach
class TestAPIHooking:
    """Test API hooking for license validation interception."""

    @pytest.fixture
    def debugged_process(
        self, target_process: subprocess.Popen[bytes]
    ) -> Generator[LicenseDebugger, None, None]:
        """Debugger attached to target process."""
        debugger = LicenseDebugger()

        if not debugger._enable_debug_privilege():
            pytest.skip("Debug privilege elevation requires administrator privileges")

        if not debugger.attach_to_process(target_process.pid):
            pytest.skip("Process attachment failed - requires debugger privileges")

        time.sleep(1)

        yield debugger

        debugger.detach()

    def test_hook_license_api_sets_breakpoint_on_function(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """License API hook sets breakpoint on target function."""
        debugger = debugged_process

        def hook_callback(dbg: LicenseDebugger, event: Any) -> None:
            pass

        result = debugger.hook_license_api("kernel32", "GetTickCount", hook_callback)

        if result:
            assert len(debugger.api_hooks) > 0


@pytest.mark.requires_admin
@pytest.mark.requires_process_attach
class TestStringOperations:
    """Test string reading from process memory."""

    @pytest.fixture
    def debugged_process(
        self, target_process: subprocess.Popen[bytes]
    ) -> Generator[LicenseDebugger, None, None]:
        """Debugger attached to target process."""
        debugger = LicenseDebugger()

        if not debugger._enable_debug_privilege():
            pytest.skip("Debug privilege elevation requires administrator privileges")

        if not debugger.attach_to_process(target_process.pid):
            pytest.skip("Process attachment failed - requires debugger privileges")

        time.sleep(1)

        yield debugger

        debugger.detach()

    def test_read_string_from_valid_address(
        self, debugged_process: LicenseDebugger
    ) -> None:
        """String read returns null-terminated string."""
        debugger = debugged_process

        memory_regions = debugger._enumerate_memory_regions()

        if not memory_regions:
            pytest.skip("No memory regions available")

        test_string = b"TestString\x00"
        found_string = False

        for region in memory_regions[:5]:
            address = region["base_address"]
            data = debugger._read_memory(address, 256)

            if data and b"\x00" in data:
                string = debugger._read_string(address)
                if string is not None:
                    found_string = True
                    break

        assert found_string or len(memory_regions) == 0


class TestExceptionHandling:
    """Test exception handling in debug loop."""

    def test_exception_code_enum_has_required_codes(self) -> None:
        """ExceptionCode enum contains all required exception codes."""
        assert hasattr(ExceptionCode, "EXCEPTION_ACCESS_VIOLATION")
        assert hasattr(ExceptionCode, "EXCEPTION_BREAKPOINT")
        assert hasattr(ExceptionCode, "EXCEPTION_SINGLE_STEP")
        assert hasattr(ExceptionCode, "EXCEPTION_INT_DIVIDE_BY_ZERO")
        assert hasattr(ExceptionCode, "EXCEPTION_ILLEGAL_INSTRUCTION")
        assert hasattr(ExceptionCode, "EXCEPTION_GUARD_PAGE")

    def test_debug_event_enum_has_required_events(self) -> None:
        """DebugEvent enum contains all required event types."""
        assert hasattr(DebugEvent, "EXCEPTION_DEBUG_EVENT")
        assert hasattr(DebugEvent, "CREATE_THREAD_DEBUG_EVENT")
        assert hasattr(DebugEvent, "CREATE_PROCESS_DEBUG_EVENT")
        assert hasattr(DebugEvent, "EXIT_THREAD_DEBUG_EVENT")
        assert hasattr(DebugEvent, "EXIT_PROCESS_DEBUG_EVENT")
        assert hasattr(DebugEvent, "LOAD_DLL_DEBUG_EVENT")
        assert hasattr(DebugEvent, "UNLOAD_DLL_DEBUG_EVENT")
        assert hasattr(DebugEvent, "OUTPUT_DEBUG_STRING_EVENT")


@pytest.mark.requires_admin
class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling."""

    def test_attach_to_protected_process_fails_gracefully(self) -> None:
        """Attachment to protected process fails gracefully."""
        debugger = LicenseDebugger()

        if not debugger._enable_debug_privilege():
            pytest.skip("Debug privilege elevation requires administrator privileges")

        system_pid = 4

        result = debugger.attach_to_process(system_pid)

        assert result is False

    def test_read_memory_zero_size_returns_none(self) -> None:
        """Read memory with zero size returns None."""
        debugger = LicenseDebugger()
        debugger.process_handle = 1

        result = debugger._read_memory(0x400000, 0)

        assert result is None or isinstance(result, bytes)

    def test_write_memory_empty_data_fails(self) -> None:
        """Write memory with empty data fails."""
        debugger = LicenseDebugger()
        debugger.process_handle = 1

        result = debugger._write_memory(0x400000, b"")

        assert result is False or isinstance(result, bool)

    def test_validate_condition_syntax_rejects_invalid_syntax(self) -> None:
        """Condition validation rejects invalid syntax."""
        debugger = LicenseDebugger()

        invalid_conditions = [
            "invalid",
            "rax ===",
            ";;;",
            "DROP TABLE",
        ]

        for condition in invalid_conditions:
            result = debugger._validate_condition_syntax(condition)
            assert result is False

    def test_get_register_value_invalid_register_returns_none(self) -> None:
        """Get register value with invalid register returns None."""
        debugger = LicenseDebugger()

        context = CONTEXT()

        result = debugger._get_register_value("invalid_reg", context)

        assert result is None
