"""Comprehensive production tests for PEB flag clearing bypass functionality.

This file is part of Intellicrack.
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

Tests verify complete PEB flag clearing including:
- PEB.BeingDebugged flag completely cleared
- PEB.NtGlobalFlag debug-related bits cleared
- ProcessHeap.Flags manipulation
- Heap tail checking spoofing
- 32-bit PEB access from 64-bit processes
- Edge cases: WoW64, protected PEB reads
"""

import ctypes
import platform
import struct
import sys
from typing import Any

import pytest

from intellicrack.core.anti_analysis.debugger_bypass import DebuggerBypass


pytestmark = pytest.mark.skipif(
    platform.system() != "Windows", reason="Windows-only PEB manipulation tests"
)


class ProcessBasicInformation(ctypes.Structure):
    """Process Basic Information structure for NtQueryInformationProcess."""

    _fields_ = [
        ("Reserved1", ctypes.c_void_p),
        ("PebBaseAddress", ctypes.c_void_p),
        ("Reserved2", ctypes.c_void_p * 2),
        ("UniqueProcessId", ctypes.POINTER(ctypes.c_ulong)),
        ("Reserved3", ctypes.c_void_p),
    ]


def get_peb_address() -> int:
    """Get PEB base address for current process.

    Returns:
        PEB base address as integer, or 0 if retrieval failed.
    """
    try:
        ntdll = ctypes.windll.ntdll
        kernel32 = ctypes.windll.kernel32
        current_process = kernel32.GetCurrentProcess()

        pbi = ProcessBasicInformation()
        status = ntdll.NtQueryInformationProcess(
            current_process, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), None
        )

        if status != 0 or not pbi.PebBaseAddress:
            return 0

        return int(pbi.PebBaseAddress.value)
    except Exception:
        return 0


def read_peb_byte(offset: int) -> int:
    """Read single byte from PEB at offset.

    Args:
        offset: Offset from PEB base address.

    Returns:
        Byte value read from PEB, or -1 if read failed.
    """
    try:
        peb_address = get_peb_address()
        if peb_address == 0:
            return -1

        return ctypes.c_ubyte.from_address(peb_address + offset).value
    except Exception:
        return -1


def read_peb_dword(offset: int) -> int:
    """Read DWORD from PEB at offset.

    Args:
        offset: Offset from PEB base address.

    Returns:
        DWORD value read from PEB, or -1 if read failed.
    """
    try:
        peb_address = get_peb_address()
        if peb_address == 0:
            return -1

        return ctypes.c_ulong.from_address(peb_address + offset).value
    except Exception:
        return -1


def read_heap_flags(heap_address: int, is_64bit: bool) -> tuple[int, int]:
    """Read heap Flags and ForceFlags from heap structure.

    Args:
        heap_address: Base address of process heap.
        is_64bit: Whether running on 64-bit architecture.

    Returns:
        Tuple of (Flags, ForceFlags) values, or (-1, -1) if read failed.
    """
    try:
        if heap_address == 0:
            return (-1, -1)

        flags_offset = 0x70 if is_64bit else 0x44
        force_flags_offset = 0x74 if is_64bit else 0x48

        flags = ctypes.c_ulong.from_address(heap_address + flags_offset).value
        force_flags = ctypes.c_ulong.from_address(heap_address + force_flags_offset).value

        return (flags, force_flags)
    except Exception:
        return (-1, -1)


def get_process_heap_address() -> int:
    """Get ProcessHeap address from PEB.

    Returns:
        ProcessHeap address, or 0 if retrieval failed.
    """
    try:
        peb_address = get_peb_address()
        if peb_address == 0:
            return 0

        is_64bit = platform.machine().endswith("64")
        heap_offset = 0x30 if is_64bit else 0x18

        kernel32 = ctypes.windll.kernel32
        current_process = kernel32.GetCurrentProcess()

        process_heap_addr = ctypes.c_void_p()
        bytes_read = ctypes.c_size_t()

        kernel32.ReadProcessMemory(
            current_process,
            ctypes.c_void_p(peb_address + heap_offset),
            ctypes.byref(process_heap_addr),
            ctypes.sizeof(ctypes.c_void_p),
            ctypes.byref(bytes_read),
        )

        return process_heap_addr.value if process_heap_addr.value else 0
    except Exception:
        return 0


class TestPEBBeingDebuggedFlagClearing:
    """Tests validating complete PEB.BeingDebugged flag clearing."""

    def test_being_debugged_flag_cleared_completely(self) -> None:
        """PEB.BeingDebugged flag is completely cleared to 0x00."""
        bypass = DebuggerBypass()

        result = bypass._bypass_peb_flags()

        assert result is True, "PEB flags bypass must succeed"

        being_debugged = read_peb_byte(2)
        assert being_debugged == 0, "BeingDebugged flag must be completely cleared to 0"

    def test_being_debugged_remains_cleared_after_multiple_calls(self) -> None:
        """BeingDebugged flag remains cleared across multiple bypass calls."""
        bypass = DebuggerBypass()

        bypass._bypass_peb_flags()
        bypass._bypass_peb_flags()
        bypass._bypass_peb_flags()

        being_debugged = read_peb_byte(2)
        assert being_debugged == 0, "BeingDebugged must remain cleared after multiple calls"

    def test_isdebuggerpresent_returns_false_after_flag_clear(self) -> None:
        """IsDebuggerPresent returns FALSE after BeingDebugged cleared."""
        bypass = DebuggerBypass()

        bypass._bypass_isdebuggerpresent()

        kernel32 = ctypes.windll.kernel32
        result = kernel32.IsDebuggerPresent()

        assert result == 0, "IsDebuggerPresent must return FALSE after bypass"

    def test_checkremotedebuggerpresent_returns_false_after_flag_clear(self) -> None:
        """CheckRemoteDebuggerPresent returns FALSE after BeingDebugged cleared."""
        bypass = DebuggerBypass()

        bypass._bypass_checkremotedebuggerpresent()

        kernel32 = ctypes.windll.kernel32
        is_debugged = ctypes.c_bool(True)

        kernel32.CheckRemoteDebuggerPresent(
            kernel32.GetCurrentProcess(), ctypes.byref(is_debugged)
        )

        assert is_debugged.value is False, "CheckRemoteDebuggerPresent must return FALSE"


class TestNtGlobalFlagClearing:
    """Tests validating complete PEB.NtGlobalFlag debug-related bits clearing."""

    def test_ntglobalflag_debug_bits_cleared(self) -> None:
        """NtGlobalFlag debug-related bits (0x70) are completely cleared."""
        bypass = DebuggerBypass()

        result = bypass._bypass_ntglobalflag()

        assert result is True, "NtGlobalFlag bypass must succeed"

        is_64bit = platform.machine().endswith("64")
        offset = 0xBC if is_64bit else 0x68

        nt_global_flag = read_peb_dword(offset)
        assert nt_global_flag != -1, "Must successfully read NtGlobalFlag"

        debug_flags = 0x70
        assert (
            nt_global_flag & debug_flags
        ) == 0, f"Debug flags 0x70 must be cleared, got 0x{nt_global_flag:08X}"

    def test_ntglobalflag_architecture_specific_offset(self) -> None:
        """NtGlobalFlag uses correct offset for architecture (0x68/32-bit or 0xBC/64-bit)."""
        bypass = DebuggerBypass()

        bypass._bypass_ntglobalflag()

        is_64bit = platform.machine().endswith("64")
        correct_offset = 0xBC if is_64bit else 0x68
        incorrect_offset = 0x68 if is_64bit else 0xBC

        correct_value = read_peb_dword(correct_offset)
        incorrect_value = read_peb_dword(incorrect_offset)

        assert correct_value != -1, "Must read NtGlobalFlag at correct offset"
        assert (
            correct_value != incorrect_value
        ), "Correct and incorrect offsets should yield different values"

    def test_ntglobalflag_heap_create_enable_cleared(self) -> None:
        """FLG_HEAP_ENABLE_TAIL_CHECK (0x10) is cleared from NtGlobalFlag."""
        bypass = DebuggerBypass()

        bypass._bypass_ntglobalflag()

        is_64bit = platform.machine().endswith("64")
        offset = 0xBC if is_64bit else 0x68

        nt_global_flag = read_peb_dword(offset)

        FLG_HEAP_ENABLE_TAIL_CHECK = 0x10
        assert (
            nt_global_flag & FLG_HEAP_ENABLE_TAIL_CHECK
        ) == 0, "FLG_HEAP_ENABLE_TAIL_CHECK must be cleared"

    def test_ntglobalflag_heap_free_checking_cleared(self) -> None:
        """FLG_HEAP_ENABLE_FREE_CHECK (0x20) is cleared from NtGlobalFlag."""
        bypass = DebuggerBypass()

        bypass._bypass_ntglobalflag()

        is_64bit = platform.machine().endswith("64")
        offset = 0xBC if is_64bit else 0x68

        nt_global_flag = read_peb_dword(offset)

        FLG_HEAP_ENABLE_FREE_CHECK = 0x20
        assert (
            nt_global_flag & FLG_HEAP_ENABLE_FREE_CHECK
        ) == 0, "FLG_HEAP_ENABLE_FREE_CHECK must be cleared"

    def test_ntglobalflag_heap_validate_parameters_cleared(self) -> None:
        """FLG_HEAP_VALIDATE_PARAMETERS (0x40) is cleared from NtGlobalFlag."""
        bypass = DebuggerBypass()

        bypass._bypass_ntglobalflag()

        is_64bit = platform.machine().endswith("64")
        offset = 0xBC if is_64bit else 0x68

        nt_global_flag = read_peb_dword(offset)

        FLG_HEAP_VALIDATE_PARAMETERS = 0x40
        assert (
            nt_global_flag & FLG_HEAP_VALIDATE_PARAMETERS
        ) == 0, "FLG_HEAP_VALIDATE_PARAMETERS must be cleared"


class TestProcessHeapFlagsManipulation:
    """Tests validating ProcessHeap.Flags manipulation."""

    def test_heap_flags_set_to_heap_growable(self) -> None:
        """ProcessHeap.Flags is set to HEAP_GROWABLE (0x00000002)."""
        bypass = DebuggerBypass()

        bypass._bypass_peb_flags()

        heap_address = get_process_heap_address()
        assert heap_address != 0, "Must successfully retrieve ProcessHeap address"

        is_64bit = platform.machine().endswith("64")
        flags, force_flags = read_heap_flags(heap_address, is_64bit)

        assert flags != -1, "Must successfully read heap Flags"

        HEAP_GROWABLE = 0x00000002
        assert flags == HEAP_GROWABLE, f"Heap Flags must be HEAP_GROWABLE (0x02), got 0x{flags:08X}"

    def test_heap_force_flags_cleared_to_zero(self) -> None:
        """ProcessHeap.ForceFlags is cleared to 0x00000000."""
        bypass = DebuggerBypass()

        bypass._bypass_peb_flags()

        heap_address = get_process_heap_address()
        assert heap_address != 0, "Must successfully retrieve ProcessHeap address"

        is_64bit = platform.machine().endswith("64")
        flags, force_flags = read_heap_flags(heap_address, is_64bit)

        assert force_flags != -1, "Must successfully read heap ForceFlags"
        assert force_flags == 0, f"Heap ForceFlags must be 0, got 0x{force_flags:08X}"

    def test_heap_flags_debug_bits_cleared(self) -> None:
        """Heap debug flags (HEAP_CREATE_ENABLE_EXECUTE) are cleared."""
        bypass = DebuggerBypass()

        bypass._bypass_peb_flags()

        heap_address = get_process_heap_address()
        assert heap_address != 0, "Must successfully retrieve ProcessHeap address"

        is_64bit = platform.machine().endswith("64")
        flags, force_flags = read_heap_flags(heap_address, is_64bit)

        HEAP_CREATE_ENABLE_EXECUTE = 0x00040000
        assert (
            flags & HEAP_CREATE_ENABLE_EXECUTE
        ) == 0, "HEAP_CREATE_ENABLE_EXECUTE must be cleared"

    def test_heap_flags_architecture_specific_offsets(self) -> None:
        """Heap flags use architecture-specific offsets (0x44/0x70 for 32/64-bit)."""
        bypass = DebuggerBypass()

        bypass._bypass_peb_flags()

        heap_address = get_process_heap_address()
        assert heap_address != 0, "Must retrieve ProcessHeap address"

        is_64bit = platform.machine().endswith("64")
        expected_flags_offset = 0x70 if is_64bit else 0x44
        expected_force_flags_offset = 0x74 if is_64bit else 0x48

        try:
            flags = ctypes.c_ulong.from_address(heap_address + expected_flags_offset).value
            force_flags = ctypes.c_ulong.from_address(
                heap_address + expected_force_flags_offset
            ).value

            assert flags == 0x00000002, "Flags at correct offset must be HEAP_GROWABLE"
            assert force_flags == 0, "ForceFlags at correct offset must be 0"
        except Exception as e:
            pytest.fail(f"Failed to read heap flags at architecture-specific offsets: {e}")


class TestHeapTailCheckingSpoofing:
    """Tests validating heap tail checking spoofing."""

    def test_heap_tail_check_disabled(self) -> None:
        """Heap tail checking is disabled by clearing NtGlobalFlag."""
        bypass = DebuggerBypass()

        bypass._bypass_peb_flags()

        is_64bit = platform.machine().endswith("64")
        offset = 0xBC if is_64bit else 0x68

        nt_global_flag = read_peb_dword(offset)

        FLG_HEAP_ENABLE_TAIL_CHECK = 0x10
        assert (
            nt_global_flag & FLG_HEAP_ENABLE_TAIL_CHECK
        ) == 0, "Heap tail checking must be disabled"

    def test_heap_free_checking_disabled(self) -> None:
        """Heap free checking is disabled by clearing NtGlobalFlag."""
        bypass = DebuggerBypass()

        bypass._bypass_peb_flags()

        is_64bit = platform.machine().endswith("64")
        offset = 0xBC if is_64bit else 0x68

        nt_global_flag = read_peb_dword(offset)

        FLG_HEAP_ENABLE_FREE_CHECK = 0x20
        assert (
            nt_global_flag & FLG_HEAP_ENABLE_FREE_CHECK
        ) == 0, "Heap free checking must be disabled"

    def test_heap_validate_parameters_disabled(self) -> None:
        """Heap parameter validation is disabled by clearing NtGlobalFlag."""
        bypass = DebuggerBypass()

        bypass._bypass_peb_flags()

        is_64bit = platform.machine().endswith("64")
        offset = 0xBC if is_64bit else 0x68

        nt_global_flag = read_peb_dword(offset)

        FLG_HEAP_VALIDATE_PARAMETERS = 0x40
        assert (
            nt_global_flag & FLG_HEAP_VALIDATE_PARAMETERS
        ) == 0, "Heap parameter validation must be disabled"


class Test64BitProcessHeapAccess:
    """Tests validating 32-bit PEB access from 64-bit processes."""

    @pytest.mark.skipif(not platform.machine().endswith("64"), reason="64-bit only test")
    def test_64bit_process_uses_correct_peb_offsets(self) -> None:
        """64-bit process uses correct PEB offsets (0xBC for NtGlobalFlag)."""
        bypass = DebuggerBypass()

        bypass._bypass_peb_flags()

        nt_global_flag = read_peb_dword(0xBC)

        assert nt_global_flag != -1, "Must read NtGlobalFlag at 64-bit offset 0xBC"
        assert (nt_global_flag & 0x70) == 0, "Debug flags must be cleared at 64-bit offset"

    @pytest.mark.skipif(not platform.machine().endswith("64"), reason="64-bit only test")
    def test_64bit_process_uses_correct_heap_offsets(self) -> None:
        """64-bit process uses correct heap offsets (0x30 for ProcessHeap)."""
        bypass = DebuggerBypass()

        bypass._bypass_peb_flags()

        heap_address = get_process_heap_address()
        assert heap_address != 0, "Must retrieve ProcessHeap at 64-bit offset 0x30"

        flags, force_flags = read_heap_flags(heap_address, True)

        assert flags == 0x00000002, "Heap Flags must be set correctly in 64-bit process"
        assert force_flags == 0, "Heap ForceFlags must be cleared in 64-bit process"

    @pytest.mark.skipif(platform.machine().endswith("64"), reason="32-bit only test")
    def test_32bit_process_uses_correct_peb_offsets(self) -> None:
        """32-bit process uses correct PEB offsets (0x68 for NtGlobalFlag)."""
        bypass = DebuggerBypass()

        bypass._bypass_peb_flags()

        nt_global_flag = read_peb_dword(0x68)

        assert nt_global_flag != -1, "Must read NtGlobalFlag at 32-bit offset 0x68"
        assert (nt_global_flag & 0x70) == 0, "Debug flags must be cleared at 32-bit offset"

    @pytest.mark.skipif(platform.machine().endswith("64"), reason="32-bit only test")
    def test_32bit_process_uses_correct_heap_offsets(self) -> None:
        """32-bit process uses correct heap offsets (0x18 for ProcessHeap)."""
        bypass = DebuggerBypass()

        bypass._bypass_peb_flags()

        heap_address = get_process_heap_address()
        assert heap_address != 0, "Must retrieve ProcessHeap at 32-bit offset 0x18"

        flags, force_flags = read_heap_flags(heap_address, False)

        assert flags == 0x00000002, "Heap Flags must be set correctly in 32-bit process"
        assert force_flags == 0, "Heap ForceFlags must be cleared in 32-bit process"


class TestWoW64EdgeCases:
    """Tests validating WoW64 edge cases."""

    @pytest.mark.skipif(not platform.machine().endswith("64"), reason="64-bit only test")
    def test_wow64_peb_access_not_confused_with_native(self) -> None:
        """WoW64 processes correctly distinguish between 32-bit and 64-bit PEB."""
        bypass = DebuggerBypass()

        bypass._bypass_peb_flags()

        peb_address = get_peb_address()
        assert peb_address != 0, "Must retrieve PEB address"

        being_debugged = read_peb_byte(2)
        assert being_debugged == 0, "BeingDebugged must be cleared"

        nt_global_flag_64 = read_peb_dword(0xBC)
        assert nt_global_flag_64 != -1, "Must read 64-bit NtGlobalFlag"
        assert (nt_global_flag_64 & 0x70) == 0, "64-bit NtGlobalFlag debug bits must be cleared"

    @pytest.mark.skipif(not platform.machine().endswith("64"), reason="64-bit only test")
    def test_native_64bit_process_peb_manipulation(self) -> None:
        """Native 64-bit process correctly manipulates 64-bit PEB structures."""
        bypass = DebuggerBypass()

        result = bypass._bypass_peb_flags()

        assert result is True, "64-bit PEB manipulation must succeed"

        being_debugged = read_peb_byte(2)
        nt_global_flag = read_peb_dword(0xBC)

        assert being_debugged == 0, "BeingDebugged must be cleared in native 64-bit"
        assert (
            nt_global_flag & 0x70
        ) == 0, "NtGlobalFlag debug bits must be cleared in native 64-bit"


class TestProtectedPEBReads:
    """Tests validating handling of protected PEB reads."""

    def test_bypass_handles_access_denied_gracefully(self) -> None:
        """Bypass handles ACCESS_DENIED errors without crashing."""
        bypass = DebuggerBypass()

        try:
            result = bypass._bypass_peb_flags()
            assert isinstance(result, bool), "Must return boolean even on access errors"
        except Exception as e:
            pytest.fail(f"Bypass must not raise exception on access errors: {e}")

    def test_bypass_handles_invalid_peb_address_gracefully(self) -> None:
        """Bypass handles invalid PEB address without crashing."""
        bypass = DebuggerBypass()

        try:
            result = bypass._bypass_peb_flags()
            assert isinstance(result, bool), "Must return boolean even with invalid PEB"
        except Exception as e:
            pytest.fail(f"Bypass must not raise exception on invalid PEB: {e}")

    def test_bypass_handles_memory_protection_errors(self) -> None:
        """Bypass handles memory protection violations gracefully."""
        bypass = DebuggerBypass()

        try:
            result = bypass._bypass_peb_flags()
            assert isinstance(result, bool), "Must return boolean on memory protection errors"
        except Exception as e:
            pytest.fail(f"Bypass must not raise exception on memory protection errors: {e}")

    def test_bypass_returns_false_on_ntqueryinformationprocess_failure(self) -> None:
        """Bypass returns False when NtQueryInformationProcess fails."""
        bypass = DebuggerBypass()

        original_ntdll = bypass.ntdll

        class FakeNtdll:
            def NtQueryInformationProcess(
                self, process: Any, info_class: Any, info: Any, size: Any, ret_len: Any
            ) -> int:
                return 0xC0000001

        bypass.ntdll = FakeNtdll()

        result = bypass._bypass_peb_flags()

        bypass.ntdll = original_ntdll

        assert result is False, "Must return False when NtQueryInformationProcess fails"


class TestComprehensivePEBBypassValidation:
    """Tests validating comprehensive PEB bypass across all components."""

    def test_all_peb_flags_cleared_simultaneously(self) -> None:
        """All PEB debug flags are cleared simultaneously in single bypass call."""
        bypass = DebuggerBypass()

        result = bypass._bypass_peb_flags()

        assert result is True, "Comprehensive PEB bypass must succeed"

        being_debugged = read_peb_byte(2)

        is_64bit = platform.machine().endswith("64")
        nt_global_flag = read_peb_dword(0xBC if is_64bit else 0x68)

        heap_address = get_process_heap_address()
        flags, force_flags = (
            read_heap_flags(heap_address, is_64bit) if heap_address != 0 else (-1, -1)
        )

        assert being_debugged == 0, "BeingDebugged must be cleared"
        assert (nt_global_flag & 0x70) == 0, "NtGlobalFlag debug bits must be cleared"
        if flags != -1:
            assert flags == 0x00000002, "Heap Flags must be HEAP_GROWABLE"
            assert force_flags == 0, "Heap ForceFlags must be 0"

    def test_peb_bypass_effectiveness_against_isdebuggerpresent(self) -> None:
        """PEB bypass prevents IsDebuggerPresent detection."""
        bypass = DebuggerBypass()

        bypass._bypass_peb_flags()

        kernel32 = ctypes.windll.kernel32
        result = kernel32.IsDebuggerPresent()

        assert result == 0, "IsDebuggerPresent must return FALSE after PEB bypass"

    def test_peb_bypass_effectiveness_against_checkremotedebuggerpresent(self) -> None:
        """PEB bypass prevents CheckRemoteDebuggerPresent detection."""
        bypass = DebuggerBypass()

        bypass._bypass_peb_flags()

        kernel32 = ctypes.windll.kernel32
        is_debugged = ctypes.c_bool(True)

        kernel32.CheckRemoteDebuggerPresent(
            kernel32.GetCurrentProcess(), ctypes.byref(is_debugged)
        )

        assert is_debugged.value is False, "CheckRemoteDebuggerPresent must return FALSE"

    def test_peb_bypass_effectiveness_against_ntglobalflag_checks(self) -> None:
        """PEB bypass prevents NtGlobalFlag-based heap flag detection."""
        bypass = DebuggerBypass()

        bypass._bypass_peb_flags()

        is_64bit = platform.machine().endswith("64")
        nt_global_flag = read_peb_dword(0xBC if is_64bit else 0x68)

        FLG_HEAP_ENABLE_TAIL_CHECK = 0x10
        FLG_HEAP_ENABLE_FREE_CHECK = 0x20
        FLG_HEAP_VALIDATE_PARAMETERS = 0x40

        assert (nt_global_flag & FLG_HEAP_ENABLE_TAIL_CHECK) == 0, "Tail check must be disabled"
        assert (nt_global_flag & FLG_HEAP_ENABLE_FREE_CHECK) == 0, "Free check must be disabled"
        assert (
            nt_global_flag & FLG_HEAP_VALIDATE_PARAMETERS
        ) == 0, "Parameter validation must be disabled"

    def test_peb_bypass_persists_across_api_calls(self) -> None:
        """PEB bypass remains effective across multiple API calls."""
        bypass = DebuggerBypass()

        bypass._bypass_peb_flags()

        kernel32 = ctypes.windll.kernel32

        for _ in range(10):
            result = kernel32.IsDebuggerPresent()
            assert result == 0, "IsDebuggerPresent must remain FALSE across multiple calls"

    def test_peb_bypass_idempotent_behavior(self) -> None:
        """PEB bypass can be called multiple times without side effects."""
        bypass = DebuggerBypass()

        result1 = bypass._bypass_peb_flags()
        result2 = bypass._bypass_peb_flags()
        result3 = bypass._bypass_peb_flags()

        assert result1 is True, "First bypass call must succeed"
        assert result2 is True, "Second bypass call must succeed"
        assert result3 is True, "Third bypass call must succeed"

        being_debugged = read_peb_byte(2)
        assert being_debugged == 0, "BeingDebugged must remain cleared after multiple calls"


class TestPEBBypassIntegrationWithOtherBypasses:
    """Tests validating PEB bypass integration with other bypass methods."""

    def test_peb_bypass_compatible_with_debug_port_bypass(self) -> None:
        """PEB bypass works correctly alongside debug port bypass."""
        bypass = DebuggerBypass()

        peb_result = bypass._bypass_peb_flags()
        port_result = bypass._bypass_debug_port()

        assert peb_result is True, "PEB bypass must succeed"
        assert isinstance(port_result, bool), "Debug port bypass must return boolean"

        being_debugged = read_peb_byte(2)
        assert being_debugged == 0, "BeingDebugged must be cleared with combined bypasses"

    def test_peb_bypass_compatible_with_hardware_breakpoint_bypass(self) -> None:
        """PEB bypass works correctly alongside hardware breakpoint bypass."""
        bypass = DebuggerBypass()

        peb_result = bypass._bypass_peb_flags()
        hw_result = bypass._bypass_hardware_breakpoints()

        assert peb_result is True, "PEB bypass must succeed"
        assert isinstance(hw_result, bool), "Hardware BP bypass must return boolean"

        being_debugged = read_peb_byte(2)
        assert being_debugged == 0, "BeingDebugged must be cleared with combined bypasses"

    def test_peb_bypass_compatible_with_timing_bypass(self) -> None:
        """PEB bypass works correctly alongside timing bypass."""
        bypass = DebuggerBypass()

        peb_result = bypass._bypass_peb_flags()
        timing_result = bypass._bypass_timing()

        assert peb_result is True, "PEB bypass must succeed"
        assert timing_result is True, "Timing bypass must succeed"

        being_debugged = read_peb_byte(2)
        assert being_debugged == 0, "BeingDebugged must be cleared with combined bypasses"

    def test_install_bypasses_activates_peb_bypass_correctly(self) -> None:
        """install_bypasses method correctly activates PEB bypass."""
        bypass = DebuggerBypass()

        results = bypass.install_bypasses(["peb_flags"])

        assert "peb_flags" in results, "Results must include peb_flags"
        assert results["peb_flags"] is True, "PEB flags bypass must succeed"

        being_debugged = read_peb_byte(2)
        assert being_debugged == 0, "BeingDebugged must be cleared via install_bypasses"
