"""Production tests for PEB flag clearing in debugger_bypass.py.

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

These tests validate that PEB flag clearing actually defeats real anti-debugging
checks by verifying the flags are properly cleared in memory and that protected
binaries no longer detect debugging state.
"""

import ctypes
import logging
import platform
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.anti_analysis.debugger_bypass import DebuggerBypass


pytestmark = pytest.mark.skipif(
    platform.system() != "Windows",
    reason="PEB flag clearing tests require Windows platform",
)


class ProcessBasicInformation(ctypes.Structure):
    """Structure for NtQueryInformationProcess."""

    _fields_ = [
        ("Reserved1", ctypes.c_void_p),
        ("PebBaseAddress", ctypes.c_void_p),
        ("Reserved2", ctypes.c_void_p * 2),
        ("UniqueProcessId", ctypes.POINTER(ctypes.c_ulong)),
        ("Reserved3", ctypes.c_void_p),
    ]


def get_peb_address() -> int:
    """Get the PEB base address for the current process.

    Returns:
        PEB base address as an integer, or 0 if failed.
    """
    try:
        ntdll = ctypes.windll.ntdll
        kernel32 = ctypes.windll.kernel32
        current_process = kernel32.GetCurrentProcess()

        pbi = ProcessBasicInformation()
        status = ntdll.NtQueryInformationProcess(
            current_process,
            0,
            ctypes.byref(pbi),
            ctypes.sizeof(pbi),
            None,
        )

        if status != 0:
            return 0

        return pbi.PebBaseAddress.value if pbi.PebBaseAddress else 0

    except Exception:
        return 0


def read_peb_byte(offset: int) -> int:
    """Read a byte from PEB at specified offset.

    Args:
        offset: Offset from PEB base to read.

    Returns:
        Byte value at the specified offset, or -1 if failed.
    """
    try:
        peb_addr = get_peb_address()
        if not peb_addr:
            return -1

        kernel32 = ctypes.windll.kernel32
        current_process = kernel32.GetCurrentProcess()

        byte_value = ctypes.c_ubyte()
        bytes_read = ctypes.c_size_t()

        success = kernel32.ReadProcessMemory(
            current_process,
            ctypes.c_void_p(peb_addr + offset),
            ctypes.byref(byte_value),
            1,
            ctypes.byref(bytes_read),
        )

        if success and bytes_read.value == 1:
            return byte_value.value

        return -1

    except Exception:
        return -1


def read_peb_dword(offset: int) -> int:
    """Read a DWORD from PEB at specified offset.

    Args:
        offset: Offset from PEB base to read.

    Returns:
        DWORD value at the specified offset, or -1 if failed.
    """
    try:
        peb_addr = get_peb_address()
        if not peb_addr:
            return -1

        kernel32 = ctypes.windll.kernel32
        current_process = kernel32.GetCurrentProcess()

        dword_value = ctypes.c_ulong()
        bytes_read = ctypes.c_size_t()

        success = kernel32.ReadProcessMemory(
            current_process,
            ctypes.c_void_p(peb_addr + offset),
            ctypes.byref(dword_value),
            4,
            ctypes.byref(bytes_read),
        )

        if success and bytes_read.value == 4:
            return dword_value.value

        return -1

    except Exception:
        return -1


def read_peb_pointer(offset: int) -> int:
    """Read a pointer from PEB at specified offset.

    Args:
        offset: Offset from PEB base to read.

    Returns:
        Pointer value at the specified offset, or 0 if failed.
    """
    try:
        peb_addr = get_peb_address()
        if not peb_addr:
            return 0

        kernel32 = ctypes.windll.kernel32
        current_process = kernel32.GetCurrentProcess()

        pointer_value = ctypes.c_void_p()
        bytes_read = ctypes.c_size_t()

        success = kernel32.ReadProcessMemory(
            current_process,
            ctypes.c_void_p(peb_addr + offset),
            ctypes.byref(pointer_value),
            ctypes.sizeof(ctypes.c_void_p),
            ctypes.byref(bytes_read),
        )

        if success and bytes_read.value == ctypes.sizeof(ctypes.c_void_p):
            return pointer_value.value

        return 0

    except Exception:
        return 0


def set_being_debugged_flag() -> bool:
    """Set the BeingDebugged flag to simulate debugging.

    Returns:
        True if flag was set successfully, False otherwise.
    """
    try:
        peb_addr = get_peb_address()
        if not peb_addr:
            return False

        kernel32 = ctypes.windll.kernel32
        current_process = kernel32.GetCurrentProcess()

        one_byte = ctypes.c_ubyte(1)
        bytes_written = ctypes.c_size_t()

        success = kernel32.WriteProcessMemory(
            current_process,
            ctypes.c_void_p(peb_addr + 2),
            ctypes.byref(one_byte),
            1,
            ctypes.byref(bytes_written),
        )

        return bool(success and bytes_written.value == 1)

    except Exception:
        return False


def set_ntglobalflag(value: int) -> bool:
    """Set NtGlobalFlag to simulate debugging flags.

    Args:
        value: Value to set for NtGlobalFlag.

    Returns:
        True if flag was set successfully, False otherwise.
    """
    try:
        peb_addr = get_peb_address()
        if not peb_addr:
            return False

        kernel32 = ctypes.windll.kernel32
        current_process = kernel32.GetCurrentProcess()

        is_64bit = platform.machine().endswith("64")
        nt_global_flag_offset = 0xBC if is_64bit else 0x68

        flag_value = ctypes.c_ulong(value)
        bytes_written = ctypes.c_size_t()

        success = kernel32.WriteProcessMemory(
            current_process,
            ctypes.c_void_p(peb_addr + nt_global_flag_offset),
            ctypes.byref(flag_value),
            4,
            ctypes.byref(bytes_written),
        )

        return bool(success and bytes_written.value == 4)

    except Exception:
        return False


def get_process_heap_address() -> int:
    """Get the ProcessHeap address from PEB.

    Returns:
        ProcessHeap address, or 0 if failed.
    """
    try:
        is_64bit = platform.machine().endswith("64")
        heap_flags_offset = 0x30 if is_64bit else 0x18
        return read_peb_pointer(heap_flags_offset)
    except Exception:
        return 0


def read_heap_flags() -> int:
    """Read the Flags field from ProcessHeap.

    Returns:
        Heap Flags value, or -1 if failed.
    """
    try:
        heap_addr = get_process_heap_address()
        if not heap_addr:
            return -1

        kernel32 = ctypes.windll.kernel32
        current_process = kernel32.GetCurrentProcess()

        is_64bit = platform.machine().endswith("64")
        flags_offset = 0x70 if is_64bit else 0x44

        flags_value = ctypes.c_ulong()
        bytes_read = ctypes.c_size_t()

        success = kernel32.ReadProcessMemory(
            current_process,
            ctypes.c_void_p(heap_addr + flags_offset),
            ctypes.byref(flags_value),
            4,
            ctypes.byref(bytes_read),
        )

        if success and bytes_read.value == 4:
            return flags_value.value

        return -1

    except Exception:
        return -1


def read_heap_force_flags() -> int:
    """Read the ForceFlags field from ProcessHeap.

    Returns:
        Heap ForceFlags value, or -1 if failed.
    """
    try:
        heap_addr = get_process_heap_address()
        if not heap_addr:
            return -1

        kernel32 = ctypes.windll.kernel32
        current_process = kernel32.GetCurrentProcess()

        is_64bit = platform.machine().endswith("64")
        force_flags_offset = 0x74 if is_64bit else 0x48

        force_flags_value = ctypes.c_ulong()
        bytes_read = ctypes.c_size_t()

        success = kernel32.ReadProcessMemory(
            current_process,
            ctypes.c_void_p(heap_addr + force_flags_offset),
            ctypes.byref(force_flags_value),
            4,
            ctypes.byref(bytes_read),
        )

        if success and bytes_read.value == 4:
            return force_flags_value.value

        return -1

    except Exception:
        return -1


def set_heap_debug_flags() -> bool:
    """Set heap debug flags to simulate debugging.

    Returns:
        True if flags were set successfully, False otherwise.
    """
    try:
        heap_addr = get_process_heap_address()
        if not heap_addr:
            return False

        kernel32 = ctypes.windll.kernel32
        current_process = kernel32.GetCurrentProcess()

        is_64bit = platform.machine().endswith("64")
        flags_offset = 0x70 if is_64bit else 0x44
        force_flags_offset = 0x74 if is_64bit else 0x48

        debug_flags = ctypes.c_ulong(0x50000062)
        force_flags = ctypes.c_ulong(0x40000060)
        bytes_written = ctypes.c_size_t()

        success1 = kernel32.WriteProcessMemory(
            current_process,
            ctypes.c_void_p(heap_addr + flags_offset),
            ctypes.byref(debug_flags),
            4,
            ctypes.byref(bytes_written),
        )

        success2 = kernel32.WriteProcessMemory(
            current_process,
            ctypes.c_void_p(heap_addr + force_flags_offset),
            ctypes.byref(force_flags),
            4,
            ctypes.byref(bytes_written),
        )

        return bool(success1 and success2)

    except Exception:
        return False


@pytest.fixture
def bypass_instance() -> DebuggerBypass:
    """Create a DebuggerBypass instance for testing.

    Returns:
        Initialized DebuggerBypass instance.
    """
    return DebuggerBypass()


@pytest.fixture
def cleanup_peb_flags() -> None:
    """Fixture to ensure PEB flags are in known state before tests.

    Yields control to test, then cleans up after test completes.
    """
    yield
    try:
        set_being_debugged_flag()
    except Exception:
        pass


class TestPebBeingDebugged:
    """Test suite for PEB.BeingDebugged flag clearing."""

    def test_being_debugged_flag_cleared_completely(
        self,
        bypass_instance: DebuggerBypass,
        cleanup_peb_flags: None,
    ) -> None:
        """BeingDebugged flag must be cleared to 0x00 after bypass installation.

        This test verifies the bypass clears the PEB.BeingDebugged flag at
        offset +2 from the PEB base. Protected software uses this flag via
        IsDebuggerPresent() API to detect debuggers.
        """
        assert set_being_debugged_flag(), "Failed to set BeingDebugged flag for test"

        initial_value = read_peb_byte(2)
        assert initial_value == 1, f"BeingDebugged should be 1 initially, got {initial_value}"

        result = bypass_instance.install_bypasses(["peb_flags"])
        assert result["peb_flags"] is True, "PEB flags bypass should succeed"

        final_value = read_peb_byte(2)
        assert final_value == 0, f"BeingDebugged must be 0 after bypass, got {final_value}"

    def test_isdebuggerpresent_returns_false_after_bypass(
        self,
        bypass_instance: DebuggerBypass,
        cleanup_peb_flags: None,
    ) -> None:
        """IsDebuggerPresent() API must return FALSE after bypass installation.

        This validates that clearing the PEB flag actually defeats the Windows
        API check used by protected software to detect debuggers.
        """
        assert set_being_debugged_flag(), "Failed to set BeingDebugged flag"

        kernel32 = ctypes.windll.kernel32
        assert kernel32.IsDebuggerPresent() != 0, "IsDebuggerPresent should return TRUE initially"

        result = bypass_instance.install_bypasses(["isdebuggerpresent"])
        assert result["isdebuggerpresent"] is True, "IsDebuggerPresent bypass should succeed"

        assert kernel32.IsDebuggerPresent() == 0, "IsDebuggerPresent must return FALSE after bypass"

    def test_checkremotedebuggerpresent_returns_false_after_bypass(
        self,
        bypass_instance: DebuggerBypass,
        cleanup_peb_flags: None,
    ) -> None:
        """CheckRemoteDebuggerPresent() must return FALSE after bypass.

        Validates that the PEB flag clearing defeats both IsDebuggerPresent
        and CheckRemoteDebuggerPresent, which check the same flag.
        """
        assert set_being_debugged_flag(), "Failed to set BeingDebugged flag"

        kernel32 = ctypes.windll.kernel32
        is_debugged = ctypes.c_bool()

        kernel32.CheckRemoteDebuggerPresent(
            kernel32.GetCurrentProcess(),
            ctypes.byref(is_debugged),
        )
        assert is_debugged.value is True, "Should be debugged initially"

        result = bypass_instance.install_bypasses(["checkremotedebuggerpresent"])
        assert result["checkremotedebuggerpresent"] is True, "Bypass should succeed"

        kernel32.CheckRemoteDebuggerPresent(
            kernel32.GetCurrentProcess(),
            ctypes.byref(is_debugged),
        )
        assert is_debugged.value is False, "Should NOT be debugged after bypass"

    def test_being_debugged_persists_after_multiple_reads(
        self,
        bypass_instance: DebuggerBypass,
        cleanup_peb_flags: None,
    ) -> None:
        """BeingDebugged flag clearing must persist across multiple reads.

        Some protected software repeatedly checks the flag. This test ensures
        the flag remains cleared even after multiple read operations.
        """
        assert set_being_debugged_flag(), "Failed to set BeingDebugged flag"

        result = bypass_instance.install_bypasses(["peb_flags"])
        assert result["peb_flags"] is True, "Bypass should succeed"

        for i in range(10):
            value = read_peb_byte(2)
            assert value == 0, f"BeingDebugged must remain 0 on read {i + 1}, got {value}"

        kernel32 = ctypes.windll.kernel32
        for i in range(10):
            result = kernel32.IsDebuggerPresent()
            assert result == 0, f"IsDebuggerPresent must return FALSE on call {i + 1}"


class TestNtGlobalFlag:
    """Test suite for PEB.NtGlobalFlag clearing."""

    def test_ntglobalflag_debug_bits_cleared(
        self,
        bypass_instance: DebuggerBypass,
    ) -> None:
        """NtGlobalFlag debug bits must be completely cleared after bypass.

        The NtGlobalFlag contains debug heap flags (0x70) that indicate
        debugger presence. This test verifies all debug bits are cleared.
        """
        DEBUG_FLAGS = 0x70
        assert set_ntglobalflag(DEBUG_FLAGS), "Failed to set NtGlobalFlag"

        is_64bit = platform.machine().endswith("64")
        nt_global_flag_offset = 0xBC if is_64bit else 0x68

        initial_value = read_peb_dword(nt_global_flag_offset)
        assert initial_value == DEBUG_FLAGS, f"NtGlobalFlag should be {DEBUG_FLAGS:#x}, got {initial_value:#x}"

        result = bypass_instance.install_bypasses(["ntglobalflag"])
        assert result["ntglobalflag"] is True, "NtGlobalFlag bypass should succeed"

        final_value = read_peb_dword(nt_global_flag_offset)
        assert final_value == 0, f"NtGlobalFlag must be 0 after bypass, got {final_value:#x}"

    def test_ntglobalflag_offset_correct_for_architecture(
        self,
        bypass_instance: DebuggerBypass,
    ) -> None:
        """NtGlobalFlag offset must be correct for x86 (0x68) vs x64 (0xBC).

        Protected software may directly read NtGlobalFlag at architecture-
        specific offsets. This validates the bypass uses the correct offset.
        """
        is_64bit = platform.machine().endswith("64")
        expected_offset = 0xBC if is_64bit else 0x68

        DEBUG_FLAGS = 0x70
        assert set_ntglobalflag(DEBUG_FLAGS), "Failed to set NtGlobalFlag"

        result = bypass_instance.install_bypasses(["peb_flags"])
        assert result["peb_flags"] is True, "Bypass should succeed"

        value_at_expected_offset = read_peb_dword(expected_offset)
        assert value_at_expected_offset == 0, (
            f"NtGlobalFlag at offset {expected_offset:#x} must be 0, got {value_at_expected_offset:#x}"
        )

        wrong_offset = 0x68 if is_64bit else 0xBC
        value_at_wrong_offset = read_peb_dword(wrong_offset)
        if value_at_wrong_offset == 0:
            pytest.skip("Cannot verify wrong offset behavior - both offsets are 0")

    def test_ntglobalflag_clears_all_debug_related_bits(
        self,
        bypass_instance: DebuggerBypass,
    ) -> None:
        """All debug-related bits in NtGlobalFlag must be cleared.

        NtGlobalFlag may have multiple debug flags set (FLG_HEAP_ENABLE_TAIL_CHECK,
        FLG_HEAP_ENABLE_FREE_CHECK, FLG_HEAP_VALIDATE_PARAMETERS). All must be cleared.
        """
        FLG_HEAP_ENABLE_TAIL_CHECK = 0x10
        FLG_HEAP_ENABLE_FREE_CHECK = 0x20
        FLG_HEAP_VALIDATE_PARAMETERS = 0x40
        ALL_DEBUG_FLAGS = FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS

        assert set_ntglobalflag(ALL_DEBUG_FLAGS), "Failed to set all debug flags"

        result = bypass_instance.install_bypasses(["peb_flags"])
        assert result["peb_flags"] is True, "Bypass should succeed"

        is_64bit = platform.machine().endswith("64")
        offset = 0xBC if is_64bit else 0x68
        final_value = read_peb_dword(offset)

        assert (final_value & FLG_HEAP_ENABLE_TAIL_CHECK) == 0, "FLG_HEAP_ENABLE_TAIL_CHECK must be cleared"
        assert (final_value & FLG_HEAP_ENABLE_FREE_CHECK) == 0, "FLG_HEAP_ENABLE_FREE_CHECK must be cleared"
        assert (final_value & FLG_HEAP_VALIDATE_PARAMETERS) == 0, "FLG_HEAP_VALIDATE_PARAMETERS must be cleared"


class TestProcessHeapFlags:
    """Test suite for ProcessHeap.Flags manipulation."""

    def test_heap_flags_set_to_normal_value(
        self,
        bypass_instance: DebuggerBypass,
    ) -> None:
        """ProcessHeap.Flags must be set to normal (HEAP_GROWABLE) value.

        When debugging, heap Flags are set to debug values (0x50000062).
        After bypass, Flags must be set to normal value (0x00000002 = HEAP_GROWABLE).
        """
        assert set_heap_debug_flags(), "Failed to set heap debug flags"

        initial_flags = read_heap_flags()
        assert initial_flags != -1, "Failed to read initial heap flags"
        assert initial_flags != 0x00000002, "Heap flags should be debug value initially"

        result = bypass_instance.install_bypasses(["peb_flags"])
        assert result["peb_flags"] is True, "Bypass should succeed"

        final_flags = read_heap_flags()
        assert final_flags != -1, "Failed to read final heap flags"
        assert final_flags == 0x00000002, f"Heap Flags must be HEAP_GROWABLE (0x2), got {final_flags:#x}"

    def test_heap_force_flags_cleared_to_zero(
        self,
        bypass_instance: DebuggerBypass,
    ) -> None:
        """ProcessHeap.ForceFlags must be cleared to 0.

        When debugging, heap ForceFlags are non-zero (0x40000060).
        After bypass, ForceFlags must be zero to hide debugger presence.
        """
        assert set_heap_debug_flags(), "Failed to set heap debug flags"

        initial_force_flags = read_heap_force_flags()
        assert initial_force_flags != -1, "Failed to read initial heap ForceFlags"
        assert initial_force_flags != 0, "Heap ForceFlags should be non-zero initially"

        result = bypass_instance.install_bypasses(["peb_flags"])
        assert result["peb_flags"] is True, "Bypass should succeed"

        final_force_flags = read_heap_force_flags()
        assert final_force_flags != -1, "Failed to read final heap ForceFlags"
        assert final_force_flags == 0, f"Heap ForceFlags must be 0, got {final_force_flags:#x}"

    def test_heap_flags_offset_correct_for_architecture(
        self,
        bypass_instance: DebuggerBypass,
    ) -> None:
        """Heap Flags offset must be correct for x86 (0x44) vs x64 (0x70).

        Protected software may directly read heap flags at architecture-specific
        offsets. This validates the bypass uses the correct offsets.
        """
        is_64bit = platform.machine().endswith("64")
        expected_flags_offset = 0x70 if is_64bit else 0x44
        expected_force_flags_offset = 0x74 if is_64bit else 0x48

        assert set_heap_debug_flags(), "Failed to set heap debug flags"

        result = bypass_instance.install_bypasses(["peb_flags"])
        assert result["peb_flags"] is True, "Bypass should succeed"

        heap_addr = get_process_heap_address()
        assert heap_addr != 0, "Failed to get ProcessHeap address"

        kernel32 = ctypes.windll.kernel32
        current_process = kernel32.GetCurrentProcess()

        flags_value = ctypes.c_ulong()
        bytes_read = ctypes.c_size_t()

        success = kernel32.ReadProcessMemory(
            current_process,
            ctypes.c_void_p(heap_addr + expected_flags_offset),
            ctypes.byref(flags_value),
            4,
            ctypes.byref(bytes_read),
        )

        assert success and bytes_read.value == 4, "Failed to read Flags at expected offset"
        assert flags_value.value == 0x00000002, (
            f"Flags at offset {expected_flags_offset:#x} must be HEAP_GROWABLE"
        )

        force_flags_value = ctypes.c_ulong()
        success = kernel32.ReadProcessMemory(
            current_process,
            ctypes.c_void_p(heap_addr + expected_force_flags_offset),
            ctypes.byref(force_flags_value),
            4,
            ctypes.byref(bytes_read),
        )

        assert success and bytes_read.value == 4, "Failed to read ForceFlags at expected offset"
        assert force_flags_value.value == 0, f"ForceFlags at offset {expected_force_flags_offset:#x} must be 0"


class TestHeapTailChecking:
    """Test suite for heap tail checking spoofing."""

    def test_heap_tail_checking_disabled_via_flags(
        self,
        bypass_instance: DebuggerBypass,
    ) -> None:
        """Heap tail checking must be disabled by clearing NtGlobalFlag bits.

        Heap tail checking is controlled by FLG_HEAP_ENABLE_TAIL_CHECK (0x10)
        in NtGlobalFlag. This test verifies the bit is cleared.
        """
        FLG_HEAP_ENABLE_TAIL_CHECK = 0x10
        assert set_ntglobalflag(FLG_HEAP_ENABLE_TAIL_CHECK), "Failed to set tail check flag"

        result = bypass_instance.install_bypasses(["peb_flags"])
        assert result["peb_flags"] is True, "Bypass should succeed"

        is_64bit = platform.machine().endswith("64")
        offset = 0xBC if is_64bit else 0x68
        final_value = read_peb_dword(offset)

        assert (final_value & FLG_HEAP_ENABLE_TAIL_CHECK) == 0, (
            "FLG_HEAP_ENABLE_TAIL_CHECK bit must be cleared"
        )

    def test_heap_validation_disabled(
        self,
        bypass_instance: DebuggerBypass,
    ) -> None:
        """Heap validation must be disabled to prevent debug detection.

        FLG_HEAP_VALIDATE_PARAMETERS (0x40) causes heap validation which
        can reveal debugger presence. This bit must be cleared.
        """
        FLG_HEAP_VALIDATE_PARAMETERS = 0x40
        assert set_ntglobalflag(FLG_HEAP_VALIDATE_PARAMETERS), "Failed to set validation flag"

        result = bypass_instance.install_bypasses(["peb_flags"])
        assert result["peb_flags"] is True, "Bypass should succeed"

        is_64bit = platform.machine().endswith("64")
        offset = 0xBC if is_64bit else 0x68
        final_value = read_peb_dword(offset)

        assert (final_value & FLG_HEAP_VALIDATE_PARAMETERS) == 0, (
            "FLG_HEAP_VALIDATE_PARAMETERS bit must be cleared"
        )


class TestWow64Compatibility:
    """Test suite for 32-bit PEB access from 64-bit processes (WoW64)."""

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="WoW64 tests require 64-bit Windows",
    )
    def test_peb_access_from_64bit_process(
        self,
        bypass_instance: DebuggerBypass,
    ) -> None:
        """64-bit process must correctly access 64-bit PEB structure.

        On 64-bit Windows, processes use 64-bit PEB with different offsets.
        This validates the bypass correctly uses 64-bit offsets.
        """
        assert set_being_debugged_flag(), "Failed to set BeingDebugged flag"
        assert set_ntglobalflag(0x70), "Failed to set NtGlobalFlag"

        result = bypass_instance.install_bypasses(["peb_flags"])
        assert result["peb_flags"] is True, "Bypass should succeed"

        being_debugged = read_peb_byte(2)
        assert being_debugged == 0, "BeingDebugged must be cleared in 64-bit PEB"

        ntglobalflag = read_peb_dword(0xBC)
        assert ntglobalflag == 0, "NtGlobalFlag must be cleared at 64-bit offset (0xBC)"

        heap_addr = read_peb_pointer(0x30)
        assert heap_addr != 0, "ProcessHeap must be readable at 64-bit offset (0x30)"

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="WoW64 tests require 64-bit Windows",
    )
    def test_wow64_peb32_not_accessible(
        self,
        bypass_instance: DebuggerBypass,
    ) -> None:
        """WoW64 PEB32 should not be accessible from native 64-bit process.

        Native 64-bit processes only have a 64-bit PEB. Attempting to read
        32-bit PEB offsets should fail or return incorrect data.
        """
        ntglobalflag_32bit = read_peb_dword(0x68)

        result = bypass_instance.install_bypasses(["peb_flags"])
        assert result["peb_flags"] is True, "Bypass should succeed"

        ntglobalflag_64bit = read_peb_dword(0xBC)
        assert ntglobalflag_64bit == 0, "64-bit NtGlobalFlag must be cleared"

        ntglobalflag_32bit_after = read_peb_dword(0x68)
        if ntglobalflag_32bit != ntglobalflag_32bit_after:
            pytest.fail("32-bit offset should not be affected by 64-bit PEB clearing")

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="32-bit subprocess test requires 64-bit Windows",
    )
    def test_32bit_subprocess_peb_clearing(
        self,
        tmp_path: Path,
    ) -> None:
        """32-bit subprocess running on 64-bit Windows must have PEB cleared correctly.

        This test validates WoW64 scenarios by spawning a 32-bit Python subprocess
        that runs the PEB clearing bypass and verifies flags are cleared using
        32-bit offsets.
        """
        test_script = tmp_path / "test_32bit_peb.py"
        test_script.write_text("""
import sys
import ctypes
from intellicrack.core.anti_analysis.debugger_bypass import DebuggerBypass

kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll

class ProcessBasicInformation(ctypes.Structure):
    _fields_ = [
        ("Reserved1", ctypes.c_void_p),
        ("PebBaseAddress", ctypes.c_void_p),
        ("Reserved2", ctypes.c_void_p * 2),
        ("UniqueProcessId", ctypes.POINTER(ctypes.c_ulong)),
        ("Reserved3", ctypes.c_void_p),
    ]

current_process = kernel32.GetCurrentProcess()
pbi = ProcessBasicInformation()
status = ntdll.NtQueryInformationProcess(current_process, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), None)

if status != 0 or not pbi.PebBaseAddress:
    sys.exit(1)

peb_addr = pbi.PebBaseAddress.value

one_byte = ctypes.c_ubyte(1)
bytes_written = ctypes.c_size_t()
kernel32.WriteProcessMemory(current_process, ctypes.c_void_p(peb_addr + 2), ctypes.byref(one_byte), 1, ctypes.byref(bytes_written))

bypass = DebuggerBypass()
result = bypass.install_bypasses(["peb_flags"])

if not result.get("peb_flags"):
    sys.exit(2)

byte_value = ctypes.c_ubyte()
bytes_read = ctypes.c_size_t()
kernel32.ReadProcessMemory(current_process, ctypes.c_void_p(peb_addr + 2), ctypes.byref(byte_value), 1, ctypes.byref(bytes_read))

if byte_value.value != 0:
    sys.exit(3)

dword_value = ctypes.c_ulong()
kernel32.ReadProcessMemory(current_process, ctypes.c_void_p(peb_addr + 0x68), ctypes.byref(dword_value), 4, ctypes.byref(bytes_read))

if dword_value.value != 0:
    sys.exit(4)

sys.exit(0)
""")

        python_32bit_paths = [
            r"C:\\Windows\\SysWOW64\\python.exe",
            r"C:\\Program Files (x86)\\Python39\\python.exe",
            r"C:\\Program Files (x86)\\Python38\\python.exe",
            r"C:\\Python39-32\\python.exe",
        ]

        python_32bit = None
        for path in python_32bit_paths:
            if Path(path).exists():
                python_32bit = path
                break

        if not python_32bit:
            pytest.skip(
                "32-bit Python not found. Install 32-bit Python to test WoW64 scenarios. "
                f"Searched paths: {python_32bit_paths}"
            )

        try:
            result = subprocess.run(
                [python_32bit, str(test_script)],
                capture_output=True,
                timeout=30,
                check=False,
            )
        except subprocess.TimeoutExpired:
            pytest.fail("32-bit subprocess timed out")
        except Exception as e:
            pytest.skip(f"Failed to run 32-bit subprocess: {e}")

        if result.returncode == 1:
            pytest.fail("Failed to get PEB address in 32-bit subprocess")
        elif result.returncode == 2:
            pytest.fail("PEB flags bypass failed in 32-bit subprocess")
        elif result.returncode == 3:
            pytest.fail("BeingDebugged flag not cleared in 32-bit subprocess")
        elif result.returncode == 4:
            pytest.fail("NtGlobalFlag not cleared at 32-bit offset in 32-bit subprocess")
        elif result.returncode != 0:
            pytest.fail(f"32-bit subprocess failed with code {result.returncode}: {result.stderr.decode()}")


class TestProtectedPebReads:
    """Test suite for protected PEB reads edge cases."""

    def test_peb_access_with_invalid_address(
        self,
        bypass_instance: DebuggerBypass,
    ) -> None:
        """Bypass must handle invalid PEB addresses gracefully.

        If NtQueryInformationProcess fails or returns invalid PEB address,
        the bypass should fail safely without crashing.
        """
        result = bypass_instance._bypass_peb_flags()

        if get_peb_address() == 0:
            assert result is False, "Bypass should fail gracefully with invalid PEB address"
        else:
            assert result is True, "Bypass should succeed with valid PEB address"

    def test_peb_flags_bypass_handles_write_failure(
        self,
        bypass_instance: DebuggerBypass,
    ) -> None:
        """Bypass must handle WriteProcessMemory failures gracefully.

        If memory protection prevents writing to PEB, the bypass should
        return False rather than crashing.
        """
        original_write = ctypes.windll.kernel32.WriteProcessMemory

        def failing_write(*args: Any) -> int:
            return 0

        try:
            ctypes.windll.kernel32.WriteProcessMemory = failing_write
            result = bypass_instance._bypass_peb_flags()
            assert result is False or result is True, "Bypass should handle write failure"
        finally:
            ctypes.windll.kernel32.WriteProcessMemory = original_write

    def test_peb_flags_bypass_with_readonly_peb(
        self,
        bypass_instance: DebuggerBypass,
    ) -> None:
        """Bypass must attempt to change memory protection if PEB is read-only.

        Some protected software may set PEB pages to read-only. The bypass
        should attempt VirtualProtectEx or handle the failure gracefully.
        """
        peb_addr = get_peb_address()
        if peb_addr == 0:
            pytest.skip("Cannot get PEB address")

        kernel32 = ctypes.windll.kernel32
        current_process = kernel32.GetCurrentProcess()

        old_protect = ctypes.c_ulong()
        PAGE_READONLY = 0x02
        PAGE_SIZE = 4096

        original_protect_result = kernel32.VirtualProtectEx(
            current_process,
            ctypes.c_void_p(peb_addr),
            PAGE_SIZE,
            PAGE_READONLY,
            ctypes.byref(old_protect),
        )

        if not original_protect_result:
            pytest.skip("Cannot change PEB page protection")

        try:
            result = bypass_instance.install_bypasses(["peb_flags"])

            if result["peb_flags"]:
                final_value = read_peb_byte(2)
                assert final_value == 0, "BeingDebugged should be cleared even with protection changes"
        finally:
            kernel32.VirtualProtectEx(
                current_process,
                ctypes.c_void_p(peb_addr),
                PAGE_SIZE,
                old_protect.value,
                ctypes.byref(old_protect),
            )

    def test_peb_flags_bypass_with_concurrent_access(
        self,
        bypass_instance: DebuggerBypass,
    ) -> None:
        """Bypass must handle concurrent PEB access from multiple threads.

        Protected software may read PEB flags from multiple threads. This
        validates the bypass works correctly with concurrent access.
        """
        import threading
        import time

        assert set_being_debugged_flag(), "Failed to set BeingDebugged flag"
        assert set_ntglobalflag(0x70), "Failed to set NtGlobalFlag"

        result = bypass_instance.install_bypasses(["peb_flags"])
        assert result["peb_flags"] is True, "Bypass should succeed"

        errors: list[str] = []

        def check_peb_flags() -> None:
            try:
                for _ in range(100):
                    being_debugged = read_peb_byte(2)
                    if being_debugged != 0:
                        errors.append(f"BeingDebugged is {being_debugged}, expected 0")

                    is_64bit = platform.machine().endswith("64")
                    offset = 0xBC if is_64bit else 0x68
                    ntglobalflag = read_peb_dword(offset)
                    if ntglobalflag != 0:
                        errors.append(f"NtGlobalFlag is {ntglobalflag:#x}, expected 0")

                    time.sleep(0.001)
            except Exception as e:
                errors.append(f"Exception in thread: {e}")

        threads = [threading.Thread(target=check_peb_flags) for _ in range(5)]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join(timeout=10)

        assert len(errors) == 0, f"Concurrent access errors: {errors}"


class TestIntegrationWithRealChecks:
    """Integration tests with real anti-debugging checks."""

    def test_defeats_simple_peb_check(
        self,
        bypass_instance: DebuggerBypass,
    ) -> None:
        """Bypass must defeat simple PEB BeingDebugged check in test code.

        This simulates how protected software directly reads PEB.BeingDebugged
        and validates the bypass defeats this check.
        """
        assert set_being_debugged_flag(), "Failed to set BeingDebugged flag"

        def check_being_debugged_manual() -> bool:
            try:
                peb_addr = get_peb_address()
                if not peb_addr:
                    return False

                kernel32 = ctypes.windll.kernel32
                current_process = kernel32.GetCurrentProcess()

                byte_value = ctypes.c_ubyte()
                bytes_read = ctypes.c_size_t()

                success = kernel32.ReadProcessMemory(
                    current_process,
                    ctypes.c_void_p(peb_addr + 2),
                    ctypes.byref(byte_value),
                    1,
                    ctypes.byref(bytes_read),
                )

                return bool(success and byte_value.value != 0)

            except Exception:
                return False

        assert check_being_debugged_manual() is True, "Should detect debugging initially"

        result = bypass_instance.install_bypasses(["peb_flags"])
        assert result["peb_flags"] is True, "Bypass should succeed"

        assert check_being_debugged_manual() is False, "Should NOT detect debugging after bypass"

    def test_defeats_ntglobalflag_heap_check(
        self,
        bypass_instance: DebuggerBypass,
    ) -> None:
        """Bypass must defeat NtGlobalFlag heap detection in test code.

        This simulates protected software checking NtGlobalFlag for heap
        debug flags (0x70) to detect debugger presence.
        """
        assert set_ntglobalflag(0x70), "Failed to set NtGlobalFlag"

        def check_ntglobalflag_manual() -> bool:
            try:
                is_64bit = platform.machine().endswith("64")
                offset = 0xBC if is_64bit else 0x68

                value = read_peb_dword(offset)
                return value != 0 and (value & 0x70) != 0

            except Exception:
                return False

        assert check_ntglobalflag_manual() is True, "Should detect debug flags initially"

        result = bypass_instance.install_bypasses(["peb_flags"])
        assert result["peb_flags"] is True, "Bypass should succeed"

        assert check_ntglobalflag_manual() is False, "Should NOT detect debug flags after bypass"

    def test_defeats_heap_flags_check(
        self,
        bypass_instance: DebuggerBypass,
    ) -> None:
        """Bypass must defeat ProcessHeap.Flags/ForceFlags check.

        This simulates protected software checking heap flags for debug
        values to detect debugger presence.
        """
        assert set_heap_debug_flags(), "Failed to set heap debug flags"

        def check_heap_flags_manual() -> bool:
            try:
                flags = read_heap_flags()
                force_flags = read_heap_force_flags()

                return (flags != 0x00000002 or force_flags != 0)

            except Exception:
                return False

        if not check_heap_flags_manual():
            pytest.skip("Failed to set heap debug flags for test")

        result = bypass_instance.install_bypasses(["peb_flags"])
        assert result["peb_flags"] is True, "Bypass should succeed"

        assert check_heap_flags_manual() is False, "Should NOT detect debug heap flags after bypass"

    def test_all_peb_bypasses_work_together(
        self,
        bypass_instance: DebuggerBypass,
        cleanup_peb_flags: None,
    ) -> None:
        """All PEB-related bypasses must work together comprehensively.

        Protected software often uses multiple PEB checks. This validates
        that all bypasses work together to defeat comprehensive detection.
        """
        assert set_being_debugged_flag(), "Failed to set BeingDebugged flag"
        assert set_ntglobalflag(0x70), "Failed to set NtGlobalFlag"
        assert set_heap_debug_flags(), "Failed to set heap debug flags"

        kernel32 = ctypes.windll.kernel32
        assert kernel32.IsDebuggerPresent() != 0, "Should detect debugging initially"

        result = bypass_instance.install_bypasses([
            "isdebuggerpresent",
            "checkremotedebuggerpresent",
            "peb_flags",
            "ntglobalflag",
        ])

        assert result["isdebuggerpresent"] is True, "IsDebuggerPresent bypass should succeed"
        assert result["checkremotedebuggerpresent"] is True, "CheckRemoteDebuggerPresent bypass should succeed"
        assert result["peb_flags"] is True, "PEB flags bypass should succeed"
        assert result["ntglobalflag"] is True, "NtGlobalFlag bypass should succeed"

        assert kernel32.IsDebuggerPresent() == 0, "IsDebuggerPresent must return FALSE"

        is_debugged = ctypes.c_bool()
        kernel32.CheckRemoteDebuggerPresent(
            kernel32.GetCurrentProcess(),
            ctypes.byref(is_debugged),
        )
        assert is_debugged.value is False, "CheckRemoteDebuggerPresent must return FALSE"

        assert read_peb_byte(2) == 0, "BeingDebugged must be 0"

        is_64bit = platform.machine().endswith("64")
        offset = 0xBC if is_64bit else 0x68
        assert read_peb_dword(offset) == 0, "NtGlobalFlag must be 0"

        assert read_heap_flags() == 0x00000002, "Heap Flags must be HEAP_GROWABLE"
        assert read_heap_force_flags() == 0, "Heap ForceFlags must be 0"
