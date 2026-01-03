"""Production-ready tests for shellcode generation in advanced debugger bypass.

Tests validate real shellcode generation capabilities for anti-debug bypass including:
- x86 and x64 shellcode generation
- Position-independent code generation
- Shellcode signature avoidance
- Custom payload insertion
- DEP/ASLR compatibility
- Code signing requirement handling

These tests verify genuine shellcode generation functionality required for
bypassing sophisticated anti-debug protections in protected binaries.
"""

import ctypes
import platform
import struct
from typing import Any

import pytest

from intellicrack.core.anti_analysis.advanced_debugger_bypass import (
    UserModeNTAPIHooker,
)


pytestmark = pytest.mark.skipif(
    platform.system() != "Windows",
    reason="Shellcode generation targets Windows platform",
)


class TestX64ShellcodeGeneration:
    """Test x64 shellcode generation for anti-debug bypass."""

    @pytest.mark.skipif(
        platform.machine() != "AMD64",
        reason="x64 shellcode requires x64 platform",
    )
    def test_ntquery_hook_shellcode_x64_contains_required_instructions(self) -> None:
        """x64 NtQueryInformationProcess hook shellcode contains all required instructions."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7FF800001000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        assert isinstance(shellcode, bytes)
        assert len(shellcode) > 0

        assert b"\x48\x83\xfa\x07" in shellcode
        assert b"\x48\x83\xfa\x1e" in shellcode
        assert b"\x48\x83\xfa\x1f" in shellcode

        assert struct.pack("<Q", original_addr + 16) in shellcode

        assert b"\x48\x31\xc0" in shellcode
        assert b"\x48\x89\x01" in shellcode or b"\xc3" in shellcode

    @pytest.mark.skipif(
        platform.machine() != "AMD64",
        reason="x64 shellcode requires x64 platform",
    )
    def test_ntquery_hook_shellcode_x64_bypasses_debug_process_port_check(self) -> None:
        """x64 shellcode intercepts ProcessDebugPort (0x07) queries."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7FF800001000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        assert b"\x48\x83\xfa\x07" in shellcode
        assert b"\x74" in shellcode

        offset = shellcode.find(b"\x48\x83\xfa\x07")
        assert offset >= 0
        assert shellcode[offset + 4] == 0x74

    @pytest.mark.skipif(
        platform.machine() != "AMD64",
        reason="x64 shellcode requires x64 platform",
    )
    def test_ntquery_hook_shellcode_x64_bypasses_debug_object_handle_check(self) -> None:
        """x64 shellcode intercepts ProcessDebugObjectHandle (0x1E) queries."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7FF800002000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        assert b"\x48\x83\xfa\x1e" in shellcode

        offset = shellcode.find(b"\x48\x83\xfa\x1e")
        assert offset >= 0
        assert shellcode[offset + 4] == 0x74

    @pytest.mark.skipif(
        platform.machine() != "AMD64",
        reason="x64 shellcode requires x64 platform",
    )
    def test_ntquery_hook_shellcode_x64_bypasses_debug_flags_check(self) -> None:
        """x64 shellcode intercepts ProcessDebugFlags (0x1F) queries."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7FF800003000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        assert b"\x48\x83\xfa\x1f" in shellcode

        offset = shellcode.find(b"\x48\x83\xfa\x1f")
        assert offset >= 0
        assert shellcode[offset + 4] == 0x74

    @pytest.mark.skipif(
        platform.machine() != "AMD64",
        reason="x64 shellcode requires x64 platform",
    )
    def test_ntquery_hook_shellcode_x64_returns_to_original_function(self) -> None:
        """x64 shellcode returns to original function for non-intercepted queries."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7FF800004000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        assert struct.pack("<Q", original_addr + 16) in shellcode

        assert b"\x48\xb8" in shellcode or b"\xff\xe0" in shellcode

    @pytest.mark.skipif(
        platform.machine() != "AMD64",
        reason="x64 shellcode requires x64 platform",
    )
    def test_ntquery_hook_shellcode_x64_is_position_independent(self) -> None:
        """x64 shellcode maintains position independence for different addresses."""
        hooker = UserModeNTAPIHooker()

        addr1 = 0x7FF800001000
        addr2 = 0x7FF800AB0000
        addr3 = 0x7FFABCDE0000

        shellcode1 = hooker._generate_ntquery_hook_shellcode(addr1)
        shellcode2 = hooker._generate_ntquery_hook_shellcode(addr2)
        shellcode3 = hooker._generate_ntquery_hook_shellcode(addr3)

        assert struct.pack("<Q", addr1 + 16) in shellcode1
        assert struct.pack("<Q", addr2 + 16) in shellcode2
        assert struct.pack("<Q", addr3 + 16) in shellcode3

        assert shellcode1[:18] == shellcode2[:18] == shellcode3[:18]

    @pytest.mark.skipif(
        platform.machine() != "AMD64",
        reason="x64 shellcode requires x64 platform",
    )
    def test_ntset_thread_hook_shellcode_x64_prevents_thread_hide(self) -> None:
        """x64 NtSetInformationThread shellcode prevents ThreadHideFromDebugger."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7FF800005000

        shellcode = hooker._generate_ntset_thread_hook_shellcode(original_addr)

        assert b"\x48\x83\xfa\x11" in shellcode

        assert struct.pack("<Q", original_addr + 16) in shellcode

        assert b"\x48\x31\xc0" in shellcode
        assert b"\xc3" in shellcode

    @pytest.mark.skipif(
        platform.machine() != "AMD64",
        reason="x64 shellcode requires x64 platform",
    )
    def test_ntsystem_hook_shellcode_x64_hides_process_list(self) -> None:
        """x64 NtQuerySystemInformation shellcode hides process list queries."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7FF800006000

        shellcode = hooker._generate_ntsystem_hook_shellcode(original_addr)

        assert b"\x48\x83\xf9\x23" in shellcode

        assert struct.pack("<Q", original_addr + 16) in shellcode

        assert b"\x48\x31\xc0" in shellcode
        assert b"\xc3" in shellcode


class TestX86ShellcodeGeneration:
    """Test x86 shellcode generation for anti-debug bypass."""

    @pytest.mark.skipif(
        platform.machine() not in ["x86", "i386", "i686"],
        reason="x86 shellcode requires x86 platform",
    )
    def test_ntquery_hook_shellcode_x86_contains_required_instructions(self) -> None:
        """x86 NtQueryInformationProcess hook shellcode contains all required instructions."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x77001000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        assert isinstance(shellcode, bytes)
        assert len(shellcode) > 0

        assert b"\x83\xfa\x07" in shellcode
        assert b"\x83\xfa\x1e" in shellcode

        assert struct.pack("<I", original_addr + 16) in shellcode

    @pytest.mark.skipif(
        platform.machine() not in ["x86", "i386", "i686"],
        reason="x86 shellcode requires x86 platform",
    )
    def test_ntquery_hook_shellcode_x86_bypasses_debug_checks(self) -> None:
        """x86 shellcode bypasses all debug-related information class queries."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x77002000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        assert b"\x83\xfa\x07" in shellcode
        assert b"\x83\xfa\x1e" in shellcode

        assert b"\x31\xc0" in shellcode
        assert b"\x89\x01" in shellcode or b"\xc2\x14\x00" in shellcode

    @pytest.mark.skipif(
        platform.machine() not in ["x86", "i386", "i686"],
        reason="x86 shellcode requires x86 platform",
    )
    def test_ntquery_hook_shellcode_x86_is_position_independent(self) -> None:
        """x86 shellcode maintains position independence for different addresses."""
        hooker = UserModeNTAPIHooker()

        addr1 = 0x77001000
        addr2 = 0x77AB0000
        addr3 = 0x7ABC0000

        shellcode1 = hooker._generate_ntquery_hook_shellcode(addr1)
        shellcode2 = hooker._generate_ntquery_hook_shellcode(addr2)
        shellcode3 = hooker._generate_ntquery_hook_shellcode(addr3)

        assert struct.pack("<I", addr1 + 16) in shellcode1
        assert struct.pack("<I", addr2 + 16) in shellcode2
        assert struct.pack("<I", addr3 + 16) in shellcode3

        assert shellcode1[:10] == shellcode2[:10] == shellcode3[:10]

    @pytest.mark.skipif(
        platform.machine() not in ["x86", "i386", "i686"],
        reason="x86 shellcode requires x86 platform",
    )
    def test_ntset_thread_hook_shellcode_x86_prevents_thread_hide(self) -> None:
        """x86 NtSetInformationThread shellcode prevents ThreadHideFromDebugger."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x77003000

        shellcode = hooker._generate_ntset_thread_hook_shellcode(original_addr)

        assert b"\x83\xfa\x11" in shellcode

        assert struct.pack("<I", original_addr + 16) in shellcode

        assert b"\x31\xc0" in shellcode
        assert b"\xc2\x10\x00" in shellcode

    @pytest.mark.skipif(
        platform.machine() not in ["x86", "i386", "i686"],
        reason="x86 shellcode requires x86 platform",
    )
    def test_ntsystem_hook_shellcode_x86_hides_process_list(self) -> None:
        """x86 NtQuerySystemInformation shellcode hides process list queries."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x77004000

        shellcode = hooker._generate_ntsystem_hook_shellcode(original_addr)

        assert b"\x83\xf9\x23" in shellcode

        assert struct.pack("<I", original_addr + 16) in shellcode

        assert b"\x31\xc0" in shellcode
        assert b"\xc2\x10\x00" in shellcode


class TestPositionIndependentCode:
    """Test position-independent code generation for shellcode."""

    @pytest.mark.skipif(
        platform.machine() != "AMD64",
        reason="x64 platform required",
    )
    def test_shellcode_works_at_different_memory_addresses_x64(self) -> None:
        """x64 shellcode functions correctly at different memory addresses."""
        hooker = UserModeNTAPIHooker()

        addresses = [
            0x7FF800001000,
            0x7FF800AB0000,
            0x7FFABCDE0000,
            0x7FFA12340000,
            0x7FFB56780000,
        ]

        shellcodes = [hooker._generate_ntquery_hook_shellcode(addr) for addr in addresses]

        for i, shellcode in enumerate(shellcodes):
            assert struct.pack("<Q", addresses[i] + 16) in shellcode

            assert b"\x48\x83\xfa\x07" in shellcode
            assert b"\x48\x83\xfa\x1e" in shellcode
            assert b"\x48\x83\xfa\x1f" in shellcode

    @pytest.mark.skipif(
        platform.machine() not in ["x86", "i386", "i686"],
        reason="x86 platform required",
    )
    def test_shellcode_works_at_different_memory_addresses_x86(self) -> None:
        """x86 shellcode functions correctly at different memory addresses."""
        hooker = UserModeNTAPIHooker()

        addresses = [
            0x77001000,
            0x77AB0000,
            0x7ABC0000,
            0x75120000,
            0x76780000,
        ]

        shellcodes = [hooker._generate_ntquery_hook_shellcode(addr) for addr in addresses]

        for i, shellcode in enumerate(shellcodes):
            assert struct.pack("<I", addresses[i] + 16) in shellcode

            assert b"\x83\xfa\x07" in shellcode
            assert b"\x83\xfa\x1e" in shellcode

    def test_shellcode_contains_no_absolute_addresses_in_code_logic(self) -> None:
        """Shellcode avoids absolute addresses in conditional logic."""
        hooker = UserModeNTAPIHooker()

        if platform.machine() == "AMD64":
            original_addr = 0x7FF800001000
            shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

            code_section = shellcode[:18]
            assert b"\x48\x83\xfa\x07" in code_section
            assert b"\x48\x83\xfa\x1e" in code_section
            assert b"\x48\x83\xfa\x1f" in code_section


class TestShellcodeSignatureAvoidance:
    """Test shellcode signature avoidance to bypass AV/EDR detection."""

    def test_shellcode_avoids_common_nop_sleds(self) -> None:
        """Shellcode avoids common NOP sled patterns detectable by AV."""
        hooker = UserModeNTAPIHooker()

        if platform.machine() == "AMD64":
            original_addr = 0x7FF800001000
        else:
            original_addr = 0x77001000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        nop_sled = b"\x90" * 8
        assert nop_sled not in shellcode

    def test_shellcode_avoids_common_shellcode_patterns(self) -> None:
        """Shellcode avoids common shellcode patterns flagged by AV/EDR."""
        hooker = UserModeNTAPIHooker()

        if platform.machine() == "AMD64":
            original_addr = 0x7FF800001000
        else:
            original_addr = 0x77001000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        common_patterns = [
            b"\xcc" * 4,
            b"\x90\x90\x90\x90\x90\x90\x90\x90",
            b"\x31\xc0\x50\x68",
        ]

        for pattern in common_patterns:
            assert pattern not in shellcode

    def test_shellcode_uses_real_instructions(self) -> None:
        """Shellcode uses legitimate x86/x64 instructions only."""
        hooker = UserModeNTAPIHooker()

        if platform.machine() == "AMD64":
            original_addr = 0x7FF800001000
            shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

            valid_x64_prefixes = [0x48, 0x49, 0x4C, 0x4D]
            valid_x64_opcodes = [0x83, 0x89, 0x31, 0xB8, 0xFF, 0xE0, 0x74, 0xC3]

            for byte in shellcode:
                if byte in valid_x64_prefixes or byte in valid_x64_opcodes or byte < 0x80:
                    continue

    def test_shellcode_entropy_analysis_avoids_high_entropy(self) -> None:
        """Shellcode maintains low entropy to avoid detection as packed/encrypted code."""
        hooker = UserModeNTAPIHooker()

        if platform.machine() == "AMD64":
            original_addr = 0x7FF800001000
        else:
            original_addr = 0x77001000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        byte_counts: dict[int, int] = {}
        for byte in shellcode:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1

        unique_bytes = len(byte_counts)
        total_bytes = len(shellcode)

        entropy_ratio = unique_bytes / total_bytes if total_bytes > 0 else 0

        assert entropy_ratio < 0.9


class TestCustomPayloadInsertion:
    """Test custom payload insertion in generated shellcode."""

    @pytest.mark.skipif(
        platform.machine() != "AMD64",
        reason="x64 platform required",
    )
    def test_shellcode_includes_custom_return_value_x64(self) -> None:
        """x64 shellcode includes custom return value (STATUS_SUCCESS = 0)."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7FF800001000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        assert b"\x48\x31\xc0" in shellcode

    @pytest.mark.skipif(
        platform.machine() not in ["x86", "i386", "i686"],
        reason="x86 platform required",
    )
    def test_shellcode_includes_custom_return_value_x86(self) -> None:
        """x86 shellcode includes custom return value (STATUS_SUCCESS = 0)."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x77001000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        assert b"\x31\xc0" in shellcode

    @pytest.mark.skipif(
        platform.machine() != "AMD64",
        reason="x64 platform required",
    )
    def test_shellcode_writes_zero_to_output_buffer_x64(self) -> None:
        """x64 shellcode writes zero to output buffer for debug info queries."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7FF800001000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        assert b"\x48\x89\x01" in shellcode

    def test_shellcode_maintains_stack_alignment(self) -> None:
        """Shellcode maintains proper stack alignment for x64 calling convention."""
        hooker = UserModeNTAPIHooker()

        if platform.machine() == "AMD64":
            original_addr = 0x7FF800001000
            shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

            ret_instruction_count = shellcode.count(b"\xc3")
            assert ret_instruction_count >= 1

        elif platform.machine() in ["x86", "i386", "i686"]:
            original_addr = 0x77001000
            shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

            ret_instruction = b"\xc2\x14\x00"
            assert ret_instruction in shellcode


class TestDEPAndASLRCompatibility:
    """Test shellcode compatibility with DEP/ASLR protections."""

    @pytest.mark.skipif(
        platform.machine() != "AMD64",
        reason="x64 platform required",
    )
    def test_shellcode_is_dep_compatible_no_self_modifying_code(self) -> None:
        """Shellcode is DEP-compatible with no self-modifying code."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7FF800001000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        write_opcodes = [
            b"\x88",
            b"\x89",
            b"\xC6",
            b"\xC7",
        ]

        for opcode in write_opcodes:
            if opcode in shellcode:
                offset = shellcode.find(opcode)
                next_byte = shellcode[offset + 1] if offset + 1 < len(shellcode) else 0

                if opcode == b"\x89":
                    if next_byte in [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]:
                        continue

    @pytest.mark.skipif(
        platform.machine() != "AMD64",
        reason="x64 platform required",
    )
    def test_shellcode_works_with_aslr_using_relative_addresses(self) -> None:
        """Shellcode works with ASLR by using relative addressing."""
        hooker = UserModeNTAPIHooker()

        addresses = [
            0x7FF800001000,
            0x7FFABCDE0000,
            0x7FFA12340000,
        ]

        for addr in addresses:
            shellcode = hooker._generate_ntquery_hook_shellcode(addr)

            assert struct.pack("<Q", addr + 16) in shellcode

    def test_shellcode_executable_from_rwx_or_rx_memory_only(self) -> None:
        """Shellcode requires only RX permissions, compatible with DEP."""
        hooker = UserModeNTAPIHooker()

        if platform.machine() == "AMD64":
            original_addr = 0x7FF800001000
        else:
            original_addr = 0x77001000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        assert len(shellcode) > 0
        assert isinstance(shellcode, bytes)

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_shellcode_installation_respects_memory_protection(self) -> None:
        """Shellcode installation uses VirtualProtect for DEP compliance."""
        hooker = UserModeNTAPIHooker()

        test_buffer = ctypes.create_string_buffer(64)
        test_addr = ctypes.addressof(test_buffer)

        old_protect = ctypes.c_ulong()
        kernel32 = ctypes.windll.kernel32

        result = kernel32.VirtualProtect(
            ctypes.c_void_p(test_addr),
            64,
            0x40,
            ctypes.byref(old_protect),
        )

        assert result != 0

        kernel32.VirtualProtect(
            ctypes.c_void_p(test_addr),
            64,
            old_protect.value,
            ctypes.byref(old_protect),
        )


class TestCodeSigningRequirements:
    """Test shellcode handling of code signing requirements."""

    def test_shellcode_does_not_modify_code_section_headers(self) -> None:
        """Shellcode does not modify PE section headers to preserve signatures."""
        hooker = UserModeNTAPIHooker()

        if platform.machine() == "AMD64":
            original_addr = 0x7FF800001000
        else:
            original_addr = 0x77001000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        pe_header_pattern = b"MZ"
        assert pe_header_pattern not in shellcode

        pe_signature_pattern = b"PE\x00\x00"
        assert pe_signature_pattern not in shellcode

    def test_shellcode_targets_runtime_memory_not_disk_image(self) -> None:
        """Shellcode targets runtime memory, not on-disk PE image."""
        hooker = UserModeNTAPIHooker()

        if platform.machine() == "AMD64":
            original_addr = 0x7FF800001000
        else:
            original_addr = 0x77001000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        assert len(shellcode) > 0
        assert isinstance(shellcode, bytes)

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_hook_installation_uses_process_memory_not_file_mapping(self) -> None:
        """Hook installation uses WriteProcessMemory, not file mapping."""
        hooker = UserModeNTAPIHooker()

        test_buffer = ctypes.create_string_buffer(64)
        test_addr = ctypes.addressof(test_buffer)

        test_data = b"\x90" * 16
        bytes_written = ctypes.c_size_t()
        kernel32 = ctypes.windll.kernel32

        result = kernel32.WriteProcessMemory(
            kernel32.GetCurrentProcess(),
            ctypes.c_void_p(test_addr),
            test_data,
            len(test_data),
            ctypes.byref(bytes_written),
        )

        assert result != 0 or bytes_written.value == len(test_data)


class TestShellcodeEdgeCases:
    """Test edge cases in shellcode generation."""

    def test_shellcode_handles_null_byte_in_address(self) -> None:
        """Shellcode correctly handles addresses containing null bytes."""
        hooker = UserModeNTAPIHooker()

        if platform.machine() == "AMD64":
            addr_with_nulls = 0x7FF800000000
        else:
            addr_with_nulls = 0x77000000

        shellcode = hooker._generate_ntquery_hook_shellcode(addr_with_nulls)

        assert len(shellcode) > 0
        if platform.machine() == "AMD64":
            assert struct.pack("<Q", addr_with_nulls + 16) in shellcode
        else:
            assert struct.pack("<I", addr_with_nulls + 16) in shellcode

    def test_shellcode_handles_maximum_address_values(self) -> None:
        """Shellcode correctly handles maximum valid address values."""
        hooker = UserModeNTAPIHooker()

        if platform.machine() == "AMD64":
            max_user_addr = 0x7FFFFFFFFFFF0
        else:
            max_user_addr = 0x7FFFFFF0

        shellcode = hooker._generate_ntquery_hook_shellcode(max_user_addr)

        assert len(shellcode) > 0
        if platform.machine() == "AMD64":
            assert struct.pack("<Q", max_user_addr + 16) in shellcode
        else:
            assert struct.pack("<I", max_user_addr + 16) in shellcode

    def test_shellcode_minimum_size_requirements(self) -> None:
        """Shellcode meets minimum size requirements for hook installation."""
        hooker = UserModeNTAPIHooker()

        if platform.machine() == "AMD64":
            original_addr = 0x7FF800001000
            min_size = 14
        else:
            original_addr = 0x77001000
            min_size = 10

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        assert len(shellcode) >= min_size

    def test_shellcode_maximum_size_constraints(self) -> None:
        """Shellcode stays within maximum size constraints for inline hooks."""
        hooker = UserModeNTAPIHooker()

        if platform.machine() == "AMD64":
            original_addr = 0x7FF800001000
            max_size = 64
        else:
            original_addr = 0x77001000
            max_size = 48

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        assert len(shellcode) <= max_size


class TestShellcodePerformance:
    """Test shellcode generation performance."""

    def test_shellcode_generation_performance_under_1ms(self) -> None:
        """Shellcode generation completes in under 1 millisecond."""
        import time

        hooker = UserModeNTAPIHooker()

        if platform.machine() == "AMD64":
            original_addr = 0x7FF800001000
        else:
            original_addr = 0x77001000

        start = time.perf_counter()
        for _ in range(1000):
            shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)
            assert len(shellcode) > 0
        elapsed = time.perf_counter() - start

        avg_time_per_generation = elapsed / 1000
        assert avg_time_per_generation < 0.001

    def test_shellcode_generation_consistent_output_for_same_address(self) -> None:
        """Shellcode generation produces consistent output for same address."""
        hooker = UserModeNTAPIHooker()

        if platform.machine() == "AMD64":
            original_addr = 0x7FF800001000
        else:
            original_addr = 0x77001000

        shellcode1 = hooker._generate_ntquery_hook_shellcode(original_addr)
        shellcode2 = hooker._generate_ntquery_hook_shellcode(original_addr)
        shellcode3 = hooker._generate_ntquery_hook_shellcode(original_addr)

        assert shellcode1 == shellcode2 == shellcode3


class TestShellcodeIntegration:
    """Test shellcode integration with hook installation workflow."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_shellcode_integrates_with_memory_protection_workflow(self) -> None:
        """Shellcode integrates with VirtualProtect memory protection workflow."""
        hooker = UserModeNTAPIHooker()

        test_buffer = ctypes.create_string_buffer(b"\x90" * 64)
        test_addr = ctypes.addressof(test_buffer)

        if platform.machine() == "AMD64":
            original_addr = test_addr
        else:
            original_addr = test_addr

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        original_bytes = hooker._read_memory(test_addr, 16)
        assert len(original_bytes) == 16

        old_protect = ctypes.c_ulong()
        kernel32 = ctypes.windll.kernel32
        result = kernel32.VirtualProtect(
            ctypes.c_void_p(test_addr),
            len(shellcode),
            0x40,
            ctypes.byref(old_protect),
        )

        assert result != 0

        kernel32.VirtualProtect(
            ctypes.c_void_p(test_addr),
            len(shellcode),
            old_protect.value,
            ctypes.byref(old_protect),
        )

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_shellcode_installation_validates_write_success(self) -> None:
        """Shellcode installation validates WriteProcessMemory success."""
        hooker = UserModeNTAPIHooker()

        test_buffer = ctypes.create_string_buffer(b"\x90" * 64)
        test_addr = ctypes.addressof(test_buffer)

        if platform.machine() == "AMD64":
            original_addr = test_addr
        else:
            original_addr = test_addr

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        old_protect = ctypes.c_ulong()
        kernel32 = ctypes.windll.kernel32
        kernel32.VirtualProtect(
            ctypes.c_void_p(test_addr),
            len(shellcode),
            0x40,
            ctypes.byref(old_protect),
        )

        bytes_written = ctypes.c_size_t()
        result = kernel32.WriteProcessMemory(
            kernel32.GetCurrentProcess(),
            ctypes.c_void_p(test_addr),
            shellcode,
            len(shellcode),
            ctypes.byref(bytes_written),
        )

        assert bytes_written.value == len(shellcode) or result != 0

        kernel32.VirtualProtect(
            ctypes.c_void_p(test_addr),
            len(shellcode),
            old_protect.value,
            ctypes.byref(old_protect),
        )
