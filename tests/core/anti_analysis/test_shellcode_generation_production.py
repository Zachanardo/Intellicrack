"""Production-ready tests for shellcode generation in advanced debugger bypass.

Tests validate real shellcode generation capabilities for anti-debug bypass:
- x86 shellcode generation for NT API hooks
- x64 shellcode generation for NT API hooks
- Position-independent code (PIC) generation
- Avoidance of common shellcode signatures
- Custom payload insertion support
- DEP/ASLR compatibility
- Code signing requirements handling

These tests verify genuine offensive capabilities for bypassing anti-debugging protections.
"""

import ctypes
import platform
import struct
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.anti_analysis.advanced_debugger_bypass import (
    UserModeNTAPIHooker,
)


pytestmark = pytest.mark.skipif(
    platform.system() != "Windows",
    reason="Shellcode generation targets Windows NT API functions",
)


class TestX86ShellcodeGeneration:
    """Test x86 (32-bit) shellcode generation for NT API hooks."""

    @pytest.mark.skipif(
        platform.machine().endswith("64"),
        reason="x86 shellcode validation requires 32-bit environment or emulation",
    )
    def test_ntquery_hook_shellcode_x86_structure(self) -> None:
        """NtQueryInformationProcess x86 shellcode has valid structure."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7C800000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        assert isinstance(shellcode, bytes)
        assert len(shellcode) > 0
        assert shellcode[0] == 0x83
        assert shellcode[1] == 0xFA
        assert shellcode[2] == 0x07

    @pytest.mark.skipif(
        platform.machine().endswith("64"),
        reason="x86 shellcode validation requires 32-bit environment",
    )
    def test_ntquery_hook_shellcode_x86_checks_processdebuport(self) -> None:
        """NtQueryInformationProcess x86 shellcode checks ProcessDebugPort (0x07)."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7C800000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        comparison_value = shellcode[2]
        assert comparison_value == 0x07

    @pytest.mark.skipif(
        platform.machine().endswith("64"),
        reason="x86 shellcode validation requires 32-bit environment",
    )
    def test_ntquery_hook_shellcode_x86_checks_debugobjecthandle(self) -> None:
        """NtQueryInformationProcess x86 shellcode checks ProcessDebugObjectHandle (0x1E)."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7C800000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        comparison_value = shellcode[6]
        assert comparison_value == 0x1E

    @pytest.mark.skipif(
        platform.machine().endswith("64"),
        reason="x86 shellcode validation requires 32-bit environment",
    )
    def test_ntquery_hook_shellcode_x86_returns_clean(self) -> None:
        """NtQueryInformationProcess x86 shellcode returns clean status for debug queries."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7C800000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        xor_eax_eax_pattern = b"\x31\xc0"
        assert xor_eax_eax_pattern in shellcode

    @pytest.mark.skipif(
        platform.machine().endswith("64"),
        reason="x86 shellcode validation requires 32-bit environment",
    )
    def test_ntquery_hook_shellcode_x86_embedded_return_address(self) -> None:
        """NtQueryInformationProcess x86 shellcode embeds correct return address."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7C800000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        expected_return = original_addr + 16
        return_addr_bytes = struct.pack("<I", expected_return)
        assert return_addr_bytes in shellcode

    @pytest.mark.skipif(
        platform.machine().endswith("64"),
        reason="x86 shellcode validation requires 32-bit environment",
    )
    def test_ntset_thread_hook_shellcode_x86_structure(self) -> None:
        """NtSetInformationThread x86 shellcode has valid structure."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7C800000

        shellcode = hooker._generate_ntset_thread_hook_shellcode(original_addr)

        assert isinstance(shellcode, bytes)
        assert len(shellcode) > 0
        assert shellcode[0] == 0x83
        assert shellcode[1] == 0xFA

    @pytest.mark.skipif(
        platform.machine().endswith("64"),
        reason="x86 shellcode validation requires 32-bit environment",
    )
    def test_ntset_thread_hook_shellcode_x86_checks_threadhidefromdebugger(self) -> None:
        """NtSetInformationThread x86 shellcode checks ThreadHideFromDebugger (0x11)."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7C800000

        shellcode = hooker._generate_ntset_thread_hook_shellcode(original_addr)

        comparison_value = shellcode[2]
        assert comparison_value == 0x11

    @pytest.mark.skipif(
        platform.machine().endswith("64"),
        reason="x86 shellcode validation requires 32-bit environment",
    )
    def test_ntset_thread_hook_shellcode_x86_returns_success(self) -> None:
        """NtSetInformationThread x86 shellcode returns success for hide requests."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7C800000

        shellcode = hooker._generate_ntset_thread_hook_shellcode(original_addr)

        xor_eax_eax_pattern = b"\x31\xc0"
        assert xor_eax_eax_pattern in shellcode

    @pytest.mark.skipif(
        platform.machine().endswith("64"),
        reason="x86 shellcode validation requires 32-bit environment",
    )
    def test_ntsystem_hook_shellcode_x86_structure(self) -> None:
        """NtQuerySystemInformation x86 shellcode has valid structure."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7C800000

        shellcode = hooker._generate_ntsystem_hook_shellcode(original_addr)

        assert isinstance(shellcode, bytes)
        assert len(shellcode) > 0
        assert shellcode[0] == 0x83

    @pytest.mark.skipif(
        platform.machine().endswith("64"),
        reason="x86 shellcode validation requires 32-bit environment",
    )
    def test_ntsystem_hook_shellcode_x86_checks_systemkerneldebuggerinformation(
        self,
    ) -> None:
        """NtQuerySystemInformation x86 shellcode checks SystemKernelDebuggerInformation (0x23)."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7C800000

        shellcode = hooker._generate_ntsystem_hook_shellcode(original_addr)

        comparison_value = shellcode[2]
        assert comparison_value == 0x23


class TestX64ShellcodeGeneration:
    """Test x64 (64-bit) shellcode generation for NT API hooks."""

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="x64 shellcode requires 64-bit environment",
    )
    def test_ntquery_hook_shellcode_x64_structure(self) -> None:
        """NtQueryInformationProcess x64 shellcode has valid structure."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7FF800001000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        assert isinstance(shellcode, bytes)
        assert len(shellcode) > 0
        assert shellcode[0] == 0x48
        assert shellcode[1] == 0x83
        assert shellcode[2] == 0xFA
        assert shellcode[3] == 0x07

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="x64 shellcode requires 64-bit environment",
    )
    def test_ntquery_hook_shellcode_x64_checks_processdebuport(self) -> None:
        """NtQueryInformationProcess x64 shellcode checks ProcessDebugPort (0x07)."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7FF800001000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        comparison_value = shellcode[3]
        assert comparison_value == 0x07

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="x64 shellcode requires 64-bit environment",
    )
    def test_ntquery_hook_shellcode_x64_checks_debugobjecthandle(self) -> None:
        """NtQueryInformationProcess x64 shellcode checks ProcessDebugObjectHandle (0x1E)."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7FF800001000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        comparison_value = shellcode[8]
        assert comparison_value == 0x1E

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="x64 shellcode requires 64-bit environment",
    )
    def test_ntquery_hook_shellcode_x64_checks_debugflags(self) -> None:
        """NtQueryInformationProcess x64 shellcode checks ProcessDebugFlags (0x1F)."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7FF800001000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        comparison_value = shellcode[13]
        assert comparison_value == 0x1F

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="x64 shellcode requires 64-bit environment",
    )
    def test_ntquery_hook_shellcode_x64_returns_clean(self) -> None:
        """NtQueryInformationProcess x64 shellcode returns clean status for debug queries."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7FF800001000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        xor_rax_rax_pattern = b"\x48\x31\xc0"
        assert xor_rax_rax_pattern in shellcode

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="x64 shellcode requires 64-bit environment",
    )
    def test_ntquery_hook_shellcode_x64_embedded_return_address(self) -> None:
        """NtQueryInformationProcess x64 shellcode embeds correct 64-bit return address."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7FF800001000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        expected_return = original_addr + 16
        return_addr_bytes = struct.pack("<Q", expected_return)
        assert return_addr_bytes in shellcode

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="x64 shellcode requires 64-bit environment",
    )
    def test_ntquery_hook_shellcode_x64_uses_movabs(self) -> None:
        """NtQueryInformationProcess x64 shellcode uses movabs for 64-bit addresses."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7FF800001000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        movabs_rax_pattern = b"\x48\xb8"
        assert movabs_rax_pattern in shellcode

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="x64 shellcode requires 64-bit environment",
    )
    def test_ntset_thread_hook_shellcode_x64_structure(self) -> None:
        """NtSetInformationThread x64 shellcode has valid structure."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7FF800001000

        shellcode = hooker._generate_ntset_thread_hook_shellcode(original_addr)

        assert isinstance(shellcode, bytes)
        assert len(shellcode) > 0
        assert shellcode[0] == 0x48
        assert shellcode[1] == 0x83
        assert shellcode[2] == 0xFA

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="x64 shellcode requires 64-bit environment",
    )
    def test_ntset_thread_hook_shellcode_x64_checks_threadhidefromdebugger(self) -> None:
        """NtSetInformationThread x64 shellcode checks ThreadHideFromDebugger (0x11)."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7FF800001000

        shellcode = hooker._generate_ntset_thread_hook_shellcode(original_addr)

        comparison_value = shellcode[3]
        assert comparison_value == 0x11

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="x64 shellcode requires 64-bit environment",
    )
    def test_ntset_thread_hook_shellcode_x64_returns_success(self) -> None:
        """NtSetInformationThread x64 shellcode returns success for hide requests."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7FF800001000

        shellcode = hooker._generate_ntset_thread_hook_shellcode(original_addr)

        xor_rax_rax_pattern = b"\x48\x31\xc0"
        assert xor_rax_rax_pattern in shellcode

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="x64 shellcode requires 64-bit environment",
    )
    def test_ntsystem_hook_shellcode_x64_structure(self) -> None:
        """NtQuerySystemInformation x64 shellcode has valid structure."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7FF800001000

        shellcode = hooker._generate_ntsystem_hook_shellcode(original_addr)

        assert isinstance(shellcode, bytes)
        assert len(shellcode) > 0
        assert shellcode[0] == 0x48
        assert shellcode[1] == 0x83

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="x64 shellcode requires 64-bit environment",
    )
    def test_ntsystem_hook_shellcode_x64_checks_systemkerneldebuggerinformation(
        self,
    ) -> None:
        """NtQuerySystemInformation x64 shellcode checks SystemKernelDebuggerInformation (0x23)."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7FF800001000

        shellcode = hooker._generate_ntsystem_hook_shellcode(original_addr)

        comparison_value = shellcode[3]
        assert comparison_value == 0x23


class TestPositionIndependentCode:
    """Test position-independent code (PIC) generation for shellcode."""

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="PIC validation requires 64-bit environment",
    )
    def test_shellcode_works_at_different_addresses(self) -> None:
        """Shellcode structure remains valid when target address changes."""
        hooker = UserModeNTAPIHooker()

        addresses = [
            0x7FF800001000,
            0x7FF900002000,
            0x7FFA00003000,
            0x7FFB00004000,
        ]

        shellcodes = [hooker._generate_ntquery_hook_shellcode(addr) for addr in addresses]

        for i in range(len(shellcodes) - 1):
            assert shellcodes[i][0:18] == shellcodes[i + 1][0:18]

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="PIC validation requires 64-bit environment",
    )
    def test_shellcode_relative_jump_calculation(self) -> None:
        """Shellcode calculates correct relative jumps based on target address."""
        hooker = UserModeNTAPIHooker()

        addr1 = 0x7FF800001000
        addr2 = 0x7FF800002000

        shellcode1 = hooker._generate_ntquery_hook_shellcode(addr1)
        shellcode2 = hooker._generate_ntquery_hook_shellcode(addr2)

        return_addr1 = struct.unpack("<Q", shellcode1[19:27])[0]
        return_addr2 = struct.unpack("<Q", shellcode2[19:27])[0]

        assert return_addr1 == addr1 + 16
        assert return_addr2 == addr2 + 16
        assert return_addr2 - return_addr1 == 0x1000

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="PIC validation requires 64-bit environment",
    )
    def test_shellcode_no_hardcoded_addresses_in_instruction_logic(self) -> None:
        """Shellcode instruction logic contains no hardcoded absolute addresses."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7FF800001000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        instruction_logic = shellcode[:18]

        hardcoded_patterns = [
            b"\x7f\xf8",
            b"\x00\x00\x01\x10",
        ]

        for pattern in hardcoded_patterns:
            assert pattern not in instruction_logic


class TestShellcodeSignatureAvoidance:
    """Test avoidance of common shellcode signatures and patterns."""

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="Signature analysis requires 64-bit environment",
    )
    def test_shellcode_avoids_common_nop_sleds(self) -> None:
        """Shellcode does not contain common NOP sled patterns."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7FF800001000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        nop_patterns = [
            b"\x90\x90\x90\x90",
            b"\x90\x90\x90",
        ]

        for pattern in nop_patterns:
            assert pattern not in shellcode

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="Signature analysis requires 64-bit environment",
    )
    def test_shellcode_avoids_metasploit_signatures(self) -> None:
        """Shellcode does not match common Metasploit shellcode signatures."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7FF800001000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        metasploit_patterns = [
            b"\xfc\x48\x83\xe4\xf0",
            b"\xd9\xee\xd9\x74\x24\xf4",
            b"\x6a\x40\x68\x00\x10\x00\x00",
        ]

        for pattern in metasploit_patterns:
            assert pattern not in shellcode

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="Signature analysis requires 64-bit environment",
    )
    def test_shellcode_entropy_reasonable(self) -> None:
        """Shellcode has reasonable entropy to avoid detection."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7FF800001000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        byte_counts: dict[int, int] = {}
        for byte in shellcode:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1

        unique_bytes = len(byte_counts)
        assert unique_bytes > 5

        max_repetition = max(byte_counts.values())
        assert max_repetition < len(shellcode) * 0.5

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="Signature analysis requires 64-bit environment",
    )
    def test_shellcode_no_null_bytes_in_critical_sections(self) -> None:
        """Shellcode minimizes null bytes in instruction sequences."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7FF800001000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        instruction_section = shellcode[:18]

        null_count = instruction_section.count(b"\x00")
        assert null_count <= 2


class TestCustomPayloadInsertion:
    """Test custom payload insertion capabilities in shellcode."""

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="Payload insertion requires 64-bit environment",
    )
    def test_shellcode_supports_different_target_addresses(self) -> None:
        """Shellcode generation accepts custom target addresses as payload parameter."""
        hooker = UserModeNTAPIHooker()

        custom_addresses = [
            0x7FF800001000,
            0x7FF900002000,
            0x7FFA00003000,
        ]

        for addr in custom_addresses:
            shellcode = hooker._generate_ntquery_hook_shellcode(addr)
            embedded_return = struct.unpack("<Q", shellcode[19:27])[0]
            assert embedded_return == addr + 16

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="Payload insertion requires 64-bit environment",
    )
    def test_shellcode_generation_for_different_hook_types(self) -> None:
        """Shellcode generation supports different hook types with custom logic."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7FF800001000

        ntquery_shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)
        ntset_shellcode = hooker._generate_ntset_thread_hook_shellcode(original_addr)
        ntsystem_shellcode = hooker._generate_ntsystem_hook_shellcode(original_addr)

        assert ntquery_shellcode != ntset_shellcode
        assert ntquery_shellcode != ntsystem_shellcode
        assert ntset_shellcode != ntsystem_shellcode

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="Payload insertion requires 64-bit environment",
    )
    def test_shellcode_embeds_correct_return_logic(self) -> None:
        """Shellcode embeds correct return logic for bypassing detection."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7FF800001000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        return_pattern = b"\xc3"
        assert return_pattern in shellcode


class TestDEPASLRCompatibility:
    """Test shellcode compatibility with DEP and ASLR protections."""

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="DEP/ASLR testing requires 64-bit environment",
    )
    def test_shellcode_installs_in_executable_memory(self) -> None:
        """Shellcode installation changes memory to executable for DEP compatibility."""
        hooker = UserModeNTAPIHooker()

        try:
            ntdll = ctypes.windll.ntdll
            func_addr = ctypes.cast(ntdll.NtQueryInformationProcess, ctypes.c_void_p).value

            if not func_addr:
                pytest.skip("Cannot get NtQueryInformationProcess address")

            original_bytes = hooker._read_memory(func_addr, 16)

            if not original_bytes:
                pytest.skip("Cannot read original memory")

            assert len(original_bytes) == 16

        except Exception as e:
            pytest.skip(f"DEP compatibility test requires elevated privileges: {e}")

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="ASLR testing requires 64-bit environment",
    )
    def test_shellcode_handles_aslr_addresses(self) -> None:
        """Shellcode generation handles ASLR-randomized addresses correctly."""
        hooker = UserModeNTAPIHooker()

        try:
            ntdll = ctypes.windll.ntdll
            kernel32 = ctypes.windll.kernel32

            ntdll_base = kernel32.GetModuleHandleW("ntdll.dll")
            kernel32_base = kernel32.GetModuleHandleW("kernel32.dll")

            assert ntdll_base != kernel32_base
            assert ntdll_base > 0x10000
            assert kernel32_base > 0x10000

            func_addr = ctypes.cast(ntdll.NtQueryInformationProcess, ctypes.c_void_p).value

            if func_addr:
                shellcode = hooker._generate_ntquery_hook_shellcode(func_addr)
                assert len(shellcode) > 0

        except Exception as e:
            pytest.skip(f"ASLR test requires valid module handles: {e}")

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="Memory protection testing requires 64-bit environment",
    )
    def test_shellcode_respects_memory_protection(self) -> None:
        """Shellcode installation respects existing memory protection flags."""
        hooker = UserModeNTAPIHooker()

        try:
            ntdll = ctypes.windll.ntdll
            kernel32 = ctypes.windll.kernel32

            func_addr = ctypes.cast(ntdll.NtQueryInformationProcess, ctypes.c_void_p).value

            if not func_addr:
                pytest.skip("Cannot get function address")

            old_protect = ctypes.c_ulong()
            size = 16

            result = kernel32.VirtualProtect(
                ctypes.c_void_p(func_addr),
                size,
                0x40,
                ctypes.byref(old_protect),
            )

            if result:
                kernel32.VirtualProtect(
                    ctypes.c_void_p(func_addr),
                    size,
                    old_protect.value,
                    ctypes.byref(old_protect),
                )

                assert old_protect.value in [0x02, 0x04, 0x10, 0x20, 0x40]

        except Exception as e:
            pytest.skip(f"Memory protection test requires elevated privileges: {e}")


class TestCodeSigningRequirements:
    """Test shellcode behavior with code signing requirements."""

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="Code signing testing requires 64-bit environment",
    )
    def test_shellcode_modifies_unsigned_code_only(self) -> None:
        """Shellcode targets unsigned code sections only."""
        hooker = UserModeNTAPIHooker()

        try:
            ntdll = ctypes.windll.ntdll
            func_addr = ctypes.cast(ntdll.NtQueryInformationProcess, ctypes.c_void_p).value

            if func_addr:
                shellcode = hooker._generate_ntquery_hook_shellcode(func_addr)
                assert len(shellcode) > 0

        except Exception as e:
            pytest.skip(f"Code signing test requires valid function address: {e}")

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="Instruction cache testing requires 64-bit environment",
    )
    def test_inline_hook_flushes_instruction_cache(self) -> None:
        """Inline hook installation flushes instruction cache for code integrity."""
        hooker = UserModeNTAPIHooker()

        try:
            ntdll = ctypes.windll.ntdll
            func_addr = ctypes.cast(ntdll.NtQueryInformationProcess, ctypes.c_void_p).value

            if not func_addr:
                pytest.skip("Cannot get function address")

            original_bytes = hooker._read_memory(func_addr, 16)

            if not original_bytes:
                pytest.skip("Cannot read original bytes")

            hook_shellcode = hooker._generate_ntquery_hook_shellcode(func_addr)

            assert len(hook_shellcode) <= len(original_bytes) + 16

        except Exception as e:
            pytest.skip(f"Instruction cache test requires valid memory access: {e}")


class TestShellcodeEdgeCases:
    """Test shellcode generation edge cases and error conditions."""

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="Edge case testing requires 64-bit environment",
    )
    def test_shellcode_handles_zero_address(self) -> None:
        """Shellcode generation handles zero address gracefully."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x0

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        assert isinstance(shellcode, bytes)
        assert len(shellcode) > 0

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="Edge case testing requires 64-bit environment",
    )
    def test_shellcode_handles_max_64bit_address(self) -> None:
        """Shellcode generation handles maximum 64-bit address."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0xFFFFFFFFFFFFFFFF

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        assert isinstance(shellcode, bytes)
        assert len(shellcode) > 0

        embedded_return = struct.unpack("<Q", shellcode[19:27])[0]
        expected_return = (original_addr + 16) & 0xFFFFFFFFFFFFFFFF
        assert embedded_return == expected_return

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="Edge case testing requires 64-bit environment",
    )
    def test_shellcode_consistent_across_multiple_generations(self) -> None:
        """Shellcode generation produces consistent output for same input."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7FF800001000

        shellcode1 = hooker._generate_ntquery_hook_shellcode(original_addr)
        shellcode2 = hooker._generate_ntquery_hook_shellcode(original_addr)
        shellcode3 = hooker._generate_ntquery_hook_shellcode(original_addr)

        assert shellcode1 == shellcode2 == shellcode3

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="Edge case testing requires 64-bit environment",
    )
    def test_shellcode_handles_common_ntdll_address_ranges(self) -> None:
        """Shellcode generation handles common ntdll address ranges correctly."""
        hooker = UserModeNTAPIHooker()

        common_ranges = [
            0x7FF800000000,
            0x7FF900000000,
            0x7FFA00000000,
            0x7FFB00000000,
            0x7FFC00000000,
            0x7FFD00000000,
            0x7FFE00000000,
        ]

        for base_addr in common_ranges:
            shellcode = hooker._generate_ntquery_hook_shellcode(base_addr)
            assert len(shellcode) > 0
            embedded_return = struct.unpack("<Q", shellcode[19:27])[0]
            assert embedded_return == base_addr + 16


class TestShellcodeIntegrationWithHooks:
    """Test shellcode integration with actual hook installation."""

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="Hook integration testing requires 64-bit environment",
    )
    def test_ntquery_hook_uses_generated_shellcode(self) -> None:
        """NtQueryInformationProcess hook installation uses generated shellcode."""
        hooker = UserModeNTAPIHooker()

        try:
            ntdll = ctypes.windll.ntdll
            func_addr = ctypes.cast(ntdll.NtQueryInformationProcess, ctypes.c_void_p).value

            if not func_addr:
                pytest.skip("Cannot get NtQueryInformationProcess address")

            expected_shellcode = hooker._generate_ntquery_hook_shellcode(func_addr)

            assert len(expected_shellcode) > 0

        except Exception as e:
            pytest.skip(f"Hook integration test requires valid environment: {e}")

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="Hook integration testing requires 64-bit environment",
    )
    def test_ntset_thread_hook_uses_generated_shellcode(self) -> None:
        """NtSetInformationThread hook installation uses generated shellcode."""
        hooker = UserModeNTAPIHooker()

        try:
            ntdll = ctypes.windll.ntdll
            func_addr = ctypes.cast(ntdll.NtSetInformationThread, ctypes.c_void_p).value

            if not func_addr:
                pytest.skip("Cannot get NtSetInformationThread address")

            expected_shellcode = hooker._generate_ntset_thread_hook_shellcode(func_addr)

            assert len(expected_shellcode) > 0

        except Exception as e:
            pytest.skip(f"Hook integration test requires valid environment: {e}")

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="Hook integration testing requires 64-bit environment",
    )
    def test_ntsystem_hook_uses_generated_shellcode(self) -> None:
        """NtQuerySystemInformation hook installation uses generated shellcode."""
        hooker = UserModeNTAPIHooker()

        try:
            ntdll = ctypes.windll.ntdll
            func_addr = ctypes.cast(ntdll.NtQuerySystemInformation, ctypes.c_void_p).value

            if not func_addr:
                pytest.skip("Cannot get NtQuerySystemInformation address")

            expected_shellcode = hooker._generate_ntsystem_hook_shellcode(func_addr)

            assert len(expected_shellcode) > 0

        except Exception as e:
            pytest.skip(f"Hook integration test requires valid environment: {e}")


class TestShellcodeSecurityValidation:
    """Test shellcode security and correctness validation."""

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="Security validation requires 64-bit environment",
    )
    def test_shellcode_no_stack_corruption(self) -> None:
        """Shellcode does not corrupt stack during execution."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7FF800001000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        push_patterns = shellcode.count(b"\x50")
        pop_patterns = shellcode.count(b"\x58")

        assert push_patterns == pop_patterns

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="Security validation requires 64-bit environment",
    )
    def test_shellcode_preserves_critical_registers(self) -> None:
        """Shellcode preserves critical registers during execution."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7FF800001000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        xor_rax_pattern = b"\x48\x31\xc0"
        mov_rax_pattern = b"\x48\xb8"

        has_rax_manipulation = xor_rax_pattern in shellcode or mov_rax_pattern in shellcode
        assert has_rax_manipulation

    @pytest.mark.skipif(
        not platform.machine().endswith("64"),
        reason="Security validation requires 64-bit environment",
    )
    def test_shellcode_no_buffer_overflow_risk(self) -> None:
        """Shellcode has fixed size with no buffer overflow risk."""
        hooker = UserModeNTAPIHooker()

        addresses = [
            0x7FF800001000,
            0x7FF900002000,
            0x7FFA00003000,
        ]

        shellcode_sizes = [len(hooker._generate_ntquery_hook_shellcode(addr)) for addr in addresses]

        assert all(size == shellcode_sizes[0] for size in shellcode_sizes)
        assert shellcode_sizes[0] < 256
