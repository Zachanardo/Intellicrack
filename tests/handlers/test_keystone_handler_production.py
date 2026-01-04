"""Production tests for Keystone assembler handler.

Validates that Keystone integration works correctly for assembling x86/ARM
instructions used in binary patching and protection bypass operations.
"""

import pytest

from intellicrack.handlers import keystone_handler


class TestKeystoneAvailability:
    """Tests for Keystone availability detection."""

    def test_availability_flag_is_boolean(self) -> None:
        """Keystone availability flag must be a boolean value."""
        assert isinstance(keystone_handler.KEYSTONE_AVAILABLE, bool)

    def test_architecture_constants_exist(self) -> None:
        """Architecture constants must be defined regardless of availability."""
        assert hasattr(keystone_handler, "KS_ARCH_X86")
        assert hasattr(keystone_handler, "KS_ARCH_ARM")
        assert hasattr(keystone_handler, "KS_ARCH_ARM64")

    def test_mode_constants_exist(self) -> None:
        """Mode constants must be defined regardless of availability."""
        assert hasattr(keystone_handler, "KS_MODE_32")
        assert hasattr(keystone_handler, "KS_MODE_64")
        assert hasattr(keystone_handler, "KS_MODE_ARM")
        assert hasattr(keystone_handler, "KS_MODE_THUMB")

    def test_assembler_class_exists(self) -> None:
        """Ks assembler class must be defined."""
        assert hasattr(keystone_handler, "Ks")


@pytest.mark.skipif(
    not keystone_handler.KEYSTONE_AVAILABLE,
    reason="Keystone not available in environment"
)
class TestKeystoneAssemblerFunctionality:
    """Tests for actual Keystone assembly operations."""

    def test_assemble_x86_32bit_nop(self) -> None:
        """Assembler produces correct x86 32-bit NOP instruction."""
        ks = keystone_handler.Ks(  # type: ignore[misc]
            keystone_handler.KS_ARCH_X86,
            keystone_handler.KS_MODE_32
        )
        encoding, count = ks.asm("nop")

        assert encoding is not None
        assert len(encoding) == 1
        assert encoding[0] == 0x90
        assert count == 1

    def test_assemble_x86_64bit_nop(self) -> None:
        """Assembler produces correct x86 64-bit NOP instruction."""
        ks = keystone_handler.Ks(  # type: ignore[misc]
            keystone_handler.KS_ARCH_X86,
            keystone_handler.KS_MODE_64
        )
        encoding, count = ks.asm("nop")

        assert encoding is not None
        assert len(encoding) == 1
        assert encoding[0] == 0x90
        assert count == 1

    def test_assemble_x86_32bit_ret(self) -> None:
        """Assembler produces correct x86 32-bit RET instruction."""
        ks = keystone_handler.Ks(  # type: ignore[misc]
            keystone_handler.KS_ARCH_X86,
            keystone_handler.KS_MODE_32
        )
        encoding, count = ks.asm("ret")

        assert encoding is not None
        assert len(encoding) == 1
        assert encoding[0] == 0xC3
        assert count == 1

    def test_assemble_x86_32bit_mov_immediate(self) -> None:
        """Assembler produces correct x86 32-bit MOV with immediate value."""
        ks = keystone_handler.Ks(  # type: ignore[misc]
            keystone_handler.KS_ARCH_X86,
            keystone_handler.KS_MODE_32
        )
        encoding, count = ks.asm("mov eax, 1")

        assert encoding is not None
        assert len(encoding) == 5
        assert encoding[0] == 0xB8
        assert encoding[1:5] == [0x01, 0x00, 0x00, 0x00]
        assert count == 1

    def test_assemble_x86_64bit_mov_immediate(self) -> None:
        """Assembler produces correct x86 64-bit MOV with immediate value."""
        ks = keystone_handler.Ks(  # type: ignore[misc]
            keystone_handler.KS_ARCH_X86,
            keystone_handler.KS_MODE_64
        )
        encoding, count = ks.asm("mov rax, 1")

        assert encoding is not None
        assert len(encoding) == 7
        assert encoding[0] == 0x48
        assert encoding[1] == 0xC7
        assert encoding[2] == 0xC0
        assert count == 1

    def test_assemble_x86_32bit_jmp_relative(self) -> None:
        """Assembler produces correct x86 32-bit relative JMP."""
        ks = keystone_handler.Ks(  # type: ignore[misc]
            keystone_handler.KS_ARCH_X86,
            keystone_handler.KS_MODE_32
        )
        encoding, count = ks.asm("jmp 0x10")

        assert encoding is not None
        assert len(encoding) == 2
        assert encoding[0] == 0xEB
        assert count == 1

    def test_assemble_x86_32bit_call(self) -> None:
        """Assembler produces correct x86 32-bit CALL instruction."""
        ks = keystone_handler.Ks(  # type: ignore[misc]
            keystone_handler.KS_ARCH_X86,
            keystone_handler.KS_MODE_32
        )
        encoding, count = ks.asm("call 0x400000")

        assert encoding is not None
        assert len(encoding) > 0
        assert encoding[0] == 0xE8
        assert count == 1

    def test_assemble_x86_32bit_push_pop(self) -> None:
        """Assembler produces correct x86 32-bit PUSH/POP sequence."""
        ks = keystone_handler.Ks(  # type: ignore[misc]
            keystone_handler.KS_ARCH_X86,
            keystone_handler.KS_MODE_32
        )
        encoding, count = ks.asm("push eax; pop ebx")

        assert encoding is not None
        assert len(encoding) == 2
        assert encoding[0] == 0x50
        assert encoding[1] == 0x5B
        assert count == 2

    def test_assemble_x86_32bit_xor_register(self) -> None:
        """Assembler produces correct x86 32-bit XOR for zeroing register."""
        ks = keystone_handler.Ks(  # type: ignore[misc]
            keystone_handler.KS_ARCH_X86,
            keystone_handler.KS_MODE_32
        )
        encoding, count = ks.asm("xor eax, eax")

        assert encoding is not None
        assert len(encoding) == 2
        assert encoding[0] == 0x31
        assert encoding[1] == 0xC0
        assert count == 1

    def test_assemble_arm_nop(self) -> None:
        """Assembler produces correct ARM NOP instruction."""
        ks = keystone_handler.Ks(  # type: ignore[misc]
            keystone_handler.KS_ARCH_ARM,
            keystone_handler.KS_MODE_ARM
        )
        encoding, count = ks.asm("nop")

        assert encoding is not None
        assert len(encoding) == 4
        assert count == 1

    def test_assemble_arm64_nop(self) -> None:
        """Assembler produces correct ARM64 NOP instruction."""
        ks = keystone_handler.Ks(  # type: ignore[misc]
            keystone_handler.KS_ARCH_ARM64,
            0
        )
        encoding, count = ks.asm("nop")

        assert encoding is not None
        assert len(encoding) == 4
        assert count == 1

    def test_assemble_arm_mov_immediate(self) -> None:
        """Assembler produces correct ARM MOV with immediate value."""
        ks = keystone_handler.Ks(  # type: ignore[misc]
            keystone_handler.KS_ARCH_ARM,
            keystone_handler.KS_MODE_ARM
        )
        encoding, count = ks.asm("mov r0, #1")

        assert encoding is not None
        assert len(encoding) == 4
        assert count == 1

    def test_assemble_thumb_nop(self) -> None:
        """Assembler produces correct Thumb mode NOP instruction."""
        ks = keystone_handler.Ks(  # type: ignore[misc]
            keystone_handler.KS_ARCH_ARM,
            keystone_handler.KS_MODE_THUMB
        )
        encoding, count = ks.asm("nop")

        assert encoding is not None
        assert len(encoding) == 2
        assert count == 1

    def test_assemble_multiple_x86_instructions(self) -> None:
        """Assembler produces correct multi-instruction sequence."""
        ks = keystone_handler.Ks(  # type: ignore[misc]
            keystone_handler.KS_ARCH_X86,
            keystone_handler.KS_MODE_32
        )
        encoding, count = ks.asm("push ebp; mov ebp, esp; pop ebp; ret")

        assert encoding is not None
        assert count == 4
        assert len(encoding) > 0

    def test_assemble_x86_conditional_jump(self) -> None:
        """Assembler produces correct x86 conditional jump."""
        ks = keystone_handler.Ks(  # type: ignore[misc]
            keystone_handler.KS_ARCH_X86,
            keystone_handler.KS_MODE_32
        )
        encoding, count = ks.asm("jz 0x10")

        assert encoding is not None
        assert len(encoding) > 0
        assert count == 1


@pytest.mark.skipif(
    not keystone_handler.KEYSTONE_AVAILABLE,
    reason="Keystone not available in environment"
)
class TestKeystoneAssemblerErrors:
    """Tests for error handling in assembly operations."""

    def test_assemble_invalid_instruction_raises_error(self) -> None:
        """Assembler raises error for invalid instruction syntax."""
        ks = keystone_handler.Ks(  # type: ignore[misc]
            keystone_handler.KS_ARCH_X86,
            keystone_handler.KS_MODE_32
        )

        with pytest.raises(Exception):
            ks.asm("invalid_instruction_xyz")

    def test_assemble_empty_string_returns_none(self) -> None:
        """Assembler returns None for empty instruction string."""
        ks = keystone_handler.Ks(  # type: ignore[misc]
            keystone_handler.KS_ARCH_X86,
            keystone_handler.KS_MODE_32
        )

        encoding, count = ks.asm("")
        assert encoding is None
        assert count == 0

    def test_assemble_invalid_register_raises_error(self) -> None:
        """Assembler raises error for invalid register name."""
        ks = keystone_handler.Ks(  # type: ignore[misc]
            keystone_handler.KS_ARCH_X86,
            keystone_handler.KS_MODE_32
        )

        with pytest.raises(Exception):
            ks.asm("mov eax, invalid_register")

    def test_assemble_arm_instruction_in_x86_mode_raises_error(self) -> None:
        """Assembler raises error when ARM instruction used in x86 mode."""
        ks = keystone_handler.Ks(  # type: ignore[misc]
            keystone_handler.KS_ARCH_X86,
            keystone_handler.KS_MODE_32
        )

        with pytest.raises(Exception):
            ks.asm("bx lr")


@pytest.mark.skipif(
    keystone_handler.KEYSTONE_AVAILABLE,
    reason="Test only relevant when Keystone unavailable"
)
class TestKeystoneFallbackBehavior:
    """Tests for fallback behavior when Keystone is not available."""

    def test_constants_are_none_when_unavailable(self) -> None:
        """All architecture/mode constants are None when Keystone unavailable."""
        assert keystone_handler.KS_ARCH_X86 is None
        assert keystone_handler.KS_ARCH_ARM is None
        assert keystone_handler.KS_ARCH_ARM64 is None
        assert keystone_handler.KS_MODE_32 is None
        assert keystone_handler.KS_MODE_64 is None
        assert keystone_handler.KS_MODE_ARM is None
        assert keystone_handler.KS_MODE_THUMB is None

    def test_assembler_class_is_none_when_unavailable(self) -> None:
        """Ks assembler class is None when Keystone unavailable."""
        assert keystone_handler.Ks is None


@pytest.mark.skipif(
    not keystone_handler.KEYSTONE_AVAILABLE,
    reason="Keystone not available in environment"
)
class TestKeystonePatching:
    """Tests for assembly operations used in binary patching scenarios."""

    def test_assemble_license_check_bypass_nop_sled(self) -> None:
        """Assembler produces NOP sled for license check bypass."""
        ks = keystone_handler.Ks(  # type: ignore[misc]
            keystone_handler.KS_ARCH_X86,
            keystone_handler.KS_MODE_32
        )
        encoding, count = ks.asm("nop; nop; nop; nop; nop")

        assert encoding is not None
        assert len(encoding) == 5
        assert all(byte == 0x90 for byte in encoding)
        assert count == 5

    def test_assemble_unconditional_jump_for_bypass(self) -> None:
        """Assembler produces unconditional jump for protection bypass."""
        ks = keystone_handler.Ks(  # type: ignore[misc]
            keystone_handler.KS_ARCH_X86,
            keystone_handler.KS_MODE_32
        )
        encoding, count = ks.asm("jmp 0x100")

        assert encoding is not None
        assert len(encoding) > 0
        assert encoding[0] == 0xE9
        assert count == 1

    def test_assemble_return_true_for_license_validation(self) -> None:
        """Assembler produces code sequence to force license validation success."""
        ks = keystone_handler.Ks(  # type: ignore[misc]
            keystone_handler.KS_ARCH_X86,
            keystone_handler.KS_MODE_32
        )
        encoding, count = ks.asm("mov eax, 1; ret")

        assert encoding is not None
        assert len(encoding) == 6
        assert encoding[0] == 0xB8
        assert encoding[5] == 0xC3
        assert count == 2

    def test_assemble_register_zeroing_for_flag_reset(self) -> None:
        """Assembler produces register zeroing for flag manipulation."""
        ks = keystone_handler.Ks(  # type: ignore[misc]
            keystone_handler.KS_ARCH_X86,
            keystone_handler.KS_MODE_64
        )
        encoding, count = ks.asm("xor rax, rax; ret")

        assert encoding is not None
        assert len(encoding) > 0
        assert count == 2
