"""Production tests for Keystone Assembler Handler.

Tests REAL assembly encoding capabilities:
- Multi-architecture assembly (x86, x86-64, ARM, ARM64)
- Instruction encoding validation
- Mode switching (32-bit, 64-bit, Thumb)
- Error handling for invalid instructions
- Performance benchmarks for batch assembly

All tests validate genuine Keystone functionality.
"""

import pytest

try:
    from intellicrack.handlers.keystone_handler import (
        KEYSTONE_AVAILABLE,
        KS_ARCH_ARM,
        KS_ARCH_ARM64,
        KS_ARCH_X86,
        KS_MODE_32,
        KS_MODE_64,
        KS_MODE_ARM,
        KS_MODE_THUMB,
        Ks,
    )
    KEYSTONE_HANDLER_AVAILABLE = True
except ImportError:
    KEYSTONE_AVAILABLE = False
    KS_ARCH_ARM = None
    KS_ARCH_ARM64 = None
    KS_ARCH_X86 = None
    KS_MODE_32 = None
    KS_MODE_64 = None
    KS_MODE_ARM = None
    KS_MODE_THUMB = None
    Ks = None
    KEYSTONE_HANDLER_AVAILABLE = False


pytestmark = pytest.mark.skipif(
    not KEYSTONE_HANDLER_AVAILABLE or not KEYSTONE_AVAILABLE,
    reason="Keystone handler not available"
)


class TestKeystoneAvailability:
    """Test Keystone module availability."""

    def test_keystone_imported_successfully(self) -> None:
        """Keystone module imports without errors."""
        assert KEYSTONE_AVAILABLE is True
        assert Ks is not None

    def test_architecture_constants_defined(self) -> None:
        """All architecture constants are properly defined."""
        assert KS_ARCH_X86 is not None
        assert KS_ARCH_ARM is not None
        assert KS_ARCH_ARM64 is not None

    def test_mode_constants_defined(self) -> None:
        """All mode constants are properly defined."""
        assert KS_MODE_32 is not None
        assert KS_MODE_64 is not None
        assert KS_MODE_ARM is not None
        assert KS_MODE_THUMB is not None


class TestX86Assembly:
    """Test x86 32-bit assembly encoding."""

    def test_assembles_simple_mov_instruction(self) -> None:
        """Keystone assembles simple MOV instruction correctly."""
        ks = Ks(KS_ARCH_X86, KS_MODE_32)

        encoding, count = ks.asm("mov eax, 0x12345678")

        assert encoding is not None
        assert count == 1
        assert isinstance(encoding, (list, bytes))
        assert bytes(encoding) == b"\xb8\x78\x56\x34\x12"

    def test_assembles_add_instruction(self) -> None:
        """Keystone assembles ADD instruction with correct encoding."""
        ks = Ks(KS_ARCH_X86, KS_MODE_32)

        encoding, count = ks.asm("add eax, ebx")

        assert encoding is not None
        assert count == 1
        assert bytes(encoding) == b"\x01\xd8"

    def test_assembles_conditional_jump(self) -> None:
        """Keystone assembles conditional jump instructions."""
        ks = Ks(KS_ARCH_X86, KS_MODE_32)

        encoding, count = ks.asm("je 0x10")

        assert encoding is not None
        assert count == 1
        assert isinstance(bytes(encoding), bytes)

    def test_assembles_call_instruction(self) -> None:
        """Keystone assembles CALL instruction."""
        ks = Ks(KS_ARCH_X86, KS_MODE_32)

        encoding, count = ks.asm("call 0x1000")

        assert encoding is not None
        assert count == 1
        assert bytes(encoding)[0] == 0xe8

    def test_assembles_push_pop(self) -> None:
        """Keystone assembles PUSH/POP instructions."""
        ks = Ks(KS_ARCH_X86, KS_MODE_32)

        push_enc, push_count = ks.asm("push eax")
        pop_enc, pop_count = ks.asm("pop ebx")

        assert bytes(push_enc) == b"\x50"
        assert bytes(pop_enc) == b"\x5b"

    def test_assembles_nop_instruction(self) -> None:
        """Keystone assembles NOP instruction."""
        ks = Ks(KS_ARCH_X86, KS_MODE_32)

        encoding, count = ks.asm("nop")

        assert encoding is not None
        assert count == 1
        assert bytes(encoding) == b"\x90"

    def test_assembles_ret_instruction(self) -> None:
        """Keystone assembles RET instruction."""
        ks = Ks(KS_ARCH_X86, KS_MODE_32)

        encoding, count = ks.asm("ret")

        assert encoding is not None
        assert count == 1
        assert bytes(encoding) == b"\xc3"

    def test_assembles_multiple_instructions(self) -> None:
        """Keystone assembles multiple instructions in sequence."""
        ks = Ks(KS_ARCH_X86, KS_MODE_32)

        code = """
        push ebp
        mov ebp, esp
        sub esp, 0x10
        mov eax, 0
        leave
        ret
        """

        encoding, count = ks.asm(code)

        assert encoding is not None
        assert count == 6
        assert len(bytes(encoding)) > 6


class TestX64Assembly:
    """Test x86-64 assembly encoding."""

    def test_assembles_x64_mov_instruction(self) -> None:
        """Keystone assembles x64 MOV with REX prefix."""
        ks = Ks(KS_ARCH_X86, KS_MODE_64)

        encoding, count = ks.asm("mov rax, 0x1234567890ABCDEF")

        assert encoding is not None
        assert count == 1
        assert bytes(encoding)[0] == 0x48

    def test_assembles_x64_add_instruction(self) -> None:
        """Keystone assembles x64 ADD instruction."""
        ks = Ks(KS_ARCH_X86, KS_MODE_64)

        encoding, count = ks.asm("add rax, rbx")

        assert encoding is not None
        assert count == 1
        assert bytes(encoding) == b"\x48\x01\xd8"

    def test_assembles_x64_syscall(self) -> None:
        """Keystone assembles SYSCALL instruction."""
        ks = Ks(KS_ARCH_X86, KS_MODE_64)

        encoding, count = ks.asm("syscall")

        assert encoding is not None
        assert count == 1
        assert bytes(encoding) == b"\x0f\x05"

    def test_assembles_x64_extended_registers(self) -> None:
        """Keystone assembles instructions using R8-R15."""
        ks = Ks(KS_ARCH_X86, KS_MODE_64)

        encoding, count = ks.asm("mov r8, r9")

        assert encoding is not None
        assert count == 1
        assert isinstance(bytes(encoding), bytes)

    def test_assembles_x64_memory_operations(self) -> None:
        """Keystone assembles memory access instructions."""
        ks = Ks(KS_ARCH_X86, KS_MODE_64)

        encoding, count = ks.asm("mov qword ptr [rax], rbx")

        assert encoding is not None
        assert count == 1


class TestARMAssembly:
    """Test ARM 32-bit assembly encoding."""

    def test_assembles_arm_mov_instruction(self) -> None:
        """Keystone assembles ARM MOV instruction."""
        ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)

        encoding, count = ks.asm("mov r0, #42")

        assert encoding is not None
        assert count == 1
        assert isinstance(bytes(encoding), bytes)
        assert len(bytes(encoding)) == 4

    def test_assembles_arm_add_instruction(self) -> None:
        """Keystone assembles ARM ADD instruction."""
        ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)

        encoding, count = ks.asm("add r0, r1, r2")

        assert encoding is not None
        assert count == 1
        assert len(bytes(encoding)) == 4

    def test_assembles_arm_branch(self) -> None:
        """Keystone assembles ARM branch instruction."""
        ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)

        encoding, count = ks.asm("b #0x100")

        assert encoding is not None
        assert count == 1
        assert len(bytes(encoding)) == 4

    def test_assembles_arm_load_store(self) -> None:
        """Keystone assembles ARM load/store instructions."""
        ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)

        ldr_enc, ldr_count = ks.asm("ldr r0, [r1]")
        str_enc, str_count = ks.asm("str r0, [r1]")

        assert ldr_enc is not None
        assert str_enc is not None
        assert len(bytes(ldr_enc)) == 4
        assert len(bytes(str_enc)) == 4


class TestARMThumbMode:
    """Test ARM Thumb mode assembly."""

    def test_assembles_thumb_mov(self) -> None:
        """Keystone assembles Thumb MOV instruction."""
        ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)

        encoding, count = ks.asm("mov r0, #42")

        assert encoding is not None
        assert count == 1
        assert isinstance(bytes(encoding), bytes)
        assert len(bytes(encoding)) == 2

    def test_assembles_thumb_add(self) -> None:
        """Keystone assembles Thumb ADD instruction."""
        ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)

        encoding, count = ks.asm("add r0, r1, r2")

        assert encoding is not None
        assert count == 1

    def test_thumb_produces_compact_code(self) -> None:
        """Thumb mode produces more compact code than ARM mode."""
        ks_arm = Ks(KS_ARCH_ARM, KS_MODE_ARM)
        ks_thumb = Ks(KS_ARCH_ARM, KS_MODE_THUMB)

        arm_enc, _ = ks_arm.asm("mov r0, #10")
        thumb_enc, _ = ks_thumb.asm("mov r0, #10")

        assert len(bytes(arm_enc)) == 4
        assert len(bytes(thumb_enc)) == 2


class TestARM64Assembly:
    """Test ARM64/AArch64 assembly encoding."""

    def test_assembles_arm64_mov(self) -> None:
        """Keystone assembles ARM64 MOV instruction."""
        ks = Ks(KS_ARCH_ARM64, KS_MODE_ARM)

        encoding, count = ks.asm("mov x0, #42")

        assert encoding is not None
        assert count == 1
        assert len(bytes(encoding)) == 4

    def test_assembles_arm64_add(self) -> None:
        """Keystone assembles ARM64 ADD instruction."""
        ks = Ks(KS_ARCH_ARM64, KS_MODE_ARM)

        encoding, count = ks.asm("add x0, x1, x2")

        assert encoding is not None
        assert count == 1
        assert len(bytes(encoding)) == 4

    def test_assembles_arm64_branch(self) -> None:
        """Keystone assembles ARM64 branch instruction."""
        ks = Ks(KS_ARCH_ARM64, KS_MODE_ARM)

        encoding, count = ks.asm("b #0x100")

        assert encoding is not None
        assert count == 1
        assert len(bytes(encoding)) == 4

    def test_assembles_arm64_load_store(self) -> None:
        """Keystone assembles ARM64 load/store."""
        ks = Ks(KS_ARCH_ARM64, KS_MODE_ARM)

        ldr_enc, ldr_count = ks.asm("ldr x0, [x1]")
        str_enc, str_count = ks.asm("str x0, [x1]")

        assert ldr_enc is not None
        assert str_enc is not None


class TestErrorHandling:
    """Test error handling for invalid assembly."""

    def test_raises_on_invalid_syntax(self) -> None:
        """Keystone raises error for invalid syntax."""
        ks = Ks(KS_ARCH_X86, KS_MODE_32)

        with pytest.raises(Exception):
            ks.asm("invalid_instruction_xyz")

    def test_raises_on_invalid_register(self) -> None:
        """Keystone raises error for invalid register names."""
        ks = Ks(KS_ARCH_X86, KS_MODE_32)

        with pytest.raises(Exception):
            ks.asm("mov invalid_reg, eax")

    def test_handles_empty_input(self) -> None:
        """Keystone handles empty assembly input."""
        ks = Ks(KS_ARCH_X86, KS_MODE_32)

        encoding, count = ks.asm("")

        assert count == 0


class TestComplexAssembly:
    """Test complex assembly scenarios."""

    def test_assembles_function_prologue(self) -> None:
        """Keystone assembles standard function prologue."""
        ks = Ks(KS_ARCH_X86, KS_MODE_64)

        code = """
        push rbp
        mov rbp, rsp
        sub rsp, 0x20
        """

        encoding, count = ks.asm(code)

        assert encoding is not None
        assert count == 3

    def test_assembles_function_epilogue(self) -> None:
        """Keystone assembles standard function epilogue."""
        ks = Ks(KS_ARCH_X86, KS_MODE_64)

        code = """
        leave
        ret
        """

        encoding, count = ks.asm(code)

        assert encoding is not None
        assert count == 2

    def test_assembles_loop_structure(self) -> None:
        """Keystone assembles loop with conditional jump."""
        ks = Ks(KS_ARCH_X86, KS_MODE_32)

        code = """
        mov ecx, 10
        loop_start:
        dec ecx
        jnz loop_start
        """

        encoding, count = ks.asm(code)

        assert encoding is not None
        assert count >= 2

    def test_assembles_shellcode(self) -> None:
        """Keystone assembles shellcode payload."""
        ks = Ks(KS_ARCH_X86, KS_MODE_64)

        code = """
        xor rax, rax
        xor rdi, rdi
        xor rsi, rsi
        mov al, 60
        syscall
        """

        encoding, count = ks.asm(code)

        assert encoding is not None
        assert count == 5
        assert bytes(encoding)


class TestPatchGeneration:
    """Test patch generation for binary patching."""

    def test_generates_nop_sled(self) -> None:
        """Keystone generates NOP sled for patching."""
        ks = Ks(KS_ARCH_X86, KS_MODE_32)

        nops = []
        for _ in range(10):
            enc, _ = ks.asm("nop")
            nops.append(bytes(enc))

        nop_sled = b"".join(nops)

        assert len(nop_sled) == 10
        assert all(b == 0x90 for b in nop_sled)

    def test_generates_unconditional_jump(self) -> None:
        """Keystone generates unconditional jump for redirection."""
        ks = Ks(KS_ARCH_X86, KS_MODE_32)

        encoding, count = ks.asm("jmp 0x1000")

        assert encoding is not None
        assert bytes(encoding)[0] == 0xe9

    def test_inverts_conditional_jump(self) -> None:
        """Keystone generates inverted conditional jump."""
        ks = Ks(KS_ARCH_X86, KS_MODE_32)

        je_enc, _ = ks.asm("je 0x10")
        jne_enc, _ = ks.asm("jne 0x10")

        assert bytes(je_enc) != bytes(jne_enc)
        assert bytes(je_enc)[0] == 0x74
        assert bytes(jne_enc)[0] == 0x75

    def test_generates_return_value_patch(self) -> None:
        """Keystone generates return value modification patch."""
        ks = Ks(KS_ARCH_X86, KS_MODE_32)

        code = """
        mov eax, 1
        ret
        """

        encoding, count = ks.asm(code)

        assert encoding is not None
        assert count == 2


class TestPerformance:
    """Test assembly performance."""

    def test_batch_assembly_performance(self) -> None:
        """Keystone handles batch assembly efficiently."""
        import time

        ks = Ks(KS_ARCH_X86, KS_MODE_64)

        instructions = [
            "mov rax, rbx",
            "add rax, 1",
            "sub rbx, 2",
            "xor rcx, rcx",
            "push rax",
            "pop rbx",
        ] * 100

        start = time.time()
        for inst in instructions:
            ks.asm(inst)
        duration = time.time() - start

        assert duration < 2.0

    def test_large_code_assembly(self) -> None:
        """Keystone assembles large code blocks efficiently."""
        import time

        ks = Ks(KS_ARCH_X86, KS_MODE_32)

        code = "\n".join(["nop"] * 1000)

        start = time.time()
        encoding, count = ks.asm(code)
        duration = time.time() - start

        assert encoding is not None
        assert count == 1000
        assert duration < 1.0


class TestArchitectureSwitch:
    """Test switching between architectures."""

    def test_switches_from_x86_to_arm(self) -> None:
        """Keystone switches between x86 and ARM."""
        ks_x86 = Ks(KS_ARCH_X86, KS_MODE_32)
        ks_arm = Ks(KS_ARCH_ARM, KS_MODE_ARM)

        x86_enc, _ = ks_x86.asm("mov eax, 0")
        arm_enc, _ = ks_arm.asm("mov r0, #0")

        assert bytes(x86_enc) != bytes(arm_enc)

    def test_switches_between_modes(self) -> None:
        """Keystone switches between 32-bit and 64-bit modes."""
        ks_32 = Ks(KS_ARCH_X86, KS_MODE_32)
        ks_64 = Ks(KS_ARCH_X86, KS_MODE_64)

        enc_32, _ = ks_32.asm("mov eax, 0")
        enc_64, _ = ks_64.asm("mov rax, 0")

        assert len(bytes(enc_32)) != len(bytes(enc_64))
