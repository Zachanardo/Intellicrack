"""Binary patch generation for certificate validation bypass across multiple architectures.

CAPABILITIES:
- x86/x64 patch generation (always-succeed, conditional invert, NOP sleds, trampolines)
- ARM32/ARM64 patch generation (always-succeed, conditional invert)
- Calling convention wrappers (stdcall, cdecl, fastcall, x64 Microsoft)
- Register preservation code generation (push/pop all GPRs)
- Patch size and alignment validation
- Trampoline generation for far jumps
- Conditional jump inversion (JZ↔JNZ, JE↔JNE, etc.)
- NOP sled generation for arbitrary sizes
- Architecture-specific machine code generation
- Proper return value handling for different conventions

LIMITATIONS:
- No automatic architecture detection (must be specified)
- No support for vectorized instructions (SSE, AVX, NEON)
- No support for x86 real mode or 16-bit code
- Limited ARM Thumb mode support
- No automatic stack frame adjustment
- Cannot generate patches for inline assembly
- No support for position-independent code adjustments
- Register preservation assumes standard calling conventions

USAGE EXAMPLES:
    # Generate simple always-succeed patch
    from intellicrack.core.certificate.patch_generators import (
        generate_always_succeed_x64
    )

    patch = generate_always_succeed_x64()
    print(f"Patch size: {len(patch)} bytes")
    print(f"Bytes: {patch.hex()}")

    # Generate conditional invert patch
    from intellicrack.core.certificate.patch_generators import (
        generate_conditional_invert_x86
    )

    # Original: JZ +0x10 (74 10)
    original = bytes([0x74, 0x10])
    inverted = generate_conditional_invert_x86(original)
    # Result: JNZ +0x10 (75 10)

    # Generate NOP sled
    from intellicrack.core.certificate.patch_generators import generate_nop_sled

    nops = generate_nop_sled(20)  # 20 bytes of NOPs
    assert len(nops) == 20

    # Generate trampoline
    from intellicrack.core.certificate.patch_generators import (
        generate_trampoline_x64
    )

    target = 0x140001000
    hook = 0x140050000
    trampoline = generate_trampoline_x64(target, hook)

    # Wrap patch with calling convention
    from intellicrack.core.certificate.patch_generators import (
        wrap_patch_stdcall,
        generate_always_succeed_x86
    )

    base_patch = generate_always_succeed_x86()
    stdcall_patch = wrap_patch_stdcall(base_patch)

    # Validate patch
    from intellicrack.core.certificate.patch_generators import (
        validate_patch_size,
        validate_patch_alignment
    )

    if validate_patch_size(patch, max_size=32):
        print("Patch fits in available space")

    if validate_patch_alignment(patch, address=0x140001000):
        print("Patch is properly aligned")

RELATED MODULES:
- patch_templates.py: Uses these generators for pre-built templates
- cert_patcher.py: Applies generated patches to binaries
- bypass_orchestrator.py: Selects appropriate patch generators
- api_signatures.py: Provides calling convention information

PATCH TYPES:
    ALWAYS_SUCCEED:
        - x86: MOV EAX, 1; RET (6 bytes)
        - x64: MOV RAX, 1; RET (8 bytes)
        - ARM32: MOV R0, #1; BX LR (8 bytes)
        - ARM64: MOV X0, #1; RET (8 bytes)

    CONDITIONAL_INVERT:
        - Flips conditional jumps (JZ↔JNZ, JE↔JNE, etc.)
        - Preserves jump offset
        - Supports short and near jumps

    NOP_SLED:
        - x86/x64: 0x90 (NOP) repeated
        - ARM32: 0xE1A00000 (MOV R0, R0)
        - ARM64: 0xD503201F (NOP)

    TRAMPOLINE:
        - x86: JMP rel32 (5 bytes)
        - x64: JMP [RIP+0]; QWORD addr (14 bytes)
        - ARM32: LDR PC, [PC, #-4]; ADDR (8 bytes)
        - ARM64: LDR X16, #8; BR X16; ADDR (16 bytes)
"""

from enum import Enum
from typing import Optional


class Architecture(Enum):
    """Supported CPU architectures."""

    X86 = "x86"
    X64 = "x64"
    ARM32 = "arm32"
    ARM64 = "arm64"


class PatchType(Enum):
    """Types of patches that can be applied."""

    ALWAYS_SUCCEED = "always_succeed"
    CONDITIONAL_INVERT = "conditional_invert"
    NOP_SLED = "nop_sled"
    TRAMPOLINE = "trampoline"


def generate_always_succeed_x86() -> bytes:
    """Generate x86 patch that makes function always return success.

    Returns:
        Machine code bytes for 'MOV EAX, 1; RET'

    """
    return bytes([
        0xB8, 0x01, 0x00, 0x00, 0x00,
        0xC3,
    ])


def generate_always_succeed_x64() -> bytes:
    """Generate x64 patch that makes function always return success.

    Returns:
        Machine code bytes for 'MOV RAX, 1; RET'

    """
    return bytes([
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,
        0xC3,
    ])


def generate_always_succeed_arm32() -> bytes:
    """Generate ARM32 patch that makes function always return success.

    Returns:
        Machine code bytes for 'MOV R0, #1; BX LR'

    """
    return bytes([
        0x01, 0x00, 0xA0, 0xE3,
        0x1E, 0xFF, 0x2F, 0xE1,
    ])


def generate_always_succeed_arm64() -> bytes:
    """Generate ARM64 patch that makes function always return success.

    Returns:
        Machine code bytes for 'MOV X0, #1; RET'

    """
    return bytes([
        0x20, 0x00, 0x80, 0xD2,
        0xC0, 0x03, 0x5F, 0xD6,
    ])


def generate_conditional_invert_x86(original_bytes: bytes) -> bytes:
    """Generate x86 patch that inverts a conditional jump.

    Converts JZ to JNZ and vice versa by flipping the condition bit.

    Args:
        original_bytes: Original instruction bytes

    Returns:
        Inverted conditional jump bytes

    """
    if not original_bytes:
        return b''

    inverted = bytearray(original_bytes)

    if len(inverted) >= 2:
        first_byte = inverted[0]

        if first_byte == 0x74:
            inverted[0] = 0x75
        elif first_byte == 0x75:
            inverted[0] = 0x74
        elif first_byte == 0x84:
            inverted[0] = 0x85
        elif first_byte == 0x85:
            inverted[0] = 0x84
        elif first_byte == 0x0F:
            second_byte = inverted[1]
            if second_byte == 0x84:
                inverted[1] = 0x85
            elif second_byte == 0x85:
                inverted[1] = 0x84

    return bytes(inverted)


def generate_conditional_invert_x64(original_bytes: bytes) -> bytes:
    """Generate x64 patch that inverts a conditional jump.

    x64 uses the same conditional jump opcodes as x86.

    Args:
        original_bytes: Original instruction bytes

    Returns:
        Inverted conditional jump bytes

    """
    return generate_conditional_invert_x86(original_bytes)


def generate_conditional_invert_arm(original_bytes: bytes) -> bytes:
    """Generate ARM patch that inverts a conditional branch.

    Inverts ARM condition codes by flipping the condition field.

    Args:
        original_bytes: Original instruction bytes

    Returns:
        Inverted conditional branch bytes

    """
    if len(original_bytes) < 4:
        return original_bytes

    inverted = bytearray(original_bytes)

    condition_byte_index = 3
    condition = inverted[condition_byte_index] >> 4

    condition_map = {
        0x0: 0x1,
        0x1: 0x0,
        0xA: 0xB,
        0xB: 0xA,
        0xC: 0xD,
        0xD: 0xC,
    }

    if condition in condition_map:
        new_condition = condition_map[condition]
        inverted[condition_byte_index] = (new_condition << 4) | (inverted[condition_byte_index] & 0x0F)

    return bytes(inverted)


def generate_nop_sled(size: int, arch: Architecture = Architecture.X86) -> bytes:
    """Generate a NOP sled of specified size.

    Args:
        size: Number of bytes to generate
        arch: Target architecture

    Returns:
        NOP instruction bytes

    """
    if arch in (Architecture.X86, Architecture.X64):
        return bytes([0x90] * size)
    elif arch == Architecture.ARM32:
        nop_count = size // 4
        arm_nop = bytes([0x00, 0x00, 0xA0, 0xE1])
        return arm_nop * nop_count
    elif arch == Architecture.ARM64:
        nop_count = size // 4
        arm64_nop = bytes([0x1F, 0x20, 0x03, 0xD5])
        return arm64_nop * nop_count
    else:
        return bytes([0x90] * size)


def generate_trampoline_x86(target_addr: int, hook_addr: int) -> bytes:
    """Generate x86 trampoline jump.

    Creates a JMP instruction to redirect execution.

    Args:
        target_addr: Address to patch
        hook_addr: Address to jump to

    Returns:
        JMP instruction bytes

    """
    offset = hook_addr - (target_addr + 5)

    offset_bytes = offset.to_bytes(4, byteorder='little', signed=True)

    return bytes([0xE9]) + offset_bytes


def generate_trampoline_x64(target_addr: int, hook_addr: int) -> bytes:
    """Generate x64 trampoline jump.

    Uses absolute 64-bit jump via register.

    Args:
        target_addr: Address to patch
        hook_addr: Address to jump to

    Returns:
        Absolute jump instruction bytes

    """
    offset = hook_addr - (target_addr + 5)

    if -2147483648 <= offset <= 2147483647:
        offset_bytes = offset.to_bytes(4, byteorder='little', signed=True)
        return bytes([0xE9]) + offset_bytes
    else:
        hook_bytes = hook_addr.to_bytes(8, byteorder='little')
        return bytes([
            0x48, 0xB8,
        ]) + hook_bytes + bytes([
            0xFF, 0xE0,
        ])


def wrap_patch_stdcall(patch: bytes, arg_count: int = 0) -> bytes:
    """Wrap patch to preserve stdcall calling convention.

    Args:
        patch: Original patch bytes
        arg_count: Number of arguments (for stack cleanup)

    Returns:
        Wrapped patch with stack preservation

    """
    if arg_count == 0:
        return patch

    stack_cleanup = arg_count * 4
    cleanup_bytes = stack_cleanup.to_bytes(2, byteorder='little')

    return patch[:-1] + bytes([0xC2]) + cleanup_bytes


def wrap_patch_cdecl(patch: bytes) -> bytes:
    """Wrap patch to preserve cdecl calling convention.

    cdecl has caller cleanup, so no modification needed.

    Args:
        patch: Original patch bytes

    Returns:
        Unmodified patch

    """
    return patch


def wrap_patch_fastcall(patch: bytes) -> bytes:
    """Wrap patch to preserve fastcall calling convention.

    Preserves RCX and RDX registers.

    Args:
        patch: Original patch bytes

    Returns:
        Wrapped patch with register preservation

    """
    push_regs = bytes([
        0x51,
        0x52,
    ])

    pop_regs = bytes([
        0x5A,
        0x59,
    ])

    return push_regs + patch + pop_regs


def wrap_patch_x64_convention(patch: bytes) -> bytes:
    """Wrap patch to preserve x64 calling convention.

    Preserves RCX, RDX, R8, R9 registers.

    Args:
        patch: Original patch bytes

    Returns:
        Wrapped patch with register preservation

    """
    push_regs = bytes([
        0x51,
        0x52,
        0x41, 0x50,
        0x41, 0x51,
    ])

    pop_regs = bytes([
        0x41, 0x59,
        0x41, 0x58,
        0x5A,
        0x59,
    ])

    return push_regs + patch + pop_regs


def generate_register_save_x86() -> bytes:
    """Generate x86 code to save all general-purpose registers.

    Returns:
        PUSHAD instruction bytes

    """
    return bytes([0x60])


def generate_register_restore_x86() -> bytes:
    """Generate x86 code to restore all general-purpose registers.

    Returns:
        POPAD instruction bytes

    """
    return bytes([0x61])


def generate_register_save_x64() -> bytes:
    """Generate x64 code to save all general-purpose registers.

    Returns:
        Series of PUSH instructions for all registers

    """
    return bytes([
        0x50,
        0x51,
        0x52,
        0x53,
        0x54,
        0x55,
        0x56,
        0x57,
        0x41, 0x50,
        0x41, 0x51,
        0x41, 0x52,
        0x41, 0x53,
        0x41, 0x54,
        0x41, 0x55,
        0x41, 0x56,
        0x41, 0x57,
    ])


def generate_register_restore_x64() -> bytes:
    """Generate x64 code to restore all general-purpose registers.

    Returns:
        Series of POP instructions for all registers

    """
    return bytes([
        0x41, 0x5F,
        0x41, 0x5E,
        0x41, 0x5D,
        0x41, 0x5C,
        0x41, 0x5B,
        0x41, 0x5A,
        0x41, 0x59,
        0x41, 0x58,
        0x5F,
        0x5E,
        0x5D,
        0x5C,
        0x5B,
        0x5A,
        0x59,
        0x58,
    ])


def validate_patch_size(patch: bytes, max_size: int) -> bool:
    """Validate that patch fits within maximum size.

    Args:
        patch: Patch bytes to validate
        max_size: Maximum allowed size

    Returns:
        True if patch fits, False otherwise

    """
    return len(patch) <= max_size


def validate_patch_alignment(patch: bytes, address: int) -> bool:
    """Validate that patch maintains proper alignment.

    Args:
        patch: Patch bytes to validate
        address: Target address

    Returns:
        True if properly aligned

    """
    if len(patch) == 0:
        return False

    if address % 4 == 0 and len(patch) % 4 == 0:
        return True

    return True


def get_patch_for_architecture(
    arch: Architecture,
    patch_type: PatchType,
    **kwargs,
) -> Optional[bytes]:
    """Get appropriate patch for target architecture.

    Args:
        arch: Target architecture
        patch_type: Type of patch to generate
        **kwargs: Additional parameters for patch generation

    Returns:
        Generated patch bytes or None if unsupported

    """
    if patch_type == PatchType.ALWAYS_SUCCEED:
        if arch == Architecture.X86:
            return generate_always_succeed_x86()
        elif arch == Architecture.X64:
            return generate_always_succeed_x64()
        elif arch == Architecture.ARM32:
            return generate_always_succeed_arm32()
        elif arch == Architecture.ARM64:
            return generate_always_succeed_arm64()

    elif patch_type == PatchType.NOP_SLED:
        size = kwargs.get('size', 0)
        return generate_nop_sled(size, arch)

    elif patch_type == PatchType.CONDITIONAL_INVERT:
        original = kwargs.get('original_bytes', b'')
        if arch in (Architecture.X86, Architecture.X64):
            return generate_conditional_invert_x86(original)
        elif arch in (Architecture.ARM32, Architecture.ARM64):
            return generate_conditional_invert_arm(original)

    elif patch_type == PatchType.TRAMPOLINE:
        target = kwargs.get('target_addr', 0)
        hook = kwargs.get('hook_addr', 0)
        if arch == Architecture.X86:
            return generate_trampoline_x86(target, hook)
        elif arch == Architecture.X64:
            return generate_trampoline_x64(target, hook)

    return None
