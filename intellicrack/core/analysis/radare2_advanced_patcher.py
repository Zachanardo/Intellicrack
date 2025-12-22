#!/usr/bin/env python3
"""Radare2 Advanced Patching Engine.

Production-ready implementation for sophisticated binary patching:
- Multi-byte NOP sled generation
- Jump table modifications
- Function epilogue/prologue patches
- Conditional jump inversions
- Return value modifications
- Call target redirection
"""

import hashlib
import json
import logging
import struct
from dataclasses import dataclass
from enum import Enum
from typing import Any, TYPE_CHECKING

import r2pipe

if TYPE_CHECKING:
    from r2pipe import open as R2Open


logger = logging.getLogger(__name__)


class PatchType(Enum):
    """Types of patches that can be applied."""

    NOP_SLED = "nop_sled"
    JUMP_TABLE = "jump_table"
    PROLOGUE = "prologue"
    EPILOGUE = "epilogue"
    CONDITIONAL_JUMP = "conditional_jump"
    RETURN_VALUE = "return_value"
    CALL_TARGET = "call_target"
    INSTRUCTION_REPLACE = "instruction_replace"
    FUNCTION_HOOK = "function_hook"
    ANTI_DEBUG_DEFEAT = "anti_debug_defeat"


class Architecture(Enum):
    """Supported architectures."""

    X86 = "x86"
    X86_64 = "x86_64"
    ARM = "arm"
    ARM64 = "arm64"
    MIPS = "mips"
    PPC = "ppc"


@dataclass
class PatchInfo:
    """Information about a patch."""

    type: PatchType
    address: int
    original_bytes: bytes
    patched_bytes: bytes
    description: str
    metadata: dict[str, Any]


class Radare2AdvancedPatcher:
    """Advanced binary patching engine using Radare2."""

    def __init__(self, binary_path: str) -> None:
        """Initialize the Radare2AdvancedPatcher with a binary file path.

        Args:
            binary_path: Path to the binary file to patch.

        """
        self.binary_path = binary_path
        self.r2: Any = None
        self.patches: list[PatchInfo] = []
        self.architecture: Architecture | None = None
        self.bits: int = 0
        self.endianness: str = "little"

    def open(self, write_mode: bool = True) -> bool:
        """Open binary in Radare2."""
        try:
            flags = ["-w"] if write_mode else []
            self.r2 = r2pipe.open(self.binary_path, flags=flags)

            # Analyze binary
            self.r2.cmd("aaa")

            # Get architecture info
            info = self.r2.cmdj("ij")
            self.bits = info["bin"]["bits"]
            self.endianness = info["bin"]["endian"]

            arch = info["bin"]["arch"]
            if arch == "x86":
                self.architecture = Architecture.X86_64 if self.bits == 64 else Architecture.X86
            elif arch == "arm":
                self.architecture = Architecture.ARM64 if self.bits == 64 else Architecture.ARM
            elif arch == "mips":
                self.architecture = Architecture.MIPS
            elif arch == "ppc":
                self.architecture = Architecture.PPC

            if self.architecture:
                logger.info("Opened %s: %s %s-bit %s", self.binary_path, self.architecture.value, self.bits, self.endianness)
            else:
                logger.info("Opened %s: unknown architecture %s-bit %s", self.binary_path, self.bits, self.endianness)
            return True

        except Exception as e:
            logger.exception("Failed to open binary: %s", e, exc_info=True)
            return False

    def generate_nop_sled(self, address: int, size: int) -> PatchInfo:
        """Generate multi-byte NOP sled."""
        if not self.r2:
            raise RuntimeError("Radare2 session not opened")

        nop_bytes = self._get_nop_instruction() * (size // len(self._get_nop_instruction()))

        # Read original bytes
        original: Any = self.r2.cmdj(f"pxj {size} @ {address}")
        original_bytes = bytes(original)

        # Create patch
        patch = PatchInfo(
            type=PatchType.NOP_SLED,
            address=address,
            original_bytes=original_bytes,
            patched_bytes=nop_bytes,
            description=f"NOP sled of {size} bytes at {hex(address)}",
            metadata={"size": size},
        )

        # Apply patch
        self._write_bytes(address, nop_bytes)
        self.patches.append(patch)

        logger.info("Generated NOP sled: %s bytes at %s", size, hex(address))
        return patch

    def _get_nop_instruction(self) -> bytes:
        """Get NOP instruction for current architecture."""
        nop_map: dict[Architecture, bytes] = {
            Architecture.X86: b"\x90",
            Architecture.X86_64: b"\x90",
            Architecture.ARM: b"\x00\x00\x00\xe1",
            Architecture.ARM64: b"\x1f\x20\x03\xd5",
            Architecture.MIPS: b"\x00\x00\x00\x00",
            Architecture.PPC: b"\x60\x00\x00\x00",
        }
        if self.architecture is None:
            return b"\x90"
        return nop_map.get(self.architecture, b"\x90")

    def modify_jump_table(self, table_address: int, entries: list[int]) -> PatchInfo:
        """Modify jump table entries."""
        if not self.r2:
            raise RuntimeError("Radare2 session not opened")

        entry_size = 8 if self.bits == 64 else 4
        table_size = len(entries) * entry_size

        # Read original table
        original: Any = self.r2.cmdj(f"pxj {table_size} @ {table_address}")
        original_bytes = bytes(original)

        # Create new table
        new_table = b""
        for entry in entries:
            if self.bits == 64:
                new_table += struct.pack("<Q" if self.endianness == "little" else ">Q", entry)
            else:
                new_table += struct.pack("<I" if self.endianness == "little" else ">I", entry)

        patch = PatchInfo(
            type=PatchType.JUMP_TABLE,
            address=table_address,
            original_bytes=original_bytes,
            patched_bytes=new_table,
            description=f"Modified jump table at {hex(table_address)} with {len(entries)} entries",
            metadata={"entries": entries, "entry_size": entry_size},
        )

        # Apply patch
        self._write_bytes(table_address, new_table)
        self.patches.append(patch)

        logger.info("Modified jump table at %s", hex(table_address))
        return patch

    def patch_function_prologue(self, func_address: int, skip_bytes: int = 0, custom_prologue: bytes | None = None) -> PatchInfo:
        """Patch function prologue."""
        if not self.r2:
            raise RuntimeError("Radare2 session not opened")

        if custom_prologue:
            prologue_bytes = custom_prologue
        else:
            # Generate standard prologue based on architecture
            prologue_bytes = self._generate_standard_prologue(skip_bytes)

        # Read original prologue
        prologue_size = len(prologue_bytes)
        original: Any = self.r2.cmdj(f"pxj {prologue_size} @ {func_address}")
        original_bytes = bytes(original)

        patch = PatchInfo(
            type=PatchType.PROLOGUE,
            address=func_address,
            original_bytes=original_bytes,
            patched_bytes=prologue_bytes,
            description=f"Patched function prologue at {hex(func_address)}",
            metadata={"skip_bytes": skip_bytes, "custom": custom_prologue is not None},
        )

        # Apply patch
        self._write_bytes(func_address, prologue_bytes)
        self.patches.append(patch)

        logger.info("Patched function prologue at %s", hex(func_address))
        return patch

    def _generate_standard_prologue(self, skip_bytes: int) -> bytes:
        """Generate standard function prologue."""
        if self.architecture == Architecture.X86_64:
            # Standard x64 prologue
            prologue = b"\x55"  # push rbp
            prologue += b"\x48\x89\xe5"  # mov rbp, rsp

            if skip_bytes > 0:
                # Add stack allocation
                prologue += b"\x48\x83\xec" + bytes([skip_bytes])  # sub rsp, skip_bytes

        elif self.architecture == Architecture.X86:
            # Standard x86 prologue
            prologue = b"\x55"  # push ebp
            prologue += b"\x89\xe5"  # mov ebp, esp

            if skip_bytes > 0:
                # Add stack allocation
                prologue += b"\x83\xec" + bytes([skip_bytes])  # sub esp, skip_bytes

        elif self.architecture == Architecture.ARM64:
            # ARM64 prologue
            prologue = b"\xfd\x7b\xbe\xa9"  # stp x29, x30, [sp, #-0x20]!
            prologue += b"\xfd\x03\x00\x91"  # mov x29, sp

        elif self.architecture == Architecture.ARM:
            # ARM prologue
            prologue = b"\x00\x48\x2d\xe9"  # push {r11, lr}
            prologue += b"\x0d\xb0\xa0\xe1"  # mov r11, sp

        else:
            # Default to NOPs
            prologue = self._get_nop_instruction() * 8

        return prologue

    def patch_function_epilogue(self, func_address: int, func_size: int, custom_epilogue: bytes | None = None) -> PatchInfo:
        """Patch function epilogue."""
        if not self.r2:
            raise RuntimeError("Radare2 session not opened")

        # Find epilogue location
        epilogue_address = self._find_epilogue(func_address, func_size)

        if custom_epilogue:
            epilogue_bytes = custom_epilogue
        else:
            epilogue_bytes = self._generate_standard_epilogue()

        # Read original epilogue
        epilogue_size = len(epilogue_bytes)
        original: Any = self.r2.cmdj(f"pxj {epilogue_size} @ {epilogue_address}")
        original_bytes = bytes(original)

        patch = PatchInfo(
            type=PatchType.EPILOGUE,
            address=epilogue_address,
            original_bytes=original_bytes,
            patched_bytes=epilogue_bytes,
            description=f"Patched function epilogue at {hex(epilogue_address)}",
            metadata={"function_start": func_address, "custom": custom_epilogue is not None},
        )

        # Apply patch
        self._write_bytes(epilogue_address, epilogue_bytes)
        self.patches.append(patch)

        logger.info("Patched function epilogue at %s", hex(epilogue_address))
        return patch

    def _find_epilogue(self, func_address: int, func_size: int) -> int:
        """Find function epilogue location."""
        if not self.r2:
            raise RuntimeError("Radare2 session not opened")

        # Disassemble function
        disasm: Any = self.r2.cmdj(f"pdj {func_size} @ {func_address}")

        # Look for return instructions
        for inst in reversed(disasm):
            if self.architecture in [Architecture.X86, Architecture.X86_64]:
                if inst.get("mnemonic") in ["ret", "retn", "leave"]:
                    offset: Any = inst.get("offset")
                    if isinstance(offset, int):
                        return offset - 8
            elif self.architecture in [Architecture.ARM, Architecture.ARM64]:
                mnemonic: Any = inst.get("mnemonic", "")
                opcode: Any = inst.get("opcode", "")
                if "bx" in mnemonic and "lr" in opcode:
                    offset = inst.get("offset")
                    if isinstance(offset, int):
                        return offset - 8

        # Default to end of function minus typical epilogue size
        return func_address + func_size - 16

    def _generate_standard_epilogue(self) -> bytes:
        """Generate standard function epilogue."""
        if self.architecture == Architecture.X86_64:
            # Standard x64 epilogue
            epilogue = b"\x48\x89\xec"  # mov rsp, rbp
            epilogue += b"\x5d"  # pop rbp
            epilogue += b"\xc3"  # ret

        elif self.architecture == Architecture.X86:
            # Standard x86 epilogue
            epilogue = b"\x89\xec"  # mov esp, ebp
            epilogue += b"\x5d"  # pop ebp
            epilogue += b"\xc3"  # ret

        elif self.architecture == Architecture.ARM64:
            # ARM64 epilogue
            epilogue = b"\xfd\x7b\xc2\xa8"  # ldp x29, x30, [sp], #0x20
            epilogue += b"\xc0\x03\x5f\xd6"  # ret

        elif self.architecture == Architecture.ARM:
            # ARM epilogue
            epilogue = b"\x00\x88\xbd\xe8"  # pop {r11, pc}

        else:
            # Default return
            epilogue = b"\xc3"  # ret

        return epilogue

    def invert_conditional_jump(self, address: int) -> PatchInfo:
        """Invert conditional jump instruction."""
        if not self.r2:
            raise RuntimeError("Radare2 session not opened")

        # Get instruction at address
        inst_list: Any = self.r2.cmdj(f"pdj 1 @ {address}")
        inst: Any = inst_list[0]
        mnemonic: Any = inst["mnemonic"]
        opcode_bytes = bytes.fromhex(inst["bytes"])

        # Map of x86/x64 conditional jumps and their inversions
        jump_inversions = {
            "je": "jne",
            "jz": "jnz",
            "jne": "je",
            "jnz": "jz",
            "jg": "jle",
            "jnle": "jle",
            "jge": "jl",
            "jnl": "jl",
            "jl": "jge",
            "jnge": "jge",
            "jle": "jg",
            "jng": "jg",
            "ja": "jbe",
            "jnbe": "jbe",
            "jae": "jb",
            "jnb": "jb",
            "jnc": "jc",
            "jb": "jae",
            "jnae": "jae",
            "jc": "jnc",
            "jbe": "ja",
            "jna": "ja",
            "jo": "jno",
            "jno": "jo",
            "js": "jns",
            "jns": "js",
            "jp": "jnp",
            "jpe": "jpo",
            "jnp": "jp",
            "jpo": "jpe",
        }

        if mnemonic.lower() in jump_inversions:
            # Calculate inverted opcode
            inverted_mnemonic = jump_inversions[mnemonic.lower()]
            inverted_bytes = self._get_inverted_jump_bytes(opcode_bytes, mnemonic, inverted_mnemonic)

            patch = PatchInfo(
                type=PatchType.CONDITIONAL_JUMP,
                address=address,
                original_bytes=opcode_bytes,
                patched_bytes=inverted_bytes,
                description=f"Inverted jump from {mnemonic} to {inverted_mnemonic} at {hex(address)}",
                metadata={"original_mnemonic": mnemonic, "inverted_mnemonic": inverted_mnemonic},
            )

            # Apply patch
            self._write_bytes(address, inverted_bytes)
            self.patches.append(patch)

            logger.info("Inverted conditional jump at %s: %s -> %s", hex(address), mnemonic, inverted_mnemonic)
            return patch

        raise ValueError(f"Cannot invert non-conditional jump: {mnemonic}")

    def _get_inverted_jump_bytes(self, original: bytes, original_mnemonic: str, inverted_mnemonic: str) -> bytes:
        """Get inverted jump instruction bytes."""
        # For x86/x64, conditional jumps differ by one bit in many cases
        if len(original) == 2 and original[0] == 0x0F:
            # Long conditional jump (0F xx)
            opcode_map = {
                0x84: 0x85,
                0x85: 0x84,  # je/jne
                0x8F: 0x8E,
                0x8E: 0x8F,  # jg/jle
                0x8D: 0x8C,
                0x8C: 0x8D,  # jge/jl
                0x87: 0x86,
                0x86: 0x87,  # ja/jbe
                0x83: 0x82,
                0x82: 0x83,  # jae/jb
                0x80: 0x81,
                0x81: 0x80,  # jo/jno
                0x88: 0x89,
                0x89: 0x88,  # js/jns
                0x8A: 0x8B,
                0x8B: 0x8A,  # jp/jnp
            }

            if original[1] in opcode_map:
                return bytes([original[0], opcode_map[original[1]]])

        elif len(original) == 1:
            # Short conditional jump (7x)
            opcode_map = {
                0x74: 0x75,
                0x75: 0x74,  # je/jne
                0x7F: 0x7E,
                0x7E: 0x7F,  # jg/jle
                0x7D: 0x7C,
                0x7C: 0x7D,  # jge/jl
                0x77: 0x76,
                0x76: 0x77,  # ja/jbe
                0x73: 0x72,
                0x72: 0x73,  # jae/jb
                0x70: 0x71,
                0x71: 0x70,  # jo/jno
                0x78: 0x79,
                0x79: 0x78,  # js/jns
                0x7A: 0x7B,
                0x7B: 0x7A,  # jp/jnp
            }

            if original[0] in opcode_map:
                return bytes([opcode_map[original[0]]])

        # If we can't determine the inversion, XOR the condition bit
        inverted = bytearray(original)
        inverted[-1] ^= 0x01
        return bytes(inverted)

    def modify_return_value(self, func_address: int, return_value: int) -> PatchInfo:
        """Modify function return value."""
        if not self.r2:
            raise RuntimeError("Radare2 session not opened")

        # Find all return points in function
        func_info_list: Any = self.r2.cmdj(f"afij @ {func_address}")
        func_info: Any = func_info_list[0]
        func_size: Any = func_info["size"]

        # Disassemble function
        disasm: Any = self.r2.cmdj(f"pdj {func_size} @ {func_address}")

        patches_made = []
        for inst in disasm:
            if inst["mnemonic"] in ["ret", "retn"]:
                ret_address = inst["offset"]

                # Insert return value modification before ret
                if self.architecture == Architecture.X86_64:
                    # mov rax, return_value
                    if return_value <= 0x7FFFFFFF:
                        mod_bytes = b"\xb8" + struct.pack("<I", return_value)  # mov eax, imm32
                    else:
                        mod_bytes = b"\x48\xb8" + struct.pack("<Q", return_value)  # mov rax, imm64

                elif self.architecture == Architecture.X86:
                    # mov eax, return_value
                    mod_bytes = b"\xb8" + struct.pack("<I", return_value & 0xFFFFFFFF)

                elif self.architecture == Architecture.ARM64:
                    # mov x0, return_value
                    mod_bytes = self._encode_arm64_mov_immediate(0, return_value)

                elif self.architecture == Architecture.ARM:
                    # mov r0, return_value
                    mod_bytes = self._encode_arm_mov_immediate(0, return_value)

                else:
                    continue

                # We need to insert before the ret, which might require code cave
                patch_address = ret_address - len(mod_bytes)

                # Read original bytes
                original_data: Any = self.r2.cmdj(f"pxj {len(mod_bytes)} @ {patch_address}")
                original_bytes = bytes(original_data)

                # Apply patch
                self._write_bytes(patch_address, mod_bytes)

                patches_made.append({"address": patch_address, "original": original_bytes, "patched": mod_bytes})

        if patches_made:
            patch = PatchInfo(
                type=PatchType.RETURN_VALUE,
                address=func_address,
                original_bytes=b"".join([p["original"] for p in patches_made]),
                patched_bytes=b"".join([p["patched"] for p in patches_made]),
                description=f"Modified return value to {hex(return_value)} for function at {hex(func_address)}",
                metadata={"return_value": return_value, "patches": patches_made},
            )

            self.patches.append(patch)
            logger.info("Modified return value for function at %s to %s", hex(func_address), hex(return_value))
            return patch

        raise ValueError(f"No return instructions found in function at {hex(func_address)}")

    def _encode_arm64_mov_immediate(self, reg: int, value: int) -> bytes:
        """Encode ARM64 mov immediate instruction."""
        # Simplified encoding for common values
        if value == 0:
            # mov xN, xzr
            return struct.pack("<I", 0xAA1F03E0 | reg)
        if value <= 0xFFFF:
            # movz xN, #value
            return struct.pack("<I", 0xD2800000 | (value << 5) | reg)
        # Multiple instructions needed for large values
        instructions = [struct.pack("<I", 0xD2800000 | ((value & 0xFFFF) << 5) | reg)]
        instructions.append(struct.pack("<I", 0xF2A00000 | (((value >> 16) & 0xFFFF) << 5) | reg))
        return b"".join(instructions)

    def _encode_arm_mov_immediate(self, reg: int, value: int) -> bytes:
        """Encode ARM mov immediate instruction."""
        if value <= 0xFF:
            # mov rN, #value
            return struct.pack("<I", 0xE3A00000 | (reg << 12) | value)
        # movw rN, #(value & 0xFFFF)
        low = value & 0xFFFF
        inst = 0xE3000000 | (reg << 12) | ((low & 0xF000) << 4) | (low & 0xFFF)
        return struct.pack("<I", inst)

    def redirect_call_target(self, call_address: int, new_target: int) -> PatchInfo:
        """Redirect function call to new target."""
        if not self.r2:
            raise RuntimeError("Radare2 session not opened")

        # Get call instruction
        inst_list: Any = self.r2.cmdj(f"pdj 1 @ {call_address}")
        inst: Any = inst_list[0]
        mnemonic: Any = inst["mnemonic"]
        original_bytes = bytes.fromhex(inst["bytes"])

        if mnemonic.lower() != "call":
            raise ValueError(f"Address {hex(call_address)} is not a call instruction")

        # Calculate relative offset for new target
        if self.architecture in [Architecture.X86, Architecture.X86_64]:
            # E8 rel32
            call_end = call_address + len(original_bytes)
            offset = new_target - call_end

            if original_bytes[0] == 0xE8:
                # Direct call with rel32
                new_bytes = b"\xe8" + struct.pack("<i", offset)
            elif original_bytes[:2] == b"\xff\x15":
                # Indirect call through memory
                # We need to patch the memory location instead
                mem_offset = struct.unpack("<i", original_bytes[2:6])[0]
                mem_address = call_address + 6 + mem_offset

                if self.bits == 64:
                    self._write_bytes(mem_address, struct.pack("<Q", new_target))
                else:
                    self._write_bytes(mem_address, struct.pack("<I", new_target))

                new_bytes = original_bytes  # Keep the call instruction unchanged
            else:
                # Other call types - replace with direct call
                new_bytes = b"\xe8" + struct.pack("<i", offset)
                # Pad with NOPs if needed
                if len(new_bytes) < len(original_bytes):
                    new_bytes += self._get_nop_instruction() * (len(original_bytes) - len(new_bytes))

        elif self.architecture == Architecture.ARM64:
            # BL instruction
            offset = (new_target - call_address) // 4
            if -0x2000000 <= offset <= 0x1FFFFFF:
                # Can use direct BL
                inst_word = 0x94000000 | (offset & 0x3FFFFFF)
                new_bytes = struct.pack("<I", inst_word)
            else:
                # Large offset requires trampoline through code cave
                cave = self._find_code_cave(16)

                # Create trampoline in code cave:
                # movz x16, #(target & 0xFFFF)
                # movk x16, #((target >> 16) & 0xFFFF), lsl #16
                # movk x16, #((target >> 32) & 0xFFFF), lsl #32
                # movk x16, #((target >> 48) & 0xFFFF), lsl #48
                # br x16

                trampoline = [0xD2800010 | (new_target & 0xFFFF) << 5]
                # movk x16, #((target >> 16) & 0xFFFF), lsl #16
                if new_target > 0xFFFF:
                    trampoline.append(0xF2A00010 | (((new_target >> 16) & 0xFFFF) << 5))
                # movk x16, #((target >> 32) & 0xFFFF), lsl #32
                if new_target > 0xFFFFFFFF:
                    trampoline.append(0xF2C00010 | (((new_target >> 32) & 0xFFFF) << 5))
                # movk x16, #((target >> 48) & 0xFFFF), lsl #48
                if new_target > 0xFFFFFFFFFFFF:
                    trampoline.append(0xF2E00010 | (((new_target >> 48) & 0xFFFF) << 5))
                # br x16
                trampoline.append(0xD61F0200)

                # Write trampoline to code cave
                trampoline_bytes = b"".join([struct.pack("<I", inst) for inst in trampoline])
                self._write_bytes(cave, trampoline_bytes)

                # Now redirect call to trampoline
                cave_offset = (cave - call_address) // 4
                if -0x2000000 <= cave_offset <= 0x1FFFFFF:
                    inst_word = 0x94000000 | (cave_offset & 0x3FFFFFF)
                    new_bytes = struct.pack("<I", inst_word)
                else:
                    # Even cave is too far, use absolute branch
                    # ldr x16, [pc, #8]; br x16; .quad target
                    new_bytes = b"\x50\x00\x00\x58"  # ldr x16, [pc, #8]
                    new_bytes += b"\x00\x02\x1f\xd6"  # br x16
                    new_bytes += struct.pack("<Q", cave)

        elif self.architecture == Architecture.ARM:
            # BL instruction
            offset = (new_target - call_address - 8) // 4
            if -0x1000000 <= offset <= 0xFFFFFF:
                # Can use direct BL
                inst_word = 0xEB000000 | (offset & 0xFFFFFF)
                new_bytes = struct.pack("<I", inst_word)
            else:
                # Large offset requires trampoline through code cave
                cave = self._find_code_cave(20)

                # Create trampoline in code cave:
                # ldr r12, [pc, #0]  ; Load target address
                # bx r12             ; Branch to target
                # .word target       ; Target address

                trampoline = [3852451840, 3778019100, new_target & 0xFFFFFFFF]
                # Write trampoline to code cave
                trampoline_bytes = b"".join([struct.pack("<I", inst) for inst in trampoline])
                self._write_bytes(cave, trampoline_bytes)

                # Now redirect call to trampoline
                cave_offset = (cave - call_address - 8) // 4
                if -0x1000000 <= cave_offset <= 0xFFFFFF:
                    inst_word = 0xEB000000 | (cave_offset & 0xFFFFFF)
                    new_bytes = struct.pack("<I", inst_word)
                else:
                    # Even cave is too far, use absolute load and branch
                    # This overwrites more instructions, need larger patch
                    # ldr pc, [pc, #-4]  ; Load and branch to address after this instruction
                    # .word cave         ; Cave address
                    new_bytes = b"\x04\xf0\x1f\xe5"  # ldr pc, [pc, #-4]
                    new_bytes += struct.pack("<I", cave)

        elif self.architecture == Architecture.MIPS:
            # MIPS call redirection
            # lui $t9, %hi(target)
            # ori $t9, $t9, %lo(target)
            # jalr $t9
            # nop (delay slot)

            high = (new_target >> 16) & 0xFFFF
            low = new_target & 0xFFFF

            # lui t9, high
            new_bytes = struct.pack(">I", 0x3C190000 | high)
            # ori t9, t9, low
            new_bytes += struct.pack(">I", 0x37390000 | low)
            # jalr t9
            new_bytes += struct.pack(">I", 0x0320F809)
            # nop (delay slot)
            new_bytes += struct.pack(">I", 0x00000000)

            # Pad with NOPs if original instruction was larger
            while len(new_bytes) < len(original_bytes):
                new_bytes += struct.pack(">I", 0x00000000)

        elif self.architecture == Architecture.PPC:
            # PowerPC call redirection
            # lis r12, target@h
            # ori r12, r12, target@l
            # mtctr r12
            # bctr

            high = (new_target >> 16) & 0xFFFF
            low = new_target & 0xFFFF

            # lis r12, high
            new_bytes = struct.pack(">I", 0x3D800000 | high)
            # ori r12, r12, low
            new_bytes += struct.pack(">I", 0x618C0000 | low)
            # mtctr r12
            new_bytes += struct.pack(">I", 0x7D8903A6)
            # bctr
            new_bytes += struct.pack(">I", 0x4E800420)

            # Pad with NOPs if needed
            while len(new_bytes) < len(original_bytes):
                new_bytes += struct.pack(">I", 0x60000000)  # PPC NOP

        else:
            # Generic fallback for unknown architectures
            # Try to use a simple jump table approach
            # This attempts to write the target address directly

            if self.bits == 64:
                # 64-bit absolute jump via register
                # We'll try to construct a generic sequence
                # This is architecture-specific but we'll use common patterns

                # Try to allocate a code cave for trampoline
                cave = self._find_code_cave(16)

                # Write target address to cave
                self._write_bytes(cave, struct.pack("<Q", new_target))

                # Create a PC-relative load and jump
                # This is a best-effort approach for unknown architectures
                offset_to_cave = cave - call_address

                # Try to encode as a relative jump with offset
                if abs(offset_to_cave) < 0x7FFFFFFF:
                    # 32-bit relative jump (common pattern)
                    new_bytes = b"\xe9" + struct.pack("<i", offset_to_cave)
                else:
                    # Absolute indirect jump through memory
                    # Load address and jump pattern (x86-like)
                    new_bytes = b"\xff\x25\x00\x00\x00\x00" + struct.pack("<Q", cave)
            # 32-bit absolute jump
            elif abs(new_target - call_address) < 0x7FFFFFFF:
                # Relative jump
                offset = new_target - (call_address + 5)
                new_bytes = b"\xe9" + struct.pack("<i", offset)
            else:
                # Absolute jump via register
                new_bytes = b"\xb8" + struct.pack("<I", new_target)  # mov eax, target
                new_bytes += b"\xff\xe0"  # jmp eax

            # Ensure we don't exceed original instruction size
            if len(new_bytes) > len(original_bytes):
                # Truncate and use code cave instead
                cave = self._find_code_cave(len(new_bytes) + 8)
                self._write_bytes(cave, new_bytes)
                # Jump to cave
                cave_offset = cave - (call_address + 5)
                new_bytes = b"\xe9" + struct.pack("<i", cave_offset)
                new_bytes += self._get_nop_instruction() * (len(original_bytes) - len(new_bytes))

        patch = PatchInfo(
            type=PatchType.CALL_TARGET,
            address=call_address,
            original_bytes=original_bytes,
            patched_bytes=new_bytes,
            description=f"Redirected call at {hex(call_address)} to {hex(new_target)}",
            metadata={"original_target": inst.get("jump", 0), "new_target": new_target},
        )

        # Apply patch
        self._write_bytes(call_address, new_bytes)
        self.patches.append(patch)

        logger.info("Redirected call at %s to %s", hex(call_address), hex(new_target))
        return patch

    def create_function_hook(self, func_address: int, hook_code: bytes, preserve_original: bool = True) -> PatchInfo:
        """Create inline function hook."""
        if preserve_original:
            # Create trampoline
            trampoline = self._create_trampoline(func_address, len(hook_code))

            # Generate jump to hook
            if self.architecture in [Architecture.X86, Architecture.X86_64]:
                # JMP rel32
                hook_offset = (func_address + len(hook_code)) - (func_address + 5)
                jump_to_hook = b"\xe9" + struct.pack("<i", hook_offset)

                # Add jump back to original
                jump_back = b"\xe9" + struct.pack("<i", trampoline - (func_address + len(hook_code) + 5))
            elif self.architecture == Architecture.ARM64:
                # ARM64 hook with trampoline
                # Calculate relative branch offset
                hook_offset = (func_address + len(hook_code)) - func_address
                trampoline_offset = trampoline - (func_address + len(hook_code))

                # B offset (unconditional branch)
                if abs(hook_offset // 4) < 0x2000000:
                    jump_to_hook = struct.pack("<I", 0x14000000 | ((hook_offset // 4) & 0x3FFFFFF))
                else:
                    # Use absolute branch via register
                    # ldr x16, [pc, #8]
                    # br x16
                    # .quad hook_address
                    jump_to_hook = b"\x50\x00\x00\x58"  # ldr x16, [pc, #8]
                    jump_to_hook += b"\x00\x02\x1f\xd6"  # br x16
                    jump_to_hook += struct.pack("<Q", func_address + len(hook_code))

                # Jump back to trampoline
                if abs(trampoline_offset // 4) < 0x2000000:
                    jump_back = struct.pack("<I", 0x14000000 | ((trampoline_offset // 4) & 0x3FFFFFF))
                else:
                    jump_back = b"\x50\x00\x00\x58"  # ldr x16, [pc, #8]
                    jump_back += b"\x00\x02\x1f\xd6"  # br x16
                    jump_back += struct.pack("<Q", trampoline)

            elif self.architecture == Architecture.ARM:
                # ARM hook with trampoline
                hook_offset = (func_address + len(hook_code)) - func_address - 8
                trampoline_offset = trampoline - (func_address + len(hook_code)) - 8

                # B offset (unconditional branch)
                if abs(hook_offset // 4) < 0x1000000:
                    jump_to_hook = struct.pack("<I", 0xEA000000 | ((hook_offset // 4) & 0xFFFFFF))
                else:
                    # Use absolute branch
                    # ldr pc, [pc, #-4]
                    # .word hook_address
                    jump_to_hook = b"\x04\xf0\x1f\xe5"  # ldr pc, [pc, #-4]
                    jump_to_hook += struct.pack("<I", func_address + len(hook_code))

                # Jump back to trampoline
                if abs(trampoline_offset // 4) < 0x1000000:
                    jump_back = struct.pack("<I", 0xEA000000 | ((trampoline_offset // 4) & 0xFFFFFF))
                else:
                    jump_back = b"\x04\xf0\x1f\xe5"  # ldr pc, [pc, #-4]
                    jump_back += struct.pack("<I", trampoline)

            elif self.architecture == Architecture.MIPS:
                # MIPS hook implementation
                # Jump to hook code, then jump to trampoline

                # j hook_offset (26-bit offset)
                hook_addr = func_address + len(hook_code)
                if (hook_addr & 0xF0000000) == (func_address & 0xF0000000):
                    # Same 256MB region, can use J instruction
                    jump_to_hook = struct.pack(">I", 0x08000000 | ((hook_addr >> 2) & 0x3FFFFFF))
                else:
                    # Use JAL with register
                    # lui $t9, %hi(hook_addr)
                    # ori $t9, $t9, %lo(hook_addr)
                    # jr $t9
                    # nop
                    high = (hook_addr >> 16) & 0xFFFF
                    low = hook_addr & 0xFFFF
                    jump_to_hook = struct.pack(">I", 0x3C190000 | high)  # lui t9, high
                    jump_to_hook += struct.pack(">I", 0x37390000 | low)  # ori t9, t9, low
                    jump_to_hook += struct.pack(">I", 0x03200008)  # jr t9
                    jump_to_hook += struct.pack(">I", 0x00000000)  # nop (delay slot)

                # Jump back to trampoline
                if (trampoline & 0xF0000000) == ((func_address + len(hook_code)) & 0xF0000000):
                    jump_back = struct.pack(">I", 0x08000000 | ((trampoline >> 2) & 0x3FFFFFF))
                else:
                    high = (trampoline >> 16) & 0xFFFF
                    low = trampoline & 0xFFFF
                    jump_back = struct.pack(">I", 0x3C190000 | high)  # lui t9, high
                    jump_back += struct.pack(">I", 0x37390000 | low)  # ori t9, t9, low
                    jump_back += struct.pack(">I", 0x03200008)  # jr t9
                jump_back += struct.pack(">I", 0x00000000)  # nop (delay slot)
            elif self.architecture == Architecture.PPC:
                # PowerPC hook implementation
                # b hook_offset (branch)
                hook_offset = (func_address + len(hook_code)) - func_address
                trampoline_offset = trampoline - (func_address + len(hook_code))

                if abs(hook_offset) < 0x2000000:
                    # Can use relative branch
                    jump_to_hook = struct.pack(">I", 0x48000000 | (hook_offset & 0x3FFFFFC))
                else:
                    # Use absolute branch with register
                    # lis r12, hook_addr@h
                    # ori r12, r12, hook_addr@l
                    # mtctr r12
                    # bctr
                    hook_addr = func_address + len(hook_code)
                    high = (hook_addr >> 16) & 0xFFFF
                    low = hook_addr & 0xFFFF
                    jump_to_hook = struct.pack(">I", 0x3D800000 | high)  # lis r12, high
                    jump_to_hook += struct.pack(">I", 0x618C0000 | low)  # ori r12, r12, low
                    jump_to_hook += struct.pack(">I", 0x7D8903A6)  # mtctr r12
                    jump_to_hook += struct.pack(">I", 0x4E800420)  # bctr

                # Jump back to trampoline
                if abs(trampoline_offset) < 0x2000000:
                    jump_back = struct.pack(">I", 0x48000000 | (trampoline_offset & 0x3FFFFFC))
                else:
                    high = (trampoline >> 16) & 0xFFFF
                    low = trampoline & 0xFFFF
                    jump_back = struct.pack(">I", 0x3D800000 | high)  # lis r12, high
                    jump_back += struct.pack(">I", 0x618C0000 | low)  # ori r12, r12, low
                    jump_back += struct.pack(">I", 0x7D8903A6)  # mtctr r12
                    jump_back += struct.pack(">I", 0x4E800420)  # bctr

            else:
                # 64-bit generic hook
                # Try x86-64 style first (most common)
                hook_offset = (func_address + len(hook_code)) - (func_address + 5)
                trampoline_offset = trampoline - (func_address + len(hook_code) + 5)

                # Generic fallback for unknown architectures
                # Use a simple jump pattern that works for most architectures

                if self.bits == 64:
                    if abs(hook_offset) < 0x7FFFFFFF:
                        jump_to_hook = b"\xe9" + struct.pack("<i", hook_offset)
                    else:
                        # Absolute jump via register
                        jump_to_hook = b"\x48\xb8" + struct.pack("<Q", func_address + len(hook_code))  # movabs rax, addr
                        jump_to_hook += b"\xff\xe0"  # jmp rax

                    if abs(trampoline_offset) < 0x7FFFFFFF:
                        jump_back = b"\xe9" + struct.pack("<i", trampoline_offset)
                    else:
                        jump_back = b"\x48\xb8" + struct.pack("<Q", trampoline)  # movabs rax, addr
                        jump_back += b"\xff\xe0"  # jmp rax

                else:
                    if abs(hook_offset) < 0x7FFFFFFF:
                        jump_to_hook = b"\xe9" + struct.pack("<i", hook_offset)
                    else:
                        jump_to_hook = b"\xb8" + struct.pack("<I", func_address + len(hook_code))  # mov eax, addr
                        jump_to_hook += b"\xff\xe0"  # jmp eax

                    if abs(trampoline_offset) < 0x7FFFFFFF:
                        jump_back = b"\xe9" + struct.pack("<i", trampoline_offset)
                    else:
                        jump_back = b"\xb8" + struct.pack("<I", trampoline)  # mov eax, addr
                        jump_back += b"\xff\xe0"  # jmp eax

            complete_hook = hook_code + jump_back

            # Find code cave to place the hook code
            hook_cave = self._find_code_cave(len(complete_hook))

            # Write complete hook to code cave
            self._write_bytes(hook_cave, complete_hook)

            # Recalculate jump_to_hook to point to the code cave
            if self.architecture in [Architecture.X86, Architecture.X86_64]:
                prologue_offset = hook_cave - (func_address + 5)
                if abs(prologue_offset) < 0x7FFFFFFF:
                    jump_to_hook = b"\xe9" + struct.pack("<i", prologue_offset)
                else:
                    if self.bits == 64:
                        jump_to_hook = b"\x48\xb8" + struct.pack("<Q", hook_cave)
                    else:
                        jump_to_hook = b"\xb8" + struct.pack("<I", hook_cave)
                    jump_to_hook += b"\xff\xe0"
            elif self.architecture == Architecture.ARM64:
                prologue_offset = hook_cave - func_address
                if abs(prologue_offset // 4) < 0x2000000:
                    jump_to_hook = struct.pack("<I", 0x14000000 | ((prologue_offset // 4) & 0x3FFFFFF))
                else:
                    jump_to_hook = b"\x50\x00\x00\x58"
                    jump_to_hook += b"\x00\x02\x1f\xd6"
                    jump_to_hook += struct.pack("<Q", hook_cave)
            elif self.architecture == Architecture.ARM:
                prologue_offset = hook_cave - func_address - 8
                if abs(prologue_offset // 4) < 0x1000000:
                    jump_to_hook = struct.pack("<I", 0xEA000000 | ((prologue_offset // 4) & 0xFFFFFF))
                else:
                    jump_to_hook = b"\x04\xf0\x1f\xe5"
                    jump_to_hook += struct.pack("<I", hook_cave)
            elif self.architecture == Architecture.MIPS:
                if (hook_cave & 0xF0000000) == (func_address & 0xF0000000):
                    jump_to_hook = struct.pack(">I", 0x08000000 | ((hook_cave >> 2) & 0x3FFFFFF))
                else:
                    high = (hook_cave >> 16) & 0xFFFF
                    low = hook_cave & 0xFFFF
                    jump_to_hook = struct.pack(">I", 0x3C190000 | high)
                    jump_to_hook += struct.pack(">I", 0x37390000 | low)
                    jump_to_hook += struct.pack(">I", 0x03200008)
                    jump_to_hook += struct.pack(">I", 0x00000000)
            elif self.architecture == Architecture.PPC:
                prologue_offset = hook_cave - func_address
                if abs(prologue_offset) < 0x2000000:
                    jump_to_hook = struct.pack(">I", 0x48000000 | (prologue_offset & 0x3FFFFFC))
                else:
                    high = (hook_cave >> 16) & 0xFFFF
                    low = hook_cave & 0xFFFF
                    jump_to_hook = struct.pack(">I", 0x3D800000 | high)
                    jump_to_hook += struct.pack(">I", 0x618C0000 | low)
                    jump_to_hook += struct.pack(">I", 0x7D8903A6)
                    jump_to_hook += struct.pack(">I", 0x4E800420)
            else:
                # Fallback for unknown architectures - assume x86-like
                prologue_offset = hook_cave - (func_address + 5)
                if abs(prologue_offset) < 0x7FFFFFFF:
                    jump_to_hook = b"\xe9" + struct.pack("<i", prologue_offset)
                else:
                    if self.bits == 64:
                        jump_to_hook = b"\x48\xb8" + struct.pack("<Q", hook_cave)
                    else:
                        jump_to_hook = b"\xb8" + struct.pack("<I", hook_cave)
                    jump_to_hook += b"\xff\xe0"
            # Read original prologue bytes before overwriting
            original_data: Any = self.r2.cmdj(f"pxj {len(jump_to_hook)} @ {func_address}")
            original_bytes = bytes(original_data) if original_data else b""

            # Write jump_to_hook to function prologue to redirect to hook
            self._write_bytes(func_address, jump_to_hook)

            patch = PatchInfo(
                type=PatchType.FUNCTION_HOOK,
                address=func_address,
                original_bytes=original_bytes,
                patched_bytes=jump_to_hook,
                description=f"Hooked function at {hex(func_address)}",
                metadata={
                    "preserve_original": preserve_original,
                    "hook_size": len(hook_code),
                    "hook_cave": hook_cave,
                    "trampoline": trampoline,
                    "complete_hook_size": len(complete_hook),
                },
            )
        else:
            # Simple replacement
            if not self.r2:
                raise RuntimeError("Radare2 session not opened")

            complete_hook = hook_code

            # Read original bytes
            original_hook_data: Any = self.r2.cmdj(f"pxj {len(complete_hook)} @ {func_address}")
            original_bytes = bytes(original_hook_data) if original_hook_data else b""

            patch = PatchInfo(
                type=PatchType.FUNCTION_HOOK,
                address=func_address,
                original_bytes=original_bytes,
                patched_bytes=complete_hook,
                description=f"Hooked function at {hex(func_address)}",
                metadata={
                    "preserve_original": preserve_original,
                    "hook_size": len(hook_code),
                    "trampoline": None,
                },
            )

            # Apply patch
            self._write_bytes(func_address, complete_hook)
        self.patches.append(patch)

        logger.info("Created function hook at %s", hex(func_address))
        return patch

    def _create_trampoline(self, original_address: int, hook_size: int) -> int:
        """Create trampoline for preserving original function."""
        if not self.r2:
            raise RuntimeError("Radare2 session not opened")

        # Find code cave
        code_cave = self._find_code_cave(hook_size + 16)

        # Copy original instructions
        original_code: Any = self.r2.cmdj(f"pxj {hook_size} @ {original_address}")
        self._write_bytes(code_cave, bytes(original_code))

        # Add jump back to original function
        if self.architecture in [Architecture.X86, Architecture.X86_64]:
            jump_back_offset = (original_address + hook_size) - (code_cave + hook_size + 5)
            jump_back = b"\xe9" + struct.pack("<i", jump_back_offset)
            self._write_bytes(code_cave + hook_size, jump_back)

        return code_cave

    def _find_code_cave(self, size: int) -> int:
        """Find suitable code cave for patches."""
        if not self.r2:
            raise RuntimeError("Radare2 session not opened")

        # Get sections
        sections: Any = self.r2.cmdj("iSj")

        for section in sections:
            # Look for executable sections with padding
            if section["perm"] & 0x1:
                # Scan for consecutive zeros
                section_data: Any = self.r2.cmdj(f"pxj {section['size']} @ {section['vaddr']}")
                zero_count = 0
                cave_start = 0

                for i, byte in enumerate(section_data):
                    if byte == 0:
                        if zero_count == 0:
                            cave_start = section["vaddr"] + i
                        zero_count += 1

                        if zero_count >= size:
                            logger.info("Found code cave at %s with %s bytes", hex(cave_start), zero_count)
                            return cave_start
                    else:
                        zero_count = 0

        raise ValueError(f"No suitable code cave found for {size} bytes")

    def defeat_anti_debugging(self) -> list[PatchInfo]:
        """Apply anti-debugging defeat patches."""
        if not self.r2:
            raise RuntimeError("Radare2 session not opened")

        patches_applied: list[PatchInfo] = []

        if self.architecture in [Architecture.X86, Architecture.X86_64]:
            # Patch IsDebuggerPresent
            imports: Any = self.r2.cmdj("iij")
            for imp in imports:
                if imp["name"] == "IsDebuggerPresent":
                    # Replace with XOR EAX, EAX; RET
                    patch_bytes = b"\x31\xc0\xc3"
                    patch = self.generate_nop_sled(imp["plt"], 3)
                    self._write_bytes(imp["plt"], patch_bytes)
                    patches_applied.append(patch)
                    logger.info("Defeated IsDebuggerPresent at %s", hex(imp["plt"]))

            # Find and patch inline checks
            peb_checks: Any = self.r2.cmd("/x 64a13000000000")
            for line in peb_checks.split("\n"):
                if line and "0x" in line:
                    addr = int(line.split()[0], 16)
                    # Check if it's accessing BeingDebugged flag
                    next_inst_list: Any = self.r2.cmdj(f"pdj 1 @ {addr + 8}")
                    next_inst: Any = next_inst_list[0]
                    if "0x2" in next_inst.get("opcode", ""):
                        # Patch to always return 0
                        patch = self.generate_nop_sled(addr, 16)
                        patches_applied.append(patch)
                        logger.info("Defeated PEB.BeingDebugged check at %s", hex(addr))

            # Patch NtQueryInformationProcess
            nt_query: Any = self.r2.cmd("/x b8ea000000")
            for line in nt_query.split("\n"):
                if line and "0x" in line:
                    addr = int(line.split()[0], 16)
                    # Replace with successful return
                    patch_bytes = b"\x31\xc0\xc3"
                    original_data: Any = self.r2.cmdj(f"pxj 3 @ {addr}")

                    patch = PatchInfo(
                        type=PatchType.ANTI_DEBUG_DEFEAT,
                        address=addr,
                        original_bytes=bytes(original_data),
                        patched_bytes=patch_bytes,
                        description=f"Defeated NtQueryInformationProcess at {hex(addr)}",
                        metadata={"method": "NtQueryInformationProcess"},
                    )
                    self._write_bytes(addr, patch_bytes)
                    patches_applied.append(patch)

        return patches_applied

    def _write_bytes(self, address: int, data: bytes) -> None:
        """Write bytes to address."""
        if not self.r2:
            raise RuntimeError("Radare2 session not opened")

        hex_data = data.hex()
        self.r2.cmd(f"wx {hex_data} @ {address}")

    def apply_patch(self, patch: PatchInfo) -> bool:
        """Apply a single patch."""
        try:
            self._write_bytes(patch.address, patch.patched_bytes)
            logger.info("Applied patch: %s", patch.description)
            return True
        except Exception as e:
            logger.exception("Failed to apply patch at %s: %s", hex(patch.address), e, exc_info=True)
            return False

    def revert_patch(self, patch: PatchInfo) -> bool:
        """Revert a single patch."""
        try:
            self._write_bytes(patch.address, patch.original_bytes)
            logger.info("Reverted patch: %s", patch.description)
            return True
        except Exception as e:
            logger.exception("Failed to revert patch at %s: %s", hex(patch.address), e, exc_info=True)
            return False

    def _read_binary_content(self) -> bytes:
        """Read binary content safely using a context manager."""
        with open(self.binary_path, "rb") as f:
            return f.read()

    def save_patches(self, output_file: str) -> bool:
        """Save patches to JSON file."""
        try:
            patches_data = [
                {
                    "type": patch.type.value,
                    "address": patch.address,
                    "original": patch.original_bytes.hex(),
                    "patched": patch.patched_bytes.hex(),
                    "description": patch.description,
                    "metadata": patch.metadata,
                }
                for patch in self.patches
            ]
            with open(output_file, "w") as f:
                json.dump(
                    {
                        "binary": self.binary_path,
                        "architecture": self.architecture.value if self.architecture else None,
                        "bits": self.bits,
                        "endianness": self.endianness,
                        "patches": patches_data,
                        "checksum": hashlib.sha256(self._read_binary_content()).hexdigest(),
                    },
                    f,
                    indent=2,
                )

            logger.info("Saved %s patches to %s", len(self.patches), output_file)
            return True

        except Exception as e:
            logger.exception("Failed to save patches: %s", e, exc_info=True)
            return False

    def load_patches(self, patch_file: str) -> bool:
        """Load and apply patches from JSON file."""
        try:
            with open(patch_file) as f:
                data = json.load(f)

            # Verify binary checksum
            current_checksum = hashlib.sha256(self._read_binary_content()).hexdigest()
            if data.get("checksum") != current_checksum:
                logger.warning("Binary checksum mismatch - patches may not apply correctly")

            # Load patches
            self.patches = []
            for patch_data in data["patches"]:
                patch = PatchInfo(
                    type=PatchType(patch_data["type"]),
                    address=patch_data["address"],
                    original_bytes=bytes.fromhex(patch_data["original"]),
                    patched_bytes=bytes.fromhex(patch_data["patched"]),
                    description=patch_data["description"],
                    metadata=patch_data["metadata"],
                )
                self.patches.append(patch)
                self.apply_patch(patch)

            logger.info("Loaded and applied %s patches", len(self.patches))
            return True

        except Exception as e:
            logger.exception("Failed to load patches: %s", e, exc_info=True)
            return False

    def generate_patch_script(self, script_type: str = "python") -> str:
        """Generate standalone patch script."""
        if script_type == "python":
            script = self._generate_python_script()
        elif script_type == "radare2":
            script = self._generate_radare2_script()
        elif script_type == "c":
            script = self._generate_c_patcher()
        else:
            raise ValueError(f"Unsupported script type: {script_type}")

        return script

    def _generate_python_script(self) -> str:
        """Generate Python patching script."""
        script = [
            "#!/usr/bin/env python3",
            "import sys",
            "import struct",
            "",
            "def apply_patches(binary_path):",
            "    with open(binary_path, 'r+b') as f:",
            "        patches = [",
        ]

        script.extend(f"            ({hex(patch.address)}, bytes.fromhex('{patch.patched_bytes.hex()}'))," for patch in self.patches)
        script.extend(
            [
                "        ]",
                "",
                "        for address, data in patches:",
                "            f.seek(address)",
                "            f.write(data)",
                "            print(f'Patched {len(data)} bytes at {hex(address)}')",
                "",
                "if __name__ == '__main__':",
                "    if len(sys.argv) != 2:",
                "        print('Usage: patch.py <binary>')",
                "        sys.exit(1)",
                "    apply_patches(sys.argv[1])",
                "    print('All patches applied successfully')",
            ],
        )

        return "\n".join(script)

    def _generate_radare2_script(self) -> str:
        """Generate Radare2 script."""
        script = ["#!/usr/bin/r2 -qi"]

        for patch in self.patches:
            hex_data = patch.patched_bytes.hex()
            script.append(f"wx {hex_data} @ {hex(patch.address)}")

        script.append("q")
        return "\n".join(script)

    def _generate_c_patcher(self) -> str:
        """Generate C patcher program."""
        script = [
            "#include <stdio.h>",
            "#include <stdlib.h>",
            "#include <string.h>",
            "",
            "typedef struct {",
            "    long address;",
            "    unsigned char *data;",
            "    size_t size;",
            "} Patch;",
            "",
            "int main(int argc, char *argv[]) {",
            "    if (argc != 2) {",
            '        printf("Usage: %s <binary>\\n", argv[0]);',
            "        return 1;",
            "    }",
            "",
            '    FILE *f = fopen(argv[1], "r+b");',
            "    if (!f) {",
            '        perror("Failed to open file");',
            "        return 1;",
            "    }",
            "",
            "    Patch patches[] = {",
        ]

        for patch in self.patches:
            hex_str = ",".join([f"0x{b:02x}" for b in patch.patched_bytes])
            script.append(f"        {{{hex(patch.address)}, (unsigned char[]){{{hex_str}}}, {len(patch.patched_bytes)}}},")

        script.extend(
            [
                "    };",
                "",
                "    int num_patches = sizeof(patches) / sizeof(patches[0]);",
                "    for (int i = 0; i < num_patches; i++) {",
                "        fseek(f, patches[i].address, SEEK_SET);",
                "        fwrite(patches[i].data, 1, patches[i].size, f);",
                '        printf("Patched %zu bytes at 0x%lx\\n", patches[i].size, patches[i].address);',
                "    }",
                "",
                "    fclose(f);",
                '    printf("All patches applied successfully\\n");',
                "    return 0;",
                "}",
            ],
        )

        return "\n".join(script)

    def close(self) -> None:
        """Close Radare2 session."""
        if self.r2:
            self.r2.quit()
            self.r2 = None
            logger.info("Closed Radare2 session")


def main() -> None:
    """Demonstrate usage of Radare2AdvancedPatcher."""
    import argparse

    parser = argparse.ArgumentParser(description="Radare2 Advanced Patching Engine")
    parser.add_argument("binary", help="Binary file to patch")
    parser.add_argument("-n", "--nop", metavar="ADDR:SIZE", help="Generate NOP sled at address")
    parser.add_argument("-j", "--jump", metavar="ADDR", help="Invert conditional jump at address")
    parser.add_argument(
        "-r",
        "--return",
        metavar="FUNC:VALUE",
        dest="return_value",
        help="Modify function return value",
    )
    parser.add_argument("-c", "--call", metavar="CALL:TARGET", help="Redirect call target")
    parser.add_argument("-a", "--antidebug", action="store_true", help="Defeat anti-debugging")
    parser.add_argument("-s", "--save", metavar="FILE", help="Save patches to file")
    parser.add_argument("-l", "--load", metavar="FILE", help="Load patches from file")
    parser.add_argument("-g", "--generate", metavar="TYPE", help="Generate patch script (python/radare2/c)")

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    # Create patcher instance
    patcher = Radare2AdvancedPatcher(args.binary)

    if not patcher.open(write_mode=True):
        logger.exception("Failed to open binary")
        return

    try:
        # Apply requested patches
        if args.nop:
            addr, size = args.nop.split(":")
            patcher.generate_nop_sled(int(addr, 0), int(size, 0))

        if args.jump:
            patcher.invert_conditional_jump(int(args.jump, 0))

        if args.return_value:
            func, value = args.return_value.split(":")
            patcher.modify_return_value(int(func, 0), int(value, 0))

        if args.call:
            call, target = args.call.split(":")
            patcher.redirect_call_target(int(call, 0), int(target, 0))

        if args.antidebug:
            patches = patcher.defeat_anti_debugging()
            logger.info("Applied %s anti-debugging defeat patches", len(patches))

        if args.load:
            patcher.load_patches(args.load)

        if args.save:
            patcher.save_patches(args.save)

        if args.generate:
            script = patcher.generate_patch_script(args.generate)
            output_file = f"patch.{args.generate}"
            with open(output_file, "w") as f:
                f.write(script)
            logger.info("Generated patch script: %s", output_file)

        logger.info("Total patches applied: %s", len(patcher.patches))

    finally:
        patcher.close()


if __name__ == "__main__":
    main()
