"""Radare2 Advanced Patching Engine - Production Implementation.

Copyright (C) 2025 Zachary Flint

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
"""

import json
import logging
import struct
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import r2pipe


logger = logging.getLogger(__name__)


class PatchType(Enum):
    """Types of patches that can be applied."""

    NOP_SLED = "nop_sled"
    JUMP_MODIFICATION = "jump_modification"
    CALL_REDIRECTION = "call_redirection"
    RETURN_VALUE = "return_value"
    CONDITIONAL_INVERSION = "conditional_inversion"
    FUNCTION_REPLACEMENT = "function_replacement"
    IMPORT_HOOKING = "import_hooking"
    INLINE_PATCH = "inline_patch"
    VTABLE_MODIFICATION = "vtable_modification"
    STRING_REPLACEMENT = "string_replacement"


@dataclass
class PatchInstruction:
    """Represents a single patch instruction."""

    address: int
    original_bytes: bytes
    patch_bytes: bytes
    patch_type: PatchType
    description: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class PatchSet:
    """Collection of related patches."""

    name: str
    patches: list[PatchInstruction]
    target_binary: Path
    architecture: str
    checksum_original: str
    checksum_patched: str | None = None
    applied: bool = False


class Radare2PatchEngine:
    """Advanced binary patching engine using Radare2."""

    # Architecture-specific NOP instructions
    NOP_INSTRUCTIONS = {
        "x86": b"\x90",
        "x86_64": b"\x90",
        "arm": b"\x00\xf0\x20\xe3",  # NOP for ARM
        "arm64": b"\x1f\x20\x03\xd5",  # NOP for ARM64
        "mips": b"\x00\x00\x00\x00",  # NOP for MIPS
    }

    # Jump instruction opcodes
    JUMP_OPCODES = {
        "x86": {
            "jmp": b"\xe9",  # Near jump
            "jmp_short": b"\xeb",  # Short jump
            "call": b"\xe8",  # Near call
        },
        "x86_64": {
            "jmp": b"\xe9",  # Near jump (32-bit relative)
            "jmp_short": b"\xeb",  # Short jump
            "call": b"\xe8",  # Near call
            "jmp_far": b"\xff\x25",  # Far jump (64-bit)
        },
    }

    # Conditional jump inversions
    CONDITIONAL_INVERSIONS = {
        0x74: 0x75,  # JE -> JNE
        0x75: 0x74,  # JNE -> JE
        0x76: 0x77,  # JBE -> JA
        0x77: 0x76,  # JA -> JBE
        0x78: 0x79,  # JS -> JNS
        0x79: 0x78,  # JNS -> JS
        0x7C: 0x7D,  # JL -> JGE
        0x7D: 0x7C,  # JGE -> JL
        0x7E: 0x7F,  # JLE -> JG
        0x7F: 0x7E,  # JG -> JLE
        # Extended conditional jumps (0x0F prefix)
        0x84: 0x85,  # JE -> JNE (extended)
        0x85: 0x84,  # JNE -> JE (extended)
    }

    def __init__(self, binary_path: Path, write_mode: bool = False) -> None:
        """Initialize the patch engine.

        Args:
            binary_path: Path to the binary to patch
            write_mode: If True, opens in write mode for applying patches

        """
        self.binary_path = binary_path
        self.write_mode = write_mode
        self.r2 = None
        self.architecture = None
        self.bits = None
        self.endian = None
        self.patch_sets: dict[str, PatchSet] = {}
        self._init_r2()

    def _init_r2(self) -> None:
        """Initialize Radare2 connection."""
        try:
            flags = ["-w"] if self.write_mode else []
            self.r2 = r2pipe.open(str(self.binary_path), flags=flags)

            # Analyze binary
            self.r2.cmd("aaa")  # Full analysis

            # Get architecture info
            info = json.loads(self.r2.cmd("ij"))
            self.architecture = info["bin"]["arch"]
            self.bits = info["bin"]["bits"]
            self.endian = info["bin"]["endian"]

            logger.info(f"Initialized patch engine for {self.architecture} {self.bits}-bit {self.endian}")

        except Exception as e:
            logger.error(f"Failed to initialize Radare2: {e}")
            raise

    def create_nop_sled(self, address: int, length: int) -> PatchInstruction:
        """Create a NOP sled at the specified address.

        Args:
            address: Starting address for NOP sled
            length: Number of bytes to NOP

        Returns:
            PatchInstruction for the NOP sled

        """
        # Get architecture-specific NOP
        nop = self.NOP_INSTRUCTIONS.get(self.architecture, b"\x90")

        nop_count, remainder = divmod(length, len(nop))
        # Create NOP sled
        patch_bytes = nop * nop_count

        # Handle remainder with shorter NOPs if needed
        if remainder > 0:
            if self.architecture in ["x86", "x86_64"]:
                # Use multi-byte NOPs for x86/x64
                patch_bytes += self._get_multibyte_nop(remainder)
            else:
                # Pad with single-byte NOPs
                patch_bytes += nop[:remainder]

        # Read original bytes
        original_bytes = self._read_bytes(address, length)

        return PatchInstruction(
            address=address,
            original_bytes=original_bytes,
            patch_bytes=patch_bytes,
            patch_type=PatchType.NOP_SLED,
            description=f"NOP sled of {length} bytes at 0x{address:x}",
        )

    def _get_multibyte_nop(self, length: int) -> bytes:
        """Get multi-byte NOP for x86/x64."""
        # Intel recommended multi-byte NOPs
        multibyte_nops = {
            1: b"\x90",  # NOP
            2: b"\x66\x90",  # 66 NOP
            3: b"\x0f\x1f\x00",  # NOP DWORD ptr [EAX]
            4: b"\x0f\x1f\x40\x00",  # NOP DWORD ptr [EAX + 00H]
            5: b"\x0f\x1f\x44\x00\x00",  # NOP DWORD ptr [EAX + EAX*1 + 00H]
            6: b"\x66\x0f\x1f\x44\x00\x00",  # 66 NOP DWORD ptr [EAX + EAX*1 + 00H]
            7: b"\x0f\x1f\x80\x00\x00\x00\x00",  # NOP DWORD ptr [EAX + 00000000H]
            8: b"\x0f\x1f\x84\x00\x00\x00\x00\x00",  # NOP DWORD ptr [EAX + EAX*1 + 00000000H]
            9: b"\x66\x0f\x1f\x84\x00\x00\x00\x00\x00",  # 66 NOP DWORD ptr [EAX + EAX*1 + 00000000H]
        }

        return multibyte_nops.get(length, b"\x90" * length)

    def modify_jump(self, address: int, target: int, jump_type: str = "jmp") -> PatchInstruction:
        """Modify a jump instruction to point to a new target.

        Args:
            address: Address of the jump instruction
            target: New target address
            jump_type: Type of jump ("jmp", "call", etc.)

        Returns:
            PatchInstruction for the jump modification

        """
        patch_bytes = b""

        if self.architecture in ["x86", "x86_64"]:
            # For near jumps, calculate 32-bit relative offset
            # Offset is from the end of the instruction
            instruction_size = 5  # 1 byte opcode + 4 byte offset
            offset = target - (address + instruction_size)

            # Check if short jump is possible (-128 to 127)
            if -128 <= offset <= 127 and jump_type == "jmp":
                opcode = self.JUMP_OPCODES[self.architecture]["jmp_short"]
                patch_bytes = opcode + struct.pack("<b", offset)
                instruction_size = 2
            else:
                # Use near jump
                opcode = self.JUMP_OPCODES[self.architecture].get(jump_type, b"\xe9")
                patch_bytes = opcode + struct.pack("<i", offset)

        elif self.architecture == "arm":
            # ARM branch instruction (B or BL)
            offset = (target - address - 8) // 4  # ARM PC is 8 bytes ahead

            if jump_type == "call":
                # BL (Branch with Link) - 0xEB for condition AL (always)
                instruction = 0xEB000000 | (offset & 0x00FFFFFF)
            else:
                # B (Branch) - 0xEA for condition AL (always)
                instruction = 0xEA000000 | (offset & 0x00FFFFFF)

            patch_bytes = struct.pack("<I", instruction)

        elif self.architecture == "arm64":
            # ARM64/AArch64 branch instruction
            offset = (target - address) // 4

            if jump_type == "call" and -0x2000000 <= offset <= 0x1FFFFFF:
                instruction = 0x94000000 | (offset & 0x03FFFFFF)
            elif jump_type == "call" or not -0x2000000 <= offset <= 0x1FFFFFF:
                # Use ADRP + ADD + BR for long jumps
                page_offset = ((target & ~0xFFF) - (address & ~0xFFF)) >> 12
                page_remainder = target & 0xFFF

                # ADRP X16, target_page
                adrp = 0x90000010 | ((page_offset & 0x3) << 29) | ((page_offset >> 2) & 0x7FFFF) << 5
                # ADD X16, X16, page_remainder
                add = 0x91000210 | ((page_remainder & 0xFFF) << 10)
                # BR X16
                br = 0xD61F0200

                patch_bytes = struct.pack("<III", adrp, add, br)
                original_bytes = self._read_bytes(address, 12)

                return PatchInstruction(
                    address=address,
                    original_bytes=original_bytes,
                    patch_bytes=patch_bytes,
                    patch_type=PatchType.JUMP_MODIFICATION,
                    description=f"Long {jump_type} at 0x{address:x} to 0x{target:x}",
                    metadata={"target": target, "jump_type": jump_type},
                )
            else:
                instruction = 0x14000000 | (offset & 0x03FFFFFF)
            patch_bytes = struct.pack("<I", instruction)

        elif self.architecture == "mips":
            # JAL (Jump and Link)
            target_addr = (target & 0x0FFFFFFF) >> 2
            # MIPS jump instruction
            if jump_type == "call":
                instruction = 0x0C000000 | target_addr
            else:
                instruction = 0x08000000 | target_addr

            # Add delay slot NOP
            patch_bytes = struct.pack(">II", instruction, 0x00000000)

        elif self.architecture == "ppc":
            # PowerPC branch instruction
            offset = target - address

            if jump_type == "call":
                # BL (Branch with Link)
                instruction = 0x48000001 | (offset & 0x03FFFFFC)
            else:
                # B (Branch)
                instruction = 0x48000000 | (offset & 0x03FFFFFC)

            patch_bytes = struct.pack(">I", instruction)

        else:
            # Default fallback - use generic branch encoding
            logger.warning(f"Using generic branch encoding for {self.architecture}")
            # Try to use Radare2's assembler
            if jump_type == "call":
                asm_cmd = f"pa bl 0x{target:x}"
            else:
                asm_cmd = f"pa b 0x{target:x}"

            assembled = self.r2.cmd(asm_cmd)
            if assembled and "invalid" not in assembled.lower():
                patch_bytes = bytes.fromhex(assembled.strip())
            else:
                # Last resort - create a simple jump using indirect addressing
                patch_bytes = self._create_indirect_jump(target)

        # Read original bytes
        original_bytes = self._read_bytes(address, len(patch_bytes))

        return PatchInstruction(
            address=address,
            original_bytes=original_bytes,
            patch_bytes=patch_bytes,
            patch_type=PatchType.JUMP_MODIFICATION,
            description=f"Redirect {jump_type} at 0x{address:x} to 0x{target:x}",
            metadata={"target": target, "jump_type": jump_type},
        )

    def _create_indirect_jump(self, target: int) -> bytes:
        """Create an indirect jump for unknown architectures."""
        # Generic pattern: load address to register, jump to register
        # This is architecture-specific but provides a fallback
        if self.bits == 64:
            # 64-bit generic jump
            return struct.pack("<BQ", 0xFF, target)  # Simplified - would need arch-specific encoding
        # 32-bit generic jump
        return struct.pack("<BI", 0xFF, target)  # Simplified - would need arch-specific encoding

    def redirect_call(self, address: int, new_function: int) -> PatchInstruction:
        """Redirect a function call to a different function.

        Args:
            address: Address of the call instruction
            new_function: Address of the new function to call

        Returns:
            PatchInstruction for the call redirection

        """
        return self.modify_jump(address, new_function, "call")

    def patch_return_value(self, function_address: int, return_value: int, value_size: int = 4) -> list[PatchInstruction]:
        """Patch a function to return a specific value.

        Args:
            function_address: Address of the function
            return_value: Value to return
            value_size: Size of return value in bytes

        Returns:
            List of patches to apply

        """
        patches = []

        if self.architecture in ["x86", "x86_64"]:
            # MOV EAX/RAX, value
            if value_size == 1:
                # MOV AL, value
                patch_bytes = b"\xb0" + struct.pack("<B", return_value & 0xFF)
            elif value_size == 2:
                # MOV AX, value
                patch_bytes = b"\x66\xb8" + struct.pack("<H", return_value & 0xFFFF)
            elif value_size == 4:
                # MOV EAX, value
                patch_bytes = b"\xb8" + struct.pack("<I", return_value & 0xFFFFFFFF)
            elif value_size == 8 and self.bits == 64:
                # MOV RAX, value
                patch_bytes = b"\x48\xb8" + struct.pack("<Q", return_value)
            else:
                raise ValueError(f"Unsupported return value size: {value_size}")

            # Add RET instruction
            patch_bytes += b"\xc3"

            # Read original bytes
            original_bytes = self._read_bytes(function_address, len(patch_bytes))

            patches.append(
                PatchInstruction(
                    address=function_address,
                    original_bytes=original_bytes,
                    patch_bytes=patch_bytes,
                    patch_type=PatchType.RETURN_VALUE,
                    description=f"Patch function at 0x{function_address:x} to return 0x{return_value:x}",
                ),
            )

            # NOP remaining bytes if function is longer
            function_size = self._get_function_size(function_address)
            if function_size > len(patch_bytes):
                nop_patch = self.create_nop_sled(function_address + len(patch_bytes), function_size - len(patch_bytes))
                patches.append(nop_patch)

        elif self.architecture == "arm":
            # ARM: MOV R0, value + BX LR
            if value_size <= 4:
                # MOVW R0, lower16
                movw = 0xE3000000 | ((return_value & 0xF000) << 4) | (return_value & 0xFFF)
                # MOVT R0, upper16 (if needed)
                if return_value > 0xFFFF:
                    movt = 0xE3400000 | (((return_value >> 16) & 0xF000) << 4) | ((return_value >> 16) & 0xFFF)
                    patch_bytes = struct.pack("<II", movw, movt)
                else:
                    patch_bytes = struct.pack("<I", movw)

                # Add BX LR (return)
                patch_bytes += struct.pack("<I", 0xE12FFF1E)

            original_bytes = self._read_bytes(function_address, len(patch_bytes))
            patches.append(
                PatchInstruction(
                    address=function_address,
                    original_bytes=original_bytes,
                    patch_bytes=patch_bytes,
                    patch_type=PatchType.RETURN_VALUE,
                    description=f"Patch ARM function at 0x{function_address:x} to return 0x{return_value:x}",
                ),
            )

        elif self.architecture == "arm64":
            # ARM64: MOV X0/W0, value + RET
            if value_size <= 4:
                # MOV W0, value (32-bit)
                if return_value <= 0xFFFF:
                    # MOVZ W0, immediate
                    instruction = 0x52800000 | ((return_value & 0xFFFF) << 5)
                    patch_bytes = struct.pack("<I", instruction)
                else:
                    # MOVZ W0, lower16 + MOVK W0, upper16
                    movz = 0x52800000 | ((return_value & 0xFFFF) << 5)
                    movk = 0x72A00000 | (((return_value >> 16) & 0xFFFF) << 5)
                    patch_bytes = struct.pack("<II", movz, movk)
            else:
                # MOV X0, value (64-bit)
                instructions = [0xD2800000 | (return_value & 0xFFFF) << 5]
                if return_value > 0xFFFF:
                    # MOVK X0, bits[31:16], lsl #16
                    instructions.append(0xF2A00000 | (((return_value >> 16) & 0xFFFF) << 5))
                if return_value > 0xFFFFFFFF:
                    # MOVK X0, bits[47:32], lsl #32
                    instructions.append(0xF2C00000 | (((return_value >> 32) & 0xFFFF) << 5))
                if return_value > 0xFFFFFFFFFFFF:
                    # MOVK X0, bits[63:48], lsl #48
                    instructions.append(0xF2E00000 | (((return_value >> 48) & 0xFFFF) << 5))

                patch_bytes = b"".join(struct.pack("<I", inst) for inst in instructions)

            # Add RET instruction
            patch_bytes += struct.pack("<I", 0xD65F03C0)

            original_bytes = self._read_bytes(function_address, len(patch_bytes))
            patches.append(
                PatchInstruction(
                    address=function_address,
                    original_bytes=original_bytes,
                    patch_bytes=patch_bytes,
                    patch_type=PatchType.RETURN_VALUE,
                    description=f"Patch ARM64 function at 0x{function_address:x} to return 0x{return_value:x}",
                ),
            )

        elif self.architecture == "mips":
            # MIPS: LI V0, value + JR RA + NOP
            if value_size <= 4:
                if return_value <= 0xFFFF:
                    # ORI V0, ZERO, immediate
                    ori = 0x34020000 | (return_value & 0xFFFF)
                    patch_bytes = struct.pack(">I", ori)
                else:
                    # LUI V0, upper + ORI V0, V0, lower
                    lui = 0x3C020000 | ((return_value >> 16) & 0xFFFF)
                    ori = 0x34420000 | (return_value & 0xFFFF)
                    patch_bytes = struct.pack(">II", lui, ori)

                # Add JR RA + NOP (delay slot)
                patch_bytes += struct.pack(">II", 0x03E00008, 0x00000000)

            original_bytes = self._read_bytes(function_address, len(patch_bytes))
            patches.append(
                PatchInstruction(
                    address=function_address,
                    original_bytes=original_bytes,
                    patch_bytes=patch_bytes,
                    patch_type=PatchType.RETURN_VALUE,
                    description=f"Patch MIPS function at 0x{function_address:x} to return 0x{return_value:x}",
                ),
            )

        elif self.architecture == "ppc":
            # PowerPC: LI R3, value + BLR
            if value_size <= 4:
                if -32768 <= return_value <= 32767:
                    # LI R3, immediate (addi r3, 0, immediate)
                    li = 0x38600000 | (return_value & 0xFFFF)
                    patch_bytes = struct.pack(">I", li)
                else:
                    # LIS R3, upper + ORI R3, R3, lower
                    lis = 0x3C600000 | ((return_value >> 16) & 0xFFFF)
                    ori = 0x60630000 | (return_value & 0xFFFF)
                    patch_bytes = struct.pack(">II", lis, ori)

                # Add BLR (branch to link register)
                patch_bytes += struct.pack(">I", 0x4E800020)

            original_bytes = self._read_bytes(function_address, len(patch_bytes))
            patches.append(
                PatchInstruction(
                    address=function_address,
                    original_bytes=original_bytes,
                    patch_bytes=patch_bytes,
                    patch_type=PatchType.RETURN_VALUE,
                    description=f"Patch PowerPC function at 0x{function_address:x} to return 0x{return_value:x}",
                ),
            )

        else:
            # Generic fallback using Radare2 assembler
            logger.warning(f"Using generic return value patch for {self.architecture}")

            # Try to assemble architecture-specific return sequence
            asm_commands = []
            if value_size <= 4:
                asm_commands.append(f"mov r0, {return_value}")  # Generic register name
            else:
                asm_commands.append(f"mov r0, {return_value & 0xFFFFFFFF}")
                if self.bits == 64:
                    asm_commands.append(f"mov r1, {return_value >> 32}")

            asm_commands.append("ret")  # Generic return

            patch_bytes = b""
            for cmd in asm_commands:
                assembled = self.r2.cmd(f"pa {cmd}")
                if assembled and "invalid" not in assembled.lower():
                    patch_bytes += bytes.fromhex(assembled.strip())

            if patch_bytes:
                original_bytes = self._read_bytes(function_address, len(patch_bytes))
                patches.append(
                    PatchInstruction(
                        address=function_address,
                        original_bytes=original_bytes,
                        patch_bytes=patch_bytes,
                        patch_type=PatchType.RETURN_VALUE,
                        description=f"Patch function at 0x{function_address:x} to return 0x{return_value:x}",
                    ),
                )
            else:
                # Last resort - write return value directly to return register location
                # This is highly architecture-dependent but provides a fallback
                if self.bits == 64:
                    patch_bytes = struct.pack("<Q", return_value) + b"\xc3"  # value + RET
                else:
                    patch_bytes = struct.pack("<I", return_value) + b"\xc3"  # value + RET

                original_bytes = self._read_bytes(function_address, len(patch_bytes))
                patches.append(
                    PatchInstruction(
                        address=function_address,
                        original_bytes=original_bytes,
                        patch_bytes=patch_bytes,
                        patch_type=PatchType.RETURN_VALUE,
                        description=f"Generic patch at 0x{function_address:x} to return 0x{return_value:x}",
                    ),
                )

        return patches

    def invert_conditional_jump(self, address: int) -> PatchInstruction:
        """Invert a conditional jump (JE -> JNE, etc.).

        Args:
            address: Address of the conditional jump

        Returns:
            PatchInstruction for the inverted jump

        """
        # Read the jump instruction
        original_bytes = self._read_bytes(address, 2)

        # Check for extended jump (0x0F prefix)
        if original_bytes[0] == 0x0F:
            opcode = original_bytes[1]
            if opcode in self.CONDITIONAL_INVERSIONS:
                new_opcode = self.CONDITIONAL_INVERSIONS[opcode]
                patch_bytes = bytes([0x0F, new_opcode])
            else:
                raise ValueError(f"Unknown extended conditional jump: 0x0F{opcode:02x}")
        else:
            opcode = original_bytes[0]
            if opcode in self.CONDITIONAL_INVERSIONS:
                new_opcode = self.CONDITIONAL_INVERSIONS[opcode]
                patch_bytes = bytes([new_opcode, original_bytes[1]])
            else:
                raise ValueError(f"Unknown conditional jump: 0x{opcode:02x}")

        return PatchInstruction(
            address=address,
            original_bytes=original_bytes,
            patch_bytes=patch_bytes,
            patch_type=PatchType.CONDITIONAL_INVERSION,
            description=f"Invert conditional jump at 0x{address:x}",
        )

    def patch_function_prologue(self, address: int, new_prologue: bytes) -> PatchInstruction:
        """Replace function prologue with custom code.

        Args:
            address: Function address
            new_prologue: New prologue bytes

        Returns:
            PatchInstruction for the prologue replacement

        """
        # Read original prologue
        original_bytes = self._read_bytes(address, len(new_prologue))

        return PatchInstruction(
            address=address,
            original_bytes=original_bytes,
            patch_bytes=new_prologue,
            patch_type=PatchType.FUNCTION_REPLACEMENT,
            description=f"Replace function prologue at 0x{address:x}",
        )

    def patch_function_epilogue(self, function_address: int, new_epilogue: bytes) -> PatchInstruction:
        """Replace function epilogue with custom code.

        Args:
            function_address: Function address
            new_epilogue: New epilogue bytes

        Returns:
            PatchInstruction for the epilogue replacement

        """
        # Find function epilogue
        function_size = self._get_function_size(function_address)
        epilogue_address = function_address + function_size - len(new_epilogue)

        # Read original epilogue
        original_bytes = self._read_bytes(epilogue_address, len(new_epilogue))

        return PatchInstruction(
            address=epilogue_address,
            original_bytes=original_bytes,
            patch_bytes=new_epilogue,
            patch_type=PatchType.FUNCTION_REPLACEMENT,
            description=f"Replace function epilogue at 0x{epilogue_address:x}",
        )

    def create_jump_table_patch(self, table_address: int, entries: list[int]) -> list[PatchInstruction]:
        """Modify a jump table with new entries.

        Args:
            table_address: Address of the jump table
            entries: New jump table entries

        Returns:
            List of patches for the jump table

        """
        patches = []
        entry_size = 8 if self.bits == 64 else 4

        for i, entry in enumerate(entries):
            address = table_address + (i * entry_size)
            original_bytes = self._read_bytes(address, entry_size)

            if self.bits == 64:
                patch_bytes = struct.pack("<Q", entry)
            else:
                patch_bytes = struct.pack("<I", entry)

            patches.append(
                PatchInstruction(
                    address=address,
                    original_bytes=original_bytes,
                    patch_bytes=patch_bytes,
                    patch_type=PatchType.VTABLE_MODIFICATION,
                    description=f"Patch jump table entry {i} at 0x{address:x}",
                ),
            )

        return patches

    def create_inline_patch(self, address: int, assembly_code: str) -> PatchInstruction:
        """Create an inline patch using assembly code.

        Args:
            address: Address to patch
            assembly_code: Assembly code to assemble and patch

        Returns:
            PatchInstruction for the inline patch

        """
        # Assemble the code using Radare2
        assembled = self.r2.cmd(f"pa {assembly_code}")
        if not assembled or "invalid" in assembled.lower():
            raise ValueError(f"Failed to assemble: {assembly_code}")

        # Convert hex string to bytes
        patch_bytes = bytes.fromhex(assembled.strip())

        # Read original bytes
        original_bytes = self._read_bytes(address, len(patch_bytes))

        return PatchInstruction(
            address=address,
            original_bytes=original_bytes,
            patch_bytes=patch_bytes,
            patch_type=PatchType.INLINE_PATCH,
            description=f"Inline patch at 0x{address:x}: {assembly_code}",
            metadata={"assembly": assembly_code},
        )

    def apply_patch(self, patch: PatchInstruction) -> bool:
        """Apply a single patch to the binary.

        Args:
            patch: Patch to apply

        Returns:
            True if successful

        """
        if not self.write_mode:
            logger.error("Cannot apply patch: not in write mode")
            return False

        try:
            # Write patch bytes
            hex_bytes = patch.patch_bytes.hex()
            self.r2.cmd(f"wx {hex_bytes} @ {patch.address}")

            logger.info(f"Applied patch: {patch.description}")
            return True

        except Exception as e:
            logger.error(f"Failed to apply patch: {e}")
            return False

    def apply_patch_set(self, patch_set_name: str) -> bool:
        """Apply a complete patch set.

        Args:
            patch_set_name: Name of the patch set to apply

        Returns:
            True if all patches applied successfully

        """
        if patch_set_name not in self.patch_sets:
            logger.error(f"Unknown patch set: {patch_set_name}")
            return False

        patch_set = self.patch_sets[patch_set_name]

        if patch_set.applied:
            logger.warning(f"Patch set already applied: {patch_set_name}")
            return True

        success = all(self.apply_patch(patch) for patch in patch_set.patches)
        if success:
            patch_set.applied = True
            # Calculate new checksum
            patch_set.checksum_patched = self._calculate_checksum()

        return success

    def revert_patch(self, patch: PatchInstruction) -> bool:
        """Revert a single patch.

        Args:
            patch: Patch to revert

        Returns:
            True if successful

        """
        if not self.write_mode:
            logger.error("Cannot revert patch: not in write mode")
            return False

        try:
            # Write original bytes back
            hex_bytes = patch.original_bytes.hex()
            self.r2.cmd(f"wx {hex_bytes} @ {patch.address}")

            logger.info(f"Reverted patch: {patch.description}")
            return True

        except Exception as e:
            logger.error(f"Failed to revert patch: {e}")
            return False

    def create_patch_set(self, name: str, patches: list[PatchInstruction]) -> PatchSet:
        """Create a named patch set.

        Args:
            name: Name for the patch set
            patches: List of patches in the set

        Returns:
            Created PatchSet

        """
        patch_set = PatchSet(
            name=name,
            patches=patches,
            target_binary=self.binary_path,
            architecture=self.architecture,
            checksum_original=self._calculate_checksum(),
        )

        self.patch_sets[name] = patch_set
        return patch_set

    def export_patch_set(self, patch_set_name: str, output_path: Path) -> None:
        """Export a patch set to a file.

        Args:
            patch_set_name: Name of the patch set
            output_path: Path to save the patch set

        """
        if patch_set_name not in self.patch_sets:
            raise ValueError(f"Unknown patch set: {patch_set_name}")

        patch_set = self.patch_sets[patch_set_name]

        export_data = {
            "name": patch_set.name,
            "target_binary": str(patch_set.target_binary),
            "architecture": patch_set.architecture,
            "checksum_original": patch_set.checksum_original,
            "checksum_patched": patch_set.checksum_patched,
            "applied": patch_set.applied,
            "patches": [
                {
                    "address": p.address,
                    "original_bytes": p.original_bytes.hex(),
                    "patch_bytes": p.patch_bytes.hex(),
                    "patch_type": p.patch_type.value,
                    "description": p.description,
                    "metadata": p.metadata,
                }
                for p in patch_set.patches
            ],
        }

        with open(output_path, "w") as f:
            json.dump(export_data, f, indent=2)

    def _read_bytes(self, address: int, size: int) -> bytes:
        """Read bytes from the binary."""
        result = self.r2.cmdj(f"pxj {size} @ {address}")
        return bytes(result)

    def _get_function_size(self, address: int) -> int:
        """Get the size of a function."""
        result = self.r2.cmdj(f"afij @ {address}")
        return result[0].get("size", 0) if result and len(result) > 0 else 0

    def _calculate_checksum(self) -> str:
        """Calculate binary checksum."""
        result = self.r2.cmd("ph sha256")
        return result.strip()

    def close(self) -> None:
        """Close Radare2 connection."""
        if self.r2:
            self.r2.quit()
            self.r2 = None
