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

This module provides comprehensive binary patching capabilities using
Radare2 as the backend analysis and manipulation engine. Supports multiple
architectures and patch types for software licensing protection analysis.

Classes:
    PatchType: Enumeration of supported patch types.
    PatchInstruction: Represents a single atomic patch operation.
    PatchSet: Groups related patches for batch application.
    Radare2PatchEngine: Main patching engine implementation.

Example:
    >>> engine = Radare2PatchEngine(Path("binary"), write_mode=True)
    >>> nop_patch = engine.create_nop_sled(0x1000, 10)
    >>> patch_set = engine.create_patch_set("disable_checks", [nop_patch])
    >>> engine.apply_patch_set("disable_checks")
    >>> engine.close()
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
    """Represents a single patch instruction to be applied to a binary.

    Contains the address, original bytecode, new bytecode, patch type,
    and metadata for a single atomic patch operation.

    Attributes:
        address (int): Target address in the binary where the patch is
            applied.
        original_bytes (bytes): Original bytecode at the target address
            before patching.
        patch_bytes (bytes): New bytecode to write at the target address.
        patch_type (PatchType): Type of patch (NOP, jump, etc.).
        description (str): Human-readable description of the patch.
        metadata (dict[str, Any]): Additional metadata about the patch,
            such as target addresses or instruction types.
    """

    address: int
    original_bytes: bytes
    patch_bytes: bytes
    patch_type: PatchType
    description: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class PatchSet:
    """Collection of related patches for a target binary.

    Groups multiple patch instructions into a named set with metadata
    about the target binary, architecture, and application state.

    Attributes:
        name (str): Name of the patch set (used as identifier).
        patches (list[PatchInstruction]): List of patch instructions
            in this set.
        target_binary (Path): Path to the binary this patch set targets.
        architecture (str): Architecture of the target binary (x86, arm64,
            etc.).
        checksum_original (str): SHA256 checksum of the original binary.
        checksum_patched (str | None): SHA256 checksum after patches
            applied. None if not yet applied.
        applied (bool): Whether all patches in the set have been applied.
    """

    name: str
    patches: list[PatchInstruction]
    target_binary: Path
    architecture: str
    checksum_original: str
    checksum_patched: str | None = None
    applied: bool = False


class Radare2PatchEngine:
    """Advanced binary patching engine using Radare2.

    Provides comprehensive patching capabilities for multiple architectures
    including x86, x86_64, ARM, ARM64, MIPS, and PowerPC. Supports NOP
    sleds, jump modifications, return value patching, conditional jump
    inversions, and inline assembly patching. Manages patch sets and
    tracks binary checksums for integrity validation.

    Attributes:
        NOP_INSTRUCTIONS (dict): Architecture-specific NOP bytecode.
        JUMP_OPCODES (dict): Jump instruction opcodes by architecture.
        CONDITIONAL_INVERSIONS (dict): Mapping of conditional jump
            opcodes to their inverted forms.
    """

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

        Opens a Radare2 connection to the binary and performs initial
        analysis. Extracts architecture information that is used for
        architecture-specific patch generation.

        Args:
            binary_path (Path): Path to the binary file to patch.
            write_mode (bool): If True, opens in write mode for applying
                patches. Defaults to False (read-only).

        Returns:
            None

        Raises:
            RuntimeError: If Radare2 connection fails or binary analysis
                fails.
        """
        self.binary_path = binary_path
        self.write_mode = write_mode
        self.r2: Any | None = None
        self.architecture: str | None = None
        self.bits: int | None = None
        self.endian: str | None = None
        self.patch_sets: dict[str, PatchSet] = {}
        self._init_r2()

    def _init_r2(self) -> None:
        """Initialize Radare2 connection and analyze the binary.

        Opens a Radare2 pipe connection to the target binary, performs
        initial analysis (aaa), and extracts architecture information.

        Returns:
            None

        Raises:
            RuntimeError: If r2pipe connection fails or binary analysis
                fails.
        """
        try:
            flags = ["-w"] if self.write_mode else []
            self.r2 = r2pipe.open(str(self.binary_path), flags=flags)

            if self.r2 is None:
                raise RuntimeError("Failed to open r2pipe connection")

            # Analyze binary
            self.r2.cmd("aaa")

            # Get architecture info
            info_str: str = self.r2.cmd("ij")
            info: dict[str, Any] = json.loads(info_str)
            bin_info: dict[str, Any] = info["bin"]
            self.architecture = str(bin_info["arch"])
            self.bits = int(bin_info["bits"])
            self.endian = str(bin_info["endian"])

            logger.info("Initialized patch engine for %s %d-bit %s", self.architecture, self.bits, self.endian)

        except Exception as e:
            logger.exception("Failed to initialize Radare2: %s", e)
            raise

    def create_nop_sled(self, address: int, length: int) -> PatchInstruction:
        """Create a NOP sled at the specified address.

        Generates a sequence of NOP (no-operation) instructions to fill
        a specified range of bytes. Handles remainder bytes by using
        multi-byte NOPs for x86/x86_64 architectures.

        Args:
            address (int): Starting address for the NOP sled.
            length (int): Number of bytes to fill with NOPs.

        Returns:
            PatchInstruction: Patch instruction representing the NOP sled.
        """
        # Get architecture-specific NOP
        arch: str = self.architecture if self.architecture is not None else "x86"
        nop = self.NOP_INSTRUCTIONS.get(arch, b"\x90")

        nop_count, remainder = divmod(length, len(nop))
        # Create NOP sled
        patch_bytes = nop * nop_count

        # Handle remainder with shorter NOPs if needed
        if remainder > 0:
            if arch in ["x86", "x86_64"]:
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
        """Get multi-byte NOP instruction for x86/x86_64 architectures.

        Returns Intel-recommended multi-byte NOP instructions that are
        optimal for filling code gaps while maintaining proper alignment
        and instruction decode efficiency.

        Args:
            length (int): Number of bytes needed for the NOP instruction.

        Returns:
            bytes: Multi-byte NOP instruction bytes matching the requested
                length. Falls back to single-byte NOPs if length exceeds
                9 bytes.
        """
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
        """Modify a jump instruction to point to a new target address.

        Generates architecture-specific jump/call instructions with proper
        offset calculation. Handles short jumps, near jumps, and far jumps
        depending on distance and architecture. Falls back to Radare2
        assembler for unknown architectures.

        Args:
            address (int): Address of the jump instruction to modify.
            target (int): New target address for the jump.
            jump_type (str): Type of jump instruction ("jmp", "call", etc.).
                Defaults to "jmp".

        Returns:
            PatchInstruction: Jump modification patch instruction with
                metadata containing target and jump type.

        Raises:
            RuntimeError: If r2pipe is not initialized when assembling
                for unknown architectures.
        """
        patch_bytes = b""
        arch: str = self.architecture if self.architecture is not None else "x86"

        if arch in ["x86", "x86_64"]:
            # For near jumps, calculate 32-bit relative offset
            # Offset is from the end of the instruction
            instruction_size = 5  # 1 byte opcode + 4 byte offset
            offset = target - (address + instruction_size)

            # Check if short jump is possible (-128 to 127)
            if -128 <= offset <= 127 and jump_type == "jmp":
                opcode = self.JUMP_OPCODES[arch]["jmp_short"]
                patch_bytes = opcode + struct.pack("<b", offset)
                instruction_size = 2
            else:
                # Use near jump
                opcode = self.JUMP_OPCODES[arch].get(jump_type, b"\xe9")
                patch_bytes = opcode + struct.pack("<i", offset)

        elif arch == "arm":
            # ARM branch instruction (B or BL)
            offset = (target - address - 8) // 4  # ARM PC is 8 bytes ahead

            if jump_type == "call":
                # BL (Branch with Link) - 0xEB for condition AL (always)
                instruction = 0xEB000000 | (offset & 0x00FFFFFF)
            else:
                # B (Branch) - 0xEA for condition AL (always)
                instruction = 0xEA000000 | (offset & 0x00FFFFFF)

            patch_bytes = struct.pack("<I", instruction)

        elif arch == "arm64":
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

        elif arch == "mips":
            # JAL (Jump and Link)
            target_addr = (target & 0x0FFFFFFF) >> 2
            # MIPS jump instruction
            if jump_type == "call":
                instruction = 0x0C000000 | target_addr
            else:
                instruction = 0x08000000 | target_addr

            # Add delay slot NOP
            patch_bytes = struct.pack(">II", instruction, 0x00000000)

        elif arch == "ppc":
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
            logger.warning("Using generic branch encoding for %s", arch)

            if self.r2 is None:
                raise RuntimeError("r2pipe not initialized")

            # Try to use Radare2's assembler
            if jump_type == "call":
                asm_cmd = f"pa bl 0x{target:x}"
            else:
                asm_cmd = f"pa b 0x{target:x}"

            assembled: str = self.r2.cmd(asm_cmd)
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
        """Create an indirect jump instruction for unknown architectures.

        Generates a generic indirect jump pattern by loading target address
        into a register and jumping to that register. This provides a
        fallback mechanism for architectures without built-in support.

        Args:
            target (int): Target address for the jump instruction.

        Returns:
            bytes: Indirect jump instruction bytes compatible with the
                architecture bitness (32-bit or 64-bit).
        """
        # Generic pattern: load address to register, jump to register
        # This is architecture-specific but provides a fallback
        bits: int = self.bits if self.bits is not None else 32
        if bits == 64:
            # 64-bit generic jump
            return struct.pack("<BQ", 0xFF, target)
        # 32-bit generic jump
        return struct.pack("<BI", 0xFF, target)

    def redirect_call(self, address: int, new_function: int) -> PatchInstruction:
        """Redirect a function call to a different function address.

        Modifies a call instruction at the specified address to invoke a
        different function instead. Internally uses modify_jump with
        "call" jump type.

        Args:
            address (int): Address of the call instruction to modify.
            new_function (int): Address of the new function to call.

        Returns:
            PatchInstruction: Call redirection patch instruction.
        """
        return self.modify_jump(address, new_function, "call")

    def patch_return_value(self, function_address: int, return_value: int, value_size: int = 4) -> list[PatchInstruction]:
        """Patch a function to return a specific value immediately.

        Replaces function prologue with architecture-specific code to load
        a return value into the appropriate register and return. Handles
        multi-byte return values on 64-bit architectures. May append NOP
        sled if function is longer than generated patch code.

        Args:
            function_address (int): Starting address of the function to patch.
            return_value (int): Value to load into return register.
            value_size (int): Size of return value in bytes. Defaults to 4.

        Returns:
            list[PatchInstruction]: List of patch instructions required
                to implement the return value patch. May contain multiple
                instructions for NOP padding.

        Raises:
            ValueError: If the return value size is unsupported for the
                target architecture.
            RuntimeError: If r2pipe is not initialized when using generic
                fallback patching.
        """
        patches: list[PatchInstruction] = []
        arch: str = self.architecture if self.architecture is not None else "x86"
        bits: int = self.bits if self.bits is not None else 32

        if arch in ["x86", "x86_64"]:
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
            elif value_size == 8 and bits == 64:
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

        elif arch == "arm":
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

        elif arch == "arm64":
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

        elif arch == "mips":
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

        elif arch == "ppc":
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
            logger.warning("Using generic return value patch for %s", arch)

            if self.r2 is None:
                raise RuntimeError("r2pipe not initialized")

            # Try to assemble architecture-specific return sequence
            asm_commands: list[str] = []
            if value_size <= 4:
                asm_commands.append(f"mov r0, {return_value}")
            else:
                asm_commands.append(f"mov r0, {return_value & 0xFFFFFFFF}")
                if bits == 64:
                    asm_commands.append(f"mov r1, {return_value >> 32}")

            asm_commands.append("ret")

            patch_bytes = b""
            for cmd in asm_commands:
                assembled: str = self.r2.cmd(f"pa {cmd}")
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
                if bits == 64:
                    patch_bytes = struct.pack("<Q", return_value) + b"\xc3"
                else:
                    patch_bytes = struct.pack("<I", return_value) + b"\xc3"

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
        """Invert a conditional jump instruction.

        Flips the condition of a conditional jump instruction (e.g., JE
        becomes JNE). Supports both single-byte conditional jumps and
        two-byte extended conditional jumps with 0x0F prefix. Uses
        CONDITIONAL_INVERSIONS mapping to find the inverted opcode.

        Args:
            address (int): Address of the conditional jump instruction.

        Returns:
            PatchInstruction: Conditional jump inversion patch instruction
                with inverted opcode.

        Raises:
            ValueError: If jump instruction opcode is not recognized in
                CONDITIONAL_INVERSIONS mapping.
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
        """Replace a function prologue with custom code.

        Overwrites the function prologue at the specified address with
        custom bytecode. Useful for skipping stack frame setup or
        modifying register initialization at function entry.

        Args:
            address (int): Function address (prologue start).
            new_prologue (bytes): New prologue bytecode to write.

        Returns:
            PatchInstruction: Prologue replacement patch instruction.
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
        """Replace a function epilogue with custom code.

        Locates the function epilogue at the end of the specified function
        and replaces it with custom bytecode. Epilogue address is calculated
        by subtracting epilogue length from function size.

        Args:
            function_address (int): Starting address of the function.
            new_epilogue (bytes): New epilogue bytecode to write.

        Returns:
            PatchInstruction: Epilogue replacement patch instruction.
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
        """Modify a jump table with new entry addresses.

        Creates a series of patch instructions to replace jump table
        entries with new target addresses. Entry size is automatically
        determined based on architecture bitness (4 bytes for 32-bit,
        8 bytes for 64-bit).

        Args:
            table_address (int): Address of the jump table.
            entries (list[int]): List of new jump table entry addresses.

        Returns:
            list[PatchInstruction]: List of patch instructions, one per
                table entry, in sequential memory layout.
        """
        patches: list[PatchInstruction] = []
        bits: int = self.bits if self.bits is not None else 32
        entry_size = 8 if bits == 64 else 4

        for i, entry in enumerate(entries):
            address = table_address + (i * entry_size)
            original_bytes = self._read_bytes(address, entry_size)

            if bits == 64:
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

        Assembles the provided assembly code using Radare2's assembler
        and creates a patch instruction. Validates that assembly succeeds
        before returning the patch instruction.

        Args:
            address (int): Address to apply the inline patch.
            assembly_code (str): Assembly code to assemble and patch at
                the address.

        Returns:
            PatchInstruction: Inline patch instruction with assembled
                bytecode and assembly metadata.

        Raises:
            RuntimeError: If r2pipe is not initialized.
            ValueError: If assembly code fails to assemble or produces
                invalid output.
        """
        if self.r2 is None:
            raise RuntimeError("r2pipe not initialized")

        # Assemble the code using Radare2
        assembled: str = self.r2.cmd(f"pa {assembly_code}")
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
        """Apply a single patch instruction to the binary.

        Writes patch bytecode to the specified address using Radare2's
        write command. Requires write_mode to be enabled. Logs success
        and failure details.

        Args:
            patch (PatchInstruction): Patch instruction to apply.

        Returns:
            bool: True if patch was applied successfully, False if not in
                write mode or Radare2 is not initialized.
        """
        if not self.write_mode:
            logger.exception("Cannot apply patch: not in write mode")
            return False

        if self.r2 is None:
            logger.exception("Cannot apply patch: r2pipe not initialized")
            return False

        try:
            # Write patch bytes
            hex_bytes = patch.patch_bytes.hex()
            self.r2.cmd(f"wx {hex_bytes} @ {patch.address}")

            logger.info("Applied patch: %s", patch.description)
            return True

        except Exception as e:
            logger.exception("Failed to apply patch: %s", e)
            return False

    def apply_patch_set(self, patch_set_name: str) -> bool:
        """Apply a complete patch set to the binary.

        Applies all patch instructions in the named patch set sequentially.
        Updates patch_set.applied flag and calculates patched checksum upon
        successful application of all patches.

        Args:
            patch_set_name (str): Name of the patch set to apply.

        Returns:
            bool: True if all patches in the set were applied successfully,
                False if patch set not found or any patch failed.
        """
        if patch_set_name not in self.patch_sets:
            logger.exception("Unknown patch set: %s", patch_set_name)
            return False

        patch_set = self.patch_sets[patch_set_name]

        if patch_set.applied:
            logger.warning("Patch set already applied: %s", patch_set_name)
            return True

        success = all(self.apply_patch(patch) for patch in patch_set.patches)
        if success:
            patch_set.applied = True
            # Calculate new checksum
            patch_set.checksum_patched = self._calculate_checksum()

        return success

    def revert_patch(self, patch: PatchInstruction) -> bool:
        """Revert a single patch instruction.

        Restores the original bytecode for a patch instruction at its
        address. Requires write_mode to be enabled. Logs success and
        failure details.

        Args:
            patch (PatchInstruction): Patch instruction to revert.

        Returns:
            bool: True if patch was reverted successfully, False if not in
                write mode or Radare2 is not initialized.
        """
        if not self.write_mode:
            logger.exception("Cannot revert patch: not in write mode")
            return False

        if self.r2 is None:
            logger.exception("Cannot revert patch: r2pipe not initialized")
            return False

        try:
            # Write original bytes back
            hex_bytes = patch.original_bytes.hex()
            self.r2.cmd(f"wx {hex_bytes} @ {patch.address}")

            logger.info("Reverted patch: %s", patch.description)
            return True

        except Exception as e:
            logger.exception("Failed to revert patch: %s", e)
            return False

    def create_patch_set(self, name: str, patches: list[PatchInstruction]) -> PatchSet:
        """Create a named patch set and register it with the engine.

        Creates a PatchSet object containing the provided patches and
        registers it in the patch_sets dictionary. Automatically calculates
        and stores the original binary checksum.

        Args:
            name (str): Name for the patch set (used as dictionary key).
            patches (list[PatchInstruction]): List of patch instructions
                to include in the set.

        Returns:
            PatchSet: Newly created and registered PatchSet object.
        """
        arch: str = self.architecture if self.architecture is not None else "unknown"

        patch_set = PatchSet(
            name=name,
            patches=patches,
            target_binary=self.binary_path,
            architecture=arch,
            checksum_original=self._calculate_checksum(),
        )

        self.patch_sets[name] = patch_set
        return patch_set

    def export_patch_set(self, patch_set_name: str, output_path: Path) -> None:
        """Export a patch set to a JSON file.

        Serializes a registered patch set to JSON format including all
        patch instructions, metadata, architecture info, and checksums.
        Each patch is exported with addresses and bytecode in hex format.

        Args:
            patch_set_name (str): Name of the patch set to export.
            output_path (Path): Path where the JSON file will be saved.

        Returns:
            None

        Raises:
            ValueError: If patch set with the specified name not found.
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
        """Read bytes from the binary at the specified address.

        Uses Radare2's pxj command to read raw binary data at the given
        address as a JSON array of bytes and converts to bytes object.

        Args:
            address (int): Starting address to read from.
            size (int): Number of bytes to read.

        Returns:
            bytes: Raw bytes read from the binary at the specified address.

        Raises:
            RuntimeError: If r2pipe is not initialized.
        """
        if self.r2 is None:
            raise RuntimeError("r2pipe not initialized")

        result: list[int] = self.r2.cmdj(f"pxj {size} @ {address}")
        return bytes(result)

    def _get_function_size(self, address: int) -> int:
        """Get the size of a function in bytes.

        Queries Radare2's function analysis (afij) to determine the size
        of the function at the specified address. Returns 0 if no function
        is found at the address.

        Args:
            address (int): Starting address of the function.

        Returns:
            int: Size of the function in bytes, or 0 if no function found
                at the address.

        Raises:
            RuntimeError: If r2pipe is not initialized.
        """
        if self.r2 is None:
            raise RuntimeError("r2pipe not initialized")

        result: list[dict[str, Any]] = self.r2.cmdj(f"afij @ {address}")
        if result and len(result) > 0:
            size_val: Any = result[0].get("size", 0)
            return int(size_val) if isinstance(size_val, (int, float, str)) else 0
        return 0

    def _calculate_checksum(self) -> str:
        """Calculate the SHA256 checksum of the binary.

        Uses Radare2's ph sha256 command to compute a cryptographic hash
        of the current binary state. Useful for validating patch integrity
        before and after modifications.

        Args:
            (none)

        Returns:
            str: SHA256 checksum of the binary as a hex string.

        Raises:
            RuntimeError: If r2pipe is not initialized.
        """
        if self.r2 is None:
            raise RuntimeError("r2pipe not initialized")

        result: str = self.r2.cmd("ph sha256")
        return result.strip()

    def close(self) -> None:
        """Close Radare2 connection and cleanup resources.

        Closes the r2pipe connection and releases all associated resources.
        Should be called when finished with patch engine to ensure proper
        cleanup.

        Args:
            (none)

        Returns:
            None
        """
        if self.r2 is not None:
            self.r2.quit()
            self.r2 = None
