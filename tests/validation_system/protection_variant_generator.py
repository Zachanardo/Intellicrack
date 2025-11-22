"""
Protection Variant Generator for Phase 2.5 validation.
Generates mutated variants of protected binaries for testing Intellicrack's adaptability.
"""

import os
import struct
import hashlib
import random
import shutil
import tempfile
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum
import logging

try:
    import pefile
except ImportError:
    import subprocess
    import sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pefile"])
    import pefile

try:
    import capstone
except ImportError:
    import subprocess
    import sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "capstone"])
    import capstone

try:
    import keystone
except ImportError:
    import subprocess
    import sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "keystone-engine"])
    import keystone


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MutationType(Enum):
    """Types of mutations that can be applied to protected binaries."""
    CONSTANT_MODIFICATION = "constant_modification"
    OPCODE_SUBSTITUTION = "opcode_substitution"
    FLOW_REORDERING = "flow_reordering"
    OBFUSCATION_LAYER = "obfuscation_layer"
    COMPILER_FLAGS = "compiler_flags"
    NOP_INSERTION = "nop_insertion"
    JUNK_CODE = "junk_code"
    PACKING = "packing"


@dataclass
class MutationResult:
    """Result of a mutation operation."""
    original_hash: str
    mutated_hash: str
    mutation_type: MutationType
    mutations_applied: list[dict[str, Any]]
    binary_path: str
    success: bool
    verification_passed: bool
    error_message: str | None = None


class ProtectionVariantGenerator:
    """Generates mutated variants of protected binaries for validation testing."""

    def __init__(self, work_dir: str = None):
        """Initialize the protection variant generator."""
        self.work_dir = Path(work_dir) if work_dir else Path(tempfile.mkdtemp())
        self.work_dir.mkdir(parents=True, exist_ok=True)

        # Initialize disassembler and assembler
        self.cs_x86 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.cs_x64 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.ks_x86 = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
        self.ks_x64 = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)

        # Common protection constants to search for
        self.protection_constants = [
            b"FLEXLM",
            b"LICENSE",
            b"TRIAL",
            b"DEMO",
            b"EVALUATION",
            b"REGISTERED",
            b"UNREGISTERED",
            b"EXPIRED",
            b"VALID",
            b"INVALID"
        ]

        # Common magic numbers in protection schemes
        self.magic_numbers = [
            0xDEADBEEF,
            0xCAFEBABE,
            0x12345678,
            0x87654321,
            0xFEEDFACE,
            0xBADC0FFE
        ]

        # Track generated variants
        self.variants: list[MutationResult] = []

    def generate_variant(self, binary_path: str, mutation_type: MutationType) -> MutationResult:
        """Generate a single variant with specified mutation type."""
        logger.info(f"Generating {mutation_type.value} variant for {binary_path}")

        # Calculate original hash
        original_hash = self._calculate_hash(binary_path)

        # Create working copy
        variant_path = self._create_working_copy(binary_path, mutation_type)

        try:
            # Apply mutation based on type
            mutations_applied = []

            if mutation_type == MutationType.CONSTANT_MODIFICATION:
                mutations_applied = self._modify_constants(variant_path)
            elif mutation_type == MutationType.OPCODE_SUBSTITUTION:
                mutations_applied = self._substitute_opcodes(variant_path)
            elif mutation_type == MutationType.FLOW_REORDERING:
                mutations_applied = self._reorder_flow(variant_path)
            elif mutation_type == MutationType.NOP_INSERTION:
                mutations_applied = self._insert_nops(variant_path)
            elif mutation_type == MutationType.JUNK_CODE:
                mutations_applied = self._add_junk_code(variant_path)
            elif mutation_type == MutationType.OBFUSCATION_LAYER:
                mutations_applied = self._add_obfuscation(variant_path)
            elif mutation_type == MutationType.PACKING:
                mutations_applied = self._apply_packing(variant_path)
            elif mutation_type == MutationType.COMPILER_FLAGS:
                mutations_applied = self._recompile_with_flags(variant_path)

            # Calculate mutated hash
            mutated_hash = self._calculate_hash(variant_path)

            # Verify protection still active
            verification_passed = self._verify_protection_active(variant_path)

            result = MutationResult(
                original_hash=original_hash,
                mutated_hash=mutated_hash,
                mutation_type=mutation_type,
                mutations_applied=mutations_applied,
                binary_path=variant_path,
                success=True,
                verification_passed=verification_passed
            )

            self.variants.append(result)
            return result

        except Exception as e:
            logger.error(f"Failed to generate variant: {e}")
            return MutationResult(
                original_hash=original_hash,
                mutated_hash="",
                mutation_type=mutation_type,
                mutations_applied=[],
                binary_path=variant_path,
                success=False,
                verification_passed=False,
                error_message=str(e)
            )

    def _modify_constants(self, binary_path: str) -> list[dict[str, Any]]:
        """Modify protection constants and magic numbers in binary."""
        mutations = []

        with open(binary_path, 'rb') as f:
            data = bytearray(f.read())

        # Search and replace protection constants
        for constant in self.protection_constants:
            offset = 0
            while True:
                offset = data.find(constant, offset)
                if offset == -1:
                    break

                # Generate random replacement of same length
                replacement = bytes([random.randint(0, 255) for _ in range(len(constant))])

                # Store mutation info
                mutations.append({
                    'offset': offset,
                    'original': constant.hex(),
                    'replacement': replacement.hex(),
                    'type': 'string_constant'
                })

                # Apply mutation
                data[offset:offset+len(constant)] = replacement
                offset += len(constant)

        # Search and replace magic numbers
        for magic in self.magic_numbers:
            magic_bytes = struct.pack('<I', magic)
            offset = 0
            while True:
                offset = data.find(magic_bytes, offset)
                if offset == -1:
                    break

                # Generate random 32-bit replacement
                replacement = struct.pack('<I', random.randint(0, 0xFFFFFFFF))

                mutations.append({
                    'offset': offset,
                    'original': magic_bytes.hex(),
                    'replacement': replacement.hex(),
                    'type': 'magic_number'
                })

                data[offset:offset+4] = replacement
                offset += 4

        # Write modified binary
        with open(binary_path, 'wb') as f:
            f.write(data)

        logger.info(f"Modified {len(mutations)} constants")
        return mutations

    def _substitute_opcodes(self, binary_path: str) -> list[dict[str, Any]]:
        """Substitute conditional jump opcodes to alter control flow."""
        mutations = []

        try:
            pe = pefile.PE(binary_path)

            # Get code section
            for section in pe.sections:
                if section.Name.startswith(b'.text'):
                    code_data = bytearray(section.get_data())
                    code_offset = section.PointerToRawData

                    # Disassemble and find conditional jumps
                    if pe.FILE_HEADER.Machine == 0x014c:  # x86
                        cs = self.cs_x86
                    else:  # x64
                        cs = self.cs_x64

                    for inst in cs.disasm(bytes(code_data), 0):
                        # Check for conditional jumps
                        if inst.mnemonic in ['jz', 'jnz', 'je', 'jne', 'jg', 'jl', 'jge', 'jle']:
                            # Randomly decide whether to invert
                            if random.random() < 0.3:  # 30% chance
                                original_bytes = code_data[inst.address:inst.address+inst.size]

                                # Invert the condition
                                inverted = self._invert_jump(inst.mnemonic)

                                # Assemble new instruction
                                new_inst = f"{inverted} 0x{inst.op_str}"
                                if pe.FILE_HEADER.Machine == 0x014c:
                                    encoding, _ = self.ks_x86.asm(new_inst)
                                else:
                                    encoding, _ = self.ks_x64.asm(new_inst)

                                if encoding and len(encoding) == inst.size:
                                    mutations.append({
                                        'offset': code_offset + inst.address,
                                        'original': original_bytes.hex(),
                                        'replacement': bytes(encoding).hex(),
                                        'type': 'opcode_substitution',
                                        'instruction': f"{inst.mnemonic} -> {inverted}"
                                    })

                                    # Apply mutation
                                    code_data[inst.address:inst.address+inst.size] = bytes(encoding)

                    # Write back modified code section
                    pe.set_bytes_at_offset(code_offset, bytes(code_data))
                    break

            pe.write(binary_path)
            pe.close()

        except Exception as e:
            logger.error(f"Error substituting opcodes: {e}")

        logger.info(f"Substituted {len(mutations)} opcodes")
        return mutations

    def _reorder_flow(self, binary_path: str) -> list[dict[str, Any]]:
        """Reorder non-dependent protection checks."""
        mutations = []

        try:
            pe = pefile.PE(binary_path)

            # Find function boundaries and identify independent code blocks
            for section in pe.sections:
                if section.Name.startswith(b'.text'):
                    code_data = bytearray(section.get_data())
                    code_offset = section.PointerToRawData

                    # Find sequences that can be reordered (simplified approach)
                    # Look for push/pop pairs that can be swapped
                    i = 0
                    while i < len(code_data) - 10:
                        # Look for independent instruction sequences
                        if code_data[i] == 0x50:  # PUSH instruction
                            # Find corresponding POP
                            for j in range(i+1, min(i+20, len(code_data))):
                                if code_data[j] == 0x58:  # POP instruction
                                    # Check if we can swap this block
                                    block1 = code_data[i:j+1]

                                    # Look for next independent block
                                    if j+1 < len(code_data) - 10 and code_data[j+1] == 0x50:
                                        for k in range(j+2, min(j+21, len(code_data))):
                                            if code_data[k] == 0x58:
                                                block2 = code_data[j+1:k+1]

                                                # Swap blocks
                                                mutations.append({
                                                    'offset1': code_offset + i,
                                                    'offset2': code_offset + j+1,
                                                    'block1_size': len(block1),
                                                    'block2_size': len(block2),
                                                    'type': 'flow_reorder'
                                                })

                                                # Apply swap
                                                temp = code_data[i:i+len(block1)+len(block2)]
                                                code_data[i:i+len(block2)] = block2
                                                code_data[i+len(block2):i+len(block1)+len(block2)] = block1

                                                i = k + 1
                                                break
                                    break
                        i += 1

                    # Write back modified code
                    pe.set_bytes_at_offset(code_offset, bytes(code_data))
                    break

            pe.write(binary_path)
            pe.close()

        except Exception as e:
            logger.error(f"Error reordering flow: {e}")

        logger.info(f"Reordered {len(mutations)} code blocks")
        return mutations

    def _insert_nops(self, binary_path: str) -> list[dict[str, Any]]:
        """Insert NOP sleds between protection checks."""
        mutations = []

        try:
            pe = pefile.PE(binary_path)

            for section in pe.sections:
                if section.Name.startswith(b'.text'):
                    code_data = bytearray(section.get_data())
                    code_offset = section.PointerToRawData

                    # Find suitable locations for NOP insertion
                    # Look for call instructions
                    insertions = []
                    for i in range(len(code_data) - 5):
                        if code_data[i] == 0xE8:  # CALL instruction
                            # Insert NOPs after the call
                            nop_count = random.randint(1, 5)
                            insertions.append((i + 5, nop_count))

                    # Apply insertions in reverse order to maintain offsets
                    offset_adjustment = 0
                    for pos, nop_count in reversed(insertions):
                        if len(mutations) < 20:  # Limit number of insertions
                            nops = bytes([0x90] * nop_count)
                            code_data[pos:pos] = nops

                            mutations.append({
                                'offset': code_offset + pos + offset_adjustment,
                                'nop_count': nop_count,
                                'type': 'nop_insertion'
                            })

                            offset_adjustment += nop_count

                    # Adjust section size
                    section.SizeOfRawData = len(code_data)
                    section.Misc_VirtualSize = len(code_data)

                    # Write back modified code
                    pe.set_bytes_at_offset(code_offset, bytes(code_data))
                    break

            pe.write(binary_path)
            pe.close()

        except Exception as e:
            logger.error(f"Error inserting NOPs: {e}")

        logger.info(f"Inserted {len(mutations)} NOP sleds")
        return mutations

    def _add_junk_code(self, binary_path: str) -> list[dict[str, Any]]:
        """Add junk code between protection checks."""
        mutations = []

        try:
            pe = pefile.PE(binary_path)

            # Junk code patterns that don't affect execution
            junk_patterns = [
                bytes([0x90]),  # NOP
                bytes([0x50, 0x58]),  # PUSH EAX; POP EAX
                bytes([0x51, 0x59]),  # PUSH ECX; POP ECX
                bytes([0x52, 0x5A]),  # PUSH EDX; POP EDX
                bytes([0x53, 0x5B]),  # PUSH EBX; POP EBX
                bytes([0x87, 0xC0]),  # XCHG EAX, EAX
                bytes([0x89, 0xC0]),  # MOV EAX, EAX
            ]

            for section in pe.sections:
                if section.Name.startswith(b'.text'):
                    code_data = bytearray(section.get_data())
                    code_offset = section.PointerToRawData

                    # Find locations to insert junk code
                    insertions = []
                    for i in range(0, len(code_data) - 10, 100):  # Every 100 bytes
                        junk = random.choice(junk_patterns) * random.randint(1, 3)
                        insertions.append((i, junk))

                    # Apply insertions
                    offset_adjustment = 0
                    for pos, junk in reversed(insertions):
                        if len(mutations) < 15:
                            code_data[pos:pos] = junk

                            mutations.append({
                                'offset': code_offset + pos + offset_adjustment,
                                'junk_size': len(junk),
                                'junk_bytes': junk.hex(),
                                'type': 'junk_code'
                            })

                            offset_adjustment += len(junk)

                    # Update section size
                    section.SizeOfRawData = len(code_data)
                    section.Misc_VirtualSize = len(code_data)

                    pe.set_bytes_at_offset(code_offset, bytes(code_data))
                    break

            pe.write(binary_path)
            pe.close()

        except Exception as e:
            logger.error(f"Error adding junk code: {e}")

        logger.info(f"Added {len(mutations)} junk code segments")
        return mutations

    def _add_obfuscation(self, binary_path: str) -> list[dict[str, Any]]:
        """Add obfuscation layer to the binary."""
        mutations = []

        try:
            # Simple XOR obfuscation of code section
            pe = pefile.PE(binary_path)
            xor_key = random.randint(1, 255)

            for section in pe.sections:
                if section.Name.startswith(b'.text'):
                    code_data = bytearray(section.get_data())
                    code_offset = section.PointerToRawData

                    # XOR obfuscate portions of code
                    for i in range(0, len(code_data), 1000):
                        end = min(i + 100, len(code_data))

                        # Skip if this looks like critical code
                        if not self._is_safe_to_obfuscate(code_data[i:end]):
                            continue

                        original = code_data[i:end]
                        for j in range(i, end):
                            code_data[j] ^= xor_key

                        mutations.append({
                            'offset': code_offset + i,
                            'size': end - i,
                            'xor_key': xor_key,
                            'type': 'xor_obfuscation'
                        })

                    # Add deobfuscation stub
                    deobfuscation_stub = self._generate_deobfuscation_stub(xor_key, mutations)
                    if deobfuscation_stub:
                        # Find cave to insert stub
                        cave_offset = self._find_code_cave(pe, len(deobfuscation_stub))
                        if cave_offset:
                            pe.set_bytes_at_offset(cave_offset, deobfuscation_stub)
                            mutations.append({
                                'stub_offset': cave_offset,
                                'stub_size': len(deobfuscation_stub),
                                'type': 'deobfuscation_stub'
                            })

                    pe.set_bytes_at_offset(code_offset, bytes(code_data))
                    break

            pe.write(binary_path)
            pe.close()

        except Exception as e:
            logger.error(f"Error adding obfuscation: {e}")

        logger.info(f"Added {len(mutations)} obfuscation layers")
        return mutations

    def _apply_packing(self, binary_path: str) -> list[dict[str, Any]]:
        """Apply packing to the binary (UPX simulation)."""
        mutations = []

        try:
            # Check if UPX is available
            upx_path = shutil.which("upx")
            if upx_path:
                # Use real UPX if available
                import subprocess
                result = subprocess.run(
                    [upx_path, "-9", binary_path],
                    capture_output=True,
                    text=True
                )

                if result.returncode == 0:
                    mutations.append({
                        'packer': 'UPX',
                        'compression_level': 9,
                        'type': 'real_packing'
                    })
                    logger.info("Applied real UPX packing")
            else:
                # Implement simple packing simulation
                with open(binary_path, 'rb') as f:
                    original_data = f.read()

                # Simple RLE compression for demonstration
                compressed = self._simple_rle_compress(original_data)

                # Create packed binary structure
                packed_data = self._create_packed_structure(compressed, len(original_data))

                with open(binary_path, 'wb') as f:
                    f.write(packed_data)

                mutations.append({
                    'packer': 'Custom_RLE',
                    'original_size': len(original_data),
                    'packed_size': len(packed_data),
                    'type': 'custom_packing'
                })

        except Exception as e:
            logger.error(f"Error applying packing: {e}")

        return mutations

    def _recompile_with_flags(self, binary_path: str) -> list[dict[str, Any]]:
        """Simulate recompilation with different compiler flags."""
        mutations = []

        try:
            # Since we can't actually recompile, we'll modify optimization patterns
            pe = pefile.PE(binary_path)

            for section in pe.sections:
                if section.Name.startswith(b'.text'):
                    code_data = bytearray(section.get_data())
                    code_offset = section.PointerToRawData

                    # Simulate different optimization levels by modifying patterns

                    # Pattern 1: Replace MOV+MOV with XCHG (simulating -O2)
                    for i in range(len(code_data) - 4):
                        if (code_data[i] == 0x89 and  # MOV
                            code_data[i+2] == 0x89):  # MOV
                            # Replace with XCHG
                            code_data[i] = 0x87
                            code_data[i+2] = 0x90  # NOP

                            mutations.append({
                                'offset': code_offset + i,
                                'pattern': 'MOV_MOV_to_XCHG',
                                'type': 'optimization_pattern'
                            })

                    # Pattern 2: Remove redundant NOPs (simulating -Os)
                    i = 0
                    while i < len(code_data):
                        if code_data[i] == 0x90:  # NOP
                            j = i
                            while j < len(code_data) and code_data[j] == 0x90:
                                j += 1

                            if j - i > 2:  # Remove excessive NOPs
                                del code_data[i:j-1]
                                mutations.append({
                                    'offset': code_offset + i,
                                    'nops_removed': j - i - 1,
                                    'type': 'nop_removal'
                                })
                        i += 1

                    pe.set_bytes_at_offset(code_offset, bytes(code_data))
                    break

            pe.write(binary_path)
            pe.close()

        except Exception as e:
            logger.error(f"Error simulating recompilation: {e}")

        logger.info(f"Applied {len(mutations)} compiler flag simulations")
        return mutations

    def _invert_jump(self, mnemonic: str) -> str:
        """Invert a conditional jump instruction."""
        inversions = {
            'jz': 'jnz', 'jnz': 'jz',
            'je': 'jne', 'jne': 'je',
            'jg': 'jle', 'jle': 'jg',
            'jl': 'jge', 'jge': 'jl',
            'ja': 'jbe', 'jbe': 'ja',
            'jb': 'jae', 'jae': 'jb'
        }
        return inversions.get(mnemonic, mnemonic)

    def _is_safe_to_obfuscate(self, code_chunk: bytes) -> bool:
        """Check if code chunk is safe to obfuscate."""
        # Don't obfuscate if it contains:
        # - Import table references
        # - Exception handlers
        # - Critical system calls

        critical_patterns = [
            b'\xFF\x15',  # CALL DWORD PTR
            b'\xFF\x25',  # JMP DWORD PTR
            b'\xE8\x00\x00\x00\x00',  # CALL with 0 offset (likely relocated)
        ]

        for pattern in critical_patterns:
            if pattern in code_chunk:
                return False

        return True

    def _generate_deobfuscation_stub(self, xor_key: int, mutations: list) -> bytes | None:
        """Generate a deobfuscation stub."""
        # Simple x86 deobfuscation loop
        stub = bytearray()

        # PUSH registers
        stub.extend([0x50, 0x51, 0x52])  # PUSH EAX, ECX, EDX

        for mutation in mutations:
            if mutation['type'] == 'xor_obfuscation':
                # MOV ECX, size
                stub.extend([0xB9])
                stub.extend(struct.pack('<I', mutation['size']))

                # MOV EDI, offset
                stub.extend([0xBF])
                stub.extend(struct.pack('<I', mutation['offset']))

                # XOR loop
                # XOR BYTE PTR [EDI], key
                stub.extend([0x80, 0x37, xor_key])
                # INC EDI
                stub.extend([0x47])
                # LOOP
                stub.extend([0xE2, 0xFA])

        # POP registers
        stub.extend([0x5A, 0x59, 0x58])  # POP EDX, ECX, EAX

        # RET
        stub.extend([0xC3])

        return bytes(stub) if len(stub) < 1000 else None

    def _find_code_cave(self, pe: pefile.PE, size: int) -> int | None:
        """Find a code cave in the PE file."""
        for section in pe.sections:
            data = section.get_data()
            # Look for sequence of zeros
            zero_run = 0
            for i, byte in enumerate(data):
                if byte == 0:
                    zero_run += 1
                    if zero_run >= size:
                        return section.PointerToRawData + i - size + 1
                else:
                    zero_run = 0
        return None

    def _simple_rle_compress(self, data: bytes) -> bytes:
        """Simple RLE compression."""
        compressed = bytearray()
        i = 0

        while i < len(data):
            run_length = 1
            while i + run_length < len(data) and data[i] == data[i + run_length] and run_length < 255:
                run_length += 1

            if run_length > 3:
                compressed.extend([0xFF, run_length, data[i]])
                i += run_length
            else:
                compressed.append(data[i])
                i += 1

        return bytes(compressed)

    def _create_packed_structure(self, compressed: bytes, original_size: int) -> bytes:
        """Create a packed binary structure."""
        # Simple packed format:
        # [MAGIC][ORIGINAL_SIZE][COMPRESSED_SIZE][COMPRESSED_DATA][UNPACKER_STUB]

        magic = b'PACK'
        header = magic + struct.pack('<II', original_size, len(compressed))

        # Real RLE unpacker stub for decompression
        unpacker_stub = bytearray([
            # Save registers
            0x60,  # PUSHAD

            # Set up decompression
            0xBE, *struct.pack('<I', len(header)),  # MOV ESI, offset to compressed data
            0xBF, 0x00, 0x10, 0x40, 0x00,  # MOV EDI, 0x401000 (typical unpack target)
            0xB9, *struct.pack('<I', len(compressed)),  # MOV ECX, compressed_size

            # RLE decompression loop
            0x8A, 0x06,        # MOV AL, [ESI]     ; Load byte
            0x46,              # INC ESI           ; Next source byte
            0x3C, 0xFF,        # CMP AL, 0xFF      ; Check RLE marker
            0x75, 0x06,        # JNZ copy_byte     ; Not RLE, copy directly

            # RLE sequence: next byte is count, byte after is value
            0x8A, 0x1E,        # MOV BL, [ESI]     ; Load count
            0x46,              # INC ESI           ; Next byte
            0x8A, 0x06,        # MOV AL, [ESI]     ; Load value to repeat
            0x46,              # INC ESI           ; Next byte

            # Repeat loop
            # repeat_loop:
            0x88, 0x07,        # MOV [EDI], AL     ; Store byte
            0x47,              # INC EDI           ; Next destination
            0x4B,              # DEC BL            ; Decrement count
            0x75, 0xFA,        # JNZ repeat_loop   ; Continue if count > 0
            0xEB, 0x04,        # JMP continue_loop ; Skip copy_byte

            # copy_byte:
            0x88, 0x07,        # MOV [EDI], AL     ; Copy byte directly
            0x47,              # INC EDI           ; Next destination

            # continue_loop:
            0xE2, 0xE6,        # LOOP main_loop    ; Continue until ECX = 0

            # Clean up and jump to unpacked code
            0x61,              # POPAD             ; Restore registers
            0xE9, 0x00, 0x10, 0x40, 0x00,  # JMP 0x401000 ; Jump to unpacked entry point
        ])

        return header + compressed + unpacker_stub

    def _calculate_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file."""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _create_working_copy(self, binary_path: str, mutation_type: MutationType) -> str:
        """Create a working copy of the binary for mutation."""
        basename = Path(binary_path).stem
        extension = Path(binary_path).suffix
        variant_name = f"{basename}_{mutation_type.value}{extension}"
        variant_path = self.work_dir / variant_name

        shutil.copy2(binary_path, variant_path)
        return str(variant_path)

    def _verify_protection_active(self, binary_path: str) -> bool:
        """Verify that protection is still active in the mutated binary."""
        try:
            # Check if binary still has protection markers
            with open(binary_path, 'rb') as f:
                data = f.read()

            # Look for protection indicators
            protection_indicators = [
                b'IsDebuggerPresent',
                b'CheckRemoteDebuggerPresent',
                b'NtQueryInformationProcess',
                b'GetTickCount',
                b'QueryPerformanceCounter'
            ]

            found_indicators = 0
            for indicator in protection_indicators:
                if indicator in data:
                    found_indicators += 1

            # Also check PE structure integrity
            try:
                pe = pefile.PE(binary_path)
                has_imports = len(pe.DIRECTORY_ENTRY_IMPORT) > 0 if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else False
                has_valid_entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint > 0
                pe.close()

                return found_indicators > 0 and has_imports and has_valid_entry

            except:
                return False

        except Exception as e:
            logger.error(f"Error verifying protection: {e}")
            return False

    def generate_all_variants(self, binary_path: str) -> list[MutationResult]:
        """Generate all 5 required variants for a binary."""
        logger.info(f"Generating all variants for {binary_path}")

        variants = []

        # Variant A: Modified constants only
        variant_a = self.generate_variant(binary_path, MutationType.CONSTANT_MODIFICATION)
        variants.append(variant_a)

        # Variant B: Reordered protection flow
        variant_b = self.generate_variant(binary_path, MutationType.FLOW_REORDERING)
        variants.append(variant_b)

        # Variant C: Added obfuscation layer
        variant_c = self.generate_variant(binary_path, MutationType.OBFUSCATION_LAYER)
        variants.append(variant_c)

        # Variant D: Combined modifications
        combined_path = self._create_working_copy(binary_path, MutationType.CONSTANT_MODIFICATION)
        self._modify_constants(combined_path)
        self._substitute_opcodes(combined_path)
        self._insert_nops(combined_path)

        variant_d = MutationResult(
            original_hash=self._calculate_hash(binary_path),
            mutated_hash=self._calculate_hash(combined_path),
            mutation_type=MutationType.CONSTANT_MODIFICATION,
            mutations_applied=[{'type': 'combined', 'modifications': ['constants', 'opcodes', 'nops']}],
            binary_path=combined_path,
            success=True,
            verification_passed=self._verify_protection_active(combined_path)
        )
        variants.append(variant_d)
        self.variants.append(variant_d)

        # Variant E: Recompiled with different compiler flags
        variant_e = self.generate_variant(binary_path, MutationType.COMPILER_FLAGS)
        variants.append(variant_e)

        logger.info(f"Generated {len(variants)} variants")
        return variants

    def get_variant_report(self) -> str:
        """Generate a report of all generated variants."""
        report = ["Protection Variant Generation Report", "=" * 50, ""]

        for i, variant in enumerate(self.variants, 1):
            report.append(f"Variant {i}: {variant.mutation_type.value}")
            report.append(f"  Original Hash: {variant.original_hash[:16]}...")
            report.append(f"  Mutated Hash:  {variant.mutated_hash[:16]}...")
            report.append(f"  Success: {variant.success}")
            report.append(f"  Protection Active: {variant.verification_passed}")
            report.append(f"  Mutations Applied: {len(variant.mutations_applied)}")

            if variant.error_message:
                report.append(f"  Error: {variant.error_message}")

            report.append("")

        return "\n".join(report)


if __name__ == "__main__":
    # Test the generator
    generator = ProtectionVariantGenerator()

    # Use a test binary if available
    test_binary = r"C:\Windows\System32\notepad.exe"
    if os.path.exists(test_binary):
        print(f"Generating variants for {test_binary}")
        variants = generator.generate_all_variants(test_binary)
        print(generator.get_variant_report())
    else:
        print("Test binary not found")
