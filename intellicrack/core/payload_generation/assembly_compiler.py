"""
Assembly Compiler for Payload Generation

Compiles assembly code to machine code with support for multiple architectures
and position-independent code generation.
"""

import logging
import struct
from typing import Dict, List, Tuple

from .payload_types import Architecture

logger = logging.getLogger(__name__)


class AssemblyCompiler:
    """
    Advanced assembly compiler with support for multiple architectures
    and position-independent code generation.
    """

    def __init__(self):
        self.logger = logging.getLogger("IntellicrackLogger.AssemblyCompiler")

        # x86 instruction mappings
        self.x86_instructions = {
            'nop': b'\x90',
            'int3': b'\xCC',
            'ret': b'\xC3',
            'call': self._compile_call_x86,
            'jmp': self._compile_jmp_x86,
            'push': self._compile_push_x86,
            'pop': self._compile_pop_x86,
            'mov': self._compile_mov_x86,
            'xor': self._compile_xor_x86,
            'add': self._compile_add_x86,
            'sub': self._compile_sub_x86,
            'test': self._compile_test_x86,
            'cmp': self._compile_cmp_x86,
            'je': self._compile_conditional_jump_x86,
            'jz': self._compile_conditional_jump_x86,
            'jne': self._compile_conditional_jump_x86,
            'jnz': self._compile_conditional_jump_x86,
            'jl': self._compile_conditional_jump_x86,
            'jg': self._compile_conditional_jump_x86,
        }

        # x64 instruction mappings
        self.x64_instructions = {
            'nop': b'\x90',
            'int3': b'\xCC',
            'ret': b'\xC3',
            'call': self._compile_call_x64,
            'jmp': self._compile_jmp_x64,
            'push': self._compile_push_x64,
            'pop': self._compile_pop_x64,
            'mov': self._compile_mov_x64,
            'xor': self._compile_xor_x64,
            'add': self._compile_add_x64,
            'sub': self._compile_sub_x64,
            'test': self._compile_test_x64,
            'cmp': self._compile_cmp_x64,
        }

        # Register mappings
        self.x86_registers = {
            'eax': 0, 'ecx': 1, 'edx': 2, 'ebx': 3,
            'esp': 4, 'ebp': 5, 'esi': 6, 'edi': 7,
            'ax': 0, 'cx': 1, 'dx': 2, 'bx': 3,
            'al': 0, 'cl': 1, 'dl': 2, 'bl': 3,
            'ah': 4, 'ch': 5, 'dh': 6, 'bh': 7
        }

        self.x64_registers = {
            'rax': 0, 'rcx': 1, 'rdx': 2, 'rbx': 3,
            'rsp': 4, 'rbp': 5, 'rsi': 6, 'rdi': 7,
            'r8': 8, 'r9': 9, 'r10': 10, 'r11': 11,
            'r12': 12, 'r13': 13, 'r14': 14, 'r15': 15
        }

    def compile_assembly(self,
                        assembly_code: str,
                        architecture: Architecture,
                        position_independent: bool = True) -> bytes:
        """
        Compile assembly code to machine code.
        
        Args:
            assembly_code: Assembly source code
            architecture: Target architecture
            position_independent: Generate position-independent code
            
        Returns:
            Compiled machine code
        """
        try:
            self.logger.info(f"Compiling assembly for {architecture.value}")

            # Preprocess assembly code
            processed_code = self._preprocess_assembly(assembly_code)

            # Parse instructions
            instructions = self._parse_instructions(processed_code)

            # Resolve labels and calculate offsets
            labels, resolved_instructions = self._resolve_labels(instructions)

            # Compile to machine code
            machine_code = self._compile_instructions(
                resolved_instructions,
                architecture,
                labels,
                position_independent
            )

            self.logger.info(f"Compiled {len(instructions)} instructions to {len(machine_code)} bytes")
            return machine_code

        except Exception as e:
            self.logger.error(f"Assembly compilation failed: {e}")
            raise

    def _preprocess_assembly(self, assembly_code: str) -> str:
        """Preprocess assembly code (remove comments, normalize whitespace)."""
        lines = []
        for line in assembly_code.split('\n'):
            # Remove comments
            if ';' in line:
                line = line[:line.index(';')]

            # Strip whitespace and skip empty lines
            line = line.strip()
            if line:
                lines.append(line)

        return '\n'.join(lines)

    def _parse_instructions(self, assembly_code: str) -> List[Dict]:
        """Parse assembly code into instruction objects."""
        instructions = []

        for line_num, line in enumerate(assembly_code.split('\n'), 1):
            if not line.strip():
                continue

            # Check for labels
            if line.endswith(':'):
                instructions.append({
                    'type': 'label',
                    'name': line[:-1],
                    'line': line_num
                })
                continue

            # Parse instruction
            parts = line.split()
            if not parts:
                continue

            mnemonic = parts[0].lower()
            operands = []

            if len(parts) > 1:
                # Join remaining parts and split by commas
                operand_str = ' '.join(parts[1:])
                operands = [op.strip() for op in operand_str.split(',')]

            instructions.append({
                'type': 'instruction',
                'mnemonic': mnemonic,
                'operands': operands,
                'line': line_num,
                'original': line
            })

        return instructions

    def _resolve_labels(self, instructions: List[Dict]) -> Tuple[Dict, List[Dict]]:
        """Resolve label references and calculate offsets."""
        labels = {}
        resolved_instructions = []
        current_offset = 0

        # First pass: collect labels
        for instruction in instructions:
            if instruction['type'] == 'label':
                labels[instruction['name']] = current_offset
            else:
                resolved_instructions.append(instruction)
                # Estimate instruction size (will be refined in compilation)
                current_offset += self._estimate_instruction_size(instruction)

        # Second pass: resolve label references
        current_offset = 0
        for instruction in resolved_instructions:
            instruction['offset'] = current_offset
            current_offset += self._estimate_instruction_size(instruction)

        return labels, resolved_instructions

    def _estimate_instruction_size(self, instruction: Dict) -> int:
        """Estimate the size of an instruction in bytes."""
        mnemonic = instruction['mnemonic']
        operands = instruction['operands']

        # Basic size estimates (this is simplified)
        if mnemonic in ['nop', 'ret', 'int3']:
            return 1
        elif mnemonic in ['push', 'pop'] and len(operands) == 1:
            return 1 if self._is_register(operands[0]) else 5
        elif mnemonic in ['mov', 'xor', 'add', 'sub', 'test', 'cmp']:
            return 2 if all(self._is_register(op) for op in operands) else 6
        elif mnemonic in ['call', 'jmp']:
            return 5  # Relative call/jump
        elif mnemonic.startswith('j'):  # Conditional jumps
            return 2  # Short jump, may need to be extended
        else:
            return 3  # Default estimate

    def _is_register(self, operand: str) -> bool:
        """Check if operand is a register."""
        return operand.lower() in self.x86_registers or operand.lower() in self.x64_registers

    def _compile_instructions(self,
                            instructions: List[Dict],
                            architecture: Architecture,
                            labels: Dict[str, int],
                            position_independent: bool) -> bytes:
        """Compile resolved instructions to machine code."""
        machine_code = b''

        if architecture == Architecture.X86:
            instruction_set = self.x86_instructions
        elif architecture == Architecture.X64:
            instruction_set = self.x64_instructions
        else:
            raise ValueError(f"Unsupported architecture: {architecture}")

        for instruction in instructions:
            mnemonic = instruction['mnemonic']
            operands = instruction['operands']

            if mnemonic in instruction_set:
                if callable(instruction_set[mnemonic]):
                    # Complex instruction requiring compilation function
                    compiled_bytes = instruction_set[mnemonic](
                        operands, labels, instruction['offset'], position_independent
                    )
                else:
                    # Simple instruction with direct byte mapping
                    compiled_bytes = instruction_set[mnemonic]

                machine_code += compiled_bytes
            else:
                self.logger.warning(f"Unknown instruction: {mnemonic}")
                # Add NOP as fallback
                machine_code += b'\x90'

        return machine_code

    # x86 instruction compilation methods
    def _compile_call_x86(self, operands: List[str], labels: Dict[str, int],
                         current_offset: int, position_independent: bool) -> bytes:
        """Compile x86 CALL instruction."""
        if len(operands) != 1:
            raise ValueError("CALL requires exactly one operand")

        operand = operands[0]

        if operand in labels:
            # Call to label
            target_offset = labels[operand]
            relative_offset = target_offset - (current_offset + 5)  # 5 = size of call instruction
            return b'\xE8' + struct.pack('<i', relative_offset)
        elif operand.lower() in self.x86_registers:
            # Call register
            reg_code = self.x86_registers[operand.lower()]
            return b'\xFF' + bytes([0xD0 + reg_code])
        else:
            # Call immediate address (simplified)
            try:
                address = int(operand, 16) if operand.startswith('0x') else int(operand)
                return b'\xFF\x15' + struct.pack('<I', address)
            except ValueError:
                raise ValueError(f"Invalid call target: {operand}")

    def _compile_jmp_x86(self, operands: List[str], labels: Dict[str, int],
                        current_offset: int, position_independent: bool) -> bytes:
        """Compile x86 JMP instruction."""
        if len(operands) != 1:
            raise ValueError("JMP requires exactly one operand")

        operand = operands[0]

        if operand in labels:
            target_offset = labels[operand]
            relative_offset = target_offset - (current_offset + 5)
            return b'\xE9' + struct.pack('<i', relative_offset)
        elif operand.lower() in self.x86_registers:
            reg_code = self.x86_registers[operand.lower()]
            return b'\xFF' + bytes([0xE0 + reg_code])
        else:
            try:
                address = int(operand, 16) if operand.startswith('0x') else int(operand)
                return b'\xFF\x25' + struct.pack('<I', address)
            except ValueError:
                raise ValueError(f"Invalid jump target: {operand}")

    def _compile_push_x86(self, operands: List[str], labels: Dict[str, int],
                         current_offset: int, position_independent: bool) -> bytes:
        """Compile x86 PUSH instruction."""
        self.logger.debug(f"Compiling PUSH at offset 0x{current_offset:04x}, PIC: {position_independent}")

        if len(operands) != 1:
            raise ValueError("PUSH requires exactly one operand")

        operand = operands[0]

        # Check if operand references a label
        if operand in labels:
            self.logger.debug(f"PUSH operand '{operand}' references label at offset 0x{labels[operand]:04x}")

        if operand.lower() in self.x86_registers:
            reg_code = self.x86_registers[operand.lower()]
            return bytes([0x50 + reg_code])
        else:
            # Push immediate value
            try:
                value = int(operand, 16) if operand.startswith('0x') else int(operand)
                # For position-independent code, log immediate value usage
                if position_independent and abs(value) > 0xFFFF:
                    self.logger.warning(f"Large immediate value 0x{value:x} in PIC code may cause relocation issues")

                if -128 <= value <= 127:
                    return b'\x6A' + struct.pack('<b', value)
                else:
                    return b'\x68' + struct.pack('<I', value & 0xFFFFFFFF)
            except ValueError:
                raise ValueError(f"Invalid push value: {operand}")

    def _compile_pop_x86(self, operands: List[str], labels: Dict[str, int],
                        current_offset: int, position_independent: bool) -> bytes:
        """Compile x86 POP instruction."""
        self.logger.debug(f"Compiling POP at offset 0x{current_offset:04x}, PIC: {position_independent}")

        if len(operands) != 1:
            raise ValueError("POP requires exactly one operand")

        operand = operands[0]

        # Validate operand is not a label reference (POP doesn't support direct label addressing)
        if operand in labels:
            raise ValueError(f"POP cannot directly reference label '{operand}' - use register or memory operand")

        if operand.lower() in self.x86_registers:
            reg_code = self.x86_registers[operand.lower()]
            return bytes([0x58 + reg_code])
        else:
            raise ValueError(f"Invalid pop target: {operand}")

    def _compile_mov_x86(self, operands: List[str], labels: Dict[str, int],
                        current_offset: int, position_independent: bool) -> bytes:
        """Compile x86 MOV instruction."""
        self.logger.debug(f"Compiling MOV at offset 0x{current_offset:04x}, PIC: {position_independent}")

        if len(operands) != 2:
            raise ValueError("MOV requires exactly two operands")

        dst, src = operands

        # Check for label references in source operand
        if src in labels:
            self.logger.debug(f"MOV source '{src}' references label at offset 0x{labels[src]:04x}")
            if position_independent:
                self.logger.warning("MOV with label reference in PIC code - consider RIP-relative addressing")

        # MOV register, immediate
        if dst.lower() in self.x86_registers and src.lower() not in self.x86_registers:
            reg_code = self.x86_registers[dst.lower()]
            try:
                value = int(src, 16) if src.startswith('0x') else int(src)
                # For position-independent code, warn about absolute addresses
                if position_independent and value > 0xFFFF:
                    self.logger.warning(f"Absolute address 0x{value:x} in PIC code may need relocation")
                return bytes([0xB8 + reg_code]) + struct.pack('<I', value & 0xFFFFFFFF)
            except ValueError:
                pass

        # MOV register, register
        if dst.lower() in self.x86_registers and src.lower() in self.x86_registers:
            dst_code = self.x86_registers[dst.lower()]
            src_code = self.x86_registers[src.lower()]
            return b'\x89' + bytes([0xC0 + (src_code << 3) + dst_code])

        raise ValueError(f"Unsupported MOV instruction: {dst}, {src}")

    def _compile_xor_x86(self, operands: List[str], labels: Dict[str, int],
                        current_offset: int, position_independent: bool) -> bytes:
        """Compile x86 XOR instruction."""
        self.logger.debug(f"Compiling XOR at offset 0x{current_offset:04x}, PIC: {position_independent}")

        if len(operands) != 2:
            raise ValueError("XOR requires exactly two operands")

        dst, src = operands

        # Validate operands don't reference labels (XOR doesn't support direct label addressing)
        for i, operand in enumerate([dst, src]):
            if operand in labels:
                raise ValueError(f"XOR operand {i+1} '{operand}' cannot directly reference label - use register or memory operand")

        # XOR register, register
        if dst.lower() in self.x86_registers and src.lower() in self.x86_registers:
            dst_code = self.x86_registers[dst.lower()]
            src_code = self.x86_registers[src.lower()]
            return b'\x31' + bytes([0xC0 + (src_code << 3) + dst_code])

        raise ValueError(f"Unsupported XOR instruction: {dst}, {src}")

    def _compile_add_x86(self, operands: List[str], labels: Dict[str, int],
                        current_offset: int, position_independent: bool) -> bytes:
        """Compile x86 ADD instruction."""
        self.logger.debug(f"Compiling ADD at offset 0x{current_offset:04x}, PIC: {position_independent}")

        if len(operands) != 2:
            raise ValueError("ADD requires exactly two operands")

        dst, src = operands

        # Validate operands don't reference labels (ADD doesn't support direct label addressing)
        for i, operand in enumerate([dst, src]):
            if operand in labels:
                raise ValueError(f"ADD operand {i+1} '{operand}' cannot directly reference label - use register or memory operand")

        # ADD register, register
        if dst.lower() in self.x86_registers and src.lower() in self.x86_registers:
            dst_code = self.x86_registers[dst.lower()]
            src_code = self.x86_registers[src.lower()]
            return b'\x01' + bytes([0xC0 + (src_code << 3) + dst_code])

        raise ValueError(f"Unsupported ADD instruction: {dst}, {src}")

    def _compile_sub_x86(self, operands: List[str], labels: Dict[str, int],
                        current_offset: int, position_independent: bool) -> bytes:
        """Compile x86 SUB instruction."""
        self.logger.debug(f"Compiling SUB at offset 0x{current_offset:04x}, PIC: {position_independent}")

        if len(operands) != 2:
            raise ValueError("SUB requires exactly two operands")

        dst, src = operands

        # Validate operands don't reference labels (SUB doesn't support direct label addressing)
        for i, operand in enumerate([dst, src]):
            if operand in labels:
                raise ValueError(f"SUB operand {i+1} '{operand}' cannot directly reference label - use register or memory operand")

        # SUB register, register
        if dst.lower() in self.x86_registers and src.lower() in self.x86_registers:
            dst_code = self.x86_registers[dst.lower()]
            src_code = self.x86_registers[src.lower()]
            return b'\x29' + bytes([0xC0 + (src_code << 3) + dst_code])

        raise ValueError(f"Unsupported SUB instruction: {dst}, {src}")

    def _compile_test_x86(self, operands: List[str], labels: Dict[str, int],
                         current_offset: int, position_independent: bool) -> bytes:
        """Compile x86 TEST instruction."""
        self.logger.debug(f"Compiling TEST at offset 0x{current_offset:04x}, PIC: {position_independent}")

        if len(operands) != 2:
            raise ValueError("TEST requires exactly two operands")

        dst, src = operands

        # Validate operands don't reference labels (TEST doesn't support direct label addressing)
        for i, operand in enumerate([dst, src]):
            if operand in labels:
                raise ValueError(f"TEST operand {i+1} '{operand}' cannot directly reference label - use register or memory operand")

        # TEST register, register
        if dst.lower() in self.x86_registers and src.lower() in self.x86_registers:
            dst_code = self.x86_registers[dst.lower()]
            src_code = self.x86_registers[src.lower()]
            return b'\x85' + bytes([0xC0 + (src_code << 3) + dst_code])

        raise ValueError(f"Unsupported TEST instruction: {dst}, {src}")

    def _compile_cmp_x86(self, operands: List[str], labels: Dict[str, int],
                        current_offset: int, position_independent: bool) -> bytes:
        """Compile x86 CMP instruction."""
        self.logger.debug(f"Compiling CMP at offset 0x{current_offset:04x}, PIC: {position_independent}")

        if len(operands) != 2:
            raise ValueError("CMP requires exactly two operands")

        dst, src = operands

        # Validate operands don't reference labels (CMP doesn't support direct label addressing)
        for i, operand in enumerate([dst, src]):
            if operand in labels:
                raise ValueError(f"CMP operand {i+1} '{operand}' cannot directly reference label - use register or memory operand")

        # CMP register, register
        if dst.lower() in self.x86_registers and src.lower() in self.x86_registers:
            dst_code = self.x86_registers[dst.lower()]
            src_code = self.x86_registers[src.lower()]
            return b'\x39' + bytes([0xC0 + (src_code << 3) + dst_code])

        raise ValueError(f"Unsupported CMP instruction: {dst}, {src}")

    def _compile_conditional_jump_x86(self, operands: List[str], labels: Dict[str, int],
                                     current_offset: int, position_independent: bool) -> bytes:
        """Compile x86 conditional jump instructions."""
        if len(operands) != 1:
            raise ValueError("Conditional jump requires exactly one operand")

        operand = operands[0]

        if operand in labels:
            target_offset = labels[operand]
            relative_offset = target_offset - (current_offset + 2)  # 2 = size of short jump

            # Use short jump if possible
            if -128 <= relative_offset <= 127:
                jump_opcodes = {
                    'je': b'\x74', 'jz': b'\x74',
                    'jne': b'\x75', 'jnz': b'\x75',
                    'jl': b'\x7C', 'jg': b'\x7F'
                }
                return jump_opcodes.get(operand.lower(), b'\x74') + struct.pack('<b', relative_offset)
            else:
                # Use near jump
                relative_offset = target_offset - (current_offset + 6)  # 6 = size of near jump
                jump_opcodes = {
                    'je': b'\x0F\x84', 'jz': b'\x0F\x84',
                    'jne': b'\x0F\x85', 'jnz': b'\x0F\x85',
                    'jl': b'\x0F\x8C', 'jg': b'\x0F\x8F'
                }
                return jump_opcodes.get(operand.lower(), b'\x0F\x84') + struct.pack('<i', relative_offset)
        else:
            raise ValueError(f"Invalid jump target: {operand}")

    # x64 instruction compilation methods (simplified versions)
    def _compile_call_x64(self, operands: List[str], labels: Dict[str, int],
                         current_offset: int, position_independent: bool) -> bytes:
        """Compile x64 CALL instruction."""
        return self._compile_call_x86(operands, labels, current_offset, position_independent)

    def _compile_jmp_x64(self, operands: List[str], labels: Dict[str, int],
                        current_offset: int, position_independent: bool) -> bytes:
        """Compile x64 JMP instruction."""
        return self._compile_jmp_x86(operands, labels, current_offset, position_independent)

    def _compile_push_x64(self, operands: List[str], labels: Dict[str, int],
                         current_offset: int, position_independent: bool) -> bytes:
        """Compile x64 PUSH instruction."""
        return self._compile_push_x86(operands, labels, current_offset, position_independent)

    def _compile_pop_x64(self, operands: List[str], labels: Dict[str, int],
                        current_offset: int, position_independent: bool) -> bytes:
        """Compile x64 POP instruction."""
        return self._compile_pop_x86(operands, labels, current_offset, position_independent)

    def _compile_mov_x64(self, operands: List[str], labels: Dict[str, int],
                        current_offset: int, position_independent: bool) -> bytes:
        """Compile x64 MOV instruction."""
        return self._compile_mov_x86(operands, labels, current_offset, position_independent)

    def _compile_xor_x64(self, operands: List[str], labels: Dict[str, int],
                        current_offset: int, position_independent: bool) -> bytes:
        """Compile x64 XOR instruction."""
        return self._compile_xor_x86(operands, labels, current_offset, position_independent)

    def _compile_add_x64(self, operands: List[str], labels: Dict[str, int],
                        current_offset: int, position_independent: bool) -> bytes:
        """Compile x64 ADD instruction."""
        return self._compile_add_x86(operands, labels, current_offset, position_independent)

    def _compile_sub_x64(self, operands: List[str], labels: Dict[str, int],
                        current_offset: int, position_independent: bool) -> bytes:
        """Compile x64 SUB instruction."""
        return self._compile_sub_x86(operands, labels, current_offset, position_independent)

    def _compile_test_x64(self, operands: List[str], labels: Dict[str, int],
                         current_offset: int, position_independent: bool) -> bytes:
        """Compile x64 TEST instruction."""
        return self._compile_test_x86(operands, labels, current_offset, position_independent)

    def _compile_cmp_x64(self, operands: List[str], labels: Dict[str, int],
                        current_offset: int, position_independent: bool) -> bytes:
        """Compile x64 CMP instruction."""
        return self._compile_cmp_x86(operands, labels, current_offset, position_independent)
