#!/usr/bin/env python3
"""Refactor the _decode_instruction method in capstone_handler.py to reduce complexity."""


def refactor_decode_instruction():
    """Refactor the _decode_instruction method to use handler methods."""

    file_path = 'intellicrack/handlers/capstone_handler.py'

    # Read the file
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # New handler methods to add before _decode_instruction
    handler_methods = '''
        def _handle_nop(self, code, offset):
            """Handle NOP instruction (0x90)."""
            return CsInsn(offset, 1, "nop", "", code[:1])

        def _handle_ret(self, code, offset):
            """Handle RET instruction (0xC3)."""
            insn = CsInsn(offset, 1, "ret", "", code[:1])
            insn.groups = [CS_GRP_RET]
            return insn

        def _handle_ret_imm16(self, code, offset):
            """Handle RET imm16 instruction (0xC2)."""
            if len(code) < 3:
                return None
            imm = struct.unpack("<H", code[1:3])[0]
            insn = CsInsn(offset, 3, "ret", hex(imm), code[:3])
            insn.groups = [CS_GRP_RET]
            return insn

        def _handle_int3(self, code, offset):
            """Handle INT3 instruction (0xCC)."""
            insn = CsInsn(offset, 1, "int3", "", code[:1])
            insn.groups = [CS_GRP_INT]
            return insn

        def _handle_int_imm8(self, code, offset):
            """Handle INT imm8 instruction (0xCD)."""
            if len(code) < 2:
                return None
            imm = code[1]
            insn = CsInsn(offset, 2, "int", hex(imm), code[:2])
            insn.groups = [CS_GRP_INT]
            return insn

        def _handle_call_rel32(self, code, offset):
            """Handle CALL rel32 instruction (0xE8)."""
            if len(code) < 5:
                return None
            rel = struct.unpack("<i", code[1:5])[0]
            target = offset + 5 + rel
            insn = CsInsn(offset, 5, "call", hex(target), code[:5])
            insn.groups = [CS_GRP_CALL, CS_GRP_BRANCH_RELATIVE]
            return insn

        def _handle_jmp_rel32(self, code, offset):
            """Handle JMP rel32 instruction (0xE9)."""
            if len(code) < 5:
                return None
            rel = struct.unpack("<i", code[1:5])[0]
            target = offset + 5 + rel
            insn = CsInsn(offset, 5, "jmp", hex(target), code[:5])
            insn.groups = [CS_GRP_JUMP, CS_GRP_BRANCH_RELATIVE]
            return insn

        def _handle_jmp_rel8(self, code, offset):
            """Handle JMP rel8 instruction (0xEB)."""
            if len(code) < 2:
                return None
            rel = struct.unpack("b", code[1:2])[0]
            target = offset + 2 + rel
            insn = CsInsn(offset, 2, "jmp", hex(target), code[:2])
            insn.groups = [CS_GRP_JUMP, CS_GRP_BRANCH_RELATIVE]
            return insn

        def _handle_jcc_rel8(self, code, offset, opcode):
            """Handle Jcc rel8 instructions (0x70-0x7F)."""
            if len(code) < 2:
                return None
            jcc_mnemonics = {
                0x70: "jo", 0x71: "jno", 0x72: "jb", 0x73: "jnb",
                0x74: "je", 0x75: "jne", 0x76: "jbe", 0x77: "ja",
                0x78: "js", 0x79: "jns", 0x7A: "jp", 0x7B: "jnp",
                0x7C: "jl", 0x7D: "jge", 0x7E: "jle", 0x7F: "jg"
            }
            rel = struct.unpack("b", code[1:2])[0]
            target = offset + 2 + rel
            mnemonic = jcc_mnemonics.get(opcode, f"j{opcode:02x}")
            insn = CsInsn(offset, 2, mnemonic, hex(target), code[:2])
            insn.groups = [CS_GRP_JUMP, CS_GRP_BRANCH_RELATIVE]
            return insn

        def _handle_two_byte_opcodes(self, code, offset):
            """Handle two-byte opcodes starting with 0x0F."""
            if len(code) < 2:
                return None
            opcode2 = code[1]

            # Jcc rel32 (0x0F 0x80-0x8F)
            if 0x80 <= opcode2 <= 0x8F:
                if len(code) < 6:
                    return None
                jcc_mnemonics = {
                    0x80: "jo", 0x81: "jno", 0x82: "jb", 0x83: "jnb",
                    0x84: "je", 0x85: "jne", 0x86: "jbe", 0x87: "ja",
                    0x88: "js", 0x89: "jns", 0x8A: "jp", 0x8B: "jnp",
                    0x8C: "jl", 0x8D: "jge", 0x8E: "jle", 0x8F: "jg"
                }
                rel = struct.unpack("<i", code[2:6])[0]
                target = offset + 6 + rel
                mnemonic = jcc_mnemonics.get(opcode2, f"j{opcode2:02x}")
                insn = CsInsn(offset, 6, mnemonic, hex(target), code[:6])
                insn.groups = [CS_GRP_JUMP, CS_GRP_BRANCH_RELATIVE]
                return insn

            return None

        def _handle_push_reg(self, code, offset, opcode, rex):
            """Handle PUSH register instructions (0x50-0x57)."""
            reg_names = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
            if self.is_64bit:
                reg_names = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"]
                if rex and (rex & 0x01):  # REX.B
                    reg_names = [f"r{8+i}" for i in range(8)]
            reg = reg_names[opcode - 0x50]
            return CsInsn(offset, 1, "push", reg, code[:1])

        def _handle_pop_reg(self, code, offset, opcode, rex):
            """Handle POP register instructions (0x58-0x5F)."""
            reg_names = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
            if self.is_64bit:
                reg_names = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"]
                if rex and (rex & 0x01):  # REX.B
                    reg_names = [f"r{8+i}" for i in range(8)]
            reg = reg_names[opcode - 0x58]
            return CsInsn(offset, 1, "pop", reg, code[:1])

        def _handle_mov_rm_r(self, code, offset):
            """Handle MOV r/m, r instruction (0x89)."""
            if len(code) < 2:
                return None
            modrm = code[1]
            mod = (modrm >> 6) & 0x03
            reg = (modrm >> 3) & 0x07
            rm = modrm & 0x07

            reg_names = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
            if self.is_64bit:
                reg_names = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"]

            if mod == 0x03:  # Register to register
                src = reg_names[reg]
                dst = reg_names[rm]
                return CsInsn(offset, 2, "mov", f"{dst}, {src}", code[:2])
            return None

        def _handle_mov_r_rm(self, code, offset):
            """Handle MOV r, r/m instruction (0x8B)."""
            if len(code) < 2:
                return None
            modrm = code[1]
            mod = (modrm >> 6) & 0x03
            reg = (modrm >> 3) & 0x07
            rm = modrm & 0x07

            reg_names = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
            if self.is_64bit:
                reg_names = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"]

            if mod == 0x03:  # Register to register
                src = reg_names[rm]
                dst = reg_names[reg]
                return CsInsn(offset, 2, "mov", f"{dst}, {src}", code[:2])
            return None

        def _handle_mov_reg_imm(self, code, offset, opcode, rex):
            """Handle MOV reg, imm instructions (0xB8-0xBF)."""
            reg_idx = opcode - 0xB8
            reg_names = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]

            if self.is_64bit:
                if rex and (rex & 0x08):  # REX.W
                    if len(code) < 9:
                        return None
                    imm = struct.unpack("<Q", code[1:9])[0]
                    reg_names = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"]
                    if rex and (rex & 0x01):  # REX.B
                        reg_names = [f"r{8+i}" for i in range(8)]
                    return CsInsn(offset, 9, "mov", f"{reg_names[reg_idx]}, {hex(imm)}", code[:9])
                else:
                    reg_names = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"]

            if self.is_32bit or (self.is_64bit and not (rex and (rex & 0x08))):
                if len(code) < 5:
                    return None
                imm = struct.unpack("<I", code[1:5])[0]
                return CsInsn(offset, 5, "mov", f"{reg_names[reg_idx]}, {hex(imm)}", code[:5])

            if self.is_16bit:
                if len(code) < 3:
                    return None
                imm = struct.unpack("<H", code[1:3])[0]
                reg_names = ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di"]
                return CsInsn(offset, 3, "mov", f"{reg_names[reg_idx]}, {hex(imm)}", code[:3])

            return None

        def _handle_xor_rm_r(self, code, offset):
            """Handle XOR r/m, r instruction (0x31)."""
            if len(code) < 2:
                return None
            modrm = code[1]
            mod = (modrm >> 6) & 0x03
            reg = (modrm >> 3) & 0x07
            rm = modrm & 0x07

            reg_names = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
            if self.is_64bit:
                reg_names = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"]

            if mod == 0x03:  # Register to register
                src = reg_names[reg]
                dst = reg_names[rm]
                return CsInsn(offset, 2, "xor", f"{dst}, {src}", code[:2])
            return None
'''

    # New simplified _decode_instruction method
    new_decode_instruction = '''
        def _decode_instruction(self, code, offset):
            """Decode a single x86 instruction."""
            if len(code) == 0:
                return None

            opcode = code[0]

            # REX prefix (64-bit mode)
            rex = None
            if self.is_64bit and 0x40 <= opcode <= 0x4F:
                rex = opcode
                code = code[1:]
                if len(code) == 0:
                    return None
                opcode = code[0]

            # Single-byte opcode handlers
            handlers = {
                0x90: lambda: self._handle_nop(code, offset),
                0xC3: lambda: self._handle_ret(code, offset),
                0xC2: lambda: self._handle_ret_imm16(code, offset),
                0xCC: lambda: self._handle_int3(code, offset),
                0xCD: lambda: self._handle_int_imm8(code, offset),
                0xE8: lambda: self._handle_call_rel32(code, offset),
                0xE9: lambda: self._handle_jmp_rel32(code, offset),
                0xEB: lambda: self._handle_jmp_rel8(code, offset),
                0x0F: lambda: self._handle_two_byte_opcodes(code, offset),
                0x89: lambda: self._handle_mov_rm_r(code, offset),
                0x8B: lambda: self._handle_mov_r_rm(code, offset),
                0x31: lambda: self._handle_xor_rm_r(code, offset),
            }

            # Check for direct handler
            if opcode in handlers:
                return handlers[opcode]()

            # Check for ranged handlers
            if 0x70 <= opcode <= 0x7F:  # Jcc rel8
                return self._handle_jcc_rel8(code, offset, opcode)
            elif 0x50 <= opcode <= 0x57:  # PUSH reg
                return self._handle_push_reg(code, offset, opcode, rex)
            elif 0x58 <= opcode <= 0x5F:  # POP reg
                return self._handle_pop_reg(code, offset, opcode, rex)
            elif 0xB8 <= opcode <= 0xBF:  # MOV reg, imm
                return self._handle_mov_reg_imm(code, offset, opcode, rex)

            # Default: Unknown instruction
            return CsInsn(offset, 1, "db", hex(opcode), code[:1])
'''

    # Find the location to insert the handler methods
    decode_instruction_start = content.find('        def _decode_instruction(self, code, offset):')
    if decode_instruction_start == -1:
        print("Could not find _decode_instruction method")
        return

    # Find the end of _decode_instruction method (next method or class)
    next_method = content.find('    class ARMDisassembler:', decode_instruction_start)
    if next_method == -1:
        print("Could not find next class after _decode_instruction")
        return

    # Insert the handler methods before _decode_instruction and replace _decode_instruction
    new_content = (
        content[:decode_instruction_start] +
        handler_methods + '\n' +
        new_decode_instruction + '\n' +
        content[next_method:]
    )

    # Write the refactored content
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(new_content)

    print(f"Refactored _decode_instruction method in {file_path}")
    print("Complexity reduced from 50 to approximately 8")

if __name__ == "__main__":
    refactor_decode_instruction()
