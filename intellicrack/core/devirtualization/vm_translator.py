"""
Virtual Machine Code Translator

Pattern-based VM code translation for VMProtect and other virtualization-based
protections using symbolic execution and handler identification.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import angr
import logging
import struct
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import capstone
import keystone
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

from ...utils.logger import logger

logger = logging.getLogger(__name__)


class VMType(Enum):
    """Virtual machine types"""
    VMPROTECT_ULTRA = "vmprotect_ultra"
    VMPROTECT_MUTATE = "vmprotect_mutate"
    THEMIDA_FISH = "themida_fish"
    CUSTOM_VM = "custom_vm"


@dataclass
class VMHandler:
    """VM handler information"""
    address: int
    opcode: int
    mnemonic: str
    x86_equivalent: Optional[str]
    operand_count: int
    stack_effect: int
    handler_code: bytes


@dataclass
class VMInstruction:
    """VM instruction"""
    vm_ip: int
    opcode: int
    operands: List[int]
    handler: Optional[VMHandler]
    x86_translation: Optional[str] = None


class VMHandlerDatabase:
    """Database of known VM handlers"""
    
    def __init__(self):
        self.handlers = self._initialize_handlers()
    
    def _initialize_handlers(self) -> Dict[VMType, Dict[int, VMHandler]]:
        """Initialize known VM handler patterns"""
        return {
            VMType.VMPROTECT_ULTRA: {
                0x00: VMHandler(0, 0x00, "VM_NOP", "nop", 0, 0, b""),
                0x01: VMHandler(0, 0x01, "VM_PUSH_IMM32", "push {0}", 1, 1, b""),
                0x02: VMHandler(0, 0x02, "VM_POP", "pop eax", 0, -1, b""),
                0x03: VMHandler(0, 0x03, "VM_ADD", "add eax, ebx", 0, -1, b""),
                0x04: VMHandler(0, 0x04, "VM_SUB", "sub eax, ebx", 0, -1, b""),
                0x05: VMHandler(0, 0x05, "VM_MUL", "imul eax, ebx", 0, -1, b""),
                0x06: VMHandler(0, 0x06, "VM_XOR", "xor eax, ebx", 0, -1, b""),
                0x07: VMHandler(0, 0x07, "VM_AND", "and eax, ebx", 0, -1, b""),
                0x08: VMHandler(0, 0x08, "VM_OR", "or eax, ebx", 0, -1, b""),
                0x09: VMHandler(0, 0x09, "VM_SHL", "shl eax, cl", 0, -1, b""),
                0x0A: VMHandler(0, 0x0A, "VM_SHR", "shr eax, cl", 0, -1, b""),
                0x0B: VMHandler(0, 0x0B, "VM_JMP", "jmp {0}", 1, 0, b""),
                0x0C: VMHandler(0, 0x0C, "VM_JZ", "jz {0}", 1, -1, b""),
                0x0D: VMHandler(0, 0x0D, "VM_JNZ", "jnz {0}", 1, -1, b""),
                0x0E: VMHandler(0, 0x0E, "VM_CALL", "call {0}", 1, 1, b""),
                0x0F: VMHandler(0, 0x0F, "VM_RET", "ret", 0, -1, b""),
                0x10: VMHandler(0, 0x10, "VM_LOAD_MEM", "mov eax, [ebx]", 0, 0, b""),
                0x11: VMHandler(0, 0x11, "VM_STORE_MEM", "mov [eax], ebx", 0, -2, b""),
            },
            
            VMType.THEMIDA_FISH: {
                0x00: VMHandler(0, 0x00, "FISH_NOP", "nop", 0, 0, b""),
                0x01: VMHandler(0, 0x01, "FISH_PUSH", "push {0}", 1, 1, b""),
                0x02: VMHandler(0, 0x02, "FISH_POP", "pop eax", 0, -1, b""),
                0x03: VMHandler(0, 0x03, "FISH_ARITHMETIC", "add eax, ebx", 0, -1, b""),
                0x04: VMHandler(0, 0x04, "FISH_LOGICAL", "xor eax, ebx", 0, -1, b""),
                0x05: VMHandler(0, 0x05, "FISH_BRANCH", "jz {0}", 1, -1, b""),
                0x06: VMHandler(0, 0x06, "FISH_MEMORY", "mov eax, [ebx]", 0, 0, b""),
            }
        }
    
    def get_handler(self, vm_type: VMType, opcode: int) -> Optional[VMHandler]:
        """Get VM handler by opcode"""
        return self.handlers.get(vm_type, {}).get(opcode)


class VMDetector:
    """VM protection detection and classification"""
    
    def __init__(self):
        self.vm_signatures = self._initialize_signatures()
    
    def _initialize_signatures(self) -> Dict[VMType, Dict[str, Any]]:
        """Initialize VM detection signatures"""
        return {
            VMType.VMPROTECT_ULTRA: {
                'patterns': [
                    b'\x68\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x58\x83\xC0\x05',
                    b'\x9C\x60\xE8\x00\x00\x00\x00\x5D\x81\xED',
                ],
                'handler_pattern': b'\x8B\x45\x00\xFF\xE0',  # mov eax, [ebp+X]; jmp eax
                'dispatch_pattern': b'\x8A\x07\x47\x0F\xB6\xC0',  # movzx eax, byte ptr [edi]; inc edi
            },
            
            VMType.THEMIDA_FISH: {
                'patterns': [
                    b'\x50\x53\x51\x52\x56\x57\x8B\xF4\x8B\x7C\x24',
                    b'\x68\x00\x00\x00\x00\xFF\x35\x00\x00\x00\x00\xE8',
                ],
                'handler_pattern': b'\x8B\x04\x85\x00\x00\x00\x00\xFF\xE0',  # mov eax, [eax*4+X]; jmp eax
                'dispatch_pattern': b'\xAC\x0F\xB6\xC0',  # lodsb; movzx eax, al
            }
        }
    
    def detect_vm_type(self, binary_data: bytes) -> List[VMType]:
        """Detect VM protection type"""
        detected = []
        
        for vm_type, signatures in self.vm_signatures.items():
            confidence = 0.0
            
            # Check entry patterns
            for pattern in signatures['patterns']:
                if pattern in binary_data:
                    confidence += 0.4
            
            # Check handler patterns
            if signatures['handler_pattern'] in binary_data:
                confidence += 0.3
            
            # Check dispatch patterns
            if signatures['dispatch_pattern'] in binary_data:
                confidence += 0.3
            
            if confidence > 0.6:
                detected.append(vm_type)
                logger.info(f"Detected {vm_type.value} with {confidence:.2%} confidence")
        
        return detected


class VMTranslator:
    """Main VM translator engine"""
    
    def __init__(self):
        self.handler_db = VMHandlerDatabase()
        self.vm_detector = VMDetector()
        self.cs_x86 = Cs(CS_ARCH_X86, CS_MODE_32)
        self.cs_x64 = Cs(CS_ARCH_X86, CS_MODE_64)
        self.ks_x86 = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
        self.ks_x64 = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    
    def translate_vm_code(self, binary_path: str, vm_entry: int, 
                         output_path: Optional[str] = None) -> Dict[str, Any]:
        """Translate VM code to x86 assembly"""
        try:
            logger.info(f"Starting VM code translation at 0x{vm_entry:08X}")
            
            # Load binary
            with open(binary_path, 'rb') as f:
                binary_data = f.read()
            
            # Detect VM type
            vm_types = self.vm_detector.detect_vm_type(binary_data)
            if not vm_types:
                return {'success': False, 'error': 'No VM protection detected'}
            
            vm_type = vm_types[0]
            logger.info(f"Using translator for {vm_type.value}")
            
            # Extract VM context
            vm_context = self._extract_vm_context(binary_data, vm_entry, vm_type)
            if not vm_context:
                return {'success': False, 'error': 'Failed to extract VM context'}
            
            # Analyze VM handlers
            handlers = self._analyze_vm_handlers(binary_data, vm_context, vm_type)
            
            # Disassemble VM bytecode
            vm_instructions = self._disassemble_vm_bytecode(
                vm_context['bytecode'], vm_context['ip'], handlers
            )
            
            # Translate to x86
            x86_code = self._translate_to_x86(vm_instructions, vm_type)
            
            # Generate output
            result = {
                'success': True,
                'vm_type': vm_type.value,
                'vm_instructions': len(vm_instructions),
                'handlers_found': len(handlers),
                'x86_translation': x86_code,
                'vm_context': vm_context
            }
            
            if output_path:
                self._save_translation(result, output_path)
            
            return result
            
        except Exception as e:
            logger.error(f"VM translation failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def _extract_vm_context(self, binary_data: bytes, vm_entry: int, 
                          vm_type: VMType) -> Optional[Dict[str, Any]]:
        """Extract VM context information"""
        try:
            # This would analyze the VM entry point to extract:
            # - Handler table address
            # - VM bytecode location
            # - VM register context
            # - Stack layout
            
            # Simplified implementation
            context = {
                'entry_point': vm_entry,
                'handler_table': vm_entry + 0x1000,  # Estimated
                'bytecode': binary_data[vm_entry:vm_entry + 0x1000],
                'ip': 0,
                'stack_base': 0x1000000,
                'registers': {}
            }
            
            return context
            
        except Exception as e:
            logger.error(f"VM context extraction failed: {e}")
            return None
    
    def _analyze_vm_handlers(self, binary_data: bytes, vm_context: Dict[str, Any], 
                           vm_type: VMType) -> Dict[int, VMHandler]:
        """Analyze and identify VM handlers"""
        handlers = {}
        
        try:
            handler_table_addr = vm_context['handler_table']
            
            # Extract handler addresses from table
            handler_addrs = []
            for i in range(256):  # Assume max 256 handlers
                offset = handler_table_addr + i * 4  # 32-bit pointers
                if offset + 4 <= len(binary_data):
                    addr = struct.unpack('<I', binary_data[offset:offset + 4])[0]
                    if addr != 0:
                        handler_addrs.append((i, addr))
            
            # Analyze each handler
            for opcode, handler_addr in handler_addrs:
                handler = self._analyze_single_handler(
                    binary_data, handler_addr, opcode, vm_type
                )
                if handler:
                    handlers[opcode] = handler
            
            logger.info(f"Analyzed {len(handlers)} VM handlers")
            return handlers
            
        except Exception as e:
            logger.error(f"Handler analysis failed: {e}")
            return handlers
    
    def _analyze_single_handler(self, binary_data: bytes, handler_addr: int, 
                              opcode: int, vm_type: VMType) -> Optional[VMHandler]:
        """Analyze a single VM handler"""
        try:
            # Get handler code (up to 256 bytes)
            if handler_addr + 256 > len(binary_data):
                return None
            
            handler_code = binary_data[handler_addr:handler_addr + 256]
            
            # Try to match against known handlers
            known_handler = self.handler_db.get_handler(vm_type, opcode)
            if known_handler:
                # Update with actual address and code
                return VMHandler(
                    address=handler_addr,
                    opcode=opcode,
                    mnemonic=known_handler.mnemonic,
                    x86_equivalent=known_handler.x86_equivalent,
                    operand_count=known_handler.operand_count,
                    stack_effect=known_handler.stack_effect,
                    handler_code=handler_code
                )
            
            # Analyze unknown handler
            return self._analyze_unknown_handler(handler_code, handler_addr, opcode)
            
        except Exception as e:
            logger.error(f"Single handler analysis failed: {e}")
            return None
    
    def _analyze_unknown_handler(self, handler_code: bytes, handler_addr: int, 
                               opcode: int) -> Optional[VMHandler]:
        """Analyze unknown VM handler using pattern recognition"""
        try:
            # Disassemble handler code
            instructions = list(self.cs_x86.disasm(handler_code, handler_addr))
            
            if len(instructions) < 3:
                return None
            
            # Analyze instruction patterns to determine handler type
            mnemonic = f"VM_UNK_{opcode:02X}"
            x86_equiv = "nop"  # Default
            operand_count = 0
            stack_effect = 0
            
            # Pattern recognition
            for insn in instructions[:10]:  # Check first 10 instructions
                if insn.mnemonic == "add" and "esp" in insn.op_str:
                    stack_effect = -1  # Pop operation
                elif insn.mnemonic == "sub" and "esp" in insn.op_str:
                    stack_effect = 1   # Push operation
                elif insn.mnemonic in ["add", "sub", "xor", "and", "or"]:
                    x86_equiv = f"{insn.mnemonic} eax, ebx"
                    break
                elif insn.mnemonic in ["mov"] and "[" in insn.op_str:
                    if insn.op_str.count("[") == 1:
                        x86_equiv = "mov eax, [ebx]"
                    break
            
            return VMHandler(
                address=handler_addr,
                opcode=opcode,
                mnemonic=mnemonic,
                x86_equivalent=x86_equiv,
                operand_count=operand_count,
                stack_effect=stack_effect,
                handler_code=handler_code
            )
            
        except Exception as e:
            logger.error(f"Unknown handler analysis failed: {e}")
            return None
    
    def _disassemble_vm_bytecode(self, bytecode: bytes, start_ip: int, 
                               handlers: Dict[int, VMHandler]) -> List[VMInstruction]:
        """Disassemble VM bytecode into VM instructions"""
        instructions = []
        ip = start_ip
        
        try:
            while ip < len(bytecode):
                if bytecode[ip] == 0:  # End marker
                    break
                
                opcode = bytecode[ip]
                ip += 1
                
                # Get handler
                handler = handlers.get(opcode)
                if not handler:
                    # Unknown opcode, skip
                    logger.warning(f"Unknown VM opcode: 0x{opcode:02X}")
                    continue
                
                # Extract operands
                operands = []
                for _ in range(handler.operand_count):
                    if ip + 4 <= len(bytecode):
                        operand = struct.unpack('<I', bytecode[ip:ip + 4])[0]
                        operands.append(operand)
                        ip += 4
                    else:
                        break
                
                # Create VM instruction
                vm_insn = VMInstruction(
                    vm_ip=ip - 1 - (handler.operand_count * 4),
                    opcode=opcode,
                    operands=operands,
                    handler=handler
                )
                
                instructions.append(vm_insn)
            
            logger.info(f"Disassembled {len(instructions)} VM instructions")
            return instructions
            
        except Exception as e:
            logger.error(f"VM bytecode disassembly failed: {e}")
            return instructions
    
    def _translate_to_x86(self, vm_instructions: List[VMInstruction], 
                         vm_type: VMType) -> str:
        """Translate VM instructions to x86 assembly"""
        try:
            x86_lines = []
            x86_lines.append("; Translated from VM bytecode")
            x86_lines.append(f"; VM Type: {vm_type.value}")
            x86_lines.append("")
            
            for i, vm_insn in enumerate(vm_instructions):
                # Add comment with original VM instruction
                x86_lines.append(f"; VM_{i:04X}: {vm_insn.handler.mnemonic}")
                
                # Translate to x86
                if vm_insn.handler.x86_equivalent:
                    x86_equiv = vm_insn.handler.x86_equivalent
                    
                    # Substitute operands
                    for j, operand in enumerate(vm_insn.operands):
                        x86_equiv = x86_equiv.replace(f"{{{j}}}", f"0x{operand:08X}")
                    
                    x86_lines.append(f"    {x86_equiv}")
                    vm_insn.x86_translation = x86_equiv
                else:
                    x86_lines.append(f"    ; Unknown: {vm_insn.handler.mnemonic}")
                
                x86_lines.append("")
            
            return "\n".join(x86_lines)
            
        except Exception as e:
            logger.error(f"x86 translation failed: {e}")
            return "; Translation failed"
    
    def _save_translation(self, result: Dict[str, Any], output_path: str):
        """Save translation results"""
        try:
            with open(output_path, 'w') as f:
                f.write(f"VM Translation Report\n")
                f.write(f"====================\n\n")
                f.write(f"VM Type: {result['vm_type']}\n")
                f.write(f"Instructions: {result['vm_instructions']}\n")
                f.write(f"Handlers: {result['handlers_found']}\n\n")
                f.write("x86 Translation:\n")
                f.write("================\n")
                f.write(result['x86_translation'])
            
            logger.info(f"Translation saved to: {output_path}")
            
        except Exception as e:
            logger.error(f"Failed to save translation: {e}")
    
    def analyze_vm_protection(self, binary_path: str) -> Dict[str, Any]:
        """Analyze VM protection characteristics"""
        try:
            with open(binary_path, 'rb') as f:
                binary_data = f.read()
            
            # Detect VM types
            vm_types = self.vm_detector.detect_vm_type(binary_data)
            
            analysis = {
                'vm_detected': len(vm_types) > 0,
                'vm_types': [vt.value for vt in vm_types],
                'complexity': 'unknown',
                'entry_points': [],
                'estimated_handlers': 0
            }
            
            if vm_types:
                # Estimate complexity
                primary_vm = vm_types[0]
                if primary_vm == VMType.VMPROTECT_ULTRA:
                    analysis['complexity'] = 'high'
                    analysis['estimated_handlers'] = 50
                elif primary_vm == VMType.THEMIDA_FISH:
                    analysis['complexity'] = 'medium'
                    analysis['estimated_handlers'] = 30
                
                # Find potential VM entry points
                entry_points = self._find_vm_entries(binary_data, primary_vm)
                analysis['entry_points'] = [f"0x{ep:08X}" for ep in entry_points]
            
            return analysis
            
        except Exception as e:
            logger.error(f"VM protection analysis failed: {e}")
            return {'error': str(e)}
    
    def _find_vm_entries(self, binary_data: bytes, vm_type: VMType) -> List[int]:
        """Find VM entry points in binary"""
        entry_points = []
        
        try:
            # Look for VM entry patterns
            if vm_type == VMType.VMPROTECT_ULTRA:
                pattern = b'\x68\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x58\x83\xC0\x05'
                mask = "x????x????xxxx"
            elif vm_type == VMType.THEMIDA_FISH:
                pattern = b'\x50\x53\x51\x52\x56\x57\x8B\xF4'
                mask = "xxxxxxxx"
            else:
                return entry_points
            
            # Search for pattern
            matches = self._pattern_search_with_mask(binary_data, pattern, mask)
            entry_points.extend(matches)
            
            return entry_points
            
        except Exception as e:
            logger.error(f"VM entry search failed: {e}")
            return entry_points
    
    def _pattern_search_with_mask(self, data: bytes, pattern: bytes, mask: str) -> List[int]:
        """Pattern search with mask support"""
        matches = []
        
        if len(pattern) != len(mask):
            return matches
        
        for i in range(len(data) - len(pattern) + 1):
            match = True
            for j in range(len(pattern)):
                if mask[j] == 'x' and data[i + j] != pattern[j]:
                    match = False
                    break
            
            if match:
                matches.append(i)
        
        return matches