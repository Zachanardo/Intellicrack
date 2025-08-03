"""
Virtualization-Based Protection Detection Engine

Specialized detection for virtualization-based obfuscation techniques including:
- Code virtualization detection
- Bytecode interpretation identification
- VM-based protection analysis
- JIT compilation detection
- Custom instruction set recognition

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import logging
import re
import struct
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

from ....utils.logger import get_logger

logger = get_logger(__name__)

try:
    import r2pipe
    R2_AVAILABLE = True
except ImportError:
    R2_AVAILABLE = False


@dataclass
class VMPattern:
    """Detected virtualization pattern"""
    address: int
    vm_type: str
    confidence: float
    indicators: List[str]
    metadata: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'address': self.address,
            'vm_type': self.vm_type,
            'confidence': self.confidence,
            'indicators': self.indicators,
            'metadata': self.metadata
        }


@dataclass
class VMArchitecture:
    """Virtual machine architecture analysis"""
    entry_point: int
    bytecode_sections: List[Tuple[int, int]]  # (start, size) pairs
    handler_table: Optional[int]
    dispatch_function: Optional[int]
    vm_registers: List[str]
    instruction_format: str
    complexity_score: float
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'entry_point': self.entry_point,
            'bytecode_sections': self.bytecode_sections,
            'handler_table': self.handler_table,
            'dispatch_function': self.dispatch_function,
            'vm_registers': self.vm_registers,
            'instruction_format': self.instruction_format,
            'complexity_score': self.complexity_score
        }


class VirtualizationDetector:
    """Advanced virtualization-based protection detector"""
    
    def __init__(self, r2_session: Optional[Any] = None):
        """Initialize virtualization detector
        
        Args:
            r2_session: Optional radare2 session
        """
        self.r2 = r2_session
        self.logger = logger
        
        # Detection thresholds
        self.vm_confidence_threshold = 0.6
        self.bytecode_confidence_threshold = 0.5
        self.jit_confidence_threshold = 0.7
        
        # Known VM signatures and patterns
        self.vm_signatures = self._load_vm_signatures()
        self.bytecode_patterns = self._load_bytecode_patterns()
        
    def detect_code_virtualization(self) -> List[VMPattern]:
        """Detect code virtualization patterns
        
        Returns:
            List of detected virtualization patterns
        """
        patterns = []
        
        if not self.r2:
            return patterns
        
        try:
            # Look for VM dispatch patterns
            dispatch_patterns = self._find_vm_dispatch_patterns()
            patterns.extend(dispatch_patterns)
            
            # Look for interpreter loops
            interpreter_patterns = self._find_interpreter_loops()
            patterns.extend(interpreter_patterns)
            
            # Look for custom opcode handlers
            handler_patterns = self._find_opcode_handlers()
            patterns.extend(handler_patterns)
            
            return patterns
            
        except Exception as e:
            self.logger.error(f"Code virtualization detection failed: {e}")
            return []
    
    def detect_bytecode_interpretation(self) -> List[VMPattern]:
        """Detect bytecode interpretation patterns
        
        Returns:
            List of detected bytecode interpretation patterns
        """
        patterns = []
        
        if not self.r2:
            return patterns
        
        try:
            # Look for bytecode sections
            bytecode_sections = self._find_bytecode_sections()
            
            for section_addr, section_size in bytecode_sections:
                # Analyze bytecode format
                bytecode_analysis = self._analyze_bytecode_format(section_addr, section_size)
                
                if bytecode_analysis['confidence'] > self.bytecode_confidence_threshold:
                    pattern = VMPattern(
                        address=section_addr,
                        vm_type='bytecode_interpreter',
                        confidence=bytecode_analysis['confidence'],
                        indicators=bytecode_analysis['indicators'],
                        metadata={
                            'section_size': section_size,
                            'instruction_format': bytecode_analysis.get('format', 'unknown'),
                            'estimated_instructions': bytecode_analysis.get('instruction_count', 0)
                        }
                    )
                    patterns.append(pattern)
            
            return patterns
            
        except Exception as e:
            self.logger.error(f"Bytecode interpretation detection failed: {e}")
            return []
    
    def detect_vm_based_protection(self) -> List[VMPattern]:
        """Detect VM-based protection schemes
        
        Returns:
            List of detected VM protection patterns
        """
        patterns = []
        
        if not self.r2:
            return patterns
        
        try:
            # Check for known VM protectors
            known_vm_patterns = self._detect_known_vm_protectors()
            patterns.extend(known_vm_patterns)
            
            # Look for VM context switching
            context_patterns = self._detect_vm_context_switching()
            patterns.extend(context_patterns)
            
            # Look for VM stack operations
            stack_patterns = self._detect_vm_stack_operations()
            patterns.extend(stack_patterns)
            
            return patterns
            
        except Exception as e:
            self.logger.error(f"VM-based protection detection failed: {e}")
            return []
    
    def detect_jit_compilation(self) -> List[VMPattern]:
        """Detect JIT compilation patterns
        
        Returns:
            List of detected JIT compilation patterns
        """
        patterns = []
        
        if not self.r2:
            return patterns
        
        try:
            # Look for dynamic code generation
            codegen_patterns = self._detect_dynamic_code_generation()
            
            for pattern in codegen_patterns:
                if pattern['confidence'] > self.jit_confidence_threshold:
                    vm_pattern = VMPattern(
                        address=pattern['address'],
                        vm_type='jit_compiler',
                        confidence=pattern['confidence'],
                        indicators=pattern['indicators'],
                        metadata=pattern['metadata']
                    )
                    patterns.append(vm_pattern)
            
            return patterns
            
        except Exception as e:
            self.logger.error(f"JIT compilation detection failed: {e}")
            return []
    
    def analyze_vm_architecture(self) -> Optional[VMArchitecture]:
        """Analyze the virtual machine architecture
        
        Returns:
            VM architecture analysis or None if no VM detected
        """
        if not self.r2:
            return None
        
        try:
            # Find VM entry point
            entry_point = self._find_vm_entry_point()
            if not entry_point:
                return None
            
            # Find bytecode sections
            bytecode_sections = self._find_bytecode_sections()
            
            # Find handler table
            handler_table = self._find_handler_table()
            
            # Find dispatch function
            dispatch_function = self._find_dispatch_function()
            
            # Analyze VM registers/context
            vm_registers = self._analyze_vm_registers()
            
            # Determine instruction format
            instruction_format = self._determine_instruction_format(bytecode_sections)
            
            # Calculate complexity score
            complexity_score = self._calculate_vm_complexity(
                bytecode_sections, handler_table, vm_registers
            )
            
            return VMArchitecture(
                entry_point=entry_point,
                bytecode_sections=bytecode_sections,
                handler_table=handler_table,
                dispatch_function=dispatch_function,
                vm_registers=vm_registers,
                instruction_format=instruction_format,
                complexity_score=complexity_score
            )
            
        except Exception as e:
            self.logger.error(f"VM architecture analysis failed: {e}")
            return None
    
    def _find_vm_dispatch_patterns(self) -> List[VMPattern]:
        """Find virtual machine dispatch patterns"""
        patterns = []
        
        if not self.r2:
            return patterns
        
        try:
            functions = self.r2.cmdj("aflj") or []
            
            for func in functions:
                func_addr = func.get('offset', 0)
                disasm = self.r2.cmd(f"pdf @ {func_addr}")
                
                indicators = []
                confidence = 0.0
                metadata = {}
                
                # Look for switch/jump table patterns
                if self._has_switch_table(disasm):
                    indicators.append('switch_table_dispatch')
                    confidence += 0.3
                
                # Look for computed jumps
                if self._has_computed_jumps(disasm):
                    indicators.append('computed_jumps')
                    confidence += 0.2
                
                # Look for opcode fetching patterns
                if self._has_opcode_fetching(disasm):
                    indicators.append('opcode_fetching')
                    confidence += 0.3
                
                # Look for VM context manipulation
                if self._has_vm_context_manipulation(disasm):
                    indicators.append('vm_context_manipulation')
                    confidence += 0.2
                
                if confidence > self.vm_confidence_threshold:
                    pattern = VMPattern(
                        address=func_addr,
                        vm_type='vm_dispatcher',
                        confidence=min(confidence, 1.0),
                        indicators=indicators,
                        metadata=metadata
                    )
                    patterns.append(pattern)
            
            return patterns
            
        except Exception as e:
            self.logger.error(f"VM dispatch pattern detection failed: {e}")
            return []
    
    def _find_interpreter_loops(self) -> List[VMPattern]:
        """Find interpreter loop patterns"""
        patterns = []
        
        if not self.r2:
            return patterns
        
        try:
            functions = self.r2.cmdj("aflj") or []
            
            for func in functions:
                func_addr = func.get('offset', 0)
                disasm = self.r2.cmd(f"pdf @ {func_addr}")
                
                # Look for characteristics of interpreter loops
                if self._is_interpreter_loop(disasm):
                    indicators = self._analyze_interpreter_loop(disasm)
                    
                    pattern = VMPattern(
                        address=func_addr,
                        vm_type='interpreter_loop',
                        confidence=0.8,
                        indicators=indicators,
                        metadata={'function_size': len(disasm.split('\n'))}
                    )
                    patterns.append(pattern)
            
            return patterns
            
        except Exception as e:
            self.logger.error(f"Interpreter loop detection failed: {e}")
            return []
    
    def _find_opcode_handlers(self) -> List[VMPattern]:
        """Find opcode handler patterns"""
        patterns = []
        
        if not self.r2:
            return patterns
        
        try:
            functions = self.r2.cmdj("aflj") or []
            
            # Look for groups of similar small functions (likely handlers)
            small_functions = [f for f in functions if f.get('size', 0) < 200]
            
            if len(small_functions) > 10:  # Likely has handler table
                # Analyze function similarities
                handler_groups = self._group_similar_functions(small_functions)
                
                for group in handler_groups:
                    if len(group) > 5:  # Significant number of handlers
                        pattern = VMPattern(
                            address=group[0]['offset'],
                            vm_type='opcode_handlers',
                            confidence=0.7,
                            indicators=['multiple_small_functions', 'handler_pattern'],
                            metadata={
                                'handler_count': len(group),
                                'average_size': sum(f.get('size', 0) for f in group) / len(group)
                            }
                        )
                        patterns.append(pattern)
            
            return patterns
            
        except Exception as e:
            self.logger.error(f"Opcode handler detection failed: {e}")
            return []
    
    def _find_bytecode_sections(self) -> List[Tuple[int, int]]:
        """Find potential bytecode sections"""
        sections = []
        
        if not self.r2:
            return sections
        
        try:
            # Get all sections
            section_info = self.r2.cmdj("iSj") or []
            
            for section in section_info:
                if self._is_potential_bytecode_section(section):
                    addr = section.get('vaddr', 0)
                    size = section.get('vsize', 0)
                    sections.append((addr, size))
            
            # Also look for data sections with high entropy but structured patterns
            data_sections = self._find_structured_data_sections()
            sections.extend(data_sections)
            
            return sections
            
        except Exception as e:
            self.logger.error(f"Bytecode section detection failed: {e}")
            return []
    
    def _analyze_bytecode_format(self, addr: int, size: int) -> Dict[str, Any]:
        """Analyze bytecode format at given address"""
        analysis = {
            'confidence': 0.0,
            'indicators': [],
            'format': 'unknown',
            'instruction_count': 0
        }
        
        if not self.r2:
            return analysis
        
        try:
            # Read bytecode data
            data = self.r2.cmd(f"p8 {min(size, 1024)} @ {addr}")
            if not data:
                return analysis
            
            bytes_data = bytes.fromhex(data)
            
            # Analyze patterns in the bytecode
            analysis.update(self._detect_bytecode_patterns(bytes_data))
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Bytecode format analysis failed: {e}")
            return analysis
    
    def _detect_known_vm_protectors(self) -> List[VMPattern]:
        """Detect known VM-based protectors"""
        patterns = []
        
        # Check for VMProtect signatures
        vmprotect_patterns = self._detect_vmprotect()
        patterns.extend(vmprotect_patterns)
        
        # Check for Themida/WinLicense VM
        themida_patterns = self._detect_themida_vm()
        patterns.extend(themida_patterns)
        
        # Check for Code Virtualizer
        cv_patterns = self._detect_code_virtualizer()
        patterns.extend(cv_patterns)
        
        return patterns
    
    def _detect_vmprotect(self) -> List[VMPattern]:
        """Detect VMProtect virtualization"""
        patterns = []
        
        if not self.r2:
            return patterns
        
        try:
            # Look for VMProtect-specific patterns
            vmprotect_sigs = [
                b'\x68\x00\x00\x00\x00\x50\x68',  # VMProtect entry pattern
                b'\xE8\x00\x00\x00\x00\x58\x83\xC0',  # VMProtect context setup
            ]
            
            for sig in vmprotect_sigs:
                matches = self._search_binary_pattern(sig)
                for match_addr in matches:
                    pattern = VMPattern(
                        address=match_addr,
                        vm_type='vmprotect',
                        confidence=0.9,
                        indicators=['vmprotect_signature'],
                        metadata={'signature_type': 'binary_pattern'}
                    )
                    patterns.append(pattern)
            
            return patterns
            
        except Exception as e:
            self.logger.error(f"VMProtect detection failed: {e}")
            return []
    
    def _load_vm_signatures(self) -> Dict[str, List[bytes]]:
        """Load known VM protection signatures"""
        return {
            'vmprotect': [
                b'\x68\x00\x00\x00\x00\x50\x68',
                b'\xE8\x00\x00\x00\x00\x58\x83\xC0',
            ],
            'themida': [
                b'\x8B\x85\x00\x00\x00\x00\x89\x85',
                b'\x50\x53\x51\x52\x56\x57\x55',
            ],
            'code_virtualizer': [
                b'\x60\x61\x9C\x9D\x50\x58',
                b'\xFF\x35\x00\x00\x00\x00\x8F\x05',
            ]
        }
    
    def _load_bytecode_patterns(self) -> List[Dict[str, Any]]:
        """Load known bytecode patterns"""
        return [
            {
                'name': 'stack_based_vm',
                'pattern': r'[\x50-\x57][\x58-\x5F]',  # push/pop patterns
                'confidence': 0.6
            },
            {
                'name': 'register_based_vm', 
                'pattern': r'[\x88-\x8B][\x40-\x47]',  # mov reg patterns
                'confidence': 0.7
            }
        ]    
    def _detect_themida_vm(self) -> List[VMPattern]:
        """Detect Themida/WinLicense VM patterns"""
        patterns = []
        
        if not self.r2:
            return patterns
        
        try:
            # Look for Themida-specific VM patterns
            themida_indicators = self._search_themida_patterns()
            
            if themida_indicators:
                pattern = VMPattern(
                    address=themida_indicators[0],
                    vm_type='themida_vm',
                    confidence=0.85,
                    indicators=['themida_vm_signature'],
                    metadata={'pattern_matches': len(themida_indicators)}
                )
                patterns.append(pattern)
            
            return patterns
            
        except Exception as e:
            self.logger.error(f"Themida VM detection failed: {e}")
            return []
    
    def _detect_code_virtualizer(self) -> List[VMPattern]:
        """Detect Code Virtualizer patterns"""
        patterns = []
        
        if not self.r2:
            return patterns
        
        try:
            # Look for Code Virtualizer-specific patterns
            cv_indicators = self._search_code_virtualizer_patterns()
            
            if cv_indicators:
                pattern = VMPattern(
                    address=cv_indicators[0],
                    vm_type='code_virtualizer',
                    confidence=0.8,
                    indicators=['code_virtualizer_signature'],
                    metadata={'pattern_matches': len(cv_indicators)}
                )
                patterns.append(pattern)
            
            return patterns
            
        except Exception as e:
            self.logger.error(f"Code Virtualizer detection failed: {e}")
            return []
    
    def _detect_vm_context_switching(self) -> List[VMPattern]:
        """Detect VM context switching patterns"""
        patterns = []
        
        if not self.r2:
            return patterns
        
        try:
            functions = self.r2.cmdj("aflj") or []
            
            for func in functions:
                func_addr = func.get('offset', 0)
                disasm = self.r2.cmd(f"pdf @ {func_addr}")
                
                if self._has_context_switching(disasm):
                    pattern = VMPattern(
                        address=func_addr,
                        vm_type='vm_context_switch',
                        confidence=0.75,
                        indicators=['context_switching', 'vm_state_management'],
                        metadata={'function_type': 'context_switcher'}
                    )
                    patterns.append(pattern)
            
            return patterns
            
        except Exception as e:
            self.logger.error(f"VM context switching detection failed: {e}")
            return []
    
    def _detect_vm_stack_operations(self) -> List[VMPattern]:
        """Detect VM stack operation patterns"""
        patterns = []
        
        if not self.r2:
            return patterns
        
        try:
            functions = self.r2.cmdj("aflj") or []
            
            for func in functions:
                func_addr = func.get('offset', 0)
                disasm = self.r2.cmd(f"pdf @ {func_addr}")
                
                stack_ops = self._analyze_vm_stack_operations(disasm)
                if stack_ops['confidence'] > 0.6:
                    pattern = VMPattern(
                        address=func_addr,
                        vm_type='vm_stack_handler',
                        confidence=stack_ops['confidence'],
                        indicators=stack_ops['indicators'],
                        metadata=stack_ops['metadata']
                    )
                    patterns.append(pattern)
            
            return patterns
            
        except Exception as e:
            self.logger.error(f"VM stack operations detection failed: {e}")
            return []
    
    def _detect_dynamic_code_generation(self) -> List[Dict[str, Any]]:
        """Detect dynamic code generation patterns"""
        patterns = []
        
        if not self.r2:
            return patterns
        
        try:
            functions = self.r2.cmdj("aflj") or []
            
            for func in functions:
                func_addr = func.get('offset', 0)
                disasm = self.r2.cmd(f"pdf @ {func_addr}")
                
                # Look for VirtualAlloc with EXECUTE permissions
                if 'VirtualAlloc' in disasm and 'PAGE_EXECUTE' in disasm:
                    indicators = ['virtualalloc_execute']
                    confidence = 0.4
                    
                    # Look for code copying/generation
                    if self._has_code_copying(disasm):
                        indicators.append('code_copying')
                        confidence += 0.3
                    
                    # Look for dynamic patching
                    if self._has_dynamic_patching(disasm):
                        indicators.append('dynamic_patching')
                        confidence += 0.2
                    
                    # Look for instruction encoding
                    if self._has_instruction_encoding(disasm):
                        indicators.append('instruction_encoding')
                        confidence += 0.3
                    
                    if confidence > self.jit_confidence_threshold:
                        pattern = {
                            'address': func_addr,
                            'confidence': min(confidence, 1.0),
                            'indicators': indicators,
                            'metadata': {'jit_type': 'dynamic_code_generation'}
                        }
                        patterns.append(pattern)
            
            return patterns
            
        except Exception as e:
            self.logger.error(f"Dynamic code generation detection failed: {e}")
            return []
    
    def _find_vm_entry_point(self) -> Optional[int]:
        """Find the VM entry point"""
        if not self.r2:
            return None
        
        try:
            # Look for functions with VM characteristics
            functions = self.r2.cmdj("aflj") or []
            
            for func in functions:
                func_addr = func.get('offset', 0)
                disasm = self.r2.cmd(f"pdf @ {func_addr}")
                
                # Check if this looks like a VM entry point
                if self._is_vm_entry_point(disasm):
                    return func_addr
            
            return None
            
        except Exception as e:
            self.logger.error(f"VM entry point detection failed: {e}")
            return None
    
    def _find_handler_table(self) -> Optional[int]:
        """Find the VM handler table"""
        if not self.r2:
            return None
        
        try:
            # Look for data sections with pointer arrays
            sections = self.r2.cmdj("iSj") or []
            
            for section in sections:
                if section.get('flags', '').lower() in ['data', 'rdata']:
                    addr = section.get('vaddr', 0)
                    size = section.get('vsize', 0)
                    
                    if self._is_handler_table(addr, size):
                        return addr
            
            return None
            
        except Exception as e:
            self.logger.error(f"Handler table detection failed: {e}")
            return None
    
    def _find_dispatch_function(self) -> Optional[int]:
        """Find the VM dispatch function"""
        if not self.r2:
            return None
        
        try:
            # Look for functions with dispatch characteristics
            dispatch_patterns = self._find_vm_dispatch_patterns()
            
            if dispatch_patterns:
                return dispatch_patterns[0].address
            
            return None
            
        except Exception as e:
            self.logger.error(f"Dispatch function detection failed: {e}")
            return None
    
    def _analyze_vm_registers(self) -> List[str]:
        """Analyze VM register usage patterns"""
        registers = []
        
        if not self.r2:
            return registers
        
        try:
            # Analyze register usage in potential VM functions
            vm_patterns = self._find_vm_dispatch_patterns()
            
            for pattern in vm_patterns:
                disasm = self.r2.cmd(f"pdf @ {pattern.address}")
                func_registers = self._extract_vm_registers(disasm)
                registers.extend(func_registers)
            
            # Remove duplicates and return unique registers
            return list(set(registers))
            
        except Exception as e:
            self.logger.error(f"VM register analysis failed: {e}")
            return []
    
    def _determine_instruction_format(self, bytecode_sections: List[Tuple[int, int]]) -> str:
        """Determine the VM instruction format"""
        if not bytecode_sections or not self.r2:
            return 'unknown'
        
        try:
            # Analyze the first bytecode section
            addr, size = bytecode_sections[0]
            sample_size = min(size, 256)
            
            data = self.r2.cmd(f"p8 {sample_size} @ {addr}")
            if not data:
                return 'unknown'
            
            bytes_data = bytes.fromhex(data)
            
            # Analyze instruction patterns
            format_analysis = self._analyze_instruction_format(bytes_data)
            return format_analysis
            
        except Exception as e:
            self.logger.error(f"Instruction format analysis failed: {e}")
            return 'unknown'
    
    def _calculate_vm_complexity(self, bytecode_sections: List[Tuple[int, int]], 
                               handler_table: Optional[int], 
                               vm_registers: List[str]) -> float:
        """Calculate VM complexity score"""
        complexity = 0.0
        
        # Bytecode complexity
        if bytecode_sections:
            total_bytecode = sum(size for _, size in bytecode_sections)
            complexity += min(total_bytecode / 10000.0, 0.3)  # Max 0.3 from bytecode size
        
        # Handler table complexity
        if handler_table:
            complexity += 0.2
        
        # Register complexity
        complexity += min(len(vm_registers) / 20.0, 0.2)  # Max 0.2 from registers
        
        # Number of sections
        complexity += min(len(bytecode_sections) / 10.0, 0.3)  # Max 0.3 from sections
        
        return min(complexity, 1.0)
    
    # Helper methods for pattern detection
    
    def _has_switch_table(self, disasm: str) -> bool:
        """Check if disassembly contains switch table patterns"""
        switch_patterns = [
            r'jmp\s+\w+\[\w+\*[248]\]',  # Indirect jump with scale
            r'mov\s+\w+,\s*dword\s+ptr\s+\[\w+\+\w+\*[248]\]',  # Array access
            r'cmp\s+\w+,\s*\d+.*ja\s+',  # Bounds check before jump
        ]
        
        for pattern in switch_patterns:
            if re.search(pattern, disasm, re.IGNORECASE):
                return True
        
        return False
    
    def _has_computed_jumps(self, disasm: str) -> bool:
        """Check if disassembly contains computed jump patterns"""
        computed_patterns = [
            r'jmp\s+\w+',  # Indirect jump to register
            r'call\s+\w+',  # Indirect call to register
            r'add\s+\w+,\s*\w+.*jmp\s+\w+',  # Address calculation + jump
        ]
        
        for pattern in computed_patterns:
            if re.search(pattern, disasm, re.IGNORECASE):
                return True
        
        return False
    
    def _has_opcode_fetching(self, disasm: str) -> bool:
        """Check if disassembly contains opcode fetching patterns"""
        fetch_patterns = [
            r'mov\s+\w+,\s*(?:byte|word|dword)\s+ptr\s+\[\w+\]',  # Memory read
            r'inc\s+\w+',  # PC increment
            r'add\s+\w+,\s*[1248]',  # PC advancement
            r'lodsb|lodsw|lodsd',  # String load instructions
        ]
        
        fetch_count = 0
        for pattern in fetch_patterns:
            if re.search(pattern, disasm, re.IGNORECASE):
                fetch_count += 1
        
        return fetch_count >= 2  # Multiple patterns suggest opcode fetching
    
    def _has_vm_context_manipulation(self, disasm: str) -> bool:
        """Check if disassembly contains VM context manipulation"""
        context_patterns = [
            r'pushad|pusha',  # Save all registers
            r'popad|popa',    # Restore all registers
            r'pushf|popf',    # Save/restore flags
            r'mov\s+\[\w+\],\s*esp',  # Save stack pointer
            r'mov\s+esp,\s*\[\w+\]',  # Restore stack pointer
        ]
        
        for pattern in context_patterns:
            if re.search(pattern, disasm, re.IGNORECASE):
                return True
        
        return False
    
    def _is_interpreter_loop(self, disasm: str) -> bool:
        """Check if function is an interpreter loop"""
        # Look for characteristics of interpreter loops
        has_loop = 'jmp' in disasm.lower() and len(disasm.split('\n')) > 20
        has_switch = self._has_switch_table(disasm)
        has_fetch = self._has_opcode_fetching(disasm)
        
        return has_loop and (has_switch or has_fetch)
    
    def _analyze_interpreter_loop(self, disasm: str) -> List[str]:
        """Analyze interpreter loop characteristics"""
        indicators = ['interpreter_loop']
        
        if self._has_switch_table(disasm):
            indicators.append('switch_dispatch')
        
        if self._has_opcode_fetching(disasm):
            indicators.append('opcode_fetching')
        
        if self._has_vm_context_manipulation(disasm):
            indicators.append('context_manipulation')
        
        if 'call' in disasm.lower():
            indicators.append('handler_calls')
        
        return indicators
    
    def _group_similar_functions(self, functions: List[Dict]) -> List[List[Dict]]:
        """Group similar functions together"""
        groups = []
        processed = set()
        
        for func in functions:
            if func['offset'] in processed:
                continue
            
            group = [func]
            processed.add(func['offset'])
            
            # Find similar functions
            for other_func in functions:
                if (other_func['offset'] not in processed and 
                    self._are_functions_similar(func, other_func)):
                    group.append(other_func)
                    processed.add(other_func['offset'])
            
            if len(group) > 1:
                groups.append(group)
        
        return groups
    
    def _are_functions_similar(self, func1: Dict, func2: Dict) -> bool:
        """Check if two functions are similar (likely handlers)"""
        size1 = func1.get('size', 0)
        size2 = func2.get('size', 0)
        
        # Similar size range
        if abs(size1 - size2) > 50:
            return False
        
        # Both should be small (handler-like)
        if size1 > 200 or size2 > 200:
            return False
        
        return True
    
    def _is_potential_bytecode_section(self, section: Dict) -> bool:
        """Check if section might contain bytecode"""
        name = section.get('name', '').lower()
        flags = section.get('flags', '').lower()
        size = section.get('vsize', 0)
        
        # Skip obviously non-bytecode sections
        if any(skip in name for skip in ['.text', '.rsrc', '.reloc', '.import']):
            return False
        
        # Look for data sections with reasonable size
        if 'data' in flags and 100 < size < 100000:
            return True
        
        # Look for custom sections
        if name.startswith('.') and not name.startswith('.debug'):
            return True
        
        return False
    
    def _find_structured_data_sections(self) -> List[Tuple[int, int]]:
        """Find data sections with structured patterns"""
        sections = []
        
        if not self.r2:
            return sections
        
        try:
            # Get all data sections
            section_info = self.r2.cmdj("iSj") or []
            
            for section in section_info:
                if ('data' in section.get('flags', '').lower() and 
                    section.get('vsize', 0) > 100):
                    
                    addr = section.get('vaddr', 0)
                    size = section.get('vsize', 0)
                    
                    # Check if section has structured patterns
                    if self._has_structured_patterns(addr, min(size, 1024)):
                        sections.append((addr, size))
            
            return sections
            
        except Exception as e:
            self.logger.error(f"Structured data section detection failed: {e}")
            return []
    
    def _has_structured_patterns(self, addr: int, size: int) -> bool:
        """Check if memory region has structured patterns"""
        if not self.r2:
            return False
        
        try:
            data = self.r2.cmd(f"p8 {size} @ {addr}")
            if not data:
                return False
            
            bytes_data = bytes.fromhex(data)
            
            # Look for repeating patterns
            if self._has_repeating_patterns(bytes_data):
                return True
            
            # Look for structured opcodes
            if self._has_opcode_like_patterns(bytes_data):
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Structured pattern analysis failed: {e}")
            return False
    
    def _detect_bytecode_patterns(self, data: bytes) -> Dict[str, Any]:
        """Detect patterns in potential bytecode"""
        analysis = {
            'confidence': 0.0,
            'indicators': [],
            'format': 'unknown',
            'instruction_count': 0
        }
        
        if not data:
            return analysis
        
        # Look for instruction-like patterns
        if self._has_opcode_like_patterns(data):
            analysis['indicators'].append('opcode_patterns')
            analysis['confidence'] += 0.3
        
        # Look for operand patterns
        if self._has_operand_patterns(data):
            analysis['indicators'].append('operand_patterns')
            analysis['confidence'] += 0.2
        
        # Look for jump/branch patterns
        if self._has_branch_patterns(data):
            analysis['indicators'].append('branch_patterns')
            analysis['confidence'] += 0.3
        
        # Estimate instruction count
        analysis['instruction_count'] = self._estimate_instruction_count(data)
        
        # Determine format
        analysis['format'] = self._guess_bytecode_format(data)
        
        return analysis
    
    def _search_binary_pattern(self, pattern: bytes) -> List[int]:
        """Search for binary pattern in the binary"""
        matches = []
        
        if not self.r2:
            return matches
        
        try:
            # Convert pattern to hex string for radare2
            hex_pattern = pattern.hex()
            
            # Search for pattern
            result = self.r2.cmd(f"/x {hex_pattern}")
            
            # Parse results
            for line in result.split('\n'):
                if line.startswith('0x'):
                    addr = int(line.split()[0], 16)
                    matches.append(addr)
            
            return matches
            
        except Exception as e:
            self.logger.error(f"Binary pattern search failed: {e}")
            return []
    
    def _search_themida_patterns(self) -> List[int]:
        """Search for Themida-specific patterns"""
        if not self.r2:
            return []
        
        # Themida VM signatures
        themida_patterns = [
            b'\x8B\x85\x00\x00\x00\x00\x89\x85',
            b'\x50\x53\x51\x52\x56\x57\x55',
        ]
        
        matches = []
        for pattern in themida_patterns:
            pattern_matches = self._search_binary_pattern(pattern)
            matches.extend(pattern_matches)
        
        return matches
    
    def _search_code_virtualizer_patterns(self) -> List[int]:
        """Search for Code Virtualizer-specific patterns"""
        if not self.r2:
            return []
        
        # Code Virtualizer signatures
        cv_patterns = [
            b'\x60\x61\x9C\x9D\x50\x58',
            b'\xFF\x35\x00\x00\x00\x00\x8F\x05',
        ]
        
        matches = []
        for pattern in cv_patterns:
            pattern_matches = self._search_binary_pattern(pattern)
            matches.extend(pattern_matches)
        
        return matches
    
    def _has_context_switching(self, disasm: str) -> bool:
        """Check if function performs context switching"""
        context_indicators = [
            'pushad', 'popad', 'pushf', 'popf',
            'mov.*esp', 'mov.*ebp', 'fxsave', 'fxrstor'
        ]
        
        indicator_count = 0
        for indicator in context_indicators:
            if re.search(indicator, disasm, re.IGNORECASE):
                indicator_count += 1
        
        return indicator_count >= 3  # Multiple context operations
    
    def _analyze_vm_stack_operations(self, disasm: str) -> Dict[str, Any]:
        """Analyze VM stack operations in disassembly"""
        analysis = {
            'confidence': 0.0,
            'indicators': [],
            'metadata': {}
        }
        
        # Count stack operations
        push_count = len(re.findall(r'push', disasm, re.IGNORECASE))
        pop_count = len(re.findall(r'pop', disasm, re.IGNORECASE))
        
        # VM stack operations often have many push/pop
        if push_count > 10 or pop_count > 10:
            analysis['indicators'].append('heavy_stack_usage')
            analysis['confidence'] += 0.3
        
        # Check for stack pointer manipulation
        if re.search(r'add\s+esp', disasm, re.IGNORECASE):
            analysis['indicators'].append('stack_pointer_manipulation')
            analysis['confidence'] += 0.2
        
        # Check for custom stack operations
        if re.search(r'mov.*\[esp', disasm, re.IGNORECASE):
            analysis['indicators'].append('custom_stack_access')
            analysis['confidence'] += 0.2
        
        analysis['metadata'] = {
            'push_count': push_count,
            'pop_count': pop_count,
            'stack_balance': push_count - pop_count
        }
        
        return analysis
    
    def _has_code_copying(self, disasm: str) -> bool:
        """Check if function copies code"""
        copy_patterns = [
            r'rep\s+movs',  # String copy
            r'memcpy',      # C library copy
            r'memmove',     # C library move
            r'rep\s+stos',  # String store
        ]
        
        for pattern in copy_patterns:
            if re.search(pattern, disasm, re.IGNORECASE):
                return True
        
        return False
    
    def _has_dynamic_patching(self, disasm: str) -> bool:
        """Check if function performs dynamic patching"""
        patch_patterns = [
            r'mov\s+(?:byte|word|dword)\s+ptr\s+\[',  # Memory write
            r'VirtualProtect',  # Change protection
            r'FlushInstructionCache',  # Flush cache after patch
        ]
        
        for pattern in patch_patterns:
            if re.search(pattern, disasm, re.IGNORECASE):
                return True
        
        return False
    
    def _has_instruction_encoding(self, disasm: str) -> bool:
        """Check if function encodes instructions"""
        encoding_patterns = [
            r'shl\s+.*,\s*8',   # Shift for encoding
            r'or\s+.*,\s*\w+',  # OR for combining
            r'and\s+.*,\s*0x[0-9a-f]+',  # AND for masking
        ]
        
        pattern_count = 0
        for pattern in encoding_patterns:
            if re.search(pattern, disasm, re.IGNORECASE):
                pattern_count += 1
        
        return pattern_count >= 2  # Multiple encoding operations
    
    def _is_vm_entry_point(self, disasm: str) -> bool:
        """Check if function looks like a VM entry point"""
        entry_indicators = [
            self._has_vm_context_manipulation(disasm),
            self._has_opcode_fetching(disasm),
            'call' in disasm.lower(),  # Calls to handlers
            len(disasm.split('\n')) > 50  # Substantial function
        ]
        
        return sum(entry_indicators) >= 3
    
    def _is_handler_table(self, addr: int, size: int) -> bool:
        """Check if memory region is a handler table"""
        if not self.r2 or size < 16:  # Too small for handler table
            return False
        
        try:
            # Read some data from the region
            sample_size = min(size, 128)
            data = self.r2.cmd(f"p8 {sample_size} @ {addr}")
            
            if not data:
                return False
            
            bytes_data = bytes.fromhex(data)
            
            # Check if it looks like an array of pointers
            if len(bytes_data) % 4 == 0:  # 32-bit pointers
                pointers = struct.unpack('<' + 'I' * (len(bytes_data) // 4), bytes_data)
                
                # Check if values look like valid addresses
                valid_count = 0
                for ptr in pointers:
                    if 0x400000 <= ptr <= 0x7FFFFFFF:  # Typical executable range
                        valid_count += 1
                
                return valid_count / len(pointers) > 0.8  # Most should be valid
            
            return False
            
        except Exception as e:
            self.logger.error(f"Handler table validation failed: {e}")
            return False
    
    def _extract_vm_registers(self, disasm: str) -> List[str]:
        """Extract VM register patterns from disassembly"""
        registers = []
        
        # Look for register-like memory accesses
        reg_patterns = [
            r'\[ebp\+([0-9a-fx-]+)\]',  # Stack frame offsets
            r'\[esi\+([0-9a-fx-]+)\]',  # Array/structure access
            r'\[edi\+([0-9a-fx-]+)\]',  # Array/structure access
        ]
        
        for pattern in reg_patterns:
            matches = re.findall(pattern, disasm, re.IGNORECASE)
            for match in matches:
                registers.append(f'vm_reg_{match}')
        
        return list(set(registers))  # Remove duplicates
    
    def _analyze_instruction_format(self, data: bytes) -> str:
        """Analyze instruction format from bytecode"""
        if not data:
            return 'unknown'
        
        # Simple heuristics for instruction format
        if len(data) % 2 == 0 and self._has_word_aligned_patterns(data):
            return '16bit_opcodes'
        
        if len(data) % 4 == 0 and self._has_dword_aligned_patterns(data):
            return '32bit_opcodes'
        
        if self._has_variable_length_patterns(data):
            return 'variable_length'
        
        return 'byte_opcodes'
    
    def _has_word_aligned_patterns(self, data: bytes) -> bool:
        """Check for 16-bit aligned patterns"""
        # Simple check for word-aligned opcodes
        return len([b for b in data[1::2] if b == 0]) > len(data) // 8
    
    def _has_dword_aligned_patterns(self, data: bytes) -> bool:
        """Check for 32-bit aligned patterns"""
        # Simple check for dword-aligned opcodes
        return len([b for b in data[3::4] if b == 0]) > len(data) // 16
    
    def _has_variable_length_patterns(self, data: bytes) -> bool:
        """Check for variable length instruction patterns"""
        # Look for patterns suggesting variable length instructions
        unique_bytes = len(set(data))
        return unique_bytes < len(data) // 4  # High repetition suggests opcodes
    
    def _has_repeating_patterns(self, data: bytes) -> bool:
        """Check for repeating patterns in data"""
        if len(data) < 8:
            return False
        
        # Look for repeating 2-byte and 4-byte patterns
        for pattern_len in [2, 4]:
            if len(data) >= pattern_len * 3:  # At least 3 repetitions
                pattern = data[:pattern_len]
                repetitions = 0
                for i in range(0, len(data) - pattern_len + 1, pattern_len):
                    if data[i:i+pattern_len] == pattern:
                        repetitions += 1
                
                if repetitions >= 3:
                    return True
        
        return False
    
    def _has_opcode_like_patterns(self, data: bytes) -> bool:
        """Check if data has opcode-like patterns"""
        if len(data) < 10:
            return False
        
        # Look for patterns typical of instruction streams
        # High byte (often opcode) followed by lower bytes (often operands)
        high_bytes = [b for b in data[::2]]  # Every other byte
        unique_high = len(set(high_bytes))
        
        # Opcodes typically have limited unique values
        return 5 <= unique_high <= 50 and unique_high < len(high_bytes) // 2
    
    def _has_operand_patterns(self, data: bytes) -> bool:
        """Check for operand patterns in bytecode"""
        if len(data) < 8:
            return False
        
        # Look for immediate values and addresses
        for i in range(0, len(data) - 3, 4):
            dword = struct.unpack('<I', data[i:i+4])[0]
            
            # Check if looks like an address or large immediate
            if 0x400000 <= dword <= 0x7FFFFFFF:
                return True
        
        return False
    
    def _has_branch_patterns(self, data: bytes) -> bool:
        """Check for branch/jump patterns in bytecode"""
        if len(data) < 4:
            return False
        
        # Look for relative offsets (common in branches)
        for i in range(len(data) - 1):
            # Small positive/negative values often indicate relative jumps
            if data[i] in range(0xE0, 0xFF) or data[i] in range(0x01, 0x20):
                return True
        
        return False
    
    def _estimate_instruction_count(self, data: bytes) -> int:
        """Estimate number of instructions in bytecode"""
        if not data:
            return 0
        
        # Simple heuristic: assume average instruction length
        avg_instruction_length = 3  # Estimate
        return len(data) // avg_instruction_length
    
    def _guess_bytecode_format(self, data: bytes) -> str:
        """Guess the bytecode format"""
        if self._has_word_aligned_patterns(data):
            return 'fixed_16bit'
        elif self._has_dword_aligned_patterns(data):
            return 'fixed_32bit'
        elif self._has_variable_length_patterns(data):
            return 'variable_length'
        else:
            return 'byte_stream'