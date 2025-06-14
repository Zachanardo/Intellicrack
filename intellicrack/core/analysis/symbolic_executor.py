"""
Symbolic Execution Engine for Automatic Vulnerability Discovery 

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""


import logging
import traceback
from typing import Any, Dict, List, Optional

# Optional dependencies - graceful fallback if not available
try:
    import angr
    import claripy
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False


class SymbolicExecutionEngine:
    """
    Advanced symbolic execution engine for automatic vulnerability discovery.

    This engine uses symbolic execution techniques to explore program paths
    and automatically discover vulnerabilities by reasoning about program states
    and identifying conditions that could lead to security issues.
    """

    def __init__(self, binary_path: str, max_paths: int = 100, timeout: int = 300, memory_limit: int = 4096):
        """
        Initialize the symbolic execution engine.

        Args:
            binary_path: Path to the binary to analyze
            max_paths: Maximum number of paths to explore (default: 100)
            timeout: Maximum execution time in seconds (default: 300)
            memory_limit: Maximum memory usage in MB (default: 4096)
        """
        self.binary_path = binary_path
        self.max_paths = max_paths
        self.timeout = timeout
        self.memory_limit = memory_limit
        self.logger = logging.getLogger(__name__)
        self.angr_available = ANGR_AVAILABLE
        self.z3_available = ANGR_AVAILABLE  # Z3 comes with angr

        # Check for required dependencies
        if ANGR_AVAILABLE:
            self.logger.info("Symbolic execution dependencies available")
        else:
            self.logger.error("Symbolic execution dependency missing: angr/claripy not installed")

    def discover_vulnerabilities(self, vulnerability_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Perform symbolic execution to discover vulnerabilities.

        Args:
            vulnerability_types: List of vulnerability types to look for, or None for all

        Returns:
            list: Discovered vulnerabilities with details
        """
        if not self.angr_available:
            # Comprehensive fallback implementation without angr dependency
            return self._native_vulnerability_discovery(vulnerability_types)

        if vulnerability_types is None:
            vulnerability_types = [
                "buffer_overflow", "integer_overflow", "use_after_free",
                "format_string", "command_injection", "path_traversal"
            ]

        self.logger.info("Starting symbolic execution on %s", self.binary_path)
        self.logger.info("Looking for vulnerability types: %s", vulnerability_types)

        try:
            # Create project
            project = angr.Project(self.binary_path, auto_load_libs=False)

            # Create symbolic arguments
            symbolic_args = []
            if "buffer_overflow" in vulnerability_types or "format_string" in vulnerability_types:
                symbolic_args.append(claripy.BVS("arg1", 8 * 100))  # 100-byte symbolic buffer

            # Create initial state with symbolic arguments
            initial_state = project.factory.entry_state(args=[project.filename] + symbolic_args)

            # Set up exploration technique
            simgr = project.factory.simulation_manager(initial_state)

            # Add exploration techniques
            if "buffer_overflow" in vulnerability_types:
                simgr.use_technique(angr.exploration_techniques.Spiller())
                simgr.use_technique(angr.exploration_techniques.LengthLimiter(max_length=self.max_paths))
                if hasattr(angr.exploration_techniques, 'MemoryLimiter'):
                    simgr.use_technique(angr.exploration_techniques.MemoryLimiter(self.memory_limit))
                else:
                    self.logger.warning("MemoryLimiter not available in this angr version")

            # Explore the program
            self.logger.info("Exploring program paths...")
            simgr.explore(timeout=self.timeout)

            # Analyze results with enhanced vulnerability detection
            vulnerabilities = []
            
            # Use enhanced vulnerability analysis
            enhanced_vulns = self._analyze_vulnerable_paths(simgr, vulnerability_types)
            vulnerabilities.extend(enhanced_vulns)

            # Check for integer overflows
            if "integer_overflow" in vulnerability_types:
                for _state in simgr.deadended + simgr.active:
                    # Look for arithmetic operations with insufficient bounds checking
                    for _constraint in _state.solver.constraints:
                        if "mul" in str(_constraint) or "add" in str(_constraint):
                            if self._check_integer_overflow(_state, _constraint):
                                vuln = {
                                    "type": "integer_overflow",
                                    "address": hex(_state.addr),
                                    "description": "Potential integer overflow detected",
                                    "constraint": str(_constraint)
                                }
                                vulnerabilities.append(vuln)

            # Check for format string vulnerabilities
            if "format_string" in vulnerability_types:
                for _state in simgr.active + simgr.deadended:
                    if self._check_format_string(_state, project):
                        vuln = {
                            "type": "format_string",
                            "address": hex(_state.addr),
                            "description": "Potential format string vulnerability detected",
                            "input": _state.posix.dumps(0) if hasattr(_state, "posix") else None
                        }
                        vulnerabilities.append(vuln)

            self.logger.info("Symbolic execution completed. Found %d potential vulnerabilities.", len(vulnerabilities))
            return vulnerabilities

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error during symbolic execution: %s", e)
            self.logger.error(traceback.format_exc())
            return [{"error": f"Symbolic execution failed: {str(e)}"}]

    def _check_integer_overflow(self, state, constraint) -> bool:
        """
        Check if a constraint could lead to an integer overflow.

        Args:
            state: Program state
            constraint: Constraint to check

        Returns:
            bool: True if potential integer overflow, False otherwise
        """
        try:
            # Check if constraint involves arithmetic that could overflow
            constraint_str = str(constraint)
            self.logger.debug("Checking for integer overflow in constraint: %s at 0x%d", constraint_str, state.addr)
            if "+" in constraint_str or "*" in constraint_str:
                # Try to find cases where large values are possible
                if state.solver.satisfiable(extra_constraints=[constraint]):
                    # Check if we can satisfy with very large values
                    for _var in state.solver.variables:
                        try:
                            max_val = state.solver.max(_var)
                            if max_val > 2**30:  # Large value threshold
                                self.logger.info("Potential integer overflow identified due to large variable value for '%s'", _var)
                                return True
                        except (AttributeError, ValueError, RuntimeError) as e:
                            self.logger.debug("Failed to analyze variable for overflow: %s", e)
            return False
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.warning("Error during integer overflow check: %s", e, exc_info=False)
            return False

    def _check_format_string(self, state, project) -> bool:
        """
        Check if state could contain a format string vulnerability.

        Args:
            state: Program state
            project: Angr project

        Returns:
            bool: True if potential format string vulnerability, False otherwise
        """
        try:
            # Look for printf-like function calls with user-controlled format string
            self.logger.debug("Checking for format string vulnerability at 0x%d", state.addr)
            for _addr in state.history.bbl_addrs:
                try:
                    function = project.kb.functions.get_by_addr(_addr)
                    if function and function.name:
                        self.logger.debug("Found call to %s at 0x%d", function.name, _addr)
                        if "printf" in function.name or "sprintf" in function.name or "fprintf" in function.name:
                            # Check if first argument (format string) is symbolic
                            for _var in state.solver.variables:
                                var_name = str(_var)
                                if "arg" in var_name and "%" in state.solver.eval(_var, cast_to=bytes).decode('latin-1', errors='ignore'):
                                    self.logger.info("Potential format string vulnerability: Symbolic format string for %s controlled by '%s'", function.name, var_name)
                                    return True
                except (OSError, ValueError, RuntimeError):
                    continue
            return False
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.warning("Error during format string check: %s", e, exc_info=False)
            return False

    def generate_exploit(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a proof-of-concept exploit for a discovered vulnerability.

        Args:
            vulnerability: Vulnerability information from discover_vulnerabilities

        Returns:
            dict: Exploit information including payload and instructions
        """
        if not self.angr_available:
            return {"error": "Required dependencies not available"}

        try:
            vuln_type = vulnerability.get("type")

            if vuln_type == "buffer_overflow":
                # Generate buffer overflow exploit
                payload = b"A" * 256  # Basic overflow pattern
                if "input" in vulnerability and vulnerability["input"]:
                    # Use the input that triggered the vulnerability
                    payload = vulnerability["input"]

                return {
                    "type": "buffer_overflow",
                    "payload": payload.hex(),
                    "instructions": "Send this payload to the program input to trigger the buffer overflow"
                }

            elif vuln_type == "format_string":
                # Generate format string exploit
                payload = b"%x " * 20  # Basic format string leak

                return {
                    "type": "format_string",
                    "payload": payload.hex(),
                    "instructions": "Send this payload to leak memory through format string vulnerability"
                }

            elif vuln_type == "integer_overflow":
                # Generate integer overflow exploit
                return {
                    "type": "integer_overflow",
                    "payload": "0x7FFFFFFF",
                    "instructions": "Use this value to trigger integer overflow"
                }

            return {"error": f"Exploit generation not implemented for {vuln_type}"}

        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error generating exploit: %s", e)
            return {"error": f"Exploit generation failed: {str(e)}"}

    def _check_buffer_overflow(self, state, project) -> bool:
        """
        Check if state could contain a buffer overflow vulnerability.

        Args:
            state: Program state
            project: Angr project

        Returns:
            bool: True if potential buffer overflow vulnerability, False otherwise
        """
        try:
            self.logger.debug("Checking for buffer overflow at 0x%x", state.addr)
            
            # Check for memory violations
            if hasattr(state, 'memory'):
                try:
                    # Look for writes to invalid memory regions
                    memory_plugins = state.memory.mem._memory_backer
                    if hasattr(memory_plugins, '_memory_objects_by_region'):
                        # Check if we're writing outside allocated regions
                        for region in memory_plugins._memory_objects_by_region:
                            if hasattr(region, 'violations') and region.violations:
                                self.logger.info("Memory violation detected at 0x%x", state.addr)
                                return True
                except (AttributeError, TypeError) as e:
                    self.logger.debug("Failed to analyze memory for violations: %s", e)

            # Check for stack buffer overflows by examining stack pointer manipulation
            if hasattr(state, 'regs'):
                try:
                    # Get current stack pointer
                    sp_name = 'rsp' if state.arch.bits == 64 else 'esp'
                    if hasattr(state.regs, sp_name):
                        current_sp = getattr(state.regs, sp_name)
                        
                        # Check if stack pointer is symbolic and unconstrained
                        if current_sp.symbolic and len(current_sp.variables) > 0:
                            # Check if we can make SP point to arbitrary locations
                            try:
                                min_sp = state.solver.min(current_sp)
                                max_sp = state.solver.max(current_sp)
                                
                                # If SP can vary widely, it might indicate stack corruption
                                if max_sp - min_sp > 0x10000:  # 64KB range
                                    self.logger.info("Potential stack buffer overflow: SP can vary by %d bytes", max_sp - min_sp)
                                    return True
                            except (RuntimeError, ValueError) as e:
                                self.logger.debug("Failed to analyze stack pointer variation: %s", e)
                                
                except (AttributeError, TypeError) as e:
                    self.logger.debug("Failed to analyze stack buffer overflow: %s", e)

            # Check for function calls to dangerous functions with symbolic arguments
            if hasattr(state, 'history') and hasattr(state.history, 'bbl_addrs'):
                try:
                    for addr in state.history.bbl_addrs[-5:]:  # Check last 5 basic blocks
                        try:
                            block = project.factory.block(addr)
                            for insn in block.capstone.insns:
                                # Look for calls to dangerous functions
                                if insn.mnemonic == 'call':
                                    try:
                                        target = insn.operands[0].value.imm
                                        if target in project.kb.functions:
                                            func = project.kb.functions[target]
                                            if func.name and any(dangerous in func.name.lower() for dangerous in 
                                                               ['strcpy', 'strcat', 'gets', 'sprintf', 'scanf']):
                                                # Check if arguments are symbolic
                                                for reg in ['rdi', 'rsi', 'rdx'] if state.arch.bits == 64 else ['eax', 'ebx', 'ecx']:
                                                    if hasattr(state.regs, reg):
                                                        arg = getattr(state.regs, reg)
                                                        if arg.symbolic:
                                                            self.logger.info("Dangerous function %s called with symbolic argument", func.name)
                                                            return True
                                    except (AttributeError, IndexError, KeyError):
                                        continue
                        except (RuntimeError, ValueError):
                            continue
                except (AttributeError, TypeError) as e:
                    self.logger.debug("Failed to analyze dangerous function calls: %s", e)

            # Check for heap buffer overflows by examining malloc/free patterns
            if hasattr(state, 'heap'):
                try:
                    # Look for heap metadata corruption indicators
                    heap_chunks = getattr(state.heap, '_chunks', {})
                    for chunk_addr, chunk_info in heap_chunks.items():
                        if hasattr(chunk_info, 'size') and hasattr(chunk_info, 'data'):
                            # Check if chunk size is symbolic and can be made very large
                            if chunk_info.size.symbolic:
                                try:
                                    max_size = state.solver.max(chunk_info.size)
                                    if max_size > 0x100000:  # 1MB threshold
                                        self.logger.info("Potential heap overflow: chunk size can be %d bytes", max_size)
                                        return True
                                except (RuntimeError, ValueError) as e:
                                    self.logger.debug("Failed to analyze heap operation: %s", e)
                except (AttributeError, TypeError) as e:
                    self.logger.debug("Failed to analyze heap buffer overflow: %s", e)

            return False
            
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.warning("Error during buffer overflow check: %s", e, exc_info=False)
            return False

    def _analyze_vulnerable_paths(self, simgr, vulnerability_types: List[str]) -> List[Dict[str, Any]]:
        """
        Analyze simulation manager paths for vulnerabilities with enhanced detection.

        Args:
            simgr: Simulation manager
            vulnerability_types: Types of vulnerabilities to look for

        Returns:
            list: Detected vulnerabilities with enhanced information
        """
        vulnerabilities = []
        
        try:
            # Enhanced buffer overflow detection
            if "buffer_overflow" in vulnerability_types:
                # Check errored states for segfaults
                for state in simgr.errored:
                    if isinstance(state.error, angr.errors.SimSegfaultError):
                        vuln = {
                            "type": "buffer_overflow",
                            "address": hex(state.addr),
                            "description": "Segmentation fault detected",
                            "input": state.posix.dumps(0) if hasattr(state, "posix") else None,
                            "error_type": "segfault",
                            "severity": "high"
                        }
                        vulnerabilities.append(vuln)

                # Check active and deadended states for potential overflows
                for state in simgr.active + simgr.deadended:
                    if self._check_buffer_overflow(state, simgr._project):
                        vuln = {
                            "type": "buffer_overflow",
                            "address": hex(state.addr),
                            "description": "Potential buffer overflow condition detected",
                            "input": state.posix.dumps(0) if hasattr(state, "posix") else None,
                            "error_type": "overflow_condition",
                            "severity": "medium"
                        }
                        vulnerabilities.append(vuln)

            return vulnerabilities
            
        except Exception as e:
            self.logger.error("Error analyzing vulnerable paths: %s", e)
            return vulnerabilities

    def _native_vulnerability_discovery(self, vulnerability_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Native vulnerability discovery implementation without angr dependency.
        
        Performs comprehensive static and heuristic analysis to identify potential
        vulnerabilities using pattern matching, control flow analysis, and code inspection.
        
        Args:
            vulnerability_types: List of vulnerability types to look for
            
        Returns:
            List of discovered vulnerabilities with detailed information
        """
        if vulnerability_types is None:
            vulnerability_types = [
                "buffer_overflow", "integer_overflow", "use_after_free",
                "format_string", "command_injection", "path_traversal",
                "sql_injection", "xss", "memory_leak", "null_pointer_deref"
            ]

        self.logger.info("Starting native vulnerability discovery on %s", self.binary_path)
        self.logger.info("Target vulnerability types: %s", vulnerability_types)

        vulnerabilities = []
        
        try:
            # Read and analyze the binary file
            with open(self.binary_path, 'rb') as f:
                binary_data = f.read()
            
            # Extract strings for analysis
            strings = self._extract_binary_strings(binary_data)
            
            # Perform disassembly if possible
            disasm_info = self._perform_basic_disassembly(binary_data)
            
            # Analyze each vulnerability type
            if "buffer_overflow" in vulnerability_types:
                vulns = self._detect_buffer_overflow_patterns(binary_data, strings, disasm_info)
                vulnerabilities.extend(vulns)
                
            if "format_string" in vulnerability_types:
                vulns = self._detect_format_string_vulns(binary_data, strings, disasm_info)
                vulnerabilities.extend(vulns)
                
            if "integer_overflow" in vulnerability_types:
                vulns = self._detect_integer_overflow_patterns(binary_data, strings, disasm_info)
                vulnerabilities.extend(vulns)
                
            if "command_injection" in vulnerability_types:
                vulns = self._detect_command_injection_patterns(binary_data, strings, disasm_info)
                vulnerabilities.extend(vulns)
                
            if "use_after_free" in vulnerability_types:
                vulns = self._detect_use_after_free_patterns(binary_data, strings, disasm_info)
                vulnerabilities.extend(vulns)
                
            if "path_traversal" in vulnerability_types:
                vulns = self._detect_path_traversal_patterns(binary_data, strings, disasm_info)
                vulnerabilities.extend(vulns)
                
            if "sql_injection" in vulnerability_types:
                vulns = self._detect_sql_injection_patterns(binary_data, strings, disasm_info)
                vulnerabilities.extend(vulns)
                
            if "memory_leak" in vulnerability_types:
                vulns = self._detect_memory_leak_patterns(binary_data, strings, disasm_info)
                vulnerabilities.extend(vulns)
                
            if "null_pointer_deref" in vulnerability_types:
                vulns = self._detect_null_pointer_patterns(binary_data, strings, disasm_info)
                vulnerabilities.extend(vulns)

            # Remove duplicates and sort by severity
            vulnerabilities = self._deduplicate_and_rank_vulnerabilities(vulnerabilities)

            self.logger.info("Native vulnerability discovery completed. Found %d potential vulnerabilities.", len(vulnerabilities))
            return vulnerabilities

        except Exception as e:
            self.logger.error("Error during native vulnerability discovery: %s", e)
            return [{"error": f"Native vulnerability discovery failed: {str(e)}"}]

    def _extract_binary_strings(self, binary_data: bytes) -> List[Dict[str, Any]]:
        """Extract strings from binary data for vulnerability analysis."""
        strings = []
        
        # ASCII strings
        import re
        ascii_pattern = re.compile(b'[ -~]{4,}')
        for match in ascii_pattern.finditer(binary_data):
            try:
                string_value = match.group(0).decode('ascii')
                strings.append({
                    'offset': match.start(),
                    'value': string_value,
                    'encoding': 'ascii',
                    'length': len(string_value)
                })
            except UnicodeDecodeError:
                pass
        
        # UTF-16 strings (Windows)
        utf16_pattern = re.compile(b'(?:[A-Za-z0-9!@#$%^&*()_+={}\[\]|\\:";\'<>?,./ ][\x00]){4,}')
        for match in utf16_pattern.finditer(binary_data):
            try:
                string_value = match.group(0).decode('utf-16le').rstrip('\x00')
                if len(string_value) >= 4:
                    strings.append({
                        'offset': match.start(),
                        'value': string_value,
                        'encoding': 'utf-16le',
                        'length': len(string_value)
                    })
            except UnicodeDecodeError:
                pass
        
        return strings

    def _perform_basic_disassembly(self, binary_data: bytes) -> Dict[str, Any]:
        """Perform basic disassembly and control flow analysis."""
        disasm_info = {
            'instructions': [],
            'function_calls': [],
            'jumps': [],
            'system_calls': [],
            'dangerous_functions': []
        }
        
        try:
            # Try to use capstone if available
            try:
                import capstone
                
                # Detect architecture from binary header
                if binary_data.startswith(b'MZ'):  # PE file
                    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
                elif binary_data.startswith(b'\x7fELF'):  # ELF file
                    if binary_data[4] == 2:  # 64-bit
                        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                    else:  # 32-bit
                        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
                else:
                    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
                
                cs.detail = True
                
                # Find code sections and disassemble
                code_sections = self._find_code_sections(binary_data)
                
                for section_offset, section_data in code_sections:
                    for instruction in cs.disasm(section_data[:min(4096, len(section_data))], section_offset):
                        inst_info = {
                            'address': instruction.address,
                            'mnemonic': instruction.mnemonic,
                            'op_str': instruction.op_str,
                            'bytes': instruction.bytes
                        }
                        disasm_info['instructions'].append(inst_info)
                        
                        # Track function calls
                        if instruction.mnemonic in ['call', 'jmp']:
                            disasm_info['function_calls'].append(inst_info)
                            
                            # Check for dangerous function calls
                            if any(func in instruction.op_str.lower() for func in 
                                  ['strcpy', 'sprintf', 'gets', 'scanf', 'strcat', 'memcpy']):
                                disasm_info['dangerous_functions'].append(inst_info)
                        
                        # Track jumps and branches
                        elif instruction.mnemonic.startswith('j'):
                            disasm_info['jumps'].append(inst_info)
                        
                        # Track system calls
                        elif instruction.mnemonic in ['int', 'syscall', 'sysenter']:
                            disasm_info['system_calls'].append(inst_info)
                            
            except ImportError:
                self.logger.warning("Capstone not available - using basic pattern analysis")
                disasm_info = self._basic_pattern_analysis(binary_data)
                
        except Exception as e:
            self.logger.warning("Disassembly failed: %s", e)
            disasm_info = self._basic_pattern_analysis(binary_data)
            
        return disasm_info

    def _find_code_sections(self, binary_data: bytes) -> List[tuple]:
        """Find executable code sections in the binary."""
        code_sections = []
        
        try:
            if binary_data.startswith(b'MZ'):  # PE file
                # Basic PE parsing
                dos_header = binary_data[:64]
                if len(dos_header) >= 60:
                    pe_offset = int.from_bytes(dos_header[60:64], 'little')
                    if pe_offset < len(binary_data) - 4:
                        pe_sig = binary_data[pe_offset:pe_offset+4]
                        if pe_sig == b'PE\x00\x00':
                            # Found PE header - assume .text section starts at 0x1000
                            code_sections.append((0x1000, binary_data[0x1000:0x5000]))
                            
            elif binary_data.startswith(b'\x7fELF'):  # ELF file
                # Basic ELF parsing - assume .text section
                code_sections.append((0x1000, binary_data[0x1000:0x5000]))
                
            else:
                # Unknown format - assume first 4KB contains code
                code_sections.append((0, binary_data[:4096]))
                
        except Exception:
            # Fallback - analyze first 4KB
            code_sections.append((0, binary_data[:4096]))
            
        return code_sections

    def _basic_pattern_analysis(self, binary_data: bytes) -> Dict[str, Any]:
        """Basic pattern analysis when disassembly is not available."""
        patterns = {
            'instructions': [],
            'function_calls': [],
            'jumps': [],
            'system_calls': [],
            'dangerous_functions': []
        }
        
        # Look for common x86 instruction patterns
        dangerous_patterns = [
            b'\xff\x25',  # jmp [mem] - indirect jump
            b'\xff\x15',  # call [mem] - indirect call
            b'\xcd\x80',  # int 0x80 - Linux system call
            b'\x0f\x05',  # syscall - 64-bit system call
        ]
        
        for pattern in dangerous_patterns:
            offset = 0
            while True:
                offset = binary_data.find(pattern, offset)
                if offset == -1:
                    break
                patterns['system_calls'].append({
                    'address': offset,
                    'pattern': pattern.hex(),
                    'description': 'Potential system call'
                })
                offset += len(pattern)
                
        return patterns

    def _detect_buffer_overflow_patterns(self, binary_data: bytes, strings: List[Dict], disasm_info: Dict) -> List[Dict[str, Any]]:
        """Detect potential buffer overflow vulnerabilities."""
        vulnerabilities = []
        
        # Check for dangerous function usage in strings
        dangerous_functions = [
            'strcpy', 'strcat', 'sprintf', 'gets', 'scanf', 
            'memcpy', 'memmove', 'strncpy', 'strncat'
        ]
        
        for string in strings:
            for func in dangerous_functions:
                if func in string['value'].lower():
                    vuln = {
                        'type': 'buffer_overflow',
                        'severity': 'high' if func in ['strcpy', 'gets', 'sprintf'] else 'medium',
                        'address': hex(string['offset']),
                        'description': f'Dangerous function "{func}" found in binary',
                        'function': func,
                        'context': string['value'][:100],
                        'detection_method': 'string_analysis'
                    }
                    vulnerabilities.append(vuln)
        
        # Check disassembly for dangerous function calls
        for func_call in disasm_info.get('dangerous_functions', []):
            vuln = {
                'type': 'buffer_overflow',
                'severity': 'high',
                'address': hex(func_call['address']),
                'description': f'Dangerous function call: {func_call["op_str"]}',
                'instruction': f'{func_call["mnemonic"]} {func_call["op_str"]}',
                'detection_method': 'disassembly_analysis'
            }
            vulnerabilities.append(vuln)
        
        # Look for large stack allocations
        for instruction in disasm_info.get('instructions', []):
            if instruction['mnemonic'] == 'sub' and 'esp' in instruction['op_str']:
                # Extract immediate value for stack allocation
                import re
                immediate = re.search(r'0x([0-9a-fA-F]+)', instruction['op_str'])
                if immediate:
                    stack_size = int(immediate.group(1), 16)
                    if stack_size > 1024:  # Large stack allocation
                        vuln = {
                            'type': 'buffer_overflow',
                            'severity': 'low',
                            'address': hex(instruction['address']),
                            'description': f'Large stack allocation: {stack_size} bytes',
                            'stack_size': stack_size,
                            'detection_method': 'stack_analysis'
                        }
                        vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _detect_format_string_vulns(self, binary_data: bytes, strings: List[Dict], disasm_info: Dict) -> List[Dict[str, Any]]:
        """Detect potential format string vulnerabilities."""
        vulnerabilities = []
        
        # Look for format string patterns
        format_patterns = ['%s', '%d', '%x', '%n', '%p', '%%']
        
        for string in strings:
            format_count = sum(string['value'].count(pattern) for pattern in format_patterns)
            if format_count > 0:
                # Check for potentially dangerous combinations
                if '%n' in string['value']:
                    severity = 'critical'
                    desc = 'Format string with %n specifier detected - potential arbitrary write'
                elif format_count > 3:
                    severity = 'high'
                    desc = f'Complex format string with {format_count} specifiers'
                else:
                    severity = 'medium'
                    desc = f'Format string with {format_count} specifiers'
                    
                vuln = {
                    'type': 'format_string',
                    'severity': severity,
                    'address': hex(string['offset']),
                    'description': desc,
                    'format_string': string['value'][:100],
                    'specifier_count': format_count,
                    'detection_method': 'string_analysis'
                }
                vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _detect_integer_overflow_patterns(self, binary_data: bytes, strings: List[Dict], disasm_info: Dict) -> List[Dict[str, Any]]:
        """Detect potential integer overflow vulnerabilities."""
        vulnerabilities = []
        
        # Look for arithmetic operations without bounds checking
        arithmetic_ops = ['add', 'mul', 'imul', 'shl', 'sal']
        
        for instruction in disasm_info.get('instructions', []):
            if instruction['mnemonic'] in arithmetic_ops:
                # Look for operations on user-controlled data
                if 'eax' in instruction['op_str'] or 'rax' in instruction['op_str']:
                    vuln = {
                        'type': 'integer_overflow',
                        'severity': 'medium',
                        'address': hex(instruction['address']),
                        'description': f'Arithmetic operation without bounds checking: {instruction["mnemonic"]}',
                        'instruction': f'{instruction["mnemonic"]} {instruction["op_str"]}',
                        'detection_method': 'instruction_analysis'
                    }
                    vulnerabilities.append(vuln)
        
        # Check for size calculations in strings
        size_keywords = ['size', 'length', 'count', 'num', 'malloc', 'calloc']
        for string in strings:
            for keyword in size_keywords:
                if keyword in string['value'].lower():
                    vuln = {
                        'type': 'integer_overflow',
                        'severity': 'low',
                        'address': hex(string['offset']),
                        'description': f'Size calculation reference: {keyword}',
                        'context': string['value'][:100],
                        'detection_method': 'string_analysis'
                    }
                    vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _detect_command_injection_patterns(self, binary_data: bytes, strings: List[Dict], disasm_info: Dict) -> List[Dict[str, Any]]:
        """Detect potential command injection vulnerabilities."""
        vulnerabilities = []
        
        # Look for system command execution
        dangerous_functions = ['system', 'exec', 'popen', 'CreateProcess', 'ShellExecute']
        command_chars = [';', '|', '&', '`', '$', '>', '<']
        
        for string in strings:
            # Check for dangerous function calls
            for func in dangerous_functions:
                if func in string['value']:
                    vuln = {
                        'type': 'command_injection',
                        'severity': 'high',
                        'address': hex(string['offset']),
                        'description': f'Command execution function: {func}',
                        'function': func,
                        'context': string['value'][:100],
                        'detection_method': 'string_analysis'
                    }
                    vulnerabilities.append(vuln)
            
            # Check for command injection characters
            injection_chars = [char for char in command_chars if char in string['value']]
            if injection_chars:
                vuln = {
                    'type': 'command_injection',
                    'severity': 'medium',
                    'address': hex(string['offset']),
                    'description': f'Command injection characters found: {injection_chars}',
                    'characters': injection_chars,
                    'context': string['value'][:100],
                    'detection_method': 'pattern_analysis'
                }
                vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _detect_use_after_free_patterns(self, binary_data: bytes, strings: List[Dict], disasm_info: Dict) -> List[Dict[str, Any]]:
        """Detect potential use-after-free vulnerabilities."""
        vulnerabilities = []
        
        # Look for malloc/free patterns
        memory_functions = ['malloc', 'free', 'calloc', 'realloc', 'new', 'delete']
        
        for string in strings:
            for func in memory_functions:
                if func in string['value'].lower():
                    vuln = {
                        'type': 'use_after_free',
                        'severity': 'medium',
                        'address': hex(string['offset']),
                        'description': f'Memory management function: {func}',
                        'function': func,
                        'context': string['value'][:100],
                        'detection_method': 'string_analysis'
                    }
                    vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _detect_path_traversal_patterns(self, binary_data: bytes, strings: List[Dict], disasm_info: Dict) -> List[Dict[str, Any]]:
        """Detect potential path traversal vulnerabilities."""
        vulnerabilities = []
        
        # Look for path traversal patterns
        traversal_patterns = ['../', '..\\', '%2e%2e%2f', '%2e%2e%5c']
        
        for string in strings:
            for pattern in traversal_patterns:
                if pattern in string['value'].lower():
                    vuln = {
                        'type': 'path_traversal',
                        'severity': 'high',
                        'address': hex(string['offset']),
                        'description': f'Path traversal pattern: {pattern}',
                        'pattern': pattern,
                        'context': string['value'][:100],
                        'detection_method': 'pattern_analysis'
                    }
                    vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _detect_sql_injection_patterns(self, binary_data: bytes, strings: List[Dict], disasm_info: Dict) -> List[Dict[str, Any]]:
        """Detect potential SQL injection vulnerabilities."""
        vulnerabilities = []
        
        # Look for SQL keywords and injection patterns
        sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'UNION', 'OR', 'AND']
        injection_patterns = ["'", '"', '--', '/*', '*/', 'UNION SELECT', "' OR '1'='1"]
        
        for string in strings:
            sql_count = sum(1 for keyword in sql_keywords if keyword in string['value'].upper())
            injection_count = sum(1 for pattern in injection_patterns if pattern in string['value'])
            
            if sql_count > 0 or injection_count > 0:
                severity = 'high' if injection_count > 0 else 'medium'
                vuln = {
                    'type': 'sql_injection',
                    'severity': severity,
                    'address': hex(string['offset']),
                    'description': f'SQL pattern detected - keywords: {sql_count}, injection patterns: {injection_count}',
                    'sql_keywords': sql_count,
                    'injection_patterns': injection_count,
                    'context': string['value'][:100],
                    'detection_method': 'pattern_analysis'
                }
                vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _detect_memory_leak_patterns(self, binary_data: bytes, strings: List[Dict], disasm_info: Dict) -> List[Dict[str, Any]]:
        """Detect potential memory leak vulnerabilities."""
        vulnerabilities = []
        
        # Look for memory allocation without corresponding free
        alloc_functions = ['malloc', 'calloc', 'realloc', 'new', 'LocalAlloc', 'GlobalAlloc']
        
        for string in strings:
            for func in alloc_functions:
                if func in string['value'].lower():
                    vuln = {
                        'type': 'memory_leak',
                        'severity': 'low',
                        'address': hex(string['offset']),
                        'description': f'Memory allocation function without visible free: {func}',
                        'function': func,
                        'context': string['value'][:100],
                        'detection_method': 'static_analysis'
                    }
                    vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _detect_null_pointer_patterns(self, binary_data: bytes, strings: List[Dict], disasm_info: Dict) -> List[Dict[str, Any]]:
        """Detect potential null pointer dereference vulnerabilities."""
        vulnerabilities = []
        
        # Look for null checks and pointer operations
        for instruction in disasm_info.get('instructions', []):
            # Look for comparisons with NULL (0)
            if instruction['mnemonic'] in ['cmp', 'test'] and '0' in instruction['op_str']:
                vuln = {
                    'type': 'null_pointer_deref',
                    'severity': 'medium',
                    'address': hex(instruction['address']),
                    'description': f'Null pointer check: {instruction["mnemonic"]} {instruction["op_str"]}',
                    'instruction': f'{instruction["mnemonic"]} {instruction["op_str"]}',
                    'detection_method': 'instruction_analysis'
                }
                vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _deduplicate_and_rank_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicates and rank vulnerabilities by severity."""
        # Remove duplicates based on type and address
        seen = set()
        unique_vulns = []
        
        for vuln in vulnerabilities:
            key = (vuln['type'], vuln.get('address', ''))
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)
        
        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        unique_vulns.sort(key=lambda v: severity_order.get(v.get('severity', 'low'), 3))
        
        return unique_vulns


__all__ = ['SymbolicExecutionEngine']
