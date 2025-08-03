"""
Original Entry Point (OEP) Detection Engine

Advanced OEP detection using multiple heuristics and analysis techniques
for unpacked binaries and protected executables.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import logging
import struct
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

import lief
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_OP_IMM, CS_OP_MEM

logger = logging.getLogger(__name__)


class OEPHeuristic(Enum):
    """OEP detection heuristic types"""
    COMPILER_SIGNATURE = "compiler_signature"
    API_CALL_PATTERN = "api_call_pattern"
    ENTROPY_ANALYSIS = "entropy_analysis"
    DISASSEMBLY_PATTERN = "disassembly_pattern"
    STACK_ANALYSIS = "stack_analysis"
    CROSS_REFERENCE = "cross_reference"


@dataclass
class OEPCandidate:
    """OEP candidate with confidence scoring"""
    address: int
    confidence: float
    heuristics: List[OEPHeuristic]
    evidence: Dict[str, Any]
    disassembly: Optional[str] = None


@dataclass
class CompilerSignature:
    """Compiler signature for OEP detection"""
    name: str
    patterns: List[bytes]
    masks: List[str]
    confidence_weight: float
    architecture: str


class CompilerSignatureDatabase:
    """Database of compiler signatures for OEP detection"""
    
    def __init__(self):
        self.signatures = self._initialize_signatures()
    
    def _initialize_signatures(self) -> List[CompilerSignature]:
        """Initialize compiler signature database"""
        return [
            # Microsoft Visual C++
            CompilerSignature(
                name="MSVC x86",
                patterns=[
                    b"\x55\x8B\xEC\x83\xEC",  # push ebp; mov ebp, esp; sub esp, X
                    b"\x55\x8B\xEC\x6A\xFF",  # push ebp; mov ebp, esp; push -1
                    b"\x55\x8B\xEC\x51\x51",  # push ebp; mov ebp, esp; push ecx; push ecx
                ],
                masks=[
                    "xxxxx",
                    "xxxxx",
                    "xxxxx",
                ],
                confidence_weight=0.8,
                architecture="x86"
            ),
            CompilerSignature(
                name="MSVC x64",
                patterns=[
                    b"\x48\x89\x5C\x24\x08\x48\x89\x6C\x24\x10",  # mov [rsp+8], rbx; mov [rsp+10h], rbp
                    b"\x48\x83\xEC\x20\x48\x89\x5C\x24\x30",      # sub rsp, 20h; mov [rsp+30h], rbx
                    b"\x40\x53\x48\x83\xEC\x20",                  # push rbx; sub rsp, 20h
                ],
                masks=[
                    "xxxxxxxxxx",
                    "xxxxxxxxx",
                    "xxxxxx",
                ],
                confidence_weight=0.8,
                architecture="x64"
            ),
            
            # GCC/MinGW
            CompilerSignature(
                name="GCC x86",
                patterns=[
                    b"\x55\x89\xE5\x83\xEC",  # push ebp; mov ebp, esp; sub esp, X
                    b"\x55\x89\xE5\x53",      # push ebp; mov ebp, esp; push ebx
                    b"\x55\x89\xE5\x57\x56",  # push ebp; mov ebp, esp; push edi; push esi
                ],
                masks=[
                    "xxxxx",
                    "xxxx",
                    "xxxxx",
                ],
                confidence_weight=0.7,
                architecture="x86"
            ),
            
            # Borland/Embarcadero
            CompilerSignature(
                name="Borland x86",
                patterns=[
                    b"\x55\x8B\xEC\x33\xC0\x55",  # push ebp; mov ebp, esp; xor eax, eax; push ebp
                    b"\x6A\x00\x68\x00\x00\x00\x00\x68",  # push 0; push offset; push
                ],
                masks=[
                    "xxxxxx",
                    "xx????xx",
                ],
                confidence_weight=0.7,
                architecture="x86"
            ),
            
            # Delphi
            CompilerSignature(
                name="Delphi",
                patterns=[
                    b"\x53\x8B\xD8\x33\xC0\x8B\xC3",  # push ebx; mov ebx, eax; xor eax, eax; mov eax, ebx
                    b"\x55\x8B\xEC\x33\xC0\x89\x45",  # push ebp; mov ebp, esp; xor eax, eax; mov [ebp+X], eax
                ],
                masks=[
                    "xxxxxxx",
                    "xxxxxxx",
                ],
                confidence_weight=0.6,
                architecture="x86"
            ),
            
            # .NET Framework
            CompilerSignature(
                name=".NET Native",
                patterns=[
                    b"\x48\x83\xEC\x28\x48\x8B\x05",  # sub rsp, 28h; mov rax, [X]
                    b"\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20",  # mov [rsp+8], rbx; push rdi; sub rsp, 20h
                ],
                masks=[
                    "xxxxxxx",
                    "xxxxxxxxxx",
                ],
                confidence_weight=0.7,
                architecture="x64"
            ),
        ]
    
    def match_signature(self, data: bytes, architecture: str) -> List[Tuple[CompilerSignature, int]]:
        """Match compiler signatures in data"""
        matches = []
        
        for signature in self.signatures:
            if signature.architecture != architecture:
                continue
            
            for i, pattern in enumerate(signature.patterns):
                mask = signature.masks[i] if i < len(signature.masks) else 'x' * len(pattern)
                pattern_matches = self._pattern_search_with_mask(data, pattern, mask)
                
                for match_offset in pattern_matches:
                    matches.append((signature, match_offset))
        
        return matches
    
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


class OEPDetector:
    """Advanced Original Entry Point detector"""
    
    def __init__(self):
        self.signature_db = CompilerSignatureDatabase()
        self._initialize_disassemblers()
    
    def _initialize_disassemblers(self):
        """Initialize Capstone disassemblers"""
        self.cs_x86 = Cs(CS_ARCH_X86, CS_MODE_32)
        self.cs_x64 = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs_x86.detail = True
        self.cs_x64.detail = True
    
    def detect_oep(self, binary_data: bytes, candidates: List[int], 
                   architecture: str = "x64") -> Optional[int]:
        """Detect OEP using multiple heuristics"""
        try:
            logger.info(f"Detecting OEP with {len(candidates)} candidates")
            
            # Analyze each candidate
            scored_candidates = []
            
            for candidate_addr in candidates:
                candidate = self._analyze_oep_candidate(
                    binary_data, candidate_addr, architecture
                )
                if candidate and candidate.confidence > 0.3:  # 30% minimum confidence
                    scored_candidates.append(candidate)
            
            # Sort by confidence
            scored_candidates.sort(key=lambda x: x.confidence, reverse=True)
            
            if scored_candidates:
                best_candidate = scored_candidates[0]
                logger.info(f"Best OEP candidate: 0x{best_candidate.address:08X} "
                          f"(confidence: {best_candidate.confidence:.2%})")
                return best_candidate.address
            
            # Fallback: try automatic detection
            return self._automatic_oep_detection(binary_data, architecture)
            
        except Exception as e:
            logger.error(f"OEP detection failed: {e}")
            return None
    
    def _analyze_oep_candidate(self, data: bytes, address: int, 
                              architecture: str) -> Optional[OEPCandidate]:
        """Analyze a single OEP candidate"""
        try:
            # Extract code segment around candidate
            code_offset = address if address < len(data) else len(data) - 0x100
            code_segment = data[code_offset:code_offset + 0x200]  # 512 bytes
            
            if len(code_segment) < 16:
                return None
            
            candidate = OEPCandidate(
                address=address,
                confidence=0.0,
                heuristics=[],
                evidence={}
            )
            
            # Apply heuristics
            self._apply_compiler_signature_heuristic(candidate, code_segment, architecture)
            self._apply_api_call_pattern_heuristic(candidate, code_segment, architecture)
            self._apply_entropy_analysis_heuristic(candidate, code_segment)
            self._apply_disassembly_pattern_heuristic(candidate, code_segment, architecture)
            self._apply_stack_analysis_heuristic(candidate, code_segment, architecture)
            
            # Calculate final confidence
            self._calculate_final_confidence(candidate)
            
            return candidate
            
        except Exception as e:
            logger.error(f"Candidate analysis failed: {e}")
            return None
    
    def _apply_compiler_signature_heuristic(self, candidate: OEPCandidate, 
                                           code: bytes, architecture: str):
        """Apply compiler signature heuristic"""
        matches = self.signature_db.match_signature(code, architecture)
        
        if matches:
            best_match = max(matches, key=lambda x: x[0].confidence_weight)
            signature, offset = best_match
            
            candidate.heuristics.append(OEPHeuristic.COMPILER_SIGNATURE)
            candidate.evidence['compiler_signature'] = {
                'name': signature.name,
                'offset': offset,
                'weight': signature.confidence_weight
            }
            candidate.confidence += signature.confidence_weight * 0.4  # 40% weight
    
    def _apply_api_call_pattern_heuristic(self, candidate: OEPCandidate, 
                                         code: bytes, architecture: str):
        """Apply API call pattern heuristic"""
        try:
            # Disassemble code
            cs = self.cs_x64 if architecture == "x64" else self.cs_x86
            instructions = list(cs.disasm(code, 0))
            
            # Look for typical startup API patterns
            api_patterns = [
                "GetModuleHandle",
                "GetProcAddress", 
                "LoadLibrary",
                "VirtualAlloc",
                "GetCommandLine",
                "GetEnvironmentStrings",
                "ExitProcess",
                "GetCurrentProcess"
            ]
            
            api_calls_found = 0
            for insn in instructions[:20]:  # Check first 20 instructions
                if insn.mnemonic == "call":
                    api_calls_found += 1
            
            if api_calls_found >= 2:  # At least 2 API calls
                candidate.heuristics.append(OEPHeuristic.API_CALL_PATTERN)
                candidate.evidence['api_calls'] = api_calls_found
                candidate.confidence += 0.2  # 20% weight
                
        except Exception as e:
            logger.debug(f"API pattern analysis failed: {e}")
    
    def _apply_entropy_analysis_heuristic(self, candidate: OEPCandidate, code: bytes):
        """Apply entropy analysis heuristic"""
        try:
            entropy = self._calculate_entropy(code)
            
            # Good OEP typically has moderate entropy (3-6)
            if 3.0 <= entropy <= 6.0:
                candidate.heuristics.append(OEPHeuristic.ENTROPY_ANALYSIS)
                candidate.evidence['entropy'] = entropy
                
                # Higher confidence for optimal entropy range
                if 4.0 <= entropy <= 5.5:
                    candidate.confidence += 0.15  # 15% weight
                else:
                    candidate.confidence += 0.05  # 5% weight
                    
        except Exception as e:
            logger.debug(f"Entropy analysis failed: {e}")
    
    def _apply_disassembly_pattern_heuristic(self, candidate: OEPCandidate, 
                                            code: bytes, architecture: str):
        """Apply disassembly pattern heuristic"""
        try:
            cs = self.cs_x64 if architecture == "x64" else self.cs_x86
            instructions = list(cs.disasm(code, 0))
            
            if len(instructions) < 5:
                return
            
            # Store disassembly for analysis
            candidate.disassembly = "\n".join([f"{insn.mnemonic} {insn.op_str}" 
                                             for insn in instructions[:10]])
            
            # Look for typical OEP patterns
            pattern_score = 0.0
            
            # Pattern 1: Function prologue
            if (instructions[0].mnemonic == "push" and 
                len(instructions) > 1 and instructions[1].mnemonic == "mov"):
                pattern_score += 0.1
            
            # Pattern 2: Stack frame setup
            for i, insn in enumerate(instructions[:5]):
                if insn.mnemonic in ["sub", "add"] and "sp" in insn.op_str:
                    pattern_score += 0.05
                    break
            
            # Pattern 3: Register initialization
            for insn in instructions[:10]:
                if insn.mnemonic in ["xor", "mov"] and insn.op_str.count(",") > 0:
                    ops = insn.op_str.split(",")
                    if len(ops) >= 2 and ops[0].strip() == ops[1].strip():
                        pattern_score += 0.05  # xor reg, reg pattern
                        break
            
            # Pattern 4: No obvious jumps backward (not loop body)
            backward_jumps = 0
            for insn in instructions[:15]:
                if insn.mnemonic.startswith("j") and len(insn.operands) > 0:
                    if insn.operands[0].type == CS_OP_IMM:
                        target = insn.operands[0].imm
                        if target < insn.address:
                            backward_jumps += 1
            
            if backward_jumps == 0:
                pattern_score += 0.1
            
            if pattern_score > 0.1:
                candidate.heuristics.append(OEPHeuristic.DISASSEMBLY_PATTERN)
                candidate.evidence['disassembly_patterns'] = pattern_score
                candidate.confidence += min(pattern_score, 0.2)  # Max 20% weight
                
        except Exception as e:
            logger.debug(f"Disassembly pattern analysis failed: {e}")
    
    def _apply_stack_analysis_heuristic(self, candidate: OEPCandidate, 
                                       code: bytes, architecture: str):
        """Apply stack analysis heuristic"""
        try:
            cs = self.cs_x64 if architecture == "x64" else self.cs_x86
            instructions = list(cs.disasm(code, 0))
            
            # Analyze stack operations
            stack_ops = 0
            for insn in instructions[:10]:
                if ("sp" in insn.op_str or "bp" in insn.op_str or 
                    insn.mnemonic in ["push", "pop", "call", "ret"]):
                    stack_ops += 1
            
            # Good OEP typically has some stack operations
            if stack_ops >= 2:
                candidate.heuristics.append(OEPHeuristic.STACK_ANALYSIS)
                candidate.evidence['stack_operations'] = stack_ops
                candidate.confidence += 0.1  # 10% weight
                
        except Exception as e:
            logger.debug(f"Stack analysis failed: {e}")
    
    def _calculate_final_confidence(self, candidate: OEPCandidate):
        """Calculate final confidence score"""
        # Apply diminishing returns for multiple heuristics
        heuristic_count = len(candidate.heuristics)
        if heuristic_count >= 3:
            candidate.confidence *= 1.2  # Bonus for multiple heuristics
        elif heuristic_count >= 2:
            candidate.confidence *= 1.1
        
        # Cap confidence at 100%
        candidate.confidence = min(candidate.confidence, 1.0)
    
    def _automatic_oep_detection(self, data: bytes, architecture: str) -> Optional[int]:
        """Automatic OEP detection without candidates"""
        try:
            logger.info("Attempting automatic OEP detection")
            
            # Try to parse as PE
            try:
                pe = pefile.PE(data=data)
                entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                image_base = pe.OPTIONAL_HEADER.ImageBase
                
                # Verify this looks like a real OEP
                file_offset = pe.get_offset_from_rva(entry_point)
                if file_offset and file_offset < len(data):
                    code_segment = data[file_offset:file_offset + 0x100]
                    
                    candidate = self._analyze_oep_candidate(
                        data, image_base + entry_point, architecture
                    )
                    
                    if candidate and candidate.confidence > 0.4:
                        logger.info(f"Automatic OEP detection successful: 0x{candidate.address:08X}")
                        return candidate.address
                        
            except Exception:
                pass
            
            # Fallback: scan for compiler signatures
            matches = self.signature_db.match_signature(data, architecture)
            if matches:
                best_match = max(matches, key=lambda x: x[0].confidence_weight)
                signature, offset = best_match
                
                logger.info(f"Found {signature.name} signature at offset 0x{offset:08X}")
                return offset
            
            return None
            
        except Exception as e:
            logger.error(f"Automatic OEP detection failed: {e}")
            return None
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        # Count byte frequencies
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        
        for count in freq:
            if count > 0:
                probability = count / data_len
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    
    def analyze_oep_region(self, data: bytes, oep_address: int, 
                          architecture: str = "x64") -> Dict[str, Any]:
        """Analyze OEP region for additional insights"""
        try:
            # Extract larger region around OEP
            code_offset = oep_address if oep_address < len(data) else len(data) - 0x400
            code_region = data[code_offset:code_offset + 0x400]  # 1KB region
            
            cs = self.cs_x64 if architecture == "x64" else self.cs_x86
            instructions = list(cs.disasm(code_region, oep_address))
            
            analysis = {
                'instruction_count': len(instructions),
                'entropy': self._calculate_entropy(code_region),
                'functions_detected': self._detect_functions(instructions),
                'api_calls': self._extract_api_calls(instructions),
                'control_flow': self._analyze_control_flow(instructions),
                'disassembly': [f"0x{insn.address:08X}: {insn.mnemonic} {insn.op_str}" 
                              for insn in instructions[:20]]
            }
            
            return analysis
            
        except Exception as e:
            logger.error(f"OEP region analysis failed: {e}")
            return {}
    
    def _detect_functions(self, instructions: List[Any]) -> List[Dict[str, Any]]:
        """Detect function boundaries in disassembly"""
        functions = []
        current_function_start = None
        
        for insn in instructions:
            # Function start indicators
            if (insn.mnemonic == "push" and "bp" in insn.op_str) or \
               (insn.mnemonic == "mov" and "bp" in insn.op_str and "sp" in insn.op_str):
                if current_function_start is None:
                    current_function_start = insn.address
            
            # Function end indicators
            elif insn.mnemonic == "ret":
                if current_function_start is not None:
                    functions.append({
                        'start': current_function_start,
                        'end': insn.address,
                        'size': insn.address - current_function_start
                    })
                    current_function_start = None
        
        return functions
    
    def _extract_api_calls(self, instructions: List[Any]) -> List[Dict[str, Any]]:
        """Extract API calls from disassembly"""
        api_calls = []
        
        for insn in instructions:
            if insn.mnemonic == "call":
                api_calls.append({
                    'address': insn.address,
                    'target': insn.op_str,
                    'type': 'direct' if insn.operands[0].type == CS_OP_IMM else 'indirect'
                })
        
        return api_calls
    
    def _analyze_control_flow(self, instructions: List[Any]) -> Dict[str, Any]:
        """Analyze control flow patterns"""
        jumps = []
        calls = []
        returns = []
        
        for insn in instructions:
            if insn.mnemonic.startswith('j'):
                jumps.append({
                    'address': insn.address,
                    'type': insn.mnemonic,
                    'target': insn.op_str
                })
            elif insn.mnemonic == 'call':
                calls.append(insn.address)
            elif insn.mnemonic == 'ret':
                returns.append(insn.address)
        
        return {
            'jumps': jumps,
            'calls': calls,
            'returns': returns,
            'complexity': len(jumps) + len(calls)
        }