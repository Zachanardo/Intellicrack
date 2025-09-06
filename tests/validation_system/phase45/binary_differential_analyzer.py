"""Binary Differential Analysis for Intellicrack Validation Framework.

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

import hashlib
import json
import logging
import mmap
import os
import struct
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import psutil

try:
    import capstone
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
except ImportError:
    capstone = None
    Cs = CS_ARCH_X86 = CS_MODE_32 = CS_MODE_64 = None

try:
    import pefile
except ImportError:
    pefile = None

try:
    import networkx as nx
except ImportError:
    nx = None

try:
    import numpy as np
except ImportError:
    np = None


class DisassemblyEngine:
    """Advanced disassembly engine for sophisticated binary analysis."""
    
    def __init__(self, binary_data: bytes, arch: int = CS_ARCH_X86, mode: int = CS_MODE_64):
        """Initialize disassembly engine.
        
        Args:
            binary_data: Binary data to disassemble
            arch: Capstone architecture constant
            mode: Capstone mode constant (32/64 bit)
        """
        self.binary_data = binary_data
        self.arch = arch
        self.mode = mode
        self.disassembler = None
        self.instructions = []
        self.control_flow_graph = None
        self.function_boundaries = {}
        self.crypto_signatures = {}
        self.protection_patterns = {}
        
        if capstone:
            self.disassembler = Cs(arch, mode)
            self.disassembler.detail = True
    
    def disassemble_region(self, start_offset: int, size: int) -> List[Dict]:
        """Disassemble a specific region of the binary.
        
        Args:
            start_offset: Starting offset in binary
            size: Number of bytes to disassemble
            
        Returns:
            List of disassembled instructions
        """
        if not self.disassembler:
            return []
        
        instructions = []
        region_data = self.binary_data[start_offset:start_offset + size]
        
        for insn in self.disassembler.disasm(region_data, start_offset):
            instruction = {
                "address": insn.address,
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "bytes": insn.bytes.hex(),
                "size": insn.size,
                "groups": [self.disassembler.group_name(g) for g in insn.groups] if insn.detail else [],
                "regs_read": [self.disassembler.reg_name(r) for r in insn.regs_read] if insn.detail else [],
                "regs_write": [self.disassembler.reg_name(r) for r in insn.regs_write] if insn.detail else [],
                "semantic_type": self._classify_instruction(insn)
            }
            instructions.append(instruction)
        
        return instructions
    
    def _classify_instruction(self, insn) -> str:
        """Classify instruction by semantic type.
        
        Args:
            insn: Capstone instruction object
            
        Returns:
            Semantic classification
        """
        mnemonic = insn.mnemonic.lower()
        
        # Anti-debugging instructions
        if mnemonic in ['rdtsc', 'cpuid', 'int3', 'int', 'icebp']:
            return "anti_debug"
        
        # Crypto operations
        elif mnemonic in ['aesenc', 'aesdec', 'aesimc', 'aeskeygen', 'sha256msg1', 'sha256msg2']:
            return "crypto"
        
        # Control flow
        elif mnemonic in ['jmp', 'je', 'jne', 'jz', 'jnz', 'call', 'ret', 'loop']:
            return "control_flow"
        
        # Memory operations
        elif mnemonic in ['mov', 'lea', 'push', 'pop', 'xchg']:
            return "memory"
        
        # Arithmetic
        elif mnemonic in ['add', 'sub', 'mul', 'div', 'imul', 'idiv', 'inc', 'dec']:
            return "arithmetic"
        
        # Logical
        elif mnemonic in ['and', 'or', 'xor', 'not', 'test', 'cmp']:
            return "logical"
        
        # Obfuscation patterns
        elif mnemonic in ['pushf', 'popf', 'sahf', 'lahf', 'clc', 'stc', 'cmc']:
            return "obfuscation"
        
        else:
            return "general"
    
    def build_control_flow_graph(self, start_address: int = 0) -> nx.DiGraph:
        """Build control flow graph from disassembled instructions.
        
        Args:
            start_address: Starting address for CFG construction
            
        Returns:
            NetworkX directed graph representing control flow
        """
        if not nx:
            return None
        
        cfg = nx.DiGraph()
        basic_blocks = self._identify_basic_blocks(start_address)
        
        for block_id, block in basic_blocks.items():
            cfg.add_node(block_id, **block)
            
            # Add edges based on control flow
            last_insn = block.get("last_instruction")
            if last_insn:
                if last_insn["mnemonic"].lower() in ['jmp', 'je', 'jne', 'jz', 'jnz']:
                    # Extract jump target
                    target = self._extract_jump_target(last_insn)
                    if target:
                        cfg.add_edge(block_id, target, type="jump")
                
                elif last_insn["mnemonic"].lower() == 'call':
                    # Extract call target
                    target = self._extract_call_target(last_insn)
                    if target:
                        cfg.add_edge(block_id, target, type="call")
                        # Also add fallthrough edge
                        next_block = block_id + block["size"]
                        cfg.add_edge(block_id, next_block, type="fallthrough")
                
                elif last_insn["mnemonic"].lower() != 'ret':
                    # Fallthrough to next block
                    next_block = block_id + block["size"]
                    cfg.add_edge(block_id, next_block, type="fallthrough")
        
        self.control_flow_graph = cfg
        return cfg
    
    def _identify_basic_blocks(self, start_address: int) -> Dict[int, Dict]:
        """Identify basic blocks in disassembled code.
        
        Args:
            start_address: Starting address
            
        Returns:
            Dictionary of basic blocks
        """
        blocks = {}
        current_block = {"start": start_address, "instructions": [], "size": 0}
        block_starts = {start_address}
        
        # First pass: identify block boundaries
        for insn in self.instructions:
            mnemonic = insn["mnemonic"].lower()
            
            # Check if this is a block boundary
            if insn["address"] in block_starts and insn["address"] != current_block["start"]:
                # Save current block
                if current_block["instructions"]:
                    blocks[current_block["start"]] = current_block
                
                # Start new block
                current_block = {"start": insn["address"], "instructions": [], "size": 0}
            
            current_block["instructions"].append(insn)
            current_block["size"] += insn["size"]
            
            # Check if this instruction ends a block
            if mnemonic in ['jmp', 'je', 'jne', 'jz', 'jnz', 'ret', 'call']:
                current_block["last_instruction"] = insn
                blocks[current_block["start"]] = current_block
                
                # Mark next instruction as block start
                next_addr = insn["address"] + insn["size"]
                block_starts.add(next_addr)
                
                # For conditional jumps, mark target as block start
                if mnemonic in ['je', 'jne', 'jz', 'jnz']:
                    target = self._extract_jump_target(insn)
                    if target:
                        block_starts.add(target)
                
                current_block = {"start": next_addr, "instructions": [], "size": 0}
        
        # Save last block if any
        if current_block["instructions"]:
            blocks[current_block["start"]] = current_block
        
        return blocks
    
    def _extract_jump_target(self, insn: Dict) -> Optional[int]:
        """Extract jump target address from instruction.
        
        Args:
            insn: Instruction dictionary
            
        Returns:
            Target address or None
        """
        op_str = insn.get("op_str", "")
        
        # Try to parse as hex address
        if op_str.startswith("0x"):
            try:
                return int(op_str, 16)
            except ValueError:
                pass
        
        # Handle relative jumps
        try:
            offset = int(op_str, 16) if op_str.startswith("0x") else int(op_str)
            return insn["address"] + insn["size"] + offset
        except (ValueError, TypeError):
            return None
    
    def _extract_call_target(self, insn: Dict) -> Optional[int]:
        """Extract call target address from instruction.
        
        Args:
            insn: Instruction dictionary
            
        Returns:
            Target address or None
        """
        return self._extract_jump_target(insn)  # Similar logic for calls
    
    def detect_protection_patterns(self) -> Dict[str, List[Dict]]:
        """Detect common protection patterns in disassembled code.
        
        Returns:
            Dictionary of detected protection patterns
        """
        patterns = {
            "anti_debug": [],
            "anti_vm": [],
            "packing": [],
            "obfuscation": [],
            "encryption": [],
            "licensing": [],
            "integrity_checks": []
        }
        
        for i, insn in enumerate(self.instructions):
            # Anti-debugging patterns
            if insn["semantic_type"] == "anti_debug":
                patterns["anti_debug"].append({
                    "address": insn["address"],
                    "type": "instruction",
                    "detail": f"{insn['mnemonic']} - Direct anti-debug instruction"
                })
            
            # Check for IsDebuggerPresent pattern
            if insn["mnemonic"].lower() == "call" and "IsDebuggerPresent" in insn.get("op_str", ""):
                patterns["anti_debug"].append({
                    "address": insn["address"],
                    "type": "api_call",
                    "detail": "IsDebuggerPresent API call"
                })
            
            # VM detection patterns
            if insn["mnemonic"].lower() == "cpuid":
                patterns["anti_vm"].append({
                    "address": insn["address"],
                    "type": "cpuid",
                    "detail": "CPUID instruction - potential VM detection"
                })
            
            # Packing indicators
            if i < len(self.instructions) - 1:
                next_insn = self.instructions[i + 1]
                if insn["mnemonic"].lower() == "pushad" and next_insn["mnemonic"].lower() in ["xor", "add", "sub"]:
                    patterns["packing"].append({
                        "address": insn["address"],
                        "type": "unpacking_stub",
                        "detail": "Potential unpacking stub detected"
                    })
            
            # Obfuscation patterns
            if insn["mnemonic"].lower() in ["jmp"] and i < len(self.instructions) - 1:
                # Check for jmp to next instruction (obfuscation)
                next_addr = insn["address"] + insn["size"]
                target = self._extract_jump_target(insn)
                if target == next_addr:
                    patterns["obfuscation"].append({
                        "address": insn["address"],
                        "type": "redundant_jump",
                        "detail": "Jump to next instruction - obfuscation"
                    })
            
            # Crypto operations
            if insn["semantic_type"] == "crypto":
                patterns["encryption"].append({
                    "address": insn["address"],
                    "type": "crypto_instruction",
                    "detail": f"{insn['mnemonic']} - Cryptographic operation"
                })
            
            # License checking patterns
            if "license" in insn.get("op_str", "").lower() or "serial" in insn.get("op_str", "").lower():
                patterns["licensing"].append({
                    "address": insn["address"],
                    "type": "license_reference",
                    "detail": f"Potential license check at {hex(insn['address'])}"
                })
            
            # Integrity checks (CRC32, checksums)
            if insn["mnemonic"].lower() in ["crc32", "adler32"]:
                patterns["integrity_checks"].append({
                    "address": insn["address"],
                    "type": "checksum",
                    "detail": f"{insn['mnemonic']} - Integrity check"
                })
        
        self.protection_patterns = patterns
        return patterns
    
    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data.
        
        Args:
            data: Binary data
            
        Returns:
            Entropy value (0-8)
        """
        if not data or not np:
            return 0.0
        
        # Calculate byte frequency
        byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        probabilities = byte_counts[byte_counts > 0] / len(data)
        
        # Calculate entropy
        entropy = -np.sum(probabilities * np.log2(probabilities))
        return float(entropy)


class BinaryDifferentialAnalyzer:
    """Performs sophisticated differential analysis of binary modifications with deep disassembly."""

    def __init__(self, target_binary_path: str, work_dir: Optional[str] = None):
        """Initialize binary differential analyzer.
        
        Args:
            target_binary_path: Path to the target binary to analyze
            work_dir: Working directory for storing analysis results
        """
        self.target_binary_path = Path(target_binary_path)
        self.work_dir = Path(work_dir) if work_dir else Path.cwd() / "binary_diff_analysis"
        self.work_dir.mkdir(parents=True, exist_ok=True)
        
        self.logger = logging.getLogger(__name__)
        self._setup_logging()
        
        # Binary snapshots
        self.original_binary_data: Optional[bytes] = None
        self.modified_binary_data: Optional[bytes] = None
        self.original_hash: Optional[str] = None
        self.modified_hash: Optional[str] = None
        
        # Memory snapshots
        self.original_memory_data: Dict[int, bytes] = {}
        self.modified_memory_data: Dict[int, bytes] = {}
        
        # Analysis results
        self.byte_differences: List[Dict] = []
        self.memory_differences: List[Dict] = []
        self.modification_analysis: Dict = {}
        
        # Disassembly engines
        self.original_disassembly: Optional[DisassemblyEngine] = None
        self.modified_disassembly: Optional[DisassemblyEngine] = None
        self.instruction_differences: List[Dict] = []
        self.cfg_differences: Dict = {}
        self.protection_analysis: Dict = {}
        
        # Validate target binary exists
        if not self.target_binary_path.exists():
            raise FileNotFoundError(f"Target binary not found: {target_binary_path}")
            
        self.logger.info(f"Initialized BinaryDifferentialAnalyzer for {self.target_binary_path}")
        
        # Initialize architecture detection
        self.architecture = None
        self.is_64bit = None

    def _setup_logging(self) -> None:
        """Setup logging for the analyzer."""
        log_file = self.work_dir / "binary_diff_analysis.log"
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )

    def capture_original_state(self) -> bool:
        """Capture the original binary state before any modifications.
        
        Returns:
            True if capture successful, False otherwise
        """
        try:
            self.logger.info("Capturing original binary state...")
            
            # Read original binary data
            with open(self.target_binary_path, 'rb') as f:
                self.original_binary_data = f.read()
            
            # Calculate hash
            self.original_hash = hashlib.sha256(self.original_binary_data).hexdigest()
            
            # Save original binary snapshot
            original_snapshot_path = self.work_dir / f"original_binary_{int(time.time())}.bin"
            with open(original_snapshot_path, 'wb') as f:
                f.write(self.original_binary_data)
            
            self.logger.info(f"Original binary captured: {len(self.original_binary_data)} bytes")
            self.logger.info(f"Original SHA-256: {self.original_hash}")
            
            # If binary is loaded in memory, capture memory state
            self._capture_memory_state("original")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to capture original state: {e}")
            return False

    def capture_modified_state(self) -> bool:
        """Capture the binary state after modifications.
        
        Returns:
            True if capture successful, False otherwise
        """
        try:
            self.logger.info("Capturing modified binary state...")
            
            # Read modified binary data
            with open(self.target_binary_path, 'rb') as f:
                self.modified_binary_data = f.read()
            
            # Calculate hash
            self.modified_hash = hashlib.sha256(self.modified_binary_data).hexdigest()
            
            # Save modified binary snapshot
            modified_snapshot_path = self.work_dir / f"modified_binary_{int(time.time())}.bin"
            with open(modified_snapshot_path, 'wb') as f:
                f.write(self.modified_binary_data)
            
            self.logger.info(f"Modified binary captured: {len(self.modified_binary_data)} bytes")
            self.logger.info(f"Modified SHA-256: {self.modified_hash}")
            
            # If binary is loaded in memory, capture memory state
            self._capture_memory_state("modified")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to capture modified state: {e}")
            return False

    def _capture_memory_state(self, state_type: str) -> None:
        """Capture memory state of running process.
        
        Args:
            state_type: "original" or "modified"
        """
        try:
            binary_name = self.target_binary_path.stem + ".exe"
            processes = [p for p in psutil.process_iter(['pid', 'name']) 
                        if p.info['name'].lower() == binary_name.lower()]
            
            if not processes:
                self.logger.warning(f"No running process found for {binary_name}")
                return
            
            for process in processes[:1]:  # Analyze first matching process
                pid = process.info['pid']
                self.logger.info(f"Capturing memory state for PID {pid} ({state_type})")
                
                try:
                    proc = psutil.Process(pid)
                    memory_info = proc.memory_info()
                    
                    # Capture memory mappings
                    memory_data = self._read_process_memory(pid)
                    
                    if state_type == "original":
                        self.original_memory_data[pid] = memory_data
                    else:
                        self.modified_memory_data[pid] = memory_data
                        
                    self.logger.info(f"Memory captured: {len(memory_data)} bytes")
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    self.logger.warning(f"Cannot access process {pid}: {e}")
                    
        except Exception as e:
            self.logger.error(f"Failed to capture memory state: {e}")

    def _read_process_memory(self, pid: int) -> bytes:
        """Read process memory using Windows API.
        
        Args:
            pid: Process ID
            
        Returns:
            Process memory content
        """
        try:
            import ctypes
            from ctypes import wintypes
            
            # Windows API constants
            PROCESS_VM_READ = 0x0010
            PROCESS_QUERY_INFORMATION = 0x0400
            
            kernel32 = ctypes.windll.kernel32
            
            # Open process
            process_handle = kernel32.OpenProcess(
                PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                False,
                pid
            )
            
            if not process_handle:
                raise OSError(f"Cannot open process {pid}")
            
            try:
                # Query process memory regions
                memory_data = b""
                address = 0
                
                while address < 0x7FFFFFFF:  # User space limit
                    mbi = ctypes.create_string_buffer(48)  # MEMORY_BASIC_INFORMATION size
                    
                    result = kernel32.VirtualQueryEx(
                        process_handle,
                        ctypes.c_void_p(address),
                        mbi,
                        48
                    )
                    
                    if not result:
                        break
                    
                    # Parse MEMORY_BASIC_INFORMATION
                    base_address = struct.unpack('Q', mbi.raw[0:8])[0]
                    region_size = struct.unpack('Q', mbi.raw[16:24])[0]
                    state = struct.unpack('I', mbi.raw[24:28])[0]
                    protect = struct.unpack('I', mbi.raw[28:32])[0]
                    
                    # Read committed executable memory
                    if state == 0x1000 and (protect & 0x20 or protect & 0x40):  # MEM_COMMIT, PAGE_EXECUTE_*
                        buffer = ctypes.create_string_buffer(region_size)
                        bytes_read = ctypes.c_size_t()
                        
                        success = kernel32.ReadProcessMemory(
                            process_handle,
                            ctypes.c_void_p(base_address),
                            buffer,
                            region_size,
                            ctypes.byref(bytes_read)
                        )
                        
                        if success and bytes_read.value > 0:
                            memory_data += buffer.raw[:bytes_read.value]
                    
                    address = base_address + region_size
                
                return memory_data
                
            finally:
                kernel32.CloseHandle(process_handle)
                
        except Exception as e:
            self.logger.error(f"Failed to read process memory: {e}")
            return b""

    def generate_binary_diff(self) -> Dict:
        """Generate byte-level diff between original and modified binary.
        
        Returns:
            Dictionary containing detailed difference analysis
        """
        if not self.original_binary_data or not self.modified_binary_data:
            raise ValueError("Original and modified binary data required")
        
        self.logger.info("Generating byte-level binary diff...")
        
        # Reset differences
        self.byte_differences = []
        
        # Compare binary sizes
        original_size = len(self.original_binary_data)
        modified_size = len(self.modified_binary_data)
        
        if original_size != modified_size:
            self.logger.warning(f"Binary size changed: {original_size} -> {modified_size}")
        
        # Byte-by-byte comparison
        min_size = min(original_size, modified_size)
        modification_count = 0
        
        for offset in range(min_size):
            original_byte = self.original_binary_data[offset]
            modified_byte = self.modified_binary_data[offset]
            
            if original_byte != modified_byte:
                modification_count += 1
                
                # Analyze modification context
                context_start = max(0, offset - 16)
                context_end = min(len(self.original_binary_data), offset + 17)
                
                original_context = self.original_binary_data[context_start:context_end]
                modified_context = self.modified_binary_data[context_start:context_end]
                
                difference = {
                    "offset": f"0x{offset:08X}",
                    "original_byte": f"0x{original_byte:02X}",
                    "modified_byte": f"0x{modified_byte:02X}",
                    "original_context": original_context.hex(),
                    "modified_context": modified_context.hex(),
                    "section": self._get_pe_section(offset),
                    "explanation": self._explain_modification(offset, original_byte, modified_byte),
                    "modification_type": self._classify_modification(original_byte, modified_byte)
                }
                
                self.byte_differences.append(difference)
        
        # Handle size differences
        if modified_size > original_size:
            for offset in range(original_size, modified_size):
                self.byte_differences.append({
                    "offset": f"0x{offset:08X}",
                    "original_byte": "N/A",
                    "modified_byte": f"0x{self.modified_binary_data[offset]:02X}",
                    "explanation": "Byte added to binary",
                    "modification_type": "addition"
                })
        elif original_size > modified_size:
            for offset in range(modified_size, original_size):
                self.byte_differences.append({
                    "offset": f"0x{offset:08X}",
                    "original_byte": f"0x{self.original_binary_data[offset]:02X}",
                    "modified_byte": "N/A",
                    "explanation": "Byte removed from binary",
                    "modification_type": "deletion"
                })
        
        diff_summary = {
            "total_modifications": len(self.byte_differences),
            "original_size": original_size,
            "modified_size": modified_size,
            "size_change": modified_size - original_size,
            "original_hash": self.original_hash,
            "modified_hash": self.modified_hash,
            "modifications": self.byte_differences,
            "analysis_timestamp": time.time()
        }
        
        self.logger.info(f"Binary diff complete: {len(self.byte_differences)} modifications found")
        
        # Save diff report
        diff_report_path = self.work_dir / f"binary_diff_report_{int(time.time())}.json"
        with open(diff_report_path, 'w', encoding='utf-8') as f:
            json.dump(diff_summary, f, indent=2, ensure_ascii=False)
        
        return diff_summary

    def _get_pe_section(self, offset: int) -> str:
        """Identify which PE section contains the given offset.
        
        Args:
            offset: Byte offset in binary
            
        Returns:
            Section name or "Unknown"
        """
        if not pefile:
            return "Unknown (pefile not available)"
        
        try:
            pe = pefile.PE(data=self.original_binary_data)
            
            for section in pe.sections:
                section_start = section.PointerToRawData
                section_end = section_start + section.SizeOfRawData
                
                if section_start <= offset < section_end:
                    return section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            
            return "Unknown"
            
        except Exception as e:
            self.logger.warning(f"Failed to parse PE sections: {e}")
            return "Unknown"

    def _explain_modification(self, offset: int, original_byte: int, modified_byte: int) -> str:
        """Provide explanation for the byte modification.
        
        Args:
            offset: Byte offset
            original_byte: Original byte value
            modified_byte: Modified byte value
            
        Returns:
            Human-readable explanation
        """
        # Common patterns
        if original_byte == 0x74 and modified_byte == 0x75:
            return "JZ -> JNZ: Jump condition inverted"
        elif original_byte == 0x75 and modified_byte == 0x74:
            return "JNZ -> JZ: Jump condition inverted"
        elif original_byte == 0x85 and modified_byte == 0x31:
            return "TEST -> XOR: Register comparison to zero"
        elif original_byte == 0xE8 and modified_byte == 0x90:
            return "CALL -> NOP: Function call disabled"
        elif modified_byte == 0x90:
            return f"Byte NOPed: 0x{original_byte:02X} -> NOP"
        elif original_byte == 0x90 and modified_byte != 0x90:
            return f"NOP replaced: NOP -> 0x{modified_byte:02X}"
        elif abs(modified_byte - original_byte) == 1:
            return f"Single bit flip: 0x{original_byte:02X} -> 0x{modified_byte:02X}"
        else:
            return f"Byte changed: 0x{original_byte:02X} -> 0x{modified_byte:02X}"

    def _classify_modification(self, original_byte: int, modified_byte: int) -> str:
        """Classify the type of modification.
        
        Args:
            original_byte: Original byte value
            modified_byte: Modified byte value
            
        Returns:
            Modification classification
        """
        if modified_byte == 0x90:
            return "nop_patch"
        elif original_byte == 0x90:
            return "nop_replacement"
        elif original_byte in [0x74, 0x75] and modified_byte in [0x74, 0x75]:
            return "conditional_jump_flip"
        elif original_byte == 0xE8:
            return "call_modification"
        elif abs(modified_byte - original_byte) == 1:
            return "bit_flip"
        elif abs(modified_byte - original_byte) < 16:
            return "small_change"
        else:
            return "major_change"

    def validate_modifications(self) -> Dict:
        """Validate that modifications are intentional and safe.
        
        Returns:
            Validation results
        """
        if not self.byte_differences:
            return {"status": "no_modifications", "validation": "passed"}
        
        self.logger.info("Validating binary modifications...")
        
        validation_results = {
            "total_modifications": len(self.byte_differences),
            "modification_types": {},
            "suspicious_patterns": [],
            "validation_status": "unknown",
            "recommendations": []
        }
        
        # Count modification types
        for diff in self.byte_differences:
            mod_type = diff.get("modification_type", "unknown")
            validation_results["modification_types"][mod_type] = \
                validation_results["modification_types"].get(mod_type, 0) + 1
        
        # Check for suspicious patterns
        suspicious_count = 0
        
        # Too many modifications might indicate corruption
        if len(self.byte_differences) > 1000:
            validation_results["suspicious_patterns"].append(
                f"Excessive modifications: {len(self.byte_differences)} changes detected"
            )
            suspicious_count += 1
        
        # Random modifications might indicate corruption
        major_changes = validation_results["modification_types"].get("major_change", 0)
        if major_changes > len(self.byte_differences) * 0.5:
            validation_results["suspicious_patterns"].append(
                f"Many major changes: {major_changes} significant byte alterations"
            )
            suspicious_count += 1
        
        # Check for unintended side effects
        if "addition" in validation_results["modification_types"]:
            validation_results["suspicious_patterns"].append(
                "Binary size increased - check for unintended additions"
            )
        
        # Determine overall validation status
        if suspicious_count == 0:
            validation_results["validation_status"] = "passed"
        elif suspicious_count <= 2:
            validation_results["validation_status"] = "warning"
        else:
            validation_results["validation_status"] = "failed"
        
        # Generate recommendations
        if validation_results["modification_types"].get("nop_patch", 0) > 0:
            validation_results["recommendations"].append(
                "NOPs detected - verify instruction alignment is maintained"
            )
        
        if validation_results["modification_types"].get("conditional_jump_flip", 0) > 0:
            validation_results["recommendations"].append(
                "Jump conditions modified - verify program logic remains sound"
            )
        
        self.logger.info(f"Validation status: {validation_results['validation_status']}")
        
        # Save validation report
        validation_report_path = self.work_dir / f"validation_report_{int(time.time())}.json"
        with open(validation_report_path, 'w', encoding='utf-8') as f:
            json.dump(validation_results, f, indent=2, ensure_ascii=False)
        
        return validation_results

    def generate_comprehensive_report(self) -> Dict:
        """Generate comprehensive analysis report.
        
        Returns:
            Complete analysis report
        """
        if not self.original_binary_data or not self.modified_binary_data:
            raise ValueError("Binary analysis not performed")
        
        # Generate diff if not already done
        if not self.byte_differences:
            self.generate_binary_diff()
        
        # Perform validation
        validation_results = self.validate_modifications()
        
        report = {
            "analysis_info": {
                "target_binary": str(self.target_binary_path),
                "work_directory": str(self.work_dir),
                "analysis_timestamp": time.time(),
                "analyzer_version": "1.0.0"
            },
            "binary_hashes": {
                "original_sha256": self.original_hash,
                "modified_sha256": self.modified_hash,
                "hashes_match": self.original_hash == self.modified_hash
            },
            "size_analysis": {
                "original_size": len(self.original_binary_data),
                "modified_size": len(self.modified_binary_data),
                "size_difference": len(self.modified_binary_data) - len(self.original_binary_data)
            },
            "modifications": {
                "total_count": len(self.byte_differences),
                "details": self.byte_differences[:100],  # Limit details in report
                "modification_summary": validation_results["modification_types"]
            },
            "validation": validation_results,
            "memory_analysis": {
                "original_processes": len(self.original_memory_data),
                "modified_processes": len(self.modified_memory_data),
                "memory_changes_detected": len(self.memory_differences) > 0
            }
        }
        
        # Save comprehensive report
        report_path = self.work_dir / f"comprehensive_report_{int(time.time())}.json"
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"Comprehensive report generated: {report_path}")
        
        return report