"""
Memory Structure Analysis Engine

Advanced analysis of memory structures including heap chunks, stack frames,
page tables, and memory corruption detection for security research.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from ...utils.logger import get_logger

logger = get_logger(__name__)

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False


class HeapType(Enum):
    """Types of heap implementations"""
    WINDOWS_NT_HEAP = "windows_nt_heap"
    GLIBC_HEAP = "glibc_heap"
    DLMALLOC = "dlmalloc"
    JEMALLOC = "jemalloc"
    TCMALLOC = "tcmalloc"
    CUSTOM_HEAP = "custom_heap"
    UNKNOWN = "unknown"


class ChunkState(Enum):
    """Heap chunk states"""
    FREE = "free"
    ALLOCATED = "allocated"
    TOP_CHUNK = "top_chunk"
    CORRUPTED = "corrupted"
    UNKNOWN = "unknown"


@dataclass
class HeapChunk:
    """Heap chunk metadata"""
    address: int
    size: int
    state: ChunkState
    prev_size: int = 0
    flags: int = 0
    user_data_size: int = 0
    fd: int = 0  # Forward pointer for free chunks
    bk: int = 0  # Backward pointer for free chunks
    corruption_indicators: List[str] = field(default_factory=list)
    
    @property
    def is_corrupted(self) -> bool:
        """Check if chunk shows corruption signs"""
        return len(self.corruption_indicators) > 0
    
    @property
    def is_large_chunk(self) -> bool:
        """Check if this is a large chunk (>64KB)"""
        return self.size > 65536


@dataclass
class HeapBin:
    """Heap bin for organizing free chunks"""
    index: int
    chunk_size: int
    chunks: List[HeapChunk] = field(default_factory=list)
    corruption_detected: bool = False


@dataclass
class HeapArena:
    """Heap arena (main heap structure)"""
    base_address: int
    size: int
    heap_type: HeapType
    chunks: List[HeapChunk] = field(default_factory=list)
    bins: List[HeapBin] = field(default_factory=list)
    top_chunk: Optional[HeapChunk] = None
    corruption_score: float = 0.0


@dataclass
class StackFrame:
    """Stack frame information"""
    frame_pointer: int
    return_address: int
    stack_pointer: int
    function_name: str = ""
    parameters: List[int] = field(default_factory=list)
    local_variables: List[Tuple[int, int]] = field(default_factory=list)  # (address, size)
    corruption_indicators: List[str] = field(default_factory=list)
    
    @property
    def is_corrupted(self) -> bool:
        """Check if frame shows corruption signs"""
        return len(self.corruption_indicators) > 0


@dataclass
class CallChain:
    """Complete call chain reconstruction"""
    frames: List[StackFrame] = field(default_factory=list)
    corruption_detected: bool = False
    rop_chain_detected: bool = False
    gadgets_found: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class MemoryCorruption:
    """Memory corruption analysis result"""
    corruption_type: str
    address: int
    size: int
    severity: str  # low, medium, high, critical
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    exploitability: str = "unknown"  # none, low, medium, high


class WindowsHeapAnalyzer:
    """Analyzer for Windows NT Heap structures"""
    
    def __init__(self):
        self.logger = logger.getChild("WindowsHeap")
    
    def analyze_heap(self, memory_data: bytes, base_address: int) -> HeapArena:
        """Analyze Windows NT Heap structure"""
        try:
            arena = HeapArena(
                base_address=base_address,
                size=len(memory_data),
                heap_type=HeapType.WINDOWS_NT_HEAP
            )
            
            # Parse heap header (simplified Windows NT heap)
            if len(memory_data) < 0x88:  # Minimum heap header size
                return arena
            
            # Windows heap signature and validation
            heap_signature = struct.unpack('<I', memory_data[0x50:0x54])[0]
            if heap_signature != 0xEEFFEEFF:  # Common heap signature
                self.logger.debug("Invalid Windows heap signature")
            
            # Parse heap segments
            segments_offset = 0x88
            current_offset = segments_offset
            
            while current_offset < len(memory_data) - 16:
                chunk = self._parse_windows_chunk(
                    memory_data[current_offset:current_offset + 16],
                    base_address + current_offset
                )
                
                if chunk:
                    arena.chunks.append(chunk)
                    current_offset += max(chunk.size, 16)
                else:
                    current_offset += 16
                
                # Prevent infinite loops
                if len(arena.chunks) > 10000:
                    break
            
            # Detect corruption
            arena.corruption_score = self._detect_windows_heap_corruption(arena)
            
            return arena
            
        except Exception as e:
            self.logger.error(f"Windows heap analysis failed: {e}")
            return HeapArena(
                base_address=base_address,
                size=len(memory_data),
                heap_type=HeapType.WINDOWS_NT_HEAP
            )
    
    def _parse_windows_chunk(self, chunk_data: bytes, address: int) -> Optional[HeapChunk]:
        """Parse a Windows heap chunk"""
        try:
            if len(chunk_data) < 16:
                return None
            
            # Parse chunk header
            prev_size = struct.unpack('<I', chunk_data[0:4])[0]
            size = struct.unpack('<I', chunk_data[4:8])[0]
            flags = struct.unpack('<I', chunk_data[8:12])[0]
            tag = struct.unpack('<I', chunk_data[12:16])[0]
            
            # Validate size
            if size == 0 or size > 0x7FFFFFFF:
                return None
            
            # Determine chunk state
            state = ChunkState.ALLOCATED
            if flags & 0x01:  # Free flag
                state = ChunkState.FREE
            
            chunk = HeapChunk(
                address=address,
                size=size,
                state=state,
                prev_size=prev_size,
                flags=flags,
                user_data_size=size - 16  # Subtract header size
            )
            
            # Check for corruption indicators
            corruption_indicators = []
            
            # Size validation
            if size < 16 or size > 0x1000000:  # 16MB max reasonable size
                corruption_indicators.append("Invalid chunk size")
            
            # Alignment check
            if size % 8 != 0:
                corruption_indicators.append("Chunk size not aligned")
            
            # Flag validation
            if flags & 0xFFFFFFFE:  # Only LSB should be set for basic flags
                corruption_indicators.append("Invalid flags")
            
            chunk.corruption_indicators = corruption_indicators
            
            return chunk
            
        except Exception as e:
            self.logger.debug(f"Windows chunk parsing failed: {e}")
            return None
    
    def _detect_windows_heap_corruption(self, arena: HeapArena) -> float:
        """Detect Windows heap corruption patterns"""
        corruption_score = 0.0
        
        try:
            total_chunks = len(arena.chunks)
            if total_chunks == 0:
                return 0.0
            
            corrupted_chunks = sum(1 for chunk in arena.chunks if chunk.is_corrupted)
            corruption_score += (corrupted_chunks / total_chunks) * 5.0
            
            # Check for heap spray patterns
            chunk_sizes = [chunk.size for chunk in arena.chunks]
            if NUMPY_AVAILABLE:
                size_std = np.std(chunk_sizes) if chunk_sizes else 0
                if size_std < 100:  # Very uniform sizes suggest spray
                    corruption_score += 2.0
            
            # Check for double-free patterns
            free_chunks = [chunk for chunk in arena.chunks if chunk.state == ChunkState.FREE]
            free_addresses = set()
            for chunk in free_chunks:
                if chunk.address in free_addresses:
                    corruption_score += 3.0  # Double-free detected
                free_addresses.add(chunk.address)
            
            return min(corruption_score, 10.0)
            
        except Exception as e:
            self.logger.debug(f"Windows heap corruption detection failed: {e}")
            return 0.0


class GlibcHeapAnalyzer:
    """Analyzer for glibc malloc heap structures"""
    
    def __init__(self):
        self.logger = logger.getChild("GlibcHeap")
    
    def analyze_heap(self, memory_data: bytes, base_address: int) -> HeapArena:
        """Analyze glibc heap structure"""
        try:
            arena = HeapArena(
                base_address=base_address,
                size=len(memory_data),
                heap_type=HeapType.GLIBC_HEAP
            )
            
            # Parse malloc_state structure (arena header)
            if len(memory_data) < 0x440:  # Size of malloc_state on x64
                return arena
            
            # Parse bins
            arena.bins = self._parse_glibc_bins(memory_data[:0x440])
            
            # Parse chunks in the heap
            current_offset = 0x440  # After arena header
            
            while current_offset < len(memory_data) - 16:
                chunk = self._parse_glibc_chunk(
                    memory_data[current_offset:],
                    base_address + current_offset
                )
                
                if chunk:
                    arena.chunks.append(chunk)
                    current_offset += chunk.size
                else:
                    current_offset += 16
                
                # Prevent infinite loops
                if len(arena.chunks) > 10000:
                    break
            
            # Detect corruption
            arena.corruption_score = self._detect_glibc_heap_corruption(arena)
            
            return arena
            
        except Exception as e:
            self.logger.error(f"Glibc heap analysis failed: {e}")
            return HeapArena(
                base_address=base_address,
                size=len(memory_data),
                heap_type=HeapType.GLIBC_HEAP
            )
    
    def _parse_glibc_bins(self, arena_data: bytes) -> List[HeapBin]:
        """Parse glibc bin structures"""
        bins = []
        
        try:
            # Parse fastbins (first 10 bins)
            for i in range(10):
                offset = 8 + (i * 8)  # 8 bytes per pointer on x64
                if offset + 8 <= len(arena_data):
                    bin_head = struct.unpack('<Q', arena_data[offset:offset + 8])[0]
                    
                    bin_obj = HeapBin(
                        index=i,
                        chunk_size=32 + (i * 16)  # Fastbin sizes
                    )
                    
                    # Follow bin linked list to get chunks
                    try:
                        # Parse linked list of chunks in this bin
                        current_chunk = bin_obj.get('fd', 0)
                        chunk_count = 0
                        while current_chunk != 0 and chunk_count < 100:  # Prevent infinite loops
                            chunk_data = self._parse_chunk_at_address(dump_data, current_chunk - base_addr)
                            if chunk_data:
                                bin_obj['chunks'].append(chunk_data)
                                current_chunk = chunk_data.get('fd', 0)
                            else:
                                break
                            chunk_count += 1
                    except:
                        pass  # Continue with bin even if chunk parsing fails
                    
                    bins.append(bin_obj)
            
            return bins
            
        except Exception as e:
            self.logger.debug(f"Glibc bin parsing failed: {e}")
            return []
    
    def _parse_glibc_chunk(self, chunk_data: bytes, address: int) -> Optional[HeapChunk]:
        """Parse a glibc malloc chunk"""
        try:
            if len(chunk_data) < 16:
                return None
            
            # Parse chunk header
            prev_size = struct.unpack('<Q', chunk_data[0:8])[0]
            size_and_flags = struct.unpack('<Q', chunk_data[8:16])[0]
            
            # Extract size and flags
            size = size_and_flags & ~0x7  # Clear last 3 bits
            flags = size_and_flags & 0x7
            
            # Validate size
            if size == 0 or size > 0x7FFFFFFF:
                return None
            
            # Determine chunk state
            state = ChunkState.ALLOCATED
            if flags & 0x1 == 0:  # PREV_INUSE flag not set means this chunk is free
                state = ChunkState.FREE
            
            chunk = HeapChunk(
                address=address,
                size=size,
                state=state,
                prev_size=prev_size,
                flags=flags,
                user_data_size=size - 16  # Subtract header
            )
            
            # Parse forward/backward pointers for free chunks
            if state == ChunkState.FREE and len(chunk_data) >= 32:
                chunk.fd = struct.unpack('<Q', chunk_data[16:24])[0]
                chunk.bk = struct.unpack('<Q', chunk_data[24:32])[0]
            
            # Check for corruption
            corruption_indicators = []
            
            # Size validation
            if size < 32 or size > 0x1000000:
                corruption_indicators.append("Invalid chunk size")
            
            # Alignment check (should be 16-byte aligned on x64)
            if size % 16 != 0:
                corruption_indicators.append("Chunk size not aligned")
            
            # Check for safe linking corruption (glibc 2.32+)
            if state == ChunkState.FREE and chunk.fd != 0:
                expected_safe_link = chunk.address >> 12
                if (chunk.fd >> 32) != expected_safe_link:
                    corruption_indicators.append("Safe linking corruption detected")
            
            chunk.corruption_indicators = corruption_indicators
            
            return chunk
            
        except Exception as e:
            self.logger.debug(f"Glibc chunk parsing failed: {e}")
            return None
    
    def _detect_glibc_heap_corruption(self, arena: HeapArena) -> float:
        """Detect glibc heap corruption patterns"""
        corruption_score = 0.0
        
        try:
            total_chunks = len(arena.chunks)
            if total_chunks == 0:
                return 0.0
            
            # Count corrupted chunks
            corrupted_chunks = sum(1 for chunk in arena.chunks if chunk.is_corrupted)
            corruption_score += (corrupted_chunks / total_chunks) * 5.0
            
            # Check for use-after-free patterns
            free_chunks = [chunk for chunk in arena.chunks if chunk.state == ChunkState.FREE]
            for chunk in free_chunks:
                # Check if fd/bk pointers point to valid heap addresses
                if chunk.fd != 0 and (chunk.fd < arena.base_address or 
                                     chunk.fd > arena.base_address + arena.size):
                    corruption_score += 2.0
                
                if chunk.bk != 0 and (chunk.bk < arena.base_address or 
                                     chunk.bk > arena.base_address + arena.size):
                    corruption_score += 2.0
            
            # Check for heap feng shui patterns
            allocated_chunks = [chunk for chunk in arena.chunks if chunk.state == ChunkState.ALLOCATED]
            if len(allocated_chunks) > 10:
                sizes = [chunk.size for chunk in allocated_chunks]
                if NUMPY_AVAILABLE:
                    # Look for patterns in allocation sizes
                    size_variance = np.var(sizes) if sizes else 0
                    if size_variance < 1000:  # Very uniform allocations
                        corruption_score += 1.5
            
            return min(corruption_score, 10.0)
            
        except Exception as e:
            self.logger.debug(f"Glibc heap corruption detection failed: {e}")
            return 0.0


class StackAnalyzer:
    """Analyzer for stack structures and corruption"""
    
    def __init__(self):
        self.logger = logger.getChild("StackAnalyzer")
    
    def analyze_stack(
        self, 
        memory_data: bytes, 
        stack_base: int, 
        stack_pointer: int,
        architecture: str = "x86_64"
    ) -> CallChain:
        """Analyze stack structure and reconstruct call chain"""
        try:
            call_chain = CallChain()
            
            # Determine pointer size based on architecture
            ptr_size = 8 if "64" in architecture else 4
            
            # Find stack frames
            frames = self._find_stack_frames(
                memory_data, stack_base, stack_pointer, ptr_size
            )
            
            call_chain.frames = frames
            
            # Detect corruption
            call_chain.corruption_detected = self._detect_stack_corruption(frames)
            
            # Detect ROP chains
            call_chain.rop_chain_detected, call_chain.gadgets_found = self._detect_rop_chain(
                memory_data, stack_base, ptr_size
            )
            
            return call_chain
            
        except Exception as e:
            self.logger.error(f"Stack analysis failed: {e}")
            return CallChain()
    
    def _find_stack_frames(
        self, 
        memory_data: bytes, 
        stack_base: int, 
        stack_pointer: int,
        ptr_size: int
    ) -> List[StackFrame]:
        """Find and parse stack frames"""
        frames = []
        
        try:
            # Calculate stack bounds
            stack_size = len(memory_data)
            current_sp = stack_pointer - stack_base
            
            if current_sp < 0 or current_sp >= stack_size:
                return frames
            
            # Walk the stack looking for valid frame pointers
            while current_sp < stack_size - ptr_size * 2:
                frame = self._parse_stack_frame(
                    memory_data[current_sp:], 
                    stack_base + current_sp,
                    ptr_size
                )
                
                if frame:
                    frames.append(frame)
                    
                    # Move to next frame
                    if frame.frame_pointer > stack_base + current_sp:
                        next_fp = frame.frame_pointer - stack_base
                        if next_fp < stack_size:
                            current_sp = next_fp
                        else:
                            break
                    else:
                        current_sp += ptr_size
                else:
                    current_sp += ptr_size
                
                # Limit frames to prevent infinite loops
                if len(frames) > 100:
                    break
            
            return frames
            
        except Exception as e:
            self.logger.debug(f"Stack frame finding failed: {e}")
            return []
    
    def _parse_stack_frame(
        self, 
        frame_data: bytes, 
        frame_address: int,
        ptr_size: int
    ) -> Optional[StackFrame]:
        """Parse a single stack frame"""
        try:
            if len(frame_data) < ptr_size * 2:
                return None
            
            # Parse frame pointer and return address
            if ptr_size == 8:
                frame_pointer = struct.unpack('<Q', frame_data[0:8])[0]
                return_address = struct.unpack('<Q', frame_data[8:16])[0]
            else:
                frame_pointer = struct.unpack('<I', frame_data[0:4])[0]
                return_address = struct.unpack('<I', frame_data[4:8])[0]
            
            # Validate addresses
            if return_address == 0 or frame_pointer == 0:
                return None
            
            frame = StackFrame(
                frame_pointer=frame_pointer,
                return_address=return_address,
                stack_pointer=frame_address
            )
            
            # Check for corruption indicators
            corruption_indicators = []
            
            # Check if return address looks like valid code
            if not self._is_valid_code_address(return_address):
                corruption_indicators.append("Invalid return address")
            
            # Check frame pointer alignment
            if ptr_size == 8 and frame_pointer % 8 != 0:
                corruption_indicators.append("Frame pointer not aligned")
            elif ptr_size == 4 and frame_pointer % 4 != 0:
                corruption_indicators.append("Frame pointer not aligned")
            
            # Check for stack canary corruption (simplified check)
            if len(frame_data) >= ptr_size * 4:
                canary_offset = ptr_size * 2
                if ptr_size == 8:
                    canary = struct.unpack('<Q', frame_data[canary_offset:canary_offset + 8])[0]
                    # Common stack canary patterns
                    if canary != 0 and canary != 0xdeadbeefdeadbeef:
                        # Check if it's been corrupted
                        if (canary & 0xFF) == 0x00:  # Canary should end with null
                            pass  # Valid canary
                        else:
                            corruption_indicators.append("Stack canary corruption")
            
            frame.corruption_indicators = corruption_indicators
            
            return frame
            
        except Exception as e:
            self.logger.debug(f"Stack frame parsing failed: {e}")
            return None
    
    def _is_valid_code_address(self, address: int) -> bool:
        """Check if address looks like valid code"""
        # Basic heuristics for valid code addresses
        
        # Null pointer
        if address == 0:
            return False
        
        # Common code section ranges
        valid_ranges = [
            (0x400000, 0x7FFFFFFFFFFF),  # User space on x64
            (0x8000000000000000, 0xFFFFFFFFFFFFFFFF),  # Kernel space on x64
            (0x10000, 0x7FFFFFFF),  # User space on x32
            (0x80000000, 0xFFFFFFFF),  # Kernel space on x32
        ]
        
        return any(start <= address <= end for start, end in valid_ranges)
    
    def _detect_stack_corruption(self, frames: List[StackFrame]) -> bool:
        """Detect stack corruption patterns"""
        try:
            # Check if any frame is corrupted
            if any(frame.is_corrupted for frame in frames):
                return True
            
            # Check for abnormal call patterns
            if len(frames) > 50:  # Unusually deep call stack
                return True
            
            # Check for repeated return addresses (possible spray)
            return_addresses = [frame.return_address for frame in frames]
            if len(set(return_addresses)) < len(return_addresses) // 2:
                return True  # Too many repeated addresses
            
            return False
            
        except Exception:
            return False
    
    def _detect_rop_chain(
        self, 
        memory_data: bytes, 
        stack_base: int,
        ptr_size: int
    ) -> Tuple[bool, List[Dict[str, Any]]]:
        """Detect ROP/JOP chain patterns"""
        try:
            gadgets = []
            
            # Scan stack for potential ROP gadgets
            for i in range(0, len(memory_data) - ptr_size, ptr_size):
                if ptr_size == 8:
                    addr = struct.unpack('<Q', memory_data[i:i + 8])[0]
                else:
                    addr = struct.unpack('<I', memory_data[i:i + 4])[0]
                
                # Check if address points to potential gadget
                if self._is_potential_gadget(addr):
                    gadgets.append({
                        'address': addr,
                        'stack_offset': i,
                        'type': 'rop_gadget'
                    })
            
            # Detect JOP chains (jump-oriented programming)
            jop_gadgets = self._detect_jop_gadgets(memory_data, ptr_size)
            gadgets.extend(jop_gadgets)
            
            # Consider it a ROP chain if we find multiple gadgets
            is_rop_chain = len(gadgets) > 5
            
            return is_rop_chain, gadgets
            
        except Exception as e:
            self.logger.debug(f"ROP chain detection failed: {e}")
            return False, []
    
    def _is_potential_gadget(self, address: int) -> bool:
        """Check if address could be a ROP gadget"""
        # Basic heuristics for ROP gadgets
        
        if not self._is_valid_code_address(address):
            return False
        
        # ROP gadgets often end in specific bytes
        # This is a simplified check - real implementation would
        # disassemble the code at the address
        
        addr_bytes = address.to_bytes(8, 'little')
        
        # Look for common gadget endings
        gadget_endings = [
            b'\xc3',        # RET
            b'\xc2\x00\x00', # RET imm16
            b'\xcb',        # RETF
            b'\xff\xe0',    # JMP EAX
            b'\xff\xe4',    # JMP ESP
        ]
        
        # This is a simplified check - would need actual disassembly
        return any(ending in addr_bytes for ending in gadget_endings)
    
    def _detect_jop_gadgets(self, memory_data: bytes, ptr_size: int) -> List[Dict[str, Any]]:
        """Detect jump-oriented programming gadgets"""
        jop_gadgets = []
        
        try:
            # Look for indirect jump patterns on stack
            for i in range(0, len(memory_data) - ptr_size * 2, ptr_size):
                if ptr_size == 8:
                    addr1 = struct.unpack('<Q', memory_data[i:i + 8])[0]
                    addr2 = struct.unpack('<Q', memory_data[i + 8:i + 16])[0]
                else:
                    addr1 = struct.unpack('<I', memory_data[i:i + 4])[0]
                    addr2 = struct.unpack('<I', memory_data[i + 4:i + 8])[0]
                
                # Check for JOP dispatch patterns
                if self._is_jop_dispatcher(addr1) and self._is_valid_code_address(addr2):
                    jop_gadgets.append({
                        'dispatcher': addr1,
                        'target': addr2,
                        'stack_offset': i,
                        'type': 'jop_gadget'
                    })
            
            return jop_gadgets
            
        except Exception:
            return []
    
    def _is_jop_dispatcher(self, address: int) -> bool:
        """Check if address could be a JOP dispatcher"""
        # Simplified JOP dispatcher detection
        # Real implementation would check for indirect jump instructions
        
        if not self._is_valid_code_address(address):
            return False
        
        # JOP dispatchers often have specific patterns
        # This is a placeholder - would need actual disassembly
        return address % 16 == 0  # Simplified heuristic


class MemoryCorruptionDetector:
    """Main class for detecting various memory corruption patterns"""
    
    def __init__(self):
        self.logger = logger.getChild("CorruptionDetector")
        self.windows_heap_analyzer = WindowsHeapAnalyzer()
        self.glibc_heap_analyzer = GlibcHeapAnalyzer()
        self.stack_analyzer = StackAnalyzer()
    
    def detect_corruption(
        self,
        memory_data: bytes,
        base_address: int,
        region_type: str,
        architecture: str = "x86_64"
    ) -> List[MemoryCorruption]:
        """
        Detect various types of memory corruption
        
        Args:
            memory_data: Memory region data
            base_address: Base address of the region
            region_type: Type of memory region (heap, stack, code, data)
            architecture: Target architecture
            
        Returns:
            List of detected corruption patterns
        """
        corruptions = []
        
        try:
            if region_type.lower() == "heap":
                corruptions.extend(self._detect_heap_corruption(
                    memory_data, base_address, architecture
                ))
            elif region_type.lower() == "stack":
                corruptions.extend(self._detect_stack_corruption(
                    memory_data, base_address, architecture
                ))
            
            # Always check for generic corruption patterns
            corruptions.extend(self._detect_generic_corruption(
                memory_data, base_address
            ))
            
            return corruptions
            
        except Exception as e:
            self.logger.error(f"Corruption detection failed: {e}")
            return []
    
    def _detect_heap_corruption(
        self,
        memory_data: bytes,
        base_address: int,
        architecture: str
    ) -> List[MemoryCorruption]:
        """Detect heap-specific corruption patterns"""
        corruptions = []
        
        try:
            # Try Windows heap analysis first
            windows_arena = self.windows_heap_analyzer.analyze_heap(memory_data, base_address)
            
            if windows_arena.corruption_score > 2.0:
                corruptions.append(MemoryCorruption(
                    corruption_type="heap_corruption",
                    address=base_address,
                    size=len(memory_data),
                    severity="medium" if windows_arena.corruption_score < 5.0 else "high",
                    description=f"Windows heap corruption detected (score: {windows_arena.corruption_score:.1f})",
                    evidence={
                        'heap_type': 'windows_nt_heap',
                        'corruption_score': windows_arena.corruption_score,
                        'corrupted_chunks': len([c for c in windows_arena.chunks if c.is_corrupted])
                    },
                    exploitability="medium"
                ))
            
            # Try glibc heap analysis
            glibc_arena = self.glibc_heap_analyzer.analyze_heap(memory_data, base_address)
            
            if glibc_arena.corruption_score > 2.0:
                corruptions.append(MemoryCorruption(
                    corruption_type="heap_corruption",
                    address=base_address,
                    size=len(memory_data),
                    severity="medium" if glibc_arena.corruption_score < 5.0 else "high",
                    description=f"Glibc heap corruption detected (score: {glibc_arena.corruption_score:.1f})",
                    evidence={
                        'heap_type': 'glibc_heap',
                        'corruption_score': glibc_arena.corruption_score,
                        'corrupted_chunks': len([c for c in glibc_arena.chunks if c.is_corrupted])
                    },
                    exploitability="high"
                ))
            
            return corruptions
            
        except Exception as e:
            self.logger.debug(f"Heap corruption detection failed: {e}")
            return []
    
    def _detect_stack_corruption(
        self,
        memory_data: bytes,
        base_address: int,
        architecture: str
    ) -> List[MemoryCorruption]:
        """Detect stack-specific corruption patterns"""
        corruptions = []
        
        try:
            # Analyze stack assuming SP is at the beginning
            call_chain = self.stack_analyzer.analyze_stack(
                memory_data, base_address, base_address, architecture
            )
            
            if call_chain.corruption_detected:
                corruptions.append(MemoryCorruption(
                    corruption_type="stack_corruption",
                    address=base_address,
                    size=len(memory_data),
                    severity="high",
                    description="Stack corruption detected in call chain",
                    evidence={
                        'corrupted_frames': len([f for f in call_chain.frames if f.is_corrupted]),
                        'total_frames': len(call_chain.frames)
                    },
                    exploitability="high"
                ))
            
            if call_chain.rop_chain_detected:
                corruptions.append(MemoryCorruption(
                    corruption_type="rop_chain",
                    address=base_address,
                    size=len(memory_data),
                    severity="critical",
                    description="ROP/JOP chain detected on stack",
                    evidence={
                        'gadgets_found': len(call_chain.gadgets_found),
                        'gadget_details': call_chain.gadgets_found[:10]  # Limit details
                    },
                    exploitability="high"
                ))
            
            return corruptions
            
        except Exception as e:
            self.logger.debug(f"Stack corruption detection failed: {e}")
            return []
    
    def _detect_generic_corruption(
        self,
        memory_data: bytes,
        base_address: int
    ) -> List[MemoryCorruption]:
        """Detect generic corruption patterns"""
        corruptions = []
        
        try:
            # Check for buffer overflow patterns
            overflow_patterns = [
                b'AAAA' * 10,  # Classic overflow
                b'\x41' * 40,  # 'A' pattern
                b'\x90' * 20,  # NOP sled
            ]
            
            for pattern in overflow_patterns:
                if pattern in memory_data:
                    offset = memory_data.find(pattern)
                    corruptions.append(MemoryCorruption(
                        corruption_type="buffer_overflow",
                        address=base_address + offset,
                        size=len(pattern),
                        severity="medium",
                        description=f"Buffer overflow pattern detected: {pattern.hex()}",
                        evidence={'pattern': pattern.hex(), 'offset': offset},
                        exploitability="medium"
                    ))
            
            # Check for format string vulnerabilities
            format_patterns = [
                b'%x%x%x%x',
                b'%s%s%s%s',
                b'%n%n%n%n',
            ]
            
            for pattern in format_patterns:
                if pattern in memory_data:
                    offset = memory_data.find(pattern)
                    corruptions.append(MemoryCorruption(
                        corruption_type="format_string",
                        address=base_address + offset,
                        size=len(pattern),
                        severity="high",
                        description="Format string vulnerability pattern detected",
                        evidence={'pattern': pattern.hex(), 'offset': offset},
                        exploitability="high"
                    ))
            
            # Check for use-after-free patterns
            uaf_patterns = [
                b'\xfe\xee\xfe\xee',  # Common freed memory pattern
                b'\xde\xad\xbe\xef',  # Another common pattern
            ]
            
            for pattern in uaf_patterns:
                if pattern in memory_data:
                    offset = memory_data.find(pattern)
                    corruptions.append(MemoryCorruption(
                        corruption_type="use_after_free",
                        address=base_address + offset,
                        size=len(pattern),
                        severity="high",
                        description="Use-after-free pattern detected",
                        evidence={'pattern': pattern.hex(), 'offset': offset},
                        exploitability="high"
                    ))
            
            return corruptions
            
        except Exception as e:
            self.logger.debug(f"Generic corruption detection failed: {e}")
            return []


# Factory functions for easy integration
def analyze_heap_structure(
    memory_data: bytes,
    base_address: int,
    heap_type: str = "auto"
) -> HeapArena:
    """Analyze heap structure with automatic type detection"""
    if heap_type == "windows" or heap_type == "auto":
        analyzer = WindowsHeapAnalyzer()
        result = analyzer.analyze_heap(memory_data, base_address)
        if result.chunks:  # If we found chunks, return Windows result
            return result
    
    if heap_type == "glibc" or heap_type == "auto":
        analyzer = GlibcHeapAnalyzer()
        return analyzer.analyze_heap(memory_data, base_address)
    
    # Default empty arena
    return HeapArena(
        base_address=base_address,
        size=len(memory_data),
        heap_type=HeapType.UNKNOWN
    )


def analyze_stack_structure(
    memory_data: bytes,
    stack_base: int,
    stack_pointer: int,
    architecture: str = "x86_64"
) -> CallChain:
    """Analyze stack structure and call chain"""
    analyzer = StackAnalyzer()
    return analyzer.analyze_stack(memory_data, stack_base, stack_pointer, architecture)


def detect_memory_corruption(
    memory_data: bytes,
    base_address: int,
    region_type: str = "unknown",
    architecture: str = "x86_64"
) -> List[MemoryCorruption]:
    """Detect memory corruption patterns"""
    detector = MemoryCorruptionDetector()
    return detector.detect_corruption(memory_data, base_address, region_type, architecture)