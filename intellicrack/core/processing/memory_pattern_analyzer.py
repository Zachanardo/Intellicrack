"""
Memory Pattern Analyzer - Advanced memory access pattern analysis.

This module provides sophisticated analysis of memory access patterns to detect
self-modifying code, heap sprays, ROP chains, and other memory-based attack techniques.

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

import ctypes
import mmap
import os
import psutil
import re
import struct
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple
import logging

try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

try:
    import win32api
    import win32process
    import win32con
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False

from intellicrack.logger import logger


class MemoryAccessType(Enum):
    """Types of memory access."""
    READ = auto()
    WRITE = auto()
    EXECUTE = auto()
    ALLOCATE = auto()
    FREE = auto()
    PROTECT = auto()


class MemoryRegionType(Enum):
    """Types of memory regions."""
    STACK = auto()
    HEAP = auto()
    CODE = auto()
    DATA = auto()
    SHARED = auto()
    MAPPED = auto()
    UNKNOWN = auto()


@dataclass
class MemoryAccess:
    """Represents a memory access event."""
    timestamp: float
    process_id: int
    thread_id: int
    access_type: MemoryAccessType
    address: int
    size: int
    value: Optional[bytes] = None
    protection: Optional[int] = None
    region_type: Optional[MemoryRegionType] = None
    call_stack: List[int] = field(default_factory=list)


@dataclass
class MemoryRegion:
    """Represents a memory region."""
    base_address: int
    size: int
    protection: int
    region_type: MemoryRegionType
    allocation_time: float
    last_access: Optional[float] = None
    access_count: int = 0
    modification_count: int = 0
    is_executable: bool = False
    is_writable: bool = False
    content_hash: Optional[str] = None


@dataclass
class SuspiciousPattern:
    """Represents a suspicious memory pattern."""
    pattern_type: str
    description: str
    confidence: float
    addresses: List[int]
    evidence: Dict[str, Any]
    timestamp: float
    severity: str = "medium"


class MemoryPatternAnalyzer:
    """
    Advanced memory pattern analyzer for detecting sophisticated memory-based attacks.
    
    This analyzer monitors memory access patterns, detects code injection,
    heap sprays, ROP chains, and other memory-based exploitation techniques.
    """

    def __init__(self, process_id: int):
        """
        Initialize memory pattern analyzer.
        
        Args:
            process_id: Target process to analyze
        """
        self.process_id = process_id
        self.logger = logging.getLogger(__name__)
        
        # Memory tracking
        self.memory_regions: Dict[int, MemoryRegion] = {}
        self.memory_accesses: deque = deque(maxlen=50000)
        self.code_modifications: List[Dict[str, Any]] = []
        
        # Pattern detection
        self.heap_spray_threshold = 1000  # Number of similar allocations
        self.rop_chain_threshold = 20     # Minimum gadget count
        self.shellcode_patterns = self._load_shellcode_patterns()
        
        # Analysis state
        self.is_analyzing = False
        self.analysis_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        
        # Performance optimization
        self.analysis_interval = 1.0  # seconds
        self.last_analysis = time.time()
        
        # Platform-specific initialization
        if os.name == 'nt' and WIN32_AVAILABLE:
            self._initialize_windows_memory_analysis()
        else:
            self._initialize_linux_memory_analysis()

    def _initialize_windows_memory_analysis(self):
        """Initialize Windows-specific memory analysis."""
        try:
            # Open process handle
            self.process_handle = win32api.OpenProcess(
                win32con.PROCESS_QUERY_INFORMATION | 
                win32con.PROCESS_VM_READ |
                win32con.PROCESS_VM_OPERATION,
                False,
                self.process_id
            )
            
            # Get initial memory layout
            self._scan_initial_memory_layout()
            
            self.logger.info(f"Windows memory analysis initialized for PID {self.process_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Windows memory analysis: {e}")

    def _initialize_linux_memory_analysis(self):
        """Initialize Linux-specific memory analysis."""
        try:
            # Check if we can access /proc/pid/maps
            maps_path = f"/proc/{self.process_id}/maps"
            if not os.path.exists(maps_path):
                raise FileNotFoundError(f"Process maps not accessible: {maps_path}")
            
            # Get initial memory layout
            self._scan_initial_memory_layout()
            
            self.logger.info(f"Linux memory analysis initialized for PID {self.process_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Linux memory analysis: {e}")

    def start_analysis(self) -> bool:
        """
        Start memory pattern analysis.
        
        Returns:
            True if analysis started successfully
        """
        if self.is_analyzing:
            self.logger.warning("Memory analysis already running")
            return True

        try:
            self.stop_event.clear()
            self.is_analyzing = True
            
            # Start analysis thread
            self.analysis_thread = threading.Thread(
                target=self._analysis_loop,
                daemon=True
            )
            self.analysis_thread.start()
            
            self.logger.info("Memory pattern analysis started")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start memory analysis: {e}")
            self.is_analyzing = False
            return False

    def stop_analysis(self) -> Dict[str, Any]:
        """
        Stop memory analysis and return results.
        
        Returns:
            Dictionary containing analysis results
        """
        if not self.is_analyzing:
            return self._get_current_results()

        try:
            self.stop_event.set()
            self.is_analyzing = False
            
            if self.analysis_thread and self.analysis_thread.is_alive():
                self.analysis_thread.join(timeout=5.0)
            
            results = self._get_current_results()
            self.logger.info("Memory pattern analysis stopped")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error stopping memory analysis: {e}")
            return self._get_current_results()

    def _analysis_loop(self):
        """Main analysis loop."""
        try:
            while not self.stop_event.is_set():
                current_time = time.time()
                
                # Periodic memory scan
                if current_time - self.last_analysis >= self.analysis_interval:
                    self._perform_memory_scan()
                    self._detect_suspicious_patterns()
                    self.last_analysis = current_time
                
                # Short sleep to prevent CPU overload
                time.sleep(0.1)
                
        except Exception as e:
            self.logger.error(f"Error in memory analysis loop: {e}")

    def _perform_memory_scan(self):
        """Perform memory scan to detect changes."""
        try:
            if os.name == 'nt':
                self._scan_windows_memory()
            else:
                self._scan_linux_memory()
                
        except Exception as e:
            self.logger.error(f"Error performing memory scan: {e}")

    def _scan_windows_memory(self):
        """Scan Windows process memory."""
        try:
            import win32api
            import win32con
            
            # Query memory regions
            address = 0
            while address < 0x7FFFFFFFFFFFFFFF:
                try:
                    mbi = win32api.VirtualQueryEx(self.process_handle, address)
                    
                    if mbi[1] != 0:  # Region size > 0
                        region_base = mbi[0]
                        region_size = mbi[1]
                        protection = mbi[2]
                        
                        # Check if this is a new or modified region
                        if region_base not in self.memory_regions:
                            self._handle_new_memory_region(region_base, region_size, protection)
                        else:
                            self._check_region_modifications(region_base, region_size, protection)
                        
                        address = region_base + region_size
                    else:
                        address += 0x1000  # Move to next page
                        
                except Exception:
                    address += 0x1000
                    continue
                    
        except Exception as e:
            self.logger.error(f"Error scanning Windows memory: {e}")

    def _scan_linux_memory(self):
        """Scan Linux process memory via /proc."""
        try:
            maps_path = f"/proc/{self.process_id}/maps"
            
            with open(maps_path, 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) < 2:
                        continue
                    
                    # Parse address range
                    addr_range = parts[0]
                    start_addr, end_addr = addr_range.split('-')
                    start_addr = int(start_addr, 16)
                    end_addr = int(end_addr, 16)
                    size = end_addr - start_addr
                    
                    # Parse permissions
                    perms = parts[1]
                    protection = self._parse_linux_permissions(perms)
                    
                    # Check if this is a new region
                    if start_addr not in self.memory_regions:
                        self._handle_new_memory_region(start_addr, size, protection)
                    else:
                        self._check_region_modifications(start_addr, size, protection)
                        
        except Exception as e:
            self.logger.error(f"Error scanning Linux memory: {e}")

    def _handle_new_memory_region(self, base_address: int, size: int, protection: int):
        """Handle discovery of new memory region."""
        try:
            region_type = self._classify_memory_region(base_address, size, protection)
            
            region = MemoryRegion(
                base_address=base_address,
                size=size,
                protection=protection,
                region_type=region_type,
                allocation_time=time.time(),
                is_executable=(protection & 0x20) != 0,  # PAGE_EXECUTE
                is_writable=(protection & 0x04) != 0     # PAGE_READWRITE
            )
            
            self.memory_regions[base_address] = region
            
            # Check for suspicious allocations
            if region.is_executable and region.is_writable:
                self._detect_rwx_allocation(region)
            
            if region.region_type == MemoryRegionType.HEAP:
                self._check_heap_spray(region)
                
        except Exception as e:
            self.logger.error(f"Error handling new memory region: {e}")

    def _check_region_modifications(self, base_address: int, size: int, protection: int):
        """Check for modifications to existing memory region."""
        try:
            if base_address not in self.memory_regions:
                return
            
            region = self.memory_regions[base_address]
            
            # Check for protection changes
            if region.protection != protection:
                self._handle_protection_change(region, protection)
            
            # Update access time
            region.last_access = time.time()
            region.access_count += 1
            
            # Check for code modifications in executable regions
            if region.is_executable:
                self._check_code_modifications(region)
                
        except Exception as e:
            self.logger.error(f"Error checking region modifications: {e}")

    def _handle_protection_change(self, region: MemoryRegion, new_protection: int):
        """Handle memory protection changes."""
        try:
            old_protection = region.protection
            region.protection = new_protection
            
            # Update flags
            region.is_executable = (new_protection & 0x20) != 0
            region.is_writable = (new_protection & 0x04) != 0
            
            # Detect suspicious protection changes
            if not (old_protection & 0x20) and (new_protection & 0x20):
                # Memory became executable
                self._detect_code_injection(region)
            
            if (old_protection & 0x04) and not (new_protection & 0x04):
                # Memory became non-writable (possible code finalization)
                self._detect_code_finalization(region)
                
        except Exception as e:
            self.logger.error(f"Error handling protection change: {e}")

    def _detect_suspicious_patterns(self):
        """Detect various suspicious memory patterns."""
        try:
            self._detect_heap_spray_patterns()
            self._detect_rop_chains()
            self._detect_shellcode_patterns()
            self._detect_code_caves()
            self._detect_return_address_overwrites()
            
        except Exception as e:
            self.logger.error(f"Error detecting suspicious patterns: {e}")

    def _detect_heap_spray_patterns(self):
        """Detect heap spray attacks."""
        try:
            heap_regions = [r for r in self.memory_regions.values() 
                           if r.region_type == MemoryRegionType.HEAP]
            
            if len(heap_regions) > self.heap_spray_threshold:
                # Check for similar-sized allocations
                size_groups = defaultdict(list)
                for region in heap_regions:
                    size_groups[region.size].append(region)
                
                for size, regions in size_groups.items():
                    if len(regions) > 100:  # Many allocations of same size
                        pattern = SuspiciousPattern(
                            pattern_type="heap_spray",
                            description=f"Possible heap spray: {len(regions)} allocations of size {size}",
                            confidence=0.8,
                            addresses=[r.base_address for r in regions],
                            evidence={
                                'allocation_count': len(regions),
                                'allocation_size': size,
                                'total_memory': len(regions) * size
                            },
                            timestamp=time.time(),
                            severity="high"
                        )
                        self._record_suspicious_pattern(pattern)
                        
        except Exception as e:
            self.logger.error(f"Error detecting heap spray: {e}")

    def _detect_rop_chains(self):
        """Detect ROP (Return-Oriented Programming) chains."""
        try:
            if not CAPSTONE_AVAILABLE:
                return
            
            # Look for sequences of short code gadgets
            executable_regions = [r for r in self.memory_regions.values() 
                                 if r.is_executable]
            
            for region in executable_regions:
                gadgets = self._find_rop_gadgets(region)
                
                if len(gadgets) > self.rop_chain_threshold:
                    pattern = SuspiciousPattern(
                        pattern_type="rop_chain",
                        description=f"Possible ROP chain: {len(gadgets)} gadgets found",
                        confidence=0.7,
                        addresses=[g['address'] for g in gadgets],
                        evidence={
                            'gadget_count': len(gadgets),
                            'gadgets': gadgets[:20]  # Limit for storage
                        },
                        timestamp=time.time(),
                        severity="high"
                    )
                    self._record_suspicious_pattern(pattern)
                    
        except Exception as e:
            self.logger.error(f"Error detecting ROP chains: {e}")

    def _find_rop_gadgets(self, region: MemoryRegion) -> List[Dict[str, Any]]:
        """Find ROP gadgets in memory region."""
        gadgets = []
        
        try:
            if not CAPSTONE_AVAILABLE:
                return gadgets
            
            # Read memory content
            memory_content = self._read_memory_region(region)
            if not memory_content:
                return gadgets
            
            # Disassemble with Capstone
            if os.name == 'nt':
                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            else:
                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            
            md.detail = True
            
            instructions = list(md.disasm(memory_content, region.base_address))
            
            # Look for ROP gadget patterns
            for i, insn in enumerate(instructions):
                # Check for ret instruction
                if insn.mnemonic == 'ret':
                    # Look backwards for useful instructions
                    gadget_instructions = []
                    for j in range(max(0, i-5), i+1):
                        gadget_instructions.append({
                            'address': instructions[j].address,
                            'mnemonic': instructions[j].mnemonic,
                            'op_str': instructions[j].op_str
                        })
                    
                    if len(gadget_instructions) > 1:
                        gadgets.append({
                            'address': instructions[max(0, i-5)].address,
                            'length': i - max(0, i-5) + 1,
                            'instructions': gadget_instructions
                        })
                        
        except Exception as e:
            self.logger.error(f"Error finding ROP gadgets: {e}")
        
        return gadgets

    def _detect_shellcode_patterns(self):
        """Detect shellcode patterns in memory."""
        try:
            for region in self.memory_regions.values():
                if region.is_executable:
                    content = self._read_memory_region(region)
                    if content:
                        shellcode_matches = self._scan_for_shellcode(content, region.base_address)
                        
                        if shellcode_matches:
                            pattern = SuspiciousPattern(
                                pattern_type="shellcode",
                                description=f"Possible shellcode detected: {len(shellcode_matches)} patterns",
                                confidence=0.85,
                                addresses=[m['address'] for m in shellcode_matches],
                                evidence={
                                    'matches': shellcode_matches,
                                    'region_size': region.size
                                },
                                timestamp=time.time(),
                                severity="critical"
                            )
                            self._record_suspicious_pattern(pattern)
                            
        except Exception as e:
            self.logger.error(f"Error detecting shellcode: {e}")

    def _scan_for_shellcode(self, content: bytes, base_address: int) -> List[Dict[str, Any]]:
        """Scan memory content for shellcode patterns."""
        matches = []
        
        try:
            # Common shellcode patterns
            for pattern_name, pattern_bytes in self.shellcode_patterns.items():
                offset = 0
                while True:
                    index = content.find(pattern_bytes, offset)
                    if index == -1:
                        break
                    
                    matches.append({
                        'pattern': pattern_name,
                        'address': base_address + index,
                        'size': len(pattern_bytes)
                    })
                    
                    offset = index + 1
                    
        except Exception as e:
            self.logger.error(f"Error scanning for shellcode: {e}")
        
        return matches

    def _detect_code_caves(self):
        """Detect code caves (unused executable memory spaces)."""
        try:
            for region in self.memory_regions.values():
                if region.is_executable:
                    content = self._read_memory_region(region)
                    if content:
                        caves = self._find_code_caves(content, region.base_address)
                        
                        if caves:
                            pattern = SuspiciousPattern(
                                pattern_type="code_cave",
                                description=f"Code caves detected: {len(caves)} caves",
                                confidence=0.6,
                                addresses=[c['address'] for c in caves],
                                evidence={'caves': caves},
                                timestamp=time.time(),
                                severity="medium"
                            )
                            self._record_suspicious_pattern(pattern)
                            
        except Exception as e:
            self.logger.error(f"Error detecting code caves: {e}")

    def _find_code_caves(self, content: bytes, base_address: int) -> List[Dict[str, Any]]:
        """Find code caves in executable memory."""
        caves = []
        
        try:
            # Look for sequences of null bytes or NOPs
            null_pattern = b'\x00' * 16  # 16+ null bytes
            nop_pattern = b'\x90' * 8    # 8+ NOP instructions
            
            for pattern_name, pattern in [('null_cave', null_pattern), ('nop_cave', nop_pattern)]:
                offset = 0
                while True:
                    index = content.find(pattern, offset)
                    if index == -1:
                        break
                    
                    # Find the full extent of the cave
                    cave_start = index
                    cave_end = index + len(pattern)
                    
                    # Extend backwards
                    while cave_start > 0 and content[cave_start - 1] == pattern[0]:
                        cave_start -= 1
                    
                    # Extend forwards
                    while cave_end < len(content) and content[cave_end] == pattern[0]:
                        cave_end += 1
                    
                    cave_size = cave_end - cave_start
                    if cave_size >= 32:  # Minimum cave size
                        caves.append({
                            'type': pattern_name,
                            'address': base_address + cave_start,
                            'size': cave_size
                        })
                    
                    offset = cave_end
                    
        except Exception as e:
            self.logger.error(f"Error finding code caves: {e}")
        
        return caves

    def _detect_return_address_overwrites(self):
        """Detect potential return address overwrites."""
        try:
            # This would require stack monitoring and call/ret tracking
            # Implementation would depend on hooking mechanism
            pass
            
        except Exception as e:
            self.logger.error(f"Error detecting return address overwrites: {e}")

    def _read_memory_region(self, region: MemoryRegion) -> Optional[bytes]:
        """Read memory content from region."""
        try:
            if os.name == 'nt' and WIN32_AVAILABLE:
                return self._read_windows_memory(region.base_address, region.size)
            else:
                return self._read_linux_memory(region.base_address, region.size)
                
        except Exception as e:
            self.logger.error(f"Error reading memory region: {e}")
            return None

    def _read_windows_memory(self, address: int, size: int) -> Optional[bytes]:
        """Read Windows process memory."""
        try:
            import win32api
            return win32api.ReadProcessMemory(self.process_handle, address, size)
            
        except Exception as e:
            self.logger.debug(f"Could not read Windows memory at {hex(address)}: {e}")
            return None

    def _read_linux_memory(self, address: int, size: int) -> Optional[bytes]:
        """Read Linux process memory via /proc/pid/mem."""
        try:
            mem_path = f"/proc/{self.process_id}/mem"
            
            with open(mem_path, 'rb') as f:
                f.seek(address)
                return f.read(size)
                
        except Exception as e:
            self.logger.debug(f"Could not read Linux memory at {hex(address)}: {e}")
            return None

    def _load_shellcode_patterns(self) -> Dict[str, bytes]:
        """Load common shellcode patterns."""
        return {
            'nop_sled': b'\x90\x90\x90\x90',
            'xor_eax': b'\x31\xc0',
            'xor_ebx': b'\x31\xdb',
            'xor_ecx': b'\x31\xc9',
            'xor_edx': b'\x31\xd2',
            'push_pop': b'\x50\x58',
            'infinite_loop': b'\xeb\xfe',
            'call_next': b'\xe8\x00\x00\x00\x00',
            'win32_api': b'\x64\x8b\x15\x30\x00\x00\x00',  # TEB access
            'stack_pivot': b'\x94\x94\x94',  # Multiple XCHG EAX,ESP
        }

    def _classify_memory_region(self, base_address: int, size: int, protection: int) -> MemoryRegionType:
        """Classify memory region type."""
        try:
            # Simple heuristics for region classification
            if protection & 0x20:  # PAGE_EXECUTE
                return MemoryRegionType.CODE
            elif base_address < 0x10000:  # Low memory
                return MemoryRegionType.DATA
            elif size > 0x100000:  # Large allocation
                return MemoryRegionType.MAPPED
            else:
                return MemoryRegionType.HEAP
                
        except Exception:
            return MemoryRegionType.UNKNOWN

    def _parse_linux_permissions(self, perms: str) -> int:
        """Parse Linux memory permissions to protection flags."""
        protection = 0
        
        if 'r' in perms:
            protection |= 0x02  # PAGE_READONLY
        if 'w' in perms:
            protection |= 0x04  # PAGE_READWRITE
        if 'x' in perms:
            protection |= 0x20  # PAGE_EXECUTE
            
        return protection

    def _record_suspicious_pattern(self, pattern: SuspiciousPattern):
        """Record a suspicious memory pattern."""
        self.logger.warning(f"Suspicious pattern detected: {pattern.pattern_type} - {pattern.description}")
        # Could be stored in database or sent to monitoring system

    def _get_current_results(self) -> Dict[str, Any]:
        """Get current analysis results."""
        return {
            'memory_regions': len(self.memory_regions),
            'executable_regions': len([r for r in self.memory_regions.values() if r.is_executable]),
            'writable_executable_regions': len([r for r in self.memory_regions.values() 
                                              if r.is_executable and r.is_writable]),
            'total_memory': sum(r.size for r in self.memory_regions.values()),
            'code_modifications': len(self.code_modifications),
            'analysis_duration': time.time() - min(r.allocation_time for r in self.memory_regions.values()) 
                                if self.memory_regions else 0
        }

    # Additional helper methods for specific detection techniques
    def _detect_rwx_allocation(self, region: MemoryRegion):
        """Detect suspicious RWX memory allocation."""
        pattern = SuspiciousPattern(
            pattern_type="rwx_allocation",
            description="Memory region allocated with Read+Write+Execute permissions",
            confidence=0.9,
            addresses=[region.base_address],
            evidence={
                'size': region.size,
                'protection': region.protection
            },
            timestamp=time.time(),
            severity="high"
        )
        self._record_suspicious_pattern(pattern)

    def _check_heap_spray(self, region: MemoryRegion):
        """Check for heap spray patterns."""
        heap_regions = [r for r in self.memory_regions.values() 
                       if r.region_type == MemoryRegionType.HEAP]
        
        # Check for many similar-sized allocations
        similar_size_count = len([r for r in heap_regions 
                                 if abs(r.size - region.size) < 0x1000])
        
        if similar_size_count > 50:
            pattern = SuspiciousPattern(
                pattern_type="potential_heap_spray",
                description=f"Many similar-sized heap allocations: {similar_size_count}",
                confidence=0.7,
                addresses=[r.base_address for r in heap_regions if abs(r.size - region.size) < 0x1000],
                evidence={
                    'allocation_size': region.size,
                    'similar_count': similar_size_count
                },
                timestamp=time.time(),
                severity="medium"
            )
            self._record_suspicious_pattern(pattern)

    def _detect_code_injection(self, region: MemoryRegion):
        """Detect code injection via protection change."""
        pattern = SuspiciousPattern(
            pattern_type="code_injection",
            description="Memory region became executable (possible code injection)",
            confidence=0.85,
            addresses=[region.base_address],
            evidence={
                'size': region.size,
                'allocation_time': region.allocation_time
            },
            timestamp=time.time(),
            severity="critical"
        )
        self._record_suspicious_pattern(pattern)

    def _detect_code_finalization(self, region: MemoryRegion):
        """Detect code finalization (write protection removal)."""
        pattern = SuspiciousPattern(
            pattern_type="code_finalization",
            description="Executable memory became non-writable (possible code finalization)",
            confidence=0.7,
            addresses=[region.base_address],
            evidence={
                'size': region.size,
                'modification_count': region.modification_count
            },
            timestamp=time.time(),
            severity="medium"
        )
        self._record_suspicious_pattern(pattern)

    def _check_code_modifications(self, region: MemoryRegion):
        """Check for modifications to executable code."""
        try:
            current_content = self._read_memory_region(region)
            if not current_content:
                return
            
            # Calculate content hash
            import hashlib
            current_hash = hashlib.md5(current_content).hexdigest()
            
            if region.content_hash is None:
                region.content_hash = current_hash
            elif region.content_hash != current_hash:
                # Code has been modified
                region.modification_count += 1
                region.content_hash = current_hash
                
                modification = {
                    'timestamp': time.time(),
                    'region_address': region.base_address,
                    'region_size': region.size,
                    'modification_count': region.modification_count
                }
                self.code_modifications.append(modification)
                
                pattern = SuspiciousPattern(
                    pattern_type="code_modification",
                    description="Executable code has been modified",
                    confidence=0.9,
                    addresses=[region.base_address],
                    evidence=modification,
                    timestamp=time.time(),
                    severity="high"
                )
                self._record_suspicious_pattern(pattern)
                
        except Exception as e:
            self.logger.error(f"Error checking code modifications: {e}")

    def _scan_initial_memory_layout(self):
        """Scan initial memory layout of the process."""
        try:
            # Get initial snapshot
            if os.name == 'nt':
                self._scan_windows_memory()
            else:
                self._scan_linux_memory()
                
            self.logger.info(f"Initial memory scan completed: {len(self.memory_regions)} regions")
            
        except Exception as e:
            self.logger.error(f"Error scanning initial memory layout: {e}")

    def get_memory_statistics(self) -> Dict[str, Any]:
        """Get comprehensive memory statistics."""
        try:
            total_memory = sum(r.size for r in self.memory_regions.values())
            executable_memory = sum(r.size for r in self.memory_regions.values() if r.is_executable)
            writable_memory = sum(r.size for r in self.memory_regions.values() if r.is_writable)
            rwx_memory = sum(r.size for r in self.memory_regions.values() 
                           if r.is_executable and r.is_writable)
            
            region_types = defaultdict(int)
            for region in self.memory_regions.values():
                region_types[region.region_type.name] += 1
            
            return {
                'total_regions': len(self.memory_regions),
                'total_memory': total_memory,
                'executable_memory': executable_memory,
                'writable_memory': writable_memory,
                'rwx_memory': rwx_memory,
                'region_types': dict(region_types),
                'code_modifications': len(self.code_modifications),
                'memory_accesses': len(self.memory_accesses)
            }
            
        except Exception as e:
            self.logger.error(f"Error getting memory statistics: {e}")
            return {}