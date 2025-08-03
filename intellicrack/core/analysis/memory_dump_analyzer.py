"""
Comprehensive Memory Dump Analysis System

Advanced memory dump analysis capabilities for various formats including QEMU snapshots,
Windows crash dumps, VMware memory dumps, process dumps, and custom binary formats.
Provides deep analysis of memory structures, code patterns, and forensic artifacts.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import hashlib
import json
import logging
import os
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from ...utils.logger import get_logger
from .memory_forensics_engine import MemoryForensicsEngine, MemoryAnalysisResult

logger = get_logger(__name__)

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    logger.warning("NumPy not available - advanced memory analysis features limited")

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False
    logger.warning("Capstone not available - disassembly features disabled")

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logger.warning("YARA not available - pattern matching limited")


class MemoryDumpFormat(Enum):
    """Supported memory dump formats"""
    RAW_MEMORY = "raw_memory"
    QEMU_SNAPSHOT = "qemu_snapshot"
    WINDOWS_CRASH_DUMP = "windows_crash_dump"
    WINDOWS_MINIDUMP = "windows_minidump"
    VMWARE_VMEM = "vmware_vmem"
    LINUX_CORE_DUMP = "linux_core_dump"
    HYPERV_SAVE_STATE = "hyperv_save_state"
    VIRTUALBOX_SAVE_STATE = "virtualbox_save_state"
    CUSTOM_BINARY = "custom_binary"
    UNKNOWN = "unknown"


class MemoryArchitecture(Enum):
    """Memory dump architectures"""
    X86_32 = "x86_32"
    X86_64 = "x86_64"
    ARM_32 = "arm_32"
    ARM_64 = "arm_64"
    MIPS_32 = "mips_32"
    MIPS_64 = "mips_64"
    UNKNOWN = "unknown"


class MemoryRegionType(Enum):
    """Types of memory regions"""
    CODE = "code"
    DATA = "data"
    HEAP = "heap"
    STACK = "stack"
    SHARED_LIBRARY = "shared_library"
    KERNEL_CODE = "kernel_code"
    KERNEL_DATA = "kernel_data"
    DEVICE_MEMORY = "device_memory"
    RESERVED = "reserved"
    FREE = "free"
    GUARD_PAGE = "guard_page"
    UNKNOWN = "unknown"


@dataclass
class MemoryPage:
    """Individual memory page information"""
    virtual_address: int
    physical_address: int = 0
    size: int = 4096
    permissions: str = ""
    page_type: MemoryRegionType = MemoryRegionType.UNKNOWN
    present: bool = True
    dirty: bool = False
    accessed: bool = False
    executable: bool = False
    writable: bool = False
    user_accessible: bool = True
    content_hash: str = ""
    entropy: float = 0.0
    strings_count: int = 0
    suspicious_patterns: List[str] = field(default_factory=list)


@dataclass
class MemoryRegion:
    """Memory region containing multiple pages"""
    start_address: int
    end_address: int
    size: int
    region_type: MemoryRegionType
    permissions: str
    protection: str = ""
    mapped_file: str = ""
    pages: List[MemoryPage] = field(default_factory=list)
    disassembly: List[Dict[str, Any]] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    patterns_found: List[str] = field(default_factory=list)
    entropy_analysis: Dict[str, Any] = field(default_factory=dict)
    code_analysis: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_executable(self) -> bool:
        """Check if region is executable"""
        return 'x' in self.permissions.lower() or self.region_type == MemoryRegionType.CODE

    @property
    def is_writable(self) -> bool:
        """Check if region is writable"""
        return 'w' in self.permissions.lower()

    @property
    def has_shellcode_characteristics(self) -> bool:
        """Check if region shows shellcode characteristics"""
        return (
            self.is_executable and
            self.entropy_analysis.get('entropy', 0) > 6.0 and
            len(self.patterns_found) > 0
        )


@dataclass
class ProcessMemoryLayout:
    """Complete process memory layout"""
    process_id: int
    process_name: str
    base_address: int
    image_size: int
    regions: List[MemoryRegion] = field(default_factory=list)
    threads: List[Dict[str, Any]] = field(default_factory=list)
    modules: List[Dict[str, Any]] = field(default_factory=list)
    heap_regions: List[MemoryRegion] = field(default_factory=list)
    stack_regions: List[MemoryRegion] = field(default_factory=list)
    code_regions: List[MemoryRegion] = field(default_factory=list)
    injected_code: List[MemoryRegion] = field(default_factory=list)
    suspicious_regions: List[MemoryRegion] = field(default_factory=list)

    @property
    def total_memory_size(self) -> int:
        """Calculate total memory size"""
        return sum(region.size for region in self.regions)

    @property
    def executable_regions_count(self) -> int:
        """Count executable regions"""
        return len([r for r in self.regions if r.is_executable])


@dataclass
class HeapAnalysis:
    """Heap corruption and vulnerability analysis"""
    heap_base: int
    heap_size: int
    heap_type: str
    chunks: List[Dict[str, Any]] = field(default_factory=list)
    free_chunks: List[Dict[str, Any]] = field(default_factory=list)
    corrupted_chunks: List[Dict[str, Any]] = field(default_factory=list)
    use_after_free_indicators: List[Dict[str, Any]] = field(default_factory=list)
    double_free_indicators: List[Dict[str, Any]] = field(default_factory=list)
    heap_spray_patterns: List[Dict[str, Any]] = field(default_factory=list)
    overflow_patterns: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def has_corruption(self) -> bool:
        """Check if heap shows corruption signs"""
        return len(self.corrupted_chunks) > 0 or len(self.overflow_patterns) > 0

    @property
    def vulnerability_score(self) -> float:
        """Calculate vulnerability score"""
        score = 0.0
        score += len(self.corrupted_chunks) * 2.0
        score += len(self.use_after_free_indicators) * 3.0
        score += len(self.double_free_indicators) * 3.0
        score += len(self.heap_spray_patterns) * 1.5
        score += len(self.overflow_patterns) * 2.5
        return min(score, 10.0)


@dataclass
class StackAnalysis:
    """Stack analysis for overflow detection"""
    stack_base: int
    stack_size: int
    stack_pointer: int
    return_addresses: List[int] = field(default_factory=list)
    call_chain: List[str] = field(default_factory=list)
    overflow_indicators: List[Dict[str, Any]] = field(default_factory=list)
    rop_gadgets: List[Dict[str, Any]] = field(default_factory=list)
    canary_values: List[int] = field(default_factory=list)
    corrupted_frames: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def has_overflow_signs(self) -> bool:
        """Check for stack overflow indicators"""
        return len(self.overflow_indicators) > 0 or len(self.corrupted_frames) > 0

    @property
    def has_rop_chain(self) -> bool:
        """Check for ROP chain patterns"""
        return len(self.rop_gadgets) > 5


@dataclass
class CodeInjectionAnalysis:
    """Code injection detection and analysis"""
    injection_type: str
    target_process: str
    injection_address: int
    injection_size: int
    shellcode_detected: bool = False
    dll_injection: bool = False
    process_hollowing: bool = False
    code_cave_injection: bool = False
    manual_dll_loading: bool = False
    reflective_dll_loading: bool = False
    thread_hijacking: bool = False
    atom_bombing: bool = False
    injection_artifacts: List[Dict[str, Any]] = field(default_factory=list)
    api_hooks: List[Dict[str, Any]] = field(default_factory=list)
    payload_analysis: Dict[str, Any] = field(default_factory=dict)

    @property
    def severity_score(self) -> float:
        """Calculate injection severity score"""
        score = 0.0
        if self.shellcode_detected:
            score += 4.0
        if self.process_hollowing:
            score += 3.5
        if self.reflective_dll_loading:
            score += 3.0
        if self.thread_hijacking:
            score += 2.5
        if self.dll_injection:
            score += 2.0
        score += len(self.api_hooks) * 0.5
        return min(score, 10.0)


@dataclass
class MemoryDumpAnalysisResult:
    """Comprehensive memory dump analysis results"""
    dump_path: str
    dump_format: MemoryDumpFormat
    architecture: MemoryArchitecture
    dump_size: int
    analysis_timestamp: float
    
    # Core analysis results
    processes: List[ProcessMemoryLayout] = field(default_factory=list)
    memory_regions: List[MemoryRegion] = field(default_factory=list)
    code_injections: List[CodeInjectionAnalysis] = field(default_factory=list)
    heap_analyses: List[HeapAnalysis] = field(default_factory=list)
    stack_analyses: List[StackAnalysis] = field(default_factory=list)
    
    # Extracted artifacts
    extracted_strings: List[str] = field(default_factory=list)
    crypto_artifacts: List[Dict[str, Any]] = field(default_factory=list)
    network_artifacts: List[Dict[str, Any]] = field(default_factory=list)
    file_artifacts: List[Dict[str, Any]] = field(default_factory=list)
    registry_artifacts: List[Dict[str, Any]] = field(default_factory=list)
    
    # Security analysis
    exploit_signatures: List[Dict[str, Any]] = field(default_factory=list)
    anti_analysis_techniques: List[Dict[str, Any]] = field(default_factory=list)
    behavioral_artifacts: List[Dict[str, Any]] = field(default_factory=list)
    
    # Analysis metadata
    analysis_duration: float = 0.0
    total_regions_analyzed: int = 0
    total_patterns_found: int = 0
    confidence_score: float = 0.0
    error_messages: List[str] = field(default_factory=list)

    @property
    def has_code_injection(self) -> bool:
        """Check if code injection was detected"""
        return len(self.code_injections) > 0

    @property
    def has_heap_corruption(self) -> bool:
        """Check if heap corruption was detected"""
        return any(heap.has_corruption for heap in self.heap_analyses)

    @property
    def has_exploits(self) -> bool:
        """Check if exploit signatures were found"""
        return len(self.exploit_signatures) > 0

    @property
    def security_risk_score(self) -> float:
        """Calculate overall security risk score"""
        score = 0.0
        score += sum(inj.severity_score for inj in self.code_injections)
        score += sum(heap.vulnerability_score for heap in self.heap_analyses)
        score += len(self.exploit_signatures) * 2.0
        score += len(self.anti_analysis_techniques) * 1.5
        return min(score / max(len(self.processes), 1), 10.0)


class MemoryDumpAnalyzer:
    """
    Comprehensive memory dump analysis system that provides deep forensic analysis
    of memory dumps from various sources and formats.
    """

    def __init__(self, cache_directory: Optional[str] = None):
        """Initialize the memory dump analyzer"""
        self.logger = logging.getLogger("IntellicrackLogger.MemoryDumpAnalyzer")
        
        # Set up cache directory
        if cache_directory:
            self.cache_directory = Path(cache_directory)
        else:
            self.cache_directory = Path("./cache/memory_dumps")
        
        self.cache_directory.mkdir(parents=True, exist_ok=True)
        
        # Initialize existing memory forensics engine
        self.memory_forensics = MemoryForensicsEngine(str(self.cache_directory))
        
        # Initialize disassemblers
        self.disassemblers = {}
        if CAPSTONE_AVAILABLE:
            self.disassemblers['x86_64'] = Cs(CS_ARCH_X86, CS_MODE_64)
            self.disassemblers['x86_32'] = Cs(CS_ARCH_X86, CS_MODE_32)
        
        # YARA rules for pattern detection
        self.yara_rules = None
        if YARA_AVAILABLE:
            self._load_yara_rules()
        
        # Analysis cache
        self.analysis_cache = {}
        self.processed_dumps: Set[str] = set()

    def analyze_memory_dump(
        self,
        dump_path: Union[str, Path],
        dump_format: Optional[MemoryDumpFormat] = None,
        deep_analysis: bool = True,
        include_disassembly: bool = True,
        extract_artifacts: bool = True
    ) -> MemoryDumpAnalysisResult:
        """
        Perform comprehensive analysis of a memory dump
        
        Args:
            dump_path: Path to the memory dump file
            dump_format: Format of the memory dump (auto-detected if None)
            deep_analysis: Whether to perform deep vulnerability analysis
            include_disassembly: Whether to include disassembly analysis
            extract_artifacts: Whether to extract forensic artifacts
            
        Returns:
            Comprehensive analysis results
        """
        start_time = time.time()
        dump_path = str(dump_path)
        
        self.logger.info(f"Starting comprehensive memory dump analysis: {dump_path}")
        
        if not os.path.exists(dump_path):
            return MemoryDumpAnalysisResult(
                dump_path=dump_path,
                dump_format=MemoryDumpFormat.UNKNOWN,
                architecture=MemoryArchitecture.UNKNOWN,
                dump_size=0,
                analysis_timestamp=start_time,
                error_messages=[f"Memory dump not found: {dump_path}"]
            )
        
        # Check cache
        dump_hash = self._calculate_file_hash(dump_path)
        if dump_hash in self.analysis_cache:
            self.logger.info(f"Using cached analysis for {dump_path}")
            cached_result = self.analysis_cache[dump_hash]
            cached_result.analysis_timestamp = start_time
            return cached_result
        
        # Initialize result
        dump_size = os.path.getsize(dump_path)
        result = MemoryDumpAnalysisResult(
            dump_path=dump_path,
            dump_format=dump_format or self._detect_dump_format(dump_path),
            architecture=self._detect_architecture(dump_path),
            dump_size=dump_size,
            analysis_timestamp=start_time
        )
        
        try:
            # Step 1: Basic memory forensics analysis using existing engine
            self.logger.info("Running basic memory forensics analysis")
            basic_analysis = self.memory_forensics.analyze_memory_dump(
                dump_path, deep_analysis=deep_analysis
            )
            
            # Step 2: Enhanced memory structure analysis
            self.logger.info("Analyzing memory structures")
            result.memory_regions = self._analyze_memory_regions(dump_path, result.architecture)
            
            # Step 3: Process memory layout reconstruction
            self.logger.info("Reconstructing process memory layouts")
            result.processes = self._reconstruct_process_layouts(
                dump_path, basic_analysis, result.memory_regions
            )
            
            # Step 4: Code analysis and injection detection
            if include_disassembly:
                self.logger.info("Analyzing code and detecting injections")
                result.code_injections = self._detect_code_injections(
                    result.processes, result.memory_regions
                )
            
            # Step 5: Heap and stack analysis
            if deep_analysis:
                self.logger.info("Performing heap and stack analysis")
                result.heap_analyses = self._analyze_heap_structures(result.processes)
                result.stack_analyses = self._analyze_stack_structures(result.processes)
            
            # Step 6: Artifact extraction
            if extract_artifacts:
                self.logger.info("Extracting forensic artifacts")
                self._extract_forensic_artifacts(dump_path, result)
            
            # Step 7: Security analysis
            self.logger.info("Performing security analysis")
            self._perform_security_analysis(result)
            
            # Step 8: Pattern matching and signature detection
            if YARA_AVAILABLE and self.yara_rules:
                self.logger.info("Running YARA pattern matching")
                self._run_yara_analysis(dump_path, result)
            
            # Calculate final metrics
            result.analysis_duration = time.time() - start_time
            result.total_regions_analyzed = len(result.memory_regions)
            result.total_patterns_found = sum(
                len(region.patterns_found) for region in result.memory_regions
            )
            result.confidence_score = self._calculate_confidence_score(result)
            
            # Cache results
            self.analysis_cache[dump_hash] = result
            self.processed_dumps.add(dump_path)
            
            self.logger.info(
                f"Memory dump analysis completed in {result.analysis_duration:.2f}s "
                f"(Risk Score: {result.security_risk_score:.1f}/10.0)"
            )
            
        except Exception as e:
            self.logger.error(f"Memory dump analysis failed: {e}")
            result.error_messages.append(str(e))
            result.analysis_duration = time.time() - start_time
        
        return result

    def _detect_dump_format(self, dump_path: str) -> MemoryDumpFormat:
        """Detect memory dump format from file headers and signatures"""
        try:
            with open(dump_path, 'rb') as f:
                header = f.read(512)
            
            # Windows crash dump signatures
            if header.startswith(b'PAGEDUMP') or header.startswith(b'PAGE'):
                return MemoryDumpFormat.WINDOWS_CRASH_DUMP
            
            if header.startswith(b'MDMP'):
                return MemoryDumpFormat.WINDOWS_MINIDUMP
            
            # VMware memory file signature
            if b'VMware' in header[:100] or dump_path.endswith('.vmem'):
                return MemoryDumpFormat.VMWARE_VMEM
            
            # QEMU snapshot signatures
            if b'QVM' in header[:50] or b'QEMU' in header[:100]:
                return MemoryDumpFormat.QEMU_SNAPSHOT
            
            # Linux core dump signature
            if header.startswith(b'\x7fELF') and b'CORE' in header[:100]:
                return MemoryDumpFormat.LINUX_CORE_DUMP
            
            # Hyper-V save state
            if b'HVSS' in header[:50] or b'Microsoft' in header[:100]:
                return MemoryDumpFormat.HYPERV_SAVE_STATE
            
            # VirtualBox save state
            if b'VirtualBox' in header[:100] or dump_path.endswith('.sav'):
                return MemoryDumpFormat.VIRTUALBOX_SAVE_STATE
            
            # Default to raw memory if no specific format detected
            return MemoryDumpFormat.RAW_MEMORY
            
        except Exception as e:
            self.logger.debug(f"Format detection failed: {e}")
            return MemoryDumpFormat.UNKNOWN

    def _detect_architecture(self, dump_path: str) -> MemoryArchitecture:
        """Detect memory dump architecture"""
        try:
            with open(dump_path, 'rb') as f:
                # Read larger sample for architecture detection
                sample = f.read(4096)
            
            # Look for common x86_64 patterns
            x64_patterns = [
                b'\x48\x89',  # REX.W MOV instructions
                b'\x48\x8b',  # REX.W MOV from memory
                b'\x48\x83',  # REX.W arithmetic
                b'\x48\x85',  # REX.W TEST
            ]
            
            x64_count = sum(sample.count(pattern) for pattern in x64_patterns)
            
            # Look for common x86_32 patterns
            x32_patterns = [
                b'\x89\x45',  # MOV to stack
                b'\x8b\x45',  # MOV from stack
                b'\x83\xec',  # SUB ESP
                b'\x83\xc4',  # ADD ESP
            ]
            
            x32_count = sum(sample.count(pattern) for pattern in x32_patterns)
            
            # ARM patterns
            arm_patterns = [
                b'\x00\x00\xa0\xe3',  # MOV r0, #0
                b'\x1e\xff\x2f\xe1',  # BX lr
            ]
            
            arm_count = sum(sample.count(pattern) for pattern in arm_patterns)
            
            # Determine architecture based on pattern frequency
            if x64_count > max(x32_count, arm_count):
                return MemoryArchitecture.X86_64
            elif x32_count > max(x64_count, arm_count):
                return MemoryArchitecture.X86_32
            elif arm_count > 0:
                return MemoryArchitecture.ARM_32
            
            # Fallback: check file size and common addresses
            file_size = os.path.getsize(dump_path)
            if file_size > 4 * 1024 * 1024 * 1024:  # > 4GB suggests 64-bit
                return MemoryArchitecture.X86_64
            
            return MemoryArchitecture.X86_32
            
        except Exception as e:
            self.logger.debug(f"Architecture detection failed: {e}")
            return MemoryArchitecture.UNKNOWN

    def _analyze_memory_regions(
        self, 
        dump_path: str, 
        architecture: MemoryArchitecture
    ) -> List[MemoryRegion]:
        """Analyze memory regions and page structures"""
        regions = []
        
        try:
            with open(dump_path, 'rb') as f:
                # Read memory dump in chunks
                chunk_size = 1024 * 1024  # 1MB chunks
                offset = 0
                
                while offset < os.path.getsize(dump_path):
                    f.seek(offset)
                    chunk = f.read(chunk_size)
                    
                    if not chunk:
                        break
                    
                    # Analyze chunk for memory region characteristics
                    region = self._analyze_memory_chunk(chunk, offset, architecture)
                    if region:
                        regions.append(region)
                    
                    offset += chunk_size
                    
                    # Limit analysis to prevent excessive processing
                    if len(regions) > 1000:
                        break
            
            # Merge adjacent regions with similar characteristics
            regions = self._merge_adjacent_regions(regions)
            
        except Exception as e:
            self.logger.error(f"Memory region analysis failed: {e}")
        
        return regions

    def _analyze_memory_chunk(
        self, 
        chunk: bytes, 
        offset: int, 
        architecture: MemoryArchitecture
    ) -> Optional[MemoryRegion]:
        """Analyze a chunk of memory for region characteristics"""
        if not chunk:
            return None
        
        try:
            # Calculate entropy
            entropy = self._calculate_entropy(chunk)
            
            # Detect region type based on content patterns
            region_type = self._detect_region_type(chunk, entropy)
            
            # Extract strings
            strings = self._extract_strings_from_chunk(chunk)
            
            # Analyze for code patterns
            disassembly = []
            if region_type == MemoryRegionType.CODE and CAPSTONE_AVAILABLE:
                disassembly = self._disassemble_chunk(chunk, architecture)
            
            # Create memory region
            region = MemoryRegion(
                start_address=offset,
                end_address=offset + len(chunk),
                size=len(chunk),
                region_type=region_type,
                permissions=self._infer_permissions(chunk, region_type),
                strings=strings[:100],  # Limit strings
                disassembly=disassembly[:50],  # Limit disassembly
                entropy_analysis={
                    'entropy': entropy,
                    'high_entropy_blocks': self._find_high_entropy_blocks(chunk)
                }
            )
            
            # Detect patterns
            region.patterns_found = self._detect_patterns_in_chunk(chunk)
            
            return region
            
        except Exception as e:
            self.logger.debug(f"Chunk analysis failed at offset {offset}: {e}")
            return None

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        try:
            if NUMPY_AVAILABLE:
                # Use NumPy for efficient calculation
                byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
                probabilities = byte_counts / len(data)
                probabilities = probabilities[probabilities > 0]
                return -np.sum(probabilities * np.log2(probabilities))
            else:
                # Fallback implementation
                byte_counts = [0] * 256
                for byte in data:
                    byte_counts[byte] += 1
                
                entropy = 0.0
                length = len(data)
                
                for count in byte_counts:
                    if count > 0:
                        p = count / length
                        entropy -= p * (p.bit_length() - 1)  # Approximation of log2
                
                return entropy
                
        except Exception:
            return 0.0

    def _detect_region_type(self, chunk: bytes, entropy: float) -> MemoryRegionType:
        """Detect memory region type based on content analysis"""
        try:
            # High entropy suggests encrypted/compressed data or code
            if entropy > 7.5:
                return MemoryRegionType.DATA
            
            # Look for executable code patterns
            if self._has_code_patterns(chunk):
                return MemoryRegionType.CODE
            
            # Look for heap patterns
            if self._has_heap_patterns(chunk):
                return MemoryRegionType.HEAP
            
            # Look for stack patterns
            if self._has_stack_patterns(chunk):
                return MemoryRegionType.STACK
            
            # Default to data
            return MemoryRegionType.DATA
            
        except Exception:
            return MemoryRegionType.UNKNOWN

    def _has_code_patterns(self, chunk: bytes) -> bool:
        """Check if chunk contains executable code patterns"""
        # Common x86/x64 instruction prefixes and opcodes
        code_patterns = [
            b'\x48\x89',  # MOV (64-bit)
            b'\x48\x8b',  # MOV (64-bit)
            b'\x89\x45',  # MOV to stack
            b'\x8b\x45',  # MOV from stack
            b'\xff\x15',  # CALL indirect
            b'\xe8',      # CALL relative
            b'\xc3',      # RET
            b'\x90',      # NOP
        ]
        
        code_count = sum(chunk.count(pattern) for pattern in code_patterns)
        return code_count > len(chunk) // 100  # At least 1% code patterns

    def _has_heap_patterns(self, chunk: bytes) -> bool:
        """Check if chunk contains heap structure patterns"""
        # Look for heap metadata patterns
        heap_patterns = [
            b'\x00\x00\x00\x00\x00\x00\x00\x00',  # Null pointers
            b'\xff\xff\xff\xff',  # Uninitialized data
        ]
        
        # Check for repeated patterns typical in heap
        null_count = chunk.count(b'\x00')
        return null_count > len(chunk) // 4  # More than 25% nulls

    def _has_stack_patterns(self, chunk: bytes) -> bool:
        """Check if chunk contains stack structure patterns"""
        # Look for return addresses (pointers in executable range)
        addr_patterns = []
        
        for i in range(0, len(chunk) - 8, 8):
            try:
                # Extract potential 64-bit address
                addr = struct.unpack('<Q', chunk[i:i+8])[0]
                # Check if it looks like a code address
                if 0x400000 <= addr <= 0x7fffffffffff:
                    addr_patterns.append(addr)
            except:
                continue
        
        return len(addr_patterns) > 5  # Multiple potential return addresses

    def _extract_strings_from_chunk(self, chunk: bytes, min_length: int = 4) -> List[str]:
        """Extract ASCII and Unicode strings from memory chunk"""
        strings = []
        
        try:
            # ASCII strings
            current_string = ""
            for byte in chunk:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string += chr(byte)
                else:
                    if len(current_string) >= min_length:
                        strings.append(current_string)
                    current_string = ""
            
            if len(current_string) >= min_length:
                strings.append(current_string)
            
            # Unicode strings (UTF-16LE)
            try:
                unicode_text = chunk.decode('utf-16le', errors='ignore')
                unicode_strings = [s for s in unicode_text.split('\x00') if len(s) >= min_length]
                strings.extend(unicode_strings[:10])  # Limit Unicode strings
            except:
                pass
            
        except Exception as e:
            self.logger.debug(f"String extraction failed: {e}")
        
        return strings[:50]  # Limit total strings per chunk

    def _disassemble_chunk(
        self, 
        chunk: bytes, 
        architecture: MemoryArchitecture
    ) -> List[Dict[str, Any]]:
        """Disassemble code chunk using Capstone"""
        if not CAPSTONE_AVAILABLE:
            return []
        
        try:
            arch_key = 'x86_64' if architecture == MemoryArchitecture.X86_64 else 'x86_32'
            disassembler = self.disassemblers.get(arch_key)
            
            if not disassembler:
                return []
            
            instructions = []
            try:
                for i, instruction in enumerate(disassembler.disasm(chunk, 0)):
                    instructions.append({
                        'address': instruction.address,
                        'mnemonic': instruction.mnemonic,
                        'op_str': instruction.op_str,
                        'size': instruction.size,
                        'bytes': instruction.bytes.hex()
                    })
                    
                    # Limit instructions to prevent excessive data
                    if i >= 100:
                        break
            except Exception as disasm_error:
                self.logger.debug(f"Disassembly error: {disasm_error}")
            
            return instructions
            
        except Exception as e:
            self.logger.debug(f"Chunk disassembly failed: {e}")
            return []

    def _detect_patterns_in_chunk(self, chunk: bytes) -> List[str]:
        """Detect security-relevant patterns in memory chunk"""
        patterns = []
        
        try:
            # Shellcode patterns
            shellcode_patterns = [
                (b'\x31\xc0', 'XOR EAX, EAX (shellcode pattern)'),
                (b'\x50\x68', 'PUSH/PUSH pattern (shellcode)'),
                (b'\xeb\xfe', 'Infinite loop (shellcode)'),
                (b'\x90\x90\x90\x90', 'NOP sled'),
            ]
            
            for pattern, description in shellcode_patterns:
                if pattern in chunk:
                    patterns.append(description)
            
            # ROP gadgets
            rop_patterns = [
                (b'\xc3', 'RET instruction'),
                (b'\x5d\xc3', 'POP EBP; RET'),
                (b'\x58\xc3', 'POP EAX; RET'),
            ]
            
            for pattern, description in rop_patterns:
                if chunk.count(pattern) > 5:
                    patterns.append(f"Multiple {description} gadgets")
            
            # API hashing patterns
            if b'\x13\x8b\x6f\x87' in chunk:  # Common API hash
                patterns.append('API hashing detected')
            
            # Packer signatures
            packer_patterns = [
                (b'UPX!', 'UPX packer signature'),
                (b'PECompact', 'PECompact packer'),
                (b'ASPack', 'ASPack packer'),
            ]
            
            for pattern, description in packer_patterns:
                if pattern in chunk:
                    patterns.append(description)
            
        except Exception as e:
            self.logger.debug(f"Pattern detection failed: {e}")
        
        return patterns

    def _find_high_entropy_blocks(self, chunk: bytes, block_size: int = 256) -> List[Dict[str, Any]]:
        """Find high-entropy blocks within a chunk (potential encryption/compression)"""
        high_entropy_blocks = []
        
        try:
            for i in range(0, len(chunk), block_size):
                block = chunk[i:i + block_size]
                if len(block) < block_size // 2:
                    continue
                
                entropy = self._calculate_entropy(block)
                if entropy > 7.0:  # High entropy threshold
                    high_entropy_blocks.append({
                        'offset': i,
                        'size': len(block),
                        'entropy': entropy
                    })
        
        except Exception as e:
            self.logger.debug(f"High entropy block detection failed: {e}")
        
        return high_entropy_blocks

    def _infer_permissions(self, chunk: bytes, region_type: MemoryRegionType) -> str:
        """Infer memory permissions based on content and type"""
        permissions = "r"  # Default readable
        
        if region_type == MemoryRegionType.CODE:
            permissions += "x"  # Executable
        
        if region_type in [MemoryRegionType.DATA, MemoryRegionType.HEAP, MemoryRegionType.STACK]:
            permissions += "w"  # Writable
        
        return permissions

    def _merge_adjacent_regions(self, regions: List[MemoryRegion]) -> List[MemoryRegion]:
        """Merge adjacent regions with similar characteristics"""
        if not regions:
            return []
        
        merged = []
        current_region = regions[0]
        
        for next_region in regions[1:]:
            # Check if regions should be merged
            if (
                current_region.end_address == next_region.start_address and
                current_region.region_type == next_region.region_type and
                current_region.permissions == next_region.permissions
            ):
                # Merge regions
                current_region.end_address = next_region.end_address
                current_region.size += next_region.size
                current_region.strings.extend(next_region.strings[:10])
                current_region.patterns_found.extend(next_region.patterns_found)
            else:
                # Start new region
                merged.append(current_region)
                current_region = next_region
        
        merged.append(current_region)
        return merged

    def _reconstruct_process_layouts(
        self,
        dump_path: str,
        basic_analysis: MemoryAnalysisResult,
        memory_regions: List[MemoryRegion]
    ) -> List[ProcessMemoryLayout]:
        """Reconstruct process memory layouts"""
        process_layouts = []
        
        try:
            # Use basic analysis process information
            for process in basic_analysis.processes:
                layout = ProcessMemoryLayout(
                    process_id=process.pid,
                    process_name=process.name,
                    base_address=process.image_base,
                    image_size=process.image_size
                )
                
                # Assign memory regions to process (simplified heuristic)
                # In real implementation, this would use process memory maps
                for region in memory_regions:
                    if region.region_type == MemoryRegionType.HEAP:
                        layout.heap_regions.append(region)
                    elif region.region_type == MemoryRegionType.STACK:
                        layout.stack_regions.append(region)
                    elif region.region_type == MemoryRegionType.CODE:
                        layout.code_regions.append(region)
                        
                        # Check for potential injection
                        if region.entropy_analysis.get('entropy', 0) > 6.5:
                            layout.injected_code.append(region)
                    
                    layout.regions.append(region)
                
                # Identify suspicious regions
                for region in layout.regions:
                    if (
                        region.has_shellcode_characteristics or
                        len(region.patterns_found) > 3 or
                        'shellcode' in str(region.patterns_found).lower()
                    ):
                        layout.suspicious_regions.append(region)
                
                process_layouts.append(layout)
                
        except Exception as e:
            self.logger.error(f"Process layout reconstruction failed: {e}")
        
        return process_layouts

    def _detect_code_injections(
        self,
        processes: List[ProcessMemoryLayout],
        memory_regions: List[MemoryRegion]
    ) -> List[CodeInjectionAnalysis]:
        """Detect various forms of code injection"""
        injections = []
        
        try:
            for process in processes:
                # Look for injected code in each process
                for region in process.injected_code:
                    injection = self._analyze_potential_injection(process, region)
                    if injection:
                        injections.append(injection)
                
                # Check for DLL injection indicators
                dll_injection = self._detect_dll_injection(process)
                if dll_injection:
                    injections.append(dll_injection)
                
                # Check for process hollowing
                hollowing = self._detect_process_hollowing(process)
                if hollowing:
                    injections.append(hollowing)
        
        except Exception as e:
            self.logger.error(f"Code injection detection failed: {e}")
        
        return injections

    def _analyze_potential_injection(
        self,
        process: ProcessMemoryLayout,
        region: MemoryRegion
    ) -> Optional[CodeInjectionAnalysis]:
        """Analyze a memory region for code injection characteristics"""
        try:
            injection = CodeInjectionAnalysis(
                injection_type="unknown",
                target_process=process.process_name,
                injection_address=region.start_address,
                injection_size=region.size
            )
            
            # Check for shellcode characteristics
            if region.has_shellcode_characteristics:
                injection.shellcode_detected = True
                injection.injection_type = "shellcode_injection"
            
            # Check for code cave injection
            if region.size < 4096 and region.is_executable:
                injection.code_cave_injection = True
                injection.injection_type = "code_cave_injection"
            
            # Analyze payload
            injection.payload_analysis = {
                'entropy': region.entropy_analysis.get('entropy', 0),
                'patterns': region.patterns_found,
                'size': region.size,
                'disassembly_available': len(region.disassembly) > 0
            }
            
            # Only return if we found injection indicators
            if (injection.shellcode_detected or injection.code_cave_injection or
                len(region.patterns_found) > 0):
                return injection
            
        except Exception as e:
            self.logger.debug(f"Injection analysis failed: {e}")
        
        return None

    def _detect_dll_injection(self, process: ProcessMemoryLayout) -> Optional[CodeInjectionAnalysis]:
        """Detect DLL injection patterns"""
        try:
            # Look for suspicious DLL loading patterns
            suspicious_modules = []
            
            for module in process.modules:
                module_path = module.get('path', '').lower()
                
                # Check for DLLs loaded from unusual locations
                if any(path in module_path for path in ['temp', 'appdata', 'downloads']):
                    suspicious_modules.append(module)
            
            if suspicious_modules:
                injection = CodeInjectionAnalysis(
                    injection_type="dll_injection",
                    target_process=process.process_name,
                    injection_address=0,
                    injection_size=0,
                    dll_injection=True
                )
                
                injection.injection_artifacts = [
                    {'type': 'suspicious_module', 'data': module}
                    for module in suspicious_modules
                ]
                
                return injection
                
        except Exception as e:
            self.logger.debug(f"DLL injection detection failed: {e}")
        
        return None

    def _detect_process_hollowing(self, process: ProcessMemoryLayout) -> Optional[CodeInjectionAnalysis]:
        """Detect process hollowing patterns"""
        try:
            # Look for mismatched entry points or unusual memory layouts
            hollowing_indicators = []
            
            # Check for unusual executable regions
            exec_regions = [r for r in process.regions if r.is_executable]
            
            # Process hollowing often creates new executable sections
            if len(exec_regions) > 5:  # Unusually many executable regions
                hollowing_indicators.append("Multiple executable regions")
            
            # Check for high entropy in main executable region
            for region in process.code_regions:
                if region.entropy_analysis.get('entropy', 0) > 7.0:
                    hollowing_indicators.append("High entropy in code region")
            
            if hollowing_indicators:
                injection = CodeInjectionAnalysis(
                    injection_type="process_hollowing",
                    target_process=process.process_name,
                    injection_address=process.base_address,
                    injection_size=process.image_size,
                    process_hollowing=True
                )
                
                injection.injection_artifacts = [
                    {'type': 'hollowing_indicator', 'description': indicator}
                    for indicator in hollowing_indicators
                ]
                
                return injection
                
        except Exception as e:
            self.logger.debug(f"Process hollowing detection failed: {e}")
        
        return None

    def _analyze_heap_structures(self, processes: List[ProcessMemoryLayout]) -> List[HeapAnalysis]:
        """Analyze heap structures for corruption and vulnerabilities"""
        heap_analyses = []
        
        try:
            for process in processes:
                for heap_region in process.heap_regions:
                    analysis = self._analyze_single_heap(heap_region, process)
                    if analysis:
                        heap_analyses.append(analysis)
        
        except Exception as e:
            self.logger.error(f"Heap analysis failed: {e}")
        
        return heap_analyses

    def _analyze_single_heap(
        self,
        heap_region: MemoryRegion,
        process: ProcessMemoryLayout
    ) -> Optional[HeapAnalysis]:
        """Analyze a single heap region"""
        try:
            analysis = HeapAnalysis(
                heap_base=heap_region.start_address,
                heap_size=heap_region.size,
                heap_type="unknown"
            )
            
            # Look for heap corruption patterns
            corruption_patterns = [
                pattern for pattern in heap_region.patterns_found
                if 'corruption' in pattern.lower() or 'overflow' in pattern.lower()
            ]
            
            if corruption_patterns:
                analysis.corrupted_chunks = [
                    {'pattern': pattern, 'region': heap_region.start_address}
                    for pattern in corruption_patterns
                ]
            
            # Check for heap spray patterns
            if heap_region.entropy_analysis.get('entropy', 0) < 2.0:  # Low entropy = repeated data
                analysis.heap_spray_patterns = [{
                    'type': 'low_entropy_spray',
                    'entropy': heap_region.entropy_analysis.get('entropy', 0),
                    'size': heap_region.size
                }]
            
            # Only return if we found interesting heap characteristics
            if analysis.has_corruption or len(analysis.heap_spray_patterns) > 0:
                return analysis
                
        except Exception as e:
            self.logger.debug(f"Single heap analysis failed: {e}")
        
        return None

    def _analyze_stack_structures(self, processes: List[ProcessMemoryLayout]) -> List[StackAnalysis]:
        """Analyze stack structures for overflow detection"""
        stack_analyses = []
        
        try:
            for process in processes:
                for stack_region in process.stack_regions:
                    analysis = self._analyze_single_stack(stack_region, process)
                    if analysis:
                        stack_analyses.append(analysis)
        
        except Exception as e:
            self.logger.error(f"Stack analysis failed: {e}")
        
        return stack_analyses

    def _analyze_single_stack(
        self,
        stack_region: MemoryRegion,
        process: ProcessMemoryLayout
    ) -> Optional[StackAnalysis]:
        """Analyze a single stack region"""
        try:
            analysis = StackAnalysis(
                stack_base=stack_region.start_address,
                stack_size=stack_region.size,
                stack_pointer=stack_region.start_address  # Simplified
            )
            
            # Look for ROP gadgets in disassembly
            rop_gadgets = []
            for instr in stack_region.disassembly:
                if instr.get('mnemonic') == 'ret':
                    rop_gadgets.append({
                        'address': instr.get('address', 0),
                        'instruction': f"{instr.get('mnemonic', '')} {instr.get('op_str', '')}"
                    })
            
            analysis.rop_gadgets = rop_gadgets
            
            # Check for overflow patterns
            overflow_patterns = [
                pattern for pattern in stack_region.patterns_found
                if 'overflow' in pattern.lower() or 'ret' in pattern.lower()
            ]
            
            if overflow_patterns:
                analysis.overflow_indicators = [
                    {'pattern': pattern, 'region': stack_region.start_address}
                    for pattern in overflow_patterns
                ]
            
            # Only return if we found interesting stack characteristics
            if analysis.has_overflow_signs or analysis.has_rop_chain:
                return analysis
                
        except Exception as e:
            self.logger.debug(f"Single stack analysis failed: {e}")
        
        return None

    def _extract_forensic_artifacts(self, dump_path: str, result: MemoryDumpAnalysisResult):
        """Extract various forensic artifacts from memory dump"""
        try:
            # Extract strings
            result.extracted_strings = self._extract_all_strings(dump_path)
            
            # Extract network artifacts
            result.network_artifacts = self._extract_network_artifacts(result.extracted_strings)
            
            # Extract file artifacts
            result.file_artifacts = self._extract_file_artifacts(result.extracted_strings)
            
            # Extract crypto artifacts
            result.crypto_artifacts = self._extract_crypto_artifacts(result.extracted_strings)
            
            # Extract registry artifacts
            result.registry_artifacts = self._extract_registry_artifacts(result.extracted_strings)
            
        except Exception as e:
            self.logger.error(f"Artifact extraction failed: {e}")
            result.error_messages.append(f"Artifact extraction failed: {e}")

    def _extract_all_strings(self, dump_path: str, max_strings: int = 10000) -> List[str]:
        """Extract all strings from memory dump"""
        strings = []
        
        try:
            with open(dump_path, 'rb') as f:
                chunk_size = 1024 * 1024  # 1MB chunks
                current_string = ""
                
                while len(strings) < max_strings:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    for byte in chunk:
                        if 32 <= byte <= 126:  # Printable ASCII
                            current_string += chr(byte)
                        else:
                            if len(current_string) >= 6:  # Minimum string length
                                strings.append(current_string)
                            current_string = ""
                    
                    if len(strings) % 1000 == 0:
                        self.logger.debug(f"Extracted {len(strings)} strings so far")
                
                # Don't forget the last string
                if len(current_string) >= 6:
                    strings.append(current_string)
            
        except Exception as e:
            self.logger.error(f"String extraction failed: {e}")
        
        return strings[:max_strings]

    def _extract_network_artifacts(self, strings: List[str]) -> List[Dict[str, Any]]:
        """Extract network-related artifacts from strings"""
        artifacts = []
        
        try:
            import re
            
            # IP address pattern
            ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
            
            # URL pattern
            url_pattern = re.compile(r'https?://[^\s<>"\']+|ftp://[^\s<>"\']+')
            
            # Domain pattern
            domain_pattern = re.compile(r'\b[a-zA-Z0-9-]+\.(?:com|org|net|edu|gov|mil|int|co\.uk|de|fr|jp)\b')
            
            for string in strings:
                # Find IP addresses
                ips = ip_pattern.findall(string)
                for ip in ips:
                    artifacts.append({
                        'type': 'ip_address',
                        'value': ip,
                        'context': string[:100]
                    })
                
                # Find URLs
                urls = url_pattern.findall(string)
                for url in urls:
                    artifacts.append({
                        'type': 'url',
                        'value': url,
                        'context': string[:100]
                    })
                
                # Find domains
                domains = domain_pattern.findall(string)
                for domain in domains:
                    artifacts.append({
                        'type': 'domain',
                        'value': domain,
                        'context': string[:100]
                    })
        
        except Exception as e:
            self.logger.debug(f"Network artifact extraction failed: {e}")
        
        return artifacts[:500]  # Limit artifacts

    def _extract_file_artifacts(self, strings: List[str]) -> List[Dict[str, Any]]:
        """Extract file-related artifacts from strings"""
        artifacts = []
        
        try:
            import re
            
            # File path patterns
            windows_path_pattern = re.compile(r'[A-Za-z]:\\[^<>:"|?*\n\r]*')
            unix_path_pattern = re.compile(r'/[^\s<>"|*\n\r]+')
            
            for string in strings:
                # Find Windows paths
                win_paths = windows_path_pattern.findall(string)
                for path in win_paths:
                    artifacts.append({
                        'type': 'windows_path',
                        'value': path,
                        'context': string[:100]
                    })
                
                # Find Unix paths
                unix_paths = unix_path_pattern.findall(string)
                for path in unix_paths:
                    if len(path) > 5:  # Filter out short matches
                        artifacts.append({
                            'type': 'unix_path',
                            'value': path,
                            'context': string[:100]
                        })
        
        except Exception as e:
            self.logger.debug(f"File artifact extraction failed: {e}")
        
        return artifacts[:500]  # Limit artifacts

    def _extract_crypto_artifacts(self, strings: List[str]) -> List[Dict[str, Any]]:
        """Extract cryptographic artifacts from strings"""
        artifacts = []
        
        try:
            import re
            
            # Common crypto patterns
            patterns = {
                'base64': re.compile(r'[A-Za-z0-9+/]{40,}={0,2}'),
                'hex_key': re.compile(r'[A-Fa-f0-9]{32,}'),
                'pem_header': re.compile(r'-----BEGIN [A-Z ]+-----'),
                'pem_footer': re.compile(r'-----END [A-Z ]+-----'),
            }
            
            crypto_keywords = [
                'private key', 'public key', 'certificate', 'rsa', 'aes', 'des',
                'sha', 'md5', 'password', 'secret', 'token', 'api_key'
            ]
            
            for string in strings:
                string_lower = string.lower()
                
                # Check for crypto keywords
                for keyword in crypto_keywords:
                    if keyword in string_lower:
                        artifacts.append({
                            'type': 'crypto_keyword',
                            'keyword': keyword,
                            'value': string[:200],
                            'context': string[:100]
                        })
                
                # Check for crypto patterns
                for pattern_name, pattern in patterns.items():
                    matches = pattern.findall(string)
                    for match in matches[:5]:  # Limit matches per string
                        artifacts.append({
                            'type': pattern_name,
                            'value': match[:100],  # Truncate long values
                            'context': string[:100]
                        })
        
        except Exception as e:
            self.logger.debug(f"Crypto artifact extraction failed: {e}")
        
        return artifacts[:200]  # Limit artifacts

    def _extract_registry_artifacts(self, strings: List[str]) -> List[Dict[str, Any]]:
        """Extract Windows registry artifacts from strings"""
        artifacts = []
        
        try:
            import re
            
            # Registry key pattern
            reg_pattern = re.compile(r'HKEY_[A-Z_]+\\[^<>:"|?*\n\r]+')
            
            for string in strings:
                reg_keys = reg_pattern.findall(string)
                for key in reg_keys:
                    artifacts.append({
                        'type': 'registry_key',
                        'value': key,
                        'context': string[:100]
                    })
        
        except Exception as e:
            self.logger.debug(f"Registry artifact extraction failed: {e}")
        
        return artifacts[:200]  # Limit artifacts

    def _perform_security_analysis(self, result: MemoryDumpAnalysisResult):
        """Perform comprehensive security analysis"""
        try:
            # Detect exploit signatures
            result.exploit_signatures = self._detect_exploit_signatures(result)
            
            # Detect anti-analysis techniques
            result.anti_analysis_techniques = self._detect_anti_analysis_techniques(result)
            
            # Extract behavioral artifacts
            result.behavioral_artifacts = self._extract_behavioral_artifacts(result)
            
        except Exception as e:
            self.logger.error(f"Security analysis failed: {e}")
            result.error_messages.append(f"Security analysis failed: {e}")

    def _detect_exploit_signatures(self, result: MemoryDumpAnalysisResult) -> List[Dict[str, Any]]:
        """Detect known exploit signatures and patterns"""
        signatures = []
        
        try:
            # Check all extracted strings for exploit indicators
            exploit_keywords = [
                'metasploit', 'meterpreter', 'payload', 'exploit', 'shellcode',
                'buffer overflow', 'format string', 'use after free', 'double free',
                'heap spray', 'rop chain', 'jop', 'return oriented programming'
            ]
            
            for string in result.extracted_strings:
                string_lower = string.lower()
                for keyword in exploit_keywords:
                    if keyword in string_lower:
                        signatures.append({
                            'type': 'exploit_keyword',
                            'keyword': keyword,
                            'context': string[:200],
                            'severity': 'medium'
                        })
            
            # Check for exploit patterns in memory regions
            for region in result.memory_regions:
                for pattern in region.patterns_found:
                    if any(exploit_term in pattern.lower() for exploit_term in ['shellcode', 'exploit', 'payload']):
                        signatures.append({
                            'type': 'exploit_pattern',
                            'pattern': pattern,
                            'address': hex(region.start_address),
                            'severity': 'high'
                        })
            
        except Exception as e:
            self.logger.debug(f"Exploit signature detection failed: {e}")
        
        return signatures[:50]  # Limit signatures

    def _detect_anti_analysis_techniques(self, result: MemoryDumpAnalysisResult) -> List[Dict[str, Any]]:
        """Detect anti-analysis and evasion techniques"""
        techniques = []
        
        try:
            # Check for debugger detection strings
            debugger_strings = [
                'ollydbg', 'x64dbg', 'windbg', 'ida', 'ghidra', 'radare2',
                'debugger', 'breakpoint', 'stepping', 'analysis'
            ]
            
            for string in result.extracted_strings:
                string_lower = string.lower()
                for debugger_str in debugger_strings:
                    if debugger_str in string_lower:
                        techniques.append({
                            'type': 'debugger_detection',
                            'technique': debugger_str,
                            'context': string[:200]
                        })
            
            # Check for VM detection
            vm_indicators = [
                'vmware', 'virtualbox', 'qemu', 'xen', 'hyper-v',
                'sandbox', 'virtual machine', 'vm detection'
            ]
            
            for string in result.extracted_strings:
                string_lower = string.lower()
                for vm_indicator in vm_indicators:
                    if vm_indicator in string_lower:
                        techniques.append({
                            'type': 'vm_detection',
                            'technique': vm_indicator,
                            'context': string[:200]
                        })
            
            # Check for high entropy regions (possible packing/encryption)
            for region in result.memory_regions:
                if region.entropy_analysis.get('entropy', 0) > 7.5:
                    techniques.append({
                        'type': 'high_entropy_region',
                        'technique': 'possible_packing_encryption',
                        'address': hex(region.start_address),
                        'entropy': region.entropy_analysis.get('entropy', 0)
                    })
            
        except Exception as e:
            self.logger.debug(f"Anti-analysis detection failed: {e}")
        
        return techniques[:50]  # Limit techniques

    def _extract_behavioral_artifacts(self, result: MemoryDumpAnalysisResult) -> List[Dict[str, Any]]:
        """Extract behavioral artifacts and indicators"""
        artifacts = []
        
        try:
            # Check for persistence mechanisms
            persistence_indicators = [
                'autorun', 'startup', 'service', 'scheduled task', 'registry run',
                'wmi event', 'dll hijacking', 'com hijacking'
            ]
            
            for string in result.extracted_strings:
                string_lower = string.lower()
                for indicator in persistence_indicators:
                    if indicator in string_lower:
                        artifacts.append({
                            'type': 'persistence_mechanism',
                            'indicator': indicator,
                            'context': string[:200]
                        })
            
            # Check for lateral movement indicators
            lateral_movement = [
                'psexec', 'wmiexec', 'powershell', 'remote desktop', 'ssh',
                'smb', 'admin$', 'c$', 'ipc$'
            ]
            
            for string in result.extracted_strings:
                string_lower = string.lower()
                for movement in lateral_movement:
                    if movement in string_lower:
                        artifacts.append({
                            'type': 'lateral_movement',
                            'indicator': movement,
                            'context': string[:200]
                        })
            
            # Check for data exfiltration indicators
            exfiltration_indicators = [
                'ftp upload', 'http post', 'email', 'cloud storage', 'dropbox',
                'onedrive', 'google drive', 'exfiltrate', 'steal', 'copy'
            ]
            
            for string in result.extracted_strings:
                string_lower = string.lower()
                for indicator in exfiltration_indicators:
                    if indicator in string_lower:
                        artifacts.append({
                            'type': 'data_exfiltration',
                            'indicator': indicator,
                            'context': string[:200]
                        })
            
        except Exception as e:
            self.logger.debug(f"Behavioral artifact extraction failed: {e}")
        
        return artifacts[:100]  # Limit artifacts

    def _load_yara_rules(self):
        """Load YARA rules for pattern matching"""
        if not YARA_AVAILABLE:
            return
        
        try:
            # Define basic YARA rules for memory analysis
            rules_source = '''
            rule Shellcode_Pattern {
                strings:
                    $a = { 31 C0 }  // XOR EAX, EAX
                    $b = { 50 68 }  // PUSH, PUSH
                    $c = { EB FE }  // JMP $
                    $d = { 90 90 90 90 }  // NOP sled
                condition:
                    any of them
            }
            
            rule API_Hashing {
                strings:
                    $a = { 13 8B 6F 87 }  // Common API hash
                    $b = "GetProcAddress"
                    $c = "LoadLibraryA"
                condition:
                    any of them
            }
            
            rule Process_Injection {
                strings:
                    $a = "VirtualAllocEx"
                    $b = "WriteProcessMemory"
                    $c = "CreateRemoteThread"
                    $d = "SetThreadContext"
                condition:
                    2 of them
            }
            
            rule Packer_Signatures {
                strings:
                    $upx = "UPX!"
                    $aspack = "ASPack"
                    $pecompact = "PECompact"
                    $vmprotect = "VMProtect"
                condition:
                    any of them
            }
            '''
            
            self.yara_rules = yara.compile(source=rules_source)
            self.logger.info("YARA rules loaded successfully")
            
        except Exception as e:
            self.logger.warning(f"Failed to load YARA rules: {e}")
            self.yara_rules = None

    def _run_yara_analysis(self, dump_path: str, result: MemoryDumpAnalysisResult):
        """Run YARA pattern matching on memory dump"""
        if not self.yara_rules:
            return
        
        try:
            # Run YARA on entire dump file
            matches = self.yara_rules.match(dump_path)
            
            for match in matches:
                signature = {
                    'rule_name': match.rule,
                    'namespace': match.namespace,
                    'tags': list(match.tags),
                    'strings': []
                }
                
                # Extract matching strings
                for string_match in match.strings:
                    signature['strings'].append({
                        'identifier': string_match.identifier,
                        'offset': string_match.instances[0].offset if string_match.instances else 0,
                        'length': string_match.instances[0].length if string_match.instances else 0
                    })
                
                result.exploit_signatures.append(signature)
            
            self.logger.info(f"YARA analysis found {len(matches)} matches")
            
        except Exception as e:
            self.logger.warning(f"YARA analysis failed: {e}")

    def _calculate_confidence_score(self, result: MemoryDumpAnalysisResult) -> float:
        """Calculate confidence score for analysis results"""
        try:
            score = 0.0
            max_score = 10.0
            
            # Base score for successful analysis
            if not result.error_messages:
                score += 2.0
            
            # Score based on artifacts found
            if result.extracted_strings:
                score += min(len(result.extracted_strings) / 1000, 2.0)
            
            if result.memory_regions:
                score += min(len(result.memory_regions) / 100, 2.0)
            
            if result.crypto_artifacts:
                score += min(len(result.crypto_artifacts) / 10, 1.0)
            
            if result.network_artifacts:
                score += min(len(result.network_artifacts) / 10, 1.0)
            
            # Score based on analysis depth
            if result.processes:
                score += min(len(result.processes) / 10, 1.0)
            
            if result.heap_analyses or result.stack_analyses:
                score += 1.0
            
            # Penalty for errors
            score -= min(len(result.error_messages) * 0.5, 2.0)
            
            return max(0.0, min(score, max_score))
            
        except Exception:
            return 0.0

    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file for caching"""
        try:
            hasher = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return str(os.path.getmtime(file_path))  # Fallback to mtime

    def export_analysis_report(
        self,
        result: MemoryDumpAnalysisResult,
        output_path: str,
        format_type: str = "json"
    ) -> Tuple[bool, str]:
        """
        Export comprehensive analysis results to a report
        
        Args:
            result: Analysis results to export
            output_path: Path to save the report
            format_type: Format for the report (json, html, txt)
            
        Returns:
            Tuple of (success, message)
        """
        try:
            if format_type.lower() == "json":
                return self._export_json_report(result, output_path)
            elif format_type.lower() == "html":
                return self._export_html_report(result, output_path)
            elif format_type.lower() == "txt":
                return self._export_text_report(result, output_path)
            else:
                return False, f"Unsupported format: {format_type}"
                
        except Exception as e:
            return False, f"Export failed: {e}"

    def _export_json_report(self, result: MemoryDumpAnalysisResult, output_path: str) -> Tuple[bool, str]:
        """Export analysis results as JSON"""
        try:
            report_data = {
                "metadata": {
                    "dump_path": result.dump_path,
                    "dump_format": result.dump_format.value,
                    "architecture": result.architecture.value,
                    "dump_size": result.dump_size,
                    "analysis_timestamp": result.analysis_timestamp,
                    "analysis_duration": result.analysis_duration,
                    "confidence_score": result.confidence_score,
                    "security_risk_score": result.security_risk_score
                },
                "summary": {
                    "total_processes": len(result.processes),
                    "total_memory_regions": len(result.memory_regions),
                    "code_injections_detected": len(result.code_injections),
                    "heap_corruptions": len([h for h in result.heap_analyses if h.has_corruption]),
                    "stack_overflows": len([s for s in result.stack_analyses if s.has_overflow_signs]),
                    "exploit_signatures": len(result.exploit_signatures),
                    "anti_analysis_techniques": len(result.anti_analysis_techniques)
                },
                "processes": [
                    {
                        "process_id": proc.process_id,
                        "process_name": proc.process_name,
                        "base_address": hex(proc.base_address),
                        "total_memory_size": proc.total_memory_size,
                        "executable_regions": proc.executable_regions_count,
                        "suspicious_regions": len(proc.suspicious_regions),
                        "injected_code_regions": len(proc.injected_code)
                    }
                    for proc in result.processes
                ],
                "memory_regions": [
                    {
                        "start_address": hex(region.start_address),
                        "end_address": hex(region.end_address),
                        "size": region.size,
                        "type": region.region_type.value,
                        "permissions": region.permissions,
                        "entropy": region.entropy_analysis.get('entropy', 0),
                        "patterns_found": region.patterns_found,
                        "strings_count": len(region.strings),
                        "has_shellcode_characteristics": region.has_shellcode_characteristics
                    }
                    for region in result.memory_regions[:100]  # Limit regions in report
                ],
                "code_injections": [
                    {
                        "injection_type": inj.injection_type,
                        "target_process": inj.target_process,
                        "injection_address": hex(inj.injection_address),
                        "injection_size": inj.injection_size,
                        "severity_score": inj.severity_score,
                        "shellcode_detected": inj.shellcode_detected,
                        "dll_injection": inj.dll_injection,
                        "process_hollowing": inj.process_hollowing
                    }
                    for inj in result.code_injections
                ],
                "heap_analyses": [
                    {
                        "heap_base": hex(heap.heap_base),
                        "heap_size": heap.heap_size,
                        "has_corruption": heap.has_corruption,
                        "vulnerability_score": heap.vulnerability_score,
                        "corrupted_chunks": len(heap.corrupted_chunks),
                        "use_after_free_indicators": len(heap.use_after_free_indicators),
                        "heap_spray_patterns": len(heap.heap_spray_patterns)
                    }
                    for heap in result.heap_analyses
                ],
                "stack_analyses": [
                    {
                        "stack_base": hex(stack.stack_base),
                        "stack_size": stack.stack_size,
                        "has_overflow_signs": stack.has_overflow_signs,
                        "has_rop_chain": stack.has_rop_chain,
                        "rop_gadgets": len(stack.rop_gadgets),
                        "overflow_indicators": len(stack.overflow_indicators)
                    }
                    for stack in result.stack_analyses
                ],
                "forensic_artifacts": {
                    "total_strings": len(result.extracted_strings),
                    "crypto_artifacts": len(result.crypto_artifacts),
                    "network_artifacts": len(result.network_artifacts),
                    "file_artifacts": len(result.file_artifacts),
                    "registry_artifacts": len(result.registry_artifacts)
                },
                "security_analysis": {
                    "exploit_signatures": result.exploit_signatures,
                    "anti_analysis_techniques": result.anti_analysis_techniques,
                    "behavioral_artifacts": result.behavioral_artifacts[:20]  # Limit in report
                },
                "errors": result.error_messages
            }
            
            with open(output_path, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)
            
            return True, f"JSON report exported to {output_path}"
            
        except Exception as e:
            return False, f"JSON export failed: {e}"

    def _export_text_report(self, result: MemoryDumpAnalysisResult, output_path: str) -> Tuple[bool, str]:
        """Export analysis results as text summary"""
        try:
            with open(output_path, 'w') as f:
                f.write("=" * 80 + "\n")
                f.write("COMPREHENSIVE MEMORY DUMP ANALYSIS REPORT\n")
                f.write("=" * 80 + "\n\n")
                
                # Metadata
                f.write("ANALYSIS METADATA\n")
                f.write("-" * 40 + "\n")
                f.write(f"Dump Path: {result.dump_path}\n")
                f.write(f"Dump Format: {result.dump_format.value}\n")
                f.write(f"Architecture: {result.architecture.value}\n")
                f.write(f"Dump Size: {result.dump_size:,} bytes\n")
                f.write(f"Analysis Duration: {result.analysis_duration:.2f} seconds\n")
                f.write(f"Confidence Score: {result.confidence_score:.1f}/10.0\n")
                f.write(f"Security Risk Score: {result.security_risk_score:.1f}/10.0\n\n")
                
                # Summary
                f.write("ANALYSIS SUMMARY\n")
                f.write("-" * 40 + "\n")
                f.write(f"Processes Analyzed: {len(result.processes)}\n")
                f.write(f"Memory Regions: {len(result.memory_regions)}\n")
                f.write(f"Code Injections: {len(result.code_injections)}\n")
                f.write(f"Heap Corruptions: {len([h for h in result.heap_analyses if h.has_corruption])}\n")
                f.write(f"Stack Overflows: {len([s for s in result.stack_analyses if s.has_overflow_signs])}\n")
                f.write(f"Exploit Signatures: {len(result.exploit_signatures)}\n")
                f.write(f"Anti-Analysis Techniques: {len(result.anti_analysis_techniques)}\n\n")
                
                # Security Findings
                if result.has_code_injection or result.has_heap_corruption or result.has_exploits:
                    f.write("CRITICAL SECURITY FINDINGS\n")
                    f.write("-" * 40 + "\n")
                    
                    if result.has_code_injection:
                        f.write("⚠️  CODE INJECTION DETECTED\n")
                        for injection in result.code_injections[:5]:
                            f.write(f"   - {injection.injection_type} in {injection.target_process}\n")
                            f.write(f"     Address: {hex(injection.injection_address)}, Size: {injection.injection_size}\n")
                    
                    if result.has_heap_corruption:
                        f.write("⚠️  HEAP CORRUPTION DETECTED\n")
                        for heap in result.heap_analyses:
                            if heap.has_corruption:
                                f.write(f"   - Heap at {hex(heap.heap_base)}, Vulnerability Score: {heap.vulnerability_score:.1f}\n")
                    
                    if result.has_exploits:
                        f.write("⚠️  EXPLOIT SIGNATURES FOUND\n")
                        for sig in result.exploit_signatures[:5]:
                            f.write(f"   - {sig.get('type', 'unknown')}: {sig.get('description', 'No description')}\n")
                    
                    f.write("\n")
                
                # Forensic Artifacts
                f.write("FORENSIC ARTIFACTS\n")
                f.write("-" * 40 + "\n")
                f.write(f"Extracted Strings: {len(result.extracted_strings):,}\n")
                f.write(f"Network Artifacts: {len(result.network_artifacts)}\n")
                f.write(f"File Artifacts: {len(result.file_artifacts)}\n")
                f.write(f"Crypto Artifacts: {len(result.crypto_artifacts)}\n")
                f.write(f"Registry Artifacts: {len(result.registry_artifacts)}\n\n")
                
                # Errors
                if result.error_messages:
                    f.write("ERRORS AND WARNINGS\n")
                    f.write("-" * 40 + "\n")
                    for error in result.error_messages:
                        f.write(f"• {error}\n")
                    f.write("\n")
                
                f.write("=" * 80 + "\n")
                f.write("End of Report\n")
            
            return True, f"Text report exported to {output_path}"
            
        except Exception as e:
            return False, f"Text export failed: {e}"

    def _export_html_report(self, result: MemoryDumpAnalysisResult, output_path: str) -> Tuple[bool, str]:
        """Export analysis results as HTML report"""
        try:
            html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Memory Dump Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #2c3e50; color: white; padding: 20px; text-align: center; }}
        .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; }}
        .critical {{ background-color: #ffebee; border-left: 5px solid #f44336; }}
        .warning {{ background-color: #fff3e0; border-left: 5px solid #ff9800; }}
        .info {{ background-color: #e3f2fd; border-left: 5px solid #2196f3; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f5f5f5; }}
        .metric {{ font-size: 24px; font-weight: bold; color: #2c3e50; }}
        .score-high {{ color: #f44336; }}
        .score-medium {{ color: #ff9800; }}
        .score-low {{ color: #4caf50; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Comprehensive Memory Dump Analysis Report</h1>
        <p>Generated on {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(result.analysis_timestamp))}</p>
    </div>
    
    <div class="section info">
        <h2>Analysis Overview</h2>
        <table>
            <tr><td><strong>Dump Path:</strong></td><td>{result.dump_path}</td></tr>
            <tr><td><strong>Format:</strong></td><td>{result.dump_format.value}</td></tr>
            <tr><td><strong>Architecture:</strong></td><td>{result.architecture.value}</td></tr>
            <tr><td><strong>Size:</strong></td><td>{result.dump_size:,} bytes</td></tr>
            <tr><td><strong>Analysis Duration:</strong></td><td>{result.analysis_duration:.2f} seconds</td></tr>
            <tr><td><strong>Confidence Score:</strong></td><td class="metric">{result.confidence_score:.1f}/10.0</td></tr>
            <tr><td><strong>Security Risk Score:</strong></td><td class="metric score-{('high' if result.security_risk_score > 7 else 'medium' if result.security_risk_score > 4 else 'low')}">{result.security_risk_score:.1f}/10.0</td></tr>
        </table>
    </div>
    
    <div class="section">
        <h2>Analysis Summary</h2>
        <table>
            <tr><td>Processes Analyzed</td><td class="metric">{len(result.processes)}</td></tr>
            <tr><td>Memory Regions</td><td class="metric">{len(result.memory_regions)}</td></tr>
            <tr><td>Code Injections</td><td class="metric">{len(result.code_injections)}</td></tr>
            <tr><td>Heap Corruptions</td><td class="metric">{len([h for h in result.heap_analyses if h.has_corruption])}</td></tr>
            <tr><td>Stack Overflows</td><td class="metric">{len([s for s in result.stack_analyses if s.has_overflow_signs])}</td></tr>
            <tr><td>Exploit Signatures</td><td class="metric">{len(result.exploit_signatures)}</td></tr>
        </table>
    </div>
    """
            
            # Add security findings if any
            if result.has_code_injection or result.has_heap_corruption or result.has_exploits:
                html_content += '<div class="section critical"><h2>⚠️ Critical Security Findings</h2><ul>'
                
                for injection in result.code_injections[:5]:
                    html_content += f'<li><strong>Code Injection:</strong> {injection.injection_type} in {injection.target_process}</li>'
                
                for heap in result.heap_analyses:
                    if heap.has_corruption:
                        html_content += f'<li><strong>Heap Corruption:</strong> At {hex(heap.heap_base)}, Score: {heap.vulnerability_score:.1f}</li>'
                
                for sig in result.exploit_signatures[:5]:
                    html_content += f'<li><strong>Exploit Signature:</strong> {sig.get("type", "unknown")}</li>'
                
                html_content += '</ul></div>'
            
            # Add forensic artifacts summary
            html_content += f"""
    <div class="section">
        <h2>Forensic Artifacts</h2>
        <table>
            <tr><td>Extracted Strings</td><td>{len(result.extracted_strings):,}</td></tr>
            <tr><td>Network Artifacts</td><td>{len(result.network_artifacts)}</td></tr>
            <tr><td>File Artifacts</td><td>{len(result.file_artifacts)}</td></tr>
            <tr><td>Crypto Artifacts</td><td>{len(result.crypto_artifacts)}</td></tr>
            <tr><td>Registry Artifacts</td><td>{len(result.registry_artifacts)}</td></tr>
        </table>
    </div>
    """
            
            # Add errors if any
            if result.error_messages:
                html_content += '<div class="section warning"><h2>Errors and Warnings</h2><ul>'
                for error in result.error_messages:
                    html_content += f'<li>{error}</li>'
                html_content += '</ul></div>'
            
            html_content += """
    <div class="section">
        <h2>Report Information</h2>
        <p>This report was generated by the Intellicrack Memory Dump Analyzer.</p>
        <p>For detailed analysis data, please refer to the JSON export.</p>
    </div>
</body>
</html>
"""
            
            with open(output_path, 'w') as f:
                f.write(html_content)
            
            return True, f"HTML report exported to {output_path}"
            
        except Exception as e:
            return False, f"HTML export failed: {e}"

    def get_analysis_statistics(self) -> Dict[str, Any]:
        """Get statistics about performed analyses"""
        return {
            "total_dumps_processed": len(self.processed_dumps),
            "cached_analyses": len(self.analysis_cache),
            "capabilities": {
                "numpy_available": NUMPY_AVAILABLE,
                "capstone_available": CAPSTONE_AVAILABLE,
                "yara_available": YARA_AVAILABLE,
                "volatility3_available": hasattr(self.memory_forensics, 'volatility_available') and self.memory_forensics.volatility_available
            },
            "supported_architectures": [arch.value for arch in MemoryArchitecture],
            "supported_formats": [fmt.value for fmt in MemoryDumpFormat]
        }


# Singleton instance
_memory_dump_analyzer: Optional[MemoryDumpAnalyzer] = None


def get_memory_dump_analyzer() -> Optional[MemoryDumpAnalyzer]:
    """Get or create the memory dump analyzer singleton"""
    global _memory_dump_analyzer
    if _memory_dump_analyzer is None:
        try:
            _memory_dump_analyzer = MemoryDumpAnalyzer()
        except Exception as e:
            logger.error(f"Failed to initialize memory dump analyzer: {e}")
            return None
    return _memory_dump_analyzer


def analyze_memory_dump_comprehensive(
    dump_path: str,
    dump_format: Optional[str] = None,
    deep_analysis: bool = True
) -> Optional[MemoryDumpAnalysisResult]:
    """Quick comprehensive memory dump analysis function for integration"""
    analyzer = get_memory_dump_analyzer()
    if analyzer:
        format_enum = None
        if dump_format:
            try:
                format_enum = MemoryDumpFormat(dump_format.lower())
            except ValueError:
                pass
        
        return analyzer.analyze_memory_dump(
            dump_path,
            dump_format=format_enum,
            deep_analysis=deep_analysis
        )
    return None