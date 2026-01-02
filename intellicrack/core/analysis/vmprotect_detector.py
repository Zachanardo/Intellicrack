"""Production VMProtect Detection and Analysis with Advanced Instruction-Level Analysis.

Comprehensive detection system for VMProtect 1.x, 2.x, and 3.x protected binaries:
- Instruction-level semantic analysis using Capstone disassembly
- VM handler pattern recognition through opcode sequence analysis
- Control flow graph recovery for virtualized blocks
- Polymorphic mutation detection via instruction normalization
- Multi-architecture support (x86, x64, ARM) with proper platform detection
- Handler table and dispatcher identification through disassembly analysis
- All protection levels (Lite, Standard, Ultra) with confidence scoring

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from __future__ import annotations

import mmap
import struct
import types
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from intellicrack.utils.logger import get_logger

logger = get_logger(__name__)

pefile: types.ModuleType | None

try:
    import pefile as _pefile_module

    pefile = _pefile_module
    PEFILE_AVAILABLE = True
except ImportError:
    pefile = None
    PEFILE_AVAILABLE = False
    logger.debug("pefile not available - VMProtect detection limited")

try:
    from capstone import (
        CS_ARCH_ARM,
        CS_ARCH_ARM64,
        CS_ARCH_X86,
        CS_GRP_JUMP,
        CS_MODE_32,
        CS_MODE_64,
        CS_MODE_ARM,
        CS_OP_IMM,
        CS_OP_MEM,
        Cs,
    )
    from capstone.x86 import (
        X86_OP_IMM,
        X86_OP_MEM,
        X86_OP_REG,
    )

    try:
        from capstone.arm import (
            ARM_OP_IMM,
            ARM_OP_MEM,
            ARM_OP_REG,
        )

        ARM_AVAILABLE = True
    except ImportError:
        ARM_AVAILABLE = False

    try:
        from capstone.arm64 import (
            ARM64_OP_IMM,
            ARM64_OP_MEM,
            ARM64_OP_REG,
        )

        ARM64_AVAILABLE = True
    except ImportError:
        ARM64_AVAILABLE = False

    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False
    ARM_AVAILABLE = False
    ARM64_AVAILABLE = False
    logger.debug("Capstone not available - VMProtect disassembly disabled")

if TYPE_CHECKING:
    try:
        from capstone import CsInsn
    except ImportError:
        pass


class VMProtectLevel(Enum):
    """VMProtect protection levels with increasing obfuscation strength."""

    LITE = "lite"
    STANDARD = "standard"
    ULTRA = "ultra"
    UNKNOWN = "unknown"


class VMProtectMode(Enum):
    """VMProtect virtualization modes affecting code transformation."""

    VIRTUALIZATION = "virtualization"
    MUTATION = "mutation"
    HYBRID = "hybrid"


@dataclass
class InstructionPattern:
    """Semantic instruction pattern for VMProtect handler recognition."""

    mnemonic_sequence: list[str]
    requires_memory_access: bool
    requires_register_usage: list[str]
    pattern_type: str
    confidence: float
    min_instructions: int = 3
    max_instructions: int = 15


@dataclass
class VMHandler:
    """VMProtect virtual machine handler with comprehensive analysis."""

    offset: int
    size: int
    handler_type: str
    pattern: bytes
    confidence: float
    opcodes: list[tuple[int, str]] = field(default_factory=list)
    xrefs: list[int] = field(default_factory=list)
    complexity: int = 0
    branches: int = 0
    memory_ops: int = 0
    semantic_signature: str = ""
    normalized_instructions: list[str] = field(default_factory=list)


@dataclass
class VirtualizedRegion:
    """Region of virtualized code with control flow characteristics."""

    start_offset: int
    end_offset: int
    vm_entry: int
    vm_exit: int | None
    handlers_used: set[str]
    control_flow_complexity: float
    mutation_detected: bool = False
    protection_level: VMProtectLevel = VMProtectLevel.UNKNOWN
    basic_blocks: int = 0
    indirect_jumps: int = 0
    dispatcher_calls: int = 0


@dataclass
class ControlFlowGraph:
    """Recovered control flow graph for virtualized region."""

    basic_blocks: dict[int, list[int]]
    edges: list[tuple[int, int]]
    entry_points: list[int]
    exit_points: list[int]
    complexity_score: float
    indirect_branches: int
    vm_context_switches: int


@dataclass
class VMProtectDetection:
    """Complete VMProtect detection results with analysis artifacts."""

    detected: bool
    version: str
    protection_level: VMProtectLevel
    mode: VMProtectMode
    architecture: str
    handlers: list[VMHandler]
    virtualized_regions: list[VirtualizedRegion]
    dispatcher_offset: int | None
    handler_table_offset: int | None
    confidence: float
    technical_details: dict[str, Any] = field(default_factory=dict)
    bypass_recommendations: list[str] = field(default_factory=list)
    control_flow_graphs: dict[int, ControlFlowGraph] = field(default_factory=dict)


class VMProtectDetector:
    """Production-ready VMProtect detector with instruction-level analysis.

    Implements comprehensive detection using:
    - Semantic instruction pattern matching instead of static byte patterns
    - Control flow graph recovery for obfuscated code
    - Polymorphic mutation detection through instruction normalization
    - Multi-architecture support with architecture-specific analysis
    - Handler table identification through disassembly analysis
    """

    VMP_SEMANTIC_PATTERNS_X86: list[InstructionPattern] = [
        InstructionPattern(
            mnemonic_sequence=["push", "push", "push", "mov", "mov"],
            requires_memory_access=True,
            requires_register_usage=["ebp", "esp"],
            pattern_type="vm_entry_prologue",
            confidence=0.92,
            min_instructions=5,
            max_instructions=10,
        ),
        InstructionPattern(
            mnemonic_sequence=["push", "push", "mov"],
            requires_memory_access=True,
            requires_register_usage=[],
            pattern_type="vm_entry_prologue_v3",
            confidence=0.88,
            min_instructions=3,
            max_instructions=8,
        ),
        InstructionPattern(
            mnemonic_sequence=["pushfd", "pushad"],
            requires_memory_access=False,
            requires_register_usage=[],
            pattern_type="context_save",
            confidence=0.95,
            min_instructions=2,
            max_instructions=4,
        ),
        InstructionPattern(
            mnemonic_sequence=["push", "push"],
            requires_memory_access=False,
            requires_register_usage=[],
            pattern_type="context_save_v3",
            confidence=0.85,
            min_instructions=2,
            max_instructions=6,
        ),
        InstructionPattern(
            mnemonic_sequence=["mov", "add", "mov"],
            requires_memory_access=True,
            requires_register_usage=["eax"],
            pattern_type="vm_ip_increment",
            confidence=0.85,
            min_instructions=3,
            max_instructions=6,
        ),
        InstructionPattern(
            mnemonic_sequence=["mov", "add"],
            requires_memory_access=True,
            requires_register_usage=[],
            pattern_type="vm_ip_increment_v3",
            confidence=0.80,
            min_instructions=2,
            max_instructions=5,
        ),
        InstructionPattern(
            mnemonic_sequence=["jmp"],
            requires_memory_access=True,
            requires_register_usage=[],
            pattern_type="handler_dispatch",
            confidence=0.90,
            min_instructions=1,
            max_instructions=3,
        ),
        InstructionPattern(
            mnemonic_sequence=["movzx", "inc", "mov"],
            requires_memory_access=True,
            requires_register_usage=["esi"],
            pattern_type="vm_fetch_byte",
            confidence=0.88,
            min_instructions=3,
            max_instructions=5,
        ),
        InstructionPattern(
            mnemonic_sequence=["movzx", "inc"],
            requires_memory_access=True,
            requires_register_usage=[],
            pattern_type="vm_fetch_byte_v3",
            confidence=0.82,
            min_instructions=2,
            max_instructions=4,
        ),
        InstructionPattern(
            mnemonic_sequence=["popad", "popfd", "ret"],
            requires_memory_access=False,
            requires_register_usage=[],
            pattern_type="vm_exit_epilogue",
            confidence=0.94,
            min_instructions=3,
            max_instructions=5,
        ),
        InstructionPattern(
            mnemonic_sequence=["pop", "pop", "ret"],
            requires_memory_access=False,
            requires_register_usage=[],
            pattern_type="vm_exit_epilogue_v3",
            confidence=0.87,
            min_instructions=3,
            max_instructions=6,
        ),
    ]

    VMP_SEMANTIC_PATTERNS_X64: list[InstructionPattern] = [
        InstructionPattern(
            mnemonic_sequence=["mov", "mov", "mov", "lea"],
            requires_memory_access=True,
            requires_register_usage=["rsp", "rbp"],
            pattern_type="vm_entry_prologue_x64",
            confidence=0.92,
            min_instructions=4,
            max_instructions=10,
        ),
        InstructionPattern(
            mnemonic_sequence=["mov", "mov", "lea"],
            requires_memory_access=True,
            requires_register_usage=[],
            pattern_type="vm_entry_prologue_x64_v3",
            confidence=0.87,
            min_instructions=3,
            max_instructions=8,
        ),
        InstructionPattern(
            mnemonic_sequence=["pushfq", "push", "push", "push"],
            requires_memory_access=False,
            requires_register_usage=[],
            pattern_type="context_save_x64",
            confidence=0.93,
            min_instructions=4,
            max_instructions=8,
        ),
        InstructionPattern(
            mnemonic_sequence=["push", "push", "push"],
            requires_memory_access=False,
            requires_register_usage=[],
            pattern_type="context_save_x64_v3",
            confidence=0.84,
            min_instructions=3,
            max_instructions=7,
        ),
        InstructionPattern(
            mnemonic_sequence=["mov", "add", "mov"],
            requires_memory_access=True,
            requires_register_usage=["rax", "rcx"],
            pattern_type="vm_ip_increment_x64",
            confidence=0.85,
            min_instructions=3,
            max_instructions=6,
        ),
        InstructionPattern(
            mnemonic_sequence=["mov", "add"],
            requires_memory_access=True,
            requires_register_usage=[],
            pattern_type="vm_ip_increment_x64_v3",
            confidence=0.79,
            min_instructions=2,
            max_instructions=5,
        ),
        InstructionPattern(
            mnemonic_sequence=["jmp"],
            requires_memory_access=True,
            requires_register_usage=[],
            pattern_type="handler_dispatch_x64",
            confidence=0.90,
            min_instructions=1,
            max_instructions=3,
        ),
        InstructionPattern(
            mnemonic_sequence=["pop", "pop", "pop", "popfq"],
            requires_memory_access=False,
            requires_register_usage=[],
            pattern_type="vm_exit_epilogue_x64",
            confidence=0.94,
            min_instructions=4,
            max_instructions=6,
        ),
        InstructionPattern(
            mnemonic_sequence=["pop", "pop", "ret"],
            requires_memory_access=False,
            requires_register_usage=[],
            pattern_type="vm_exit_epilogue_x64_v3",
            confidence=0.86,
            min_instructions=3,
            max_instructions=5,
        ),
    ]

    VMP_MUTATION_INSTRUCTION_PATTERNS: list[tuple[str, float]] = [
        ("nop", 0.70),
        ("xchg eax, eax", 0.75),
        ("xchg rax, rax", 0.75),
        ("mov eax, eax", 0.73),
        ("mov rax, rax", 0.73),
        ("inc+dec", 0.72),
        ("push+pop", 0.78),
        ("lea", 0.68),
    ]

    VMP_STRING_INDICATORS: list[str] = [
        "vmp",
        "vmprotect",
        "oreans",
        "virtualizer",
        "protected by vmprotect",
        ".vmp0",
        ".vmp1",
        ".vmp2",
    ]

    VMP_HANDLER_SIGNATURES_X86: dict[str, bytes] = {
        "vm_entry_prologue": b"\x55\x8b\xec\x53\x56\x57\x8b\x7d\x08",
        "context_save": b"\x9c\x60",
        "handler_dispatch": b"\xff\x24\x85",
        "vm_exit_epilogue": b"\x61\x9d",
    }

    VMP_HANDLER_SIGNATURES_X64: dict[str, bytes] = {
        "vm_entry_prologue_x64": b"\x48\x89\x5c\x24\x08\x48\x89\x74\x24\x10",
        "context_save_x64": b"\x9c\x50\x53\x51",
        "handler_dispatch_x64": b"\xff\x24\xc5",
        "vm_exit_epilogue_x64": b"\x5f\x5e\x5a\x59\x5b\x58\x9d",
    }

    VMP_MUTATION_PATTERNS: dict[str, bytes] = {
        "nop_sled": b"\x90\x90\x90",
        "xchg_nop": b"\x87\xc0",
        "mov_self": b"\x89\xc0",
        "xchg_nop_x64": b"\x48\x87\xc0",
        "push_pop": b"\x50\x58",
    }

    def __init__(self) -> None:
        """Initialize VMProtect detector with Capstone disassemblers.

        Sets up architecture-specific disassemblers and enables detailed
        instruction analysis for semantic pattern matching.
        """
        self.cs_x86: Cs | None = None
        self.cs_x64: Cs | None = None
        self.cs_arm: Cs | None = None
        self.cs_arm64: Cs | None = None

        if CAPSTONE_AVAILABLE:
            self.cs_x86 = Cs(CS_ARCH_X86, CS_MODE_32)
            self.cs_x64 = Cs(CS_ARCH_X86, CS_MODE_64)
            self.cs_arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
            self.cs_arm64 = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

            self.cs_x86.detail = True
            self.cs_x64.detail = True
            self.cs_arm.detail = True
            self.cs_arm64.detail = True

    def detect(self, binary_path: str) -> VMProtectDetection:
        """Perform comprehensive VMProtect detection with instruction-level analysis.

        Analyzes binary for VMProtect protection using semantic pattern matching,
        control flow recovery, and mutation detection to identify virtualized regions
        and protection characteristics across all VMProtect versions.

        Args:
            binary_path: Path to the PE/ELF binary file to analyze.

        Returns:
            VMProtectDetection: Complete detection results including handlers, regions,
                control flow graphs, confidence scoring, and bypass recommendations.
        """
        detection = VMProtectDetection(
            detected=False,
            version="Unknown",
            protection_level=VMProtectLevel.UNKNOWN,
            mode=VMProtectMode.VIRTUALIZATION,
            architecture="unknown",
            handlers=[],
            virtualized_regions=[],
            dispatcher_offset=None,
            handler_table_offset=None,
            confidence=0.0,
        )

        try:
            file_size = Path(binary_path).stat().st_size
            large_file_threshold = 100 * 1024 * 1024

            if file_size > large_file_threshold:
                binary_data = self._read_with_mmap(binary_path)
            else:
                with open(binary_path, "rb") as f:
                    binary_data = f.read()

            if not self._is_pe(binary_data):
                logger.debug("Not a PE file, attempting generic binary analysis")
                return self._detect_generic_binary(binary_data, detection)

            detection.architecture = self._detect_architecture(binary_data)
            logger.debug("Detected architecture: %s", detection.architecture)

            section_analysis = self._analyze_sections(binary_data)
            detection.technical_details["sections"] = section_analysis

            handlers = self._detect_vm_handlers_semantic(binary_data, detection.architecture)
            detection.handlers = handlers
            logger.debug("Detected %d VM handlers", len(handlers))

            if handlers:
                detection.detected = True
                detection.confidence = max(detection.confidence, 0.7)

            if dispatcher := self._find_dispatcher_advanced(binary_data, detection.architecture):
                detection.dispatcher_offset = dispatcher
                detection.confidence = max(detection.confidence, 0.85)
                logger.debug("Located dispatcher at 0x%08x", dispatcher)

            if handler_table := self._find_handler_table_advanced(binary_data, detection.architecture):
                detection.handler_table_offset = handler_table
                detection.confidence = max(detection.confidence, 0.90)
                logger.debug("Located handler table at 0x%08x", handler_table)

            virtualized_regions = self._identify_virtualized_regions_advanced(
                binary_data, handlers, detection.architecture
            )
            detection.virtualized_regions = virtualized_regions
            logger.debug("Identified %d virtualized regions", len(virtualized_regions))

            if virtualized_regions:
                detection.confidence = max(detection.confidence, 0.92)

                for region in virtualized_regions:
                    cfg = self._recover_control_flow(binary_data, region, detection.architecture)
                    detection.control_flow_graphs[region.start_offset] = cfg

            mutation_analysis = self._detect_mutations_advanced(binary_data, detection.architecture)
            detection.technical_details["mutation_analysis"] = mutation_analysis
            mutation_score = mutation_analysis["score"]

            if mutation_score > 0.5:
                detection.mode = VMProtectMode.MUTATION if mutation_score > 0.8 else VMProtectMode.HYBRID

            detection.protection_level = self._determine_protection_level(
                handlers, virtualized_regions, mutation_score
            )

            detection.version = self._detect_version_advanced(binary_data, section_analysis, handlers)

            detection.bypass_recommendations = self._generate_bypass_recommendations(detection)

            if string_matches := self._scan_strings(binary_data):
                detection.detected = True
                detection.confidence = max(detection.confidence, 0.6)
                detection.technical_details["string_matches"] = string_matches

        except Exception as e:
            logger.exception("VMProtect detection failed: %s", e)
            detection.technical_details["error"] = str(e)

        return detection

    def _read_with_mmap(self, binary_path: str) -> bytes:
        """Read large binary file using memory-mapped I/O for efficiency.

        Args:
            binary_path: Path to binary file.

        Returns:
            bytes: Binary data (mapped view acts as bytes).
        """
        with open(binary_path, "rb") as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped:
                return bytes(mmapped)

    def _is_pe(self, data: bytes) -> bool:
        """Check if data is a PE file.

        Args:
            data: Binary data to validate.

        Returns:
            bool: True if data appears to be a PE executable.
        """
        return len(data) > 64 and data[:2] == b"MZ"

    def _detect_architecture(self, data: bytes) -> str:
        """Detect binary architecture from PE headers.

        Args:
            data: Binary data containing PE file.

        Returns:
            str: Architecture identifier (x86, x64, arm, or unknown).
        """
        if not PEFILE_AVAILABLE or pefile is None:
            return self._detect_architecture_fallback(data)

        try:
            pe = pefile.PE(data=data)
            machine = pe.FILE_HEADER.Machine

            arch_map = {
                0x014C: "x86",
                0x8664: "x64",
                0x01C0: "arm",
                0x01C4: "arm64",
                0xAA64: "arm64",
            }

            return arch_map.get(machine, f"unknown_0x{machine:04x}")
        except Exception:
            return self._detect_architecture_fallback(data)

    def _detect_architecture_fallback(self, data: bytes) -> str:
        """Fallback architecture detection through heuristic analysis.

        Args:
            data: Binary data to analyze.

        Returns:
            str: Best-guess architecture identifier.
        """
        if len(data) < 64:
            return "unknown"

        x64_indicators = [b"\x48\x8b", b"\x48\x89", b"\x48\x83", b"\x48\x8d"]
        x86_indicators = [b"\x55\x8b\xec", b"\x8b\x45", b"\xff\x15"]

        x64_count = sum(data.count(pattern) for pattern in x64_indicators)
        x86_count = sum(data.count(pattern) for pattern in x86_indicators)

        if x64_count > x86_count * 2:
            return "x64"
        if x86_count > 10:
            return "x86"

        return "unknown"

    def _detect_generic_binary(self, data: bytes, detection: VMProtectDetection) -> VMProtectDetection:
        """Attempt detection on non-PE binaries.

        Args:
            data: Binary data to analyze.
            detection: Partial detection results to populate.

        Returns:
            VMProtectDetection: Updated detection results.
        """
        detection.architecture = self._detect_architecture_fallback(data)

        if string_matches := self._scan_strings(data):
            detection.detected = True
            detection.confidence = 0.5
            detection.technical_details["string_matches"] = string_matches

        return detection

    def _analyze_sections(self, data: bytes) -> dict[str, Any]:
        """Analyze PE sections for VMProtect characteristics.

        Scans sections for VMProtect-specific names, high entropy regions,
        and suspicious memory protection flags.

        Args:
            data: Binary data containing PE file.

        Returns:
            dict[str, Any]: Section analysis with vmp_sections, entropy, and flags.
        """
        analysis: dict[str, Any] = {
            "vmp_sections": [],
            "high_entropy_sections": [],
            "suspicious_characteristics": [],
        }

        if not PEFILE_AVAILABLE or pefile is None:
            return analysis

        try:
            pe = pefile.PE(data=data)

            for section in pe.sections:
                section_name = section.Name.decode("utf-8", errors="ignore").rstrip("\x00")
                entropy = section.get_entropy()

                if any(vmp_str in section_name.lower() for vmp_str in [".vmp", "vmp0", "vmp1", "vmp2"]):
                    analysis["vmp_sections"].append(
                        {
                            "name": section_name,
                            "virtual_address": section.VirtualAddress,
                            "virtual_size": section.Misc_VirtualSize,
                            "raw_size": section.SizeOfRawData,
                            "entropy": entropy,
                            "characteristics": section.Characteristics,
                        }
                    )

                if entropy > 7.3:
                    analysis["high_entropy_sections"].append({"name": section_name, "entropy": entropy})

                if section.Characteristics & 0xE0000000 == 0xE0000000:
                    analysis["suspicious_characteristics"].append(
                        {
                            "name": section_name,
                            "flags": "CODE|READ|WRITE",
                            "characteristics": section.Characteristics,
                        }
                    )

            pe.close()

        except Exception as e:
            logger.debug("Section analysis failed: %s", e)

        return analysis

    def _detect_vm_handlers(self, data: bytes, architecture: str) -> list[VMHandler]:
        """Detect VM handlers using semantic analysis (backward compatibility wrapper).

        This method delegates to _detect_vm_handlers_semantic for backward compatibility
        with existing test suites while maintaining modern implementation.

        Args:
            data: Binary data to analyze.
            architecture: Target architecture (x86, x64, arm).

        Returns:
            list[VMHandler]: Detected handlers with semantic signatures.
        """
        return self._detect_vm_handlers_semantic(data, architecture)

    def _detect_vm_handlers_semantic(self, data: bytes, architecture: str) -> list[VMHandler]:
        """Detect VM handlers using semantic instruction pattern matching.

        Replaces static byte pattern matching with instruction-level analysis
        to identify VMProtect handlers through mnemonic sequences and register usage.

        Args:
            data: Binary data to analyze.
            architecture: Target architecture (x86, x64, arm).

        Returns:
            list[VMHandler]: Detected handlers with semantic signatures.
        """
        handlers: list[VMHandler] = []

        if not CAPSTONE_AVAILABLE:
            logger.warning("Capstone unavailable - using fallback pattern matching")
            return self._detect_vm_handlers_fallback(data, architecture)

        cs = self._get_disassembler(architecture)
        if cs is None:
            return handlers

        patterns = (
            self.VMP_SEMANTIC_PATTERNS_X64 if architecture == "x64" else self.VMP_SEMANTIC_PATTERNS_X86
        )

        scan_step = 16
        max_offset = len(data) - 1000

        for offset in range(0, max_offset, scan_step):
            chunk_size = min(512, len(data) - offset)

            try:
                instructions = list(cs.disasm(data[offset : offset + chunk_size], offset))

                if len(instructions) < 3:
                    continue

                for pattern in patterns:
                    if match := self._match_semantic_pattern(instructions, pattern, architecture):
                        handler = self._create_handler_from_match(
                            data, match["offset"], match["size"], pattern, architecture
                        )
                        handlers.append(handler)

            except Exception as e:
                logger.debug("Failed to analyze offset 0x%08x: %s", offset, e)
                continue

        handlers = self._deduplicate_handlers(handlers)
        logger.debug("Detected %d unique handlers after deduplication", len(handlers))

        return handlers

    def _get_disassembler(self, architecture: str) -> Cs | None:
        """Get appropriate Capstone disassembler for architecture.

        Args:
            architecture: Target architecture identifier.

        Returns:
            Cs | None: Capstone disassembler instance or None if unavailable.
        """
        arch_map = {
            "x86": self.cs_x86,
            "x64": self.cs_x64,
            "arm": self.cs_arm,
            "arm64": self.cs_arm64,
        }

        return arch_map.get(architecture)

    def _match_semantic_pattern(
        self, instructions: list["CsInsn"], pattern: InstructionPattern, architecture: str
    ) -> dict[str, Any] | None:
        """Match instruction sequence against semantic pattern.

        Performs semantic matching by comparing instruction mnemonics,
        register usage, and memory access patterns.

        Args:
            instructions: List of disassembled instructions to match.
            pattern: Semantic pattern to match against.
            architecture: Target architecture for register name validation.

        Returns:
            dict[str, Any] | None: Match details with offset and size if matched, None otherwise.
        """
        if len(instructions) < pattern.min_instructions:
            return None

        for start_idx in range(len(instructions) - pattern.min_instructions + 1):
            end_idx = min(start_idx + pattern.max_instructions, len(instructions))
            window = instructions[start_idx:end_idx]

            if self._check_mnemonic_sequence(window, pattern.mnemonic_sequence):
                if pattern.requires_memory_access and not self._has_memory_access(window):
                    continue

                if pattern.requires_register_usage and not self._uses_registers(
                    window, pattern.requires_register_usage
                ):
                    continue

                match_size = sum(insn.size for insn in window)
                return {
                    "offset": window[0].address,
                    "size": match_size,
                    "instructions": window,
                }

        return None

    def _check_mnemonic_sequence(self, instructions: list["CsInsn"], sequence: list[str]) -> bool:
        """Check if instruction mnemonics match expected sequence.

        Args:
            instructions: Instructions to check.
            sequence: Expected mnemonic sequence.

        Returns:
            bool: True if sequence matches (allowing gaps).
        """
        if not sequence:
            return True

        seq_idx = 0
        for insn in instructions:
            if seq_idx >= len(sequence):
                return True

            if insn.mnemonic == sequence[seq_idx]:
                seq_idx += 1

        return seq_idx >= len(sequence)

    def _has_memory_access(self, instructions: list["CsInsn"]) -> bool:
        """Check if instruction sequence contains memory access.

        Args:
            instructions: Instructions to check.

        Returns:
            bool: True if any instruction accesses memory.
        """
        for insn in instructions:
            if "[" in insn.op_str:
                return True

            if hasattr(insn, "operands"):
                for op in insn.operands:
                    if op.type == CS_OP_MEM:
                        return True
                    if op.type == X86_OP_MEM:
                        return True
                    if ARM_AVAILABLE and hasattr(op, "type"):
                        try:
                            if op.type == ARM_OP_MEM:
                                return True
                        except (NameError, AttributeError):
                            pass
                    if ARM64_AVAILABLE and hasattr(op, "type"):
                        try:
                            if op.type == ARM64_OP_MEM:
                                return True
                        except (NameError, AttributeError):
                            pass

        return False

    def _uses_registers(self, instructions: list["CsInsn"], registers: list[str]) -> bool:
        """Check if instruction sequence uses specified registers.

        Args:
            instructions: Instructions to check.
            registers: Required register names.

        Returns:
            bool: True if any required register is used.
        """
        if not registers:
            return True

        for insn in instructions:
            for reg in registers:
                if reg in insn.op_str.lower():
                    return True

        return False

    def _create_handler_from_match(
        self, data: bytes, offset: int, size: int, pattern: InstructionPattern, architecture: str
    ) -> VMHandler:
        """Create VMHandler object from pattern match.

        Args:
            data: Binary data containing handler.
            offset: Handler offset in binary.
            size: Handler size in bytes.
            pattern: Matched semantic pattern.
            architecture: Target architecture.

        Returns:
            VMHandler: Complete handler object with analysis metrics.
        """
        complexity_metrics = self._calculate_handler_complexity_advanced(data, offset, size, architecture)

        opcodes = self._extract_opcodes(data, offset, size, architecture)
        normalized = self._normalize_instructions(opcodes)
        semantic_sig = self._generate_semantic_signature(opcodes)

        xrefs = self._find_handler_xrefs(data, offset)

        handler = VMHandler(
            offset=offset,
            size=size,
            handler_type=pattern.pattern_type,
            pattern=data[offset : offset + min(16, size)],
            confidence=pattern.confidence * complexity_metrics["confidence_factor"],
            opcodes=opcodes,
            xrefs=xrefs,
            complexity=complexity_metrics["complexity"],
            branches=complexity_metrics["branches"],
            memory_ops=complexity_metrics["memory_ops"],
            semantic_signature=semantic_sig,
            normalized_instructions=normalized,
        )

        return handler

    def _calculate_handler_complexity_advanced(
        self, data: bytes, offset: int, size: int, architecture: str
    ) -> dict[str, Any]:
        """Calculate advanced handler complexity metrics.

        Args:
            data: Binary data containing handler.
            offset: Handler offset.
            size: Handler size.
            architecture: Target architecture.

        Returns:
            dict[str, Any]: Complexity metrics including confidence factor.
        """
        default_result: dict[str, Any] = {
            "complexity": 10,
            "branches": 0,
            "memory_ops": 0,
            "confidence_factor": 0.8,
        }

        if not CAPSTONE_AVAILABLE:
            return default_result

        cs = self._get_disassembler(architecture)
        if cs is None:
            return default_result

        try:
            complexity = 0
            instruction_count = 0
            unique_opcodes: set[str] = set()
            branches = 0
            memory_ops = 0
            arithmetic_ops = 0

            for insn in cs.disasm(data[offset : offset + size], offset):
                instruction_count += 1
                unique_opcodes.add(insn.mnemonic)

                if insn.mnemonic.startswith("j") or insn.mnemonic in ["call", "ret"]:
                    branches += 1
                    complexity += 3

                if "[" in insn.op_str:
                    memory_ops += 1
                    complexity += 2

                if insn.mnemonic in ["xor", "add", "sub", "mul", "div", "shl", "shr", "rol", "ror", "and", "or"]:
                    arithmetic_ops += 1
                    complexity += 1

            complexity += len(unique_opcodes) * 2
            complexity += instruction_count

            confidence_factor = min(1.0, 0.7 + (complexity / 200))

            return {
                "complexity": complexity,
                "branches": branches,
                "memory_ops": memory_ops,
                "arithmetic_ops": arithmetic_ops,
                "unique_opcodes": len(unique_opcodes),
                "instruction_count": instruction_count,
                "confidence_factor": confidence_factor,
            }

        except Exception:
            return default_result

    def _normalize_instructions(self, opcodes: list[tuple[int, str]]) -> list[str]:
        """Normalize instructions for mutation-resistant comparison.

        Converts instructions to canonical form by abstracting register names
        and immediate values to enable polymorphic variant detection.

        Args:
            opcodes: List of (address, instruction) tuples.

        Returns:
            list[str]: Normalized instruction representations.
        """
        normalized: list[str] = []

        for _addr, insn_str in opcodes:
            parts = insn_str.split()
            if not parts:
                continue

            mnemonic = parts[0]

            normalized_ops = "REG" if len(parts) > 1 else ""

            normalized.append(f"{mnemonic} {normalized_ops}".strip())

        return normalized

    def _generate_semantic_signature(self, opcodes: list[tuple[int, str]]) -> str:
        """Generate semantic signature from instruction sequence.

        Creates a compact signature representing the handler's semantic behavior
        by hashing normalized instruction patterns.

        Args:
            opcodes: List of (address, instruction) tuples.

        Returns:
            str: Semantic signature hash string.
        """
        if not opcodes:
            return ""

        mnemonics = [insn.split()[0] for _addr, insn in opcodes if insn.split()]
        signature = "-".join(mnemonics[:10])

        return signature

    def _deduplicate_handlers(self, handlers: list[VMHandler]) -> list[VMHandler]:
        """Remove duplicate handler detections.

        Args:
            handlers: List of detected handlers.

        Returns:
            list[VMHandler]: Deduplicated handler list.
        """
        if not handlers:
            return handlers

        unique: dict[str, VMHandler] = {}

        for handler in sorted(handlers, key=lambda h: h.confidence, reverse=True):
            key = f"{handler.offset}_{handler.handler_type}"

            if key not in unique:
                is_duplicate = False

                for existing_key, existing_handler in unique.items():
                    if abs(handler.offset - existing_handler.offset) < 32:
                        is_duplicate = True
                        break

                if not is_duplicate:
                    unique[key] = handler

        return list(unique.values())

    def _detect_vm_handlers_fallback(self, data: bytes, architecture: str) -> list[VMHandler]:
        """Fallback handler detection using byte patterns.

        Args:
            data: Binary data to scan.
            architecture: Target architecture.

        Returns:
            list[VMHandler]: Detected handlers using legacy pattern matching.
        """
        handlers: list[VMHandler] = []

        static_patterns_x86 = [
            (b"\x55\x8b\xec\x53\x56\x57\x8b\x7d\x08", "vm_entry_prologue", 0.85),
            (b"\x9c\x60", "context_save", 0.90),
            (b"\xff\x24\x85", "handler_dispatch", 0.92),
            (b"\x61\x9d", "vm_exit_epilogue", 0.94),
        ]

        static_patterns_x64 = [
            (b"\x48\x89\x5c\x24\x08\x48\x89\x74\x24\x10", "vm_entry_prologue_x64", 0.85),
            (b"\x9c\x50\x53\x51", "context_save_x64", 0.90),
            (b"\xff\x24\xc5", "handler_dispatch_x64", 0.92),
            (b"\x5f\x5e\x5a\x59\x5b\x58\x9d", "vm_exit_epilogue_x64", 0.94),
        ]

        patterns = static_patterns_x64 if architecture == "x64" else static_patterns_x86

        for pattern, handler_type, confidence in patterns:
            offset = 0
            while True:
                offset = data.find(pattern, offset)
                if offset == -1:
                    break

                handler = VMHandler(
                    offset=offset,
                    size=len(pattern),
                    handler_type=handler_type,
                    pattern=pattern,
                    confidence=confidence,
                )

                handlers.append(handler)
                offset += len(pattern)

        return handlers

    def _extract_opcodes(self, data: bytes, offset: int, size: int, architecture: str) -> list[tuple[int, str]]:
        """Extract opcodes from handler using disassembly.

        Args:
            data: Binary data containing handler.
            offset: Handler offset.
            size: Handler size.
            architecture: Target architecture.

        Returns:
            list[tuple[int, str]]: List of (address, instruction) tuples.
        """
        opcodes: list[tuple[int, str]] = []

        if not CAPSTONE_AVAILABLE:
            return opcodes

        cs = self._get_disassembler(architecture)
        if cs is None:
            return opcodes

        try:
            for insn in cs.disasm(data[offset : offset + size], offset):
                opcodes.append((insn.address, f"{insn.mnemonic} {insn.op_str}"))

                if len(opcodes) > 50:
                    break

        except Exception as e:
            logger.debug("Failed to extract opcodes at 0x%08x: %s", offset, e)

        return opcodes

    def _find_handler_xrefs(self, data: bytes, handler_offset: int) -> list[int]:
        """Find cross-references to handler.

        Args:
            data: Binary data to scan.
            handler_offset: Handler offset to find references to.

        Returns:
            list[int]: List of offsets containing references.
        """
        xrefs: list[int] = []

        handler_bytes_32 = struct.pack("<I", handler_offset & 0xFFFFFFFF)
        handler_bytes_64 = struct.pack("<Q", handler_offset)

        for handler_bytes in [handler_bytes_32, handler_bytes_64]:
            offset = 0
            while True:
                offset = data.find(handler_bytes, offset)
                if offset == -1:
                    break

                if offset != handler_offset:
                    xrefs.append(offset)

                offset += len(handler_bytes)

        return xrefs[:10]

    def _find_dispatcher_advanced(self, data: bytes, architecture: str) -> int | None:
        """Find VMProtect dispatcher using instruction-level analysis.

        Locates dispatcher by identifying indirect jump table patterns through
        disassembly rather than static byte pattern matching.

        Args:
            data: Binary data to analyze.
            architecture: Target architecture.

        Returns:
            int | None: Dispatcher offset if found.
        """
        if not CAPSTONE_AVAILABLE:
            return self._find_dispatcher_fallback(data, architecture)

        cs = self._get_disassembler(architecture)
        if cs is None:
            return None

        scan_step = 64
        max_offset = len(data) - 1000

        for offset in range(0, max_offset, scan_step):
            chunk_size = min(256, len(data) - offset)

            try:
                instructions = list(cs.disasm(data[offset : offset + chunk_size], offset))

                indirect_jmp_count = 0
                memory_load_before_jmp = False
                has_switch_pattern = False
                has_vmprotect_markers = False

                for i, insn in enumerate(instructions):
                    if insn.mnemonic == "jmp" and "[" in insn.op_str:
                        indirect_jmp_count += 1

                        if i > 0 and instructions[i - 1].mnemonic in ["mov", "lea"]:
                            memory_load_before_jmp = True

                        if i > 1:
                            prev_insns = instructions[max(0, i - 3) : i]
                            has_arith = any(
                                ins.mnemonic in ["add", "mul", "shl", "and"] for ins in prev_insns
                            )
                            if has_arith:
                                has_switch_pattern = True

                    if insn.mnemonic in ["pushad", "popad", "pushfd", "popfd"]:
                        has_vmprotect_markers = True

                is_likely_dispatcher = indirect_jmp_count >= 1 and (memory_load_before_jmp or has_switch_pattern)

                if is_likely_dispatcher:
                    if not has_vmprotect_markers:
                        for reg_check_insn in instructions[:10]:
                            if any(
                                reg in reg_check_insn.op_str.lower()
                                for reg in ["ebp", "esp", "rbp", "rsp", "esi", "edi", "rsi", "rdi"]
                            ):
                                has_vmprotect_markers = True
                                break

                if is_likely_dispatcher and has_vmprotect_markers:
                    logger.debug("Found dispatcher candidate at 0x%08x", offset)
                    return offset

            except Exception as e:
                logger.debug("Failed to analyze dispatcher at 0x%08x: %s", offset, e)
                continue

        return None

    def _find_dispatcher_fallback(self, data: bytes, architecture: str) -> int | None:
        """Fallback dispatcher detection using byte patterns.

        Args:
            data: Binary data to scan.
            architecture: Target architecture.

        Returns:
            int | None: Dispatcher offset if found.
        """
        patterns = (
            [b"\xff\x24\xc5", b"\xff\x24\xcd"] if architecture == "x64" else [b"\xff\x24\x85", b"\xff\x24\x8d"]
        )

        for pattern in patterns:
            offset = data.find(pattern)
            if offset != -1:
                return offset

        return None

    def _find_handler_table_advanced(self, data: bytes, architecture: str) -> int | None:
        """Find handler table using advanced heuristics.

        Identifies handler tables by analyzing pointer density and alignment
        within VMProtect sections through disassembly context.

        Args:
            data: Binary data containing PE file.
            architecture: Target architecture.

        Returns:
            int | None: Handler table offset if found.
        """
        if not PEFILE_AVAILABLE or pefile is None:
            return None

        try:
            pe = pefile.PE(data=data)

            for section in pe.sections:
                section_name = section.Name.decode("utf-8", errors="ignore").rstrip("\x00")

                if any(vmp in section_name.lower() for vmp in [".vmp", "vmp0", "vmp1"]):
                    section_data = section.get_data()

                    if candidate_offset := self._scan_for_handler_table_advanced(section_data, architecture):
                        return int(section.PointerToRawData + candidate_offset)

            pe.close()

        except Exception as e:
            logger.debug("Failed to find handler table: %s", e)

        return None

    def _scan_for_handler_table_advanced(self, section_data: bytes, architecture: str) -> int | None:
        """Scan section for handler table with validation.

        Args:
            section_data: Section data to scan.
            architecture: Target architecture.

        Returns:
            int | None: Handler table offset if found.
        """
        ptr_size = 8 if architecture == "x64" else 4
        min_table_size = 16
        max_table_size = 512
        alignment = ptr_size

        for offset in range(0, len(section_data) - min_table_size * ptr_size, alignment):
            if offset % alignment != 0:
                continue

            consecutive_pointers = 0
            pointer_values: list[int] = []

            for i in range(offset, min(offset + max_table_size * ptr_size, len(section_data)), ptr_size):
                if i + ptr_size > len(section_data):
                    break

                if ptr_size == 4:
                    ptr_val = struct.unpack("<I", section_data[i : i + 4])[0]
                    valid_range = 0x1000 < ptr_val < 0x7FFFFFFF
                else:
                    ptr_val = struct.unpack("<Q", section_data[i : i + 8])[0]
                    valid_range = 0x1000 < ptr_val < 0x7FFFFFFFFFFF

                if valid_range:
                    consecutive_pointers += 1
                    pointer_values.append(ptr_val)
                else:
                    break

                if consecutive_pointers >= min_table_size:
                    if self._validate_handler_table(pointer_values):
                        return offset

        return None

    def _validate_handler_table(self, pointers: list[int]) -> bool:
        """Validate that pointer sequence represents a handler table.

        Args:
            pointers: List of pointer values to validate.

        Returns:
            bool: True if pointers appear to form a valid handler table.
        """
        if len(pointers) < 8:
            return False

        unique_count = len(set(pointers))
        if unique_count < len(pointers) * 0.6:
            return False

        for i in range(len(pointers) - 1):
            if abs(pointers[i] - pointers[i + 1]) > 0x100000:
                return False

        sequential_pattern_count = 0
        for i in range(len(pointers) - 1):
            diff = pointers[i + 1] - pointers[i]
            if 0 < diff < 16:
                sequential_pattern_count += 1

        if sequential_pattern_count > len(pointers) * 0.3:
            return False

        alignment_score = sum(1 for p in pointers if p % 4 == 0)
        if alignment_score < len(pointers) * 0.7:
            return False

        return True

    def _identify_virtualized_regions_advanced(
        self, data: bytes, handlers: list[VMHandler], architecture: str
    ) -> list[VirtualizedRegion]:
        """Identify virtualized regions using advanced control flow analysis.

        Args:
            data: Binary data to analyze.
            handlers: Detected VM handlers.
            architecture: Target architecture.

        Returns:
            list[VirtualizedRegion]: Identified virtualized code regions.
        """
        regions: list[VirtualizedRegion] = []

        if not handlers:
            return regions

        entry_handlers = [h for h in handlers if "entry" in h.handler_type.lower()]

        for entry_handler in entry_handlers:
            exit_offset = self._find_vm_exit_advanced(data, entry_handler.offset, architecture)

            region_end = exit_offset if exit_offset else entry_handler.offset + 10000

            region_handlers = {
                handler.handler_type
                for handler in handlers
                if entry_handler.offset < handler.offset < region_end
            }

            cf_analysis = self._analyze_region_control_flow(data, entry_handler.offset, region_end, architecture)

            mutation_detected = self._check_region_mutation_advanced(
                data, entry_handler.offset, region_end, architecture
            )

            region = VirtualizedRegion(
                start_offset=entry_handler.offset,
                end_offset=region_end,
                vm_entry=entry_handler.offset,
                vm_exit=exit_offset,
                handlers_used=region_handlers,
                control_flow_complexity=cf_analysis["complexity"],
                mutation_detected=mutation_detected,
                basic_blocks=cf_analysis["basic_blocks"],
                indirect_jumps=cf_analysis["indirect_jumps"],
                dispatcher_calls=cf_analysis["dispatcher_calls"],
            )

            regions.append(region)

        return regions

    def _find_vm_exit_advanced(self, data: bytes, entry_offset: int, architecture: str) -> int | None:
        """Find VM exit using instruction-level analysis.

        Args:
            data: Binary data to analyze.
            entry_offset: VM entry offset.
            architecture: Target architecture.

        Returns:
            int | None: VM exit offset if found.
        """
        if not CAPSTONE_AVAILABLE:
            return None

        cs = self._get_disassembler(architecture)
        if cs is None:
            return None

        search_range = 5000

        try:
            context_restore_sequence = ["popad", "popfd"] if architecture == "x86" else ["pop", "popfq"]

            instructions = list(cs.disasm(data[entry_offset : entry_offset + search_range], entry_offset))

            for i, insn in enumerate(instructions):
                if insn.mnemonic in context_restore_sequence:
                    if i + 1 < len(instructions):
                        next_insn = instructions[i + 1]
                        if next_insn.mnemonic in ["ret", "jmp"]:
                            return int(insn.address)

        except Exception as e:
            logger.debug("Failed to find VM exit: %s", e)

        return None

    def _analyze_region_control_flow(
        self, data: bytes, start: int, end: int, architecture: str
    ) -> dict[str, Any]:
        """Analyze control flow characteristics of region.

        Args:
            data: Binary data to analyze.
            start: Region start offset.
            end: Region end offset.
            architecture: Target architecture.

        Returns:
            dict[str, Any]: Control flow metrics.
        """
        default_result = {
            "complexity": 1.0,
            "basic_blocks": 0,
            "indirect_jumps": 0,
            "dispatcher_calls": 0,
        }

        if not CAPSTONE_AVAILABLE:
            return default_result

        cs = self._get_disassembler(architecture)
        if cs is None:
            return default_result

        try:
            branches = 0
            instructions = 0
            unique_targets: set[int] = set()
            indirect_jumps = 0
            dispatcher_calls = 0

            for insn in cs.disasm(data[start:end], start):
                instructions += 1

                if insn.mnemonic.startswith("j"):
                    branches += 1

                    if "[" in insn.op_str:
                        indirect_jumps += 1
                    elif hasattr(insn, "operands") and insn.operands:
                        for op in insn.operands:
                            if op.type == CS_OP_IMM:
                                unique_targets.add(op.imm)
                            elif op.type == X86_OP_IMM:
                                unique_targets.add(op.imm)
                            elif ARM_AVAILABLE and hasattr(op, "type"):
                                try:
                                    if op.type == ARM_OP_IMM:
                                        unique_targets.add(op.imm)
                                except (NameError, AttributeError):
                                    pass
                            elif ARM64_AVAILABLE and hasattr(op, "type"):
                                try:
                                    if op.type == ARM64_OP_IMM:
                                        unique_targets.add(op.imm)
                                except (NameError, AttributeError):
                                    pass

                if insn.mnemonic == "call":
                    if "[" in insn.op_str:
                        dispatcher_calls += 1

            if instructions > 0:
                complexity = (branches / instructions) * (1 + len(unique_targets) * 0.1)
            else:
                complexity = 0.0

            basic_blocks = len(unique_targets) + 1

            return {
                "complexity": min(complexity, 10.0),
                "basic_blocks": basic_blocks,
                "indirect_jumps": indirect_jumps,
                "dispatcher_calls": dispatcher_calls,
            }

        except Exception:
            return default_result

    def _check_region_mutation_advanced(self, data: bytes, start: int, end: int, architecture: str) -> bool:
        """Check region for mutation patterns using instruction analysis.

        Args:
            data: Binary data to analyze.
            start: Region start offset.
            end: Region end offset.
            architecture: Target architecture.

        Returns:
            bool: True if significant mutation detected.
        """
        if not CAPSTONE_AVAILABLE:
            return self._check_region_mutation_fallback(data, start, end)

        cs = self._get_disassembler(architecture)
        if cs is None:
            return False

        try:
            junk_count = 0
            total_instructions = 0

            for insn in cs.disasm(data[start:end], start):
                total_instructions += 1

                if self._is_junk_instruction(insn):
                    junk_count += 1

            if total_instructions == 0:
                return False

            junk_ratio = junk_count / total_instructions
            return junk_ratio > 0.15

        except Exception:
            return False

    def _is_junk_instruction(self, insn: "CsInsn") -> bool:
        """Determine if instruction is junk/mutation code.

        Args:
            insn: Instruction to analyze.

        Returns:
            bool: True if instruction is junk code.
        """
        if insn.mnemonic == "nop":
            return True

        if insn.mnemonic == "xchg":
            operands = insn.op_str.split(",")
            if len(operands) == 2:
                op1 = operands[0].strip()
                op2 = operands[1].strip()
                if op1 == op2:
                    return True

        if insn.mnemonic == "mov":
            operands = insn.op_str.split(",")
            if len(operands) == 2:
                op1 = operands[0].strip()
                op2 = operands[1].strip()
                if op1 == op2:
                    return True

        if insn.mnemonic == "add":
            if ", 0" in insn.op_str or ",0" in insn.op_str:
                return True

        if insn.mnemonic == "sub":
            if ", 0" in insn.op_str or ",0" in insn.op_str:
                return True

        if insn.mnemonic in ["lea"] and "[" not in insn.op_str:
            return True

        return False

    def _check_region_mutation_fallback(self, data: bytes, start: int, end: int) -> bool:
        """Fallback mutation detection using byte patterns.

        Args:
            data: Binary data to analyze.
            start: Region start.
            end: Region end.

        Returns:
            bool: True if mutation detected.
        """
        region_data = data[start:end]
        mutation_patterns = [b"\x90", b"\x87\xc0", b"\x89\xc0", b"\x48\x87\xc0"]

        mutation_count = sum(region_data.count(pattern) for pattern in mutation_patterns)

        return mutation_count > len(region_data) * 0.01

    def _recover_control_flow(
        self, data: bytes, region: VirtualizedRegion, architecture: str
    ) -> ControlFlowGraph:
        """Recover control flow graph from virtualized region.

        Reconstructs CFG by analyzing branch instructions and building
        basic block connectivity graph.

        Args:
            data: Binary data to analyze.
            region: Virtualized region to recover CFG for.
            architecture: Target architecture.

        Returns:
            ControlFlowGraph: Recovered control flow graph.
        """
        cfg = ControlFlowGraph(
            basic_blocks={},
            edges=[],
            entry_points=[region.vm_entry],
            exit_points=[],
            complexity_score=0.0,
            indirect_branches=0,
            vm_context_switches=0,
        )

        if not CAPSTONE_AVAILABLE:
            return cfg

        cs = self._get_disassembler(architecture)
        if cs is None:
            return cfg

        try:
            basic_blocks: dict[int, list[int]] = defaultdict(list)
            current_block_start = region.start_offset
            current_block: list[int] = []

            for insn in cs.disasm(data[region.start_offset : region.end_offset], region.start_offset):
                current_block.append(int(insn.address))

                is_terminator = insn.mnemonic in ["ret", "jmp", "call"] or insn.mnemonic.startswith("j")

                if is_terminator:
                    basic_blocks[current_block_start] = current_block
                    current_block_start = int(insn.address + insn.size)
                    current_block = []

                    if insn.mnemonic == "ret":
                        cfg.exit_points.append(int(insn.address))

                    if "[" in insn.op_str:
                        cfg.indirect_branches += 1

                if insn.mnemonic in ["pushad", "popad", "pushfd", "popfd", "pushfq", "popfq"]:
                    cfg.vm_context_switches += 1

            if current_block:
                basic_blocks[current_block_start] = current_block

            cfg.basic_blocks = dict(basic_blocks)

            insn_map: dict[int, int] = {}
            for insn in cs.disasm(data[region.start_offset : region.end_offset], region.start_offset):
                insn_map[int(insn.address)] = insn.size

            for block_start in basic_blocks:
                block_addrs = basic_blocks[block_start]
                if block_addrs:
                    last_addr = block_addrs[-1]
                    insn_size = insn_map.get(last_addr, 1)
                    next_sequential = last_addr + insn_size
                    if next_sequential in basic_blocks:
                        cfg.edges.append((block_start, next_sequential))

            cfg.complexity_score = len(basic_blocks) + cfg.indirect_branches * 2

        except Exception as e:
            logger.debug("Failed to recover CFG: %s", e)

        return cfg

    def _detect_mutations_advanced(self, data: bytes, architecture: str) -> dict[str, Any]:
        """Detect mutations using instruction-level analysis.

        Args:
            data: Binary data to analyze.
            architecture: Target architecture.

        Returns:
            dict[str, Any]: Mutation analysis with score and details.
        """
        analysis = {
            "score": 0.0,
            "junk_instruction_ratio": 0.0,
            "pattern_diversity": 0.0,
            "code_bloat_factor": 1.0,
        }

        if not CAPSTONE_AVAILABLE:
            return self._detect_mutations_fallback(data)

        cs = self._get_disassembler(architecture)
        if cs is None:
            return analysis

        try:
            sample_size = min(100000, len(data))
            junk_count = 0
            total_instructions = 0
            instruction_sizes: list[int] = []

            for offset in range(0, sample_size, 1000):
                chunk_size = min(200, sample_size - offset)

                for insn in cs.disasm(data[offset : offset + chunk_size], offset):
                    total_instructions += 1
                    instruction_sizes.append(insn.size)

                    if self._is_junk_instruction(insn):
                        junk_count += 1

            if total_instructions > 0:
                junk_ratio = junk_count / total_instructions
                analysis["junk_instruction_ratio"] = junk_ratio

                if instruction_sizes:
                    avg_size = sum(instruction_sizes) / len(instruction_sizes)
                    analysis["code_bloat_factor"] = avg_size / 3.0

                pattern_score = self._calculate_pattern_diversity(data)
                analysis["pattern_diversity"] = pattern_score

                analysis["score"] = (junk_ratio * 0.5 + pattern_score * 0.3 + min(1.0, analysis["code_bloat_factor"] / 2) * 0.2)

        except Exception as e:
            logger.debug("Advanced mutation detection failed: %s", e)
            return self._detect_mutations_fallback(data)

        return analysis

    def _calculate_pattern_diversity(self, data: bytes) -> float:
        """Calculate diversity of byte patterns indicating polymorphism.

        Args:
            data: Binary data to analyze.

        Returns:
            float: Pattern diversity score (0.0 to 1.0).
        """
        sample_size = min(50000, len(data))
        ngram_size = 4
        ngrams: set[bytes] = set()

        for i in range(0, sample_size - ngram_size, ngram_size):
            ngram = data[i : i + ngram_size]
            ngrams.add(ngram)

        expected_unique = sample_size // ngram_size
        actual_unique = len(ngrams)

        diversity = min(1.0, actual_unique / expected_unique if expected_unique > 0 else 0.0)

        return diversity

    def _detect_mutations_fallback(self, data: bytes) -> dict[str, Any]:
        """Fallback mutation detection using byte patterns.

        Args:
            data: Binary data to analyze.

        Returns:
            dict[str, Any]: Basic mutation analysis.
        """
        mutation_patterns = [b"\x90", b"\x87\xc0", b"\x89\xc0", b"\x40\x4f", b"\x33\xc0\x50\x58"]

        total_occurrences = sum(data.count(pattern) for pattern in mutation_patterns)
        score = min(1.0, total_occurrences / len(data) * 100)

        return {"score": score, "junk_instruction_ratio": score, "pattern_diversity": 0.0, "code_bloat_factor": 1.0}

    def _determine_protection_level(
        self, handlers: list[VMHandler], regions: list[VirtualizedRegion], mutation_score: float
    ) -> VMProtectLevel:
        """Determine VMProtect protection level from analysis results.

        Args:
            handlers: Detected VM handlers.
            regions: Virtualized regions.
            mutation_score: Mutation detection score.

        Returns:
            VMProtectLevel: Classified protection level.
        """
        if not handlers:
            return VMProtectLevel.UNKNOWN

        handler_complexity = sum(h.complexity for h in handlers) / len(handlers)
        avg_region_complexity = sum(r.control_flow_complexity for r in regions) / len(regions) if regions else 0

        if mutation_score > 0.7 or handler_complexity > 80 or avg_region_complexity > 5.0:
            return VMProtectLevel.ULTRA

        region_count = len(regions)

        if mutation_score > 0.4 or handler_complexity > 50 or region_count > 5:
            return VMProtectLevel.STANDARD

        return VMProtectLevel.LITE

    def _detect_version_advanced(
        self, data: bytes, section_analysis: dict[str, Any], handlers: list[VMHandler]
    ) -> str:
        """Detect VMProtect version using multiple heuristics.

        Args:
            data: Binary data to analyze.
            section_analysis: Section analysis results.
            handlers: Detected handlers.

        Returns:
            str: Detected version string.
        """
        vmp_sections = section_analysis.get("vmp_sections", [])

        version_indicators = {
            "3.x": [b"VMProtect 3", b"vmp3", b".vmp0", b".vmp1", b".vmp2"],
            "2.x": [b"VMProtect 2", b"vmp2"],
            "1.x": [b"VMProtect 1", b"vmp1"],
        }

        for version, indicators in version_indicators.items():
            for indicator in indicators:
                if indicator in data:
                    return version

        if len(vmp_sections) >= 3:
            return "3.x"
        if len(vmp_sections) >= 2:
            return "2.x-3.x"
        if len(vmp_sections) == 1:
            return "2.x"

        if handlers:
            avg_handler_complexity = sum(h.complexity for h in handlers) / len(handlers)
            if avg_handler_complexity > 70:
                return "3.x (inferred from complexity)"
            if avg_handler_complexity > 40:
                return "2.x (inferred from complexity)"

        return "Unknown (likely 2.x or 3.x)"

    def _scan_strings(self, data: bytes) -> list[str]:
        """Scan for VMProtect indicator strings.

        Args:
            data: Binary data to scan.

        Returns:
            list[str]: Found VMProtect indicator strings.
        """
        return [
            indicator
            for indicator in self.VMP_STRING_INDICATORS
            if indicator.encode("utf-8", errors="ignore") in data.lower()
        ]

    def _generate_bypass_recommendations(self, detection: VMProtectDetection) -> list[str]:
        """Generate bypass recommendations based on detection results.

        Args:
            detection: VMProtect detection results.

        Returns:
            list[str]: Actionable bypass recommendations.
        """
        recommendations: list[str] = []

        if not detection.detected:
            return recommendations

        if detection.protection_level == VMProtectLevel.ULTRA:
            recommendations.extend(
                [
                    "Ultra protection detected - Requires advanced devirtualization with symbolic execution",
                    "Recommended tools: Custom devirtualizer, Triton framework, Miasm2",
                    "Expected time: 4-8 weeks for full devirtualization",
                    "Success rate: 40-60% depending on code complexity",
                    "Consider focusing on specific licensing functions rather than full devirtualization",
                ]
            )
        elif detection.protection_level == VMProtectLevel.STANDARD:
            recommendations.extend(
                [
                    "Standard protection - Use pattern-based devirtualization with handler identification",
                    "Recommended tools: x64dbg with VMProtect plugin, IDA Pro with devirtualization scripts",
                    "Expected time: 1-3 weeks",
                    "Success rate: 65-75%",
                    "Handler table analysis can accelerate devirtualization process",
                ]
            )
        elif detection.protection_level == VMProtectLevel.LITE:
            recommendations.extend(
                [
                    "Lite protection - Basic handler analysis and code flow reconstruction",
                    "Recommended tools: IDA Pro, Ghidra with custom scripts",
                    "Expected time: 3-7 days",
                    "Success rate: 75-85%",
                    "Manual analysis feasible for experienced reverse engineers",
                ]
            )

        if detection.mode == VMProtectMode.MUTATION:
            recommendations.append(
                "Mutation mode detected - Focus on instruction normalization before analysis"
            )

        if detection.dispatcher_offset:
            recommendations.append(
                f"Dispatcher located at 0x{detection.dispatcher_offset:08x} - Use as starting point for handler enumeration"
            )

        if detection.handler_table_offset:
            recommendations.append(
                f"Handler table at 0x{detection.handler_table_offset:08x} - Extract for handler mapping"
            )

        if len(detection.virtualized_regions) > 0:
            recommendations.append(
                f"Identified {len(detection.virtualized_regions)} virtualized regions - Prioritize by licensing relevance"
            )

        if detection.control_flow_graphs:
            recommendations.append(
                "Control flow graphs recovered - Use for automated symbolic execution or pattern matching"
            )

        return recommendations
