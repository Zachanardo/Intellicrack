"""Production VMProtect 3.x Detection and Analysis.

Sophisticated detection system for VMProtect 3.x protected binaries including:
- VM handler pattern recognition
- Control flow analysis for virtualized blocks
- Mutation detection
- Multi-architecture support (x86, x64)
- All protection levels (Lite, Standard, Ultra)

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import struct
from dataclasses import dataclass, field
from enum import Enum

from intellicrack.utils.logger import get_logger

logger = get_logger(__name__)

try:
    import pefile

    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False
    logger.debug("pefile not available - VMProtect detection limited")

try:
    from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False
    logger.debug("Capstone not available - VMProtect disassembly limited")


class VMProtectLevel(Enum):
    """VMProtect protection levels."""

    LITE = "lite"
    STANDARD = "standard"
    ULTRA = "ultra"
    UNKNOWN = "unknown"


class VMProtectMode(Enum):
    """VMProtect virtualization modes."""

    VIRTUALIZATION = "virtualization"
    MUTATION = "mutation"
    HYBRID = "hybrid"


@dataclass
class VMHandler:
    """VMProtect virtual machine handler."""

    offset: int
    size: int
    handler_type: str
    pattern: bytes
    confidence: float
    opcodes: list[tuple[int, str]] = field(default_factory=list)
    xrefs: list[int] = field(default_factory=list)
    complexity: int = 0


@dataclass
class VirtualizedRegion:
    """Region of virtualized code."""

    start_offset: int
    end_offset: int
    vm_entry: int
    vm_exit: int | None
    handlers_used: set[str]
    control_flow_complexity: float
    mutation_detected: bool = False
    protection_level: VMProtectLevel = VMProtectLevel.UNKNOWN


@dataclass
class VMProtectDetection:
    """Complete VMProtect detection results."""

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
    technical_details: dict[str, any] = field(default_factory=dict)
    bypass_recommendations: list[str] = field(default_factory=list)


class VMProtectDetector:
    """Production-ready VMProtect 3.x detector."""

    VMP_HANDLER_SIGNATURES_X86 = [
        (b"\x55\x8b\xec\x53\x56\x57\x8b\x7d\x08", "vm_entry_prologue", 0.95),
        (b"\x9c\x60\x8b\x74\x24\x24", "pushad_context_save", 0.90),
        (b"\x8b\x45\xfc\x03\x45\xf8", "vm_ip_increment", 0.85),
        (b"\xff\x24\x85", "handler_dispatch_table", 0.92),
        (b"\x0f\xb6\x06\x46\x89\x75", "vm_fetch_byte", 0.88),
        (b"\x8b\x45\x08\x8b\x00", "vm_stack_pop", 0.85),
        (b"\x8b\x45\xf8\xff\x30", "vm_stack_push", 0.85),
        (b"\x8d\x45\xf8\x50\xe8", "vm_call_handler", 0.87),
        (b"\x8b\x45\x0c\x33\x45\x08", "vm_xor_operation", 0.83),
        (b"\x8b\x45\x0c\x01\x45\x08", "vm_add_operation", 0.83),
        (b"\x61\x9d\x5f\x5e\x5b\xc9\xc3", "vm_exit_epilogue", 0.94),
    ]

    VMP_HANDLER_SIGNATURES_X64 = [
        (b"\x48\x89\x5c\x24\x08\x48\x89\x74\x24\x10", "vm_entry_prologue_x64", 0.95),
        (b"\x9c\x50\x53\x51\x52\x56\x57", "context_save_x64", 0.90),
        (b"\x48\x8b\x45\xf8\x48\x03\x45\xf0", "vm_ip_increment_x64", 0.85),
        (b"\xff\x24\xc5", "handler_dispatch_table_x64", 0.92),
        (b"\x0f\xb6\x06\x48\xff\xc6", "vm_fetch_byte_x64", 0.88),
        (b"\x48\x8b\x45\x08\x48\x8b\x00", "vm_stack_pop_x64", 0.85),
        (b"\x48\x8b\x45\xf8\xff\x30", "vm_stack_push_x64", 0.85),
        (b"\x48\x8d\x45\xf8\x48\x8b\xc8\xe8", "vm_call_handler_x64", 0.87),
        (b"\x48\x8b\x45\x10\x48\x33\x45\x08", "vm_xor_operation_x64", 0.83),
        (b"\x5f\x5e\x5a\x59\x5b\x58\x9d\xc3", "vm_exit_epilogue_x64", 0.94),
    ]

    VMP_MUTATION_PATTERNS = [
        (b"\x90\x90\x90", "nop_padding", 0.70),
        (b"\x87\xc0", "xchg_eax_eax", 0.75),
        (b"\x40\x4f", "inc_dec_pair", 0.72),
        (b"\x33\xc0\x50\x58", "xor_push_pop", 0.78),
        (b"\x8b\xc0", "mov_eax_eax", 0.73),
        (b"\x89\xc0", "mov_eax_eax_alt", 0.73),
        (b"\x48\x87\xc0", "xchg_rax_rax", 0.75),
    ]

    VMP_STRING_INDICATORS = [
        "vmp",
        "vmprotect",
        "oreans",
        "virtualizer",
        "protected by vmprotect",
        ".vmp0",
        ".vmp1",
        ".vmp2",
    ]

    def __init__(self) -> None:
        """Initialize VMProtect detector."""
        if CAPSTONE_AVAILABLE:
            self.cs_x86 = Cs(CS_ARCH_X86, CS_MODE_32)
            self.cs_x64 = Cs(CS_ARCH_X86, CS_MODE_64)
            self.cs_x86.detail = True
            self.cs_x64.detail = True

    def detect(self, binary_path: str) -> VMProtectDetection:
        """Perform comprehensive VMProtect 3.x detection."""
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
            with open(binary_path, "rb") as f:
                binary_data = f.read()

            if not self._is_pe(binary_data):
                return detection

            detection.architecture = self._detect_architecture(binary_data)

            section_analysis = self._analyze_sections(binary_data)
            detection.technical_details["sections"] = section_analysis

            handlers = self._detect_vm_handlers(binary_data, detection.architecture)
            detection.handlers = handlers

            if handlers:
                detection.detected = True
                detection.confidence = max(detection.confidence, 0.7)

            dispatcher = self._find_dispatcher(binary_data, detection.architecture)
            if dispatcher:
                detection.dispatcher_offset = dispatcher
                detection.confidence = max(detection.confidence, 0.85)

            handler_table = self._find_handler_table(binary_data, detection.architecture)
            if handler_table:
                detection.handler_table_offset = handler_table
                detection.confidence = max(detection.confidence, 0.90)

            virtualized_regions = self._identify_virtualized_regions(binary_data, handlers, detection.architecture)
            detection.virtualized_regions = virtualized_regions

            if virtualized_regions:
                detection.confidence = max(detection.confidence, 0.92)

            mutation_score = self._detect_mutations(binary_data)
            detection.technical_details["mutation_score"] = mutation_score

            if mutation_score > 0.5:
                detection.mode = VMProtectMode.MUTATION if mutation_score > 0.8 else VMProtectMode.HYBRID

            detection.protection_level = self._determine_protection_level(handlers, virtualized_regions, mutation_score)

            detection.version = self._detect_version(binary_data, section_analysis)

            cf_analysis = self._analyze_control_flow(binary_data, virtualized_regions, detection.architecture)
            detection.technical_details["control_flow"] = cf_analysis

            detection.bypass_recommendations = self._generate_bypass_recommendations(detection)

            string_matches = self._scan_strings(binary_data)
            if string_matches:
                detection.detected = True
                detection.confidence = max(detection.confidence, 0.6)
                detection.technical_details["string_matches"] = string_matches

        except Exception as e:
            logger.error(f"VMProtect detection failed: {e}")
            detection.technical_details["error"] = str(e)

        return detection

    def _is_pe(self, data: bytes) -> bool:
        """Check if data is a PE file."""
        return len(data) > 64 and data[:2] == b"MZ"

    def _detect_architecture(self, data: bytes) -> str:
        """Detect binary architecture."""
        if not PEFILE_AVAILABLE:
            return "unknown"

        try:
            pe = pefile.PE(data=data)
            machine = pe.FILE_HEADER.Machine

            if machine == 0x14C:
                return "x86"
            if machine == 0x8664:
                return "x64"
            return f"unknown_0x{machine:04x}"

        except Exception:
            return "unknown"

    def _analyze_sections(self, data: bytes) -> dict[str, any]:
        """Analyze PE sections for VMProtect characteristics."""
        analysis = {
            "vmp_sections": [],
            "high_entropy_sections": [],
            "suspicious_characteristics": [],
        }

        if not PEFILE_AVAILABLE:
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
                        },
                    )

                if entropy > 7.3:
                    analysis["high_entropy_sections"].append({"name": section_name, "entropy": entropy})

                if section.Characteristics & 0xE0000000 == 0xE0000000:
                    analysis["suspicious_characteristics"].append(
                        {"name": section_name, "flags": "CODE|READ|WRITE", "characteristics": section.Characteristics},
                    )

            pe.close()

        except Exception as e:
            logger.debug(f"Section analysis failed: {e}")

        return analysis

    def _detect_vm_handlers(self, data: bytes, architecture: str) -> list[VMHandler]:
        """Detect VMProtect VM handlers using signature matching."""
        handlers = []

        signatures = self.VMP_HANDLER_SIGNATURES_X64 if architecture == "x64" else self.VMP_HANDLER_SIGNATURES_X86

        for pattern, handler_type, base_confidence in signatures:
            offset = 0
            while True:
                offset = data.find(pattern, offset)
                if offset == -1:
                    break

                handler_size = self._estimate_handler_size(data, offset, architecture)

                complexity = self._calculate_handler_complexity(data, offset, handler_size, architecture)

                confidence = base_confidence * (0.8 + min(0.2, complexity / 100))

                opcodes = self._extract_opcodes(data, offset, handler_size, architecture)

                xrefs = self._find_handler_xrefs(data, offset)

                handler = VMHandler(
                    offset=offset,
                    size=handler_size,
                    handler_type=handler_type,
                    pattern=pattern,
                    confidence=confidence,
                    opcodes=opcodes,
                    xrefs=xrefs,
                    complexity=complexity,
                )

                handlers.append(handler)
                offset += len(pattern)

        return handlers

    def _estimate_handler_size(self, data: bytes, offset: int, architecture: str) -> int:
        """Estimate VM handler size through basic flow analysis."""
        if not CAPSTONE_AVAILABLE:
            return 64

        cs = self.cs_x64 if architecture == "x64" else self.cs_x86
        max_size = 512
        size = 0

        try:
            for insn in cs.disasm(data[offset : offset + max_size], offset):
                size = insn.address - offset + insn.size

                if insn.mnemonic in ["ret", "jmp"]:
                    if insn.mnemonic == "ret" or (insn.mnemonic == "jmp" and insn.op_str.startswith("[")):
                        break

                if size > max_size - 16:
                    break

        except Exception:
            size = 64

        return max(size, 16)

    def _calculate_handler_complexity(self, data: bytes, offset: int, size: int, architecture: str) -> int:
        """Calculate handler complexity score."""
        if not CAPSTONE_AVAILABLE:
            return 10

        cs = self.cs_x64 if architecture == "x64" else self.cs_x86
        complexity = 0

        try:
            instruction_count = 0
            unique_opcodes = set()
            branches = 0
            memory_ops = 0

            for insn in cs.disasm(data[offset : offset + size], offset):
                instruction_count += 1
                unique_opcodes.add(insn.mnemonic)

                if insn.mnemonic.startswith("j"):
                    branches += 1
                    complexity += 3

                if "[" in insn.op_str:
                    memory_ops += 1
                    complexity += 2

                if insn.mnemonic in ["xor", "add", "sub", "mul", "div", "shl", "shr", "rol", "ror"]:
                    complexity += 1

            complexity += len(unique_opcodes) * 2
            complexity += instruction_count

        except Exception:
            complexity = 10

        return complexity

    def _extract_opcodes(self, data: bytes, offset: int, size: int, architecture: str) -> list[tuple[int, str]]:
        """Extract opcodes from handler."""
        opcodes = []

        if not CAPSTONE_AVAILABLE:
            return opcodes

        cs = self.cs_x64 if architecture == "x64" else self.cs_x86

        try:
            for insn in cs.disasm(data[offset : offset + size], offset):
                opcodes.append((insn.address, f"{insn.mnemonic} {insn.op_str}"))

                if len(opcodes) > 50:
                    break

        except Exception as e:
            logger.debug(f"Failed to extract opcodes at offset 0x{offset:08x}: {e}")

        return opcodes

    def _find_handler_xrefs(self, data: bytes, handler_offset: int) -> list[int]:
        """Find cross-references to a handler."""
        xrefs = []

        handler_bytes = struct.pack("<I", handler_offset)

        offset = 0
        while True:
            offset = data.find(handler_bytes, offset)
            if offset == -1:
                break

            if offset != handler_offset:
                xrefs.append(offset)

            offset += 4

        return xrefs[:10]

    def _find_dispatcher(self, data: bytes, architecture: str) -> int | None:
        """Find VMProtect dispatcher logic."""
        if not CAPSTONE_AVAILABLE:
            return None

        cs = self.cs_x64 if architecture == "x64" else self.cs_x86

        dispatch_patterns_x86 = [b"\xff\x24\x85", b"\xff\x24\x8d"]

        dispatch_patterns_x64 = [b"\xff\x24\xc5", b"\xff\x24\xcd"]

        patterns = dispatch_patterns_x64 if architecture == "x64" else dispatch_patterns_x86

        for pattern in patterns:
            offset = data.find(pattern)
            if offset != -1:
                return offset

        for i in range(0, len(data) - 100, 16):
            try:
                insns = list(cs.disasm(data[i : i + 100], i))

                jmp_table_count = 0
                for insn in insns:
                    if insn.mnemonic == "jmp" and "[" in insn.op_str:
                        jmp_table_count += 1

                    if jmp_table_count >= 2:
                        return i

            except Exception as e:
                logger.debug(f"Failed to analyze dispatcher at offset 0x{i:08x}: {e}")
                continue

        return None

    def _find_handler_table(self, data: bytes, architecture: str) -> int | None:
        """Find VMProtect handler table."""
        if not PEFILE_AVAILABLE:
            return None

        try:
            pe = pefile.PE(data=data)

            for section in pe.sections:
                section_name = section.Name.decode("utf-8", errors="ignore").rstrip("\x00")

                if any(vmp in section_name.lower() for vmp in [".vmp", "vmp0", "vmp1"]):
                    section_data = section.get_data()

                    candidate_offset = self._scan_for_handler_table(section_data, architecture)
                    if candidate_offset is not None:
                        return section.PointerToRawData + candidate_offset

            pe.close()

        except Exception as e:
            logger.debug(f"Failed to find handler table: {e}")

        return None

    def _scan_for_handler_table(self, section_data: bytes, architecture: str) -> int | None:
        """Scan section for handler table structure."""
        ptr_size = 8 if architecture == "x64" else 4
        min_table_size = 16
        max_table_size = 512

        for offset in range(0, len(section_data) - min_table_size * ptr_size, ptr_size):
            consecutive_pointers = 0

            for i in range(offset, min(offset + max_table_size * ptr_size, len(section_data)), ptr_size):
                if ptr_size == 4:
                    ptr_val = struct.unpack("<I", section_data[i : i + 4])[0]
                else:
                    ptr_val = struct.unpack("<Q", section_data[i : i + 8])[0]

                if 0x1000 < ptr_val < 0x7FFFFFFF if ptr_size == 4 else 0x1000 < ptr_val < 0x7FFFFFFFFFFF:
                    consecutive_pointers += 1
                else:
                    break

                if consecutive_pointers >= min_table_size:
                    return offset

        return None

    def _identify_virtualized_regions(self, data: bytes, handlers: list[VMHandler], architecture: str) -> list[VirtualizedRegion]:
        """Identify regions of virtualized code."""
        regions = []

        if not handlers:
            return regions

        entry_handlers = [h for h in handlers if "entry" in h.handler_type.lower()]

        for entry_handler in entry_handlers:
            exit_offset = self._find_vm_exit(data, entry_handler.offset, architecture)

            region_handlers = set()
            for handler in handlers:
                if entry_handler.offset < handler.offset < (exit_offset or entry_handler.offset + 10000):
                    region_handlers.add(handler.handler_type)

            cf_complexity = self._calculate_region_complexity(data, entry_handler.offset, exit_offset, architecture)

            mutation_detected = self._check_region_mutation(data, entry_handler.offset, exit_offset or entry_handler.offset + 1000)

            region = VirtualizedRegion(
                start_offset=entry_handler.offset,
                end_offset=exit_offset or entry_handler.offset + 1000,
                vm_entry=entry_handler.offset,
                vm_exit=exit_offset,
                handlers_used=region_handlers,
                control_flow_complexity=cf_complexity,
                mutation_detected=mutation_detected,
            )

            regions.append(region)

        return regions

    def _find_vm_exit(self, data: bytes, entry_offset: int, architecture: str) -> int | None:
        """Find VM exit point."""
        if not CAPSTONE_AVAILABLE:
            return None

        cs = self.cs_x64 if architecture == "x64" else self.cs_x86
        search_range = 5000

        exit_patterns = [
            b"\x61\x9d",
            b"\x5f\x5e\x5b",
            b"\x5f\x5e\x5a\x59\x5b\x58\x9d",
        ]

        for pattern in exit_patterns:
            offset = data.find(pattern, entry_offset, entry_offset + search_range)
            if offset != -1:
                return offset

        try:
            for insn in cs.disasm(data[entry_offset : entry_offset + search_range], entry_offset):
                if insn.mnemonic == "popad" or (insn.mnemonic == "pop" and "di" in insn.op_str):
                    next_offset = insn.address + insn.size
                    next_insns = list(cs.disasm(data[next_offset : next_offset + 10], next_offset))

                    if next_insns and next_insns[0].mnemonic == "popfd":
                        return insn.address

        except Exception as e:
            logger.debug(f"Failed to find VM exit point: {e}")

        return None

    def _calculate_region_complexity(self, data: bytes, start: int, end: int | None, architecture: str) -> float:
        """Calculate control flow complexity of a region."""
        if not CAPSTONE_AVAILABLE or not end:
            return 1.0

        cs = self.cs_x64 if architecture == "x64" else self.cs_x86
        complexity = 0.0

        try:
            branches = 0
            instructions = 0
            unique_targets = set()

            for insn in cs.disasm(data[start:end], start):
                instructions += 1

                if insn.mnemonic.startswith("j"):
                    branches += 1

                    if insn.operands and insn.operands[0].type == 1:
                        unique_targets.add(insn.operands[0].imm)

                if insn.mnemonic == "call":
                    branches += 1

            if instructions > 0:
                complexity = (branches / instructions) * (1 + len(unique_targets) * 0.1)

        except Exception:
            complexity = 1.0

        return min(complexity, 10.0)

    def _check_region_mutation(self, data: bytes, start: int, end: int) -> bool:
        """Check if region shows mutation patterns."""
        region_data = data[start:end]
        mutation_count = 0

        for pattern, _, _ in self.VMP_MUTATION_PATTERNS:
            count = region_data.count(pattern)
            mutation_count += count

        return mutation_count > 5

    def _detect_mutations(self, data: bytes) -> float:
        """Detect mutation/polymorphic code patterns."""
        mutation_score = 0.0
        total_patterns = len(self.VMP_MUTATION_PATTERNS)

        for pattern, _pattern_name, weight in self.VMP_MUTATION_PATTERNS:
            count = data.count(pattern)

            if count > 10:
                mutation_score += weight

        mutation_score = min(mutation_score / total_patterns, 1.0)

        junk_ratio = self._calculate_junk_code_ratio(data)
        mutation_score = (mutation_score + junk_ratio) / 2

        return mutation_score

    def _calculate_junk_code_ratio(self, data: bytes) -> float:
        """Calculate ratio of junk code to real code."""
        if not CAPSTONE_AVAILABLE:
            return 0.0

        junk_instructions = 0
        total_instructions = 0
        sample_size = min(50000, len(data))

        cs = self.cs_x86

        try:
            for i in range(0, sample_size, 1000):
                for insn in cs.disasm(data[i : i + 100], i):
                    total_instructions += 1

                    if (insn.mnemonic in ["nop", "xchg"] and "eax" in insn.op_str and "eax" in insn.op_str) or (insn.mnemonic == "mov" and insn.op_str.split(",")[0].strip() == insn.op_str.split(",")[1].strip()):
                        junk_instructions += 1

        except Exception as e:
            logger.debug(f"Failed to calculate junk code ratio: {e}")

        if total_instructions == 0:
            return 0.0

        return min(junk_instructions / total_instructions, 1.0)

    def _determine_protection_level(
        self, handlers: list[VMHandler], regions: list[VirtualizedRegion], mutation_score: float,
    ) -> VMProtectLevel:
        """Determine VMProtect protection level."""
        if not handlers:
            return VMProtectLevel.UNKNOWN

        handler_complexity = sum(h.complexity for h in handlers) / len(handlers)
        region_count = len(regions)

        avg_region_complexity = sum(r.control_flow_complexity for r in regions) / len(regions) if regions else 0

        if mutation_score > 0.7 or handler_complexity > 80 or avg_region_complexity > 5.0:
            return VMProtectLevel.ULTRA
        if mutation_score > 0.4 or handler_complexity > 50 or region_count > 5:
            return VMProtectLevel.STANDARD
        if handlers or regions:
            return VMProtectLevel.LITE
        return VMProtectLevel.UNKNOWN

    def _detect_version(self, data: bytes, section_analysis: dict) -> str:
        """Detect VMProtect version."""
        vmp_sections = section_analysis.get("vmp_sections", [])

        if len(vmp_sections) >= 2:
            return "3.x"
        if len(vmp_sections) == 1:
            return "2.x-3.x"

        version_strings = [b"VMProtect 3", b"VMProtect v3", b"3.0", b"3.1", b"3.2", b"3.3", b"3.4", b"3.5", b"3.6"]

        for version_str in version_strings:
            if version_str in data:
                try:
                    version_bytes = data[data.find(version_str) : data.find(version_str) + 20]
                    version_text = version_bytes.decode("utf-8", errors="ignore")
                    return version_text.split()[1] if len(version_text.split()) > 1 else "3.x"
                except Exception:
                    return "3.x"

        return "Unknown (likely 2.x or 3.x)"

    def _analyze_control_flow(self, data: bytes, regions: list[VirtualizedRegion], architecture: str) -> dict[str, any]:
        """Analyze control flow within virtualized regions."""
        analysis = {
            "total_regions": len(regions),
            "avg_complexity": 0.0,
            "max_complexity": 0.0,
            "indirect_branches": 0,
            "vm_transitions": 0,
        }

        if not regions:
            return analysis

        complexities = [r.control_flow_complexity for r in regions]
        analysis["avg_complexity"] = sum(complexities) / len(complexities)
        analysis["max_complexity"] = max(complexities)

        if not CAPSTONE_AVAILABLE:
            return analysis

        cs = self.cs_x64 if architecture == "x64" else self.cs_x86

        for region in regions:
            try:
                for insn in cs.disasm(data[region.start_offset : region.end_offset], region.start_offset):
                    if insn.mnemonic in ["jmp", "call"] and "[" in insn.op_str:
                        analysis["indirect_branches"] += 1

                    if insn.mnemonic in ["pushad", "popad", "pushfd", "popfd"]:
                        analysis["vm_transitions"] += 1

            except Exception as e:
                logger.debug(f"Failed to analyze control flow in region at 0x{region.start_offset:08x}: {e}")
                continue

        return analysis

    def _scan_strings(self, data: bytes) -> list[str]:
        """Scan for VMProtect-related strings."""
        matches = []

        for indicator in self.VMP_STRING_INDICATORS:
            if indicator.encode("utf-8", errors="ignore") in data.lower():
                matches.append(indicator)

        return matches

    def _generate_bypass_recommendations(self, detection: VMProtectDetection) -> list[str]:
        """Generate bypass recommendations based on detection results."""
        recommendations = []

        if not detection.detected:
            return recommendations

        if detection.protection_level == VMProtectLevel.ULTRA:
            recommendations.append(
                "Ultra protection detected - Requires advanced devirtualization techniques with symbolic execution and SMT solving",
            )
            recommendations.append("Recommended tools: Custom devirtualizer, Triton framework, Miasm2, or commercial VMProtect devirtualizers")
            recommendations.append("Expected time: 4-8 weeks for full devirtualization")
            recommendations.append("Success rate: 40-60% depending on code complexity")
        elif detection.protection_level == VMProtectLevel.STANDARD:
            recommendations.append("Standard protection - Use pattern-based devirtualization with handler identification")
            recommendations.append("Recommended tools: x64dbg with VMProtect plugin, IDA Pro with devirtualization scripts")
            recommendations.append("Expected time: 1-3 weeks")
            recommendations.append("Success rate: 65-75%")
        elif detection.protection_level == VMProtectLevel.LITE:
            recommendations.append("Lite protection - Basic handler analysis and code flow reconstruction")
            recommendations.append("Recommended tools: IDA Pro, Ghidra with custom scripts")
            recommendations.append("Expected time: 3-7 days")
            recommendations.append("Success rate: 75-85%")

        if detection.mode == VMProtectMode.MUTATION:
            recommendations.append("Mutation mode detected - Focus on pattern normalization before analysis")

        if detection.dispatcher_offset:
            recommendations.append(f"Dispatcher located at 0x{detection.dispatcher_offset:08x} - Use as starting point for handler enumeration")

        if detection.handler_table_offset:
            recommendations.append(f"Handler table at 0x{detection.handler_table_offset:08x} - Extract for handler mapping")

        if len(detection.virtualized_regions) > 0:
            recommendations.append(f"Identified {len(detection.virtualized_regions)} virtualized regions - Prioritize by licensing relevance")

        return recommendations
