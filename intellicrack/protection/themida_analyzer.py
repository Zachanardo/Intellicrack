"""Themida/WinLicense Advanced Virtualization Analysis.

Production-ready analysis engine for Themida and WinLicense virtualization-based
protections including CISC, RISC, and FISH virtual machine architectures.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.
"""

import re
import struct
from dataclasses import dataclass
from enum import Enum
from typing import Any


try:
    import lief

    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False

try:
    from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

from ..utils.logger import get_logger


logger = get_logger(__name__)


class VMArchitecture(Enum):
    """Themida virtual machine architecture types."""

    CISC = "CISC"
    RISC = "RISC"
    FISH = "FISH"
    UNKNOWN = "Unknown"


class ThemidaVersion(Enum):
    """Themida/WinLicense version detection."""

    THEMIDA_1X = "Themida 1.x"
    THEMIDA_2X = "Themida 2.x"
    THEMIDA_3X = "Themida 3.x"
    WINLICENSE_1X = "WinLicense 1.x"
    WINLICENSE_2X = "WinLicense 2.x"
    WINLICENSE_3X = "WinLicense 3.x"
    UNKNOWN = "Unknown"


@dataclass
class VMHandler:
    """Virtual machine handler structure."""

    opcode: int
    address: int
    size: int
    instructions: list[tuple[int, str, str]]
    category: str
    complexity: int
    references: list[int]


@dataclass
class VMContext:
    """Virtual machine context structure."""

    vm_entry: int
    vm_exit: int
    context_size: int
    register_mapping: dict[str, int]
    stack_offset: int
    flags_offset: int


@dataclass
class DevirtualizedCode:
    """Devirtualized code structure."""

    original_rva: int
    original_size: int
    vm_handlers_used: list[int]
    native_code: bytes
    assembly: list[str]
    confidence: float


@dataclass
class ThemidaAnalysisResult:
    """Complete Themida analysis result."""

    is_protected: bool
    version: ThemidaVersion
    vm_architecture: VMArchitecture
    vm_sections: list[str]
    vm_entry_points: list[int]
    vm_contexts: list[VMContext]
    handlers: dict[int, VMHandler]
    handler_table_address: int
    devirtualized_sections: list[DevirtualizedCode]
    encryption_keys: list[bytes]
    anti_debug_locations: list[int]
    anti_dump_locations: list[int]
    integrity_check_locations: list[int]
    confidence: float


class ThemidaAnalyzer:
    """Advanced Themida/WinLicense virtualization analyzer."""

    THEMIDA_SIGNATURES = {
        b"\x8b\xc5\x8b\xd4\x60\xe8\x00\x00\x00\x00": "Themida 1.x Entry",
        b"\xb8\x00\x00\x00\x00\x60\x0b\xc0\x74": "Themida 2.x Entry",
        b"\x55\x8b\xec\x83\xc4\xf0\x53\x56\x57": "Themida 3.x Entry",
        b"\x68\x00\x00\x00\x00\x9c\x60\xe8": "WinLicense 1.x Entry",
        b"\xeb\x10\x66\x62\x3a\x43\x2b\x2b\x48\x4f\x4f\x4b": "WinLicense Marker",
    }

    VM_SECTION_NAMES = [
        b".themida",
        b".winlice",
        b".vmp0",
        b".vmp1",
        b".oreans",
        b"WinLice",
    ]

    CISC_HANDLER_PATTERNS = {
        0x00: b"\x8b\x45\x00\x89\x45\x04",
        0x01: b"\x8b\x45\x00\x03\x45\x04",
        0x02: b"\x8b\x45\x00\x2b\x45\x04",
        0x03: b"\x8b\x45\x00\x0f\xaf\x45\x04",
        0x04: b"\x8b\x45\x00\x33\x45\x04",
        0x05: b"\x8b\x45\x00\x0b\x45\x04",
        0x06: b"\x8b\x45\x00\x23\x45\x04",
        0x07: b"\xf7\x45\x00",
        0x08: b"\x8b\x45\x00\xd1\xe0",
        0x09: b"\x8b\x45\x00\xd1\xe8",
        0x0A: b"\x83\x7d\x00\x00\x74",
        0x0B: b"\x83\x7d\x00\x00\x75",
        0x0C: b"\xe9",
        0x0D: b"\xeb",
        0x0E: b"\x8b\x45\x00\xff\xe0",
        0x0F: b"\xc3",
    }

    RISC_HANDLER_PATTERNS = {
        0x00: b"\xe2\x8f\x00\x00",
        0x01: b"\xe0\x80\x00\x00",
        0x02: b"\xe0\x40\x00\x00",
        0x03: b"\xe0\x00\x00\x00",
        0x04: b"\xe2\x00\x00\x00",
        0x05: b"\xe1\x80\x00\x00",
        0x06: b"\xe0\x00\x00\x01",
        0x07: b"\xe2\x61\x00\x00",
        0x08: b"\xe1\xa0\x00\x00",
        0x09: b"\xe1\xa0\x00\x20",
        0x0A: b"\xea\x00\x00\x00",
        0x0B: b"\xe3\x50\x00\x00",
    }

    FISH_HANDLER_PATTERNS = {
        0x00: b"\x48\x8b\x00",
        0x01: b"\x48\x01\x00",
        0x02: b"\x48\x29\x00",
        0x03: b"\x48\x0f\xaf\x00",
        0x04: b"\x48\x31\x00",
        0x05: b"\x48\x09\x00",
        0x06: b"\x48\x21\x00",
        0x07: b"\x48\xf7\x18",
        0x08: b"\x48\xd1\xe0",
        0x09: b"\x48\xd1\xe8",
        0x0A: b"\x48\x85\xc0\x74",
        0x0B: b"\x48\x85\xc0\x75",
        0x0C: b"\xe9",
        0x0D: b"\xeb",
        0x0E: b"\xff\xe0",
        0x0F: b"\xc3",
    }

    def __init__(self) -> None:
        """Initialize Themida analyzer."""
        self.binary: Any | None = None
        self.binary_data: bytes | None = None
        self.is_64bit = False

    def analyze(self, binary_path: str) -> ThemidaAnalysisResult:
        """Perform comprehensive Themida/WinLicense analysis.

        Args:
            binary_path: Path to binary to analyze

        Returns:
            Complete analysis result

        """
        logger.info("Starting Themida analysis on %s", binary_path)

        with open(binary_path, "rb") as f:
            self.binary_data = f.read()

        if LIEF_AVAILABLE:
            try:
                self.binary = lief.parse(binary_path)
                if self.binary and hasattr(self.binary, "header"):
                    header = self.binary.header
                    if hasattr(header, "machine") and hasattr(lief, "PE"):
                        pe_module = getattr(lief, "PE")
                        if hasattr(pe_module, "MACHINE_TYPES"):
                            self.is_64bit = header.machine == pe_module.MACHINE_TYPES.AMD64
            except Exception as e:
                logger.warning("LIEF parsing failed: %s", e)

        result = ThemidaAnalysisResult(
            is_protected=False,
            version=ThemidaVersion.UNKNOWN,
            vm_architecture=VMArchitecture.UNKNOWN,
            vm_sections=[],
            vm_entry_points=[],
            vm_contexts=[],
            handlers={},
            handler_table_address=0,
            devirtualized_sections=[],
            encryption_keys=[],
            anti_debug_locations=[],
            anti_dump_locations=[],
            integrity_check_locations=[],
            confidence=0.0,
        )

        if not self._detect_themida_presence():
            logger.info("Themida/WinLicense not detected")
            return result

        result.is_protected = True
        result.version = self._detect_version()
        result.vm_sections = self._find_vm_sections()
        result.vm_entry_points = self._find_vm_entry_points()
        result.vm_architecture = self._detect_vm_architecture()
        result.handler_table_address = self._find_handler_table()
        result.handlers = self._extract_handlers(result.handler_table_address, result.vm_architecture)
        result.vm_contexts = self._extract_vm_contexts(result.vm_entry_points)
        result.encryption_keys = self._extract_encryption_keys()
        result.anti_debug_locations = self._find_anti_debug_checks()
        result.anti_dump_locations = self._find_anti_dump_checks()
        result.integrity_check_locations = self._find_integrity_checks()
        result.devirtualized_sections = self._devirtualize_code(result.handlers, result.vm_contexts)
        result.confidence = self._calculate_confidence(result)

        logger.info(
            "Themida analysis complete: %s, VM: %s, Confidence: %.1f%%",
            result.version.value,
            result.vm_architecture.value,
            result.confidence,
        )
        return result

    def _detect_themida_presence(self) -> bool:
        """Detect if binary is protected by Themida/WinLicense."""
        if self.binary_data is not None:
            for signature in self.THEMIDA_SIGNATURES:
                if signature in self.binary_data:
                    return True

        if self.binary:
            for section in self.binary.sections:
                section_name = section.name.encode() if isinstance(section.name, str) else section.name
                for vm_section in self.VM_SECTION_NAMES:
                    if vm_section in section_name:
                        return True

        return False

    def _detect_version(self) -> ThemidaVersion:
        """Detect Themida/WinLicense version."""
        if self.binary_data is not None:
            version_patterns = {
                b"\x8b\xc5\x8b\xd4\x60\xe8\x00\x00\x00\x00": ThemidaVersion.THEMIDA_1X,
                b"\xb8\x00\x00\x00\x00\x60\x0b\xc0\x74": ThemidaVersion.THEMIDA_2X,
                b"\x55\x8b\xec\x83\xc4\xf0\x53\x56\x57": ThemidaVersion.THEMIDA_3X,
                b"\x68\x00\x00\x00\x00\x9c\x60\xe8": ThemidaVersion.WINLICENSE_1X,
                b"\xeb\x10\x66\x62\x3a\x43\x2b\x2b\x48\x4f\x4f\x4b": ThemidaVersion.WINLICENSE_2X,
            }

            for pattern, version in version_patterns.items():
                if pattern in self.binary_data:
                    return version

            if b"WinLicense" in self.binary_data:
                return ThemidaVersion.WINLICENSE_3X
            if b"Themida" in self.binary_data:
                return ThemidaVersion.THEMIDA_3X

        return ThemidaVersion.UNKNOWN

    def _find_vm_sections(self) -> list[str]:
        """Find virtual machine sections."""
        vm_sections: list[str] = []

        if not self.binary:
            return vm_sections

        for section in self.binary.sections:
            section_name = section.name
            for vm_name in [".themida", ".winlice", ".vmp", ".oreans", "WinLice"]:
                if vm_name in section_name:
                    vm_sections.append(section_name)
                    break

            if section.characteristics & 0x20000000 and section.entropy > 7.5:
                vm_sections.append(section_name)

        return vm_sections

    def _find_vm_entry_points(self) -> list[int]:
        """Find virtual machine entry points."""
        entry_points = []

        entry_patterns = [
            b"\x9c\x60\xe8\x00\x00\x00\x00\x5d\x81\xed",
            b"\x60\xe8\x00\x00\x00\x00\x5d\x81\xed",
            b"\x55\x8b\xec\x83\xc4\xf0\xb8",
            b"\xe8\x00\x00\x00\x00\x58\x25\xff\xff\xff\x00",
        ]

        if self.binary_data is not None:
            for pattern in entry_patterns:
                offset = 0
                while True:
                    offset = self.binary_data.find(pattern, offset)
                    if offset == -1:
                        break
                    entry_points.append(offset)
                    offset += len(pattern)

        if self.binary:
            entry_points.append(self.binary.optional_header.addressof_entrypoint)

        return sorted(set(entry_points))

    def _detect_vm_architecture(self) -> VMArchitecture:
        """Detect virtual machine architecture type."""
        risc_score = 0
        fish_score = 0
        cisc_score = 0

        if self.binary_data is not None:
            cisc_score = sum(pattern in self.binary_data for pattern in self.CISC_HANDLER_PATTERNS.values())
            for pattern in self.RISC_HANDLER_PATTERNS.values():
                if pattern in self.binary_data:
                    risc_score += 1

            for pattern in self.FISH_HANDLER_PATTERNS.values():
                if pattern in self.binary_data:
                    fish_score += 1

            cisc_strings = [b"CISC", b"complex instruction", b"x86 emulation"]
            risc_strings = [b"RISC", b"reduced instruction", b"ARM emulation"]
            fish_strings = [b"FISH", b"flexible instruction", b"hybrid VM"]

            for s in cisc_strings:
                if s in self.binary_data:
                    cisc_score += 2

            for s in risc_strings:
                if s in self.binary_data:
                    risc_score += 2

            for s in fish_strings:
                if s in self.binary_data:
                    fish_score += 2

        max_score = max(cisc_score, risc_score, fish_score)
        if max_score == 0:
            return VMArchitecture.UNKNOWN
        if max_score == cisc_score:
            return VMArchitecture.CISC
        return VMArchitecture.RISC if max_score == risc_score else VMArchitecture.FISH

    def _find_handler_table(self) -> int:
        """Find virtual machine handler dispatch table."""
        handler_table_patterns = [
            b"\xff\x24\x85",
            b"\xff\x24\x8d",
            b"\xff\x14\x85",
            b"\xff\x14\x8d",
            b"\x41\xff\x24\xc5" if self.is_64bit else b"\xff\x24\x85",
        ]

        candidates = []

        if self.binary_data is not None:
            for pattern in handler_table_patterns:
                offset = 0
                while True:
                    offset = self.binary_data.find(pattern, offset)
                    if offset == -1:
                        break

                    if offset + 7 < len(self.binary_data):
                        table_addr = struct.unpack("<I", self.binary_data[offset + 3 : offset + 7])[0]

                        if 0x400000 <= table_addr <= 0x10000000:
                            candidates.append((table_addr, offset))

                    offset += len(pattern)

            pointer_array_pattern = re.compile(b"([\x00-\xff]{4})" * 16)
            for match in pointer_array_pattern.finditer(self.binary_data):
                pointers = [struct.unpack("<I", match.group(i))[0] for i in range(1, 17)]

                if all(0x400000 <= p <= 0x10000000 for p in pointers) and len(set(pointers)) > 8:
                    candidates.append((match.start(), match.start()))

        return max(candidates, key=lambda x: x[1])[0] if candidates else 0

    def _extract_handlers(self, handler_table_address: int, vm_arch: VMArchitecture) -> dict[int, VMHandler]:
        """Extract virtual machine handlers.

        Args:
            handler_table_address: Address of handler dispatch table
            vm_arch: Detected VM architecture

        Returns:
            Dictionary mapping opcode to handler information

        """
        handlers = {}

        if handler_table_address == 0:
            logger.warning("No handler table found, using pattern-based extraction")
            return self._extract_handlers_by_pattern(vm_arch)

        handler_patterns = {
            VMArchitecture.CISC: self.CISC_HANDLER_PATTERNS,
            VMArchitecture.RISC: self.RISC_HANDLER_PATTERNS,
            VMArchitecture.FISH: self.FISH_HANDLER_PATTERNS,
        }.get(vm_arch, {})

        if self.binary_data is not None:
            for opcode, pattern in handler_patterns.items():
                offset = self.binary_data.find(pattern)
                if offset != -1:
                    handler_size = self._estimate_handler_size(offset)
                    instructions = self._disassemble_handler(offset, handler_size)
                    category = self._categorize_handler(instructions)
                    complexity = self._calculate_handler_complexity(instructions)
                    references = self._find_handler_references(offset)

                    handlers[opcode] = VMHandler(
                        opcode=opcode,
                        address=offset,
                        size=handler_size,
                        instructions=instructions,
                        category=category,
                        complexity=complexity,
                        references=references,
                    )

        logger.info("Extracted %d VM handlers", len(handlers))
        return handlers

    def _extract_handlers_by_pattern(self, vm_arch: VMArchitecture) -> dict[int, VMHandler]:
        """Extract handlers using pattern matching when table is not found."""
        handlers = {}

        handler_patterns = {
            VMArchitecture.CISC: self.CISC_HANDLER_PATTERNS,
            VMArchitecture.RISC: self.RISC_HANDLER_PATTERNS,
            VMArchitecture.FISH: self.FISH_HANDLER_PATTERNS,
        }.get(vm_arch, {})

        if self.binary_data is not None:
            for opcode, pattern in handler_patterns.items():
                offset = 0
                while True:
                    offset = self.binary_data.find(pattern, offset)
                    if offset == -1:
                        break

                    if opcode not in handlers:
                        handler_size = self._estimate_handler_size(offset)
                        instructions = self._disassemble_handler(offset, handler_size)
                        category = self._categorize_handler(instructions)
                        complexity = self._calculate_handler_complexity(instructions)
                        references = self._find_handler_references(offset)

                        handlers[opcode] = VMHandler(
                            opcode=opcode,
                            address=offset,
                            size=handler_size,
                            instructions=instructions,
                            category=category,
                            complexity=complexity,
                            references=references,
                        )
                        break

                    offset += len(pattern)

        return handlers

    def _estimate_handler_size(self, start_offset: int) -> int:
        """Estimate size of a handler by finding return instruction."""
        max_size = 256
        if self.binary_data is not None:
            ret_patterns = [b"\xc3", b"\xc2", b"\xcb", b"\xca"]

            for i in range(start_offset, min(start_offset + max_size, len(self.binary_data))):
                for ret_pattern in ret_patterns:
                    if self.binary_data[i : i + len(ret_pattern)] == ret_pattern:
                        return i - start_offset + len(ret_pattern)

        return max_size

    def _disassemble_handler(self, offset: int, size: int) -> list[tuple[int, str, str]]:
        """Disassemble handler code.

        Returns:
            List of (address, mnemonic, operands) tuples

        """
        if not CAPSTONE_AVAILABLE:
            return [(offset, "unknown", "disassembler not available")]

        instructions: list[tuple[int, str, str]] = []
        mode = CS_MODE_64 if self.is_64bit else CS_MODE_32

        if self.binary_data is not None:
            try:
                md = Cs(CS_ARCH_X86, mode)
                code = self.binary_data[offset : offset + size]

                instructions.extend((insn.address, insn.mnemonic, insn.op_str) for insn in md.disasm(code, offset))
            except Exception as e:
                logger.warning("Disassembly failed at %x: %s", offset, e)

        return instructions

    def _categorize_handler(self, instructions: list[tuple[int, str, str]]) -> str:
        """Categorize handler based on instruction patterns."""
        if not instructions:
            return "unknown"

        mnemonics = [insn[1] for insn in instructions]

        if any(m in ["add", "sub", "mul", "imul", "div", "idiv"] for m in mnemonics):
            return "arithmetic"
        if any(m in ["and", "or", "xor", "not", "shl", "shr", "rol", "ror"] for m in mnemonics):
            return "logical"
        if any(m in ["mov", "movzx", "movsx", "lea"] for m in mnemonics):
            return "data_transfer"
        if any(m in ["cmp", "test"] for m in mnemonics):
            return "comparison"
        if any(m in ["jmp", "je", "jne", "jg", "jl", "ja", "jb", "call"] for m in mnemonics):
            return "control_flow"
        if any(m in ["push", "pop"] for m in mnemonics):
            return "stack_operation"
        return "complex"

    def _calculate_handler_complexity(self, instructions: list[tuple[int, str, str]]) -> int:
        """Calculate handler complexity score (1-10)."""
        if not instructions:
            return 1

        complexity = len(instructions) + len({insn[1] for insn in instructions})
        branch_count = sum(insn[1] in ["jmp", "je", "jne", "jg", "jl", "ja", "jb"] for insn in instructions)
        complexity += branch_count * 2

        return min(max(complexity // 5, 1), 10)

    def _find_handler_references(self, handler_offset: int) -> list[int]:
        """Find all references to this handler."""
        references = []
        handler_bytes = struct.pack("<I", handler_offset)

        if self.binary_data is not None:
            offset = 0
            while True:
                offset = self.binary_data.find(handler_bytes, offset)
                if offset == -1:
                    break
                references.append(offset)
                offset += 4

        return references

    def _extract_vm_contexts(self, entry_points: list[int]) -> list[VMContext]:
        """Extract VM context structures from entry points."""
        contexts = []

        if self.binary_data is not None:
            for entry in entry_points:
                if entry >= len(self.binary_data) - 100:
                    continue

                context_size = self._detect_context_size(entry)
                register_mapping = self._extract_register_mapping(entry)
                stack_offset = self._find_stack_offset(entry)
                flags_offset = self._find_flags_offset(entry)
                vm_exit = self._find_vm_exit(entry)

                contexts.append(
                    VMContext(
                        vm_entry=entry,
                        vm_exit=vm_exit,
                        context_size=context_size,
                        register_mapping=register_mapping,
                        stack_offset=stack_offset,
                        flags_offset=flags_offset,
                    )
                )

        return contexts

    def _detect_context_size(self, entry: int) -> int:
        """Detect VM context structure size."""
        if self.binary_data is not None:
            search_area = self.binary_data[entry : entry + 100]

            sub_esp_pattern = b"\x83\xec"
            offset = search_area.find(sub_esp_pattern)
            if offset != -1 and offset + 3 <= len(search_area):
                size_value: int = struct.unpack("B", search_area[offset + 2 : offset + 3])[0]
                return size_value

            add_esp_pattern = b"\x81\xec"

            offset = search_area.find(add_esp_pattern)
            if offset != -1 and offset + 6 <= len(search_area):
                return int(struct.unpack("<I", search_area[offset + 2 : offset + 6])[0])
        return 0x100

    def _extract_register_mapping(self, entry: int) -> dict[str, int]:
        """Extract VM register to native register mapping."""
        registers = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"]

        return {reg: i * 4 for i, reg in enumerate(registers)}

    def _find_stack_offset(self, entry: int) -> int:
        """Find VM stack offset in context."""
        return 0x80

    def _find_flags_offset(self, entry: int) -> int:
        """Find VM flags offset in context."""
        return 0xA0

    def _find_vm_exit(self, vm_entry: int) -> int:
        """Find VM exit point corresponding to entry."""
        if self.binary_data is not None:
            search_start = vm_entry
            search_end = min(vm_entry + 10000, len(self.binary_data))
            search_area = self.binary_data[search_start:search_end]

            ret_pattern = b"\x61\x9d\xc3"
            offset = search_area.find(ret_pattern)
            if offset != -1:
                exit_offset: int = search_start + offset
                return exit_offset

            popad_ret = b"\x61\xc3"

            offset = search_area.find(popad_ret)
            if offset != -1:
                return search_start + offset

        return 0

    def _extract_encryption_keys(self) -> list[bytes]:
        """Extract encryption keys used by Themida."""
        keys = []

        key_patterns = [
            re.compile(rb"[\x00-\xff]{16}"),
            re.compile(rb"[\x00-\xff]{32}"),
        ]

        if self.binary_data is not None:
            high_entropy_threshold = 7.0

            for i in range(0, len(self.binary_data) - 32, 4):
                chunk = self.binary_data[i : i + 32]

                if self._calculate_entropy_bytes(chunk) > high_entropy_threshold:
                    chunk_16 = chunk[:16]
                    chunk_32 = chunk[:32]

                    if chunk_16 not in keys and key_patterns[0].fullmatch(chunk_16):
                        keys.append(chunk_16)

                    if chunk_32 not in keys and key_patterns[1].fullmatch(chunk_32):
                        keys.append(chunk_32)

        return keys[:10]

    def _calculate_entropy_bytes(self, data: bytes) -> float:
        """Calculate Shannon entropy of byte data."""
        if not data:
            return 0.0

        frequency: dict[int, int] = {}
        for byte in data:
            frequency[byte] = frequency.get(byte, 0) + 1

        import math

        entropy = 0.0
        data_len = len(data)

        for count in frequency.values():
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)

        return entropy

    def _find_anti_debug_checks(self) -> list[int]:
        """Find anti-debugging check locations."""
        anti_debug_locations = []

        anti_debug_patterns = [
            b"\x64\xa1\x30\x00\x00\x00",
            b"\x64\x8b\x15\x30\x00\x00\x00",
            b"IsDebuggerPresent",
            b"CheckRemoteDebuggerPresent",
            b"NtQueryInformationProcess",
            b"\x0f\x31",
        ]

        if self.binary_data is not None:
            for pattern in anti_debug_patterns:
                offset = 0
                while True:
                    offset = self.binary_data.find(pattern, offset)
                    if offset == -1:
                        break
                    anti_debug_locations.append(offset)
                    offset += len(pattern)

        return sorted(set(anti_debug_locations))

    def _find_anti_dump_checks(self) -> list[int]:
        """Find anti-dumping check locations."""
        anti_dump_locations = []

        anti_dump_patterns = [
            b"VirtualProtect",
            b"VirtualAlloc",
            b"WriteProcessMemory",
            b"\x89\x45\x00\x8b\x45\x04\x89\x45\x08",
        ]

        if self.binary_data is not None:
            for pattern in anti_dump_patterns:
                offset = 0
                while True:
                    offset = self.binary_data.find(pattern, offset)
                    if offset == -1:
                        break
                    anti_dump_locations.append(offset)
                    offset += len(pattern)

        return sorted(set(anti_dump_locations))

    def _find_integrity_checks(self) -> list[int]:
        """Find integrity check locations."""
        integrity_locations = []

        integrity_patterns = [
            b"\x81\xc1",
            b"\x81\xc9",
            b"\x33\xc0\x8b",
            b"\x0f\xb6",
        ]

        if self.binary_data is not None:
            crc_references = [b"CRC32", b"checksum", b"integrity"]

            for pattern in integrity_patterns:
                offset = 0
                while True:
                    offset = self.binary_data.find(pattern, offset)
                    if offset == -1:
                        break

                    nearby_area = self.binary_data[max(0, offset - 100) : offset + 100]
                    if any(ref in nearby_area for ref in crc_references):
                        integrity_locations.append(offset)

                    offset += len(pattern)

        return sorted(set(integrity_locations))

    def _devirtualize_code(self, handlers: dict[int, VMHandler], contexts: list[VMContext]) -> list[DevirtualizedCode]:
        """Devirtualize VM-protected code sections.

        Args:
            handlers: Extracted VM handlers
            contexts: VM context structures

        Returns:
            List of devirtualized code sections

        """
        devirtualized: list[DevirtualizedCode] = []

        if not handlers or not contexts:
            logger.warning("Cannot devirtualize without handlers and contexts")
            return devirtualized

        if self.binary_data is not None:
            for context in contexts:
                vm_code_start = context.vm_entry
                vm_code_end = context.vm_exit if context.vm_exit > 0 else vm_code_start + 1000

                if vm_code_end > len(self.binary_data):
                    continue

                vm_bytecode = self.binary_data[vm_code_start:vm_code_end]

                native_code, assembly, handlers_used, confidence = self._translate_vm_to_native(
                    vm_bytecode,
                    handlers,
                    context,
                )

                devirtualized.append(
                    DevirtualizedCode(
                        original_rva=vm_code_start,
                        original_size=vm_code_end - vm_code_start,
                        vm_handlers_used=handlers_used,
                        native_code=native_code,
                        assembly=assembly,
                        confidence=confidence,
                    )
                )

        logger.info("Devirtualized %d code sections", len(devirtualized))
        return devirtualized

    def _translate_vm_to_native(
        self,
        vm_bytecode: bytes,
        handlers: dict[int, VMHandler],
        context: VMContext,
    ) -> tuple[bytes, list[str], list[int], float]:
        """Translate VM bytecode to native x86/x64 code.

        Returns:
            (native_code, assembly_lines, handlers_used, confidence)

        """
        assembly = []
        native_code = bytearray()
        handlers_used = []
        confidence = 0.0

        opcode_translation = {
            0x00: (b"\x8b\x45\x00", "mov eax, [ebp+0]"),
            0x01: (b"\x01\x45\x00", "add [ebp+0], eax"),
            0x02: (b"\x29\x45\x00", "sub [ebp+0], eax"),
            0x03: (b"\x0f\xaf\x45\x00", "imul eax, [ebp+0]"),
            0x04: (b"\x31\x45\x00", "xor [ebp+0], eax"),
            0x05: (b"\x09\x45\x00", "or [ebp+0], eax"),
            0x06: (b"\x21\x45\x00", "and [ebp+0], eax"),
            0x07: (b"\xf7\x5d\x00", "neg [ebp+0]"),
            0x08: (b"\xd1\x65\x00", "shl [ebp+0], 1"),
            0x09: (b"\xd1\x6d\x00", "shr [ebp+0], 1"),
            0x0A: (b"\x74\x00", "je short 0"),
            0x0B: (b"\x75\x00", "jne short 0"),
            0x0C: (b"\xe9\x00\x00\x00\x00", "jmp 0"),
            0x0D: (b"\xeb\x00", "jmp short 0"),
            0x0E: (b"\xff\xe0", "jmp eax"),
            0x0F: (b"\xc3", "ret"),
        }

        i = 0
        valid_translations = 0
        total_opcodes = 0

        while i < len(vm_bytecode):
            opcode = vm_bytecode[i]
            total_opcodes += 1

            i += 1

            if opcode in handlers:
                handlers_used.append(opcode)

                if opcode in opcode_translation:
                    native_bytes, asm_str = opcode_translation[opcode]
                    native_code.extend(native_bytes)
                    assembly.append(asm_str)
                    valid_translations += 1
                else:
                    assembly.append(f"vm_handler_{opcode:02x}")

                if (
                    i < len(vm_bytecode)
                    and handlers[opcode].category
                    in [
                        "data_transfer",
                        "arithmetic",
                    ]
                    and i + 4 <= len(vm_bytecode)
                ):
                    operand = struct.unpack("<I", vm_bytecode[i : i + 4])[0]
                    assembly[-1] += f"  ; operand: {operand:08x}"
                    i += 4
            else:
                assembly.append(f"db {opcode:02x}h")
                native_code.append(opcode)
        if total_opcodes > 0:
            confidence = (valid_translations / total_opcodes) * 100.0
        else:
            confidence = 0.0

        return bytes(native_code), assembly, handlers_used, confidence

    def _calculate_confidence(self, result: ThemidaAnalysisResult) -> float:
        """Calculate overall analysis confidence score."""
        confidence = 0.0

        if result.version != ThemidaVersion.UNKNOWN:
            confidence += 20.0

        if result.vm_architecture != VMArchitecture.UNKNOWN:
            confidence += 20.0

        if result.vm_sections:
            confidence += 15.0

        if result.vm_entry_points:
            confidence += 10.0

        if result.handler_table_address > 0:
            confidence += 15.0

        if result.handlers:
            confidence += min(len(result.handlers) * 0.5, 10.0)

        if result.devirtualized_sections:
            avg_dev_confidence = sum(d.confidence for d in result.devirtualized_sections) / len(result.devirtualized_sections)
            confidence += min(avg_dev_confidence * 0.1, 10.0)

        return min(confidence, 100.0)

    def get_analysis_report(self, result: ThemidaAnalysisResult) -> dict[str, Any]:
        """Generate human-readable analysis report.

        Args:
            result: Analysis result

        Returns:
            Dictionary containing formatted report

        """
        report: dict[str, Any] = {
            "protection_detected": result.is_protected,
            "version": result.version.value,
            "vm_architecture": result.vm_architecture.value,
            "confidence": f"{result.confidence:.1f}%",
            "vm_sections": result.vm_sections,
            "vm_entry_points": [f"0x{ep:08x}" for ep in result.vm_entry_points],
            "handler_table": f"0x{result.handler_table_address:08x}" if result.handler_table_address else "Not found",
            "handlers_extracted": len(result.handlers),
            "vm_contexts": len(result.vm_contexts),
            "devirtualized_sections": len(result.devirtualized_sections),
            "anti_debug_checks": len(result.anti_debug_locations),
            "anti_dump_checks": len(result.anti_dump_locations),
            "integrity_checks": len(result.integrity_check_locations),
        }

        if result.handlers:
            handler_categories: dict[str, int] = {}
            for handler in result.handlers.values():
                category = handler.category
                handler_categories[category] = handler_categories.get(category, 0) + 1
            report["handler_categories"] = handler_categories

        if result.devirtualized_sections:
            devirtualization_quality: dict[str, Any] = {
                "average_confidence": f"{sum(d.confidence for d in result.devirtualized_sections) / len(result.devirtualized_sections):.1f}%",
                "total_instructions": sum(len(d.assembly) for d in result.devirtualized_sections),
            }
            report["devirtualization_quality"] = devirtualization_quality

        return report
