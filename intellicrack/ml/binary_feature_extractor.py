"""Production-ready binary feature extraction for neural network training.

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


import contextlib
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, Any

import numpy as np
from numpy.typing import NDArray

from ..utils.logger import get_logger


logger = get_logger(__name__)


try:
    import capstone

    capstone_module: ModuleType | None = capstone
    from capstone_module import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
    CAPSTONE_AVAILABLE = True
except ImportError:
    logger.debug("Capstone not available", exc_info=True)
    CAPSTONE_AVAILABLE = False
    capstone_module = None
    CS_ARCH_X86 = 0
    CS_MODE_32 = 0
    CS_MODE_64 = 0
    Cs = None

try:
    import pefile

    pefile_module: ModuleType | None = pefile
    PEFILE_AVAILABLE = True
except ImportError:
    logger.debug("pefile not available", exc_info=True)
    PEFILE_AVAILABLE = False
    pefile_module = None

try:
    import networkx

    nx_module: ModuleType | None = networkx
    NETWORKX_AVAILABLE = True
except ImportError:
    logger.debug("NetworkX not available", exc_info=True)
    NETWORKX_AVAILABLE = False
    nx_module = None

try:
    import lief

    lief_module: ModuleType | None = lief
    LIEF_AVAILABLE = True
except ImportError:
    logger.debug("LIEF not available", exc_info=True)
    LIEF_AVAILABLE = False
    lief_module = None


class BinaryFeatureExtractor:
    """Advanced feature extraction from binaries for ML training."""

    def __init__(self, binary_path: str) -> None:
        """Initialize feature extractor with binary file."""
        self.binary_path = Path(binary_path)
        self.logger = logger
        self.data: bytes | None = None
        self.pe: Any = None
        self.lief_binary: Any = None
        self.arch: int | None = None
        self.mode: int | None = None
        self.disassembler: Any = None

        # Load binary
        self._load_binary()

        # Initialize disassemblers
        self._init_disassembler()

    def _load_binary(self) -> None:
        """Load binary file and parse headers."""
        with open(self.binary_path, "rb") as f:
            self.data = f.read()

        # Try PE parsing
        if PEFILE_AVAILABLE and pefile_module is not None and self.data is not None:
            try:
                self.pe = pefile_module.PE(data=self.data, fast_load=True)
                if self.pe is not None:
                    self.pe.parse_data_directories()

                    self.arch = CS_ARCH_X86
                    # Determine architecture
                    self.mode = CS_MODE_64 if self.pe.FILE_HEADER.Machine == 0x8664 else CS_MODE_32
            except Exception as e:
                self.logger.warning("PE parsing failed: %s", e, exc_info=True)

        # Try LIEF for cross-platform support
        if LIEF_AVAILABLE and lief_module is not None and not self.pe and self.data is not None:
            try:
                self.lief_binary = lief_module.parse(self.data)
                if self.lief_binary is not None:
                    lief_format = getattr(lief_module, "EXE_FORMATS", None)
                    if lief_format is not None and hasattr(lief_format, "PE") and self.lief_binary.format == lief_format.PE:
                        lief_pe = getattr(lief_module, "PE", None)
                        if lief_pe is not None and hasattr(lief_pe, "MACHINE_TYPES"):
                            machine_types = lief_pe.MACHINE_TYPES
                            if hasattr(machine_types, "I386") and self.lief_binary.header.machine == machine_types.I386:
                                self.arch = CS_ARCH_X86
                                self.mode = CS_MODE_32
                            elif hasattr(machine_types, "AMD64") and self.lief_binary.header.machine == machine_types.AMD64:
                                self.arch = CS_ARCH_X86
                                self.mode = CS_MODE_64
            except Exception as e:
                self.logger.warning("LIEF parsing failed: %s", e, exc_info=True)

        # Default to x86-64 if unable to determine
        if not self.arch:
            self.arch = CS_ARCH_X86
            self.mode = CS_MODE_64

    def _init_disassembler(self) -> None:
        """Initialize Capstone disassembler."""
        if CAPSTONE_AVAILABLE and Cs is not None:
            self.disassembler = Cs(self.arch, self.mode)
            self.disassembler.detail = True
        else:
            self.disassembler = None

    def extract_opcode_histogram(self, normalize: bool = True) -> NDArray[np.float32]:
        """Extract histogram of x86/x64 opcodes using Capstone."""
        if not CAPSTONE_AVAILABLE or not self.disassembler or self.data is None:
            # Fallback to byte histogram
            histogram = np.zeros(256, dtype=np.float32)
            if self.data is not None:
                for byte in self.data:
                    histogram[byte] += 1
                if normalize and len(self.data) > 0:
                    histogram /= len(self.data)
            return histogram

        # Create opcode frequency map
        opcode_counts: dict[str, int] = {}
        total_instructions = 0

        # Get executable sections
        exec_sections = self._get_executable_sections()

        for section_data, section_va in exec_sections:
            try:
                # Disassemble section
                for insn in self.disassembler.disasm(section_data, section_va):
                    opcode_counts[insn.mnemonic] = opcode_counts.get(insn.mnemonic, 0) + 1
                    total_instructions += 1
            except Exception as e:
                self.logger.debug("Disassembly error: %s", e, exc_info=True)

        # Create feature vector for most common opcodes
        common_opcodes = [
            "mov",
            "push",
            "call",
            "pop",
            "ret",
            "jmp",
            "je",
            "jne",
            "cmp",
            "test",
            "lea",
            "add",
            "sub",
            "xor",
            "and",
            "or",
            "shl",
            "shr",
            "nop",
            "int",
            "inc",
            "dec",
            "mul",
            "div",
            "jg",
            "jl",
            "jge",
            "jle",
            "jz",
            "jnz",
            "movzx",
            "movsx",
            "imul",
            "idiv",
            "cdq",
            "cbw",
            "cwde",
            "cdqe",
            "rep",
            "repe",
            "repne",
            "loop",
            "loope",
            "loopne",
            "syscall",
            "sysenter",
            "cpuid",
        ]

        histogram = np.zeros(len(common_opcodes) + 1, dtype=np.float32)

        for i, opcode in enumerate(common_opcodes):
            histogram[i] = opcode_counts.get(opcode, 0)

        # Last element for "other" opcodes
        other_count = sum(count for op, count in opcode_counts.items() if op not in common_opcodes)
        histogram[-1] = other_count

        if normalize and total_instructions > 0:
            histogram /= total_instructions

        return histogram

    def _get_executable_sections(self) -> list[tuple[bytes, int]]:
        """Get executable sections from binary."""
        sections: list[tuple[bytes, int]] = []

        if self.pe is not None:
            for section in self.pe.sections:
                # Check if section is executable
                if section.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                    section_data = section.get_data()
                    section_va = self.pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
                    sections.append((section_data, section_va))
        elif self.lief_binary is not None and lief_module is not None:
            lief_pe = getattr(lief_module, "PE", None)
            if lief_pe is not None and hasattr(lief_pe, "SECTION_CHARACTERISTICS"):
                section_chars = lief_pe.SECTION_CHARACTERISTICS
                if hasattr(section_chars, "MEM_EXECUTE"):
                    sections.extend(
                        (bytes(section.content), section.virtual_address)
                        for section in self.lief_binary.sections
                        if section.has_characteristic(section_chars.MEM_EXECUTE)
                    )
        elif self.data is not None:
            # Fallback: treat entire binary as executable
            sections.append((self.data, 0x400000))

        return sections

    def build_control_flow_graph(self) -> dict[str, Any]:
        """Build control flow graph and extract graph features."""
        if not NETWORKX_AVAILABLE or nx_module is None:
            return {
                "num_nodes": 0,
                "num_edges": 0,
                "avg_degree": 0.0,
                "max_degree": 0,
                "density": 0.0,
                "num_components": 0,
                "largest_component": 0,
            }

        cfg = nx_module.DiGraph()
        basic_blocks = self._extract_basic_blocks()

        # Build graph from basic blocks
        for block in basic_blocks:
            cfg.add_node(block["start"], size=block["size"], type=block["type"])

            for target in block.get("targets", []):
                cfg.add_edge(block["start"], target)

        # Extract graph features
        features: dict[str, Any] = {
            "num_nodes": cfg.number_of_nodes(),
            "num_edges": cfg.number_of_edges(),
            "avg_degree": 0.0,
            "max_degree": 0,
            "density": nx_module.density(cfg) if cfg.number_of_nodes() > 0 else 0.0,
            "num_components": nx_module.number_weakly_connected_components(cfg),
            "largest_component": 0,
        }

        if cfg.number_of_nodes() > 0:
            degrees = [d for n, d in cfg.degree()]
            features["avg_degree"] = float(np.mean(degrees))
            features["max_degree"] = max(degrees)

            if nx_module is not None:
                if components := list(nx_module.weakly_connected_components(cfg)):
                    features["largest_component"] = len(max(components, key=len))

        return features

    def _extract_basic_blocks(self) -> list[dict[str, Any]]:
        """Extract basic blocks from binary."""
        blocks: list[dict[str, Any]] = []

        if not CAPSTONE_AVAILABLE or not self.disassembler or capstone_module is None:
            return blocks

        exec_sections = self._get_executable_sections()

        for section_data, section_va in exec_sections:
            current_block: dict[str, Any] = {"start": section_va, "size": 0, "type": "normal", "targets": []}

            try:
                for insn in self.disassembler.disasm(section_data, section_va):
                    current_block["size"] = current_block["size"] + insn.size

                    # Check if instruction ends basic block
                    if insn.mnemonic in [
                        "ret",
                        "retn",
                        "jmp",
                        "je",
                        "jne",
                        "jg",
                        "jl",
                        "jge",
                        "jle",
                        "jz",
                        "jnz",
                        "call",
                    ]:
                        if insn.mnemonic == "ret":
                            current_block["type"] = "return"
                        elif insn.mnemonic == "call":
                            current_block["type"] = "call"
                        elif insn.mnemonic.startswith("j"):
                            current_block["type"] = "conditional"

                        # Extract jump/call targets
                        if insn.operands and capstone_module is not None:
                            x86_module = getattr(capstone_module, "x86", None)
                            if x86_module is not None and hasattr(x86_module, "X86_OP_IMM"):
                                op = insn.operands[0]
                                if op.type == x86_module.X86_OP_IMM:
                                    target_list = current_block["targets"]
                                    if isinstance(target_list, list):
                                        target_list.append(op.imm)

                        blocks.append(current_block)

                        # Start new block
                        current_block = {
                            "start": insn.address + insn.size,
                            "size": 0,
                            "type": "normal",
                            "targets": [],
                        }

                # Add final block if it has content
                block_size = current_block["size"]
                if isinstance(block_size, int) and block_size > 0:
                    blocks.append(current_block)

            except Exception as e:
                self.logger.debug("Basic block extraction error: %s", e, exc_info=True)

        return blocks

    def extract_api_sequences(self) -> NDArray[np.float32]:
        """Extract API call sequences from import table."""
        api_features = np.zeros(256, dtype=np.float32)

        # License-related API categories
        api_categories = {
            "registry": [
                "RegOpenKey",
                "RegQueryValue",
                "RegSetValue",
                "RegCreateKey",
                "RegDeleteKey",
                "RegEnumKey",
            ],
            "crypto": [
                "CryptHashData",
                "CryptGenKey",
                "CryptEncrypt",
                "CryptDecrypt",
                "CryptCreateHash",
                "CryptAcquireContext",
            ],
            "network": [
                "InternetOpen",
                "InternetConnect",
                "HttpOpenRequest",
                "HttpSendRequest",
                "WSAStartup",
                "connect",
                "send",
                "recv",
            ],
            "hardware": [
                "GetVolumeInformation",
                "GetSystemInfo",
                "GetComputerName",
                "GetAdaptersInfo",
                "DeviceIoControl",
            ],
            "time": [
                "GetSystemTime",
                "GetTickCount",
                "QueryPerformanceCounter",
                "GetLocalTime",
                "timeGetTime",
            ],
            "process": [
                "CreateProcess",
                "OpenProcess",
                "TerminateProcess",
                "GetCurrentProcess",
                "GetProcessId",
            ],
            "file": ["CreateFile", "ReadFile", "WriteFile", "GetFileAttributes", "FindFirstFile"],
            "memory": ["VirtualAlloc", "VirtualProtect", "VirtualFree", "HeapAlloc", "GlobalAlloc"],
        }

        imports = self._extract_imports()

        # Create feature vector based on API presence
        feature_idx = 0
        for apis in api_categories.values():
            category_count = 0
            for api in apis:
                for imp in imports:
                    if api.lower() in imp.lower():
                        category_count += 1
                        break

            # Store normalized count for this category
            if feature_idx < len(api_features):
                api_features[feature_idx] = min(category_count / len(apis), 1.0)
                feature_idx += 1

        return api_features

    def _extract_imports(self) -> list[str]:
        """Extract import table entries."""
        imports: list[str] = []

        if self.pe is not None:
            try:
                if hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
                    for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                        imports.extend(imp.name.decode("utf-8", errors="ignore") for imp in entry.imports if imp.name)
            except Exception as e:
                self.logger.debug("Import extraction error: %s", e, exc_info=True)
        elif self.lief_binary is not None:
            try:
                for imported in self.lief_binary.imports:
                    imports.extend(entry.name for entry in imported.entries if entry.name)
            except Exception as e:
                self.logger.debug("LIEF import extraction error: %s", e, exc_info=True)

        return imports

    def calculate_section_entropy(self) -> NDArray[np.float32]:
        """Calculate entropy for each section."""
        entropies: list[float] = []

        if self.pe is not None:
            for section in self.pe.sections:
                section_data = section.get_data()
                entropy = self._calculate_entropy(section_data)
                entropies.append(entropy)
        elif self.lief_binary is not None:
            for section in self.lief_binary.sections:
                section_data = bytes(section.content)
                entropy = self._calculate_entropy(section_data)
                entropies.append(entropy)
        elif self.data is not None:
            # Calculate entropy for whole binary in chunks
            chunk_size = len(self.data) // 8
            for i in range(8):
                if chunk := self.data[i * chunk_size : (i + 1) * chunk_size]:
                    entropy = self._calculate_entropy(chunk)
                    entropies.append(entropy)

        # Pad or truncate to fixed size
        while len(entropies) < 16:
            entropies.append(0.0)

        return np.array(entropies[:16], dtype=np.float32)

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0

        # Calculate byte frequency
        byte_counts = np.zeros(256)
        for byte in data:
            byte_counts[byte] += 1

        # Calculate probabilities
        probabilities = byte_counts / len(data)

        # Calculate entropy
        entropy = 0.0
        for p in probabilities:
            if p > 0:
                entropy -= p * np.log2(p)

        return entropy

    def extract_string_features(self) -> NDArray[np.float32]:
        """Extract license-related string features with encoding detection."""
        features = np.zeros(128, dtype=np.float32)

        # Extract strings with different encoding
        if self.data is None:
            return features

        ascii_strings = self._extract_strings(self.data, min_length=4, encoding="ascii")
        unicode_strings = self._extract_strings(self.data, min_length=4, encoding="utf-16le")

        all_strings = ascii_strings + unicode_strings

        # License-related patterns
        patterns = {
            "license": ["license", "licence", "licensed", "licensing"],
            "serial": ["serial", "key", "code", "productkey", "activation"],
            "trial": ["trial", "evaluation", "demo", "expired", "days_left"],
            "registration": ["register", "registration", "activate", "unlock"],
            "hardware": ["hwid", "hardware", "machine", "computer_id"],
            "network": ["http", "https", "server", "validate", "check_license"],
            "crypto": ["rsa", "aes", "signature", "hash", "encrypt"],
            "protection": ["protected", "tamper", "integrity", "checksum"],
        }

        # Count pattern occurrences
        feature_idx = 0
        for keywords in patterns.values():
            if feature_idx >= len(features):
                break

            category_count = 0
            for string in all_strings:
                string_lower = string.lower()
                for keyword in keywords:
                    if keyword in string_lower:
                        category_count += 1
                        break

            features[feature_idx] = min(category_count / 10.0, 1.0)  # Normalize
            feature_idx += 1

        # Add string statistics
        if feature_idx < len(features) - 3:
            features[feature_idx] = len(all_strings) / 1000.0  # Total strings (normalized)
            features[feature_idx + 1] = len(ascii_strings) / 1000.0  # ASCII strings
            features[feature_idx + 2] = len(unicode_strings) / 1000.0  # Unicode strings

        return features

    def _extract_strings(self, data: bytes, min_length: int = 4, encoding: str = "ascii") -> list[str]:
        """Extract strings from binary data."""
        strings = []

        if encoding == "ascii":
            # ASCII string extraction
            current_string = b""

            for byte in data:
                if 0x20 <= byte <= 0x7E:  # Printable ASCII
                    current_string += bytes([byte])
                else:
                    if len(current_string) >= min_length:
                        with contextlib.suppress(UnicodeDecodeError, ValueError):
                            strings.append(current_string.decode("ascii"))
                    current_string = b""

            # Check final string
            if len(current_string) >= min_length:
                with contextlib.suppress(UnicodeDecodeError, ValueError):
                    strings.append(current_string.decode("ascii"))

        elif encoding == "utf-16le":
            # UTF-16LE string extraction (common in Windows)
            i = 0
            while i < len(data) - 1:
                # Look for sequences of printable characters with null bytes
                current_string = b""
                while i < len(data) - 1:
                    if 0x20 <= data[i] <= 0x7E and data[i + 1] == 0:
                        current_string += bytes([data[i]])
                        i += 2
                    else:
                        break

                if len(current_string) >= min_length:
                    with contextlib.suppress(UnicodeDecodeError, ValueError):
                        strings.append(current_string.decode("ascii"))

                i += 1

        return strings

    def extract_all_features(self) -> dict[str, NDArray[np.float32]]:
        """Extract all features from binary."""
        return {
            "opcode_histogram": self.extract_opcode_histogram(),
            "cfg_features": self._cfg_to_vector(self.build_control_flow_graph()),
            "api_sequences": self.extract_api_sequences(),
            "section_entropy": self.calculate_section_entropy(),
            "string_features": self.extract_string_features(),
        }

    def _cfg_to_vector(self, cfg_dict: dict[str, Any]) -> NDArray[np.float32]:
        """Convert CFG dictionary to feature vector."""
        vector = np.zeros(16, dtype=np.float32)

        vector[0] = cfg_dict.get("num_nodes", 0) / 10000.0  # Normalize
        vector[1] = cfg_dict.get("num_edges", 0) / 10000.0
        vector[2] = cfg_dict.get("avg_degree", 0) / 100.0
        vector[3] = cfg_dict.get("max_degree", 0) / 1000.0
        vector[4] = cfg_dict.get("density", 0)
        vector[5] = cfg_dict.get("num_components", 0) / 100.0
        vector[6] = cfg_dict.get("largest_component", 0) / 10000.0

        return vector


def extract_features_for_ml(binary_path: str) -> NDArray[np.float32]:
    """Extract features from binary for ML training (convenience function)."""
    extractor = BinaryFeatureExtractor(binary_path)
    features = extractor.extract_all_features()

    return np.concatenate(
        [
            features["opcode_histogram"],
            features["cfg_features"],
            features["api_sequences"],
            features["section_entropy"],
            features["string_features"],
        ],
    )
