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
import logging
from pathlib import Path
from typing import Any

import numpy as np

try:
    import capstone
    from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False
    capstone = None

try:
    import pefile

    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False
    pefile = None

try:
    import networkx as nx

    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False
    nx = None

try:
    import lief

    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False
    lief = None


class BinaryFeatureExtractor:
    """Advanced feature extraction from binaries for ML training."""

    def __init__(self, binary_path: str) -> None:
        """Initialize feature extractor with binary file."""
        self.binary_path = Path(binary_path)
        self.logger = logging.getLogger(__name__)
        self.data = None
        self.pe = None
        self.lief_binary = None
        self.arch = None
        self.mode = None

        # Load binary
        self._load_binary()

        # Initialize disassemblers
        self._init_disassembler()

    def _load_binary(self) -> None:
        """Load binary file and parse headers."""
        with open(self.binary_path, "rb") as f:
            self.data = f.read()

        # Try PE parsing
        if PEFILE_AVAILABLE:
            try:
                self.pe = pefile.PE(data=self.data, fast_load=True)
                self.pe.parse_data_directories()

                # Determine architecture
                if self.pe.FILE_HEADER.Machine == 0x014C:  # IMAGE_FILE_MACHINE_I386
                    self.arch = CS_ARCH_X86
                    self.mode = CS_MODE_32
                elif self.pe.FILE_HEADER.Machine == 0x8664:  # IMAGE_FILE_MACHINE_AMD64
                    self.arch = CS_ARCH_X86
                    self.mode = CS_MODE_64
                else:
                    self.arch = CS_ARCH_X86
                    self.mode = CS_MODE_32
            except Exception as e:
                self.logger.warning(f"PE parsing failed: {e}")

        # Try LIEF for cross-platform support
        if LIEF_AVAILABLE and not self.pe:
            try:
                self.lief_binary = lief.parse(self.data)
                if self.lief_binary:
                    if self.lief_binary.format == lief.EXE_FORMATS.PE:
                        if self.lief_binary.header.machine == lief.PE.MACHINE_TYPES.I386:
                            self.arch = CS_ARCH_X86
                            self.mode = CS_MODE_32
                        elif self.lief_binary.header.machine == lief.PE.MACHINE_TYPES.AMD64:
                            self.arch = CS_ARCH_X86
                            self.mode = CS_MODE_64
            except Exception as e:
                self.logger.warning(f"LIEF parsing failed: {e}")

        # Default to x86-64 if unable to determine
        if not self.arch:
            self.arch = CS_ARCH_X86
            self.mode = CS_MODE_64

    def _init_disassembler(self) -> None:
        """Initialize Capstone disassembler."""
        if CAPSTONE_AVAILABLE:
            self.disassembler = Cs(self.arch, self.mode)
            self.disassembler.detail = True
        else:
            self.disassembler = None

    def extract_opcode_histogram(self, normalize: bool = True) -> np.ndarray:
        """Extract histogram of x86/x64 opcodes using Capstone."""
        if not CAPSTONE_AVAILABLE or not self.disassembler:
            # Fallback to byte histogram
            histogram = np.zeros(256, dtype=np.float32)
            for byte in self.data:
                histogram[byte] += 1
            if normalize and len(self.data) > 0:
                histogram = histogram / len(self.data)
            return histogram

        # Create opcode frequency map
        opcode_counts = {}
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
                self.logger.debug(f"Disassembly error: {e}")

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
            histogram = histogram / total_instructions

        return histogram

    def _get_executable_sections(self) -> list[tuple[bytes, int]]:
        """Get executable sections from binary."""
        sections = []

        if self.pe:
            for section in self.pe.sections:
                # Check if section is executable
                if section.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                    section_data = section.get_data()
                    section_va = self.pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
                    sections.append((section_data, section_va))
        elif self.lief_binary:
            for section in self.lief_binary.sections:
                if section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE):
                    section_data = bytes(section.content)
                    section_va = section.virtual_address
                    sections.append((section_data, section_va))
        else:
            # Fallback: treat entire binary as executable
            sections.append((self.data, 0x400000))

        return sections

    def build_control_flow_graph(self) -> dict[str, Any]:
        """Build control flow graph and extract graph features."""
        if not NETWORKX_AVAILABLE:
            return {
                "num_nodes": 0,
                "num_edges": 0,
                "avg_degree": 0.0,
                "max_degree": 0,
                "density": 0.0,
                "num_components": 0,
                "largest_component": 0,
            }

        cfg = nx.DiGraph()
        basic_blocks = self._extract_basic_blocks()

        # Build graph from basic blocks
        for block in basic_blocks:
            cfg.add_node(block["start"], size=block["size"], type=block["type"])

            for target in block.get("targets", []):
                cfg.add_edge(block["start"], target)

        # Extract graph features
        features = {
            "num_nodes": cfg.number_of_nodes(),
            "num_edges": cfg.number_of_edges(),
            "avg_degree": 0.0,
            "max_degree": 0,
            "density": nx.density(cfg) if cfg.number_of_nodes() > 0 else 0.0,
            "num_components": nx.number_weakly_connected_components(cfg),
            "largest_component": 0,
        }

        if cfg.number_of_nodes() > 0:
            degrees = [d for n, d in cfg.degree()]
            features["avg_degree"] = np.mean(degrees)
            features["max_degree"] = max(degrees)

            # Get largest component size
            components = list(nx.weakly_connected_components(cfg))
            if components:
                features["largest_component"] = len(max(components, key=len))

        return features

    def _extract_basic_blocks(self) -> list[dict[str, Any]]:
        """Extract basic blocks from binary."""
        blocks = []

        if not CAPSTONE_AVAILABLE or not self.disassembler:
            return blocks

        exec_sections = self._get_executable_sections()

        for section_data, section_va in exec_sections:
            current_block = {"start": section_va, "size": 0, "type": "normal", "targets": []}

            try:
                for insn in self.disassembler.disasm(section_data, section_va):
                    current_block["size"] += insn.size

                    # Check if instruction ends basic block
                    if insn.mnemonic in ["ret", "retn", "jmp", "je", "jne", "jg", "jl", "jge", "jle", "jz", "jnz", "call"]:
                        if insn.mnemonic == "ret":
                            current_block["type"] = "return"
                        elif insn.mnemonic == "call":
                            current_block["type"] = "call"
                        elif insn.mnemonic.startswith("j"):
                            current_block["type"] = "conditional"

                        # Extract jump/call targets
                        if insn.operands:
                            op = insn.operands[0]
                            if op.type == capstone.x86.X86_OP_IMM:
                                current_block["targets"].append(op.imm)

                        blocks.append(current_block)

                        # Start new block
                        current_block = {"start": insn.address + insn.size, "size": 0, "type": "normal", "targets": []}

                # Add final block if it has content
                if current_block["size"] > 0:
                    blocks.append(current_block)

            except Exception as e:
                self.logger.debug(f"Basic block extraction error: {e}")

        return blocks

    def extract_api_sequences(self) -> np.ndarray:
        """Extract API call sequences from import table."""
        api_features = np.zeros(256, dtype=np.float32)

        # License-related API categories
        api_categories = {
            "registry": ["RegOpenKey", "RegQueryValue", "RegSetValue", "RegCreateKey", "RegDeleteKey", "RegEnumKey"],
            "crypto": ["CryptHashData", "CryptGenKey", "CryptEncrypt", "CryptDecrypt", "CryptCreateHash", "CryptAcquireContext"],
            "network": ["InternetOpen", "InternetConnect", "HttpOpenRequest", "HttpSendRequest", "WSAStartup", "connect", "send", "recv"],
            "hardware": ["GetVolumeInformation", "GetSystemInfo", "GetComputerName", "GetAdaptersInfo", "DeviceIoControl"],
            "time": ["GetSystemTime", "GetTickCount", "QueryPerformanceCounter", "GetLocalTime", "timeGetTime"],
            "process": ["CreateProcess", "OpenProcess", "TerminateProcess", "GetCurrentProcess", "GetProcessId"],
            "file": ["CreateFile", "ReadFile", "WriteFile", "GetFileAttributes", "FindFirstFile"],
            "memory": ["VirtualAlloc", "VirtualProtect", "VirtualFree", "HeapAlloc", "GlobalAlloc"],
        }

        imports = self._extract_imports()

        # Create feature vector based on API presence
        feature_idx = 0
        for _category, apis in api_categories.items():
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
        imports = []

        if self.pe:
            try:
                if hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
                    for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                        for imp in entry.imports:
                            if imp.name:
                                imports.append(imp.name.decode("utf-8", errors="ignore"))
            except Exception as e:
                self.logger.debug(f"Import extraction error: {e}")
        elif self.lief_binary:
            try:
                for imported in self.lief_binary.imports:
                    for entry in imported.entries:
                        if entry.name:
                            imports.append(entry.name)
            except Exception as e:
                self.logger.debug(f"LIEF import extraction error: {e}")

        return imports

    def calculate_section_entropy(self) -> np.ndarray:
        """Calculate entropy for each section."""
        entropies = []

        if self.pe:
            for section in self.pe.sections:
                section_data = section.get_data()
                entropy = self._calculate_entropy(section_data)
                entropies.append(entropy)
        elif self.lief_binary:
            for section in self.lief_binary.sections:
                section_data = bytes(section.content)
                entropy = self._calculate_entropy(section_data)
                entropies.append(entropy)
        else:
            # Calculate entropy for whole binary in chunks
            chunk_size = len(self.data) // 8
            for i in range(8):
                chunk = self.data[i * chunk_size : (i + 1) * chunk_size]
                if chunk:
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

    def extract_string_features(self) -> np.ndarray:
        """Extract license-related string features with encoding detection."""
        features = np.zeros(128, dtype=np.float32)

        # Extract strings with different encoding
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
        for _category, keywords in patterns.items():
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

    def extract_all_features(self) -> dict[str, np.ndarray]:
        """Extract all features from binary."""
        features = {
            "opcode_histogram": self.extract_opcode_histogram(),
            "cfg_features": self._cfg_to_vector(self.build_control_flow_graph()),
            "api_sequences": self.extract_api_sequences(),
            "section_entropy": self.calculate_section_entropy(),
            "string_features": self.extract_string_features(),
        }

        return features

    def _cfg_to_vector(self, cfg_dict: dict[str, Any]) -> np.ndarray:
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


def extract_features_for_ml(binary_path: str) -> np.ndarray:
    """Extract features from binary for ML training (convenience function)."""
    extractor = BinaryFeatureExtractor(binary_path)
    features = extractor.extract_all_features()

    # Concatenate all features into single vector
    feature_vector = np.concatenate(
        [
            features["opcode_histogram"],
            features["cfg_features"],
            features["api_sequences"],
            features["section_entropy"],
            features["string_features"],
        ],
    )

    return feature_vector
