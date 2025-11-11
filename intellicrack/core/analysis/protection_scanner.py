"""Enhanced Protection Scanner with Dynamic Signature Extraction.

Advanced protection scanner that dynamically extracts and learns protection signatures
from analyzed binaries instead of relying on hardcoded patterns. Uses machine learning
and pattern evolution for adaptive detection of modern software protections.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
import sqlite3
import struct
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from threading import Lock, Thread
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np

from intellicrack.core.analysis.binary_analyzer import BinaryAnalyzer
from intellicrack.core.analysis.binary_pattern_detector import BinaryPatternDetector
from intellicrack.core.analysis.polymorphic_analyzer import (
    MutationType,
    PolymorphicAnalyzer,
)
from intellicrack.core.analysis.vmprotect_detector import VMProtectDetector
from intellicrack.core.analysis.yara_pattern_engine import YaraPatternEngine
from intellicrack.ml.pattern_evolution_tracker import PatternEvolutionTracker
from intellicrack.utils.logger import get_logger

logger = get_logger(__name__)

try:
    import pefile

    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False
    logger.debug("pefile not available - PE analysis limited")

try:
    from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False
    logger.debug("Capstone not available - disassembly limited")


class ProtectionCategory(Enum):
    """Categories of protection mechanisms."""

    PACKER = "packer"
    PROTECTOR = "protector"
    ANTI_DEBUG = "anti_debug"
    ANTI_VM = "anti_vm"
    ANTI_DUMP = "anti_dump"
    OBFUSCATION = "obfuscation"
    ENCRYPTION = "encryption"
    LICENSING = "licensing"
    DRM = "drm"
    CUSTOM = "custom"


@dataclass
class DynamicSignature:
    """Dynamically extracted protection signature."""

    category: ProtectionCategory
    confidence: float
    pattern_bytes: bytes
    mask: bytes
    context: str
    frequency: int = 1
    false_positives: int = 0
    last_seen: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def effectiveness_score(self) -> float:
        """Calculate signature effectiveness based on metrics."""
        if self.frequency + self.false_positives == 0:
            return 0.0
        accuracy = self.frequency / (self.frequency + self.false_positives)
        recency_factor = min(1.0, (time.time() - self.last_seen) / (30 * 24 * 3600))
        return accuracy * (1 - recency_factor * 0.2) * self.confidence


@dataclass
class ProtectionSignature:
    """Complete protection signature with all detection methods."""

    name: str
    category: ProtectionCategory
    static_patterns: List[DynamicSignature]
    behavioral_indicators: List[str]
    entropy_ranges: Tuple[float, float]
    section_characteristics: Dict[str, Any]
    import_signatures: Set[str]
    export_signatures: Set[str]
    string_indicators: Set[str]
    code_patterns: List[bytes]
    confidence_threshold: float = 0.7


class DynamicSignatureExtractor:
    """Extracts protection signatures dynamically from binaries."""

    def __init__(self, db_path: str = "protection_signatures.db") -> None:
        """Initialize the dynamic signature extractor."""
        self.db_path = db_path
        self.signatures: Dict[str, List[DynamicSignature]] = defaultdict(list)
        self.pattern_tracker = PatternEvolutionTracker()
        self.binary_detector = BinaryPatternDetector()
        self.mutation_engine = MutationEngine()
        self.lock = Lock()

        if CAPSTONE_AVAILABLE:
            self.cs_x86 = Cs(CS_ARCH_X86, CS_MODE_32)
            self.cs_x64 = Cs(CS_ARCH_X86, CS_MODE_64)
            self.cs_x86.detail = True
            self.cs_x64.detail = True

        self._initialize_database()
        self._load_signatures()

    def _initialize_database(self) -> None:
        """Initialize SQLite database for persistent signature storage."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS signatures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category TEXT NOT NULL,
                pattern_hex TEXT NOT NULL,
                mask_hex TEXT NOT NULL,
                confidence REAL NOT NULL,
                frequency INTEGER DEFAULT 1,
                false_positives INTEGER DEFAULT 0,
                last_seen REAL NOT NULL,
                context TEXT,
                metadata TEXT,
                UNIQUE(pattern_hex, mask_hex)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS protection_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                category TEXT NOT NULL,
                signatures TEXT NOT NULL,
                behavioral_indicators TEXT,
                entropy_min REAL,
                entropy_max REAL,
                imports TEXT,
                exports TEXT,
                strings TEXT,
                last_updated REAL NOT NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS mutation_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_pattern TEXT NOT NULL,
                mutated_pattern TEXT NOT NULL,
                mutation_type TEXT NOT NULL,
                success_rate REAL DEFAULT 0.0,
                timestamp REAL NOT NULL
            )
        """)

        conn.commit()
        conn.close()

    def extract_signatures(self, binary_path: str, known_protection: Optional[str] = None) -> List[DynamicSignature]:
        """Extract protection signatures dynamically from a binary."""
        signatures = []

        try:
            with open(binary_path, "rb") as f:
                data = f.read()

            # Extract various signature types
            signatures.extend(self._extract_entropy_signatures(data))
            signatures.extend(self._extract_section_signatures(data))
            signatures.extend(self._extract_import_signatures(data))
            signatures.extend(self._extract_code_signatures(data))
            signatures.extend(self._extract_string_signatures(data))
            signatures.extend(self._extract_behavioral_signatures(data))
            signatures.extend(self._extract_mutation_signatures(data))

            # Use pattern evolution to improve signatures
            evolved_signatures = self._evolve_signatures(signatures, data)
            signatures.extend(evolved_signatures)

            # Store signatures if protection is known
            if known_protection:
                self._store_signatures(signatures, known_protection)

            # Update pattern tracker
            for sig in signatures:
                self.pattern_tracker.track_pattern(sig.pattern_bytes.hex(), sig.category.value, {"confidence": sig.confidence})

        except Exception as e:
            logger.error(f"Failed to extract signatures: {e}")

        return signatures

    def _extract_entropy_signatures(self, data: bytes) -> List[DynamicSignature]:
        """Extract signatures based on entropy analysis."""
        signatures = []
        window_size = 4096

        for i in range(0, len(data) - window_size, window_size // 2):
            window = data[i : i + window_size]
            entropy = self._calculate_entropy(window)

            # High entropy indicates packing/encryption
            if entropy > 7.5:
                # Extract pattern around high entropy region
                pattern_start = max(0, i - 16)
                pattern_end = min(len(data), i + 32)
                pattern = data[pattern_start:pattern_end]

                # Create signature with wildcards for variable parts
                mask = self._generate_entropy_mask(pattern)

                sig = DynamicSignature(
                    category=ProtectionCategory.PACKER if entropy > 7.8 else ProtectionCategory.ENCRYPTION,
                    confidence=min(1.0, entropy / 8.0),
                    pattern_bytes=pattern,
                    mask=mask,
                    context=f"High entropy region: {entropy:.2f}",
                    metadata={"entropy": entropy, "offset": i},
                )
                signatures.append(sig)

        return signatures

    def _extract_section_signatures(self, data: bytes) -> List[DynamicSignature]:
        """Extract signatures from PE section characteristics."""
        signatures = []

        if not PEFILE_AVAILABLE or data[:2] != b"MZ":
            return signatures

        try:
            pe = pefile.PE(data=data)

            for section in pe.sections:
                section_name = section.Name.decode("utf-8", errors="ignore").rstrip("\x00")
                entropy = section.get_entropy()

                # Dynamic detection of packed sections
                if entropy > 6.5 or section_name.startswith("."):
                    # Extract section header pattern
                    pattern = bytes(section.__pack__()[:40])

                    # Create mask for variable fields
                    mask = bytearray(len(pattern))
                    mask[0:8] = b"\xff" * 8  # Name field
                    mask[12:16] = b"\x00" * 4  # VirtualAddress (relocatable)
                    mask[20:24] = b"\x00" * 4  # PointerToRawData (variable)

                    category = self._determine_section_category(section_name, entropy)

                    sig = DynamicSignature(
                        category=category,
                        confidence=self._calculate_section_confidence(entropy, section),
                        pattern_bytes=pattern,
                        mask=bytes(mask),
                        context=f"Section: {section_name}, Entropy: {entropy:.2f}",
                        metadata={
                            "section_name": section_name,
                            "entropy": entropy,
                            "characteristics": section.Characteristics,
                            "virtual_size": section.Misc_VirtualSize,
                            "raw_size": section.SizeOfRawData,
                        },
                    )
                    signatures.append(sig)

            pe.close()

        except Exception as e:
            logger.debug(f"PE section extraction failed: {e}")

        return signatures

    def _extract_import_signatures(self, data: bytes) -> List[DynamicSignature]:
        """Extract signatures from import table patterns."""
        signatures = []

        if not PEFILE_AVAILABLE or data[:2] != b"MZ":
            return signatures

        try:
            pe = pefile.PE(data=data)

            # Build import profile
            import_profile = defaultdict(list)
            suspicious_apis = set()

            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="ignore").lower()

                for imp in entry.imports:
                    if imp.name:
                        api_name = imp.name.decode("utf-8", errors="ignore")
                        import_profile[dll_name].append(api_name)

                        # Detect suspicious APIs dynamically
                        if self._is_suspicious_api(api_name):
                            suspicious_apis.add(api_name)

            # Create signature from import patterns
            if suspicious_apis:
                # Generate import table pattern
                import_pattern = self._generate_import_pattern(pe, suspicious_apis)

                if import_pattern:
                    sig = DynamicSignature(
                        category=self._categorize_imports(suspicious_apis),
                        confidence=min(1.0, len(suspicious_apis) * 0.1),
                        pattern_bytes=import_pattern,
                        mask=b"\xff" * len(import_pattern),
                        context=f"Suspicious imports: {', '.join(list(suspicious_apis)[:5])}",
                        metadata={"imports": list(suspicious_apis), "dll_count": len(import_profile)},
                    )
                    signatures.append(sig)

            pe.close()

        except Exception as e:
            logger.debug(f"Import extraction failed: {e}")

        return signatures

    def _extract_code_signatures(self, data: bytes) -> List[DynamicSignature]:
        """Extract signatures from code pattern analysis."""
        signatures = []

        if not CAPSTONE_AVAILABLE:
            return signatures

        # Scan for code patterns using binary pattern detector
        matches = self.binary_detector.scan_binary(data, ["protection", "anti_debug", "obfuscation"])

        for match in matches:
            # Convert binary pattern match to dynamic signature
            sig = DynamicSignature(
                category=self._map_pattern_category(match.pattern.category),
                confidence=match.confidence,
                pattern_bytes=match.matched_bytes,
                mask=match.pattern.mask,
                context=match.pattern.description,
                metadata={"offset": match.offset, "xrefs": match.xrefs, "pattern_name": match.pattern.name},
            )
            signatures.append(sig)

        # Extract custom code patterns through disassembly
        code_patterns = self._analyze_code_sequences(data)
        signatures.extend(code_patterns)

        return signatures

    def _extract_string_signatures(self, data: bytes) -> List[DynamicSignature]:
        """Extract signatures from string analysis."""
        signatures = []

        # Extract ASCII and Unicode strings
        ascii_strings = self._extract_strings(data, encoding="ascii")
        unicode_strings = self._extract_strings(data, encoding="utf-16le")

        all_strings = ascii_strings + unicode_strings

        # Analyze strings for protection indicators
        protection_strings = self._analyze_protection_strings(all_strings)

        for prot_str, category, confidence in protection_strings:
            # Find string position in binary
            str_bytes = prot_str.encode("utf-8", errors="ignore")
            offset = data.find(str_bytes)

            if offset != -1:
                # Create pattern around string
                pattern_start = max(0, offset - 8)
                pattern_end = min(len(data), offset + len(str_bytes) + 8)
                pattern = data[pattern_start:pattern_end]

                # Create mask allowing string variation
                mask = bytearray(len(pattern))
                mask[: offset - pattern_start] = b"\xff" * (offset - pattern_start)
                mask[offset - pattern_start + len(str_bytes) :] = b"\xff" * (pattern_end - offset - len(str_bytes))

                sig = DynamicSignature(
                    category=category,
                    confidence=confidence,
                    pattern_bytes=pattern,
                    mask=bytes(mask),
                    context=f"String indicator: {prot_str[:50]}",
                    metadata={"string": prot_str, "offset": offset, "encoding": "ascii" if prot_str in ascii_strings else "unicode"},
                )
                signatures.append(sig)

        return signatures

    def _extract_behavioral_signatures(self, data: bytes) -> List[DynamicSignature]:
        """Extract behavioral signatures through advanced analysis."""
        signatures = []

        # Analyze control flow patterns
        cf_patterns = self._analyze_control_flow(data)

        # Analyze API call sequences
        api_sequences = self._analyze_api_sequences(data)

        # Analyze timing checks
        timing_patterns = self._analyze_timing_patterns(data)

        # Combine behavioral indicators
        behavioral_patterns = cf_patterns + api_sequences + timing_patterns

        for pattern, category, confidence, context in behavioral_patterns:
            sig = DynamicSignature(
                category=category,
                confidence=confidence,
                pattern_bytes=pattern,
                mask=self._generate_behavioral_mask(pattern),
                context=context,
                metadata={"type": "behavioral"},
            )
            signatures.append(sig)

        return signatures

    def _extract_mutation_signatures(self, data: bytes) -> List[DynamicSignature]:
        """Extract signatures for polymorphic/metamorphic code."""
        signatures = []

        # Detect self-modifying code patterns
        smc_patterns = self._detect_self_modifying_code(data)

        # Detect polymorphic engines
        poly_patterns = self._detect_polymorphic_engines(data)

        # Detect metamorphic transformations
        meta_patterns = self._detect_metamorphic_code(data)

        all_mutation_patterns = smc_patterns + poly_patterns + meta_patterns

        for pattern, confidence, mutation_type in all_mutation_patterns:
            sig = DynamicSignature(
                category=ProtectionCategory.OBFUSCATION,
                confidence=confidence,
                pattern_bytes=pattern,
                mask=self._generate_mutation_mask(pattern),
                context=f"Mutation pattern: {mutation_type}",
                metadata={"mutation_type": mutation_type, "complexity": self._assess_mutation_complexity(pattern)},
            )
            signatures.append(sig)

        return signatures

    def _evolve_signatures(self, signatures: List[DynamicSignature], data: bytes) -> List[DynamicSignature]:
        """Use pattern evolution to generate improved signatures."""
        evolved = []

        for sig in signatures:
            # Track pattern for evolution
            pattern_id = self.pattern_tracker.track_pattern(sig.pattern_bytes.hex(), sig.category.value, {"confidence": sig.confidence})

            # Get mutations
            mutations = self.pattern_tracker.get_pattern_mutations(pattern_id)

            for mutation in mutations:
                # Test mutation effectiveness
                if self._test_mutation_effectiveness(mutation, data):
                    evolved_sig = DynamicSignature(
                        category=sig.category,
                        confidence=sig.confidence * 0.9,
                        pattern_bytes=bytes.fromhex(mutation),
                        mask=self._evolve_mask(sig.mask, mutation),
                        context=f"Evolved from: {sig.context}",
                        metadata={"parent_pattern": sig.pattern_bytes.hex(), "evolution_generation": 1},
                    )
                    evolved.append(evolved_sig)

        return evolved

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0

        byte_counts = defaultdict(int)
        for byte in data:
            byte_counts[byte] += 1

        entropy = 0.0
        data_len = len(data)

        for count in byte_counts.values():
            if count > 0:
                probability = count / data_len
                entropy -= probability * np.log2(probability)

        return entropy

    def _generate_entropy_mask(self, pattern: bytes) -> bytes:
        """Generate mask for entropy-based pattern."""
        mask = bytearray(len(pattern))

        # Keep first and last 8 bytes exact
        if len(pattern) > 16:
            mask[:8] = b"\xff" * 8
            mask[-8:] = b"\xff" * 8
        else:
            mask[:] = b"\xff" * len(pattern)

        return bytes(mask)

    def _determine_section_category(self, name: str, entropy: float) -> ProtectionCategory:
        """Determine protection category from section characteristics."""
        name_lower = name.lower()

        if "pack" in name_lower or entropy > 7.5:
            return ProtectionCategory.PACKER
        elif "vmp" in name_lower or "themida" in name_lower:
            return ProtectionCategory.PROTECTOR
        elif "obf" in name_lower or "mut" in name_lower:
            return ProtectionCategory.OBFUSCATION
        elif entropy > 7.0:
            return ProtectionCategory.ENCRYPTION
        else:
            return ProtectionCategory.CUSTOM

    def _calculate_section_confidence(self, entropy: float, section: Any) -> float:
        """Calculate confidence score for section-based signature."""
        confidence = min(1.0, entropy / 8.0)

        # Adjust based on section characteristics
        if section.Characteristics & 0x20000000:  # CODE
            confidence *= 1.1
        if section.Characteristics & 0x80000000:  # WRITE
            confidence *= 1.15

        return min(1.0, confidence)

    def _is_suspicious_api(self, api_name: str) -> bool:
        """Dynamically determine if an API is suspicious."""
        suspicious_patterns = [
            "debug",
            "protect",
            "crypt",
            "obfuscat",
            "pack",
            "virtual",
            "query",
            "enum",
            "hook",
            "inject",
            "hide",
            "stealth",
            "bypass",
            "patch",
            "modify",
        ]

        api_lower = api_name.lower()
        return any(pattern in api_lower for pattern in suspicious_patterns)

    def _categorize_imports(self, apis: Set[str]) -> ProtectionCategory:
        """Categorize protection based on imported APIs."""
        api_str = " ".join(apis).lower()

        if "debug" in api_str:
            return ProtectionCategory.ANTI_DEBUG
        elif "virtual" in api_str or "vm" in api_str:
            return ProtectionCategory.ANTI_VM
        elif "crypt" in api_str:
            return ProtectionCategory.ENCRYPTION
        elif "protect" in api_str:
            return ProtectionCategory.PROTECTOR
        else:
            return ProtectionCategory.CUSTOM

    def _generate_import_pattern(self, pe: Any, apis: Set[str]) -> Optional[bytes]:
        """Generate pattern from import table structure."""
        try:
            # Extract import directory structure
            import_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[1]

            if import_dir.VirtualAddress == 0:
                return None

            # Create pattern from import descriptor
            pattern = struct.pack(
                "<IIIII",
                0,  # OriginalFirstThunk (variable)
                0,  # TimeDateStamp
                0,  # ForwarderChain
                0,  # Name RVA (variable)
                0,
            )  # FirstThunk (variable)

            return pattern

        except Exception:
            return None

    def _map_pattern_category(self, category: str) -> ProtectionCategory:
        """Map binary pattern category to protection category."""
        mapping = {
            "protection": ProtectionCategory.PROTECTOR,
            "anti_debug": ProtectionCategory.ANTI_DEBUG,
            "anti_vm": ProtectionCategory.ANTI_VM,
            "obfuscation": ProtectionCategory.OBFUSCATION,
            "packer": ProtectionCategory.PACKER,
            "licensing": ProtectionCategory.LICENSING,
        }
        return mapping.get(category, ProtectionCategory.CUSTOM)

    def _extract_strings(self, data: bytes, encoding: str = "ascii", min_length: int = 4) -> List[str]:
        """Extract readable strings from binary data."""
        strings = []

        if encoding == "ascii":
            pattern = b"[\x20-\x7e]{%d,}" % min_length
            import re

            for match in re.finditer(pattern, data):
                try:
                    strings.append(match.group().decode("ascii"))
                except Exception as e:
                    logger.debug(f"String decoding failed: {e}")

        elif encoding == "utf-16le":
            # Simple Unicode string extraction
            i = 0
            while i < len(data) - 1:
                s = []
                while i < len(data) - 1:
                    c = data[i : i + 2]
                    if c[1] == 0 and 0x20 <= c[0] <= 0x7E:
                        s.append(chr(c[0]))
                        i += 2
                    else:
                        break

                if len(s) >= min_length:
                    strings.append("".join(s))
                i += 2

        return strings

    def _analyze_protection_strings(self, strings: List[str]) -> List[Tuple[str, ProtectionCategory, float]]:
        """Analyze strings for protection indicators."""
        indicators = []

        protection_keywords = {
            ProtectionCategory.PROTECTOR: ["vmprotect", "themida", "enigma", "obsidium", "armadillo"],
            ProtectionCategory.PACKER: ["upx", "aspack", "pecompact", "petite", "mpress"],
            ProtectionCategory.ANTI_DEBUG: ["debugger", "isdebuggerpresent", "checkremotedebugger"],
            ProtectionCategory.ANTI_VM: ["vmware", "virtualbox", "sandbox", "wine", "qemu"],
            ProtectionCategory.LICENSING: ["license", "registration", "activation", "serial", "keygen"],
            ProtectionCategory.DRM: ["denuvo", "steam", "securom", "safedisc", "starforce"],
        }

        for string in strings:
            string_lower = string.lower()

            for category, keywords in protection_keywords.items():
                for keyword in keywords:
                    if keyword in string_lower:
                        confidence = 0.9 if keyword == string_lower else 0.7
                        indicators.append((string, category, confidence))
                        break

        return indicators

    def _analyze_control_flow(self, data: bytes) -> List[Tuple[bytes, ProtectionCategory, float, str]]:
        """Analyze control flow for protection patterns."""
        patterns = []

        if not CAPSTONE_AVAILABLE:
            return patterns

        # Simplified control flow analysis
        jmp_chains = self._find_jump_chains(data)
        self._analyze_call_depth(data)

        for chain in jmp_chains:
            if len(chain) > 5:  # Suspicious jump chain
                pattern = self._extract_pattern_from_chain(data, chain)
                patterns.append((pattern, ProtectionCategory.OBFUSCATION, min(1.0, len(chain) * 0.15), f"Jump chain length: {len(chain)}"))

        return patterns

    def _find_jump_chains(self, data: bytes) -> List[List[int]]:
        """Find chains of jumps in code."""
        chains = []

        if not CAPSTONE_AVAILABLE:
            return chains

        cs = self.cs_x86

        # Simple jump chain detection
        for i in range(0, len(data) - 100, 16):
            chain = []
            offset = i

            for _ in range(10):  # Max chain length
                try:
                    insns = list(cs.disasm(data[offset : offset + 15], offset))
                    if insns and insns[0].mnemonic.startswith("j"):
                        chain.append(offset)
                        # Simplified - just move forward
                        offset += insns[0].size
                    else:
                        break
                except Exception:
                    break

            if len(chain) > 3:
                chains.append(chain)

        return chains

    def _analyze_call_depth(self, data: bytes) -> List[int]:
        """Analyze call instruction depth by tracking nested call chains."""
        depths = []

        if not CAPSTONE_AVAILABLE:
            return depths

        cs = self.cs_x86
        call_stack = []
        visited_addresses = set()
        max_depth = 0

        # Scan for CALL instructions and track depth
        for offset in range(0, len(data) - 32, 1):
            try:
                # Disassemble instruction at current offset
                code = data[offset : offset + 15]
                insns = list(cs.disasm(code, offset))

                if not insns:
                    continue

                insn = insns[0]

                # Track CALL instructions
                if insn.mnemonic == "call":
                    # Push call onto stack
                    call_stack.append(insn.address)
                    current_depth = len(call_stack)

                    max_depth = max(max_depth, current_depth)

                    depths.append(current_depth)

                    # Analyze call target if it's a direct call
                    if insn.operands:
                        target_op = insn.operands[0]
                        if target_op.type == 1:  # Immediate operand
                            target_addr = target_op.imm

                            # Avoid infinite recursion
                            if target_addr not in visited_addresses and 0 <= target_addr < len(data):
                                visited_addresses.add(target_addr)

                                # Recursively analyze call target
                                target_depths = self._analyze_call_target(data, target_addr, current_depth, visited_addresses)
                                depths.extend(target_depths)

                elif insn.mnemonic == "ret" and call_stack:
                    # Pop from call stack on return
                    call_stack.pop()

                # Track indirect calls through registers
                elif (insn.mnemonic == "call" and insn.op_str.startswith("e")) or insn.op_str.startswith("r"):
                    depths.append(len(call_stack) + 1)

            except Exception as e:
                # Log the exception with details for debugging
                import logging

                logging.warning(f"Error processing instruction in call depth analysis: {e}")
                continue

        # Return unique depth levels found
        return sorted(set(depths)) if depths else []

    def _analyze_call_target(self, data: bytes, target_addr: int, current_depth: int, visited: Set[int]) -> List[int]:
        """Recursively analyze call targets to find maximum call depth."""
        depths = []

        if not CAPSTONE_AVAILABLE or target_addr >= len(data):
            return depths

        cs = self.cs_x86
        max_scan = min(target_addr + 1000, len(data))

        # Scan target function for more calls
        for offset in range(target_addr, max_scan, 1):
            try:
                code = data[offset : offset + 15]
                insns = list(cs.disasm(code, offset))

                if not insns:
                    continue

                insn = insns[0]

                # Found another call - increase depth
                if insn.mnemonic == "call":
                    depths.append(current_depth + 1)

                    # Check for recursive patterns
                    if insn.operands and insn.operands[0].type == 1:
                        nested_target = insn.operands[0].imm

                        # Detect recursion
                        if nested_target == target_addr:
                            depths.append(current_depth + 10)  # Recursive call indicator

                elif insn.mnemonic == "ret":
                    # End of function
                    break

            except Exception as e:
                # Log the exception with details for debugging
                import logging

                logging.warning(f"Error processing instruction in call target analysis: {e}")
                continue

        return depths

    def _extract_pattern_from_chain(self, data: bytes, chain: List[int]) -> bytes:
        """Extract pattern from jump chain."""
        if not chain:
            return b""

        start = chain[0]
        end = min(chain[-1] + 16, len(data))

        return data[start:end]

    def _analyze_api_sequences(self, data: bytes) -> List[Tuple[bytes, ProtectionCategory, float, str]]:
        """Analyze API call sequences."""
        # Simplified - would need full IAT analysis
        return []

    def _analyze_timing_patterns(self, data: bytes) -> List[Tuple[bytes, ProtectionCategory, float, str]]:
        """Analyze timing check patterns."""
        patterns = []

        # RDTSC instruction pattern
        rdtsc_pattern = b"\x0f\x31"
        offset = 0

        while True:
            offset = data.find(rdtsc_pattern, offset)
            if offset == -1:
                break

            # Extract context around RDTSC
            start = max(0, offset - 16)
            end = min(len(data), offset + 32)
            pattern = data[start:end]

            patterns.append((pattern, ProtectionCategory.ANTI_DEBUG, 0.85, "Timing check (RDTSC)"))

            offset += 2

        return patterns

    def _generate_behavioral_mask(self, pattern: bytes) -> bytes:
        """Generate mask for behavioral pattern."""
        # Allow some variation in behavioral patterns
        mask = bytearray(len(pattern))

        for i in range(len(pattern)):
            # Keep opcodes, allow operand variation
            if i % 2 == 0:
                mask[i] = 0xFF
            else:
                mask[i] = 0x00

        return bytes(mask)

    def _detect_self_modifying_code(self, data: bytes) -> List[Tuple[bytes, float, str]]:
        """Detect self-modifying code patterns."""
        patterns = []

        # Look for code that writes to code sections
        write_patterns = [(b"\x89", 0.6, "MOV to memory"), (b"\xc7", 0.7, "MOV immediate to memory"), (b"\x88", 0.6, "MOV byte to memory")]

        for pattern, conf, desc in write_patterns:
            offset = 0
            while True:
                offset = data.find(pattern, offset)
                if offset == -1:
                    break

                # Extract context
                start = max(0, offset - 8)
                end = min(len(data), offset + 16)

                patterns.append((data[start:end], conf, f"SMC: {desc}"))
                offset += 1

        return patterns

    def _detect_polymorphic_engines(self, data: bytes) -> List[Tuple[bytes, float, str]]:
        """Detect polymorphic engine signatures using advanced analysis."""
        patterns = []

        try:
            analyzer = PolymorphicAnalyzer(arch="x86", bits=self._guess_bitness(data))

            analysis = analyzer.analyze_polymorphic_code(data, base_address=0, max_instructions=500)

            if analysis.engine_type.value != "unknown":
                semantic_sig = analysis.invariant_features.get("semantic_sequence", ())
                if semantic_sig:
                    sig_bytes = str(semantic_sig).encode()[:64]
                    confidence = 0.85 if analysis.mutation_complexity > 0.5 else 0.70
                    patterns.append((sig_bytes, confidence, f"Polymorphic engine: {analysis.engine_type.value}"))

            if analysis.decryption_routine:
                decryption_block = analysis.decryption_routine
                routine_bytes = data[decryption_block.start_address:decryption_block.end_address][:64]
                patterns.append((routine_bytes, 0.90, "Polymorphic decryption routine"))

            for mutation_type in analysis.mutation_types:
                mutation_desc = mutation_type.value.replace("_", " ").title()
                patterns.append((data[:32], 0.65, f"Mutation: {mutation_desc}"))

            for behavior in analysis.behavior_patterns:
                behavior_bytes = behavior.behavioral_hash.encode()[:64]
                patterns.append((behavior_bytes, behavior.confidence, f"Behavior pattern: {behavior.pattern_id}"))

        except Exception as e:
            logger.debug(f"Polymorphic analysis error: {e}")

            xor_loop = b"\x31"
            offset = 0
            while True:
                offset = data.find(xor_loop, offset)
                if offset == -1:
                    break
                context = data[max(0, offset - 32) : min(len(data), offset + 32)]
                if b"\xe2" in context or b"\x75" in context:
                    patterns.append((context, 0.60, "Possible polymorphic decryption loop"))
                offset += 1

        return patterns

    def _detect_metamorphic_code(self, data: bytes) -> List[Tuple[bytes, float, str]]:
        """Detect metamorphic code transformations using semantic analysis."""
        patterns = []

        try:
            analyzer = PolymorphicAnalyzer(arch="x86", bits=self._guess_bitness(data))

            analysis = analyzer.analyze_polymorphic_code(data, base_address=0, max_instructions=500)

            metamorphic_mutations = {
                MutationType.INSTRUCTION_SUBSTITUTION,
                MutationType.INSTRUCTION_EXPANSION,
                MutationType.CODE_REORDERING,
                MutationType.SEMANTIC_NOP,
            }

            detected_metamorphic = [m for m in analysis.mutation_types if m in metamorphic_mutations]

            if len(detected_metamorphic) >= 2:
                semantic_sig = analyzer.extract_semantic_signature(data, base_address=0)
                if semantic_sig:
                    sig_bytes = semantic_sig.encode()[:64]
                    confidence = min(0.95, 0.70 + (len(detected_metamorphic) * 0.08))
                    patterns.append((sig_bytes, confidence, f"Metamorphic code: {len(detected_metamorphic)} techniques"))

            for mutation in detected_metamorphic:
                mutation_name = mutation.value.replace("_", " ").title()
                patterns.append((data[:32], 0.70, f"Metamorphic: {mutation_name}"))

            if analysis.invariant_features:
                invariants = analysis.invariant_features
                if invariants.get("control_flow_branches", 0) > 5:
                    patterns.append((data[:48], 0.75, "Metamorphic: Complex control flow"))

        except Exception as e:
            logger.debug(f"Metamorphic analysis error: {e}")

        return patterns

    def _guess_bitness(self, data: bytes) -> int:
        """Guess binary bitness from code patterns."""
        if len(data) < 64:
            return 32

        rex_prefix_count = sum(1 for b in data[:64] if 0x40 <= b <= 0x4F)
        if rex_prefix_count > 2:
            return 64

        reg64_patterns = [b"\x48\x8b", b"\x48\x89", b"\x48\x83", b"\x48\x8d"]
        for pattern in reg64_patterns:
            if pattern in data[:128]:
                return 64

        return 32

    def _assess_mutation_complexity(self, pattern: bytes) -> str:
        """Assess complexity of mutation pattern."""
        unique_bytes = len(set(pattern))

        if unique_bytes < len(pattern) * 0.3:
            return "low"
        elif unique_bytes < len(pattern) * 0.6:
            return "medium"
        else:
            return "high"

    def _generate_mutation_mask(self, pattern: bytes) -> bytes:
        """Generate mask for mutation pattern."""
        # Allow high variation for mutations
        mask = bytearray(len(pattern))

        # Keep structure bytes, allow content variation
        for i in range(0, len(pattern), 4):
            mask[i] = 0xFF

        return bytes(mask)

    def _test_mutation_effectiveness(self, mutation: str, data: bytes) -> bool:
        """Test if a mutation is effective."""
        try:
            pattern = bytes.fromhex(mutation)
            return pattern in data
        except Exception:
            return False

    def _evolve_mask(self, original_mask: bytes, mutation: str) -> bytes:
        """Evolve mask for mutated pattern."""
        try:
            mutation_bytes = bytes.fromhex(mutation)

            if len(mutation_bytes) != len(original_mask):
                # Adjust mask length
                if len(mutation_bytes) > len(original_mask):
                    return original_mask + b"\x00" * (len(mutation_bytes) - len(original_mask))
                else:
                    return original_mask[: len(mutation_bytes)]

            return original_mask

        except Exception:
            return original_mask

    def _store_signatures(self, signatures: List[DynamicSignature], protection_name: str) -> None:
        """Store signatures in database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        for sig in signatures:
            try:
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO signatures
                    (category, pattern_hex, mask_hex, confidence, frequency,
                     false_positives, last_seen, context, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        sig.category.value,
                        sig.pattern_bytes.hex(),
                        sig.mask.hex(),
                        sig.confidence,
                        sig.frequency,
                        sig.false_positives,
                        sig.last_seen,
                        sig.context,
                        json.dumps(sig.metadata),
                    ),
                )
            except sqlite3.IntegrityError:
                # Update existing signature
                cursor.execute(
                    """
                    UPDATE signatures
                    SET frequency = frequency + 1,
                        last_seen = ?,
                        confidence = (confidence + ?) / 2
                    WHERE pattern_hex = ? AND mask_hex = ?
                """,
                    (sig.last_seen, sig.confidence, sig.pattern_bytes.hex(), sig.mask.hex()),
                )

        conn.commit()
        conn.close()

    def _load_signatures(self) -> None:
        """Load signatures from database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM signatures")

        for row in cursor.fetchall():
            sig = DynamicSignature(
                category=ProtectionCategory(row[1]),
                confidence=row[4],
                pattern_bytes=bytes.fromhex(row[2]),
                mask=bytes.fromhex(row[3]),
                context=row[8] or "",
                frequency=row[5],
                false_positives=row[6],
                last_seen=row[7],
                metadata=json.loads(row[9]) if row[9] else {},
            )

            self.signatures[sig.category.value].append(sig)

        conn.close()


class MutationEngine:
    """Engine for generating pattern mutations."""

    def __init__(self) -> None:
        """Initialize the PatternMutator with available mutation strategies."""
        self.mutation_strategies = [
            self._byte_substitution,
            self._instruction_replacement,
            self._nop_insertion,
            self._register_swapping,
            self._operand_modification,
        ]

    def generate_mutations(self, pattern: bytes, count: int = 5) -> List[bytes]:
        """Generate mutations of a pattern."""
        mutations = []

        for strategy in self.mutation_strategies[:count]:
            mutated = strategy(pattern)
            if mutated and mutated != pattern:
                mutations.append(mutated)

        return mutations

    def _byte_substitution(self, pattern: bytes) -> bytes:
        """Substitute functionally equivalent bytes."""
        mutated = bytearray(pattern)

        # Example: XOR -> ADD with zero
        for i in range(len(mutated) - 1):
            if mutated[i] == 0x31:  # XOR
                mutated[i] = 0x01  # ADD

        return bytes(mutated)

    def _instruction_replacement(self, pattern: bytes) -> bytes:
        """Replace instructions with equivalents."""
        mutated = bytearray(pattern)

        # Example: JZ -> JE (same opcode actually)
        replacements = {
            0x74: 0x74,  # JZ/JE
            0x75: 0x75,  # JNZ/JNE
            0x90: 0x90,  # NOP
        }

        for i, byte in enumerate(mutated):
            if byte in replacements:
                mutated[i] = replacements[byte]

        return bytes(mutated)

    def _nop_insertion(self, pattern: bytes) -> bytes:
        """Insert NOPs at safe positions."""
        mutated = bytearray(pattern)

        # Insert NOP after unconditional jumps
        result = bytearray()
        i = 0

        while i < len(mutated):
            result.append(mutated[i])

            # After unconditional jump
            if mutated[i] in [0xEB, 0xE9]:  # JMP short/near
                result.append(0x90)  # NOP

            i += 1

        return bytes(result)

    def _register_swapping(self, pattern: bytes) -> bytes:
        """Swap equivalent registers."""
        # Simplified - would need proper instruction decoding
        return pattern

    def _operand_modification(self, pattern: bytes) -> bytes:
        """Modify operands while preserving function."""
        # Simplified - would need proper instruction decoding
        return pattern


class EnhancedProtectionScanner:
    """Enhanced protection scanner with dynamic signature extraction."""

    def __init__(self) -> None:
        """Initialize the EnhancedProtectionScanner with various analysis components."""
        self.signature_extractor = DynamicSignatureExtractor()
        self.binary_analyzer = BinaryAnalyzer()
        self.yara_engine = YaraPatternEngine()
        self.binary_detector = BinaryPatternDetector()
        self.vmprotect_detector = VMProtectDetector()

        # Cache for performance
        self.cache = {}
        self.cache_lock = Lock()

    def scan(self, binary_path: str, deep_scan: bool = True) -> Dict[str, Any]:
        """Perform comprehensive protection scan with dynamic signatures."""
        # Check cache
        cache_key = f"{binary_path}:{deep_scan}"
        with self.cache_lock:
            if cache_key in self.cache:
                cached = self.cache[cache_key]
                if time.time() - cached["timestamp"] < 3600:  # 1 hour cache
                    return cached["results"]

        results = {
            "file_path": binary_path,
            "timestamp": time.time(),
            "protections": [],
            "packers": [],
            "anti_debug": [],
            "anti_vm": [],
            "obfuscation": [],
            "licensing": [],
            "custom": [],
            "confidence_scores": {},
            "bypass_recommendations": [],
            "technical_details": {},
        }

        try:
            # Extract dynamic signatures
            dynamic_sigs = self.signature_extractor.extract_signatures(binary_path)

            # Categorize and score signatures
            for sig in dynamic_sigs:
                category_key = sig.category.value + "s" if sig.category.value != "custom" else "custom"

                if category_key in results:
                    results[category_key].append(
                        {
                            "pattern": sig.pattern_bytes.hex()[:32] + "...",
                            "confidence": sig.confidence,
                            "context": sig.context,
                            "effectiveness": sig.effectiveness_score,
                        },
                    )

                # Update confidence scores
                if sig.category.value not in results["confidence_scores"]:
                    results["confidence_scores"][sig.category.value] = 0.0

                results["confidence_scores"][sig.category.value] = max(results["confidence_scores"][sig.category.value], sig.confidence)

            # Use binary pattern detector for additional detection
            with open(binary_path, "rb") as f:
                binary_data = f.read()

            binary_patterns = self.binary_detector.scan_binary(binary_data)

            for match in binary_patterns:
                category = match.pattern.category

                if category not in results["technical_details"]:
                    results["technical_details"][category] = []

                results["technical_details"][category].append(
                    {
                        "name": match.pattern.name,
                        "offset": f"0x{match.offset:08x}",
                        "confidence": match.confidence,
                        "xrefs": len(match.xrefs),
                        "description": match.pattern.description,
                    },
                )

            # Generate bypass recommendations
            results["bypass_recommendations"] = self._generate_bypass_recommendations(
                results["confidence_scores"], results["technical_details"],
            )

            # Cache results
            with self.cache_lock:
                self.cache[cache_key] = {"timestamp": time.time(), "results": results}

        except Exception as e:
            logger.error(f"Protection scan failed: {e}")
            results["error"] = str(e)

        return results

    def _generate_bypass_recommendations(
        self, confidence_scores: Dict[str, float], technical_details: Dict[str, List],
    ) -> List[Dict[str, Any]]:
        """Generate specific bypass recommendations based on detections."""
        recommendations = []

        # High confidence protection detected
        if confidence_scores.get("protector", 0) > 0.8:
            recommendations.append(
                {
                    "category": "Protector Bypass",
                    "method": "VM analysis and devirtualization",
                    "tools": ["IDA Pro", "x64dbg", "VMProtect Devirtualizer"],
                    "difficulty": "extreme",
                    "time_estimate": "2-4 weeks",
                    "success_rate": "60-70%",
                },
            )

        # High confidence packer detected
        if confidence_scores.get("packer", 0) > 0.8:
            recommendations.append(
                {
                    "category": "Unpacking",
                    "method": "OEP detection and IAT reconstruction",
                    "tools": ["Scylla", "ImpREC", "x64dbg"],
                    "difficulty": "medium",
                    "time_estimate": "2-6 hours",
                    "success_rate": "85-95%",
                },
            )

        # Anti-debug detected
        if confidence_scores.get("anti_debug", 0) > 0.7:
            recommendations.append(
                {
                    "category": "Anti-Debug Bypass",
                    "method": "API hooking and flag manipulation",
                    "tools": ["ScyllaHide", "TitanHide", "SharpOD"],
                    "difficulty": "medium",
                    "time_estimate": "1-3 hours",
                    "success_rate": "90-95%",
                },
            )

        # Licensing detected
        if confidence_scores.get("licensing", 0) > 0.7:
            recommendations.append(
                {
                    "category": "License Bypass",
                    "method": "Patch validation checks or emulate license",
                    "tools": ["Custom patcher", "License emulator"],
                    "difficulty": "high",
                    "time_estimate": "1-2 weeks",
                    "success_rate": "70-80%",
                },
            )

        return recommendations


def run_scan_thread(main_app, binary_path) -> None:
    """Enhanced scanning logic with dynamic signature extraction."""
    try:
        if hasattr(main_app, "update_output"):
            main_app.update_output.emit("[Protection Scanner] Starting enhanced scan with dynamic signatures...")
        elif hasattr(main_app, "update_scan_status"):
            main_app.update_scan_status("Starting enhanced scan with dynamic signatures...")

        scanner = EnhancedProtectionScanner()
        results = scanner.scan(binary_path, deep_scan=True)

        # Report results
        if hasattr(main_app, "update_protection_results"):
            main_app.update_protection_results(results)

        if hasattr(main_app, "update_analysis_results"):
            main_app.update_analysis_results.emit(json.dumps(results, indent=2))

        # Report confidence scores
        if results.get("confidence_scores"):
            summary = "Detection Confidence:\n"
            for category, score in results["confidence_scores"].items():
                summary += f"  {category}: {score:.1%}\n"

            if hasattr(main_app, "update_output"):
                main_app.update_output.emit(f"[Protection Scanner] {summary}")

        # Report recommendations
        if results.get("bypass_recommendations"):
            if hasattr(main_app, "update_output"):
                main_app.update_output.emit(
                    f"[Protection Scanner] Generated {len(results['bypass_recommendations'])} bypass recommendations",
                )

    except Exception as e:
        error_msg = f"[Protection Scanner] Critical error: {e}"

        if hasattr(main_app, "update_output"):
            main_app.update_output.emit(error_msg)
        elif hasattr(main_app, "error_messages"):
            main_app.error_messages.append(error_msg)

    finally:
        if hasattr(main_app, "analysis_completed"):
            main_app.analysis_completed.emit("Enhanced Protection Scan")
        elif hasattr(main_app, "update_scan_status"):
            main_app.update_scan_status("Scan complete")


def run_enhanced_protection_scan(main_app) -> None:
    """Entry point for enhanced protection scanning."""
    if not hasattr(main_app, "current_binary") or not main_app.current_binary:
        if hasattr(main_app, "update_output"):
            main_app.update_output.emit("[Protection Scanner] Error: No binary loaded.")
        return

    binary_path = main_app.current_binary if hasattr(main_app, "current_binary") else main_app.loaded_binary_path

    thread = Thread(target=run_scan_thread, args=(main_app, binary_path), daemon=True)
    thread.start()

    if hasattr(main_app, "update_output"):
        main_app.update_output.emit("[Protection Scanner] Protection scan task submitted.")
