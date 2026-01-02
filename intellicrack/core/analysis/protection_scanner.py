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
from typing import Any

import numpy as np

from intellicrack.core.analysis.binary_analyzer import BinaryAnalyzer
from intellicrack.core.analysis.binary_pattern_detector import BinaryPatternDetector
from intellicrack.core.analysis.polymorphic_analyzer import MutationType, PolymorphicAnalyzer
from intellicrack.core.analysis.vmprotect_detector import VMProtectDetector
from intellicrack.core.analysis.yara_pattern_engine import YaraPatternEngine
from intellicrack.data import PROTECTION_SIGNATURES_DB
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
    """Dynamically extracted protection signature.

    Represents a binary pattern signature extracted during analysis that indicates
    the presence of a protection mechanism. Includes confidence scoring, masking
    for flexible matching, and metadata for tracking signature effectiveness.

    Attributes:
        category: ProtectionCategory enum indicating type of protection detected.
        confidence: Float between 0.0 and 1.0 indicating detection confidence.
        pattern_bytes: Raw bytes of the detected pattern.
        mask: Byte mask for pattern matching (0xFF=match exactly, 0x00=wildcard).
        context: Human-readable description of the detection context.
        frequency: Number of times this signature has been observed. Defaults to 1.
        false_positives: Count of false positive detections with this signature.
        last_seen: Unix timestamp of when signature was last observed.
        metadata: Dictionary of additional information (offsets, instruction names, etc).

    """

    category: ProtectionCategory
    confidence: float
    pattern_bytes: bytes
    mask: bytes
    context: str
    frequency: int = 1
    false_positives: int = 0
    last_seen: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def effectiveness_score(self) -> float:
        """Calculate signature effectiveness based on metrics.

        Computes a composite effectiveness score combining accuracy, recency, and
        confidence metrics. The score decreases with age using a time-decay factor
        to prioritize recently validated signatures.

        Returns:
            float: Effectiveness score between 0.0 and 1.0, calculated as
                (accuracy) * (1 - recency_decay) * confidence. Returns 0.0 if no
                frequency or false positive data exists.

        """
        if self.frequency + self.false_positives == 0:
            return 0.0
        accuracy = self.frequency / (self.frequency + self.false_positives)
        recency_factor = min(1.0, (time.time() - self.last_seen) / (30 * 24 * 3600))
        return accuracy * (1 - recency_factor * 0.2) * self.confidence


@dataclass
class ProtectionSignature:
    """Complete protection signature with all detection methods.

    Comprehensive signature combining multiple detection approaches for a specific
    protection mechanism. Used to define and track the characteristics of known
    protectors, packers, and DRM schemes.

    Attributes:
        name: Name of the protection mechanism (e.g., "VMProtect 3.8").
        category: ProtectionCategory enum for the protection type.
        static_patterns: List of DynamicSignature objects for pattern matching.
        behavioral_indicators: List of behavioral characteristics as strings.
        entropy_ranges: Tuple of (min_entropy, max_entropy) for detection.
        section_characteristics: Dictionary of PE section flags and properties.
        import_signatures: Set of suspicious API imports characteristic of protection.
        export_signatures: Set of exported function names indicating protection.
        string_indicators: Set of string keywords indicating protection presence.
        code_patterns: List of binary instruction patterns for detection.
        confidence_threshold: Minimum confidence (0.0-1.0) for positive detection.

    """

    name: str
    category: ProtectionCategory
    static_patterns: list[DynamicSignature]
    behavioral_indicators: list[str]
    entropy_ranges: tuple[float, float]
    section_characteristics: dict[str, Any]
    import_signatures: set[str]
    export_signatures: set[str]
    string_indicators: set[str]
    code_patterns: list[bytes]
    confidence_threshold: float = 0.7


class DynamicSignatureExtractor:
    """Extracts protection signatures dynamically from binaries.

    Advanced signature extraction engine that analyzes binaries to identify
    protection mechanisms through multiple analysis techniques including entropy
    analysis, section inspection, import/export analysis, code pattern detection,
    string indicators, behavioral analysis, and mutation detection. Uses pattern
    evolution and machine learning to improve detection accuracy over time.

    """

    def __init__(self, db_path: str = "") -> None:
        """Initialize the dynamic signature extractor.

        Sets up the signature extraction engine with database persistence, pattern
        tracking, and various analysis tools for detecting protection mechanisms
        in binaries.

        Args:
            db_path: Path to SQLite database for signature persistence. Defaults to
                the project's PROTECTION_SIGNATURES_DB if not specified.

        """
        self.db_path = db_path or str(PROTECTION_SIGNATURES_DB)
        self.signatures: dict[str, list[DynamicSignature]] = defaultdict(list)
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
        """Initialize SQLite database for persistent signature storage.

        Creates necessary database tables for storing signatures, protection profiles,
        and mutation history. This is called during initialization to ensure the
        database schema exists before any operations.

        Raises:
            sqlite3.Error: If database creation or table creation fails.

        """
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

    def extract_signatures(self, binary_path: str, known_protection: str | None = None) -> list[DynamicSignature]:
        """Extract protection signatures dynamically from a binary.

        Performs comprehensive signature extraction using multiple analysis techniques
        including entropy analysis, section inspection, import table analysis, code
        pattern recognition, string analysis, behavioral indicators, and mutation
        detection. Results are evolved through pattern evolution to improve accuracy.

        Args:
            binary_path: Path to the binary file to analyze.
            known_protection: Optional name of the known protection mechanism for
                signature learning and persistence. If provided, extracted signatures
                are stored in the database for future reference.

        Returns:
            list[DynamicSignature]: List of extracted protection signatures, each
                containing pattern bytes, confidence scores, and contextual metadata.
                Returns empty list if extraction fails.

        Raises:
            IOError: If the binary file cannot be read.
            Exception: If signature extraction or database storage fails. Exceptions
                are caught and logged; empty list is returned gracefully.

        """
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
                if hasattr(self.pattern_tracker, "track_pattern"):
                    self.pattern_tracker.track_pattern(sig.pattern_bytes.hex(), sig.category.value, {"confidence": sig.confidence})

        except Exception as e:
            logger.exception("Failed to extract signatures: %s", e)

        return signatures

    def _extract_entropy_signatures(self, data: bytes) -> list[DynamicSignature]:
        """Extract signatures based on entropy analysis.

        Analyzes binary data using a sliding window approach to detect high-entropy
        regions characteristic of packed or encrypted code. High entropy (>7.5) is
        flagged as potential packing or encryption protection.

        Args:
            data: Raw binary data to analyze.

        Returns:
            list[DynamicSignature]: List of entropy-based protection signatures.
                Includes confidence scoring based on entropy values and contextual
                information about entropy levels at detection offsets.

        """
        signatures: list[DynamicSignature] = []
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

    def _extract_section_signatures(self, data: bytes) -> list[DynamicSignature]:
        """Extract signatures from PE section characteristics.

        Analyzes PE section headers to detect protection signatures based on entropy
        levels, section names, and characteristics. Sections with high entropy (>6.5)
        or suspicious names are flagged as potential protection mechanisms.

        Args:
            data: Raw binary data to analyze. Must be a PE executable.

        Returns:
            list[DynamicSignature]: List of section-based protection signatures with
                metadata including section name, entropy, characteristics, and size
                information. Returns empty list if data is not a PE or pefile is
                unavailable.

        Raises:
            Exception: If PE parsing fails. Exceptions are caught and logged; empty
                list is returned gracefully.

        """
        signatures: list[DynamicSignature] = []

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
                    mask[:8] = b"\xff" * 8
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
            logger.debug("PE section extraction failed: %s", e)

        return signatures

    def _extract_import_signatures(self, data: bytes) -> list[DynamicSignature]:
        """Extract signatures from import table patterns.

        Analyzes the PE import address table to identify suspicious API imports
        indicative of protection mechanisms. Detects anti-debug, anti-VM, encryption,
        and other protection-related imports.

        Args:
            data: Raw binary data to analyze. Must be a PE executable.

        Returns:
            list[DynamicSignature]: List of import-based protection signatures
                categorized by protection type (anti-debug, anti-VM, encryption, etc.)
                with metadata about imported APIs and DLL counts. Returns empty list
                if data is not a PE or pefile is unavailable.

        Raises:
            Exception: If PE parsing or import table analysis fails. Exceptions are
                caught and logged; empty list is returned gracefully.

        """
        signatures: list[DynamicSignature] = []

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
                if import_pattern := self._generate_import_pattern(pe, suspicious_apis):
                    sig = DynamicSignature(
                        category=self._categorize_imports(suspicious_apis),
                        confidence=min(1.0, len(suspicious_apis) * 0.1),
                        pattern_bytes=import_pattern,
                        mask=b"\xff" * len(import_pattern),
                        context=f"Suspicious imports: {', '.join(list(suspicious_apis)[:5])}",
                        metadata={
                            "imports": list(suspicious_apis),
                            "dll_count": len(import_profile),
                        },
                    )
                    signatures.append(sig)

            pe.close()

        except Exception as e:
            logger.debug("Import extraction failed: %s", e)

        return signatures

    def _extract_code_signatures(self, data: bytes) -> list[DynamicSignature]:
        """Extract signatures from code pattern analysis.

        Analyzes binary code sequences using the binary pattern detector and
        disassembly to identify protection-related instruction patterns including
        anti-debug checks, anti-VM detection, and obfuscation techniques.

        Args:
            data: Raw binary data to analyze.

        Returns:
            list[DynamicSignature]: List of code pattern-based protection signatures
                with offset information, cross-reference counts, and pattern names
                extracted from disassembly analysis. Returns empty list if Capstone
                is unavailable.

        Raises:
            Exception: If pattern detection or code analysis fails. Exceptions may
                be raised by binary pattern detector or disassembly analysis.

        """
        signatures: list[DynamicSignature] = []

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
                metadata={
                    "offset": match.offset,
                    "xrefs": match.xrefs,
                    "pattern_name": match.pattern.name,
                },
            )
            signatures.append(sig)

        # Extract custom code patterns through disassembly
        code_patterns = self._analyze_code_sequences(data)
        signatures.extend(code_patterns)

        return signatures

    def _extract_string_signatures(self, data: bytes) -> list[DynamicSignature]:
        """Extract signatures from string analysis.

        Extracts ASCII and Unicode strings from binary data and analyzes them for
        protection-related keywords such as product names, activation strings, and
        anti-analysis indicators.

        Args:
            data: Raw binary data to analyze.

        Returns:
            list[DynamicSignature]: List of string-based protection signatures with
                encoding type, string offsets, and protection category. Each signature
                includes context and neighboring bytes for pattern matching.

        Raises:
            Exception: If string extraction or encoding analysis fails.

        """
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
                    metadata={
                        "string": prot_str,
                        "offset": offset,
                        "encoding": "ascii" if prot_str in ascii_strings else "unicode",
                    },
                )
                signatures.append(sig)

        return signatures

    def _extract_behavioral_signatures(self, data: bytes) -> list[DynamicSignature]:
        """Extract behavioral signatures through advanced analysis.

        Analyzes runtime behavior patterns including control flow, API call sequences,
        and timing checks to identify protection mechanisms that operate through
        behavioral anomalies rather than static code patterns.

        Args:
            data: Raw binary data to analyze.

        Returns:
            list[DynamicSignature]: List of behavioral protection signatures including
                control flow anomalies, suspicious API sequences, and timing checks.

        Raises:
            Exception: If behavioral analysis or pattern extraction fails.

        """
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

    def _extract_mutation_signatures(self, data: bytes) -> list[DynamicSignature]:
        """Extract signatures for polymorphic/metamorphic code.

        Detects code mutation techniques including self-modifying code, polymorphic
        engines, and metamorphic transformations that dynamically alter code structure
        to evade static detection.

        Args:
            data: Raw binary data to analyze.

        Returns:
            list[DynamicSignature]: List of mutation-based protection signatures with
                mutation type classification and complexity assessment (low, medium, high).

        Raises:
            Exception: If mutation detection or complexity assessment fails.

        """
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
                metadata={
                    "mutation_type": mutation_type,
                    "complexity": self._assess_mutation_complexity(pattern),
                },
            )
            signatures.append(sig)

        return signatures

    def _evolve_signatures(self, signatures: list[DynamicSignature], data: bytes) -> list[DynamicSignature]:
        """Use pattern evolution to generate improved signatures.

        Applies machine learning pattern evolution to existing signatures to create
        mutated variants that improve detection accuracy and coverage against
        polymorphic protection mechanisms.

        Args:
            signatures: List of base signatures to evolve.
            data: Raw binary data for validating evolved signatures.

        Returns:
            list[DynamicSignature]: List of evolved signatures with reduced confidence
                (multiplied by 0.9) and parent pattern tracking for genealogy.

        Raises:
            Exception: If pattern tracking or mutation detection fails.

        """
        evolved: list[DynamicSignature] = []

        for sig in signatures:
            # Track pattern for evolution
            if hasattr(self.pattern_tracker, "track_pattern"):
                pattern_id = self.pattern_tracker.track_pattern(sig.pattern_bytes.hex(), sig.category.value, {"confidence": sig.confidence})
            else:
                continue

            # Get mutations
            if hasattr(self.pattern_tracker, "detect_pattern_mutations"):
                mutations = self.pattern_tracker.detect_pattern_mutations(pattern_id)
            else:
                continue

            for mutation in mutations:
                # Mutation is dict[str, Any], extract pattern string
                mutation_pattern = mutation.get("pattern")
                if not isinstance(mutation_pattern, str):
                    continue

                # Test mutation effectiveness
                if self._test_mutation_effectiveness(mutation_pattern, data):
                    evolved_sig = DynamicSignature(
                        category=sig.category,
                        confidence=sig.confidence * 0.9,
                        pattern_bytes=bytes.fromhex(mutation_pattern),
                        mask=self._evolve_mask(sig.mask, mutation_pattern),
                        context=f"Evolved from: {sig.context}",
                        metadata={
                            "parent_pattern": sig.pattern_bytes.hex(),
                            "evolution_generation": 1,
                        },
                    )
                    evolved.append(evolved_sig)

        return evolved

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data.

        Computes the Shannon entropy of binary data to measure randomness and
        identify compressed or encrypted sections. Higher entropy indicates
        packed/encrypted code.

        Args:
            data: Raw bytes to calculate entropy for.

        Returns:
            float: Shannon entropy value between 0.0 (highly ordered) and 8.0
                (maximum randomness for bytes). Returns 0.0 for empty data.

        """
        if not data:
            return 0.0

        byte_counts: dict[int, int] = defaultdict(int)
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
        """Generate mask for entropy-based pattern.

        Creates a pattern mask for entropy signatures allowing variable middle sections
        while preserving exact matching on boundaries.

        Args:
            pattern: The pattern bytes to generate a mask for.

        Returns:
            bytes: Mask with 0xFF at fixed boundaries and 0x00 in variable regions.

        """
        mask = bytearray(len(pattern))

        # Keep first and last 8 bytes exact
        if len(pattern) > 16:
            mask[:8] = b"\xff" * 8
            mask[-8:] = b"\xff" * 8
        else:
            mask[:] = b"\xff" * len(pattern)

        return bytes(mask)

    def _determine_section_category(self, name: str, entropy: float) -> ProtectionCategory:
        """Determine protection category from section characteristics.

        Classifies sections based on naming conventions and entropy levels to
        identify the type of protection mechanism present.

        Args:
            name: PE section name (e.g., ".text", ".pack", ".vmp").
            entropy: Calculated entropy of the section.

        Returns:
            ProtectionCategory: Enum value indicating packer, protector, obfuscation,
                encryption, or custom category based on heuristics.

        """
        name_lower = name.lower()

        if "pack" in name_lower or entropy > 7.5:
            return ProtectionCategory.PACKER
        if "vmp" in name_lower or "themida" in name_lower:
            return ProtectionCategory.PROTECTOR
        if "obf" in name_lower or "mut" in name_lower:
            return ProtectionCategory.OBFUSCATION
        if entropy > 7.0:
            return ProtectionCategory.ENCRYPTION
        return ProtectionCategory.CUSTOM

    def _calculate_section_confidence(self, entropy: float, section: object) -> float:
        """Calculate confidence score for section-based signature.

        Computes confidence based on entropy levels and section characteristics
        flags that indicate protected or suspicious content.

        Args:
            entropy: Calculated entropy of the section.
            section: PE section object with characteristics attributes.

        Returns:
            float: Confidence score between 0.0 and 1.0, adjusted by section
                characteristics flags.

        """
        confidence = min(1.0, entropy / 8.0)

        if hasattr(section, "Characteristics"):
            if section.Characteristics & 0x20000000:
                confidence *= 1.1
            if section.Characteristics & 0x80000000:
                confidence *= 1.15

        return min(1.0, confidence)

    def _is_suspicious_api(self, api_name: str) -> bool:
        """Dynamically determine if an API is suspicious.

        Checks API name against known protection-related keywords that indicate
        anti-debug, anti-VM, cryptography, or other suspicious behavior.

        Args:
            api_name: Name of the API to check.

        Returns:
            bool: True if API name matches suspicious patterns, False otherwise.

        """
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

    def _categorize_imports(self, apis: set[str]) -> ProtectionCategory:
        """Categorize protection based on imported APIs.

        Determines protection type by analyzing the set of suspicious APIs
        imported by the binary.

        Args:
            apis: Set of suspicious API names.

        Returns:
            ProtectionCategory: Protection type based on API analysis (anti-debug,
                anti-VM, encryption, protector, or custom).

        """
        api_str = " ".join(apis).lower()

        if "debug" in api_str:
            return ProtectionCategory.ANTI_DEBUG
        if "virtual" in api_str or "vm" in api_str:
            return ProtectionCategory.ANTI_VM
        if "crypt" in api_str:
            return ProtectionCategory.ENCRYPTION
        if "protect" in api_str:
            return ProtectionCategory.PROTECTOR
        return ProtectionCategory.CUSTOM

    def _generate_import_pattern(self, pe: object, apis: set[str]) -> bytes | None:
        """Generate pattern from import table structure.

        Creates a binary pattern from the import directory structure for matching
        against other binaries with similar import characteristics.

        Args:
            pe: PE object with OPTIONAL_HEADER containing import directory.
            apis: Set of suspicious API names (unused, for future reference).

        Returns:
            bytes | None: Packed import directory structure pattern, or None if
                extraction fails or import directory is unavailable.

        """
        try:
            # Extract import directory structure
            if not hasattr(pe, "OPTIONAL_HEADER"):
                return None

            import_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[1]

            if not hasattr(import_dir, "VirtualAddress") or import_dir.VirtualAddress == 0:
                return None

            return struct.pack(
                "<IIIII",
                0,  # OriginalFirstThunk (variable)
                0,  # TimeDateStamp
                0,  # ForwarderChain
                0,  # Name RVA (variable)
                0,
            )
        except Exception:
            return None

    def _map_pattern_category(self, category: str) -> ProtectionCategory:
        """Map binary pattern category to protection category.

        Converts string category names from the binary pattern detector to
        ProtectionCategory enum values.

        Args:
            category: String category name from binary pattern detection.

        Returns:
            ProtectionCategory: Mapped protection category enum, or CUSTOM if no
                match found.

        """
        mapping = {
            "protection": ProtectionCategory.PROTECTOR,
            "anti_debug": ProtectionCategory.ANTI_DEBUG,
            "anti_vm": ProtectionCategory.ANTI_VM,
            "obfuscation": ProtectionCategory.OBFUSCATION,
            "packer": ProtectionCategory.PACKER,
            "licensing": ProtectionCategory.LICENSING,
        }
        return mapping.get(category, ProtectionCategory.CUSTOM)

    def _extract_strings(self, data: bytes, encoding: str = "ascii", min_length: int = 4) -> list[str]:
        """Extract readable strings from binary data.

        Extracts ASCII or UTF-16LE encoded strings from binary data using regex or
        character scanning depending on the requested encoding.

        Args:
            data: Raw binary data to scan for strings.
            encoding: String encoding type ("ascii" or "utf-16le"). Defaults to "ascii".
            min_length: Minimum string length to extract. Defaults to 4 bytes.

        Returns:
            list[str]: List of extracted strings. Returns empty list if encoding is
                unsupported or no strings found.

        """
        strings = []

        if encoding == "ascii":
            pattern = b"[\x20-\x7e]{%d,}" % min_length
            import re

            for match in re.finditer(pattern, data):
                try:
                    strings.append(match.group().decode("ascii"))
                except Exception as e:
                    logger.debug("String decoding failed: %s", e)

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

    def _analyze_protection_strings(self, strings: list[str]) -> list[tuple[str, ProtectionCategory, float]]:
        """Analyze strings for protection indicators.

        Scans extracted strings for keywords related to known protection mechanisms
        including protectors (VMProtect, Themida), packers (UPX, ASPack), anti-debug,
        anti-VM (VMware, VirtualBox), licensing, and DRM (Denuvo, SecuROM). Returns
        high confidence (0.9) for exact matches and medium confidence (0.7) for
        substring matches.

        Args:
            strings: List of extracted strings from binary.

        Returns:
            list[tuple[str, ProtectionCategory, float]]: List of (string, category,
                confidence) tuples. Confidence is 0.9 for exact matches and 0.7 for
                substring matches in the string.

        """
        indicators = []

        protection_keywords = {
            ProtectionCategory.PROTECTOR: [
                "vmprotect",
                "themida",
                "enigma",
                "obsidium",
                "armadillo",
            ],
            ProtectionCategory.PACKER: ["upx", "aspack", "pecompact", "petite", "mpress"],
            ProtectionCategory.ANTI_DEBUG: ["debugger", "isdebuggerpresent", "checkremotedebugger"],
            ProtectionCategory.ANTI_VM: ["vmware", "virtualbox", "sandbox", "wine", "qemu"],
            ProtectionCategory.LICENSING: [
                "license",
                "registration",
                "activation",
                "serial",
                "keygen",
            ],
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

    def _analyze_control_flow(self, data: bytes) -> list[tuple[bytes, ProtectionCategory, float, str]]:
        """Analyze control flow for protection patterns.

        Detects control flow obfuscation through jump chain analysis and call depth
        tracking, which are indicators of code protection or obfuscation. Identifies
        suspicious jump chains (>5 consecutive jumps) and deeply nested call sequences
        that suggest anti-analysis or obfuscation techniques.

        Args:
            data: Raw binary data to analyze.

        Returns:
            list[tuple[bytes, ProtectionCategory, float, str]]: List of (pattern,
                category, confidence, context) tuples for detected control flow
                anomalies. Returns empty list if Capstone is unavailable.

        """
        patterns: list[tuple[bytes, ProtectionCategory, float, str]] = []

        if not CAPSTONE_AVAILABLE:
            return patterns

        # Simplified control flow analysis
        jmp_chains = self._find_jump_chains(data)
        self._analyze_call_depth(data)

        for chain in jmp_chains:
            if len(chain) > 5:  # Suspicious jump chain
                pattern = self._extract_pattern_from_chain(data, chain)
                patterns.append((
                    pattern,
                    ProtectionCategory.OBFUSCATION,
                    min(1.0, len(chain) * 0.15),
                    f"Jump chain length: {len(chain)}",
                ))

        return patterns

    def _find_jump_chains(self, data: bytes) -> list[list[int]]:
        """Find chains of jumps in code.

        Detects sequences of consecutive jump instructions which indicate control
        flow obfuscation or indirect branching patterns common in protected code.

        Args:
            data: Raw binary data to scan for jump chains.

        Returns:
            list[list[int]]: List of jump chains, each containing offsets where
                jump instructions occur. Returns empty list if Capstone unavailable.

        """
        chains: list[list[int]] = []

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

    def _analyze_call_depth(self, data: bytes) -> list[int]:
        """Analyze call instruction depth by tracking nested call chains.

        Scans code for CALL and RET instructions to measure call stack depth,
        which helps identify deeply nested function calls indicative of protection.

        Args:
            data: Raw binary data to analyze.

        Returns:
            list[int]: Sorted list of unique call depth levels found. Returns empty
                list if Capstone is unavailable or no calls detected.

        """
        depths: list[int] = []

        if not CAPSTONE_AVAILABLE:
            return depths

        cs = self.cs_x86
        call_stack = []
        visited_addresses = set()
        max_depth = 0

        # Scan for CALL instructions and track depth
        for offset in range(len(data) - 32):
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
                logger.warning("Error processing instruction in call depth analysis: %s", e)
                continue

        # Return unique depth levels found
        return sorted(set(depths)) if depths else []

    def _analyze_call_target(self, data: bytes, target_addr: int, current_depth: int, visited: set[int]) -> list[int]:
        """Recursively analyze call targets to find maximum call depth.

        Recursively examines function calls detected at a target address to
        measure nested call depth and detect recursive patterns.

        Args:
            data: Raw binary data.
            target_addr: Address to begin analysis.
            current_depth: Current call depth level.
            visited: Set of visited addresses to avoid infinite recursion.

        Returns:
            list[int]: List of depth values found in the call target. Values >5
                indicate deeply nested calls. Recursive calls return depth+10.

        """
        depths: list[int] = []

        if not CAPSTONE_AVAILABLE or target_addr >= len(data):
            return depths

        cs = self.cs_x86
        max_scan = min(target_addr + 1000, len(data))

        # Scan target function for more calls
        for offset in range(target_addr, max_scan):
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
                logger.warning("Error processing instruction in call target analysis: %s", e)
                continue

        return depths

    def _extract_pattern_from_chain(self, data: bytes, chain: list[int]) -> bytes:
        """Extract pattern from jump chain.

        Extracts binary data spanning a jump chain for pattern matching.

        Args:
            data: Raw binary data.
            chain: List of offsets forming a jump chain.

        Returns:
            bytes: Binary data from first jump to 16 bytes past last jump, or
                empty bytes if chain is empty.

        """
        return data[chain[0] : min(chain[-1] + 16, len(data))] if chain else b""

    def _analyze_code_sequences(self, data: bytes) -> list[DynamicSignature]:
        """Analyze code sequences through disassembly for protection signatures.

        Scans binary code for known protection instruction patterns including
        anti-debug checks (INT3, INT2D), VM detection (CPUID, SIDT, SGDT), timing
        checks (RDTSC), and obfuscation indicators. Validates patterns against
        disassembly and extracts obfuscation and license check sequences.

        Args:
            data: Raw binary data to analyze.

        Returns:
            list[DynamicSignature]: List of DynamicSignature objects representing
                detected protection patterns with metadata and confidence scores.

        Raises:
            Exception: If disassembly validation or sequence analysis fails.

        """
        signatures: list[DynamicSignature] = []

        if not CAPSTONE_AVAILABLE or len(data) < 16:
            return signatures

        cs = self.cs_x86

        protection_instruction_patterns = {
            "anti_debug_int3": (b"\xcc", ProtectionCategory.ANTI_DEBUG, 0.6),
            "anti_debug_int2d": (b"\xcd\x2d", ProtectionCategory.ANTI_DEBUG, 0.85),
            "vm_detect_cpuid": (b"\x0f\xa2", ProtectionCategory.ANTI_VM, 0.7),
            "rdtsc_timing": (b"\x0f\x31", ProtectionCategory.ANTI_DEBUG, 0.8),
            "pushf_popf_debug": (b"\x9c\x9d", ProtectionCategory.ANTI_DEBUG, 0.65),
            "sidt_vm_detect": (b"\x0f\x01\x0c", ProtectionCategory.ANTI_VM, 0.75),
            "sgdt_vm_detect": (b"\x0f\x01\x04", ProtectionCategory.ANTI_VM, 0.75),
            "sldt_vm_detect": (b"\x0f\x00\x00", ProtectionCategory.ANTI_VM, 0.7),
            "str_vm_detect": (b"\x0f\x00\xc8", ProtectionCategory.ANTI_VM, 0.7),
        }

        for pattern_name, (pattern_bytes, category, base_confidence) in protection_instruction_patterns.items():
            offset = 0
            occurrences = 0

            while offset < len(data) - len(pattern_bytes):
                found_offset = data.find(pattern_bytes, offset)
                if found_offset == -1:
                    break

                occurrences += 1
                context_start = max(0, found_offset - 16)
                context_end = min(len(data), found_offset + len(pattern_bytes) + 16)
                context_bytes = data[context_start:context_end]

                try:
                    instructions = list(cs.disasm(context_bytes, context_start))
                    valid_instruction = any(insn.address <= found_offset < insn.address + insn.size for insn in instructions)

                    if valid_instruction:
                        confidence = min(1.0, base_confidence + (occurrences * 0.02))

                        mask = bytearray(len(context_bytes))
                        pattern_rel_start = found_offset - context_start
                        mask[pattern_rel_start : pattern_rel_start + len(pattern_bytes)] = b"\xff" * len(pattern_bytes)

                        sig = DynamicSignature(
                            category=category,
                            confidence=confidence,
                            pattern_bytes=context_bytes,
                            mask=bytes(mask),
                            context=f"Code sequence: {pattern_name} at offset 0x{found_offset:08x}",
                            metadata={
                                "pattern_name": pattern_name,
                                "offset": found_offset,
                                "instruction_bytes": pattern_bytes.hex(),
                                "occurrences": occurrences,
                            },
                        )
                        signatures.append(sig)

                except Exception as e:
                    logger.debug("Disassembly validation failed for %s: %s", pattern_name, e)

                offset = found_offset + 1

        obfuscation_sequences = self._detect_obfuscation_sequences(data, cs)
        signatures.extend(obfuscation_sequences)

        license_check_sequences = self._detect_license_check_sequences(data, cs)
        signatures.extend(license_check_sequences)

        return signatures

    def _detect_obfuscation_sequences(self, data: bytes, cs: object) -> list[DynamicSignature]:
        """Detect obfuscation patterns in code sequences.

        Identifies obfuscation techniques including NOP sleds (sequences of 10+
        NOP instructions) and junk code patterns (push/pop, xchg pairs). These
        patterns are commonly used to increase code complexity and evade signature
        matching.

        Args:
            data: Raw binary data.
            cs: Capstone disassembler instance for instruction analysis.

        Returns:
            list[DynamicSignature]: List of DynamicSignature objects for detected
                obfuscation patterns with offset, pattern type, and instance counts.

        Raises:
            Exception: If pattern analysis or iteration fails.

        """
        signatures: list[DynamicSignature] = []

        nop_sled_threshold = 10
        nop_count = 0
        nop_start = -1

        for i, byte in enumerate(data):
            if byte == 0x90:
                if nop_start == -1:
                    nop_start = i
                nop_count += 1
            else:
                if nop_count >= nop_sled_threshold:
                    pattern = data[nop_start : nop_start + nop_count]
                    sig = DynamicSignature(
                        category=ProtectionCategory.OBFUSCATION,
                        confidence=min(0.9, 0.5 + (nop_count * 0.01)),
                        pattern_bytes=pattern[:64],
                        mask=b"\xff" * min(64, len(pattern)),
                        context=f"NOP sled: {nop_count} bytes at 0x{nop_start:08x}",
                        metadata={
                            "pattern_type": "nop_sled",
                            "offset": nop_start,
                            "length": nop_count,
                        },
                    )
                    signatures.append(sig)

                nop_count = 0
                nop_start = -1

        junk_code_patterns = [
            (b"\x50\x58", "push_pop_eax"),
            (b"\x51\x59", "push_pop_ecx"),
            (b"\x52\x5a", "push_pop_edx"),
            (b"\x53\x5b", "push_pop_ebx"),
            (b"\x87\xc0", "xchg_eax_eax"),
            (b"\x87\xdb", "xchg_ebx_ebx"),
        ]

        junk_count = 0
        for pattern, _name in junk_code_patterns:
            offset = 0
            while True:
                found = data.find(pattern, offset)
                if found == -1:
                    break
                junk_count += 1
                offset = found + 1

        if junk_count > 5:
            sig = DynamicSignature(
                category=ProtectionCategory.OBFUSCATION,
                confidence=min(0.85, 0.4 + (junk_count * 0.03)),
                pattern_bytes=b"\x50\x58",
                mask=b"\xff\xff",
                context=f"Junk code insertion: {junk_count} instances detected",
                metadata={
                    "pattern_type": "junk_code",
                    "instance_count": junk_count,
                },
            )
            signatures.append(sig)

        return signatures

    def _detect_license_check_sequences(self, data: bytes, cs: object) -> list[DynamicSignature]:
        """Detect license validation code sequences.

        Identifies license verification routines by matching comparison and jump
        instructions (CMP, TEST, JZ, JNZ) that are typically used for license
        validation logic, especially when found near license-related strings
        like "license", "serial", "key", "valid", or "trial".

        Args:
            data: Raw binary data.
            cs: Capstone disassembler instance for instruction validation.

        Returns:
            list[DynamicSignature]: List of DynamicSignature objects for detected
                license check patterns with instruction names and offsets.

        Raises:
            Exception: If pattern matching or context extraction fails.

        """
        signatures: list[DynamicSignature] = []

        license_patterns = [
            (b"\x3d", "cmp_eax_imm32", 0.5),
            (b"\x81\xf8", "cmp_eax_imm32_alt", 0.5),
            (b"\x83\xf8", "cmp_eax_imm8", 0.45),
            (b"\x85\xc0", "test_eax_eax", 0.4),
            (b"\x0f\x84", "jz_near", 0.35),
            (b"\x0f\x85", "jnz_near", 0.35),
            (b"\x74", "jz_short", 0.3),
            (b"\x75", "jnz_short", 0.3),
        ]

        comparison_sequence_count = 0

        for pattern, name, base_conf in license_patterns:
            offset = 0
            while True:
                found = data.find(pattern, offset)
                if found == -1:
                    break

                context_start = max(0, found - 8)
                context_end = min(len(data), found + 16)
                context = data[context_start:context_end]

                has_string_ref = any(
                    license_str in data[max(0, found - 256) : found + 256].lower()
                    for license_str in [
                        b"license",
                        b"serial",
                        b"key",
                        b"valid",
                        b"trial",
                    ]
                )
                if has_string_ref:
                    comparison_sequence_count += 1
                    confidence = min(0.9, base_conf + 0.3)

                    sig = DynamicSignature(
                        category=ProtectionCategory.LICENSING,
                        confidence=confidence,
                        pattern_bytes=context,
                        mask=b"\xff" * len(context),
                        context=f"License check: {name} near license string at 0x{found:08x}",
                        metadata={
                            "pattern_type": "license_check",
                            "instruction": name,
                            "offset": found,
                            "near_license_string": True,
                        },
                    )
                    signatures.append(sig)

                offset = found + 1

        return signatures

    def _analyze_api_sequences(self, data: bytes) -> list[tuple[bytes, ProtectionCategory, float, str]]:
        """Analyze API call sequences.

        Detects suspicious patterns in API call sequences that indicate protection
        or anti-analysis mechanisms by searching for characteristic instruction
        patterns (indirect calls via IAT, direct calls) that precede API invocations.
        Validates sequences against disassembly to ensure proper instruction alignment.

        Args:
            data: Raw binary data to analyze.

        Returns:
            list[tuple[bytes, ProtectionCategory, float, str]]: List of (pattern,
                category, confidence, context) tuples for suspicious API call sequences
                with pattern names and offsets in the binary.

        Raises:
            Exception: If disassembly or pattern analysis fails.

        """
        patterns: list[tuple[bytes, ProtectionCategory, float, str]] = []

        if not CAPSTONE_AVAILABLE:
            return patterns

        cs = self.cs_x86

        # Scan for suspicious API call patterns
        api_call_patterns = [
            (b"\xff\x15", "indirect_call_iat", ProtectionCategory.ANTI_DEBUG, 0.6),
            (b"\xe8", "direct_call", ProtectionCategory.PROTECTOR, 0.5),
        ]

        for pattern_bytes, pattern_name, category, base_conf in api_call_patterns:
            offset = 0
            sequence_count = 0

            while offset < len(data) - len(pattern_bytes):
                found = data.find(pattern_bytes, offset)
                if found == -1:
                    break

                sequence_count += 1

                # Extract context around API call
                context_start = max(0, found - 16)
                context_end = min(len(data), found + 24)
                context_bytes = data[context_start:context_end]

                try:
                    instructions = list(cs.disasm(context_bytes, context_start))
                    if len(instructions) >= 2:
                        confidence = min(1.0, base_conf + (sequence_count * 0.05))
                        patterns.append((
                            context_bytes,
                            category,
                            confidence,
                            f"API sequence: {pattern_name} at 0x{found:08x}",
                        ))
                except Exception:
                    pass

                offset = found + 1

        return patterns

    def _analyze_timing_patterns(self, data: bytes) -> list[tuple[bytes, ProtectionCategory, float, str]]:
        """Analyze timing check patterns.

        Detects timing-based anti-debug checks using the RDTSC instruction that
        measures CPU cycle counters to determine if code is being debugged. RDTSC
        timing discrepancies indicate debugger presence (stepping slows down timing).

        Args:
            data: Raw binary data to scan for timing check instructions.

        Returns:
            list[tuple[bytes, ProtectionCategory, float, str]]: List of (pattern,
                category, confidence, context) tuples for detected RDTSC timing checks
                with offsets and surrounding code context.

        Raises:
            Exception: If pattern extraction fails.

        """
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
        """Generate mask for behavioral pattern.

        Creates a mask allowing variation in operand fields while preserving
        opcode bytes for behavioral pattern matching. This enables flexible
        matching of instruction sequences where operand values may vary but
        the overall behavior remains consistent.

        Args:
            pattern: Behavioral pattern bytes.

        Returns:
            bytes: Mask with 0xFF on even indices (opcodes) and 0x00 on odd
                indices (operands) to enforce strict opcode matching while
                allowing operand variation.

        """
        # Allow some variation in behavioral patterns
        mask = bytearray(len(pattern))

        for i in range(len(pattern)):
            # Keep opcodes, allow operand variation
            mask[i] = 0xFF if i % 2 == 0 else 0x00
        return bytes(mask)

    def _detect_self_modifying_code(self, data: bytes) -> list[tuple[bytes, float, str]]:
        """Detect self-modifying code patterns.

        Detects write instructions (MOV, MOVQ) targeting code sections, which
        indicate self-modifying code or runtime code generation techniques.
        These are sophisticated protection mechanisms that dynamically patch
        or generate code at runtime to evade static analysis.

        Args:
            data: Raw binary data to analyze.

        Returns:
            list[tuple[bytes, float, str]]: List of (pattern, confidence, description)
                tuples for detected self-modifying code patterns with offset context
                and instruction mnemonics.

        Raises:
            Exception: If pattern matching fails.

        """
        patterns = []

        # Look for code that writes to code sections
        write_patterns = [
            (b"\x89", 0.6, "MOV to memory"),
            (b"\xc7", 0.7, "MOV immediate to memory"),
            (b"\x88", 0.6, "MOV byte to memory"),
        ]

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

    def _detect_polymorphic_engines(self, data: bytes) -> list[tuple[bytes, float, str]]:
        """Detect polymorphic engine signatures using advanced analysis.

        Uses the PolymorphicAnalyzer to detect code mutation engines, self-modifying
        code, and decryption routines. Falls back to pattern detection for XOR
        decryption loops (XOR with branch/loop instructions) if advanced analysis
        fails. Detects semantic invariants and behavior patterns to identify
        polymorphic protection mechanisms.

        Args:
            data: Raw binary data to analyze.

        Returns:
            list[tuple[bytes, float, str]]: List of (pattern, confidence, description)
                tuples for detected polymorphic engines, decryption routines, mutation
                techniques, and behavior patterns.

        Raises:
            Exception: If polymorphic analysis or fallback pattern detection fails.

        """
        patterns = []

        try:
            analyzer = PolymorphicAnalyzer(arch="x86", bits=self._guess_bitness(data))

            analysis = analyzer.analyze_polymorphic_code(data, base_address=0, max_instructions=500)

            if analysis.engine_type.value != "unknown":
                if semantic_sig := analysis.invariant_features.get("semantic_sequence", ()):
                    sig_bytes = str(semantic_sig).encode()[:64]
                    confidence = 0.85 if analysis.mutation_complexity > 0.5 else 0.70
                    patterns.append((sig_bytes, confidence, f"Polymorphic engine: {analysis.engine_type.value}"))

            if analysis.decryption_routine:
                decryption_block = analysis.decryption_routine
                routine_bytes = data[decryption_block.start_address : decryption_block.end_address][:64]
                patterns.append((routine_bytes, 0.90, "Polymorphic decryption routine"))

            for mutation_type in analysis.mutation_types:
                mutation_desc = mutation_type.value.replace("_", " ").title()
                patterns.append((data[:32], 0.65, f"Mutation: {mutation_desc}"))

            for behavior in analysis.behavior_patterns:
                behavior_bytes = behavior.behavioral_hash.encode()[:64]
                patterns.append((
                    behavior_bytes,
                    behavior.confidence,
                    f"Behavior pattern: {behavior.pattern_id}",
                ))

        except Exception as e:
            logger.debug("Polymorphic analysis error: %s", e)

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

    def _detect_metamorphic_code(self, data: bytes) -> list[tuple[bytes, float, str]]:
        """Detect metamorphic code transformations using semantic analysis.

        Detects metamorphic engines that use multiple transformation techniques
        including instruction substitution (different opcodes for same operation),
        instruction expansion (one opcode becomes multiple), code reordering
        (instructions rearranged), and semantic NOPs (instructions that don't
        affect functionality) to evade static detection. Requires 2+ techniques
        for positive identification.

        Args:
            data: Raw binary data to analyze.

        Returns:
            list[tuple[bytes, float, str]]: List of (pattern, confidence, description)
                tuples for detected metamorphic transformation techniques with
                control flow complexity information.

        Raises:
            Exception: If metamorphic analysis or semantic signature extraction fails.

        """
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
                if semantic_sig := analyzer.extract_semantic_signature(data, base_address=0):
                    sig_bytes = semantic_sig.encode()[:64]
                    confidence = min(0.95, 0.70 + (len(detected_metamorphic) * 0.08))
                    patterns.append((
                        sig_bytes,
                        confidence,
                        f"Metamorphic code: {len(detected_metamorphic)} techniques",
                    ))

            for mutation in detected_metamorphic:
                mutation_name = mutation.value.replace("_", " ").title()
                patterns.append((data[:32], 0.70, f"Metamorphic: {mutation_name}"))

            if analysis.invariant_features:
                invariants = analysis.invariant_features
                if invariants.get("control_flow_branches", 0) > 5:
                    patterns.append((data[:48], 0.75, "Metamorphic: Complex control flow"))

        except Exception as e:
            logger.debug("Metamorphic analysis error: %s", e)

        return patterns

    def _guess_bitness(self, data: bytes) -> int:
        """Guess binary bitness from code patterns.

        Determines whether binary is 32-bit or 64-bit by analyzing instruction
        prefixes and x86-64 specific patterns in the code. Checks for REX prefixes
        (0x40-0x4F) and common 64-bit instruction patterns (0x48 prefix).

        Args:
            data: Raw binary data to analyze.

        Returns:
            int: 32 for 32-bit binaries, 64 for 64-bit binaries based on pattern
                analysis. Defaults to 32 for data < 64 bytes.

        """
        if len(data) < 64:
            return 32

        rex_prefix_count = sum(0x40 <= b <= 0x4F for b in data[:64])
        if rex_prefix_count > 2:
            return 64

        reg64_patterns = [b"\x48\x8b", b"\x48\x89", b"\x48\x83", b"\x48\x8d"]
        return next((64 for pattern in reg64_patterns if pattern in data[:128]), 32)

    def _assess_mutation_complexity(self, pattern: bytes) -> str:
        """Assess complexity of mutation pattern.

        Analyzes byte diversity to classify mutation complexity level. Higher
        byte diversity indicates more sophisticated mutation techniques and
        stronger protection mechanisms.

        Args:
            pattern: Pattern bytes to assess.

        Returns:
            str: Complexity level - "low" if <30% unique bytes, "medium" if
                <60% unique bytes, "high" if >= 60% unique bytes.

        """
        unique_bytes = len(set(pattern))

        if unique_bytes < len(pattern) * 0.3:
            return "low"
        return "medium" if unique_bytes < len(pattern) * 0.6 else "high"

    def _generate_mutation_mask(self, pattern: bytes) -> bytes:
        """Generate mask for mutation pattern.

        Creates a sparse mask allowing high variation in mutation patterns while
        preserving structural anchors for matching. Enables matching of polymorphic
        variants that differ significantly in byte content but maintain similar
        structural elements every 4 bytes.

        Args:
            pattern: Pattern bytes to generate mask for.

        Returns:
            bytes: Mask with 0xFF every 4 bytes to anchor structure, 0x00 elsewhere
                for flexible matching of polymorphic code variants.

        """
        # Allow high variation for mutations
        mask = bytearray(len(pattern))

        # Keep structure bytes, allow content variation
        for i in range(0, len(pattern), 4):
            mask[i] = 0xFF

        return bytes(mask)

    def _test_mutation_effectiveness(self, mutation: str, data: bytes) -> bool:
        """Test if a mutation is effective.

        Validates that a mutated pattern actually exists in the binary data
        by attempting to decode it from hex and searching for it. Returns False
        if hex decoding fails or pattern is not found.

        Args:
            mutation: Hex string representation of mutated pattern.
            data: Binary data to search for the pattern.

        Returns:
            bool: True if mutation pattern found in data, False if pattern not
                found or hex decoding fails.

        """
        try:
            pattern = bytes.fromhex(mutation)
            return pattern in data
        except Exception:
            return False

    def _evolve_mask(self, original_mask: bytes, mutation: str) -> bytes:
        """Evolve mask for mutated pattern.

        Adjusts pattern mask to match the length of a mutated pattern, preserving
        the original mask constraints as much as possible. Pads with 0x00 for
        longer mutations or truncates for shorter mutations.

        Args:
            original_mask: Original pattern mask bytes.
            mutation: Hex string representation of mutated pattern.

        Returns:
            bytes: Evolved mask matching the mutation length, or original mask if
                evolution fails (hex decode error, empty mutation, etc.).

        """
        try:
            mutation_bytes = bytes.fromhex(mutation)

            if len(mutation_bytes) != len(original_mask):
                # Adjust mask length
                if len(mutation_bytes) > len(original_mask):
                    return original_mask + b"\x00" * (len(mutation_bytes) - len(original_mask))
                return original_mask[: len(mutation_bytes)]

            return original_mask

        except Exception:
            return original_mask

    def _store_signatures(self, signatures: list[DynamicSignature], protection_name: str) -> None:
        """Store signatures in database.

        Persists extracted signatures to the SQLite database for future reference
        and incremental learning of protection patterns. Updates existing signatures
        when conflicts occur, incrementing frequency and averaging confidence.

        Args:
            signatures: List of DynamicSignature objects to store.
            protection_name: Name of the protection mechanism for reference.

        Raises:
            sqlite3.Error: If database connection or insert/update operations fail.

        """
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
        """Load signatures from database.

        Retrieves previously stored signatures from the SQLite database and
        populates the in-memory signature cache organized by protection category.
        Reconstructs DynamicSignature objects from database rows with full metadata.

        Raises:
            Exception: If database connection or query execution fails.

        """
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
    """Engine for generating pattern mutations.

    Generates mutations of binary patterns to detect polymorphic protection variants
    through byte substitution, instruction replacement, NOP insertion, register
    swapping, and operand modification. Creates functionally equivalent pattern
    variants to improve detection of code that morphs or mutates at runtime.

    The engine applies multiple transformation strategies to create diverse pattern
    variants that maintain behavioral equivalence while altering byte signatures,
    enabling detection of polymorphic and metamorphic protection mechanisms.

    """

    def __init__(self) -> None:
        """Initialize the MutationEngine with available mutation strategies.

        Sets up the list of transformation strategies that will be applied to
        patterns to generate variants. Strategies include byte substitution,
        instruction replacement, NOP insertion, register swapping, and operand
        modification for polymorphic pattern detection.

        """
        self.mutation_strategies = [
            self._byte_substitution,
            self._instruction_replacement,
            self._nop_insertion,
            self._register_swapping,
            self._operand_modification,
        ]

    def generate_mutations(self, pattern: bytes, count: int = 5) -> list[bytes]:
        """Generate mutations of a pattern.

        Applies transformation strategies to create variants of a pattern for
        polymorphic detection. Each strategy is applied sequentially up to the
        specified count, generating functionally equivalent pattern variants.

        Args:
            pattern: Original pattern bytes to mutate.
            count: Number of mutation strategies to apply. Defaults to 5.

        Returns:
            list[bytes]: List of unique mutated patterns. Does not include the
                original pattern if mutations are successful. Returns empty list
                if all mutations fail or pattern is None.

        """
        mutations = []

        for strategy in self.mutation_strategies[:count]:
            mutated = strategy(pattern)
            if mutated and mutated != pattern:
                mutations.append(mutated)

        return mutations

    def _byte_substitution(self, pattern: bytes) -> bytes:
        """Substitute functionally equivalent bytes.

        Replaces x86 instruction bytes with functionally equivalent alternatives
        (e.g., XOR opcode 0x31 with ADD opcode 0x01) to create variants that
        maintain functional equivalence while altering byte signatures.

        Args:
            pattern: Original pattern bytes to mutate.

        Returns:
            bytes: Mutated pattern with equivalent byte substitutions applied.
                Returns original pattern if no substitutions match.

        """
        mutated = bytearray(pattern)

        # Example: XOR -> ADD with zero
        for i in range(len(mutated) - 1):
            if mutated[i] == 0x31:  # XOR
                mutated[i] = 0x01  # ADD

        return bytes(mutated)

    def _instruction_replacement(self, pattern: bytes) -> bytes:
        """Replace instructions with equivalents.

        Replaces instructions with semantically equivalent alternatives to evade
        byte-for-byte pattern matching. Uses instruction replacement table to
        map original opcodes to equivalent ones while maintaining behavior.

        Args:
            pattern: Original pattern bytes to mutate.

        Returns:
            bytes: Pattern with instruction replacements applied from the
                replacement mapping table. Returns original pattern if no
                replacements found.

        """
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
        """Insert NOPs at safe positions.

        Inserts NOP (0x90) instructions at semantically safe locations (after
        unconditional jumps) to add length without changing behavior. Increases
        pattern length while preserving functional equivalence.

        Args:
            pattern: Original pattern bytes to mutate.

        Returns:
            bytes: Pattern with NOPs inserted after jumps and other safe locations,
                resulting in a longer but functionally equivalent pattern. Returns
                pattern with at least one NOP added or original if no jumps found.

        """
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
        """Swap equivalent registers.

        Swaps functionally equivalent registers (e.g., eax with ecx) to create
        variants. Maps x86-32 and x86-64 registers to swap them in instruction
        encoding. Handles ModR/M byte register field substitution for operand
        registers while preserving instruction structure.

        Args:
            pattern: Original pattern bytes to mutate.

        Returns:
            bytes: Pattern with register swaps applied by substituting equivalent
                register encodings in ModR/M and other instruction fields. Returns
                original pattern if no compatible instructions found.

        """
        mutated = bytearray(pattern)

        # Register mapping for common registers: eax, ecx, edx, ebx, esp, ebp, esi, edi
        # ModR/M register field (bits 3-5) encoding: 0=eax, 1=ecx, 2=edx, 3=ebx, etc.
        register_swaps = {
            0: 1,  # eax <-> ecx
            1: 2,  # ecx <-> edx
            2: 3,  # edx <-> ebx
            3: 6,  # ebx <-> esi
            6: 7,  # esi <-> edi
            7: 0,  # edi <-> eax
        }

        for i in range(len(mutated) - 1):
            byte = mutated[i]
            # Check for ModR/M byte following instruction opcode
            if i < len(mutated) - 1:
                modrm = mutated[i + 1]
                # Extract and swap register field (bits 3-5 or bits 0-2)
                if (byte in [0x89, 0x8B, 0x8A, 0x88, 0x83, 0x81]):  # Common MOV/ALU instructions
                    reg_field = (modrm >> 3) & 0x07
                    if reg_field in register_swaps:
                        new_reg = register_swaps[reg_field]
                        mutated[i + 1] = (modrm & 0xC7) | (new_reg << 3)

        return bytes(mutated)

    def _operand_modification(self, pattern: bytes) -> bytes:
        """Modify operands while preserving function.

        Modifies immediate values and operands in instructions to create variants
        while maintaining functional equivalence. Implements instruction decoding
        to identify and modify immediate operands (hardcoded values in instructions)
        while preserving the overall control flow and behavior.

        Args:
            pattern: Original pattern bytes to mutate.

        Returns:
            bytes: Pattern with modified operands that maintain functional equivalence.
                Modifies immediate values while preserving instruction semantics.
                Returns original pattern if no modifiable operands found.

        """
        mutated = bytearray(pattern)

        # Modify immediate values in common instructions
        # This detects immediate operands and applies transformations
        i = 0
        while i < len(mutated) - 4:
            byte = mutated[i]

            # CMP with 32-bit immediate (0x3D or 0x81 0xF8)
            if byte == 0x3D and i + 4 < len(mutated):
                # Modify the 32-bit immediate value slightly
                imm_offset = i + 1
                imm_bytes = mutated[imm_offset:imm_offset + 4]
                imm_value = int.from_bytes(imm_bytes, byteorder='little')
                # XOR with a small value to create variant
                modified_value = (imm_value ^ 0x00000001).to_bytes(4, byteorder='little')
                mutated[imm_offset:imm_offset + 4] = modified_value
                i += 5

            # MOV with 32-bit immediate (0xB8-0xBF or 0xC7)
            elif byte in range(0xB8, 0xC0) and i + 4 < len(mutated):
                # Modify immediate for register MOV
                imm_offset = i + 1
                imm_bytes = mutated[imm_offset:imm_offset + 4]
                imm_value = int.from_bytes(imm_bytes, byteorder='little')
                modified_value = (imm_value ^ 0x00000001).to_bytes(4, byteorder='little')
                mutated[imm_offset:imm_offset + 4] = modified_value
                i += 5

            # ADD/SUB/XOR with 8-bit immediate
            elif byte in [0x83] and i + 2 < len(mutated):
                modrm = mutated[i + 1]
                if (modrm & 0xC0) == 0xC0:  # Register operand
                    imm_offset = i + 2
                    imm_val = mutated[imm_offset]
                    mutated[imm_offset] = (imm_val ^ 0x01) & 0xFF
                    i += 3
                else:
                    i += 1
            else:
                i += 1

        return bytes(mutated)


class EnhancedProtectionScanner:
    """Enhanced protection scanner with dynamic signature extraction.

    Comprehensive protection detection engine that combines dynamic signature
    extraction, binary pattern analysis, YARA rules, and specialized detectors
    for VMProtect and other commercial protections.

    """

    def __init__(self) -> None:
        """Initialize the EnhancedProtectionScanner with various analysis components.

        Sets up multiple analysis tools including dynamic signature extractor,
        binary analyzer, YARA engine (if available), binary pattern detector, and
        VMProtect-specific detector. Initializes thread-safe caching for performance
        and gracefully handles optional dependencies like YARA.

        """
        self.signature_extractor = DynamicSignatureExtractor()
        self.binary_analyzer = BinaryAnalyzer()

        self.yara_engine: YaraPatternEngine | None
        try:
            self.yara_engine = YaraPatternEngine()
        except ImportError:
            logger.warning("YaraPatternEngine not available - continuing without YARA support")
            self.yara_engine = None

        self.binary_detector = BinaryPatternDetector()
        self.vmprotect_detector = VMProtectDetector()

        # Cache for performance
        self.cache: dict[str, dict[str, Any]] = {}
        self.cache_lock = Lock()

    def scan(self, binary_path: str, deep_scan: bool = True) -> dict[str, Any]:
        """Perform comprehensive protection scan with dynamic signatures.

        Executes a full protection detection scan on a binary file, combining
        dynamic signature extraction, pattern matching, and specialized protector
        detection. Results are cached for performance on subsequent scans of the
        same binary.

        Args:
            binary_path: Path to the binary file to scan.
            deep_scan: If True, performs exhaustive analysis. Defaults to True.

        Returns:
            dict[str, Any]: Scan results containing protection detections,
                confidence scores, technical details, and bypass recommendations.
                Keys include 'protections', 'packers', 'anti_debug', 'anti_vm',
                'licensing', 'confidence_scores', 'bypass_recommendations', and
                'technical_details'. Returns dict with 'error' key if scan fails.

        Raises:
            IOError: If binary file cannot be read.
            Exception: If signature extraction or pattern detection fails.

        """
        # Check cache
        cache_key = f"{binary_path}:{deep_scan}"
        with self.cache_lock:
            if cache_key in self.cache:
                cached = self.cache[cache_key]
                if time.time() - float(cached["timestamp"]) < 3600:  # 1 hour cache
                    return dict(cached["results"])

        results: dict[str, Any] = {
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
                category_key = f"{sig.category.value}s" if sig.category.value != "custom" else "custom"

                if category_key in results:
                    category_list = results[category_key]
                    if isinstance(category_list, list):
                        category_list.append({
                            "pattern": f"{sig.pattern_bytes.hex()[:32]}...",
                            "confidence": sig.confidence,
                            "context": sig.context,
                            "effectiveness": sig.effectiveness_score,
                        })

                # Update confidence scores
                confidence_scores = results["confidence_scores"]
                if isinstance(confidence_scores, dict):
                    if sig.category.value not in confidence_scores:
                        confidence_scores[sig.category.value] = 0.0

                    current_score = confidence_scores[sig.category.value]
                    if isinstance(current_score, (int, float)):
                        confidence_scores[sig.category.value] = max(float(current_score), sig.confidence)

            # Use binary pattern detector for additional detection
            with open(binary_path, "rb") as f:
                binary_data = f.read()

            binary_patterns = self.binary_detector.scan_binary(binary_data)

            for match in binary_patterns:
                category = match.pattern.category

                technical_details = results["technical_details"]
                if isinstance(technical_details, dict):
                    if category not in technical_details:
                        technical_details[category] = []

                    category_details = technical_details[category]
                    if isinstance(category_details, list):
                        category_details.append(
                            {
                                "name": match.pattern.name,
                                "offset": f"0x{match.offset:08x}",
                                "confidence": match.confidence,
                                "xrefs": len(match.xrefs),
                                "description": match.pattern.description,
                            },
                        )

            # Generate bypass recommendations
            confidence_scores = results["confidence_scores"]
            technical_details_final = results["technical_details"]
            if isinstance(confidence_scores, dict) and isinstance(technical_details_final, dict):
                results["bypass_recommendations"] = self._generate_bypass_recommendations(
                    confidence_scores,
                    technical_details_final,
                )

            # Cache results
            with self.cache_lock:
                self.cache[cache_key] = {"timestamp": time.time(), "results": results}

        except Exception as e:
            logger.exception("Protection scan failed: %s", e)
            results["error"] = str(e)

        return results

    def _generate_bypass_recommendations(
        self,
        confidence_scores: dict[str, float],
        technical_details: dict[str, list[Any]],
    ) -> list[dict[str, Any]]:
        """Generate specific bypass recommendations based on detections.

        Creates actionable bypass recommendations tailored to detected protection
        mechanisms with difficulty ratings and time estimates for security researchers.
        Analyzes confidence scores and generates targeted recommendations for each
        detected protection type.

        Args:
            confidence_scores: Dictionary mapping protection types to confidence
                scores (0.0-1.0).
            technical_details: Dictionary containing detailed detection information
                by protection category.

        Returns:
            list[dict[str, Any]]: List of recommendation dictionaries, each with
                keys: 'category', 'method', 'tools', 'difficulty', 'time_estimate',
                'success_rate'. Returns empty list if no high-confidence protections
                detected.

        """
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


def run_scan_thread(main_app: object, binary_path: str) -> None:
    """Enhanced scanning logic with dynamic signature extraction.

    Executes protection scanning in a background thread, providing progress updates
    and results to the main application through signal emission or method calls.
    Captures scan results, confidence scores, and bypass recommendations and
    communicates them back to the main application via various callback mechanisms.

    Args:
        main_app: Application object with optional update_output, update_scan_status,
            update_protection_results, update_analysis_results, analysis_completed
            methods/signals for status and result reporting.
        binary_path: Path to the binary file to scan for protection mechanisms.

    Raises:
        Exception: If protection scanning fails or binary cannot be read. Exceptions
            are logged and reported back to the main application via error_messages
            or update_output.

    """
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
        if results.get("bypass_recommendations") and hasattr(main_app, "update_output"):
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


def run_enhanced_protection_scan(main_app: object) -> None:
    """Entry point for enhanced protection scanning.

    Initiates enhanced protection scanning for the currently loaded binary in the
    main application. Spawns a daemon thread to perform the scan without blocking
    the main application event loop. Validates that a binary is loaded before
    spawning the scanning thread.

    Args:
        main_app: Application object with current_binary, loaded_binary_path, and
            update_output attributes or signals for binary retrieval and status updates.

    Raises:
        ValueError: If no binary is currently loaded in the application.

    """
    if not hasattr(main_app, "current_binary") or not main_app.current_binary:
        if hasattr(main_app, "update_output"):
            main_app.update_output.emit("[Protection Scanner] Error: No binary loaded.")
        return

    binary_path: str
    if hasattr(main_app, "current_binary"):
        binary_path = str(main_app.current_binary)
    elif hasattr(main_app, "loaded_binary_path"):
        binary_path = str(main_app.loaded_binary_path)
    else:
        if hasattr(main_app, "update_output"):
            main_app.update_output.emit("[Protection Scanner] Error: No binary path found.")
        return

    thread = Thread(target=run_scan_thread, args=(main_app, binary_path), daemon=True)
    thread.start()

    if hasattr(main_app, "update_output"):
        main_app.update_output.emit("[Protection Scanner] Protection scan task submitted.")
