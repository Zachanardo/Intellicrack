"""YARA Pattern Engine.

Advanced pattern matching engine for protection and license bypass detection using YARA rules.
Provides comprehensive pattern analysis for identifying protections, packers, and suspicious code.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import hashlib
import json
import os
import re
import struct
import tempfile
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, BinaryIO, Dict, List, Optional, Set, Tuple

import requests
from ...utils.logger import get_logger
from .binary_pattern_detector import BinaryPatternDetector, PatternMatchType, BinaryPattern, PatternMatch

logger = get_logger(__name__)

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logger.warning("YARA not available - pattern matching disabled")

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False
    logger.debug("pefile not available - PE analysis limited")

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False
    logger.debug("Capstone not available - disassembly limited")


class PatternCategory(Enum):
    """Categories of YARA pattern detection."""

    PROTECTION = "protection"
    PACKER = "packer"
    CRYPTOR = "cryptor"
    LICENSING = "licensing"
    ANTI_DEBUG = "anti_debug"
    ANTI_VM = "anti_vm"
    OBFUSCATION = "obfuscation"
    COMPILER = "compiler"
    SUSPICIOUS = "suspicious"
    LICENSE_BYPASS = "license_bypass"


@dataclass
class YaraMatch:
    """Single YARA rule match."""

    rule_name: str
    namespace: str
    tags: list[str]
    category: PatternCategory
    confidence: float
    offset: int
    length: int
    identifier: str
    string_data: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def severity(self) -> str:
        """Get severity based on category and confidence."""
        if self.category in [PatternCategory.LICENSE_BYPASS, PatternCategory.ANTI_DEBUG]:
            return "high" if self.confidence > 0.8 else "medium"
        if self.category in [PatternCategory.PROTECTION, PatternCategory.PACKER]:
            return "medium" if self.confidence > 0.7 else "low"
        return "low"


@dataclass
class YaraScanResult:
    """Complete YARA scan results."""

    file_path: str
    matches: list[YaraMatch] = field(default_factory=list)
    total_rules: int = 0
    scan_time: float = 0.0
    error: str | None = None

    @property
    def has_protections(self) -> bool:
        """Check if any protection patterns were found."""
        return any(m.category == PatternCategory.PROTECTION for m in self.matches)

    @property
    def has_packers(self) -> bool:
        """Check if any packer patterns were found."""
        return any(m.category == PatternCategory.PACKER for m in self.matches)

    @property
    def has_licensing(self) -> bool:
        """Check if any licensing patterns were found."""
        return any(m.category == PatternCategory.LICENSING for m in self.matches)

    @property
    def high_confidence_matches(self) -> list[YaraMatch]:
        """Get matches with high confidence (>0.8)."""
        return [m for m in self.matches if m.confidence > 0.8]

    def get_matches_by_category(self, category: PatternCategory) -> list[YaraMatch]:
        """Get all matches for a specific category."""
        return [m for m in self.matches if m.category == category]


class YaraPatternEngine:
    """Advanced YARA pattern matching engine for binary analysis.

    Provides comprehensive detection of protections, packers, licensing schemes,
    and other patterns relevant to security analysis. Integrates with ICP backend
    to provide supplemental pattern-based detection alongside ICP analysis.
    """

    def __init__(self, custom_rules_path: str | None = None, cloud_update_url: str | None = None):
        """Initialize YARA pattern engine with integrated binary pattern detection.

        Args:
            custom_rules_path: Optional path to custom YARA rules directory
            cloud_update_url: Optional URL for cloud-based rule updates

        """
        if not YARA_AVAILABLE:
            raise ImportError("yara-python package is required but not installed")

        self.custom_rules_path = custom_rules_path
        self.cloud_update_url = cloud_update_url or "https://intellicrack-rules.s3.amazonaws.com/rules"
        self.compiled_rules: yara.Rules | None = None
        self.rule_metadata: dict[str, dict[str, Any]] = {}
        self.scanned_files: set[str] = set()
        self.dynamic_rules_cache: Dict[str, str] = {}
        self.pattern_database: Dict[str, List[bytes]] = defaultdict(list)
        self.rule_effectiveness_scores: Dict[str, float] = {}
        self.sample_analysis_cache: Dict[str, Dict[str, Any]] = {}
        self.update_lock = threading.Lock()
        self.last_cloud_update: float = 0

        # Initialize integrated binary pattern detector
        self.binary_detector = BinaryPatternDetector()

        self._initialize_pattern_extractors()
        self._load_rules()

    def _initialize_pattern_extractors(self):
        """Initialize pattern extraction methods."""
        self.pattern_extractors = {
            'entropy': self._extract_entropy_patterns,
            'opcodes': self._extract_opcode_patterns,
            'strings': self._extract_string_patterns,
            'imports': self._extract_import_patterns,
            'sections': self._extract_section_patterns,
            'signatures': self._extract_signature_patterns,
            'byte_sequences': self._extract_byte_sequence_patterns,
        }

    def _load_rules(self):
        """Load and compile YARA rules."""
        try:
            # Get built-in rules directory
            rules_dir = Path(__file__).parent.parent.parent / "data" / "yara_rules"
            rules_dir.mkdir(parents=True, exist_ok=True)

            # Generate dynamic rules from analyzed samples
            self._generate_dynamic_rules(rules_dir)

            # Check for cloud updates
            if self._should_update_from_cloud():
                self._update_rules_from_cloud(rules_dir)

            # Collect all rule files
            rule_files = {}

            # Load generated dynamic rules
            for rule_file in rules_dir.glob("*.yar"):
                namespace = rule_file.stem
                rule_files[namespace] = str(rule_file)

            # Load custom rules if specified
            if self.custom_rules_path:
                custom_path = Path(self.custom_rules_path)
                if custom_path.exists():
                    for rule_file in custom_path.glob("*.yar"):
                        namespace = f"custom_{rule_file.stem}"
                        rule_files[namespace] = str(rule_file)

            if not rule_files:
                logger.warning("No YARA rules found - generating from samples")
                self._generate_dynamic_rules(rules_dir)
                rule_files = {rf.stem: str(rf) for rf in rules_dir.glob("*.yar")}

            # Compile rules with optimization
            self.compiled_rules = self._compile_optimized_rules(rule_files)
            self._extract_rule_metadata()

            logger.info(f"Loaded {len(rule_files)} YARA rule namespaces with {self._count_total_rules()} rules")

        except Exception as e:
            logger.error(f"Failed to load YARA rules: {e}")
            self.compiled_rules = None

    def _generate_dynamic_rules(self, rules_dir: Path):
        """Generate YARA rules dynamically from analyzed samples."""
        logger.info("Generating dynamic YARA rules from analyzed samples")

        # Scan sample directories for protected binaries
        samples_dir = Path(__file__).parent.parent.parent / "data" / "samples"
        if not samples_dir.exists():
            samples_dir.mkdir(parents=True, exist_ok=True)
            # Create initial patterns from known protections
            self._create_initial_protection_patterns(samples_dir)

        # Analyze samples and extract patterns
        protection_patterns = self._analyze_samples_for_patterns(samples_dir)

        # Generate rules for each protection category
        self._generate_protection_rules(rules_dir, protection_patterns)
        self._generate_packer_rules(rules_dir, protection_patterns)
        self._generate_licensing_rules(rules_dir, protection_patterns)
        self._generate_antidebug_rules(rules_dir, protection_patterns)
        self._generate_compiler_rules(rules_dir, protection_patterns)

    def _analyze_samples_for_patterns(self, samples_dir: Path) -> Dict[str, List[Dict[str, Any]]]:
        """Analyze sample binaries to extract protection patterns."""
        patterns = defaultdict(list)

        for sample_file in samples_dir.glob("**/*"):
            if not sample_file.is_file():
                continue

            try:
                # Check cache first
                cache_key = f"{sample_file}:{sample_file.stat().st_mtime}"
                if cache_key in self.sample_analysis_cache:
                    cached_patterns = self.sample_analysis_cache[cache_key]
                    for category, pattern_list in cached_patterns.items():
                        patterns[category].extend(pattern_list)
                    continue

                # Analyze new sample
                sample_patterns = self._extract_patterns_from_binary(sample_file)

                # Cache results
                self.sample_analysis_cache[cache_key] = sample_patterns

                # Merge patterns
                for category, pattern_list in sample_patterns.items():
                    patterns[category].extend(pattern_list)

            except Exception as e:
                logger.debug(f"Could not analyze {sample_file}: {e}")

        return patterns

    def _extract_patterns_from_binary(self, file_path: Path) -> Dict[str, List[Dict[str, Any]]]:
        """Extract various patterns from a binary file."""
        patterns = defaultdict(list)

        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            # Extract different types of patterns
            for extractor_name, extractor_func in self.pattern_extractors.items():
                try:
                    extracted = extractor_func(data, file_path)
                    if extracted:
                        patterns[extractor_name].extend(extracted)
                except Exception as e:
                    logger.debug(f"Pattern extractor {extractor_name} failed: {e}")

        except Exception as e:
            logger.debug(f"Could not read {file_path}: {e}")

        return patterns

    def _extract_entropy_patterns(self, data: bytes, file_path: Path) -> List[Dict[str, Any]]:
        """Extract high-entropy regions that may indicate encryption/packing."""
        patterns = []
        window_size = 256
        threshold = 7.0

        for i in range(0, len(data) - window_size, window_size // 2):
            window = data[i:i + window_size]
            entropy = self._calculate_entropy(window)

            if entropy > threshold:
                # Extract surrounding bytes as pattern
                pattern_start = max(0, i - 16)
                pattern_end = min(len(data), i + window_size + 16)
                pattern_bytes = data[pattern_start:pattern_end]

                patterns.append({
                    'type': 'high_entropy',
                    'offset': i,
                    'entropy': entropy,
                    'bytes': pattern_bytes[:64],  # Limit pattern size
                    'confidence': min(1.0, entropy / 8.0)
                })

        return patterns

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0

        counts = defaultdict(int)
        for byte in data:
            counts[byte] += 1

        entropy = 0.0
        total = len(data)

        for count in counts.values():
            if count > 0:
                probability = count / total
                entropy -= probability * (probability and probability * (1.0 / probability).bit_length())

        return entropy

    def _extract_opcode_patterns(self, data: bytes, file_path: Path) -> List[Dict[str, Any]]:
        """Extract opcode sequences that indicate specific protections."""
        patterns = []

        if not CAPSTONE_AVAILABLE:
            return patterns

        # Detect architecture
        is_64bit = self._detect_architecture(data)
        mode = CS_MODE_64 if is_64bit else CS_MODE_32

        try:
            cs = Cs(CS_ARCH_X86, mode)

            # Find code sections
            code_sections = self._find_code_sections(data)

            for section_start, section_data in code_sections:
                # Disassemble and look for protection patterns
                opcode_sequences = []

                for insn in cs.disasm(section_data, section_start):
                    opcode_sequences.append(insn.bytes)

                    # Check for anti-debug patterns
                    if insn.mnemonic in ['int', 'int3', 'rdtsc', 'cpuid']:
                        patterns.append({
                            'type': 'anti_debug_opcode',
                            'mnemonic': insn.mnemonic,
                            'bytes': insn.bytes,
                            'offset': insn.address,
                            'confidence': 0.8
                        })

                    # Check for VM detection patterns
                    if insn.mnemonic == 'cpuid' or (insn.mnemonic == 'mov' and 'gs:' in insn.op_str):
                        patterns.append({
                            'type': 'anti_vm_opcode',
                            'mnemonic': insn.mnemonic,
                            'bytes': insn.bytes,
                            'offset': insn.address,
                            'confidence': 0.7
                        })

                # Look for obfuscated patterns
                if len(opcode_sequences) > 10:
                    self._detect_obfuscation_patterns(opcode_sequences, patterns, section_start)

        except Exception as e:
            logger.debug(f"Opcode extraction failed: {e}")

        return patterns

    def _detect_architecture(self, data: bytes) -> bool:
        """Detect if binary is 64-bit."""
        if len(data) < 0x40:
            return False

        # Check PE header
        if data[:2] == b'MZ':
            try:
                pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
                if len(data) > pe_offset + 6:
                    machine = struct.unpack('<H', data[pe_offset + 4:pe_offset + 6])[0]
                    return machine == 0x8664  # AMD64
            except:
                pass

        return False

    def _find_code_sections(self, data: bytes) -> List[Tuple[int, bytes]]:
        """Find executable code sections in binary."""
        sections = []

        if PEFILE_AVAILABLE and data[:2] == b'MZ':
            try:
                pe = pefile.PE(data=data)
                for section in pe.sections:
                    if section.IMAGE_SCN_MEM_EXECUTE:
                        sections.append((section.VirtualAddress, section.get_data()))
            except:
                # Fallback to heuristic detection
                pass

        if not sections:
            # Heuristic: look for common code patterns
            for i in range(0, len(data) - 0x1000, 0x100):
                chunk = data[i:i + 0x1000]
                # Check for common x86 prologue
                if chunk[:3] in [b'\x55\x89\xe5', b'\x55\x48\x89', b'\x48\x89\x5c']:
                    sections.append((i, chunk))

        return sections

    def _detect_obfuscation_patterns(self, sequences: List[bytes], patterns: List[Dict], offset: int):
        """Detect obfuscation patterns in opcode sequences."""
        # Check for excessive jumps
        jump_opcodes = [b'\xe9', b'\xeb', b'\x0f\x84', b'\x0f\x85']
        jump_count = sum(1 for seq in sequences if any(seq.startswith(jmp) for jmp in jump_opcodes))

        if jump_count > len(sequences) * 0.3:
            patterns.append({
                'type': 'obfuscation',
                'subtype': 'excessive_jumps',
                'ratio': jump_count / len(sequences),
                'offset': offset,
                'confidence': 0.75
            })

        # Check for dead code patterns
        nop_count = sum(1 for seq in sequences if seq == b'\x90')
        if nop_count > len(sequences) * 0.2:
            patterns.append({
                'type': 'obfuscation',
                'subtype': 'dead_code',
                'ratio': nop_count / len(sequences),
                'offset': offset,
                'confidence': 0.7
            })

    def _extract_string_patterns(self, data: bytes, file_path: Path) -> List[Dict[str, Any]]:
        """Extract string patterns indicating protections."""
        patterns = []

        # Protection-related strings
        protection_indicators = [
            (b'VMProtect', 'vmprotect', 0.9),
            (b'Themida', 'themida', 0.9),
            (b'WinLicense', 'winlicense', 0.9),
            (b'Enigma', 'enigma', 0.8),
            (b'ASProtect', 'asprotect', 0.8),
            (b'Armadillo', 'armadillo', 0.8),
            (b'SecuROM', 'securom', 0.85),
            (b'SafeDisc', 'safedisc', 0.85),
            (b'StarForce', 'starforce', 0.85),
            (b'Denuvo', 'denuvo', 0.95),
        ]

        for indicator, name, confidence in protection_indicators:
            positions = self._find_all_occurrences(data, indicator)
            for pos in positions:
                patterns.append({
                    'type': 'protection_string',
                    'name': name,
                    'string': indicator,
                    'offset': pos,
                    'confidence': confidence
                })

        # Licensing strings
        licensing_indicators = [
            (b'license', 'license_check', 0.6),
            (b'serial', 'serial_check', 0.6),
            (b'activation', 'activation_check', 0.7),
            (b'trial', 'trial_check', 0.6),
            (b'expired', 'expiration_check', 0.6),
            (b'FlexLM', 'flexlm', 0.9),
            (b'HASP', 'hasp', 0.85),
            (b'Sentinel', 'sentinel', 0.85),
            (b'CodeMeter', 'codemeter', 0.85),
        ]

        for indicator, name, confidence in licensing_indicators:
            positions = self._find_all_occurrences(data, indicator, case_insensitive=True)
            for pos in positions:
                patterns.append({
                    'type': 'licensing_string',
                    'name': name,
                    'string': indicator,
                    'offset': pos,
                    'confidence': confidence
                })

        return patterns

    def _find_all_occurrences(self, data: bytes, pattern: bytes, case_insensitive: bool = False) -> List[int]:
        """Find all occurrences of a pattern in data."""
        positions = []
        search_data = data.lower() if case_insensitive else data
        search_pattern = pattern.lower() if case_insensitive else pattern

        start = 0
        while True:
            pos = search_data.find(search_pattern, start)
            if pos == -1:
                break
            positions.append(pos)
            start = pos + 1

        return positions

    def _extract_import_patterns(self, data: bytes, file_path: Path) -> List[Dict[str, Any]]:
        """Extract import table patterns."""
        patterns = []

        if PEFILE_AVAILABLE and data[:2] == b'MZ':
            try:
                pe = pefile.PE(data=data)

                # Anti-debug imports
                antidebug_apis = [
                    'IsDebuggerPresent',
                    'CheckRemoteDebuggerPresent',
                    'NtQueryInformationProcess',
                    'OutputDebugStringA',
                    'GetTickCount',
                    'QueryPerformanceCounter',
                ]

                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            imp_name = imp.name.decode('utf-8', errors='ignore')

                            if imp_name in antidebug_apis:
                                patterns.append({
                                    'type': 'antidebug_import',
                                    'api': imp_name,
                                    'dll': entry.dll.decode('utf-8', errors='ignore'),
                                    'confidence': 0.8
                                })

            except Exception as e:
                logger.debug(f"Import extraction failed: {e}")

        return patterns

    def _extract_section_patterns(self, data: bytes, file_path: Path) -> List[Dict[str, Any]]:
        """Extract section header patterns."""
        patterns = []

        if PEFILE_AVAILABLE and data[:2] == b'MZ':
            try:
                pe = pefile.PE(data=data)

                # Known protection section names
                protection_sections = [
                    ('.vmp', 'vmprotect', 0.95),
                    ('.themida', 'themida', 0.95),
                    ('.enigma', 'enigma', 0.9),
                    ('.aspack', 'aspack', 0.9),
                    ('.upx', 'upx', 0.95),
                    ('.mpress', 'mpress', 0.9),
                    ('.nsp', 'nspack', 0.85),
                ]

                for section in pe.sections:
                    section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')

                    for pattern, name, confidence in protection_sections:
                        if section_name.lower().startswith(pattern):
                            patterns.append({
                                'type': 'protection_section',
                                'section': section_name,
                                'protection': name,
                                'confidence': confidence
                            })

                    # Check for high entropy sections
                    entropy = section.get_entropy()
                    if entropy > 7.0:
                        patterns.append({
                            'type': 'packed_section',
                            'section': section_name,
                            'entropy': entropy,
                            'confidence': min(1.0, entropy / 8.0)
                        })

            except Exception as e:
                logger.debug(f"Section extraction failed: {e}")

        return patterns

    def _extract_signature_patterns(self, data: bytes, file_path: Path) -> List[Dict[str, Any]]:
        """Extract known signature patterns."""
        patterns = []

        # Known packer/protector signatures
        signatures = [
            # UPX
            (b'UPX!', 'upx', 0.95),
            (b'UPX0', 'upx', 0.95),
            (b'UPX1', 'upx', 0.95),
            # ASPack
            (b'\x60\xe8\x03\x00\x00\x00\xe9\xeb\x04\x5d\x45\x55\xc3\xe8\x01', 'aspack', 0.9),
            # PECompact
            (b'PECompact2', 'pecompact', 0.9),
            # VMProtect markers
            (b'.vmp0', 'vmprotect', 0.95),
            (b'.vmp1', 'vmprotect', 0.95),
            # Themida
            (b'\x8b\x85[\x00-\xff]{4}\x03\x85[\x00-\xff]{4}\x89\x85', 'themida', 0.8),
        ]

        for signature, name, confidence in signatures:
            if b'[' in signature:  # Regex pattern
                import re
                regex = signature.replace(b'[\x00-\xff]', b'.')
                matches = re.finditer(regex, data)
                for match in matches:
                    patterns.append({
                        'type': 'signature',
                        'name': name,
                        'offset': match.start(),
                        'bytes': match.group(),
                        'confidence': confidence
                    })
            else:
                positions = self._find_all_occurrences(data, signature)
                for pos in positions:
                    patterns.append({
                        'type': 'signature',
                        'name': name,
                        'offset': pos,
                        'bytes': signature,
                        'confidence': confidence
                    })

        return patterns

    def _extract_byte_sequence_patterns(self, data: bytes, file_path: Path) -> List[Dict[str, Any]]:
        """Extract interesting byte sequence patterns."""
        patterns = []

        # Common protection/packing patterns
        byte_patterns = [
            # INT3 padding (anti-debug)
            (b'\xcc' * 16, 'int3_padding', 0.7),
            # NOP slides
            (b'\x90' * 32, 'nop_slide', 0.6),
        ]

        regex_patterns = [
            (rb'\x68[\x00-\xFF]{4}\xE8[\x00-\xFF]{4}\x83\xC4\x04', 'vm_entry', 0.75),
            (rb'\x65\x8B\x00\x8B\x40[\x00-\xFF]\x8A\x40\x02', 'peb_debug_flag', 0.85),
            (rb'\x64\xA1\x00\x00\x00\x00\x50\x64\x89\x25', 'seh_manipulation', 0.8),
            (rb'\x0F\xA2', 'cpuid_check', 0.7),
            (rb'\x0F\x31', 'rdtsc_timing', 0.75),
            (rb'\x56\x4D\x50[\x00-\xFF]{2}', 'vmp_mutation', 0.85),
            (rb'\xFF\x25[\x00-\xFF]{4}', 'api_redirection', 0.65),
            (rb'\x80\x3D[\x00-\xFF]{4}\xCC', 'breakpoint_scan', 0.8),
            (rb'\x64\xA1\x30\x00\x00\x00\x0F\xB6\x40\x02', 'inline_debugcheck', 0.9),
            (rb'\x64\x8B\x35\x30\x00\x00\x00\x8B\x76\x68', 'globalflag_check', 0.85),
        ]

        pattern_descriptions = {
            'vm_entry': 'Virtual machine entry point sequence detection',
            'peb_debug_flag': 'Process Environment Block BeingDebugged flag access',
            'seh_manipulation': 'Structured Exception Handler chain manipulation',
            'cpuid_check': 'CPUID instruction for virtualization detection',
            'rdtsc_timing': 'RDTSC instruction for timing-based anti-debugging',
            'vmp_mutation': 'VMProtect mutation engine signature',
            'api_redirection': 'API redirection jump pattern',
            'breakpoint_scan': 'Software breakpoint scanning pattern',
            'inline_debugcheck': 'Inline IsDebuggerPresent check',
            'globalflag_check': 'NtGlobalFlag debugging check',
        }

        # Static byte patterns
        for pattern, name, confidence in byte_patterns:
            positions = self._find_all_occurrences(data, pattern)
            for pos in positions:
                patterns.append({
                    'type': 'byte_pattern',
                    'name': name,
                    'offset': pos,
                    'bytes': pattern,
                    'confidence': confidence
                })

        # PEB access pattern (static)
        peb_pattern = b'\x64\x8b\x30\x8b\x76\x0c\x8b\x76\x1c'
        positions = self._find_all_occurrences(data, peb_pattern)
        for pos in positions:
            patterns.append({
                'type': 'byte_pattern',
                'name': 'peb_access',
                'offset': pos,
                'bytes': peb_pattern,
                'confidence': 0.8
            })

        # Process regex patterns
        for regex_pattern, name, confidence in regex_patterns:
            try:
                matches = re.finditer(regex_pattern, data, re.DOTALL)
                for match in matches:
                    patterns.append({
                        'type': 'byte_pattern',
                        'name': name,
                        'offset': match.start(),
                        'bytes': match.group(),
                        'confidence': confidence,
                        'description': pattern_descriptions.get(name, '')
                    })
            except Exception as e:
                logger.debug(f"Regex pattern {name} failed: {e}")

        return patterns

    def _create_initial_protection_patterns(self, samples_dir: Path):
        """Create initial protection patterns for bootstrapping."""
        # Create sample protection indicators
        initial_patterns = {
            'vmprotect': b'\x56\x4d\x50\x72\x6f\x74\x65\x63\x74',  # "VMProtect"
            'themida': b'\x54\x68\x65\x6d\x69\x64\x61',  # "Themida"
            'upx': b'\x55\x50\x58\x21',  # "UPX!"
            'aspack': b'\x41\x53\x50\x61\x63\x6b',  # "ASPack"
        }

        patterns_file = samples_dir / 'initial_patterns.json'
        with open(patterns_file, 'w') as f:
            json.dump(initial_patterns, f, indent=2, default=lambda x: x.hex() if isinstance(x, bytes) else x)

    def _generate_protection_rules(self, rules_dir: Path, patterns: Dict[str, List[Dict[str, Any]]]):
        """Generate YARA rules for protection detection."""
        rules = []

        # Group patterns by protection type
        protection_groups = defaultdict(list)

        for category, pattern_list in patterns.items():
            for pattern in pattern_list:
                if pattern.get('type') in ['protection_string', 'protection_section', 'signature']:
                    name = pattern.get('name') or pattern.get('protection') or 'unknown'
                    protection_groups[name].append(pattern)

        # Generate rule for each protection
        for protection_name, protection_patterns in protection_groups.items():
            rule = self._build_yara_rule(
                name=f"{protection_name}_detection",
                category="protection",
                patterns=protection_patterns,
                description=f"Detects {protection_name} protection"
            )
            rules.append(rule)

        # Combine and optimize rules
        optimized_rules = self._optimize_rules(rules)

        # Write to file
        rules_content = "\n\n".join(optimized_rules)
        (rules_dir / "protections_dynamic.yar").write_text(rules_content)

    def _generate_packer_rules(self, rules_dir: Path, patterns: Dict[str, List[Dict[str, Any]]]):
        """Generate YARA rules for packer detection."""
        rules = []

        # Extract packer-specific patterns
        packer_patterns = defaultdict(list)

        for category, pattern_list in patterns.items():
            for pattern in pattern_list:
                if pattern.get('type') in ['packed_section', 'high_entropy']:
                    packer_patterns['generic_packer'].append(pattern)
                elif 'pack' in str(pattern.get('name', '')).lower():
                    name = pattern.get('name')
                    packer_patterns[name].append(pattern)

        # Generate rules
        for packer_name, patterns_list in packer_patterns.items():
            rule = self._build_yara_rule(
                name=f"{packer_name}_packer",
                category="packer",
                patterns=patterns_list,
                description=f"Detects {packer_name} packer"
            )
            rules.append(rule)

        # Write to file
        if rules:
            rules_content = "\n\n".join(self._optimize_rules(rules))
            (rules_dir / "packers_dynamic.yar").write_text(rules_content)

    def _generate_licensing_rules(self, rules_dir: Path, patterns: Dict[str, List[Dict[str, Any]]]):
        """Generate YARA rules for licensing detection."""
        rules = []

        # Extract licensing patterns
        licensing_patterns = defaultdict(list)

        for category, pattern_list in patterns.items():
            for pattern in pattern_list:
                if pattern.get('type') == 'licensing_string':
                    name = pattern.get('name', 'generic_license')
                    licensing_patterns[name].append(pattern)

        # Generate rules
        for license_type, patterns_list in licensing_patterns.items():
            rule = self._build_yara_rule(
                name=f"{license_type}_licensing",
                category="licensing",
                patterns=patterns_list,
                description=f"Detects {license_type} licensing"
            )
            rules.append(rule)

        # Write to file
        if rules:
            rules_content = "\n\n".join(self._optimize_rules(rules))
            (rules_dir / "licensing_dynamic.yar").write_text(rules_content)

    def _generate_antidebug_rules(self, rules_dir: Path, patterns: Dict[str, List[Dict[str, Any]]]):
        """Generate YARA rules for anti-debug detection."""
        rules = []

        # Extract anti-debug patterns
        antidebug_patterns = []

        for category, pattern_list in patterns.items():
            for pattern in pattern_list:
                if 'debug' in pattern.get('type', '').lower() or 'debug' in pattern.get('name', '').lower():
                    antidebug_patterns.append(pattern)

        if antidebug_patterns:
            rule = self._build_yara_rule(
                name="anti_debug_techniques",
                category="anti_debug",
                patterns=antidebug_patterns,
                description="Detects anti-debugging techniques"
            )
            rules.append(rule)

        # Anti-VM patterns
        antivm_patterns = []
        for category, pattern_list in patterns.items():
            for pattern in pattern_list:
                if 'vm' in pattern.get('type', '').lower():
                    antivm_patterns.append(pattern)

        if antivm_patterns:
            rule = self._build_yara_rule(
                name="anti_vm_techniques",
                category="anti_vm",
                patterns=antivm_patterns,
                description="Detects anti-VM techniques"
            )
            rules.append(rule)

        # Write to file
        if rules:
            rules_content = "\n\n".join(self._optimize_rules(rules))
            (rules_dir / "antidebug_dynamic.yar").write_text(rules_content)

    def _generate_compiler_rules(self, rules_dir: Path, patterns: Dict[str, List[Dict[str, Any]]]):
        """Generate YARA rules for compiler detection."""
        rules = []

        # Compiler signatures from binary analysis
        compiler_signatures = {
            'msvc': ['MSVCR', '.rdata$zzz', 'Microsoft (R)', '__CxxFrameHandler'],
            'gcc': ['GCC:', '__gmon_start__', '.eh_frame', '__libc_start_main'],
            'delphi': ['Borland', '@AbstractError', 'Controls.TControl', 'System.@'],
            'mingw': ['MinGW', '__mingw', '.CRT$', '__dllonexit'],
            'clang': ['clang version', '__clang', 'LLVM'],
            'golang': ['runtime.goexit', 'runtime.main', 'go.buildid'],
            'rust': ['rust_panic', 'rust_begin_unwind', '.rustc'],
        }

        # Check for compiler patterns in strings
        for category, pattern_list in patterns.items():
            if category == 'strings':
                for pattern in pattern_list:
                    string_data = pattern.get('string', b'').decode('utf-8', errors='ignore')
                    for compiler, signatures in compiler_signatures.items():
                        if any(sig.lower() in string_data.lower() for sig in signatures):
                            rules.append(self._build_yara_rule(
                                name=f"{compiler}_compiler_detection",
                                category="compiler",
                                patterns=[pattern],
                                description=f"Detects {compiler.upper()} compiler"
                            ))

        # Write to file
        if rules:
            rules_content = "\n\n".join(self._optimize_rules(rules))
            (rules_dir / "compilers_dynamic.yar").write_text(rules_content)

    def _build_yara_rule(self, name: str, category: str, patterns: List[Dict[str, Any]],
                        description: str) -> str:
        """Build a YARA rule from extracted patterns."""
        rule_parts = []
        rule_parts.append(f"rule {name}")
        rule_parts.append("{")

        # Add metadata
        rule_parts.append("    meta:")
        rule_parts.append(f'        category = "{category}"')
        rule_parts.append(f'        description = "{description}"')

        # Calculate average confidence
        confidences = [p.get('confidence', 0.5) for p in patterns]
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0.5
        rule_parts.append(f'        confidence = {avg_confidence:.2f}')
        rule_parts.append(f'        generated = "dynamic"')
        rule_parts.append(f'        pattern_count = {len(patterns)}')

        # Add strings section
        rule_parts.append("")
        rule_parts.append("    strings:")

        string_identifiers = []
        for i, pattern in enumerate(patterns):
            pattern_type = pattern.get('type')
            pattern_bytes = pattern.get('bytes')
            pattern_string = pattern.get('string')

            if pattern_bytes:
                # Convert bytes to hex string
                if isinstance(pattern_bytes, bytes):
                    hex_pattern = ' '.join(f'{b:02x}' for b in pattern_bytes[:32])  # Limit size
                    rule_parts.append(f"        $pattern_{i} = {{ {hex_pattern} }}")
                    string_identifiers.append(f"$pattern_{i}")
            elif pattern_string:
                # Add string pattern
                if isinstance(pattern_string, bytes):
                    string_val = pattern_string.decode('utf-8', errors='ignore')
                else:
                    string_val = pattern_string
                # Escape special characters
                string_val = string_val.replace('"', '\\"').replace('\\', '\\\\')
                rule_parts.append(f'        $string_{i} = "{string_val}" ascii nocase')
                string_identifiers.append(f"$string_{i}")

            # Add specific patterns based on type
            if pattern_type == 'anti_debug_opcode':
                mnemonic = pattern.get('mnemonic', '')
                if mnemonic == 'int3':
                    rule_parts.append(f"        $int3_{i} = {{ cc }}")
                    string_identifiers.append(f"$int3_{i}")
                elif mnemonic == 'rdtsc':
                    rule_parts.append(f"        $rdtsc_{i} = {{ 0f 31 }}")
                    string_identifiers.append(f"$rdtsc_{i}")

        # Add condition
        rule_parts.append("")
        rule_parts.append("    condition:")

        if len(string_identifiers) == 1:
            rule_parts.append(f"        {string_identifiers[0]}")
        elif len(string_identifiers) > 1:
            # Use different conditions based on pattern count and confidence
            if avg_confidence > 0.8 and len(string_identifiers) > 3:
                rule_parts.append(f"        {len(string_identifiers) // 2} of them")
            elif avg_confidence > 0.6:
                rule_parts.append("        any of them")
            else:
                rule_parts.append(f"        2 of ({', '.join(string_identifiers)})")
        else:
            # Fallback condition for rules without patterns
            rule_parts.append("        false")

        rule_parts.append("}")

        return "\n".join(rule_parts)

    def _optimize_rules(self, rules: List[str]) -> List[str]:
        """Optimize and merge similar YARA rules."""
        optimized = []
        rule_signatures = {}

        for rule in rules:
            # Extract rule components for comparison
            lines = rule.split('\n')
            rule_name = lines[0].replace('rule ', '').strip()

            # Extract strings section
            strings_section = []
            in_strings = False
            for line in lines:
                if 'strings:' in line:
                    in_strings = True
                elif 'condition:' in line:
                    in_strings = False
                elif in_strings and line.strip():
                    strings_section.append(line.strip())

            # Create signature for deduplication
            signature = '|'.join(sorted(strings_section))

            if signature not in rule_signatures:
                rule_signatures[signature] = rule
                optimized.append(rule)
            else:
                # Merge rules with same signatures
                existing_rule = rule_signatures[signature]
                merged_rule = self._merge_similar_rules(existing_rule, rule)
                index = optimized.index(existing_rule)
                optimized[index] = merged_rule
                rule_signatures[signature] = merged_rule

        return optimized

    def _merge_similar_rules(self, rule1: str, rule2: str) -> str:
        """Merge two similar YARA rules."""
        # Extract rule names
        name1 = rule1.split('\n')[0].replace('rule ', '').strip()
        name2 = rule2.split('\n')[0].replace('rule ', '').strip()

        # Create merged name
        merged_name = f"{name1}_and_{name2}" if name1 != name2 else name1

        # Use the first rule as base and update the name
        merged_lines = rule1.split('\n')
        merged_lines[0] = f"rule {merged_name}"

        return "\n".join(merged_lines)

    def _compile_optimized_rules(self, rule_files: Dict[str, str]) -> Optional[yara.Rules]:
        """Compile YARA rules with optimization."""
        try:
            # First attempt: compile all rules together
            compiled = yara.compile(filepaths=rule_files)

            # Validate compilation with actual PE header structure
            dos_header = b'MZ' + b'\x90\x00' * 29
            pe_sig_offset = struct.pack('<I', 0x80)
            dos_program = b'\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21'
            dos_program += b'This program cannot be run in DOS mode.\r\r\n$\x00\x00\x00'
            padding = b'\x00' * (0x80 - len(dos_header) - 4 - len(dos_program))
            pe_header = b'PE\x00\x00'
            machine = struct.pack('<H', 0x014c)
            sections = struct.pack('<H', 1)
            timestamp = struct.pack('<I', int(time.time()))
            optional_header_size = struct.pack('<H', 0xe0)
            characteristics = struct.pack('<H', 0x0102)

            test_data = dos_header + pe_sig_offset + dos_program + padding + pe_header
            test_data += machine + sections + timestamp + b'\x00' * 8
            test_data += optional_header_size + characteristics
            test_data += b'\x00' * (0x200 - len(test_data))

            # Validate rules can process real PE structure
            compiled.match(data=test_data, timeout=1)

            return compiled

        except yara.SyntaxError as e:
            logger.warning(f"YARA syntax error, attempting to fix: {e}")

            # Attempt to fix common syntax errors
            fixed_files = {}
            for namespace, filepath in rule_files.items():
                try:
                    with open(filepath, 'r') as f:
                        content = f.read()

                    # Fix common issues
                    content = self._fix_yara_syntax(content)

                    # Write fixed content
                    fixed_path = filepath.replace('.yar', '_fixed.yar')
                    with open(fixed_path, 'w') as f:
                        f.write(content)

                    fixed_files[namespace] = fixed_path
                except Exception as fix_error:
                    logger.debug(f"Could not fix {filepath}: {fix_error}")

            if fixed_files:
                try:
                    return yara.compile(filepaths=fixed_files)
                except:
                    pass

        except Exception as e:
            logger.error(f"Failed to compile YARA rules: {e}")

        return None

    def _fix_yara_syntax(self, content: str) -> str:
        """Fix common YARA syntax issues."""
        lines = content.split('\n')
        fixed_lines = []

        for line in lines:
            # Fix hex string formatting
            if '{ ' in line and ' }' in line:
                # Ensure proper spacing in hex patterns
                line = re.sub(r'\{\s*([0-9a-fA-F\s]+)\s*\}',
                            lambda m: '{ ' + ' '.join(m.group(1).split()) + ' }', line)

            # Fix string escaping
            if '= "' in line:
                # Properly escape backslashes and quotes
                parts = line.split('= "', 1)
                if len(parts) == 2 and '"' in parts[1]:
                    string_part = parts[1].rsplit('"', 1)[0]
                    string_part = string_part.replace('\\', '\\\\').replace('\"', '\\"')
                    line = parts[0] + '= "' + string_part + '"' + parts[1].rsplit('"', 1)[1]

            fixed_lines.append(line)

        return '\n'.join(fixed_lines)

    def _should_update_from_cloud(self) -> bool:
        """Check if cloud rule update is needed."""
        if not self.cloud_update_url:
            return False

        # Update every 24 hours
        current_time = time.time()
        if current_time - self.last_cloud_update < 86400:
            return False

        return True

    def _update_rules_from_cloud(self, rules_dir: Path):
        """Download and update rules from cloud repository."""
        with self.update_lock:
            try:
                logger.info("Checking for cloud rule updates")

                # Download rule manifest
                manifest_url = f"{self.cloud_update_url}/manifest.json"
                response = requests.get(manifest_url, timeout=10)

                if response.status_code == 200:
                    manifest = response.json()

                    for rule_info in manifest.get('rules', []):
                        rule_name = rule_info['name']
                        rule_version = rule_info['version']
                        rule_url = rule_info['url']

                        # Check if update needed
                        local_rule_path = rules_dir / f"{rule_name}.yar"

                        if self._needs_rule_update(local_rule_path, rule_version):
                            self._download_rule(rule_url, local_rule_path)
                            logger.info(f"Updated rule: {rule_name} to version {rule_version}")

                    self.last_cloud_update = time.time()

            except requests.RequestException as e:
                logger.debug(f"Cloud update failed: {e}")
            except Exception as e:
                logger.error(f"Unexpected error during cloud update: {e}")

    def _needs_rule_update(self, local_path: Path, cloud_version: str) -> bool:
        """Check if a rule needs updating."""
        if not local_path.exists():
            return True

        # Check version in rule metadata
        try:
            with open(local_path, 'r') as f:
                content = f.read()
                if f'version = "{cloud_version}"' not in content:
                    return True
        except:
            return True

        return False

    def _download_rule(self, url: str, destination: Path):
        """Download a rule file from URL."""
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                destination.write_bytes(response.content)
        except Exception as e:
            logger.error(f"Failed to download rule from {url}: {e}")

    def analyze_and_generate_rule(self, sample_path: str) -> Optional[str]:
        """Analyze a sample and generate a custom YARA rule."""
        try:
            with open(sample_path, 'rb') as f:
                data = f.read()

            # Extract patterns
            patterns = self._extract_patterns_from_binary(Path(sample_path))

            # Find most distinctive patterns
            distinctive_patterns = self._find_distinctive_patterns(patterns)

            if not distinctive_patterns:
                logger.warning("No distinctive patterns found for rule generation")
                return None

            # Generate rule name from file
            rule_name = Path(sample_path).stem.replace('.', '_').replace('-', '_')
            rule_name = f"custom_{rule_name}_{int(time.time())}"

            # Build rule
            rule = self._build_yara_rule(
                name=rule_name,
                category="custom",
                patterns=distinctive_patterns,
                description=f"Custom rule for {Path(sample_path).name}"
            )

            # Validate rule
            try:
                yara.compile(source=rule)
                return rule
            except yara.SyntaxError as e:
                logger.error(f"Generated rule has syntax error: {e}")
                # Attempt to fix and return
                fixed_rule = self._fix_yara_syntax(rule)
                yara.compile(source=fixed_rule)  # Validate again
                return fixed_rule

        except Exception as e:
            logger.error(f"Failed to generate rule for {sample_path}: {e}")
            return None

    def _find_distinctive_patterns(self, patterns: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """Find the most distinctive patterns from extracted patterns."""
        distinctive = []

        # Score patterns by distinctiveness
        scored_patterns = []

        for category, pattern_list in patterns.items():
            for pattern in pattern_list:
                score = 0

                # High-value pattern types
                if pattern.get('type') in ['protection_string', 'signature', 'protection_section']:
                    score += 10

                # Confidence contributes to score
                score += pattern.get('confidence', 0.5) * 5

                # Longer patterns are more distinctive
                if pattern.get('bytes'):
                    score += min(len(pattern['bytes']) / 10, 5)

                # Anti-analysis patterns are valuable
                if 'anti' in pattern.get('type', '').lower():
                    score += 3

                scored_patterns.append((score, pattern))

        # Sort by score and take top patterns
        scored_patterns.sort(key=lambda x: x[0], reverse=True)

        # Take top 10 patterns
        for score, pattern in scored_patterns[:10]:
            if score > 3:  # Minimum score threshold
                distinctive.append(pattern)

        return distinctive

    def update_rule_effectiveness(self, rule_name: str, success: bool):
        """Update effectiveness score for a rule based on results."""
        if rule_name not in self.rule_effectiveness_scores:
            self.rule_effectiveness_scores[rule_name] = 0.5

        # Update score using exponential moving average
        alpha = 0.1  # Learning rate
        current_score = self.rule_effectiveness_scores[rule_name]

        if success:
            self.rule_effectiveness_scores[rule_name] = current_score + alpha * (1.0 - current_score)
        else:
            self.rule_effectiveness_scores[rule_name] = current_score + alpha * (0.0 - current_score)

        # Persist effectiveness scores
        scores_file = Path(__file__).parent.parent.parent / "data" / "rule_effectiveness.json"
        try:
            with open(scores_file, 'w') as f:
                json.dump(self.rule_effectiveness_scores, f, indent=2)
        except Exception as e:
            logger.debug(f"Could not save effectiveness scores: {e}")

    def _create_default_rules(self, rules_dir: Path):
        """Create default rules as fallback."""
        # This method is now replaced by _generate_dynamic_rules
        # but kept for backward compatibility
        self._generate_dynamic_rules(rules_dir)

    def generate_semantic_patterns(self, binary_data: bytes) -> Dict[str, Any]:
        """Generate semantic patterns from binary for advanced detection."""
        semantic_patterns = {
            'control_flow': [],
            'data_flow': [],
            'behavioral': [],
            'polymorphic': []
        }

        # Extract control flow patterns
        cf_patterns = self._extract_control_flow_patterns(binary_data)
        semantic_patterns['control_flow'].extend(cf_patterns)

        # Extract data flow patterns
        df_patterns = self._extract_data_flow_patterns(binary_data)
        semantic_patterns['data_flow'].extend(df_patterns)

        # Extract behavioral patterns
        behavioral = self._extract_behavioral_patterns(binary_data)
        semantic_patterns['behavioral'].extend(behavioral)

        # Detect polymorphic code patterns
        polymorphic = self._detect_polymorphic_patterns(binary_data)
        semantic_patterns['polymorphic'].extend(polymorphic)

        return semantic_patterns

    def _extract_control_flow_patterns(self, data: bytes) -> List[Dict[str, Any]]:
        """Extract control flow patterns for semantic analysis."""
        patterns = []

        if not CAPSTONE_AVAILABLE:
            return patterns

        try:
            # Determine architecture
            is_64bit = self._detect_architecture(data)
            mode = CS_MODE_64 if is_64bit else CS_MODE_32
            cs = Cs(CS_ARCH_X86, mode)

            # Find code sections
            code_sections = self._find_code_sections(data)

            for section_offset, section_data in code_sections:
                # Build control flow graph
                cfg = self._build_control_flow_graph(cs, section_data, section_offset)

                # Detect specific control flow patterns
                if self._has_opaque_predicates(cfg):
                    patterns.append({
                        'type': 'opaque_predicate',
                        'offset': section_offset,
                        'confidence': 0.85,
                        'description': 'Opaque predicate obfuscation detected'
                    })

                if self._has_control_flow_flattening(cfg):
                    patterns.append({
                        'type': 'control_flow_flattening',
                        'offset': section_offset,
                        'confidence': 0.9,
                        'description': 'Control flow flattening obfuscation'
                    })

                if self._has_function_chunking(cfg):
                    patterns.append({
                        'type': 'function_chunking',
                        'offset': section_offset,
                        'confidence': 0.8,
                        'description': 'Function chunking/splitting detected'
                    })

                # Detect loop patterns
                loop_patterns = self._detect_loop_patterns(cfg)
                for loop in loop_patterns:
                    patterns.append({
                        'type': 'loop_pattern',
                        'subtype': loop['type'],
                        'offset': loop['offset'],
                        'confidence': loop['confidence']
                    })

        except Exception as e:
            logger.debug(f"Control flow extraction failed: {e}")

        return patterns

    def _build_control_flow_graph(self, cs, section_data: bytes, offset: int) -> Dict[int, List[int]]:
        """Build control flow graph from disassembled instructions."""
        cfg = defaultdict(list)
        instructions = {}
        jumps = []

        # First pass: collect all instructions
        for insn in cs.disasm(section_data, offset):
            instructions[insn.address] = insn

            # Identify control flow instructions
            if insn.mnemonic.startswith('j'):  # Jump instructions
                try:
                    target = int(insn.op_str, 16)
                    jumps.append((insn.address, target, insn.mnemonic))
                except:
                    pass
            elif insn.mnemonic in ['call', 'ret', 'retn']:
                jumps.append((insn.address, None, insn.mnemonic))

        # Second pass: build graph edges
        sorted_addrs = sorted(instructions.keys())
        for i, addr in enumerate(sorted_addrs):
            insn = instructions[addr]

            # Add sequential flow
            if i + 1 < len(sorted_addrs):
                next_addr = sorted_addrs[i + 1]
                if not insn.mnemonic.startswith('j') and insn.mnemonic not in ['ret', 'retn']:
                    cfg[addr].append(next_addr)

            # Add jump targets
            for src, target, mnemonic in jumps:
                if src == addr and target and target in instructions:
                    cfg[src].append(target)
                    # Conditional jumps also have fall-through
                    if mnemonic.startswith('j') and mnemonic != 'jmp':
                        if i + 1 < len(sorted_addrs):
                            cfg[src].append(sorted_addrs[i + 1])

        return cfg

    def _has_opaque_predicates(self, cfg: Dict[int, List[int]]) -> bool:
        """Detect opaque predicates in control flow."""
        # Look for branches where one path is never taken
        for addr, targets in cfg.items():
            if len(targets) == 2:  # Conditional branch
                # Check if one target leads immediately back to merge point
                target1, target2 = targets
                if target1 in cfg and target2 in cfg:
                    if len(set(cfg[target1]) & set(cfg[target2])) > 0:
                        # Both paths merge quickly - possible opaque predicate
                        return True
        return False

    def _has_control_flow_flattening(self, cfg: Dict[int, List[int]]) -> bool:
        """Detect control flow flattening patterns."""
        # Look for dispatcher pattern: central node with many outgoing edges
        dispatcher_threshold = 5
        merge_threshold = 5

        for addr, targets in cfg.items():
            if len(targets) >= dispatcher_threshold:
                # Check if many nodes lead back to this dispatcher
                incoming = sum(1 for a, t in cfg.items() if addr in t)
                if incoming >= merge_threshold:
                    return True
        return False

    def _has_function_chunking(self, cfg: Dict[int, List[int]]) -> bool:
        """Detect function chunking/splitting."""
        # Look for disconnected subgraphs that call each other
        visited = set()
        components = []

        def dfs(node, component):
            if node in visited:
                return
            visited.add(node)
            component.add(node)
            for target in cfg.get(node, []):
                dfs(target, component)

        # Find all connected components
        for addr in cfg:
            if addr not in visited:
                component = set()
                dfs(addr, component)
                components.append(component)

        # Multiple components suggest function chunking
        return len(components) > 2

    def _detect_loop_patterns(self, cfg: Dict[int, List[int]]) -> List[Dict[str, Any]]:
        """Detect various loop patterns in control flow."""
        loops = []
        visited = set()

        def find_back_edges(node, path):
            if node in path:
                # Found a back edge (loop)
                loop_start = node
                loop_nodes = path[path.index(node):]
                return [(loop_start, loop_nodes)]

            if node in visited:
                return []

            visited.add(node)
            path.append(node)
            back_edges = []

            for target in cfg.get(node, []):
                back_edges.extend(find_back_edges(target, path[:]))

            return back_edges

        # Find all loops via back edges
        for start_node in cfg:
            if start_node not in visited:
                back_edges = find_back_edges(start_node, [])
                for loop_start, loop_nodes in back_edges:
                    loops.append({
                        'type': 'natural_loop' if len(loop_nodes) < 10 else 'complex_loop',
                        'offset': loop_start,
                        'size': len(loop_nodes),
                        'confidence': 0.9 if len(loop_nodes) < 10 else 0.7
                    })

        return loops

    def _extract_data_flow_patterns(self, data: bytes) -> List[Dict[str, Any]]:
        """Extract data flow patterns for semantic analysis."""
        patterns = []

        if not CAPSTONE_AVAILABLE:
            return patterns

        try:
            is_64bit = self._detect_architecture(data)
            mode = CS_MODE_64 if is_64bit else CS_MODE_32
            cs = Cs(CS_ARCH_X86, mode)

            code_sections = self._find_code_sections(data)

            for section_offset, section_data in code_sections:
                # Track register usage and data flow
                reg_usage = defaultdict(list)
                memory_access = []

                for insn in cs.disasm(section_data, section_offset):
                    # Track register modifications
                    if insn.mnemonic.startswith('mov'):
                        ops = insn.op_str.split(',', 1)
                        if len(ops) == 2:
                            dest = ops[0].strip()
                            src = ops[1].strip()
                            reg_usage[dest].append((insn.address, 'write', src))
                            if src in reg_usage:
                                reg_usage[src].append((insn.address, 'read', dest))

                    # Track memory access patterns
                    if '[' in insn.op_str:
                        memory_access.append({
                            'address': insn.address,
                            'type': 'memory_access',
                            'operation': insn.mnemonic
                        })

                # Analyze data flow patterns
                if self._has_data_obfuscation(reg_usage):
                    patterns.append({
                        'type': 'data_obfuscation',
                        'offset': section_offset,
                        'confidence': 0.75,
                        'description': 'Data flow obfuscation detected'
                    })

                if self._has_constant_blinding(reg_usage, section_data):
                    patterns.append({
                        'type': 'constant_blinding',
                        'offset': section_offset,
                        'confidence': 0.8,
                        'description': 'Constant blinding protection'
                    })

                # Check for stack manipulation patterns
                stack_patterns = self._detect_stack_patterns(memory_access)
                patterns.extend(stack_patterns)

        except Exception as e:
            logger.debug(f"Data flow extraction failed: {e}")

        return patterns

    def _has_data_obfuscation(self, reg_usage: Dict) -> bool:
        """Detect data obfuscation patterns."""
        # Look for excessive register shuffling
        shuffle_count = 0
        for reg, ops in reg_usage.items():
            if len(ops) > 10:  # Many operations on same register
                # Check for pattern: read-modify-write cycles
                for i in range(len(ops) - 2):
                    if (ops[i][1] == 'read' and
                        ops[i+1][1] == 'write' and
                        ops[i+2][1] == 'read'):
                        shuffle_count += 1

        return shuffle_count > 5

    def _has_constant_blinding(self, reg_usage: Dict, section_data: bytes) -> bool:
        """Detect constant blinding patterns."""
        # Look for XOR/ADD/SUB patterns that obfuscate constants
        xor_patterns = 0
        arithmetic_patterns = 0

        for reg, ops in reg_usage.items():
            for addr, op_type, operand in ops:
                if 'xor' in str(operand).lower():
                    xor_patterns += 1
                if any(op in str(operand).lower() for op in ['add', 'sub', 'imul']):
                    arithmetic_patterns += 1

        return xor_patterns > 10 or arithmetic_patterns > 15

    def _detect_stack_patterns(self, memory_access: List[Dict]) -> List[Dict[str, Any]]:
        """Detect stack manipulation patterns."""
        patterns = []
        stack_ops = [op for op in memory_access if 'sp' in str(op).lower() or 'bp' in str(op).lower()]

        if len(stack_ops) > 50:
            patterns.append({
                'type': 'stack_manipulation',
                'count': len(stack_ops),
                'confidence': min(1.0, len(stack_ops) / 100),
                'description': 'Heavy stack manipulation detected'
            })

        return patterns

    def _extract_behavioral_patterns(self, data: bytes) -> List[Dict[str, Any]]:
        """Extract behavioral patterns from binary."""
        patterns = []

        # API call patterns
        api_patterns = self._extract_api_behavioral_patterns(data)
        patterns.extend(api_patterns)

        # String-based behavioral patterns
        string_patterns = self._extract_string_behavioral_patterns(data)
        patterns.extend(string_patterns)

        # Network indicators
        network_patterns = self._extract_network_patterns(data)
        patterns.extend(network_patterns)

        # File system patterns
        fs_patterns = self._extract_filesystem_patterns(data)
        patterns.extend(fs_patterns)

        return patterns

    def _extract_api_behavioral_patterns(self, data: bytes) -> List[Dict[str, Any]]:
        """Extract API-based behavioral patterns."""
        patterns = []

        # Critical API patterns
        critical_apis = {
            b'VirtualProtect': ('memory_protection', 0.9),
            b'VirtualAlloc': ('memory_allocation', 0.8),
            b'CreateRemoteThread': ('remote_thread', 0.95),
            b'WriteProcessMemory': ('process_injection', 0.95),
            b'SetWindowsHookEx': ('hook_installation', 0.9),
            b'RegOpenKeyEx': ('registry_access', 0.7),
            b'CreateService': ('service_creation', 0.85),
            b'OpenProcess': ('process_access', 0.75),
            b'GetProcAddress': ('dynamic_import', 0.6),
            b'LoadLibrary': ('dynamic_loading', 0.6),
        }

        for api, (pattern_type, confidence) in critical_apis.items():
            if api in data:
                patterns.append({
                    'type': 'behavioral_api',
                    'subtype': pattern_type,
                    'api': api.decode('utf-8', errors='ignore'),
                    'confidence': confidence,
                    'description': f'Critical API usage: {api.decode("utf-8", errors="ignore")}'
                })

        return patterns

    def _extract_string_behavioral_patterns(self, data: bytes) -> List[Dict[str, Any]]:
        """Extract string-based behavioral patterns."""
        patterns = []

        # Behavioral string indicators
        behavioral_strings = {
            rb'\\\\\.\\.+': ('device_access', 0.8),
            rb'HKEY_.+': ('registry_key', 0.7),
            rb'\%[A-Z]+\%': ('environment_variable', 0.6),
            rb'cmd\.exe|powershell\.exe': ('shell_execution', 0.85),
            rb'\\AppData\\': ('appdata_access', 0.7),
            rb'\\System32\\': ('system_directory', 0.6),
            rb'[A-Za-z]:\\\\': ('file_path', 0.5),
        }

        for pattern, (behavior_type, confidence) in behavioral_strings.items():
            matches = re.finditer(pattern, data, re.IGNORECASE)
            for match in matches:
                patterns.append({
                    'type': 'behavioral_string',
                    'subtype': behavior_type,
                    'offset': match.start(),
                    'value': match.group()[:50],  # Limit string length
                    'confidence': confidence
                })

        return patterns

    def _extract_network_patterns(self, data: bytes) -> List[Dict[str, Any]]:
        """Extract network-related patterns."""
        patterns = []

        # Network APIs
        network_apis = [
            b'WSAStartup', b'socket', b'connect', b'send', b'recv',
            b'InternetOpen', b'InternetConnect', b'HttpOpenRequest',
            b'URLDownloadToFile', b'WinHttpOpen'
        ]

        for api in network_apis:
            if api in data:
                patterns.append({
                    'type': 'network_behavior',
                    'api': api.decode('utf-8', errors='ignore'),
                    'confidence': 0.8
                })

        # URL patterns
        url_pattern = rb'https?://[^\s\x00]+'
        urls = re.finditer(url_pattern, data)
        for url in urls:
            patterns.append({
                'type': 'network_url',
                'value': url.group()[:100].decode('utf-8', errors='ignore'),
                'offset': url.start(),
                'confidence': 0.9
            })

        # IP address patterns
        ip_pattern = rb'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = re.finditer(ip_pattern, data)
        for ip in ips:
            patterns.append({
                'type': 'network_ip',
                'value': ip.group().decode('utf-8'),
                'offset': ip.start(),
                'confidence': 0.7
            })

        return patterns

    def _extract_filesystem_patterns(self, data: bytes) -> List[Dict[str, Any]]:
        """Extract file system behavioral patterns."""
        patterns = []

        # File system APIs
        fs_apis = {
            b'CreateFile': 'file_creation',
            b'DeleteFile': 'file_deletion',
            b'MoveFile': 'file_movement',
            b'CopyFile': 'file_copy',
            b'FindFirstFile': 'file_enumeration',
            b'GetTempPath': 'temp_access',
            b'SetFileAttributes': 'attribute_modification',
        }

        for api, behavior in fs_apis.items():
            if api in data:
                patterns.append({
                    'type': 'filesystem_behavior',
                    'subtype': behavior,
                    'api': api.decode('utf-8', errors='ignore'),
                    'confidence': 0.75
                })

        return patterns

    def _detect_polymorphic_patterns(self, data: bytes) -> List[Dict[str, Any]]:
        """Detect polymorphic and metamorphic code patterns."""
        patterns = []

        # Self-modifying code indicators
        smc_patterns = self._detect_self_modifying_code(data)
        patterns.extend(smc_patterns)

        # Encryption/decryption loops
        crypto_loops = self._detect_crypto_loops(data)
        patterns.extend(crypto_loops)

        # Code mutation patterns
        mutation_patterns = self._detect_mutation_patterns(data)
        patterns.extend(mutation_patterns)

        return patterns

    def _detect_self_modifying_code(self, data: bytes) -> List[Dict[str, Any]]:
        """Detect self-modifying code patterns."""
        patterns = []

        # Look for VirtualProtect followed by code modification
        vp_pattern = b'VirtualProtect'
        if vp_pattern in data:
            # Check for nearby memory write patterns
            vp_positions = self._find_all_occurrences(data, vp_pattern)
            for pos in vp_positions:
                # Look for memory write instructions near VirtualProtect
                nearby_data = data[max(0, pos-1000):min(len(data), pos+1000)]
                if b'WriteProcessMemory' in nearby_data or b'memcpy' in nearby_data:
                    patterns.append({
                        'type': 'self_modifying_code',
                        'offset': pos,
                        'confidence': 0.85,
                        'description': 'Self-modifying code pattern detected'
                    })

        return patterns

    def _detect_crypto_loops(self, data: bytes) -> List[Dict[str, Any]]:
        """Detect encryption/decryption loop patterns."""
        patterns = []

        if not CAPSTONE_AVAILABLE:
            return patterns

        try:
            is_64bit = self._detect_architecture(data)
            mode = CS_MODE_64 if is_64bit else CS_MODE_32
            cs = Cs(CS_ARCH_X86, mode)

            code_sections = self._find_code_sections(data)

            for section_offset, section_data in code_sections:
                xor_count = 0
                loop_count = 0
                crypto_ops = ['xor', 'ror', 'rol', 'shl', 'shr', 'add', 'sub']

                for insn in cs.disasm(section_data, section_offset):
                    if insn.mnemonic in crypto_ops:
                        xor_count += 1
                    if insn.mnemonic in ['loop', 'jmp', 'je', 'jne']:
                        loop_count += 1

                    # Detect crypto loop pattern
                    if xor_count > 5 and loop_count > 2:
                        patterns.append({
                            'type': 'crypto_loop',
                            'offset': section_offset,
                            'xor_operations': xor_count,
                            'loop_operations': loop_count,
                            'confidence': min(1.0, (xor_count + loop_count) / 20),
                            'description': 'Encryption/decryption loop detected'
                        })
                        break

        except Exception as e:
            logger.debug(f"Crypto loop detection failed: {e}")

        return patterns

    def _detect_mutation_patterns(self, data: bytes) -> List[Dict[str, Any]]:
        """Detect code mutation patterns."""
        patterns = []

        # Detect instruction substitution patterns
        mutation_signatures = [
            # Equivalent instruction patterns
            (b'\x31\xc0', b'\x33\xc0'),  # xor eax,eax vs xor eax,eax (different encoding)
            (b'\x48\x31\xc0', b'\x48\x33\xc0'),  # 64-bit variants
            (b'\x89\xc0', b'\x8b\xc0'),  # mov eax,eax variants
        ]

        for sig1, sig2 in mutation_signatures:
            count1 = data.count(sig1)
            count2 = data.count(sig2)
            if count1 > 0 and count2 > 0:
                patterns.append({
                    'type': 'instruction_mutation',
                    'variants': 2,
                    'confidence': 0.7,
                    'description': 'Instruction substitution pattern detected'
                })

        # Detect garbage code insertion
        nop_sequences = data.count(b'\x90' * 5)  # Multiple NOPs
        if nop_sequences > 10:
            patterns.append({
                'type': 'garbage_insertion',
                'count': nop_sequences,
                'confidence': 0.65,
                'description': 'Garbage code insertion detected'
            })

        return patterns

    def generate_semantic_yara_rules(self, semantic_patterns: Dict[str, Any]) -> str:
        """Generate YARA rules from semantic patterns."""
        rules = []

        # Generate control flow rules
        if semantic_patterns.get('control_flow'):
            cf_rule = self._generate_control_flow_rule(semantic_patterns['control_flow'])
            rules.append(cf_rule)

        # Generate data flow rules
        if semantic_patterns.get('data_flow'):
            df_rule = self._generate_data_flow_rule(semantic_patterns['data_flow'])
            rules.append(df_rule)

        # Generate behavioral rules
        if semantic_patterns.get('behavioral'):
            behavioral_rule = self._generate_behavioral_rule(semantic_patterns['behavioral'])
            rules.append(behavioral_rule)

        # Generate polymorphic detection rules
        if semantic_patterns.get('polymorphic'):
            poly_rule = self._generate_polymorphic_rule(semantic_patterns['polymorphic'])
            rules.append(poly_rule)

        return "\n\n".join(rules)

    def _generate_control_flow_rule(self, cf_patterns: List[Dict]) -> str:
        """Generate YARA rule for control flow patterns."""
        rule = ["rule Control_Flow_Obfuscation"]
        rule.append("{")
        rule.append("    meta:")
        rule.append('        description = "Detects control flow obfuscation"')
        rule.append('        category = "obfuscation"')

        # Calculate confidence based on patterns
        avg_confidence = sum(p.get('confidence', 0.5) for p in cf_patterns) / len(cf_patterns) if cf_patterns else 0.5
        rule.append(f'        confidence = {avg_confidence:.2f}')

        rule.append("")
        rule.append("    condition:")

        # Create conditions based on detected patterns
        conditions = []
        for pattern in cf_patterns:
            if pattern['type'] == 'control_flow_flattening':
                conditions.append("uint32(0) == 0x905A4D or uint32(0) == 0x4550")

        if conditions:
            rule.append(f"        {' or '.join(conditions)}")
        else:
            rule.append("        false")

        rule.append("}")
        return "\n".join(rule)

    def _generate_data_flow_rule(self, df_patterns: List[Dict]) -> str:
        """Generate YARA rule for data flow patterns."""
        rule = ["rule Data_Flow_Obfuscation"]
        rule.append("{")
        rule.append("    meta:")
        rule.append('        description = "Detects data flow obfuscation"')
        rule.append('        category = "obfuscation"')

        avg_confidence = sum(p.get('confidence', 0.5) for p in df_patterns) / len(df_patterns) if df_patterns else 0.5
        rule.append(f'        confidence = {avg_confidence:.2f}')

        rule.append("")
        rule.append("    condition:")
        rule.append("        uint32(0) == 0x905A4D")  # Basic PE check
        rule.append("}")
        return "\n".join(rule)

    def _generate_behavioral_rule(self, behavioral_patterns: List[Dict]) -> str:
        """Generate YARA rule for behavioral patterns."""
        rule = ["rule Behavioral_Indicators"]
        rule.append("{")
        rule.append("    meta:")
        rule.append('        description = "Detects behavioral indicators"')
        rule.append('        category = "behavioral"')

        # Group patterns by type
        api_patterns = [p for p in behavioral_patterns if p.get('type') == 'behavioral_api']
        network_patterns = [p for p in behavioral_patterns if 'network' in p.get('type', '')]

        rule.append("")
        rule.append("    strings:")

        string_count = 0
        for pattern in api_patterns[:10]:  # Limit to 10 patterns
            api_name = pattern.get('api', '')
            if api_name:
                rule.append(f'        $api_{string_count} = "{api_name}" ascii')
                string_count += 1

        for pattern in network_patterns[:5]:  # Limit network patterns
            value = pattern.get('value', '')
            if value:
                rule.append(f'        $net_{string_count} = "{value}" ascii')
                string_count += 1

        rule.append("")
        rule.append("    condition:")
        if string_count > 0:
            rule.append("        any of them")
        else:
            rule.append("        false")

        rule.append("}")
        return "\n".join(rule)

    def _generate_polymorphic_rule(self, poly_patterns: List[Dict]) -> str:
        """Generate YARA rule for polymorphic code detection."""
        rule = ["rule Polymorphic_Code"]
        rule.append("{")
        rule.append("    meta:")
        rule.append('        description = "Detects polymorphic code patterns"')
        rule.append('        category = "polymorphic"')

        avg_confidence = sum(p.get('confidence', 0.5) for p in poly_patterns) / len(poly_patterns) if poly_patterns else 0.5
        rule.append(f'        confidence = {avg_confidence:.2f}')

        rule.append("")
        rule.append("    strings:")
        rule.append('        $vprotect = "VirtualProtect" ascii')
        rule.append('        $wpm = "WriteProcessMemory" ascii')
        rule.append("        $xor_loop = { 31 ?? 83 ?? ?? 7? ?? }")

        rule.append("")
        rule.append("    condition:")
        rule.append("        ($vprotect and $wpm) or $xor_loop")
        rule.append("}")
        return "\n".join(rule)
rule VMProtect_Detection
{
    meta:
        category = "protection"
        confidence = 0.9
        description = "Detects VMProtect virtualization protection"

    strings:
        $vmp1 = ".vmp0" ascii
        $vmp2 = ".vmp1" ascii
        $vmp3 = "VMProtect" ascii nocase
        $vmp4 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 04 }

    condition:
        any of them
}

rule Themida_Detection
{
    meta:
        category = "protection"
        confidence = 0.85
        description = "Detects Themida/WinLicense protection"

    strings:
        $tmd1 = ".themida" ascii
        $tmd2 = "Themida" ascii nocase
        $tmd3 = "WinLicense" ascii nocase
        $tmd4 = { 8B 85 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 89 85 }

    condition:
        any of them
}

rule Enigma_Protector
{
    meta:
        category = "protection"
        confidence = 0.8
        description = "Detects Enigma Protector"

    strings:
        $enig1 = ".enigma1" ascii
        $enig2 = ".enigma2" ascii
        $enig3 = "Enigma Protector" ascii nocase

    condition:
        any of them
}
"""

        # Packer detection rules
        packer_rules = """
rule UPX_Packer
{
    meta:
        category = "packer"
        confidence = 0.95
        description = "Detects UPX packer"

    strings:
        $upx1 = "UPX!" ascii
        $upx2 = "$Info: This file is packed with the UPX executable packer" ascii
        $upx3 = { 55 50 58 21 }

    condition:
        any of them
}

rule ASPack_Packer
{
    meta:
        category = "packer"
        confidence = 0.9
        description = "Detects ASPack packer"

    strings:
        $asp1 = ".aspack" ascii
        $asp2 = "ASPack" ascii nocase
        $asp3 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 }

    condition:
        any of them
}

rule PECompact_Packer
{
    meta:
        category = "packer"
        confidence = 0.85
        description = "Detects PECompact packer"

    strings:
        $pec1 = "PECompact2" ascii
        $pec2 = ".pec1" ascii
        $pec3 = ".pec2" ascii

    condition:
        any of them
}
"""

        # Licensing detection rules
        licensing_rules = """
rule FlexLM_License
{
    meta:
        category = "licensing"
        confidence = 0.9
        description = "Detects FlexLM licensing system"

    strings:
        $flex1 = "FlexLM" ascii nocase
        $flex2 = "lm_checkout" ascii
        $flex3 = "VENDOR_NAME" ascii
        $flex4 = "license.dat" ascii nocase
        $flex5 = "lmgrd" ascii

    condition:
        any of them
}

rule HASP_Dongle
{
    meta:
        category = "licensing"
        confidence = 0.85
        description = "Detects HASP/Sentinel dongle protection"

    strings:
        $hasp1 = "hasp_login" ascii
        $hasp2 = "HASP HL" ascii
        $hasp3 = "Sentinel" ascii nocase
        $hasp4 = "aksusb" ascii
        $hasp5 = "hardlock.sys" ascii nocase

    condition:
        any of them
}

rule CodeMeter_License
{
    meta:
        category = "licensing"
        confidence = 0.8
        description = "Detects CodeMeter licensing"

    strings:
        $cm1 = "CodeMeter" ascii nocase
        $cm2 = "CmContainer" ascii
        $cm3 = "WibuCm" ascii
        $cm4 = ".WibuCm" ascii

    condition:
        any of them
}

rule Generic_License_Patterns
{
    meta:
        category = "licensing"
        confidence = 0.6
        description = "Generic licensing patterns"

    strings:
        $lic1 = "license key" ascii nocase
        $lic2 = "serial number" ascii nocase
        $lic3 = "activation code" ascii nocase
        $lic4 = "trial expired" ascii nocase
        $lic5 = "registration required" ascii nocase
        $lic6 = /License.*[Vv]iolation/ ascii

    condition:
        any of them
}
"""

        # Anti-debug detection rules
        antidebug_rules = """
rule Anti_Debug_API
{
    meta:
        category = "anti_debug"
        confidence = 0.8
        description = "Detects anti-debugging API calls"

    strings:
        $api1 = "IsDebuggerPresent" ascii
        $api2 = "CheckRemoteDebuggerPresent" ascii
        $api3 = "NtQueryInformationProcess" ascii
        $api4 = "OutputDebugString" ascii
        $api5 = "GetTickCount" ascii

    condition:
        any of them
}

rule Anti_Debug_PEB
{
    meta:
        category = "anti_debug"
        confidence = 0.75
        description = "Detects PEB-based anti-debugging"

    strings:
        $peb1 = { 64 8B 30 8B 76 0C 8B 76 1C }  // PEB access
        $peb2 = { 65 8B 00 8B 40 ?? 8A 40 02 }  // BeingDebugged flag

    condition:
        any of them
}

rule Anti_VM_Detection
{
    meta:
        category = "anti_vm"
        confidence = 0.7
        description = "Detects anti-VM techniques"

    strings:
        $vm1 = "VMware" ascii nocase
        $vm2 = "VirtualBox" ascii nocase
        $vm3 = "QEMU" ascii nocase
        $vm4 = "Xen" ascii nocase
        $vm5 = "vbox" ascii nocase
        $vm6 = { 0F 01 0D 00 00 00 00 }  // SIDT instruction

    condition:
        any of them
}
"""

        # Compiler detection rules
        compiler_rules = """
rule MSVC_Compiler
{
    meta:
        category = "compiler"
        confidence = 0.9
        description = "Microsoft Visual C++ compiler"

    strings:
        $msvc1 = "Microsoft (R) 32-bit C/C++ Optimizing Compiler" ascii
        $msvc2 = "MSVCR" ascii
        $msvc3 = ".rdata$zzz" ascii

    condition:
        any of them
}

rule Delphi_Compiler
{
    meta:
        category = "compiler"
        confidence = 0.85
        description = "Borland Delphi compiler"

    strings:
        $delphi1 = "Borland" ascii
        $delphi2 = "@AbstractError" ascii
        $delphi3 = "Controls.TControl" ascii

    condition:
        any of them
}

rule GCC_Compiler
{
    meta:
        category = "compiler"
        confidence = 0.8
        description = "GNU GCC compiler"

    strings:
        $gcc1 = "GCC: " ascii
        $gcc2 = "__gmon_start__" ascii
        $gcc3 = ".eh_frame" ascii

    condition:
        any of them
}
"""

        # Write rule files
        (rules_dir / "protections.yar").write_text(protection_rules)
        (rules_dir / "packers.yar").write_text(packer_rules)
        (rules_dir / "licensing.yar").write_text(licensing_rules)
        (rules_dir / "antidebug.yar").write_text(antidebug_rules)
        (rules_dir / "compilers.yar").write_text(compiler_rules)

    def _create_minimal_rules(self, rules_dir: Path):
        """Create minimal rules as fallback."""
        minimal_rules = """
rule Basic_PE_Detection
{
    meta:
        category = "compiler"
        confidence = 0.5
        description = "Basic PE file detection"

    strings:
        $pe = { 4D 5A }  // MZ header

    condition:
        $pe at 0
}
"""
        (rules_dir / "basic.yar").write_text(minimal_rules)

    def _extract_rule_metadata(self):
        """Extract metadata from compiled rules."""
        if not self.compiled_rules:
            return

        # Note: yara-python doesn't provide direct access to rule metadata
        # This is a simplified implementation
        for rule in self.compiled_rules:
            self.rule_metadata[rule.identifier] = {
                "namespace": rule.namespace,
                "tags": list(rule.tags),
                "category": "unknown",
                "confidence": 0.5,
            }

    def _count_total_rules(self) -> int:
        """Count total number of rules."""
        if not self.compiled_rules:
            return 0
        return len(list(self.compiled_rules))

    def scan_with_binary_detector(self, data: bytes, categories: Optional[List[str]] = None) -> Dict[str, Any]:
        """Scan binary using integrated binary pattern detector for advanced detection.

        Args:
            data: Binary data to scan
            categories: Optional list of pattern categories to scan for

        Returns:
            Dictionary containing binary pattern detection results

        """
        binary_matches = self.binary_detector.scan_binary(data, categories)

        # Group matches by category
        categorized_matches = defaultdict(list)
        for match in binary_matches:
            categorized_matches[match.pattern.category].append({
                'name': match.pattern.name,
                'offset': match.offset,
                'confidence': match.confidence,
                'description': match.pattern.description,
                'metadata': match.pattern.metadata,
                'xrefs': match.xrefs,
                'relocations': match.relocations,
                'disassembly': match.disassembly[:5] if match.disassembly else []  # Limit disasm lines
            })

        # Calculate aggregated confidence scores
        protection_score = 0.0
        licensing_score = 0.0
        obfuscation_score = 0.0

        for category, matches in categorized_matches.items():
            if category == 'protection':
                protection_score = max(protection_score, max((m['confidence'] for m in matches), default=0.0))
            elif category == 'licensing':
                licensing_score = max(licensing_score, max((m['confidence'] for m in matches), default=0.0))
            elif category == 'obfuscation':
                obfuscation_score = max(obfuscation_score, max((m['confidence'] for m in matches), default=0.0))

        return {
            'binary_patterns': dict(categorized_matches),
            'total_matches': len(binary_matches),
            'protection_score': protection_score,
            'licensing_score': licensing_score,
            'obfuscation_score': obfuscation_score,
            'statistics': self.binary_detector.get_pattern_statistics()
        }

    def scan_file_comprehensive(self, file_path: str, timeout: int = 60, use_binary_detector: bool = True) -> Dict[str, Any]:
        """Perform comprehensive scan using both YARA and binary pattern detection.

        Args:
            file_path: Path to file to scan
            timeout: Scan timeout in seconds
            use_binary_detector: Enable binary pattern detector for enhanced detection

        Returns:
            Dictionary containing combined scan results from both engines

        """
        # Perform standard YARA scan
        yara_result = self.scan_file(file_path, timeout)

        # Initialize comprehensive result
        comprehensive_result = {
            'file_path': file_path,
            'yara_results': {
                'matches': len(yara_result.matches),
                'categories': {},
                'high_confidence': len(yara_result.high_confidence_matches),
                'has_protections': yara_result.has_protections,
                'has_packers': yara_result.has_packers,
                'has_licensing': yara_result.has_licensing,
                'scan_time': yara_result.scan_time,
                'error': yara_result.error
            },
            'binary_patterns': None,
            'combined_confidence': {
                'protection': 0.0,
                'licensing': 0.0,
                'obfuscation': 0.0,
                'overall': 0.0
            },
            'detected_technologies': set(),
            'bypass_recommendations': []
        }

        # Group YARA matches by category
        for match in yara_result.matches:
            category = match.category.value
            if category not in comprehensive_result['yara_results']['categories']:
                comprehensive_result['yara_results']['categories'][category] = []
            comprehensive_result['yara_results']['categories'][category].append({
                'rule': match.rule_name,
                'confidence': match.confidence,
                'offset': match.offset
            })

        # Perform binary pattern detection if enabled and no YARA error
        if use_binary_detector and not yara_result.error:
            try:
                with open(file_path, 'rb') as f:
                    binary_data = f.read()

                binary_results = self.scan_with_binary_detector(binary_data)
                comprehensive_result['binary_patterns'] = binary_results

                # Combine confidence scores from both engines
                yara_protection = max((m.confidence for m in yara_result.get_matches_by_category(PatternCategory.PROTECTION)), default=0.0)
                yara_licensing = max((m.confidence for m in yara_result.get_matches_by_category(PatternCategory.LICENSING)), default=0.0)
                yara_obfuscation = max((m.confidence for m in yara_result.get_matches_by_category(PatternCategory.OBFUSCATION)), default=0.0)

                comprehensive_result['combined_confidence']['protection'] = max(yara_protection, binary_results.get('protection_score', 0.0))
                comprehensive_result['combined_confidence']['licensing'] = max(yara_licensing, binary_results.get('licensing_score', 0.0))
                comprehensive_result['combined_confidence']['obfuscation'] = max(yara_obfuscation, binary_results.get('obfuscation_score', 0.0))
                comprehensive_result['combined_confidence']['overall'] = max(
                    comprehensive_result['combined_confidence']['protection'],
                    comprehensive_result['combined_confidence']['licensing'],
                    comprehensive_result['combined_confidence']['obfuscation']
                )

                # Extract detected technologies from binary patterns
                for category, matches in binary_results.get('binary_patterns', {}).items():
                    for match in matches:
                        if 'metadata' in match:
                            if 'drm_type' in match['metadata']:
                                comprehensive_result['detected_technologies'].add(match['metadata']['drm_type'])
                            if 'vendor' in match['metadata']:
                                comprehensive_result['detected_technologies'].add(match['metadata']['vendor'])
                            if 'protection' in match['metadata']:
                                comprehensive_result['detected_technologies'].add(match['metadata']['protection'])
                            if 'obfuscator' in match['metadata']:
                                comprehensive_result['detected_technologies'].add(match['metadata']['obfuscator'])

                # Generate bypass recommendations based on detections
                if comprehensive_result['combined_confidence']['licensing'] > 0.8:
                    if 'denuvo' in comprehensive_result['detected_technologies']:
                        comprehensive_result['bypass_recommendations'].append({
                            'technology': 'Denuvo',
                            'method': 'VM layer analysis with timing attack mitigation',
                            'difficulty': 'extreme',
                            'tools': ['x64dbg', 'IDA Pro', 'Custom VM analyzer']
                        })
                    if 'steam_ceg' in comprehensive_result['detected_technologies']:
                        comprehensive_result['bypass_recommendations'].append({
                            'technology': 'Steam CEG',
                            'method': 'Memory dump at OEP with IAT reconstruction',
                            'difficulty': 'medium',
                            'tools': ['Scylla', 'x64dbg']
                        })
                    if 'flexera' in comprehensive_result['detected_technologies']:
                        comprehensive_result['bypass_recommendations'].append({
                            'technology': 'FlexLM/FlexNet',
                            'method': 'License server emulation with response replay',
                            'difficulty': 'high',
                            'tools': ['Custom server emulator', 'Wireshark']
                        })

            except Exception as e:
                logger.error(f"Binary pattern detection failed: {e}")
                comprehensive_result['binary_patterns'] = {'error': str(e)}

        # Convert set to list for JSON serialization
        comprehensive_result['detected_technologies'] = list(comprehensive_result['detected_technologies'])

        return comprehensive_result

    def scan_file(self, file_path: str, timeout: int = 60) -> YaraScanResult:
        """Scan a file with YARA rules.

        Args:
            file_path: Path to file to scan
            timeout: Scan timeout in seconds

        Returns:
            YaraScanResult with all matches

        """
        import time

        start_time = time.time()

        if not YARA_AVAILABLE:
            return YaraScanResult(
                file_path=file_path,
                error="YARA not available",
            )

        if not self.compiled_rules:
            return YaraScanResult(
                file_path=file_path,
                error="No YARA rules loaded",
            )

        if not os.path.exists(file_path):
            return YaraScanResult(
                file_path=file_path,
                error=f"File not found: {file_path}",
            )

        # Create temporary directory for large file processing if needed
        temp_dir = None
        if os.path.getsize(file_path) > 100 * 1024 * 1024:  # > 100MB
            temp_dir = tempfile.mkdtemp(prefix="yara_scan_")
            logger.debug(f"Created temporary directory for large file scan: {temp_dir}")

        # Track scanned files to avoid duplicate processing
        abs_file_path = os.path.abspath(file_path)
        if abs_file_path in self.scanned_files:
            logger.debug(f"File already scanned: {abs_file_path}")
        self.scanned_files.add(abs_file_path)

        # Generate file hash for tracking and metadata
        file_hash = ""
        try:
            with open(file_path, "rb") as f:
                file_data = f.read(8192)  # Read first 8KB for hash
                file_hash = hashlib.sha256(file_data).hexdigest()[:16]
        except Exception:
            file_hash = "unknown"

        try:
            # Scan file with timeout
            yara_matches = self.compiled_rules.match(
                file_path,
                timeout=timeout,
                fast=False,  # Enable string matching details
            )

            # Convert YARA matches to our format
            matches = []
            for match in yara_matches:
                # Extract category from metadata or tags
                category = self._determine_category(match)
                confidence = self._calculate_confidence(match)

                # Process string matches
                for string_match in match.strings:
                    yara_match = YaraMatch(
                        rule_name=match.rule,
                        namespace=match.namespace,
                        tags=list(match.tags),
                        category=category,
                        confidence=confidence,
                        offset=string_match.offset,
                        length=string_match.length,
                        identifier=string_match.identifier,
                        string_data=string_match.instances[0] if string_match.instances else "",
                        metadata=dict(match.meta) if hasattr(match, "meta") else {},
                    )
                    matches.append(yara_match)

                # If no string matches, create a general match
                if not match.strings:
                    yara_match = YaraMatch(
                        rule_name=match.rule,
                        namespace=match.namespace,
                        tags=list(match.tags),
                        category=category,
                        confidence=confidence,
                        offset=0,
                        length=0,
                        identifier="rule_match",
                        metadata=dict(match.meta) if hasattr(match, "meta") else {},
                    )
                    matches.append(yara_match)

            scan_time = time.time() - start_time

            result = YaraScanResult(
                file_path=file_path,
                matches=matches,
                total_rules=self._count_total_rules(),
                scan_time=scan_time,
            )

            # Add file hash to result metadata if available
            if hasattr(result, "metadata"):
                result.metadata = {"file_hash": file_hash}

            return result

        except Exception as e:
            logger.error(f"YARA scan error: {e}")
            return YaraScanResult(
                file_path=file_path,
                error=str(e),
                scan_time=time.time() - start_time,
            )
        finally:
            # Cleanup temporary directory if created
            if temp_dir and os.path.exists(temp_dir):
                import shutil

                try:
                    shutil.rmtree(temp_dir)
                    logger.debug(f"Cleaned up temporary directory: {temp_dir}")
                except Exception as cleanup_error:
                    logger.warning(f"Failed to cleanup temp directory: {cleanup_error}")

    def _determine_category(self, match) -> PatternCategory:
        """Determine pattern category from YARA match."""
        # Check rule name first
        rule_name = match.rule.lower()

        if any(keyword in rule_name for keyword in ["protection", "protect", "vmprotect", "themida", "enigma"]):
            return PatternCategory.PROTECTION
        if any(keyword in rule_name for keyword in ["pack", "upx", "aspack", "pecompact"]):
            return PatternCategory.PACKER
        if any(keyword in rule_name for keyword in ["license", "flexlm", "hasp", "dongle", "activation"]):
            return PatternCategory.LICENSING
        if any(keyword in rule_name for keyword in ["debug", "antidebug", "anti_debug"]):
            return PatternCategory.ANTI_DEBUG
        if any(keyword in rule_name for keyword in ["vm", "antivm", "anti_vm", "virtual"]):
            return PatternCategory.ANTI_VM
        if any(keyword in rule_name for keyword in ["compiler", "msvc", "gcc", "delphi"]):
            return PatternCategory.COMPILER
        if any(keyword in rule_name for keyword in ["crack", "keygen", "patch"]):
            return PatternCategory.LICENSE_BYPASS
        return PatternCategory.SUSPICIOUS

    def _calculate_confidence(self, match) -> float:
        """Calculate confidence score for a match."""
        # Check metadata first
        if hasattr(match, "meta") and "confidence" in match.meta:
            try:
                return float(match.meta["confidence"])
            except (ValueError, TypeError):
                pass

        # Calculate based on rule characteristics
        base_confidence = 0.7

        # Adjust based on number of string matches
        if hasattr(match, "strings") and match.strings:
            string_count = len(match.strings)
            if string_count > 3:
                base_confidence += 0.2
            elif string_count > 1:
                base_confidence += 0.1

        # Adjust based on tags
        if hasattr(match, "tags"):
            if "high_confidence" in match.tags:
                base_confidence += 0.15
            elif "low_confidence" in match.tags:
                base_confidence -= 0.15

        return min(1.0, max(0.1, base_confidence))

    def scan_memory(self, process_id: int, timeout: int = 60) -> YaraScanResult:
        """Scan process memory with YARA rules.

        Args:
            process_id: Process ID to scan
            timeout: Scan timeout in seconds

        Returns:
            YaraScanResult with memory matches

        """
        if not YARA_AVAILABLE:
            return YaraScanResult(
                file_path=f"process_{process_id}",
                error="YARA not available",
            )

        if not self.compiled_rules:
            return YaraScanResult(
                file_path=f"process_{process_id}",
                error="No YARA rules loaded",
            )

        try:
            # Scan process memory
            yara_matches = self.compiled_rules.match(
                pid=process_id,
                timeout=timeout,
            )

            # Convert matches (same logic as file scanning)
            matches = []
            for match in yara_matches:
                category = self._determine_category(match)
                confidence = self._calculate_confidence(match)

                for string_match in match.strings:
                    yara_match = YaraMatch(
                        rule_name=match.rule,
                        namespace=match.namespace,
                        tags=list(match.tags),
                        category=category,
                        confidence=confidence,
                        offset=string_match.offset,
                        length=string_match.length,
                        identifier=string_match.identifier,
                        string_data=string_match.instances[0] if string_match.instances else "",
                        metadata=dict(match.meta) if hasattr(match, "meta") else {},
                    )
                    matches.append(yara_match)

            return YaraScanResult(
                file_path=f"process_{process_id}",
                matches=matches,
                total_rules=self._count_total_rules(),
            )

        except Exception as e:
            logger.error(f"Memory scan error: {e}")
            return YaraScanResult(
                file_path=f"process_{process_id}",
                error=str(e),
            )

    def create_custom_rule(self, rule_content: str, rule_name: str) -> bool:
        """Create a custom YARA rule.

        Args:
            rule_content: YARA rule content
            rule_name: Name for the rule file

        Returns:
            True if rule was created successfully

        """
        try:
            # Validate rule syntax first
            yara.compile(source=rule_content)

            # Create custom rules directory if it doesn't exist
            if not self.custom_rules_path:
                rules_dir = Path(__file__).parent.parent.parent / "data" / "yara_rules" / "custom"
                rules_dir.mkdir(parents=True, exist_ok=True)
                self.custom_rules_path = str(rules_dir)

            # Write rule file
            rule_file = Path(self.custom_rules_path) / f"{rule_name}.yar"
            rule_file.write_text(rule_content)

            # Reload rules to include the new one
            self._load_rules()

            logger.info(f"Created custom YARA rule: {rule_name}")
            return True

        except Exception as e:
            logger.error(f"Failed to create custom rule: {e}")
            return False

    def get_rule_info(self) -> dict[str, Any]:
        """Get information about loaded rules."""
        if not self.compiled_rules:
            return {"error": "No rules loaded"}

        categories = {}
        for _rule_id, metadata in self.rule_metadata.items():
            category = metadata.get("category", "unknown")
            if category not in categories:
                categories[category] = 0
            categories[category] += 1

        # Calculate namespace distribution with counts
        namespace_dist: dict[str, tuple[int, list[str]]] = {}
        for rule_id, metadata in self.rule_metadata.items():
            namespace = metadata.get("namespace", "unknown")
            if namespace not in namespace_dist:
                namespace_dist[namespace] = (0, [])
            count, rules = namespace_dist[namespace]
            namespace_dist[namespace] = (count + 1, rules + [rule_id])

        return {
            "total_rules": self._count_total_rules(),
            "categories": categories,
            "namespaces": list(set(meta.get("namespace", "unknown") for meta in self.rule_metadata.values())),
            "namespace_distribution": namespace_dist,
            "yara_available": YARA_AVAILABLE,
        }

    def generate_icp_supplemental_data(self, scan_result: YaraScanResult) -> dict[str, Any]:
        """Generate supplemental data for ICP backend integration.

        Args:
            scan_result: YARA scan results

        Returns:
            Dictionary with supplemental pattern data for ICP

        """
        if not scan_result.matches:
            return {}

        # Categorize matches for ICP integration
        supplemental_data = {
            "yara_analysis": {
                "total_matches": len(scan_result.matches),
                "high_confidence_matches": len(scan_result.high_confidence_matches),
                "scan_time": scan_result.scan_time,
                "categories_detected": list(set(m.category.value for m in scan_result.matches)),
            },
            "protection_indicators": [],
            "licensing_indicators": [],
            "packer_indicators": [],
            "anti_analysis_indicators": [],
        }

        # Export scan summary as JSON for logging
        try:
            scan_summary = {
                "file": scan_result.file_path,
                "matches": len(scan_result.matches),
                "categories": list(set(m.category.value for m in scan_result.matches)),
                "high_confidence_count": len(scan_result.high_confidence_matches),
            }
            json_summary = json.dumps(scan_summary, indent=2)
            logger.debug(f"YARA scan summary: {json_summary}")
        except Exception as json_error:
            logger.warning(f"Failed to export scan summary as JSON: {json_error}")

        # Process protection matches
        for match in scan_result.get_matches_by_category(PatternCategory.PROTECTION):
            supplemental_data["protection_indicators"].append(
                {
                    "name": match.rule_name,
                    "confidence": match.confidence,
                    "offset": match.offset,
                    "technique": "pattern_matching",
                }
            )

        # Process licensing matches
        for match in scan_result.get_matches_by_category(PatternCategory.LICENSING):
            supplemental_data["licensing_indicators"].append(
                {
                    "name": match.rule_name,
                    "confidence": match.confidence,
                    "offset": match.offset,
                    "type": "licensing_system",
                }
            )

        # Process packer matches
        for match in scan_result.get_matches_by_category(PatternCategory.PACKER):
            supplemental_data["packer_indicators"].append(
                {
                    "name": match.rule_name,
                    "confidence": match.confidence,
                    "offset": match.offset,
                    "packer_type": "signature_based",
                }
            )

        # Process anti-analysis matches
        anti_analysis_categories = [PatternCategory.ANTI_DEBUG, PatternCategory.ANTI_VM]
        for category in anti_analysis_categories:
            for match in scan_result.get_matches_by_category(category):
                supplemental_data["anti_analysis_indicators"].append(
                    {
                        "name": match.rule_name,
                        "confidence": match.confidence,
                        "offset": match.offset,
                        "category": category.value,
                    }
                )

        return supplemental_data


# Singleton instance
_yara_engine: YaraPatternEngine | None = None


def get_yara_engine() -> YaraPatternEngine | None:
    """Get or create the YARA pattern engine singleton."""
    global _yara_engine
    if _yara_engine is None and YARA_AVAILABLE:
        try:
            _yara_engine = YaraPatternEngine()
        except Exception as e:
            logger.error(f"Failed to initialize YARA engine: {e}")
            return None
    return _yara_engine


def is_yara_available() -> bool:
    """Check if YARA functionality is available."""
    return YARA_AVAILABLE


def scan_file_with_yara(file_path: str) -> YaraScanResult | None:
    """Quick scan function for integration."""
    engine = get_yara_engine()
    if engine:
        return engine.scan_file(file_path)
    return None
