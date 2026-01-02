"""Arxan TransformIT Analysis Module for Intellicrack.

Performs deep analysis of Arxan-protected binaries including anti-tampering mechanisms,
control flow obfuscation, RASP features, license validation routines, and integrity checks.

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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from intellicrack.utils.type_safety import get_typed_item, validate_type


if TYPE_CHECKING:
    from types import ModuleType


try:
    import capstone

    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False
    capstone = cast("ModuleType", None)

try:
    import lief

    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False
    lief = cast("ModuleType", None)

try:
    import pefile

    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False
    pefile = cast("ModuleType", None)

from intellicrack.core.protection_detection.arxan_detector import ArxanDetector


logger = logging.getLogger(__name__)


@dataclass
class TamperCheckLocation:
    """Location of anti-tampering check.

    Attributes:
        address: Memory address where the tamper check is located.
        size: Size of the tamper check pattern in bytes.
        check_type: Type of tamper check (e.g., "tamper_detection", "inline_check").
        target_region: Tuple of (start, end) addresses for the protected region.
        algorithm: Algorithm used for verification (e.g., "crc32", "md5").
        bypass_complexity: Complexity level for bypassing the check
            ("low", "medium", or "high").
    """

    address: int
    size: int
    check_type: str
    target_region: tuple[int, int]
    algorithm: str
    bypass_complexity: str


@dataclass
class ControlFlowAnalysis:
    """Analysis of control flow obfuscation.

    Attributes:
        opaque_predicates: List of memory addresses containing opaque predicate
            patterns.
        indirect_jumps: List of memory addresses containing indirect jump
            instructions.
        control_flow_flattening: Boolean indicating presence of control flow
            flattening obfuscation.
        junk_code_blocks: List of (address, size) tuples for detected junk code
            blocks.
        obfuscation_density: Float representing the density of obfuscation as
            a percentage (0.0 to 1.0).
    """

    opaque_predicates: list[int] = field(default_factory=list)
    indirect_jumps: list[int] = field(default_factory=list)
    control_flow_flattening: bool = False
    junk_code_blocks: list[tuple[int, int]] = field(default_factory=list)
    obfuscation_density: float = 0.0


@dataclass
class RASPMechanism:
    """Runtime Application Self-Protection mechanism.

    Attributes:
        mechanism_type: Type of RASP protection (e.g., "anti_frida",
            "anti_debug", "anti_hook", "anti_vm", "exception_handler").
        address: Memory address where the RASP mechanism is detected.
        hook_target: Target of the hook or protection (e.g., "runtime", "SEH").
        detection_method: Method used to detect tampering (e.g.,
            "string_detection", "peb_check", "integrity_check",
            "signature_scan", "exception_based").
        severity: Severity level of the RASP mechanism ("low", "medium", or
            "high").
    """

    mechanism_type: str
    address: int
    hook_target: str
    detection_method: str
    severity: str


@dataclass
class LicenseValidationRoutine:
    """License validation routine information.

    Attributes:
        address: Memory address where the license validation routine is located.
        function_name: Derived function name based on address (e.g.,
            "license_check_0x12345678").
        algorithm: Cryptographic algorithm used for validation (e.g., "RSA",
            "AES", "custom").
        key_length: Key length in bits for cryptographic operations.
        validation_type: Type of license validation (e.g., "rsa_validation",
            "aes_license", "serial_check").
        crypto_operations: List of cryptographic operations detected in the
            routine (e.g., "modular_exponentiation", "sbox_substitution").
        string_references: List of string references found near the license
            validation routine.
    """

    address: int
    function_name: str
    algorithm: str
    key_length: int
    validation_type: str
    crypto_operations: list[str] = field(default_factory=list)
    string_references: list[str] = field(default_factory=list)


@dataclass
class IntegrityCheckMechanism:
    """Integrity check mechanism details.

    Attributes:
        address: Memory address where the integrity check is located or invoked.
        check_type: Type of integrity check (e.g., "hash_verification",
            "api_based").
        target_section: Section being checked (e.g., "code", "data", "all").
        hash_algorithm: Algorithm used for integrity verification (e.g.,
            "CRC32", "SHA256").
        check_frequency: How often the check occurs (e.g., "periodic",
            "on_load", "on_demand").
        bypass_strategy: Recommended bypass approach (e.g.,
            "hook_hash_function", "hook_crypto_api").
    """

    address: int
    check_type: str
    target_section: str
    hash_algorithm: str
    check_frequency: str
    bypass_strategy: str


@dataclass
class ArxanAnalysisResult:
    """Complete Arxan analysis result.

    Attributes:
        tamper_checks: List of detected anti-tampering check locations.
        control_flow: Control flow obfuscation analysis results.
        rasp_mechanisms: List of detected Runtime Application Self-Protection
            mechanisms.
        license_routines: List of detected license validation routines.
        integrity_checks: List of detected integrity check mechanisms.
        encrypted_strings: List of (address, size) tuples for encrypted string
            regions.
        white_box_crypto_tables: List of (address, size) tuples for white-box
            cryptography lookup tables.
        metadata: Dictionary containing analysis metadata (binary size, Arxan
            version, protection features, etc.).
    """

    tamper_checks: list[TamperCheckLocation] = field(default_factory=list)
    control_flow: ControlFlowAnalysis = field(default_factory=ControlFlowAnalysis)
    rasp_mechanisms: list[RASPMechanism] = field(default_factory=list)
    license_routines: list[LicenseValidationRoutine] = field(default_factory=list)
    integrity_checks: list[IntegrityCheckMechanism] = field(default_factory=list)
    encrypted_strings: list[tuple[int, int]] = field(default_factory=list)
    white_box_crypto_tables: list[tuple[int, int]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class ArxanAnalyzer:
    """Analyzes Arxan TransformIT protected binaries."""

    TAMPER_CHECK_SIGNATURES: dict[str, dict[str, list[bytes] | str]] = {
        "crc32": {
            "patterns": [
                b"\x33\xd2\x8a\x10\x8b\xc2\xc1\xe8\x08",
                b"\x8b\x55\x08\x33\xc0\x8a\x02",
            ],
            "complexity": "low",
        },
        "md5": {
            "patterns": [
                b"\x67\x45\x23\x01",
                b"\x01\x23\x45\x67\x89\xab\xcd\xef",
            ],
            "complexity": "medium",
        },
        "sha256": {
            "patterns": [
                b"\x6a\x09\xe6\x67",
                b"\x42\x8a\x2f\x98",
            ],
            "complexity": "high",
        },
        "hmac": {
            "patterns": [
                b"\x36\x36\x36\x36",
                b"\x5c\x5c\x5c\x5c",
            ],
            "complexity": "high",
        },
    }

    OPAQUE_PREDICATE_PATTERNS: list[bytes] = [
        b"\x85\xc0\x75\x02\x75\x00",
        b"\x85\xc0\x74\x02\x74\x00",
        b"\x33\xc0\x85\xc0\x74",
        b"\x33\xc0\x85\xc0\x75",
        b"\x83\xf8\x00\x74\x02\x74",
        b"\x0f\x85..\x00\x00\x0f\x84",
    ]

    RASP_DETECTION_PATTERNS: dict[str, list[bytes]] = {
        "anti_frida": [
            b"frida",
            b"gum-js-loop",
            b"frida-agent",
            b"/frida/",
        ],
        "anti_debug": [
            b"\x64\xa1\x30\x00\x00\x00\x0f\xb6\x40\x02",
            b"\x64\x8b\x05\x30\x00\x00\x00\x80\x78\x02\x00",
            b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00",
        ],
        "anti_hook": [
            b"\xe8....\x81\x38\x4d\x5a\x00\x00",
            b"\x8b\x45\x00\x3d\x4d\x5a\x00\x00",
        ],
        "anti_vm": [
            b"VMware",
            b"VBoxGuest",
            b"VBOX",
            b"QEMU",
        ],
    }

    LICENSE_VALIDATION_SIGNATURES: dict[str, list[bytes]] = {
        "rsa_validation": [
            b"\x00\x01\xff\xff",
            b"\x00\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01",
        ],
        "aes_license": [
            b"\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5",
            b"\x52\x09\x6a\xd5\x30\x36\xa5\x38",
        ],
        "serial_check": [
            b"-\x00-\x00-\x00-\x00",
            b"[A-Z0-9]{5}-[A-Z0-9]{5}",
        ],
    }

    def __init__(self) -> None:
        """Initialize ArxanAnalyzer with disassemblers and pattern matchers.

        Initializes Capstone disassemblers for x86 32-bit and 64-bit architectures,
        and sets up the Arxan detector for protection identification.
        """
        self.logger: logging.Logger = logging.getLogger(__name__)

        self.md_32: Any = None
        self.md_64: Any = None

        if CAPSTONE_AVAILABLE:
            self.md_32 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            self.md_32.detail = True
            self.md_64 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            self.md_64.detail = True
        else:
            self.logger.warning("Capstone not available - disassembly features disabled")

        self.detector: ArxanDetector = ArxanDetector()

    def analyze(self, binary_path: str | Path) -> ArxanAnalysisResult:
        """Perform comprehensive Arxan analysis.

        Args:
            binary_path: Path to binary to analyze

        Returns:
            ArxanAnalysisResult with detailed analysis

        Raises:
            FileNotFoundError: When the binary file does not exist.
        """
        binary_path = Path(binary_path)

        if not binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        self.logger.info("Starting Arxan analysis: %s", binary_path)

        detection_result = self.detector.detect(binary_path)

        if not detection_result.is_protected:
            self.logger.warning("Binary does not appear to be Arxan-protected")

        result = ArxanAnalysisResult()

        with open(binary_path, "rb") as f:
            binary_data = f.read()

        result.metadata["binary_size"] = len(binary_data)
        result.metadata["arxan_version"] = detection_result.version.value
        result.metadata["protection_features"] = detection_result.features

        result.tamper_checks = self._analyze_tamper_checks(binary_path, binary_data)
        result.control_flow = self._analyze_control_flow(binary_path, binary_data)
        result.rasp_mechanisms = self._analyze_rasp(binary_data)
        result.license_routines = self._analyze_license_validation(binary_path, binary_data)
        result.integrity_checks = self._analyze_integrity_checks(binary_path, binary_data)
        result.encrypted_strings = self._find_encrypted_strings(binary_data)
        result.white_box_crypto_tables = self._find_white_box_tables(binary_data)

        result.metadata["analysis_complete"] = True
        result.metadata["total_tamper_checks"] = len(result.tamper_checks)
        result.metadata["total_rasp_mechanisms"] = len(result.rasp_mechanisms)
        result.metadata["total_license_routines"] = len(result.license_routines)

        self.logger.info("Arxan analysis complete")

        return result

    def _analyze_tamper_checks(
        self, binary_path: Path, binary_data: bytes
    ) -> list[TamperCheckLocation]:
        """Analyze anti-tampering mechanisms.

        Scans binary data for tamper check signatures and analyzes executable
        sections of PE files for additional inline tamper detection patterns.

        Args:
            binary_path: Path to the binary file.
            binary_data: Raw binary data as bytes.

        Returns:
            List of detected tamper check locations.
        """
        tamper_checks: list[TamperCheckLocation] = []

        for check_type, info in self.TAMPER_CHECK_SIGNATURES.items():
            patterns = validate_type(info["patterns"], list)
            complexity = get_typed_item(info, "complexity", str)
            for pattern in patterns:
                offset: int = 0
                while True:
                    pos = binary_data.find(pattern, offset)
                    if pos == -1:
                        break

                    target_start = max(0, pos - 0x1000)
                    target_end = min(len(binary_data), pos + 0x1000)

                    tamper_check = TamperCheckLocation(
                        address=pos,
                        size=len(pattern),
                        check_type="tamper_detection",
                        target_region=(target_start, target_end),
                        algorithm=check_type,
                        bypass_complexity=complexity,
                    )
                    tamper_checks.append(tamper_check)

                    self.logger.debug("Found %s tamper check at 0x%x", check_type, pos)

                    offset = pos + 1

        if binary_path.suffix.lower() in [".exe", ".dll", ".sys"] and PEFILE_AVAILABLE:
            try:
                pe = pefile.PE(str(binary_path))

                for section in pe.sections:
                    if section.IMAGE_SCN_MEM_EXECUTE:
                        section_data = section.get_data()
                        section_va = section.VirtualAddress

                        self._scan_section_for_tamper_checks(section_data, section_va, tamper_checks)

                pe.close()

            except Exception:
                self.logger.debug("PE section analysis error", exc_info=True)

        return tamper_checks

    def _scan_section_for_tamper_checks(
        self, section_data: bytes, section_va: int, tamper_checks: list[TamperCheckLocation]
    ) -> None:
        """Scan executable section for tamper check patterns.

        Detects inline tamper check patterns that involve memory reads followed
        by XOR/SUB operations, indicating checksum or comparison routines.

        Args:
            section_data: Raw bytes of the section to scan.
            section_va: Virtual address of the section.
            tamper_checks: List to append detected tamper checks to.
        """
        memory_read_patterns: list[bytes] = [
            b"\x8b\x45",
            b"\x8b\x55",
            b"\x8b\x4d",
            b"\x48\x8b\x45",
            b"\x48\x8b\x55",
        ]

        for i in range(0, len(section_data) - 20, 4):
            chunk = section_data[i : i + 20]

            if any(pattern in chunk for pattern in memory_read_patterns) and (b"\x33" in chunk or b"\x35" in chunk):
                tamper_check = TamperCheckLocation(
                    address=section_va + i,
                    size=20,
                    check_type="inline_check",
                    target_region=(section_va + i - 0x100, section_va + i + 0x100),
                    algorithm="xor_checksum",
                    bypass_complexity="medium",
                )
                tamper_checks.append(tamper_check)

    def _analyze_control_flow(
        self, binary_path: Path, binary_data: bytes
    ) -> ControlFlowAnalysis:
        """Analyze control flow obfuscation.

        Detects opaque predicates, indirect jumps, control flow flattening patterns,
        and junk code blocks to quantify overall obfuscation density.

        Args:
            binary_path: Path to the binary file.
            binary_data: Raw binary data as bytes.

        Returns:
            ControlFlowAnalysis containing obfuscation patterns and density.
        """
        analysis: ControlFlowAnalysis = ControlFlowAnalysis()

        for pattern in self.OPAQUE_PREDICATE_PATTERNS:
            offset: int = 0
            while True:
                pos = binary_data.find(pattern, offset)
                if pos == -1:
                    break

                analysis.opaque_predicates.append(pos)
                offset = pos + 1

        indirect_jump_patterns: list[bytes] = [
            b"\xff\x25",
            b"\xff\x15",
            b"\xff\xe0",
            b"\xff\xe1",
            b"\xff\xe2",
            b"\xff\xe3",
        ]

        for pattern in indirect_jump_patterns:
            offset = 0
            while True:
                pos = binary_data.find(pattern, offset)
                if pos == -1:
                    break

                analysis.indirect_jumps.append(pos)
                offset = pos + 1

        total_instructions: int = len(binary_data) // 4
        obfuscated_instructions: int = len(analysis.opaque_predicates) + len(analysis.indirect_jumps) + len(analysis.junk_code_blocks) * 10

        if len(analysis.opaque_predicates) > 100:
            analysis.control_flow_flattening = True

        try:
            if binary_path.suffix.lower() in [".exe", ".dll", ".sys"] and PEFILE_AVAILABLE:
                pe = pefile.PE(str(binary_path))

                for section in pe.sections:
                    if section.IMAGE_SCN_MEM_EXECUTE:
                        section_data = section.get_data()
                        junk_blocks = self._detect_junk_code(section_data, section.VirtualAddress)
                        analysis.junk_code_blocks.extend(junk_blocks)

                pe.close()

        except Exception:
            self.logger.debug("Control flow analysis error", exc_info=True)

        analysis.obfuscation_density = min(obfuscated_instructions / max(total_instructions, 1), 1.0)

        return analysis

    def _detect_junk_code(
        self, section_data: bytes, section_va: int
    ) -> list[tuple[int, int]]:
        """Detect junk code blocks.

        Identifies filler code patterns including NOP sequences, INT3 breakpoints,
        and padding instructions used to obfuscate executable sections.

        Args:
            section_data: Raw bytes of the section to analyze.
            section_va: Virtual address of the section.

        Returns:
            List of (address, size) tuples for detected junk code blocks.
        """
        junk_blocks: list[tuple[int, int]] = []

        junk_patterns: list[bytes] = [
            b"\x90\x90\x90\x90\x90",
            b"\xcc\xcc\xcc\xcc\xcc",
            b"\x0f\x1f\x00",
            b"\x0f\x1f\x40\x00",
            b"\x66\x90",
        ]

        for i in range(0, len(section_data) - 50, 10):
            chunk = section_data[i : i + 50]

            if any(pattern in chunk for pattern in junk_patterns):
                junk_blocks.append((section_va + i, 50))

        return junk_blocks

    def _analyze_rasp(self, binary_data: bytes) -> list[RASPMechanism]:
        """Analyze Runtime Application Self-Protection mechanisms.

        Args:
            binary_data: Raw binary data as bytes.

        Returns:
            List of detected RASP mechanisms.
        """
        rasp_mechanisms: list[RASPMechanism] = []

        for mechanism_type, patterns in self.RASP_DETECTION_PATTERNS.items():
            for pattern in patterns:
                offset: int = 0
                while True:
                    pos = binary_data.find(pattern, offset)
                    if pos == -1:
                        break

                    detection_method: str
                    severity: str
                    if mechanism_type == "anti_frida":
                        detection_method = "string_detection"
                        severity = "high"
                    elif mechanism_type == "anti_debug":
                        detection_method = "peb_check"
                        severity = "high"
                    elif mechanism_type == "anti_hook":
                        detection_method = "integrity_check"
                        severity = "medium"
                    else:
                        detection_method = "signature_scan"
                        severity = "medium"

                    rasp = RASPMechanism(
                        mechanism_type=mechanism_type,
                        address=pos,
                        hook_target="runtime",
                        detection_method=detection_method,
                        severity=severity,
                    )
                    rasp_mechanisms.append(rasp)

                    self.logger.debug("Found RASP mechanism: %s at 0x%x", mechanism_type, pos)

                    offset = pos + 1

        exception_handlers = self._find_exception_handlers(binary_data)
        for handler_addr in exception_handlers:
            rasp = RASPMechanism(
                mechanism_type="exception_handler",
                address=handler_addr,
                hook_target="SEH",
                detection_method="exception_based",
                severity="high",
            )
            rasp_mechanisms.append(rasp)

        return rasp_mechanisms

    def _find_exception_handlers(self, binary_data: bytes) -> list[int]:
        """Find exception handler installations.

        Args:
            binary_data: Raw binary data as bytes.

        Returns:
            List of addresses where exception handlers are installed.
        """
        handler_addresses: list[int] = []

        seh_patterns: list[bytes] = [
            b"\x64\xa1\x00\x00\x00\x00\x50",
            b"\x64\x89\x25\x00\x00\x00\x00",
            b"\xff\x15....\x50",
        ]

        for pattern in seh_patterns:
            offset = 0
            while True:
                pos = binary_data.find(pattern, offset)
                if pos == -1:
                    break

                handler_addresses.append(pos)
                offset = pos + 1

        return handler_addresses

    def _analyze_license_validation(
        self, binary_path: Path, binary_data: bytes
    ) -> list[LicenseValidationRoutine]:
        """Analyze license validation routines.

        Identifies RSA, AES, and serial number validation signatures, then correlates
        them with nearby license-related strings for enhanced context.

        Args:
            binary_path: Path to the binary file.
            binary_data: Raw binary data as bytes.

        Returns:
            List of detected license validation routines.
        """
        license_routines: list[LicenseValidationRoutine] = []

        for validation_type, patterns in self.LICENSE_VALIDATION_SIGNATURES.items():
            for pattern in patterns:
                offset: int = 0
                while True:
                    pos = binary_data.find(pattern, offset)
                    if pos == -1:
                        break

                    algorithm: str
                    key_length: int
                    crypto_ops: list[str]
                    if validation_type == "rsa_validation":
                        algorithm = "RSA"
                        key_length = 2048
                        crypto_ops = ["modular_exponentiation", "pkcs1_padding"]
                    elif validation_type == "aes_license":
                        algorithm = "AES"
                        key_length = 256
                        crypto_ops = ["sbox_substitution", "mix_columns"]
                    else:
                        algorithm = "custom"
                        key_length = 128
                        crypto_ops = ["string_compare"]

                    routine = LicenseValidationRoutine(
                        address=pos,
                        function_name=f"license_check_{pos:x}",
                        algorithm=algorithm,
                        key_length=key_length,
                        validation_type=validation_type,
                        crypto_operations=crypto_ops,
                    )

                    license_routines.append(routine)

                    self.logger.debug("Found license routine: %s at 0x%x", validation_type, pos)

                    offset = pos + 1

        license_strings = self._find_license_strings(binary_data)
        for routine in license_routines:
            nearby_strings = [s for addr, s in license_strings if abs(addr - routine.address) < 0x1000]
            routine.string_references = nearby_strings

        return license_routines

    def _find_license_strings(self, binary_data: bytes) -> list[tuple[int, str]]:
        """Find license-related strings.

        Args:
            binary_data: Raw binary data as bytes.

        Returns:
            List of (address, string) tuples for license-related strings.
        """
        license_keywords: list[bytes] = [
            b"license",
            b"serial",
            b"activation",
            b"registration",
            b"product",
            b"trial",
            b"expir",
        ]

        found_strings: list[tuple[int, str]] = []

        for keyword in license_keywords:
            offset: int = 0
            while True:
                pos = binary_data.find(keyword, offset)
                if pos == -1:
                    break

                start = max(0, pos - 50)
                end = min(len(binary_data), pos + 50)
                context = binary_data[start:end]

                try:
                    string_val = context.decode("utf-8", errors="ignore")
                    if string_val.strip():
                        found_strings.append((pos, string_val.strip()))
                except Exception:
                    self.logger.debug("Error decoding string at position %d", pos, exc_info=True)

                offset = pos + 1

        return found_strings

    def _analyze_integrity_checks(
        self, binary_path: Path, binary_data: bytes
    ) -> list[IntegrityCheckMechanism]:
        """Analyze integrity check mechanisms.

        Detects CRC32 and hash-based integrity verification patterns in binary code,
        and identifies cryptographic API imports used for signature verification.

        Args:
            binary_path: Path to the binary file.
            binary_data: Raw binary data as bytes.

        Returns:
            List of detected integrity check mechanisms.
        """
        integrity_checks: list[IntegrityCheckMechanism] = []

        crc_patterns: list[tuple[bytes, str, str, str]] = [
            (b"\xc1\xe8\x08\x33", "CRC32", "code", "periodic"),
            (b"\x33\x81", "CRC32", "data", "on_load"),
        ]

        for pattern, hash_algo, target, frequency in crc_patterns:
            offset: int = 0
            while True:
                pos = binary_data.find(pattern, offset)
                if pos == -1:
                    break

                check = IntegrityCheckMechanism(
                    address=pos,
                    check_type="hash_verification",
                    target_section=target,
                    hash_algorithm=hash_algo,
                    check_frequency=frequency,
                    bypass_strategy="hook_hash_function",
                )
                integrity_checks.append(check)

                offset = pos + 1

        try:
            if binary_path.suffix.lower() in [".exe", ".dll", ".sys"] and PEFILE_AVAILABLE:
                pe = pefile.PE(str(binary_path))

                if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        for imp in entry.imports:
                            if imp.name:
                                func_name = imp.name.decode() if isinstance(imp.name, bytes) else imp.name

                                if func_name in ["CryptHashData", "CryptVerifySignature"]:
                                    check = IntegrityCheckMechanism(
                                        address=imp.address,
                                        check_type="api_based",
                                        target_section="all",
                                        hash_algorithm="SHA256",
                                        check_frequency="on_demand",
                                        bypass_strategy="hook_crypto_api",
                                    )
                                    integrity_checks.append(check)

                pe.close()

        except Exception:
            self.logger.debug("Integrity check analysis error", exc_info=True)

        return integrity_checks

    def _find_encrypted_strings(self, binary_data: bytes) -> list[tuple[int, int]]:
        """Find encrypted string regions.

        Args:
            binary_data: Raw binary data as bytes.

        Returns:
            List of (address, size) tuples for encrypted string regions.
        """
        encrypted_regions: list[tuple[int, int]] = []

        xor_loop_pattern: bytes = b"\x30\x04"
        offset: int = 0

        while True:
            pos = binary_data.find(xor_loop_pattern, offset)
            if pos == -1:
                break

            start = pos
            end = min(pos + 256, len(binary_data))

            chunk = binary_data[start:end]
            printable = sum(32 <= b < 127 for b in chunk)

            if printable < len(chunk) * 0.1:
                encrypted_regions.append((start, end - start))

            offset = pos + 1

        return encrypted_regions

    def _find_white_box_tables(self, binary_data: bytes) -> list[tuple[int, int]]:
        """Find white-box cryptography lookup tables.

        Args:
            binary_data: Raw binary data as bytes.

        Returns:
            List of (address, size) tuples for white-box crypto tables.
        """
        tables: list[tuple[int, int]] = []

        for i in range(0, len(binary_data) - 2048, 256):
            chunk = binary_data[i : i + 2048]

            unique_bytes = len(set(chunk))

            if unique_bytes > 200:
                byte_freq: dict[int, int] = {}
                for byte in chunk:
                    byte_freq[byte] = byte_freq.get(byte, 0) + 1

                max_freq = max(byte_freq.values())
                avg_freq = len(chunk) / 256

                if max_freq < avg_freq * 3:
                    tables.append((i, 2048))

        return tables


def main() -> None:
    """Test entry point for Arxan analyzer.

    Parses command-line arguments and performs Arxan analysis on the specified
    binary file, outputting results in either human-readable or JSON format.
    """
    import argparse
    import json

    main_logger = logging.getLogger(__name__)

    parser = argparse.ArgumentParser(description="Arxan TransformIT Analyzer")
    parser.add_argument("binary", help="Binary file to analyze")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-j", "--json", action="store_true", help="Output JSON")

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    analyzer = ArxanAnalyzer()
    result = analyzer.analyze(args.binary)

    if args.json:
        output = {
            "tamper_checks": len(result.tamper_checks),
            "rasp_mechanisms": len(result.rasp_mechanisms),
            "license_routines": len(result.license_routines),
            "integrity_checks": len(result.integrity_checks),
            "encrypted_strings": len(result.encrypted_strings),
            "white_box_tables": len(result.white_box_crypto_tables),
            "control_flow": {
                "opaque_predicates": len(result.control_flow.opaque_predicates),
                "indirect_jumps": len(result.control_flow.indirect_jumps),
                "flattening": result.control_flow.control_flow_flattening,
                "density": result.control_flow.obfuscation_density,
            },
        }
        main_logger.info("%s", json.dumps(output, indent=2))
    else:
        main_logger.info("=== Arxan Analysis Results ===")
        main_logger.info("Tamper Checks: %d", len(result.tamper_checks))
        for check in result.tamper_checks[:5]:
            main_logger.info("  - 0x%x: %s (%s)", check.address, check.algorithm, check.bypass_complexity)

        main_logger.info("Control Flow Obfuscation:")
        main_logger.info("  Opaque Predicates: %d", len(result.control_flow.opaque_predicates))
        main_logger.info("  Indirect Jumps: %d", len(result.control_flow.indirect_jumps))
        main_logger.info("  Flow Flattening: %s", result.control_flow.control_flow_flattening)
        main_logger.info("  Obfuscation Density: %.2f%%", result.control_flow.obfuscation_density * 100)

        main_logger.info("RASP Mechanisms: %d", len(result.rasp_mechanisms))
        for rasp in result.rasp_mechanisms[:5]:
            main_logger.info("  - %s: %s (%s)", rasp.mechanism_type, rasp.detection_method, rasp.severity)

        main_logger.info("License Validation Routines: %d", len(result.license_routines))
        for routine in result.license_routines[:5]:
            main_logger.info("  - 0x%x: %s (%s)", routine.address, routine.algorithm, routine.validation_type)

        main_logger.info("Integrity Checks: %d", len(result.integrity_checks))
        for integrity_check in result.integrity_checks[:5]:
            main_logger.info("  - 0x%x: %s (%s)", integrity_check.address, integrity_check.hash_algorithm, integrity_check.bypass_strategy)

        main_logger.info("Encrypted String Regions: %d", len(result.encrypted_strings))
        main_logger.info("White-Box Crypto Tables: %d", len(result.white_box_crypto_tables))


if __name__ == "__main__":
    main()
