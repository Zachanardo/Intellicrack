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
from typing import Any


try:
    import capstone

    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False
    capstone = None

try:
    import lief

    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False
    lief = None

try:
    import pefile

    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False
    pefile = None

from intellicrack.core.protection_detection.arxan_detector import ArxanDetector


logger = logging.getLogger(__name__)


@dataclass
class TamperCheckLocation:
    """Location of anti-tampering check."""

    address: int
    size: int
    check_type: str
    target_region: tuple[int, int]
    algorithm: str
    bypass_complexity: str


@dataclass
class ControlFlowAnalysis:
    """Analysis of control flow obfuscation."""

    opaque_predicates: list[int] = field(default_factory=list)
    indirect_jumps: list[int] = field(default_factory=list)
    control_flow_flattening: bool = False
    junk_code_blocks: list[tuple[int, int]] = field(default_factory=list)
    obfuscation_density: float = 0.0


@dataclass
class RASPMechanism:
    """Runtime Application Self-Protection mechanism."""

    mechanism_type: str
    address: int
    hook_target: str
    detection_method: str
    severity: str


@dataclass
class LicenseValidationRoutine:
    """License validation routine information."""

    address: int
    function_name: str
    algorithm: str
    key_length: int
    validation_type: str
    crypto_operations: list[str] = field(default_factory=list)
    string_references: list[str] = field(default_factory=list)


@dataclass
class IntegrityCheckMechanism:
    """Integrity check mechanism details."""

    address: int
    check_type: str
    target_section: str
    hash_algorithm: str
    check_frequency: str
    bypass_strategy: str


@dataclass
class ArxanAnalysisResult:
    """Complete Arxan analysis result."""

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

    TAMPER_CHECK_SIGNATURES = {
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

    OPAQUE_PREDICATE_PATTERNS = [
        b"\x85\xc0\x75\x02\x75\x00",
        b"\x85\xc0\x74\x02\x74\x00",
        b"\x33\xc0\x85\xc0\x74",
        b"\x33\xc0\x85\xc0\x75",
        b"\x83\xf8\x00\x74\x02\x74",
        b"\x0f\x85..\x00\x00\x0f\x84",
    ]

    RASP_DETECTION_PATTERNS = {
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

    LICENSE_VALIDATION_SIGNATURES = {
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
        """Initialize ArxanAnalyzer with disassemblers and pattern matchers."""
        self.logger = logging.getLogger(__name__)

        if CAPSTONE_AVAILABLE:
            self.md_32 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            self.md_32.detail = True
            self.md_64 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            self.md_64.detail = True
        else:
            self.md_32 = None
            self.md_64 = None
            self.logger.warning("Capstone not available - disassembly features disabled")

        self.detector = ArxanDetector()

    def analyze(self, binary_path: str | Path) -> ArxanAnalysisResult:
        """Perform comprehensive Arxan analysis.

        Args:
            binary_path: Path to binary to analyze

        Returns:
            ArxanAnalysisResult with detailed analysis

        """
        binary_path = Path(binary_path)

        if not binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        self.logger.info(f"Starting Arxan analysis: {binary_path}")

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

    def _analyze_tamper_checks(self, binary_path: Path, binary_data: bytes) -> list[TamperCheckLocation]:
        """Analyze anti-tampering mechanisms."""
        tamper_checks = []

        for check_type, info in self.TAMPER_CHECK_SIGNATURES.items():
            for pattern in info["patterns"]:
                offset = 0
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
                        bypass_complexity=info["complexity"],
                    )
                    tamper_checks.append(tamper_check)

                    self.logger.debug(f"Found {check_type} tamper check at 0x{pos:x}")

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

            except Exception as e:
                self.logger.debug(f"PE section analysis error: {e}")

        return tamper_checks

    def _scan_section_for_tamper_checks(self, section_data: bytes, section_va: int, tamper_checks: list[TamperCheckLocation]) -> None:
        """Scan executable section for tamper check patterns."""
        memory_read_patterns = [
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

    def _analyze_control_flow(self, binary_path: Path, binary_data: bytes) -> ControlFlowAnalysis:
        """Analyze control flow obfuscation."""
        analysis = ControlFlowAnalysis()

        for pattern in self.OPAQUE_PREDICATE_PATTERNS:
            offset = 0
            while True:
                pos = binary_data.find(pattern, offset)
                if pos == -1:
                    break

                analysis.opaque_predicates.append(pos)
                offset = pos + 1

        indirect_jump_patterns = [
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

        except Exception as e:
            self.logger.debug(f"Control flow analysis error: {e}")

        total_instructions = len(binary_data) // 4
        obfuscated_instructions = len(analysis.opaque_predicates) + len(analysis.indirect_jumps) + len(analysis.junk_code_blocks) * 10

        analysis.obfuscation_density = min(obfuscated_instructions / max(total_instructions, 1), 1.0)

        return analysis

    def _detect_junk_code(self, section_data: bytes, section_va: int) -> list[tuple[int, int]]:
        """Detect junk code blocks."""
        junk_blocks = []

        junk_patterns = [
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
        """Analyze Runtime Application Self-Protection mechanisms."""
        rasp_mechanisms = []

        for mechanism_type, patterns in self.RASP_DETECTION_PATTERNS.items():
            for pattern in patterns:
                offset = 0
                while True:
                    pos = binary_data.find(pattern, offset)
                    if pos == -1:
                        break

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

                    self.logger.debug(f"Found RASP mechanism: {mechanism_type} at 0x{pos:x}")

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
        """Find exception handler installations."""
        handler_addresses = []

        seh_patterns = [
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

    def _analyze_license_validation(self, binary_path: Path, binary_data: bytes) -> list[LicenseValidationRoutine]:
        """Analyze license validation routines."""
        license_routines = []

        for validation_type, patterns in self.LICENSE_VALIDATION_SIGNATURES.items():
            for pattern in patterns:
                offset = 0
                while True:
                    pos = binary_data.find(pattern, offset)
                    if pos == -1:
                        break

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

                    self.logger.debug(f"Found license routine: {validation_type} at 0x{pos:x}")

                    offset = pos + 1

        license_strings = self._find_license_strings(binary_data)
        for routine in license_routines:
            nearby_strings = [s for addr, s in license_strings if abs(addr - routine.address) < 0x1000]
            routine.string_references = nearby_strings

        return license_routines

    def _find_license_strings(self, binary_data: bytes) -> list[tuple[int, str]]:
        """Find license-related strings."""
        license_keywords = [
            b"license",
            b"serial",
            b"activation",
            b"registration",
            b"product",
            b"trial",
            b"expir",
        ]

        found_strings = []

        for keyword in license_keywords:
            offset = 0
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
                except Exception as e:
                    self.logger.debug(f"Error decoding string at position {pos}: {e}")

                offset = pos + 1

        return found_strings

    def _analyze_integrity_checks(self, binary_path: Path, binary_data: bytes) -> list[IntegrityCheckMechanism]:
        """Analyze integrity check mechanisms."""
        integrity_checks = []

        crc_patterns = [
            (b"\xc1\xe8\x08\x33", "CRC32", "code", "periodic"),
            (b"\x33\x81", "CRC32", "data", "on_load"),
        ]

        for pattern, hash_algo, target, frequency in crc_patterns:
            offset = 0
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

        except Exception as e:
            self.logger.debug(f"Integrity check analysis error: {e}")

        return integrity_checks

    def _find_encrypted_strings(self, binary_data: bytes) -> list[tuple[int, int]]:
        """Find encrypted string regions."""
        encrypted_regions = []

        xor_loop_pattern = b"\x30\x04"
        offset = 0

        while True:
            pos = binary_data.find(xor_loop_pattern, offset)
            if pos == -1:
                break

            start = pos
            end = min(pos + 256, len(binary_data))

            chunk = binary_data[start:end]
            printable = sum(bool(32 <= b < 127) for b in chunk)

            if printable < len(chunk) * 0.1:
                encrypted_regions.append((start, end - start))

            offset = pos + 1

        return encrypted_regions

    def _find_white_box_tables(self, binary_data: bytes) -> list[tuple[int, int]]:
        """Find white-box cryptography lookup tables."""
        tables = []

        for i in range(0, len(binary_data) - 2048, 256):
            chunk = binary_data[i : i + 2048]

            unique_bytes = len(set(chunk))

            if unique_bytes > 200:
                byte_freq = {}
                for byte in chunk:
                    byte_freq[byte] = byte_freq.get(byte, 0) + 1

                max_freq = max(byte_freq.values())
                avg_freq = len(chunk) / 256

                if max_freq < avg_freq * 3:
                    tables.append((i, 2048))

        return tables


def main() -> None:
    """Test entry point for Arxan analyzer."""
    import argparse
    import json

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
        print(json.dumps(output, indent=2))
    else:
        print("\n=== Arxan Analysis Results ===")
        print(f"\nTamper Checks: {len(result.tamper_checks)}")
        for check in result.tamper_checks[:5]:
            print(f"  - 0x{check.address:x}: {check.algorithm} ({check.bypass_complexity})")

        print("\nControl Flow Obfuscation:")
        print(f"  Opaque Predicates: {len(result.control_flow.opaque_predicates)}")
        print(f"  Indirect Jumps: {len(result.control_flow.indirect_jumps)}")
        print(f"  Flow Flattening: {result.control_flow.control_flow_flattening}")
        print(f"  Obfuscation Density: {result.control_flow.obfuscation_density:.2%}")

        print(f"\nRASP Mechanisms: {len(result.rasp_mechanisms)}")
        for rasp in result.rasp_mechanisms[:5]:
            print(f"  - {rasp.mechanism_type}: {rasp.detection_method} ({rasp.severity})")

        print(f"\nLicense Validation Routines: {len(result.license_routines)}")
        for routine in result.license_routines[:5]:
            print(f"  - 0x{routine.address:x}: {routine.algorithm} ({routine.validation_type})")

        print(f"\nIntegrity Checks: {len(result.integrity_checks)}")
        for check in result.integrity_checks[:5]:
            print(f"  - 0x{check.address:x}: {check.hash_algorithm} ({check.bypass_strategy})")

        print(f"\nEncrypted String Regions: {len(result.encrypted_strings)}")
        print(f"White-Box Crypto Tables: {len(result.white_box_crypto_tables)}")


if __name__ == "__main__":
    main()
