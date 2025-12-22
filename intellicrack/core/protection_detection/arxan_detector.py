"""Arxan TransformIT Detection Module for Intellicrack.

Detects Arxan TransformIT protection in binaries using signature-based analysis,
heuristic detection, and version fingerprinting for TransformIT 5.x, 6.x, and 7.x.

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
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any


try:
    import lief

    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False
    if TYPE_CHECKING:
        import lief
    else:
        lief = None  # type: ignore[assignment]

try:
    import pefile

    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False
    pefile = None

logger = logging.getLogger(__name__)


class ArxanVersion(Enum):
    """Arxan TransformIT version enumeration."""

    UNKNOWN = "unknown"
    TRANSFORM_5X = "5.x"
    TRANSFORM_6X = "6.x"
    TRANSFORM_7X = "7.x"
    TRANSFORM_8X = "8.x"


@dataclass
class ArxanProtectionFeatures:
    """Detected Arxan protection features."""

    anti_debugging: bool = False
    anti_tampering: bool = False
    control_flow_obfuscation: bool = False
    string_encryption: bool = False
    integrity_checks: bool = False
    rasp_protection: bool = False
    license_validation: bool = False
    code_virtualization: bool = False
    junk_code_insertion: bool = False
    api_wrapping: bool = False
    certificate_pinning: bool = False
    white_box_crypto: bool = False


@dataclass
class ArxanDetectionResult:
    """Result of Arxan detection analysis."""

    is_protected: bool
    confidence: float
    version: ArxanVersion
    features: ArxanProtectionFeatures
    signatures_found: list[str] = field(default_factory=list)
    sections: list[str] = field(default_factory=list)
    import_hints: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class ArxanDetector:
    """Detects Arxan TransformIT protection in binaries."""

    ARXAN_STRING_SIGNATURES = [
        b"Arxan",
        b"ARXAN",
        b"TransformIT",
        b"TRANSFORMIT",
        b"GuardIT",
        b"GUARDIT",
        b"arxan.com",
        b"arxantechnologies",
        b"Arxan Technologies",
        b"TAMResistant",
        b"GuardianSDK",
        b"arxan_runtime",
        b"arxan_init",
        b"arxan_validate",
        b"ARXAN_LICENSE",
        b"__arxan__",
        b".arxan",
        b"_ARXAN_",
        b"arxprotect",
        b"arx_check",
        b"arx_init",
        b"arx_verify",
        b"GuardianCore",
        b"TransformSDK",
    ]

    ARXAN_SECTION_NAMES = [
        b".arxan",
        b".arx",
        b".guard",
        b".grd",
        b".tamper",
        b".tamp",
        b".protect",
        b".prot",
        b".arxdata",
        b".arxcode",
        b".arxtext",
        b".guardit",
        b".transform",
        b".rasp",
        b".whitebox",
    ]

    ARXAN_API_PATTERNS = [
        "CryptProtectMemory",
        "CryptUnprotectMemory",
        "VirtualProtect",
        "VirtualAlloc",
        "FlushInstructionCache",
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "NtSetInformationThread",
        "OutputDebugString",
        "SetUnhandledExceptionFilter",
        "RaiseException",
        "GetTickCount",
        "QueryPerformanceCounter",
        "GetSystemTime",
    ]

    VERSION_SIGNATURES = {
        ArxanVersion.TRANSFORM_5X: [
            b"\x55\x8b\xec\x83\xec\x10\x56\x57\xe8",
            b"\x55\x8b\xec\x51\x51\x53\x56\x57\x8b\x7d\x08",
            b"\x40\x72\x78\x61\x6e\x35",
        ],
        ArxanVersion.TRANSFORM_6X: [
            b"\x55\x8b\xec\x83\xec\x20\x53\x56\x57\x8b\x7d",
            b"\x48\x89\x5c\x24\x08\x48\x89\x6c\x24\x10\x48\x89\x74\x24\x18",
            b"\x40\x72\x78\x61\x6e\x36",
        ],
        ArxanVersion.TRANSFORM_7X: [
            b"\x48\x89\x5c\x24\x10\x48\x89\x74\x24\x18\x57\x48\x83\xec\x20",
            b"\x40\x53\x48\x83\xec\x20\x48\x8b\xd9\xe8",
            b"\x40\x72\x78\x61\x6e\x37",
            b"\x48\x8b\xc4\x48\x89\x58\x08\x48\x89\x70\x10\x48\x89\x78\x18",
        ],
        ArxanVersion.TRANSFORM_8X: [
            b"\x48\x89\x5c\x24\x08\x48\x89\x6c\x24\x10\x48\x89\x74\x24\x18\x57\x41\x56",
            b"\x40\x72\x78\x61\x6e\x38",
            b"\x4c\x8b\xdc\x49\x89\x5b\x08\x49\x89\x6b\x10\x49\x89\x73\x18",
        ],
    }

    ANTI_DEBUG_PATTERNS = [
        b"\x64\xa1\x30\x00\x00\x00\x0f\xb6\x40\x02",
        b"\x64\x8b\x05\x30\x00\x00\x00\x80\x78\x02\x00",
        b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00",
        b"\xff\x15..\x00\x00\x85\xc0\x75",
        b"\xe8....\x85\xc0\x0f\x85",
        b"\xb8\x69\x00\x00\x00\xcd\x2e",
    ]

    INTEGRITY_CHECK_PATTERNS = [
        b"\x8b\x45\x08\x8b\x4d\x0c\x33\xd2\x8a\x10",
        b"\x8b\x55\x08\x8b\x45\x0c\x33\xc9\x8a\x0a",
        b"\x48\x8b\x45\x08\x48\x8b\x4d\x10\x33\xd2",
        b"\xf3\x0f\x7e\x05",
        b"\x66\x0f\x38\x00",
    ]

    def __init__(self) -> None:
        """Initialize ArxanDetector with pattern databases."""
        self.logger = logging.getLogger(__name__)

    def detect(self, binary_path: str | Path) -> ArxanDetectionResult:
        """Detect Arxan protection in binary.

        Args:
            binary_path: Path to binary file to analyze

        Returns:
            ArxanDetectionResult with detection details and confidence

        """
        binary_path = Path(binary_path)

        if not binary_path.exists():
            error_msg = f"Binary not found: {binary_path}"
            logger.error(error_msg)
            raise FileNotFoundError(error_msg)

        self.logger.info("Analyzing binary for Arxan protection: %s", binary_path)

        try:
            with open(binary_path, "rb") as f:
                binary_data = f.read()

            signatures_found: list[str] = []
            sections: list[str] = []
            import_hints: list[str] = []
            features = ArxanProtectionFeatures()
            metadata: dict[str, Any] = {}

            signature_score = self._check_string_signatures(binary_data, signatures_found)
            section_score = self._check_section_names(binary_path, sections)
            import_score = self._check_api_imports(binary_path, import_hints)
            version = self._detect_version(binary_data, metadata)
            heuristic_score = self._heuristic_analysis(binary_data, features, metadata)

            total_score = signature_score * 0.35 + section_score * 0.25 + import_score * 0.20 + heuristic_score * 0.20

            is_protected = total_score >= 0.50
            confidence = min(total_score, 1.0)

            self.logger.info(
                "Arxan detection complete: protected=%s, confidence=%.2f%%, version=%s",
                is_protected,
                confidence * 100,
                version.value,
            )

            return ArxanDetectionResult(
                is_protected=is_protected,
                confidence=confidence,
                version=version,
                features=features,
                signatures_found=signatures_found,
                sections=sections,
                import_hints=import_hints,
                metadata=metadata,
            )

        except Exception as e:
            self.logger.exception("Arxan detection failed: %s", e)
            raise

    def _check_string_signatures(self, binary_data: bytes, signatures_found: list[str]) -> float:
        """Check for Arxan string signatures in binary."""
        found_count = 0

        for signature in self.ARXAN_STRING_SIGNATURES:
            if signature in binary_data:
                sig_str = signature.decode("utf-8", errors="ignore")
                signatures_found.append(sig_str)
                found_count += 1
                self.logger.debug("Found Arxan signature: %s", sig_str)

        return min(found_count / 5.0, 1.0)

    def _check_section_names(self, binary_path: Path, sections: list[str]) -> float:
        """Check for Arxan-specific section names."""
        found_count = 0

        try:
            if binary_path.suffix.lower() in [".exe", ".dll", ".sys"] and PEFILE_AVAILABLE:
                pe = pefile.PE(str(binary_path))

                for section in pe.sections:
                    section_name = section.Name.strip(b"\x00")

                    for arxan_section in self.ARXAN_SECTION_NAMES:
                        if arxan_section in section_name.lower():
                            sec_str = section_name.decode("utf-8", errors="ignore")
                            sections.append(sec_str)
                            found_count += 1
                            self.logger.debug("Found Arxan section: %s", sec_str)
                            break

                pe.close()

            elif LIEF_AVAILABLE:
                if binary := lief.parse(str(binary_path)):
                    for section in binary.sections:
                        section_name_raw = section.name
                        if isinstance(section_name_raw, str):
                            section_name = section_name_raw.encode()
                        else:
                            section_name = section_name_raw

                        for arxan_section in self.ARXAN_SECTION_NAMES:
                            if arxan_section in section_name.lower():
                                section_str = section_name_raw if isinstance(section_name_raw, str) else section_name_raw.decode("utf-8", errors="ignore")
                                sections.append(section_str)
                                found_count += 1
                                self.logger.debug("Found Arxan section: %s", section_str)
                                break

        except Exception as e:
            self.logger.debug("Section analysis error: %s", e, exc_info=True)

        return min(found_count / 2.0, 1.0)

    def _check_api_imports(self, binary_path: Path, import_hints: list[str]) -> float:
        """Check for API imports commonly used by Arxan."""
        found_count = 0
        suspicious_count = 0

        try:
            if binary_path.suffix.lower() in [".exe", ".dll", ".sys"] and PEFILE_AVAILABLE:
                pe = pefile.PE(str(binary_path))

                if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        for imp in entry.imports:
                            if imp.name:
                                func_name = imp.name.decode() if isinstance(imp.name, bytes) else imp.name

                                if func_name in self.ARXAN_API_PATTERNS:
                                    if func_name not in import_hints:
                                        import_hints.append(func_name)
                                        suspicious_count += 1

                                    found_count += 1

                pe.close()

            elif LIEF_AVAILABLE:
                if binary := lief.parse(str(binary_path)):
                    if hasattr(binary, "imported_functions"):
                        for func in binary.imported_functions:
                            func_name_raw = func.name
                            func_name = func_name_raw if isinstance(func_name_raw, str) else (func_name_raw.decode("utf-8", errors="ignore") if isinstance(func_name_raw, bytes) else str(func_name_raw))

                            if func_name in self.ARXAN_API_PATTERNS:
                                if func_name not in import_hints:
                                    import_hints.append(func_name)
                                    suspicious_count += 1

                                found_count += 1

        except Exception as e:
            self.logger.debug("Import analysis error: %s", e, exc_info=True)

        if found_count >= 8:
            return min(suspicious_count / 5.0, 1.0)
        elif found_count >= 5:
            return 0.5
        else:
            return 0.0

    def _detect_version(self, binary_data: bytes, metadata: dict[str, Any]) -> ArxanVersion:
        """Detect Arxan TransformIT version."""
        version_scores = dict.fromkeys(ArxanVersion, 0)

        for version, patterns in self.VERSION_SIGNATURES.items():
            for pattern in patterns:
                if pattern in binary_data:
                    version_scores[version] += 1
                    self.logger.debug("Found %s version signature", version.value)

        best_version = ArxanVersion.UNKNOWN
        best_score = 0

        for version, score in version_scores.items():
            if score > best_score:
                best_score = score
                best_version = version

        metadata["version_scores"] = {v.value: s for v, s in version_scores.items()}
        metadata["detected_version"] = best_version.value

        return best_version

    def _heuristic_analysis(
        self,
        binary_data: bytes,
        features: ArxanProtectionFeatures,
        metadata: dict[str, Any],
    ) -> float:
        """Perform heuristic analysis for Arxan protection features."""
        score = 0.0
        feature_count = 0

        anti_debug_count = sum(pattern in binary_data for pattern in self.ANTI_DEBUG_PATTERNS)
        if anti_debug_count >= 2:
            features.anti_debugging = True
            score += 0.15
            feature_count += 1

        integrity_count = sum(pattern in binary_data for pattern in self.INTEGRITY_CHECK_PATTERNS)
        if integrity_count >= 2:
            features.integrity_checks = True
            features.anti_tampering = True
            score += 0.15
            feature_count += 1

        entropy = self._calculate_entropy(binary_data[: min(len(binary_data), 100000)])
        metadata["entropy"] = entropy

        if entropy > 7.5:
            features.code_virtualization = True
            features.control_flow_obfuscation = True
            score += 0.10
            feature_count += 1

        if self._check_string_encryption(binary_data):
            features.string_encryption = True
            score += 0.10
            feature_count += 1

        if self._check_control_flow_obfuscation(binary_data):
            features.control_flow_obfuscation = True
            features.junk_code_insertion = True
            score += 0.10
            feature_count += 1

        if self._check_rasp_indicators(binary_data):
            features.rasp_protection = True
            score += 0.15
            feature_count += 1

        if self._check_license_validation(binary_data):
            features.license_validation = True
            score += 0.15
            feature_count += 1

        if self._check_white_box_crypto(binary_data):
            features.white_box_crypto = True
            score += 0.10
            feature_count += 1

        metadata["feature_count"] = feature_count
        metadata["heuristic_score"] = score

        return score

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0

        import math

        frequency = [0] * 256
        for byte in data:
            frequency[byte] += 1

        entropy = 0.0
        data_len = len(data)

        for count in frequency:
            if count > 0:
                freq = float(count) / data_len
                entropy -= freq * math.log2(freq)

        return entropy

    def _check_string_encryption(self, binary_data: bytes) -> bool:
        """Check for encrypted string patterns."""
        xor_patterns = [
            b"\x80\x30",
            b"\x30\x04",
            b"\x32\x04",
            b"\x80\x34",
        ]

        for pattern in xor_patterns:
            if binary_data.count(pattern) > 10:
                return True

        printable_ratio = sum(32 <= b < 127 for b in binary_data[:10000]) / min(len(binary_data), 10000)

        return printable_ratio < 0.05

    def _check_control_flow_obfuscation(self, binary_data: bytes) -> bool:
        """Check for control flow obfuscation patterns."""
        jmp_patterns = [
            b"\xe9",
            b"\xeb",
            b"\xff\x25",
            b"\xff\x15",
        ]

        jmp_count = sum(binary_data.count(pattern) for pattern in jmp_patterns)

        if jmp_count > 500:
            return True

        opaque_predicate_patterns = [
            b"\x85\xc0\x75\x02\x75\x00",
            b"\x85\xc0\x74\x02\x74\x00",
            b"\x0f\x85..\x00\x00\x0f\x84",
        ]

        return any(pattern in binary_data for pattern in opaque_predicate_patterns)

    def _check_rasp_indicators(self, binary_data: bytes) -> bool:
        """Check for Runtime Application Self-Protection indicators."""
        rasp_strings = [
            b"tamper",
            b"rootkit",
            b"frida",
            b"xposed",
            b"substrate",
            b"hook",
            b"inject",
            b"memory_check",
            b"runtime_check",
        ]

        rasp_count = sum(s in binary_data.lower() for s in rasp_strings)

        if rasp_count >= 3:
            return True

        exception_handler_patterns = [
            b"\x64\xa1\x00\x00\x00\x00\x50",
            b"\x64\x89\x25\x00\x00\x00\x00",
            b"\xff\x15....\x85\xc0\x74",
        ]

        return any(binary_data.count(pattern) > 5 for pattern in exception_handler_patterns)

    def _check_license_validation(self, binary_data: bytes) -> bool:
        """Check for license validation routines."""
        license_strings = [
            b"license",
            b"serial",
            b"activation",
            b"registration",
            b"product_key",
            b"auth",
            b"validate",
            b"verify",
            b"expir",
            b"trial",
        ]

        license_count = sum(s in binary_data.lower() for s in license_strings)

        if license_count >= 4:
            return True

        crypto_license_patterns = [
            b"\x55\x8b\xec\x83\xec.\x53\x56\x57\x8b\x7d\x08\x8b\x75\x0c",
            b"\x48\x89\x5c\x24\x08\x57\x48\x83\xec\x20\x48\x8b\xf9\x48\x8b\xda",
        ]

        return any(pattern in binary_data for pattern in crypto_license_patterns)

    def _check_white_box_crypto(self, binary_data: bytes) -> bool:
        """Check for white-box cryptography implementations."""
        large_lookup_tables = 0
        offset = 0

        while offset < len(binary_data) - 1024:
            chunk = binary_data[offset : offset + 1024]

            unique_bytes = len(set(chunk))
            if unique_bytes > 200:
                large_lookup_tables += 1

            offset += 512

        if large_lookup_tables > 10:
            return True

        aes_sbox_partial = b"\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5"
        return aes_sbox_partial in binary_data and binary_data.count(aes_sbox_partial) > 4


def main() -> None:
    """Test entry point for Arxan detector."""
    import argparse

    parser = argparse.ArgumentParser(description="Arxan TransformIT Detector")
    parser.add_argument("binary", help="Binary file to analyze")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    detector = ArxanDetector()
    result = detector.detect(args.binary)

    logger.info("=== Arxan Detection Results ===")
    logger.info("Protected: %s", result.is_protected)
    logger.info("Confidence: %.2f%%", result.confidence * 100)
    logger.info("Version: %s", result.version.value)

    logger.info("=== Protection Features ===")
    features_dict = {
        "Anti-Debugging": result.features.anti_debugging,
        "Anti-Tampering": result.features.anti_tampering,
        "Control Flow Obfuscation": result.features.control_flow_obfuscation,
        "String Encryption": result.features.string_encryption,
        "Integrity Checks": result.features.integrity_checks,
        "RASP Protection": result.features.rasp_protection,
        "License Validation": result.features.license_validation,
        "Code Virtualization": result.features.code_virtualization,
        "Junk Code Insertion": result.features.junk_code_insertion,
        "White-Box Crypto": result.features.white_box_crypto,
    }

    for feature, enabled in features_dict.items():
        status = "YES" if enabled else "NO"
        logger.info("  %s: %s", feature, status)

    if result.signatures_found:
        logger.info("=== Signatures Found (%d) ===", len(result.signatures_found))
        for sig in result.signatures_found[:10]:
            logger.info("  - %s", sig)

    if result.sections:
        logger.info("=== Arxan Sections (%d) ===", len(result.sections))
        for section in result.sections:
            logger.info("  - %s", section)

    if result.import_hints:
        logger.info("=== Suspicious Imports (%d) ===", len(result.import_hints))
        for imp in result.import_hints[:10]:
            logger.info("  - %s", imp)


if __name__ == "__main__":
    main()
