"""ASProtect Protection Detection Module.

Provides comprehensive detection of ASProtect software protection including
anti-debugging mechanisms, integrity checks, license validation routines, and
version fingerprinting for ASProtect 1.x through 2.x variants.
"""

import logging
import winreg
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

try:
    import pefile

    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    import yara

    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


class ASProtectVersion(Enum):
    """ASProtect version enumeration."""

    UNKNOWN = "unknown"
    V1_X = "1.x"
    V2_0 = "2.0"
    V2_1 = "2.1"
    V2_2 = "2.2"
    V2_3 = "2.3"
    SKE = "SKE"


@dataclass
class ASProtectFeatures:
    """Detected ASProtect protection features."""

    anti_debugging: bool = False
    anti_dumping: bool = False
    api_redirection: bool = False
    crc_checks: bool = False
    import_protection: bool = False
    registration_system: bool = False
    trial_limitations: bool = False
    code_encryption: bool = False
    resource_protection: bool = False
    anti_monitoring: bool = False
    hardware_locking: bool = False
    compression: bool = False


@dataclass
class ASProtectDetection:
    """Results from ASProtect detection analysis."""

    detected: bool
    version: ASProtectVersion
    confidence: float
    features: ASProtectFeatures
    signatures_found: list[str] = field(default_factory=list)
    protected_sections: list[str] = field(default_factory=list)
    registry_keys: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)


class ASProtectDetector:
    """Comprehensive ASProtect software protection detection system.

    Detects ASProtect through signature analysis, PE structure examination,
    registry artifacts, and behavioral pattern recognition.
    """

    STRING_SIGNATURES = [
        b"ASProtect",
        b"ASPROTECT",
        b"ASPack",
        b"ASPACK",
        b"Alexey Solodovnikov",
        b"www.aspack.com",
        b"ASProtect SKE",
        b"kkrunchy",
        b".aspack",
        b".asprotect",
        b".adata",
        b".acode",
        b"ASPRHide",
        b"ASProtectLoader",
        b"ASPack_Magic",
        b"REGISTRY_ASPROTECT",
        b"ASPR_KEY",
        b"ASPR_HWID",
    ]

    SECTION_NAMES = [
        b".aspack",
        b".adata",
        b".acode",
        b".asprotect",
        b".petite",
        b".packed",
        b".enigma",
        b".encrypt",
        b".protect",
    ]

    REGISTRY_KEYS = [
        r"SOFTWARE\ASProtect",
        r"SOFTWARE\Wow6432Node\ASProtect",
        r"SOFTWARE\ASPack",
        r"SOFTWARE\Wow6432Node\ASPack",
    ]

    VERSION_SIGNATURES: dict[ASProtectVersion, list[bytes]] = {
        ASProtectVersion.V1_X: [
            b"\x60\x90\xe8\x03\x00\x00\x00\xe9\xeb",
            b"\x60\xe8\x00\x00\x00\x00\x5d\x81\xed",
            b"\x41\x53\x50\x72\x6f\x74\x65\x63\x74\x31",
        ],
        ASProtectVersion.V2_0: [
            b"\x60\xe8\x01\x00\x00\x00\x90\x5d\x81\xed",
            b"\x90\x60\xe8\x03\x00\x00\x00\xe9\xeb\x04",
            b"\x41\x53\x50\x72\x6f\x74\x65\x63\x74\x32\x30",
        ],
        ASProtectVersion.V2_1: [
            b"\x60\x90\x90\xe8\x03\x00\x00\x00\xe9\xeb",
            b"\x90\x60\xe8\x01\x00\x00\x00\x90\x5d",
            b"\x41\x53\x50\x72\x6f\x74\x65\x63\x74\x32\x31",
        ],
        ASProtectVersion.V2_2: [
            b"\x68\x00\x00\x00\x00\xe8\x01\x00\x00\x00\xc3\xc3",
            b"\x90\x60\xe8\x00\x00\x00\x00\x5d\x50\x51",
            b"\x41\x53\x50\x72\x6f\x74\x65\x63\x74\x32\x32",
        ],
        ASProtectVersion.V2_3: [
            b"\x90\x60\xe8\x03\x00\x00\x00\xe9\xeb\x04\x5d\x45\x55",
            b"\x68\x00\x00\x00\x00\xe8\x00\x00\x00\x00\x5d",
            b"\x41\x53\x50\x72\x6f\x74\x65\x63\x74\x32\x33",
        ],
        ASProtectVersion.SKE: [
            b"SKE\x00",
            b"ASProtect SKE",
            b"\x90\x90\x90\x60\xe8\x00\x00\x00\x00\x5d\x81\xed",
        ],
    }

    ANTI_DEBUG_PATTERNS = [
        b"\x64\xa1\x30\x00\x00\x00\x0f\xb6\x40\x02",
        b"\x64\x8b\x05\x30\x00\x00\x00\x80\x78\x02\x00",
        b"\xff\x15..\x00\x00\x85\xc0\x75",
        b"\xb8\x69\x00\x00\x00\xcd\x2e",
        b"\x8b\x45\x04\x8b\x00\x3d\x00\x50\x00\x00",
    ]

    CRC_CHECK_PATTERNS = [
        b"\x8b\x45\x08\x8b\x4d\x0c\x33\xd2\x8a\x10",
        b"\x33\xc0\x33\xdb\x8a\x04\x0e\x32\xc3",
        b"\xf7\xd1\x33\xc8\xc1\xe9\x08",
    ]

    API_REDIRECT_PATTERNS = [
        b"\xe9....\x90\x90\x90\x90\x90",
        b"\xff\x25....",
        b"\x68....\xc3",
        b"\xeb\x05\xe8..\x00\x00",
    ]

    def __init__(self) -> None:
        """Initialize ASProtect detector."""
        self.logger: logging.Logger = logging.getLogger(__name__)
        self._yara_rules: Any | None = self._compile_yara_rules() if YARA_AVAILABLE else None

    def _compile_yara_rules(self) -> Any | None:
        """Compile YARA rules for ASProtect signature detection."""
        if not YARA_AVAILABLE:
            return None

        rules_source = """
        rule ASProtect_v1x {
            meta:
                description = "ASProtect v1.x protection"
                version = "1.x"
            strings:
                $sig1 = { 60 90 E8 03 00 00 00 E9 EB }
                $sig2 = { 60 E8 00 00 00 00 5D 81 ED }
                $str1 = "ASProtect" ascii nocase
                $str2 = "ASPACK" ascii nocase
            condition:
                (1 of ($sig*)) or (all of ($str*))
        }

        rule ASProtect_v2x {
            meta:
                description = "ASProtect v2.x protection"
                version = "2.x"
            strings:
                $sig1 = { 60 E8 01 00 00 00 90 5D 81 ED }
                $sig2 = { 90 60 E8 03 00 00 00 E9 EB 04 }
                $sig3 = { 68 00 00 00 00 E8 01 00 00 00 C3 C3 }
                $str1 = "ASProtect" ascii nocase
            condition:
                (1 of ($sig*)) and $str1
        }

        rule ASProtect_SKE {
            meta:
                description = "ASProtect SKE (Skeleton) variant"
                version = "SKE"
            strings:
                $ske1 = "ASProtect SKE" ascii
                $ske2 = "SKE" ascii
                $sig1 = { 90 90 90 60 E8 00 00 00 00 5D 81 ED }
            condition:
                ($ske1 or ($ske2 and $sig1))
        }

        rule ASProtect_Registration {
            meta:
                description = "ASProtect registration system"
            strings:
                $reg1 = "REGISTRY_ASPROTECT" ascii
                $reg2 = "ASPR_KEY" ascii
                $reg3 = "ASPR_HWID" ascii
                $reg4 = /[Rr]egistration/ ascii
                $reg5 = /[Ss]erial/ ascii
            condition:
                2 of them
        }

        rule ASProtect_Anti_Debug {
            meta:
                description = "ASProtect anti-debugging code"
            strings:
                $ad1 = { 64 A1 30 00 00 00 0F B6 40 02 }
                $ad2 = { FF 15 ?? ?? ?? ?? 85 C0 75 }
                $ad3 = { B8 69 00 00 00 CD 2E }
                $ad4 = "IsDebuggerPresent" ascii
                $ad5 = "CheckRemoteDebuggerPresent" ascii
            condition:
                2 of them
        }

        rule ASProtect_CRC_Check {
            meta:
                description = "ASProtect CRC integrity checking"
            strings:
                $crc1 = { 8B 45 08 8B 4D 0C 33 D2 8A 10 }
                $crc2 = { 33 C0 33 DB 8A 04 0E 32 C3 }
                $crc3 = { F7 D1 33 C8 C1 E9 08 }
            condition:
                2 of them
        }
        """

        try:
            return yara.compile(source=rules_source)
        except Exception as e:
            self.logger.debug("Failed to compile YARA rules: %s", e)
            return None

    def detect(self, target_path: Path) -> ASProtectDetection:
        """Perform comprehensive ASProtect detection.

        Args:
            target_path: Path to executable to analyze

        Returns:
            ASProtectDetection results with confidence score

        """
        signatures_found: list[str] = []
        protected_sections: list[str] = []
        registry_keys: list[str] = []
        features = ASProtectFeatures()
        details: dict[str, Any] = {}
        version = ASProtectVersion.UNKNOWN
        yara_matches: list[dict[str, str]] = []

        if target_path.exists():
            binary_data = target_path.read_bytes()

            signature_score = self._check_string_signatures(binary_data, signatures_found)
            section_score = self._detect_protected_sections(target_path, protected_sections)
            version = self._detect_version(binary_data)
            feature_score = self._detect_features(binary_data, features)

            if self._yara_rules:
                yara_matches = self._yara_scan(target_path)

            yara_score = min(len(yara_matches) / 3.0, 1.0) if yara_matches else 0.0

            registry_keys = self._detect_registry_keys()

            details["yara_matches"] = yara_matches
            details["entry_point_signature"] = self._get_entry_point_signature(target_path)
            details["import_protection"] = features.import_protection
            details["api_redirection_count"] = self._count_api_redirects(binary_data)

        else:
            signature_score = 0.0
            section_score = 0.0
            feature_score = 0.0
            yara_score = 0.0

        confidence = self._calculate_confidence(
            signature_score,
            section_score,
            feature_score,
            yara_score,
            len(registry_keys),
        )

        detected = confidence > 0.5

        return ASProtectDetection(
            detected=detected,
            version=version,
            confidence=confidence,
            features=features,
            signatures_found=signatures_found,
            protected_sections=protected_sections,
            registry_keys=registry_keys,
            details=details,
        )

    def _check_string_signatures(self, binary_data: bytes, signatures_found: list[str]) -> float:
        """Check for ASProtect string signatures in binary."""
        found_count = 0

        for signature in self.STRING_SIGNATURES:
            if signature in binary_data:
                sig_str = signature.decode("utf-8", errors="ignore")
                signatures_found.append(sig_str)
                found_count += 1
                self.logger.debug("Found ASProtect signature: %s", sig_str)

        return min(found_count / 4.0, 1.0)

    def _detect_protected_sections(self, target_path: Path, protected_sections: list[str]) -> float:
        """Detect ASProtect protected PE sections."""
        if not PEFILE_AVAILABLE:
            return 0.0

        found_count = 0

        try:
            pe = pefile.PE(str(target_path))

            for section in pe.sections:
                section_name = section.Name.decode("utf-8", errors="ignore").rstrip("\x00")

                if any(asp_name in section.Name for asp_name in self.SECTION_NAMES):
                    protected_sections.append(section_name)
                    found_count += 1

                if section.SizeOfRawData == 0 and section.Misc_VirtualSize > 0:
                    protected_sections.append(f"{section_name} (virtual)")
                    found_count += 1

                if section.Characteristics & 0xE0000000:
                    protected_sections.append(f"{section_name} (protected)")
                    found_count += 1

            pe.close()

        except Exception as e:
            self.logger.debug("Error analyzing PE sections: %s", e)

        return min(found_count / 2.0, 1.0)

    def _detect_version(self, binary_data: bytes) -> ASProtectVersion:
        """Detect ASProtect version from binary signatures."""
        version_scores: dict[ASProtectVersion, int] = {v: 0 for v in ASProtectVersion}

        for version, patterns in self.VERSION_SIGNATURES.items():
            for pattern in patterns:
                if pattern in binary_data:
                    version_scores[version] += 1
                    self.logger.debug("Found %s version signature", version.value)

        best_version = ASProtectVersion.UNKNOWN
        best_score = 0

        for version, score in version_scores.items():
            if score > best_score:
                best_score = score
                best_version = version

        return best_version

    def _detect_features(self, binary_data: bytes, features: ASProtectFeatures) -> float:
        """Detect ASProtect protection features."""
        score = 0.0

        anti_debug_count = sum(1 for pattern in self.ANTI_DEBUG_PATTERNS if pattern in binary_data)
        if anti_debug_count >= 2:
            features.anti_debugging = True
            score += 0.15

        crc_count = sum(1 for pattern in self.CRC_CHECK_PATTERNS if pattern in binary_data)
        if crc_count >= 1:
            features.crc_checks = True
            score += 0.1

        api_redirect_count = sum(1 for pattern in self.API_REDIRECT_PATTERNS if pattern in binary_data)
        if api_redirect_count >= 5:
            features.api_redirection = True
            score += 0.15

        if self._detect_registration_system(binary_data):
            features.registration_system = True
            score += 0.2

        if self._detect_import_protection(binary_data):
            features.import_protection = True
            score += 0.1

        if self._detect_code_encryption(binary_data):
            features.code_encryption = True
            score += 0.15

        if self._detect_anti_dumping(binary_data):
            features.anti_dumping = True
            score += 0.1

        entropy = self._calculate_entropy(binary_data[:min(len(binary_data), 50000)])
        if entropy > 7.0:
            features.compression = True
            score += 0.05

        return score

    def _detect_registration_system(self, binary_data: bytes) -> bool:
        """Detect registration/licensing system."""
        reg_strings = [
            b"registration",
            b"serial",
            b"license",
            b"activation",
            b"ASPR_KEY",
            b"HWID",
            b"product key",
            b"trial",
        ]

        reg_count = sum(1 for s in reg_strings if s.lower() in binary_data.lower())
        return reg_count >= 3

    def _detect_import_protection(self, binary_data: bytes) -> bool:
        """Detect import table protection."""
        import_patterns = [
            b"\x8b\x45\x3c\x03\xc5\x8b\x40\x78",
            b"\x8b\x4d\x3c\x03\xcd\x8b\x51\x78",
        ]

        return any(pattern in binary_data for pattern in import_patterns)

    def _detect_code_encryption(self, binary_data: bytes) -> bool:
        """Detect code encryption patterns."""
        decrypt_loops = [
            b"\x30\x04\x0e\x41\x81\xf9",
            b"\x80\x34\x08\xff\x40\x3d",
            b"\x32\x04\x0f\x47\x81\xff",
        ]

        return any(pattern in binary_data for pattern in decrypt_loops)

    def _detect_anti_dumping(self, binary_data: bytes) -> bool:
        """Detect anti-dumping techniques."""
        anti_dump_patterns = [
            b"\x64\xa1\x18\x00\x00\x00\x8b\x40\x30",
            b"\x8b\x45\x3c\x8b\x54\x05\x78",
        ]

        return any(pattern in binary_data for pattern in anti_dump_patterns)

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0

        import math

        frequency: list[int] = [0] * 256
        for byte in data:
            frequency[byte] += 1

        entropy = 0.0
        data_len = len(data)

        for count in frequency:
            if count > 0:
                freq = float(count) / data_len
                entropy -= freq * math.log2(freq)

        return entropy

    def _yara_scan(self, target_path: Path) -> list[dict[str, str]]:
        """Scan executable with YARA rules."""
        if not self._yara_rules:
            return []

        matches: list[dict[str, str]] = []

        try:
            results: Any = self._yara_rules.match(str(target_path))

            for match in results:
                matches.append(
                    {
                        "rule": str(match.rule),
                        "version": str(match.meta.get("version", "unknown")),
                        "description": str(match.meta.get("description", "")),
                    }
                )

        except Exception as e:
            self.logger.debug("Error in YARA signature detection: %s", e)

        return matches

    def _detect_registry_keys(self) -> list[str]:
        """Detect ASProtect registry keys."""
        detected: list[str] = []

        for key_path in self.REGISTRY_KEYS:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ)
                winreg.CloseKey(key)
                detected.append(key_path)
            except OSError:
                pass

        return detected

    def _get_entry_point_signature(self, target_path: Path) -> str:
        """Get signature bytes at entry point."""
        if not PEFILE_AVAILABLE:
            return ""

        try:
            pe = pefile.PE(str(target_path))
            ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint

            for section in pe.sections:
                if section.VirtualAddress <= ep < section.VirtualAddress + section.Misc_VirtualSize:
                    offset = ep - section.VirtualAddress + section.PointerToRawData
                    data = pe.get_memory_mapped_image()
                    ep_bytes = data[offset : offset + 16]
                    pe.close()
                    return " ".join(f"{b:02x}" for b in ep_bytes)

            pe.close()

        except Exception as e:
            self.logger.debug("Error getting entry point signature: %s", e)

        return ""

    def _count_api_redirects(self, binary_data: bytes) -> int:
        """Count API redirection patterns in binary."""
        count = 0
        for pattern in self.API_REDIRECT_PATTERNS:
            count += binary_data.count(pattern)
        return count

    def _calculate_confidence(
        self,
        signature_score: float,
        section_score: float,
        feature_score: float,
        yara_score: float,
        registry_count: int,
    ) -> float:
        """Calculate overall detection confidence score."""
        registry_score = min(registry_count / 2.0, 1.0)

        total_score = (
            signature_score * 0.30
            + section_score * 0.20
            + feature_score * 0.25
            + yara_score * 0.15
            + registry_score * 0.10
        )

        return min(total_score, 1.0)
