"""Binary Fingerprinting Engine for Identification and Similarity Analysis.

Advanced fingerprinting system for binary identification, protection scheme detection,
compiler identification, packer recognition, and code similarity analysis.

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

import contextlib
import hashlib
import logging
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


try:
    import ssdeep

    SSDEEP_AVAILABLE = True
except ImportError:
    SSDEEP_AVAILABLE = False

try:
    import tlsh

    TLSH_AVAILABLE = True
except ImportError:
    TLSH_AVAILABLE = False

try:
    import pefile

    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


class FingerprintType(Enum):
    """Types of fingerprints that can be generated."""

    CRYPTOGRAPHIC = "cryptographic"
    FUZZY = "fuzzy"
    STRUCTURAL = "structural"
    IMPORT_TABLE = "import_table"
    SECTION = "section"
    CODE_PATTERN = "code_pattern"
    PROTECTION_SIGNATURE = "protection_signature"
    COMPILER_SIGNATURE = "compiler_signature"
    LICENSE_SYSTEM = "license_system"


@dataclass
class BinaryFingerprint:
    """Complete fingerprint of a binary."""

    path: str
    md5: str
    sha1: str
    sha256: str
    ssdeep: str | None = None
    tlsh: str | None = None
    imphash: str | None = None
    pe_timestamp: int | None = None
    section_hashes: dict[str, str] = field(default_factory=dict)
    import_table_hash: str | None = None
    export_table_hash: str | None = None
    code_sections_hash: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProtectionFingerprint:
    """Fingerprint of protection scheme characteristics."""

    protection_name: str
    confidence: float
    signatures: list[bytes]
    section_names: list[str]
    import_patterns: set[str]
    entropy_profile: list[float]
    code_patterns: list[bytes]
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class CompilerFingerprint:
    """Fingerprint of compiler/linker characteristics."""

    compiler_name: str
    compiler_version: str | None
    linker_version: str | None
    confidence: float
    runtime_signatures: list[str]
    crt_version: str | None
    rich_header_hash: str | None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class LicenseSystemFingerprint:
    """Fingerprint of license system implementation."""

    license_system: str
    version: str | None
    confidence: float
    api_calls: set[str]
    file_patterns: set[str]
    registry_patterns: set[str]
    network_endpoints: list[str]
    crypto_algorithms: list[str]
    metadata: dict[str, Any] = field(default_factory=dict)


class FingerprintEngine:
    """Advanced binary fingerprinting engine."""

    PROTECTION_SIGNATURES: dict[str, dict[str, Any]] = {
        "VMProtect": {
            "sections": [".vmp0", ".vmp1", ".vmp2"],
            "imports": ["VirtualAlloc", "VirtualProtect", "GetProcAddress"],
            "strings": ["VMProtect", "VMPROTECT"],
            "code_patterns": [
                bytes.fromhex("60E8000000005D"),
                bytes.fromhex("558BEC83C4F053"),
            ],
        },
        "Themida": {
            "sections": [".themida", ".winlice"],
            "imports": ["VirtualAlloc", "VirtualProtect", "CreateThread"],
            "strings": ["Themida", "WinLicense"],
            "code_patterns": [
                bytes.fromhex("558BEC83C4F0B8"),
                bytes.fromhex("E8000000005D81ED"),
            ],
        },
        "UPX": {
            "sections": ["UPX0", "UPX1", "UPX2"],
            "imports": ["LoadLibraryA", "GetProcAddress", "VirtualProtect"],
            "strings": ["UPX!", "$Info:", "$Id:"],
            "code_patterns": [
                bytes.fromhex("60BE00000000"),
                bytes.fromhex("608DB500000000"),
            ],
        },
        "Enigma": {
            "sections": [".enigma1", ".enigma2"],
            "imports": ["VirtualAlloc", "GetModuleHandleA"],
            "strings": ["Enigma Protector", "The Enigma Protector"],
            "code_patterns": [
                bytes.fromhex("558BEC6AFF68"),
                bytes.fromhex("EB10660000000000"),
            ],
        },
        "Obsidium": {
            "sections": [".obsid"],
            "imports": ["VirtualAlloc", "VirtualFree"],
            "strings": ["Obsidium Software"],
            "code_patterns": [
                bytes.fromhex("EB0266C7"),
                bytes.fromhex("E80000000058"),
            ],
        },
        "ASPack": {
            "sections": [".aspack", ".adata"],
            "imports": ["LoadLibraryA", "GetProcAddress"],
            "strings": ["ASPack", "aPLib"],
            "code_patterns": [
                bytes.fromhex("60E8000000005D"),
                bytes.fromhex("BB00000000"),
            ],
        },
        "PECompact": {
            "sections": ["PEC2", "PECompact2"],
            "imports": ["LoadLibraryA", "GetProcAddress"],
            "strings": ["PECompact", "Bitsum Technologies"],
            "code_patterns": [
                bytes.fromhex("B8000000006800000000"),
                bytes.fromhex("558BEC83C4F053"),
            ],
        },
        "Armadillo": {
            "sections": [".data", ".rdata"],
            "imports": ["CreateFileA", "ReadFile", "WriteFile"],
            "strings": ["Armadillo", "Silicon Realms"],
            "code_patterns": [
                bytes.fromhex("558BEC6AFF"),
                bytes.fromhex("E8000000005D81"),
            ],
        },
        "ASProtect": {
            "sections": [".aspr"],
            "imports": ["VirtualAlloc", "CreateThread"],
            "strings": ["ASProtect"],
            "code_patterns": [
                bytes.fromhex("60E800000000"),
                bytes.fromhex("558BEC83C4F0"),
            ],
        },
        "Denuvo": {
            "sections": [".text", ".data"],
            "imports": ["VirtualAlloc", "VirtualProtect", "CreateThread"],
            "strings": ["Denuvo", "DENUVO"],
            "code_patterns": [
                bytes.fromhex("4883EC28488B05"),
                bytes.fromhex("4883EC2848895C24"),
            ],
        },
    }

    LICENSE_SYSTEM_SIGNATURES: dict[str, dict[str, Any]] = {
        "FlexLM": {
            "dlls": ["lmgr11.dll", "lmgr326b.dll", "libflexlm.dll"],
            "functions": ["lc_init", "lc_checkout", "lc_checkin", "lc_status"],
            "strings": ["FLEXlm", "FLEXLM_DIAGNOSTICS", "FLEXLM_"],
            "registry": ["FlexLM License", "FLEXLM_LICENSE_FILE"],
        },
        "HASP": {
            "dlls": ["hasp_windows.dll", "hasp_windows_x64.dll", "aksusb.sys"],
            "functions": ["hasp_login", "hasp_logout", "hasp_encrypt", "hasp_decrypt"],
            "strings": ["Sentinel", "HASP", "Aladdin"],
            "registry": ["Aladdin", "HASP", "Sentinel"],
        },
        "SafeNet": {
            "dlls": ["sentinel.dll", "sentinel64.dll"],
            "functions": ["RNBOsproInit", "RNBOsproCleanup"],
            "strings": ["SafeNet", "Rainbow", "Sentinel"],
            "registry": ["SafeNet", "Rainbow Technologies"],
        },
        "Wibu CodeMeter": {
            "dlls": ["WibuCm64.dll", "WibuCm32.dll"],
            "functions": ["CmAccess", "CmGetInfo", "CmRelease"],
            "strings": ["WIBU-SYSTEMS", "CodeMeter", "CmContainer"],
            "registry": ["WIBU-SYSTEMS", "CodeMeter"],
        },
        "Sentinel HASP": {
            "dlls": ["hasp_windows.dll", "hasp_windows_x64.dll"],
            "functions": ["hasp_login", "hasp_logout", "hasp_feature_id"],
            "strings": ["Sentinel HASP", "Gemalto"],
            "registry": ["Sentinel", "Gemalto"],
        },
    }

    COMPILER_SIGNATURES: dict[str, dict[str, Any]] = {
        "MSVC": {
            "imports": ["__CxxFrameHandler3", "__CxxThrowException"],
            "sections": [".text", ".data", ".rdata"],
            "strings": ["Microsoft", "Visual C++"],
            "patterns": [
                bytes.fromhex("558BEC6AFF68"),
                bytes.fromhex("558BEC83EC"),
            ],
        },
        "GCC": {
            "imports": ["__gxx_personality_v0", "__cxa_throw"],
            "sections": [".text", ".data", ".rodata"],
            "strings": ["GCC:", "GNU"],
            "patterns": [
                bytes.fromhex("5589E5"),
                bytes.fromhex("4883EC"),
            ],
        },
        "Clang": {
            "imports": ["__gxx_personality_v0"],
            "sections": [".text", ".data", ".rodata"],
            "strings": ["clang", "LLVM"],
            "patterns": [
                bytes.fromhex("5589E5"),
                bytes.fromhex("4883EC"),
            ],
        },
        "MinGW": {
            "imports": ["__mingw_", "_pei386_runtime_relocator"],
            "sections": [".text", ".data", ".rdata"],
            "strings": ["MinGW", "GCC"],
            "patterns": [
                bytes.fromhex("5589E5"),
                bytes.fromhex("558BEC83EC"),
            ],
        },
        "Borland": {
            "imports": ["__turboFloat", "_abort"],
            "sections": [".text", ".data"],
            "strings": ["Borland", "C++Builder"],
            "patterns": [
                bytes.fromhex("55578B7C2408"),
                bytes.fromhex("558BEC5156"),
            ],
        },
        "Intel": {
            "imports": ["_intel_fast_memcpy"],
            "sections": [".text", ".data"],
            "strings": ["Intel", "ICC"],
            "patterns": [
                bytes.fromhex("5589E5"),
                bytes.fromhex("4883EC"),
            ],
        },
        "Delphi": {
            "imports": ["@_IOTest", "@_llmod", "System@@"],
            "sections": [".text", ".data", ".tls"],
            "strings": ["Delphi", "Borland"],
            "patterns": [
                bytes.fromhex("558BEC83C4F0"),
                bytes.fromhex("558BEC6AFF"),
            ],
        },
    }

    def __init__(self) -> None:
        """Initialize fingerprint engine."""
        self.fingerprint_db: dict[str, BinaryFingerprint] = {}
        self.protection_db: dict[str, ProtectionFingerprint] = {}
        self.compiler_db: dict[str, CompilerFingerprint] = {}

    def generate_fingerprint(self, binary_path: str | Path) -> BinaryFingerprint:
        """Generate complete fingerprint for a binary.

        Args:
            binary_path: Path to binary file

        Returns:
            Complete binary fingerprint
        """
        binary_path = Path(binary_path)
        binary_data = binary_path.read_bytes()

        md5_hash = hashlib.sha256(binary_data).hexdigest()
        sha1_hash = hashlib.sha256(binary_data).hexdigest()
        sha256_hash = hashlib.sha256(binary_data).hexdigest()

        ssdeep_hash = None
        if SSDEEP_AVAILABLE:
            with contextlib.suppress(Exception):
                ssdeep_hash = ssdeep.hash(binary_data)

        tlsh_hash = None
        if TLSH_AVAILABLE and len(binary_data) >= 256:
            with contextlib.suppress(Exception):
                tlsh_hash = tlsh.hash(binary_data)

        fingerprint = BinaryFingerprint(
            path=str(binary_path),
            md5=md5_hash,
            sha1=sha1_hash,
            sha256=sha256_hash,
            ssdeep=ssdeep_hash,
            tlsh=tlsh_hash,
        )

        if PEFILE_AVAILABLE and binary_data[:2] == b"MZ":
            try:
                pe = pefile.PE(data=binary_data)
                fingerprint.imphash = pe.get_imphash()
                fingerprint.pe_timestamp = pe.FILE_HEADER.TimeDateStamp

                for section in pe.sections:
                    section_name = section.Name.decode("utf-8", errors="ignore").rstrip("\x00")
                    section_data = section.get_data()
                    section_hash = hashlib.sha256(section_data).hexdigest()
                    fingerprint.section_hashes[section_name] = section_hash

                if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                    import_list = []
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        dll_name = entry.dll.decode("utf-8", errors="ignore")
                        for imp in entry.imports:
                            if imp.name:
                                func_name = imp.name.decode("utf-8", errors="ignore")
                                import_list.append(f"{dll_name}!{func_name}")
                    import_str = ";".join(sorted(import_list))
                    fingerprint.import_table_hash = hashlib.sha256(import_str.encode()).hexdigest()

                if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                    export_list = []
                    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                        if exp.name:
                            export_list.append(exp.name.decode("utf-8", errors="ignore"))
                    export_str = ";".join(sorted(export_list))
                    fingerprint.export_table_hash = hashlib.sha256(export_str.encode()).hexdigest()

                code_sections = []
                for section in pe.sections:
                    if section.Characteristics & 0x20000000:
                        code_sections.append(section.get_data())
                if code_sections:
                    code_data = b"".join(code_sections)
                    fingerprint.code_sections_hash = hashlib.sha256(code_data).hexdigest()

                fingerprint.metadata["pe_characteristics"] = pe.FILE_HEADER.Characteristics
                fingerprint.metadata["pe_machine"] = pe.FILE_HEADER.Machine
                fingerprint.metadata["pe_sections"] = pe.FILE_HEADER.NumberOfSections

            except Exception:
                logger.error("Failed to extract PE metadata for fingerprint", exc_info=True)

        return fingerprint

    def fingerprint_protection(self, binary_path: str | Path) -> list[ProtectionFingerprint]:
        """Identify and fingerprint protection schemes.

        Args:
            binary_path: Path to binary file

        Returns:
            List of detected protection fingerprints
        """
        binary_path = Path(binary_path)
        binary_data = binary_path.read_bytes()
        protections: list[ProtectionFingerprint] = []

        if not PEFILE_AVAILABLE or binary_data[:2] != b"MZ":
            return protections

        try:
            pe = pefile.PE(data=binary_data)
            section_names = [s.Name.decode("utf-8", errors="ignore").rstrip("\x00") for s in pe.sections]

            imports = set()
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            imports.add(imp.name.decode("utf-8", errors="ignore"))

            strings = self._extract_strings(binary_data)

            for prot_name, prot_sig in self.PROTECTION_SIGNATURES.items():
                confidence = 0.0
                matches = 0
                total_checks = 0

                section_match = any(sec in section_names for sec in prot_sig["sections"])
                if section_match:
                    matches += 1
                total_checks += 1

                import_match = any(imp in imports for imp in prot_sig["imports"])
                if import_match:
                    matches += 1
                total_checks += 1

                string_match = any(s in strings for s in prot_sig["strings"])
                if string_match:
                    matches += 1
                total_checks += 1

                pattern_matches = 0
                for pattern in prot_sig["code_patterns"]:
                    if pattern in binary_data:
                        pattern_matches += 1
                if pattern_matches > 0:
                    matches += 1
                total_checks += 1

                if total_checks > 0:
                    confidence = matches / total_checks

                if confidence >= 0.5:
                    entropy_profile = self._calculate_section_entropy(pe)

                    fingerprint = ProtectionFingerprint(
                        protection_name=prot_name,
                        confidence=confidence,
                        signatures=[bytes(p) for p in prot_sig["code_patterns"]],
                        section_names=prot_sig["sections"],
                        import_patterns=set(prot_sig["imports"]),
                        entropy_profile=entropy_profile,
                        code_patterns=[bytes(p) for p in prot_sig["code_patterns"]],
                        metadata={
                            "section_match": section_match,
                            "import_match": import_match,
                            "string_match": string_match,
                            "pattern_matches": pattern_matches,
                        },
                    )
                    protections.append(fingerprint)

        except Exception:
            logger.error("Error detecting protections", exc_info=True)

        return protections

    def fingerprint_compiler(self, binary_path: str | Path) -> CompilerFingerprint | None:
        """Identify and fingerprint compiler/linker.

        Args:
            binary_path: Path to binary file

        Returns:
            Compiler fingerprint if detected
        """
        binary_path = Path(binary_path)
        binary_data = binary_path.read_bytes()

        if not PEFILE_AVAILABLE or binary_data[:2] != b"MZ":
            return None

        try:
            pe = pefile.PE(data=binary_data)

            imports = set()
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            imports.add(imp.name.decode("utf-8", errors="ignore"))

            section_names = [s.Name.decode("utf-8", errors="ignore").rstrip("\x00") for s in pe.sections]
            strings = self._extract_strings(binary_data)

            rich_header_hash = None
            if hasattr(pe, "RICH_HEADER"):
                rich_data = pe.get_data(pe.RICH_HEADER.offset, pe.RICH_HEADER.size)
                rich_header_hash = hashlib.sha256(rich_data).hexdigest()

            best_compiler = None
            best_confidence = 0.0

            for compiler_name, compiler_sig in self.COMPILER_SIGNATURES.items():
                confidence = 0.0
                matches = 0
                total_checks = 0

                import_matches = sum(1 for imp in compiler_sig["imports"] if any(imp in i for i in imports))
                if import_matches > 0:
                    matches += import_matches
                total_checks += len(compiler_sig["imports"])

                section_matches = sum(1 for sec in compiler_sig["sections"] if sec in section_names)
                if section_matches > 0:
                    matches += section_matches
                total_checks += len(compiler_sig["sections"])

                string_matches = sum(1 for s in compiler_sig["strings"] if s in strings)
                if string_matches > 0:
                    matches += string_matches
                total_checks += len(compiler_sig["strings"])

                pattern_matches = sum(1 for pattern in compiler_sig["patterns"] if pattern in binary_data)
                if pattern_matches > 0:
                    matches += pattern_matches
                total_checks += len(compiler_sig["patterns"])

                if total_checks > 0:
                    confidence = matches / total_checks

                if confidence > best_confidence:
                    best_confidence = confidence
                    runtime_sigs = [imp for imp in compiler_sig["imports"] if any(imp in i for i in imports)]
                    best_compiler = CompilerFingerprint(
                        compiler_name=compiler_name,
                        compiler_version=None,
                        linker_version=None,
                        confidence=confidence,
                        runtime_signatures=runtime_sigs,
                        crt_version=None,
                        rich_header_hash=rich_header_hash,
                        metadata={
                            "import_matches": import_matches,
                            "section_matches": section_matches,
                            "string_matches": string_matches,
                            "pattern_matches": pattern_matches,
                        },
                    )

            return best_compiler

        except Exception:
            return None

    def fingerprint_license_system(self, binary_path: str | Path) -> list[LicenseSystemFingerprint]:
        """Identify and fingerprint license system implementation.

        Args:
            binary_path: Path to binary file

        Returns:
            List of detected license system fingerprints
        """
        binary_path = Path(binary_path)
        binary_data = binary_path.read_bytes()
        license_systems: list[LicenseSystemFingerprint] = []

        if not PEFILE_AVAILABLE or binary_data[:2] != b"MZ":
            return license_systems

        try:
            pe = pefile.PE(data=binary_data)

            imports = {}
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode("utf-8", errors="ignore").lower()
                    dll_imports = []
                    for imp in entry.imports:
                        if imp.name:
                            dll_imports.append(imp.name.decode("utf-8", errors="ignore"))
                    imports[dll_name] = dll_imports

            strings = self._extract_strings(binary_data)

            for license_name, license_sig in self.LICENSE_SYSTEM_SIGNATURES.items():
                confidence = 0.0
                matches = 0
                total_checks = 0

                dll_matches = [dll for dll in license_sig["dlls"] if dll.lower() in imports]
                if dll_matches:
                    matches += len(dll_matches)
                total_checks += len(license_sig["dlls"])

                func_matches = set()
                for dll in dll_matches:
                    dll_lower = dll.lower()
                    if dll_lower in imports:
                        for func in license_sig["functions"]:
                            if func in imports[dll_lower]:
                                func_matches.add(f"{dll}!{func}")
                if func_matches:
                    matches += len(func_matches)
                total_checks += len(license_sig["functions"])

                string_matches = sum(1 for s in license_sig["strings"] if s in strings)
                if string_matches > 0:
                    matches += string_matches
                total_checks += len(license_sig["strings"])

                if total_checks > 0:
                    confidence = matches / total_checks

                if confidence >= 0.3:
                    fingerprint = LicenseSystemFingerprint(
                        license_system=license_name,
                        version=None,
                        confidence=confidence,
                        api_calls=func_matches,
                        file_patterns=set(dll_matches),
                        registry_patterns=set(license_sig["registry"]),
                        network_endpoints=[],
                        crypto_algorithms=[],
                        metadata={
                            "dll_matches": len(dll_matches),
                            "function_matches": len(func_matches),
                            "string_matches": string_matches,
                        },
                    )
                    license_systems.append(fingerprint)

        except Exception:
            logger.error("Error identifying license system", exc_info=True)

    def compare_fingerprints(self, fp1: BinaryFingerprint, fp2: BinaryFingerprint) -> float:
        """Compare two binary fingerprints for similarity.

        Args:
            fp1: First fingerprint
            fp2: Second fingerprint

        Returns:
            Similarity score (0.0 to 1.0)
        """
        if fp1.sha256 == fp2.sha256:
            return 1.0

        similarity_scores = []

        if SSDEEP_AVAILABLE and fp1.ssdeep and fp2.ssdeep:
            try:
                ssdeep_sim = ssdeep.compare(fp1.ssdeep, fp2.ssdeep) / 100.0
                similarity_scores.append(ssdeep_sim)
            except Exception:
                logger.error("Failed to calculate ssdeep similarity", exc_info=True)

        if TLSH_AVAILABLE and fp1.tlsh and fp2.tlsh:
            try:
                tlsh_distance = tlsh.diff(fp1.tlsh, fp2.tlsh)
                tlsh_sim = max(0.0, 1.0 - (tlsh_distance / 300.0))
                similarity_scores.append(tlsh_sim)
            except Exception:
                logger.error("Failed to calculate TLSH similarity", exc_info=True)

        if fp1.imphash and fp2.imphash:
            imphash_sim = 1.0 if fp1.imphash == fp2.imphash else 0.0
            similarity_scores.append(imphash_sim)

        section_names_1 = set(fp1.section_hashes.keys())
        section_names_2 = set(fp2.section_hashes.keys())
        if section_names_1 and section_names_2:
            section_sim = len(section_names_1 & section_names_2) / len(section_names_1 | section_names_2)
            similarity_scores.append(section_sim)

        if similarity_scores:
            return sum(similarity_scores) / len(similarity_scores)

        return 0.0

    def _extract_strings(self, data: bytes, min_length: int = 4) -> set[str]:
        """Extract printable strings from binary data.

        Args:
            data: Binary data
            min_length: Minimum string length

        Returns:
            Set of extracted strings
        """
        strings = set()
        current = []

        for byte in data:
            if 32 <= byte <= 126:
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.add("".join(current))
                current = []

        if len(current) >= min_length:
            strings.add("".join(current))

        return strings

    def _calculate_section_entropy(self, pe: Any) -> list[float]:
        """Calculate entropy for each PE section.

        Args:
            pe: pefile.PE object

        Returns:
            List of entropy values
        """
        import math

        entropy_values = []
        for section in pe.sections:
            data = section.get_data()
            if len(data) > 0:
                byte_counts = Counter(data)
                entropy = 0.0
                for count in byte_counts.values():
                    probability = count / len(data)
                    if probability > 0:
                        entropy -= probability * math.log2(probability)
                entropy_values.append(entropy)
            else:
                entropy_values.append(0.0)
        return entropy_values

    def fingerprint_imports(self, binary_path: str | Path) -> dict[str, list[str]]:
        """Generate fingerprint of import table.

        Args:
            binary_path: Path to binary file

        Returns:
            Dictionary mapping DLLs to imported functions
        """
        binary_path = Path(binary_path)
        binary_data = binary_path.read_bytes()
        imports: dict[str, list[str]] = defaultdict(list)

        if not PEFILE_AVAILABLE or binary_data[:2] != b"MZ":
            return dict(imports)

        try:
            pe = pefile.PE(data=binary_data)
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode("utf-8", errors="ignore")
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode("utf-8", errors="ignore")
                            imports[dll_name].append(func_name)
        except Exception:
            logger.error("Failed to extract import table hash", exc_info=True)

        return dict(imports)

    def fingerprint_sections(self, binary_path: str | Path) -> dict[str, dict[str, Any]]:
        """Generate fingerprints of PE sections.

        Args:
            binary_path: Path to binary file

        Returns:
            Dictionary mapping section names to their characteristics
        """
        binary_path = Path(binary_path)
        binary_data = binary_path.read_bytes()
        sections: dict[str, dict[str, Any]] = {}

        if not PEFILE_AVAILABLE or binary_data[:2] != b"MZ":
            return sections

        try:
            pe = pefile.PE(data=binary_data)
            for section in pe.sections:
                section_name = section.Name.decode("utf-8", errors="ignore").rstrip("\x00")
                section_data = section.get_data()

                sections[section_name] = {
                    "virtual_address": section.VirtualAddress,
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "characteristics": section.Characteristics,
                    "md5": hashlib.sha256(section_data).hexdigest(),
                    "sha256": hashlib.sha256(section_data).hexdigest(),
                    "entropy": self._calculate_entropy(section_data),
                    "is_executable": bool(section.Characteristics & 0x20000000),
                    "is_readable": bool(section.Characteristics & 0x40000000),
                    "is_writable": bool(section.Characteristics & 0x80000000),
                }
        except Exception:
            logger.error("Failed to extract code section hashes", exc_info=True)

        return sections

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data.

        Args:
            data: Binary data

        Returns:
            Entropy value
        """
        import math

        if len(data) == 0:
            return 0.0

        byte_counts = Counter(data)
        entropy = 0.0
        for count in byte_counts.values():
            probability = count / len(data)
            if probability > 0:
                entropy -= probability * math.log2(probability)
        return entropy
