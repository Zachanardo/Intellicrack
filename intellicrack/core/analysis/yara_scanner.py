"""YARA Rule Scanner - Production Implementation.


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

import json
import logging
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yara

logger = logging.getLogger(__name__)


class RuleCategory(Enum):
    """Categories of YARA rules."""

    PACKER = "packer"
    PROTECTOR = "protector"
    CRYPTO = "crypto"
    LICENSE = "license"
    MALWARE = "malware"
    COMPILER = "compiler"
    ANTI_DEBUG = "anti_debug"
    ANTI_VM = "anti_vm"
    OBFUSCATION = "obfuscation"
    CUSTOM = "custom"


@dataclass
class YaraMatch:
    """Represents a YARA rule match."""

    rule_name: str
    category: RuleCategory
    offset: int
    matched_strings: List[Tuple[int, str, bytes]]
    tags: List[str]
    meta: Dict[str, Any]
    confidence: float


@dataclass
class ProtectionSignature:
    """Signature for a protection scheme."""

    name: str
    version: Optional[str]
    category: str
    signatures: List[bytes]
    entry_point_pattern: Optional[bytes]
    section_characteristics: Optional[Dict[str, Any]]
    imports: Optional[List[str]]


class YaraScanner:
    """YARA-based signature scanner for binary analysis."""

    # Built-in protection signatures
    PROTECTION_SIGNATURES = {
        "VMProtect": ProtectionSignature(
            name="VMProtect",
            version=None,
            category="protector",
            signatures=[
                b"\x56\x4d\x50\x72\x6f\x74\x65\x63\x74",  # "VMProtect"
                b"\x2e\x76\x6d\x70\x30",  # ".vmp0"
                b"\x2e\x76\x6d\x70\x31",  # ".vmp1"
                b"\x2e\x76\x6d\x70\x32",  # ".vmp2"
            ],
            entry_point_pattern=b"\x68\x00\x00\x00\x00\xe8",
            section_characteristics={"name": ".vmp", "flags": 0xE0000020},
            imports=None,
        ),
        "Themida": ProtectionSignature(
            name="Themida",
            version=None,
            category="protector",
            signatures=[
                b"\x54\x68\x65\x6d\x69\x64\x61",  # "Themida"
                b"\x2e\x74\x68\x65\x6d\x69\x64\x61",  # ".themida"
                b"\xb8\x00\x00\x00\x00\x60\x0b\xc0\x74\x58",
            ],
            entry_point_pattern=b"\xb8\x00\x00\x00\x00\x60\x0b\xc0",
            section_characteristics=None,
            imports=["SecureEngineSDK.dll"],
        ),
        "ASProtect": ProtectionSignature(
            name="ASProtect",
            version=None,
            category="protector",
            signatures=[
                b"\x41\x53\x50\x72\x6f\x74\x65\x63\x74",  # "ASProtect"
                b"\x2e\x61\x73\x70\x72",  # ".aspr"
                b"\x60\xe8\x03\x00\x00\x00\xe9\xeb\x04",
            ],
            entry_point_pattern=b"\x60\xe8\x03\x00\x00\x00",
            section_characteristics={"name": ".aspack", "flags": 0xE0000020},
            imports=None,
        ),
        "Denuvo": ProtectionSignature(
            name="Denuvo",
            version=None,
            category="protector",
            signatures=[
                b"\x44\x65\x6e\x75\x76\x6f",  # "Denuvo"
                b"\x2e\x64\x65\x6e\x75",  # ".denu"
                b"\x48\x8d\x05\x00\x00\x00\x00\x48\x89\x45",
            ],
            entry_point_pattern=None,
            section_characteristics=None,
            imports=["denuvo32.dll", "denuvo64.dll"],
        ),
        "UPX": ProtectionSignature(
            name="UPX",
            version=None,
            category="packer",
            signatures=[
                b"\x55\x50\x58\x21",  # "UPX!"
                b"\x55\x50\x58\x30",  # "UPX0"
                b"\x55\x50\x58\x31",  # "UPX1"
                b"\x55\x50\x58\x32",  # "UPX2"
            ],
            entry_point_pattern=b"\x60\xbe\x00\x00\x00\x00\x8d\xbe",
            section_characteristics={"name": "UPX", "flags": 0xE0000080},
            imports=None,
        ),
    }

    def __init__(self, rules_dir: Optional[Path] = None):
        """Initialize YARA scanner.

        Args:
            rules_dir: Directory containing YARA rule files
        """
        self.rules_dir = rules_dir or Path(__file__).parent / "yara_rules"
        self.compiled_rules: Dict[RuleCategory, yara.Rules] = {}
        self.custom_rules: Dict[str, yara.Rules] = {}
        self._load_builtin_rules()
        if self.rules_dir.exists():
            self._load_custom_rules()

    def _load_builtin_rules(self):
        """Load built-in YARA rules."""
        # Create built-in rules for each category
        builtin_rules = {
            RuleCategory.PACKER: self._create_packer_rules(),
            RuleCategory.PROTECTOR: self._create_protector_rules(),
            RuleCategory.CRYPTO: self._create_crypto_rules(),
            RuleCategory.LICENSE: self._create_license_rules(),
            RuleCategory.ANTI_DEBUG: self._create_antidebug_rules(),
            RuleCategory.COMPILER: self._create_compiler_rules(),
        }

        for category, rule_source in builtin_rules.items():
            try:
                self.compiled_rules[category] = yara.compile(source=rule_source)
                logger.info(f"Loaded built-in rules for {category.value}")
            except Exception as e:
                logger.error(f"Failed to compile {category.value} rules: {e}")

    def _create_packer_rules(self) -> str:
        """Create YARA rules for packer detection."""
        return """
rule UPX_Packer {
    meta:
        description = "Detects UPX packed executables"
        category = "packer"
        confidence = 90
    strings:
        $upx1 = "UPX!"
        $upx2 = "UPX0"
        $upx3 = "UPX1"
        $upx4 = "UPX2"
        $ep1 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? }
        $ep2 = { 80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 BE }
    condition:
        uint16(0) == 0x5A4D and
        (any of ($upx*) or any of ($ep*))
}

rule ASPack_Packer {
    meta:
        description = "Detects ASPack packed executables"
        category = "packer"
        confidence = 85
    strings:
        $aspack1 = "ASPack"
        $aspack2 = ".aspack"
        $ep = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? }
    condition:
        uint16(0) == 0x5A4D and
        (any of ($aspack*) or $ep)
}

rule PECompact_Packer {
    meta:
        description = "Detects PECompact packed executables"
        category = "packer"
        confidence = 85
    strings:
        $pec1 = "PECompact"
        $pec2 = "PEC2"
        $ep = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and
        (any of ($pec*) or $ep)
}
"""

    def _create_protector_rules(self) -> str:
        """Create YARA rules for protector detection."""
        return """
rule VMProtect_Protector {
    meta:
        description = "Detects VMProtect protected executables"
        category = "protector"
        confidence = 95
    strings:
        $vmp1 = "VMProtect"
        $vmp2 = ".vmp0"
        $vmp3 = ".vmp1"
        $vmp4 = ".vmp2"
        $ep = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? }
        $sig = { 9C 60 68 00 00 00 00 8B 74 24 28 }
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($vmp*) or ($ep and $sig))
}

rule Themida_Protector {
    meta:
        description = "Detects Themida protected executables"
        category = "protector"
        confidence = 95
    strings:
        $themida1 = "Themida"
        $themida2 = ".themida"
        $themida3 = "SecureEngineSDK.dll"
        $ep = { B8 00 00 00 00 60 0B C0 74 58 }
        $sig = { 8B C5 8B D4 60 E8 00 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and
        (any of ($themida*) or $ep or $sig)
}

rule Denuvo_Protector {
    meta:
        description = "Detects Denuvo protected executables"
        category = "protector"
        confidence = 90
    strings:
        $denuvo1 = "Denuvo"
        $denuvo2 = "denuvo32.dll"
        $denuvo3 = "denuvo64.dll"
        $sig1 = { 48 8D 05 ?? ?? ?? ?? 48 89 45 }
        $sig2 = { 48 89 5C 24 08 48 89 74 24 10 }
    condition:
        uint16(0) == 0x5A4D and
        (any of ($denuvo*) or all of ($sig*))
}

rule ASProtect_Protector {
    meta:
        description = "Detects ASProtect protected executables"
        category = "protector"
        confidence = 90
    strings:
        $asp1 = "ASProtect"
        $asp2 = ".aspr"
        $asp3 = ".adata"
        $ep = { 60 E8 03 00 00 00 E9 EB 04 }
        $sig = { 68 01 ?? ?? ?? C3 AA }
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($asp*) or $ep or $sig)
}
"""

    def _create_crypto_rules(self) -> str:
        """Create YARA rules for cryptographic algorithm detection."""
        return """
rule AES_Constants {
    meta:
        description = "Detects AES encryption constants"
        category = "crypto"
        confidence = 85
    strings:
        $sbox = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
        $rcon = { 01 00 00 00 02 00 00 00 04 00 00 00 08 00 00 00 }
        $td0 = { A5 63 63 C6 84 7C 7C F8 }
    condition:
        any of them
}

rule RSA_Operations {
    meta:
        description = "Detects RSA cryptographic operations"
        category = "crypto"
        confidence = 80
    strings:
        $bignum1 = "BN_mod_exp"
        $bignum2 = "BN_mod_mul"
        $rsa1 = "RSA_public_encrypt"
        $rsa2 = "RSA_private_decrypt"
        $padding = { 00 01 FF FF FF FF FF FF }
    condition:
        2 of them
}

rule SHA256_Constants {
    meta:
        description = "Detects SHA-256 hash constants"
        category = "crypto"
        confidence = 85
    strings:
        $k1 = { 67 E6 09 6A 85 AE 67 BB 72 F3 6E 3C 3A F5 4F A5 }
        $h1 = { 6A 09 E6 67 BB 67 AE 85 3C 6E F3 72 A5 4F F5 3A }
        $init = { 67 45 23 01 EF CD AB 89 98 BA DC FE 10 32 54 76 }
    condition:
        any of them
}

rule MD5_Constants {
    meta:
        description = "Detects MD5 hash constants"
        category = "crypto"
        confidence = 85
    strings:
        $init = { 01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10 }
        $sin1 = { 78 A4 6A D7 56 B7 C7 E8 }
        $sin2 = { DB 70 20 24 EE CE BD C1 }
    condition:
        any of them
}
"""

    def _create_license_rules(self) -> str:
        """Create YARA rules for license validation detection."""
        return """
rule License_Check_Patterns {
    meta:
        description = "Detects license validation routines"
        category = "license"
        confidence = 75
    strings:
        $lic1 = "Invalid license" nocase
        $lic2 = "License expired" nocase
        $lic3 = "Trial period" nocase
        $lic4 = "Product key" nocase
        $lic5 = "Serial number" nocase
        $lic6 = "Activation code" nocase
        $check1 = "CheckLicense"
        $check2 = "ValidateLicense"
        $check3 = "VerifyLicense"
    condition:
        2 of them
}

rule FlexLM_License {
    meta:
        description = "Detects FlexLM license manager"
        category = "license"
        confidence = 90
    strings:
        $flex1 = "FLEXlm"
        $flex2 = "lmgrd"
        $flex3 = "FLEXLM_DIAGNOSTICS"
        $flex4 = "vendor daemon"
        $api1 = "lc_checkout"
        $api2 = "lc_checkin"
    condition:
        2 of them
}

rule Sentinel_HASP {
    meta:
        description = "Detects Sentinel HASP license protection"
        category = "license"
        confidence = 90
    strings:
        $hasp1 = "hasp_login"
        $hasp2 = "hasp_logout"
        $hasp3 = "hasp_encrypt"
        $hasp4 = "HASP HL"
        $hasp5 = "Sentinel HASP"
    condition:
        2 of them
}

rule CodeMeter_License {
    meta:
        description = "Detects CodeMeter license protection"
        category = "license"
        confidence = 90
    strings:
        $cm1 = "CodeMeter"
        $cm2 = "CmStick"
        $cm3 = "WibuCm"
        $cm4 = "CmActLicense"
        $api1 = "CmGetLicenseInfo"
        $api2 = "CmCheckLicense"
    condition:
        2 of them
}
"""

    def _create_antidebug_rules(self) -> str:
        """Create YARA rules for anti-debugging detection."""
        return """
rule AntiDebug_IsDebuggerPresent {
    meta:
        description = "Detects IsDebuggerPresent anti-debug"
        category = "anti_debug"
        confidence = 95
    strings:
        $api1 = "IsDebuggerPresent"
        $api2 = "CheckRemoteDebuggerPresent"
        $api3 = "NtQueryInformationProcess"
        $peb = { 64 A1 30 00 00 00 0F B6 40 02 }
        $flag = { 64 8B 05 30 00 00 00 8B 40 68 }
    condition:
        any of them
}

rule AntiDebug_Timing {
    meta:
        description = "Detects timing-based anti-debug"
        category = "anti_debug"
        confidence = 80
    strings:
        $time1 = "GetTickCount"
        $time2 = "QueryPerformanceCounter"
        $time3 = "rdtsc"
        $cpuid = { 0F A2 }
        $rdtsc = { 0F 31 }
    condition:
        2 of them
}

rule AntiDebug_Exception {
    meta:
        description = "Detects exception-based anti-debug"
        category = "anti_debug"
        confidence = 85
    strings:
        $seh = "SetUnhandledExceptionFilter"
        $veh = "AddVectoredExceptionHandler"
        $int3 = { CC }
        $int2d = { CD 2D }
        $icebp = { F1 }
    condition:
        ($seh or $veh) and any of ($int*)
}
"""

    def _create_compiler_rules(self) -> str:
        """Create YARA rules for compiler detection."""
        return """
rule MSVC_Compiler {
    meta:
        description = "Detects Microsoft Visual C++ compiler"
        category = "compiler"
        confidence = 90
    strings:
        $msvc1 = "Microsoft Visual C++"
        $msvc2 = "MSVCR"
        $msvc3 = "MSVCP"
        $rich = "Rich"
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($msvc*) or $rich)
}

rule GCC_Compiler {
    meta:
        description = "Detects GCC compiler"
        category = "compiler"
        confidence = 85
    strings:
        $gcc1 = "GCC:"
        $gcc2 = "GNU C"
        $gcc3 = "gcc version"
        $mingw = "MinGW"
    condition:
        any of them
}

rule Delphi_Compiler {
    meta:
        description = "Detects Delphi/Borland compiler"
        category = "compiler"
        confidence = 90
    strings:
        $delphi1 = "Borland"
        $delphi2 = "Delphi"
        $delphi3 = "CodeGear"
        $tls = { 00 00 00 00 00 00 00 00 00 00 00 00 34 ?? ?? ?? }
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($delphi*) or $tls)
}
"""

    def _load_custom_rules(self):
        """Load custom YARA rules from directory."""
        for rule_file in self.rules_dir.glob("*.yar"):
            try:
                rules = yara.compile(filepath=str(rule_file))
                self.custom_rules[rule_file.stem] = rules
                logger.info(f"Loaded custom rule: {rule_file.stem}")
            except Exception as e:
                logger.error(f"Failed to load rule {rule_file}: {e}")

    def scan_file(self, file_path: Path, categories: Optional[List[RuleCategory]] = None) -> List[YaraMatch]:
        """Scan a file with YARA rules.

        Args:
            file_path: Path to file to scan
            categories: Categories to scan (None = all)

        Returns:
            List of YARA matches
        """
        matches = []

        # Determine which rules to use
        if categories:
            rules_to_scan = {cat: self.compiled_rules[cat] for cat in categories if cat in self.compiled_rules}
        else:
            rules_to_scan = self.compiled_rules

        # Scan with each rule set
        for category, rules in rules_to_scan.items():
            try:
                yara_matches = rules.match(str(file_path))

                for match in yara_matches:
                    yara_match = YaraMatch(
                        rule_name=match.rule,
                        category=category,
                        offset=match.strings[0][0] if match.strings else 0,
                        matched_strings=[(s[0], s[1], s[2]) for s in match.strings],
                        tags=match.tags,
                        meta=match.meta,
                        confidence=float(match.meta.get("confidence", 50)),
                    )
                    matches.append(yara_match)

            except Exception as e:
                logger.error(f"Failed to scan with {category.value} rules: {e}")

        # Scan with custom rules
        for rule_name, rules in self.custom_rules.items():
            try:
                yara_matches = rules.match(str(file_path))

                for match in yara_matches:
                    yara_match = YaraMatch(
                        rule_name=match.rule,
                        category=RuleCategory.CUSTOM,
                        offset=match.strings[0][0] if match.strings else 0,
                        matched_strings=[(s[0], s[1], s[2]) for s in match.strings],
                        tags=match.tags,
                        meta=match.meta,
                        confidence=float(match.meta.get("confidence", 50)),
                    )
                    matches.append(yara_match)

            except Exception as e:
                logger.error(f"Failed to scan with custom rule {rule_name}: {e}")

        return matches

    def scan_memory(self, pid: int, categories: Optional[List[RuleCategory]] = None) -> List[YaraMatch]:
        """Scan process memory with YARA rules.

        Args:
            pid: Process ID to scan
            categories: Categories to scan (None = all)

        Returns:
            List of YARA matches
        """
        matches = []

        # Determine which rules to use
        if categories:
            rules_to_scan = {cat: self.compiled_rules[cat] for cat in categories if cat in self.compiled_rules}
        else:
            rules_to_scan = self.compiled_rules

        # Scan process memory
        for category, rules in rules_to_scan.items():
            try:
                yara_matches = rules.match(pid=pid)

                for match in yara_matches:
                    yara_match = YaraMatch(
                        rule_name=match.rule,
                        category=category,
                        offset=match.strings[0][0] if match.strings else 0,
                        matched_strings=[(s[0], s[1], s[2]) for s in match.strings],
                        tags=match.tags,
                        meta=match.meta,
                        confidence=float(match.meta.get("confidence", 50)),
                    )
                    matches.append(yara_match)

            except Exception as e:
                logger.error(f"Failed to scan process {pid} with {category.value} rules: {e}")

        return matches

    def detect_protections(self, file_path: Path) -> Dict[str, Any]:
        """Detect protection schemes in a binary.

        Args:
            file_path: Path to binary file

        Returns:
            Dictionary of detected protections
        """
        protections = {"packers": [], "protectors": [], "crypto": [], "license": [], "anti_debug": [], "compiler": None}

        # Scan with protection-related categories
        matches = self.scan_file(
            file_path,
            categories=[
                RuleCategory.PACKER,
                RuleCategory.PROTECTOR,
                RuleCategory.CRYPTO,
                RuleCategory.LICENSE,
                RuleCategory.ANTI_DEBUG,
                RuleCategory.COMPILER,
            ],
        )

        # Organize matches by category
        for match in matches:
            if match.category == RuleCategory.PACKER:
                protections["packers"].append({"name": match.rule_name, "confidence": match.confidence, "offset": match.offset})
            elif match.category == RuleCategory.PROTECTOR:
                protections["protectors"].append({"name": match.rule_name, "confidence": match.confidence, "offset": match.offset})
            elif match.category == RuleCategory.CRYPTO:
                protections["crypto"].append({"algorithm": match.rule_name, "confidence": match.confidence, "offset": match.offset})
            elif match.category == RuleCategory.LICENSE:
                protections["license"].append({"type": match.rule_name, "confidence": match.confidence, "offset": match.offset})
            elif match.category == RuleCategory.ANTI_DEBUG:
                protections["anti_debug"].append({"technique": match.rule_name, "confidence": match.confidence, "offset": match.offset})
            elif match.category == RuleCategory.COMPILER:
                if protections["compiler"] is None or match.confidence > protections["compiler"]["confidence"]:
                    protections["compiler"] = {"name": match.rule_name, "confidence": match.confidence}

        # Also check with signature-based detection
        sig_detections = self._detect_by_signatures(file_path)
        protections["signature_based"] = sig_detections

        return protections

    def _detect_by_signatures(self, file_path: Path) -> List[Dict[str, Any]]:
        """Detect protections using byte signatures.

        Args:
            file_path: Path to binary file

        Returns:
            List of detected protections
        """
        detections = []

        try:
            with open(file_path, "rb") as f:
                # Read first 64KB for signature scanning
                data = f.read(65536)

                for name, signature in self.PROTECTION_SIGNATURES.items():
                    detected = False
                    confidence = 0

                    # Check byte signatures
                    for sig_bytes in signature.signatures:
                        if sig_bytes in data:
                            detected = True
                            confidence += 30
                            break

                    # Check entry point pattern
                    if signature.entry_point_pattern:
                        # Read entry point area
                        f.seek(0)
                        header = f.read(1024)
                        if signature.entry_point_pattern in header:
                            detected = True
                            confidence += 40

                    if detected:
                        detections.append({"name": name, "category": signature.category, "confidence": min(confidence, 95)})

        except Exception as e:
            logger.error(f"Failed to perform signature-based detection: {e}")

        return detections

    def create_custom_rule(self, rule_name: str, rule_content: str, category: RuleCategory = RuleCategory.CUSTOM) -> bool:
        """Create and compile a custom YARA rule.

        Args:
            rule_name: Name for the rule
            rule_content: YARA rule content
            category: Category for the rule

        Returns:
            True if successful
        """
        try:
            # Compile rule to verify syntax
            rules = yara.compile(source=rule_content)

            # Save to file
            rule_file = self.rules_dir / f"{rule_name}.yar"
            self.rules_dir.mkdir(parents=True, exist_ok=True)

            with open(rule_file, "w") as f:
                f.write(rule_content)

            # Store compiled rule
            self.custom_rules[rule_name] = rules

            logger.info(f"Created custom rule: {rule_name}")
            return True

        except Exception as e:
            logger.error(f"Failed to create custom rule: {e}")
            return False

    def compile_rules(self, incremental: bool = False, timeout: int = 30) -> bool:
        """Compile all loaded rules with performance optimization."""
        import hashlib
        import time

        try:
            # Generate hash of current rules for caching
            rules_hash = hashlib.sha256("".join(sorted(self.builtin_rules.values())).encode()).hexdigest()

            # Check if rules haven't changed (use cached compilation)
            if hasattr(self, "_rules_hash") and self._rules_hash == rules_hash:
                logger.debug("Rules unchanged, using cached compilation")
                return True

            # Combine all rules with error handling for individual rule failures
            valid_rules = []
            failed_rules = []

            for name, content in self.builtin_rules.items():
                try:
                    # Validate individual rule
                    yara.compile(source=content)
                    valid_rules.append(content)
                except Exception as e:
                    logger.warning(f"Rule '{name}' failed validation: {e}")
                    failed_rules.append(name)
                    if not incremental:
                        raise

            if not valid_rules:
                logger.error("No valid rules to compile")
                return False

            # Compile with timeout for large rule sets
            start_time = time.time()
            all_rules = "\n\n".join(valid_rules)

            # Add performance hints
            if len(valid_rules) > 100:
                # For large rule sets, compile with includes to reduce memory
                self.compiled_rules = yara.compile(source=all_rules, includes=True, error_on_warning=False)
            else:
                self.compiled_rules = yara.compile(source=all_rules)

            compile_time = time.time() - start_time
            logger.info(f"Compiled {len(valid_rules)} rules in {compile_time:.2f}s")

            # Remove failed rules from builtin_rules if incremental
            if incremental and failed_rules:
                for name in failed_rules:
                    del self.builtin_rules[name]
                logger.info(f"Removed {len(failed_rules)} invalid rules")

            # Cache the hash
            self._rules_hash = rules_hash
            return True

        except yara.TimeoutError:
            logger.error(f"Rule compilation timeout after {timeout}s")
            return False
        except Exception as e:
            logger.error(f"Failed to compile rules: {e}")
            return False

    def add_rule(
        self, rule_name: str, rule_content: str, category: RuleCategory = RuleCategory.LICENSE, validate_syntax: bool = True
    ) -> bool:
        """Add a new YARA rule with validation and categorization."""
        import re

        try:
            # Sanitize rule name
            safe_name = re.sub(r"[^a-zA-Z0-9_]", "_", rule_name)

            # Check for duplicate
            if safe_name in self.builtin_rules:
                logger.warning(f"Rule '{safe_name}' already exists, updating...")

            # Validate rule syntax if requested
            if validate_syntax:
                try:
                    test_compiled = yara.compile(source=rule_content)
                    # Test the rule on empty data to ensure it doesn't crash
                    test_compiled.match(data=b"test")
                except yara.SyntaxError as e:
                    logger.error(f"Rule syntax error: {e}")
                    return False
                except Exception as e:
                    logger.error(f"Rule validation error: {e}")
                    return False

            # Add metadata to rule if not present
            if "meta:" not in rule_content:
                # Insert metadata after rule name
                lines = rule_content.split("\n")
                for i, line in enumerate(lines):
                    if "{" in line:
                        lines.insert(
                            i + 1, f'    meta:\n        category = "{category.value}"\n        added_date = "{os.environ.get("DATE", "")}"'
                        )
                        break
                rule_content = "\n".join(lines)

            # Store rule with category tracking
            self.builtin_rules[safe_name] = rule_content
            if not hasattr(self, "_rule_categories"):
                self._rule_categories = {}
            self._rule_categories[safe_name] = category

            # Incremental compilation for performance
            return self.compile_rules(incremental=True)

        except Exception as e:
            logger.error(f"Failed to add rule {rule_name}: {e}")
            return False

    def remove_rule(self, rule_name: str, check_dependencies: bool = True) -> bool:
        """Remove a YARA rule with dependency checking."""
        if rule_name not in self.builtin_rules:
            logger.warning(f"Rule '{rule_name}' not found")
            return False

        try:
            # Check if other rules depend on this one
            if check_dependencies:
                for name, content in self.builtin_rules.items():
                    if name != rule_name and rule_name in content:
                        logger.warning(f"Rule '{name}' may depend on '{rule_name}'")
                        # Continue anyway but log the warning

            # Remove rule and its category
            del self.builtin_rules[rule_name]
            if hasattr(self, "_rule_categories") and rule_name in self._rule_categories:
                del self._rule_categories[rule_name]

            # Recompile remaining rules
            return self.compile_rules()

        except Exception as e:
            logger.error(f"Failed to remove rule {rule_name}: {e}")
            return False

    def scan_process(
        self, pid: int, categories: Optional[List[RuleCategory]] = None, scan_dlls: bool = True, scan_heap: bool = True
    ) -> List[YaraMatch]:
        """Scan a running process memory with advanced options."""
        import ctypes
        from ctypes import wintypes

        import psutil

        matches = []

        try:
            # Verify process exists
            if not psutil.pid_exists(pid):
                logger.error(f"Process {pid} does not exist")
                return matches

            # Get process info
            try:
                process = psutil.Process(pid)
                process_name = process.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                logger.error(f"Cannot access process {pid}: {e}")
                return matches

            # Open process with required permissions
            PROCESS_VM_READ = 0x0010
            PROCESS_QUERY_INFORMATION = 0x0400

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            process_handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)

            if not process_handle:
                # Try using YARA's built-in process scanning
                logger.info(f"Using YARA built-in scanning for process {pid}")
                try:
                    # Filter rules by category
                    if categories:
                        filtered_rules = self._filter_rules_by_category(categories)
                        if filtered_rules:
                            compiled = yara.compile(source=filtered_rules)
                        else:
                            compiled = self.compiled_rules
                    else:
                        compiled = self.compiled_rules

                    # Scan process
                    yara_matches = compiled.match(pid=pid)

                    for match in yara_matches:
                        matches.append(
                            YaraMatch(
                                rule_name=match.rule,
                                category=self._get_rule_category(match.rule),
                                matched_data=f"Process: {process_name} (PID: {pid})",
                                metadata={
                                    "pid": pid,
                                    "process_name": process_name,
                                    "strings": [(s.offset, s.matched_data) for s in match.strings],
                                },
                            )
                        )

                except Exception as e:
                    logger.error(f"YARA process scan failed: {e}")
            else:
                # Enhanced scanning with handle
                logger.info(f"Enhanced scanning of process {pid} with handle")

                # Enumerate memory regions
                class MEMORY_BASIC_INFORMATION(ctypes.Structure):
                    _fields_ = [
                        ("BaseAddress", ctypes.c_void_p),
                        ("AllocationBase", ctypes.c_void_p),
                        ("AllocationProtect", wintypes.DWORD),
                        ("RegionSize", ctypes.c_size_t),
                        ("State", wintypes.DWORD),
                        ("Protect", wintypes.DWORD),
                        ("Type", wintypes.DWORD),
                    ]

                mbi = MEMORY_BASIC_INFORMATION()
                address = 0
                MEM_COMMIT = 0x1000
                PAGE_READWRITE = 0x04
                PAGE_EXECUTE_READWRITE = 0x40

                while address < 0x7FFFFFFF0000:
                    result = kernel32.VirtualQueryEx(process_handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))

                    if not result:
                        break

                    # Scan committed memory with appropriate permissions
                    if mbi.State == MEM_COMMIT and (scan_heap or mbi.Protect in [PAGE_EXECUTE_READWRITE]):
                        # Read memory region
                        buffer = ctypes.create_string_buffer(mbi.RegionSize)
                        bytes_read = ctypes.c_size_t()

                        if kernel32.ReadProcessMemory(process_handle, mbi.BaseAddress, buffer, mbi.RegionSize, ctypes.byref(bytes_read)):
                            # Scan this memory region
                            region_matches = self._scan_memory_region(buffer.raw[: bytes_read.value], mbi.BaseAddress, categories)
                            matches.extend(region_matches)

                    address = mbi.BaseAddress + mbi.RegionSize

                kernel32.CloseHandle(process_handle)

            # Store matches
            if not hasattr(self, "_matches"):
                self._matches = []
            self._matches.extend(matches)

            logger.info(f"Found {len(matches)} matches in process {pid}")
            return matches

        except Exception as e:
            logger.error(f"Process scanning error: {e}")
            return matches

    def generate_rule(
        self, name: str, strings: List[str], condition: str = "any of them", add_wildcards: bool = True, add_case_variations: bool = True
    ) -> str:
        """Generate sophisticated YARA rules for licensing protection detection."""
        import re

        # Sanitize rule name
        safe_name = re.sub(r"[^a-zA-Z0-9_]", "_", name)

        rule_content = f"rule {safe_name} {{\n"
        rule_content += "    meta:\n"
        rule_content += f'        description = "Auto-generated rule for {name}"\n'
        rule_content += '        category = "license"\n'
        rule_content += "    strings:\n"

        string_vars = []

        for i, s in enumerate(strings):
            var_name = f"s{i}"

            if s.startswith("/") and s.endswith("/"):
                # Regex pattern - validate it
                try:
                    re.compile(s[1:-1])
                    rule_content += f"        ${var_name} = {s}\n"
                    string_vars.append(f"${var_name}")
                except re.error as e:
                    logger.warning(f"Invalid regex pattern: {s} - {e}")
                    continue

            elif s.startswith("{") and s.endswith("}"):
                # Hex pattern - add wildcards for flexibility
                hex_pattern = s
                if add_wildcards:
                    # Convert some bytes to wildcards for variation matching
                    hex_bytes = hex_pattern[1:-1].strip().split()
                    if len(hex_bytes) > 4:
                        # Make every 3rd byte a wildcard
                        for j in range(2, len(hex_bytes), 3):
                            if hex_bytes[j] != "??":
                                hex_bytes[j] = "??"
                        hex_pattern = "{ " + " ".join(hex_bytes) + " }"

                rule_content += f"        ${var_name} = {hex_pattern}\n"
                string_vars.append(f"${var_name}")

            else:
                # String literal - add variations
                base_var = f"${var_name}"

                # Add base string
                rule_content += f'        {base_var} = "{s}"\n'
                string_vars.append(base_var)

                if add_case_variations:
                    # Add case-insensitive version
                    rule_content += f'        {base_var}_nocase = "{s}" nocase\n'
                    string_vars.append(f"{base_var}_nocase")

                    # Add wide string version (Unicode)
                    rule_content += f'        {base_var}_wide = "{s}" wide\n'
                    string_vars.append(f"{base_var}_wide")

                    # Add ASCII version
                    rule_content += f'        {base_var}_ascii = "{s}" ascii\n'
                    string_vars.append(f"{base_var}_ascii")

                # Add common obfuscation patterns
                if "license" in s.lower() or "serial" in s.lower() or "key" in s.lower():
                    # Add hex-encoded version
                    hex_encoded = " ".join([f"{ord(c):02X}" for c in s])
                    rule_content += f"        ${var_name}_hex = {{ {hex_encoded} }}\n"
                    string_vars.append(f"${var_name}_hex")

                    # Add base64 pattern
                    import base64

                    b64_encoded = base64.b64encode(s.encode()).decode()
                    rule_content += f'        ${var_name}_b64 = "{b64_encoded}"\n'
                    string_vars.append(f"${var_name}_b64")

        # Generate sophisticated conditions
        if condition == "any of them":
            condition = f"any of ({', '.join(string_vars)})"
        elif condition == "all of them":
            condition = f"all of ({', '.join(string_vars)})"
        elif condition.startswith("custom:"):
            # Parse custom condition
            condition = condition[7:]
        else:
            # Add advanced conditions for license detection
            conditions = []

            # Check for at least 2 strings
            if len(string_vars) > 2:
                conditions.append(f"2 of ({', '.join(string_vars)})")

            # Add filesize constraint for efficiency
            conditions.append("filesize < 50MB")

            # Combine conditions
            condition = " and ".join(conditions) if conditions else "any of them"

        rule_content += f"    condition:\n        {condition}\n}}"

        return rule_content

    def get_matches(self) -> List[YaraMatch]:
        """Get all stored matches (thread-safe)."""
        import threading

        if not hasattr(self, "_matches"):
            self._matches = []

        if not hasattr(self, "_match_lock"):
            self._match_lock = threading.Lock()

        with self._match_lock:
            return list(self._matches)  # Return copy to prevent external modification

    def clear_matches(self) -> None:
        """Clear stored matches (thread-safe)."""
        import threading

        if not hasattr(self, "_match_lock"):
            self._match_lock = threading.Lock()

        with self._match_lock:
            self._matches = []
            logger.debug("Cleared all stored matches")

    def _scan_memory_region(self, data: bytes, base_address: int, categories: Optional[List[RuleCategory]]) -> List[YaraMatch]:
        """Scan a memory region with filtered rules."""
        matches = []

        try:
            # Filter rules by category if specified
            if categories:
                filtered_rules = self._filter_rules_by_category(categories)
                if filtered_rules:
                    compiled = yara.compile(source=filtered_rules)
                else:
                    compiled = self.compiled_rules
            else:
                compiled = self.compiled_rules

            # Scan memory region
            yara_matches = compiled.match(data=data)

            for match in yara_matches:
                matches.append(
                    YaraMatch(
                        rule_name=match.rule,
                        category=self._get_rule_category(match.rule),
                        matched_data=f"Memory at 0x{base_address:X}",
                        metadata={
                            "base_address": base_address,
                            "strings": [(s.offset + base_address, s.matched_data) for s in match.strings],
                        },
                    )
                )

        except Exception as e:
            logger.error(f"Memory region scan error: {e}")

        return matches

    def _filter_rules_by_category(self, categories: List[RuleCategory]) -> str:
        """Filter rules by category."""
        if not hasattr(self, "_rule_categories"):
            return "\n".join(self.builtin_rules.values())

        filtered = []
        for name, content in self.builtin_rules.items():
            if name in self._rule_categories:
                if self._rule_categories[name] in categories:
                    filtered.append(content)

        return "\n\n".join(filtered)

    def _get_rule_category(self, rule_name: str) -> RuleCategory:
        """Get category for a rule."""
        if hasattr(self, "_rule_categories") and rule_name in self._rule_categories:
            return self._rule_categories[rule_name]
        return RuleCategory.CUSTOM

    def export_detections(self, detections: Dict[str, Any], output_path: Path) -> None:
        """Export detection results to file.

        Args:
            detections: Detection results
            output_path: Path to save results
        """
        export_data = {
            "timestamp": os.path.getmtime(output_path.parent),
            "detections": detections,
            "statistics": {
                "total_packers": len(detections.get("packers", [])),
                "total_protectors": len(detections.get("protectors", [])),
                "total_crypto": len(detections.get("crypto", [])),
                "total_license": len(detections.get("license", [])),
                "total_anti_debug": len(detections.get("anti_debug", [])),
            },
        }

        with open(output_path, "w") as f:
            json.dump(export_data, f, indent=2)

        logger.info(f"Exported detections to {output_path}")
