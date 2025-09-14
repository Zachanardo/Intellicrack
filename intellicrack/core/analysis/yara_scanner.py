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

import yara
import os
import json
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import logging

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
                b"\x56\x4D\x50\x72\x6F\x74\x65\x63\x74",  # "VMProtect"
                b"\x2E\x76\x6D\x70\x30",  # ".vmp0"
                b"\x2E\x76\x6D\x70\x31",  # ".vmp1"
                b"\x2E\x76\x6D\x70\x32",  # ".vmp2"
            ],
            entry_point_pattern=b"\x68\x00\x00\x00\x00\xE8",
            section_characteristics={"name": ".vmp", "flags": 0xE0000020},
            imports=None
        ),
        "Themida": ProtectionSignature(
            name="Themida",
            version=None,
            category="protector",
            signatures=[
                b"\x54\x68\x65\x6D\x69\x64\x61",  # "Themida"
                b"\x2E\x74\x68\x65\x6D\x69\x64\x61",  # ".themida"
                b"\xB8\x00\x00\x00\x00\x60\x0B\xC0\x74\x58",
            ],
            entry_point_pattern=b"\xB8\x00\x00\x00\x00\x60\x0B\xC0",
            section_characteristics=None,
            imports=["SecureEngineSDK.dll"]
        ),
        "ASProtect": ProtectionSignature(
            name="ASProtect",
            version=None,
            category="protector",
            signatures=[
                b"\x41\x53\x50\x72\x6F\x74\x65\x63\x74",  # "ASProtect"
                b"\x2E\x61\x73\x70\x72",  # ".aspr"
                b"\x60\xE8\x03\x00\x00\x00\xE9\xEB\x04",
            ],
            entry_point_pattern=b"\x60\xE8\x03\x00\x00\x00",
            section_characteristics={"name": ".aspack", "flags": 0xE0000020},
            imports=None
        ),
        "Denuvo": ProtectionSignature(
            name="Denuvo",
            version=None,
            category="protector",
            signatures=[
                b"\x44\x65\x6E\x75\x76\x6F",  # "Denuvo"
                b"\x2E\x64\x65\x6E\x75",  # ".denu"
                b"\x48\x8D\x05\x00\x00\x00\x00\x48\x89\x45",
            ],
            entry_point_pattern=None,
            section_characteristics=None,
            imports=["denuvo32.dll", "denuvo64.dll"]
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
            entry_point_pattern=b"\x60\xBE\x00\x00\x00\x00\x8D\xBE",
            section_characteristics={"name": "UPX", "flags": 0xE0000080},
            imports=None
        )
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
            RuleCategory.COMPILER: self._create_compiler_rules()
        }

        for category, rule_source in builtin_rules.items():
            try:
                self.compiled_rules[category] = yara.compile(source=rule_source)
                logger.info(f"Loaded built-in rules for {category.value}")
            except Exception as e:
                logger.error(f"Failed to compile {category.value} rules: {e}")

    def _create_packer_rules(self) -> str:
        """Create YARA rules for packer detection."""
        return '''
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
'''

    def _create_protector_rules(self) -> str:
        """Create YARA rules for protector detection."""
        return '''
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
'''

    def _create_crypto_rules(self) -> str:
        """Create YARA rules for cryptographic algorithm detection."""
        return '''
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
'''

    def _create_license_rules(self) -> str:
        """Create YARA rules for license validation detection."""
        return '''
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
'''

    def _create_antidebug_rules(self) -> str:
        """Create YARA rules for anti-debugging detection."""
        return '''
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
'''

    def _create_compiler_rules(self) -> str:
        """Create YARA rules for compiler detection."""
        return '''
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
'''

    def _load_custom_rules(self):
        """Load custom YARA rules from directory."""
        for rule_file in self.rules_dir.glob("*.yar"):
            try:
                rules = yara.compile(filepath=str(rule_file))
                self.custom_rules[rule_file.stem] = rules
                logger.info(f"Loaded custom rule: {rule_file.stem}")
            except Exception as e:
                logger.error(f"Failed to load rule {rule_file}: {e}")

    def scan_file(self, file_path: Path,
                  categories: Optional[List[RuleCategory]] = None) -> List[YaraMatch]:
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
            rules_to_scan = {cat: self.compiled_rules[cat]
                            for cat in categories
                            if cat in self.compiled_rules}
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
                        confidence=float(match.meta.get("confidence", 50))
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
                        confidence=float(match.meta.get("confidence", 50))
                    )
                    matches.append(yara_match)

            except Exception as e:
                logger.error(f"Failed to scan with custom rule {rule_name}: {e}")

        return matches

    def scan_memory(self, pid: int,
                   categories: Optional[List[RuleCategory]] = None) -> List[YaraMatch]:
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
            rules_to_scan = {cat: self.compiled_rules[cat]
                            for cat in categories
                            if cat in self.compiled_rules}
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
                        confidence=float(match.meta.get("confidence", 50))
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
        protections = {
            "packers": [],
            "protectors": [],
            "crypto": [],
            "license": [],
            "anti_debug": [],
            "compiler": None
        }

        # Scan with protection-related categories
        matches = self.scan_file(
            file_path,
            categories=[
                RuleCategory.PACKER,
                RuleCategory.PROTECTOR,
                RuleCategory.CRYPTO,
                RuleCategory.LICENSE,
                RuleCategory.ANTI_DEBUG,
                RuleCategory.COMPILER
            ]
        )

        # Organize matches by category
        for match in matches:
            if match.category == RuleCategory.PACKER:
                protections["packers"].append({
                    "name": match.rule_name,
                    "confidence": match.confidence,
                    "offset": match.offset
                })
            elif match.category == RuleCategory.PROTECTOR:
                protections["protectors"].append({
                    "name": match.rule_name,
                    "confidence": match.confidence,
                    "offset": match.offset
                })
            elif match.category == RuleCategory.CRYPTO:
                protections["crypto"].append({
                    "algorithm": match.rule_name,
                    "confidence": match.confidence,
                    "offset": match.offset
                })
            elif match.category == RuleCategory.LICENSE:
                protections["license"].append({
                    "type": match.rule_name,
                    "confidence": match.confidence,
                    "offset": match.offset
                })
            elif match.category == RuleCategory.ANTI_DEBUG:
                protections["anti_debug"].append({
                    "technique": match.rule_name,
                    "confidence": match.confidence,
                    "offset": match.offset
                })
            elif match.category == RuleCategory.COMPILER:
                if protections["compiler"] is None or match.confidence > protections["compiler"]["confidence"]:
                    protections["compiler"] = {
                        "name": match.rule_name,
                        "confidence": match.confidence
                    }

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
            with open(file_path, 'rb') as f:
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
                        detections.append({
                            "name": name,
                            "category": signature.category,
                            "confidence": min(confidence, 95)
                        })

        except Exception as e:
            logger.error(f"Failed to perform signature-based detection: {e}")

        return detections

    def create_custom_rule(self, rule_name: str, rule_content: str,
                          category: RuleCategory = RuleCategory.CUSTOM) -> bool:
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

            with open(rule_file, 'w') as f:
                f.write(rule_content)

            # Store compiled rule
            self.custom_rules[rule_name] = rules

            logger.info(f"Created custom rule: {rule_name}")
            return True

        except Exception as e:
            logger.error(f"Failed to create custom rule: {e}")
            return False

    def export_detections(self, detections: Dict[str, Any],
                         output_path: Path) -> None:
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
                "total_anti_debug": len(detections.get("anti_debug", []))
            }
        }

        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2)

        logger.info(f"Exported detections to {output_path}")