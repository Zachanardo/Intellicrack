"""YARA Pattern Engine

Advanced pattern matching engine for protection and malware detection using YARA rules.
Provides comprehensive pattern analysis for identifying protections, packers, and suspicious code.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from ...utils.logger import get_logger

logger = get_logger(__name__)

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logger.warning("YARA not available - pattern matching disabled")


class PatternCategory(Enum):
    """Categories of YARA pattern detection"""

    PROTECTION = "protection"
    PACKER = "packer"
    CRYPTOR = "cryptor"
    LICENSING = "licensing"
    ANTI_DEBUG = "anti_debug"
    ANTI_VM = "anti_vm"
    OBFUSCATION = "obfuscation"
    COMPILER = "compiler"
    SUSPICIOUS = "suspicious"
    MALWARE = "malware"


@dataclass
class YaraMatch:
    """Single YARA rule match"""

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
        """Get severity based on category and confidence"""
        if self.category in [PatternCategory.MALWARE, PatternCategory.ANTI_DEBUG]:
            return "high" if self.confidence > 0.8 else "medium"
        if self.category in [PatternCategory.PROTECTION, PatternCategory.PACKER]:
            return "medium" if self.confidence > 0.7 else "low"
        return "low"


@dataclass
class YaraScanResult:
    """Complete YARA scan results"""

    file_path: str
    matches: list[YaraMatch] = field(default_factory=list)
    total_rules: int = 0
    scan_time: float = 0.0
    error: str | None = None

    @property
    def has_protections(self) -> bool:
        """Check if any protection patterns were found"""
        return any(m.category == PatternCategory.PROTECTION for m in self.matches)

    @property
    def has_packers(self) -> bool:
        """Check if any packer patterns were found"""
        return any(m.category == PatternCategory.PACKER for m in self.matches)

    @property
    def has_licensing(self) -> bool:
        """Check if any licensing patterns were found"""
        return any(m.category == PatternCategory.LICENSING for m in self.matches)

    @property
    def high_confidence_matches(self) -> list[YaraMatch]:
        """Get matches with high confidence (>0.8)"""
        return [m for m in self.matches if m.confidence > 0.8]

    def get_matches_by_category(self, category: PatternCategory) -> list[YaraMatch]:
        """Get all matches for a specific category"""
        return [m for m in self.matches if m.category == category]


class YaraPatternEngine:
    """Advanced YARA pattern matching engine for binary analysis.

    Provides comprehensive detection of protections, packers, licensing schemes,
    and other patterns relevant to security analysis. Integrates with ICP backend
    to provide supplemental pattern-based detection alongside die-python analysis.
    """

    def __init__(self, custom_rules_path: str | None = None):
        """Initialize YARA pattern engine

        Args:
            custom_rules_path: Optional path to custom YARA rules directory

        """
        if not YARA_AVAILABLE:
            raise ImportError("yara-python package is required but not installed")

        self.custom_rules_path = custom_rules_path
        self.compiled_rules: yara.Rules | None = None
        self.rule_metadata: dict[str, dict[str, Any]] = {}
        self.scanned_files: set[str] = set()  # Track scanned files for deduplication
        self._load_rules()

    def _load_rules(self):
        """Load and compile YARA rules"""
        try:
            # Get built-in rules directory
            rules_dir = Path(__file__).parent.parent.parent / "data" / "yara_rules"
            rules_dir.mkdir(parents=True, exist_ok=True)

            # Create default rules if they don't exist
            self._create_default_rules(rules_dir)

            # Collect all rule files
            rule_files = {}

            # Load built-in rules
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
                logger.warning("No YARA rules found - creating minimal rule set")
                self._create_minimal_rules(rules_dir)
                rule_files["basic"] = str(rules_dir / "basic.yar")

            # Compile rules
            self.compiled_rules = yara.compile(filepaths=rule_files)
            self._extract_rule_metadata()

            logger.info(f"Loaded {len(rule_files)} YARA rule namespaces with {self._count_total_rules()} rules")

        except Exception as e:
            logger.error(f"Failed to load YARA rules: {e}")
            self.compiled_rules = None

    def _create_default_rules(self, rules_dir: Path):
        """Create comprehensive default YARA rules"""
        # Protection detection rules
        protection_rules = """
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
        """Create minimal rules as fallback"""
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
        """Extract metadata from compiled rules"""
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
        """Count total number of rules"""
        if not self.compiled_rules:
            return 0
        return len(list(self.compiled_rules))

    def scan_file(self, file_path: str, timeout: int = 60) -> YaraScanResult:
        """Scan a file with YARA rules

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
        """Determine pattern category from YARA match"""
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
        if any(keyword in rule_name for keyword in ["malware", "trojan", "virus"]):
            return PatternCategory.MALWARE
        return PatternCategory.SUSPICIOUS

    def _calculate_confidence(self, match) -> float:
        """Calculate confidence score for a match"""
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
        """Scan process memory with YARA rules

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
        """Create a custom YARA rule

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
        """Get information about loaded rules"""
        if not self.compiled_rules:
            return {"error": "No rules loaded"}

        categories = {}
        for rule_id, metadata in self.rule_metadata.items():
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
        """Generate supplemental data for ICP backend integration

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
            supplemental_data["protection_indicators"].append({
                "name": match.rule_name,
                "confidence": match.confidence,
                "offset": match.offset,
                "technique": "pattern_matching",
            })

        # Process licensing matches
        for match in scan_result.get_matches_by_category(PatternCategory.LICENSING):
            supplemental_data["licensing_indicators"].append({
                "name": match.rule_name,
                "confidence": match.confidence,
                "offset": match.offset,
                "type": "licensing_system",
            })

        # Process packer matches
        for match in scan_result.get_matches_by_category(PatternCategory.PACKER):
            supplemental_data["packer_indicators"].append({
                "name": match.rule_name,
                "confidence": match.confidence,
                "offset": match.offset,
                "packer_type": "signature_based",
            })

        # Process anti-analysis matches
        anti_analysis_categories = [PatternCategory.ANTI_DEBUG, PatternCategory.ANTI_VM]
        for category in anti_analysis_categories:
            for match in scan_result.get_matches_by_category(category):
                supplemental_data["anti_analysis_indicators"].append({
                    "name": match.rule_name,
                    "confidence": match.confidence,
                    "offset": match.offset,
                    "category": category.value,
                })

        return supplemental_data


# Singleton instance
_yara_engine: YaraPatternEngine | None = None


def get_yara_engine() -> YaraPatternEngine | None:
    """Get or create the YARA pattern engine singleton"""
    global _yara_engine
    if _yara_engine is None and YARA_AVAILABLE:
        try:
            _yara_engine = YaraPatternEngine()
        except Exception as e:
            logger.error(f"Failed to initialize YARA engine: {e}")
            return None
    return _yara_engine


def is_yara_available() -> bool:
    """Check if YARA functionality is available"""
    return YARA_AVAILABLE


def scan_file_with_yara(file_path: str) -> YaraScanResult | None:
    """Quick scan function for integration"""
    engine = get_yara_engine()
    if engine:
        return engine.scan_file(file_path)
    return None
