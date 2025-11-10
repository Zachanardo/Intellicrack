"""
Version Difference Analyzer for Phase 2.5.2.2 validation.
Documents specific technical differences between protection versions.
"""

import json
import logging
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
import re


logger = logging.getLogger(__name__)


@dataclass
class VersionSignature:
    """Signature characteristics of a specific protection version."""
    version: str
    binary_path: str
    binary_hash: str
    patterns: List[str]
    imports: List[str]
    strings: List[str]
    entry_points: List[str]
    sections: List[str]
    resources: List[str]
    crypto_indicators: List[str]
    obfuscation_markers: List[str]
    anti_debug_methods: List[str]
    license_validation_patterns: List[str]
    network_communication: List[str]
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


@dataclass
class VersionDifference:
    """Specific difference between two protection versions."""
    diff_type: str  # 'added', 'removed', 'modified', 'relocated'
    category: str  # 'pattern', 'import', 'string', 'crypto', 'anti_debug', etc.
    old_version: str
    new_version: str
    old_value: str
    new_value: str
    description: str
    severity: str  # 'critical', 'high', 'medium', 'low'
    impact: str
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


@dataclass
class VersionComparisonReport:
    """Comprehensive comparison report between protection versions."""
    software_name: str
    protection_name: str
    compared_versions: List[str]
    signatures: Dict[str, VersionSignature]
    differences: List[VersionDifference]
    evolution_summary: Dict[str, Any]
    attack_surface_changes: Dict[str, List[str]]
    bypass_implications: Dict[str, str]
    overall_assessment: str
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


class VersionDifferenceAnalyzer:
    """Analyzes and documents differences between protection versions."""

    def __init__(self, base_dir: str = "C:\\Intellicrack\\tests\\validation_system"):
        self.base_dir = Path(base_dir)
        self.reports_dir = self.base_dir / "reports" / "version_differences"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        # Configure pattern libraries for different protections
        self._init_protection_patterns()

    def _init_protection_patterns(self):
        """Initialize protection-specific pattern libraries."""
        self.protection_patterns = {
            "FlexLM": {
                "crypto_patterns": [
                    b"RSA", b"AES", b"DES", b"MD5", b"SHA", b"CRC",
                    b"HMAC", b"encrypt", b"decrypt", b"hash"
                ],
                "license_patterns": [
                    b"FLEXLM", b"FLEXnet", b"lm_checkout", b"lm_checkin",
                    b"lm_license", b"ADSKFLEX", b"license_key"
                ],
                "anti_debug_patterns": [
                    b"IsDebuggerPresent", b"CheckRemoteDebuggerPresent",
                    b"NtQueryInformationProcess", b"OutputDebugString"
                ],
                "network_patterns": [
                    b"connect", b"send", b"recv", b"socket", b"WSAStartup",
                    b"InternetOpen", b"HttpOpenRequest"
                ]
            },
            "Adobe Licensing": {
                "crypto_patterns": [
                    b"Adobe", b"AMT", b"OOBE", b"Creative", b"Suite",
                    b"activation", b"serial"
                ],
                "license_patterns": [
                    b"adobe_caps", b"AdobePatchFiles", b"Creative Suite",
                    b"Adobe Systems", b"license_check"
                ],
                "anti_debug_patterns": [
                    b"anti_debug", b"debugger", b"IsDebuggerPresent"
                ],
                "network_patterns": [
                    b"adobe.com", b"activation", b"https", b"ssl"
                ]
            },
            "Sentinel HASP": {
                "crypto_patterns": [
                    b"HASP", b"Sentinel", b"SafeNet", b"dongle",
                    b"hardware", b"key"
                ],
                "license_patterns": [
                    b"SENTINEL", b"HASP", b"Aladdin", b"hasplm",
                    b"dongle_check"
                ],
                "anti_debug_patterns": [
                    b"hardware_check", b"tamper", b"integrity"
                ],
                "network_patterns": [
                    b"sentinel", b"safenet", b"license_server"
                ]
            }
        }

    def analyze_binary_signature(self, binary_path: str, version: str, protection_name: str) -> VersionSignature:
        """
        Extract comprehensive signature from a binary for version comparison.
        """
        logger.info(f"Analyzing binary signature for {protection_name} {version}: {binary_path}")

        try:
            import pefile
        except ImportError:
            import subprocess
            import sys
            subprocess.check_call([sys.executable, "-m", "pip", "install", "pefile"])
            import pefile

        # Read binary data
        with open(binary_path, 'rb') as f:
            binary_data = f.read()

        # Calculate hash
        binary_hash = hashlib.sha256(binary_data).hexdigest()

        # Initialize signature components
        patterns = []
        imports = []
        strings = []
        entry_points = []
        sections = []
        resources = []
        crypto_indicators = []
        obfuscation_markers = []
        anti_debug_methods = []
        license_validation_patterns = []
        network_communication = []

        # Analyze PE structure
        try:
            pe = pefile.PE(binary_path)

            # Extract entry points
            entry_points.append(hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))

            # Extract section information
            for section in pe.sections:
                section_name = section.Name.decode().rstrip('\x00')
                sections.append({
                    "name": section_name,
                    "virtual_address": hex(section.VirtualAddress),
                    "size": section.SizeOfRawData,
                    "characteristics": hex(section.Characteristics)
                })

            # Extract imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode()
                    imports.append(dll_name)
                    for imp in entry.imports:
                        if imp.name:
                            import_name = imp.name.decode()
                            imports.append(f"{dll_name}::{import_name}")

            # Extract resources
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    resources.append(f"Type: {resource_type.id}")

            pe.close()

        except Exception as e:
            logger.error(f"PE analysis failed: {e}")

        # Extract strings (printable ASCII strings >= 4 chars)
        strings = self._extract_strings(binary_data)

        # Analyze protection-specific patterns
        if protection_name in self.protection_patterns:
            patterns_config = self.protection_patterns[protection_name]

            # Crypto indicators
            for pattern in patterns_config.get("crypto_patterns", []):
                if pattern in binary_data:
                    crypto_indicators.append(pattern.decode('ascii', errors='ignore'))

            # License validation patterns
            for pattern in patterns_config.get("license_patterns", []):
                if pattern in binary_data:
                    license_validation_patterns.append(pattern.decode('ascii', errors='ignore'))

            # Anti-debug methods
            for pattern in patterns_config.get("anti_debug_patterns", []):
                if pattern in binary_data:
                    anti_debug_methods.append(pattern.decode('ascii', errors='ignore'))

            # Network communication indicators
            for pattern in patterns_config.get("network_patterns", []):
                if pattern in binary_data:
                    network_communication.append(pattern.decode('ascii', errors='ignore'))

        # Detect obfuscation markers
        obfuscation_markers = self._detect_obfuscation(binary_data)

        return VersionSignature(
            version=version,
            binary_path=binary_path,
            binary_hash=binary_hash,
            patterns=patterns,
            imports=imports[:50],  # Limit to avoid huge lists
            strings=strings[:100],  # Limit to avoid huge lists
            entry_points=entry_points,
            sections=[str(s) for s in sections],
            resources=resources,
            crypto_indicators=crypto_indicators,
            obfuscation_markers=obfuscation_markers,
            anti_debug_methods=anti_debug_methods,
            license_validation_patterns=license_validation_patterns,
            network_communication=network_communication
        )

    def _extract_strings(self, binary_data: bytes, min_length: int = 4) -> List[str]:
        """Extract printable ASCII strings from binary data."""
        strings = []
        current_string = ""

        for byte in binary_data:
            if 32 <= byte <= 126:  # Printable ASCII range
                current_string += chr(byte)
            else:
                if len(current_string) >= min_length:
                    strings.append(current_string)
                current_string = ""

        # Don't forget the last string if it ends at EOF
        if len(current_string) >= min_length:
            strings.append(current_string)

        # Filter out common but uninteresting strings
        filtered_strings = []
        for s in strings:
            # Skip pure numeric strings, paths, and very common strings
            if not s.isdigit() and len(s) <= 100:
                if not any(skip in s.lower() for skip in ['temp', 'windows', 'system32', 'program files']):
                    filtered_strings.append(s)

        return list(set(filtered_strings))[:100]  # Remove duplicates and limit

    def _detect_obfuscation(self, binary_data: bytes) -> List[str]:
        """Detect obfuscation markers in binary data."""
        obfuscation_markers = []

        # Common obfuscation patterns
        obfuscation_patterns = [
            (b"UPX", "UPX Packer"),
            (b"VMProtect", "VMProtect"),
            (b"Themida", "Themida"),
            (b"ASPack", "ASPack"),
            (b"PECompact", "PECompact"),
            (b"Armadillo", "Armadillo"),
            (b"Obsidium", "Obsidium")
        ]

        for pattern, name in obfuscation_patterns:
            if pattern in binary_data:
                obfuscation_markers.append(name)

        # Calculate entropy to detect potential obfuscation
        entropy = self._calculate_entropy(binary_data)
        if entropy > 7.5:  # High entropy suggests obfuscation/encryption
            obfuscation_markers.append(f"High entropy ({entropy:.2f})")

        return obfuscation_markers

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of binary data."""
        import math

        if not data:
            return 0.0

        # Count frequency of each byte value
        frequency = [0] * 256
        for byte in data:
            frequency[byte] += 1

        # Calculate Shannon entropy
        entropy = 0.0
        data_len = len(data)
        for count in frequency:
            if count > 0:
                p = count / data_len
                entropy -= p * math.log2(p)

        return entropy

    def compare_versions(self, signatures: Dict[str, VersionSignature]) -> List[VersionDifference]:
        """
        Compare version signatures and identify specific differences.
        """
        differences = []
        versions = sorted(signatures.keys())

        logger.info(f"Comparing {len(versions)} versions: {versions}")

        # Compare each pair of consecutive versions
        for i in range(len(versions) - 1):
            old_version = versions[i]
            new_version = versions[i + 1]
            old_sig = signatures[old_version]
            new_sig = signatures[new_version]

            # Compare imports
            old_imports = set(old_sig.imports)
            new_imports = set(new_sig.imports)

            for added_import in new_imports - old_imports:
                differences.append(VersionDifference(
                    diff_type="added",
                    category="import",
                    old_version=old_version,
                    new_version=new_version,
                    old_value="",
                    new_value=added_import,
                    description=f"New import added: {added_import}",
                    severity=self._assess_import_severity(added_import),
                    impact="New functionality or dependency introduced"
                ))

            for removed_import in old_imports - new_imports:
                differences.append(VersionDifference(
                    diff_type="removed",
                    category="import",
                    old_version=old_version,
                    new_version=new_version,
                    old_value=removed_import,
                    new_value="",
                    description=f"Import removed: {removed_import}",
                    severity=self._assess_import_severity(removed_import),
                    impact="Functionality potentially removed or refactored"
                ))

            # Compare crypto indicators
            old_crypto = set(old_sig.crypto_indicators)
            new_crypto = set(new_sig.crypto_indicators)

            for added_crypto in new_crypto - old_crypto:
                differences.append(VersionDifference(
                    diff_type="added",
                    category="crypto",
                    old_version=old_version,
                    new_version=new_version,
                    old_value="",
                    new_value=added_crypto,
                    description=f"New cryptographic indicator: {added_crypto}",
                    severity="high",
                    impact="New encryption/protection mechanism potentially added"
                ))

            for removed_crypto in old_crypto - new_crypto:
                differences.append(VersionDifference(
                    diff_type="removed",
                    category="crypto",
                    old_version=old_version,
                    new_version=new_version,
                    old_value=removed_crypto,
                    new_value="",
                    description=f"Cryptographic indicator removed: {removed_crypto}",
                    severity="high",
                    impact="Encryption/protection mechanism potentially weakened"
                ))

            # Compare anti-debug methods
            old_antidebug = set(old_sig.anti_debug_methods)
            new_antidebug = set(new_sig.anti_debug_methods)

            for added_antidebug in new_antidebug - old_antidebug:
                differences.append(VersionDifference(
                    diff_type="added",
                    category="anti_debug",
                    old_version=old_version,
                    new_version=new_version,
                    old_value="",
                    new_value=added_antidebug,
                    description=f"New anti-debug method: {added_antidebug}",
                    severity="medium",
                    impact="Increased debugging/reverse engineering resistance"
                ))

            # Compare obfuscation markers
            old_obfuscation = set(old_sig.obfuscation_markers)
            new_obfuscation = set(new_sig.obfuscation_markers)

            for added_obfuscation in new_obfuscation - old_obfuscation:
                differences.append(VersionDifference(
                    diff_type="added",
                    category="obfuscation",
                    old_version=old_version,
                    new_version=new_version,
                    old_value="",
                    new_value=added_obfuscation,
                    description=f"New obfuscation detected: {added_obfuscation}",
                    severity="high",
                    impact="Code obfuscation increased, analysis more difficult"
                ))

            # Compare license validation patterns
            old_license = set(old_sig.license_validation_patterns)
            new_license = set(new_sig.license_validation_patterns)

            for added_license in new_license - old_license:
                differences.append(VersionDifference(
                    diff_type="added",
                    category="license_validation",
                    old_version=old_version,
                    new_version=new_version,
                    old_value="",
                    new_value=added_license,
                    description=f"New license validation pattern: {added_license}",
                    severity="critical",
                    impact="License validation logic changed, bypass methods may need updates"
                ))

            for removed_license in old_license - new_license:
                differences.append(VersionDifference(
                    diff_type="removed",
                    category="license_validation",
                    old_version=old_version,
                    new_version=new_version,
                    old_value=removed_license,
                    new_value="",
                    description=f"License validation pattern removed: {removed_license}",
                    severity="critical",
                    impact="License validation simplified or refactored"
                ))

        logger.info(f"Found {len(differences)} differences across versions")
        return differences

    def _assess_import_severity(self, import_name: str) -> str:
        """Assess the security impact severity of an import change."""
        high_impact_imports = [
            "crypt", "encrypt", "decrypt", "hash", "md5", "sha",
            "debug", "protect", "license", "validate", "check"
        ]

        for keyword in high_impact_imports:
            if keyword.lower() in import_name.lower():
                return "high"

        # Network and system imports are medium impact
        medium_impact_imports = [
            "network", "socket", "internet", "http", "ssl", "tls",
            "registry", "process", "thread", "memory"
        ]

        for keyword in medium_impact_imports:
            if keyword.lower() in import_name.lower():
                return "medium"

        return "low"

    def generate_evolution_summary(self, signatures: Dict[str, VersionSignature],
                                   differences: List[VersionDifference]) -> Dict[str, Any]:
        """
        Generate high-level summary of protection evolution across versions.
        """
        versions = sorted(signatures.keys())

        evolution_summary = {
            "total_versions_analyzed": len(versions),
            "version_range": f"{versions[0]} to {versions[-1]}",
            "total_differences_found": len(differences),
            "categories_changed": list(set(diff.category for diff in differences)),
            "security_trend": "unknown",
            "complexity_trend": "unknown",
            "major_changes": []
        }

        # Analyze security trend
        crypto_additions = len([d for d in differences if d.category == "crypto" and d.diff_type == "added"])
        crypto_removals = len([d for d in differences if d.category == "crypto" and d.diff_type == "removed"])
        antidebug_additions = len([d for d in differences if d.category == "anti_debug" and d.diff_type == "added"])

        if crypto_additions + antidebug_additions > crypto_removals:
            evolution_summary["security_trend"] = "strengthening"
        elif crypto_removals > crypto_additions + antidebug_additions:
            evolution_summary["security_trend"] = "weakening"
        else:
            evolution_summary["security_trend"] = "stable"

        # Analyze complexity trend
        obfuscation_additions = len([d for d in differences if d.category == "obfuscation" and d.diff_type == "added"])
        total_additions = len([d for d in differences if d.diff_type == "added"])
        total_removals = len([d for d in differences if d.diff_type == "removed"])

        if obfuscation_additions > 0 or total_additions > total_removals * 1.5:
            evolution_summary["complexity_trend"] = "increasing"
        elif total_removals > total_additions * 1.5:
            evolution_summary["complexity_trend"] = "decreasing"
        else:
            evolution_summary["complexity_trend"] = "stable"

        # Identify major changes
        critical_changes = [d for d in differences if d.severity == "critical"]
        high_changes = [d for d in differences if d.severity == "high"]

        for change in critical_changes[:5]:  # Top 5 critical changes
            evolution_summary["major_changes"].append({
                "type": "critical",
                "description": change.description,
                "impact": change.impact,
                "versions": f"{change.old_version} -> {change.new_version}"
            })

        for change in high_changes[:3]:  # Top 3 high impact changes
            evolution_summary["major_changes"].append({
                "type": "high_impact",
                "description": change.description,
                "impact": change.impact,
                "versions": f"{change.old_version} -> {change.new_version}"
            })

        return evolution_summary

    def analyze_attack_surface_changes(self, differences: List[VersionDifference]) -> Dict[str, List[str]]:
        """
        Analyze how the attack surface changes across versions.
        """
        attack_surface_changes = {
            "new_attack_vectors": [],
            "closed_attack_vectors": [],
            "modified_attack_vectors": [],
            "bypass_difficulty_changes": []
        }

        for diff in differences:
            if diff.category == "crypto":
                if diff.diff_type == "added":
                    attack_surface_changes["bypass_difficulty_changes"].append(
                        f"New crypto {diff.new_value} increases bypass complexity"
                    )
                elif diff.diff_type == "removed":
                    attack_surface_changes["closed_attack_vectors"].append(
                        f"Crypto method {diff.old_value} removed - related bypasses obsolete"
                    )

            elif diff.category == "anti_debug":
                if diff.diff_type == "added":
                    attack_surface_changes["bypass_difficulty_changes"].append(
                        f"New anti-debug {diff.new_value} complicates analysis"
                    )

            elif diff.category == "license_validation":
                if diff.diff_type == "added":
                    attack_surface_changes["new_attack_vectors"].append(
                        f"New validation pattern {diff.new_value} creates bypass opportunity"
                    )
                elif diff.diff_type == "removed":
                    attack_surface_changes["closed_attack_vectors"].append(
                        f"Validation {diff.old_value} removed - bypass method obsolete"
                    )
                elif diff.diff_type == "modified":
                    attack_surface_changes["modified_attack_vectors"].append(
                        f"Validation changed: {diff.old_value} -> {diff.new_value}"
                    )

            elif diff.category == "import":
                if diff.diff_type == "added" and any(keyword in diff.new_value.lower()
                                                     for keyword in ['crypt', 'hash', 'validate', 'check']):
                    attack_surface_changes["new_attack_vectors"].append(
                        f"New security-related import {diff.new_value}"
                    )

        return attack_surface_changes

    def generate_bypass_implications(self, differences: List[VersionDifference],
                                     evolution_summary: Dict[str, Any]) -> Dict[str, str]:
        """
        Generate implications for bypass development across versions.
        """
        bypass_implications = {}

        versions = set()
        for diff in differences:
            versions.add(diff.old_version)
            versions.add(diff.new_version)

        for version in sorted(versions):
            version_diffs = [d for d in differences if d.new_version == version or d.old_version == version]

            implications = []

            # License validation changes
            license_changes = [d for d in version_diffs if d.category == "license_validation"]
            if license_changes:
                implications.append("License validation modified - bypass methods need updates")

            # Crypto changes
            crypto_changes = [d for d in version_diffs if d.category == "crypto"]
            if crypto_changes:
                implications.append("Cryptographic changes detected - key generation/validation may differ")

            # Anti-debug changes
            antidebug_changes = [d for d in version_diffs if d.category == "anti_debug"]
            if antidebug_changes:
                implications.append("Anti-debugging measures modified - analysis techniques need adjustment")

            # Obfuscation changes
            obfuscation_changes = [d for d in version_diffs if d.category == "obfuscation"]
            if obfuscation_changes:
                implications.append("Code obfuscation changed - deobfuscation methods need updates")

            if implications:
                bypass_implications[version] = " | ".join(implications)
            else:
                bypass_implications[version] = "Minimal changes - existing bypass methods likely compatible"

        return bypass_implications

    def create_comparison_report(self, software_name: str, protection_name: str,
                                 signatures: Dict[str, VersionSignature]) -> VersionComparisonReport:
        """
        Create comprehensive version comparison report.
        """
        logger.info(f"Creating comparison report for {protection_name} versions")

        # Analyze differences
        differences = self.compare_versions(signatures)

        # Generate evolution summary
        evolution_summary = self.generate_evolution_summary(signatures, differences)

        # Analyze attack surface changes
        attack_surface_changes = self.analyze_attack_surface_changes(differences)

        # Generate bypass implications
        bypass_implications = self.generate_bypass_implications(differences, evolution_summary)

        # Overall assessment
        critical_count = len([d for d in differences if d.severity == "critical"])
        high_count = len([d for d in differences if d.severity == "high"])

        if critical_count > 0:
            overall_assessment = (
                f"Major changes detected ({critical_count} critical, {high_count} high impact). "
                "Bypass methods require significant updates."
            )
        elif high_count > 2:
            overall_assessment = f"Moderate changes detected ({high_count} high impact). Bypass methods may need adjustments."
        elif len(differences) > 10:
            overall_assessment = f"Many minor changes detected ({len(differences)} total). Review recommended."
        else:
            overall_assessment = f"Minimal changes detected ({len(differences)} total). Existing methods likely compatible."

        return VersionComparisonReport(
            software_name=software_name,
            protection_name=protection_name,
            compared_versions=sorted(signatures.keys()),
            signatures=signatures,
            differences=differences,
            evolution_summary=evolution_summary,
            attack_surface_changes=attack_surface_changes,
            bypass_implications=bypass_implications,
            overall_assessment=overall_assessment
        )

    def save_comparison_report(self, report: VersionComparisonReport, filename: Optional[str] = None) -> str:
        """
        Save version comparison report to JSON file.
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_name = re.sub(r'[^\w\s-]', '', report.protection_name).strip().replace(' ', '_')
            filename = f"version_comparison_{safe_name}_{timestamp}.json"

        report_path = self.reports_dir / filename

        # Convert dataclass to dict for JSON serialization
        report_dict = asdict(report)

        with open(report_path, 'w') as f:
            json.dump(report_dict, f, indent=2)

        logger.info(f"Saved version comparison report to {report_path}")
        return str(report_path)

    def generate_human_readable_report(self, report: VersionComparisonReport) -> str:
        """
        Generate human-readable version comparison report.
        """
        lines = [
            "Version Difference Analysis Report",
            "=" * 50,
            f"Software: {report.software_name}",
            f"Protection: {report.protection_name}",
            f"Versions Analyzed: {', '.join(report.compared_versions)}",
            f"Generated: {report.timestamp}",
            "",
            "OVERALL ASSESSMENT:",
            f"{report.overall_assessment}",
            "",
            "EVOLUTION SUMMARY:",
            f"- Versions analyzed: {report.evolution_summary['total_versions_analyzed']}",
            f"- Total differences: {report.evolution_summary['total_differences_found']}",
            f"- Security trend: {report.evolution_summary['security_trend']}",
            f"- Complexity trend: {report.evolution_summary['complexity_trend']}",
            f"- Categories changed: {', '.join(report.evolution_summary['categories_changed'])}",
            ""
        ]

        # Major changes
        if report.evolution_summary['major_changes']:
            lines.append("MAJOR CHANGES:")
            for change in report.evolution_summary['major_changes']:
                lines.append(f"- [{change['type']}] {change['description']}")
                lines.append(f"  Impact: {change['impact']}")
                lines.append(f"  Versions: {change['versions']}")
            lines.append("")

        # Attack surface analysis
        lines.append("ATTACK SURFACE ANALYSIS:")
        for category, changes in report.attack_surface_changes.items():
            if changes:
                lines.append(f"- {category.replace('_', ' ').title()}:")
                for change in changes:
                    lines.append(f"   {change}")
        lines.append("")

        # Bypass implications
        lines.append("BYPASS IMPLICATIONS BY VERSION:")
        for version, implication in report.bypass_implications.items():
            lines.append(f"- {version}: {implication}")
        lines.append("")

        # Detailed differences (top 10)
        lines.append("DETAILED DIFFERENCES (Top 10 by Severity):")
        severity_map = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        sorted_diffs = sorted(report.differences, key=lambda x: severity_map.get(x.severity, 0), reverse=True)
        for diff in sorted_diffs[:10]:
            lines.append(f"- [{diff.severity.upper()}] {diff.description}")
            lines.append(f"  Type: {diff.diff_type} | Category: {diff.category}")
            lines.append(f"  Versions: {diff.old_version} -> {diff.new_version}")
            lines.append(f"  Impact: {diff.impact}")
            lines.append("")

        return "\n".join(lines)


if __name__ == "__main__":
    # Test the version difference analyzer
    analyzer = VersionDifferenceAnalyzer()

    print("Version Difference Analyzer initialized")
    print("This tool analyzes and documents specific differences between protection versions")
    print("Integration with cross_version_tester.py enables comprehensive version analysis")
