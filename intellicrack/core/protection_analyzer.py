"""Protection analysis engine for binary protection detection and analysis.

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

import hashlib
import logging
from pathlib import Path
from typing import Any

from ..utils.logger import get_logger, log_all_methods


try:
    from intellicrack.handlers.pefile_handler import pefile

    HAS_PEFILE = True
except ImportError:
    get_logger(__name__).warning("pefile not found, PE analysis will be disabled.")
    HAS_PEFILE = False

try:
    from intellicrack.handlers.pyelftools_handler import HAS_PYELFTOOLS, ELFFile

    HAS_ELFTOOLS = HAS_PYELFTOOLS
except ImportError:
    get_logger(__name__).warning("pyelftools not found, ELF analysis will be disabled.")
    HAS_ELFTOOLS = False
    HAS_PYELFTOOLS = False
    ELFFile = None

try:
    from intellicrack.handlers.lief_handler import HAS_LIEF, lief
except ImportError:
    get_logger(__name__).warning("lief not found, some analysis features will be disabled.")
    HAS_LIEF = False
    lief = None


@log_all_methods
class ProtectionAnalyzer:
    """Comprehensive protection analysis engine for binary files."""

    def __init__(self, logger: logging.Logger | None = None) -> None:
        """Initialize protection analyzer."""
        self.logger = logger or get_logger(__name__)
        self.protection_signatures = self._load_protection_signatures()
        self.entropy_threshold_high = 7.5
        self.entropy_threshold_low = 1.0

    def _load_protection_signatures(self) -> dict[str, dict[str, Any]]:
        """Load known protection system signatures."""
        return {
            "upx": {
                "name": "UPX Packer",
                "type": "packer",
                "signatures": [
                    b"UPX0",
                    b"UPX1",
                    b"UPX2",
                    b"UPX!",
                    b"\x55\x50\x58\x30",
                    b"\x55\x50\x58\x31",
                ],
                "strings": ["UPX", "upx"],
                "severity": "medium",
            },
            "vmprotect": {
                "name": "VMProtect",
                "type": "protector",
                "signatures": [
                    b"VMProtect",
                    b"\x60\xe8\x00\x00\x00\x00\x5d\x50\x51\x52\x53\x56\x57",
                ],
                "strings": ["VMProtect", "VMP"],
                "entropy_indicators": True,
                "severity": "high",
            },
            "themida": {
                "name": "Themida",
                "type": "protector",
                "signatures": [
                    b"Themida",
                    b"\xeb\x10\x00\x00\x00\x56\x69\x72\x74\x75\x61\x6c\x41\x6c\x6c\x6f\x63",
                ],
                "strings": ["Themida", "Oreans"],
                "severity": "high",
            },
            "asprotect": {
                "name": "ASProtect",
                "type": "protector",
                "signatures": [
                    b"ASProtect",
                    b"\x68\x00\x00\x00\x00\x64\xff\x35\x00\x00\x00\x00",
                ],
                "strings": ["ASProtect"],
                "severity": "medium",
            },
            "armadillo": {
                "name": "Armadillo",
                "type": "protector",
                "signatures": [
                    b"Armadillo",
                    b"\x55\x8b\xec\x6a\xff\x68\x00\x00\x00\x00",
                ],
                "strings": ["Armadillo"],
                "severity": "medium",
            },
            "obsidium": {
                "name": "Obsidium",
                "type": "protector",
                "signatures": [b"Obsidium", b"\xeb\x02\xcd\x20\x03\xc0\x0f\x84"],
                "strings": ["Obsidium"],
                "severity": "medium",
            },
            "dotfuscator": {
                "name": ".NET Reactor/Dotfuscator",
                "type": "obfuscator",
                "signatures": [
                    b"Dotfuscator",
                    b".NET Reactor",
                    b"Eziriz",
                    b"ConfuserEx",
                ],
                "strings": [".NET Reactor", "Dotfuscator", "ConfuserEx"],
                "severity": "medium",
            },
            "safengine": {
                "name": "SafeEngine Protector",
                "type": "protector",
                "signatures": [
                    b"SafeEngine",
                    b"\x60\xe8\x00\x00\x00\x00\x5d\x81\xed",
                ],
                "strings": ["SafeEngine"],
                "severity": "medium",
            },
        }

    def analyze(self, file_path: str | Path) -> dict[str, Any]:
        """Perform comprehensive protection analysis on a binary file."""
        self.logger.info("Starting protection analysis for %s", file_path)
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                self.logger.error("File not found: %s", file_path)
                return {"error": f"File not found: {file_path}"}

            self.logger.debug("Reading file: %s", file_path)
            try:
                with open(file_path, "rb") as f:
                    file_data = f.read()
            except OSError as e:
                self.logger.exception("Failed to read file %s: %s", file_path, e)
                return {"error": f"Failed to read file: {e}"}
            self.logger.debug("File size: %d bytes", len(file_data))

            self.logger.info("Step 1: Getting file info.")
            file_info = self._get_file_info(file_path, file_data)
            self.logger.info("Step 1: Completed.")

            self.logger.info("Step 2: Detecting protections.")
            detected_protections = self._detect_protections(file_data)
            self.logger.info("Found %d protection(s).", len(detected_protections))
            self.logger.info("Step 2: Completed.")

            self.logger.info("Step 3: Analyzing entropy.")
            entropy_analysis = self._analyze_entropy(file_data)
            self.logger.info("Step 3: Completed.")

            self.logger.info("Step 4: Analyzing sections.")
            section_analysis = self._analyze_sections(file_path, file_data)
            self.logger.info("Step 4: Completed.")

            self.logger.info("Step 5: Analyzing imports.")
            import_analysis = self._analyze_imports(file_path, file_data)
            self.logger.info("Step 5: Completed.")

            self.logger.info("Step 6: Detecting anti-analysis techniques.")
            anti_analysis = self._detect_anti_analysis(file_data)
            self.logger.info("Step 6: Completed.")

            self.logger.info("Step 7: Generating recommendations.")
            recommendations = self._generate_recommendations(
                detected_protections,
                entropy_analysis,
                section_analysis,
                anti_analysis,
            )
            self.logger.info("Generated %d recommendation(s).", len(recommendations))
            self.logger.info("Step 7: Completed.")

            self.logger.info("Step 8: Calculating risk score.")
            risk_score = self._calculate_risk_score(detected_protections, entropy_analysis, anti_analysis)
            self.logger.info("Calculated risk score: %s", risk_score)
            self.logger.info("Step 8: Completed.")

            self.logger.info("Protection analysis for %s completed successfully.", file_path)
            return {
                "file_info": file_info,
                "detected_protections": detected_protections,
                "entropy_analysis": entropy_analysis,
                "section_analysis": section_analysis,
                "import_analysis": import_analysis,
                "anti_analysis": anti_analysis,
                "recommendations": recommendations,
                "risk_score": risk_score,
                "analysis_timestamp": self._get_protection_timestamp(),
            }

        except Exception as e:
            self.logger.exception("An unexpected error occurred during protection analysis for %s: %s", file_path, e)
            return {"error": str(e)}

    def _get_file_info(self, file_path: Path, file_data: bytes) -> dict[str, Any]:
        """Get basic file information."""
        return {
            "filename": file_path.name,
            "filepath": str(file_path),
            "size": len(file_data),
            "sha256_primary": hashlib.sha256(file_data).hexdigest(),
            "sha3_256": hashlib.sha3_256(file_data).hexdigest(),
            "sha256": hashlib.sha256(file_data).hexdigest(),
            "file_type": self._detect_file_type(file_data),
        }

    def _detect_file_type(self, file_data: bytes) -> str:
        """Detect binary file type from magic bytes."""
        if len(file_data) < 4:
            return "Unknown"

        if file_data[:2] == b"MZ":
            return "PE"
        if file_data[:4] == b"\x7fELF":
            return "ELF"
        if file_data[:4] in (
            b"\xfe\xed\xfa\xce",
            b"\xfe\xed\xfa\xcf",
            b"\xce\xfa\xed\xfe",
            b"\xcf\xfa\xed\xfe",
        ):
            return "Mach-O"

        return "Unknown"

    def _detect_protections(self, file_data: bytes) -> list[dict[str, Any]]:
        """Detect protection systems using signatures and heuristics."""
        detections = []

        for prot_info in self.protection_signatures.values():
            for sig in prot_info["signatures"]:
                if sig in file_data:
                    detections.append({
                        "name": prot_info["name"],
                        "type": prot_info["type"],
                        "severity": prot_info["severity"],
                        "signatures_matched": [sig.hex() if isinstance(sig, bytes) else sig],
                    })
                    break

        return detections

    def _analyze_entropy(self, file_data: bytes) -> dict[str, Any]:
        """Calculate Shannon entropy of file data."""
        if not file_data:
            return {
                "overall_entropy": 0.0,
                "high_entropy_sections": [],
                "low_entropy_sections": [],
            }

        import math
        from collections import Counter

        byte_counts = Counter(file_data)
        entropy = 0.0
        data_len = len(file_data)

        for count in byte_counts.values():
            if count == 0:
                continue
            probability = count / data_len
            entropy -= probability * math.log2(probability)

        return {
            "overall_entropy": entropy,
            "high_entropy_sections": [i for i, _ in enumerate(file_data[::1024]) if _ > 200],
            "low_entropy_sections": [i for i, _ in enumerate(file_data[::1024]) if _ < 10],
        }

    def _analyze_sections(self, file_path: Path, file_data: bytes) -> dict[str, Any]:
        """Analyze binary sections for suspicious characteristics."""
        sections = []

        if HAS_PEFILE and file_data[:2] == b"MZ":
            try:
                pe = pefile.PE(data=file_data)
                sections.extend(
                    {
                        "name": section.Name.decode().rstrip("\x00"),
                        "virtual_address": section.VirtualAddress,
                        "virtual_size": section.Misc_VirtualSize,
                        "raw_size": section.SizeOfRawData,
                        "entropy": section.get_entropy(),
                        "characteristics": section.Characteristics,
                    }
                    for section in pe.sections
                )
            except Exception as e:
                self.logger.warning("Failed to parse PE sections: %s", e)

        return {
            "sections": sections,
            "suspicious_sections": [s for s in sections if s.get("entropy", 0) > 7.0],
        }

    def _analyze_imports(self, file_path: Path, file_data: bytes) -> dict[str, Any]:
        """Analyze import table for suspicious API calls."""
        imports = []
        suspicious_imports = []

        suspicious_apis = [
            "VirtualAlloc",
            "VirtualProtect",
            "CreateRemoteThread",
            "WriteProcessMemory",
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
            "ZwQueryInformationProcess",
        ]

        if HAS_PEFILE and file_data[:2] == b"MZ":
            try:
                pe = pefile.PE(data=file_data)
                if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        dll_name = entry.dll.decode() if isinstance(entry.dll, bytes) else entry.dll
                        for imp in entry.imports:
                            if imp.name:
                                func_name = imp.name.decode() if isinstance(imp.name, bytes) else imp.name
                                imports.append(f"{dll_name}!{func_name}")
                                if any(api in func_name for api in suspicious_apis):
                                    suspicious_imports.append(f"{dll_name}!{func_name}")
            except Exception as e:
                self.logger.warning("Failed to parse PE imports: %s", e)

        return {
            "imports": imports[:100],
            "suspicious_imports": suspicious_imports,
            "import_count": len(imports),
        }

    def _detect_anti_analysis(self, file_data: bytes) -> dict[str, Any]:
        """Detect anti-analysis and anti-debugging techniques."""
        anti_debug_signatures = {
            "IsDebuggerPresent": b"IsDebuggerPresent",
            "CheckRemoteDebuggerPresent": b"CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess": b"NtQueryInformationProcess",
            "OutputDebugString": b"OutputDebugStringA",
            "RDTSC timing": b"\x0f\x31",
        }

        techniques = [technique for technique, signature in anti_debug_signatures.items() if signature in file_data]
        return {
            "anti_debug_detected": len(techniques) > 0,
            "techniques": techniques,
            "risk_level": "high" if len(techniques) >= 3 else "medium" if techniques else "low",
        }

    def _generate_recommendations(
        self,
        detected_protections: list[dict[str, Any]],
        entropy_analysis: dict[str, Any],
        section_analysis: dict[str, Any],
        anti_analysis: dict[str, Any],
    ) -> list[str]:
        """Generate analysis recommendations based on findings."""
        recommendations = []

        if detected_protections:
            prot_names = [p["name"] for p in detected_protections]
            recommendations.extend((
                f"Binary is protected with: {', '.join(prot_names)}",
                "Consider using specialized unpacking tools for detected protections",
            ))
        if entropy_analysis.get("overall_entropy", 0) > self.entropy_threshold_high:
            recommendations.extend((
                "High entropy detected - binary likely encrypted or compressed",
                "Attempt unpacking before static analysis",
            ))
        if section_analysis.get("suspicious_sections"):
            recommendations.append("Suspicious high-entropy sections detected")

        if anti_analysis.get("anti_debug_detected"):
            recommendations.append("Anti-debugging techniques detected - use stealth debugging")

        if not recommendations:
            recommendations.append("No significant protections detected - proceed with standard analysis")

        return recommendations

    def _calculate_risk_score(
        self,
        detected_protections: list[dict[str, Any]],
        entropy_analysis: dict[str, Any],
        anti_analysis: dict[str, Any],
    ) -> int:
        """Calculate overall risk score (0-100)."""
        risk_score = 0

        risk_score += len(detected_protections) * 15
        risk_score += min(len([p for p in detected_protections if p.get("severity") == "high"]) * 10, 30)

        entropy = entropy_analysis.get("overall_entropy", 0)
        if entropy > self.entropy_threshold_high:
            risk_score += 20
        elif entropy > 6.5:
            risk_score += 10

        if anti_analysis.get("anti_debug_detected"):
            risk_score += len(anti_analysis.get("techniques", [])) * 5

        return min(risk_score, 100)

    def _get_protection_timestamp(self) -> str:
        """Get current timestamp for analysis."""
        from datetime import datetime

        return f"{datetime.utcnow().isoformat()}Z"
